//go:build linux

package extensionrunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const (
	nodeInstallMetadataName = ".dirextalk-node-install-v1.json"
	nodeRemoveStateRootName = ".node-remove-v1"
	nodeRemoveReceiptV1     = "dirextalk.node-remove/v1"
)

type NodeOfflineBuilder struct {
	PreparedRoot    string
	PublicationRoot string
	RuntimeRoot     string
	CgroupRoot      string
	Logger          *slog.Logger
	mu              sync.Mutex
	heartbeatEvery  time.Duration
	readDir         func(string) ([]os.DirEntry, error)
}

type nodeCanonicalFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type nodeSourceManifestV1 struct {
	SchemaVersion  string                     `json:"schema_version"`
	PackageName    string                     `json:"package_name"`
	PackageVersion string                     `json:"package_version"`
	EntryPath      string                     `json:"entry_path"`
	EntrySHA256    string                     `json:"entry_sha256"`
	LockSHA256     string                     `json:"lock_sha256"`
	Tarballs       []nodeSourceTarballBinding `json:"tarballs"`
}

type nodeSourceTarballBinding struct {
	LockPath  string `json:"lock_path"`
	Path      string `json:"path"`
	Integrity string `json:"integrity"`
}

type nodeInstallMetadataV1 struct {
	SchemaVersion  string `json:"schema_version"`
	InputDigest    string `json:"input_digest"`
	PackageName    string `json:"package_name"`
	PackageVersion string `json:"package_version"`
	LockSHA256     string `json:"lock_sha256"`
	EntryPath      string `json:"entry_path"`
	EntrySHA256    string `json:"entry_sha256"`
	NodeVersion    string `json:"node_version"`
	NPMVersion     string `json:"npm_version"`
}

type nodeRemoveReceipt struct {
	SchemaVersion string `json:"schema_version"`
	Scope         string `json:"scope"`
	Digest        string `json:"digest"`
	CleanupToken  string `json:"cleanup_token"`
}

func (b *NodeOfflineBuilder) Build(ctx context.Context, request NodeBuildRequestV1, sourceFD int) (NodeBuildReceiptV1, error) {
	if ctx == nil || request.Validate(1) != nil {
		b.logAdmissionFailure("request_validate")
		return NodeBuildReceiptV1{}, ErrDenied
	}
	if !safeRunnerRoot(b.PreparedRoot) || !safeRunnerRoot(b.PublicationRoot) {
		b.logAdmissionFailure("root")
		return NodeBuildReceiptV1{}, ErrDenied
	}
	if !safeNodeRuntimeRoot(b.RuntimeRoot) {
		b.logAdmissionFailure("runtime")
		return NodeBuildReceiptV1{}, ErrDenied
	}
	if !filepath.IsAbs(b.CgroupRoot) || filepath.Clean(b.CgroupRoot) != b.CgroupRoot {
		b.logAdmissionFailure("cgroup")
		return NodeBuildReceiptV1{}, ErrDenied
	}
	if err := verifySealedNodeSource(sourceFD, request.ContentSize, request.ContentSHA256); err != nil {
		b.logAdmissionFailure("source_seal")
		return NodeBuildReceiptV1{}, ErrDenied
	}
	content := make([]byte, request.ContentSize)
	if n, err := unix.Pread(sourceFD, content, 0); err != nil || n != len(content) {
		return NodeBuildReceiptV1{}, ErrDenied
	}
	files, manifest, err := decodeNodeSource(content)
	if err != nil || manifest.PackageName != request.PackageName || manifest.PackageVersion != request.PackageVersion || manifest.EntryPath != request.EntryPath || manifest.EntrySHA256 != request.EntrySHA256 || manifest.LockSHA256 != request.LockSHA256 {
		b.logAdmissionFailure("source_decode")
		return NodeBuildReceiptV1{}, ErrDenied
	}
	b.log("offline_install", "start", 0, len(files), len(content))
	started := time.Now()
	buildRoot, err := os.MkdirTemp(b.PreparedRoot, ".node-build-")
	if err != nil {
		return NodeBuildReceiptV1{}, ErrUnavailable
	}
	defer removePublishedTree(buildRoot)
	for _, file := range files {
		if err := writeNodeInputFile(buildRoot, file); err != nil {
			return NodeBuildReceiptV1{}, ErrDenied
		}
	}
	originalLock, err := os.ReadFile(filepath.Join(buildRoot, "package-lock.json"))
	if err != nil || DigestBytes(originalLock) != request.LockSHA256 {
		return NodeBuildReceiptV1{}, ErrDenied
	}
	if err = rewriteNodeLockForOffline(buildRoot, originalLock, manifest.Tarballs); err != nil {
		return NodeBuildReceiptV1{}, ErrDenied
	}
	if err = b.runOfflineNPM(ctx, buildRoot); err != nil {
		b.log("offline_install", "failed", time.Since(started), 0, 0)
		return NodeBuildReceiptV1{}, err
	}
	if err = os.WriteFile(filepath.Join(buildRoot, "package-lock.json"), originalLock, 0o600); err != nil {
		return NodeBuildReceiptV1{}, ErrUnavailable
	}
	if err = removePublishedTree(filepath.Join(buildRoot, ".dirextalk-npm-tarballs")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return NodeBuildReceiptV1{}, ErrUnavailable
	}
	if err = os.Remove(filepath.Join(buildRoot, ".dirextalk-node-source-v1.json")); err != nil {
		return NodeBuildReceiptV1{}, ErrUnavailable
	}
	if err = cleanupNPMInstallState(buildRoot); err != nil {
		return NodeBuildReceiptV1{}, ErrUnavailable
	}
	b.log("verify", "start", time.Since(started), 0, 0)
	metadata := nodeInstallMetadataV1{SchemaVersion: NodeInstallManifestV1, InputDigest: request.InputDigest, PackageName: request.PackageName, PackageVersion: request.PackageVersion, LockSHA256: request.LockSHA256, EntryPath: request.EntryPath, EntrySHA256: request.EntrySHA256, NodeVersion: ManagedNodeVersionV1, NPMVersion: ManagedNPMVersionV1}
	metadataBytes, _ := json.Marshal(metadata)
	if err = os.WriteFile(filepath.Join(buildRoot, nodeInstallMetadataName), append(metadataBytes, '\n'), 0o600); err != nil {
		return NodeBuildReceiptV1{}, ErrUnavailable
	}
	entries, artifactBytes, err := verifyExpandedNodeTree(buildRoot, request)
	if err != nil {
		return NodeBuildReceiptV1{}, err
	}
	digest := ManifestDigest(entries)
	manifestBytes, _ := json.Marshal(DiskInstallManifestV1{SchemaVersion: installManifestSchemaV1, Entries: entries})
	if err = os.WriteFile(filepath.Join(buildRoot, installManifestName), append(manifestBytes, '\n'), 0o400); err != nil || makeNodeTreeImmutable(buildRoot) != nil {
		return NodeBuildReceiptV1{}, ErrUnavailable
	}
	receipt := NodeBuildReceiptV1{InputDigest: request.InputDigest, ArtifactDigest: digest, ArtifactBytes: uint64(artifactBytes), FileCount: uint32(len(entries)), EntryPath: request.EntryPath, EntrySHA256: request.EntrySHA256, PackageName: request.PackageName, PackageVersion: request.PackageVersion, LockSHA256: request.LockSHA256, NodeVersion: ManagedNodeVersionV1, NPMVersion: ManagedNPMVersionV1, LifecycleScriptsDisabled: true, NativeAddonsAbsent: true}
	physicalBytes, physicalErr := nodeTreePhysicalBytes(buildRoot)
	b.mu.Lock()
	defer b.mu.Unlock()
	if physicalErr != nil || receipt.Validate() != nil || b.ensurePhysicalQuota(physicalBytes) != nil {
		return NodeBuildReceiptV1{}, ErrNodeInstallCapacity
	}
	digestRoot := filepath.Join(b.PreparedRoot, digest)
	if err = os.Mkdir(digestRoot, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return NodeBuildReceiptV1{}, ErrUnavailable
	}
	target := filepath.Join(digestRoot, request.CleanupToken)
	if err = moveImmutableNodeTree(buildRoot, target); err != nil {
		if existing, verifyErr := resolveNodeBundle(target, receipt); verifyErr == nil {
			_ = existing.Close()
			return receipt, nil
		}
		return NodeBuildReceiptV1{}, ErrUnavailable
	}
	b.log("verify", "complete", time.Since(started), len(entries), int(artifactBytes))
	return receipt, nil
}

func (b *NodeOfflineBuilder) Promote(request NodePromoteRequestV1) error {
	if request.Validate() != nil || !safeRunnerRoot(b.PreparedRoot) || !safeRunnerRoot(b.PublicationRoot) {
		return ErrDenied
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	started := time.Now()
	b.log("publish", "start", 0, int(request.Receipt.FileCount), int(request.Receipt.ArtifactBytes))
	prepared := filepath.Join(b.PreparedRoot, request.Receipt.ArtifactDigest, request.CleanupToken)
	admitted, err := resolveNodeBundle(prepared, request.Receipt)
	if err != nil {
		if active, activeErr := resolveNodeBundle(filepath.Join(b.PublicationRoot, request.Receipt.ArtifactDigest), request.Receipt); activeErr == nil {
			_ = active.Close()
			if refErr := b.addActiveReference(request.Receipt.ArtifactDigest, request.CleanupToken); refErr != nil {
				return refErr
			}
			b.log("publish", "complete", time.Since(started), int(request.Receipt.FileCount), int(request.Receipt.ArtifactBytes))
			return nil
		}
		return ErrDenied
	}
	_ = admitted.Close()
	active := filepath.Join(b.PublicationRoot, request.Receipt.ArtifactDigest)
	if err = moveImmutableNodeTree(prepared, active); err != nil {
		if existing, verifyErr := resolveNodeBundle(active, request.Receipt); verifyErr != nil {
			return ErrDenied
		} else {
			_ = existing.Close()
			_ = removePublishedTree(prepared)
		}
	}
	if err := b.addActiveReference(request.Receipt.ArtifactDigest, request.CleanupToken); err != nil {
		b.log("publish", "failed", time.Since(started), 0, 0)
		return err
	}
	b.log("publish", "complete", time.Since(started), int(request.Receipt.FileCount), int(request.Receipt.ArtifactBytes))
	return nil
}

func (b *NodeOfflineBuilder) Remove(request NodeRemoveRequestV1) error {
	if request.Validate() != nil || !safeRunnerRoot(b.PreparedRoot) || !safeRunnerRoot(b.PublicationRoot) {
		return ErrDenied
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	state, err := b.beginNodeRemove(request)
	if err != nil {
		return err
	}
	if state == "done" {
		return nil
	}
	if request.Scope == "prepared" {
		digestRoot := filepath.Join(b.PreparedRoot, request.Digest)
		if err := removePublishedTree(filepath.Join(digestRoot, request.CleanupToken)); err != nil {
			return err
		}
		if err := removeEmptyNodeDirectory(digestRoot); err != nil {
			return err
		}
		return b.completeNodeRemove(request)
	}
	refRoot := filepath.Join(b.PreparedRoot, ".active-refs", request.Digest)
	ref := filepath.Join(refRoot, request.CleanupToken)
	if err := os.Remove(ref); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrDenied
	}
	entries, err := b.readNodeDirectory(refRoot)
	if err != nil {
		return ErrDenied
	}
	for _, entry := range entries {
		if uuid.Validate(entry.Name()) != nil || !entry.Type().IsRegular() {
			return ErrDenied
		}
	}
	if len(entries) != 0 {
		return b.completeNodeRemove(request)
	}
	if err := removePublishedTree(filepath.Join(b.PublicationRoot, request.Digest)); err != nil {
		return err
	}
	if err := removeEmptyNodeDirectory(filepath.Join(b.PreparedRoot, request.Digest)); err != nil {
		return err
	}
	if err := b.completeNodeRemove(request); err != nil {
		return err
	}
	if err := os.Remove(refRoot); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) {
		return ErrDenied
	}
	return nil
}

func (b *NodeOfflineBuilder) beginNodeRemove(request NodeRemoveRequestV1) (string, error) {
	done, err := b.validNodeRemoveReceipt(request, "done")
	if err != nil {
		return "", err
	}
	if done {
		return "done", nil
	}
	pending, err := b.validNodeRemoveReceipt(request, "pending")
	if err != nil {
		return "", err
	}
	if pending {
		return "pending", nil
	}
	var owner string
	if request.Scope == "prepared" {
		owner = filepath.Join(b.PreparedRoot, request.Digest, request.CleanupToken)
		info, statErr := os.Lstat(owner)
		if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", ErrDenied
		}
	} else {
		owner = filepath.Join(b.PreparedRoot, ".active-refs", request.Digest, request.CleanupToken)
		info, statErr := os.Lstat(owner)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return "", ErrDenied
		}
	}
	receiptDir := b.nodeRemoveReceiptDir(request)
	if err := os.MkdirAll(receiptDir, 0o700); err != nil {
		return "", ErrUnavailable
	}
	if err := syncNodeRemoveReceiptPath(b.PreparedRoot, receiptDir); err != nil {
		return "", ErrUnavailable
	}
	body := nodeRemoveReceiptBody(request)
	pendingPath := filepath.Join(receiptDir, "pending")
	if err := writeNodeRemovePending(pendingPath, body); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		valid, verifyErr := b.validNodeRemoveReceipt(request, "pending")
		if verifyErr != nil || !valid {
			return "", ErrDenied
		}
	}
	if err := syncDirectory(receiptDir); err != nil {
		return "", ErrUnavailable
	}
	return "pending", nil
}

func (b *NodeOfflineBuilder) completeNodeRemove(request NodeRemoveRequestV1) error {
	done, err := b.validNodeRemoveReceipt(request, "done")
	if err != nil {
		return err
	}
	if done {
		return nil
	}
	pending, err := b.validNodeRemoveReceipt(request, "pending")
	if err != nil || !pending {
		return ErrDenied
	}
	receiptDir := b.nodeRemoveReceiptDir(request)
	if err := os.Rename(filepath.Join(receiptDir, "pending"), filepath.Join(receiptDir, "done")); err != nil {
		return ErrUnavailable
	}
	if err := syncDirectory(receiptDir); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (b *NodeOfflineBuilder) validNodeRemoveReceipt(request NodeRemoveRequestV1, state string) (bool, error) {
	path := filepath.Join(b.nodeRemoveReceiptDir(request), state)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, ErrDenied
	}
	body, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(body, nodeRemoveReceiptBody(request)) {
		return false, ErrDenied
	}
	return true, nil
}

func (b *NodeOfflineBuilder) nodeRemoveReceiptDir(request NodeRemoveRequestV1) string {
	return filepath.Join(b.PreparedRoot, nodeRemoveStateRootName, request.Scope, request.Digest, request.CleanupToken)
}

func nodeRemoveReceiptBody(request NodeRemoveRequestV1) []byte {
	body, _ := json.Marshal(nodeRemoveReceipt{SchemaVersion: nodeRemoveReceiptV1, Scope: request.Scope, Digest: request.Digest, CleanupToken: request.CleanupToken})
	return body
}

func writeNodeRemovePending(path string, body []byte) error {
	temporary := path + ".tmp-" + uuid.NewString()
	if err := writeFileSync(temporary, body, 0o400); err != nil {
		return ErrUnavailable
	}
	defer os.Remove(temporary)
	if err := unix.Renameat2(unix.AT_FDCWD, temporary, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			return os.ErrExist
		}
		return ErrUnavailable
	}
	return nil
}

func syncNodeRemoveReceiptPath(root, receiptDir string) error {
	for path := receiptDir; ; path = filepath.Dir(path) {
		if err := syncDirectory(path); err != nil {
			return err
		}
		if path == root {
			return nil
		}
		parent := filepath.Dir(path)
		if parent == path || !strings.HasPrefix(parent+string(filepath.Separator), root+string(filepath.Separator)) {
			return ErrDenied
		}
	}
}

func (b *NodeOfflineBuilder) readNodeDirectory(path string) ([]os.DirEntry, error) {
	if b.readDir != nil {
		return b.readDir(path)
	}
	return os.ReadDir(path)
}

func removeEmptyNodeDirectory(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && !errors.Is(err, syscall.ENOTEMPTY) {
		return err
	}
	return nil
}

func (b *NodeOfflineBuilder) addActiveReference(digest, token string) error {
	root := filepath.Join(b.PreparedRoot, ".active-refs", digest)
	if err := os.MkdirAll(root, 0o700); err != nil {
		return ErrUnavailable
	}
	fd, err := os.OpenFile(filepath.Join(root, token), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o400)
	if errors.Is(err, os.ErrExist) {
		return nil
	}
	if err != nil {
		return ErrUnavailable
	}
	return fd.Close()
}

func (b *NodeOfflineBuilder) runOfflineNPM(ctx context.Context, root string) error {
	loader := filepath.Join(b.RuntimeRoot, "lib/ld-musl-x86_64.so.1")
	node := filepath.Join(b.RuntimeRoot, "usr/local/bin/node")
	npm := filepath.Join(b.RuntimeRoot, "usr/local/lib/node_modules/npm/bin/npm-cli.js")
	for _, path := range []string{loader, node, npm} {
		if !filepath.IsAbs(path) {
			return ErrDenied
		}
	}
	installCtx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(installCtx, loader, nodeOfflineNPMArguments(b.RuntimeRoot, node, npm)...)
	cmd.Dir = root
	cmd.Env = nodeOfflineNPMEnvironment(root)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL, Cloneflags: unix.CLONE_NEWUSER | unix.CLONE_NEWNET, UidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Geteuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getegid(), Size: 1}}, GidMappingsEnableSetgroups: false}
	var stdout, stderr boundedBuffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Start(); err != nil {
		return ErrUnavailable
	}
	cgroup := filepath.Join(b.CgroupRoot, "node-install-"+uuid.NewString())
	limits := LimitsV2{CPUSeconds: 30, MemoryBytes: 256 << 20, Processes: 32, FileBytes: MaxNodeArtifactBytes, OpenFiles: 64}
	if err := setupCgroup(cgroup, limits, cmd.Process.Pid); err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		return err
	}
	done := make(chan struct{})
	go b.heartbeat(installCtx, done)
	err := cmd.Wait()
	close(done)
	_ = cleanupSetupCgroup(defaultCgroupOps(), cgroup)
	if err != nil || stdout.exceeded || stderr.exceeded {
		return ErrDenied
	}
	return nil
}

func nodeOfflineNPMEnvironment(root string) []string {
	return []string{"HOME=" + root, "TMPDIR=" + root, "npm_config_cache=" + filepath.Join(root, ".npm-cache"), "npm_config_ignore_scripts=true", "npm_config_update_notifier=false", "NODE_DISABLE_COMPILE_CACHE=1", "NODE_OPTIONS=--max-old-space-size=192"}
}

func nodeOfflineNPMArguments(runtimeRoot, node, npm string) []string {
	return []string{"--library-path", filepath.Join(runtimeRoot, "usr/lib"), node, npm, "ci", "--offline", "--ignore-scripts", "--omit=dev", "--no-audit", "--no-fund", "--workspaces=false"}
}

func (b *NodeOfflineBuilder) heartbeat(ctx context.Context, done <-chan struct{}) {
	every := b.heartbeatEvery
	if every <= 0 {
		every = 10 * time.Second
	}
	ticker := time.NewTicker(every)
	defer ticker.Stop()
	started := time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			b.log("offline_install", "running", time.Since(started), 0, 0)
		}
	}
}

func (b *NodeOfflineBuilder) log(phase, state string, elapsed time.Duration, files, bytes int) {
	logger := b.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Info("managed Node install", "phase", phase, "state", state, "elapsed_ms", elapsed.Milliseconds(), "file_count", files, "artifact_bytes", bytes)
}

func (b *NodeOfflineBuilder) logAdmissionFailure(stage string) {
	logger := b.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logger.Warn("managed Node install", "phase", "offline_install", "state", "failed", "class", "denied", "stage", stage, "elapsed_ms", 0, "file_count", 0, "artifact_bytes", 0)
}

func cleanupNPMInstallState(root string) error {
	for _, relative := range []string{".npm-cache", ".npmrc", "node-compile-cache", "node_modules/.package-lock.json", "node_modules/.bin"} {
		if err := removePublishedTree(filepath.Join(root, filepath.FromSlash(relative))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "npm-debug.log") {
			if err := removePublishedTree(filepath.Join(root, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}

func verifySealedNodeSource(fd int, size int64, digest string) error {
	if fd < 0 || size <= 0 || size > MaxNodeSourceBytes || !digestRE.MatchString(digest) {
		return ErrInvalid
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size != size {
		return ErrInvalid
	}
	seals, err := unix.FcntlInt(uintptr(fd), unix.F_GET_SEALS, 0)
	required := unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
	if err != nil || seals&required != required {
		return ErrInvalid
	}
	h := sha256.New()
	buffer := make([]byte, 32<<10)
	for offset := int64(0); offset < size; {
		want := int64(len(buffer))
		if remaining := size - offset; remaining < want {
			want = remaining
		}
		n, readErr := unix.Pread(fd, buffer[:want], offset)
		if readErr != nil || n <= 0 {
			return ErrInvalid
		}
		_, _ = h.Write(buffer[:n])
		offset += int64(n)
	}
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return ErrInvalid
	}
	return nil
}

func decodeNodeSource(content []byte) ([]nodeCanonicalFile, nodeSourceManifestV1, error) {
	var files []nodeCanonicalFile
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&files) != nil || len(files) == 0 || len(files) > MaxNodeArtifactFiles {
		return nil, nodeSourceManifestV1{}, ErrInvalid
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, nodeSourceManifestV1{}, ErrInvalid
	}
	canonical, _ := json.Marshal(files)
	if !bytes.Equal(canonical, content) {
		return nil, nodeSourceManifestV1{}, ErrInvalid
	}
	var manifest nodeSourceManifestV1
	last := ""
	for _, file := range files {
		if !safeRelativeSlash(file.Path) || last >= file.Path || len(file.Content) > int(MaxNodeSourceBytes)*2 {
			return nil, manifest, ErrInvalid
		}
		last = file.Path
		if file.Path == ".dirextalk-node-source-v1.json" {
			body, err := base64.RawStdEncoding.DecodeString(file.Content)
			if err != nil || json.Unmarshal(body, &manifest) != nil {
				return nil, manifest, ErrInvalid
			}
		}
	}
	if manifest.SchemaVersion != "dirextalk.node-source/v1" {
		return nil, manifest, ErrInvalid
	}
	return files, manifest, nil
}

func writeNodeInputFile(root string, file nodeCanonicalFile) error {
	data, err := base64.RawStdEncoding.DecodeString(file.Content)
	if err != nil {
		return ErrInvalid
	}
	target := filepath.Join(root, filepath.FromSlash(file.Path))
	if !strings.HasPrefix(target, root+string(os.PathSeparator)) {
		return ErrInvalid
	}
	if err = os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return err
	}
	return os.WriteFile(target, data, 0o600)
}

func rewriteNodeLockForOffline(root string, original []byte, bindings []nodeSourceTarballBinding) error {
	var lock map[string]any
	decoder := json.NewDecoder(bytes.NewReader(original))
	decoder.UseNumber()
	if decoder.Decode(&lock) != nil {
		return ErrInvalid
	}
	packages, ok := lock["packages"].(map[string]any)
	if !ok {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for _, binding := range bindings {
		pkg, ok := packages[binding.LockPath].(map[string]any)
		if !ok || !safeRelativeSlash(binding.Path) || !strings.HasPrefix(binding.Path, ".dirextalk-npm-tarballs/") || seen[binding.LockPath] {
			return ErrInvalid
		}
		seen[binding.LockPath] = true
		pkg["resolved"] = "file:" + filepath.Join(root, filepath.FromSlash(binding.Path))
	}
	for lockPath, raw := range packages {
		if lockPath == "" {
			continue
		}
		pkg, ok := raw.(map[string]any)
		if !ok {
			return ErrInvalid
		}
		if dev, _ := pkg["dev"].(bool); !dev && !seen[lockPath] {
			return ErrInvalid
		}
	}
	updated, err := json.Marshal(lock)
	if err != nil {
		return ErrInvalid
	}
	return os.WriteFile(filepath.Join(root, "package-lock.json"), updated, 0o600)
}

func verifyExpandedNodeTree(root string, request NodeBuildRequestV1) ([]ManifestEntry, int64, error) {
	entries := make([]ManifestEntry, 0)
	var total int64
	err := filepath.Walk(root, func(current string, info os.FileInfo, err error) error {
		if err != nil {
			return ErrDenied
		}
		if current == root {
			return nil
		}
		rel, err := filepath.Rel(root, current)
		if err != nil || !safeRelativeSlash(filepath.ToSlash(rel)) || info.Mode()&os.ModeSymlink != 0 {
			return ErrDenied
		}
		lower := strings.ToLower(filepath.ToSlash(rel))
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() || info.Size() < 0 || total+info.Size() > MaxNodeArtifactBytes || len(entries) >= MaxNodeArtifactFiles {
			return ErrNodeInstallCapacity
		}
		ext := strings.ToLower(filepath.Ext(lower))
		if ext == ".node" || ext == ".so" || ext == ".dylib" || ext == ".dll" || ext == ".a" || ext == ".o" || filepath.Base(lower) == "binding.gyp" {
			return ErrDenied
		}
		data, err := os.ReadFile(current)
		if err != nil {
			return ErrDenied
		}
		if filepath.Base(lower) == "package.json" {
			var pkg struct {
				Gypfile bool `json:"gypfile"`
			}
			if json.Unmarshal(data, &pkg) != nil || pkg.Gypfile {
				return ErrDenied
			}
		}
		digest := DigestBytes(data)
		if filepath.ToSlash(rel) == request.EntryPath && digest != request.EntrySHA256 {
			return ErrDenied
		}
		entries = append(entries, ManifestEntry{Path: filepath.ToSlash(rel), SHA256: digest, Size: info.Size()})
		total += info.Size()
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	found := false
	for _, entry := range entries {
		if entry.Path == request.EntryPath {
			found = true
		}
	}
	if !found {
		return nil, 0, ErrDenied
	}
	return entries, total, nil
}

func resolveNodeBundle(root string, receipt NodeBuildReceiptV1) (*AdmittedInstall, error) {
	if receipt.Validate() != nil {
		return nil, ErrInvalid
	}
	manifestBytes, err := os.ReadFile(filepath.Join(root, installManifestName))
	if err != nil {
		return nil, ErrInvalid
	}
	var manifest DiskInstallManifestV1
	if json.Unmarshal(bytes.TrimSuffix(manifestBytes, []byte{'\n'}), &manifest) != nil || ManifestDigest(manifest.Entries) != receipt.ArtifactDigest || uint32(len(manifest.Entries)) != receipt.FileCount {
		return nil, ErrInvalid
	}
	var bytesTotal uint64
	for _, entry := range manifest.Entries {
		bytesTotal += uint64(entry.Size)
	}
	if bytesTotal != receipt.ArtifactBytes {
		return nil, ErrInvalid
	}
	return OpenAdmittedNodeInstall(root, receipt.ArtifactDigest, manifest.Entries, receipt.EntryPath, receipt.EntrySHA256)
}

func (b *NodeOfflineBuilder) ensurePhysicalQuota(incoming int64) error {
	used, err := nodePublishedStorageBytes(b.PublicationRoot, false)
	if err != nil {
		return err
	}
	prepared, err := nodePublishedStorageBytes(b.PreparedRoot, true)
	if err != nil {
		return err
	}
	if incoming < 0 || used > MaxNodeStorageBytes-prepared || used+prepared > MaxNodeStorageBytes-incoming {
		return ErrNodeInstallCapacity
	}
	return nil
}

func nodePublishedStorageBytes(root string, nested bool) (int64, error) {
	children, err := os.ReadDir(root)
	if err != nil {
		return 0, err
	}
	var total int64
	for _, child := range children {
		if !child.IsDir() || strings.HasPrefix(child.Name(), ".") {
			continue
		}
		paths := []string{filepath.Join(root, child.Name())}
		if nested {
			paths = paths[:0]
			generations, readErr := os.ReadDir(filepath.Join(root, child.Name()))
			if readErr != nil {
				return 0, readErr
			}
			for _, generation := range generations {
				if generation.IsDir() {
					paths = append(paths, filepath.Join(root, child.Name(), generation.Name()))
				}
			}
		}
		for _, tree := range paths {
			if _, statErr := os.Stat(filepath.Join(tree, nodeInstallMetadataName)); statErr != nil {
				continue
			}
			err = filepath.Walk(tree, func(_ string, info os.FileInfo, walkErr error) error {
				if walkErr != nil {
					return walkErr
				}
				if info.Mode().IsRegular() {
					total += info.Size()
					if total > MaxNodeStorageBytes {
						return ErrNodeInstallCapacity
					}
				}
				return nil
			})
			if err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

func nodeTreePhysicalBytes(root string) (int64, error) {
	var total int64
	err := filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}

func makeNodeTreeImmutable(root string) error {
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path != root && info.Mode().IsRegular() {
			return os.Chmod(path, 0o400)
		}
		return nil
	}); err != nil {
		return err
	}
	return makePublishedTreeImmutable(root)
}

// Moving a directory across parents updates its internal `..` entry and Linux
// therefore requires the directory itself to be writable. The tree is never
// admitted while writable: resolvers require a non-writable root. Files and
// descendants remain immutable throughout, and the destination root is made
// non-writable before this function returns.
func moveImmutableNodeTree(source, target string) error {
	if err := os.Chmod(source, 0o700); err != nil {
		return err
	}
	if err := os.Rename(source, target); err != nil {
		_ = os.Chmod(source, 0o500)
		return err
	}
	if err := os.Chmod(target, 0o500); err != nil {
		_ = removePublishedTree(target)
		return err
	}
	parent, err := os.Open(filepath.Dir(target))
	if err != nil {
		_ = removePublishedTree(target)
		return err
	}
	err = parent.Sync()
	closeErr := parent.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func safeNodeRuntimeRoot(root string) bool {
	fd, _, err := openNodeRuntimeRoot(root)
	if err != nil {
		return false
	}
	return unix.Close(fd) == nil
}

func openNodeRuntimeRoot(root string) (int, unix.Stat_t, error) {
	var st unix.Stat_t
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || root == "/" {
		return -1, st, ErrDenied
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, st, ErrDenied
	}
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Uid != 0 && st.Uid != uint32(os.Geteuid())) || st.Mode&0o022 != 0 {
		unix.Close(fd)
		return -1, unix.Stat_t{}, ErrDenied
	}
	for _, relative := range []string{"lib/ld-musl-x86_64.so.1", "usr/local/bin/node", "usr/local/lib/node_modules/npm/bin/npm-cli.js", "usr/lib/libstdc++.so.6", "usr/lib/libgcc_s.so.1"} {
		file, err := unix.Openat2(fd, relative, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			unix.Close(fd)
			return -1, unix.Stat_t{}, ErrDenied
		}
		var fileStat unix.Stat_t
		valid := unix.Fstat(file, &fileStat) == nil && fileStat.Mode&unix.S_IFMT == unix.S_IFREG && (fileStat.Uid == 0 || fileStat.Uid == uint32(os.Geteuid())) && fileStat.Mode&0o022 == 0
		unix.Close(file)
		if !valid {
			unix.Close(fd)
			return -1, unix.Stat_t{}, ErrDenied
		}
	}
	return fd, st, nil
}
