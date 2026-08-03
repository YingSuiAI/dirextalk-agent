// Package workerrootfs creates the deterministic, strictly allow-listed rootfs
// archive used to attest a Dirextalk Cloud Worker AMI.
package workerrootfs

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

const (
	SchemaV1 = "dirextalk.agent.worker-rootfs/v1"

	workerBinaryPath     = "usr/local/bin/dirextalk-cloud-worker"
	workerSidecarPath    = "usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256"
	installerBinaryPath  = "usr/local/bin/dirextalk-worker-installer"
	installerSidecarPath = "usr/local/share/dirextalk-worker/dirextalk-worker-installer.sha256"
	runtimeInstallPath   = "etc/dirextalk-worker/runtime-installation.json"
	runtimeEnvironment   = "etc/dirextalk-worker/runtime.env"
	piBinaryPath         = "opt/dirextalk-worker/runtimes/pi/bin/pi"
	piPackageJSONPath    = "opt/dirextalk-worker/runtimes/pi/bin/package.json"
	piPhotonWASMPath     = "opt/dirextalk-worker/runtimes/pi/bin/photon_rs_bg.wasm"
	piExtensionPath      = "opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts"
	piDarkThemePath      = "opt/dirextalk-worker/runtimes/pi/bin/theme/dark.json"
	piLightThemePath     = "opt/dirextalk-worker/runtimes/pi/bin/theme/light.json"
	piThemeSchemaPath    = "opt/dirextalk-worker/runtimes/pi/bin/theme/theme-schema.json"
)

// ManifestV1 is safe to print: it contains only content digests and size, never
// local source paths or rootfs contents.
type ManifestV1 struct {
	Schema       string `json:"schema"`
	RootFSDigest string `json:"rootfs_digest"`
	BinaryDigest string `json:"binary_digest"`
	Size         int64  `json:"size"`
}

type entryKind uint8

const (
	directoryEntry entryKind = iota + 1
	regularEntry
)

type entrySpec struct {
	path     string
	kind     entryKind
	mode     int64
	maxBytes int64
}

// rootfsEntries is deliberately closed. It mirrors only the paths emitted by
// deploy/container/worker.Containerfile. Adding a runtime asset requires an
// explicit code and test change here; an exported image can never smuggle an
// extra executable or configuration file into the AMI.
var rootfsEntries = []entrySpec{
	{path: "etc", kind: directoryEntry, mode: 0o755},
	{path: "etc/ssl", kind: directoryEntry, mode: 0o755},
	{path: "etc/ssl/certs", kind: directoryEntry, mode: 0o755},
	{path: "etc/ssl/certs/ca-certificates.crt", kind: regularEntry, mode: 0o444, maxBytes: 16 << 20},
	{path: "etc/dirextalk-worker", kind: directoryEntry, mode: 0o755},
	{path: runtimeInstallPath, kind: regularEntry, mode: 0o444, maxBytes: workerruntime.MaxInstallationBytes},
	{path: runtimeEnvironment, kind: regularEntry, mode: 0o444, maxBytes: 4 << 10},
	{path: "opt", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtime-contexts", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes/pi", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes/pi/bin", kind: directoryEntry, mode: 0o755},
	{path: piBinaryPath, kind: regularEntry, mode: 0o555, maxBytes: 192 << 20},
	{path: piPackageJSONPath, kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: piPhotonWASMPath, kind: regularEntry, mode: 0o444, maxBytes: 8 << 20},
	{path: "opt/dirextalk-worker/runtimes/pi/bin/theme", kind: directoryEntry, mode: 0o755},
	{path: piDarkThemePath, kind: regularEntry, mode: 0o444, maxBytes: 256 << 10},
	{path: piLightThemePath, kind: regularEntry, mode: 0o444, maxBytes: 256 << 10},
	{path: piThemeSchemaPath, kind: regularEntry, mode: 0o444, maxBytes: 256 << 10},
	{path: "opt/dirextalk-worker/runtimes/pi/extensions", kind: directoryEntry, mode: 0o755},
	{path: piExtensionPath, kind: regularEntry, mode: 0o444, maxBytes: 256 << 10},
	{path: "usr", kind: directoryEntry, mode: 0o755},
	{path: "usr/local", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/bin", kind: directoryEntry, mode: 0o755},
	{path: workerBinaryPath, kind: regularEntry, mode: 0o555, maxBytes: 256 << 20},
	{path: installerBinaryPath, kind: regularEntry, mode: 0o555, maxBytes: 256 << 20},
	{path: "usr/local/share", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/share/dirextalk-worker", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/share/dirextalk-worker/ami", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/share/dirextalk-worker/ami/dirextalk-cloud-worker.service", kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: "usr/local/share/dirextalk-worker/ami/dirextalk-installer.tmpfiles", kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: "usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer-bootstrap.service", kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: "usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.service", kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: "usr/local/share/dirextalk-worker/ami/dirextalk-worker-installer.socket", kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: "usr/local/share/dirextalk-worker/ami/dirextalk-worker.sysusers", kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: "usr/local/share/dirextalk-worker/ami/dirextalk-worker.tmpfiles", kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: installerSidecarPath, kind: regularEntry, mode: 0o444, maxBytes: 65},
	{path: workerSidecarPath, kind: regularEntry, mode: 0o444, maxBytes: 65},
	{path: "var", kind: directoryEntry, mode: 0o755},
	{path: "var/lib", kind: directoryEntry, mode: 0o755},
	{path: "var/lib/dirextalk-worker", kind: directoryEntry, mode: 0o755},
}

type packedEntry struct {
	spec entrySpec
	data []byte
}

// Pack validates root as an exact exported Worker filesystem and creates a new
// deterministic USTAR archive at output. Existing output files are never
// replaced. If writing fails, the partial output is removed.
func Pack(root, output string) (ManifestV1, error) {
	rootPath, outputPath, err := validateArguments(root, output)
	if err != nil {
		return ManifestV1{}, err
	}
	entries, binaryDigest, err := snapshotRoot(rootPath)
	if err != nil {
		return ManifestV1{}, err
	}
	return writeArchive(outputPath, entries, binaryDigest)
}

// VerifyArchive independently parses the deterministic USTAR emitted by Pack,
// requires the exact closed entry set and canonical headers, and re-hashes both
// executables against their sidecars. The Worker digest must also equal the
// immutable release manifest supplied by the AMI publisher.
func VerifyArchive(reader io.Reader, expectedWorkerDigest string) error {
	if reader == nil || !strings.HasPrefix(expectedWorkerDigest, "sha256:") || len(expectedWorkerDigest) != len("sha256:")+sha256.Size*2 {
		return errors.New("invalid expected Worker digest")
	}
	expected := append([]entrySpec(nil), rootfsEntries...)
	sort.Slice(expected, func(i, j int) bool { return expected[i].path < expected[j].path })
	archive := tar.NewReader(reader)
	digests := make(map[string]string, 3)
	sidecars := make(map[string]string, 2)
	runtimeFiles := make(map[string][]byte, 6)
	epoch := time.Unix(0, 0).UTC()
	for _, spec := range expected {
		header, err := archive.Next()
		if err != nil {
			return errors.New("rootfs archive is missing a required entry")
		}
		name := spec.path
		kind := byte(tar.TypeReg)
		if spec.kind == directoryEntry {
			name += "/"
			kind = tar.TypeDir
		}
		if header.Name != name || header.Typeflag != kind || header.Mode != spec.mode || header.Uid != 0 || header.Gid != 0 ||
			header.Format != tar.FormatUSTAR || !header.ModTime.Equal(epoch) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() ||
			header.Linkname != "" || header.Uname != "" || header.Gname != "" || header.Devmajor != 0 || header.Devminor != 0 || len(header.PAXRecords) != 0 {
			return errors.New("rootfs archive header is not canonical")
		}
		if spec.kind == directoryEntry {
			if header.Size != 0 {
				return errors.New("rootfs archive directory has content")
			}
			continue
		}
		if header.Size < 0 || header.Size > spec.maxBytes {
			return errors.New("rootfs archive entry exceeds its fixed size limit")
		}
		var destination io.Writer = io.Discard
		var buffer strings.Builder
		hasher := sha256.New()
		switch spec.path {
		case workerBinaryPath, installerBinaryPath, piBinaryPath:
			destination = hasher
		case workerSidecarPath,
			installerSidecarPath,
			runtimeInstallPath,
			runtimeEnvironment,
			piPackageJSONPath,
			piPhotonWASMPath,
			piExtensionPath,
			piDarkThemePath,
			piLightThemePath,
			piThemeSchemaPath:
			buffer.Grow(int(header.Size))
			destination = &buffer
		}
		written, err := io.Copy(destination, io.LimitReader(archive, header.Size+1))
		if err != nil || written != header.Size {
			return errors.New("read rootfs archive entry")
		}
		switch spec.path {
		case workerBinaryPath, installerBinaryPath, piBinaryPath:
			digests[spec.path] = hex.EncodeToString(hasher.Sum(nil))
		case workerSidecarPath, installerSidecarPath:
			sidecars[spec.path] = buffer.String()
		case runtimeInstallPath,
			runtimeEnvironment,
			piPackageJSONPath,
			piPhotonWASMPath,
			piExtensionPath,
			piDarkThemePath,
			piLightThemePath,
			piThemeSchemaPath:
			runtimeFiles[spec.path] = []byte(buffer.String())
		}
	}
	if _, err := archive.Next(); err != io.EOF {
		return errors.New("rootfs archive contains an unexpected entry")
	}
	workerHex := digests[workerBinaryPath]
	installerHex := digests[installerBinaryPath]
	if workerHex == "" || installerHex == "" || sidecars[workerSidecarPath] != workerHex+"\n" ||
		sidecars[installerSidecarPath] != installerHex+"\n" || expectedWorkerDigest != "sha256:"+workerHex {
		return errors.New("rootfs executable digest binding does not match")
	}
	if verifyPiRuntimeBindings(
		runtimeFiles,
		digests[piBinaryPath],
	) != nil {
		return errors.New("rootfs Pi runtime binding does not match")
	}
	return nil
}

func validateArguments(root, output string) (string, string, error) {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(output) == "" {
		return "", "", errors.New("root and output are required")
	}
	rootPath, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", "", errors.New("resolve root")
	}
	providedRoot, err := os.Lstat(rootPath)
	if err != nil {
		return "", "", errors.New("inspect root")
	}
	if providedRoot.Mode()&os.ModeSymlink != 0 || !providedRoot.IsDir() {
		return "", "", errors.New("root must be a real directory")
	}
	rootPath, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return "", "", errors.New("resolve root")
	}
	outputPath, err := filepath.Abs(filepath.Clean(output))
	if err != nil {
		return "", "", errors.New("resolve output")
	}
	outputParent, err := filepath.EvalSymlinks(filepath.Dir(outputPath))
	if err != nil {
		return "", "", errors.New("resolve output")
	}
	outputPath = filepath.Join(outputParent, filepath.Base(outputPath))
	info, err := os.Lstat(rootPath)
	if err != nil {
		return "", "", errors.New("inspect root")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", errors.New("root must be a real directory")
	}
	if withinRoot(rootPath, outputPath) {
		return "", "", errors.New("output must be outside root")
	}
	return rootPath, outputPath, nil
}

func withinRoot(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func snapshotRoot(root string) ([]packedEntry, string, error) {
	allowed := make(map[string]entrySpec, len(rootfsEntries))
	for _, spec := range rootfsEntries {
		allowed[spec.path] = spec
	}
	seen := make(map[string]struct{}, len(rootfsEntries))
	entries := make([]packedEntry, 0, len(rootfsEntries))

	err := filepath.WalkDir(root, func(name string, dirEntry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("walk rootfs")
		}
		if name == root {
			return nil
		}
		relative, err := filepath.Rel(root, name)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("rootfs path escapes root")
		}
		archivePath := filepath.ToSlash(relative)
		if archivePath == "" || strings.HasPrefix(archivePath, "/") || strings.Contains(archivePath, "\\") {
			return errors.New("rootfs contains an invalid path")
		}
		spec, ok := allowed[archivePath]
		if !ok {
			return fmt.Errorf("rootfs contains unexpected path %q", archivePath)
		}
		if _, duplicate := seen[archivePath]; duplicate {
			return errors.New("rootfs contains duplicate path")
		}
		seen[archivePath] = struct{}{}

		info, err := dirEntry.Info()
		if err != nil {
			return errors.New("inspect rootfs entry")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("rootfs contains a symbolic link")
		}
		switch spec.kind {
		case directoryEntry:
			if !info.IsDir() {
				return errors.New("rootfs directory has invalid type")
			}
			entries = append(entries, packedEntry{spec: spec})
		case regularEntry:
			if !info.Mode().IsRegular() {
				return errors.New("rootfs file has invalid type")
			}
			content, err := readRegularFile(name, info, spec.maxBytes)
			if err != nil {
				return err
			}
			entries = append(entries, packedEntry{spec: spec, data: content})
		default:
			return errors.New("rootfs allow-list is invalid")
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}
	if len(seen) != len(rootfsEntries) {
		return nil, "", errors.New("rootfs is missing a required path")
	}

	content := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.spec.kind == regularEntry {
			content[entry.spec.path] = entry.data
		}
	}
	workerSum := sha256.Sum256(content[workerBinaryPath])
	workerHex := hex.EncodeToString(workerSum[:])
	if string(content[workerSidecarPath]) != workerHex+"\n" {
		return nil, "", errors.New("Worker binary digest sidecar does not match")
	}
	installerSum := sha256.Sum256(content[installerBinaryPath])
	if string(content[installerSidecarPath]) != hex.EncodeToString(installerSum[:])+"\n" {
		return nil, "", errors.New("installer binary digest sidecar does not match")
	}
	piSum := sha256.Sum256(content[piBinaryPath])
	if verifyPiRuntimeBindings(
		content,
		hex.EncodeToString(piSum[:]),
	) != nil {
		return nil, "", errors.New("Pi runtime installation does not match")
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].spec.path < entries[j].spec.path
	})
	return entries, "sha256:" + workerHex, nil
}

func verifyPiRuntimeBindings(
	content map[string][]byte,
	piExecutableHex string,
) error {
	if len(piExecutableHex) != sha256.Size*2 ||
		string(content[runtimeEnvironment]) !=
			"DIREXTALK_WORKER_RUNTIME_INSTALLATION_FILE="+
				"/etc/dirextalk-worker/runtime-installation.json\n" {
		return errors.New("invalid Pi runtime environment")
	}
	installation, err := workerruntime.ParseInstallationJSON(
		content[runtimeInstallPath],
	)
	if err != nil ||
		installation.SchemaVersion != workerruntime.InstallationSchemaV2 ||
		installation.RuntimeRelease.Adapter != workerruntime.AdapterPiV1 ||
		installation.RuntimeRelease.ExecutablePath !=
			workerruntime.DefaultPiExecutable ||
		installation.RuntimeRelease.ExecutableSHA256 !=
			"sha256:"+piExecutableHex ||
		len(installation.Models) != 1 ||
		installation.Models[0].ProfileID != "deepseek-v4-pro" ||
		installation.Models[0].Provider != "deepseek" ||
		installation.Models[0].Model != "deepseek-v4-pro" ||
		installation.Models[0].Interface !=
			workerruntime.ModelOpenAICompatible ||
		installation.Models[0].CredentialSlot != "model-token" {
		return errors.New("invalid Pi runtime installation")
	}
	extension, found := installation.Extension(
		workerruntime.PiResultExtensionName,
	)
	extensionSum := sha256.Sum256(content[piExtensionPath])
	if !found ||
		extension.Path != workerruntime.DefaultPiResultExtension ||
		extension.SHA256 !=
			"sha256:"+hex.EncodeToString(extensionSum[:]) {
		return errors.New("invalid Pi runtime extension")
	}
	for _, path := range []string{
		piDarkThemePath,
		piLightThemePath,
		piThemeSchemaPath,
	} {
		if len(content[path]) == 0 ||
			!json.Valid(content[path]) ||
			bytes.Contains(content[path], []byte{0}) {
			return errors.New("invalid Pi runtime theme")
		}
	}
	photon := content[piPhotonWASMPath]
	if len(photon) < 8 ||
		!bytes.Equal(photon[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		return errors.New("invalid Pi photon runtime")
	}
	var packageMetadata struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		PIConfig struct {
			ConfigDirectory string `json:"configDir"`
		} `json:"piConfig"`
	}
	if json.Unmarshal(
		content[piPackageJSONPath],
		&packageMetadata,
	) != nil ||
		packageMetadata.Name !=
			"@earendil-works/pi-coding-agent" ||
		packageMetadata.Version != "0.83.0" ||
		packageMetadata.PIConfig.ConfigDirectory != ".pi" {
		return errors.New("invalid Pi package metadata")
	}
	return nil
}

func readRegularFile(name string, initial os.FileInfo, maxBytes int64) ([]byte, error) {
	if initial.Size() < 0 || initial.Size() > maxBytes {
		return nil, errors.New("rootfs file exceeds its fixed size limit")
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, errors.New("open rootfs file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(initial, opened) {
		return nil, errors.New("rootfs file changed during validation")
	}
	links, err := regularFileLinkCount(file, opened)
	if err != nil {
		return nil, errors.New("inspect rootfs file links")
	}
	if links != 1 {
		return nil, errors.New("rootfs contains a hard link")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(content)) != opened.Size() || int64(len(content)) > maxBytes {
		return nil, errors.New("read rootfs file")
	}
	after, err := os.Lstat(name)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(opened, after) || after.Size() != int64(len(content)) {
		return nil, errors.New("rootfs file changed during validation")
	}
	return content, nil
}

func writeArchive(output string, entries []packedEntry, binaryDigest string) (manifest ManifestV1, err error) {
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ManifestV1{}, errors.New("create rootfs archive")
	}
	created := true
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if err != nil && created {
			_ = os.Remove(output)
		}
	}()
	if chmodErr := file.Chmod(0o600); chmodErr != nil {
		return ManifestV1{}, errors.New("set rootfs archive permissions")
	}

	hasher := sha256.New()
	archive := tar.NewWriter(io.MultiWriter(file, hasher))
	for _, entry := range entries {
		name := entry.spec.path
		header := &tar.Header{
			Name:       name,
			Mode:       entry.spec.mode,
			Uid:        0,
			Gid:        0,
			ModTime:    time.Unix(0, 0).UTC(),
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
			Format:     tar.FormatUSTAR,
		}
		if entry.spec.kind == directoryEntry {
			header.Name += "/"
			header.Typeflag = tar.TypeDir
		} else {
			header.Typeflag = tar.TypeReg
			header.Size = int64(len(entry.data))
		}
		if writeErr := archive.WriteHeader(header); writeErr != nil {
			return ManifestV1{}, errors.New("write rootfs archive header")
		}
		if len(entry.data) > 0 {
			if _, writeErr := archive.Write(entry.data); writeErr != nil {
				return ManifestV1{}, errors.New("write rootfs archive content")
			}
		}
	}
	if closeErr := archive.Close(); closeErr != nil {
		return ManifestV1{}, errors.New("finalize rootfs archive")
	}
	if syncErr := file.Sync(); syncErr != nil {
		return ManifestV1{}, errors.New("sync rootfs archive")
	}
	info, statErr := file.Stat()
	if statErr != nil {
		return ManifestV1{}, errors.New("inspect rootfs archive")
	}
	if closeErr := file.Close(); closeErr != nil {
		file = nil
		return ManifestV1{}, errors.New("close rootfs archive")
	}
	file = nil
	created = false
	return ManifestV1{
		Schema:       SchemaV1,
		RootFSDigest: "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		BinaryDigest: binaryDigest,
		Size:         info.Size(),
	}, nil
}
