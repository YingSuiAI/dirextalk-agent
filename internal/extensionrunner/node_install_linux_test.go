//go:build linux

package extensionrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func nodeBuildRequestFixture() NodeBuildRequestV1 {
	return NodeBuildRequestV1{Op: "build_node_v1", InputDigest: strings.Repeat("a", 64), CleanupToken: uuid.NewString(), ContentSize: 1, ContentSHA256: strings.Repeat("a", 64), EntryPath: "server.js", EntrySHA256: strings.Repeat("b", 64), PackageName: "fixture", PackageVersion: "1.2.3", LockSHA256: strings.Repeat("c", 64)}
}

func nodeReceiptFixture(entries []ManifestEntry) NodeBuildReceiptV1 {
	var size uint64
	for _, entry := range entries {
		size += uint64(entry.Size)
	}
	return NodeBuildReceiptV1{InputDigest: strings.Repeat("a", 64), ArtifactDigest: ManifestDigest(entries), ArtifactBytes: size, FileCount: uint32(len(entries)), EntryPath: "server.js", EntrySHA256: entries[0].SHA256, PackageName: "fixture", PackageVersion: "1.2.3", LockSHA256: strings.Repeat("c", 64), NodeVersion: ManagedNodeVersionV1, NPMVersion: ManagedNPMVersionV1, LifecycleScriptsDisabled: true, NativeAddonsAbsent: true}
}

func TestNodeBuildProtocolLocksExactRuntimeAndLimits(t *testing.T) {
	request := nodeBuildRequestFixture()
	if err := request.Validate(1); err != nil {
		t.Fatal(err)
	}
	receipt := NodeBuildReceiptV1{InputDigest: request.InputDigest, ArtifactDigest: strings.Repeat("d", 64), ArtifactBytes: uint64(MaxNodeArtifactBytes), FileCount: MaxNodeArtifactFiles, EntryPath: request.EntryPath, EntrySHA256: request.EntrySHA256, PackageName: request.PackageName, PackageVersion: request.PackageVersion, LockSHA256: request.LockSHA256, NodeVersion: "v24.18.1", NPMVersion: "11.16.0", LifecycleScriptsDisabled: true, NativeAddonsAbsent: true}
	if err := receipt.Validate(); err != nil {
		t.Fatal(err)
	}
	receipt.ArtifactBytes++
	if err := receipt.Validate(); err == nil {
		t.Fatal("expanded artifact above 64 MiB accepted")
	}
	receipt.ArtifactBytes = 1
	receipt.FileCount = MaxNodeArtifactFiles + 1
	if err := receipt.Validate(); err == nil {
		t.Fatal("expanded artifact above 8192 files accepted")
	}
}

func TestNodeBuildReceiptRejectsOldLifecycleKeyAndDisabledFalse(t *testing.T) {
	receipt := nodeReceiptFixture([]ManifestEntry{{Path: "server.js", SHA256: strings.Repeat("b", 64), Size: 1}})
	payload, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := bytes.Replace(payload, []byte(`"lifecycle_scripts_disabled"`), []byte(`"lifecycle_scripts_absent"`), 1)
	var decoded NodeBuildReceiptV1
	if decodeCanonicalNode(oldKey, &decoded) == nil {
		t.Fatal("accepted superseded lifecycle_scripts_absent key")
	}
	receipt.LifecycleScriptsDisabled = false
	if err := receipt.Validate(); err == nil {
		t.Fatal("accepted lifecycle_scripts_disabled=false")
	}
}

func TestVerifySealedNodeSourceNeverTakesOwnershipOfCallerFD(t *testing.T) {
	content := []byte("sealed source ownership fixture")
	fd, err := sealedMemfd("node-source-ownership", content)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := verifySealedNodeSource(fd, int64(len(content)), DigestBytes(content)); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	runtime.Gosched()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		t.Fatalf("caller-owned source descriptor was closed: %v", err)
	}
}

func TestNodeInstallSlotRejectsSecondBuildBeforeWork(t *testing.T) {
	request := nodeBuildRequestFixture()
	payload, _ := json.Marshal(request)
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	server := Server{NodeBuilder: &NodeOfflineBuilder{}, NodeInstallSlots: slots}
	response := server.buildNode(context.Background(), payload, []int{0})
	if response.Error != "capacity" {
		t.Fatalf("response=%+v", response)
	}
}

func TestNodeOfflineInstallLongStepEmitsSafeHeartbeat(t *testing.T) {
	var output bytes.Buffer
	builder := &NodeOfflineBuilder{Logger: slog.New(slog.NewTextHandler(&output, nil)), heartbeatEvery: 5 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		builder.heartbeat(ctx, done)
	}()
	time.Sleep(18 * time.Millisecond)
	close(done)
	cancel()
	<-exited
	log := output.String()
	if !strings.Contains(log, "phase=offline_install") || !strings.Contains(log, "state=running") || strings.Contains(log, "fixture") || strings.Contains(log, "https://") {
		t.Fatalf("unsafe or missing heartbeat: %q", log)
	}
}

func TestCleanupNPMInstallStateExcludesInstallerCacheAndLogs(t *testing.T) {
	root := t.TempDir()
	for path, body := range map[string][]byte{
		".npm-cache/_logs/install.log":         []byte("private resolver output"),
		".npmrc":                               []byte("//registry.example/:_authToken=secret"),
		"node-compile-cache/v24/cache":         []byte("compiled npm internals"),
		"npm-debug.log.1":                      []byte("debug"),
		"node_modules/.bin/dependency":         []byte("generated command shim"),
		"node_modules/.package-lock.json":      []byte("{}"),
		"node_modules/dependency/package.json": []byte("{}"),
	} {
		mustWriteNodeTestFile(t, root, path, body)
	}
	if err := cleanupNPMInstallState(root); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{".npm-cache", ".npmrc", "node-compile-cache", "npm-debug.log.1", "node_modules/.package-lock.json", "node_modules/.bin"} {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(path))); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("installer state %q remains: %v", path, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "node_modules/dependency/package.json")); err != nil {
		t.Fatalf("runtime dependency removed: %v", err)
	}
}

func TestVerifyExpandedNodeTreeAllowsLifecycleDeclarationsBecauseInstallDisablesScripts(t *testing.T) {
	for _, lifecycle := range []string{"prepublish", "preprepare", "prepare", "postprepare", "preinstall", "install", "postinstall"} {
		t.Run(lifecycle, func(t *testing.T) {
			root := t.TempDir()
			entry := []byte("console.log('ok')")
			mustWriteNodeTestFile(t, root, "server.js", entry)
			mustWriteNodeTestFile(t, root, "package.json", []byte(`{"name":"fixture","version":"1.2.3","scripts":{"`+lifecycle+`":"malicious"}}`))
			request := nodeBuildRequestFixture()
			request.EntrySHA256 = DigestBytes(entry)
			entries, _, err := verifyExpandedNodeTree(root, request)
			if err != nil || len(entries) != 2 || entries[0].Path != "package.json" || entries[0].SHA256 != DigestBytes([]byte(`{"name":"fixture","version":"1.2.3","scripts":{"`+lifecycle+`":"malicious"}}`)) {
				t.Fatalf("lifecycle %q err=%v", lifecycle, err)
			}
		})
	}
}

func TestVerifyExpandedNodeTreeRejectsNativeOutputButAllowsOrdinaryBuildDirectory(t *testing.T) {
	for _, native := range []string{"addon.node", "addon.so", "addon.dll", "addon.dylib", "addon.a", "addon.o", "binding.gyp"} {
		t.Run(native, func(t *testing.T) {
			root := t.TempDir()
			entry := []byte("console.log('ok')")
			mustWriteNodeTestFile(t, root, "server.js", entry)
			mustWriteNodeTestFile(t, root, "package.json", []byte(`{"name":"fixture","version":"1.2.3"}`))
			mustWriteNodeTestFile(t, root, native, []byte("native"))
			request := nodeBuildRequestFixture()
			request.EntrySHA256 = DigestBytes(entry)
			if _, _, err := verifyExpandedNodeTree(root, request); !errors.Is(err, ErrDenied) {
				t.Fatalf("native %q err=%v", native, err)
			}
		})
	}
	root := t.TempDir()
	entry := []byte("console.log('ok')")
	mustWriteNodeTestFile(t, root, "server.js", entry)
	mustWriteNodeTestFile(t, root, "package.json", []byte(`{"name":"fixture","version":"1.2.3"}`))
	mustWriteNodeTestFile(t, root, "build/output.js", []byte("ordinary build output"))
	request := nodeBuildRequestFixture()
	request.EntrySHA256 = DigestBytes(entry)
	if _, _, err := verifyExpandedNodeTree(root, request); err != nil {
		t.Fatalf("ordinary build directory rejected: %v", err)
	}
}

func TestNodeOfflineNPMEnvironmentDisablesLifecycleScripts(t *testing.T) {
	env := nodeOfflineNPMEnvironment("/tmp/node-root")
	if !slices.Contains(env, "npm_config_ignore_scripts=true") {
		t.Fatalf("offline npm environment does not disable scripts: %q", env)
	}
	args := nodeOfflineNPMArguments("/runtime", "/runtime/node", "/runtime/npm-cli.js")
	if !slices.Contains(args, "ci") || !slices.Contains(args, "--offline") || !slices.Contains(args, "--ignore-scripts") {
		t.Fatalf("offline npm arguments do not enforce scripts-disabled install: %q", args)
	}
}

func TestVerifyExpandedNodeTreeRejectsArtifactBytesAndFileCount(t *testing.T) {
	t.Run("bytes", func(t *testing.T) {
		root := t.TempDir()
		mustWriteNodeTestFile(t, root, "server.js", []byte("ok"))
		if err := os.Truncate(filepath.Join(root, "server.js"), MaxNodeArtifactBytes+1); err != nil {
			t.Fatal(err)
		}
		request := nodeBuildRequestFixture()
		if _, _, err := verifyExpandedNodeTree(root, request); !errors.Is(err, ErrNodeInstallCapacity) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("files", func(t *testing.T) {
		root := t.TempDir()
		for index := 0; index <= MaxNodeArtifactFiles; index++ {
			mustWriteNodeTestFile(t, root, "f/"+leftPad(index)+".js", nil)
		}
		request := nodeBuildRequestFixture()
		request.EntryPath = "f/00000.js"
		request.EntrySHA256 = DigestBytes(nil)
		if _, _, err := verifyExpandedNodeTree(root, request); !errors.Is(err, ErrNodeInstallCapacity) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestNodePreparedPromoteReferenceAndCleanupLifecycle(t *testing.T) {
	publication := t.TempDir()
	prepared := filepath.Join(publication, ".prepared")
	if err := os.Mkdir(prepared, 0o700); err != nil {
		t.Fatal(err)
	}
	builder := &NodeOfflineBuilder{PublicationRoot: publication, PreparedRoot: prepared}
	if !safeRunnerRoot(publication) || !safeRunnerRoot(prepared) {
		t.Fatalf("unsafe fixture roots publication=%v prepared=%v", safeRunnerRoot(publication), safeRunnerRoot(prepared))
	}
	token := uuid.NewString()
	entry := []byte("console.log('ok')")
	entries := []ManifestEntry{{Path: "server.js", SHA256: DigestBytes(entry), Size: int64(len(entry))}}
	receipt := nodeReceiptFixture(entries)
	if err := receipt.Validate(); err != nil {
		t.Fatalf("receipt: %v %+v", err, receipt)
	}
	root := filepath.Join(prepared, receipt.ArtifactDigest, token)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	mustWriteNodeTestFile(t, root, "server.js", entry)
	manifest, _ := json.Marshal(DiskInstallManifestV1{SchemaVersion: installManifestSchemaV1, Entries: entries})
	mustWriteNodeTestFile(t, root, installManifestName, append(manifest, '\n'))
	metadata, _ := json.Marshal(nodeInstallMetadataV1{SchemaVersion: NodeInstallManifestV1})
	mustWriteNodeTestFile(t, root, nodeInstallMetadataName, append(metadata, '\n'))
	// The metadata is part of real manifests. This focused lifecycle fixture
	// keeps the receipt minimal, so remove it after making the tree recognizable
	// to storage accounting and before immutable admission.
	if err := os.Remove(filepath.Join(root, nodeInstallMetadataName)); err != nil {
		t.Fatal(err)
	}
	if err := makeNodeTreeImmutable(root); err != nil {
		t.Fatal(err)
	}
	if admitted, err := OpenAdmittedBundle(root, receipt.ArtifactDigest, entries); err != nil {
		t.Fatalf("bundle fixture admission: %v", err)
	} else {
		_ = admitted.Close()
	}
	if admitted, err := resolveNodeBundle(root, receipt); err != nil {
		t.Fatalf("prepared fixture admission: %v", err)
	} else {
		_ = admitted.Close()
	}
	promote := NodePromoteRequestV1{Op: "promote_node_v1", CleanupToken: token, Receipt: receipt}
	if err := promote.Validate(); err != nil {
		t.Fatalf("promote request: %v", err)
	}
	if err := builder.Promote(promote); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(publication, receipt.ArtifactDigest)); err != nil {
		t.Fatal(err)
	}
	if err := builder.Remove(NodeRemoveRequestV1{Op: "remove_node_v1", Scope: "active", Digest: receipt.ArtifactDigest, CleanupToken: token}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(publication, receipt.ArtifactDigest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active tree remains: %v", err)
	}
	if err := builder.Remove(NodeRemoveRequestV1{Op: "remove_node_v1", Scope: "active", Digest: receipt.ArtifactDigest, CleanupToken: token}); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
	if _, err := os.Stat(filepath.Join(prepared, receipt.ArtifactDigest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("empty prepared digest parent remains: %v", err)
	}
}

func TestNodeRemoveRejectsWrongAndMissingOwnershipTokens(t *testing.T) {
	digest := strings.Repeat("d", 64)
	correct := uuid.NewString()
	wrong := uuid.NewString()
	t.Run("prepared wrong token", func(t *testing.T) {
		publication := t.TempDir()
		prepared := t.TempDir()
		target := filepath.Join(prepared, digest, correct)
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
		builder := &NodeOfflineBuilder{PublicationRoot: publication, PreparedRoot: prepared}
		err := builder.Remove(NodeRemoveRequestV1{Op: "remove_node_v1", Scope: "prepared", Digest: digest, CleanupToken: wrong})
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("wrong prepared token err=%v", err)
		}
		if _, err := os.Stat(target); err != nil {
			t.Fatalf("owned prepared tree removed: %v", err)
		}
	})
	t.Run("prepared missing ref", func(t *testing.T) {
		publication := t.TempDir()
		prepared := t.TempDir()
		builder := &NodeOfflineBuilder{PublicationRoot: publication, PreparedRoot: prepared}
		err := builder.Remove(NodeRemoveRequestV1{Op: "remove_node_v1", Scope: "prepared", Digest: digest, CleanupToken: correct})
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("missing prepared ref err=%v", err)
		}
	})
	t.Run("active wrong token", func(t *testing.T) {
		builder, publication, prepared := nodeActiveRemoveFixture(t, digest, correct)
		err := builder.Remove(NodeRemoveRequestV1{Op: "remove_node_v1", Scope: "active", Digest: digest, CleanupToken: wrong})
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("wrong active token err=%v", err)
		}
		if _, err := os.Stat(filepath.Join(publication, digest)); err != nil {
			t.Fatalf("active tree removed: %v", err)
		}
		if _, err := os.Stat(filepath.Join(prepared, ".active-refs", digest, correct)); err != nil {
			t.Fatalf("correct ref removed: %v", err)
		}
	})
	t.Run("active missing ref", func(t *testing.T) {
		builder, publication, prepared := nodeActiveRemoveFixture(t, digest, correct)
		if err := os.Remove(filepath.Join(prepared, ".active-refs", digest, correct)); err != nil {
			t.Fatal(err)
		}
		err := builder.Remove(NodeRemoveRequestV1{Op: "remove_node_v1", Scope: "active", Digest: digest, CleanupToken: correct})
		if !errors.Is(err, ErrDenied) {
			t.Fatalf("missing active ref err=%v", err)
		}
		if _, err := os.Stat(filepath.Join(publication, digest)); err != nil {
			t.Fatalf("active tree removed: %v", err)
		}
	})
}

func TestNodeActiveRemoveFailsClosedOnReadDirError(t *testing.T) {
	digest := strings.Repeat("d", 64)
	token := uuid.NewString()
	builder, publication, prepared := nodeActiveRemoveFixture(t, digest, token)
	builder.readDir = func(string) ([]os.DirEntry, error) { return nil, os.ErrPermission }
	request := NodeRemoveRequestV1{Op: "remove_node_v1", Scope: "active", Digest: digest, CleanupToken: token}
	if err := builder.Remove(request); !errors.Is(err, ErrDenied) {
		t.Fatalf("ReadDir failure err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(publication, digest)); err != nil {
		t.Fatalf("active tree removed after ReadDir failure: %v", err)
	}
	restarted := &NodeOfflineBuilder{PublicationRoot: publication, PreparedRoot: prepared}
	if err := restarted.Remove(request); err != nil {
		t.Fatalf("restart exact pending replay did not recover: %v", err)
	}
	if _, err := os.Stat(filepath.Join(publication, digest)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active tree remains after recovered replay: %v", err)
	}
}

func TestNodeRemoveExactReplayPersistsAcrossRestart(t *testing.T) {
	digest := strings.Repeat("d", 64)
	token := uuid.NewString()
	builder, publication, prepared := nodeActiveRemoveFixture(t, digest, token)
	request := NodeRemoveRequestV1{Op: "remove_node_v1", Scope: "active", Digest: digest, CleanupToken: token}
	if err := builder.Remove(request); err != nil {
		t.Fatal(err)
	}
	if err := builder.Remove(request); err != nil {
		t.Fatalf("same-process exact replay: %v", err)
	}
	restarted := &NodeOfflineBuilder{PublicationRoot: publication, PreparedRoot: prepared}
	if err := restarted.Remove(request); err != nil {
		t.Fatalf("restart exact replay: %v", err)
	}
	wrong := request
	wrong.CleanupToken = uuid.NewString()
	if err := restarted.Remove(wrong); !errors.Is(err, ErrDenied) {
		t.Fatalf("wrong-token replay err=%v", err)
	}
}

func TestNodePreparedRemoveExactReplayPersistsAcrossRestart(t *testing.T) {
	digest := strings.Repeat("d", 64)
	token := uuid.NewString()
	publication := t.TempDir()
	prepared := t.TempDir()
	target := filepath.Join(prepared, digest, token)
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	request := NodeRemoveRequestV1{Op: "remove_node_v1", Scope: "prepared", Digest: digest, CleanupToken: token}
	builder := &NodeOfflineBuilder{PublicationRoot: publication, PreparedRoot: prepared}
	if err := builder.Remove(request); err != nil {
		t.Fatal(err)
	}
	restarted := &NodeOfflineBuilder{PublicationRoot: publication, PreparedRoot: prepared}
	if err := restarted.Remove(request); err != nil {
		t.Fatalf("restart exact replay: %v", err)
	}
}

func TestNodeStorageQuotaCountsExistingPreparedAndActiveOnce(t *testing.T) {
	publication := t.TempDir()
	prepared := t.TempDir()
	active := filepath.Join(publication, strings.Repeat("d", 64))
	if err := os.Mkdir(active, 0o700); err != nil {
		t.Fatal(err)
	}
	metadata := []byte("{}")
	mustWriteNodeTestFile(t, active, nodeInstallMetadataName, metadata)
	remaining := int64(100)
	if err := os.WriteFile(filepath.Join(active, "payload"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(filepath.Join(active, "payload"), MaxNodeStorageBytes-int64(len(metadata))-remaining); err != nil {
		t.Fatal(err)
	}
	builder := &NodeOfflineBuilder{PublicationRoot: publication, PreparedRoot: prepared}
	if err := builder.ensurePhysicalQuota(remaining); err != nil {
		t.Fatalf("exact storage boundary rejected: %v", err)
	}
	if err := builder.ensurePhysicalQuota(remaining + 1); !errors.Is(err, ErrNodeInstallCapacity) {
		t.Fatalf("storage overflow err=%v", err)
	}
}

func mustWriteNodeTestFile(t *testing.T, root, relative string, body []byte) {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

func nodeActiveRemoveFixture(t *testing.T, digest, token string) (*NodeOfflineBuilder, string, string) {
	t.Helper()
	publication := t.TempDir()
	prepared := t.TempDir()
	if err := os.Mkdir(filepath.Join(publication, digest), 0o500); err != nil {
		t.Fatal(err)
	}
	builder := &NodeOfflineBuilder{PublicationRoot: publication, PreparedRoot: prepared}
	if err := builder.addActiveReference(digest, token); err != nil {
		t.Fatal(err)
	}
	return builder, publication, prepared
}

func leftPad(value int) string {
	text := fmt.Sprint(value)
	return strings.Repeat("0", 5-len(text)) + text
}
