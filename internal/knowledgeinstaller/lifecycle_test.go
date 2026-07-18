package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type lifecycleProbe struct {
	err   error
	calls int
}

func (probe *lifecycleProbe) RoundTrip(_ context.Context, request map[string]any) (map[string]any, error) {
	probe.calls++
	if probe.err != nil {
		return nil, probe.err
	}
	switch request["operation"] {
	case "store_memory":
		return map[string]any{"ok": true, "operation_id": request["operation_id"], "result": map[string]any{
			"owner_id": probeOwnerID, "binding_id": probeBindingID, "point_id": probePointID, "source_id": probeMemoryID,
			"revision_id": probeRevision, "content_size": float64(49), "content_sha256": probeDigest, "indexed_segment_count": float64(1),
		}}, nil
	case "search":
		return map[string]any{"ok": true, "operation_id": request["operation_id"], "result": map[string]any{"results": []any{map[string]any{
			"point_id": probePointID, "owner_id": probeOwnerID, "binding_id": probeBindingID, "source_id": probeMemoryID,
			"revision_id": probeRevision, "kind": "memory", "content_size": float64(49), "content_sha256": probeDigest,
		}}}}, nil
	case "status":
		return map[string]any{"ok": true, "operation_id": request["operation_id"], "result": map[string]any{
			"owner_id": probeOwnerID, "binding_id": probeBindingID, "ready": true, "model": "intfloat/multilingual-e5-small",
			"model_revision": ModelRevision, "dimensions": float64(384), "execution_provider": "CPUExecutionProvider",
			"collection": "dirextalk_knowledge_v1", "status": "green", "persistence": map[string]any{
				"verified": true, "point_id": probePointID, "source_id": probeMemoryID, "revision_id": probeRevision,
				"content_size": float64(49), "content_sha256": probeDigest,
			},
		}}, nil
	default:
		return nil, errors.New("unexpected operation")
	}
}

func TestKnowledgeBackupRestoreIsDurableIdempotentAndExcludesSecrets(t *testing.T) {
	t.Parallel()
	paths, err := TestPaths(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	prepareLifecycleFixture(t, paths)
	canary := "deepseek-secret-canary-must-not-enter-backup"
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "qdrant-v1")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "adapter-v1")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/secrets/qdrant-api-key"), canary)
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/tls/qdrant.key"), canary)
	runner, probe := &fakeRunner{}, &lifecycleProbe{}
	value := Installer{Paths: paths, Runner: runner, Probe: probe}
	if err := value.BackupV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	generation, err := (GenerationObserver{Paths: paths}).CurrentGeneration(context.Background())
	if err != nil || generation == "" {
		t.Fatalf("backup generation=%q error=%v", generation, err)
	}
	manifestBefore, err := os.ReadFile(paths.Resolve(BackupCurrentRoot + "/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if backupTreeContains(t, paths.Resolve(BackupCurrentRoot), canary) {
		t.Fatal("backup persisted secret or TLS bytes")
	}
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "qdrant-v2")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "adapter-v2")
	if drifted, err := (GenerationObserver{Paths: paths}).CurrentGeneration(context.Background()); err == nil || drifted != "" {
		t.Fatalf("drifted live generation=%q error=%v", drifted, err)
	}
	if err := value.RestoreV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restored, err := (GenerationObserver{Paths: paths}).CurrentGeneration(context.Background()); err != nil || restored != generation {
		t.Fatalf("restored generation=%q want=%q error=%v", restored, generation, err)
	}
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "qdrant-v1")
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "adapter-v1")
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/secrets/qdrant-api-key"), canary)
	if probe.calls != 3 {
		t.Fatalf("semantic restore verification calls = %d", probe.calls)
	}
	if err := value.BackupV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	manifestAfter, _ := os.ReadFile(paths.Resolve(BackupCurrentRoot + "/manifest.json"))
	if string(manifestAfter) != string(manifestBefore) {
		t.Fatal("exact backup replay changed the durable manifest")
	}
	writeLifecycleFile(t, paths.Resolve(BackupCurrentRoot+"/adapter/ledger.db"), "corrupt")
	if err := value.BackupV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertLifecycleFile(t, paths.Resolve(BackupCurrentRoot+"/adapter/ledger.db"), "adapter-v1")
	for _, path := range []string{BackupStageRoot, RestoreStageRoot, RestorePreviousRoot, RestoreJournalPath} {
		if _, err := os.Lstat(paths.Resolve(path)); !os.IsNotExist(err) {
			t.Fatalf("temporary lifecycle state remains at %s", path)
		}
	}
}

func TestKnowledgeRestoreRollsBackLiveStateWhenSemanticVerificationFails(t *testing.T) {
	t.Parallel()
	paths, _ := TestPaths(t.TempDir())
	prepareLifecycleFixture(t, paths)
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "backup-state")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "backup-state")
	runner := &fakeRunner{}
	value := Installer{Paths: paths, Runner: runner, Probe: &lifecycleProbe{}}
	if err := value.BackupV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "live-state")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "live-state")
	value.Probe = &lifecycleProbe{err: errors.New("semantic unavailable")}
	if err := value.RestoreV1(context.Background()); err == nil || strings.Contains(err.Error(), "live-state") {
		t.Fatalf("restore error = %v", err)
	}
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "live-state")
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "live-state")
	for _, path := range []string{RestoreStageRoot, RestorePreviousRoot, RestoreJournalPath} {
		if _, err := os.Lstat(paths.Resolve(path)); !os.IsNotExist(err) {
			t.Fatalf("failed restore left unsafe state at %s", path)
		}
	}
}

func TestKnowledgeRestoreCrashRecoveryRequiresObservedTargetAfterPostSwapRestartFailures(t *testing.T) {
	t.Parallel()
	paths, _ := TestPaths(t.TempDir())
	prepareLifecycleFixture(t, paths)
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "target-generation")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "target-generation")
	if err := (Installer{Paths: paths, Runner: &fakeRunner{}, Probe: &lifecycleProbe{}}).
		BackupV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	targetGeneration, err := (GenerationObserver{Paths: paths}).CurrentGeneration(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "original-generation")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "original-generation")
	failing := &failSetRunner{failures: map[int]error{
		4: errors.New("post-swap target restart failed"),
		8: errors.New("post-rollback original restart failed"),
	}}
	first := Installer{Paths: paths, Runner: failing, Probe: &lifecycleProbe{}}
	if err := first.RestoreV1(context.Background()); err == nil {
		t.Fatal("post-swap and rollback restart failures were reported as recovered")
	}
	recoveredOriginalGeneration, err := (GenerationObserver{Paths: paths}).CurrentGeneration(context.Background())
	if err != nil || recoveredOriginalGeneration == "" || recoveredOriginalGeneration == targetGeneration {
		t.Fatalf("durable original recovery generation=%q target=%q error=%v",
			recoveredOriginalGeneration, targetGeneration, err)
	}

	// A new process must recover the same fixed operation idempotently. It
	// cannot release the control-plane fence until the root observer can bind
	// the live target to the durable generation.
	restarted := Installer{Paths: paths, Runner: &fakeRunner{}, Probe: &lifecycleProbe{}}
	if err := restarted.RestoreV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	if observed, err := (GenerationObserver{Paths: paths}).CurrentGeneration(context.Background()); err != nil ||
		observed != recoveredOriginalGeneration {
		t.Fatalf("recovered original generation=%q want=%q error=%v", observed, recoveredOriginalGeneration, err)
	}
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "original-generation")
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "original-generation")
}

func TestKnowledgeRestoreResumesSwappedJournalWithoutRepeatingTheMutation(t *testing.T) {
	t.Parallel()
	paths, _ := TestPaths(t.TempDir())
	prepareLifecycleFixture(t, paths)
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "backup-state")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "backup-state")
	value := Installer{Paths: paths, Runner: &fakeRunner{}, Probe: &lifecycleProbe{}}
	if err := value.BackupV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "later-live-state")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "later-live-state")
	manifest, encoded, err := loadAndVerifyBackup(paths)
	if err != nil {
		t.Fatal(err)
	}
	if err := prepareRestore(paths, manifest, encoded); err != nil {
		t.Fatal(err)
	}
	if err := value.StopV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := swapRestore(paths, encoded); err != nil {
		t.Fatal(err)
	}
	runner, probe := &fakeRunner{}, &lifecycleProbe{}
	value.Runner, value.Probe = runner, probe
	if err := value.RestoreV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "backup-state")
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "backup-state")
	if probe.calls != 3 || len(runner.commands) != 5 {
		t.Fatalf("recovered restore repeated lifecycle mutation: probe=%d commands=%d", probe.calls, len(runner.commands))
	}
	for _, path := range []string{RestoreStageRoot, RestorePreviousRoot, RestoreJournalPath} {
		if _, err := os.Lstat(paths.Resolve(path)); !os.IsNotExist(err) {
			t.Fatalf("recovered restore left state at %s", path)
		}
	}
}

func TestKnowledgeDestroyIsFixedIdempotentAndPreservesSecretSlotSource(t *testing.T) {
	t.Parallel()
	paths, _ := TestPaths(t.TempDir())
	prepareLifecycleFixture(t, paths)
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "private-index")
	writeLifecycleFile(t, paths.Resolve(APIKeySourcePath), "source-secret-remains")
	outside := paths.Resolve("/var/lib/other-service/data")
	writeLifecycleFile(t, outside, "outside-remains")
	runner := &fakeRunner{}
	value := Installer{Paths: paths, Runner: runner}
	if err := value.DestroyV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := value.DestroyV1(context.Background()); err != nil {
		t.Fatalf("destroy replay failed: %v", err)
	}
	for _, path := range []string{PersistentRoot, InstallRoot, QdrantConfigPath, QdrantUnitPath, AdapterUnitPath, RuntimeRoot} {
		if _, err := os.Lstat(paths.Resolve(path)); !os.IsNotExist(err) {
			t.Fatalf("destroyed boundary remains at %s", path)
		}
	}
	if info, err := os.Lstat(paths.Resolve(LifecycleLockPath)); err != nil || !info.Mode().IsRegular() {
		t.Fatal("destroy removed the held lifecycle lock inode")
	}
	assertLifecycleFile(t, paths.Resolve(APIKeySourcePath), "source-secret-remains")
	assertLifecycleFile(t, outside, "outside-remains")
}

func TestKnowledgeDestroyRejectsUnitDriftBeforeCommandsOrDeletion(t *testing.T) {
	t.Parallel()
	paths, _ := TestPaths(t.TempDir())
	prepareLifecycleFixture(t, paths)
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "retained")
	if err := os.WriteFile(paths.Resolve(AdapterUnitPath), []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	if err := (Installer{Paths: paths, Runner: runner}).DestroyV1(context.Background()); err == nil {
		t.Fatal("destroy accepted a drifted service unit")
	}
	if len(runner.commands) != 0 {
		t.Fatal("destroy ran systemd commands before validating every unit")
	}
	assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "retained")
}

func TestKnowledgeDestroyRejectsMissingUnitWhileOwnedStateRemains(t *testing.T) {
	t.Parallel()
	for _, missing := range []string{AdapterUnitPath, QdrantUnitPath} {
		t.Run(missing, func(t *testing.T) {
			paths, _ := TestPaths(t.TempDir())
			prepareLifecycleFixture(t, paths)
			writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "retained")
			if err := os.Remove(paths.Resolve(missing)); err != nil {
				t.Fatal(err)
			}
			runner := &fakeRunner{}
			if err := (Installer{Paths: paths, Runner: runner}).DestroyV1(context.Background()); err == nil {
				t.Fatal("destroy accepted missing unit while owned state remained")
			}
			if len(runner.commands) != 0 {
				t.Fatal("destroy ran systemd commands before fencing missing units")
			}
			assertLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "retained")
		})
	}
}

func TestEveryPublicLifecycleCommandUsesOneNonblockingLock(t *testing.T) {
	t.Parallel()
	paths, _ := TestPaths(t.TempDir())
	unlock, err := acquireLifecycleLock(paths)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	runner := &fakeRunner{}
	value := Installer{
		Paths: paths, Runner: runner, Probe: &lifecycleProbe{},
		Identities: lifecycleIdentityResolver{}, Materializer: lifecycleMaterializer{},
	}
	commands := map[string]func(context.Context) error{
		"install": value.InstallV1, "restart": value.RestartV1, "probe": value.SemanticProbeV1,
		"stop": value.StopV1, "backup": value.BackupV1, "restore": value.RestoreV1,
		"upgrade": value.UpgradeV1, "rollback": value.RollbackV1, "destroy": value.DestroyV1,
	}
	for name, call := range commands {
		t.Run(name, func(t *testing.T) {
			if err := call(context.Background()); err == nil || !strings.Contains(err.Error(), "acquire lifecycle lock") {
				t.Fatalf("lock error=%v", err)
			}
		})
	}
	if len(runner.commands) != 0 {
		t.Fatal("locked public command reached an external command")
	}
}

func TestLifecycleLockRejectsSymlinkSharedRootAndReplaceableInode(t *testing.T) {
	t.Parallel()
	for _, setup := range []struct {
		name string
		run  func(*testing.T, Paths)
	}{
		{
			name: "symlink",
			run: func(t *testing.T, paths Paths) {
				if err := os.MkdirAll(paths.Resolve(LifecycleLockRoot), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("/tmp/attacker-lock", paths.Resolve(LifecycleLockPath)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "shared-root",
			run: func(t *testing.T, paths Paths) {
				if err := os.MkdirAll(paths.Resolve(LifecycleLockRoot), 0o777); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(paths.Resolve(LifecycleLockRoot), 0o777); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "replaceable-hardlink",
			run: func(t *testing.T, paths Paths) {
				if err := os.MkdirAll(paths.Resolve(LifecycleLockRoot), 0o700); err != nil {
					t.Fatal(err)
				}
				outside := filepath.Join(t.TempDir(), "attacker-reference")
				if err := os.WriteFile(outside, nil, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(outside, paths.Resolve(LifecycleLockPath)); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(setup.name, func(t *testing.T) {
			paths, _ := TestPaths(t.TempDir())
			setup.run(t, paths)
			if unlock, err := acquireLifecycleLock(paths); err == nil {
				unlock()
				t.Fatal("unsafe lifecycle lock boundary was accepted")
			}
		})
	}
}

func TestBackupRotationJournalRecoversEveryDurablePhase(t *testing.T) {
	t.Parallel()
	for _, phase := range []string{backupRotationStaged, backupRotationPrevious, backupRotationPromoted} {
		t.Run(phase, func(t *testing.T) {
			paths, _ := TestPaths(t.TempDir())
			prepareLifecycleFixture(t, paths)
			writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "qdrant")
			writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "adapter")
			if err := (Installer{Paths: paths, Runner: &fakeRunner{}}).BackupV1(context.Background()); err != nil {
				t.Fatal(err)
			}
			_, encoded, err := loadBackupManifest(paths.Resolve(BackupCurrentRoot + "/manifest.json"))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(encoded)
			digest := hex.EncodeToString(sum[:])
			switch phase {
			case backupRotationStaged:
				copyLifecycleTree(t, paths.Resolve(BackupCurrentRoot), paths.Resolve(BackupStageRoot))
			case backupRotationPrevious:
				copyLifecycleTree(t, paths.Resolve(BackupCurrentRoot), paths.Resolve(BackupStageRoot))
				if err := os.Rename(paths.Resolve(BackupCurrentRoot), paths.Resolve(BackupPreviousRoot)); err != nil {
					t.Fatal(err)
				}
			case backupRotationPromoted:
				copyLifecycleTree(t, paths.Resolve(BackupCurrentRoot), paths.Resolve(BackupPreviousRoot))
			}
			if err := writeBackupRotationJournal(paths, backupRotationJournal{
				SchemaVersion: backupRotationSchema, Phase: phase, ManifestSHA256: digest,
			}); err != nil {
				t.Fatal(err)
			}
			if err := recoverBackupRotation(paths); err != nil {
				t.Fatal(err)
			}
			if err := verifyBackupRoot(paths.Resolve(BackupCurrentRoot), digest); err != nil {
				t.Fatal(err)
			}
			for _, logical := range []string{BackupPreviousRoot, BackupStageRoot, BackupJournalPath} {
				if _, err := os.Lstat(paths.Resolve(logical)); !os.IsNotExist(err) {
					t.Fatalf("rotation recovery left %s", logical)
				}
			}
		})
	}
}

func TestBackupRotationRecoveryPreservesLastKnownGoodWhenPromotedBackupIsCorrupt(t *testing.T) {
	t.Parallel()
	paths, _ := TestPaths(t.TempDir())
	prepareLifecycleFixture(t, paths)
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "qdrant")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "adapter")
	if err := (Installer{Paths: paths, Runner: &fakeRunner{}}).BackupV1(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, encoded, err := loadBackupManifest(paths.Resolve(BackupCurrentRoot + "/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	digest := hex.EncodeToString(sum[:])
	copyLifecycleTree(t, paths.Resolve(BackupCurrentRoot), paths.Resolve(BackupPreviousRoot))
	writeLifecycleFile(t, paths.Resolve(BackupCurrentRoot+"/qdrant/storage/index.bin"), "corrupt")
	if err := writeBackupRotationJournal(paths, backupRotationJournal{
		SchemaVersion: backupRotationSchema, Phase: backupRotationPromoted, ManifestSHA256: digest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := recoverBackupRotation(paths); err == nil {
		t.Fatal("corrupt promoted backup recovery unexpectedly succeeded")
	}
	if err := verifyBackupRoot(paths.Resolve(BackupCurrentRoot), digest); err != nil {
		t.Fatalf("last-known-good backup was not restored: %v", err)
	}
}

func TestKnowledgeBackupRejectsSymlinkedLiveStateBeforeCommands(t *testing.T) {
	t.Parallel()
	paths, _ := TestPaths(t.TempDir())
	prepareLifecycleFixture(t, paths)
	target := paths.Resolve(PersistentRoot + "/qdrant/storage")
	if err := os.RemoveAll(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", target); err != nil {
		t.Fatal(err)
	}
	runner := &fakeRunner{}
	if err := (Installer{Paths: paths, Runner: runner}).BackupV1(context.Background()); err == nil {
		t.Fatal("symlinked live state was accepted")
	}
	if len(runner.commands) != 0 {
		t.Fatal("service commands ran before filesystem boundary validation")
	}
}

func TestKnowledgeBackupRestartsAfterPartialStopFailure(t *testing.T) {
	t.Parallel()
	paths, _ := TestPaths(t.TempDir())
	prepareLifecycleFixture(t, paths)
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/qdrant/storage/index.bin"), "qdrant")
	writeLifecycleFile(t, paths.Resolve(PersistentRoot+"/adapter/ledger.db"), "adapter")
	runner := &failOnceRunner{failure: errors.New("qdrant stop failed"), failAt: 2}
	err := (Installer{Paths: paths, Runner: runner}).BackupV1(context.Background())
	if err == nil || !strings.Contains(err.Error(), "qdrant stop failed") {
		t.Fatalf("partial stop error = %v", err)
	}
	if len(runner.commands) != 7 {
		t.Fatalf("partial stop recovery command count = %d, want 7", len(runner.commands))
	}
	if _, err := os.Lstat(paths.Resolve(BackupCurrentRoot)); !os.IsNotExist(err) {
		t.Fatal("backup mutated durable state after a partial stop failure")
	}
}

type failOnceRunner struct {
	commands []recordedCommand
	failure  error
	failAt   int
}

type failSetRunner struct {
	commands []recordedCommand
	failures map[int]error
}

type lifecycleIdentityResolver struct{}

func (lifecycleIdentityResolver) Resolve(string) (Identity, error) {
	return Identity{UID: os.Geteuid(), GID: os.Getegid()}, nil
}

type lifecycleMaterializer struct{}

func (lifecycleMaterializer) Materialize(Paths) error { return nil }

func (runner *failOnceRunner) Run(_ context.Context, executable string, args ...string) error {
	runner.commands = append(runner.commands, recordedCommand{executable: executable, args: append([]string(nil), args...)})
	if len(runner.commands) == runner.failAt {
		return runner.failure
	}
	return nil
}

func (*failOnceRunner) UnitState(context.Context, string) (UnitState, error) {
	return UnitState{LoadState: "loaded", ActiveState: "inactive"}, nil
}

func (runner *failSetRunner) Run(_ context.Context, executable string, args ...string) error {
	runner.commands = append(runner.commands, recordedCommand{
		executable: executable, args: append([]string(nil), args...),
	})
	return runner.failures[len(runner.commands)]
}

func (*failSetRunner) UnitState(context.Context, string) (UnitState, error) {
	return UnitState{LoadState: "loaded", ActiveState: "inactive"}, nil
}

func prepareLifecycleFixture(t *testing.T, paths Paths) {
	t.Helper()
	for _, path := range []string{ReleaseRoot + "/.provenance-sha256", QdrantConfigPath} {
		writeLifecycleFile(t, paths.Resolve(path), "fixed")
	}
	for path, content := range map[string]string{QdrantUnitPath: renderQdrantUnit(), AdapterUnitPath: renderAdapterUnit()} {
		target := paths.Resolve(path)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil || os.WriteFile(target, []byte(content), 0o644) != nil {
			t.Fatal("prepare exact unit fixture")
		}
	}
	for _, path := range []string{PersistentRoot + "/qdrant/storage", PersistentRoot + "/adapter", PersistentRoot + "/secrets", PersistentRoot + "/tls", RuntimeRoot} {
		if err := os.MkdirAll(paths.Resolve(path), 0o750); err != nil {
			t.Fatal(err)
		}
	}
}

func writeLifecycleFile(t *testing.T, path, value string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertLifecycleFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != want {
		t.Fatalf("fixed lifecycle file mismatch: error=%v", err)
	}
}

func backupTreeContains(t *testing.T, root, value string) bool {
	t.Helper()
	found := false
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			payload, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			found = found || strings.Contains(string(payload), value)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return found
}

func copyLifecycleTree(t *testing.T, source, destination string) {
	t.Helper()
	if err := filepath.Walk(source, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		input, err := os.Open(path)
		if err != nil {
			return err
		}
		defer input.Close()
		if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
			return err
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm())
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(output, input)
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	}); err != nil {
		t.Fatal(err)
	}
}
