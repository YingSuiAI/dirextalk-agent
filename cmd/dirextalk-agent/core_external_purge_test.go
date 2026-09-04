package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
)

func TestCoreExternalPurgeRegistryPurgesConfiguredRootsWhenKnowledgeDisabled(t *testing.T) {
	roots := map[string]string{
		"extension-staging":   t.TempDir(),
		"extension-workspace": t.TempDir(),
		"knowledge-content":   t.TempDir(),
		"knowledge-mount":     t.TempDir(),
	}
	for name, root := range roots {
		path := filepath.Join(root, name, "nested", "sentinel")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(roots["extension-workspace"], 0o770); err != nil {
		t.Fatal(err)
	}
	registry, err := composeCoreExternalPurge(config.Config{
		CoreKnowledgeEnabled:       false,
		CoreExtensionStagingRoot:   roots["extension-staging"],
		CoreExtensionWorkspaceRoot: roots["extension-workspace"],
		CoreExtensionRunnerUID:     uint32(os.Geteuid()),
		CoreKnowledgeContentRoot:   roots["knowledge-content"],
		CoreKnowledgeMountRoot:     roots["knowledge-mount"],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if err := registry.Purge(context.Background()); err != nil {
		t.Fatal(err)
	}
	for name, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		if name == "knowledge-mount" {
			if len(entries) != 1 {
				t.Fatalf("read-only Knowledge mount was unexpectedly purged: %v", entries)
			}
			continue
		}
		if len(entries) != 0 {
			t.Fatalf("disabled Knowledge purge left %s entries: %v", name, entries)
		}
	}
}

func TestCoreExternalPurgeRejectsRetainedWorkersWithoutDeletingState(t *testing.T) {
	for _, phase := range []string{"provisioning", "failed", "idle", "busy", "destroying"} {
		t.Run(phase, func(t *testing.T) {
			staging := t.TempDir()
			checker, err := composeRetainedWorkerDeprovisionChecker(config.Config{CoreExtensionStagingRoot: staging})
			if err != nil {
				t.Fatal(err)
			}
			worker := retainedWorkerFixture(sshworker.WorkerPhase(phase), "owner", 7)
			if err := checker.store.SaveWorker(context.Background(), worker); err != nil {
				t.Fatal(err)
			}
			err = checker.CheckDeprovision(context.Background(), deprovisionCommand("owner", 7))
			if !errors.Is(err, coredeprovision.ErrRetainedWorkers) {
				t.Fatalf("phase=%q err=%v, want ErrRetainedWorkers", phase, err)
			}
			if _, _, err := checker.store.LoadWorker(context.Background(), worker.WorkerID); err != nil {
				t.Fatalf("precondition check changed Worker state: %v", err)
			}
		})
	}
}

func TestRetainedWorkerDeprovisionCheckerBlocksAnyWorkerScope(t *testing.T) {
	for _, test := range []struct {
		name        string
		worker      *sshworker.WorkerRecord
		owner       string
		generation  int64
		wantBlocked bool
	}{
		{name: "empty state", owner: "owner", generation: 7},
		{name: "destroyed Worker", worker: workerFixturePtr(retainedWorkerFixture(sshworker.WorkerDestroyed, "owner", 7)), owner: "owner", generation: 7},
		{name: "other owner", worker: workerFixturePtr(retainedWorkerFixture(sshworker.WorkerIdle, "other", 7)), owner: "owner", generation: 7, wantBlocked: true},
		{name: "other generation", worker: workerFixturePtr(retainedWorkerFixture(sshworker.WorkerIdle, "owner", 6)), owner: "owner", generation: 7, wantBlocked: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			staging := t.TempDir()
			checker, err := composeRetainedWorkerDeprovisionChecker(config.Config{CoreExtensionStagingRoot: staging})
			if err != nil {
				t.Fatal(err)
			}
			if test.worker != nil {
				if err := checker.store.SaveWorker(context.Background(), *test.worker); err != nil {
					t.Fatal(err)
				}
			}
			err = checker.CheckDeprovision(context.Background(), deprovisionCommand(test.owner, test.generation))
			if test.wantBlocked && !errors.Is(err, coredeprovision.ErrRetainedWorkers) {
				t.Fatalf("global retained Worker err=%v, want ErrRetainedWorkers", err)
			}
			if !test.wantBlocked && err != nil {
				t.Fatalf("satisfied precondition rejected: %v", err)
			}
		})
	}
}

func TestCoreExternalPurgeFailsClosedOnInvalidWorkerState(t *testing.T) {
	staging := t.TempDir()
	checker, err := composeRetainedWorkerDeprovisionChecker(config.Config{CoreExtensionStagingRoot: staging})
	if err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(staging, "cloud-worker", "state", "worker-worker-a.json")
	if err := os.WriteFile(record, []byte(`not-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	err = checker.CheckDeprovision(context.Background(), deprovisionCommand("owner", 7))
	if err == nil || errors.Is(err, coredeprovision.ErrRetainedWorkers) {
		t.Fatalf("corrupt record err=%v, want infrastructure failure", err)
	}
}

func TestRetainedWorkerHistoryReferenceRequiresCurrentWorkerAuthority(t *testing.T) {
	for _, test := range []struct {
		name       string
		worker     *sshworker.WorkerRecord
		owner      string
		generation uint64
		want       bool
	}{
		{name: "retained", worker: workerFixturePtr(retainedWorkerFixture(sshworker.WorkerIdle, "owner", 7)), owner: "owner", generation: 7, want: true},
		{name: "destroyed", worker: workerFixturePtr(retainedWorkerFixture(sshworker.WorkerDestroyed, "owner", 7)), owner: "owner", generation: 7},
		{name: "missing", owner: "owner", generation: 7},
		{name: "foreign owner", worker: workerFixturePtr(retainedWorkerFixture(sshworker.WorkerIdle, "other", 7)), owner: "owner", generation: 7},
		{name: "foreign generation", worker: workerFixturePtr(retainedWorkerFixture(sshworker.WorkerIdle, "owner", 6)), owner: "owner", generation: 7},
	} {
		t.Run(test.name, func(t *testing.T) {
			checker, err := composeRetainedWorkerDeprovisionChecker(config.Config{CoreExtensionStagingRoot: t.TempDir()})
			if err != nil {
				t.Fatal(err)
			}
			if test.worker != nil {
				if err = checker.store.SaveWorker(context.Background(), *test.worker); err != nil {
					t.Fatal(err)
				}
			}
			available, err := checker.CloudWorkerReferenceAvailable(context.Background(), test.owner, test.generation, "worker-a")
			if err != nil || available != test.want {
				t.Fatalf("available=%t err=%v, want %t", available, err, test.want)
			}
		})
	}
}

func retainedWorkerFixture(phase sshworker.WorkerPhase, owner string, generation uint64) sshworker.WorkerRecord {
	return sshworker.WorkerRecord{
		WorkerID: "worker-a", OwnerID: owner, AccountGeneration: generation, Phase: phase,
		Credential: sshworker.CredentialIdentity{CredentialID: "credential-a", CredentialRevision: 3, AccountID: "123456789012", Region: "us-east-1"},
	}
}

func workerFixturePtr(worker sshworker.WorkerRecord) *sshworker.WorkerRecord { return &worker }

func deprovisionCommand(owner string, generation int64) coredeprovision.Command {
	return coredeprovision.Command{OwnerID: owner, AccountGeneration: generation, IdempotencyKey: "00000000-0000-4000-8000-000000000001", Confirmation: coredeprovision.Confirmation}
}
