package roothelper

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
)

func TestRestartJournalCreationSyncsParentExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.journal")
	syncCalls := 0
	journal, err := openRestartJournalWithSync(path, false, func(parent string) error {
		if parent != filepath.Dir(path) {
			t.Fatalf("synced wrong parent: %s", parent)
		}
		syncCalls++
		return nil
	})
	if err != nil || journal == nil || syncCalls != 1 {
		t.Fatalf("create journal err=%v sync_calls=%d", err, syncCalls)
	}
	if _, err := openRestartJournalWithSync(path, false, func(string) error {
		syncCalls++
		return nil
	}); err != nil || syncCalls != 1 {
		t.Fatalf("existing journal unexpectedly repeated creation sync: err=%v sync_calls=%d", err, syncCalls)
	}
}

func TestRestartJournalResumesOnlyExplicitRecoveryOperationAfterCrash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.journal")
	journal, err := openRestartJournal(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := journal.Begin("operation", "digest"); err != nil {
		t.Fatal(err)
	}
	restarted, err := openRestartJournal(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.Begin("operation", "digest"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ordinary interrupted operation resumed: %v", err)
	}
	if _, found, err := restarted.BeginRecovery("operation", "digest"); err != nil || found {
		t.Fatalf("recovery operation was not resumed: found=%t err=%v", found, err)
	}
}

func TestGenerationRecoveryJournalIdentitySurvivesLeaseRotation(t *testing.T) {
	value := installer.RootHelperRestartCapabilityV1{
		OperationID: uuid.NewString(), DeploymentID: uuid.NewString(), OwnerID: "owner",
		Action: string(workeroperation.ActionRestore), WorkerLeaseEpoch: 1,
	}
	first, err := restartJournalDigest(value)
	if err != nil {
		t.Fatal(err)
	}
	value.WorkerLeaseEpoch = 2
	second, err := restartJournalDigest(value)
	if err != nil || second != first {
		t.Fatalf("recovery journal identity rotated with lease: first=%q second=%q err=%v", first, second, err)
	}
	value.Action = string(workeroperation.ActionBackup)
	backup, err := restartJournalDigest(value)
	if err != nil || backup == first {
		t.Fatalf("ordinary generation action lost lease fence: recovery=%q backup=%q err=%v", first, backup, err)
	}
}
