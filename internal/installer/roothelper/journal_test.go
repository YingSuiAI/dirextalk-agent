package roothelper

import (
	"path/filepath"
	"testing"
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
