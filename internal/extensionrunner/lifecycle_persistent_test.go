package extensionrunner

import "testing"

func TestPersistentRunRegistryReplaysExactTerminalAndRejectsConflict(t *testing.T) {
	r, err := NewPersistentRunRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111-1111-4111-8111-111111111111"
	digest := DigestBytes([]byte("request"))
	if _, ok, err := r.ClaimDigest(id, digest); err != nil || ok {
		t.Fatalf("claim=%v %v", ok, err)
	}
	status := StatusV1{RunID: id, Phase: PhaseTombstone, Error: ErrorNone, Status: "ok"}
	if err := r.Record(id, digest, status); err != nil {
		t.Fatal(err)
	}
	r2, err := NewPersistentRunRegistry(r.path[:len(r.path)-len("runs-v2.json")])
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := r2.ClaimDigest(id, digest)
	if err != nil || !ok || got.Status != "ok" {
		t.Fatalf("replay=%#v %v %v", got, ok, err)
	}
	if _, _, err = r2.ClaimDigest(id, DigestBytes([]byte("other"))); err != ErrReplay {
		t.Fatalf("conflict err=%v", err)
	}
}

func TestPersistentRunRegistryRecordsTerminalAfterLifecycleTombstone(t *testing.T) {
	r, err := NewPersistentRunRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := "33333333-3333-4333-8333-333333333333"
	digest := DigestBytes([]byte("request"))
	if _, ok, err := r.ClaimDigest(id, digest); err != nil || ok {
		t.Fatalf("claim=%v %v", ok, err)
	}
	for _, phase := range []Phase{PhaseAdmitted, PhasePrepared, PhaseRunning, PhaseCollecting, PhaseExited, PhaseCleaned, PhaseTombstone} {
		if err = r.Transition(id, phase, ErrorNone); err != nil {
			t.Fatalf("transition %s: %v", phase, err)
		}
	}
	status := StatusV1{RunID: id, Phase: PhaseTombstone, Status: "ok"}
	if err = r.Record(id, digest, status); err != nil {
		t.Fatal(err)
	}
	r2, err := NewPersistentRunRegistry(r.path[:len(r.path)-len("runs-v2.json")])
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := r2.ClaimDigest(id, digest)
	if err != nil || !ok || got.RunID != status.RunID || got.Phase != status.Phase || got.Status != status.Status {
		t.Fatalf("replay=%#v %v %v", got, ok, err)
	}
}

func TestPersistentRunRegistryTombstonesNonterminalAfterRestart(t *testing.T) {
	r, err := NewPersistentRunRegistry(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id := "22222222-2222-4222-8222-222222222222"
	if _, _, err := r.ClaimDigest(id, "digest"); err != nil {
		t.Fatal(err)
	}
	r2, err := NewPersistentRunRegistry(r.path[:len(r.path)-len("runs-v2.json")])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r2.TombstoneOf(id); !ok {
		t.Fatal("nonterminal run was not reconciled to tombstone")
	}
}
