package postgres

import (
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/corememory"
	"github.com/google/uuid"
)

func TestCoreMemoryPostgresCanonicalLifecycleAndReplay(t *testing.T) {
	ctx, knowledge, cleanup := knowledgePGFixture(t)
	defer cleanup()
	store, err := NewCoreMemoryStore(knowledge.store, nil)
	if err != nil {
		t.Fatal(err)
	}
	firstSource, err := knowledge.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "response preference", Content: "用户偏好简短回答", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	key := corememory.SlotKey{Scope: corememory.ScopeOwner, CanonicalKey: "preference.response.length"}
	create := canonicalApplyCommand(corememory.ChangeCreate, key, 0, firstSource)
	created, err := store.Apply(ctx, create)
	if err != nil || created.Revision != 1 || created.Deleted || created.CurrentSourceID != firstSource.ID {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	replayed, err := store.Apply(ctx, create)
	if err != nil || replayed != created {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	if _, err = store.Apply(ctx, corememory.ApplyCommand{IdempotencyKey: create.IdempotencyKey, Action: create.Action, Slot: create.Slot, SourceID: create.SourceID, SourceRevision: create.SourceRevision, TextDigest: create.TextDigest, Type: create.Type, Sensitivity: create.Sensitivity, Confidence: 0.91, Importance: create.Importance, CandidateSchemaVersion: create.CandidateSchemaVersion, PolicyVersion: create.PolicyVersion}); !errors.Is(err, corememory.ErrIdempotencyConflict) {
		t.Fatalf("idempotency conflict err=%v", err)
	}

	secondSource, err := knowledge.CreateMemory(ctx, coreknowledge.MemoryCommand{IdempotencyKey: uuid.NewString(), Title: "response preference", Content: "用户偏好详细回答", MediaType: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	update := canonicalApplyCommand(corememory.ChangeUpdate, key, created.Revision, secondSource)
	updated, err := store.Apply(ctx, update)
	if err != nil || updated.Revision != 2 || updated.CurrentSourceID != secondSource.ID {
		t.Fatalf("updated=%+v err=%v", updated, err)
	}
	stale := canonicalApplyCommand(corememory.ChangeUpdate, key, 1, firstSource)
	if _, err = store.Apply(ctx, stale); !errors.Is(err, corememory.ErrRevisionConflict) {
		t.Fatalf("stale update err=%v", err)
	}

	remove := corememory.ApplyCommand{IdempotencyKey: uuid.NewString(), Action: corememory.ChangeDelete, Slot: key, ExpectedRevision: updated.Revision, Type: updated.Type, Sensitivity: updated.Sensitivity, Confidence: updated.Confidence, Importance: updated.Importance, CandidateSchemaVersion: corememory.CandidateSchemaVersion, PolicyVersion: corememory.PolicyVersion}
	deleted, err := store.Apply(ctx, remove)
	if err != nil || !deleted.Deleted || deleted.Revision != 3 || deleted.CurrentSourceID != "" {
		t.Fatalf("deleted=%+v err=%v", deleted, err)
	}
	got, err := store.Get(ctx, key)
	if err != nil || got != deleted {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	active, err := store.List(ctx, corememory.ScopeOwner, "", false, 10)
	if err != nil || len(active) != 0 {
		t.Fatalf("active=%+v err=%v", active, err)
	}
	all, err := store.List(ctx, corememory.ScopeOwner, "", true, 10)
	if err != nil || len(all) != 1 || !all[0].Deleted {
		t.Fatalf("all=%+v err=%v", all, err)
	}

	restarted, err := NewCoreMemoryStore(knowledge.store, nil)
	if err != nil {
		t.Fatal(err)
	}
	originalReceipt, err := restarted.Apply(ctx, create)
	if err != nil || originalReceipt.Revision != 1 || originalReceipt.Deleted {
		t.Fatalf("original receipt=%+v err=%v", originalReceipt, err)
	}
	var revisions int
	if err = knowledge.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_memory_revisions WHERE memory_id=$1`, created.ID).Scan(&revisions); err != nil || revisions != 3 {
		t.Fatalf("revisions=%d err=%v", revisions, err)
	}
}

func canonicalApplyCommand(action corememory.ChangeAction, key corememory.SlotKey, expected int64, source coreknowledge.Source) corememory.ApplyCommand {
	return corememory.ApplyCommand{IdempotencyKey: uuid.NewString(), Action: action, Slot: key, ExpectedRevision: expected, SourceID: source.ID, SourceRevision: source.Revision, TextDigest: source.Digest, Type: corememory.MemoryTypePreference, Sensitivity: corememory.SensitivityLow, Confidence: 0.95, Importance: 0.8, CandidateSchemaVersion: corememory.CandidateSchemaVersion, PolicyVersion: corememory.PolicyVersion}
}
