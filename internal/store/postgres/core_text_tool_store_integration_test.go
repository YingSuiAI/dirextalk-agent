package postgres

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretexttool"
	"github.com/google/uuid"
)

func TestCoreTextToolStorePostgresIntegration(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	owner := "text-tool-integration-" + uuid.NewString()
	repository := NewCoreTextToolStore(store)
	virtual, err := repository.Get(ctx, owner, 1, time.Now().UTC())
	if err != nil || virtual.Revision != 0 || virtual.UpdatedAt.IsZero() || len(virtual.Tools) != 4 {
		t.Fatalf("virtual=%+v err=%v", virtual, err)
	}
	tools := []coretexttool.Tool{{ID: "search", Name: "Search", SystemPrompt: "Use evidence", Order: 0, Enabled: true}, {ID: uuid.NewString(), Name: "Custom", SystemPrompt: "Transform", Order: 1, Enabled: false}}
	mutation := coretexttool.Mutation{UpdateCommand: coretexttool.UpdateCommand{OwnerID: owner, AccountGeneration: 1, IdempotencyKey: uuid.NewString(), ExpectedRevision: 0, Enabled: true, Tools: tools}, RequestDigest: strings.Repeat("a", 64), Now: time.Now().UTC()}
	created, err := repository.Update(ctx, mutation)
	if err != nil || created.Revision != 1 || len(created.Tools) != 2 || created.Tools[0].ID != "search" {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	persisted, err := repository.Get(ctx, owner, 1, time.Now().UTC())
	if err != nil || persisted.Revision != 1 || persisted.Tools[1].ID != tools[1].ID {
		t.Fatalf("persisted=%+v err=%v", persisted, err)
	}
	replay, err := repository.Update(ctx, mutation)
	if err != nil || replay.Revision != 1 {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	mutation.RequestDigest = strings.Repeat("b", 64)
	if _, err := repository.Update(ctx, mutation); !errors.Is(err, coretexttool.ErrIdempotencyConflict) {
		t.Fatalf("digest conflict=%v", err)
	}
}
