package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/google/uuid"
)

func TestCoreDeprovisionRetainedWorkerCheckPrecedesReceiptAndRows(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	if _, err := store.Pool().Exec(ctx, `CREATE TABLE core_deprovision_precondition_sentinel(value text NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool().Exec(ctx, `INSERT INTO core_deprovision_precondition_sentinel(value) VALUES('must-survive')`); err != nil {
		t.Fatal(err)
	}
	externalCalls := 0
	command := coredeprovision.Command{OwnerID: "retained-worker-owner", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), Confirmation: coredeprovision.Confirmation}
	_, err := NewCoreDeprovisionStore(store.Pool()).Deprovision(ctx, command, func(context.Context) error {
		return coredeprovision.ErrRetainedWorkers
	}, func(context.Context) error {
		externalCalls++
		return nil
	})
	if !errors.Is(err, coredeprovision.ErrRetainedWorkers) {
		t.Fatalf("deprovision err=%v, want ErrRetainedWorkers", err)
	}
	var rows, receipts int
	if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM core_deprovision_precondition_sentinel`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := store.Pool().QueryRow(ctx, `SELECT count(*) FROM agent_account_deprovisions`).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if rows != 1 || receipts != 0 || externalCalls != 0 {
		t.Fatalf("blocked deprovision mutated state rows=%d receipts=%d external_calls=%d", rows, receipts, externalCalls)
	}
}
