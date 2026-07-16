package p0_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

func TestMigrationRejectsDifferentAgentInstance(t *testing.T) {
	pool := newIsolatedPool(t)
	firstInstance := uuid.NewString()
	secondInstance := uuid.NewString()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := postgres.ApplyMigrations(ctx, pool, firstInstance); err != nil {
		t.Fatalf("initial migration failed (%T)", err)
	}
	if err := postgres.ApplyMigrations(ctx, pool, firstInstance); err != nil {
		t.Fatalf("same-instance migration replay failed (%T)", err)
	}
	err := postgres.ApplyMigrations(ctx, pool, secondInstance)
	if err == nil || !strings.Contains(err.Error(), "database belongs to agent instance") {
		t.Fatalf("different agent_instance_id must fail with ownership mismatch, got %T", err)
	}
	if err := postgres.VerifySchema(ctx, pool, firstInstance); err != nil {
		t.Fatalf("ownership mismatch attempt changed original instance metadata (%T)", err)
	}
}

func TestMigrationRejectsChangedAppliedScript(t *testing.T) {
	pool := newIsolatedPool(t)
	instanceID := uuid.NewString()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := postgres.ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("initial migration failed (%T)", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE agent_schema_migrations SET checksum=decode(repeat('00',32),'hex') WHERE version=1`); err != nil {
		t.Fatalf("corrupt migration checksum: %v", err)
	}
	err := postgres.ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("changed applied migration must fail closed, got %T", err)
	}
}
