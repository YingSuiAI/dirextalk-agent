package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOrphanRecoveryControllerPersistsRetryAndDeduplicatesSafeAlerts(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	activeID, inactiveID := uuid.NewString(), uuid.NewString()
	unsafeRole := "arn:aws:iam::123456789012:role/unsafe-role-canary"
	unsafeStack := "unsafe-foundation-stack-canary"
	for _, connection := range []struct {
		id, status string
	}{
		{id: activeID, status: "active"},
		{id: inactiveID, status: "degraded"},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO cloud_connections
				(connection_id, agent_instance_id, owner_id, account_id, region, control_role_arn,
				 foundation_stack_id, credential_generation, status, revision, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,1,$8,1,$9,$9)`,
			connection.id, instanceID, "owner-orphan-recovery", "123456789012", "us-west-2", unsafeRole, unsafeStack, connection.status, now); err != nil {
			t.Fatalf("insert %s connection: %v", connection.status, err)
		}
	}

	claimed, err := store.ClaimDueOrphanRecoveryControllers(ctx, now, now.Add(time.Minute), 8)
	if err != nil || len(claimed) != 1 || claimed[0].Connection.ConnectionID != activeID || claimed[0].Revision != 2 ||
		claimed[0].Attempt != 0 || claimed[0].AlertState != postgres.OrphanRecoveryAlertClear {
		t.Fatalf("initial active claim=%+v err=%v", claimed, err)
	}
	if claimedAgain, err := store.ClaimDueOrphanRecoveryControllers(ctx, now, now.Add(time.Minute), 8); err != nil || len(claimedAgain) != 0 {
		t.Fatalf("claimed in-flight controller again=%+v err=%v", claimedAgain, err)
	}
	if confirmed, err := store.ConfirmActiveOrphanRecoveryConnection(ctx, activeID, "owner-orphan-recovery", claimed[0].Revision, claimed[0].Connection.Revision); err != nil || confirmed != claimed[0].Connection {
		t.Fatalf("fresh active connection confirmation=%+v err=%v", confirmed, err)
	}

	firstFailure, err := store.RecordOrphanRecoveryFailure(
		ctx, activeID, claimed[0].Revision, now, now.Add(2*time.Second), postgres.OrphanRecoveryErrorProviderUnavailable,
	)
	if err != nil || firstFailure.Revision != 3 || firstFailure.Attempt != 1 ||
		firstFailure.SafeErrorCode != postgres.OrphanRecoveryErrorProviderUnavailable ||
		firstFailure.AlertState != postgres.OrphanRecoveryAlertRaised || firstFailure.AlertErrorCode != postgres.OrphanRecoveryErrorProviderUnavailable {
		t.Fatalf("first persisted failure=%+v err=%v", firstFailure, err)
	}
	assertOrphanRecoveryAlertCount(t, pool, activeID, 1)

	// Reopen the Store to prove the next durable claim starts from the persisted
	// controller rather than an in-memory retry counter.
	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	retryClaim, err := restarted.ClaimDueOrphanRecoveryControllers(ctx, now.Add(2*time.Second), now.Add(3*time.Second), 8)
	if err != nil || len(retryClaim) != 1 || retryClaim[0].Revision != 4 || retryClaim[0].Attempt != 1 {
		t.Fatalf("restart retry claim=%+v err=%v", retryClaim, err)
	}
	secondFailure, err := restarted.RecordOrphanRecoveryFailure(
		ctx, activeID, retryClaim[0].Revision, now.Add(2*time.Second), now.Add(5*time.Second), postgres.OrphanRecoveryErrorProviderUnavailable,
	)
	if err != nil || secondFailure.Revision != 5 || secondFailure.Attempt != 2 {
		t.Fatalf("same-state failure=%+v err=%v", secondFailure, err)
	}
	assertOrphanRecoveryAlertCount(t, pool, activeID, 1)

	successClaim, err := restarted.ClaimDueOrphanRecoveryControllers(ctx, now.Add(5*time.Second), now.Add(6*time.Second), 8)
	if err != nil || len(successClaim) != 1 || successClaim[0].Revision != 6 || successClaim[0].Attempt != 2 {
		t.Fatalf("success claim=%+v err=%v", successClaim, err)
	}
	success, err := restarted.RecordOrphanRecoverySuccess(ctx, activeID, successClaim[0].Revision, now.Add(5*time.Second), now.Add(9*time.Second))
	if err != nil || success.Revision != 7 || success.Attempt != 0 || success.SafeErrorCode != "" ||
		success.AlertState != postgres.OrphanRecoveryAlertClear || success.AlertErrorCode != "" || success.LastSuccessAt == nil || !success.LastSuccessAt.Equal(now.Add(5*time.Second)) {
		t.Fatalf("success clear state=%+v err=%v", success, err)
	}

	// A later recurrence is a new stale/error state and emits exactly one new
	// alert; a stale revision never writes another event or overwrites state.
	recurrenceClaim, err := restarted.ClaimDueOrphanRecoveryControllers(ctx, now.Add(9*time.Second), now.Add(10*time.Second), 8)
	if err != nil || len(recurrenceClaim) != 1 || recurrenceClaim[0].Revision != 8 {
		t.Fatalf("recurrence claim=%+v err=%v", recurrenceClaim, err)
	}
	if _, err := restarted.RecordOrphanRecoveryFailure(ctx, activeID, recurrenceClaim[0].Revision-1, now.Add(9*time.Second), now.Add(12*time.Second), postgres.OrphanRecoveryErrorInvalid); !errors.Is(err, cloudapp.ErrRevisionConflict) {
		t.Fatalf("stale controller revision error=%v", err)
	}
	recurrence, err := restarted.RecordOrphanRecoveryFailure(ctx, activeID, recurrenceClaim[0].Revision, now.Add(9*time.Second), now.Add(12*time.Second), postgres.OrphanRecoveryErrorInvalid)
	if err != nil {
		t.Fatalf("recurrence failure: %v", err)
	}
	assertOrphanRecoveryAlertCount(t, pool, activeID, 2)
	if _, err := pool.Exec(ctx, `UPDATE cloud_connections SET status='degraded', revision=revision+1 WHERE connection_id=$1`, activeID); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.ConfirmActiveOrphanRecoveryConnection(ctx, activeID, "owner-orphan-recovery", recurrence.Revision, recurrence.Connection.Revision); !errors.Is(err, cloudapp.ErrRevisionConflict) {
		t.Fatalf("degraded connection confirmation error=%v", err)
	}

	var persisted string
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(string_agg(event.summary_json::text || E'\n' || outbox.payload_json::text, E'\n'), '')
		FROM task_events AS event
		JOIN outbox_events AS outbox ON outbox.event_seq=event.seq
		WHERE event.event_type='cloud.alert.raised' AND event.aggregate_id=$1`, activeID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{unsafeRole, unsafeStack, "owner-orphan-recovery", "123456789012", "us-west-2"} {
		if strings.Contains(persisted, forbidden) {
			t.Fatalf("orphan recovery alert leaked private connection value %q", forbidden)
		}
	}
	if !strings.Contains(persisted, string(postgres.OrphanRecoveryErrorProviderUnavailable)) || !strings.Contains(persisted, string(postgres.OrphanRecoveryErrorInvalid)) ||
		!strings.Contains(persisted, activeID) {
		t.Fatal("orphan recovery alert omitted its fixed error code or controller identity")
	}
}

func assertOrphanRecoveryAlertCount(t *testing.T, pool *pgxpool.Pool, connectionID string, want int) {
	t.Helper()
	var events, outbox int
	if err := pool.QueryRow(context.Background(), `
		SELECT
			(SELECT count(*) FROM task_events WHERE event_type='cloud.alert.raised' AND aggregate_id=$1),
			(SELECT count(*) FROM outbox_events AS outbox
			 JOIN task_events AS event ON event.seq=outbox.event_seq
			 WHERE event.event_type='cloud.alert.raised' AND event.aggregate_id=$1)`, connectionID).Scan(&events, &outbox); err != nil {
		t.Fatal(err)
	}
	if events != want || outbox != want {
		t.Fatalf("alert events=%d outbox=%d want=%d", events, outbox, want)
	}
}
