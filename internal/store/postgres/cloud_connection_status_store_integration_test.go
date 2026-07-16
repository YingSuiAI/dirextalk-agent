package postgres_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

func TestCloudConnectionPostgresOwnerIsolationStablePaginationAndRestart(t *testing.T) {
	pool, baseStore, instanceID := newPlanningTestStore(t)
	ctx := context.Background()
	baseTime := time.Date(2026, 7, 16, 8, 0, 0, 123000000, time.UTC)
	type fixture struct {
		id, owner, account, region, status string
		generation, revision               int64
		createdAt, updatedAt               time.Time
	}
	fixtures := []fixture{
		{id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", owner: "owner-a", account: "123456789012", region: "us-east-1", status: "active", generation: 2, revision: 1, createdAt: baseTime, updatedAt: baseTime},
		{id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", owner: "owner-a", account: "123456789013", region: "us-west-2", status: "degraded", generation: 7, revision: 4, createdAt: baseTime.Add(time.Second), updatedAt: baseTime.Add(3 * time.Minute)},
		{id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc", owner: "owner-b", account: "123456789014", region: "eu-west-1", status: "teardown_blocked", generation: 3, revision: 9, createdAt: baseTime.Add(2 * time.Second), updatedAt: baseTime.Add(5 * time.Minute)},
	}
	for _, item := range fixtures {
		if _, err := pool.Exec(ctx, `
			INSERT INTO cloud_connections
			    (connection_id, agent_instance_id, owner_id, account_id, region, control_role_arn,
			     foundation_stack_id, credential_generation, status, revision, created_at, updated_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
			item.id, instanceID, item.owner, item.account, item.region,
			"arn:aws:iam::"+item.account+":role/dirextalk-control", "foundation-"+item.id,
			item.generation, item.status, item.revision, item.createdAt, item.updatedAt); err != nil {
			t.Fatal(err)
		}
	}

	statuses, err := postgres.NewCloudStatusStore(baseStore)
	if err != nil {
		t.Fatal(err)
	}
	got, err := statuses.GetConnection(ctx, "owner-a", fixtures[1].id)
	if err != nil || got.Status != fixtures[1].status || got.CredentialGeneration != fixtures[1].generation ||
		got.Revision != fixtures[1].revision || !got.CreatedAt.Equal(fixtures[1].createdAt) || !got.UpdatedAt.Equal(fixtures[1].updatedAt) {
		t.Fatalf("durable connection=%+v err=%v", got, err)
	}
	if _, err := statuses.GetConnection(ctx, "owner-b", fixtures[1].id); !errors.Is(err, cloudstatus.ErrNotFound) {
		t.Fatalf("cross-owner connection read error=%v", err)
	}
	if _, err := statuses.GetConnection(ctx, "owner-a", strings.ToUpper(fixtures[1].id)); !errors.Is(err, cloudstatus.ErrInvalid) {
		t.Fatalf("non-canonical connection UUID was accepted: %v", err)
	}

	firstPage, err := statuses.ListConnections(ctx, cloudstatus.ListQuery{OwnerID: "owner-a", PageSize: 1})
	if err != nil || len(firstPage.Connections) != 1 || firstPage.NextPageToken == "" {
		t.Fatalf("first connection page=%+v err=%v", firstPage, err)
	}
	secondPage, err := statuses.ListConnections(ctx, cloudstatus.ListQuery{
		OwnerID: "owner-a", PageSize: 1, PageToken: firstPage.NextPageToken,
	})
	if err != nil || len(secondPage.Connections) != 1 || secondPage.NextPageToken != "" ||
		secondPage.Connections[0].ConnectionID == firstPage.Connections[0].ConnectionID {
		t.Fatalf("second connection page=%+v err=%v", secondPage, err)
	}
	seen := map[string]bool{firstPage.Connections[0].ConnectionID: true, secondPage.Connections[0].ConnectionID: true}
	if !seen[fixtures[0].id] || !seen[fixtures[1].id] || seen[fixtures[2].id] {
		t.Fatalf("owner-filtered connection IDs=%v", seen)
	}
	if _, err := statuses.ListWorkers(ctx, cloudstatus.ListQuery{
		OwnerID: "owner-a", PageSize: 1, PageToken: firstPage.NextPageToken,
	}); !errors.Is(err, cloudstatus.ErrInvalid) {
		t.Fatalf("connection cursor was accepted by Worker pagination: %v", err)
	}
	if _, err := statuses.ListConnections(ctx, cloudstatus.ListQuery{
		OwnerID: "owner-b", PageSize: 1, PageToken: firstPage.NextPageToken,
	}); !errors.Is(err, cloudstatus.ErrInvalid) {
		t.Fatalf("owner-a connection cursor was accepted for owner-b: %v", err)
	}
	foreignCursor, err := json.Marshal(map[string]any{
		"kind": "worker", "created_at": baseTime, "id": fixtures[0].id,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := statuses.ListConnections(ctx, cloudstatus.ListQuery{
		OwnerID: "owner-a", PageSize: 1, PageToken: base64.RawURLEncoding.EncodeToString(foreignCursor),
	}); !errors.Is(err, cloudstatus.ErrInvalid) {
		t.Fatalf("foreign cursor was accepted by connection pagination: %v", err)
	}

	restartedBaseStore, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	restartedStatuses, err := postgres.NewCloudStatusStore(restartedBaseStore)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := restartedStatuses.GetConnection(ctx, "owner-a", fixtures[1].id)
	if err != nil || reloaded != got {
		t.Fatalf("restarted connection=%+v want=%+v err=%v", reloaded, got, err)
	}
}
