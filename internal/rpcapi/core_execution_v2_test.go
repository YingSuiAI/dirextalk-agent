package rpcapi

import (
	"context"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCoreExecutionV2RPCPreservesAccountGeneration(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	scope := coretask.OwnerScope{OwnerID: "@execution-rpc:example.test", AccountGeneration: 8}
	store := coreexecutionv2.NewMemoryStore()
	now := time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC)
	recordID := uuid.NewString()
	if _, err := store.Create(ctx, coreexecutionv2.Record{OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, Kind: "run", ID: recordID, Revision: 1, Status: "queued", Digest: "digest", Payload: map[string]any{"run_id": recordID}, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendEvent(ctx, coreexecutionv2.Event{OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, Kind: "run", ResourceID: recordID, EventID: uuid.NewString(), Type: "queued", Payload: map[string]any{"run_id": recordID}, CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	domain, err := coreexecutionv2.NewService(coreexecutionv2.Config{Store: store})
	if err != nil {
		t.Fatal(err)
	}
	rpc, err := NewCoreExecutionV2Service(domain, func(context.Context) (coretask.OwnerScope, error) { return scope, nil })
	if err != nil {
		t.Fatal(err)
	}
	got, err := rpc.Get(ctx, &agentv1.CoreExecutionV2ServiceGetRequest{Kind: "run", Id: recordID})
	if err != nil || got.GetRecord().GetOwnerId() != scope.OwnerID || got.GetRecord().GetAccountGeneration() != scope.AccountGeneration {
		t.Fatalf("record=%v err=%v", got, err)
	}
	events, err := rpc.ListEvents(ctx, &agentv1.CoreExecutionV2ServiceListEventsRequest{Kind: "run", Id: recordID, Limit: 10})
	if err != nil || len(events.GetEvents()) != 1 || events.GetEvents()[0].GetAccountGeneration() != scope.AccountGeneration {
		t.Fatalf("events=%v err=%v", events, err)
	}

	foreign, err := NewCoreExecutionV2Service(domain, func(context.Context) (coretask.OwnerScope, error) {
		return coretask.OwnerScope{OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration + 1}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := foreign.Get(ctx, &agentv1.CoreExecutionV2ServiceGetRequest{Kind: "run", Id: recordID}); status.Code(err) != codes.NotFound {
		t.Fatalf("cross-generation read err=%v", err)
	}
}
