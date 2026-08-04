package server

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type closedObservationGuard struct {
	mu      sync.Mutex
	entered int
}

func (g *closedObservationGuard) Enter(context.Context) (func(), error) {
	g.mu.Lock()
	g.entered++
	g.mu.Unlock()
	return nil, coredeprovision.ErrClosed
}

func (g *closedObservationGuard) Entered() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.entered
}

type observationWatchStream struct {
	grpc.ServerStream
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	events []*capv1.WatchOperationEvent
}

func newObservationWatchStream() *observationWatchStream {
	ctx, cancel := context.WithCancel(context.Background())
	return &observationWatchStream{ctx: ctx, cancel: cancel}
}

func (s *observationWatchStream) Context() context.Context { return s.ctx }

func (s *observationWatchStream) Send(event *capv1.WatchOperationEvent) error {
	s.mu.Lock()
	s.events = append(s.events, event)
	terminal := event.GetResult() != nil || event.GetError() != nil || event.GetCancelled() != nil
	s.mu.Unlock()
	if terminal {
		s.cancel()
	}
	return nil
}

func (s *observationWatchStream) Events() []*capv1.WatchOperationEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*capv1.WatchOperationEvent(nil), s.events...)
}

func observationDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE operations (
		id TEXT PRIMARY KEY, capability_id TEXT NOT NULL, operation_name TEXT NOT NULL, state TEXT NOT NULL,
		request_json BLOB NOT NULL DEFAULT X'7B7D' CHECK (request_json = X'7B7D'), root_request_digest BLOB NOT NULL,
		request_digest BLOB NOT NULL, result_json BLOB, error_code TEXT, error_message TEXT,
		expected_revision INTEGER DEFAULT 0, actual_revision INTEGER DEFAULT 0, created_at TIMESTAMP NOT NULL,
		updated_at TIMESTAMP NOT NULL, completed_at TIMESTAMP, owner_id TEXT NOT NULL, account_generation INTEGER NOT NULL
	);
	CREATE TABLE operation_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL, event_type TEXT NOT NULL,
		event_json BLOB NOT NULL, created_at TIMESTAMP NOT NULL
	);`)
	if err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db
}

func observationControl(t *testing.T, operationID, owner string, generation int64, action string) (*capv1.CallContext, *capv1.PermissionContext, ed25519.PublicKey) {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	call := &capv1.CallContext{ChainId: uuid.NewString(), RootOperationId: uuid.NewString(), Hop: 2, Route: "ms→agent", DeadlineUnixMs: time.Now().Add(time.Minute).UnixMilli()}
	grant, err := (capv1.GrantCodec{}).SignOperationControlGrant(capv1.OperationControlGrant{
		ChainID: call.GetChainId(), OwnerID: owner, AccountGeneration: generation, OperationID: operationID,
		ControlAction: action, ControlScope: "operation:control:" + action, EntryRoute: "ms", EntryHop: 1,
		DeadlineUnixMs: call.GetDeadlineUnixMs(),
	}, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return call, &capv1.PermissionContext{AuthenticatedOwnerId: owner, AccountGeneration: generation, CapabilityGrant: grant}, privateKey.Public().(ed25519.PublicKey)
}

func TestCapabilityObservationLifecycleGateAndDeprovisionException(t *testing.T) {
	db := observationDB(t)
	defer db.Close()
	manager := operation.NewManager(db)
	owner, generation := "owner", int64(7)
	normal := &operation.Operation{ID: uuid.NewString(), CapabilityID: "agent.test.v1", OperationName: "mutate", RequestJSON: []byte(`{}`), RequestDigest: []byte("normal"), OwnerID: owner, AccountGeneration: generation}
	deprov := &operation.Operation{ID: uuid.NewString(), CapabilityID: "agent.account.v1", OperationName: "deprovision_account", RequestJSON: []byte(`{}`), RequestDigest: []byte("deprov"), OwnerID: owner, AccountGeneration: generation}
	if err := manager.Start(context.Background(), normal); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background(), deprov); err != nil {
		t.Fatal(err)
	}
	if err := manager.Complete(context.Background(), deprov.ID, []byte(`{"deprovisioned":true}`)); err != nil {
		t.Fatal(err)
	}
	guard := &closedObservationGuard{}
	s := &Server{config: &Config{AccountGeneration: generation}, grantKey: nil, opMgr: manager, mutationGuard: guard, watchSem: make(chan struct{}, 1)}

	getCall, getPermission, publicKey := observationControl(t, normal.ID, owner, generation, "get")
	s.grantKey = publicKey
	if _, err := s.GetOperation(context.Background(), &capv1.GetOperationRequest{OperationId: normal.ID, CallContext: getCall, Permission: getPermission}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ordinary GetOperation after seal err=%v", err)
	}

	watchCall, watchPermission, _ := observationControl(t, normal.ID, owner, generation, "watch")
	ordinaryStream := newObservationWatchStream()
	if err := s.WatchOperation(&capv1.WatchOperationRequest{OperationId: normal.ID, CallContext: watchCall, Permission: watchPermission}, ordinaryStream); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("ordinary WatchOperation after seal err=%v", err)
	}
	if len(s.watchSem) != 0 {
		t.Fatalf("ordinary WatchOperation leaked watch semaphore: len=%d", len(s.watchSem))
	}

	deprovGetCall, deprovGetPermission, deprovPublicKey := observationControl(t, deprov.ID, owner, generation, "get")
	s.grantKey = deprovPublicKey
	response, err := s.GetOperation(context.Background(), &capv1.GetOperationRequest{OperationId: deprov.ID, CallContext: deprovGetCall, Permission: deprovGetPermission})
	if err != nil || response.GetState() != capv1.OperationState_OPERATION_STATE_COMPLETED {
		t.Fatalf("deprovision GetOperation after seal response=%+v err=%v", response, err)
	}

	deprovWatchCall, deprovWatchPermission, deprovWatchPublicKey := observationControl(t, deprov.ID, owner, generation, "watch")
	s.grantKey = deprovWatchPublicKey
	deprovStream := newObservationWatchStream()
	err = s.WatchOperation(&capv1.WatchOperationRequest{OperationId: deprov.ID, CallContext: deprovWatchCall, Permission: deprovWatchPermission}, deprovStream)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("deprovision WatchOperation did not stream terminal event: %v", err)
	}
	var terminal bool
	for _, event := range deprovStream.Events() {
		if event.GetResult() != nil {
			terminal = true
		}
	}
	if !terminal {
		t.Fatal("deprovision watcher did not observe terminal result")
	}
	if guard.Entered() != 2 {
		t.Fatalf("observation lifecycle gate entries=%d, want ordinary Get+Watch only", guard.Entered())
	}
}
