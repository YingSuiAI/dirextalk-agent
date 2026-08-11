package server

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type executionLifecycleCapability struct {
	descriptor *capv1.CapabilityDescriptor
	handle     func(context.Context, string, []byte) ([]byte, error)
}

func (c executionLifecycleCapability) Descriptor() *capv1.CapabilityDescriptor {
	return c.descriptor
}

func (c executionLifecycleCapability) HandleOperation(ctx context.Context, operationID string, raw []byte) ([]byte, error) {
	return c.handle(ctx, operationID, raw)
}

func TestStartOperationResponseReportsDurableReplay(t *testing.T) {
	op := &operation.Operation{ID: "operation-1", State: operation.StatePending}

	first := startOperationResponse(op, true)
	if first.GetOperationId() != op.ID || first.GetState() != capv1.OperationState_OPERATION_STATE_PENDING || first.GetReplayed() {
		t.Fatalf("first admission response = %#v", first)
	}

	replay := startOperationResponse(op, false)
	if replay.GetOperationId() != op.ID || replay.GetState() != capv1.OperationState_OPERATION_STATE_PENDING || !replay.GetReplayed() {
		t.Fatalf("replay response = %#v", replay)
	}
}

func TestKnowledgeQuotaFailureDetailsSurviveDurableStartWatchAndReconcileShapes(t *testing.T) {
	op := &operation.Operation{ID: "operation-quota", State: operation.StateFailed, ErrorCode: "RESOURCE_EXHAUSTED", ErrorMessage: operation.KnowledgeQuotaExceededMessage}
	started := startOperationResponse(op, false)
	if started.GetError().GetDetails()["code"] != "knowledge_quota_exceeded" {
		t.Fatalf("start error=%v", started.GetError())
	}
	watched := eventProto(operation.Event{OperationID: op.ID, EventType: "error", EventJSON: []byte(`{"error_code":"RESOURCE_EXHAUSTED","error_message":"Knowledge content quota is exhausted"}`)})
	if watched.GetError().GetError().GetDetails()["code"] != "knowledge_quota_exceeded" {
		t.Fatalf("watch error=%v", watched.GetError())
	}
	reconciled := capabilityError(op.ErrorCode, op.ErrorMessage)
	if reconciled.GetDetails()["code"] != "knowledge_quota_exceeded" {
		t.Fatalf("reconcile error=%v", reconciled)
	}
	if got := operationStatusError(operation.NewFailure(op.ErrorCode, op.ErrorMessage, errors.New("quota"))); status.Code(got) != codes.ResourceExhausted || status.Convert(got).Message() != operation.KnowledgeQuotaExceededMessage {
		t.Fatalf("direct query status=%v", got)
	}
}

func TestOperationStatusErrorRedactsUnclassifiedDetails(t *testing.T) {
	sentinel := errors.New("provider returned secret-sentinel")
	for _, err := range []error{
		sentinel,
		operation.NewFailure("FUTURE_CODE", "future secret-sentinel", sentinel),
	} {
		got := operationStatusError(err)
		if status.Code(got) != codes.Unavailable || status.Convert(got).Message() != "Agent operation failed" {
			t.Fatalf("status = %v, want fixed unavailable failure", got)
		}
		if strings.Contains(got.Error(), "secret-sentinel") {
			t.Fatalf("status leaked upstream detail: %v", got)
		}
	}
}

func TestOperationStatusErrorPreservesDeadlineExceeded(t *testing.T) {
	got := operationStatusError(errors.Join(context.DeadlineExceeded, errors.New("private provider detail")))
	if status.Code(got) != codes.DeadlineExceeded || status.Convert(got).Message() != context.DeadlineExceeded.Error() {
		t.Fatalf("status = %v, want redacted deadline exceeded", got)
	}
}

func TestAcceptedOperationExecutionUsesDescriptorLifecycle(t *testing.T) {
	t.Run("durable stream outlives admission deadline", func(t *testing.T) {
		db := observationDB(t)
		defer db.Close()
		manager := operation.NewManager(db)
		server := lifecycleTestCapabilityServer(manager)
		operationID := uuid.NewString()
		startLifecycleOperation(t, manager, operationID)

		started := make(chan struct{})
		inspect := make(chan struct{})
		inspected := make(chan error, 1)
		release := make(chan struct{})
		premature := make(chan error, 1)
		capability := executionLifecycleCapability{handle: func(ctx context.Context, gotOperation string, raw []byte) ([]byte, error) {
			if gotOperation != "execute" || string(raw) != `{}` {
				return nil, errors.New("unexpected handler input")
			}
			close(started)
			select {
			case <-ctx.Done():
				premature <- context.Cause(ctx)
				return nil, ctx.Err()
			case <-inspect:
			}
			callContext, callOK := capabilityclient.CallContextFromContext(ctx)
			permission, permissionOK := capabilityclient.PermissionFromContext(ctx)
			durableOperationID, operationOK := operation.OperationIDFromContext(ctx)
			if !callOK || callContext.GetRootOperationId() != operationID || callContext.GetRoute() != "ms→agent" || callContext.GetHop() != 2 ||
				!permissionOK || permission.GetAuthenticatedOwnerId() != "owner" || permission.GetAccountGeneration() != 7 ||
				len(permission.GetGrantedScopes()) != 1 || permission.GetGrantedScopes()[0] != "agent.test.execute" || string(permission.GetCapabilityGrant()) != "signed-grant" ||
				!operationOK || durableOperationID != operationID {
				inspected <- errors.New("authenticated execution context is incomplete")
				return nil, errors.New("authenticated execution context is incomplete")
			}
			if _, inheritedDeadline := ctx.Deadline(); inheritedDeadline {
				inspected <- errors.New("durable handler inherited admission deadline")
				return nil, errors.New("durable handler inherited admission deadline")
			}
			inspected <- nil
			select {
			case <-ctx.Done():
				premature <- context.Cause(ctx)
				return nil, ctx.Err()
			case <-release:
				return []byte(`{"done":true}`), nil
			}
		}}
		deadline := time.Now().Add(40 * time.Millisecond)
		server.executeAcceptedOperation(lifecycleRequest(operationID, deadline), lifecycleDescriptor(capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM), capability)
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("durable handler did not start")
		}
		time.Sleep(time.Until(deadline) + 40*time.Millisecond)
		select {
		case cause := <-premature:
			t.Fatalf("durable handler inherited admission deadline: %v", cause)
		default:
		}
		close(inspect)
		select {
		case err := <-inspected:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("durable handler did not retain authenticated context after admission deadline")
		}
		close(release)
		got := waitLifecycleState(t, manager, operationID, operation.StateCompleted)
		if string(got.ResultJSON) != `{"done":true}` {
			t.Fatalf("durable result=%s", got.ResultJSON)
		}
	})

	t.Run("mutation retains call deadline", func(t *testing.T) {
		db := observationDB(t)
		defer db.Close()
		manager := operation.NewManager(db)
		server := lifecycleTestCapabilityServer(manager)
		operationID := uuid.NewString()
		startLifecycleOperation(t, manager, operationID)

		started := make(chan struct{})
		cancelled := make(chan error, 1)
		capability := executionLifecycleCapability{handle: func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
			close(started)
			<-ctx.Done()
			cancelled <- ctx.Err()
			return nil, ctx.Err()
		}}
		server.executeAcceptedOperation(lifecycleRequest(operationID, time.Now().Add(40*time.Millisecond)), lifecycleDescriptor(capv1.OperationType_OPERATION_TYPE_MUTATION), capability)
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("mutation handler did not start")
		}
		select {
		case err := <-cancelled:
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("mutation handler error=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("mutation handler ignored call deadline")
		}
		got := waitLifecycleState(t, manager, operationID, operation.StateUncertain)
		if got.ErrorCode != "UNCERTAIN" {
			t.Fatalf("mutation terminal=%+v", got)
		}
	})

	t.Run("durable stream remains explicitly cancellable", func(t *testing.T) {
		db := observationDB(t)
		defer db.Close()
		manager := operation.NewManager(db)
		server := lifecycleTestCapabilityServer(manager)
		operationID := uuid.NewString()
		startLifecycleOperation(t, manager, operationID)

		started := make(chan struct{})
		cause := make(chan error, 1)
		capability := executionLifecycleCapability{handle: func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
			close(started)
			<-ctx.Done()
			cause <- context.Cause(ctx)
			return nil, ctx.Err()
		}}
		server.executeAcceptedOperation(lifecycleRequest(operationID, time.Now().Add(time.Minute)), lifecycleDescriptor(capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM), capability)
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("durable handler did not start")
		}
		if err := manager.Cancel(context.Background(), operationID, "owner requested cancellation"); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-cause:
			if !errors.Is(err, operation.ErrExplicitCancel) {
				t.Fatalf("durable cancellation cause=%v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("durable handler did not observe explicit cancellation")
		}
		waitLifecycleState(t, manager, operationID, operation.StateCancelled)
	})

	t.Run("server shutdown cancels and drains durable stream", func(t *testing.T) {
		db := observationDB(t)
		defer db.Close()
		manager := operation.NewManager(db)
		server := lifecycleTestCapabilityServer(manager)
		operationID := uuid.NewString()
		startLifecycleOperation(t, manager, operationID)

		started := make(chan struct{})
		returned := make(chan struct{})
		cause := make(chan error, 1)
		capability := executionLifecycleCapability{handle: func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
			close(started)
			<-ctx.Done()
			cause <- context.Cause(ctx)
			close(returned)
			return nil, operation.NewFailure("CANCELLED", "turn cancelled", ctx.Err())
		}}
		server.executeAcceptedOperation(lifecycleRequest(operationID, time.Now().Add(40*time.Millisecond)), lifecycleDescriptor(capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM), capability)
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("durable handler did not start")
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := server.Stop(shutdownCtx); err != nil {
			t.Fatal(err)
		}
		select {
		case got := <-cause:
			if !errors.Is(got, errCapabilityServerShutdown) || errors.Is(got, operation.ErrExplicitCancel) {
				t.Fatalf("durable shutdown cause=%v", got)
			}
		case <-time.After(time.Second):
			t.Fatal("durable handler did not observe server shutdown")
		}
		select {
		case <-returned:
		default:
			t.Fatal("server Stop returned before durable handler")
		}
		waitLifecycleState(t, manager, operationID, operation.StateUncertain)
		server.durableMu.Lock()
		active := server.durableActive
		server.durableMu.Unlock()
		if active != 0 {
			t.Fatalf("durable jobs remain active after Stop: %d", active)
		}
	})
}

func TestDurableJobAdmissionIsFencedBeforeShutdownWait(t *testing.T) {
	server := lifecycleTestCapabilityServer(nil)
	baseCtx, admitted := server.beginDurableJob()
	if !admitted {
		t.Fatal("initial durable job was not admitted")
	}
	baseDone := make(chan struct{})
	go func() {
		defer close(baseDone)
		<-baseCtx.Done()
		server.finishDurableJob()
	}()
	const candidates = 64
	start := make(chan struct{})
	var callers sync.WaitGroup
	callers.Add(candidates)
	for range candidates {
		go func() {
			defer callers.Done()
			<-start
			ctx, admitted := server.beginDurableJob()
			if !admitted {
				return
			}
			defer server.finishDurableJob()
			<-ctx.Done()
			if !errors.Is(context.Cause(ctx), errCapabilityServerShutdown) {
				t.Errorf("durable admission cancellation cause=%v", context.Cause(ctx))
			}
		}()
	}
	close(start)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Stop(shutdownCtx); err != nil {
		t.Fatal(err)
	}
	<-baseDone
	callers.Wait()
	if _, admitted := server.beginDurableJob(); admitted {
		t.Fatal("durable job admitted after shutdown wait began")
	}
	server.durableMu.Lock()
	active := server.durableActive
	server.durableMu.Unlock()
	if active != 0 {
		t.Fatalf("durable jobs remain active after concurrent shutdown: %d", active)
	}
}

func lifecycleDescriptor(kind capv1.OperationType) *capv1.OperationDescriptor {
	return &capv1.OperationDescriptor{OperationId: "execute", OperationType: kind}
}

func lifecycleRequest(operationID string, deadline time.Time) *capv1.StartOperationRequest {
	return &capv1.StartOperationRequest{
		OperationId: operationID, Operation: "execute", RequestJson: []byte(`{}`),
		CallContext: &capv1.CallContext{ChainId: uuid.NewString(), RootOperationId: operationID, Route: "ms→agent", Hop: 2, DeadlineUnixMs: deadline.UnixMilli()},
		Permission: &capv1.PermissionContext{AuthenticatedOwnerId: "owner", AccountGeneration: 7,
			GrantedScopes: []string{"agent.test.execute"}, CapabilityGrant: []byte("signed-grant")},
	}
}

func lifecycleTestCapabilityServer(manager *operation.Manager) *Server {
	server := &Server{opMgr: manager}
	server.initializeDurableLifecycle()
	return server
}

func startLifecycleOperation(t *testing.T, manager *operation.Manager, operationID string) {
	t.Helper()
	err := manager.Start(context.Background(), &operation.Operation{
		ID: operationID, CapabilityID: "agent.test.v1", OperationName: "execute", RequestJSON: []byte(`{}`),
		RootRequestDigest: []byte("root"), RequestDigest: []byte("request"), OwnerID: "owner", AccountGeneration: 7,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func waitLifecycleState(t *testing.T, manager *operation.Manager, operationID string, wanted operation.State) *operation.Operation {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		got, err := manager.Get(context.Background(), operationID)
		if err == nil && got.State == wanted {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("operation %s state=%v err=%v, want %s", operationID, got, err, wanted)
		}
		time.Sleep(time.Millisecond)
	}
}
