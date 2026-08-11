package server

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"sort"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/capability/operation"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func (s *Server) DescribeCapabilities(ctx context.Context, req *capv1.DescribeCapabilitiesRequest) (*capv1.DescribeCapabilitiesResponse, error) {
	if s.registry == nil {
		return nil, status.Error(codes.Unavailable, "registry not initialized")
	}
	descriptors := s.registry.List()
	digest := computeCatalogDigest(descriptors)
	return &capv1.DescribeCapabilitiesResponse{Capabilities: descriptors, CatalogVersion: 1, CatalogDigest: digest}, nil
}

func computeCatalogDigest(descriptors []*capv1.CapabilityDescriptor) []byte {
	sorted := append([]*capv1.CapabilityDescriptor(nil), descriptors...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].GetCapabilityId() < sorted[j].GetCapabilityId() })
	h := sha256.New()
	for _, desc := range sorted {
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(desc)
		h.Write(b)
	}
	return h.Sum(nil)
}

func (s *Server) Query(ctx context.Context, req *capv1.QueryRequest) (*capv1.QueryResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.requireCallContext(req); err != nil {
		return nil, err
	}
	release, err := s.enterMutation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	if err := s.acquireQuerySem(ctx); err != nil {
		return nil, err
	}
	defer s.releaseQuerySem()
	desc, opDesc, err := s.operationDescriptor(req.GetCapabilityId(), operationIDFromQuery(req))
	if err != nil {
		return nil, err
	}
	if opDesc.GetOperationType() != capv1.OperationType_OPERATION_TYPE_READ {
		return nil, status.Error(codes.InvalidArgument, "Query only supports read operations")
	}
	if len(req.GetRequestJson()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "request_json is required")
	}
	canonicalJSON, canonicalErr := capv1.CanonicalizeJSON(req.GetRequestJson())
	if canonicalErr != nil || !bytes.Equal(canonicalJSON, req.GetRequestJson()) {
		return nil, status.Error(codes.InvalidArgument, "request_json must be RFC 8785 canonical JSON")
	}
	rootDigest, digestErr := canonicalRootRequestDigest(desc, opDesc, &capv1.StartOperationRequest{RequestJson: req.GetRequestJson()})
	if digestErr != nil {
		return nil, status.Error(codes.InvalidArgument, digestErr.Error())
	}
	if err := s.validatePermission(req.GetCallContext(), req.GetPermission(), desc, opDesc.GetOperationId(), rootDigest); err != nil {
		return nil, err
	}
	capability, _ := s.registry.Get(req.GetCapabilityId())
	// Preserve the authenticated route and grant for nested Core adapters. A
	// Product Capability call must continue the same ms→agent chain; it may not
	// synthesize a fresh context at the capability boundary.
	handlingCtx := capabilityclient.WithCallContext(ctx, req.GetCallContext(), req.GetPermission())
	result, err := capability.HandleOperation(handlingCtx, req.GetOperationId(), req.GetRequestJson())
	if err != nil {
		return nil, operationStatusError(err)
	}
	return &capv1.QueryResponse{ResultJson: result}, nil
}

// QueryRequest historically did not carry a separate operation field in the
// first draft of the API.  The generated contract uses operation_id as the
// stable wire name; this helper keeps the adapter explicit at the boundary.
func operationIDFromQuery(req *capv1.QueryRequest) string { return req.GetOperationId() }

func (s *Server) StartOperation(ctx context.Context, req *capv1.StartOperationRequest) (*capv1.StartOperationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.requireCallContext(req); err != nil {
		return nil, err
	}
	if err := capv1.ValidateRootOperationRequest(req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid root operation request: %v", err)
	}
	if err := s.acquireQuerySem(ctx); err != nil {
		return nil, err
	}
	defer s.releaseQuerySem()
	if req.GetOperationId() == "" || req.GetCapabilityId() == "" || req.GetOperation() == "" {
		return nil, status.Error(codes.InvalidArgument, "operation_id, capability_id and operation are required")
	}
	desc, opDesc, err := s.operationDescriptor(req.GetCapabilityId(), req.GetOperation())
	if err != nil {
		return nil, err
	}
	if opDesc.GetOperationType() == capv1.OperationType_OPERATION_TYPE_READ {
		return nil, status.Error(codes.InvalidArgument, "read operation must use Query")
	}
	if len(req.GetRequestJson()) == 0 || !json.Valid(req.GetRequestJson()) {
		return nil, status.Error(codes.InvalidArgument, "request_json must be valid JSON")
	}
	rootDigest, err := canonicalRootRequestDigest(desc, opDesc, req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	digest, err := canonicalRequestDigest(desc, opDesc, req)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := capv1.VerifyRequestDigest(req.GetRequestDigest(), digest); err != nil {
		return nil, status.Errorf(codes.Aborted, "operation request digest conflicts with canonical request: %v", err)
	}
	if err := s.validatePermissionWithRoot(req.GetCallContext(), req.GetPermission(), desc, req.GetOperation(), rootDigest, false); err != nil {
		return nil, err
	}
	capability, _ := s.registry.Get(req.GetCapabilityId())
	ledger := &operation.Operation{ID: req.GetOperationId(), CapabilityID: req.GetCapabilityId(), OperationName: req.GetOperation(), RequestJSON: append([]byte(nil), req.GetRequestJson()...), RootRequestDigest: rootDigest, RequestDigest: digest, ExpectedRevision: req.GetExpectedRevision(), OwnerID: req.GetPermission().GetAuthenticatedOwnerId(), AccountGeneration: req.GetPermission().GetAccountGeneration()}
	accepted, created, err := s.opMgr.StartOrGet(ctx, ledger)
	if err != nil {
		code := codes.Aborted
		if errors.Is(err, operation.ErrNotFound) {
			code = codes.NotFound
		}
		return nil, status.Error(code, err.Error())
	}
	shouldExecute := created
	if !created && req.GetCapabilityId() == "agent.account.v1" && req.GetOperation() == "deprovision_account" && (accepted.State == operation.StateFailed || accepted.State == operation.StateUncertain) {
		var reopened bool
		accepted, reopened, err = s.opMgr.ReopenForReplay(ctx, req.GetOperationId())
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
		if reopened {
			s.opMgr.RememberSecrets(req.GetOperationId(), req.GetRequestJson())
			shouldExecute = true
		}
	}
	if shouldExecute {
		s.executeAcceptedOperation(req, opDesc, capability)
	}
	return startOperationResponse(accepted, created), nil
}

func (s *Server) executeAcceptedOperation(req *capv1.StartOperationRequest, descriptor *capv1.OperationDescriptor, capability Capability) {
	buildExecutionContext := func(parent context.Context) context.Context {
		// Build the value-bearing context first. Deriving it from the inbound RPC
		// would transfer a transport/admission cancellation into durable work and
		// silently discard the authenticated CallContext/PermissionContext.
		executionCtx := capabilityclient.WithCallContext(parent, req.GetCallContext(), req.GetPermission())
		return operation.WithOperationID(executionCtx, req.GetOperationId())
	}
	run := func(managerCtx context.Context, lifecycleCtx context.Context) {
		s.opMgr.Execute(managerCtx, req.GetOperationId(), func(handlerCtx context.Context, _ *operation.Operation) ([]byte, error) {
			executionHandlerCtx := handlerCtx
			if lifecycleCtx != nil {
				var cancel context.CancelCauseFunc
				executionHandlerCtx, cancel = context.WithCancelCause(handlerCtx)
				stopLifecycleCancel := context.AfterFunc(lifecycleCtx, func() {
					cancel(context.Cause(lifecycleCtx))
				})
				defer func() {
					stopLifecycleCancel()
					cancel(nil)
				}()
			}
			result, err := capability.HandleOperation(executionHandlerCtx, req.GetOperation(), req.GetRequestJson())
			// Service shutdown is a lifecycle fence, not a user cancellation. A
			// typed adapter may classify its closed event stream as CANCELLED; retain
			// the lifecycle cancellation so Manager records an interrupted outcome
			// without invoking the explicit-cancel business path.
			if err != nil && errors.Is(context.Cause(executionHandlerCtx), errCapabilityServerShutdown) {
				return nil, context.Canceled
			}
			return result, err
		})
	}

	// A durable stream's CallContext deadline is an admission fence. Its
	// accepted background lifecycle is ended by its domain terminal state or
	// explicit operation cancellation, not by that short transport budget.
	if descriptor.GetOperationType() == capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM {
		lifecycleCtx, admitted := s.beginDurableJob()
		if !admitted {
			_ = s.opMgr.Fail(context.Background(), req.GetOperationId(), "UNAVAILABLE", "capability server stopped before operation execution")
			return
		}
		// Manager must be able to persist its running/terminal fences even when
		// Stop wins immediately after job registration. Only the capability
		// handler inherits lifecycle cancellation; authenticated values remain on
		// the non-cancelled manager context.
		executionCtx := buildExecutionContext(context.WithoutCancel(lifecycleCtx))
		go func() {
			defer s.finishDurableJob()
			run(executionCtx, lifecycleCtx)
		}()
		return
	}

	// Mutations retain the existing bounded execution behavior.
	executionCtx := buildExecutionContext(context.Background())
	if cc := req.GetCallContext(); cc != nil && cc.GetDeadlineUnixMs() > 0 {
		remaining := time.Until(time.UnixMilli(cc.GetDeadlineUnixMs()))
		if remaining <= 0 {
			_ = s.opMgr.Fail(context.Background(), req.GetOperationId(), "UNCERTAIN", "call context deadline elapsed")
			return
		}
		var cancel context.CancelFunc
		executionCtx, cancel = context.WithTimeout(executionCtx, remaining)
		go func() {
			defer cancel()
			run(executionCtx, nil)
		}()
		return
	}
	go run(executionCtx, nil)
}

func startOperationResponse(accepted *operation.Operation, created bool) *capv1.StartOperationResponse {
	if accepted == nil {
		return &capv1.StartOperationResponse{}
	}
	response := &capv1.StartOperationResponse{
		OperationId: accepted.ID,
		State:       stateToProto(accepted.State),
		// `replayed` is transport metadata from the outer durable operation
		// ledger.  Domain result JSON remains immutable across retries and must
		// not guess whether StartOrGet admitted a new operation.
		Replayed: !created,
	}
	if accepted.ErrorCode != "" {
		response.Error = capabilityError(accepted.ErrorCode, accepted.ErrorMessage)
	}
	return response
}

func canonicalRequestDigest(desc *capv1.CapabilityDescriptor, opDesc *capv1.OperationDescriptor, req *capv1.StartOperationRequest) ([]byte, error) {
	business, err := capv1.ParseBusinessInput(req.GetRequestJson())
	if err != nil {
		return nil, err
	}
	schema := sha256.Sum256([]byte(opDesc.GetInputSchemaJson()))
	grant := sha256.Sum256(req.GetPermission().GetCapabilityGrant())
	return capv1.ComputeRequestDigest(desc.GetProtocolVersion(), desc.GetCapabilityId(), desc.GetSemanticVersion(), schema[:], opDesc.GetOperationId(), req.GetExpectedRevision(), business, nil, grant[:])
}

func canonicalRootRequestDigest(desc *capv1.CapabilityDescriptor, opDesc *capv1.OperationDescriptor, req *capv1.StartOperationRequest) ([]byte, error) {
	business, err := capv1.ParseBusinessInput(req.GetRequestJson())
	if err != nil {
		return nil, err
	}
	schema := sha256.Sum256([]byte(opDesc.GetInputSchemaJson()))
	return capv1.ComputeRootRequestDigest(desc.GetProtocolVersion(), desc.GetCapabilityId(), desc.GetSemanticVersion(), schema[:], opDesc.GetOperationId(), req.GetExpectedRevision(), business, nil)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (s *Server) GetOperation(ctx context.Context, req *capv1.GetOperationRequest) (*capv1.GetOperationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.requireCallContext(req); err != nil {
		return nil, err
	}
	op, err := s.opMgr.Get(ctx, req.GetOperationId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "operation not found")
	}
	if err := s.allowOperationObservation(ctx, op); err != nil {
		return nil, err
	}
	if err := s.authorizeOperation(req.GetCallContext(), req.GetPermission(), op, "get"); err != nil {
		return nil, err
	}
	return op.ToProto(), nil
}

func (s *Server) WatchOperation(req *capv1.WatchOperationRequest, stream capv1.AgentCapabilityService_WatchOperationServer) error {
	if req == nil {
		return status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.requireCallContext(req); err != nil {
		return err
	}
	if err := s.acquireWatchSem(stream.Context()); err != nil {
		return err
	}
	defer s.releaseWatchSem()
	op, err := s.opMgr.Get(stream.Context(), req.GetOperationId())
	if err != nil {
		return status.Error(codes.NotFound, "operation not found")
	}
	if err := s.allowOperationObservation(stream.Context(), op); err != nil {
		return err
	}
	if err := s.authorizeOperation(req.GetCallContext(), req.GetPermission(), op, "watch"); err != nil {
		return err
	}
	events, err := s.opMgr.Watch(stream.Context(), req.GetOperationId(), req.GetAfterSequence())
	if err != nil {
		return status.Error(codes.NotFound, "operation not found")
	}
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		case event, ok := <-events:
			if !ok {
				return nil
			}
			if err := stream.Send(eventProto(event)); err != nil {
				return err
			}
		}
	}
}

func eventProto(event operation.Event) *capv1.WatchOperationEvent {
	out := &capv1.WatchOperationEvent{OperationId: event.OperationID, Sequence: event.Sequence, TimestampUnixMs: event.CreatedAt.UnixMilli()}
	switch event.EventType {
	case "accepted", "running", "state_changed":
		var payload struct {
			State    string `json:"state"`
			NewState string `json:"new_state"`
		}
		_ = json.Unmarshal(event.EventJSON, &payload)
		state := payload.State
		if state == "" {
			state = payload.NewState
		}
		out.Event = &capv1.WatchOperationEvent_Accepted{Accepted: &capv1.AcceptedEvent{State: operationStateFromString(state)}}
	case "result":
		out.Event = &capv1.WatchOperationEvent_Result{Result: &capv1.ResultEvent{ResultJson: event.EventJSON}}
	case "error":
		var p struct {
			ErrorCode    string `json:"error_code"`
			ErrorMessage string `json:"error_message"`
		}
		_ = json.Unmarshal(event.EventJSON, &p)
		out.Event = &capv1.WatchOperationEvent_Error{Error: &capv1.ErrorEvent{Error: capabilityError(p.ErrorCode, p.ErrorMessage)}}
	case "cancelled":
		var p struct {
			Reason string `json:"reason"`
		}
		_ = json.Unmarshal(event.EventJSON, &p)
		out.Event = &capv1.WatchOperationEvent_Cancelled{Cancelled: &capv1.CancelledEvent{Reason: p.Reason}}
	default:
		out.Event = &capv1.WatchOperationEvent_Progress{Progress: &capv1.ProgressEvent{EventJson: event.EventJSON}}
	}
	return out
}

func (s *Server) CancelOperation(ctx context.Context, req *capv1.CancelOperationRequest) (*capv1.CancelOperationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.requireCallContext(req); err != nil {
		return nil, err
	}
	release, err := s.enterMutation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	op, err := s.opMgr.Get(ctx, req.GetOperationId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "operation not found")
	}
	if err := s.authorizeOperation(req.GetCallContext(), req.GetPermission(), op, "cancel"); err != nil {
		return nil, err
	}
	if err := s.opMgr.Cancel(ctx, req.GetOperationId(), "user requested"); err != nil && !errors.Is(err, operation.ErrTerminal) {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	op, _ = s.opMgr.Get(ctx, req.GetOperationId())
	return &capv1.CancelOperationResponse{State: stateToProto(op.State)}, nil
}

func (s *Server) ReconcileOperation(ctx context.Context, req *capv1.ReconcileOperationRequest) (*capv1.ReconcileOperationResponse, error) {
	if req == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	if err := s.requireCallContext(req); err != nil {
		return nil, err
	}
	release, err := s.enterMutation(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	op, err := s.opMgr.Get(ctx, req.GetOperationId())
	if err != nil {
		return nil, status.Error(codes.NotFound, "operation not found")
	}
	if err := s.authorizeOperation(req.GetCallContext(), req.GetPermission(), op, "reconcile"); err != nil {
		return nil, err
	}
	op, err = s.opMgr.Reconcile(ctx, req.GetOperationId())
	if err != nil {
		return nil, status.Error(codes.Unavailable, err.Error())
	}
	resp := &capv1.ReconcileOperationResponse{State: stateToProto(op.State), ResultJson: op.ResultJSON}
	if op.ErrorCode != "" {
		resp.Error = capabilityError(op.ErrorCode, op.ErrorMessage)
	}
	return resp, nil
}

func (s *Server) enterMutation(ctx context.Context) (func(), error) {
	if s == nil || s.mutationGuard == nil {
		return func() {}, nil
	}
	release, err := s.mutationGuard.Enter(ctx)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, "Agent account is deprovisioning")
	}
	return release, nil
}

// allowOperationObservation performs a one-shot lifecycle admission for
// Get/Watch. It intentionally does not hold a reader lease for the lifetime
// of a stream: an ordinary watcher must be allowed to terminate when account
// purge closes its event channel. The deprovision operation remains observable
// after sealing so callers can receive its terminal result.
func (s *Server) allowOperationObservation(ctx context.Context, op *operation.Operation) error {
	if isDeprovisionOperation(op) || s == nil || s.mutationGuard == nil {
		return nil
	}
	release, err := s.mutationGuard.Enter(ctx)
	if err != nil {
		return status.Error(codes.FailedPrecondition, "Agent account is deprovisioning")
	}
	release()
	return nil
}

func isDeprovisionOperation(op *operation.Operation) bool {
	return op != nil && op.CapabilityID == "agent.account.v1" && op.OperationName == "deprovision_account"
}

func (s *Server) authorizeOperation(callCtx *capv1.CallContext, permission *capv1.PermissionContext, op *operation.Operation, action string) error {
	if permission == nil || permission.GetAuthenticatedOwnerId() == "" {
		return status.Error(codes.PermissionDenied, "permission context is required")
	}
	if permission.GetAuthenticatedOwnerId() != op.OwnerID {
		return status.Error(codes.PermissionDenied, "operation owner mismatch")
	}
	if s.config.AccountGeneration > 0 && permission.GetAccountGeneration() != s.config.AccountGeneration {
		return status.Error(codes.PermissionDenied, "account generation is stale")
	}
	if len(permission.GetCapabilityGrant()) == 0 {
		return status.Error(codes.PermissionDenied, "capability grant is required")
	}
	controlScope := "operation:control:" + action
	if _, err := (capv1.GrantCodec{}).VerifyOperationControlGrant(permission.GetCapabilityGrant(), s.grantKey, capv1.OperationControlGrantBinding{
		CallContext: callCtx, OwnerID: permission.GetAuthenticatedOwnerId(), AccountGeneration: permission.GetAccountGeneration(), OperationID: op.ID, ControlAction: action, ControlScope: controlScope,
	}); err != nil {
		return status.Errorf(codes.PermissionDenied, "invalid operation control grant: %v", err)
	}
	return nil
}

func stateToProto(state operation.State) capv1.OperationState {
	switch state {
	case operation.StatePending:
		return capv1.OperationState_OPERATION_STATE_PENDING
	case operation.StateRunning:
		return capv1.OperationState_OPERATION_STATE_RUNNING
	case operation.StateCompleted:
		return capv1.OperationState_OPERATION_STATE_COMPLETED
	case operation.StateFailed:
		return capv1.OperationState_OPERATION_STATE_FAILED
	case operation.StateCancelled:
		return capv1.OperationState_OPERATION_STATE_CANCELLED
	case operation.StateUncertain:
		return capv1.OperationState_OPERATION_STATE_UNCERTAIN
	default:
		return capv1.OperationState_OPERATION_STATE_UNSPECIFIED
	}
}
func operationStateFromString(v string) capv1.OperationState { return stateToProto(operation.State(v)) }
func operationErrorCode(v string) capv1.ErrorCode            { return operationErrorCodeInternal(v) }
func capabilityError(code, message string) *capv1.CapabilityError {
	return &capv1.CapabilityError{Code: operationErrorCode(code), Message: message, Details: operation.SafeFailureDetails(code, message)}
}
func operationErrorCodeInternal(v string) capv1.ErrorCode {
	switch v {
	case "INVALID_ARGUMENT":
		return capv1.ErrorCode_ERROR_CODE_INVALID_ARGUMENT
	case "PERMISSION_DENIED":
		return capv1.ErrorCode_ERROR_CODE_PERMISSION_DENIED
	case "NOT_FOUND":
		return capv1.ErrorCode_ERROR_CODE_NOT_FOUND
	case "CONFLICT":
		return capv1.ErrorCode_ERROR_CODE_CONFLICT
	case "PRECONDITION_FAILED":
		return capv1.ErrorCode_ERROR_CODE_PRECONDITION_FAILED
	case "NOT_READY":
		return capv1.ErrorCode_ERROR_CODE_NOT_READY
	case "UNAVAILABLE":
		return capv1.ErrorCode_ERROR_CODE_UNAVAILABLE
	case "UNCERTAIN":
		return capv1.ErrorCode_ERROR_CODE_UNCERTAIN
	case "CYCLE_DETECTED":
		return capv1.ErrorCode_ERROR_CODE_CYCLE_DETECTED
	case "RESOURCE_EXHAUSTED":
		return capv1.ErrorCode_ERROR_CODE_RESOURCE_EXHAUSTED
	default:
		return capv1.ErrorCode_ERROR_CODE_UPSTREAM_FAILED
	}
}
func operationStatusError(err error) error {
	if errors.Is(err, context.Canceled) {
		return status.Error(codes.Canceled, err.Error())
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, context.DeadlineExceeded.Error())
	}
	if code, message, ok := operation.FailureDetails(err); ok {
		switch code {
		case "INVALID_ARGUMENT":
			return status.Error(codes.InvalidArgument, message)
		case "PERMISSION_DENIED":
			return status.Error(codes.PermissionDenied, message)
		case "NOT_FOUND":
			return status.Error(codes.NotFound, message)
		case "CONFLICT":
			return status.Error(codes.Aborted, message)
		case "PRECONDITION_FAILED", "NOT_READY":
			return status.Error(codes.FailedPrecondition, message)
		case "UNAVAILABLE", "UPSTREAM_FAILED":
			return status.Error(codes.Unavailable, message)
		case "RESOURCE_EXHAUSTED":
			return status.Error(codes.ResourceExhausted, message)
		}
	}
	return status.Error(codes.Unavailable, "Agent operation failed")
}
