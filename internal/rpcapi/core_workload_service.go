package rpcapi

import (
	"context"
	"encoding/json"
	"errors"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type WorkloadService struct {
	agentv1.UnimplementedWorkloadServiceServer
	service *coreworkload.Service
}

func NewWorkloadService(s *coreworkload.Service) (*WorkloadService, error) {
	if s == nil {
		return nil, errors.New("workload service requires domain")
	}
	return &WorkloadService{service: s}, nil
}
func (s *WorkloadService) Plan(ctx context.Context, r *agentv1.WorkloadServicePlanRequest) (*agentv1.WorkloadServicePlanResponse, error) {
	if r == nil || !validCoreUUID(r.GetIdempotencyKey()) || r.GetExpiresAt() == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid plan")
	}
	typedTarget := r.GetTypedTarget()
	if typedTarget == nil {
		return nil, status.Error(codes.InvalidArgument, "typed_target is required")
	}
	target := targetSettingsFromTypedProto(typedTarget)
	refs := make([]coreworkload.SecretGrantRef, 0, len(r.GetTypedSecretGrants()))
	for _, ref := range r.GetTypedSecretGrants() {
		if ref != nil {
			refs = append(refs, coreworkload.SecretGrantRef{ReferenceID: ref.GetReferenceId(), Purpose: coreworkloadSecretPurpose(ref.GetPurpose()), BindingDigest: coreconfirmation.Digest(ref.GetBindingDigest())})
		}
	}
	network := make([]string, 0, len(typedTarget.GetNetworkGrants()))
	for _, grant := range typedTarget.GetNetworkGrants() {
		if grant != nil {
			network = append(network, grant.GetReferenceId())
		}
	}
	v, e := s.service.CreatePlan(ctx, coreworkload.PlanInput{IdempotencyKey: r.GetIdempotencyKey(), Summary: r.GetSummary(), Artifact: r.GetArtifact(), Source: r.GetSource(), CommandSteps: r.GetCommandSteps(), ImageDigest: r.GetImageDigest(), TargetKind: workloadTarget(r.GetTargetKind()), Target: target, NetworkGrants: network, SecretGrantRefs: refs, ResourceLimits: resourceLimitsFromTypedProto(r.GetTypedResourceLimits()), ExpiresAt: r.GetExpiresAt().AsTime().UTC()})
	if e != nil {
		return nil, workloadRPCError(e)
	}
	return &agentv1.WorkloadServicePlanResponse{Plan: workloadPlanProto(v)}, nil
}
func (s *WorkloadService) Get(ctx context.Context, r *agentv1.WorkloadServiceGetRequest) (*agentv1.WorkloadServiceGetResponse, error) {
	if r == nil || !validCoreUUID(r.GetPlanId()) {
		return nil, status.Error(codes.InvalidArgument, "plan_id is invalid")
	}
	v, e := s.service.GetPlan(ctx, r.GetPlanId())
	if e != nil {
		return nil, workloadRPCError(e)
	}
	return &agentv1.WorkloadServiceGetResponse{Plan: workloadPlanProto(v)}, nil
}
func (s *WorkloadService) List(ctx context.Context, r *agentv1.WorkloadServiceListRequest) (*agentv1.WorkloadServiceListResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	limit, e := pageLimit(r.GetPageSize())
	if e != nil {
		return nil, e
	}
	items, next, e := s.service.ListPlans(ctx, limit, r.GetPageToken())
	if e != nil {
		return nil, workloadRPCError(e)
	}
	out := &agentv1.WorkloadServiceListResponse{NextPageToken: next}
	for _, v := range items {
		out.Plans = append(out.Plans, workloadPlanProto(v))
	}
	return out, nil
}
func (s *WorkloadService) Quote(ctx context.Context, r *agentv1.WorkloadServiceQuoteRequest) (*agentv1.WorkloadServiceQuoteResponse, error) {
	if r == nil || !validCoreUUID(r.GetPlanId()) {
		return nil, status.Error(codes.InvalidArgument, "plan_id is invalid")
	}
	p, e := s.service.GetPlan(ctx, r.GetPlanId())
	if e != nil {
		return nil, workloadRPCError(e)
	}
	return &agentv1.WorkloadServiceQuoteResponse{Quote: &agentv1.CoreWorkloadQuote{PlanId: p.ID, PlanDigest: p.Digest, Summary: p.Summary}}, nil
}
func (s *WorkloadService) RequestApply(ctx context.Context, r *agentv1.WorkloadServiceRequestApplyRequest) (*agentv1.WorkloadServiceRequestApplyResponse, error) {
	if r == nil || !validCoreUUID(r.GetPlanId()) || !validCoreUUID(r.GetIdempotencyKey()) {
		return nil, status.Error(codes.InvalidArgument, "invalid apply request")
	}
	v, e := s.service.RequestApply(ctx, coreworkload.RequestApplyInput{PlanID: r.GetPlanId(), WorkloadID: r.GetWorkloadId(), IdempotencyKey: r.GetIdempotencyKey()})
	if e != nil {
		return nil, workloadRPCError(e)
	}
	return &agentv1.WorkloadServiceRequestApplyResponse{Operation: s.operationProto(ctx, v.Operation), TaskId: v.Task.ID, Confirmation: confirmationProto(v.Confirmation)}, nil
}
func (s *WorkloadService) RequestDestroy(ctx context.Context, r *agentv1.WorkloadServiceRequestDestroyRequest) (*agentv1.WorkloadServiceRequestDestroyResponse, error) {
	if r == nil || !validCoreUUID(r.GetPlanId()) || !validCoreUUID(r.GetIdempotencyKey()) {
		return nil, status.Error(codes.InvalidArgument, "invalid destroy request")
	}
	v, e := s.service.RequestDestroy(ctx, coreworkload.RequestDestroyInput{PlanID: r.GetPlanId(), WorkloadID: r.GetWorkloadId(), IdempotencyKey: r.GetIdempotencyKey()})
	if e != nil {
		return nil, workloadRPCError(e)
	}
	return &agentv1.WorkloadServiceRequestDestroyResponse{Operation: s.operationProto(ctx, v.Operation), TaskId: v.Task.ID, Confirmation: confirmationProto(v.Confirmation)}, nil
}
func (s *WorkloadService) GetWorkload(ctx context.Context, r *agentv1.WorkloadServiceGetWorkloadRequest) (*agentv1.WorkloadServiceGetWorkloadResponse, error) {
	if r == nil || !validCoreUUID(r.GetWorkloadId()) {
		return nil, status.Error(codes.InvalidArgument, "workload_id is invalid")
	}
	w, e := s.service.GetWorkload(ctx, r.GetWorkloadId())
	if e != nil {
		return nil, workloadRPCError(e)
	}
	return &agentv1.WorkloadServiceGetWorkloadResponse{Workload: workloadActualProto(w)}, nil
}
func (s *WorkloadService) ListWorkloads(ctx context.Context, r *agentv1.WorkloadServiceListWorkloadsRequest) (*agentv1.WorkloadServiceListWorkloadsResponse, error) {
	if r == nil {
		return nil, status.Error(codes.InvalidArgument, "request is required")
	}
	limit, e := pageLimit(r.GetPageSize())
	if e != nil {
		return nil, e
	}
	items, next, e := s.service.ListWorkloads(ctx, limit, r.GetPageToken())
	if e != nil {
		return nil, workloadRPCError(e)
	}
	out := &agentv1.WorkloadServiceListWorkloadsResponse{NextPageToken: next}
	for _, w := range items {
		out.Workloads = append(out.Workloads, workloadActualProto(w))
	}
	return out, nil
}
func (s *WorkloadService) GetOperation(ctx context.Context, r *agentv1.WorkloadServiceGetOperationRequest) (*agentv1.WorkloadServiceGetOperationResponse, error) {
	if r == nil || !validCoreUUID(r.GetOperationId()) {
		return nil, status.Error(codes.InvalidArgument, "operation_id is invalid")
	}
	o, e := s.service.GetOperation(ctx, r.GetOperationId())
	if e != nil {
		return nil, workloadRPCError(e)
	}
	return &agentv1.WorkloadServiceGetOperationResponse{Operation: s.operationProto(ctx, o)}, nil
}
func (s *WorkloadService) ListEvents(ctx context.Context, r *agentv1.WorkloadServiceListEventsRequest) (*agentv1.WorkloadServiceListEventsResponse, error) {
	if r == nil || !validCoreUUID(r.GetOperationId()) {
		return nil, status.Error(codes.InvalidArgument, "operation_id is invalid")
	}
	events, e := s.service.ListEvents(ctx, r.GetOperationId(), r.GetAfterSequence())
	if e != nil {
		return nil, workloadRPCError(e)
	}
	out := &agentv1.WorkloadServiceListEventsResponse{}
	for _, ev := range events {
		item := &agentv1.CoreWorkloadEvent{OperationId: ev.OperationID, Sequence: int64(ev.Sequence), Kind: ev.Kind, Status: string(ev.Status), Message: ev.Message, At: timestamppb.New(ev.At)}
		var rb coreworkload.Readback
		if len(ev.Readback) > 0 && json.Unmarshal(ev.Readback, &rb) == nil && rb.WorkloadID != "" {
			item.Actual = &agentv1.CoreWorkloadActualSnapshot{WorkloadId: rb.WorkloadID, State: rb.State, Identity: &agentv1.CoreWorkloadTargetIdentity{Kind: workloadTargetProto(rb.Identity.Kind), CoreRunnerId: rb.Identity.CoreRunnerID, CoreRunnerService: rb.Identity.CoreRunnerService, ImageDigest: rb.Identity.ImageDigest}, ReadbackDigest: rb.Digest, ProviderVersion: rb.ProviderVersion, ObservedAt: timestamppb.New(rb.At)}
		}
		out.Events = append(out.Events, item)
	}
	return out, nil
}
func (s *WorkloadService) Cancel(ctx context.Context, r *agentv1.WorkloadServiceCancelRequest) (*agentv1.WorkloadServiceCancelResponse, error) {
	if r == nil || !validCoreUUID(r.GetOperationId()) || !validCoreUUID(r.GetIdempotencyKey()) || r.GetExpectedRevision() < 1 {
		return nil, status.Error(codes.InvalidArgument, "invalid cancel request")
	}
	o, e := s.service.Cancel(ctx, r.GetOperationId(), r.GetIdempotencyKey(), uint64(r.GetExpectedRevision()))
	if e != nil {
		return nil, workloadRPCError(e)
	}
	return &agentv1.WorkloadServiceCancelResponse{Operation: s.operationProto(ctx, o), TaskId: o.TaskID}, nil
}

func (s *WorkloadService) operationProto(ctx context.Context, o coreworkload.Operation) *agentv1.CoreWorkloadOperation {
	out := workloadOperationProto(o)
	if p, err := s.service.GetPlan(ctx, o.PlanID); err == nil {
		out.DesiredPlan = &agentv1.CoreWorkloadOperationPlan{PlanId: p.ID, PlanRevision: p.Revision, PlanDigest: p.Digest, Target: typedTargetProto(p), ResourceLimits: typedLimitsProto(p.ResourceLimits)}
		for _, ref := range p.SecretGrantRefs {
			out.DesiredPlan.SecretGrants = append(out.DesiredPlan.SecretGrants, &agentv1.CoreWorkloadSecretGrantRef{ReferenceId: ref.ReferenceID, Purpose: workloadSecretPurposeProto(ref.Purpose), BindingDigest: string(ref.BindingDigest)})
		}
	}
	if w, err := s.service.GetWorkload(ctx, o.WorkloadID); err == nil {
		out.Actual = workloadActualProto(w)
	}
	return out
}
func workloadTarget(v agentv1.CoreWorkloadTargetKind) coreworkload.TargetKind {
	switch v {
	case agentv1.CoreWorkloadTargetKind_CORE_WORKLOAD_TARGET_KIND_CORE_RUNNER:
		return coreworkload.TargetCoreRunner
	}
	return ""
}

func workloadTargetProto(v coreworkload.TargetKind) agentv1.CoreWorkloadTargetKind {
	if v == coreworkload.TargetCoreRunner {
		return agentv1.CoreWorkloadTargetKind_CORE_WORKLOAD_TARGET_KIND_CORE_RUNNER
	}
	return agentv1.CoreWorkloadTargetKind_CORE_WORKLOAD_TARGET_KIND_UNSPECIFIED
}
func coreworkloadSecretPurpose(v agentv1.CoreWorkloadSecretPurpose) coreconfirmation.SecretPurpose {
	switch v {
	case agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_MODEL_API_KEY:
		return coreconfirmation.SecretPurposeModelAPIKey
	case agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_MCP_CREDENTIAL:
		return coreconfirmation.SecretPurposeMCPCredential
	case agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_SKILL_SECRET:
		return coreconfirmation.SecretPurposeSkillSecret
	case agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_AWS_CREDENTIAL:
		return coreconfirmation.SecretPurposeAWSCredential
	case agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_OTHER_EXTENSION_SECRET:
		return coreconfirmation.SecretPurposeOtherExtensionSecret
	}
	return ""
}
func workloadSecretPurposeProto(v coreconfirmation.SecretPurpose) agentv1.CoreWorkloadSecretPurpose {
	switch v {
	case coreconfirmation.SecretPurposeModelAPIKey:
		return agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_MODEL_API_KEY
	case coreconfirmation.SecretPurposeMCPCredential:
		return agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_MCP_CREDENTIAL
	case coreconfirmation.SecretPurposeSkillSecret:
		return agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_SKILL_SECRET
	case coreconfirmation.SecretPurposeAWSCredential:
		return agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_AWS_CREDENTIAL
	case coreconfirmation.SecretPurposeOtherExtensionSecret:
		return agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_OTHER_EXTENSION_SECRET
	default:
		return agentv1.CoreWorkloadSecretPurpose_CORE_WORKLOAD_SECRET_PURPOSE_UNSPECIFIED
	}
}
func targetSettingsFromTypedProto(v *agentv1.CoreWorkloadTargetSettings) coreworkload.TargetSettings {
	if v == nil {
		return coreworkload.TargetSettings{}
	}
	out := coreworkload.TargetSettings{Labels: map[string]string{}}
	if id := v.GetIdentity(); id != nil {
		out.Identity = coreworkload.TargetIdentity{Kind: workloadTarget(id.GetKind()), CoreRunnerID: id.GetCoreRunnerId(), CoreRunnerService: id.GetCoreRunnerService(), ImageDigest: id.GetImageDigest()}
	}
	for _, p := range v.GetPorts() {
		if p != nil {
			out.Ports = append(out.Ports, int32(p.GetPort()))
			out.PortDetails = append(out.PortDetails, coreworkload.Port{Port: p.GetPort()})
		}
	}
	for _, g := range v.GetNetworkGrants() {
		if g != nil {
			out.NetworkGrantDetails = append(out.NetworkGrantDetails, coreworkload.NetworkGrant{ReferenceID: g.GetReferenceId(), Kind: g.GetKind()})
		}
	}
	for k, val := range v.GetLabels() {
		out.Labels[k] = val
	}
	return out
}
func workloadPlanProto(p coreworkload.Plan) *agentv1.CoreWorkloadPlan {
	refs := make([]*agentv1.CoreWorkloadSecretGrantRef, 0, len(p.SecretGrantRefs))
	for _, ref := range p.SecretGrantRefs {
		refs = append(refs, &agentv1.CoreWorkloadSecretGrantRef{ReferenceId: ref.ReferenceID, Purpose: workloadSecretPurposeProto(ref.Purpose), BindingDigest: string(ref.BindingDigest)})
	}
	return &agentv1.CoreWorkloadPlan{PlanId: p.ID, Revision: int64(p.Revision), Digest: p.Digest, Summary: p.Summary, Artifact: p.Artifact, Source: p.Source, CommandSteps: p.CommandSteps, ImageDigest: p.ImageDigest, TargetKind: workloadTargetProto(p.TargetKind), TypedTarget: typedTargetProto(p), TypedResourceLimits: typedLimitsProto(p.ResourceLimits), TypedSecretGrants: refs, ExpiresAt: timestamppb.New(p.ExpiresAt), CreatedAt: timestamppb.New(p.CreatedAt)}
}
func resourceLimitsFromTypedProto(v *agentv1.CoreWorkloadResourceLimits) coreworkload.ResourceLimits {
	if v == nil {
		return coreworkload.ResourceLimits{}
	}
	return coreworkload.ResourceLimits{CPU: v.GetCpu(), MemoryMB: v.GetMemoryMb(), Processes: v.GetProcesses(), DiskMB: v.GetDiskMb(), TimeoutS: v.GetTimeoutSeconds(), OutputMB: v.GetOutputMb()}
}
func typedTargetProto(p coreworkload.Plan) *agentv1.CoreWorkloadTargetSettings {
	id := p.Target.Identity
	if id.Kind == "" {
		id.Kind = p.TargetKind
	}
	if id.ImageDigest == "" {
		id.ImageDigest = p.ImageDigest
	}
	out := &agentv1.CoreWorkloadTargetSettings{Identity: &agentv1.CoreWorkloadTargetIdentity{Kind: workloadTargetProto(id.Kind), CoreRunnerId: id.CoreRunnerID, CoreRunnerService: id.CoreRunnerService, ImageDigest: id.ImageDigest}, Labels: p.Target.Labels}
	for _, port := range p.Target.PortDetails {
		out.Ports = append(out.Ports, &agentv1.CoreWorkloadPort{Port: port.Port})
	}
	if len(out.Ports) == 0 {
		for _, port := range p.Target.Ports {
			out.Ports = append(out.Ports, &agentv1.CoreWorkloadPort{Port: uint32(port)})
		}
	}
	for _, grant := range p.Target.NetworkGrantDetails {
		out.NetworkGrants = append(out.NetworkGrants, &agentv1.CoreWorkloadNetworkGrant{ReferenceId: grant.ReferenceID, Kind: grant.Kind})
	}
	if len(out.NetworkGrants) == 0 {
		for _, ref := range p.NetworkGrants {
			out.NetworkGrants = append(out.NetworkGrants, &agentv1.CoreWorkloadNetworkGrant{ReferenceId: ref})
		}
	}
	return out
}
func typedLimitsProto(v coreworkload.ResourceLimits) *agentv1.CoreWorkloadResourceLimits {
	return &agentv1.CoreWorkloadResourceLimits{Cpu: v.CPU, MemoryMb: v.MemoryMB, Processes: v.Processes, DiskMb: v.DiskMB, TimeoutSeconds: v.TimeoutS, OutputMb: v.OutputMB}
}
func workloadActualProto(w coreworkload.Workload) *agentv1.CoreWorkloadActualSnapshot {
	a := w.Actual
	if a.WorkloadID != "" {
		return &agentv1.CoreWorkloadActualSnapshot{WorkloadId: a.WorkloadID, Revision: a.Revision, State: a.State, AppliedPlanId: a.AppliedPlanID, AppliedPlanDigest: a.AppliedPlanDigest, ReadbackDigest: a.ReadbackDigest, ProviderVersion: a.ProviderVersion, ObservedAt: timestamppb.New(a.ObservedAt), UpdatedAt: timestamppb.New(a.UpdatedAt), Identity: typedTargetProto(coreworkload.Plan{TargetKind: a.Identity.Kind, Target: coreworkload.TargetSettings{Identity: a.Identity}}).Identity}
	}
	id := w.Identity
	if id.Kind == "" {
		id.Kind = w.TargetKind
	}
	return &agentv1.CoreWorkloadActualSnapshot{WorkloadId: w.ID, Revision: w.Revision, State: w.State, AppliedPlanId: w.PlanID, AppliedPlanDigest: w.PlanDigest, UpdatedAt: timestamppb.New(w.UpdatedAt), Identity: &agentv1.CoreWorkloadTargetIdentity{Kind: workloadTargetProto(id.Kind), CoreRunnerId: id.CoreRunnerID, CoreRunnerService: id.CoreRunnerService, ImageDigest: id.ImageDigest}}
}

func workloadOperationProto(o coreworkload.Operation) *agentv1.CoreWorkloadOperation {
	return &agentv1.CoreWorkloadOperation{OperationId: o.ID, WorkloadId: o.WorkloadID, PlanId: o.PlanID, Kind: map[coreworkload.OperationKind]agentv1.CoreWorkloadOperationKind{coreworkload.OperationApply: agentv1.CoreWorkloadOperationKind_CORE_WORKLOAD_OPERATION_KIND_APPLY, coreworkload.OperationDestroy: agentv1.CoreWorkloadOperationKind_CORE_WORKLOAD_OPERATION_KIND_DESTROY}[o.Kind], PlanRevision: int64(o.PlanRevision), PlanDigest: o.PlanDigest, TargetKind: workloadTargetProto(o.TargetKind), TaskId: o.TaskID, ConfirmationId: o.ConfirmationID, Status: string(o.Status), Revision: int64(o.Revision), FailureCode: o.FailureCode, FailureSummary: o.FailureSummary, DispatchClaim: o.DispatchClaim, DispatchEpoch: o.DispatchEpoch, DispatchLeaseUntil: timestamppb.New(o.DispatchLeaseUntil), CreatedAt: timestamppb.New(o.CreatedAt), UpdatedAt: timestamppb.New(o.UpdatedAt)}
}
func workloadRPCError(e error) error {
	switch {
	case errors.Is(e, coreworkload.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid workload request")
	case errors.Is(e, coreworkload.ErrNotFound):
		return status.Error(codes.NotFound, "workload resource not found")
	case errors.Is(e, coreworkload.ErrRevisionConflict), errors.Is(e, coreworkload.ErrStale):
		return status.Error(codes.Aborted, "workload revision conflict")
	case errors.Is(e, coreworkload.ErrConflict):
		return status.Error(codes.Aborted, "workload request conflict")
	default:
		return status.Error(codes.Internal, "workload service failure")
	}
}
