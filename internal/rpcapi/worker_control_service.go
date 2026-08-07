package rpcapi

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const maximumWorkerControlMaterialBytes = 2 << 20

// WorkerLaunchLookup is the immutable bootstrap identity presented before an
// EC2 instance is allowed to receive a nonce. The resolver must read the
// current dispatch/resource ledger and CoreTask lease; request fields alone
// are never an authorization boundary.
type WorkerLaunchLookup = control.LaunchLookup

type WorkerLaunchResolver interface {
	ResolveWorkerLaunch(context.Context, WorkerLaunchLookup) (control.IssueChallengeRequest, error)
}

// WorkerClaimMaterial is private execution material returned only after the
// signed EC2 identity was verified and a fenced WorkerControl session was
// created. Implementations issue a short-lived relay bearer; they never return
// the underlying provider credential.
type WorkerClaimMaterial struct {
	RuntimeTaskJSON     []byte
	RuntimeTaskDigest   string
	InputManifestJSON   []byte
	InputManifestDigest string
	ArtifactScope       cloudresult.Scope
	ModelGrant          cloudruntime.ModelGrant
	HeartbeatInterval   time.Duration
	NotAfter            time.Time
}

func (material *WorkerClaimMaterial) Destroy() {
	if material == nil {
		return
	}
	clear(material.RuntimeTaskJSON)
	clear(material.InputManifestJSON)
	material.ModelGrant.Destroy()
	*material = WorkerClaimMaterial{}
}

type WorkerClaimMaterialIssuer interface {
	IssueWorkerClaimMaterial(context.Context, control.Session) (WorkerClaimMaterial, error)
	ValidateWorkerResultClaim(context.Context, control.TaskFence, control.ObjectClaim) error
	ValidateWorkerRuntimeTopology(context.Context, control.TaskFence, execgate.Proof) error
}

// WorkerControlService is registered only on the dedicated Worker TLS
// listener. It deliberately has no service-token, Product Capability, or
// authenticated-owner fallback.
type WorkerControlService struct {
	agentv1.UnimplementedWorkerControlServiceServer
	control   *control.Service
	launches  WorkerLaunchResolver
	materials WorkerClaimMaterialIssuer
	now       func() time.Time
}

func NewWorkerControlService(
	service *control.Service,
	launches WorkerLaunchResolver,
	materials WorkerClaimMaterialIssuer,
) (*WorkerControlService, error) {
	if service == nil || launches == nil || materials == nil {
		return nil, errors.New("WorkerControlService requires control, launch, and material authorities")
	}
	return &WorkerControlService{
		control: service, launches: launches, materials: materials,
		now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (service *WorkerControlService) IssueIdentityChallenge(
	ctx context.Context,
	request *agentv1.WorkerControlServiceIssueIdentityChallengeRequest,
) (*agentv1.WorkerControlServiceIssueIdentityChallengeResponse, error) {
	if service == nil || request == nil || request.Launch == nil || !canonicalControlUUID(request.IdempotencyKey) {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker identity challenge request")
	}
	lookup := WorkerLaunchLookup{
		ExecutionID: request.Launch.ExecutionId, TaskID: request.Launch.TaskId,
		AccountGeneration: request.Launch.AccountGeneration,
		InstanceID:        request.Launch.InstanceId, LaunchIdentity: request.Launch.LaunchIdentity,
	}
	if !canonicalControlUUID(lookup.ExecutionID) || !canonicalControlUUID(lookup.TaskID) ||
		lookup.AccountGeneration == 0 || strings.TrimSpace(lookup.InstanceID) != lookup.InstanceID ||
		strings.TrimSpace(lookup.LaunchIdentity) != lookup.LaunchIdentity || lookup.InstanceID == "" || lookup.LaunchIdentity == "" {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker launch identity")
	}
	domainRequest, err := service.launches.ResolveWorkerLaunch(ctx, lookup)
	if err != nil {
		return nil, workerControlError(err)
	}
	if domainRequest.Fence.ExecutionID != lookup.ExecutionID || domainRequest.Fence.TaskID != lookup.TaskID ||
		domainRequest.Fence.AccountGeneration != lookup.AccountGeneration ||
		domainRequest.Expectation.AccountGeneration != lookup.AccountGeneration ||
		domainRequest.Expectation.InstanceID != lookup.InstanceID ||
		domainRequest.Expectation.LaunchIdentity != lookup.LaunchIdentity {
		return nil, status.Error(codes.FailedPrecondition, "Worker launch fence changed")
	}
	challenge, err := service.control.IssueIdentityChallenge(ctx, domainRequest)
	if err != nil {
		return nil, workerControlError(err)
	}
	return &agentv1.WorkerControlServiceIssueIdentityChallengeResponse{
		ChallengeId: challenge.ChallengeID, Nonce: challenge.Nonce,
		Fence: workerFenceProto(challenge.Fence), ExpiresAt: timestamppb.New(challenge.ExpiresAt),
	}, nil
}

func (service *WorkerControlService) Claim(
	ctx context.Context,
	request *agentv1.WorkerControlServiceClaimRequest,
) (*agentv1.WorkerControlServiceClaimResponse, error) {
	if service == nil || request == nil || request.Proof == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker claim request")
	}
	fence, err := workerFenceFromProto(request.Fence)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker task fence")
	}
	proofPayload := bytes.Clone(request.Proof.Payload)
	defer clear(proofPayload)
	claimed, err := service.control.Claim(ctx, control.ClaimRequest{
		ChallengeID: request.ChallengeId, Nonce: request.Nonce, Fence: fence,
		Proof: control.IdentityProof{Method: request.Proof.Method, Payload: proofPayload},
	})
	if err != nil {
		return nil, workerControlError(err)
	}
	defer claimed.Destroy()
	material, err := service.materials.IssueWorkerClaimMaterial(ctx, claimed.Session)
	if err != nil {
		return nil, workerControlError(err)
	}
	defer material.Destroy()
	if err := validateWorkerClaimMaterial(claimed.Session, claimed.SessionToken, material, service.now().UTC()); err != nil {
		return nil, status.Error(codes.FailedPrecondition, "Worker launch material changed")
	}
	grantExpiry := time.Unix(material.ModelGrant.ExpiresAtUnix, 0).UTC()
	return &agentv1.WorkerControlServiceClaimResponse{
		Session: workerSessionProto(claimed.Session), SessionToken: bytes.Clone(claimed.SessionToken),
		ModelGrant: &agentv1.CoreCloudWorkerModelGrant{
			GrantId: material.ModelGrant.GrantID, BearerToken: bytes.Clone(material.ModelGrant.BearerToken),
			ModelBindingDigest: material.ModelGrant.ModelBindingSHA256,
			AudienceDigest:     material.ModelGrant.AudienceSHA256, ExpiresAt: timestamppb.New(grantExpiry),
			RelayUrl: material.ModelGrant.RelayBaseURL, RelayBindingDigest: material.ModelGrant.RelayBindingSHA256,
			MaxTokens: material.ModelGrant.MaxOutputTokens, LimitDigest: material.ModelGrant.LimitSHA256,
		},
		RuntimeTaskJson: bytes.Clone(material.RuntimeTaskJSON), RuntimeTaskDigest: material.RuntimeTaskDigest,
		InputManifestJson: bytes.Clone(material.InputManifestJSON), InputManifestDigest: material.InputManifestDigest,
		ArtifactBucket: material.ArtifactScope.Bucket, ArtifactKeyPrefix: material.ArtifactScope.KeyPrefix,
		HeartbeatIntervalMillis: uint64(material.HeartbeatInterval / time.Millisecond),
		NotAfter:                timestamppb.New(material.NotAfter),
	}, nil
}

func (service *WorkerControlService) Heartbeat(
	ctx context.Context,
	request *agentv1.WorkerControlServiceHeartbeatRequest,
) (*agentv1.WorkerControlServiceHeartbeatResponse, error) {
	if service == nil || request == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker heartbeat request")
	}
	fence, err := workerFenceFromProto(request.Fence)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker task fence")
	}
	sessionToken := bytes.Clone(request.SessionToken)
	defer clear(sessionToken)
	session, err := service.control.Heartbeat(ctx, control.HeartbeatRequest{
		SessionID: request.SessionId, SessionToken: sessionToken, Fence: fence,
		ProgressSequence: request.ProgressSequence, IdempotencyKey: request.IdempotencyKey,
	})
	if err != nil {
		return nil, workerControlError(err)
	}
	return &agentv1.WorkerControlServiceHeartbeatResponse{Session: workerSessionProto(session)}, nil
}

func (service *WorkerControlService) Complete(
	ctx context.Context,
	request *agentv1.WorkerControlServiceCompleteRequest,
) (*agentv1.WorkerControlServiceCompleteResponse, error) {
	if service == nil || request == nil || request.Claim == nil || request.RuntimeTopology == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker completion request")
	}
	fence, err := workerFenceFromProto(request.Fence)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker task fence")
	}
	claim := control.ObjectClaim{
		Bucket: request.Claim.Bucket, Key: request.Claim.Key, VersionID: request.Claim.VersionId,
		SHA256: request.Claim.Sha256, SizeBytes: request.Claim.SizeBytes, MediaType: request.Claim.MediaType,
	}
	topology, err := workerRuntimeTopologyFromProto(request.RuntimeTopology)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker runtime topology")
	}
	if err := service.materials.ValidateWorkerRuntimeTopology(ctx, fence, topology); err != nil {
		return nil, workerControlError(err)
	}
	if err := service.materials.ValidateWorkerResultClaim(ctx, fence, claim); err != nil {
		return nil, workerControlError(err)
	}
	sessionToken := bytes.Clone(request.SessionToken)
	defer clear(sessionToken)
	session, err := service.control.Complete(ctx, control.CompleteRequest{
		SessionID: request.SessionId, SessionToken: sessionToken, Fence: fence,
		Claim:           claim,
		RuntimeTopology: topology,
		IdempotencyKey:  request.IdempotencyKey,
	})
	if err != nil {
		return nil, workerControlError(err)
	}
	return &agentv1.WorkerControlServiceCompleteResponse{Session: workerSessionProto(session)}, nil
}

func (service *WorkerControlService) Fail(
	ctx context.Context,
	request *agentv1.WorkerControlServiceFailRequest,
) (*agentv1.WorkerControlServiceFailResponse, error) {
	if service == nil || request == nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker failure request")
	}
	fence, err := workerFenceFromProto(request.Fence)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid Worker task fence")
	}
	sessionToken := bytes.Clone(request.SessionToken)
	defer clear(sessionToken)
	session, err := service.control.Fail(ctx, control.FailRequest{
		SessionID: request.SessionId, SessionToken: sessionToken, Fence: fence,
		Code: request.Code, Summary: request.Summary, IdempotencyKey: request.IdempotencyKey,
	})
	if err != nil {
		return nil, workerControlError(err)
	}
	return &agentv1.WorkerControlServiceFailResponse{Session: workerSessionProto(session)}, nil
}

func validateWorkerClaimMaterial(session control.Session, sessionToken []byte, material WorkerClaimMaterial, now time.Time) error {
	if session.State != control.SessionActive || len(sessionToken) < 32 || len(sessionToken) > 256 ||
		len(material.RuntimeTaskJSON) == 0 || len(material.RuntimeTaskJSON) > maximumWorkerControlMaterialBytes ||
		len(material.InputManifestJSON) == 0 || len(material.InputManifestJSON) > maximumWorkerControlMaterialBytes ||
		material.ArtifactScope.Validate() != nil || material.HeartbeatInterval < time.Second ||
		material.HeartbeatInterval > time.Minute || material.NotAfter != material.NotAfter.UTC() ||
		!material.NotAfter.After(now.Add(2*material.HeartbeatInterval)) {
		return errors.New("invalid Worker claim material")
	}
	task, err := cloudruntime.ParseTask(material.RuntimeTaskJSON)
	if err != nil || task.TaskID != session.Fence.TaskID || task.ExecutionID != session.Fence.ExecutionID {
		return errors.New("invalid Worker runtime task")
	}
	digest, err := task.Digest()
	if err != nil || digest != material.RuntimeTaskDigest || task.InputManifestSHA256 != material.InputManifestDigest ||
		cloudruntime.ValidateInputManifestJSON(material.InputManifestJSON, material.InputManifestDigest) != nil ||
		material.ModelGrant.ValidateFor(task, now) != nil ||
		time.Unix(material.ModelGrant.ExpiresAtUnix, 0).UTC().Before(material.NotAfter) {
		return errors.New("invalid Worker material binding")
	}
	return nil
}

func workerFenceFromProto(value *agentv1.CoreCloudWorkerTaskFence) (control.TaskFence, error) {
	if value == nil || !canonicalControlUUID(value.ExecutionId) || !canonicalControlUUID(value.TaskId) ||
		value.AccountGeneration == 0 || value.Attempt == 0 || value.LeaseEpoch == 0 {
		return control.TaskFence{}, errors.New("invalid Worker task fence")
	}
	return control.TaskFence{
		ExecutionID: value.ExecutionId, TaskID: value.TaskId, AccountGeneration: value.AccountGeneration,
		Attempt: value.Attempt, LeaseEpoch: value.LeaseEpoch,
	}, nil
}

func workerFenceProto(value control.TaskFence) *agentv1.CoreCloudWorkerTaskFence {
	return &agentv1.CoreCloudWorkerTaskFence{
		ExecutionId: value.ExecutionID, TaskId: value.TaskID, AccountGeneration: value.AccountGeneration,
		Attempt: value.Attempt, LeaseEpoch: value.LeaseEpoch,
	}
}

func workerSessionProto(value control.Session) *agentv1.CoreCloudWorkerSession {
	result := &agentv1.CoreCloudWorkerSession{
		SessionId: value.SessionID, Fence: workerFenceProto(value.Fence),
		ProgressSequence: value.ProgressSequence, FailureCode: value.FailureCode,
		FailureSummary: value.FailureSummary, Revision: value.Revision,
	}
	switch value.State {
	case control.SessionActive:
		result.State = agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_ACTIVE
	case control.SessionCompleted:
		result.State = agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_COMPLETED
	case control.SessionFailed:
		result.State = agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_FAILED
	}
	if value.Result != nil {
		result.Result = &agentv1.CoreCloudWorkerObjectClaim{
			Bucket: value.Result.Bucket, Key: value.Result.Key, VersionId: value.Result.VersionID,
			Sha256: value.Result.SHA256, SizeBytes: value.Result.SizeBytes, MediaType: value.Result.MediaType,
		}
	}
	if value.RuntimeTopology != nil {
		result.RuntimeTopology = workerRuntimeTopologyProto(*value.RuntimeTopology)
		result.RuntimeTopologyDigest = value.TopologyDigest
	}
	if !value.ClaimedAt.IsZero() {
		result.ClaimedAt = timestamppb.New(value.ClaimedAt)
	}
	if !value.HeartbeatAt.IsZero() {
		result.HeartbeatAt = timestamppb.New(value.HeartbeatAt)
	}
	if !value.FinishedAt.IsZero() {
		result.FinishedAt = timestamppb.New(value.FinishedAt)
	}
	return result
}

func workerRuntimeTopologyProto(proof execgate.Proof) *agentv1.CoreCloudWorkerRuntimeTopologyProof {
	state := agentv1.CoreCloudWorkerRuntimeTopologyState_CORE_CLOUD_WORKER_RUNTIME_TOPOLOGY_STATE_UNSPECIFIED
	switch proof.State {
	case execgate.ProofActive:
		state = agentv1.CoreCloudWorkerRuntimeTopologyState_CORE_CLOUD_WORKER_RUNTIME_TOPOLOGY_STATE_ACTIVE
	case execgate.ProofTerminal:
		state = agentv1.CoreCloudWorkerRuntimeTopologyState_CORE_CLOUD_WORKER_RUNTIME_TOPOLOGY_STATE_TERMINAL
	case execgate.ProofViolated:
		state = agentv1.CoreCloudWorkerRuntimeTopologyState_CORE_CLOUD_WORKER_RUNTIME_TOPOLOGY_STATE_VIOLATED
	}
	return &agentv1.CoreCloudWorkerRuntimeTopologyProof{
		SchemaVersion: proof.SchemaVersion, State: state, RunId: proof.RunID,
		ExecutionId: proof.ExecutionID, TaskId: proof.TaskID, Attempt: proof.Attempt,
		LeaseEpoch: proof.LeaseEpoch, RuntimeTaskSha256: proof.RuntimeTaskSHA256,
		BootId: proof.BootID, CgroupSha256: proof.CgroupSHA256, PolicySha256: proof.PolicySHA256,
		Worker: &agentv1.CoreCloudWorkerProcessIdentity{
			Pid: proof.Worker.PID, StartTimeTicks: proof.Worker.StartTimeTicks,
			Device: proof.Worker.Device, Inode: proof.Worker.Inode, Sha256: proof.Worker.SHA256,
		},
		Pi: &agentv1.CoreCloudWorkerProcessIdentity{
			Pid: proof.Pi.PID, StartTimeTicks: proof.Pi.StartTimeTicks,
			Device: proof.Pi.Device, Inode: proof.Pi.Inode, Sha256: proof.Pi.SHA256,
		},
		WorkerProcessCount: proof.WorkerProcessCount, ActivePiProcesses: proof.ActivePiProcesses,
		TotalAllowedPiExecs: proof.TotalAllowedPiExecs, ObservedAtUnixNano: proof.ObservedAtUnixNano,
		ViolationCode: proof.ViolationCode, CgroupProcessCount: proof.CgroupProcessCount,
		ActiveDescendants: proof.ActiveDescendants,
	}
}

func workerRuntimeTopologyFromProto(value *agentv1.CoreCloudWorkerRuntimeTopologyProof) (execgate.Proof, error) {
	if value == nil || value.Worker == nil || value.Pi == nil {
		return execgate.Proof{}, errors.New("missing Worker runtime topology")
	}
	state := execgate.ProofState("")
	switch value.State {
	case agentv1.CoreCloudWorkerRuntimeTopologyState_CORE_CLOUD_WORKER_RUNTIME_TOPOLOGY_STATE_ACTIVE:
		state = execgate.ProofActive
	case agentv1.CoreCloudWorkerRuntimeTopologyState_CORE_CLOUD_WORKER_RUNTIME_TOPOLOGY_STATE_TERMINAL:
		state = execgate.ProofTerminal
	case agentv1.CoreCloudWorkerRuntimeTopologyState_CORE_CLOUD_WORKER_RUNTIME_TOPOLOGY_STATE_VIOLATED:
		state = execgate.ProofViolated
	default:
		return execgate.Proof{}, errors.New("invalid Worker runtime topology state")
	}
	proof := execgate.Proof{
		SchemaVersion: value.SchemaVersion, State: state, RunID: value.RunId,
		ExecutionID: value.ExecutionId, TaskID: value.TaskId, Attempt: value.Attempt,
		LeaseEpoch: value.LeaseEpoch, RuntimeTaskSHA256: value.RuntimeTaskSha256,
		BootID: value.BootId, CgroupSHA256: value.CgroupSha256, PolicySHA256: value.PolicySha256,
		Worker: execgate.ProcessIdentity{
			PID: value.Worker.Pid, StartTimeTicks: value.Worker.StartTimeTicks,
			Device: value.Worker.Device, Inode: value.Worker.Inode, SHA256: value.Worker.Sha256,
		},
		Pi: execgate.ProcessIdentity{
			PID: value.Pi.Pid, StartTimeTicks: value.Pi.StartTimeTicks,
			Device: value.Pi.Device, Inode: value.Pi.Inode, SHA256: value.Pi.Sha256,
		},
		WorkerProcessCount: value.WorkerProcessCount, ActivePiProcesses: value.ActivePiProcesses,
		TotalAllowedPiExecs: value.TotalAllowedPiExecs, ObservedAtUnixNano: value.ObservedAtUnixNano,
		ViolationCode: value.ViolationCode, CgroupProcessCount: value.CgroupProcessCount,
		ActiveDescendants: value.ActiveDescendants,
	}
	if proof.ValidateTerminal() != nil {
		return execgate.Proof{}, errors.New("invalid terminal Worker runtime topology")
	}
	return proof, nil
}

func canonicalControlUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func workerControlError(err error) error {
	switch {
	case errors.Is(err, control.ErrInvalid):
		return status.Error(codes.InvalidArgument, "invalid Worker control request")
	case errors.Is(err, control.ErrNotFound):
		return status.Error(codes.NotFound, "Worker control record not found")
	case errors.Is(err, control.ErrChallengeExpired), errors.Is(err, control.ErrChallengeConsumed),
		errors.Is(err, control.ErrIdentityRejected), errors.Is(err, control.ErrSessionRejected),
		errors.Is(err, control.ErrStaleLease), errors.Is(err, control.ErrTerminal):
		return status.Error(codes.FailedPrecondition, "Worker control fence rejected")
	case errors.Is(err, control.ErrConflict):
		return status.Error(codes.Aborted, "Worker control state changed")
	case errors.Is(err, context.Canceled):
		return status.Error(codes.Canceled, "Worker control request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return status.Error(codes.DeadlineExceeded, "Worker control deadline exceeded")
	default:
		return status.Error(codes.Internal, "Worker control unavailable")
	}
}

var _ agentv1.WorkerControlServiceServer = (*WorkerControlService)(nil)
