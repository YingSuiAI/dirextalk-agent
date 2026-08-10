package worker

import (
	"bytes"
	"context"
	"errors"
	"math"
	"sync"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/identitywire"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type GRPCControlClient struct {
	rpc       agentv1.WorkerControlServiceClient
	bootstrap BootstrapBinding
	now       func() time.Time

	mu        sync.Mutex
	sessionID string
	fence     Fence
	notAfter  time.Time
}

func NewGRPCControlClient(
	rpc agentv1.WorkerControlServiceClient,
	bootstrap BootstrapBinding,
) (*GRPCControlClient, error) {
	return newGRPCControlClient(rpc, bootstrap, func() time.Time { return time.Now().UTC() })
}

func newGRPCControlClient(
	rpc agentv1.WorkerControlServiceClient,
	bootstrap BootstrapBinding,
	now func() time.Time,
) (*GRPCControlClient, error) {
	if rpc == nil || bootstrap.Validate() != nil || now == nil {
		return nil, ErrInvalid
	}
	return &GRPCControlClient{rpc: rpc, bootstrap: bootstrap, now: now}, nil
}

func (client *GRPCControlClient) IssueIdentityChallenge(
	ctx context.Context,
	request ChallengeRequest,
) (Challenge, error) {
	if client == nil || ctx == nil || request.Validate() != nil ||
		request.ExecutionID != client.bootstrap.ExecutionID ||
		request.TaskID != client.bootstrap.TaskID ||
		request.AccountGeneration != client.bootstrap.AccountGeneration ||
		request.InstanceID != client.bootstrap.InstanceID ||
		request.LaunchIdentity != client.bootstrap.LaunchIdentity {
		return Challenge{}, ErrInvalid
	}
	response, err := client.rpc.IssueIdentityChallenge(
		ctx, &agentv1.WorkerControlServiceIssueIdentityChallengeRequest{
			Launch: &agentv1.CoreCloudWorkerLaunchLookup{
				ExecutionId: request.ExecutionID, TaskId: request.TaskID,
				AccountGeneration: request.AccountGeneration,
				InstanceId:        request.InstanceID, LaunchIdentity: request.LaunchIdentity,
			},
			IdempotencyKey: request.IdempotencyKey,
		},
	)
	if err != nil {
		return Challenge{}, mapControlRPCError(err)
	}
	if response == nil || response.ExpiresAt == nil ||
		response.ExpiresAt.CheckValid() != nil {
		return Challenge{}, ErrInvalid
	}
	fence, err := fenceFromProto(response.Fence)
	if err != nil {
		return Challenge{}, err
	}
	challenge := Challenge{
		ChallengeID: response.ChallengeId, Nonce: response.Nonce,
		Fence: fence, ExpiresAt: response.ExpiresAt.AsTime().UTC(),
	}
	if !validChallenge(challenge, client.bootstrap, client.now().UTC()) {
		return Challenge{}, ErrInvalid
	}
	return challenge, nil
}

func (client *GRPCControlClient) Claim(
	ctx context.Context,
	fence Fence,
	challengeID string,
	proof *IdentityProof,
) (ClaimedTask, error) {
	if client == nil || ctx == nil || fence.Validate() != nil ||
		!canonicalUUID(challengeID) || proof == nil || proof.Challenge == "" {
		return ClaimedTask{}, ErrInvalid
	}
	binding, err := client.bootstrap.Bind(fence)
	if err != nil {
		return ClaimedTask{}, err
	}
	wirePayload := identitywire.Payload{
		Region: proof.Region, Endpoint: proof.Endpoint, Method: proof.Method,
		Host: proof.Host, ContentType: proof.ContentType,
		ContentSHA256: proof.ContentSHA256, AmzDate: proof.AmzDate,
		Challenge: proof.Challenge, Body: bytes.Clone(proof.Body),
		Authorization: bytes.Clone(proof.Authorization),
		SessionToken:  bytes.Clone(proof.SessionToken),
		IMDSDocument:  bytes.Clone(proof.IMDSDocument),
		IMDSPKCS7:     bytes.Clone(proof.IMDSPKCS7),
	}
	defer wirePayload.Destroy()
	payload, err := identitywire.Encode(wirePayload)
	if err != nil {
		clear(payload)
		return ClaimedTask{}, ErrIdentityChanged
	}
	defer clear(payload)
	response, err := client.rpc.Claim(ctx, &agentv1.WorkerControlServiceClaimRequest{
		ChallengeId: challengeID, Nonce: proof.Challenge, Fence: fenceToProto(fence),
		Proof: &agentv1.CoreCloudWorkerIdentityProof{
			Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: payload,
		},
	})
	if err != nil {
		return ClaimedTask{}, mapControlRPCError(err)
	}
	claimed, err := client.claimedTaskFromProto(binding, response)
	if err != nil {
		claimed.Destroy()
		return ClaimedTask{}, err
	}
	client.mu.Lock()
	client.sessionID, client.fence, client.notAfter =
		claimed.SessionID, claimed.Binding.Fence(), claimed.NotAfter
	client.mu.Unlock()
	return claimed, nil
}

func (client *GRPCControlClient) claimedTaskFromProto(
	binding Binding,
	response *agentv1.WorkerControlServiceClaimResponse,
) (ClaimedTask, error) {
	if response == nil || response.Session == nil || response.ModelGrant == nil ||
		response.NotAfter == nil || response.NotAfter.CheckValid() != nil ||
		response.ModelGrant.ExpiresAt == nil ||
		response.ModelGrant.ExpiresAt.CheckValid() != nil ||
		response.RuntimeTaskDigest != binding.TaskSHA256 ||
		response.InputManifestDigest != binding.InputManifestSHA256 ||
		!bytes.Equal(bytes.TrimSpace(response.RuntimeTaskJson), response.RuntimeTaskJson) ||
		!bytes.Equal(bytes.TrimSpace(response.InputManifestJson), response.InputManifestJson) ||
		response.HeartbeatIntervalMillis > math.MaxInt64/uint64(time.Millisecond) {
		return ClaimedTask{}, ErrInvalid
	}
	sessionFence, err := fenceFromProto(response.Session.Fence)
	if err != nil || sessionFence != binding.Fence() ||
		response.Session.State != agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_ACTIVE {
		return ClaimedTask{}, ErrInvalid
	}
	task, err := cloudruntime.ParseTask(response.RuntimeTaskJson)
	if err != nil {
		return ClaimedTask{}, ErrInvalid
	}
	taskDigest, err := task.Digest()
	if err != nil || taskDigest != response.RuntimeTaskDigest ||
		task.ExecutionID != binding.ExecutionID || task.TaskID != binding.TaskID ||
		task.InputManifestSHA256 != response.InputManifestDigest ||
		cloudruntime.ValidateInputManifestJSON(
			response.InputManifestJson, response.InputManifestDigest,
		) != nil {
		return ClaimedTask{}, ErrInvalid
	}
	grant := cloudruntime.ModelGrant{
		GrantID:            response.ModelGrant.GrantId,
		BearerToken:        bytes.Clone(response.ModelGrant.BearerToken),
		ModelBindingSHA256: response.ModelGrant.ModelBindingDigest,
		AudienceSHA256:     response.ModelGrant.AudienceDigest,
		ExpiresAtUnix:      response.ModelGrant.ExpiresAt.AsTime().UTC().Unix(),
		LimitSHA256:        response.ModelGrant.LimitDigest,
		RelayBaseURL:       response.ModelGrant.RelayUrl,
		RelayBindingSHA256: response.ModelGrant.RelayBindingDigest,
		MaxOutputTokens:    response.ModelGrant.MaxTokens,
	}
	now := client.now().UTC()
	if grant.ValidateFor(task, now) != nil {
		grant.Destroy()
		return ClaimedTask{}, ErrInvalid
	}
	claimed := ClaimedTask{
		Binding: binding, SessionID: response.Session.SessionId,
		SessionToken: bytes.Clone(response.SessionToken), Task: task, ModelGrant: grant,
		InputManifestJSON: bytes.Clone(response.InputManifestJson),
		ArtifactScope: cloudresult.Scope{
			Bucket: response.ArtifactBucket, KeyPrefix: response.ArtifactKeyPrefix,
		},
		HeartbeatInterval: time.Duration(response.HeartbeatIntervalMillis) * time.Millisecond,
		NotAfter:          response.NotAfter.AsTime().UTC(),
	}
	if validateClaimedTask(claimed, binding, now) != nil {
		claimed.Destroy()
		return ClaimedTask{}, ErrInvalid
	}
	return claimed, nil
}

func (client *GRPCControlClient) Heartbeat(
	ctx context.Context,
	fence Fence,
	sessionID string,
	sessionToken []byte,
	sequence uint64,
	idempotencyKey string,
) (HeartbeatResult, error) {
	if client == nil || ctx == nil || fence.Validate() != nil ||
		!canonicalUUID(sessionID) || len(sessionToken) < 32 || sequence == 0 ||
		!canonicalUUID(idempotencyKey) {
		return HeartbeatResult{}, ErrInvalid
	}
	rpcRequest := &agentv1.WorkerControlServiceHeartbeatRequest{
		SessionId: sessionID, SessionToken: bytes.Clone(sessionToken), Fence: fenceToProto(fence),
		ProgressSequence: sequence, IdempotencyKey: idempotencyKey,
	}
	defer clear(rpcRequest.SessionToken)
	response, err := client.rpc.Heartbeat(ctx, rpcRequest)
	if err != nil {
		return HeartbeatResult{}, mapControlRPCError(err)
	}
	if response == nil || response.Session == nil ||
		response.Session.SessionId != sessionID || response.Session.ProgressSequence != sequence {
		return HeartbeatResult{}, ErrInvalid
	}
	responseFence, err := fenceFromProto(response.Session.Fence)
	if err != nil || responseFence != fence {
		return HeartbeatResult{}, ErrInvalid
	}
	client.mu.Lock()
	registered := client.sessionID == sessionID && client.fence == fence
	notAfter := client.notAfter
	client.mu.Unlock()
	if !registered || notAfter.IsZero() {
		return HeartbeatResult{}, ErrInvalid
	}
	state := LeaseActive
	switch response.Session.State {
	case agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_ACTIVE:
	case agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_FAILED:
		state = LeaseCanceled
	default:
		return HeartbeatResult{}, ErrInvalid
	}
	return HeartbeatResult{State: state, NotAfter: notAfter, Sequence: sequence}, nil
}

func (client *GRPCControlClient) Complete(
	ctx context.Context,
	request CompleteRequest,
) error {
	if client == nil || ctx == nil || request.Fence.Validate() != nil ||
		!canonicalUUID(request.SessionID) || len(request.SessionToken) < 32 ||
		!canonicalUUID(request.IdempotencyKey) || request.ManifestClaim.Name != "result.json" ||
		request.ManifestClaim.Validate() != nil || request.RuntimeTopology.ValidateTerminal() != nil ||
		request.RuntimeTopology.ExecutionID != request.Fence.ExecutionID ||
		request.RuntimeTopology.TaskID != request.Fence.TaskID ||
		request.RuntimeTopology.Attempt != request.Fence.Attempt ||
		request.RuntimeTopology.LeaseEpoch != request.Fence.LeaseEpoch ||
		request.RuntimeTopology.RuntimeTaskSHA256 != client.bootstrap.TaskSHA256 {
		return ErrInvalid
	}
	topologyDigest, err := request.RuntimeTopology.Digest()
	if err != nil {
		return ErrInvalid
	}
	rpcRequest := &agentv1.WorkerControlServiceCompleteRequest{
		SessionId: request.SessionID, SessionToken: bytes.Clone(request.SessionToken),
		Fence: request.FenceToProto(), Claim: objectClaimToProto(request.ManifestClaim),
		IdempotencyKey: request.IdempotencyKey, RuntimeTopology: runtimeTopologyToProto(request.RuntimeTopology),
	}
	defer clear(rpcRequest.SessionToken)
	response, err := client.rpc.Complete(ctx, rpcRequest)
	if err != nil {
		return mapControlRPCError(err)
	}
	if err = validateTerminalSession(
		response.GetSession(), request.SessionID, request.Fence,
		agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_COMPLETED,
	); err != nil {
		return err
	}
	returned, err := runtimeTopologyFromProto(response.GetSession().GetRuntimeTopology())
	if err != nil || returned != request.RuntimeTopology || response.GetSession().GetRuntimeTopologyDigest() != topologyDigest {
		return ErrInvalid
	}
	return nil
}

func (client *GRPCControlClient) Fail(ctx context.Context, request FailRequest) error {
	if client == nil || ctx == nil || request.Fence.Validate() != nil ||
		!canonicalUUID(request.SessionID) || len(request.SessionToken) < 32 ||
		!canonicalUUID(request.IdempotencyKey) || request.Code == "" {
		return ErrInvalid
	}
	rpcRequest := &agentv1.WorkerControlServiceFailRequest{
		SessionId: request.SessionID, SessionToken: bytes.Clone(request.SessionToken),
		Fence: fenceToProto(request.Fence), Code: request.Code,
		IdempotencyKey: request.IdempotencyKey,
	}
	defer clear(rpcRequest.SessionToken)
	response, err := client.rpc.Fail(ctx, rpcRequest)
	if err != nil {
		return mapControlRPCError(err)
	}
	return validateTerminalSession(
		response.GetSession(), request.SessionID, request.Fence,
		agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_FAILED,
	)
}

func (request CompleteRequest) FenceToProto() *agentv1.CoreCloudWorkerTaskFence {
	return fenceToProto(request.Fence)
}

func fenceToProto(fence Fence) *agentv1.CoreCloudWorkerTaskFence {
	return &agentv1.CoreCloudWorkerTaskFence{
		ExecutionId: fence.ExecutionID, TaskId: fence.TaskID,
		AccountGeneration: fence.AccountGeneration,
		Attempt:           fence.Attempt, LeaseEpoch: fence.LeaseEpoch,
	}
}

func fenceFromProto(value *agentv1.CoreCloudWorkerTaskFence) (Fence, error) {
	if value == nil {
		return Fence{}, ErrInvalid
	}
	fence := Fence{
		ExecutionID: value.ExecutionId, TaskID: value.TaskId,
		AccountGeneration: value.AccountGeneration,
		Attempt:           value.Attempt, LeaseEpoch: value.LeaseEpoch,
	}
	if fence.Validate() != nil {
		return Fence{}, ErrInvalid
	}
	return fence, nil
}

func objectClaimToProto(claim cloudresult.ObjectClaim) *agentv1.CoreCloudWorkerObjectClaim {
	return &agentv1.CoreCloudWorkerObjectClaim{
		Bucket: claim.Bucket, Key: claim.Key, VersionId: claim.VersionID,
		Sha256: claim.SHA256, SizeBytes: claim.SizeBytes, MediaType: claim.MediaType,
	}
}

func runtimeTopologyToProto(proof execgate.Proof) *agentv1.CoreCloudWorkerRuntimeTopologyProof {
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
		Worker: processIdentityToProto(proof.Worker), Pi: processIdentityToProto(proof.Pi),
		WorkerProcessCount: proof.WorkerProcessCount, ActivePiProcesses: proof.ActivePiProcesses,
		TotalAllowedPiExecs: proof.TotalAllowedPiExecs, ObservedAtUnixNano: proof.ObservedAtUnixNano,
		ViolationCode: proof.ViolationCode, CgroupProcessCount: proof.CgroupProcessCount,
		ActiveDescendants: proof.ActiveDescendants,
	}
}

func processIdentityToProto(identity execgate.ProcessIdentity) *agentv1.CoreCloudWorkerProcessIdentity {
	return &agentv1.CoreCloudWorkerProcessIdentity{
		Pid: identity.PID, StartTimeTicks: identity.StartTimeTicks,
		Device: identity.Device, Inode: identity.Inode, Sha256: identity.SHA256,
	}
}

func runtimeTopologyFromProto(value *agentv1.CoreCloudWorkerRuntimeTopologyProof) (execgate.Proof, error) {
	if value == nil || value.Worker == nil || value.Pi == nil {
		return execgate.Proof{}, ErrInvalid
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
		return execgate.Proof{}, ErrInvalid
	}
	proof := execgate.Proof{
		SchemaVersion: value.SchemaVersion, State: state, RunID: value.RunId,
		ExecutionID: value.ExecutionId, TaskID: value.TaskId, Attempt: value.Attempt,
		LeaseEpoch: value.LeaseEpoch, RuntimeTaskSHA256: value.RuntimeTaskSha256,
		BootID: value.BootId, CgroupSHA256: value.CgroupSha256, PolicySHA256: value.PolicySha256,
		Worker: processIdentityFromProto(value.Worker), Pi: processIdentityFromProto(value.Pi),
		WorkerProcessCount: value.WorkerProcessCount, ActivePiProcesses: value.ActivePiProcesses,
		TotalAllowedPiExecs: value.TotalAllowedPiExecs, ObservedAtUnixNano: value.ObservedAtUnixNano,
		ViolationCode: value.ViolationCode, CgroupProcessCount: value.CgroupProcessCount,
		ActiveDescendants: value.ActiveDescendants,
	}
	if proof.Validate() != nil {
		return execgate.Proof{}, ErrInvalid
	}
	return proof, nil
}

func processIdentityFromProto(value *agentv1.CoreCloudWorkerProcessIdentity) execgate.ProcessIdentity {
	return execgate.ProcessIdentity{
		PID: value.Pid, StartTimeTicks: value.StartTimeTicks,
		Device: value.Device, Inode: value.Inode, SHA256: value.Sha256,
	}
}

func validateTerminalSession(
	session *agentv1.CoreCloudWorkerSession,
	sessionID string,
	fence Fence,
	want agentv1.CoreCloudWorkerSessionState,
) error {
	if session == nil || session.SessionId != sessionID || session.State != want {
		return ErrInvalid
	}
	actual, err := fenceFromProto(session.Fence)
	if err != nil || actual != fence {
		return ErrInvalid
	}
	return nil
}

func mapControlRPCError(err error) error {
	if err == nil {
		return nil
	}
	switch status.Code(err) {
	case codes.Canceled:
		return ErrCanceled
	case codes.DeadlineExceeded:
		// Preserve the transport deadline as a detectable cause while keeping
		// the existing public classification unavailable. Workflow can then
		// distinguish an in-flight heartbeat interrupted by its own local stop
		// from the same deadline returned while the heartbeat context is active.
		return errors.Join(ErrUnavailable, context.DeadlineExceeded)
	case codes.InvalidArgument:
		return ErrInvalid
	case codes.NotFound:
		return ErrNotReady
	case codes.Aborted, codes.AlreadyExists, codes.FailedPrecondition:
		return ErrStaleLease
	default:
		if errors.Is(err, context.Canceled) {
			return ErrCanceled
		}
		return ErrUnavailable
	}
}

var _ ControlClient = (*GRPCControlClient)(nil)
