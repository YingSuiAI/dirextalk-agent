package production

import (
	"bytes"
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
)

const defaultWorkerHeartbeatInterval = 10 * time.Second
const maximumRuntimeTopologyFutureSkew = 5 * time.Second

type currentTaskReader interface {
	GetTask(context.Context, string) (coretask.Task, error)
}

type resumeContextReader interface {
	GetResumeContext(context.Context, coretask.Task) (cloudworker.ResumeContext, error)
}

type modelCredentialResolver interface {
	ResolveWorkerCredential(context.Context, cloudworker.ModelAuthorization) ([]byte, error)
}

// WorkerAuthority issues only claim material. Challenge and lease authority
// remain on CloudWorkerControlStore so its store mutations can repeat their
// checks under the same PostgreSQL row lock.
type WorkerAuthority struct {
	tasks             currentTaskReader
	cloud             resumeContextReader
	credentials       modelCredentialResolver
	heartbeatInterval time.Duration
	now               func() time.Time
}

func NewWorkerAuthority(tasks currentTaskReader, cloud resumeContextReader, credentials modelCredentialResolver, heartbeatInterval time.Duration, clocks ...func() time.Time) (*WorkerAuthority, error) {
	if tasks == nil || cloud == nil || credentials == nil {
		return nil, cloudworker.ErrInvalid
	}
	if heartbeatInterval == 0 {
		heartbeatInterval = defaultWorkerHeartbeatInterval
	}
	if heartbeatInterval < time.Second || heartbeatInterval > time.Minute {
		return nil, cloudworker.ErrInvalid
	}
	clock := func() time.Time { return time.Now().UTC() }
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	return &WorkerAuthority{tasks: tasks, cloud: cloud, credentials: credentials, heartbeatInterval: heartbeatInterval, now: clock}, nil
}

func (authority *WorkerAuthority) IssueWorkerClaimMaterial(ctx context.Context, session control.Session, requested cloudprotocol.Versions) (rpcapi.WorkerClaimMaterial, error) {
	if authority == nil || ctx == nil || session.State != control.SessionActive || session.SessionID == "" ||
		session.Fence.ExecutionID == "" || session.Fence.TaskID == "" || session.Fence.AccountGeneration == 0 ||
		session.Fence.Attempt == 0 || session.Fence.LeaseEpoch == 0 || !requested.IsCurrent() {
		return rpcapi.WorkerClaimMaterial{}, control.ErrInvalid
	}
	task, err := authority.tasks.GetTask(ctx, session.Fence.TaskID)
	if err != nil || !currentTaskMatchesSession(task, session, authority.now().UTC()) {
		return rpcapi.WorkerClaimMaterial{}, control.ErrStaleLease
	}
	resume, err := authority.cloud.GetResumeContext(ctx, task)
	if err != nil {
		return rpcapi.WorkerClaimMaterial{}, err
	}
	defer resume.Destroy()
	if !resumeMatchesSession(resume, task, session) {
		return rpcapi.WorkerClaimMaterial{}, control.ErrIdentityRejected
	}
	deadline, err := workerHardDeadline(resume, task, session, authority.now().UTC(), authority.heartbeatInterval)
	if err != nil {
		return rpcapi.WorkerClaimMaterial{}, err
	}
	material, err := resume.Material.CloneForFence(cloudworker.RuntimeTaskFence{
		ExecutionID: session.Fence.ExecutionID, TaskID: session.Fence.TaskID,
		AccountGeneration: session.Fence.AccountGeneration, Attempt: session.Fence.Attempt,
		LeaseEpoch: session.Fence.LeaseEpoch,
	})
	if err != nil {
		return rpcapi.WorkerClaimMaterial{}, err
	}
	defer material.Destroy()
	if material.ProtocolVersions != requested {
		return rpcapi.WorkerClaimMaterial{}, control.ErrIdentityRejected
	}
	credential, err := authority.credentials.ResolveWorkerCredential(
		ctx, resume.Plan.ModelAuthorization,
	)
	if err != nil {
		return rpcapi.WorkerClaimMaterial{}, err
	}
	defer clear(credential)
	grant := cloudruntime.ModelGrant{
		GrantID: session.SessionID, BearerToken: bytes.Clone(credential),
		ModelBindingSHA256: material.Task.ModelBindingSHA256,
		AudienceSHA256:     material.Task.ModelGrantAudienceSHA256,
		ExpiresAtUnix:      deadline.Unix(), LimitSHA256: material.Task.ModelGrantLimitSHA256,
		BaseURL:               material.Task.ModelBaseURL,
		EndpointBindingSHA256: material.Task.ModelEndpointBindingSHA256,
		MaxOutputTokens:       material.Task.MaxOutputTokens,
	}
	scope := cloudresult.Scope{Bucket: resume.Plan.ArtifactGrant.Bucket, KeyPrefix: resume.Plan.ArtifactGrant.KeyPrefix}
	if scope.Validate() != nil || time.Unix(grant.ExpiresAtUnix, 0).UTC() != deadline {
		grant.Destroy()
		return rpcapi.WorkerClaimMaterial{}, cloudworker.ErrStaleAuthorization
	}
	return rpcapi.WorkerClaimMaterial{
		ProtocolVersions: material.ProtocolVersions,
		RuntimeTaskJSON:  bytes.Clone(material.RuntimeTaskJSON), RuntimeTaskDigest: material.RuntimeTaskSHA256,
		InputManifestJSON: bytes.Clone(material.InputManifestJSON), InputManifestDigest: material.InputManifestSHA256,
		ArtifactScope: scope, ModelGrant: grant,
		HeartbeatInterval: authority.heartbeatInterval, NotAfter: deadline,
	}, nil
}

func (authority *WorkerAuthority) ValidateWorkerResultClaim(ctx context.Context, fence control.TaskFence, claim control.ObjectClaim) error {
	if authority == nil || ctx == nil || fence.ExecutionID == "" || fence.TaskID == "" ||
		fence.AccountGeneration == 0 || fence.Attempt == 0 || fence.LeaseEpoch == 0 {
		return control.ErrInvalid
	}
	task, err := authority.tasks.GetTask(ctx, fence.TaskID)
	if err != nil || task.Status != coretask.StatusRunning || task.Lease == nil || task.Spec.Payload.CloudWorker == nil ||
		task.Spec.Payload.CloudWorker.ExecutionID != fence.ExecutionID ||
		task.Spec.Payload.CloudWorker.AccountGeneration != fence.AccountGeneration ||
		task.Attempt != fence.Attempt || task.LeaseEpoch != fence.LeaseEpoch ||
		!task.Lease.ExpiresAt.After(authority.now().UTC()) {
		return control.ErrStaleLease
	}
	resume, err := authority.cloud.GetResumeContext(ctx, task)
	if err != nil {
		return err
	}
	defer resume.Destroy()
	scope := cloudresult.Scope{Bucket: resume.Plan.ArtifactGrant.Bucket, KeyPrefix: resume.Plan.ArtifactGrant.KeyPrefix}
	manifestClaim := cloudresult.ObjectClaim{
		Name: "result.json", Bucket: claim.Bucket, Key: claim.Key, VersionID: claim.VersionID,
		SHA256: claim.SHA256, SizeBytes: claim.SizeBytes, MediaType: claim.MediaType,
	}
	if resume.Plan.ExecutionID != fence.ExecutionID || resume.Plan.TaskID != fence.TaskID ||
		resume.Plan.AccountGeneration != fence.AccountGeneration || scope.Validate() != nil ||
		manifestClaim.Validate() != nil || !scope.Contains(manifestClaim) ||
		uint64(claim.SizeBytes) > resume.Plan.Limits.MaxOutputBytes {
		return control.ErrSessionRejected
	}
	return nil
}

func (authority *WorkerAuthority) ValidateWorkerRuntimeTopology(ctx context.Context, fence control.TaskFence, proof execgate.Proof) error {
	if authority == nil || ctx == nil || proof.ValidateTerminal() != nil ||
		proof.ExecutionID != fence.ExecutionID || proof.TaskID != fence.TaskID ||
		proof.Attempt != fence.Attempt || proof.LeaseEpoch != fence.LeaseEpoch {
		return control.ErrInvalid
	}
	task, err := authority.tasks.GetTask(ctx, fence.TaskID)
	if err != nil || task.Status != coretask.StatusRunning || task.Lease == nil ||
		task.Spec.Payload.CloudWorker == nil ||
		task.Spec.Payload.CloudWorker.ExecutionID != fence.ExecutionID ||
		task.Spec.Payload.CloudWorker.AccountGeneration != fence.AccountGeneration ||
		task.Attempt != fence.Attempt || task.LeaseEpoch != fence.LeaseEpoch ||
		!task.Lease.ExpiresAt.After(authority.now().UTC()) {
		return control.ErrStaleLease
	}
	resume, err := authority.cloud.GetResumeContext(ctx, task)
	if err != nil {
		return err
	}
	defer resume.Destroy()
	material, err := resume.Material.CloneForRecoveryFence(cloudworker.RuntimeTaskFence{
		ExecutionID: fence.ExecutionID, TaskID: fence.TaskID,
		AccountGeneration: fence.AccountGeneration, Attempt: fence.Attempt, LeaseEpoch: fence.LeaseEpoch,
	})
	if err != nil {
		return control.ErrIdentityRejected
	}
	defer material.Destroy()
	observedAt, err := execgate.UnixNanoUTC(proof.ObservedAtUnixNano)
	now := authority.now().UTC()
	// The terminal proof is produced before result upload. A large, bounded
	// artifact can legitimately take more than a minute to reach Complete, so
	// its age is not an authorization boundary. The current task lease and
	// fence above remain the live authorization check; only a proof dated in
	// the future indicates an invalid Worker clock or forged observation.
	if err != nil || !runtimeTopologyObservationAllowed(observedAt, now) ||
		proof.RuntimeTaskSHA256 != material.RuntimeTaskSHA256 ||
		proof.Pi.SHA256 != material.Task.PiExecutableSHA256 ||
		proof.Worker.SHA256 != resume.Plan.Compute.WorkerReleaseDigest {
		return control.ErrIdentityRejected
	}
	return nil
}

func runtimeTopologyObservationAllowed(observedAt, now time.Time) bool {
	return !observedAt.After(now.Add(maximumRuntimeTopologyFutureSkew))
}

func currentTaskMatchesSession(task coretask.Task, session control.Session, now time.Time) bool {
	payload := task.Spec.Payload.CloudWorker
	return task.Status == coretask.StatusRunning && task.Lease != nil && payload != nil &&
		task.ID == session.Fence.TaskID && payload.ExecutionID == session.Fence.ExecutionID &&
		payload.AccountGeneration == session.Fence.AccountGeneration && task.Attempt == session.Fence.Attempt &&
		task.LeaseEpoch == session.Fence.LeaseEpoch && task.Lease.Epoch == session.Fence.LeaseEpoch &&
		task.Lease.ExpiresAt.After(now)
}

func resumeMatchesSession(resume cloudworker.ResumeContext, task coretask.Task, session control.Session) bool {
	if resume.Plan.Seal() != nil || resume.Execution.Seal() != nil || resume.AWSRecord.Validate() != nil ||
		resume.Plan.ExecutionID != session.Fence.ExecutionID || resume.Plan.TaskID != session.Fence.TaskID ||
		resume.Plan.AccountGeneration != session.Fence.AccountGeneration ||
		resume.Execution.ExecutionID != resume.Plan.ExecutionID || !resume.Execution.ProviderMutationStarted ||
		resume.Execution.TerminalIntent != "" ||
		(resume.Execution.State != cloudworker.StateAwaitingWorker && resume.Execution.State != cloudworker.StateRunning) ||
		resume.CurrentFence.ExecutionID != session.Fence.ExecutionID || resume.CurrentFence.TaskID != session.Fence.TaskID ||
		resume.CurrentFence.AccountGeneration != session.Fence.AccountGeneration ||
		resume.CurrentFence.Attempt != session.Fence.Attempt || resume.CurrentFence.LeaseEpoch != session.Fence.LeaseEpoch ||
		resume.AWSRecord.State != cloudaws.LifecycleActive ||
		resume.AWSRecord.Identity.ExecutionID != session.Fence.ExecutionID ||
		resume.AWSRecord.Identity.TaskID != session.Fence.TaskID ||
		resume.AWSRecord.Identity.AccountGeneration != session.Fence.AccountGeneration ||
		resume.AWSRecord.Identity.LaunchIdentity != session.Expectation.LaunchIdentity ||
		resume.AWSRecord.Resources[cloudaws.ResourceEC2].ProviderID != session.Expectation.InstanceID ||
		session.Expectation.OwnerID != resume.Plan.OwnerID || session.Expectation.AccountID != resume.Plan.AWS.AccountID ||
		session.Expectation.Region != resume.Plan.AWS.Region || session.Identity.InstanceID != session.Expectation.InstanceID ||
		session.Identity.LaunchIdentity != session.Expectation.LaunchIdentity ||
		session.Identity.AccountID != session.Expectation.AccountID || session.Identity.Region != session.Expectation.Region ||
		task.ExecutionDeadlineAt == nil {
		return false
	}
	return true
}

func workerHardDeadline(resume cloudworker.ResumeContext, task coretask.Task, session control.Session, now time.Time, heartbeat time.Duration) (time.Time, error) {
	if task.ExecutionDeadlineAt == nil || resume.InitialAuthorization.AuthorizedAt.IsZero() ||
		resume.AWSRecord.Plan.DestroyDeadline.IsZero() || session.ClaimedAt.IsZero() {
		return time.Time{}, cloudworker.ErrStaleAuthorization
	}
	authorizedAt := resume.InitialAuthorization.AuthorizedAt.UTC()
	claimedAt := session.ClaimedAt.UTC()
	if claimedAt.Before(authorizedAt) {
		return time.Time{}, cloudworker.ErrStaleAuthorization
	}
	destroyDeadline := resume.AWSRecord.Plan.DestroyDeadline.UTC().Add(-time.Duration(cloudworker.EphemeralCleanupReserveSeconds) * time.Second)
	taskDeadline := task.ExecutionDeadlineAt.UTC()
	if resume.Plan.Limits.InfrastructureLifetimeSeconds != 0 {
		deadline := destroyDeadline
		if taskDeadline.Before(deadline) {
			deadline = taskDeadline
		}
		deadline = deadline.Truncate(time.Second)
		if deadline.After(destroyDeadline) || deadline.After(taskDeadline) ||
			!deadline.After(now.UTC().Add(2*heartbeat)) ||
			!deadline.After(now.UTC().Add(cloudruntime.MinimumModelGrantLifetime)) {
			return time.Time{}, cloudworker.ErrStaleAuthorization
		}
		return deadline, nil
	}
	if resume.Plan.Limits.MaxRuntimeSeconds == 0 {
		return time.Time{}, cloudworker.ErrStaleAuthorization
	}
	cloudWindowSeconds, err := resume.Plan.Limits.CloudWindowSeconds()
	if err != nil {
		return time.Time{}, cloudworker.ErrStaleAuthorization
	}
	runtimeDeadline := claimedAt.Add(time.Duration(resume.Plan.Limits.MaxRuntimeSeconds) * time.Second)
	cloudDeadline := authorizedAt.Add(time.Duration(cloudWindowSeconds) * time.Second)
	deadline := runtimeDeadline
	for _, candidate := range []time.Time{cloudDeadline, destroyDeadline, taskDeadline} {
		if candidate.Before(deadline) {
			deadline = candidate
		}
	}
	deadline = deadline.Truncate(time.Second)
	if deadline.After(runtimeDeadline) || deadline.After(cloudDeadline) || deadline.After(destroyDeadline) || deadline.After(taskDeadline) ||
		!deadline.After(now.UTC().Add(2*heartbeat)) ||
		!deadline.After(now.UTC().Add(cloudruntime.MinimumModelGrantLifetime)) {
		return time.Time{}, cloudworker.ErrStaleAuthorization
	}
	return deadline, nil
}

var _ rpcapi.WorkerClaimMaterialIssuer = (*WorkerAuthority)(nil)
