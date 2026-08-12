package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/identitywire"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/modelrelay"
	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	cloudresult "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/result"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type freshStateOwnerResolver struct {
	ownerID           string
	accountGeneration uint64
}

func (resolver freshStateOwnerResolver) ResolveCloudWorkerOwner(context.Context, core.TurnLease) (cloudworker.IntrinsicOwnerContext, error) {
	return cloudworker.IntrinsicOwnerContext{
		OwnerID:           resolver.ownerID,
		AccountGeneration: resolver.accountGeneration,
	}, nil
}

// freshStateInputStager deliberately represents workspace_mode=none. It
// exercises the same typed staging/cleanup ports as production without
// creating an S3 object or making any external call.
type freshStateInputStager struct {
	stageCalls   int
	cleanupCalls int
}

type freshStateOutputVersions struct {
	identity       cloudworker.OutputExecutionIdentity
	objects        *freshStateObjectReader
	inventoryCalls int
	deleteCalls    int
}

func (objects *freshStateOutputVersions) StoreForOutput(_ context.Context, identity cloudworker.OutputExecutionIdentity) (cloudworker.OutputVersionStore, error) {
	if objects.identity.ExecutionID == "" {
		objects.identity = identity
	}
	if objects.identity != identity {
		return nil, cloudworker.ErrStaleAuthorization
	}
	return objects, nil
}

func (objects *freshStateOutputVersions) InventoryPage(_ context.Context, request cloudworker.OutputInventoryRequest) (cloudworker.OutputInventoryPage, error) {
	if objects.identity != request.Identity || objects.objects == nil || request.Cursor.KeyMarker != "" || request.Cursor.VersionIDMarker != "" {
		return cloudworker.OutputInventoryPage{}, cloudworker.ErrInvalid
	}
	objects.inventoryCalls++
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	page := cloudworker.OutputInventoryPage{Identity: request.Identity, ObservedAt: observedAt}
	for _, stored := range objects.objects.objects {
		page.Versions = append(page.Versions, cloudworker.OutputVersionObservation{
			Identity: cloudworker.OutputVersionIdentity{OutputExecutionIdentity: request.Identity,
				Key: stored.claim.Key, VersionID: stored.claim.VersionID},
			SizeBytes: stored.claim.SizeBytes, ObservedAt: observedAt,
		})
	}
	return page, nil
}

func (objects *freshStateOutputVersions) ObserveExact(_ context.Context, identity cloudworker.OutputVersionIdentity) (cloudworker.OutputExactObservation, error) {
	if objects.identity != identity.OutputExecutionIdentity || objects.objects == nil {
		return cloudworker.OutputExactObservation{}, cloudworker.ErrInvalid
	}
	stored, ok := objects.objects.objects[freshStateObjectKey(identity.Bucket, identity.Key, identity.VersionID)]
	observedAt := time.Now().UTC().Truncate(time.Microsecond)
	if !ok {
		return cloudworker.OutputExactObservation{Identity: identity, ObservedAt: observedAt}, nil
	}
	return cloudworker.OutputExactObservation{
		Identity: identity, Exists: true, SizeBytes: stored.claim.SizeBytes,
		MediaType: stored.claim.MediaType, SHA256: stored.claim.SHA256,
		KMSKeyARN: identity.KMSKeyARN, ObservedAt: observedAt,
	}, nil
}

func (objects *freshStateOutputVersions) DeleteExact(_ context.Context, identity cloudworker.OutputVersionIdentity) error {
	if objects.identity != identity.OutputExecutionIdentity || objects.objects == nil {
		return cloudworker.ErrInvalid
	}
	key := freshStateObjectKey(identity.Bucket, identity.Key, identity.VersionID)
	if _, ok := objects.objects.objects[key]; !ok {
		return cloudworker.ErrOutputDeleteUncertain
	}
	delete(objects.objects.objects, key)
	objects.deleteCalls++
	return nil
}

func (stager *freshStateInputStager) Stage(_ context.Context, plan cloudworker.Plan, _ cloudworker.Execution, _ cloudworker.LaunchPrerequisite) (cloudworker.StagedInputManifest, error) {
	stager.stageCalls++
	manifest := cloudworker.StagedInputManifest{ExecutionID: plan.ExecutionID}
	if _, err := manifest.Seal(plan.InputManifest); err != nil {
		return cloudworker.StagedInputManifest{}, err
	}
	return manifest, nil
}

func (stager *freshStateInputStager) Cleanup(context.Context, cloudworker.Plan) error {
	stager.cleanupCalls++
	return nil
}

// freshStateAWS is a typed, PostgreSQL-ledger-backed provider qualification
// fake. It persists the deterministic dispatch intent and an eight-resource
// graph, but never constructs an AWS SDK client and therefore cannot mutate
// an AWS account.
type freshStateAWS struct {
	t            *testing.T
	ledger       *cloudaws.PostgresLedger
	record       cloudaws.LedgerRecord
	prepareCalls int
	ensureCalls  int
	observeCalls int
	destroyCalls int
}

func (provider *freshStateAWS) Prepare(ctx context.Context, plan cloudaws.Plan, intent cloudaws.DispatchIntent) (cloudaws.ExecutionIdentity, error) {
	provider.prepareCalls++
	record, err := cloudaws.NewLedgerRecord(plan, intent, intent.RecordedAt)
	if err != nil {
		return cloudaws.ExecutionIdentity{}, err
	}
	record, err = provider.ledger.CreateIntent(ctx, record)
	if err != nil {
		return cloudaws.ExecutionIdentity{}, err
	}
	provider.record = record
	return record.Identity, nil
}

func (provider *freshStateAWS) Ensure(ctx context.Context, plan cloudaws.Plan, intent cloudaws.DispatchIntent) (cloudaws.ObservedGraph, error) {
	provider.ensureCalls++
	if !provider.record.Identity.Equal(plan.Identity) || provider.record.Intent.IntentDigest != intent.IntentDigest {
		return cloudaws.ObservedGraph{}, cloudaws.ErrIdentityMismatch
	}
	if provider.record.State != cloudaws.LifecycleActive {
		provider.record = activatePGCloudLedger(provider.t, ctx, provider.ledger, provider.record, intent.RecordedAt.Add(time.Microsecond))
	}
	return freshStateAWSGraph(provider.record)
}

func (provider *freshStateAWS) Observe(ctx context.Context, identity cloudaws.ExecutionIdentity) (cloudaws.ObservedGraph, error) {
	provider.observeCalls++
	record, err := provider.ledger.Get(ctx, identity)
	if err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	provider.record = record
	return freshStateAWSGraph(record)
}

func (provider *freshStateAWS) Destroy(ctx context.Context, identity cloudaws.ExecutionIdentity, graph cloudaws.ObservedGraph) (cloudaws.ObservedGraph, error) {
	provider.destroyCalls++
	if !provider.record.Identity.Equal(identity) || graph.Validate(provider.record.Plan, provider.record.Intent) != nil {
		return cloudaws.ObservedGraph{}, cloudaws.ErrIdentityMismatch
	}
	if provider.record.State != cloudaws.LifecycleVerifiedDestroyed {
		provider.record = destroyPGCloudLedger(provider.t, ctx, provider.ledger, provider.record, graph.ObservedAt.Add(time.Microsecond))
	}
	return freshStateAWSGraph(provider.record)
}

func freshStateAWSGraph(record cloudaws.LedgerRecord) (cloudaws.ObservedGraph, error) {
	if record.Validate() != nil {
		return cloudaws.ObservedGraph{}, cloudaws.ErrInvalid
	}
	graphState := cloudaws.GraphProvisioning
	switch record.State {
	case cloudaws.LifecycleActive:
		graphState = cloudaws.GraphActive
	case cloudaws.LifecycleDestroying:
		graphState = cloudaws.GraphDestroying
	case cloudaws.LifecycleVerifiedDestroyed:
		graphState = cloudaws.GraphVerifiedDestroyed
	}
	policy, err := record.Plan.Network.SecurityGroupPolicy()
	if err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	tags := cloudaws.RequiredTags(record.Identity, record.Plan.Digest, record.Plan.InfrastructureDigest, record.Intent.IntentDigest)
	resources := make([]cloudaws.ResourceObservation, 0, len(cloudaws.AllResourceKinds()))
	for _, kind := range cloudaws.AllResourceKinds() {
		entry := record.Resources[kind]
		observation := cloudaws.ResourceObservation{
			Kind: kind, LogicalID: cloudaws.LogicalID(kind), ProviderID: entry.ProviderID,
			Exists: graphState == cloudaws.GraphActive, Tags: cloneFreshStateTags(tags),
			LaunchIdentity: record.Identity.LaunchIdentity, Generation: record.Identity.Generation,
			ObservedAt: record.UpdatedAt,
		}
		resources = append(resources, observation)
	}
	graph := cloudaws.ObservedGraph{
		Identity: record.Identity, PlanDigest: record.Plan.Digest,
		InfrastructureDigest: record.Plan.InfrastructureDigest, IntentDigest: record.Intent.IntentDigest,
		StackProviderID: record.StackProviderID, State: graphState, Resources: resources,
		Topology: cloudaws.TopologyProof{
			EC2InstanceCount: 1,
			Ingress:          []cloudaws.NetworkRule{}, Egress: append([]cloudaws.NetworkRule(nil), policy.Egress...),
			SSMEnabled: false, FQDNEnforcement: policy.FQDNEnforcement, FQDNPolicyDigest: policy.FQDNPolicyDigest,
		},
		ObservedAt: record.UpdatedAt,
	}
	if err := graph.Validate(record.Plan, record.Intent); err != nil {
		return cloudaws.ObservedGraph{}, err
	}
	return graph, nil
}

func cloneFreshStateTags(values map[string]string) map[string]string {
	result := make(map[string]string, len(values))
	for key, value := range values {
		result[key] = value
	}
	return result
}

type freshStateStoredObject struct {
	claim cloudresult.ObjectClaim
	raw   []byte
}

type freshStateObjectReader struct {
	objects map[string]freshStateStoredObject
	reads   int
}

func newFreshStateObjectReader() *freshStateObjectReader {
	return &freshStateObjectReader{objects: make(map[string]freshStateStoredObject)}
}

func (reader *freshStateObjectReader) add(claim cloudresult.ObjectClaim, raw []byte) {
	reader.objects[freshStateObjectKey(claim.Bucket, claim.Key, claim.VersionID)] = freshStateStoredObject{
		claim: claim,
		raw:   bytes.Clone(raw),
	}
}

func (reader *freshStateObjectReader) ReadObject(_ context.Context, request cloudresult.ObjectRequest) (cloudresult.ObjectRead, error) {
	reader.reads++
	stored, ok := reader.objects[freshStateObjectKey(request.Bucket, request.Key, request.VersionID)]
	if !ok || request.MaximumBytes != stored.claim.SizeBytes {
		return cloudresult.ObjectRead{}, cloudresult.ErrUnavailable
	}
	return cloudresult.ObjectRead{
		Bucket: stored.claim.Bucket, Key: stored.claim.Key, VersionID: stored.claim.VersionID,
		SizeBytes: stored.claim.SizeBytes, MediaType: stored.claim.MediaType,
		Body: io.NopCloser(bytes.NewReader(bytes.Clone(stored.raw))),
	}, nil
}

func freshStateObjectKey(bucket, key, versionID string) string {
	return bucket + "\x00" + key + "\x00" + versionID
}

func freshStateResultClaim(name string, plan cloudworker.Plan, suffix, versionID, mediaType string, raw []byte) cloudresult.ObjectClaim {
	digest := sha256.Sum256(raw)
	return cloudresult.ObjectClaim{
		Name: name, Bucket: plan.ArtifactGrant.Bucket, Key: plan.ArtifactGrant.KeyPrefix + suffix,
		VersionID: versionID, SHA256: hex.EncodeToString(digest[:]), SizeBytes: int64(len(raw)), MediaType: mediaType,
	}
}

type freshStateIdentityVerifier struct{ claims control.IdentityClaims }

func (verifier freshStateIdentityVerifier) Verify(context.Context, string, control.IdentityProof) (control.IdentityClaims, error) {
	claims := verifier.claims
	claims.Tags = cloneFreshStateTags(verifier.claims.Tags)
	return claims, nil
}

// freshStateWorkerSessions delegates all authority and persistence to the real
// WorkerControl PostgreSQL store. SetLaunchExpectation synchronously runs a
// fake booting Worker through challenge, claim, heartbeat, canonical Pi event
// parsing, exact-version result upload, and Complete.
type freshStateWorkerSessions struct {
	cloud         *CloudWorkerStore
	controlStore  *CloudWorkerControlStore
	objects       *freshStateObjectReader
	setCalls      int
	claimCalls    int
	completeCalls int
	setErr        error
	setPhase      string
}

func (sessions *freshStateWorkerSessions) SetLaunchExpectation(ctx context.Context, task coretask.Task, expectation control.IdentityExpectation) (resultErr error) {
	defer func() { sessions.setErr = resultErr }()
	sessions.setCalls++
	sessions.setPhase = "persist expectation"
	if err := sessions.controlStore.SetLaunchExpectation(ctx, task, expectation); err != nil {
		return err
	}
	sessions.setPhase = "resolve launch"
	request, err := sessions.controlStore.ResolveWorkerLaunch(ctx, control.LaunchLookup{
		ExecutionID: expectation.RequiredTags[cloudaws.TagExecutionID],
		TaskID:      expectation.RequiredTags[cloudaws.TagTaskID], AccountGeneration: expectation.AccountGeneration,
		InstanceID: expectation.InstanceID, LaunchIdentity: expectation.LaunchIdentity,
	})
	if err != nil {
		return err
	}
	sessions.setPhase = "construct control service"
	claims := control.IdentityClaims{
		AccountGeneration: expectation.AccountGeneration, AccountID: expectation.AccountID,
		Region: expectation.Region, InstanceID: expectation.InstanceID, LaunchIdentity: expectation.LaunchIdentity,
		RoleARN: expectation.RoleARN, RoleID: expectation.RoleID, InstanceProfileID: expectation.InstanceProfileID,
		Tags: cloneFreshStateTags(expectation.RequiredTags),
	}
	service, err := control.NewService(sessions.controlStore, freshStateIdentityVerifier{claims: claims}, sessions.controlStore)
	if err != nil {
		return err
	}
	sessions.setPhase = "issue challenge"
	challenge, err := service.IssueIdentityChallenge(ctx, request)
	if err != nil {
		return err
	}
	sessions.setPhase = "claim"
	claimed, err := service.Claim(ctx, control.ClaimRequest{
		ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce, Fence: request.Fence,
		Proof:    control.IdentityProof{Method: identitywire.MethodSTSSigV4IMDSPKCS7V1, Payload: []byte("fresh-state-signed-iid")},
		Versions: cloudprotocol.Current(),
	})
	if err != nil {
		return err
	}
	sessions.claimCalls++
	defer claimed.Destroy()
	sessions.setPhase = "heartbeat"
	if _, err = service.Heartbeat(ctx, control.HeartbeatRequest{
		SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: request.Fence,
		ProgressSequence: 1, Progress: control.ProgressSnapshot{
			Phase: control.ProgressClaimed, LastActivityAt: claimed.Session.ClaimedAt,
		}, IdempotencyKey: uuid.NewString(),
	}); err != nil {
		return err
	}
	sessions.setPhase = "resume"
	resume, err := sessions.cloud.GetResumeContext(ctx, task)
	if err != nil {
		return err
	}
	defer resume.Destroy()
	sessions.setPhase = "pi result"
	manifestClaim, err := sessions.buildPiResult(resume, claimed.Session)
	if err != nil {
		return err
	}
	sessions.setPhase = "complete"
	completeRequest := control.CompleteRequest{
		SessionID: claimed.Session.SessionID, SessionToken: claimed.SessionToken, Fence: request.Fence,
		Claim: control.ObjectClaim{
			Bucket: manifestClaim.Bucket, Key: manifestClaim.Key, VersionID: manifestClaim.VersionID,
			SHA256: manifestClaim.SHA256, SizeBytes: manifestClaim.SizeBytes, MediaType: manifestClaim.MediaType,
		},
		RuntimeTopology:  freshStateRuntimeTopology(resume, request.Fence),
		ProgressSequence: 2,
		Progress: control.ProgressSnapshot{
			Phase: control.ProgressCompleting, UploadedBytes: uint64(manifestClaim.SizeBytes),
			LastActivityAt: claimed.Session.ClaimedAt,
		},
		IdempotencyKey: uuid.NewString(),
	}
	// Force the progress-event append to fail after the session UPDATE. The
	// serializable terminal transaction must roll back progress, terminal state,
	// and replay together; removing the injected collision then allows the exact
	// same terminal request to succeed.
	collisionID := uuid.NewString()
	if _, err = sessions.controlStore.store.pool.Exec(ctx, `INSERT INTO core_cloud_worker_events(
		execution_id,sequence,event_id,owner_id,kind,state,revision,payload_digest,payload_json,created_at,session_id,worker_progress_sequence)
		SELECT execution_id,(SELECT COALESCE(MAX(sequence),0)+1 FROM core_cloud_worker_events WHERE execution_id=$1),
			$2,owner_id,'worker_progress',state,revision,repeat('a',64),'{}'::jsonb,$3,$4,2
		FROM core_cloud_worker_executions WHERE execution_id=$1`, request.Fence.ExecutionID, collisionID, time.Now().UTC(), claimed.Session.SessionID); err != nil {
		return err
	}
	if _, injectedErr := service.Complete(ctx, completeRequest); injectedErr == nil {
		return errors.New("injected terminal progress collision did not fail")
	}
	rolledBack, rollbackErr := sessions.controlStore.GetSession(ctx, claimed.Session.SessionID)
	if rollbackErr != nil || rolledBack.State != control.SessionActive || rolledBack.ProgressSequence != 1 ||
		rolledBack.LatestProgress == nil || rolledBack.LatestProgress.Phase != control.ProgressClaimed {
		return errors.Join(errors.New("terminal progress transaction did not roll back"), rollbackErr)
	}
	var replayCount int
	if err = sessions.controlStore.store.pool.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_session_replays
		WHERE operation='complete' AND session_id=$1 AND idempotency_key=$2`, claimed.Session.SessionID, completeRequest.IdempotencyKey).Scan(&replayCount); err != nil || replayCount != 0 {
		return errors.Join(errors.New("failed terminal progress persisted replay"), err)
	}
	if _, err = sessions.controlStore.store.pool.Exec(ctx, `DELETE FROM core_cloud_worker_events WHERE event_id=$1`, collisionID); err != nil {
		return err
	}
	completed, err := service.Complete(ctx, completeRequest)
	if err != nil || completed.State != control.SessionCompleted {
		return errors.Join(control.ErrConflict, err)
	}
	sessions.completeCalls++
	sessions.setPhase = "done"
	return nil
}

func freshStateRuntimeTopology(
	resume cloudworker.ResumeContext,
	fence control.TaskFence,
) execgate.Proof {
	return execgate.Proof{
		SchemaVersion: execgate.ProofSchemaV1, State: execgate.ProofTerminal,
		RunID: uuid.NewString(), ExecutionID: fence.ExecutionID, TaskID: fence.TaskID,
		Attempt: fence.Attempt, LeaseEpoch: fence.LeaseEpoch,
		RuntimeTaskSHA256: resume.Material.RuntimeTaskSHA256,
		BootID:            uuid.NewString(), CgroupSHA256: pgCloudDigest("fresh-state-cgroup"),
		PolicySHA256: pgCloudDigest("fresh-state-exec-policy"),
		Worker: execgate.ProcessIdentity{
			PID: 10, StartTimeTicks: 100, Device: 1, Inode: 10,
			SHA256: resume.Plan.Compute.WorkerReleaseDigest,
		},
		Pi: execgate.ProcessIdentity{
			PID: 11, StartTimeTicks: 101, Device: 1, Inode: 11,
			SHA256: resume.Material.Task.PiExecutableSHA256,
		},
		WorkerProcessCount: 1, CgroupProcessCount: 1, ActiveDescendants: 0,
		ActivePiProcesses: 0, TotalAllowedPiExecs: 1,
		ObservedAtUnixNano: time.Now().UTC().UnixNano(),
	}
}

func (sessions *freshStateWorkerSessions) buildPiResult(resume cloudworker.ResumeContext, session control.Session) (cloudresult.ObjectClaim, error) {
	piEvents := []byte(
		`{"type":"session","version":3,"id":"fresh-state"}` + "\n" +
			`{"type":"agent_start"}` + "\n" +
			`{"type":"message_end","message":{"role":"assistant","stopReason":"toolUse","usage":{"input":120,"output":24,"cacheRead":20,"reasoning":6}}}` + "\n" +
			`{"type":"tool_execution_end","toolName":"dirextalk_submit_result","result":{"details":{"status":"completed","summary":"Fresh-state task completed.","deliverables":["Verified report produced."],"tests":["Pi loopback passed."],"risks":[]},"terminate":true},"isError":false}` + "\n" +
			`{"type":"agent_end","willRetry":false}` + "\n" +
			`{"type":"agent_settled"}` + "\n",
	)
	usage, finalRaw, err := cloudruntime.ParsePiEvents(piEvents)
	if err != nil {
		return cloudresult.ObjectClaim{}, err
	}
	defer clear(finalRaw)
	finalClaim := freshStateResultClaim("final.json", resume.Plan, "results/final.json", "fresh-final-v1", "application/json", finalRaw)
	manifest := cloudresult.Manifest{
		SchemaVersion: cloudresult.ManifestSchemaV1,
		ExecutionID:   resume.Plan.ExecutionID, ExecutionSHA256: resume.Plan.ExecutionDigest,
		TaskID: resume.Plan.TaskID, TaskSHA256: resume.Material.RuntimeTaskSHA256,
		SessionID: session.SessionID, Attempt: int32(session.Fence.Attempt), LeaseEpoch: int64(session.Fence.LeaseEpoch),
		Adapter: cloudruntime.AdapterPiJSONTaskV1, WorkspaceMode: cloudruntime.WorkspaceMode(resume.Plan.WorkspaceMode),
		Status: "succeeded", Usage: usage, Artifacts: []cloudresult.ObjectClaim{finalClaim},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		return cloudresult.ObjectClaim{}, err
	}
	defer clear(manifestRaw)
	manifestClaim := freshStateResultClaim("result.json", resume.Plan, "results/result.json", "fresh-manifest-v1", "application/json", manifestRaw)
	sessions.objects.add(finalClaim, finalRaw)
	sessions.objects.add(manifestClaim, manifestRaw)
	return manifestClaim, nil
}

func (sessions *freshStateWorkerSessions) FindLatestSessionByExecution(ctx context.Context, executionID, taskID string, generation uint64) (control.Session, error) {
	return sessions.controlStore.FindLatestSessionByExecution(ctx, executionID, taskID, generation)
}

func (sessions *freshStateWorkerSessions) FenceExecutionSessions(ctx context.Context, task coretask.Task, executionID, reason string) (control.Session, error) {
	return sessions.controlStore.FenceExecutionSessions(ctx, task, executionID, reason)
}

type freshStateModelGrants struct{ fenceCalls int }

func (grants *freshStateModelGrants) FenceExecution(context.Context, modelrelay.Fence, string, bool) error {
	grants.fenceCalls++
	return nil
}

type freshStateStoreTrace struct {
	cloudworker.Store
	authorizeErr error
}

func (store *freshStateStoreTrace) AuthorizeLaunch(ctx context.Context, command cloudworker.AuthorizeLaunchCommand) (cloudworker.LaunchAuthorization, error) {
	authorization, err := store.Store.AuthorizeLaunch(ctx, command)
	store.authorizeErr = err
	return authorization, err
}

func TestCloudWorkerFreshStateIntrinsicToVerifiedCompletionWithoutAWSMutation(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()

	intrinsic, err := cloudworker.NewProposeIntrinsic(h.service, freshStateOwnerResolver{
		ownerID: h.owner, accountGeneration: h.generation,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := intrinsic.ResolveIntrinsicTools(h.ctx, h.lease)
	if err != nil || len(resolved) != 1 || resolved[0].Tool.Name != coremodel.IntrinsicCloudWorkerProposeToolName {
		t.Fatalf("resolve cloud_worker_propose: tools=%+v err=%v", resolved, err)
	}
	arguments, _ := json.Marshal(map[string]any{
		"objective":      "Produce a centrally verified fresh-state result",
		"workspace_mode": string(cloudworker.WorkspaceNone),
	})
	callID := uuid.NewString()
	h.recordProposalModelResult(t, callID, arguments)
	result, err := resolved[0].Execute(h.ctx, core.IntrinsicExecutionRequest{
		Lease:              h.lease,
		Call:               core.ToolCall{ID: callID, Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: string(arguments)},
		CanonicalArguments: arguments,
	})
	if err != nil || !result.TurnCommitted {
		t.Fatalf("cloud_worker_propose result=%+v err=%v", result, err)
	}

	plans, _, err := h.cloud.ListPlansForAuthority(h.ctx, h.owner, h.generation, "", 10)
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans=%+v err=%v", plans, err)
	}
	plan := plans[0]
	execution, err := h.cloud.GetExecutionForAuthority(h.ctx, h.owner, h.generation, plan.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	task, err := h.tasks.GetTask(h.ctx, plan.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	confirmation, err := h.confirmations.Get(h.ctx, plan.ConfirmationID)
	if err != nil {
		t.Fatal(err)
	}
	var offerRows, offerMessages int
	if err = h.store.pool.QueryRow(h.ctx, `SELECT
		(SELECT count(*) FROM core_cloud_worker_offer_outbox WHERE execution_id=$1),
		(SELECT count(*) FROM core_messages WHERE conversation_id=$2)`, plan.ExecutionID, plan.ConversationID).Scan(&offerRows, &offerMessages); err != nil {
		t.Fatal(err)
	}
	if plan.Status != string(cloudworker.StateWaitingUser) || execution.State != cloudworker.StateWaitingUser ||
		task.Status != coretask.StatusWaitingUser || confirmation.State != coreconfirmation.StatePending || offerRows != 1 || offerMessages != 2 {
		t.Fatalf("offer graph plan=%s execution=%s task=%s confirmation=%s outbox=%d messages=%d",
			plan.Status, execution.State, task.Status, confirmation.State, offerRows, offerMessages)
	}

	confirmed, err := h.confirmation.Confirm(h.ctx, coreconfirmation.ConfirmCommand{
		ConfirmationID: confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(),
		ExpectedRevision: confirmation.Revision, At: time.Now().UTC().Truncate(time.Microsecond),
	})
	if err != nil || confirmed.State != coreconfirmation.StateConfirmed {
		t.Fatalf("confirm=%+v err=%v", confirmed, err)
	}
	runningTask, _, err := h.tasks.ClaimNextDue(h.ctx, "fresh-state-controller", h.now.Add(2*time.Second), 30*time.Minute, 4)
	if err != nil || runningTask.ID != plan.TaskID {
		t.Fatalf("claim task=%+v err=%v", runningTask, err)
	}

	ledger, err := cloudaws.NewPostgresLedger(h.store.pool)
	if err != nil {
		t.Fatal(err)
	}
	outputLedger, err := cloudworker.NewPostgresOutputJournalLedger(h.store.pool)
	if err != nil {
		t.Fatal(err)
	}
	outputObjects := &freshStateOutputVersions{}
	outputs, err := cloudworker.NewOutputJournalManager(outputLedger, outputObjects, func() time.Time {
		return time.Now().UTC().Truncate(time.Microsecond)
	})
	if err != nil {
		t.Fatal(err)
	}
	provider := &freshStateAWS{t: t, ledger: ledger}
	stager := &freshStateInputStager{}
	objects := newFreshStateObjectReader()
	outputObjects.objects = objects
	workerSessions := &freshStateWorkerSessions{
		cloud: h.cloud, controlStore: NewCloudWorkerControlStore(h.store), objects: objects,
	}
	grants := &freshStateModelGrants{}
	qualification := cloudworker.RuntimeQualification{
		WorkerProtocolVersion: cloudprotocol.WorkerProtocolVersion, RuntimeContractVersion: cloudprotocol.RuntimeContractVersion,
		PiRuntimeDigest: plan.Compute.PiRuntimeDigest, PiVersion: "0.83.0",
		PiExecutableSHA256:    pgCloudDigest("fresh-state-pi"),
		ResultExtensionSHA256: pgCloudDigest("fresh-state-result-extension"),
	}
	awsBindingReads := 0
	validator, err := cloudworker.NewResultValidator(objects, func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) })
	if err != nil {
		t.Fatal(err)
	}
	storeTrace := &freshStateStoreTrace{Store: h.cloud}
	controller, err := cloudworker.NewController(cloudworker.ControllerConfig{
		Store: storeTrace, BaseLimits: plan.Limits,
		Quoter: cloudworker.FakeQuoter{
			AmountMicros: plan.Quote.AmountMicros, MaximumAuthorizedMicros: plan.Quote.MaximumAuthorizedCostMicros,
			TTL: time.Hour, Now: func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) },
		},
		AWSBindings: cloudworker.AWSBindingResolverFunc(func(context.Context) (cloudworker.AWSBinding, error) {
			awsBindingReads++
			return plan.AWS, nil
		}),
		ModelAuthorizations: cloudworker.ModelAuthorizationResolverFunc(func(context.Context, cloudworker.ModelAuthorization) (cloudworker.ModelAuthorization, error) {
			return plan.ModelAuthorization, nil
		}),
		Stager: stager, Outputs: outputs,
		Qualifications: cloudworker.ControllerQualificationResolverFunc(func(context.Context, cloudworker.Plan) (cloudworker.RuntimeQualification, error) {
			return qualification, nil
		}),
		AWS: provider, Sessions: workerSessions, ModelGrants: grants, Results: validator,
		Clock: func() time.Time { return time.Now().UTC().Truncate(time.Microsecond) }, PollInterval: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	outcome := controller.Handle(h.ctx, runningTask)
	if outcome.Err != nil || !outcome.TerminalOwned {
		t.Fatalf("controller outcome=%+v authorize_err=%v worker_set_phase=%s worker_set_err=%v stage_calls=%d prepare_calls=%d", outcome, storeTrace.authorizeErr, workerSessions.setPhase, workerSessions.setErr, stager.stageCalls, provider.prepareCalls)
	}

	terminal, err := h.cloud.GetExecutionForAuthority(h.ctx, h.owner, h.generation, plan.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	terminalTask, err := h.tasks.GetTask(h.ctx, plan.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	var taskSnapshot cloudworker.TaskResultSnapshot
	if terminalTask.Result == nil || json.Unmarshal(terminalTask.Result.JSON, &taskSnapshot) != nil ||
		taskSnapshot.ExecutionID != plan.ExecutionID || taskSnapshot.ServerSnapshot.Name == "" ||
		taskSnapshot.ServerSnapshot.Region != plan.AWS.Region ||
		taskSnapshot.ServerSnapshot.WorkerConfig.InstanceType != plan.Compute.InstanceType ||
		taskSnapshot.ServerSnapshot.WorkerConfig.WorkerReleaseDigest != plan.Compute.WorkerReleaseDigest {
		t.Fatalf("terminal task did not retain its server configuration snapshot: task=%+v snapshot=%+v", terminalTask, taskSnapshot)
	}
	turn, err := h.conversation.GetTurn(h.ctx, plan.TurnID)
	if err != nil {
		t.Fatal(err)
	}
	conversation, err := h.conversation.LoadConversation(h.ctx, plan.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	replayedExecution, replayedOutbox, err := h.cloud.CompleteExecution(h.ctx, runningTask, terminal.Revision, cloudworker.ProviderResult{Summary: "lost response replay"})
	if err != nil || replayedExecution.Revision != terminal.Revision {
		t.Fatalf("lost terminal response replay execution=%+v outbox=%+v err=%v", replayedExecution, replayedOutbox, err)
	}
	outboxes, err := h.cloud.ListPendingCompletionOutbox(h.ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(outboxes) != 1 || replayedOutbox.EventID != outboxes[0].EventID || replayedOutbox.ResultMessageID != outboxes[0].ResultMessageID {
		t.Fatalf("completion replay created a second result: replay=%+v pending=%+v", replayedOutbox, outboxes)
	}
	resultMessageID := uuid.Nil.String()
	if len(outboxes) == 1 {
		resultMessageID = outboxes[0].ResultMessageID
	}
	var verifiedResources, ledgerDestroyed, outputJournals, resultRows int
	if err = h.store.pool.QueryRow(h.ctx, `SELECT
		(SELECT count(*) FROM core_cloud_worker_resources WHERE execution_id=$1 AND state='verified_destroyed'),
		(SELECT count(*) FROM core_cloud_worker_aws_ledger WHERE execution_id=$1 AND state='verified_destroyed'),
		(SELECT count(*) FROM core_cloud_worker_output_journals WHERE execution_id=$1 AND state='verified_clean'),
		(SELECT count(*) FROM core_messages WHERE message_id=$2)`, plan.ExecutionID, resultMessageID).Scan(
		&verifiedResources, &ledgerDestroyed, &outputJournals, &resultRows); err != nil {
		t.Fatal(err)
	}
	events, err := h.conversation.LoadTurnEvents(h.ctx, plan.TurnID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var completionCalls, completionResults int
	for _, event := range events {
		if event.Kind == core.TurnEventToolCall && event.ToolCall != nil && event.ToolCall.Name == coremodel.IntrinsicCloudWorkerProposeToolName {
			completionCalls++
		}
		if event.Kind == core.TurnEventToolResult && event.ToolResult != nil && event.ToolResult.ToolName == coremodel.IntrinsicCloudWorkerProposeToolName {
			completionResults++
			if len(event.ToolResult.RelatedTaskIDs) != 1 || event.ToolResult.RelatedTaskIDs[0] != plan.TaskID ||
				len(event.ToolResult.RelatedPlanIDs) != 1 || event.ToolResult.RelatedPlanIDs[0] != plan.PlanID ||
				!strings.Contains(event.ToolResult.Content, "dirextalk.cloud-worker-completion/v1") {
				t.Fatalf("completion tool result lost authority: %+v", event.ToolResult)
			}
		}
	}
	if terminal.State != cloudworker.StateSucceeded || !terminal.Cleanup.VerifiedDestroyed ||
		terminal.Cleanup.ResourcesTotal != uint64(len(cloudaws.AllResourceKinds())) ||
		terminal.Cleanup.ResourcesVerifiedDestroyed != uint64(len(cloudaws.AllResourceKinds())) ||
		terminalTask.Status != coretask.StatusSucceeded || turn.State != core.TurnAccepted ||
		len(conversation.Messages) != 2 || len(outboxes) != 1 || outboxes[0].TerminalState != string(cloudworker.StateSucceeded) ||
		verifiedResources != len(cloudaws.AllResourceKinds()) || ledgerDestroyed != 1 || outputJournals != 1 ||
		outputObjects.inventoryCalls != 2 || outputObjects.deleteCalls != 1 || resultRows != 0 || completionCalls != 1 || completionResults != 1 {
		t.Fatalf("terminal graph execution=%+v task=%s turn=%s messages=%d outboxes=%+v resources=%d ledger=%d result_rows=%d tool_calls=%d tool_results=%d",
			terminal, terminalTask.Status, turn.State, len(conversation.Messages), outboxes,
			verifiedResources, ledgerDestroyed, resultRows, completionCalls, completionResults)
	}
	if provider.prepareCalls != 1 || provider.ensureCalls != 1 || provider.observeCalls != 1 || provider.destroyCalls != 1 ||
		workerSessions.setCalls != 1 || workerSessions.claimCalls != 1 || workerSessions.completeCalls != 1 ||
		stager.stageCalls != 1 || stager.cleanupCalls != 1 || grants.fenceCalls != 1 || objects.reads != 2 || awsBindingReads < 3 {
		t.Fatalf("single-worker qualification provider=%+v sessions=%+v stager=%+v grants=%+v object_reads=%d aws_binding_reads=%d",
			provider, workerSessions, stager, grants, objects.reads, awsBindingReads)
	}
}
