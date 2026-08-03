package postgres_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamresult"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

func TestTeamRoleDispatchPostgresClaimsSignedReadyRoleAndRecovers(
	t *testing.T,
) {
	pool, store, instanceID := newTeamInputTestStore(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		45*time.Second,
	)
	defer cancel()
	scope := task.MutationScope{
		ClientID:     "internal.team-dispatcher",
		CredentialID: uuid.NewString(),
	}
	execution := createDispatchingPiTeamInputExecution(
		t,
		ctx,
		pool,
		store,
		instanceID,
		scope,
	)
	authorized, err := store.LoadAuthorizedExecution(
		ctx,
		execution.Execution.OwnerID,
		execution.Execution.ExecutionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authorized.Execution.ExecutionDigest !=
		execution.ExecutionDigest {
		t.Fatal("authorized Execution digest drifted")
	}
	dispatchable, err := store.ListDispatchableExecutions(
		ctx,
		nil,
		32,
	)
	if err != nil ||
		len(dispatchable) != 1 ||
		dispatchable[0].OwnerID != execution.Execution.OwnerID ||
		dispatchable[0].Status != execution.Status ||
		dispatchable[0].TaskID != execution.Execution.TaskID ||
		dispatchable[0].ExecutionID !=
			execution.Execution.ExecutionID {
		t.Fatalf(
			"dispatchable Team executions=%#v error=%v",
			dispatchable,
			err,
		)
	}
	progress, err := store.LoadRoleProgress(
		ctx,
		execution.Execution.OwnerID,
		execution.Execution.ExecutionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := teamdispatch.ReadyRoleIDs(
		authorized,
		progress,
		nil,
	)
	if err != nil ||
		len(ready) != 1 ||
		ready[0] != execution.Execution.Roles[0].RoleID {
		t.Fatalf("ready roles=%#v error=%v", ready, err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	intent, err := teamdispatch.NewIntent(authorized, ready[0], now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := teamdispatch.ClaimIdempotencyKey(intent)
	if err != nil {
		t.Fatal(err)
	}
	command := teamdispatch.ClaimCommand{
		IdempotencyKey:     key,
		Intent:             intent,
		MaxConcurrentRoles: execution.Execution.MaxConcurrentWorkers,
	}
	first, replayed, err := store.ClaimRole(
		ctx,
		scope,
		command,
	)
	if err != nil || replayed || first.Phase != teamdispatch.PhaseIntent {
		t.Fatalf(
			"first Team role claim=%#v replayed=%v error=%v",
			first,
			replayed,
			err,
		)
	}
	same, replayed, err := store.ClaimRole(ctx, scope, command)
	if err != nil || !replayed || !reflect.DeepEqual(same, first) {
		t.Fatalf(
			"same-key Team role claim=%#v replayed=%v error=%v",
			same,
			replayed,
			err,
		)
	}
	otherScope := task.MutationScope{
		ClientID:     scope.ClientID,
		CredentialID: uuid.NewString(),
	}
	otherCommand := command
	otherCommand.IdempotencyKey = uuid.NewString()
	converged, replayed, err := store.ClaimRole(
		ctx,
		otherScope,
		otherCommand,
	)
	if err != nil || !replayed || !reflect.DeepEqual(converged, first) {
		t.Fatalf(
			"cross-credential Team role claim=%#v replayed=%v error=%v",
			converged,
			replayed,
			err,
		)
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	operations, err := restarted.ListExecutionOperations(
		ctx,
		execution.Execution.OwnerID,
		execution.Execution.ExecutionID,
	)
	if err != nil ||
		len(operations) != 1 ||
		!reflect.DeepEqual(operations[0], first) {
		t.Fatalf("restarted operations=%#v error=%v", operations, err)
	}
	recoverable, err := restarted.ListRecoverableRoleDispatches(
		ctx,
		nil,
		32,
		now.Add(time.Minute),
	)
	if err != nil ||
		len(recoverable) != 1 ||
		!reflect.DeepEqual(recoverable[0], first) {
		t.Fatalf(
			"recoverable operations=%#v error=%v",
			recoverable,
			err,
		)
	}

	tampered := command
	tampered.IdempotencyKey = uuid.NewString()
	tampered.Intent.ModelCredentialRef = "secret_ref:model/substitute"
	if _, _, err := restarted.ClaimRole(
		ctx,
		scope,
		tampered,
	); !errors.Is(err, teamdispatch.ErrNotReady) {
		t.Fatalf("signed credential substitution error=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_role_dispatches
		SET model_credential_ref='secret_ref:model/substitute',
		    record_revision=record_revision+1
		WHERE operation_id=$1`,
		first.Intent.OperationID,
	); err == nil ||
		!strings.Contains(
			err.Error(),
			"Team role dispatch intent is immutable",
		) {
		t.Fatalf("immutable Team role dispatch update error=%v", err)
	}

	retryAt := time.Now().UTC().Add(time.Minute).
		Truncate(time.Microsecond)
	retrying, err := restarted.ScheduleRoleRetry(
		ctx,
		teamdispatch.RetryCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: first.RecordRevision,
			Phase:            teamdispatch.PhaseIntent,
			FailureCode:      "artifact_service_unavailable",
			RetryAfter:       retryAt,
		},
	)
	if err != nil ||
		retrying.Attempt != 1 ||
		retrying.RetryAfter == nil ||
		!retrying.RetryAfter.Equal(retryAt) {
		t.Fatalf("scheduled retry=%#v error=%v", retrying, err)
	}
	notDue, err := restarted.ListRecoverableRoleDispatches(
		ctx,
		nil,
		32,
		retryAt.Add(-time.Second),
	)
	if err != nil || len(notDue) != 0 {
		t.Fatalf("not-due retries=%#v error=%v", notDue, err)
	}
	due, err := restarted.ListRecoverableRoleDispatches(
		ctx,
		nil,
		32,
		retryAt,
	)
	if err != nil || len(due) != 1 ||
		due[0].Intent.OperationID != first.Intent.OperationID {
		t.Fatalf("due retries=%#v error=%v", due, err)
	}
	inputReady, err := restarted.AdvanceRole(
		ctx,
		teamdispatch.AdvanceCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: retrying.RecordRevision,
			FromPhase:        teamdispatch.PhaseIntent,
			ToPhase:          teamdispatch.PhaseInputReady,
			Outcome:          task.OutcomePending,
		},
	)
	if err != nil ||
		inputReady.Phase != teamdispatch.PhaseInputReady ||
		inputReady.RetryAfter != nil ||
		inputReady.FailureCode != "" {
		t.Fatalf("input-ready dispatch=%#v error=%v", inputReady, err)
	}
	if _, err := restarted.AdvanceRole(
		ctx,
		teamdispatch.AdvanceCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: inputReady.RecordRevision,
			FromPhase:        teamdispatch.PhaseInputReady,
			ToPhase:          teamdispatch.PhaseArtifactsReady,
			Outcome:          task.OutcomePending,
		},
	); !errors.Is(err, teamdispatch.ErrInvalid) {
		t.Fatalf("evidence-free artifact transition error=%v", err)
	}
	evidence := teamDispatchPublishedEvidence(
		t,
		first.Intent,
		authorized.Approval.Approval.Authorization.
			ProviderScope.ConnectionID,
	)
	current, err := restarted.PublishRoleArtifacts(
		ctx,
		teamdispatch.PublishArtifactsCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: inputReady.RecordRevision,
			Evidence:         evidence,
		},
	)
	if err != nil ||
		current.Phase != teamdispatch.PhaseArtifactsReady ||
		current.PublishedEvidence == nil ||
		current.PublishedEvidenceDigest == "" {
		t.Fatalf("published Team artifacts=%#v error=%v", current, err)
	}
	replayedPublication, err := restarted.PublishRoleArtifacts(
		ctx,
		teamdispatch.PublishArtifactsCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: inputReady.RecordRevision,
			Evidence:         evidence,
		},
	)
	if err != nil ||
		replayedPublication.PublishedEvidenceDigest !=
			current.PublishedEvidenceDigest ||
		replayedPublication.RecordRevision != current.RecordRevision {
		t.Fatalf(
			"replayed Team publication=%#v error=%v",
			replayedPublication,
			err,
		)
	}
	for _, next := range []teamdispatch.Phase{
		teamdispatch.PhaseWorkerRegistered,
		teamdispatch.PhaseBootstrapReady,
	} {
		current, err = restarted.AdvanceRole(
			ctx,
			teamdispatch.AdvanceCommand{
				OwnerID:          first.Intent.OwnerID,
				OperationID:      first.Intent.OperationID,
				ExpectedRevision: current.RecordRevision,
				FromPhase:        current.Phase,
				ToPhase:          next,
				Outcome:          task.OutcomePending,
			},
		)
		if err != nil {
			t.Fatalf("advance dispatch to %s: %v", next, err)
		}
	}
	workerCreatedAt := time.Now().UTC().Truncate(time.Microsecond)
	var (
		workerRevision int64
		enrollmentEnds time.Time
	)
	if err := pool.QueryRow(ctx, `
		INSERT INTO worker_deployments (
		    deployment_id, agent_instance_id, owner_id,
		    task_id, step_id, control_plane_endpoint,
		    recipe_bundle_ref, recipe_bundle_sha256,
		    execution_bundle_ref, execution_bundle_sha256,
		    execution_timeout_seconds, state, outcome,
		    artifact_prefix, checkpoint_prefix, evidence_prefix,
		    log_prefix, enrollment_digest, enrollment_expires_at,
		    revision, created_at, updated_at
		)
		VALUES (
		    $1,$2,$3,$4,$5,
		    'grpcs://worker-control.test.dirextalk.ai:7443',
		    's3://team-test/recipe.cbor',
		    decode(repeat('11',32),'hex'),
		    's3://team-test/execution.json',
		    decode(repeat('22',32),'hex'),
		    300,'pending_enrollment','pending',
		    's3://team-test/artifacts/',
		    's3://team-test/checkpoints/',
		    's3://team-test/evidence/',
		    'cloudwatch://team-test/worker',
		    decode(repeat('33',32),'hex'),
		    $6::timestamptz + interval '10 minutes',
		    1,$6::timestamptz,$6::timestamptz
		)
		RETURNING revision, enrollment_expires_at`,
		first.Intent.DeploymentID,
		first.Intent.AgentInstanceID,
		first.Intent.OwnerID,
		first.Intent.TaskID,
		first.Intent.TaskStepID,
		workerCreatedAt,
	).Scan(&workerRevision, &enrollmentEnds); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.AdvanceRole(
		ctx,
		teamdispatch.AdvanceCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: current.RecordRevision,
			FromPhase:        teamdispatch.PhaseBootstrapReady,
			ToPhase:          teamdispatch.PhaseProvisioning,
			Outcome:          task.OutcomePending,
		},
	); !errors.Is(err, teamdispatch.ErrInvalid) {
		t.Fatalf("unquoted provisioning transition error=%v", err)
	}
	quote := teamDispatchFreshQuote(
		t,
		*authorized.Approval.Approval.Authorization,
	)
	expiredQuote := quote
	expiredQuote.ValidUntil = expiredQuote.CapturedAt.Add(30 * time.Second)
	if _, err := restarted.BeginProvisioning(
		ctx,
		teamdispatch.BeginProvisioningCommand{
			OwnerID:                  first.Intent.OwnerID,
			OperationID:              first.Intent.OperationID,
			ExpectedRevision:         current.RecordRevision,
			WorkerDeploymentRevision: uint64(workerRevision),
			Quote:                    expiredQuote,
		},
	); !errors.Is(err, teamdispatch.ErrNotReady) {
		t.Fatalf("expired provisioning quote error=%v", err)
	}
	provisioning, err := restarted.BeginProvisioning(
		ctx,
		teamdispatch.BeginProvisioningCommand{
			OwnerID:                  first.Intent.OwnerID,
			OperationID:              first.Intent.OperationID,
			ExpectedRevision:         current.RecordRevision,
			WorkerDeploymentRevision: uint64(workerRevision),
			Quote:                    quote,
		},
	)
	if err != nil ||
		provisioning.Phase != teamdispatch.PhaseProvisioning ||
		provisioning.ProvisioningQuote == nil ||
		provisioning.ProvisioningWorkerRevision !=
			uint64(workerRevision) ||
		provisioning.ProvisioningEnrollmentExpires == nil ||
		!provisioning.ProvisioningEnrollmentExpires.Equal(
			enrollmentEnds.UTC(),
		) {
		t.Fatalf(
			"provisioning dispatch=%#v error=%v",
			provisioning,
			err,
		)
	}
	recoveredStore, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := recoveredStore.GetRoleOperation(
		ctx,
		first.Intent.OwnerID,
		first.Intent.OperationID,
	)
	if err != nil || !reflect.DeepEqual(recovered, provisioning) {
		t.Fatalf(
			"recovered provisioning dispatch=%#v error=%v",
			recovered,
			err,
		)
	}
	workerLaunch, err := recoveredStore.LoadWorkerLaunchByDeployment(
		ctx,
		first.Intent.OwnerID,
		first.Intent.DeploymentID,
	)
	if err != nil ||
		workerLaunch.ValidateForIdentity() != nil ||
		!reflect.DeepEqual(workerLaunch.Dispatch, provisioning) ||
		workerLaunch.Authorization.Execution.ExecutionDigest !=
			execution.ExecutionDigest {
		t.Fatalf(
			"recovered Team Worker launch=%#v error=%v",
			workerLaunch,
			err,
		)
	}
	convergedProvisioning, err := recoveredStore.BeginProvisioning(
		ctx,
		teamdispatch.BeginProvisioningCommand{
			OwnerID:                  first.Intent.OwnerID,
			OperationID:              first.Intent.OperationID,
			ExpectedRevision:         current.RecordRevision,
			WorkerDeploymentRevision: uint64(workerRevision),
			Quote:                    quote,
		},
	)
	if err != nil ||
		!reflect.DeepEqual(convergedProvisioning, provisioning) {
		t.Fatalf(
			"converged provisioning dispatch=%#v error=%v",
			convergedProvisioning,
			err,
		)
	}
	refreshedQuote := quote
	refreshedQuote.SnapshotID = uuid.NewString()
	refreshedQuote.SnapshotDigest =
		"sha256:" + strings.Repeat("c", 64)
	refreshedQuote.CapturedAt =
		provisioning.ProvisioningStartedAt.Add(time.Microsecond)
	refreshedQuote.ValidUntil = refreshedQuote.CapturedAt.Add(
		time.Duration(
			refreshedQuote.MaximumQuoteAgeSeconds,
		) * time.Second,
	)
	refreshed, err := recoveredStore.RefreshProvisioningQuote(
		ctx,
		teamdispatch.RefreshProvisioningQuoteCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: provisioning.RecordRevision,
			Quote:            refreshedQuote,
		},
	)
	if err != nil ||
		refreshed.ProvisioningQuote == nil ||
		refreshed.ProvisioningQuoteDigest ==
			provisioning.ProvisioningQuoteDigest ||
		refreshed.ProvisioningStartedAt == nil ||
		!refreshed.ProvisioningStartedAt.After(
			*provisioning.ProvisioningStartedAt,
		) {
		t.Fatalf(
			"refreshed Team provisioning quote=%#v error=%v",
			refreshed,
			err,
		)
	}
	replayedRefresh, err := recoveredStore.RefreshProvisioningQuote(
		ctx,
		teamdispatch.RefreshProvisioningQuoteCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: provisioning.RecordRevision,
			Quote:            refreshedQuote,
		},
	)
	if err != nil || !reflect.DeepEqual(replayedRefresh, refreshed) {
		t.Fatalf(
			"replayed Team quote refresh=%#v error=%v",
			replayedRefresh,
			err,
		)
	}
	var quoteHistoryCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM team_role_provisioning_quote_history
		WHERE operation_id=$1`,
		first.Intent.OperationID,
	).Scan(&quoteHistoryCount); err != nil || quoteHistoryCount != 2 {
		t.Fatalf(
			"Team quote history count=%d error=%v",
			quoteHistoryCount,
			err,
		)
	}
	provisioning = refreshed
	resourceStore, err := recoveredStore.NewResourceStore()
	if err != nil {
		t.Fatal(err)
	}
	teamResource := workerResourceIntentFixture(
		first.Intent.AgentInstanceID,
		first.Intent.OwnerID,
		first.Intent.TaskID,
		first.Intent.DeploymentID,
		first.Intent.PlanDigest,
		first.Intent.ApprovalID,
	)
	teamResource.Type = resource.TypeEC2
	teamResource.LogicalName = "team-worker-instance"
	teamResource.Region = authorized.Approval.Plan.Plan.Region
	teamResource.CreatedAt = teamResource.CreatedAt.Add(123 * time.Nanosecond)
	teamResource.UpdatedAt = teamResource.CreatedAt
	createdResource, err := resourceStore.CreateIntent(ctx, teamResource)
	if err != nil {
		t.Fatalf("create Team Worker resource intent: %v", err)
	}
	if createdResource.ResourceID != teamResource.ResourceID ||
		createdResource.ApprovalID != first.Intent.ApprovalID ||
		createdResource.ApprovedPlanHash != first.Intent.PlanDigest {
		t.Fatalf("stored Team Worker resource intent=%+v", createdResource)
	}
	providerInstanceID := "i-0123456789abcdef0"
	createdResource.ProviderID = providerInstanceID
	createdResource.ReadBack = resource.ReadBackEvidence{
		Exists:     true,
		ProviderID: providerInstanceID,
		ObservedAt: createdResource.UpdatedAt.Add(time.Second),
		TagDigest:  "sha256:" + strings.Repeat("d", 64),
	}
	createdResource.State = resource.StateActive
	createdResource.Revision++
	createdResource.UpdatedAt = createdResource.ReadBack.ObservedAt
	createdResource, err = resourceStore.Save(
		ctx,
		createdResource,
		createdResource.Revision-1,
	)
	if err != nil {
		t.Fatalf("activate Team Worker EC2 resource: %v", err)
	}
	workerStore, err := recoveredStore.NewWorkerStore(
		bytes.Repeat([]byte{0x51}, 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	workerService, err := worker.NewService(
		workerStore,
		bytes.Repeat([]byte{0x52}, 32),
	)
	if err != nil {
		t.Fatal(err)
	}
	identityChallenge, err := workerService.CreateIdentityChallenge(
		ctx,
		worker.CreateIdentityChallengeRequest{
			DeploymentID:     first.Intent.DeploymentID,
			WorkerID:         first.Intent.ExpectedWorkerID,
			IdempotencyKey:   uuid.NewString(),
			ExpectedRevision: workerRevision,
		},
	)
	if err != nil ||
		identityChallenge.OwnerID != first.Intent.OwnerID ||
		identityChallenge.AccountID !=
			authorized.Approval.Plan.Plan.ProviderScope.AccountID ||
		identityChallenge.Region != authorized.Approval.Plan.Plan.Region ||
		identityChallenge.ExpectedProviderInstanceID != providerInstanceID {
		t.Fatalf(
			"Team Worker identity challenge=%+v error=%v",
			identityChallenge,
			err,
		)
	}
	providerCreateStartedAt := time.Now().UTC().Truncate(time.Microsecond)
	providerCreateStarted := createdResource
	providerCreateStarted.Intent.ProviderCreateStartedAt = providerCreateStartedAt
	providerCreateStarted.Revision++
	providerCreateStarted.UpdatedAt = providerCreateStartedAt
	providerCreateStarted, err = resourceStore.Save(
		ctx,
		providerCreateStarted,
		createdResource.Revision,
	)
	if err != nil ||
		!providerCreateStarted.Intent.ProviderCreateStartedAt.Equal(
			providerCreateStartedAt,
		) {
		t.Fatalf(
			"persist Team Worker provider-create boundary=%+v error=%v",
			providerCreateStarted,
			err,
		)
	}
	tamperedResource := workerResourceIntentFixture(
		first.Intent.AgentInstanceID,
		first.Intent.OwnerID,
		first.Intent.TaskID,
		first.Intent.DeploymentID,
		entryDigest("0"),
		first.Intent.ApprovalID,
	)
	tamperedResource.Region = authorized.Approval.Plan.Plan.Region
	if _, err := resourceStore.CreateIntent(ctx, tamperedResource); !errors.Is(err, resource.ErrInvalid) {
		t.Fatalf(
			"tampered Team Worker resource intent error=%v, want resource.ErrInvalid",
			err,
		)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_role_dispatches
		SET provisioning_quote_digest=$2,
		    record_revision=record_revision+1
		WHERE operation_id=$1`,
		first.Intent.OperationID,
		"sha256:"+strings.Repeat("0", 64),
	); err == nil ||
		!strings.Contains(err.Error(), "quote refresh is not authorized") {
		t.Fatalf("immutable provisioning quote update error=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_role_dispatches
		SET published_evidence_digest=$2,
		    record_revision=record_revision+1
		WHERE operation_id=$1`,
		first.Intent.OperationID,
		"sha256:"+strings.Repeat("0", 64),
	); err == nil ||
		!strings.Contains(err.Error(), "publication evidence is immutable") {
		t.Fatalf("immutable publication evidence update error=%v", err)
	}
	active, err := recoveredStore.AdvanceRole(
		ctx,
		teamdispatch.AdvanceCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: provisioning.RecordRevision,
			FromPhase:        teamdispatch.PhaseProvisioning,
			ToPhase:          teamdispatch.PhaseActive,
			Outcome:          task.OutcomePending,
		},
	)
	if err != nil ||
		active.Phase != teamdispatch.PhaseActive ||
		active.ProvisioningQuote == nil {
		t.Fatalf("active dispatch=%#v error=%v", active, err)
	}
	resultRef := "s3://team-test/artifacts/result-a1-e1.json"
	resultDigest := "sha256:" + strings.Repeat("e", 64)
	resultSize := int64(512)
	workerEvidence, err := json.Marshal([]worker.EvidenceRef{{
		Kind:         "artifact",
		Ref:          resultRef,
		ObjectSHA256: resultDigest,
		SizeBytes:    resultSize,
		MediaType:    "application/json",
		Trust:        worker.TrustWorkerClaim,
		Attempt:      1,
		LeaseEpoch:   1,
		RecordedAt:   workerCreatedAt.Add(time.Minute),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE worker_deployments
		SET worker_id=$2,
		    state='finished',
		    outcome='succeeded',
		    enrollment_consumed_at=$3,
		    session_digest=decode(repeat('44',32),'hex'),
		    lease_attempt=1,
		    lease_epoch=1,
		    lease_expires_at=NULL,
		    last_heartbeat_at=$3,
		    result_ref=$4,
		    evidence_json=$5,
		    revision=revision+1,
		    updated_at=$3
		WHERE deployment_id=$1`,
		first.Intent.DeploymentID,
		first.Intent.ExpectedWorkerID,
		workerCreatedAt.Add(time.Minute),
		resultRef,
		workerEvidence,
	); err != nil {
		t.Fatal(err)
	}
	resultEvidence := teamresult.EvidenceV1{
		SchemaVersion:    teamresult.SchemaV1,
		OperationID:      first.Intent.OperationID,
		ExecutionID:      first.Intent.ExecutionID,
		RoleID:           first.Intent.RoleID,
		DeploymentID:     first.Intent.DeploymentID,
		ExpectedWorkerID: first.Intent.ExpectedWorkerID,
		TaskID:           first.Intent.TaskID,
		TaskStepID:       first.Intent.TaskStepID,
		WorkerID:         first.Intent.ExpectedWorkerID,
		Attempt:          1,
		LeaseEpoch:       1,
		ResultRef:        resultRef,
		ResultSHA256:     resultDigest,
		ResultSizeBytes:  resultSize,
		ResultMediaType:  "application/json",
		Finals: []teamresult.FinalV1{{
			ActionID: "execute",
			Adapter:  workerruntime.AdapterPiV1,
			Usage: workerruntime.Usage{
				InputTokens:  100,
				OutputTokens: 20,
			},
			Status:       "completed",
			Summary:      "Implementation completed and verified.",
			Deliverables: []string{"Implementation"},
			Tests:        []string{"Focused tests passed."},
			Risks:        []string{},
			ArtifactRef: "s3://team-test/artifacts/" +
				"runtime-a1-e1-execute-final.json",
			ArtifactSHA256:    "sha256:" + strings.Repeat("f", 64),
			ArtifactSizeBytes: 256,
			ArtifactMediaType: "application/json",
		}},
	}
	registeredArtifact, err := teamartifact.NewVerified(
		teamartifact.BuildRequest{
			AgentInstanceID: first.Intent.AgentInstanceID,
			OwnerID:         first.Intent.OwnerID,
			ExecutionID:     first.Intent.ExecutionID,
			OperationID:     first.Intent.OperationID,
			TaskID:          first.Intent.TaskID,
			PlanID:          first.Intent.PlanID,
			PlanRevision:    first.Intent.PlanRevision,
			ConnectionID:    execution.Execution.ProviderScope.ConnectionID,
			RoleID:          first.Intent.RoleID,
			ActionID:        "execute",
			DeploymentID:    first.Intent.DeploymentID,
			Name:            "final.json",
			MediaType:       "application/json",
			SizeBytes:       256,
			SHA256:          "sha256:" + strings.Repeat("f", 64),
			ObjectRef: "s3://team-test/artifacts/" +
				"runtime-a1-e1-execute-final.json",
			CreatedAt:        workerCreatedAt.Add(time.Minute),
			RetentionExpires: workerCreatedAt.Add(90 * 24 * time.Hour),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	registeredArtifacts := []teamartifact.ArtifactV1{registeredArtifact}
	resultReady, err := recoveredStore.RecordRoleResult(
		ctx,
		teamdispatch.RecordResultCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: active.RecordRevision,
			Evidence:         resultEvidence,
			Artifacts:        registeredArtifacts,
		},
	)
	if err != nil ||
		resultReady.Phase != teamdispatch.PhaseResultReady ||
		resultReady.ResultEvidence == nil ||
		resultReady.ResultEvidenceDigest == "" ||
		resultReady.ResultVerifiedAt == nil {
		t.Fatalf(
			"result-ready dispatch=%#v error=%v",
			resultReady,
			err,
		)
	}
	replayedResult, err := recoveredStore.RecordRoleResult(
		ctx,
		teamdispatch.RecordResultCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: active.RecordRevision,
			Evidence:         resultEvidence,
			Artifacts:        registeredArtifacts,
		},
	)
	if err != nil ||
		!reflect.DeepEqual(replayedResult, resultReady) {
		t.Fatalf(
			"replayed Team result=%#v error=%v",
			replayedResult,
			err,
		)
	}
	storedArtifacts, err := restarted.ListTeamArtifacts(
		ctx,
		first.Intent.OwnerID,
		first.Intent.ExecutionID,
	)
	if err != nil ||
		len(storedArtifacts) != 1 ||
		!reflect.DeepEqual(storedArtifacts[0], registeredArtifact) {
		t.Fatalf("stored Team artifacts=%#v error=%v", storedArtifacts, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_artifacts
		SET name='changed.txt'
		WHERE artifact_id=$1`,
		registeredArtifact.ArtifactID,
	); err == nil ||
		!strings.Contains(err.Error(), "artifact metadata is immutable") {
		t.Fatalf("immutable Team artifact update error=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_role_dispatches
		SET result_evidence_digest=$2,
		    record_revision=record_revision+1
		WHERE operation_id=$1`,
		first.Intent.OperationID,
		"sha256:"+strings.Repeat("0", 64),
	); err == nil ||
		!strings.Contains(err.Error(), "result evidence is immutable") {
		t.Fatalf("immutable result evidence update error=%v", err)
	}
	destroying, err := restarted.AdvanceRole(
		ctx,
		teamdispatch.AdvanceCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: resultReady.RecordRevision,
			FromPhase:        teamdispatch.PhaseResultReady,
			ToPhase:          teamdispatch.PhaseDestroying,
			Outcome:          task.OutcomePending,
		},
	)
	if err != nil || destroying.Phase != teamdispatch.PhaseDestroying {
		t.Fatalf("destroying dispatch=%#v error=%v", destroying, err)
	}
	completed, err := restarted.AdvanceRole(
		ctx,
		teamdispatch.AdvanceCommand{
			OwnerID:          first.Intent.OwnerID,
			OperationID:      first.Intent.OperationID,
			ExpectedRevision: destroying.RecordRevision,
			FromPhase:        teamdispatch.PhaseDestroying,
			ToPhase:          teamdispatch.PhaseCompleted,
			Outcome:          task.OutcomeSucceeded,
		},
	)
	if err != nil ||
		completed.Phase != teamdispatch.PhaseCompleted ||
		completed.Outcome != task.OutcomeSucceeded ||
		completed.ResultEvidence == nil {
		t.Fatalf("completed dispatch=%#v error=%v", completed, err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE task_steps
		SET execution_status='finished',
		    outcome_status='succeeded',
		    result_ref=$3,
		    revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE task_id=$1 AND step_id=$2`,
		first.Intent.TaskID,
		first.Intent.TaskStepID,
		resultRef,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE tasks
		SET execution_status='finished',
		    outcome_status='succeeded',
		    current_step_id=NULL,
		    revision=revision+1,
		    updated_at=clock_timestamp()
		WHERE task_id=$1`,
		first.Intent.TaskID,
	); err != nil {
		t.Fatal(err)
	}
	for _, status := range []teamexecution.Status{
		teamexecution.StatusRunning,
		teamexecution.StatusVerifying,
	} {
		if _, err := pool.Exec(ctx, `
			UPDATE team_executions
			SET status=$2,
			    record_revision=record_revision+1,
			    updated_at=clock_timestamp()
			WHERE execution_id=$1`,
			first.Intent.ExecutionID,
			status,
		); err != nil {
			t.Fatal(err)
		}
	}
	conversationID := persistTeamPlanPrepareReceipt(
		t,
		ctx,
		recoveredStore,
		scope,
		first.Intent.OwnerID,
		first.Intent.TaskID,
	)
	if pendingReport, found, err :=
		recoveredStore.FindTeamExecutionReportByTask(
			ctx,
			first.Intent.OwnerID,
			first.Intent.TaskID,
		); err != nil || found || pendingReport.ReportDigest != "" {
		t.Fatalf(
			"premature Team report=%#v found=%t error=%v",
			pendingReport,
			found,
			err,
		)
	}
	finalized, err := recoveredStore.
		FinalizeReadyTeamExecutions(
			ctx,
			scope,
			32,
		)
	if err != nil || finalized != 1 {
		t.Fatalf(
			"finalized Team executions=%d error=%v",
			finalized,
			err,
		)
	}
	finalExecution, err := recoveredStore.GetTeamExecution(
		ctx,
		first.Intent.OwnerID,
		first.Intent.ExecutionID,
	)
	if err != nil ||
		finalExecution.Status != teamexecution.StatusCompleted {
		t.Fatalf(
			"final Team execution=%#v error=%v",
			finalExecution,
			err,
		)
	}
	report, err := recoveredStore.GetTeamExecutionReport(
		ctx,
		first.Intent.OwnerID,
		first.Intent.ExecutionID,
	)
	if err != nil ||
		report.Report.ExecutionID != first.Intent.ExecutionID ||
		report.ReportDigest == "" ||
		len(report.Report.Roles) != 1 ||
		report.Report.Roles[0].RoleID != first.Intent.RoleID ||
		report.Report.Roles[0].Finals[0].Summary !=
			"Implementation completed and verified." ||
		report.Report.TotalUsage.InputTokens != 100 ||
		report.Report.TotalUsage.OutputTokens != 20 {
		t.Fatalf("final Team report=%#v error=%v", report, err)
	}
	var completionSummary []byte
	if err := pool.QueryRow(ctx, `
		SELECT summary_json
		FROM task_events
		WHERE event_type='team.execution.completed'
		  AND aggregate_type='team_execution'
		  AND aggregate_id=$1`,
		first.Intent.ExecutionID,
	).Scan(&completionSummary); err != nil {
		t.Fatalf("read Team completion event: %v", err)
	}
	var completion struct {
		SchemaVersion   int    `json:"schema_version"`
		ExecutionID     string `json:"execution_id"`
		TaskID          string `json:"task_id"`
		PlanID          string `json:"plan_id"`
		ConversationID  string `json:"conversation_id"`
		ReportDigest    string `json:"report_digest"`
		CleanupVerified bool   `json:"cleanup_verified"`
	}
	if err := json.Unmarshal(completionSummary, &completion); err != nil ||
		completion.SchemaVersion != 1 ||
		completion.ExecutionID != first.Intent.ExecutionID ||
		completion.TaskID != first.Intent.TaskID ||
		completion.PlanID != first.Intent.PlanID ||
		completion.ConversationID != conversationID ||
		completion.ReportDigest != report.ReportDigest ||
		!completion.CleanupVerified {
		t.Fatalf(
			"Team completion summary=%s decoded=%#v error=%v",
			completionSummary,
			completion,
			err,
		)
	}
	byTask, found, err := recoveredStore.FindTeamExecutionReportByTask(
		ctx,
		first.Intent.OwnerID,
		first.Intent.TaskID,
	)
	if err != nil || !found ||
		byTask.ReportDigest != report.ReportDigest ||
		byTask.Report.ExecutionID != first.Intent.ExecutionID ||
		byTask.Report.TaskID != first.Intent.TaskID {
		t.Fatalf(
			"Team report by Task=%#v found=%t error=%v",
			byTask,
			found,
			err,
		)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE team_executions
		SET report_digest=$2,
		    record_revision=record_revision+1,
		    updated_at=clock_timestamp()
		WHERE execution_id=$1`,
		first.Intent.ExecutionID,
		"sha256:"+strings.Repeat("0", 64),
	); err == nil ||
		!strings.Contains(err.Error(), "report is immutable") {
		t.Fatalf("immutable Team report update error=%v", err)
	}
	replayedFinalization, err := recoveredStore.
		FinalizeReadyTeamExecutions(
			ctx,
			scope,
			32,
		)
	if err != nil || replayedFinalization != 0 {
		t.Fatalf(
			"replayed finalization=%d error=%v",
			replayedFinalization,
			err,
		)
	}
	var completionEventCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM task_events
		WHERE event_type='team.execution.completed'
		  AND aggregate_id=$1`,
		first.Intent.ExecutionID,
	).Scan(&completionEventCount); err != nil || completionEventCount != 1 {
		t.Fatalf(
			"Team completion event count=%d error=%v",
			completionEventCount,
			err,
		)
	}
	remaining, err := restarted.ListRecoverableRoleDispatches(
		ctx,
		nil,
		32,
		retryAt.Add(time.Minute),
	)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("terminal recoverable rows=%#v error=%v", remaining, err)
	}
	if _, err := pool.Exec(ctx, `
		DELETE FROM team_role_dispatches WHERE operation_id=$1`,
		first.Intent.OperationID,
	); err == nil ||
		!strings.Contains(
			err.Error(),
			"team_role_dispatches cannot be deleted",
		) {
		t.Fatalf("immutable Team role dispatch delete error=%v", err)
	}
}

func persistTeamPlanPrepareReceipt(
	t *testing.T,
	ctx context.Context,
	store *postgres.Store,
	scope task.MutationScope,
	ownerID string,
	taskID string,
) string {
	t.Helper()
	conversationID := "agent-chat-" + uuid.NewString()
	requestID := uuid.NewString()
	runtimeScope := runtimeapi.MutationScope{
		ClientID:     scope.ClientID,
		CredentialID: scope.CredentialID,
	}
	requestClaim, err := store.BeginRuntimeRequest(
		ctx,
		runtimeScope,
		runtimeapi.RuntimeRequestCommand{
			Request: runtimeapi.ChatRequest{
				RequestID:      requestID,
				OwnerID:        ownerID,
				ConversationID: conversationID,
				MemoryDisabled: true,
				Messages: []modelapi.Message{{
					Role:    modelapi.RoleUser,
					Content: "Prepare a Team Plan.",
				}},
			},
			LeaseDuration: time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("begin Team Plan runtime receipt: %v", err)
	}
	if _, err := store.BindRuntimeRequestMemoryMode(
		ctx,
		runtimeScope,
		runtimeapi.BindRuntimeRequestMemoryModeCommand{
			RequestID:      requestID,
			LeaseEpoch:     requestClaim.LeaseEpoch,
			MemoryDisabled: true,
		},
	); err != nil {
		t.Fatalf("bind Team Plan runtime receipt: %v", err)
	}
	toolCallID := "team-plan-prepare"
	toolClaim, err := store.BeginToolExecution(
		ctx,
		runtimeScope,
		runtimeapi.ToolExecutionCommand{
			RequestID:        requestID,
			ParentLeaseEpoch: requestClaim.LeaseEpoch,
			OwnerID:          ownerID,
			ConversationID:   conversationID,
			ToolCallID:       toolCallID,
			Name:             "team_plan_prepare",
			Arguments:        json.RawMessage(`{}`),
			LeaseDuration:    time.Minute,
		},
	)
	if err != nil {
		t.Fatalf("begin Team Plan tool receipt: %v", err)
	}
	if _, err := store.CompleteToolExecution(
		ctx,
		runtimeScope,
		runtimeapi.CompleteToolExecutionCommand{
			RequestID:        requestID,
			ToolCallID:       toolCallID,
			ParentLeaseEpoch: requestClaim.LeaseEpoch,
			LeaseEpoch:       toolClaim.LeaseEpoch,
			Execution: runtimeapi.ToolExecution{
				ToolCallID:     toolCallID,
				Name:           "team_plan_prepare",
				Content:        `{}`,
				RelatedTaskIDs: []string{taskID},
			},
		},
	); err != nil {
		t.Fatalf("complete Team Plan tool receipt: %v", err)
	}
	return conversationID
}

func TestRecoverableTeamRoleDispatchIncludesCanceledProjectionGap(
	t *testing.T,
) {
	pool, store, instanceID := newTeamInputTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scope := task.MutationScope{
		ClientID:     "internal.team-controller",
		CredentialID: uuid.NewString(),
	}
	execution := createDispatchingTeamInputExecution(
		t,
		ctx,
		pool,
		store,
		instanceID,
		scope,
	)
	authorized, err := store.LoadAuthorizedExecution(
		ctx,
		execution.Execution.OwnerID,
		execution.Execution.ExecutionID,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	intent, err := teamdispatch.NewIntent(
		authorized,
		execution.Execution.Roles[0].RoleID,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	key, err := teamdispatch.ClaimIdempotencyKey(intent)
	if err != nil {
		t.Fatal(err)
	}
	claimed, _, err := store.ClaimRole(ctx, scope, teamdispatch.ClaimCommand{
		IdempotencyKey:     key,
		Intent:             intent,
		MaxConcurrentRoles: execution.Execution.MaxConcurrentWorkers,
	})
	if err != nil {
		t.Fatal(err)
	}
	destroying, err := store.AdvanceRole(ctx, teamdispatch.AdvanceCommand{
		OwnerID:          intent.OwnerID,
		OperationID:      intent.OperationID,
		ExpectedRevision: claimed.RecordRevision,
		FromPhase:        teamdispatch.PhaseIntent,
		ToPhase:          teamdispatch.PhaseDestroying,
		Outcome:          task.OutcomePending,
	})
	if err != nil {
		t.Fatal(err)
	}
	completed, err := store.AdvanceRole(ctx, teamdispatch.AdvanceCommand{
		OwnerID:          intent.OwnerID,
		OperationID:      intent.OperationID,
		ExpectedRevision: destroying.RecordRevision,
		FromPhase:        teamdispatch.PhaseDestroying,
		ToPhase:          teamdispatch.PhaseCompleted,
		Outcome:          task.OutcomeCanceled,
	})
	if err != nil {
		t.Fatal(err)
	}
	recoverable, err := store.ListRecoverableRoleDispatches(
		ctx,
		nil,
		32,
		now.Add(time.Minute),
	)
	if err != nil || len(recoverable) != 1 ||
		recoverable[0].Intent.OperationID != completed.Intent.OperationID {
		t.Fatalf("recoverable canceled projection=%#v error=%v", recoverable, err)
	}
	currentTask, err := store.Get(ctx, execution.Execution.TaskID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Cancel(ctx, scope, task.CancelCommand{
		IdempotencyKey:   uuid.NewString(),
		TaskID:           currentTask.TaskID,
		ExpectedRevision: currentTask.Revision,
		Reason:           "terminal canceled role projection",
	}); err != nil {
		t.Fatal(err)
	}
	recoverable, err = store.ListRecoverableRoleDispatches(
		ctx,
		nil,
		32,
		now.Add(time.Minute),
	)
	if err != nil || len(recoverable) != 0 {
		t.Fatalf("converged canceled projection=%#v error=%v", recoverable, err)
	}
}

func teamDispatchPublishedEvidence(
	t *testing.T,
	intent teamdispatch.IntentV1,
	connectionID string,
) teamdispatch.PublishedEvidenceV1 {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	recipeDigest := sha256.Sum256([]byte("team recipe"))
	executionDigest := sha256.Sum256([]byte("team execution"))
	launchDigest := sha256.Sum256([]byte("team launch"))
	slotID := "model-" + strings.Repeat("a", 16)
	versionID := uuid.NewSHA1(
		uuid.MustParse(intent.DeploymentID),
		[]byte("test-model-credential"),
	).String()
	secretName := "dtx/" + intent.AgentInstanceID +
		"/deployments/" + intent.DeploymentID + "/" + slotID
	declaration := installer.SecretV1{
		SlotID:     slotID,
		SecretRef:  intent.ModelCredentialRef,
		SecretName: secretName,
		VersionID:  versionID,
		TargetPath: installer.PreinstalledSecretRoot + "/" + slotID,
		FileMode:   0o400,
		OwnerUID:   65532,
		OwnerGID:   65532,
	}
	binding := installer.BindingV1{
		AgentInstanceID: intent.AgentInstanceID,
		DeploymentID:    intent.DeploymentID,
		TaskID:          intent.TaskID,
		PlanHash:        intent.PlanDigest,
		ApprovalID:      intent.ApprovalID,
		RecipeDigest: "sha256:" +
			hex.EncodeToString(recipeDigest[:]),
	}
	issuer, err := installer.NewTrustIssuer(
		[]byte(strings.Repeat("k", sha256.Size)),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	delivery, err := issuer.Issue(
		installer.InstallerPlanV1{
			SchemaVersion: installer.PlanSchemaV1,
			Binding:       binding,
			SecretRefs:    []string{declaration.SecretRef},
			Secrets:       []installer.SecretV1{declaration},
			Network:       installer.NetworkV1{},
			ExpiresAt: now.Add(2 * time.Hour).
				Format(time.RFC3339Nano),
		},
		installer.DaemonConfigV1{
			SchemaVersion: installer.DaemonConfigSchema,
			Binding:       binding,
			TargetRoot:    installer.PreinstalledArtifactRoot,
		},
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	root, err := delivery.RootTrustMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := installerbootstrap.NewRootTrustMaterial(root)
	if err != nil {
		t.Fatal(err)
	}
	base := "s3://dtx-team-test/deployments/" +
		intent.DeploymentID + "/"
	opaqueSecret := "secret://aws/deployments/" +
		intent.DeploymentID + "/" + slotID + "/" + versionID
	evidence, err := teamdispatch.NewPublishedEvidenceV1(
		intent,
		connectionID,
		cloudexecution.PublishedBundles{
			Recipe: worker.BundleRef{
				S3Ref:  base + "bundles/recipe.cbor",
				SHA256: recipeDigest,
			},
			Execution: worker.BundleRef{
				S3Ref:  base + "bundles/execution.json",
				SHA256: executionDigest,
			},
			Launch: cloudexecution.BootstrapArtifact{
				Reference: base + "launch/config.json",
				SHA256:    launchDigest,
			},
			Access: worker.AccessScope{
				ArtifactPrefix:   base + "artifacts/",
				CheckpointPrefix: base + "checkpoints/",
				EvidencePrefix:   base + "evidence/",
				LogPrefix: "cloudwatch://dtx-team-test/" +
					intent.DeploymentID,
				SecretRefs: []string{opaqueSecret},
			},
			SecretBindings: map[string]string{
				intent.ModelCredentialRef: opaqueSecret,
			},
			InstallerRootTrust: &trust,
			InstallerArtifacts: []installerbootstrap.ArtifactSourceV1{},
			InstallerSecrets: []installerbootstrap.SecretSourceV1{{
				SchemaVersion: installerbootstrap.SecretSourceSchemaV1,
				SlotID:        declaration.SlotID,
				SecretRef:     declaration.SecretRef,
				SecretARN: "arn:aws:secretsmanager:us-east-1:" +
					"123456789012:secret:" +
					declaration.SecretName + "-ABCDEF",
				SecretName: declaration.SecretName,
				VersionID:  declaration.VersionID,
				KMSKeyARN: "arn:aws:kms:us-east-1:123456789012:key/" +
					"11111111-2222-4333-8444-555555555555",
				TargetPath:   declaration.TargetPath,
				FileMode:     declaration.FileMode,
				OwnerUID:     declaration.OwnerUID,
				OwnerGID:     declaration.OwnerGID,
				RecipeDigest: binding.RecipeDigest,
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return evidence
}

func teamDispatchFreshQuote(
	t *testing.T,
	authorization teamlaunch.AuthorizationV1,
) teamlaunch.FreshQuoteV1 {
	t.Helper()
	authorizationDigest, err := authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	roles := make(
		[]teamlaunch.FreshRoleQuoteV1,
		0,
		len(authorization.Roles),
	)
	var total uint64
	for _, approved := range authorization.Roles {
		roles = append(roles, teamlaunch.FreshRoleQuoteV1{
			RoleID:               approved.RoleID,
			ComputeMaximumMicros: approved.MaximumApprovedCostMicros,
			TotalMaximumMicros:   approved.MaximumApprovedCostMicros,
		})
		total += approved.MaximumApprovedCostMicros
	}
	quote := teamlaunch.FreshQuoteV1{
		SchemaVersion:       teamlaunch.FreshQuoteSchemaV1,
		AuthorizationID:     authorization.AuthorizationID,
		AuthorizationDigest: authorizationDigest,
		PlanID:              authorization.PlanID,
		PlanRevision:        authorization.PlanRevision,
		PlanDigest:          authorization.PlanDigest,
		ProviderScope:       authorization.ProviderScope,
		Region:              authorization.Region,
		Currency:            authorization.Currency,
		SnapshotID:          uuid.NewString(),
		SnapshotDigest:      "sha256:" + strings.Repeat("d", 64),
		CapturedAt:          authorization.LaunchNotBefore,
		ValidUntil: authorization.LaunchNotBefore.Add(
			time.Duration(
				authorization.MaximumQuoteAgeSeconds,
			) * time.Second,
		),
		MaximumQuoteAgeSeconds: authorization.MaximumQuoteAgeSeconds,
		Roles:                  roles,
		TotalMaximumMicros:     total,
		HardBudgetMicros:       authorization.HardBudgetMicros,
	}
	if quote.ValidateAgainstAuthorization(authorization) != nil {
		t.Fatal("Team fresh quote fixture is invalid")
	}
	return quote
}
