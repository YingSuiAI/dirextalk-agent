package postgres

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/jackc/pgx/v5"
)

// CloudWorkerControlStore is the private WorkerControl durability boundary.
// Every token-bearing mutation locks the authoritative CoreTask in the same
// transaction, so a successful preflight check cannot race lease reclaim.
type CloudWorkerControlStore struct{ store *Store }

func NewCloudWorkerControlStore(store *Store) *CloudWorkerControlStore {
	return &CloudWorkerControlStore{store: store}
}

func validControlFence(fence control.TaskFence) bool {
	return coretask.ValidUUID(fence.ExecutionID) && coretask.ValidUUID(fence.TaskID) && fence.AccountGeneration > 0 && fence.Attempt > 0 && fence.LeaseEpoch > 0
}

func lockControlFenceTx(ctx context.Context, tx pgx.Tx, fence control.TaskFence, now time.Time) (coretask.Task, error) {
	if !validControlFence(fence) {
		return coretask.Task{}, control.ErrInvalid
	}
	task, err := scanCoreTask(tx.QueryRow(ctx, taskSelect+` WHERE task_id=$1 AND deleted_at IS NULL FOR UPDATE`, fence.TaskID))
	if err != nil || task.Spec.Kind != coretask.TaskKindCloudWorker || task.Spec.Payload.CloudWorker == nil ||
		task.Spec.Payload.CloudWorker.ExecutionID != fence.ExecutionID || task.Spec.Payload.CloudWorker.AccountGeneration != fence.AccountGeneration ||
		task.Status != coretask.StatusRunning || task.Attempt != fence.Attempt || task.LeaseEpoch != fence.LeaseEpoch ||
		task.Lease == nil || !task.Lease.ExpiresAt.After(now.UTC()) {
		return coretask.Task{}, control.ErrStaleLease
	}
	return task, nil
}

func controlFenceForTask(task coretask.Task, executionID string) (control.TaskFence, error) {
	if task.Spec.Kind != coretask.TaskKindCloudWorker || task.Spec.Payload.CloudWorker == nil || task.Lease == nil ||
		task.Spec.Payload.CloudWorker.ExecutionID != executionID || task.Status != coretask.StatusRunning || task.Attempt == 0 || task.LeaseEpoch == 0 {
		return control.TaskFence{}, control.ErrInvalid
	}
	return control.TaskFence{ExecutionID: executionID, TaskID: task.ID, AccountGeneration: task.Spec.Payload.CloudWorker.AccountGeneration, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch}, nil
}

// ValidateCloudWorkerLease performs the early WorkerControl lease check. Each
// token-bearing store mutation repeats this check while holding the CoreTask
// row lock, so this method is never the sole authorization boundary.
func (s *CloudWorkerControlStore) ValidateCloudWorkerLease(ctx context.Context, fence control.TaskFence) error {
	if s == nil || s.store == nil || ctx == nil || !validControlFence(fence) {
		return control.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err = lockControlFenceTx(ctx, tx, fence, now); err != nil {
		return err
	}
	var expectationCount int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_launch_expectations
		WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4
		  AND account_generation=$5 AND current=true`, fence.ExecutionID, fence.TaskID,
		fence.Attempt, fence.LeaseEpoch, fence.AccountGeneration).Scan(&expectationCount); err != nil {
		return err
	}
	if expectationCount != 1 {
		return control.ErrStaleLease
	}
	return tx.Commit(ctx)
}

func (s *CloudWorkerControlStore) workerLaunchPublicationPending(ctx context.Context, lookup control.LaunchLookup, fence control.TaskFence) (bool, error) {
	var pending bool
	now := time.Now().UTC().Truncate(time.Microsecond)
	err := s.store.pool.QueryRow(ctx, `SELECT NOT EXISTS (
		SELECT 1 FROM core_cloud_worker_launch_expectations expectation
		WHERE expectation.execution_id=execution.execution_id
		  AND expectation.task_id=task.task_id AND expectation.task_attempt=task.attempt
		  AND expectation.lease_epoch=task.lease_epoch
		  AND expectation.account_generation=execution.account_generation AND expectation.current=true
	)
	FROM core_tasks task
	JOIN core_cloud_worker_executions execution ON execution.task_id=task.task_id
	JOIN core_cloud_worker_launch_material material ON material.execution_id=execution.execution_id
	WHERE task.task_id=$1 AND task.deleted_at IS NULL AND task.status='running'
	  AND task.attempt=$2 AND task.lease_epoch=$3 AND task.lease_expires_at>$4
	  AND execution.execution_id=$5 AND execution.account_generation=$6
	  AND execution.provider_mutation_started=true AND execution.terminal_intent=''
	  AND execution.state IN ('provisioning','awaiting_worker')
	  AND material.task_id=task.task_id AND material.account_generation=execution.account_generation
	  AND material.launch_identity=$7`, lookup.TaskID, fence.Attempt, fence.LeaseEpoch, now,
		lookup.ExecutionID, lookup.AccountGeneration, lookup.LaunchIdentity).Scan(&pending)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return pending, err
}

// ResolveWorkerLaunch revalidates a boot request against the current CoreTask,
// exact launch expectation, immutable launch material and active AWS ledger.
// A mutable EC2 name or tag lookup cannot manufacture this authority.
func (s *CloudWorkerControlStore) ResolveWorkerLaunch(ctx context.Context, lookup control.LaunchLookup) (control.IssueChallengeRequest, error) {
	if s == nil || s.store == nil || ctx == nil || !coretask.ValidUUID(lookup.ExecutionID) ||
		!coretask.ValidUUID(lookup.TaskID) || lookup.AccountGeneration == 0 ||
		strings.TrimSpace(lookup.InstanceID) != lookup.InstanceID || lookup.InstanceID == "" ||
		strings.TrimSpace(lookup.LaunchIdentity) != lookup.LaunchIdentity || lookup.LaunchIdentity == "" {
		return control.IssueChallengeRequest{}, control.ErrInvalid
	}
	task, err := NewCoreTaskStore(s.store).GetTask(ctx, lookup.TaskID)
	if err != nil {
		return control.IssueChallengeRequest{}, control.ErrStaleLease
	}
	fence, err := controlFenceForTask(task, lookup.ExecutionID)
	if err != nil || fence.AccountGeneration != lookup.AccountGeneration {
		return control.IssueChallengeRequest{}, control.ErrStaleLease
	}
	pending, err := s.workerLaunchPublicationPending(ctx, lookup, fence)
	if err != nil {
		return control.IssueChallengeRequest{}, err
	}
	if pending {
		// EC2 can finish cloud-init before the controller has observed the
		// stack and published its exact identity expectation. No authority is
		// issued here; NotFound activates the Worker's bounded retry path.
		return control.IssueChallengeRequest{}, control.ErrNotFound
	}
	if err = s.ValidateCloudWorkerLease(ctx, fence); err != nil {
		return control.IssueChallengeRequest{}, err
	}
	var expectation control.IdentityExpectation
	var tagsRaw, ledgerRaw []byte
	var executionState, ledgerState, materialLaunchIdentity, ledgerLaunchIdentity string
	err = s.store.pool.QueryRow(ctx, `SELECT expectation.owner_id,expectation.account_generation,
		expectation.account_id,expectation.region,expectation.instance_id,expectation.launch_identity,
		expectation.role_arn,expectation.role_id,expectation.instance_profile_id,expectation.required_tags_json,execution.state,ledger.state,ledger.record_json,
		material.launch_identity,ledger.launch_identity
		FROM core_cloud_worker_launch_expectations expectation
		JOIN core_cloud_worker_executions execution ON execution.execution_id=expectation.execution_id
		JOIN core_cloud_worker_launch_material material ON material.execution_id=expectation.execution_id
		JOIN core_cloud_worker_aws_ledger ledger ON ledger.execution_id=expectation.execution_id
		WHERE expectation.execution_id=$1 AND expectation.task_id=$2
		  AND expectation.task_attempt=$3 AND expectation.lease_epoch=$4
		  AND expectation.account_generation=$5 AND expectation.instance_id=$6
		  AND expectation.launch_identity=$7 AND expectation.current=true
		  AND execution.provider_mutation_started=true AND execution.terminal_intent=''
		  AND ledger.owner_id=expectation.owner_id
		  AND ledger.account_id=expectation.account_id
		  AND ledger.account_generation=expectation.account_generation
		  AND ledger.region=expectation.region`, lookup.ExecutionID, lookup.TaskID,
		fence.Attempt, fence.LeaseEpoch, lookup.AccountGeneration, lookup.InstanceID,
		lookup.LaunchIdentity).Scan(&expectation.OwnerID, &expectation.AccountGeneration,
		&expectation.AccountID, &expectation.Region, &expectation.InstanceID,
		&expectation.LaunchIdentity, &expectation.RoleARN, &expectation.RoleID, &expectation.InstanceProfileID,
		&tagsRaw, &executionState,
		&ledgerState, &ledgerRaw, &materialLaunchIdentity, &ledgerLaunchIdentity)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return control.IssueChallengeRequest{}, control.ErrStaleLease
		}
		return control.IssueChallengeRequest{}, err
	}
	var ledgerRecord cloudaws.LedgerRecord
	if json.Unmarshal(tagsRaw, &expectation.RequiredTags) != nil || json.Unmarshal(ledgerRaw, &ledgerRecord) != nil ||
		ledgerRecord.Validate() != nil || ledgerRecord.State != cloudaws.LifecycleActive ||
		(executionState != string(cloudworker.StateAwaitingWorker) && executionState != string(cloudworker.StateRunning)) ||
		ledgerState != string(cloudaws.LifecycleActive) || materialLaunchIdentity != lookup.LaunchIdentity ||
		ledgerLaunchIdentity != lookup.LaunchIdentity || ledgerRecord.Identity.OwnerID != expectation.OwnerID ||
		ledgerRecord.Identity.AccountID != expectation.AccountID || ledgerRecord.Identity.AccountGeneration != expectation.AccountGeneration ||
		ledgerRecord.Identity.Region != expectation.Region || ledgerRecord.Identity.LaunchIdentity != expectation.LaunchIdentity ||
		ledgerRecord.Resources[cloudaws.ResourceEC2].ProviderID != expectation.InstanceID ||
		ledgerRecord.Resources[cloudaws.ResourceIAMRole].ProviderID != expectation.RoleID ||
		ledgerRecord.Resources[cloudaws.ResourceInstanceProfile].ProviderID != expectation.InstanceProfileID {
		return control.IssueChallengeRequest{}, control.ErrIdentityRejected
	}
	canonical, err := expectation.Canonical()
	if err != nil || !reflect.DeepEqual(canonical, expectation) {
		return control.IssueChallengeRequest{}, control.ErrIdentityRejected
	}
	return control.IssueChallengeRequest{Fence: fence, Expectation: canonical, TTL: control.DefaultChallengeTTL}, nil
}

// SetLaunchExpectation publishes the only current Worker identity fence. All
// non-identity claim material is read from the locked Plan and the immutable
// first launch material, so a controller reclaim cannot accidentally change
// runtime bytes, artifact scope, AWS launch identity, or create a second
// dispatch. Rotating to a reclaimed CoreTask fence atomically fences the old
// Worker sessions and model grants before the replacement becomes current.
func (s *CloudWorkerControlStore) SetLaunchExpectation(ctx context.Context, supplied coretask.Task, expectation control.IdentityExpectation) error {
	if s == nil || s.store == nil || supplied.Lease == nil || supplied.Spec.Payload.CloudWorker == nil {
		return control.ErrInvalid
	}
	canonical, err := expectation.Canonical()
	if err != nil || !reflect.DeepEqual(canonical, expectation) {
		return control.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC().Truncate(time.Microsecond)
	currentTask, err := NewCoreTaskStore(s.store).taskTxLocked(ctx, tx, supplied.ID, false)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, now) != nil {
		return control.ErrStaleLease
	}
	plan, execution, err := cloudWorkerPlanAndExecutionTx(ctx, tx, currentTask.Spec.Payload.CloudWorker, true)
	if err != nil || !execution.ProviderMutationStarted || execution.TerminalIntent != "" ||
		execution.State == cloudworker.StateCleaning || execution.State == cloudworker.StateSucceeded ||
		execution.State == cloudworker.StateFailed || execution.State == cloudworker.StateCanceled ||
		execution.State == cloudworker.StateRejected || execution.State == cloudworker.StateExpired {
		return control.ErrStaleLease
	}
	if canonical.OwnerID != plan.OwnerID || canonical.AccountGeneration != plan.AccountGeneration ||
		canonical.AccountID != plan.AWS.AccountID || canonical.Region != plan.AWS.Region {
		return control.ErrIdentityRejected
	}

	var initialAttempt uint32
	var initialEpoch uint64
	var runtimeDigest, inputDigest, launchIdentity string
	var initialIdentityRaw []byte
	if err = tx.QueryRow(ctx, `SELECT task_attempt,lease_epoch,runtime_task_sha256,input_manifest_sha256,
		launch_identity,aws_identity_json FROM core_cloud_worker_launch_material WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID).Scan(
		&initialAttempt, &initialEpoch, &runtimeDigest, &inputDigest, &launchIdentity, &initialIdentityRaw); err != nil {
		return control.ErrIdentityRejected
	}
	var initialIdentity cloudaws.ExecutionIdentity
	if json.Unmarshal(initialIdentityRaw, &initialIdentity) != nil || initialIdentity.Validate() != nil ||
		initialIdentity.ExecutionID != plan.ExecutionID || initialIdentity.TaskID != plan.TaskID ||
		initialIdentity.TaskAttempt != initialAttempt || initialIdentity.LeaseEpoch != initialEpoch ||
		initialIdentity.LaunchIdentity != launchIdentity || canonical.LaunchIdentity != launchIdentity {
		return control.ErrIdentityRejected
	}

	var ledgerOwner, ledgerAccount, ledgerRegion, ledgerExecution, ledgerTask, ledgerLaunch string
	var ledgerGeneration, ledgerAttempt, ledgerEpoch uint64
	var ledgerPlanDigest, ledgerInfrastructureDigest, ledgerIntentDigest, ledgerState string
	var ledgerRaw []byte
	if err = tx.QueryRow(ctx, `SELECT owner_id,account_id,account_generation,region,execution_id::text,task_id::text,
		task_attempt,lease_epoch,launch_identity,plan_digest,infrastructure_digest,intent_digest,state,record_json
		FROM core_cloud_worker_aws_ledger WHERE execution_id=$1 FOR UPDATE`, plan.ExecutionID).Scan(
		&ledgerOwner, &ledgerAccount, &ledgerGeneration, &ledgerRegion, &ledgerExecution, &ledgerTask,
		&ledgerAttempt, &ledgerEpoch, &ledgerLaunch, &ledgerPlanDigest, &ledgerInfrastructureDigest,
		&ledgerIntentDigest, &ledgerState, &ledgerRaw); err != nil {
		return control.ErrIdentityRejected
	}
	var ledger cloudaws.LedgerRecord
	if json.Unmarshal(ledgerRaw, &ledger) != nil || ledger.Validate() != nil || ledger.State != cloudaws.LifecycleActive ||
		ledgerState != string(cloudaws.LifecycleActive) || ledgerOwner != plan.OwnerID || ledgerAccount != plan.AWS.AccountID ||
		ledgerGeneration != plan.AccountGeneration || ledgerRegion != plan.AWS.Region || ledgerExecution != plan.ExecutionID ||
		ledgerTask != plan.TaskID || ledgerAttempt != uint64(initialAttempt) || ledgerEpoch != initialEpoch ||
		ledgerLaunch != launchIdentity || ledgerPlanDigest != ledger.Plan.Digest ||
		ledgerInfrastructureDigest != ledger.Plan.InfrastructureDigest || ledgerIntentDigest != ledger.Intent.IntentDigest ||
		!ledger.Identity.Equal(initialIdentity) {
		return control.ErrIdentityRejected
	}
	ec2 := ledger.Resources[cloudaws.ResourceEC2]
	role := ledger.Resources[cloudaws.ResourceIAMRole]
	instanceProfile := ledger.Resources[cloudaws.ResourceInstanceProfile]
	partition := "aws"
	if strings.HasPrefix(plan.AWS.Region, "cn-") {
		partition = "aws-cn"
	} else if strings.HasPrefix(plan.AWS.Region, "us-gov-") {
		partition = "aws-us-gov"
	}
	expected := control.IdentityExpectation{
		OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration,
		AccountID: plan.AWS.AccountID, Region: plan.AWS.Region,
		InstanceID: ec2.ProviderID, LaunchIdentity: launchIdentity,
		RoleARN: fmt.Sprintf("arn:%s:iam::%s:role/%s", partition, plan.AWS.AccountID, ledger.Plan.IAMRoleName),
		RoleID:  role.ProviderID, InstanceProfileID: instanceProfile.ProviderID,
		RequiredTags: cloudaws.RequiredTags(ledger.Identity, ledger.Plan.Digest, ledger.Plan.InfrastructureDigest, ledger.Intent.IntentDigest),
	}
	expected, err = expected.Canonical()
	requiredTags := expected.RequiredTags
	if err != nil || ec2.State != cloudaws.ResourceActive || role.State != cloudaws.ResourceActive ||
		!ec2.Observation.Exists || ec2.Observation.ProviderID != ec2.ProviderID ||
		ec2.Observation.LaunchIdentity != ledger.Identity.LaunchIdentity || ec2.Observation.Generation != ledger.Identity.Generation ||
		!cloudaws.ContainsRequiredTags(ec2.Observation.Tags, requiredTags) ||
		!role.Observation.Exists || !cloudaws.ValidIAMImmutableID(role.ProviderID) || role.Observation.ProviderID != role.ProviderID ||
		role.Observation.LaunchIdentity != ledger.Identity.LaunchIdentity || role.Observation.Generation != ledger.Identity.Generation ||
		!cloudaws.ContainsRequiredTags(role.Observation.Tags, requiredTags) ||
		instanceProfile.State != cloudaws.ResourceActive || instanceProfile.IdentityState != cloudaws.ResourceIdentityVerified ||
		!instanceProfile.Observation.Exists || !cloudaws.ValidIAMImmutableID(instanceProfile.ProviderID) ||
		instanceProfile.Observation.ProviderID != instanceProfile.ProviderID ||
		instanceProfile.Observation.LaunchIdentity != ledger.Identity.LaunchIdentity ||
		instanceProfile.Observation.Generation != ledger.Identity.Generation ||
		!cloudaws.ContainsRequiredTags(instanceProfile.Observation.Tags, requiredTags) ||
		!equalControlExpectation(expected, canonical) {
		return control.ErrIdentityRejected
	}

	artifactBucket, artifactPrefix := plan.ArtifactGrant.Bucket, plan.ArtifactGrant.KeyPrefix
	maximumArtifactBytes := int64(plan.Limits.MaxOutputBytes)
	var oldFence control.TaskFence
	var oldExpectation control.IdentityExpectation
	var oldRuntime, oldInput, oldBucket, oldPrefix string
	var oldMaximum int64
	var oldTagsRaw []byte
	currentErr := tx.QueryRow(ctx, `SELECT task_id::text,task_attempt,lease_epoch,owner_id,account_generation,account_id,
		region,instance_id,launch_identity,role_arn,role_id,instance_profile_id,required_tags_json,runtime_task_sha256,input_manifest_sha256,
		artifact_bucket,artifact_prefix,maximum_artifact_bytes
		FROM core_cloud_worker_launch_expectations WHERE execution_id=$1 AND current=true FOR UPDATE`, plan.ExecutionID).Scan(
		&oldFence.TaskID, &oldFence.Attempt, &oldFence.LeaseEpoch, &oldExpectation.OwnerID,
		&oldExpectation.AccountGeneration, &oldExpectation.AccountID, &oldExpectation.Region,
		&oldExpectation.InstanceID, &oldExpectation.LaunchIdentity, &oldExpectation.RoleARN,
		&oldExpectation.RoleID, &oldExpectation.InstanceProfileID, &oldTagsRaw,
		&oldRuntime, &oldInput, &oldBucket, &oldPrefix, &oldMaximum)
	if currentErr == nil {
		oldFence.ExecutionID, oldFence.AccountGeneration = plan.ExecutionID, oldExpectation.AccountGeneration
		if json.Unmarshal(oldTagsRaw, &oldExpectation.RequiredTags) != nil || !equalControlExpectation(oldExpectation, canonical) ||
			oldRuntime != runtimeDigest || oldInput != inputDigest || oldBucket != artifactBucket ||
			oldPrefix != artifactPrefix || oldMaximum != maximumArtifactBytes || oldFence.TaskID != plan.TaskID {
			return control.ErrIdentityRejected
		}
		newFence := control.TaskFence{ExecutionID: plan.ExecutionID, TaskID: plan.TaskID,
			AccountGeneration: plan.AccountGeneration, Attempt: currentTask.Attempt, LeaseEpoch: currentTask.LeaseEpoch}
		if oldFence == newFence {
			var fenced int
			if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_session_fences
				WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4`,
				newFence.ExecutionID, newFence.TaskID, newFence.Attempt, newFence.LeaseEpoch).Scan(&fenced); err != nil || fenced != 0 {
				return control.ErrStaleLease
			}
			return tx.Commit(ctx)
		}
		if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_session_fences(execution_id,task_id,task_attempt,lease_epoch,fenced_at,reason)
			VALUES($1,$2,$3,$4,$5,'lease_reclaimed') ON CONFLICT DO NOTHING`, oldFence.ExecutionID, oldFence.TaskID,
			oldFence.Attempt, oldFence.LeaseEpoch, now); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE core_cloud_worker_sessions SET state='failed',failure_code='session_superseded',
			failure_summary='CoreTask lease reclaimed',finished_at=$2,revision=revision+1
			WHERE execution_id=$1 AND task_id=$3 AND task_attempt=$4 AND lease_epoch=$5 AND state='active'`,
			plan.ExecutionID, now, oldFence.TaskID, oldFence.Attempt, oldFence.LeaseEpoch); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `UPDATE core_cloud_worker_model_grants SET state='fenced',reason_code='lease_reclaimed',
			fenced_at=$2,updated_at=$2,revision=revision+1
			WHERE execution_id=$1 AND task_id=$3 AND task_attempt=$4 AND lease_epoch=$5 AND state='active'`,
			plan.ExecutionID, now, oldFence.TaskID, oldFence.Attempt, oldFence.LeaseEpoch); err != nil {
			return err
		}
		updated, updateErr := tx.Exec(ctx, `UPDATE core_cloud_worker_launch_expectations SET current=false,superseded_at=$2
			WHERE execution_id=$1 AND task_attempt=$3 AND lease_epoch=$4 AND current=true`,
			plan.ExecutionID, now, oldFence.Attempt, oldFence.LeaseEpoch)
		if updateErr != nil || updated.RowsAffected() != 1 {
			return control.ErrConflict
		}
	} else if !errors.Is(currentErr, pgx.ErrNoRows) {
		return currentErr
	}
	tagsRaw, _ := json.Marshal(canonical.RequiredTags)
	inserted, err := tx.Exec(ctx, `INSERT INTO core_cloud_worker_launch_expectations(
		execution_id,task_id,task_attempt,lease_epoch,owner_id,account_generation,account_id,region,instance_id,
		launch_identity,role_arn,role_id,instance_profile_id,required_tags_json,runtime_task_sha256,input_manifest_sha256,artifact_bucket,
		artifact_prefix,maximum_artifact_bytes,created_at,current)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,true)`,
		plan.ExecutionID, plan.TaskID, currentTask.Attempt, currentTask.LeaseEpoch, canonical.OwnerID,
		canonical.AccountGeneration, canonical.AccountID, canonical.Region, canonical.InstanceID,
		canonical.LaunchIdentity, canonical.RoleARN, canonical.RoleID, canonical.InstanceProfileID, tagsRaw, runtimeDigest, inputDigest,
		artifactBucket, artifactPrefix, maximumArtifactBytes, now)
	if err != nil || inserted.RowsAffected() != 1 {
		return control.ErrConflict
	}
	return tx.Commit(ctx)
}

func (s *CloudWorkerControlStore) CreateChallenge(ctx context.Context, record control.ChallengeRecord) error {
	if s == nil || s.store == nil || !coretask.ValidUUID(record.ChallengeID) || !validControlFence(record.Fence) || record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) {
		return control.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = lockControlFenceTx(ctx, tx, record.Fence, record.CreatedAt); err != nil {
		return err
	}
	// Persist the service-normalized expectation and compare it with the
	// authoritative expectation row using the typed columns below.
	var ownerID, accountID, region, instanceID, launchIdentity, roleARN, roleID, instanceProfileID string
	var generation uint64
	var tagsRaw []byte
	if err = tx.QueryRow(ctx, `SELECT owner_id,account_generation,account_id,region,instance_id,launch_identity,role_arn,role_id,instance_profile_id,required_tags_json
		FROM core_cloud_worker_launch_expectations WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4 AND current=true`,
		record.Fence.ExecutionID, record.Fence.TaskID, record.Fence.Attempt, record.Fence.LeaseEpoch).Scan(&ownerID, &generation, &accountID, &region, &instanceID, &launchIdentity, &roleARN, &roleID, &instanceProfileID, &tagsRaw); err != nil {
		return control.ErrStaleLease
	}
	var tags map[string]string
	if json.Unmarshal(tagsRaw, &tags) != nil || ownerID != record.Expectation.OwnerID || generation != record.Expectation.AccountGeneration ||
		accountID != record.Expectation.AccountID || region != record.Expectation.Region || instanceID != record.Expectation.InstanceID ||
		launchIdentity != record.Expectation.LaunchIdentity || roleARN != record.Expectation.RoleARN ||
		roleID != record.Expectation.RoleID || instanceProfileID != record.Expectation.InstanceProfileID ||
		!reflect.DeepEqual(tags, record.Expectation.RequiredTags) {
		return control.ErrIdentityRejected
	}
	var fenced int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_session_fences WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4`, record.Fence.ExecutionID, record.Fence.TaskID, record.Fence.Attempt, record.Fence.LeaseEpoch).Scan(&fenced); err != nil || fenced != 0 {
		return control.ErrStaleLease
	}
	expectationRaw, _ := json.Marshal(record.Expectation)
	inserted, err := tx.Exec(ctx, `INSERT INTO core_cloud_worker_identity_challenges(challenge_id,nonce_digest,execution_id,task_id,task_attempt,lease_epoch,account_generation,expectation_json,expires_at,consumed_at,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, record.ChallengeID, record.NonceDigest[:], record.Fence.ExecutionID,
		record.Fence.TaskID, record.Fence.Attempt, record.Fence.LeaseEpoch, record.Fence.AccountGeneration, expectationRaw,
		record.ExpiresAt.UTC(), nullableTimePG(record.ConsumedAt), record.CreatedAt.UTC())
	if err != nil || inserted.RowsAffected() != 1 {
		if err == nil {
			return control.ErrConflict
		}
		return control.ErrConflict
	}
	return tx.Commit(ctx)
}

func (s *CloudWorkerControlStore) GetChallenge(ctx context.Context, challengeID string) (control.ChallengeRecord, error) {
	if s == nil || s.store == nil || !coretask.ValidUUID(challengeID) {
		return control.ChallengeRecord{}, control.ErrInvalid
	}
	var record control.ChallengeRecord
	var nonce, expectationRaw []byte
	var consumed *time.Time
	err := s.store.pool.QueryRow(ctx, `SELECT challenge_id::text,nonce_digest,execution_id::text,task_id::text,task_attempt,lease_epoch,
		account_generation,expectation_json,expires_at,consumed_at,created_at FROM core_cloud_worker_identity_challenges WHERE challenge_id=$1`, challengeID).Scan(
		&record.ChallengeID, &nonce, &record.Fence.ExecutionID, &record.Fence.TaskID, &record.Fence.Attempt, &record.Fence.LeaseEpoch,
		&record.Fence.AccountGeneration, &expectationRaw, &record.ExpiresAt, &consumed, &record.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return record, control.ErrNotFound
	}
	if err != nil || len(nonce) != len(record.NonceDigest) || json.Unmarshal(expectationRaw, &record.Expectation) != nil {
		return control.ChallengeRecord{}, control.ErrConflict
	}
	copy(record.NonceDigest[:], nonce)
	record.ExpiresAt, record.CreatedAt = record.ExpiresAt.UTC(), record.CreatedAt.UTC()
	if consumed != nil {
		record.ConsumedAt = consumed.UTC()
	}
	return record, nil
}

func equalControlExpectation(left, right control.IdentityExpectation) bool {
	return left.OwnerID == right.OwnerID && left.AccountGeneration == right.AccountGeneration && left.AccountID == right.AccountID &&
		left.Region == right.Region && left.InstanceID == right.InstanceID && left.LaunchIdentity == right.LaunchIdentity &&
		left.RoleARN == right.RoleARN && left.RoleID == right.RoleID && left.InstanceProfileID == right.InstanceProfileID &&
		reflect.DeepEqual(left.RequiredTags, right.RequiredTags)
}

func equalControlClaims(expectation control.IdentityExpectation, claims control.IdentityClaims) bool {
	if expectation.AccountGeneration != claims.AccountGeneration || expectation.AccountID != claims.AccountID || expectation.Region != claims.Region ||
		expectation.InstanceID != claims.InstanceID || expectation.LaunchIdentity != claims.LaunchIdentity || expectation.RoleARN != claims.RoleARN ||
		expectation.RoleID != claims.RoleID || expectation.InstanceProfileID != claims.InstanceProfileID {
		return false
	}
	for key, value := range expectation.RequiredTags {
		if claims.Tags[key] != value {
			return false
		}
	}
	return true
}

func (s *CloudWorkerControlStore) Claim(ctx context.Context, mutation control.ClaimMutation) (control.Session, error) {
	if s == nil || s.store == nil || !coretask.ValidUUID(mutation.ChallengeID) || !coretask.ValidUUID(mutation.SessionID) || !validControlFence(mutation.Fence) || mutation.At.IsZero() {
		return control.Session{}, control.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return control.Session{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = lockControlFenceTx(ctx, tx, mutation.Fence, mutation.At); err != nil {
		return control.Session{}, err
	}
	var nonce, expectationRaw []byte
	var expires time.Time
	var consumed *time.Time
	if err = tx.QueryRow(ctx, `SELECT nonce_digest,expectation_json,expires_at,consumed_at FROM core_cloud_worker_identity_challenges
		WHERE challenge_id=$1 AND execution_id=$2 AND task_id=$3 AND task_attempt=$4 AND lease_epoch=$5 FOR UPDATE`, mutation.ChallengeID,
		mutation.Fence.ExecutionID, mutation.Fence.TaskID, mutation.Fence.Attempt, mutation.Fence.LeaseEpoch).Scan(&nonce, &expectationRaw, &expires, &consumed); err != nil {
		return control.Session{}, control.ErrNotFound
	}
	if consumed != nil {
		return control.Session{}, control.ErrChallengeConsumed
	}
	if !mutation.At.Before(expires.UTC()) {
		return control.Session{}, control.ErrChallengeExpired
	}
	if len(nonce) != len(mutation.NonceDigest) || subtle.ConstantTimeCompare(nonce, mutation.NonceDigest[:]) != 1 {
		return control.Session{}, control.ErrIdentityRejected
	}
	var expectation control.IdentityExpectation
	if json.Unmarshal(expectationRaw, &expectation) != nil || !equalControlClaims(expectation, mutation.Identity) {
		return control.Session{}, control.ErrIdentityRejected
	}
	var fenced int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_session_fences WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4`, mutation.Fence.ExecutionID, mutation.Fence.TaskID, mutation.Fence.Attempt, mutation.Fence.LeaseEpoch).Scan(&fenced); err != nil || fenced != 0 {
		return control.Session{}, control.ErrStaleLease
	}
	rows, err := tx.Query(ctx, `SELECT session_id::text,expectation_json,state,failure_code FROM core_cloud_worker_sessions
		WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4 FOR UPDATE`, mutation.Fence.ExecutionID,
		mutation.Fence.TaskID, mutation.Fence.Attempt, mutation.Fence.LeaseEpoch)
	if err != nil {
		return control.Session{}, err
	}
	var activeIDs []string
	for rows.Next() {
		var id, state, failure string
		var raw []byte
		if err = rows.Scan(&id, &raw, &state, &failure); err != nil {
			rows.Close()
			return control.Session{}, err
		}
		var oldExpectation control.IdentityExpectation
		if json.Unmarshal(raw, &oldExpectation) != nil || !equalControlExpectation(oldExpectation, expectation) {
			rows.Close()
			return control.Session{}, control.ErrIdentityRejected
		}
		switch state {
		case "active":
			activeIDs = append(activeIDs, id)
		case "completed":
			rows.Close()
			return control.Session{}, control.ErrTerminal
		case "failed":
			if failure != "session_superseded" {
				rows.Close()
				return control.Session{}, control.ErrTerminal
			}
		default:
			rows.Close()
			return control.Session{}, control.ErrConflict
		}
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return control.Session{}, err
	}
	rows.Close()
	for _, id := range activeIDs {
		updated, updateErr := tx.Exec(ctx, `UPDATE core_cloud_worker_sessions SET state='failed',failure_code='session_superseded',
			failure_summary='replaced by a fresh identity claim',finished_at=$2,revision=revision+1 WHERE session_id=$1 AND state='active'`, id, mutation.At.UTC())
		if updateErr != nil || updated.RowsAffected() != 1 {
			if updateErr != nil {
				return control.Session{}, updateErr
			}
			return control.Session{}, control.ErrConflict
		}
	}
	challengeUpdate, updateErr := tx.Exec(ctx, `UPDATE core_cloud_worker_identity_challenges SET consumed_at=$2
		WHERE challenge_id=$1 AND consumed_at IS NULL`, mutation.ChallengeID, mutation.At.UTC())
	if updateErr != nil || challengeUpdate.RowsAffected() != 1 {
		if updateErr != nil {
			return control.Session{}, updateErr
		}
		return control.Session{}, control.ErrChallengeConsumed
	}
	identityRaw, _ := json.Marshal(mutation.Identity)
	sessionInsert, insertErr := tx.Exec(ctx, `INSERT INTO core_cloud_worker_sessions(session_id,challenge_id,execution_id,task_id,task_attempt,lease_epoch,
		token_digest,expectation_json,identity_json,state,progress_sequence,revision,claimed_at,heartbeat_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,'active',0,1,$10,$10)`, mutation.SessionID, mutation.ChallengeID,
		mutation.Fence.ExecutionID, mutation.Fence.TaskID, mutation.Fence.Attempt, mutation.Fence.LeaseEpoch,
		mutation.TokenDigest[:], expectationRaw, identityRaw, mutation.At.UTC())
	if insertErr != nil || sessionInsert.RowsAffected() != 1 {
		return control.Session{}, control.ErrConflict
	}
	session := control.Session{SessionID: mutation.SessionID, Fence: mutation.Fence, Expectation: expectation,
		Identity: mutation.Identity, State: control.SessionActive, Revision: 1, ClaimedAt: mutation.At.UTC(), HeartbeatAt: mutation.At.UTC()}
	if err = tx.Commit(ctx); err != nil {
		return control.Session{}, err
	}
	return session, nil
}

func scanControlSession(row interface{ Scan(...any) error }) (control.Session, []byte, error) {
	var session control.Session
	var token, expectationRaw, identityRaw, resultRaw, topologyRaw, progressRaw []byte
	var topologyDigest *string
	var state string
	var finished *time.Time
	err := row.Scan(&session.SessionID, &session.Fence.ExecutionID, &session.Fence.TaskID, &session.Fence.Attempt,
		&session.Fence.LeaseEpoch, &session.Fence.AccountGeneration, &token, &expectationRaw, &identityRaw, &state,
		&session.ProgressSequence, &progressRaw, &resultRaw, &topologyRaw, &topologyDigest,
		&session.FailureCode, &session.FailureSummary, &session.Revision,
		&session.ClaimedAt, &session.HeartbeatAt, &finished)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return session, nil, control.ErrNotFound
		}
		return session, nil, err
	}
	if json.Unmarshal(expectationRaw, &session.Expectation) != nil || json.Unmarshal(identityRaw, &session.Identity) != nil {
		return control.Session{}, nil, control.ErrConflict
	}
	session.State = control.SessionState(state)
	if len(progressRaw) > 0 {
		var progress control.ProgressSnapshot
		if json.Unmarshal(progressRaw, &progress) != nil {
			return control.Session{}, nil, control.ErrConflict
		}
		session.LatestProgress = &progress
	}
	if len(resultRaw) > 0 {
		var claim control.ObjectClaim
		if json.Unmarshal(resultRaw, &claim) != nil {
			return control.Session{}, nil, control.ErrConflict
		}
		session.Result = &claim
	}
	if len(topologyRaw) > 0 {
		var proof execgate.Proof
		if json.Unmarshal(topologyRaw, &proof) != nil || proof.ValidateTerminal() != nil || topologyDigest == nil {
			return control.Session{}, nil, control.ErrConflict
		}
		digest, digestErr := proof.Digest()
		if digestErr != nil || digest != *topologyDigest {
			return control.Session{}, nil, control.ErrConflict
		}
		session.RuntimeTopology, session.TopologyDigest = &proof, digest
	} else if topologyDigest != nil {
		return control.Session{}, nil, control.ErrConflict
	}
	session.ClaimedAt, session.HeartbeatAt = session.ClaimedAt.UTC(), session.HeartbeatAt.UTC()
	if finished != nil {
		session.FinishedAt = finished.UTC()
	}
	return session, token, nil
}

const controlSessionSelect = `SELECT s.session_id::text,s.execution_id::text,s.task_id::text,s.task_attempt,s.lease_epoch,
e.account_generation,s.token_digest,s.expectation_json,s.identity_json,s.state,s.progress_sequence,s.latest_progress_json,
s.result_claim_json,
s.runtime_topology_json,s.runtime_topology_digest,
s.failure_code,s.failure_summary,s.revision,s.claimed_at,s.heartbeat_at,s.finished_at
FROM core_cloud_worker_sessions s JOIN core_cloud_worker_executions e ON e.execution_id=s.execution_id`

func (s *CloudWorkerControlStore) mutateSession(ctx context.Context, operation string, mutation control.SessionMutation) (control.Session, error) {
	if s == nil || s.store == nil || !coretask.ValidUUID(mutation.SessionID) || !coretask.ValidUUID(mutation.IdempotencyKey) ||
		!coretask.ValidDigest(mutation.RequestDigest) || !validControlFence(mutation.Fence) || mutation.At.IsZero() {
		return control.Session{}, control.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return control.Session{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = lockControlFenceTx(ctx, tx, mutation.Fence, mutation.At); err != nil {
		return control.Session{}, err
	}
	var executionOwner, executionState string
	var executionGeneration, executionRevision uint64
	err = tx.QueryRow(ctx, `SELECT owner_id,account_generation,state,revision
			FROM core_cloud_worker_executions WHERE execution_id=$1 AND task_id=$2 FOR UPDATE`,
		mutation.Fence.ExecutionID, mutation.Fence.TaskID).Scan(
		&executionOwner, &executionGeneration, &executionState, &executionRevision,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return control.Session{}, control.ErrStaleLease
	}
	if err != nil {
		return control.Session{}, err
	}
	if executionGeneration != mutation.Fence.AccountGeneration {
		return control.Session{}, control.ErrIdentityRejected
	}
	var replayDigest string
	var replayRaw []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,response_json FROM core_cloud_worker_session_replays WHERE operation=$1 AND session_id=$2 AND idempotency_key=$3 FOR UPDATE`, operation, mutation.SessionID, mutation.IdempotencyKey).Scan(&replayDigest, &replayRaw)
	if err == nil {
		if replayDigest != mutation.RequestDigest {
			return control.Session{}, control.ErrConflict
		}
		var replay control.Session
		if json.Unmarshal(replayRaw, &replay) != nil {
			return control.Session{}, control.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return control.Session{}, err
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return control.Session{}, err
	}
	session, token, err := scanControlSession(tx.QueryRow(ctx, controlSessionSelect+` WHERE s.session_id=$1 FOR UPDATE`, mutation.SessionID))
	if err != nil {
		return control.Session{}, err
	}
	if session.Fence != mutation.Fence || len(token) != len(mutation.TokenDigest) || subtle.ConstantTimeCompare(token, mutation.TokenDigest[:]) != 1 {
		return control.Session{}, control.ErrSessionRejected
	}
	if session.State != control.SessionActive {
		return control.Session{}, control.ErrTerminal
	}
	var fenced int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_session_fences WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4`, mutation.Fence.ExecutionID, mutation.Fence.TaskID, mutation.Fence.Attempt, mutation.Fence.LeaseEpoch).Scan(&fenced); err != nil || fenced != 0 {
		return control.Session{}, control.ErrStaleLease
	}
	if mutation.Progress == nil || mutation.ProgressSequence != session.ProgressSequence+1 ||
		control.ValidateProgressAdvance(session.LatestProgress, *mutation.Progress, session.ClaimedAt.UTC(), mutation.At.UTC()) != nil {
		return control.Session{}, control.ErrConflict
	}
	progress := *mutation.Progress
	var invocationCount uint64
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_model_invocations invocation
		JOIN core_cloud_worker_model_grants model_grant ON model_grant.grant_id=invocation.grant_id
		WHERE model_grant.session_id=$1`, session.SessionID).Scan(&invocationCount); err != nil {
		return control.Session{}, err
	}
	if invocationCount < progress.InvocationCount || invocationCount > control.MaximumProgressInvocationCount {
		return control.Session{}, control.ErrConflict
	}
	progress.InvocationCount = invocationCount
	if control.ValidateProgressAdvance(session.LatestProgress, progress, session.ClaimedAt.UTC(), mutation.At.UTC()) != nil {
		return control.Session{}, control.ErrConflict
	}
	session.ProgressSequence, session.HeartbeatAt, session.LatestProgress = mutation.ProgressSequence, mutation.At.UTC(), &progress
	switch operation {
	case "heartbeat":
	case "complete":
		if mutation.Claim == nil || mutation.RuntimeTopology == nil ||
			mutation.RuntimeTopology.ValidateTerminal() != nil ||
			!coretask.ValidDigest(mutation.TopologyDigest) {
			return control.Session{}, control.ErrInvalid
		}
		topologyDigest, digestErr := mutation.RuntimeTopology.Digest()
		if digestErr != nil || topologyDigest != mutation.TopologyDigest {
			return control.Session{}, control.ErrIdentityRejected
		}
		var bucket, prefix string
		var maximum int64
		if err = tx.QueryRow(ctx, `SELECT artifact_bucket,artifact_prefix,maximum_artifact_bytes FROM core_cloud_worker_launch_expectations
			WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4 FOR UPDATE`, mutation.Fence.ExecutionID,
			mutation.Fence.TaskID, mutation.Fence.Attempt, mutation.Fence.LeaseEpoch).Scan(&bucket, &prefix, &maximum); err != nil ||
			mutation.Claim.Bucket != bucket || !strings.HasPrefix(mutation.Claim.Key, prefix) || mutation.Claim.SizeBytes > maximum ||
			!coretask.ValidDigest(mutation.Claim.SHA256) || mutation.Claim.VersionID == "" {
			return control.Session{}, control.ErrIdentityRejected
		}
		claim := *mutation.Claim
		topology := *mutation.RuntimeTopology
		session.Result, session.RuntimeTopology, session.TopologyDigest = &claim, &topology, topologyDigest
		session.State, session.FinishedAt = control.SessionCompleted, mutation.At.UTC()
	case "fail":
		if mutation.FailureCode == "" || len(mutation.FailureCode) > 64 || len(mutation.FailureSummary) > 512 {
			return control.Session{}, control.ErrInvalid
		}
		session.State, session.FailureCode, session.FailureSummary, session.FinishedAt = control.SessionFailed, mutation.FailureCode, mutation.FailureSummary, mutation.At.UTC()
	default:
		return control.Session{}, control.ErrInvalid
	}
	session.Revision++
	resultRaw, _ := json.Marshal(session.Result)
	if session.Result == nil {
		resultRaw = nil
	}
	var topologyRaw []byte
	var storedTopologyDigest any
	if session.RuntimeTopology != nil {
		topologyRaw, _ = json.Marshal(session.RuntimeTopology)
		storedTopologyDigest = session.TopologyDigest
	}
	var progressRaw []byte
	if session.LatestProgress != nil {
		progressRaw, _ = json.Marshal(session.LatestProgress)
	}
	tag, err := tx.Exec(ctx, `UPDATE core_cloud_worker_sessions SET state=$2,progress_sequence=$3,latest_progress_json=$4,result_claim_json=$5,
		runtime_topology_json=$6,runtime_topology_digest=$7,failure_code=$8,failure_summary=$9,revision=$10,
		heartbeat_at=$11,finished_at=$12 WHERE session_id=$1 AND revision=$13 AND state='active'`,
		session.SessionID, session.State, session.ProgressSequence, progressRaw, resultRaw, topologyRaw, storedTopologyDigest,
		session.FailureCode, session.FailureSummary, session.Revision, session.HeartbeatAt,
		nullableTimePG(session.FinishedAt), session.Revision-1)
	if err != nil || tag.RowsAffected() != 1 {
		return control.Session{}, control.ErrConflict
	}
	replayRaw, _ = json.Marshal(session)
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_session_replays(operation,session_id,idempotency_key,request_digest,response_json) VALUES($1,$2,$3,$4,$5)`, operation, session.SessionID, mutation.IdempotencyKey, mutation.RequestDigest, replayRaw); err != nil {
		return control.Session{}, control.ErrConflict
	}
	if operation == "heartbeat" || operation == "complete" || operation == "fail" {
		progress := session.LatestProgress
		event := cloudworker.Event{
			OwnerID: executionOwner, AccountGeneration: executionGeneration,
			RunID: mutation.Fence.ExecutionID, ExecutionID: mutation.Fence.ExecutionID,
			EventID: deterministicCloudWorkerUUID("worker-progress", fmt.Sprintf("%s:%d", session.SessionID, mutation.ProgressSequence)),
			Type:    "worker_progress", State: cloudworker.ExecutionState(executionState), Revision: executionRevision,
			Progress: &cloudworker.WorkerProgress{
				Phase: string(progress.Phase), ElapsedMS: progress.ElapsedMS, LastActivityAt: progress.LastActivityAt,
				CPUTimeMS: progress.CPUTimeMS, MemoryHighWaterBytes: progress.MemoryHighWaterBytes,
				InvocationCount: progress.InvocationCount, UploadedBytes: progress.UploadedBytes,
				OutputTruncated: progress.OutputTruncated,
			}, CreatedAt: mutation.At.UTC(),
		}
		event.PayloadDigest = digestCloudWorkerValue(struct {
			SessionID string
			Sequence  uint64
			Progress  cloudworker.WorkerProgress
		}{session.SessionID, mutation.ProgressSequence, *event.Progress})
		if err = appendCloudWorkerEventTx(ctx, tx, &event, session.SessionID, mutation.ProgressSequence); err != nil {
			return control.Session{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return control.Session{}, err
	}
	return session, nil
}

func (s *CloudWorkerControlStore) Heartbeat(ctx context.Context, mutation control.SessionMutation) (control.Session, error) {
	return s.mutateSession(ctx, "heartbeat", mutation)
}
func (s *CloudWorkerControlStore) Complete(ctx context.Context, mutation control.SessionMutation) (control.Session, error) {
	return s.mutateSession(ctx, "complete", mutation)
}
func (s *CloudWorkerControlStore) Fail(ctx context.Context, mutation control.SessionMutation) (control.Session, error) {
	return s.mutateSession(ctx, "fail", mutation)
}

func (s *CloudWorkerControlStore) GetSession(ctx context.Context, sessionID string) (control.Session, error) {
	if s == nil || s.store == nil || !coretask.ValidUUID(sessionID) {
		return control.Session{}, control.ErrInvalid
	}
	session, _, err := scanControlSession(s.store.pool.QueryRow(ctx, controlSessionSelect+` WHERE s.session_id=$1`, sessionID))
	return session, err
}

func (s *CloudWorkerControlStore) FindSessionByFence(ctx context.Context, fence control.TaskFence) (control.Session, error) {
	if s == nil || s.store == nil || !validControlFence(fence) {
		return control.Session{}, control.ErrInvalid
	}
	session, _, err := scanControlSession(s.store.pool.QueryRow(ctx, controlSessionSelect+` WHERE s.execution_id=$1 AND s.task_id=$2 AND s.task_attempt=$3 AND s.lease_epoch=$4 ORDER BY (s.state='active') DESC,s.claimed_at DESC,s.revision DESC,s.session_id DESC LIMIT 1`, fence.ExecutionID, fence.TaskID, fence.Attempt, fence.LeaseEpoch))
	if err == nil && session.Fence.AccountGeneration != fence.AccountGeneration {
		return control.Session{}, control.ErrIdentityRejected
	}
	return session, err
}

func (s *CloudWorkerControlStore) FindLatestSessionByExecution(ctx context.Context, executionID, taskID string, accountGeneration uint64) (control.Session, error) {
	if s == nil || s.store == nil || !coretask.ValidUUID(executionID) || !coretask.ValidUUID(taskID) || accountGeneration == 0 {
		return control.Session{}, control.ErrInvalid
	}
	session, _, err := scanControlSession(s.store.pool.QueryRow(ctx, controlSessionSelect+` WHERE s.execution_id=$1 AND s.task_id=$2 AND e.account_generation=$3 ORDER BY s.claimed_at DESC,s.revision DESC,s.session_id DESC LIMIT 1`, executionID, taskID, accountGeneration))
	return session, err
}

func (s *CloudWorkerControlStore) FenceSession(ctx context.Context, mutation control.SessionFenceMutation) (control.Session, error) {
	if s == nil || s.store == nil || !validControlFence(mutation.Fence) || mutation.At.IsZero() || strings.TrimSpace(mutation.Reason) == "" || len(mutation.Reason) > 512 {
		return control.Session{}, control.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return control.Session{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = lockControlFenceTx(ctx, tx, mutation.Fence, mutation.At); err != nil {
		return control.Session{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_session_fences(execution_id,task_id,task_attempt,lease_epoch,fenced_at,reason)
		VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`, mutation.Fence.ExecutionID, mutation.Fence.TaskID,
		mutation.Fence.Attempt, mutation.Fence.LeaseEpoch, mutation.At.UTC(), strings.TrimSpace(mutation.Reason)); err != nil {
		return control.Session{}, err
	}
	session, _, err := scanControlSession(tx.QueryRow(ctx, controlSessionSelect+` WHERE s.execution_id=$1 AND s.task_id=$2 AND s.task_attempt=$3 AND s.lease_epoch=$4 ORDER BY (s.state='active') DESC,s.claimed_at DESC LIMIT 1 FOR UPDATE`, mutation.Fence.ExecutionID, mutation.Fence.TaskID, mutation.Fence.Attempt, mutation.Fence.LeaseEpoch))
	if err != nil {
		return control.Session{}, err
	}
	if session.State == control.SessionActive {
		session.State, session.FailureCode, session.FailureSummary = control.SessionFailed, "session_fenced", strings.TrimSpace(mutation.Reason)
		session.FinishedAt, session.Revision = mutation.At.UTC(), session.Revision+1
		updated, updateErr := tx.Exec(ctx, `UPDATE core_cloud_worker_sessions SET state='failed',failure_code='session_fenced',
			failure_summary=$2,finished_at=$3,revision=revision+1 WHERE session_id=$1 AND state='active'`,
			session.SessionID, session.FailureSummary, session.FinishedAt)
		if updateErr != nil || updated.RowsAffected() != 1 {
			if updateErr != nil {
				return control.Session{}, updateErr
			}
			return control.Session{}, control.ErrConflict
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return control.Session{}, err
	}
	return session, nil
}

func (s *CloudWorkerControlStore) FenceExecutionSessions(ctx context.Context, supplied coretask.Task, executionID, reason string) (control.Session, error) {
	if s == nil || s.store == nil || strings.TrimSpace(reason) == "" || len(reason) > 512 {
		return control.Session{}, control.ErrInvalid
	}
	fence, err := controlFenceForTask(supplied, executionID)
	if err != nil {
		return control.Session{}, err
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return control.Session{}, err
	}
	defer tx.Rollback(ctx)
	currentTask, err := lockControlFenceTx(ctx, tx, fence, now)
	if err != nil || validateCloudWorkerTaskFence(currentTask, supplied, now) != nil {
		return control.Session{}, control.ErrStaleLease
	}
	// Fence every published launch expectation, including a current expectation
	// owned by a previous CoreTask lease. A controller may reclaim an execution
	// after the runtime deadline but before it can publish a replacement
	// expectation; terminal cleanup must still revoke that Worker authority.
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_session_fences(execution_id,task_id,task_attempt,lease_epoch,fenced_at,reason)
		SELECT execution_id,task_id,task_attempt,lease_epoch,$2,$3 FROM core_cloud_worker_launch_expectations WHERE execution_id=$1
		ON CONFLICT DO NOTHING`, executionID, now, strings.TrimSpace(reason)); err != nil {
		return control.Session{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_cloud_worker_sessions SET state='failed',failure_code='session_fenced',failure_summary=$2,
		finished_at=$3,revision=revision+1 WHERE execution_id=$1 AND state='active'`, executionID, strings.TrimSpace(reason), now); err != nil {
		return control.Session{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_cloud_worker_model_grants SET state='fenced',reason_code='session_fenced',fenced_at=$2,
		updated_at=$2,revision=revision+1 WHERE execution_id=$1 AND state='active'`, executionID, now); err != nil {
		return control.Session{}, err
	}
	var unfencedSessions, activeSessions, activeGrants int
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_sessions s
		WHERE s.execution_id=$1 AND NOT EXISTS (
			SELECT 1 FROM core_cloud_worker_session_fences f WHERE f.execution_id=s.execution_id AND f.task_id=s.task_id
			AND f.task_attempt=s.task_attempt AND f.lease_epoch=s.lease_epoch)`, executionID).Scan(&unfencedSessions); err != nil {
		return control.Session{}, err
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_sessions WHERE execution_id=$1 AND state='active'`, executionID).Scan(&activeSessions); err != nil {
		return control.Session{}, err
	}
	if err = tx.QueryRow(ctx, `SELECT count(*) FROM core_cloud_worker_model_grants WHERE execution_id=$1 AND state='active'`, executionID).Scan(&activeGrants); err != nil {
		return control.Session{}, err
	}
	if unfencedSessions != 0 || activeSessions != 0 || activeGrants != 0 {
		return control.Session{}, control.ErrConflict
	}
	latest, _, latestErr := scanControlSession(tx.QueryRow(ctx, controlSessionSelect+` WHERE s.execution_id=$1 ORDER BY s.claimed_at DESC,s.revision DESC,s.session_id DESC LIMIT 1`, executionID))
	if latestErr != nil && !errors.Is(latestErr, control.ErrNotFound) {
		return control.Session{}, latestErr
	}
	if err = tx.Commit(ctx); err != nil {
		return control.Session{}, err
	}
	return latest, nil
}

var _ control.Store = (*CloudWorkerControlStore)(nil)
