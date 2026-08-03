package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTeamWorkerInputPostgresIsImmutableScopedAndRestartable(
	t *testing.T,
) {
	pool, store, instanceID := newTeamInputTestStore(t)
	ctx, cancel := context.WithTimeout(
		context.Background(),
		45*time.Second,
	)
	defer cancel()
	scope := task.MutationScope{
		ClientID:     "team-input-integration",
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
	const contextCanary = "transient-team-context-canary-49"
	key := uuid.NewString()
	command := teamInputPersistCommand(
		t,
		execution,
		key,
		contextCanary,
	)
	request := teaminput.MaterializeRequest{
		IdempotencyKey: key,
		OwnerID:        execution.Execution.OwnerID,
		ExecutionID:    execution.Execution.ExecutionID,
		RoleID:         execution.Execution.Roles[0].RoleID,
	}
	if fact, found, err := store.FindMaterializedInput(
		ctx,
		scope,
		request,
	); err != nil || found || fact.Materialization.InputID != "" {
		t.Fatalf(
			"fresh Team Worker input lookup=%#v found=%v error=%v",
			fact,
			found,
			err,
		)
	}
	first, err := store.PersistMaterializedInput(ctx, scope, command)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != teaminput.StatusMaterialized ||
		first.RecordRevision != 1 ||
		first.Materialization.InputID !=
			command.Materialization.InputID {
		t.Fatalf("materialized Team Worker input=%#v", first)
	}
	replayed, err := store.PersistMaterializedInput(ctx, scope, command)
	if err != nil || !reflect.DeepEqual(replayed, first) {
		t.Fatalf("same-key replay=%#v error=%v", replayed, err)
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	readBack, found, err := restarted.FindMaterializedInput(
		ctx,
		scope,
		request,
	)
	if err != nil || !found || !reflect.DeepEqual(readBack, first) {
		t.Fatalf(
			"restarted replay=%#v found=%v error=%v",
			readBack,
			found,
			err,
		)
	}
	anotherRequest := request
	anotherRequest.IdempotencyKey = uuid.NewString()
	converged, found, err := restarted.FindMaterializedInput(
		ctx,
		scope,
		anotherRequest,
	)
	if err != nil || !found || !reflect.DeepEqual(converged, first) {
		t.Fatalf(
			"cross-key convergence=%#v found=%v error=%v",
			converged,
			found,
			err,
		)
	}
	otherScope := task.MutationScope{
		ClientID:     scope.ClientID,
		CredentialID: uuid.NewString(),
	}
	scoped, found, err := restarted.FindMaterializedInput(
		ctx,
		otherScope,
		request,
	)
	if err != nil || !found || !reflect.DeepEqual(scoped, first) {
		t.Fatalf(
			"cross-credential convergence=%#v found=%v error=%v",
			scoped,
			found,
			err,
		)
	}
	conflictingRequest := request
	conflictingRequest.ExecutionID = uuid.NewString()
	if _, _, err := restarted.FindMaterializedInput(
		ctx,
		scope,
		conflictingRequest,
	); !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("identity request-digest conflict error=%v", err)
	}
	drifted := teamInputPersistCommand(
		t,
		execution,
		key,
		"different transient Team context",
	)
	if _, err := restarted.PersistMaterializedInput(
		ctx,
		scope,
		drifted,
	); !errors.Is(err, idempotency.ErrConflict) {
		t.Fatalf("same-key payload drift error=%v", err)
	}

	malicious := command
	malicious.IdempotencyKey = uuid.NewString()
	var bundle map[string]any
	if err := json.Unmarshal(
		malicious.ExecutionBundleJSON,
		&bundle,
	); err != nil {
		t.Fatal(err)
	}
	bundle["api_key"] = "sk-secret-canary-not-for-postgres"
	malicious.ExecutionBundleJSON, err = json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(malicious.ExecutionBundleJSON)
	malicious.Materialization.ExecutionBundleDigest =
		"sha256:" + hex.EncodeToString(digest[:])
	if malicious.Validate() != nil {
		t.Fatal("secret canary command must reach the repository guard")
	}
	if _, err := restarted.PersistMaterializedInput(
		ctx,
		scope,
		malicious,
	); !errors.Is(err, teaminput.ErrInvalid) {
		t.Fatalf("credential material persistence error=%v", err)
	}

	var contextColumnCount, leakedCanaryCount, replayCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema=current_schema()
		  AND table_name='team_worker_inputs'
		  AND column_name='context_bytes'`,
	).Scan(&contextColumnCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM team_worker_inputs
		WHERE materialization_json::text LIKE '%' || $1 || '%'
		   OR manifest_json::text LIKE '%' || $1 || '%'
		   OR convert_from(manifest_raw, 'UTF8') LIKE '%' || $1 || '%'
		   OR execution_bundle_json::text LIKE '%' || $1 || '%'
		   OR convert_from(
		          execution_bundle_raw,
		          'UTF8'
		      ) LIKE '%' || $1 || '%'`,
		contextCanary,
	).Scan(&leakedCanaryCount); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM idempotency_records
		WHERE operation='team.worker_input.materialize'
		  AND caller_client_id=$1
		  AND caller_credential_id=$2
		  AND idempotency_key=$3
		  AND octet_length(request_hash)=32`,
		scope.ClientID,
		scope.CredentialID,
		key,
	).Scan(&replayCount); err != nil {
		t.Fatal(err)
	}
	if contextColumnCount != 0 ||
		leakedCanaryCount != 0 ||
		replayCount != 1 {
		t.Fatalf(
			"context columns=%d leaked=%d replay rows=%d",
			contextColumnCount,
			leakedCanaryCount,
			replayCount,
		)
	}

	if _, err := pool.Exec(ctx, `
		UPDATE team_worker_inputs
		SET execution_bundle_digest=$2
		WHERE input_id=$1`,
		first.Materialization.InputID,
		"sha256:"+strings.Repeat("f", 64),
	); err == nil ||
		!strings.Contains(
			err.Error(),
			"materialized Team Worker input fields are immutable",
		) {
		t.Fatalf("immutable digest update error=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		DELETE FROM team_worker_inputs WHERE input_id=$1`,
		first.Materialization.InputID,
	); err == nil ||
		!strings.Contains(err.Error(), "team_worker_inputs cannot be deleted") {
		t.Fatalf("immutable input delete error=%v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO team_worker_inputs (
		    input_id, agent_instance_id, owner_id,
		    execution_id, execution_digest, role_id, role_digest,
		    task_id, task_step_id, deployment_id, expected_worker_id,
		    context_snapshot_id, context_digest,
		    workspace_snapshot_id, workspace_digest,
		    manifest_digest, runtime_task_digest,
		    execution_bundle_digest, credential_grant_digest,
		    materialization_json, manifest_json, manifest_raw,
		    execution_bundle_json, execution_bundle_raw,
		    status, record_revision
		)
		SELECT
		    $2::uuid, agent_instance_id, owner_id,
		    execution_id, execution_digest, 'review', role_digest,
		    task_id, task_step_id, deployment_id, expected_worker_id,
		    context_snapshot_id, context_digest,
		    workspace_snapshot_id, workspace_digest,
		    manifest_digest, runtime_task_digest,
		    execution_bundle_digest, credential_grant_digest,
		    jsonb_set(
		        jsonb_set(
		            materialization_json,
		            '{input_id}',
		            to_jsonb(($2::uuid)::text)
		        ),
		        '{role_id}',
		        '"review"'::jsonb
		    ),
		    manifest_json, manifest_raw,
		    execution_bundle_json, execution_bundle_raw,
		    status, record_revision
		FROM team_worker_inputs
		WHERE input_id=$1`,
		first.Materialization.InputID,
		uuid.NewString(),
	); err == nil ||
		!strings.Contains(
			err.Error(),
			"Team Worker input JSON does not match its immutable columns",
		) {
		t.Fatalf("unbound role insert error=%v", err)
	}
}

func newTeamInputTestStore(
	t *testing.T,
) (*pgxpool.Pool, *postgres.Store, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN to run PostgreSQL integration tests")
	}
	adminConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal("AGENT_TEST_POSTGRES_DSN is invalid")
	}
	adminConfig.MaxConns = 2
	ctx, cancel := context.WithTimeout(
		context.Background(),
		20*time.Second,
	)
	defer cancel()
	adminPool, err := pgxpool.NewWithConfig(ctx, adminConfig)
	if err != nil {
		t.Fatalf("open PostgreSQL administration pool failed (%T)", err)
	}
	schema := "dtx_team_input_" +
		strings.ReplaceAll(uuid.NewString(), "-", "")
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(
		ctx,
		"CREATE SCHEMA "+quotedSchema,
	); err != nil {
		adminPool.Close()
		t.Fatalf("create isolated PostgreSQL schema failed (%T)", err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		adminPool.Close()
		t.Fatal("AGENT_TEST_POSTGRES_DSN is invalid")
	}
	if config.ConnConfig.RuntimeParams == nil {
		config.ConnConfig.RuntimeParams = make(map[string]string)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	config.ConnConfig.RuntimeParams["application_name"] =
		"dirextalk-agent-team-input-test"
	config.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		adminPool.Close()
		t.Fatalf("open isolated PostgreSQL pool failed (%T)", err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanupContext, cleanupCancel := context.WithTimeout(
			context.Background(),
			10*time.Second,
		)
		defer cleanupCancel()
		if _, cleanupErr := adminPool.Exec(
			cleanupContext,
			"DROP SCHEMA "+quotedSchema+" CASCADE",
		); cleanupErr != nil {
			t.Errorf(
				"drop isolated PostgreSQL schema failed (%T)",
				cleanupErr,
			)
		}
		adminPool.Close()
	})
	instanceID := uuid.NewString()
	if err := postgres.ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("apply Agent migrations failed: %v", err)
	}
	store, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatalf("construct PostgreSQL store failed (%T)", err)
	}
	return pool, store, instanceID
}

func createDispatchingTeamInputExecution(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	store *postgres.Store,
	instanceID string,
	scope task.MutationScope,
) teamexecution.Fact {
	return createDispatchingTeamInputExecutionWithRuntime(
		t,
		ctx,
		pool,
		store,
		instanceID,
		scope,
		teamplan.RuntimeCodex,
		teamplan.AdapterCodexV1,
		"1.0.0",
	)
}

func createDispatchingPiTeamInputExecution(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	store *postgres.Store,
	instanceID string,
	scope task.MutationScope,
) teamexecution.Fact {
	return createDispatchingTeamInputExecutionWithRuntime(
		t,
		ctx,
		pool,
		store,
		instanceID,
		scope,
		teamplan.RuntimePi,
		teamplan.AdapterPiV1,
		"0.83.0",
	)
}

func createDispatchingTeamInputExecutionWithRuntime(
	t *testing.T,
	ctx context.Context,
	pool *pgxpool.Pool,
	store *postgres.Store,
	instanceID string,
	scope task.MutationScope,
	runtimeFamily teamplan.RuntimeFamily,
	runtimeAdapter teamplan.RuntimeAdapter,
	runtimeVersion string,
) teamexecution.Fact {
	t.Helper()
	ownerID := "owner-team-input"
	connectionID := uuid.NewString()
	if _, err := pool.Exec(ctx, `
		INSERT INTO cloud_connections
		    (connection_id, agent_instance_id, owner_id, account_id, region,
		     control_role_arn, foundation_stack_id, credential_generation,
		     status, revision)
		VALUES ($1,$2,$3,'123456789012','us-east-1',
		        'arn:aws:iam::123456789012:role/test-control',
		        'test-foundation-stack',1,'active',1)`,
		connectionID,
		instanceID,
		ownerID,
	); err != nil {
		t.Fatal(err)
	}
	goal := "Materialize one immutable Worker input."
	createdTask, err := store.Create(
		ctx,
		scope,
		task.CreateCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Goal:           goal,
			Retention:      task.RetentionEphemeralAutoDestroy,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	snapshot := teamOfferSnapshotFixture(
		t,
		connectionID,
		now.Add(-time.Minute),
	)
	if _, err := store.CreateTeamOfferSnapshot(
		ctx,
		scope,
		postgres.CreateTeamOfferSnapshotCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			Snapshot:       snapshot,
		},
	); err != nil {
		t.Fatal(err)
	}
	plan := teamPlanFixture(
		t,
		snapshot,
		ownerID,
		goal,
		uuid.NewString(),
		1,
	)
	plan.Assignments[0].RuntimeFamily = runtimeFamily
	plan.Assignments[0].RuntimeAdapter = runtimeAdapter
	plan.Assignments[0].RuntimeVersion = runtimeVersion
	planRecord, err := store.CreateTeamPlan(
		ctx,
		scope,
		postgres.CreateTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			TaskID:         createdTask.TaskID,
			Plan:           plan,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("Team input approval device"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	signerKeyID := "team-input-device-1"
	if _, err := store.RegisterApprovalDevice(
		ctx,
		scope,
		postgres.RegisterApprovalDeviceCommand{
			IdempotencyKey: uuid.NewString(),
			Device: cloudapproval.DeviceKeyV1{
				KeyID:           signerKeyID,
				AgentInstanceID: instanceID,
				OwnerID:         ownerID,
				Revision:        1,
				Status:          cloudapproval.DeviceKeyActive,
				PublicKey:       privateKey.Public().(ed25519.PublicKey),
				NotBefore:       now.Add(-time.Hour),
				ExpiresAt:       now.Add(time.Hour),
			},
		},
	); err != nil {
		t.Fatal(err)
	}
	approvalID, launchAuthorization :=
		newTeamLaunchAuthorizationFixture(t, plan, instanceID)
	challenge, err := store.CreateTeamApprovalChallenge(
		ctx,
		scope,
		postgres.CreateTeamApprovalChallengeCommand{
			IdempotencyKey:             uuid.NewString(),
			OwnerID:                    ownerID,
			PlanID:                     plan.PlanID,
			PlanRevision:               plan.Revision,
			ExpectedPlanRecordRevision: planRecord.RecordRevision,
			ApprovalID:                 approvalID,
			ChallengeID:                uuid.NewString(),
			SignerKeyID:                signerKeyID,
			Authorization:              launchAuthorization,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	approvedPlan, err := store.ApproveTeamPlan(
		ctx,
		scope,
		postgres.ApproveTeamPlanCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			ExpectedPlanRecordRevision: planRecord.
				RecordRevision,
			ExpectedChallengeRecordRevision: challenge.
				RecordRevision,
			Signature: signTeamApproval(
				t,
				challenge.Challenge,
				privateKey,
			),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := store.GetTeamApprovalForPlan(
		ctx,
		ownerID,
		plan.PlanID,
		plan.Revision,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization := teamorchestration.ApprovedPlanFact{
		Plan: teamorchestration.PlanFact{
			TaskID:         approvedPlan.TaskID,
			Plan:           approvedPlan.Plan,
			PlanDigest:     approvedPlan.PlanDigest,
			Status:         teamorchestration.PlanApproved,
			RecordRevision: approvedPlan.RecordRevision,
			CreatedAt:      approvedPlan.CreatedAt,
			UpdatedAt:      approvedPlan.UpdatedAt,
		},
		Approval: teamorchestration.ApprovalFact{
			Signature:     approval.Signature,
			Authorization: approval.Authorization,
			ApprovedAt:    approval.ApprovedAt,
			CreatedAt:     approval.CreatedAt,
		},
	}
	execution, err := teamexecution.Materialize(authorization)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.PersistExecution(
		ctx,
		scope,
		teamexecution.PersistCommand{
			IdempotencyKey: uuid.NewString(),
			Authorization:  authorization,
			Execution:      execution,
		},
	); err != nil {
		t.Fatal(err)
	}
	dispatched, err := store.BeginDispatch(
		ctx,
		scope,
		teamexecution.BeginDispatchCommand{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        ownerID,
			ExecutionID:    execution.ExecutionID,
			Authorization:  &authorization,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return dispatched
}

func teamInputPersistCommand(
	t *testing.T,
	execution teamexecution.Fact,
	key,
	goalSummary string,
) teaminput.PersistCommand {
	t.Helper()
	role := execution.Execution.Roles[0]
	contextSnapshotID, err := teaminput.ContextSnapshotID(
		execution.Execution.ExecutionID,
		role.RoleID,
	)
	if err != nil {
		t.Fatal(err)
	}
	workspaceSnapshotID, err := teaminput.WorkspaceSnapshotID(
		execution.Execution.ExecutionID,
		role.RoleID,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := teaminput.Compile(teaminput.CompileRequest{
		Execution:       execution.Execution,
		ExecutionDigest: execution.ExecutionDigest,
		RoleID:          role.RoleID,
		Context: teaminput.ContextInput{
			SnapshotID:  contextSnapshotID,
			GoalDigest:  execution.Execution.GoalDigest,
			GoalSummary: goalSummary,
		},
		Workspace: teaminput.WorkspaceSnapshot{
			SnapshotID: workspaceSnapshotID,
			Digest:     "sha256:" + strings.Repeat("c", 64),
			SizeBytes:  10 << 20,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer compiled.Destroy()
	inputID, err := teaminput.InputID(
		execution.Execution.ExecutionID,
		role.RoleID,
	)
	if err != nil {
		t.Fatal(err)
	}
	roleDigest, err := role.Digest()
	if err != nil {
		t.Fatal(err)
	}
	materialization := teaminput.MaterializationV1{
		SchemaVersion:         teaminput.MaterializationSchemaV1,
		InputID:               inputID,
		OwnerID:               execution.Execution.OwnerID,
		ExecutionID:           execution.Execution.ExecutionID,
		ExecutionDigest:       execution.ExecutionDigest,
		RoleID:                role.RoleID,
		RoleDigest:            roleDigest,
		TaskID:                execution.Execution.TaskID,
		TaskStepID:            role.TaskStepID,
		DeploymentID:          role.DeploymentID,
		ExpectedWorkerID:      role.ExpectedWorkerID,
		ContextSnapshotID:     compiled.Manifest.ContextSnapshotID,
		ContextDigest:         compiled.Manifest.ContextDigest,
		WorkspaceSnapshotID:   compiled.Manifest.WorkspaceSnapshotID,
		WorkspaceDigest:       compiled.Manifest.WorkspaceDigest,
		Manifest:              compiled.Manifest,
		ManifestDigest:        compiled.ManifestDigest,
		RuntimeTask:           compiled.RuntimeTask,
		RuntimeTaskDigest:     compiled.Manifest.RuntimeTaskDigest,
		ExecutionBundleDigest: compiled.ExecutionBundleDigest,
		CredentialGrant:       compiled.CredentialGrant,
		CredentialGrantDigest: compiled.CredentialGrantDigest,
		ContextTargetPath:     compiled.ContextTargetPath,
		WorkspaceTargetPath:   compiled.WorkspaceTargetPath,
		CredentialTargetPath:  compiled.CredentialTargetPath,
	}
	command := teaminput.PersistCommand{
		IdempotencyKey:      key,
		Materialization:     materialization,
		ManifestJSON:        bytes.Clone(compiled.ManifestBytes),
		ExecutionBundleJSON: bytes.Clone(compiled.ExecutionBytes),
	}
	if command.Validate() != nil {
		t.Fatal("Team Worker input command fixture is invalid")
	}
	return command
}
