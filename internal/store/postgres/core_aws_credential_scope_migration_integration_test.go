package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreknowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/migrations"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoreAWSCredentialScopeMigrationBackfillsExistingRows(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for Core AWS PostgreSQL migration integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "dtx_agent_aws_scope_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if _, dropErr := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); dropErr != nil {
			t.Errorf("drop isolated schema: %v", dropErr)
		}
	}()

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err = pool.Exec(ctx, `CREATE TABLE agent_schema_migrations (
		version bigint PRIMARY KEY,
		checksum bytea NOT NULL CHECK (octet_length(checksum)=32),
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
	)`); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations.Ordered()[:3] {
		if _, err = pool.Exec(ctx, string(migration.Script)); err != nil {
			t.Fatalf("apply legacy migration %d: %v", migration.Version, err)
		}
		checksum := sha256.Sum256(migration.Script)
		if _, err = pool.Exec(ctx, `INSERT INTO agent_schema_migrations(version,checksum) VALUES($1,$2)`, migration.Version, checksum[:]); err != nil {
			t.Fatal(err)
		}
	}
	instanceID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_instance_metadata(agent_instance_id) VALUES($1)`, instanceID); err != nil {
		t.Fatal(err)
	}
	credentialID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_credentials(
		credential_id,name,region,secret_key_version,
		access_key_id_nonce,access_key_id_ciphertext,
		secret_access_key_nonce,secret_access_key_ciphertext,
		session_token_nonce,session_token_ciphertext,
		revision,created_at,updated_at
	) VALUES($1,'legacy','ap-northeast-3',1,
		decode(repeat('01',12),'hex'),decode(repeat('02',16),'hex'),
		decode(repeat('03',12),'hex'),decode(repeat('04',16),'hex'),
		decode(repeat('05',12),'hex'),decode(repeat('06',16),'hex'),
		1,clock_timestamp(),clock_timestamp())`, credentialID); err != nil {
		t.Fatal(err)
	}
	legacyCredentialTestKey := uuid.NewString()
	legacyCredentialTestLease := time.Now().UTC().Truncate(time.Microsecond).Add(time.Minute)
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_credential_test_claims(
		idempotency_key,claim_id,credential_id,expected_revision,request_hash,state,lease_expires_at,completion_grace_until
	) VALUES($1,$2,$3,1,$4,'in_progress',$5,$6)`, legacyCredentialTestKey, uuid.NewString(), credentialID, coreaws.CredentialTestBindingDigest(credentialID, 1), legacyCredentialTestLease, legacyCredentialTestLease.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	ownerScope := coreteam.Scope{OwnerID: "@migrated-owner:example.test", AccountGeneration: 7}
	ownedCredentialID := uuid.NewString()
	keyring := testSecretKeyring(t)
	preMigrationStore, err := New(pool, instanceID, keyring)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	profileID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_model_profiles(profile_id,display_name,provider,base_url,model_name,created_at,updated_at) VALUES($1,'legacy task profile','openai_compatible','https://example.test','legacy-model',$2,$2)`, profileID, now); err != nil {
		t.Fatal(err)
	}
	legacyScheduleKey, legacyScheduleID := uuid.NewString(), uuid.NewString()
	runAt := now.Add(time.Hour)
	legacySchedule := coretask.Schedule{
		ID: legacyScheduleID, Name: "legacy public schedule",
		Spec:  coretask.TaskTemplate{Goal: "legacy scheduled task", ModelProfileID: profileID},
		RunAt: &runAt, NextRunAt: runAt, Timezone: "UTC",
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	legacySchedule, err = legacySchedule.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	legacyScheduleTemplate, _ := json.Marshal(legacySchedule.Spec)
	if _, err = pool.Exec(ctx, `INSERT INTO core_schedules(schedule_id,name,task_template,run_at,timezone,paused,next_run_at,revision,created_at,updated_at) VALUES($1,$2,$3,$4,'UTC',false,$4,1,$5,$5)`, legacyScheduleID, legacySchedule.Name, legacyScheduleTemplate, runAt, now); err != nil {
		t.Fatal(err)
	}
	legacyScheduleDigest := strings.Repeat("8", 64)
	legacyScheduleReplay, _ := json.Marshal(legacySchedule)
	if _, err = pool.Exec(ctx, `INSERT INTO core_schedule_replays(operation,idempotency_key,schedule_id,request_hash,response_json) VALUES('create',$1,$2,$3,$4)`, legacyScheduleKey, legacyScheduleID, legacyScheduleDigest, legacyScheduleReplay); err != nil {
		t.Fatal(err)
	}
	legacyScheduleResult, _ := json.Marshal(map[string]any{"schedule": map[string]any{"id": legacyScheduleID}})
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.schedules.v1','create_schedule','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), legacyScheduleResult, ownerScope.OwnerID, ownerScope.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}

	legacyMemoryKey := uuid.NewString()
	legacyMemoryID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("memory:"+legacyMemoryKey)).String()
	legacyMemoryContent := "legacy memory content"
	legacyMemorySHA := sha256.Sum256([]byte(legacyMemoryContent))
	legacyMemoryCommand := coreknowledge.MemoryCommand{IdempotencyKey: legacyMemoryKey, SourceID: legacyMemoryID, Title: "legacy public memory", Content: legacyMemoryContent, ContentSHA256: fmt.Sprintf("%x", legacyMemorySHA), MediaType: "text/plain"}
	legacyMemoryDigest := knowledgeDigest(legacyMemoryCommand)
	legacyMemoryRef := "legacy-memory-" + legacyMemoryID
	legacyMemorySource := coreknowledge.Source{
		ID: legacyMemoryID, Kind: coreknowledge.SourceKindMemory, Status: coreknowledge.SourceStatusReady,
		Title: legacyMemoryCommand.Title, Digest: fmt.Sprintf("%x", legacyMemorySHA), SizeBytes: int64(len(legacyMemoryCommand.Content)),
		MediaType: legacyMemoryCommand.MediaType, Revision: 1, CreatedAt: now, UpdatedAt: now, ContentRef: legacyMemoryRef,
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,content_ref,created_at,updated_at) VALUES($1,'memory','ready',$2,$3,$4,$5,1,$6,$7,$7)`, legacyMemoryID, legacyMemorySource.Title, legacyMemorySource.Digest, legacyMemorySource.SizeBytes, legacyMemorySource.MediaType, legacyMemoryRef, now); err != nil {
		t.Fatal(err)
	}
	legacyMemoryReplay, _ := json.Marshal(knowledgeReplay{Source: legacyMemorySource})
	if _, err = pool.Exec(ctx, `INSERT INTO core_knowledge_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES('memory',$1,$2,$3)`, legacyMemoryKey, legacyMemoryDigest, legacyMemoryReplay); err != nil {
		t.Fatal(err)
	}
	legacyMemoryResult, _ := json.Marshal(map[string]any{"memory_id": legacyMemoryID})
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.knowledge.v1','create_memory','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), legacyMemoryResult, ownerScope.OwnerID, ownerScope.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	publicTaskID := uuid.NewString()
	quarantinedTaskID := uuid.NewString()
	for _, task := range []struct{ id, goal string }{{publicTaskID, "public legacy task"}, {quarantinedTaskID, "internal legacy task"}} {
		if _, err = pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,$2,$3,$4,'agent','{}'::jsonb,'queued',1,$5,$5,$5)`, task.id, task.goal, profileID, uuid.NewString(), now); err != nil {
			t.Fatal(err)
		}
	}
	publicTaskResult, err := json.Marshal(map[string]any{"id": publicTaskID, "status": "queued"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.tasks.v1','create_task','completed',$2,$2,$3,$4,$5,clock_timestamp())`, uuid.NewString(), make([]byte, 32), publicTaskResult, ownerScope.OwnerID, ownerScope.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	insertLegacyPublicTaskOwner := func(taskID string) {
		t.Helper()
		result, marshalErr := json.Marshal(map[string]any{"id": taskID})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, insertErr := pool.Exec(ctx, `INSERT INTO agent_capability_operations(
			operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
			owner_id,account_generation,completed_at
		) VALUES($1,'agent.tasks.v1','create_task','completed',$2,$2,$3,$4,$5,clock_timestamp())`, uuid.NewString(), make([]byte, 32), result, ownerScope.OwnerID, ownerScope.AccountGeneration); insertErr != nil {
			t.Fatal(insertErr)
		}
	}
	insertLegacyTask := func(id, goal, createKey, status, failureCode string, attempt int, revision int64) {
		t.Helper()
		if _, insertErr := pool.Exec(ctx, `INSERT INTO core_tasks(
			task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,attempt,failure_code,revision,available_at,created_at,updated_at
		) VALUES($1,$2,$3,$4,'agent','{}'::jsonb,$5,$6,$7,$8,$9,$9,$9)`, id, goal, profileID, createKey, status, attempt, failureCode, revision, now); insertErr != nil {
			t.Fatal(insertErr)
		}
		insertLegacyPublicTaskOwner(id)
	}
	legacyTaskView := func(id string, spec coretask.TaskSpec, status coretask.Status, attempt uint32, revision uint64, failureCode string) coretask.Task {
		return coretask.Task{
			ID: id, Spec: spec, Status: status, Attempt: attempt, Revision: revision,
			CreatedAt: now, UpdatedAt: now, AvailableAt: now, FailureCode: failureCode,
		}
	}
	insertLegacyTaskReplay := func(operation, key, digest string, value coretask.Task) {
		t.Helper()
		raw, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, insertErr := pool.Exec(ctx, `INSERT INTO core_task_replays(operation,idempotency_key,request_hash,response_json) VALUES($1,$2,$3,$4)`, operation, key, digest, raw); insertErr != nil {
			t.Fatal(insertErr)
		}
	}

	legacyCreateKey := uuid.NewString()
	legacyCreateTaskID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("task:"+legacyCreateKey)).String()
	legacyCreateSpec := coretask.TaskSpec{Kind: coretask.TaskKindAgent, Goal: "legacy public create replay", ModelProfileID: profileID, IdempotencyKey: legacyCreateKey}
	legacyCreateDigest, err := legacyCreateSpec.MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	insertLegacyTask(legacyCreateTaskID, legacyCreateSpec.Goal, legacyCreateKey, "queued", "", 0, 1)
	insertLegacyTaskReplay("create", legacyCreateKey, legacyCreateDigest, legacyTaskView(legacyCreateTaskID, legacyCreateSpec, coretask.StatusQueued, 0, 1, ""))

	legacyCancelKey := uuid.NewString()
	legacyCancelTaskID := uuid.NewString()
	legacyCancelReason := "legacy owner cancel"
	legacyCancelDigest, err := coretask.CanonicalMutationDigest(map[string]any{"operation": "cancel", "task_id": legacyCancelTaskID, "revision": uint64(1), "reason": legacyCancelReason})
	if err != nil {
		t.Fatal(err)
	}
	legacyCancelSpec := coretask.TaskSpec{Kind: coretask.TaskKindAgent, Goal: "legacy public cancel replay", ModelProfileID: profileID, IdempotencyKey: uuid.NewString()}
	insertLegacyTask(legacyCancelTaskID, legacyCancelSpec.Goal, legacyCancelSpec.IdempotencyKey, "canceled", "user_canceled", 1, 2)
	insertLegacyTaskReplay("cancel", legacyCancelKey, legacyCancelDigest, legacyTaskView(legacyCancelTaskID, legacyCancelSpec, coretask.StatusCanceled, 1, 2, "user_canceled"))

	legacyRetryKey := uuid.NewString()
	legacyRetryOriginalID := uuid.NewString()
	legacyRetryTaskID := uuid.NewString()
	legacyRetryDigest, err := coretask.CanonicalMutationDigest(map[string]any{"operation": "retry", "task_id": legacyRetryOriginalID, "revision": uint64(2)})
	if err != nil {
		t.Fatal(err)
	}
	legacyRetryOriginalSpec := coretask.TaskSpec{Kind: coretask.TaskKindAgent, Goal: "legacy public retry source", ModelProfileID: profileID, IdempotencyKey: uuid.NewString()}
	legacyRetrySpec := legacyRetryOriginalSpec
	legacyRetrySpec.IdempotencyKey = legacyRetryKey
	insertLegacyTask(legacyRetryOriginalID, legacyRetryOriginalSpec.Goal, legacyRetryOriginalSpec.IdempotencyKey, "failed", "legacy_failure", 1, 2)
	insertLegacyTask(legacyRetryTaskID, legacyRetrySpec.Goal, legacyRetryKey, "queued", "", 0, 1)
	if _, err = pool.Exec(ctx, `UPDATE core_tasks SET retry_of_task_id=$2 WHERE task_id=$1`, legacyRetryTaskID, legacyRetryOriginalID); err != nil {
		t.Fatal(err)
	}
	legacyRetryOperationResult, _ := json.Marshal(map[string]any{"id": legacyRetryTaskID})
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.tasks.v1','retry_task','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), legacyRetryOperationResult, ownerScope.OwnerID, ownerScope.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	legacyRetryView := legacyTaskView(legacyRetryTaskID, legacyRetrySpec, coretask.StatusQueued, 0, 1, "")
	legacyRetryView.RetryOfTaskID = legacyRetryOriginalID
	insertLegacyTaskReplay("retry", legacyRetryKey, legacyRetryDigest, legacyRetryView)

	legacyConfirmationBinding := func(targetID string) coreconfirmation.Binding {
		return coreconfirmation.Binding{
			OwnerID: ownerScope.OwnerID, OperationDomain: "legacy.public", TargetID: targetID, TargetRevision: 1, SourceVersion: "core-v1",
			ContentDigest: coreconfirmation.Digest(strings.Repeat("1", 64)), ParameterDigest: coreconfirmation.Digest(strings.Repeat("2", 64)),
			NetworkDigest: coreconfirmation.Digest(strings.Repeat("3", 64)), SecretGrantDigest: coreconfirmation.Digest(strings.Repeat("4", 64)),
		}
	}
	insertLegacyConfirmation := func(taskID, confirmationID string, state coreconfirmation.State, binding coreconfirmation.Binding, revision int64) coreconfirmation.Confirmation {
		t.Helper()
		bindingRaw, marshalErr := json.Marshal(binding)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, insertErr := pool.Exec(ctx, `INSERT INTO core_confirmations(
			confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at,terminal_code,terminal_reason
		) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$9,$10,$11,$11)`, confirmationID, binding.OperationDomain, binding.TargetID, binding.TargetRevision, bindingRaw, taskID, state, revision, now, now.Add(time.Hour), func() string {
			if state == coreconfirmation.StateRejected {
				return coreconfirmation.ReasonUserRejected
			}
			return ""
		}()); insertErr != nil {
			t.Fatal(insertErr)
		}
		if _, insertErr := pool.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json) VALUES($1,$2)`, confirmationID, bindingRaw); insertErr != nil {
			t.Fatal(insertErr)
		}
		return coreconfirmation.Confirmation{
			ConfirmationID: confirmationID, Binding: binding, TaskID: taskID, State: state, Revision: revision,
			CreatedAt: now, UpdatedAt: now, ExpiresAt: now.Add(time.Hour),
		}
	}
	legacyConfirmKey := uuid.NewString()
	legacyConfirmTaskID := uuid.NewString()
	legacyConfirmID := uuid.NewString()
	legacyConfirmBinding := legacyConfirmationBinding("legacy-confirm-" + legacyConfirmID)
	legacyConfirmSpec := coretask.TaskSpec{Kind: coretask.TaskKindAgent, Goal: "legacy public confirmation replay", ModelProfileID: profileID, IdempotencyKey: uuid.NewString()}
	insertLegacyTask(legacyConfirmTaskID, legacyConfirmSpec.Goal, legacyConfirmSpec.IdempotencyKey, "queued", "", 0, 2)
	legacyConfirmed := insertLegacyConfirmation(legacyConfirmTaskID, legacyConfirmID, coreconfirmation.StateConfirmed, legacyConfirmBinding, 2)
	legacyConfirmDigestRaw, _ := json.Marshal(struct {
		ID               string
		ExpectedRevision int64
	}{legacyConfirmID, 1})
	legacyConfirmDigest := sha256.Sum256(legacyConfirmDigestRaw)
	legacyConfirmedRaw, _ := json.Marshal(legacyConfirmed)
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmation_replays(operation,idempotency_key,request_hash,response_json) VALUES('confirm',$1,$2,$3)`, legacyConfirmKey, fmt.Sprintf("%x", legacyConfirmDigest), legacyConfirmedRaw); err != nil {
		t.Fatal(err)
	}

	legacyRejectKey := uuid.NewString()
	legacyRejectTaskID := uuid.NewString()
	legacyRejectID := uuid.NewString()
	legacyRejectReason := "legacy owner reject"
	legacyRejectNote := "legacy replay note"
	legacyRejectBinding := legacyConfirmationBinding("legacy-reject-" + legacyRejectID)
	legacyRejectSpec := coretask.TaskSpec{Kind: coretask.TaskKindAgent, Goal: "legacy public rejection replay", ModelProfileID: profileID, IdempotencyKey: uuid.NewString()}
	insertLegacyTask(legacyRejectTaskID, legacyRejectSpec.Goal, legacyRejectSpec.IdempotencyKey, "canceled", "user_rejected", 1, 2)
	legacyRejected := insertLegacyConfirmation(legacyRejectTaskID, legacyRejectID, coreconfirmation.StateRejected, legacyRejectBinding, 2)
	legacyRejected.TerminalCode = coreconfirmation.ReasonUserRejected
	legacyRejected.TerminalReason = coreconfirmation.ReasonUserRejected
	legacyRejectDigestRaw, _ := json.Marshal(struct {
		ID               string
		ExpectedRevision int64
		Reason, Note     string
	}{legacyRejectID, 1, legacyRejectReason, legacyRejectNote})
	legacyRejectDigest := sha256.Sum256(legacyRejectDigestRaw)
	legacyRejectedRaw, _ := json.Marshal(legacyRejected)
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmation_replays(operation,idempotency_key,request_hash,response_json) VALUES('reject',$1,$2,$3)`, legacyRejectKey, fmt.Sprintf("%x", legacyRejectDigest), legacyRejectedRaw); err != nil {
		t.Fatal(err)
	}
	ownedCredential := coreaws.RehydrateCredentialsWithTestedAt(
		ownedCredentialID, "owned-legacy", "ap-northeast-3", "", "",
		[]byte("AKIA-OWNED"), []byte("owned-secret"), nil, 0, 1, time.Time{}, now, now,
	)
	encrypted, err := NewCoreAWSStore(preMigrationStore).sealCredential(ownedCredential)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_credentials(
		credential_id,name,region,secret_key_version,
		access_key_id_nonce,access_key_id_ciphertext,
		secret_access_key_nonce,secret_access_key_ciphertext,
		session_token_nonce,session_token_ciphertext,
		revision,created_at,updated_at
	) VALUES($1,'owned-legacy','ap-northeast-3',$2,$3,$4,$5,$6,$7,$8,1,$9,$9)`, ownedCredentialID, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, now); err != nil {
		t.Fatal(err)
	}
	resultJSON, err := json.Marshal(map[string]any{"credential": map[string]any{"credential_id": ownedCredentialID, "revision": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.aws.v1','create_credential','completed',$2,$2,$3,$4,$5,clock_timestamp())`, uuid.NewString(), make([]byte, 32), resultJSON, ownerScope.OwnerID, ownerScope.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.aws.v1','create_credential','completed',$2,$2,decode('ff','hex'),$3,$4,clock_timestamp())`, uuid.NewString(), make([]byte, 32), ownerScope.OwnerID, ownerScope.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE core_aws_credentials SET account_id='123456789012',user_arn='arn:aws:iam::123456789012:user/migrated-owner',verified_revision=revision,tested_at=$2 WHERE credential_id=$1`, ownedCredentialID, now); err != nil {
		t.Fatal(err)
	}
	legacyPlanID := uuid.NewString()
	legacyTaskID := uuid.NewString()
	legacyConfirmationID := uuid.NewString()
	legacyChangeID := uuid.NewString()
	legacyReplayKey := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_plans(plan_id,credential_id,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at) VALUES($1,$2,'ap-northeast-3','legacy-pending','create',$3,$4,'{}'::jsonb,'{}'::jsonb,'[]'::jsonb,1,$5)`, legacyPlanID, ownedCredentialID, []byte(`{"Resources":{}}`), strings.Repeat("a", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,'legacy AWS request',NULL,$2,'aws_change',$3,'waiting_user',1,$4,$4,$4)`, legacyTaskID, legacyReplayKey, []byte(`{"aws_change":{"change_id":"`+legacyChangeID+`"}}`), now); err != nil {
		t.Fatal(err)
	}
	verifiedOwnedCredential := ownedCredential
	verifiedOwnedCredential.AccountID = "123456789012"
	verifiedOwnedCredential.UserARN = "arn:aws:iam::123456789012:user/migrated-owner"
	verifiedOwnedCredential.VerifiedRevision = verifiedOwnedCredential.Revision
	currentBinding := coreaws.BindingForPlan(coreaws.Plan{
		ID: legacyPlanID, OwnerID: ownerScope.OwnerID, AccountGeneration: ownerScope.AccountGeneration,
		CredentialID: ownedCredentialID, Region: "ap-northeast-3", StackName: "legacy-pending", Revision: 1,
	}, verifiedOwnedCredential)
	legacyBinding := coreconfirmation.Binding{
		OperationDomain: "aws", TargetID: currentBinding.TargetID, TargetRevision: 1,
		SourceVersion: "core-v1", ContentDigest: coreconfirmation.Digest(strings.Repeat("c", 64)),
		ParameterDigest: coreconfirmation.Digest(strings.Repeat("d", 64)), NetworkDigest: coreconfirmation.Digest(strings.Repeat("e", 64)),
		SecretGrantDigest: coreconfirmation.Digest(strings.Repeat("f", 64)), SecretGrants: []coreconfirmation.SecretGrant{{
			ReferenceID: ownedCredentialID, Purpose: coreconfirmation.SecretPurposeAWSCredential, BindingDigest: coreconfirmation.Digest(strings.Repeat("f", 64)),
		}},
	}
	legacyBindingJSON, err := json.Marshal(legacyBinding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,'aws',$2,1,$3,$4,'pending',1,$5,$5,$6)`, legacyConfirmationID, legacyBinding.TargetID, legacyBindingJSON, legacyTaskID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json) VALUES($1,$2)`, legacyConfirmationID, legacyBindingJSON); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES('aws',$1,1,$2,$3)`, legacyBinding.TargetID, legacyBindingJSON, now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_changes(change_id,plan_id,credential_id,task_id,confirmation_id,operation,status,stage,provider_token,provider_request_digest,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5::uuid,'create','waiting_user','requested',$5::text,$6,1,$7,$7)`, legacyChangeID, legacyPlanID, ownedCredentialID, legacyTaskID, legacyConfirmationID, strings.Repeat("1", 64), now); err != nil {
		t.Fatal(err)
	}
	legacyReplayJSON, err := json.Marshal(map[string]any{"Change": map[string]any{"ID": legacyChangeID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_replays(operation,idempotency_key,request_hash,response_json) VALUES('request_change',$1,$2,$3)`, legacyReplayKey, strings.Repeat("2", 64), legacyReplayJSON); err != nil {
		t.Fatal(err)
	}
	terminalTaskID := uuid.NewString()
	terminalConfirmationID := uuid.NewString()
	terminalChangeID := uuid.NewString()
	terminalReplayKey := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,attempt,failure_code,revision,available_at,created_at,updated_at) VALUES($1,'terminal legacy AWS request',NULL,$2,'aws_change',$3,'failed',1,'provider_error',2,$4,$4,$4)`, terminalTaskID, terminalReplayKey, []byte(`{"aws_change":{"change_id":"`+terminalChangeID+`"}}`), now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at,terminal_code,terminal_reason) VALUES($1,'aws',$2,1,$3,$4,'expired',2,$5,$5,$6,'provider_error','provider_error')`, terminalConfirmationID, legacyBinding.TargetID, legacyBindingJSON, terminalTaskID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json) VALUES($1,$2)`, terminalConfirmationID, legacyBindingJSON); err != nil {
		t.Fatal(err)
	}
	terminalChange := coreaws.Change{
		ID: terminalChangeID, PlanID: legacyPlanID, CredentialID: ownedCredentialID,
		TaskID: terminalTaskID, ConfirmationID: terminalConfirmationID,
		Operation: coreaws.OperationCreate, Status: coreaws.ChangeFailed, Stage: coreaws.StageFailed,
		ProviderToken: terminalConfirmationID, ProviderRequestDigest: strings.Repeat("3", 64),
		Revision: 2, ErrorCode: "provider_error", CreatedAt: now, UpdatedAt: now,
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_changes(change_id,plan_id,credential_id,task_id,confirmation_id,operation,status,stage,provider_token,provider_request_digest,revision,error_code,created_at,updated_at) VALUES($1,$2,$3,$4,$5::uuid,'create','failed','failed',$5::text,$6,2,'provider_error',$7,$7)`, terminalChangeID, legacyPlanID, ownedCredentialID, terminalTaskID, terminalConfirmationID, terminalChange.ProviderRequestDigest, now); err != nil {
		t.Fatal(err)
	}
	terminalConfirmation := coreconfirmation.Confirmation{
		ConfirmationID: terminalConfirmationID, Binding: legacyBinding, TaskID: terminalTaskID,
		State: coreconfirmation.StateExpired, Revision: 2, CreatedAt: now, UpdatedAt: now,
		ExpiresAt: now.Add(time.Hour), TerminalCode: "provider_error", TerminalReason: "provider_error",
	}
	terminalReplayJSON, err := json.Marshal(coreaws.ChangeRequestResult{
		Change:       terminalChange,
		Task:         coreaws.Task{ID: terminalTaskID, Status: "failed", Revision: 2, PlanID: legacyPlanID, ConfirmationID: terminalConfirmationID},
		Confirmation: terminalConfirmation,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminalLegacyHash := sha256.Sum256([]byte(legacyPlanID + ":" + terminalReplayKey + ":" + legacyBinding.TargetID + ":" + strconv.FormatInt(legacyBinding.TargetRevision, 10)))
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_replays(operation,idempotency_key,request_hash,response_json) VALUES('request_change',$1,$2,$3)`, terminalReplayKey, fmt.Sprintf("%x", terminalLegacyHash), terminalReplayJSON); err != nil {
		t.Fatal(err)
	}
	legacyChatRequestID := uuid.NewString()
	legacyChatConversationID := uuid.NewString()
	legacyCreateConversationID := uuid.NewString()
	for _, conversationID := range []string{legacyChatConversationID, legacyCreateConversationID} {
		if _, err = pool.Exec(ctx, `INSERT INTO core_conversations(conversation_id,title,revision,created_at,updated_at) VALUES($1,'legacy public Conversation',1,$2,$2)`, conversationID, now); err != nil {
			t.Fatal(err)
		}
	}
	legacyChatResult, err := json.Marshal(map[string]any{
		"request_id": legacyChatRequestID, "conversation_id": legacyChatConversationID,
		"revision": 1, "message": map[string]any{}, "done": true, "model_profile_id": profileID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_chat_request_leases(
		request_id,conversation_id,idempotency_key,request_fingerprint,profile_id,
		profile_snapshot_json,profile_snapshot_digest,extensions_json,state,response_json
	) VALUES($1,$2,$1,$3,$4,'{}'::jsonb,$5,'[]'::jsonb,'completed',$6)`, legacyChatRequestID, legacyChatConversationID, strings.Repeat("4", 64), profileID, strings.Repeat("5", 64), legacyChatResult); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.chat.v1','chat','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), legacyChatResult, ownerScope.OwnerID, ownerScope.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	legacyCreateResult, err := json.Marshal(map[string]any{
		"conversation": map[string]any{"conversation_id": legacyCreateConversationID, "title": "legacy public Conversation", "revision": 1},
		"replayed":     false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.chat.v1','create_conversation','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), legacyCreateResult, ownerScope.OwnerID, ownerScope.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	legacyFailedChatRequestID := uuid.NewString()
	legacyFailedChatProfileID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_model_profiles(profile_id,display_name,provider,base_url,model_name,created_at,updated_at) VALUES($1,'legacy failed chat profile','openai_compatible','https://example.test','legacy-chat-model',$2,$2)`, legacyFailedChatProfileID, now); err != nil {
		t.Fatal(err)
	}
	legacyModelResult, err := json.Marshal(map[string]any{"id": legacyFailedChatProfileID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.models.v1','create_model','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), legacyModelResult, ownerScope.OwnerID, ownerScope.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_chat_request_leases(
		request_id,idempotency_key,request_fingerprint,profile_id,extensions_json,state,error_code,error_summary
	) VALUES($1,$1,$2,$3,'[]'::jsonb,'failed','model_failed','legacy public chat failed')`, legacyFailedChatRequestID, strings.Repeat("6", 64), legacyFailedChatProfileID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,error_code,error_message,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.chat.v1','chat','failed',$2,$2,'UPSTREAM_FAILED','operation failed',$3,$4,$5)`, uuid.NewString(), make([]byte, 32), ownerScope.OwnerID, ownerScope.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}

	if err = ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	var owner string
	var generation int64
	if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_aws_credentials WHERE credential_id=$1`, credentialID).Scan(&owner, &generation); err != nil {
		t.Fatal(err)
	}
	if owner != instanceID || generation != 1 {
		t.Fatalf("legacy credential scope=(%q,%d), want (%q,1)", owner, generation, instanceID)
	}
	if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_aws_credential_test_claims WHERE idempotency_key=$1`, legacyCredentialTestKey).Scan(&owner, &generation); err != nil {
		t.Fatal(err)
	}
	if owner != instanceID || generation != 1 {
		t.Fatalf("legacy credential-test claim scope=(%q,%d), want (%q,1)", owner, generation, instanceID)
	}
	if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_aws_credentials WHERE credential_id=$1`, ownedCredentialID).Scan(&owner, &generation); err != nil {
		t.Fatal(err)
	}
	if owner != ownerScope.OwnerID || generation != ownerScope.AccountGeneration {
		t.Fatalf("capability credential scope=(%q,%d), want (%q,%d)", owner, generation, ownerScope.OwnerID, ownerScope.AccountGeneration)
	}
	if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_task_scopes WHERE task_id=$1`, publicTaskID).Scan(&owner, &generation); err != nil {
		t.Fatal(err)
	}
	if owner != ownerScope.OwnerID || generation != ownerScope.AccountGeneration {
		t.Fatalf("public Task scope=(%q,%d), want (%q,%d)", owner, generation, ownerScope.OwnerID, ownerScope.AccountGeneration)
	}
	if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_chat_request_leases WHERE idempotency_key=$1`, legacyChatRequestID).Scan(&owner, &generation); err != nil {
		t.Fatal(err)
	}
	if owner != ownerScope.OwnerID || generation != ownerScope.AccountGeneration {
		t.Fatalf("public Chat request scope=(%q,%d), want (%q,%d)", owner, generation, ownerScope.OwnerID, ownerScope.AccountGeneration)
	}
	if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_chat_request_leases WHERE idempotency_key=$1`, legacyFailedChatRequestID).Scan(&owner, &generation); err != nil {
		t.Fatal(err)
	}
	if owner != ownerScope.OwnerID || generation != ownerScope.AccountGeneration {
		t.Fatalf("failed public Chat request scope=(%q,%d), want (%q,%d)", owner, generation, ownerScope.OwnerID, ownerScope.AccountGeneration)
	}
	for _, conversationID := range []string{legacyChatConversationID, legacyCreateConversationID} {
		if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_conversations WHERE conversation_id=$1`, conversationID).Scan(&owner, &generation); err != nil {
			t.Fatal(err)
		}
		if owner != ownerScope.OwnerID || generation != ownerScope.AccountGeneration {
			t.Fatalf("public Conversation %s scope=(%q,%d), want (%q,%d)", conversationID, owner, generation, ownerScope.OwnerID, ownerScope.AccountGeneration)
		}
	}
	if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_task_scopes WHERE task_id=$1`, quarantinedTaskID).Scan(&owner, &generation); err != nil {
		t.Fatal(err)
	}
	if owner != "__dirextalk_internal_legacy_task__:"+quarantinedTaskID || generation != 1 {
		t.Fatalf("unowned Task scope=(%q,%d), want reserved quarantine", owner, generation)
	}
	var confirmationState, confirmationCode, taskStatus, taskCode, changeStatus, changeCode string
	if err = pool.QueryRow(ctx, `SELECT confirmation.state,confirmation.terminal_code,task.status,task.failure_code,change.status,change.error_code FROM core_confirmations confirmation JOIN core_tasks task ON task.task_id=confirmation.task_id JOIN core_aws_changes change ON change.confirmation_id=confirmation.confirmation_id WHERE confirmation.confirmation_id=$1`, legacyConfirmationID).Scan(&confirmationState, &confirmationCode, &taskStatus, &taskCode, &changeStatus, &changeCode); err != nil {
		t.Fatal(err)
	}
	for field, got := range map[string]string{
		"confirmation_state": confirmationState,
		"confirmation_code":  confirmationCode,
		"task_status":        taskStatus,
		"task_code":          taskCode,
		"change_status":      changeStatus,
		"change_code":        changeCode,
	} {
		want := "binding_upgrade_reconfirmation_required"
		if field == "confirmation_state" {
			want = "expired"
		} else if field == "task_status" || field == "change_status" {
			want = "failed"
		}
		if got != want {
			t.Fatalf("%s=%q want %q", field, got, want)
		}
	}
	store, err := New(pool, instanceID, keyring)
	if err != nil {
		t.Fatal(err)
	}
	coordinator := NewCoreAWSChangeCoordinator(store, time.Now)
	service := coreaws.NewServiceWithCoordinator(NewCoreAWSStore(store), coordinator, nil, nil, nil, nil, time.Now)
	confirmationService, err := coreconfirmation.NewService(NewCoreConfirmationStore(store), func() time.Time { return now.Add(30 * time.Minute) })
	if err != nil {
		t.Fatal(err)
	}
	legacyKnowledgeContent := &pgKnowledgeContent{objects: map[string][]byte{legacyMemoryRef: []byte(legacyMemoryContent)}}
	knowledgeStore, err := NewCoreKnowledgeStore(store, CoreKnowledgeStoreConfig{Content: legacyKnowledgeContent, ManagedFiles: pgKnowledgeOpener{}, Search: pgKnowledgeSearch{}})
	if err != nil {
		t.Fatal(err)
	}
	knowledgeService, err := coreknowledge.NewService(knowledgeStore, nil)
	if err != nil {
		t.Fatal(err)
	}
	ownerContext, err := coreaws.WithCredentialMutationScope(ctx, ownerScope)
	if err != nil {
		t.Fatal(err)
	}
	replayOwnerContext, err := coretask.WithOwnerScope(ownerContext, coretask.OwnerScope{OwnerID: ownerScope.OwnerID, AccountGeneration: ownerScope.AccountGeneration})
	if err != nil {
		t.Fatal(err)
	}
	scheduleReplay, replayed, err := NewCoreScheduleStore(store).LookupScheduleMutation(replayOwnerContext, "create", legacyScheduleKey, legacyScheduleDigest)
	if err != nil || !replayed || scheduleReplay.ID != legacyScheduleID {
		t.Fatalf("legacy Schedule replay=%#v replayed=%v err=%v", scheduleReplay, replayed, err)
	}
	replayTx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var memoryReplay knowledgeReplay
	replayed, err = replayKnowledge(replayOwnerContext, replayTx, "memory", legacyMemoryKey, legacyMemoryDigest, &memoryReplay)
	_ = replayTx.Rollback(ctx)
	if err != nil || !replayed || memoryReplay.Source.ID != legacyMemoryID {
		t.Fatalf("legacy Knowledge replay=%#v replayed=%v err=%v", memoryReplay, replayed, err)
	}
	retried, err := coordinator.RequestChange(ownerContext, coreaws.RequestChangeInput{
		Scope: ownerScope, PlanID: legacyPlanID, IdempotencyKey: legacyReplayKey,
	})
	if err != nil || retried.Change.ID == legacyChangeID {
		t.Fatalf("retry after binding upgrade terminalization=%#v err=%v", retried, err)
	}
	terminalReplay, err := coordinator.RequestChange(ownerContext, coreaws.RequestChangeInput{
		Scope: ownerScope, PlanID: legacyPlanID, IdempotencyKey: terminalReplayKey,
	})
	if err != nil || terminalReplay.Change.ID != terminalChangeID {
		t.Fatalf("terminal legacy replay=%#v err=%v", terminalReplay, err)
	}
	registry := agentcapability.NewCoreRegistry(agentcapability.CoreBindings{
		AWS: service, Tasks: NewCoreTaskStore(store), Confirmations: confirmationService, Schedules: NewCoreScheduleStore(store), Knowledge: knowledgeService,
	})
	publicAWS, ok := registry.Get("agent.aws.v1")
	if !ok {
		t.Fatal("public AWS capability is not registered")
	}
	publicContext := capabilityclient.WithCallContext(ownerContext, &capv1.CallContext{}, &capv1.PermissionContext{
		AuthenticatedOwnerId: ownerScope.OwnerID,
		AccountGeneration:    ownerScope.AccountGeneration,
	})
	publicTasks, ok := registry.Get("agent.tasks.v1")
	if !ok {
		t.Fatal("public Task capability is not registered")
	}
	publicConfirmations, ok := registry.Get("agent.confirmations.v1")
	if !ok {
		t.Fatal("public Confirmation capability is not registered")
	}
	publicSchedules, ok := registry.Get("agent.schedules.v1")
	if !ok {
		t.Fatal("public Schedule capability is not registered")
	}
	publicScheduleRaw, err := publicSchedules.HandleOperation(publicContext, "create_schedule", []byte(fmt.Sprintf(
		`{"idempotency_key":%q,"name":%q,"run_at":%q,"timezone":"UTC","spec":{"goal":%q,"model_profile_id":%q}}`,
		legacyScheduleKey, legacySchedule.Name, runAt.Format(time.RFC3339Nano), legacySchedule.Spec.Goal, profileID,
	)))
	if err != nil {
		t.Fatalf("public Schedule legacy replay: %v", err)
	}
	var publicScheduleResult struct {
		Schedule coretask.Schedule `json:"schedule"`
	}
	if err = json.Unmarshal(publicScheduleRaw, &publicScheduleResult); err != nil || publicScheduleResult.Schedule.ID != legacyScheduleID {
		t.Fatalf("public Schedule legacy replay=%#v err=%v raw=%s", publicScheduleResult, err, publicScheduleRaw)
	}
	publicKnowledge, ok := registry.Get("agent.knowledge.v1")
	if !ok {
		t.Fatal("public Knowledge capability is not registered")
	}
	publicMemoryRaw, err := publicKnowledge.HandleOperation(publicContext, "create_memory", []byte(fmt.Sprintf(
		`{"idempotency_key":%q,"title":%q,"content":%q}`, legacyMemoryKey, legacyMemoryCommand.Title, legacyMemoryCommand.Content,
	)))
	if err != nil {
		t.Fatalf("public Knowledge legacy replay: %v", err)
	}
	var publicMemoryResult struct {
		MemoryID string `json:"memory_id"`
	}
	if err = json.Unmarshal(publicMemoryRaw, &publicMemoryResult); err != nil || publicMemoryResult.MemoryID != legacyMemoryID {
		t.Fatalf("public Knowledge legacy replay=%#v err=%v raw=%s", publicMemoryResult, err, publicMemoryRaw)
	}
	var tasksBeforeReplay int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM core_tasks`).Scan(&tasksBeforeReplay); err != nil {
		t.Fatal(err)
	}
	assertTaskReplay := func(operation string, request []byte, wantID string) {
		t.Helper()
		raw, operationErr := publicTasks.HandleOperation(publicContext, operation, request)
		if operationErr != nil {
			t.Fatalf("public %s legacy replay: %v", operation, operationErr)
		}
		var task coretask.Task
		if unmarshalErr := json.Unmarshal(raw, &task); unmarshalErr != nil {
			t.Fatalf("decode public %s replay: %v raw=%s", operation, unmarshalErr, raw)
		}
		if task.ID != wantID {
			t.Fatalf("public %s replay task=%q want=%q raw=%s", operation, task.ID, wantID, raw)
		}
	}
	assertTaskReplay("create_task", []byte(fmt.Sprintf(
		`{"goal":%q,"model_profile_id":%q,"idempotency_key":%q}`, legacyCreateSpec.Goal, profileID, legacyCreateKey,
	)), legacyCreateTaskID)
	assertTaskReplay("cancel_task", []byte(fmt.Sprintf(
		`{"task_id":%q,"reason":%q,"expected_revision":1,"idempotency_key":%q}`, legacyCancelTaskID, legacyCancelReason, legacyCancelKey,
	)), legacyCancelTaskID)
	assertTaskReplay("retry_task", []byte(fmt.Sprintf(
		`{"task_id":%q,"expected_revision":2,"idempotency_key":%q}`, legacyRetryOriginalID, legacyRetryKey,
	)), legacyRetryTaskID)
	assertConfirmationReplay := func(operation string, request []byte, wantID string, wantState coreconfirmation.State) {
		t.Helper()
		raw, operationErr := publicConfirmations.HandleOperation(publicContext, operation, request)
		if operationErr != nil {
			t.Fatalf("public %s legacy replay: %v", operation, operationErr)
		}
		var result struct {
			Confirmation coreconfirmation.Confirmation `json:"confirmation"`
		}
		if unmarshalErr := json.Unmarshal(raw, &result); unmarshalErr != nil {
			t.Fatalf("decode public %s replay: %v raw=%s", operation, unmarshalErr, raw)
		}
		if result.Confirmation.ConfirmationID != wantID || result.Confirmation.State != wantState {
			t.Fatalf("public %s replay=%+v want id=%s state=%s", operation, result.Confirmation, wantID, wantState)
		}
	}
	assertConfirmationReplay("confirm", []byte(fmt.Sprintf(
		`{"confirmation_id":%q,"expected_revision":1,"idempotency_key":%q}`, legacyConfirmID, legacyConfirmKey,
	)), legacyConfirmID, coreconfirmation.StateConfirmed)
	assertConfirmationReplay("reject", []byte(fmt.Sprintf(
		`{"confirmation_id":%q,"expected_revision":1,"reason":%q,"note":%q,"idempotency_key":%q}`, legacyRejectID, legacyRejectReason, legacyRejectNote, legacyRejectKey,
	)), legacyRejectID, coreconfirmation.StateRejected)
	var tasksAfterReplay int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM core_tasks`).Scan(&tasksAfterReplay); err != nil {
		t.Fatal(err)
	}
	if tasksAfterReplay != tasksBeforeReplay {
		t.Fatalf("public v2 replay created duplicate Tasks: before=%d after=%d", tasksBeforeReplay, tasksAfterReplay)
	}
	for table, key := range map[string]string{
		"core_task_replays":               legacyCreateKey,
		"core_confirmation_replays":       legacyConfirmKey,
		"core_schedule_replays":           legacyScheduleKey,
		"core_knowledge_mutation_replays": legacyMemoryKey,
	} {
		var owner string
		var generation int64
		if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM `+table+` WHERE idempotency_key=$1`, key).Scan(&owner, &generation); err != nil {
			t.Fatalf("read migrated %s scope: %v", table, err)
		}
		if owner != ownerScope.OwnerID || generation != ownerScope.AccountGeneration {
			t.Fatalf("migrated %s scope=(%q,%d) want=(%q,%d)", table, owner, generation, ownerScope.OwnerID, ownerScope.AccountGeneration)
		}
	}
	publicRaw, err := publicAWS.HandleOperation(publicContext, "request_change", []byte(fmt.Sprintf(
		`{"idempotency_key":%q,"plan_id":%q}`, terminalReplayKey, legacyPlanID,
	)))
	if err != nil {
		t.Fatalf("public terminal legacy replay: %v", err)
	}
	var publicResult struct {
		Change struct {
			ID string `json:"change_id"`
		} `json:"change"`
	}
	if err = json.Unmarshal(publicRaw, &publicResult); err != nil {
		t.Fatalf("decode public terminal replay: %v", err)
	}
	if publicResult.Change.ID != terminalChangeID {
		t.Fatalf("public terminal legacy replay change=%q want=%q raw=%s", publicResult.Change.ID, terminalChangeID, publicRaw)
	}
	var terminalGraphCount int
	if err = pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM core_aws_changes WHERE change_id=$1) +
		(SELECT count(*) FROM core_tasks WHERE task_id=$2) +
		(SELECT count(*) FROM core_confirmations WHERE confirmation_id=$3)`,
		terminalChangeID, terminalTaskID, terminalConfirmationID,
	).Scan(&terminalGraphCount); err != nil {
		t.Fatal(err)
	}
	if terminalGraphCount != 3 {
		t.Fatalf("public legacy replay duplicated durable graph: count=%d want=3", terminalGraphCount)
	}
	var replayHashVersion int
	if err = pool.QueryRow(ctx, `SELECT hash_version FROM core_aws_change_request_replays WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, ownerScope.OwnerID, ownerScope.AccountGeneration, terminalReplayKey).Scan(&replayHashVersion); err != nil || replayHashVersion != 2 {
		t.Fatalf("terminal replay hash_version=%d err=%v", replayHashVersion, err)
	}
	replaced, err := service.ReplaceCredential(ownerContext, coreaws.CredentialInput{
		ID: ownedCredentialID, Name: "owned-upgraded", Region: "ap-northeast-3",
		AccessKeyID: "AKIA-UPGRADED", SecretAccessKey: "upgraded-secret",
	}, 1, uuid.NewString())
	if err != nil || replaced.Revision != 2 {
		t.Fatalf("replace migrated credential=%#v err=%v", replaced, err)
	}
	if _, err = service.CreatePlan(ownerContext, coreaws.PlanInput{
		CredentialID: ownedCredentialID, StackName: "migrated-scope", Operation: coreaws.OperationCreate,
		Template: []byte(`{"Resources":{}}`), IdempotencyKey: uuid.NewString(),
	}); err != nil {
		t.Fatalf("create Plan from migrated credential: %v", err)
	}
}

func TestCoreAWSCredentialScopeMigrationRejectsAmbiguousLegacyOwner(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for Core AWS PostgreSQL migration integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "dtx_agent_aws_ambiguous_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if _, dropErr := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); dropErr != nil {
			t.Errorf("drop isolated schema: %v", dropErr)
		}
	}()

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err = pool.Exec(ctx, `CREATE TABLE agent_schema_migrations (
		version bigint PRIMARY KEY,
		checksum bytea NOT NULL CHECK (octet_length(checksum)=32),
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
	)`); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations.Ordered()[:2] {
		if _, err = pool.Exec(ctx, string(migration.Script)); err != nil {
			t.Fatalf("apply legacy migration %d: %v", migration.Version, err)
		}
		checksum := sha256.Sum256(migration.Script)
		if _, err = pool.Exec(ctx, `INSERT INTO agent_schema_migrations(version,checksum) VALUES($1,$2)`, migration.Version, checksum[:]); err != nil {
			t.Fatal(err)
		}
	}
	instanceID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_instance_metadata(agent_instance_id) VALUES($1)`, instanceID); err != nil {
		t.Fatal(err)
	}
	credentialID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_credentials(
		credential_id,name,region,secret_key_version,
		access_key_id_nonce,access_key_id_ciphertext,
		secret_access_key_nonce,secret_access_key_ciphertext,
		session_token_nonce,session_token_ciphertext,
		revision,created_at,updated_at
	) VALUES($1,'ambiguous','ap-northeast-3',1,
		decode(repeat('01',12),'hex'),decode(repeat('02',16),'hex'),
		decode(repeat('03',12),'hex'),decode(repeat('04',16),'hex'),
		decode(repeat('05',12),'hex'),decode(repeat('06',16),'hex'),
		1,clock_timestamp(),clock_timestamp())`, credentialID); err != nil {
		t.Fatal(err)
	}
	resultJSON, err := json.Marshal(map[string]any{"credential": map[string]any{"credential_id": credentialID, "revision": 1}})
	if err != nil {
		t.Fatal(err)
	}
	for index, owner := range []string{"@ambiguous-a:example.test", "@ambiguous-b:example.test"} {
		if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
			operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
			owner_id,account_generation,completed_at
		) VALUES($1,'agent.aws.v1','create_credential','completed',$2,$2,$3,$4,$5,clock_timestamp())`, uuid.NewString(), make([]byte, 32), resultJSON, owner, index+1); err != nil {
			t.Fatal(err)
		}
	}

	err = ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "ambiguous legacy AWS credential ownership") {
		t.Fatalf("ambiguous ownership migration err=%v", err)
	}
	var version4Count int
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM agent_schema_migrations WHERE version=4`).Scan(&version4Count); queryErr != nil {
		t.Fatal(queryErr)
	}
	if version4Count != 0 {
		t.Fatal("failed migration recorded version 4")
	}
}

func TestCoreAWSCredentialScopeMigrationRejectsActiveConsumedChange(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for Core AWS PostgreSQL migration integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "dtx_agent_aws_consumed_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if _, dropErr := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); dropErr != nil {
			t.Errorf("drop isolated schema: %v", dropErr)
		}
	}()

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err = pool.Exec(ctx, `CREATE TABLE agent_schema_migrations (
		version bigint PRIMARY KEY,
		checksum bytea NOT NULL CHECK (octet_length(checksum)=32),
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
	)`); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations.Ordered()[:2] {
		if _, err = pool.Exec(ctx, string(migration.Script)); err != nil {
			t.Fatalf("apply legacy migration %d: %v", migration.Version, err)
		}
		checksum := sha256.Sum256(migration.Script)
		if _, err = pool.Exec(ctx, `INSERT INTO agent_schema_migrations(version,checksum) VALUES($1,$2)`, migration.Version, checksum[:]); err != nil {
			t.Fatal(err)
		}
	}
	instanceID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_instance_metadata(agent_instance_id) VALUES($1)`, instanceID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	credentialID, planID, taskID, confirmationID, changeID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_credentials(
		credential_id,name,region,secret_key_version,
		access_key_id_nonce,access_key_id_ciphertext,
		secret_access_key_nonce,secret_access_key_ciphertext,
		session_token_nonce,session_token_ciphertext,
		account_id,user_arn,verified_revision,revision,created_at,updated_at
	) VALUES($1,'consumed','ap-northeast-3',1,
		decode(repeat('01',12),'hex'),decode(repeat('02',16),'hex'),
		decode(repeat('03',12),'hex'),decode(repeat('04',16),'hex'),
		decode(repeat('05',12),'hex'),decode(repeat('06',16),'hex'),
		'123456789012','arn:aws:iam::123456789012:user/consumed',1,1,$2,$2)`, credentialID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_plans(plan_id,credential_id,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at) VALUES($1,$2,'ap-northeast-3','consumed','create',$3,$4,'{}'::jsonb,'{}'::jsonb,'[]'::jsonb,1,$5)`, planID, credentialID, []byte(`{"Resources":{}}`), strings.Repeat("a", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,attempt,lease_epoch,lease_holder,lease_expires_at,revision,available_at,created_at,updated_at) VALUES($1,'active consumed AWS request',NULL,$2,'aws_change',$3,'running',1,1,'legacy-worker',$4,2,$5,$5,$5)`, taskID, uuid.NewString(), []byte(`{"aws_change":{"change_id":"`+changeID+`"}}`), now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	binding := coreconfirmation.Binding{
		OperationDomain: "aws", TargetID: "aws-target:" + strings.Repeat("b", 64), TargetRevision: 1,
		SourceVersion: "core-v1", ContentDigest: coreconfirmation.Digest(strings.Repeat("c", 64)),
		ParameterDigest: coreconfirmation.Digest(strings.Repeat("d", 64)), NetworkDigest: coreconfirmation.Digest(strings.Repeat("e", 64)),
		SecretGrantDigest: coreconfirmation.Digest(strings.Repeat("f", 64)), SecretGrants: []coreconfirmation.SecretGrant{{
			ReferenceID: credentialID, Purpose: coreconfirmation.SecretPurposeAWSCredential, BindingDigest: coreconfirmation.Digest(strings.Repeat("f", 64)),
		}},
	}
	bindingJSON, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,'aws',$2,1,$3,$4,'consumed',2,$5,$5,$6)`, confirmationID, binding.TargetID, bindingJSON, taskID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_changes(change_id,plan_id,credential_id,task_id,confirmation_id,operation,status,stage,provider_token,provider_request_digest,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5::uuid,'create','running','change_set_creating',$5::text,$6,2,$7,$7)`, changeID, planID, credentialID, taskID, confirmationID, strings.Repeat("1", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmation_reservations(confirmation_id,task_id,acquired_attempt,acquired_lease_epoch,task_revision,acquired_lease_expires_at,active) VALUES($1,$2,1,1,2,$3,true)`, confirmationID, taskID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	err = ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "active consumed AWS change must be reconciled") {
		t.Fatalf("active consumed migration err=%v", err)
	}
	var version4Count int
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM agent_schema_migrations WHERE version=4`).Scan(&version4Count); queryErr != nil {
		t.Fatal(queryErr)
	}
	if version4Count != 0 {
		t.Fatal("failed migration recorded version 4")
	}
}

func TestCoreAWSReplayMigrationRejectsDanglingLegacyReceipt(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_aws_dangling_replay_")
	replayKey := uuid.NewString()
	replayJSON, err := json.Marshal(map[string]any{"Change": map[string]any{"ID": uuid.NewString()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_replays(operation,idempotency_key,request_hash,response_json) VALUES('request_change',$1,$2,$3)`, replayKey, strings.Repeat("a", 64), replayJSON); err != nil {
		t.Fatal(err)
	}

	err = ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "malformed legacy AWS request replay relationship") {
		t.Fatalf("dangling request replay migration err=%v", err)
	}
	var version4Count, replayCount int
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM agent_schema_migrations WHERE version=4`).Scan(&version4Count); queryErr != nil {
		t.Fatal(queryErr)
	}
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM core_aws_replays WHERE operation='request_change' AND idempotency_key=$1`, replayKey).Scan(&replayCount); queryErr != nil {
		t.Fatal(queryErr)
	}
	if version4Count != 0 || replayCount != 1 {
		t.Fatalf("failed migration version4=%d durable legacy replay=%d, want 0 and 1", version4Count, replayCount)
	}
}

func TestCoreAWSReplayMigrationRejectsMismatchedDurableGraph(t *testing.T) {
	for _, mismatch := range []string{"response_task", "confirmation_target", "binding_owner"} {
		t.Run(mismatch, func(t *testing.T) {
			testCoreAWSReplayMigrationRejectsMismatchedDurableGraph(t, mismatch)
		})
	}
}

func testCoreAWSReplayMigrationRejectsMismatchedDurableGraph(t *testing.T, mismatch string) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_aws_mismatched_replay_")
	now := time.Now().UTC().Truncate(time.Microsecond)
	owner := coreteam.Scope{OwnerID: "@legacy-replay-owner:example.test", AccountGeneration: 3}
	credentialID, planID := uuid.NewString(), uuid.NewString()
	taskID, confirmationID, changeID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	replayKey := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO core_aws_credentials(
		credential_id,name,region,secret_key_version,
		access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,
		session_token_nonce,session_token_ciphertext,revision,created_at,updated_at
	) VALUES($1,'legacy-replay','ap-northeast-3',1,
		decode(repeat('01',12),'hex'),decode(repeat('02',16),'hex'),decode(repeat('03',12),'hex'),decode(repeat('04',16),'hex'),
		decode(repeat('05',12),'hex'),decode(repeat('06',16),'hex'),1,$2,$2)`, credentialID, now); err != nil {
		t.Fatal(err)
	}
	credentialResult, err := json.Marshal(map[string]any{"credential": map[string]any{"credential_id": credentialID, "revision": 1}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,owner_id,account_generation,completed_at
	) VALUES($1,'agent.aws.v1','create_credential','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), credentialResult, owner.OwnerID, owner.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_plans(plan_id,credential_id,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at) VALUES($1,$2,'ap-northeast-3','legacy-replay','create',$3,$4,'{}','{}','[]',1,$5)`, planID, credentialID, []byte(`{"Resources":{}}`), strings.Repeat("a", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,attempt,failure_code,revision,available_at,created_at,updated_at) VALUES($1,'legacy replay',NULL,$2,'aws_change',$3,'failed',1,'legacy_failure',2,$4,$4,$4)`, taskID, replayKey, []byte(`{"aws_change":{"change_id":"`+changeID+`"}}`), now); err != nil {
		t.Fatal(err)
	}
	binding := coreconfirmation.Binding{OwnerID: owner.OwnerID, OperationDomain: "aws", TargetID: "aws-target:" + strings.Repeat("b", 64), TargetRevision: 1, ContentDigest: coreconfirmation.Digest(strings.Repeat("c", 64))}
	if mismatch == "binding_owner" {
		binding.OwnerID = "@tampered-binding-owner:example.test"
	}
	bindingJSON, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	confirmationTargetID := binding.TargetID
	if mismatch == "confirmation_target" {
		confirmationTargetID += ":tampered"
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,'aws',$2,1,$3,$4,'expired',2,$5,$5,$6)`, confirmationID, confirmationTargetID, bindingJSON, taskID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json) VALUES($1,$2)`, confirmationID, bindingJSON); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES('aws',$1,1,$2,$3)`, binding.TargetID, bindingJSON, now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_changes(change_id,plan_id,credential_id,task_id,confirmation_id,operation,status,stage,provider_request_digest,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'create','failed','failed',$6,2,$7,$7)`, changeID, planID, credentialID, taskID, confirmationID, strings.Repeat("d", 64), now); err != nil {
		t.Fatal(err)
	}
	replayTaskID := taskID
	if mismatch == "response_task" {
		replayTaskID = uuid.NewString()
	}
	replayJSON, err := json.Marshal(coreaws.ChangeRequestResult{
		Change:       coreaws.Change{ID: changeID, PlanID: planID, CredentialID: credentialID, TaskID: taskID, ConfirmationID: confirmationID},
		Task:         coreaws.Task{ID: replayTaskID, PlanID: planID, ConfirmationID: confirmationID},
		Confirmation: coreconfirmation.Confirmation{ConfirmationID: confirmationID, Binding: binding, TaskID: taskID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_aws_replays(operation,idempotency_key,request_hash,response_json) VALUES('request_change',$1,$2,$3)`, replayKey, strings.Repeat("e", 64), replayJSON); err != nil {
		t.Fatal(err)
	}

	err = ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "malformed legacy AWS request replay relationship") {
		t.Fatalf("mismatched request replay migration err=%v", err)
	}
	var version4Count, replayCount int
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM agent_schema_migrations WHERE version=4`).Scan(&version4Count); queryErr != nil {
		t.Fatal(queryErr)
	}
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM core_aws_replays WHERE operation='request_change' AND idempotency_key=$1`, replayKey).Scan(&replayCount); queryErr != nil {
		t.Fatal(queryErr)
	}
	if version4Count != 0 || replayCount != 1 {
		t.Fatalf("failed migration version4=%d durable legacy replay=%d, want 0 and 1", version4Count, replayCount)
	}
}

func TestCoreTaskScopeMigrationRejectsAmbiguousLegacyOwner(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_task_ambiguous_")
	now := time.Now().UTC().Truncate(time.Microsecond)
	profileID, taskID := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO core_model_profiles(profile_id,display_name,provider,base_url,model_name,created_at,updated_at) VALUES($1,'ambiguous task profile','openai_compatible','https://example.test','legacy-model',$2,$2)`, profileID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,'ambiguous legacy task',$2,$3,'agent','{}'::jsonb,'queued',1,$4,$4,$4)`, taskID, profileID, uuid.NewString(), now); err != nil {
		t.Fatal(err)
	}
	resultJSON, err := json.Marshal(map[string]any{"id": taskID, "status": "queued"})
	if err != nil {
		t.Fatal(err)
	}
	for index, owner := range []string{"@task-owner-a:example.test", "@task-owner-b:example.test"} {
		if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
			operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
			owner_id,account_generation,completed_at
		) VALUES($1,'agent.tasks.v1','create_task','completed',$2,$2,$3,$4,$5,clock_timestamp())`, uuid.NewString(), make([]byte, 32), resultJSON, owner, index+1); err != nil {
			t.Fatal(err)
		}
	}

	err = ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "ambiguous legacy Core Task ownership") {
		t.Fatalf("ambiguous Task ownership migration err=%v", err)
	}
	var version4Count int
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM agent_schema_migrations WHERE version=4`).Scan(&version4Count); queryErr != nil {
		t.Fatal(queryErr)
	}
	if version4Count != 0 {
		t.Fatal("failed migration recorded version 4")
	}
}

func TestCoreTaskScopeMigrationIgnoresReadOnlyConfirmationResults(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_task_read_result_")
	now := time.Now().UTC().Truncate(time.Microsecond)
	profileID, taskID := uuid.NewString(), uuid.NewString()
	owner := coreteam.Scope{OwnerID: "@task-authoritative-owner:example.test", AccountGeneration: 5}
	if _, err := pool.Exec(ctx, `INSERT INTO core_model_profiles(profile_id,display_name,provider,base_url,model_name,created_at,updated_at) VALUES($1,'task owner profile','openai_compatible','https://example.test','legacy-model',$2,$2)`, profileID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,'authoritative legacy task',$2,$3,'agent','{}'::jsonb,'queued',1,$4,$4,$4)`, taskID, profileID, uuid.NewString(), now); err != nil {
		t.Fatal(err)
	}
	createResult, err := json.Marshal(map[string]any{"id": taskID, "status": "queued"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.tasks.v1','create_task','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), createResult, owner.OwnerID, owner.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	readResult, err := json.Marshal(map[string]any{"confirmations": []any{map[string]any{"TaskID": taskID}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.confirmations.v1','list','completed',$2,$2,$3,'@read-only-observer:example.test',9,$4)`, uuid.NewString(), make([]byte, 32), readResult, now); err != nil {
		t.Fatal(err)
	}

	if err = ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("read-only result must not own Task: %v", err)
	}
	var ownerID string
	var generation int64
	if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_task_scopes WHERE task_id=$1`, taskID).Scan(&ownerID, &generation); err != nil {
		t.Fatal(err)
	}
	if ownerID != owner.OwnerID || generation != owner.AccountGeneration {
		t.Fatalf("Task owner=%s/%d, want %s/%d", ownerID, generation, owner.OwnerID, owner.AccountGeneration)
	}
}

func TestCoreExtensionReplayMigrationPreservesPublicOwnerReplay(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_extension_replay_")
	owner := coretask.OwnerScope{OwnerID: "@legacy-extension-owner:example.test", AccountGeneration: 7}
	mutation, expected := seedLegacyExtensionReplay(t, ctx, pool, owner)

	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("migrate valid legacy Extension replay: %v", err)
	}
	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	ownerContext, err := coretask.WithOwnerScope(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := NewCoreExtensionStore(store).CreateMutation(ownerContext, mutation)
	if err != nil {
		t.Fatalf("replay migrated public Extension install: %v", err)
	}
	if replayed.TaskID != expected.TaskID || replayed.ConfirmationID != expected.ConfirmationID || replayed.Installation.ID != expected.Installation.ID {
		t.Fatalf("migrated Extension replay=%#v, want %#v", replayed, expected)
	}
	var replayOwner string
	var replayGeneration int64
	if err = pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_extension_replays WHERE operation='install' AND idempotency_key=$1`, mutation.IdempotencyKey).Scan(&replayOwner, &replayGeneration); err != nil {
		t.Fatal(err)
	}
	if replayOwner != owner.OwnerID || replayGeneration != owner.AccountGeneration {
		t.Fatalf("Extension replay owner=%s/%d, want %s/%d", replayOwner, replayGeneration, owner.OwnerID, owner.AccountGeneration)
	}
}

func TestCoreScheduleReplayMigrationPreservesTriggerGraph(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_schedule_trigger_")
	owner := coretask.OwnerScope{OwnerID: "@legacy-schedule-owner:example.test", AccountGeneration: 5}
	key, scheduleID := seedLegacyScheduleTriggerReplay(t, ctx, pool, owner, false)

	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("migrate valid legacy Schedule trigger replay: %v", err)
	}
	var replayOwner string
	var replayGeneration int64
	if err := pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_schedule_replays WHERE operation='trigger_now' AND idempotency_key=$1`, key).Scan(&replayOwner, &replayGeneration); err != nil {
		t.Fatal(err)
	}
	if replayOwner != owner.OwnerID || replayGeneration != owner.AccountGeneration {
		t.Fatalf("Schedule replay owner=%s/%d, want %s/%d", replayOwner, replayGeneration, owner.OwnerID, owner.AccountGeneration)
	}
	var scheduleOwner string
	var scheduleGeneration int64
	if err := pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_schedules WHERE schedule_id=$1`, scheduleID).Scan(&scheduleOwner, &scheduleGeneration); err != nil {
		t.Fatal(err)
	}
	if scheduleOwner != owner.OwnerID || scheduleGeneration != owner.AccountGeneration {
		t.Fatalf("Schedule owner=%s/%d, want %s/%d", scheduleOwner, scheduleGeneration, owner.OwnerID, owner.AccountGeneration)
	}
}

func TestCoreScheduleReplayMigrationRejectsMismatchedTriggerGraphAtomically(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_schedule_bad_graph_")
	owner := coretask.OwnerScope{OwnerID: "@legacy-schedule-owner:example.test", AccountGeneration: 5}
	seedLegacyScheduleTriggerReplay(t, ctx, pool, owner, true)

	err := ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "unrecoverable legacy Core Schedule trigger replay graph") {
		t.Fatalf("mismatched Schedule replay migration err=%v", err)
	}
	assertLegacyV4MigrationRolledBack(t, ctx, pool, "core_schedule_replays", "owner_id")
}

func TestCoreKnowledgeReplayMigrationPreservesUploadLifecycleGraph(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_knowledge_upload_")
	owner := coretask.OwnerScope{OwnerID: "@legacy-knowledge-owner:example.test", AccountGeneration: 9}
	keys, sourceID := seedLegacyKnowledgeUploadReplays(t, ctx, pool, owner, false)

	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("migrate valid legacy Knowledge upload replays: %v", err)
	}
	for operation, key := range keys {
		var replayOwner string
		var replayGeneration int64
		if err := pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_knowledge_mutation_replays WHERE operation=$1 AND idempotency_key=$2`, operation, key).Scan(&replayOwner, &replayGeneration); err != nil {
			t.Fatalf("read migrated Knowledge %s replay: %v", operation, err)
		}
		if replayOwner != owner.OwnerID || replayGeneration != owner.AccountGeneration {
			t.Fatalf("Knowledge %s replay owner=%s/%d, want %s/%d", operation, replayOwner, replayGeneration, owner.OwnerID, owner.AccountGeneration)
		}
	}
	var sourceOwner string
	var sourceGeneration int64
	if err := pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_knowledge_sources WHERE source_id=$1`, sourceID).Scan(&sourceOwner, &sourceGeneration); err != nil {
		t.Fatal(err)
	}
	if sourceOwner != owner.OwnerID || sourceGeneration != owner.AccountGeneration {
		t.Fatalf("Knowledge source owner=%s/%d, want %s/%d", sourceOwner, sourceGeneration, owner.OwnerID, owner.AccountGeneration)
	}
}

func TestCoreKnowledgeReplayMigrationRejectsMismatchedUploadGraphAtomically(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_knowledge_bad_graph_")
	owner := coretask.OwnerScope{OwnerID: "@legacy-knowledge-owner:example.test", AccountGeneration: 9}
	seedLegacyKnowledgeUploadReplays(t, ctx, pool, owner, true)

	err := ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "unrecoverable legacy Core Knowledge upload replay graph") {
		t.Fatalf("mismatched Knowledge replay migration err=%v", err)
	}
	assertLegacyV4MigrationRolledBack(t, ctx, pool, "core_knowledge_mutation_replays", "owner_id")
}

func TestCoreChatScopeMigrationRejectsCompletedOperationWithoutLeaseAtomically(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_chat_missing_lease_")
	result, err := json.Marshal(map[string]any{
		"request_id": uuid.NewString(), "conversation_id": uuid.NewString(),
		"revision": 1, "message": map[string]any{}, "done": true, "model_profile_id": uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.chat.v1','chat','completed',$2,$2,$3,$4,7,clock_timestamp())`, uuid.NewString(), make([]byte, 32), result, "@legacy-chat-owner:example.test"); err != nil {
		t.Fatal(err)
	}

	err = ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "unrecoverable legacy completed Core Chat request graph") {
		t.Fatalf("missing Chat lease migration err=%v", err)
	}
	assertLegacyV4MigrationRolledBack(t, ctx, pool, "core_chat_request_leases", "owner_id")
}

func TestCoreExecutionV2MigrationRecoversSecretGenerationAndQuarantinesOwnerOnlyState(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_execution_v2_scope_")
	owner := coretask.OwnerScope{OwnerID: "@legacy-execution-owner:example.test", AccountGeneration: 11}
	resourceID, eventID, secretRef, replayKey := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	seedLegacyExecutionV2State(t, ctx, pool, owner, resourceID, eventID, secretRef, replayKey, true)

	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("migrate valid legacy ExecutionV2 state: %v", err)
	}
	var recordOwner string
	var recordGeneration int64
	if err := pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_execution_v2_records WHERE resource_id=$1`, resourceID).Scan(&recordOwner, &recordGeneration); err != nil {
		t.Fatal(err)
	}
	if recordOwner == owner.OwnerID || !strings.HasPrefix(recordOwner, "__dirextalk_internal_execution_v2_legacy__:") || recordGeneration != 1 {
		t.Fatalf("legacy ExecutionV2 record scope=%s/%d, want quarantined generation 1", recordOwner, recordGeneration)
	}
	var secretOwner, replayState string
	var secretGeneration int64
	var aadVersion int16
	if err := pool.QueryRow(ctx, `SELECT owner_id,account_generation,aad_version FROM core_execution_v2_secrets WHERE secret_ref=$1`, secretRef).Scan(&secretOwner, &secretGeneration, &aadVersion); err != nil {
		t.Fatal(err)
	}
	if secretOwner != owner.OwnerID || secretGeneration != owner.AccountGeneration || aadVersion != 1 {
		t.Fatalf("legacy ExecutionV2 secret scope=%s/%d aad=%d, want %s/%d aad=1", secretOwner, secretGeneration, aadVersion, owner.OwnerID, owner.AccountGeneration)
	}
	if err := pool.QueryRow(ctx, `SELECT state FROM core_execution_v2_replays WHERE idempotency_key=$1`, replayKey).Scan(&replayState); err != nil {
		t.Fatal(err)
	}
	if replayState != "completed" {
		t.Fatalf("legacy ExecutionV2 replay state=%q, want completed", replayState)
	}
}

func TestCoreExecutionV2MigrationRejectsUnrecoverableSecretGenerationAtomically(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_execution_v2_bad_secret_")
	owner := coretask.OwnerScope{OwnerID: "@legacy-execution-owner:example.test", AccountGeneration: 11}
	seedLegacyExecutionV2State(t, ctx, pool, owner, uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), false)

	err := ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "unrecoverable legacy ExecutionV2 secret account generation") {
		t.Fatalf("unrecoverable ExecutionV2 secret migration err=%v", err)
	}
	assertLegacyV4MigrationRolledBack(t, ctx, pool, "core_execution_v2_secrets", "account_generation")
}

func TestScopeMigrationRejectsNonterminalAuthoritativeOperationAtomically(t *testing.T) {
	for _, tc := range []struct {
		name          string
		capabilityID  string
		operationName string
	}{
		{name: "aws credential", capabilityID: "agent.aws.v1", operationName: "create_credential"},
		{name: "aws credential test", capabilityID: "agent.aws.v1", operationName: "test_credential"},
		{name: "schedule", capabilityID: "agent.schedules.v1", operationName: "create_schedule"},
		{name: "knowledge memory", capabilityID: "agent.knowledge.v1", operationName: "create_memory"},
		{name: "knowledge upload", capabilityID: "agent.knowledge.v1", operationName: "start_upload"},
		{name: "execution secret", capabilityID: "agent.execution.v2", operationName: "secrets_create"},
		{name: "conversation create", capabilityID: "agent.chat.v1", operationName: "create_conversation"},
		{name: "conversation chat", capabilityID: "agent.chat.v1", operationName: "chat"},
		{name: "conversation stream", capabilityID: "agent.chat.v1", operationName: "stream_chat"},
		{name: "conversation rename", capabilityID: "agent.chat.v1", operationName: "rename_conversation"},
		{name: "conversation delete", capabilityID: "agent.chat.v1", operationName: "delete_conversation"},
		{name: "conversation compress", capabilityID: "agent.chat.v1", operationName: "compress_context"},
		{name: "model create", capabilityID: "agent.models.v1", operationName: "create_model"},
		{name: "model sync", capabilityID: "agent.models.v1", operationName: "sync_models"},
		{name: "model update", capabilityID: "agent.models.v1", operationName: "update_model"},
		{name: "model delete", capabilityID: "agent.models.v1", operationName: "delete_model"},
		{name: "task create", capabilityID: "agent.tasks.v1", operationName: "create_task"},
		{name: "task retry", capabilityID: "agent.tasks.v1", operationName: "retry_task"},
		{name: "skill install", capabilityID: "agent.skills.v1", operationName: "install_skill"},
		{name: "mcp install", capabilityID: "agent.skills.v1", operationName: "install_mcp"},
		{name: "skill update", capabilityID: "agent.skills.v1", operationName: "update_skill"},
		{name: "mcp update", capabilityID: "agent.skills.v1", operationName: "update_mcp"},
		{name: "skill remove", capabilityID: "agent.skills.v1", operationName: "remove_skill"},
		{name: "mcp remove", capabilityID: "agent.skills.v1", operationName: "remove_mcp"},
		{name: "skill enable", capabilityID: "agent.skills.v1", operationName: "enable_skill"},
		{name: "skills enable alias", capabilityID: "agent.skills.v1", operationName: "skills_enable"},
		{name: "mcp enable", capabilityID: "agent.skills.v1", operationName: "enable_mcp"},
		{name: "mcp enable alias", capabilityID: "agent.skills.v1", operationName: "mcp_enable"},
		{name: "skill disable", capabilityID: "agent.skills.v1", operationName: "disable_skill"},
		{name: "skills disable alias", capabilityID: "agent.skills.v1", operationName: "skills_disable"},
		{name: "mcp disable", capabilityID: "agent.skills.v1", operationName: "disable_mcp"},
		{name: "mcp disable alias", capabilityID: "agent.skills.v1", operationName: "mcp_disable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_scope_active_")
			if _, err := pool.Exec(ctx, `INSERT INTO agent_capability_operations(
				operation_id,capability_id,operation_name,state,root_request_digest,request_digest,
				owner_id,account_generation
			) VALUES($1,$2,$3,'running',$4,$4,'@active-migration:example.test',2)`, uuid.NewString(), tc.capabilityID, tc.operationName, make([]byte, 32)); err != nil {
				t.Fatal(err)
			}

			err := ApplyMigrations(ctx, pool, instanceID)
			if err == nil || !strings.Contains(err.Error(), "nonterminal scoped capability operation blocks migration") {
				t.Fatalf("active operation migration err=%v", err)
			}
			assertLegacyV4MigrationRolledBack(t, ctx, pool, "core_knowledge_sources", "owner_id")
		})
	}
}

func TestScopeMigrationWaitsForConcurrentOperationThenRejects(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_scope_concurrent_")
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	operationID := uuid.NewString()
	if _, err = tx.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,owner_id,account_generation
	) VALUES($1,'agent.tasks.v1','create_task','running',$2,$2,'@concurrent-migration:example.test',3)`, operationID, make([]byte, 32)); err != nil {
		_ = tx.Rollback(ctx)
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- ApplyMigrations(ctx, pool, instanceID) }()
	select {
	case migrationErr := <-done:
		_ = tx.Rollback(ctx)
		t.Fatalf("migration did not wait for concurrent operation transaction: %v", migrationErr)
	case <-time.After(200 * time.Millisecond):
	}
	if err = tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case migrationErr := <-done:
		if migrationErr == nil || !strings.Contains(migrationErr.Error(), "nonterminal scoped capability operation blocks migration") {
			t.Fatalf("concurrent operation migration err=%v", migrationErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("migration did not resume after concurrent operation committed")
	}
	assertLegacyV4MigrationRolledBack(t, ctx, pool, "core_knowledge_sources", "owner_id")
}

func TestScopeMigrationGuardsLateLegacyCapabilityCompletion(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_scope_late_")
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("migrate clean legacy schema: %v", err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := strings.Repeat("a", 64)
	knowledgeOwner := coretask.OwnerScope{OwnerID: "@knowledge-owner:example.test", AccountGeneration: 4}
	sourceID := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO core_knowledge_sources(
		source_id,kind,status,title,digest,size_bytes,media_type,revision,created_at,updated_at,owner_id,account_generation
	) VALUES($1,'memory','ready','late legacy source',$2,1,'text/plain',1,$3,$3,$4,$5)`, sourceID, digest, now, knowledgeOwner.OwnerID, knowledgeOwner.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	knowledgeResult, err := json.Marshal(map[string]any{"memory_id": sourceID})
	if err != nil {
		t.Fatal(err)
	}
	wrongKnowledgeOperation := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,owner_id,account_generation
	) VALUES($1,'agent.knowledge.v1','create_memory','running',$2,$2,$3,$4)`, wrongKnowledgeOperation, make([]byte, 32), knowledgeOwner.OwnerID, knowledgeOwner.AccountGeneration+1); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE agent_capability_operations SET state='completed',result_json=$2,completed_at=$3 WHERE operation_id=$1`, wrongKnowledgeOperation, knowledgeResult, now); err == nil || !strings.Contains(err.Error(), "completed Knowledge operation owner scope does not match source") {
		t.Fatalf("mismatched Knowledge completion err=%v", err)
	}

	executionOwner := coretask.OwnerScope{OwnerID: "@execution-owner:example.test", AccountGeneration: 7}
	secretRef := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_execution_v2_secrets(
		owner_id,account_generation,secret_ref,revision,provider,purpose,aad_version,secret_key_version,
		secret_value_nonce,secret_value_ciphertext,binding_digest,status,created_at,updated_at
	) VALUES($1,$2,$3,1,'openai','ai_provider_api_key',2,1,$4,$5,$6,'active',$7,$7)`, executionOwner.OwnerID, executionOwner.AccountGeneration, secretRef, make([]byte, 12), make([]byte, 16), digest, now); err != nil {
		t.Fatal(err)
	}
	executionResult, err := json.Marshal(map[string]any{"secret": map[string]any{"secret_ref": secretRef}})
	if err != nil {
		t.Fatal(err)
	}
	wrongExecutionOperation := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,owner_id,account_generation
	) VALUES($1,'agent.execution.v2','secrets_create','running',$2,$2,$3,$4)`, wrongExecutionOperation, make([]byte, 32), executionOwner.OwnerID, executionOwner.AccountGeneration+1); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE agent_capability_operations SET state='completed',result_json=$2,completed_at=$3 WHERE operation_id=$1`, wrongExecutionOperation, executionResult, now); err == nil || !strings.Contains(err.Error(), "completed ExecutionV2 secret operation owner scope does not match secret") {
		t.Fatalf("mismatched ExecutionV2 completion err=%v", err)
	}

	chatOwner := coretask.OwnerScope{OwnerID: "@chat-owner:example.test", AccountGeneration: 5}
	chatRequestID, chatStorageID, chatConversationID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	chatResult, err := json.Marshal(map[string]any{
		"request_id": chatRequestID, "conversation_id": chatConversationID,
		"revision": 1, "message": map[string]any{}, "done": true, "model_profile_id": uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_conversations(conversation_id,title,revision,created_at,updated_at,owner_id,account_generation) VALUES($1,'late chat',1,$2,$2,$3,$4)`, chatConversationID, now, chatOwner.OwnerID, chatOwner.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_chat_request_leases(
		request_id,conversation_id,idempotency_key,request_fingerprint,profile_id,
		profile_snapshot_json,profile_snapshot_digest,extensions_json,state,response_json,owner_id,account_generation
	) VALUES($1,$2,$3,$4,$5,'{}'::jsonb,$6,'[]'::jsonb,'completed',$7,$8,$9)`, chatStorageID, chatConversationID, chatRequestID, digest, uuid.NewString(), digest, chatResult, chatOwner.OwnerID, chatOwner.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	correctChatOperation := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,owner_id,account_generation
	) VALUES($1,'agent.chat.v1','chat','running',$2,$2,$3,$4)`, correctChatOperation, make([]byte, 32), chatOwner.OwnerID, chatOwner.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE agent_capability_operations SET state='completed',result_json=$2,completed_at=$3 WHERE operation_id=$1`, correctChatOperation, chatResult, now); err != nil {
		t.Fatalf("current Chat completion result rejected: %v", err)
	}
	wrongChatOperation := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,owner_id,account_generation
	) VALUES($1,'agent.chat.v1','chat','running',$2,$2,$3,$4)`, wrongChatOperation, make([]byte, 32), chatOwner.OwnerID, chatOwner.AccountGeneration+1); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE agent_capability_operations SET state='completed',result_json=$2,completed_at=$3 WHERE operation_id=$1`, wrongChatOperation, chatResult, now); err == nil || !strings.Contains(err.Error(), "completed Chat operation owner scope does not match request lease") {
		t.Fatalf("mismatched Chat completion err=%v", err)
	}

	store, err := New(pool, instanceID, testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	awsOwner := coreteam.Scope{OwnerID: "@aws-owner:example.test", AccountGeneration: 9}
	credentialID := uuid.NewString()
	credential := coreaws.RehydrateCredentials(credentialID, "late credential test", "us-east-1", "", "", []byte("access"), []byte("secret"), nil, 0, 1, now, now)
	if _, err = NewCoreAWSStore(store).CreateCredentialGuarded(ctx, awsOwner, credential); err != nil {
		t.Fatal(err)
	}
	awsTestResult, err := json.Marshal(map[string]any{"credential_id": credentialID})
	if err != nil {
		t.Fatal(err)
	}
	wrongAWSOperation := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,owner_id,account_generation
	) VALUES($1,'agent.aws.v1','test_credential','running',$2,$2,$3,$4)`, wrongAWSOperation, make([]byte, 32), awsOwner.OwnerID, awsOwner.AccountGeneration+1); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE agent_capability_operations SET state='completed',result_json=$2,completed_at=$3 WHERE operation_id=$1`, wrongAWSOperation, awsTestResult, now); err == nil || !strings.Contains(err.Error(), "completed AWS credential operation owner scope does not match credential") {
		t.Fatalf("mismatched AWS credential-test completion err=%v", err)
	}
	modelProfileID := uuid.NewString()
	createTestProfile(ctx, t, store, modelProfileID, "late-task-model", "late-task-secret")
	taskID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,'late task',$2,$3,'agent','{}','queued',1,$4,$4,$4)`, taskID, modelProfileID, uuid.NewString(), now); err != nil {
		t.Fatal(err)
	}
	taskResult, err := json.Marshal(map[string]any{"id": taskID})
	if err != nil {
		t.Fatal(err)
	}
	wrongTaskOperation := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,owner_id,account_generation
	) VALUES($1,'agent.tasks.v1','create_task','running',$2,$2,'@late-task-owner:example.test',12)`, wrongTaskOperation, make([]byte, 32)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE agent_capability_operations SET state='completed',result_json=$2,completed_at=$3 WHERE operation_id=$1`, wrongTaskOperation, taskResult, now); err == nil || !strings.Contains(err.Error(), "completed Task operation owner scope does not match task") {
		t.Fatalf("mismatched Task completion err=%v", err)
	}

	for _, op := range []struct {
		capabilityID  string
		operationName string
		owner         coretask.OwnerScope
		result        []byte
	}{
		{capabilityID: "agent.aws.v1", operationName: "test_credential", owner: coretask.OwnerScope{OwnerID: awsOwner.OwnerID, AccountGeneration: awsOwner.AccountGeneration}, result: awsTestResult},
		{capabilityID: "agent.knowledge.v1", operationName: "create_memory", owner: knowledgeOwner, result: knowledgeResult},
		{capabilityID: "agent.execution.v2", operationName: "secrets_create", owner: executionOwner, result: executionResult},
	} {
		operationID := uuid.NewString()
		if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
			operation_id,capability_id,operation_name,state,root_request_digest,request_digest,owner_id,account_generation
		) VALUES($1,$2,$3,'running',$4,$4,$5,$6)`, operationID, op.capabilityID, op.operationName, make([]byte, 32), op.owner.OwnerID, op.owner.AccountGeneration); err != nil {
			t.Fatal(err)
		}
		if _, err = pool.Exec(ctx, `UPDATE agent_capability_operations SET state='completed',result_json=$2,completed_at=$3 WHERE operation_id=$1`, operationID, op.result, now); err != nil {
			t.Fatalf("matching %s completion: %v", op.operationName, err)
		}
	}
}

func seedLegacyScheduleTriggerReplay(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner coretask.OwnerScope, malformed bool) (string, string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	scheduleID, occurrenceID, taskID, key := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,'legacy scheduled Task',$2,'aws_change','{}','queued',1,$3,$3,$3)`, taskID, uuid.NewString(), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_schedules(schedule_id,name,task_template,run_at,timezone,paused,next_run_at,revision,created_at,updated_at) VALUES($1,'legacy trigger','{}',$2,'UTC',false,$2,1,$3,$3)`, scheduleID, now.Add(time.Hour), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_schedule_occurrences(occurrence_id,schedule_id,scheduled_for,trigger_key,task_id,spec_snapshot_json,created_at) VALUES($1,$2,$3,$4,$5,'{}',$3)`, occurrenceID, scheduleID, now, key, taskID); err != nil {
		t.Fatal(err)
	}
	responseTaskID := taskID
	if malformed {
		responseTaskID = uuid.NewString()
	}
	response, err := json.Marshal(map[string]any{
		"schedule":   map[string]any{"id": scheduleID},
		"occurrence": map[string]any{"id": occurrenceID, "schedule_id": scheduleID, "task_id": responseTaskID},
		"task":       map[string]any{"id": taskID},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_schedule_replays(operation,idempotency_key,schedule_id,request_hash,response_json) VALUES('trigger_now',$1,$2,$3,$4)`, key, scheduleID, strings.Repeat("c", 64), response); err != nil {
		t.Fatal(err)
	}
	createResult, err := json.Marshal(map[string]any{"schedule": map[string]any{"id": scheduleID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,owner_id,account_generation,completed_at) VALUES($1,'agent.schedules.v1','create_schedule','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), createResult, owner.OwnerID, owner.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	return key, scheduleID
}

func seedLegacyKnowledgeUploadReplays(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner coretask.OwnerScope, malformed bool) (map[string]string, string) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	uploadID, sourceID := uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("d", 64)
	metadata, err := json.Marshal(coreknowledge.UploadMetadata{UploadID: uploadID, SourceID: sourceID, Title: "legacy upload", MediaType: "text/plain", DeclaredSize: 1, ContentSHA256: digest})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,created_at,updated_at) VALUES($1,'upload','uploading','legacy upload',$2,1,'text/plain',1,$3,$3)`, sourceID, digest, now); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_knowledge_uploads(upload_id,source_id,metadata_json,declared_size,content_digest,status,created_at,updated_at) VALUES($1,$2,$3,1,$4,'uploading',$5,$5)`, uploadID, sourceID, metadata, digest, now); err != nil {
		t.Fatal(err)
	}
	keys := map[string]string{
		"upload.start":  uuid.NewString(),
		"upload.chunk":  uuid.NewString(),
		"upload.abort":  uuid.NewString(),
		"upload.commit": uuid.NewString(),
	}
	for operation, key := range keys {
		responseUploadID := uploadID
		if malformed && operation == "upload.chunk" {
			responseUploadID = uuid.NewString()
		}
		response := map[string]any{"upload": map[string]any{"ID": responseUploadID, "SourceID": sourceID}}
		if operation == "upload.commit" {
			response = map[string]any{"pair": map[string]any{
				"upload": map[string]any{"ID": uploadID, "SourceID": sourceID},
				"source": map[string]any{"ID": sourceID},
			}}
		}
		raw, marshalErr := json.Marshal(response)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if _, err = pool.Exec(ctx, `INSERT INTO core_knowledge_mutation_replays(operation,idempotency_key,request_hash,response_json) VALUES($1,$2,$3,$4)`, operation, key, strings.Repeat("e", 64), raw); err != nil {
			t.Fatal(err)
		}
	}
	startResult, err := json.Marshal(map[string]any{"source_id": sourceID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,owner_id,account_generation,completed_at) VALUES($1,'agent.knowledge.v1','start_upload','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), startResult, owner.OwnerID, owner.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	return keys, sourceID
}

func seedLegacyExecutionV2State(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner coretask.OwnerScope, resourceID, eventID, secretRef, replayKey string, recoverSecret bool) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	digest := strings.Repeat("f", 64)
	if _, err := pool.Exec(ctx, `INSERT INTO core_execution_v2_records(owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at,updated_at) VALUES($1,'plan',$2,1,'ready',$3,'{}',$4,$4)`, owner.OwnerID, resourceID, digest, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_execution_v2_revisions(owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at) VALUES($1,'plan',$2,1,'ready',$3,'{}',$4)`, owner.OwnerID, resourceID, digest, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_execution_v2_events(owner_id,resource_type,resource_id,sequence,event_id,event_type,payload_json,created_at) VALUES($1,'plan',$2,1,$3,'created','{}',$4)`, owner.OwnerID, resourceID, eventID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_execution_v2_replays(owner_id,action,idempotency_key,request_digest,response_json,created_at) VALUES($1,'plans_create',$2,$3,'{}',$4)`, owner.OwnerID, replayKey, make([]byte, 32), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_execution_v2_secrets(owner_id,secret_ref,revision,provider,purpose,secret_key_version,secret_value_nonce,secret_value_ciphertext,binding_digest,status,created_at,updated_at) VALUES($1,$2,1,'openai','ai_provider_api_key',1,$3,$4,$5,'active',$6,$6)`, owner.OwnerID, secretRef, make([]byte, 12), make([]byte, 16), digest, now); err != nil {
		t.Fatal(err)
	}
	if !recoverSecret {
		return
	}
	result, err := json.Marshal(map[string]any{"secret": map[string]any{
		"secret_ref": secretRef, "revision": uint64(1), "provider": "openai", "purpose": "ai_provider_api_key",
		"binding_digest": digest, "status": "active",
		"created_at": now.Format(time.RFC3339Nano), "updated_at": now.Format(time.RFC3339Nano),
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,owner_id,account_generation,completed_at) VALUES($1,'agent.execution.v2','secrets_create','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), result, owner.OwnerID, owner.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
}

func assertLegacyV4MigrationRolledBack(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, column string) {
	t.Helper()
	var version3Count, version4Count, scopedColumns int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_schema_migrations WHERE version=3`).Scan(&version3Count); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM agent_schema_migrations WHERE version=4`).Scan(&version4Count); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name=$1 AND column_name=$2`, table, column).Scan(&scopedColumns); err != nil {
		t.Fatal(err)
	}
	if version3Count != 1 || version4Count != 0 || scopedColumns != 0 {
		t.Fatalf("failed migration version3=%d version4=%d %s.%s columns=%d, want v3 applied and v4 atomically rolled back", version3Count, version4Count, table, column, scopedColumns)
	}
}

func TestCoreExtensionReplayMigrationRejectsMismatchedDurableGraphAtomically(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_extension_bad_graph_")
	owner := coretask.OwnerScope{OwnerID: "@legacy-extension-owner:example.test", AccountGeneration: 7}
	mutation, expected := seedLegacyExtensionReplay(t, ctx, pool, owner)
	malformed, err := json.Marshal(coreextension.MutationResult{
		Installation:   expected.Installation,
		ConfirmationID: expected.ConfirmationID,
		TaskID:         uuid.NewString(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE core_extension_replays SET response_json=$2 WHERE operation='install' AND idempotency_key=$1`, mutation.IdempotencyKey, malformed); err != nil {
		t.Fatal(err)
	}

	err = ApplyMigrations(ctx, pool, instanceID)
	if err == nil || !strings.Contains(err.Error(), "unrecoverable legacy Core Extension lifecycle replay graph") {
		t.Fatalf("mismatched Extension replay migration err=%v", err)
	}
	var version4Count, legacyColumns int
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM agent_schema_migrations WHERE version=4`).Scan(&version4Count); queryErr != nil {
		t.Fatal(queryErr)
	}
	if queryErr := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='core_extension_replays' AND column_name IN ('owner_id','account_generation')`).Scan(&legacyColumns); queryErr != nil {
		t.Fatal(queryErr)
	}
	if version4Count != 0 || legacyColumns != 0 {
		t.Fatalf("failed Extension migration version4=%d scoped_columns=%d, want atomic rollback", version4Count, legacyColumns)
	}
}

func seedLegacyExtensionReplay(t *testing.T, ctx context.Context, pool *pgxpool.Pool, owner coretask.OwnerScope) (coreextension.Mutation, coreextension.MutationResult) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Microsecond)
	candidate, inspection := extensionFixture()
	installationID, versionID := uuid.NewString(), uuid.NewString()
	taskID, confirmationID, lifecycleID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	mutation := coreextension.Mutation{
		IdempotencyKey: uuid.NewString(),
		Candidate:      candidate,
		Inspection:     inspection,
		ArtifactPath:   "legacy/extension/fixture",
		ArtifactDigest: strings.Repeat("a", 64),
	}
	version := versionFromInspectionPG(inspection, uuid.MustParse(versionID), now, mutation)
	installation := coreextension.Installation{
		ID:                installationID,
		Candidate:         candidate,
		Kind:              candidate.Kind,
		Source:            candidate.Source,
		CandidateID:       candidate.ID,
		Name:              candidate.Name,
		Description:       candidate.Description,
		Transport:         candidate.Transport,
		Revision:          1,
		State:             coreextension.StateInstalling,
		ProposedVersionID: versionID,
		Versions:          []coreextension.VersionRecord{version},
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	candidateJSON, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_extension_installations(
		installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,
		active_version_id,proposed_version_id,network_grants_json,secret_grants_json,created_at,updated_at
	) VALUES($1,$2,$3,$4,$5,$6,$7,$8,1,'installing',false,NULL,$9,'[]','[]',$10,$10)`,
		installationID, candidateJSON, candidate.Kind, candidate.Source, candidate.ID, candidate.Name, candidate.Description, candidate.Transport, versionID, now); err != nil {
		t.Fatal(err)
	}
	versionJSON, err := json.Marshal(version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,$3,$4)`, versionID, installationID, versionJSON, now); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{
		Operation: coretask.ExtensionOperationInstall, InstallationID: installationID, ExpectedRevision: 1,
		Version: versionID, Digest: inspection.ContentDigest, ConfirmationID: confirmationID,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,'legacy extension install',NULL,$2,'extension',$3,'waiting_user',1,$4,$4,$4)`, taskID, mutation.IdempotencyKey, payload, now); err != nil {
		t.Fatal(err)
	}
	binding := bindingPG(installation, mutation)
	bindingJSON, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,'extension',$2,1,$3,$4,'pending',1,$5,$5,$6)`, confirmationID, installationID, bindingJSON, taskID, now, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json) VALUES($1,$2)`, confirmationID, bindingJSON); err != nil {
		t.Fatal(err)
	}
	requestHash := digestPG(mutation, coreextension.OperationInstall)
	if _, err = pool.Exec(ctx, `INSERT INTO core_extension_lifecycles(lifecycle_id,installation_id,operation,confirmation_id,task_id,binding_json,request_hash,expected_revision) VALUES($1,$2,'install',$3,$4,$5,$6,1)`, lifecycleID, installationID, confirmationID, taskID, bindingJSON, requestHash); err != nil {
		t.Fatal(err)
	}
	result := coreextension.MutationResult{Installation: installation, ConfirmationID: confirmationID, TaskID: taskID}
	resultJSON, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_extension_replays(operation,idempotency_key,request_hash,response_json) VALUES('install',$1,$2,$3)`, mutation.IdempotencyKey, requestHash, resultJSON); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO agent_capability_operations(
		operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,
		owner_id,account_generation,completed_at
	) VALUES($1,'agent.skills.v1','install_mcp','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), resultJSON, owner.OwnerID, owner.AccountGeneration, now); err != nil {
		t.Fatal(err)
	}
	return mutation, result
}

func legacyV2MigrationFixture(t *testing.T, schemaPrefix string) (context.Context, *pgxpool.Pool, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("AGENT_TEST_POSTGRES_DSN"))
	if dsn == "" {
		t.Skip("set AGENT_TEST_POSTGRES_DSN for Core AWS PostgreSQL migration integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	schema := schemaPrefix + strings.ReplaceAll(uuid.NewString(), "-", "")
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err = admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		admin.Close()
		cancel()
		t.Fatal(err)
	}
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
		cancel()
		t.Fatal(err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		_, _ = admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE")
		admin.Close()
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		pool.Close()
		cleanup, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if _, dropErr := admin.Exec(cleanup, "DROP SCHEMA "+quoted+" CASCADE"); dropErr != nil {
			t.Errorf("drop isolated schema: %v", dropErr)
		}
		admin.Close()
		cancel()
	})
	if _, err = pool.Exec(ctx, `CREATE TABLE agent_schema_migrations (
		version bigint PRIMARY KEY,
		checksum bytea NOT NULL CHECK (octet_length(checksum)=32),
		applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
	)`); err != nil {
		t.Fatal(err)
	}
	for _, migration := range migrations.Ordered()[:2] {
		if _, err = pool.Exec(ctx, string(migration.Script)); err != nil {
			t.Fatalf("apply legacy migration %d: %v", migration.Version, err)
		}
		checksum := sha256.Sum256(migration.Script)
		if _, err = pool.Exec(ctx, `INSERT INTO agent_schema_migrations(version,checksum) VALUES($1,$2)`, migration.Version, checksum[:]); err != nil {
			t.Fatal(err)
		}
	}
	instanceID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO agent_instance_metadata(agent_instance_id) VALUES($1)`, instanceID); err != nil {
		t.Fatal(err)
	}
	return ctx, pool, instanceID
}
