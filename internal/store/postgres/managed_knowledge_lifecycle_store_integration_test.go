package postgres_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managedlifecycle"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestManagedKnowledgeLifecycleFenceSerializesConcurrentPublicBindingUpdate(t *testing.T) {
	fixture := newManagedKnowledgeLifecycleFixture(t, managedlifecycle.ActionStop)
	configs, err := knowledge.NewPostgresRepository(fixture.pool, fixture.instanceID, knowledge.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	fenceResult, putResult := make(chan error, 1), make(chan error, 1)
	go func() {
		<-start
		fenceResult <- fixture.lifecycle.FenceManagedKnowledgeLifecycleExecution(
			context.Background(), fixture.assignment, fixture.now.Add(time.Second))
	}()
	go func() {
		<-start
		_, err := configs.PutConfig(context.Background(),
			knowledge.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
			knowledge.PutConfigCommand{
				IdempotencyKey: uuid.NewString(), OwnerID: fixture.ownerID, BindingID: fixture.bindingID,
				ExpectedRevision: fixture.bindingRevision,
				Spec: knowledge.ConfigSpec{
					DeploymentID: fixture.deploymentID, ManagedServiceID: fixture.serviceID,
					RecipeDigest: fixture.recipeDigest, EmbeddingProfileID: knowledge.LocalMultilingualE5SmallProfileID,
					Enabled: false,
				},
			})
		putResult <- err
	}()
	close(start)
	fenceErr, putErr := <-fenceResult, <-putResult

	switch {
	case fenceErr == nil:
		if !errors.Is(putErr, knowledge.ErrState) {
			t.Fatalf("reserved binding update error=%v", putErr)
		}
		fixture.assertRevisions(t, fixture.serviceRevision+1, fixture.bindingRevision, true, true)
	case putErr == nil:
		if !errors.Is(fenceErr, workeroperation.ErrRevisionConflict) {
			t.Fatalf("post-approval drift fence error=%v", fenceErr)
		}
		fixture.assertRevisions(t, fixture.serviceRevision, fixture.bindingRevision+1, false, false)
	default:
		t.Fatalf("fence error=%v binding update error=%v", fenceErr, putErr)
	}
}

func TestManagedKnowledgeLifecycleTerminalTransitionCASesReservationBeforeDestroyRelease(t *testing.T) {
	fixture := newManagedKnowledgeLifecycleFixture(t, managedlifecycle.ActionDestroy)
	ctx := context.Background()
	if err := fixture.lifecycle.FenceManagedKnowledgeLifecycleExecution(ctx, fixture.assignment, fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE managed_services SET revision=revision+1 WHERE service_id=$1`, fixture.serviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.lifecycle.Transition(ctx, fixture.operationID, fixture.operationRevision,
		managedlifecycle.StatusSucceeded, "", fixture.now.Add(2*time.Second)); !errors.Is(err, managedlifecycle.ErrRevisionConflict) {
		t.Fatalf("service revision drift terminal error=%v", err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE managed_services SET revision=$1 WHERE service_id=$2`,
		fixture.serviceRevision+1, fixture.serviceID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `UPDATE knowledge_configs SET revision=revision+1
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3`,
		fixture.instanceID, fixture.ownerID, fixture.bindingID); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.lifecycle.Transition(ctx, fixture.operationID, fixture.operationRevision,
		managedlifecycle.StatusSucceeded, "", fixture.now.Add(3*time.Second)); !errors.Is(err, managedlifecycle.ErrRevisionConflict) {
		t.Fatalf("binding revision drift terminal error=%v", err)
	}
	fixture.assertReservationActive(t)
	if _, err := fixture.pool.Exec(ctx, `UPDATE knowledge_configs SET revision=$1
		WHERE agent_instance_id=$2 AND owner_id=$3 AND binding_id=$4`,
		fixture.bindingRevision, fixture.instanceID, fixture.ownerID, fixture.bindingID); err != nil {
		t.Fatal(err)
	}
	completed, err := fixture.lifecycle.Transition(ctx, fixture.operationID, fixture.operationRevision,
		managedlifecycle.StatusSucceeded, "", fixture.now.Add(4*time.Second))
	if err != nil || completed.Status != managedlifecycle.StatusSucceeded {
		t.Fatalf("destroy completion=%+v error=%v", completed, err)
	}
	fixture.assertRevisions(t, fixture.serviceRevision+2, fixture.bindingRevision+1, false, false)
	var state string
	if err := fixture.pool.QueryRow(ctx, `SELECT state FROM managed_services WHERE service_id=$1`, fixture.serviceID).Scan(&state); err != nil || state != "destroyed" {
		t.Fatalf("managed service state=%q error=%v", state, err)
	}
}

func TestManagedKnowledgeLifecycleReservationSkipsHealthStateMutationAndAllowsTerminalCompletion(t *testing.T) {
	fixture := newManagedKnowledgeLifecycleFixture(t, managedlifecycle.ActionStop)
	ctx := context.Background()
	if err := fixture.lifecycle.FenceManagedKnowledgeLifecycleExecution(ctx, fixture.assignment, fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	planHash := "sha256:" + string(bytes.Repeat([]byte{'c'}, 64))
	suite := postgresHealthSuite(t, fixture.deploymentID, planHash, fixture.recipeDigest)
	suiteJSON, err := json.Marshal(suite)
	if err != nil {
		t.Fatal(err)
	}
	record := resource.ProbeMonitorRecord{
		DeploymentID: fixture.deploymentID, MonitorKind: resource.ProbeMonitorService, OwnerID: fixture.ownerID,
		Suite: suite, Interval: time.Minute, Status: healthprobe.AggregatePending, NextRunAt: fixture.now,
		Revision: 1, CreatedAt: fixture.now, UpdatedAt: fixture.now,
	}
	if record.Validate() != nil {
		t.Fatal("health monitor fixture is invalid")
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO deployment_health_monitors
		(deployment_id,monitor_kind,agent_instance_id,owner_id,plan_hash,recipe_digest,suite_json,interval_seconds,
		 aggregate_status,next_run_at,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,1,$9,$9)`,
		fixture.deploymentID, resource.ProbeMonitorService, fixture.instanceID, fixture.ownerID,
		planHash, fixture.recipeDigest, suiteJSON, int64(time.Minute/time.Second), fixture.now); err != nil {
		t.Fatal(err)
	}
	transport := &barrierHealthTransport{release: make(chan struct{}), digest: postgresHealthDigest("reserved-health")}
	close(transport.release)
	engine, err := healthprobe.NewEngine(transport)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := engine.RunExternalSuite(ctx, suite)
	if err != nil {
		t.Fatal(err)
	}
	base, err := postgres.New(fixture.pool, fixture.instanceID)
	if err != nil {
		t.Fatal(err)
	}
	healthStore, err := base.NewHealthProbeStore()
	if err != nil {
		t.Fatal(err)
	}
	saved, err := healthStore.SaveExternalProbe(ctx, record, evidence, fixture.now.Add(2*time.Second))
	if err != nil || saved.Status != healthprobe.AggregateDegraded {
		t.Fatalf("saved health=%+v error=%v", saved, err)
	}
	fixture.assertRevisions(t, fixture.serviceRevision+1, fixture.bindingRevision, true, true)
	var state string
	if err := fixture.pool.QueryRow(ctx, `SELECT state FROM managed_services WHERE service_id=$1`, fixture.serviceID).Scan(&state); err != nil {
		t.Fatal(err)
	}
	if state != "active" {
		t.Fatalf("reserved health reconciliation changed managed service state to %q", state)
	}
	completed, err := fixture.lifecycle.Transition(ctx, fixture.operationID, fixture.operationRevision,
		managedlifecycle.StatusSucceeded, "", fixture.now.Add(3*time.Second))
	if err != nil || completed.Status != managedlifecycle.StatusSucceeded {
		t.Fatalf("terminal lifecycle completion=%+v error=%v", completed, err)
	}
	fixture.assertRevisions(t, fixture.serviceRevision+2, fixture.bindingRevision+1, true, false)
	if err := fixture.pool.QueryRow(ctx, `SELECT state FROM managed_services WHERE service_id=$1`, fixture.serviceID).Scan(&state); err != nil || state != "stopped" {
		t.Fatalf("terminal managed service state=%q error=%v", state, err)
	}
}

func TestManagedKnowledgeBackupRestoreReconcilesExactCatalogGenerationAndFencesMutations(t *testing.T) {
	fixture := newManagedKnowledgeLifecycleFixture(t, managedlifecycle.ActionBackup)
	ctx := context.Background()
	sourceA, sourceB := uuid.NewString(), uuid.NewString()
	for _, sourceID := range []string{sourceA, sourceB} {
		if _, err := fixture.pool.Exec(ctx, `INSERT INTO knowledge_sources
			(agent_instance_id,owner_id,binding_id,source_id,kind,status,media_type,title,size_bytes,
			 content_sha256,backend_point_id,indexed_segment_count,chunk_count,revision,created_at,updated_at)
			VALUES($1,$2,$3,$4,'memory','ready','text/plain','snapshot source',4,$5,$6,1,1,1,$7,$7)`,
			fixture.instanceID, fixture.ownerID, fixture.bindingID, sourceID,
			"sha256:"+string(bytes.Repeat([]byte{'d'}, 64)), uuid.NewString(), fixture.now); err != nil {
			t.Fatal(err)
		}
	}
	uploadSource, uploadID := uuid.NewString(), uuid.NewString()
	secretCanary := []byte("private-snapshot-canary-sk-0123456789abcdefghijklmnopqrstuvwxyz")
	firstChunk := secretCanary[:16]
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO knowledge_sources
		(agent_instance_id,owner_id,binding_id,source_id,kind,status,media_type,title,size_bytes,
		 content_sha256,indexed_segment_count,error_code,chunk_count,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,'attachment','uploading','text/plain','partial upload',$5,'',0,'',1,1,$6,$6)`,
		fixture.instanceID, fixture.ownerID, fixture.bindingID, uploadSource, len(secretCanary), fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO knowledge_uploads
		(agent_instance_id,owner_id,binding_id,source_id,upload_id,status,media_type,declared_size_bytes,
		 received_size_bytes,next_chunk_ordinal,binding_revision,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,'receiving','text/plain',$6,$7,1,$8,1,$9,$9)`,
		fixture.instanceID, fixture.ownerID, fixture.bindingID, uploadSource, uploadID, len(secretCanary),
		len(firstChunk), fixture.bindingRevision, fixture.now); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(ctx, `INSERT INTO knowledge_upload_chunks
		(agent_instance_id,owner_id,binding_id,upload_id,chunk_ordinal,offset_bytes,size_bytes,chunk_sha256,created_at)
		VALUES($1,$2,$3,$4,0,0,$5,$6,$7)`,
		fixture.instanceID, fixture.ownerID, fixture.bindingID, uploadID, len(firstChunk),
		knowledge.SHA256(firstChunk), fixture.now); err != nil {
		t.Fatal(err)
	}
	if err := fixture.lifecycle.FenceManagedKnowledgeLifecycleExecution(ctx, fixture.assignment, fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	generation := "sha256:" + string(bytes.Repeat([]byte{'e'}, 64))
	fixture.persistSucceededWorkerGeneration(t, fixture.assignment, generation, fixture.now.Add(2*time.Second))
	if _, err := fixture.lifecycle.Transition(ctx, fixture.operationID, fixture.operationRevision,
		managedlifecycle.StatusSucceeded, "", fixture.now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	var (
		executionCatalogDigest, generationCatalogDigest  string
		snapshotSources, snapshotUploads, snapshotChunks int
	)
	if err := fixture.pool.QueryRow(ctx, `SELECT l.execution_catalog_digest,g.catalog_digest,
		(SELECT count(*) FROM knowledge_data_snapshot_sources s WHERE s.snapshot_operation_id=l.operation_id),
		(SELECT count(*) FROM knowledge_data_snapshot_uploads u WHERE u.snapshot_operation_id=l.operation_id),
		(SELECT count(*) FROM knowledge_data_snapshot_chunks c WHERE c.snapshot_operation_id=l.operation_id)
		FROM managed_knowledge_lifecycle_operations l
		JOIN knowledge_data_generations g ON g.snapshot_operation_id=l.operation_id
		WHERE l.operation_id=$1`, fixture.operationID,
	).Scan(&executionCatalogDigest, &generationCatalogDigest, &snapshotSources, &snapshotUploads, &snapshotChunks); err != nil {
		t.Fatal(err)
	}
	if executionCatalogDigest != generationCatalogDigest || !strings.HasPrefix(executionCatalogDigest, "sha256:") ||
		snapshotSources != 3 || snapshotUploads != 1 || snapshotChunks != 1 {
		t.Fatalf("normalized snapshot digest=%q generation digest=%q rows=(%d,%d,%d)",
			executionCatalogDigest, generationCatalogDigest, snapshotSources, snapshotUploads, snapshotChunks)
	}
	var leaked bool
	if err := fixture.pool.QueryRow(ctx, `SELECT EXISTS (
		SELECT 1 FROM knowledge_configs v WHERE to_jsonb(v)::text LIKE $1
		UNION ALL SELECT 1 FROM knowledge_sources v WHERE to_jsonb(v)::text LIKE $1
		UNION ALL SELECT 1 FROM knowledge_uploads v WHERE to_jsonb(v)::text LIKE $1
		UNION ALL SELECT 1 FROM knowledge_upload_chunks v WHERE to_jsonb(v)::text LIKE $1
		UNION ALL SELECT 1 FROM knowledge_data_snapshot_sources v WHERE to_jsonb(v)::text LIKE $1
		UNION ALL SELECT 1 FROM knowledge_data_snapshot_uploads v WHERE to_jsonb(v)::text LIKE $1
		UNION ALL SELECT 1 FROM knowledge_data_snapshot_chunks v WHERE to_jsonb(v)::text LIKE $1
		UNION ALL SELECT 1 FROM knowledge_data_generations v WHERE to_jsonb(v)::text LIKE $1
	)`, "%"+string(secretCanary)+"%").Scan(&leaked); err != nil {
		t.Fatal(err)
	}
	if leaked {
		t.Fatal("Knowledge catalog snapshot persisted secret content")
	}
	repository, err := knowledge.NewPostgresRepository(fixture.pool, fixture.instanceID, knowledge.DefaultCatalog())
	if err != nil {
		t.Fatal(err)
	}
	postBackupSource := uuid.NewString()
	postBackupContent := []byte("post")
	postBackupDigest := knowledge.SHA256(postBackupContent)
	mutationScope := knowledge.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()}
	createCommand := knowledge.CreateMemoryCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: fixture.ownerID, BindingID: fixture.bindingID,
		SourceID: postBackupSource, ExpectedBindingRevision: fixture.bindingRevision + 1,
		Content: postBackupContent, ContentSHA256: postBackupDigest, Title: "post-backup",
	}
	if _, err := repository.CreateMemory(ctx, mutationScope, createCommand,
		func(context.Context, knowledge.MemoryContent) (knowledge.ContentReceipt, error) {
			return knowledge.ContentReceipt{
				SizeBytes: 4, ContentSHA256: postBackupDigest, PointID: uuid.NewString(), IndexedSegmentCount: 1,
			}, nil
		}); err != nil {
		t.Fatal(err)
	}
	deleteCommand := knowledge.DeleteSourceCommand{
		IdempotencyKey: uuid.NewString(), OwnerID: fixture.ownerID, BindingID: fixture.bindingID,
		SourceID: sourceA, ExpectedBindingRevision: fixture.bindingRevision + 1, ExpectedSourceRevision: 1,
	}
	if _, err := repository.DeleteSource(ctx, mutationScope, deleteCommand,
		func(context.Context, knowledge.SourceTarget) error { return nil }); err != nil {
		t.Fatal(err)
	}

	restore := fixture.insertLifecycleOperation(t, managedlifecycle.ActionRestore,
		fixture.serviceRevision+2, fixture.bindingRevision+1, fixture.now.Add(4*time.Second))
	if err := fixture.lifecycle.FenceManagedKnowledgeLifecycleExecution(ctx, restore.assignment, fixture.now.Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	createResult, deleteResult := make(chan error, 1), make(chan error, 1)
	go func() {
		content := []byte("blocked")
		_, err := repository.CreateMemory(context.Background(),
			knowledge.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
			knowledge.CreateMemoryCommand{
				IdempotencyKey: uuid.NewString(), OwnerID: fixture.ownerID, BindingID: fixture.bindingID,
				SourceID: uuid.NewString(), ExpectedBindingRevision: fixture.bindingRevision + 1,
				Content: content, ContentSHA256: knowledge.SHA256(content),
				Title: "blocked",
			}, func(context.Context, knowledge.MemoryContent) (knowledge.ContentReceipt, error) {
				return knowledge.ContentReceipt{}, errors.New("backend must not be reached")
			})
		createResult <- err
	}()
	go func() {
		_, err := repository.DeleteSource(context.Background(),
			knowledge.MutationScope{ClientID: "message-server", CredentialID: uuid.NewString()},
			knowledge.DeleteSourceCommand{
				IdempotencyKey: uuid.NewString(), OwnerID: fixture.ownerID, BindingID: fixture.bindingID,
				SourceID: sourceB, ExpectedBindingRevision: fixture.bindingRevision + 1, ExpectedSourceRevision: 1,
			}, func(context.Context, knowledge.SourceTarget) error {
				return errors.New("backend must not be reached")
			})
		deleteResult <- err
	}()
	if err := <-createResult; !errors.Is(err, knowledge.ErrState) {
		t.Fatalf("concurrent create during restore error=%v", err)
	}
	if err := <-deleteResult; !errors.Is(err, knowledge.ErrState) {
		t.Fatalf("concurrent delete during restore error=%v", err)
	}
	fixture.persistSucceededWorkerGeneration(t, restore.assignment, generation, fixture.now.Add(6*time.Second))
	completed, err := fixture.lifecycle.Transition(ctx, restore.operationID, restore.operationRevision,
		managedlifecycle.StatusSucceeded, "", fixture.now.Add(7*time.Second))
	if err != nil || completed.Status != managedlifecycle.StatusSucceeded {
		t.Fatalf("restore completion=%+v error=%v", completed, err)
	}
	replayed, err := fixture.lifecycle.Get(ctx, fixture.ownerID, restore.operationID)
	if err != nil || replayed.Revision != completed.Revision || replayed.Status != managedlifecycle.StatusSucceeded {
		t.Fatalf("response-loss replay=%+v error=%v", replayed, err)
	}
	var dataEpoch, bindingRevision int64
	var storedGeneration string
	if err := fixture.pool.QueryRow(ctx, `SELECT data_epoch,backend_generation_digest,revision
		FROM knowledge_configs WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3`,
		fixture.instanceID, fixture.ownerID, fixture.bindingID,
	).Scan(&dataEpoch, &storedGeneration, &bindingRevision); err != nil {
		t.Fatal(err)
	}
	if dataEpoch != 4 || storedGeneration != generation || bindingRevision != fixture.bindingRevision+2 {
		t.Fatalf("restored epoch=%d generation=%q binding revision=%d", dataEpoch, storedGeneration, bindingRevision)
	}
	var ready, postBackup int
	if err := fixture.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE source_id=ANY($4) AND status='ready'),
		count(*) FILTER (WHERE source_id=$5)
		FROM knowledge_sources
		WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3`,
		fixture.instanceID, fixture.ownerID, fixture.bindingID,
		[]uuid.UUID{uuid.MustParse(sourceA), uuid.MustParse(sourceB)}, postBackupSource,
	).Scan(&ready, &postBackup); err != nil {
		t.Fatal(err)
	}
	if ready != 2 || postBackup != 0 {
		t.Fatalf("restored ready sources=%d post-backup sources=%d", ready, postBackup)
	}
	var (
		restoredSourceStatus, restoredUploadStatus string
		restoredSourceChunks, restoredReceived     int
		restoredNextChunk                          int
		restoredUploadBindingRevision              int64
		restoredChunkCount, restoredChunkBytes     int
	)
	if err := fixture.pool.QueryRow(ctx, `SELECT s.status,s.chunk_count,u.status,u.received_size_bytes,
		u.next_chunk_ordinal,u.binding_revision,
		(SELECT count(*) FROM knowledge_upload_chunks c
		 WHERE c.agent_instance_id=u.agent_instance_id AND c.owner_id=u.owner_id
		   AND c.binding_id=u.binding_id AND c.upload_id=u.upload_id),
		(SELECT COALESCE(sum(size_bytes),0) FROM knowledge_upload_chunks c
		 WHERE c.agent_instance_id=u.agent_instance_id AND c.owner_id=u.owner_id
		   AND c.binding_id=u.binding_id AND c.upload_id=u.upload_id)
		FROM knowledge_sources s
		JOIN knowledge_uploads u USING (agent_instance_id,owner_id,binding_id,source_id)
		WHERE s.agent_instance_id=$1 AND s.owner_id=$2 AND s.binding_id=$3 AND s.source_id=$4`,
		fixture.instanceID, fixture.ownerID, fixture.bindingID, uploadSource,
	).Scan(&restoredSourceStatus, &restoredSourceChunks, &restoredUploadStatus, &restoredReceived,
		&restoredNextChunk, &restoredUploadBindingRevision, &restoredChunkCount, &restoredChunkBytes); err != nil {
		t.Fatal(err)
	}
	if restoredSourceStatus != "uploading" || restoredSourceChunks != 1 ||
		restoredUploadStatus != "receiving" || restoredReceived != len(firstChunk) ||
		restoredNextChunk != 1 || restoredUploadBindingRevision != fixture.bindingRevision+2 ||
		restoredChunkCount != 1 || restoredChunkBytes != len(firstChunk) {
		t.Fatalf("restored partial upload source=(%s,%d) upload=(%s,%d,%d,%d) chunks=(%d,%d)",
			restoredSourceStatus, restoredSourceChunks, restoredUploadStatus, restoredReceived,
			restoredNextChunk, restoredUploadBindingRevision, restoredChunkCount, restoredChunkBytes)
	}
	if _, err := repository.CreateMemory(ctx, mutationScope, createCommand,
		func(context.Context, knowledge.MemoryContent) (knowledge.ContentReceipt, error) {
			return knowledge.ContentReceipt{}, errors.New("stale create replay reached backend")
		}); !errors.Is(err, knowledge.ErrState) {
		t.Fatalf("post-restore stale create replay error=%v", err)
	}
	if _, err := repository.DeleteSource(ctx, mutationScope, deleteCommand,
		func(context.Context, knowledge.SourceTarget) error {
			return errors.New("stale delete replay reached backend")
		}); !errors.Is(err, knowledge.ErrState) {
		t.Fatalf("post-restore stale delete replay error=%v", err)
	}
}

func TestManagedKnowledgeConsecutiveUnchangedGenerationOperationsTerminate(t *testing.T) {
	for _, action := range []managedlifecycle.Action{
		managedlifecycle.ActionBackup,
		managedlifecycle.ActionUpgrade,
	} {
		t.Run(string(action), func(t *testing.T) {
			fixture := newManagedKnowledgeLifecycleFixture(t, action)
			ctx := context.Background()
			generation := "sha256:" + string(bytes.Repeat([]byte{'7'}, 64))
			if err := fixture.lifecycle.FenceManagedKnowledgeLifecycleExecution(
				ctx, fixture.assignment, fixture.now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			fixture.persistSucceededWorkerGeneration(t, fixture.assignment, generation, fixture.now.Add(2*time.Second))
			first, err := fixture.lifecycle.Transition(ctx, fixture.operationID, fixture.operationRevision,
				managedlifecycle.StatusSucceeded, "", fixture.now.Add(3*time.Second))
			if err != nil || first.Status != managedlifecycle.StatusSucceeded {
				t.Fatalf("first unchanged %s completion=%+v error=%v", action, first, err)
			}
			secondFixture := fixture.insertLifecycleOperation(
				t, action, fixture.serviceRevision+2, fixture.bindingRevision+1, fixture.now.Add(4*time.Second))
			if err := fixture.lifecycle.FenceManagedKnowledgeLifecycleExecution(
				ctx, secondFixture.assignment, fixture.now.Add(5*time.Second)); err != nil {
				t.Fatal(err)
			}
			fixture.persistSucceededWorkerGeneration(
				t, secondFixture.assignment, generation, fixture.now.Add(6*time.Second))
			second, err := fixture.lifecycle.Transition(ctx, secondFixture.operationID,
				secondFixture.operationRevision, managedlifecycle.StatusSucceeded, "", fixture.now.Add(7*time.Second))
			if err != nil || second.Status != managedlifecycle.StatusSucceeded {
				t.Fatalf("second unchanged %s completion=%+v error=%v", action, second, err)
			}
			var generations, activeReservations int
			if err := fixture.pool.QueryRow(ctx, `SELECT
				(SELECT count(*) FROM knowledge_data_generations
				 WHERE agent_instance_id=$1 AND owner_id=$2 AND binding_id=$3),
				(SELECT count(*) FROM managed_knowledge_lifecycle_operations
				 WHERE agent_instance_id=$1 AND knowledge_binding_id=$3
				   AND execution_fenced_at IS NOT NULL AND reservation_released_at IS NULL)`,
				fixture.instanceID, fixture.ownerID, fixture.bindingID,
			).Scan(&generations, &activeReservations); err != nil {
				t.Fatal(err)
			}
			if generations != 1 || activeReservations != 0 {
				t.Fatalf("unchanged %s generations=%d active reservations=%d",
					action, generations, activeReservations)
			}
		})
	}
}

func TestManagedKnowledgeFailedSwapActionsRemainFencedWithoutSignedGeneration(t *testing.T) {
	for _, action := range []managedlifecycle.Action{
		managedlifecycle.ActionRestore,
		managedlifecycle.ActionRollback,
		managedlifecycle.ActionUpgrade,
	} {
		t.Run(string(action), func(t *testing.T) {
			fixture := newManagedKnowledgeLifecycleFixture(t, action)
			if action == managedlifecycle.ActionRestore || action == managedlifecycle.ActionRollback {
				_ = seedManagedKnowledgeGeneration(t, fixture)
			}
			ctx := context.Background()
			if err := fixture.lifecycle.FenceManagedKnowledgeLifecycleExecution(
				ctx, fixture.assignment, fixture.now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			current, err := fixture.lifecycle.Transition(ctx, fixture.operationID, fixture.operationRevision,
				managedlifecycle.StatusFailed, "root_helper_failed", fixture.now.Add(2*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if current.Status != managedlifecycle.StatusRunning || current.Revision != fixture.operationRevision {
				t.Fatalf("unsigned failed %s escaped recovery fence: %+v", action, current)
			}
			fixture.assertRevisions(t, fixture.serviceRevision+1, fixture.bindingRevision, true, true)
		})
	}
}

func TestManagedKnowledgeSignedOriginalGenerationClosesFailedRestoreDeterministically(t *testing.T) {
	for _, action := range []managedlifecycle.Action{
		managedlifecycle.ActionRestore,
		managedlifecycle.ActionRollback,
	} {
		t.Run(string(action), func(t *testing.T) {
			fixture := newManagedKnowledgeLifecycleFixture(t, action)
			targetGeneration := seedManagedKnowledgeGeneration(t, fixture)
			sourceID := uuid.NewString()
			if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO knowledge_sources
				(agent_instance_id,owner_id,binding_id,source_id,kind,status,media_type,title,size_bytes,
				 content_sha256,backend_point_id,indexed_segment_count,error_code,chunk_count,
				 revision,created_at,updated_at)
				VALUES($1,$2,$3,$4,'memory','ready','text/plain','original catalog',4,$5,$6,1,'',1,1,$7,$7)`,
				fixture.instanceID, fixture.ownerID, fixture.bindingID, sourceID,
				"sha256:"+string(bytes.Repeat([]byte{'4'}, 64)), uuid.NewString(), fixture.now); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := fixture.lifecycle.FenceManagedKnowledgeLifecycleExecution(
				ctx, fixture.assignment, fixture.now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			originalGeneration := "sha256:" + string(bytes.Repeat([]byte{'8'}, 64))
			if originalGeneration == targetGeneration {
				t.Fatal("invalid generation fixture")
			}
			fixture.persistSucceededWorkerGeneration(
				t, fixture.assignment, originalGeneration, fixture.now.Add(2*time.Second))
			completed, err := fixture.lifecycle.Transition(ctx, fixture.operationID, fixture.operationRevision,
				managedlifecycle.StatusSucceeded, "", fixture.now.Add(3*time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if completed.Status != managedlifecycle.StatusFailed ||
				completed.ErrorCode != "recovered_original_generation" {
				t.Fatalf("signed original %s completion=%+v", action, completed)
			}
			fixture.assertRevisions(t, fixture.serviceRevision+2, fixture.bindingRevision+1, true, false)
			var storedGeneration string
			var retainedSources, generations int
			if err := fixture.pool.QueryRow(ctx, `SELECT k.backend_generation_digest,
				(SELECT count(*) FROM knowledge_sources s
				 WHERE s.agent_instance_id=k.agent_instance_id AND s.owner_id=k.owner_id
				   AND s.binding_id=k.binding_id AND s.source_id=$4),
				(SELECT count(*) FROM knowledge_data_generations g
				 WHERE g.agent_instance_id=k.agent_instance_id AND g.owner_id=k.owner_id
				   AND g.binding_id=k.binding_id)
				FROM knowledge_configs k
				WHERE k.agent_instance_id=$1 AND k.owner_id=$2 AND k.binding_id=$3`,
				fixture.instanceID, fixture.ownerID, fixture.bindingID, sourceID,
			).Scan(&storedGeneration, &retainedSources, &generations); err != nil {
				t.Fatal(err)
			}
			if storedGeneration != originalGeneration || retainedSources != 1 || generations != 2 {
				t.Fatalf("signed original %s generation=%q sources=%d generations=%d",
					action, storedGeneration, retainedSources, generations)
			}
		})
	}
}

type managedKnowledgeLifecycleFixture struct {
	pool                                                    *pgxpool.Pool
	lifecycle                                               *postgres.ManagedKnowledgeLifecycleStore
	instanceID, ownerID, deploymentID, serviceID, bindingID string
	operationID, workerOperationID, recipeDigest            string
	serviceRevision, bindingRevision, operationRevision     int64
	assignment                                              workeroperation.Assignment
	now                                                     time.Time
}

func seedManagedKnowledgeGeneration(t *testing.T, fixture managedKnowledgeLifecycleFixture) string {
	t.Helper()
	operationID := uuid.NewString()
	catalogDigest := "sha256:" + string(bytes.Repeat([]byte{'6'}, 64))
	generation := "sha256:" + string(bytes.Repeat([]byte{'5'}, 64))
	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO managed_knowledge_lifecycle_operations
		(operation_id,agent_instance_id,owner_id,deployment_id,managed_service_id,knowledge_binding_id,
		 action,status,worker_operation_id,revision,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,'backup','failed',$7,1,'{}',$8,$8)`,
		operationID, fixture.instanceID, fixture.ownerID, fixture.deploymentID, fixture.serviceID,
		fixture.bindingID, uuid.NewString(), fixture.now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO knowledge_data_generations
		(agent_instance_id,owner_id,binding_id,backend_generation_digest,catalog_digest,
		 data_epoch,snapshot_operation_id,created_at)
		VALUES($1,$2,$3,$4,$5,1,$6,$7)`,
		fixture.instanceID, fixture.ownerID, fixture.bindingID, generation, catalogDigest,
		operationID, fixture.now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	return generation
}

type lifecycleOperationFixture struct {
	operationID, workerOperationID string
	operationRevision              int64
	assignment                     workeroperation.Assignment
}

func (fixture managedKnowledgeLifecycleFixture) insertLifecycleOperation(t *testing.T, action managedlifecycle.Action,
	serviceRevision, bindingRevision int64, at time.Time,
) lifecycleOperationFixture {
	t.Helper()
	operationID, workerOperationID := uuid.NewString(), uuid.NewString()
	scope := managedlifecycle.ScopeV1{
		SchemaVersion: managedlifecycle.ScopeSchemaV1, AgentInstanceID: fixture.instanceID, OwnerID: fixture.ownerID,
		DeploymentID: fixture.deploymentID, ManagedServiceID: fixture.serviceID, KnowledgeBindingID: fixture.bindingID,
		DeploymentRevision: 7, ManagedServiceRevision: serviceRevision, KnowledgeBindingRevision: bindingRevision,
		RecipeDigest: fixture.recipeDigest, Action: action, LifecycleRef: "lifecycle-" + string(action),
		ExecutionBundleDigest:   "sha256:" + hex.EncodeToString(bytes.Repeat([]byte{0x42}, 32)),
		InstalledManifestDigest: "sha256:" + string(bytes.Repeat([]byte{'b'}, 64)),
	}
	scopeDigest, err := managedlifecycle.ScopeDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	challenge := managedlifecycle.ChallengeV1{
		OperationID: operationID, ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(), SignerKeyID: "owner-device",
		Scope: scope, ScopeDigest: scopeDigest, IssuedAt: at.Add(-time.Minute), ExpiresAt: at.Add(time.Minute), Revision: 1,
	}
	challenge.SigningCBOR, err = challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	approvedAt := at.Add(-30 * time.Second)
	const operationRevision = int64(3)
	operation := managedlifecycle.OperationV1{
		Challenge: challenge, Status: managedlifecycle.StatusRunning, WorkerOperationID: workerOperationID,
		Revision: operationRevision, CreatedAt: challenge.IssuedAt, UpdatedAt: at, ApprovedAt: &approvedAt,
	}
	snapshot, err := json.Marshal(operation)
	if err != nil || operation.Validate() != nil {
		t.Fatalf("lifecycle operation fixture error=%v", err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO managed_knowledge_lifecycle_operations
		(operation_id,agent_instance_id,owner_id,deployment_id,managed_service_id,knowledge_binding_id,action,status,
		 worker_operation_id,revision,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,'running',$8,$9,$10,$11,$12)`,
		operationID, fixture.instanceID, fixture.ownerID, fixture.deploymentID, fixture.serviceID,
		fixture.bindingID, action, workerOperationID, operationRevision, snapshot, operation.CreatedAt, operation.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	return lifecycleOperationFixture{
		operationID: operationID, workerOperationID: workerOperationID, operationRevision: operationRevision,
		assignment: workeroperation.Assignment{
			OperationID: workerOperationID, DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID,
			Action: workeroperation.Action(action), LifecycleRestartRef: scope.LifecycleRef,
			ExecutionBundleDigest: scope.ExecutionBundleDigest, ExpectedInstalledManifestDigest: scope.InstalledManifestDigest,
			ExpectedDeploymentRevision: scope.DeploymentRevision, ExpectedManagedServiceRevision: serviceRevision,
			ExpectedKnowledgeBindingRevision: bindingRevision,
		},
	}
}

func (fixture managedKnowledgeLifecycleFixture) persistSucceededWorkerGeneration(t *testing.T,
	assignment workeroperation.Assignment, generation string, at time.Time,
) {
	t.Helper()
	receipt := workeroperation.RootHelperReceipt{
		SchemaVersion: workeroperation.SchemaV1, OperationID: assignment.OperationID,
		DeploymentID: assignment.DeploymentID, OwnerID: assignment.OwnerID, Action: assignment.Action,
		LifecycleRestartRef: assignment.LifecycleRestartRef, ExecutionBundleDigest: assignment.ExecutionBundleDigest,
		LeaseEpoch: 1, InstallManifestDigest: assignment.ExpectedInstalledManifestDigest,
		RestartObservationDigest: generation, ExpectedDeploymentRevision: assignment.ExpectedDeploymentRevision,
		ExpectedManagedServiceRevision:   assignment.ExpectedManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: assignment.ExpectedKnowledgeBindingRevision,
		ObservedAt:                       at, HelperID: "root-helper", SignerKeyID: "root-helper-key",
		Signature: bytes.Repeat([]byte{1}, 64),
	}
	operation := workeroperation.Operation{
		SchemaVersion: workeroperation.SchemaV1, OperationID: assignment.OperationID,
		DeploymentID: assignment.DeploymentID, OwnerID: assignment.OwnerID, Action: assignment.Action,
		LifecycleRestartRef: assignment.LifecycleRestartRef, ExecutionBundleDigest: assignment.ExecutionBundleDigest,
		ExpectedInstalledManifestDigest:  assignment.ExpectedInstalledManifestDigest,
		ExpectedDeploymentRevision:       assignment.ExpectedDeploymentRevision,
		ExpectedManagedServiceRevision:   assignment.ExpectedManagedServiceRevision,
		ExpectedKnowledgeBindingRevision: assignment.ExpectedKnowledgeBindingRevision,
		State:                            workeroperation.StateSucceeded, WorkerID: uuid.NewString(), LeaseEpoch: 1, Receipt: &receipt,
		Revision: 3, CreatedAt: at.Add(-2 * time.Second), UpdatedAt: at.Add(time.Second),
	}
	if operation.Validate() != nil {
		t.Fatal("succeeded Worker generation fixture is invalid")
	}
	snapshot, err := json.Marshal(operation)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.pool.Exec(context.Background(), `INSERT INTO worker_service_operations
		(operation_id,agent_instance_id,deployment_id,owner_id,action,lifecycle_restart_ref,execution_bundle_digest,
		 expected_installed_manifest_digest,state,worker_id,lease_epoch,revision,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,'succeeded',$9,1,3,$10,$11,$12)`,
		operation.OperationID, fixture.instanceID, operation.DeploymentID, operation.OwnerID, operation.Action,
		operation.LifecycleRestartRef, operation.ExecutionBundleDigest, operation.ExpectedInstalledManifestDigest,
		operation.WorkerID, snapshot, operation.CreatedAt, operation.UpdatedAt); err != nil {
		t.Fatal(err)
	}
}

func newManagedKnowledgeLifecycleFixture(t *testing.T, action managedlifecycle.Action) managedKnowledgeLifecycleFixture {
	t.Helper()
	pool, store, instanceID := newPlanningTestStore(t)
	taskID, stepID := createWorkerTask(t, store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	ownerID := "owner-worker-store"
	deploymentID, serviceID, bindingID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	operationID, workerOperationID := uuid.NewString(), uuid.NewString()
	executionDigest := bytes.Repeat([]byte{0x42}, 32)
	recipeDigest := "sha256:" + string(bytes.Repeat([]byte{'a'}, 64))
	const deploymentRevision, serviceRevision, bindingRevision, operationRevision int64 = 7, 11, 13, 3
	if _, err := pool.Exec(context.Background(), `INSERT INTO worker_deployments
		(deployment_id,agent_instance_id,owner_id,task_id,step_id,control_plane_endpoint,recipe_bundle_ref,recipe_bundle_sha256,
		 execution_bundle_ref,execution_bundle_sha256,execution_timeout_seconds,worker_id,state,outcome,artifact_prefix,checkpoint_prefix,
		 evidence_prefix,log_prefix,enrollment_digest,enrollment_expires_at,session_digest,enrollment_consumed_at,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,'grpcs://agent.example:8443','s3://bucket/recipe',$6,'s3://bucket/execution',$7,3600,$8,
		 'finished','succeeded','s3://bucket/artifacts/','s3://bucket/checkpoints/','s3://bucket/evidence/',
		 'cloudwatch://managed/logs',$9,$10,$11,$12,$13,$14,$14)`,
		deploymentID, instanceID, ownerID, taskID, stepID, bytes.Repeat([]byte{1}, 32), executionDigest,
		uuid.NewString(), bytes.Repeat([]byte{2}, 32), now.Add(time.Hour), bytes.Repeat([]byte{3}, 32), now,
		deploymentRevision, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO managed_services
		(service_id,deployment_id,agent_instance_id,owner_id,contract_json,state,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,'{}','active',$5,$6,$6)`,
		serviceID, deploymentID, instanceID, ownerID, serviceRevision, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO knowledge_configs
		(agent_instance_id,owner_id,binding_id,deployment_id,managed_service_id,recipe_digest,embedding_profile_id,enabled,revision,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,true,$8,$9,$9)`,
		instanceID, ownerID, bindingID, deploymentID, serviceID, recipeDigest,
		knowledge.LocalMultilingualE5SmallProfileID, bindingRevision, now); err != nil {
		t.Fatal(err)
	}
	scope := managedlifecycle.ScopeV1{
		SchemaVersion: managedlifecycle.ScopeSchemaV1, AgentInstanceID: instanceID, OwnerID: ownerID,
		DeploymentID: deploymentID, ManagedServiceID: serviceID, KnowledgeBindingID: bindingID,
		DeploymentRevision: deploymentRevision, ManagedServiceRevision: serviceRevision,
		KnowledgeBindingRevision: bindingRevision, RecipeDigest: recipeDigest, Action: action,
		LifecycleRef: "lifecycle-" + string(action), ExecutionBundleDigest: "sha256:" + hex.EncodeToString(executionDigest),
		InstalledManifestDigest: "sha256:" + string(bytes.Repeat([]byte{'b'}, 64)),
	}
	scopeDigest, err := managedlifecycle.ScopeDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	challenge := managedlifecycle.ChallengeV1{
		OperationID: operationID, ChallengeID: uuid.NewString(), ApprovalID: uuid.NewString(), SignerKeyID: "owner-device",
		Scope: scope, ScopeDigest: scopeDigest, IssuedAt: now.Add(-time.Minute), ExpiresAt: now.Add(time.Minute), Revision: 1,
	}
	challenge.SigningCBOR, err = challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	approvedAt := now.Add(-30 * time.Second)
	operation := managedlifecycle.OperationV1{
		Challenge: challenge, Status: managedlifecycle.StatusRunning, WorkerOperationID: workerOperationID,
		Revision: operationRevision, CreatedAt: challenge.IssuedAt, UpdatedAt: now, ApprovedAt: &approvedAt,
	}
	snapshot, err := json.Marshal(operation)
	if err != nil || operation.Validate() != nil {
		t.Fatalf("lifecycle fixture error=%v", err)
	}
	if _, err := pool.Exec(context.Background(), `INSERT INTO managed_knowledge_lifecycle_operations
		(operation_id,agent_instance_id,owner_id,deployment_id,managed_service_id,knowledge_binding_id,action,status,
		 worker_operation_id,revision,snapshot_json,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,'running',$8,$9,$10,$11,$12)`,
		operationID, instanceID, ownerID, deploymentID, serviceID, bindingID, action, workerOperationID,
		operationRevision, snapshot, operation.CreatedAt, operation.UpdatedAt); err != nil {
		t.Fatal(err)
	}
	lifecycle, err := postgres.NewManagedKnowledgeLifecycleStore(store)
	if err != nil {
		t.Fatal(err)
	}
	return managedKnowledgeLifecycleFixture{
		pool: pool, lifecycle: lifecycle, instanceID: instanceID, ownerID: ownerID, deploymentID: deploymentID,
		serviceID: serviceID, bindingID: bindingID, operationID: operationID, workerOperationID: workerOperationID,
		recipeDigest: recipeDigest, serviceRevision: serviceRevision, bindingRevision: bindingRevision,
		operationRevision: operationRevision, now: now,
		assignment: workeroperation.Assignment{
			OperationID: workerOperationID, DeploymentID: deploymentID, OwnerID: ownerID,
			Action: workeroperation.Action(action), LifecycleRestartRef: scope.LifecycleRef,
			ExecutionBundleDigest: scope.ExecutionBundleDigest, ExpectedInstalledManifestDigest: scope.InstalledManifestDigest,
			ExpectedDeploymentRevision: deploymentRevision, ExpectedManagedServiceRevision: serviceRevision,
			ExpectedKnowledgeBindingRevision: bindingRevision,
		},
	}
}

func (fixture managedKnowledgeLifecycleFixture) assertRevisions(t *testing.T, service, binding int64, enabled, reserved bool) {
	t.Helper()
	var serviceRevision, bindingRevision int64
	var bindingEnabled, lifecycleReserved bool
	if err := fixture.pool.QueryRow(context.Background(), `SELECT m.revision,k.revision,k.enabled,
		EXISTS (SELECT 1 FROM managed_knowledge_lifecycle_operations l
			WHERE l.operation_id=$1 AND l.execution_fenced_at IS NOT NULL AND l.reservation_released_at IS NULL)
		FROM managed_services m JOIN knowledge_configs k ON k.managed_service_id=m.service_id
		WHERE m.service_id=$2 AND k.binding_id=$3`,
		fixture.operationID, fixture.serviceID, fixture.bindingID,
	).Scan(&serviceRevision, &bindingRevision, &bindingEnabled, &lifecycleReserved); err != nil {
		t.Fatal(err)
	}
	if serviceRevision != service || bindingRevision != binding || bindingEnabled != enabled || lifecycleReserved != reserved {
		t.Fatalf("service revision=%d binding revision=%d enabled=%t reserved=%t",
			serviceRevision, bindingRevision, bindingEnabled, lifecycleReserved)
	}
}

func (fixture managedKnowledgeLifecycleFixture) assertReservationActive(t *testing.T) {
	t.Helper()
	var active bool
	if err := fixture.pool.QueryRow(context.Background(), `SELECT execution_fenced_at IS NOT NULL
		AND reservation_released_at IS NULL AND status='running'
		FROM managed_knowledge_lifecycle_operations WHERE operation_id=$1`, fixture.operationID).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if !active {
		t.Fatal("lifecycle reservation was released after a failed terminal CAS")
	}
}
