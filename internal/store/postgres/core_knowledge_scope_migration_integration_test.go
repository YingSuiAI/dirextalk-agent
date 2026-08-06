package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoreKnowledgeScopeMigrationQuarantinesLegacyGlobalState(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_knowledge_scope_")
	now := time.Now().UTC().Truncate(time.Microsecond)
	legacyProfileID, snapshotID := uuid.NewString(), uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO core_knowledge_embedding_config(singleton,embedding_profile_id,dimension,collection,collection_config_digest,revision,updated_at) VALUES(true,$1,2,'knowledge',$2,1,$3)`, legacyProfileID, strings.Repeat("a", 64), now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_knowledge_list_snapshots(snapshot_id,query_digest,snapshot_at,expires_at,source_ids,search_matches) VALUES($1,$2,$3,$4,'[]','[]')`, snapshotID, strings.Repeat("b", 64), now, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("migrate legacy Knowledge global state: %v", err)
	}
	internalOwner := internalEntityOwnerID("knowledge", instanceID)
	assertKnowledgeScopeRow(t, ctx, pool, "core_knowledge_embedding_config", "embedding_profile_id", legacyProfileID, internalOwner, 1)
	assertKnowledgeScopeRow(t, ctx, pool, "core_knowledge_list_snapshots", "snapshot_id", snapshotID, internalOwner, 1)

	ownerA := coretask.OwnerScope{OwnerID: "@knowledge-migration-a:example.test", AccountGeneration: 3}
	ownerB := coretask.OwnerScope{OwnerID: "@knowledge-migration-b:example.test", AccountGeneration: 8}
	for _, owner := range []coretask.OwnerScope{ownerA, ownerB} {
		if _, err := pool.Exec(ctx, `INSERT INTO core_knowledge_embedding_config(singleton,owner_id,account_generation,embedding_profile_id,dimension,collection,collection_config_digest,revision,updated_at) VALUES(true,$1,$2,$3,2,'knowledge',$4,1,$5)`, owner.OwnerID, owner.AccountGeneration, uuid.NewString(), strings.Repeat("c", 64), now); err != nil {
			t.Fatalf("insert scoped Knowledge config for %s/%d: %v", owner.OwnerID, owner.AccountGeneration, err)
		}
		if _, err := pool.Exec(ctx, `INSERT INTO core_knowledge_list_snapshots(snapshot_id,owner_id,account_generation,query_digest,snapshot_at,expires_at,source_ids,search_matches) VALUES($1,$2,$3,$4,$5,$6,'[]','[]')`, snapshotID, owner.OwnerID, owner.AccountGeneration, strings.Repeat("d", 64), now, now.Add(time.Minute)); err != nil {
			t.Fatalf("insert scoped Knowledge snapshot for %s/%d: %v", owner.OwnerID, owner.AccountGeneration, err)
		}
	}
	var configRows, snapshotRows int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_embedding_config`).Scan(&configRows); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM core_knowledge_list_snapshots WHERE snapshot_id=$1`, snapshotID).Scan(&snapshotRows); err != nil {
		t.Fatal(err)
	}
	if configRows != 3 || snapshotRows != 3 {
		t.Fatalf("scoped Knowledge rows config=%d snapshot=%d, want 3/3", configRows, snapshotRows)
	}
}

func TestCoreKnowledgeSourceOwnerScopeIsImmutable(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_knowledge_immutable_")
	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	sourceID := uuid.NewString()
	owner := coretask.OwnerScope{OwnerID: "@knowledge-immutable:example.test", AccountGeneration: 6}
	if _, err := pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,created_at,updated_at,owner_id,account_generation) VALUES($1,'memory','ready','immutable',$2,1,'text/plain',1,$3,$3,$4,$5)`, sourceID, strings.Repeat("e", 64), now, owner.OwnerID, owner.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `UPDATE core_knowledge_sources SET owner_id=$2 WHERE source_id=$1`, sourceID, "@knowledge-attacker:example.test"); err == nil || !strings.Contains(err.Error(), "owner scope is immutable") {
		t.Fatalf("mutate Knowledge source owner err=%v", err)
	}
}

func TestCoreKnowledgeScopeMigrationBackfillsImmutableIndexDimension(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_knowledge_dimension_")
	now := time.Now().UTC().Truncate(time.Microsecond)
	profileID, sourceID, taskID, jobID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("f", 64)
	if _, err := pool.Exec(ctx, `INSERT INTO core_model_profiles(profile_id,display_name,provider,base_url,model_name,created_at,updated_at) VALUES($1,'legacy embedding','openai_compatible','https://example.test','legacy-embedding',$2,$2)`, profileID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_knowledge_embedding_config(singleton,embedding_profile_id,dimension,collection,collection_config_digest,revision,updated_at) VALUES(true,$1,7,'knowledge',$2,1,$3)`, profileID, digest, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_knowledge_sources(source_id,kind,status,title,digest,size_bytes,media_type,revision,created_at,updated_at) VALUES($1,'memory','indexing','legacy dimension',$2,1,'text/plain',1,$3,$3)`, sourceID, digest, now); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"knowledge_index":{"source_ids":["` + sourceID + `"],"expected_source_revisions":[1],"collection_config_digest":"` + digest + `"}}`)
	if _, err := pool.Exec(ctx, `INSERT INTO core_tasks(task_id,goal,model_profile_id,create_idempotency_key,task_kind,payload_json,status,revision,available_at,created_at,updated_at) VALUES($1,'legacy dimension',$2,$3,'knowledge_index',$4,'queued',1,$5,$5,$5)`, taskID, profileID, uuid.NewString(), payload, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO core_knowledge_index_jobs(job_id,task_id,source_ids,expected_revisions,profile_id,profile_revision,collection_config_digest,generation,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,1,$6,$7,'queued',$8,$8)`, jobID, taskID, []byte(`["`+sourceID+`"]`), []byte(`[1]`), profileID, digest, "legacy-generation-"+jobID, now); err != nil {
		t.Fatal(err)
	}

	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("migrate legacy Knowledge index dimension: %v", err)
	}
	var jobDimension, payloadDimension int
	if err := pool.QueryRow(ctx, `SELECT job.embedding_dimension,(task.payload_json #>> '{knowledge_index,embedding_dimension}')::integer FROM core_knowledge_index_jobs job JOIN core_tasks task ON task.task_id=job.task_id WHERE job.job_id=$1`, jobID).Scan(&jobDimension, &payloadDimension); err != nil {
		t.Fatal(err)
	}
	if jobDimension != 7 || payloadDimension != 7 {
		t.Fatalf("backfilled dimensions job=%d payload=%d, want 7/7", jobDimension, payloadDimension)
	}
}

func assertKnowledgeScopeRow(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, keyColumn, key, wantOwner string, wantGeneration int64) {
	t.Helper()
	var owner string
	var generation int64
	query := `SELECT owner_id,account_generation FROM ` + pgx.Identifier{table}.Sanitize() + ` WHERE ` + pgx.Identifier{keyColumn}.Sanitize() + `=$1`
	if err := pool.QueryRow(ctx, query, key).Scan(&owner, &generation); err != nil {
		t.Fatal(err)
	}
	if owner != wantOwner || generation != wantGeneration {
		t.Fatalf("%s scope=%s/%d, want %s/%d", table, owner, generation, wantOwner, wantGeneration)
	}
}
