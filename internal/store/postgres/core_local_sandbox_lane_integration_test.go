package postgres

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func createSandboxLaneTask(t *testing.T, ctx context.Context, tasks *CoreTaskStore, target coretask.ExtensionExecutionTarget, availableAt time.Time) coretask.Task {
	t.Helper()
	key := uuid.NewString()
	installationID, versionID := uuid.NewString(), uuid.NewString()
	kind := "mcp"
	transport := "stdio_static"
	execution := `{"stdio":{"relative_path":"entry","digest":"` + strings.Repeat("b", 64) + `","argv":["entry"]}}`
	operation := coretask.ExtensionOperationExecuteTool
	toolName := "write_html"
	if target == coretask.ExtensionExecutionTargetStaticSkill {
		kind = "skill"
		transport = "skill_static"
		execution = `{"skill":{"relative_path":"SKILL.md","digest":"` + strings.Repeat("b", 64) + `"}}`
		operation = coretask.ExtensionOperationExecuteSkill
		toolName = ""
	} else if target == coretask.ExtensionExecutionTargetRemoteExtension {
		transport = "streamable_http"
		execution = `{"remote":{"url":"https://example.test/mcp"}}`
	}
	now := time.Now().UTC()
	if _, err := tasks.store.pool.Exec(ctx, `INSERT INTO core_extension_installations(
		installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,active_version_id,
		network_grants_json,secret_grants_json,created_at,updated_at)
		VALUES($1,'{}'::jsonb,$2,'github',$3,$3,'',$4,1,'installed',true,$5,'[]'::jsonb,'[]'::jsonb,$6,$6)`,
		installationID, kind, key, transport, versionID, now); err != nil {
		t.Fatal(err)
	}
	versionJSON := `{"version":"1.0.0","content_digest":"` + strings.Repeat("a", 64) + `","artifact_digest":"` + strings.Repeat("b", 64) + `","execution":` + execution + `}`
	if _, err := tasks.store.pool.Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,$3,$4)`, versionID, installationID, []byte(versionJSON), now); err != nil {
		t.Fatal(err)
	}
	spec := coretask.TaskSpec{
		Kind:           coretask.TaskKindExtension,
		Goal:           "sandbox lane " + string(target),
		IdempotencyKey: key,
		AvailableAt:    availableAt,
		Payload: coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{
			Operation:          operation,
			ExecutionTarget:    target,
			InstallationID:     installationID,
			ExpectedRevision:   1,
			Version:            "1.0.0",
			Digest:             strings.Repeat("a", 64),
			ArtifactDigest:     strings.Repeat("b", 64),
			ToolName:           toolName,
			CanonicalInputJSON: []byte(`{"content":"ok"}`),
		}},
	}
	digest, err := spec.MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	task, err := tasks.CreateTask(ctx, coretask.CreateTaskCommand{
		Spec: spec,
		Mutation: coretask.MutationCommand{
			IdempotencyKey: key,
			RequestDigest:  digest,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return task
}

func TestCoreTaskLocalSandboxLaneSkipsBusyLocalAndReclaimsExpiredLease(t *testing.T) {
	ctx, store, _, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	tasks := NewCoreTaskStore(store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	firstLocal := createSandboxLaneTask(t, ctx, tasks, coretask.ExtensionExecutionTargetLocalSandbox, now)
	secondLocal := createSandboxLaneTask(t, ctx, tasks, coretask.ExtensionExecutionTargetLocalSandbox, now.Add(time.Millisecond))
	staticSkill := createSandboxLaneTask(t, ctx, tasks, coretask.ExtensionExecutionTargetStaticSkill, now.Add(2*time.Millisecond))
	remote := createSandboxLaneTask(t, ctx, tasks, coretask.ExtensionExecutionTargetRemoteExtension, now.Add(3*time.Millisecond))
	// Change the mutable live projection after task creation. The sealed task
	// must remain in the local lane even though the installation now advertises
	// a different active shape.
	if _, err := store.pool.Exec(ctx, `UPDATE core_extension_installations SET enabled=false WHERE installation_id=$1`, firstLocal.Spec.Payload.Extension.InstallationID); err != nil {
		t.Fatal(err)
	}
	if _, err := store.pool.Exec(ctx, `UPDATE core_extension_versions SET version_json=jsonb_set(version_json,'{execution}','{"remote":{"url":"https://changed.example/mcp"}}'::jsonb) WHERE installation_id=$1`, firstLocal.Spec.Payload.Extension.InstallationID); err != nil {
		t.Fatal(err)
	}

	claimedLocal, firstLease, err := tasks.ClaimNextDue(ctx, "local-a", now.Add(time.Second), time.Minute, 4)
	if err != nil || claimedLocal.ID != firstLocal.ID {
		t.Fatalf("first local claim=%+v err=%v", claimedLocal, err)
	}
	// Recreate the store wrapper to prove the lane is entirely durable and does
	// not rely on an in-memory semaphore surviving restart.
	restarted := NewCoreTaskStore(store)
	claimedStatic, _, err := restarted.ClaimNextDue(ctx, "static-skill-a", now.Add(time.Second), time.Minute, 4)
	if err != nil || claimedStatic.ID != staticSkill.ID {
		t.Fatalf("static Skill bypass claim=%+v err=%v", claimedStatic, err)
	}
	claimedRemote, _, err := restarted.ClaimNextDue(ctx, "remote-a", now.Add(time.Second), time.Minute, 4)
	if err != nil || claimedRemote.ID != remote.ID {
		t.Fatalf("remote bypass claim=%+v err=%v", claimedRemote, err)
	}
	if _, _, err = restarted.ClaimNextDue(ctx, "local-blocked", now.Add(time.Second), time.Minute, 4); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("second local was not queued while lane busy: %v", err)
	}
	queued, err := restarted.GetTask(ctx, secondLocal.ID)
	if err != nil || queued.Status != coretask.StatusQueued || queued.Lease != nil {
		t.Fatalf("blocked local task=%+v err=%v", queued, err)
	}

	reclaimed, lease, err := restarted.ClaimNextDue(ctx, "local-reclaimer", now.Add(2*time.Minute), time.Minute, 4)
	if err != nil || reclaimed.ID != firstLocal.ID || lease.Epoch <= firstLease.Epoch {
		t.Fatalf("expired local reclaim=%+v lease=%+v err=%v", reclaimed, lease, err)
	}
}

func TestCoreTaskLocalSandboxLaneConcurrentClaimsStartOneLocalTask(t *testing.T) {
	ctx, store, _, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	tasks := NewCoreTaskStore(store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	createSandboxLaneTask(t, ctx, tasks, coretask.ExtensionExecutionTargetLocalSandbox, now)
	createSandboxLaneTask(t, ctx, tasks, coretask.ExtensionExecutionTargetLocalSandbox, now.Add(time.Millisecond))

	type claimResult struct {
		task coretask.Task
		err  error
	}
	start := make(chan struct{})
	results := make(chan claimResult, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(holder string) {
			defer wg.Done()
			<-start
			task, _, err := NewCoreTaskStore(store).ClaimNextDue(ctx, holder, now.Add(time.Second), time.Minute, 4)
			results <- claimResult{task: task, err: err}
		}(uuid.NewString())
	}
	close(start)
	wg.Wait()
	close(results)

	succeeded := 0
	for result := range results {
		if result.err == nil {
			succeeded++
			if result.task.Spec.Payload.Extension == nil || result.task.Spec.Payload.Extension.ExecutionTarget != coretask.ExtensionExecutionTargetLocalSandbox {
				t.Fatalf("claimed unexpected task=%+v", result.task)
			}
		}
	}
	var running, queued int
	if err := store.pool.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE status='running'),
		count(*) FILTER (WHERE status='queued')
		FROM core_tasks
		WHERE task_kind='extension'
		  AND payload_json#>>'{extension,execution_target}'='local_sandbox'`).Scan(&running, &queued); err != nil {
		t.Fatal(err)
	}
	if succeeded != 1 || running != 1 || queued != 1 {
		t.Fatalf("claims succeeded=%d running=%d queued=%d", succeeded, running, queued)
	}
}
