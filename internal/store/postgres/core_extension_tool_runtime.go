package postgres

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type PostgresExtensionToolRuntime struct {
	store  *Store
	tasks  *CoreTaskStore
	coord  *PostgresExtensionExecutionCoordinator
	local  *execution.LocalExecutor
	remote *execution.RemoteExecutor
}

// NewPostgresExtensionRunnerToolRuntime wires tool discovery/calls directly
// to the isolated runner and exact remote MCP resolver. No in-process provider
// or network fallback is available through this constructor.
func NewPostgresExtensionRunnerToolRuntime(s *Store, coord *PostgresExtensionExecutionCoordinator, local *execution.LocalExecutor, remote *execution.RemoteExecutor) *PostgresExtensionToolRuntime {
	if coord == nil {
		coord = NewPostgresExtensionExecutionCoordinator(s)
	}
	return &PostgresExtensionToolRuntime{store: s, tasks: NewCoreTaskStore(s), coord: coord, local: local, remote: remote}
}

func (r *PostgresExtensionToolRuntime) ListTools(ctx context.Context, i coreextension.Installation, v coreextension.VersionRecord) ([]coreextension.Tool, error) {
	if r == nil || r.store == nil || r.tasks == nil || r.coord == nil || (r.local == nil && r.remote == nil) || uuid.Validate(i.ID) != nil || uuid.Validate(v.VersionID) != nil {
		return nil, coreextension.ErrInvalid
	}
	if i.State != coreextension.StateInstalled || i.ActiveVersionID != v.VersionID || len(v.ContentDigest) != 64 {
		return nil, coreextension.ErrConflict
	}
	task, replay, err := r.prepare(ctx, i, v, "__list_tools", []byte(`{}`))
	if err != nil {
		return nil, err
	}
	if replay {
		return decodeTools(taskResult(task))
	}
	claimed, err := r.claimExact(ctx, task.ID)
	if err != nil {
		return nil, err
	}
	tools, err := r.listTools(ctx, claimed, i, v)
	if err != nil {
		_ = r.tasks.FailTask(ctx, coretask.FailCommand{Fence: fenceFor(claimed), At: time.Now().UTC(), ErrorCode: "extension_list_tools_failed", ErrorSummary: "extension list tools failed"})
		return nil, err
	}
	if err = r.persistTools(ctx, i.ID, v.VersionID, tools); err != nil {
		_ = r.tasks.FailTask(ctx, coretask.FailCommand{Fence: fenceFor(claimed), At: time.Now().UTC(), ErrorCode: "extension_list_tools_persist_failed", ErrorSummary: "extension tool descriptors could not be pinned"})
		return nil, err
	}
	raw, err := json.Marshal(tools)
	if err != nil {
		return nil, err
	}
	result := coretask.Result{Text: string(raw), Summary: "extension tools"}
	if err = result.Validate(); err != nil {
		return nil, err
	}
	if _, err = r.tasks.CompleteTask(ctx, coretask.CompleteCommand{Fence: fenceFor(claimed), At: time.Now().UTC(), Result: result}); err != nil {
		return nil, err
	}
	return tools, nil
}

func (r *PostgresExtensionToolRuntime) persistTools(ctx context.Context, installationID, versionID string, tools []coreextension.Tool) error {
	if len(tools) == 0 {
		return coreextension.ErrConflict
	}
	tx, err := r.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var raw []byte
	if err = tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2 FOR UPDATE`, installationID, versionID).Scan(&raw); err != nil {
		return err
	}
	var version coreextension.VersionRecord
	if err = json.Unmarshal(raw, &version); err != nil {
		return coreextension.ErrConflict
	}
	if len(version.Tools) > 0 {
		old, _ := json.Marshal(version.Tools)
		fresh, _ := json.Marshal(tools)
		if string(old) != string(fresh) {
			return coreextension.ErrConflict
		}
		return tx.Commit(ctx)
	}
	version.Tools = append([]coreextension.Tool(nil), tools...)
	updated, err := json.Marshal(version)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_extension_versions SET version_json=$3 WHERE installation_id=$1 AND version_id=$2`, installationID, versionID, updated); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (r *PostgresExtensionToolRuntime) CallTool(ctx context.Context, i coreextension.Installation, v coreextension.VersionRecord, name string, input []byte) (string, error) {
	if r == nil || r.store == nil || r.tasks == nil || r.coord == nil || (r.local == nil && r.remote == nil) || uuid.Validate(i.ID) != nil || uuid.Validate(v.VersionID) != nil || strings.TrimSpace(name) == "" {
		return "", coreextension.ErrInvalid
	}
	if i.State != coreextension.StateInstalled || i.ActiveVersionID != v.VersionID || len(v.ContentDigest) != 64 {
		return "", coreextension.ErrConflict
	}
	task, replay, err := r.prepare(ctx, i, v, name, input)
	if err != nil {
		return "", err
	}
	if replay {
		if task.Status != coretask.StatusSucceeded {
			return "", coreextension.ErrConflict
		}
		result, err := taskResultValue(task)
		if err != nil {
			return "", err
		}
		return result.Text, nil
	}
	claimed, err := r.claimExact(ctx, task.ID)
	if err != nil {
		return "", err
	}
	result, err := r.callTool(ctx, claimed, i, v, name, canonicalInput(task.Spec.Payload.Extension.CanonicalInputJSON))
	if err != nil {
		_ = r.tasks.FailTask(ctx, coretask.FailCommand{Fence: fenceFor(claimed), At: time.Now().UTC(), ErrorCode: "extension_tool_failed", ErrorSummary: "extension tool failed"})
		return "", err
	}
	if err = result.Validate(); err != nil {
		_ = r.tasks.FailTask(ctx, coretask.FailCommand{Fence: fenceFor(claimed), At: time.Now().UTC(), ErrorCode: "extension_tool_invalid_result", ErrorSummary: "extension tool returned invalid result"})
		return "", err
	}
	if _, err = r.tasks.CompleteTask(ctx, coretask.CompleteCommand{Fence: fenceFor(claimed), At: time.Now().UTC(), Result: result}); err != nil {
		return "", err
	}
	if result.Text != "" {
		return result.Text, nil
	}
	return string(result.JSON), nil
}

func (r *PostgresExtensionToolRuntime) listTools(ctx context.Context, task coretask.Task, i coreextension.Installation, v coreextension.VersionRecord) ([]coreextension.Tool, error) {
	if r.local != nil || r.remote != nil {
		inv, err := r.coord.Resolve(ctx, task)
		if err != nil {
			return nil, err
		}
		if inv.Local != nil && r.local != nil {
			return r.local.ListTools(ctx, *inv.Local)
		}
		if inv.Remote != nil && r.remote != nil {
			return r.remote.ListToolsBoundExact(ctx, inv.Remote.Endpoint, inv.Remote.InstallationID, inv.Remote.VersionID, inv.Remote.Purpose, inv.Remote.BindingDigest)
		}
		return nil, coreextension.ErrConflict
	}
	return nil, coreextension.ErrConflict
}

func (r *PostgresExtensionToolRuntime) callTool(ctx context.Context, task coretask.Task, i coreextension.Installation, v coreextension.VersionRecord, name string, input []byte) (coretask.Result, error) {
	if r.local != nil || r.remote != nil {
		inv, err := r.coord.Resolve(ctx, task)
		if err != nil {
			return coretask.Result{}, err
		}
		if inv.Local != nil && r.local != nil {
			return r.local.CallTool(ctx, *inv.Local, name, input)
		}
		if inv.Remote != nil && r.remote != nil {
			return r.remote.ExecuteBoundExact(ctx, inv.Remote.Endpoint, inv.Remote.InstallationID, inv.Remote.VersionID, inv.Remote.Purpose, inv.Remote.BindingDigest, name, input)
		}
		return coretask.Result{}, coreextension.ErrConflict
	}
	return coretask.Result{}, coreextension.ErrConflict
}

func (r *PostgresExtensionToolRuntime) prepare(ctx context.Context, i coreextension.Installation, v coreextension.VersionRecord, name string, input []byte) (coretask.Task, bool, error) {
	if len(input) == 0 {
		input = []byte(`{}`)
	}
	var value any
	if json.Unmarshal(input, &value) != nil {
		return coretask.Task{}, false, coreextension.ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return coretask.Task{}, false, coreextension.ErrInvalid
	}
	input = canonical
	idempotency := uuid.NewSHA1(uuid.NameSpaceURL, []byte(i.ID+":"+v.VersionID+":"+name+":"+string(input))).String()
	if existing, getErr := r.tasks.GetTask(ctx, coreTaskID(idempotency)); getErr == nil {
		return existing, true, nil
	}
	digest, err := coretask.CanonicalMutationDigest(struct {
		InstallationID string
		VersionID      string
		Revision       int64
		ArtifactDigest string
		Name           string
		Input          json.RawMessage
	}{i.ID, v.VersionID, i.Revision, v.ArtifactDigest, name, input})
	if err != nil {
		return coretask.Task{}, false, err
	}
	spec := coretask.TaskSpec{Kind: coretask.TaskKindExtension, Goal: "extension tool " + name, IdempotencyKey: idempotency, Payload: coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{Operation: coretask.ExtensionOperationExecuteTool, InstallationID: i.ID, ExpectedRevision: uint64(i.Revision), Version: versionPin(v), Digest: v.ContentDigest, ArtifactDigest: v.ArtifactDigest, ToolName: name, CanonicalInputJSON: input}}}
	task, err := r.tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: idempotency, RequestDigest: digest}})
	if err == nil {
		return task, false, nil
	}
	if existing, getErr := r.tasks.GetTask(ctx, coreTaskID(idempotency)); getErr == nil {
		return existing, true, nil
	}
	return coretask.Task{}, false, err
}

func decodeTools(result *coretask.Result) ([]coreextension.Tool, error) {
	if result == nil {
		return nil, coreextension.ErrConflict
	}
	var tools []coreextension.Tool
	if json.Unmarshal([]byte(result.Text), &tools) != nil {
		return nil, coreextension.ErrConflict
	}
	return tools, nil
}

func taskResult(task coretask.Task) *coretask.Result {
	result, err := taskResultValue(task)
	if err != nil {
		return nil
	}
	return &result
}

func taskResultValue(task coretask.Task) (coretask.Result, error) {
	if task.Status != coretask.StatusSucceeded || task.Result == nil {
		return coretask.Result{}, coreextension.ErrConflict
	}
	if len(task.Result.JSON) > 0 {
		var result coretask.Result
		if json.Unmarshal(task.Result.JSON, &result) != nil || result.Validate() != nil {
			return coretask.Result{}, coreextension.ErrConflict
		}
		return result, nil
	}
	return *task.Result, task.Result.Validate()
}

func canonicalInput(raw []byte) []byte {
	if len(raw) == 0 {
		return []byte(`{}`)
	}
	return raw
}

func fenceFor(task coretask.Task) coretask.Fence {
	return coretask.Fence{TaskID: task.ID, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch, ExpectedRevision: task.Revision}
}

func (r *PostgresExtensionToolRuntime) claimExact(ctx context.Context, id string) (coretask.Task, error) {
	holder := "extension-runtime:" + id
	tx, err := r.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coretask.Task{}, err
	}
	defer tx.Rollback(ctx)
	task, err := r.tasks.taskTxLocked(ctx, tx, id, false)
	if err != nil {
		return coretask.Task{}, err
	}
	if task.Status != coretask.StatusQueued {
		return coretask.Task{}, coretask.ErrConflict
	}
	now := time.Now().UTC()
	lease := now.Add(10 * time.Minute)
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_runtime_concurrency(singleton,max_concurrent) VALUES(true,1) ON CONFLICT(singleton) DO NOTHING`); err != nil {
		return coretask.Task{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=running_count+1,revision=revision+1,updated_at=$1 WHERE singleton=true`, now); err != nil {
		return coretask.Task{}, err
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET status='running',attempt=GREATEST(attempt,1),lease_epoch=lease_epoch+1,lease_holder=$2,lease_expires_at=$3,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=$4 WHERE task_id=$1 AND status='queued'`, id, holder, lease, now); err != nil {
		return coretask.Task{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,progress_message,occurred_at) SELECT task_id,progress_sequence,$2,attempt,'running','claimed','task claimed',$3 FROM core_tasks WHERE task_id=$1`, id, uuid.New(), now); err != nil {
		return coretask.Task{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coretask.Task{}, err
	}
	return r.tasks.GetTask(ctx, id)
}

var _ coreextension.ToolRuntime = (*PostgresExtensionToolRuntime)(nil)
