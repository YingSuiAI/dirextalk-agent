package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PostgresExtensionExecutionCoordinator is the durable fence between the
// generic Core task history and extension execution. It never keeps a second
// execution state in memory: resolve, terminal result, and replay all use the
// core_tasks/core_task_events tables in one transaction.
type PostgresExtensionExecutionCoordinator struct {
	store         *Store
	secrets       *CoreExtensionSecretStore
	WorkspaceRoot string
}

func NewPostgresExtensionExecutionCoordinator(s *Store, secretStores ...*CoreExtensionSecretStore) *PostgresExtensionExecutionCoordinator {
	var secrets *CoreExtensionSecretStore
	if len(secretStores) > 0 {
		secrets = secretStores[0]
	}
	if secrets == nil && s != nil {
		secrets = NewCoreExtensionSecretStore(s)
	}
	return &PostgresExtensionExecutionCoordinator{store: s, secrets: secrets}
}

func (c *PostgresExtensionExecutionCoordinator) CreateTask(ctx context.Context, in coreextension.ExecuteRequest) (string, error) {
	if c == nil || c.store == nil || !coretask.ValidUUID(in.IdempotencyKey) || !coretask.ValidUUID(in.InstallationID) || in.ExpectedRevision == 0 {
		return "", coreextension.ErrInvalid
	}
	if strings.TrimSpace(in.ToolName) != in.ToolName {
		return "", coreextension.ErrInvalid
	}
	input := in.Input
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	canonical, err := canonicalJSON(input, coretask.MaxCanonicalInputBytes)
	if err != nil {
		return "", coreextension.ErrInvalid
	}
	installation, err := NewCoreExtensionStore(c.store).Get(ctx, in.InstallationID)
	if err != nil {
		return "", err
	}
	if installation.State != coreextension.StateInstalled || installation.Revision != in.ExpectedRevision || installation.ActiveVersionID == "" {
		return "", coreextension.ErrRevisionConflict
	}
	var version coreextension.VersionRecord
	found := false
	for _, candidate := range installation.Versions {
		if candidate.VersionID == installation.ActiveVersionID {
			version, found = candidate, true
			break
		}
	}
	if !found || len(version.ContentDigest) != 64 || len(version.ArtifactDigest) != 64 {
		return "", coreextension.ErrConflict
	}
	operation := coretask.ExtensionOperationExecuteTool
	goal := "extension tool " + in.ToolName
	if installation.Kind == coreextension.KindSkill {
		if in.ToolName != "" || version.Execution.Skill == nil {
			return "", coreextension.ErrInvalid
		}
		operation = coretask.ExtensionOperationExecuteSkill
		goal = "extension skill " + version.VersionID
	}
	if installation.Kind == coreextension.KindMCP && strings.TrimSpace(in.ToolName) == "" {
		return "", coreextension.ErrInvalid
	}
	spec := coretask.TaskSpec{Kind: coretask.TaskKindExtension, Goal: goal, IdempotencyKey: in.IdempotencyKey, Payload: coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{Operation: operation, InstallationID: installation.ID, ExpectedRevision: uint64(installation.Revision), Version: versionPin(version), Digest: version.ContentDigest, ArtifactDigest: version.ArtifactDigest, ToolName: in.ToolName, CanonicalInputJSON: canonical}}}
	digest, err := coretask.CanonicalMutationDigest(struct {
		InstallationID string
		Revision       int64
		ToolName       string
		Input          json.RawMessage
	}{installation.ID, installation.Revision, in.ToolName, canonical})
	if err != nil {
		return "", err
	}
	task, err := NewCoreTaskStore(c.store).CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: in.IdempotencyKey, RequestDigest: digest}})
	if err != nil {
		return "", err
	}
	return task.ID, nil
}

func NewValidatedPostgresExtensionExecutionCoordinator(s *Store, workspaceRoot string, secretStores ...*CoreExtensionSecretStore) (*PostgresExtensionExecutionCoordinator, error) {
	if s == nil || strings.TrimSpace(workspaceRoot) == "" || !filepath.IsAbs(workspaceRoot) || filepath.Clean(workspaceRoot) != workspaceRoot {
		return nil, coreextension.ErrInvalid
	}
	c := NewPostgresExtensionExecutionCoordinator(s, secretStores...)
	c.WorkspaceRoot = workspaceRoot
	return c, nil
}

func (c *PostgresExtensionExecutionCoordinator) Resolve(ctx context.Context, task coretask.Task) (execution.Invocation, error) {
	if c == nil || c.store == nil || task.ID == "" || task.Spec.Kind != coretask.TaskKindExtension || task.Spec.Payload.Extension == nil || task.Status != coretask.StatusRunning || task.Lease == nil {
		return execution.Invocation{}, coretask.ErrInvalid
	}
	p := task.Spec.Payload.Extension
	if p.Operation != coretask.ExtensionOperationExecuteTool && p.Operation != coretask.ExtensionOperationExecuteSkill {
		return execution.Invocation{}, coretask.ErrConflict
	}
	var status, holder string
	var attempt, leaseEpoch, revision int64
	var expires time.Time
	var payload []byte
	err := c.store.pool.QueryRow(ctx, `SELECT status,attempt,lease_epoch,lease_holder,lease_expires_at,revision,payload_json FROM core_tasks WHERE task_id=$1`, task.ID).Scan(&status, &attempt, &leaseEpoch, &holder, &expires, &revision, &payload)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return execution.Invocation{}, coretask.ErrNotFound
		}
		return execution.Invocation{}, err
	}
	if status != string(coretask.StatusRunning) || uint32(attempt) != task.Attempt || uint64(leaseEpoch) != task.LeaseEpoch || holder != task.Lease.Holder || revision != int64(task.Revision) || expires.Before(time.Now().UTC()) {
		return execution.Invocation{}, coretask.ErrLeaseConflict
	}
	if p.ExpectedRevision == 0 {
		return execution.Invocation{}, coretask.ErrConflict
	}
	// Execution is bound to the immutable snapshot captured at task creation,
	// not to the installation's current active projection. This deliberately
	// permits a queued task to finish against a predecessor version while a
	// later update/uninstall changes the active pointer.
	var snapshotRaw []byte
	if err = c.store.pool.QueryRow(ctx, `SELECT snapshot_json FROM core_task_execution_snapshots WHERE task_id=$1`, task.ID).Scan(&snapshotRaw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return execution.Invocation{}, coretask.ErrNotFound
		}
		return execution.Invocation{}, err
	}
	var snapshot coretask.ExecutionSnapshot
	if json.Unmarshal(snapshotRaw, &snapshot) != nil || snapshot.Validate() != nil {
		return execution.Invocation{}, coretask.ErrConflict
	}
	var pinned *coretask.ExtensionExecutionSnapshot
	for idx := range snapshot.Extensions {
		candidate := &snapshot.Extensions[idx]
		if candidate.InstallationID == p.InstallationID {
			if pinned != nil || candidate.Version != p.Version {
				return execution.Invocation{}, coretask.ErrConflict
			}
			pinned = candidate
		}
	}
	if pinned == nil || pinned.Version != p.Version || pinned.Revision != int64(p.ExpectedRevision) || pinned.ContentDigest != p.Digest || pinned.ArtifactDigest != p.ArtifactDigest {
		return execution.Invocation{}, coretask.ErrConflict
	}
	var raw []byte
	if err = c.store.pool.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2`, p.InstallationID, pinned.VersionID).Scan(&raw); err != nil {
		return execution.Invocation{}, coretask.ErrNotFound
	}
	var version coreextension.VersionRecord
	if json.Unmarshal(raw, &version) != nil || version.ContentDigest != p.Digest {
		return execution.Invocation{}, coretask.ErrConflict
	}
	if version.Execution.Stdio != nil {
		if p.Operation != coretask.ExtensionOperationExecuteTool || strings.TrimSpace(p.ToolName) == "" {
			return execution.Invocation{}, coretask.ErrConflict
		}
		if c.WorkspaceRoot == "" {
			return execution.Invocation{}, coretask.ErrInvalid
		}
		workspace := filepath.Join(c.WorkspaceRoot, task.ID)
		if len(version.ArtifactDigest) != 64 || p.ArtifactDigest != version.ArtifactDigest {
			return execution.Invocation{}, coretask.ErrConflict
		}
		return execution.Invocation{Kind: coreextension.KindMCP, Local: &execution.LocalInvocation{
			TaskID: task.ID, TaskFence: execution.StableRunID(task.ID, fmt.Sprintf("%d", task.Attempt), fmt.Sprintf("%d", task.LeaseEpoch)), InstallationID: p.InstallationID, VersionID: pinned.VersionID, InstallDigest: p.ArtifactDigest, ContentDigest: p.Digest, ArtifactDigest: p.ArtifactDigest,
			EntryPath: version.Execution.Stdio.RelativePath, Argv: append([]string(nil), version.Execution.Stdio.Argv...), Workspace: workspace, Timeout: 10 * time.Minute,
			Secrets: secretBindings(p.InstallationID, pinned.VersionID, version), ResultFiles: nil,
		}}, nil
	}
	if version.Execution.Remote != nil {
		if p.Operation != coretask.ExtensionOperationExecuteTool || p.ToolName == "" {
			return execution.Invocation{}, coretask.ErrConflict
		}
		binding := ""
		for _, g := range version.SecretGrants {
			if g.ReferenceID == version.Execution.Remote.CredentialReferenceID {
				binding = g.BindingDigest
			}
		}
		if binding == "" {
			return execution.Invocation{}, execution.ErrSecretBinding
		}
		return execution.Invocation{Kind: coreextension.KindMCP, Remote: &execution.RemoteInvocation{Endpoint: *version.Execution.Remote, InstallationID: p.InstallationID, VersionID: pinned.VersionID, Purpose: string(coreextension.SecretPurposeMCPCredential), BindingDigest: binding, Tool: p.ToolName, Input: append(json.RawMessage(nil), p.CanonicalInputJSON...)}}, nil
	}
	if version.Execution.Skill != nil && p.Operation == coretask.ExtensionOperationExecuteSkill {
		if len(version.ArtifactDigest) != 64 || p.ArtifactDigest != version.ArtifactDigest {
			return execution.Invocation{}, coreextension.ErrConflict
		}
		skill := &execution.SkillInvocation{Entry: *version.Execution.Skill, InstallDigest: version.ArtifactDigest, Input: append(json.RawMessage(nil), p.CanonicalInputJSON...), TaskID: task.ID, TaskFence: execution.StableRunID(task.ID, fmt.Sprintf("%d", task.Attempt), fmt.Sprintf("%d", task.LeaseEpoch)), InstallationID: p.InstallationID, VersionID: pinned.VersionID, ContentDigest: p.Digest, ArtifactDigest: p.ArtifactDigest, Secrets: secretBindings(p.InstallationID, pinned.VersionID, version)}
		if version.Execution.Skill.Executable {
			if c.WorkspaceRoot == "" {
				return execution.Invocation{}, coretask.ErrInvalid
			}
			skill.Workspace = filepath.Join(c.WorkspaceRoot, task.ID)
		}
		return execution.Invocation{Kind: coreextension.KindSkill, Skill: skill}, nil
	}
	return execution.Invocation{}, coretask.ErrConflict
}

func secretBindings(installationID, versionID string, v coreextension.VersionRecord) []execution.SecretBinding {
	out := make([]execution.SecretBinding, 0, len(v.SecretGrants))
	for _, g := range v.SecretGrants {
		out = append(out, execution.SecretBinding{
			Name: g.ReferenceID, InstallationID: installationID, VersionID: versionID,
			ReferenceID: g.ReferenceID, Purpose: string(g.Purpose), BindingDigest: g.BindingDigest,
		})
	}
	return out
}

func versionPin(v coreextension.VersionRecord) string {
	if strings.TrimSpace(v.Pin.RegistryVersion) != "" {
		return strings.TrimSpace(v.Pin.RegistryVersion)
	}
	return strings.TrimSpace(v.Pin.GitCommit)
}

func executionHash(task coretask.Task, result any) string {
	b, _ := json.Marshal(struct {
		ID       string
		Attempt  uint32
		Epoch    uint64
		Revision uint64
		Result   any
	}{task.ID, task.Attempt, task.LeaseEpoch, task.Revision, result})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (c *PostgresExtensionExecutionCoordinator) Complete(ctx context.Context, task coretask.Task, result coretask.Result) (bool, error) {
	if c == nil || c.store == nil || task.Status != coretask.StatusRunning || task.Lease == nil || result.Validate() != nil {
		return false, coretask.ErrInvalid
	}
	hash := executionHash(task, result)
	return c.finish(ctx, task, hash, &result, "", "")
}

func (c *PostgresExtensionExecutionCoordinator) Fail(ctx context.Context, task coretask.Task, code, summary string) (bool, error) {
	if c == nil || c.store == nil || task.Status != coretask.StatusRunning || task.Lease == nil || strings.TrimSpace(code) == "" || strings.TrimSpace(summary) == "" {
		return false, coretask.ErrInvalid
	}
	hash := executionHash(task, struct{ Code, Summary string }{code, summary})
	return c.finish(ctx, task, hash, nil, code, summary)
}

func (c *PostgresExtensionExecutionCoordinator) finish(ctx context.Context, task coretask.Task, hash string, result *coretask.Result, code, summary string) (bool, error) {
	tx, err := c.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	var priorHash string
	var priorRaw []byte
	if err = tx.QueryRow(ctx, `SELECT request_hash,result_json FROM core_extension_execution_replays WHERE task_id=$1 FOR UPDATE`, task.ID).Scan(&priorHash, &priorRaw); err == nil {
		if priorHash != hash {
			return false, coretask.ErrLeaseConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return false, err
		}
		return true, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return false, err
	}
	var status, holder string
	var attempt, epoch, revision int64
	var expires *time.Time
	if err = tx.QueryRow(ctx, `SELECT status,attempt,lease_epoch,lease_holder,lease_expires_at,revision FROM core_tasks WHERE task_id=$1 FOR UPDATE`, task.ID).Scan(&status, &attempt, &epoch, &holder, &expires, &revision); err != nil {
		return false, coretask.ErrNotFound
	}
	if status != string(coretask.StatusRunning) || uint32(attempt) != task.Attempt || uint64(epoch) != task.LeaseEpoch || holder != task.Lease.Holder || uint64(revision) != task.Revision || expires == nil || !expires.After(time.Now().UTC()) {
		return false, coretask.ErrLeaseConflict
	}
	var resultJSON []byte
	if result != nil {
		resultJSON, _ = json.Marshal(result)
		if len(resultJSON) > coretask.MaxResultBytes {
			return false, coretask.ErrInvalid
		}
	}
	terminalStatus, failureCode, failureSummary := "succeeded", "", ""
	if result == nil {
		terminalStatus, failureCode, failureSummary = "failed", code, summary
	}
	if _, err = tx.Exec(ctx, `UPDATE core_tasks SET status=$2,result_json=$3,failure_code=$4,failure_summary=$5,lease_holder='',lease_expires_at=NULL,revision=revision+1,progress_sequence=progress_sequence+1,updated_at=clock_timestamp() WHERE task_id=$1 AND revision=$6`, task.ID, terminalStatus, resultJSON, failureCode, failureSummary, task.Revision); err != nil {
		return false, err
	}
	_, _ = tx.Exec(ctx, `UPDATE core_task_runtime_concurrency SET running_count=GREATEST(0,running_count-1),revision=revision+1,updated_at=clock_timestamp() WHERE singleton=true`)
	if _, err = tx.Exec(ctx, `INSERT INTO core_task_events(task_id,sequence,event_id,attempt,status,phase,result_json,error_code,error_summary,occurred_at) SELECT task_id,progress_sequence,$2,attempt,$3,'extension_execution',result_json,failure_code,failure_summary,clock_timestamp() FROM core_tasks WHERE task_id=$1`, task.ID, uuid.New(), terminalStatus); err != nil {
		return false, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_extension_execution_replays(task_id,request_hash,result_json) VALUES($1,$2,$3)`, task.ID, hash, func() []byte {
		if resultJSON == nil {
			return []byte(`{}`)
		}
		return resultJSON
	}()); err != nil {
		return false, err
	}
	if err = tx.Commit(ctx); err != nil {
		return false, err
	}
	return true, nil
}

var _ execution.Coordinator = (*PostgresExtensionExecutionCoordinator)(nil)

func canonicalJSON(raw json.RawMessage, max int) (json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > max || !json.Valid(raw) {
		return nil, coreextension.ErrInvalid
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, coreextension.ErrInvalid
	}
	out, err := json.Marshal(value)
	if err != nil || len(out) > max {
		return nil, coreextension.ErrInvalid
	}
	return out, nil
}
