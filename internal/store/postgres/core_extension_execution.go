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

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
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
	out, err := c.RequestTask(ctx, in)
	return out.TaskID, err
}

// RequestTask stages an extension execution behind the shared durable
// confirmation lifecycle. The task is inserted as waiting_user in the same
// transaction as its immutable binding; only ConfirmationService.Confirm may
// transition it to queued.
func (c *PostgresExtensionExecutionCoordinator) RequestTask(ctx context.Context, in coreextension.ExecuteRequest) (coreextension.ExecuteResult, error) {
	if c == nil || c.store == nil || !coretask.ValidUUID(in.IdempotencyKey) || !coretask.ValidUUID(in.InstallationID) || in.ExpectedRevision == 0 {
		return coreextension.ExecuteResult{}, coreextension.ErrInvalid
	}
	if strings.TrimSpace(in.ToolName) != in.ToolName {
		return coreextension.ExecuteResult{}, coreextension.ErrInvalid
	}
	input := in.Input
	if len(input) == 0 {
		input = json.RawMessage(`{}`)
	}
	canonical, err := canonicalJSON(input, coretask.MaxCanonicalInputBytes)
	if err != nil {
		return coreextension.ExecuteResult{}, coreextension.ErrInvalid
	}
	installation, err := NewCoreExtensionStore(c.store).Get(ctx, in.InstallationID)
	if err != nil {
		return coreextension.ExecuteResult{}, err
	}
	if installation.State != coreextension.StateInstalled || !installation.Enabled || installation.Revision != in.ExpectedRevision || installation.ActiveVersionID == "" {
		return coreextension.ExecuteResult{}, coreextension.ErrRevisionConflict
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
		return coreextension.ExecuteResult{}, coreextension.ErrConflict
	}
	operation := coretask.ExtensionOperationExecuteTool
	goal := "extension tool " + in.ToolName
	if installation.Kind == coreextension.KindSkill {
		if in.ToolName != "" || version.Execution.Skill == nil {
			return coreextension.ExecuteResult{}, coreextension.ErrInvalid
		}
		operation = coretask.ExtensionOperationExecuteSkill
		goal = "extension skill " + version.VersionID
	}
	if installation.Kind == coreextension.KindMCP && strings.TrimSpace(in.ToolName) == "" {
		return coreextension.ExecuteResult{}, coreextension.ErrInvalid
	}
	binding, err := extensionExecutionBinding(c.store.instanceID.String(), installation, version, in.ToolName, canonical)
	if err != nil {
		return coreextension.ExecuteResult{}, err
	}
	confirmationID := uuid.New()
	spec := coretask.TaskSpec{Kind: coretask.TaskKindExtension, Goal: goal, IdempotencyKey: in.IdempotencyKey, Payload: coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{Operation: operation, InstallationID: installation.ID, ExpectedRevision: uint64(installation.Revision), Version: versionPin(version), Digest: version.ContentDigest, ArtifactDigest: version.ArtifactDigest, ConfirmationID: confirmationID.String(), ToolName: in.ToolName, CanonicalInputJSON: canonical}}}
	digest, err := coretask.CanonicalMutationDigest(struct {
		Binding coreconfirmation.Binding
	}{binding})
	if err != nil {
		return coreextension.ExecuteResult{}, err
	}
	taskStore := NewCoreTaskStore(c.store)
	task, err := taskStore.mutateTask(ctx, "create", coretask.MutationCommand{IdempotencyKey: in.IdempotencyKey, RequestDigest: digest}, func(tx pgx.Tx) (coretask.Task, error) {
		// A single installation may not have multiple live execution proposals.
		// Serialize this check with the current-binding projection so independent
		// requests cannot invalidate one another by replacing the target binding.
		if _, e := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "core_extension_installation:"+installation.ID); e != nil {
			return coretask.Task{}, e
		}
		var existingID, existingState string
		var consumedReleased bool
		existingErr := tx.QueryRow(ctx, `SELECT confirmation_id::text,state,consumed_released FROM core_confirmations WHERE operation_domain='extension.execute' AND target_id=$1 AND state IN ('pending','confirmed','consumed') ORDER BY created_at DESC,confirmation_id DESC LIMIT 1 FOR UPDATE`, installation.ID).Scan(&existingID, &existingState, &consumedReleased)
		if existingErr == nil {
			if existingState != string(coreconfirmation.StateConsumed) || !consumedReleased {
				return coretask.Task{}, coreextension.ErrConflict
			}
		} else if !errors.Is(existingErr, pgx.ErrNoRows) {
			return coretask.Task{}, existingErr
		}
		task, e := taskStore.createTaskTx(ctx, tx, spec, string(coretask.StatusWaitingUser))
		if e != nil {
			return coretask.Task{}, e
		}
		raw, e := json.Marshal(binding)
		if e != nil {
			return coretask.Task{}, e
		}
		now := time.Now().UTC()
		expires := now.Add(time.Hour)
		if _, e = tx.Exec(ctx, `INSERT INTO core_confirmations(confirmation_id,operation_domain,target_id,target_revision,binding_json,task_id,state,revision,created_at,updated_at,expires_at) VALUES($1,'extension.execute',$2,$3,$4,$5,'pending',1,$6,$6,$7)`, confirmationID, installation.ID, installation.Revision, raw, task.ID, now, expires); e != nil {
			return coretask.Task{}, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_confirmation_target_bindings(confirmation_id,binding_json,updated_at) VALUES($1,$2,$3)`, confirmationID, raw, now); e != nil {
			return coretask.Task{}, e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_confirmation_current_bindings(operation_domain,target_id,target_revision,binding_json,updated_at) VALUES('extension.execute',$1,$2,$3,$4) ON CONFLICT(operation_domain,target_id) DO UPDATE SET target_revision=EXCLUDED.target_revision,binding_json=EXCLUDED.binding_json,updated_at=EXCLUDED.updated_at`, installation.ID, installation.Revision, raw, now); e != nil {
			return coretask.Task{}, e
		}
		return task, nil
	})
	if err != nil {
		return coreextension.ExecuteResult{}, err
	}
	var cid string
	if task.Spec.Payload.Extension != nil {
		cid = task.Spec.Payload.Extension.ConfirmationID
	}
	if !coretask.ValidUUID(cid) {
		return coreextension.ExecuteResult{}, coreextension.ErrConflict
	}
	return coreextension.ExecuteResult{TaskID: task.ID, ConfirmationID: cid}, nil
}

func extensionExecutionBinding(ownerID string, installation coreextension.Installation, version coreextension.VersionRecord, tool string, input json.RawMessage) (coreconfirmation.Binding, error) {
	parameter, err := coretask.CanonicalMutationDigest(struct{ Input json.RawMessage }{input})
	if err != nil {
		return coreconfirmation.Binding{}, err
	}
	network := digestPG(version.NetworkGrants, "extension-execute-network")
	secret := digestPG(version.SecretGrants, "extension-execute-secrets")
	permission := digestPG(struct {
		Kind, Transport                      string
		Manifest, Execution, Network, Secret string
	}{string(installation.Kind), string(installation.Transport), version.ManifestDigest, version.ExecutionDigest, version.NetworkSchemaDigest, version.SecretSchemaDigest}, "extension-execute-permission")
	command := []string(nil)
	switch {
	case version.Execution.Stdio != nil:
		command = append(command, version.Execution.Stdio.Argv...)
	case version.Execution.Skill != nil:
		command = append(command, version.Execution.Skill.Argv...)
	case version.Execution.Remote != nil:
		command = []string{"remote", version.Execution.Remote.URL}
	}
	b := coreconfirmation.Binding{OwnerID: ownerID, OperationDomain: "extension.execute", TargetID: installation.ID, TargetRevision: installation.Revision, TargetKind: string(installation.Kind), SourceVersion: version.Pin.RegistryVersion, SourceCommit: version.Pin.GitCommit, ContentDigest: coreconfirmation.Digest(version.ContentDigest), ManifestDigest: coreconfirmation.Digest(version.ManifestDigest), ExecutionDigest: coreconfirmation.Digest(version.ExecutionDigest), PermissionDigest: coreconfirmation.Digest(permission), ParameterDigest: coreconfirmation.Digest(parameter), NetworkDigest: coreconfirmation.Digest(network), SecretGrantDigest: coreconfirmation.Digest(secret), SelectedTool: tool, SelectedCommand: command}
	for _, g := range version.NetworkGrants {
		b.NetworkGrants = append(b.NetworkGrants, fmt.Sprintf("%s://%s:%d%s:%s", g.Scheme, g.Host, g.Port, g.PathPrefix, g.Digest))
	}
	for _, g := range version.SecretGrants {
		b.SecretGrants = append(b.SecretGrants, coreconfirmation.SecretGrant{ReferenceID: g.ReferenceID, Purpose: coreconfirmation.SecretPurpose(g.Purpose), BindingDigest: coreconfirmation.Digest(g.BindingDigest)})
	}
	return b.Normalize()
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
	if task.Spec.Kind == coretask.TaskKindConversationTool {
		return c.ResolveConversationInvocation(ctx, task)
	}
	if c == nil || c.store == nil || task.ID == "" || task.Spec.Kind != coretask.TaskKindExtension || task.Spec.Payload.Extension == nil || task.Status != coretask.StatusRunning || task.Lease == nil {
		return execution.Invocation{}, coretask.ErrInvalid
	}
	p := task.Spec.Payload.Extension
	if p.Operation != coretask.ExtensionOperationExecuteTool && p.Operation != coretask.ExtensionOperationExecuteSkill {
		return execution.Invocation{}, coretask.ErrConflict
	}
	confirmationStore := NewCoreConfirmationStore(c.store)
	confirmation, err := confirmationStore.Get(ctx, p.ConfirmationID)
	if err != nil {
		return execution.Invocation{}, err
	}
	if confirmation.State == coreconfirmation.StateConfirmed {
		consumeKey := uuid.NewSHA1(uuid.NameSpaceURL, []byte("extension-execute-consume:"+task.ID+":"+fmt.Sprint(task.Attempt)+":"+fmt.Sprint(task.LeaseEpoch))).String()
		_, err = confirmationStore.Consume(ctx, coreconfirmation.ConsumeCommand{
			ConfirmationID: p.ConfirmationID,
			IdempotencyKey: consumeKey,
			RequestDigest:  coreconfirmation.Digest(digestPG(struct{ Task, Binding any }{task.ID, confirmation.Binding}, "extension-execute-consume")),
			TaskID:         task.ID, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch,
			ExpectedRevision: confirmation.Revision, ExpectedTaskRevision: int64(task.Revision), Binding: confirmation.Binding, At: time.Now().UTC(),
		})
		if err != nil {
			return execution.Invocation{}, err
		}
	} else if confirmation.State != coreconfirmation.StateConsumed {
		return execution.Invocation{}, coreconfirmation.ErrConflict
	}
	if err := c.requireActiveExecutionReservation(ctx, p.ConfirmationID, task); err != nil {
		// A consumed confirmation is a one-shot capability. If the worker was
		// reclaimed after consumption, do not redispatch it under a new lease;
		// terminalize the exact current task as uncertain and retain the active
		// reservation for explicit operational reconciliation.
		_, terminalErr := c.Fail(ctx, task, "extension_execution_uncertain", "execution outcome is uncertain; reconciliation required")
		if terminalErr != nil {
			return execution.Invocation{}, errors.Join(err, terminalErr)
		}
		return execution.Invocation{}, err
	}
	var status, holder string
	var attempt, leaseEpoch, revision int64
	var expires time.Time
	var payload []byte
	err = c.store.pool.QueryRow(ctx, `SELECT status,attempt,lease_epoch,lease_holder,lease_expires_at,revision,payload_json FROM core_tasks WHERE task_id=$1`, task.ID).Scan(&status, &attempt, &leaseEpoch, &holder, &expires, &revision, &payload)
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

func (c *PostgresExtensionExecutionCoordinator) requireActiveExecutionReservation(ctx context.Context, confirmationID string, task coretask.Task) error {
	if c == nil || c.store == nil || !coretask.ValidUUID(confirmationID) || task.Lease == nil {
		return coretask.ErrConflict
	}
	var state string
	var released bool
	if err := c.store.pool.QueryRow(ctx, `SELECT state,consumed_released FROM core_confirmations WHERE confirmation_id=$1 AND task_id=$2`, confirmationID, task.ID).Scan(&state, &released); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coretask.ErrNotFound
		}
		return err
	}
	if state != string(coreconfirmation.StateConsumed) || released {
		return coretask.ErrConflict
	}
	var reservationTask string
	var attempt, epoch, revision int64
	var active bool
	if err := c.store.pool.QueryRow(ctx, `SELECT task_id::text,acquired_attempt,acquired_lease_epoch,task_revision,active FROM core_confirmation_reservations WHERE confirmation_id=$1`, confirmationID).Scan(&reservationTask, &attempt, &epoch, &revision, &active); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coretask.ErrConflict
		}
		return err
	}
	if !active || reservationTask != task.ID || attempt != int64(task.Attempt) || epoch != int64(task.LeaseEpoch) || revision != int64(task.Revision) {
		return coretask.ErrLeaseConflict
	}
	return nil
}

// ResolveConversationInvocation resolves a conversation_tool task directly
// from its durable task/attempt/turn fences. It never converts the task into
// the legacy extension task shape and never consults the mutable active
// version pointer.
func (c *PostgresExtensionExecutionCoordinator) ResolveConversationInvocation(ctx context.Context, task coretask.Task) (execution.Invocation, error) {
	if c == nil || c.store == nil || task.Spec.Kind != coretask.TaskKindConversationTool || task.Spec.Payload.ConversationTool == nil || task.Status != coretask.StatusRunning || task.Lease == nil {
		return execution.Invocation{}, coretask.ErrInvalid
	}
	p := task.Spec.Payload.ConversationTool
	if !coretask.ValidUUID(p.AttemptID) || p.TurnID == "" || p.InstallationID == "" || p.VersionID == "" {
		return execution.Invocation{}, coretask.ErrInvalid
	}
	var status, holder string
	var attempt, epoch, revision int64
	var expires time.Time
	if err := c.store.pool.QueryRow(ctx, `SELECT status,attempt,lease_epoch,lease_holder,lease_expires_at,revision FROM core_tasks WHERE task_id=$1`, task.ID).Scan(&status, &attempt, &epoch, &holder, &expires, &revision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return execution.Invocation{}, coretask.ErrNotFound
		}
		return execution.Invocation{}, err
	}
	if status != string(coretask.StatusRunning) || uint32(attempt) != task.Attempt || uint64(epoch) != task.LeaseEpoch || holder != task.Lease.Holder || revision != int64(task.Revision) || expires.Before(time.Now().UTC()) {
		return execution.Invocation{}, coretask.ErrLeaseConflict
	}
	var turnSnapshot []byte
	if err := c.store.pool.QueryRow(ctx, `SELECT extension_snapshot_json FROM core_conversation_turns WHERE turn_id=$1`, p.TurnID).Scan(&turnSnapshot); err != nil {
		return execution.Invocation{}, coretask.ErrNotFound
	}
	var snapshots []coreconversation.ExtensionExecutionSnapshot
	if json.Unmarshal(turnSnapshot, &snapshots) != nil {
		return execution.Invocation{}, coretask.ErrConflict
	}
	var pinned *coreconversation.ExtensionExecutionSnapshot
	for i := range snapshots {
		if snapshots[i].InstallationID == p.InstallationID && snapshots[i].VersionID == p.VersionID {
			if pinned != nil {
				return execution.Invocation{}, coretask.ErrConflict
			}
			pinned = &snapshots[i]
		}
	}
	if pinned == nil || pinned.ContentDigest != p.ExtensionSnapshotDigest || pinned.ToolSchemaDigest != p.ToolSchemaDigest || pinned.InstallationRevision != p.InstallationRevision {
		return execution.Invocation{}, coretask.ErrConflict
	}
	var attemptState, confirmationID, toolName, argsDigest, schemaDigest, contentDigest, artifactDigest string
	var argsJSON []byte
	var attemptEpoch int64
	if err := c.store.pool.QueryRow(ctx, `SELECT state,confirmation_id,tool_name,tool_schema_digest,arguments_digest,arguments_json,extension_snapshot_digest,installation_revision FROM core_conversation_tool_attempts WHERE attempt_id=$1 AND turn_id=$2`, p.AttemptID, p.TurnID).Scan(&attemptState, &confirmationID, &toolName, &schemaDigest, &argsDigest, &argsJSON, &contentDigest, &attemptEpoch); err != nil {
		return execution.Invocation{}, coretask.ErrNotFound
	}
	if attemptState != "dispatched" || attemptEpoch != int64(p.InstallationRevision) || toolName != p.ToolName || schemaDigest != p.ToolSchemaDigest || argsDigest != p.ArgumentsDigest || contentDigest != p.ExtensionSnapshotDigest || !json.Valid(argsJSON) {
		return execution.Invocation{}, coretask.ErrConflict
	}
	if confirmationID != "" {
		var confirmationState string
		var bindingRaw []byte
		if err := c.store.pool.QueryRow(ctx, `SELECT state,binding_json FROM core_confirmations WHERE confirmation_id=$1`, confirmationID).Scan(&confirmationState, &bindingRaw); err != nil || confirmationState != "consumed" {
			return execution.Invocation{}, execution.ErrNotConfirmed
		}
		var binding map[string]any
		if json.Unmarshal(bindingRaw, &binding) != nil || binding["operation_domain"] != "conversation_tool" || binding["target_id"] != p.AttemptID {
			return execution.Invocation{}, coretask.ErrConflict
		}
	}
	var versionRaw []byte
	if err := c.store.pool.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2`, p.InstallationID, p.VersionID).Scan(&versionRaw); err != nil {
		return execution.Invocation{}, coretask.ErrNotFound
	}
	var version coreextension.VersionRecord
	if json.Unmarshal(versionRaw, &version) != nil || version.ContentDigest == "" || version.ContentDigest != pinned.ContentDigest || version.ArtifactDigest != pinned.ArtifactDigest {
		return execution.Invocation{}, coretask.ErrConflict
	}
	contentDigest, artifactDigest = version.ContentDigest, version.ArtifactDigest
	if version.Execution.Stdio != nil {
		if c.WorkspaceRoot == "" {
			return execution.Invocation{}, coretask.ErrInvalid
		}
		return execution.Invocation{Kind: coreextension.KindMCP, Local: &execution.LocalInvocation{TaskID: task.ID, TaskFence: execution.StableRunID(task.ID, fmt.Sprintf("%d", task.Attempt), fmt.Sprintf("%d", task.LeaseEpoch)), InstallationID: p.InstallationID, VersionID: p.VersionID, InstallDigest: artifactDigest, ContentDigest: contentDigest, ArtifactDigest: artifactDigest, EntryPath: version.Execution.Stdio.RelativePath, Argv: append([]string(nil), version.Execution.Stdio.Argv...), Workspace: filepath.Join(c.WorkspaceRoot, task.ID), Timeout: 10 * time.Minute, Secrets: secretBindings(p.InstallationID, p.VersionID, version), Stdin: append([]byte(nil), argsJSON...)}}, nil
	}
	if version.Execution.Remote != nil {
		if toolName == "" {
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
		return execution.Invocation{Kind: coreextension.KindMCP, Remote: &execution.RemoteInvocation{Endpoint: *version.Execution.Remote, InstallationID: p.InstallationID, VersionID: p.VersionID, Purpose: string(coreextension.SecretPurposeMCPCredential), BindingDigest: binding, Tool: toolName, Input: append(json.RawMessage(nil), argsJSON...)}}, nil
	}
	if version.Execution.Skill != nil {
		if version.Execution.Skill.Executable && c.WorkspaceRoot == "" {
			return execution.Invocation{}, coretask.ErrInvalid
		}
		skill := &execution.SkillInvocation{Entry: *version.Execution.Skill, InstallDigest: artifactDigest, Input: append(json.RawMessage(nil), argsJSON...), TaskID: task.ID, TaskFence: execution.StableRunID(task.ID, fmt.Sprintf("%d", task.Attempt), fmt.Sprintf("%d", task.LeaseEpoch)), InstallationID: p.InstallationID, VersionID: p.VersionID, ContentDigest: contentDigest, ArtifactDigest: artifactDigest, Secrets: secretBindings(p.InstallationID, p.VersionID, version)}
		if version.Execution.Skill.Executable {
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
	// The generic Task contract has no separate uncertain enum. Persist the
	// canonical failed/reconciliation_required marker while deliberately
	// retaining the consumed reservation as the one-shot side-effect fence.
	uncertain := code == "extension_execution_uncertain"
	if !uncertain {
		if p := task.Spec.Payload.Extension; p != nil && (p.Operation == coretask.ExtensionOperationExecuteTool || p.Operation == coretask.ExtensionOperationExecuteSkill) && coretask.ValidUUID(p.ConfirmationID) {
			if _, e := tx.Exec(ctx, `UPDATE core_confirmation_reservations SET active=false WHERE confirmation_id=$1 AND task_id=$2 AND active=true`, p.ConfirmationID, task.ID); e != nil {
				return false, e
			}
			if _, e := tx.Exec(ctx, `UPDATE core_confirmations SET consumed_released=true,revision=revision+1,updated_at=clock_timestamp() WHERE confirmation_id=$1 AND task_id=$2 AND state='consumed' AND consumed_released=false`, p.ConfirmationID, task.ID); e != nil {
				return false, e
			}
		}
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
