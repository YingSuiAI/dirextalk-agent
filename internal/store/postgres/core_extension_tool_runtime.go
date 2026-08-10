package postgres

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
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
	if r == nil || uuid.Validate(i.ID) != nil || uuid.Validate(v.VersionID) != nil {
		return nil, coreextension.ErrInvalid
	}
	if i.State != coreextension.StateInstalled || !i.Enabled || i.ActiveVersionID != v.VersionID || len(v.ContentDigest) != 64 {
		return nil, coreextension.ErrConflict
	}
	if len(v.Tools) != 0 {
		return append([]coreextension.Tool(nil), v.Tools...), nil
	}
	tools, err := r.discoverTools(ctx, i, v)
	if err != nil {
		return nil, err
	}
	if err = validateDiscoveredTools(tools); err != nil {
		return nil, err
	}
	if err = r.persistTools(ctx, i.ID, v.VersionID, tools); err != nil {
		return nil, err
	}
	return append([]coreextension.Tool(nil), tools...), nil
}

func (r *PostgresExtensionToolRuntime) discoverTools(ctx context.Context, i coreextension.Installation, v coreextension.VersionRecord) ([]coreextension.Tool, error) {
	if r == nil || r.coord == nil || i.ID == "" || i.Revision <= 0 || v.VersionID == "" {
		return nil, coreextension.ErrInvalid
	}
	switch {
	case v.Execution.Stdio != nil:
		if r.local == nil || r.coord.WorkspaceRoot == "" {
			return nil, coreextension.ErrConflict
		}
		fence := execution.StableRunID("extension-tool-catalog", i.ID, fmt.Sprint(i.Revision), v.VersionID, v.ContentDigest)
		return r.local.ListTools(ctx, execution.LocalInvocation{
			TaskID: i.ID, TaskFence: fence, InstallationID: i.ID, VersionID: v.VersionID,
			InstallDigest: v.ArtifactDigest, ContentDigest: v.ContentDigest, ArtifactDigest: v.ArtifactDigest,
			EntryPath: v.Execution.Stdio.RelativePath, Argv: append([]string(nil), v.Execution.Stdio.Argv...),
			Workspace: filepath.Join(r.coord.WorkspaceRoot, i.ID), Timeout: 30 * time.Second,
			Limits: execution.LocalSandboxLimitsV2(), Secrets: secretBindings(i.ID, v.VersionID, v),
		})
	case v.Execution.Remote != nil:
		if r.remote == nil {
			return nil, coreextension.ErrConflict
		}
		purpose, binding, err := remoteCredentialBinding(v)
		if err != nil {
			return nil, err
		}
		return r.remote.ListToolsBoundExact(ctx, *v.Execution.Remote, i.ID, v.VersionID, purpose, binding)
	default:
		return nil, coreextension.ErrConflict
	}
}

func validateDiscoveredTools(tools []coreextension.Tool) error {
	if len(tools) == 0 {
		return coreextension.ErrConflict
	}
	seen := make(map[string]struct{}, len(tools))
	for _, tool := range tools {
		if tool.Name == "" || tool.Name != strings.TrimSpace(tool.Name) || coremodel.IsIntrinsicToolName(tool.Name) ||
			!coretask.ValidDigest(tool.InputSchemaDigest) {
			return coreextension.ErrConflict
		}
		if _, duplicate := seen[tool.Name]; duplicate {
			return coreextension.ErrConflict
		}
		seen[tool.Name] = struct{}{}
		var schema map[string]any
		if json.Unmarshal(tool.InputSchema, &schema) != nil || schema == nil {
			return coreextension.ErrConflict
		}
		canonical, err := json.Marshal(schema)
		if err != nil {
			return coreextension.ErrConflict
		}
		if fmt.Sprintf("%x", sha256Bytes(canonical)) != tool.InputSchemaDigest {
			return coreextension.ErrConflict
		}
	}
	return nil
}

func (r *PostgresExtensionToolRuntime) persistTools(ctx context.Context, installationID, versionID string, tools []coreextension.Tool) error {
	if r == nil || r.store == nil || r.store.pool == nil || len(tools) == 0 {
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
	// Third-party execution must enter the durable confirmation/task path via
	// coreextension.Service.Execute. This legacy synchronous seam cannot carry
	// a confirmation receipt, so fail closed instead of creating a runnable
	// task or dispatching directly.
	return "", coreextension.ErrConflict
}

var _ coreextension.ToolRuntime = (*PostgresExtensionToolRuntime)(nil)
