package postgres

import (
	"context"
	"encoding/json"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
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
	if len(v.Tools) == 0 {
		return nil, coreextension.ErrConflict
	}
	return append([]coreextension.Tool(nil), v.Tools...), nil
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
	// Third-party execution must enter the durable confirmation/task path via
	// coreextension.Service.Execute. This legacy synchronous seam cannot carry
	// a confirmation receipt, so fail closed instead of creating a runnable
	// task or dispatching directly.
	return "", coreextension.ErrConflict
}

var _ coreextension.ToolRuntime = (*PostgresExtensionToolRuntime)(nil)
