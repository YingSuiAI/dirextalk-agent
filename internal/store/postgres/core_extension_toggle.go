package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SetEnabled is the small durable projection mutation used by both the Skill
// and MCP aliases. It shares the extension replay table, row revision, and
// advisory lock with lifecycle mutations, so a disable racing an update or
// uninstall cannot publish a stale execution gate.
func (s *CoreExtensionStore) SetEnabled(ctx context.Context, command coreextension.ToggleCommand) (coreextension.Installation, error) {
	if s == nil || s.store == nil || uuid.Validate(command.IdempotencyKey) != nil || uuid.Validate(command.InstallationID) != nil || command.ExpectedRevision < 1 {
		return coreextension.Installation{}, coreextension.ErrInvalid
	}
	op := "disable"
	if command.Enabled {
		op = "enable"
	}
	digest := toggleDigest(command)
	ownerID, generation, err := replayOwnerScope(ctx, "extension", command.IdempotencyKey)
	if err != nil {
		return coreextension.Installation{}, coreextension.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coreextension.Installation{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, fmt.Sprintf("core_extension_toggle:%s:%d:%s", ownerID, generation, command.IdempotencyKey)); err != nil {
		return coreextension.Installation{}, err
	}
	installationLock := "core_extension_installation:" + command.InstallationID
	if scope, ok := coretask.OwnerScopeFromContext(ctx); ok {
		installationLock = fmt.Sprintf("core_extension_installation:%s:%d:%s", scope.OwnerID, scope.AccountGeneration, command.InstallationID)
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, installationLock); err != nil {
		return coreextension.Installation{}, err
	}
	var stored string
	var raw []byte
	lookupErr := tx.QueryRow(ctx, `SELECT request_hash,response_json FROM core_extension_replays WHERE owner_id=$1 AND account_generation=$2 AND operation=$3 AND idempotency_key=$4 FOR UPDATE`, ownerID, generation, op, command.IdempotencyKey).Scan(&stored, &raw)
	if lookupErr == nil {
		if stored != digest {
			return coreextension.Installation{}, coreextension.ErrIdempotencyConflict
		}
		var out coreextension.Installation
		if json.Unmarshal(raw, &out) != nil {
			return coreextension.Installation{}, coreextension.ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return coreextension.Installation{}, err
		}
		return out, nil
	}
	if !errors.Is(lookupErr, pgx.ErrNoRows) && !strings.Contains(strings.ToLower(lookupErr.Error()), "no rows") {
		return coreextension.Installation{}, lookupErr
	}
	var revision int64
	var state string
	var enabled bool
	var active string
	ownerID, installationGeneration := "", int64(0)
	if scope, ok := coretask.OwnerScopeFromContext(ctx); ok {
		ownerID, installationGeneration = scope.OwnerID, scope.AccountGeneration
	}
	if err = tx.QueryRow(ctx, `SELECT revision,state,enabled,COALESCE(active_version_id::text,'') FROM core_extension_installations WHERE installation_id=$1 AND ($2='' OR (owner_id=$2 AND account_generation=$3)) FOR UPDATE`, command.InstallationID, ownerID, installationGeneration).Scan(&revision, &state, &enabled, &active); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreextension.Installation{}, coreextension.ErrNotFound
		}
		return coreextension.Installation{}, err
	}
	if revision != command.ExpectedRevision {
		return coreextension.Installation{}, coreextension.ErrRevisionConflict
	}
	if state != string(coreextension.StateInstalled) || active == "" {
		return coreextension.Installation{}, coreextension.ErrConflict
	}
	if enabled != command.Enabled {
		if _, err = tx.Exec(ctx, `UPDATE core_extension_installations SET enabled=$2,revision=revision+1,updated_at=clock_timestamp() WHERE installation_id=$1 AND revision=$3 AND ($4='' OR (owner_id=$4 AND account_generation=$5))`, command.InstallationID, command.Enabled, command.ExpectedRevision, ownerID, installationGeneration); err != nil {
			return coreextension.Installation{}, err
		}
	}
	var out coreextension.Installation
	getQuery := `SELECT installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,COALESCE(active_version_id::text,''),COALESCE(proposed_version_id::text,''),network_grants_json,secret_grants_json,created_at,updated_at FROM core_extension_installations WHERE installation_id=$1 AND ($2='' OR (owner_id=$2 AND account_generation=$3))`
	if out, err = s.getTx(ctx, tx.QueryRow(ctx, getQuery, command.InstallationID, ownerID, installationGeneration)); err != nil {
		return coreextension.Installation{}, err
	}
	response, _ := json.Marshal(out)
	if _, err = tx.Exec(ctx, `INSERT INTO core_extension_replays(owner_id,account_generation,operation,idempotency_key,request_hash,response_json) VALUES($1,$2,$3,$4,$5,$6)`, ownerID, generation, op, command.IdempotencyKey, digest, response); err != nil {
		return coreextension.Installation{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreextension.Installation{}, err
	}
	return out, nil
}

func toggleDigest(command coreextension.ToggleCommand) string {
	b, _ := json.Marshal(struct {
		InstallationID   string
		ExpectedRevision int64
		Enabled          bool
	}{command.InstallationID, command.ExpectedRevision, command.Enabled})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
