package postgres

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CoreDeprovisionStore owns the account deletion fence. Agent and Core rows
// are namespaced by the core_/agent_ prefixes; the protected ledger and state
// rows survive so a repeated request after a restart has a durable receipt.
type CoreDeprovisionStore struct{ pool *pgxpool.Pool }

func NewCoreDeprovisionStore(pool *pgxpool.Pool) *CoreDeprovisionStore {
	return &CoreDeprovisionStore{pool: pool}
}

func (s *CoreDeprovisionStore) CheckAdmission(ctx context.Context, owner string, generation int64) error {
	if s == nil || s.pool == nil || ctx == nil || strings.TrimSpace(owner) == "" || generation <= 0 {
		return coredeprovision.ErrInvalid
	}
	var state string
	err := s.pool.QueryRow(ctx, `SELECT state FROM `+deprovisionTable+` WHERE owner_id=$1 AND account_generation=$2 ORDER BY updated_at DESC LIMIT 1`, owner, generation).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("check account deprovision fence: %w", err)
	}
	return coredeprovision.ErrNotReady
}

func (s *CoreDeprovisionStore) HasDeprovisionFence(ctx context.Context) (bool, error) {
	if s == nil || s.pool == nil || ctx == nil {
		return false, coredeprovision.ErrInvalid
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM `+deprovisionTable+`)`).Scan(&exists); err != nil {
		return false, fmt.Errorf("read account deprovision fence: %w", err)
	}
	return exists, nil
}

const (
	deprovisionTable            = "agent_account_deprovisions"
	deprovisionAdvisoryLockName = "dirextalk:agent-account-deprovision"
	stateRunning                = "running"
	stateDBPurged               = "database_purged"
	stateCompleted              = "completed"
	stateFailed                 = "failed"
)

func (s *CoreDeprovisionStore) Deprovision(ctx context.Context, command coredeprovision.Command, checkPrecondition, externalPurge func(context.Context) error) (coredeprovision.Result, error) {
	if s == nil || s.pool == nil || ctx == nil || checkPrecondition == nil || externalPurge == nil {
		return coredeprovision.Result{}, coredeprovision.ErrInvalid
	}
	digest := deprovisionDigest(command)
	if err := ensureDeprovisionIdentity(command); err != nil {
		return coredeprovision.Result{}, err
	}

	// The DB phase is one transaction: claim the idempotency key, purge all
	// Agent-owned relational rows, and record that durable phase. The state
	// table and capability ledger are intentionally excluded from the purge.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coredeprovision.Result{}, fmt.Errorf("begin account deprovision: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		return coredeprovision.Result{}, fmt.Errorf("lock account deprovision fence: %w", err)
	}
	// Revalidate retained external state while holding the durable lifecycle
	// lock and before claiming a receipt or deleting any Agent-owned row.
	if err := checkPrecondition(ctx); err != nil {
		return coredeprovision.Result{}, err
	}
	var state string
	var existingDigest []byte
	err = tx.QueryRow(ctx, `SELECT state, request_digest FROM `+deprovisionTable+` WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 FOR UPDATE`, command.OwnerID, command.AccountGeneration, command.IdempotencyKey).Scan(&state, &existingDigest)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if _, err := tx.Exec(ctx, `INSERT INTO `+deprovisionTable+` (owner_id,account_generation,idempotency_key,request_digest,state,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,clock_timestamp(),clock_timestamp())`, command.OwnerID, command.AccountGeneration, command.IdempotencyKey, digest[:], stateRunning); err != nil {
			return coredeprovision.Result{}, fmt.Errorf("claim account deprovision: %w", err)
		}
	case err != nil:
		return coredeprovision.Result{}, fmt.Errorf("read account deprovision state: %w", err)
	default:
		if !equalDigest(existingDigest, digest[:]) {
			return coredeprovision.Result{}, coredeprovision.ErrConflict
		}
		if state == stateCompleted {
			if err := tx.Commit(ctx); err != nil {
				return coredeprovision.Result{}, fmt.Errorf("commit account deprovision replay: %w", err)
			}
			return coredeprovision.Result{Status: "deprovisioned", DatabasePurged: true, ExternalPurged: true}, nil
		}
		if _, err := tx.Exec(ctx, `UPDATE `+deprovisionTable+` SET state=$4, error_code='', error_message='', updated_at=clock_timestamp() WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, command.OwnerID, command.AccountGeneration, command.IdempotencyKey, stateRunning); err != nil {
			return coredeprovision.Result{}, fmt.Errorf("resume account deprovision: %w", err)
		}
	}
	if err := truncateAgentRows(ctx, tx); err != nil {
		return coredeprovision.Result{}, fmt.Errorf("purge Agent database rows: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE `+deprovisionTable+` SET state=$4, updated_at=clock_timestamp() WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, command.OwnerID, command.AccountGeneration, command.IdempotencyKey, stateDBPurged); err != nil {
		return coredeprovision.Result{}, fmt.Errorf("record Agent database purge: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return coredeprovision.Result{}, fmt.Errorf("commit Agent database purge: %w", err)
	}

	// Filesystem deletion is idempotent and happens only after the
	// relational fence is durable. A retry can therefore safely resume this
	// phase without replaying any user mutation.
	if err := externalPurge(ctx); err != nil {
		failedCtx := context.Background()
		_, _ = s.pool.Exec(failedCtx, `UPDATE `+deprovisionTable+` SET state=$4,error_code=$5,error_message=$6,updated_at=clock_timestamp() WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, command.OwnerID, command.AccountGeneration, command.IdempotencyKey, stateFailed, "EXTERNAL_PURGE_FAILED", safePurgeError(err))
		return coredeprovision.Result{Status: "database_purged", DatabasePurged: true}, fmt.Errorf("%w: %v", coredeprovision.ErrExternalPurge, err)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE `+deprovisionTable+` SET state=$4,error_code='',error_message='',updated_at=clock_timestamp(),completed_at=clock_timestamp() WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, command.OwnerID, command.AccountGeneration, command.IdempotencyKey, stateCompleted); err != nil {
		return coredeprovision.Result{Status: "external_purged", DatabasePurged: true, ExternalPurged: true}, fmt.Errorf("record completed Agent deprovision: %w", err)
	}
	return coredeprovision.Result{Status: "deprovisioned", DatabasePurged: true, ExternalPurged: true}, nil
}

func ensureDeprovisionIdentity(command coredeprovision.Command) error {
	if strings.TrimSpace(command.OwnerID) == "" || command.AccountGeneration <= 0 || command.Confirmation != coredeprovision.Confirmation {
		return coredeprovision.ErrInvalid
	}
	if _, err := uuid.Parse(command.IdempotencyKey); err != nil {
		return coredeprovision.ErrInvalid
	}
	return nil
}

func deprovisionDigest(command coredeprovision.Command) [32]byte {
	return sha256.Sum256([]byte(command.OwnerID + "\x00" + fmt.Sprint(command.AccountGeneration) + "\x00" + command.IdempotencyKey + "\x00" + command.Confirmation))
}

func equalDigest(a, b []byte) bool {
	return len(a) == len(b) && string(a) == string(b)
}

// truncateAgentRows obtains the table list from PostgreSQL rather than
// trusting a hand-maintained list. Prefixes are the Agent schema boundary;
// message-server tables in the shared database are never selected.
func truncateAgentRows(ctx context.Context, tx pgx.Tx) error {
	// Capability request/result/event payloads may contain chat, knowledge or
	// credential material. Remove every historical event and non-deprovision
	// operation before the broad prefix purge; only the minimal current
	// deprovision receipt (owner/generation/root digest/state) survives.
	if _, err := tx.Exec(ctx, `DELETE FROM agent_capability_operation_events`); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM agent_capability_operations WHERE capability_id <> 'agent.account.v1' OR operation_name <> 'deprovision_account'`); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=current_schema() AND c.relkind='r' AND (left(c.relname,5)='core_' OR left(c.relname,6)='agent_') AND c.relname NOT IN ('agent_instance_metadata','agent_schema_migrations','agent_capability_operations','agent_capability_operation_events','agent_account_deprovisions') ORDER BY c.relname`)
	if err != nil {
		return err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return err
		}
		if name == "" || strings.ContainsAny(name, "\x00\r\n\"") {
			return fmt.Errorf("invalid Agent table name")
		}
		tables = append(tables, `"`+strings.ReplaceAll(name, `"`, `""`)+`"`)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(tables) == 0 {
		return nil
	}
	// Keep deterministic ordering for logs and reproducible lock acquisition.
	sort.Strings(tables)
	_, err = tx.Exec(ctx, `TRUNCATE TABLE `+strings.Join(tables, ",")+` RESTART IDENTITY CASCADE`)
	return err
}

func safePurgeError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 4096 {
		s = s[:4096]
	}
	return s
}
