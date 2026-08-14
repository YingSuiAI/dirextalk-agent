package modelrelay

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	PostgresBudgetTable     = "core_cloud_worker_model_budgets"
	PostgresGrantTable      = "core_cloud_worker_model_grants"
	PostgresInvocationTable = "core_cloud_worker_model_invocations"
)

// PostgresSchemaRequirement is consumed by the single Adam migration. The
// relay never creates or migrates tables at runtime.
const PostgresSchemaRequirement = `CREATE TABLE core_cloud_worker_model_budgets (
    execution_id uuid PRIMARY KEY REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    plan_id uuid NOT NULL REFERENCES core_cloud_worker_plans(plan_id) ON DELETE RESTRICT,
    plan_revision bigint NOT NULL CHECK (plan_revision > 0),
    plan_digest char(64) NOT NULL CHECK (plan_digest ~ '^[a-f0-9]{64}$'),
    limit_digest char(64) NOT NULL CHECK (limit_digest ~ '^[a-f0-9]{64}$'),
	max_tokens bigint NOT NULL CHECK (max_tokens BETWEEN 0 AND 10000000),
    reserved_tokens bigint NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    settled_tokens bigint NOT NULL DEFAULT 0 CHECK (settled_tokens >= 0),
    revision bigint NOT NULL CHECK (revision > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
	CHECK (max_tokens = 0 OR reserved_tokens <= max_tokens - settled_tokens),
    CHECK (updated_at >= created_at)
);

CREATE TABLE core_cloud_worker_model_grants (
    grant_id uuid PRIMARY KEY,
    owner_id text NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 512),
    account_generation bigint NOT NULL CHECK (account_generation > 0),
    execution_id uuid NOT NULL REFERENCES core_cloud_worker_executions(execution_id) ON DELETE RESTRICT,
    task_id uuid NOT NULL REFERENCES core_tasks(task_id) ON DELETE RESTRICT,
    task_attempt integer NOT NULL CHECK (task_attempt > 0),
    lease_epoch bigint NOT NULL CHECK (lease_epoch > 0),
    session_id uuid NOT NULL REFERENCES core_cloud_worker_sessions(session_id) ON DELETE RESTRICT,
    token_digest bytea NOT NULL UNIQUE CHECK (octet_length(token_digest) = 32),
    model_profile_id uuid NOT NULL,
	model_profile_revision bigint NOT NULL CHECK (model_profile_revision > 0),
	credential_version bigint NOT NULL CHECK (credential_version > 0),
	model_maximum_output_tokens bigint NOT NULL CHECK (model_maximum_output_tokens BETWEEN 0 AND 10000000),
	provider text NOT NULL CHECK (provider IN ('openai','openai_compatible')),
    model_interface text NOT NULL CHECK (model_interface IN ('openai_responses','openai_compatible')),
    model_name text NOT NULL CHECK (length(model_name) BETWEEN 1 AND 256),
    credential_binding_digest char(64) NOT NULL CHECK (credential_binding_digest ~ '^[a-f0-9]{64}$'),
    model_binding_digest char(64) NOT NULL CHECK (model_binding_digest ~ '^[a-f0-9]{64}$'),
    audience_digest char(64) NOT NULL CHECK (audience_digest ~ '^[a-f0-9]{64}$'),
    limit_digest char(64) NOT NULL CHECK (limit_digest ~ '^[a-f0-9]{64}$'),
    relay_url text NOT NULL CHECK (length(relay_url) BETWEEN 1 AND 2048),
    relay_binding_digest char(64) NOT NULL CHECK (relay_binding_digest ~ '^[a-f0-9]{64}$'),
	max_tokens bigint NOT NULL CHECK (max_tokens BETWEEN 0 AND 10000000),
    reserved_tokens bigint NOT NULL DEFAULT 0 CHECK (reserved_tokens >= 0),
    settled_tokens bigint NOT NULL DEFAULT 0 CHECK (settled_tokens >= 0),
    state text NOT NULL CHECK (state IN ('active','fenced','terminal')),
    reason_code text NOT NULL DEFAULT '' CHECK (length(reason_code) <= 64),
    expires_at timestamptz NOT NULL,
    activated_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    fenced_at timestamptz,
    terminal_at timestamptz,
    revision bigint NOT NULL CHECK (revision > 0),
    FOREIGN KEY (task_id, task_attempt, lease_epoch)
        REFERENCES core_cloud_worker_launch_expectations(task_id, task_attempt, lease_epoch) ON DELETE RESTRICT,
	CHECK (max_tokens = 0 OR reserved_tokens <= max_tokens - settled_tokens),
    CHECK (expires_at > activated_at),
    CHECK ((state = 'active') = (reason_code = '' AND fenced_at IS NULL AND terminal_at IS NULL)),
    CHECK ((state = 'fenced') = (fenced_at IS NOT NULL AND terminal_at IS NULL)),
    CHECK ((state = 'terminal') = (terminal_at IS NOT NULL))
);
CREATE UNIQUE INDEX core_cloud_worker_model_grants_one_active_idx
    ON core_cloud_worker_model_grants(execution_id) WHERE state = 'active';

CREATE TABLE core_cloud_worker_model_invocations (
    invocation_id uuid PRIMARY KEY,
    grant_id uuid NOT NULL REFERENCES core_cloud_worker_model_grants(grant_id) ON DELETE RESTRICT,
    path text NOT NULL CHECK (path IN ('/v1/responses','/v1/chat/completions')),
    request_digest char(64) NOT NULL CHECK (request_digest ~ '^[a-f0-9]{64}$'),
    reserved_tokens bigint NOT NULL CHECK (reserved_tokens BETWEEN 1 AND 10000000),
    actual_tokens bigint CHECK (actual_tokens BETWEEN 0 AND reserved_tokens),
    state text NOT NULL CHECK (state IN ('reserved','settled','refunded')),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK ((state = 'settled') = (actual_tokens IS NOT NULL)),
    CHECK (state = 'settled' OR actual_tokens IS NULL)
);
CREATE INDEX core_cloud_worker_model_invocations_grant_idx
    ON core_cloud_worker_model_invocations(grant_id, state, created_at);`

const grantColumns = `grant_id::text,owner_id,account_generation,execution_id::text,task_id::text,
	task_attempt,lease_epoch,session_id::text,model_profile_id::text,model_profile_revision,
	credential_version,model_maximum_output_tokens,provider,model_interface,model_name,credential_binding_digest,
model_binding_digest,audience_digest,limit_digest,relay_url,relay_binding_digest,
max_tokens,reserved_tokens,settled_tokens,state,reason_code,expires_at,activated_at,
updated_at,fenced_at,terminal_at,revision`

const invocationColumns = `invocation_id::text,grant_id::text,path,request_digest,
reserved_tokens,actual_tokens,state,created_at,updated_at`

const budgetColumns = `execution_id::text,plan_id::text,plan_revision,plan_digest,
limit_digest,max_tokens,reserved_tokens,settled_tokens,revision,created_at,updated_at`

type postgresPool interface {
	BeginTx(context.Context, pgx.TxOptions) (pgx.Tx, error)
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

type PostgresStore struct{ pool postgresPool }

type postgresExecutionBudget struct {
	executionBudget
	PlanID       string
	PlanRevision uint64
	PlanDigest   string
}

func (budget postgresExecutionBudget) validate() error {
	if budget.executionBudget.validate() != nil || !canonicalUUID(budget.PlanID) ||
		budget.PlanRevision == 0 || !validDigest(budget.PlanDigest) {
		return ErrInvalid
	}
	return nil
}

func NewPostgresStore(pool *pgxpool.Pool) (*PostgresStore, error) {
	if pool == nil {
		return nil, ErrInvalid
	}
	return &PostgresStore{pool: pool}, nil
}

func newPostgresStore(pool postgresPool) (*PostgresStore, error) {
	if pool == nil {
		return nil, ErrInvalid
	}
	return &PostgresStore{pool: pool}, nil
}

func (s *PostgresStore) Ready(ctx context.Context) error {
	if s == nil || s.pool == nil || ctx == nil {
		return ErrInvalid
	}
	var budgets, grants, invocations string
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(to_regclass($1)::text,''),COALESCE(to_regclass($2)::text,''),COALESCE(to_regclass($3)::text,'')`,
		PostgresBudgetTable, PostgresGrantTable, PostgresInvocationTable).Scan(&budgets, &grants, &invocations); err != nil ||
		budgets != PostgresBudgetTable || grants != PostgresGrantTable || invocations != PostgresInvocationTable {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) Activate(ctx context.Context, mutation ActivationMutation) (Grant, error) {
	if s == nil || s.pool == nil || ctx == nil || mutation.Grant.Validate() != nil ||
		mutation.Grant.State != GrantActive {
		return Grant{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Grant{}, ErrConflict
	}
	defer tx.Rollback(ctx)
	if err := lockRelayAuthority(ctx, tx, mutation.Grant.Fence); err != nil {
		return Grant{}, err
	}
	budget, err := activateExecutionBudget(ctx, tx, mutation.Grant)
	if err != nil {
		return Grant{}, err
	}
	if budget.availableTokens() == 0 {
		return Grant{}, ErrBudgetExhausted
	}
	if _, err := tx.Exec(ctx, `UPDATE core_cloud_worker_model_grants
SET state='fenced',reason_code='superseded',fenced_at=$2,updated_at=$2,revision=revision+1
WHERE execution_id=$1 AND state='active'`, mutation.Grant.Fence.ExecutionID, mutation.Grant.ActivatedAt); err != nil {
		return Grant{}, ErrConflict
	}
	g := mutation.Grant
	_, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_model_grants
(grant_id,owner_id,account_generation,execution_id,task_id,task_attempt,lease_epoch,session_id,
	 token_digest,model_profile_id,model_profile_revision,credential_version,model_maximum_output_tokens,provider,model_interface,
 model_name,credential_binding_digest,model_binding_digest,audience_digest,limit_digest,relay_url,
 relay_binding_digest,max_tokens,reserved_tokens,settled_tokens,state,reason_code,expires_at,
 activated_at,updated_at,fenced_at,terminal_at,revision)
	VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,0,0,$24,'',$25,$26,$26,NULL,NULL,1)`,
		g.GrantID, g.Fence.OwnerID, int64(g.Fence.AccountGeneration), g.Fence.ExecutionID,
		g.Fence.TaskID, int32(g.Fence.Attempt), int64(g.Fence.LeaseEpoch), g.Fence.SessionID,
		mutation.TokenDigest[:], g.Profile.ProfileID, int64(g.Profile.ProfileRevision),
		int64(g.Profile.CredentialVersion), int64(g.Profile.MaximumOutputTokens),
		g.Profile.Provider, g.Profile.Interface, g.Profile.Model,
		g.Profile.CredentialBindingDigest, g.Profile.ModelBindingDigest, g.AudienceDigest,
		g.LimitDigest, g.RelayURL, g.RelayBindingDigest, int64(g.MaxTokens), string(g.State),
		g.ExpiresAt, g.ActivatedAt)
	if err != nil {
		return Grant{}, ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return Grant{}, ErrConflict
	}
	return g, nil
}

func activateExecutionBudget(
	ctx context.Context,
	tx pgx.Tx,
	grant Grant,
) (postgresExecutionBudget, error) {
	var planID, planDigest string
	var planRevision int64
	var planMaxTokens sql.NullInt64
	err := tx.QueryRow(ctx, `SELECT e.plan_id::text,e.plan_revision,e.plan_digest,
       (p.plan_json #>> '{limits,max_tokens}')::bigint
FROM core_cloud_worker_executions e
JOIN core_cloud_worker_plans p ON p.plan_id=e.plan_id
WHERE e.execution_id=$1 AND p.execution_id=e.execution_id
  AND p.revision=e.plan_revision AND p.digest=e.plan_digest`, grant.Fence.ExecutionID).Scan(
		&planID, &planRevision, &planDigest, &planMaxTokens)
	expectedMaxTokens, expectedErr := authorizedPlanMaxTokens(planMaxTokens)
	if err != nil || !canonicalUUID(planID) || planRevision <= 0 || !validDigest(planDigest) ||
		expectedErr != nil || grant.MaxTokens != expectedMaxTokens {
		return postgresExecutionBudget{}, ErrConflict
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_cloud_worker_model_budgets(
execution_id,plan_id,plan_revision,plan_digest,limit_digest,max_tokens,reserved_tokens,
settled_tokens,revision,created_at,updated_at)
	VALUES($1,$2,$3,$4,$5,$6,0,0,1,$7,$7)
ON CONFLICT (execution_id) DO NOTHING`, grant.Fence.ExecutionID, planID, planRevision,
		planDigest, grant.LimitDigest, int64(grant.MaxTokens), grant.ActivatedAt); err != nil {
		return postgresExecutionBudget{}, ErrConflict
	}
	budget, err := scanExecutionBudget(tx.QueryRow(ctx, `SELECT `+budgetColumns+`
FROM core_cloud_worker_model_budgets WHERE execution_id=$1 FOR UPDATE`, grant.Fence.ExecutionID))
	if err != nil || budget.PlanID != planID || budget.PlanRevision != uint64(planRevision) ||
		budget.PlanDigest != planDigest || budget.LimitDigest != grant.LimitDigest ||
		budget.MaxTokens != grant.MaxTokens {
		return postgresExecutionBudget{}, ErrConflict
	}
	return budget, nil
}

func (s *PostgresStore) BeginInvocation(ctx context.Context, mutation BeginMutation) (Grant, Invocation, error) {
	if s == nil || s.pool == nil || ctx == nil || !canonicalUUID(mutation.InvocationID) ||
		!validPath(mutation.Path) || !validDigest(mutation.RequestDigest) ||
		mutation.RequestedTokens == 0 || mutation.RequestedTokens > MaximumRequestTokens ||
		mutation.At.IsZero() || mutation.At != mutation.At.UTC() {
		return Grant{}, Invocation{}, ErrInvalid
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	defer tx.Rollback(ctx)
	initial, err := scanGrant(tx.QueryRow(ctx,
		`SELECT `+grantColumns+` FROM core_cloud_worker_model_grants WHERE token_digest=$1`, mutation.TokenDigest[:]))
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, Invocation{}, ErrUnauthorized
	}
	if err != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	authorityErr := lockRelayAuthority(ctx, tx, initial.Fence)
	if authorityErr != nil && !errors.Is(authorityErr, ErrStaleFence) &&
		!errors.Is(authorityErr, ErrTerminal) {
		return Grant{}, Invocation{}, authorityErr
	}
	budget, err := lockExecutionBudget(ctx, tx, initial.Fence.ExecutionID)
	if err != nil {
		return Grant{}, Invocation{}, err
	}
	grant, err := scanGrant(tx.QueryRow(ctx, `SELECT `+grantColumns+`
FROM core_cloud_worker_model_grants WHERE grant_id=$1 AND token_digest=$2 FOR UPDATE`,
		initial.GrantID, mutation.TokenDigest[:]))
	if err != nil || !sameGrantAuthorization(initial, grant) || budget.LimitDigest != grant.LimitDigest ||
		budget.MaxTokens != grant.MaxTokens {
		return Grant{}, Invocation{}, ErrConflict
	}
	if authorityErr != nil {
		terminal := errors.Is(authorityErr, ErrTerminal)
		reason := "stale_fence"
		if terminal {
			reason = "execution_terminal"
		}
		if grant.State == GrantActive {
			next := fenceGrant(grant, reason, terminal, mutation.At)
			if err := updateGrant(ctx, tx, next, grant.Revision); err != nil {
				return Grant{}, Invocation{}, err
			}
			grant = next
		}
		if err := tx.Commit(ctx); err != nil {
			return Grant{}, Invocation{}, ErrConflict
		}
		return grant, Invocation{}, authorityErr
	}
	if grant.State == GrantTerminal {
		return grant, Invocation{}, ErrTerminal
	}
	if grant.State != GrantActive {
		return grant, Invocation{}, ErrFenced
	}
	if !mutation.At.Before(grant.ExpiresAt) {
		next := fenceGrant(grant, "expired", false, mutation.At)
		if err := updateGrant(ctx, tx, next, grant.Revision); err != nil {
			return Grant{}, Invocation{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return Grant{}, Invocation{}, ErrConflict
		}
		return next, Invocation{}, ErrExpired
	}
	if mutation.Path != grant.Profile.Path() {
		return grant, Invocation{}, ErrUnauthorized
	}
	available := budget.availableTokens()
	if grantAvailable := grant.AvailableTokens(); grantAvailable < available {
		available = grantAvailable
	}
	if available == 0 {
		return grant, Invocation{}, ErrBudgetExhausted
	}
	reserved := mutation.RequestedTokens
	if reserved > available {
		reserved = available
	}
	invocation := Invocation{
		InvocationID: mutation.InvocationID, GrantID: grant.GrantID,
		Path: mutation.Path, RequestDigest: mutation.RequestDigest,
		ReservedTokens: reserved, State: InvocationReserved,
		CreatedAt: mutation.At, UpdatedAt: mutation.At,
	}
	if invocation.Validate() != nil {
		return Grant{}, Invocation{}, ErrInvalid
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core_cloud_worker_model_invocations
(invocation_id,grant_id,path,request_digest,reserved_tokens,actual_tokens,state,created_at,updated_at)
VALUES($1,$2,$3,$4,$5,NULL,'reserved',$6,$6)`, invocation.InvocationID, invocation.GrantID,
		invocation.Path, invocation.RequestDigest, int64(invocation.ReservedTokens), invocation.CreatedAt); err != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	next := grant
	next.ReservedTokens += reserved
	next.Revision++
	next.UpdatedAt = mutation.At
	nextBudget := budget
	nextBudget.ReservedTokens += reserved
	nextBudget.Revision++
	nextBudget.UpdatedAt = mutation.At
	if err := updateGrant(ctx, tx, next, grant.Revision); err != nil {
		return Grant{}, Invocation{}, err
	}
	if err := updateExecutionBudget(ctx, tx, nextBudget, budget.Revision); err != nil {
		return Grant{}, Invocation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	return next, invocation, nil
}

func (s *PostgresStore) Settle(ctx context.Context, mutation SettleMutation) (Grant, Invocation, error) {
	if s == nil || s.pool == nil || ctx == nil || !canonicalUUID(mutation.InvocationID) ||
		mutation.ActualTokens > MaximumRequestTokens || mutation.At.IsZero() || mutation.At != mutation.At.UTC() {
		return Grant{}, Invocation{}, ErrInvalid
	}
	return s.finishInvocation(ctx, mutation.InvocationID, mutation.ActualTokens, false, mutation.At)
}

func (s *PostgresStore) Refund(ctx context.Context, mutation RefundMutation) (Grant, Invocation, error) {
	if s == nil || s.pool == nil || ctx == nil || !canonicalUUID(mutation.InvocationID) ||
		mutation.At.IsZero() || mutation.At != mutation.At.UTC() {
		return Grant{}, Invocation{}, ErrInvalid
	}
	return s.finishInvocation(ctx, mutation.InvocationID, 0, true, mutation.At)
}

func (s *PostgresStore) finishInvocation(
	ctx context.Context,
	invocationID string,
	actual uint64,
	refund bool,
	at time.Time,
) (Grant, Invocation, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})
	if err != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	defer tx.Rollback(ctx)
	initial, err := scanInvocation(tx.QueryRow(ctx, `SELECT `+invocationColumns+`
FROM core_cloud_worker_model_invocations WHERE invocation_id=$1`, invocationID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, Invocation{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	initialGrant, err := scanGrant(tx.QueryRow(ctx, `SELECT `+grantColumns+`
FROM core_cloud_worker_model_grants WHERE grant_id=$1`, initial.GrantID))
	if err != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	var authorityErr error
	if !refund {
		authorityErr = lockRelayAuthority(ctx, tx, initialGrant.Fence)
		if authorityErr != nil && !errors.Is(authorityErr, ErrStaleFence) &&
			!errors.Is(authorityErr, ErrTerminal) {
			return Grant{}, Invocation{}, authorityErr
		}
	}
	budget, err := lockExecutionBudget(ctx, tx, initialGrant.Fence.ExecutionID)
	if err != nil {
		return Grant{}, Invocation{}, err
	}
	grant, err := scanGrant(tx.QueryRow(ctx, `SELECT `+grantColumns+`
FROM core_cloud_worker_model_grants WHERE grant_id=$1 FOR UPDATE`, initial.GrantID))
	if err != nil || !sameGrantAuthorization(initialGrant, grant) || budget.LimitDigest != grant.LimitDigest ||
		budget.MaxTokens != grant.MaxTokens {
		return Grant{}, Invocation{}, ErrConflict
	}
	invocation, err := scanInvocation(tx.QueryRow(ctx, `SELECT `+invocationColumns+`
FROM core_cloud_worker_model_invocations WHERE invocation_id=$1 FOR UPDATE`, invocationID))
	if err != nil || invocation.GrantID != grant.GrantID || invocation.ReservedTokens > grant.ReservedTokens {
		return Grant{}, Invocation{}, ErrConflict
	}
	if invocation.State != InvocationReserved {
		if (refund && invocation.State == InvocationRefunded) ||
			(!refund && invocation.State == InvocationSettled && invocation.ActualTokens == actual) {
			if err := tx.Commit(ctx); err != nil {
				return Grant{}, Invocation{}, ErrConflict
			}
			return grant, invocation, nil
		}
		return grant, invocation, ErrConflict
	}
	if budget.ReservedTokens < invocation.ReservedTokens {
		return Grant{}, Invocation{}, ErrConflict
	}
	nextGrant := grant
	nextGrant.ReservedTokens -= invocation.ReservedTokens
	nextGrant.Revision++
	nextGrant.UpdatedAt = at
	nextBudget := budget
	nextBudget.ReservedTokens -= invocation.ReservedTokens
	nextBudget.Revision++
	nextBudget.UpdatedAt = at
	var outcomeErr error
	if !refund {
		switch grant.State {
		case GrantTerminal:
			outcomeErr = ErrTerminal
		case GrantFenced:
			outcomeErr = ErrFenced
		case GrantActive:
			if !at.Before(grant.ExpiresAt) {
				outcomeErr = ErrExpired
			} else if authorityErr != nil {
				outcomeErr = authorityErr
			}
		default:
			return Grant{}, Invocation{}, ErrConflict
		}
	}
	nextInvocation := invocation
	nextInvocation.UpdatedAt = at
	overrun := !refund && actual > invocation.ReservedTokens
	if refund {
		nextInvocation.State = InvocationRefunded
	} else {
		if overrun {
			actual = invocation.ReservedTokens
		}
		nextInvocation.State = InvocationSettled
		nextInvocation.ActualTokens = actual
		nextGrant.SettledTokens += actual
		nextBudget.SettledTokens += actual
	}
	if overrun {
		outcomeErr = ErrBudgetExhausted
		if nextGrant.State == GrantActive {
			nextGrant.State = GrantFenced
			nextGrant.ReasonCode = "provider_token_overrun"
			nextGrant.FencedAt = at
		}
	} else if outcomeErr != nil && nextGrant.State == GrantActive {
		reason, terminal := "stale_fence", false
		switch {
		case errors.Is(outcomeErr, ErrExpired):
			reason = "expired"
		case errors.Is(outcomeErr, ErrTerminal):
			reason, terminal = "execution_terminal", true
		}
		nextGrant.State = GrantFenced
		nextGrant.ReasonCode = reason
		nextGrant.FencedAt = at
		if terminal {
			nextGrant.State = GrantTerminal
			nextGrant.TerminalAt = at
		}
	}
	if nextGrant.Validate() != nil || nextInvocation.Validate() != nil || nextBudget.validate() != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	var actualArg any
	if nextInvocation.State == InvocationSettled {
		actualArg = int64(nextInvocation.ActualTokens)
	}
	result, err := tx.Exec(ctx, `UPDATE core_cloud_worker_model_invocations
SET actual_tokens=$2,state=$3,updated_at=$4 WHERE invocation_id=$1 AND state='reserved'`,
		nextInvocation.InvocationID, actualArg, string(nextInvocation.State), nextInvocation.UpdatedAt)
	if err != nil || result.RowsAffected() != 1 {
		return Grant{}, Invocation{}, ErrConflict
	}
	if err := updateGrant(ctx, tx, nextGrant, grant.Revision); err != nil {
		return Grant{}, Invocation{}, err
	}
	if err := updateExecutionBudget(ctx, tx, nextBudget, budget.Revision); err != nil {
		return Grant{}, Invocation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	if outcomeErr != nil {
		return nextGrant, nextInvocation, outcomeErr
	}
	return nextGrant, nextInvocation, nil
}

func (s *PostgresStore) FenceExecution(ctx context.Context, mutation FenceMutation) error {
	if s == nil || s.pool == nil || ctx == nil || mutation.Fence.Validate() != nil ||
		mutation.ReasonCode == "" || !validReason(mutation.ReasonCode) ||
		mutation.At.IsZero() || mutation.At != mutation.At.UTC() {
		return ErrInvalid
	}
	state := string(GrantFenced)
	var terminalAt any
	if mutation.Terminal {
		state = string(GrantTerminal)
		terminalAt = mutation.At
	}
	result, err := s.execFence(ctx, mutation, state, terminalAt)
	if err != nil {
		return ErrConflict
	}
	if result.RowsAffected() != 0 {
		return nil
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_cloud_worker_model_grants
WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4 AND session_id=$5)`,
		mutation.Fence.ExecutionID, mutation.Fence.TaskID, int32(mutation.Fence.Attempt),
		int64(mutation.Fence.LeaseEpoch), mutation.Fence.SessionID).Scan(&exists); err != nil {
		return ErrConflict
	}
	if !exists {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) execFence(
	ctx context.Context,
	mutation FenceMutation,
	state string,
	terminalAt any,
) (pgconn.CommandTag, error) {
	return s.pool.Exec(ctx, `UPDATE core_cloud_worker_model_grants
SET state=$6,reason_code=$7,fenced_at=COALESCE(fenced_at,$8),terminal_at=$9,
    updated_at=$8,revision=revision+1
WHERE execution_id=$1 AND task_id=$2 AND task_attempt=$3 AND lease_epoch=$4 AND session_id=$5
  AND (state='active' OR ($6='terminal' AND state='fenced'))`,
		mutation.Fence.ExecutionID, mutation.Fence.TaskID, int32(mutation.Fence.Attempt),
		int64(mutation.Fence.LeaseEpoch), mutation.Fence.SessionID, state,
		mutation.ReasonCode, mutation.At, terminalAt)
}

func (s *PostgresStore) GetGrant(ctx context.Context, grantID string) (Grant, error) {
	if s == nil || s.pool == nil || ctx == nil || !canonicalUUID(grantID) {
		return Grant{}, ErrInvalid
	}
	grant, err := scanGrant(s.pool.QueryRow(ctx, `SELECT `+grantColumns+`
FROM core_cloud_worker_model_grants WHERE grant_id=$1`, grantID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Grant{}, ErrNotFound
	}
	if err != nil {
		return Grant{}, ErrConflict
	}
	return grant, nil
}

type rowScanner interface{ Scan(...any) error }

func scanGrant(row rowScanner) (Grant, error) {
	var grant Grant
	var accountGeneration, leaseEpoch, profileRevision, credentialVersion, maximumOutputTokens int64
	var maxTokens, reservedTokens, settledTokens, revision int64
	var attempt int32
	var state string
	var fencedAt, terminalAt *time.Time
	err := row.Scan(&grant.GrantID, &grant.Fence.OwnerID, &accountGeneration,
		&grant.Fence.ExecutionID, &grant.Fence.TaskID, &attempt, &leaseEpoch,
		&grant.Fence.SessionID, &grant.Profile.ProfileID, &profileRevision,
		&credentialVersion, &maximumOutputTokens, &grant.Profile.Provider, &grant.Profile.Interface,
		&grant.Profile.Model, &grant.Profile.CredentialBindingDigest,
		&grant.Profile.ModelBindingDigest, &grant.AudienceDigest, &grant.LimitDigest,
		&grant.RelayURL, &grant.RelayBindingDigest, &maxTokens, &reservedTokens,
		&settledTokens, &state, &grant.ReasonCode, &grant.ExpiresAt,
		&grant.ActivatedAt, &grant.UpdatedAt, &fencedAt, &terminalAt, &revision)
	if err != nil {
		return Grant{}, err
	}
	if accountGeneration <= 0 || leaseEpoch <= 0 || profileRevision <= 0 ||
		credentialVersion <= 0 || maximumOutputTokens < 0 || maxTokens < 0 || reservedTokens < 0 || settledTokens < 0 ||
		revision <= 0 || attempt <= 0 {
		return Grant{}, ErrConflict
	}
	grant.Fence.AccountGeneration = uint64(accountGeneration)
	grant.Fence.Attempt = uint32(attempt)
	grant.Fence.LeaseEpoch = uint64(leaseEpoch)
	grant.Profile.OwnerID = grant.Fence.OwnerID
	grant.Profile.AccountGeneration = grant.Fence.AccountGeneration
	grant.Profile.ProfileRevision = uint64(profileRevision)
	grant.Profile.CredentialVersion = uint64(credentialVersion)
	grant.Profile.MaximumOutputTokens = uint64(maximumOutputTokens)
	grant.MaxTokens, grant.ReservedTokens, grant.SettledTokens = uint64(maxTokens), uint64(reservedTokens), uint64(settledTokens)
	grant.State, grant.Revision = GrantState(state), uint64(revision)
	if fencedAt != nil {
		grant.FencedAt = fencedAt.UTC()
	}
	if terminalAt != nil {
		grant.TerminalAt = terminalAt.UTC()
	}
	grant.ExpiresAt = grant.ExpiresAt.UTC()
	grant.ActivatedAt = grant.ActivatedAt.UTC()
	grant.UpdatedAt = grant.UpdatedAt.UTC()
	if grant.Validate() != nil {
		return Grant{}, ErrConflict
	}
	return grant, nil
}

func scanInvocation(row rowScanner) (Invocation, error) {
	var invocation Invocation
	var reserved int64
	var actual sql.NullInt64
	var state string
	if err := row.Scan(&invocation.InvocationID, &invocation.GrantID, &invocation.Path,
		&invocation.RequestDigest, &reserved, &actual, &state,
		&invocation.CreatedAt, &invocation.UpdatedAt); err != nil {
		return Invocation{}, err
	}
	if reserved <= 0 || (actual.Valid && actual.Int64 < 0) {
		return Invocation{}, ErrConflict
	}
	invocation.ReservedTokens = uint64(reserved)
	invocation.State = InvocationState(state)
	if actual.Valid {
		invocation.ActualTokens = uint64(actual.Int64)
	}
	invocation.CreatedAt = invocation.CreatedAt.UTC()
	invocation.UpdatedAt = invocation.UpdatedAt.UTC()
	if (invocation.State == InvocationSettled) != actual.Valid || invocation.Validate() != nil {
		return Invocation{}, ErrConflict
	}
	return invocation, nil
}

func lockExecutionBudget(
	ctx context.Context,
	tx pgx.Tx,
	executionID string,
) (postgresExecutionBudget, error) {
	if !canonicalUUID(executionID) {
		return postgresExecutionBudget{}, ErrInvalid
	}
	var planID, planDigest string
	var planRevision int64
	var planMaxTokens sql.NullInt64
	if err := tx.QueryRow(ctx, `SELECT e.plan_id::text,e.plan_revision,e.plan_digest,
       (p.plan_json #>> '{limits,max_tokens}')::bigint
FROM core_cloud_worker_executions e
JOIN core_cloud_worker_plans p ON p.plan_id=e.plan_id
WHERE e.execution_id=$1 AND p.execution_id=e.execution_id
  AND p.revision=e.plan_revision AND p.digest=e.plan_digest
FOR UPDATE OF e`, executionID).Scan(&planID, &planRevision, &planDigest, &planMaxTokens); err != nil {
		return postgresExecutionBudget{}, ErrConflict
	}
	expectedMaxTokens, err := authorizedPlanMaxTokens(planMaxTokens)
	if err != nil || !canonicalUUID(planID) || planRevision <= 0 || !validDigest(planDigest) {
		return postgresExecutionBudget{}, ErrConflict
	}
	budget, err := scanExecutionBudget(tx.QueryRow(ctx, `SELECT `+budgetColumns+`
FROM core_cloud_worker_model_budgets WHERE execution_id=$1 FOR UPDATE`, executionID))
	if err != nil {
		return postgresExecutionBudget{}, ErrConflict
	}
	if budget.PlanID != planID || budget.PlanRevision != uint64(planRevision) ||
		budget.PlanDigest != planDigest || budget.MaxTokens != expectedMaxTokens {
		return postgresExecutionBudget{}, ErrConflict
	}
	return budget, nil
}

func scanExecutionBudget(row rowScanner) (postgresExecutionBudget, error) {
	var budget postgresExecutionBudget
	var planRevision, maxTokens, reservedTokens, settledTokens, revision int64
	err := row.Scan(&budget.ExecutionID, &budget.PlanID, &planRevision, &budget.PlanDigest,
		&budget.LimitDigest, &maxTokens, &reservedTokens, &settledTokens, &revision,
		&budget.CreatedAt, &budget.UpdatedAt)
	if err != nil {
		return postgresExecutionBudget{}, err
	}
	if planRevision <= 0 || maxTokens < 0 || reservedTokens < 0 || settledTokens < 0 || revision <= 0 {
		return postgresExecutionBudget{}, ErrConflict
	}
	budget.PlanRevision = uint64(planRevision)
	budget.MaxTokens = uint64(maxTokens)
	budget.ReservedTokens = uint64(reservedTokens)
	budget.SettledTokens = uint64(settledTokens)
	budget.Revision = uint64(revision)
	budget.CreatedAt = budget.CreatedAt.UTC()
	budget.UpdatedAt = budget.UpdatedAt.UTC()
	if budget.validate() != nil {
		return postgresExecutionBudget{}, ErrConflict
	}
	return budget, nil
}

func authorizedPlanMaxTokens(value sql.NullInt64) (uint64, error) {
	if !value.Valid {
		return 0, nil
	}
	if value.Int64 <= 0 || value.Int64 > int64(MaximumRequestTokens) {
		return 0, ErrConflict
	}
	return uint64(value.Int64), nil
}

func updateExecutionBudget(
	ctx context.Context,
	tx pgx.Tx,
	next postgresExecutionBudget,
	expectedRevision uint64,
) error {
	if next.validate() != nil || expectedRevision == 0 || next.Revision != expectedRevision+1 {
		return ErrInvalid
	}
	result, err := tx.Exec(ctx, `UPDATE core_cloud_worker_model_budgets
SET reserved_tokens=$2,settled_tokens=$3,revision=$4,updated_at=$5
WHERE execution_id=$1 AND revision=$6`, next.ExecutionID, int64(next.ReservedTokens),
		int64(next.SettledTokens), int64(next.Revision), next.UpdatedAt, int64(expectedRevision))
	if err != nil || result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func updateGrant(ctx context.Context, tx pgx.Tx, next Grant, expectedRevision uint64) error {
	if next.Validate() != nil || expectedRevision == 0 || next.Revision <= expectedRevision {
		return ErrInvalid
	}
	var fencedAt, terminalAt any
	if !next.FencedAt.IsZero() {
		fencedAt = next.FencedAt
	}
	if !next.TerminalAt.IsZero() {
		terminalAt = next.TerminalAt
	}
	result, err := tx.Exec(ctx, `UPDATE core_cloud_worker_model_grants
SET reserved_tokens=$2,settled_tokens=$3,state=$4,reason_code=$5,updated_at=$6,
    fenced_at=$7,terminal_at=$8,revision=$9 WHERE grant_id=$1 AND revision=$10`,
		next.GrantID, int64(next.ReservedTokens), int64(next.SettledTokens), string(next.State),
		next.ReasonCode, next.UpdatedAt, fencedAt, terminalAt, int64(next.Revision), int64(expectedRevision))
	if err != nil || result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func lockRelayAuthority(ctx context.Context, tx pgx.Tx, fence Fence) error {
	if fence.Validate() != nil {
		return ErrInvalid
	}
	var ownerID, executionState, taskStatus, executionID, taskID, sessionState string
	var accountGeneration, leaseEpoch, sessionLeaseEpoch int64
	var attempt, sessionAttempt int32
	var leaseExpiresAt sql.NullTime
	err := tx.QueryRow(ctx, `SELECT e.owner_id,e.account_generation,e.state,t.status,t.attempt,t.lease_epoch,t.lease_expires_at,
s.execution_id::text,s.task_id::text,s.task_attempt,s.lease_epoch,s.state
FROM core_cloud_worker_executions e
JOIN core_tasks t ON t.task_id=e.task_id
JOIN core_cloud_worker_sessions s ON s.session_id=$3
WHERE e.execution_id=$1 AND e.task_id=$2
FOR UPDATE OF e,t,s`, fence.ExecutionID, fence.TaskID, fence.SessionID).Scan(
		&ownerID, &accountGeneration, &executionState, &taskStatus, &attempt, &leaseEpoch,
		&leaseExpiresAt, &executionID, &taskID, &sessionAttempt, &sessionLeaseEpoch, &sessionState)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrStaleFence
	}
	if err != nil {
		return ErrConflict
	}
	if ownerID != fence.OwnerID || accountGeneration != int64(fence.AccountGeneration) ||
		executionID != fence.ExecutionID || taskID != fence.TaskID ||
		attempt != int32(fence.Attempt) || sessionAttempt != int32(fence.Attempt) ||
		leaseEpoch != int64(fence.LeaseEpoch) || sessionLeaseEpoch != int64(fence.LeaseEpoch) ||
		taskStatus != "running" || sessionState != "active" {
		return ErrStaleFence
	}
	switch executionState {
	case "awaiting_worker", "running":
		var databaseNow time.Time
		if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&databaseNow); err != nil {
			return ErrConflict
		}
		if !leaseExpiresAt.Valid || !databaseNow.Before(leaseExpiresAt.Time) {
			return ErrStaleFence
		}
		return nil
	case "succeeded", "failed", "canceled", "rejected", "expired":
		return ErrTerminal
	default:
		return ErrStaleFence
	}
}

var _ Store = (*PostgresStore)(nil)
