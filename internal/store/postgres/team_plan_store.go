package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	createTeamPlanOperation = "team.plan.create"
	expireTeamPlanOperation = "team.plan.expire"
)

type teamPlanReplay struct {
	SchemaVersion int            `json:"schema_version"`
	Record        TeamPlanRecord `json:"record"`
}

func (store *Store) CreateTeamPlan(
	ctx context.Context,
	scope task.MutationScope,
	command CreateTeamPlanCommand,
) (TeamPlanRecord, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if err := command.validate(); err != nil {
		return TeamPlanRecord{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return TeamPlanRecord{}, err
	}
	planID, _ := uuid.Parse(command.Plan.PlanID)
	versionID := teamPlanVersionID(planID, command.Plan.Revision)

	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return TeamPlanRecord{}, fmt.Errorf("begin create Team Plan: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		createTeamPlanOperation,
		command.IdempotencyKey,
		requestDigest[:],
		versionID,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if existing {
		record, err := decodeTeamPlanReplay(response)
		if err != nil {
			return TeamPlanRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return TeamPlanRecord{}, fmt.Errorf(
				"commit Team Plan replay: %w",
				err,
			)
		}
		return record, nil
	}
	record, err := store.createTeamPlanTx(ctx, tx, caller, command)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if err := setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		createTeamPlanOperation,
		command.IdempotencyKey,
		teamPlanReplay{
			SchemaVersion: teamFactSnapshotSchemaV1,
			Record:        record,
		},
	); err != nil {
		return TeamPlanRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TeamPlanRecord{}, fmt.Errorf("commit create Team Plan: %w", err)
	}
	return record, nil
}

func (store *Store) createTeamPlanTx(
	ctx context.Context,
	tx pgx.Tx,
	caller idempotencyCaller,
	command CreateTeamPlanCommand,
) (TeamPlanRecord, error) {
	if err := command.validate(); err != nil {
		return TeamPlanRecord{}, err
	}
	planID, _ := uuid.Parse(command.Plan.PlanID)
	snapshotID, _ := uuid.Parse(command.Plan.PricingSnapshotID)
	planDigest, err := command.Plan.Digest()
	if err != nil {
		return TeamPlanRecord{}, ErrTeamFactInvalid
	}
	planCBOR, err := command.Plan.CanonicalCBOR()
	if err != nil {
		return TeamPlanRecord{}, ErrTeamFactInvalid
	}
	planJSON, err := json.Marshal(command.Plan)
	if err != nil {
		return TeamPlanRecord{}, ErrTeamFactInvalid
	}
	if _, err := tx.Exec(
		ctx,
		`SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`,
		"team-plan:"+planID.String(),
	); err != nil {
		return TeamPlanRecord{}, fmt.Errorf("lock Team Plan aggregate: %w", err)
	}

	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(
		&databaseNow,
	); err != nil {
		return TeamPlanRecord{}, fmt.Errorf(
			"read Team Plan creation time: %w",
			err,
		)
	}
	databaseNow = databaseNow.UTC()
	snapshotRecord, err := readTeamOfferSnapshot(
		ctx,
		tx,
		store.instanceID,
		snapshotID,
		true,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	snapshot, err := snapshotRecord.Snapshot()
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if snapshotRecord.OwnerID != command.Plan.OwnerID {
		return TeamPlanRecord{}, ErrTeamFactScope
	}
	if err := snapshot.VerifyPlanPricing(command.Plan, databaseNow); err != nil {
		return TeamPlanRecord{}, err
	}
	if err := verifyTeamConnectionScope(
		ctx,
		tx,
		store.instanceID,
		command.Plan.OwnerID,
		command.Plan.ProviderScope,
		command.Plan.Region,
	); err != nil {
		return TeamPlanRecord{}, err
	}
	if command.TaskID != "" {
		if err := verifyTeamPlanTaskBinding(
			ctx,
			tx,
			command.TaskID,
			command.Plan,
		); err != nil {
			return TeamPlanRecord{}, err
		}
	}

	var maximumRevision int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(max(plan_revision), 0)
		FROM team_plans
		WHERE plan_id=$1`,
		planID,
	).Scan(&maximumRevision); err != nil {
		return TeamPlanRecord{}, fmt.Errorf(
			"read Team Plan aggregate revision: %w",
			err,
		)
	}
	if command.Plan.Revision == 1 {
		if maximumRevision != 0 {
			return TeamPlanRecord{}, ErrTeamFactRevision
		}
	} else {
		if maximumRevision != int64(command.ExpectedPreviousRevision) {
			return TeamPlanRecord{}, ErrTeamFactRevision
		}
		previous, err := readTeamPlan(
			ctx,
			tx,
			store.instanceID,
			planID,
			command.ExpectedPreviousRevision,
			true,
		)
		if err != nil {
			return TeamPlanRecord{}, err
		}
		if previous.Plan.OwnerID != command.Plan.OwnerID ||
			previous.TaskID != command.TaskID {
			return TeamPlanRecord{}, ErrTeamFactRevision
		}
		switch previous.Status {
		case TeamPlanReadyForConfirmation:
			if previous.RecordRevision >= uint64(math.MaxInt64) {
				return TeamPlanRecord{}, ErrTeamFactRevision
			}
			previous.Status = TeamPlanSuperseded
			previous.RecordRevision++
			if err := tx.QueryRow(ctx, `
				UPDATE team_plans
				SET status='superseded',
				    record_revision=record_revision+1,
				    updated_at=GREATEST(updated_at, clock_timestamp())
				WHERE plan_id=$1
				  AND plan_revision=$2
				  AND record_revision=$3
				  AND status='ready_for_confirmation'
				RETURNING updated_at`,
				planID,
				int64(command.ExpectedPreviousRevision),
				int64(previous.RecordRevision-1),
			).Scan(&previous.UpdatedAt); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return TeamPlanRecord{}, ErrTeamFactRevision
				}
				return TeamPlanRecord{}, fmt.Errorf(
					"supersede previous Team Plan revision: %w",
					err,
				)
			}
			previous.UpdatedAt = previous.UpdatedAt.UTC()
			if err := appendTeamPlanEvent(
				ctx,
				tx,
				caller,
				previous,
			); err != nil {
				return TeamPlanRecord{}, err
			}
		case TeamPlanExpired:
			// An expired signed revision remains immutable and inactive.
		default:
			return TeamPlanRecord{}, ErrTeamFactRevision
		}
	}

	record := TeamPlanRecord{
		TaskID:         command.TaskID,
		Plan:           command.Plan,
		PlanDigest:     planDigest,
		Status:         TeamPlanReadyForConfirmation,
		RecordRevision: 1,
	}
	providerScope := command.Plan.ProviderScope
	if err := tx.QueryRow(ctx, `
		INSERT INTO team_plans
		    (plan_id, plan_revision, agent_instance_id, owner_id, task_id,
		     provider, connection_id, connection_revision, account_id, region,
		     catalog_revision, policy_revision, goal_digest,
		     snapshot_id, snapshot_digest,
		     plan_digest, plan_json, plan_cbor, status, record_revision,
		     quoted_at, valid_until)
		VALUES (
		    $1,$2,$3,$4,NULLIF($5::text,'')::uuid,
		    $6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,
		    'ready_for_confirmation',1,$19,$20
		)
		RETURNING created_at, updated_at`,
		planID,
		int64(command.Plan.Revision),
		store.instanceID,
		command.Plan.OwnerID,
		command.TaskID,
		providerScope.Provider,
		providerScope.ConnectionID,
		int64(providerScope.ConnectionRevision),
		providerScope.AccountID,
		command.Plan.Region,
		command.Plan.CatalogRevision,
		command.Plan.PolicyRevision,
		command.Plan.GoalDigest,
		snapshotID,
		command.Plan.PricingSnapshotDigest,
		planDigest,
		planJSON,
		planCBOR,
		command.Plan.QuotedAt.UTC(),
		command.Plan.ValidUntil.UTC(),
	).Scan(&record.CreatedAt, &record.UpdatedAt); err != nil {
		return TeamPlanRecord{}, fmt.Errorf("insert Team Plan: %w", err)
	}
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	if err := appendTeamPlanEvent(ctx, tx, caller, record); err != nil {
		return TeamPlanRecord{}, err
	}
	return record, nil
}

func (store *Store) ExpireTeamPlan(
	ctx context.Context,
	scope task.MutationScope,
	command ExpireTeamPlanCommand,
) (TeamPlanRecord, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if err := command.validate(); err != nil {
		return TeamPlanRecord{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return TeamPlanRecord{}, err
	}
	planID, _ := uuid.Parse(command.PlanID)
	versionID := teamPlanVersionID(planID, command.PlanRevision)
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return TeamPlanRecord{}, fmt.Errorf("begin expire Team Plan: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		expireTeamPlanOperation,
		command.IdempotencyKey,
		requestDigest[:],
		versionID,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if existing {
		record, err := decodeTeamPlanReplay(response)
		if err != nil {
			return TeamPlanRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return TeamPlanRecord{}, fmt.Errorf(
				"commit Team Plan expiry replay: %w",
				err,
			)
		}
		return record, nil
	}
	record, err := readTeamPlan(
		ctx,
		tx,
		store.instanceID,
		planID,
		command.PlanRevision,
		true,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if record.Plan.OwnerID != command.OwnerID {
		return TeamPlanRecord{}, ErrTeamFactScope
	}
	if record.RecordRevision != command.ExpectedRecordRevision ||
		record.Status != TeamPlanReadyForConfirmation {
		return TeamPlanRecord{}, ErrTeamFactRevision
	}
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(
		&databaseNow,
	); err != nil {
		return TeamPlanRecord{}, fmt.Errorf("read Team Plan expiry time: %w", err)
	}
	if databaseNow.UTC().Before(record.Plan.ValidUntil) {
		return TeamPlanRecord{}, ErrTeamFactInvalid
	}
	if record.RecordRevision >= uint64(math.MaxInt64) {
		return TeamPlanRecord{}, ErrTeamFactRevision
	}
	previousRecordRevision := record.RecordRevision
	record.RecordRevision++
	record.Status = TeamPlanExpired
	if err := tx.QueryRow(ctx, `
		UPDATE team_plans
		SET status='expired',
		    record_revision=record_revision+1,
		    updated_at=GREATEST(updated_at, clock_timestamp())
		WHERE plan_id=$1
		  AND plan_revision=$2
		  AND record_revision=$3
		  AND status='ready_for_confirmation'
		  AND valid_until<=clock_timestamp()
		RETURNING updated_at`,
		planID,
		int64(command.PlanRevision),
		int64(previousRecordRevision),
	).Scan(&record.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TeamPlanRecord{}, ErrTeamFactRevision
		}
		return TeamPlanRecord{}, fmt.Errorf("expire Team Plan: %w", err)
	}
	record.UpdatedAt = record.UpdatedAt.UTC()
	if err := appendTeamPlanEvent(ctx, tx, caller, record); err != nil {
		return TeamPlanRecord{}, err
	}
	if err := setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		expireTeamPlanOperation,
		command.IdempotencyKey,
		teamPlanReplay{
			SchemaVersion: teamFactSnapshotSchemaV1,
			Record:        record,
		},
	); err != nil {
		return TeamPlanRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TeamPlanRecord{}, fmt.Errorf("commit expire Team Plan: %w", err)
	}
	return record, nil
}

func (store *Store) GetTeamPlan(
	ctx context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (TeamPlanRecord, error) {
	parsed, err := uuid.Parse(planID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != planID ||
		ownerID != strings.TrimSpace(ownerID) ||
		ownerID == "" ||
		planRevision == 0 ||
		planRevision > uint64(math.MaxInt64) {
		return TeamPlanRecord{}, ErrTeamFactInvalid
	}
	record, err := readTeamPlan(
		ctx,
		store.pool,
		store.instanceID,
		parsed,
		planRevision,
		false,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	if record.Plan.OwnerID != ownerID {
		return TeamPlanRecord{}, ErrTeamFactScope
	}
	snapshotID, _ := uuid.Parse(record.Plan.PricingSnapshotID)
	snapshotRecord, err := readTeamOfferSnapshot(
		ctx,
		store.pool,
		store.instanceID,
		snapshotID,
		false,
	)
	if err != nil {
		return TeamPlanRecord{}, err
	}
	snapshot, err := snapshotRecord.Snapshot()
	if err != nil ||
		snapshotRecord.OwnerID != ownerID ||
		snapshot.VerifyPlanPricing(record.Plan, record.Plan.QuotedAt) != nil {
		return TeamPlanRecord{}, ErrTeamFactCorrupt
	}
	return record, nil
}

type teamPlanQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readTeamPlan(
	ctx context.Context,
	query teamPlanQuerier,
	instanceID uuid.UUID,
	planID uuid.UUID,
	planRevision uint64,
	lock bool,
) (TeamPlanRecord, error) {
	statement := `
		SELECT agent_instance_id, owner_id, COALESCE(task_id::text,''),
		       provider, connection_id, connection_revision, account_id, region,
		       catalog_revision, policy_revision, goal_digest,
		       snapshot_id, snapshot_digest,
		       plan_digest, plan_json, plan_cbor, status, record_revision,
		       quoted_at, valid_until, created_at, updated_at
		FROM team_plans
		WHERE plan_id=$1
		  AND plan_revision=$2
		  AND agent_instance_id=$3`
	if lock {
		statement += " FOR UPDATE"
	}
	var (
		agentID, connectionID, snapshotID    uuid.UUID
		ownerID, provider, accountID, region string
		catalogRevision, policyRevision      string
		goalDigest, snapshotDigest           string
		status                               string
		connectionRevision, recordRevision   int64
		planJSON, planCBOR                   []byte
		record                               TeamPlanRecord
	)
	quotedAt := new(time.Time)
	validUntil := new(time.Time)
	if err := query.QueryRow(
		ctx,
		statement,
		planID,
		int64(planRevision),
		instanceID,
	).Scan(
		&agentID,
		&ownerID,
		&record.TaskID,
		&provider,
		&connectionID,
		&connectionRevision,
		&accountID,
		&region,
		&catalogRevision,
		&policyRevision,
		&goalDigest,
		&snapshotID,
		&snapshotDigest,
		&record.PlanDigest,
		&planJSON,
		&planCBOR,
		&status,
		&recordRevision,
		quotedAt,
		validUntil,
		&record.CreatedAt,
		&record.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TeamPlanRecord{}, ErrTeamFactNotFound
		}
		return TeamPlanRecord{}, fmt.Errorf("read Team Plan: %w", err)
	}
	if connectionRevision <= 0 ||
		recordRevision <= 0 ||
		json.Unmarshal(planJSON, &record.Plan) != nil {
		return TeamPlanRecord{}, ErrTeamFactCorrupt
	}
	record.Status = TeamPlanStatus(status)
	record.RecordRevision = uint64(recordRevision)
	record.CreatedAt = record.CreatedAt.UTC()
	record.UpdatedAt = record.UpdatedAt.UTC()
	if err := record.Plan.Validate(); err != nil ||
		!validTeamPlanStatus(record.Status) ||
		agentID != instanceID ||
		record.Plan.PlanID != planID.String() ||
		record.Plan.Revision != planRevision ||
		record.Plan.OwnerID != ownerID ||
		record.Plan.ProviderScope.Provider != teamplan.CloudProvider(provider) ||
		record.Plan.ProviderScope.ConnectionID != connectionID.String() ||
		record.Plan.ProviderScope.ConnectionRevision !=
			uint64(connectionRevision) ||
		record.Plan.ProviderScope.AccountID != accountID ||
		record.Plan.Region != region ||
		record.Plan.CatalogRevision != catalogRevision ||
		record.Plan.PolicyRevision != policyRevision ||
		record.Plan.GoalDigest != goalDigest ||
		record.Plan.PricingSnapshotID != snapshotID.String() ||
		record.Plan.PricingSnapshotDigest != snapshotDigest ||
		!record.Plan.QuotedAt.Equal(quotedAt.UTC()) ||
		!record.Plan.ValidUntil.Equal(validUntil.UTC()) {
		return TeamPlanRecord{}, ErrTeamFactCorrupt
	}
	actualDigest, err := record.Plan.Digest()
	if err != nil || actualDigest != record.PlanDigest {
		return TeamPlanRecord{}, ErrTeamFactCorrupt
	}
	actualCBOR, err := record.Plan.CanonicalCBOR()
	if err != nil || !bytes.Equal(actualCBOR, planCBOR) {
		return TeamPlanRecord{}, ErrTeamFactCorrupt
	}
	return record, nil
}

func decodeTeamPlanReplay(encoded []byte) (TeamPlanRecord, error) {
	var replay teamPlanReplay
	if json.Unmarshal(encoded, &replay) != nil ||
		replay.SchemaVersion != teamFactSnapshotSchemaV1 ||
		replay.Record.RecordRevision == 0 ||
		!validTeamPlanStatus(replay.Record.Status) {
		return TeamPlanRecord{}, ErrTeamFactCorrupt
	}
	digest, err := replay.Record.Plan.Digest()
	if err != nil || digest != replay.Record.PlanDigest {
		return TeamPlanRecord{}, ErrTeamFactCorrupt
	}
	replay.Record.CreatedAt = replay.Record.CreatedAt.UTC()
	replay.Record.UpdatedAt = replay.Record.UpdatedAt.UTC()
	return replay.Record, nil
}

func verifyTeamPlanTaskBinding(
	ctx context.Context,
	query teamPlanQuerier,
	taskID string,
	plan teamplan.Plan,
) error {
	var ownerID, goal string
	if err := query.QueryRow(ctx, `
		SELECT owner_id, goal
		FROM tasks
		WHERE task_id=$1
		FOR SHARE`,
		taskID,
	).Scan(&ownerID, &goal); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTeamFactScope
		}
		return fmt.Errorf("read Team Plan Task binding: %w", err)
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(goal)))
	if ownerID != plan.OwnerID ||
		"sha256:"+hex.EncodeToString(digest[:]) != plan.GoalDigest {
		return ErrTeamFactScope
	}
	return nil
}

func appendTeamPlanEvent(
	ctx context.Context,
	tx pgx.Tx,
	caller idempotencyCaller,
	record TeamPlanRecord,
) error {
	planID, err := uuid.Parse(record.Plan.PlanID)
	if err != nil {
		return ErrTeamFactInvalid
	}
	summary := struct {
		SchemaVersion       int             `json:"schema_version"`
		PlanID              string          `json:"plan_id"`
		PlanRevision        uint64          `json:"plan_revision"`
		OwnerID             string          `json:"owner_id"`
		TaskID              string          `json:"task_id,omitempty"`
		Status              TeamPlanStatus  `json:"status"`
		RecordRevision      uint64          `json:"record_revision"`
		PlanDigest          string          `json:"plan_digest"`
		PricingSnapshotID   string          `json:"pricing_snapshot_id"`
		WorkerCount         uint32          `json:"worker_count"`
		MaxConcurrent       uint32          `json:"max_concurrent_workers"`
		Currency            string          `json:"currency"`
		ExpectedCostMicros  uint64          `json:"expected_cost_micros"`
		HardBudgetMicros    uint64          `json:"hard_budget_micros"`
		ExpectedWallSeconds uint64          `json:"expected_wall_seconds"`
		ValidUntil          time.Time       `json:"valid_until"`
		Actor               cloudEventActor `json:"actor"`
	}{
		SchemaVersion:       teamFactSnapshotSchemaV1,
		PlanID:              record.Plan.PlanID,
		PlanRevision:        record.Plan.Revision,
		OwnerID:             record.Plan.OwnerID,
		TaskID:              record.TaskID,
		Status:              record.Status,
		RecordRevision:      record.RecordRevision,
		PlanDigest:          record.PlanDigest,
		PricingSnapshotID:   record.Plan.PricingSnapshotID,
		WorkerCount:         record.Plan.WorkerCount,
		MaxConcurrent:       record.Plan.MaxConcurrentWorkers,
		Currency:            record.Plan.Cost.Currency,
		ExpectedCostMicros:  record.Plan.Cost.ExpectedMicros,
		HardBudgetMicros:    record.Plan.Cost.HardBudgetMicros,
		ExpectedWallSeconds: uint64(record.Plan.Schedule.ExpectedWallTime / time.Second),
		ValidUntil:          record.Plan.ValidUntil.UTC(),
		Actor:               newCloudEventActor(caller),
	}
	return appendCloudFactEvent(
		ctx,
		tx,
		teamPlanVersionID(planID, record.Plan.Revision),
		"team_plan_version",
		"team.plan.changed",
		record.RecordRevision,
		summary,
	)
}

func teamPlanVersionID(planID uuid.UUID, revision uint64) uuid.UUID {
	return uuid.NewSHA1(
		planID,
		[]byte(fmt.Sprintf("team-plan-version:%d", revision)),
	)
}
