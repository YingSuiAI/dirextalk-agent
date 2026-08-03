package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/YingSuiAI/dirextalk-agent/internal/idempotency"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const prepareTeamPlanOperationDomain = "team.plan.prepare"

type teamPlanPreparationReplay struct {
	SchemaVersion int                     `json:"schema_version"`
	Offer         TeamOfferSnapshotRecord `json:"offer"`
	Plan          TeamPlanRecord          `json:"plan"`
}

func (store *Store) FindPreparedTeamPlan(
	ctx context.Context,
	scope task.MutationScope,
	command FindPreparedTeamPlanCommand,
) (PreparedTeamPlanRecord, bool, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return PreparedTeamPlanRecord{}, false, err
	}
	if err := command.validate(); err != nil {
		return PreparedTeamPlanRecord{}, false, err
	}
	requestDigest, err := command.Intent.digest()
	if err != nil {
		return PreparedTeamPlanRecord{}, false, err
	}
	var storedDigest, response []byte
	operation := store.prepareTeamPlanOperation()
	if err := store.pool.QueryRow(ctx, `
		SELECT request_hash, response_json
		FROM idempotency_records
		WHERE operation=$1
		  AND caller_client_id=$2
		  AND caller_credential_id=$3
		  AND idempotency_key=$4`,
		operation,
		caller.ClientID,
		caller.CredentialID,
		command.IdempotencyKey,
	).Scan(&storedDigest, &response); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PreparedTeamPlanRecord{}, false, nil
		}
		return PreparedTeamPlanRecord{}, false, fmt.Errorf(
			"find prepared Team Plan: %w",
			err,
		)
	}
	if !bytes.Equal(storedDigest, requestDigest[:]) {
		return PreparedTeamPlanRecord{}, false, idempotency.ErrConflict
	}
	if len(response) == 0 {
		return PreparedTeamPlanRecord{}, false, ErrTeamFactCorrupt
	}
	replay, err := decodeTeamPlanPreparationReplay(response)
	if err != nil {
		return PreparedTeamPlanRecord{}, false, err
	}
	record, err := store.readPreparedTeamPlan(
		ctx,
		store.pool,
		command.Intent,
		replay,
	)
	if err != nil {
		return PreparedTeamPlanRecord{}, false, err
	}
	record.Replayed = true
	return record, true, nil
}

func (store *Store) PrepareTeamPlan(
	ctx context.Context,
	scope task.MutationScope,
	command PrepareTeamPlanCommand,
) (PreparedTeamPlanRecord, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return PreparedTeamPlanRecord{}, err
	}
	if err := command.validate(); err != nil {
		return PreparedTeamPlanRecord{}, err
	}
	requestDigest, err := command.Intent.digest()
	if err != nil {
		return PreparedTeamPlanRecord{}, err
	}
	planID, _ := uuid.Parse(command.Intent.PlanID)
	versionID := teamPlanVersionID(planID, command.Intent.Revision)
	operation := store.prepareTeamPlanOperation()
	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return PreparedTeamPlanRecord{}, fmt.Errorf(
			"begin prepare Team Plan: %w",
			err,
		)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	existing, _, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		operation,
		command.IdempotencyKey,
		requestDigest[:],
		versionID,
	)
	if err != nil {
		return PreparedTeamPlanRecord{}, err
	}
	if existing {
		replay, err := decodeTeamPlanPreparationReplay(response)
		if err != nil {
			return PreparedTeamPlanRecord{}, err
		}
		record, err := store.readPreparedTeamPlan(
			ctx,
			tx,
			command.Intent,
			replay,
		)
		if err != nil {
			return PreparedTeamPlanRecord{}, err
		}
		if record.Plan.Status == TeamPlanReadyForConfirmation {
			boundTask, err := lockTeamPlanTaskForPreparation(
				ctx,
				tx,
				record.Plan.TaskID,
				record.Plan.Plan,
			)
			if err != nil {
				return PreparedTeamPlanRecord{}, err
			}
			if err := transitionTeamPlanTaskAwaitingApproval(
				ctx,
				tx,
				caller,
				boundTask,
				false,
			); err != nil {
				return PreparedTeamPlanRecord{}, err
			}
		}
		record.Replayed = true
		if err := tx.Commit(ctx); err != nil {
			return PreparedTeamPlanRecord{}, fmt.Errorf(
				"commit prepared Team Plan replay: %w",
				err,
			)
		}
		return record, nil
	}

	offerRecord, err := store.createTeamOfferSnapshotTx(
		ctx,
		tx,
		CreateTeamOfferSnapshotCommand{
			IdempotencyKey: command.IdempotencyKey,
			OwnerID:        command.Intent.OwnerID,
			Snapshot:       command.Snapshot,
		},
	)
	if err != nil {
		return PreparedTeamPlanRecord{}, err
	}
	planRecord, err := store.createTeamPlanTx(
		ctx,
		tx,
		caller,
		CreateTeamPlanCommand{
			IdempotencyKey:           command.IdempotencyKey,
			TaskID:                   command.Intent.TaskID,
			ExpectedPreviousRevision: command.Intent.ExpectedPreviousRevision,
			Plan:                     command.Plan,
		},
	)
	if err != nil {
		return PreparedTeamPlanRecord{}, err
	}
	replay := teamPlanPreparationReplay{
		SchemaVersion: teamFactSnapshotSchemaV1,
		Offer:         offerRecord,
		Plan:          planRecord,
	}
	if err := setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		operation,
		command.IdempotencyKey,
		replay,
	); err != nil {
		return PreparedTeamPlanRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return PreparedTeamPlanRecord{}, fmt.Errorf(
			"commit prepare Team Plan: %w",
			err,
		)
	}
	return PreparedTeamPlanRecord{
		Offer: offerRecord,
		Plan:  planRecord,
	}, nil
}

func (store *Store) prepareTeamPlanOperation() string {
	return prepareTeamPlanOperationDomain + ":" + store.instanceID.String()
}

func decodeTeamPlanPreparationReplay(
	encoded []byte,
) (teamPlanPreparationReplay, error) {
	var replay teamPlanPreparationReplay
	if json.Unmarshal(encoded, &replay) != nil ||
		replay.SchemaVersion != teamFactSnapshotSchemaV1 {
		return teamPlanPreparationReplay{}, ErrTeamFactCorrupt
	}
	if _, err := replay.Offer.Snapshot(); err != nil {
		return teamPlanPreparationReplay{}, err
	}
	planDigest, err := replay.Plan.Plan.Digest()
	if err != nil ||
		planDigest != replay.Plan.PlanDigest ||
		!validTeamPlanStatus(replay.Plan.Status) ||
		replay.Plan.RecordRevision == 0 {
		return teamPlanPreparationReplay{}, ErrTeamFactCorrupt
	}
	return replay, nil
}

func (store *Store) readPreparedTeamPlan(
	ctx context.Context,
	query teamOfferSnapshotQuerier,
	intent TeamPlanPreparationIntent,
	replay teamPlanPreparationReplay,
) (PreparedTeamPlanRecord, error) {
	snapshotID, err := uuid.Parse(replay.Offer.Document.SnapshotID)
	if err != nil || snapshotID == uuid.Nil {
		return PreparedTeamPlanRecord{}, ErrTeamFactCorrupt
	}
	planID, err := uuid.Parse(replay.Plan.Plan.PlanID)
	if err != nil || planID == uuid.Nil {
		return PreparedTeamPlanRecord{}, ErrTeamFactCorrupt
	}
	offer, err := readTeamOfferSnapshot(
		ctx,
		query,
		store.instanceID,
		snapshotID,
		false,
	)
	if err != nil {
		return PreparedTeamPlanRecord{}, err
	}
	plan, err := readTeamPlan(
		ctx,
		query,
		store.instanceID,
		planID,
		replay.Plan.Plan.Revision,
		false,
	)
	if err != nil {
		return PreparedTeamPlanRecord{}, err
	}
	replayPlanDigest, err := replay.Plan.Plan.Digest()
	if err != nil ||
		offer.OwnerID != replay.Offer.OwnerID ||
		offer.Digest != replay.Offer.Digest ||
		offer.Document.SnapshotID != replay.Offer.Document.SnapshotID ||
		!offer.CreatedAt.Equal(replay.Offer.CreatedAt) ||
		plan.TaskID != replay.Plan.TaskID ||
		plan.PlanDigest != replay.Plan.PlanDigest ||
		plan.PlanDigest != replayPlanDigest ||
		!plan.CreatedAt.Equal(replay.Plan.CreatedAt) ||
		plan.Plan.OwnerID != intent.OwnerID ||
		plan.TaskID != intent.TaskID ||
		plan.Plan.PlanID != intent.PlanID ||
		plan.Plan.Revision != intent.Revision ||
		plan.Plan.GoalDigest != intent.GoalDigest ||
		plan.Plan.TaskInput != intent.TaskInput ||
		plan.Plan.PricingSnapshotID != offer.Document.SnapshotID ||
		plan.Plan.PricingSnapshotDigest != offer.Digest ||
		plan.Plan.ProposalConfidence != intent.Proposal.Confidence ||
		plan.Plan.ProposalRationale != intent.Proposal.Rationale ||
		plan.Plan.WorkerCount != uint32(len(intent.Proposal.Roles)) {
		return PreparedTeamPlanRecord{}, ErrTeamFactCorrupt
	}
	return PreparedTeamPlanRecord{Offer: offer, Plan: plan}, nil
}
