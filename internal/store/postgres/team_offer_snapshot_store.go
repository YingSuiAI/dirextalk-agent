package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const createTeamOfferSnapshotOperation = "team.offer_snapshot.create"

type teamOfferSnapshotReplay struct {
	SchemaVersion int                     `json:"schema_version"`
	Record        TeamOfferSnapshotRecord `json:"record"`
}

func (store *Store) CreateTeamOfferSnapshot(
	ctx context.Context,
	scope task.MutationScope,
	command CreateTeamOfferSnapshotCommand,
) (TeamOfferSnapshotRecord, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	if err := command.validate(); err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	requestDigest, err := command.digest()
	if err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	snapshotID, _ := uuid.Parse(command.Snapshot.SnapshotID())

	tx, err := store.pool.BeginTx(
		ctx,
		pgx.TxOptions{IsoLevel: pgx.ReadCommitted},
	)
	if err != nil {
		return TeamOfferSnapshotRecord{}, fmt.Errorf(
			"begin create Team Offer Snapshot: %w",
			err,
		)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, response, err := claimScopedIdempotency(
		ctx,
		tx,
		caller,
		createTeamOfferSnapshotOperation,
		command.IdempotencyKey,
		requestDigest[:],
		snapshotID,
	)
	if err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	if existing {
		record, err := decodeTeamOfferSnapshotReplay(response)
		if err != nil {
			return TeamOfferSnapshotRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return TeamOfferSnapshotRecord{}, fmt.Errorf(
				"commit Team Offer Snapshot replay: %w",
				err,
			)
		}
		return record, nil
	}
	record, err := store.createTeamOfferSnapshotTx(ctx, tx, command)
	if err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	if err := setScopedIdempotencyResponse(
		ctx,
		tx,
		caller,
		createTeamOfferSnapshotOperation,
		command.IdempotencyKey,
		teamOfferSnapshotReplay{
			SchemaVersion: teamFactSnapshotSchemaV1,
			Record:        record,
		},
	); err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return TeamOfferSnapshotRecord{}, fmt.Errorf(
			"commit create Team Offer Snapshot: %w",
			err,
		)
	}
	return record, nil
}

func (store *Store) createTeamOfferSnapshotTx(
	ctx context.Context,
	tx pgx.Tx,
	command CreateTeamOfferSnapshotCommand,
) (TeamOfferSnapshotRecord, error) {
	if err := command.validate(); err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	snapshotID, _ := uuid.Parse(command.Snapshot.SnapshotID())
	document := command.Snapshot.Document()
	documentJSON, err := json.Marshal(document)
	if err != nil {
		return TeamOfferSnapshotRecord{}, ErrTeamFactInvalid
	}
	documentCBOR, err := command.Snapshot.CanonicalCBOR()
	if err != nil {
		return TeamOfferSnapshotRecord{}, ErrTeamFactInvalid
	}
	var databaseNow time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(
		&databaseNow,
	); err != nil {
		return TeamOfferSnapshotRecord{}, fmt.Errorf(
			"read Team Offer Snapshot creation time: %w",
			err,
		)
	}
	if err := command.Snapshot.ValidateAt(databaseNow.UTC()); err != nil {
		return TeamOfferSnapshotRecord{}, ErrTeamFactInvalid
	}
	if err := verifyTeamConnectionScope(
		ctx,
		tx,
		store.instanceID,
		command.OwnerID,
		document.ProviderScope,
		document.Region,
	); err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	var alreadyExists bool
	if err := tx.QueryRow(
		ctx,
		`SELECT EXISTS (
			SELECT 1 FROM team_offer_snapshots WHERE snapshot_id=$1
		)`,
		snapshotID,
	).Scan(&alreadyExists); err != nil {
		return TeamOfferSnapshotRecord{}, fmt.Errorf(
			"check Team Offer Snapshot existence: %w",
			err,
		)
	}
	if alreadyExists {
		return TeamOfferSnapshotRecord{}, ErrTeamFactRevision
	}
	record := TeamOfferSnapshotRecord{
		OwnerID:  command.OwnerID,
		Document: document,
		Digest:   command.Snapshot.Digest(),
	}
	providerScope := document.ProviderScope
	if err := tx.QueryRow(ctx, `
		INSERT INTO team_offer_snapshots
		    (snapshot_id, agent_instance_id, owner_id, provider, connection_id,
		     connection_revision, account_id, region, snapshot_digest,
		     snapshot_json, snapshot_cbor, captured_at, valid_until)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
		RETURNING created_at`,
		snapshotID,
		store.instanceID,
		command.OwnerID,
		providerScope.Provider,
		providerScope.ConnectionID,
		int64(providerScope.ConnectionRevision),
		providerScope.AccountID,
		document.Region,
		record.Digest,
		documentJSON,
		documentCBOR,
		document.CapturedAt.UTC(),
		document.ValidUntil.UTC(),
	).Scan(&record.CreatedAt); err != nil {
		return TeamOfferSnapshotRecord{}, fmt.Errorf(
			"insert Team Offer Snapshot: %w",
			err,
		)
	}
	record.CreatedAt = record.CreatedAt.UTC()
	return record, nil
}

func (store *Store) GetTeamOfferSnapshot(
	ctx context.Context,
	ownerID,
	snapshotID string,
) (TeamOfferSnapshotRecord, error) {
	parsed, err := uuid.Parse(snapshotID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != snapshotID ||
		ownerID != strings.TrimSpace(ownerID) ||
		ownerID == "" {
		return TeamOfferSnapshotRecord{}, ErrTeamFactInvalid
	}
	record, err := readTeamOfferSnapshot(
		ctx,
		store.pool,
		store.instanceID,
		parsed,
		false,
	)
	if err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	if record.OwnerID != ownerID {
		return TeamOfferSnapshotRecord{}, ErrTeamFactScope
	}
	return record, nil
}

func (store *Store) VerifyTeamConnectionScope(
	ctx context.Context,
	ownerID string,
	scope teamplan.ProviderScope,
	region string,
) error {
	if store == nil || store.pool == nil || ctx == nil ||
		ownerID != strings.TrimSpace(ownerID) || ownerID == "" ||
		scope.Validate() != nil ||
		region != strings.TrimSpace(region) || region == "" {
		return ErrTeamFactInvalid
	}
	return verifyTeamConnectionScope(
		ctx,
		store.pool,
		store.instanceID,
		ownerID,
		scope,
		region,
	)
}

type teamOfferSnapshotQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readTeamOfferSnapshot(
	ctx context.Context,
	query teamOfferSnapshotQuerier,
	instanceID uuid.UUID,
	snapshotID uuid.UUID,
	lock bool,
) (TeamOfferSnapshotRecord, error) {
	statement := `
		SELECT agent_instance_id, owner_id, provider, connection_id,
		       connection_revision, account_id, region, snapshot_digest,
		       snapshot_json, snapshot_cbor, captured_at, valid_until, created_at
		FROM team_offer_snapshots
		WHERE snapshot_id=$1 AND agent_instance_id=$2`
	if lock {
		statement += " FOR SHARE"
	}
	var (
		agentID                     uuid.UUID
		connectionID                uuid.UUID
		provider, accountID, region string
		connectionRevision          int64
		documentJSON, documentCBOR  []byte
		capturedAt, validUntil      time.Time
		record                      TeamOfferSnapshotRecord
	)
	if err := query.QueryRow(ctx, statement, snapshotID, instanceID).Scan(
		&agentID,
		&record.OwnerID,
		&provider,
		&connectionID,
		&connectionRevision,
		&accountID,
		&region,
		&record.Digest,
		&documentJSON,
		&documentCBOR,
		&capturedAt,
		&validUntil,
		&record.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return TeamOfferSnapshotRecord{}, ErrTeamFactNotFound
		}
		return TeamOfferSnapshotRecord{}, fmt.Errorf(
			"read Team Offer Snapshot: %w",
			err,
		)
	}
	if connectionRevision <= 0 ||
		json.Unmarshal(documentJSON, &record.Document) != nil {
		return TeamOfferSnapshotRecord{}, ErrTeamFactCorrupt
	}
	snapshot, err := record.Snapshot()
	if err != nil ||
		snapshot.SnapshotID() != snapshotID.String() ||
		agentID != instanceID ||
		record.Document.ProviderScope.Provider !=
			teamplan.CloudProvider(provider) ||
		record.Document.ProviderScope.ConnectionID != connectionID.String() ||
		record.Document.ProviderScope.ConnectionRevision !=
			uint64(connectionRevision) ||
		record.Document.ProviderScope.AccountID != accountID ||
		record.Document.Region != region ||
		!record.Document.CapturedAt.Equal(capturedAt.UTC()) ||
		!record.Document.ValidUntil.Equal(validUntil.UTC()) {
		return TeamOfferSnapshotRecord{}, ErrTeamFactCorrupt
	}
	actualCBOR, err := snapshot.CanonicalCBOR()
	if err != nil || !bytes.Equal(actualCBOR, documentCBOR) {
		return TeamOfferSnapshotRecord{}, ErrTeamFactCorrupt
	}
	record.CreatedAt = record.CreatedAt.UTC()
	return record, nil
}

func decodeTeamOfferSnapshotReplay(
	encoded []byte,
) (TeamOfferSnapshotRecord, error) {
	var replay teamOfferSnapshotReplay
	if json.Unmarshal(encoded, &replay) != nil ||
		replay.SchemaVersion != teamFactSnapshotSchemaV1 {
		return TeamOfferSnapshotRecord{}, ErrTeamFactCorrupt
	}
	if _, err := replay.Record.Snapshot(); err != nil {
		return TeamOfferSnapshotRecord{}, err
	}
	replay.Record.CreatedAt = replay.Record.CreatedAt.UTC()
	return replay.Record, nil
}

func verifyTeamConnectionScope(
	ctx context.Context,
	query teamOfferSnapshotQuerier,
	instanceID uuid.UUID,
	ownerID string,
	scope teamplan.ProviderScope,
	region string,
) error {
	var (
		storedInstanceID                               uuid.UUID
		storedOwnerID, accountID, storedRegion, status string
		revision                                       int64
	)
	if err := query.QueryRow(ctx, `
		SELECT agent_instance_id, owner_id, account_id, region, status, revision
		FROM cloud_connections
		WHERE connection_id=$1
		FOR SHARE`,
		scope.ConnectionID,
	).Scan(
		&storedInstanceID,
		&storedOwnerID,
		&accountID,
		&storedRegion,
		&status,
		&revision,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTeamFactScope
		}
		return fmt.Errorf("read Team Plan Cloud Connection scope: %w", err)
	}
	if scope.Provider != teamplan.CloudProviderAWS ||
		storedInstanceID != instanceID ||
		storedOwnerID != ownerID ||
		accountID != scope.AccountID ||
		storedRegion != region ||
		status != "active" ||
		revision <= 0 ||
		uint64(revision) != scope.ConnectionRevision {
		return ErrTeamFactScope
	}
	return nil
}
