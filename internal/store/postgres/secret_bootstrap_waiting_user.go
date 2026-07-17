package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// CommitUploadIdempotentAndWake is the production UploadEncrypted commit path.
// It persists ciphertext, clears the one-time token, resumes only exact
// metadata-bound waiting Tasks, writes their task_events/outbox entries, and
// records the upload replay snapshot in one PostgreSQL transaction.
func (store *SecretBootstrapStore) CommitUploadIdempotentAndWake(
	ctx context.Context,
	mutation secretbootstrap.IdempotencyMutation,
	sessionID string,
	expectedRevision uint64,
	uploadTokenHash [32]byte,
	envelope secretbootstrap.EnvelopeV1,
	now time.Time,
) (secretbootstrap.Record, error) {
	if mutation.Operation != secretbootstrap.UploadOperation || mutation.Validate() != nil {
		return secretbootstrap.Record{}, secretbootstrap.ErrInvalidContext
	}
	parsedSessionID, err := uuid.Parse(sessionID)
	if err != nil || expectedRevision == 0 {
		return secretbootstrap.Record{}, secretbootstrap.ErrInvalidContext
	}
	credentialID, _ := uuid.Parse(mutation.Scope.CredentialID)
	caller := idempotencyCaller{ClientID: mutation.Scope.ClientID, CredentialID: credentialID}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return secretbootstrap.Record{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, responseSnapshot, err := claimScopedIdempotency(ctx, tx, caller, mutation.Operation, mutation.Key, mutation.RequestHash[:], parsedSessionID)
	if err != nil {
		return secretbootstrap.Record{}, err
	}
	if existing {
		var session secretbootstrap.SessionV1
		if err := json.Unmarshal(responseSnapshot, &session); err != nil {
			return secretbootstrap.Record{}, fmt.Errorf("decode idempotent secret upload response: %w", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return secretbootstrap.Record{}, err
		}
		return secretbootstrap.Record{Session: session}, nil
	}
	row := tx.QueryRow(ctx, `
		UPDATE secret_bootstrap_sessions
		SET status='uploaded', revision=revision+1, upload_token_hash=NULL,
		    idempotency_token_nonce=NULL, idempotency_token_ciphertext=NULL,
		    envelope_schema=$4, client_public_key=$5, envelope_nonce=$6, envelope_ciphertext=$7,
		    updated_at=clock_timestamp()
		WHERE session_id=$1 AND revision=$2 AND status='awaiting_upload'
		  AND expires_at>$3 AND upload_token_hash=$8
		RETURNING `+bootstrapRecordColumns, parsedSessionID, expectedRevision, now.UTC(), envelope.SchemaVersion,
		envelope.ClientPublicKey, envelope.Nonce, envelope.Ciphertext, uploadTokenHash[:])
	record, err := scanBootstrapRecord(row)
	if errors.Is(err, secretbootstrap.ErrNotFound) {
		current, readErr := readBootstrapRecord(ctx, tx, sessionID, " FOR UPDATE")
		if readErr != nil {
			return secretbootstrap.Record{}, readErr
		}
		switch {
		case current.Session.Revision != expectedRevision:
			return secretbootstrap.Record{}, secretbootstrap.ErrRevisionConflict
		case !now.UTC().Before(current.Session.ExpiresAt):
			return secretbootstrap.Record{}, secretbootstrap.ErrExpired
		default:
			return secretbootstrap.Record{}, secretbootstrap.ErrStateConflict
		}
	}
	if err != nil {
		return secretbootstrap.Record{}, err
	}
	if record.CreatorClientID != caller.ClientID {
		return secretbootstrap.Record{}, secretbootstrap.ErrCallerMismatch
	}
	if err := wakeCloudGoalSecretWaits(ctx, tx, record, caller); err != nil {
		return secretbootstrap.Record{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, mutation.Operation, mutation.Key, record.Session); err != nil {
		return secretbootstrap.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return secretbootstrap.Record{}, err
	}
	return record, nil
}
