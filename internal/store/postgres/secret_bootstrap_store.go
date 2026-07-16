package postgres

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	bootstrapKeyAADDomain   = "dirextalk.agent.secret-bootstrap/key-vault/v1"
	bootstrapTokenAADDomain = "dirextalk.agent.secret-bootstrap/idempotency-token/v1"
)

// SecretBootstrapStore persists only authenticated ciphertext and hashes. The
// mounted master key remains process-local and is never written to PostgreSQL.
type SecretBootstrapStore struct {
	pool      *pgxpool.Pool
	masterKey [32]byte
	random    io.Reader
}

var _ secretbootstrap.Store = (*SecretBootstrapStore)(nil)
var _ secretbootstrap.AtomicSessionStore = (*SecretBootstrapStore)(nil)
var _ secretbootstrap.AtomicIdempotentSessionStore = (*SecretBootstrapStore)(nil)

func NewSecretBootstrapStore(pool *pgxpool.Pool, masterKey []byte) (*SecretBootstrapStore, error) {
	if pool == nil || len(masterKey) != 32 {
		return nil, secretbootstrap.ErrInvalidContext
	}
	var key [32]byte
	copy(key[:], masterKey)
	var zero [32]byte
	if subtle.ConstantTimeCompare(key[:], zero[:]) == 1 {
		return nil, secretbootstrap.ErrInvalidContext
	}
	return &SecretBootstrapStore{pool: pool, masterKey: key, random: cryptorand.Reader}, nil
}

func (store *Store) NewSecretBootstrapStore(masterKey []byte) (*SecretBootstrapStore, error) {
	if store == nil {
		return nil, secretbootstrap.ErrInvalidContext
	}
	return NewSecretBootstrapStore(store.pool, masterKey)
}

func (store *SecretBootstrapStore) CreateWithPrivateKey(ctx context.Context, record secretbootstrap.Record, privateKey []byte) (secretbootstrap.Record, error) {
	if err := validateBootstrapCreate(record, false); err != nil || len(privateKey) != 32 {
		return secretbootstrap.Record{}, secretbootstrap.ErrInvalidContext
	}
	handle, err := uuid.NewRandom()
	if err != nil {
		return secretbootstrap.Record{}, secretbootstrap.ErrKeyUnavailable
	}
	nonce, ciphertext, err := store.sealKey(record.Session.SessionID, handle.String(), privateKey)
	if err != nil {
		return secretbootstrap.Record{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return secretbootstrap.Record{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `
		INSERT INTO secret_bootstrap_keys (key_handle, session_id, nonce, ciphertext)
		VALUES ($1,$2,$3,$4)`, handle, record.Session.SessionID, nonce, ciphertext); err != nil {
		return secretbootstrap.Record{}, mapBootstrapWriteError(err)
	}
	record.KeyHandle = handle.String()
	if err := insertBootstrapRecord(ctx, tx, record, nil, nil); err != nil {
		return secretbootstrap.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return secretbootstrap.Record{}, err
	}
	return record, nil
}

func (store *SecretBootstrapStore) CreateIdempotent(ctx context.Context, mutation secretbootstrap.IdempotencyMutation, record secretbootstrap.Record, privateKey []byte, uploadToken string) (secretbootstrap.Record, string, error) {
	if mutation.Operation != secretbootstrap.CreateOperation || mutation.Validate() != nil || validateBootstrapCreate(record, false) != nil || len(privateKey) != 32 {
		return secretbootstrap.Record{}, "", secretbootstrap.ErrInvalidContext
	}
	tokenBytes, err := base64.RawURLEncoding.DecodeString(uploadToken)
	if err != nil || len(tokenBytes) != 32 {
		secretbootstrap.Wipe(tokenBytes)
		return secretbootstrap.Record{}, "", secretbootstrap.ErrInvalidContext
	}
	secretbootstrap.Wipe(tokenBytes)
	credentialID, _ := uuid.Parse(mutation.Scope.CredentialID)
	caller := idempotencyCaller{ClientID: mutation.Scope.ClientID, CredentialID: credentialID}
	sessionID, _ := uuid.Parse(record.Session.SessionID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return secretbootstrap.Record{}, "", err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, aggregateID, _, err := claimScopedIdempotency(ctx, tx, caller, mutation.Operation, mutation.Key, mutation.RequestHash[:], sessionID)
	if err != nil {
		return secretbootstrap.Record{}, "", err
	}
	if existing {
		restored, readErr := readBootstrapRecord(ctx, tx, aggregateID.String(), " FOR UPDATE")
		if readErr != nil {
			return secretbootstrap.Record{}, "", readErr
		}
		var tokenNonce, tokenCiphertext []byte
		if err := tx.QueryRow(ctx, `SELECT idempotency_token_nonce, idempotency_token_ciphertext
			FROM secret_bootstrap_sessions WHERE session_id=$1`, aggregateID).Scan(&tokenNonce, &tokenCiphertext); err != nil {
			return secretbootstrap.Record{}, "", err
		}
		replayToken := ""
		if len(tokenNonce) > 0 || len(tokenCiphertext) > 0 {
			var openErr error
			replayToken, openErr = store.openReplayToken(restored.Session.SessionID, tokenNonce, tokenCiphertext)
			if openErr != nil {
				return secretbootstrap.Record{}, "", openErr
			}
		} else if restored.Session.Status == secretbootstrap.StatusAwaitingUpload || restored.Session.Status == secretbootstrap.StatusUploaded {
			return secretbootstrap.Record{}, "", secretbootstrap.ErrKeyUnavailable
		}
		if err := tx.Commit(ctx); err != nil {
			return secretbootstrap.Record{}, "", err
		}
		return restored, replayToken, nil
	}
	handle, err := uuid.NewRandom()
	if err != nil {
		return secretbootstrap.Record{}, "", secretbootstrap.ErrKeyUnavailable
	}
	keyNonce, keyCiphertext, err := store.sealKey(record.Session.SessionID, handle.String(), privateKey)
	if err != nil {
		return secretbootstrap.Record{}, "", err
	}
	tokenNonce, tokenCiphertext, err := store.sealReplayToken(record.Session.SessionID, uploadToken)
	if err != nil {
		return secretbootstrap.Record{}, "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO secret_bootstrap_keys (key_handle, session_id, nonce, ciphertext) VALUES ($1,$2,$3,$4)`,
		handle, sessionID, keyNonce, keyCiphertext); err != nil {
		return secretbootstrap.Record{}, "", mapBootstrapWriteError(err)
	}
	record.KeyHandle = handle.String()
	if err := insertBootstrapRecord(ctx, tx, record, tokenNonce, tokenCiphertext); err != nil {
		return secretbootstrap.Record{}, "", err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, mutation.Operation, mutation.Key, record.Session); err != nil {
		return secretbootstrap.Record{}, "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return secretbootstrap.Record{}, "", err
	}
	return record, uploadToken, nil
}

func (store *SecretBootstrapStore) Create(ctx context.Context, record secretbootstrap.Record) error {
	if err := validateBootstrapCreate(record, true); err != nil {
		return err
	}
	return insertBootstrapRecord(ctx, store.pool, record, nil, nil)
}

func insertBootstrapRecord(ctx context.Context, query interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}, record secretbootstrap.Record, replayNonce, replayCiphertext []byte) error {
	handle, err := uuid.Parse(record.KeyHandle)
	if err != nil {
		return secretbootstrap.ErrInvalidContext
	}
	_, err = query.Exec(ctx, `
		INSERT INTO secret_bootstrap_sessions
		    (session_id, agent_instance_id, creator_client_id, owner_id, purpose, target_id, server_public_key,
		     upload_token_hash, idempotency_token_nonce, idempotency_token_ciphertext,
		     key_handle, status, revision, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		record.Session.SessionID, record.Session.AgentInstanceID, record.CreatorClientID, record.Session.OwnerID,
		record.Session.Purpose, record.Session.TargetID, record.Session.ServerPublicKey,
		record.UploadTokenHash[:], replayNonce, replayCiphertext, handle, record.Session.Status, record.Session.Revision,
		record.Session.CreatedAt.UTC(), record.Session.ExpiresAt.UTC())
	if err != nil {
		return mapBootstrapWriteError(err)
	}
	return nil
}

func validateBootstrapCreate(record secretbootstrap.Record, requireHandle bool) error {
	if record.Session.SchemaVersion != secretbootstrap.SessionSchemaV1 || record.Session.Status != secretbootstrap.StatusAwaitingUpload ||
		record.Session.Revision != 1 || record.Session.SessionID == "" || record.Session.AgentInstanceID == "" ||
		secretbootstrap.ValidateClientID(record.CreatorClientID) != nil ||
		strings.TrimSpace(record.Session.OwnerID) == "" || strings.TrimSpace(record.Session.Purpose) == "" ||
		strings.TrimSpace(record.Session.TargetID) == "" || record.Session.ServerPublicKey == "" ||
		record.Session.CreatedAt.IsZero() || !record.Session.ExpiresAt.After(record.Session.CreatedAt) ||
		record.UploadTokenHash == ([32]byte{}) || record.Envelope != nil || (requireHandle && record.KeyHandle == "") {
		return secretbootstrap.ErrInvalidContext
	}
	if _, err := uuid.Parse(record.Session.SessionID); err != nil {
		return secretbootstrap.ErrInvalidContext
	}
	if _, err := uuid.Parse(record.Session.AgentInstanceID); err != nil {
		return secretbootstrap.ErrInvalidContext
	}
	return nil
}

func (store *SecretBootstrapStore) Get(ctx context.Context, sessionID string) (secretbootstrap.Record, error) {
	return readBootstrapRecord(ctx, store.pool, sessionID, "")
}

func (store *SecretBootstrapStore) CommitUpload(ctx context.Context, sessionID string, expectedRevision uint64, uploadTokenHash [32]byte, envelope secretbootstrap.EnvelopeV1, now time.Time) (secretbootstrap.Record, error) {
	row := store.pool.QueryRow(ctx, `
		UPDATE secret_bootstrap_sessions
		SET status='uploaded', revision=revision+1, upload_token_hash=NULL,
		    envelope_schema=$4, client_public_key=$5, envelope_nonce=$6, envelope_ciphertext=$7,
		    updated_at=clock_timestamp()
		WHERE session_id=$1 AND revision=$2 AND status='awaiting_upload'
		  AND expires_at>$3 AND upload_token_hash=$8
		RETURNING `+bootstrapRecordColumns, sessionID, expectedRevision, now.UTC(), envelope.SchemaVersion,
		envelope.ClientPublicKey, envelope.Nonce, envelope.Ciphertext, uploadTokenHash[:])
	record, err := scanBootstrapRecord(row)
	if errors.Is(err, secretbootstrap.ErrNotFound) {
		return secretbootstrap.Record{}, store.bootstrapConflict(ctx, sessionID, expectedRevision, now, secretbootstrap.StatusAwaitingUpload)
	}
	return record, err
}

func (store *SecretBootstrapStore) CommitUploadIdempotent(ctx context.Context, mutation secretbootstrap.IdempotencyMutation, sessionID string, expectedRevision uint64, uploadTokenHash [32]byte, envelope secretbootstrap.EnvelopeV1, now time.Time) (secretbootstrap.Record, error) {
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
	if err := setScopedIdempotencyResponse(ctx, tx, caller, mutation.Operation, mutation.Key, record.Session); err != nil {
		return secretbootstrap.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return secretbootstrap.Record{}, err
	}
	return record, nil
}

func (store *SecretBootstrapStore) ClaimConsume(ctx context.Context, sessionID string, expectedRevision uint64, now time.Time) (secretbootstrap.Record, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return secretbootstrap.Record{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	record, err := readBootstrapRecord(ctx, tx, sessionID, " FOR UPDATE")
	if err != nil {
		return secretbootstrap.Record{}, err
	}
	if record.Session.Revision != expectedRevision {
		return secretbootstrap.Record{}, secretbootstrap.ErrRevisionConflict
	}
	if record.Session.Status != secretbootstrap.StatusUploaded || record.Envelope == nil || record.KeyHandle == "" {
		return secretbootstrap.Record{}, secretbootstrap.ErrStateConflict
	}
	if !now.UTC().Before(record.Session.ExpiresAt) {
		return secretbootstrap.Record{}, secretbootstrap.ErrExpired
	}
	claimed := record
	claimed.Session.Status = secretbootstrap.StatusConsumed
	claimed.Session.Revision++
	if _, err := tx.Exec(ctx, `
		UPDATE secret_bootstrap_sessions
		SET status='consumed', revision=$2, upload_token_hash=NULL,
		    idempotency_token_nonce=NULL, idempotency_token_ciphertext=NULL,
		    envelope_schema=NULL, client_public_key=NULL, envelope_nonce=NULL, envelope_ciphertext=NULL,
		    updated_at=clock_timestamp()
		WHERE session_id=$1 AND revision=$3 AND status='uploaded'`, sessionID, claimed.Session.Revision, expectedRevision); err != nil {
		return secretbootstrap.Record{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return secretbootstrap.Record{}, err
	}
	return claimed, nil
}

func (store *SecretBootstrapStore) ExpireBefore(ctx context.Context, now time.Time) ([]secretbootstrap.Record, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	rows, err := tx.Query(ctx, `SELECT `+bootstrapRecordColumns+` FROM secret_bootstrap_sessions
		WHERE status IN ('awaiting_upload','uploaded') AND expires_at<=$1
		ORDER BY expires_at, session_id FOR UPDATE`, now.UTC())
	if err != nil {
		return nil, err
	}
	var expired []secretbootstrap.Record
	for rows.Next() {
		record, scanErr := scanBootstrapRecord(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		record.Session.Status = secretbootstrap.StatusExpired
		record.Session.Revision++
		record.Envelope = nil
		record.UploadTokenHash = [32]byte{}
		expired = append(expired, record)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, record := range expired {
		if _, err := tx.Exec(ctx, `
			UPDATE secret_bootstrap_sessions
			SET status='expired', revision=$2, upload_token_hash=NULL,
			    idempotency_token_nonce=NULL, idempotency_token_ciphertext=NULL,
			    envelope_schema=NULL, client_public_key=NULL, envelope_nonce=NULL, envelope_ciphertext=NULL,
			    updated_at=clock_timestamp()
			WHERE session_id=$1`, record.Session.SessionID, record.Session.Revision); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return expired, nil
}

func (store *SecretBootstrapStore) PendingKeyCleanup(ctx context.Context) ([]secretbootstrap.Record, error) {
	rows, err := store.pool.Query(ctx, `SELECT `+bootstrapRecordColumns+` FROM secret_bootstrap_sessions
		WHERE status IN ('consumed','expired') AND key_handle IS NOT NULL ORDER BY session_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []secretbootstrap.Record
	for rows.Next() {
		record, scanErr := scanBootstrapRecord(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	return records, rows.Err()
}

func (store *SecretBootstrapStore) ClearKeyHandle(ctx context.Context, sessionID string, revision uint64, keyHandle string) error {
	handle, err := uuid.Parse(keyHandle)
	if err != nil {
		return secretbootstrap.ErrInvalidContext
	}
	result, err := store.pool.Exec(ctx, `
		UPDATE secret_bootstrap_sessions SET key_handle=NULL, updated_at=clock_timestamp()
		WHERE session_id=$1 AND revision=$2 AND key_handle=$3 AND status IN ('consumed','expired')`, sessionID, revision, handle)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 1 {
		return nil
	}
	return store.bootstrapConflict(ctx, sessionID, revision, time.Time{}, secretbootstrap.StatusConsumed, secretbootstrap.StatusExpired)
}

const bootstrapRecordColumns = `session_id, agent_instance_id, creator_client_id, owner_id, purpose, target_id, server_public_key,
	upload_token_hash, key_handle, envelope_schema, client_public_key, envelope_nonce, envelope_ciphertext,
	status, revision, created_at, expires_at`

type rowScanner interface{ Scan(...any) error }

func readBootstrapRecord(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, sessionID, suffix string) (secretbootstrap.Record, error) {
	return scanBootstrapRecord(query.QueryRow(ctx, `SELECT `+bootstrapRecordColumns+` FROM secret_bootstrap_sessions WHERE session_id=$1`+suffix, sessionID))
}

func scanBootstrapRecord(row rowScanner) (secretbootstrap.Record, error) {
	var record secretbootstrap.Record
	var uploadHash []byte
	var keyHandle *uuid.UUID
	var schema, clientKey, nonce, ciphertext *string
	var status string
	if err := row.Scan(&record.Session.SessionID, &record.Session.AgentInstanceID, &record.CreatorClientID, &record.Session.OwnerID,
		&record.Session.Purpose, &record.Session.TargetID, &record.Session.ServerPublicKey,
		&uploadHash, &keyHandle, &schema, &clientKey, &nonce, &ciphertext,
		&status, &record.Session.Revision, &record.Session.CreatedAt, &record.Session.ExpiresAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return secretbootstrap.Record{}, secretbootstrap.ErrNotFound
		}
		return secretbootstrap.Record{}, err
	}
	record.Session.SchemaVersion = secretbootstrap.SessionSchemaV1
	record.Session.Status = secretbootstrap.Status(status)
	record.Session.CreatedAt = record.Session.CreatedAt.UTC()
	record.Session.ExpiresAt = record.Session.ExpiresAt.UTC()
	if len(uploadHash) == 32 {
		copy(record.UploadTokenHash[:], uploadHash)
	} else if len(uploadHash) != 0 {
		return secretbootstrap.Record{}, secretbootstrap.ErrInvalidContext
	}
	if keyHandle != nil {
		record.KeyHandle = keyHandle.String()
	}
	if schema != nil || clientKey != nil || nonce != nil || ciphertext != nil {
		if schema == nil || clientKey == nil || nonce == nil || ciphertext == nil {
			return secretbootstrap.Record{}, secretbootstrap.ErrInvalidContext
		}
		record.Envelope = &secretbootstrap.EnvelopeV1{
			SchemaVersion: *schema, SessionID: record.Session.SessionID,
			ClientPublicKey: *clientKey, Nonce: *nonce, Ciphertext: *ciphertext,
		}
	}
	return record, nil
}

func (store *SecretBootstrapStore) bootstrapConflict(ctx context.Context, sessionID string, expectedRevision uint64, now time.Time, allowed ...secretbootstrap.Status) error {
	record, err := store.Get(ctx, sessionID)
	if err != nil {
		return err
	}
	if record.Session.Revision != expectedRevision {
		return secretbootstrap.ErrRevisionConflict
	}
	if !now.IsZero() && !now.UTC().Before(record.Session.ExpiresAt) {
		return secretbootstrap.ErrExpired
	}
	for _, status := range allowed {
		if record.Session.Status == status {
			return secretbootstrap.ErrStateConflict
		}
	}
	return secretbootstrap.ErrStateConflict
}

func mapBootstrapWriteError(err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return secretbootstrap.ErrAlreadyExists
	}
	return err
}

func (store *SecretBootstrapStore) Put(ctx context.Context, sessionID string, privateKey []byte) (string, error) {
	if _, err := uuid.Parse(sessionID); err != nil || len(privateKey) != 32 {
		return "", secretbootstrap.ErrInvalidContext
	}
	handle, err := uuid.NewRandom()
	if err != nil {
		return "", secretbootstrap.ErrKeyUnavailable
	}
	nonce, ciphertext, err := store.sealKey(sessionID, handle.String(), privateKey)
	if err != nil {
		return "", err
	}
	if _, err := store.pool.Exec(ctx, `INSERT INTO secret_bootstrap_keys (key_handle, session_id, nonce, ciphertext) VALUES ($1,$2,$3,$4)`,
		handle, sessionID, nonce, ciphertext); err != nil {
		return "", mapBootstrapWriteError(err)
	}
	return handle.String(), nil
}

type bootstrapKeyStoreAdapter struct{ store *SecretBootstrapStore }

func (store *SecretBootstrapStore) KeyStore() secretbootstrap.KeyStore {
	return bootstrapKeyStoreAdapter{store: store}
}

func (adapter bootstrapKeyStoreAdapter) Put(ctx context.Context, sessionID string, privateKey []byte) (string, error) {
	return adapter.store.Put(ctx, sessionID, privateKey)
}
func (adapter bootstrapKeyStoreAdapter) Get(ctx context.Context, handle string) ([]byte, error) {
	return adapter.store.readKey(ctx, adapter.store.pool, handle, false)
}
func (adapter bootstrapKeyStoreAdapter) Take(ctx context.Context, handle string) ([]byte, error) {
	return adapter.store.takeKey(ctx, handle)
}
func (adapter bootstrapKeyStoreAdapter) Delete(ctx context.Context, handle string) error {
	parsed, err := uuid.Parse(handle)
	if err != nil {
		return secretbootstrap.ErrInvalidContext
	}
	_, err = adapter.store.pool.Exec(ctx, `DELETE FROM secret_bootstrap_keys WHERE key_handle=$1`, parsed)
	return err
}

func (store *SecretBootstrapStore) readKey(ctx context.Context, query interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, handle string, forUpdate bool) ([]byte, error) {
	parsed, err := uuid.Parse(handle)
	if err != nil {
		return nil, secretbootstrap.ErrInvalidContext
	}
	suffix := ""
	if forUpdate {
		suffix = " FOR UPDATE"
	}
	var sessionID string
	var nonce, ciphertext []byte
	if err := query.QueryRow(ctx, `SELECT session_id, nonce, ciphertext FROM secret_bootstrap_keys WHERE key_handle=$1`+suffix, parsed).Scan(&sessionID, &nonce, &ciphertext); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, secretbootstrap.ErrKeyUnavailable
		}
		return nil, err
	}
	return store.openKey(sessionID, handle, nonce, ciphertext)
}

func (store *SecretBootstrapStore) takeKey(ctx context.Context, handle string) ([]byte, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	plaintext, err := store.readKey(ctx, tx, handle, true)
	if err != nil {
		return nil, err
	}
	parsed, _ := uuid.Parse(handle)
	if _, err := tx.Exec(ctx, `DELETE FROM secret_bootstrap_keys WHERE key_handle=$1`, parsed); err != nil {
		secretbootstrap.Wipe(plaintext)
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		secretbootstrap.Wipe(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func (store *SecretBootstrapStore) sealKey(sessionID, handle string, plaintext []byte) ([]byte, []byte, error) {
	gcm, err := store.gcm()
	if err != nil {
		return nil, nil, secretbootstrap.ErrKeyUnavailable
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(store.random, nonce); err != nil {
		return nil, nil, secretbootstrap.ErrKeyUnavailable
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, bootstrapKeyAAD(sessionID, handle))
	return nonce, ciphertext, nil
}

func (store *SecretBootstrapStore) openKey(sessionID, handle string, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := store.gcm()
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, secretbootstrap.ErrKeyUnavailable
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, bootstrapKeyAAD(sessionID, handle))
	if err != nil || len(plaintext) != 32 {
		secretbootstrap.Wipe(plaintext)
		return nil, secretbootstrap.ErrKeyUnavailable
	}
	return plaintext, nil
}

func (store *SecretBootstrapStore) sealReplayToken(sessionID, token string) ([]byte, []byte, error) {
	gcm, err := store.gcm()
	if err != nil {
		return nil, nil, secretbootstrap.ErrKeyUnavailable
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(store.random, nonce); err != nil {
		return nil, nil, secretbootstrap.ErrKeyUnavailable
	}
	plaintext := []byte(token)
	defer secretbootstrap.Wipe(plaintext)
	if len(plaintext) != 43 {
		return nil, nil, secretbootstrap.ErrInvalidContext
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, bootstrapTokenAAD(sessionID)), nil
}

func (store *SecretBootstrapStore) openReplayToken(sessionID string, nonce, ciphertext []byte) (string, error) {
	gcm, err := store.gcm()
	if err != nil || len(nonce) != gcm.NonceSize() {
		return "", secretbootstrap.ErrKeyUnavailable
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, bootstrapTokenAAD(sessionID))
	if err != nil || len(plaintext) != 43 {
		secretbootstrap.Wipe(plaintext)
		return "", secretbootstrap.ErrKeyUnavailable
	}
	defer secretbootstrap.Wipe(plaintext)
	token := string(plaintext)
	decoded, decodeErr := base64.RawURLEncoding.DecodeString(token)
	secretbootstrap.Wipe(decoded)
	if decodeErr != nil || len(decoded) != 32 {
		return "", secretbootstrap.ErrKeyUnavailable
	}
	return token, nil
}

func (store *SecretBootstrapStore) gcm() (cipher.AEAD, error) {
	block, err := aes.NewCipher(store.masterKey[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func bootstrapKeyAAD(sessionID, handle string) []byte {
	return []byte(fmt.Sprintf("%s\x00%s\x00%s", bootstrapKeyAADDomain, sessionID, handle))
}

func bootstrapTokenAAD(sessionID string) []byte {
	return []byte(fmt.Sprintf("%s\x00%s", bootstrapTokenAADDomain, sessionID))
}
