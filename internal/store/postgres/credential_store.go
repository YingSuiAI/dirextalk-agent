package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) CredentialByKeyID(ctx context.Context, keyID string) (auth.Credential, error) {
	credential, err := scanCredential(store.pool.QueryRow(ctx, `
		SELECT credential_id, key_id, client_id, scopes, secret_digest, active, expires_at, revision
		FROM service_credentials WHERE key_id=$1`, keyID))
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Credential{}, auth.ErrCredentialNotFound
	}
	return credential, err
}

func (store *Store) EnsureBootstrapCredential(ctx context.Context, bootstrap auth.BootstrapCredential) (auth.Credential, error) {
	if err := bootstrap.Validate(); err != nil {
		return auth.Credential{}, err
	}
	credentialID, err := uuid.NewV7()
	if err != nil {
		return auth.Credential{}, fmt.Errorf("generate bootstrap credential id: %w", err)
	}
	scopes := canonicalScopes(bootstrap.Scopes)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return auth.Credential{}, fmt.Errorf("begin bootstrap credential: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	result, err := tx.Exec(ctx, `
		INSERT INTO service_credentials (credential_id, key_id, client_id, scopes, secret_digest)
		VALUES ($1,$2,$3,$4,$5)
		ON CONFLICT (key_id) DO NOTHING`, credentialID, bootstrap.KeyID, bootstrap.ClientID, scopes, bootstrap.SecretDigest)
	if err != nil {
		return auth.Credential{}, fmt.Errorf("insert bootstrap credential: %w", err)
	}
	credential, err := scanCredential(tx.QueryRow(ctx, `
		SELECT credential_id, key_id, client_id, scopes, secret_digest, active, expires_at, revision
		FROM service_credentials WHERE key_id=$1 FOR UPDATE`, bootstrap.KeyID))
	if err != nil {
		return auth.Credential{}, fmt.Errorf("read bootstrap credential: %w", err)
	}
	if result.RowsAffected() == 0 && (credential.ClientID != bootstrap.ClientID || !slices.Equal(credential.Scopes, scopes) || !bytes.Equal(credential.SecretDigest, bootstrap.SecretDigest)) {
		return auth.Credential{}, errors.New("bootstrap key id is already bound to different credential material")
	}
	if !credential.Active {
		return auth.Credential{}, auth.ErrCredentialInactive
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.Credential{}, fmt.Errorf("commit bootstrap credential: %w", err)
	}
	return credential, nil
}

func (store *Store) CreateCredential(ctx context.Context, command auth.CreateCredentialCommand) (auth.CreatedCredential, error) {
	if err := command.Validate(time.Now().UTC()); err != nil {
		return auth.CreatedCredential{}, err
	}
	credentialID, _ := uuid.Parse(command.CredentialID)
	callerCredentialID, _ := uuid.Parse(command.CallerCredentialID)
	caller := idempotencyCaller{ClientID: command.CallerClientID, CredentialID: callerCredentialID}
	digest := command.Digest()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return auth.CreatedCredential{}, fmt.Errorf("begin create credential: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, responseSnapshot, err := claimScopedIdempotency(ctx, tx, caller, "credential.create", command.IdempotencyKey, digest[:], credentialID)
	if err != nil {
		return auth.CreatedCredential{}, err
	}
	if existing {
		created, err := decodeCredentialSnapshot(responseSnapshot)
		if err != nil {
			return auth.CreatedCredential{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return auth.CreatedCredential{}, fmt.Errorf("commit idempotent create credential: %w", err)
		}
		return created, nil
	}
	credential, err := scanCredential(tx.QueryRow(ctx, `
		INSERT INTO service_credentials (credential_id, key_id, client_id, scopes, secret_digest, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING credential_id, key_id, client_id, scopes, secret_digest, active, expires_at, revision`,
		credentialID, command.KeyID, command.ClientID, canonicalScopes(command.Scopes), command.SecretDigest, command.ExpiresAt,
	))
	if err != nil {
		return auth.CreatedCredential{}, fmt.Errorf("insert service credential: %w", err)
	}
	if err := appendCredentialEvent(ctx, tx, credential, "agent.credential.created", command.CallerClientID, command.CallerCredentialID); err != nil {
		return auth.CreatedCredential{}, err
	}
	created := auth.CreatedCredential{Credential: credential, Delivery: cloneEncryptedDelivery(command.Delivery)}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, "credential.create", command.IdempotencyKey, newCredentialSnapshot(created)); err != nil {
		return auth.CreatedCredential{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.CreatedCredential{}, fmt.Errorf("commit create credential: %w", err)
	}
	return created, nil
}

func (store *Store) RevokeCredential(ctx context.Context, command auth.RevokeCredentialCommand) (auth.Credential, error) {
	if err := command.Validate(); err != nil {
		return auth.Credential{}, err
	}
	credentialID, _ := uuid.Parse(command.CredentialID)
	callerCredentialID, _ := uuid.Parse(command.CallerCredentialID)
	caller := idempotencyCaller{ClientID: command.CallerClientID, CredentialID: callerCredentialID}
	digest := command.Digest()
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return auth.Credential{}, fmt.Errorf("begin revoke credential: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, responseSnapshot, err := claimScopedIdempotency(ctx, tx, caller, "credential.revoke", command.IdempotencyKey, digest[:], credentialID)
	if err != nil {
		return auth.Credential{}, err
	}
	if existing {
		created, err := decodeCredentialSnapshot(responseSnapshot)
		if err != nil {
			return auth.Credential{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return auth.Credential{}, fmt.Errorf("commit idempotent revoke credential: %w", err)
		}
		return created.Credential, nil
	}
	credential, err := credentialByID(ctx, tx, credentialID, true)
	if err != nil {
		return auth.Credential{}, err
	}
	if credential.Revision != command.ExpectedRevision {
		return auth.Credential{}, auth.ErrCredentialRevision
	}
	if !credential.Active {
		return auth.Credential{}, auth.ErrCredentialInactive
	}
	if err := tx.QueryRow(ctx, `
		UPDATE service_credentials
		SET active=false, revision=revision+1, updated_at=clock_timestamp()
		WHERE credential_id=$1
		RETURNING credential_id, key_id, client_id, scopes, secret_digest, active, expires_at, revision`, credentialID,
	).Scan(&credential.CredentialID, &credential.KeyID, &credential.ClientID, &credential.Scopes, &credential.SecretDigest, &credential.Active, &credential.ExpiresAt, &credential.Revision); err != nil {
		return auth.Credential{}, fmt.Errorf("revoke service credential: %w", err)
	}
	if err := appendCredentialEvent(ctx, tx, credential, "agent.credential.revoked", command.CallerClientID, command.CallerCredentialID); err != nil {
		return auth.Credential{}, err
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, "credential.revoke", command.IdempotencyKey, newCredentialSnapshot(auth.CreatedCredential{Credential: credential})); err != nil {
		return auth.Credential{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return auth.Credential{}, fmt.Errorf("commit revoke credential: %w", err)
	}
	return credential, nil
}

type credentialScanner interface{ Scan(...any) error }

func scanCredential(scanner credentialScanner) (auth.Credential, error) {
	var credential auth.Credential
	if err := scanner.Scan(
		&credential.CredentialID, &credential.KeyID, &credential.ClientID, &credential.Scopes,
		&credential.SecretDigest, &credential.Active, &credential.ExpiresAt, &credential.Revision,
	); err != nil {
		return auth.Credential{}, err
	}
	return credential, nil
}

func credentialByID(ctx context.Context, query rowQuerier, credentialID uuid.UUID, forUpdate bool) (auth.Credential, error) {
	statement := `SELECT credential_id, key_id, client_id, scopes, secret_digest, active, expires_at, revision
		FROM service_credentials WHERE credential_id=$1`
	if forUpdate {
		statement += " FOR UPDATE"
	}
	credential, err := scanCredential(query.QueryRow(ctx, statement, credentialID))
	if errors.Is(err, pgx.ErrNoRows) {
		return auth.Credential{}, auth.ErrCredentialNotFound
	}
	return credential, err
}

func appendCredentialEvent(ctx context.Context, tx pgx.Tx, credential auth.Credential, eventType, actorClientID, actorCredentialID string) error {
	summary, err := json.Marshal(struct {
		SchemaVersion     int      `json:"schema_version"`
		CredentialID      string   `json:"credential_id"`
		KeyID             string   `json:"key_id"`
		ClientID          string   `json:"client_id"`
		Scopes            []string `json:"scopes"`
		Active            bool     `json:"active"`
		Revision          int64    `json:"revision"`
		ActorClientID     string   `json:"actor_client_id"`
		ActorCredentialID string   `json:"actor_credential_id"`
	}{
		SchemaVersion: snapshotSchemaV1, CredentialID: credential.CredentialID, KeyID: credential.KeyID,
		ClientID: credential.ClientID, Scopes: credential.Scopes, Active: credential.Active, Revision: credential.Revision,
		ActorClientID: actorClientID, ActorCredentialID: actorCredentialID,
	})
	if err != nil {
		return fmt.Errorf("encode credential event: %w", err)
	}
	eventID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate credential event id: %w", err)
	}
	var seq int64
	if err := tx.QueryRow(ctx, `
		INSERT INTO task_events (event_id, event_type, aggregate_type, aggregate_id, revision, summary_json)
		VALUES ($1,$2,'credential',$3,$4,$5) RETURNING seq`, eventID, eventType, credential.CredentialID, credential.Revision, summary).Scan(&seq); err != nil {
		return fmt.Errorf("insert credential event: %w", err)
	}
	outboxID, err := uuid.NewV7()
	if err != nil {
		return fmt.Errorf("generate credential outbox id: %w", err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO outbox_events (outbox_id, event_seq, topic, payload_json) VALUES ($1,$2,$3,$4)`, outboxID, seq, eventType, summary); err != nil {
		return fmt.Errorf("insert credential outbox: %w", err)
	}
	return nil
}

func canonicalScopes(scopes []string) []string {
	result := append([]string(nil), scopes...)
	slices.Sort(result)
	return slices.Compact(result)
}

type credentialSnapshot struct {
	SchemaVersion int                    `json:"schema_version"`
	CredentialID  string                 `json:"credential_id"`
	KeyID         string                 `json:"key_id"`
	ClientID      string                 `json:"client_id"`
	Scopes        []string               `json:"scopes"`
	Active        bool                   `json:"active"`
	ExpiresAt     *time.Time             `json:"expires_at,omitempty"`
	Revision      int64                  `json:"revision"`
	Delivery      auth.EncryptedDelivery `json:"delivery"`
}

func newCredentialSnapshot(created auth.CreatedCredential) credentialSnapshot {
	credential := created.Credential
	return credentialSnapshot{
		SchemaVersion: snapshotSchemaV1,
		CredentialID:  credential.CredentialID, KeyID: credential.KeyID, ClientID: credential.ClientID,
		Scopes: append([]string(nil), credential.Scopes...), Active: credential.Active,
		ExpiresAt: credential.ExpiresAt, Revision: credential.Revision, Delivery: cloneEncryptedDelivery(created.Delivery),
	}
}

func decodeCredentialSnapshot(encoded []byte) (auth.CreatedCredential, error) {
	var snapshot credentialSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil {
		return auth.CreatedCredential{}, fmt.Errorf("decode idempotent credential response: %w", err)
	}
	if snapshot.SchemaVersion != snapshotSchemaV1 {
		return auth.CreatedCredential{}, errors.New("idempotent credential response has unsupported schema version")
	}
	return auth.CreatedCredential{
		Credential: auth.Credential{
			CredentialID: snapshot.CredentialID, KeyID: snapshot.KeyID, ClientID: snapshot.ClientID,
			Scopes: snapshot.Scopes, Active: snapshot.Active, ExpiresAt: snapshot.ExpiresAt, Revision: snapshot.Revision,
		},
		Delivery: cloneEncryptedDelivery(snapshot.Delivery),
	}, nil
}

func cloneEncryptedDelivery(delivery auth.EncryptedDelivery) auth.EncryptedDelivery {
	delivery.AssociatedData = append([]byte(nil), delivery.AssociatedData...)
	return delivery
}
