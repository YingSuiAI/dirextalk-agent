package coreexecutionv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PostgresStore persists only Agent-owned execution tables.  It intentionally
// does not reuse Message Server storage or its migration names.
type PostgresStore struct {
	pool *pgxpool.Pool
	key  *secretbox.Keyring
}

func NewPostgresStore(pool *pgxpool.Pool, keys ...*secretbox.Keyring) (*PostgresStore, error) {
	if pool == nil {
		return nil, ErrInvalid
	}
	if len(keys) > 1 {
		return nil, ErrInvalid
	}
	var key *secretbox.Keyring
	if len(keys) == 1 {
		key = keys[0]
	}
	return &PostgresStore{pool: pool, key: key}, nil
}

func nullableBytes(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}

func (s *PostgresStore) Read(ctx context.Context, scope coretask.OwnerScope, kind, id string, revision uint64) (Record, error) {
	var record Record
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT owner_id,account_generation,resource_type,resource_id::text,revision,status,digest,payload_json,created_at,updated_at,COALESCE(last_replay_action,''),COALESCE(last_idempotency_key::text,''),last_request_digest FROM core_execution_v2_records WHERE owner_id=$1 AND account_generation=$2 AND resource_type=$3 AND resource_id=$4 AND ($5=0 OR revision=$5)`, scope.OwnerID, scope.AccountGeneration, kind, id, revision).Scan(&record.OwnerID, &record.AccountGeneration, &record.Kind, &record.ID, &record.Revision, &record.Status, &record.Digest, &raw, &record.CreatedAt, &record.UpdatedAt, &record.MutationAction, &record.MutationKey, &record.MutationDigest)
	if errors.Is(err, pgx.ErrNoRows) && revision > 0 {
		err = s.pool.QueryRow(ctx, `SELECT owner_id,account_generation,resource_type,resource_id::text,revision,status,digest,payload_json,created_at,created_at FROM core_execution_v2_revisions WHERE owner_id=$1 AND account_generation=$2 AND resource_type=$3 AND resource_id=$4 AND revision=$5`, scope.OwnerID, scope.AccountGeneration, kind, id, revision).Scan(&record.OwnerID, &record.AccountGeneration, &record.Kind, &record.ID, &record.Revision, &record.Status, &record.Digest, &raw, &record.CreatedAt, &record.UpdatedAt)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, err
	}
	if err := json.Unmarshal(raw, &record.Payload); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *PostgresStore) List(ctx context.Context, scope coretask.OwnerScope, kind string, filter map[string]string, token string, limit int) ([]Record, string, error) {
	args := []any{scope.OwnerID, scope.AccountGeneration, kind}
	where := `owner_id=$1 AND account_generation=$2 AND resource_type=$3`
	index := 4
	for _, key := range []string{"project_id", "deployment_id", "status"} {
		if value := strings.TrimSpace(filter[key]); value != "" {
			where += fmt.Sprintf(" AND payload_json->>'%s'=$%d", key, index)
			args = append(args, value)
			index++
		}
	}
	if states := strings.TrimSpace(filter["state"]); states != "" {
		values := strings.Split(states, ",")
		placeholders := make([]string, 0, len(values))
		for _, value := range values {
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			placeholders = append(placeholders, fmt.Sprintf("$%d", index))
			args = append(args, value)
			index++
		}
		if len(placeholders) > 0 {
			where += fmt.Sprintf(" AND status IN (%s)", strings.Join(placeholders, ","))
		}
	}
	if token != "" {
		where += fmt.Sprintf(" AND resource_id::text>$%d", index)
		args = append(args, token)
		index++
	}
	args = append(args, limit)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT owner_id,account_generation,resource_type,resource_id::text,revision,status,digest,payload_json,created_at,updated_at,COALESCE(last_replay_action,''),COALESCE(last_idempotency_key::text,''),last_request_digest FROM core_execution_v2_records WHERE %s ORDER BY resource_id LIMIT $%d`, where, index), args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]Record, 0)
	for rows.Next() {
		var record Record
		var raw []byte
		if err := rows.Scan(&record.OwnerID, &record.AccountGeneration, &record.Kind, &record.ID, &record.Revision, &record.Status, &record.Digest, &raw, &record.CreatedAt, &record.UpdatedAt, &record.MutationAction, &record.MutationKey, &record.MutationDigest); err != nil {
			return nil, "", err
		}
		if err := json.Unmarshal(raw, &record.Payload); err != nil {
			return nil, "", err
		}
		items = append(items, record)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) == limit {
		next = items[len(items)-1].ID
	}
	return items, next, nil
}

func (s *PostgresStore) Create(ctx context.Context, record Record) (Record, error) {
	raw, err := json.Marshal(record.Payload)
	if err != nil {
		return Record{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_records(owner_id,account_generation,resource_type,resource_id,revision,status,digest,payload_json,created_at,updated_at,last_replay_action,last_idempotency_key,last_request_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NULLIF($11,''),NULLIF($12,'')::uuid,$13)`, record.OwnerID, record.AccountGeneration, record.Kind, record.ID, record.Revision, record.Status, record.Digest, raw, record.CreatedAt, record.UpdatedAt, record.MutationAction, record.MutationKey, nullableBytes(record.MutationDigest))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return Record{}, ErrConflict
		}
		return Record{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_revisions(owner_id,account_generation,resource_type,resource_id,revision,status,digest,payload_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, record.OwnerID, record.AccountGeneration, record.Kind, record.ID, record.Revision, record.Status, record.Digest, raw, record.CreatedAt); err != nil {
		return Record{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *PostgresStore) Update(ctx context.Context, record Record, expected uint64) (Record, error) {
	raw, err := json.Marshal(record.Payload)
	if err != nil {
		return Record{}, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Record{}, err
	}
	defer tx.Rollback(ctx)
	result, err := tx.Exec(ctx, `UPDATE core_execution_v2_records SET revision=revision+1,status=$1,digest=$2,payload_json=$3,updated_at=$4,last_replay_action=NULLIF($5,''),last_idempotency_key=NULLIF($6,'')::uuid,last_request_digest=$7 WHERE owner_id=$8 AND account_generation=$9 AND resource_type=$10 AND resource_id=$11 AND revision=$12`, record.Status, record.Digest, raw, record.UpdatedAt, record.MutationAction, record.MutationKey, nullableBytes(record.MutationDigest), record.OwnerID, record.AccountGeneration, record.Kind, record.ID, expected)
	if err != nil {
		return Record{}, err
	}
	if result.RowsAffected() != 1 {
		return Record{}, ErrConflict
	}
	record.Revision = expected + 1
	if _, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_revisions(owner_id,account_generation,resource_type,resource_id,revision,status,digest,payload_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, record.OwnerID, record.AccountGeneration, record.Kind, record.ID, record.Revision, record.Status, record.Digest, raw, record.UpdatedAt); err != nil {
		return Record{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *PostgresStore) BeginReplay(ctx context.Context, scope coretask.OwnerScope, action, id string, digest []byte, now time.Time, lease time.Duration) (ReplayClaim, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ReplayClaim{}, err
	}
	defer tx.Rollback(ctx)
	token := uuid.NewString()
	result, err := tx.Exec(ctx, `INSERT INTO core_execution_v2_replays(owner_id,account_generation,action,idempotency_key,request_digest,response_json,provider_response_json,state,claim_token,lease_expires_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,NULL,NULL,'running',$6,$7,$8,$8) ON CONFLICT(owner_id,account_generation,action,idempotency_key) DO NOTHING`, scope.OwnerID, scope.AccountGeneration, action, id, digest, token, now.Add(lease), now)
	if err != nil {
		return ReplayClaim{}, err
	}
	if result.RowsAffected() == 1 {
		if err := tx.Commit(ctx); err != nil {
			return ReplayClaim{}, err
		}
		return ReplayClaim{Token: token}, nil
	}
	var storedDigest, response, providerResponse []byte
	var state, storedToken string
	var leaseExpiresAt *time.Time
	err = tx.QueryRow(ctx, `SELECT request_digest,response_json,provider_response_json,state,COALESCE(claim_token::text,''),lease_expires_at FROM core_execution_v2_replays WHERE owner_id=$1 AND account_generation=$2 AND action=$3 AND idempotency_key=$4 FOR UPDATE`, scope.OwnerID, scope.AccountGeneration, action, id).Scan(&storedDigest, &response, &providerResponse, &state, &storedToken, &leaseExpiresAt)
	if err != nil {
		return ReplayClaim{}, err
	}
	if !equalBytes(storedDigest, digest) {
		return ReplayClaim{}, ErrConflict
	}
	if state == "completed" {
		if err := tx.Commit(ctx); err != nil {
			return ReplayClaim{}, err
		}
		return ReplayClaim{Response: append([]byte(nil), response...), Completed: true}, nil
	}
	if state != "running" && state != "dispatched" || leaseExpiresAt == nil {
		return ReplayClaim{}, ErrConflict
	}
	if now.Before(*leaseExpiresAt) {
		return ReplayClaim{}, ErrReplayInProgress
	}
	if state == "dispatched" && len(providerResponse) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return ReplayClaim{}, err
		}
		return ReplayClaim{Dispatched: true}, nil
	}
	result, err = tx.Exec(ctx, `UPDATE core_execution_v2_replays SET claim_token=$1,lease_expires_at=$2,updated_at=$3 WHERE owner_id=$4 AND account_generation=$5 AND action=$6 AND idempotency_key=$7 AND state=$8 AND claim_token=$9`, token, now.Add(lease), now, scope.OwnerID, scope.AccountGeneration, action, id, state, storedToken)
	if err != nil {
		return ReplayClaim{}, err
	}
	if result.RowsAffected() != 1 {
		return ReplayClaim{}, ErrReplayInProgress
	}
	if err := tx.Commit(ctx); err != nil {
		return ReplayClaim{}, err
	}
	return ReplayClaim{Token: token, Dispatched: state == "dispatched", ProviderResponse: append([]byte(nil), providerResponse...)}, nil
}

func (s *PostgresStore) MarkReplayDispatched(ctx context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, updatedAt time.Time) error {
	result, err := s.pool.Exec(ctx, `UPDATE core_execution_v2_replays SET state='dispatched',updated_at=$1 WHERE owner_id=$2 AND account_generation=$3 AND action=$4 AND idempotency_key=$5 AND request_digest=$6 AND state='running' AND claim_token=$7`, updatedAt, scope.OwnerID, scope.AccountGeneration, action, id, digest, token)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (s *PostgresStore) StoreReplayProviderResponse(ctx context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, response []byte, updatedAt time.Time) error {
	result, err := s.pool.Exec(ctx, `UPDATE core_execution_v2_replays SET provider_response_json=$1,updated_at=$2 WHERE owner_id=$3 AND account_generation=$4 AND action=$5 AND idempotency_key=$6 AND request_digest=$7 AND state='dispatched' AND claim_token=$8`, response, updatedAt, scope.OwnerID, scope.AccountGeneration, action, id, digest, token)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (s *PostgresStore) CompleteReplay(ctx context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string, response []byte, completedAt time.Time) error {
	result, err := s.pool.Exec(ctx, `UPDATE core_execution_v2_replays SET response_json=$1,state='completed',claim_token=NULL,lease_expires_at=NULL,updated_at=$2 WHERE owner_id=$3 AND account_generation=$4 AND action=$5 AND idempotency_key=$6 AND request_digest=$7 AND state IN ('running','dispatched') AND claim_token=$8`, response, completedAt, scope.OwnerID, scope.AccountGeneration, action, id, digest, token)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (s *PostgresStore) AbortReplay(ctx context.Context, scope coretask.OwnerScope, action, id string, digest []byte, token string) error {
	result, err := s.pool.Exec(ctx, `DELETE FROM core_execution_v2_replays WHERE owner_id=$1 AND account_generation=$2 AND action=$3 AND idempotency_key=$4 AND request_digest=$5 AND state='running' AND claim_token=$6`, scope.OwnerID, scope.AccountGeneration, action, id, digest, token)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrConflict
	}
	return nil
}

func (s *PostgresStore) AppendEvent(ctx context.Context, event Event) (Event, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Event{}, err
	}
	defer tx.Rollback(ctx)
	// Event sequence numbers are scoped to one owner/resource. Serialize only
	// that narrow key so concurrent providers cannot both observe the same MAX.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, executionEventLockKey(event)); err != nil {
		return Event{}, err
	}
	var sequence uint64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_execution_v2_events WHERE owner_id=$1 AND account_generation=$2 AND resource_type=$3 AND resource_id=$4`, event.OwnerID, event.AccountGeneration, event.Kind, event.ResourceID).Scan(&sequence); err != nil {
		return Event{}, err
	}
	event.Sequence = sequence
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	raw, err := json.Marshal(event.Payload)
	if err != nil {
		return Event{}, err
	}
	result, err := tx.Exec(ctx, `INSERT INTO core_execution_v2_events(owner_id,account_generation,resource_type,resource_id,sequence,event_id,event_type,payload_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(owner_id,account_generation,event_id) DO NOTHING`, event.OwnerID, event.AccountGeneration, event.Kind, event.ResourceID, event.Sequence, event.EventID, event.Type, raw, event.CreatedAt)
	if err != nil {
		return Event{}, err
	}
	if result.RowsAffected() == 0 {
		var existing Event
		var existingRaw []byte
		if err = tx.QueryRow(ctx, `SELECT owner_id,account_generation,resource_type,resource_id::text,sequence,event_id::text,event_type,payload_json,created_at FROM core_execution_v2_events WHERE owner_id=$1 AND account_generation=$2 AND event_id=$3`, event.OwnerID, event.AccountGeneration, event.EventID).Scan(&existing.OwnerID, &existing.AccountGeneration, &existing.Kind, &existing.ResourceID, &existing.Sequence, &existing.EventID, &existing.Type, &existingRaw, &existing.CreatedAt); err != nil {
			return Event{}, err
		}
		if err = json.Unmarshal(existingRaw, &existing.Payload); err != nil {
			return Event{}, err
		}
		if existing.Kind != event.Kind || existing.ResourceID != event.ResourceID || existing.Type != event.Type || digestPayload(existing.Payload) != digestPayload(event.Payload) {
			return Event{}, ErrConflict
		}
		if err = tx.Commit(ctx); err != nil {
			return Event{}, err
		}
		return existing, nil
	}
	if err = tx.Commit(ctx); err != nil {
		return Event{}, err
	}
	return event, nil
}

func executionEventLockKey(event Event) string {
	raw, _ := json.Marshal([]any{event.OwnerID, event.AccountGeneration, event.Kind, event.ResourceID})
	digest := sha256.Sum256(raw)
	return "core_execution_v2_event:" + hex.EncodeToString(digest[:])
}

func (s *PostgresStore) Events(ctx context.Context, scope coretask.OwnerScope, kind, id string, after uint64, limit int) ([]Event, uint64, error) {
	rows, err := s.pool.Query(ctx, `SELECT owner_id,account_generation,resource_type,resource_id::text,sequence,event_id::text,event_type,payload_json,created_at FROM core_execution_v2_events WHERE owner_id=$1 AND account_generation=$2 AND resource_type=$3 AND resource_id=$4 AND sequence>$5 ORDER BY sequence LIMIT $6`, scope.OwnerID, scope.AccountGeneration, kind, id, after, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]Event, 0)
	for rows.Next() {
		var event Event
		var raw []byte
		if err := rows.Scan(&event.OwnerID, &event.AccountGeneration, &event.Kind, &event.ResourceID, &event.Sequence, &event.EventID, &event.Type, &raw, &event.CreatedAt); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal(raw, &event.Payload); err != nil {
			return nil, 0, err
		}
		items = append(items, event)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	var latest uint64
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0) FROM core_execution_v2_events WHERE owner_id=$1 AND account_generation=$2 AND resource_type=$3 AND resource_id=$4`, scope.OwnerID, scope.AccountGeneration, kind, id).Scan(&latest); err != nil {
		return nil, 0, err
	}
	return items, latest, nil
}

func (s *PostgresStore) SaveSecret(ctx context.Context, secret Secret) (Secret, error) {
	if s.key == nil || s.key.Version() < secretbox.KeyVersionMin {
		return Secret{}, ErrSecretNotFound
	}
	aad, err := executionSecretAAD(secret.OwnerID, secret.AccountGeneration, secret.Ref, secret.Revision, executionSecretAADScoped)
	if err != nil {
		return Secret{}, ErrInvalid
	}
	envelope, err := s.key.Seal([]byte(secret.Value), aad)
	if err != nil {
		return Secret{}, err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO core_execution_v2_secrets(owner_id,account_generation,secret_ref,revision,provider,purpose,aad_version,secret_key_version,secret_value_nonce,secret_value_ciphertext,binding_digest,status,created_at,updated_at,last_replay_action,last_idempotency_key,last_request_digest) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,NULLIF($15,''),NULLIF($16,'')::uuid,$17)`, secret.OwnerID, secret.AccountGeneration, secret.Ref, secret.Revision, secret.Provider, secret.Purpose, executionSecretAADScoped, envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext, secret.BindingDigest, secret.Status, secret.CreatedAt, secret.UpdatedAt, secret.MutationAction, secret.MutationKey, nullableBytes(secret.MutationDigest))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return Secret{}, ErrConflict
		}
		return Secret{}, err
	}
	return secret, nil
}
func (s *PostgresStore) ReadSecret(ctx context.Context, scope coretask.OwnerScope, ref string, revision uint64) (Secret, error) {
	var secret Secret
	var aadVersion uint16
	var version uint32
	var nonce, ciphertext []byte
	err := s.pool.QueryRow(ctx, `SELECT owner_id,account_generation,secret_ref::text,revision,provider,purpose,aad_version,secret_key_version,secret_value_nonce,secret_value_ciphertext,binding_digest,status,created_at,updated_at,COALESCE(last_replay_action,''),COALESCE(last_idempotency_key::text,''),last_request_digest FROM core_execution_v2_secrets WHERE owner_id=$1 AND account_generation=$2 AND secret_ref=$3 AND ($4=0 OR revision=$4)`, scope.OwnerID, scope.AccountGeneration, ref, revision).Scan(&secret.OwnerID, &secret.AccountGeneration, &secret.Ref, &secret.Revision, &secret.Provider, &secret.Purpose, &aadVersion, &version, &nonce, &ciphertext, &secret.BindingDigest, &secret.Status, &secret.CreatedAt, &secret.UpdatedAt, &secret.MutationAction, &secret.MutationKey, &secret.MutationDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return Secret{}, ErrSecretNotFound
	}
	if err != nil {
		return secret, err
	}
	key := s.key
	if key == nil {
		return Secret{}, ErrSecretNotFound
	}
	aad, aadErr := executionSecretAAD(secret.OwnerID, secret.AccountGeneration, ref, secret.Revision, aadVersion)
	if aadErr != nil {
		return Secret{}, ErrInvalid
	}
	plaintext, openErr := key.Open(secretbox.Envelope{KeyVersion: version, Nonce: nonce, Ciphertext: ciphertext}, aad)
	if openErr != nil {
		return Secret{}, ErrSecretNotFound
	}
	secret.Value = string(plaintext)
	for i := range plaintext {
		plaintext[i] = 0
	}
	return secret, nil
}
func (s *PostgresStore) ListSecrets(ctx context.Context, scope coretask.OwnerScope, token string, limit int) ([]Secret, string, error) {
	rows, err := s.pool.Query(ctx, `SELECT owner_id,account_generation,secret_ref::text,revision,provider,purpose,aad_version,secret_key_version,secret_value_nonce,secret_value_ciphertext,binding_digest,status,created_at,updated_at,COALESCE(last_replay_action,''),COALESCE(last_idempotency_key::text,''),last_request_digest FROM core_execution_v2_secrets WHERE owner_id=$1 AND account_generation=$2 AND ($3='' OR secret_ref::text>$3) ORDER BY secret_ref LIMIT $4`, scope.OwnerID, scope.AccountGeneration, token, limit)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]Secret, 0)
	for rows.Next() {
		var secret Secret
		var aadVersion uint16
		var version uint32
		var nonce, ciphertext []byte
		if err := rows.Scan(&secret.OwnerID, &secret.AccountGeneration, &secret.Ref, &secret.Revision, &secret.Provider, &secret.Purpose, &aadVersion, &version, &nonce, &ciphertext, &secret.BindingDigest, &secret.Status, &secret.CreatedAt, &secret.UpdatedAt, &secret.MutationAction, &secret.MutationKey, &secret.MutationDigest); err != nil {
			return nil, "", err
		}
		if s.key == nil {
			return nil, "", ErrSecretNotFound
		}
		aad, err := executionSecretAAD(secret.OwnerID, secret.AccountGeneration, secret.Ref, secret.Revision, aadVersion)
		if err != nil {
			return nil, "", ErrInvalid
		}
		plaintext, err := s.key.Open(secretbox.Envelope{KeyVersion: version, Nonce: nonce, Ciphertext: ciphertext}, aad)
		if err != nil {
			return nil, "", ErrSecretNotFound
		}
		secret.Value = string(plaintext)
		for i := range plaintext {
			plaintext[i] = 0
		}
		items = append(items, secret)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(items) == limit {
		next = items[len(items)-1].Ref
	}
	return items, next, nil
}
func (s *PostgresStore) RevokeSecret(ctx context.Context, secret Secret, expected uint64) (Secret, error) {
	if s.key == nil || s.key.Version() < secretbox.KeyVersionMin {
		return Secret{}, ErrSecretNotFound
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Secret{}, err
	}
	defer tx.Rollback(ctx)
	var version uint32
	var aadVersion uint16
	var nonce, ciphertext []byte
	if err := tx.QueryRow(ctx, `SELECT aad_version,secret_key_version,secret_value_nonce,secret_value_ciphertext FROM core_execution_v2_secrets WHERE owner_id=$1 AND account_generation=$2 AND secret_ref=$3 AND revision=$4 FOR UPDATE`, secret.OwnerID, secret.AccountGeneration, secret.Ref, expected).Scan(&aadVersion, &version, &nonce, &ciphertext); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Secret{}, ErrConflict
		}
		return Secret{}, err
	}
	aad, err := executionSecretAAD(secret.OwnerID, secret.AccountGeneration, secret.Ref, expected, aadVersion)
	if err != nil {
		return Secret{}, ErrInvalid
	}
	plaintext, err := s.key.Open(secretbox.Envelope{KeyVersion: version, Nonce: nonce, Ciphertext: ciphertext}, aad)
	if err != nil {
		return Secret{}, ErrSecretNotFound
	}
	newRevision := expected + 1
	newAAD, err := executionSecretAAD(secret.OwnerID, secret.AccountGeneration, secret.Ref, newRevision, executionSecretAADScoped)
	if err != nil {
		for i := range plaintext {
			plaintext[i] = 0
		}
		return Secret{}, ErrInvalid
	}
	envelope, err := s.key.Seal(plaintext, newAAD)
	for i := range plaintext {
		plaintext[i] = 0
	}
	if err != nil {
		return Secret{}, err
	}
	result, err := tx.Exec(ctx, `UPDATE core_execution_v2_secrets SET revision=$1,status=$2,aad_version=$3,secret_key_version=$4,secret_value_nonce=$5,secret_value_ciphertext=$6,updated_at=$7,last_replay_action=NULLIF($8,''),last_idempotency_key=NULLIF($9,'')::uuid,last_request_digest=$10 WHERE owner_id=$11 AND account_generation=$12 AND secret_ref=$13 AND revision=$14`, newRevision, secret.Status, executionSecretAADScoped, envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext, secret.UpdatedAt, secret.MutationAction, secret.MutationKey, nullableBytes(secret.MutationDigest), secret.OwnerID, secret.AccountGeneration, secret.Ref, expected)
	if err != nil {
		return Secret{}, err
	}
	if result.RowsAffected() != 1 {
		return Secret{}, ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return Secret{}, err
	}
	secret.Revision = newRevision
	return secret, nil
}

const (
	executionSecretAADLegacy uint16 = 1
	executionSecretAADScoped uint16 = 2
)

func executionSecretAAD(owner string, generation int64, ref string, revision uint64, aadVersion uint16) ([]byte, error) {
	var subject string
	switch aadVersion {
	case executionSecretAADLegacy:
		subject = owner + "/" + ref
	case executionSecretAADScoped:
		subject = fmt.Sprintf("%s/%d/%s", owner, generation, ref)
	default:
		return nil, ErrInvalid
	}
	return secretbox.BindAAD("core_execution_v2_secrets", subject, int64(revision), "secret_value")
}
