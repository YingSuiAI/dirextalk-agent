package coreexecutionv2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
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

func (s *PostgresStore) Read(ctx context.Context, owner, kind, id string, revision uint64) (Record, error) {
	var record Record
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT owner_id,resource_type,resource_id::text,revision,status,digest,payload_json,created_at,updated_at FROM core_execution_v2_records WHERE owner_id=$1 AND resource_type=$2 AND resource_id=$3 AND ($4=0 OR revision=$4)`, owner, kind, id, revision).Scan(&record.OwnerID, &record.Kind, &record.ID, &record.Revision, &record.Status, &record.Digest, &raw, &record.CreatedAt, &record.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) && revision > 0 {
		err = s.pool.QueryRow(ctx, `SELECT owner_id,resource_type,resource_id::text,revision,status,digest,payload_json,created_at,created_at FROM core_execution_v2_revisions WHERE owner_id=$1 AND resource_type=$2 AND resource_id=$3 AND revision=$4`, owner, kind, id, revision).Scan(&record.OwnerID, &record.Kind, &record.ID, &record.Revision, &record.Status, &record.Digest, &raw, &record.CreatedAt, &record.UpdatedAt)
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

func (s *PostgresStore) List(ctx context.Context, owner, kind string, filter map[string]string, token string, limit int) ([]Record, string, error) {
	args := []any{owner, kind}
	where := `owner_id=$1 AND resource_type=$2`
	index := 3
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
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`SELECT owner_id,resource_type,resource_id::text,revision,status,digest,payload_json,created_at,updated_at FROM core_execution_v2_records WHERE %s ORDER BY resource_id LIMIT $%d`, where, index))
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]Record, 0)
	for rows.Next() {
		var record Record
		var raw []byte
		if err := rows.Scan(&record.OwnerID, &record.Kind, &record.ID, &record.Revision, &record.Status, &record.Digest, &raw, &record.CreatedAt, &record.UpdatedAt); err != nil {
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
	_, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_records(owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, record.OwnerID, record.Kind, record.ID, record.Revision, record.Status, record.Digest, raw, record.CreatedAt, record.UpdatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return Record{}, ErrConflict
		}
		return Record{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_revisions(owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, record.OwnerID, record.Kind, record.ID, record.Revision, record.Status, record.Digest, raw, record.CreatedAt); err != nil {
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
	result, err := tx.Exec(ctx, `UPDATE core_execution_v2_records SET revision=revision+1,status=$1,digest=$2,payload_json=$3,updated_at=$4 WHERE owner_id=$5 AND resource_type=$6 AND resource_id=$7 AND revision=$8`, record.Status, record.Digest, raw, record.UpdatedAt, record.OwnerID, record.Kind, record.ID, expected)
	if err != nil {
		return Record{}, err
	}
	if result.RowsAffected() != 1 {
		return Record{}, ErrConflict
	}
	record.Revision = expected + 1
	if _, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_revisions(owner_id,resource_type,resource_id,revision,status,digest,payload_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, record.OwnerID, record.Kind, record.ID, record.Revision, record.Status, record.Digest, raw, record.UpdatedAt); err != nil {
		return Record{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Record{}, err
	}
	return record, nil
}

func (s *PostgresStore) Replay(ctx context.Context, owner, action, id string) (Replay, bool, error) {
	var replay Replay
	err := s.pool.QueryRow(ctx, `SELECT request_digest,response_json FROM core_execution_v2_replays WHERE owner_id=$1 AND action=$2 AND idempotency_key=$3`, owner, action, id).Scan(&replay.Digest, &replay.Response)
	if errors.Is(err, pgx.ErrNoRows) {
		return Replay{}, false, nil
	}
	if err != nil {
		return Replay{}, false, err
	}
	return replay, true, nil
}
func (s *PostgresStore) SaveReplay(ctx context.Context, owner, action, id string, digest, response []byte) error {
	result, err := s.pool.Exec(ctx, `INSERT INTO core_execution_v2_replays(owner_id,action,idempotency_key,request_digest,response_json,created_at) VALUES($1,$2,$3,$4,$5,clock_timestamp()) ON CONFLICT(owner_id,action,idempotency_key) DO UPDATE SET request_digest=EXCLUDED.request_digest WHERE core_execution_v2_replays.request_digest=EXCLUDED.request_digest`, owner, action, id, digest, response)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
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
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, event.OwnerID+"\x00"+event.Kind+"\x00"+event.ResourceID); err != nil {
		return Event{}, err
	}
	var sequence uint64
	if err = tx.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0)+1 FROM core_execution_v2_events WHERE owner_id=$1 AND resource_type=$2 AND resource_id=$3`, event.OwnerID, event.Kind, event.ResourceID).Scan(&sequence); err != nil {
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
	_, err = tx.Exec(ctx, `INSERT INTO core_execution_v2_events(owner_id,resource_type,resource_id,sequence,event_id,event_type,payload_json,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, event.OwnerID, event.Kind, event.ResourceID, event.Sequence, event.EventID, event.Type, raw, event.CreatedAt)
	if err != nil {
		return Event{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return Event{}, err
	}
	return event, nil
}
func (s *PostgresStore) Events(ctx context.Context, owner, kind, id string, after uint64, limit int) ([]Event, uint64, error) {
	rows, err := s.pool.Query(ctx, `SELECT owner_id,resource_type,resource_id::text,sequence,event_id::text,event_type,payload_json,created_at FROM core_execution_v2_events WHERE owner_id=$1 AND resource_type=$2 AND resource_id=$3 AND sequence>$4 ORDER BY sequence LIMIT $5`, owner, kind, id, after, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	items := make([]Event, 0)
	for rows.Next() {
		var event Event
		var raw []byte
		if err := rows.Scan(&event.OwnerID, &event.Kind, &event.ResourceID, &event.Sequence, &event.EventID, &event.Type, &raw, &event.CreatedAt); err != nil {
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
	if err := s.pool.QueryRow(ctx, `SELECT COALESCE(MAX(sequence),0) FROM core_execution_v2_events WHERE owner_id=$1 AND resource_type=$2 AND resource_id=$3`, owner, kind, id).Scan(&latest); err != nil {
		return nil, 0, err
	}
	return items, latest, nil
}

func (s *PostgresStore) SaveSecret(ctx context.Context, secret Secret) (Secret, error) {
	if s.key == nil || s.key.Version() < secretbox.KeyVersionMin {
		return Secret{}, ErrSecretNotFound
	}
	aad, err := secretbox.BindAAD("core_execution_v2_secrets", secret.OwnerID+"/"+secret.Ref, int64(secret.Revision), "secret_value")
	if err != nil {
		return Secret{}, ErrInvalid
	}
	envelope, err := s.key.Seal([]byte(secret.Value), aad)
	if err != nil {
		return Secret{}, err
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO core_execution_v2_secrets(owner_id,secret_ref,revision,provider,purpose,secret_key_version,secret_value_nonce,secret_value_ciphertext,binding_digest,status,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, secret.OwnerID, secret.Ref, secret.Revision, secret.Provider, secret.Purpose, envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext, secret.BindingDigest, secret.Status, secret.CreatedAt, secret.UpdatedAt)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "duplicate") {
			return Secret{}, ErrConflict
		}
		return Secret{}, err
	}
	return secret, nil
}
func (s *PostgresStore) ReadSecret(ctx context.Context, owner, ref string, revision uint64) (Secret, error) {
	var secret Secret
	var version uint32
	var nonce, ciphertext []byte
	err := s.pool.QueryRow(ctx, `SELECT owner_id,secret_ref::text,revision,provider,purpose,secret_key_version,secret_value_nonce,secret_value_ciphertext,binding_digest,status,created_at,updated_at FROM core_execution_v2_secrets WHERE owner_id=$1 AND secret_ref=$2 AND ($3=0 OR revision=$3)`, owner, ref, revision).Scan(&secret.OwnerID, &secret.Ref, &secret.Revision, &secret.Provider, &secret.Purpose, &version, &nonce, &ciphertext, &secret.BindingDigest, &secret.Status, &secret.CreatedAt, &secret.UpdatedAt)
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
	aad, aadErr := secretbox.BindAAD("core_execution_v2_secrets", owner+"/"+ref, int64(secret.Revision), "secret_value")
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
func (s *PostgresStore) ListSecrets(ctx context.Context, owner, token string, limit int) ([]Secret, string, error) {
	rows, err := s.pool.Query(ctx, `SELECT owner_id,secret_ref::text,revision,provider,purpose,secret_key_version,secret_value_nonce,secret_value_ciphertext,binding_digest,status,created_at,updated_at FROM core_execution_v2_secrets WHERE owner_id=$1 AND ($2='' OR secret_ref::text>$2) ORDER BY secret_ref LIMIT $3`, owner, token, limit)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	items := make([]Secret, 0)
	for rows.Next() {
		var secret Secret
		var version uint32
		var nonce, ciphertext []byte
		if err := rows.Scan(&secret.OwnerID, &secret.Ref, &secret.Revision, &secret.Provider, &secret.Purpose, &version, &nonce, &ciphertext, &secret.BindingDigest, &secret.Status, &secret.CreatedAt, &secret.UpdatedAt); err != nil {
			return nil, "", err
		}
		if s.key == nil {
			return nil, "", ErrSecretNotFound
		}
		aad, err := secretbox.BindAAD("core_execution_v2_secrets", owner+"/"+secret.Ref, int64(secret.Revision), "secret_value")
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
	var nonce, ciphertext []byte
	if err := tx.QueryRow(ctx, `SELECT secret_key_version,secret_value_nonce,secret_value_ciphertext FROM core_execution_v2_secrets WHERE owner_id=$1 AND secret_ref=$2 AND revision=$3 FOR UPDATE`, secret.OwnerID, secret.Ref, expected).Scan(&version, &nonce, &ciphertext); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Secret{}, ErrConflict
		}
		return Secret{}, err
	}
	aad, err := secretbox.BindAAD("core_execution_v2_secrets", secret.OwnerID+"/"+secret.Ref, int64(expected), "secret_value")
	if err != nil {
		return Secret{}, ErrInvalid
	}
	plaintext, err := s.key.Open(secretbox.Envelope{KeyVersion: version, Nonce: nonce, Ciphertext: ciphertext}, aad)
	if err != nil {
		return Secret{}, ErrSecretNotFound
	}
	newRevision := expected + 1
	newAAD, err := secretbox.BindAAD("core_execution_v2_secrets", secret.OwnerID+"/"+secret.Ref, int64(newRevision), "secret_value")
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
	result, err := tx.Exec(ctx, `UPDATE core_execution_v2_secrets SET revision=$1,status=$2,secret_key_version=$3,secret_value_nonce=$4,secret_value_ciphertext=$5,updated_at=$6 WHERE owner_id=$7 AND secret_ref=$8 AND revision=$9`, newRevision, secret.Status, envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext, secret.UpdatedAt, secret.OwnerID, secret.Ref, expected)
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
