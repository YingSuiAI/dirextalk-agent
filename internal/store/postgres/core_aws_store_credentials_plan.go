package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreAWSStore struct{ store *Store }

func NewCoreAWSStore(s *Store) *CoreAWSStore { return &CoreAWSStore{store: s} }

const awsCredentialDomain = "core_aws_credentials"

func (s *CoreAWSStore) keyring() (*secretbox.Keyring, error) {
	if s == nil || s.store == nil {
		return nil, errSecretKeyUnavailable
	}
	return s.store.secretKeyring()
}

func secretCredential(c coreaws.Credentials, a, se, t []byte) coreaws.Credentials { // restore private bytes for provider use; never serialized/logged
	defer clearBytes(a)
	defer clearBytes(se)
	defer clearBytes(t)
	return coreaws.RehydrateCredentialsWithTestedAt(c.ID, c.Name, c.Region, c.AccountID, c.UserARN, a, se, t, c.VerifiedRevision, c.Revision, c.TestedAt, c.CreatedAt, c.UpdatedAt)
}
func credArgs(c coreaws.Credentials) ([]byte, []byte, []byte) {
	return c.StoredSecretBytes()
}

func credentialSessionConfigured(c coreaws.Credentials) bool {
	a, se, t := credArgs(c)
	configured := len(t) > 0
	clearBytes(a)
	clearBytes(se)
	clearBytes(t)
	return configured
}

type encryptedCredential struct {
	keyVersion                      uint32
	accessNonce, accessCiphertext   []byte
	secretNonce, secretCiphertext   []byte
	sessionNonce, sessionCiphertext []byte
}

func (s *CoreAWSStore) sealCredential(c coreaws.Credentials) (encryptedCredential, error) {
	key, err := s.keyring()
	if err != nil {
		return encryptedCredential{}, err
	}
	a, se, t := credArgs(c)
	defer clearBytes(a)
	defer clearBytes(se)
	defer clearBytes(t)
	seal := func(field string, plaintext []byte) (secretbox.Envelope, error) {
		aad, err := secretbox.BindAAD(awsCredentialDomain, c.ID, c.Revision, field)
		if err != nil {
			return secretbox.Envelope{}, err
		}
		return key.Seal(plaintext, aad)
	}
	access, err := seal("access_key_id", a)
	if err != nil {
		return encryptedCredential{}, err
	}
	secret, err := seal("secret_access_key", se)
	if err != nil {
		return encryptedCredential{}, err
	}
	session, err := seal("session_token", t)
	if err != nil {
		return encryptedCredential{}, err
	}
	return encryptedCredential{keyVersion: key.Version(), accessNonce: access.Nonce, accessCiphertext: access.Ciphertext, secretNonce: secret.Nonce, secretCiphertext: secret.Ciphertext, sessionNonce: session.Nonce, sessionCiphertext: session.Ciphertext}, nil
}

func (s *CoreAWSStore) openCredential(c coreaws.Credentials, encrypted encryptedCredential) (coreaws.Credentials, error) {
	key, err := s.keyring()
	if err != nil {
		return coreaws.Credentials{}, err
	}
	if encrypted.keyVersion != key.Version() {
		return coreaws.Credentials{}, secretbox.ErrKeyVersionMismatch
	}
	open := func(field string, nonce, ciphertext []byte) ([]byte, error) {
		aad, err := secretbox.BindAAD(awsCredentialDomain, c.ID, c.Revision, field)
		if err != nil {
			return nil, err
		}
		return key.Open(secretbox.Envelope{KeyVersion: encrypted.keyVersion, Nonce: nonce, Ciphertext: ciphertext}, aad)
	}
	a, err := open("access_key_id", encrypted.accessNonce, encrypted.accessCiphertext)
	if err != nil {
		return coreaws.Credentials{}, err
	}
	se, err := open("secret_access_key", encrypted.secretNonce, encrypted.secretCiphertext)
	if err != nil {
		clearBytes(a)
		return coreaws.Credentials{}, err
	}
	t, err := open("session_token", encrypted.sessionNonce, encrypted.sessionCiphertext)
	if err != nil {
		clearBytes(a)
		clearBytes(se)
		return coreaws.Credentials{}, err
	}
	return secretCredential(c, a, se, t), nil
}

type credentialRow interface{ Scan(...any) error }

func (s *CoreAWSStore) scanCredentialRow(row credentialRow) (coreaws.Credentials, error) {
	var c coreaws.Credentials
	var encrypted encryptedCredential
	var testedAt *time.Time
	if err := row.Scan(&c.ID, &c.Name, &c.Region, &encrypted.keyVersion, &encrypted.accessNonce, &encrypted.accessCiphertext, &encrypted.secretNonce, &encrypted.secretCiphertext, &encrypted.sessionNonce, &encrypted.sessionCiphertext, &c.AccountID, &c.UserARN, &c.VerifiedRevision, &c.Revision, &testedAt, &c.CreatedAt, &c.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c, coreaws.ErrNotFound
		}
		return c, err
	}
	if testedAt != nil {
		c.TestedAt = testedAt.UTC()
	}
	c.CreatedAt = c.CreatedAt.UTC()
	c.UpdatedAt = c.UpdatedAt.UTC()
	return s.openCredential(c, encrypted)
}

func clearBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

func nullableCredentialTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func (s *CoreAWSStore) CreateCredential(ctx context.Context, c coreaws.Credentials) (coreaws.Credentials, error) {
	if c.Validate() != nil || s == nil || s.store == nil {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	encrypted, err := s.sealCredential(c)
	if err != nil {
		return coreaws.Credentials{}, err
	}
	configured := credentialSessionConfigured(c)
	_, e := s.store.pool.Exec(ctx, `INSERT INTO core_aws_credentials(credential_id,owner_id,account_generation,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at) VALUES($1,$2,1,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`, c.ID, s.store.instanceID.String(), c.Name, c.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, c.AccountID, c.UserARN, c.VerifiedRevision, c.Revision, nullableCredentialTime(c.TestedAt), c.CreatedAt, c.UpdatedAt)
	if e != nil {
		return coreaws.Credentials{}, e
	}
	return c, nil
}
func (s *CoreAWSStore) GetCredential(ctx context.Context, id string) (coreaws.Credentials, error) {
	if s == nil || s.store == nil {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	return s.scanCredentialRow(s.store.pool.QueryRow(ctx, `SELECT credential_id::text,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at FROM core_aws_credentials WHERE credential_id=$1`, id))
}

func (s *CoreAWSStore) GetCredentialScoped(ctx context.Context, scope coreteam.Scope, id string) (coreaws.Credentials, error) {
	if s == nil || s.store == nil || scope.Validate() != nil {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	return s.scanCredentialRow(s.store.pool.QueryRow(ctx, `SELECT credential_id::text,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at FROM core_aws_credentials WHERE credential_id=$1 AND owner_id=$2 AND account_generation=$3`, id, scope.OwnerID, scope.AccountGeneration))
}
func (s *CoreAWSStore) ListCredentials(ctx context.Context, size int, token string) (coreaws.CredentialPage, error) {
	if size < 0 || size > 100 {
		return coreaws.CredentialPage{}, coreaws.ErrInvalid
	}
	rows, e := s.store.pool.Query(ctx, `SELECT credential_id::text,name,region,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at,TRUE,TRUE,session_token_configured FROM core_aws_credentials WHERE credential_id::text>$1 ORDER BY credential_id LIMIT $2`, token, size+1)
	if e != nil {
		return coreaws.CredentialPage{}, e
	}
	defer rows.Close()
	var out []coreaws.CredentialView
	for rows.Next() {
		var v coreaws.CredentialView
		var testedAt *time.Time
		if e = rows.Scan(&v.ID, &v.Name, &v.Region, &v.AccountID, &v.UserARN, &v.VerifiedRevision, &v.Revision, &testedAt, &v.CreatedAt, &v.UpdatedAt, &v.HasAccessKey, &v.HasSecretKey, &v.HasSessionToken); e != nil {
			return coreaws.CredentialPage{}, e
		}
		if testedAt != nil {
			v.TestedAt = testedAt.UTC()
		}
		out = append(out, v)
	}
	page := coreaws.CredentialPage{Items: out}
	if len(out) > size {
		page.Items = out[:size]
		if size > 0 {
			page.NextPageToken = page.Items[len(page.Items)-1].ID
		}
	}
	return page, rows.Err()
}

func (s *CoreAWSStore) ListCredentialsScoped(ctx context.Context, scope coreteam.Scope, size int, token string) (coreaws.CredentialPage, error) {
	if scope.Validate() != nil || size < 0 || size > 100 {
		return coreaws.CredentialPage{}, coreaws.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT credential_id::text,name,region,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at,TRUE,TRUE,session_token_configured FROM core_aws_credentials WHERE owner_id=$1 AND account_generation=$2 AND credential_id::text>$3 ORDER BY credential_id LIMIT $4`, scope.OwnerID, scope.AccountGeneration, token, size+1)
	if err != nil {
		return coreaws.CredentialPage{}, err
	}
	defer rows.Close()
	var items []coreaws.CredentialView
	for rows.Next() {
		var view coreaws.CredentialView
		var testedAt *time.Time
		if err = rows.Scan(&view.ID, &view.Name, &view.Region, &view.AccountID, &view.UserARN, &view.VerifiedRevision, &view.Revision, &testedAt, &view.CreatedAt, &view.UpdatedAt, &view.HasAccessKey, &view.HasSecretKey, &view.HasSessionToken); err != nil {
			return coreaws.CredentialPage{}, err
		}
		if testedAt != nil {
			view.TestedAt = testedAt.UTC()
		}
		items = append(items, view)
	}
	page := coreaws.CredentialPage{Items: items}
	if len(items) > size {
		page.Items = items[:size]
		if size > 0 {
			page.NextPageToken = page.Items[len(page.Items)-1].ID
		}
	}
	return page, rows.Err()
}
func (s *CoreAWSStore) UpdateCredential(ctx context.Context, c coreaws.Credentials, expected int64) (coreaws.Credentials, error) {
	if c.Validate() != nil || c.Revision != expected+1 {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	encrypted, err := s.sealCredential(c)
	if err != nil {
		return coreaws.Credentials{}, err
	}
	configured := credentialSessionConfigured(c)
	tag, e := s.store.pool.Exec(ctx, `UPDATE core_aws_credentials SET name=$2,region=$3,secret_key_version=$4,access_key_id_nonce=$5,access_key_id_ciphertext=$6,secret_access_key_nonce=$7,secret_access_key_ciphertext=$8,session_token_nonce=$9,session_token_ciphertext=$10,session_token_configured=$11,account_id=$12,user_arn=$13,verified_revision=$14,revision=$15,tested_at=$16,updated_at=$17 WHERE credential_id=$1 AND revision=$18 AND owner_id=$19 AND account_generation=1`, c.ID, c.Name, c.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, c.AccountID, c.UserARN, c.VerifiedRevision, c.Revision, nullableCredentialTime(c.TestedAt), c.UpdatedAt, expected, s.store.instanceID.String())
	if e != nil {
		return coreaws.Credentials{}, e
	}
	if tag.RowsAffected() != 1 {
		return coreaws.Credentials{}, coreaws.ErrRevisionConflict
	}
	return s.GetCredential(ctx, c.ID)
}
func (s *CoreAWSStore) DeleteCredential(ctx context.Context, id string, expected int64) error {
	tag, e := s.store.pool.Exec(ctx, `DELETE FROM core_aws_credentials WHERE credential_id=$1 AND revision=$2 AND owner_id=$3 AND account_generation=1`, id, expected, s.store.instanceID.String())
	if e == nil && tag.RowsAffected() == 0 {
		return coreaws.ErrRevisionConflict
	}
	return e
}
func (s *CoreAWSStore) RecordCredentialIdentity(ctx context.Context, id string, rev int64, i coreaws.Identity, testedAt time.Time) (coreaws.Credentials, error) {
	if testedAt.IsZero() {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	testedAt = testedAt.UTC()
	tag, e := s.store.pool.Exec(ctx, `UPDATE core_aws_credentials SET account_id=$2,user_arn=$3,verified_revision=$4,tested_at=$5,updated_at=$5 WHERE credential_id=$1 AND revision=$4`, id, i.AccountID, i.UserARN, rev, testedAt)
	if e != nil {
		return coreaws.Credentials{}, e
	}
	if tag.RowsAffected() != 1 {
		return coreaws.Credentials{}, coreaws.ErrRevisionConflict
	}
	return s.GetCredential(ctx, id)
}

// BeginCredentialTest commits a durable claim before any provider call.  The
// transaction and advisory lock are intentionally short: they serialize only
// claim creation/replay inspection, never the potentially 30-second STS
// request. Active in-progress claims are reported to bounded same-key waiters;
// uncertain claims are fail-closed on retry.
func (s *CoreAWSStore) BeginCredentialTest(ctx context.Context, scope coreteam.Scope, id string, expected int64, key string, leaseTimes ...time.Time) (coreaws.CredentialTestClaim, *coreaws.CredentialTest, error) {
	if s == nil || s.store == nil || s.store.pool == nil || scope.Validate() != nil || uuid.Validate(id) != nil || uuid.Validate(key) != nil || expected < 1 {
		return coreaws.CredentialTestClaim{}, nil, coreaws.ErrInvalid
	}
	leaseExpiresAt, completionGraceUntil, err := coreaws.CredentialTestLeaseTimes(time.Now(), leaseTimes...)
	if err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::bigint,$3::text)::text,0))`, scope.OwnerID, scope.AccountGeneration, key); err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	digest := coreaws.CredentialTestBindingDigest(id, expected)
	var storedHash, state, claimID, storedCredentialID string
	var storedExpected int64
	var replayRaw []byte
	var storedLeaseExpiresAt, storedCompletionGraceUntil time.Time
	claimErr := tx.QueryRow(ctx, `SELECT request_hash,state,claim_id::text,credential_id::text,expected_revision,lease_expires_at,completion_grace_until,response_json FROM core_aws_credential_test_claims WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, scope.OwnerID, scope.AccountGeneration, key).Scan(&storedHash, &state, &claimID, &storedCredentialID, &storedExpected, &storedLeaseExpiresAt, &storedCompletionGraceUntil, &replayRaw)
	if claimErr == nil {
		if storedHash != digest || storedCredentialID != id || storedExpected != expected {
			return coreaws.CredentialTestClaim{}, nil, coreaws.ErrIdempotencyConflict
		}
		switch state {
		case "in_progress":
			return coreaws.CredentialTestClaim{}, nil, &coreaws.CredentialTestInProgressError{LeaseExpiresAt: storedLeaseExpiresAt.UTC(), CompletionGraceUntil: storedCompletionGraceUntil.UTC()}
		case "uncertain":
			return coreaws.CredentialTestClaim{}, nil, coreaws.ErrResponseUncertain
		case "failed":
			return coreaws.CredentialTestClaim{}, nil, coreaws.ErrProvider
		case "completed":
			var replay coreaws.CredentialTest
			if len(replayRaw) == 0 || json.Unmarshal(replayRaw, &replay) != nil || replay.CredentialID != id || replay.CredentialRevision != expected || replay.TestedAt.IsZero() {
				return coreaws.CredentialTestClaim{}, nil, coreaws.ErrConflict
			}
			if err := tx.Commit(ctx); err != nil {
				return coreaws.CredentialTestClaim{}, nil, err
			}
			return coreaws.CredentialTestClaim{}, &replay, nil
		default:
			return coreaws.CredentialTestClaim{}, nil, coreaws.ErrConflict
		}
	}
	if !errors.Is(claimErr, pgx.ErrNoRows) {
		return coreaws.CredentialTestClaim{}, nil, claimErr
	}
	credential, err := s.scanCredentialRow(tx.QueryRow(ctx, `SELECT credential_id::text,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at FROM core_aws_credentials WHERE owner_id=$1 AND account_generation=$2 AND credential_id=$3`, scope.OwnerID, scope.AccountGeneration, id))
	if err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	if credential.Revision != expected {
		return coreaws.CredentialTestClaim{}, nil, coreaws.ErrRevisionConflict
	}
	claimID = uuid.NewString()
	if _, err = tx.Exec(ctx, `INSERT INTO core_aws_credential_test_claims(owner_id,account_generation,idempotency_key,claim_id,credential_id,expected_revision,request_hash,state,lease_expires_at,completion_grace_until) VALUES($1,$2,$3,$4,$5,$6,$7,'in_progress',$8,$9)`, scope.OwnerID, scope.AccountGeneration, key, claimID, id, expected, digest, leaseExpiresAt, completionGraceUntil); err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	return coreaws.CredentialTestClaim{ClaimID: claimID, IdempotencyKey: key, OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, CredentialID: id, ExpectedRevision: expected, LeaseExpiresAt: leaseExpiresAt, CompletionGraceUntil: completionGraceUntil, Credential: credential}, nil, nil
}

// CompleteCredentialTest commits the provider identity and replay receipt in
// one short transaction after the provider call has returned.  It never
// invokes provider code and therefore cannot hold database locks across STS.
func (s *CoreAWSStore) CompleteCredentialTest(ctx context.Context, claim coreaws.CredentialTestClaim, identity coreaws.Identity, testedAt time.Time) (coreaws.CredentialTest, error) {
	scope := coreteam.Scope{OwnerID: claim.OwnerID, AccountGeneration: claim.AccountGeneration}
	if s == nil || s.store == nil || s.store.pool == nil || scope.Validate() != nil || uuid.Validate(claim.ClaimID) != nil || uuid.Validate(claim.IdempotencyKey) != nil || uuid.Validate(claim.CredentialID) != nil || claim.ExpectedRevision < 1 || testedAt.IsZero() {
		return coreaws.CredentialTest{}, coreaws.ErrInvalid
	}
	testedAt = testedAt.UTC().Truncate(time.Microsecond)
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return coreaws.CredentialTest{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::bigint,$3::text)::text,0))`, scope.OwnerID, scope.AccountGeneration, claim.IdempotencyKey); err != nil {
		return coreaws.CredentialTest{}, err
	}
	digest := coreaws.CredentialTestBindingDigest(claim.CredentialID, claim.ExpectedRevision)
	var credentialRevision int64
	if err = tx.QueryRow(ctx, `SELECT revision FROM core_aws_credentials WHERE owner_id=$1 AND account_generation=$2 AND credential_id=$3 FOR UPDATE`, scope.OwnerID, scope.AccountGeneration, claim.CredentialID).Scan(&credentialRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreaws.CredentialTest{}, coreaws.ErrResponseUncertain
		}
		return coreaws.CredentialTest{}, err
	}
	if credentialRevision != claim.ExpectedRevision {
		return coreaws.CredentialTest{}, coreaws.ErrRevisionConflict
	}
	var storedHash, state, storedClaimID, storedCredentialID string
	var storedExpected int64
	var replayRaw []byte
	if err = tx.QueryRow(ctx, `SELECT request_hash,state,claim_id::text,credential_id::text,expected_revision,response_json FROM core_aws_credential_test_claims WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 FOR UPDATE`, scope.OwnerID, scope.AccountGeneration, claim.IdempotencyKey).Scan(&storedHash, &state, &storedClaimID, &storedCredentialID, &storedExpected, &replayRaw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreaws.CredentialTest{}, coreaws.ErrResponseUncertain
		}
		return coreaws.CredentialTest{}, err
	}
	if storedHash != digest || storedClaimID != claim.ClaimID || storedCredentialID != claim.CredentialID || storedExpected != claim.ExpectedRevision {
		return coreaws.CredentialTest{}, coreaws.ErrIdempotencyConflict
	}
	if state == "completed" {
		var replay coreaws.CredentialTest
		if len(replayRaw) == 0 || json.Unmarshal(replayRaw, &replay) != nil {
			return coreaws.CredentialTest{}, coreaws.ErrConflict
		}
		if err := tx.Commit(ctx); err != nil {
			return coreaws.CredentialTest{}, err
		}
		return replay, nil
	}
	if state != "in_progress" {
		return coreaws.CredentialTest{}, coreaws.ErrResponseUncertain
	}
	var persistedAccountID, persistedUserARN string
	var persistedTestedAt, persistedUpdatedAt time.Time
	if err := tx.QueryRow(ctx, `UPDATE core_aws_credentials SET account_id=CASE WHEN tested_at IS NULL OR tested_at <= $7 THEN $4 ELSE account_id END,user_arn=CASE WHEN tested_at IS NULL OR tested_at <= $7 THEN $5 ELSE user_arn END,verified_revision=$6,tested_at=GREATEST(COALESCE(tested_at,'epoch'::timestamptz),$7),updated_at=GREATEST(updated_at,$7) WHERE owner_id=$1 AND account_generation=$2 AND credential_id=$3 AND revision=$6 RETURNING account_id,user_arn,tested_at,updated_at`, scope.OwnerID, scope.AccountGeneration, claim.CredentialID, identity.AccountID, identity.UserARN, claim.ExpectedRevision, testedAt).Scan(&persistedAccountID, &persistedUserARN, &persistedTestedAt, &persistedUpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreaws.CredentialTest{}, coreaws.ErrRevisionConflict
		}
		return coreaws.CredentialTest{}, err
	}
	_ = persistedUpdatedAt
	identity.AccountID, identity.UserARN = persistedAccountID, persistedUserARN
	test := coreaws.CredentialTest{CredentialID: claim.CredentialID, Identity: identity, CredentialRevision: claim.ExpectedRevision, TestedAt: persistedTestedAt.UTC()}
	encoded, err := json.Marshal(test)
	if err != nil {
		return coreaws.CredentialTest{}, err
	}
	claimUpdate, err := tx.Exec(ctx, `UPDATE core_aws_credential_test_claims SET state='completed',response_json=$4,completed_at=$5,updated_at=$5 WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 AND state='in_progress'`, scope.OwnerID, scope.AccountGeneration, claim.IdempotencyKey, encoded, testedAt)
	if err != nil {
		return coreaws.CredentialTest{}, err
	}
	if claimUpdate.RowsAffected() != 1 {
		return coreaws.CredentialTest{}, coreaws.ErrResponseUncertain
	}
	if err := tx.Commit(ctx); err != nil {
		return coreaws.CredentialTest{}, err
	}
	return test, nil
}

// MarkCredentialTestUncertain fences a claim after a provider error or a
// failed completion.  It is intentionally terminal: a retry must not guess
// whether the provider request reached AWS.
func (s *CoreAWSStore) MarkCredentialTestUncertain(ctx context.Context, claim coreaws.CredentialTestClaim) error {
	scope := coreteam.Scope{OwnerID: claim.OwnerID, AccountGeneration: claim.AccountGeneration}
	if s == nil || s.store == nil || s.store.pool == nil || scope.Validate() != nil || uuid.Validate(claim.ClaimID) != nil || uuid.Validate(claim.IdempotencyKey) != nil || uuid.Validate(claim.CredentialID) != nil || claim.ExpectedRevision < 1 {
		return coreaws.ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::bigint,$3::text)::text,0))`, scope.OwnerID, scope.AccountGeneration, claim.IdempotencyKey); err != nil {
		return err
	}
	digest := coreaws.CredentialTestBindingDigest(claim.CredentialID, claim.ExpectedRevision)
	tag, err := tx.Exec(ctx, `UPDATE core_aws_credential_test_claims SET state='uncertain',error_code='UNCERTAIN',error_message='provider outcome requires reconciliation',updated_at=clock_timestamp() WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 AND claim_id=$4 AND credential_id=$5 AND expected_revision=$6 AND request_hash=$7 AND state='in_progress'`, scope.OwnerID, scope.AccountGeneration, claim.IdempotencyKey, claim.ClaimID, claim.CredentialID, claim.ExpectedRevision, digest)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_aws_credential_test_claims WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 AND claim_id=$4`, scope.OwnerID, scope.AccountGeneration, claim.IdempotencyKey, claim.ClaimID).Scan(&state); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coreaws.ErrResponseUncertain
			}
			return err
		}
		if state != "completed" && state != "uncertain" {
			return coreaws.ErrResponseUncertain
		}
	}
	return tx.Commit(ctx)
}

func (s *CoreAWSStore) MarkCredentialTestFailed(ctx context.Context, claim coreaws.CredentialTestClaim) error {
	scope := coreteam.Scope{OwnerID: claim.OwnerID, AccountGeneration: claim.AccountGeneration}
	if s == nil || s.store == nil || s.store.pool == nil || scope.Validate() != nil || uuid.Validate(claim.ClaimID) != nil || uuid.Validate(claim.IdempotencyKey) != nil || uuid.Validate(claim.CredentialID) != nil || claim.ExpectedRevision < 1 {
		return coreaws.ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended(jsonb_build_array($1::text,$2::bigint,$3::text)::text,0))`, scope.OwnerID, scope.AccountGeneration, claim.IdempotencyKey); err != nil {
		return err
	}
	digest := coreaws.CredentialTestBindingDigest(claim.CredentialID, claim.ExpectedRevision)
	tag, err := tx.Exec(ctx, `UPDATE core_aws_credential_test_claims SET state='failed',error_code='PROVIDER_FAILED',error_message='provider credential test failed',updated_at=clock_timestamp() WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 AND claim_id=$4 AND credential_id=$5 AND expected_revision=$6 AND request_hash=$7 AND state='in_progress'`, scope.OwnerID, scope.AccountGeneration, claim.IdempotencyKey, claim.ClaimID, claim.CredentialID, claim.ExpectedRevision, digest)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_aws_credential_test_claims WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 AND claim_id=$4`, scope.OwnerID, scope.AccountGeneration, claim.IdempotencyKey, claim.ClaimID).Scan(&state); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coreaws.ErrResponseUncertain
			}
			return err
		}
		if state != "failed" {
			if state == "completed" {
				return tx.Commit(ctx)
			}
			return coreaws.ErrResponseUncertain
		}
	}
	return tx.Commit(ctx)
}

func (s *CoreAWSStore) RecordCredentialIdentityScoped(ctx context.Context, scope coreteam.Scope, id string, revision int64, identity coreaws.Identity, testedAt time.Time) (coreaws.Credentials, error) {
	if scope.Validate() != nil || testedAt.IsZero() {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	testedAt = testedAt.UTC()
	tag, err := s.store.pool.Exec(ctx, `UPDATE core_aws_credentials SET account_id=$4,user_arn=$5,verified_revision=$6,tested_at=$7,updated_at=$7 WHERE credential_id=$1 AND owner_id=$2 AND account_generation=$3 AND revision=$6`, id, scope.OwnerID, scope.AccountGeneration, identity.AccountID, identity.UserARN, revision, testedAt)
	if err != nil {
		return coreaws.Credentials{}, err
	}
	if tag.RowsAffected() != 1 {
		return coreaws.Credentials{}, coreaws.ErrRevisionConflict
	}
	return s.GetCredentialScoped(ctx, scope, id)
}
func (s *CoreAWSStore) CreatePlan(ctx context.Context, p coreaws.Plan) (coreaws.Plan, error) {
	if p.Validate() != nil {
		return p, coreaws.ErrInvalid
	}
	pj, _ := json.Marshal(p.Parameters)
	tj, _ := json.Marshal(p.Tags)
	cj, _ := json.Marshal(p.Capabilities)
	_, e := s.store.pool.Exec(ctx, `INSERT INTO core_aws_plans(plan_id,owner_id,account_generation,credential_id,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, p.ID, p.OwnerID, p.AccountGeneration, p.CredentialID, p.Region, p.StackName, p.Operation, p.Template, p.TemplateSHA256, pj, tj, cj, p.Revision, p.CreatedAt)
	return p, e
}

func (s *CoreAWSStore) CreatePlanScoped(ctx context.Context, scope coreteam.Scope, plan coreaws.Plan, idempotencyKey, requestDigest string) (coreaws.Plan, error) {
	invalidDigest := len(requestDigest) != 64 || strings.IndexFunc(requestDigest, func(r rune) bool { return r < '0' || r > '9' && r < 'a' || r > 'f' }) >= 0
	if scope.Validate() != nil || plan.Validate() != nil || plan.OwnerID != scope.OwnerID || plan.AccountGeneration != scope.AccountGeneration || uuid.Validate(idempotencyKey) != nil || invalidDigest {
		return coreaws.Plan{}, coreaws.ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return coreaws.Plan{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "core_aws_plan:"+scope.OwnerID+":"+idempotencyKey); err != nil {
		return coreaws.Plan{}, err
	}
	var existingDigest, existingPlanID string
	err = tx.QueryRow(ctx, `SELECT request_hash,plan_id::text FROM core_aws_plan_replays WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, scope.OwnerID, scope.AccountGeneration, idempotencyKey).Scan(&existingDigest, &existingPlanID)
	if err == nil {
		if existingDigest != requestDigest {
			return coreaws.Plan{}, coreaws.ErrIdempotencyConflict
		}
		return scanAWSPlanRow(tx.QueryRow(ctx, awsPlanSelect+` WHERE plan_id=$1 AND owner_id=$2 AND account_generation=$3`, existingPlanID, scope.OwnerID, scope.AccountGeneration))
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coreaws.Plan{}, err
	}
	var credentialID string
	if err = tx.QueryRow(ctx, `SELECT credential_id::text FROM core_aws_credentials WHERE credential_id=$1 AND owner_id=$2 AND account_generation=$3 FOR KEY SHARE`, plan.CredentialID, scope.OwnerID, scope.AccountGeneration).Scan(&credentialID); errors.Is(err, pgx.ErrNoRows) {
		return coreaws.Plan{}, coreaws.ErrNotFound
	} else if err != nil {
		return coreaws.Plan{}, err
	}
	parameters, _ := json.Marshal(plan.Parameters)
	tags, _ := json.Marshal(plan.Tags)
	capabilities, _ := json.Marshal(plan.Capabilities)
	if _, err = tx.Exec(ctx, `INSERT INTO core_aws_plans(plan_id,owner_id,account_generation,credential_id,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, plan.ID, scope.OwnerID, scope.AccountGeneration, plan.CredentialID, plan.Region, plan.StackName, plan.Operation, plan.Template, plan.TemplateSHA256, parameters, tags, capabilities, plan.Revision, plan.CreatedAt); err != nil {
		return coreaws.Plan{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO core_aws_plan_replays(owner_id,account_generation,idempotency_key,request_hash,plan_id,created_at) VALUES($1,$2,$3,$4,$5,$6)`, scope.OwnerID, scope.AccountGeneration, idempotencyKey, requestDigest, plan.ID, plan.CreatedAt); err != nil {
		return coreaws.Plan{}, err
	}
	if err = tx.Commit(ctx); err != nil {
		return coreaws.Plan{}, err
	}
	return plan, nil
}

const awsPlanSelect = `SELECT plan_id::text,owner_id,account_generation,credential_id::text,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at FROM core_aws_plans`

func scanAWSPlanRow(row credentialRow) (coreaws.Plan, error) {
	var plan coreaws.Plan
	var operation string
	var parameters, tags, capabilities []byte
	err := row.Scan(&plan.ID, &plan.OwnerID, &plan.AccountGeneration, &plan.CredentialID, &plan.Region, &plan.StackName, &operation, &plan.Template, &plan.TemplateSHA256, &parameters, &tags, &capabilities, &plan.Revision, &plan.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return coreaws.Plan{}, coreaws.ErrNotFound
	}
	if err != nil {
		return coreaws.Plan{}, err
	}
	plan.Operation = coreaws.Operation(operation)
	if json.Unmarshal(parameters, &plan.Parameters) != nil || json.Unmarshal(tags, &plan.Tags) != nil || json.Unmarshal(capabilities, &plan.Capabilities) != nil {
		return coreaws.Plan{}, coreaws.ErrConflict
	}
	return plan, nil
}

func (s *CoreAWSStore) GetPlan(ctx context.Context, id string) (coreaws.Plan, error) {
	return scanAWSPlanRow(s.store.pool.QueryRow(ctx, awsPlanSelect+` WHERE plan_id=$1`, id))
}

func (s *CoreAWSStore) GetPlanScoped(ctx context.Context, scope coreteam.Scope, id string) (coreaws.Plan, error) {
	if scope.Validate() != nil {
		return coreaws.Plan{}, coreaws.ErrInvalid
	}
	return scanAWSPlanRow(s.store.pool.QueryRow(ctx, awsPlanSelect+` WHERE plan_id=$1 AND owner_id=$2 AND account_generation=$3`, id, scope.OwnerID, scope.AccountGeneration))
}
func (s *CoreAWSStore) ListPlans(ctx context.Context, size int, token string) (coreaws.PlanPage, error) {
	rows, e := s.store.pool.Query(ctx, `SELECT plan_id::text FROM core_aws_plans WHERE plan_id::text>$1 ORDER BY plan_id LIMIT $2`, token, size+1)
	if e != nil {
		return coreaws.PlanPage{}, e
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	page := coreaws.PlanPage{}
	for i, id := range ids {
		if i >= size {
			if len(page.Items) > 0 {
				page.NextPageToken = page.Items[len(page.Items)-1].ID
			}
			break
		}
		p, e := s.GetPlan(ctx, id)
		if e != nil {
			return page, e
		}
		page.Items = append(page.Items, p.View())
	}
	return page, rows.Err()
}

func (s *CoreAWSStore) ListPlansScoped(ctx context.Context, scope coreteam.Scope, size int, token string) (coreaws.PlanPage, error) {
	if scope.Validate() != nil || size < 0 || size > 100 {
		return coreaws.PlanPage{}, coreaws.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT plan_id::text FROM core_aws_plans WHERE owner_id=$1 AND account_generation=$2 AND plan_id::text>$3 ORDER BY plan_id LIMIT $4`, scope.OwnerID, scope.AccountGeneration, token, size+1)
	if err != nil {
		return coreaws.PlanPage{}, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return coreaws.PlanPage{}, err
		}
		ids = append(ids, id)
	}
	page := coreaws.PlanPage{}
	for index, id := range ids {
		if index >= size {
			if len(page.Items) > 0 {
				page.NextPageToken = page.Items[len(page.Items)-1].ID
			}
			break
		}
		plan, getErr := s.GetPlanScoped(ctx, scope, id)
		if getErr != nil {
			return coreaws.PlanPage{}, getErr
		}
		page.Items = append(page.Items, plan.View())
	}
	return page, rows.Err()
}
func (s *CoreAWSStore) CreateChange(ctx context.Context, c coreaws.Change) (coreaws.Change, error) {
	_, e := s.store.pool.Exec(ctx, `INSERT INTO core_aws_changes(change_id,plan_id,credential_id,task_id,confirmation_id,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, c.ID, c.PlanID, c.CredentialID, c.TaskID, c.ConfirmationID, c.Operation, c.Status, c.Stage, c.ChangeSetID, c.ProviderRequestDigest, c.ProviderToken, c.Revision, c.ErrorCode, c.ErrorSummary, c.CreatedAt, c.UpdatedAt)
	return c, e
}
func (s *CoreAWSStore) GetChange(ctx context.Context, id string) (coreaws.Change, error) {
	return s.scanChange(s.store.pool.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE change_id=$1`, id))
}

func (s *CoreAWSStore) GetChangeScoped(ctx context.Context, scope coreteam.Scope, id string) (coreaws.Change, error) {
	if scope.Validate() != nil {
		return coreaws.Change{}, coreaws.ErrInvalid
	}
	return s.scanChange(s.store.pool.QueryRow(ctx, `SELECT change.change_id::text,change.plan_id::text,change.credential_id::text,change.task_id::text,change.confirmation_id::text,change.operation,change.status,change.stage,change.change_set_id,change.provider_request_digest,change.provider_token,change.revision,change.error_code,change.error_summary,change.created_at,change.updated_at FROM core_aws_changes change JOIN core_aws_plans plan ON plan.plan_id=change.plan_id WHERE change.change_id=$1 AND plan.owner_id=$2 AND plan.account_generation=$3`, id, scope.OwnerID, scope.AccountGeneration))
}
func (s *CoreAWSStore) GetChangeByConfirmation(ctx context.Context, id string) (coreaws.Change, error) {
	return s.scanChange(s.store.pool.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE confirmation_id=$1`, id))
}

// ListChanges returns a stable lexicographic cursor over change IDs.
func (s *CoreAWSStore) ListChanges(ctx context.Context, size int, planID, token string) (coreaws.Page[coreaws.Change], error) {
	if size < 0 || size > 100 {
		return coreaws.Page[coreaws.Change]{}, coreaws.ErrInvalid
	}
	lastID, err := changeCursor(planID, token)
	if err != nil {
		return coreaws.Page[coreaws.Change]{}, coreaws.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT change_id::text FROM core_aws_changes WHERE ($1='' OR plan_id::text=$1) AND change_id::text>$2 ORDER BY change_id LIMIT $3`, planID, lastID, size+1)
	if err != nil {
		return coreaws.Page[coreaws.Change]{}, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return coreaws.Page[coreaws.Change]{}, err
		}
		ids = append(ids, id)
	}
	page := coreaws.Page[coreaws.Change]{}
	for i, id := range ids {
		if i >= size {
			page.NextPageToken = makeChangeCursor(planID, page.Items[len(page.Items)-1].ID)
			break
		}
		v, e := s.GetChange(ctx, id)
		if e != nil {
			return page, e
		}
		page.Items = append(page.Items, v)
	}
	return page, rows.Err()
}

func (s *CoreAWSStore) ListChangesScoped(ctx context.Context, scope coreteam.Scope, size int, planID, token string) (coreaws.ChangePage, error) {
	if scope.Validate() != nil || size < 0 || size > 100 {
		return coreaws.ChangePage{}, coreaws.ErrInvalid
	}
	lastID, err := changeCursor(planID, token)
	if err != nil {
		return coreaws.ChangePage{}, coreaws.ErrInvalid
	}
	rows, err := s.store.pool.Query(ctx, `SELECT change.change_id::text FROM core_aws_changes change JOIN core_aws_plans plan ON plan.plan_id=change.plan_id WHERE plan.owner_id=$1 AND plan.account_generation=$2 AND ($3='' OR change.plan_id::text=$3) AND change.change_id::text>$4 ORDER BY change.change_id LIMIT $5`, scope.OwnerID, scope.AccountGeneration, planID, lastID, size+1)
	if err != nil {
		return coreaws.ChangePage{}, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return coreaws.ChangePage{}, err
		}
		ids = append(ids, id)
	}
	page := coreaws.ChangePage{}
	for index, id := range ids {
		if index >= size {
			if len(page.Items) > 0 {
				page.NextPageToken = makeChangeCursor(planID, page.Items[len(page.Items)-1].ID)
			}
			break
		}
		change, getErr := s.GetChangeScoped(ctx, scope, id)
		if getErr != nil {
			return coreaws.ChangePage{}, getErr
		}
		page.Items = append(page.Items, change)
	}
	return page, rows.Err()
}

var _ coreaws.ScopedRepository = (*CoreAWSStore)(nil)

// A change cursor is bound to its filter.  Its key is the last emitted row,
// never the look-ahead row, so the next query cannot skip an item.
func makeChangeCursor(planID, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(planID + "\x00" + id))
}
func changeCursor(planID, token string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 2 || parts[0] != planID || uuid.Validate(parts[1]) != nil {
		return "", errors.New("invalid cursor")
	}
	return parts[1], nil
}
func (s *CoreAWSStore) scanChange(row interface{ Scan(...any) error }) (coreaws.Change, error) {
	var c coreaws.Change
	var op, st, stage string
	e := row.Scan(&c.ID, &c.PlanID, &c.CredentialID, &c.TaskID, &c.ConfirmationID, &op, &st, &stage, &c.ChangeSetID, &c.ProviderRequestDigest, &c.ProviderToken, &c.Revision, &c.ErrorCode, &c.ErrorSummary, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return c, coreaws.ErrNotFound
	}
	c.Operation = coreaws.Operation(op)
	c.Status = coreaws.ChangeStatus(st)
	c.Stage = coreaws.ChangeStage(stage)
	return c, e
}
func (s *CoreAWSStore) UpdateChange(ctx context.Context, c coreaws.Change, expected int64) (coreaws.Change, error) {
	tag, e := s.store.pool.Exec(ctx, `UPDATE core_aws_changes SET status=$2,stage=$3,change_set_id=$4,provider_request_digest=$5,provider_token=$6,revision=$7,error_code=$8,error_summary=$9,updated_at=$10 WHERE change_id=$1 AND revision=$11`, c.ID, c.Status, c.Stage, c.ChangeSetID, c.ProviderRequestDigest, c.ProviderToken, c.Revision, c.ErrorCode, c.ErrorSummary, c.UpdatedAt, expected)
	if e == nil && tag.RowsAffected() == 0 {
		return c, coreaws.ErrRevisionConflict
	}
	return c, e
}
