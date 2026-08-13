package postgres

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreaws"
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
	tx, e := s.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.Credentials{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `INSERT INTO core_aws_credentials(credential_id,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`, c.ID, c.Name, c.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, c.AccountID, c.UserARN, c.VerifiedRevision, c.Revision, nullableCredentialTime(c.TestedAt), c.CreatedAt, c.UpdatedAt); e != nil {
		return coreaws.Credentials{}, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_aws_credential_revisions(credential_id,revision,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, c.ID, c.Revision, c.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, c.CreatedAt); e != nil {
		return coreaws.Credentials{}, e
	}
	if !c.TestedAt.IsZero() {
		if _, e = tx.Exec(ctx, `INSERT INTO core_aws_credential_revision_evidence(credential_id,revision,account_id,user_arn,tested_at) VALUES($1,$2,$3,$4,$5)`, c.ID, c.Revision, c.AccountID, c.UserARN, c.TestedAt); e != nil {
			return coreaws.Credentials{}, e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.Credentials{}, e
	}
	return c, nil
}
func (s *CoreAWSStore) GetCredential(ctx context.Context, id string) (coreaws.Credentials, error) {
	if s == nil || s.store == nil {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	return s.scanCredentialRow(s.store.pool.QueryRow(ctx, `SELECT credential_id::text,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at FROM core_aws_credentials WHERE credential_id=$1 AND disabled_at IS NULL`, id))
}
func (s *CoreAWSStore) GetCredentialRevision(ctx context.Context, id string, revision int64) (coreaws.Credentials, error) {
	if s == nil || s.store == nil || revision < 1 {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	return s.scanCredentialRow(s.store.pool.QueryRow(ctx, `SELECT c.credential_id::text,c.name,r.region,r.secret_key_version,r.access_key_id_nonce,r.access_key_id_ciphertext,r.secret_access_key_nonce,r.secret_access_key_ciphertext,r.session_token_nonce,r.session_token_ciphertext,COALESCE(e.account_id,''),COALESCE(e.user_arn,''),CASE WHEN e.tested_at IS NULL THEN 0 ELSE r.revision END,r.revision,e.tested_at,r.created_at,COALESCE(e.tested_at,r.created_at) FROM core_aws_credentials c JOIN core_aws_credential_revisions r ON r.credential_id=c.credential_id LEFT JOIN core_aws_credential_revision_evidence e ON e.credential_id=r.credential_id AND e.revision=r.revision WHERE c.credential_id=$1 AND r.revision=$2`, id, revision))
}
func (s *CoreAWSStore) ListCredentials(ctx context.Context, size int, token string) (coreaws.CredentialPage, error) {
	if size < 0 || size > 100 {
		return coreaws.CredentialPage{}, coreaws.ErrInvalid
	}
	rows, e := s.store.pool.Query(ctx, `SELECT credential_id::text,name,region,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at,TRUE,TRUE,session_token_configured FROM core_aws_credentials WHERE disabled_at IS NULL AND credential_id::text>$1 ORDER BY credential_id LIMIT $2`, token, size+1)
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
func (s *CoreAWSStore) UpdateCredential(ctx context.Context, c coreaws.Credentials, expected int64) (coreaws.Credentials, error) {
	if c.Validate() != nil || c.Revision != expected+1 {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	encrypted, err := s.sealCredential(c)
	if err != nil {
		return coreaws.Credentials{}, err
	}
	configured := credentialSessionConfigured(c)
	tx, e := s.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.Credentials{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = tx.Exec(ctx, `INSERT INTO core_aws_credential_revisions(credential_id,revision,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,session_token_configured,created_at) SELECT credential_id,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12 FROM core_aws_credentials WHERE credential_id=$1 AND revision=$13 AND disabled_at IS NULL`, c.ID, c.Revision, c.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, c.UpdatedAt, expected); e != nil {
		return coreaws.Credentials{}, e
	}
	tag, e := tx.Exec(ctx, `UPDATE core_aws_credentials SET name=$2,region=$3,secret_key_version=$4,access_key_id_nonce=$5,access_key_id_ciphertext=$6,secret_access_key_nonce=$7,secret_access_key_ciphertext=$8,session_token_nonce=$9,session_token_ciphertext=$10,session_token_configured=$11,account_id=$12,user_arn=$13,verified_revision=$14,revision=$15,tested_at=$16,updated_at=$17 WHERE credential_id=$1 AND revision=$18 AND disabled_at IS NULL`, c.ID, c.Name, c.Region, encrypted.keyVersion, encrypted.accessNonce, encrypted.accessCiphertext, encrypted.secretNonce, encrypted.secretCiphertext, encrypted.sessionNonce, encrypted.sessionCiphertext, configured, c.AccountID, c.UserARN, c.VerifiedRevision, c.Revision, nullableCredentialTime(c.TestedAt), c.UpdatedAt, expected)
	if e != nil {
		return coreaws.Credentials{}, e
	}
	if tag.RowsAffected() != 1 {
		return coreaws.Credentials{}, coreaws.ErrRevisionConflict
	}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.Credentials{}, e
	}
	return c, nil
}
func (s *CoreAWSStore) DeleteCredential(ctx context.Context, id string, expected int64) error {
	tag, e := s.store.pool.Exec(ctx, `UPDATE core_aws_credentials SET disabled_at=clock_timestamp(),updated_at=clock_timestamp() WHERE credential_id=$1 AND revision=$2 AND disabled_at IS NULL`, id, expected)
	if e == nil && tag.RowsAffected() == 0 {
		return coreaws.ErrRevisionConflict
	}
	return e
}
func (s *CoreAWSStore) RecordCredentialIdentity(ctx context.Context, id string, rev int64, i coreaws.Identity, testedAt time.Time) (coreaws.Credentials, error) {
	if testedAt.IsZero() {
		return coreaws.Credentials{}, coreaws.ErrInvalid
	}
	testedAt = testedAt.UTC().Truncate(time.Microsecond)
	tx, e := s.store.pool.Begin(ctx)
	if e != nil {
		return coreaws.Credentials{}, e
	}
	defer tx.Rollback(ctx)
	var active bool
	if e = tx.QueryRow(ctx, `SELECT revision=$2 AND disabled_at IS NULL FROM core_aws_credentials WHERE credential_id=$1 FOR UPDATE`, id, rev).Scan(&active); e != nil || !active {
		return coreaws.Credentials{}, coreaws.ErrRevisionConflict
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_aws_credential_revision_evidence(credential_id,revision,account_id,user_arn,tested_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT (credential_id,revision) DO NOTHING`, id, rev, i.AccountID, i.UserARN, testedAt); e != nil {
		return coreaws.Credentials{}, e
	}
	var persistedAccount, persistedARN string
	var persistedAt time.Time
	if e = tx.QueryRow(ctx, `SELECT account_id,user_arn,tested_at FROM core_aws_credential_revision_evidence WHERE credential_id=$1 AND revision=$2`, id, rev).Scan(&persistedAccount, &persistedARN, &persistedAt); e != nil || persistedAccount != i.AccountID || persistedARN != i.UserARN {
		return coreaws.Credentials{}, coreaws.ErrConflict
	}
	if _, e = tx.Exec(ctx, `UPDATE core_aws_credentials SET account_id=$2,user_arn=$3,verified_revision=$4,tested_at=$5,updated_at=GREATEST(updated_at,$5) WHERE credential_id=$1 AND revision=$4 AND disabled_at IS NULL`, id, persistedAccount, persistedARN, rev, persistedAt); e != nil {
		return coreaws.Credentials{}, e
	}
	if e = tx.Commit(ctx); e != nil {
		return coreaws.Credentials{}, e
	}
	return s.GetCredential(ctx, id)
}

// BeginCredentialTest commits a durable claim before any provider call.  The
// transaction and advisory lock are intentionally short: they serialize only
// claim creation/replay inspection, never the potentially 30-second STS
// request. Active in-progress claims are reported to bounded same-key waiters;
// uncertain claims are fail-closed on retry.
func (s *CoreAWSStore) BeginCredentialTest(ctx context.Context, id string, expected int64, key string, leaseTimes ...time.Time) (coreaws.CredentialTestClaim, *coreaws.CredentialTest, error) {
	if s == nil || s.store == nil || s.store.pool == nil || uuid.Validate(id) != nil || uuid.Validate(key) != nil || expected < 1 {
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
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "core_aws:test_credential:"+key); err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	digest := coreaws.CredentialTestBindingDigest(id, expected)
	var storedHash, state, claimID, storedCredentialID string
	var storedExpected int64
	var replayRaw []byte
	var storedLeaseExpiresAt, storedCompletionGraceUntil time.Time
	claimErr := tx.QueryRow(ctx, `SELECT request_hash,state,claim_id::text,credential_id::text,expected_revision,lease_expires_at,completion_grace_until,response_json FROM core_aws_credential_test_claims WHERE idempotency_key=$1`, key).Scan(&storedHash, &state, &claimID, &storedCredentialID, &storedExpected, &storedLeaseExpiresAt, &storedCompletionGraceUntil, &replayRaw)
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
	var currentRevision int64
	if err = tx.QueryRow(ctx, `SELECT revision FROM core_aws_credentials WHERE credential_id=$1 AND disabled_at IS NULL`, id).Scan(&currentRevision); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return coreaws.CredentialTestClaim{}, nil, coreaws.ErrNotFound
		}
		return coreaws.CredentialTestClaim{}, nil, err
	}
	if currentRevision != expected {
		return coreaws.CredentialTestClaim{}, nil, coreaws.ErrRevisionConflict
	}
	credential, err := s.scanCredentialRow(tx.QueryRow(ctx, `SELECT credential_id::text,name,region,secret_key_version,access_key_id_nonce,access_key_id_ciphertext,secret_access_key_nonce,secret_access_key_ciphertext,session_token_nonce,session_token_ciphertext,account_id,user_arn,verified_revision,revision,tested_at,created_at,updated_at FROM core_aws_credentials WHERE credential_id=$1 AND disabled_at IS NULL`, id))
	if err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	if credential.Revision != expected {
		return coreaws.CredentialTestClaim{}, nil, coreaws.ErrRevisionConflict
	}
	claimID = uuid.NewString()
	if _, err = tx.Exec(ctx, `INSERT INTO core_aws_credential_test_claims(idempotency_key,claim_id,credential_id,expected_revision,request_hash,state,lease_expires_at,completion_grace_until) VALUES($1,$2,$3,$4,$5,'in_progress',$6,$7)`, key, claimID, id, expected, digest, leaseExpiresAt, completionGraceUntil); err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return coreaws.CredentialTestClaim{}, nil, err
	}
	return coreaws.CredentialTestClaim{ClaimID: claimID, IdempotencyKey: key, CredentialID: id, ExpectedRevision: expected, LeaseExpiresAt: leaseExpiresAt, CompletionGraceUntil: completionGraceUntil, Credential: credential}, nil, nil
}

// CompleteCredentialTest commits the provider identity and replay receipt in
// one short transaction after the provider call has returned.  It never
// invokes provider code and therefore cannot hold database locks across STS.
func (s *CoreAWSStore) CompleteCredentialTest(ctx context.Context, claim coreaws.CredentialTestClaim, identity coreaws.Identity, testedAt time.Time) (coreaws.CredentialTest, error) {
	if s == nil || s.store == nil || s.store.pool == nil || uuid.Validate(claim.ClaimID) != nil || uuid.Validate(claim.IdempotencyKey) != nil || uuid.Validate(claim.CredentialID) != nil || claim.ExpectedRevision < 1 || testedAt.IsZero() {
		return coreaws.CredentialTest{}, coreaws.ErrInvalid
	}
	testedAt = testedAt.UTC().Truncate(time.Microsecond)
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return coreaws.CredentialTest{}, err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "core_aws:test_credential:"+claim.IdempotencyKey); err != nil {
		return coreaws.CredentialTest{}, err
	}
	digest := coreaws.CredentialTestBindingDigest(claim.CredentialID, claim.ExpectedRevision)
	var storedHash, state, storedClaimID, storedCredentialID string
	var storedExpected int64
	var replayRaw []byte
	if err = tx.QueryRow(ctx, `SELECT request_hash,state,claim_id::text,credential_id::text,expected_revision,response_json FROM core_aws_credential_test_claims WHERE idempotency_key=$1 FOR UPDATE`, claim.IdempotencyKey).Scan(&storedHash, &state, &storedClaimID, &storedCredentialID, &storedExpected, &replayRaw); err != nil {
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
	credential, err := s.scanCredentialRow(tx.QueryRow(ctx, `SELECT c.credential_id::text,c.name,r.region,r.secret_key_version,r.access_key_id_nonce,r.access_key_id_ciphertext,r.secret_access_key_nonce,r.secret_access_key_ciphertext,r.session_token_nonce,r.session_token_ciphertext,COALESCE(e.account_id,''),COALESCE(e.user_arn,''),CASE WHEN e.tested_at IS NULL THEN 0 ELSE r.revision END,r.revision,e.tested_at,r.created_at,COALESCE(e.tested_at,r.created_at) FROM core_aws_credentials c JOIN core_aws_credential_revisions r ON r.credential_id=c.credential_id LEFT JOIN core_aws_credential_revision_evidence e ON e.credential_id=r.credential_id AND e.revision=r.revision WHERE c.credential_id=$1 AND r.revision=$2 FOR UPDATE OF r`, claim.CredentialID, claim.ExpectedRevision))
	if err != nil {
		return coreaws.CredentialTest{}, err
	}
	_ = credential
	if _, err = tx.Exec(ctx, `INSERT INTO core_aws_credential_revision_evidence(credential_id,revision,account_id,user_arn,tested_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT (credential_id,revision) DO NOTHING`, claim.CredentialID, claim.ExpectedRevision, identity.AccountID, identity.UserARN, testedAt); err != nil {
		return coreaws.CredentialTest{}, err
	}
	var persistedAccountID, persistedUserARN string
	var persistedTestedAt time.Time
	if err = tx.QueryRow(ctx, `SELECT account_id,user_arn,tested_at FROM core_aws_credential_revision_evidence WHERE credential_id=$1 AND revision=$2`, claim.CredentialID, claim.ExpectedRevision).Scan(&persistedAccountID, &persistedUserARN, &persistedTestedAt); err != nil {
		return coreaws.CredentialTest{}, err
	}
	if persistedAccountID != identity.AccountID || persistedUserARN != identity.UserARN {
		return coreaws.CredentialTest{}, coreaws.ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE core_aws_credentials SET account_id=$2,user_arn=$3,verified_revision=$4,tested_at=$5,updated_at=GREATEST(updated_at,$5) WHERE credential_id=$1 AND revision=$4 AND disabled_at IS NULL`, claim.CredentialID, persistedAccountID, persistedUserARN, claim.ExpectedRevision, persistedTestedAt); err != nil {
		return coreaws.CredentialTest{}, err
	}
	identity.AccountID, identity.UserARN = persistedAccountID, persistedUserARN
	test := coreaws.CredentialTest{CredentialID: claim.CredentialID, Identity: identity, CredentialRevision: claim.ExpectedRevision, TestedAt: persistedTestedAt.UTC()}
	encoded, err := json.Marshal(test)
	if err != nil {
		return coreaws.CredentialTest{}, err
	}
	claimUpdate, err := tx.Exec(ctx, `UPDATE core_aws_credential_test_claims SET state='completed',response_json=$2,completed_at=$3,updated_at=$3 WHERE idempotency_key=$1 AND state='in_progress'`, claim.IdempotencyKey, encoded, testedAt)
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
	if s == nil || s.store == nil || s.store.pool == nil || uuid.Validate(claim.ClaimID) != nil || uuid.Validate(claim.IdempotencyKey) != nil || uuid.Validate(claim.CredentialID) != nil || claim.ExpectedRevision < 1 {
		return coreaws.ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "core_aws:test_credential:"+claim.IdempotencyKey); err != nil {
		return err
	}
	digest := coreaws.CredentialTestBindingDigest(claim.CredentialID, claim.ExpectedRevision)
	tag, err := tx.Exec(ctx, `UPDATE core_aws_credential_test_claims SET state='uncertain',error_code='UNCERTAIN',error_message='provider outcome requires reconciliation',updated_at=clock_timestamp() WHERE idempotency_key=$1 AND claim_id=$2 AND credential_id=$3 AND expected_revision=$4 AND request_hash=$5 AND state='in_progress'`, claim.IdempotencyKey, claim.ClaimID, claim.CredentialID, claim.ExpectedRevision, digest)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_aws_credential_test_claims WHERE idempotency_key=$1 AND claim_id=$2`, claim.IdempotencyKey, claim.ClaimID).Scan(&state); err != nil {
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
	if s == nil || s.store == nil || s.store.pool == nil || uuid.Validate(claim.ClaimID) != nil || uuid.Validate(claim.IdempotencyKey) != nil || uuid.Validate(claim.CredentialID) != nil || claim.ExpectedRevision < 1 {
		return coreaws.ErrInvalid
	}
	tx, err := s.store.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "core_aws:test_credential:"+claim.IdempotencyKey); err != nil {
		return err
	}
	digest := coreaws.CredentialTestBindingDigest(claim.CredentialID, claim.ExpectedRevision)
	tag, err := tx.Exec(ctx, `UPDATE core_aws_credential_test_claims SET state='failed',error_code='PROVIDER_FAILED',error_message='provider credential test failed',updated_at=clock_timestamp() WHERE idempotency_key=$1 AND claim_id=$2 AND credential_id=$3 AND expected_revision=$4 AND request_hash=$5 AND state='in_progress'`, claim.IdempotencyKey, claim.ClaimID, claim.CredentialID, claim.ExpectedRevision, digest)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM core_aws_credential_test_claims WHERE idempotency_key=$1 AND claim_id=$2`, claim.IdempotencyKey, claim.ClaimID).Scan(&state); err != nil {
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
func (s *CoreAWSStore) CreatePlan(ctx context.Context, p coreaws.Plan) (coreaws.Plan, error) {
	if p.Validate() != nil {
		return p, coreaws.ErrInvalid
	}
	pj, _ := json.Marshal(p.Parameters)
	tj, _ := json.Marshal(p.Tags)
	cj, _ := json.Marshal(p.Capabilities)
	_, e := s.store.pool.Exec(ctx, `INSERT INTO core_aws_plans(plan_id,credential_id,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`, p.ID, p.CredentialID, p.Region, p.StackName, p.Operation, p.Template, p.TemplateSHA256, pj, tj, cj, p.Revision, p.CreatedAt)
	return p, e
}
func (s *CoreAWSStore) GetPlan(ctx context.Context, id string) (coreaws.Plan, error) {
	var p coreaws.Plan
	var op string
	var pj, tj, cj []byte
	e := s.store.pool.QueryRow(ctx, `SELECT plan_id::text,credential_id::text,region,stack_name,operation,template,template_sha256,parameters_json,tags_json,capabilities_json,revision,created_at FROM core_aws_plans WHERE plan_id=$1`, id).Scan(&p.ID, &p.CredentialID, &p.Region, &p.StackName, &op, &p.Template, &p.TemplateSHA256, &pj, &tj, &cj, &p.Revision, &p.CreatedAt)
	if errors.Is(e, pgx.ErrNoRows) {
		return p, coreaws.ErrNotFound
	}
	if e != nil {
		return p, e
	}
	p.Operation = coreaws.Operation(op)
	_ = json.Unmarshal(pj, &p.Parameters)
	_ = json.Unmarshal(tj, &p.Tags)
	_ = json.Unmarshal(cj, &p.Capabilities)
	return p, nil
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
func (s *CoreAWSStore) CreateChange(ctx context.Context, c coreaws.Change) (coreaws.Change, error) {
	_, e := s.store.pool.Exec(ctx, `INSERT INTO core_aws_changes(change_id,plan_id,credential_id,task_id,confirmation_id,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`, c.ID, c.PlanID, c.CredentialID, c.TaskID, c.ConfirmationID, c.Operation, c.Status, c.Stage, c.ChangeSetID, c.ProviderRequestDigest, c.ProviderToken, c.Revision, c.ErrorCode, c.ErrorSummary, c.CreatedAt, c.UpdatedAt)
	return c, e
}
func (s *CoreAWSStore) GetChange(ctx context.Context, id string) (coreaws.Change, error) {
	return s.scanChange(s.store.pool.QueryRow(ctx, `SELECT change_id::text,plan_id::text,credential_id::text,task_id::text,confirmation_id::text,operation,status,stage,change_set_id,provider_request_digest,provider_token,revision,error_code,error_summary,created_at,updated_at FROM core_aws_changes WHERE change_id=$1`, id))
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
