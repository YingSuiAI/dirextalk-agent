package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coregithub"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const githubSecretField = "github_token"

const githubDispatchCleanupTimeout = 5 * time.Second

type CoreGitHubStore struct {
	store *Store
}

func NewCoreGitHubStore(store *Store) *CoreGitHubStore {
	return &CoreGitHubStore{store: store}
}

type githubRow struct {
	config            coregithub.Config
	accountGeneration int64
	credentialVersion int64
	keyVersion        uint32
	nonce             []byte
	ciphertext        []byte
}

type githubQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

const githubColumns = `account_generation,enabled,provider,github_token_configured,credential_version,github_token_key_version,github_token_nonce,github_token_ciphertext,revision,tested_at,updated_at`
const githubSelect = `SELECT ` + githubColumns + ` FROM core_github_configs WHERE owner_id=$1 AND account_generation=$2`

func (s *CoreGitHubStore) Get(ctx context.Context, ownerID string, accountGeneration int64) (coregithub.Config, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !coregithub.ValidIdentity(ownerID, accountGeneration) {
		return coregithub.Config{}, coregithub.ErrInvalid
	}
	if err := s.checkGitHubAdmission(ctx, ownerID, accountGeneration); err != nil {
		return coregithub.Config{}, err
	}
	row, err := scanGitHubRow(s.store.pool.QueryRow(ctx, githubSelect, ownerID, accountGeneration))
	if errors.Is(err, pgx.ErrNoRows) {
		return coregithub.DefaultConfig(), nil
	}
	if err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	return row.config, nil
}

func (s *CoreGitHubStore) Resolve(ctx context.Context, ownerID string, accountGeneration int64) (coregithub.ResolvedConfig, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !coregithub.ValidIdentity(ownerID, accountGeneration) {
		return coregithub.ResolvedConfig{}, coregithub.ErrInvalid
	}
	if err := s.checkGitHubAdmission(ctx, ownerID, accountGeneration); err != nil {
		return coregithub.ResolvedConfig{}, err
	}
	row, err := scanGitHubRow(s.store.pool.QueryRow(ctx, githubSelect, ownerID, accountGeneration))
	if errors.Is(err, pgx.ErrNoRows) {
		return coregithub.ResolvedConfig{}, coregithub.ErrNotConfigured
	}
	if err != nil {
		return coregithub.ResolvedConfig{}, coregithub.ErrRepository
	}
	resolved := coregithub.ResolvedConfig{Config: row.config, CredentialVersion: row.credentialVersion, OwnerID: ownerID, AccountGeneration: accountGeneration}
	if !row.config.GitHubTokenConfigured {
		return resolved, nil
	}
	if row.credentialVersion <= 0 || len(row.nonce) == 0 || len(row.ciphertext) == 0 {
		return coregithub.ResolvedConfig{}, coregithub.ErrRepository
	}
	plaintext, err := s.store.openDurableSecret(s.secretDomain(row.config.Provider), githubSecretRecordID(ownerID, accountGeneration), row.credentialVersion, githubSecretField, row.keyVersion, row.nonce, row.ciphertext)
	if err != nil {
		return coregithub.ResolvedConfig{}, coregithub.ErrRepository
	}
	resolved.GitHubToken = string(plaintext)
	clearBytes(plaintext)
	return resolved, nil
}

func (s *CoreGitHubStore) Update(ctx context.Context, mutation coregithub.Mutation, validateEnable func(string) error) (coregithub.Config, error) {
	mutation.OwnerID = strings.TrimSpace(mutation.OwnerID)
	if !coregithub.ValidIdentity(mutation.OwnerID, mutation.AccountGeneration) {
		return coregithub.Config{}, coregithub.ErrInvalid
	}
	key, err := uuid.Parse(mutation.IdempotencyKey)
	if err != nil || key == uuid.Nil || len(mutation.RequestDigest) != 64 {
		return coregithub.Config{}, coregithub.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	defer rollbackGitHubTx(tx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	if err := checkGitHubAdmissionTx(ctx, tx, mutation.OwnerID, mutation.AccountGeneration); err != nil {
		return coregithub.Config{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, githubIdentityLockKey(mutation.OwnerID, mutation.AccountGeneration)); err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	if err := checkGitHubAdmissionTx(ctx, tx, mutation.OwnerID, mutation.AccountGeneration); err != nil {
		return coregithub.Config{}, err
	}
	var storedDigest string
	var storedResponse []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,response_json FROM core_github_replays WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 FOR UPDATE`, mutation.OwnerID, mutation.AccountGeneration, key).Scan(&storedDigest, &storedResponse)
	if err == nil {
		if storedDigest != mutation.RequestDigest {
			return coregithub.Config{}, coregithub.ErrIdempotencyConflict
		}
		var replay coregithub.Config
		if json.Unmarshal(storedResponse, &replay) != nil {
			return coregithub.Config{}, coregithub.ErrRepository
		}
		if err := tx.Commit(ctx); err != nil {
			return coregithub.Config{}, coregithub.ErrRepository
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return coregithub.Config{}, coregithub.ErrRepository
	}

	current, err := scanGitHubRow(tx.QueryRow(ctx, githubSelect+` FOR UPDATE`, mutation.OwnerID, mutation.AccountGeneration))
	exists := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		current = githubRow{config: coregithub.DefaultConfig(), keyVersion: secretbox.KeyVersionMin}
	} else if err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	if current.config.Revision != mutation.ExpectedRevision {
		return coregithub.Config{}, coregithub.ErrRevisionConflict
	}
	provider := current.config.Provider
	if mutation.Provider != nil {
		provider = *mutation.Provider
	}
	if provider != coregithub.ProviderGitHub {
		return coregithub.Config{}, coregithub.ErrInvalid
	}
	enabled := current.config.Enabled
	if mutation.Enabled != nil {
		enabled = *mutation.Enabled
	}
	configured := current.config.GitHubTokenConfigured
	credentialVersion := current.credentialVersion
	keyVersion, nonce, ciphertext := current.keyVersion, current.nonce, current.ciphertext
	if mutation.GitHubToken != nil {
		credentialVersion++
		if credentialVersion <= 0 {
			credentialVersion = 1
		}
		plaintext := []byte(*mutation.GitHubToken)
		envelope, sealErr := s.store.sealDurableSecret(s.secretDomain(provider), githubSecretRecordID(mutation.OwnerID, mutation.AccountGeneration), credentialVersion, githubSecretField, plaintext)
		clearBytes(plaintext)
		if sealErr != nil {
			return coregithub.Config{}, coregithub.ErrRepository
		}
		keyVersion, nonce, ciphertext = envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext
		configured = true
	} else if mutation.GitHubTokenClear {
		if configured {
			credentialVersion++
		}
		keyVersion, nonce, ciphertext = secretbox.KeyVersionMin, nil, nil
		configured = false
	}
	if enabled && !configured {
		return coregithub.Config{}, coregithub.ErrNotConfigured
	}
	now := mutation.Now.UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return coregithub.Config{}, coregithub.ErrInvalid
	}
	testedAt := current.config.TestedAt
	if mutation.GitHubToken != nil || mutation.GitHubTokenClear {
		// A successful credential rotation or clear invalidates the previous
		// provider test, even when the public config revision is otherwise
		// unchanged by the caller.
		testedAt = nil
	}
	if enabled && (!current.config.Enabled || mutation.GitHubToken != nil) {
		if validateEnable == nil {
			return coregithub.Config{}, coregithub.ErrInvalid
		}
		proposedToken := mutation.GitHubToken
		var decrypted []byte
		if proposedToken == nil {
			if credentialVersion <= 0 || len(nonce) == 0 || len(ciphertext) == 0 {
				return coregithub.Config{}, coregithub.ErrNotConfigured
			}
			plaintext, openErr := s.store.openDurableSecret(s.secretDomain(provider), githubSecretRecordID(mutation.OwnerID, mutation.AccountGeneration), credentialVersion, githubSecretField, keyVersion, nonce, ciphertext)
			if openErr != nil {
				return coregithub.Config{}, coregithub.ErrRepository
			}
			decrypted = plaintext
			value := string(plaintext)
			proposedToken = &value
		}
		if decrypted != nil {
			defer clearBytes(decrypted)
		}
		if proposedToken == nil || strings.TrimSpace(*proposedToken) == "" {
			return coregithub.Config{}, coregithub.ErrNotConfigured
		}
		if validateErr := validateEnable(*proposedToken); validateErr != nil {
			return coregithub.Config{}, validateErr
		}
		testedAt = &now
	}
	next := coregithub.Config{Enabled: enabled, Provider: provider, GitHubTokenConfigured: configured, Revision: current.config.Revision + 1, TestedAt: testedAt, UpdatedAt: &now}
	if !exists {
		_, err = tx.Exec(ctx, `INSERT INTO core_github_configs(owner_id,account_generation,enabled,provider,github_token_configured,credential_version,github_token_key_version,github_token_nonce,github_token_ciphertext,revision,tested_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`, mutation.OwnerID, mutation.AccountGeneration, enabled, provider, configured, credentialVersion, keyVersion, nonce, ciphertext, next.Revision, next.TestedAt, now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE core_github_configs SET enabled=$3,provider=$4,github_token_configured=$5,credential_version=$6,github_token_key_version=$7,github_token_nonce=$8,github_token_ciphertext=$9,revision=$10,tested_at=$11,updated_at=$12 WHERE owner_id=$1 AND account_generation=$2 AND revision=$13`, mutation.OwnerID, mutation.AccountGeneration, enabled, provider, configured, credentialVersion, keyVersion, nonce, ciphertext, next.Revision, next.TestedAt, now, mutation.ExpectedRevision)
	}
	if err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	response, err := json.Marshal(next)
	if err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core_github_replays(owner_id,account_generation,idempotency_key,request_digest,response_json,created_at) VALUES($1,$2,$3,$4,$5,$6)`, mutation.OwnerID, mutation.AccountGeneration, key, mutation.RequestDigest, response, now); err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	if err := tx.Commit(ctx); err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	return next, nil
}

func (s *CoreGitHubStore) MarkTested(ctx context.Context, ownerID string, accountGeneration, expectedRevision int64, testedAt time.Time) (coregithub.Config, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !coregithub.ValidIdentity(ownerID, accountGeneration) {
		return coregithub.Config{}, coregithub.ErrInvalid
	}
	if err := s.checkGitHubAdmission(ctx, ownerID, accountGeneration); err != nil {
		return coregithub.Config{}, err
	}
	testedAt = testedAt.UTC().Truncate(time.Microsecond)
	row, err := scanGitHubRow(s.store.pool.QueryRow(ctx, `UPDATE core_github_configs SET tested_at=$4 WHERE owner_id=$1 AND account_generation=$2 AND revision=$3 RETURNING `+githubColumns, ownerID, accountGeneration, expectedRevision, testedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return coregithub.Config{}, coregithub.ErrRevisionConflict
	}
	if err != nil {
		return coregithub.Config{}, coregithub.ErrRepository
	}
	return row.config, nil
}

// ResolveForDispatch acquires the same lock order as Update and
// CoreDeprovisionStore: the global account-deprovision guard first, then the
// Web Search identity lock. The returned release function rolls back/ends the
// read-only transaction only after the bounded provider request, so
// deprovision cannot commit between the final config check and outbound
// dispatch.
func (s *CoreGitHubStore) ResolveForDispatch(ctx context.Context, ownerID string, accountGeneration int64, snapshot coregithub.ResolvedConfig) (coregithub.ResolvedConfig, func() error, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !coregithub.ValidIdentity(ownerID, accountGeneration) {
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrRepository
	}
	rollback := func() { rollbackGitHubTx(tx) }
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		rollback()
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrRepository
	}
	if err := checkGitHubAdmissionTx(ctx, tx, ownerID, accountGeneration); err != nil {
		rollback()
		return coregithub.ResolvedConfig{}, nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, githubIdentityLockKey(ownerID, accountGeneration)); err != nil {
		rollback()
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrRepository
	}
	if err := checkGitHubAdmissionTx(ctx, tx, ownerID, accountGeneration); err != nil {
		rollback()
		return coregithub.ResolvedConfig{}, nil, err
	}
	row, err := scanGitHubRow(tx.QueryRow(ctx, githubSelect+` FOR UPDATE`, ownerID, accountGeneration))
	if errors.Is(err, pgx.ErrNoRows) {
		rollback()
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrNotConfigured
	}
	if err != nil {
		rollback()
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrRepository
	}
	if !row.config.GitHubTokenConfigured || row.credentialVersion <= 0 || len(row.nonce) == 0 || len(row.ciphertext) == 0 {
		rollback()
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrNotConfigured
	}
	current := coregithub.ResolvedConfig{Config: row.config, CredentialVersion: row.credentialVersion, OwnerID: ownerID, AccountGeneration: accountGeneration}
	if current.Revision != snapshot.Revision || current.CredentialVersion != snapshot.CredentialVersion || current.Provider != snapshot.Provider || !current.GitHubTokenConfigured || snapshot.OwnerID != ownerID || snapshot.AccountGeneration != accountGeneration {
		rollback()
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrRevisionConflict
	}
	if !current.Enabled {
		rollback()
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrDisabled
	}
	plaintext, err := s.store.openDurableSecret(s.secretDomain(row.config.Provider), githubSecretRecordID(ownerID, accountGeneration), row.credentialVersion, githubSecretField, row.keyVersion, row.nonce, row.ciphertext)
	if err != nil {
		rollback()
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrRepository
	}
	current.GitHubToken = string(plaintext)
	clearBytes(plaintext)
	if strings.TrimSpace(current.GitHubToken) == "" {
		rollback()
		return coregithub.ResolvedConfig{}, nil, coregithub.ErrNotConfigured
	}
	released := false
	release := func() error {
		if released {
			return nil
		}
		released = true
		cleanupCtx, cancel := context.WithTimeout(context.Background(), githubDispatchCleanupTimeout)
		defer cancel()
		if err := tx.Rollback(cleanupCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			return coregithub.ErrRepository
		}
		return nil
	}
	return current, release, nil
}

func rollbackGitHubTx(tx pgx.Tx) {
	if tx == nil {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), githubDispatchCleanupTimeout)
	defer cancel()
	_ = tx.Rollback(cleanupCtx)
}

func (s *CoreGitHubStore) secretDomain(provider coregithub.Provider) string {
	return fmt.Sprintf("core_github_configs/%s/%s", s.store.instanceID.String(), strings.ToLower(string(provider)))
}

// checkGitHubAdmission is the durable generation/deprovision fence. The
// deprovision receipt survives the broad Agent-row purge, so a stale tool
// cannot resurrect or dispatch through a generation whose account teardown
// has begun even if the configuration row has not been truncated yet.
func (s *CoreGitHubStore) checkGitHubAdmission(ctx context.Context, ownerID string, accountGeneration int64) error {
	var fenced bool
	if err := s.store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_account_deprovisions WHERE owner_id=$1 AND account_generation=$2)`, ownerID, accountGeneration).Scan(&fenced); err != nil {
		return coregithub.ErrRepository
	}
	if fenced {
		return coregithub.ErrNotConfigured
	}
	return nil
}

func checkGitHubAdmissionTx(ctx context.Context, tx pgx.Tx, ownerID string, accountGeneration int64) error {
	var fenced bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_account_deprovisions WHERE owner_id=$1 AND account_generation=$2)`, ownerID, accountGeneration).Scan(&fenced); err != nil {
		return coregithub.ErrRepository
	}
	if fenced {
		return coregithub.ErrNotConfigured
	}
	return nil
}

func githubSecretRecordID(ownerID string, accountGeneration int64) string {
	// The owner generation is immutable for the lifetime of this record. The
	// credential version is bound separately by the durable-secret envelope;
	// configuration revision is intentionally excluded so an enable/disable or
	// other metadata change cannot make the existing ciphertext undecryptable.
	return "owner=" + strconv.Itoa(len(ownerID)) + ":" + ownerID + ";generation=" + strconv.FormatInt(accountGeneration, 10)
}

func githubIdentityLockKey(ownerID string, accountGeneration int64) string {
	return "github:owner=" + strconv.Itoa(len(ownerID)) + ":" + ownerID + ";generation=" + strconv.FormatInt(accountGeneration, 10)
}

func scanGitHubRow(row pgx.Row) (githubRow, error) {
	var value githubRow
	var provider string
	var testedAt, updatedAt *time.Time
	err := row.Scan(&value.accountGeneration, &value.config.Enabled, &provider, &value.config.GitHubTokenConfigured, &value.credentialVersion, &value.keyVersion, &value.nonce, &value.ciphertext, &value.config.Revision, &testedAt, &updatedAt)
	if err != nil {
		return githubRow{}, err
	}
	value.config.Provider = coregithub.Provider(strings.ToLower(strings.TrimSpace(provider)))
	if value.accountGeneration <= 0 || value.config.Provider != coregithub.ProviderGitHub || value.config.Revision <= 0 || value.credentialVersion < 0 {
		return githubRow{}, coregithub.ErrRepository
	}
	if testedAt != nil {
		v := testedAt.UTC()
		value.config.TestedAt = &v
	}
	if updatedAt != nil {
		v := updatedAt.UTC()
		value.config.UpdatedAt = &v
	}
	return value, nil
}
