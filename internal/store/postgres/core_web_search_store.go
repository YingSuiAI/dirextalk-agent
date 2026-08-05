package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/corewebsearch"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const webSearchSecretField = "api_key"

const webSearchDispatchCleanupTimeout = 5 * time.Second

type CoreWebSearchStore struct {
	store *Store
}

func NewCoreWebSearchStore(store *Store) *CoreWebSearchStore {
	return &CoreWebSearchStore{store: store}
}

type webSearchRow struct {
	config            corewebsearch.Config
	accountGeneration int64
	credentialVersion int64
	keyVersion        uint32
	nonce             []byte
	ciphertext        []byte
}

type webSearchQuery interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

const webSearchColumns = `account_generation,enabled,provider,api_key_configured,credential_version,api_key_key_version,api_key_nonce,api_key_ciphertext,revision,tested_at,updated_at`
const webSearchSelect = `SELECT ` + webSearchColumns + ` FROM core_web_search_configs WHERE owner_id=$1 AND account_generation=$2`

func (s *CoreWebSearchStore) Get(ctx context.Context, ownerID string, accountGeneration int64) (corewebsearch.Config, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !corewebsearch.ValidIdentity(ownerID, accountGeneration) {
		return corewebsearch.Config{}, corewebsearch.ErrInvalid
	}
	if err := s.checkWebSearchAdmission(ctx, ownerID, accountGeneration); err != nil {
		return corewebsearch.Config{}, err
	}
	row, err := scanWebSearchRow(s.store.pool.QueryRow(ctx, webSearchSelect, ownerID, accountGeneration))
	if errors.Is(err, pgx.ErrNoRows) {
		return corewebsearch.DefaultConfig(), nil
	}
	if err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	return row.config, nil
}

func (s *CoreWebSearchStore) Resolve(ctx context.Context, ownerID string, accountGeneration int64) (corewebsearch.ResolvedConfig, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !corewebsearch.ValidIdentity(ownerID, accountGeneration) {
		return corewebsearch.ResolvedConfig{}, corewebsearch.ErrInvalid
	}
	if err := s.checkWebSearchAdmission(ctx, ownerID, accountGeneration); err != nil {
		return corewebsearch.ResolvedConfig{}, err
	}
	row, err := scanWebSearchRow(s.store.pool.QueryRow(ctx, webSearchSelect, ownerID, accountGeneration))
	if errors.Is(err, pgx.ErrNoRows) {
		return corewebsearch.ResolvedConfig{}, corewebsearch.ErrNotConfigured
	}
	if err != nil {
		return corewebsearch.ResolvedConfig{}, corewebsearch.ErrRepository
	}
	resolved := corewebsearch.ResolvedConfig{Config: row.config, CredentialVersion: row.credentialVersion, OwnerID: ownerID, AccountGeneration: accountGeneration}
	if !row.config.APIKeyConfigured {
		return resolved, nil
	}
	if row.credentialVersion <= 0 || len(row.nonce) == 0 || len(row.ciphertext) == 0 {
		return corewebsearch.ResolvedConfig{}, corewebsearch.ErrRepository
	}
	plaintext, err := s.store.openDurableSecret(s.secretDomain(row.config.Provider), webSearchSecretRecordID(ownerID, accountGeneration), row.credentialVersion, webSearchSecretField, row.keyVersion, row.nonce, row.ciphertext)
	if err != nil {
		return corewebsearch.ResolvedConfig{}, corewebsearch.ErrRepository
	}
	resolved.APIKey = string(plaintext)
	clearBytes(plaintext)
	return resolved, nil
}

func (s *CoreWebSearchStore) Update(ctx context.Context, mutation corewebsearch.Mutation) (corewebsearch.Config, error) {
	mutation.OwnerID = strings.TrimSpace(mutation.OwnerID)
	if !corewebsearch.ValidIdentity(mutation.OwnerID, mutation.AccountGeneration) {
		return corewebsearch.Config{}, corewebsearch.ErrInvalid
	}
	key, err := uuid.Parse(mutation.IdempotencyKey)
	if err != nil || key == uuid.Nil || len(mutation.RequestDigest) != 64 {
		return corewebsearch.Config{}, corewebsearch.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	defer rollbackWebSearchTx(tx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	if err := checkWebSearchAdmissionTx(ctx, tx, mutation.OwnerID, mutation.AccountGeneration); err != nil {
		return corewebsearch.Config{}, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, webSearchIdentityLockKey(mutation.OwnerID, mutation.AccountGeneration)); err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	if err := checkWebSearchAdmissionTx(ctx, tx, mutation.OwnerID, mutation.AccountGeneration); err != nil {
		return corewebsearch.Config{}, err
	}
	var storedDigest string
	var storedResponse []byte
	err = tx.QueryRow(ctx, `SELECT request_digest,response_json FROM core_web_search_replays WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3 FOR UPDATE`, mutation.OwnerID, mutation.AccountGeneration, key).Scan(&storedDigest, &storedResponse)
	if err == nil {
		if storedDigest != mutation.RequestDigest {
			return corewebsearch.Config{}, corewebsearch.ErrIdempotencyConflict
		}
		var replay corewebsearch.Config
		if json.Unmarshal(storedResponse, &replay) != nil {
			return corewebsearch.Config{}, corewebsearch.ErrRepository
		}
		if err := tx.Commit(ctx); err != nil {
			return corewebsearch.Config{}, corewebsearch.ErrRepository
		}
		return replay, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}

	current, err := scanWebSearchRow(tx.QueryRow(ctx, webSearchSelect+` FOR UPDATE`, mutation.OwnerID, mutation.AccountGeneration))
	exists := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		current = webSearchRow{config: corewebsearch.DefaultConfig(), keyVersion: secretbox.KeyVersionMin}
	} else if err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	if current.config.Revision != mutation.ExpectedRevision {
		return corewebsearch.Config{}, corewebsearch.ErrRevisionConflict
	}
	provider := current.config.Provider
	if mutation.Provider != nil {
		provider = *mutation.Provider
	}
	if provider != corewebsearch.ProviderTavily {
		return corewebsearch.Config{}, corewebsearch.ErrInvalid
	}
	enabled := current.config.Enabled
	if mutation.Enabled != nil {
		enabled = *mutation.Enabled
	}
	configured := current.config.APIKeyConfigured
	credentialVersion := current.credentialVersion
	keyVersion, nonce, ciphertext := current.keyVersion, current.nonce, current.ciphertext
	if mutation.APIKey != nil {
		credentialVersion++
		if credentialVersion <= 0 {
			credentialVersion = 1
		}
		plaintext := []byte(*mutation.APIKey)
		envelope, sealErr := s.store.sealDurableSecret(s.secretDomain(provider), webSearchSecretRecordID(mutation.OwnerID, mutation.AccountGeneration), credentialVersion, webSearchSecretField, plaintext)
		clearBytes(plaintext)
		if sealErr != nil {
			return corewebsearch.Config{}, corewebsearch.ErrRepository
		}
		keyVersion, nonce, ciphertext = envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext
		configured = true
	} else if mutation.APIKeyClear {
		if configured {
			credentialVersion++
		}
		keyVersion, nonce, ciphertext = secretbox.KeyVersionMin, nil, nil
		configured = false
	}
	if enabled && !configured {
		return corewebsearch.Config{}, corewebsearch.ErrNotConfigured
	}
	now := mutation.Now.UTC().Truncate(time.Microsecond)
	if now.IsZero() {
		return corewebsearch.Config{}, corewebsearch.ErrInvalid
	}
	testedAt := current.config.TestedAt
	if mutation.APIKey != nil || mutation.APIKeyClear {
		// A successful credential rotation or clear invalidates the previous
		// provider test, even when the public config revision is otherwise
		// unchanged by the caller.
		testedAt = nil
	}
	next := corewebsearch.Config{Enabled: enabled, Provider: provider, APIKeyConfigured: configured, Revision: current.config.Revision + 1, TestedAt: testedAt, UpdatedAt: &now}
	if !exists {
		_, err = tx.Exec(ctx, `INSERT INTO core_web_search_configs(owner_id,account_generation,enabled,provider,api_key_configured,credential_version,api_key_key_version,api_key_nonce,api_key_ciphertext,revision,tested_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$12)`, mutation.OwnerID, mutation.AccountGeneration, enabled, provider, configured, credentialVersion, keyVersion, nonce, ciphertext, next.Revision, next.TestedAt, now)
	} else {
		_, err = tx.Exec(ctx, `UPDATE core_web_search_configs SET enabled=$3,provider=$4,api_key_configured=$5,credential_version=$6,api_key_key_version=$7,api_key_nonce=$8,api_key_ciphertext=$9,revision=$10,tested_at=$11,updated_at=$12 WHERE owner_id=$1 AND account_generation=$2 AND revision=$13`, mutation.OwnerID, mutation.AccountGeneration, enabled, provider, configured, credentialVersion, keyVersion, nonce, ciphertext, next.Revision, next.TestedAt, now, mutation.ExpectedRevision)
	}
	if err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	response, err := json.Marshal(next)
	if err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core_web_search_replays(owner_id,account_generation,idempotency_key,request_digest,response_json,created_at) VALUES($1,$2,$3,$4,$5,$6)`, mutation.OwnerID, mutation.AccountGeneration, key, mutation.RequestDigest, response, now); err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	if err := tx.Commit(ctx); err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	return next, nil
}

func (s *CoreWebSearchStore) MarkTested(ctx context.Context, ownerID string, accountGeneration, expectedRevision int64, testedAt time.Time) (corewebsearch.Config, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !corewebsearch.ValidIdentity(ownerID, accountGeneration) {
		return corewebsearch.Config{}, corewebsearch.ErrInvalid
	}
	if err := s.checkWebSearchAdmission(ctx, ownerID, accountGeneration); err != nil {
		return corewebsearch.Config{}, err
	}
	testedAt = testedAt.UTC().Truncate(time.Microsecond)
	row, err := scanWebSearchRow(s.store.pool.QueryRow(ctx, `UPDATE core_web_search_configs SET tested_at=$4 WHERE owner_id=$1 AND account_generation=$2 AND revision=$3 RETURNING `+webSearchColumns, ownerID, accountGeneration, expectedRevision, testedAt))
	if errors.Is(err, pgx.ErrNoRows) {
		return corewebsearch.Config{}, corewebsearch.ErrRevisionConflict
	}
	if err != nil {
		return corewebsearch.Config{}, corewebsearch.ErrRepository
	}
	return row.config, nil
}

// ResolveForDispatch acquires the same lock order as Update and
// CoreDeprovisionStore: the global account-deprovision guard first, then the
// Web Search identity lock. The returned release function rolls back/ends the
// read-only transaction only after the bounded provider request, so
// deprovision cannot commit between the final config check and outbound
// dispatch.
func (s *CoreWebSearchStore) ResolveForDispatch(ctx context.Context, ownerID string, accountGeneration int64, snapshot corewebsearch.ResolvedConfig) (corewebsearch.ResolvedConfig, func() error, error) {
	ownerID = strings.TrimSpace(ownerID)
	if !corewebsearch.ValidIdentity(ownerID, accountGeneration) {
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrInvalid
	}
	tx, err := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrRepository
	}
	rollback := func() { rollbackWebSearchTx(tx) }
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock_shared(hashtextextended($1,0))`, deprovisionAdvisoryLockName); err != nil {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrRepository
	}
	if err := checkWebSearchAdmissionTx(ctx, tx, ownerID, accountGeneration); err != nil {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, webSearchIdentityLockKey(ownerID, accountGeneration)); err != nil {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrRepository
	}
	if err := checkWebSearchAdmissionTx(ctx, tx, ownerID, accountGeneration); err != nil {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, err
	}
	row, err := scanWebSearchRow(tx.QueryRow(ctx, webSearchSelect+` FOR UPDATE`, ownerID, accountGeneration))
	if errors.Is(err, pgx.ErrNoRows) {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrNotConfigured
	}
	if err != nil {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrRepository
	}
	if !row.config.APIKeyConfigured || row.credentialVersion <= 0 || len(row.nonce) == 0 || len(row.ciphertext) == 0 {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrNotConfigured
	}
	current := corewebsearch.ResolvedConfig{Config: row.config, CredentialVersion: row.credentialVersion, OwnerID: ownerID, AccountGeneration: accountGeneration}
	if current.Revision != snapshot.Revision || current.CredentialVersion != snapshot.CredentialVersion || current.Provider != snapshot.Provider || !current.APIKeyConfigured || snapshot.OwnerID != ownerID || snapshot.AccountGeneration != accountGeneration {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrRevisionConflict
	}
	if !current.Enabled {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrDisabled
	}
	plaintext, err := s.store.openDurableSecret(s.secretDomain(row.config.Provider), webSearchSecretRecordID(ownerID, accountGeneration), row.credentialVersion, webSearchSecretField, row.keyVersion, row.nonce, row.ciphertext)
	if err != nil {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrRepository
	}
	current.APIKey = string(plaintext)
	clearBytes(plaintext)
	if strings.TrimSpace(current.APIKey) == "" {
		rollback()
		return corewebsearch.ResolvedConfig{}, nil, corewebsearch.ErrNotConfigured
	}
	released := false
	release := func() error {
		if released {
			return nil
		}
		released = true
		cleanupCtx, cancel := context.WithTimeout(context.Background(), webSearchDispatchCleanupTimeout)
		defer cancel()
		if err := tx.Rollback(cleanupCtx); err != nil && !errors.Is(err, pgx.ErrTxClosed) {
			return corewebsearch.ErrRepository
		}
		return nil
	}
	return current, release, nil
}

func rollbackWebSearchTx(tx pgx.Tx) {
	if tx == nil {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), webSearchDispatchCleanupTimeout)
	defer cancel()
	_ = tx.Rollback(cleanupCtx)
}

func (s *CoreWebSearchStore) secretDomain(provider corewebsearch.Provider) string {
	return fmt.Sprintf("core_web_search_configs/%s/%s", s.store.instanceID.String(), strings.ToLower(string(provider)))
}

// checkWebSearchAdmission is the durable generation/deprovision fence. The
// deprovision receipt survives the broad Agent-row purge, so a stale tool
// cannot resurrect or dispatch through a generation whose account teardown
// has begun even if the configuration row has not been truncated yet.
func (s *CoreWebSearchStore) checkWebSearchAdmission(ctx context.Context, ownerID string, accountGeneration int64) error {
	var fenced bool
	if err := s.store.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_account_deprovisions WHERE owner_id=$1 AND account_generation=$2)`, ownerID, accountGeneration).Scan(&fenced); err != nil {
		return corewebsearch.ErrRepository
	}
	if fenced {
		return corewebsearch.ErrNotConfigured
	}
	return nil
}

func checkWebSearchAdmissionTx(ctx context.Context, tx pgx.Tx, ownerID string, accountGeneration int64) error {
	var fenced bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agent_account_deprovisions WHERE owner_id=$1 AND account_generation=$2)`, ownerID, accountGeneration).Scan(&fenced); err != nil {
		return corewebsearch.ErrRepository
	}
	if fenced {
		return corewebsearch.ErrNotConfigured
	}
	return nil
}

func webSearchSecretRecordID(ownerID string, accountGeneration int64) string {
	return "owner=" + strconv.Itoa(len(ownerID)) + ":" + ownerID + ";generation=" + strconv.FormatInt(accountGeneration, 10)
}

func webSearchIdentityLockKey(ownerID string, accountGeneration int64) string {
	return "web-search:" + webSearchSecretRecordID(ownerID, accountGeneration)
}

func scanWebSearchRow(row pgx.Row) (webSearchRow, error) {
	var value webSearchRow
	var provider string
	var testedAt, updatedAt *time.Time
	err := row.Scan(&value.accountGeneration, &value.config.Enabled, &provider, &value.config.APIKeyConfigured, &value.credentialVersion, &value.keyVersion, &value.nonce, &value.ciphertext, &value.config.Revision, &testedAt, &updatedAt)
	if err != nil {
		return webSearchRow{}, err
	}
	value.config.Provider = corewebsearch.Provider(strings.ToLower(strings.TrimSpace(provider)))
	if value.accountGeneration <= 0 || value.config.Provider != corewebsearch.ProviderTavily || value.config.Revision <= 0 || value.credentialVersion < 0 {
		return webSearchRow{}, corewebsearch.ErrRepository
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
