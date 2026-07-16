package awsfoundation

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
)

const (
	MasterKeyFileEnv           = "AGENT_MASTER_KEY_FILE"
	sourceCredentialEnvelopeV1 = "dirextalk.agent.aws-source-credential/aes256gcm/v1"
	maxMasterKeyFileSize       = 256
	maxAdminAuthorizationAge   = 10 * time.Minute
)

var (
	ErrMasterKey                  = errors.New("invalid Agent master key")
	ErrCredentialEnvelope         = errors.New("invalid encrypted source credential")
	ErrCredentialNotFound         = errors.New("encrypted source credential not found")
	ErrCredentialRevisionConflict = errors.New("encrypted source credential revision conflict")
	ErrAdminAuthorizationRequired = errors.New("fresh admin bootstrap authorization required")
)

type SourceCredentialBinding struct {
	AgentInstanceID string
	AccountID       string
	Region          string
}

type AdminAuthorization struct {
	SessionID  string
	AccountID  string
	Region     string
	VerifiedAt time.Time
	ExpiresAt  time.Time
}

type EncryptedSourceCredential struct {
	SchemaVersion   string    `json:"schema_version"`
	AgentInstanceID string    `json:"agent_instance_id"`
	AccountID       string    `json:"account_id"`
	Region          string    `json:"region"`
	OperationID     string    `json:"operation_id"`
	Generation      uint64    `json:"generation"`
	CreatedAt       time.Time `json:"created_at"`
	Nonce           []byte    `json:"nonce"`
	Ciphertext      []byte    `json:"ciphertext"`
}

type CredentialStore interface {
	Get(context.Context, string) (EncryptedSourceCredential, error)
	PutCAS(context.Context, string, uint64, EncryptedSourceCredential) error
	DeleteCAS(context.Context, string, uint64) error
}

type CredentialVault struct {
	store     CredentialStore
	masterKey []byte
	random    io.Reader
	now       func() time.Time
}

func NewCredentialVault(store CredentialStore, masterKey []byte, random io.Reader, now func() time.Time) (*CredentialVault, error) {
	if store == nil || len(masterKey) != 32 || random == nil || now == nil {
		return nil, ErrMasterKey
	}
	keyCopy := append([]byte(nil), masterKey...)
	return &CredentialVault{store: store, masterKey: keyCopy, random: random, now: now}, nil
}

func (vault *CredentialVault) Close() {
	if vault == nil {
		return
	}
	zeroBytes(vault.masterKey)
	vault.masterKey = nil
}

func (vault *CredentialVault) SealAndStore(ctx context.Context, binding SourceCredentialBinding, expectedGeneration uint64, authorization AdminAuthorization, credentials awsprovider.SourceCredentials) (EncryptedSourceCredential, error) {
	now := vault.now()
	if err := validateBinding(binding); err != nil || !validAuthorization(binding, authorization, now) {
		return EncryptedSourceCredential{}, ErrAdminAuthorizationRequired
	}
	record, err := sealSourceCredential(vault.masterKey, binding, authorization.SessionID, expectedGeneration+1, now.UTC(), credentials, vault.random)
	if err != nil {
		return EncryptedSourceCredential{}, err
	}
	if err := vault.store.PutCAS(ctx, binding.AgentInstanceID, expectedGeneration, record); err != nil {
		zeroBytes(record.Nonce)
		zeroBytes(record.Ciphertext)
		if errors.Is(err, ErrCredentialRevisionConflict) {
			return EncryptedSourceCredential{}, ErrCredentialRevisionConflict
		}
		return EncryptedSourceCredential{}, ErrCredentialEnvelope
	}
	return cloneEncryptedCredential(record), nil
}

// ResumeExistingGeneration accepts only the exact generation written by the
// same persisted bootstrap operation. It authenticates the envelope before a
// caller skips another IAM access-key rotation.
func (vault *CredentialVault) ResumeExistingGeneration(ctx context.Context, binding SourceCredentialBinding, expectedGeneration uint64, operationID string) (EncryptedSourceCredential, error) {
	if err := validateBinding(binding); err != nil || !idPattern.MatchString(operationID) || expectedGeneration == ^uint64(0) {
		return EncryptedSourceCredential{}, ErrCredentialRevisionConflict
	}
	record, err := vault.store.Get(ctx, binding.AgentInstanceID)
	if err != nil || record.AgentInstanceID != binding.AgentInstanceID || record.AccountID != binding.AccountID || record.Region != binding.Region || record.Generation != expectedGeneration+1 || record.OperationID != operationID {
		return EncryptedSourceCredential{}, ErrCredentialRevisionConflict
	}
	opened, err := openSourceCredential(vault.masterKey, binding, record)
	if err != nil {
		return EncryptedSourceCredential{}, err
	}
	opened.Wipe()
	return cloneEncryptedCredential(record), nil
}

// CheckGeneration is a read-before-mutate guard for IAM access-key rotation.
// Bootstrapper additionally serializes rotations in the single control
// process; the final store write remains compare-and-swap protected.
func (vault *CredentialVault) CheckGeneration(ctx context.Context, binding SourceCredentialBinding, expectedGeneration uint64) error {
	if err := validateBinding(binding); err != nil {
		return ErrCredentialEnvelope
	}
	record, err := vault.store.Get(ctx, binding.AgentInstanceID)
	if expectedGeneration == 0 && errors.Is(err, ErrCredentialNotFound) {
		return nil
	}
	if err != nil {
		return ErrCredentialEnvelope
	}
	if record.AgentInstanceID != binding.AgentInstanceID || record.AccountID != binding.AccountID || record.Region != binding.Region || record.Generation != expectedGeneration {
		return ErrCredentialRevisionConflict
	}
	return nil
}

func (vault *CredentialVault) Open(ctx context.Context, binding SourceCredentialBinding) (awsprovider.SourceCredentials, error) {
	if err := validateBinding(binding); err != nil {
		return awsprovider.SourceCredentials{}, ErrCredentialEnvelope
	}
	record, err := vault.store.Get(ctx, binding.AgentInstanceID)
	if err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			return awsprovider.SourceCredentials{}, ErrCredentialNotFound
		}
		return awsprovider.SourceCredentials{}, ErrCredentialEnvelope
	}
	return openSourceCredential(vault.masterKey, binding, record)
}

func (vault *CredentialVault) Delete(ctx context.Context, binding SourceCredentialBinding, expectedGeneration uint64, authorization AdminAuthorization) error {
	if err := validateBinding(binding); err != nil || !validAuthorization(binding, authorization, vault.now()) {
		return ErrAdminAuthorizationRequired
	}
	if err := vault.store.DeleteCAS(ctx, binding.AgentInstanceID, expectedGeneration); err != nil {
		if errors.Is(err, ErrCredentialRevisionConflict) || errors.Is(err, ErrCredentialNotFound) {
			return err
		}
		return ErrCredentialEnvelope
	}
	return nil
}

func validAuthorization(binding SourceCredentialBinding, authorization AdminAuthorization, now time.Time) bool {
	return idPattern.MatchString(authorization.SessionID) && authorization.AccountID == binding.AccountID && authorization.Region == binding.Region &&
		!authorization.VerifiedAt.IsZero() && !authorization.ExpiresAt.IsZero() && !authorization.VerifiedAt.After(now) && now.Before(authorization.ExpiresAt) &&
		authorization.ExpiresAt.Sub(authorization.VerifiedAt) <= maxAdminAuthorizationAge
}

func validateBinding(binding SourceCredentialBinding) error {
	if !idPattern.MatchString(binding.AgentInstanceID) || !accountPattern.MatchString(binding.AccountID) || !regionPattern.MatchString(binding.Region) {
		return ErrCredentialEnvelope
	}
	return nil
}

func sealSourceCredential(masterKey []byte, binding SourceCredentialBinding, operationID string, generation uint64, createdAt time.Time, credentials awsprovider.SourceCredentials, random io.Reader) (EncryptedSourceCredential, error) {
	if len(masterKey) != 32 || !idPattern.MatchString(operationID) || generation == 0 || createdAt.IsZero() || random == nil || len(credentials.AccessKeyID) == 0 || len(credentials.SecretAccessKey) == 0 || len(credentials.AccessKeyID) > 128 || len(credentials.SecretAccessKey) > 256 {
		return EncryptedSourceCredential{}, ErrCredentialEnvelope
	}
	plaintext := make([]byte, 4+len(credentials.AccessKeyID)+len(credentials.SecretAccessKey))
	binary.BigEndian.PutUint16(plaintext[0:2], uint16(len(credentials.AccessKeyID)))
	copy(plaintext[2:], credentials.AccessKeyID)
	offset := 2 + len(credentials.AccessKeyID)
	binary.BigEndian.PutUint16(plaintext[offset:offset+2], uint16(len(credentials.SecretAccessKey)))
	copy(plaintext[offset+2:], credentials.SecretAccessKey)
	defer zeroBytes(plaintext)

	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return EncryptedSourceCredential{}, ErrCredentialEnvelope
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return EncryptedSourceCredential{}, ErrCredentialEnvelope
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(random, nonce); err != nil {
		return EncryptedSourceCredential{}, ErrCredentialEnvelope
	}
	// PostgreSQL timestamptz persists microsecond precision. Normalize before
	// authenticating metadata so a durable round-trip cannot invalidate AAD.
	record := EncryptedSourceCredential{SchemaVersion: sourceCredentialEnvelopeV1, AgentInstanceID: binding.AgentInstanceID, AccountID: binding.AccountID, Region: binding.Region, OperationID: operationID, Generation: generation, CreatedAt: createdAt.UTC().Truncate(time.Microsecond), Nonce: nonce}
	record.Ciphertext = gcm.Seal(nil, nonce, plaintext, credentialAAD(record))
	return record, nil
}

func openSourceCredential(masterKey []byte, binding SourceCredentialBinding, record EncryptedSourceCredential) (awsprovider.SourceCredentials, error) {
	if len(masterKey) != 32 || record.SchemaVersion != sourceCredentialEnvelopeV1 || record.AgentInstanceID != binding.AgentInstanceID || record.AccountID != binding.AccountID || record.Region != binding.Region || !idPattern.MatchString(record.OperationID) || record.Generation == 0 || record.CreatedAt.IsZero() {
		return awsprovider.SourceCredentials{}, ErrCredentialEnvelope
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return awsprovider.SourceCredentials{}, ErrCredentialEnvelope
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(record.Nonce) != gcm.NonceSize() || len(record.Ciphertext) <= gcm.Overhead()+4 {
		return awsprovider.SourceCredentials{}, ErrCredentialEnvelope
	}
	plaintext, err := gcm.Open(nil, record.Nonce, record.Ciphertext, credentialAAD(record))
	if err != nil {
		zeroBytes(plaintext)
		return awsprovider.SourceCredentials{}, ErrCredentialEnvelope
	}
	defer zeroBytes(plaintext)
	if len(plaintext) < 4 {
		return awsprovider.SourceCredentials{}, ErrCredentialEnvelope
	}
	accessLength := int(binary.BigEndian.Uint16(plaintext[0:2]))
	if accessLength == 0 || 2+accessLength+2 > len(plaintext) {
		return awsprovider.SourceCredentials{}, ErrCredentialEnvelope
	}
	offset := 2 + accessLength
	secretLength := int(binary.BigEndian.Uint16(plaintext[offset : offset+2]))
	if secretLength == 0 || offset+2+secretLength != len(plaintext) {
		return awsprovider.SourceCredentials{}, ErrCredentialEnvelope
	}
	return awsprovider.SourceCredentials{
		AccessKeyID:     append([]byte(nil), plaintext[2:offset]...),
		SecretAccessKey: append([]byte(nil), plaintext[offset+2:]...),
	}, nil
}

func credentialAAD(record EncryptedSourceCredential) []byte {
	return []byte(strings.Join([]string{record.SchemaVersion, record.AgentInstanceID, record.AccountID, record.Region, record.OperationID, uintString(record.Generation), record.CreatedAt.UTC().Format(time.RFC3339Nano)}, "\x00"))
}

func uintString(value uint64) string {
	var buffer [20]byte
	index := len(buffer)
	for {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
		if value == 0 {
			return string(buffer[index:])
		}
	}
}

func LoadMasterKeyFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, ErrMasterKey
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrMasterKey
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxMasterKeyFileSize || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, ErrMasterKey
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxMasterKeyFileSize+1))
	if err != nil {
		zeroBytes(raw)
		return nil, ErrMasterKey
	}
	defer zeroBytes(raw)
	trimmed := bytesTrimSpace(raw)
	if len(trimmed) == 32 {
		return append([]byte(nil), trimmed...), nil
	}
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(trimmed)))
	count, err := base64.RawURLEncoding.Decode(decoded, trimmed)
	if err != nil || count != 32 {
		zeroBytes(decoded)
		return nil, ErrMasterKey
	}
	return decoded[:count], nil
}

func bytesTrimSpace(value []byte) []byte {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\t' || value[start] == '\r' || value[start] == '\n') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\t' || value[end-1] == '\r' || value[end-1] == '\n') {
		end--
	}
	return value[start:end]
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

type MemoryCredentialStore struct {
	mu      sync.Mutex
	records map[string]EncryptedSourceCredential
}

func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{records: make(map[string]EncryptedSourceCredential)}
}

func (store *MemoryCredentialStore) Get(ctx context.Context, agentInstanceID string) (EncryptedSourceCredential, error) {
	if err := ctx.Err(); err != nil {
		return EncryptedSourceCredential{}, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, ok := store.records[agentInstanceID]
	if !ok {
		return EncryptedSourceCredential{}, ErrCredentialNotFound
	}
	return cloneEncryptedCredential(record), nil
}

func (store *MemoryCredentialStore) PutCAS(ctx context.Context, agentInstanceID string, expectedGeneration uint64, record EncryptedSourceCredential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	current, exists := store.records[agentInstanceID]
	if (!exists && expectedGeneration != 0) || (exists && current.Generation != expectedGeneration) || record.Generation != expectedGeneration+1 || record.AgentInstanceID != agentInstanceID {
		return ErrCredentialRevisionConflict
	}
	store.records[agentInstanceID] = cloneEncryptedCredential(record)
	return nil
}

func (store *MemoryCredentialStore) DeleteCAS(ctx context.Context, agentInstanceID string, expectedGeneration uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	record, exists := store.records[agentInstanceID]
	if !exists {
		return ErrCredentialNotFound
	}
	if record.Generation != expectedGeneration {
		return ErrCredentialRevisionConflict
	}
	delete(store.records, agentInstanceID)
	return nil
}

func (store *MemoryCredentialStore) Force(record EncryptedSourceCredential) {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.records[record.AgentInstanceID] = cloneEncryptedCredential(record)
}

func cloneEncryptedCredential(value EncryptedSourceCredential) EncryptedSourceCredential {
	value.Nonce = append([]byte(nil), value.Nonce...)
	value.Ciphertext = append([]byte(nil), value.Ciphertext...)
	return value
}
