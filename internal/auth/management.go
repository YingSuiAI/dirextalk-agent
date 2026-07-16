package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidCredentialInput = errors.New("invalid service credential input")
	ErrCredentialRevision     = errors.New("service credential revision conflict")
	ErrCredentialInactive     = errors.New("service credential is already inactive")
)

var (
	scopePattern        = regexp.MustCompile(`^[a-z][a-z0-9_.:-]{0,127}$`)
	serviceKeyIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	clientIDPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,254}$`)
)

type CreateCredentialCommand struct {
	CallerCredentialID string
	CallerClientID     string
	IdempotencyKey     string
	CredentialID       string
	KeyID              string
	ClientID           string
	Scopes             []string
	RecipientPublicKey string
	SecretDigest       []byte
	Delivery           EncryptedDelivery
	ExpiresAt          *time.Time
}

type EncryptedDelivery struct {
	SchemaVersion   string `json:"schema_version"`
	ServerPublicKey string `json:"server_public_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
	AssociatedData  []byte `json:"associated_data"`
}

type CreatedCredential struct {
	Credential Credential
	Delivery   EncryptedDelivery
}

func (command CreateCredentialCommand) Validate(now time.Time) error {
	if _, err := uuid.Parse(command.IdempotencyKey); err != nil {
		return fmt.Errorf("%w: idempotency_key must be a UUID", ErrInvalidCredentialInput)
	}
	if _, err := uuid.Parse(command.CallerCredentialID); err != nil {
		return fmt.Errorf("%w: caller credential id must be a UUID", ErrInvalidCredentialInput)
	}
	if !clientIDPattern.MatchString(command.CallerClientID) {
		return fmt.Errorf("%w: caller client id is invalid", ErrInvalidCredentialInput)
	}
	if _, err := uuid.Parse(command.CredentialID); err != nil {
		return fmt.Errorf("%w: credential_id must be a UUID", ErrInvalidCredentialInput)
	}
	if !serviceKeyIDPattern.MatchString(command.KeyID) {
		return fmt.Errorf("%w: invalid key_id", ErrInvalidCredentialInput)
	}
	if !clientIDPattern.MatchString(command.ClientID) {
		return fmt.Errorf("%w: invalid client_id", ErrInvalidCredentialInput)
	}
	if len(command.SecretDigest) != sha256.Size {
		return fmt.Errorf("%w: secret digest must contain 32 bytes", ErrInvalidCredentialInput)
	}
	if !isRawURLBytes(command.RecipientPublicKey, 32, 32) || command.Delivery.SchemaVersion == "" ||
		!isRawURLBytes(command.Delivery.ServerPublicKey, 32, 32) || !isRawURLBytes(command.Delivery.Nonce, 12, 12) ||
		!isRawURLBytes(command.Delivery.Ciphertext, 17, 1024*1024+16) || len(command.Delivery.AssociatedData) == 0 || len(command.Delivery.AssociatedData) > 64*1024 {
		return fmt.Errorf("%w: encrypted credential delivery is required", ErrInvalidCredentialInput)
	}
	if len(command.Scopes) == 0 {
		return fmt.Errorf("%w: at least one scope is required", ErrInvalidCredentialInput)
	}
	for _, scope := range command.Scopes {
		if !scopePattern.MatchString(scope) {
			return fmt.Errorf("%w: invalid scope", ErrInvalidCredentialInput)
		}
	}
	if command.ExpiresAt != nil && !now.Before(command.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: expiry must be in the future", ErrInvalidCredentialInput)
	}
	return nil
}

func isRawURLBytes(value string, minimum, maximum int) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) < minimum || len(decoded) > maximum {
		clear(decoded)
		return false
	}
	clear(decoded)
	return true
}

func (command CreateCredentialCommand) Digest() [sha256.Size]byte {
	scopes := append([]string(nil), command.Scopes...)
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	expiresAt := ""
	if command.ExpiresAt != nil {
		expiresAt = command.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	encoded, _ := json.Marshal(struct {
		CallerCredentialID string   `json:"caller_credential_id"`
		CallerClientID     string   `json:"caller_client_id"`
		ClientID           string   `json:"client_id"`
		Scopes             []string `json:"scopes"`
		ExpiresAt          string   `json:"expires_at"`
		RecipientPublicKey string   `json:"recipient_public_key"`
	}{command.CallerCredentialID, command.CallerClientID, command.ClientID, scopes, expiresAt, command.RecipientPublicKey})
	return sha256.Sum256(encoded)
}

type RevokeCredentialCommand struct {
	CallerCredentialID string
	CallerClientID     string
	IdempotencyKey     string
	CredentialID       string
	ExpectedRevision   int64
}

func (command RevokeCredentialCommand) Validate() error {
	if _, err := uuid.Parse(command.IdempotencyKey); err != nil {
		return fmt.Errorf("%w: idempotency_key must be a UUID", ErrInvalidCredentialInput)
	}
	if _, err := uuid.Parse(command.CallerCredentialID); err != nil {
		return fmt.Errorf("%w: caller credential id must be a UUID", ErrInvalidCredentialInput)
	}
	if !clientIDPattern.MatchString(command.CallerClientID) {
		return fmt.Errorf("%w: caller client id is invalid", ErrInvalidCredentialInput)
	}
	if _, err := uuid.Parse(command.CredentialID); err != nil {
		return fmt.Errorf("%w: credential_id must be a UUID", ErrInvalidCredentialInput)
	}
	if command.ExpectedRevision < 1 {
		return fmt.Errorf("%w: expected_revision must be positive", ErrInvalidCredentialInput)
	}
	return nil
}

func (command RevokeCredentialCommand) Digest() [sha256.Size]byte {
	encoded, _ := json.Marshal(struct {
		CallerCredentialID string `json:"caller_credential_id"`
		CallerClientID     string `json:"caller_client_id"`
		CredentialID       string `json:"credential_id"`
		ExpectedRevision   int64  `json:"expected_revision"`
	}{command.CallerCredentialID, command.CallerClientID, command.CredentialID, command.ExpectedRevision})
	return sha256.Sum256(encoded)
}

type BootstrapCredential struct {
	KeyID        string
	ClientID     string
	Scopes       []string
	SecretDigest []byte
}

func (credential BootstrapCredential) Validate() error {
	if !serviceKeyIDPattern.MatchString(credential.KeyID) {
		return fmt.Errorf("%w: invalid bootstrap key_id", ErrInvalidCredentialInput)
	}
	if !clientIDPattern.MatchString(credential.ClientID) {
		return fmt.Errorf("%w: invalid bootstrap client_id", ErrInvalidCredentialInput)
	}
	if len(credential.SecretDigest) != sha256.Size || len(credential.Scopes) == 0 {
		return fmt.Errorf("%w: bootstrap digest and scopes are required", ErrInvalidCredentialInput)
	}
	for _, scope := range credential.Scopes {
		if !scopePattern.MatchString(scope) {
			return fmt.Errorf("%w: invalid bootstrap scope", ErrInvalidCredentialInput)
		}
	}
	return nil
}

type CredentialManagerRepository interface {
	CredentialRepository
	EnsureBootstrapCredential(context.Context, BootstrapCredential) (Credential, error)
	CreateCredential(context.Context, CreateCredentialCommand) (CreatedCredential, error)
	RevokeCredential(context.Context, RevokeCredentialCommand) (Credential, error)
}
