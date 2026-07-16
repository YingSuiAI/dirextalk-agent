// Package secretbootstrap implements the transport-independent, one-use secret
// bootstrap boundary. It contains no HTTP, AWS, broker, or database code.
package secretbootstrap

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	SessionSchemaV1           = "dirextalk.agent.secret-bootstrap.session/v1"
	EnvelopeSchemaV1          = "dirextalk.agent.secret-bootstrap.envelope/v1"
	RecipientEnvelopeSchemaV1 = "dirextalk.agent.recipient-envelope/v1"
	SessionTTL                = 10 * time.Minute
	MaxPlaintextSize          = 1024 * 1024
	MaxAADSize                = 64 * 1024
	CreateOperation           = "secret.bootstrap.create"
	UploadOperation           = "secret.bootstrap.upload"
	legacyUnboundClientID     = "__legacy_unbound__"
)

// MutationScope binds one idempotency key to the authenticated calling
// service and the concrete credential used for the request. It intentionally
// does not grant approval for consuming or delivering a secret.
type MutationScope struct {
	ClientID     string
	CredentialID string
}

func (scope MutationScope) Validate() error {
	if err := ValidateClientID(scope.ClientID); err != nil {
		return err
	}
	credentialID, err := uuid.Parse(scope.CredentialID)
	if err != nil || credentialID == uuid.Nil {
		return ErrInvalidContext
	}
	return nil
}

// ValidateClientID validates the stable authenticated service identity used to
// own a bootstrap session. Credential IDs are intentionally excluded so an
// overlapping service-key rotation does not strand an in-flight session.
func ValidateClientID(value string) error {
	clientID := strings.TrimSpace(value)
	if utf8.RuneCountInString(clientID) < 1 || utf8.RuneCountInString(clientID) > 255 || clientID == legacyUnboundClientID || security.ContainsLikelySecret(clientID) {
		return ErrInvalidContext
	}
	for _, r := range clientID {
		if unicode.IsControl(r) {
			return ErrInvalidContext
		}
	}
	return nil
}

// IdempotencyMutation is a secret-free persistence command. RequestHash is
// computed over the immutable request binding and digests of bearer material,
// never over plaintext credentials.
type IdempotencyMutation struct {
	Operation   string
	Scope       MutationScope
	Key         string
	RequestHash [sha256.Size]byte
}

func (mutation IdempotencyMutation) Validate() error {
	if mutation.Operation != CreateOperation && mutation.Operation != UploadOperation {
		return ErrInvalidContext
	}
	if err := mutation.Scope.Validate(); err != nil {
		return err
	}
	key, err := uuid.Parse(mutation.Key)
	if err != nil || key == uuid.Nil {
		return ErrInvalidContext
	}
	return nil
}

type Status string

const (
	StatusAwaitingUpload Status = "awaiting_upload"
	StatusUploaded       Status = "uploaded"
	StatusConsumed       Status = "consumed"
	StatusExpired        Status = "expired"
)

type BindingV1 struct {
	AgentInstanceID string `json:"agent_instance_id"`
	OwnerID         string `json:"owner_id"`
	Purpose         string `json:"purpose"`
	TargetID        string `json:"target_id"`
}

// SessionV1 is the public, non-secret session descriptor. Its immutable fields
// form the AEAD associated data and must be sent to clients exactly as stored.
type SessionV1 struct {
	SchemaVersion   string    `json:"schema_version"`
	SessionID       string    `json:"session_id"`
	AgentInstanceID string    `json:"agent_instance_id"`
	OwnerID         string    `json:"owner_id"`
	Purpose         string    `json:"purpose"`
	TargetID        string    `json:"target_id"`
	ServerPublicKey string    `json:"server_public_key"`
	CreatedAt       time.Time `json:"created_at"`
	ExpiresAt       time.Time `json:"expires_at"`
	Status          Status    `json:"status"`
	Revision        uint64    `json:"revision"`
}

func (s SessionV1) Binding() BindingV1 {
	return BindingV1{
		AgentInstanceID: s.AgentInstanceID,
		OwnerID:         s.OwnerID,
		Purpose:         s.Purpose,
		TargetID:        s.TargetID,
	}
}

type EnvelopeV1 struct {
	SchemaVersion   string `json:"schema_version"`
	SessionID       string `json:"session_id"`
	ClientPublicKey string `json:"client_public_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

// RecipientEnvelopeV1 is an outbound envelope for returning generated
// credentials to a registered X25519 recipient without exposing plaintext in
// an RPC response or persistence record.
type RecipientEnvelopeV1 struct {
	SchemaVersion   string `json:"schema_version"`
	ServerPublicKey string `json:"server_public_key"`
	Nonce           string `json:"nonce"`
	Ciphertext      string `json:"ciphertext"`
}

// UploadToken deliberately redacts all ordinary formatting and JSON output.
// Reveal is the only operation that returns the one-time bearer value.
type UploadToken struct {
	value string
}

func newUploadToken(value string) UploadToken { return UploadToken{value: value} }

func (t UploadToken) Reveal() string { return t.value }

func (UploadToken) String() string   { return "[REDACTED]" }
func (UploadToken) GoString() string { return "[REDACTED]" }

func (UploadToken) Format(state fmt.State, _ rune) {
	_, _ = state.Write([]byte("[REDACTED]"))
}

func (UploadToken) MarshalJSON() ([]byte, error) {
	return json.Marshal("[REDACTED]")
}

type CreateResult struct {
	Session     SessionV1   `json:"session"`
	UploadToken UploadToken `json:"upload_token"`
}

type SecretConsumer func(plaintext []byte) error

// Record is the persistence representation. It contains a token digest, an
// opaque key-vault handle, and authenticated ciphertext, never plaintext,
// upload-token material, or an X25519 private key.
type Record struct {
	Session         SessionV1   `json:"session"`
	CreatorClientID string      `json:"creator_client_id"`
	UploadTokenHash [32]byte    `json:"upload_token_hash"`
	KeyHandle       string      `json:"key_handle,omitempty"`
	Envelope        *EnvelopeV1 `json:"envelope,omitempty"`
}

func createMutation(scope MutationScope, key string, binding BindingV1) (IdempotencyMutation, error) {
	binding = BindingV1{
		AgentInstanceID: strings.TrimSpace(binding.AgentInstanceID),
		OwnerID:         strings.TrimSpace(binding.OwnerID),
		Purpose:         strings.TrimSpace(binding.Purpose),
		TargetID:        strings.TrimSpace(binding.TargetID),
	}
	encoded, _ := json.Marshal(binding)
	mutation := IdempotencyMutation{
		Operation: CreateOperation,
		Scope: MutationScope{
			ClientID:     strings.TrimSpace(scope.ClientID),
			CredentialID: strings.TrimSpace(scope.CredentialID),
		},
		Key:         strings.TrimSpace(key),
		RequestHash: sha256.Sum256(encoded),
	}
	return mutation, mutation.Validate()
}

func uploadMutation(scope MutationScope, key, sessionID string, expectedRevision uint64, tokenHash [sha256.Size]byte, envelope EnvelopeV1) (IdempotencyMutation, error) {
	encoded, _ := json.Marshal(struct {
		SessionID        string     `json:"session_id"`
		ExpectedRevision uint64     `json:"expected_revision"`
		UploadTokenHash  [32]byte   `json:"upload_token_hash"`
		Envelope         EnvelopeV1 `json:"envelope"`
	}{
		SessionID: strings.TrimSpace(sessionID), ExpectedRevision: expectedRevision,
		UploadTokenHash: tokenHash, Envelope: envelope,
	})
	mutation := IdempotencyMutation{
		Operation: UploadOperation,
		Scope: MutationScope{
			ClientID:     strings.TrimSpace(scope.ClientID),
			CredentialID: strings.TrimSpace(scope.CredentialID),
		},
		Key:         strings.TrimSpace(key),
		RequestHash: sha256.Sum256(encoded),
	}
	return mutation, mutation.Validate()
}
