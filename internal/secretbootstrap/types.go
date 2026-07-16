// Package secretbootstrap implements the transport-independent, one-use secret
// bootstrap boundary. It contains no HTTP, AWS, broker, or database code.
package secretbootstrap

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	SessionSchemaV1           = "dirextalk.agent.secret-bootstrap.session/v1"
	EnvelopeSchemaV1          = "dirextalk.agent.secret-bootstrap.envelope/v1"
	RecipientEnvelopeSchemaV1 = "dirextalk.agent.recipient-envelope/v1"
	SessionTTL                = 10 * time.Minute
	MaxPlaintextSize          = 1024 * 1024
	MaxAADSize                = 64 * 1024
)

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
	UploadTokenHash [32]byte    `json:"upload_token_hash"`
	KeyHandle       string      `json:"key_handle,omitempty"`
	Envelope        *EnvelopeV1 `json:"envelope,omitempty"`
}
