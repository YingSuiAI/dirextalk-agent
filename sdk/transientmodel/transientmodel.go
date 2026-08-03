// Package transientmodel exposes the non-secret, cross-service helpers needed
// to bind a client-selected model profile to one SecretBootstrap upload.
package transientmodel

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
)

const (
	CredentialPurpose          = "runtime_model_credential_v1"
	ExpectedUploadedRevision   = int64(2)
	bindingSchemaVersion       = "dirextalk.runtime_model_credential_binding.v1"
	credentialTargetIDPrefix   = "runtime-model:"
	maximumBindingStringLength = 2048
)

var ErrInvalidBinding = errors.New("invalid transient model credential binding")

// Profile contains only public model metadata. SecretRef is deliberately not
// represented because transient credentials are addressed by the bootstrap
// session carried beside this value.
type Profile struct {
	ProfileID       string   `json:"profile_id"`
	Provider        string   `json:"provider"`
	Model           string   `json:"model"`
	BaseURL         string   `json:"base_url"`
	Temperature     *float64 `json:"temperature,omitempty"`
	TopP            *float64 `json:"top_p,omitempty"`
	MaxOutputTokens int32    `json:"max_output_tokens"`
	ContextWindow   int32    `json:"context_window"`
	ReasoningEffort string   `json:"reasoning_effort,omitempty"`
}

type bindingDocument struct {
	SchemaVersion    string  `json:"schema_version"`
	OwnerID          string  `json:"owner_id"`
	RequestID        string  `json:"request_id"`
	Profile          Profile `json:"profile"`
	CredentialSHA256 string  `json:"credential_sha256"`
}

// ProfileFromProto strips the forbidden secret reference and canonicalizes
// the provider name used by both the Message Server and Agent.
func ProfileFromProto(profile *agentv1.ModelProfile) (Profile, error) {
	if profile == nil || strings.TrimSpace(profile.GetSecretRef()) != "" {
		return Profile{}, ErrInvalidBinding
	}
	provider := ""
	switch profile.GetProvider() {
	case agentv1.ModelProvider_MODEL_PROVIDER_OPENAI_COMPATIBLE:
		provider = "openai_compatible"
	case agentv1.ModelProvider_MODEL_PROVIDER_DEEPSEEK:
		provider = "deepseek"
	case agentv1.ModelProvider_MODEL_PROVIDER_ANTHROPIC:
		provider = "anthropic"
	default:
		return Profile{}, ErrInvalidBinding
	}
	result := Profile{
		ProfileID: strings.TrimSpace(profile.GetProfileId()), Provider: provider,
		Model: strings.TrimSpace(profile.GetModel()), BaseURL: strings.TrimRight(strings.TrimSpace(profile.GetBaseUrl()), "/"),
		MaxOutputTokens: profile.GetMaxOutputTokens(), ContextWindow: profile.GetContextWindow(),
		ReasoningEffort: strings.TrimSpace(profile.GetReasoningEffort()),
	}
	if profile.Temperature != nil {
		value := profile.GetTemperature()
		result.Temperature = &value
	}
	if profile.TopP != nil {
		value := profile.GetTopP()
		result.TopP = &value
	}
	result, ok := canonicalProfile(result)
	if !ok {
		return Profile{}, ErrInvalidBinding
	}
	return result, nil
}

// TargetID binds owner, request, exact public profile, and credential digest
// into a SecretBootstrap target accepted by the Agent identifier contract.
func TargetID(ownerID, requestID string, profile Profile, credentialSHA256 []byte) (string, error) {
	ownerID = strings.TrimSpace(ownerID)
	requestID = strings.TrimSpace(requestID)
	profile, profileOK := canonicalProfile(profile)
	if !validBindingString(ownerID) || !validBindingString(requestID) || !profileOK || len(credentialSHA256) != sha256.Size {
		return "", ErrInvalidBinding
	}
	document := bindingDocument{
		SchemaVersion: bindingSchemaVersion, OwnerID: ownerID, RequestID: requestID,
		Profile: profile, CredentialSHA256: base64.RawURLEncoding.EncodeToString(credentialSHA256),
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", ErrInvalidBinding
	}
	digest := sha256.Sum256(encoded)
	return credentialTargetIDPrefix + hex.EncodeToString(digest[:]), nil
}

// Envelope contains only encrypted upload material in the raw byte shape used
// by UploadEncryptedRequest.
type Envelope struct {
	ClientPublicKey []byte
	Nonce           []byte
	Ciphertext      []byte
}

// Seal converts the public protobuf descriptor to the Agent's reference
// SecretBootstrap envelope without exposing internal crypto types to clients.
func Seal(session *agentv1.SecretBootstrapSession, plaintext []byte, random io.Reader) (Envelope, error) {
	if session == nil || random == nil || len(plaintext) == 0 ||
		session.GetStatus() != agentv1.SecretBootstrapSessionStatus_SECRET_BOOTSTRAP_SESSION_STATUS_AWAITING_UPLOAD ||
		session.GetRevision() != 1 || session.GetEnvelopeSchemaVersion() != secretbootstrap.EnvelopeSchemaV1 ||
		session.GetCreatedAt() == nil || session.GetExpiresAt() == nil || !session.GetCreatedAt().IsValid() || !session.GetExpiresAt().IsValid() {
		return Envelope{}, ErrInvalidBinding
	}
	descriptor := secretbootstrap.SessionV1{
		SchemaVersion: session.GetSessionSchemaVersion(), SessionID: session.GetSessionId(),
		AgentInstanceID: session.GetAgentInstanceId(), OwnerID: session.GetOwnerId(),
		Purpose: session.GetPurpose(), TargetID: session.GetTargetId(),
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(session.GetServerPublicKey()),
		CreatedAt:       session.GetCreatedAt().AsTime(), ExpiresAt: session.GetExpiresAt().AsTime(),
		Status: secretbootstrap.StatusAwaitingUpload, Revision: uint64(session.GetRevision()),
	}
	sealed, err := secretbootstrap.Seal(descriptor, plaintext, random)
	if err != nil {
		return Envelope{}, ErrInvalidBinding
	}
	clientPublicKey, err := decode(sealed.ClientPublicKey, 32)
	if err != nil {
		return Envelope{}, err
	}
	nonce, err := decode(sealed.Nonce, 12)
	if err != nil {
		clear(clientPublicKey)
		return Envelope{}, err
	}
	ciphertext, err := decode(sealed.Ciphertext, -1)
	if err != nil || len(ciphertext) < 16 {
		clear(clientPublicKey)
		clear(nonce)
		clear(ciphertext)
		return Envelope{}, ErrInvalidBinding
	}
	return Envelope{ClientPublicKey: clientPublicKey, Nonce: nonce, Ciphertext: ciphertext}, nil
}

func canonicalProfile(profile Profile) (Profile, bool) {
	profile.ProfileID = strings.TrimSpace(profile.ProfileID)
	profile.Provider = strings.TrimSpace(profile.Provider)
	profile.Model = strings.TrimSpace(profile.Model)
	profile.BaseURL = strings.TrimRight(strings.TrimSpace(profile.BaseURL), "/")
	profile.ReasoningEffort = strings.TrimSpace(profile.ReasoningEffort)
	if profile.ProfileID == "" || len(profile.ProfileID) > 128 || profile.Model == "" || len(profile.Model) > 512 ||
		profile.BaseURL == "" || len(profile.BaseURL) > 2048 || len(profile.ReasoningEffort) > 128 ||
		profile.ContextWindow < 1 || profile.MaxOutputTokens < 1 || profile.MaxOutputTokens > profile.ContextWindow ||
		!validOptionalFloat(profile.Temperature, 0, 2) || !validOptionalFloat(profile.TopP, 0, 1) {
		return Profile{}, false
	}
	switch profile.Provider {
	case "openai_compatible", "deepseek", "anthropic":
		return profile, true
	default:
		return Profile{}, false
	}
}

func validBindingString(value string) bool {
	return value != "" && len(value) <= maximumBindingStringLength && !strings.ContainsAny(value, "\x00\r\n\t")
}

func validOptionalFloat(value *float64, minimum, maximum float64) bool {
	return value == nil || (!math.IsNaN(*value) && !math.IsInf(*value, 0) && *value >= minimum && *value <= maximum)
}

func decode(value string, exactLength int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || (exactLength >= 0 && len(decoded) != exactLength) {
		clear(decoded)
		return nil, ErrInvalidBinding
	}
	return decoded, nil
}
