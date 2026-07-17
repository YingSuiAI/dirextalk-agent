package pairing

import (
	"context"
	"encoding/base64"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
)

const SchemaV1 = "dirextalk.agent.pairing-session/v1"

var (
	ErrInvalid          = errors.New("invalid pairing session")
	ErrNotFound         = errors.New("pairing session not found")
	ErrRevisionConflict = errors.New("pairing session revision conflict")
	digestPattern       = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	refPattern          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$`)
)

type Status string

const (
	StatusWaitingPayload Status = "waiting_payload"
	StatusPayloadReady   Status = "payload_ready"
	StatusWaitingUser    Status = "waiting_user"
	StatusResuming       Status = "resuming"
	StatusSucceeded      Status = "succeeded"
	StatusTimedOut       Status = "timed_out"
	StatusFailed         Status = "failed"
)

type SessionV1 struct {
	SchemaVersion           string                               `json:"schema_version"`
	SessionID               string                               `json:"session_id"`
	OwnerID                 string                               `json:"owner_id"`
	DeploymentID            string                               `json:"deployment_id"`
	DeploymentRevision      int64                                `json:"deployment_revision"`
	PlanID                  string                               `json:"plan_id"`
	ConnectionID            string                               `json:"connection_id"`
	TaskID                  string                               `json:"task_id"`
	StepID                  string                               `json:"step_id"`
	RecipeID                string                               `json:"recipe_id"`
	RecipeDigest            string                               `json:"recipe_digest"`
	RecipeRevision          int64                                `json:"recipe_revision"`
	ExecutionManifestDigest string                               `json:"execution_manifest_digest"`
	BeginCommand            string                               `json:"begin_command"`
	ResumeCommand           string                               `json:"resume_command"`
	Status                  Status                               `json:"status"`
	RecipientKeyDigest      string                               `json:"recipient_key_digest,omitempty"`
	Envelope                *secretbootstrap.RecipientEnvelopeV1 `json:"recipient_envelope,omitempty"`
	AssociatedDataCBOR      []byte                               `json:"associated_data_cbor,omitempty"`
	PayloadDigest           string                               `json:"payload_digest,omitempty"`
	PayloadScopeRevision    int64                                `json:"payload_scope_revision,omitempty"`
	ExpiresAt               time.Time                            `json:"expires_at"`
	Revision                int64                                `json:"revision"`
	CreatedAt               time.Time                            `json:"created_at"`
	UpdatedAt               time.Time                            `json:"updated_at"`
	ResumeStartedAt         *time.Time                           `json:"resume_started_at,omitempty"`
	CompletedAt             *time.Time                           `json:"completed_at,omitempty"`
	FailureCode             string                               `json:"failure_code,omitempty"`
}

func (value SessionV1) Validate() error {
	if value.SchemaVersion != SchemaV1 || !validUUID(value.SessionID) || !validRef(value.OwnerID) ||
		!validUUID(value.DeploymentID) || value.DeploymentRevision < 1 || !validUUID(value.PlanID) || !validUUID(value.ConnectionID) ||
		!validUUID(value.TaskID) || !validUUID(value.StepID) ||
		!validRef(value.RecipeID) || !validDigest(value.RecipeDigest) || value.RecipeRevision < 1 ||
		!validDigest(value.ExecutionManifestDigest) ||
		!validRef(value.BeginCommand) || !validRef(value.ResumeCommand) || !validStatus(value.Status) ||
		value.Revision < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.IsZero() ||
		!value.ExpiresAt.After(value.CreatedAt) || value.UpdatedAt.Before(value.CreatedAt) {
		return ErrInvalid
	}
	hasEnvelope := value.Envelope != nil || value.RecipientKeyDigest != "" || len(value.AssociatedDataCBOR) != 0 ||
		value.PayloadDigest != "" || value.PayloadScopeRevision != 0
	if hasEnvelope {
		if value.Envelope == nil || !validDigest(value.RecipientKeyDigest) || !validDigest(value.PayloadDigest) ||
			len(value.AssociatedDataCBOR) == 0 || len(value.AssociatedDataCBOR) > 64*1024 ||
			value.PayloadScopeRevision < 1 || !validEnvelope(*value.Envelope) {
			return ErrInvalid
		}
	}
	switch value.Status {
	case StatusWaitingPayload:
		if hasEnvelope || value.ResumeStartedAt != nil || value.CompletedAt != nil || value.FailureCode != "" {
			return ErrInvalid
		}
	case StatusPayloadReady, StatusWaitingUser:
		if !hasEnvelope || value.ResumeStartedAt != nil || value.CompletedAt != nil || value.FailureCode != "" {
			return ErrInvalid
		}
	case StatusResuming:
		if !hasEnvelope || value.ResumeStartedAt == nil || value.CompletedAt != nil || value.FailureCode != "" {
			return ErrInvalid
		}
	case StatusSucceeded:
		if !hasEnvelope || value.ResumeStartedAt == nil || value.CompletedAt == nil || value.FailureCode != "" {
			return ErrInvalid
		}
	case StatusFailed:
		if !hasEnvelope || value.ResumeStartedAt == nil || value.CompletedAt == nil || !validRef(value.FailureCode) {
			return ErrInvalid
		}
	case StatusTimedOut:
		// An expired session is deliberately scrubbed of the encrypted delivery
		// material.  This makes a timeout terminal even if a Worker produced a
		// receipt just as the session expired.
		if hasEnvelope || value.CompletedAt == nil || !validRef(value.FailureCode) {
			return ErrInvalid
		}
	}
	if value.ResumeStartedAt != nil && value.ResumeStartedAt.Before(value.CreatedAt) ||
		value.CompletedAt != nil && value.CompletedAt.Before(value.CreatedAt) ||
		value.ResumeStartedAt != nil && value.CompletedAt != nil && value.CompletedAt.Before(*value.ResumeStartedAt) {
		return ErrInvalid
	}
	return nil
}

type Mutation struct {
	OwnerID        string
	IdempotencyKey string
	RequestDigest  string
}

// PayloadReservationV1 is an internal, durable dispatch fence.  It binds the
// first encrypted-payload request to one recipient digest and one immutable
// payload scope before any Worker/root-helper work is dispatched.  The raw
// recipient key is intentionally never represented here.
type PayloadReservationV1 struct {
	SessionID            string    `json:"session_id"`
	OwnerID              string    `json:"owner_id"`
	PayloadScopeRevision int64     `json:"payload_scope_revision"`
	RecipientKeyDigest   string    `json:"recipient_key_digest"`
	OperationID          string    `json:"operation_id"`
	CreatedAt            time.Time `json:"created_at"`
}

func (value PayloadReservationV1) Validate() error {
	if !validUUID(value.SessionID) || !validRef(value.OwnerID) || value.PayloadScopeRevision < 1 ||
		!validDigest(value.RecipientKeyDigest) || !validUUID(value.OperationID) || value.CreatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

func (value Mutation) Validate() error {
	if !validRef(value.OwnerID) || !validUUID(value.IdempotencyKey) || !validDigest(value.RequestDigest) {
		return ErrInvalid
	}
	return nil
}

func ValidateLookup(ownerID, sessionID string) error {
	if !validRef(ownerID) || !validUUID(sessionID) {
		return ErrInvalid
	}
	return nil
}

type Repository interface {
	Create(context.Context, Mutation, int64, SessionV1) (SessionV1, error)
	Get(context.Context, string, string) (SessionV1, error)
	ReservePayload(context.Context, Mutation, string, int64, string, string, time.Time) (SessionV1, PayloadReservationV1, bool, error)
	RecordEnvelope(context.Context, Mutation, string, int64, string, string, secretbootstrap.RecipientEnvelopeV1, []byte, string, time.Time) (SessionV1, error)
	Expire(context.Context, string, string, time.Time) (SessionV1, error)
	BeginResume(context.Context, Mutation, string, int64, time.Time) (SessionV1, error)
	CompleteResume(context.Context, Mutation, string, int64, Status, string, time.Time) (SessionV1, error)
}

func (value SessionV1) Clone() SessionV1 {
	cloned := value
	cloned.AssociatedDataCBOR = append([]byte(nil), value.AssociatedDataCBOR...)
	if value.Envelope != nil {
		envelope := *value.Envelope
		cloned.Envelope = &envelope
	}
	return cloned
}

func RecordEnvelopeStatus(status Status) (Status, error) {
	if status != StatusWaitingPayload {
		return "", ErrRevisionConflict
	}
	return StatusWaitingUser, nil
}
func CanRecordEnvelope(status Status) bool {
	_, err := RecordEnvelopeStatus(status)
	return err == nil
}
func CanBeginResume(status Status) bool {
	return status == StatusPayloadReady || status == StatusWaitingUser
}
func CanCompleteResume(status Status) bool {
	return status == StatusSucceeded || status == StatusTimedOut || status == StatusFailed
}

func IsTerminal(status Status) bool {
	return status == StatusSucceeded || status == StatusTimedOut || status == StatusFailed
}

// PayloadOperationID is the durable Worker operation identity for a begin
// request.  It is derived only from the session, immutable payload scope, and
// SHA-256 recipient digest so it can be persisted without retaining the raw
// recipient key.  pairingworker must use the same derivation when it turns an
// Executor.Begin call into a Worker command.
func PayloadOperationID(sessionID string, payloadScopeRevision int64, recipientKeyDigest string) (string, error) {
	parsed, err := uuid.Parse(sessionID)
	if err != nil || parsed == uuid.Nil || parsed.String() != sessionID || payloadScopeRevision < 1 || !validDigest(recipientKeyDigest) {
		return "", ErrInvalid
	}
	return uuid.NewSHA1(parsed, []byte("pairing_begin:"+strings.TrimPrefix(recipientKeyDigest, "sha256:")+":"+strconv.FormatInt(payloadScopeRevision, 10))).String(), nil
}

func validStatus(value Status) bool {
	switch value {
	case StatusWaitingPayload, StatusPayloadReady, StatusWaitingUser, StatusResuming, StatusSucceeded, StatusTimedOut, StatusFailed:
		return true
	default:
		return false
	}
}
func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
func validDigest(value string) bool { return digestPattern.MatchString(value) }
func validRef(value string) bool {
	return refPattern.MatchString(value)
}
func validEnvelope(value secretbootstrap.RecipientEnvelopeV1) bool {
	publicKey, publicErr := base64.RawURLEncoding.DecodeString(value.ServerPublicKey)
	nonce, nonceErr := base64.RawURLEncoding.DecodeString(value.Nonce)
	ciphertext, ciphertextErr := base64.RawURLEncoding.DecodeString(value.Ciphertext)
	return value.SchemaVersion == secretbootstrap.RecipientEnvelopeSchemaV1 &&
		publicErr == nil && len(publicKey) == 32 && nonceErr == nil && len(nonce) == 12 &&
		ciphertextErr == nil && len(ciphertext) >= 16 && len(ciphertext) <= secretbootstrap.MaxPlaintextSize+16
}
