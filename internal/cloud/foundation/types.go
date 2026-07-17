// Package foundation defines the independent device-approved AWS Foundation
// lifecycle contract. It deliberately contains no Worker Plan, quote, release
// operator credential, or provider implementation.
package foundation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	ScopeSchemaV1     = "dirextalk.agent.aws-foundation-operation-scope/v1"
	SigningPayloadV1  = "dirextalk.agent.aws-foundation-operation-approval/v1"
	ChallengeValidity = 5 * time.Minute
)

var (
	ErrInvalid             = errors.New("invalid Foundation operation")
	ErrApprovalRequired    = errors.New("valid Foundation device approval is required")
	ErrRevisionConflict    = errors.New("Foundation revision conflict")
	ErrIdempotencyConflict = errors.New("Foundation idempotency conflict")
	ErrNotFound            = errors.New("Foundation operation not found")
	ErrUnavailable         = errors.New("Foundation persistence is unavailable")
	accountPattern         = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern          = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	digestPattern          = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
)

type Action string

const (
	ActionEstablish Action = "establish"
	ActionUpgrade   Action = "upgrade"
	ActionTeardown  Action = "teardown"
	ActionRemediate Action = "remediate_destroy_blocked"
)

type MutationScope struct {
	ClientID     string
	CredentialID string
}

func (scope MutationScope) Validate() error {
	if strings.TrimSpace(scope.ClientID) == "" || len(scope.ClientID) > 255 || security.ContainsLikelySecret(scope.ClientID) {
		return ErrInvalid
	}
	if parsed, err := uuid.Parse(strings.TrimSpace(scope.CredentialID)); err != nil || parsed == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

type ReleaseEnvironmentV1 struct {
	PrivateSubnetCIDR string `json:"private_subnet_cidr"`
	ZeroIngress       bool   `json:"zero_ingress"`
	ArtifactBucket    string `json:"artifact_bucket"`
	KMSAlias          string `json:"kms_alias"`
	BucketVersioned   bool   `json:"bucket_versioned"`
	BucketSSEKMS      bool   `json:"bucket_sse_kms"`
}

type ScopeV1 struct {
	SchemaVersion                string               `json:"schema_version"`
	AgentInstanceID              string               `json:"agent_instance_id"`
	OwnerID                      string               `json:"owner_id"`
	Action                       Action               `json:"action"`
	ConnectionID                 string               `json:"connection_id"`
	ExpectedConnectionRevision   int64                `json:"expected_connection_revision"`
	AccountID                    string               `json:"account_id"`
	Region                       string               `json:"region"`
	BootstrapSessionID           string               `json:"bootstrap_session_id"`
	ExpectedBootstrapRevision    uint64               `json:"expected_bootstrap_revision"`
	ExpectedCredentialGeneration uint64               `json:"expected_credential_generation"`
	IdentityObservedAt           time.Time            `json:"identity_observed_at"`
	IdentityExpiresAt            time.Time            `json:"identity_expires_at"`
	FoundationTemplateDigest     string               `json:"foundation_template_digest"`
	ReaperImageURI               string               `json:"reaper_image_uri"`
	ReleaseEnvironment           ReleaseEnvironmentV1 `json:"release_environment"`
}

func (scope ScopeV1) Validate() error {
	if scope.SchemaVersion != ScopeSchemaV1 || !validUUID(scope.AgentInstanceID) || !validUUID(scope.ConnectionID) ||
		!validUUID(scope.BootstrapSessionID) || strings.TrimSpace(scope.OwnerID) == "" || len(scope.OwnerID) > 255 ||
		security.ContainsLikelySecret(scope.OwnerID) || !accountPattern.MatchString(scope.AccountID) ||
		!regionPattern.MatchString(scope.Region) || scope.ExpectedBootstrapRevision == 0 || scope.IdentityObservedAt.IsZero() ||
		!scope.IdentityObservedAt.Before(scope.IdentityExpiresAt) || scope.IdentityExpiresAt.Sub(scope.IdentityObservedAt) > 10*time.Minute ||
		!digestPattern.MatchString(scope.FoundationTemplateDigest) || !strings.Contains(scope.ReaperImageURI, "@sha256:") {
		return ErrInvalid
	}
	switch scope.Action {
	case ActionEstablish:
		if scope.ExpectedConnectionRevision != 0 || scope.ExpectedCredentialGeneration != 0 {
			return ErrInvalid
		}
	case ActionUpgrade, ActionTeardown, ActionRemediate:
		if scope.ExpectedConnectionRevision < 1 || scope.ExpectedCredentialGeneration < 1 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	environment := scope.ReleaseEnvironment
	if environment.PrivateSubnetCIDR != "10.255.0.0/26" || !environment.ZeroIngress || !environment.BucketVersioned || !environment.BucketSSEKMS ||
		strings.TrimSpace(environment.ArtifactBucket) == "" || !strings.HasPrefix(environment.KMSAlias, "alias/dtx-agent-") {
		return ErrInvalid
	}
	return nil
}

type ChallengeV1 struct {
	OperationID string    `json:"operation_id"`
	ChallengeID string    `json:"challenge_id"`
	ApprovalID  string    `json:"approval_id"`
	SignerKeyID string    `json:"signer_key_id"`
	Scope       ScopeV1   `json:"scope"`
	ScopeDigest string    `json:"scope_digest"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	SigningCBOR []byte    `json:"-"`
	Revision    int64     `json:"revision"`
}

func (challenge ChallengeV1) Validate() error {
	if !validUUID(challenge.OperationID) || !validUUID(challenge.ChallengeID) || !validUUID(challenge.ApprovalID) ||
		strings.TrimSpace(challenge.SignerKeyID) == "" || challenge.Scope.Validate() != nil || !digestPattern.MatchString(challenge.ScopeDigest) ||
		challenge.Revision != 1 || challenge.IssuedAt.IsZero() || !challenge.IssuedAt.Before(challenge.ExpiresAt) ||
		challenge.ExpiresAt.Sub(challenge.IssuedAt) > ChallengeValidity {
		return ErrInvalid
	}
	return nil
}

func (challenge ChallengeV1) SigningPayload() ([]byte, error) {
	if err := challenge.Validate(); err != nil {
		return nil, err
	}
	return canonical.Marshal(struct {
		PayloadSchema string    `json:"payload_schema"`
		OperationID   string    `json:"operation_id"`
		ChallengeID   string    `json:"challenge_id"`
		ApprovalID    string    `json:"approval_id"`
		SignerKeyID   string    `json:"signer_key_id"`
		Scope         ScopeV1   `json:"scope"`
		ExpiresAt     time.Time `json:"expires_at"`
	}{SigningPayloadV1, challenge.OperationID, challenge.ChallengeID, challenge.ApprovalID, challenge.SignerKeyID, challenge.Scope, challenge.ExpiresAt.UTC()})
}

type SignatureV1 struct {
	ApprovalID  string
	ChallengeID string
	SignerKeyID string
	ExpiresAt   time.Time
	Signature   []byte
}

func (signature SignatureV1) Validate() error {
	if !validUUID(signature.ApprovalID) || !validUUID(signature.ChallengeID) || strings.TrimSpace(signature.SignerKeyID) == "" ||
		signature.ExpiresAt.IsZero() || len(signature.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	return nil
}

type Status string

const (
	StatusAwaitingApproval Status = "awaiting_approval"
	StatusApproved         Status = "approved"
	StatusRunning          Status = "running"
	StatusSucceeded        Status = "succeeded"
	StatusFailedRetriable  Status = "failed_retriable"
	StatusFailedTerminal   Status = "failed_terminal"
	StatusDestroyBlocked   Status = "destroy_blocked"
)

type OperationV1 struct {
	Caller        MutationScope
	Recovery      bool
	AdoptExisting bool
	Challenge     ChallengeV1
	Status        Status
	Signature     []byte
	ErrorCode     string
	BlockedReason string
	Revision      int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
	ApprovedAt    *time.Time
}

type Mutation struct {
	Caller         MutationScope
	OwnerID        string
	IdempotencyKey string
	RequestHash    [sha256.Size]byte
}

func (mutation Mutation) Validate() error {
	if mutation.Caller.Validate() != nil || strings.TrimSpace(mutation.OwnerID) == "" || !validUUID(mutation.IdempotencyKey) || mutation.RequestHash == ([sha256.Size]byte{}) {
		return ErrInvalid
	}
	return nil
}

type Snapshot struct {
	Scope             ScopeV1
	SessionUploadedAt time.Time
	SessionExpiresAt  time.Time
}

type SnapshotReader interface {
	SnapshotFoundation(context.Context, MutationScope, string, Action, string, string, uint64) (Snapshot, error)
}

type Repository interface {
	CreateChallenge(context.Context, Mutation, ChallengeV1) (ChallengeV1, error)
	GetChallenge(context.Context, string, string) (ChallengeV1, error)
	Approve(context.Context, Mutation, SignatureV1, time.Time) (OperationV1, error)
	GetOperation(context.Context, string, string) (OperationV1, error)
}

type Notifier interface{ NotifyFoundationOperation() }

func ScopeDigest(scope ScopeV1) (string, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}
	encoded, err := canonical.Marshal(scope)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return fmt.Sprintf("sha256:%x", digest), nil
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == strings.TrimSpace(value)
}
