// Package managedlifecycle defines the owner/device-approved lifecycle
// contract for retained Knowledge services. It deliberately carries only
// signed immutable facts and closed Recipe lifecycle references.
package managedlifecycle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	ScopeSchemaV1     = "dirextalk.agent.managed-knowledge-lifecycle-scope/v1"
	SigningPayloadV1  = "dirextalk.agent.managed-knowledge-lifecycle-approval/v1"
	ChallengeValidity = 5 * time.Minute
)

var (
	ErrInvalid             = errors.New("managed Knowledge lifecycle request is invalid")
	ErrNotFound            = errors.New("managed Knowledge lifecycle operation was not found")
	ErrRevisionConflict    = errors.New("managed Knowledge lifecycle revision conflict")
	ErrIdempotencyConflict = errors.New("managed Knowledge lifecycle idempotency conflict")
	ErrApprovalRequired    = errors.New("managed Knowledge lifecycle device approval is required")
)

var digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var refPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

type Action string

const (
	ActionStop     Action = "stop"
	ActionBackup   Action = "backup"
	ActionRestore  Action = "restore"
	ActionUpgrade  Action = "upgrade"
	ActionRollback Action = "rollback"
	ActionDestroy  Action = "destroy"
)

func (value Action) valid() bool {
	switch value {
	case ActionStop, ActionBackup, ActionRestore, ActionUpgrade, ActionRollback, ActionDestroy:
		return true
	default:
		return false
	}
}

func (value Action) Valid() bool { return value.valid() }

type Status string

const (
	StatusAwaitingApproval Status = "awaiting_approval"
	StatusScheduled        Status = "scheduled"
	StatusRunning          Status = "running"
	StatusSucceeded        Status = "succeeded"
	StatusFailed           Status = "failed"
	StatusDestroyBlocked   Status = "destroy_blocked"
)

type MutationScope struct{ ClientID, CredentialID string }

func (scope MutationScope) Validate() error {
	if !safe(scope.ClientID) || !validUUID(scope.CredentialID) {
		return ErrInvalid
	}
	return nil
}

type Mutation struct {
	Caller                               MutationScope
	OwnerID, IdempotencyKey, RequestHash string
}

func (value Mutation) Validate() error {
	return validateMutation(value.Caller, value.OwnerID, value.IdempotencyKey, value.RequestHash)
}

type ScopeV1 struct {
	SchemaVersion            string `json:"schema_version"`
	AgentInstanceID          string `json:"agent_instance_id"`
	OwnerID                  string `json:"owner_id"`
	DeploymentID             string `json:"deployment_id"`
	ManagedServiceID         string `json:"managed_service_id"`
	KnowledgeBindingID       string `json:"knowledge_binding_id"`
	DeploymentRevision       int64  `json:"deployment_revision"`
	ManagedServiceRevision   int64  `json:"managed_service_revision"`
	KnowledgeBindingRevision int64  `json:"knowledge_binding_revision"`
	RecipeDigest             string `json:"recipe_digest"`
	Action                   Action `json:"action"`
	LifecycleRef             string `json:"lifecycle_ref"`
	ExecutionBundleDigest    string `json:"execution_bundle_digest"`
	InstalledManifestDigest  string `json:"installed_manifest_digest"`
}

func (value ScopeV1) Validate() error {
	if value.SchemaVersion != ScopeSchemaV1 || !validUUID(value.AgentInstanceID) || !safe(value.OwnerID) ||
		!validUUID(value.DeploymentID) || !validUUID(value.ManagedServiceID) || !validUUID(value.KnowledgeBindingID) ||
		value.DeploymentRevision < 1 || value.ManagedServiceRevision < 1 || value.KnowledgeBindingRevision < 1 ||
		!digestPattern.MatchString(value.RecipeDigest) || !value.Action.valid() || !refPattern.MatchString(value.LifecycleRef) ||
		!digestPattern.MatchString(value.ExecutionBundleDigest) || !digestPattern.MatchString(value.InstalledManifestDigest) {
		return ErrInvalid
	}
	return nil
}

type ChallengeV1 struct {
	OperationID, ChallengeID, ApprovalID, SignerKeyID string
	Scope                                             ScopeV1
	ScopeDigest                                       string
	IssuedAt, ExpiresAt                               time.Time
	SigningCBOR                                       []byte
	Revision                                          int64
}

func (value ChallengeV1) Validate() error {
	if !validUUID(value.OperationID) || !validUUID(value.ChallengeID) || !validUUID(value.ApprovalID) || !safe(value.SignerKeyID) ||
		value.Scope.Validate() != nil || !digestPattern.MatchString(value.ScopeDigest) || value.Revision != 1 ||
		value.IssuedAt.IsZero() || !value.IssuedAt.Before(value.ExpiresAt) || value.ExpiresAt.Sub(value.IssuedAt) > ChallengeValidity {
		return ErrInvalid
	}
	return nil
}

func (value ChallengeV1) SigningPayload() ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrInvalid
	}
	return canonical.Marshal(struct {
		PayloadSchema string    `json:"payload_schema"`
		OperationID   string    `json:"operation_id"`
		ChallengeID   string    `json:"challenge_id"`
		ApprovalID    string    `json:"approval_id"`
		SignerKeyID   string    `json:"signer_key_id"`
		Scope         ScopeV1   `json:"scope"`
		ExpiresAt     time.Time `json:"expires_at"`
	}{SigningPayloadV1, value.OperationID, value.ChallengeID, value.ApprovalID, value.SignerKeyID, value.Scope, value.ExpiresAt.UTC()})
}

type SignatureV1 struct {
	ChallengeID, ApprovalID, SignerKeyID string
	Signature                            []byte
}

type OperationV1 struct {
	Challenge            ChallengeV1
	Status               Status
	WorkerOperationID    string
	ErrorCode            string
	RequiresNewApproval  bool
	Revision             int64
	CreatedAt, UpdatedAt time.Time
	ApprovedAt           *time.Time
}

func (value OperationV1) Validate() error {
	if value.Challenge.Validate() != nil || value.Revision < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) {
		return ErrInvalid
	}
	switch value.Status {
	case StatusAwaitingApproval:
		if value.WorkerOperationID != "" || value.ErrorCode != "" || value.RequiresNewApproval || value.ApprovedAt != nil {
			return ErrInvalid
		}
	case StatusScheduled, StatusRunning:
		if !validUUID(value.WorkerOperationID) || value.ErrorCode != "" || value.RequiresNewApproval || value.ApprovedAt == nil {
			return ErrInvalid
		}
	case StatusSucceeded:
		if !validUUID(value.WorkerOperationID) || value.ErrorCode != "" || value.RequiresNewApproval || value.ApprovedAt == nil {
			return ErrInvalid
		}
	case StatusFailed:
		if !validUUID(value.WorkerOperationID) || !refPattern.MatchString(value.ErrorCode) || value.RequiresNewApproval || value.ApprovedAt == nil {
			return ErrInvalid
		}
	case StatusDestroyBlocked:
		if value.Challenge.Scope.Action != ActionDestroy || !validUUID(value.WorkerOperationID) || !refPattern.MatchString(value.ErrorCode) || !value.RequiresNewApproval || value.ApprovedAt == nil {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type ScopeBuilder interface {
	BuildManagedKnowledgeLifecycleScope(context.Context, string, string, string, Action) (ScopeV1, error)
}
type Repository interface {
	CreateChallenge(context.Context, Mutation, ChallengeV1) (ChallengeV1, error)
	GetChallenge(context.Context, string, string) (ChallengeV1, error)
	Approve(context.Context, Mutation, SignatureV1, string, time.Time) (OperationV1, error)
	Get(context.Context, string, string) (OperationV1, error)
	Transition(context.Context, string, int64, Status, string, time.Time) (OperationV1, error)
}
type DeviceRepository = cloudapproval.DeviceKeyRepository

func ScopeDigest(value ScopeV1) (string, error) {
	if value.Validate() != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(value)
}
func validUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
func CanonicalUUID(value string) bool { return validUUID(value) }
func safe(value string) bool {
	return strings.TrimSpace(value) == value && len(value) > 0 && len(value) <= 255 && !security.ContainsLikelySecret(value)
}
func validateMutation(caller MutationScope, owner, key, hash string) error {
	if caller.Validate() != nil || !safe(owner) || !validUUID(key) || !digestPattern.MatchString(hash) {
		return ErrInvalid
	}
	return nil
}
func requestHash(value any) (string, error) {
	digest, err := canonical.Digest(value)
	if err != nil {
		return "", fmt.Errorf("%w: request hash", ErrInvalid)
	}
	return digest, nil
}
func SignatureFor(challenge ChallengeV1, key ed25519.PrivateKey) (SignatureV1, error) {
	payload, err := challenge.SigningPayload()
	if err != nil || len(key) != ed25519.PrivateKeySize {
		return SignatureV1{}, ErrInvalid
	}
	return SignatureV1{ChallengeID: challenge.ChallengeID, ApprovalID: challenge.ApprovalID, SignerKeyID: challenge.SignerKeyID, Signature: ed25519.Sign(key, payload)}, nil
}
func signatureValid(challenge ChallengeV1, signature SignatureV1, key ed25519.PublicKey, now time.Time) error {
	if signature.ChallengeID != challenge.ChallengeID || signature.ApprovalID != challenge.ApprovalID || signature.SignerKeyID != challenge.SignerKeyID || len(signature.Signature) != ed25519.SignatureSize || !now.Before(challenge.ExpiresAt) {
		return ErrApprovalRequired
	}
	payload, err := challenge.SigningPayload()
	if err != nil || !ed25519.Verify(key, payload, signature.Signature) {
		return ErrApprovalRequired
	}
	return nil
}
func deterministicID(agentID, domain string, caller MutationScope, key string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(agentID+"\x00"+domain+"\x00"+caller.ClientID+"\x00"+caller.CredentialID+"\x00"+key)).String()
}
func hashCommand(value any) (string, error) {
	hash, err := requestHash(value)
	if err != nil {
		return "", err
	}
	if hash == "" {
		return "", ErrInvalid
	}
	return hash, nil
}

var _ = sha256.Size
