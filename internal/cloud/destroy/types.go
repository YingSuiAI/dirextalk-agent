// Package destroy defines the device-approved, durable manual-destruction
// contract. It contains no provider or RPC implementation.
package destroy

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

const (
	ScopeSchemaV1     = "dirextalk.agent.cloud-deployment-destroy-scope/v1"
	SigningPayloadV1  = "dirextalk.agent.cloud-deployment-destroy-approval/v1"
	ChallengeValidity = 5 * time.Minute
)

var (
	ErrInvalid             = errors.New("invalid cloud destroy request")
	ErrNotFound            = errors.New("cloud destroy operation not found")
	ErrRevisionConflict    = errors.New("cloud destroy revision conflict")
	ErrIdempotencyConflict = errors.New("cloud destroy idempotency conflict")
	ErrApprovalRequired    = errors.New("valid cloud destroy device approval is required")
	ErrManaged             = errors.New("managed resources cannot use ephemeral manual destroy")
	ErrUnavailable         = errors.New("cloud destroy persistence is unavailable")
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

type ReadBackScopeV1 struct {
	Observed   bool      `json:"observed"`
	Exists     bool      `json:"exists"`
	ProviderID string    `json:"provider_id"`
	ObservedAt time.Time `json:"observed_at"`
	TagDigest  string    `json:"tag_digest"`
}

type ResourceScopeV1 struct {
	ResourceID          string               `json:"resource_id"`
	Type                resource.Type        `json:"type"`
	ProviderID          string               `json:"provider_id"`
	Revision            int64                `json:"revision"`
	DependsOn           []string             `json:"depends_on_resource_ids"`
	Retention           task.RetentionPolicy `json:"retention_policy"`
	State               resource.State       `json:"status"`
	Region              string               `json:"region"`
	SpecDigest          string               `json:"spec_digest"`
	ApprovedPlanHash    string               `json:"approved_plan_hash"`
	OriginalApprovalID  string               `json:"original_approval_id"`
	ReadBack            ReadBackScopeV1      `json:"read_back"`
	DestroyDeadline     time.Time            `json:"destroy_deadline"`
	AutoDestroyApproved bool                 `json:"auto_destroy_approved"`
}

type ScopeV1 struct {
	SchemaVersion      string            `json:"schema_version"`
	AgentInstanceID    string            `json:"agent_instance_id"`
	OwnerID            string            `json:"owner_id"`
	DeploymentID       string            `json:"deployment_id"`
	DeploymentRevision int64             `json:"deployment_revision"`
	TaskID             string            `json:"task_id"`
	PlanID             string            `json:"plan_id"`
	PlanHash           string            `json:"plan_hash"`
	ConnectionID       string            `json:"connection_id"`
	Resources          []ResourceScopeV1 `json:"resources"`
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

type SignatureV1 struct {
	ApprovalID  string
	ChallengeID string
	SignerKeyID string
	ExpiresAt   time.Time
	Signature   []byte
}

type Status string

const (
	StatusAwaitingApproval  Status = "awaiting_approval"
	StatusApproved          Status = "approved"
	StatusDestroying        Status = "destroying"
	StatusVerifiedDestroyed Status = "verified_destroyed"
	StatusDestroyBlocked    Status = "destroy_blocked"
)

type OperationV1 struct {
	Challenge     ChallengeV1 `json:"challenge"`
	Status        Status      `json:"status"`
	Signature     []byte      `json:"-"`
	ErrorCode     string      `json:"error_code,omitempty"`
	BlockedReason string      `json:"blocked_reason,omitempty"`
	Revision      int64       `json:"revision"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
	ApprovedAt    *time.Time  `json:"approved_at,omitempty"`
}

type Mutation struct {
	Caller         MutationScope
	OwnerID        string
	IdempotencyKey string
	RequestHash    [sha256.Size]byte
}

func (mutation Mutation) Validate() error {
	if mutation.Caller.Validate() != nil || strings.TrimSpace(mutation.OwnerID) == "" || len(mutation.OwnerID) > 255 || security.ContainsLikelySecret(mutation.OwnerID) {
		return ErrInvalid
	}
	if parsed, err := uuid.Parse(strings.TrimSpace(mutation.IdempotencyKey)); err != nil || parsed == uuid.Nil {
		return ErrInvalid
	}
	if mutation.RequestHash == ([sha256.Size]byte{}) {
		return ErrInvalid
	}
	return nil
}

type Repository interface {
	CreateDestroyChallenge(context.Context, Mutation, ChallengeV1) (ChallengeV1, error)
	GetDestroyChallenge(context.Context, string, string) (ChallengeV1, error)
	ApproveDestroy(context.Context, Mutation, string, int64, SignatureV1, time.Time) (OperationV1, error)
	GetDestroyOperation(context.Context, string, string) (OperationV1, error)
	ListPendingDestroy(context.Context, int) ([]OperationV1, error)
	SaveDestroyOperation(context.Context, OperationV1, int64) (OperationV1, error)
}

func (challenge ChallengeV1) SigningPayload() ([]byte, error) {
	if err := challenge.Validate(); err != nil {
		return nil, err
	}
	document := struct {
		PayloadSchema string    `json:"payload_schema"`
		OperationID   string    `json:"operation_id"`
		ChallengeID   string    `json:"challenge_id"`
		ApprovalID    string    `json:"approval_id"`
		SignerKeyID   string    `json:"signer_key_id"`
		Scope         ScopeV1   `json:"scope"`
		ExpiresAt     time.Time `json:"expires_at"`
	}{SigningPayloadV1, challenge.OperationID, challenge.ChallengeID, challenge.ApprovalID, challenge.SignerKeyID, challenge.Scope, challenge.ExpiresAt.UTC()}
	return canonical.Marshal(document)
}

func (challenge ChallengeV1) Validate() error {
	for _, value := range []string{challenge.OperationID, challenge.ChallengeID, challenge.ApprovalID, challenge.Scope.AgentInstanceID,
		challenge.Scope.DeploymentID, challenge.Scope.TaskID, challenge.Scope.PlanID, challenge.Scope.ConnectionID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return ErrInvalid
		}
	}
	if challenge.Scope.SchemaVersion != ScopeSchemaV1 || challenge.Scope.OwnerID == "" || challenge.SignerKeyID == "" ||
		challenge.Scope.DeploymentRevision < 1 || challenge.Revision != 1 || challenge.IssuedAt.IsZero() ||
		!challenge.IssuedAt.Before(challenge.ExpiresAt) || challenge.ExpiresAt.Sub(challenge.IssuedAt) > ChallengeValidity ||
		len(challenge.Scope.Resources) == 0 || !strings.HasPrefix(challenge.Scope.PlanHash, "sha256:") ||
		!strings.HasPrefix(challenge.ScopeDigest, "sha256:") {
		return ErrInvalid
	}
	return validateScopeResourceGraph(challenge.Scope.Resources)
}

func NormalizeScope(scope ScopeV1) ScopeV1 {
	scope.Resources = slices.Clone(scope.Resources)
	for index := range scope.Resources {
		scope.Resources[index].DependsOn = append([]string{}, scope.Resources[index].DependsOn...)
		slices.Sort(scope.Resources[index].DependsOn)
		scope.Resources[index].DestroyDeadline = scope.Resources[index].DestroyDeadline.UTC()
		scope.Resources[index].ReadBack.ObservedAt = scope.Resources[index].ReadBack.ObservedAt.UTC()
	}
	slices.SortFunc(scope.Resources, func(left, right ResourceScopeV1) int { return strings.Compare(left.ResourceID, right.ResourceID) })
	return scope
}

func ScopeDigest(scope ScopeV1) (string, error) {
	if err := validateScopeResourceGraph(scope.Resources); err != nil {
		return "", err
	}
	return canonical.Digest(NormalizeScope(scope))
}

// validateScopeResourceGraph closes the signed manual-destroy graph before it
// reaches the typed resource lifecycle. It intentionally validates graph
// identity only: the resource service remains the single source of truth for
// dependency readiness, provider deletion, and read-back evidence.
func validateScopeResourceGraph(resources []ResourceScopeV1) error {
	if len(resources) == 0 {
		return ErrInvalid
	}
	byID := make(map[string]ResourceScopeV1, len(resources))
	for _, item := range resources {
		parsed, err := uuid.Parse(strings.TrimSpace(item.ResourceID))
		if err != nil || parsed == uuid.Nil || !supportedResourceType(item.Type) {
			return ErrInvalid
		}
		if item.Retention == task.RetentionManaged || item.State == resource.StateRetainedManaged {
			return ErrManaged
		}
		if item.Retention != task.RetentionEphemeralAutoDestroy {
			return ErrInvalid
		}
		resourceID := parsed.String()
		if _, duplicate := byID[resourceID]; duplicate {
			return ErrInvalid
		}
		byID[resourceID] = item
	}
	for resourceID, item := range byID {
		seen := make(map[string]struct{}, len(item.DependsOn))
		for _, dependency := range item.DependsOn {
			parsed, err := uuid.Parse(strings.TrimSpace(dependency))
			if err != nil || parsed == uuid.Nil || parsed.String() == resourceID {
				return ErrInvalid
			}
			dependencyID := parsed.String()
			if _, duplicate := seen[dependencyID]; duplicate {
				return ErrInvalid
			}
			if _, exists := byID[dependencyID]; !exists {
				return ErrInvalid
			}
			seen[dependencyID] = struct{}{}
		}
	}

	state := make(map[string]uint8, len(byID))
	var visit func(string) error
	visit = func(resourceID string) error {
		switch state[resourceID] {
		case 1:
			return ErrInvalid
		case 2:
			return nil
		}
		state[resourceID] = 1
		for _, dependency := range byID[resourceID].DependsOn {
			parsed, err := uuid.Parse(strings.TrimSpace(dependency))
			if err != nil {
				return ErrInvalid
			}
			if err := visit(parsed.String()); err != nil {
				return err
			}
		}
		state[resourceID] = 2
		return nil
	}
	resourceIDs := make([]string, 0, len(byID))
	for resourceID := range byID {
		resourceIDs = append(resourceIDs, resourceID)
	}
	sort.Strings(resourceIDs)
	for _, resourceID := range resourceIDs {
		if err := visit(resourceID); err != nil {
			return err
		}
	}
	return nil
}

func supportedResourceType(value resource.Type) bool {
	switch value {
	case resource.TypeEC2, resource.TypeEBS, resource.TypeENI, resource.TypeSG,
		resource.TypeALB, resource.TypeTargetGroup, resource.TypeListener, resource.TypeSecurityGroupRule:
		return true
	default:
		return false
	}
}

func (signature SignatureV1) Validate() error {
	for _, value := range []string{signature.ApprovalID, signature.ChallengeID} {
		if parsed, err := uuid.Parse(strings.TrimSpace(value)); err != nil || parsed == uuid.Nil {
			return ErrInvalid
		}
	}
	if signature.SignerKeyID == "" || signature.ExpiresAt.IsZero() || len(signature.Signature) != ed25519.SignatureSize {
		return ErrInvalid
	}
	return nil
}

func ValidateOperation(value OperationV1) error {
	if value.Challenge.Validate() != nil || value.Revision < 1 || value.CreatedAt.IsZero() || value.UpdatedAt.Before(value.CreatedAt) ||
		len(value.ErrorCode) > 128 || len(value.BlockedReason) > 512 || security.ContainsLikelySecret(value.BlockedReason) {
		return ErrInvalid
	}
	switch value.Status {
	case StatusAwaitingApproval:
		if len(value.Signature) != 0 || value.ApprovedAt != nil {
			return ErrInvalid
		}
	case StatusApproved, StatusDestroying, StatusVerifiedDestroyed, StatusDestroyBlocked:
		if len(value.Signature) != ed25519.SignatureSize || value.ApprovedAt == nil || value.ApprovedAt.IsZero() {
			return ErrInvalid
		}
	default:
		return fmt.Errorf("%w: invalid destroy status", ErrInvalid)
	}
	return nil
}
