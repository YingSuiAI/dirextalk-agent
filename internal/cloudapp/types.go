// Package cloudapp defines the typed application boundary used by gRPC and
// the native cloud-dispatcher Skill. It exposes no AWS credentials, SDK
// clients, shell, or arbitrary provider operation.
package cloudapp

import (
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

var (
	ErrInvalid            = errors.New("invalid cloud control request")
	ErrNotFound           = errors.New("cloud control entity not found")
	ErrForbidden          = errors.New("cloud control caller is not authorized for this entity")
	ErrRevisionConflict   = errors.New("cloud control revision conflict")
	ErrApprovalRequired   = errors.New("valid device approval is required")
	ErrQuoteExpired       = errors.New("cloud quote expired or scope changed")
	ErrCapabilityNotReady = errors.New("worker-control PrivateLink capability is not ready")
	ErrUnavailable        = errors.New("cloud provider unavailable")
)

type MutationScope struct {
	ClientID     string
	CredentialID string
}

type Capabilities struct {
	AWS       bool
	DirectSTS bool
	Worker    bool
	Reaper    bool
}

// WorkerControlPrivateLinkCapability is the process-local readiness seam for
// every operation whose signed or provider scope contains worker_control.
type WorkerControlPrivateLinkCapability interface {
	WorkerControlPrivateLinkReady() bool
}

type AWSIdentity struct {
	AccountID    string
	PrincipalARN string
	PrincipalID  string
	Region       string
	RootIdentity bool
}

type AWSIdentityEvidence struct {
	BootstrapSessionID string
	SessionRevision    uint64
	AgentInstanceID    string
	OwnerID            string
	TargetID           string
	Identity           AWSIdentity
	ObservedAt         time.Time
	ExpiresAt          time.Time
}

type AWSIdentityRepository interface {
	PutAWSIdentityEvidence(context.Context, AWSIdentityEvidence) error
	GetAWSIdentityEvidence(context.Context, string, uint64) (AWSIdentityEvidence, error)
}

type ConnectionRepository interface {
	BeginFoundationOperation(context.Context, MutationScope, FoundationOperationIntent) (FoundationOperation, bool, error)
	ListRecoverableFoundationOperations(context.Context, int) ([]FoundationOperation, error)
	MarkFoundationOperationRunning(context.Context, string, int64) (FoundationOperation, error)
	FinalizeFoundationOperation(context.Context, string, int64, string, uint64, Connection) (FoundationOperation, error)
	FailFoundationOperation(context.Context, string, int64, bool, string) (FoundationOperation, error)
}

// FoundationLaunchHandoff is the de-secreted, caller-bound command implied by
// a succeeded Foundation operation. PostgreSQL retains the Foundation fact as
// an outbox until the matching cloud launch intent exists, so a transient
// launch-store failure cannot strand an active, billable Connection.
type FoundationLaunchHandoff struct {
	Caller     MutationScope
	OwnerID    string
	PlanID     string
	ApprovalID string
}

type FoundationLaunchHandoffRepository interface {
	ListPendingFoundationLaunchHandoffs(context.Context, int) ([]FoundationLaunchHandoff, error)
}

type Connection struct {
	ConnectionID    string
	OwnerID         string
	AccountID       string
	Region          string
	ControlRoleARN  string
	FoundationStack string
	Status          string
	Revision        int64
}

type FoundationOperationStatus string

const (
	FoundationOperationIntentStatus    FoundationOperationStatus = "intent"
	FoundationOperationRunning         FoundationOperationStatus = "running"
	FoundationOperationSucceeded       FoundationOperationStatus = "succeeded"
	FoundationOperationFailedRetriable FoundationOperationStatus = "failed_retriable"
	FoundationOperationDestroyBlocked  FoundationOperationStatus = "destroy_blocked"
)

type FoundationOperationIntent struct {
	Caller                       MutationScope
	OperationID                  string
	IdempotencyKey               string
	RequestHash                  [32]byte
	OwnerID                      string
	BootstrapSessionID           string
	PlanID                       string
	ConnectionID                 string
	AccountID                    string
	Region                       string
	ExpectedCredentialGeneration uint64
	ExpectedSessionRevision      uint64
	ReaperImageURI               string
}

type FoundationOperation struct {
	FoundationOperationIntent
	Status        FoundationOperationStatus
	Connection    *Connection
	RedactedError string
	Revision      int64
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type RecipeResolver interface {
	ResolveRecipe(context.Context, string, string, string) (recipe.RecipeV1, error)
}

// CloudFactRepository is the durable fact boundary used by Coordinator. Its
// implementation owns caller-scoped idempotency and atomic approval/challenge
// transitions; provider calls never occur inside this interface.
type CloudFactRepository interface {
	PersistQuote(context.Context, MutationScope, string, [32]byte, cloudquote.QuoteV1) (cloudquote.QuoteV1, error)
	LoadQuote(context.Context, string, string) (cloudquote.QuoteV1, error)
	PersistPlan(context.Context, MutationScope, string, cloudapproval.PlanV1) (cloudapproval.PlanV1, error)
	LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
	PersistChallenge(context.Context, MutationScope, string, cloudapproval.ChallengeV1) (cloudapproval.ChallengeV1, error)
	LoadChallenge(context.Context, string) (cloudapproval.ChallengeV1, error)
	PersistApproval(context.Context, MutationScope, string, uint64, uint64, cloudapproval.ApprovalV1) (cloudapproval.PlanV1, error)
	LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error)
}

type RegisterApprovalDeviceCommand struct {
	IdempotencyKey string
	OwnerID        string
	KeyID          string
	PublicKey      ed25519.PublicKey
	NotBefore      time.Time
	ExpiresAt      time.Time
}

type RevokeApprovalDeviceCommand struct {
	IdempotencyKey   string
	KeyID            string
	ExpectedRevision uint64
}

type ApprovalDeviceAdmin interface {
	RegisterApprovalDevice(context.Context, MutationScope, RegisterApprovalDeviceCommand) (cloudapproval.DeviceKeyV1, error)
	RevokeApprovalDevice(context.Context, MutationScope, RevokeApprovalDeviceCommand) (cloudapproval.DeviceKeyV1, error)
}

type CreateQuoteCommand struct {
	IdempotencyKey          string
	BootstrapSessionID      string
	ExpectedSessionRevision uint64
	Scopes                  []cloudquote.ScopeV1
	Usage                   cloudquote.UsageV1
	SpotQualification       *cloudquote.SpotQualificationV1
}

type CreatePlanCommand struct {
	IdempotencyKey string
	QuoteID        string
	CandidateID    cloudquote.CandidateProfile
	CurrentScope   cloudquote.ScopeV1
}

type CreateChallengeCommand struct {
	IdempotencyKey   string
	OwnerID          string
	PlanID           string
	ExpectedRevision uint64
	SignerKeyID      string
}

type Challenge struct {
	ApprovalID  string
	Challenge   cloudapproval.ChallengeV1
	ExpiresAt   time.Time
	SigningCBOR []byte
}

type ApprovalSignature struct {
	ApprovalID  string
	ChallengeID string
	SignerKeyID string
	ExpiresAt   time.Time
	Signature   []byte
}

type ApprovePlanCommand struct {
	IdempotencyKey   string
	OwnerID          string
	PlanID           string
	ExpectedRevision uint64
	Approval         ApprovalSignature
}

type EstablishConnectionCommand struct {
	IdempotencyKey          string
	OwnerID                 string
	BootstrapSessionID      string
	ExpectedSessionRevision uint64
	PlanID                  string
	ExpectedPlanRevision    uint64
	Approval                ApprovalSignature
}

type SubmitApprovedPlanCommand struct {
	OwnerID    string
	PlanID     string
	ApprovalID string
}

// DeploymentLauncher is a durable enqueue boundary. Implementations must
// persist an intent before returning and perform provider work asynchronously;
// they never receive an approval signing key or AWS credential.
type DeploymentLauncher interface {
	SubmitApprovedPlan(context.Context, MutationScope, SubmitApprovedPlanCommand) error
}

type Coordinator interface {
	Capabilities(context.Context) Capabilities
	PreviewAWSIdentity(context.Context, MutationScope, string, uint64, string) (AWSIdentityEvidence, error)
	CreateQuote(context.Context, MutationScope, CreateQuoteCommand) (cloudquote.QuoteV1, error)
	GetQuote(context.Context, string, string) (cloudquote.QuoteV1, error)
	CreatePlan(context.Context, MutationScope, CreatePlanCommand) (cloudapproval.PlanV1, error)
	GetPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
	CreateApprovalChallenge(context.Context, MutationScope, CreateChallengeCommand) (Challenge, error)
	ApprovePlan(context.Context, MutationScope, ApprovePlanCommand) (cloudapproval.PlanV1, error)
	EstablishAWSConnection(context.Context, MutationScope, EstablishConnectionCommand) (Connection, error)
}
