// Package cloudexecution turns one device-approved cloud Plan into a durable
// Task, an exclusive Worker deployment, immutable artifacts, and a typed AWS
// resource graph. It is application code: it never exposes an AWS SDK client,
// raw provider operation, shell command, or credential to Eino.
package cloudexecution

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
)

var (
	ErrInvalid           = errors.New("invalid cloud execution request")
	ErrNotReady          = errors.New("cloud execution prerequisites are not ready")
	ErrRevisionConflict  = errors.New("cloud execution revision conflict")
	ErrUnsupportedRecipe = errors.New("recipe requires an unavailable Worker action")
	ErrUnavailable       = errors.New("cloud execution dependency unavailable")
)

type State string

const (
	StateIntent           State = "intent"
	StateTaskReady        State = "task_ready"
	StateBundlesReady     State = "bundles_ready"
	StateWorkerRegistered State = "worker_registered"
	StateBootstrapReady   State = "bootstrap_ready"
	StateProvisioning     State = "provisioning"
	StateActive           State = "active"
	StateFailedRetriable  State = "failed_retriable"
	StateDestroyBlocked   State = "destroy_blocked"
)

type LaunchRequest struct {
	IdempotencyKey     string
	OwnerID            string
	PlanID             string
	ApprovalID         string
	ControlPlaneTarget string
}

type Intent struct {
	OperationID      string
	RequestHash      [sha256.Size]byte
	Caller           cloudapp.MutationScope
	SecretClientID   string
	Launch           LaunchRequest
	ConnectionID     string
	ApprovedPlanHash string
	TaskStepID       string
	DeploymentID     string
	RecordedAt       time.Time
}

type PublishedBundle struct {
	Reference worker.BundleRef
}

type PublishedBundles struct {
	Recipe             worker.BundleRef
	Execution          worker.BundleRef
	Launch             BootstrapArtifact
	Access             worker.AccessScope
	SecretBindings     map[string]string
	InstallerRootTrust *InstallerRootTrustV1
	InstallerArtifacts []installerbootstrap.ArtifactSourceV1
	InstallerSecrets   []installerbootstrap.SecretSourceV1
}

// InstallerArtifactContent is an already-resolved, replayable byte source.
// Publication never resolves a URL or performs arbitrary HTTP; a later
// official-artifact resolver may provide this typed input.
type InstallerArtifactContent interface {
	Open(context.Context) (io.ReadSeekCloser, error)
	Cleanup() error
}

type InstallerArtifactStagingInput struct {
	Name         string
	SourceID     string
	SHA256       string
	SizeBytes    int64
	TargetPath   string
	RecipeDigest string
	Content      InstallerArtifactContent
}

type InstallerArtifactResolveRequest struct {
	SourceID     string
	SourceURL    string
	Official     bool
	SHA256       string
	SizeBytes    int64
	TargetPath   string
	RecipeDigest string
}

type InstallerArtifactResolver interface {
	Resolve(context.Context, InstallerArtifactResolveRequest) (InstallerArtifactContent, error)
}

// InstallerSecretContent performs one-use secret delivery without returning
// plaintext to cloudexecution. Materialize is retryable while the encrypted
// bootstrap session remains uploaded; Commit consumes it only after the AWS
// destination has been independently read back.
type InstallerSecretContent interface {
	Materialize(context.Context, func([]byte) error) error
	Commit(context.Context, func() error) error
}

type InstallerSecretStagingInput struct {
	SlotID       string
	SecretRef    string
	SecretName   string
	VersionID    string
	TargetPath   string
	FileMode     uint32
	OwnerUID     uint32
	OwnerGID     uint32
	RecipeDigest string
	Content      InstallerSecretContent
}

type InstallerSecretResolveRequest struct {
	CallerClientID string
	OwnerID        string
	PlanID         string
	SlotID         string
	Purpose        string
	SecretRef      string
	SecretName     string
	VersionID      string
	TargetPath     string
	FileMode       uint32
	OwnerUID       uint32
	OwnerGID       uint32
	RecipeDigest   string
}

type InstallerSecretResolver interface {
	Resolve(context.Context, InstallerSecretResolveRequest) (InstallerSecretContent, error)
}

// BootstrapArtifact is a non-secret immutable object consumed by the fixed
// Worker AMI bootstrap. EnrollmentMaterialRef may name a deployment-scoped,
// KMS-protected delivery channel, but may never contain credential bytes.
type BootstrapArtifact struct {
	Reference             string
	SHA256                [sha256.Size]byte
	EnrollmentMaterialRef string
}

type Operation struct {
	Intent
	State               State
	TaskID              string
	RecipeBundle        worker.BundleRef
	ExecutionBundle     worker.BundleRef
	InstallerDelivery   *installer.DeliveryV1
	InstallerCommandIDs []string
	InstallerRootTrust  *InstallerRootTrustV1
	InstallerArtifacts  []installerbootstrap.ArtifactSourceV1
	InstallerSecrets    []installerbootstrap.SecretSourceV1
	Bootstrap           BootstrapArtifact
	ResourceIDs         []string
	RedactedError       string
	Revision            int64
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

type Repository interface {
	Begin(context.Context, Intent) (Operation, bool, error)
	Save(context.Context, Operation, int64) (Operation, error)
	GetByPlan(context.Context, string, string) (Operation, error)
	ListRecoverable(context.Context, int) ([]Operation, error)
}

type FactReader interface {
	LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error)
	LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error)
}

type ConnectionReader interface {
	LoadConnection(context.Context, string, string) (cloudapp.Connection, error)
}

type RecipeResolver interface {
	ResolveRecipe(context.Context, string, string, string) (recipe.RecipeV1, error)
}

type TaskCreator interface {
	Create(context.Context, task.MutationScope, task.CreateCommand) (task.Task, error)
}

type BundlePublisher interface {
	PublishBundles(context.Context, cloudapp.Connection, string, CompiledBundles, []string) (PublishedBundles, error)
}

// WorkerCreator must provide caller-scoped, request-bound idempotency and
// encrypted replay of the one-time credential after response loss.
type WorkerCreator interface {
	CreateDeployment(context.Context, WorkerCreateMutation, worker.CreateDeploymentRequest) (worker.Deployment, SensitiveCredential, error)
}

type SensitiveCredential interface {
	Reveal() []byte
	Destroy()
}

type WorkerCreateMutation struct {
	ClientID       string
	CredentialID   string
	IdempotencyKey string
}

// BootstrapPublisher receives the one-time credential only in memory. It must
// place it in a deployment-scoped encrypted delivery channel and wipe its
// local copy. The returned launch artifact itself must be non-secret because
// EC2 user-data contains only its S3 reference and digest.
type BootstrapPublisher interface {
	PublishBootstrap(context.Context, cloudapp.Connection, BootstrapRequest) (BootstrapArtifact, error)
}

type BootstrapRequest struct {
	DeploymentID         string
	WorkerID             string
	ControlPlaneTarget   string
	Launch               BootstrapArtifact
	EnrollmentCredential []byte
	EnrollmentRevision   int64
}

type ResourceProvisioner interface {
	Provision(context.Context, cloudapp.Connection, resource.ProvisionSpec, resource.ProviderCreateAuthorization) (resource.ResourceV1, error)
}

type ResourcePlanBuilder interface {
	Build(cloudapproval.PlanV1, cloudapp.Connection, recipe.RecipeV1, Operation) ([]resource.ProvisionSpec, error)
}
