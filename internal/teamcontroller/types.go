// Package teamcontroller advances approved Team roles through a durable,
// replayable control loop. It can coordinate AWS-capable ports, but it never
// receives an AWS SDK client or accepts provider fields from a model.
package teamcontroller

import (
	"context"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamcredential"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerresult"
)

var (
	ErrInvalid      = errors.New("invalid Team controller configuration")
	ErrFactMismatch = errors.New("Team controller fact mismatch")
	ErrNotReady     = errors.New("Team controller dependency is not ready")
	ErrUnsupported  = errors.New("Team controller runtime is unsupported")
)

type InputMaterializer interface {
	Materialize(
		context.Context,
		task.MutationScope,
		teaminput.MaterializeRequest,
	) (teaminput.PreparedInput, error)
}

type ExecutionDispatcher interface {
	BeginDispatch(
		context.Context,
		task.MutationScope,
		teamexecution.BeginDispatchRequest,
	) (teamexecution.Fact, error)
}

type WorkspaceContentSource interface {
	LoadRoleWorkspaceContent(
		context.Context,
		teamdispatch.IntentV1,
		teaminput.MaterializationV1,
	) (awsartifact.TeamWorkspaceContent, error)
}

type CredentialBuilder interface {
	Build(teamcredential.BuildRequest) (teamcredential.RoleBundles, error)
}

type ArtifactPublisher interface {
	PublishTeamInputs(
		context.Context,
		cloudapp.Connection,
		string,
		teaminput.CompiledInput,
		awsartifact.TeamWorkspaceContent,
	) error
	PublishBundles(
		context.Context,
		cloudapp.Connection,
		string,
		cloudexecution.CompiledBundles,
		[]string,
	) (cloudexecution.PublishedBundles, error)
}

type ConnectionReader interface {
	LoadConnection(
		context.Context,
		string,
		string,
	) (cloudapp.Connection, error)
}

type WorkerControl interface {
	CreateDeployment(
		context.Context,
		cloudexecution.WorkerCreateMutation,
		worker.CreateDeploymentRequest,
	) (worker.Deployment, cloudexecution.SensitiveCredential, error)
	GetDeployment(
		context.Context,
		string,
	) (worker.Deployment, error)
	RequestCancel(
		context.Context,
		string,
		string,
	) (worker.Deployment, error)
	ExpireLease(context.Context, string) (worker.Deployment, error)
}

type BootstrapPublisher interface {
	PublishBootstrap(
		context.Context,
		cloudapp.Connection,
		cloudexecution.BootstrapRequest,
	) (cloudexecution.BootstrapArtifact, error)
}

type FreshOfferSource interface {
	BuildForConnection(
		context.Context,
		string,
		string,
	) (*teamplan.OfferSnapshot, error)
}

type ResourceProvisioner interface {
	Provision(
		context.Context,
		cloudapp.Connection,
		resource.ProvisionSpec,
		resource.ProviderCreateAuthorization,
	) (resource.ResourceV1, error)
}

type ResultCollector interface {
	Collect(
		context.Context,
		cloudapp.Connection,
		worker.Deployment,
	) (workerresult.Collected, error)
}

type RoleCleanup interface {
	DestroyRole(
		context.Context,
		cloudapp.Connection,
		teamdispatch.Fact,
	) (bool, error)
}

type ExecutionFinalizer interface {
	FinalizeReadyTeamExecutions(
		context.Context,
		task.MutationScope,
		uint32,
	) (uint32, error)
}

type TaskControl interface {
	Get(context.Context, string) (task.Task, error)
	Cancel(
		context.Context,
		task.MutationScope,
		task.CancelCommand,
	) (task.Task, error)
}

type PlanExpiryStatus string

const (
	PlanExpiryReadyForConfirmation PlanExpiryStatus = "ready_for_confirmation"
	PlanExpiryExpired              PlanExpiryStatus = "expired"
)

type PlanExpiryWork struct {
	OwnerID        string
	TaskID         string
	PlanID         string
	PlanRevision   uint64
	RecordRevision uint64
	Status         PlanExpiryStatus
	ValidUntil     time.Time
}

type ExpireReadyPlanRequest struct {
	IdempotencyKey         string
	OwnerID                string
	PlanID                 string
	PlanRevision           uint64
	ExpectedRecordRevision uint64
}

type PlanExpiryControl interface {
	ListPlanExpiryWork(
		context.Context,
		uint32,
	) ([]PlanExpiryWork, error)
	ExpireReadyPlan(
		context.Context,
		task.MutationScope,
		ExpireReadyPlanRequest,
	) error
}

type Config struct {
	AgentInstanceID   string
	PollInterval      time.Duration
	BatchSize         uint32
	ArtifactRetention time.Duration
	Now               func() time.Time
	ReportError       func(error)
}

type Dependencies struct {
	Scheduler       *teamdispatch.Service
	Executions      ExecutionDispatcher
	ExecutionQueue  teamdispatch.ExecutionQueueReader
	Dispatches      teamdispatch.Repository
	Authorizations  teamdispatch.AuthorizationReader
	Inputs          InputMaterializer
	Workspaces      WorkspaceContentSource
	Credentials     CredentialBuilder
	Artifacts       ArtifactPublisher
	Connections     ConnectionReader
	Workers         WorkerControl
	Bootstraps      BootstrapPublisher
	Offers          FreshOfferSource
	Resources       ResourceProvisioner
	Results         ResultCollector
	Cleanup         RoleCleanup
	Finalizer       ExecutionFinalizer
	Tasks           TaskControl
	PlanExpirations PlanExpiryControl
}
