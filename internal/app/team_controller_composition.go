package app

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/githubsource"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamcontroller"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamcredential"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamdispatch"
	"github.com/YingSuiAI/dirextalk-agent/internal/teaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
)

// NewTeamController joins the runtime planning authority to the typed AWS
// ports only after both compositions are complete. The controller itself
// receives no AWS SDK client and no model-provided provider fields.
func (composition *CloudComposition) NewTeamController(
	runtime RuntimeComposition,
	offers teamorchestration.TrustedOfferBuilder,
	credentialReadiness *teampricing.CatalogCredentialReadiness,
	sourceSnapshotter *githubsource.Snapshotter,
) (*teamcontroller.Controller, error) {
	if composition == nil ||
		composition.cloudGoalStore == nil ||
		composition.teamInstallerIssuer == nil ||
		composition.teamArtifactPublisher == nil ||
		composition.teamResourceProvisioner == nil ||
		composition.teamWorkerControl == nil ||
		composition.teamBootstrapPublisher == nil ||
		composition.teamResultCollector == nil ||
		composition.teamRoleCleanup == nil ||
		runtime.TeamExecutions == nil ||
		offers == nil ||
		credentialReadiness == nil {
		return nil, teamcontroller.ErrInvalid
	}
	store := composition.cloudGoalStore
	contexts, err := newDurableTeamContextSource(store, store)
	if err != nil {
		return nil, fmt.Errorf("initialize durable Team context source: %w", err)
	}
	emptyWorkspace, err := newEmptyTeamWorkspaceProvider()
	if err != nil {
		return nil, fmt.Errorf("initialize empty Team workspace provider: %w", err)
	}
	var (
		sourceConnections teamSourceConnectionReader
		sourceFacts       githubsource.Repository
		sourcePublisher   githubTeamSourcePublisher
		githubSnapshotter githubTeamSourceSnapshotter
	)
	if normalized := normalizeGitHubSourceSnapshotter(sourceSnapshotter); normalized != nil {
		sourceConnections = store
		sourceFacts = store
		sourcePublisher = composition.teamArtifactPublisher
		githubSnapshotter = normalized
	}
	workspaces, err := newDurableTeamWorkspaceProvider(
		emptyWorkspace,
		store,
		sourceConnections,
		sourceFacts,
		githubSnapshotter,
		sourcePublisher,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize durable Team workspace provider: %w", err)
	}
	inputs, err := teaminput.NewService(
		store,
		contexts,
		workspaces,
		store,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Team input materializer: %w", err)
	}
	credentials, err := teamcredential.NewBuilder(
		composition.teamInstallerIssuer,
		credentialReadiness,
		time.Now,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Team credential builder: %w", err)
	}
	scheduler, err := teamdispatch.NewService(
		store,
		store,
		store,
		time.Now,
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Team scheduler: %w", err)
	}
	controller, err := teamcontroller.New(
		teamcontroller.Config{
			AgentInstanceID: composition.agentInstanceID,
			PollInterval:    2 * time.Second,
			BatchSize:       64,
			Now:             time.Now,
			ReportError: func(err error) {
				slog.Warn(
					"Team controller reconciliation failed",
					"error",
					security.RedactText(err.Error()),
				)
			},
		},
		teamcontroller.Dependencies{
			Scheduler:       scheduler,
			Executions:      runtime.TeamExecutions,
			ExecutionQueue:  store,
			Dispatches:      store,
			Authorizations:  store,
			Inputs:          inputs,
			Workspaces:      workspaces,
			Credentials:     credentials,
			Artifacts:       composition.teamArtifactPublisher,
			Connections:     store,
			Workers:         composition.teamWorkerControl,
			Bootstraps:      composition.teamBootstrapPublisher,
			Offers:          offers,
			Resources:       composition.teamResourceProvisioner,
			Results:         composition.teamResultCollector,
			Cleanup:         composition.teamRoleCleanup,
			Finalizer:       store,
			Tasks:           store,
			PlanExpirations: store,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Team reconciliation controller: %w", err)
	}
	return controller, nil
}

func normalizeGitHubSourceSnapshotter(
	snapshotter *githubsource.Snapshotter,
) githubTeamSourceSnapshotter {
	if snapshotter == nil {
		return nil
	}
	return snapshotter
}

var _ teamcontroller.ExecutionFinalizer = (*postgres.Store)(nil)
var _ teamcontroller.PlanExpiryControl = (*postgres.Store)(nil)
