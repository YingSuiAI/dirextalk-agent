package app

import (
	"context"
	"crypto/rand"
	"errors"
	"time"

	awsfoundationassets "github.com/YingSuiAI/dirextalk-agent/deploy/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
)

type CloudComposition struct {
	Coordinator                cloudapp.Coordinator
	DestroyCoordinator         *clouddestroy.Service
	Dispatcher                 *cloudexecution.Dispatcher
	Lifecycle                  *cloudexecution.EphemeralDestroyController
	WorkerIdentityVerifier     *workeridentity.Verifier
	WorkerIdentityMaterializer *workerIdentityMaterializer
	FoundationConnections      *cloudapp.AWSConnectionService
	ActiveQuotes               *cloudapp.AWSActiveQuoteEngine
	ActivePlacements           *cloudapp.AWSActivePlacementResolver
	ProviderPlans              planning.ProviderPlanMaterializer
	ManifestRecovery           *resourceManifestRecovery
	foundationLaunches         *foundationLaunchCompensator
	agentInstanceID            string
	cloudGoalStore             *postgres.Store
	vault                      *awsfoundation.CredentialVault
}

// NewCloudGoalOutputAdapter composes the durable provider path only after a
// real model/research implementation is supplied. Startup intentionally does
// not install a stub model or fabricate planning output.
func (composition *CloudComposition) NewCloudGoalOutputAdapter(model planning.CloudGoalPlanningModel) (*planning.PersistentCloudGoalOutputAdapter, error) {
	if composition == nil || composition.cloudGoalStore == nil || composition.ProviderPlans == nil || model == nil {
		return nil, errors.New("cloud Goal planning dependencies are unavailable")
	}
	return planning.NewPersistentCloudGoalOutputAdapter(
		composition.agentInstanceID, composition.cloudGoalStore, composition.cloudGoalStore,
		model, composition.ProviderPlans, composition.cloudGoalStore, time.Now,
	)
}

// Recover resumes exact, pre-authorized Foundation operations and persists any
// missing post-Foundation launch handoff before accepting new cloud mutations.
func (composition *CloudComposition) Recover(ctx context.Context) error {
	if composition == nil || composition.FoundationConnections == nil || composition.foundationLaunches == nil || composition.ManifestRecovery == nil || composition.Lifecycle == nil || ctx == nil {
		return errors.New("Foundation recovery is unavailable")
	}
	if err := composition.FoundationConnections.RecoverPendingFoundationOperations(ctx, 64); err != nil {
		return err
	}
	if err := composition.foundationLaunches.RunOnce(ctx); err != nil {
		return err
	}
	if err := composition.ManifestRecovery.RunOnce(ctx); err != nil {
		return err
	}
	return composition.Lifecycle.RunOnce(ctx)
}

func (composition *CloudComposition) Close() {
	if composition != nil && composition.vault != nil {
		composition.vault.Close()
	}
}

func (composition *CloudComposition) Run(ctx context.Context) error {
	if composition == nil || composition.Dispatcher == nil || composition.Lifecycle == nil || composition.foundationLaunches == nil || composition.ManifestRecovery == nil || ctx == nil {
		return errors.New("cloud dispatcher is unavailable")
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, 4)
	go func() { errorsChannel <- composition.Dispatcher.Run(runContext) }()
	go func() { errorsChannel <- composition.Lifecycle.Run(runContext) }()
	go func() { errorsChannel <- composition.foundationLaunches.Run(runContext) }()
	go func() { errorsChannel <- composition.ManifestRecovery.Run(runContext) }()
	first := <-errorsChannel
	cancel()
	runErrors := []error{first, <-errorsChannel, <-errorsChannel, <-errorsChannel}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var result error
	for _, runErr := range runErrors {
		if runErr != nil && !errors.Is(runErr, context.Canceled) && !errors.Is(runErr, context.DeadlineExceeded) {
			result = errors.Join(result, runErr)
		}
	}
	if result != nil {
		return result
	}
	return first
}

func NewCloudComposition(store *postgres.Store, manager *secretbootstrap.Manager, workerStore *postgres.WorkerStore, workerService *worker.Service, agentInstanceID string, masterKey []byte, reaperImageURI, workerControlTarget string) (*CloudComposition, error) {
	if store == nil || manager == nil || workerStore == nil || workerService == nil || len(masterKey) != 32 || reaperImageURI == "" || workerControlTarget == "" {
		return nil, errors.New("cloud composition requires durable stores, master key, and immutable Reaper image")
	}
	facts, err := postgres.NewCloudAdapter(store)
	if err != nil {
		return nil, err
	}
	approvalReads, err := postgres.NewApprovalReadRepository(store)
	if err != nil {
		return nil, err
	}
	approvalService, err := cloudapproval.NewService(approvalReads, approvalReads, time.Now)
	if err != nil {
		return nil, err
	}
	pricing, err := cloudapp.NewAWSBootstrapQuoteEngine(agentInstanceID, manager, store, store, cloudapp.SDKBootstrapPricingFactory{}, time.Now)
	if err != nil {
		return nil, err
	}
	providerFactory := awsprovider.NewSDKFactory()
	identity, err := cloudapp.NewAWSController(agentInstanceID, manager, providerFactory, store, time.Now)
	if err != nil {
		return nil, err
	}
	vault, err := awsfoundation.NewCredentialVault(store.AWSCredentialStore(), masterKey, rand.Reader, time.Now)
	if err != nil {
		return nil, err
	}
	foundation, err := awsfoundation.NewBootstrapper(providerFactory, vault, awsfoundationassets.Template(), time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	connections, err := cloudapp.NewAWSConnectionService(
		agentInstanceID, reaperImageURI, facts, store, store, manager, foundation, time.Now,
	)
	if err != nil {
		vault.Close()
		return nil, err
	}
	artifactPublisher, err := awsartifact.NewBundlePublisher(agentInstanceID, vault, awsartifact.SDKFactory{})
	if err != nil {
		vault.Close()
		return nil, err
	}
	activeQuotes, err := cloudapp.NewAWSActiveQuoteEngine(agentInstanceID, vault, store, cloudapp.SDKActivePricingFactory{}, time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	activePlacements, err := cloudapp.NewAWSActivePlacementResolver(agentInstanceID, vault, cloudapp.SDKActivePlacementFactory{})
	if err != nil {
		vault.Close()
		return nil, err
	}
	providerPlans, err := newCloudGoalProviderPlanMaterializer(agentInstanceID, store, activePlacements, activeQuotes, facts, time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	principalBinder, err := awsartifact.NewPrincipalBinder(agentInstanceID, vault, awsartifact.SDKFactory{})
	if err != nil {
		vault.Close()
		return nil, err
	}
	workerAdapter, err := cloudexecution.NewWorkerServiceAdapter(workerService)
	if err != nil {
		vault.Close()
		return nil, err
	}
	resourceStore, err := store.NewResourceStore()
	if err != nil {
		vault.Close()
		return nil, err
	}
	runtimeFactory, err := newAWSResourceRuntimeFactory(agentInstanceID, vault, resourceStore)
	if err != nil {
		vault.Close()
		return nil, err
	}
	manifestRecovery, err := newResourceManifestRecovery(
		agentInstanceID, resourceStore, store, store, runtimeFactory,
		trackedManifestGenerationReplayer{store: resourceStore}, 15*time.Second,
	)
	if err != nil {
		vault.Close()
		return nil, err
	}
	identityAuthorizer, err := newWorkerIdentityAuthorizer(agentInstanceID, store, store, resourceStore, workerStore, runtimeFactory)
	if err != nil {
		vault.Close()
		return nil, err
	}
	identityVerifier, err := workeridentity.NewDefaultVerifier(agentInstanceID, identityAuthorizer, time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	identityMaterializer, err := newWorkerIdentityMaterializer(store, store, workerStore, principalBinder)
	if err != nil {
		vault.Close()
		return nil, err
	}
	resourceProvisioner, err := cloudexecution.NewDynamicResourceProvisioner(resourceStore, runtimeFactory)
	if err != nil {
		vault.Close()
		return nil, err
	}
	resourcePlans, err := cloudexecution.NewAWSResourcePlanBuilder(agentInstanceID)
	if err != nil {
		vault.Close()
		return nil, err
	}
	execution, err := cloudexecution.NewService(
		agentInstanceID, facts, store, store, store, artifactPublisher, workerAdapter,
		cloudexecution.NewIdentityBootstrapPublisher(), resourcePlans, resourceProvisioner, store, time.Now,
	)
	if err != nil {
		vault.Close()
		return nil, err
	}
	dispatcher, err := cloudexecution.NewDispatcher(execution, store, 15*time.Second)
	if err != nil {
		vault.Close()
		return nil, err
	}
	lifecycle, err := cloudexecution.NewEphemeralDestroyController(cloudexecution.EphemeralDestroyConfig{
		AgentInstanceID: agentInstanceID, PollInterval: 30 * time.Second,
		Resources: resourceStore, Launches: store, Facts: facts, Connections: store, Tasks: store,
		Lifecycles: awsLifecycleFactory{repository: resourceStore, runtimes: runtimeFactory}, Now: time.Now,
	})
	if err != nil {
		vault.Close()
		return nil, err
	}
	cloudStatuses, err := postgres.NewCloudStatusStore(store)
	if err != nil {
		vault.Close()
		return nil, err
	}
	destroyCoordinator, err := clouddestroy.NewService(agentInstanceID, store, approvalReads, cloudStatuses, facts, lifecycle, time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	if err := lifecycle.ConfigureManualDestroy(store, destroyCoordinator); err != nil {
		vault.Close()
		return nil, err
	}
	launcher := cloudLaunchAdapter{dispatcher: dispatcher, target: workerControlTarget}
	launchCompensator, err := newFoundationLaunchCompensator(store, launcher, 15*time.Second)
	if err != nil {
		vault.Close()
		return nil, err
	}
	coordinator, err := cloudapp.NewService(
		agentInstanceID, facts, store, pricing, approvalService, identity, connections,
		cloudapp.Capabilities{AWS: true, DirectSTS: true, Worker: true, Reaper: true}, time.Now,
		cloudapp.WithDeploymentLauncher(launcher),
	)
	if err != nil {
		vault.Close()
		return nil, err
	}
	return &CloudComposition{
		Coordinator: coordinator, DestroyCoordinator: destroyCoordinator, Dispatcher: dispatcher, Lifecycle: lifecycle,
		WorkerIdentityVerifier: identityVerifier, WorkerIdentityMaterializer: identityMaterializer,
		FoundationConnections: connections, ActiveQuotes: activeQuotes, ActivePlacements: activePlacements, ProviderPlans: providerPlans,
		ManifestRecovery:   manifestRecovery,
		foundationLaunches: launchCompensator,
		agentInstanceID:    agentInstanceID,
		cloudGoalStore:     store,
		vault:              vault,
	}, nil
}
