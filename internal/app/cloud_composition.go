package app

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"time"

	awsfoundationassets "github.com/YingSuiAI/dirextalk-agent/deploy/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/artifactresolver"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/costalert"
	clouddestroy "github.com/YingSuiAI/dirextalk-agent/internal/cloud/destroy"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entryexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	cloudfoundation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/foundation"
	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairingworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretresolver"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeroperation"
)

type CloudComposition struct {
	Coordinator                cloudapp.Coordinator
	DestroyCoordinator         *clouddestroy.Service
	Entrypoint                 *entrypoint.Service
	FoundationLifecycle        *cloudfoundation.Service
	ManagedAcceptance          *cloudmanaged.Service
	ManagedPreparation         *serviceoperation.Service
	Dispatcher                 *cloudexecution.Dispatcher
	Lifecycle                  *cloudexecution.EphemeralDestroyController
	WorkerIdentityVerifier     *workeridentity.Verifier
	WorkerIdentityMaterializer *workerIdentityMaterializer
	FoundationConnections      *cloudapp.AWSConnectionService
	ActiveQuotes               *cloudapp.AWSActiveQuoteEngine
	ActivePlacements           *cloudapp.AWSActivePlacementResolver
	ProviderPlans              planning.ProviderPlanMaterializer
	ManifestRecovery           *resourceManifestRecovery
	HealthProbes               *resource.ProbeService
	HealthProbeReader          cloudstatus.HealthReader
	RootHelperApprovals        *rootHelperApprovalCoordinator
	RootHelperDeliveries       *helperkey.Service
	WorkerOperations           *workeroperation.Service
	RootHelperCapabilities     *productionRootHelperCapabilityIssuer
	Pairing                    *pairingRuntime
	PairingApprovals           *pairing.ApprovalService
	PairingWorkerOperations    *pairingworker.Service
	PairingReceiptVerifier     pairingWorkerReceiptVerifier
	foundationLaunches         *foundationLaunchCompensator
	healthProbeScheduler       *healthProbeScheduler
	orphanRecovery             *orphanRecoveryController
	entryExecutor              entryexecution.Runner
	foundationExecutor         *cloudfoundation.Executor
	managedAcceptanceExecutor  *cloudmanaged.Executor
	managedPreparationRecovery *managedPreparationRecoveryController
	agentInstanceID            string
	cloudGoalStore             *postgres.Store
	vault                      *awsfoundation.CredentialVault
	rootHelperDeriver          *helperkey.DeterministicKeyDeriver
}

type CloudCompositionOption func(*cloudCompositionOptions)

type cloudCompositionOptions struct {
	enableManagedPreparationAWS bool
}

// WithManagedPreparationAWS enables the public ManagedPreparation API and its
// typed AWS recovery loop. It is intentionally opt-in in addition to the
// existing AWS-control gate.
func WithManagedPreparationAWS() CloudCompositionOption {
	return func(options *cloudCompositionOptions) { options.enableManagedPreparationAWS = true }
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
	if composition == nil || composition.FoundationConnections == nil || composition.FoundationLifecycle == nil || composition.foundationExecutor == nil || composition.foundationLaunches == nil || composition.ManifestRecovery == nil || composition.Lifecycle == nil || composition.orphanRecovery == nil || composition.entryExecutor == nil || composition.managedAcceptanceExecutor == nil || composition.managedPreparationRecovery == nil || ctx == nil {
		return errors.New("Foundation recovery is unavailable")
	}
	if err := composition.FoundationConnections.RecoverPendingFoundationOperations(ctx, 64); err != nil {
		return err
	}
	if err := composition.foundationExecutor.RunOnce(ctx); err != nil {
		return err
	}
	if err := composition.foundationLaunches.RunOnce(ctx); err != nil {
		return err
	}
	if err := composition.ManifestRecovery.RunOnce(ctx); err != nil {
		return err
	}
	if err := composition.Lifecycle.RunOnce(ctx); err != nil {
		return err
	}
	if err := composition.managedPreparationRecovery.RunOnce(ctx); err != nil {
		return err
	}
	if err := composition.managedAcceptanceExecutor.RunOnce(ctx); err != nil {
		return err
	}
	if err := composition.orphanRecovery.RunOnce(ctx); err != nil {
		return err
	}
	return composition.entryExecutor.RunOnce(ctx)
}

func (composition *CloudComposition) Close() {
	if composition != nil {
		if composition.rootHelperDeriver != nil {
			composition.rootHelperDeriver.Close()
		}
		if composition.vault != nil {
			composition.vault.Close()
		}
	}
}

func (composition *CloudComposition) Run(ctx context.Context) error {
	if composition == nil || composition.Dispatcher == nil || composition.Lifecycle == nil || composition.FoundationLifecycle == nil || composition.foundationExecutor == nil || composition.foundationLaunches == nil || composition.ManifestRecovery == nil || composition.HealthProbes == nil || composition.healthProbeScheduler == nil || composition.orphanRecovery == nil || composition.entryExecutor == nil || composition.managedAcceptanceExecutor == nil || composition.managedPreparationRecovery == nil || ctx == nil {
		return errors.New("cloud dispatcher is unavailable")
	}
	runContext, cancel := context.WithCancel(ctx)
	defer cancel()
	errorsChannel := make(chan error, 10)
	go func() { errorsChannel <- composition.Dispatcher.Run(runContext) }()
	go func() { errorsChannel <- composition.Lifecycle.Run(runContext) }()
	go func() { errorsChannel <- composition.foundationLaunches.Run(runContext) }()
	go func() { errorsChannel <- composition.ManifestRecovery.Run(runContext) }()
	go func() { errorsChannel <- composition.healthProbeScheduler.Run(runContext) }()
	go func() { errorsChannel <- composition.orphanRecovery.Run(runContext) }()
	go func() { errorsChannel <- composition.entryExecutor.Run(runContext) }()
	go func() { errorsChannel <- composition.foundationExecutor.Run(runContext) }()
	go func() { errorsChannel <- composition.managedAcceptanceExecutor.Run(runContext) }()
	go func() { errorsChannel <- composition.managedPreparationRecovery.Run(runContext) }()
	first := <-errorsChannel
	cancel()
	runErrors := []error{first, <-errorsChannel, <-errorsChannel, <-errorsChannel, <-errorsChannel, <-errorsChannel, <-errorsChannel, <-errorsChannel, <-errorsChannel, <-errorsChannel}
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

func NewCloudComposition(store *postgres.Store, manager *secretbootstrap.Manager, workerStore *postgres.WorkerStore, workerService *worker.Service, installerIssuer *installer.TrustIssuer, agentInstanceID string, masterKey []byte, reaperImageURI, workerControlTarget string, optionValues ...CloudCompositionOption) (*CloudComposition, error) {
	if store == nil || manager == nil || workerStore == nil || workerService == nil || installerIssuer == nil || len(masterKey) != 32 || reaperImageURI == "" || workerControlTarget == "" {
		return nil, errors.New("cloud composition requires durable stores, master key, and immutable Reaper image")
	}
	options := cloudCompositionOptions{}
	for _, option := range optionValues {
		if option != nil {
			option(&options)
		}
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
	deploymentSecrets, err := awsartifact.NewDeploymentSecretLifecycle(agentInstanceID, vault, awsartifact.SDKFactory{})
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
	providerPlans, err := newCloudGoalProviderPlanMaterializer(agentInstanceID, store, activePlacements, activeQuotes, facts, manager, time.Now)
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
	resourceApprovals := destroyResourceApprovalAdapter{store: store}
	healthProbeStore, err := store.NewHealthProbeStore()
	if err != nil {
		vault.Close()
		return nil, err
	}
	healthProbeEngine, err := healthprobe.NewEngine(healthprobe.NewNetworkTransport())
	if err != nil {
		vault.Close()
		return nil, err
	}
	healthProbes, err := resource.NewProbeService(healthProbeEngine, healthProbeStore)
	if err != nil {
		vault.Close()
		return nil, err
	}
	entryHealth, err := newEntrypointHealthProbeAdapter(healthProbes, healthProbeStore)
	if err != nil {
		vault.Close()
		return nil, err
	}
	healthProbeScheduler, err := newHealthProbeScheduler(healthProbes, 15*time.Second, time.Second, time.Minute)
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
	orphanRecovery, err := newOrphanRecoveryController(
		agentInstanceID, store,
		orphanRecoveryResourceFactory{repository: resourceStore, providers: runtimeFactory},
		30*time.Second, 5*time.Second, 5*time.Minute, 2*time.Minute, time.Now,
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
	installerArtifacts, err := artifactresolver.New(artifactresolver.DefaultConfig())
	if err != nil {
		vault.Close()
		return nil, err
	}
	installerSecrets, err := secretresolver.New(manager)
	if err != nil {
		vault.Close()
		return nil, err
	}
	execution, err := cloudexecution.NewService(
		agentInstanceID, facts, store, store, store, artifactPublisher, workerAdapter,
		cloudexecution.NewIdentityBootstrapPublisher(), resourcePlans, resourceProvisioner, store, time.Now,
		cloudexecution.WithInstallerTrustIssuer(installerIssuer),
		cloudexecution.WithInstallerArtifactResolver(installerArtifacts),
		cloudexecution.WithInstallerSecretResolver(installerSecrets),
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
		Lifecycles: awsLifecycleFactory{repository: resourceStore, runtimes: runtimeFactory}, Secrets: deploymentSecrets,
		Approvals: resourceApprovals, Now: time.Now,
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
	rootHelperStore, err := postgres.NewRootHelperKeyStore(store)
	if err != nil {
		vault.Close()
		return nil, err
	}
	helperRoot := rootHelperDerivationRoot(masterKey)
	rootHelperDeriver, err := helperkey.NewDeterministicKeyDeriver(helperRoot)
	clear(helperRoot)
	if err != nil {
		vault.Close()
		return nil, err
	}
	retainRootHelperDeriver := false
	defer func() {
		if !retainRootHelperDeriver {
			rootHelperDeriver.Close()
		}
	}()
	closeRootHelper := func() {
		rootHelperDeriver.Close()
		vault.Close()
	}
	rootHelperApprovalService, err := helperkey.NewApprovalService(
		rootHelperStore, rootHelperApprovalDeviceVerifier{devices: store, now: time.Now}, rootHelperDeriver, time.Now,
	)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	rootHelperAWS := &rootHelperAWSRouter{
		agentInstanceID: agentInstanceID, current: cloudStatuses, vault: vault, factory: sdkRootHelperSecretsFactory{},
	}
	rootHelperDeliveries, err := helperkey.NewService(
		rootHelperStore, rootHelperAWS, rootHelperAWS, time.Now,
		helperkey.WithApprovedKeyDelivery(rootHelperApprovalService, rootHelperDeriver),
	)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	rootHelperAuthority := &productionRootHelperBindingAuthority{
		agentInstanceID: agentInstanceID, current: cloudStatuses, identities: workerStore,
		vault: vault, factory: sdkRootHelperCloudFormationFactory{},
	}
	rootHelperApprovals, err := newRootHelperApprovalCoordinator(rootHelperAuthority, rootHelperApprovalService, rootHelperDeliveries)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	workerOperationStore, err := postgres.NewWorkerServiceOperationStore(store)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	workerOperations, err := workeroperation.NewService(
		workerOperationStore, workeroperation.CurrentReadyReceiptVerifier{Keys: rootHelperStore}, time.Now,
	)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	rootHelperCapabilities, err := newProductionRootHelperCapabilityIssuer(
		workerStore, rootHelperStore, installerIssuer, time.Now,
	)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationFacts := managedPreparationFactAdapter{cloud: facts, recipes: store, launches: store}
	pairingWorkerStore, err := postgres.NewPairingWorkerOperationStore(store)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	pairingWorkerOperations, err := pairingworker.NewService(pairingWorkerStore, time.Now)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	pairingStore := store.Pairing()
	pairingSessions, err := pairing.NewService(pairingStore, pairingworker.Executor{Dispatch: pairingworker.DurableDispatcher{
		Operations: pairingWorkerOperations, Poll: 200 * time.Millisecond,
	}}, time.Now)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	pairingRuntime, err := newPairingRuntime(agentInstanceID, pairingSessions, managedPreparationFacts, cloudStatuses)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	pairingApprovals, err := pairing.NewApprovalService(agentInstanceID, pairingStore, pairingDeviceAdapter{devices: store}, pairingRuntime, pairingRuntime, time.Now)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationScopes, err := newManagedPreparationScopeBuilder(
		agentInstanceID, managedPreparationFacts, cloudStatuses, healthProbeStore,
	)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationTemplates, err := newManagedPreparationSnapshotTemplates(
		managedPreparationTemplateFactAdapter{current: cloudStatuses, recipes: store},
	)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationResources, err := newManagedPreparationResourceLifecycle(store, runtimeFactory, resourceStore)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationHealth, err := newManagedPreparationSemanticHealth(healthProbes, healthProbeStore)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedCostStore, err := postgres.NewManagedCostAlertStore(store)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedCostController, err := costalert.NewController(agentInstanceID, managedPreparationFacts, managedCostStore)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationCost, err := newManagedPreparationCostPolicy(managedCostController, managedCostStore)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationStack, err := newManagedPreparationStackObservation(store, runtimeFactory, managedPreparationFacts)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationRestart, err := newWorkerOperationRestartPort(workerOperations, rootHelperStore)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationExecutor, err := serviceoperation.NewExecutor(
		store, managedPreparationScopes, managedPreparationRestart, managedPreparationResources,
		managedPreparationHealth, managedPreparationCost, managedPreparationStack,
		managedPreparationTemplates, store, time.Now,
	)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	managedPreparationGate := staticManagedPreparationAWSGate(options.enableManagedPreparationAWS)
	managedPreparationRecovery, err := newManagedPreparationRecoveryController(
		store, managedPreparationExecutor, managedPreparationGate, 64,
	)
	if err != nil {
		closeRootHelper()
		return nil, err
	}
	var managedPreparation *serviceoperation.Service
	if managedPreparationGate.Enabled() {
		managedPreparation, err = serviceoperation.NewService(
			agentInstanceID, store, approvalReads, managedPreparationScopes, time.Now,
		)
		if err != nil {
			closeRootHelper()
			return nil, err
		}
	}
	foundationRepository, err := postgres.NewFoundationLifecycleRepository(store)
	if err != nil {
		vault.Close()
		return nil, err
	}
	foundationSnapshots, err := cloudapp.NewFoundationSnapshotReader(agentInstanceID, awsfoundationassets.Template(), reaperImageURI, manager, store, cloudStatuses, foundationRepository, time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	foundationMutator, err := cloudapp.NewAWSFoundationLifecycleMutator(foundation)
	if err != nil {
		vault.Close()
		return nil, err
	}
	foundationProvider, err := cloudapp.NewFoundationLifecycleProvider(manager, foundationMutator)
	if err != nil {
		vault.Close()
		return nil, err
	}
	foundationExecutor, err := cloudfoundation.NewExecutor(foundationRepository, foundationProvider)
	if err != nil {
		vault.Close()
		return nil, err
	}
	foundationLifecycle, err := cloudfoundation.NewService(agentInstanceID, foundationRepository, approvalReads, foundationSnapshots, foundationExecutor, time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	entryScopeBuilder, err := newEntrypointScopeBuilder(agentInstanceID, facts, store, cloudStatuses, runtimeFactory, time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	entryExecutor, err := entryexecution.NewExecutor(entryexecution.Config{
		Operations:   store,
		Plans:        entrypointOperationPlanResolver{store: store},
		Scopes:       entrypointScopeRevalidator{builder: entryScopeBuilder},
		Resources:    entrypointDeploymentResourceReader{statuses: cloudStatuses},
		Provision:    entrypointScopedProvisioner{connections: store, provisioner: resourceProvisioner},
		Health:       entryHealth,
		PollInterval: 15 * time.Second,
		Now:          time.Now,
	})
	if err != nil {
		vault.Close()
		return nil, err
	}
	entryService, err := entrypoint.NewService(agentInstanceID, store, approvalReads, entryScopeBuilder, entryExecutor, time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	destroyCoordinator, err := clouddestroy.NewService(agentInstanceID, store, approvalReads, cloudStatuses, facts, resourceApprovals, lifecycle, time.Now)
	if err != nil {
		vault.Close()
		return nil, err
	}
	managedScopes, err := newManagedAcceptanceScopeBuilder(store, cloudStatuses, facts, store)
	if err != nil {
		vault.Close()
		return nil, err
	}
	managedAcceptor, err := newManagedAcceptanceResourceAcceptor(store, resourceStore, runtimeFactory)
	if err != nil {
		vault.Close()
		return nil, err
	}
	managedExecutor, err := cloudmanaged.NewExecutor(store, managedScopes, managedAcceptor, 15*time.Second)
	if err != nil {
		vault.Close()
		return nil, err
	}
	managedAcceptance, err := cloudmanaged.NewService(agentInstanceID, store, approvalReads, managedScopes, managedExecutor, time.Now)
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
	retainRootHelperDeriver = true
	return &CloudComposition{
		Coordinator: coordinator, DestroyCoordinator: destroyCoordinator, Entrypoint: entryService, FoundationLifecycle: foundationLifecycle, ManagedAcceptance: managedAcceptance, Dispatcher: dispatcher, Lifecycle: lifecycle,
		WorkerIdentityVerifier: identityVerifier, WorkerIdentityMaterializer: identityMaterializer,
		FoundationConnections: connections, ActiveQuotes: activeQuotes, ActivePlacements: activePlacements, ProviderPlans: providerPlans,
		ManifestRecovery:           manifestRecovery,
		HealthProbes:               healthProbes,
		HealthProbeReader:          healthProbeStore,
		RootHelperApprovals:        rootHelperApprovals,
		RootHelperDeliveries:       rootHelperDeliveries,
		WorkerOperations:           workerOperations,
		RootHelperCapabilities:     rootHelperCapabilities,
		Pairing:                    pairingRuntime,
		PairingApprovals:           pairingApprovals,
		PairingWorkerOperations:    pairingWorkerOperations,
		PairingReceiptVerifier:     pairingWorkerReceiptVerifier{keys: rootHelperStore},
		ManagedPreparation:         managedPreparation,
		foundationLaunches:         launchCompensator,
		healthProbeScheduler:       healthProbeScheduler,
		orphanRecovery:             orphanRecovery,
		entryExecutor:              entryExecutor,
		foundationExecutor:         foundationExecutor,
		managedAcceptanceExecutor:  managedExecutor,
		managedPreparationRecovery: managedPreparationRecovery,
		agentInstanceID:            agentInstanceID,
		cloudGoalStore:             store,
		vault:                      vault,
		rootHelperDeriver:          rootHelperDeriver,
	}, nil
}

func rootHelperDerivationRoot(masterKey []byte) []byte {
	mac := hmac.New(sha256.New, masterKey)
	_, _ = mac.Write([]byte("dirextalk-agent/root-helper-key-deriver/v1"))
	return mac.Sum(nil)
}
