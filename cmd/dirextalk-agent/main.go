package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/githubapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/githubsource"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledgeworker"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/scheduling"
	"github.com/YingSuiAI/dirextalk-agent/internal/searchprofile"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretref"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teambundle"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamcontroller"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workermarket"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/google/uuid"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("dirextalk-agent stopped", "error", safeError(err))
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: dirextalk-agent <migrate|bootstrap-service-key|rotate-bootstrap-service-key|bootstrap-approval-device|publish-worker-ami|healthcheck|serve>")
	}
	switch arguments[0] {
	case "migrate":
		if len(arguments) != 1 {
			return errors.New("migrate does not accept arguments")
		}
		return migrate()
	case "bootstrap-service-key":
		if len(arguments) != 1 {
			return errors.New("bootstrap-service-key does not accept arguments")
		}
		return bootstrapServiceKey()
	case "rotate-bootstrap-service-key":
		if len(arguments) != 1 {
			return errors.New("rotate-bootstrap-service-key does not accept arguments")
		}
		return rotateBootstrapServiceKey()
	case "bootstrap-approval-device":
		if len(arguments) != 1 {
			return errors.New("bootstrap-approval-device does not accept arguments")
		}
		return bootstrapApprovalDevice()
	case "publish-worker-ami":
		return publishWorkerAMI(arguments[1:])
	case "healthcheck":
		if len(arguments) != 1 {
			return errors.New("healthcheck does not accept arguments")
		}
		return runHealthcheck()
	case "serve":
		if len(arguments) != 1 {
			return errors.New("serve does not accept arguments")
		}
		return serve()
	default:
		return errors.New("unknown command; expected migrate, bootstrap-service-key, rotate-bootstrap-service-key, bootstrap-approval-device, publish-worker-ami, healthcheck, or serve")
	}
}

func migrate() error {
	common, err := config.LoadCommon()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := postgres.Open(ctx, common.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := postgres.ApplyMigrations(ctx, pool, common.InstanceID); err != nil {
		return err
	}
	slog.Info("agent database migration complete")
	return nil
}

func bootstrapServiceKey() error {
	common, err := config.LoadCommon()
	if err != nil {
		return err
	}
	pepperPath := strings.TrimSpace(os.Getenv("AGENT_SERVICE_KEY_PEPPER_FILE"))
	keyPath := strings.TrimSpace(os.Getenv("AGENT_BOOTSTRAP_SERVICE_KEY_FILE"))
	clientID := strings.TrimSpace(os.Getenv("AGENT_BOOTSTRAP_CLIENT_ID"))
	if pepperPath == "" || keyPath == "" || clientID == "" {
		return errors.New("AGENT_SERVICE_KEY_PEPPER_FILE, AGENT_BOOTSTRAP_SERVICE_KEY_FILE, and AGENT_BOOTSTRAP_CLIENT_ID are required")
	}
	pepper, err := config.ReadKeyMaterial(pepperPath)
	if err != nil {
		return err
	}
	defer clear(pepper)
	if err := config.ValidateMountedSecretFile(keyPath); err != nil {
		return err
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return errors.New("could not read mounted bootstrap service key")
	}
	keyID, secret, err := auth.ReadSecretFileValue(raw)
	if err != nil {
		return err
	}
	defer clear(secret)
	scopes := splitScopes(os.Getenv("AGENT_BOOTSTRAP_SCOPES"))
	if len(scopes) == 0 {
		scopes = []string{"admin"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := postgres.Open(ctx, common.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := postgres.VerifySchema(ctx, pool, common.InstanceID); err != nil {
		return err
	}
	store, err := postgres.New(pool, common.InstanceID)
	if err != nil {
		return err
	}
	_, err = store.EnsureBootstrapCredential(ctx, auth.BootstrapCredential{
		KeyID: keyID, ClientID: clientID, Scopes: scopes, SecretDigest: auth.Digest(pepper, secret),
	})
	if err != nil {
		return err
	}
	slog.Info("bootstrap service credential is ready", "client_id", clientID, "key_id", keyID)
	return nil
}

func serve() error {
	serverConfig, err := config.LoadServer()
	if err != nil {
		return err
	}
	effectiveMemoryLimit, restoreMemoryLimit, err := applyGoMemoryLimit(serverConfig.GoMemoryLimitBytes)
	if err != nil {
		return err
	}
	defer restoreMemoryLimit()
	runBudget, err := scheduling.NewRunBudget(scheduling.RunBudgetLimits{
		MaxActive:      serverConfig.MaxActiveLocalRuns,
		MaxInteractive: serverConfig.MaxActiveLocalRuns,
		MaxBackground:  serverConfig.MaxBackgroundLocalRuns,
	})
	if err != nil {
		return errors.New("could not initialize local Agent run budget")
	}
	var teamPlanCompiler *teamplan.CatalogCompiler
	var teamPolicyResolver *teamorchestration.StaticPolicyResolver
	var loadedTeamBundle *teambundle.Bundle
	var modelProfiles *modelapi.ProfileCatalog
	var searchProfiles *searchprofile.Catalog
	if serverConfig.TeamBundleDir != "" {
		loadedTeamBundle, err = teambundle.Load(
			serverConfig.TeamBundleDir,
		)
		if err != nil ||
			loadedTeamBundle.Manifest.AgentInstanceID !=
				serverConfig.InstanceID {
			return errors.New(
				"could not verify configured Pi Team bundle",
			)
		}
		modelProfiles = loadedTeamBundle.ModelProfiles
	} else {
		modelProfiles, err = modelapi.LoadProfileCatalog(
			serverConfig.ModelProfilesFile,
		)
		if err != nil {
			return errors.New("could not load model profile catalog")
		}
	}
	if serverConfig.SearchProfilesFile != "" {
		searchProfiles, err = searchprofile.LoadCatalog(
			serverConfig.SearchProfilesFile,
		)
		if err != nil {
			return errors.New("could not load search profile catalog")
		}
	}
	mountedSecrets, err := secretref.NewMountedResolver(
		serverConfig.MountedSecretsDir,
	)
	if err != nil {
		return errors.New("could not initialize mounted runtime secrets")
	}
	var githubSourceSnapshotter *githubsource.Snapshotter
	if serverConfig.GitHubAppConnectionsFile != "" {
		githubConnections, loadErr :=
			githubapp.LoadConnectionCatalog(
				serverConfig.GitHubAppConnectionsFile,
			)
		if loadErr != nil {
			return errors.New(
				"could not load protected GitHub App connections",
			)
		}
		githubPrivateKeys, loadErr :=
			githubapp.NewResolverPrivateKeySource(mountedSecrets)
		if loadErr != nil {
			return errors.New(
				"could not initialize GitHub App private keys",
			)
		}
		githubHTTPClient := &http.Client{
			Transport: http.DefaultTransport,
			Timeout:   30 * time.Second,
			CheckRedirect: func(
				*http.Request,
				[]*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		}
		githubBroker, loadErr := githubapp.NewBroker(
			githubConnections,
			githubPrivateKeys,
			githubHTTPClient,
			time.Now,
		)
		if loadErr != nil {
			return errors.New(
				"could not initialize GitHub App credential broker",
			)
		}
		githubSourceRoot, loadErr := os.MkdirTemp(
			"",
			"dirextalk-github-source-",
		)
		if loadErr != nil {
			return errors.New(
				"could not initialize protected GitHub source storage",
			)
		}
		defer os.RemoveAll(githubSourceRoot)
		githubSourceSnapshotter, loadErr =
			githubsource.NewSnapshotter(
				githubBroker,
				http.DefaultTransport,
				githubSourceRoot,
			)
		if loadErr != nil {
			return errors.New(
				"could not initialize GitHub source snapshotter",
			)
		}
	}
	var teamModelOffers *teampricing.ModelOfferCatalog
	var teamComputeCatalog *awsprovider.TeamComputeCatalog
	var teamCredentialReadiness *teampricing.CatalogCredentialReadiness
	var workerMarketGate *workermarket.TeamPlanGate
	var runtimeCatalog *teamplan.RuntimeCatalog
	if loadedTeamBundle != nil {
		runtimeCatalog = loadedTeamBundle.RuntimeCatalog
		teamPolicyResolver = loadedTeamBundle.Policy
		teamModelOffers = loadedTeamBundle.ModelOffers
		teamComputeCatalog = loadedTeamBundle.ComputeCatalog
	}
	if serverConfig.WorkerMarketRegistryFile != "" {
		workerRegistry, loadErr := workermarket.LoadRegistry(
			serverConfig.WorkerMarketRegistryFile,
			serverConfig.WorkerMarketPublicKeyFile,
		)
		if loadErr != nil {
			return errors.New(
				"could not verify configured Worker Marketplace registry",
			)
		}
		workerMarketGate, loadErr = workermarket.NewTeamPlanGate(
			workerRegistry,
			serverConfig.WorkerMarketOrganizationID,
		)
		if loadErr != nil {
			return errors.New(
				"could not initialize Worker Marketplace approval gate",
			)
		}
	}
	if runtimeCatalog == nil && serverConfig.RuntimeCatalogFile != "" {
		runtimeCatalog, err = teamplan.LoadRuntimeCatalog(
			serverConfig.RuntimeCatalogFile,
			serverConfig.RuntimeCatalogPublicKeyFile,
		)
		if err != nil {
			return errors.New("could not verify configured runtime catalog")
		}
	}
	if runtimeCatalog != nil {
		var loadErr error
		if workerMarketGate != nil {
			teamPlanCompiler, loadErr =
				teamplan.NewCatalogCompilerForMarketplace(
					runtimeCatalog,
					[]teamplan.RuntimeAdapter{
						teamplan.AdapterPiV1,
					},
					workerMarketGate,
					time.Now,
				)
		} else {
			teamPlanCompiler, loadErr =
				teamplan.NewCatalogCompilerForAdapters(
					runtimeCatalog,
					[]teamplan.RuntimeAdapter{
						teamplan.AdapterPiV1,
					},
				)
		}
		if loadErr != nil {
			return errors.New("could not initialize runtime-catalog-bound Team Plan compiler")
		}
	}
	if teamPolicyResolver == nil && serverConfig.TeamPolicyFile != "" {
		teamPolicyResolver, err =
			teamorchestration.LoadStaticPolicyResolver(
				serverConfig.TeamPolicyFile,
			)
		if err != nil {
			return errors.New("could not load protected Team Plan policy")
		}
	}
	if teamModelOffers == nil &&
		serverConfig.TeamModelOfferCatalogFile != "" {
		teamModelOffers, err = teampricing.LoadModelOfferCatalog(
			serverConfig.TeamModelOfferCatalogFile,
			modelProfiles,
		)
		if err != nil {
			return errors.New("could not load protected Team model offer catalog")
		}
		teamComputeCatalog, err = awsprovider.LoadTeamComputeCatalog(
			serverConfig.TeamComputeCatalogFile,
		)
		if err != nil {
			return errors.New("could not load protected Team compute catalog")
		}
	}
	if teamModelOffers != nil {
		teamCredentialReadiness, err =
			teampricing.NewCatalogCredentialReadiness(
				teamModelOffers,
				mountedSecrets,
			)
		if err != nil {
			return errors.New("could not initialize Team model credential readiness")
		}
	}
	pepper, err := config.ReadKeyMaterial(serverConfig.PepperFile)
	if err != nil {
		return err
	}
	defer clear(pepper)
	masterKey, err := config.ReadKeyMaterial(serverConfig.MasterKeyFile)
	if err != nil {
		return err
	}
	defer clear(masterKey)
	if len(masterKey) != 32 {
		return errors.New("AGENT_MASTER_KEY_FILE must contain exactly 32 bytes")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	pool, err := postgres.Open(ctx, serverConfig.DatabaseURL)
	if err != nil {
		cancel()
		return err
	}
	defer pool.Close()
	if err := postgres.VerifySchema(ctx, pool, serverConfig.InstanceID); err != nil {
		cancel()
		return err
	}
	cancel()
	store, err := postgres.New(pool, serverConfig.InstanceID)
	if err != nil {
		return err
	}
	reconcileCtx, reconcileCancel := context.WithTimeout(
		context.Background(),
		30*time.Second,
	)
	repairedTasks, err := store.ReconcileTeamPlanTaskApprovalStates(reconcileCtx)
	reconcileCancel()
	if err != nil {
		return errors.New("could not reconcile Team Plan Task approval states")
	}
	if repairedTasks > 0 {
		slog.Info(
			"reconciled Team Plan Task approval states",
			"tasks", repairedTasks,
		)
	}
	knowledgeCatalog := knowledge.DefaultCatalog()
	knowledgeRepository, err := knowledge.NewPostgresRepository(pool, serverConfig.InstanceID, knowledgeCatalog)
	if err != nil {
		return errors.New("could not initialize Knowledge persistence")
	}
	knowledgeWorkerBroker, err := knowledgeworker.NewBroker(time.Now)
	if err != nil {
		return errors.New("could not initialize Knowledge Worker relay")
	}
	knowledgeService, err := knowledge.NewService(knowledgeRepository, knowledgeWorkerBroker, knowledgeCatalog, time.Now)
	if err != nil {
		return errors.New("could not initialize Knowledge service")
	}
	secretStore, err := store.NewSecretBootstrapStore(masterKey)
	if err != nil {
		return errors.New("could not initialize secret bootstrap persistence")
	}
	secretManager, err := secretbootstrap.NewManager(secretStore, secretStore.KeyStore(), rand.Reader, time.Now)
	if err != nil {
		return errors.New("could not initialize secret bootstrap manager")
	}
	recoveryContext, recoveryCancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, recoveryErr := secretManager.Expire(recoveryContext)
	recoveryCancel()
	if recoveryErr != nil {
		return errors.New("could not recover expired secret bootstrap sessions")
	}
	workerReplayKey := deriveKey(masterKey, "dirextalk-agent/worker-replay/v1")
	defer clear(workerReplayKey)
	workerCredentialPepper := deriveKey(masterKey, "dirextalk-agent/worker-credential/v1")
	defer clear(workerCredentialPepper)
	installerIssuerKey := deriveKey(masterKey, "dirextalk-agent/installer-trust-issuer/v1")
	installerIssuer, err := installer.NewTrustIssuer(installerIssuerKey)
	clear(installerIssuerKey)
	if err != nil {
		return errors.New("could not initialize Worker installer trust")
	}
	defer installerIssuer.Close()
	workerStore, err := store.NewWorkerStore(workerReplayKey)
	if err != nil {
		return errors.New("could not initialize Worker persistence")
	}
	workerTaskCoordinator, err := app.NewWorkerTaskCoordinator(serverConfig.InstanceID, store)
	if err != nil {
		return errors.New("could not initialize Worker Task coordination")
	}
	workerService, err := worker.NewService(workerStore, workerCredentialPepper, worker.WithTaskExecutionCoordinator(workerTaskCoordinator), worker.WithInstallerTrustIssuer(installerIssuer))
	if err != nil {
		return errors.New("could not initialize Worker control")
	}
	var cloudComposition *app.CloudComposition
	var cloudCoordinator cloudapp.Coordinator
	if serverConfig.EnableAWSControl {
		var configuredWorkerRelease *workerrelease.ReleaseV1
		if loadedTeamBundle != nil {
			release := loadedTeamBundle.WorkerRelease
			configuredWorkerRelease = &release
		} else if serverConfig.WorkerAMIPublicationFile != "" {
			release, releaseErr := workerrelease.LoadPublicationFile(
				serverConfig.WorkerAMIPublicationFile,
			)
			if releaseErr != nil || release.AgentInstanceID != serverConfig.InstanceID {
				return errors.New("could not validate configured Worker AMI publication")
			}
			configuredWorkerRelease = &release
		}
		if configuredWorkerRelease != nil {
			if configuredWorkerRelease.AgentInstanceID !=
				serverConfig.InstanceID {
				return errors.New(
					"could not validate configured Worker AMI publication",
				)
			}
			importContext, stopImport := context.WithTimeout(context.Background(), 30*time.Second)
			_, releaseErr := store.ImportWorkerRelease(
				importContext,
				*configuredWorkerRelease,
			)
			stopImport()
			if releaseErr != nil {
				return errors.New("could not persist configured Worker AMI publication")
			}
		}
		var cloudErr error
		if serverConfig.StagedWorkerControl {
			cloudCoordinator, cloudErr = app.NewStagedAWSControl(serverConfig.InstanceID, secretManager, store)
		} else {
			cloudOptions := make([]app.CloudCompositionOption, 0, 2)
			cloudOptions = append(cloudOptions, app.WithManagedKnowledgeBinding(knowledgeService))
			if serverConfig.EnableManagedPreparationAWS {
				cloudOptions = append(cloudOptions, app.WithManagedPreparationAWS())
			}
			cloudComposition, cloudErr = app.NewCloudComposition(
				store, secretManager, workerStore, workerService, installerIssuer, serverConfig.InstanceID, masterKey,
				serverConfig.AWSReaperImageURI, serverConfig.WorkerControlEndpoint, serverConfig.WorkerControlEndpointServiceName,
				serverConfig.WorkerConnectivityMode,
				cloudOptions...,
			)
			if cloudErr == nil {
				cloudCoordinator = cloudComposition.Coordinator
			}
		}
		if cloudErr != nil {
			return errors.New("could not initialize typed AWS cloud control")
		}
		if cloudComposition != nil {
			defer cloudComposition.Close()
			foundationRecoveryContext, stopFoundationRecovery := context.WithTimeout(context.Background(), 2*time.Minute)
			cloudErr = cloudComposition.Recover(foundationRecoveryContext)
			stopFoundationRecovery()
			if cloudErr != nil {
				// Every cloud mutation is fenced by its durable operation row,
				// and each runtime recovery component is supervised independently.
				// Keep the local control plane available while the failed
				// component retries the exact persisted operation.
				slog.Warn("initial AWS cloud recovery deferred", "error", safeError(cloudErr))
			}
		}
	}
	runtimeOptions := make([]app.RuntimeCompositionOption, 0, 7)
	var teamOfferBuilder teamorchestration.TrustedOfferSource
	runtimeOptions = append(
		runtimeOptions,
		app.WithLocalRunBudget(runBudget),
		app.WithLoadedModelProfiles(modelProfiles),
		app.WithTransientModelCredentials(secretManager),
	)
	if searchProfiles != nil {
		runtimeOptions = append(
			runtimeOptions,
			app.WithLoadedSearchProfiles(searchProfiles),
		)
	}
	if teamPlanCompiler != nil {
		runtimeOptions = append(
			runtimeOptions,
			app.WithTeamPlanCompiler(teamPlanCompiler),
		)
	}
	if teamPolicyResolver != nil {
		runtimeOptions = append(
			runtimeOptions,
			app.WithTeamPolicyResolver(teamPolicyResolver),
		)
	}
	if cloudComposition != nil {
		runtimeOptions = append(runtimeOptions, app.WithCloudGoalMaterializer(cloudComposition.ProviderPlans))
	}
	if teamModelOffers != nil {
		if cloudComposition == nil {
			return errors.New("Team pricing requires complete AWS cloud composition")
		}
		var builderErr error
		teamOfferBuilder, builderErr =
			cloudComposition.NewTeamOfferBuilder(
				teamModelOffers,
				teamCredentialReadiness,
				teamComputeCatalog,
			)
		if builderErr != nil {
			return errors.New("could not initialize trusted Team offer builder")
		}
		teamLaunchBuilder, builderErr :=
			cloudComposition.NewTeamLaunchAuthorizationBuilder(
				teamPlanCompiler,
			)
		if builderErr != nil {
			return errors.New(
				"could not initialize trusted Team launch authorization",
			)
		}
		runtimeOptions = append(
			runtimeOptions,
			app.WithTeamOfferBuilder(teamOfferBuilder),
			app.WithTeamLaunchAuthorizationBuilder(
				teamLaunchBuilder,
			),
		)
	}
	runtimeComposition, err := app.NewRuntimeComposition(
		store, serverConfig.InstanceID, serverConfig.MountedSecretsDir, serverConfig.ModelProfilesFile, serverConfig.MCPServersFile,
		runtimeOptions...,
	)
	if err != nil {
		return errors.New("could not initialize Agent runtime")
	}
	var centralTeamController *teamcontroller.Controller
	if runtimeComposition.TeamExecutions != nil {
		if cloudComposition == nil ||
			teamOfferBuilder == nil ||
			teamCredentialReadiness == nil {
			return errors.New(
				"Team execution requires complete cloud controller dependencies",
			)
		}
		centralTeamController, err =
			cloudComposition.NewTeamController(
				runtimeComposition,
				teamOfferBuilder,
				teamCredentialReadiness,
				githubSourceSnapshotter,
			)
		if err != nil {
			return fmt.Errorf(
				"could not initialize Team execution controller: %w",
				err,
			)
		}
		teamRecoveryContext, stopTeamRecovery :=
			context.WithTimeout(
				context.Background(),
				2*time.Minute,
			)
		teamRecoveryErr := centralTeamController.RunOnce(
			teamRecoveryContext,
		)
		stopTeamRecovery()
		if teamRecoveryErr != nil {
			slog.Warn(
				"Team execution recovery deferred",
				"error",
				safeError(teamRecoveryErr),
			)
		}
	}
	cloudGoalRecoveryContext, stopCloudGoalRecovery := context.WithTimeout(context.Background(), 30*time.Second)
	cloudGoalRecoveryErr := runtimeComposition.RecoverCloudGoals(cloudGoalRecoveryContext)
	stopCloudGoalRecovery()
	if cloudGoalRecoveryErr != nil {
		// Cloud Goal planning cannot mutate AWS or approve spend. A transient
		// model/provider/read-store failure must not make the whole Agent
		// unavailable after restart; the durable dispatcher retries the exact
		// fenced stage after startup and all provider mutations remain closed.
		slog.Warn("queued Cloud Goal recovery deferred", "error", safeError(cloudGoalRecoveryErr))
	}
	serverOptions := []app.ServerOption{
		app.WithRuntime(runtimeComposition.Coordinator, runtimeComposition.Features),
		app.WithKnowledge(knowledgeService),
		app.WithKnowledgeWorkerRelay(knowledgeWorkerBroker),
		app.WithCloudGoals(runtimeComposition.CloudGoals),
		app.WithSecretBootstrap(secretManager, serverConfig.InstanceID),
		app.WithWorkerControl(workerService),
	}
	if runtimeComposition.TeamPreparation != nil &&
		runtimeComposition.TeamOrchestrator != nil {
		serverOptions = append(
			serverOptions,
			app.WithTeamPlans(
				runtimeComposition.TeamPreparation,
				runtimeComposition.TeamOrchestrator,
			),
		)
		if runtimeComposition.TeamExecutions != nil {
			serverOptions = append(
				serverOptions,
				app.WithTeamExecutions(
					runtimeComposition.TeamExecutions,
				),
			)
		}
	}
	if cloudCoordinator != nil {
		serverOptions = append(serverOptions, app.WithCloudControl(cloudCoordinator))
	}
	if cloudComposition != nil {
		serverOptions = append(serverOptions,
			app.WithCloudDestroy(cloudComposition.DestroyCoordinator),
			app.WithCloudEntrypoint(cloudComposition.Entrypoint),
			app.WithCloudFoundation(cloudComposition.FoundationLifecycle),
			app.WithCloudManagedAcceptance(cloudComposition.ManagedAcceptance),
			app.WithManagedKnowledgeLifecycle(cloudComposition.ManagedKnowledgeLifecycle),
			app.WithCloudPairing(cloudComposition.Pairing, cloudComposition.PairingApprovals),
			app.WithCloudHealth(cloudComposition.HealthProbeReader),
			app.WithWorkerIdentity(cloudComposition.WorkerIdentityVerifier, cloudComposition.WorkerIdentityMaterializer),
			app.WithWorkerMilestoneWriter(cloudComposition.WorkerMilestones),
			app.WithRootHelperControl(cloudComposition.RootHelperApprovals, cloudComposition.RootHelperDeliveries,
				cloudComposition.WorkerOperations, cloudComposition.RootHelperCapabilities),
			app.WithPairingWorkerControl(cloudComposition.PairingWorkerOperations, cloudComposition.RootHelperCapabilities,
				cloudComposition.PairingReceiptVerifier),
		)
		if cloudComposition.ManagedPreparation != nil {
			serverOptions = append(serverOptions, app.WithCloudManagedPreparation(cloudComposition.ManagedPreparation))
		}
	}
	grpcServer, err := app.NewServer(
		store, pepper, serverConfig.TLSCertFile, serverConfig.TLSKeyFile,
		serverOptions...,
	)
	if err != nil {
		return errors.New("could not initialize TLS gRPC server")
	}
	listener, err := net.Listen("tcp", serverConfig.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for gRPC: %w", err)
	}
	defer listener.Close()
	bootstrapContext, stopBootstrap := context.WithCancel(context.Background())
	defer stopBootstrap()
	go expireBootstrapSessions(bootstrapContext, secretManager)
	if runtimeComposition.TeamExecutions != nil {
		instanceID := uuid.MustParse(serverConfig.InstanceID)
		go recoverApprovedTeamExecutions(
			bootstrapContext,
			runtimeComposition.TeamExecutions,
			task.MutationScope{
				ClientID: "dirextalk-agent-team-execution-recovery",
				CredentialID: uuid.NewSHA1(
					instanceID,
					[]byte("team-execution-recovery/v1"),
				).String(),
			},
		)
	}
	go func() {
		if dispatchErr := runtimeComposition.RunCloudGoals(bootstrapContext); dispatchErr != nil && !errors.Is(dispatchErr, context.Canceled) {
			slog.Warn("cloud Goal dispatcher stopped", "error", safeError(dispatchErr))
		}
	}()
	if cloudComposition != nil {
		go func() {
			if dispatchErr := cloudComposition.Run(bootstrapContext); dispatchErr != nil && !errors.Is(dispatchErr, context.Canceled) {
				slog.Warn("cloud dispatcher stopped", "error", safeError(dispatchErr))
			}
		}()
	}
	if centralTeamController != nil {
		go func() {
			if controllerErr := centralTeamController.Run(
				bootstrapContext,
			); controllerErr != nil &&
				!errors.Is(controllerErr, context.Canceled) {
				slog.Warn(
					"Team execution controller stopped",
					"error",
					safeError(controllerErr),
				)
			}
		}()
	}

	stopped := make(chan struct{})
	go func() {
		signals := make(chan os.Signal, 1)
		signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(signals)
		<-signals
		close(stopped)
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if shutdownErr := grpcServer.Shutdown(shutdownContext); shutdownErr != nil {
			slog.Warn("forced gRPC shutdown after grace period", "error", safeError(shutdownErr))
		}
	}()
	slog.Info("dirextalk-agent gRPC server ready",
		"listen", serverConfig.ListenAddress,
		"instance_id", serverConfig.InstanceID,
		"max_active_local_runs", serverConfig.MaxActiveLocalRuns,
		"max_background_local_runs", serverConfig.MaxBackgroundLocalRuns,
		"go_memory_limit_mib", effectiveMemoryLimit/(1024*1024),
		"runtime_catalog_revision", runtimeComposition.TeamPlans.CatalogRevision(),
		"team_policy_revision", teamPolicyResolver.Revision(),
	)
	err = grpcServer.Serve(listener)
	select {
	case <-stopped:
		return nil
	default:
		return err
	}
}

func deriveKey(masterKey []byte, label string) []byte {
	mac := hmac.New(sha256.New, masterKey)
	_, _ = mac.Write([]byte(label))
	return mac.Sum(nil)
}

func expireBootstrapSessions(ctx context.Context, manager *secretbootstrap.Manager) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if _, err := manager.Expire(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("secret bootstrap expiry sweep failed", "error", safeError(err))
			}
		}
	}
}

func recoverApprovedTeamExecutions(
	ctx context.Context,
	executions *teamexecution.Service,
	scope task.MutationScope,
) {
	run := func() {
		recoveryContext, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		recovered, err := executions.RecoverPendingMaterializations(
			recoveryContext,
			scope,
			64,
		)
		if recovered > 0 {
			slog.Info(
				"approved Team executions materialized",
				"count",
				recovered,
			)
		}
		if err != nil && ctx.Err() == nil {
			slog.Warn(
				"approved Team execution recovery deferred",
				"error",
				safeError(err),
			)
		}
	}
	run()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func splitScopes(value string) []string {
	result := []string{}
	for _, scope := range strings.Split(value, ",") {
		if scope = strings.TrimSpace(scope); scope != "" {
			result = append(result, scope)
		}
	}
	return result
}

func safeError(err error) string {
	if err == nil {
		return ""
	}
	message := security.RedactText(err.Error())
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}
