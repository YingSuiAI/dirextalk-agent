package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/control"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/controlserver"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/modelrelay"
	cloudproduction "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/production"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	workaws "github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/aws"
	"github.com/YingSuiAI/dirextalk-agent/internal/rpcapi"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

type coreCloudWorkerComposition struct {
	domain        *cloudworker.Service
	intrinsic     coreconversation.IntrinsicResolver
	executionPort coreexecutionv2.CloudWorkerExecutionPort
	taskHandler   coreruntime.TaskHandler
	outboxStore   cloudworker.CompletionOutboxStore

	workerControl *controlserver.Server
	modelRelay    *cloudWorkerModelRelayServer
	reaper        *cloudWorkerReaperLoop
	retention     *cloudworker.ArtifactRetentionCleaner
	outputHistory *cloudworker.OutputHistoryCleaner
	completion    *cloudworker.CompletionLoop

	mu      sync.Mutex
	started bool
	stopped bool
}

func composeCoreCloudWorker(
	ctx context.Context,
	cfg config.Config,
	store *postgres.Store,
	conversationStore *postgres.CoreConversationStore,
	profiles *coremodel.Service,
	tasks *postgres.CoreTaskStore,
) (*coreCloudWorkerComposition, error) {
	if !cfg.CoreCloudWorker.Enabled {
		return nil, nil
	}
	if ctx == nil || store == nil || conversationStore == nil || profiles == nil || tasks == nil {
		return nil, fmt.Errorf("cloud Worker production dependencies are incomplete")
	}
	if err := config.ValidateCoreCloudWorker(&cfg); err != nil {
		return nil, err
	}
	worker := cfg.CoreCloudWorker
	accountGeneration := uint64(cfg.CapabilityAccountGeneration)
	cloudStore := postgres.NewCloudWorkerStore(store)
	controlStore := postgres.NewCloudWorkerControlStore(store)

	pricing, err := cloudworker.NewPinnedPricingCatalog(worker.PricingCatalogFile, worker.PricingCatalogSHA256)
	if err != nil {
		return nil, fmt.Errorf("load Cloud Worker pricing catalog: %w", err)
	}
	quoter, err := cloudworker.NewProductionQuoter(pricing, cloudworker.ProductionQuoterConfig{
		QuoteTTL: worker.QuoteTTL, MaximumCatalogAge: worker.MaximumCatalogAge,
		CleanupReserveSeconds:   cloudworker.EphemeralCleanupReserveSeconds,
		ContingencyBasisPoints:  worker.ContingencyBasisPoints,
		AbsoluteHardLimitMicros: worker.AbsoluteHardLimitMicros,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker production quoter: %w", err)
	}
	qualification, err := cloudworker.NewPinnedRuntimeQualification(worker.RuntimeQualificationFile, worker.RuntimeQualificationSHA256)
	if err != nil {
		return nil, fmt.Errorf("load Cloud Worker runtime qualification: %w", err)
	}
	defaults := cloudworker.Defaults{
		AWS: cloudworker.AWSBinding{AccountID: worker.AccountID, Region: worker.Region, CredentialID: worker.CredentialID, CredentialRevision: worker.CredentialRevision},
		Compute: cloudworker.ComputeSpec{
			InstanceType: worker.InstanceType, Architecture: worker.Architecture, RootDeviceName: worker.RootDeviceName,
			VolumeGiB: worker.VolumeGiB, VolumeType: worker.VolumeType, VolumeIOPS: worker.VolumeIOPS,
			VolumeThroughputMiB: worker.VolumeThroughputMiB, AMIID: worker.AMIID, AMIDigest: worker.AMIDigest,
			WorkerReleaseDigest: worker.WorkerReleaseDigest, PiRuntimeDigest: worker.PiRuntimeDigest,
			HostNetworkPolicySHA256: worker.HostNetworkPolicySHA256,
		},
		Placement: cloudworker.PlacementSpec{VPCID: worker.VPCID, SubnetID: worker.SubnetID},
		NetworkPolicy: cloudworker.NetworkPolicy{
			DNSResolverCIDRs: append([]string(nil), worker.DNSResolverCIDRs...), TLSProxyCIDRs: append([]string(nil), worker.TLSProxyCIDRs...),
			AllowedFQDNs: append([]string(nil), worker.AllowedFQDNs...), OutboundProxyURL: worker.OutboundProxyURL,
			OutboundProxyServerName: worker.OutboundProxyServerName, OutboundProxyTrustBundleSHA256: worker.OutboundProxyTrustSHA256,
		},
		ArtifactBucket: worker.ArtifactBucket, ArtifactBasePrefix: worker.ArtifactBasePrefix,
		ArtifactKMSKeyARN: worker.ArtifactKMSKeyARN, ArtifactVersioned: true,
		WorkerBootstrap: cloudworker.WorkerBootstrap{
			Protocol: cloudworker.WorkerControlProtocolV1, Endpoint: worker.WorkerControlEndpoint,
			TLSServerName: worker.WorkerControlServerName, TrustBundleDigest: worker.WorkerControlTrustSHA256,
		},
		ModelRelay:    cloudworker.ModelRelayBinding{Endpoint: worker.ModelRelayEndpoint, TLSServerName: worker.ModelRelayServerName, TrustBundleDigest: worker.ModelRelayTrustSHA256},
		Limits:        cloudworker.Limits{MaxRuntimeSeconds: uint64(worker.MaxRuntime / time.Second), MaxTokens: worker.MaxTokens, MaxOutputBytes: worker.MaxOutputBytes},
		NetworkGrants: append([]string(nil), worker.AllowedFQDNs...), ArtifactRetentionSeconds: uint64(worker.ArtifactRetention / time.Second),
		QuoteAmountMicros: 0, MaximumAuthorizedMicros: worker.AbsoluteHardLimitMicros, QuoteTTL: worker.QuoteTTL,
	}
	credentialResolver, err := postgres.NewCoreWorkloadCredentialResolver(postgres.NewCoreAWSStore(store))
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker credential resolver: %w", err)
	}
	credentialRevisionResolver, ok := credentialResolver.(workaws.CredentialRevisionResolver)
	if !ok {
		return nil, fmt.Errorf("Cloud Worker credential revision authority is unavailable")
	}
	exactCredentialResolver, ok := credentialResolver.(workaws.ExactCredentialResolver)
	if !ok {
		return nil, fmt.Errorf("Cloud Worker exact credential authority is unavailable")
	}
	credentialAuthority, err := newCloudWorkerCredentialAuthority(credentialResolver, credentialRevisionResolver, exactCredentialResolver, defaults.AWS)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker credential authority: %w", err)
	}
	domain, err := cloudworker.NewServiceWithAWSBindingResolver(cloudStore, defaults, quoter, credentialAuthority)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker domain: %w", err)
	}
	ownerResolver := fixedCloudWorkerOwnerResolver{base: conversationStore, accountGeneration: accountGeneration}
	intrinsic, err := cloudworker.NewProposeIntrinsic(domain, ownerResolver, conversationStore, conversationStore)
	if err != nil {
		return nil, fmt.Errorf("initialize cloud_worker_propose: %w", err)
	}
	sdkFactory, err := newCloudWorkerSDKFactory(credentialAuthority, accountGeneration)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker revision-aware AWS SDK factory: %w", err)
	}
	awsClient := cloudWorkerAWSClientRouter{factory: sdkFactory}
	stagingObjects := cloudWorkerStagingStoreRouter{factory: sdkFactory}
	retentionObjects := cloudWorkerArtifactObjectStoreRouter{factory: sdkFactory}
	outputObjects := cloudWorkerOutputVersionStoreRouter{factory: sdkFactory}

	awsLedger, err := cloudaws.NewPostgresLedger(store.Pool())
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker AWS ledger: %w", err)
	}
	stagingLedger, err := cloudworker.NewPostgresStagingLedger(store.Pool())
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker staging ledger: %w", err)
	}
	outputLedger, err := cloudworker.NewPostgresOutputJournalLedger(store.Pool())
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker output journal: %w", err)
	}
	outputs, err := cloudworker.NewOutputJournalManager(outputLedger, outputObjects)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker output cleanup: %w", err)
	}
	relayStore, err := modelrelay.NewPostgresStore(store.Pool())
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker Model Relay store: %w", err)
	}
	readyCtx, cancelReady := context.WithTimeout(ctx, 10*time.Second)
	err = errors.Join(awsLedger.Ready(readyCtx), stagingLedger.Ready(readyCtx), outputLedger.Ready(readyCtx), relayStore.Ready(readyCtx), cloudStore.ArtifactRetentionReady(readyCtx))
	cancelReady()
	if err != nil {
		return nil, fmt.Errorf("qualify Cloud Worker PostgreSQL authorities: %w", err)
	}
	provider, err := cloudaws.NewProvider(awsClient, awsLedger)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker AWS provider: %w", err)
	}
	stager, err := cloudworker.NewInputStager(conversationStore, stagingObjects, stagingLedger)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker input stager: %w", err)
	}

	modelResolver, err := cloudproduction.NewExactModelResolver(profiles)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker exact model resolver: %w", err)
	}
	providerTransport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("initialize Cloud Worker Model Relay transport")
	}
	providerTransport = providerTransport.Clone()
	providerTransport.Proxy = nil
	providerTransport.DisableCompression = true
	providerTransport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	providerHTTP := &http.Client{Transport: providerTransport, Timeout: 2 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	modelBackend, err := modelrelay.NewHTTPBackend(providerHTTP)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker Model Relay backend: %w", err)
	}
	relay, err := modelrelay.NewService(relayStore, modelResolver, modelResolver, modelBackend)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker Model Relay: %w", err)
	}

	identityEvidence, err := control.NewRevalidatingIdentityEvidenceReader(awsLedger, awsClient, time.Now)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker identity evidence: %w", err)
	}
	iidCertificate, err := os.ReadFile(worker.IIDCertificateFile)
	if err != nil {
		return nil, fmt.Errorf("read Cloud Worker IID certificate: %w", err)
	}
	iidVerifier, err := control.NewPKCS7IIDVerifier(map[string][][]byte{worker.Region: {iidCertificate}})
	clear(iidCertificate)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker IID verifier: %w", err)
	}
	identityVerifier, err := control.NewSTSSigV4IdentityVerifier(iidVerifier, identityEvidence, time.Now)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker identity verifier: %w", err)
	}
	controlDomain, err := control.NewService(controlStore, identityVerifier, controlStore)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker control domain: %w", err)
	}
	workerAuthority, err := cloudproduction.NewWorkerAuthority(tasks, cloudStore, relay, worker.WorkerHeartbeatInterval)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker claim authority: %w", err)
	}
	workerRPC, err := rpcapi.NewWorkerControlService(controlDomain, controlStore, workerAuthority)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker control RPC: %w", err)
	}
	if _, err = loadCloudWorkerTLSIdentity(worker.WorkerControlTLSCertFile, worker.WorkerControlTLSKeyFile, worker.WorkerControlServerName); err != nil {
		return nil, fmt.Errorf("validate Cloud Worker private control identity: %w", err)
	}
	workerControl, err := controlserver.New(controlserver.Config{
		ListenAddress: worker.WorkerControlListenAddress, TLSCertFile: worker.WorkerControlTLSCertFile,
		TLSKeyFile: worker.WorkerControlTLSKeyFile, MaximumConcurrentRPC: worker.WorkerControlMaxConcurrentRPC,
	}, workerRPC)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker private control listener: %w", err)
	}
	modelRelayServer, err := newCloudWorkerModelRelayServer(worker.ModelRelayListenAddress, worker.ModelRelayServerName, worker.ModelRelayTLSCertFile, worker.ModelRelayTLSKeyFile, relay)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker private model listener: %w", err)
	}

	resultReaders := cloudWorkerResultReaderRouter{factory: sdkFactory}
	results, err := cloudworker.NewResultValidatorFactory(resultReaders)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker result validator: %w", err)
	}
	artifactReaders := cloudWorkerArtifactReaderRouter{factory: sdkFactory}
	artifactDownloads, err := cloudworker.NewArtifactDownloadService(cloudStore, credentialAuthority, artifactReaders)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker artifact download service: %w", err)
	}
	executionPort, err := coreexecutionv2.NewCloudWorkerExecutionPort(cloudStore, artifactDownloads)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker Execution V2 port: %w", err)
	}
	controller, err := cloudworker.NewController(cloudworker.ControllerConfig{
		Store: cloudStore, Quoter: quoter, BaseLimits: defaults.Limits, AWSBindings: credentialAuthority, ModelAuthorizations: modelResolver,
		Stager: stager, Outputs: outputs, Qualifications: qualification,
		AWS: provider, Sessions: controlStore, ModelGrants: relay, Results: results,
		PollInterval: worker.ControllerPollInterval, WorkerHeartbeatStaleAfter: 3 * worker.WorkerHeartbeatInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker controller: %w", err)
	}
	reaperDomain, err := cloudaws.NewReaper(provider, awsLedger)
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker Reaper: %w", err)
	}
	retention, err := cloudworker.NewArtifactRetentionCleaner(cloudworker.ArtifactRetentionCleanerConfig{
		Store: cloudStore, Objects: retentionObjects, AWSBindings: credentialAuthority,
		PollInterval: worker.ReaperInterval, ClaimLease: 2 * time.Minute,
		RetryDelay: time.Minute, BatchSize: 32,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker artifact retention cleaner: %w", err)
	}
	outputHistory, err := cloudworker.NewOutputHistoryCleaner(cloudworker.OutputHistoryCleanerConfig{
		Store: cloudStore, PollInterval: worker.ReaperInterval, BatchSize: 32,
	})
	if err != nil {
		return nil, fmt.Errorf("initialize Cloud Worker output history cleaner: %w", err)
	}
	return &coreCloudWorkerComposition{
		domain: domain, intrinsic: intrinsic, executionPort: executionPort, taskHandler: controller.Handler(), outboxStore: cloudStore,
		workerControl: workerControl, modelRelay: modelRelayServer,
		reaper: newCloudWorkerReaperLoop(reaperDomain, worker.ReaperInterval), retention: retention,
		outputHistory: outputHistory,
	}, nil
}

func (composition *coreCloudWorkerComposition) BindCompletion(client *client.Client, interval time.Duration) error {
	if composition == nil || client == nil {
		return cloudworker.ErrInvalid
	}
	dispatcher, err := cloudworker.NewProductCompletionDispatcher(client)
	if err != nil {
		return err
	}
	if composition.outboxStore == nil {
		return cloudworker.ErrInvalid
	}
	loop, err := cloudworker.NewCompletionLoop(cloudworker.CompletionLoopConfig{Store: composition.outboxStore, Dispatcher: dispatcher, PollInterval: interval})
	if err != nil {
		return err
	}
	composition.mu.Lock()
	defer composition.mu.Unlock()
	if composition.started || composition.completion != nil {
		return cloudworker.ErrConflict
	}
	composition.completion = loop
	return nil
}

func (composition *coreCloudWorkerComposition) StartPrivate() error {
	if composition == nil || composition.workerControl == nil || composition.modelRelay == nil || composition.completion == nil {
		return cloudworker.ErrInvalid
	}
	composition.mu.Lock()
	defer composition.mu.Unlock()
	if composition.started || composition.stopped {
		return cloudworker.ErrConflict
	}
	if err := composition.workerControl.Start(); err != nil {
		return err
	}
	if err := composition.modelRelay.Start(); err != nil {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = composition.workerControl.Stop(stopCtx)
		cancel()
		return err
	}
	composition.started = true
	return nil
}

func (composition *coreCloudWorkerComposition) StopPrivate(ctx context.Context) error {
	if composition == nil {
		return nil
	}
	composition.mu.Lock()
	if composition.stopped || !composition.started {
		composition.stopped = true
		composition.mu.Unlock()
		return nil
	}
	composition.stopped = true
	composition.mu.Unlock()
	return errors.Join(composition.modelRelay.Stop(ctx), composition.workerControl.Stop(ctx))
}

func (composition *coreCloudWorkerComposition) Cleaners() []coreLifecycleCleaner {
	if composition == nil {
		return nil
	}
	cleaners := make([]coreLifecycleCleaner, 0, 4)
	if composition.reaper != nil {
		cleaners = append(cleaners, composition.reaper)
	}
	if composition.retention != nil {
		cleaners = append(cleaners, composition.retention)
	}
	if composition.outputHistory != nil {
		cleaners = append(cleaners, composition.outputHistory)
	}
	if composition.completion != nil {
		cleaners = append(cleaners, composition.completion)
	}
	return cleaners
}

type fixedCloudWorkerOwnerResolver struct {
	base              cloudworker.IntrinsicOwnerResolver
	accountGeneration uint64
}

func (resolver fixedCloudWorkerOwnerResolver) ResolveCloudWorkerOwner(ctx context.Context, lease coreconversation.TurnLease) (cloudworker.IntrinsicOwnerContext, error) {
	if resolver.base == nil || resolver.accountGeneration == 0 {
		return cloudworker.IntrinsicOwnerContext{}, cloudworker.ErrInvalid
	}
	owner, err := resolver.base.ResolveCloudWorkerOwner(ctx, lease)
	if err != nil || owner.AccountGeneration != resolver.accountGeneration {
		return cloudworker.IntrinsicOwnerContext{}, cloudworker.ErrStaleAuthorization
	}
	return owner, nil
}

type cloudWorkerModelRelayServer struct {
	address string
	tls     *tls.Config
	server  *http.Server

	mu       sync.Mutex
	listener net.Listener
	started  bool
}

func newCloudWorkerModelRelayServer(address, serverName, certFile, keyFile string, handler http.Handler) (*cloudWorkerModelRelayServer, error) {
	address, serverName = strings.TrimSpace(address), strings.TrimSpace(serverName)
	if address == "" || serverName == "" || handler == nil {
		return nil, cloudworker.ErrInvalid
	}
	identity, err := loadCloudWorkerTLSIdentity(certFile, keyFile, serverName)
	if err != nil {
		return nil, err
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{identity}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}, SessionTicketsDisabled: true}
	server := &http.Server{Handler: handler, TLSConfig: tlsConfig, ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 2 * time.Minute, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	return &cloudWorkerModelRelayServer{address: address, tls: tlsConfig, server: server}, nil
}

func (server *cloudWorkerModelRelayServer) Start() error {
	if server == nil || server.server == nil || server.tls == nil {
		return cloudworker.ErrInvalid
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.started {
		return cloudworker.ErrConflict
	}
	listener, err := net.Listen("tcp", server.address)
	if err != nil {
		return err
	}
	server.listener, server.started = listener, true
	tlsListener := tls.NewListener(listener, server.tls.Clone())
	go func() {
		if err := server.server.Serve(tlsListener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			slog.Error("Cloud Worker Model Relay stopped", "error", err)
		}
	}()
	return nil
}

func (server *cloudWorkerModelRelayServer) Stop(ctx context.Context) error {
	if server == nil || server.server == nil || ctx == nil {
		return cloudworker.ErrInvalid
	}
	server.mu.Lock()
	started := server.started
	server.started = false
	server.mu.Unlock()
	if !started {
		return nil
	}
	return server.server.Shutdown(ctx)
}

func loadCloudWorkerTLSIdentity(certFile, keyFile, serverName string) (tls.Certificate, error) {
	identity, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil || len(identity.Certificate) == 0 {
		return tls.Certificate{}, errors.Join(cloudworker.ErrInvalid, err)
	}
	leaf, err := x509.ParseCertificate(identity.Certificate[0])
	if err != nil || leaf.VerifyHostname(serverName) != nil {
		return tls.Certificate{}, cloudworker.ErrInvalid
	}
	identity.Leaf = leaf
	return identity, nil
}

type cloudWorkerReaperLoop struct {
	reaper   *cloudaws.Reaper
	interval time.Duration
	done     chan struct{}
}

func newCloudWorkerReaperLoop(reaper *cloudaws.Reaper, interval time.Duration) *cloudWorkerReaperLoop {
	if reaper == nil || interval <= 0 {
		return nil
	}
	return &cloudWorkerReaperLoop{reaper: reaper, interval: interval, done: make(chan struct{})}
}

func (loop *cloudWorkerReaperLoop) Run(ctx context.Context) error {
	if loop == nil || ctx == nil {
		return cloudworker.ErrInvalid
	}
	defer close(loop.done)
	ticker := time.NewTicker(loop.interval)
	defer ticker.Stop()
	for {
		if _, err := loop.reaper.Sweep(ctx); err != nil && ctx.Err() == nil {
			slog.Warn("Cloud Worker Reaper sweep deferred", "error", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (loop *cloudWorkerReaperLoop) Wait(ctx context.Context) error {
	if loop == nil || ctx == nil {
		return cloudworker.ErrInvalid
	}
	select {
	case <-loop.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
