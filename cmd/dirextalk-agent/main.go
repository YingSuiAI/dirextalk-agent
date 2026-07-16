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
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/app"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/worker"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("dirextalk-agent stopped", "error", safeError(err))
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) != 1 {
		return errors.New("usage: dirextalk-agent <migrate|bootstrap-service-key|bootstrap-approval-device|serve>")
	}
	switch arguments[0] {
	case "migrate":
		return migrate()
	case "bootstrap-service-key":
		return bootstrapServiceKey()
	case "bootstrap-approval-device":
		return bootstrapApprovalDevice()
	case "serve":
		return serve()
	default:
		return errors.New("unknown command; expected migrate, bootstrap-service-key, bootstrap-approval-device, or serve")
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
	if serverConfig.EnableAWSControl {
		if serverConfig.WorkerAMIPublicationFile != "" {
			release, releaseErr := workerrelease.LoadPublicationFile(serverConfig.WorkerAMIPublicationFile)
			if releaseErr != nil || release.AgentInstanceID != serverConfig.InstanceID {
				return errors.New("could not validate configured Worker AMI publication")
			}
			importContext, stopImport := context.WithTimeout(context.Background(), 30*time.Second)
			_, releaseErr = store.ImportWorkerRelease(importContext, release)
			stopImport()
			if releaseErr != nil {
				return errors.New("could not persist configured Worker AMI publication")
			}
		}
		var cloudErr error
		cloudComposition, cloudErr = app.NewCloudComposition(
			store, secretManager, workerStore, workerService, installerIssuer, serverConfig.InstanceID, masterKey,
			serverConfig.AWSReaperImageURI, serverConfig.WorkerControlEndpoint,
		)
		if cloudErr != nil {
			return errors.New("could not initialize typed AWS cloud control")
		}
		defer cloudComposition.Close()
		foundationRecoveryContext, stopFoundationRecovery := context.WithTimeout(context.Background(), 2*time.Minute)
		cloudErr = cloudComposition.Recover(foundationRecoveryContext)
		stopFoundationRecovery()
		if cloudErr != nil {
			return errors.New("could not safely recover pending AWS Foundation operations")
		}
	}
	runtimeOptions := make([]app.RuntimeCompositionOption, 0, 1)
	if cloudComposition != nil {
		runtimeOptions = append(runtimeOptions, app.WithCloudGoalMaterializer(cloudComposition.ProviderPlans))
	}
	runtimeComposition, err := app.NewRuntimeComposition(
		store, serverConfig.InstanceID, serverConfig.MountedSecretsDir, serverConfig.ModelProfilesFile, serverConfig.MCPServersFile,
		runtimeOptions...,
	)
	if err != nil {
		return errors.New("could not initialize Agent runtime")
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
		app.WithCloudGoals(runtimeComposition.CloudGoals),
		app.WithSecretBootstrap(secretManager, serverConfig.InstanceID),
		app.WithWorkerControl(workerService),
	}
	if cloudComposition != nil {
		serverOptions = append(serverOptions,
			app.WithCloudControl(cloudComposition.Coordinator),
			app.WithCloudDestroy(cloudComposition.DestroyCoordinator),
			app.WithWorkerIdentity(cloudComposition.WorkerIdentityVerifier, cloudComposition.WorkerIdentityMaterializer),
		)
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
	slog.Info("dirextalk-agent gRPC server ready", "listen", serverConfig.ListenAddress, "instance_id", serverConfig.InstanceID)
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
