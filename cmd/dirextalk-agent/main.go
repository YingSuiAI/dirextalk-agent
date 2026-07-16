package main

import (
	"context"
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
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("dirextalk-agent stopped", "error", safeError(err))
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) != 1 {
		return errors.New("usage: dirextalk-agent <migrate|bootstrap-service-key|serve>")
	}
	switch arguments[0] {
	case "migrate":
		return migrate()
	case "bootstrap-service-key":
		return bootstrapServiceKey()
	case "serve":
		return serve()
	default:
		return errors.New("unknown command; expected migrate, bootstrap-service-key, or serve")
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
	runtimeComposition, err := app.NewRuntimeComposition(
		store, serverConfig.InstanceID, serverConfig.MountedSecretsDir, serverConfig.ModelProfilesFile, serverConfig.MCPServersFile,
	)
	if err != nil {
		return errors.New("could not initialize Agent runtime")
	}
	grpcServer, err := app.NewServer(
		store, pepper, serverConfig.TLSCertFile, serverConfig.TLSKeyFile,
		app.WithRuntime(runtimeComposition.Coordinator, runtimeComposition.Features),
	)
	if err != nil {
		return errors.New("could not initialize TLS gRPC server")
	}
	listener, err := net.Listen("tcp", serverConfig.ListenAddress)
	if err != nil {
		return fmt.Errorf("listen for gRPC: %w", err)
	}
	defer listener.Close()

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
