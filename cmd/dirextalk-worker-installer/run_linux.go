//go:build linux

package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/ec2rolecreds"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
)

const (
	defaultTrustFile   = "/etc/dirextalk-installer/trust.cbor"
	defaultJournalFile = "/var/lib/dirextalk-installer/execution.journal"
)

func run() error {
	if os.Geteuid() != 0 {
		return installer.Error(installer.CodeInvalidRequest)
	}
	if len(os.Args) != 2 {
		return installer.Error(installer.CodeInvalidRequest)
	}
	switch os.Args[1] {
	case "serve":
		return runDaemon()
	case "bootstrap":
		return runBootstrap()
	default:
		return installer.Error(installer.CodeInvalidRequest)
	}
}

func runDaemon() error {
	trustContent, err := installer.ReadRootOwnedFile(defaultTrustFile, 64<<10)
	if err != nil {
		return err
	}
	defer clear(trustContent)
	trust, err := installerbootstrap.DecodeTrustFile(trustContent)
	if err != nil {
		return installer.Error(installer.CodeInvalidRequest)
	}
	inspector, err := installer.NewRootOwnedArtifactInspector(trust.Config.TargetRoot)
	if err != nil {
		return err
	}
	journal, err := installer.OpenRootOwnedExecutionJournal(defaultJournalFile)
	if err != nil {
		return err
	}
	verifier, err := installer.NewVerifier(installer.VerifierConfig{
		PublicKey: trust.PublicKey, ExpectedTrustID: trust.TrustID, ExpectedBinding: trust.Config.Binding, TargetRoot: trust.Config.TargetRoot, Inspector: inspector,
		Runner: installer.OSCommandRunner{}, Journal: journal,
	})
	if err != nil {
		return err
	}
	listener, err := systemdListener()
	if err != nil {
		return installer.Error(installer.CodeInvalidRequest)
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = listener.Close()
	}()
	return installer.NewServer(verifier, installer.ServerConfig{}).Serve(ctx, listener)
}

func runBootstrap() error {
	metadata := imds.New(imds.Options{EnableFallback: aws.FalseTernary})
	source, err := installerbootstrap.NewIMDSSource(metadata)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	configuration, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithEC2IMDSRegion(func(options *awsconfig.UseEC2IMDSRegion) { options.Client = metadata }),
		awsconfig.WithCredentialsProvider(ec2rolecreds.New(func(options *ec2rolecreds.Options) { options.Client = metadata })),
	)
	if err != nil {
		return installerbootstrap.ErrArtifactSource
	}
	downloader, err := installerbootstrap.NewS3ArtifactDownloader(s3.NewFromConfig(configuration))
	if err != nil {
		return err
	}
	secretDownloader, err := installerbootstrap.NewSecretsDownloader(secretsmanager.NewFromConfig(configuration))
	if err != nil {
		return err
	}
	service, err := installerbootstrap.NewArtifactSecretAndVolumeService(
		source, installerbootstrap.NewAtomicTrustMaterializer(), downloader, installerbootstrap.NewAtomicArtifactMaterializer(),
		installerbootstrap.NewLinuxVolumeMaterializer(),
		secretDownloader, installerbootstrap.NewAtomicSecretMaterializer(),
		installerbootstrap.NewSystemdSocketController(), installerbootstrap.DefaultTrustFile,
	)
	if err != nil {
		return err
	}
	return service.Run(ctx)
}

func systemdListener() (net.Listener, error) {
	pid, pidErr := strconv.Atoi(os.Getenv("LISTEN_PID"))
	fds, fdsErr := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	if pidErr != nil || fdsErr != nil || pid != os.Getpid() || fds != 1 {
		return nil, fmt.Errorf("exactly one systemd socket is required")
	}
	file := os.NewFile(uintptr(3), "dirextalk-worker-installer.socket")
	if file == nil {
		return nil, fmt.Errorf("systemd listener fd is unavailable")
	}
	defer file.Close()
	listener, err := net.FileListener(file)
	if err != nil {
		return nil, err
	}
	if _, ok := listener.(*net.UnixListener); !ok {
		_ = listener.Close()
		return nil, fmt.Errorf("systemd listener is not a Unix socket")
	}
	return listener, nil
}
