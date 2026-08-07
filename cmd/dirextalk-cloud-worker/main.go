// dirextalk-cloud-worker executes exactly one confirmed ephemeral Pi task and
// exits. It has no Agent configuration, database, MCP, Skill, Knowledge,
// extension-runner, local fallback, installer, maintenance, or inbound server.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/worker"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const maximumWorkerControlMessageBytes = 2 << 20

func main() {
	if len(os.Args) != 1 {
		slog.Error("[cloud-worker] outcome=invalid_arguments")
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := run(ctx); err != nil {
		slog.Error("[cloud-worker] outcome=failed", "code", safeFailureCode(err))
		os.Exit(1)
	}
	slog.Info("[cloud-worker] outcome=succeeded")
}

func run(ctx context.Context) error {
	if ctx == nil || currentEffectiveUID() == 0 ||
		validatePrivateDirectory(worker.DefaultStateRoot, currentEffectiveUID(), worker.PiRuntimeGID) != nil ||
		validatePrivateDirectory(worker.DefaultWorkspaceRoot, currentEffectiveUID(), worker.PiRuntimeGID) != nil {
		return worker.ErrInvalid
	}
	imds := worker.NewIMDSClient()
	bootstrapRaw, err := imds.ReadUserData(ctx)
	if err != nil {
		clear(bootstrapRaw)
		return err
	}
	document, unbound, err := worker.ParseBootstrapDocument(bootstrapRaw)
	clear(bootstrapRaw)
	if err != nil {
		return err
	}
	identity, err := imds.ReadIdentity(ctx)
	if err != nil {
		identity.Destroy()
		return err
	}
	bootstrap, err := worker.BindBootstrapIdentity(unbound, identity)
	identity.Destroy()
	if err != nil {
		return err
	}
	installation, err := worker.LoadInstallation(document)
	if err != nil {
		return err
	}
	if err := verifyCurrentExecutable(worker.DefaultWorkerExecutablePath); err != nil {
		return err
	}
	outboundProxy, err := worker.NewOutboundProxy(
		worker.ProxyBindingFromBootstrap(document), installation.OutboundProxyRoots,
		installation.SystemTrustRoots,
	)
	if err != nil {
		return err
	}
	piProxy, err := worker.StartPiCONNECTBridge(
		ctx, outboundProxy, document.ModelRelayServerName,
	)
	if err != nil {
		return err
	}
	defer piProxy.Close()
	connection, err := connectWorkerControl(ctx, document, installation, outboundProxy)
	if err != nil {
		return err
	}
	defer connection.Close()
	control, err := worker.NewGRPCControlClient(
		agentv1.NewWorkerControlServiceClient(connection), bootstrap,
	)
	if err != nil {
		return err
	}
	proofs, err := worker.NewSigV4ProofGenerator(imds, func() time.Time {
		return time.Now().UTC()
	})
	if err != nil {
		return err
	}
	inputObjects, err := worker.NewS3HTTPInputReader(imds, imds, outboundProxy)
	if err != nil {
		return err
	}
	workspaces, err := worker.NewFilesystemWorkspacePreparer(
		inputObjects, worker.DefaultWorkspaceRoot, worker.PiRuntimeGID,
	)
	if err != nil {
		return err
	}
	processes, err := cloudruntime.NewOSProcessRunner(worker.PiRuntimeUID, worker.PiRuntimeGID)
	if err != nil {
		return err
	}
	executor, err := worker.NewPiTaskExecutor(worker.PiTaskExecutorConfig{
		Release: installation.Release, Processes: processes,
		Outputs: cloudruntime.FilesystemOutputCollector{}, Workspaces: workspaces,
		StateRoot: worker.DefaultStateRoot, SearchPath: cloudruntime.DefaultSearchPath,
		PiProxy: piProxy, ModelRelayTrustBundlePath: installation.ModelRelayTrustBundlePath,
		RuntimeGID: worker.PiRuntimeGID,
	})
	if err != nil {
		return err
	}
	outputObjects, err := worker.NewS3HTTPWriter(
		imds, imds, outboundProxy, document.ArtifactKMSKeyARN,
	)
	if err != nil {
		return err
	}
	uploader, err := worker.NewManifestUploader(outputObjects)
	if err != nil {
		return err
	}
	workflow, err := worker.NewWorkflow(worker.WorkflowConfig{
		Bootstrap: bootstrap, Identity: imds, Proofs: proofs, Control: control,
		Executor: executor, Topology: processes, Uploader: uploader,
	})
	if err != nil {
		return err
	}
	workflowCtx, cancelWorkflow := context.WithCancel(ctx)
	defer cancelWorkflow()
	workflowDone := make(chan error, 1)
	go func() { workflowDone <- workflow.Run(workflowCtx) }()
	select {
	case err := <-workflowDone:
		return err
	case bridgeErr := <-piProxy.Errors():
		cancelWorkflow()
		if bridgeErr == nil {
			return worker.ErrUnavailable
		}
		return bridgeErr
	}
}

type workerControlTunnel interface {
	DialTunnel(context.Context, string) (net.Conn, error)
}

func connectWorkerControl(
	ctx context.Context,
	document worker.BootstrapDocument,
	installation worker.Installation,
	outboundProxy workerControlTunnel,
) (*grpc.ClientConn, error) {
	endpoint, err := url.Parse(document.ControlPlaneEndpoint)
	if ctx == nil || err != nil || endpoint.Scheme != "https" || endpoint.Host == "" ||
		installation.TrustRoots == nil || outboundProxy == nil {
		return nil, worker.ErrInvalid
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		RootCAs: installation.TrustRoots, ServerName: document.ControlPlaneServerName,
		NextProtos: []string{"h2"},
	}
	connection, err := grpc.NewClient(
		// The controlled proxy authorizes the original FQDN authority.  Using
		// grpc's DNS resolver here would replace it with an IP address before the
		// custom dialer runs, which both loses that authority and is rejected by
		// OutboundProxy's hostname-only CONNECT boundary.
		"passthrough:///"+endpoint.Host,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithContextDialer(func(dialCtx context.Context, address string) (net.Conn, error) {
			return outboundProxy.DialTunnel(dialCtx, address)
		}),
		grpc.WithDisableRetry(),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maximumWorkerControlMessageBytes),
			grpc.MaxCallSendMsgSize(maximumWorkerControlMessageBytes),
		),
	)
	if err != nil {
		return nil, worker.ErrUnavailable
	}
	return connection, nil
}

func verifyCurrentExecutable(expectedPath string) error {
	actualPath, err := os.Executable()
	if err != nil || !filepath.IsAbs(actualPath) || filepath.Clean(actualPath) != actualPath {
		return worker.ErrInvalid
	}
	actual, err := os.Stat(actualPath)
	if err != nil || !actual.Mode().IsRegular() {
		return worker.ErrInvalid
	}
	expected, err := os.Stat(expectedPath)
	if err != nil || !expected.Mode().IsRegular() || !os.SameFile(actual, expected) {
		return worker.ErrIdentityChanged
	}
	return nil
}

func safeFailureCode(err error) string {
	switch {
	case errors.Is(err, worker.ErrIdentityChanged):
		return "identity_changed"
	case errors.Is(err, worker.ErrCanceled), errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, worker.ErrExpired), errors.Is(err, context.DeadlineExceeded):
		return "expired"
	case errors.Is(err, worker.ErrStaleLease):
		return "stale_lease"
	case errors.Is(err, worker.ErrUploadUncertain):
		return "upload_uncertain"
	case errors.Is(err, cloudruntime.ErrExecution):
		return "runtime_failed"
	case errors.Is(err, worker.ErrInvalid), errors.Is(err, cloudruntime.ErrInvalid),
		errors.Is(err, cloudruntime.ErrUnsupported):
		return "invalid_contract"
	default:
		return "unavailable"
	}
}
