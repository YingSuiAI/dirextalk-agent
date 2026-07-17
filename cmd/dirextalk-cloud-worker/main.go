package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/config"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
	installerroothelper "github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/workeridentity"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerlog"
	"github.com/YingSuiAI/dirextalk-agent/internal/workermaintenance"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/ec2/imds"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	workerBootstrapSchema = installerbootstrap.UserDataSchemaV1
	identityMethod        = "aws_sts_sigv4"
	maxUserDataBytes      = 32 << 10
	localTokenMode        = "token"
	workerRuntimeUID      = 65532
	workerRuntimeGID      = 65532
)

var (
	digestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	regionPattern = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
)

func main() {
	if err := run(); err != nil {
		slog.Error("cloud Worker stopped", "error", safeWorkerError(err))
		os.Exit(1)
	}
}

func run() error {
	if err := validateRuntimeIdentity(currentRuntimeIdentity()); err != nil {
		return err
	}
	if err := verifyCurrentExecutable(requiredEnvironment("DIREXTALK_WORKER_BINARY_SHA256_FILE")); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	launch, err := loadLaunch(ctx, imdsUserDataSource{client: imds.New(imds.Options{EnableFallback: aws.FalseTernary})})
	if err != nil {
		return err
	}
	defer clear(launch.token)

	endpoint, err := parseControlEndpoint(launch.endpoint)
	if err != nil {
		return err
	}
	roots, err := loadRoots(requiredEnvironment("DIREXTALK_WORKER_TLS_CA_FILE"))
	if err != nil {
		return err
	}
	connection, err := grpc.NewClient(endpoint.Host, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: endpoint.Hostname(),
	})))
	if err != nil {
		return errors.New("initialize outbound Worker gRPC client")
	}
	defer connection.Close()

	awsOptions := make([]func(*awsconfig.LoadOptions) error, 0, 1)
	if launch.region != "" {
		awsOptions = append(awsOptions, awsconfig.WithRegion(launch.region))
	}
	awsConfiguration, err := awsconfig.LoadDefaultConfig(ctx, awsOptions...)
	if err != nil {
		return errors.New("load scoped Worker role configuration")
	}
	control := workerrunner.NewGRPCControlClient(agentv1.NewWorkerControlServiceClient(connection))
	if launch.method == identityMethod {
		generator, err := workeridentity.NewGenerator(awsConfiguration.Credentials, time.Now)
		if err != nil {
			return errors.New("initialize Worker identity proof")
		}
		enrolled, err := enrollAWSIdentity(ctx, control, generator, launch.config, launch.region)
		if err != nil {
			return err
		}
		launch.config.IdentityAssignment = enrolled.GetAssignment()
		launch.config.IdentitySessionToken = enrolled.GetSessionToken()
		defer clear(launch.config.IdentitySessionToken)
	} else {
		launch.config.EnrollmentToken = launch.token
	}

	objects, err := workerrunner.NewS3ObjectStore(s3.NewFromConfig(awsConfiguration))
	if err != nil {
		return err
	}
	installerClient, err := installer.NewSocketClient(installer.DefaultSocketPath)
	if err != nil {
		return err
	}
	installerAction, err := workerrunner.NewInstallerExecuteAction(installerClient, time.Now)
	if err != nil {
		return err
	}
	registry, err := workerrunner.NewRegistry(workerrunner.NoopAction{}, installerAction)
	if err != nil {
		return err
	}
	var logs workerrunner.LogSink
	if launch.method == identityMethod {
		access := launch.config.IdentityAssignment.GetAccess()
		if access == nil {
			return errors.New("provider-verified Worker assignment has no log scope")
		}
		cloudwatchSink, err := workerlog.NewCloudWatchSink(cloudwatchlogs.NewFromConfig(awsConfiguration), access.GetLogGroup(), access.GetLogPrefix())
		if err != nil {
			return errors.New("initialize scoped Worker milestone logs")
		}
		logs = cloudwatchSink
	}
	runner := workerrunner.Runner{Control: control, Objects: objects, Registry: registry, Logs: logs}
	slog.Info("cloud Worker starting typed execution", "deployment_id", launch.config.DeploymentID, "worker_id", launch.config.WorkerID)
	result, err := runner.Run(ctx, launch.config)
	if err != nil {
		return err
	}
	slog.Info("cloud Worker execution finished", "deployment_id", launch.config.DeploymentID, "outcome", result.Outcome.String(), "actions", len(result.CompletedActions))
	if launch.method != identityMethod {
		return nil
	}
	rootSocket, err := installerroothelper.NewSocketClient(installer.DefaultSocketPath)
	if err != nil {
		return errors.New("initialize root-helper socket client")
	}
	rootControl, err := workermaintenance.NewSocketRootControl(rootSocket)
	if err != nil {
		return errors.New("initialize root-helper control")
	}
	maintenanceControl, err := workermaintenance.NewGRPCControl(
		agentv1.NewRootHelperBootstrapControlServiceClient(connection),
		agentv1.NewWorkerServiceOperationServiceClient(connection),
		launch.config.DeploymentID, launch.config.WorkerID, launch.config.IdentitySessionToken,
	)
	if err != nil {
		return errors.New("initialize Worker maintenance control")
	}
	defer maintenanceControl.Close()
	slog.Info("cloud Worker entering typed maintenance", "deployment_id", launch.config.DeploymentID, "worker_id", launch.config.WorkerID)
	err = (&workermaintenance.Service{
		Control: maintenanceControl, Root: rootControl, PollInterval: time.Second,
		Lease: launch.config.LeaseDuration,
	}).Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

type runtimeIdentity struct {
	uid      int
	gid      int
	verified bool
}

func validateRuntimeIdentity(identity runtimeIdentity) error {
	if !identity.verified || identity.uid != workerRuntimeUID || identity.gid != workerRuntimeGID {
		return fmt.Errorf("cloud Worker must run as fixed unprivileged uid/gid %d:%d", workerRuntimeUID, workerRuntimeGID)
	}
	return nil
}

func verifyCurrentExecutable(digestFile string) error {
	if strings.TrimSpace(digestFile) == "" {
		return errors.New("DIREXTALK_WORKER_BINARY_SHA256_FILE is required")
	}
	executable, err := os.Executable()
	if err != nil {
		return errors.New("resolve Worker executable")
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return errors.New("resolve Worker executable path")
	}
	return verifyExecutableDigest(executable, digestFile)
}

func verifyExecutableDigest(executable, digestFile string) error {
	digestInfo, err := os.Lstat(digestFile)
	if err != nil || !digestInfo.Mode().IsRegular() || digestInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("Worker binary digest file must be a regular file")
	}
	digestReader, err := os.Open(digestFile)
	if err != nil {
		return errors.New("open Worker binary digest file")
	}
	digestBytes, readErr := io.ReadAll(io.LimitReader(digestReader, 66))
	closeErr := digestReader.Close()
	if readErr != nil || closeErr != nil || len(digestBytes) == 0 || len(digestBytes) > 65 {
		clear(digestBytes)
		return errors.New("read Worker binary digest file")
	}
	digestText := string(digestBytes)
	clear(digestBytes)
	if strings.HasSuffix(digestText, "\n") {
		digestText = strings.TrimSuffix(digestText, "\n")
	}
	if len(digestText) != sha256.Size*2 || strings.ToLower(digestText) != digestText {
		return errors.New("Worker binary digest is invalid")
	}
	expected, err := hex.DecodeString(digestText)
	if err != nil || len(expected) != sha256.Size {
		clear(expected)
		return errors.New("Worker binary digest is invalid")
	}
	defer clear(expected)

	binary, err := os.Open(executable)
	if err != nil {
		return errors.New("open Worker executable")
	}
	hash := sha256.New()
	_, copyErr := io.Copy(hash, binary)
	closeErr = binary.Close()
	actual := hash.Sum(nil)
	defer clear(actual)
	if copyErr != nil || closeErr != nil {
		return errors.New("hash Worker executable")
	}
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return errors.New("Worker executable digest mismatch")
	}
	return nil
}

type workerLaunch struct {
	config   workerrunner.Config
	endpoint string
	region   string
	method   string
	token    []byte
}

type workerBootstrapV1 = installerbootstrap.UserDataV1

type userDataSource interface {
	Read(context.Context) ([]byte, error)
}

type imdsUserDataSource struct{ client *imds.Client }

func (source imdsUserDataSource) Read(ctx context.Context) ([]byte, error) {
	if source.client == nil {
		return nil, errors.New("EC2 metadata client is unavailable")
	}
	response, err := source.client.GetUserData(ctx, nil)
	if err != nil || response == nil || response.Content == nil {
		return nil, errors.New("read EC2 Worker bootstrap from IMDSv2")
	}
	defer response.Content.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Content, maxUserDataBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxUserDataBytes {
		clear(raw)
		return nil, errors.New("EC2 Worker bootstrap is invalid")
	}
	return raw, nil
}

func loadLaunch(ctx context.Context, source userDataSource) (workerLaunch, error) {
	mode := requiredEnvironment("DIREXTALK_WORKER_LOCAL_TEST_MODE")
	if mode != "" {
		if mode != localTokenMode {
			return workerLaunch{}, errors.New("DIREXTALK_WORKER_LOCAL_TEST_MODE must be token when enabled")
		}
		return loadLocalTokenLaunch()
	}
	if source == nil {
		return workerLaunch{}, errors.New("EC2 Worker bootstrap source is unavailable")
	}
	raw, err := source.Read(ctx)
	if err != nil {
		return workerLaunch{}, err
	}
	defer clear(raw)
	var bootstrap workerBootstrapV1
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bootstrap); err != nil {
		return workerLaunch{}, errors.New("decode EC2 Worker bootstrap")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return workerLaunch{}, errors.New("EC2 Worker bootstrap has trailing data")
	}
	if err := validateBootstrap(bootstrap); err != nil {
		return workerLaunch{}, err
	}
	leaseSeconds, err := leaseSecondsEnvironment()
	if err != nil {
		return workerLaunch{}, err
	}
	return workerLaunch{
		endpoint: bootstrap.ControlPlaneEndpoint, region: bootstrap.Region, method: bootstrap.EnrollmentMethod,
		config: workerrunner.Config{
			DeploymentID: bootstrap.DeploymentID, WorkerID: bootstrap.WorkerID,
			EnrollmentExpectedRevision: bootstrap.EnrollmentExpectedRevision,
			LeaseDuration:              time.Duration(leaseSeconds) * time.Second,
		},
	}, nil
}

func validateBootstrap(bootstrap workerBootstrapV1) error {
	for _, value := range []string{bootstrap.ResourceID, bootstrap.DeploymentID, bootstrap.WorkerID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil || parsed.String() != value {
			return errors.New("EC2 Worker bootstrap identifiers are invalid")
		}
	}
	artifact, err := url.Parse(strings.TrimSpace(bootstrap.ArtifactRef))
	if bootstrap.SchemaVersion != workerBootstrapSchema || !digestPattern.MatchString(bootstrap.SpecDigest) || !digestPattern.MatchString(bootstrap.ArtifactDigest) ||
		artifact == nil || err != nil || artifact.Scheme != "s3" || artifact.Host == "" || artifact.Path == "" || strings.HasSuffix(artifact.Path, "/") ||
		artifact.User != nil || artifact.RawQuery != "" || artifact.Fragment != "" || !regionPattern.MatchString(bootstrap.Region) ||
		bootstrap.EnrollmentExpectedRevision < 1 || bootstrap.EnrollmentMethod != identityMethod {
		return errors.New("EC2 Worker bootstrap contract is invalid")
	}
	if bootstrap.InstallerTrust != nil {
		if _, err := installerbootstrap.ValidateTrustMaterial(*bootstrap.InstallerTrust, bootstrap.DeploymentID); err != nil {
			return errors.New("EC2 Worker installer trust is invalid")
		}
	}
	_, err = parseControlEndpoint(bootstrap.ControlPlaneEndpoint)
	return err
}

func loadLocalTokenLaunch() (workerLaunch, error) {
	expectedRevision, err := integerEnvironment("DIREXTALK_WORKER_ENROLL_EXPECTED_REVISION", 1)
	if err != nil || expectedRevision < 1 {
		return workerLaunch{}, errors.New("DIREXTALK_WORKER_ENROLL_EXPECTED_REVISION must be positive")
	}
	leaseSeconds, err := leaseSecondsEnvironment()
	if err != nil {
		return workerLaunch{}, err
	}
	tokenFile := requiredEnvironment("DIREXTALK_WORKER_ENROLLMENT_TOKEN_FILE")
	if err := config.ValidateMountedSecretFile(tokenFile); err != nil {
		return workerLaunch{}, errors.New("Worker enrollment token file is not protected")
	}
	raw, err := os.ReadFile(tokenFile)
	if err != nil {
		return workerLaunch{}, errors.New("read Worker enrollment token file")
	}
	token := bytes.Clone(bytes.TrimSpace(raw))
	clear(raw)
	if len(token) < 32 || len(token) > 128 {
		clear(token)
		return workerLaunch{}, errors.New("Worker enrollment token is invalid")
	}
	return workerLaunch{
		endpoint: requiredEnvironment("DIREXTALK_WORKER_CONTROL_ENDPOINT"), region: requiredEnvironment("DIREXTALK_WORKER_AWS_REGION"), method: localTokenMode, token: token,
		config: workerrunner.Config{
			DeploymentID: requiredEnvironment("DIREXTALK_WORKER_DEPLOYMENT_ID"), WorkerID: requiredEnvironment("DIREXTALK_WORKER_ID"),
			EnrollmentIdempotencyKey: requiredEnvironment("DIREXTALK_WORKER_ENROLL_IDEMPOTENCY_KEY"), EnrollmentExpectedRevision: expectedRevision,
			LeaseDuration: time.Duration(leaseSeconds) * time.Second,
		},
	}, nil
}

type identityControl interface {
	CreateIdentityChallenge(context.Context, *agentv1.CreateIdentityChallengeRequest) (*agentv1.CreateIdentityChallengeResponse, error)
	EnrollVerifiedIdentity(context.Context, *agentv1.EnrollVerifiedIdentityRequest) (*agentv1.EnrollVerifiedIdentityResponse, error)
}

type proofGenerator interface {
	Generate(context.Context, workeridentity.GenerateRequest) (workeridentity.ProofV1, error)
}

func enrollAWSIdentity(ctx context.Context, control identityControl, generator proofGenerator, runnerConfig workerrunner.Config, region string) (*agentv1.EnrollVerifiedIdentityResponse, error) {
	if control == nil || generator == nil || !regionPattern.MatchString(region) {
		return nil, errors.New("Worker identity enrollment is not configured")
	}
	challengeKey, err := deterministicWorkerKey(runnerConfig.DeploymentID, runnerConfig.WorkerID, "identity-challenge")
	if err != nil {
		return nil, err
	}
	enrollmentKey, err := deterministicWorkerKey(runnerConfig.DeploymentID, runnerConfig.WorkerID, "identity-enrollment")
	if err != nil {
		return nil, err
	}
	challengeResponse, err := retryIdentity(ctx, func() (*agentv1.CreateIdentityChallengeResponse, error) {
		return control.CreateIdentityChallenge(ctx, &agentv1.CreateIdentityChallengeRequest{
			DeploymentId: runnerConfig.DeploymentID, WorkerId: runnerConfig.WorkerID,
			IdempotencyKey: challengeKey, ExpectedRevision: runnerConfig.EnrollmentExpectedRevision,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("create Worker identity challenge: %w", err)
	}
	challenge := challengeResponse.GetChallenge()
	if challenge == nil || challenge.GetDeploymentId() != runnerConfig.DeploymentID || challenge.GetWorkerId() != runnerConfig.WorkerID ||
		challenge.GetRegion() != region || challenge.GetExpectedRevision() != runnerConfig.EnrollmentExpectedRevision {
		return nil, errors.New("Worker identity challenge response is invalid")
	}
	return retryIdentity(ctx, func() (*agentv1.EnrollVerifiedIdentityResponse, error) {
		proof, err := generator.Generate(ctx, workeridentity.GenerateRequest{Region: region, ChallengeID: challenge.GetChallengeId()})
		if err != nil {
			return nil, errors.New("generate Worker identity proof")
		}
		defer proof.Destroy()
		response, err := control.EnrollVerifiedIdentity(ctx, &agentv1.EnrollVerifiedIdentityRequest{
			ChallengeId: challenge.GetChallengeId(), DeploymentId: runnerConfig.DeploymentID, WorkerId: runnerConfig.WorkerID,
			IdempotencyKey: enrollmentKey, ExpectedRevision: runnerConfig.EnrollmentExpectedRevision,
			Proof: &agentv1.WorkerIdentityProof{
				SchemaVersion: int32(proof.SchemaVersion), Region: proof.Region, Endpoint: proof.Endpoint, Method: proof.Method, Host: proof.Host,
				ContentType: proof.ContentType, ContentSha256: proof.ContentSHA256, AmzDate: proof.AmzDate, ChallengeId: proof.ChallengeID,
				Body: proof.Body, Authorization: proof.Authorization, SessionToken: proof.SessionToken,
			},
		})
		if err != nil {
			return nil, err
		}
		if response.GetAssignment() == nil || response.GetAssignment().GetDeploymentId() != runnerConfig.DeploymentID ||
			response.GetAssignment().GetWorkerId() != runnerConfig.WorkerID || response.GetAssignment().GetRevision() <= runnerConfig.EnrollmentExpectedRevision ||
			len(response.GetSessionToken()) < 32 {
			clear(response.SessionToken)
			return nil, errors.New("Worker identity enrollment response is invalid")
		}
		return response, nil
	})
}

func deterministicWorkerKey(deploymentID, workerID, operation string) (string, error) {
	deployment, deploymentErr := uuid.Parse(strings.TrimSpace(deploymentID))
	workerIDValue, workerErr := uuid.Parse(strings.TrimSpace(workerID))
	if deploymentErr != nil || deployment == uuid.Nil || workerErr != nil || workerIDValue == uuid.Nil || operation == "" {
		return "", errors.New("Worker identity enrollment identifiers are invalid")
	}
	return uuid.NewSHA1(deployment, []byte("dirextalk-agent/"+operation+"/"+workerIDValue.String())).String(), nil
}

func retryIdentity[T any](ctx context.Context, call func() (T, error)) (T, error) {
	var zero T
	for attempt := 0; attempt < 3; attempt++ {
		result, err := call()
		if err == nil {
			return result, nil
		}
		if ctx.Err() != nil || (status.Code(err) != codes.Unavailable && status.Code(err) != codes.DeadlineExceeded) || attempt == 2 {
			return zero, err
		}
		timer := time.NewTimer(250 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return zero, ctx.Err()
		case <-timer.C:
		}
	}
	return zero, errors.New("Worker identity retry exhausted")
}

func parseControlEndpoint(raw string) (*url.URL, error) {
	endpoint, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || endpoint.Scheme != "grpcs" || endpoint.Host == "" || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || security.ContainsLikelySecret(raw) {
		return nil, errors.New("Worker control endpoint must be a credential-free grpcs endpoint")
	}
	return endpoint, nil
}

func loadRoots(path string) (*x509.CertPool, error) {
	roots, err := x509.SystemCertPool()
	if err != nil || roots == nil {
		roots = x509.NewCertPool()
	}
	if strings.TrimSpace(path) == "" {
		return roots, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("read Worker TLS CA file")
	}
	defer clear(content)
	if !roots.AppendCertsFromPEM(content) {
		return nil, errors.New("Worker TLS CA file contains no certificates")
	}
	return roots, nil
}

func leaseSecondsEnvironment() (int64, error) {
	leaseSeconds, err := integerEnvironment("DIREXTALK_WORKER_LEASE_SECONDS", 60)
	if err != nil || leaseSeconds < 5 || leaseSeconds > 1800 {
		return 0, errors.New("DIREXTALK_WORKER_LEASE_SECONDS must be between 5 and 1800")
	}
	return leaseSeconds, nil
}

func requiredEnvironment(name string) string { return strings.TrimSpace(os.Getenv(name)) }

func integerEnvironment(name string, fallback int64) (int64, error) {
	value := requiredEnvironment(name)
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s", name)
	}
	return parsed, nil
}

func safeWorkerError(err error) string {
	if err == nil {
		return ""
	}
	message := security.RedactText(err.Error())
	if len(message) > 512 {
		message = message[:512]
	}
	return message
}
