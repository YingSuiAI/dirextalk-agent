package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteaminput"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	maxContextBytes           = 512 << 10
	maxCredentialBytes        = 64 << 10
	defaultRPCTimeout         = 20 * time.Second
	officialPiExecutablePath  = "/opt/dirextalk-worker/runtimes/pi/bin/pi"
	officialPiExtensionPath   = "/opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts"
	officialPiSandboxPath     = "/usr/local/bin/dirextalk-pi-sandbox"
	officialPiSearchPath      = "/usr/bin:/bin"
	officialWorkspaceRoot     = "/var/lib/dirextalk-worker/workspaces"
	officialWorkerDigestFile  = "/usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256"
	officialSandboxDigestFile = "/usr/local/share/dirextalk-worker/dirextalk-pi-sandbox.sha256"
)

var (
	digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	rolePattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
	errConfig     = errors.New("cloud Worker configuration is invalid")
	errControl    = errors.New("cloud Worker control is unavailable")
	errInput      = errors.New("cloud Worker input is invalid")
)

type runtimeConfig struct {
	executablePath    string
	executableDigest  string
	extensionPath     string
	extensionDigest   string
	sandboxPath       string
	sandboxDigestFile string
	stateRoot         string
	searchPath        string
	binaryDigestFile  string
	timeout           time.Duration
}

type launchConfig struct {
	endpoint           string
	serverName         string
	caFile             string
	certificateFile    string
	keyFile            string
	executionID        string
	roleID             string
	attempt            uint32
	idempotencyKey     string
	model              coreteamruntime.ModelBinding
	modelRevision      uint64
	credentialRevision uint64
	contextFile        string
	contextDigest      string
	manifestFile       string
	manifestDigest     string
	credentialRoot     string
	workspaceDigest    string
	receiptRoot        string
	workspace          string
	rpcTimeout         time.Duration
}

func main() {
	failure, err := run()
	if err != nil || failure.Valid() {
		slog.Error("cloud Worker stopped", "code", safeWorkerError(err, failure))
		os.Exit(1)
	}
}

func run() (coreteamruntime.ClosedFailure, error) {
	if validateWorkerIdentity() != nil || protectControlProcess() != nil {
		return coreteamruntime.ClosedFailure{}, errConfig
	}
	executable, err := os.Executable()
	if err != nil || verifyExecutable(executable, officialWorkerDigestFile) != nil {
		return coreteamruntime.ClosedFailure{}, errConfig
	}
	launch, err := loadLaunch(os.Getenv)
	if err != nil {
		return coreteamruntime.ClosedFailure{}, err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	journal, err := newReceiptJournal(launch.receiptRoot, uint32(os.Geteuid()))
	if err != nil {
		return coreteamruntime.ClosedFailure{}, errConfig
	}
	locked, err := journal.lock(ctx, receiptKey{ExecutionID: launch.executionID, RoleID: launch.roleID, Attempt: launch.attempt})
	if err != nil {
		return coreteamruntime.ClosedFailure{}, err
	}
	defer locked.close()
	requiresControl, err := receiptRequiresControl(locked)
	if err != nil {
		return coreteamruntime.ClosedFailure{}, err
	}
	if !requiresControl {
		return coreteamruntime.ClosedFailure{}, nil
	}
	connection, identityDigest, err := connectControl(ctx, launch)
	if err != nil {
		return coreteamruntime.ClosedFailure{}, err
	}
	defer connection.Close()
	return executeLockedRole(
		ctx, agentv1.NewCoreTeamWorkerServiceClient(connection), launch, identityDigest, locked,
		func() (coreteamruntime.Runner, error) { return initializePiRunner(os.Getenv) },
	)
}

func initializePiRunner(getenv func(string) string) (coreteamruntime.Runner, error) {
	runtimeValues, err := loadConfig(getenv)
	if err != nil {
		return nil, err
	}
	runner, err := coreteamruntime.NewPiRunner(coreteamruntime.PiConfig{
		ExecutablePath: runtimeValues.executablePath, ExecutableSHA256: runtimeValues.executableDigest,
		ExtensionPath: runtimeValues.extensionPath, ExtensionSHA256: runtimeValues.extensionDigest,
		SandboxLauncherPath: runtimeValues.sandboxPath,
		StateRoot:           runtimeValues.stateRoot, WorkspaceRoot: officialWorkspaceRoot, SearchPath: runtimeValues.searchPath,
		Timeout: runtimeValues.timeout, Processes: coreteamruntime.OSProcessRunner{},
	})
	if err != nil || verifyExecutable(runtimeValues.sandboxPath, runtimeValues.sandboxDigestFile) != nil {
		return nil, errConfig
	}
	return runner, nil
}

func executeLockedRole(
	ctx context.Context,
	control agentv1.CoreTeamWorkerServiceClient,
	launch launchConfig,
	identityDigest string,
	receipt roleReceiptState,
	initialize func() (coreteamruntime.Runner, error),
) (coreteamruntime.ClosedFailure, error) {
	if ctx == nil || control == nil || receipt == nil || initialize == nil {
		return coreteamruntime.ClosedFailure{}, errConfig
	}
	_, found, err := receipt.load()
	if err != nil {
		return coreteamruntime.ClosedFailure{}, errInput
	}
	if found {
		return executeRole(ctx, control, nil, launch, identityDigest, receipt)
	}
	runner, err := initialize()
	if err != nil || runner == nil {
		return coreteamruntime.ClosedFailure{}, errConfig
	}
	return executeRole(ctx, control, runner, launch, identityDigest, receipt)
}

func receiptRequiresControl(receipt roleReceiptState) (bool, error) {
	if receipt == nil {
		return false, errInput
	}
	stored, found, err := receipt.load()
	if err != nil {
		return false, errInput
	}
	if !found {
		return true, nil
	}
	switch stored.State {
	case receiptCompletionAcknowledged:
		return false, nil
	case receiptLaunchCommitted, receiptCompletionPending:
		return true, nil
	default:
		return false, errInput
	}
}

func loadConfig(getenv func(string) string) (runtimeConfig, error) {
	if getenv == nil {
		return runtimeConfig{}, errConfig
	}
	config := runtimeConfig{
		executablePath:    strings.TrimSpace(getenv("DIREXTALK_PI_EXECUTABLE")),
		executableDigest:  strings.TrimSpace(getenv("DIREXTALK_PI_EXECUTABLE_SHA256")),
		extensionPath:     strings.TrimSpace(getenv("DIREXTALK_PI_EXTENSION")),
		extensionDigest:   strings.TrimSpace(getenv("DIREXTALK_PI_EXTENSION_SHA256")),
		sandboxPath:       strings.TrimSpace(getenv("DIREXTALK_PI_SANDBOX")),
		sandboxDigestFile: strings.TrimSpace(getenv("DIREXTALK_PI_SANDBOX_SHA256_FILE")),
		stateRoot:         strings.TrimSpace(getenv("DIREXTALK_PI_STATE_ROOT")),
		searchPath:        strings.TrimSpace(getenv("DIREXTALK_PI_SEARCH_PATH")),
		binaryDigestFile:  strings.TrimSpace(getenv("DIREXTALK_WORKER_BINARY_SHA256_FILE")),
		timeout:           2 * time.Hour,
	}
	if value := strings.TrimSpace(getenv("DIREXTALK_PI_TIMEOUT")); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return runtimeConfig{}, errConfig
		}
		config.timeout = parsed
	}
	if !cleanAbsolute(config.executablePath) || !digestPattern.MatchString(config.executableDigest) ||
		!cleanAbsolute(config.extensionPath) || !digestPattern.MatchString(config.extensionDigest) ||
		config.executableDigest != coreteamruntime.OfficialPiExecutableSHA256 ||
		config.extensionDigest != coreteamruntime.OfficialPiResultExtensionSHA256 ||
		config.executablePath != officialPiExecutablePath || config.extensionPath != officialPiExtensionPath ||
		config.sandboxPath != officialPiSandboxPath || config.sandboxDigestFile != officialSandboxDigestFile ||
		!cleanAbsolute(config.stateRoot) || config.searchPath != officialPiSearchPath || !cleanAbsolute(config.binaryDigestFile) ||
		config.binaryDigestFile != officialWorkerDigestFile ||
		!outsideWorkspaceRoot(config.sandboxDigestFile) || !outsideWorkspaceRoot(config.stateRoot) ||
		!outsideWorkspaceRoot(config.binaryDigestFile) ||
		config.timeout < time.Second || config.timeout > 6*time.Hour || containsSecretConfig(
		config.executablePath, config.extensionPath, config.sandboxPath, config.sandboxDigestFile,
		config.stateRoot, config.searchPath, config.binaryDigestFile,
	) {
		return runtimeConfig{}, errConfig
	}
	return config, nil
}

func loadLaunch(getenv func(string) string) (launchConfig, error) {
	if getenv == nil {
		return launchConfig{}, errConfig
	}
	attempt, err := strconv.ParseUint(strings.TrimSpace(getenv("DIREXTALK_WORKER_ATTEMPT")), 10, 32)
	if err != nil || attempt == 0 {
		return launchConfig{}, errConfig
	}
	modelRevision, err := strconv.ParseUint(strings.TrimSpace(getenv("DIREXTALK_WORKER_MODEL_REVISION")), 10, 64)
	if err != nil || modelRevision == 0 {
		return launchConfig{}, errConfig
	}
	credentialRevision, err := strconv.ParseUint(strings.TrimSpace(getenv("DIREXTALK_WORKER_CREDENTIAL_REVISION")), 10, 64)
	if err != nil || credentialRevision == 0 {
		return launchConfig{}, errConfig
	}
	launch := launchConfig{
		endpoint:        strings.TrimSpace(getenv("DIREXTALK_WORKER_CONTROL_ENDPOINT")),
		serverName:      strings.TrimSpace(getenv("DIREXTALK_WORKER_TLS_SERVER_NAME")),
		caFile:          strings.TrimSpace(getenv("DIREXTALK_WORKER_TLS_CA_FILE")),
		certificateFile: strings.TrimSpace(getenv("DIREXTALK_WORKER_TLS_CERT_FILE")),
		keyFile:         strings.TrimSpace(getenv("DIREXTALK_WORKER_TLS_KEY_FILE")),
		executionID:     strings.TrimSpace(getenv("DIREXTALK_WORKER_EXECUTION_ID")),
		roleID:          strings.TrimSpace(getenv("DIREXTALK_WORKER_ROLE_ID")),
		attempt:         uint32(attempt),
		idempotencyKey:  strings.TrimSpace(getenv("DIREXTALK_WORKER_IDEMPOTENCY_KEY")),
		model: coreteamruntime.ModelBinding{
			Provider:  strings.TrimSpace(getenv("DIREXTALK_WORKER_MODEL_PROVIDER")),
			Name:      strings.TrimSpace(getenv("DIREXTALK_WORKER_MODEL")),
			Interface: "openai_compatible",
		},
		modelRevision: modelRevision, credentialRevision: credentialRevision,
		contextFile:     strings.TrimSpace(getenv("DIREXTALK_WORKER_CONTEXT_FILE")),
		contextDigest:   strings.TrimSpace(getenv("DIREXTALK_WORKER_CONTEXT_SHA256")),
		manifestFile:    strings.TrimSpace(getenv("DIREXTALK_WORKER_INPUT_MANIFEST_FILE")),
		manifestDigest:  strings.TrimSpace(getenv("DIREXTALK_WORKER_INPUT_MANIFEST_SHA256")),
		credentialRoot:  strings.TrimSpace(getenv("DIREXTALK_WORKER_SECRET_ROOT")),
		workspaceDigest: strings.TrimSpace(getenv("DIREXTALK_WORKER_WORKSPACE_SHA256")),
		receiptRoot:     strings.TrimSpace(getenv("DIREXTALK_WORKER_RECEIPT_ROOT")),
		workspace:       strings.TrimSpace(getenv("DIREXTALK_WORKER_WORKSPACE")),
		rpcTimeout:      defaultRPCTimeout,
	}
	if value := strings.TrimSpace(getenv("DIREXTALK_WORKER_RPC_TIMEOUT")); value != "" {
		parsed, parseErr := time.ParseDuration(value)
		if parseErr != nil {
			return launchConfig{}, errConfig
		}
		launch.rpcTimeout = parsed
	}
	if !validEndpoint(launch.endpoint) || launch.serverName == "" || strings.IndexByte(launch.serverName, 0) >= 0 ||
		!cleanAbsolute(launch.caFile) || !cleanAbsolute(launch.certificateFile) || !cleanAbsolute(launch.keyFile) ||
		!outsideWorkspaceRoot(launch.caFile) || !outsideWorkspaceRoot(launch.certificateFile) || !outsideWorkspaceRoot(launch.keyFile) ||
		uuid.Validate(launch.executionID) != nil || !rolePattern.MatchString(launch.roleID) ||
		uuid.Validate(launch.idempotencyKey) != nil || launch.model.Provider == "" || launch.model.Name == "" ||
		!cleanAbsolute(launch.contextFile) || !digestPattern.MatchString(launch.contextDigest) ||
		!cleanAbsolute(launch.manifestFile) || !digestPattern.MatchString(launch.manifestDigest) ||
		!cleanAbsolute(launch.credentialRoot) || !digestPattern.MatchString(launch.workspaceDigest) ||
		!cleanAbsolute(launch.receiptRoot) || !outsideWorkspaceRoot(launch.contextFile) || !outsideWorkspaceRoot(launch.manifestFile) ||
		!outsideWorkspaceRoot(launch.credentialRoot) || !outsideWorkspaceRoot(launch.receiptRoot) || (launch.workspace != "" &&
		(!cleanAbsolute(launch.workspace) || !strictDescendant(officialWorkspaceRoot, launch.workspace))) ||
		launch.rpcTimeout < time.Second || launch.rpcTimeout > time.Minute || containsSecretConfig(
		launch.endpoint, launch.serverName, launch.caFile, launch.certificateFile, launch.keyFile,
		launch.executionID, launch.roleID, launch.idempotencyKey, launch.model.Provider, launch.model.Name,
		launch.contextFile, launch.manifestFile,
		launch.credentialRoot, launch.receiptRoot, launch.workspace,
	) {
		return launchConfig{}, errConfig
	}
	return launch, nil
}

func connectControl(ctx context.Context, launch launchConfig) (*grpc.ClientConn, string, error) {
	caBytes, err := readFile(launch.caFile, 1<<20, false)
	if err != nil {
		return nil, "", errControl
	}
	defer clear(caBytes)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caBytes) {
		return nil, "", errControl
	}
	certificateBytes, err := readFile(launch.certificateFile, 1<<20, false)
	if err != nil {
		return nil, "", errControl
	}
	defer clear(certificateBytes)
	keyBytes, err := readControlPrivateKey(launch.keyFile, uint32(os.Geteuid()))
	if err != nil {
		return nil, "", errControl
	}
	defer clear(keyBytes)
	certificate, err := tls.X509KeyPair(certificateBytes, keyBytes)
	if err != nil || len(certificate.Certificate) == 0 {
		return nil, "", errControl
	}
	digest := sha256.Sum256(certificate.Certificate[0])
	identityDigest := hex.EncodeToString(digest[:])
	connection, err := grpc.NewClient(launch.endpoint, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots, ServerName: launch.serverName,
		Certificates: []tls.Certificate{certificate},
	})))
	if err != nil {
		return nil, "", errControl
	}
	select {
	case <-ctx.Done():
		connection.Close()
		return nil, "", ctx.Err()
	default:
	}
	return connection, identityDigest, nil
}

func executeRole(
	ctx context.Context,
	control agentv1.CoreTeamWorkerServiceClient,
	runner coreteamruntime.Runner,
	launch launchConfig,
	identityDigest string,
	receipt roleReceiptState,
) (coreteamruntime.ClosedFailure, error) {
	if ctx == nil || control == nil || receipt == nil || !digestPattern.MatchString(identityDigest) {
		return coreteamruntime.ClosedFailure{}, errConfig
	}
	key := receiptKey{ExecutionID: launch.executionID, RoleID: launch.roleID, Attempt: launch.attempt}
	stored, found, err := receipt.load()
	if err != nil {
		return coreteamruntime.ClosedFailure{}, errInput
	}
	if found {
		request, parseErr := parseCompleteRequest(stored.CompletionRequest, key)
		if parseErr != nil {
			return coreteamruntime.ClosedFailure{}, errInput
		}
		switch stored.State {
		case receiptCompletionAcknowledged:
			return coreteamruntime.ClosedFailure{}, nil
		case receiptCompletionPending:
			return submitPendingCompletion(ctx, control, request, launch.rpcTimeout, receipt)
		case receiptLaunchCommitted:
			return persistAndSubmitCompletion(ctx, control, request, launch.rpcTimeout, receipt)
		default:
			return coreteamruntime.ClosedFailure{}, errInput
		}
	}
	if runner == nil {
		return coreteamruntime.ClosedFailure{}, errConfig
	}
	challengeContext, cancel := context.WithTimeout(ctx, launch.rpcTimeout)
	challenge, err := control.CreateIdentityChallenge(challengeContext, &agentv1.CoreTeamWorkerServiceCreateIdentityChallengeRequest{
		ExecutionId: launch.executionID, RoleId: launch.roleID, Attempt: launch.attempt,
		IdentityDigest: identityDigest, IdempotencyKey: launch.idempotencyKey,
	})
	cancel()
	if err != nil || uuid.Validate(challenge.GetWorkerId()) != nil || uuid.Validate(challenge.GetChallengeId()) != nil ||
		challenge.GetExecutionId() != launch.executionID || challenge.GetRoleId() != launch.roleID || challenge.GetAttempt() != launch.attempt {
		return coreteamruntime.ClosedFailure{}, errControl
	}
	enrollContext, cancel := context.WithTimeout(ctx, launch.rpcTimeout)
	enrollment, err := control.Enroll(enrollContext, &agentv1.CoreTeamWorkerServiceEnrollRequest{
		ChallengeId: challenge.GetChallengeId(), WorkerId: challenge.GetWorkerId(),
	})
	cancel()
	if err != nil || enrollment.GetWorkerId() != challenge.GetWorkerId() || enrollment.GetExecutionId() != launch.executionID ||
		enrollment.GetRoleId() != launch.roleID || enrollment.GetAttempt() != launch.attempt || enrollment.GetExpiresAt() == nil {
		return coreteamruntime.ClosedFailure{}, errControl
	}
	assignmentContext, cancel := context.WithTimeout(ctx, launch.rpcTimeout)
	wireAssignment, err := control.GetAssignment(assignmentContext, &agentv1.CoreTeamWorkerServiceGetAssignmentRequest{WorkerId: challenge.GetWorkerId()})
	cancel()
	if err != nil {
		return coreteamruntime.ClosedFailure{}, errControl
	}
	assignment, err := mapAssignment(wireAssignment, launch.model)
	if err != nil || assignment.Worker.ExecutionID != launch.executionID || assignment.Worker.RoleID != launch.roleID || assignment.Worker.Attempt != launch.attempt {
		return coreteamruntime.ClosedFailure{}, errControl
	}
	claimContext, cancel := context.WithTimeout(ctx, launch.rpcTimeout)
	claim, err := control.Claim(claimContext, &agentv1.CoreTeamWorkerServiceClaimRequest{
		WorkerId: assignment.Worker.WorkerID, ExecutionId: assignment.Worker.ExecutionID,
		RoleId: assignment.Worker.RoleID, Attempt: assignment.Worker.Attempt,
		ClaimId: stableOperationID(assignment.Worker.ExecutionID, assignment.Worker.RoleID, assignment.Worker.Attempt, "claim"),
	})
	cancel()
	if err != nil || !validClaim(claim, assignment.Worker) {
		return coreteamruntime.ClosedFailure{}, errControl
	}
	if err = receipt.commitLaunch(failureCompleteRequest(claim.GetFence(), coreteamworker.FailureExecutionUncertain)); err != nil {
		return coreteamruntime.ClosedFailure{}, errInput
	}
	contextJSON, err := readDigestBoundFile(launch.contextFile, launch.contextDigest, maxContextBytes, false)
	if err != nil {
		return persistAndSubmitCompletion(ctx, control, failureCompleteRequest(claim.GetFence(), coreteamworker.FailureInternal), launch.rpcTimeout, receipt)
	}
	defer clear(contextJSON)
	manifestJSON, err := readDigestBoundFile(launch.manifestFile, launch.manifestDigest, coreteaminput.MaxManifestBytes, false)
	if err != nil {
		return persistAndSubmitCompletion(ctx, control, failureCompleteRequest(claim.GetFence(), coreteamworker.FailureInternal), launch.rpcTimeout, receipt)
	}
	defer clear(manifestJSON)
	if coreteamruntime.VerifyWorkspaceDigest(launch.workspace, launch.workspaceDigest) != nil {
		return persistAndSubmitCompletion(ctx, control, failureCompleteRequest(claim.GetFence(), coreteamworker.FailureInternal), launch.rpcTimeout, receipt)
	}
	credential, err := consumeModelCredential(launch.credentialRoot, uint32(os.Geteuid()))
	if err != nil {
		return persistAndSubmitCompletion(ctx, control, failureCompleteRequest(claim.GetFence(), coreteamworker.FailureInternal), launch.rpcTimeout, receipt)
	}
	defer clear(credential)
	if coreteaminput.VerifyMaterialized(coreteaminput.MaterializedInput{
		Assignment: assignment.Worker,
		Model: coreteaminput.ModelBindingV1{
			Provider: launch.model.Provider, Name: launch.model.Name, Interface: launch.model.Interface, Revision: launch.modelRevision,
		},
		CredentialRevision: launch.credentialRevision, ContextJSON: contextJSON, ManifestJSON: manifestJSON,
		WorkspaceDigest: launch.workspaceDigest, Credential: credential,
	}) != nil {
		return persistAndSubmitCompletion(ctx, control, failureCompleteRequest(claim.GetFence(), coreteamworker.FailureInternal), launch.rpcTimeout, receipt)
	}
	runContext, cancelRun := context.WithCancel(ctx)
	heartbeatErrors := make(chan error, 1)
	go maintainLease(runContext, cancelRun, control, claim.GetFence(), claim.GetExpiresAt().AsTime(), launch.rpcTimeout, heartbeatErrors)
	result, failure, runErr := runner.Run(runContext, assignment, coreteamruntime.Workspace{
		Directory: launch.workspace, ContextJSON: contextJSON, Credential: credential,
	})
	cancelRun()
	select {
	case heartbeatErr := <-heartbeatErrors:
		if heartbeatErr != nil && runErr == nil && !failure.Valid() {
			runErr = errControl
		}
	default:
	}
	if failure.Valid() {
		code := coreteamworker.FailurePi
		if failure.Stage == coreteamruntime.FailureProcess {
			code = coreteamworker.FailureProcess
		}
		return persistAndSubmitCompletion(ctx, control, failureCompleteRequest(claim.GetFence(), code), launch.rpcTimeout, receipt)
	}
	if runErr != nil {
		code := coreteamworker.FailureInternal
		if errors.Is(runErr, context.Canceled) {
			code = coreteamworker.FailureCanceled
		}
		if errors.Is(runErr, context.DeadlineExceeded) {
			code = coreteamworker.FailureTimeout
		}
		return persistAndSubmitCompletion(ctx, control, failureCompleteRequest(claim.GetFence(), code), launch.rpcTimeout, receipt)
	}
	metadata, err := coreteamruntime.BuildResultMetadata(result)
	if err != nil {
		return persistAndSubmitCompletion(ctx, control, failureCompleteRequest(claim.GetFence(), coreteamworker.FailureInvalidResult), launch.rpcTimeout, receipt)
	}
	defer clear(metadata.PayloadJSON)
	request := &agentv1.CoreTeamWorkerServiceCompleteRequest{
		Fence: claim.GetFence(), CompletionId: stableOperationID(assignment.Worker.ExecutionID, assignment.Worker.RoleID, assignment.Worker.Attempt, "complete"),
		Outcome:             agentv1.CoreTeamWorkerCompletionOutcome_CORE_TEAM_WORKER_COMPLETION_OUTCOME_SUCCEEDED,
		ResultSchemaVersion: metadata.SchemaVersion, ResultDigest: metadata.Digest,
		ResultSizeBytes: metadata.SizeBytes, ResultJson: metadata.PayloadJSON,
	}
	return persistAndSubmitCompletion(ctx, control, request, launch.rpcTimeout, receipt)
}

func strictDescendant(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func outsideWorkspaceRoot(candidate string) bool {
	if !cleanAbsolute(candidate) {
		return false
	}
	relative, err := filepath.Rel(officialWorkspaceRoot, candidate)
	return err == nil && (relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func persistAndSubmitCompletion(
	ctx context.Context,
	control agentv1.CoreTeamWorkerServiceClient,
	request *agentv1.CoreTeamWorkerServiceCompleteRequest,
	timeout time.Duration,
	receipt roleReceiptState,
) (coreteamruntime.ClosedFailure, error) {
	if receipt == nil || request == nil || receipt.commitPending(request) != nil {
		return coreteamruntime.ClosedFailure{}, errInput
	}
	return submitPendingCompletion(ctx, control, request, timeout, receipt)
}

func submitPendingCompletion(
	ctx context.Context,
	control agentv1.CoreTeamWorkerServiceClient,
	request *agentv1.CoreTeamWorkerServiceCompleteRequest,
	timeout time.Duration,
	receipt roleReceiptState,
) (coreteamruntime.ClosedFailure, error) {
	if ctx == nil || control == nil || request == nil || receipt == nil {
		return coreteamruntime.ClosedFailure{}, errConfig
	}
	completeContext, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := control.Complete(completeContext, request)
	if err != nil || !validCompleteResponse(response, request) {
		return coreteamruntime.ClosedFailure{}, errControl
	}
	if receipt.commitAcknowledged() != nil {
		return coreteamruntime.ClosedFailure{}, errInput
	}
	return coreteamruntime.ClosedFailure{}, nil
}

func failureCompleteRequest(fence *agentv1.CoreTeamWorkerLeaseFence, code coreteamworker.FailureCode) *agentv1.CoreTeamWorkerServiceCompleteRequest {
	if fence == nil {
		return nil
	}
	return &agentv1.CoreTeamWorkerServiceCompleteRequest{
		Fence:        fence,
		CompletionId: stableOperationID(fence.GetExecutionId(), fence.GetRoleId(), fence.GetAttempt(), "complete"),
		Outcome:      agentv1.CoreTeamWorkerCompletionOutcome_CORE_TEAM_WORKER_COMPLETION_OUTCOME_FAILED,
		FailureCode:  wireFailureCode(code),
	}
}

func validCompleteResponse(response *agentv1.CoreTeamWorkerServiceCompleteResponse, request *agentv1.CoreTeamWorkerServiceCompleteRequest) bool {
	return response != nil && request != nil && response.GetCompletionId() == request.GetCompletionId() &&
		response.GetOutcome() == request.GetOutcome() && response.GetAcceptedAt() != nil && response.GetAcceptedAt().CheckValid() == nil &&
		!response.GetAcceptedAt().AsTime().IsZero()
}

func maintainLease(
	ctx context.Context,
	cancelRun context.CancelFunc,
	control agentv1.CoreTeamWorkerServiceClient,
	fence *agentv1.CoreTeamWorkerLeaseFence,
	expiresAt time.Time,
	rpcTimeout time.Duration,
	result chan<- error,
) {
	interval := time.Until(expiresAt) / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			result <- nil
			return
		case <-ticker.C:
			heartbeatContext, cancel := context.WithTimeout(ctx, rpcTimeout)
			response, err := control.Heartbeat(heartbeatContext, &agentv1.CoreTeamWorkerServiceHeartbeatRequest{
				Fence: fence, HeartbeatId: uuid.NewString(),
			})
			cancel()
			if err != nil || response.GetFence() == nil || response.GetExpiresAt() == nil ||
				!sameFence(response.GetFence(), fence) || !response.GetExpiresAt().AsTime().After(time.Now()) {
				cancelRun()
				result <- errControl
				return
			}
			expiresAt = response.GetExpiresAt().AsTime()
		}
	}
}

func validClaim(claim *agentv1.CoreTeamWorkerServiceClaimResponse, assignment coreteamworker.Assignment) bool {
	return claim != nil && claim.GetFence() != nil && claim.GetExpiresAt() != nil && claim.GetExpiresAt().AsTime().After(time.Now()) &&
		claim.GetFence().GetExecutionId() == assignment.ExecutionID && claim.GetFence().GetRoleId() == assignment.RoleID &&
		claim.GetFence().GetWorkerId() == assignment.WorkerID && claim.GetFence().GetAttempt() == assignment.Attempt &&
		claim.GetFence().GetLeaseEpoch() != 0
}

func sameFence(left, right *agentv1.CoreTeamWorkerLeaseFence) bool {
	return left != nil && right != nil && left.GetExecutionId() == right.GetExecutionId() && left.GetRoleId() == right.GetRoleId() &&
		left.GetWorkerId() == right.GetWorkerId() && left.GetAttempt() == right.GetAttempt() && left.GetLeaseEpoch() == right.GetLeaseEpoch()
}

func mapAssignment(input *agentv1.CoreTeamWorkerServiceGetAssignmentResponse, model coreteamruntime.ModelBinding) (coreteamruntime.Assignment, error) {
	if input == nil {
		return coreteamruntime.Assignment{}, errControl
	}
	capabilities := make([]coreteam.Capability, len(input.GetCapabilities()))
	for index, capability := range input.GetCapabilities() {
		capabilities[index] = coreteam.Capability(capability)
	}
	assignment := coreteamruntime.Assignment{
		Worker: coreteamworker.Assignment{
			WorkerID: input.GetWorkerId(), ExecutionID: input.GetExecutionId(), PlanID: input.GetPlanId(),
			RoleID: input.GetRoleId(), Attempt: input.GetAttempt(), PlanDigest: input.GetPlanDigest(),
			RuntimeContextDigest: input.GetRuntimeContextDigest(),
			Goal:                 input.GetGoal(), Capabilities: capabilities, RuntimeID: input.GetRuntimeId(),
			OutputTokens: input.GetOutputTokens(), ResultSchemaVersion: input.GetResultSchemaVersion(),
		},
		Model: model,
	}
	if assignment.Validate() != nil {
		return coreteamruntime.Assignment{}, errControl
	}
	return assignment, nil
}

func wireFailureCode(code coreteamworker.FailureCode) agentv1.CoreTeamWorkerFailureCode {
	switch code {
	case coreteamworker.FailureProcess:
		return agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_PROCESS
	case coreteamworker.FailurePi:
		return agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_PI
	case coreteamworker.FailureInvalidResult:
		return agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_INVALID_RESULT
	case coreteamworker.FailureTimeout:
		return agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_TIMEOUT
	case coreteamworker.FailureCanceled:
		return agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_CANCELED
	case coreteamworker.FailureExecutionUncertain:
		return agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_EXECUTION_UNCERTAIN
	default:
		return agentv1.CoreTeamWorkerFailureCode_CORE_TEAM_WORKER_FAILURE_CODE_INTERNAL
	}
}

func stableOperationID(executionID, roleID string, attempt uint32, operation string) string {
	name := fmt.Sprintf("%s/%s/%d/%s", executionID, roleID, attempt, operation)
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String()
}

func readDigestBoundFile(path, expectedDigest string, maximum int64, secret bool) ([]byte, error) {
	content, err := readFile(path, maximum, secret)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(content)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		clear(content)
		return nil, errInput
	}
	return content, nil
}

func readFile(path string, maximum int64, secret bool) ([]byte, error) {
	state, err := os.Lstat(path)
	if err != nil || state.Mode()&os.ModeSymlink != 0 || !state.Mode().IsRegular() || state.Size() < 1 || state.Size() > maximum ||
		(secret && state.Mode().Perm()&0o077 != 0) {
		return nil, errInput
	}
	content, err := os.ReadFile(path)
	if err != nil || int64(len(content)) != state.Size() {
		clear(content)
		return nil, errInput
	}
	return content, nil
}

func verifyExecutable(executablePath, digestFile string) error {
	if !cleanAbsolute(executablePath) || !cleanAbsolute(digestFile) {
		return errConfig
	}
	sidecar, err := readFile(digestFile, 512, false)
	if err != nil {
		return errConfig
	}
	defer clear(sidecar)
	fields := strings.Fields(string(sidecar))
	if len(fields) != 2 || !digestPattern.MatchString(fields[0]) || fields[1] != executablePath {
		return errConfig
	}
	state, err := os.Lstat(executablePath)
	if err != nil || state.Mode()&os.ModeSymlink != 0 || !state.Mode().IsRegular() || state.Mode().Perm()&0o022 != 0 {
		return errConfig
	}
	file, err := os.Open(executablePath)
	if err != nil {
		return errConfig
	}
	defer file.Close()
	openedState, err := file.Stat()
	if err != nil || !os.SameFile(state, openedState) {
		return errConfig
	}
	digest := sha256.New()
	written, err := io.Copy(digest, io.LimitReader(file, state.Size()+1))
	if err != nil || written != state.Size() {
		return errConfig
	}
	if hex.EncodeToString(digest.Sum(nil)) != fields[0] {
		return errConfig
	}
	return nil
}

func safeWorkerError(_ error, failure coreteamruntime.ClosedFailure) string {
	if failure.Valid() {
		return failure.Error()
	}
	return "worker_internal"
}

func validEndpoint(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" || strings.ContainsAny(value, "/@") {
		return false
	}
	_, err = strconv.ParseUint(port, 10, 16)
	return err == nil
}

func validSearchPath(value string) bool {
	if value == "" || strings.IndexByte(value, 0) >= 0 {
		return false
	}
	for _, entry := range strings.Split(value, ":") {
		if !cleanAbsolute(entry) {
			return false
		}
	}
	return true
}

func containsSecretConfig(values ...string) bool {
	for _, value := range values {
		if security.ContainsLikelySecret(value) {
			return true
		}
	}
	return false
}

func cleanAbsolute(value string) bool {
	return filepath.IsAbs(value) && filepath.Clean(value) == value
}
