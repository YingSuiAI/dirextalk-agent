// Package coreteamruntime runs one qualified official Pi role and reduces all
// runtime traffic to the closed Agent Core Team result contract.
package coreteamruntime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	OfficialPiVersion               = "0.83.0"
	OfficialPiExecutableSHA256      = "c25c16162b62eda32deb0d544bcae5e5d6c6148958e17130e6aed2d115104f1a"
	OfficialPiResultExtensionSHA256 = "39e98a6a8339a48c0b1609ff7aed3c7af0807ee9e2cb4a975b64e46a2e5f94d9"
	PiResultExtensionName           = "dirextalk_result_v1"
	piResultToolName                = "dirextalk_submit_result"
	maxPiEventLineBytes             = 2 << 20
	MaxProcessOutputBytes           = 8 << 20
	maxRuntimeContextBytes          = 512 << 10
	maxModelCredentialBytes         = 64 << 10
	defaultRuntimeTimeout           = 2 * time.Hour
)

const piSystemPrompt = `Execute one approved Dirextalk Worker role.
Use only the enabled tools and the supplied workspace.
Do not inspect credential locations or reveal private configuration.
Call dirextalk_submit_result exactly once as the final action.`

var (
	ErrInvalid       = errors.New("core Team runtime input is invalid")
	ErrInvalidResult = errors.New("core Team runtime result is invalid")
	ErrUnavailable   = errors.New("core Team runtime is unavailable")
	digestPattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	providerPattern  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	modelPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
)

type FailureStage string

const (
	FailureProcess FailureStage = "process"
	FailurePi      FailureStage = "pi"
)

type FailureCode string

const (
	FailureProcessStart           FailureCode = "process_start"
	FailureProcessTimeout         FailureCode = "process_timeout"
	FailureProcessOutputLimit     FailureCode = "process_output_limit"
	FailureProcessExitNonZero     FailureCode = "process_exit_nonzero"
	FailureProviderAuthentication FailureCode = "provider_authentication"
	FailureProviderQuota          FailureCode = "provider_quota"
	FailureProviderRateLimit      FailureCode = "provider_rate_limit"
	FailureProviderRequest        FailureCode = "provider_request"
	FailureProviderServer         FailureCode = "provider_server"
	FailureProviderNetwork        FailureCode = "provider_network"
	FailureProviderUnknown        FailureCode = "provider_unknown"
	FailurePiAborted              FailureCode = "pi_aborted"
	FailurePiEventInvalid         FailureCode = "pi_event_invalid"
	FailurePiFinalMissing         FailureCode = "pi_final_missing"
)

type ClosedFailure struct {
	Stage FailureStage
	Code  FailureCode
}

func (failure ClosedFailure) Valid() bool {
	switch failure.Stage {
	case FailureProcess:
		switch failure.Code {
		case FailureProcessStart, FailureProcessTimeout, FailureProcessOutputLimit, FailureProcessExitNonZero:
			return true
		}
	case FailurePi:
		switch failure.Code {
		case FailureProviderAuthentication, FailureProviderQuota, FailureProviderRateLimit,
			FailureProviderRequest, FailureProviderServer, FailureProviderNetwork, FailureProviderUnknown,
			FailurePiAborted, FailurePiEventInvalid, FailurePiFinalMissing:
			return true
		}
	}
	return false
}

func (failure ClosedFailure) Error() string {
	if !failure.Valid() {
		return "runtime_failure"
	}
	return string(failure.Stage) + "/" + string(failure.Code)
}

type ModelBinding struct {
	Provider  string
	Name      string
	Interface string
}

func (binding ModelBinding) validate() error {
	if !providerPattern.MatchString(binding.Provider) || !modelPattern.MatchString(binding.Name) ||
		binding.Interface != "openai_compatible" || modelCredentialEnvironment(binding.Provider) == "" {
		return ErrInvalid
	}
	return nil
}

// Assignment adds the qualified model binding to the immutable Worker DTO.
// The controller maps the first field directly from coreteamworker.Assignment.
type Assignment struct {
	Worker coreteamworker.Assignment
	Model  ModelBinding
}

func (assignment Assignment) Validate() error {
	if assignment.Worker.Validate() != nil || assignment.Worker.RuntimeID != coreteam.OfficialRuntimeID ||
		assignment.Model.validate() != nil {
		return ErrInvalid
	}
	return nil
}

type Workspace struct {
	Directory   string
	ContextJSON []byte
	Credential  []byte
}

func (workspace Workspace) validate() error {
	if workspace.Directory != "" && !cleanAbsolute(workspace.Directory) {
		return ErrInvalid
	}
	if len(workspace.ContextJSON) == 0 || len(workspace.ContextJSON) > maxRuntimeContextBytes ||
		!json.Valid(workspace.ContextJSON) || security.ContainsLikelySecret(string(workspace.ContextJSON)) ||
		len(workspace.Credential) < 16 || len(workspace.Credential) > maxModelCredentialBytes ||
		bytes.IndexByte(workspace.Credential, 0) >= 0 {
		return ErrInvalid
	}
	return nil
}

// Runner intentionally returns known runtime failures separately from internal
// errors so provider text and terminal output cannot cross the Worker boundary.
type Runner interface {
	Run(context.Context, Assignment, Workspace) (Result, ClosedFailure, error)
}

type PiConfig struct {
	ExecutablePath      string
	ExecutableSHA256    string
	ExtensionPath       string
	ExtensionSHA256     string
	SandboxLauncherPath string
	StateRoot           string
	WorkspaceRoot       string
	SearchPath          string
	Timeout             time.Duration
	Processes           ProcessRunner
}

type PiRunner struct {
	executablePath      string
	executableSHA256    string
	extensionPath       string
	extensionSHA256     string
	runtimeRoot         string
	sandboxLauncherPath string
	stateRoot           string
	workspaceRoot       string
	searchPath          string
	timeout             time.Duration
	processes           ProcessRunner
}

func NewPiRunner(config PiConfig) (*PiRunner, error) {
	if !cleanAbsolute(config.ExecutablePath) || !digestPattern.MatchString(config.ExecutableSHA256) ||
		!cleanAbsolute(config.ExtensionPath) || !digestPattern.MatchString(config.ExtensionSHA256) ||
		!cleanAbsolute(config.SandboxLauncherPath) || !cleanAbsolute(config.StateRoot) || !cleanAbsolute(config.WorkspaceRoot) ||
		!validSearchPath(config.SearchPath) || config.Processes == nil {
		return nil, ErrInvalid
	}
	runtimeRoot := filepath.Dir(filepath.Dir(config.ExecutablePath))
	if !withinPath(runtimeRoot, config.ExtensionPath) {
		return nil, ErrInvalid
	}
	if config.Timeout == 0 {
		config.Timeout = defaultRuntimeTimeout
	}
	if config.Timeout < time.Second || config.Timeout > 6*time.Hour ||
		verifyRegularFile(config.ExecutablePath, config.ExecutableSHA256, true) != nil ||
		verifyRegularFile(config.ExtensionPath, config.ExtensionSHA256, false) != nil ||
		verifyExecutablePath(config.SandboxLauncherPath) != nil || verifyStateRoot(config.StateRoot) != nil ||
		verifyStateRoot(config.WorkspaceRoot) != nil {
		return nil, ErrInvalid
	}
	if preparePiDirectory(config.StateRoot) != nil || preparePiDirectory(config.WorkspaceRoot) != nil {
		return nil, ErrInvalid
	}
	return &PiRunner{
		executablePath: config.ExecutablePath, executableSHA256: config.ExecutableSHA256,
		extensionPath: config.ExtensionPath, extensionSHA256: config.ExtensionSHA256,
		runtimeRoot: runtimeRoot, sandboxLauncherPath: config.SandboxLauncherPath,
		stateRoot: config.StateRoot, workspaceRoot: config.WorkspaceRoot,
		searchPath: config.SearchPath, timeout: config.Timeout, processes: config.Processes,
	}, nil
}

func (runner *PiRunner) Run(ctx context.Context, assignment Assignment, workspace Workspace) (result Result, failure ClosedFailure, runErr error) {
	if runner == nil || ctx == nil || assignment.Validate() != nil || workspace.validate() != nil {
		return Result{}, ClosedFailure{}, ErrInvalid
	}
	if err := validateQualifiedCapabilities(assignment.Worker.Capabilities, runner.searchPath); err != nil {
		return Result{}, ClosedFailure{}, err
	}
	if verifyRegularFile(runner.executablePath, runner.executableSHA256, true) != nil ||
		verifyRegularFile(runner.extensionPath, runner.extensionSHA256, false) != nil {
		return Result{}, ClosedFailure{}, ErrUnavailable
	}
	jobRoot, err := os.MkdirTemp(runner.stateRoot, "pi-role-")
	if err != nil {
		return Result{}, ClosedFailure{}, ErrUnavailable
	}
	defer func() {
		if cleanupErr := cleanupPiJobRoot(runner.stateRoot, jobRoot); cleanupErr != nil {
			result = Result{}
			failure = ClosedFailure{}
			runErr = ErrUnavailable
		}
	}()
	if preparePiDirectory(jobRoot) != nil {
		return Result{}, ClosedFailure{}, ErrUnavailable
	}
	home := filepath.Join(jobRoot, "home")
	configRoot := filepath.Join(jobRoot, "config")
	temporaryRoot := filepath.Join(jobRoot, "tmp")
	for _, directory := range []string{home, configRoot, temporaryRoot} {
		if os.Mkdir(directory, piDirectoryMode) != nil || preparePiDirectory(directory) != nil {
			return Result{}, ClosedFailure{}, ErrUnavailable
		}
	}
	workspaceDirectory := workspace.Directory
	if workspaceDirectory == "" {
		workspaceDirectory = filepath.Join(jobRoot, "workspace")
		if os.Mkdir(workspaceDirectory, piDirectoryMode) != nil || preparePiDirectory(workspaceDirectory) != nil {
			return Result{}, ClosedFailure{}, ErrUnavailable
		}
	} else if verifyWorkspace(runner.workspaceRoot, workspaceDirectory) != nil {
		return Result{}, ClosedFailure{}, ErrInvalid
	} else if err := preparePiWorkspace(workspaceDirectory); err != nil {
		if errors.Is(err, ErrInvalid) {
			return Result{}, ClosedFailure{}, ErrInvalid
		}
		return Result{}, ClosedFailure{}, ErrUnavailable
	}
	if writeModelsConfig(configRoot, assignment) != nil {
		return Result{}, ClosedFailure{}, ErrUnavailable
	}
	prompt, err := piPrompt(assignment, workspace.ContextJSON)
	if err != nil {
		return Result{}, ClosedFailure{}, err
	}
	defer clear(prompt)
	credential := bytes.Clone(workspace.Credential)
	defer clear(credential)
	secretEnvironment := map[string][]byte{modelCredentialEnvironment(assignment.Model.Provider): credential}
	defer destroySecretEnvironment(secretEnvironment)
	environment := map[string]string{
		"PATH": runner.searchPath, "HOME": home, "PI_CODING_AGENT_DIR": configRoot,
		"TMPDIR": temporaryRoot, "PI_OFFLINE": "1", "PI_TELEMETRY": "0",
		"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "dumb",
	}
	if capabilitiesRequireShell(assignment.Worker.Capabilities) {
		environment["GIT_CONFIG_COUNT"] = "1"
		environment["GIT_CONFIG_KEY_0"] = "safe.directory"
		environment["GIT_CONFIG_VALUE_0"] = workspaceDirectory
	}
	stdout, failure, runErr := runner.processes.Run(ctx, ProcessSpec{
		Executable:        runner.executablePath,
		Arguments:         piArguments(assignment, runner.extensionPath),
		Directory:         workspaceDirectory,
		Environment:       environment,
		SecretEnvironment: secretEnvironment,
		Stdin:             prompt, MaxStdoutBytes: MaxProcessOutputBytes,
		MaxStderrBytes: coreteamworker.MaxResultTextBytes, Timeout: runner.timeout,
		Sandbox: runner.piSandboxPolicy(jobRoot, workspaceDirectory, assignment.Worker.Capabilities),
	})
	defer clear(stdout)
	if recoverPiWorkspace(workspaceDirectory) != nil {
		return Result{}, ClosedFailure{}, ErrUnavailable
	}
	if failure.Valid() {
		return Result{}, failure, nil
	}
	if runErr != nil {
		if errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded) {
			return Result{}, ClosedFailure{}, runErr
		}
		return Result{}, ClosedFailure{}, ErrUnavailable
	}
	parsed, parseFailure := parsePiEvents(stdout)
	if parseFailure.Valid() {
		return Result{}, parseFailure, nil
	}
	result, err = buildResult(parsed.final, parsed.usage)
	if err != nil {
		return Result{}, ClosedFailure{Stage: FailurePi, Code: FailurePiEventInvalid}, nil
	}
	return result, ClosedFailure{}, nil
}

func (runner *PiRunner) piSandboxPolicy(jobRoot, workspace string, capabilities []coreteam.Capability) *SandboxPolicy {
	paths := []SandboxPath{{Path: runner.runtimeRoot, Access: SandboxReadExecute}}
	for _, path := range []string{"/usr/lib", "/usr/lib64", "/lib", "/lib64"} {
		paths = appendExistingSandboxPath(paths, path, SandboxReadExecute)
	}
	for _, path := range []string{
		"/usr/share", "/etc/ssl/certs", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
		"/etc/passwd", "/etc/group",
	} {
		paths = appendExistingSandboxPath(paths, path, SandboxReadOnly)
	}
	paths = append(paths, SandboxPath{Path: "/proc/self", Access: SandboxReadOnly})
	for _, path := range []string{"/dev/null", "/dev/urandom"} {
		paths = appendExistingSandboxPath(paths, path, SandboxReadWrite)
	}
	workspaceAccess := SandboxReadOnly
	shell := capabilitiesRequireShell(capabilities)
	write := capabilitiesRequireWorkspaceWrite(capabilities)
	if write {
		workspaceAccess = SandboxReadWrite
	}
	if shell {
		if write {
			workspaceAccess = SandboxReadWriteExecute
		} else {
			workspaceAccess = SandboxReadExecute
		}
		for _, directory := range strings.Split(runner.searchPath, ":") {
			paths = appendExistingSandboxPath(paths, directory, SandboxReadExecute)
		}
		paths = appendExistingSandboxPath(paths, "/usr/libexec", SandboxReadExecute)
	}
	paths = append(paths, SandboxPath{Path: jobRoot, Access: SandboxReadWrite})
	if workspace != jobRoot {
		paths = append(paths, SandboxPath{Path: workspace, Access: workspaceAccess})
	}
	return &SandboxPolicy{LauncherPath: runner.sandboxLauncherPath, MinimumLandlockABI: 2, Paths: paths}
}

func appendExistingSandboxPath(paths []SandboxPath, path string, access SandboxAccess) []SandboxPath {
	if !cleanAbsolute(path) {
		return paths
	}
	if _, err := os.Stat(path); err != nil {
		return paths
	}
	for _, existing := range paths {
		if existing.Path == path && existing.Access == access {
			return paths
		}
	}
	return append(paths, SandboxPath{Path: path, Access: access})
}

func capabilitiesRequireShell(capabilities []coreteam.Capability) bool {
	for _, capability := range capabilities {
		if capability == coreteam.CapabilityShell || capability == coreteam.CapabilityTest || capability == coreteam.CapabilityGit {
			return true
		}
	}
	return false
}

func capabilitiesRequireWorkspaceWrite(capabilities []coreteam.Capability) bool {
	for _, capability := range capabilities {
		if capability == coreteam.CapabilityRepositoryWrite {
			return true
		}
	}
	return false
}

func withinPath(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func verifyExecutablePath(path string) error {
	state, err := os.Stat(path)
	if err != nil || !state.Mode().IsRegular() || state.Mode().Perm()&0o111 == 0 {
		return ErrInvalid
	}
	return nil
}

func piArguments(assignment Assignment, extensionPath string) []string {
	return []string{
		"--mode", "json", "--print", "--no-session", "--offline",
		"--provider", assignment.Model.Provider, "--model", assignment.Model.Name,
		"--thinking", "medium", "--tools", piTools(assignment.Worker.Capabilities),
		"--extension", extensionPath, "--no-extensions", "--no-skills", "--no-prompt-templates",
		"--no-themes", "--no-context-files", "--no-approve", "--system-prompt", piSystemPrompt,
	}
}

func piTools(capabilities []coreteam.Capability) string {
	allowed := []string{"read", "grep", "find", "ls"}
	bashEnabled := false
	for _, capability := range capabilities {
		if !bashEnabled && (capability == coreteam.CapabilityShell || capability == coreteam.CapabilityTest || capability == coreteam.CapabilityGit) {
			allowed = append(allowed, "bash")
			bashEnabled = true
		}
		if capability == coreteam.CapabilityRepositoryWrite {
			allowed = append(allowed, "edit", "write")
		}
	}
	allowed = append(allowed, piResultToolName)
	return strings.Join(allowed, ",")
}

func validateQualifiedCapabilities(capabilities []coreteam.Capability, searchPath string) error {
	requiresShell := false
	requiresGit := false
	for _, capability := range capabilities {
		switch capability {
		case coreteam.CapabilityRepositoryRead, coreteam.CapabilityRepositoryWrite,
			coreteam.CapabilityCodeReview, coreteam.CapabilityStructuredResult:
		case coreteam.CapabilityShell, coreteam.CapabilityTest:
			requiresShell = true
		case coreteam.CapabilityGit:
			requiresShell = true
			requiresGit = true
		case coreteam.CapabilityWebResearch, coreteam.CapabilityBrowser, coreteam.CapabilityMCPClient:
			return ErrInvalid
		default:
			return ErrInvalid
		}
	}
	if requiresShell && !executableInSearchPath(searchPath, "bash") {
		return ErrUnavailable
	}
	if requiresGit && !executableInSearchPath(searchPath, "git") {
		return ErrUnavailable
	}
	return nil
}

func executableInSearchPath(searchPath, name string) bool {
	for _, directory := range strings.Split(searchPath, ":") {
		state, err := os.Stat(filepath.Join(directory, name))
		if err == nil && state.Mode().IsRegular() && state.Mode().Perm()&0o111 != 0 {
			return true
		}
	}
	return false
}

func piPrompt(assignment Assignment, contextJSON []byte) ([]byte, error) {
	if assignment.Validate() != nil || !json.Valid(contextJSON) || security.ContainsLikelySecret(string(contextJSON)) {
		return nil, ErrInvalid
	}
	var prompt bytes.Buffer
	prompt.WriteString("Execute one approved remote Worker role.\n")
	prompt.WriteString("Use dirextalk_submit_result exactly once as the final action.\n\n")
	prompt.WriteString("Execution ID: ")
	prompt.WriteString(assignment.Worker.ExecutionID)
	prompt.WriteString("\nRole: ")
	prompt.WriteString(assignment.Worker.RoleID)
	prompt.WriteString("\nObjective:\n")
	prompt.WriteString(assignment.Worker.Goal)
	prompt.WriteString("\n\nImmutable context JSON (sha256 verified):\n")
	prompt.Write(contextJSON)
	prompt.WriteByte('\n')
	if prompt.Len() > coreteam.MaxRoleGoalBytes+maxRuntimeContextBytes+1024 {
		return nil, ErrInvalid
	}
	return prompt.Bytes(), nil
}

func writeModelsConfig(configRoot string, assignment Assignment) error {
	override := map[string]any{"maxTokens": assignment.Worker.OutputTokens}
	if assignment.Model.Provider == "deepseek" {
		override["compat"] = map[string]any{"maxTokensField": "max_tokens"}
	}
	config := map[string]any{"providers": map[string]any{
		assignment.Model.Provider: map[string]any{"modelOverrides": map[string]any{assignment.Model.Name: override}},
	}}
	encoded, err := json.Marshal(config)
	if err != nil {
		return ErrUnavailable
	}
	defer clear(encoded)
	path := filepath.Join(configRoot, "models.json")
	if os.WriteFile(path, encoded, piConfigFileMode) != nil || preparePiFile(path) != nil {
		return ErrUnavailable
	}
	return nil
}

type parsedPiResult struct {
	final piFinal
	usage coreteamworker.ResultUsageV1
}

type piEvent struct {
	Type      string          `json:"type"`
	Version   int             `json:"version,omitempty"`
	Message   json.RawMessage `json:"message,omitempty"`
	ToolName  string          `json:"toolName,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	IsError   bool            `json:"isError,omitempty"`
	WillRetry bool            `json:"willRetry,omitempty"`
}

type piMessage struct {
	Role         string  `json:"role"`
	Usage        piUsage `json:"usage"`
	StopReason   string  `json:"stopReason"`
	ErrorMessage string  `json:"errorMessage"`
}

type piUsage struct {
	Input      int64 `json:"input"`
	Output     int64 `json:"output"`
	CacheRead  int64 `json:"cacheRead"`
	CacheWrite int64 `json:"cacheWrite"`
	Reasoning  int64 `json:"reasoning"`
}

type piToolResult struct {
	Details   json.RawMessage `json:"details"`
	Terminate bool            `json:"terminate"`
}

func parsePiEvents(stream []byte) (parsedPiResult, ClosedFailure) {
	invalid := ClosedFailure{Stage: FailurePi, Code: FailurePiEventInvalid}
	if len(stream) == 0 || len(stream) > MaxProcessOutputBytes || !utf8.Valid(stream) {
		return parsedPiResult{}, invalid
	}
	scanner := bufio.NewScanner(bytes.NewReader(stream))
	scanner.Buffer(make([]byte, 64<<10), maxPiEventLineBytes)
	sessionSeen, agentStarted, agentEnded, agentSettled, finalSeen := false, false, false, false, false
	var parsed parsedPiResult
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if agentSettled {
			return parsedPiResult{}, invalid
		}
		var event piEvent
		if json.Unmarshal(line, &event) != nil || !validPiEventType(event.Type) {
			return parsedPiResult{}, invalid
		}
		if (!sessionSeen && event.Type != "session") ||
			(sessionSeen && !agentStarted && event.Type != "agent_start") ||
			(agentEnded && !agentSettled && event.Type != "agent_settled") {
			return parsedPiResult{}, invalid
		}
		switch event.Type {
		case "session":
			if sessionSeen || agentStarted || event.Version != 3 {
				return parsedPiResult{}, invalid
			}
			sessionSeen = true
		case "agent_start":
			if !sessionSeen || agentStarted || agentEnded {
				return parsedPiResult{}, invalid
			}
			agentStarted = true
		case "message_end":
			if !agentStarted || agentEnded {
				return parsedPiResult{}, invalid
			}
			var message piMessage
			if json.Unmarshal(event.Message, &message) != nil {
				return parsedPiResult{}, invalid
			}
			if message.Role == "assistant" {
				if message.StopReason == "error" {
					return parsedPiResult{}, classifyProviderFailure(message.ErrorMessage)
				}
				if message.StopReason == "aborted" {
					return parsedPiResult{}, ClosedFailure{Stage: FailurePi, Code: FailurePiAborted}
				}
				if addPiUsage(&parsed.usage, message.Usage) != nil {
					return parsedPiResult{}, invalid
				}
			}
		case "tool_execution_end":
			if !agentStarted || agentEnded {
				return parsedPiResult{}, invalid
			}
			if event.ToolName != piResultToolName {
				continue
			}
			if finalSeen || event.IsError {
				return parsedPiResult{}, invalid
			}
			var result piToolResult
			if json.Unmarshal(event.Result, &result) != nil || !result.Terminate {
				return parsedPiResult{}, invalid
			}
			final, err := parsePiFinal(result.Details)
			if err != nil {
				return parsedPiResult{}, invalid
			}
			parsed.final, finalSeen = final, true
		case "agent_end":
			if !agentStarted || agentEnded || event.WillRetry {
				return parsedPiResult{}, invalid
			}
			agentEnded = true
		case "agent_settled":
			if !agentEnded || agentSettled {
				return parsedPiResult{}, invalid
			}
			agentSettled = true
		}
	}
	if scanner.Err() != nil || !sessionSeen || !agentStarted || !agentEnded || !agentSettled {
		return parsedPiResult{}, invalid
	}
	if !finalSeen {
		return parsedPiResult{}, ClosedFailure{Stage: FailurePi, Code: FailurePiFinalMissing}
	}
	if parsed.usage.Validate() != nil {
		return parsedPiResult{}, invalid
	}
	return parsed, ClosedFailure{}
}

func parsePiFinal(input []byte) (piFinal, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var final piFinal
	if decoder.Decode(&final) != nil {
		return piFinal{}, ErrInvalidResult
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return piFinal{}, ErrInvalidResult
	}
	if final.Deliverables == nil || final.Tests == nil || final.Risks == nil {
		return piFinal{}, ErrInvalidResult
	}
	if _, err := buildResult(final, coreteamworker.ResultUsageV1{}); err != nil {
		return piFinal{}, err
	}
	return final, nil
}

func addPiUsage(total *coreteamworker.ResultUsageV1, value piUsage) error {
	if total == nil || value.Input < 0 || value.Output < 0 || value.CacheRead < 0 || value.CacheWrite < 0 || value.Reasoning < 0 ||
		value.CacheRead > math.MaxInt64-value.Input || value.CacheWrite > math.MaxInt64-value.Input-value.CacheRead {
		return ErrInvalidResult
	}
	input := uint64(value.Input + value.CacheRead + value.CacheWrite)
	if total.InputTokens > math.MaxUint64-input || total.OutputTokens > math.MaxUint64-uint64(value.Output) ||
		total.CachedInputTokens > math.MaxUint64-uint64(value.CacheRead) ||
		total.ReasoningOutputTokens > math.MaxUint64-uint64(value.Reasoning) {
		return ErrInvalidResult
	}
	total.InputTokens += input
	total.CachedInputTokens += uint64(value.CacheRead)
	total.OutputTokens += uint64(value.Output)
	total.ReasoningOutputTokens += uint64(value.Reasoning)
	return total.Validate()
}

func classifyProviderFailure(message string) ClosedFailure {
	normalized := strings.ToLower(strings.TrimSpace(message))
	code := FailureProviderUnknown
	switch {
	case strings.HasPrefix(normalized, "401"), strings.Contains(normalized, "authentication"), strings.Contains(normalized, "unauthorized"), strings.Contains(normalized, "invalid api key"):
		code = FailureProviderAuthentication
	case strings.HasPrefix(normalized, "402"), strings.Contains(normalized, "insufficient_balance"), strings.Contains(normalized, "quota"), strings.Contains(normalized, "billing"):
		code = FailureProviderQuota
	case strings.HasPrefix(normalized, "429"), strings.Contains(normalized, "rate_limit"):
		code = FailureProviderRateLimit
	case strings.HasPrefix(normalized, "400"), strings.HasPrefix(normalized, "404"), strings.HasPrefix(normalized, "422"), strings.Contains(normalized, "invalid_request"):
		code = FailureProviderRequest
	case strings.HasPrefix(normalized, "500"), strings.HasPrefix(normalized, "502"), strings.HasPrefix(normalized, "503"), strings.HasPrefix(normalized, "504"), strings.Contains(normalized, "server_error"), strings.Contains(normalized, "service unavailable"):
		code = FailureProviderServer
	case strings.Contains(normalized, "fetch failed"), strings.Contains(normalized, "connection"), strings.Contains(normalized, "network"), strings.Contains(normalized, "timed out"):
		code = FailureProviderNetwork
	}
	return ClosedFailure{Stage: FailurePi, Code: code}
}

func validPiEventType(value string) bool {
	switch value {
	case "session", "agent_start", "agent_end", "agent_settled", "entry_appended", "session_info_changed",
		"thinking_level_changed", "turn_start", "turn_end", "message_start", "message_update", "message_end",
		"bash_execution_update", "tool_execution_start", "tool_execution_update", "tool_execution_end", "queue_update",
		"compaction_start", "compaction_end", "auto_retry_start", "auto_retry_end", "summarization_retry_scheduled",
		"summarization_retry_attempt_start", "summarization_retry_finished":
		return true
	default:
		return false
	}
}

func modelCredentialEnvironment(provider string) string {
	switch provider {
	case "openai":
		return "OPENAI_API_KEY"
	case "deepseek":
		return "DEEPSEEK_API_KEY"
	default:
		return ""
	}
}

func verifyRegularFile(path, expectedDigest string, executable bool) error {
	state, err := os.Lstat(path)
	if err != nil || state.Mode()&os.ModeSymlink != 0 || !state.Mode().IsRegular() || state.Mode().Perm()&0o022 != 0 ||
		(executable && state.Mode().Perm()&0o111 == 0) {
		return ErrInvalid
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return ErrInvalid
	}
	defer clear(content)
	if digestBytes(content) != expectedDigest {
		return ErrInvalid
	}
	return nil
}

func verifyStateRoot(path string) error {
	state, err := os.Lstat(path)
	if err != nil || state.Mode()&os.ModeSymlink != 0 || !state.IsDir() || state.Mode().Perm()&0o002 != 0 {
		return ErrInvalid
	}
	return nil
}

func verifyWorkspace(root, path string) error {
	state, err := os.Lstat(path)
	if err != nil || state.Mode()&os.ModeSymlink != 0 || !state.IsDir() || !withinPath(root, path) {
		return ErrInvalid
	}
	resolvedRoot, rootErr := filepath.EvalSymlinks(root)
	resolved, pathErr := filepath.EvalSymlinks(path)
	if rootErr != nil || pathErr != nil || !withinPath(resolvedRoot, resolved) {
		return ErrInvalid
	}
	return nil
}

func validSearchPath(value string) bool {
	if value == "" || strings.IndexByte(value, 0) >= 0 || security.ContainsLikelySecret(value) {
		return false
	}
	for _, entry := range strings.Split(value, ":") {
		if !cleanAbsolute(entry) {
			return false
		}
	}
	return true
}

func cleanAbsolute(value string) bool { return filepath.IsAbs(value) && filepath.Clean(value) == value }

func digestBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func destroySecretEnvironment(environment map[string][]byte) {
	for name, value := range environment {
		clear(value)
		delete(environment, name)
	}
}
