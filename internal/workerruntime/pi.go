package workerruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

const (
	PiFinalSchemaV1       = "dirextalk.agent.pi-final/v1"
	PiResultExtensionName = "dirextalk_result_v1"
	piResultToolName      = "dirextalk_submit_result"
	maxPiEventLineBytes   = 2 << 20
	defaultPiOutputTokens = 8192
)

const piSystemPrompt = `Execute one approved Dirextalk Worker role.
Use only the enabled tools and the supplied workspace.
Do not inspect credential locations or reveal private configuration.
Retain user-facing JSON, Markdown, text, or PPTX files in the workspace and list their relative paths in the artifacts field.
Call dirextalk_submit_result exactly once as the final action.`

type PiConfig struct {
	Release         InstalledRelease
	ResultExtension InstalledExtension
	Models          []QualifiedModel
	Inputs          InputResolver
	Processes       ProcessRunner
	Patches         PatchCollector
	StateRoot       string
	SearchPath      string
}

type PiExecutor struct {
	release         InstalledRelease
	resultExtension InstalledExtension
	models          []QualifiedModel
	inputs          InputResolver
	processes       ProcessRunner
	patches         PatchCollector
	stateRoot       string
	searchPath      string
}

func NewPiExecutor(config PiConfig) (*PiExecutor, error) {
	if config.Release.Adapter != AdapterPiV1 ||
		config.Release.VerifyExecutable() != nil ||
		config.ResultExtension.Name != PiResultExtensionName ||
		config.ResultExtension.Verify() != nil ||
		config.Inputs == nil ||
		config.Processes == nil ||
		!cleanAbsolute(config.StateRoot) ||
		!validSearchPath(config.SearchPath) ||
		len(config.Models) == 0 {
		return nil, ErrInvalid
	}
	state, err := os.Lstat(config.StateRoot)
	if err != nil ||
		state.Mode()&os.ModeSymlink != 0 ||
		!state.IsDir() ||
		state.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalid
	}
	models := make([]QualifiedModel, len(config.Models))
	seenProfiles := make(map[string]struct{}, len(config.Models))
	for index, model := range config.Models {
		if model.validate() != nil ||
			!supportedPiModel(model) {
			return nil, ErrInvalid
		}
		if _, duplicate := seenProfiles[model.ProfileID]; duplicate {
			return nil, ErrInvalid
		}
		seenProfiles[model.ProfileID] = struct{}{}
		models[index] = model
	}
	return &PiExecutor{
		release:         config.Release,
		resultExtension: config.ResultExtension,
		models:          models,
		inputs:          config.Inputs,
		processes:       config.Processes,
		patches:         config.Patches,
		stateRoot:       config.StateRoot,
		searchPath:      config.SearchPath,
	}, nil
}

func (*PiExecutor) Adapter() Adapter { return AdapterPiV1 }

func (executor *PiExecutor) ValidateTask(task TaskV1) error {
	if executor == nil ||
		task.Validate() != nil ||
		!executor.release.Matches(task) {
		return ErrInvalid
	}
	qualified := false
	for _, model := range executor.models {
		if model.matches(task) {
			qualified = true
			break
		}
	}
	if !qualified ||
		!supportedPiModel(QualifiedModel{
			ProfileID:      task.ModelProfileID,
			Provider:       task.ModelProvider,
			Model:          task.Model,
			Interface:      task.ModelInterface,
			CredentialSlot: task.CredentialSlot,
		}) ||
		(task.IncludePatch &&
			(task.WorkspaceMode == WorkspaceNone ||
				task.WorkspaceMode == WorkspaceReadOnly ||
				executor.patches == nil)) {
		return ErrUnsupported
	}
	return nil
}

func (executor *PiExecutor) Execute(
	ctx context.Context,
	task TaskV1,
) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalid
	}
	if err := executor.ValidateTask(task); err != nil {
		return Result{}, err
	}
	if executor.release.VerifyExecutable() != nil ||
		executor.resultExtension.Verify() != nil {
		return Result{}, fmt.Errorf(
			"%w: verify Pi release",
			ErrExecution,
		)
	}
	inputs, err := executor.inputs.Resolve(ctx, task)
	if err != nil {
		return Result{}, fmt.Errorf(
			"%w: resolve Pi inputs: %v",
			ErrExecution, err,
		)
	}
	defer inputs.Destroy()

	jobRoot, err := os.MkdirTemp(executor.stateRoot, "pi-task-")
	if err != nil {
		return Result{}, ErrExecution
	}
	defer os.RemoveAll(jobRoot)
	if err := os.Chmod(jobRoot, 0o700); err != nil {
		return Result{}, ErrExecution
	}
	home := filepath.Join(jobRoot, "home")
	configRoot := filepath.Join(jobRoot, "config")
	if err := os.Mkdir(home, 0o700); err != nil {
		return Result{}, ErrExecution
	}
	if err := os.Mkdir(configRoot, 0o700); err != nil {
		return Result{}, ErrExecution
	}
	if writePiModelsConfig(configRoot, task) != nil {
		return Result{}, ErrExecution
	}
	workspace := inputs.WorkspaceDir
	if workspace == "" {
		workspace = filepath.Join(jobRoot, "workspace")
		if err := os.Mkdir(workspace, 0o700); err != nil {
			return Result{}, ErrExecution
		}
	}
	prompt, err := piPrompt(task, inputs.ContextJSON)
	if err != nil {
		return Result{}, err
	}
	defer clear(prompt)
	processOutput, err := executor.processes.Run(
		ctx,
		ProcessSpec{
			Executable: executor.release.ExecutablePath,
			Arguments: piArguments(
				task,
				executor.resultExtension.Path,
			),
			Directory: workspace,
			Environment: map[string]string{
				"PATH":                executor.searchPath,
				"HOME":                home,
				"PI_CODING_AGENT_DIR": configRoot,
				"PI_OFFLINE":          "1",
				"PI_TELEMETRY":        "0",
				"LANG":                "C.UTF-8",
				"LC_ALL":              "C.UTF-8",
				"TERM":                "dumb",
			},
			SecretEnvironment: piSecretEnvironment(
				task.ModelProvider,
				inputs.Credential,
			),
			Stdin:          prompt,
			StdoutPolicy:   ProcessStdoutPiEventsV1,
			MaxStdoutBytes: MaxProcessOutputBytes,
			MaxStderrBytes: MaxFinalResponseBytes,
		},
	)
	if err != nil {
		return Result{}, fmt.Errorf("run Pi: %w", err)
	}
	defer clear(processOutput.Stdout)
	var artifactPaths []string
	usage, finalJSON, err := parsePiEventsWithArtifacts(
		processOutput.Stdout,
		&artifactPaths,
	)
	if err != nil {
		return Result{}, err
	}
	artifacts := []Artifact{{
		Name:      "final.json",
		MediaType: "application/json",
		Content:   finalJSON,
	}}
	retained, err := collectPiArtifacts(
		ctx,
		task,
		workspace,
		artifactPaths,
	)
	if err != nil {
		clear(finalJSON)
		return Result{}, fmt.Errorf(
			"%w: collect Pi artifacts",
			ErrExecution,
		)
	}
	artifacts = append(artifacts, retained...)
	if task.IncludePatch {
		patch, err := executor.patches.Collect(ctx, workspace)
		if err != nil {
			destroyArtifacts(artifacts)
			return Result{}, fmt.Errorf(
				"%w: collect Pi patch",
				ErrExecution,
			)
		}
		if len(patch) != 0 {
			artifacts = append(artifacts, Artifact{
				Name:      "changes.patch",
				MediaType: "text/plain; charset=utf-8",
				Content:   patch,
			})
		}
	}
	result := Result{Usage: usage, Artifacts: artifacts}
	if err := result.Validate(); err != nil {
		for _, artifact := range artifacts {
			clear(artifact.Content)
		}
		return Result{}, fmt.Errorf(
			"%w: validate Pi outputs",
			ErrExecution,
		)
	}
	return result, nil
}

func writePiModelsConfig(configRoot string, task TaskV1) error {
	maxTokens := task.MaxOutputTokens
	if maxTokens == 0 {
		maxTokens = defaultPiOutputTokens
	}
	override := map[string]any{"maxTokens": maxTokens}
	if task.ModelProvider == "deepseek" {
		override["compat"] = map[string]any{
			"maxTokensField": "max_tokens",
		}
	}
	config := map[string]any{
		"providers": map[string]any{
			task.ModelProvider: map[string]any{
				"modelOverrides": map[string]any{
					task.Model: override,
				},
			},
		},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return ErrExecution
	}
	defer clear(encoded)
	if err := os.WriteFile(
		filepath.Join(configRoot, "models.json"),
		encoded,
		0o600,
	); err != nil {
		return ErrExecution
	}
	return nil
}

func piSecretEnvironment(
	provider string,
	credential []byte,
) map[string][]byte {
	name := "OPENAI_API_KEY"
	if provider == "deepseek" {
		name = "DEEPSEEK_API_KEY"
	}
	return map[string][]byte{name: credential}
}

func piArguments(
	task TaskV1,
	resultExtensionPath string,
) []string {
	return []string{
		"--mode", "json",
		"--print",
		"--no-session",
		"--offline",
		"--provider", task.ModelProvider,
		"--model", task.Model,
		"--thinking", "medium",
		"--tools", piTools(task.WorkspaceMode),
		"--extension", resultExtensionPath,
		"--no-extensions",
		"--no-skills",
		"--no-prompt-templates",
		"--no-themes",
		"--no-context-files",
		"--no-approve",
		"--system-prompt", piSystemPrompt,
	}
}

func piTools(mode WorkspaceMode) string {
	switch mode {
	case WorkspaceNone:
		return piResultToolName
	case WorkspaceReadOnly:
		return strings.Join(
			[]string{
				"read",
				"grep",
				"find",
				"ls",
				piResultToolName,
			},
			",",
		)
	default:
		return strings.Join(
			[]string{
				"read",
				"bash",
				"edit",
				"write",
				"grep",
				"find",
				"ls",
				piResultToolName,
			},
			",",
		)
	}
}

func piPrompt(task TaskV1, contextJSON []byte) ([]byte, error) {
	if task.Validate() != nil ||
		!json.Valid(contextJSON) ||
		securityContainsSecret(contextJSON) {
		return nil, ErrInvalid
	}
	var prompt bytes.Buffer
	prompt.WriteString("Execute one approved remote Worker role.\n")
	prompt.WriteString(
		"Use dirextalk_submit_result exactly once as the final action. " +
			"List each retained user-facing JSON, Markdown, text, or PPTX file by its relative workspace path in artifacts.\n\n",
	)
	prompt.WriteString("Task ID: ")
	prompt.WriteString(task.TaskID)
	prompt.WriteString("\nRole: ")
	prompt.WriteString(task.RoleID)
	prompt.WriteString("\nObjective:\n")
	prompt.WriteString(task.Objective)
	prompt.WriteString(
		"\n\nImmutable context JSON (sha256 verified):\n",
	)
	prompt.Write(contextJSON)
	prompt.WriteByte('\n')
	if prompt.Len() > MaxObjectiveBytes+MaxContextBytes+1024 {
		return nil, ErrInvalid
	}
	return prompt.Bytes(), nil
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

type piFinalDetails struct {
	Status       string   `json:"status"`
	Summary      string   `json:"summary"`
	Deliverables []string `json:"deliverables"`
	Tests        []string `json:"tests"`
	Risks        []string `json:"risks"`
	Artifacts    []string `json:"artifacts,omitempty"`
}

func parsePiEvents(stream []byte) (Usage, []byte, error) {
	return parsePiEventsWithArtifacts(stream, nil)
}

func parsePiEventsWithArtifacts(
	stream []byte,
	artifactPaths *[]string,
) (Usage, []byte, error) {
	if len(stream) == 0 ||
		len(stream) > MaxProcessOutputBytes ||
		!utf8.Valid(stream) {
		return Usage{}, nil, newFailure(
			FailureStagePi,
			FailureCodePiEventInvalid,
		)
	}
	scanner := bufio.NewScanner(bytes.NewReader(stream))
	scanner.Buffer(make([]byte, 64<<10), maxPiEventLineBytes)
	sessionSeen := false
	agentStarted := false
	agentEnded := false
	agentSettled := false
	finalSeen := false
	var usage Usage
	var finalJSON []byte
	var retainedPaths []string
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if agentSettled {
			clear(finalJSON)
			return Usage{}, nil, piEventInvalid()
		}
		var event piEvent
		if json.Unmarshal(line, &event) != nil ||
			!validPiEventType(event.Type) {
			clear(finalJSON)
			return Usage{}, nil, piEventInvalid()
		}
		switch event.Type {
		case "session":
			if sessionSeen ||
				agentStarted ||
				event.Version != 3 {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			sessionSeen = true
		case "agent_start":
			if !sessionSeen || agentStarted || agentEnded {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			agentStarted = true
		case "message_end":
			if !agentStarted || agentEnded {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			var message piMessage
			if json.Unmarshal(event.Message, &message) != nil {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			if message.Role == "assistant" {
				if message.StopReason == "error" {
					clear(finalJSON)
					return Usage{}, nil, classifyPiProviderFailure(
						message.ErrorMessage,
					)
				}
				if message.StopReason == "aborted" {
					clear(finalJSON)
					return Usage{}, nil, newFailure(
						FailureStagePi,
						FailureCodePiAborted,
					)
				}
				if addPiUsage(&usage, message.Usage) != nil {
					clear(finalJSON)
					return Usage{}, nil, piEventInvalid()
				}
			}
		case "tool_execution_end":
			if !agentStarted || agentEnded {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			if event.ToolName != piResultToolName {
				continue
			}
			if finalSeen || event.IsError {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			var result piToolResult
			if json.Unmarshal(event.Result, &result) != nil ||
				!result.Terminate {
				return Usage{}, nil, piEventInvalid()
			}
			canonical, paths, err := canonicalPiFinal(result.Details)
			if err != nil {
				return Usage{}, nil, err
			}
			finalJSON = canonical
			retainedPaths = paths
			finalSeen = true
		case "agent_end":
			if !agentStarted ||
				agentEnded ||
				event.WillRetry {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			agentEnded = true
		case "agent_settled":
			if !agentEnded || agentSettled {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			agentSettled = true
		}
	}
	if scanner.Err() != nil ||
		!sessionSeen ||
		!agentStarted ||
		!agentEnded ||
		!agentSettled ||
		usage.Validate() != nil {
		clear(finalJSON)
		return Usage{}, nil, piEventInvalid()
	}
	if !finalSeen {
		clear(finalJSON)
		return Usage{}, nil, newFailure(
			FailureStagePi,
			FailureCodePiFinalMissing,
		)
	}
	if artifactPaths != nil {
		*artifactPaths = append((*artifactPaths)[:0], retainedPaths...)
	}
	return usage, finalJSON, nil
}

func piEventInvalid() error {
	return newFailure(FailureStagePi, FailureCodePiEventInvalid)
}

func classifyPiProviderFailure(message string) error {
	normalized := strings.ToLower(strings.TrimSpace(message))
	code := FailureCodeProviderUnknown
	switch {
	case strings.HasPrefix(normalized, "401"),
		strings.Contains(normalized, "authentication"),
		strings.Contains(normalized, "unauthorized"),
		strings.Contains(normalized, "invalid api key"):
		code = FailureCodeProviderAuthentication
	case strings.HasPrefix(normalized, "402"),
		strings.Contains(normalized, "insufficient_balance"),
		strings.Contains(normalized, "quota"),
		strings.Contains(normalized, "billing"):
		code = FailureCodeProviderQuota
	case strings.HasPrefix(normalized, "429"),
		strings.Contains(normalized, "rate_limit"):
		code = FailureCodeProviderRateLimit
	case strings.HasPrefix(normalized, "400"),
		strings.HasPrefix(normalized, "404"),
		strings.HasPrefix(normalized, "422"),
		strings.Contains(normalized, "invalid_request"):
		code = FailureCodeProviderRequest
	case strings.HasPrefix(normalized, "500"),
		strings.HasPrefix(normalized, "502"),
		strings.HasPrefix(normalized, "503"),
		strings.HasPrefix(normalized, "504"),
		strings.Contains(normalized, "server_error"),
		strings.Contains(normalized, "service unavailable"):
		code = FailureCodeProviderServer
	case strings.Contains(normalized, "fetch failed"),
		strings.Contains(normalized, "connection"),
		strings.Contains(normalized, "network"),
		strings.Contains(normalized, "timed out"):
		code = FailureCodeProviderNetwork
	}
	return newFailure(FailureStagePi, code)
}

func validPiEventType(value string) bool {
	switch value {
	case "session",
		"agent_start",
		"agent_end",
		"agent_settled",
		"entry_appended",
		"session_info_changed",
		"thinking_level_changed",
		"turn_start",
		"turn_end",
		"message_start",
		"message_update",
		"message_end",
		"bash_execution_update",
		"tool_execution_start",
		"tool_execution_update",
		"tool_execution_end",
		"queue_update",
		"compaction_start",
		"compaction_end",
		"auto_retry_start",
		"auto_retry_end",
		"summarization_retry_scheduled",
		"summarization_retry_attempt_start",
		"summarization_retry_finished":
		return true
	default:
		return false
	}
}

func addPiUsage(total *Usage, value piUsage) error {
	if total == nil ||
		value.Input < 0 ||
		value.Output < 0 ||
		value.CacheRead < 0 ||
		value.CacheWrite < 0 ||
		value.Reasoning < 0 ||
		value.CacheRead > math.MaxInt64-value.Input ||
		value.CacheWrite > math.MaxInt64-value.Input-value.CacheRead {
		return ErrExecution
	}
	normalizedInput := value.Input + value.CacheRead + value.CacheWrite
	if total.InputTokens > math.MaxInt64-normalizedInput ||
		total.OutputTokens > math.MaxInt64-value.Output ||
		total.CachedInputTokens > math.MaxInt64-value.CacheRead ||
		total.ReasoningOutputTokens >
			math.MaxInt64-value.Reasoning {
		return ErrExecution
	}
	total.InputTokens += normalizedInput
	total.OutputTokens += value.Output
	total.CachedInputTokens += value.CacheRead
	total.ReasoningOutputTokens += value.Reasoning
	return nil
}

type PiFinalV1 struct {
	SchemaVersion string   `json:"schema_version"`
	Status        string   `json:"status"`
	Summary       string   `json:"summary"`
	Deliverables  []string `json:"deliverables"`
	Tests         []string `json:"tests"`
	Risks         []string `json:"risks"`
}

func canonicalPiFinal(detailsJSON []byte) ([]byte, []string, error) {
	decoder := json.NewDecoder(bytes.NewReader(detailsJSON))
	decoder.DisallowUnknownFields()
	var details piFinalDetails
	if decoder.Decode(&details) != nil {
		return nil, nil, ErrExecution
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, nil, ErrExecution
	}
	final := PiFinalV1{
		SchemaVersion: PiFinalSchemaV1,
		Status:        details.Status,
		Summary:       details.Summary,
		Deliverables:  details.Deliverables,
		Tests:         details.Tests,
		Risks:         details.Risks,
	}
	encoded, err := json.Marshal(final)
	if err != nil {
		return nil, nil, ErrExecution
	}
	_, canonical, err := ParsePiFinalV1(encoded)
	clear(encoded)
	if err != nil {
		return nil, nil, err
	}
	return canonical, append([]string(nil), details.Artifacts...), nil
}

// ParsePiFinalV1 applies the same strict, secret-rejecting contract used by
// the Pi Worker before Central accepts a downloaded final artifact.
func ParsePiFinalV1(input []byte) (PiFinalV1, []byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var final PiFinalV1
	if decoder.Decode(&final) != nil {
		return PiFinalV1{}, nil, ErrExecution
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PiFinalV1{}, nil, ErrExecution
	}
	if final.SchemaVersion != PiFinalSchemaV1 ||
		(final.Status != "completed" &&
			final.Status != "partial" &&
			final.Status != "blocked") ||
		!validFinalText(final.Summary) ||
		!validFinalList(final.Deliverables) ||
		!validFinalList(final.Tests) ||
		!validFinalList(final.Risks) {
		return PiFinalV1{}, nil, ErrExecution
	}
	encoded, err := json.Marshal(final)
	if err != nil {
		return PiFinalV1{}, nil, ErrExecution
	}
	return final, encoded, nil
}
