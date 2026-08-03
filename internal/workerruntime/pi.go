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
)

const piSystemPrompt = `Execute one approved Dirextalk Worker role.
Use only the enabled tools and the supplied workspace.
Do not inspect credential locations or reveal private configuration.
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
			MaxStdoutBytes: MaxProcessOutputBytes,
			MaxStderrBytes: MaxFinalResponseBytes,
		},
	)
	if err != nil {
		return Result{}, fmt.Errorf("%w: run Pi", ErrExecution)
	}
	defer clear(processOutput.Stdout)
	usage, finalJSON, err := parsePiEvents(processOutput.Stdout)
	if err != nil {
		return Result{}, err
	}
	artifacts := []Artifact{{
		Name:      "final.json",
		MediaType: "application/json",
		Content:   finalJSON,
	}}
	if task.IncludePatch {
		patch, err := executor.patches.Collect(ctx, workspace)
		if err != nil {
			clear(finalJSON)
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
		"Use dirextalk_submit_result exactly once as the final action.\n\n",
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
	Version   int             `json:"version"`
	Message   json.RawMessage `json:"message"`
	ToolName  string          `json:"toolName"`
	Result    json.RawMessage `json:"result"`
	IsError   bool            `json:"isError"`
	WillRetry bool            `json:"willRetry"`
}

type piMessage struct {
	Role       string  `json:"role"`
	Usage      piUsage `json:"usage"`
	StopReason string  `json:"stopReason"`
}

type piUsage struct {
	Input     int64 `json:"input"`
	Output    int64 `json:"output"`
	CacheRead int64 `json:"cacheRead"`
	Reasoning int64 `json:"reasoning"`
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
}

func parsePiEvents(stream []byte) (Usage, []byte, error) {
	if len(stream) == 0 ||
		len(stream) > MaxProcessOutputBytes ||
		!utf8.Valid(stream) {
		return Usage{}, nil, ErrExecution
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
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if agentSettled {
			clear(finalJSON)
			return Usage{}, nil, ErrExecution
		}
		var event piEvent
		if json.Unmarshal(line, &event) != nil ||
			!validPiEventType(event.Type) {
			clear(finalJSON)
			return Usage{}, nil, ErrExecution
		}
		switch event.Type {
		case "session":
			if sessionSeen ||
				agentStarted ||
				event.Version != 3 {
				clear(finalJSON)
				return Usage{}, nil, ErrExecution
			}
			sessionSeen = true
		case "agent_start":
			if !sessionSeen || agentStarted || agentEnded {
				clear(finalJSON)
				return Usage{}, nil, ErrExecution
			}
			agentStarted = true
		case "message_end":
			if !agentStarted || agentEnded {
				clear(finalJSON)
				return Usage{}, nil, ErrExecution
			}
			var message piMessage
			if json.Unmarshal(event.Message, &message) != nil {
				clear(finalJSON)
				return Usage{}, nil, ErrExecution
			}
			if message.Role == "assistant" {
				if message.StopReason == "error" ||
					message.StopReason == "aborted" ||
					addPiUsage(&usage, message.Usage) != nil {
					clear(finalJSON)
					return Usage{}, nil, ErrExecution
				}
			}
		case "tool_execution_end":
			if !agentStarted || agentEnded {
				clear(finalJSON)
				return Usage{}, nil, ErrExecution
			}
			if event.ToolName != piResultToolName {
				continue
			}
			if finalSeen || event.IsError {
				clear(finalJSON)
				return Usage{}, nil, ErrExecution
			}
			var result piToolResult
			if json.Unmarshal(event.Result, &result) != nil ||
				!result.Terminate {
				return Usage{}, nil, ErrExecution
			}
			canonical, err := canonicalPiFinal(result.Details)
			if err != nil {
				return Usage{}, nil, err
			}
			finalJSON = canonical
			finalSeen = true
		case "agent_end":
			if !agentStarted ||
				agentEnded ||
				event.WillRetry {
				clear(finalJSON)
				return Usage{}, nil, ErrExecution
			}
			agentEnded = true
		case "agent_settled":
			if !agentEnded || agentSettled {
				clear(finalJSON)
				return Usage{}, nil, ErrExecution
			}
			agentSettled = true
		}
	}
	if scanner.Err() != nil ||
		!sessionSeen ||
		!agentStarted ||
		!agentEnded ||
		!agentSettled ||
		!finalSeen ||
		usage.Validate() != nil {
		clear(finalJSON)
		return Usage{}, nil, ErrExecution
	}
	return usage, finalJSON, nil
}

func validPiEventType(value string) bool {
	switch value {
	case "session",
		"agent_start",
		"agent_end",
		"agent_settled",
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
		value.Reasoning < 0 ||
		value.CacheRead > value.Input ||
		total.InputTokens > math.MaxInt64-value.Input ||
		total.OutputTokens > math.MaxInt64-value.Output ||
		total.CachedInputTokens > math.MaxInt64-value.CacheRead ||
		total.ReasoningOutputTokens >
			math.MaxInt64-value.Reasoning {
		return ErrExecution
	}
	total.InputTokens += value.Input
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

func canonicalPiFinal(detailsJSON []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(detailsJSON))
	decoder.DisallowUnknownFields()
	var details piFinalDetails
	if decoder.Decode(&details) != nil {
		return nil, ErrExecution
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrExecution
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
		return nil, ErrExecution
	}
	_, canonical, err := ParsePiFinalV1(encoded)
	clear(encoded)
	return canonical, err
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
