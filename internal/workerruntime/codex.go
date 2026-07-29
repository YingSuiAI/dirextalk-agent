package workerruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	CodexFinalSchemaV1    = "dirextalk.agent.codex-final/v1"
	MaxFinalResponseBytes = MaxFinalArtifactBytes
	MaxPatchBytes         = 7 << 20
	maxFinalListItems     = 64
	maxFinalItemBytes     = 8 << 10
)

var codexOutputSchema = []byte(`{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "status", "summary", "deliverables", "tests", "risks"],
  "properties": {
    "schema_version": {"const": "dirextalk.agent.codex-final/v1"},
    "status": {"type": "string", "enum": ["completed", "partial", "blocked"]},
    "summary": {"type": "string"},
    "deliverables": {"type": "array", "items": {"type": "string"}},
    "tests": {"type": "array", "items": {"type": "string"}},
    "risks": {"type": "array", "items": {"type": "string"}}
  }
}`)

type QualifiedModel struct {
	ProfileID      string         `json:"profile_id"`
	Provider       string         `json:"provider"`
	Model          string         `json:"model"`
	Interface      ModelInterface `json:"interface"`
	CredentialSlot string         `json:"credential_slot"`
}

func (model QualifiedModel) matches(task TaskV1) bool {
	return task.ModelProfileID == model.ProfileID &&
		task.ModelProvider == model.Provider &&
		task.Model == model.Model &&
		task.ModelInterface == model.Interface &&
		task.CredentialSlot == model.CredentialSlot
}

func (model QualifiedModel) validate() error {
	if !validCatalogName(model.ProfileID) ||
		!validCatalogName(model.Provider) ||
		!validCatalogName(model.Model) ||
		!validModelInterface(model.Interface) ||
		!credentialSlot.MatchString(model.CredentialSlot) {
		return ErrInvalid
	}
	return nil
}

type PatchCollector interface {
	Collect(context.Context, string) ([]byte, error)
}

type CodexConfig struct {
	Release    InstalledRelease
	Models     []QualifiedModel
	Inputs     InputResolver
	Processes  ProcessRunner
	Patches    PatchCollector
	StateRoot  string
	SearchPath string
}

type CodexExecutor struct {
	release    InstalledRelease
	models     []QualifiedModel
	inputs     InputResolver
	processes  ProcessRunner
	patches    PatchCollector
	stateRoot  string
	searchPath string
}

func NewCodexExecutor(config CodexConfig) (*CodexExecutor, error) {
	if config.Release.Adapter != AdapterCodexV1 ||
		config.Release.VerifyExecutable() != nil ||
		config.Inputs == nil || config.Processes == nil ||
		!cleanAbsolute(config.StateRoot) ||
		!validSearchPath(config.SearchPath) ||
		len(config.Models) == 0 {
		return nil, ErrInvalid
	}
	state, err := os.Lstat(config.StateRoot)
	if err != nil || state.Mode()&os.ModeSymlink != 0 || !state.IsDir() ||
		state.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalid
	}
	models := make([]QualifiedModel, len(config.Models))
	seenProfiles := make(map[string]struct{}, len(config.Models))
	for index, model := range config.Models {
		if model.validate() != nil {
			return nil, ErrInvalid
		}
		if _, duplicate := seenProfiles[model.ProfileID]; duplicate {
			return nil, ErrInvalid
		}
		seenProfiles[model.ProfileID] = struct{}{}
		models[index] = model
	}
	return &CodexExecutor{
		release: config.Release, models: models, inputs: config.Inputs,
		processes: config.Processes, patches: config.Patches,
		stateRoot: config.StateRoot, searchPath: config.SearchPath,
	}, nil
}

func validSearchPath(value string) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, entry := range filepath.SplitList(value) {
		if !cleanAbsolute(entry) {
			return false
		}
	}
	return true
}

func (*CodexExecutor) Adapter() Adapter { return AdapterCodexV1 }

func (executor *CodexExecutor) ValidateTask(task TaskV1) error {
	if executor == nil || task.Validate() != nil ||
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
	if !qualified || task.ModelProvider != "openai" ||
		task.ModelInterface != ModelOpenAIResponses ||
		(task.IncludePatch && (task.WorkspaceMode == WorkspaceNone ||
			task.WorkspaceMode == WorkspaceReadOnly ||
			executor.patches == nil)) {
		return ErrUnsupported
	}
	return nil
}

func (executor *CodexExecutor) Execute(
	ctx context.Context,
	task TaskV1,
) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalid
	}
	if err := executor.ValidateTask(task); err != nil {
		return Result{}, err
	}
	if err := executor.release.VerifyExecutable(); err != nil {
		return Result{}, fmt.Errorf("%w: verify Codex release", ErrExecution)
	}
	inputs, err := executor.inputs.Resolve(ctx, task)
	if err != nil {
		return Result{}, fmt.Errorf("%w: resolve Codex inputs", ErrExecution)
	}
	defer inputs.Destroy()

	jobRoot, err := os.MkdirTemp(executor.stateRoot, "codex-task-")
	if err != nil {
		return Result{}, ErrExecution
	}
	defer os.RemoveAll(jobRoot)
	if err := os.Chmod(jobRoot, 0o700); err != nil {
		return Result{}, ErrExecution
	}
	codexHome := filepath.Join(jobRoot, "home")
	if err := os.Mkdir(codexHome, 0o700); err != nil {
		return Result{}, ErrExecution
	}
	workspace := inputs.WorkspaceDir
	if workspace == "" {
		workspace = filepath.Join(jobRoot, "workspace")
		if err := os.Mkdir(workspace, 0o700); err != nil {
			return Result{}, ErrExecution
		}
	}
	schemaPath := filepath.Join(jobRoot, "final.schema.json")
	outputPath := filepath.Join(jobRoot, "final.json")
	if err := writeExclusive(schemaPath, codexOutputSchema, 0o600); err != nil {
		return Result{}, ErrExecution
	}

	prompt, err := codexPrompt(task, inputs.ContextJSON)
	if err != nil {
		return Result{}, err
	}
	defer clear(prompt)
	processOutput, err := executor.processes.Run(ctx, ProcessSpec{
		Executable: executor.release.ExecutablePath,
		Arguments: codexArguments(
			task, workspace, schemaPath, outputPath,
		),
		Directory: workspace,
		Environment: map[string]string{
			"PATH": executor.searchPath, "HOME": jobRoot,
			"CODEX_HOME": codexHome, "LANG": "C.UTF-8",
			"LC_ALL": "C.UTF-8", "TERM": "dumb",
		},
		SecretEnvironment: map[string][]byte{
			"CODEX_API_KEY": inputs.Credential,
		},
		Stdin: prompt, MaxStdoutBytes: MaxProcessOutputBytes,
		MaxStderrBytes: MaxFinalResponseBytes,
	})
	if err != nil {
		return Result{}, fmt.Errorf("%w: run Codex", ErrExecution)
	}
	defer clear(processOutput.Stdout)
	usage, err := parseCodexEvents(processOutput.Stdout)
	if err != nil {
		return Result{}, err
	}
	finalJSON, err := readStableFile(
		ctx, outputPath, MaxFinalResponseBytes,
	)
	if err != nil {
		return Result{}, fmt.Errorf("%w: read Codex final response", ErrExecution)
	}
	defer clear(finalJSON)
	canonicalFinal, err := validateCodexFinal(finalJSON)
	if err != nil {
		return Result{}, err
	}
	artifacts := []Artifact{{
		Name: "final.json", MediaType: "application/json",
		Content: canonicalFinal,
	}}
	if task.IncludePatch {
		patch, err := executor.patches.Collect(ctx, workspace)
		if err != nil {
			clear(canonicalFinal)
			return Result{}, fmt.Errorf("%w: collect Codex patch", ErrExecution)
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
		return Result{}, fmt.Errorf("%w: validate Codex outputs", ErrExecution)
	}
	return result, nil
}

func codexArguments(
	task TaskV1,
	workspace string,
	schemaPath string,
	outputPath string,
) []string {
	sandbox := "workspace-write"
	if task.WorkspaceMode == WorkspaceNone ||
		task.WorkspaceMode == WorkspaceReadOnly {
		sandbox = "read-only"
	}
	return []string{
		"--ask-for-approval", "never", "exec",
		"--json", "--color", "never", "--ephemeral",
		"--ignore-user-config", "--ignore-rules", "--strict-config",
		"--model", task.Model, "--sandbox", sandbox,
		"--cd", workspace,
		"--skip-git-repo-check", "--output-schema", schemaPath,
		"--output-last-message", outputPath,
		"--config", `allow_login_shell=false`,
		"--config", `history.persistence="none"`,
		"--config", `web_search="disabled"`,
		"--config", `features.apps=false`,
		"--config", `features.auth_elicitation=false`,
		"--config", `features.browser_use=false`,
		"--config", `features.browser_use_external=false`,
		"--config", `features.browser_use_full_cdp_access=false`,
		"--config", `features.computer_use=false`,
		"--config", `features.fast_mode=false`,
		"--config", `features.goals=false`,
		"--config", `features.hooks=false`,
		"--config", `features.image_generation=false`,
		"--config", `features.in_app_browser=false`,
		"--config", `features.multi_agent=false`,
		"--config", `features.plugin_sharing=false`,
		"--config", `features.plugins=false`,
		"--config", `features.remote_plugin=false`,
		"--config", `features.shell_snapshot=false`,
		"--config", `features.skill_mcp_dependency_install=false`,
		"--config", `features.tool_suggest=false`,
		"--config", `features.workspace_dependencies=false`,
		"--config", `shell_environment_policy.inherit="none"`,
		"--config", `shell_environment_policy.ignore_default_excludes=false`,
		"--config", `shell_environment_policy.include_only=["PATH","HOME","LANG","LC_ALL"]`,
		"-",
	}
}

func codexPrompt(task TaskV1, contextJSON []byte) ([]byte, error) {
	if task.Validate() != nil || !json.Valid(contextJSON) ||
		securityContainsSecret(contextJSON) {
		return nil, ErrInvalid
	}
	var prompt bytes.Buffer
	prompt.WriteString("Execute one approved remote Worker role.\n")
	prompt.WriteString("Do not expose credentials or inspect credential locations.\n")
	prompt.WriteString("Return only the final JSON required by the output schema.\n\n")
	prompt.WriteString("Task ID: ")
	prompt.WriteString(task.TaskID)
	prompt.WriteString("\nRole: ")
	prompt.WriteString(task.RoleID)
	prompt.WriteString("\nObjective:\n")
	prompt.WriteString(task.Objective)
	prompt.WriteString("\n\nImmutable context JSON (sha256 verified):\n")
	prompt.Write(contextJSON)
	prompt.WriteByte('\n')
	if prompt.Len() > MaxObjectiveBytes+MaxContextBytes+1024 {
		return nil, ErrInvalid
	}
	return prompt.Bytes(), nil
}

type codexEvent struct {
	Type  string `json:"type"`
	Usage Usage  `json:"usage"`
}

func parseCodexEvents(stream []byte) (Usage, error) {
	if len(stream) == 0 || len(stream) > MaxProcessOutputBytes ||
		!utf8.Valid(stream) {
		return Usage{}, ErrExecution
	}
	scanner := bufio.NewScanner(bytes.NewReader(stream))
	scanner.Buffer(make([]byte, 64<<10), MaxFinalResponseBytes)
	threadStarted := false
	turnCompleted := false
	var usage Usage
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var event codexEvent
		if json.Unmarshal(line, &event) != nil {
			return Usage{}, ErrExecution
		}
		switch event.Type {
		case "thread.started":
			if threadStarted || turnCompleted {
				return Usage{}, ErrExecution
			}
			threadStarted = true
		case "turn.completed":
			if !threadStarted || turnCompleted ||
				event.Usage.Validate() != nil {
				return Usage{}, ErrExecution
			}
			turnCompleted = true
			usage = event.Usage
		case "turn.failed", "error":
			return Usage{}, ErrExecution
		}
	}
	if scanner.Err() != nil || !threadStarted || !turnCompleted {
		return Usage{}, ErrExecution
	}
	return usage, nil
}

type codexFinal struct {
	SchemaVersion string   `json:"schema_version"`
	Status        string   `json:"status"`
	Summary       string   `json:"summary"`
	Deliverables  []string `json:"deliverables"`
	Tests         []string `json:"tests"`
	Risks         []string `json:"risks"`
}

func validateCodexFinal(input []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var final codexFinal
	if decoder.Decode(&final) != nil {
		return nil, ErrExecution
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrExecution
	}
	if final.SchemaVersion != CodexFinalSchemaV1 ||
		(final.Status != "completed" && final.Status != "partial" &&
			final.Status != "blocked") ||
		!validFinalText(final.Summary) ||
		!validFinalList(final.Deliverables) ||
		!validFinalList(final.Tests) ||
		!validFinalList(final.Risks) {
		return nil, ErrExecution
	}
	encoded, err := json.Marshal(final)
	if err != nil {
		return nil, ErrExecution
	}
	return encoded, nil
}

func validFinalList(values []string) bool {
	if values == nil || len(values) > maxFinalListItems {
		return false
	}
	for _, value := range values {
		if !validFinalText(value) {
			return false
		}
	}
	return true
}

func validFinalText(value string) bool {
	if value == "" || value != strings.TrimSpace(value) ||
		len(value) > maxFinalItemBytes || !utf8.ValidString(value) ||
		securityContainsSecret([]byte(value)) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) && character != '\n' &&
			character != '\r' && character != '\t' {
			return false
		}
	}
	return true
}

func securityContainsSecret(value []byte) bool {
	return security.ContainsLikelySecret(string(value))
}

func writeExclusive(name string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	written, writeErr := file.Write(content)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil ||
		written != len(content) {
		_ = os.Remove(name)
		return ErrExecution
	}
	return nil
}
