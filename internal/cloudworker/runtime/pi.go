package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const DefaultSearchPath = "/usr/local/bin:/usr/bin:/bin"

const piSystemPrompt = `Execute exactly one authorized Dirextalk Cloud Worker task.
Use only the enabled tools and supplied workspace. Never inspect credential locations or reveal private configuration.
Call dirextalk_submit_result exactly once as the final action.`

type PiConfig struct {
	Release                   PiRelease
	Models                    []QualifiedModel
	Inputs                    InputResolver
	Processes                 ProcessRunner
	Outputs                   OutputCollector
	StateRoot                 string
	SearchPath                string
	OutboundProxyURL          string
	ModelRelayTrustBundlePath string
	RuntimeGID                uint32
	Now                       func() time.Time
}

type PiExecutor struct {
	release                   PiRelease
	models                    []QualifiedModel
	inputs                    InputResolver
	processes                 ProcessRunner
	outputs                   OutputCollector
	stateRoot                 string
	searchPath                string
	outboundProxyURL          string
	modelRelayTrustBundlePath string
	runtimeGID                uint32
	now                       func() time.Time
}

func NewPiExecutor(config PiConfig) (*PiExecutor, error) {
	if config.Release.verify() != nil || config.Inputs == nil ||
		config.Processes == nil || !cleanAbsolute(config.StateRoot) ||
		config.SearchPath != DefaultSearchPath || !validOutboundProxyURL(config.OutboundProxyURL) || config.RuntimeGID == 0 || len(config.Models) == 0 ||
		config.ModelRelayTrustBundlePath != PiModelRelayTrustBundlePath ||
		len(config.Models) > 64 {
		return nil, ErrInvalid
	}
	if config.Now == nil {
		config.Now = func() time.Time { return time.Now().UTC() }
	}
	state, err := os.Lstat(config.StateRoot)
	if err != nil || state.Mode()&os.ModeSymlink != 0 || !state.IsDir() ||
		state.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalid
	}
	models := make([]QualifiedModel, len(config.Models))
	seen := make(map[string]struct{}, len(config.Models))
	for index, model := range config.Models {
		if model.validate() != nil || !supportedPiModel(model) {
			return nil, ErrInvalid
		}
		if _, duplicate := seen[model.ProfileID]; duplicate {
			return nil, ErrInvalid
		}
		seen[model.ProfileID] = struct{}{}
		models[index] = model
	}
	return &PiExecutor{
		release: config.Release, models: models, inputs: config.Inputs,
		processes: config.Processes, outputs: config.Outputs,
		stateRoot: config.StateRoot, searchPath: config.SearchPath,
		outboundProxyURL:          config.OutboundProxyURL,
		modelRelayTrustBundlePath: config.ModelRelayTrustBundlePath,
		runtimeGID:                config.RuntimeGID,
		now:                       config.Now,
	}, nil
}

func (executor *PiExecutor) ValidateTask(task Task) error {
	if executor == nil || task.Validate() != nil || !executor.release.matches(task) {
		return ErrInvalid
	}
	qualified := false
	for _, model := range executor.models {
		if model.matches(task) {
			qualified = true
			break
		}
	}
	if !qualified || (task.WorkspaceMode == WorkspaceWrite && executor.outputs == nil) {
		return ErrUnsupported
	}
	return nil
}

func (executor *PiExecutor) Run(
	ctx context.Context,
	task Task,
	grant ModelGrant,
) (Result, error) {
	if ctx == nil {
		return Result{}, ErrInvalid
	}
	if err := executor.ValidateTask(task); err != nil {
		return Result{}, err
	}
	// Reverify immediately before every invocation. Image qualification alone
	// is not enough if a local path was replaced after startup.
	if executor.release.verify() != nil {
		return Result{}, fmt.Errorf("%w: pinned Pi release verification", ErrExecution)
	}
	model := executor.qualifiedModel(task)
	inputs, err := executor.inputs.Resolve(ctx, task)
	if err != nil {
		inputs.Destroy()
		return Result{}, fmt.Errorf("%w: resolve approved inputs", ErrExecution)
	}
	defer inputs.Destroy()
	if inputs.validate(task) != nil || grant.ValidateFor(task, executor.now()) != nil {
		return Result{}, fmt.Errorf("%w: validate approved inputs", ErrExecution)
	}
	grantCtx, cancelGrant := context.WithDeadline(
		ctx, time.Unix(grant.ExpiresAtUnix, 0).UTC(),
	)
	defer cancelGrant()

	jobRoot, err := os.MkdirTemp(executor.stateRoot, "pi-task-")
	if err != nil {
		return Result{}, ErrExecution
	}
	defer removePiJobRoot(jobRoot)
	if err := os.Chmod(jobRoot, 0o700); err != nil {
		return Result{}, ErrExecution
	}
	home := filepath.Join(jobRoot, "home")
	configRoot := filepath.Join(jobRoot, "config")
	if os.Mkdir(home, 0o700) != nil || os.Mkdir(configRoot, 0o700) != nil ||
		writePiModelsConfig(configRoot, task) != nil {
		return Result{}, ErrExecution
	}
	if preparePiJobDirectories(jobRoot, home, configRoot, executor.runtimeGID) != nil {
		return Result{}, ErrExecution
	}
	workspace := inputs.Workspace.Directory
	if task.WorkspaceMode == WorkspaceNone {
		workspace = filepath.Join(jobRoot, "workspace")
		if os.Mkdir(workspace, 0o770) != nil ||
			os.Chown(workspace, -1, int(executor.runtimeGID)) != nil ||
			os.Chmod(workspace, 0o770) != nil {
			return Result{}, ErrExecution
		}
	} else if !validWorkspaceDirectory(workspace) {
		return Result{}, ErrExecution
	}
	var baseline WorkspaceBaseline
	if task.WorkspaceMode == WorkspaceWrite {
		baseline, err = executor.outputs.Snapshot(
			grantCtx, workspace, task.InputManifestSHA256, task.MaxOutputBytes,
		)
		if err != nil {
			baseline.Destroy()
			return Result{}, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
		}
		defer baseline.Destroy()
	}
	prompt, err := piPrompt(task, inputs.InputManifestJSON)
	if err != nil {
		return Result{}, err
	}
	defer clear(prompt)
	processOutput, err := executor.processes.Run(grantCtx, ProcessSpec{
		Executable:               executor.release.Executable.Path,
		ExpectedExecutableSHA256: task.PiExecutableSHA256,
		Arguments:                piArguments(task, executor.release.ResultExtension.Path),
		Directory:                workspace,
		Environment: map[string]string{
			"PATH": executor.searchPath, "HOME": home,
			"PI_CODING_AGENT_DIR": configRoot,
			"PI_OFFLINE":          "1", "PI_TELEMETRY": "0",
			"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
			"TERM": "dumb", "NO_COLOR": "1",
			"HTTP_PROXY":          executor.outboundProxyURL,
			"HTTPS_PROXY":         executor.outboundProxyURL,
			"NO_PROXY":            "",
			"NODE_EXTRA_CA_CERTS": executor.modelRelayTrustBundlePath,
		},
		SecretEnvironment: map[string][]byte{
			model.CredentialEnvironment: grant.BearerToken,
		},
		Stdin: prompt, StdoutPolicy: ProcessStdoutPiEventsV1,
		MaxStdoutBytes: MaxProcessOutputBytes,
		MaxStderrBytes: MaxFinalArtifactBytes,
	})
	if err != nil {
		return Result{}, fmt.Errorf("run Pi: %w", err)
	}
	defer clear(processOutput.Stdout)
	if _, guarded := executor.processes.(RuntimeTopologySource); guarded {
		runtimeTaskSHA256, digestErr := task.Digest()
		proof := processOutput.RuntimeTopology
		if digestErr != nil || proof.ValidateTerminal() != nil ||
			proof.ExecutionID != task.ExecutionID || proof.TaskID != task.TaskID ||
			proof.RuntimeTaskSHA256 != runtimeTaskSHA256 ||
			proof.Pi.SHA256 != task.PiExecutableSHA256 {
			return Result{}, newFailure(FailureStageProcess, FailureCodeProcessTopology)
		}
	}
	usage, finalJSON, err := ParsePiEvents(processOutput.Stdout)
	if err != nil {
		return Result{}, err
	}
	if usage.OutputTokens > int64(task.MaxOutputTokens) {
		clear(finalJSON)
		return Result{}, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	artifacts := []Artifact{{
		Name: "final.json", MediaType: "application/json", Content: finalJSON,
	}}
	if task.WorkspaceMode == WorkspaceWrite {
		if uint64(len(finalJSON)) >= task.MaxOutputBytes {
			destroyArtifacts(artifacts)
			return Result{}, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
		}
		outputs, collectErr := executor.outputs.Collect(
			grantCtx, workspace, baseline,
			task.MaxOutputBytes-uint64(len(finalJSON)),
		)
		if collectErr != nil {
			destroyArtifacts(artifacts)
			destroyArtifacts(outputs)
			return Result{}, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
		}
		for _, artifact := range outputs {
			if artifact.Name == "final.json" {
				destroyArtifacts(artifacts)
				destroyArtifacts(outputs)
				return Result{}, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
			}
		}
		artifacts = append(artifacts, outputs...)
	}
	result := Result{Usage: usage, Artifacts: artifacts}
	if result.ValidateFor(task.WorkspaceMode) != nil ||
		resultArtifactBytes(result) > task.MaxOutputBytes {
		DestroyResult(&result)
		return Result{}, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	return result, nil
}

func preparePiJobDirectories(jobRoot, home, configRoot string, runtimeGID uint32) error {
	models := filepath.Join(configRoot, "models.json")
	for _, path := range []string{jobRoot, home, configRoot, models} {
		if os.Chown(path, -1, int(runtimeGID)) != nil {
			return ErrExecution
		}
	}
	if os.Chmod(jobRoot, 0o750) != nil || os.Chmod(home, 0o770) != nil ||
		os.Chmod(configRoot, 0o550) != nil || os.Chmod(models, 0o440) != nil {
		return ErrExecution
	}
	return nil
}

func removePiJobRoot(jobRoot string) {
	// The immutable Pi configuration is deliberately not owner-writable while
	// the child is running. Restore only the worker-owned directory modes before
	// removal; WalkDir never follows a child-created symlink.
	_ = filepath.WalkDir(jobRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr == nil && entry.IsDir() {
			_ = os.Chmod(path, 0o700)
		}
		return nil
	})
	_ = os.RemoveAll(jobRoot)
}

func resultArtifactBytes(result Result) uint64 {
	var total uint64
	for _, artifact := range result.Artifacts {
		total += uint64(len(artifact.Content))
	}
	return total
}

func (executor *PiExecutor) qualifiedModel(task Task) QualifiedModel {
	for _, model := range executor.models {
		if model.matches(task) {
			return model
		}
	}
	return QualifiedModel{}
}

func supportedPiModel(model QualifiedModel) bool {
	return (model.Provider == "openai" &&
		model.Interface == ModelOpenAIResponses &&
		model.CredentialEnvironment == "OPENAI_API_KEY") ||
		(model.Provider == "deepseek" &&
			model.Interface == ModelOpenAICompatible &&
			model.CredentialEnvironment == "DEEPSEEK_API_KEY")
}

func writePiModelsConfig(configRoot string, task Task) error {
	override := map[string]any{"maxTokens": task.MaxOutputTokens}
	if task.ModelInterface == ModelOpenAICompatible {
		override["compat"] = map[string]any{"maxTokensField": "max_tokens"}
	}
	config := map[string]any{
		"providers": map[string]any{
			task.ModelProvider: map[string]any{
				"baseUrl":        task.ModelRelayBaseURL,
				"modelOverrides": map[string]any{task.Model: override},
			},
		},
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return ErrExecution
	}
	defer clear(encoded)
	file, err := os.OpenFile(
		filepath.Join(configRoot, "models.json"),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL,
		0o600,
	)
	if err != nil {
		return ErrExecution
	}
	written, writeErr := file.Write(encoded)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil || written != len(encoded) {
		return ErrExecution
	}
	return nil
}

func piArguments(task Task, resultExtensionPath string) []string {
	return []string{
		"--mode", "json", "--print", "--no-session", "--offline",
		"--provider", task.ModelProvider, "--model", task.Model,
		"--thinking", "medium", "--tools", piTools(task.WorkspaceMode),
		"--extension", resultExtensionPath,
		"--no-extensions", "--no-skills", "--no-prompt-templates",
		"--no-themes", "--no-context-files", "--no-approve",
		"--system-prompt", piSystemPrompt,
	}
}

func piTools(mode WorkspaceMode) string {
	switch mode {
	case WorkspaceNone:
		return PiResultToolName
	case WorkspaceReadOnly:
		return strings.Join([]string{"read", "grep", "find", "ls", PiResultToolName}, ",")
	case WorkspaceWrite:
		return strings.Join(
			[]string{"read", "bash", "edit", "write", "grep", "find", "ls", PiResultToolName},
			",",
		)
	default:
		return ""
	}
}

func piPrompt(task Task, inputManifestJSON []byte) ([]byte, error) {
	if task.Validate() != nil || !isCanonicalJSON(inputManifestJSON) ||
		len(inputManifestJSON) > MaxInputManifestBytes ||
		!matchesDigest(inputManifestJSON, task.InputManifestSHA256) {
		return nil, ErrInvalid
	}
	var prompt bytes.Buffer
	prompt.WriteString("Execute the authorized remote task.\n")
	prompt.WriteString("Use dirextalk_submit_result exactly once as the final action.\n\nTask ID: ")
	prompt.WriteString(task.TaskID)
	prompt.WriteString("\nExecution ID: ")
	prompt.WriteString(task.ExecutionID)
	prompt.WriteString("\nObjective:\n")
	prompt.WriteString(task.Objective)
	prompt.WriteString("\n\nImmutable input manifest JSON (SHA-256 verified):\n")
	prompt.Write(inputManifestJSON)
	prompt.WriteByte('\n')
	if prompt.Len() > MaxObjectiveBytes+MaxInputManifestBytes+1024 {
		return nil, ErrInvalid
	}
	return prompt.Bytes(), nil
}

func validWorkspaceDirectory(path string) bool {
	if !cleanAbsolute(path) {
		return false
	}
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink == 0 && info.IsDir()
}

func destroyArtifacts(artifacts []Artifact) {
	for index := range artifacts {
		clear(artifacts[index].Content)
	}
}
