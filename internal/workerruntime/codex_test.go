package workerruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCodexExecutorUsesQualifiedReleaseAndFixedInvocation(t *testing.T) {
	t.Parallel()
	task := validTask()
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	credential := []byte("scoped-test-credential-1234567890")
	process := &codexFakeProcess{
		final: []byte(`{
			"schema_version":"dirextalk.agent.codex-final/v1",
			"status":"completed",
			"summary":"Implemented the approved change.",
			"deliverables":["Updated the API implementation."],
			"tests":["Focused tests passed."],
			"risks":[]
		}`),
		events: []byte(
			"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n" +
				"{\"type\":\"item.completed\",\"item\":{\"type\":\"agent_message\"}}\n" +
				"{\"type\":\"turn.completed\",\"usage\":{\"input_tokens\":100,\"cached_input_tokens\":25,\"output_tokens\":40,\"reasoning_output_tokens\":10}}\n",
		),
	}
	patches := &fakePatchCollector{
		content: []byte("diff --git a/api.go b/api.go\n"),
	}
	executor := newTestCodexExecutor(
		t, task, workspace, credential, process, patches,
	)
	result, err := executor.Execute(context.Background(), task)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, artifact := range result.Artifacts {
			clear(artifact.Content)
		}
	}()
	if result.Usage.InputTokens != 100 ||
		result.Usage.CachedInputTokens != 25 ||
		result.Usage.OutputTokens != 40 ||
		result.Usage.ReasoningOutputTokens != 10 ||
		len(result.Artifacts) != 2 ||
		result.Artifacts[0].Name != "final.json" ||
		result.Artifacts[1].Name != "changes.patch" {
		t.Fatalf("result = %+v", result)
	}
	if process.calls != 1 || process.spec.Executable == "" ||
		process.spec.Directory != workspace {
		t.Fatalf("process spec = %+v", process.spec)
	}
	arguments := strings.Join(process.spec.Arguments, "\n")
	if strings.Contains(arguments, task.Objective) ||
		strings.Contains(arguments, string(credential)) ||
		len(process.spec.Arguments) < 3 ||
		!slices.Equal(
			process.spec.Arguments[:3],
			[]string{"--ask-for-approval", "never", "exec"},
		) ||
		!slices.Contains(process.spec.Arguments, "--ignore-user-config") ||
		!slices.Contains(process.spec.Arguments, "--ignore-rules") ||
		!slices.Contains(process.spec.Arguments, `web_search="disabled"`) ||
		!slices.Contains(process.spec.Arguments, `features.multi_agent=false`) ||
		!slices.Contains(process.spec.Arguments, `features.plugins=false`) ||
		!slices.Contains(process.spec.Arguments, "workspace-write") {
		t.Fatalf("unsafe or incomplete Codex arguments: %v", process.spec.Arguments)
	}
	if !bytes.Contains(process.spec.Stdin, []byte(task.Objective)) ||
		!bytes.Contains(process.spec.Stdin, []byte(`{"scope":"approved"}`)) ||
		bytes.Contains(process.spec.Stdin, credential) {
		t.Fatalf("Codex stdin = %q", process.spec.Stdin)
	}
	if string(process.spec.SecretEnvironment["CODEX_API_KEY"]) !=
		string(credential) {
		t.Fatal("Codex scoped credential was not passed through the secret channel")
	}
}

func TestCodexExecutorRejectsUnqualifiedModelAndFailedTurn(t *testing.T) {
	t.Parallel()
	task := validTask()
	task.IncludePatch = false
	process := &codexFakeProcess{
		final: []byte(`{
			"schema_version":"dirextalk.agent.codex-final/v1",
			"status":"blocked",
			"summary":"The task is blocked.",
			"deliverables":[],
			"tests":[],
			"risks":["Required input is unavailable."]
		}`),
		events: []byte(
			"{\"type\":\"thread.started\",\"thread_id\":\"thread-1\"}\n" +
				"{\"type\":\"turn.failed\",\"error\":{\"message\":\"failed\"}}\n",
		),
	}
	executor := newTestCodexExecutor(
		t, task, "", []byte("scoped-test-credential-1234567890"),
		process, nil,
	)
	unqualified := task
	unqualified.Model = "unqualified-model"
	if !errors.Is(executor.ValidateTask(unqualified), ErrUnsupported) {
		t.Fatal("unqualified model was accepted")
	}
	if _, err := executor.Execute(context.Background(), task); !errors.Is(err, ErrExecution) {
		t.Fatalf("failed Codex turn error = %v", err)
	}
}

func TestCodexExecutorReverifiesReleaseBeforeEveryTask(t *testing.T) {
	t.Parallel()
	task := validTask()
	task.IncludePatch = false
	process := &codexFakeProcess{}
	executor := newTestCodexExecutor(
		t, task, "",
		[]byte("scoped-test-credential-1234567890"),
		process, nil,
	)
	if err := os.WriteFile(
		executor.release.ExecutablePath,
		[]byte("#!/bin/true\n"),
		0o700,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(
		context.Background(), task,
	); !errors.Is(err, ErrExecution) {
		t.Fatalf("tampered release error = %v", err)
	}
	if process.calls != 0 {
		t.Fatal("tampered Codex executable was invoked")
	}
}

func TestParseCodexEventsRequiresOneCompletedTurn(t *testing.T) {
	t.Parallel()
	for _, stream := range [][]byte{
		[]byte(`{"type":"turn.completed","usage":{}}` + "\n"),
		[]byte(`{"type":"thread.started"}` + "\n"),
		[]byte(
			"{\"type\":\"thread.started\"}\n" +
				"{\"type\":\"turn.completed\",\"usage\":{}}\n" +
				"{\"type\":\"turn.completed\",\"usage\":{}}\n",
		),
	} {
		if _, err := parseCodexEvents(stream); !errors.Is(err, ErrExecution) {
			t.Fatalf("invalid event stream accepted: %s", stream)
		}
	}
}

func TestValidateCodexFinalRejectsUnknownFieldsAndSecrets(t *testing.T) {
	t.Parallel()
	for _, value := range [][]byte{
		[]byte(`{
			"schema_version":"dirextalk.agent.codex-final/v1",
			"status":"completed",
			"summary":"Done.",
			"deliverables":[],
			"tests":[],
			"risks":[],
			"extra":true
		}`),
		[]byte(`{
			"schema_version":"dirextalk.agent.codex-final/v1",
			"status":"completed",
			"summary":"sk-abcdefghijklmnopqrstuvwxyz",
			"deliverables":[],
			"tests":[],
			"risks":[]
		}`),
	} {
		if _, err := validateCodexFinal(value); !errors.Is(err, ErrExecution) {
			t.Fatalf("unsafe final response accepted: %s", value)
		}
	}
}

func newTestCodexExecutor(
	t *testing.T,
	task TaskV1,
	workspace string,
	credential []byte,
	process ProcessRunner,
	patches PatchCollector,
) *CodexExecutor {
	t.Helper()
	binaryPath := filepath.Join(t.TempDir(), "codex")
	binary := []byte("#!/bin/false\n")
	if err := os.WriteFile(binaryPath, binary, 0o700); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	release := InstalledRelease{
		ReleaseID: task.RuntimeReleaseID, Version: task.RuntimeVersion,
		ImageDigest: task.RuntimeImageDigest, Adapter: AdapterCodexV1,
		ExecutablePath:   binaryPath,
		ExecutableSHA256: "sha256:" + hex.EncodeToString(digest[:]),
	}
	contextJSON := []byte(`{"scope":"approved"}`)
	resolver := &fakeInputResolver{inputs: ResolvedInputs{
		ContextJSON: bytes.Clone(contextJSON), WorkspaceDir: workspace,
		Credential: bytes.Clone(credential),
	}}
	stateRoot := t.TempDir()
	executor, err := NewCodexExecutor(CodexConfig{
		Release: release,
		Models: []QualifiedModel{{
			ProfileID: task.ModelProfileID, Provider: task.ModelProvider,
			Model: task.Model, Interface: task.ModelInterface,
			CredentialSlot: task.CredentialSlot,
		}},
		Inputs: resolver, Processes: process, Patches: patches,
		StateRoot: stateRoot, SearchPath: "/usr/local/bin:/usr/bin:/bin",
	})
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

type fakeInputResolver struct {
	inputs ResolvedInputs
	err    error
}

func (resolver *fakeInputResolver) Resolve(
	context.Context,
	TaskV1,
) (ResolvedInputs, error) {
	return ResolvedInputs{
		ContextJSON:  bytes.Clone(resolver.inputs.ContextJSON),
		WorkspaceDir: resolver.inputs.WorkspaceDir,
		Credential:   bytes.Clone(resolver.inputs.Credential),
	}, resolver.err
}

type codexFakeProcess struct {
	final  []byte
	events []byte
	err    error
	calls  int
	spec   ProcessSpec
}

func (process *codexFakeProcess) Run(
	_ context.Context,
	spec ProcessSpec,
) (ProcessOutput, error) {
	process.calls++
	process.spec = cloneProcessSpec(spec)
	if process.err != nil {
		return ProcessOutput{}, process.err
	}
	outputPath := argumentValue(spec.Arguments, "--output-last-message")
	if outputPath == "" {
		return ProcessOutput{}, ErrExecution
	}
	if err := os.WriteFile(outputPath, process.final, 0o600); err != nil {
		return ProcessOutput{}, err
	}
	return ProcessOutput{Stdout: bytes.Clone(process.events)}, nil
}

func cloneProcessSpec(value ProcessSpec) ProcessSpec {
	cloned := value
	cloned.Arguments = slices.Clone(value.Arguments)
	cloned.Stdin = bytes.Clone(value.Stdin)
	cloned.Environment = make(map[string]string, len(value.Environment))
	for key, item := range value.Environment {
		cloned.Environment[key] = item
	}
	cloned.SecretEnvironment = make(
		map[string][]byte,
		len(value.SecretEnvironment),
	)
	for key, item := range value.SecretEnvironment {
		cloned.SecretEnvironment[key] = bytes.Clone(item)
	}
	return cloned
}

func argumentValue(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}

type fakePatchCollector struct {
	content []byte
	err     error
}

func (collector *fakePatchCollector) Collect(
	context.Context,
	string,
) ([]byte, error) {
	return bytes.Clone(collector.content), collector.err
}
