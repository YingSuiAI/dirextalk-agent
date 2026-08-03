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

func TestPiExecutorUsesQualifiedReleaseAndStructuredResult(t *testing.T) {
	t.Parallel()
	task := validPiTask()
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	credential := []byte("scoped-test-credential-1234567890")
	process := &piFakeProcess{events: validPiEventStream()}
	patches := &fakePatchCollector{
		content: []byte("diff --git a/api.go b/api.go\n"),
	}
	executor := newTestPiExecutor(
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
	if result.Usage.InputTokens != 120 ||
		result.Usage.CachedInputTokens != 20 ||
		result.Usage.OutputTokens != 24 ||
		result.Usage.ReasoningOutputTokens != 6 ||
		len(result.Artifacts) != 2 ||
		result.Artifacts[0].Name != "final.json" ||
		result.Artifacts[1].Name != "changes.patch" {
		t.Fatalf("result = %+v", result)
	}
	final, canonical, err := ParsePiFinalV1(result.Artifacts[0].Content)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, result.Artifacts[0].Content) ||
		final.Status != "completed" ||
		final.Summary != "Implemented the approved change." {
		t.Fatalf("final = %+v", final)
	}
	if process.calls != 1 ||
		process.spec.Executable != executor.release.ExecutablePath ||
		process.spec.Directory != workspace {
		t.Fatalf("process spec = %+v", process.spec)
	}
	arguments := strings.Join(process.spec.Arguments, "\n")
	if strings.Contains(arguments, task.Objective) ||
		strings.Contains(arguments, string(credential)) ||
		!slices.Contains(process.spec.Arguments, "--mode") ||
		argumentValue(process.spec.Arguments, "--mode") != "json" ||
		!slices.Contains(process.spec.Arguments, "--print") ||
		!slices.Contains(process.spec.Arguments, "--no-session") ||
		!slices.Contains(process.spec.Arguments, "--offline") ||
		!slices.Contains(process.spec.Arguments, "--no-extensions") ||
		!slices.Contains(process.spec.Arguments, "--no-skills") ||
		!slices.Contains(process.spec.Arguments, "--no-context-files") ||
		!slices.Contains(process.spec.Arguments, "--no-approve") ||
		argumentValue(process.spec.Arguments, "--provider") != "openai" ||
		argumentValue(process.spec.Arguments, "--model") != task.Model ||
		argumentValue(process.spec.Arguments, "--extension") !=
			executor.resultExtension.Path ||
		!strings.Contains(
			argumentValue(process.spec.Arguments, "--tools"),
			piResultToolName,
		) {
		t.Fatalf("unsafe or incomplete Pi arguments: %v", process.spec.Arguments)
	}
	if !bytes.Contains(process.spec.Stdin, []byte(task.Objective)) ||
		!bytes.Contains(process.spec.Stdin, []byte(`{"scope":"approved"}`)) ||
		bytes.Contains(process.spec.Stdin, credential) {
		t.Fatalf("Pi stdin = %q", process.spec.Stdin)
	}
	if len(process.spec.SecretEnvironment) != 1 ||
		string(process.spec.SecretEnvironment["OPENAI_API_KEY"]) !=
			string(credential) {
		t.Fatal("Pi scoped credential was not isolated in the secret channel")
	}
}

func TestPiExecutorUsesDeepSeekCredentialChannel(t *testing.T) {
	t.Parallel()
	task := validPiTask()
	task.ModelProfileID = "deepseek-v4-pro"
	task.ModelProvider = "deepseek"
	task.Model = "deepseek-v4-pro"
	task.ModelInterface = ModelOpenAICompatible
	task.IncludePatch = false
	credential := []byte("scoped-deepseek-credential-1234567890")
	process := &piFakeProcess{events: validPiEventStream()}
	executor := newTestPiExecutor(
		t,
		task,
		"",
		credential,
		process,
		nil,
	)

	result, err := executor.Execute(t.Context(), task)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, artifact := range result.Artifacts {
			clear(artifact.Content)
		}
	}()
	if argumentValue(
		process.spec.Arguments,
		"--provider",
	) != "deepseek" ||
		argumentValue(
			process.spec.Arguments,
			"--model",
		) != "deepseek-v4-pro" ||
		len(process.spec.SecretEnvironment) != 1 ||
		string(
			process.spec.SecretEnvironment["DEEPSEEK_API_KEY"],
		) != string(credential) {
		t.Fatalf("DeepSeek process spec = %+v", process.spec)
	}
	if _, present := process.spec.SecretEnvironment["OPENAI_API_KEY"]; present {
		t.Fatal("DeepSeek credential was also exposed as OPENAI_API_KEY")
	}
}

func TestPiExecutorAcceptsDeploymentScopedCredentialSlot(t *testing.T) {
	t.Parallel()
	task := validPiTask()
	task.CredentialSlot = "model-c9bba9b368d4b0dd"
	task.IncludePatch = false
	process := &piFakeProcess{events: validPiEventStream()}
	executor := newTestPiExecutor(
		t,
		task,
		"",
		[]byte("scoped-test-credential-1234567890"),
		process,
		nil,
	)

	if err := executor.ValidateTask(task); err != nil {
		t.Fatalf("deployment-scoped credential slot rejected: %v", err)
	}
	unqualified := task
	unqualified.Model = "unqualified-model"
	if !errors.Is(executor.ValidateTask(unqualified), ErrUnsupported) {
		t.Fatal("unqualified model was accepted")
	}
	if _, err := executor.Execute(t.Context(), task); err != nil {
		t.Fatalf("execute deployment-scoped credential slot: %v", err)
	}
	if process.calls != 1 {
		t.Fatalf("Pi process calls = %d", process.calls)
	}
}

func TestPiExecutorReverifiesReleaseAndExtensionBeforeEveryTask(
	t *testing.T,
) {
	t.Parallel()
	task := validPiTask()
	task.IncludePatch = false
	process := &piFakeProcess{events: validPiEventStream()}
	executor := newTestPiExecutor(
		t,
		task,
		"",
		[]byte("scoped-test-credential-1234567890"),
		process,
		nil,
	)
	if err := os.WriteFile(
		executor.resultExtension.Path,
		[]byte("tampered extension"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Execute(
		context.Background(), task,
	); !errors.Is(err, ErrExecution) {
		t.Fatalf("tampered extension error = %v", err)
	}
	if process.calls != 0 {
		t.Fatal("Pi was invoked with a tampered result extension")
	}
}

func TestParsePiEventsRequiresSettledSingleFinalResult(t *testing.T) {
	t.Parallel()
	valid := validPiEventStream()
	for _, stream := range [][]byte{
		[]byte(
			`{"type":"agent_start"}` + "\n" +
				`{"type":"agent_end","willRetry":false}` + "\n" +
				`{"type":"agent_settled"}` + "\n",
		),
		bytes.Replace(
			valid,
			[]byte(`{"type":"agent_settled"}`+"\n"),
			nil,
			1,
		),
		bytes.Replace(
			valid,
			[]byte(`"willRetry":false`),
			[]byte(`"willRetry":true`),
			1,
		),
		bytes.Replace(
			valid,
			[]byte(`"terminate":true`),
			[]byte(`"terminate":false`),
			1,
		),
		append(
			bytes.Replace(
				valid,
				[]byte(`{"type":"agent_settled"}`+"\n"),
				nil,
				1,
			),
			[]byte(
				`{"type":"tool_execution_end","toolName":"dirextalk_submit_result","result":{"details":{"status":"completed","summary":"Duplicate.","deliverables":[],"tests":[],"risks":[]},"terminate":true},"isError":false}`+
					"\n"+
					`{"type":"agent_settled"}`+"\n",
			)...,
		),
	} {
		usage, final, err := parsePiEvents(stream)
		clear(final)
		if !errors.Is(err, ErrExecution) {
			t.Fatalf(
				"invalid Pi stream accepted: usage=%+v stream=%s",
				usage,
				stream,
			)
		}
	}
}

func TestParsePiFinalRejectsUnknownFieldsAndSecrets(t *testing.T) {
	t.Parallel()
	for _, value := range [][]byte{
		[]byte(`{
			"schema_version":"dirextalk.agent.pi-final/v1",
			"status":"completed",
			"summary":"Done.",
			"deliverables":[],
			"tests":[],
			"risks":[],
			"extra":true
		}`),
		[]byte(`{
			"schema_version":"dirextalk.agent.pi-final/v1",
			"status":"completed",
			"summary":"sk-abcdefghijklmnopqrstuvwxyz",
			"deliverables":[],
			"tests":[],
			"risks":[]
		}`),
	} {
		_, canonical, err := ParsePiFinalV1(value)
		clear(canonical)
		if !errors.Is(err, ErrExecution) {
			t.Fatalf("unsafe Pi final accepted: %s", value)
		}
	}
}

func newTestPiExecutor(
	t *testing.T,
	task TaskV1,
	workspace string,
	credential []byte,
	process ProcessRunner,
	patches PatchCollector,
) *PiExecutor {
	t.Helper()
	binaryPath, binaryDigest := writePiTestFile(
		t,
		"pi",
		[]byte("#!/bin/false\n"),
		0o700,
	)
	extensionPath, extensionDigest := writePiTestFile(
		t,
		"dirextalk-result.ts",
		[]byte("export default function register() {}\n"),
		0o600,
	)
	resolver := &fakeInputResolver{inputs: ResolvedInputs{
		ContextJSON:  []byte(`{"scope":"approved"}`),
		WorkspaceDir: workspace,
		Credential:   bytes.Clone(credential),
	}}
	executor, err := NewPiExecutor(PiConfig{
		Release: InstalledRelease{
			ReleaseID:        task.RuntimeReleaseID,
			Version:          task.RuntimeVersion,
			ImageDigest:      task.RuntimeImageDigest,
			Adapter:          AdapterPiV1,
			ExecutablePath:   binaryPath,
			ExecutableSHA256: binaryDigest,
		},
		ResultExtension: InstalledExtension{
			Name:   PiResultExtensionName,
			Path:   extensionPath,
			SHA256: extensionDigest,
		},
		Models: []QualifiedModel{{
			ProfileID:      task.ModelProfileID,
			Provider:       task.ModelProvider,
			Model:          task.Model,
			Interface:      task.ModelInterface,
			CredentialSlot: "model-token",
		}},
		Inputs:     resolver,
		Processes:  process,
		Patches:    patches,
		StateRoot:  t.TempDir(),
		SearchPath: DefaultRuntimeSearchPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func writePiTestFile(
	t *testing.T,
	name string,
	content []byte,
	mode os.FileMode,
) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return path, "sha256:" + hex.EncodeToString(digest[:])
}

func validPiTask() TaskV1 {
	task := validTask()
	task.Adapter = AdapterPiV1
	task.RuntimeVersion = "0.83.0"
	task.ModelProfileID = "openai-pi-worker"
	return task
}

func validPiEventStream() []byte {
	return []byte(
		`{"type":"session","version":3,"id":"session-1"}` + "\n" +
			`{"type":"agent_start"}` + "\n" +
			`{"type":"turn_start"}` + "\n" +
			`{"type":"message_end","message":{"role":"assistant","stopReason":"toolUse","usage":{"input":120,"output":24,"cacheRead":20,"reasoning":6}}}` + "\n" +
			`{"type":"tool_execution_start","toolCallId":"call-1","toolName":"dirextalk_submit_result","args":{}}` + "\n" +
			`{"type":"tool_execution_end","toolCallId":"call-1","toolName":"dirextalk_submit_result","result":{"content":[{"type":"text","text":"Final result submitted."}],"details":{"status":"completed","summary":"Implemented the approved change.","deliverables":["Updated the API implementation."],"tests":["Focused tests passed."],"risks":[]},"terminate":true},"isError":false}` + "\n" +
			`{"type":"turn_end","message":{"role":"assistant"},"toolResults":[]}` + "\n" +
			`{"type":"agent_end","messages":[],"willRetry":false}` + "\n" +
			`{"type":"agent_settled"}` + "\n",
	)
}

type piFakeProcess struct {
	events []byte
	err    error
	calls  int
	spec   ProcessSpec
}

func (process *piFakeProcess) Run(
	_ context.Context,
	spec ProcessSpec,
) (ProcessOutput, error) {
	process.calls++
	process.spec = cloneProcessSpec(spec)
	if process.err != nil {
		return ProcessOutput{}, process.err
	}
	return ProcessOutput{Stdout: bytes.Clone(process.events)}, nil
}
