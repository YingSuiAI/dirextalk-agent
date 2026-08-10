package runtime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPiRunnerUsesPinnedClosedInvocationAndExactMaxTokens(t *testing.T) {
	t.Parallel()
	contextJSON := []byte(`{"scope":"approved"}`)
	task := validTask(contextJSON, WorkspaceWrite)
	workspace := filepath.Join(t.TempDir(), "isolated-workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	process := &fakeProcess{events: validPiEventStream()}
	collector := &fakeOutputCollector{artifacts: []Artifact{{
		Name: "changes.patch", MediaType: "text/plain; charset=utf-8",
		Content: []byte("diff --git a/main.go b/main.go\n"),
	}}}
	credential := []byte("cwmg1_abcdefghijklmnopqrstuvwxyzABCDEFGH")
	grant := validModelGrant(task)
	grant.BearerToken = bytes.Clone(credential)
	executor := newTestExecutor(t, task, Inputs{
		InputManifestJSON: bytes.Clone(contextJSON),
		Workspace: Workspace{
			Directory: workspace, Mode: WorkspaceWrite,
			SHA256: task.WorkspaceSHA256, Isolated: true,
		},
	}, process, collector)

	result, err := executor.Run(context.Background(), task, grant)
	if err != nil {
		t.Fatal(err)
	}
	defer DestroyResult(&result)
	if len(result.Artifacts) != 2 || result.Artifacts[0].Name != "final.json" ||
		result.Artifacts[1].Name != "changes.patch" || collector.calls != 1 ||
		collector.snapshotCalls != 1 || collector.workspace != workspace {
		t.Fatalf("result=%+v collector=%+v", result, collector)
	}
	final, canonical, err := ParsePiFinalV1(result.Artifacts[0].Content)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(canonical)
	if !bytes.Equal(canonical, result.Artifacts[0].Content) ||
		final.Status != "completed" || final.Summary != "Implemented the approved task." {
		t.Fatalf("final=%+v", final)
	}

	if process.calls != 1 || process.spec.Executable != executor.release.Executable.Path ||
		process.spec.Directory != workspace ||
		process.spec.StdoutPolicy != ProcessStdoutPiEventsV1 {
		t.Fatalf("process spec=%+v", process.spec)
	}
	if process.spec.Environment["HTTP_PROXY"] != PiLoopbackProxyURL ||
		process.spec.Environment["HTTPS_PROXY"] != PiLoopbackProxyURL ||
		process.spec.Environment["NO_PROXY"] != "" {
		t.Fatalf("Pi proxy environment escaped loopback bridge: %+v", process.spec.Environment)
	}
	if process.spec.Environment["NODE_EXTRA_CA_CERTS"] != PiModelRelayTrustBundlePath {
		t.Fatalf("Pi did not receive only the model-relay trust bundle: %+v", process.spec.Environment)
	}
	for _, value := range process.spec.Environment {
		if strings.Contains(value, "outbound-proxy-ca") || strings.Contains(value, "control-plane-ca") {
			t.Fatalf("Worker-only CA leaked into Pi environment: %q", value)
		}
	}
	arguments := strings.Join(process.spec.Arguments, "\n")
	for _, required := range []string{
		"--offline", "--no-session", "--no-extensions", "--no-skills",
		"--no-prompt-templates", "--no-context-files", "--no-approve",
	} {
		if !slices.Contains(process.spec.Arguments, required) {
			t.Fatalf("missing Pi argument %q: %v", required, process.spec.Arguments)
		}
	}
	if strings.Contains(arguments, task.Objective) || strings.Contains(arguments, string(credential)) ||
		strings.Contains(strings.ToLower(arguments), "mcp") ||
		argumentValue(process.spec.Arguments, "--tools") !=
			"read,bash,edit,write,grep,find,ls,"+PiResultToolName {
		t.Fatalf("unsafe Pi arguments: %v", process.spec.Arguments)
	}
	if !bytes.Contains(process.spec.Stdin, []byte(task.Objective)) ||
		bytes.Contains(process.spec.Stdin, credential) ||
		len(process.spec.SecretEnvironment) != 1 ||
		!bytes.Equal(process.spec.SecretEnvironment["DEEPSEEK_API_KEY"], credential) {
		t.Fatal("Pi prompt or credential channel is invalid")
	}
	if _, present := process.spec.SecretEnvironment["OPENAI_API_KEY"]; present {
		t.Fatal("credential was copied into a second provider channel")
	}
	for name := range process.spec.Environment {
		if strings.Contains(name, "MCP") || strings.Contains(name, "SKILL") ||
			strings.Contains(name, "AWS_") {
			t.Fatalf("unexpected inherited capability environment: %s", name)
		}
	}
	var config struct {
		Providers map[string]struct {
			BaseURL        string `json:"baseUrl"`
			ModelOverrides map[string]struct {
				MaxTokens uint64 `json:"maxTokens"`
				Compat    struct {
					MaxTokensField string `json:"maxTokensField"`
				} `json:"compat"`
			} `json:"modelOverrides"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(process.modelsConfig, &config); err != nil {
		t.Fatalf("models config=%q: %v", process.modelsConfig, err)
	}
	override := config.Providers[task.ModelProvider].ModelOverrides[task.Model]
	if config.Providers[task.ModelProvider].BaseURL != task.ModelRelayBaseURL ||
		override.MaxTokens != task.MaxOutputTokens ||
		override.Compat.MaxTokensField != "max_tokens" {
		t.Fatalf("model override=%+v", override)
	}
}

func TestPiRunnerWorkspaceModesAreClosed(t *testing.T) {
	t.Parallel()
	contextJSON := []byte(`{"scope":"approved"}`)
	for _, mode := range []WorkspaceMode{WorkspaceNone, WorkspaceReadOnly} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			task := validTask(contextJSON, mode)
			inputs := Inputs{
				InputManifestJSON: bytes.Clone(contextJSON),
			}
			if mode == WorkspaceReadOnly {
				workspace := filepath.Join(t.TempDir(), "read-only-workspace")
				if err := os.Mkdir(workspace, 0o500); err != nil {
					t.Fatal(err)
				}
				inputs.Workspace = Workspace{
					Directory: workspace, Mode: WorkspaceReadOnly,
					SHA256: task.WorkspaceSHA256, ReadOnly: true,
				}
			}
			process := &fakeProcess{events: validPiEventStream()}
			collector := &fakeOutputCollector{}
			executor := newTestExecutor(t, task, inputs, process, collector)
			result, err := executor.Run(t.Context(), task, validModelGrant(task))
			if err != nil {
				t.Fatal(err)
			}
			DestroyResult(&result)
			tools := argumentValue(process.spec.Arguments, "--tools")
			if collector.calls != 0 || strings.Contains(tools, "bash") ||
				strings.Contains(tools, "edit") || strings.Contains(tools, "write") {
				t.Fatalf("mode=%s tools=%q collector calls=%d", mode, tools, collector.calls)
			}
			if mode == WorkspaceNone && tools != PiResultToolName {
				t.Fatalf("none tools=%q", tools)
			}
			if mode == WorkspaceNone && process.directoryMode != 0o770 {
				t.Fatalf("none workspace mode=%#o", process.directoryMode)
			}
		})
	}
}

func TestPiRunnerRejectsUnisolatedWriteWorkspace(t *testing.T) {
	t.Parallel()
	contextJSON := []byte(`{"scope":"approved"}`)
	task := validTask(contextJSON, WorkspaceWrite)
	workspace := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	process := &fakeProcess{events: validPiEventStream()}
	executor := newTestExecutor(t, task, Inputs{
		InputManifestJSON: bytes.Clone(contextJSON),
		Workspace: Workspace{
			Directory: workspace, Mode: WorkspaceWrite, SHA256: task.WorkspaceSHA256,
		},
	}, process, &fakeOutputCollector{})
	if _, err := executor.Run(t.Context(), task, validModelGrant(task)); !errors.Is(err, ErrExecution) {
		t.Fatalf("unisolated workspace error=%v", err)
	}
	if process.calls != 0 {
		t.Fatal("Pi ran against a non-isolated write workspace")
	}
}

func TestPiRunnerReverifiesPinsBeforeInvocation(t *testing.T) {
	t.Parallel()
	contextJSON := []byte(`{"scope":"approved"}`)
	task := validTask(contextJSON, WorkspaceNone)
	process := &fakeProcess{events: validPiEventStream()}
	executor := newTestExecutor(t, task, Inputs{
		InputManifestJSON: bytes.Clone(contextJSON),
	}, process, nil)
	if err := os.WriteFile(executor.release.ResultExtension.Path, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := executor.Run(t.Context(), task, validModelGrant(task)); !errors.Is(err, ErrExecution) {
		t.Fatalf("tampered extension error=%v", err)
	}
	if process.calls != 0 {
		t.Fatal("Pi ran with a tampered result extension")
	}
}

func TestPiRunnerRejectsUsageBeyondExactAuthorizedMaxTokens(t *testing.T) {
	t.Parallel()
	contextJSON := []byte(`{"scope":"approved"}`)
	task := validTask(contextJSON, WorkspaceNone)
	task.MaxOutputTokens = 512
	process := &fakeProcess{events: bytes.Replace(
		validPiEventStream(), []byte(`"output":24`), []byte(`"output":513`), 1,
	)}
	executor := newTestExecutor(t, task, Inputs{
		InputManifestJSON: bytes.Clone(contextJSON),
	}, process, nil)
	result, err := executor.Run(t.Context(), task, validModelGrant(task))
	DestroyResult(&result)
	failure, ok := FailureOf(err)
	if !ok || failure.Stage != FailureStageOutput || failure.Code != FailureCodeOutputInvalid {
		t.Fatalf("over-budget output failure=%+v ok=%t err=%v", failure, ok, err)
	}
}

func TestPiRunnerRequiresShortLivedBoundRelayGrant(t *testing.T) {
	t.Parallel()
	contextJSON := []byte(`{"scope":"approved"}`)
	task := validTask(contextJSON, WorkspaceNone)
	for _, test := range []struct {
		name   string
		mutate func(*Task, *ModelGrant)
	}{
		{name: "long_lived_provider_key", mutate: func(_ *Task, grant *ModelGrant) {
			grant.BearerToken = []byte("sk-abcdefghijklmnopqrstuvwxyz1234567890")
		}},
		{name: "audience_drift", mutate: func(_ *Task, grant *ModelGrant) {
			grant.AudienceSHA256 = strings.Repeat("e", 64)
		}},
		{name: "limit_drift", mutate: func(_ *Task, grant *ModelGrant) {
			grant.MaxOutputTokens++
		}},
		{name: "expired", mutate: func(_ *Task, grant *ModelGrant) {
			grant.ExpiresAtUnix = time.Now().UTC().Add(time.Second).Unix()
		}},
		{name: "public_provider_endpoint", mutate: func(task *Task, grant *ModelGrant) {
			task.ModelRelayBaseURL = "https://api.deepseek.com/v1"
			digest := sha256.Sum256([]byte(task.ModelRelayBaseURL))
			task.ModelRelayEndpointSHA256 = hex.EncodeToString(digest[:])
			grant.RelayBaseURL = task.ModelRelayBaseURL
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			candidate := task
			grant := validModelGrant(candidate)
			test.mutate(&candidate, &grant)
			if candidate.Validate() == nil && grant.ValidateFor(
				candidate, time.Now().UTC(),
			) == nil {
				t.Fatal("unsafe model relay grant was accepted")
			}
		})
	}
}

func TestPiContractsRejectUnboundedOrUnsafeOutput(t *testing.T) {
	t.Parallel()
	contextJSON := []byte(`{"scope":"approved"}`)
	task := validTask(contextJSON, WorkspaceNone)
	task.MaxOutputTokens = 0
	if !errors.Is(task.Validate(), ErrInvalid) {
		t.Fatal("zero max_output_tokens was accepted")
	}
	task = validTask(contextJSON, WorkspaceNone)
	task.InputManifestSHA256 = "sha256:" + task.InputManifestSHA256
	if !errors.Is(task.Validate(), ErrInvalid) {
		t.Fatal("prefixed digest was accepted")
	}
	task = validTask(contextJSON, WorkspaceNone)
	digest, err := task.Digest()
	if err != nil || len(digest) != sha256.Size*2 || strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("task digest=%q err=%v", digest, err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"schema_version":"dirextalk.agent.pi-final/v1","status":"completed","summary":"done","deliverables":[],"tests":[],"risks":[],"extra":true}`),
		[]byte(`{"schema_version":"dirextalk.agent.pi-final/v1","status":"completed","summary":"sk-abcdefghijklmnopqrstuvwxyz","deliverables":[],"tests":[],"risks":[]}`),
	} {
		_, canonical, err := ParsePiFinalV1(raw)
		clear(canonical)
		if !errors.Is(err, ErrExecution) {
			t.Fatalf("unsafe final accepted: %s", raw)
		}
	}
	_, _, err = ParsePiEvents(piFailureEventStream("error", "401 invalid api key sk-sensitive-canary"))
	failure, ok := FailureOf(err)
	if !ok || failure.Code != FailureCodeProviderAuthentication ||
		strings.Contains(err.Error(), "sensitive-canary") {
		t.Fatalf("provider failure=%+v ok=%t err=%v", failure, ok, err)
	}
}

func TestOSProcessRunnerBoundsOutputAndDoesNotInheritEnvironment(t *testing.T) {
	t.Setenv("DIREXTALK_SHOULD_NOT_LEAK", "host-value")
	directory := filepath.Clean(t.TempDir())
	output, err := (OSProcessRunner{}).Run(t.Context(), ProcessSpec{
		Executable:     "/bin/sh",
		Arguments:      []string{"-c", `printf '%s' "${DIREXTALK_SHOULD_NOT_LEAK-unset}"`},
		Directory:      directory,
		Environment:    map[string]string{"PATH": "/usr/bin:/bin"},
		MaxStdoutBytes: 32, MaxStderrBytes: 32,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(output.Stdout)
	if string(output.Stdout) != "unset" {
		t.Fatalf("inherited environment leaked: %q", output.Stdout)
	}
	_, err = (OSProcessRunner{}).Run(t.Context(), ProcessSpec{
		Executable: "/bin/sh", Arguments: []string{"-c", "printf overflow"},
		Directory: directory, Environment: map[string]string{"PATH": "/usr/bin:/bin"},
		MaxStdoutBytes: 2, MaxStderrBytes: 32,
	})
	failure, ok := FailureOf(err)
	if !ok || failure.Code != FailureCodeProcessOutputLimit {
		t.Fatalf("overflow failure=%+v ok=%t err=%v", failure, ok, err)
	}
}

type fakeResolver struct{ inputs Inputs }

func (resolver *fakeResolver) Resolve(context.Context, Task) (Inputs, error) {
	return Inputs{
		InputManifestJSON: bytes.Clone(resolver.inputs.InputManifestJSON),
		Workspace:         resolver.inputs.Workspace,
		Cleanup:           resolver.inputs.Cleanup,
	}, nil
}

type fakeProcess struct {
	events        []byte
	spec          ProcessSpec
	modelsConfig  []byte
	directoryMode os.FileMode
	calls         int
}

func (process *fakeProcess) Run(_ context.Context, spec ProcessSpec) (ProcessOutput, error) {
	process.calls++
	process.spec = spec
	process.spec.Arguments = slices.Clone(spec.Arguments)
	process.spec.Environment = make(map[string]string, len(spec.Environment))
	for name, value := range spec.Environment {
		process.spec.Environment[name] = value
	}
	process.spec.SecretEnvironment = make(map[string][]byte, len(spec.SecretEnvironment))
	for name, value := range spec.SecretEnvironment {
		process.spec.SecretEnvironment[name] = bytes.Clone(value)
	}
	process.spec.Stdin = bytes.Clone(spec.Stdin)
	directory, err := os.Stat(spec.Directory)
	if err != nil {
		return ProcessOutput{}, err
	}
	process.directoryMode = directory.Mode().Perm()
	raw, err := os.ReadFile(filepath.Join(spec.Environment["PI_CODING_AGENT_DIR"], "models.json"))
	if err != nil {
		return ProcessOutput{}, err
	}
	process.modelsConfig = raw
	return ProcessOutput{Stdout: bytes.Clone(process.events)}, nil
}

type fakeOutputCollector struct {
	artifacts     []Artifact
	workspace     string
	snapshotCalls int
	calls         int
}

func (collector *fakeOutputCollector) Snapshot(
	_ context.Context,
	workspace string,
	_ string,
	_ uint64,
) (WorkspaceBaseline, error) {
	collector.snapshotCalls++
	collector.workspace = workspace
	return WorkspaceBaseline{}, nil
}

func (collector *fakeOutputCollector) Collect(
	_ context.Context,
	workspace string,
	_ WorkspaceBaseline,
	_ uint64,
) ([]Artifact, error) {
	collector.calls++
	collector.workspace = workspace
	result := make([]Artifact, len(collector.artifacts))
	for index, artifact := range collector.artifacts {
		result[index] = artifact
		result[index].Content = bytes.Clone(artifact.Content)
	}
	return result, nil
}

func newTestExecutor(
	t *testing.T,
	task Task,
	inputs Inputs,
	process ProcessRunner,
	collector OutputCollector,
) *PiExecutor {
	t.Helper()
	binaryPath, binaryDigest := writePinnedTestFile(t, "pi", []byte("#!/bin/false\n"), 0o700)
	extensionPath, extensionDigest := writePinnedTestFile(
		t, "dirextalk-result.ts", []byte("export default function register() {}\n"), 0o600,
	)
	task.PiExecutableSHA256 = binaryDigest
	task.ResultExtensionSHA256 = extensionDigest
	// The caller's task is passed by value, so pins must already be reflected
	// in it. All fixtures use the deterministic file contents above.
	executor, err := NewPiExecutor(PiConfig{
		Release: PiRelease{
			Version:         task.PiVersion,
			Executable:      PinnedFile{Path: binaryPath, SHA256: binaryDigest},
			ResultExtension: PinnedFile{Path: extensionPath, SHA256: extensionDigest},
		},
		Models: []QualifiedModel{{
			ProfileID: task.ModelProfileID, Provider: task.ModelProvider,
			Model: task.Model, Interface: task.ModelInterface,
			CredentialEnvironment: "DEEPSEEK_API_KEY",
			RelayBaseURL:          task.ModelRelayBaseURL,
			RelayEndpointSHA256:   task.ModelRelayEndpointSHA256,
			MaximumOutputTokens:   4096,
		}},
		Inputs: &fakeResolver{inputs: inputs}, Processes: process, Outputs: collector,
		StateRoot: t.TempDir(), SearchPath: DefaultSearchPath,
		OutboundProxyURL:          PiLoopbackProxyURL,
		ModelRelayTrustBundlePath: PiModelRelayTrustBundlePath,
		RuntimeGID:                uint32(os.Getgid()),
	})
	if err != nil {
		t.Fatal(err)
	}
	return executor
}

func validTask(contextJSON []byte, mode WorkspaceMode) Task {
	contextDigest := sha256.Sum256(contextJSON)
	binaryDigest := sha256.Sum256([]byte("#!/bin/false\n"))
	extensionDigest := sha256.Sum256([]byte("export default function register() {}\n"))
	task := Task{
		SchemaVersion: TaskSchemaV1, Recipe: RecipeEphemeralPiTask,
		Adapter:             AdapterPiJSONTaskV1,
		TaskID:              "11111111-1111-4111-8111-111111111111",
		ExecutionID:         "22222222-2222-4222-8222-222222222222",
		Objective:           "Implement the approved task.",
		InputManifestSHA256: hex.EncodeToString(contextDigest[:]),
		WorkspaceMode:       mode, PiVersion: "0.83.0",
		PiExecutableSHA256:    hex.EncodeToString(binaryDigest[:]),
		ResultExtensionSHA256: hex.EncodeToString(extensionDigest[:]),
		ModelProfileID:        "deepseek-pi-worker", ModelProfileRevision: 3,
		ModelProvider: "deepseek",
		Model:         "deepseek-chat", ModelInterface: ModelOpenAICompatible,
		CredentialVersion: 5, ModelBindingSHA256: strings.Repeat("b", 64),
		ModelGrantAudienceSHA256: strings.Repeat("c", 64),
		ModelGrantLimitSHA256:    strings.Repeat("d", 64),
		ModelRelayBaseURL:        "https://model-relay.dirextalk.invalid/v1",
		MaxOutputTokens:          777,
		MaxOutputBytes:           MaxResultBytes,
	}
	relayDigest := sha256.Sum256([]byte(task.ModelRelayBaseURL))
	task.ModelRelayEndpointSHA256 = hex.EncodeToString(relayDigest[:])
	task.ModelRelayBindingSHA256 = strings.Repeat("e", 64)
	if mode != WorkspaceNone {
		task.WorkspaceSHA256 = task.InputManifestSHA256
	}
	return task
}

func validModelGrant(task Task) ModelGrant {
	return ModelGrant{
		GrantID:            "44444444-4444-4444-8444-444444444444",
		BearerToken:        []byte("cwmg1_abcdefghijklmnopqrstuvwxyzABCDEFGH"),
		ModelBindingSHA256: task.ModelBindingSHA256,
		AudienceSHA256:     task.ModelGrantAudienceSHA256,
		ExpiresAtUnix:      time.Now().UTC().Add(10 * time.Minute).Unix(),
		LimitSHA256:        task.ModelGrantLimitSHA256,
		RelayBaseURL:       task.ModelRelayBaseURL,
		RelayBindingSHA256: task.ModelRelayBindingSHA256,
		MaxOutputTokens:    task.MaxOutputTokens,
	}
}

func validPiEventStream() []byte {
	return []byte(
		`{"type":"session","version":3,"id":"session-1"}` + "\n" +
			`{"type":"agent_start"}` + "\n" +
			`{"type":"message_update","message":{"role":"assistant","content":"discarded"}}` + "\n" +
			`{"type":"message_end","message":{"role":"assistant","stopReason":"toolUse","usage":{"input":120,"output":24,"cacheRead":20,"reasoning":6}}}` + "\n" +
			`{"type":"tool_execution_end","toolName":"dirextalk_submit_result","result":{"details":{"status":"completed","summary":"Implemented the approved task.","deliverables":["Created the requested output."],"tests":["Focused tests passed."],"risks":[]},"terminate":true},"isError":false}` + "\n" +
			`{"type":"agent_end","willRetry":false}` + "\n" +
			`{"type":"agent_settled"}` + "\n",
	)
}

func piFailureEventStream(stopReason, message string) []byte {
	event, _ := json.Marshal(map[string]any{
		"type": "message_end",
		"message": map[string]any{
			"role": "assistant", "stopReason": stopReason, "errorMessage": message,
			"usage": map[string]int64{},
		},
	})
	return []byte(
		`{"type":"session","version":3}` + "\n" +
			`{"type":"agent_start"}` + "\n" + string(event) + "\n" +
			`{"type":"agent_end","willRetry":false}` + "\n" +
			`{"type":"agent_settled"}` + "\n",
	)
}

func writePinnedTestFile(t *testing.T, name string, content []byte, mode os.FileMode) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return path, hex.EncodeToString(digest[:])
}

func argumentValue(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}
