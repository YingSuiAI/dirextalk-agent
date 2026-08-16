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
	task.Model = "deepseek/deepseek-v4-flash-0731"
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
	if err := task.Validate(); err != nil {
		t.Fatalf("task fixture: %v", err)
	}
	if err := executor.ValidateTask(task); err != nil {
		t.Fatalf("qualified model fixture: %v", err)
	}
	if err := grant.ValidateFor(task, executor.now()); err != nil {
		t.Fatalf("provider credential fixture: %v", err)
	}

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
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"} {
		if _, exists := process.spec.Environment[name]; exists {
			t.Fatalf("Pi model call is still proxied through %s: %+v", name, process.spec.Environment)
		}
	}
	if _, exists := process.spec.Environment["NODE_EXTRA_CA_CERTS"]; exists {
		t.Fatalf("Pi still depends on a Central model trust bundle: %+v", process.spec.Environment)
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
		!strings.Contains(argumentValue(process.spec.Arguments, "--system-prompt"), "dirextalk-presentation guide") ||
		!strings.Contains(argumentValue(process.spec.Arguments, "--system-prompt"), "Do not claim visual verification") ||
		argumentValue(process.spec.Arguments, "--provider") != task.ModelProvider ||
		argumentValue(process.spec.Arguments, "--model") != task.Model ||
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
			BaseURL string `json:"baseUrl"`
			API     string `json:"api"`
			APIKey  string `json:"apiKey"`
			Models  []struct {
				ID            string `json:"id"`
				Reasoning     bool   `json:"reasoning"`
				MaxTokens     uint64 `json:"maxTokens"`
				ContextWindow uint64 `json:"contextWindow"`
				Compat        struct {
					MaxTokensField                              string `json:"maxTokensField"`
					SupportsStore                               bool   `json:"supportsStore"`
					SupportsDeveloperRole                       bool   `json:"supportsDeveloperRole"`
					SupportsReasoningEffort                     bool   `json:"supportsReasoningEffort"`
					ThinkingFormat                              string `json:"thinkingFormat"`
					RequiresReasoningContentOnAssistantMessages bool   `json:"requiresReasoningContentOnAssistantMessages"`
				} `json:"compat"`
			} `json:"models"`
			ModelOverrides json.RawMessage `json:"modelOverrides"`
		} `json:"providers"`
	}
	if err := json.Unmarshal(process.modelsConfig, &config); err != nil {
		t.Fatalf("models config=%q: %v", process.modelsConfig, err)
	}
	provider := config.Providers[task.ModelProvider]
	if provider.BaseURL != task.ModelBaseURL || provider.API != "openai-completions" ||
		provider.APIKey != "$DEEPSEEK_API_KEY" ||
		len(provider.Models) != 1 || provider.Models[0].ID != task.Model ||
		!provider.Models[0].Reasoning || provider.Models[0].MaxTokens != task.MaxOutputTokens ||
		provider.Models[0].ContextWindow != task.ModelContextWindow ||
		provider.Models[0].Compat.MaxTokensField != "max_tokens" ||
		provider.Models[0].Compat.SupportsStore ||
		provider.Models[0].Compat.SupportsDeveloperRole ||
		!provider.Models[0].Compat.SupportsReasoningEffort ||
		provider.Models[0].Compat.ThinkingFormat != "deepseek" ||
		!provider.Models[0].Compat.RequiresReasoningContentOnAssistantMessages ||
		provider.ModelOverrides != nil {
		t.Fatalf("provider config=%+v", provider)
	}
	if string(process.settingsConfig) != piSettingsJSON {
		t.Fatalf("settings config=%q", process.settingsConfig)
	}
}

func TestWritePiModelsConfigSelectsExactAPIInterface(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, provider, model, api string
		modelInterface             ModelInterface
		wantMaxTokensField         string
		wantDeepSeekCompatibility  bool
	}{
		{
			name: "openai_compatible", provider: "deepseek",
			model: "deepseek/deepseek-v4-flash-0731", api: "openai-completions",
			modelInterface: ModelOpenAICompatible, wantMaxTokensField: "max_tokens",
			wantDeepSeekCompatibility: true,
		},
		{
			name: "openai_responses", provider: "openai",
			model: "openai/gpt-test", api: "openai-responses",
			modelInterface: ModelOpenAIResponses,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			directory := t.TempDir()
			task := Task{
				ModelProvider: test.provider, Model: test.model,
				ModelInterface:  test.modelInterface,
				ModelBaseURL:    "https://api.dirextalk.invalid/v1",
				MaxOutputTokens: 4096, ModelContextWindow: 65536,
			}
			if err := writePiModelsConfig(directory, task); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(directory, "models.json"))
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Providers map[string]struct {
					API    string `json:"api"`
					APIKey string `json:"apiKey"`
					Models []struct {
						ID            string `json:"id"`
						Reasoning     bool   `json:"reasoning"`
						MaxTokens     uint64 `json:"maxTokens"`
						ContextWindow uint64 `json:"contextWindow"`
						Compat        struct {
							MaxTokensField                              string `json:"maxTokensField"`
							SupportsStore                               bool   `json:"supportsStore"`
							SupportsDeveloperRole                       bool   `json:"supportsDeveloperRole"`
							SupportsReasoningEffort                     bool   `json:"supportsReasoningEffort"`
							ThinkingFormat                              string `json:"thinkingFormat"`
							RequiresReasoningContentOnAssistantMessages bool   `json:"requiresReasoningContentOnAssistantMessages"`
						} `json:"compat"`
					} `json:"models"`
					ModelOverrides json.RawMessage `json:"modelOverrides"`
				} `json:"providers"`
			}
			if err := json.Unmarshal(raw, &config); err != nil {
				t.Fatal(err)
			}
			provider := config.Providers[test.provider]
			if provider.API != test.api ||
				provider.APIKey != "$"+PiCredentialEnvironment(test.provider) ||
				len(provider.Models) != 1 ||
				provider.Models[0].ID != test.model || !provider.Models[0].Reasoning ||
				provider.Models[0].MaxTokens != task.MaxOutputTokens ||
				provider.Models[0].ContextWindow != task.ModelContextWindow ||
				provider.Models[0].Compat.MaxTokensField != test.wantMaxTokensField ||
				provider.ModelOverrides != nil {
				t.Fatalf("provider config=%+v", provider)
			}
			compat := provider.Models[0].Compat
			if test.wantDeepSeekCompatibility &&
				(compat.SupportsStore || compat.SupportsDeveloperRole ||
					!compat.SupportsReasoningEffort || compat.ThinkingFormat != "deepseek" ||
					!compat.RequiresReasoningContentOnAssistantMessages) {
				t.Fatalf("deepseek compatibility=%+v", compat)
			}
		})
	}
}

func TestWritePiSettingsConfigEnablesPiSemanticAutoCompaction(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	if err := writePiSettingsConfig(directory); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings struct {
		Compaction struct {
			Enabled          bool    `json:"enabled"`
			ReserveTokens    *uint64 `json:"reserveTokens"`
			KeepRecentTokens *uint64 `json:"keepRecentTokens"`
		} `json:"compaction"`
		EnableInstallTelemetry bool `json:"enableInstallTelemetry"`
	}
	if err = json.Unmarshal(raw, &settings); err != nil {
		t.Fatalf("settings=%s: %v", raw, err)
	}
	if !settings.Compaction.Enabled || settings.Compaction.ReserveTokens != nil ||
		settings.Compaction.KeepRecentTokens != nil || settings.EnableInstallTelemetry {
		t.Fatalf("settings=%+v", settings)
	}
	if err = writePiSettingsConfig(directory); !errors.Is(err, ErrExecution) {
		t.Fatalf("settings rewrite error=%v", err)
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

func TestPiRunnerAcceptsCumulativeUsageAcrossIndividuallyBoundedModelCalls(t *testing.T) {
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
	if err != nil {
		t.Fatalf("cumulative usage from multiple bounded calls was rejected: %v", err)
	}
	defer DestroyResult(&result)
	if result.Usage.OutputTokens != 513 {
		t.Fatalf("output tokens=%d", result.Usage.OutputTokens)
	}
}

func TestParsePiEventsAcceptsPiManagedRetryAndContinuationRuns(t *testing.T) {
	t.Parallel()
	stream := []byte(
		`{"type":"session","version":3,"id":"session-1"}` + "\n" +
			`{"type":"agent_start"}` + "\n" +
			`{"type":"message_end","message":{"role":"assistant","stopReason":"error","errorMessage":"503 service unavailable","usage":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"reasoning":0}}}` + "\n" +
			`{"type":"agent_end","willRetry":true}` + "\n" +
			`{"type":"auto_retry_start","attempt":1,"maxAttempts":3,"delayMs":2000}` + "\n" +
			`{"type":"agent_start"}` + "\n" +
			`{"type":"message_end","message":{"role":"assistant","stopReason":"toolUse","usage":{"input":120,"output":24,"cacheRead":20,"cacheWrite":0,"reasoning":6}}}` + "\n" +
			`{"type":"auto_retry_end","success":true,"attempt":1}` + "\n" +
			`{"type":"tool_execution_end","toolName":"dirextalk_submit_result","result":{"content":[{"type":"text","text":"Final result submitted."}],"details":{"status":"completed","summary":"Recovered and completed the task.","deliverables":["report.txt"],"tests":["Focused tests passed."],"risks":[]},"terminate":true},"isError":false}` + "\n" +
			`{"type":"agent_end","willRetry":false}` + "\n" +
			`{"type":"agent_settled"}` + "\n",
	)

	usage, finalJSON, err := ParsePiEvents(stream)
	if err != nil {
		t.Fatalf("parse Pi-managed retry: %v", err)
	}
	defer clear(finalJSON)
	if usage.InputTokens != 140 || usage.OutputTokens != 24 ||
		usage.CachedInputTokens != 20 || usage.ReasoningOutputTokens != 6 {
		t.Fatalf("retry usage=%+v", usage)
	}
	final, canonical, err := ParsePiFinalV1(finalJSON)
	defer clear(canonical)
	if err != nil || final.Summary != "Recovered and completed the task." {
		t.Fatalf("retry final=%+v err=%v", final, err)
	}
}

func TestPiProcessOutputAcceptsRealPi083RetryLifecycle(t *testing.T) {
	t.Parallel()
	raw := []byte(
		`{"type":"session","version":3,"id":"session-1"}` + "\n" +
			`{"type":"agent_start"}` + "\n" +
			`{"type":"turn_start"}` + "\n" +
			`{"type":"message_start","message":{"role":"assistant","stopReason":"pending"}}` + "\n" +
			`{"type":"message_end","message":{"role":"assistant","stopReason":"error","errorMessage":"503 service unavailable","usage":{"input":0,"output":0,"cacheRead":0,"cacheWrite":0,"reasoning":0}}}` + "\n" +
			`{"type":"turn_end"}` + "\n" +
			`{"type":"agent_end","willRetry":true}` + "\n" +
			`{"type":"auto_retry_start","attempt":1,"maxAttempts":3,"delayMs":2000}` + "\n" +
			`{"type":"agent_start"}` + "\n" +
			`{"type":"turn_start"}` + "\n" +
			`{"type":"message_update","assistantMessageEvent":{"type":"thinking_delta","delta":"discarded"}}` + "\n" +
			`{"type":"message_end","message":{"role":"assistant","stopReason":"toolUse","usage":{"input":100,"output":20,"cacheRead":0,"cacheWrite":0,"reasoning":0}}}` + "\n" +
			`{"type":"auto_retry_end","success":true,"attempt":1}` + "\n" +
			`{"type":"tool_execution_start","toolName":"dirextalk_submit_result"}` + "\n" +
			`{"type":"tool_execution_end","toolName":"dirextalk_submit_result","result":{"content":[{"type":"text","text":"Final result submitted."}],"details":{"status":"completed","summary":"Real Pi 0.83 retry lifecycle passed.","deliverables":["retry-evidence.txt"],"tests":["real Pi 0.83 JSON event stream"],"risks":[]},"terminate":true},"isError":false}` + "\n" +
			`{"type":"turn_end"}` + "\n" +
			`{"type":"agent_end","willRetry":false}` + "\n" +
			`{"type":"agent_settled"}` + "\n",
	)
	buffer := newProcessOutputBuffer(ProcessStdoutPiEventsV1, MaxProcessOutputBytes, nil)
	for len(raw) > 0 {
		chunk := min(17, len(raw))
		if _, err := buffer.Write(raw[:chunk]); err != nil {
			t.Fatal(err)
		}
		raw = raw[chunk:]
	}
	buffer.finalize()
	if buffer.exceededLimit() {
		t.Fatal("real Pi retry lifecycle exceeded retained output limit")
	}
	retained := buffer.clone()
	buffer.destroy()
	defer clear(retained)
	usage, finalJSON, err := ParsePiEvents(retained)
	defer clear(finalJSON)
	if err != nil || usage.InputTokens != 100 || usage.OutputTokens != 20 ||
		!bytes.Contains(finalJSON, []byte("Real Pi 0.83 retry lifecycle passed.")) {
		t.Fatalf("retained retry output usage=%+v final=%s err=%v", usage, finalJSON, err)
	}
	if bytes.Contains(retained, []byte("discarded")) || bytes.Contains(retained, []byte("turn_start")) {
		t.Fatalf("transient Pi payload was retained: %s", retained)
	}
}

func TestParsePiEventsRejectsContinuationAfterFinalSubmission(t *testing.T) {
	t.Parallel()
	stream := bytes.Replace(
		validPiEventStream(),
		[]byte(`{"type":"agent_end","willRetry":false}`+"\n"),
		[]byte(
			`{"type":"agent_end","willRetry":false}`+"\n"+
				`{"type":"agent_start"}`+"\n"+
				`{"type":"agent_end","willRetry":false}`+"\n",
		),
		1,
	)
	usage, finalJSON, err := ParsePiEvents(stream)
	clear(finalJSON)
	if !errors.Is(err, ErrExecution) || usage != (Usage{}) {
		t.Fatalf("continuation after final accepted: usage=%+v err=%v", usage, err)
	}
}

func TestPiRunnerRequiresBoundTemporaryProviderCredential(t *testing.T) {
	t.Parallel()
	contextJSON := []byte(`{"scope":"approved"}`)
	task := validTask(contextJSON, WorkspaceNone)
	for _, test := range []struct {
		name   string
		mutate func(*Task, *ModelGrant)
	}{
		{name: "audience_drift", mutate: func(_ *Task, grant *ModelGrant) {
			grant.AudienceSHA256 = strings.Repeat("e", 64)
		}},
		{name: "limit_drift", mutate: func(_ *Task, grant *ModelGrant) {
			grant.MaxOutputTokens++
		}},
		{name: "expired", mutate: func(_ *Task, grant *ModelGrant) {
			grant.ExpiresAtUnix = time.Now().UTC().Add(time.Second).Unix()
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
				t.Fatal("unbound or expired provider credential was accepted")
			}
		})
	}
}

func TestPiRunnerAcceptsDirectProviderKeyAndEndpoint(t *testing.T) {
	t.Parallel()
	task := validTask([]byte(`{"scope":"approved"}`), WorkspaceNone)
	task.ModelBaseURL = "https://api.deepseek.com"
	digest := sha256.Sum256([]byte(task.ModelBaseURL))
	task.ModelEndpointSHA256 = hex.EncodeToString(digest[:])
	grant := validModelGrant(task)
	grant.BearerToken = []byte("sk-direct-provider-key")
	grant.BaseURL = task.ModelBaseURL
	if err := task.Validate(); err != nil {
		t.Fatalf("direct provider task: %v", err)
	}
	if err := grant.ValidateFor(task, time.Now().UTC()); err != nil {
		t.Fatalf("direct provider credential: %v", err)
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
	_, _, err = ParsePiEvents(piFailureEventStream(
		"error", `429 {"error":{"code":"token_budget_exhausted"}}`,
	))
	failure, ok = FailureOf(err)
	if !ok || failure.Code != FailureCodeModelBudgetExhausted ||
		failure.Stage != FailureStagePi {
		t.Fatalf("budget failure=%+v ok=%t err=%v", failure, ok, err)
	}
	_, _, err = ParsePiEvents(piFailureEventStream(
		"error", `413 {"error":{"code":"context_request_too_large"}}`,
	))
	failure, ok = FailureOf(err)
	if !ok || failure.Code != FailureCodeContextLimit || failure.Stage != FailureStagePi {
		t.Fatalf("context failure=%+v ok=%t err=%v", failure, ok, err)
	}
	_, _, err = ParsePiEvents(piFailureEventStream("aborted", ""))
	failure, ok = FailureOf(err)
	if !ok || failure.Code != FailureCodeContextLimit || failure.Stage != FailureStagePi {
		t.Fatalf("guard abort failure=%+v ok=%t err=%v", failure, ok, err)
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
	events         []byte
	spec           ProcessSpec
	modelsConfig   []byte
	settingsConfig []byte
	directoryMode  os.FileMode
	calls          int
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
	settings, err := os.ReadFile(filepath.Join(spec.Environment["PI_CODING_AGENT_DIR"], "settings.json"))
	if err != nil {
		return ProcessOutput{}, err
	}
	process.settingsConfig = settings
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
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	config := PiConfig{
		Release: PiRelease{
			Version:         task.PiVersion,
			Executable:      PinnedFile{Path: binaryPath, SHA256: binaryDigest},
			ResultExtension: PinnedFile{Path: extensionPath, SHA256: extensionDigest},
		},
		Models: []QualifiedModel{{
			ProfileID: task.ModelProfileID, Provider: task.ModelProvider,
			Model: task.Model, Interface: task.ModelInterface,
			CredentialEnvironment: "DEEPSEEK_API_KEY",
			BaseURL:               task.ModelBaseURL,
			EndpointSHA256:        task.ModelEndpointSHA256,
			MaximumOutputTokens:   4096,
		}},
		Inputs: &fakeResolver{inputs: inputs}, Processes: process, Outputs: collector,
		StateRoot: stateRoot, SearchPath: DefaultSearchPath,
		RuntimeGID: uint32(os.Getgid()),
	}
	executor, err := NewPiExecutor(config)
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
		SchemaVersion: TaskSchemaV2, Recipe: RecipeEphemeralPiTask,
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
		ModelBaseURL:             "https://api.deepseek.com",
		MaxOutputTokens:          777,
		ModelContextWindow:       65536,
		MaxOutputBytes:           MaxResultBytes,
	}
	endpointDigest := sha256.Sum256([]byte(task.ModelBaseURL))
	task.ModelEndpointSHA256 = hex.EncodeToString(endpointDigest[:])
	task.ModelEndpointBindingSHA256 = strings.Repeat("e", 64)
	if mode != WorkspaceNone {
		task.WorkspaceSHA256 = task.InputManifestSHA256
	}
	return task
}

func validModelGrant(task Task) ModelGrant {
	return ModelGrant{
		GrantID:               "44444444-4444-4444-8444-444444444444",
		BearerToken:           []byte("cwmg1_abcdefghijklmnopqrstuvwxyzABCDEFGH"),
		ModelBindingSHA256:    task.ModelBindingSHA256,
		AudienceSHA256:        task.ModelGrantAudienceSHA256,
		ExpiresAtUnix:         time.Now().UTC().Add(10 * time.Minute).Unix(),
		LimitSHA256:           task.ModelGrantLimitSHA256,
		BaseURL:               task.ModelBaseURL,
		EndpointBindingSHA256: task.ModelEndpointBindingSHA256,
		MaxOutputTokens:       task.MaxOutputTokens,
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
