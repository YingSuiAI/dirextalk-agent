package coreteamruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
)

func TestPiRunnerUsesQualifiedReleaseAndReturnsOnlyStructuredResult(t *testing.T) {
	t.Parallel()

	assignment := validRuntimeAssignment()
	credential := []byte("scoped-test-credential-1234567890")
	process := &fakeProcessRunner{stdout: validPiEventStream()}
	runner := newTestPiRunner(t, process)
	workspaceRoot := filepath.Join(runner.workspaceRoot, "workspace")
	if err := os.Mkdir(workspaceRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	result, failure, err := runner.Run(t.Context(), assignment, Workspace{
		Directory:   workspaceRoot,
		ContextJSON: []byte(`{"scope":"approved"}`),
		Credential:  credential,
	})
	if err != nil || failure.Valid() {
		t.Fatalf("run error=%v failure=%+v", err, failure)
	}
	if result.Status != "completed" || result.Summary != "Implemented the approved change." ||
		result.Usage.InputTokens != 140 || result.Usage.CachedInputTokens != 20 ||
		result.Usage.OutputTokens != 24 || result.Usage.ReasoningOutputTokens != 6 {
		t.Fatalf("result = %+v", result)
	}
	if process.calls != 1 || process.spec.Executable != runner.executablePath ||
		process.spec.Directory != workspaceRoot || process.spec.Timeout != runner.timeout {
		t.Fatalf("process spec = %+v", process.spec)
	}
	arguments := strings.Join(process.spec.Arguments, "\n")
	if strings.Contains(arguments, assignment.Worker.Goal) || strings.Contains(arguments, string(credential)) ||
		argumentValue(process.spec.Arguments, "--mode") != "json" ||
		argumentValue(process.spec.Arguments, "--provider") != assignment.Model.Provider ||
		argumentValue(process.spec.Arguments, "--model") != assignment.Model.Name ||
		argumentValue(process.spec.Arguments, "--extension") != runner.extensionPath ||
		!strings.Contains(argumentValue(process.spec.Arguments, "--tools"), piResultToolName) {
		t.Fatalf("unsafe or incomplete Pi arguments: %v", process.spec.Arguments)
	}
	if !bytes.Contains(process.spec.Stdin, []byte(assignment.Worker.Goal)) ||
		!bytes.Contains(process.spec.Stdin, []byte(`{"scope":"approved"}`)) ||
		bytes.Contains(process.spec.Stdin, credential) {
		t.Fatalf("Pi stdin = %q", process.spec.Stdin)
	}
	if got := process.spec.SecretEnvironment["DEEPSEEK_API_KEY"]; !bytes.Equal(got, credential) {
		t.Fatal("model credential was not isolated in the secret channel")
	}
	if len(process.spec.SecretEnvironment) != 1 || process.modelsMode != piConfigFileMode || process.modelsMaxTokens != assignment.Worker.OutputTokens {
		t.Fatalf("model override mode=%#o max_tokens=%d", process.modelsMode, process.modelsMaxTokens)
	}
	if process.spec.Environment["GIT_CONFIG_COUNT"] != "1" ||
		process.spec.Environment["GIT_CONFIG_KEY_0"] != "safe.directory" ||
		process.spec.Environment["GIT_CONFIG_VALUE_0"] != workspaceRoot {
		t.Fatalf("Git workspace boundary = %+v", process.spec.Environment)
	}
	for _, value := range process.spec.Environment {
		if strings.Contains(value, string(credential)) {
			t.Fatal("credential entered ordinary process environment")
		}
	}
	if process.spec.Sandbox == nil || process.spec.Sandbox.MinimumLandlockABI != 2 ||
		!sandboxGrants(process.spec.Sandbox, runner.runtimeRoot, SandboxReadExecute) ||
		!sandboxGrants(process.spec.Sandbox, process.spec.Directory, SandboxReadWriteExecute) ||
		!strings.HasPrefix(process.spec.Environment["TMPDIR"], runner.stateRoot+string(filepath.Separator)) {
		t.Fatalf("Pi sandbox = %+v environment=%+v", process.spec.Sandbox, process.spec.Environment)
	}
}

func TestPiRunnerDoesNotExposeToolchainWithoutShellCapability(t *testing.T) {
	process := &fakeProcessRunner{stdout: validPiEventStream()}
	runner := newTestPiRunner(t, process)
	assignment := validRuntimeAssignment()
	assignment.Worker.Capabilities = []coreteam.Capability{
		coreteam.CapabilityRepositoryWrite,
		coreteam.CapabilityStructuredResult,
	}
	workspace := filepath.Join(runner.workspaceRoot, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}

	_, failure, err := runner.Run(t.Context(), assignment, Workspace{
		Directory: workspace, ContextJSON: []byte(`{}`), Credential: []byte("scoped-test-credential-1234567890"),
	})
	if err != nil || failure.Valid() {
		t.Fatalf("run error=%v failure=%+v", err, failure)
	}
	if process.spec.Sandbox == nil || sandboxGrants(process.spec.Sandbox, "/usr/bin", SandboxReadExecute) ||
		!sandboxGrants(process.spec.Sandbox, workspace, SandboxReadWrite) {
		t.Fatalf("capability sandbox = %+v", process.spec.Sandbox)
	}
	for _, path := range process.spec.Sandbox.Paths {
		if path.Path == "/run" || strings.Contains(path.Path, "receipts") || strings.Contains(path.Path, "credentials") {
			t.Fatalf("control path entered Pi sandbox: %+v", path)
		}
	}
}

func TestPiRunnerWorkspaceWriteAccessRequiresRepositoryWriteCapability(t *testing.T) {
	for name, test := range map[string]struct {
		capabilities []coreteam.Capability
		access       SandboxAccess
	}{
		"read only": {
			capabilities: []coreteam.Capability{coreteam.CapabilityRepositoryRead, coreteam.CapabilityCodeReview, coreteam.CapabilityStructuredResult},
			access:       SandboxReadOnly,
		},
		"read shell": {
			capabilities: []coreteam.Capability{coreteam.CapabilityRepositoryRead, coreteam.CapabilityShell, coreteam.CapabilityStructuredResult},
			access:       SandboxReadExecute,
		},
		"write": {
			capabilities: []coreteam.Capability{coreteam.CapabilityRepositoryWrite, coreteam.CapabilityStructuredResult},
			access:       SandboxReadWrite,
		},
		"write shell": {
			capabilities: []coreteam.Capability{coreteam.CapabilityRepositoryWrite, coreteam.CapabilityShell, coreteam.CapabilityStructuredResult},
			access:       SandboxReadWriteExecute,
		},
	} {
		t.Run(name, func(t *testing.T) {
			process := &fakeProcessRunner{stdout: validPiEventStream()}
			runner := newTestPiRunner(t, process)
			workspace := filepath.Join(runner.workspaceRoot, "workspace")
			if err := os.Mkdir(workspace, 0o700); err != nil {
				t.Fatal(err)
			}
			assignment := validRuntimeAssignment()
			assignment.Worker.Capabilities = test.capabilities
			_, failure, err := runner.Run(t.Context(), assignment, Workspace{
				Directory: workspace, ContextJSON: []byte(`{}`), Credential: []byte("scoped-test-credential-1234567890"),
			})
			if err != nil || failure.Valid() {
				t.Fatalf("run error=%v failure=%+v", err, failure)
			}
			if !sandboxGrants(process.spec.Sandbox, workspace, test.access) {
				t.Fatalf("workspace access=%+v want=%v", process.spec.Sandbox.Paths, test.access)
			}
		})
	}
}

func TestPiSandboxKeepsProcSelfBoundToLauncherProcess(t *testing.T) {
	process := &fakeProcessRunner{stdout: validPiEventStream()}
	runner := newTestPiRunner(t, process)
	_, failure, err := runner.Run(t.Context(), validRuntimeAssignment(), Workspace{
		ContextJSON: []byte(`{}`), Credential: []byte("scoped-test-credential-1234567890"),
	})
	if err != nil || failure.Valid() {
		t.Fatalf("run error=%v failure=%+v", err, failure)
	}
	if !sandboxGrants(process.spec.Sandbox, "/proc/self", SandboxReadOnly) {
		t.Fatalf("sandbox resolved /proc/self outside launcher: %+v", process.spec.Sandbox)
	}
}

func sandboxGrants(policy *SandboxPolicy, path string, access SandboxAccess) bool {
	if policy == nil {
		return false
	}
	for _, candidate := range policy.Paths {
		if candidate.Path == path && candidate.Access == access {
			return true
		}
	}
	return false
}

func TestPiRunnerCreatesAndRemovesEmptyWorkspace(t *testing.T) {
	t.Parallel()
	process := &fakeProcessRunner{stdout: validPiEventStream()}
	runner := newTestPiRunner(t, process)

	_, failure, err := runner.Run(t.Context(), validRuntimeAssignment(), Workspace{
		ContextJSON: []byte(`{}`), Credential: []byte("scoped-test-credential-1234567890"),
	})
	if err != nil || failure.Valid() {
		t.Fatalf("run error=%v failure=%+v", err, failure)
	}
	if process.spec.Directory == "" || process.directoryMode != piDirectoryMode {
		t.Fatalf("workspace=%q mode=%#o", process.spec.Directory, process.directoryMode)
	}
	if _, err := os.Stat(process.spec.Directory); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary workspace survived: %v", err)
	}
}

func TestPiRunnerRejectsWorkspaceWithSymlinkedParent(t *testing.T) {
	process := &fakeProcessRunner{stdout: validPiEventStream()}
	runner := newTestPiRunner(t, process)
	realRoot := t.TempDir()
	workspace := filepath.Join(realRoot, "workspace")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	linkRoot := filepath.Join(runner.workspaceRoot, "linked")
	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	_, _, err := runner.Run(t.Context(), validRuntimeAssignment(), Workspace{
		Directory: filepath.Join(linkRoot, "workspace"), ContextJSON: []byte(`{}`),
		Credential: []byte("scoped-test-credential-1234567890"),
	})
	if !errors.Is(err, ErrInvalid) || process.calls != 0 {
		t.Fatalf("symlinked workspace err=%v process calls=%d", err, process.calls)
	}
}

func TestPiRunnerRejectsUnsupportedOrMissingCapabilityToolsBeforeProcess(t *testing.T) {
	for _, capability := range []coreteam.Capability{
		coreteam.CapabilityWebResearch,
		coreteam.CapabilityBrowser,
		coreteam.CapabilityMCPClient,
	} {
		t.Run(string(capability), func(t *testing.T) {
			process := &fakeProcessRunner{stdout: validPiEventStream()}
			runner := newTestPiRunner(t, process)
			assignment := validRuntimeAssignment()
			assignment.Worker.Capabilities = append(assignment.Worker.Capabilities, capability)
			_, _, err := runner.Run(t.Context(), assignment, Workspace{ContextJSON: []byte(`{}`), Credential: []byte("scoped-test-credential-1234567890")})
			if !errors.Is(err, ErrInvalid) || process.calls != 0 {
				t.Fatalf("capability=%q err=%v process calls=%d", capability, err, process.calls)
			}
		})
	}

	for _, capability := range []coreteam.Capability{coreteam.CapabilityShell, coreteam.CapabilityTest, coreteam.CapabilityGit} {
		t.Run("missing "+string(capability), func(t *testing.T) {
			process := &fakeProcessRunner{stdout: validPiEventStream()}
			runner := newTestPiRunner(t, process)
			runner.searchPath = t.TempDir()
			assignment := validRuntimeAssignment()
			assignment.Worker.Capabilities = []coreteam.Capability{capability, coreteam.CapabilityStructuredResult}
			_, _, err := runner.Run(t.Context(), assignment, Workspace{ContextJSON: []byte(`{}`), Credential: []byte("scoped-test-credential-1234567890")})
			if !errors.Is(err, ErrUnavailable) || process.calls != 0 {
				t.Fatalf("capability=%q err=%v process calls=%d", capability, err, process.calls)
			}
		})
	}
}

func TestPiToolsMapTestAndGitToShell(t *testing.T) {
	for _, capability := range []coreteam.Capability{coreteam.CapabilityShell, coreteam.CapabilityTest, coreteam.CapabilityGit} {
		tools := strings.Split(piTools([]coreteam.Capability{capability, coreteam.CapabilityStructuredResult}), ",")
		if !slices.Contains(tools, "bash") {
			t.Fatalf("capability %q did not enable bash: %v", capability, tools)
		}
	}
	combined := strings.Split(piTools([]coreteam.Capability{
		coreteam.CapabilityShell, coreteam.CapabilityTest, coreteam.CapabilityGit, coreteam.CapabilityStructuredResult,
	}), ",")
	if count := countValue(combined, "bash"); count != 1 {
		t.Fatalf("combined capabilities emitted bash %d times: %v", count, combined)
	}
}

func countValue(values []string, target string) int {
	count := 0
	for _, value := range values {
		if value == target {
			count++
		}
	}
	return count
}

func TestParsePiEventsRequiresOneSettledFinal(t *testing.T) {
	t.Parallel()
	valid := validPiEventStream()
	duplicateFinal := bytes.Replace(valid, []byte(`{"type":"agent_end"`), append(
		[]byte(`{"type":"tool_execution_end","toolName":"dirextalk_submit_result","result":{"details":{"status":"completed","summary":"Duplicate.","deliverables":[],"tests":[],"risks":[]},"terminate":true},"isError":false}`+"\n"),
		[]byte(`{"type":"agent_end"`)...,
	), 1)
	beforeSession := append([]byte(`{"type":"entry_appended"}`+"\n"), valid...)
	afterAgentEnd := bytes.Replace(valid, []byte(`{"type":"agent_settled"}`), []byte(`{"type":"entry_appended"}`+"\n"+`{"type":"agent_settled"}`), 1)
	for name, test := range map[string]struct {
		stream []byte
		code   FailureCode
	}{
		"empty":               {nil, FailurePiEventInvalid},
		"invalid json":        {[]byte("not-json\n"), FailurePiEventInvalid},
		"missing final":       {withoutLineContaining(valid, `"toolName":"dirextalk_submit_result"`), FailurePiFinalMissing},
		"retrying":            {bytes.Replace(valid, []byte(`"willRetry":false`), []byte(`"willRetry":true`), 1), FailurePiEventInvalid},
		"after settled":       {append(bytes.Clone(valid), []byte(`{"type":"turn_end"}`+"\n")...), FailurePiEventInvalid},
		"duplicate final":     {duplicateFinal, FailurePiEventInvalid},
		"before session":      {beforeSession, FailurePiEventInvalid},
		"after agent end":     {afterAgentEnd, FailurePiEventInvalid},
		"null lists":          {bytes.Replace(valid, []byte(`"deliverables":["source patch"]`), []byte(`"deliverables":null`), 1), FailurePiEventInvalid},
		"unknown final field": {bytes.Replace(valid, []byte(`"risks":[]`), []byte(`"risks":[],"reasoning":"raw"`), 1), FailurePiEventInvalid},
		"secret final":        {bytes.Replace(valid, []byte(`Implemented the approved change.`), []byte(`api_key=super-secret-provider-value`), 1), FailurePiEventInvalid},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, failure := parsePiEvents(test.stream)
			if !failure.Valid() || failure.Stage != FailurePi || failure.Code != test.code {
				t.Fatalf("failure = %+v", failure)
			}
		})
	}
}

func TestParsePiEventsClassifiesProviderFailuresWithoutRawText(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		raw  string
		code FailureCode
	}{
		"authentication": {"401 invalid API key sk-abcdefghijklmnopqrstuvwxyz", FailureProviderAuthentication},
		"quota":          {"402 insufficient_balance", FailureProviderQuota},
		"rate":           {"429 rate_limit", FailureProviderRateLimit},
		"request":        {"400 invalid_request", FailureProviderRequest},
		"server":         {"503 service unavailable", FailureProviderServer},
		"network":        {"fetch failed: network connection", FailureProviderNetwork},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			stream := providerFailureEventStream(test.raw)
			_, failure := parsePiEvents(stream)
			if failure.Code != test.code || failure.Stage != FailurePi || strings.Contains(failure.Error(), test.raw) || strings.Contains(failure.Error(), "sk-") {
				t.Fatalf("failure = %+v text=%q", failure, failure.Error())
			}
		})
	}
}

func TestOSProcessRunnerReturnsClosedFailuresAndDestroysOutput(t *testing.T) {
	if testing.Short() {
		t.Skip("process integration")
	}
	t.Parallel()
	runner := OSProcessRunner{}
	root := t.TempDir()

	for name, test := range map[string]struct {
		arguments []string
		timeout   time.Duration
		max       int
		code      FailureCode
	}{
		"nonzero": {[]string{"-c", "printf 'provider secret' >&2; exit 7"}, time.Second, 1024, FailureProcessExitNonZero},
		"timeout": {[]string{"-c", "sleep 2"}, 20 * time.Millisecond, 1024, FailureProcessTimeout},
		"output":  {[]string{"-c", "head -c 4096 /dev/zero"}, time.Second, 128, FailureProcessOutputLimit},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			output, failure, err := runner.Run(t.Context(), ProcessSpec{
				Executable: "/bin/sh", Arguments: test.arguments, Directory: root,
				Environment: map[string]string{"PATH": "/usr/bin:/bin"}, Stdin: []byte{},
				MaxStdoutBytes: test.max, MaxStderrBytes: test.max, Timeout: test.timeout,
			})
			if err != nil || failure.Stage != FailureProcess || failure.Code != test.code || len(output) != 0 || strings.Contains(failure.Error(), "provider secret") {
				t.Fatalf("output=%q failure=%+v err=%v", output, failure, err)
			}
		})
	}
}

func TestSandboxCommandNeverExecutesPiDirectly(t *testing.T) {
	spec := ProcessSpec{
		Executable:        "/opt/dirextalk-worker/runtimes/pi/bin/pi",
		Arguments:         []string{"--mode", "json"},
		Directory:         "/var/lib/dirextalk-worker/workspaces/role",
		Environment:       map[string]string{"PATH": "/usr/bin:/bin"},
		SecretEnvironment: map[string][]byte{"DEEPSEEK_API_KEY": []byte("scoped-test-credential-1234567890")},
		Stdin:             []byte("approved prompt"), MaxStdoutBytes: 1024, MaxStderrBytes: 1024, Timeout: time.Second,
		Sandbox: &SandboxPolicy{
			LauncherPath: "/usr/local/bin/dirextalk-pi-sandbox", MinimumLandlockABI: 2,
			Paths: []SandboxPath{
				{Path: "/workspace", Access: SandboxReadWriteExecute},
				{Path: "/opt/dirextalk-worker/runtimes/pi", Access: SandboxReadExecute},
			},
		},
	}
	executable, arguments, err := processCommand(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--landlock-abi", "2",
		"--rx", "/opt/dirextalk-worker/runtimes/pi",
		"--rwx", "/workspace",
		"--", "/opt/dirextalk-worker/runtimes/pi/bin/pi", "--mode", "json",
	}
	if executable != spec.Sandbox.LauncherPath || !slices.Equal(arguments, want) ||
		strings.Contains(strings.Join(arguments, "\x00"), "scoped-test-credential") {
		t.Fatalf("executable=%q arguments=%q", executable, arguments)
	}
}

type fakeProcessRunner struct {
	stdout          []byte
	failure         ClosedFailure
	err             error
	calls           int
	spec            ProcessSpec
	modelsMode      os.FileMode
	modelsMaxTokens uint32
	directoryMode   os.FileMode
}

func (f *fakeProcessRunner) Run(_ context.Context, spec ProcessSpec) ([]byte, ClosedFailure, error) {
	f.calls++
	f.spec = spec.clone()
	state, err := os.Stat(spec.Directory)
	if err == nil {
		f.directoryMode = state.Mode().Perm()
	}
	configPath := filepath.Join(spec.Environment["PI_CODING_AGENT_DIR"], "models.json")
	if state, statErr := os.Stat(configPath); statErr == nil {
		f.modelsMode = state.Mode().Perm()
		var config struct {
			Providers map[string]struct {
				ModelOverrides map[string]struct {
					MaxTokens uint32 `json:"maxTokens"`
				} `json:"modelOverrides"`
			} `json:"providers"`
		}
		content, readErr := os.ReadFile(configPath)
		if readErr == nil && json.Unmarshal(content, &config) == nil {
			provider := config.Providers[argumentValue(spec.Arguments, "--provider")]
			f.modelsMaxTokens = provider.ModelOverrides[argumentValue(spec.Arguments, "--model")].MaxTokens
		}
	}
	return bytes.Clone(f.stdout), f.failure, f.err
}

func validRuntimeAssignment() Assignment {
	return Assignment{
		Worker: coreteamworker.Assignment{
			WorkerID: "11111111-1111-4111-8111-111111111111", ExecutionID: "22222222-2222-4222-8222-222222222222",
			PlanID: "33333333-3333-4333-8333-333333333333", RoleID: "implementer", Attempt: 1,
			PlanDigest: strings.Repeat("a", 64), Goal: "Implement the approved change.",
			RuntimeContextDigest: strings.Repeat("b", 64),
			Capabilities:         []coreteam.Capability{coreteam.CapabilityRepositoryWrite, coreteam.CapabilityTest, coreteam.CapabilityStructuredResult},
			RuntimeID:            coreteam.OfficialRuntimeID, OutputTokens: 4096, ResultSchemaVersion: coreteamworker.ResultSchemaVersion,
		},
		Model: ModelBinding{Provider: "deepseek", Name: "deepseek-v4-pro", Interface: "openai_compatible"},
	}
}

func newTestPiRunner(t *testing.T, process ProcessRunner) *PiRunner {
	t.Helper()
	root, err := os.MkdirTemp("", "dirextalk-pi-runner-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := preparePiDirectory(root); err != nil {
		t.Fatal(err)
	}
	runtimeRoot := filepath.Join(root, "runtime")
	stateRoot := filepath.Join(root, "state")
	workspaceRoot := filepath.Join(root, "workspaces")
	launcher := filepath.Join(root, "dirextalk-pi-sandbox")
	if err := os.MkdirAll(filepath.Join(runtimeRoot, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(runtimeRoot, "extensions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(workspaceRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(runtimeRoot, "bin", "pi")
	extension := filepath.Join(runtimeRoot, "extensions", "dirextalk-result.ts")
	if err := os.WriteFile(executable, []byte("qualified-pi-binary"), 0o500); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(extension, []byte("qualified-result-extension"), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("qualified-sandbox-launcher"), 0o500); err != nil {
		t.Fatal(err)
	}
	runner, err := NewPiRunner(PiConfig{
		ExecutablePath: executable, ExecutableSHA256: fileDigest(t, executable),
		ExtensionPath: extension, ExtensionSHA256: fileDigest(t, extension),
		SandboxLauncherPath: launcher,
		StateRoot:           stateRoot, WorkspaceRoot: workspaceRoot,
		SearchPath: "/usr/bin:/bin", Timeout: time.Second, Processes: process,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func validPiEventStream() []byte {
	return []byte(
		`{"type":"session","version":3}` + "\n" +
			`{"type":"agent_start"}` + "\n" +
			`{"type":"message_end","message":{"role":"assistant","usage":{"input":100,"output":16,"cacheRead":20,"cacheWrite":20,"reasoning":4},"stopReason":"toolUse"}}` + "\n" +
			`{"type":"tool_execution_end","toolName":"dirextalk_submit_result","result":{"details":{"status":"completed","summary":"Implemented the approved change.","deliverables":["source patch"],"tests":["go test ./..."],"risks":[]},"terminate":true},"isError":false}` + "\n" +
			`{"type":"message_end","message":{"role":"assistant","usage":{"input":0,"output":8,"cacheRead":0,"cacheWrite":0,"reasoning":2},"stopReason":"stop"}}` + "\n" +
			`{"type":"agent_end","willRetry":false}` + "\n" +
			`{"type":"agent_settled"}` + "\n",
	)
}

func providerFailureEventStream(message string) []byte {
	encoded, _ := json.Marshal(message)
	return []byte(`{"type":"session","version":3}` + "\n" + `{"type":"agent_start"}` + "\n" +
		`{"type":"message_end","message":{"role":"assistant","usage":{},"stopReason":"error","errorMessage":` + string(encoded) + `}}` + "\n")
}

func argumentValue(arguments []string, name string) string {
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	return ""
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return digestBytes(content)
}

func withoutLineContaining(input []byte, needle string) []byte {
	lines := bytes.Split(input, []byte("\n"))
	filtered := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if !bytes.Contains(line, []byte(needle)) {
			filtered = append(filtered, line)
		}
	}
	return bytes.Join(filtered, []byte("\n"))
}
