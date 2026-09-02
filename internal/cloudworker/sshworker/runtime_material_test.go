package sshworker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/workerimage"
)

func TestCompileRuntimePinsMaintainedPiAndKeepsSecretOutOfPayload(t *testing.T) {
	secret := "model-secret-that-must-not-be-rendered"
	material, err := CompileRuntime(RuntimeRequest{
		TaskID:            "task-001",
		Objective:         "Deploy the repository and report actual server load.",
		Architecture:      "x86_64",
		Workload:          WorkloadJob,
		MaxRuntimeSeconds: 3600,
		Model: RuntimeModel{
			Provider: "openai_compatible", BaseURL: "https://models.example/v1",
			Name: "test-model", APIKey: secret, MaxOutputTokens: 16_384,
		},
		ImageFlavor: string(workerimage.FlavorCPU), EnableSubagent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	script := string(material.WorkerScript)
	for _, expected := range []string{
		"/opt/dirextalk-worker/bin/pi",
		"/opt/dirextalk-worker/manifest.json",
		`.image_version | test("^[0-9]+\\.[0-9]+\\.[0-9]+$")`,
		`(.pi_version == "0.84.4" or .pi_version == "0.84.1")`,
		`test "$("$pi_bin" --version)" = "$manifest_pi_version"`,
		`.tool_baseline == "1"`,
		"readonly worker_root=/var/lib/dirextalk-worker",
		`test ! -L "$worker_root"`,
		"python3 -m pip --version",
		"python3 -m venv --help",
		"command -v node",
		"command -v gh",
		"command -v go",
		"command -v rg",
		`readonly task_root="$worker_root/tasks/task-001"`,
		`dirextalk-worker-runner`,
		`server-status`,
		`artifact_root="$worker_root/artifacts"`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("script does not contain %q", expected)
		}
	}
	for _, forbidden := range []string{"apt-get", "releases/download/", "pi.tar.gz"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("task bootstrap still contains image-owned setup %q", forbidden)
		}
	}
	if strings.Contains(script, "/tmp/dirextalk-worker") || strings.Contains(remoteRunnerSource, "/tmp/dirextalk-worker") {
		t.Fatal("Worker runtime state still uses the reboot-volatile /tmp root")
	}
	if strings.Contains(script, "dnf") {
		t.Fatal("bootstrap contains the retired dnf package path")
	}
	if strings.Contains(script, "deployment flow") || strings.Contains(script, "actual server load") {
		t.Fatal("generic job prompt retained task-specific reporting requirements")
	}
	if strings.Contains(script, secret) || strings.Contains(script, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatal("model credential leaked into worker script")
	}
	start, err := material.Protocol.Start()
	if err != nil || !strings.Contains(start.Shell, "start") {
		t.Fatalf("start command: %#v, %v", start, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(start.Stdin)))
	if err != nil || !strings.Contains(string(decoded), `"version":1`) || !strings.Contains(string(decoded), secret) {
		t.Fatalf("secret stdin did not round trip: %q, %v", decoded, err)
	}
	digest := sha256.Sum256(material.WorkerScript)
	if material.WorkerScriptSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("worker script digest mismatch")
	}
}

func TestCompileRuntimeOmitsUnsetModelOutputLimit(t *testing.T) {
	material, err := CompileRuntime(RuntimeRequest{
		TaskID: "task-default-limit", Objective: "deploy the service", Architecture: "x86_64", Workload: WorkloadJob, MaxRuntimeSeconds: 3600,
		Model: RuntimeModel{Provider: "openai_compatible", BaseURL: "https://openrouter.ai/api/v1",
			Name: "deepseek/deepseek-v4-flash", APIKey: "secret"},
		ImageFlavor: string(workerimage.FlavorCPU), EnableSubagent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	config := `{"providers":{"dirextalk-worker":{"api":"openai-completions","apiKey":"$DIREXTALK_MODEL_API_KEY","baseUrl":"https://openrouter.ai/api/v1","models":[{"id":"deepseek/deepseek-v4-flash","reasoning":true}]}}}`
	encoded := base64.StdEncoding.EncodeToString([]byte(config))
	if !strings.Contains(string(material.WorkerScript), shellQuote(encoded)+` | base64 --decode > "$config_root/models.json"`) {
		t.Fatal("compiled models.json did not preserve Pi's unset-limit contract")
	}
}

func TestCompileRuntimeTreatsObjectiveAsData(t *testing.T) {
	objective := `deploy $(touch /tmp/not-executed) ; echo "done" && report`
	material, err := CompileRuntime(RuntimeRequest{
		TaskID: "task-002", Objective: objective, Architecture: "x86_64", Workload: WorkloadService, MaxRuntimeSeconds: 3600,
		Service: &RuntimeServiceSpec{WorkloadID: "memory-api", Port: 8080, HealthPath: "/health", Hostname: "api.example.test"},
		Model: RuntimeModel{Provider: "anthropic", BaseURL: "https://api.anthropic.com",
			Name: "claude-test", APIKey: "secret", MaxOutputTokens: 4096},
		ImageFlavor: string(workerimage.FlavorCPU), EnableSubagent: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	script := string(material.WorkerScript)
	if strings.Contains(script, objective) {
		t.Fatal("natural-language objective was embedded as shell source")
	}
	if !strings.Contains(script, base64.StdEncoding.EncodeToString([]byte(objective))) {
		t.Fatal("encoded objective is missing")
	}
	for _, required := range []string{" caddy", "# Managed by Dirextalk Agent", "refusing to replace an unmanaged Caddyfile"} {
		if !strings.Contains(script, required) {
			t.Fatalf("hostname runtime missing %q", required)
		}
	}
	for _, required := range []string{"after a host reboot", "systemd service or a restart-enabled container", "never use shell backgrounding (&), nohup, or disown", "listen only on 127.0.0.1", "lightweight persistent local HTTP service", "reserves ports 80 and 443", "disable its default port-80 site", "Do not install, configure, edit, or restart Caddy", `tls {\n\t\ton_demand`, "reverse_proxy 127.0.0.1:%d", "Caddy reload timed out"} {
		if !strings.Contains(remoteRunnerSource, required) {
			t.Fatalf("embedded hostname runtime missing %q", required)
		}
	}
	path := filepath.Join(t.TempDir(), "worker.sh")
	if err := os.WriteFile(path, material.WorkerScript, 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bash", "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("compiled bash is invalid: %v: %s", err, output)
	}
}

func TestCompileRuntimeRejectsIncompleteOrUnsupportedInputs(t *testing.T) {
	valid := RuntimeRequest{TaskID: "task-003", Objective: "work", Architecture: "amd64", Workload: WorkloadJob, MaxRuntimeSeconds: 3600, ImageFlavor: string(workerimage.FlavorCPU), EnableSubagent: true, Model: RuntimeModel{
		Provider: "gemini", BaseURL: "https://generativelanguage.googleapis.com/v1beta",
		Name: "gemini-test", APIKey: "secret", MaxOutputTokens: 4096,
	}}
	cases := []RuntimeRequest{
		{},
		{TaskID: valid.TaskID, Objective: valid.Objective, Architecture: "riscv64", Workload: valid.Workload, Model: valid.Model},
		{TaskID: valid.TaskID, Objective: valid.Objective, Architecture: valid.Architecture, Workload: valid.Workload, Model: RuntimeModel{
			Provider: "unknown", BaseURL: valid.Model.BaseURL, Name: valid.Model.Name,
			APIKey: valid.Model.APIKey, MaxOutputTokens: valid.Model.MaxOutputTokens,
		}},
		{TaskID: valid.TaskID, Objective: valid.Objective, Architecture: valid.Architecture, Workload: valid.Workload, Model: RuntimeModel{
			Provider: valid.Model.Provider, BaseURL: "http://models.example", Name: valid.Model.Name,
			APIKey: valid.Model.APIKey, MaxOutputTokens: valid.Model.MaxOutputTokens,
		}},
	}
	for index, request := range cases {
		if material, err := CompileRuntime(request); err == nil || !bytes.Equal(material.WorkerScript, nil) {
			t.Fatalf("case %d accepted invalid input", index)
		}
	}
}

func TestRuntimeProtocolCompilesResumableCommands(t *testing.T) {
	material, err := CompileRuntime(RuntimeRequest{
		TaskID: "task-004", Objective: "run a service", Architecture: "x86_64", Workload: WorkloadService, MaxRuntimeSeconds: 3600, ImageFlavor: string(workerimage.FlavorCPU), EnableSubagent: true,
		Service: &RuntimeServiceSpec{WorkloadID: "web", Port: 8080, HealthPath: "/health"},
		Model:   RuntimeModel{Provider: "anthropic", BaseURL: "https://api.anthropic.com", Name: "claude", APIKey: "secret", MaxOutputTokens: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _ := material.Protocol.Status()
	stop, _ := material.Protocol.Stop()
	logCommand, _ := material.Protocol.Log(512)
	list, _ := material.Protocol.Artifact("")
	download, _ := material.Protocol.Artifact("reports/load.html")
	server, _ := material.Protocol.ServerStatus()
	service, _ := material.Protocol.ServiceStatus()
	for name, command := range map[string]RuntimeCommand{"status": status, "stop": stop, "log": logCommand, "list": list, "download": download, "server": server, "service": service} {
		if command.Shell == "" || len(command.Stdin) != 0 {
			t.Fatalf("%s command is invalid: %#v", name, command)
		}
	}
	if !strings.Contains(stop.Shell, "'stop'") || !strings.Contains(logCommand.Shell, "'512'") || !strings.Contains(download.Shell, "'reports/load.html'") || !strings.Contains(server.Shell, "'server-status'") || !strings.Contains(service.Shell, "'service-status'") {
		t.Fatalf("unexpected protocol commands: %#v %#v %#v", logCommand, download, server)
	}
	if _, err := material.Protocol.Log(-1); err == nil {
		t.Fatal("negative log offset accepted")
	}
	if _, err := material.Protocol.Artifact("../secret"); err == nil {
		t.Fatal("escaping artifact accepted")
	}
}

func TestEmbeddedRemoteRunnerBuilds(t *testing.T) {
	directory := t.TempDir()
	root := filepath.Join(directory, "worker")
	source := filepath.Join(directory, "runner.go")
	body := strings.Replace(remoteRunnerSource, `const root = "/var/lib/dirextalk-worker"`, `const root = `+strconv.Quote(root), 1)
	body = strings.Replace(body, `"/opt/dirextalk-worker/bin/pi"`, `filepath.Join(root, "runtime", "pi")`, 1)
	if err := os.WriteFile(source, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := filepath.Join(directory, "runner")
	command := exec.Command("go", "build", "-o", runner, source)
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("embedded runner does not build: %v: %s", err, output)
	}

	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/health" {
			http.NotFound(response, request)
			return
		}
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	_, rawPort, err := net.SplitHostPort(strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatal(err)
	}
	taskID := "service-health"
	taskRoot := filepath.Join(root, "tasks", taskID)
	if err = os.MkdirAll(taskRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(remoteTaskSpec{TaskID: taskID, Workload: WorkloadService, Model: "test", MaxRuntimeSeconds: 3600,
		Service: &RuntimeServiceSpec{WorkloadID: "web", Port: uint16(port), HealthPath: "/health"}})
	if err = os.WriteFile(filepath.Join(taskRoot, "spec.json"), spec, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(runner, "status", taskID).CombinedOutput()
	if err != nil {
		t.Fatalf("not-started status failed: %v: %s", err, output)
	}
	var taskStatus remoteRuntimeStatus
	if json.Unmarshal(output, &taskStatus) != nil || taskStatus.Phase != "not_started" {
		t.Fatalf("not-started status=%s", output)
	}
	output, err = exec.Command(runner, "service-status", taskID).CombinedOutput()
	if err != nil {
		t.Fatalf("service status without duplicate contract failed: %v: %s", err, output)
	}
	var status struct {
		Health string `json:"health"`
		Phase  string `json:"phase"`
	}
	if json.Unmarshal(output, &status) != nil || status.Health != "healthy" || status.Phase != "running" {
		t.Fatalf("service status=%s", output)
	}
	if _, err = os.Stat(filepath.Join(taskRoot, "service.json")); !os.IsNotExist(err) {
		t.Fatalf("duplicate service contract was required or created: %v", err)
	}

	cleanupID := "github-cleanup"
	cleanupRoot := filepath.Join(root, "tasks", cleanupID)
	cleanupFiles := []string{
		filepath.Join(cleanupRoot, "github-pat"),
		filepath.Join(cleanupRoot, "gitconfig"),
		filepath.Join(cleanupRoot, "github-bin", "git-credential-github"),
		filepath.Join(cleanupRoot, "github-bin", "gh"),
	}
	for _, path := range cleanupFiles {
		if err = os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, []byte("sentinel"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if output, err = exec.Command(runner, "stop", cleanupID).CombinedOutput(); err != nil {
		t.Fatalf("cleanup not-started GitHub runtime: %v: %s", err, output)
	}
	for _, path := range cleanupFiles {
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Fatalf("GitHub runtime path survived cleanup: %s: %v", path, statErr)
		}
	}

	jobID := "job-timeout"
	jobRoot := filepath.Join(root, "tasks", jobID)
	if err = os.MkdirAll(filepath.Join(jobRoot, "workspace"), 0o700); err != nil {
		t.Fatal(err)
	}
	jobSpec, _ := json.Marshal(remoteTaskSpec{TaskID: jobID, Workload: WorkloadJob, Model: "test", MaxRuntimeSeconds: 1})
	for name, body := range map[string][]byte{"spec.json": jobSpec, "objective.txt": []byte("wait")} {
		if err = os.WriteFile(filepath.Join(jobRoot, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runtimeRoot := filepath.Join(root, "runtime")
	if err = os.MkdirAll(runtimeRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	escaped := filepath.Join(root, "escaped-after-timeout")
	piScript := "#!/bin/sh\nprintf 'internal worker report\\n'\nsetsid sh -c 'sleep 2; touch " + escaped + "' >/dev/null 2>&1 &\nsleep 5\n"
	if err = os.WriteFile(filepath.Join(runtimeRoot, "pi"), []byte(piScript), 0o700); err != nil {
		t.Fatal(err)
	}
	start := exec.Command(runner, "start", jobID)
	start.Stdin = strings.NewReader(encodeRuntimeSecretEnvelope("secret", "") + "\n")
	if output, err = start.CombinedOutput(); err != nil {
		t.Fatalf("start timeout job: %v: %s", err, output)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		output, err = exec.Command(runner, "status", jobID).CombinedOutput()
		if err == nil && json.Unmarshal(output, &taskStatus) == nil && taskStatus.Phase == "failed" {
			if taskStatus.ExitCode != 124 {
				t.Fatalf("timeout exit code = %d, want 124", taskStatus.ExitCode)
			}
			for _, name := range []string{"github-pat", "gitconfig", filepath.Join("github-bin", "git-credential-github"), filepath.Join("github-bin", "gh")} {
				if _, statErr := os.Stat(filepath.Join(jobRoot, name)); !os.IsNotExist(statErr) {
					t.Fatalf("no-PAT task retained GitHub runtime path %s: %v", name, statErr)
				}
			}
			logBody, readErr := os.ReadFile(filepath.Join(jobRoot, "runner.log"))
			if readErr != nil || !strings.Contains(string(logBody), "internal worker report") {
				t.Fatalf("internal Worker stdout was not retained in runner log: %q err=%v", logBody, readErr)
			}
			for _, name := range []string{"final-report.md", "completion-report.md"} {
				if _, statErr := os.Stat(filepath.Join(jobRoot, "artifacts", name)); !os.IsNotExist(statErr) {
					t.Fatalf("runtime created transport-only report artifact %s: %v", name, statErr)
				}
			}
			time.Sleep(1500 * time.Millisecond)
			if _, statErr := os.Stat(escaped); !os.IsNotExist(statErr) {
				t.Fatalf("descendant escaped timeout containment: %v", statErr)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timeout job did not terminate: %s, %v", output, err)
}

func TestEmbeddedRemoteRunnerUsesOnlyTaskScopedWorkspaceAndArtifacts(t *testing.T) {
	for _, expected := range []string{
		`workspaceRoot, artifactRoot := filepath.Join(taskRoot, "workspace"), filepath.Join(taskRoot, "artifacts")`,
		`command.Dir = workspaceRoot`,
		`directory := taskPath(taskID, "artifacts")`,
	} {
		if !strings.Contains(remoteRunnerSource, expected) {
			t.Fatalf("runner does not contain task-scoped path %q", expected)
		}
	}
	for _, forbidden := range []string{`command.Dir = filepath.Join(root, "workspace")`, `filepath.Join(root, "artifacts", taskID)`} {
		if strings.Contains(remoteRunnerSource, forbidden) {
			t.Fatalf("runner retains shared execution path %q", forbidden)
		}
	}
}

func TestEmbeddedRemoteRunnerKeepsTerminalStdoutInternalAndRequestedArtifactsExplicit(t *testing.T) {
	for _, expected := range []string{
		"Put genuine user-requested file deliverables under ",
		"Do not create final-report.md, completion-report.md, or another generic completion report",
		"Your final stdout response is an internal report for Central",
		"paths of genuine requested artifacts",
	} {
		if !strings.Contains(remoteRunnerSource, expected) {
			t.Fatalf("runner is missing internal-report contract %q", expected)
		}
	}
	for _, forbidden := range []string{
		`os.OpenFile(filepath.Join(artifactRoot, "final-report.md")`,
		`os.OpenFile(filepath.Join(artifactRoot, "completion-report.md")`,
		`io.MultiWriter(os.Stdout`,
	} {
		if strings.Contains(remoteRunnerSource, forbidden) {
			t.Fatalf("runner still materializes terminal stdout as an artifact: %q", forbidden)
		}
	}
}

func TestCompileRuntimeDeliversBillingTruthfulWorkerPrompt(t *testing.T) {
	material, err := CompileRuntime(RuntimeRequest{TaskID: "billing-contract", Objective: "Build a result", Architecture: "x86_64", Workload: WorkloadJob, MaxRuntimeSeconds: 60,
		Model: RuntimeModel{Provider: "openai_compatible", BaseURL: "https://example.test/v1", Name: "test", APIKey: "test"}, ImageFlavor: string(workerimage.FlavorCPU)})
	if err != nil {
		t.Fatal(err)
	}
	// Evaluate the exact prompt expressions shipped in the bootstrap, not a
	// second test-owned copy of the wording.
	if !strings.Contains(string(material.WorkerScript), shellQuote(base64.StdEncoding.EncodeToString([]byte(remoteRunnerSource)))) {
		t.Fatal("bootstrap does not deliver the current runner")
	}
	start := strings.Index(remoteRunnerSource, "\tprompt := ")
	if start < 0 {
		t.Fatal("Worker prompt assembly missing")
	}
	end := strings.Index(remoteRunnerSource[start:], "\tif githubAvailable {")
	if end < 0 {
		t.Fatal("Worker prompt assembly missing")
	}
	source := "package main\nimport \"fmt\"\nfunc main() {\nspec := struct{Workload string}{\"job\"}; artifactRoot := \"/internal/artifacts\"\n" + remoteRunnerSource[start:start+end] + "\nfmt.Print(prompt)\n}\n"
	filename := filepath.Join(t.TempDir(), "prompt.go")
	if err = os.WriteFile(filename, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("go", "run", filename).CombinedOutput()
	if err != nil {
		t.Fatalf("evaluate delivered prompt: %s %v", output, err)
	}
	for _, required := range []string{"actual billed cost as unavailable", "zero new-resource authorization", "Plan estimates are not actual billing", "retained compute and storage", "Central supplies verified artifact links", "user's requested language"} {
		if !strings.Contains(string(output), required) {
			t.Fatalf("delivered prompt lacks %q", required)
		}
	}
}

func TestEmbeddedRemoteRunnerScopesGitHubCredentialAndCleansIt(t *testing.T) {
	for _, expected := range []string{
		`github.com ] || exit 0`,
		`GH_TOKEN=\"$token\"`,
		`GIT_TERMINAL_PROMPT=0`,
		`withoutGitHubTokenEnv`,
		`cleanupGitHubRuntime(taskRoot)`,
	} {
		if !strings.Contains(remoteRunnerSource, expected) {
			t.Fatalf("runner missing GitHub isolation %q", expected)
		}
	}
	for _, forbidden := range []string{"github_pat", "GH_TOKEN=secret", "GITHUB_TOKEN=secret"} {
		if strings.Contains(string(mustCompileRuntimeForTest(t).WorkerScript), forbidden) {
			t.Fatalf("bootstrap contains credential sentinel %q", forbidden)
		}
	}
}

func TestEmbeddedRemoteRunnerHintsGitHubCapabilityOnlyForBoundTasks(t *testing.T) {
	for _, expected := range []string{
		`githubAvailable, err := githubRuntimeAvailable(taskRoot)`,
		`if githubAvailable {`,
		`HTTPS git and gh are already authenticated for github.com`,
		`clone private repositories, create a branch, edit and test code, commit and push, and create or update pull requests`,
		`Never read, print, copy, encode, or expose the credential`,
		`Before every push, revalidate the repository owner, github.com remote URL, base branch, current branch, and intended commits`,
	} {
		if !strings.Contains(remoteRunnerSource, expected) {
			t.Fatalf("runner missing conditional GitHub capability hint %q", expected)
		}
	}
	hint := strings.Index(remoteRunnerSource, `GitHub access is available for this task`)
	if hint < 0 {
		t.Fatal("GitHub capability hint is missing")
	}
	condition := strings.LastIndex(remoteRunnerSource[:hint], `if githubAvailable {`)
	blockEnd := strings.Index(remoteRunnerSource[hint:], "\n\t}")
	if condition < 0 || blockEnd < 0 {
		t.Fatal("GitHub capability hint is not confined to the credential-present branch")
	}
	for _, forbidden := range []string{"github_pat_", "RIVER-LANTERN-PAT", `GH_TOKEN=\"` + "secret"} {
		if strings.Contains(remoteRunnerSource[condition:hint+blockEnd], forbidden) {
			t.Fatalf("GitHub capability hint contains credential material %q", forbidden)
		}
	}
}

func TestEmbeddedGitHubConfigIsAcceptedByGitFirstConsumer(t *testing.T) {
	marker := `configBody := `
	start := strings.Index(remoteRunnerSource, marker)
	if start < 0 {
		t.Fatal("embedded configBody assignment is missing")
	}
	end := strings.IndexByte(remoteRunnerSource[start:], '\n')
	if end < 0 {
		t.Fatal("embedded configBody assignment is unterminated")
	}
	assignment := remoteRunnerSource[start : start+end]
	directory := t.TempDir()
	helper := filepath.Join(directory, "git-credential-github")
	evaluator := "package main\nimport \"os\"\nfunc main() {\nhelper := " + strconv.Quote(helper) + "\n" + assignment + "\n_, _ = os.Stdout.WriteString(configBody)\n}\n"
	evaluatorPath := filepath.Join(directory, "evaluate.go")
	if err := os.WriteFile(evaluatorPath, []byte(evaluator), 0o600); err != nil {
		t.Fatal(err)
	}
	configBody, err := exec.Command("go", "run", evaluatorPath).CombinedOutput()
	if err != nil {
		t.Fatalf("evaluate embedded configBody: %v: %s", err, configBody)
	}
	configPath := filepath.Join(directory, "gitconfig")
	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("git", "config", "--file", configPath, "--get", "credential.https://github.com.helper").CombinedOutput()
	if err != nil {
		t.Fatalf("git rejected embedded configBody: %v: %s\nconfig=%q", err, output, configBody)
	}
	if got := strings.TrimSpace(string(output)); got != helper {
		t.Fatalf("credential helper=%q want=%q", got, helper)
	}
	output, err = exec.Command("git", "config", "--file", configPath, "--get", "core.askpass").CombinedOutput()
	if err != nil || strings.TrimSpace(string(output)) != "/bin/false" {
		t.Fatalf("git askpass binding=%q err=%v", output, err)
	}
}

func TestWorkerLoadsOnlyExplicitBoundedServerSubagentExtension(t *testing.T) {
	material := mustCompileRuntimeForTest(t)
	script := string(material.WorkerScript)
	for _, expected := range []string{
		`"$config_root/extensions/dirextalk-subagent/extension.ts"`,
		`"$config_root/agents/worker.md"`,
		`readonly subagent_catalog=/opt/dirextalk-worker/pi-plugin-catalog/dirextalk-subagent`,
		`sha256sum -c - >/dev/null`,
		`mkdir -p -- "$config_root/extensions/dirextalk-subagent" "$config_root/agents"`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("bootstrap missing server subagent material %q", expected)
		}
	}
	disabled, err := CompileRuntime(RuntimeRequest{
		TaskID: "task-disabled-plugin", Objective: "work", Architecture: "x86_64", Workload: WorkloadJob,
		MaxRuntimeSeconds: 60, ImageFlavor: string(workerimage.FlavorCPU), EnableSubagent: false,
		Model: RuntimeModel{Provider: "openai_compatible", BaseURL: "https://models.example/v1", Name: "test", APIKey: "secret"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(disabled.WorkerScript), "readonly subagent_catalog=") {
		t.Fatal("disabled task bootstrap activates the image plugin catalog")
	}
	for _, expected := range []string{
		`tools := "read,bash,edit,write,grep,find,ls"`,
		`if spec.EnableSubagent { tools += ",subagent" }`,
		`if spec.EnableSubagent { piArguments = append(piArguments, "-e", filepath.Join(root, "pi-config", "extensions", "dirextalk-subagent", "extension.ts")) }`,
		`"--tools", tools, "--no-extensions"`,
		`"--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files"`,
		"separate git worktree and branch per writer",
		"Never expose GitHub credentials, model credentials",
	} {
		if !strings.Contains(remoteRunnerSource, expected) {
			t.Fatalf("runner missing subagent contract %q", expected)
		}
	}
	if strings.Contains(remoteRunnerSource, ".pi/agents") || strings.Contains(vendoredPiSubagentExtension, "agentScope") || strings.Contains(vendoredPiSubagentExtension, "confirmProjectAgents") {
		t.Fatal("project agent discovery remains enabled")
	}
}

func TestVendoredPiSubagentProvenanceAndBounds(t *testing.T) {
	if PiReleaseVersion != "0.84.4" || PiSubagentUpstreamCommit != "53fa77ccd8a279eb87e92294ef3687b03ff80112" {
		t.Fatalf("unexpected Pi provenance version=%s commit=%s", PiReleaseVersion, PiSubagentUpstreamCommit)
	}
	digest := sha256.Sum256([]byte(vendoredPiSubagentExtension))
	if hex.EncodeToString(digest[:]) != PiSubagentExtensionSHA256 {
		t.Fatalf("vendored extension digest mismatch")
	}
	provenance, err := os.ReadFile(filepath.Join("vendor", "pi-subagent", "v0.84.1", "PROVENANCE.md"))
	if err != nil || !strings.Contains(string(provenance), PiSubagentUpstreamCommit) || !strings.Contains(string(provenance), "MIT") {
		t.Fatalf("provenance=%q err=%v", provenance, err)
	}
	for _, expected := range []string{"MAX_PARALLEL_TASKS = 8", "MAX_CONCURRENCY = 4", "PI_CODING_AGENT_DIR/agents", "--no-extensions", "script.startsWith(\"/$bunfs/root/\")", "genericRuntime"} {
		if !strings.Contains(vendoredPiSubagentExtension, expected) {
			t.Fatalf("vendored subagent missing %q", expected)
		}
	}
	for _, forbidden := range []string{"RIVER-LANTERN-PAT", "github_pat", "GH_TOKEN="} {
		if strings.Contains(vendoredPiSubagentExtension, forbidden) || strings.Contains(vendoredPiSubagentWorkerAgent, forbidden) {
			t.Fatalf("vendored material contains credential sentinel %q", forbidden)
		}
	}
}

func mustCompileRuntimeForTest(t *testing.T) RuntimeMaterial {
	t.Helper()
	material, err := CompileRuntime(RuntimeRequest{TaskID: "task-github", Objective: "use a repository", Architecture: "x86_64", Workload: WorkloadJob, MaxRuntimeSeconds: 60, ImageFlavor: string(workerimage.FlavorCPU), EnableSubagent: true, Model: RuntimeModel{Provider: "openai_compatible", BaseURL: "https://models.example/v1", Name: "test", APIKey: "model-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	return material
}
