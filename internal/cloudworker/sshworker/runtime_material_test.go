package sshworker

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompileRuntimePinsMaintainedPiAndKeepsSecretOutOfPayload(t *testing.T) {
	secret := "model-secret-that-must-not-be-rendered"
	material, err := CompileRuntime(RuntimeRequest{
		TaskID:       "task-001",
		Objective:    "Deploy the repository and report actual server load.",
		Architecture: "x86_64",
		Workload:     WorkloadJob,
		Model: RuntimeModel{
			Provider: "openai_compatible", BaseURL: "https://models.example/v1",
			Name: "test-model", APIKey: secret, MaxOutputTokens: 16_384,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	script := string(material.WorkerScript)
	for _, expected := range []string{
		"releases/download/v0.84.1/pi-linux-x64.tar.gz",
		piLinuxX64SHA256,
		`dirextalk-worker-runner`,
		`server-status`,
		`artifact_root="$worker_root/artifacts"`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("script does not contain %q", expected)
		}
	}
	if strings.Contains(script, secret) || strings.Contains(script, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatal("model credential leaked into worker script")
	}
	start, err := material.Protocol.Start()
	if err != nil || !strings.Contains(start.Shell, "start") {
		t.Fatalf("start command: %#v, %v", start, err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(start.Stdin)))
	if err != nil || string(decoded) != secret {
		t.Fatalf("secret stdin did not round trip: %q, %v", decoded, err)
	}
	digest := sha256.Sum256(material.WorkerScript)
	if material.WorkerScriptSHA256 != hex.EncodeToString(digest[:]) {
		t.Fatal("worker script digest mismatch")
	}
}

func TestCompileRuntimeTreatsObjectiveAsData(t *testing.T) {
	objective := `deploy $(touch /tmp/not-executed) ; echo "done" && report`
	material, err := CompileRuntime(RuntimeRequest{
		TaskID: "task-002", Objective: objective, Architecture: "arm64", Workload: WorkloadService,
		Model: RuntimeModel{Provider: "anthropic", BaseURL: "https://api.anthropic.com",
			Name: "claude-test", APIKey: "secret", MaxOutputTokens: 4096},
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
	if !strings.Contains(script, piLinuxARM64SHA256) {
		t.Fatal("arm64 release pin is missing")
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
	valid := RuntimeRequest{TaskID: "task-003", Objective: "work", Architecture: "amd64", Workload: WorkloadJob, Model: RuntimeModel{
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
		TaskID: "task-004", Objective: "run a service", Architecture: "arm64", Workload: WorkloadService,
		Model: RuntimeModel{Provider: "anthropic", BaseURL: "https://api.anthropic.com", Name: "claude", APIKey: "secret", MaxOutputTokens: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, _ := material.Protocol.Status()
	logCommand, _ := material.Protocol.Log(512)
	list, _ := material.Protocol.Artifact("")
	download, _ := material.Protocol.Artifact("reports/load.html")
	server, _ := material.Protocol.ServerStatus()
	for name, command := range map[string]RuntimeCommand{"status": status, "log": logCommand, "list": list, "download": download, "server": server} {
		if command.Shell == "" || len(command.Stdin) != 0 {
			t.Fatalf("%s command is invalid: %#v", name, command)
		}
	}
	if !strings.Contains(logCommand.Shell, "'512'") || !strings.Contains(download.Shell, "'reports/load.html'") || !strings.Contains(server.Shell, "'server-status'") {
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
	source := filepath.Join(directory, "runner.go")
	if err := os.WriteFile(source, []byte(remoteRunnerSource), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "build", "-o", filepath.Join(directory, "runner"), source)
	command.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("embedded runner does not build: %v: %s", err, output)
	}
}
