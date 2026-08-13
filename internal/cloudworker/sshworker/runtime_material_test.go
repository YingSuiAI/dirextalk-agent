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
		Objective:    "Deploy the repository and report actual server load.",
		Architecture: "x86_64",
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
		`DIREXTALK_MODEL_API_KEY`,
		`< "$worker_root/objective.txt"`,
		`/tmp/dirextalk-worker/artifacts`,
		`tee "$artifact_root/final-report.md"`,
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("script does not contain %q", expected)
		}
	}
	if strings.Contains(script, secret) || strings.Contains(script, base64.StdEncoding.EncodeToString([]byte(secret))) {
		t.Fatal("model credential leaked into worker script")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(material.SecretStdin)))
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
		Objective: objective, Architecture: "arm64",
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
	valid := RuntimeRequest{Objective: "work", Architecture: "amd64", Model: RuntimeModel{
		Provider: "gemini", BaseURL: "https://generativelanguage.googleapis.com/v1beta",
		Name: "gemini-test", APIKey: "secret", MaxOutputTokens: 4096,
	}}
	cases := []RuntimeRequest{
		{},
		{Objective: valid.Objective, Architecture: "riscv64", Model: valid.Model},
		{Objective: valid.Objective, Architecture: valid.Architecture, Model: RuntimeModel{
			Provider: "unknown", BaseURL: valid.Model.BaseURL, Name: valid.Model.Name,
			APIKey: valid.Model.APIKey, MaxOutputTokens: valid.Model.MaxOutputTokens,
		}},
		{Objective: valid.Objective, Architecture: valid.Architecture, Model: RuntimeModel{
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
