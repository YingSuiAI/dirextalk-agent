package container

import (
	"bytes"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func runBootstrap(t *testing.T, script, output, cwd string, env []string, args ...string) ([]byte, error) {
	t.Helper()
	cmd := exec.Command(script, append([]string{output}, args...)...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), env...)
	return cmd.CombinedOutput()
}

func TestBootstrapLocalWritesCanonicalTokenAndAbsoluteEnvironment(t *testing.T) {
	out := filepath.Join(t.TempDir(), "protected")
	script := filepath.Join("scripts", "bootstrap-local.sh")
	cmd := exec.Command(script, out, "core:test", "runner:test", "postgres:test", "core.example.test")
	cmd.Env = append(os.Environ(), "PATH=/usr/bin:/bin")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap: %v (%s)", err, output)
	}
	token, err := os.ReadFile(filepath.Join(out, "service-token"))
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 || strings.ContainsAny(string(token), "\r\n") {
		t.Fatalf("service token must be exactly 43 bytes without newline: %d", len(token))
	}
	env, err := os.ReadFile(filepath.Join(out, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(env), "DIREXTALK_AGENT_CONFIG_FILE="+out+"/config.yaml\n") || !strings.Contains(string(env), "DIREXTALK_AGENT_CALLER_NETWORK_NAME=") {
		t.Fatalf("bootstrap environment is not absolute/caller-boundary aware: %s", env)
	}
	instanceID, err := os.ReadFile(filepath.Join(out, "instance-id"))
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(instanceID))) != 36 || !strings.Contains(string(env), "DIREXTALK_AGENT_INSTANCE_ID_FILE="+out+"/instance-id\n") {
		t.Fatalf("bootstrap must expose the canonical instance-id artifact: %q", instanceID)
	}
	config, err := os.ReadFile(filepath.Join(out, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "core_extension_enabled: false") {
		t.Fatal("local config must keep extension execution disabled")
	}
	if _, err := os.Stat(filepath.Join(out, "tls-ca")); err != nil {
		t.Fatalf("bootstrap must write a CA artifact: %v", err)
	}
	if _, err := os.Stat(filepath.Join(out, ".manifest")); err != nil {
		t.Fatalf("bootstrap must write a complete-set manifest: %v", err)
	}
}

func TestBootstrapLocalRejectsInvalidIsolationControls(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"DIREXTALK_CORE_EXTENSION_ENABLED":      "yes",
		"DIREXTALK_CORE_WORKLOAD_ENABLED":       "1",
		"DIREXTALK_CORE_EXTENSION_RUNNER_UID":   "0",
		"DIREXTALK_CORE_WORKLOAD_RUNNER_UID":    "65532",
		"DIREXTALK_CORE_WORKLOAD_RUNNER_SOCKET": "relative.sock",
	} {
		out := filepath.Join(t.TempDir(), "protected")
		cmd := exec.Command(script, out)
		cmd.Env = append(os.Environ(), name+"="+value)
		if output, err := cmd.CombinedOutput(); err == nil {
			t.Fatalf("invalid %s=%q unexpectedly succeeded: %s", name, value, output)
		}
		if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
			t.Fatalf("invalid %s left output target: %v", name, statErr)
		}
	}
}

type composeIsolationConfig struct {
	Name     string `yaml:"name"`
	Services map[string]struct {
		Profiles    []string `yaml:"profiles"`
		NetworkMode string   `yaml:"network_mode"`
		Ports       []any    `yaml:"ports"`
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
		Volumes []struct {
			Type   string `yaml:"type"`
			Source string `yaml:"source"`
			Target string `yaml:"target"`
		} `yaml:"volumes"`
	} `yaml:"services"`
	Networks map[string]struct {
		Name string `yaml:"name"`
	} `yaml:"networks"`
	Volumes map[string]struct {
		Name string `yaml:"name"`
	} `yaml:"volumes"`
}

func renderLocalCompose(t *testing.T, out string) composeIsolationConfig {
	t.Helper()
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker is required for Compose isolation verification")
	}
	compose := "compose.local.yaml"
	cmd := exec.Command(docker, "compose", "--env-file", filepath.Join(out, ".env"), "-f", compose, "--profile", "extensions", "--profile", "core-runner", "config")
	cmd.Dir = "."
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("compose config: %v", err)
	}
	var config composeIsolationConfig
	if err := yaml.Unmarshal(output, &config); err != nil {
		t.Fatalf("decode compose config: %v", err)
	}
	return config
}

func TestBootstrapLocalComposeIsolationUsesUniqueStackResources(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	outputs := make([]string, 2)
	configs := make([]composeIsolationConfig, 2)
	for i, stack := range []string{"e2e-stack-a", "e2e-stack-b"} {
		out := filepath.Join(root, stack)
		outputs[i] = out
		env := append(os.Environ(),
			"DIREXTALK_AGENT_STACK_NAME="+stack,
			"DIREXTALK_CORE_RUNNER_IMAGE_IMMUTABLE=core-runner:test",
			"DIREXTALK_EXTENSION_CGROUP_ROOT="+filepath.Join(root, stack, "extension-cgroup"),
			"DIREXTALK_CORE_RUNNER_CGROUP_ROOT="+filepath.Join(root, stack, "core-runner-cgroup"),
		)
		cmd := exec.Command(script, out)
		cmd.Env = env
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bootstrap %s: %v (%s)", stack, err, output)
		}
		configs[i] = renderLocalCompose(t, out)
	}
	for i, config := range configs {
		if len(config.Services) != 8 {
			t.Fatalf("stack %d should define exactly eight services, got %d", i, len(config.Services))
		}
		if _, ok := config.Services["postgres"]; !ok {
			t.Fatalf("stack %d is missing its Agent-owned Postgres service", i)
		}
		if len(config.Services["postgres"].Ports) != 0 || len(config.Services["core"].Ports) != 0 {
			t.Fatalf("stack %d unexpectedly publishes a host port", i)
		}
		if config.Services["extension-runner"].NetworkMode != "none" || config.Services["core-runner"].NetworkMode != "none" {
			t.Fatalf("stack %d runner network isolation is not explicit", i)
		}
		for _, service := range []string{"extension-runner", "core-runner"} {
			test := config.Services[service].Healthcheck.Test
			if len(test) < 4 || test[0] != "CMD" || test[2] != "probe" {
				t.Fatalf("stack %d %s is missing its runner readiness probe: %v", i, service, test)
			}
		}
		if len(config.Services["extension-runner"].Profiles) != 1 || config.Services["extension-runner"].Profiles[0] != "extensions" {
			t.Fatalf("stack %d extension profile is not explicit", i)
		}
		if len(config.Services["core-runner"].Profiles) != 1 || config.Services["core-runner"].Profiles[0] != "core-runner" {
			t.Fatalf("stack %d Core Runner profile is not explicit", i)
		}
	}
	if configs[0].Name == "" || configs[0].Name == configs[1].Name {
		t.Fatalf("Compose project identity is not isolated: %q vs %q", configs[0].Name, configs[1].Name)
	}
	for key, first := range configs[0].Networks {
		if second, ok := configs[1].Networks[key]; ok && first.Name == second.Name {
			t.Fatalf("network %q is shared between isolated stacks: %q", key, first.Name)
		}
	}
	for key, first := range configs[0].Volumes {
		if second, ok := configs[1].Volumes[key]; ok && first.Name == second.Name {
			t.Fatalf("volume %q is shared between isolated stacks: %q", key, first.Name)
		}
	}
	for _, service := range []string{"extension-runner", "core-runner"} {
		first, second := configs[0].Services[service], configs[1].Services[service]
		if len(first.Volumes) == 0 || len(second.Volumes) == 0 {
			t.Fatalf("%s has no socket volume", service)
		}
	}
	if configs[0].Volumes["agent_extension_socket"].Name == configs[1].Volumes["agent_extension_socket"].Name ||
		configs[0].Volumes["core_runner_socket"].Name == configs[1].Volumes["core_runner_socket"].Name {
		t.Fatal("runner socket volumes are shared between stacks")
	}
	for _, service := range []string{"extension-runner", "core-runner"} {
		findBind := func(config composeIsolationConfig) string {
			for _, volume := range config.Services[service].Volumes {
				if volume.Type == "bind" {
					return volume.Source
				}
			}
			return ""
		}
		if findBind(configs[0]) == "" || findBind(configs[0]) == findBind(configs[1]) {
			t.Fatalf("%s cgroup root is shared or missing", service)
		}
	}
	_ = outputs
}

func TestBootstrapLocalReusesCompleteSetFromAnotherWorkingDirectory(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "protected")
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil, "core:first", "runner:first", "postgres:first", "first.example"); err != nil {
		t.Fatalf("initial bootstrap: %v (%s)", err, output)
	}
	files := []string{"postgres-password", "database-url", "service-token", "instance-id", "tls-key", "tls-cert", "tls-ca", "config.yaml", ".env", ".manifest"}
	before := make(map[string][]byte, len(files))
	for _, name := range files {
		before[name], err = os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil, "core:changed", "runner:changed", "postgres:changed", "changed.example"); err != nil {
		t.Fatalf("reuse bootstrap: %v (%s)", err, output)
	}
	for _, name := range files {
		after, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before[name], after) {
			t.Fatalf("complete artifact %s changed during reuse", name)
		}
	}
}

func TestBootstrapLocalRejectsPartialTargetWithoutRegeneration(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "partial")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := []byte("do-not-replace\n")
	if err := os.WriteFile(filepath.Join(out, "postgres-password"), sentinel, 0400); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err == nil {
		t.Fatalf("partial target unexpectedly succeeded: %s", output)
	}
	got, err := os.ReadFile(filepath.Join(out, "postgres-password"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, sentinel) {
		t.Fatal("partial target was modified")
	}
}

func TestBootstrapLocalRejectsMixedCompleteTargetWithoutRepairingCredentials(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "mixed")
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err != nil {
		t.Fatalf("initial bootstrap: %v (%s)", err, output)
	}
	passwordBefore, err := os.ReadFile(filepath.Join(out, "postgres-password"))
	if err != nil {
		t.Fatal(err)
	}
	instanceBefore, err := os.ReadFile(filepath.Join(out, "instance-id"))
	if err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(out, "service-token")
	if err := os.Chmod(tokenPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), 0400); err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err == nil {
		t.Fatalf("mixed target unexpectedly succeeded: %s", output)
	}
	passwordAfter, err := os.ReadFile(filepath.Join(out, "postgres-password"))
	if err != nil {
		t.Fatal(err)
	}
	instanceAfter, err := os.ReadFile(filepath.Join(out, "instance-id"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(passwordBefore, passwordAfter) || !bytes.Equal(instanceBefore, instanceAfter) {
		t.Fatal("mixed target repair changed database or instance identity")
	}
}

func TestBootstrapLocalRejectsUnexpectedTopLevelArtifact(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "extra")
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err != nil {
		t.Fatalf("initial bootstrap: %v (%s)", err, output)
	}
	if err := os.WriteFile(filepath.Join(out, "unexpected"), []byte("extra\n"), 0400); err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err == nil {
		t.Fatalf("unexpected top-level artifact was accepted: %s", output)
	}
}

func TestBootstrapLocalLeavesNoTargetWhenGenerationIsInterrupted(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "interrupted")
	bin := filepath.Join(root, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := filepath.Join(bin, "openssl")
	contents := "#!/bin/sh\nif [ \"$1\" = req ]; then exit 42; fi\nexec " + openssl + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	pathEnv := bin + string(os.PathListSeparator) + os.Getenv("PATH")
	if output, err := runBootstrap(t, script, out, t.TempDir(), []string{"PATH=" + pathEnv}); err == nil {
		t.Fatalf("interrupted bootstrap unexpectedly succeeded: %s", output)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("interrupted bootstrap left target: %v", err)
	}
	staging, err := filepath.Glob(filepath.Join(root, ".interrupted.staging.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(staging) != 0 {
		t.Fatalf("interrupted bootstrap left staging directories: %v", staging)
	}
}

func TestBootstrapLocalConcurrentGenerationHasOneCanonicalPromotion(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "protected")
	bin := filepath.Join(root, "bin")
	readyDir := filepath.Join(root, "ready")
	if err := os.MkdirAll(readyDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal(err)
	}
	barrier := filepath.Join(root, "release")
	wrapper := filepath.Join(bin, "openssl")
	contents := "#!/bin/sh\nif [ \"$1\" = req ]; then : > \"$READY_DIR/ready\"; while [ ! -e \"$RELEASE_FILE\" ]; do sleep 0.01; done; fi\nexec " + openssl + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(contents), 0700); err != nil {
		t.Fatal(err)
	}
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	pathEnv := bin + string(os.PathListSeparator) + os.Getenv("PATH")
	start := func() (*exec.Cmd, *bytes.Buffer) {
		cmd := exec.Command(script, out, "core:test", "runner:test", "postgres:test", "localhost")
		cmd.Dir = t.TempDir()
		var output bytes.Buffer
		cmd.Stdout = &output
		cmd.Stderr = &output
		cmd.Env = append(os.Environ(), "PATH="+pathEnv, "READY_DIR="+readyDir, "RELEASE_FILE="+barrier)
		return cmd, &output
	}
	first, firstOutput := start()
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(readyDir, "ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			_ = first.Process.Kill()
			t.Fatal("first bootstrap did not reach generation barrier")
		}
		time.Sleep(10 * time.Millisecond)
	}
	second, secondOutput := start()
	if err := second.Start(); err != nil {
		_ = first.Process.Kill()
		t.Fatal(err)
	}
	if err := os.WriteFile(barrier, []byte("release\n"), 0600); err != nil {
		t.Fatal(err)
	}
	firstErr := first.Wait()
	secondErr := second.Wait()
	if firstErr != nil && secondErr != nil {
		t.Fatalf("concurrent bootstrap must produce one canonical success: first=%v (%s), second=%v (%s)", firstErr, firstOutput.String(), secondErr, secondOutput.String())
	}
	files := map[string]bool{
		".env": true, ".manifest": true, "config.yaml": true, "database-url": true,
		"instance-id": true, "postgres-password": true, "service-token": true,
		"tls-ca": true, "tls-cert": true, "tls-key": true,
	}
	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !files[entry.Name()] {
			t.Fatalf("concurrent promotion left unexpected artifact %q", entry.Name())
		}
	}
	if len(entries) != len(files) {
		t.Fatalf("concurrent promotion produced %d artifacts, want %d", len(entries), len(files))
	}
	if _, err := os.Stat(out + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("bootstrap lock remained after concurrent generation: %v", err)
	}
	staging, err := filepath.Glob(filepath.Join(root, ".protected.staging.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(staging) != 0 {
		t.Fatalf("concurrent promotion left staging directories: %v", staging)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err != nil {
		t.Fatalf("canonical output was not reusable: %v (%s)", err, output)
	}
}

func TestRefreshManifestAllowsOnlyTLSAndTokenRotation(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "protected")
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err != nil {
		t.Fatalf("initial bootstrap: %v (%s)", err, output)
	}
	refresh, err := filepath.Abs(filepath.Join("scripts", "refresh-manifest.sh"))
	if err != nil {
		t.Fatal(err)
	}
	identityBefore := make(map[string][]byte)
	for _, name := range []string{"postgres-password", "database-url", "instance-id"} {
		identityBefore[name], err = os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	manifestBefore, err := os.ReadFile(filepath.Join(out, ".manifest"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"service-token", "tls-key", "tls-cert", "tls-ca"} {
		if err := os.Chmod(filepath.Join(out, name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	rotatedToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	if err := os.WriteFile(filepath.Join(out, "service-token"), []byte(rotatedToken), 0400); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(out, "tls-key")
	certPath := filepath.Join(out, "tls-cert")
	cmd := exec.Command("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", keyPath, "-out", certPath, "-days", "365", "-subj", "/CN=localhost", "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generate rotated TLS material: %v (%s)", err, output)
	}
	if err := os.WriteFile(filepath.Join(out, "tls-ca"), mustRead(t, certPath), 0400); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"service-token", "tls-key", "tls-cert", "tls-ca"} {
		if err := os.Chmod(filepath.Join(out, name), 0400); err != nil {
			t.Fatal(err)
		}
	}
	if output, err := exec.Command(refresh, out).CombinedOutput(); err != nil {
		t.Fatalf("refresh valid rotation: %v (%s)", err, output)
	}
	manifestAfter, err := os.ReadFile(filepath.Join(out, ".manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(manifestBefore, manifestAfter) {
		t.Fatal("manifest did not change after TLS/token rotation")
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err != nil {
		t.Fatalf("rotated complete set was not reusable: %v (%s)", err, output)
	}
	for name, before := range identityBefore {
		after, err := os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Fatalf("rotation changed immutable artifact %s", name)
		}
	}
	if err := os.Chmod(filepath.Join(out, "service-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "service-token"), []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), 0400); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command(refresh, out).CombinedOutput(); err == nil {
		t.Fatalf("non-canonical token rotation unexpectedly succeeded: %s", output)
	}
	manifestAfterBadToken, err := os.ReadFile(filepath.Join(out, ".manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifestAfter, manifestAfterBadToken) {
		t.Fatal("non-canonical token rejection changed manifest")
	}
	if err := os.Chmod(filepath.Join(out, "service-token"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "service-token"), []byte(rotatedToken), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(out, "service-token"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(out, "database-url"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "database-url"), []byte("postgresql://dirextalk_agent:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@postgres:5432/dirextalk_agent?sslmode=disable\n"), 0400); err != nil {
		t.Fatal(err)
	}
	manifestStable := append([]byte(nil), manifestAfter...)
	if output, err := exec.Command(refresh, out).CombinedOutput(); err == nil {
		t.Fatalf("invalid DB rotation unexpectedly succeeded: %s", output)
	}
	manifestAfterFailure, err := os.ReadFile(filepath.Join(out, ".manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifestStable, manifestAfterFailure) {
		t.Fatal("failed rotation changed manifest")
	}
}

func TestRotateLocalRejectsNonCanonicalTokenBeforeCompose(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "protected")
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err != nil {
		t.Fatalf("initial bootstrap: %v (%s)", err, output)
	}
	tokenPath := filepath.Join(out, "service-token")
	if err := os.Chmod(tokenPath, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tokenPath, []byte("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"), 0400); err != nil {
		t.Fatal(err)
	}
	manifestBefore, err := os.ReadFile(filepath.Join(out, ".manifest"))
	if err != nil {
		t.Fatal(err)
	}
	fakeBin := filepath.Join(root, "bin")
	if err := os.Mkdir(fakeBin, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "docker-called")
	fakeDocker := filepath.Join(fakeBin, "docker")
	if err := os.WriteFile(fakeDocker, []byte("#!/bin/sh\nprintf called > \""+marker+"\"\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	rotate, err := filepath.Abs(filepath.Join("scripts", "rotate-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	compose, err := filepath.Abs(filepath.Join("deploy", "container", "compose.local.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(out, ".env")
	cmd := exec.Command(rotate, compose, envFile)
	cmd.Env = append(os.Environ(), "PATH="+fakeBin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if output, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("non-canonical rotate unexpectedly succeeded: %s", output)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("Compose was invoked before token validation: %v", err)
	}
	manifestAfter, err := os.ReadFile(filepath.Join(out, ".manifest"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(manifestBefore, manifestAfter) {
		t.Fatal("failed rotation changed manifest")
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
