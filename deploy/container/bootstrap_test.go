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
	cmd := exec.Command(script, out, "agent:test", "postgres:test", "core.example.test")
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
	if !strings.Contains(string(env), "DIREXTALK_AGENT_CONFIG_FILE="+out+"/config.yaml\n") || !strings.Contains(string(env), "DIREXTALK_AGENT_CALLER_NETWORK_NAME=") || !strings.Contains(string(env), "DIREXTALK_AGENT_IMAGE_IMMUTABLE=agent:test\n") {
		t.Fatalf("bootstrap environment is not absolute/caller-boundary aware: %s", env)
	}
	for _, line := range strings.Split(string(env), "\n") {
		if strings.HasPrefix(line, "DIREXTALK_") && strings.Contains(line, "IMAGE_IMMUTABLE=") &&
			!strings.HasPrefix(line, "DIREXTALK_AGENT_IMAGE_IMMUTABLE=") &&
			!strings.HasPrefix(line, "DIREXTALK_POSTGRES_IMAGE_IMMUTABLE=") {
			t.Fatalf("bootstrap emitted an unexpected image variable: %s", line)
		}
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

func TestBootstrapLocalDefaultsToPinnedPgvectorPostgres(t *testing.T) {
	out := filepath.Join(t.TempDir(), "protected")
	script := filepath.Join("scripts", "bootstrap-local.sh")
	cmd := exec.Command(script, out)
	cmd.Env = append(os.Environ(), "PATH=/usr/bin:/bin")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap: %v (%s)", err, output)
	}
	env, err := os.ReadFile(filepath.Join(out, ".env"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "DIREXTALK_POSTGRES_IMAGE_IMMUTABLE=docker.io/pgvector/pgvector:pg18@sha256:691673308c99d2161ba298736f3147f1f22d79de2fb7ec93ae9b4afcab870b62\n"
	if !strings.Contains(string(env), want) {
		t.Fatalf("bootstrap default PostgreSQL image must provide the vector extension: %s", env)
	}
}

func TestBootstrapLocalRejectsInvalidIsolationControls(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	invalid := []struct {
		name  string
		value string
	}{
		{"DIREXTALK_CORE_EXTENSION_ENABLED", "yes"},
		{"DIREXTALK_CORE_WORKLOAD_ENABLED", "1"},
		{"DIREXTALK_CORE_EXTENSION_RUNNER_UID", "0"},
		{"DIREXTALK_CORE_EXTENSION_RUNNER_UID", "65530"},
		{"DIREXTALK_CORE_WORKLOAD_RUNNER_UID", "65532"},
		{"DIREXTALK_CORE_WORKLOAD_RUNNER_UID", "65531"},
		{"DIREXTALK_CORE_WORKLOAD_RUNNER_SOCKET", "relative.sock"},
		{"DIREXTALK_EXTENSION_CGROUP_PARENT", "../bad.slice"},
		{"DIREXTALK_CORE_RUNNER_CGROUP_PARENT", ".slice"},
		{"DIREXTALK_EXTENSION_CGROUP_PARENT", "-bad.slice"},
		{"DIREXTALK_CORE_RUNNER_CGROUP_PARENT", "bad-.slice"},
		{"DIREXTALK_EXTENSION_CGROUP_PARENT", ".bad.slice"},
		{"DIREXTALK_CORE_RUNNER_CGROUP_PARENT", "bad_.slice"},
		{"DIREXTALK_EXTENSION_CGROUP_PARENT", "bad\n.slice"},
		{"DIREXTALK_CORE_RUNNER_CGROUP_PARENT", "good.slice\nDIREXTALK_AGENT_STACK_NAME=hijack"},
		{"DIREXTALK_EXTENSION_CGROUP_PARENT", "good.slice\rDIREXTALK_AGENT_STACK_NAME=hijack"},
	}
	for _, control := range invalid {
		name, value := control.name, control.value
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
		Image        string   `yaml:"image"`
		Entrypoint   []string `yaml:"entrypoint"`
		User         string   `yaml:"user"`
		Profiles     []string `yaml:"profiles"`
		NetworkMode  string   `yaml:"network_mode"`
		Cgroup       string   `yaml:"cgroup"`
		CgroupParent string   `yaml:"cgroup_parent"`
		Ports        []any    `yaml:"ports"`
		Command      []string `yaml:"command"`
		DependsOn    map[string]struct {
			Condition string `yaml:"condition"`
		} `yaml:"depends_on"`
		Healthcheck struct {
			Test []string `yaml:"test"`
		} `yaml:"healthcheck"`
		Volumes []struct {
			Type   string `yaml:"type"`
			Source string `yaml:"source"`
			Target string `yaml:"target"`
			Bind   struct {
				CreateHostPath bool `yaml:"create_host_path"`
			} `yaml:"bind"`
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
	cmd := exec.Command(docker, "compose", "--env-file", filepath.Join(out, ".env"), "-f", compose, "config")
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
			"DIREXTALK_AGENT_IMAGE_IMMUTABLE=agent:test",
			"DIREXTALK_EXTENSION_CGROUP_ROOT="+filepath.Join(root, stack, "extension-cgroup"),
			"DIREXTALK_CORE_RUNNER_CGROUP_ROOT="+filepath.Join(root, stack, "core-runner-cgroup"),
		)
		cmd := exec.Command(script, out, "agent:test")
		cmd.Env = env
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("bootstrap %s: %v (%s)", stack, err, output)
		}
		configs[i] = renderLocalCompose(t, out)
	}
	for i, config := range configs {
		if len(config.Services) != 9 {
			t.Fatalf("stack %d should define exactly nine services, got %d", i, len(config.Services))
		}
		if _, ok := config.Services["postgres"]; !ok {
			t.Fatalf("stack %d is missing its Agent-owned Postgres service", i)
		}
		if len(config.Services["postgres"].Ports) != 0 || len(config.Services["core"].Ports) != 0 {
			t.Fatalf("stack %d unexpectedly publishes a host port", i)
		}
		for _, service := range []string{"core", "extension-runner", "core-runner"} {
			if config.Services[service].Image != "agent:test" {
				t.Fatalf("stack %d %s does not use the unified Agent image: %q", i, service, config.Services[service].Image)
			}
		}
		if got := config.Services["extension-runner"].Entrypoint; len(got) != 1 || got[0] != "/usr/local/bin/dirextalk-extension-runner" {
			t.Fatalf("stack %d extension runner entrypoint is not explicit: %v", i, got)
		}
		if got := config.Services["core-runner"].Entrypoint; len(got) != 1 || got[0] != "/usr/local/bin/dirextalk-core-runner" {
			t.Fatalf("stack %d Core Runner entrypoint is not explicit: %v", i, got)
		}
		if config.Services["core"].User != "65532:65532" || config.Services["extension-runner"].User != "65531:65531" || config.Services["core-runner"].User != "65530:65530" {
			t.Fatalf("stack %d runtime UID isolation is not explicit: core=%q extension=%q workload=%q", i, config.Services["core"].User, config.Services["extension-runner"].User, config.Services["core-runner"].User)
		}
		for _, runner := range []string{"extension-runner", "core-runner"} {
			dependency, ok := config.Services["core"].DependsOn[runner]
			if !ok || dependency.Condition != "service_healthy" {
				t.Fatalf("stack %d core must wait for healthy %s: %+v", i, runner, config.Services["core"].DependsOn)
			}
		}
		if config.Services["extension-runner"].NetworkMode != "none" || config.Services["core-runner"].NetworkMode != "none" {
			t.Fatalf("stack %d runner network isolation is not explicit", i)
		}
		if config.Services["extension-runner"].Cgroup != "host" || config.Services["core-runner"].Cgroup != "host" {
			t.Fatalf("stack %d runner cgroup namespaces are not host-bound", i)
		}
		coreMounts := make(map[string]string, len(config.Services["core"].Volumes))
		for _, volume := range config.Services["core"].Volumes {
			coreMounts[volume.Target] = volume.Source
		}
		if got := coreMounts["/var/lib/dirextalk-agent/extension-workspaces"]; got != "agent_runner_workspaces" {
			t.Fatalf("stack %d Agent extension workspace volume = %q, want shared runner workspace", i, got)
		}
		for _, service := range []string{"extension-runner", "core-runner"} {
			test := config.Services[service].Healthcheck.Test
			if len(test) < 4 || test[0] != "CMD" || test[2] != "probe" {
				t.Fatalf("stack %d %s is missing its runner readiness probe: %v", i, service, test)
			}
		}
		extensionSocketInit := strings.Join(config.Services["extension-socket-init"].Command, " ")
		if !strings.Contains(extensionSocketInit, "chmod 2750 /socket") || strings.Contains(extensionSocketInit, "chmod 3770 /socket") {
			t.Fatalf("stack %d extension socket parent must be setgid and not group-writable: %q", i, extensionSocketInit)
		}
		coreRunnerSocketInit := strings.Join(config.Services["core-runner-socket-init"].Command, " ")
		if !strings.Contains(coreRunnerSocketInit, "chmod 3770 /socket") {
			t.Fatalf("stack %d Core Runner socket init does not preserve setgid/sticky mode: %q", i, coreRunnerSocketInit)
		}
		dataInit := config.Services["extension-runner-data-init"]
		dataInitCommand := strings.Join(dataInit.Command, " ")
		for _, contract := range []string{
			"chown 65531:65531 /install /state",
			"chmod 0700 /install /state",
			"chown 65531:65532 /workspace",
			"chmod 0770 /workspace",
		} {
			if !strings.Contains(dataInitCommand, contract) {
				t.Fatalf("stack %d extension runner data initialization is missing %q: %q", i, contract, dataInitCommand)
			}
		}
		if dataInit.User != "0:0" || dataInit.NetworkMode != "none" {
			t.Fatalf("stack %d extension runner data initializer is not isolated: user=%q network=%q", i, dataInit.User, dataInit.NetworkMode)
		}
		dataMounts := make(map[string]string, len(dataInit.Volumes))
		for _, volume := range dataInit.Volumes {
			dataMounts[volume.Target] = volume.Source
		}
		for target, source := range map[string]string{
			"/install":   "agent_extension_install",
			"/workspace": "agent_runner_workspaces",
			"/state":     "agent_extension_state",
		} {
			if dataMounts[target] != source {
				t.Fatalf("stack %d extension runner data initializer mount %s=%q, want %q", i, target, dataMounts[target], source)
			}
		}
		dataDependency, ok := config.Services["extension-runner"].DependsOn["extension-runner-data-init"]
		if !ok || dataDependency.Condition != "service_completed_successfully" {
			t.Fatalf("stack %d extension runner must wait for initialized data roots: %+v", i, config.Services["extension-runner"].DependsOn)
		}
		if len(config.Services["extension-runner"].Profiles) != 0 || len(config.Services["core-runner"].Profiles) != 0 {
			t.Fatalf("stack %d runner services must start by default", i)
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
	if configs[0].Services["extension-runner"].CgroupParent == "" || configs[0].Services["core-runner"].CgroupParent == "" ||
		configs[0].Services["extension-runner"].CgroupParent == configs[1].Services["extension-runner"].CgroupParent ||
		configs[0].Services["core-runner"].CgroupParent == configs[1].Services["core-runner"].CgroupParent {
		t.Fatal("runner cgroup parents are not distinct per stack")
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
		seenCgroupBind := false
		for _, volume := range first.Volumes {
			if volume.Target == "/cgroup" && volume.Type == "bind" {
				seenCgroupBind = true
				if volume.Bind.CreateHostPath {
					t.Fatalf("%s cgroup bind must not auto-create an ordinary host directory", service)
				}
			}
		}
		if !seenCgroupBind {
			t.Fatalf("%s cgroup bind is missing", service)
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
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil, "agent:first", "postgres:first", "first.example"); err != nil {
		t.Fatalf("initial bootstrap: %v (%s)", err, output)
	}
	files := []string{"postgres-password", "database-url", "service-token", "core-secret-master-key", "instance-id", "tls-key", "tls-cert", "tls-ca", "config.yaml", ".env", ".manifest"}
	before := make(map[string][]byte, len(files))
	for _, name := range files {
		before[name], err = os.ReadFile(filepath.Join(out, name))
		if err != nil {
			t.Fatal(err)
		}
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil, "agent:changed", "postgres:changed", "changed.example"); err != nil {
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

func TestBootstrapLocalMigratesLegacyEnvironmentWithoutRotatingIdentityOrVolumes(t *testing.T) {
	root := t.TempDir()
	out := filepath.Join(root, "legacy")
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), []string{"DIREXTALK_AGENT_STACK_NAME=legacy-stack"}); err != nil {
		t.Fatalf("initial bootstrap: %v (%s)", err, output)
	}
	beforeInstance := mustRead(t, filepath.Join(out, "instance-id"))
	beforePassword := mustRead(t, filepath.Join(out, "postgres-password"))
	beforeEnv := string(mustRead(t, filepath.Join(out, ".env")))
	if !strings.Contains(beforeEnv, "DIREXTALK_EXTENSION_CGROUP_PARENT=legacy-stack-extension.slice\n") || !strings.Contains(beforeEnv, "DIREXTALK_CORE_RUNNER_CGROUP_PARENT=legacy-stack-core-runner.slice\n") {
		t.Fatal("bootstrap did not derive expected legacy stack parents")
	}
	legacyEnv := strings.ReplaceAll(beforeEnv, "DIREXTALK_EXTENSION_CGROUP_PARENT=legacy-stack-extension.slice\n", "")
	legacyEnv = strings.ReplaceAll(legacyEnv, "DIREXTALK_CORE_RUNNER_CGROUP_PARENT=legacy-stack-core-runner.slice\n", "")
	if err := os.Chmod(filepath.Join(out, ".env"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, ".env"), []byte(legacyEnv), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(out, ".env"), 0o400); err != nil {
		t.Fatal(err)
	}
	manifestCmd := exec.Command("sh", "-ec", "{ printf '%s\\n' '# dirextalk-bootstrap-manifest-v1'; sha256sum postgres-password database-url service-token instance-id tls-key tls-cert tls-ca config.yaml .env; } > .manifest.tmp; chmod 0400 .manifest.tmp; mv .manifest.tmp .manifest")
	manifestCmd.Dir = out
	if output, err := manifestCmd.CombinedOutput(); err != nil {
		t.Fatalf("legacy manifest: %v (%s)", err, output)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err != nil {
		t.Fatalf("legacy migration: %v (%s)", err, output)
	}
	if got := mustRead(t, filepath.Join(out, "instance-id")); !bytes.Equal(got, beforeInstance) {
		t.Fatal("legacy migration rotated instance identity")
	}
	if got := mustRead(t, filepath.Join(out, "postgres-password")); !bytes.Equal(got, beforePassword) {
		t.Fatal("legacy migration rotated PostgreSQL password")
	}
	finalEnv := string(mustRead(t, filepath.Join(out, ".env")))
	for _, line := range []string{"DIREXTALK_AGENT_POSTGRES_VOLUME=legacy-stack-postgres-data\n", "DIREXTALK_EXTENSION_CGROUP_PARENT=legacy-stack-extension.slice\n", "DIREXTALK_CORE_RUNNER_CGROUP_PARENT=legacy-stack-core-runner.slice\n"} {
		if !strings.Contains(finalEnv, line) {
			t.Fatalf("migrated environment missing %q", line)
		}
	}
}

func TestBootstrapLocalRecoversInterruptedCgroupParentMigration(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, failpoint := range []string{"after-env-replace", "before-manifest-mktemp", "after-manifest-hash"} {
		t.Run(failpoint, func(t *testing.T) {
			root := t.TempDir()
			out := filepath.Join(root, "replay")
			if output, err := runBootstrap(t, script, out, t.TempDir(), []string{"DIREXTALK_AGENT_STACK_NAME=replay-stack"}); err != nil {
				t.Fatalf("initial bootstrap: %v (%s)", err, output)
			}
			beforeInstance := mustRead(t, filepath.Join(out, "instance-id"))
			beforePassword := mustRead(t, filepath.Join(out, "postgres-password"))
			beforeEnv := string(mustRead(t, filepath.Join(out, ".env")))
			legacyEnv := strings.ReplaceAll(beforeEnv, "DIREXTALK_EXTENSION_CGROUP_PARENT=replay-stack-extension.slice\n", "")
			legacyEnv = strings.ReplaceAll(legacyEnv, "DIREXTALK_CORE_RUNNER_CGROUP_PARENT=replay-stack-core-runner.slice\n", "")
			if err := os.Chmod(filepath.Join(out, ".env"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(out, ".env"), []byte(legacyEnv), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(out, ".env"), 0o400); err != nil {
				t.Fatal(err)
			}
			manifestCmd := exec.Command("sh", "-ec", "{ printf '%s\\n' '# dirextalk-bootstrap-manifest-v1'; sha256sum postgres-password database-url service-token instance-id tls-key tls-cert tls-ca config.yaml .env; } > .manifest.tmp; chmod 0400 .manifest.tmp; mv .manifest.tmp .manifest")
			manifestCmd.Dir = out
			if output, err := manifestCmd.CombinedOutput(); err != nil {
				t.Fatalf("legacy manifest: %v (%s)", err, output)
			}
			if output, err := runBootstrap(t, script, out, t.TempDir(), []string{"DIREXTALK_BOOTSTRAP_MIGRATION_FAILPOINT=" + failpoint}); err == nil {
				t.Fatalf("failpoint %s unexpectedly succeeded: %s", failpoint, output)
			}
			if _, err := os.Stat(filepath.Join(out, ".cgroup-parent-migration")); err != nil {
				t.Fatalf("failpoint %s did not leave the migration journal: %v", failpoint, err)
			}
			if failpoint == "after-env-replace" {
				corruptEnv := strings.Replace(string(mustRead(t, filepath.Join(out, ".env"))), "DIREXTALK_AGENT_STACK_NAME=replay-stack\n", "DIREXTALK_AGENT_STACK_NAME=corrupted?\n", 1)
				if err := os.Chmod(filepath.Join(out, ".env"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(out, ".env"), []byte(corruptEnv), 0o400); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(filepath.Join(out, ".env"), 0o400); err != nil {
					t.Fatal(err)
				}
			}
			if output, err := runBootstrap(t, script, out, t.TempDir(), []string{"DIREXTALK_AGENT_STACK_NAME=ignored-after-recovery"}); err != nil {
				t.Fatalf("recovery: %v (%s)", err, output)
			}
			if got := mustRead(t, filepath.Join(out, "instance-id")); !bytes.Equal(got, beforeInstance) {
				t.Fatal("recovery rotated instance identity")
			}
			if got := mustRead(t, filepath.Join(out, "postgres-password")); !bytes.Equal(got, beforePassword) {
				t.Fatal("recovery rotated PostgreSQL password")
			}
			finalEnv := string(mustRead(t, filepath.Join(out, ".env")))
			if !strings.Contains(finalEnv, "DIREXTALK_AGENT_POSTGRES_VOLUME=replay-stack-postgres-data\n") ||
				!strings.Contains(finalEnv, "DIREXTALK_EXTENSION_CGROUP_PARENT=replay-stack-extension.slice\n") ||
				!strings.Contains(finalEnv, "DIREXTALK_CORE_RUNNER_CGROUP_PARENT=replay-stack-core-runner.slice\n") {
				t.Fatal("recovery did not preserve the stack volume and complete both cgroup parent assignments")
			}
			for _, name := range []string{".cgroup-parent-migration", ".cgroup-parent-migration.tmp", ".env.migrate-backup", ".env.migrate.tmp", ".manifest.migrate-backup", ".manifest.migrate.tmp"} {
				if _, err := os.Stat(filepath.Join(out, name)); !os.IsNotExist(err) {
					t.Fatalf("recovery left migration artifact %s: %v", name, err)
				}
			}
		})
	}
}

func TestBootstrapLocalRecoversInterruptedRollbackBeforeClearingJournal(t *testing.T) {
	script, err := filepath.Abs(filepath.Join("scripts", "bootstrap-local.sh"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	out := filepath.Join(root, "rollback")
	if output, err := runBootstrap(t, script, out, t.TempDir(), []string{"DIREXTALK_AGENT_STACK_NAME=rollback-stack"}); err != nil {
		t.Fatalf("initial bootstrap: %v (%s)", err, output)
	}
	beforeInstance := mustRead(t, filepath.Join(out, "instance-id"))
	beforePassword := mustRead(t, filepath.Join(out, "postgres-password"))
	beforeEnv := string(mustRead(t, filepath.Join(out, ".env")))
	legacyEnv := strings.ReplaceAll(beforeEnv, "DIREXTALK_EXTENSION_CGROUP_PARENT=rollback-stack-extension.slice\n", "")
	legacyEnv = strings.ReplaceAll(legacyEnv, "DIREXTALK_CORE_RUNNER_CGROUP_PARENT=rollback-stack-core-runner.slice\n", "")
	if err := os.Chmod(filepath.Join(out, ".env"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, ".env"), []byte(legacyEnv), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(out, ".env"), 0o400); err != nil {
		t.Fatal(err)
	}
	manifestCmd := exec.Command("sh", "-ec", "{ printf '%s\\n' '# dirextalk-bootstrap-manifest-v1'; sha256sum postgres-password database-url service-token instance-id tls-key tls-cert tls-ca config.yaml .env; } > .manifest.tmp; chmod 0400 .manifest.tmp; mv .manifest.tmp .manifest")
	manifestCmd.Dir = out
	if output, err := manifestCmd.CombinedOutput(); err != nil {
		t.Fatalf("legacy manifest: %v (%s)", err, output)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), []string{"DIREXTALK_BOOTSTRAP_MIGRATION_FAILPOINT=after-env-replace"}); err == nil {
		t.Fatalf("after-env-replace failpoint unexpectedly succeeded: %s", output)
	}
	corruptEnv := strings.Replace(string(mustRead(t, filepath.Join(out, ".env"))), "DIREXTALK_AGENT_STACK_NAME=rollback-stack\n", "DIREXTALK_AGENT_STACK_NAME=corrupted?\n", 1)
	if err := os.Chmod(filepath.Join(out, ".env"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, ".env"), []byte(corruptEnv), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(out, ".env"), 0o400); err != nil {
		t.Fatal(err)
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), []string{"DIREXTALK_BOOTSTRAP_MIGRATION_FAILPOINT=after-env-restore"}); err == nil {
		t.Fatalf("after-env-restore failpoint unexpectedly succeeded: %s", output)
	}
	if _, err := os.Stat(filepath.Join(out, ".cgroup-parent-migration")); err != nil {
		t.Fatalf("rollback failpoint did not retain the migration journal: %v", err)
	}
	rolledBackEnv := string(mustRead(t, filepath.Join(out, ".env")))
	if strings.Contains(rolledBackEnv, "DIREXTALK_EXTENSION_CGROUP_PARENT=") || strings.Contains(rolledBackEnv, "DIREXTALK_CORE_RUNNER_CGROUP_PARENT=") {
		t.Fatal("rollback failpoint did not restore the old environment before manifest restore")
	}
	if output, err := runBootstrap(t, script, out, t.TempDir(), nil); err != nil {
		t.Fatalf("rollback recovery: %v (%s)", err, output)
	}
	if got := mustRead(t, filepath.Join(out, "instance-id")); !bytes.Equal(got, beforeInstance) {
		t.Fatal("rollback recovery rotated instance identity")
	}
	if got := mustRead(t, filepath.Join(out, "postgres-password")); !bytes.Equal(got, beforePassword) {
		t.Fatal("rollback recovery rotated PostgreSQL password")
	}
	for _, name := range []string{".cgroup-parent-migration", ".cgroup-parent-migration.tmp", ".env.migrate-backup", ".env.migrate.tmp", ".manifest.migrate-backup", ".manifest.migrate.tmp"} {
		if _, err := os.Stat(filepath.Join(out, name)); !os.IsNotExist(err) {
			t.Fatalf("rollback recovery left migration artifact %s: %v", name, err)
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
		cmd := exec.Command(script, out, "agent:test", "postgres:test", "localhost")
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
		"instance-id": true, "postgres-password": true, "service-token": true, "core-secret-master-key": true,
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
