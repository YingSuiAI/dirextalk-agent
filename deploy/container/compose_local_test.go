package container_test

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLocalComposeDefinesGatedPostgresAgentStack(t *testing.T) {
	raw := readArtifact(t, "compose.local.yaml")
	var document map[string]any
	if err := yaml.Unmarshal([]byte(raw), &document); err != nil {
		t.Fatalf("compose.local.yaml is not valid YAML: %v", err)
	}
	services := asMap(t, document["services"], "services")
	for _, name := range []string{"postgres", "migrate", "bootstrap-service-key", "agent"} {
		if _, ok := services[name]; !ok {
			t.Fatalf("missing required service %q", name)
		}
	}
	for _, forbidden := range []string{"worker", "reaper", "dirextalk-cloud-worker", "dirextalk-aws-reaper"} {
		if _, ok := services[forbidden]; ok {
			t.Fatalf("local stack must not define Worker/Reaper service %q", forbidden)
		}
	}

	postgres := asMap(t, services["postgres"], "postgres")
	image := stringValue(t, postgres["image"], "postgres.image")
	if !strings.Contains(image, "${DIREXTALK_POSTGRES_18_IMAGE_IMMUTABLE_WITH_DIGEST:?") ||
		strings.Contains(strings.ToLower(image), "latest") {
		t.Fatalf("postgres image must be caller-supplied, immutable, and PostgreSQL 18: %q", image)
	}
	if !strings.Contains(raw, "POSTGRES_PASSWORD_FILE: /run/secrets/postgres_password") {
		t.Fatal("PostgreSQL password must be delivered through a Docker secret file")
	}

	volumes := asMap(t, document["volumes"], "volumes")
	if _, ok := volumes["agent_postgres_data"]; !ok {
		t.Fatal("missing persistent named PostgreSQL volume")
	}

	assertDependsCondition(t, services, "migrate", "postgres", "service_healthy")
	assertDependsCondition(t, services, "bootstrap-service-key", "migrate", "service_completed_successfully")
	assertDependsCondition(t, services, "agent", "bootstrap-service-key", "service_completed_successfully")
	for _, name := range []string{"migrate", "bootstrap-service-key", "agent"} {
		service := asMap(t, services[name], name)
		if got := stringValue(t, service["image"], name+".image"); !strings.Contains(got, "${DIREXTALK_AGENT_IMAGE_IMMUTABLE_PRERELEASE_WITH_DIGEST:?") {
			t.Fatalf("%s image must be an immutable caller-supplied Agent image: %q", name, got)
		}
		if got := stringValue(t, service["command"], name+".command"); got == "" {
			t.Fatalf("%s command is required", name)
		}
		assertAgentHardening(t, service, name)
		assertConfigMount(t, service, name)
		if name == "agent" {
			assertReadOnlyBindMount(t, service, "/run/dirextalk/config/model-profiles.json", "AGENT_MODEL_PROFILES_PATH")
			assertReadOnlyBindMount(t, service, "/run/dirextalk/mounted-secrets", "AGENT_MOUNTED_SECRETS_DIR_PATH")
		}
		if _, ok := service["environment"]; ok {
			t.Fatalf("%s must receive runtime parameters from YAML, not Compose environment", name)
		}
	}
	for _, name := range []string{"migrate", "bootstrap-service-key"} {
		service := asMap(t, services[name], name)
		if got := stringValue(t, service["restart"], name+".restart"); got != "no" {
			t.Fatalf("%s must be one-shot (restart=no), got %q", name, got)
		}
	}

	secrets := asMap(t, document["secrets"], "secrets")
	for _, name := range []string{"postgres_password", "agent_postgres_dsn", "agent_tls_cert", "agent_tls_key", "agent_service_key_pepper", "agent_master_key", "agent_bootstrap_service_key"} {
		secret := asMap(t, secrets[name], "secrets."+name)
		file := stringValue(t, secret["file"], "secrets."+name+".file")
		if !strings.HasPrefix(file, "${") || strings.Contains(file, "environment:") {
			t.Fatalf("secret %s must use a host file path, got %q", name, file)
		}
	}
}

func assertReadOnlyBindMount(t *testing.T, service map[string]any, target, sourceVariable string) {
	t.Helper()
	mounts, ok := service["volumes"].([]any)
	if !ok {
		t.Fatalf("agent volumes must include %s", target)
	}
	for _, item := range mounts {
		mount := asMap(t, item, "agent.volume")
		if stringValue(t, mount["target"], "agent.volume.target") != target {
			continue
		}
		if got, ok := mount["read_only"].(bool); !ok || !got {
			t.Fatalf("agent mount %s must be read-only", target)
		}
		if source := stringValue(t, mount["source"], "agent.volume.source"); !strings.Contains(source, "${"+sourceVariable+":?") {
			t.Fatalf("agent mount %s source must use %s path variable, got %q", target, sourceVariable, source)
		}
		return
	}
	t.Fatalf("agent is missing read-only bind mount %s", target)
}

func assertDependsCondition(t *testing.T, services map[string]any, serviceName, dependency, want string) {
	t.Helper()
	service := asMap(t, services[serviceName], serviceName)
	depends := asMap(t, service["depends_on"], serviceName+".depends_on")
	entry := asMap(t, depends[dependency], serviceName+".depends_on."+dependency)
	if got := stringValue(t, entry["condition"], serviceName+" dependency condition"); got != want {
		t.Fatalf("%s depends on %s with condition %q, want %q", serviceName, dependency, got, want)
	}
}

func assertAgentHardening(t *testing.T, service map[string]any, name string) {
	t.Helper()
	if got := stringValue(t, service["user"], name+".user"); got != "65532:65532" {
		t.Fatalf("%s user = %q, want non-root 65532:65532", name, got)
	}
	if got, ok := service["read_only"].(bool); !ok || !got {
		t.Fatalf("%s must use read_only filesystem", name)
	}
	if got := stringValue(t, service["security_opt"], name+".security_opt"); !strings.Contains(got, "no-new-privileges:true") {
		t.Fatalf("%s must set no-new-privileges", name)
	}
	if _, ok := service["cap_drop"]; !ok {
		t.Fatalf("%s must drop all capabilities", name)
	}
}

func assertConfigMount(t *testing.T, service map[string]any, name string) {
	t.Helper()
	mounts, ok := service["volumes"].([]any)
	if !ok {
		t.Fatalf("%s volumes must include a read-only config bind", name)
	}
	for _, item := range mounts {
		mount := asMap(t, item, name+".volume")
		if stringValue(t, mount["target"], name+".volume.target") == "/etc/dirextalk-agent/config.yaml" {
			if got, ok := mount["read_only"].(bool); !ok || !got {
				t.Fatalf("%s Agent config mount must be read-only", name)
			}
			if stringValue(t, mount["source"], name+".volume.source") == "" {
				t.Fatalf("%s Agent config mount source is required", name)
			}
			return
		}
	}
	t.Fatalf("%s is missing /etc/dirextalk-agent/config.yaml mount", name)
}

func asMap(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s must be a mapping, got %T", path, value)
	}
	return result
}

func stringValue(t *testing.T, value any, path string) string {
	t.Helper()
	switch typed := value.(type) {
	case string:
		return typed
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			parts = append(parts, stringValue(t, item, path))
		}
		return strings.Join(parts, " ")
	default:
		t.Fatalf("%s must be a string (or string list), got %T", path, value)
		return ""
	}
}
