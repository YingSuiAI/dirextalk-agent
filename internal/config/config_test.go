package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestLoadCommonReadsDatabaseURLOnlyFromMountedSecretFile(t *testing.T) {
	path := writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require\n")
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", path)
	t.Setenv("AGENT_DATABASE_URL", "postgres://must-not-be-used")

	common, err := LoadCommon()
	if err != nil {
		t.Fatalf("LoadCommon: %v", err)
	}
	if common.DatabaseURL != "postgres://agent:password@db.example/agent?sslmode=require" {
		t.Fatalf("unexpected database URL source")
	}
}

func TestLoadCommonRejectsLegacyDatabaseURLEnvironmentVariable(t *testing.T) {
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", "")
	t.Setenv("AGENT_DATABASE_URL", "postgres://legacy")

	_, err := LoadCommon()
	if err == nil || !strings.Contains(err.Error(), "AGENT_DATABASE_URL_FILE is required") {
		t.Fatalf("LoadCommon error = %v", err)
	}
}

func TestLoadServerRequiresMountedRuntimeSecretDirectory(t *testing.T) {
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
	t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
	t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
	t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
	t.Setenv("AGENT_MODEL_PROFILES_FILE", "model-profiles.json")
	t.Setenv("AGENT_MOUNTED_SECRETS_DIR", "")

	_, err := LoadServer()
	if err == nil || !strings.Contains(err.Error(), "AGENT_MOUNTED_SECRETS_DIR is required") {
		t.Fatalf("LoadServer() error = %v", err)
	}
}

func TestLoadServerRequiresModelProfileCatalog(t *testing.T) {
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
	t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
	t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
	t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
	t.Setenv("AGENT_MOUNTED_SECRETS_DIR", t.TempDir())
	t.Setenv("AGENT_MODEL_PROFILES_FILE", "")

	_, err := LoadServer()
	if err == nil || !strings.Contains(err.Error(), "AGENT_MODEL_PROFILES_FILE is required") {
		t.Fatalf("LoadServer() error = %v", err)
	}
}

func TestLoadServerRequiresMountedAgentMasterKey(t *testing.T) {
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
	t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
	t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
	t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
	t.Setenv("AGENT_MOUNTED_SECRETS_DIR", t.TempDir())
	t.Setenv("AGENT_MODEL_PROFILES_FILE", "model-profiles.json")
	t.Setenv("AGENT_MASTER_KEY_FILE", "")

	_, err := LoadServer()
	if err == nil || !strings.Contains(err.Error(), "AGENT_MASTER_KEY_FILE is required") {
		t.Fatalf("LoadServer() error = %v", err)
	}
}

func TestLoadServerRejectsMutableOrReservedReaperImageTags(t *testing.T) {
	for _, image := range []string{
		"registry.example/reaper:latest@sha256:" + strings.Repeat("a", 64),
		"registry.example/reaper:v1.0.3@sha256:" + strings.Repeat("a", 64),
		"registry.example/reaper:v0.1.0@sha256:" + strings.Repeat("a", 64),
		"registry.example/reaper:alpha",
	} {
		t.Run(image, func(t *testing.T) {
			t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
			t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
			t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
			t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
			t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
			t.Setenv("AGENT_MOUNTED_SECRETS_DIR", t.TempDir())
			t.Setenv("AGENT_MODEL_PROFILES_FILE", "model-profiles.json")
			t.Setenv("AGENT_MASTER_KEY_FILE", "master-key")
			t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", image)
			if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "immutable digest-pinned") {
				t.Fatalf("image %q error=%v", image, err)
			}
		})
	}
}

func TestLoadServerRequiresCredentialFreeGRPCSWorkerControlEndpointForAWS(t *testing.T) {
	tests := map[string]struct {
		endpoint string
		valid    bool
	}{
		"missing":         {endpoint: ""},
		"non grpcs":       {endpoint: "https://worker-control.internal:9444"},
		"embedded secret": {endpoint: "grpcs://worker:secret@worker-control.internal:9444"},
		"non-443 port":    {endpoint: "grpcs://worker-control.internal:9444"},
		"valid":           {endpoint: "grpcs://worker-control.y1.dirextalk.ai:443", valid: true},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			setValidServerEnvironment(t)
			t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
			t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
			t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", test.endpoint)
			t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")

			server, err := LoadServer()
			if !test.valid {
				if err == nil || !strings.Contains(err.Error(), "AGENT_WORKER_CONTROL_ENDPOINT") {
					t.Fatalf("endpoint %q error=%v", test.endpoint, err)
				}
				return
			}
			if err != nil || server.WorkerControlEndpoint != test.endpoint {
				t.Fatalf("LoadServer endpoint=%q error=%v", server.WorkerControlEndpoint, err)
			}
		})
	}
}

func TestLoadServerKeepsAWSControlFailClosedUnlessExplicitlyEnabled(t *testing.T) {
	setValidServerEnvironment(t)
	t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", "grpcs://worker-control.y1.dirextalk.ai:443")
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")

	server, err := LoadServer()
	if err != nil || server.EnableAWSControl {
		t.Fatalf("LoadServer() enable_aws=%v error=%v", server.EnableAWSControl, err)
	}

	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
	server, err = LoadServer()
	if err != nil || !server.EnableAWSControl {
		t.Fatalf("enabled LoadServer() enable_aws=%v error=%v", server.EnableAWSControl, err)
	}
}

func TestLoadServerKeepsManagedPreparationAWSBehindIndependentExplicitGate(t *testing.T) {
	setValidServerEnvironment(t)
	t.Setenv("AGENT_AWS_REAPER_IMAGE_URI", "registry.example/reaper:v0.1.0-alpha.1@sha256:"+strings.Repeat("d", 64))
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT", "grpcs://worker-control.y1.dirextalk.ai:443")
	t.Setenv("AGENT_WORKER_CONTROL_ENDPOINT_SERVICE_NAME", "com.amazonaws.vpce.ap-northeast-3.vpce-svc-0123456789abcdef0")

	server, err := LoadServer()
	if err != nil || server.EnableManagedPreparationAWS {
		t.Fatalf("default managed preparation gate=%v error=%v", server.EnableManagedPreparationAWS, err)
	}

	t.Setenv("AGENT_ENABLE_MANAGED_PREPARATION_AWS", "true")
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "requires AGENT_ENABLE_AWS_CONTROL=true") {
		t.Fatalf("managed preparation without AWS control error=%v", err)
	}

	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
	server, err = LoadServer()
	if err != nil || !server.EnableManagedPreparationAWS {
		t.Fatalf("explicit managed preparation gate=%v error=%v", server.EnableManagedPreparationAWS, err)
	}
}

func TestLoadServerRejectsInvalidAWSControlFlagOrMissingImage(t *testing.T) {
	setValidServerEnvironment(t)
	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "yes")
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "must be true or false") {
		t.Fatalf("invalid flag error=%v", err)
	}

	t.Setenv("AGENT_ENABLE_AWS_CONTROL", "true")
	if _, err := LoadServer(); err == nil || !strings.Contains(err.Error(), "AGENT_AWS_REAPER_IMAGE_URI is required") {
		t.Fatalf("missing image error=%v", err)
	}
}

func TestValidateMountedSecretFileRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix permission bits")
	}
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ValidateMountedSecretFile(path); err == nil {
		t.Fatal("expected loose permissions to be rejected")
	}
}

func writeSecretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func setValidServerEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("AGENT_INSTANCE_ID", uuid.NewString())
	t.Setenv("AGENT_DATABASE_URL_FILE", writeSecretFile(t, "postgres://agent:password@db.example/agent?sslmode=require"))
	t.Setenv("AGENT_TLS_CERT_FILE", "tls.crt")
	t.Setenv("AGENT_TLS_KEY_FILE", "tls.key")
	t.Setenv("AGENT_SERVICE_KEY_PEPPER_FILE", "pepper")
	t.Setenv("AGENT_MOUNTED_SECRETS_DIR", t.TempDir())
	t.Setenv("AGENT_MODEL_PROFILES_FILE", "model-profiles.json")
	t.Setenv("AGENT_MASTER_KEY_FILE", "master-key")
}
