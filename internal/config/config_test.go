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
