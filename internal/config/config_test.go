package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadReadsStrictYAMLAndIgnoresOperationalEnvironment(t *testing.T) {
	dir := t.TempDir()
	databaseFile := filepath.Join(dir, "database")
	if err := os.WriteFile(databaseFile, []byte("postgres://yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(dir, "config.yaml")
	contents := "instance_id: 00000000-0000-4000-8000-000000000000\n" +
		"database_url_file: " + databaseFile + "\n" +
		"grpc_listen: ':9555'\n" +
		"enable_aws_control: false\n"
	if err := os.WriteFile(configFile, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_INSTANCE_ID", "11111111-1111-4111-8111-111111111111")
	t.Setenv("AGENT_GRPC_LISTEN", ":9999")
	t.Setenv("AGENT_DATABASE_URL", "postgres://must-not-be-used")

	cfg, err := Load(configFile)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InstanceID != "00000000-0000-4000-8000-000000000000" || cfg.ListenAddress != ":9555" {
		t.Fatalf("YAML values were not loaded: %#v", cfg)
	}
	if err := ValidateCommon(&cfg); err != nil || cfg.DatabaseURL != "postgres://yaml" {
		t.Fatalf("ValidateCommon database source: cfg=%#v err=%v", cfg, err)
	}
}

func TestLoadRejectsUnknownYAMLFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("instance_id: 00000000-0000-4000-8000-000000000000\nunknown_field: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "unknown_field") {
		t.Fatalf("unknown field error = %v", err)
	}
}

func TestValidateServerKeepsAWSGatesClosedByDefault(t *testing.T) {
	cfg := validServerConfig(t)
	if err := ValidateServer(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.EnableAWSControl || cfg.EnableManagedPreparationAWS {
		t.Fatal("AWS gates must default off")
	}
}

func TestValidateServerRejectsMountedSecretContainment(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.MountedSecretsDir = filepath.Dir(cfg.DatabaseURLFile)
	if err := ValidateServer(&cfg); err == nil || !strings.Contains(err.Error(), "must not overlap") {
		t.Fatalf("direct overlap error = %v", err)
	}
}

func TestValidateServerRejectsSymlinkMountedSecretContainment(t *testing.T) {
	cfg := validServerConfig(t)
	realDir := t.TempDir()
	linkDir := filepath.Join(t.TempDir(), "mounted")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	cfg.MountedSecretsDir = linkDir
	cfg.TLSCertFile = filepath.Join(realDir, "tls.crt")
	if err := os.WriteFile(cfg.TLSCertFile, []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateServer(&cfg); err == nil || !strings.Contains(err.Error(), "must not overlap") {
		t.Fatalf("symlink overlap error = %v", err)
	}
}

func TestValidateServerRejectsConfiguredBootstrapKeyOverlap(t *testing.T) {
	cfg := validServerConfig(t)
	cfg.BootstrapServiceKeyFile = filepath.Join(cfg.MountedSecretsDir, "bootstrap.key")
	if err := os.WriteFile(cfg.BootstrapServiceKeyFile, []byte("bootstrap"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateServer(&cfg); err == nil || !strings.Contains(err.Error(), "bootstrap_service_key_file must not overlap") {
		t.Fatalf("bootstrap overlap error = %v", err)
	}
}

func TestValidateServerStoresCanonicalResolvedPaths(t *testing.T) {
	cfg := validServerConfig(t)
	link := filepath.Join(t.TempDir(), "tls.crt")
	if err := os.Symlink(cfg.TLSCertFile, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	cfg.TLSCertFile = link
	if err := ValidateServer(&cfg); err != nil {
		t.Fatal(err)
	}
	want, err := filepath.EvalSymlinks(link)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TLSCertFile != want {
		t.Fatalf("TLS cert path = %q, want canonical %q", cfg.TLSCertFile, want)
	}
}

func validServerConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	mounted := filepath.Join(root, "mounted")
	if err := os.Mkdir(mounted, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return Config{
		Common:          Common{InstanceID: "00000000-0000-4000-8000-000000000000"},
		DatabaseURLFile: write("db", "postgres://yaml"),
		Server:          Server{ListenAddress: ":9443", TLSCertFile: write("tls.crt", "cert"), TLSKeyFile: write("tls.key", "key"), PepperFile: write("pepper", strings.Repeat("p", 32)), MasterKeyFile: write("master", strings.Repeat("m", 32)), MountedSecretsDir: mounted, ModelProfilesFile: "models"},
	}
}

func TestReadMountedSecretTextRejectsMultiline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("value\nsecond"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadMountedSecretText(path); err == nil {
		t.Fatal("multiline mounted secret accepted")
	}
}
