package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadReadsStrictCoreYAMLAndDefaults(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "database")
	if err := os.WriteFile(db, []byte("postgres://yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("instance_id: 00000000-0000-4000-8000-000000000000\ndatabase_url_file: "+db+"\ngrpc_listen: ':9555'\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != ":9555" || cfg.CoreTaskMaxConcurrency != 4 || cfg.CoreTaskLeaseTTL != 30*time.Second {
		t.Fatalf("core config defaults/values = %#v", cfg)
	}
	if err := ValidateCommon(&cfg); err != nil || cfg.DatabaseURL != "postgres://yaml" {
		t.Fatalf("database validation cfg=%#v err=%v", cfg, err)
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

func TestLoadAWSReadinessUsesExplicitSnakeCaseTargetSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := `core_aws_ssm_readiness:
  credential_reference: 00000000-0000-4000-8000-000000000001
  target:
    region: ap-northeast-3
    account_id: "123456789012"
    instance_id: i-0123456789abcdef0
    identity:
      kind: AWS_EC2_SSM
      region: ap-northeast-3
      account_id: "123456789012"
      instance_id: i-0123456789abcdef0
    ec2_document_version: "1"
    ec2_systemd_service: dirextalk-agent.service
    required_instance_tags:
      managed: "true"
`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CoreAWSSSMReadiness == nil || cfg.CoreAWSSSMReadiness.Target.EC2SystemdService != "dirextalk-agent.service" || cfg.CoreAWSSSMReadiness.Target.Identity.InstanceID == "" {
		t.Fatalf("readiness schema not decoded: %#v", cfg.CoreAWSSSMReadiness)
	}
}

func TestValidateCoreRequiresTokenAndBounds(t *testing.T) {
	cfg := validCoreConfig(t)
	if err := ValidateCore(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddress != ":9443" {
		t.Fatalf("default listen address = %q", cfg.ListenAddress)
	}
	cfg.CoreTaskMaxConcurrency = 0
	if err := ValidateCore(&cfg); err == nil || !strings.Contains(err.Error(), "core_task_max_concurrency") {
		t.Fatalf("invalid concurrency error = %v", err)
	}
	cfg = validCoreConfig(t)
	cfg.ServiceTokenFile = ""
	if err := ValidateCore(&cfg); err == nil || !strings.Contains(err.Error(), "service_token_file") {
		t.Fatalf("missing token error = %v", err)
	}
}

func TestValidateCoreExtensionEnabledFailsClosedOnPartialConfig(t *testing.T) {
	cfg := validCoreConfig(t)
	cfg.CoreExtensionEnabled = true
	if err := ValidateCore(&cfg); err == nil || !strings.Contains(err.Error(), "core_extension") {
		t.Fatalf("partial extension error = %v", err)
	}
}

func TestValidateCoreKnowledgeEnabledRequiresProductionComposition(t *testing.T) {
	cfg := validCoreConfig(t)
	root := t.TempDir()
	contentRoot := filepath.Join(root, "content")
	mountRoot := filepath.Join(root, "mount")
	if err := os.Mkdir(contentRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(mountRoot, 0o555); err != nil {
		t.Fatal(err)
	}
	cfg.CoreKnowledgeEnabled = true
	cfg.CoreKnowledgeContentRoot = contentRoot
	cfg.CoreKnowledgeMountRoot = mountRoot
	cfg.CoreKnowledgeContentQuotaBytes = 64 << 20
	cfg.CoreKnowledgeEmbeddingProfileID = "11111111-1111-4111-8111-111111111111"
	cfg.CoreKnowledgeQdrantEndpoint = "https://qdrant.example.test/"
	cfg.CoreKnowledgeQdrantCollection = "knowledge"
	cfg.CoreKnowledgeQdrantDimension = 384
	cfg.CoreKnowledgeSweepInterval = 30 * time.Second
	if err := ValidateCore(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.CoreKnowledgeQdrantEndpoint != "https://qdrant.example.test" {
		t.Fatalf("endpoint normalization = %q", cfg.CoreKnowledgeQdrantEndpoint)
	}
}

func validCoreConfig(t *testing.T) Config {
	t.Helper()
	root := t.TempDir()
	write := func(name, value string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return Config{InstanceID: "00000000-0000-4000-8000-000000000000", DatabaseURLFile: write("db", "postgres://core"), TLSCertFile: write("tls.crt", "cert"), TLSKeyFile: write("tls.key", "key"), ServiceTokenFile: write("token", strings.Repeat("A", 43)), CoreTaskMaxConcurrency: 4, CoreTaskLeaseTTL: 30 * time.Second, CoreScheduleSweepInterval: time.Second, CoreShutdownGrace: 30 * time.Second}
}
