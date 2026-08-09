package config

import (
	"os"
	"path/filepath"
	"runtime"
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

func TestLoadAcceptsExplicitVoiceCallbackRelayTokenField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	contents := "core_voice_callback_relay_token_file: /run/secrets/voice_relay_token\n"
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CoreVoiceCallbackRelayTokenFile != "/run/secrets/voice_relay_token" {
		t.Fatalf("voice callback relay token field = %q", cfg.CoreVoiceCallbackRelayTokenFile)
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

func TestLoadCloudFormationRoleARNFromExplicitEnvironmentFallback(t *testing.T) {
	t.Setenv("DIREXTALK_CORE_AWS_CLOUDFORMATION_SERVICE_ROLE_ARN", "arn:aws:iam::123456789012:role/dirextalk-cfn-execution")
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("core_execution_v2_enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CoreAWSCloudFormationServiceRoleARN == "" {
		t.Fatal("explicit role ARN environment fallback was not loaded")
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

func TestValidateCoreAWSRequiresStrictMountedMasterKey(t *testing.T) {
	cfg := validCoreConfig(t)
	cfg.CoreAWSEnabled = true
	keyPath := filepath.Join(filepath.Dir(cfg.DatabaseURLFile), "core-secret-master-key")
	cfg.CoreSecretMasterKeyFile = keyPath
	if err := ValidateCore(&cfg); err != nil {
		t.Fatalf("strict AWS key config rejected: %v", err)
	}
	if cfg.CoreSecretMasterKeyVersion != 1 || !filepath.IsAbs(cfg.CoreSecretMasterKeyFile) {
		t.Fatalf("AWS key config normalization = %#v", cfg)
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateCoreAWS(&cfg); err == nil || !strings.Contains(err.Error(), "core_secret_master_key_file") {
		t.Fatalf("insecure AWS key mode accepted: %v", err)
	}
}

func TestValidateCoreAWSDisabledDoesNotReadKeyFile(t *testing.T) {
	cfg := validCoreConfig(t)
	cfg.CoreSecretMasterKeyFile = filepath.Join(t.TempDir(), "missing")
	if err := ValidateCoreAWS(&cfg); err != nil {
		t.Fatalf("disabled AWS unexpectedly required key: %v", err)
	}
}

func TestValidateCoreExecutionV2RequiresDedicatedCloudFormationRole(t *testing.T) {
	cfg := validCoreConfig(t)
	cfg.CoreExecutionV2Enabled = true
	cfg.CoreAWSEnabled = true
	cfg.CoreExecutionV2ProbeTimeout = time.Second
	cfg.CoreExecutionV2BindingOperations = []string{"target.observe"}
	cfg.CoreAWSSSMReadiness = &AWSWorkloadReadiness{}
	if err := ValidateCoreExecutionV2(&cfg); err == nil || !strings.Contains(err.Error(), "cloudformation_service_role_arn") {
		t.Fatalf("missing service role accepted: %v", err)
	}
	cfg.CoreAWSCloudFormationServiceRoleARN = "arn:aws:iam::123456789012:role/dirextalk-cfn-execution"
	if err := ValidateCoreExecutionV2(&cfg); err != nil {
		t.Fatalf("valid service role rejected: %v", err)
	}
	cfg.CoreAWSCloudFormationServiceRoleARN = "arn:aws:iam::123456789012:role/*"
	if err := ValidateCoreExecutionV2(&cfg); err == nil {
		t.Fatal("wildcard service role accepted")
	}
}

func TestValidateCoreExecutionV2CloudWorkerOnlyDoesNotRequireSSM(t *testing.T) {
	cfg := validCoreConfig(t)
	cfg.CoreExecutionV2Enabled = true
	cfg.CoreAWSSSMReadiness = nil
	cfg.CoreExecutionV2ProbeTimeout = 0
	cfg.CoreExecutionV2BindingOperations = nil
	cfg.CoreAWSCloudFormationServiceRoleARN = ""
	if err := ValidateCoreExecutionV2(&cfg); err != nil {
		t.Fatalf("Cloud Worker-only Execution V2 rejected: %v", err)
	}
}

func TestValidateCloudWorkerModelRelayEndpointRequiresExactV1Path(t *testing.T) {
	const serverName = "model-relay.example.test"
	for _, endpoint := range []string{
		"https://model-relay.example.test",
		"https://model-relay.example.test/",
		"https://model-relay.example.test/v1/",
		"https://model-relay.example.test/%76%31",
	} {
		if _, err := validateCloudWorkerModelRelayEndpoint(endpoint, serverName); err == nil || !strings.Contains(err.Error(), "exact /v1 path") {
			t.Fatalf("invalid Model Relay endpoint %q accepted: %v", endpoint, err)
		}
	}
	if host, err := validateCloudWorkerModelRelayEndpoint("https://model-relay.example.test:443/v1", serverName); err != nil || host != serverName {
		t.Fatalf("valid Model Relay endpoint host=%q err=%v", host, err)
	}
}

func TestValidateCoreAWSRejectsSymlinkedMasterKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on Windows")
	}
	cfg := validCoreConfig(t)
	cfg.CoreAWSEnabled = true
	root := filepath.Dir(cfg.DatabaseURLFile)
	target := filepath.Join(root, "core-secret-master-key-target")
	link := filepath.Join(root, "core-secret-master-key-link")
	if err := os.WriteFile(target, []byte(strings.Repeat("K", 32)), 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	cfg.CoreSecretMasterKeyFile = link
	if err := ValidateCoreAWS(&cfg); err == nil {
		t.Fatal("symlinked AWS master key accepted")
	}
}

func TestValidateCoreExtensionEnabledFailsClosedOnPartialConfig(t *testing.T) {
	cfg := validCoreConfig(t)
	cfg.CoreExtensionEnabled = true
	if err := ValidateCore(&cfg); err == nil || !strings.Contains(err.Error(), "core_extension") {
		t.Fatalf("partial extension error = %v", err)
	}
}

func TestValidateExtensionWorkspaceRootRequiresExactSharedIdentity(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership and mode contract")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o770); err != nil {
		t.Fatal(err)
	}
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	if _, err := validateExtensionWorkspaceRoot(root, "workspace", uid, gid); err != nil {
		t.Fatalf("exact shared workspace rejected: %v", err)
	}
	for _, tc := range []struct {
		name     string
		uid, gid uint32
		mode     os.FileMode
	}{
		{name: "private mode", uid: uid, gid: gid, mode: 0o700},
		{name: "wrong owner", uid: uid + 1, gid: gid, mode: 0o770},
		{name: "wrong group", uid: uid, gid: gid + 1, mode: 0o770},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(root, tc.mode); err != nil {
				t.Fatal(err)
			}
			if _, err := validateExtensionWorkspaceRoot(root, "workspace", tc.uid, tc.gid); err == nil {
				t.Fatal("invalid shared workspace accepted")
			}
		})
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
	cfg.CoreKnowledgeEmbeddingProfileID = "11111111-1111-4111-8111-111111111111"
	cfg.CoreKnowledgeVectorDimension = 384
	cfg.CoreKnowledgeSweepInterval = 30 * time.Second
	if err := ValidateCore(&cfg); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCoreVoiceDisabledDoesNotRequireProviderSecrets(t *testing.T) {
	cfg := validCoreConfig(t)
	cfg.CoreVoiceEnabled = false
	cfg.CoreVoiceAppID = ""
	if err := ValidateCore(&cfg); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCoreVoiceRequiresProtectedFreshOnlyBinding(t *testing.T) {
	cfg := validCoreConfig(t)
	root := filepath.Dir(cfg.DatabaseURLFile)
	write := func(name, value string) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	cfg.CoreVoiceEnabled = true
	cfg.CapabilityAccountGeneration = 1
	cfg.CoreVoiceAppID = "123456789012345678901234"
	cfg.CoreVoiceCallbackEnabled = true
	cfg.CoreVoiceCallbackListenAddress = ":0"
	cfg.CoreVoiceWebhookURL = "https://message.example.test/_p2p/agent/voice/webhook"
	cfg.CoreVoiceCustomLLMURL = "https://message.example.test/_p2p/agent/voice/volc/custom-llm"
	cfg.CoreVoiceConversationProfileID = "11111111-1111-4111-8111-111111111111"
	cfg.CoreVoiceSpeechProfileID = "22222222-2222-4222-8222-222222222222"
	cfg.CoreVoiceAccessKeyIDFile = write("voice-access", "access")
	cfg.CoreVoiceSecretAccessKeyFile = write("voice-secret", "secret")
	cfg.CoreVoiceRTCAppKeyFile = write("voice-rtc", "rtc")
	cfg.CoreVoiceWebhookSecretFile = write("voice-webhook", "callback-secret")
	cfg.CoreVoiceRelayTokenFile = write("voice-relay", "relay-secret")
	if err := ValidateCore(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.CoreVoiceProvider != "volc_voice" || cfg.CoreVoiceHost != "https://rtc.volcengineapi.com" {
		t.Fatalf("voice defaults not applied: %#v", cfg)
	}

	if err := ValidateCore(&cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.CoreVoiceCallbackTLSCertFile != cfg.TLSCertFile || cfg.CoreVoiceCallbackTLSKeyFile != cfg.TLSKeyFile {
		t.Fatalf("callback TLS fallback not applied: %#v", cfg)
	}
}

func TestValidateCoreVoiceRejectsInsecureCallbackURL(t *testing.T) {
	cfg := validCoreConfig(t)
	cfg.CoreVoiceEnabled = true
	cfg.CapabilityAccountGeneration = 1
	cfg.CoreVoiceAppID = "123456789012345678901234"
	cfg.CoreVoiceWebhookURL = "http://message.example.test/voice"
	cfg.CoreVoiceCustomLLMURL = "https://message.example.test/voice"
	cfg.CoreVoiceConversationProfileID = "11111111-1111-4111-8111-111111111111"
	cfg.CoreVoiceSpeechProfileID = "22222222-2222-4222-8222-222222222222"
	root := filepath.Dir(cfg.DatabaseURLFile)
	for _, name := range []string{"access", "secret", "rtc", "webhook", "relay"} {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("value"), 0o600); err != nil {
			t.Fatal(err)
		}
		switch name {
		case "access":
			cfg.CoreVoiceAccessKeyIDFile = path
		case "secret":
			cfg.CoreVoiceSecretAccessKeyFile = path
		case "rtc":
			cfg.CoreVoiceRTCAppKeyFile = path
		case "webhook":
			cfg.CoreVoiceWebhookSecretFile = path
		case "relay":
			cfg.CoreVoiceRelayTokenFile = path
		}
	}
	if err := ValidateCore(&cfg); err == nil || !strings.Contains(err.Error(), "core_voice_webhook_url") {
		t.Fatalf("insecure callback URL error = %v", err)
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
	keyPath := write("core-secret-master-key", strings.Repeat("K", 32))
	if err := os.Chmod(keyPath, 0o400); err != nil {
		t.Fatal(err)
	}
	return Config{InstanceID: "00000000-0000-4000-8000-000000000000", DatabaseURLFile: write("db", "postgres://core"), TLSCertFile: write("tls.crt", "cert"), TLSKeyFile: write("tls.key", "key"), ServiceTokenFile: write("token", strings.Repeat("A", 43)), CoreSecretMasterKeyFile: keyPath, CoreTaskMaxConcurrency: 4, CoreTaskLeaseTTL: 30 * time.Second, CoreScheduleSweepInterval: time.Second, CoreShutdownGrace: 30 * time.Second}
}
