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

func TestValidateCoreRequiresStrictMountedMasterKey(t *testing.T) {
	cfg := validCoreConfig(t)
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
	if err := ValidateCoreSecretMasterKey(&cfg); err == nil || !strings.Contains(err.Error(), "core_secret_master_key_file") {
		t.Fatalf("insecure master key mode accepted: %v", err)
	}
}

func TestValidateCoreSecretMasterKeyRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions differ on Windows")
	}
	cfg := validCoreConfig(t)
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
	if err := ValidateCoreSecretMasterKey(&cfg); err == nil {
		t.Fatal("symlinked master key accepted")
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
	cfg.CoreVoiceCallbackRelayTokenFile = write("voice-relay", "relay-secret")
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
			cfg.CoreVoiceCallbackRelayTokenFile = path
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

func TestValidateCoreStaticSitesRequiresExplicitExistingRoot(t *testing.T) {
	cfg := validCoreConfig(t)
	cfg.CoreStaticSitesRoot = t.TempDir()
	if err := ValidateCoreStaticSites(&cfg); err == nil || !strings.Contains(err.Error(), "require core_static_sites_enabled") {
		t.Fatalf("disabled partial config err=%v", err)
	}
	cfg.CoreStaticSitesEnabled = true
	cfg.CoreStaticSitesPublicOrigin = "https://s3.dirextalk.ai"
	if err := ValidateCoreStaticSites(&cfg); err != nil || !filepath.IsAbs(cfg.CoreStaticSitesRoot) {
		t.Fatalf("enabled root=%q err=%v", cfg.CoreStaticSitesRoot, err)
	}
	cfg.CoreStaticSitesPublicOrigin = "/relative"
	if err := ValidateCoreStaticSites(&cfg); err == nil {
		t.Fatal("relative static-site public origin was accepted")
	}
	cfg.CoreStaticSitesPublicOrigin = "https://s3.dirextalk.ai"
	cfg.CoreStaticSitesRoot = filepath.Join(t.TempDir(), "missing")
	if err := ValidateCoreStaticSites(&cfg); err == nil {
		t.Fatal("missing static-site root was accepted")
	}
}
