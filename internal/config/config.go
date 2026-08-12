package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config is the complete non-secret Agent process configuration. Secret
// material is represented only by mounted-file paths.
type Config struct {
	InstanceID       string `yaml:"instance_id" mapstructure:"instance_id"`
	DatabaseURL      string `yaml:"-" mapstructure:"-"`
	DatabaseURLFile  string `yaml:"database_url_file" mapstructure:"database_url_file"`
	ListenAddress    string `yaml:"grpc_listen" mapstructure:"grpc_listen"`
	TLSCertFile      string `yaml:"tls_cert_file" mapstructure:"tls_cert_file"`
	TLSKeyFile       string `yaml:"tls_key_file" mapstructure:"tls_key_file"`
	ServiceTokenFile string `yaml:"service_token_file" mapstructure:"service_token_file"`
	// Capability API is a separate mTLS listener used by message-server.  It
	// may reuse the Core certificate/token when no separate material is
	// mounted, but production deployments should provide an independent
	// directional token file.
	CapabilityEnabled                   bool                  `yaml:"capability_enabled" mapstructure:"capability_enabled"`
	CapabilityListenAddress             string                `yaml:"capability_grpc_listen" mapstructure:"capability_grpc_listen"`
	CapabilityCACertFile                string                `yaml:"capability_ca_cert_file" mapstructure:"capability_ca_cert_file"`
	CapabilityTLSCertFile               string                `yaml:"capability_tls_cert_file" mapstructure:"capability_tls_cert_file"`
	CapabilityTLSKeyFile                string                `yaml:"capability_tls_key_file" mapstructure:"capability_tls_key_file"`
	CapabilityTokenFile                 string                `yaml:"capability_token_file" mapstructure:"capability_token_file"`
	CapabilityGrantPublicKeyFile        string                `yaml:"capability_grant_public_key_file" mapstructure:"capability_grant_public_key_file"`
	CapabilityPeerCommonName            string                `yaml:"capability_peer_common_name" mapstructure:"capability_peer_common_name"`
	CapabilityPeerInstanceID            string                `yaml:"capability_peer_instance_id" mapstructure:"capability_peer_instance_id"`
	CapabilityAccountGeneration         int64                 `yaml:"capability_account_generation" mapstructure:"capability_account_generation"`
	CapabilityMaxConcurrentQuery        int                   `yaml:"capability_max_concurrent_query" mapstructure:"capability_max_concurrent_query"`
	CapabilityMaxConcurrentWatch        int                   `yaml:"capability_max_concurrent_watch" mapstructure:"capability_max_concurrent_watch"`
	ProductCapabilityEnabled            bool                  `yaml:"product_capability_enabled" mapstructure:"product_capability_enabled"`
	ProductCapabilityAddress            string                `yaml:"product_capability_address" mapstructure:"product_capability_address"`
	ProductCapabilityCACertFile         string                `yaml:"product_capability_ca_cert_file" mapstructure:"product_capability_ca_cert_file"`
	ProductCapabilityTLSCertFile        string                `yaml:"product_capability_tls_cert_file" mapstructure:"product_capability_tls_cert_file"`
	ProductCapabilityTLSKeyFile         string                `yaml:"product_capability_tls_key_file" mapstructure:"product_capability_tls_key_file"`
	ProductCapabilityTokenFile          string                `yaml:"product_capability_token_file" mapstructure:"product_capability_token_file"`
	ProductCapabilityServerName         string                `yaml:"product_capability_server_name" mapstructure:"product_capability_server_name"`
	ProductCapabilityInstanceID         string                `yaml:"product_capability_instance_id" mapstructure:"product_capability_instance_id"`
	ProductCapabilityAccountGeneration  int64                 `yaml:"product_capability_account_generation" mapstructure:"product_capability_account_generation"`
	EnableHealthService                 bool                  `yaml:"enable_health_service" mapstructure:"enable_health_service"`
	EnableReflection                    bool                  `yaml:"enable_reflection" mapstructure:"enable_reflection"`
	CoreTaskMaxConcurrency              int                   `yaml:"core_task_max_concurrency" mapstructure:"core_task_max_concurrency"`
	CoreTaskLeaseTTL                    time.Duration         `yaml:"core_task_lease_ttl" mapstructure:"core_task_lease_ttl"`
	CoreScheduleSweepInterval           time.Duration         `yaml:"core_schedule_sweep_interval" mapstructure:"core_schedule_sweep_interval"`
	CoreShutdownGrace                   time.Duration         `yaml:"core_shutdown_grace" mapstructure:"core_shutdown_grace"`
	CoreAWSEnabled                      bool                  `yaml:"core_aws_enabled" mapstructure:"core_aws_enabled"`
	CoreSecretMasterKeyFile             string                `yaml:"core_secret_master_key_file" mapstructure:"core_secret_master_key_file"`
	CoreSecretMasterKeyVersion          uint32                `yaml:"core_secret_master_key_version" mapstructure:"core_secret_master_key_version"`
	CoreAWSSSMReadiness                 *AWSWorkloadReadiness `yaml:"core_aws_ssm_readiness" mapstructure:"core_aws_ssm_readiness"`
	CoreAWSECSReadiness                 *AWSWorkloadReadiness `yaml:"core_aws_ecs_readiness" mapstructure:"core_aws_ecs_readiness"`
	CoreAWSCloudFormationServiceRoleARN string                `yaml:"core_aws_cloudformation_service_role_arn" mapstructure:"core_aws_cloudformation_service_role_arn"`
	CoreExtensionEnabled                bool                  `yaml:"core_extension_enabled" mapstructure:"core_extension_enabled"`
	CoreExtensionStagingRoot            string                `yaml:"core_extension_staging_root" mapstructure:"core_extension_staging_root"`
	CoreExtensionWorkspaceRoot          string                `yaml:"core_extension_workspace_root" mapstructure:"core_extension_workspace_root"`
	CoreExtensionRunnerSocket           string                `yaml:"core_extension_runner_socket" mapstructure:"core_extension_runner_socket"`
	CoreExtensionRunnerUID              uint32                `yaml:"core_extension_runner_uid" mapstructure:"core_extension_runner_uid"`
	CoreWorkloadEnabled                 bool                  `yaml:"core_workload_enabled" mapstructure:"core_workload_enabled"`
	CoreWorkloadRunnerSocket            string                `yaml:"core_workload_runner_socket" mapstructure:"core_workload_runner_socket"`
	CoreWorkloadRunnerUID               uint32                `yaml:"core_workload_runner_uid" mapstructure:"core_workload_runner_uid"`
	// execution.v2 is Agent-owned. Cloud Worker reads/cancellation are composed
	// independently; an optional SSM target enables the generic imported-target
	// routes only after their own typed readiness proof succeeds.
	CoreExecutionV2Enabled           bool          `yaml:"core_execution_v2_enabled" mapstructure:"core_execution_v2_enabled"`
	CoreExecutionV2ProbeTimeout      time.Duration `yaml:"core_execution_v2_probe_timeout" mapstructure:"core_execution_v2_probe_timeout"`
	CoreExecutionV2BindingOperations []string      `yaml:"core_execution_v2_binding_operations" mapstructure:"core_execution_v2_binding_operations"`
	CoreCloudWorker                  CloudWorker   `yaml:"core_cloud_worker" mapstructure:"core_cloud_worker"`
	CoreStaticSitesEnabled           bool          `yaml:"core_static_sites_enabled" mapstructure:"core_static_sites_enabled"`
	CoreStaticSitesRoot              string        `yaml:"core_static_sites_root" mapstructure:"core_static_sites_root"`
	CoreKnowledgeEnabled             bool          `yaml:"core_knowledge_enabled" mapstructure:"core_knowledge_enabled"`
	CoreKnowledgeContentRoot         string        `yaml:"core_knowledge_content_root" mapstructure:"core_knowledge_content_root"`
	CoreKnowledgeMountRoot           string        `yaml:"core_knowledge_mount_root" mapstructure:"core_knowledge_mount_root"`
	CoreKnowledgeEmbeddingProfileID  string        `yaml:"core_knowledge_embedding_profile_id" mapstructure:"core_knowledge_embedding_profile_id"`
	CoreKnowledgeVectorDimension     int           `yaml:"core_knowledge_vector_dimension" mapstructure:"core_knowledge_vector_dimension"`
	CoreKnowledgeSweepInterval       time.Duration `yaml:"core_knowledge_sweep_interval" mapstructure:"core_knowledge_sweep_interval"`
	// Native Voice is an optional Agent-owned capability.  Credentials are
	// mounted-file references only; the values are read request-locally and
	// never written to the Agent database or returned by the capability API.
	CoreVoiceEnabled                bool   `yaml:"core_voice_enabled" mapstructure:"core_voice_enabled"`
	CoreVoiceProvider               string `yaml:"core_voice_provider" mapstructure:"core_voice_provider"`
	CoreVoiceHost                   string `yaml:"core_voice_host" mapstructure:"core_voice_host"`
	CoreVoiceRegion                 string `yaml:"core_voice_region" mapstructure:"core_voice_region"`
	CoreVoiceAppID                  string `yaml:"core_voice_app_id" mapstructure:"core_voice_app_id"`
	CoreVoiceChatAppID              string `yaml:"core_voice_chat_app_id" mapstructure:"core_voice_chat_app_id"`
	CoreVoiceAIUserID               string `yaml:"core_voice_ai_user_id" mapstructure:"core_voice_ai_user_id"`
	CoreVoiceAccessKeyIDFile        string `yaml:"core_voice_access_key_id_file" mapstructure:"core_voice_access_key_id_file"`
	CoreVoiceSecretAccessKeyFile    string `yaml:"core_voice_secret_access_key_file" mapstructure:"core_voice_secret_access_key_file"`
	CoreVoiceRTCAppKeyFile          string `yaml:"core_voice_rtc_app_key_file" mapstructure:"core_voice_rtc_app_key_file"`
	CoreVoiceWebhookURL             string `yaml:"core_voice_webhook_url" mapstructure:"core_voice_webhook_url"`
	CoreVoiceWebhookSecretFile      string `yaml:"core_voice_webhook_secret_file" mapstructure:"core_voice_webhook_secret_file"`
	CoreVoiceCallbackRelayTokenFile string `yaml:"core_voice_callback_relay_token_file" mapstructure:"core_voice_callback_relay_token_file"`
	// CoreVoiceRelayTokenFile is retained as an in-process alias for callers
	// constructing Config values directly. YAML deployments should use the
	// explicit callback name above so it matches the split compose contract.
	CoreVoiceRelayTokenFile          string        `yaml:"core_voice_relay_token_file" mapstructure:"core_voice_relay_token_file"`
	CoreVoiceCustomLLMURL            string        `yaml:"core_voice_custom_llm_url" mapstructure:"core_voice_custom_llm_url"`
	CoreVoiceConversationProfileID   string        `yaml:"core_voice_conversation_profile_id" mapstructure:"core_voice_conversation_profile_id"`
	CoreVoiceSpeechProfileID         string        `yaml:"core_voice_speech_profile_id" mapstructure:"core_voice_speech_profile_id"`
	CoreVoiceClientTranscriptEnabled bool          `yaml:"core_voice_client_transcript_enabled" mapstructure:"core_voice_client_transcript_enabled"`
	CoreVoiceCallbackEnabled         bool          `yaml:"core_voice_callback_enabled" mapstructure:"core_voice_callback_enabled"`
	CoreVoiceCallbackListenAddress   string        `yaml:"core_voice_callback_listen" mapstructure:"core_voice_callback_listen"`
	CoreVoiceCallbackTLSCertFile     string        `yaml:"core_voice_callback_tls_cert_file" mapstructure:"core_voice_callback_tls_cert_file"`
	CoreVoiceCallbackTLSKeyFile      string        `yaml:"core_voice_callback_tls_key_file" mapstructure:"core_voice_callback_tls_key_file"`
	CoreVoiceCallbackReadTimeout     time.Duration `yaml:"core_voice_callback_read_timeout" mapstructure:"core_voice_callback_read_timeout"`
	CoreVoiceCallbackWriteTimeout    time.Duration `yaml:"core_voice_callback_write_timeout" mapstructure:"core_voice_callback_write_timeout"`
}

// CloudWorker is the non-secret, exact production binding for the single
// ephemeral Pi Worker route. Credential material remains in CoreAWS storage;
// this block pins only its durable ID and verified revision.
type CloudWorker struct {
	Enabled                       bool          `yaml:"enabled" mapstructure:"enabled"`
	AccountID                     string        `yaml:"account_id" mapstructure:"account_id"`
	Region                        string        `yaml:"region" mapstructure:"region"`
	CredentialID                  string        `yaml:"credential_id" mapstructure:"credential_id"`
	CredentialRevision            uint64        `yaml:"credential_revision" mapstructure:"credential_revision"`
	InstanceType                  string        `yaml:"instance_type" mapstructure:"instance_type"`
	Architecture                  string        `yaml:"architecture" mapstructure:"architecture"`
	RootDeviceName                string        `yaml:"root_device_name" mapstructure:"root_device_name"`
	VolumeGiB                     uint64        `yaml:"volume_gib" mapstructure:"volume_gib"`
	VolumeType                    string        `yaml:"volume_type" mapstructure:"volume_type"`
	VolumeIOPS                    uint64        `yaml:"volume_iops" mapstructure:"volume_iops"`
	VolumeThroughputMiB           uint64        `yaml:"volume_throughput_mib" mapstructure:"volume_throughput_mib"`
	AMIID                         string        `yaml:"ami_id" mapstructure:"ami_id"`
	AMIDigest                     string        `yaml:"ami_digest" mapstructure:"ami_digest"`
	WorkerReleaseDigest           string        `yaml:"worker_release_digest" mapstructure:"worker_release_digest"`
	PiRuntimeDigest               string        `yaml:"pi_runtime_digest" mapstructure:"pi_runtime_digest"`
	HostNetworkPolicySHA256       string        `yaml:"host_network_policy_sha256" mapstructure:"host_network_policy_sha256"`
	VPCID                         string        `yaml:"vpc_id" mapstructure:"vpc_id"`
	SubnetID                      string        `yaml:"subnet_id" mapstructure:"subnet_id"`
	DNSResolverCIDRs              []string      `yaml:"dns_resolver_cidrs" mapstructure:"dns_resolver_cidrs"`
	TLSProxyCIDRs                 []string      `yaml:"tls_proxy_cidrs" mapstructure:"tls_proxy_cidrs"`
	AllowedFQDNs                  []string      `yaml:"allowed_fqdns" mapstructure:"allowed_fqdns"`
	OutboundProxyURL              string        `yaml:"outbound_proxy_url" mapstructure:"outbound_proxy_url"`
	OutboundProxyServerName       string        `yaml:"outbound_proxy_server_name" mapstructure:"outbound_proxy_server_name"`
	OutboundProxyTrustSHA256      string        `yaml:"outbound_proxy_trust_bundle_sha256" mapstructure:"outbound_proxy_trust_bundle_sha256"`
	ArtifactBucket                string        `yaml:"artifact_bucket" mapstructure:"artifact_bucket"`
	ArtifactBasePrefix            string        `yaml:"artifact_base_prefix" mapstructure:"artifact_base_prefix"`
	ArtifactKMSKeyARN             string        `yaml:"artifact_kms_key_arn" mapstructure:"artifact_kms_key_arn"`
	ArtifactRetention             time.Duration `yaml:"artifact_retention" mapstructure:"artifact_retention"`
	WorkerControlListenAddress    string        `yaml:"worker_control_listen" mapstructure:"worker_control_listen"`
	WorkerControlEndpoint         string        `yaml:"worker_control_endpoint" mapstructure:"worker_control_endpoint"`
	WorkerControlServerName       string        `yaml:"worker_control_server_name" mapstructure:"worker_control_server_name"`
	WorkerControlTLSCertFile      string        `yaml:"worker_control_tls_cert_file" mapstructure:"worker_control_tls_cert_file"`
	WorkerControlTLSKeyFile       string        `yaml:"worker_control_tls_key_file" mapstructure:"worker_control_tls_key_file"`
	WorkerControlTrustSHA256      string        `yaml:"worker_control_trust_bundle_sha256" mapstructure:"worker_control_trust_bundle_sha256"`
	WorkerControlMaxConcurrentRPC int           `yaml:"worker_control_max_concurrent_rpc" mapstructure:"worker_control_max_concurrent_rpc"`
	ModelRelayListenAddress       string        `yaml:"model_relay_listen" mapstructure:"model_relay_listen"`
	ModelRelayEndpoint            string        `yaml:"model_relay_endpoint" mapstructure:"model_relay_endpoint"`
	ModelRelayServerName          string        `yaml:"model_relay_server_name" mapstructure:"model_relay_server_name"`
	ModelRelayTLSCertFile         string        `yaml:"model_relay_tls_cert_file" mapstructure:"model_relay_tls_cert_file"`
	ModelRelayTLSKeyFile          string        `yaml:"model_relay_tls_key_file" mapstructure:"model_relay_tls_key_file"`
	ModelRelayTrustSHA256         string        `yaml:"model_relay_trust_bundle_sha256" mapstructure:"model_relay_trust_bundle_sha256"`
	IIDCertificateFile            string        `yaml:"iid_certificate_file" mapstructure:"iid_certificate_file"`
	PricingCatalogFile            string        `yaml:"pricing_catalog_file" mapstructure:"pricing_catalog_file"`
	PricingCatalogSHA256          string        `yaml:"pricing_catalog_sha256" mapstructure:"pricing_catalog_sha256"`
	RuntimeQualificationFile      string        `yaml:"runtime_qualification_file" mapstructure:"runtime_qualification_file"`
	RuntimeQualificationSHA256    string        `yaml:"runtime_qualification_sha256" mapstructure:"runtime_qualification_sha256"`
	QuoteTTL                      time.Duration `yaml:"quote_ttl" mapstructure:"quote_ttl"`
	MaximumCatalogAge             time.Duration `yaml:"maximum_catalog_age" mapstructure:"maximum_catalog_age"`
	ContingencyBasisPoints        uint32        `yaml:"contingency_basis_points" mapstructure:"contingency_basis_points"`
	AbsoluteHardLimitMicros       int64         `yaml:"absolute_hard_limit_micros" mapstructure:"absolute_hard_limit_micros"`
	MaxRuntime                    time.Duration `yaml:"max_runtime" mapstructure:"max_runtime"`
	MaxTokens                     uint64        `yaml:"max_tokens" mapstructure:"max_tokens"`
	MaxOutputBytes                uint64        `yaml:"max_output_bytes" mapstructure:"max_output_bytes"`
	ControllerPollInterval        time.Duration `yaml:"controller_poll_interval" mapstructure:"controller_poll_interval"`
	WorkerHeartbeatInterval       time.Duration `yaml:"worker_heartbeat_interval" mapstructure:"worker_heartbeat_interval"`
	ReaperInterval                time.Duration `yaml:"reaper_interval" mapstructure:"reaper_interval"`
	CompletionOutboxInterval      time.Duration `yaml:"completion_outbox_interval" mapstructure:"completion_outbox_interval"`
}

// AWSWorkloadReadiness is non-secret, explicit startup proof configuration.
// Credentials are resolved from the Agent database by reference only; a
// missing or stale target leaves the capability disabled.
type AWSWorkloadReadiness struct {
	CredentialReference string                      `yaml:"credential_reference" mapstructure:"credential_reference"`
	Target              coreworkload.TargetSettings `yaml:"target" mapstructure:"target"`
}

const (
	defaultCoreTaskMaxConcurrency    = 4
	defaultCoreTaskLeaseTTL          = 30 * time.Second
	defaultCoreScheduleSweepInterval = 1 * time.Second
	defaultCoreShutdownGrace         = 30 * time.Second
	defaultKnowledgeSweepInterval    = 30 * time.Second
)

// Load reads a strict YAML file through Viper.
func Load(path string) (Config, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Config{}, errors.New("config path is required")
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config file: %w", err)
	}
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetDefault("enable_health_service", true)
	v.SetDefault("core_task_max_concurrency", defaultCoreTaskMaxConcurrency)
	v.SetDefault("core_task_lease_ttl", defaultCoreTaskLeaseTTL)
	v.SetDefault("core_schedule_sweep_interval", defaultCoreScheduleSweepInterval)
	v.SetDefault("core_shutdown_grace", defaultCoreShutdownGrace)
	v.SetDefault("core_knowledge_sweep_interval", defaultKnowledgeSweepInterval)
	v.SetDefault("core_execution_v2_probe_timeout", 10*time.Second)
	v.SetDefault("core_secret_master_key_version", uint32(1))
	v.SetDefault("core_voice_callback_read_timeout", 5*time.Second)
	v.SetDefault("core_voice_callback_write_timeout", 15*time.Second)
	if err := v.ReadConfig(bytes.NewReader(contents)); err != nil {
		return Config{}, fmt.Errorf("read config through viper: %w", err)
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("viper config decode: %w", err)
	}
	if strings.TrimSpace(cfg.CoreAWSCloudFormationServiceRoleARN) == "" {
		cfg.CoreAWSCloudFormationServiceRoleARN = strings.TrimSpace(os.Getenv("DIREXTALK_CORE_AWS_CLOUDFORMATION_SERVICE_ROLE_ARN"))
	}
	var strictCfg Config
	decoder := yaml.NewDecoder(bytes.NewReader(contents))
	decoder.KnownFields(true)
	if err := decoder.Decode(&strictCfg); err != nil {
		return Config{}, fmt.Errorf("strict config decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("config file must contain one YAML document")
		}
		return Config{}, fmt.Errorf("strict config decode: %w", err)
	}
	return cfg, nil
}

// ValidateCore validates the complete Core v1 process configuration.
func ValidateCore(cfg *Config) error {
	if err := ValidateCommon(cfg); err != nil {
		return err
	}
	if err := ValidateCoreSecretMasterKey(cfg); err != nil {
		return err
	}
	if err := ValidateCoreAWS(cfg); err != nil {
		return err
	}
	if err := validateCoreRuntime(cfg); err != nil {
		return err
	}
	if err := ValidateCoreKnowledge(cfg); err != nil {
		return err
	}
	if err := ValidateCoreExtension(cfg); err != nil {
		return err
	}
	if err := ValidateCoreWorkload(cfg); err != nil {
		return err
	}
	if err := ValidateCoreExecutionV2(cfg); err != nil {
		return err
	}
	if err := ValidateCoreCloudWorker(cfg); err != nil {
		return err
	}
	if err := ValidateCoreStaticSites(cfg); err != nil {
		return err
	}
	if err := ValidateCoreVoice(cfg); err != nil {
		return err
	}
	if strings.TrimSpace(cfg.ListenAddress) == "" {
		cfg.ListenAddress = ":9443"
	}
	if strings.TrimSpace(cfg.TLSCertFile) == "" || strings.TrimSpace(cfg.TLSKeyFile) == "" {
		return errors.New("tls_cert_file and tls_key_file are required")
	}
	if strings.TrimSpace(cfg.ServiceTokenFile) == "" {
		return errors.New("service_token_file is required")
	}
	for name, path := range map[string]string{
		"tls_cert_file":      cfg.TLSCertFile,
		"tls_key_file":       cfg.TLSKeyFile,
		"service_token_file": cfg.ServiceTokenFile,
	} {
		resolved, err := canonicalPath(path)
		if err != nil {
			return fmt.Errorf("canonicalize %s: %w", name, err)
		}
		if name == "service_token_file" {
			if err := auth.ValidateServiceTokenFile(resolved); err != nil {
				return err
			}
			cfg.ServiceTokenFile = resolved
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s must resolve to a regular file", name)
		}
		if name == "tls_key_file" && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%s must not be group/world accessible", name)
		}
		switch name {
		case "tls_cert_file":
			cfg.TLSCertFile = resolved
		case "tls_key_file":
			cfg.TLSKeyFile = resolved
		}
	}
	if err := ValidateCapability(cfg); err != nil {
		return err
	}
	if err := ValidateProductCapability(cfg); err != nil {
		return err
	}
	return nil
}

// ValidateCoreSecretMasterKey validates the mounted Agent secret key used by
// every durable secret envelope (model/provider, conversation snapshots,
// extension, execution.v2, and AWS). It checks only path ownership/mode and
// never loads key bytes into configuration.
func ValidateCoreSecretMasterKey(cfg *Config) error {
	if cfg == nil {
		return errors.New("core secret master key config is required")
	}
	if cfg.CoreSecretMasterKeyVersion == 0 {
		cfg.CoreSecretMasterKeyVersion = secretbox.KeyVersionMin
	}
	if strings.TrimSpace(cfg.CoreSecretMasterKeyFile) == "" {
		return errors.New("core_secret_master_key_file is required")
	}
	resolved, err := filepath.Abs(strings.TrimSpace(cfg.CoreSecretMasterKeyFile))
	if err != nil {
		return fmt.Errorf("resolve core_secret_master_key_file: %w", err)
	}
	if err := secretbox.ValidateMountedFile(resolved); err != nil {
		return fmt.Errorf("core_secret_master_key_file: %w", err)
	}
	cfg.CoreSecretMasterKeyFile = resolved
	return nil
}

// ValidateCoreAWS retains the AWS-specific validation entry point while the
// mounted master key is now required for every Core durable-secret surface.
func ValidateCoreAWS(cfg *Config) error {
	if cfg == nil || !cfg.CoreAWSEnabled {
		return nil
	}
	return ValidateCoreSecretMasterKey(cfg)
}

// ValidateCoreExecutionV2 keeps the production execution capability opt-in.
// The composition root performs the stronger dependency/readiness checks;
// this function only validates process-level values that can be checked
// without opening a database or contacting AWS.
func ValidateCoreExecutionV2(cfg *Config) error {
	if cfg == nil || !cfg.CoreExecutionV2Enabled {
		return nil
	}
	// No SSM readiness block means this process is publishing only the
	// strongly typed Cloud Worker routes. Their complete dependency proof is
	// performed by the composition root, which has access to the store/port.
	if cfg.CoreAWSSSMReadiness == nil {
		return nil
	}
	if cfg.CoreExecutionV2ProbeTimeout <= 0 || cfg.CoreExecutionV2ProbeTimeout > 2*time.Minute {
		return errors.New("core_execution_v2_probe_timeout must be between 1ns and 2m")
	}
	if len(cfg.CoreExecutionV2BindingOperations) == 0 {
		return errors.New("core_execution_v2_binding_operations must explicitly allow at least one operation")
	}
	seen := map[string]struct{}{}
	for _, operation := range cfg.CoreExecutionV2BindingOperations {
		operation = strings.TrimSpace(operation)
		if operation == "" || len(operation) > 64 || strings.ContainsAny(operation, "\r\n\x00 ") {
			return errors.New("core_execution_v2_binding_operations contains an invalid operation")
		}
		if _, ok := seen[operation]; ok {
			return errors.New("core_execution_v2_binding_operations contains a duplicate operation")
		}
		seen[operation] = struct{}{}
	}
	if cfg.CoreAWSEnabled == false {
		return errors.New("core_aws_ssm_readiness requires core_aws_enabled")
	}
	if !awsServiceRoleARNRE.MatchString(strings.TrimSpace(cfg.CoreAWSCloudFormationServiceRoleARN)) {
		return errors.New("core_aws_cloudformation_service_role_arn must be an explicit IAM role ARN")
	}
	return nil
}

var (
	cloudWorkerDigestRE  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	cloudWorkerAccountRE = regexp.MustCompile(`^[0-9]{12}$`)
	cloudWorkerRegionRE  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	cloudWorkerAWSIDRE   = regexp.MustCompile(`^(?:ami|vpc|subnet)-[0-9a-f]{8,17}$`)
)

// ValidateCoreCloudWorker makes the paid route an all-or-nothing opt-in. A
// disabled block never affects the local sandbox/MCP/Skills path; an enabled
// block cannot publish or start with a partial AWS, TLS, pricing, or release
// qualification binding.
func ValidateCoreCloudWorker(cfg *Config) error {
	if cfg == nil || !cfg.CoreCloudWorker.Enabled {
		return nil
	}
	worker := &cfg.CoreCloudWorker
	if !cfg.CoreExecutionV2Enabled || !cfg.CoreAWSEnabled || !cfg.CapabilityEnabled || !cfg.ProductCapabilityEnabled {
		return errors.New("core_cloud_worker requires core_execution_v2, core_aws, Capability, and Product Capability")
	}
	if cfg.CapabilityAccountGeneration <= 0 || cfg.ProductCapabilityAccountGeneration != cfg.CapabilityAccountGeneration {
		return errors.New("core_cloud_worker requires one matching positive Capability account generation")
	}
	if !cloudWorkerAccountRE.MatchString(strings.TrimSpace(worker.AccountID)) ||
		!cloudWorkerRegionRE.MatchString(strings.TrimSpace(worker.Region)) {
		return errors.New("core_cloud_worker account_id and region are invalid")
	}
	credential, err := uuid.Parse(strings.TrimSpace(worker.CredentialID))
	if err != nil || credential == uuid.Nil || credential.String() != strings.TrimSpace(worker.CredentialID) || worker.CredentialRevision == 0 {
		return errors.New("core_cloud_worker credential_id and credential_revision must be exact")
	}
	if strings.TrimSpace(worker.InstanceType) == "" || len(worker.InstanceType) > 64 ||
		(worker.Architecture != "x86_64" && worker.Architecture != "arm64") ||
		!strings.HasPrefix(worker.RootDeviceName, "/dev/") || worker.VolumeGiB < 8 || worker.VolumeGiB > 16384 ||
		worker.VolumeType != "gp3" || worker.VolumeIOPS < 3000 || worker.VolumeIOPS > 16000 ||
		worker.VolumeThroughputMiB < 125 || worker.VolumeThroughputMiB > 1000 ||
		!cloudWorkerAWSIDRE.MatchString(worker.AMIID) || !strings.HasPrefix(worker.AMIID, "ami-") ||
		!cloudWorkerAWSIDRE.MatchString(worker.VPCID) || !strings.HasPrefix(worker.VPCID, "vpc-") ||
		!cloudWorkerAWSIDRE.MatchString(worker.SubnetID) || !strings.HasPrefix(worker.SubnetID, "subnet-") {
		return errors.New("core_cloud_worker compute or placement binding is invalid")
	}
	for name, digest := range map[string]string{
		"ami_digest": worker.AMIDigest, "worker_release_digest": worker.WorkerReleaseDigest,
		"pi_runtime_digest": worker.PiRuntimeDigest, "host_network_policy_sha256": worker.HostNetworkPolicySHA256,
		"outbound_proxy_trust_bundle_sha256": worker.OutboundProxyTrustSHA256,
		"worker_control_trust_bundle_sha256": worker.WorkerControlTrustSHA256,
		"model_relay_trust_bundle_sha256":    worker.ModelRelayTrustSHA256,
		"pricing_catalog_sha256":             worker.PricingCatalogSHA256,
		"runtime_qualification_sha256":       worker.RuntimeQualificationSHA256,
	} {
		if !cloudWorkerDigestRE.MatchString(strings.TrimSpace(digest)) {
			return fmt.Errorf("core_cloud_worker %s must be a lowercase SHA-256", name)
		}
	}
	if err := validateCloudWorkerNetwork(worker); err != nil {
		return err
	}
	controlHost, err := validateCloudWorkerHTTPS("worker_control_endpoint", worker.WorkerControlEndpoint, worker.WorkerControlServerName)
	if err != nil {
		return err
	}
	relayHost, err := validateCloudWorkerModelRelayEndpoint(worker.ModelRelayEndpoint, worker.ModelRelayServerName)
	if err != nil {
		return err
	}
	allowed := make(map[string]bool, len(worker.AllowedFQDNs))
	for _, value := range worker.AllowedFQDNs {
		allowed[strings.ToLower(strings.TrimSpace(value))] = true
	}
	if !allowed[controlHost] || !allowed[relayHost] {
		return errors.New("core_cloud_worker allowed_fqdns must include WorkerControl and Model Relay server names")
	}
	if strings.TrimSpace(worker.WorkerControlListenAddress) == "" || strings.TrimSpace(worker.ModelRelayListenAddress) == "" ||
		worker.WorkerControlListenAddress == worker.ModelRelayListenAddress ||
		worker.WorkerControlListenAddress == cfg.ListenAddress || worker.ModelRelayListenAddress == cfg.ListenAddress ||
		worker.WorkerControlListenAddress == cfg.CapabilityListenAddress || worker.ModelRelayListenAddress == cfg.CapabilityListenAddress {
		return errors.New("core_cloud_worker private listeners must be non-empty and distinct")
	}
	if worker.WorkerControlMaxConcurrentRPC == 0 {
		worker.WorkerControlMaxConcurrentRPC = 64
	}
	if worker.WorkerControlMaxConcurrentRPC < 1 || worker.WorkerControlMaxConcurrentRPC > 1024 {
		return errors.New("core_cloud_worker worker_control_max_concurrent_rpc is invalid")
	}
	for name, path := range map[string]string{
		"worker_control_tls_cert_file": worker.WorkerControlTLSCertFile,
		"worker_control_tls_key_file":  worker.WorkerControlTLSKeyFile,
		"model_relay_tls_cert_file":    worker.ModelRelayTLSCertFile,
		"model_relay_tls_key_file":     worker.ModelRelayTLSKeyFile,
		"iid_certificate_file":         worker.IIDCertificateFile,
		"pricing_catalog_file":         worker.PricingCatalogFile,
		"runtime_qualification_file":   worker.RuntimeQualificationFile,
	} {
		resolved, resolveErr := canonicalPath(path)
		if resolveErr != nil {
			return fmt.Errorf("canonicalize core_cloud_worker %s: %w", name, resolveErr)
		}
		info, statErr := os.Stat(resolved)
		if statErr != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("core_cloud_worker %s must resolve to a regular file", name)
		}
		if strings.HasSuffix(name, "tls_key_file") && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("core_cloud_worker %s must not be group/world accessible", name)
		}
		switch name {
		case "worker_control_tls_cert_file":
			worker.WorkerControlTLSCertFile = resolved
		case "worker_control_tls_key_file":
			worker.WorkerControlTLSKeyFile = resolved
		case "model_relay_tls_cert_file":
			worker.ModelRelayTLSCertFile = resolved
		case "model_relay_tls_key_file":
			worker.ModelRelayTLSKeyFile = resolved
		case "iid_certificate_file":
			worker.IIDCertificateFile = resolved
		case "pricing_catalog_file":
			worker.PricingCatalogFile = resolved
		case "runtime_qualification_file":
			worker.RuntimeQualificationFile = resolved
		}
	}
	if len(worker.ArtifactBucket) < 3 || len(worker.ArtifactBucket) > 63 ||
		worker.ArtifactBasePrefix == "" || strings.HasPrefix(worker.ArtifactBasePrefix, "/") ||
		!strings.HasSuffix(worker.ArtifactBasePrefix, "/") || strings.Contains(worker.ArtifactBasePrefix, "..") ||
		!strings.HasPrefix(worker.ArtifactKMSKeyARN, "arn:aws:kms:"+worker.Region+":"+worker.AccountID+":key/") {
		return errors.New("core_cloud_worker artifact binding is invalid")
	}
	if worker.ArtifactRetention <= 0 || worker.ArtifactRetention > 30*24*time.Hour {
		return errors.New("core_cloud_worker artifact_retention must be between 1ns and 30d")
	}
	if worker.QuoteTTL == 0 {
		worker.QuoteTTL = 5 * time.Minute
	}
	if worker.ControllerPollInterval == 0 {
		worker.ControllerPollInterval = 500 * time.Millisecond
	}
	if worker.WorkerHeartbeatInterval == 0 {
		worker.WorkerHeartbeatInterval = 10 * time.Second
	}
	if worker.ReaperInterval == 0 {
		worker.ReaperInterval = 30 * time.Second
	}
	if worker.CompletionOutboxInterval == 0 {
		worker.CompletionOutboxInterval = time.Second
	}
	if worker.QuoteTTL <= 0 || worker.QuoteTTL > 15*time.Minute || worker.MaximumCatalogAge < 0 || worker.MaximumCatalogAge > 15*time.Minute ||
		worker.ContingencyBasisPoints > 10_000 || worker.AbsoluteHardLimitMicros <= 0 ||
		worker.MaxRuntime < time.Minute || worker.MaxRuntime > 24*time.Hour || worker.MaxRuntime%time.Second != 0 ||
		worker.MaxTokens == 0 || worker.MaxTokens > 10_000_000 || worker.MaxOutputBytes == 0 || worker.MaxOutputBytes > cloudworker.MaxCloudWorkerOutputBytes ||
		worker.ControllerPollInterval <= 0 || worker.ControllerPollInterval > 30*time.Second ||
		worker.WorkerHeartbeatInterval < time.Second || worker.WorkerHeartbeatInterval > time.Minute ||
		worker.ReaperInterval < time.Second || worker.ReaperInterval > 10*time.Minute ||
		worker.CompletionOutboxInterval < 100*time.Millisecond || worker.CompletionOutboxInterval > time.Minute {
		return errors.New("core_cloud_worker cost, limit, or controller interval is invalid")
	}
	worker.AccountID = strings.TrimSpace(worker.AccountID)
	worker.Region = strings.TrimSpace(worker.Region)
	worker.CredentialID = strings.TrimSpace(worker.CredentialID)
	worker.WorkerControlServerName = controlHost
	worker.ModelRelayServerName = relayHost
	return nil
}

func validateCloudWorkerNetwork(worker *CloudWorker) error {
	if worker == nil || len(worker.DNSResolverCIDRs) == 0 || len(worker.DNSResolverCIDRs) > 16 ||
		len(worker.TLSProxyCIDRs) == 0 || len(worker.TLSProxyCIDRs) > 16 ||
		len(worker.AllowedFQDNs) == 0 || len(worker.AllowedFQDNs) > 64 {
		return errors.New("core_cloud_worker network grants are incomplete")
	}
	seen := map[string]bool{}
	for _, cidr := range append(append([]string(nil), worker.DNSResolverCIDRs...), worker.TLSProxyCIDRs...) {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil || ip.To4() == nil || network.String() != cidr || cidr == "0.0.0.0/0" || seen["cidr:"+cidr] {
			return errors.New("core_cloud_worker network CIDRs must be unique canonical IPv4 ranges")
		}
		seen["cidr:"+cidr] = true
	}
	for index, value := range worker.AllowedFQDNs {
		value = strings.ToLower(strings.TrimSpace(value))
		if value == "" || len(value) > 253 || !strings.Contains(value, ".") || net.ParseIP(value) != nil ||
			strings.ContainsAny(value, "*/:@\r\n\x00") || seen["fqdn:"+value] {
			return errors.New("core_cloud_worker allowed_fqdns contains an invalid value")
		}
		seen["fqdn:"+value] = true
		worker.AllowedFQDNs[index] = value
	}
	proxyHost, err := validateCloudWorkerHTTPS("outbound_proxy_url", worker.OutboundProxyURL, worker.OutboundProxyServerName)
	if err != nil {
		return err
	}
	parsed, _ := url.Parse(worker.OutboundProxyURL)
	if parsed.Port() != "443" || parsed.Path != "" {
		return errors.New("core_cloud_worker outbound_proxy_url must use port 443 without a path")
	}
	worker.OutboundProxyServerName = proxyHost
	return nil
}

func validateCloudWorkerHTTPS(name, raw, serverName string) (string, error) {
	raw = strings.TrimSpace(raw)
	serverName = strings.ToLower(strings.TrimSpace(serverName))
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		parsed.Hostname() != serverName || serverName == "" || !strings.Contains(serverName, ".") || net.ParseIP(serverName) != nil ||
		strings.ContainsAny(serverName, "*/:@\r\n\x00") {
		return "", fmt.Errorf("core_cloud_worker %s must be an exact HTTPS server binding", name)
	}
	return serverName, nil
}

func validateCloudWorkerModelRelayEndpoint(raw, serverName string) (string, error) {
	host, err := validateCloudWorkerHTTPS("model_relay_endpoint", raw, serverName)
	if err != nil {
		return "", err
	}
	parsed, _ := url.Parse(strings.TrimSpace(raw))
	if parsed.Path != "/v1" || parsed.RawPath != "" {
		return "", errors.New("core_cloud_worker model_relay_endpoint must use the exact /v1 path")
	}
	return host, nil
}

var awsServiceRoleARNRE = regexp.MustCompile(`^arn:aws:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_-]{1,512}$`)

// ValidateCoreVoice validates the optional Agent-owned Native Voice graph.
// Disabled mode deliberately leaves all voice fields untouched so an Agent
// can run without Volc credentials or a callback listener.  A deployment that
// enables Voice must provide explicit provider/profile references and
// protected mounted files; the runtime never persists their contents.
func ValidateCoreVoice(cfg *Config) error {
	if cfg == nil || !cfg.CoreVoiceEnabled {
		return nil
	}
	if strings.TrimSpace(cfg.CoreVoiceProvider) == "" {
		cfg.CoreVoiceProvider = "volc_voice"
	}
	if cfg.CoreVoiceProvider != "volc_voice" {
		return errors.New("core_voice_provider must be volc_voice")
	}
	if cfg.CapabilityAccountGeneration <= 0 {
		return errors.New("core_voice requires a positive capability_account_generation")
	}
	if strings.TrimSpace(cfg.CoreVoiceHost) == "" {
		cfg.CoreVoiceHost = "https://rtc.volcengineapi.com"
	}
	if strings.TrimSpace(cfg.CoreVoiceRegion) == "" {
		cfg.CoreVoiceRegion = "cn-north-1"
	}
	if strings.TrimSpace(cfg.CoreVoiceAppID) == "" {
		return errors.New("core_voice_app_id is required")
	}
	if strings.TrimSpace(cfg.CoreVoiceAccessKeyIDFile) == "" || strings.TrimSpace(cfg.CoreVoiceSecretAccessKeyFile) == "" || strings.TrimSpace(cfg.CoreVoiceRTCAppKeyFile) == "" || strings.TrimSpace(cfg.CoreVoiceWebhookSecretFile) == "" {
		return errors.New("core_voice credential files are required")
	}
	if strings.TrimSpace(cfg.CoreVoiceCallbackRelayTokenFile) == "" {
		cfg.CoreVoiceCallbackRelayTokenFile = cfg.CoreVoiceRelayTokenFile
	}
	if strings.TrimSpace(cfg.CoreVoiceCallbackRelayTokenFile) == "" {
		return errors.New("core_voice_callback_relay_token_file is required")
	}
	for name, value := range map[string]string{
		"core_voice_access_key_id_file":        cfg.CoreVoiceAccessKeyIDFile,
		"core_voice_secret_access_key_file":    cfg.CoreVoiceSecretAccessKeyFile,
		"core_voice_rtc_app_key_file":          cfg.CoreVoiceRTCAppKeyFile,
		"core_voice_webhook_secret_file":       cfg.CoreVoiceWebhookSecretFile,
		"core_voice_callback_relay_token_file": cfg.CoreVoiceCallbackRelayTokenFile,
	} {
		resolved, err := canonicalPath(value)
		if err != nil {
			return fmt.Errorf("canonicalize %s: %w", name, err)
		}
		if err := ValidateMountedSecretFile(resolved); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		switch name {
		case "core_voice_access_key_id_file":
			cfg.CoreVoiceAccessKeyIDFile = resolved
		case "core_voice_secret_access_key_file":
			cfg.CoreVoiceSecretAccessKeyFile = resolved
		case "core_voice_rtc_app_key_file":
			cfg.CoreVoiceRTCAppKeyFile = resolved
		case "core_voice_webhook_secret_file":
			cfg.CoreVoiceWebhookSecretFile = resolved
		case "core_voice_callback_relay_token_file":
			cfg.CoreVoiceCallbackRelayTokenFile = resolved
		}
	}
	cfg.CoreVoiceRelayTokenFile = cfg.CoreVoiceCallbackRelayTokenFile
	for name, raw := range map[string]string{
		"core_voice_host":           cfg.CoreVoiceHost,
		"core_voice_webhook_url":    cfg.CoreVoiceWebhookURL,
		"core_voice_custom_llm_url": cfg.CoreVoiceCustomLLMURL,
	} {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "\x00\r\n") {
			return fmt.Errorf("%s must be an absolute HTTPS URL", name)
		}
	}
	if strings.TrimSpace(cfg.CoreVoiceConversationProfileID) == "" || strings.TrimSpace(cfg.CoreVoiceSpeechProfileID) == "" {
		return errors.New("core_voice conversation and speech profile references are required")
	}
	conversationProfile, err := uuid.Parse(strings.TrimSpace(cfg.CoreVoiceConversationProfileID))
	if err != nil || conversationProfile == uuid.Nil || conversationProfile.String() != strings.TrimSpace(cfg.CoreVoiceConversationProfileID) {
		return errors.New("core_voice_conversation_profile_id must be a UUID")
	}
	speechProfile, err := uuid.Parse(strings.TrimSpace(cfg.CoreVoiceSpeechProfileID))
	if err != nil || speechProfile == uuid.Nil || speechProfile.String() != strings.TrimSpace(cfg.CoreVoiceSpeechProfileID) {
		return errors.New("core_voice_speech_profile_id must be a UUID")
	}
	if cfg.CoreVoiceCallbackEnabled {
		if strings.TrimSpace(cfg.CoreVoiceCallbackListenAddress) == "" {
			cfg.CoreVoiceCallbackListenAddress = ":8444"
		}
		if strings.TrimSpace(cfg.ListenAddress) != "" && cfg.CoreVoiceCallbackListenAddress == cfg.ListenAddress {
			return errors.New("core_voice_callback_listen must not reuse the Core gRPC listen address")
		}
		if cfg.CoreVoiceCallbackReadTimeout == 0 {
			cfg.CoreVoiceCallbackReadTimeout = 5 * time.Second
		}
		if cfg.CoreVoiceCallbackWriteTimeout == 0 {
			cfg.CoreVoiceCallbackWriteTimeout = 15 * time.Second
		}
		if strings.TrimSpace(cfg.CoreVoiceCallbackTLSCertFile) == "" {
			cfg.CoreVoiceCallbackTLSCertFile = cfg.TLSCertFile
		}
		if strings.TrimSpace(cfg.CoreVoiceCallbackTLSKeyFile) == "" {
			cfg.CoreVoiceCallbackTLSKeyFile = cfg.TLSKeyFile
		}
		for name, path := range map[string]string{
			"core_voice_callback_tls_cert_file": cfg.CoreVoiceCallbackTLSCertFile,
			"core_voice_callback_tls_key_file":  cfg.CoreVoiceCallbackTLSKeyFile,
		} {
			resolved, err := canonicalPath(path)
			if err != nil {
				return fmt.Errorf("canonicalize %s: %w", name, err)
			}
			info, statErr := os.Stat(resolved)
			if statErr != nil || !info.Mode().IsRegular() {
				return fmt.Errorf("%s must resolve to a regular file", name)
			}
			if name == "core_voice_callback_tls_cert_file" {
				cfg.CoreVoiceCallbackTLSCertFile = resolved
			} else {
				cfg.CoreVoiceCallbackTLSKeyFile = resolved
			}
		}
		if cfg.CoreVoiceCallbackReadTimeout < time.Second || cfg.CoreVoiceCallbackReadTimeout > time.Minute {
			return errors.New("core_voice_callback_read_timeout must be between 1s and 1m")
		}
		if cfg.CoreVoiceCallbackWriteTimeout < time.Second || cfg.CoreVoiceCallbackWriteTimeout > 2*time.Minute {
			return errors.New("core_voice_callback_write_timeout must be between 1s and 2m")
		}
	}
	if !cfg.CoreVoiceCallbackEnabled {
		return errors.New("core_voice_callback_enabled must be true when voice relay URLs are configured")
	}
	cfg.CoreVoiceProvider = strings.TrimSpace(cfg.CoreVoiceProvider)
	cfg.CoreVoiceHost = strings.TrimRight(strings.TrimSpace(cfg.CoreVoiceHost), "/")
	cfg.CoreVoiceRegion = strings.TrimSpace(cfg.CoreVoiceRegion)
	cfg.CoreVoiceConversationProfileID = strings.TrimSpace(cfg.CoreVoiceConversationProfileID)
	cfg.CoreVoiceSpeechProfileID = strings.TrimSpace(cfg.CoreVoiceSpeechProfileID)
	return nil
}

// ValidateCapability validates the message-server → Agent neutral capability
// listener.  Existing Core-only configurations remain valid when the listener
// is disabled; production config enables it explicitly.
func ValidateCapability(cfg *Config) error {
	if cfg == nil || !cfg.CapabilityEnabled {
		return nil
	}
	if strings.TrimSpace(cfg.CapabilityListenAddress) == "" {
		cfg.CapabilityListenAddress = ":50052"
	}
	if strings.TrimSpace(cfg.CapabilityPeerCommonName) == "" {
		cfg.CapabilityPeerCommonName = "message-server-client"
	}
	if strings.TrimSpace(cfg.CapabilityPeerInstanceID) == "" {
		// A single deployment commonly uses one instance identity on both
		// sides. Multi-instance deployments must set the explicit peer value.
		cfg.CapabilityPeerInstanceID = cfg.InstanceID
	}
	if strings.TrimSpace(cfg.CapabilityPeerInstanceID) == "" {
		return errors.New("capability_peer_instance_id is required")
	}
	if cfg.CapabilityMaxConcurrentQuery <= 0 {
		cfg.CapabilityMaxConcurrentQuery = 32
	}
	if cfg.CapabilityMaxConcurrentWatch <= 0 {
		cfg.CapabilityMaxConcurrentWatch = 64
	}
	if cfg.CapabilityAccountGeneration <= 0 {
		return errors.New("capability_account_generation must be positive")
	}
	if strings.TrimSpace(cfg.CapabilityTLSCertFile) == "" {
		cfg.CapabilityTLSCertFile = cfg.TLSCertFile
	}
	if strings.TrimSpace(cfg.CapabilityTLSKeyFile) == "" {
		cfg.CapabilityTLSKeyFile = cfg.TLSKeyFile
	}
	if strings.TrimSpace(cfg.CapabilityTokenFile) == "" {
		cfg.CapabilityTokenFile = cfg.ServiceTokenFile
	}
	if strings.TrimSpace(cfg.CapabilityGrantPublicKeyFile) == "" {
		return errors.New("capability_grant_public_key_file is required")
	}
	for name, path := range map[string]string{
		"capability_ca_cert_file":  cfg.CapabilityCACertFile,
		"capability_tls_cert_file": cfg.CapabilityTLSCertFile,
		"capability_tls_key_file":  cfg.CapabilityTLSKeyFile,
	} {
		resolved, err := canonicalPath(path)
		if err != nil {
			return fmt.Errorf("canonicalize %s: %w", name, err)
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s must resolve to a regular file", name)
		}
		switch name {
		case "capability_ca_cert_file":
			cfg.CapabilityCACertFile = resolved
		case "capability_tls_cert_file":
			cfg.CapabilityTLSCertFile = resolved
		case "capability_tls_key_file":
			cfg.CapabilityTLSKeyFile = resolved
		}
	}
	token, err := canonicalPath(cfg.CapabilityTokenFile)
	if err != nil {
		return fmt.Errorf("canonicalize capability_token_file: %w", err)
	}
	if err := auth.ValidateServiceTokenFile(token); err != nil {
		return fmt.Errorf("capability token: %w", err)
	}
	cfg.CapabilityTokenFile = token
	grantKey, err := canonicalPath(cfg.CapabilityGrantPublicKeyFile)
	if err != nil {
		return fmt.Errorf("canonicalize capability_grant_public_key_file: %w", err)
	}
	if info, err := os.Stat(grantKey); err != nil || !info.Mode().IsRegular() {
		return errors.New("capability_grant_public_key_file must resolve to a regular file")
	}
	key, err := os.ReadFile(grantKey)
	if err != nil {
		return fmt.Errorf("capability_grant_public_key_file cannot be read: %w", err)
	}
	if _, err := capv1.ParseGrantPublicKey(key); err != nil {
		return fmt.Errorf("capability_grant_public_key_file is invalid: %w", err)
	}
	cfg.CapabilityGrantPublicKeyFile = grantKey
	return nil
}

// ValidateProductCapability validates the optional Agent→message-server
// callback client. It is disabled by default so Core-only deployments do not
// need mounted callback credentials.
func ValidateProductCapability(cfg *Config) error {
	if cfg == nil || !cfg.ProductCapabilityEnabled {
		return nil
	}
	for name, value := range map[string]string{
		"product_capability_address":       cfg.ProductCapabilityAddress,
		"product_capability_ca_cert_file":  cfg.ProductCapabilityCACertFile,
		"product_capability_tls_cert_file": cfg.ProductCapabilityTLSCertFile,
		"product_capability_tls_key_file":  cfg.ProductCapabilityTLSKeyFile,
		"product_capability_token_file":    cfg.ProductCapabilityTokenFile,
		"product_capability_instance_id":   cfg.ProductCapabilityInstanceID,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if cfg.ProductCapabilityAccountGeneration <= 0 {
		return errors.New("product_capability_account_generation must be positive")
	}
	for name, path := range map[string]string{
		"product_capability_ca_cert_file":  cfg.ProductCapabilityCACertFile,
		"product_capability_tls_cert_file": cfg.ProductCapabilityTLSCertFile,
		"product_capability_tls_key_file":  cfg.ProductCapabilityTLSKeyFile,
	} {
		resolved, err := canonicalPath(path)
		if err != nil {
			return fmt.Errorf("canonicalize %s: %w", name, err)
		}
		info, statErr := os.Stat(resolved)
		if statErr != nil || !info.Mode().IsRegular() {
			return fmt.Errorf("%s must resolve to a regular file", name)
		}
		switch name {
		case "product_capability_ca_cert_file":
			cfg.ProductCapabilityCACertFile = resolved
		case "product_capability_tls_cert_file":
			cfg.ProductCapabilityTLSCertFile = resolved
		case "product_capability_tls_key_file":
			cfg.ProductCapabilityTLSKeyFile = resolved
		}
	}
	token, err := canonicalPath(cfg.ProductCapabilityTokenFile)
	if err != nil {
		return fmt.Errorf("canonicalize product_capability_token_file: %w", err)
	}
	if info, statErr := os.Stat(token); statErr != nil || !info.Mode().IsRegular() {
		return errors.New("product_capability_token_file must resolve to a regular file")
	}
	cfg.ProductCapabilityTokenFile = token
	return nil
}

// ValidateCoreWorkload validates only the explicit local Core Runner
// composition. Disabled mode remains planning/confirmation-only.
func ValidateCoreWorkload(cfg *Config) error {
	if cfg == nil || !cfg.CoreWorkloadEnabled {
		return nil
	}
	if cfg.CoreWorkloadRunnerUID == 0 {
		return errors.New("core_workload_runner_uid must be positive")
	}
	if runtime.GOOS != "windows" && cfg.CoreWorkloadRunnerUID == uint32(os.Geteuid()) {
		return errors.New("core_workload_runner_uid must differ from Agent uid")
	}
	value := strings.TrimSpace(cfg.CoreWorkloadRunnerSocket)
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return errors.New("core_workload_runner_socket must be an absolute clean path")
	}
	return nil
}

// ValidateCoreExtension validates the optional isolated MCP/Skill graph.
// Disabled mode leaves existing Core configurations untouched; enabled mode
// requires private Agent-owned roots and an explicit runner identity.
func ValidateCoreExtension(cfg *Config) error {
	if cfg == nil || !cfg.CoreExtensionEnabled {
		return nil
	}
	if cfg.CoreExtensionRunnerUID == 0 {
		return errors.New("core_extension_runner_uid must be positive")
	}
	stagingRoot, err := validateExtensionRoot(cfg.CoreExtensionStagingRoot, "core_extension_staging_root")
	if err != nil {
		return err
	}
	workspaceRoot, err := validateExtensionWorkspaceRoot(
		cfg.CoreExtensionWorkspaceRoot,
		"core_extension_workspace_root",
		cfg.CoreExtensionRunnerUID,
		uint32(os.Getegid()),
	)
	if err != nil {
		return err
	}
	if pathsOverlap(stagingRoot, workspaceRoot) {
		return errors.New("core_extension_staging_root and core_extension_workspace_root must not overlap")
	}
	for name, value := range map[string]string{
		"core_extension_runner_socket": cfg.CoreExtensionRunnerSocket,
	} {
		value = strings.TrimSpace(value)
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s must be an absolute clean path", name)
		}
	}
	return nil
}

func validateExtensionRoot(path, name string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%s must be an absolute clean path", name)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", fmt.Errorf("%s must resolve without symlinks", name)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%s must resolve to a directory", name)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s must be Agent-owned and private", name)
	}
	return path, nil
}

func validateExtensionWorkspaceRoot(path, name string, runnerUID, agentGID uint32) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%s must be an absolute clean path", name)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", fmt.Errorf("%s must resolve without symlinks", name)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%s must resolve to a directory", name)
	}
	if runtime.GOOS != "windows" {
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || runnerUID == 0 || agentGID == 0 || stat.Uid != runnerUID || stat.Gid != agentGID || info.Mode().Perm() != 0o770 {
			return "", fmt.Errorf("%s must be runner-owned and Agent-group writable", name)
		}
	}
	return path, nil
}

// ValidateCoreKnowledge validates the optional production Knowledge wiring.
// Disabled mode intentionally accepts the existing Core configuration without
// requiring any Knowledge paths, credentials, or backend settings.
func ValidateCoreKnowledge(cfg *Config) error {
	if cfg == nil || !cfg.CoreKnowledgeEnabled {
		return nil
	}
	contentRoot, err := validateKnowledgeRoot(cfg.CoreKnowledgeContentRoot, "core_knowledge_content_root", false)
	if err != nil {
		return err
	}
	mountRoot, err := validateKnowledgeRoot(cfg.CoreKnowledgeMountRoot, "core_knowledge_mount_root", true)
	if err != nil {
		return err
	}
	if pathsOverlap(contentRoot, mountRoot) {
		return errors.New("core_knowledge_content_root and core_knowledge_mount_root must not overlap")
	}
	parsedProfile, err := uuid.Parse(strings.TrimSpace(cfg.CoreKnowledgeEmbeddingProfileID))
	if err != nil || parsedProfile == uuid.Nil || parsedProfile.String() != strings.TrimSpace(cfg.CoreKnowledgeEmbeddingProfileID) {
		return errors.New("core_knowledge_embedding_profile_id must be a UUID")
	}
	if cfg.CoreKnowledgeVectorDimension <= 0 || cfg.CoreKnowledgeVectorDimension > 2000 {
		return errors.New("core_knowledge_vector_dimension must be between 1 and 2000")
	}
	if cfg.CoreKnowledgeSweepInterval < 100*time.Millisecond || cfg.CoreKnowledgeSweepInterval > time.Hour {
		return errors.New("core_knowledge_sweep_interval must be between 100ms and 1h")
	}
	cfg.CoreKnowledgeContentRoot = contentRoot
	cfg.CoreKnowledgeMountRoot = mountRoot
	cfg.CoreKnowledgeEmbeddingProfileID = parsedProfile.String()
	return nil
}

func validateKnowledgeRoot(path, name string, readOnly bool) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return "", fmt.Errorf("%s must be an absolute path", name)
	}
	clean := filepath.Clean(path)
	if clean != path {
		return "", fmt.Errorf("%s must be clean", name)
	}
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		return "", fmt.Errorf("%s must resolve to an existing directory", name)
	}
	if resolved != clean {
		return "", fmt.Errorf("%s must not be a symlink", name)
	}
	info, err := os.Stat(clean)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%s must resolve to a directory", name)
	}
	if readOnly && runtime.GOOS != "windows" && info.Mode().Perm()&0o222 != 0 {
		return "", fmt.Errorf("%s must be read-only", name)
	}
	if !readOnly && runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s must be Agent-owned and private", name)
	}
	return clean, nil
}

func validateCoreRuntime(cfg *Config) error {
	if cfg.CoreTaskMaxConcurrency < 1 || cfg.CoreTaskMaxConcurrency > 128 {
		return fmt.Errorf("core_task_max_concurrency must be between 1 and 128")
	}
	if cfg.CoreTaskLeaseTTL < 5*time.Second || cfg.CoreTaskLeaseTTL > 10*time.Minute {
		return fmt.Errorf("core_task_lease_ttl must be between 5s and 10m")
	}
	if cfg.CoreScheduleSweepInterval < 100*time.Millisecond || cfg.CoreScheduleSweepInterval > time.Minute {
		return fmt.Errorf("core_schedule_sweep_interval must be between 100ms and 1m")
	}
	if cfg.CoreShutdownGrace < time.Second || cfg.CoreShutdownGrace > 5*time.Minute {
		return fmt.Errorf("core_shutdown_grace must be between 1s and 5m")
	}
	return nil
}

func ValidateCommon(cfg *Config) error {
	parsedInstanceID, err := uuid.Parse(cfg.InstanceID)
	if err != nil || parsedInstanceID == uuid.Nil || parsedInstanceID.String() != cfg.InstanceID {
		return errors.New("instance_id must be a UUID")
	}
	if strings.TrimSpace(cfg.DatabaseURLFile) == "" {
		return errors.New("database_url_file is required")
	}
	databaseURL, err := ReadMountedSecretText(cfg.DatabaseURLFile)
	if err != nil {
		return fmt.Errorf("read database_url_file: %w", err)
	}
	cfg.DatabaseURL = databaseURL
	return nil
}

func canonicalPath(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("path is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

// ValidateCoreStaticSites makes the immutable static publication root an
// explicit opt-in. The directory must already exist so startup never creates
// a host bind mount at an unintended path.
func ValidateCoreStaticSites(cfg *Config) error {
	if cfg == nil {
		return errors.New("config is required")
	}
	if !cfg.CoreStaticSitesEnabled {
		if strings.TrimSpace(cfg.CoreStaticSitesRoot) != "" {
			return errors.New("core_static_sites_root requires core_static_sites_enabled")
		}
		return nil
	}
	root, err := canonicalPath(cfg.CoreStaticSitesRoot)
	if err != nil {
		return fmt.Errorf("canonicalize core_static_sites_root: %w", err)
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return errors.New("core_static_sites_root must be an existing directory")
	}
	cfg.CoreStaticSitesRoot = root
	return nil
}

func pathsOverlap(left, right string) bool {
	inside := func(parent, child string) bool {
		rel, err := filepath.Rel(parent, child)
		return err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
	}
	return left == right || inside(left, right) || inside(right, left)
}

func ReadKeyMaterial(path string) ([]byte, error) {
	if err := ValidateMountedSecretFile(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read mounted secret file: %w", err)
	}
	defer clear(raw)
	trimmed := bytes.TrimSpace(raw)
	if decoded, ok := decodeKeyMaterial(base64.RawURLEncoding, trimmed); ok {
		return decoded, nil
	}
	if decoded, ok := decodeKeyMaterial(base64.StdEncoding, trimmed); ok {
		return decoded, nil
	}
	if len(trimmed) >= 32 {
		return append([]byte(nil), trimmed...), nil
	}
	return nil, errors.New("mounted secret material must contain at least 32 bytes")
}

func decodeKeyMaterial(encoding *base64.Encoding, value []byte) ([]byte, bool) {
	decoded := make([]byte, encoding.DecodedLen(len(value)))
	written, err := encoding.Decode(decoded, value)
	if err != nil || written < 32 {
		clear(decoded)
		return nil, false
	}
	return decoded[:written], true
}

func ReadMountedSecretText(path string) (string, error) {
	if err := ValidateMountedSecretFile(path); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read mounted secret file: %w", err)
	}
	defer clear(raw)
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", errors.New("mounted secret file must not be empty")
	}
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("mounted secret file must contain one text value")
	}
	return value, nil
}

func ValidateMountedSecretFile(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("mounted secret path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect mounted secret file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return errors.New("mounted secret path must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return errors.New("mounted secret file must not be group/world accessible")
	}
	return nil
}
