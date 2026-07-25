package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config is the complete non-secret Agent process configuration. Secret
// material is represented only by mounted-file paths.
type Config struct {
	InstanceID                      string        `yaml:"instance_id" mapstructure:"instance_id"`
	DatabaseURL                     string        `yaml:"-" mapstructure:"-"`
	DatabaseURLFile                 string        `yaml:"database_url_file" mapstructure:"database_url_file"`
	ListenAddress                   string        `yaml:"grpc_listen" mapstructure:"grpc_listen"`
	TLSCertFile                     string        `yaml:"tls_cert_file" mapstructure:"tls_cert_file"`
	TLSKeyFile                      string        `yaml:"tls_key_file" mapstructure:"tls_key_file"`
	ServiceTokenFile                string        `yaml:"service_token_file" mapstructure:"service_token_file"`
	EnableHealthService             bool          `yaml:"enable_health_service" mapstructure:"enable_health_service"`
	EnableReflection                bool          `yaml:"enable_reflection" mapstructure:"enable_reflection"`
	CoreTaskMaxConcurrency          int           `yaml:"core_task_max_concurrency" mapstructure:"core_task_max_concurrency"`
	CoreTaskLeaseTTL                time.Duration `yaml:"core_task_lease_ttl" mapstructure:"core_task_lease_ttl"`
	CoreScheduleSweepInterval       time.Duration `yaml:"core_schedule_sweep_interval" mapstructure:"core_schedule_sweep_interval"`
	CoreShutdownGrace               time.Duration `yaml:"core_shutdown_grace" mapstructure:"core_shutdown_grace"`
	CoreAWSEnabled                  bool          `yaml:"core_aws_enabled" mapstructure:"core_aws_enabled"`
	CoreExtensionEnabled            bool          `yaml:"core_extension_enabled" mapstructure:"core_extension_enabled"`
	CoreExtensionStagingRoot        string        `yaml:"core_extension_staging_root" mapstructure:"core_extension_staging_root"`
	CoreExtensionWorkspaceRoot      string        `yaml:"core_extension_workspace_root" mapstructure:"core_extension_workspace_root"`
	CoreExtensionRunnerSocket       string        `yaml:"core_extension_runner_socket" mapstructure:"core_extension_runner_socket"`
	CoreExtensionRunnerUID          uint32        `yaml:"core_extension_runner_uid" mapstructure:"core_extension_runner_uid"`
	CoreKnowledgeEnabled            bool          `yaml:"core_knowledge_enabled" mapstructure:"core_knowledge_enabled"`
	CoreKnowledgeContentRoot        string        `yaml:"core_knowledge_content_root" mapstructure:"core_knowledge_content_root"`
	CoreKnowledgeMountRoot          string        `yaml:"core_knowledge_mount_root" mapstructure:"core_knowledge_mount_root"`
	CoreKnowledgeContentQuotaBytes  int64         `yaml:"core_knowledge_content_quota_bytes" mapstructure:"core_knowledge_content_quota_bytes"`
	CoreKnowledgeEmbeddingProfileID string        `yaml:"core_knowledge_embedding_profile_id" mapstructure:"core_knowledge_embedding_profile_id"`
	CoreKnowledgeQdrantEndpoint     string        `yaml:"core_knowledge_qdrant_endpoint" mapstructure:"core_knowledge_qdrant_endpoint"`
	CoreKnowledgeQdrantCollection   string        `yaml:"core_knowledge_qdrant_collection" mapstructure:"core_knowledge_qdrant_collection"`
	CoreKnowledgeQdrantDimension    int           `yaml:"core_knowledge_qdrant_dimension" mapstructure:"core_knowledge_qdrant_dimension"`
	CoreKnowledgeSweepInterval      time.Duration `yaml:"core_knowledge_sweep_interval" mapstructure:"core_knowledge_sweep_interval"`
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
	if err := v.ReadConfig(bytes.NewReader(contents)); err != nil {
		return Config{}, fmt.Errorf("read config through viper: %w", err)
	}
	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return Config{}, fmt.Errorf("viper config decode: %w", err)
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
	if err := validateCoreRuntime(cfg); err != nil {
		return err
	}
	if err := ValidateCoreKnowledge(cfg); err != nil {
		return err
	}
	if err := ValidateCoreExtension(cfg); err != nil {
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
	workspaceRoot, err := validateExtensionRoot(cfg.CoreExtensionWorkspaceRoot, "core_extension_workspace_root")
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
	if cfg.CoreKnowledgeContentQuotaBytes <= 0 || cfg.CoreKnowledgeContentQuotaBytes > 1<<40 {
		return errors.New("core_knowledge_content_quota_bytes must be positive and at most 1TiB")
	}
	parsedProfile, err := uuid.Parse(strings.TrimSpace(cfg.CoreKnowledgeEmbeddingProfileID))
	if err != nil || parsedProfile == uuid.Nil || parsedProfile.String() != strings.TrimSpace(cfg.CoreKnowledgeEmbeddingProfileID) {
		return errors.New("core_knowledge_embedding_profile_id must be a UUID")
	}
	endpoint := strings.TrimRight(strings.TrimSpace(cfg.CoreKnowledgeQdrantEndpoint), "/")
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "http" && u.Scheme != "https") || strings.ContainsAny(endpoint, "\x00\r\n") {
		return errors.New("core_knowledge_qdrant_endpoint must be an absolute HTTP(S) URL")
	}
	if strings.TrimSpace(cfg.CoreKnowledgeQdrantCollection) == "" || len(cfg.CoreKnowledgeQdrantCollection) > 256 || strings.ContainsAny(cfg.CoreKnowledgeQdrantCollection, "\x00\r\n") {
		return errors.New("core_knowledge_qdrant_collection is required")
	}
	if cfg.CoreKnowledgeQdrantDimension <= 0 || cfg.CoreKnowledgeQdrantDimension > 1<<20 {
		return errors.New("core_knowledge_qdrant_dimension must be positive")
	}
	if cfg.CoreKnowledgeSweepInterval < 100*time.Millisecond || cfg.CoreKnowledgeSweepInterval > time.Hour {
		return errors.New("core_knowledge_sweep_interval must be between 100ms and 1h")
	}
	cfg.CoreKnowledgeContentRoot = contentRoot
	cfg.CoreKnowledgeMountRoot = mountRoot
	cfg.CoreKnowledgeQdrantEndpoint = endpoint
	cfg.CoreKnowledgeEmbeddingProfileID = parsedProfile.String()
	cfg.CoreKnowledgeQdrantCollection = strings.TrimSpace(cfg.CoreKnowledgeQdrantCollection)
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
