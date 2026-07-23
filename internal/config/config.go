package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

var immutableOCIImagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]*:[vV]?[0-9]+\.[0-9]+\.[0-9]+-(?:alpha|beta|rc)(?:[.-][A-Za-z0-9][A-Za-z0-9.-]*)?@sha256:[a-f0-9]{64}$`)

type Common struct {
	InstanceID  string `yaml:"instance_id" mapstructure:"instance_id"`
	DatabaseURL string `yaml:"-"`
}

type Server struct {
	Common
	ListenAddress                    string `yaml:"grpc_listen" mapstructure:"grpc_listen"`
	TLSCertFile                      string `yaml:"tls_cert_file" mapstructure:"tls_cert_file"`
	TLSKeyFile                       string `yaml:"tls_key_file" mapstructure:"tls_key_file"`
	PepperFile                       string `yaml:"service_key_pepper_file" mapstructure:"service_key_pepper_file"`
	MasterKeyFile                    string `yaml:"master_key_file" mapstructure:"master_key_file"`
	MountedSecretsDir                string `yaml:"mounted_secrets_dir" mapstructure:"mounted_secrets_dir"`
	ModelProfilesFile                string `yaml:"model_profiles_file" mapstructure:"model_profiles_file"`
	MCPServersFile                   string `yaml:"mcp_servers_file" mapstructure:"mcp_servers_file"`
	EnableAWSControl                 bool   `yaml:"enable_aws_control" mapstructure:"enable_aws_control"`
	EnableManagedPreparationAWS      bool   `yaml:"enable_managed_preparation_aws" mapstructure:"enable_managed_preparation_aws"`
	AWSReaperImageURI                string `yaml:"aws_reaper_image_uri" mapstructure:"aws_reaper_image_uri"`
	WorkerControlEndpoint            string `yaml:"worker_control_endpoint" mapstructure:"worker_control_endpoint"`
	WorkerControlEndpointServiceName string `yaml:"worker_control_endpoint_service_name" mapstructure:"worker_control_endpoint_service_name"`
	WorkerAMIPublicationFile         string `yaml:"worker_ami_publication_file" mapstructure:"worker_ami_publication_file"`
}

// Config is the complete non-secret Agent process configuration. Secret
// material is represented only by mounted-file paths.
type Config struct {
	Common                       `yaml:",inline" mapstructure:",squash"`
	Server                       `yaml:",inline" mapstructure:",squash"`
	DatabaseURLFile              string `yaml:"database_url_file" mapstructure:"database_url_file"`
	BootstrapServiceKeyFile      string `yaml:"bootstrap_service_key_file" mapstructure:"bootstrap_service_key_file"`
	BootstrapClientID            string `yaml:"bootstrap_client_id" mapstructure:"bootstrap_client_id"`
	BootstrapScopes              string `yaml:"bootstrap_scopes" mapstructure:"bootstrap_scopes"`
	ApprovalDeviceOwnerID        string `yaml:"approval_device_owner_id" mapstructure:"approval_device_owner_id"`
	ApprovalDeviceKeyID          string `yaml:"approval_device_key_id" mapstructure:"approval_device_key_id"`
	ApprovalDeviceIdempotencyKey string `yaml:"approval_device_idempotency_key" mapstructure:"approval_device_idempotency_key"`
	ApprovalDeviceExpiresAt      string `yaml:"approval_device_expires_at" mapstructure:"approval_device_expires_at"`
	ApprovalDevicePublicKeyFile  string `yaml:"approval_device_public_key_file" mapstructure:"approval_device_public_key_file"`
	HealthcheckAddress           string `yaml:"grpc_healthcheck_address" mapstructure:"grpc_healthcheck_address"`
	HealthcheckServerName        string `yaml:"grpc_healthcheck_server_name" mapstructure:"grpc_healthcheck_server_name"`
}

// Load reads a strict YAML file through Viper. Environment variables are
// intentionally not bound; AGENT_CONFIG_FILE is handled by the command only
// to select the file path.
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

func ValidateServer(cfg *Config) error {
	if err := ValidateCommon(cfg); err != nil {
		return err
	}
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = ":9443"
	}
	if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
		return errors.New("tls_cert_file and tls_key_file are required")
	}
	if cfg.PepperFile == "" || cfg.MountedSecretsDir == "" || cfg.ModelProfilesFile == "" || cfg.MasterKeyFile == "" {
		return errors.New("tls, mounted-secrets, model-profiles, and master-key paths are required")
	}
	if err := validateMountedSecretIsolation(cfg); err != nil {
		return err
	}
	if cfg.AWSReaperImageURI != "" {
		lower := strings.ToLower(cfg.AWSReaperImageURI)
		if !immutableOCIImagePattern.MatchString(cfg.AWSReaperImageURI) || strings.Contains(lower, ":latest@") || strings.Contains(lower, ":v1.0.3@") {
			return errors.New("aws_reaper_image_uri must be an immutable digest-pinned prerelease image")
		}
	}
	if cfg.EnableManagedPreparationAWS && !cfg.EnableAWSControl {
		return errors.New("enable_managed_preparation_aws requires enable_aws_control=true")
	}
	if cfg.EnableAWSControl {
		if cfg.AWSReaperImageURI == "" {
			return errors.New("aws_reaper_image_uri is required when AWS cloud control is enabled")
		}
		if cfg.WorkerControlEndpoint != cloudquote.WorkerControlPrivateLinkEndpoint || (cfg.WorkerControlEndpointServiceName != "" && cloudquote.ValidateWorkerControlPrivateLink(cfg.WorkerControlEndpoint, cfg.WorkerControlEndpointServiceName) != nil) {
			return errors.New("worker_control_endpoint and worker_control_endpoint_service_name must be the frozen worker-control.y1.dirextalk.ai:443 and ap-northeast-3 PrivateLink service when AWS cloud control is enabled")
		}
		if cfg.EnableManagedPreparationAWS && cfg.WorkerControlEndpointServiceName == "" {
			return errors.New("enable_managed_preparation_aws requires worker_control_endpoint_service_name")
		}
	}
	return nil
}

func validateMountedSecretIsolation(cfg *Config) error {
	mountedDir, err := canonicalPath(cfg.MountedSecretsDir)
	if err != nil {
		return fmt.Errorf("canonicalize mounted_secrets_dir: %w", err)
	}
	info, err := os.Stat(mountedDir)
	if err != nil || !info.IsDir() {
		return errors.New("mounted_secrets_dir must resolve to a directory")
	}
	cfg.MountedSecretsDir = mountedDir
	core := []struct {
		name string
		path *string
	}{
		{name: "database_url_file", path: &cfg.DatabaseURLFile},
		{name: "tls_cert_file", path: &cfg.TLSCertFile},
		{name: "tls_key_file", path: &cfg.TLSKeyFile},
		{name: "service_key_pepper_file", path: &cfg.PepperFile},
		{name: "master_key_file", path: &cfg.MasterKeyFile},
	}
	if strings.TrimSpace(cfg.BootstrapServiceKeyFile) != "" {
		core = append(core, struct {
			name string
			path *string
		}{name: "bootstrap_service_key_file", path: &cfg.BootstrapServiceKeyFile})
	}
	for _, item := range core {
		resolved, resolveErr := canonicalPath(*item.path)
		if resolveErr != nil {
			return fmt.Errorf("canonicalize %s: %w", item.name, resolveErr)
		}
		fileInfo, statErr := os.Stat(resolved)
		if statErr != nil || !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("%s must resolve to a regular file", item.name)
		}
		if pathsOverlap(mountedDir, resolved) {
			return fmt.Errorf("%s must not overlap mounted_secrets_dir", item.name)
		}
		*item.path = resolved
	}
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
