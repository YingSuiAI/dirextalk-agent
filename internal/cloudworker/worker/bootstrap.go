package worker

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

const (
	BootstrapSchemaV1 = "dirextalk.agent.ephemeral-pi-bootstrap/v1"
	MaxBootstrapBytes = 16 << 10
)

var (
	providerIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$`)
	hostnamePattern   = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	kmsKeyARNPattern  = regexp.MustCompile(`^arn:(?:aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$`)
)

type BootstrapDocument struct {
	SchemaVersion                 string `json:"schema_version"`
	OwnerID                       string `json:"owner_id"`
	AccountID                     string `json:"account_id"`
	AccountGeneration             uint64 `json:"account_generation"`
	Region                        string `json:"region"`
	ExecutionID                   string `json:"execution_id"`
	TaskID                        string `json:"task_id"`
	ProviderID                    string `json:"provider_id"`
	LaunchIdentity                string `json:"launch_identity"`
	Generation                    uint64 `json:"generation"`
	PlanDigest                    string `json:"plan_digest"`
	ExecutionSHA256               string `json:"execution_sha256"`
	TaskSHA256                    string `json:"task_sha256"`
	AMIDigest                     string `json:"ami_digest"`
	WorkerDigest                  string `json:"worker_digest"`
	PiDigest                      string `json:"pi_digest"`
	HostNetworkPolicySHA256       string `json:"host_network_policy_sha256"`
	ControlPlaneEndpoint          string `json:"control_plane_endpoint"`
	ControlPlaneServerName        string `json:"control_plane_server_name"`
	ControlPlaneTrustBundleSHA256 string `json:"control_plane_trust_bundle_sha256"`
	ModelRelayServerName          string `json:"model_relay_server_name"`
	ModelRelayTrustBundleSHA256   string `json:"model_relay_trust_bundle_sha256"`
	OutboundProxyURL              string `json:"outbound_proxy_url"`
	OutboundProxyServerName       string `json:"outbound_proxy_server_name"`
	OutboundProxyTrustSHA256      string `json:"outbound_proxy_trust_bundle_sha256"`
	OutboundProxyBindingSHA256    string `json:"outbound_proxy_binding_digest"`
	WorkspaceMode                 string `json:"workspace_mode"`
	InputManifestDigest           string `json:"input_manifest_digest"`
	ModelAuthorizationDigest      string `json:"model_authorization_digest"`
	ArtifactBindingDigest         string `json:"artifact_binding_digest"`
	ArtifactKMSKeyARN             string `json:"artifact_kms_key_arn"`
}

func ParseBootstrapDocument(raw []byte) (BootstrapDocument, BootstrapBinding, error) {
	if len(raw) == 0 || len(raw) > MaxBootstrapBytes {
		return BootstrapDocument{}, BootstrapBinding{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document BootstrapDocument
	if decoder.Decode(&document) != nil {
		return BootstrapDocument{}, BootstrapBinding{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return BootstrapDocument{}, BootstrapBinding{}, ErrInvalid
	}
	canonical, err := json.Marshal(document)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return BootstrapDocument{}, BootstrapBinding{}, ErrInvalid
	}
	clear(canonical)
	endpoint, err := url.Parse(document.ControlPlaneEndpoint)
	if err != nil || document.SchemaVersion != BootstrapSchemaV1 ||
		!providerIDPattern.MatchString(document.ProviderID) || document.Generation == 0 ||
		!validDigest(document.PlanDigest) || !validDigest(document.AMIDigest) ||
		!validDigest(document.WorkerDigest) || !validDigest(document.PiDigest) ||
		!validDigest(document.ControlPlaneTrustBundleSHA256) ||
		!validDigest(document.ModelRelayTrustBundleSHA256) ||
		document.ModelRelayServerName != strings.ToLower(document.ModelRelayServerName) ||
		!hostnamePattern.MatchString(document.ModelRelayServerName) || net.ParseIP(document.ModelRelayServerName) != nil ||
		!validDigest(document.ArtifactBindingDigest) ||
		!validArtifactKMSKeyARN(document.ArtifactKMSKeyARN, document.Region, document.AccountID) ||
		endpoint.Scheme != "https" || endpoint.User != nil || endpoint.RawQuery != "" ||
		endpoint.Fragment != "" || endpoint.Path != "" || endpoint.Port() == "" ||
		endpoint.Hostname() != document.ControlPlaneServerName ||
		document.ControlPlaneServerName != strings.ToLower(document.ControlPlaneServerName) ||
		!hostnamePattern.MatchString(document.ControlPlaneServerName) ||
		net.ParseIP(document.ControlPlaneServerName) != nil {
		return BootstrapDocument{}, BootstrapBinding{}, ErrInvalid
	}
	proxy := OutboundProxyBinding{
		URL: document.OutboundProxyURL, ServerName: document.OutboundProxyServerName,
		TrustBundleSHA256: document.OutboundProxyTrustSHA256,
		BindingSHA256:     document.OutboundProxyBindingSHA256,
	}
	if proxy.Validate() != nil {
		return BootstrapDocument{}, BootstrapBinding{}, ErrInvalid
	}
	if !validDigest(document.HostNetworkPolicySHA256) {
		return BootstrapDocument{}, BootstrapBinding{}, ErrInvalid
	}
	switch cloudruntime.WorkspaceMode(document.WorkspaceMode) {
	case cloudruntime.WorkspaceNone, cloudruntime.WorkspaceReadOnly, cloudruntime.WorkspaceWrite:
	default:
		return BootstrapDocument{}, BootstrapBinding{}, ErrInvalid
	}
	binding := BootstrapBinding{
		OwnerID: document.OwnerID, AccountID: document.AccountID,
		AccountGeneration: document.AccountGeneration, Region: document.Region,
		LaunchIdentity: document.LaunchIdentity,
		ExecutionID:    document.ExecutionID, ExecutionSHA256: document.ExecutionSHA256,
		TaskID: document.TaskID, TaskSHA256: document.TaskSHA256,
		InputManifestSHA256: document.InputManifestDigest,
		ModelBindingSHA256:  document.ModelAuthorizationDigest,
	}
	// InstanceID is read independently from signed IMDS identity and is not
	// trusted from mutable user data. BindBootstrapIdentity fills it once.
	if binding.validateWithoutInstance() != nil {
		return BootstrapDocument{}, BootstrapBinding{}, ErrInvalid
	}
	return document, binding, nil
}

func validArtifactKMSKeyARN(value, region, accountID string) bool {
	if value == "" || value != strings.TrimSpace(value) ||
		!kmsKeyARNPattern.MatchString(value) {
		return false
	}
	parts := strings.SplitN(value, ":", 6)
	return len(parts) == 6 && parts[2] == "kms" && parts[3] == region &&
		parts[4] == accountID && strings.HasPrefix(parts[5], "key/")
}

func BindBootstrapIdentity(
	binding BootstrapBinding,
	identity InstanceIdentity,
) (BootstrapBinding, error) {
	if binding.InstanceID != "" || !accountPattern.MatchString(binding.AccountID) ||
		!regionPattern.MatchString(binding.Region) ||
		identity.AccountID != binding.AccountID || identity.Region != binding.Region ||
		!instancePattern.MatchString(identity.InstanceID) || len(identity.Document) == 0 ||
		len(identity.PKCS7) == 0 {
		return BootstrapBinding{}, ErrIdentityChanged
	}
	binding.InstanceID = identity.InstanceID
	if binding.Validate() != nil {
		return BootstrapBinding{}, ErrInvalid
	}
	return binding, nil
}

func VerifyTrustBundle(raw []byte, expectedSHA256 string) (*x509.CertPool, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || !validDigest(expectedSHA256) {
		return nil, ErrInvalid
	}
	digest := sha256.Sum256(raw)
	if hex.EncodeToString(digest[:]) != expectedSHA256 {
		return nil, ErrInvalid
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		return nil, ErrInvalid
	}
	return roots, nil
}
