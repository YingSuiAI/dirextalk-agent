// Package aws defines the closed AWS boundary for one ephemeral Cloud Worker.
//
// The package deliberately contains no AWS SDK client. Production wiring must
// adapt CloudClient to typed AWS calls, while tests can exercise the complete
// lifecycle without credentials or network access.
package aws

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	PlanSchemaV1   = "dirextalk.agent.cloud-worker-aws-plan/v1"
	IntentSchemaV1 = "dirextalk.agent.cloud-worker-aws-dispatch/v1"
	RecipePiTask   = "ephemeral-pi-task"
	AdapterPiJSON  = "pi_json_task_v1"
)

var (
	ErrInvalid           = errors.New("invalid ephemeral AWS worker request")
	ErrNotFound          = errors.New("ephemeral AWS worker record not found")
	ErrConflict          = errors.New("ephemeral AWS worker revision conflict")
	ErrIdentityMismatch  = errors.New("ephemeral AWS worker identity mismatch")
	ErrOwnershipMismatch = errors.New("ephemeral AWS resource ownership mismatch")
	ErrResponseUnknown   = errors.New("AWS mutation response is unknown")
	ErrCloudMutation     = errors.New("ephemeral AWS mutation failed")
	ErrCloudReadback     = errors.New("ephemeral AWS read-back failed")
	ErrReconcilePending  = errors.New("ephemeral AWS reconciliation is pending")
	ErrDestroyRequested  = errors.New("ephemeral AWS destruction is already requested")

	accountPattern      = regexp.MustCompile(`^[0-9]{12}$`)
	regionPattern       = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$`)
	providerPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,254}$`)
	awsIDPattern        = regexp.MustCompile(`^(?:ami|vpc|subnet)-[0-9a-f]{8,17}$`)
	instanceTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9]+$`)
	digestPattern       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	hostnamePattern     = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
	iamNamePattern      = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	s3BucketPattern     = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	versionIDPattern    = regexp.MustCompile(`^[A-Za-z0-9._~+/=-]+$`)
	kmsARNPattern       = regexp.MustCompile(`^arn:(?:aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$`)
)

const (
	TagOwnerID              = "dirextalk:owner_id"
	TagAccountID            = "dirextalk:account_id"
	TagAccountGeneration    = "dirextalk:account_generation"
	TagRegion               = "dirextalk:region"
	TagExecutionID          = "dirextalk:execution_id"
	TagTaskID               = "dirextalk:task_id"
	TagProviderID           = "dirextalk:provider_id"
	TagLaunchIdentity       = "dirextalk:launch_identity"
	TagGeneration           = "dirextalk:generation"
	TagPlanDigest           = "dirextalk:plan_digest"
	TagInfrastructureDigest = "dirextalk:infrastructure_digest"
	TagIntentDigest         = "dirextalk:intent_digest"
)

// ExecutionIdentity is the immutable authorization and cleanup boundary. Every
// CloudClient request carries the complete value; names and tags alone are not
// accepted as an ownership boundary.
type ExecutionIdentity struct {
	OwnerID           string `json:"owner_id"`
	AccountID         string `json:"account_id"`
	AccountGeneration uint64 `json:"account_generation"`
	Region            string `json:"region"`
	ExecutionID       string `json:"execution_id"`
	TaskID            string `json:"task_id"`
	TaskAttempt       uint32 `json:"task_attempt"`
	LeaseEpoch        uint64 `json:"lease_epoch"`
	ProviderID        string `json:"provider_id"`
	LaunchIdentity    string `json:"launch_identity"`
	Generation        uint64 `json:"generation"`
}

// DeriveLaunchIdentity makes a replacement generation distinguishable from a
// same-name or same-execution resource left behind by an earlier launch.
func DeriveLaunchIdentity(identity ExecutionIdentity) string {
	identity = identity.normalized()
	payload := struct {
		OwnerID           string `json:"owner_id"`
		AccountID         string `json:"account_id"`
		AccountGeneration uint64 `json:"account_generation"`
		Region            string `json:"region"`
		ExecutionID       string `json:"execution_id"`
		TaskID            string `json:"task_id"`
		ProviderID        string `json:"provider_id"`
		Generation        uint64 `json:"generation"`
	}{identity.OwnerID, identity.AccountID, identity.AccountGeneration, identity.Region, identity.ExecutionID, identity.TaskID,
		identity.ProviderID, identity.Generation}
	return digestJSON(payload)
}

func (identity ExecutionIdentity) Validate() error {
	normalized := identity.normalized()
	if identity != normalized {
		return ErrInvalid
	}
	identity = normalized
	parsedExecution, executionErr := uuid.Parse(identity.ExecutionID)
	parsedTask, taskErr := uuid.Parse(identity.TaskID)
	if executionErr != nil || parsedExecution == uuid.Nil || parsedExecution.String() != identity.ExecutionID ||
		taskErr != nil || parsedTask == uuid.Nil || parsedTask.String() != identity.TaskID ||
		identity.OwnerID == "" || len(identity.OwnerID) > 255 || strings.ContainsAny(identity.OwnerID, "\r\n\x00") ||
		!accountPattern.MatchString(identity.AccountID) || identity.AccountGeneration == 0 || !regionPattern.MatchString(identity.Region) ||
		identity.TaskAttempt == 0 || identity.LeaseEpoch == 0 || !providerPattern.MatchString(identity.ProviderID) || identity.Generation == 0 ||
		identity.LaunchIdentity != DeriveLaunchIdentity(identity) {
		return ErrInvalid
	}
	return nil
}

func (identity ExecutionIdentity) normalized() ExecutionIdentity {
	identity.OwnerID = strings.TrimSpace(identity.OwnerID)
	identity.AccountID = strings.TrimSpace(identity.AccountID)
	identity.Region = strings.TrimSpace(identity.Region)
	identity.ExecutionID = strings.TrimSpace(identity.ExecutionID)
	identity.TaskID = strings.TrimSpace(identity.TaskID)
	identity.ProviderID = strings.TrimSpace(identity.ProviderID)
	identity.LaunchIdentity = strings.TrimSpace(identity.LaunchIdentity)
	return identity
}

func (identity ExecutionIdentity) Equal(other ExecutionIdentity) bool {
	return identity.normalized() == other.normalized()
}

// SameDispatch compares only the immutable launch scope. TaskAttempt and
// LeaseEpoch are WorkerControl session fences: a CoreTask reclaim must reuse
// the original dispatch and must never retag or replace cloud resources.
func (identity ExecutionIdentity) SameDispatch(other ExecutionIdentity) bool {
	return dispatchIdentityFor(identity) == dispatchIdentityFor(other)
}

type dispatchIdentity struct {
	OwnerID           string `json:"owner_id"`
	AccountID         string `json:"account_id"`
	AccountGeneration uint64 `json:"account_generation"`
	Region            string `json:"region"`
	ExecutionID       string `json:"execution_id"`
	TaskID            string `json:"task_id"`
	ProviderID        string `json:"provider_id"`
	LaunchIdentity    string `json:"launch_identity"`
	Generation        uint64 `json:"generation"`
}

func dispatchIdentityFor(identity ExecutionIdentity) dispatchIdentity {
	identity = identity.normalized()
	return dispatchIdentity{
		OwnerID: identity.OwnerID, AccountID: identity.AccountID, AccountGeneration: identity.AccountGeneration,
		Region: identity.Region, ExecutionID: identity.ExecutionID, TaskID: identity.TaskID,
		ProviderID: identity.ProviderID, LaunchIdentity: identity.LaunchIdentity, Generation: identity.Generation,
	}
}

// NetworkPolicy permits DNS only to explicit resolvers and HTTPS only to an
// explicit controlled proxy. AllowedFQDNs are enforced by that proxy. AWS
// Security Groups cannot express or enforce an FQDN allow-list.
type NetworkPolicy struct {
	DNSResolverCIDRs               []string `json:"dns_resolver_cidrs"`
	TLSProxyCIDRs                  []string `json:"tls_proxy_cidrs"`
	AllowedFQDNs                   []string `json:"allowed_fqdns"`
	OutboundProxyURL               string   `json:"outbound_proxy_url"`
	OutboundProxyServerName        string   `json:"outbound_proxy_server_name"`
	OutboundProxyTrustBundleSHA256 string   `json:"outbound_proxy_trust_bundle_sha256"`
	OutboundProxyBindingDigest     string   `json:"outbound_proxy_binding_digest"`
}

type NetworkRule struct {
	Protocol string `json:"protocol"`
	FromPort uint16 `json:"from_port"`
	ToPort   uint16 `json:"to_port"`
	CIDRv4   string `json:"cidr_v4"`
}

type SecurityGroupPolicy struct {
	Ingress                   []NetworkRule `json:"ingress"`
	Egress                    []NetworkRule `json:"egress"`
	FQDNEnforcement           string        `json:"fqdn_enforcement"`
	FQDNPolicyDigest          string        `json:"fqdn_policy_digest"`
	SecurityGroupEnforcesFQDN bool          `json:"security_group_enforces_fqdn"`
}

func (policy NetworkPolicy) normalized() NetworkPolicy {
	policy.DNSResolverCIDRs = normalizedStrings(policy.DNSResolverCIDRs)
	policy.TLSProxyCIDRs = normalizedStrings(policy.TLSProxyCIDRs)
	policy.AllowedFQDNs = normalizedStrings(policy.AllowedFQDNs)
	policy.OutboundProxyURL = strings.TrimSpace(policy.OutboundProxyURL)
	policy.OutboundProxyServerName = strings.ToLower(strings.TrimSpace(policy.OutboundProxyServerName))
	policy.OutboundProxyTrustBundleSHA256 = strings.TrimSpace(policy.OutboundProxyTrustBundleSHA256)
	policy.OutboundProxyBindingDigest = digestJSON(struct {
		URL               string `json:"url"`
		ServerName        string `json:"server_name"`
		TrustBundleSHA256 string `json:"trust_bundle_sha256"`
	}{policy.OutboundProxyURL, policy.OutboundProxyServerName, policy.OutboundProxyTrustBundleSHA256})
	return policy
}

func (policy NetworkPolicy) Validate() error {
	normalized := policy.normalized()
	if !slices.Equal(policy.DNSResolverCIDRs, normalized.DNSResolverCIDRs) ||
		!slices.Equal(policy.TLSProxyCIDRs, normalized.TLSProxyCIDRs) || !slices.Equal(policy.AllowedFQDNs, normalized.AllowedFQDNs) ||
		policy.OutboundProxyURL != normalized.OutboundProxyURL || policy.OutboundProxyServerName != normalized.OutboundProxyServerName ||
		policy.OutboundProxyTrustBundleSHA256 != normalized.OutboundProxyTrustBundleSHA256 ||
		policy.OutboundProxyBindingDigest != normalized.OutboundProxyBindingDigest {
		return fmt.Errorf("%w: network policy must be canonical", ErrInvalid)
	}
	policy = normalized
	if len(policy.DNSResolverCIDRs) == 0 || len(policy.TLSProxyCIDRs) == 0 || len(policy.AllowedFQDNs) == 0 {
		return fmt.Errorf("%w: controlled DNS, TLS proxy, and FQDN allow-list are required", ErrInvalid)
	}
	for _, cidr := range append(slices.Clone(policy.DNSResolverCIDRs), policy.TLSProxyCIDRs...) {
		ip, network, err := net.ParseCIDR(cidr)
		if err != nil || ip.To4() == nil || network.String() != cidr || cidr == "0.0.0.0/0" {
			return fmt.Errorf("%w: egress CIDR must be a canonical bounded IPv4 network", ErrInvalid)
		}
	}
	for _, hostname := range policy.AllowedFQDNs {
		if hostname != strings.ToLower(hostname) || !hostnamePattern.MatchString(hostname) || net.ParseIP(hostname) != nil || strings.Contains(hostname, "*") {
			return fmt.Errorf("%w: FQDN allow-list entry is invalid", ErrInvalid)
		}
	}
	proxyURL, err := url.Parse(policy.OutboundProxyURL)
	if err != nil || proxyURL.Scheme != "https" || proxyURL.User != nil || proxyURL.RawQuery != "" || proxyURL.Fragment != "" ||
		proxyURL.Path != "" || proxyURL.RawPath != "" || proxyURL.Port() != "443" || proxyURL.Hostname() != policy.OutboundProxyServerName ||
		!hostnamePattern.MatchString(policy.OutboundProxyServerName) || net.ParseIP(policy.OutboundProxyServerName) != nil ||
		proxyURL.String() != policy.OutboundProxyURL || !digestPattern.MatchString(policy.OutboundProxyTrustBundleSHA256) ||
		!digestPattern.MatchString(policy.OutboundProxyBindingDigest) {
		return fmt.Errorf("%w: controlled outbound proxy binding is invalid", ErrInvalid)
	}
	return nil
}

func (policy NetworkPolicy) ProxyPolicyDigest() string {
	policy = policy.normalized()
	return digestJSON(struct {
		AllowedFQDNs []string `json:"allowed_fqdns"`
	}{policy.AllowedFQDNs})
}

func (policy NetworkPolicy) SecurityGroupPolicy() (SecurityGroupPolicy, error) {
	policy = policy.normalized()
	if err := policy.Validate(); err != nil {
		return SecurityGroupPolicy{}, err
	}
	rules := make([]NetworkRule, 0, len(policy.DNSResolverCIDRs)*2+len(policy.TLSProxyCIDRs))
	for _, cidr := range policy.DNSResolverCIDRs {
		rules = append(rules,
			NetworkRule{Protocol: "udp", FromPort: 53, ToPort: 53, CIDRv4: cidr},
			NetworkRule{Protocol: "tcp", FromPort: 53, ToPort: 53, CIDRv4: cidr},
		)
	}
	for _, cidr := range policy.TLSProxyCIDRs {
		rules = append(rules, NetworkRule{Protocol: "tcp", FromPort: 443, ToPort: 443, CIDRv4: cidr})
	}
	sort.Slice(rules, func(i, j int) bool {
		left := rules[i].Protocol + rules[i].CIDRv4
		right := rules[j].Protocol + rules[j].CIDRv4
		return left < right
	})
	return SecurityGroupPolicy{
		Ingress:                   []NetworkRule{},
		Egress:                    rules,
		FQDNEnforcement:           "controlled_tls_proxy",
		FQDNPolicyDigest:          policy.ProxyPolicyDigest(),
		SecurityGroupEnforcesFQDN: false,
	}, nil
}

type Plan struct {
	SchemaVersion                 string            `json:"schema_version"`
	Identity                      ExecutionIdentity `json:"identity"`
	Recipe                        string            `json:"recipe"`
	Adapter                       string            `json:"adapter"`
	AMIID                         string            `json:"ami_id"`
	AMIDigest                     string            `json:"ami_digest"`
	WorkerDigest                  string            `json:"worker_digest"`
	PiDigest                      string            `json:"pi_digest"`
	HostNetworkPolicySHA256       string            `json:"host_network_policy_sha256"`
	Architecture                  string            `json:"architecture"`
	InstanceType                  string            `json:"instance_type"`
	RootVolumeGiB                 uint32            `json:"root_volume_gib"`
	RootDeviceName                string            `json:"root_device_name"`
	RootVolumeType                string            `json:"root_volume_type"`
	RootVolumeIOPS                uint32            `json:"root_volume_iops"`
	RootVolumeThroughput          uint32            `json:"root_volume_throughput_mibps"`
	RootKMSKeyARN                 string            `json:"root_kms_key_arn"`
	VPCID                         string            `json:"vpc_id"`
	SubnetID                      string            `json:"subnet_id"`
	Network                       NetworkPolicy     `json:"network"`
	ControlPlaneEndpoint          string            `json:"control_plane_endpoint"`
	ControlPlaneServerName        string            `json:"control_plane_server_name"`
	ControlPlaneTrustBundleSHA256 string            `json:"control_plane_trust_bundle_sha256"`
	ModelRelayServerName          string            `json:"model_relay_server_name"`
	ModelRelayTrustBundleSHA256   string            `json:"model_relay_trust_bundle_sha256"`
	WorkspaceMode                 WorkspaceMode     `json:"workspace_mode"`
	ExecutionSHA256               string            `json:"execution_sha256"`
	TaskSHA256                    string            `json:"task_sha256"`
	InputManifestDigest           string            `json:"input_manifest_digest"`
	ModelAuthorizationDigest      string            `json:"model_authorization_digest"`
	ArtifactBindingDigest         string            `json:"artifact_binding_digest"`
	BootstrapDigest               string            `json:"bootstrap_digest"`
	S3Grants                      []S3ObjectGrant   `json:"s3_grants"`
	IAMRoleName                   string            `json:"iam_role_name"`
	InstanceProfileName           string            `json:"instance_profile_name"`
	ArtifactRetentionSeconds      uint32            `json:"artifact_retention_seconds"`
	DestroyDeadline               time.Time         `json:"destroy_deadline"`
	// Digest is the authoritative Core CloudWorker plan digest. The AWS
	// ledger persists only this digest, never the input manifest, model
	// authorization, credentials, or secret-bearing plan material.
	Digest               string `json:"digest"`
	InfrastructureDigest string `json:"infrastructure_digest"`
}

type S3GrantAccess string

type WorkspaceMode string

const (
	S3ReadExactVersion S3GrantAccess = "read_exact_version"
	S3WritePrefix      S3GrantAccess = "write_prefix"
	WorkspaceNone      WorkspaceMode = "none"
	WorkspaceReadOnly  WorkspaceMode = "read_only"
	WorkspaceWrite     WorkspaceMode = "write"
)

type S3ObjectGrant struct {
	Access    S3GrantAccess `json:"access"`
	Bucket    string        `json:"bucket"`
	Key       string        `json:"key"`
	VersionID string        `json:"version_id,omitempty"`
}

func (grant S3ObjectGrant) Validate() error {
	if !s3BucketPattern.MatchString(grant.Bucket) || grant.Key == "" || len(grant.Key) > 1024 || strings.HasPrefix(grant.Key, "/") ||
		strings.ContainsAny(grant.Key, "\r\n\x00") || strings.Contains(grant.Key, "../") {
		return ErrInvalid
	}
	switch grant.Access {
	case S3ReadExactVersion:
		if len(grant.VersionID) > 1024 || !versionIDPattern.MatchString(grant.VersionID) || strings.HasSuffix(grant.Key, "/") {
			return ErrInvalid
		}
	case S3WritePrefix:
		if grant.VersionID != "" || !strings.HasSuffix(grant.Key, "/") {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type BootstrapDocumentV1 struct {
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

// BootstrapDocument intentionally excludes TaskAttempt and LeaseEpoch. The
// immutable instance registers by execution/instance launch identity and must
// obtain the current task fence from WorkerControl after a lease reclaim.
func (plan Plan) BootstrapDocument() ([]byte, error) {
	document := BootstrapDocumentV1{
		SchemaVersion: "dirextalk.agent.ephemeral-pi-bootstrap/v1", OwnerID: plan.Identity.OwnerID,
		AccountID: plan.Identity.AccountID, AccountGeneration: plan.Identity.AccountGeneration, Region: plan.Identity.Region,
		ExecutionID: plan.Identity.ExecutionID, TaskID: plan.Identity.TaskID, ProviderID: plan.Identity.ProviderID,
		LaunchIdentity: plan.Identity.LaunchIdentity, Generation: plan.Identity.Generation, PlanDigest: plan.Digest,
		ExecutionSHA256: plan.ExecutionSHA256, TaskSHA256: plan.TaskSHA256, AMIDigest: plan.AMIDigest,
		WorkerDigest: plan.WorkerDigest, PiDigest: plan.PiDigest, HostNetworkPolicySHA256: plan.HostNetworkPolicySHA256,
		ControlPlaneEndpoint: plan.ControlPlaneEndpoint, ControlPlaneServerName: plan.ControlPlaneServerName,
		ControlPlaneTrustBundleSHA256: plan.ControlPlaneTrustBundleSHA256,
		ModelRelayServerName:          plan.ModelRelayServerName, ModelRelayTrustBundleSHA256: plan.ModelRelayTrustBundleSHA256,
		OutboundProxyURL: plan.Network.OutboundProxyURL, OutboundProxyServerName: plan.Network.OutboundProxyServerName,
		OutboundProxyTrustSHA256: plan.Network.OutboundProxyTrustBundleSHA256, OutboundProxyBindingSHA256: plan.Network.OutboundProxyBindingDigest,
		WorkspaceMode:       string(plan.WorkspaceMode),
		InputManifestDigest: plan.InputManifestDigest, ModelAuthorizationDigest: plan.ModelAuthorizationDigest,
		ArtifactBindingDigest: plan.ArtifactBindingDigest, ArtifactKMSKeyARN: plan.RootKMSKeyARN,
	}
	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) == 0 || len(encoded) > 16*1024 {
		return nil, ErrInvalid
	}
	return encoded, nil
}

// SealPlan canonicalizes the AWS projection and computes its infrastructure
// digest while retaining the authoritative Core CloudWorker plan digest.
func SealPlan(plan Plan) (Plan, error) {
	plan.SchemaVersion = PlanSchemaV1
	plan.Identity = plan.Identity.normalized()
	plan.Recipe = strings.TrimSpace(plan.Recipe)
	plan.Adapter = strings.TrimSpace(plan.Adapter)
	plan.AMIID = strings.TrimSpace(plan.AMIID)
	plan.AMIDigest = strings.TrimSpace(plan.AMIDigest)
	plan.WorkerDigest = strings.TrimSpace(plan.WorkerDigest)
	plan.PiDigest = strings.TrimSpace(plan.PiDigest)
	plan.HostNetworkPolicySHA256 = strings.TrimSpace(plan.HostNetworkPolicySHA256)
	plan.Architecture = strings.TrimSpace(plan.Architecture)
	plan.InstanceType = strings.TrimSpace(plan.InstanceType)
	plan.RootDeviceName = strings.TrimSpace(plan.RootDeviceName)
	plan.RootVolumeType = strings.TrimSpace(plan.RootVolumeType)
	plan.RootKMSKeyARN = strings.TrimSpace(plan.RootKMSKeyARN)
	plan.VPCID = strings.TrimSpace(plan.VPCID)
	plan.SubnetID = strings.TrimSpace(plan.SubnetID)
	plan.ControlPlaneEndpoint = strings.TrimSpace(plan.ControlPlaneEndpoint)
	plan.ControlPlaneServerName = strings.TrimSpace(plan.ControlPlaneServerName)
	plan.ControlPlaneTrustBundleSHA256 = strings.TrimSpace(plan.ControlPlaneTrustBundleSHA256)
	plan.ModelRelayServerName = strings.ToLower(strings.TrimSpace(plan.ModelRelayServerName))
	plan.ModelRelayTrustBundleSHA256 = strings.TrimSpace(plan.ModelRelayTrustBundleSHA256)
	plan.ExecutionSHA256 = strings.TrimSpace(plan.ExecutionSHA256)
	plan.TaskSHA256 = strings.TrimSpace(plan.TaskSHA256)
	plan.InputManifestDigest = strings.TrimSpace(plan.InputManifestDigest)
	plan.ModelAuthorizationDigest = strings.TrimSpace(plan.ModelAuthorizationDigest)
	plan.ArtifactBindingDigest = strings.TrimSpace(plan.ArtifactBindingDigest)
	plan.Network = plan.Network.normalized()
	plan.S3Grants = slices.Clone(plan.S3Grants)
	for index := range plan.S3Grants {
		plan.S3Grants[index].Bucket = strings.TrimSpace(plan.S3Grants[index].Bucket)
		plan.S3Grants[index].Key = strings.TrimSpace(plan.S3Grants[index].Key)
		plan.S3Grants[index].VersionID = strings.TrimSpace(plan.S3Grants[index].VersionID)
	}
	sort.Slice(plan.S3Grants, func(i, j int) bool {
		return string(plan.S3Grants[i].Access)+plan.S3Grants[i].Bucket+plan.S3Grants[i].Key+plan.S3Grants[i].VersionID <
			string(plan.S3Grants[j].Access)+plan.S3Grants[j].Bucket+plan.S3Grants[j].Key+plan.S3Grants[j].VersionID
	})
	namePrefix := "dtx-pi-" + strings.ReplaceAll(plan.Identity.ExecutionID, "-", "")[:16] + "-g" + strconv.FormatUint(plan.Identity.Generation, 10)
	plan.IAMRoleName = namePrefix + "-role"
	plan.InstanceProfileName = namePrefix + "-profile"
	plan.DestroyDeadline = plan.DestroyDeadline.UTC()
	if !digestPattern.MatchString(plan.Digest) {
		return Plan{}, ErrInvalid
	}
	plan.BootstrapDigest = ""
	bootstrap, err := plan.BootstrapDocument()
	if err != nil {
		return Plan{}, err
	}
	plan.BootstrapDigest = digestBytes(bootstrap)
	plan.InfrastructureDigest = infrastructureDigestFor(plan)
	if err := plan.Validate(); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func (plan Plan) Validate() error {
	if plan.SchemaVersion != PlanSchemaV1 || plan.Identity.Validate() != nil || plan.Recipe != RecipePiTask || plan.Adapter != AdapterPiJSON ||
		!awsIDPattern.MatchString(plan.AMIID) || !digestPattern.MatchString(plan.AMIDigest) || !digestPattern.MatchString(plan.WorkerDigest) ||
		!digestPattern.MatchString(plan.PiDigest) || !digestPattern.MatchString(plan.HostNetworkPolicySHA256) || (plan.Architecture != "amd64" && plan.Architecture != "arm64") || !instanceTypePattern.MatchString(plan.InstanceType) ||
		plan.RootVolumeGiB < 8 || plan.RootVolumeGiB > 16384 || plan.RootDeviceName != "/dev/xvda" || plan.RootVolumeType != "gp3" ||
		plan.RootVolumeIOPS < 3000 || plan.RootVolumeIOPS > 16000 || plan.RootVolumeThroughput < 125 || plan.RootVolumeThroughput > 1000 ||
		!kmsARNPattern.MatchString(plan.RootKMSKeyARN) || !strings.Contains(plan.RootKMSKeyARN, ":"+plan.Identity.Region+":"+plan.Identity.AccountID+":") ||
		!awsIDPattern.MatchString(plan.VPCID) || !awsIDPattern.MatchString(plan.SubnetID) || plan.DestroyDeadline.IsZero() || plan.Network.Validate() != nil ||
		!validControlPlaneEndpoint(plan.ControlPlaneEndpoint, plan.ControlPlaneServerName) || !digestPattern.MatchString(plan.ControlPlaneTrustBundleSHA256) ||
		!hostnamePattern.MatchString(plan.ModelRelayServerName) || net.ParseIP(plan.ModelRelayServerName) != nil ||
		!slices.Contains(plan.Network.AllowedFQDNs, plan.ModelRelayServerName) || !digestPattern.MatchString(plan.ModelRelayTrustBundleSHA256) ||
		!iamNamePattern.MatchString(plan.IAMRoleName) || !iamNamePattern.MatchString(plan.InstanceProfileName) ||
		(plan.WorkspaceMode != WorkspaceNone && plan.WorkspaceMode != WorkspaceReadOnly && plan.WorkspaceMode != WorkspaceWrite) ||
		!digestPattern.MatchString(plan.ExecutionSHA256) || !digestPattern.MatchString(plan.TaskSHA256) ||
		!digestPattern.MatchString(plan.InputManifestDigest) || !digestPattern.MatchString(plan.ModelAuthorizationDigest) ||
		!digestPattern.MatchString(plan.ArtifactBindingDigest) || !digestPattern.MatchString(plan.BootstrapDigest) ||
		plan.ArtifactRetentionSeconds == 0 || plan.ArtifactRetentionSeconds > 30*24*60*60 ||
		!digestPattern.MatchString(plan.Digest) || !digestPattern.MatchString(plan.InfrastructureDigest) {
		return ErrInvalid
	}
	if len(plan.S3Grants) == 0 {
		return ErrInvalid
	}
	writeGrant := false
	for index, grant := range plan.S3Grants {
		if grant.Validate() != nil || (index > 0 && grant == plan.S3Grants[index-1]) {
			return ErrInvalid
		}
		writeGrant = writeGrant || grant.Access == S3WritePrefix
	}
	if !writeGrant {
		return ErrInvalid
	}
	bootstrap, err := plan.BootstrapDocument()
	if err != nil || digestBytes(bootstrap) != plan.BootstrapDigest {
		return ErrInvalid
	}
	if infrastructureDigestFor(plan) != plan.InfrastructureDigest {
		return fmt.Errorf("%w: infrastructure digest mismatch", ErrInvalid)
	}
	return nil
}

func validControlPlaneEndpoint(value, serverName string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && parsed.RawQuery == "" && parsed.Fragment == "" &&
		parsed.Hostname() == serverName && hostnamePattern.MatchString(serverName) && parsed.Port() != "" && parsed.Path == ""
}

// infrastructureDigestFor excludes the mutable CoreTask session fence. The
// fence is acquired from WorkerControl after instance identity proof and does
// not authorize a second AWS dispatch.
func infrastructureDigestFor(plan Plan) string {
	copy := plan
	copy.InfrastructureDigest = ""
	copy.Identity.TaskAttempt = 0
	copy.Identity.LeaseEpoch = 0
	return digestJSON(copy)
}

type DispatchIntent struct {
	SchemaVersion        string               `json:"schema_version"`
	Identity             ExecutionIdentity    `json:"identity"`
	PlanDigest           string               `json:"plan_digest"`
	InfrastructureDigest string               `json:"infrastructure_digest"`
	Authorization        AuthorizationBinding `json:"authorization"`
	StackName            string               `json:"stack_name"`
	ClientToken          string               `json:"client_token"`
	IntentDigest         string               `json:"intent_digest"`
	RecordedAt           time.Time            `json:"recorded_at"`
}

// AuthorizationBinding carries both sides of the last-mile authorization
// comparison. The provider does not trust a previously approved quote by
// itself: the controller must supply a fresh quote digest and a fresh read of
// the CoreConfirmation binding, and both pairs must match exactly.
type AuthorizationBinding struct {
	AuthorizedQuoteDigest      string    `json:"authorized_quote_digest"`
	FreshQuoteDigest           string    `json:"fresh_quote_digest"`
	ExpectedConfirmationDigest string    `json:"expected_confirmation_digest"`
	ConfirmationDigest         string    `json:"confirmation_digest"`
	FreshQuotedAt              time.Time `json:"fresh_quoted_at"`
	QuoteExpiresAt             time.Time `json:"quote_expires_at"`
	ConfirmedAt                time.Time `json:"confirmed_at"`
	MaximumQuoteAgeSeconds     uint32    `json:"maximum_quote_age_seconds"`
}

func (binding AuthorizationBinding) Validate(recordedAt time.Time) error {
	if !digestPattern.MatchString(binding.AuthorizedQuoteDigest) || binding.AuthorizedQuoteDigest != binding.FreshQuoteDigest ||
		!digestPattern.MatchString(binding.ExpectedConfirmationDigest) || binding.ExpectedConfirmationDigest != binding.ConfirmationDigest ||
		binding.FreshQuotedAt.IsZero() || binding.QuoteExpiresAt.IsZero() || binding.ConfirmedAt.IsZero() || recordedAt.IsZero() ||
		binding.MaximumQuoteAgeSeconds == 0 || binding.MaximumQuoteAgeSeconds > 3600 {
		return fmt.Errorf("%w: fresh quote and confirmation binding are required", ErrInvalid)
	}
	fresh := binding.FreshQuotedAt.UTC()
	expires := binding.QuoteExpiresAt.UTC()
	confirmed := binding.ConfirmedAt.UTC()
	recorded := recordedAt.UTC()
	if binding.FreshQuotedAt != fresh || binding.QuoteExpiresAt != expires || binding.ConfirmedAt != confirmed || recordedAt != recorded ||
		confirmed.Before(fresh) || recorded.Before(confirmed) || !recorded.Before(expires) || !fresh.Before(expires) ||
		recorded.Sub(fresh) > time.Duration(binding.MaximumQuoteAgeSeconds)*time.Second {
		return fmt.Errorf("%w: quote is stale, expired, or was confirmed out of order", ErrInvalid)
	}
	return nil
}

func (binding AuthorizationBinding) ValidateForMutation(recordedAt, now time.Time) error {
	if err := binding.Validate(recordedAt); err != nil || now.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	if now.Before(recordedAt.UTC()) || !now.Before(binding.QuoteExpiresAt) ||
		now.Sub(binding.FreshQuotedAt) > time.Duration(binding.MaximumQuoteAgeSeconds)*time.Second {
		return fmt.Errorf("%w: fresh quote expired before provider mutation", ErrInvalid)
	}
	return nil
}

// NewDispatchIntent produces stable AWS names/tokens for a plan generation.
// RecordedAt is audit data and is intentionally excluded from IntentDigest so
// a controller restart cannot produce a second mutation identity.
func NewDispatchIntent(plan Plan, authorization AuthorizationBinding, recordedAt time.Time) (DispatchIntent, error) {
	recordedAt = recordedAt.UTC()
	if plan.Validate() != nil || authorization.Validate(recordedAt) != nil {
		return DispatchIntent{}, ErrInvalid
	}
	seed := digestJSON(struct {
		Identity             dispatchIdentity `json:"identity"`
		PlanDigest           string           `json:"plan_digest"`
		InfrastructureDigest string           `json:"infrastructure_digest"`
	}{dispatchIdentityFor(plan.Identity), plan.Digest, plan.InfrastructureDigest})
	intent := DispatchIntent{
		SchemaVersion:        IntentSchemaV1,
		Identity:             plan.Identity,
		PlanDigest:           plan.Digest,
		InfrastructureDigest: plan.InfrastructureDigest,
		Authorization:        authorization,
		StackName:            WorkerServerName(plan.Identity.ExecutionID, plan.Identity.Generation),
		ClientToken:          "dtx-" + seed,
		RecordedAt:           recordedAt.UTC(),
	}
	intent.IntentDigest = intent.expectedDigest()
	return intent, intent.Validate(plan)
}

// WorkerServerName is the stable, non-secret display name assigned to one
// immutable Cloud Worker plan generation.
func WorkerServerName(executionID string, generation uint64) string {
	compact := strings.ReplaceAll(strings.TrimSpace(executionID), "-", "")
	if len(compact) < 16 || generation == 0 {
		return ""
	}
	return "dtx-pi-" + compact[:16] + "-g" + strconv.FormatUint(generation, 10)
}

func (intent DispatchIntent) expectedDigest() string {
	return digestJSON(struct {
		SchemaVersion        string               `json:"schema_version"`
		Identity             dispatchIdentity     `json:"identity"`
		PlanDigest           string               `json:"plan_digest"`
		InfrastructureDigest string               `json:"infrastructure_digest"`
		Authorization        AuthorizationBinding `json:"authorization"`
		StackName            string               `json:"stack_name"`
		ClientToken          string               `json:"client_token"`
	}{intent.SchemaVersion, dispatchIdentityFor(intent.Identity), intent.PlanDigest, intent.InfrastructureDigest, intent.Authorization, intent.StackName, intent.ClientToken})
}

func (intent DispatchIntent) Validate(plan Plan) error {
	if plan.Validate() != nil || intent.SchemaVersion != IntentSchemaV1 || !intent.Identity.Equal(plan.Identity) || intent.PlanDigest != plan.Digest || intent.InfrastructureDigest != plan.InfrastructureDigest ||
		intent.RecordedAt.IsZero() || !providerPattern.MatchString(intent.StackName) || len(intent.StackName) > 128 ||
		!providerPattern.MatchString(intent.ClientToken) || len(intent.ClientToken) > 128 || intent.IntentDigest != intent.expectedDigest() ||
		intent.Authorization.Validate(intent.RecordedAt) != nil {
		return ErrInvalid
	}
	expected, err := newDispatchIntent(plan, intent.Authorization, intent.RecordedAt)
	if err != nil || intent.StackName != expected.StackName || intent.ClientToken != expected.ClientToken || intent.IntentDigest != expected.IntentDigest {
		return fmt.Errorf("%w: dispatch identity is not deterministic", ErrInvalid)
	}
	return nil
}

// newDispatchIntent breaks the validation recursion while retaining one
// canonical derivation path.
func newDispatchIntent(plan Plan, authorization AuthorizationBinding, recordedAt time.Time) (DispatchIntent, error) {
	if recordedAt.IsZero() || authorization.Validate(recordedAt) != nil {
		return DispatchIntent{}, ErrInvalid
	}
	seed := digestJSON(struct {
		Identity             dispatchIdentity `json:"identity"`
		PlanDigest           string           `json:"plan_digest"`
		InfrastructureDigest string           `json:"infrastructure_digest"`
	}{dispatchIdentityFor(plan.Identity), plan.Digest, plan.InfrastructureDigest})
	intent := DispatchIntent{SchemaVersion: IntentSchemaV1, Identity: plan.Identity, PlanDigest: plan.Digest, InfrastructureDigest: plan.InfrastructureDigest, Authorization: authorization,
		StackName:   WorkerServerName(plan.Identity.ExecutionID, plan.Identity.Generation),
		ClientToken: "dtx-" + seed, RecordedAt: recordedAt.UTC()}
	intent.IntentDigest = intent.expectedDigest()
	return intent, nil
}

type ResourceKind string

const (
	ResourceEC2             ResourceKind = "ec2"
	ResourceEBS             ResourceKind = "ebs"
	ResourceENI             ResourceKind = "eni"
	ResourceEIP             ResourceKind = "eip"
	ResourceSecurityGroup   ResourceKind = "security_group"
	ResourceIAMRole         ResourceKind = "iam_role"
	ResourceInstanceProfile ResourceKind = "instance_profile"
	ResourceStack           ResourceKind = "stack"
)

var allResourceKinds = []ResourceKind{
	ResourceSecurityGroup, ResourceIAMRole, ResourceInstanceProfile, ResourceENI,
	ResourceEIP, ResourceEBS, ResourceEC2, ResourceStack,
}

var destroyOrder = []ResourceKind{
	ResourceEC2, ResourceEIP, ResourceEBS, ResourceENI, ResourceSecurityGroup,
	ResourceInstanceProfile, ResourceIAMRole, ResourceStack,
}

func AllResourceKinds() []ResourceKind { return slices.Clone(allResourceKinds) }

func LogicalID(kind ResourceKind) string {
	switch kind {
	case ResourceEC2:
		return "WorkerInstance"
	case ResourceEBS:
		return "WorkerRootVolume"
	case ResourceENI:
		return "WorkerNetworkInterface"
	case ResourceEIP:
		return "WorkerElasticIP"
	case ResourceSecurityGroup:
		return "WorkerSecurityGroup"
	case ResourceIAMRole:
		return "WorkerIAMRole"
	case ResourceInstanceProfile:
		return "WorkerInstanceProfile"
	case ResourceStack:
		return "WorkerStack"
	default:
		return ""
	}
}

func validResourceKind(kind ResourceKind) bool { return slices.Contains(allResourceKinds, kind) }

func RequiredTags(identity ExecutionIdentity, planDigest, infrastructureDigest, intentDigest string) map[string]string {
	return map[string]string{
		TagOwnerID: identity.OwnerID, TagAccountID: identity.AccountID, TagAccountGeneration: strconv.FormatUint(identity.AccountGeneration, 10), TagRegion: identity.Region,
		TagExecutionID: identity.ExecutionID, TagTaskID: identity.TaskID, TagProviderID: identity.ProviderID,
		TagLaunchIdentity: identity.LaunchIdentity, TagGeneration: strconv.FormatUint(identity.Generation, 10),
		TagPlanDigest: planDigest, TagInfrastructureDigest: infrastructureDigest, TagIntentDigest: intentDigest,
	}
}

type GraphState string

const (
	GraphProvisioning      GraphState = "provisioning"
	GraphActive            GraphState = "active"
	GraphFailed            GraphState = "failed"
	GraphDestroying        GraphState = "destroying"
	GraphVerifiedDestroyed GraphState = "verified_destroyed"
)

type ResourceObservation struct {
	Kind           ResourceKind      `json:"kind"`
	LogicalID      string            `json:"logical_id"`
	ProviderID     string            `json:"provider_id"`
	PrivateIP      string            `json:"private_ip,omitempty"`
	PublicIP       string            `json:"public_ip,omitempty"`
	Exists         bool              `json:"exists"`
	Tags           map[string]string `json:"tags"`
	LaunchIdentity string            `json:"launch_identity"`
	Generation     uint64            `json:"generation"`
	ObservedAt     time.Time         `json:"observed_at"`
}

type TopologyProof struct {
	EC2InstanceCount uint8         `json:"ec2_instance_count"`
	Ingress          []NetworkRule `json:"ingress"`
	Egress           []NetworkRule `json:"egress"`
	SSMEnabled       bool          `json:"ssm_enabled"`
	FQDNEnforcement  string        `json:"fqdn_enforcement"`
	FQDNPolicyDigest string        `json:"fqdn_policy_digest"`
}

type ObservedGraph struct {
	Identity             ExecutionIdentity     `json:"identity"`
	PlanDigest           string                `json:"plan_digest"`
	InfrastructureDigest string                `json:"infrastructure_digest"`
	IntentDigest         string                `json:"intent_digest"`
	StackProviderID      string                `json:"stack_provider_id"`
	State                GraphState            `json:"state"`
	Resources            []ResourceObservation `json:"resources"`
	Topology             TopologyProof         `json:"topology"`
	ObservedAt           time.Time             `json:"observed_at"`
}

func (graph ObservedGraph) clone() ObservedGraph {
	graph.Resources = slices.Clone(graph.Resources)
	for index := range graph.Resources {
		graph.Resources[index].Tags = cloneMap(graph.Resources[index].Tags)
	}
	graph.Topology.Ingress = slices.Clone(graph.Topology.Ingress)
	graph.Topology.Egress = slices.Clone(graph.Topology.Egress)
	return graph
}

func (graph ObservedGraph) Validate(plan Plan, intent DispatchIntent) error {
	if plan.Validate() != nil || intent.Validate(plan) != nil || !graph.Identity.Equal(plan.Identity) || graph.PlanDigest != plan.Digest || graph.InfrastructureDigest != plan.InfrastructureDigest ||
		graph.IntentDigest != intent.IntentDigest || graph.ObservedAt.IsZero() || (graph.StackProviderID != "" && !providerPattern.MatchString(graph.StackProviderID)) {
		return ErrIdentityMismatch
	}
	seen := make(map[ResourceKind]struct{}, len(graph.Resources))
	requiredTags := RequiredTags(plan.Identity, plan.Digest, plan.InfrastructureDigest, intent.IntentDigest)
	for _, observation := range graph.Resources {
		if !validResourceKind(observation.Kind) || observation.LogicalID != LogicalID(observation.Kind) || observation.ObservedAt.IsZero() ||
			(observation.ProviderID != "" && !providerPattern.MatchString(observation.ProviderID)) ||
			(observation.PrivateIP != "" && (observation.Kind != ResourceEC2 || !validWorkerIPv4(observation.PrivateIP))) ||
			(observation.PublicIP != "" && (observation.Kind != ResourceEIP || !validWorkerIPv4(observation.PublicIP))) ||
			(!observation.Exists && (observation.PrivateIP != "" || observation.PublicIP != "")) {
			return ErrCloudReadback
		}
		if _, duplicate := seen[observation.Kind]; duplicate {
			return ErrCloudReadback
		}
		seen[observation.Kind] = struct{}{}
		if observation.Exists {
			if !providerPattern.MatchString(observation.ProviderID) || observation.LaunchIdentity != plan.Identity.LaunchIdentity || observation.Generation != plan.Identity.Generation ||
				!containsTags(observation.Tags, requiredTags) {
				return ErrOwnershipMismatch
			}
		}
	}
	switch graph.State {
	case GraphActive:
		if len(seen) != len(allResourceKinds) || !providerPattern.MatchString(graph.StackProviderID) {
			return ErrCloudReadback
		}
		for _, kind := range allResourceKinds {
			if _, ok := seen[kind]; !ok || !resourceExists(graph.Resources, kind) {
				return ErrCloudReadback
			}
		}
		policy, _ := plan.Network.SecurityGroupPolicy()
		if graph.Topology.EC2InstanceCount != 1 ||
			len(graph.Topology.Ingress) != 0 || graph.Topology.SSMEnabled || graph.Topology.FQDNEnforcement != policy.FQDNEnforcement ||
			graph.Topology.FQDNPolicyDigest != policy.FQDNPolicyDigest || graph.Topology.FQDNEnforcement != "controlled_tls_proxy" ||
			!equalRules(graph.Topology.Egress, policy.Egress) {
			return ErrCloudReadback
		}
		if stackProviderID(graph.Resources) != graph.StackProviderID {
			return ErrCloudReadback
		}
	case GraphProvisioning, GraphFailed:
		// Partial graphs are accepted only as reconciliation evidence. Every
		// present resource still passed the exact ownership checks above.
	case GraphDestroying:
		if len(seen) != len(allResourceKinds) || (graph.StackProviderID != "" && !providerPattern.MatchString(graph.StackProviderID)) {
			return ErrCloudReadback
		}
		for _, kind := range allResourceKinds {
			if _, ok := seen[kind]; !ok {
				return ErrCloudReadback
			}
		}
	case GraphVerifiedDestroyed:
		if len(seen) != len(allResourceKinds) {
			return ErrCloudReadback
		}
		for _, observation := range graph.Resources {
			if observation.Exists {
				return ErrCloudReadback
			}
		}
	default:
		return ErrCloudReadback
	}
	return nil
}

func validWorkerIPv4(value string) bool {
	parsed := net.ParseIP(strings.TrimSpace(value))
	return parsed != nil && parsed.To4() != nil && value == parsed.String()
}

func stackProviderID(resources []ResourceObservation) string {
	for _, observation := range resources {
		if observation.Kind == ResourceStack && observation.Exists {
			return observation.ProviderID
		}
	}
	return ""
}

func resourceExists(resources []ResourceObservation, kind ResourceKind) bool {
	for _, item := range resources {
		if item.Kind == kind {
			return item.Exists
		}
	}
	return false
}

func resourceObservedAbsent(resources []ResourceObservation, kind ResourceKind) bool {
	for _, item := range resources {
		if item.Kind == kind {
			return !item.Exists
		}
	}
	return false
}

func equalRules(left, right []NetworkRule) bool {
	left = slices.Clone(left)
	right = slices.Clone(right)
	sort.Slice(left, func(i, j int) bool { return ruleKey(left[i]) < ruleKey(left[j]) })
	sort.Slice(right, func(i, j int) bool { return ruleKey(right[i]) < ruleKey(right[j]) })
	return slices.Equal(left, right)
}

func ruleKey(rule NetworkRule) string {
	return rule.Protocol + ":" + strconv.Itoa(int(rule.FromPort)) + ":" + strconv.Itoa(int(rule.ToPort)) + ":" + rule.CIDRv4
}

func containsTags(actual, required map[string]string) bool {
	for key, value := range required {
		if actual[key] != value {
			return false
		}
	}
	return true
}

// ContainsRequiredTags applies the exact owner/execution tag subset check used
// by provider readback at storage-backed authorization boundaries.
func ContainsRequiredTags(actual, required map[string]string) bool {
	return containsTags(actual, required)
}

func normalizedStrings(values []string) []string {
	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func digestJSON(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func digestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func cloneMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	result := make(map[string]string, len(input))
	for key, value := range input {
		result[key] = value
	}
	return result
}
