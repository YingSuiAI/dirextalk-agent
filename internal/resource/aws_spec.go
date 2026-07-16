package resource

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	AWSResourceSpecSchemaV1        = "dirextalk.agent.aws-resource/v1"
	embeddedRootVolumeSpecSchemaV1 = "dirextalk.agent.embedded-root-ebs/v1"
)

var (
	awsIDPattern           = regexp.MustCompile(`^(?:ami|vpc|subnet|sg|eni|vol)-[0-9a-f]{8,17}$`)
	awsInstanceTypePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*\.[a-z0-9]+$`)
	awsZonePattern         = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+[a-z]$`)
	awsProfilePattern      = regexp.MustCompile(`^dtx-agent-[a-z0-9-]{1,54}-worker$`)
	awsKMSPattern          = regexp.MustCompile(`^(?:alias/[A-Za-z0-9/_-]{1,240}|arn:(?:aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:[0-9]{12}:(?:key/[0-9a-f-]{36}|alias/[A-Za-z0-9/_-]{1,240}))$`)
)

type AWSMarketType string

const (
	AWSMarketOnDemand AWSMarketType = "on_demand"
	AWSMarketSpot     AWSMarketType = "spot"
)

// AWSResourceSpecV1 is a closed union. It has no raw maps, SDK request, shell,
// or user-data field; the provider serializes a fixed Worker bootstrap JSON
// document from the immutable artifact reference and digest.
type AWSResourceSpecV1 struct {
	SchemaVersion    string                     `json:"schema_version"`
	SecurityGroup    *AWSSecurityGroupSpecV1    `json:"security_group,omitempty"`
	Volume           *AWSEBSVolumeSpecV1        `json:"volume,omitempty"`
	NetworkInterface *AWSNetworkInterfaceSpecV1 `json:"network_interface,omitempty"`
	Instance         *AWSEC2InstanceSpecV1      `json:"instance,omitempty"`
}

type AWSSecurityGroupSpecV1 struct {
	VPCID       string             `json:"vpc_id"`
	Description string             `json:"description"`
	Ingress     []AWSNetworkRuleV1 `json:"ingress,omitempty"`
	Egress      []AWSNetworkRuleV1 `json:"egress"`
}

type AWSNetworkRuleV1 struct {
	Protocol string `json:"protocol"`
	FromPort uint16 `json:"from_port"`
	ToPort   uint16 `json:"to_port"`
	CIDRv4   string `json:"cidr_v4"`
}

type AWSEBSVolumeSpecV1 struct {
	AvailabilityZone string `json:"availability_zone"`
	SizeGiB          uint32 `json:"size_gib"`
	VolumeType       string `json:"volume_type"`
	IOPS             uint32 `json:"iops,omitempty"`
	ThroughputMiBPS  uint32 `json:"throughput_mibps,omitempty"`
	KMSKeyID         string `json:"kms_key_id"`
}

type AWSNetworkInterfaceSpecV1 struct {
	SubnetID                string `json:"subnet_id"`
	Description             string `json:"description"`
	ExistingSecurityGroupID string `json:"existing_security_group_id,omitempty"`
}

type AWSEC2InstanceSpecV1 struct {
	ImageID                string                   `json:"image_id"`
	ImageDigest            string                   `json:"image_digest"`
	InstanceType           string                   `json:"instance_type"`
	InstanceProfileName    string                   `json:"instance_profile_name"`
	UserDataArtifactRef    string                   `json:"user_data_artifact_ref"`
	UserDataArtifactDigest string                   `json:"user_data_artifact_digest"`
	Bootstrap              AWSWorkerBootstrapSpecV1 `json:"bootstrap"`
	RootDeviceName         string                   `json:"root_device_name"`
	RootVolumeGiB          uint32                   `json:"root_volume_gib"`
	RootKMSKeyID           string                   `json:"root_kms_key_id"`
	DataDeviceName         string                   `json:"data_device_name,omitempty"`
	Market                 AWSMarketType            `json:"market"`
	EBSOptimized           bool                     `json:"ebs_optimized"`
}

// AWSWorkerBootstrapSpecV1 contains only non-secret coordinates needed by the
// digest-pinned Worker image to prove its EC2 role identity before it can read
// deployment-scoped artifacts. The provider serializes this closed structure;
// callers cannot supply shell, cloud-init, or arbitrary user-data.
type AWSWorkerBootstrapSpecV1 struct {
	DeploymentID               string `json:"deployment_id"`
	WorkerID                   string `json:"worker_id"`
	ControlPlaneEndpoint       string `json:"control_plane_endpoint"`
	EnrollmentExpectedRevision int64  `json:"enrollment_expected_revision"`
}

type ProviderDependency struct {
	ResourceID string
	Type       Type
	ProviderID string
}

// EmbeddedRootVolumeResourceID returns the stable ledger identity for the
// root EBS volume implicitly created by EC2 RunInstances.
func EmbeddedRootVolumeResourceID(parentResourceID string) (string, error) {
	parent := strings.TrimSpace(parentResourceID)
	parsed, err := uuid.Parse(parent)
	if err != nil || parsed == uuid.Nil || parsed.String() != parent {
		return "", fmt.Errorf("%w: parent resource ID must be a canonical non-zero UUID", ErrInvalid)
	}
	return uuid.NewSHA1(parsed, []byte(embeddedRootVolumeSpecSchemaV1)).String(), nil
}

// EmbeddedRootVolumeFacts derives the immutable ledger identity and digest
// for the root EBS volume that RunInstances creates atomically with an EC2
// Worker. The digest intentionally covers only root-volume behavior.
func EmbeddedRootVolumeFacts(parentResourceID string, instance *AWSEC2InstanceSpecV1) (string, string, error) {
	resourceID, err := EmbeddedRootVolumeResourceID(parentResourceID)
	if err != nil {
		return "", "", err
	}
	if instance == nil {
		return "", "", fmt.Errorf("%w: EC2 instance spec is required", ErrInvalid)
	}
	if err := instance.validate(); err != nil {
		return "", "", err
	}
	canonical := struct {
		SchemaVersion       string `json:"schema_version"`
		RootDeviceName      string `json:"root_device_name"`
		RootVolumeGiB       uint32 `json:"root_volume_gib"`
		RootKMSKeyID        string `json:"root_kms_key_id"`
		VolumeType          string `json:"volume_type"`
		Encrypted           bool   `json:"encrypted"`
		DeleteOnTermination bool   `json:"delete_on_termination"`
	}{
		SchemaVersion: embeddedRootVolumeSpecSchemaV1, RootDeviceName: instance.RootDeviceName,
		RootVolumeGiB: instance.RootVolumeGiB, RootKMSKeyID: instance.RootKMSKeyID,
		VolumeType: "gp3", Encrypted: true, DeleteOnTermination: true,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", "", fmt.Errorf("%w: encode embedded root EBS spec", ErrInvalid)
	}
	digest := sha256.Sum256(encoded)
	return resourceID, "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (spec *AWSResourceSpecV1) Clone() *AWSResourceSpecV1 {
	if spec == nil {
		return nil
	}
	clone := *spec
	if spec.SecurityGroup != nil {
		value := *spec.SecurityGroup
		value.Ingress = slices.Clone(value.Ingress)
		value.Egress = slices.Clone(value.Egress)
		clone.SecurityGroup = &value
	}
	if spec.Volume != nil {
		value := *spec.Volume
		clone.Volume = &value
	}
	if spec.NetworkInterface != nil {
		value := *spec.NetworkInterface
		clone.NetworkInterface = &value
	}
	if spec.Instance != nil {
		value := *spec.Instance
		clone.Instance = &value
	}
	return &clone
}

func (spec *AWSResourceSpecV1) Validate(kind Type) error {
	if spec == nil || spec.SchemaVersion != AWSResourceSpecSchemaV1 {
		return fmt.Errorf("%w: AWS resource schema is invalid", ErrInvalid)
	}
	count := 0
	for _, present := range []bool{spec.SecurityGroup != nil, spec.Volume != nil, spec.NetworkInterface != nil, spec.Instance != nil} {
		if present {
			count++
		}
	}
	if count != 1 {
		return fmt.Errorf("%w: AWS resource spec must select exactly one typed resource", ErrInvalid)
	}
	switch kind {
	case TypeSG:
		if spec.SecurityGroup == nil {
			return fmt.Errorf("%w: security group spec is required", ErrInvalid)
		}
		return spec.SecurityGroup.validate()
	case TypeEBS:
		if spec.Volume == nil {
			return fmt.Errorf("%w: EBS spec is required", ErrInvalid)
		}
		return spec.Volume.validate()
	case TypeENI:
		if spec.NetworkInterface == nil {
			return fmt.Errorf("%w: ENI spec is required", ErrInvalid)
		}
		return spec.NetworkInterface.validate()
	case TypeEC2:
		if spec.Instance == nil {
			return fmt.Errorf("%w: EC2 spec is required", ErrInvalid)
		}
		return spec.Instance.validate()
	default:
		return fmt.Errorf("%w: AWS resource type is not implemented", ErrInvalid)
	}
}

func (spec *AWSResourceSpecV1) Digest(kind Type) (string, error) {
	if err := spec.Validate(kind); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(spec)
	if err != nil {
		return "", fmt.Errorf("%w: encode AWS resource spec", ErrInvalid)
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func (spec AWSSecurityGroupSpecV1) validate() error {
	if !strings.HasPrefix(spec.VPCID, "vpc-") || !awsIDPattern.MatchString(spec.VPCID) || strings.TrimSpace(spec.Description) == "" || len(spec.Description) > 255 || security.ContainsLikelySecret(spec.Description) || len(spec.Ingress) > 32 || len(spec.Egress) == 0 || len(spec.Egress) > 32 {
		return fmt.Errorf("%w: security group scope is invalid", ErrInvalid)
	}
	for _, set := range [][]AWSNetworkRuleV1{spec.Ingress, spec.Egress} {
		seen := make(map[string]struct{}, len(set))
		for _, rule := range set {
			if err := rule.validate(); err != nil {
				return err
			}
			key := fmt.Sprintf("%s:%d:%d:%s", rule.Protocol, rule.FromPort, rule.ToPort, rule.CIDRv4)
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%w: duplicate security group rule", ErrInvalid)
			}
			seen[key] = struct{}{}
		}
	}
	return nil
}

func (rule AWSNetworkRuleV1) validate() error {
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		return fmt.Errorf("%w: network protocol must be tcp or udp", ErrInvalid)
	}
	if rule.FromPort == 0 || rule.ToPort < rule.FromPort {
		return fmt.Errorf("%w: network port range is invalid", ErrInvalid)
	}
	ip, network, err := net.ParseCIDR(rule.CIDRv4)
	if err != nil || ip.To4() == nil || network.String() != rule.CIDRv4 {
		return fmt.Errorf("%w: canonical IPv4 CIDR is required", ErrInvalid)
	}
	return nil
}

func (spec AWSEBSVolumeSpecV1) validate() error {
	if !awsZonePattern.MatchString(spec.AvailabilityZone) || spec.SizeGiB == 0 || spec.SizeGiB > 65_536 || spec.VolumeType != "gp3" || spec.IOPS < 3_000 || spec.IOPS > 80_000 || spec.ThroughputMiBPS < 125 || spec.ThroughputMiBPS > 2_000 || !awsKMSPattern.MatchString(spec.KMSKeyID) {
		return fmt.Errorf("%w: encrypted gp3 volume scope is invalid", ErrInvalid)
	}
	return nil
}

func (spec AWSNetworkInterfaceSpecV1) validate() error {
	if !strings.HasPrefix(spec.SubnetID, "subnet-") || !awsIDPattern.MatchString(spec.SubnetID) || strings.TrimSpace(spec.Description) == "" || len(spec.Description) > 255 || security.ContainsLikelySecret(spec.Description) {
		return fmt.Errorf("%w: ENI scope is invalid", ErrInvalid)
	}
	if spec.ExistingSecurityGroupID != "" && (!strings.HasPrefix(spec.ExistingSecurityGroupID, "sg-") || !awsIDPattern.MatchString(spec.ExistingSecurityGroupID)) {
		return fmt.Errorf("%w: existing security group is invalid", ErrInvalid)
	}
	return nil
}

func (spec AWSEC2InstanceSpecV1) validate() error {
	if !strings.HasPrefix(spec.ImageID, "ami-") || !awsIDPattern.MatchString(spec.ImageID) || !sha256Pattern.MatchString(spec.ImageDigest) || !awsInstanceTypePattern.MatchString(spec.InstanceType) || !awsProfilePattern.MatchString(spec.InstanceProfileName) || !sha256Pattern.MatchString(spec.UserDataArtifactDigest) || spec.RootDeviceName != "/dev/sda1" || spec.RootVolumeGiB < 8 || spec.RootVolumeGiB > 1024 || !awsKMSPattern.MatchString(spec.RootKMSKeyID) || (spec.Market != AWSMarketOnDemand && spec.Market != AWSMarketSpot) {
		return fmt.Errorf("%w: EC2 Worker scope is invalid", ErrInvalid)
	}
	parsed, err := url.Parse(spec.UserDataArtifactRef)
	if err != nil || parsed.Scheme != "s3" || parsed.Host == "" || parsed.Path == "" || parsed.RawQuery != "" || parsed.Fragment != "" || len(spec.UserDataArtifactRef) > 1024 || security.ContainsLikelySecret(spec.UserDataArtifactRef) {
		return fmt.Errorf("%w: immutable S3 Worker artifact reference is required", ErrInvalid)
	}
	if err := spec.Bootstrap.validate(); err != nil {
		return err
	}
	if spec.DataDeviceName != "" && !regexp.MustCompile(`^/dev/sd[f-p]$`).MatchString(spec.DataDeviceName) {
		return fmt.Errorf("%w: data device name is invalid", ErrInvalid)
	}
	return nil
}

func (spec AWSWorkerBootstrapSpecV1) validate() error {
	for _, value := range []string{spec.DeploymentID, spec.WorkerID} {
		parsed, err := uuid.Parse(strings.TrimSpace(value))
		if err != nil || parsed == uuid.Nil {
			return fmt.Errorf("%w: Worker bootstrap identifiers are invalid", ErrInvalid)
		}
	}
	endpoint, err := url.Parse(strings.TrimSpace(spec.ControlPlaneEndpoint))
	if err != nil || endpoint.Scheme != "grpcs" || endpoint.Host == "" || (endpoint.Path != "" && endpoint.Path != "/") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		len(spec.ControlPlaneEndpoint) > 1024 || security.ContainsLikelySecret(spec.ControlPlaneEndpoint) || spec.EnrollmentExpectedRevision < 1 {
		return fmt.Errorf("%w: Worker identity bootstrap scope is invalid", ErrInvalid)
	}
	return nil
}

// ValidateAWSDependencies rejects a topology which is not bound by the typed
// resource spec before the durable mutation intent is recorded.
func ValidateAWSDependencies(kind Type, dependencies []ProviderDependency, spec *AWSResourceSpecV1) error {
	if spec == nil {
		return fmt.Errorf("%w: AWS typed spec is required", ErrInvalid)
	}
	counts := make(map[Type]int)
	seen := make(map[string]struct{}, len(dependencies))
	for _, dependency := range dependencies {
		if dependency.ResourceID == "" || dependency.ProviderID == "" || !validType(dependency.Type) {
			return fmt.Errorf("%w: AWS dependency is incomplete", ErrInvalid)
		}
		if _, duplicate := seen[dependency.ResourceID]; duplicate {
			return fmt.Errorf("%w: duplicate AWS dependency", ErrInvalid)
		}
		seen[dependency.ResourceID] = struct{}{}
		counts[dependency.Type]++
	}
	switch kind {
	case TypeSG, TypeEBS:
		if len(dependencies) != 0 {
			return fmt.Errorf("%w: resource does not accept dependencies", ErrInvalid)
		}
	case TypeENI:
		existing := spec.NetworkInterface != nil && spec.NetworkInterface.ExistingSecurityGroupID != ""
		owned := len(dependencies) == 1 && counts[TypeSG] == 1
		if existing == owned {
			return fmt.Errorf("%w: ENI requires an existing or one owned security group", ErrInvalid)
		}
	case TypeEC2:
		if counts[TypeENI] != 1 || counts[TypeEBS] > 1 || len(dependencies) != counts[TypeENI]+counts[TypeEBS] {
			return fmt.Errorf("%w: EC2 requires one ENI and at most one EBS volume", ErrInvalid)
		}
		hasDataVolume := counts[TypeEBS] == 1
		if spec.Instance == nil || hasDataVolume != (spec.Instance.DataDeviceName != "") {
			return fmt.Errorf("%w: EC2 data device must match its EBS dependency", ErrInvalid)
		}
	default:
		return fmt.Errorf("%w: AWS provider resource type is not implemented", ErrInvalid)
	}
	return nil
}
