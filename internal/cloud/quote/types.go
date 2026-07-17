// Package quote owns immutable cloud-price estimates and the exact plan scope
// each estimate covers. It contains no AWS SDK dependency; provider adapters
// implement the narrow, read-only PricingPort.
package quote

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

const (
	SchemaV1      = "dirextalk.agent.cloud.quote/v1"
	ScopeSchemaV1 = "dirextalk.agent.cloud.quote-scope/v1"
	Validity      = 15 * time.Minute
)

type CandidateProfile string

const (
	CandidateEconomic    CandidateProfile = "economic"
	CandidateRecommended CandidateProfile = "recommended"
	CandidatePerformance CandidateProfile = "performance"
)

type PurchaseOption string

const (
	PurchaseOnDemand PurchaseOption = "on_demand"
	PurchaseSpot     PurchaseOption = "spot"
)

type EntryPointKind string

const (
	EntryPointNone       EntryPointKind = "none"
	EntryPointALB        EntryPointKind = "alb"
	EntryPointCloudFront EntryPointKind = "cloudfront"
)

type SecurityGroupMode string

const (
	SecurityGroupExisting        SecurityGroupMode = "existing"
	SecurityGroupCreateDedicated SecurityGroupMode = "create_dedicated"
)

type RetentionClass string

const (
	RetentionEphemeral RetentionClass = "ephemeral"
	RetentionManaged   RetentionClass = "managed"
)

type IntegrationKind string

const (
	IntegrationMCP  IntegrationKind = "mcp"
	IntegrationACP  IntegrationKind = "acp"
	IntegrationGRPC IntegrationKind = "grpc"
	IntegrationWeb  IntegrationKind = "web"
)

// ScopeV1 is the complete price-sensitive and approval-sensitive projection
// for one candidate. Any change produces another digest and requires a quote.
type ScopeV1 struct {
	SchemaVersion    string               `json:"schema_version"`
	AgentInstanceID  string               `json:"agent_instance_id"`
	OwnerID          string               `json:"owner_id"`
	ConnectionID     string               `json:"connection_id"`
	Recipe           RecipeBindingV1      `json:"recipe"`
	Resource         ResourceScopeV1      `json:"resource"`
	Network          NetworkScopeV1       `json:"network"`
	SecretScope      []SecretScopeV1      `json:"secret_scope,omitempty"`
	IntegrationScope []IntegrationScopeV1 `json:"integration_scope,omitempty"`
	Retention        RetentionScopeV1     `json:"retention"`
}

type RecipeBindingV1 struct {
	RecipeID string          `json:"recipe_id"`
	Digest   string          `json:"digest"`
	Maturity recipe.Maturity `json:"maturity"`
}

type VolumeDisposition string

const (
	VolumeDeleteWithDeployment     VolumeDisposition = "delete_with_deployment"
	VolumeRetainWithManagedService VolumeDisposition = "retain_with_managed_service"
)

// VolumeScopeV1 is one approval- and price-bound data-volume slot. It is
// deliberately separate from the Worker root disk: a persistent Recipe slot
// can never be satisfied implicitly by increasing ResourceScopeV1.DiskGiB.
type VolumeScopeV1 struct {
	SlotID          string            `json:"slot_id"`
	SizeGiB         uint32            `json:"size_gib"`
	VolumeType      string            `json:"volume_type"`
	IOPS            uint32            `json:"iops,omitempty"`
	ThroughputMiBPS uint32            `json:"throughput_mibps,omitempty"`
	Encrypted       bool              `json:"encrypted"`
	KMSKeyID        string            `json:"kms_key_id"`
	DeviceName      string            `json:"device_name"`
	MountPath       string            `json:"mount_path"`
	ReadOnly        bool              `json:"read_only"`
	Persistent      bool              `json:"persistent"`
	Disposition     VolumeDisposition `json:"disposition"`
}

// ResourceScopeV1 intentionally includes storage, image, and GPU details that
// can alter availability or price. One deployment currently means one Worker.
type ResourceScopeV1 struct {
	CandidateID           CandidateProfile    `json:"candidate_id"`
	Region                string              `json:"region"`
	AvailabilityZones     []string            `json:"availability_zones"`
	InstanceType          string              `json:"instance_type"`
	InstanceCount         uint32              `json:"instance_count"`
	Architecture          recipe.Architecture `json:"architecture"`
	VCPU                  uint32              `json:"vcpu"`
	MemoryMiB             uint64              `json:"memory_mib"`
	GPUType               string              `json:"gpu_type,omitempty"`
	GPUCount              uint32              `json:"gpu_count,omitempty"`
	GPUMemoryMiB          uint64              `json:"gpu_memory_mib,omitempty"`
	DiskGiB               uint64              `json:"disk_gib"`
	VolumeType            string              `json:"volume_type"`
	VolumeIOPS            uint32              `json:"volume_iops,omitempty"`
	VolumeThroughputMiBPS uint32              `json:"volume_throughput_mibps,omitempty"`
	VolumeEncrypted       bool                `json:"volume_encrypted"`
	PurchaseOption        PurchaseOption      `json:"purchase_option"`
	WorkerImageID         string              `json:"worker_image_id"`
	WorkerImageDigest     string              `json:"worker_image_digest"`
	VolumeScopes          []VolumeScopeV1     `json:"volume_scopes,omitempty"`
}

type NetworkScopeV1 struct {
	VPCID                  string            `json:"vpc_id"`
	SubnetID               string            `json:"subnet_id"`
	SecurityGroupMode      SecurityGroupMode `json:"security_group_mode"`
	SecurityGroupID        string            `json:"security_group_id,omitempty"`
	PublicIPv4             bool              `json:"public_ipv4"`
	EntryPoint             EntryPointKind    `json:"entry_point"`
	PublicExposure         bool              `json:"public_exposure"`
	IngressPorts           []uint32          `json:"ingress_ports,omitempty"`
	Hostname               string            `json:"hostname,omitempty"`
	TLSRequired            bool              `json:"tls_required"`
	AuthenticationRequired bool              `json:"authentication_required"`
}

type SecretScopeV1 struct {
	SecretRef string                `json:"secret_ref"`
	Purpose   string                `json:"purpose"`
	Delivery  recipe.SecretDelivery `json:"delivery"`
}

type IntegrationScopeV1 struct {
	Kind   IntegrationKind `json:"kind"`
	Name   string          `json:"name"`
	Scopes []string        `json:"scopes,omitempty"`
}

type RetentionScopeV1 struct {
	Class              RetentionClass `json:"class"`
	AutoDestroy        bool           `json:"auto_destroy"`
	GracePeriodSeconds uint32         `json:"grace_period_seconds"`
	MaxLifetimeSeconds uint64         `json:"max_lifetime_seconds"`
}

// UsageV1 makes non-compute estimates explicit. Values are integral units;
// provider adapters perform any price-list decimal conversion into micros.
type UsageV1 struct {
	RuntimeHoursPerMonth uint32 `json:"runtime_hours_per_month"`
	PublicIPv4Hours      uint32 `json:"public_ipv4_hours"`
	LogIngestMiB         uint64 `json:"log_ingest_mib"`
	LogStoredMiBMonths   uint64 `json:"log_stored_mib_months"`
	SnapshotGiBMonths    uint64 `json:"snapshot_gib_months"`
	EntryHours           uint32 `json:"entry_hours"`
	InternetEgressMiB    uint64 `json:"internet_egress_mib"`
}

// SpotQualificationV1 is persisted evidence, not an Agent assertion. A Spot
// candidate is rejected unless the evidence matches the exact Recipe digest.
type SpotQualificationV1 struct {
	EvidenceID           string    `json:"evidence_id"`
	RecipeDigest         string    `json:"recipe_digest"`
	CheckpointName       string    `json:"checkpoint_name"`
	ResumeAction         string    `json:"resume_action"`
	MaxRetries           uint32    `json:"max_retries"`
	CheckpointVerifiedAt time.Time `json:"checkpoint_verified_at"`
	InterruptionTestedAt time.Time `json:"interruption_tested_at"`
}

type RequestV1 struct {
	QuoteID           string               `json:"quote_id"`
	Scopes            []ScopeV1            `json:"scopes"`
	Usage             UsageV1              `json:"usage"`
	SpotQualification *SpotQualificationV1 `json:"spot_qualification,omitempty"`
}

// Money values are integer micro-units of QuoteV1.Currency. Floating point is
// absent from every quote and provider contract.
type CostCategory string

const (
	CostComputeOnDemand CostCategory = "ec2_on_demand"
	CostComputeSpot     CostCategory = "ec2_spot"
	CostEBS             CostCategory = "ebs"
	CostPublicIPv4      CostCategory = "public_ipv4"
	CostLogs            CostCategory = "logs"
	CostSnapshot        CostCategory = "snapshot"
	CostEntry           CostCategory = "entry"
	CostTraffic         CostCategory = "traffic"
)

type CostItemV1 struct {
	Category                  CostCategory `json:"category"`
	Description               string       `json:"description"`
	SourceID                  string       `json:"source_id"`
	HourlyEstimateMicros      uint64       `json:"hourly_estimate_micros"`
	MonthlyEstimateMicros     uint64       `json:"monthly_estimate_micros"`
	MaximumLaunchAmountMicros uint64       `json:"maximum_launch_amount_micros"`
}

type QuotaEvidenceV1 struct {
	ServiceCode   string `json:"service_code"`
	QuotaCode     string `json:"quota_code"`
	LimitUnits    uint64 `json:"limit_units"`
	UsedUnits     uint64 `json:"used_units"`
	RequiredUnits uint64 `json:"required_units"`
}

type CandidateV1 struct {
	CandidateID               CandidateProfile  `json:"candidate_id"`
	Scope                     ScopeV1           `json:"scope"`
	ScopeDigest               string            `json:"scope_digest"`
	OfferedAvailabilityZones  []string          `json:"offered_availability_zones"`
	Quotas                    []QuotaEvidenceV1 `json:"quotas"`
	CostItems                 []CostItemV1      `json:"cost_items"`
	HourlyEstimateMicros      uint64            `json:"hourly_estimate_micros"`
	MonthlyEstimateMicros     uint64            `json:"monthly_estimate_micros"`
	MaximumLaunchAmountMicros uint64            `json:"maximum_launch_amount_micros"`
}

type QuoteV1 struct {
	SchemaVersion string               `json:"schema_version"`
	QuoteID       string               `json:"quote_id"`
	QuotedAt      time.Time            `json:"quoted_at"`
	ValidUntil    time.Time            `json:"valid_until"`
	Currency      string               `json:"currency"`
	Candidates    []CandidateV1        `json:"candidates"`
	Usage         UsageV1              `json:"usage"`
	Assumptions   []string             `json:"assumptions"`
	Exclusions    []string             `json:"exclusions"`
	SpotEvidence  *SpotQualificationV1 `json:"spot_evidence,omitempty"`
}

// PricingPort is the only provider surface used by the quote domain. It is
// read-only and cannot create resources or receive secret references.
type PricingPort interface {
	Price(context.Context, PricingQueryV1) (PricingSnapshotV1, error)
}

type PricingQueryV1 struct {
	Region     string                    `json:"region"`
	Zones      []string                  `json:"zones"`
	Candidates []PricingCandidateQueryV1 `json:"candidates"`
	Usage      UsageV1                   `json:"usage"`
}

type PricingCandidateQueryV1 struct {
	CandidateID           CandidateProfile    `json:"candidate_id"`
	InstanceType          string              `json:"instance_type"`
	InstanceCount         uint32              `json:"instance_count"`
	Architecture          recipe.Architecture `json:"architecture"`
	DiskGiB               uint64              `json:"disk_gib"`
	VolumeType            string              `json:"volume_type"`
	VolumeIOPS            uint32              `json:"volume_iops,omitempty"`
	VolumeThroughputMiBPS uint32              `json:"volume_throughput_mibps,omitempty"`
	PurchaseOption        PurchaseOption      `json:"purchase_option"`
	EntryPoint            EntryPointKind      `json:"entry_point"`
	PublicIPv4            bool                `json:"public_ipv4"`
	PublicExposure        bool                `json:"public_exposure"`
	DataVolumes           []VolumePricingV1   `json:"data_volumes,omitempty"`
}

// VolumePricingV1 is the minimal non-secret projection consumed by the AWS
// Price List adapter. Mount paths, KMS aliases, and Recipe slot names never
// need to cross the read-only pricing boundary.
type VolumePricingV1 struct {
	SizeGiB         uint32 `json:"size_gib"`
	VolumeType      string `json:"volume_type"`
	IOPS            uint32 `json:"iops,omitempty"`
	ThroughputMiBPS uint32 `json:"throughput_mibps,omitempty"`
}

type PricingSnapshotV1 struct {
	CapturedAt  time.Time          `json:"captured_at"`
	Currency    string             `json:"currency"`
	Offerings   []OfferingV1       `json:"offerings"`
	Quotas      []CandidateQuotaV1 `json:"quotas"`
	Prices      []CandidatePriceV1 `json:"prices"`
	Assumptions []string           `json:"assumptions"`
	Exclusions  []string           `json:"exclusions"`
}

type OfferingV1 struct {
	CandidateID       CandidateProfile    `json:"candidate_id"`
	Region            string              `json:"region"`
	InstanceType      string              `json:"instance_type"`
	Architecture      recipe.Architecture `json:"architecture"`
	PurchaseOption    PurchaseOption      `json:"purchase_option"`
	AvailabilityZones []string            `json:"availability_zones"`
}

type CandidateQuotaV1 struct {
	CandidateID CandidateProfile `json:"candidate_id"`
	Quota       QuotaEvidenceV1  `json:"quota"`
}

type CandidatePriceV1 struct {
	CandidateID CandidateProfile `json:"candidate_id"`
	CostItems   []CostItemV1     `json:"cost_items"`
}
