// Package approval owns immutable cloud-plan projections and device-signed
// approvals. The package contains public data only; signing private keys remain
// exclusively on user devices.
package approval

import (
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

type VolumeScopeV1 = cloudquote.VolumeScopeV1
type VolumeDisposition = cloudquote.VolumeDisposition
type ServiceOperationScopeV1 = cloudquote.ServiceOperationScopeV1
type PrivateEndpointOperationSpecV1 = cloudquote.PrivateEndpointOperationSpecV1
type PrivateEndpointServiceV1 = cloudquote.PrivateEndpointServiceV1
type PrivateEndpointTypeV1 = cloudquote.PrivateEndpointTypeV1
type EndpointSecurityGroupSourceV1 = cloudquote.EndpointSecurityGroupSourceV1
type PrivateConnectivityMode = cloudquote.PrivateConnectivityMode
type SnapshotOperationSpecV1 = cloudquote.SnapshotOperationSpecV1
type SnapshotOperationDispositionV1 = cloudquote.SnapshotOperationDispositionV1

const (
	VolumeDeleteWithDeployment                       = cloudquote.VolumeDeleteWithDeployment
	VolumeRetainWithManagedService                   = cloudquote.VolumeRetainWithManagedService
	PrivateEndpointServiceS3                         = cloudquote.PrivateEndpointServiceS3
	PrivateEndpointServiceSecretsManager             = cloudquote.PrivateEndpointServiceSecretsManager
	PrivateEndpointTypeGateway                       = cloudquote.PrivateEndpointTypeGateway
	PrivateEndpointTypeInterface                     = cloudquote.PrivateEndpointTypeInterface
	EndpointSecurityGroupPlanExisting                = cloudquote.EndpointSecurityGroupPlanExisting
	EndpointSecurityGroupWorkerDedicated             = cloudquote.EndpointSecurityGroupWorkerDedicated
	EndpointSecurityGroupEndpointDedicatedFromWorker = cloudquote.EndpointSecurityGroupEndpointDedicatedFromWorker
	PrivateConnectivityNoNATEndpointsV1              = cloudquote.PrivateConnectivityNoNATEndpointsV1
	SnapshotDeleteWithDeployment                     = cloudquote.SnapshotDeleteWithDeployment
	SnapshotRetainWithManagedService                 = cloudquote.SnapshotRetainWithManagedService
)

const (
	PlanSchemaV1             = "dirextalk.agent.cloud.plan/v1"
	PlanSchemaV2             = "dirextalk.agent.cloud.plan/v2"
	ApprovalSchemaV1         = "dirextalk.agent.cloud.approval/v1"
	ApprovalSchemaV2         = "dirextalk.agent.cloud.approval/v2"
	ApprovalSigningPayloadV1 = "dirextalk.agent.cloud.approval-signing-payload/v1"
	ApprovalSigningPayloadV2 = "dirextalk.agent.cloud.approval-signing-payload/v2"
)

type PlanStatus string

const (
	PlanResearching          PlanStatus = "researching"
	PlanQuoting              PlanStatus = "quoting"
	PlanReadyForConfirmation PlanStatus = "ready_for_confirmation"
	PlanApproved             PlanStatus = "approved"
	PlanExpired              PlanStatus = "expired"
	PlanSuperseded           PlanStatus = "superseded"
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

type IntegrationKind string

const (
	IntegrationMCP  IntegrationKind = "mcp"
	IntegrationACP  IntegrationKind = "acp"
	IntegrationGRPC IntegrationKind = "grpc"
	IntegrationWeb  IntegrationKind = "web"
)

type RetentionClass string

const (
	RetentionEphemeral RetentionClass = "ephemeral"
	RetentionManaged   RetentionClass = "managed"
)

type PlanV1 struct {
	SchemaVersion     string                   `json:"schema_version"`
	AgentInstanceID   string                   `json:"agent_instance_id"`
	OwnerID           string                   `json:"owner_id"`
	PlanID            string                   `json:"plan_id"`
	Revision          uint64                   `json:"revision"`
	Status            PlanStatus               `json:"status"`
	ConnectionID      string                   `json:"connection_id"`
	Recipe            RecipeBindingV1          `json:"recipe"`
	Quote             QuoteBindingV1           `json:"quote"`
	ResourceScope     ResourceScopeV1          `json:"resource_scope"`
	NetworkScope      NetworkScopeV1           `json:"network_scope"`
	SecretScope       []SecretReferenceV1      `json:"secret_scope,omitempty"`
	IntegrationScope  []IntegrationScopeV1     `json:"integration_scope,omitempty"`
	RetentionScope    RetentionScopeV1         `json:"retention_scope"`
	ServiceOperations *ServiceOperationScopeV1 `json:"service_operations,omitempty"`
}

type RecipeBindingV1 struct {
	RecipeID string          `json:"recipe_id"`
	Digest   string          `json:"digest"`
	Maturity recipe.Maturity `json:"maturity"`
}

type QuoteBindingV1 struct {
	QuoteID     string    `json:"quote_id"`
	Digest      string    `json:"digest"`
	ScopeDigest string    `json:"scope_digest"`
	CandidateID string    `json:"candidate_id"`
	ValidUntil  time.Time `json:"valid_until"`
}

type ResourceScopeV1 struct {
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
	VPCID                  string                  `json:"vpc_id"`
	SubnetID               string                  `json:"subnet_id"`
	SecurityGroupMode      SecurityGroupMode       `json:"security_group_mode"`
	SecurityGroupID        string                  `json:"security_group_id,omitempty"`
	PublicIPv4             bool                    `json:"public_ipv4"`
	EntryPoint             EntryPointKind          `json:"entry_point"`
	PublicExposure         bool                    `json:"public_exposure"`
	IngressPorts           []uint32                `json:"ingress_ports,omitempty"`
	Hostname               string                  `json:"hostname,omitempty"`
	TLSRequired            bool                    `json:"tls_required"`
	AuthenticationRequired bool                    `json:"authentication_required"`
	RouteTableID           string                  `json:"route_table_id,omitempty"`
	ControlPlaneEndpoint   string                  `json:"control_plane_endpoint,omitempty"`
	PrivateConnectivity    PrivateConnectivityMode `json:"private_connectivity,omitempty"`
}

type SecretReferenceV1 struct {
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

type ApprovalV1 struct {
	SchemaVersion     string                   `json:"schema_version"`
	HashAlgorithm     string                   `json:"hash_algorithm"`
	ApprovalID        string                   `json:"approval_id"`
	AgentInstanceID   string                   `json:"agent_instance_id"`
	OwnerID           string                   `json:"owner_id"`
	PlanID            string                   `json:"plan_id"`
	PlanRevision      uint64                   `json:"plan_revision"`
	PlanHash          string                   `json:"plan_hash"`
	ConnectionID      string                   `json:"connection_id"`
	RecipeDigest      string                   `json:"recipe_digest"`
	QuoteID           string                   `json:"quote_id"`
	QuoteDigest       string                   `json:"quote_digest"`
	QuoteScopeDigest  string                   `json:"quote_scope_digest"`
	QuoteCandidateID  string                   `json:"quote_candidate_id"`
	QuoteValidUntil   time.Time                `json:"quote_valid_until"`
	ResourceScope     ResourceScopeV1          `json:"resource_scope"`
	NetworkScope      NetworkScopeV1           `json:"network_scope"`
	SecretScope       []SecretReferenceV1      `json:"secret_scope,omitempty"`
	IntegrationScope  []IntegrationScopeV1     `json:"integration_scope,omitempty"`
	RetentionScope    RetentionScopeV1         `json:"retention_scope"`
	ServiceOperations *ServiceOperationScopeV1 `json:"service_operations,omitempty"`
	ChallengeID       string                   `json:"challenge_id"`
	SignerKeyID       string                   `json:"signer_key_id"`
	ExpiresAt         time.Time                `json:"expires_at"`
	Signature         string                   `json:"signature,omitempty"`
}
