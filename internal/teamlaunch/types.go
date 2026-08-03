// Package teamlaunch defines the exact provider-launch facts covered by one
// Team approval. It is separate from the legacy single-Worker Cloud Plan and
// has no AWS SDK, credential, shell, or provider mutation capability.
package teamlaunch

import (
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
)

const (
	SchemaV1 = "dirextalk.agent.team-launch-authorization/v1"

	ConnectivityDirectPublicTLSV1   ConnectivityMode  = "direct_public_tls_v1"
	SecurityGroupDedicatedNoIngress SecurityGroupMode = "dedicated_no_ingress"
	PurchaseOnDemand                PurchaseOption    = "on_demand"
	RetentionEphemeralAutoDestroy   RetentionClass    = "ephemeral_auto_destroy"
	ShutdownTerminate               ShutdownBehavior  = "terminate"
)

var (
	ErrInvalid      = errors.New("invalid Team launch authorization")
	ErrExpired      = errors.New("Team launch authorization is not currently active")
	ErrPlanChanged  = errors.New("Team launch authorization no longer matches Plan")
	ErrImageChanged = errors.New("Team Worker image evidence changed")
)

type ConnectivityMode string
type SecurityGroupMode string
type PurchaseOption string
type RetentionClass string
type ShutdownBehavior string

// EgressRuleV1 is the exact dedicated security-group rule approved for a
// Worker. V1 permits only TLS and the AWS VPC resolver; arbitrary ports remain
// outside the Central Agent's provider capability.
type EgressRuleV1 struct {
	Protocol string `json:"protocol"`
	FromPort uint16 `json:"from_port"`
	ToPort   uint16 `json:"to_port"`
	CIDRv4   string `json:"cidr_v4"`
}

// NetworkV1 is deliberately outbound-only. Public IPv4 permits TLS egress to
// the Agent and model gateway; it does not authorize an inbound listener.
type NetworkV1 struct {
	ConnectivityMode     ConnectivityMode  `json:"connectivity_mode"`
	VPCID                string            `json:"vpc_id"`
	SubnetID             string            `json:"subnet_id"`
	AvailabilityZone     string            `json:"availability_zone"`
	SecurityGroupMode    SecurityGroupMode `json:"security_group_mode"`
	PublicIPv4           bool              `json:"public_ipv4"`
	PublicInbound        bool              `json:"public_inbound"`
	ControlPlaneEndpoint string            `json:"control_plane_endpoint"`
	Egress               []EgressRuleV1    `json:"egress"`
}

type RetentionV1 struct {
	Class                  RetentionClass `json:"class"`
	AutoDestroy            bool           `json:"auto_destroy"`
	MaximumLifetimeSeconds uint64         `json:"maximum_lifetime_seconds"`
	DestroyGraceSeconds    uint64         `json:"destroy_grace_seconds"`
}

type WorkerImageV1 struct {
	PublicationDigest     string              `json:"publication_digest"`
	AgentInstanceID       string              `json:"agent_instance_id"`
	AccountID             string              `json:"account_id"`
	Region                string              `json:"region"`
	Architecture          recipe.Architecture `json:"architecture"`
	ImageID               string              `json:"image_id"`
	ImageDigest           string              `json:"image_digest"`
	RootSnapshotID        string              `json:"root_snapshot_id"`
	ReleaseManifestDigest string              `json:"release_manifest_digest"`
	WorkerRootFSDigest    string              `json:"worker_rootfs_digest"`
	WorkerBinaryDigest    string              `json:"worker_binary_digest"`
	ObservedAt            time.Time           `json:"observed_at"`
}

type RootStorageV1 struct {
	DeviceName          string `json:"device_name"`
	SizeGiB             uint64 `json:"size_gib"`
	VolumeType          string `json:"volume_type"`
	IOPS                uint32 `json:"iops"`
	ThroughputMiBPS     uint32 `json:"throughput_mibps"`
	KMSKeyID            string `json:"kms_key_id"`
	Encrypted           bool   `json:"encrypted"`
	DeleteOnTermination bool   `json:"delete_on_termination"`
}

type RoleLaunchV1 struct {
	RoleID                    string                               `json:"role_id"`
	RuntimeReleaseID          string                               `json:"runtime_release_id"`
	RuntimeImageDigest        string                               `json:"runtime_image_digest"`
	Marketplace               *teamplan.WorkerMarketplaceBindingV1 `json:"marketplace,omitempty"`
	RuntimeInstallationDigest string                               `json:"runtime_installation_digest"`
	RuntimeExecutableDigest   string                               `json:"runtime_executable_digest"`
	ComputeOfferID            string                               `json:"compute_offer_id"`
	InstanceType              string                               `json:"instance_type"`
	Architecture              recipe.Architecture                  `json:"architecture"`
	VCPU                      uint32                               `json:"vcpu"`
	MemoryMiB                 uint64                               `json:"memory_mib"`
	PurchaseOption            PurchaseOption                       `json:"purchase_option"`
	InstanceProfileName       string                               `json:"instance_profile_name"`
	EBSOptimized              bool                                 `json:"ebs_optimized"`
	RequireIMDSv2             bool                                 `json:"require_imdsv2"`
	MetadataResponseHopLimit  uint32                               `json:"metadata_response_hop_limit"`
	ShutdownBehavior          ShutdownBehavior                     `json:"shutdown_behavior"`
	RootStorage               RootStorageV1                        `json:"root_storage"`
	WorkerImage               WorkerImageV1                        `json:"worker_image"`
	MaximumApprovedCostMicros uint64                               `json:"maximum_approved_cost_micros"`
}

// AuthorizationV1 is added to the device-signing challenge by digest. It
// authorizes only exact launch facts and a bounded launch window. Every actual
// provider create must also present a fresh trusted quote within the approved
// role and whole-Team cost envelopes.
type AuthorizationV1 struct {
	SchemaVersion                string                 `json:"schema_version"`
	AuthorizationID              string                 `json:"authorization_id"`
	AgentInstanceID              string                 `json:"agent_instance_id"`
	OwnerID                      string                 `json:"owner_id"`
	PlanID                       string                 `json:"plan_id"`
	PlanRevision                 uint64                 `json:"plan_revision"`
	PlanDigest                   string                 `json:"plan_digest"`
	ApprovalID                   string                 `json:"approval_id"`
	ProviderScope                teamplan.ProviderScope `json:"provider_scope"`
	Region                       string                 `json:"region"`
	Network                      NetworkV1              `json:"network"`
	Retention                    RetentionV1            `json:"retention"`
	WorkerCount                  uint32                 `json:"worker_count"`
	MaxConcurrentBillableWorkers uint32                 `json:"max_concurrent_billable_workers"`
	Currency                     string                 `json:"currency"`
	HardBudgetMicros             uint64                 `json:"hard_budget_micros"`
	RequiresFreshQuote           bool                   `json:"requires_fresh_quote"`
	MaximumQuoteAgeSeconds       uint64                 `json:"maximum_quote_age_seconds"`
	LaunchNotBefore              time.Time              `json:"launch_not_before"`
	LaunchNotAfter               time.Time              `json:"launch_not_after"`
	Roles                        []RoleLaunchV1         `json:"roles"`
}

type RoleSelection struct {
	RoleID                    string
	RuntimeInstallationDigest string
	RuntimeExecutableDigest   string
	WorkerRelease             workerrelease.ReleaseV1
}

type BuildRequest struct {
	Plan            teamplan.Plan
	AgentInstanceID string
	ApprovalID      string
	Network         NetworkV1
	Retention       RetentionV1
	LaunchNotBefore time.Time
	LaunchNotAfter  time.Time
	RoleSelections  []RoleSelection
}
