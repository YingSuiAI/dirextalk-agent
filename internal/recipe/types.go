// Package recipe defines portable, versioned, secret-free deployment recipes.
// Recipes describe desired behavior and names from typed Worker registries;
// they never carry credentials, shell fragments, or provider-control commands.
package recipe

import "time"

const SchemaV1 = "dirextalk.agent.recipe/v1"

type Maturity string

const (
	MaturityExperimental Maturity = "experimental"
	MaturityManaged      Maturity = "managed"
)

type Architecture string

const (
	ArchitectureAMD64 Architecture = "amd64"
	ArchitectureARM64 Architecture = "arm64"
)

type SourceKind string

const (
	SourceRepository    SourceKind = "repository"
	SourceDocumentation SourceKind = "documentation"
	SourceRelease       SourceKind = "release"
)

type SecretDelivery string

const (
	SecretDeliveryFile        SecretDelivery = "file"
	SecretDeliveryEnvironment SecretDelivery = "environment"
)

type ProbeKind string

const (
	ProbeHTTP   ProbeKind = "http"
	ProbeTCP    ProbeKind = "tcp"
	ProbeAction ProbeKind = "action"
)

type ActionInputKind string

const (
	ActionInputConfig     ActionInputKind = "config"
	ActionInputSource     ActionInputKind = "source"
	ActionInputVolumeSlot ActionInputKind = "volume_slot"
	ActionInputDataSlot   ActionInputKind = "data_slot"
	ActionInputSecretSlot ActionInputKind = "secret_slot"
)

type DataLocationKind string

const (
	DataLocationWorkerEphemeral DataLocationKind = "worker_ephemeral"
	DataLocationWorkerVolume    DataLocationKind = "worker_volume"
	DataLocationObjectStore     DataLocationKind = "object_store"
	DataLocationExternal        DataLocationKind = "external"
)

type RestartMode string

const (
	RestartAlways    RestartMode = "always"
	RestartOnFailure RestartMode = "on_failure"
	RestartManual    RestartMode = "manual"
)

type NetworkProtocol string

const (
	NetworkHTTPS NetworkProtocol = "https"
	NetworkDNS   NetworkProtocol = "dns"
)

type ListenerProtocol string

const (
	ListenerHTTP  ListenerProtocol = "http"
	ListenerHTTPS ListenerProtocol = "https"
	ListenerTCP   ListenerProtocol = "tcp"
)

type ListenerBindScope string

const (
	BindLoopback ListenerBindScope = "loopback"
	BindPrivate  ListenerBindScope = "private"
)

type PublicIngressMode string

const (
	PublicIngressNone       PublicIngressMode = "none"
	PublicIngressManagedTLS PublicIngressMode = "managed_tls"
)

type PairingPayloadDelivery string

const PairingPayloadOnDemandEncrypted PairingPayloadDelivery = "on_demand_encrypted"

type IntegrationKind string

const (
	IntegrationMCP       IntegrationKind = "mcp"
	IntegrationACP       IntegrationKind = "acp"
	IntegrationConnector IntegrationKind = "connector"
	IntegrationWeb       IntegrationKind = "web"
)

type IntegrationTransport string

const (
	TransportMCPStreamableHTTP IntegrationTransport = "mcp_streamable_http"
	TransportACP               IntegrationTransport = "acp"
	TransportConnector         IntegrationTransport = "dirextalk_connector"
	TransportWebHTTP           IntegrationTransport = "web_http"
)

type RecipeV1 struct {
	SchemaVersion     string                     `json:"schema_version"`
	RecipeID          string                     `json:"recipe_id"`
	Name              string                     `json:"name"`
	Maturity          Maturity                   `json:"maturity"`
	Sources           []SourceV1                 `json:"sources"`
	Requirements      ResourceRequirementsV1     `json:"requirements"`
	Install           InstallContractV1          `json:"install"`
	Health            HealthContractV1           `json:"health"`
	Lifecycle         LifecycleContractV1        `json:"lifecycle"`
	VolumeSlots       []VolumeSlotRequirementV1  `json:"volume_slots,omitempty"`
	DataSlots         []DataSlotRequirementV1    `json:"data_slots,omitempty"`
	SecretSlots       []SecretSlotRequirementV1  `json:"secret_slots,omitempty"`
	Network           *NetworkContractV1         `json:"network,omitempty"`
	Restart           *RestartContractV1         `json:"restart,omitempty"`
	Pairing           *PairingContractV1         `json:"pairing,omitempty"`
	Integrations      []IntegrationDeclarationV1 `json:"integrations,omitempty"`
	ManagedAcceptance *ManagedAcceptanceV1       `json:"managed_acceptance,omitempty"`
}

type SourceV1 struct {
	ID             string                `json:"id,omitempty"`
	URL            string                `json:"url"`
	ArtifactURL    string                `json:"artifact_url,omitempty"`
	Version        string                `json:"version"`
	Commit         string                `json:"commit"`
	ArtifactDigest string                `json:"artifact_digest"`
	ContentDigest  string                `json:"content_digest"`
	License        string                `json:"license"`
	RetrievedAt    time.Time             `json:"retrieved_at"`
	Official       bool                  `json:"official"`
	Kind           SourceKind            `json:"kind,omitempty"`
	Repository     *RepositoryIdentityV1 `json:"repository,omitempty"`
}

// ResolvedArtifactURL keeps official-source research evidence separate from
// the immutable bytes installed by a Recipe. Legacy Recipes use URL for both.
func (source SourceV1) ResolvedArtifactURL() string {
	if source.ArtifactURL != "" {
		return source.ArtifactURL
	}
	return source.URL
}

// RepositoryIdentityV1 identifies source ownership without embedding a clone
// credential or credential-bearing URL.
type RepositoryIdentityV1 struct {
	Host      string `json:"host"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

type ResourceRequirementsV1 struct {
	MinVCPU         uint32                      `json:"min_vcpu"`
	MinMemoryMiB    uint64                      `json:"min_memory_mib"`
	MinDiskGiB      uint64                      `json:"min_disk_gib"`
	Architecture    Architecture                `json:"architecture"`
	GPURequired     bool                        `json:"gpu_required"`
	MinGPUMemoryMiB uint64                      `json:"min_gpu_memory_mib,omitempty"`
	GPUFamily       string                      `json:"gpu_family,omitempty"`
	DataLocations   []DataLocationRequirementV1 `json:"data_locations,omitempty"`
}

type DataLocationRequirementV1 struct {
	DataSlotID         string           `json:"data_slot_id"`
	Kind               DataLocationKind `json:"kind"`
	VolumeSlotID       string           `json:"volume_slot_id,omitempty"`
	Residency          []string         `json:"residency,omitempty"`
	EncryptionRequired bool             `json:"encryption_required"`
}

type InstallContractV1 struct {
	RootRequired       bool                   `json:"root_required"`
	TimeoutSeconds     uint32                 `json:"timeout_seconds"`
	CheckpointNames    []string               `json:"checkpoint_names"`
	AllowedAdaptations []string               `json:"allowed_adaptations,omitempty"`
	Adaptations        []AdaptationRuleV1     `json:"adaptations,omitempty"`
	Installer          *InstallerCapabilityV1 `json:"installer,omitempty"`
	Steps              []InstallStepV1        `json:"steps"`
}

// InstallerCapabilityV1 is a portable, secret-free declaration of exact
// privileged commands. It is part of the Recipe digest and therefore of the
// device-approved Plan. Runtime actions can select only command_id; they can
// never add argv, environment, paths, or references.
type InstallerCapabilityV1 struct {
	Artifacts []InstallerArtifactV1 `json:"artifacts"`
	Commands  []InstallerCommandV1  `json:"commands"`
}

type InstallerArtifactV1 struct {
	Name       string `json:"name"`
	SourceID   string `json:"source_id"`
	SizeBytes  int64  `json:"size_bytes"`
	TargetPath string `json:"target_path"`
}

type InstallerCommandV1 struct {
	CommandID        string   `json:"command_id"`
	Argv             []string `json:"argv"`
	WorkingDirectory string   `json:"working_directory"`
	TimeoutSeconds   uint32   `json:"timeout_seconds"`
	ArtifactRefs     []string `json:"artifact_refs"`
	VolumeSlotRefs   []string `json:"volume_slot_refs,omitempty"`
	SecretSlotRefs   []string `json:"secret_slot_refs,omitempty"`
}

// InstallStepV1 identifies a typed Worker action from the locked action
// registry. Summary is descriptive only and is never interpreted as code.
type InstallStepV1 struct {
	ID             string          `json:"id"`
	Summary        string          `json:"summary"`
	TimeoutSeconds uint32          `json:"timeout_seconds"`
	Action         string          `json:"action,omitempty"`
	Inputs         []ActionInputV1 `json:"inputs,omitempty"`
	Checkpoint     string          `json:"checkpoint,omitempty"`
}

type ActionInputV1 struct {
	Name string          `json:"name"`
	Kind ActionInputKind `json:"kind"`
	Ref  string          `json:"ref"`
}

type AdaptationRuleV1 struct {
	Action      string `json:"action"`
	Summary     string `json:"summary"`
	MaxAttempts uint32 `json:"max_attempts"`
}

type HealthContractV1 struct {
	Liveness  ProbeV1 `json:"liveness"`
	Readiness ProbeV1 `json:"readiness"`
	Semantic  ProbeV1 `json:"semantic"`
}

type ProbeV1 struct {
	Kind           ProbeKind `json:"kind"`
	Target         string    `json:"target"`
	TimeoutSeconds uint32    `json:"timeout_seconds,omitempty"`
}

// LifecycleContractV1 contains names from the Worker's typed lifecycle-action
// registry, never executable command strings.
type LifecycleContractV1 struct {
	Start       string `json:"start"`
	Stop        string `json:"stop"`
	Maintenance string `json:"maintenance"`
	Restart     string `json:"restart"`
	Upgrade     string `json:"upgrade"`
	Rollback    string `json:"rollback"`
	Backup      string `json:"backup"`
	Restore     string `json:"restore"`
	Destroy     string `json:"destroy"`
}

type VolumeSlotRequirementV1 struct {
	SlotID             string `json:"slot_id"`
	Purpose            string `json:"purpose"`
	ReadOnly           bool   `json:"read_only"`
	MountPath          string `json:"mount_path,omitempty"`
	Persistent         bool   `json:"persistent,omitempty"`
	EncryptionRequired bool   `json:"encryption_required,omitempty"`
}

type DataSlotRequirementV1 struct {
	SlotID   string `json:"slot_id"`
	Purpose  string `json:"purpose"`
	ReadOnly bool   `json:"read_only"`
}

type SecretSlotRequirementV1 struct {
	SlotID     string         `json:"slot_id"`
	Purpose    string         `json:"purpose"`
	Delivery   SecretDelivery `json:"delivery"`
	TargetPath string         `json:"target_path,omitempty"`
	FileMode   uint32         `json:"file_mode,omitempty"`
	OwnerUID   uint32         `json:"owner_uid,omitempty"`
	OwnerGID   uint32         `json:"owner_gid,omitempty"`
}

type RestartContractV1 struct {
	Mode                RestartMode `json:"mode"`
	Action              string      `json:"action"`
	MaxAttempts         uint32      `json:"max_attempts"`
	RecoveryCheckpoints []string    `json:"recovery_checkpoints"`
}

// NetworkContractV1 is a declaration, not an enforcement claim. The approved
// Plan and provider remain responsible for the actual cloud boundary.
type NetworkContractV1 struct {
	DefaultDeny   bool             `json:"default_deny"`
	Outbound      []OutboundRuleV1 `json:"outbound,omitempty"`
	Listeners     []ListenerV1     `json:"listeners,omitempty"`
	PublicIngress PublicIngressV1  `json:"public_ingress"`
}

type OutboundRuleV1 struct {
	ID          string          `json:"id"`
	Protocol    NetworkProtocol `json:"protocol"`
	Destination string          `json:"destination"`
	Port        uint32          `json:"port"`
}

type ListenerV1 struct {
	ID        string            `json:"id"`
	Protocol  ListenerProtocol  `json:"protocol"`
	BindScope ListenerBindScope `json:"bind_scope"`
	Port      uint32            `json:"port"`
}

type PublicIngressV1 struct {
	Mode                   PublicIngressMode `json:"mode"`
	ListenerID             string            `json:"listener_id,omitempty"`
	TLSRequired            bool              `json:"tls_required,omitempty"`
	AuthenticationRequired bool              `json:"authentication_required,omitempty"`
}

type PairingContractV1 struct {
	BeginAction     string                 `json:"begin_action"`
	ResumeAction    string                 `json:"resume_action"`
	BeginCommandID  string                 `json:"begin_command_id"`
	ResumeCommandID string                 `json:"resume_command_id"`
	PayloadDelivery PairingPayloadDelivery `json:"payload_delivery"`
	TimeoutSeconds  uint32                 `json:"timeout_seconds"`
}

type IntegrationDeclarationV1 struct {
	ID                     string               `json:"id"`
	Kind                   IntegrationKind      `json:"kind"`
	Transport              IntegrationTransport `json:"transport"`
	ListenerID             string               `json:"listener_id,omitempty"`
	SecretSlotID           string               `json:"secret_slot_id,omitempty"`
	AuthenticationRequired bool                 `json:"authentication_required"`
}

// ManagedAcceptanceV1 binds promotion to the exact experimental Recipe
// digest and external, device-signed acceptance/verification records. It does
// not carry a signature or owner secret itself.
type ManagedAcceptanceV1 struct {
	ExperimentalDigest string    `json:"experimental_digest"`
	AcceptanceRef      string    `json:"acceptance_ref"`
	VerificationRef    string    `json:"verification_ref"`
	AcceptedAt         time.Time `json:"accepted_at"`
}
