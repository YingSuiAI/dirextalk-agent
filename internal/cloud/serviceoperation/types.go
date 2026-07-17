package serviceoperation

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	ScopeSchemaV1            = "dirextalk.agent.cloud.service-operation-scope/v1"
	ChallengeSchemaV1        = "dirextalk.agent.cloud.service-operation-challenge/v1"
	SigningPayloadV1         = "dirextalk.agent.cloud.service-operation-signing-payload/v1"
	IntentManagedPreparation = "MANAGED_PREPARATION"
)

var (
	ErrInvalid          = errors.New("invalid service operation")
	ErrNotFound         = errors.New("service operation not found")
	ErrRevisionConflict = errors.New("service operation revision conflict")
	ErrApprovalRequired = errors.New("service operation requires device approval")
	digestPattern       = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	instancePattern     = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)
	volumePattern       = regexp.MustCompile(`^vol-[0-9a-f]{8,17}$`)
	zonePattern         = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+[a-z]$`)
	kmsPattern          = regexp.MustCompile(`^(?:alias/[A-Za-z0-9/_-]{1,240}|arn:(?:aws|aws-cn|aws-us-gov):kms:[a-z0-9-]+:[0-9]{12}:(?:key/[0-9a-f-]{36}|alias/[A-Za-z0-9/_-]{1,240}))$`)
	currencyPattern     = regexp.MustCompile(`^[A-Z]{3}$`)
	devicePattern       = regexp.MustCompile(`^/dev/sd[f-p]$`)
)

type Phase string

const (
	PhaseRestart        Phase = "restart"
	PhaseBackup         Phase = "backup"
	PhaseRestoreCreate  Phase = "restore_create"
	PhaseRestoreSwap    Phase = "restore_swap"
	PhaseSemanticHealth Phase = "semantic_health"
	PhaseFinalize       Phase = "finalize"
)

var phaseSequence = [...]Phase{PhaseRestart, PhaseBackup, PhaseRestoreCreate, PhaseRestoreSwap, PhaseSemanticHealth, PhaseFinalize}

func Phases() []Phase { return slices.Clone(phaseSequence[:]) }

type ResourceFactV1 struct {
	ResourceID string `json:"resource_id"`
	ProviderID string `json:"provider_id"`
	Revision   int64  `json:"revision"`
	SpecDigest string `json:"spec_digest"`
	TagDigest  string `json:"tag_digest"`
}

type RestartReferenceV1 struct {
	OperationID             string `json:"operation_id"`
	ExpectedInitialRevision int64  `json:"expected_initial_revision"`
	Action                  string `json:"action"`
	LifecycleRestartRef     string `json:"lifecycle_restart_ref"`
	ExecutionBundleDigest   string `json:"execution_bundle_digest"`
}

type VolumePreparationV1 struct {
	SlotID                      string         `json:"slot_id"`
	SourceVolume                ResourceFactV1 `json:"source_volume"`
	SnapshotResourceID          string         `json:"snapshot_resource_id"`
	ReplacementVolumeResourceID string         `json:"replacement_volume_resource_id"`
	AvailabilityZone            string         `json:"availability_zone"`
	SizeGiB                     uint32         `json:"size_gib"`
	VolumeType                  string         `json:"volume_type"`
	IOPS                        uint32         `json:"iops"`
	ThroughputMiBPS             uint32         `json:"throughput_mibps"`
	KMSKeyID                    string         `json:"kms_key_id"`
	DeviceName                  string         `json:"device_name"`
	MountPath                   string         `json:"mount_path"`
	ReadOnly                    bool           `json:"read_only"`
	Persistent                  bool           `json:"persistent"`
	Disposition                 string         `json:"disposition"`
}

func (volume VolumePreparationV1) SourceSpecDigest() (string, error) {
	awsSpec := &resource.AWSResourceSpecV1{SchemaVersion: resource.AWSResourceSpecSchemaV1, Volume: &resource.AWSEBSVolumeSpecV1{
		AvailabilityZone: volume.AvailabilityZone, SizeGiB: volume.SizeGiB, VolumeType: volume.VolumeType,
		IOPS: volume.IOPS, ThroughputMiBPS: volume.ThroughputMiBPS, KMSKeyID: volume.KMSKeyID,
		SlotID: volume.SlotID, DeviceName: volume.DeviceName, MountPath: volume.MountPath,
		ReadOnly: volume.ReadOnly, Persistent: volume.Persistent, Disposition: resource.AWSVolumeDisposition(volume.Disposition),
	}}
	digest, err := awsSpec.Digest(resource.TypeEBS)
	if err != nil {
		return "", ErrInvalid
	}
	return digest, nil
}

type ScopeV1 struct {
	SchemaVersion                   string                `json:"schema_version"`
	Intent                          string                `json:"intent"`
	PreparationOperationID          string                `json:"preparation_operation_id"`
	OwnerID                         string                `json:"owner_id"`
	AgentInstanceID                 string                `json:"agent_instance_id"`
	DeploymentID                    string                `json:"deployment_id"`
	DeploymentRevision              int64                 `json:"deployment_revision"`
	ConnectionID                    string                `json:"connection_id"`
	ConnectionRevision              int64                 `json:"connection_revision"`
	PlanID                          string                `json:"plan_id"`
	PlanRevision                    int64                 `json:"plan_revision"`
	PlanHash                        string                `json:"plan_hash"`
	RecipeID                        string                `json:"recipe_id"`
	RecipeDigest                    string                `json:"recipe_digest"`
	RecipeRevision                  int64                 `json:"recipe_revision"`
	EC2                             ResourceFactV1        `json:"ec2"`
	SourceVolumes                   []ResourceFactV1      `json:"source_volumes"`
	Restart                         RestartReferenceV1    `json:"restart"`
	Volumes                         []VolumePreparationV1 `json:"volumes"`
	ServiceMonitorRevision          int64                 `json:"service_monitor_revision"`
	ServiceMonitorSuiteDigest       string                `json:"service_monitor_suite_digest"`
	Currency                        string                `json:"currency"`
	CostAlertAmountMinor            int64                 `json:"cost_alert_amount_minor"`
	ExpectedInstalledManifestDigest string                `json:"expected_installed_manifest_digest"`
}

func DeriveVolumeResourceIDs(operationID, sourceVolumeResourceID, slotID string) (string, string, error) {
	operation, operationErr := uuid.Parse(operationID)
	source, err := uuid.Parse(sourceVolumeResourceID)
	if operationErr != nil || operation == uuid.Nil || operation.String() != operationID ||
		err != nil || source == uuid.Nil || source.String() != sourceVolumeResourceID || !validRef(slotID) {
		return "", "", ErrInvalid
	}
	return uuid.NewSHA1(operation, []byte("snapshot:"+sourceVolumeResourceID+":"+slotID)).String(),
		uuid.NewSHA1(operation, []byte("replacement:"+sourceVolumeResourceID+":"+slotID)).String(), nil
}

func (scope ScopeV1) Validate() error {
	if scope.SchemaVersion != ScopeSchemaV1 || scope.Intent != IntentManagedPreparation || !validUUID(scope.PreparationOperationID) ||
		!validRef(scope.OwnerID) || !validUUID(scope.AgentInstanceID) || !validUUID(scope.DeploymentID) ||
		scope.DeploymentRevision < 1 || !validUUID(scope.ConnectionID) || scope.ConnectionRevision < 1 ||
		!validUUID(scope.PlanID) || scope.PlanRevision < 1 || !validDigest(scope.PlanHash) ||
		!validRef(scope.RecipeID) || !validDigest(scope.RecipeDigest) || scope.RecipeRevision < 1 ||
		!validResource(scope.EC2, instancePattern) ||
		scope.Restart.OperationID != uuid.NewSHA1(uuid.MustParse(scope.PreparationOperationID), []byte("restart")).String() ||
		scope.Restart.ExpectedInitialRevision != 1 || scope.Restart.Action != "restart" ||
		!validRef(scope.Restart.LifecycleRestartRef) || !validDigest(scope.Restart.ExecutionBundleDigest) ||
		scope.ServiceMonitorRevision < 1 || !validDigest(scope.ServiceMonitorSuiteDigest) ||
		!currencyPattern.MatchString(scope.Currency) || scope.CostAlertAmountMinor <= 0 ||
		!validDigest(scope.ExpectedInstalledManifestDigest) || len(scope.SourceVolumes) == 0 ||
		len(scope.SourceVolumes) != len(scope.Volumes) {
		return ErrInvalid
	}
	sourceByID := make(map[string]ResourceFactV1, len(scope.SourceVolumes))
	sourceProviders := make(map[string]struct{}, len(scope.SourceVolumes))
	previous := ""
	for _, source := range scope.SourceVolumes {
		if !validResource(source, volumePattern) || source.ResourceID <= previous || source.ResourceID == scope.EC2.ResourceID ||
			source.ProviderID == scope.EC2.ProviderID {
			return ErrInvalid
		}
		if _, duplicate := sourceProviders[source.ProviderID]; duplicate {
			return ErrInvalid
		}
		sourceByID[source.ResourceID], previous = source, source.ResourceID
		sourceProviders[source.ProviderID] = struct{}{}
	}
	previousSlot := ""
	usedSources := make(map[string]struct{}, len(scope.Volumes))
	usedDevices := make(map[string]struct{}, len(scope.Volumes))
	for _, volume := range scope.Volumes {
		source, found := sourceByID[volume.SourceVolume.ResourceID]
		snapshotID, replacementID, err := DeriveVolumeResourceIDs(scope.PreparationOperationID, volume.SourceVolume.ResourceID, volume.SlotID)
		specDigest, specErr := volume.SourceSpecDigest()
		if !found || err != nil || source != volume.SourceVolume || volume.SlotID <= previousSlot ||
			volume.SnapshotResourceID != snapshotID || volume.ReplacementVolumeResourceID != replacementID ||
			!zonePattern.MatchString(volume.AvailabilityZone) || volume.SizeGiB == 0 || volume.SizeGiB > 65_536 ||
			!kmsPattern.MatchString(volume.KMSKeyID) || !devicePattern.MatchString(volume.DeviceName) ||
			!volume.Persistent || volume.Disposition != string(cloudapproval.VolumeRetainWithManagedService) ||
			specErr != nil || specDigest != volume.SourceVolume.SpecDigest {
			return ErrInvalid
		}
		if _, duplicate := usedSources[volume.SourceVolume.ResourceID]; duplicate {
			return ErrInvalid
		}
		if _, duplicate := usedDevices[volume.DeviceName]; duplicate {
			return ErrInvalid
		}
		usedSources[volume.SourceVolume.ResourceID], usedDevices[volume.DeviceName] = struct{}{}, struct{}{}
		previousSlot = volume.SlotID
	}
	return nil
}

type ChallengeV1 struct {
	SchemaVersion string    `json:"schema_version"`
	ChallengeID   string    `json:"challenge_id"`
	OperationID   string    `json:"operation_id"`
	SignerKeyID   string    `json:"signer_key_id"`
	Scope         ScopeV1   `json:"scope"`
	ScopeDigest   string    `json:"scope_digest"`
	IssuedAt      time.Time `json:"issued_at"`
	ExpiresAt     time.Time `json:"expires_at"`
}

type signingPayloadV1 struct {
	SchemaVersion  string    `json:"schema_version"`
	PayloadVersion string    `json:"payload_version"`
	Intent         string    `json:"intent"`
	ChallengeID    string    `json:"challenge_id"`
	OperationID    string    `json:"operation_id"`
	SignerKeyID    string    `json:"signer_key_id"`
	Scope          ScopeV1   `json:"scope"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

func (challenge ChallengeV1) payload() signingPayloadV1 {
	return signingPayloadV1{ChallengeSchemaV1, SigningPayloadV1, IntentManagedPreparation, challenge.ChallengeID,
		challenge.OperationID, challenge.SignerKeyID, challenge.Scope, challenge.IssuedAt, challenge.ExpiresAt}
}

func (challenge ChallengeV1) SigningPayload() ([]byte, error) {
	if challenge.SchemaVersion != ChallengeSchemaV1 || !validUUID(challenge.ChallengeID) ||
		!validUUID(challenge.OperationID) || challenge.Scope.PreparationOperationID != challenge.OperationID ||
		!validRef(challenge.SignerKeyID) || challenge.Scope.Validate() != nil ||
		challenge.IssuedAt.Location() != time.UTC || challenge.ExpiresAt.Location() != time.UTC ||
		!challenge.ExpiresAt.After(challenge.IssuedAt) || challenge.ExpiresAt.Sub(challenge.IssuedAt) > 5*time.Minute {
		return nil, ErrInvalid
	}
	digest, err := canonical.Digest(challenge.payload())
	if err != nil || digest != challenge.ScopeDigest {
		return nil, ErrInvalid
	}
	return canonical.Marshal(challenge.payload())
}

func SigningPayloadDigest(challenge ChallengeV1) (string, error) {
	if challenge.Scope.Validate() != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(challenge.payload())
}

type SignatureV1 struct {
	ChallengeID string
	OperationID string
	SignerKeyID string
	Signature   []byte
}

type Status string

const (
	StatusAwaitingApproval Status = "awaiting_approval"
	StatusApproved         Status = "approved"
	StatusRunning          Status = "running"
	StatusSucceeded        Status = "succeeded"
	StatusFailedTerminal   Status = "failed_terminal"
)

type StepV1 struct {
	Phase        Phase
	Ordinal      int
	Status       StepStatus
	Revision     int64
	IntentDigest string
	StartedAt    *time.Time
	CompletedAt  *time.Time
}

type StepStatus string

const (
	StepPending   StepStatus = "pending"
	StepRunning   StepStatus = "running"
	StepSucceeded StepStatus = "succeeded"
)

type OperationV1 struct {
	OperationID  string
	Challenge    ChallengeV1
	Status       Status
	CurrentPhase Phase
	Signature    []byte
	Revision     int64
	Steps        []StepV1
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedAt   *time.Time
	Result       *ManagedPreparationResultV1
}

type ManagedPreparationResultV1 struct {
	PreparationID         string    `json:"preparation_id"`
	PreparationDigest     string    `json:"preparation_digest"`
	FreshHealthDigest     string    `json:"fresh_health_digest"`
	FreshHealthRevision   int64     `json:"fresh_health_revision"`
	FreshHealthObservedAt time.Time `json:"fresh_health_observed_at"`
	CostDigest            string    `json:"cost_digest"`
	CostPolicyRevision    int64     `json:"cost_policy_revision"`
	CostObservedAt        time.Time `json:"cost_observed_at"`
	StackDigest           string    `json:"stack_digest"`
	StackRevision         int64     `json:"stack_revision"`
	StackObservedAt       time.Time `json:"stack_observed_at"`
}

func (result ManagedPreparationResultV1) Validate() error {
	if !validUUID(result.PreparationID) || !validDigest(result.PreparationDigest) ||
		!validDigest(result.FreshHealthDigest) || result.FreshHealthRevision < 1 ||
		result.FreshHealthObservedAt.IsZero() || result.FreshHealthObservedAt.Location() != time.UTC ||
		!validDigest(result.CostDigest) || result.CostPolicyRevision < 1 ||
		result.CostObservedAt.IsZero() || result.CostObservedAt.Location() != time.UTC ||
		!validDigest(result.StackDigest) || result.StackRevision < 1 ||
		result.StackObservedAt.IsZero() || result.StackObservedAt.Location() != time.UTC {
		return ErrInvalid
	}
	return nil
}

type Mutation struct {
	ClientID       string
	CredentialID   string
	IdempotencyKey string
	RequestHash    string
}

type ScopeBuilder interface {
	BuildManagedPreparationScope(context.Context, string, string, string, int64) (ScopeV1, error)
}
type DeviceRepository = cloudapproval.DeviceKeyRepository
type Repository interface {
	FindServiceOperationChallengeReplay(context.Context, Mutation) (ChallengeV1, error)
	CreateServiceOperationChallenge(context.Context, Mutation, ChallengeV1) (ChallengeV1, error)
	GetServiceOperationChallenge(context.Context, string, string) (ChallengeV1, error)
	FindServiceOperationApprovalReplay(context.Context, Mutation) (OperationV1, error)
	ApproveServiceOperation(context.Context, Mutation, SignatureV1, time.Time) (OperationV1, error)
	GetServiceOperation(context.Context, string, string) (OperationV1, error)
	BeginServiceOperationPhase(context.Context, string, int64, Phase, string, time.Time) (OperationV1, error)
	AdvanceServiceOperationPhase(context.Context, string, int64, Phase, Phase, time.Time) (OperationV1, error)
	CompleteServiceOperation(context.Context, string, int64, ManagedPreparationResultV1, time.Time) (OperationV1, error)
	ListRecoverableServiceOperations(context.Context, int) ([]OperationV1, error)
}

func ValidatePhaseAdvance(current, next Phase) error {
	if current == PhaseFinalize && next == "" {
		return nil
	}
	for index, phase := range phaseSequence {
		if phase == current && index+1 < len(phaseSequence) && phaseSequence[index+1] == next {
			return nil
		}
	}
	return ErrRevisionConflict
}

func RequestHash(value any) (string, error) {
	digest, err := canonical.Digest(value)
	if err != nil {
		return "", fmt.Errorf("%w: request hash", ErrInvalid)
	}
	return digest, nil
}

func validUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
func validDigest(value string) bool { return digestPattern.MatchString(value) }
func validRef(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= 255 && !security.ContainsLikelySecret(value)
}
func validResource(value ResourceFactV1, providerPattern *regexp.Regexp) bool {
	return validUUID(value.ResourceID) && providerPattern.MatchString(value.ProviderID) && value.Revision > 0 &&
		validDigest(value.SpecDigest) && validDigest(value.TagDigest)
}
func validateMutation(ctx context.Context, mutation Mutation) error {
	if ctx == nil || !validRef(mutation.ClientID) || !validUUID(mutation.CredentialID) ||
		!validUUID(mutation.IdempotencyKey) || !validDigest(mutation.RequestHash) {
		return ErrInvalid
	}
	return nil
}
func signatureValid(challenge ChallengeV1, signature SignatureV1, publicKey ed25519.PublicKey, now time.Time) error {
	if signature.ChallengeID != challenge.ChallengeID || signature.OperationID != challenge.OperationID ||
		signature.SignerKeyID != challenge.SignerKeyID || len(signature.Signature) != ed25519.SignatureSize ||
		!now.Before(challenge.ExpiresAt) {
		return ErrApprovalRequired
	}
	payload, err := challenge.SigningPayload()
	if err != nil || !ed25519.Verify(publicKey, payload, signature.Signature) {
		return ErrApprovalRequired
	}
	return nil
}

func cloneScope(scope ScopeV1) ScopeV1 {
	scope.SourceVolumes = slices.Clone(scope.SourceVolumes)
	scope.Volumes = slices.Clone(scope.Volumes)
	sort.Slice(scope.SourceVolumes, func(i, j int) bool { return scope.SourceVolumes[i].ResourceID < scope.SourceVolumes[j].ResourceID })
	sort.Slice(scope.Volumes, func(i, j int) bool { return scope.Volumes[i].SlotID < scope.Volumes[j].SlotID })
	return scope
}
