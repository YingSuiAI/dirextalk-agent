package managed

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
	ScopeSchemaV1              = "dirextalk.agent.cloud.managed-acceptance-scope/v1"
	ChallengeSchemaV1          = "dirextalk.agent.cloud.managed-acceptance-challenge/v1"
	CompatibilitySchemaV1      = "cloud-orchestrator/v1"
	SigningPayloadV2           = "service-management-acceptance-signing-payload/v2"
	SigningHashAlgorithmV1     = "deterministic-cbor-sha256"
	ManagementAcceptanceIntent = "service_management_acceptance"
	AcceptancePolicyV1         = "manual_verified_v1"
)

var (
	ErrInvalid          = errors.New("invalid managed acceptance")
	ErrNotFound         = errors.New("managed acceptance not found")
	ErrRevisionConflict = errors.New("managed acceptance revision conflict")
	ErrApprovalRequired = errors.New("managed acceptance requires device approval")
	namedDigestPattern  = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
	currencyPattern     = regexp.MustCompile(`^[A-Z]{3}$`)
	instanceIDPattern   = regexp.MustCompile(`^i-[0-9a-f]{17}$`)
	volumeIDPattern     = regexp.MustCompile(`^vol-[0-9a-f]{17}$`)
	networkIDPattern    = regexp.MustCompile(`^eni-[0-9a-f]{17}$`)
	snapshotIDPattern   = regexp.MustCompile(`^snap-[0-9a-f]{17}$`)
	imageIDPattern      = regexp.MustCompile(`^ami-[0-9a-f]{17}$`)
)

type LifecycleV1 struct {
	Start       string `json:"start"`
	Stop        string `json:"stop"`
	Maintenance string `json:"maintenance"`
	Restart     string `json:"restart"`
	Backup      string `json:"backup"`
	Restore     string `json:"restore"`
	Upgrade     string `json:"upgrade"`
	Rollback    string `json:"rollback"`
	Destroy     string `json:"destroy"`
}

type ProbeV1 struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
}

type HealthContractV1 struct {
	Liveness  ProbeV1 `json:"liveness"`
	Readiness ProbeV1 `json:"readiness"`
	Semantic  ProbeV1 `json:"semantic"`
}

type VolumeSlotV1 struct {
	SlotID    string `json:"slot_id"`
	VolumeRef string `json:"volume_ref"`
	ReadOnly  bool   `json:"read_only"`
}

type DataSlotV1 struct {
	SlotID   string `json:"slot_id"`
	DataRef  string `json:"data_ref"`
	ReadOnly bool   `json:"read_only"`
}

type SecretSlotV1 struct {
	SlotID    string `json:"slot_id"`
	SecretRef string `json:"secret_ref"`
}

type ResourceV1 struct {
	ResourceID string `json:"resource_id"`
	Type       string `json:"type"`
	Revision   int64  `json:"revision"`
	ProviderID string `json:"provider_id"`
	TagDigest  string `json:"tag_digest"`
}

type CompatibilityServiceV1 struct {
	ServiceID    string                   `json:"service_id"`
	DeploymentID string                   `json:"deployment_id"`
	RecipeID     string                   `json:"recipe_id"`
	Name         string                   `json:"name"`
	Status       string                   `json:"service_status"`
	Integration  string                   `json:"integration_status"`
	Revision     int64                    `json:"revision"`
	CreatedAt    int64                    `json:"created_at"`
	UpdatedAt    int64                    `json:"updated_at"`
	Backups      []CompatibilityBackupV1  `json:"backups"`
	Restores     []CompatibilityRestoreV1 `json:"restores"`
}

func (v CompatibilityServiceV1) Validate(scope ScopeV1) error {
	snapshotProviderIDs := make([]string, 0)
	for _, item := range scope.Resources {
		if resource.Type(item.Type) == resource.TypeSnapshot {
			snapshotProviderIDs = append(snapshotProviderIDs, item.ProviderID)
		}
	}
	sort.Strings(snapshotProviderIDs)
	if v.ServiceID != scope.ServiceID || v.DeploymentID != scope.DeploymentID || v.RecipeID != scope.RecipeID ||
		!validSafeRef(v.Name) || v.Status != "awaiting_management_acceptance" || !validSafeRef(v.Integration) ||
		v.Revision != int64(scope.ServiceRevision) || v.CreatedAt <= 0 || v.UpdatedAt < v.CreatedAt ||
		len(v.Backups) != 1 || len(v.Restores) != 1 ||
		v.Backups[0].Validate(scope, v.UpdatedAt) != nil || v.Restores[0].Validate(scope, v.UpdatedAt) != nil ||
		!slices.Equal(v.Backups[0].SnapshotIDs, snapshotProviderIDs) {
		return ErrInvalid
	}
	return nil
}

type CompatibilityBackupV1 struct {
	BackupID        string   `json:"backup_id"`
	ServiceID       string   `json:"service_id"`
	DeploymentID    string   `json:"deployment_id"`
	Status          string   `json:"status"`
	RetentionPolicy string   `json:"retention_policy"`
	ImageID         string   `json:"image_id,omitempty"`
	SnapshotIDs     []string `json:"snapshot_ids,omitempty"`
	Revision        int64    `json:"revision"`
	CreatedAt       int64    `json:"created_at"`
	UpdatedAt       int64    `json:"updated_at"`
}

func (v CompatibilityBackupV1) Validate(scope ScopeV1, serviceUpdatedAt int64) error {
	if v.BackupID != scope.BackupID || v.ServiceID != scope.ServiceID || v.DeploymentID != scope.DeploymentID ||
		v.Status != "available" || v.RetentionPolicy != "manual" || v.Revision != int64(scope.BackupRevision) ||
		v.CreatedAt <= 0 || v.UpdatedAt < v.CreatedAt || v.UpdatedAt > serviceUpdatedAt ||
		(v.ImageID != "" && !imageIDPattern.MatchString(v.ImageID)) ||
		!validProviderIDs(v.SnapshotIDs, snapshotIDPattern) {
		return ErrInvalid
	}
	return nil
}

type CompatibilityRestoreV1 struct {
	RestoreID            string   `json:"restore_id"`
	RestorePlanID        string   `json:"restore_plan_id"`
	ServiceID            string   `json:"service_id"`
	DeploymentID         string   `json:"deployment_id"`
	BackupID             string   `json:"backup_id"`
	Status               string   `json:"status"`
	OriginalVolumeIDs    []string `json:"original_volume_ids,omitempty"`
	ReplacementVolumeIDs []string `json:"replacement_volume_ids,omitempty"`
	Revision             int64    `json:"revision"`
	CreatedAt            int64    `json:"created_at"`
	UpdatedAt            int64    `json:"updated_at"`
}

func (v CompatibilityRestoreV1) Validate(scope ScopeV1, serviceUpdatedAt int64) error {
	if v.RestoreID != scope.RestoreID || !validUUID(v.RestorePlanID) || v.ServiceID != scope.ServiceID ||
		v.DeploymentID != scope.DeploymentID || v.BackupID != scope.BackupID || v.Status != "succeeded" ||
		v.Revision != int64(scope.RestoreRevision) || v.CreatedAt <= 0 || v.UpdatedAt < v.CreatedAt ||
		v.UpdatedAt > serviceUpdatedAt || len(v.OriginalVolumeIDs) != len(v.ReplacementVolumeIDs) ||
		!validProviderIDs(v.OriginalVolumeIDs, volumeIDPattern) ||
		!validProviderIDs(v.ReplacementVolumeIDs, volumeIDPattern) {
		return ErrInvalid
	}
	return nil
}

type CompatibilityRecipeV1 struct {
	RecipeID  string `json:"recipe_id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Digest    string `json:"digest"`
	Maturity  string `json:"maturity"`
	Revision  int64  `json:"revision"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

func (v CompatibilityRecipeV1) Validate(scope ScopeV1) error {
	if v.RecipeID != scope.RecipeID || !validSafeRef(v.Name) || !validSafeRef(v.Version) || v.Digest != scope.RecipeDigest ||
		v.Maturity != scope.RecipeMaturity || v.Revision != int64(scope.RecipeRevision) || v.CreatedAt <= 0 || v.UpdatedAt < v.CreatedAt {
		return ErrInvalid
	}
	return nil
}

type CompatibilityAcceptanceV1 struct {
	AcceptanceID string `json:"acceptance_id"`
	ServiceID    string `json:"service_id"`
	RecipeID     string `json:"recipe_id"`
	Status       string `json:"status"`
	Revision     int64  `json:"revision"`
	CreatedAt    int64  `json:"created_at"`
	UpdatedAt    int64  `json:"updated_at"`
}

type SnapshotV1 struct {
	Scope   ScopeV1
	Service CompatibilityServiceV1
	Recipe  CompatibilityRecipeV1
}

type ScopeV1 struct {
	SchemaVersion                   string           `json:"schema_version"`
	AgentInstanceID                 string           `json:"agent_instance_id"`
	AcceptanceID                    string           `json:"acceptance_id"`
	ServiceID                       string           `json:"service_id"`
	ServiceRevision                 uint64           `json:"service_revision"`
	OwnerID                         string           `json:"owner_id"`
	DeploymentID                    string           `json:"deployment_id"`
	DeploymentRevision              int64            `json:"deployment_revision"`
	ConnectionID                    string           `json:"connection_id"`
	ConnectionRevision              int64            `json:"connection_revision"`
	PlanID                          string           `json:"plan_id"`
	PlanRevision                    uint64           `json:"plan_revision"`
	PlanHash                        string           `json:"plan_hash"`
	RecipeID                        string           `json:"recipe_id"`
	RecipeDigest                    string           `json:"recipe_digest"`
	RecipeRevision                  uint64           `json:"recipe_revision"`
	RecipeMaturity                  string           `json:"recipe_maturity"`
	InstalledManifestDigest         string           `json:"installed_manifest_digest"`
	ArtifactDigest                  string           `json:"artifact_digest"`
	ReadinessSemanticEvidenceDigest string           `json:"readiness_semantic_evidence_digest"`
	ReadinessStackObservationDigest string           `json:"readiness_stack_observation_digest"`
	RestartOperationID              string           `json:"restart_operation_id"`
	RestartOperationRevision        uint64           `json:"restart_operation_revision"`
	BackupID                        string           `json:"backup_id"`
	BackupRevision                  uint64           `json:"backup_revision"`
	RestoreID                       string           `json:"restore_id"`
	RestoreRevision                 uint64           `json:"restore_revision"`
	SourceArtifactDigests           []string         `json:"source_artifact_digests"`
	HealthRevision                  int64            `json:"health_revision"`
	HealthMonitorKind               string           `json:"health_monitor_kind"`
	HealthStatus                    string           `json:"health_status"`
	HealthEvidenceType              string           `json:"health_evidence_type"`
	HealthEvidenceDigest            string           `json:"health_evidence_digest"`
	HealthObservedAt                time.Time        `json:"health_observed_at"`
	Currency                        string           `json:"currency"`
	CostAlertAmountMinor            int64            `json:"cost_alert_amount_minor"`
	Health                          HealthContractV1 `json:"health"`
	Lifecycle                       LifecycleV1      `json:"lifecycle"`
	VolumeSlots                     []VolumeSlotV1   `json:"volume_slots"`
	DataSlots                       []DataSlotV1     `json:"data_slots"`
	SecretSlots                     []SecretSlotV1   `json:"secret_slots"`
	Resources                       []ResourceV1     `json:"resources"`
	DestroyInstanceID               string           `json:"destroy_instance_id"`
	DestroyVolumeIDs                []string         `json:"destroy_volume_ids"`
	DestroyNetworkInterfaceIDs      []string         `json:"destroy_network_interface_ids"`
	AcceptancePolicy                string           `json:"acceptance_policy"`
}

func (s ScopeV1) Validate() error {
	if s.SchemaVersion != ScopeSchemaV1 || s.AcceptancePolicy != AcceptancePolicyV1 || !validUUID(s.AgentInstanceID) ||
		!validUUID(s.AcceptanceID) || !validUUID(s.ServiceID) || !validUUID(s.DeploymentID) || !validUUID(s.ConnectionID) ||
		!validUUID(s.PlanID) || strings.TrimSpace(s.OwnerID) == "" || s.ServiceRevision < 1 || s.DeploymentRevision < 1 || s.ConnectionRevision < 1 ||
		s.PlanRevision < 1 || s.RecipeRevision < 1 || s.HealthRevision < 1 || s.HealthObservedAt.IsZero() ||
		!validDigest(s.PlanHash) || !validDigest(s.RecipeDigest) || !validDigest(s.InstalledManifestDigest) ||
		!validDigest(s.ArtifactDigest) || !validDigest(s.ReadinessSemanticEvidenceDigest) ||
		!validDigest(s.ReadinessStackObservationDigest) || !validDigest(s.HealthEvidenceDigest) ||
		s.HealthMonitorKind != "service" || s.HealthStatus != "healthy" || s.HealthEvidenceType != "independent_external" ||
		!currencyPattern.MatchString(s.Currency) ||
		s.CostAlertAmountMinor <= 0 || len(s.Resources) == 0 || len(s.OwnerID) > 255 || security.ContainsLikelySecret(s.OwnerID) ||
		strings.TrimSpace(s.OwnerID) != s.OwnerID || len(s.SourceArtifactDigests) == 0 || s.HealthObservedAt.Location() != time.UTC ||
		!validUUID(s.RestartOperationID) || s.RestartOperationRevision < 1 || !validUUID(s.BackupID) || s.BackupRevision < 1 ||
		!validUUID(s.RestoreID) || s.RestoreRevision < 1 {
		return ErrInvalid
	}
	for _, value := range []string{s.Lifecycle.Start, s.Lifecycle.Stop, s.Lifecycle.Maintenance, s.Lifecycle.Restart, s.Lifecycle.Backup, s.Lifecycle.Restore, s.Lifecycle.Upgrade, s.Lifecycle.Rollback, s.Lifecycle.Destroy} {
		if strings.TrimSpace(value) == "" || len(value) > 512 || security.ContainsLikelySecret(value) {
			return ErrInvalid
		}
	}
	for _, probe := range []ProbeV1{s.Health.Liveness, s.Health.Readiness, s.Health.Semantic} {
		if (probe.Kind != "http" && probe.Kind != "command") || !validSafeRef(probe.Target) {
			return ErrInvalid
		}
	}
	if !validSlots(s.VolumeSlots, func(slot VolumeSlotV1) (string, string) { return slot.SlotID, slot.VolumeRef }) ||
		!validSlots(s.DataSlots, func(slot DataSlotV1) (string, string) { return slot.SlotID, slot.DataRef }) ||
		!validSlots(s.SecretSlots, func(slot SecretSlotV1) (string, string) { return slot.SlotID, slot.SecretRef }) {
		return ErrInvalid
	}
	for _, digest := range s.SourceArtifactDigests {
		if !validDigest(digest) {
			return ErrInvalid
		}
	}
	if !sort.StringsAreSorted(s.SourceArtifactDigests) || len(s.SourceArtifactDigests) != len(slices.Compact(append([]string(nil), s.SourceArtifactDigests...))) {
		return ErrInvalid
	}
	seen, seenProviders, previousResourceID := map[string]struct{}{}, map[string]struct{}{}, ""
	destroyInstanceID := ""
	destroyVolumeIDs, destroyNetworkIDs := make([]string, 0), make([]string, 0)
	for _, item := range s.Resources {
		if !validUUID(item.ResourceID) || !validResourceType(item.Type) || item.Revision < 1 || !validSafeRef(item.ProviderID) || !validDigest(item.TagDigest) {
			return ErrInvalid
		}
		if _, exists := seen[item.ResourceID]; exists || item.ResourceID <= previousResourceID {
			return ErrInvalid
		}
		if _, exists := seenProviders[item.ProviderID]; exists {
			return ErrInvalid
		}
		seen[item.ResourceID] = struct{}{}
		seenProviders[item.ProviderID] = struct{}{}
		previousResourceID = item.ResourceID
		switch resource.Type(item.Type) {
		case resource.TypeEC2:
			if destroyInstanceID != "" {
				return ErrInvalid
			}
			destroyInstanceID = item.ProviderID
		case resource.TypeEBS:
			destroyVolumeIDs = append(destroyVolumeIDs, item.ProviderID)
		case resource.TypeENI:
			destroyNetworkIDs = append(destroyNetworkIDs, item.ProviderID)
		}
	}
	sort.Strings(destroyVolumeIDs)
	sort.Strings(destroyNetworkIDs)
	if !instanceIDPattern.MatchString(s.DestroyInstanceID) ||
		!validProviderIDs(s.DestroyVolumeIDs, volumeIDPattern) ||
		!validProviderIDs(s.DestroyNetworkInterfaceIDs, networkIDPattern) ||
		destroyInstanceID != s.DestroyInstanceID ||
		!slices.Equal(destroyVolumeIDs, s.DestroyVolumeIDs) ||
		!slices.Equal(destroyNetworkIDs, s.DestroyNetworkInterfaceIDs) {
		return ErrInvalid
	}
	return nil
}

type ChallengeV1 struct {
	SchemaVersion string                 `json:"schema_version"`
	ChallengeID   string                 `json:"challenge_id"`
	ApprovalID    string                 `json:"approval_id"`
	SignerKeyID   string                 `json:"signer_key_id"`
	Scope         ScopeV1                `json:"scope"`
	ScopeDigest   string                 `json:"scope_digest"`
	Service       CompatibilityServiceV1 `json:"service"`
	Recipe        CompatibilityRecipeV1  `json:"recipe"`
	IssuedAt      time.Time              `json:"issued_at"`
	ExpiresAt     time.Time              `json:"expires_at"`
}

func (c ChallengeV1) SigningPayload() ([]byte, error) {
	if c.SchemaVersion != ChallengeSchemaV1 || !validUUID(c.ChallengeID) || !validUUID(c.ApprovalID) ||
		!validSafeRef(c.SignerKeyID) || c.Scope.Validate() != nil || c.Scope.AcceptanceID != c.ApprovalID ||
		c.Service.Validate(c.Scope) != nil || c.Recipe.Validate(c.Scope) != nil ||
		c.IssuedAt.Location() != time.UTC || c.ExpiresAt.Location() != time.UTC ||
		!c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > 5*time.Minute ||
		c.Service.UpdatedAt > c.IssuedAt.UnixMilli() || c.Recipe.UpdatedAt > c.IssuedAt.UnixMilli() {
		return nil, ErrInvalid
	}
	payload, err := canonical.Marshal(c.compatibilitySigningPayload())
	if err != nil {
		return nil, ErrInvalid
	}
	payloadDigest, err := canonical.Digest(c.compatibilitySigningPayload())
	if err != nil || payloadDigest != c.ScopeDigest {
		return nil, ErrInvalid
	}
	return payload, nil
}

type compatibilityAcceptanceTargetV2 struct {
	AgentInstanceID                 string                   `json:"agent_instance_id"`
	OwnerID                         string                   `json:"owner_id"`
	AcceptanceID                    string                   `json:"acceptance_id"`
	ServiceID                       string                   `json:"service_id"`
	ServiceRevision                 uint64                   `json:"service_revision"`
	DeploymentID                    string                   `json:"deployment_id"`
	DeploymentRevision              int64                    `json:"deployment_revision"`
	CloudConnectionID               string                   `json:"cloud_connection_id"`
	ConnectionRevision              int64                    `json:"connection_revision"`
	PlanID                          string                   `json:"plan_id"`
	PlanRevision                    uint64                   `json:"plan_revision"`
	PlanHash                        string                   `json:"plan_hash"`
	RecipeID                        string                   `json:"recipe_id"`
	RecipeDigest                    string                   `json:"recipe_digest"`
	RecipeRevision                  uint64                   `json:"recipe_revision"`
	RecipeMaturity                  string                   `json:"recipe_maturity"`
	InstalledManifestDigest         string                   `json:"installed_manifest_digest"`
	ArtifactDigest                  string                   `json:"artifact_digest"`
	ReadinessSemanticEvidenceDigest string                   `json:"readiness_semantic_evidence_digest"`
	ReadinessStackObservationDigest string                   `json:"readiness_stack_observation_digest"`
	RestartOperationID              string                   `json:"restart_operation_id"`
	RestartOperationRevision        uint64                   `json:"restart_operation_revision"`
	BackupID                        string                   `json:"backup_id"`
	BackupRevision                  uint64                   `json:"backup_revision"`
	RestoreID                       string                   `json:"restore_id"`
	RestoreRevision                 uint64                   `json:"restore_revision"`
	SourceArtifactDigests           []string                 `json:"source_artifact_digests"`
	HealthRevision                  int64                    `json:"health_revision"`
	HealthMonitorKind               string                   `json:"health_monitor_kind"`
	HealthStatus                    string                   `json:"health_status"`
	HealthEvidenceType              string                   `json:"health_evidence_type"`
	HealthEvidenceDigest            string                   `json:"health_evidence_digest"`
	HealthObservedAt                time.Time                `json:"health_observed_at"`
	Currency                        string                   `json:"currency"`
	CostAlertAmountMinor            int64                    `json:"cost_alert_amount_minor"`
	Health                          HealthContractV1         `json:"health"`
	Lifecycle                       compatibilityLifecycleV1 `json:"lifecycle"`
	VolumeSlots                     []VolumeSlotV1           `json:"volume_slots"`
	DataSlots                       []DataSlotV1             `json:"data_slots"`
	SecretSlots                     []SecretSlotV1           `json:"secret_slots"`
	Resources                       []ResourceV1             `json:"resources"`
	DestroyInstanceID               string                   `json:"destroy_instance_id"`
	DestroyVolumeIDs                []string                 `json:"destroy_volume_ids"`
	DestroyNetworkInterfaceIDs      []string                 `json:"destroy_network_interface_ids"`
	AcceptancePolicy                string                   `json:"acceptance_policy"`
}

type compatibilityLifecycleV1 struct {
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

type compatibilitySigningPayloadV2 struct {
	SchemaVersion  string `json:"schema_version"`
	PayloadVersion string `json:"payload_version"`
	HashAlgorithm  string `json:"hash_algorithm"`
	Intent         string `json:"intent"`
	ApprovalID     string `json:"approval_id"`
	ChallengeID    string `json:"challenge_id"`
	SignerKeyID    string `json:"signer_key_id"`
	compatibilityAcceptanceTargetV2
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (c ChallengeV1) compatibilitySigningPayload() compatibilitySigningPayloadV2 {
	s := c.Scope
	target := compatibilityAcceptanceTargetV2{
		AgentInstanceID: s.AgentInstanceID, OwnerID: s.OwnerID,
		AcceptanceID: s.AcceptanceID, ServiceID: s.ServiceID, ServiceRevision: s.ServiceRevision,
		DeploymentID: s.DeploymentID, DeploymentRevision: s.DeploymentRevision, CloudConnectionID: s.ConnectionID, ConnectionRevision: s.ConnectionRevision,
		PlanID: s.PlanID, PlanRevision: s.PlanRevision, PlanHash: s.PlanHash,
		RecipeID: s.RecipeID, RecipeDigest: s.RecipeDigest, RecipeRevision: s.RecipeRevision, RecipeMaturity: s.RecipeMaturity,
		InstalledManifestDigest: s.InstalledManifestDigest, ArtifactDigest: s.ArtifactDigest,
		ReadinessSemanticEvidenceDigest: s.ReadinessSemanticEvidenceDigest, ReadinessStackObservationDigest: s.ReadinessStackObservationDigest,
		RestartOperationID: s.RestartOperationID, RestartOperationRevision: s.RestartOperationRevision,
		BackupID: s.BackupID, BackupRevision: s.BackupRevision, RestoreID: s.RestoreID, RestoreRevision: s.RestoreRevision,
		SourceArtifactDigests: slices.Clone(s.SourceArtifactDigests),
		HealthRevision:        s.HealthRevision, HealthMonitorKind: s.HealthMonitorKind, HealthStatus: s.HealthStatus,
		HealthEvidenceType: s.HealthEvidenceType, HealthEvidenceDigest: s.HealthEvidenceDigest, HealthObservedAt: s.HealthObservedAt,
		Currency: s.Currency, CostAlertAmountMinor: s.CostAlertAmountMinor, Health: s.Health,
		Lifecycle:   compatibilityLifecycleV1{s.Lifecycle.Start, s.Lifecycle.Stop, s.Lifecycle.Maintenance, s.Lifecycle.Restart, s.Lifecycle.Upgrade, s.Lifecycle.Rollback, s.Lifecycle.Backup, s.Lifecycle.Restore, s.Lifecycle.Destroy},
		VolumeSlots: slices.Clone(s.VolumeSlots), DataSlots: slices.Clone(s.DataSlots), SecretSlots: slices.Clone(s.SecretSlots),
		Resources:         slices.Clone(s.Resources),
		DestroyInstanceID: s.DestroyInstanceID, DestroyVolumeIDs: slices.Clone(s.DestroyVolumeIDs),
		DestroyNetworkInterfaceIDs: slices.Clone(s.DestroyNetworkInterfaceIDs), AcceptancePolicy: s.AcceptancePolicy,
	}
	sort.Strings(target.SourceArtifactDigests)
	sort.Slice(target.VolumeSlots, func(i, j int) bool { return target.VolumeSlots[i].SlotID < target.VolumeSlots[j].SlotID })
	sort.Slice(target.DataSlots, func(i, j int) bool { return target.DataSlots[i].SlotID < target.DataSlots[j].SlotID })
	sort.Slice(target.SecretSlots, func(i, j int) bool { return target.SecretSlots[i].SlotID < target.SecretSlots[j].SlotID })
	sort.Slice(target.Resources, func(i, j int) bool { return target.Resources[i].ResourceID < target.Resources[j].ResourceID })
	sort.Strings(target.DestroyVolumeIDs)
	sort.Strings(target.DestroyNetworkInterfaceIDs)
	return compatibilitySigningPayloadV2{
		SchemaVersion: CompatibilitySchemaV1, PayloadVersion: SigningPayloadV2, HashAlgorithm: SigningHashAlgorithmV1,
		Intent: ManagementAcceptanceIntent, ApprovalID: c.ApprovalID, ChallengeID: c.ChallengeID, SignerKeyID: c.SignerKeyID,
		compatibilityAcceptanceTargetV2: target, IssuedAt: c.IssuedAt.UTC(), ExpiresAt: c.ExpiresAt.UTC(),
	}
}

func SigningPayloadDigest(c ChallengeV1) (string, error) {
	return canonical.Digest(c.compatibilitySigningPayload())
}

type SignatureV1 struct {
	ChallengeID string
	ApprovalID  string
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

type OperationV1 struct {
	OperationID  string
	Challenge    ChallengeV1
	Status       Status
	Signature    []byte
	Revision     int64
	ErrorCode    string
	ErrorSummary string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	ApprovedAt   *time.Time
}

type Mutation struct {
	ClientID       string
	CredentialID   string
	IdempotencyKey string
	RequestHash    string
}

type ScopeBuilder interface {
	BuildManagedAcceptanceSnapshot(context.Context, string, string, string) (SnapshotV1, error)
}
type Repository interface {
	FindManagedAcceptanceChallengeReplay(context.Context, Mutation) (ChallengeV1, error)
	CreateManagedAcceptanceChallenge(context.Context, Mutation, ChallengeV1) (ChallengeV1, error)
	GetManagedAcceptanceChallenge(context.Context, string, string) (ChallengeV1, error)
	FindManagedAcceptanceApprovalReplay(context.Context, Mutation) (OperationV1, error)
	ApproveManagedAcceptance(context.Context, Mutation, SignatureV1, time.Time) (OperationV1, error)
	GetManagedAcceptanceOperation(context.Context, string, string) (OperationV1, error)
}
type DeviceRepository = cloudapproval.DeviceKeyRepository
type Processor interface {
	NotifyManagedAcceptance()
	ExecuteManagedAcceptance(context.Context, OperationV1) (OperationV1, error)
}

type Acceptor interface {
	AcceptManaged(context.Context, ScopeV1, string, time.Time) (resource.ManagedServiceV1, error)
	ReplayManaged(context.Context, ScopeV1, string, time.Time) (resource.ManagedServiceV1, bool, error)
}

func ScopeDigest(scope ScopeV1) (string, error) {
	if err := scope.Validate(); err != nil {
		return "", err
	}
	return canonical.Digest(scope)
}
func validUUID(v string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(v))
	return err == nil && parsed != uuid.Nil && parsed.String() == v
}
func validDigest(v string) bool { return namedDigestPattern.MatchString(v) }
func validResourceType(v string) bool {
	switch resource.Type(v) {
	case resource.TypeEC2, resource.TypeEBS, resource.TypeENI, resource.TypeEIP, resource.TypeSG, resource.TypeEndpoint, resource.TypeSnapshot, resource.TypeALB, resource.TypeTargetGroup, resource.TypeListener, resource.TypeSecurityGroupRule:
		return true
	}
	return false
}

func validSafeRef(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed != "" && trimmed == value && len(value) <= 512 && !security.ContainsLikelySecret(value)
}

func validSlots[T any](slots []T, values func(T) (string, string)) bool {
	if len(slots) > 64 {
		return false
	}
	seenIDs, seenRefs := make(map[string]struct{}, len(slots)), make(map[string]struct{}, len(slots))
	previous := ""
	for _, slot := range slots {
		id, ref := values(slot)
		if !validSafeRef(id) || !validSafeRef(ref) || id <= previous {
			return false
		}
		if _, exists := seenIDs[id]; exists {
			return false
		}
		if _, exists := seenRefs[ref]; exists {
			return false
		}
		seenIDs[id], seenRefs[ref], previous = struct{}{}, struct{}{}, id
	}
	return true
}

func validProviderIDs(values []string, pattern *regexp.Regexp) bool {
	if len(values) == 0 || len(values) > 64 || !sort.StringsAreSorted(values) {
		return false
	}
	previous := ""
	for _, value := range values {
		if !pattern.MatchString(value) || value == previous {
			return false
		}
		previous = value
	}
	return true
}
func signatureValid(c ChallengeV1, s SignatureV1, key ed25519.PublicKey, now time.Time) error {
	if s.ChallengeID != c.ChallengeID || s.ApprovalID != c.ApprovalID || s.SignerKeyID != c.SignerKeyID ||
		len(s.Signature) != ed25519.SignatureSize || !now.Before(c.ExpiresAt) {
		return ErrApprovalRequired
	}
	payload, err := c.SigningPayload()
	if err != nil || !ed25519.Verify(key, payload, s.Signature) {
		return ErrApprovalRequired
	}
	return nil
}
func requestHash(value any) (string, error) {
	digest, err := canonical.Digest(value)
	if err != nil {
		return "", fmt.Errorf("%w: request hash", ErrInvalid)
	}
	return digest, nil
}
