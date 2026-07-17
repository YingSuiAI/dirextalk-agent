package managed

import (
	"context"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const VerifiedPreparationSchemaV1 = "dirextalk.agent.cloud.managed-verified-preparation/v1"

type AttestationKind string

const (
	AttestationInstall          AttestationKind = "install"
	AttestationServiceReadiness AttestationKind = "service_readiness"
	AttestationRestart          AttestationKind = "restart"
	AttestationBackup           AttestationKind = "backup"
	AttestationRestore          AttestationKind = "restore"
	AttestationStackObservation AttestationKind = "stack_observation"
	AttestationCostAlert        AttestationKind = "cost_alert"
)

var requiredPreparationAttestations = []AttestationKind{
	AttestationInstall, AttestationServiceReadiness, AttestationRestart, AttestationBackup,
	AttestationRestore, AttestationStackObservation, AttestationCostAlert,
}

type VerifiedAttestationV1 struct {
	AttestationID string          `json:"attestation_id"`
	Kind          AttestationKind `json:"kind"`
	Digest        string          `json:"digest"`
	ObservedAt    time.Time       `json:"observed_at"`
}

type VerifiedPreparationV1 struct {
	SchemaVersion              string                  `json:"schema_version"`
	PreparationID              string                  `json:"preparation_id"`
	AgentInstanceID            string                  `json:"agent_instance_id"`
	OwnerID                    string                  `json:"owner_id"`
	DeploymentID               string                  `json:"deployment_id"`
	ExpectedDeploymentRevision int64                   `json:"expected_deployment_revision"`
	Snapshot                   SnapshotV1              `json:"snapshot"`
	SnapshotDigest             string                  `json:"snapshot_digest"`
	Attestations               []VerifiedAttestationV1 `json:"attestations"`
	CreatedAt                  time.Time               `json:"created_at"`
}

type operationAttestationBindingV1 struct {
	OperationID string `json:"operation_id"`
	Revision    uint64 `json:"revision"`
}

type costAlertAttestationBindingV1 struct {
	Currency    string `json:"currency"`
	AmountMinor int64  `json:"amount_minor"`
}

func (value VerifiedPreparationV1) Validate() error {
	if value.SchemaVersion != VerifiedPreparationSchemaV1 || !verifiedPreparationUUID(value.PreparationID) ||
		!verifiedPreparationUUID(value.AgentInstanceID) || !verifiedPreparationUUID(value.DeploymentID) ||
		strings.TrimSpace(value.OwnerID) == "" || strings.TrimSpace(value.OwnerID) != value.OwnerID ||
		len(value.OwnerID) > 255 || security.ContainsLikelySecret(value.OwnerID) ||
		value.ExpectedDeploymentRevision < 1 || value.CreatedAt.IsZero() || value.CreatedAt.Location() != time.UTC ||
		value.Snapshot.Scope.Validate() != nil || value.Snapshot.Service.Validate(value.Snapshot.Scope) != nil ||
		value.Snapshot.Recipe.Validate(value.Snapshot.Scope) != nil ||
		value.Snapshot.Scope.AgentInstanceID != value.AgentInstanceID || value.Snapshot.Scope.OwnerID != value.OwnerID ||
		value.Snapshot.Scope.DeploymentID != value.DeploymentID ||
		value.Snapshot.Scope.DeploymentRevision != value.ExpectedDeploymentRevision {
		return ErrInvalid
	}
	digest, err := SnapshotDigest(value.Snapshot)
	if err != nil || digest != value.SnapshotDigest {
		return ErrInvalid
	}
	if len(value.Attestations) != len(requiredPreparationAttestations) {
		return ErrInvalid
	}
	seen := make(map[AttestationKind]VerifiedAttestationV1, len(value.Attestations))
	previous := AttestationKind("")
	for _, attestation := range value.Attestations {
		if !verifiedPreparationUUID(attestation.AttestationID) || !validDigest(attestation.Digest) ||
			attestation.ObservedAt.IsZero() || attestation.ObservedAt.Location() != time.UTC ||
			attestation.ObservedAt.After(value.CreatedAt) || attestation.Kind <= previous ||
			!knownVerifiedAttestationKind(attestation.Kind) {
			return ErrInvalid
		}
		if _, exists := seen[attestation.Kind]; exists {
			return ErrInvalid
		}
		seen[attestation.Kind] = attestation
		previous = attestation.Kind
	}
	for _, kind := range requiredPreparationAttestations {
		if _, exists := seen[kind]; !exists {
			return ErrInvalid
		}
	}
	restartDigest, restartErr := OperationAttestationDigest(value.Snapshot.Scope.RestartOperationID, value.Snapshot.Scope.RestartOperationRevision)
	backupDigest, backupErr := OperationAttestationDigest(value.Snapshot.Scope.BackupID, value.Snapshot.Scope.BackupRevision)
	restoreDigest, restoreErr := OperationAttestationDigest(value.Snapshot.Scope.RestoreID, value.Snapshot.Scope.RestoreRevision)
	costDigest, costErr := CostAlertAttestationDigest(value.Snapshot.Scope.Currency, value.Snapshot.Scope.CostAlertAmountMinor)
	if seen[AttestationInstall].Digest != value.Snapshot.Scope.InstalledManifestDigest ||
		seen[AttestationServiceReadiness].Digest != value.Snapshot.Scope.HealthEvidenceDigest ||
		seen[AttestationServiceReadiness].ObservedAt != value.Snapshot.Scope.HealthObservedAt ||
		seen[AttestationRestart].AttestationID != value.Snapshot.Scope.RestartOperationID ||
		restartErr != nil || seen[AttestationRestart].Digest != restartDigest ||
		seen[AttestationBackup].AttestationID != value.Snapshot.Scope.BackupID ||
		backupErr != nil || seen[AttestationBackup].Digest != backupDigest ||
		seen[AttestationRestore].AttestationID != value.Snapshot.Scope.RestoreID ||
		restoreErr != nil || seen[AttestationRestore].Digest != restoreDigest ||
		seen[AttestationStackObservation].Digest != value.Snapshot.Scope.ReadinessStackObservationDigest ||
		costErr != nil || seen[AttestationCostAlert].Digest != costDigest ||
		seen[AttestationInstall].ObservedAt.After(seen[AttestationRestart].ObservedAt) ||
		seen[AttestationRestart].ObservedAt.After(seen[AttestationBackup].ObservedAt) ||
		seen[AttestationBackup].ObservedAt.After(seen[AttestationRestore].ObservedAt) ||
		seen[AttestationRestore].ObservedAt.After(seen[AttestationServiceReadiness].ObservedAt) ||
		seen[AttestationStackObservation].ObservedAt.Before(seen[AttestationRestore].ObservedAt) {
		return ErrInvalid
	}
	return nil
}

func OperationAttestationDigest(operationID string, revision uint64) (string, error) {
	if !verifiedPreparationUUID(operationID) || revision < 1 {
		return "", ErrInvalid
	}
	return canonical.Digest(operationAttestationBindingV1{OperationID: operationID, Revision: revision})
}

func CostAlertAttestationDigest(currency string, amountMinor int64) (string, error) {
	if !currencyPattern.MatchString(currency) || amountMinor < 1 {
		return "", ErrInvalid
	}
	return canonical.Digest(costAlertAttestationBindingV1{Currency: currency, AmountMinor: amountMinor})
}

func SnapshotDigest(snapshot SnapshotV1) (string, error) {
	if snapshot.Scope.Validate() != nil || snapshot.Service.Validate(snapshot.Scope) != nil ||
		snapshot.Recipe.Validate(snapshot.Scope) != nil {
		return "", ErrInvalid
	}
	return canonical.Digest(snapshot)
}

func SortVerifiedAttestations(values []VerifiedAttestationV1) []VerifiedAttestationV1 {
	result := slices.Clone(values)
	sort.Slice(result, func(i, j int) bool { return result[i].Kind < result[j].Kind })
	return result
}

type VerifiedPreparationRepository interface {
	CreateVerifiedPreparation(context.Context, Mutation, VerifiedPreparationV1) (VerifiedPreparationV1, error)
	GetVerifiedPreparation(context.Context, string, string) (VerifiedPreparationV1, error)
	GetLatestVerifiedPreparation(context.Context, string, string) (VerifiedPreparationV1, error)
}

func (value VerifiedPreparationV1) SnapshotForAcceptance(acceptanceID string) (SnapshotV1, error) {
	if value.Validate() != nil || !verifiedPreparationUUID(acceptanceID) {
		return SnapshotV1{}, ErrInvalid
	}
	result := value.Snapshot
	result.Scope.SourceArtifactDigests = slices.Clone(value.Snapshot.Scope.SourceArtifactDigests)
	result.Scope.VolumeSlots = slices.Clone(value.Snapshot.Scope.VolumeSlots)
	result.Scope.DataSlots = slices.Clone(value.Snapshot.Scope.DataSlots)
	result.Scope.SecretSlots = slices.Clone(value.Snapshot.Scope.SecretSlots)
	result.Scope.Resources = slices.Clone(value.Snapshot.Scope.Resources)
	result.Scope.DestroyVolumeIDs = slices.Clone(value.Snapshot.Scope.DestroyVolumeIDs)
	result.Scope.DestroyNetworkInterfaceIDs = slices.Clone(value.Snapshot.Scope.DestroyNetworkInterfaceIDs)
	result.Service.Backups = slices.Clone(value.Snapshot.Service.Backups)
	for index := range result.Service.Backups {
		result.Service.Backups[index].SnapshotIDs = slices.Clone(value.Snapshot.Service.Backups[index].SnapshotIDs)
	}
	result.Service.Restores = slices.Clone(value.Snapshot.Service.Restores)
	for index := range result.Service.Restores {
		result.Service.Restores[index].OriginalVolumeIDs = slices.Clone(value.Snapshot.Service.Restores[index].OriginalVolumeIDs)
		result.Service.Restores[index].ReplacementVolumeIDs = slices.Clone(value.Snapshot.Service.Restores[index].ReplacementVolumeIDs)
	}
	result.Scope.AcceptanceID = acceptanceID
	if result.Scope.Validate() != nil || result.Service.Validate(result.Scope) != nil || result.Recipe.Validate(result.Scope) != nil {
		return SnapshotV1{}, ErrInvalid
	}
	return result, nil
}

func knownVerifiedAttestationKind(value AttestationKind) bool {
	return slices.Contains(requiredPreparationAttestations, value)
}

func verifiedPreparationUUID(value string) bool {
	parsed, err := uuid.Parse(strings.TrimSpace(value))
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
