// Package knowledgeprofile owns Dirextalk's retained first-party Knowledge
// release and its exact experimental Recipe. Model research supplies only
// fresh official-source receipts; executable paths and artifact bytes remain
// server-owned constants.
package knowledgeprofile

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

const (
	ReleaseSchema      = "dirextalk.knowledge.release/v1"
	ReleaseID          = "dirextalk-knowledge-v1"
	EmbeddingProfileID = "local-multilingual-e5-small-v1"
	ManifestSHA256     = "78a75a2974a6282f90cb749b373c4c48959ec9c348d2e2f4f15ea0a6abf5e4e3"
	ManifestName       = "dirextalk-knowledge-release.v1.json"
	Origin             = "https://artifacts.y1.dirextalk.ai"

	InstallerCommandID     = "knowledge-install-v1"
	RestartCommandID       = "knowledge-restart-v1"
	SemanticProbeCommandID = "knowledge-semantic-probe-v1"
	StopCommandID          = "knowledge-stop-v1"
	BackupCommandID        = "knowledge-backup-v1"
	RestoreCommandID       = "knowledge-restore-v1"
	UpgradeCommandID       = "knowledge-upgrade-v1"
	RollbackCommandID      = "knowledge-rollback-v1"
	DestroyCommandID       = "knowledge-destroy-v1"
	VolumeSlotID           = "knowledge-data"
	SecretSlotID           = "qdrant-api-key"
)

//go:embed release.v1.json
var releaseBytes []byte

type Artifact struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
	License   string `json:"license"`
	URL       string `json:"url"`
}

type Runtime struct {
	ArtifactRoot           string   `json:"artifact_root"`
	PersistentVolumeMount  string   `json:"persistent_volume_mount"`
	QdrantAPIKeySecretPath string   `json:"qdrant_api_key_secret_path"`
	AdapterSocket          string   `json:"adapter_socket"`
	InstallerCommands      []string `json:"installer_commands"`
}

type Release struct {
	SchemaVersion      string     `json:"schema_version"`
	ReleaseID          string     `json:"release_id"`
	EmbeddingProfileID string     `json:"embedding_profile_id"`
	Artifacts          []Artifact `json:"artifacts"`
	Runtime            Runtime    `json:"runtime"`
}

type ResearchHint struct {
	SourceID       string            `json:"source_id"`
	ResearchURL    string            `json:"research_url"`
	ArtifactURL    string            `json:"artifact_url"`
	ArtifactDigest string            `json:"artifact_digest"`
	Version        string            `json:"version"`
	Commit         string            `json:"commit"`
	License        string            `json:"license"`
	Kind           recipe.SourceKind `json:"kind"`
}

type Evidence struct {
	URL           string
	RetrievedAt   time.Time
	ContentDigest string
}

func ManifestURL() string {
	return Origin + "/sha256/" + ManifestSHA256 + "/" + ManifestName
}

func ReleaseManifest() (Release, bool) {
	digest := sha256.Sum256(releaseBytes)
	if hex.EncodeToString(digest[:]) != ManifestSHA256 {
		return Release{}, false
	}
	var value Release
	if err := json.Unmarshal(releaseBytes, &value); err != nil || value.SchemaVersion != ReleaseSchema || value.ReleaseID != ReleaseID ||
		value.EmbeddingProfileID != EmbeddingProfileID || len(value.Artifacts) != 5 || value.Runtime.ArtifactRoot != installer.PreinstalledArtifactRoot ||
		value.Runtime.PersistentVolumeMount != "/var/lib/dirextalk-knowledge" || value.Runtime.QdrantAPIKeySecretPath != "/etc/dirextalk-service-secrets/qdrant-api-key" ||
		value.Runtime.AdapterSocket != "/run/dirextalk-knowledge/adapter.sock" || !slices.Equal(value.Runtime.InstallerCommands,
		[]string{"install-v1", "restart-v1", "semantic-probe-v1", "stop-v1", "backup-v1", "restore-v1", "upgrade-v1", "rollback-v1", "destroy-v1"}) {
		return Release{}, false
	}
	return value, true
}

func ResearchHints() []ResearchHint {
	release, ok := ReleaseManifest()
	if !ok {
		return nil
	}
	hints := make([]ResearchHint, 0, len(release.Artifacts))
	for _, artifact := range release.Artifacts {
		hints = append(hints, ResearchHint{
			SourceID: sourceID(artifact.ID), ResearchURL: ManifestURL() + "?artifact=" + url.QueryEscape(artifact.ID),
			ArtifactURL: artifact.URL, ArtifactDigest: "sha256:" + artifact.SHA256,
			Version: ReleaseID, Commit: ManifestSHA256, License: artifact.License, Kind: recipe.SourceRelease,
		})
	}
	return hints
}

// BindExperimentalRecipe recognizes only the exact five small-manifest
// research receipts and replaces model-authored executable detail with the
// retained, server-owned Knowledge Recipe.
func BindExperimentalRecipe(recipeID string, evidence []Evidence) (recipe.RecipeV1, bool) {
	hints := ResearchHints()
	if len(hints) == 0 || len(evidence) != len(hints) {
		return recipe.RecipeV1{}, false
	}
	byURL := make(map[string]Evidence, len(evidence))
	for _, item := range evidence {
		if item.URL == "" || item.RetrievedAt.IsZero() || item.RetrievedAt.Location() != time.UTC ||
			item.ContentDigest != "sha256:"+ManifestSHA256 {
			return recipe.RecipeV1{}, false
		}
		if _, duplicate := byURL[item.URL]; duplicate {
			return recipe.RecipeV1{}, false
		}
		byURL[item.URL] = item
	}
	sources := make([]recipe.SourceV1, 0, len(hints))
	for _, hint := range hints {
		item, found := byURL[hint.ResearchURL]
		if !found {
			return recipe.RecipeV1{}, false
		}
		sources = append(sources, recipe.SourceV1{
			ID: hint.SourceID, URL: hint.ResearchURL, ArtifactURL: hint.ArtifactURL,
			Version: hint.Version, Commit: hint.Commit, ArtifactDigest: hint.ArtifactDigest,
			ContentDigest: item.ContentDigest, License: hint.License, RetrievedAt: item.RetrievedAt,
			Official: true, Kind: hint.Kind,
		})
	}
	result := knowledgeRecipe(recipeID, sources)
	if result.Validate() != nil {
		return recipe.RecipeV1{}, false
	}
	return result, true
}

// RetainedRecipeProfile recognizes only the exact server-owned Recipe derived
// from the pinned small-manifest evidence. A valid but model-authored Recipe
// with similar lifecycle names or slots is not a retained Knowledge profile.
func RetainedRecipeProfile(value recipe.RecipeV1) (string, bool) {
	if value.Validate() != nil {
		return "", false
	}
	evidence := make([]Evidence, 0, len(value.Sources))
	for _, source := range value.Sources {
		evidence = append(evidence, Evidence{
			URL: source.URL, RetrievedAt: source.RetrievedAt, ContentDigest: source.ContentDigest,
		})
	}
	expected, matched := BindExperimentalRecipe(value.RecipeID, evidence)
	if !matched {
		return "", false
	}
	expectedDigest, expectedErr := expected.Digest()
	actualDigest, actualErr := value.Digest()
	if expectedErr != nil || actualErr != nil || expectedDigest != actualDigest {
		return "", false
	}
	return EmbeddingProfileID, true
}

func knowledgeRecipe(recipeID string, sources []recipe.SourceV1) recipe.RecipeV1 {
	release, _ := ReleaseManifest()
	artifacts := make([]recipe.InstallerArtifactV1, 0, len(release.Artifacts))
	artifactRefs := make([]string, 0, len(release.Artifacts))
	for _, artifact := range release.Artifacts {
		name := artifactRef(artifact.ID)
		artifactRefs = append(artifactRefs, name)
		artifacts = append(artifacts, recipe.InstallerArtifactV1{
			Name: name, SourceID: sourceID(artifact.ID), SizeBytes: artifact.SizeBytes,
			TargetPath: installer.PreinstalledArtifactRoot + "/" + artifact.Name,
		})
	}
	sort.Strings(artifactRefs)
	executable := installer.PreinstalledArtifactRoot + "/dirextalk-knowledge-installer"
	commands := []recipe.InstallerCommandV1{
		{
			CommandID: InstallerCommandID, Argv: []string{executable, "install-v1"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 1800, ArtifactRefs: artifactRefs, VolumeSlotRefs: []string{VolumeSlotID}, SecretSlotRefs: []string{SecretSlotID},
		},
		{
			CommandID: RestartCommandID, Argv: []string{executable, "restart-v1"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 180, ArtifactRefs: []string{artifactRef("knowledge-installer-linux-amd64")}, VolumeSlotRefs: []string{VolumeSlotID},
		},
		{
			CommandID: SemanticProbeCommandID, Argv: []string{executable, "semantic-probe-v1"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 60, ArtifactRefs: []string{artifactRef("knowledge-installer-linux-amd64")}, VolumeSlotRefs: []string{VolumeSlotID},
		},
		{
			CommandID: StopCommandID, Argv: []string{executable, "stop-v1"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 120, ArtifactRefs: []string{artifactRef("knowledge-installer-linux-amd64")}, VolumeSlotRefs: []string{VolumeSlotID},
		},
		{
			CommandID: BackupCommandID, Argv: []string{executable, "backup-v1"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 1800, ArtifactRefs: []string{artifactRef("knowledge-installer-linux-amd64")}, VolumeSlotRefs: []string{VolumeSlotID},
		},
		{
			CommandID: RestoreCommandID, Argv: []string{executable, "restore-v1"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 1800, ArtifactRefs: []string{artifactRef("knowledge-installer-linux-amd64")}, VolumeSlotRefs: []string{VolumeSlotID},
		},
		{
			CommandID: UpgradeCommandID, Argv: []string{executable, "upgrade-v1"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 3600, ArtifactRefs: artifactRefs, VolumeSlotRefs: []string{VolumeSlotID}, SecretSlotRefs: []string{SecretSlotID},
		},
		{
			CommandID: RollbackCommandID, Argv: []string{executable, "rollback-v1"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 1800, ArtifactRefs: []string{artifactRef("knowledge-installer-linux-amd64")}, VolumeSlotRefs: []string{VolumeSlotID},
		},
		{
			CommandID: DestroyCommandID, Argv: []string{executable, "destroy-v1"}, WorkingDirectory: installer.PreinstalledArtifactRoot,
			TimeoutSeconds: 600, ArtifactRefs: []string{artifactRef("knowledge-installer-linux-amd64")}, VolumeSlotRefs: []string{VolumeSlotID},
		},
	}
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1, RecipeID: recipeID, Name: "Dirextalk retained Knowledge node", Maturity: recipe.MaturityExperimental,
		Sources:      sources,
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		Install: recipe.InstallContractV1{
			RootRequired: true, TimeoutSeconds: 2400, CheckpointNames: []string{"knowledge-installed", "knowledge-semantic-verified"},
			Installer: &recipe.InstallerCapabilityV1{Artifacts: artifacts, Commands: commands},
			Steps: []recipe.InstallStepV1{
				{ID: "install-knowledge", Summary: "Install the exact retained Knowledge release", TimeoutSeconds: 1800, Action: installer.ActionExecute,
					Inputs: []recipe.ActionInputV1{{Name: "command_id", Kind: recipe.ActionInputConfig, Ref: InstallerCommandID}}, Checkpoint: "knowledge-installed"},
				{ID: "verify-knowledge", Summary: "Verify model, Qdrant, search, and persistent write read-back", TimeoutSeconds: 60, Action: installer.ActionExecute,
					Inputs: []recipe.ActionInputV1{{Name: "command_id", Kind: recipe.ActionInputConfig, Ref: SemanticProbeCommandID}}, Checkpoint: "knowledge-semantic-verified"},
			},
		},
		Health: recipe.HealthContractV1{
			Liveness:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: SemanticProbeCommandID, TimeoutSeconds: 60},
			Readiness: recipe.ProbeV1{Kind: recipe.ProbeAction, Target: SemanticProbeCommandID, TimeoutSeconds: 60},
			Semantic:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: SemanticProbeCommandID, TimeoutSeconds: 60},
		},
		Lifecycle: recipe.LifecycleContractV1{
			Start: RestartCommandID, Stop: StopCommandID, Maintenance: StopCommandID, Restart: RestartCommandID,
			Upgrade: UpgradeCommandID, Rollback: RollbackCommandID, Backup: BackupCommandID, Restore: RestoreCommandID, Destroy: DestroyCommandID,
		},
		VolumeSlots: []recipe.VolumeSlotRequirementV1{{
			SlotID: VolumeSlotID, Purpose: "Retained Qdrant index, adapter ledger, staging state, TLS, and runtime secret", MountPath: "/var/lib/dirextalk-knowledge",
			Persistent: true, EncryptionRequired: true,
		}},
		SecretSlots: []recipe.SecretSlotRequirementV1{{
			SlotID: SecretSlotID, Purpose: "Qdrant loopback API key", Delivery: recipe.SecretDeliveryFile,
			TargetPath: "/etc/dirextalk-service-secrets/qdrant-api-key", FileMode: 0o400, OwnerUID: 0, OwnerGID: 0,
		}},
		Network: &recipe.NetworkContractV1{DefaultDeny: true, PublicIngress: recipe.PublicIngressV1{Mode: recipe.PublicIngressNone}},
		Restart: &recipe.RestartContractV1{Mode: recipe.RestartOnFailure, Action: RestartCommandID, MaxAttempts: 3, RecoveryCheckpoints: []string{"knowledge-installed", "knowledge-semantic-verified"}},
	}
}

func sourceID(artifactID string) string    { return "source:" + artifactID }
func artifactRef(artifactID string) string { return strings.TrimSuffix(artifactID, "-linux-amd64") }
