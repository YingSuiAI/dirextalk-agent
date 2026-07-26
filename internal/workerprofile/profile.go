// Package workerprofile owns the fixed, low-cost Worker control-plane
// diagnostic Recipe. It is selected only through an explicit server-bound
// Recipe ID and cannot install software, receive secrets, retain data, or
// expose a listener.
package workerprofile

import (
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

const (
	RecipeIDPrefix = "dirextalk-worker-diagnostic-v1-"
	SourceID       = "source:dirextalk-agent-control-plane"
	SourceURL      = "https://github.com/YingSuiAI/dirextalk-agent/tree/7ac10ce17ae5223056c0d0a063907bed1fbbe681"
	ArtifactURL    = "https://github.com/YingSuiAI/dirextalk-agent/archive/7ac10ce17ae5223056c0d0a063907bed1fbbe681.tar.gz"
	Version        = "v0.1.0-alpha.20260719.6"
	Commit         = "7ac10ce17ae5223056c0d0a063907bed1fbbe681"
	ArtifactDigest = "sha256:5340efffeb21ec50ea23bbc54f574165139fddc04c1dd9595d4f279986da7641"
)

type ResearchHint struct {
	SourceID       string                       `json:"source_id"`
	ResearchURL    string                       `json:"research_url"`
	ArtifactURL    string                       `json:"artifact_url"`
	ArtifactDigest string                       `json:"artifact_digest"`
	Version        string                       `json:"version"`
	Commit         string                       `json:"commit"`
	License        string                       `json:"license"`
	Kind           recipe.SourceKind            `json:"kind"`
	Repository     *recipe.RepositoryIdentityV1 `json:"repository,omitempty"`
}

type Evidence struct {
	URL           string
	RetrievedAt   time.Time
	ContentDigest string
}

type Candidate struct {
	Tier         string
	Architecture recipe.Architecture
	VCPU         uint32
	MemoryMiB    uint64
	DiskGiB      uint64
	Rationale    string
}

func IsDiagnosticRecipeID(value string) bool {
	if !strings.HasPrefix(value, RecipeIDPrefix) || len(value) != len(RecipeIDPrefix)+32 {
		return false
	}
	for _, character := range value[len(RecipeIDPrefix):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func ResearchHints() []ResearchHint {
	return []ResearchHint{{
		SourceID: SourceID, ResearchURL: SourceURL, ArtifactURL: ArtifactURL,
		ArtifactDigest: ArtifactDigest, Version: Version, Commit: Commit,
		License: "Proprietary", Kind: recipe.SourceRepository,
		Repository: &recipe.RepositoryIdentityV1{
			Host: "github.com", Namespace: "YingSuiAI", Name: "dirextalk-agent",
		},
	}}
}

func BindExperimentalRecipe(recipeID string, evidence []Evidence) (recipe.RecipeV1, bool) {
	if !IsDiagnosticRecipeID(recipeID) || len(evidence) != 1 {
		return recipe.RecipeV1{}, false
	}
	item := evidence[0]
	if item.URL != SourceURL || item.RetrievedAt.IsZero() || item.RetrievedAt.Location() != time.UTC ||
		recipe.ValidateDigest(item.ContentDigest) != nil {
		return recipe.RecipeV1{}, false
	}
	value := recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1,
		RecipeID:      recipeID,
		Name:          "Dirextalk Worker control-plane diagnostic",
		Maturity:      recipe.MaturityExperimental,
		Sources: []recipe.SourceV1{{
			ID: SourceID, URL: SourceURL, ArtifactURL: ArtifactURL,
			Version: Version, Commit: Commit, ArtifactDigest: ArtifactDigest,
			ContentDigest: item.ContentDigest, License: "Proprietary",
			RetrievedAt: item.RetrievedAt, Official: true, Kind: recipe.SourceRepository,
			Repository: &recipe.RepositoryIdentityV1{
				Host: "github.com", Namespace: "YingSuiAI", Name: "dirextalk-agent",
			},
		}},
		Requirements: recipe.ResourceRequirementsV1{
			MinVCPU: 1, MinMemoryMiB: 1024, MinDiskGiB: 8,
			Architecture: recipe.ArchitectureAMD64,
		},
		Install: recipe.InstallContractV1{
			TimeoutSeconds: 30, CheckpointNames: []string{"worker-control-verified"},
			Steps: []recipe.InstallStepV1{{
				ID: "verify-worker-control", Summary: "Verify the signed Worker assignment and result channel",
				TimeoutSeconds: 10, Action: "worker.noop", Checkpoint: "worker-control-verified",
			}},
		},
		Health: recipe.HealthContractV1{
			Liveness:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "worker.noop", TimeoutSeconds: 5},
			Readiness: recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "worker.noop", TimeoutSeconds: 5},
			Semantic:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "worker.noop", TimeoutSeconds: 5},
		},
		Lifecycle: recipe.LifecycleContractV1{
			Start: "worker.noop", Stop: "worker.noop", Maintenance: "worker.noop",
			Restart: "worker.noop", Upgrade: "worker.noop", Rollback: "worker.noop",
			Backup: "worker.noop", Restore: "worker.noop", Destroy: "worker.noop",
		},
	}
	if value.Validate() != nil {
		return recipe.RecipeV1{}, false
	}
	return value, true
}

func ResourceCandidates(value recipe.RecipeV1) ([]Candidate, bool) {
	if !IsDiagnosticRecipeID(value.RecipeID) || value.Validate() != nil {
		return nil, false
	}
	evidence := []Evidence{{
		URL: value.Sources[0].URL, RetrievedAt: value.Sources[0].RetrievedAt,
		ContentDigest: value.Sources[0].ContentDigest,
	}}
	expected, matched := BindExperimentalRecipe(value.RecipeID, evidence)
	if !matched {
		return nil, false
	}
	expectedDigest, expectedErr := expected.Digest()
	actualDigest, actualErr := value.Digest()
	if expectedErr != nil || actualErr != nil || expectedDigest != actualDigest {
		return nil, false
	}
	return []Candidate{
		{Tier: "economy", Architecture: recipe.ArchitectureAMD64, VCPU: 1, MemoryMiB: 1024, DiskGiB: 8, Rationale: "minimum signed Worker control validation"},
		{Tier: "recommended", Architecture: recipe.ArchitectureAMD64, VCPU: 1, MemoryMiB: 1024, DiskGiB: 8, Rationale: "same bounded diagnostic capacity"},
		{Tier: "performance", Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 2048, DiskGiB: 16, Rationale: "diagnostic capacity with additional headroom"},
	}, true
}
