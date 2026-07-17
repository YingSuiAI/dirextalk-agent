package planning

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

func TestResearchCommandRequiresFixedControlPlaneDAG(t *testing.T) {
	t.Parallel()
	command := validResearchCommand()
	if err := command.Validate(); err != nil {
		t.Fatalf("valid research command rejected: %v", err)
	}

	invalid := command
	invalid.Create.Steps = append([]task.StepDefinition(nil), command.Create.Steps...)
	invalid.Create.Steps[2].ExecutorKind = task.ExecutorCloudWorker
	if err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cloud-worker planning step error = %v, want ErrInvalid", err)
	}
}

func TestBindingSessionIdentitySurvivesConversationTurnRequestIDs(t *testing.T) {
	t.Parallel()
	original := validBinding()
	followUp := original
	followUp.RequestID = uuid.NewString()
	if !original.SameSession(followUp) {
		t.Fatal("a follow-up request in the same conversation did not address the existing planning session")
	}
	differentOwner := followUp
	differentOwner.OwnerID = "other-owner"
	if original.SameSession(differentOwner) {
		t.Fatal("planning session identity ignored owner scope")
	}
}

func TestCandidatesAreExactlyThreeMonotonicAndSecretFree(t *testing.T) {
	t.Parallel()
	candidates := validCandidates()
	if err := ValidateResourceCandidates(candidates, QuoteAwaitingQuote); err != nil {
		t.Fatalf("valid candidates rejected: %v", err)
	}

	if err := ValidateResourceCandidates(candidates[:2], QuoteAwaitingQuote); !errors.Is(err, ErrInvalid) {
		t.Fatalf("two-candidate error = %v, want ErrInvalid", err)
	}
	nonMonotonic := append([]ResourceCandidateV1(nil), candidates...)
	nonMonotonic[1].MemoryMiB = nonMonotonic[0].MemoryMiB - 1
	if err := ValidateResourceCandidates(nonMonotonic, QuoteAwaitingQuote); !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-monotonic error = %v, want ErrInvalid", err)
	}
	withSecret := append([]ResourceCandidateV1(nil), candidates...)
	withSecret[0].Rationale = "token sk-" + strings.Repeat("q", 40)
	if err := ValidateResourceCandidates(withSecret, QuoteAwaitingQuote); !errors.Is(err, ErrRawSecret) {
		t.Fatalf("candidate secret error = %v, want ErrRawSecret", err)
	}
}

func TestRecipeDraftAcceptsOnlyBoundSecretFreeExperimentalRecipe(t *testing.T) {
	t.Parallel()
	command := SaveRecipeDraftCommand{
		IdempotencyKey: uuid.NewString(), Binding: validBinding(), Recipe: validRecipe(),
	}
	if err := command.Validate(); err != nil {
		t.Fatalf("valid recipe draft rejected: %v", err)
	}

	managed := command
	managed.Recipe.Maturity = recipe.MaturityManaged
	if err := managed.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("managed draft error = %v, want ErrInvalid", err)
	}
	secret := command
	secret.Recipe.Name = "sk-" + strings.Repeat("x", 40)
	if err := secret.Validate(); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), secret.Recipe.Name) {
		t.Fatalf("secret recipe error = %v, want redacted ErrInvalid", err)
	}
}

func validBinding() Binding {
	return Binding{
		RequestID: uuid.NewString(), OwnerID: "owner-1", ConversationID: "conversation-1",
		ConnectionID: "connection-1", RecipeID: "recipe-1", Retention: task.RetentionEphemeralAutoDestroy,
	}
}

func validResearchCommand() ResearchCommand {
	binding := validBinding()
	first := uuid.NewString()
	second := uuid.NewString()
	third := uuid.NewString()
	return ResearchCommand{
		Binding: binding,
		Create: task.CreateCommand{
			IdempotencyKey: binding.RequestID, OwnerID: binding.OwnerID, Goal: "Deploy a durable knowledge node.", Retention: binding.Retention,
			Steps: []task.StepDefinition{
				{StepID: first, Name: "research_official_sources", ExecutorKind: task.ExecutorControlPlane},
				{StepID: second, Name: "draft_recipe", ExecutorKind: task.ExecutorControlPlane, DependsOnStepIDs: []string{first}},
				{StepID: third, Name: "prepare_resource_candidates", ExecutorKind: task.ExecutorControlPlane, DependsOnStepIDs: []string{second}},
			},
		},
	}
}

func validCandidates() []ResourceCandidateV1 {
	return []ResourceCandidateV1{
		{Tier: TierEconomy, Architecture: recipe.ArchitectureAMD64, VCPU: 2, MemoryMiB: 4096, DiskGiB: 40, Rationale: "Minimum validated capacity."},
		{Tier: TierRecommended, Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 8192, DiskGiB: 80, Rationale: "Balanced steady-state capacity."},
		{Tier: TierPerformance, Architecture: recipe.ArchitectureAMD64, VCPU: 8, MemoryMiB: 16384, DiskGiB: 160, Rationale: "Extra installation and query headroom."},
	}
}

func validRecipe() recipe.RecipeV1 {
	now := time.Date(2026, 7, 16, 2, 0, 0, 0, time.UTC)
	digest := "sha256:" + strings.Repeat("a", 64)
	return recipe.RecipeV1{
		SchemaVersion: recipe.SchemaV1, RecipeID: "recipe-1", Name: "Official knowledge node", Maturity: recipe.MaturityExperimental,
		Sources:      []recipe.SourceV1{{URL: "https://example.com/official/repository", Version: "v1.2.3", Commit: "abcdef0123456789", ArtifactDigest: digest, ContentDigest: "sha256:" + strings.Repeat("b", 64), License: "Apache-2.0", RetrievedAt: now, Official: true}},
		Requirements: recipe.ResourceRequirementsV1{MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: recipe.ArchitectureAMD64},
		Install:      recipe.InstallContractV1{RootRequired: true, TimeoutSeconds: 1800, CheckpointNames: []string{"installed"}, Steps: []recipe.InstallStepV1{{ID: "install", Summary: "Install the digest-locked artifact", TimeoutSeconds: 1200}}},
		Health: recipe.HealthContractV1{
			Liveness:  recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/live", TimeoutSeconds: 5},
			Readiness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/health/ready", TimeoutSeconds: 5},
			Semantic:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "semantic_check", TimeoutSeconds: 30},
		},
		Lifecycle:   recipe.LifecycleContractV1{Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback", Backup: "backup", Restore: "restore", Destroy: "destroy"},
		VolumeSlots: []recipe.VolumeSlotRequirementV1{{SlotID: "data", Purpose: "Persistent index data"}},
	}
}
