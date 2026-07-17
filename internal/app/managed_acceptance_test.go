package app

import (
	"testing"
	"time"

	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

func TestManagedAcceptanceLiveResourceFenceRejectsProviderAndOriginDrift(t *testing.T) {
	scope := cloudmanaged.ScopeV1{
		OwnerID: "owner-1", DeploymentID: "11111111-1111-4111-8111-111111111111",
		PlanHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Resources: []cloudmanaged.ResourceV1{{
			ResourceID: "22222222-2222-4222-8222-222222222222", Type: "ec2", Revision: 4,
			ProviderID: "i-0123456789abcdef0", TagDigest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		}},
		DestroyInstanceID: "i-0123456789abcdef0", DestroyVolumeIDs: []string{}, DestroyNetworkInterfaceIDs: []string{},
	}
	current := []resource.ResourceV1{{
		ResourceID: scope.Resources[0].ResourceID, OwnerID: scope.OwnerID, DeploymentID: scope.DeploymentID,
		Type: resource.TypeEC2, ProviderID: scope.DestroyInstanceID, State: resource.StateActive, Revision: 4,
		ApprovalID: "33333333-3333-4333-8333-333333333333", ApprovedPlanHash: scope.PlanHash,
		ReadBack: resource.ReadBackEvidence{Exists: true, ProviderID: scope.DestroyInstanceID, TagDigest: scope.Resources[0].TagDigest},
	}}
	if approvalID, ok := sameManagedResources(current, scope); !ok || approvalID != current[0].ApprovalID {
		t.Fatalf("exact live resources rejected: approval=%q ok=%v", approvalID, ok)
	}
	changed := append([]resource.ResourceV1(nil), current...)
	changed[0].ReadBack.TagDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, ok := sameManagedResources(changed, scope); ok {
		t.Fatal("provider tag drift was accepted")
	}
	changed = append([]resource.ResourceV1(nil), current...)
	changed[0].ApprovedPlanHash = "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	if _, ok := sameManagedResources(changed, scope); ok {
		t.Fatal("EC2 approval origin drift was accepted")
	}
}

func TestManagedAcceptanceLiveRecipeFenceBindsContractsAndSlots(t *testing.T) {
	current := recipe.RecipeV1{
		Name: "service", Sources: []recipe.SourceV1{{ArtifactDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
		Health: recipe.HealthContractV1{
			Liveness:  recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/live"},
			Readiness: recipe.ProbeV1{Kind: recipe.ProbeHTTP, Target: "/ready"},
			Semantic:  recipe.ProbeV1{Kind: recipe.ProbeAction, Target: "semantic"},
		},
		Lifecycle: recipe.LifecycleContractV1{
			Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart", Backup: "backup", Restore: "restore",
			Upgrade: "upgrade", Rollback: "rollback", Destroy: "destroy",
		},
		VolumeSlots: []recipe.VolumeSlotRequirementV1{{SlotID: "volume", ReadOnly: false}},
		DataSlots:   []recipe.DataSlotRequirementV1{{SlotID: "data", ReadOnly: true}},
		SecretSlots: []recipe.SecretSlotRequirementV1{{SlotID: "secret"}},
	}
	snapshot := cloudmanaged.SnapshotV1{
		Recipe: cloudmanaged.CompatibilityRecipeV1{Name: current.Name},
		Scope: cloudmanaged.ScopeV1{
			RecipeMaturity: "awaiting_management_acceptance",
			Health: cloudmanaged.HealthContractV1{
				Liveness:  cloudmanaged.ProbeV1{Kind: "http", Target: "/live"},
				Readiness: cloudmanaged.ProbeV1{Kind: "http", Target: "/ready"},
				Semantic:  cloudmanaged.ProbeV1{Kind: "command", Target: "semantic"},
			},
			Lifecycle: cloudmanaged.LifecycleV1{
				Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart", Backup: "backup",
				Restore: "restore", Upgrade: "upgrade", Rollback: "rollback", Destroy: "destroy",
			},
			SourceArtifactDigests: []string{current.Sources[0].ArtifactDigest},
			VolumeSlots:           []cloudmanaged.VolumeSlotV1{{SlotID: "volume", VolumeRef: "volume://bound"}},
			DataSlots:             []cloudmanaged.DataSlotV1{{SlotID: "data", DataRef: "data://bound", ReadOnly: true}},
			SecretSlots:           []cloudmanaged.SecretSlotV1{{SlotID: "secret", SecretRef: "secret://bound/value"}},
		},
	}
	if !sameManagedRecipeContract(current, snapshot) {
		t.Fatal("exact Recipe contract rejected")
	}
	changed := snapshot
	changed.Scope.Lifecycle.Restore = "other"
	if sameManagedRecipeContract(current, changed) {
		t.Fatal("lifecycle drift was accepted")
	}
	changed = snapshot
	changed.Scope.Lifecycle.Maintenance = "other"
	if sameManagedRecipeContract(current, changed) {
		t.Fatal("maintenance drift was accepted")
	}
	changed = snapshot
	changed.Scope.VolumeSlots = []cloudmanaged.VolumeSlotV1{{SlotID: "other", VolumeRef: "volume://bound"}}
	if sameManagedRecipeContract(current, changed) {
		t.Fatal("slot drift was accepted")
	}
}

func TestManagedAcceptanceLiveHealthFenceRequiresExactIndependentEvidence(t *testing.T) {
	observedAt := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	scope := cloudmanaged.ScopeV1{
		HealthRevision: 3, HealthEvidenceDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		HealthObservedAt: observedAt,
	}
	current := cloudstatus.HealthSummary{
		Status: cloudstatus.HealthHealthy, Revision: 3, EvidenceType: cloudstatus.HealthEvidenceIndependent,
		EvidenceDigest: scope.HealthEvidenceDigest, ObservedAt: observedAt,
	}
	if !sameManagedHealth(current, scope) {
		t.Fatal("exact health evidence rejected")
	}
	current.Revision++
	if sameManagedHealth(current, scope) {
		t.Fatal("health revision drift was accepted")
	}
}
