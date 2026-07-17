package quote

import (
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

func TestQuoteBindsEveryPersistentVolumeSlotAndPricesExplicitDataEBS(t *testing.T) {
	now := time.Date(2026, time.July, 17, 8, 0, 0, 0, time.UTC)
	boundRecipe := quoteRecipe(t)
	boundRecipe.VolumeSlots = []recipe.VolumeSlotRequirementV1{{
		SlotID: "knowledge", Purpose: "persistent knowledge index", MountPath: "/srv/knowledge",
		Persistent: true, EncryptionRequired: true,
	}}
	if err := boundRecipe.Validate(); err != nil {
		t.Fatal(err)
	}
	request := quoteRequest(t, boundRecipe, PurchaseOnDemand)
	for index := range request.Scopes {
		request.Scopes[index].Resource.VolumeScopes = []VolumeScopeV1{{
			SlotID: "knowledge", SizeGiB: uint32(80 << index), VolumeType: "gp3", IOPS: 3_000, ThroughputMiBPS: 125,
			Encrypted: true, KMSKeyID: "alias/dtx-agent-test-foundation", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge",
			Persistent: true, Disposition: VolumeDeleteWithDeployment,
		}}
	}
	port := NewFakePricingPort(pricingSnapshot(now, PurchaseOnDemand))
	service, _ := NewService(port, func() time.Time { return now })

	quoted, err := service.Quote(context.Background(), request, boundRecipe)
	if err != nil {
		t.Fatal(err)
	}
	if len(quoted.Candidates[1].Scope.Resource.VolumeScopes) != 1 || quoted.Candidates[1].Scope.Resource.VolumeScopes[0].MountPath != "/srv/knowledge" {
		t.Fatalf("quote lost approval-visible volume scope: %+v", quoted.Candidates[1].Scope.Resource.VolumeScopes)
	}
	queries := port.Queries()
	if len(queries) != 1 || len(queries[0].Candidates[1].DataVolumes) != 1 || queries[0].Candidates[1].DataVolumes[0].SizeGiB != 160 {
		t.Fatalf("pricing query lost explicit data EBS: %+v", queries)
	}

	missing := request
	missing.Scopes = append([]ScopeV1(nil), request.Scopes...)
	missing.Scopes[0].Resource.VolumeScopes = nil
	if _, err := service.Quote(context.Background(), missing, boundRecipe); err == nil {
		t.Fatalf("persistent slot was silently mapped to root disk: %v", err)
	}
}

func TestVolumeScopeDriftRequiresRequote(t *testing.T) {
	now := time.Date(2026, time.July, 17, 8, 0, 0, 0, time.UTC)
	boundRecipe := quoteRecipe(t)
	boundRecipe.VolumeSlots = []recipe.VolumeSlotRequirementV1{{SlotID: "data", Purpose: "data", MountPath: "/srv/data", Persistent: true, EncryptionRequired: true}}
	request := quoteRequest(t, boundRecipe, PurchaseOnDemand)
	for index := range request.Scopes {
		request.Scopes[index].Resource.VolumeScopes = []VolumeScopeV1{{
			SlotID: "data", SizeGiB: uint32(40 << index), VolumeType: "gp3", IOPS: 3_000, ThroughputMiBPS: 125,
			Encrypted: true, KMSKeyID: "alias/dtx-agent-test-foundation", DeviceName: "/dev/sdf", MountPath: "/srv/data",
			Persistent: true, Disposition: VolumeDeleteWithDeployment,
		}}
	}
	service, _ := NewService(NewFakePricingPort(pricingSnapshot(now, PurchaseOnDemand)), func() time.Time { return now })
	quoted, err := service.Quote(context.Background(), request, boundRecipe)
	if err != nil {
		t.Fatal(err)
	}
	selected, _ := quoted.Candidate(CandidateRecommended)
	for name, mutate := range map[string]func(*VolumeScopeV1){
		"size":        func(value *VolumeScopeV1) { value.SizeGiB++ },
		"kms":         func(value *VolumeScopeV1) { value.KMSKeyID = "alias/dtx-agent-other-foundation" },
		"device":      func(value *VolumeScopeV1) { value.DeviceName = "/dev/sdg" },
		"mount":       func(value *VolumeScopeV1) { value.MountPath = "/srv/other" },
		"disposition": func(value *VolumeScopeV1) { value.Disposition = VolumeRetainWithManagedService },
	} {
		t.Run(name, func(t *testing.T) {
			changed := cloneTestScope(selected.Scope)
			changed.Resource.VolumeScopes = append([]VolumeScopeV1(nil), selected.Scope.Resource.VolumeScopes...)
			mutate(&changed.Resource.VolumeScopes[0])
			requote, digestErr := quoted.RequiresRequote(now, CandidateRecommended, changed)
			if digestErr == nil && !requote {
				t.Fatalf("drift did not require requote: requote=%v err=%v", requote, digestErr)
			}
		})
	}
}
