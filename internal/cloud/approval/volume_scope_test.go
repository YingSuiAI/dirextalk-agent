package approval

import (
	"strings"
	"testing"
	"time"
)

func TestApprovalPlanHashBindsCompleteVolumeScope(t *testing.T) {
	plan := validPlan()
	plan.ResourceScope.VolumeScopes = []VolumeScopeV1{{
		SlotID: "knowledge", SizeGiB: 80, VolumeType: "gp3", IOPS: 3_000, ThroughputMiBPS: 125,
		Encrypted: true, KMSKeyID: "alias/dtx-agent-test-foundation", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge",
		Persistent: true, Disposition: VolumeDeleteWithDeployment,
	}}
	refreshPlanScopeDigest(t, &plan)
	baseHash, err := plan.Hash()
	if err != nil {
		t.Fatal(err)
	}
	approval, err := NewApprovalV1(plan, "approval-volume", strings.Repeat("d", 48), "device-volume", plan.Quote.ValidUntil.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(approval.ResourceScope.VolumeScopes) != 1 {
		t.Fatal("approval projection omitted volume scope")
	}

	for name, mutate := range map[string]func(*VolumeScopeV1){
		"size":       func(value *VolumeScopeV1) { value.SizeGiB++ },
		"iops":       func(value *VolumeScopeV1) { value.IOPS++ },
		"throughput": func(value *VolumeScopeV1) { value.ThroughputMiBPS++ },
		"kms":        func(value *VolumeScopeV1) { value.KMSKeyID = "alias/dtx-agent-other-foundation" },
		"device":     func(value *VolumeScopeV1) { value.DeviceName = "/dev/sdg" },
		"mount":      func(value *VolumeScopeV1) { value.MountPath = "/srv/other" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := plan
			changed.ResourceScope.VolumeScopes = append([]VolumeScopeV1(nil), plan.ResourceScope.VolumeScopes...)
			mutate(&changed.ResourceScope.VolumeScopes[0])
			refreshPlanScopeDigest(t, &changed)
			changedHash, hashErr := changed.Hash()
			if hashErr == nil && changedHash == baseHash {
				t.Fatalf("%s drift did not change deterministic Plan hash", name)
			}
			if approval.ValidateAgainstPlan(changed, plan.Quote.ValidUntil.Add(-2*time.Minute)) == nil {
				t.Fatalf("%s drift was accepted by approval", name)
			}
		})
	}
	invalidType := plan
	invalidType.ResourceScope.VolumeScopes = append([]VolumeScopeV1(nil), plan.ResourceScope.VolumeScopes...)
	invalidType.ResourceScope.VolumeScopes[0].VolumeType = "gp2"
	if invalidType.Validate() == nil {
		t.Fatal("tampered data-volume type was accepted")
	}
}

func refreshPlanScopeDigest(t *testing.T, plan *PlanV1) {
	t.Helper()
	digest, err := plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.ScopeDigest = digest
}
