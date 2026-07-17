package managed

import (
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

func TestCompatibilitySigningPayloadMatchesFlutterAndMessageServerGolden(t *testing.T) {
	challenge := ChallengeV1{
		ChallengeID: "challenge-management-0001",
		ApprovalID:  "approval-management-0001",
		SignerKeyID: "device-management-0001",
		Scope: ScopeV1{
			AgentInstanceID: "11111111-1111-4111-8111-111111111111", OwnerID: "@owner:example.com",
			AcceptanceID: "acceptance-management-0001", ServiceID: "service-management-0001", ServiceRevision: 8,
			DeploymentID: "deployment-management-0001", DeploymentRevision: 11, ConnectionID: "connection-management-0001",
			ConnectionRevision: 6, PlanID: "plan-management-0001", PlanRevision: 7, PlanHash: namedDigest('9'),
			RecipeID: "recipe-management-0001", RecipeDigest: namedDigest('a'), RecipeRevision: 2,
			RecipeMaturity: "awaiting_management_acceptance", InstalledManifestDigest: namedDigest('b'), ArtifactDigest: namedDigest('c'),
			ReadinessSemanticEvidenceDigest: "sha256:bfcfa00e992ba7e0dd053757a88a15d3beb99ecbe2701d441287a07e510e679c",
			ReadinessStackObservationDigest: namedDigest('e'), RestartOperationID: "operation-management-restart-0001", RestartOperationRevision: 3,
			BackupID: "backup-management-0001", BackupRevision: 2, RestoreID: "restore-management-0001", RestoreRevision: 4,
			SourceArtifactDigests: []string{namedDigest('d')},
			HealthRevision:        5, HealthMonitorKind: "service", HealthStatus: "healthy", HealthEvidenceType: "independent_external",
			HealthEvidenceDigest: namedDigest('8'), HealthObservedAt: time.Date(2026, 7, 16, 0, 59, 0, 0, time.UTC),
			Currency: "USD", CostAlertAmountMinor: 2500,
			Health: HealthContractV1{
				Liveness: ProbeV1{Kind: "http", Target: "/live"}, Readiness: ProbeV1{Kind: "http", Target: "/ready"},
				Semantic: ProbeV1{Kind: "command", Target: "probe-semantic"},
			},
			Lifecycle:   LifecycleV1{Start: "start", Stop: "stop", Maintenance: "maintenance", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback", Backup: "backup", Restore: "restore", Destroy: "destroy"},
			VolumeSlots: []VolumeSlotV1{{SlotID: "knowledge", VolumeRef: "volume_ref:knowledge", ReadOnly: true}},
			DataSlots:   []DataSlotV1{{SlotID: "corpus", DataRef: "data_ref:corpus", ReadOnly: true}},
			SecretSlots: []SecretSlotV1{{SlotID: "model", SecretRef: "secret_ref:model"}},
			Resources: []ResourceV1{
				{ResourceID: "22222222-2222-4222-8222-222222222222", Type: "ebs", Revision: 2, ProviderID: "vol-0aaaaaaaaaaaaaaaa", TagDigest: namedDigest('6')},
				{ResourceID: "33333333-3333-4333-8333-333333333333", Type: "ebs", Revision: 3, ProviderID: "vol-0bbbbbbbbbbbbbbbb", TagDigest: namedDigest('7')},
				{ResourceID: "44444444-4444-4444-8444-444444444444", Type: "ec2", Revision: 4, ProviderID: "i-0123456789abcdef0", TagDigest: namedDigest('5')},
				{ResourceID: "55555555-5555-4555-8555-555555555555", Type: "eni", Revision: 5, ProviderID: "eni-0123456789abcdef0", TagDigest: namedDigest('4')},
			},
			DestroyInstanceID:          "i-0123456789abcdef0",
			DestroyVolumeIDs:           []string{"vol-0bbbbbbbbbbbbbbbb", "vol-0aaaaaaaaaaaaaaaa"},
			DestroyNetworkInterfaceIDs: []string{"eni-0123456789abcdef0"}, AcceptancePolicy: AcceptancePolicyV1,
		},
		IssuedAt:  time.Date(2026, 7, 16, 1, 0, 0, 0, time.UTC),
		ExpiresAt: time.Date(2026, 7, 16, 1, 5, 0, 0, time.UTC),
	}
	digest, err := canonical.Digest(challenge.compatibilitySigningPayload())
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:f85968ddfb155d602cd0b2e50de45c30cf1f8145f9fa059c860acd327d80206e"
	if digest != want {
		t.Fatalf("compatibility signing payload digest=%q, want Flutter/Message Server golden %q", digest, want)
	}
	for name, mutate := range map[string]func(*ScopeV1){
		"owner id":          func(v *ScopeV1) { v.OwnerID = "@other:example.com" },
		"agent instance id": func(v *ScopeV1) { v.AgentInstanceID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" },
		"plan id":           func(v *ScopeV1) { v.PlanID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb" },
		"plan revision":     func(v *ScopeV1) { v.PlanRevision++ },
		"plan hash":         func(v *ScopeV1) { v.PlanHash = namedDigest('0') },
		"connection revision": func(v *ScopeV1) {
			v.ConnectionRevision++
		},
		"resource id": func(v *ScopeV1) {
			v.Resources[0].ResourceID = "12121212-1212-4212-8212-121212121212"
		},
		"resource type":        func(v *ScopeV1) { v.Resources[0].Type = "snapshot" },
		"resource revision":    func(v *ScopeV1) { v.Resources[0].Revision++ },
		"resource provider id": func(v *ScopeV1) { v.Resources[0].ProviderID = "vol-0cccccccccccccccc" },
		"resource tag digest":  func(v *ScopeV1) { v.Resources[0].TagDigest = namedDigest('0') },
		"health monitor":       func(v *ScopeV1) { v.HealthMonitorKind = "worker" },
		"health status":        func(v *ScopeV1) { v.HealthStatus = "degraded" },
		"health evidence type": func(v *ScopeV1) { v.HealthEvidenceType = "internal" },
		"health evidence digest": func(v *ScopeV1) {
			v.HealthEvidenceDigest = namedDigest('0')
		},
		"health revision":    func(v *ScopeV1) { v.HealthRevision++ },
		"health observed at": func(v *ScopeV1) { v.HealthObservedAt = v.HealthObservedAt.Add(time.Second) },
		"currency":           func(v *ScopeV1) { v.Currency = "EUR" },
		"cost alert":         func(v *ScopeV1) { v.CostAlertAmountMinor++ },
		"lifecycle start":    func(v *ScopeV1) { v.Lifecycle.Start = "start-v2" },
		"lifecycle stop":     func(v *ScopeV1) { v.Lifecycle.Stop = "stop-v2" },
		"lifecycle maintenance": func(v *ScopeV1) {
			v.Lifecycle.Maintenance = "maintenance-v2"
		},
		"lifecycle restart":  func(v *ScopeV1) { v.Lifecycle.Restart = "restart-v2" },
		"lifecycle upgrade":  func(v *ScopeV1) { v.Lifecycle.Upgrade = "upgrade-v2" },
		"lifecycle rollback": func(v *ScopeV1) { v.Lifecycle.Rollback = "rollback-v2" },
		"lifecycle backup":   func(v *ScopeV1) { v.Lifecycle.Backup = "backup-v2" },
		"lifecycle restore":  func(v *ScopeV1) { v.Lifecycle.Restore = "restore-v2" },
		"lifecycle destroy":  func(v *ScopeV1) { v.Lifecycle.Destroy = "destroy-v2" },
	} {
		t.Run(name, func(t *testing.T) {
			changed := challenge
			changed.Scope.Resources = append([]ResourceV1(nil), challenge.Scope.Resources...)
			mutate(&changed.Scope)
			changedDigest, err := canonical.Digest(changed.compatibilitySigningPayload())
			if err != nil {
				t.Fatal(err)
			}
			if changedDigest == digest {
				t.Fatalf("%s is not bound by the signing payload", name)
			}
		})
	}
}

func namedDigest(value byte) string {
	result := make([]byte, 64)
	for index := range result {
		result[index] = value
	}
	return "sha256:" + string(result)
}
