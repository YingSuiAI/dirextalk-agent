package destroy

import (
	"crypto/sha256"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

func TestSigningPayloadMatchesDartGolden(t *testing.T) {
	scope := destroyGoldenScope()
	scopeDigest, err := ScopeDigest(scope)
	if err != nil {
		t.Fatal(err)
	}
	challenge := ChallengeV1{
		OperationID: "66666666-6666-4666-8666-666666666666",
		ChallengeID: "77777777-7777-4777-8777-777777777777",
		ApprovalID:  "88888888-8888-4888-8888-888888888888",
		SignerKeyID: "cloud-device-0123456789abcdef01234567",
		Scope:       NormalizeScope(scope),
		ScopeDigest: scopeDigest,
		IssuedAt:    time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 7, 17, 9, 5, 0, 0, time.UTC),
		Revision:    1,
	}
	payload, err := challenge.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	payloadDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(payload))
	if got, want := scopeDigest, "sha256:a7b0d873607b2105a6ac45228850f0457ab1eebee1b959da8b6e3338b79157b8"; got != want {
		t.Fatalf("scope digest = %q", got)
	}
	if got, want := payloadDigest, "sha256:05701a8ba952e7e175736b4e5dc41b0ea70a88fef1c88aea41b208b117445309"; got != want {
		t.Fatalf("payload digest = %q", got)
	}

	reordered := scope
	reordered.Resources = slices.Clone(scope.Resources)
	slices.Reverse(reordered.Resources)
	for index := range reordered.Resources {
		slices.Reverse(reordered.Resources[index].DependsOn)
	}
	if got, err := ScopeDigest(reordered); err != nil || got != scopeDigest {
		t.Fatalf("normalized digest = %q, %v", got, err)
	}
}

func TestManualDestroyScopeAllowsOnlyClosedEntrypointGraph(t *testing.T) {
	scope := entryDestroyScope()
	digest, err := ScopeDigest(scope)
	if err != nil {
		t.Fatalf("entry resource graph rejected: %v", err)
	}
	challenge := ChallengeV1{
		OperationID: "99999999-9999-4999-8999-999999999999",
		ChallengeID: "88888888-8888-4888-8888-888888888888",
		ApprovalID:  "77777777-7777-4777-8777-777777777777",
		SignerKeyID: "cloud-device-0123456789abcdef01234567",
		Scope:       scope,
		ScopeDigest: digest,
		IssuedAt:    time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC),
		ExpiresAt:   time.Date(2026, 7, 17, 9, 5, 0, 0, time.UTC),
		Revision:    1,
	}
	if _, err := challenge.SigningPayload(); err != nil {
		t.Fatalf("entrypoint challenge rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*ScopeV1)
		want   error
	}{
		{
			name: "unknown resource type",
			mutate: func(value *ScopeV1) {
				value.Resources[0].Type = resource.Type("unapproved_entry_resource")
			},
			want: ErrInvalid,
		},
		{
			name: "known but unsupported resource type",
			mutate: func(value *ScopeV1) {
				value.Resources[0].Type = resource.TypeEndpoint
			},
			want: ErrInvalid,
		},
		{
			name: "managed entry resource",
			mutate: func(value *ScopeV1) {
				value.Resources[0].Retention = task.RetentionManaged
			},
			want: ErrManaged,
		},
		{
			name: "unknown dependency",
			mutate: func(value *ScopeV1) {
				value.Resources[3].DependsOn = []string{"ffffffff-ffff-4fff-8fff-ffffffffffff"}
			},
			want: ErrInvalid,
		},
		{
			name: "cyclic dependency",
			mutate: func(value *ScopeV1) {
				value.Resources[4].DependsOn = []string{value.Resources[5].ResourceID}
			},
			want: ErrInvalid,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := cloneDestroyScope(scope)
			test.mutate(&value)
			if _, err := ScopeDigest(value); err != test.want {
				t.Fatalf("ScopeDigest() error = %v, want %v", err, test.want)
			}
		})
	}
}

func entryDestroyScope() ScopeV1 {
	scope := destroyGoldenScope()
	template := scope.Resources[0]
	newResource := func(resourceID string, kind resource.Type, providerID string, dependsOn ...string) ResourceScopeV1 {
		value := template
		value.ResourceID, value.Type, value.ProviderID = resourceID, kind, providerID
		value.DependsOn = slices.Clone(dependsOn)
		value.ReadBack.ProviderID = providerID
		return value
	}
	worker := newResource("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1", resource.TypeEC2, "i-0123456789abcdef0")
	workerSecurityGroup := newResource("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2", resource.TypeSG, "sg-0123456789abcdef0")
	albSecurityGroup := newResource("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3", resource.TypeSG, "sg-0fedcba9876543210")
	alb := newResource("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4", resource.TypeALB, "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/dtx/0123456789abcdef", albSecurityGroup.ResourceID)
	targetGroup := newResource("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa5", resource.TypeTargetGroup, "arn:aws:elasticloadbalancing:us-east-1:123456789012:targetgroup/dtx/0123456789abcdef", worker.ResourceID)
	listener := newResource("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa6", resource.TypeListener, "arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/dtx/0123456789abcdef/0123456789abcdef", alb.ResourceID, targetGroup.ResourceID)
	bridge := newResource("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa7", resource.TypeSecurityGroupRule, "sgr-0123456789abcdef0", albSecurityGroup.ResourceID, workerSecurityGroup.ResourceID)
	scope.Resources = []ResourceScopeV1{worker, workerSecurityGroup, albSecurityGroup, alb, targetGroup, listener, bridge}
	return NormalizeScope(scope)
}

func cloneDestroyScope(scope ScopeV1) ScopeV1 {
	clone := scope
	clone.Resources = slices.Clone(scope.Resources)
	for index := range clone.Resources {
		clone.Resources[index].DependsOn = slices.Clone(scope.Resources[index].DependsOn)
	}
	return clone
}

func destroyGoldenScope() ScopeV1 {
	resourceIDs := []string{
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa3",
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa4",
	}
	providerIDs := []string{
		"i-0123456789abcdef0",
		"vol-0123456789abcdef0",
		"eni-0123456789abcdef0",
		"sg-0123456789abcdef0",
	}
	types := []resource.Type{resource.TypeEC2, resource.TypeEBS, resource.TypeENI, resource.TypeSG}
	observedAt := time.Date(2026, 7, 17, 9, 0, 0, 0, time.UTC)
	deadline := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	resources := make([]ResourceScopeV1, 0, len(resourceIDs))
	for index := range resourceIDs {
		dependsOn := []string{resourceIDs[0]}
		if index == 0 {
			dependsOn = []string{resourceIDs[3]}
		} else if index == 3 {
			dependsOn = nil
		}
		resources = append(resources, ResourceScopeV1{
			ResourceID: resourceIDs[index], Type: types[index], ProviderID: providerIDs[index], Revision: int64(index + 1),
			DependsOn: dependsOn, Retention: task.RetentionEphemeralAutoDestroy, State: resource.StateActive, Region: "us-east-1",
			SpecDigest: "sha256:" + strings.Repeat(fmt.Sprint(index+1), 64), ApprovedPlanHash: "sha256:" + strings.Repeat("b", 64),
			OriginalApprovalID: "99999999-9999-4999-8999-999999999999",
			ReadBack:           ReadBackScopeV1{Observed: true, Exists: true, ProviderID: providerIDs[index], ObservedAt: observedAt, TagDigest: "sha256:" + strings.Repeat("c", 64)},
			DestroyDeadline:    deadline, AutoDestroyApproved: true,
		})
	}
	return ScopeV1{
		SchemaVersion: ScopeSchemaV1, AgentInstanceID: "11111111-1111-4111-8111-111111111111", OwnerID: "owner-agent-destroy-0001",
		DeploymentID: "22222222-2222-4222-8222-222222222222", DeploymentRevision: 12, TaskID: "33333333-3333-4333-8333-333333333333",
		PlanID: "44444444-4444-4444-8444-444444444444", PlanHash: "sha256:" + strings.Repeat("a", 64), ConnectionID: "55555555-5555-4555-8555-555555555555",
		Resources: resources,
	}
}
