package teamlaunch

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	workerprotocol "github.com/YingSuiAI/dirextalk-agent/sdk/workerprotocol/v1"
)

func TestProviderCreationStillRequiresFifteenMinuteQuoteFreshness(
	t *testing.T,
) {
	t.Parallel()
	if maximumQuoteAgeSeconds != uint64((15*time.Minute)/time.Second) {
		t.Fatalf("maximumQuoteAgeSeconds = %d", maximumQuoteAgeSeconds)
	}
}

func TestAuthorizationBindsExactProviderLaunchFacts(t *testing.T) {
	request := validBuildRequest(t)
	first, err := NewAuthorizationV1(request)
	if err != nil {
		t.Fatalf("NewAuthorizationV1() error = %v", err)
	}
	reordered := validBuildRequest(t)
	slices.Reverse(reordered.Network.Egress)
	second, err := NewAuthorizationV1(reordered)
	if err != nil {
		t.Fatalf("NewAuthorizationV1(reordered) error = %v", err)
	}
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatalf("Digest(reordered) error = %v", err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("unordered egress changed digest: %s != %s", firstDigest, secondDigest)
	}
	if !slices.IsSortedFunc(first.Network.Egress, compareEgressRules) {
		t.Fatalf("authorization egress is not canonical: %+v", first.Network.Egress)
	}
	expectedAlias, err := awsfoundation.KMSAliasForAgent(request.AgentInstanceID)
	if err != nil {
		t.Fatal(err)
	}
	foundation, err := awsfoundation.BuildSpec(awsfoundation.SpecInput{
		AgentInstanceID: request.AgentInstanceID,
		Partition:       "aws",
		AccountID:       request.Plan.ProviderScope.AccountID,
		Region:          request.Plan.Region,
	})
	if err != nil {
		t.Fatal(err)
	}
	role := first.Roles[0]
	if role.InstanceProfileName != foundation.WorkerProfileName ||
		role.RootStorage.KMSKeyID != expectedAlias ||
		role.RootStorage.IOPS != 3000 ||
		role.RootStorage.ThroughputMiBPS != 125 ||
		!role.EBSOptimized ||
		!role.RequireIMDSv2 ||
		role.MetadataResponseHopLimit != 1 ||
		role.ShutdownBehavior != ShutdownTerminate {
		t.Fatalf("launch safety facts were not derived exactly: %+v", role)
	}
	if err := first.ValidateAgainst(request.Plan); err != nil {
		t.Fatalf("ValidateAgainst() error = %v", err)
	}
	if err := first.ValidateWorkerReleases(
		[]workerrelease.ReleaseV1{request.RoleSelections[0].WorkerRelease},
	); err != nil {
		t.Fatalf("ValidateWorkerReleases() error = %v", err)
	}
	leftCBOR, err := first.CanonicalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	rightCBOR, err := second.CanonicalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	if string(leftCBOR) != string(rightCBOR) {
		t.Fatal("canonical CBOR changed across unordered input")
	}
}

func TestAuthorizationBindsExactMarketplaceReleaseAndPermissions(
	t *testing.T,
) {
	request := validBuildRequest(t)
	binding := marketplaceLaunchBinding(
		request.Plan.Assignments[0],
		request.Plan.ValidUntil.Add(time.Hour),
	)
	request.Plan.Assignments[0].Marketplace = &binding
	authorization, err := NewAuthorizationV1(request)
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Roles[0].Marketplace == nil ||
		!authorization.Roles[0].Marketplace.Equal(binding) {
		t.Fatalf(
			"launch Marketplace binding=%#v",
			authorization.Roles[0].Marketplace,
		)
	}
	if err := authorization.ValidateAgainst(request.Plan); err != nil {
		t.Fatalf("ValidateAgainst() error=%v", err)
	}
	tampered := authorization
	tampered.Roles = append([]RoleLaunchV1(nil), authorization.Roles...)
	changed := tampered.Roles[0].Marketplace.Clone()
	changed.ManifestDigest = testDigest("9")
	tampered.Roles[0].Marketplace = &changed
	if err := tampered.ValidateAgainst(
		request.Plan,
	); !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("manifest substitution error=%v", err)
	}
	changed = authorization.Roles[0].Marketplace.Clone()
	changed.GrantedPermissions.ToolScopes = []string{"git.read"}
	tampered.Roles[0].Marketplace = &changed
	if err := tampered.ValidateAgainst(
		request.Plan,
	); !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("permission substitution error=%v", err)
	}
}

func TestAuthorizationRejectsUnsafeLaunchShapes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthorizationV1)
	}{
		{
			name: "cross-region availability zone prefix",
			mutate: func(value *AuthorizationV1) {
				value.Network.AvailabilityZone = "ap-northeast-30a"
			},
		},
		{
			name: "public inbound",
			mutate: func(value *AuthorizationV1) {
				value.Network.PublicInbound = true
			},
		},
		{
			name: "no public address",
			mutate: func(value *AuthorizationV1) {
				value.Network.PublicIPv4 = false
			},
		},
		{
			name: "control endpoint userinfo",
			mutate: func(value *AuthorizationV1) {
				value.Network.ControlPlaneEndpoint =
					"grpcs://AKIAIOSFODNN7EXAMPLE@worker-control.demo2.dirextalk.ai:7443"
			},
		},
		{
			name: "control endpoint IP",
			mutate: func(value *AuthorizationV1) {
				value.Network.ControlPlaneEndpoint = "grpcs://203.0.113.10:7443"
			},
		},
		{
			name: "arbitrary SSH egress",
			mutate: func(value *AuthorizationV1) {
				value.Network.Egress = append(
					value.Network.Egress,
					EgressRuleV1{
						Protocol: "tcp",
						FromPort: 22,
						ToPort:   22,
						CIDRv4:   "0.0.0.0/0",
					},
				)
				slices.SortFunc(value.Network.Egress, compareEgressRules)
			},
		},
		{
			name: "IPv6 egress",
			mutate: func(value *AuthorizationV1) {
				value.Network.Egress[0].CIDRv4 = "::/0"
				slices.SortFunc(value.Network.Egress, compareEgressRules)
			},
		},
		{
			name: "retained Worker",
			mutate: func(value *AuthorizationV1) {
				value.Retention.AutoDestroy = false
			},
		},
		{
			name: "no destroy grace",
			mutate: func(value *AuthorizationV1) {
				value.Retention.DestroyGraceSeconds = 0
			},
		},
		{
			name: "no fresh quote",
			mutate: func(value *AuthorizationV1) {
				value.RequiresFreshQuote = false
			},
		},
		{
			name: "launch window too long",
			mutate: func(value *AuthorizationV1) {
				value.LaunchNotAfter = value.LaunchNotBefore.Add(
					maximumLaunchWindow + time.Second,
				)
			},
		},
		{
			name: "foreign instance profile",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].InstanceProfileName = "Administrator"
			},
		},
		{
			name: "spot purchase",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].PurchaseOption = "spot"
			},
		},
		{
			name: "EBS optimization disabled",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].EBSOptimized = false
			},
		},
		{
			name: "IMDSv1 allowed",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RequireIMDSv2 = false
			},
		},
		{
			name: "metadata hop widened",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].MetadataResponseHopLimit = 2
			},
		},
		{
			name: "stop instead of terminate",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].ShutdownBehavior = "stop"
			},
		},
		{
			name: "unencrypted root",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RootStorage.Encrypted = false
			},
		},
		{
			name: "retained root",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RootStorage.DeleteOnTermination = false
			},
		},
		{
			name: "extra provisioned IOPS",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RootStorage.IOPS = 16_000
			},
		},
		{
			name: "foreign KMS key",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RootStorage.KMSKeyID = "alias/foreign-key"
			},
		},
		{
			name: "image observed after approval window",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].WorkerImage.ObservedAt =
					value.LaunchNotBefore.Add(time.Second)
			},
		},
		{
			name: "billable concurrency exceeds team",
			mutate: func(value *AuthorizationV1) {
				value.MaxConcurrentBillableWorkers = value.WorkerCount + 1
			},
		},
		{
			name: "role cost exceeds hard budget",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].MaximumApprovedCostMicros =
					value.HardBudgetMicros + 1
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorization := validAuthorization(t)
			test.mutate(&authorization)
			if err := authorization.Validate(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("Validate() error = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestAuthorizationRejectsPlanSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthorizationV1)
	}{
		{
			name: "owner",
			mutate: func(value *AuthorizationV1) {
				value.OwnerID = "owner-b"
			},
		},
		{
			name: "plan digest",
			mutate: func(value *AuthorizationV1) {
				value.PlanDigest = testDigest("f")
			},
		},
		{
			name: "connection revision",
			mutate: func(value *AuthorizationV1) {
				value.ProviderScope.ConnectionRevision++
			},
		},
		{
			name: "runtime release",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RuntimeReleaseID =
					"99999999-9999-4999-8999-999999999999"
			},
		},
		{
			name: "runtime image",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RuntimeImageDigest = testDigest("9")
			},
		},
		{
			name: "compute offer",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].ComputeOfferID =
					"88888888-8888-4888-8888-888888888888"
			},
		},
		{
			name: "instance type",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].InstanceType = "t3.large"
			},
		},
		{
			name: "vCPU",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].VCPU++
			},
		},
		{
			name: "memory",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].MemoryMiB++
			},
		},
		{
			name: "root size",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RootStorage.SizeGiB++
			},
		},
		{
			name: "role cost",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].MaximumApprovedCostMicros--
			},
		},
	}
	plan := validTeamPlan()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorization := validAuthorization(t)
			test.mutate(&authorization)
			if err := authorization.ValidateAgainst(plan); !errors.Is(
				err,
				ErrPlanChanged,
			) {
				t.Fatalf(
					"ValidateAgainst() error = %v, want ErrPlanChanged",
					err,
				)
			}
		})
	}
}

func TestAuthorizationDigestChangesForEveryMutableLaunchFact(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*AuthorizationV1)
	}{
		{
			name: "VPC",
			mutate: func(value *AuthorizationV1) {
				value.Network.VPCID = "vpc-0fedcba9876543210"
			},
		},
		{
			name: "subnet",
			mutate: func(value *AuthorizationV1) {
				value.Network.SubnetID = "subnet-0fedcba9876543210"
			},
		},
		{
			name: "availability zone",
			mutate: func(value *AuthorizationV1) {
				value.Network.AvailabilityZone = "ap-northeast-3b"
			},
		},
		{
			name: "control endpoint",
			mutate: func(value *AuthorizationV1) {
				value.Network.ControlPlaneEndpoint =
					"grpcs://worker-control-alt.demo2.dirextalk.ai:7443"
			},
		},
		{
			name: "retention",
			mutate: func(value *AuthorizationV1) {
				value.Retention.MaximumLifetimeSeconds++
			},
		},
		{
			name: "launch deadline",
			mutate: func(value *AuthorizationV1) {
				value.LaunchNotAfter = value.LaunchNotAfter.Add(time.Second)
			},
		},
		{
			name: "runtime installation",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RuntimeInstallationDigest = testDigest("d")
			},
		},
		{
			name: "runtime executable",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].RuntimeExecutableDigest = testDigest("e")
			},
		},
		{
			name: "AMI",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].WorkerImage.ImageID =
					"ami-0fedcba9876543210"
			},
		},
		{
			name: "AMI identity digest",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].WorkerImage.ImageDigest = testDigest("6")
			},
		},
		{
			name: "publication digest",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].WorkerImage.PublicationDigest =
					testDigest("5")
			},
		},
		{
			name: "root snapshot",
			mutate: func(value *AuthorizationV1) {
				value.Roles[0].WorkerImage.RootSnapshotID =
					"snap-0fedcba9876543210"
			},
		},
	}
	baseline := validAuthorization(t)
	baselineDigest, err := baseline.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			authorization := validAuthorization(t)
			test.mutate(&authorization)
			digest, err := authorization.Digest()
			if err != nil {
				t.Fatalf("mutated Digest() error = %v", err)
			}
			if digest == baselineDigest {
				t.Fatalf("%s did not change authorization digest", test.name)
			}
		})
	}
}

func TestAuthorizationTimeAndWorkerReleaseFences(t *testing.T) {
	request := validBuildRequest(t)
	authorization, err := NewAuthorizationV1(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.ValidateAt(
		authorization.LaunchNotBefore,
	); err != nil {
		t.Fatalf("ValidateAt(start) error = %v", err)
	}
	if err := authorization.ValidateAt(
		authorization.LaunchNotBefore.Add(-time.Microsecond),
	); !errors.Is(err, ErrExpired) {
		t.Fatalf("early ValidateAt() error = %v, want ErrExpired", err)
	}
	if err := authorization.ValidateAt(
		authorization.LaunchNotAfter,
	); !errors.Is(err, ErrExpired) {
		t.Fatalf("late ValidateAt() error = %v, want ErrExpired", err)
	}

	release := request.RoleSelections[0].WorkerRelease
	drifted := release
	drifted.ImageID = "ami-0fedcba9876543210"
	if err := authorization.ValidateWorkerReleases(
		[]workerrelease.ReleaseV1{drifted},
	); !errors.Is(err, ErrImageChanged) {
		t.Fatalf(
			"indexed release drift error = %v, want ErrImageChanged",
			err,
		)
	}
	tampered := authorization
	tampered.Roles[0].WorkerImage.ImageID = "ami-0fedcba9876543210"
	if err := tampered.ValidateWorkerReleases(
		[]workerrelease.ReleaseV1{release},
	); !errors.Is(err, ErrImageChanged) {
		t.Fatalf(
			"authorization image drift error = %v, want ErrImageChanged",
			err,
		)
	}
}

func TestNewAuthorizationRejectsUnverifiedOrMismatchedWorkerRelease(
	t *testing.T,
) {
	tests := []struct {
		name   string
		mutate func(*BuildRequest)
	}{
		{
			name: "indexed release drift",
			mutate: func(value *BuildRequest) {
				value.RoleSelections[0].WorkerRelease.ImageID =
					"ami-0fedcba9876543210"
			},
		},
		{
			name: "wrong account release",
			mutate: func(value *BuildRequest) {
				value.RoleSelections[0].WorkerRelease = testWorkerRelease(
					t,
					value.AgentInstanceID,
					"999999999999",
					value.Plan.Region,
				)
			},
		},
		{
			name: "future image evidence",
			mutate: func(value *BuildRequest) {
				release := value.RoleSelections[0].WorkerRelease
				release.ObservedAt = value.LaunchNotBefore.Add(time.Second)
				value.RoleSelections[0].WorkerRelease = release
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := validBuildRequest(t)
			test.mutate(&request)
			if _, err := NewAuthorizationV1(request); !errors.Is(
				err,
				ErrInvalid,
			) {
				t.Fatalf(
					"NewAuthorizationV1() error = %v, want ErrInvalid",
					err,
				)
			}
		})
	}
}

func TestAuthorizationIDIsStableAndApprovalScoped(t *testing.T) {
	planID := "33333333-3333-4333-8333-333333333333"
	first, err := AuthorizationID(
		planID,
		1,
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := AuthorizationID(
		planID,
		1,
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := AuthorizationID(
		planID,
		2,
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
	)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := AuthorizationID(
		planID,
		1,
		"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
	)
	if err != nil {
		t.Fatal(err)
	}
	if first != replay || first == revision || first == approval {
		t.Fatalf(
			"authorization identity is not deterministic and scoped: %q %q %q %q",
			first,
			replay,
			revision,
			approval,
		)
	}
}

func validAuthorization(t *testing.T) AuthorizationV1 {
	t.Helper()
	authorization, err := NewAuthorizationV1(validBuildRequest(t))
	if err != nil {
		t.Fatalf("NewAuthorizationV1() error = %v", err)
	}
	return authorization
}

func validBuildRequest(t *testing.T) BuildRequest {
	t.Helper()
	plan := validTeamPlan()
	agentInstanceID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	return BuildRequest{
		Plan:            plan,
		AgentInstanceID: agentInstanceID,
		ApprovalID:      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		Network: NetworkV1{
			ConnectivityMode:     ConnectivityDirectPublicTLSV1,
			VPCID:                "vpc-0123456789abcdef0",
			SubnetID:             "subnet-0123456789abcdef0",
			AvailabilityZone:     "ap-northeast-3a",
			SecurityGroupMode:    SecurityGroupDedicatedNoIngress,
			PublicIPv4:           true,
			PublicInbound:        false,
			ControlPlaneEndpoint: "grpcs://worker-control.demo2.dirextalk.ai:7443",
			Egress: []EgressRuleV1{
				{
					Protocol: "udp",
					FromPort: 53,
					ToPort:   53,
					CIDRv4:   vpcResolverCIDR,
				},
				{
					Protocol: "tcp",
					FromPort: 7443,
					ToPort:   7443,
					CIDRv4:   "0.0.0.0/0",
				},
				{
					Protocol: "tcp",
					FromPort: 443,
					ToPort:   443,
					CIDRv4:   "0.0.0.0/0",
				},
			},
		},
		Retention: RetentionV1{
			Class:                  RetentionEphemeralAutoDestroy,
			AutoDestroy:            true,
			MaximumLifetimeSeconds: 2 * 60 * 60,
			DestroyGraceSeconds:    5 * 60,
		},
		LaunchNotBefore: plan.QuotedAt.Add(2 * time.Minute),
		LaunchNotAfter:  plan.QuotedAt.Add(20 * time.Minute),
		RoleSelections: []RoleSelection{{
			RoleID:                    "implementation",
			RuntimeInstallationDigest: testDigest("8"),
			RuntimeExecutableDigest:   testDigest("7"),
			WorkerRelease: testWorkerRelease(
				t,
				agentInstanceID,
				plan.ProviderScope.AccountID,
				plan.Region,
			),
		}},
	}
}

func validTeamPlan() teamplan.Plan {
	quotedAt := time.Date(2026, 7, 30, 10, 0, 0, 0, time.UTC)
	assignment := teamplan.WorkerAssignment{
		RoleID:    "implementation",
		Title:     "Implementation",
		Objective: "Implement the approved change",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityGit,
			teamplan.CapabilityRepositoryWrite,
			teamplan.CapabilityStructuredResults,
			teamplan.CapabilityTest,
		},
		Workspace:          teamplan.WorkspaceIsolated,
		RuntimeReleaseID:   "11111111-1111-4111-8111-111111111111",
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "0.1.0",
		RuntimeImageDigest: testDigest("1"),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     "openai-code-premium",
		ModelProvider:      "openai",
		Model:              "code-model",
		ModelInterface:     teamplan.ModelOpenAIResponses,
		ModelCredentialRef: "secret_ref:models/openai-code",
		ComputeOfferID:     "22222222-2222-4222-8222-222222222222",
		InstanceType:       "m7i.large",
		Resources: teamplan.ResourceEnvelope{
			VCPU:      2,
			MemoryMiB: 8192,
			DiskGiB:   40,
			Arch:      recipe.ArchitectureAMD64,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  10 * time.Minute,
			Expected: 20 * time.Minute,
			Maximum:  45 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum:   10_000,
			InputExpected:  30_000,
			InputMaximum:   80_000,
			OutputMinimum:  2_000,
			OutputExpected: 8_000,
			OutputMaximum:  20_000,
		},
		ColdStart: 90 * time.Second,
	}
	return teamplan.Plan{
		SchemaVersion: teamplan.SchemaV1,
		PlanID:        "33333333-3333-4333-8333-333333333333",
		Revision:      1,
		OwnerID:       "owner-a",
		GoalDigest:    testDigest("2"),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       "55555555-5555-4555-8555-555555555555",
			ConnectionRevision: 11,
			AccountID:          "123456789012",
		},
		Region:                "ap-northeast-3",
		CatalogRevision:       testDigest("3"),
		PolicyRevision:        testDigest("5"),
		PricingSnapshotID:     "44444444-4444-4444-8444-444444444444",
		PricingSnapshotDigest: testDigest("4"),
		QuotedAt:              quotedAt,
		ValidUntil:            quotedAt.Add(15 * time.Minute),
		ProposalConfidence:    85,
		ProposalRationale:     "One isolated implementation Worker is sufficient.",
		WorkerCount:           1,
		MaxConcurrentWorkers:  1,
		Assignments:           []teamplan.WorkerAssignment{assignment},
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  11*time.Minute + 30*time.Second,
			ExpectedWallTime: 21*time.Minute + 30*time.Second,
			MaximumWallTime:  46*time.Minute + 30*time.Second,
		},
		Cost: teamplan.CostEstimate{
			Currency:         "USD",
			MinimumMicros:    120_000,
			ExpectedMicros:   280_000,
			MaximumMicros:    650_000,
			HardBudgetMicros: 780_000,
			Roles: []teamplan.RoleCostEstimate{{
				RoleID:                "implementation",
				ComputeMinimumMicros:  20_000,
				ComputeExpectedMicros: 50_000,
				ComputeMaximumMicros:  100_000,
				ModelMinimumMicros:    90_000,
				ModelExpectedMicros:   220_000,
				ModelMaximumMicros:    540_000,
				TotalMinimumMicros:    120_000,
				TotalExpectedMicros:   280_000,
				TotalMaximumMicros:    650_000,
			}},
			Assumptions: []string{"on_demand_compute"},
			Exclusions:  []string{"third_party_paid_tools"},
		},
	}
}

func marketplaceLaunchBinding(
	assignment teamplan.WorkerAssignment,
	reviewValidUntil time.Time,
) teamplan.WorkerMarketplaceBindingV1 {
	return teamplan.WorkerMarketplaceBindingV1{
		SchemaVersion:            teamplan.WorkerMarketplaceBindingSchemaV1,
		RegistryID:               "66666666-6666-4666-8666-666666666666",
		RegistryRevision:         testDigest("6"),
		ReleaseID:                assignment.RuntimeReleaseID,
		WorkerTypeID:             "77777777-7777-4777-8777-777777777777",
		PublisherID:              "88888888-8888-4888-8888-888888888888",
		PublisherDisplayName:     "Dirextalk Official",
		PublisherTier:            "dirextalk_official",
		ManifestDigest:           testDigest("7"),
		ImageRepository:          "public.ecr.aws/dirextalk/workers/code",
		ImageDigest:              assignment.RuntimeImageDigest,
		ImageSignatureDigest:     testDigest("8"),
		SBOMDigest:               testDigest("9"),
		ProvenanceEnvelopeDigest: testDigest("a"),
		ReviewID:                 "99999999-9999-4999-8999-999999999999",
		ReviewPolicyRevision:     testDigest("b"),
		ReviewRiskClass:          "moderate",
		ReviewValidUntil: reviewValidUntil.
			UTC().
			Truncate(time.Second),
		GrantedPermissions: workerprotocol.PermissionSetV1{
			Workspace: workerprotocol.WorkspaceIsolated,
			NetworkServices: []workerprotocol.NetworkService{
				workerprotocol.NetworkArtifactStore,
				workerprotocol.NetworkControlPlane,
				workerprotocol.NetworkModelGateway,
			},
			ToolScopes: []string{
				"git.read",
				"git.write_patch",
			},
			MaxTempDiskMiB: 4096,
		},
	}
}

func testWorkerRelease(
	t *testing.T,
	agentInstanceID,
	accountID,
	region string,
) workerrelease.ReleaseV1 {
	t.Helper()
	image := workerami.ImageManifestV1{
		SchemaVersion:         workerami.ImageManifestSchemaV1,
		AgentInstanceID:       agentInstanceID,
		ImageID:               "ami-0123456789abcdef0",
		ImageName:             "dtx-worker-ami-0123456789abcdef0123",
		RootSnapshotID:        "snap-0123456789abcdef0",
		AccountID:             accountID,
		Region:                region,
		Architecture:          "amd64",
		BaseAMIID:             "ami-0abcdef0123456789",
		BaseAMIOwnerID:        "099720109477",
		RootDeviceName:        "/dev/sda1",
		ReleaseManifestDigest: testDigest("a"),
		WorkerRootFSDigest:    testDigest("b"),
		WorkerBinaryDigest:    testDigest("c"),
		CreatedAt:             "2026-07-30T08:00:00Z",
	}
	evidence := awsprovider.WorkerAMIAttestationV1{
		SchemaVersion:         awsprovider.WorkerAMIAttestationSchemaV1,
		AgentInstanceID:       image.AgentInstanceID,
		AMIID:                 image.ImageID,
		RootSnapshotID:        image.RootSnapshotID,
		AccountID:             image.AccountID,
		Region:                image.Region,
		Architecture:          recipe.ArchitectureAMD64,
		ReleaseManifestDigest: image.ReleaseManifestDigest,
		WorkerRootFSDigest:    image.WorkerRootFSDigest,
		WorkerBinaryDigest:    image.WorkerBinaryDigest,
		ObservedAt:            time.Date(2026, 7, 30, 8, 1, 0, 0, time.UTC),
	}
	imageDigest, err := evidence.ImageDigest()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(workerrelease.PublicationV1{
		SchemaVersion: workerrelease.PublicationSchemaV1,
		ImageManifest: image,
		ImageDigest:   imageDigest,
		Attestation:   evidence,
	})
	if err != nil {
		t.Fatal(err)
	}
	release, err := workerrelease.ParsePublicationJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return release
}

func testDigest(fill string) string {
	return "sha256:" + strings.Repeat(fill, 64)
}
