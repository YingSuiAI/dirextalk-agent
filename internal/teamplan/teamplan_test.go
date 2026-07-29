package teamplan

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

func TestCompileSelectsQualifiedTeamAndEstimatesParallelSchedule(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()

	plan, err := Compile(request)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if plan.WorkerCount != 3 || plan.MaxConcurrentWorkers != 2 {
		t.Fatalf(
			"team size = %d/%d, want 3 workers with peak 2",
			plan.WorkerCount,
			plan.MaxConcurrentWorkers,
		)
	}
	assertRuntime(t, plan, "implement-api", RuntimeCodex)
	assertRuntime(t, plan, "research-risk", RuntimeHermes)
	assertRuntime(t, plan, "review-api", RuntimeClaudeCode)
	if got, want := plan.Schedule.ExpectedWallTime, 31*time.Minute+15*time.Second; got != want {
		t.Fatalf("expected wall time = %v, want %v", got, want)
	}
	if plan.Cost.MinimumMicros == 0 ||
		plan.Cost.MinimumMicros > plan.Cost.ExpectedMicros ||
		plan.Cost.ExpectedMicros > plan.Cost.MaximumMicros ||
		plan.Cost.HardBudgetMicros < plan.Cost.MaximumMicros ||
		plan.Cost.HardBudgetMicros > request.Policy.MaxPlanCostMicros {
		t.Fatalf("incoherent cost estimate: %+v", plan.Cost)
	}
	if len(plan.Cost.Roles) != 3 ||
		!slices.Contains(plan.Cost.Assumptions, "remote_model_token_range") ||
		!slices.Contains(plan.Cost.Exclusions, "third_party_paid_tools") {
		t.Fatalf("missing cost evidence boundaries: %+v", plan.Cost)
	}
	digest, err := plan.Digest()
	if err != nil || !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		t.Fatalf("Digest() = %q, %v", digest, err)
	}
}

func TestCompileIsDeterministicAcrossCatalogAndProposalOrder(t *testing.T) {
	t.Parallel()
	left := validCompileRequest()
	right := validCompileRequest()
	slices.Reverse(right.Proposal.Roles)
	slices.Reverse(right.RuntimeReleases)
	slices.Reverse(right.ModelOffers)
	slices.Reverse(right.ComputeOffers)
	for index := range right.Proposal.Roles {
		slices.Reverse(right.Proposal.Roles[index].RequiredCapabilities)
		slices.Reverse(right.Proposal.Roles[index].PreferredFamilies)
		slices.Reverse(right.Proposal.Roles[index].DependsOnRoleIDs)
	}

	leftPlan, err := Compile(left)
	if err != nil {
		t.Fatalf("Compile(left) error = %v", err)
	}
	rightPlan, err := Compile(right)
	if err != nil {
		t.Fatalf("Compile(right) error = %v", err)
	}
	leftDigest, err := leftPlan.Digest()
	if err != nil {
		t.Fatalf("left Digest() error = %v", err)
	}
	rightDigest, err := rightPlan.Digest()
	if err != nil {
		t.Fatalf("right Digest() error = %v", err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("digest drifted across unordered input: %s != %s", leftDigest, rightDigest)
	}
}

func TestCompileRejectsConcurrentExclusiveWriters(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	request.Proposal.Roles = []RoleProposal{
		request.Proposal.Roles[0],
		request.Proposal.Roles[0],
	}
	request.Proposal.Roles[0].RoleID = "writer-one"
	request.Proposal.Roles[0].Workspace = WorkspaceExclusive
	request.Proposal.Roles[1].RoleID = "writer-two"
	request.Proposal.Roles[1].Workspace = WorkspaceExclusive

	if _, err := Compile(request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Compile() error = %v, want ErrInvalid", err)
	}
}

func TestCompileAllowsExplicitlySerializedExclusiveWriters(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	request.Proposal.Roles = []RoleProposal{
		request.Proposal.Roles[0],
		request.Proposal.Roles[0],
	}
	request.Proposal.Roles[0].RoleID = "writer-one"
	request.Proposal.Roles[0].Workspace = WorkspaceExclusive
	request.Proposal.Roles[1].RoleID = "writer-two"
	request.Proposal.Roles[1].Workspace = WorkspaceExclusive
	request.Proposal.Roles[1].DependsOnRoleIDs = []string{"writer-one"}

	plan, err := Compile(request)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if plan.MaxConcurrentWorkers != 1 {
		t.Fatalf("peak concurrency = %d, want 1", plan.MaxConcurrentWorkers)
	}
}

func TestCompileRejectsUnqualifiedRuntimeAndMissingModelOrCompute(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*CompileRequest)
		want   error
	}{
		{
			name: "runtime",
			mutate: func(request *CompileRequest) {
				for index := range request.RuntimeReleases {
					request.RuntimeReleases[index].Trust = RuntimeTrustCandidate
				}
			},
			want: ErrNoRuntime,
		},
		{
			name: "model",
			mutate: func(request *CompileRequest) {
				for index := range request.ModelOffers {
					request.ModelOffers[index].CredentialReady = false
				}
			},
			want: ErrNoModel,
		},
		{
			name: "compute",
			mutate: func(request *CompileRequest) {
				for index := range request.ComputeOffers {
					request.ComputeOffers[index].Available = false
				}
			},
			want: ErrNoCompute,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			request := validCompileRequest()
			test.mutate(&request)
			if _, err := Compile(request); !errors.Is(err, test.want) {
				t.Fatalf("Compile() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCompileRejectsBudgetOverrunBeforeApproval(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	request.Policy.MaxPlanCostMicros = 100

	if _, err := Compile(request); !errors.Is(err, ErrBudgetExceeded) {
		t.Fatalf("Compile() error = %v, want ErrBudgetExceeded", err)
	}
}

func TestCompileRejectsAggregateComputeCapacityOverrun(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	for index := range request.ComputeOffers {
		request.ComputeOffers[index].Available = false
		request.ComputeOffers[index].AvailableUnits = 16
	}
	request.ComputeOffers[0].Available = true
	request.ComputeOffers[0].VCPU = 8
	request.ComputeOffers[0].MemoryMiB = 16 * 1024
	request.ComputeOffers[0].DiskGiB = 200
	request.ComputeOffers[0].CapacityUnits = 8
	request.ComputeOffers[0].AvailableUnits = 16

	if _, err := Compile(request); !errors.Is(err, ErrNoCompute) {
		t.Fatalf("Compile() error = %v, want ErrNoCompute", err)
	}
}

func TestCompileRejectsSecretShapedProposal(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	request.Proposal.Roles[0].Objective =
		"Use api_key=abcdefghijklmnopqrstuvwxyz while implementing the API"

	if _, err := Compile(request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Compile() error = %v, want ErrInvalid", err)
	}

	request = validCompileRequest()
	request.ModelOffers[0].CredentialRef = "sk-abcdefghijklmnopqrstuvwxyz"
	if _, err := Compile(request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("raw model credential Compile() error = %v, want ErrInvalid", err)
	}
}

func TestCompileRejectsSubMicrosecondQuoteTimestamp(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	request.QuotedAt = request.QuotedAt.Add(time.Nanosecond)
	if _, err := Compile(request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Compile() error = %v, want ErrInvalid", err)
	}
}

func TestPlanValidationRejectsSubsecondSchedule(t *testing.T) {
	t.Parallel()
	plan, err := Compile(validCompileRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan.Schedule.ExpectedWallTime += time.Nanosecond
	if err := plan.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() error = %v, want ErrInvalid", err)
	}
}

func TestPlanValidationRejectsZeroBudgetProjection(t *testing.T) {
	t.Parallel()
	plan, err := Compile(validCompileRequest())
	if err != nil {
		t.Fatal(err)
	}
	plan.Cost.MinimumMicros = 0
	plan.Cost.ExpectedMicros = 0
	plan.Cost.MaximumMicros = 0
	plan.Cost.HardBudgetMicros = 0
	for index := range plan.Cost.Roles {
		plan.Cost.Roles[index] = RoleCostEstimate{
			RoleID: plan.Cost.Roles[index].RoleID,
		}
	}
	if err := plan.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Validate() error = %v, want ErrInvalid", err)
	}
}

func TestPlanDigestBindsRuntimeImageProviderScopeAndRejectsFloatingVersion(
	t *testing.T,
) {
	t.Parallel()
	plan, err := Compile(validCompileRequest())
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	original, err := plan.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	changed := plan
	changed.Assignments = append([]WorkerAssignment(nil), plan.Assignments...)
	changed.Assignments[0].RuntimeImageDigest = "sha256:" + strings.Repeat("f", 64)
	changedDigest, err := changed.Digest()
	if err != nil {
		t.Fatalf("changed Digest() error = %v", err)
	}
	if changedDigest == original {
		t.Fatal("runtime image change did not change Plan digest")
	}
	changed = plan
	changed.ProviderScope.ConnectionRevision++
	changedDigest, err = changed.Digest()
	if err != nil {
		t.Fatalf("provider scope mutation Digest() error = %v", err)
	}
	if changedDigest == original {
		t.Fatal("Provider scope mutation did not change Plan digest")
	}
	changed = plan
	changed.Assignments = append([]WorkerAssignment(nil), plan.Assignments...)
	changed.Assignments[0].RuntimeVersion = "latest"
	if _, err := changed.Digest(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("floating version Digest() error = %v, want ErrInvalid", err)
	}
}

func TestRuntimeCatalogRejectsTwoQualifiedReleasesForSameFamilyAndArchitecture(t *testing.T) {
	t.Parallel()
	request := validCompileRequest()
	duplicate := request.RuntimeReleases[0]
	duplicate.ReleaseID = "99999999-9999-4999-8999-999999999999"
	duplicate.Version = "0.2.0"
	duplicate.ImageDigest = "sha256:" + strings.Repeat("9", 64)
	request.RuntimeReleases = append(request.RuntimeReleases, duplicate)

	if _, err := Compile(request); !errors.Is(err, ErrInvalid) {
		t.Fatalf("Compile() error = %v, want ErrInvalid", err)
	}
}

func assertRuntime(t *testing.T, plan Plan, roleID string, want RuntimeFamily) {
	t.Helper()
	for _, assignment := range plan.Assignments {
		if assignment.RoleID == roleID {
			if assignment.RuntimeFamily != want {
				t.Fatalf(
					"runtime for %s = %s, want %s",
					roleID,
					assignment.RuntimeFamily,
					want,
				)
			}
			return
		}
	}
	t.Fatalf("role %s not found", roleID)
}

func validCompileRequest() CompileRequest {
	now := time.Date(2026, 7, 29, 8, 0, 0, 0, time.UTC)
	return CompileRequest{
		PlanID:     "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		Revision:   1,
		OwnerID:    "owner-test",
		GoalDigest: "sha256:" + strings.Repeat("1", 64),
		ProviderScope: ProviderScope{
			Provider:           CloudProviderAWS,
			ConnectionID:       "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
			ConnectionRevision: 7,
			AccountID:          "123456789012",
		},
		Region:                "ap-southeast-3",
		CatalogRevision:       "sha256:" + strings.Repeat("2", 64),
		PricingSnapshotID:     "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		PricingSnapshotDigest: "sha256:" + strings.Repeat("3", 64),
		Currency:              "USD",
		QuotedAt:              now,
		ValidUntil:            now.Add(15 * time.Minute),
		Proposal: TeamProposal{
			Confidence: 84,
			Rationale:  "Use independent implementation, research, and review roles.",
			Roles: []RoleProposal{
				{
					RoleID:    "implement-api",
					Title:     "Implement API changes",
					Objective: "Implement the bounded API change and run focused tests.",
					WorkClass: WorkSoftwareImplementation,
					RequiredCapabilities: []Capability{
						CapabilityRepositoryRead,
						CapabilityRepositoryWrite,
						CapabilityShell,
						CapabilityGit,
						CapabilityTest,
						CapabilityStructuredResults,
					},
					PreferredFamilies: []RuntimeFamily{
						RuntimeCodex,
						RuntimeClaudeCode,
						RuntimeOpenCode,
					},
					Workspace: WorkspaceIsolated,
					Duration: DurationEstimate{
						Minimum:  10 * time.Minute,
						Expected: 20 * time.Minute,
						Maximum:  40 * time.Minute,
					},
					Tokens: TokenEstimate{
						InputMinimum:   100_000,
						InputExpected:  200_000,
						InputMaximum:   400_000,
						OutputMinimum:  20_000,
						OutputExpected: 40_000,
						OutputMaximum:  80_000,
					},
					ModelNeed: ModelNeed{
						MinimumQuality:       QualityBalanced,
						MinimumContextTokens: 100_000,
					},
					MinimumResources: ResourceEnvelope{
						VCPU: 2, MemoryMiB: 2048, DiskGiB: 20,
					},
				},
				{
					RoleID:    "research-risk",
					Title:     "Research integration risks",
					Objective: "Research the integration surface and return source-backed risks.",
					WorkClass: WorkResearch,
					RequiredCapabilities: []Capability{
						CapabilityWebResearch,
						CapabilityMCPClient,
						CapabilityStructuredResults,
					},
					PreferredFamilies: []RuntimeFamily{
						RuntimeHermes,
						RuntimeOpenClaw,
					},
					Workspace: WorkspaceReadOnly,
					Duration: DurationEstimate{
						Minimum:  8 * time.Minute,
						Expected: 15 * time.Minute,
						Maximum:  30 * time.Minute,
					},
					Tokens: TokenEstimate{
						InputMinimum:   60_000,
						InputExpected:  120_000,
						InputMaximum:   250_000,
						OutputMinimum:  10_000,
						OutputExpected: 25_000,
						OutputMaximum:  50_000,
					},
					ModelNeed: ModelNeed{
						MinimumQuality:       QualityBalanced,
						MinimumContextTokens: 64_000,
					},
					MinimumResources: ResourceEnvelope{
						VCPU: 2, MemoryMiB: 3072, DiskGiB: 20,
					},
				},
				{
					RoleID:    "review-api",
					Title:     "Review implementation",
					Objective: "Independently review the implementation and test evidence.",
					WorkClass: WorkSoftwareReview,
					RequiredCapabilities: []Capability{
						CapabilityRepositoryRead,
						CapabilityCodeReview,
						CapabilityTest,
						CapabilityStructuredResults,
					},
					PreferredFamilies: []RuntimeFamily{
						RuntimeClaudeCode,
						RuntimeCodex,
					},
					Workspace:        WorkspaceReadOnly,
					DependsOnRoleIDs: []string{"implement-api"},
					Duration: DurationEstimate{
						Minimum:  5 * time.Minute,
						Expected: 10 * time.Minute,
						Maximum:  20 * time.Minute,
					},
					Tokens: TokenEstimate{
						InputMinimum:   80_000,
						InputExpected:  160_000,
						InputMaximum:   300_000,
						OutputMinimum:  10_000,
						OutputExpected: 20_000,
						OutputMaximum:  40_000,
					},
					ModelNeed: ModelNeed{
						MinimumQuality:       QualityPremium,
						MinimumContextTokens: 100_000,
					},
					MinimumResources: ResourceEnvelope{
						VCPU: 2, MemoryMiB: 2048, DiskGiB: 20,
					},
				},
			},
		},
		RuntimeReleases: validRuntimeReleases(now),
		ModelOffers: []ModelOffer{
			{
				ProfileID: "openai-balanced", Provider: "OpenAI", Model: "code-balanced",
				Interface: ModelOpenAIResponses, Quality: QualityBalanced,
				ContextTokens: 256_000, InputMicrosPerMillion: 2_000_000,
				OutputMicrosPerMillion: 8_000_000,
				CredentialRef:          "secret_ref:model-openai-balanced",
				Enabled:                true, CredentialReady: true,
			},
			{
				ProfileID: "anthropic-premium", Provider: "Anthropic", Model: "code-premium",
				Interface: ModelAnthropicAPI, Quality: QualityPremium,
				ContextTokens: 256_000, InputMicrosPerMillion: 5_000_000,
				OutputMicrosPerMillion: 25_000_000,
				CredentialRef:          "secret_ref:model-anthropic-premium",
				Enabled:                true, CredentialReady: true,
			},
			{
				ProfileID: "compatible-balanced", Provider: "Configured", Model: "general-balanced",
				Interface: ModelOpenAICompatible, Quality: QualityBalanced,
				ContextTokens: 128_000, InputMicrosPerMillion: 1_000_000,
				OutputMicrosPerMillion: 4_000_000,
				CredentialRef:          "secret_ref:model-compatible-balanced",
				Enabled:                true, CredentialReady: true,
			},
		},
		ComputeOffers: []ComputeOffer{
			{
				OfferID: "10000000-0000-4000-8000-000000000001",
				Region:  "ap-southeast-3", InstanceType: "t3.medium",
				Architecture: recipe.ArchitectureAMD64,
				VCPU:         2, MemoryMiB: 4096, DiskGiB: 40,
				HourlyMicros: 100_000, PurchaseOption: "on_demand", Available: true,
				CapacityPool:  "aws:ec2:standard",
				CapacityUnits: 2, AvailableUnits: 64,
			},
			{
				OfferID: "10000000-0000-4000-8000-000000000002",
				Region:  "ap-southeast-3", InstanceType: "t3.xlarge",
				Architecture: recipe.ArchitectureAMD64,
				VCPU:         4, MemoryMiB: 8192, DiskGiB: 80,
				HourlyMicros: 200_000, PurchaseOption: "on_demand", Available: true,
				CapacityPool:  "aws:ec2:standard",
				CapacityUnits: 4, AvailableUnits: 64,
			},
			{
				OfferID: "10000000-0000-4000-8000-000000000003",
				Region:  "ap-southeast-3", InstanceType: "t4g.medium",
				Architecture: recipe.ArchitectureARM64,
				VCPU:         2, MemoryMiB: 4096, DiskGiB: 40,
				HourlyMicros: 80_000, PurchaseOption: "on_demand", Available: true,
				CapacityPool:  "aws:ec2:standard",
				CapacityUnits: 2, AvailableUnits: 64,
			},
		},
		Policy: Policy{
			MaxWorkers:                4,
			MaxConcurrentWorkers:      3,
			MaxRoleDuration:           4 * time.Hour,
			MaxVCPUPerWorker:          8,
			MaxMemoryMiBPerWorker:     16 * 1024,
			MaxDiskGiBPerWorker:       200,
			MaxPlanCostMicros:         100_000_000,
			SafetyMarginBasisPoints:   2000,
			FixedWorkerOverheadMicros: 10_000,
			AllowedRuntimeFamilies: []RuntimeFamily{
				RuntimeClaudeCode,
				RuntimeCodex,
				RuntimeOpenClaw,
				RuntimeHermes,
				RuntimeOpenCode,
			},
		},
	}
}

func validRuntimeReleases(now time.Time) []RuntimeRelease {
	baseCapabilities := []Capability{
		CapabilityRepositoryRead,
		CapabilityShell,
		CapabilityMCPClient,
		CapabilityStructuredResults,
	}
	return []RuntimeRelease{
		{
			ReleaseID: "20000000-0000-4000-8000-000000000001",
			Family:    RuntimeCodex, Version: "0.1.0", Adapter: AdapterCodexV1,
			SourceURL:    "https://github.com/openai/codex",
			SourceCommit: strings.Repeat("a", 40), License: "Apache-2.0",
			ImageDigest: "sha256:" + strings.Repeat("a", 64),
			Capabilities: append(append([]Capability(nil), baseCapabilities...),
				CapabilityRepositoryWrite,
				CapabilityCodeReview,
				CapabilityGit,
				CapabilityTest,
			),
			ModelInterfaces: []ModelInterface{ModelOpenAIResponses},
			Suitability: []Suitability{
				{WorkClass: WorkSoftwareImplementation, Score: 98},
				{WorkClass: WorkSoftwareReview, Score: 92},
				{WorkClass: WorkSoftwareTest, Score: 97},
			},
			Minimum: ResourceEnvelope{
				VCPU: 1, MemoryMiB: 1024, DiskGiB: 10,
				Arch: recipe.ArchitectureAMD64,
			},
			Recommended: ResourceEnvelope{
				VCPU: 2, MemoryMiB: 2048, DiskGiB: 20,
				Arch: recipe.ArchitectureAMD64,
			},
			ColdStart: 30 * time.Second, Trust: RuntimeTrustQualified, QualifiedAt: now,
		},
		{
			ReleaseID: "20000000-0000-4000-8000-000000000002",
			Family:    RuntimeClaudeCode, Version: "0.1.0", Adapter: AdapterClaudeCodeV1,
			SourceURL:    "https://code.claude.com/docs/en/features-overview",
			SourceCommit: strings.Repeat("b", 40), License: "Commercial-qualified",
			ImageDigest: "sha256:" + strings.Repeat("b", 64),
			Capabilities: append(append([]Capability(nil), baseCapabilities...),
				CapabilityRepositoryWrite,
				CapabilityCodeReview,
				CapabilityGit,
				CapabilityTest,
				CapabilitySubagents,
			),
			ModelInterfaces: []ModelInterface{ModelAnthropicAPI},
			Suitability: []Suitability{
				{WorkClass: WorkSoftwareImplementation, Score: 96},
				{WorkClass: WorkSoftwareReview, Score: 99},
				{WorkClass: WorkResearch, Score: 82},
			},
			Minimum: ResourceEnvelope{
				VCPU: 2, MemoryMiB: 2048, DiskGiB: 20,
				Arch: recipe.ArchitectureAMD64,
			},
			Recommended: ResourceEnvelope{
				VCPU: 4, MemoryMiB: 4096, DiskGiB: 40,
				Arch: recipe.ArchitectureAMD64,
			},
			ColdStart: 45 * time.Second, Trust: RuntimeTrustQualified, QualifiedAt: now,
		},
		{
			ReleaseID: "20000000-0000-4000-8000-000000000003",
			Family:    RuntimeHermes, Version: "0.1.0", Adapter: AdapterHermesV1,
			SourceURL:    "https://github.com/NousResearch/hermes-agent",
			SourceCommit: strings.Repeat("c", 40), License: "MIT",
			ImageDigest: "sha256:" + strings.Repeat("c", 64),
			Capabilities: append(append([]Capability(nil), baseCapabilities...),
				CapabilityWebResearch,
				CapabilityLongMemory,
				CapabilityLongRunning,
				CapabilitySubagents,
			),
			ModelInterfaces: []ModelInterface{ModelOpenAICompatible},
			Suitability: []Suitability{
				{WorkClass: WorkResearch, Score: 95},
				{WorkClass: WorkGeneralTool, Score: 97},
				{WorkClass: WorkLongRunningOperations, Score: 97},
			},
			Minimum: ResourceEnvelope{
				VCPU: 1, MemoryMiB: 2048, DiskGiB: 20,
				Arch: recipe.ArchitectureAMD64,
			},
			Recommended: ResourceEnvelope{
				VCPU: 2, MemoryMiB: 4096, DiskGiB: 40,
				Arch: recipe.ArchitectureAMD64,
			},
			ColdStart: time.Minute, Trust: RuntimeTrustQualified, QualifiedAt: now,
		},
		{
			ReleaseID: "20000000-0000-4000-8000-000000000004",
			Family:    RuntimeOpenCode, Version: "0.1.0", Adapter: AdapterOpenCodeV1,
			SourceURL:    "https://github.com/anomalyco/opencode",
			SourceCommit: strings.Repeat("d", 40), License: "MIT",
			ImageDigest: "sha256:" + strings.Repeat("d", 64),
			Capabilities: append(append([]Capability(nil), baseCapabilities...),
				CapabilityRepositoryWrite,
				CapabilityCodeReview,
				CapabilityGit,
				CapabilityTest,
			),
			ModelInterfaces: []ModelInterface{
				ModelAnthropicAPI,
				ModelOpenAIResponses,
				ModelOpenAICompatible,
			},
			Suitability: []Suitability{
				{WorkClass: WorkSoftwareImplementation, Score: 90},
				{WorkClass: WorkSoftwareReview, Score: 90},
				{WorkClass: WorkSoftwareTest, Score: 92},
				{WorkClass: WorkResearch, Score: 70},
			},
			Minimum: ResourceEnvelope{
				VCPU: 1, MemoryMiB: 1024, DiskGiB: 10,
				Arch: recipe.ArchitectureAMD64,
			},
			Recommended: ResourceEnvelope{
				VCPU: 2, MemoryMiB: 2048, DiskGiB: 20,
				Arch: recipe.ArchitectureAMD64,
			},
			ColdStart: 30 * time.Second, Trust: RuntimeTrustQualified, QualifiedAt: now,
		},
		{
			ReleaseID: "20000000-0000-4000-8000-000000000005",
			Family:    RuntimeOpenClaw, Version: "0.1.0", Adapter: AdapterOpenClawV1,
			SourceURL:    "https://github.com/openclaw/openclaw",
			SourceCommit: strings.Repeat("e", 40), License: "MIT",
			ImageDigest: "sha256:" + strings.Repeat("e", 64),
			Capabilities: append(append([]Capability(nil), baseCapabilities...),
				CapabilityWebResearch,
				CapabilityBrowser,
				CapabilityLongMemory,
				CapabilitySubagents,
				CapabilityMessaging,
				CapabilityLongRunning,
			),
			ModelInterfaces: []ModelInterface{ModelOpenAICompatible},
			Suitability: []Suitability{
				{WorkClass: WorkResearch, Score: 85},
				{WorkClass: WorkBrowserAutomation, Score: 100},
				{WorkClass: WorkCommunication, Score: 100},
				{WorkClass: WorkLongRunningOperations, Score: 92},
			},
			Minimum: ResourceEnvelope{
				VCPU: 2, MemoryMiB: 3072, DiskGiB: 20,
				Arch: recipe.ArchitectureAMD64,
			},
			Recommended: ResourceEnvelope{
				VCPU: 4, MemoryMiB: 4096, DiskGiB: 40,
				Arch: recipe.ArchitectureAMD64,
			},
			ColdStart: 90 * time.Second, Trust: RuntimeTrustQualified, QualifiedAt: now,
		},
	}
}
