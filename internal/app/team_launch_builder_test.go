package app

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
)

const (
	teamLaunchTestAgentID  = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	teamLaunchTestEndpoint = "grpcs://worker-control.demo2.dirextalk.ai:443"
)

func TestAWSTeamLaunchAuthorizationBuilderBindsExactTrustedFacts(
	t *testing.T,
) {
	t.Parallel()
	plan := teamLaunchPlanFixture(t)
	issuedAt := plan.QuotedAt.Add(2 * time.Minute)
	connection := teamLaunchConnectionFixture(plan)
	placements := &teamLaunchPlacementFixture{
		placement: teamLaunchPlacementResult(plan.Region),
	}
	releases := &teamLaunchReleaseFixture{
		release: teamLaunchWorkerReleaseFixture(t, plan),
	}
	runtimes := &teamLaunchRuntimeFixture{
		evidence: teamplan.RuntimeLaunchEvidence{
			InstallationManifestDigest: teamLaunchTestDigest("8"),
			ExecutableDigest:           teamLaunchTestDigest("7"),
		},
	}
	builder, err := newAWSTeamLaunchAuthorizationBuilder(
		teamLaunchTestAgentID,
		teamLaunchTestEndpoint,
		&teamLaunchConnectionFixtureReader{connection: connection},
		placements,
		releases,
		runtimes,
	)
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := builder.BuildForPlan(
		context.Background(),
		plan,
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := authorization.ValidateAt(issuedAt); err != nil {
		t.Fatalf("ValidateAt() error = %v", err)
	}
	if err := authorization.ValidateAgainst(plan); err != nil {
		t.Fatalf("ValidateAgainst() error = %v", err)
	}
	if placements.calls != 1 ||
		placements.connection != connection ||
		placements.request.OwnerID != plan.OwnerID ||
		placements.request.ConnectionID !=
			plan.ProviderScope.ConnectionID ||
		placements.request.Placement.RuntimeHoursPerMonth != 2 ||
		len(placements.request.Placement.Shapes) != 1 ||
		placements.request.Placement.Shapes[0] !=
			(awsprovider.ExactPlacementShapeV1{
				InstanceType: plan.Assignments[0].InstanceType,
				Architecture: plan.Assignments[0].Resources.Arch,
				VCPU:         plan.Assignments[0].Resources.VCPU,
				MemoryMiB:    plan.Assignments[0].Resources.MemoryMiB,
				DiskGiB:      plan.Assignments[0].Resources.DiskGiB,
			}) {
		t.Fatalf(
			"exact placement request was not Plan-bound: %#v",
			placements,
		)
	}
	if releases.calls != 1 ||
		releases.agentInstanceID != teamLaunchTestAgentID ||
		releases.accountID != plan.ProviderScope.AccountID ||
		releases.region != plan.Region ||
		releases.architecture != recipe.ArchitectureAMD64 ||
		runtimes.calls != 1 ||
		runtimes.releaseID != plan.Assignments[0].RuntimeReleaseID {
		t.Fatalf(
			"release evidence was not resolved exactly: release=%#v runtime=%#v",
			releases,
			runtimes,
		)
	}
	if authorization.Network.ControlPlaneEndpoint !=
		teamLaunchTestEndpoint ||
		authorization.Network.PublicInbound ||
		!authorization.Network.PublicIPv4 ||
		len(authorization.Network.Egress) != 2 ||
		authorization.Retention.MaximumLifetimeSeconds !=
			uint64((76*time.Minute+30*time.Second)/time.Second) ||
		authorization.LaunchNotAfter !=
			issuedAt.Add(76*time.Minute+30*time.Second) ||
		len(authorization.Roles) != 1 ||
		authorization.Roles[0].RuntimeInstallationDigest !=
			runtimes.evidence.InstallationManifestDigest ||
		authorization.Roles[0].RuntimeExecutableDigest !=
			runtimes.evidence.ExecutableDigest ||
		authorization.Roles[0].WorkerImage.PublicationDigest !=
			releases.release.PublicationDigest {
		t.Fatalf("unexpected authorization: %#v", authorization)
	}
	if err := authorization.ValidateAt(
		plan.ValidUntil.Add(time.Minute),
	); err != nil {
		t.Fatalf(
			"authorization incorrectly expired with the original quote: %v",
			err,
		)
	}
	tlsRules := 0
	for _, rule := range authorization.Network.Egress {
		if rule.Protocol == "tcp" &&
			rule.FromPort == 443 &&
			rule.ToPort == 443 {
			tlsRules++
		}
	}
	if tlsRules != 1 {
		t.Fatalf(
			"endpoint on 443 produced duplicate TLS egress: %#v",
			authorization.Network.Egress,
		)
	}

	replay, err := builder.BuildForPlan(
		context.Background(),
		plan,
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		issuedAt,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := authorization.Digest()
	if err != nil {
		t.Fatal(err)
	}
	replayDigest, err := replay.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if replayDigest != firstDigest {
		t.Fatalf(
			"same trusted facts changed authorization digest: %s != %s",
			firstDigest,
			replayDigest,
		)
	}
}

func TestAWSTeamLaunchAuthorizationBuilderRejectsConnectionDriftBeforeAWS(
	t *testing.T,
) {
	t.Parallel()
	plan := teamLaunchPlanFixture(t)
	connection := teamLaunchConnectionFixture(plan)
	connection.Revision++
	placements := &teamLaunchPlacementFixture{}
	releases := &teamLaunchReleaseFixture{}
	builder, err := newAWSTeamLaunchAuthorizationBuilder(
		teamLaunchTestAgentID,
		teamLaunchTestEndpoint,
		&teamLaunchConnectionFixtureReader{connection: connection},
		placements,
		releases,
		&teamLaunchRuntimeFixture{},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = builder.BuildForPlan(
		context.Background(),
		plan,
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		plan.QuotedAt.Add(2*time.Minute),
	)
	if !errors.Is(err, teamorchestration.ErrFactMismatch) ||
		placements.calls != 0 ||
		releases.calls != 0 {
		t.Fatalf(
			"connection drift error=%v placement calls=%d release calls=%d",
			err,
			placements.calls,
			releases.calls,
		)
	}
}

func TestAWSTeamLaunchAuthorizationBuilderRejectsPlacementSubstitution(
	t *testing.T,
) {
	t.Parallel()
	plan := teamLaunchPlanFixture(t)
	placement := teamLaunchPlacementResult(plan.Region)
	placement.Region = "us-west-2"
	releases := &teamLaunchReleaseFixture{}
	builder, err := newAWSTeamLaunchAuthorizationBuilder(
		teamLaunchTestAgentID,
		teamLaunchTestEndpoint,
		&teamLaunchConnectionFixtureReader{
			connection: teamLaunchConnectionFixture(plan),
		},
		&teamLaunchPlacementFixture{placement: placement},
		releases,
		&teamLaunchRuntimeFixture{},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = builder.BuildForPlan(
		context.Background(),
		plan,
		"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		plan.QuotedAt.Add(2*time.Minute),
	)
	if !errors.Is(err, teamorchestration.ErrFactMismatch) ||
		releases.calls != 0 {
		t.Fatalf(
			"placement substitution error=%v release calls=%d",
			err,
			releases.calls,
		)
	}
}

func TestAWSTeamLaunchAuthorizationBuilderRejectsUntrustedRuntimeOrAMI(
	t *testing.T,
) {
	t.Parallel()
	tests := []struct {
		name     string
		release  func(*testing.T, teamplan.Plan) workerrelease.ReleaseV1
		runtimeE error
	}{
		{
			name: "runtime catalog lacks V2 launch evidence",
			release: func(
				t *testing.T,
				plan teamplan.Plan,
			) workerrelease.ReleaseV1 {
				return teamLaunchWorkerReleaseFixture(t, plan)
			},
			runtimeE: teamplan.ErrNoRuntime,
		},
		{
			name: "stored Worker publication was changed",
			release: func(
				t *testing.T,
				plan teamplan.Plan,
			) workerrelease.ReleaseV1 {
				release := teamLaunchWorkerReleaseFixture(t, plan)
				release.ImageID = "ami-0fedcba9876543210"
				return release
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			plan := teamLaunchPlanFixture(t)
			builder, err := newAWSTeamLaunchAuthorizationBuilder(
				teamLaunchTestAgentID,
				teamLaunchTestEndpoint,
				&teamLaunchConnectionFixtureReader{
					connection: teamLaunchConnectionFixture(plan),
				},
				&teamLaunchPlacementFixture{
					placement: teamLaunchPlacementResult(plan.Region),
				},
				&teamLaunchReleaseFixture{
					release: test.release(t, plan),
				},
				&teamLaunchRuntimeFixture{
					evidence: teamplan.RuntimeLaunchEvidence{
						InstallationManifestDigest: teamLaunchTestDigest("8"),
						ExecutableDigest:           teamLaunchTestDigest("7"),
					},
					err: test.runtimeE,
				},
			)
			if err != nil {
				t.Fatal(err)
			}
			_, err = builder.BuildForPlan(
				context.Background(),
				plan,
				"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
				plan.QuotedAt.Add(2*time.Minute),
			)
			if !errors.Is(
				err,
				teamorchestration.ErrLaunchAuthorizationUnavailable,
			) {
				t.Fatalf("untrusted launch evidence error = %v", err)
			}
		})
	}
}

type teamLaunchConnectionFixtureReader struct {
	connection cloudapp.Connection
	err        error
	calls      int
}

func (fixture *teamLaunchConnectionFixtureReader) LoadConnection(
	context.Context,
	string,
	string,
) (cloudapp.Connection, error) {
	fixture.calls++
	return fixture.connection, fixture.err
}

type teamLaunchPlacementFixture struct {
	placement  awsprovider.ExactPlacementV1
	err        error
	calls      int
	connection cloudapp.Connection
	request    cloudapp.ActiveExactPlacementRequestV1
}

func (fixture *teamLaunchPlacementFixture) ResolveExact(
	_ context.Context,
	connection cloudapp.Connection,
	request cloudapp.ActiveExactPlacementRequestV1,
) (awsprovider.ExactPlacementV1, error) {
	fixture.calls++
	fixture.connection = connection
	fixture.request = request
	return fixture.placement, fixture.err
}

type teamLaunchReleaseFixture struct {
	release         workerrelease.ReleaseV1
	err             error
	calls           int
	agentInstanceID string
	accountID       string
	region          string
	architecture    recipe.Architecture
}

func (fixture *teamLaunchReleaseFixture) ResolveActiveWorkerRelease(
	_ context.Context,
	agentInstanceID,
	accountID,
	region string,
	architecture recipe.Architecture,
) (workerrelease.ReleaseV1, error) {
	fixture.calls++
	fixture.agentInstanceID = agentInstanceID
	fixture.accountID = accountID
	fixture.region = region
	fixture.architecture = architecture
	return fixture.release, fixture.err
}

type teamLaunchRuntimeFixture struct {
	evidence   teamplan.RuntimeLaunchEvidence
	err        error
	calls      int
	releaseID  string
	assignment teamplan.WorkerAssignment
}

func (fixture *teamLaunchRuntimeFixture) ResolveAssignmentLaunchEvidence(
	assignment teamplan.WorkerAssignment,
) (teamplan.RuntimeLaunchEvidence, error) {
	fixture.calls++
	fixture.releaseID = assignment.RuntimeReleaseID
	fixture.assignment = assignment
	return fixture.evidence, fixture.err
}

func teamLaunchConnectionFixture(plan teamplan.Plan) cloudapp.Connection {
	return cloudapp.Connection{
		ConnectionID: plan.ProviderScope.ConnectionID,
		OwnerID:      plan.OwnerID,
		AccountID:    plan.ProviderScope.AccountID,
		Region:       plan.Region,
		Status:       "active",
		Revision:     int64(plan.ProviderScope.ConnectionRevision),
	}
}

func teamLaunchPlacementResult(region string) awsprovider.ExactPlacementV1 {
	return awsprovider.ExactPlacementV1{
		Region:           region,
		AvailabilityZone: region + "a",
		Network: cloudquote.NetworkScopeV1{
			VPCID:                "vpc-0123456789abcdef0",
			SubnetID:             "subnet-0123456789abcdef0",
			SecurityGroupMode:    cloudquote.SecurityGroupCreateDedicated,
			PublicIPv4:           true,
			EntryPoint:           cloudquote.EntryPointNone,
			ControlPlaneEndpoint: teamLaunchTestEndpoint,
			PrivateConnectivity: cloudquote.
				PrivateConnectivityDirectPublicTLSV1,
		},
	}
}

func teamLaunchPlanFixture(t *testing.T) teamplan.Plan {
	t.Helper()
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
		RuntimeImageDigest: teamLaunchTestDigest("1"),
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
	plan := teamplan.Plan{
		SchemaVersion: teamplan.SchemaV1,
		PlanID:        "33333333-3333-4333-8333-333333333333",
		Revision:      1,
		OwnerID:       "owner-team-launch",
		GoalDigest:    teamLaunchTestDigest("2"),
		ProviderScope: teamplan.ProviderScope{
			Provider:           teamplan.CloudProviderAWS,
			ConnectionID:       "55555555-5555-4555-8555-555555555555",
			ConnectionRevision: 11,
			AccountID:          "123456789012",
		},
		Region:                "us-east-1",
		CatalogRevision:       teamLaunchTestDigest("3"),
		PolicyRevision:        teamLaunchTestDigest("5"),
		PricingSnapshotID:     "44444444-4444-4444-8444-444444444444",
		PricingSnapshotDigest: teamLaunchTestDigest("4"),
		QuotedAt:              quotedAt,
		ValidUntil:            quotedAt.Add(30 * time.Minute),
		ProposalConfidence:    85,
		ProposalRationale: "One isolated implementation Worker " +
			"is sufficient.",
		WorkerCount:          1,
		MaxConcurrentWorkers: 1,
		Assignments:          []teamplan.WorkerAssignment{assignment},
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
	if err := plan.Validate(); err != nil {
		t.Fatalf("invalid Team launch Plan fixture: %v", err)
	}
	return plan
}

func teamLaunchWorkerReleaseFixture(
	t *testing.T,
	plan teamplan.Plan,
) workerrelease.ReleaseV1 {
	t.Helper()
	image := workerami.ImageManifestV1{
		SchemaVersion:         workerami.ImageManifestSchemaV1,
		AgentInstanceID:       teamLaunchTestAgentID,
		ImageID:               "ami-0123456789abcdef0",
		ImageName:             "dtx-worker-ami-0123456789abcdef0123",
		RootSnapshotID:        "snap-0123456789abcdef0",
		AccountID:             plan.ProviderScope.AccountID,
		Region:                plan.Region,
		Architecture:          "amd64",
		BaseAMIID:             "ami-0abcdef0123456789",
		BaseAMIOwnerID:        "099720109477",
		RootDeviceName:        "/dev/sda1",
		ReleaseManifestDigest: teamLaunchTestDigest("a"),
		WorkerRootFSDigest:    teamLaunchTestDigest("b"),
		WorkerBinaryDigest:    teamLaunchTestDigest("c"),
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
		ObservedAt: time.Date(
			2026,
			7,
			30,
			8,
			1,
			0,
			0,
			time.UTC,
		),
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

func teamLaunchTestDigest(fill string) string {
	return "sha256:" + strings.Repeat(fill, 64)
}
