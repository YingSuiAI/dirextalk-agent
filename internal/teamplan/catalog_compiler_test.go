package teamplan

import (
	"errors"
	"strings"
	"testing"
	"time"

	workerprotocol "github.com/YingSuiAI/dirextalk-agent/sdk/workerprotocol/v1"
)

func TestCatalogCompilerInjectsVerifiedCatalogAndRechecksPlan(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, validRuntimeCatalogPayload(publicKey), privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCatalogCompiler(catalog)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	plan, err := compiler.Compile(request)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if plan.CatalogRevision != catalog.Revision() ||
		compiler.CatalogRevision() != catalog.Revision() {
		t.Fatalf(
			"catalog revisions = plan:%q compiler:%q catalog:%q",
			plan.CatalogRevision,
			compiler.CatalogRevision(),
			catalog.Revision(),
		)
	}
	if err := compiler.VerifyPlan(
		plan,
		request.Offers,
		request.Policy,
		request.CompileTime,
	); err != nil {
		t.Fatalf("VerifyPlan() error = %v", err)
	}
	profiles, err := compiler.PlanningProfiles()
	if err != nil || len(profiles) != len(catalog.QualifiedReleases()) {
		t.Fatalf("PlanningProfiles() = %#v, %v", profiles, err)
	}
	if len(profiles[0].Capabilities) == 0 || len(profiles[0].WorkClasses) == 0 {
		t.Fatalf("planning profile omitted the execution surface: %#v", profiles[0])
	}
	originalCapability := profiles[0].Capabilities[0]
	profiles[0].Capabilities[0] = CapabilityDocument
	reloaded, err := compiler.PlanningProfiles()
	if err != nil || reloaded[0].Capabilities[0] != originalCapability {
		t.Fatalf("planning profiles leaked mutable catalog state: %#v, %v", reloaded, err)
	}

	tampered := plan
	tampered.Assignments = append(
		[]WorkerAssignment(nil),
		plan.Assignments...,
	)
	tampered.Assignments[0].RuntimeImageDigest =
		"sha256:" + strings.Repeat("f", 64)
	if err := compiler.VerifyPlan(
		tampered,
		request.Offers,
		request.Policy,
		request.CompileTime,
	); !errors.Is(err, ErrCatalogChanged) {
		t.Fatalf("tampered VerifyPlan() error = %v, want ErrCatalogChanged", err)
	}
}

func TestCatalogCompilerRejectsPlanFromSupersededCatalog(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	firstPayload := validRuntimeCatalogPayload(publicKey)
	firstCatalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, firstPayload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	firstCompiler, err := NewCatalogCompiler(firstCatalog)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	plan, err := firstCompiler.Compile(request)
	if err != nil {
		t.Fatal(err)
	}

	secondPayload := validRuntimeCatalogPayload(publicKey)
	secondPayload.GeneratedAt = secondPayload.GeneratedAt.Add(time.Minute)
	secondPayload.Releases[0].ImageDigest =
		"sha256:" + strings.Repeat("f", 64)
	secondCatalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, secondPayload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	secondCompiler, err := NewCatalogCompiler(secondCatalog)
	if err != nil {
		t.Fatal(err)
	}
	if secondCompiler.CatalogRevision() == firstCompiler.CatalogRevision() {
		t.Fatal("catalog mutation did not change revision")
	}
	if err := secondCompiler.VerifyPlan(
		plan,
		request.Offers,
		request.Policy,
		request.CompileTime,
	); !errors.Is(
		err,
		ErrCatalogChanged,
	) {
		t.Fatalf("superseded VerifyPlan() error = %v, want ErrCatalogChanged", err)
	}
}

func TestNewCatalogCompilerRejectsMissingCatalog(t *testing.T) {
	t.Parallel()
	if _, err := NewCatalogCompiler(nil); !errors.Is(err, ErrInvalid) {
		t.Fatalf("NewCatalogCompiler(nil) error = %v, want ErrInvalid", err)
	}
	var compiler *CatalogCompiler
	if _, err := compiler.Compile(CatalogCompileRequest{}); !errors.Is(
		err,
		ErrInvalid,
	) {
		t.Fatalf("nil Compile() error = %v, want ErrInvalid", err)
	}
}

func TestCatalogCompilerReportsCatalogWithoutQualifiedRelease(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	payload := validRuntimeCatalogPayload(publicKey)
	for index := range payload.Releases {
		payload.Releases[index].Trust = RuntimeTrustCandidate
		payload.Releases[index].Qualification = nil
	}
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, payload, privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCatalogCompiler(catalog)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	if _, err := compiler.Compile(request); !errors.Is(err, ErrNoRuntime) {
		t.Fatalf("Compile() error = %v, want ErrNoRuntime", err)
	}
}

func TestCatalogCompilerLimitsPlansToInstalledAdapters(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, validRuntimeCatalogPayload(publicKey), privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCatalogCompilerForAdapters(
		catalog,
		[]RuntimeAdapter{AdapterCodexV1},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	if _, err := compiler.Compile(request); !errors.Is(err, ErrNoRuntime) {
		t.Fatalf(
			"mixed-runtime Compile() error = %v, want ErrNoRuntime",
			err,
		)
	}

	request.Proposal.Roles = []RoleProposal{
		request.Proposal.Roles[0],
		request.Proposal.Roles[2],
	}
	request.Proposal.Roles[1].ModelNeed.MinimumQuality = QualityBalanced
	plan, err := compiler.Compile(request)
	if err != nil {
		t.Fatalf("Codex-only Compile() error = %v", err)
	}
	for _, assignment := range plan.Assignments {
		if assignment.RuntimeAdapter != AdapterCodexV1 ||
			assignment.RuntimeFamily != RuntimeCodex {
			t.Fatalf("unsupported assignment compiled: %#v", assignment)
		}
	}

	unrestricted, err := NewCatalogCompiler(catalog)
	if err != nil {
		t.Fatal(err)
	}
	mixedPlan, err := unrestricted.Compile(
		trustedCompileRequestFrom(t, validCompileRequest()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.VerifyPlan(
		mixedPlan,
		request.Offers,
		request.Policy,
		request.CompileTime,
	); !errors.Is(err, ErrCatalogChanged) {
		t.Fatalf(
			"unsupported VerifyPlan() error = %v, want ErrCatalogChanged",
			err,
		)
	}
}

func TestCatalogCompilerCompilesPiOnlyPlan(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(
			t,
			validRuntimeCatalogPayload(publicKey),
			privateKey,
		),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCatalogCompilerForAdapters(
		catalog,
		[]RuntimeAdapter{AdapterPiV1},
	)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	request.Proposal.Roles = []RoleProposal{request.Proposal.Roles[0]}
	request.Proposal.Roles[0].PreferredFamilies = []RuntimeFamily{
		RuntimePi,
	}
	request.Policy.AllowedRuntimeFamilies = []RuntimeFamily{RuntimePi}
	plan, err := compiler.Compile(request)
	if err != nil {
		t.Fatalf("Pi-only Compile() error = %v", err)
	}
	if len(plan.Assignments) != 1 ||
		plan.Assignments[0].RuntimeAdapter != AdapterPiV1 ||
		plan.Assignments[0].RuntimeFamily != RuntimePi ||
		plan.Assignments[0].RuntimeVersion != "0.83.0" {
		t.Fatalf("Pi assignment = %#v", plan.Assignments)
	}
}

func TestCatalogCompilerRejectsInvalidAdapterAllowlist(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, validRuntimeCatalogPayload(publicKey), privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, adapters := range [][]RuntimeAdapter{
		nil,
		{""},
		{AdapterCodexV1, AdapterCodexV1},
	} {
		if _, err := NewCatalogCompilerForAdapters(
			catalog,
			adapters,
		); !errors.Is(err, ErrInvalid) {
			t.Fatalf(
				"NewCatalogCompilerForAdapters(%v) error = %v",
				adapters,
				err,
			)
		}
	}
}

func TestCatalogCompilerBindsMarketplaceAndRechecksBeforeLaunch(
	t *testing.T,
) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(
			t,
			validRuntimeCatalogV2Payload(publicKey),
			privateKey,
		),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	gate := &marketplaceApprovalGateFixture{
		revision: "sha256:" + strings.Repeat("9", 64),
	}
	compiler, err := NewCatalogCompilerForMarketplace(
		catalog,
		[]RuntimeAdapter{
			AdapterClaudeCodeV1,
			AdapterCodexV1,
			AdapterOpenClawV1,
			AdapterHermesV1,
			AdapterOpenCodeV1,
		},
		gate,
		func() time.Time { return request.CompileTime },
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := compiler.Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	if compiler.CatalogRevision() == catalog.Revision() ||
		compiler.CatalogRevision() == gate.revision ||
		plan.CatalogRevision != compiler.CatalogRevision() ||
		gate.runtimeCalls == 0 ||
		gate.assignmentCalls != len(plan.Assignments) {
		t.Fatalf(
			"Marketplace binding revision=%q runtime=%d assignment=%d plan=%#v",
			compiler.CatalogRevision(),
			gate.runtimeCalls,
			gate.assignmentCalls,
			plan,
		)
	}
	if len(plan.Assignments) == 0 ||
		plan.Assignments[0].Marketplace == nil {
		t.Fatalf("compiled Plan omits Marketplace binding: %#v", plan)
	}
	originalDigest, err := plan.Digest()
	if err != nil {
		t.Fatal(err)
	}
	tampered := plan
	tampered.Assignments = append(
		[]WorkerAssignment(nil),
		plan.Assignments...,
	)
	changedBinding := tampered.Assignments[0].Marketplace.Clone()
	changedBinding.ManifestDigest =
		"sha256:" + strings.Repeat("3", 64)
	tampered.Assignments[0].Marketplace = &changedBinding
	tamperedDigest, err := tampered.Digest()
	if err != nil || tamperedDigest == originalDigest {
		t.Fatalf(
			"Marketplace substitution digest=%q original=%q error=%v",
			tamperedDigest,
			originalDigest,
			err,
		)
	}
	if err := compiler.VerifyPlan(
		tampered,
		request.Offers,
		request.Policy,
		request.CompileTime,
	); !errors.Is(err, ErrCatalogChanged) {
		t.Fatalf("Marketplace substitution VerifyPlan error=%v", err)
	}
	if err := compiler.VerifyPlan(
		plan,
		request.Offers,
		request.Policy,
		request.CompileTime,
	); err != nil {
		t.Fatal(err)
	}
	releaseID := plan.Assignments[0].RuntimeReleaseID
	if _, err := compiler.ResolveRuntimeLaunchEvidence(
		releaseID,
	); err != nil {
		t.Fatalf("approved launch evidence error=%v", err)
	}
	if _, err := compiler.ResolveAssignmentLaunchEvidence(
		plan.Assignments[0],
	); err != nil {
		t.Fatalf("approved assignment launch evidence error=%v", err)
	}
	if _, err := compiler.ResolveAssignmentLaunchEvidence(
		tampered.Assignments[0],
	); !errors.Is(err, ErrNoRuntime) {
		t.Fatalf(
			"substituted assignment launch evidence error=%v",
			err,
		)
	}

	gate.err = errors.New("release revoked")
	if err := compiler.VerifyPlan(
		plan,
		request.Offers,
		request.Policy,
		request.CompileTime,
	); !errors.Is(err, ErrCatalogChanged) {
		t.Fatalf("revoked VerifyPlan error=%v", err)
	}
	if _, err := compiler.ResolveRuntimeLaunchEvidence(
		releaseID,
	); !errors.Is(err, ErrNoRuntime) {
		t.Fatalf("revoked launch evidence error=%v", err)
	}
	if _, err := compiler.ResolveAssignmentLaunchEvidence(
		plan.Assignments[0],
	); !errors.Is(err, ErrNoRuntime) {
		t.Fatalf(
			"revoked assignment launch evidence error=%v",
			err,
		)
	}
}

func TestCatalogCompilerReportsUnavailableMarketplaceRegistry(
	t *testing.T,
) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(
			t,
			validRuntimeCatalogV2Payload(publicKey),
			privateKey,
		),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	gate := &marketplaceApprovalGateFixture{
		revision: "sha256:" + strings.Repeat("9", 64),
		err:      ErrRuntimeRegistryUnavailable,
	}
	compiler, err := NewCatalogCompilerForMarketplace(
		catalog,
		[]RuntimeAdapter{
			AdapterClaudeCodeV1,
			AdapterCodexV1,
			AdapterOpenClawV1,
			AdapterHermesV1,
			AdapterOpenCodeV1,
		},
		gate,
		func() time.Time { return request.CompileTime },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := compiler.Compile(request); !errors.Is(
		err,
		ErrRuntimeRegistryUnavailable,
	) {
		t.Fatalf("Compile() error=%v", err)
	}
}

func TestCatalogCompilerRejectsPricingMutationAndExpiry(t *testing.T) {
	t.Parallel()
	publicKey, privateKey := runtimeCatalogTestKey()
	catalog, err := ParseRuntimeCatalogJSON(
		signRuntimeCatalog(t, validRuntimeCatalogPayload(publicKey), privateKey),
		publicKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	compiler, err := NewCatalogCompiler(catalog)
	if err != nil {
		t.Fatal(err)
	}
	request := trustedCompileRequestFrom(t, validCompileRequest())
	plan, err := compiler.Compile(request)
	if err != nil {
		t.Fatal(err)
	}
	changedDocument := request.Offers.Document()
	changedDocument.ModelOffers[0].InputMicrosPerMillion++
	changedOffers, err := NewOfferSnapshot(changedDocument)
	if err != nil {
		t.Fatal(err)
	}
	if err := compiler.VerifyPlan(
		plan,
		changedOffers,
		request.Policy,
		request.CompileTime,
	); !errors.Is(err, ErrPricingChanged) {
		t.Fatalf("changed pricing VerifyPlan() error = %v, want ErrPricingChanged", err)
	}
	changedPlan := plan
	changedPlan.ProviderScope.ConnectionRevision++
	if err := compiler.VerifyPlan(
		changedPlan,
		request.Offers,
		request.Policy,
		request.CompileTime,
	); !errors.Is(err, ErrPricingChanged) {
		t.Fatalf("scope drift VerifyPlan() error = %v, want ErrPricingChanged", err)
	}
	request.CompileTime = request.Offers.ValidUntil()
	if _, err := compiler.Compile(request); !errors.Is(err, ErrPricingExpired) {
		t.Fatalf("expired Compile() error = %v, want ErrPricingExpired", err)
	}
}

type marketplaceApprovalGateFixture struct {
	revision        string
	err             error
	runtimeCalls    int
	assignmentCalls int
}

func (gate *marketplaceApprovalGateFixture) Revision() string {
	return gate.revision
}

func (gate *marketplaceApprovalGateFixture) VerifyRuntime(
	RuntimeRelease,
	time.Time,
) error {
	gate.runtimeCalls++
	return gate.err
}

func (gate *marketplaceApprovalGateFixture) VerifyAssignment(
	runtime RuntimeRelease,
	assignment WorkerAssignment,
	at time.Time,
) error {
	gate.assignmentCalls++
	if gate.err != nil {
		return gate.err
	}
	expected, err := gate.BindAssignment(runtime, assignment, at)
	if err != nil ||
		assignment.Marketplace == nil ||
		!expected.Equal(*assignment.Marketplace) {
		return errors.New("marketplace binding changed")
	}
	return nil
}

func (gate *marketplaceApprovalGateFixture) BindAssignment(
	runtime RuntimeRelease,
	assignment WorkerAssignment,
	at time.Time,
) (WorkerMarketplaceBindingV1, error) {
	if gate.err != nil {
		return WorkerMarketplaceBindingV1{}, gate.err
	}
	workspace := workerprotocol.WorkspaceIsolated
	if assignment.Workspace == WorkspaceReadOnly {
		workspace = workerprotocol.WorkspaceReadOnly
	}
	return WorkerMarketplaceBindingV1{
		SchemaVersion:            WorkerMarketplaceBindingSchemaV1,
		RegistryID:               "99999999-9999-4999-8999-999999999999",
		RegistryRevision:         gate.revision,
		ReleaseID:                runtime.ReleaseID,
		WorkerTypeID:             "88888888-8888-4888-8888-888888888888",
		PublisherID:              "77777777-7777-4777-8777-777777777777",
		PublisherDisplayName:     "Verified Worker Publisher",
		PublisherTier:            "verified_partner",
		ManifestDigest:           "sha256:" + strings.Repeat("8", 64),
		ImageRepository:          "public.ecr.aws/dirextalk/workers/test",
		ImageDigest:              runtime.ImageDigest,
		ImageSignatureDigest:     "sha256:" + strings.Repeat("7", 64),
		SBOMDigest:               "sha256:" + strings.Repeat("6", 64),
		ProvenanceEnvelopeDigest: "sha256:" + strings.Repeat("5", 64),
		ReviewID:                 "66666666-6666-4666-8666-666666666666",
		ReviewPolicyRevision:     "sha256:" + strings.Repeat("4", 64),
		ReviewRiskClass:          "moderate",
		ReviewValidUntil:         at.UTC().Truncate(time.Second).Add(24 * time.Hour),
		GrantedPermissions: workerprotocol.PermissionSetV1{
			Workspace: workspace,
			NetworkServices: []workerprotocol.NetworkService{
				workerprotocol.NetworkArtifactStore,
				workerprotocol.NetworkControlPlane,
				workerprotocol.NetworkModelGateway,
			},
			ToolScopes:     []string{"task.execute"},
			MaxTempDiskMiB: 1024,
		},
	}, nil
}

func trustedCompileRequestFrom(
	t *testing.T,
	request CompileRequest,
) CatalogCompileRequest {
	t.Helper()
	return CatalogCompileRequest{
		PlanID: request.PlanID, Revision: request.Revision,
		OwnerID: request.OwnerID, GoalDigest: request.GoalDigest,
		TaskInput: request.TaskInput,
		Proposal:  request.Proposal, Policy: request.Policy,
		Offers:      validOfferSnapshot(t, request),
		CompileTime: request.QuotedAt.Add(time.Minute),
	}
}

func validOfferSnapshot(
	t *testing.T,
	request CompileRequest,
) *OfferSnapshot {
	t.Helper()
	snapshot, err := NewOfferSnapshot(OfferSnapshotDocument{
		SchemaVersion: OfferSnapshotSchemaV1,
		SnapshotID:    request.PricingSnapshotID,
		ProviderScope: request.ProviderScope,
		Region:        request.Region, Currency: request.Currency,
		CapturedAt: request.QuotedAt, ValidUntil: request.ValidUntil,
		Sources: []OfferSourceReceipt{
			{
				Kind:       OfferSourceModelPricing,
				SourceID:   "model-catalog-v1",
				Digest:     "sha256:" + strings.Repeat("4", 64),
				CapturedAt: request.QuotedAt.Add(-time.Hour),
			},
			{
				Kind:       OfferSourceComputePricing,
				SourceID:   "aws-price-list-ap-southeast-3",
				Digest:     "sha256:" + strings.Repeat("5", 64),
				CapturedAt: request.QuotedAt,
			},
			{
				Kind:       OfferSourceComputeCapacity,
				SourceID:   "aws-ec2-offerings-ap-southeast-3",
				Digest:     "sha256:" + strings.Repeat("6", 64),
				CapturedAt: request.QuotedAt,
			},
			{
				Kind:       OfferSourceComputeConfig,
				SourceID:   "agent-team-compute-catalog:ap-southeast-3:v1",
				Digest:     "sha256:" + strings.Repeat("7", 64),
				CapturedAt: request.QuotedAt,
			},
		},
		ModelOffers:   request.ModelOffers,
		ComputeOffers: request.ComputeOffers,
	})
	if err != nil {
		t.Fatalf("NewOfferSnapshot() error = %v", err)
	}
	return snapshot
}
