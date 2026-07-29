package teamorchestration

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamapproval"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

func TestServiceGatesPlanChallengeApprovalAndExecution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	offers := orchestrationOfferFixture(t, now)
	policy := orchestrationPolicyFixture()
	repository := newOrchestrationRepositoryFixture()
	compiler := &orchestrationCompilerFixture{
		revision: "sha256:" + strings.Repeat("c", 64),
	}
	resolver := &orchestrationPolicyResolverFixture{policy: policy}
	service, err := NewService(
		compiler,
		resolver,
		repository,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	offerBuilder := &orchestrationOfferBuilderFixture{offers: offers}
	preparation, err := NewPreparationService(service, offerBuilder)
	if err != nil {
		t.Fatal(err)
	}
	scope := task.MutationScope{
		ClientID:     "team-orchestration-test",
		CredentialID: uuid.NewString(),
	}
	request := PreparePlanRequest{
		IdempotencyKey: uuid.NewString(),
		OwnerID:        "owner-team",
		ConnectionID:   offers.ProviderScope().ConnectionID,
		PlanID:         uuid.NewString(),
		Revision:       1,
		GoalDigest:     "sha256:" + strings.Repeat("d", 64),
		Proposal:       orchestrationProposalFixture(),
	}
	planFact, err := preparation.PreparePlan(
		context.Background(),
		scope,
		request,
	)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if planFact.Status != PlanReadyForConfirmation ||
		planFact.Plan.PolicyRevision != policyDigest ||
		compiler.compileCalls != 1 ||
		compiler.verifyCalls != 1 ||
		resolver.calls != 1 ||
		offerBuilder.calls != 1 ||
		offerBuilder.ownerID != request.OwnerID ||
		offerBuilder.connectionID != request.ConnectionID ||
		repository.findCalls != 1 ||
		repository.prepareCalls != 1 ||
		repository.prepareKey != request.IdempotencyKey {
		t.Fatalf(
			"prepared=%#v compiler=%d/%d policy=%d offers=%d/%q/%q repository=%d/%d key=%q",
			planFact,
			compiler.compileCalls,
			compiler.verifyCalls,
			resolver.calls,
			offerBuilder.calls,
			offerBuilder.ownerID,
			offerBuilder.connectionID,
			repository.findCalls,
			repository.prepareCalls,
			repository.prepareKey,
		)
	}
	replayedPlan, err := preparation.PreparePlan(
		context.Background(),
		scope,
		request,
	)
	if err != nil ||
		replayedPlan.PlanDigest != planFact.PlanDigest ||
		compiler.compileCalls != 1 ||
		compiler.verifyCalls != 1 ||
		resolver.calls != 1 ||
		offerBuilder.calls != 1 ||
		repository.findCalls != 2 ||
		repository.prepareCalls != 1 {
		t.Fatalf(
			"replayed=%#v error=%v compiler=%d/%d policy=%d offers=%d repository=%d/%d",
			replayedPlan,
			err,
			compiler.compileCalls,
			compiler.verifyCalls,
			resolver.calls,
			offerBuilder.calls,
			repository.findCalls,
			repository.prepareCalls,
		)
	}
	changedConnection := request
	changedConnection.ConnectionID = uuid.NewString()
	if _, err := preparation.PreparePlan(
		context.Background(),
		scope,
		changedConnection,
	); !errors.Is(err, ErrFactMismatch) ||
		offerBuilder.calls != 1 ||
		compiler.compileCalls != 1 ||
		repository.prepareCalls != 1 {
		t.Fatalf(
			"changed Connection error=%v offers=%d compiler=%d prepare=%d",
			err,
			offerBuilder.calls,
			compiler.compileCalls,
			repository.prepareCalls,
		)
	}
	if _, err := service.VerifyApprovedPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	); !errors.Is(err, ErrNotReady) {
		t.Fatalf("unapproved execution verification error=%v", err)
	}

	challengeRequest := ChallengeRequest{
		IdempotencyKey:             uuid.NewString(),
		OwnerID:                    request.OwnerID,
		PlanID:                     request.PlanID,
		PlanRevision:               1,
		ExpectedPlanRecordRevision: 1,
		ApprovalID:                 uuid.NewString(),
		ChallengeID:                uuid.NewString(),
		SignerKeyID:                "team-device-1",
	}
	compiler.verifyErr = teamplan.ErrPolicyChanged
	if _, err := service.CreateChallenge(
		context.Background(),
		scope,
		challengeRequest,
	); !errors.Is(err, teamplan.ErrPolicyChanged) ||
		repository.challengeCalls != 0 {
		t.Fatalf(
			"policy-drift challenge error=%v calls=%d",
			err,
			repository.challengeCalls,
		)
	}
	compiler.verifyErr = nil
	challengeFact, err := service.CreateChallenge(
		context.Background(),
		scope,
		challengeRequest,
	)
	if err != nil {
		t.Fatal(err)
	}
	if challengeFact.Challenge.PolicyRevision != policyDigest ||
		repository.challengeCalls != 1 {
		t.Fatalf("challenge=%#v calls=%d", challengeFact, repository.challengeCalls)
	}
	signature := teamapproval.SignatureV1{
		SchemaVersion: teamapproval.SignatureSchemaV1,
		ApprovalID:    challengeFact.Challenge.ApprovalID,
		ChallengeID:   challengeFact.Challenge.ChallengeID,
		PlanID:        challengeFact.Challenge.PlanID,
		PlanRevision:  challengeFact.Challenge.PlanRevision,
		PlanDigest:    challengeFact.Challenge.PlanDigest,
		SignerKeyID:   challengeFact.Challenge.SignerKeyID,
		SignatureBase64URL: strings.Repeat(
			"A",
			86,
		),
	}
	resolver.policy.FixedWorkerOverheadMicros++
	if _, err := service.ApprovePlan(
		context.Background(),
		scope,
		ApprovalRequest{
			IdempotencyKey:                  uuid.NewString(),
			OwnerID:                         request.OwnerID,
			ExpectedPlanRecordRevision:      1,
			ExpectedChallengeRecordRevision: 1,
			Signature:                       signature,
		},
	); !errors.Is(err, teamplan.ErrPolicyChanged) ||
		repository.approvalCalls != 0 {
		t.Fatalf(
			"changed-policy approval error=%v calls=%d",
			err,
			repository.approvalCalls,
		)
	}
	resolver.policy = policy
	approved, err := service.ApprovePlan(
		context.Background(),
		scope,
		ApprovalRequest{
			IdempotencyKey:                  uuid.NewString(),
			OwnerID:                         request.OwnerID,
			ExpectedPlanRecordRevision:      1,
			ExpectedChallengeRecordRevision: 1,
			Signature:                       signature,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if approved.Status != PlanApproved ||
		approved.RecordRevision != 2 ||
		repository.approvalCalls != 1 {
		t.Fatalf("approved=%#v calls=%d", approved, repository.approvalCalls)
	}
	validApproval := repository.approval
	repository.approval.Signature.PlanDigest = "sha256:" +
		strings.Repeat("f", 64)
	if _, err := service.VerifyApprovedPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	); !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("substituted approval verification error=%v", err)
	}
	repository.approval = validApproval
	repository.connectionErr = ErrFactMismatch
	if _, err := service.VerifyApprovedPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	); !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("changed Connection verification error=%v", err)
	}
	repository.connectionErr = nil
	verified, err := service.VerifyApprovedPlan(
		context.Background(),
		request.OwnerID,
		request.PlanID,
		1,
	)
	if err != nil ||
		verified.PlanDigest != approved.PlanDigest {
		t.Fatalf("execution verification=%#v error=%v", verified, err)
	}
}

func TestPreparationServiceRejectsOfferForAnotherConnection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	offers := orchestrationOfferFixture(t, now)
	compiler := &orchestrationCompilerFixture{
		revision: "sha256:" + strings.Repeat("c", 64),
	}
	repository := newOrchestrationRepositoryFixture()
	plans, err := NewService(
		compiler,
		&orchestrationPolicyResolverFixture{
			policy: orchestrationPolicyFixture(),
		},
		repository,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	builder := &orchestrationOfferBuilderFixture{offers: offers}
	service, err := NewPreparationService(plans, builder)
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.PreparePlan(
		context.Background(),
		task.MutationScope{
			ClientID:     "team-orchestration-test",
			CredentialID: uuid.NewString(),
		},
		PreparePlanRequest{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        "owner-team",
			ConnectionID:   uuid.NewString(),
			PlanID:         uuid.NewString(),
			Revision:       1,
			GoalDigest:     "sha256:" + strings.Repeat("d", 64),
			Proposal:       orchestrationProposalFixture(),
		},
	)
	if !errors.Is(err, ErrFactMismatch) ||
		builder.calls != 1 ||
		compiler.compileCalls != 0 ||
		repository.prepareCalls != 0 {
		t.Fatalf(
			"substituted offer error=%v builder=%d compile=%d prepare=%d",
			err,
			builder.calls,
			compiler.compileCalls,
			repository.prepareCalls,
		)
	}
}

func TestPreparePlanRejectsRepositoryFactSubstitution(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 29, 12, 0, 0, 0, time.UTC)
	repository := newOrchestrationRepositoryFixture()
	repository.tamperPlan = true
	service, err := NewService(
		&orchestrationCompilerFixture{
			revision: "sha256:" + strings.Repeat("c", 64),
		},
		&orchestrationPolicyResolverFixture{
			policy: orchestrationPolicyFixture(),
		},
		repository,
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	offers := orchestrationOfferFixture(t, now)
	preparation, err := NewPreparationService(
		service,
		&orchestrationOfferBuilderFixture{offers: offers},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = preparation.PreparePlan(
		context.Background(),
		task.MutationScope{
			ClientID:     "team-orchestration-test",
			CredentialID: uuid.NewString(),
		},
		PreparePlanRequest{
			IdempotencyKey: uuid.NewString(),
			OwnerID:        "owner-team",
			ConnectionID:   offers.ProviderScope().ConnectionID,
			PlanID:         uuid.NewString(),
			Revision:       1,
			GoalDigest:     "sha256:" + strings.Repeat("d", 64),
			Proposal:       orchestrationProposalFixture(),
		},
	)
	if !errors.Is(err, ErrFactMismatch) {
		t.Fatalf("PreparePlan() error = %v, want ErrFactMismatch", err)
	}
}

type orchestrationCompilerFixture struct {
	revision     string
	compileCalls int
	verifyCalls  int
	verifyErr    error
}

func (compiler *orchestrationCompilerFixture) CatalogRevision() string {
	return compiler.revision
}

func (compiler *orchestrationCompilerFixture) Compile(
	request teamplan.CatalogCompileRequest,
) (teamplan.Plan, error) {
	compiler.compileCalls++
	return orchestrationPlanFixture(request, compiler.revision)
}

func (compiler *orchestrationCompilerFixture) VerifyPlan(
	plan teamplan.Plan,
	offers *teamplan.OfferSnapshot,
	policy teamplan.Policy,
	now time.Time,
) error {
	compiler.verifyCalls++
	if compiler.verifyErr != nil {
		return compiler.verifyErr
	}
	digest, err := policy.Digest()
	if err != nil {
		return err
	}
	if plan.PolicyRevision != digest {
		return teamplan.ErrPolicyChanged
	}
	if offers == nil ||
		plan.CatalogRevision != compiler.revision ||
		plan.PricingSnapshotDigest != offers.Digest() ||
		now.IsZero() {
		return ErrFactMismatch
	}
	return nil
}

type orchestrationPolicyResolverFixture struct {
	policy teamplan.Policy
	calls  int
}

func (resolver *orchestrationPolicyResolverFixture) ResolveTeamPolicy(
	_ context.Context,
	_ string,
) (teamplan.Policy, error) {
	resolver.calls++
	return resolver.policy, nil
}

type orchestrationRepositoryFixture struct {
	offer           OfferFact
	plan            PlanFact
	prepareKey      string
	connectionID    string
	findCalls       int
	prepareCalls    int
	challengeCalls  int
	approvalCalls   int
	connectionCalls int
	connectionErr   error
	tamperPlan      bool
	approval        ApprovalFact
}

func (repository *orchestrationRepositoryFixture) VerifyConnectionScope(
	_ context.Context,
	ownerID string,
	scope teamplan.ProviderScope,
	region string,
) error {
	repository.connectionCalls++
	if repository.connectionErr != nil {
		return repository.connectionErr
	}
	if ownerID != repository.plan.Plan.OwnerID ||
		scope != repository.plan.Plan.ProviderScope ||
		region != repository.plan.Plan.Region {
		return ErrFactMismatch
	}
	return nil
}

func newOrchestrationRepositoryFixture() *orchestrationRepositoryFixture {
	return &orchestrationRepositoryFixture{}
}

func (repository *orchestrationRepositoryFixture) FindPreparedPlan(
	_ context.Context,
	_ task.MutationScope,
	command FindPreparedPlanCommand,
) (PreparedPlanFact, bool, error) {
	repository.findCalls++
	if repository.plan.RecordRevision == 0 {
		return PreparedPlanFact{}, false, nil
	}
	if command.IdempotencyKey != repository.prepareKey ||
		command.Intent.OwnerID != repository.plan.Plan.OwnerID ||
		command.Intent.ConnectionID != repository.connectionID ||
		command.Intent.PlanID != repository.plan.Plan.PlanID ||
		command.Intent.Revision != repository.plan.Plan.Revision {
		return PreparedPlanFact{}, false, ErrFactMismatch
	}
	return PreparedPlanFact{
		Offer:    repository.offer,
		Plan:     repository.plan,
		Replayed: true,
	}, true, nil
}

func (repository *orchestrationRepositoryFixture) PersistPreparedPlan(
	_ context.Context,
	_ task.MutationScope,
	command PersistPreparedPlanCommand,
) (PreparedPlanFact, error) {
	repository.prepareCalls++
	repository.prepareKey = command.IdempotencyKey
	repository.connectionID = command.Intent.ConnectionID
	repository.offer = OfferFact{
		OwnerID:  command.Intent.OwnerID,
		Document: command.Offers.Document(),
		Digest:   command.Offers.Digest(),
		CreatedAt: command.Offers.
			CapturedAt(),
	}
	digest, err := command.Plan.Digest()
	if err != nil {
		return PreparedPlanFact{}, err
	}
	repository.plan = PlanFact{
		TaskID:         command.Intent.TaskID,
		Plan:           command.Plan,
		PlanDigest:     digest,
		Status:         PlanReadyForConfirmation,
		RecordRevision: 1,
		CreatedAt:      command.Plan.QuotedAt,
		UpdatedAt:      command.Plan.QuotedAt,
	}
	result := repository.plan
	if repository.tamperPlan {
		result.Plan.Assignments = append(
			[]teamplan.WorkerAssignment(nil),
			result.Plan.Assignments...,
		)
		result.Plan.Assignments[0].Objective = "substituted objective"
	}
	return PreparedPlanFact{
		Offer: repository.offer,
		Plan:  result,
	}, nil
}

type orchestrationOfferBuilderFixture struct {
	offers       *teamplan.OfferSnapshot
	err          error
	calls        int
	ownerID      string
	connectionID string
}

func (builder *orchestrationOfferBuilderFixture) BuildForConnection(
	_ context.Context,
	ownerID,
	connectionID string,
) (*teamplan.OfferSnapshot, error) {
	builder.calls++
	builder.ownerID = ownerID
	builder.connectionID = connectionID
	return builder.offers, builder.err
}

func (repository *orchestrationRepositoryFixture) GetOffer(
	_ context.Context,
	ownerID,
	snapshotID string,
) (OfferFact, error) {
	if repository.offer.OwnerID != ownerID ||
		repository.offer.Document.SnapshotID != snapshotID {
		return OfferFact{}, ErrFactMismatch
	}
	return repository.offer, nil
}

func (repository *orchestrationRepositoryFixture) GetPlan(
	_ context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (PlanFact, error) {
	if repository.plan.Plan.OwnerID != ownerID ||
		repository.plan.Plan.PlanID != planID ||
		repository.plan.Plan.Revision != planRevision {
		return PlanFact{}, ErrFactMismatch
	}
	return repository.plan, nil
}

func (repository *orchestrationRepositoryFixture) PersistChallenge(
	_ context.Context,
	_ task.MutationScope,
	command PersistChallengeCommand,
) (ChallengeFact, error) {
	repository.challengeCalls++
	challenge, err := teamapproval.NewChallengeV1(
		repository.plan.Plan,
		"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		command.ApprovalID,
		command.ChallengeID,
		command.SignerKeyID,
		repository.plan.Plan.QuotedAt.Add(time.Minute),
	)
	if err != nil {
		return ChallengeFact{}, err
	}
	return ChallengeFact{
		Challenge:      challenge,
		RecordRevision: 1,
		CreatedAt:      challenge.IssuedAt,
		UpdatedAt:      challenge.IssuedAt,
	}, nil
}

func (repository *orchestrationRepositoryFixture) PersistApproval(
	_ context.Context,
	_ task.MutationScope,
	command PersistApprovalCommand,
) (PlanFact, error) {
	repository.approvalCalls++
	repository.approval = ApprovalFact{
		Signature:  command.Signature,
		ApprovedAt: repository.plan.Plan.QuotedAt.Add(2 * time.Minute),
		CreatedAt:  repository.plan.Plan.QuotedAt.Add(2 * time.Minute),
	}
	repository.plan.Status = PlanApproved
	repository.plan.RecordRevision++
	repository.plan.UpdatedAt = repository.plan.UpdatedAt.Add(time.Second)
	return repository.plan, nil
}

func (repository *orchestrationRepositoryFixture) GetApprovalForPlan(
	_ context.Context,
	ownerID,
	planID string,
	planRevision uint64,
) (ApprovalFact, error) {
	if repository.plan.Plan.OwnerID != ownerID ||
		repository.approval.Signature.PlanID != planID ||
		repository.approval.Signature.PlanRevision != planRevision {
		return ApprovalFact{}, ErrFactMismatch
	}
	return repository.approval, nil
}

func orchestrationPolicyFixture() teamplan.Policy {
	return teamplan.Policy{
		MaxWorkers:                1,
		MaxConcurrentWorkers:      1,
		MaxRoleDuration:           3 * time.Minute,
		MaxVCPUPerWorker:          2,
		MaxMemoryMiBPerWorker:     8192,
		MaxDiskGiBPerWorker:       40,
		MaxPlanCostMicros:         1_000_000,
		SafetyMarginBasisPoints:   2000,
		FixedWorkerOverheadMicros: 10_000,
		AllowedRuntimeFamilies: []teamplan.RuntimeFamily{
			teamplan.RuntimeCodex,
		},
	}
}

func orchestrationProposalFixture() teamplan.TeamProposal {
	return teamplan.TeamProposal{
		Confidence: 90,
		Rationale:  "One isolated implementation Worker is sufficient.",
		Roles: []teamplan.RoleProposal{{
			RoleID:    "implementation",
			Title:     "Implementation",
			Objective: "Implement and verify the bounded change.",
			WorkClass: teamplan.WorkSoftwareImplementation,
			RequiredCapabilities: []teamplan.Capability{
				teamplan.CapabilityGit,
			},
			Workspace: teamplan.WorkspaceIsolated,
			Duration: teamplan.DurationEstimate{
				Minimum:  time.Minute,
				Expected: 2 * time.Minute,
				Maximum:  3 * time.Minute,
			},
			Tokens: teamplan.TokenEstimate{
				InputMinimum:   1_000,
				InputExpected:  2_000,
				InputMaximum:   3_000,
				OutputMinimum:  100,
				OutputExpected: 200,
				OutputMaximum:  300,
			},
			ModelNeed: teamplan.ModelNeed{
				MinimumQuality:       teamplan.QualityBalanced,
				MinimumContextTokens: 1024,
			},
			MinimumResources: teamplan.ResourceEnvelope{
				VCPU:      2,
				MemoryMiB: 8192,
				DiskGiB:   40,
				Arch:      recipe.ArchitectureAMD64,
			},
		}},
	}
}

func orchestrationOfferFixture(
	t *testing.T,
	now time.Time,
) *teamplan.OfferSnapshot {
	t.Helper()
	snapshot, err := teamplan.NewOfferSnapshot(
		teamplan.OfferSnapshotDocument{
			SchemaVersion: teamplan.OfferSnapshotSchemaV1,
			SnapshotID:    uuid.NewString(),
			ProviderScope: teamplan.ProviderScope{
				Provider:           teamplan.CloudProviderAWS,
				ConnectionID:       uuid.NewString(),
				ConnectionRevision: 1,
				AccountID:          "123456789012",
			},
			Region:     "us-east-1",
			Currency:   "USD",
			CapturedAt: now,
			ValidUntil: now.Add(teamplan.OfferSnapshotValidity),
			Sources: []teamplan.OfferSourceReceipt{
				{
					Kind:       teamplan.OfferSourceModelPricing,
					SourceID:   "model-pricing-test",
					Digest:     "sha256:" + strings.Repeat("1", 64),
					CapturedAt: now.Add(-time.Hour),
				},
				{
					Kind:       teamplan.OfferSourceComputePricing,
					SourceID:   "compute-pricing-test",
					Digest:     "sha256:" + strings.Repeat("2", 64),
					CapturedAt: now,
				},
				{
					Kind:       teamplan.OfferSourceComputeCapacity,
					SourceID:   "compute-capacity-test",
					Digest:     "sha256:" + strings.Repeat("3", 64),
					CapturedAt: now,
				},
			},
			ModelOffers: []teamplan.ModelOffer{{
				ProfileID:              "model-balanced",
				Provider:               "openai",
				Model:                  "code-model",
				Interface:              teamplan.ModelOpenAIResponses,
				Quality:                teamplan.QualityBalanced,
				ContextTokens:          128_000,
				InputMicrosPerMillion:  1_000_000,
				OutputMicrosPerMillion: 2_000_000,
				CredentialRef:          "secret_ref:model/test",
				Enabled:                true,
				CredentialReady:        true,
			}},
			ComputeOffers: []teamplan.ComputeOffer{{
				OfferID:        uuid.NewString(),
				Region:         "us-east-1",
				InstanceType:   "m7i.large",
				Architecture:   recipe.ArchitectureAMD64,
				VCPU:           2,
				MemoryMiB:      8192,
				DiskGiB:        40,
				HourlyMicros:   3_600_000,
				PurchaseOption: "on_demand",
				CapacityPool:   "aws:ec2-quota:L-1216C47A",
				CapacityUnits:  2,
				AvailableUnits: 64,
				Available:      true,
			}},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func orchestrationPlanFixture(
	request teamplan.CatalogCompileRequest,
	catalogRevision string,
) (teamplan.Plan, error) {
	policyRevision, err := request.Policy.Digest()
	if err != nil {
		return teamplan.Plan{}, err
	}
	document := request.Offers.Document()
	model := document.ModelOffers[0]
	compute := document.ComputeOffers[0]
	assignment := teamplan.WorkerAssignment{
		RoleID:    "implementation",
		Title:     "Implementation",
		Objective: "Implement and verify the bounded change.",
		WorkClass: teamplan.WorkSoftwareImplementation,
		RequiredCapabilities: []teamplan.Capability{
			teamplan.CapabilityGit,
		},
		Workspace:          teamplan.WorkspaceIsolated,
		RuntimeReleaseID:   uuid.NewSHA1(uuid.MustParse(request.PlanID), []byte("runtime")).String(),
		RuntimeFamily:      teamplan.RuntimeCodex,
		RuntimeVersion:     "1.0.0",
		RuntimeImageDigest: "sha256:" + strings.Repeat("a", 64),
		RuntimeAdapter:     teamplan.AdapterCodexV1,
		ModelProfileID:     model.ProfileID,
		ModelProvider:      model.Provider,
		Model:              model.Model,
		ModelInterface:     model.Interface,
		ModelCredentialRef: model.CredentialRef,
		ComputeOfferID:     compute.OfferID,
		InstanceType:       compute.InstanceType,
		Resources: teamplan.ResourceEnvelope{
			VCPU:      compute.VCPU,
			MemoryMiB: compute.MemoryMiB,
			DiskGiB:   compute.DiskGiB,
			Arch:      compute.Architecture,
		},
		Duration: teamplan.DurationEstimate{
			Minimum:  time.Minute,
			Expected: 2 * time.Minute,
			Maximum:  3 * time.Minute,
		},
		Tokens: teamplan.TokenEstimate{
			InputMinimum:   1_000,
			InputExpected:  2_000,
			InputMaximum:   3_000,
			OutputMinimum:  100,
			OutputExpected: 200,
			OutputMaximum:  300,
		},
	}
	plan := teamplan.Plan{
		SchemaVersion:         teamplan.SchemaV1,
		PlanID:                request.PlanID,
		Revision:              request.Revision,
		OwnerID:               request.OwnerID,
		GoalDigest:            request.GoalDigest,
		ProviderScope:         document.ProviderScope,
		Region:                document.Region,
		CatalogRevision:       catalogRevision,
		PolicyRevision:        policyRevision,
		PricingSnapshotID:     request.Offers.SnapshotID(),
		PricingSnapshotDigest: request.Offers.Digest(),
		QuotedAt:              request.Offers.CapturedAt(),
		ValidUntil:            request.Offers.ValidUntil(),
		ProposalConfidence:    request.Proposal.Confidence,
		ProposalRationale:     request.Proposal.Rationale,
		WorkerCount:           1,
		MaxConcurrentWorkers:  1,
		Assignments:           []teamplan.WorkerAssignment{assignment},
		Schedule: teamplan.ScheduleEstimate{
			MinimumWallTime:  time.Minute,
			ExpectedWallTime: 2 * time.Minute,
			MaximumWallTime:  3 * time.Minute,
		},
		Cost: teamplan.CostEstimate{
			Currency:         "USD",
			MinimumMicros:    71_200,
			ExpectedMicros:   132_400,
			MaximumMicros:    193_600,
			HardBudgetMicros: 232_320,
			Roles: []teamplan.RoleCostEstimate{{
				RoleID:                assignment.RoleID,
				ComputeMinimumMicros:  60_000,
				ComputeExpectedMicros: 120_000,
				ComputeMaximumMicros:  180_000,
				ModelMinimumMicros:    1_200,
				ModelExpectedMicros:   2_400,
				ModelMaximumMicros:    3_600,
				TotalMinimumMicros:    71_200,
				TotalExpectedMicros:   132_400,
				TotalMaximumMicros:    193_600,
			}},
			Assumptions: []string{"on_demand_compute"},
			Exclusions:  []string{"third_party_paid_tools"},
		},
	}
	if err := plan.Validate(); err != nil {
		return teamplan.Plan{}, err
	}
	return plan, nil
}

var _ PlanCompiler = (*orchestrationCompilerFixture)(nil)
var _ PolicyResolver = (*orchestrationPolicyResolverFixture)(nil)
var _ Repository = (*orchestrationRepositoryFixture)(nil)
var _ TrustedOfferBuilder = (*orchestrationOfferBuilderFixture)(nil)
