package cloudapp

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

const (
	testAgentID      = "019b2d57-b3c0-7e65-a1d2-10c43de26710"
	testCredentialID = "019b2d57-b3c0-7e65-a1d2-10c43de26711"
)

type coordinatorFacts struct {
	plan             cloudapproval.PlanV1
	quote            cloudquote.QuoteV1
	challenge        cloudapproval.ChallengeV1
	approval         cloudapproval.ApprovalV1
	persistApprovals int
}

func (facts *coordinatorFacts) PersistQuote(context.Context, MutationScope, string, [32]byte, cloudquote.QuoteV1) (cloudquote.QuoteV1, error) {
	return facts.quote, nil
}
func (facts *coordinatorFacts) LoadQuote(context.Context, string, string) (cloudquote.QuoteV1, error) {
	return facts.quote, nil
}
func (facts *coordinatorFacts) PersistPlan(context.Context, MutationScope, string, cloudapproval.PlanV1) (cloudapproval.PlanV1, error) {
	return facts.plan, nil
}
func (facts *coordinatorFacts) LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return facts.plan, nil
}
func (facts *coordinatorFacts) PersistChallenge(_ context.Context, _ MutationScope, _ string, value cloudapproval.ChallengeV1) (cloudapproval.ChallengeV1, error) {
	facts.challenge = value
	return value, nil
}
func (facts *coordinatorFacts) LoadChallenge(context.Context, string) (cloudapproval.ChallengeV1, error) {
	return facts.challenge, nil
}
func (facts *coordinatorFacts) PersistApproval(_ context.Context, _ MutationScope, _ string, _, _ uint64, _ cloudapproval.ApprovalV1) (cloudapproval.PlanV1, error) {
	facts.persistApprovals++
	return facts.plan, nil
}
func (facts *coordinatorFacts) LoadApproval(context.Context, string, string) (cloudapproval.ApprovalV1, error) {
	return facts.approval, nil
}

type coordinatorRecipes struct{}

func (coordinatorRecipes) ResolveRecipe(context.Context, string, string, string) (recipe.RecipeV1, error) {
	return recipe.RecipeV1{}, nil
}

type coordinatorQuotes struct{}

func (coordinatorQuotes) Quote(context.Context, QuoteExecutionRequest, recipe.RecipeV1) (cloudquote.QuoteV1, error) {
	return cloudquote.QuoteV1{}, nil
}

type coordinatorApprovals struct{ verifyErr error }

func (engine *coordinatorApprovals) DraftChallenge(_ context.Context, plan cloudapproval.PlanV1, _ cloudquote.QuoteV1, signer string) (cloudapproval.ChallengeV1, error) {
	hash, _ := plan.Hash()
	return cloudapproval.ChallengeV1{
		ChallengeID: "challenge_" + strings.Repeat("a", 43), Revision: 1,
		AgentInstanceID: plan.AgentInstanceID, OwnerID: plan.OwnerID, PlanID: plan.PlanID,
		PlanRevision: plan.Revision, PlanHash: hash, ConnectionID: plan.ConnectionID,
		RecipeDigest: plan.Recipe.Digest, QuoteID: plan.Quote.QuoteID, QuoteDigest: plan.Quote.Digest,
		QuoteScopeDigest: plan.Quote.ScopeDigest, QuoteCandidateID: plan.Quote.CandidateID,
		SignerKeyID: signer, IssuedAt: plan.Quote.ValidUntil.Add(-10 * time.Minute), ExpiresAt: plan.Quote.ValidUntil.Add(-5 * time.Minute),
	}, nil
}
func (engine *coordinatorApprovals) Verify(context.Context, cloudapproval.ApprovalV1, cloudapproval.PlanV1, cloudquote.QuoteV1) error {
	return engine.verifyErr
}

func TestCoordinatorChallengeApprovalIDIsStableAndCallerBound(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := coordinatorPlan(now)
	facts := &coordinatorFacts{plan: plan}
	service, err := NewService(testAgentID, facts, coordinatorRecipes{}, coordinatorQuotes{}, &coordinatorApprovals{}, nil, nil, Capabilities{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	scope := MutationScope{ClientID: "message-server", CredentialID: testCredentialID}
	command := CreateChallengeCommand{
		IdempotencyKey: "019b2d57-b3c0-7e65-a1d2-10c43de26712", OwnerID: plan.OwnerID,
		PlanID: plan.PlanID, ExpectedRevision: plan.Revision, SignerKeyID: "device-key-1",
	}
	first, err := service.CreateApprovalChallenge(context.Background(), scope, command)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.CreateApprovalChallenge(context.Background(), scope, command)
	if err != nil {
		t.Fatal(err)
	}
	if first.ApprovalID != second.ApprovalID || len(first.SigningCBOR) == 0 {
		t.Fatalf("idempotent challenge identity changed: first=%q second=%q", first.ApprovalID, second.ApprovalID)
	}
	other := deterministicApprovalID(testAgentID, MutationScope{ClientID: "other", CredentialID: testCredentialID}, command.IdempotencyKey)
	if other == first.ApprovalID {
		t.Fatal("approval id did not bind caller identity")
	}
}

func TestCoordinatorVerifiesBeforePersistingApproval(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := coordinatorPlan(now)
	challenge := cloudapproval.ChallengeV1{ChallengeID: "challenge_" + strings.Repeat("b", 43), Revision: 1}
	facts := &coordinatorFacts{plan: plan, challenge: challenge}
	engine := &coordinatorApprovals{verifyErr: errors.New("invalid signature")}
	service, err := NewService(testAgentID, facts, coordinatorRecipes{}, coordinatorQuotes{}, engine, nil, nil, Capabilities{}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.ApprovePlan(context.Background(), MutationScope{ClientID: "message-server", CredentialID: testCredentialID}, ApprovePlanCommand{
		IdempotencyKey: "019b2d57-b3c0-7e65-a1d2-10c43de26713", OwnerID: plan.OwnerID, PlanID: plan.PlanID,
		ExpectedRevision: plan.Revision, Approval: ApprovalSignature{
			ApprovalID: "019b2d57-b3c0-7e65-a1d2-10c43de26714", ChallengeID: challenge.ChallengeID,
			SignerKeyID: "device-key-1", ExpiresAt: now.Add(time.Minute), Signature: make([]byte, ed25519.SignatureSize),
		},
	})
	if !errors.Is(err, ErrApprovalRequired) || facts.persistApprovals != 0 {
		t.Fatalf("error=%v persisted=%d, want rejected before persistence", err, facts.persistApprovals)
	}
}

func coordinatorPlan(now time.Time) cloudapproval.PlanV1 {
	value := cloudapproval.PlanV1{
		SchemaVersion: cloudapproval.PlanSchemaV1, AgentInstanceID: testAgentID, OwnerID: "owner-1",
		PlanID: "019b2d57-b3c0-7e65-a1d2-10c43de26715", Revision: 1,
		Status: cloudapproval.PlanReadyForConfirmation, ConnectionID: "019b2d57-b3c0-7e65-a1d2-10c43de26717",
		Recipe: cloudapproval.RecipeBindingV1{RecipeID: "recipe-1", Digest: testCloudDigest("a"), Maturity: recipe.MaturityExperimental},
		Quote: cloudapproval.QuoteBindingV1{
			QuoteID: "019b2d57-b3c0-7e65-a1d2-10c43de26716", Digest: testCloudDigest("b"),
			CandidateID: string(cloudquote.CandidateRecommended), ValidUntil: now.Add(15 * time.Minute),
		},
		ResourceScope: cloudapproval.ResourceScopeV1{
			Region: "us-east-1", AvailabilityZones: []string{"us-east-1a"}, InstanceType: "m7i.xlarge",
			InstanceCount: 1, Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 16384,
			DiskGiB: 80, VolumeType: "gp3", VolumeEncrypted: true, PurchaseOption: cloudapproval.PurchaseOnDemand,
			WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: testCloudDigest("c"),
		},
		NetworkScope: cloudapproval.NetworkScopeV1{
			VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0",
			SecurityGroupID: "sg-0123456789abcdef0", EntryPoint: cloudapproval.EntryPointNone,
		},
		RetentionScope: cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400},
	}
	digest, err := value.PricingScopeDigest()
	if err != nil {
		panic(err)
	}
	value.Quote.ScopeDigest = digest
	return value
}

func testCloudDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
