package cloudworker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	"github.com/google/uuid"
)

type limitRecordingQuoter struct {
	base FakeQuoter
	last QuoteRequest
}

func (quoter *limitRecordingQuoter) Quote(ctx context.Context, request QuoteRequest) (Quote, error) {
	quoter.last = request
	return quoter.base.Quote(ctx, request)
}

func (quoter *limitRecordingQuoter) Validate(ctx context.Context, plan Plan) (Quote, error) {
	return quoter.base.Validate(ctx, plan)
}

type proposalAWSBindingResolver struct {
	binding AWSBinding
	err     error
	calls   int
}

func (resolver *proposalAWSBindingResolver) ResolveCurrentAWSBinding(context.Context) (AWSBinding, error) {
	resolver.calls++
	return resolver.binding, resolver.err
}

func credentialProposalCommand() ProposeCommand {
	return ProposeCommand{
		OwnerID: "@owner:example.test", AccountGeneration: 7,
		IdempotencyKey: uuid.NewString(), ConversationID: uuid.NewString(), TurnID: uuid.NewString(),
		TurnLeaseID: uuid.NewString(), TurnLeaseEpoch: 2, ExpectedTurnRevision: 1,
		Objective: "run an exact cloud task", ObjectiveSummary: "run an exact cloud task",
		UserPromptDigest: digestValue("credential-authority-prompt"),
		ProposalReason:   ProposalReasonExplicitUserCloud,
		InputManifest:    InputManifest{Schema: InputManifestSchema, Items: []InputManifestItem{}},
		WorkspaceMode:    WorkspaceNone,
		RuntimeEstimate:  RuntimeEstimate{MinimumSeconds: 600, ExpectedSeconds: 1200, MaximumSeconds: 1800},
		ModelAuthorization: ModelAuthorization{
			ModelProfileID: uuid.NewString(), ModelProfileRevision: 2,
			Provider: "openai_compatible", BaseURL: "https://api.openai.com/v1", Model: "gpt-test", Interface: "openai_compatible",
			MaximumOutputTokens: 4096, ContextWindow: 65536,
			CredentialVersion: 4, CredentialBindingDigest: digestValue("model-credential"),
		},
	}
}

func TestServiceProposalRevalidatesCurrentAWSBinding(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	current := defaults.AWS
	current.CredentialRevision++
	resolver := &proposalAWSBindingResolver{binding: current}
	store := &intrinsicStore{}
	service, err := NewServiceWithAWSBindingResolver(
		store, defaults,
		FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }},
		resolver, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := service.Propose(context.Background(), credentialProposalCommand())
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 || len(store.commands) != 1 || offer.Plan.AWS != current ||
		offer.Plan.AWS == defaults.AWS || offer.Plan.AuthorizationBasisDigest == "" {
		t.Fatalf("proposal did not bind current credential: calls=%d plan=%+v", resolver.calls, offer.Plan)
	}
}

func TestServiceProposalFailsClosedWhenCredentialAuthorityIsStale(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	resolver := &proposalAWSBindingResolver{binding: defaults.AWS, err: ErrStaleAuthorization}
	store := &intrinsicStore{}
	service, err := NewServiceWithAWSBindingResolver(
		store, defaults,
		FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }},
		resolver, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Propose(context.Background(), credentialProposalCommand()); !errors.Is(err, ErrStaleAuthorization) {
		t.Fatalf("stale credential authority err=%v", err)
	}
	if resolver.calls != 1 || len(store.commands) != 0 {
		t.Fatalf("stale credential authority persisted an offer: calls=%d commands=%d", resolver.calls, len(store.commands))
	}
}

func TestServiceProposalChecksArtifactDestinationBeforeQuoteOrPersistence(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	resolver := &proposalAWSBindingResolver{binding: defaults.AWS}
	store := &intrinsicStore{}
	quoter := &limitRecordingQuoter{base: FakeQuoter{
		AmountMicros: 1000, MaximumAuthorizedMicros: 2000,
		TTL: 5 * time.Minute, Now: func() time.Time { return now },
	}}
	readinessCalls := 0
	service, err := NewServiceWithProductionDependencies(store, defaults, quoter, resolver,
		ArtifactDestinationReadinessFunc(func(_ context.Context, binding AWSBinding, bucket, kmsKeyARN string) error {
			readinessCalls++
			if binding != defaults.AWS || bucket != defaults.ArtifactBucket || kmsKeyARN != defaults.ArtifactKMSKeyARN {
				t.Fatalf("destination authority drift: binding=%+v bucket=%q kms=%q", binding, bucket, kmsKeyARN)
			}
			return errors.New("NoSuchBucket")
		}), func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Propose(context.Background(), credentialProposalCommand()); !errors.Is(err, ErrArtifactDestinationUnavailable) {
		t.Fatalf("proposal error = %v", err)
	}
	if readinessCalls != 1 || len(store.commands) != 0 || quoter.last.OwnerID != "" {
		t.Fatalf("unready destination crossed quote boundary: checks=%d offers=%d quote=%+v", readinessCalls, len(store.commands), quoter.last)
	}
}

func TestServiceProposalHasNoCumulativeTokenBudgetAndBindsPerRequestModelLimit(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	resolver := &proposalAWSBindingResolver{binding: defaults.AWS}
	store := &intrinsicStore{}
	quoter := &limitRecordingQuoter{base: FakeQuoter{
		AmountMicros: 1000, MaximumAuthorizedMicros: 2000,
		TTL: 5 * time.Minute, Now: func() time.Time { return now },
	}}
	service, err := NewServiceWithAWSBindingResolver(
		store, defaults, quoter, resolver, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	command := credentialProposalCommand()
	command.ModelAuthorization.MaximumOutputTokens = 8192
	offer, err := service.Propose(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	wantRequestMax := command.ModelAuthorization.MaximumOutputTokens
	publicPlan, err := json.Marshal(offer.Plan)
	if err != nil {
		t.Fatal(err)
	}
	if offer.Plan.Limits.MaxTokens != 0 || quoter.last.Limits.MaxTokens != 0 ||
		strings.Contains(string(publicPlan), `"max_tokens"`) ||
		offer.Plan.Quote.BasisDigest != offer.Plan.AuthorizationBasisDigest ||
		offer.Execution.PlanDigest != offer.Plan.Digest ||
		offer.Execution.ExecutionDigest != offer.Plan.ExecutionDigest {
		t.Fatalf("bound offer drift: plan=%+v quote_request=%+v execution=%+v", offer.Plan, quoter.last, offer.Execution)
	}

	execution, err := offer.Execution.Transition(StateQueued, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	staged := StagedInputManifest{
		Schema: StagedInputManifestSchemaV1, ExecutionID: offer.Plan.ExecutionID,
		SourceManifestDigest: offer.Plan.InputManifestDigest,
	}
	if _, err = staged.Seal(offer.Plan.InputManifest); err != nil {
		t.Fatal(err)
	}
	material, err := BuildRuntimeTask(
		offer.Plan, execution, staged,
		RuntimeTaskFence{ExecutionID: offer.Plan.ExecutionID, TaskID: offer.Plan.TaskID, AccountGeneration: offer.Plan.AccountGeneration, Attempt: 1, LeaseEpoch: 1},
		RuntimeQualification{WorkerProtocolVersion: cloudprotocol.WorkerProtocolVersion, RuntimeContractVersion: cloudprotocol.RuntimeContractVersion, PiRuntimeDigest: offer.Plan.Compute.PiRuntimeDigest, PiVersion: "0.83.0", PiExecutableSHA256: digestValue("pi-executable"), ResultExtensionSHA256: digestValue("result-extension")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer material.Destroy()
	if material.Task.MaxOutputTokens != wantRequestMax ||
		material.Task.ModelContextWindow != command.ModelAuthorization.ContextWindow {
		t.Fatalf("runtime task model limits = output:%d context:%d", material.Task.MaxOutputTokens, material.Task.ModelContextWindow)
	}
}

func TestServiceProposalRejectsUnqualifiedEffectiveTokenLimitBeforeAuthorityOrQuote(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	resolver := &proposalAWSBindingResolver{binding: defaults.AWS}
	store := &intrinsicStore{}
	quoter := &limitRecordingQuoter{base: FakeQuoter{
		AmountMicros: 1000, MaximumAuthorizedMicros: 2000,
		TTL: 5 * time.Minute, Now: func() time.Time { return now },
	}}
	service, err := NewServiceWithAWSBindingResolver(store, defaults, quoter, resolver, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	command := credentialProposalCommand()
	command.ModelAuthorization.MaximumOutputTokens = 511
	if _, err = service.Propose(context.Background(), command); !errors.Is(err, ErrInvalid) {
		t.Fatalf("proposal error = %v, want ErrInvalid", err)
	}
	if resolver.calls != 0 || len(store.commands) != 0 || quoter.last.OwnerID != "" {
		t.Fatalf("invalid output limit crossed a side-effect boundary: resolver=%d store=%d quote=%+v", resolver.calls, len(store.commands), quoter.last)
	}
}

func TestRequoteRecomputesEffectiveTokenLimitFromServerBase(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name, credentialDigest string
		oldMaximum, newMaximum uint64
	}{
		{name: "profile limit increases", credentialDigest: "requote-model-increase", oldMaximum: 2048, newMaximum: 4096},
		{name: "profile limit decreases", credentialDigest: "requote-model-decrease", oldMaximum: 4096, newMaximum: 2048},
	} {
		t.Run(test.name, func(t *testing.T) {
			defaults := intrinsicDefaults(now)
			store := &intrinsicStore{}
			quoter := FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }}
			service, err := NewService(store, defaults, quoter, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			proposal := credentialProposalCommand()
			proposal.ModelAuthorization.MaximumOutputTokens = test.oldMaximum
			offer, err := service.Propose(context.Background(), proposal)
			if err != nil {
				t.Fatal(err)
			}
			if offer.Plan.Limits.MaxTokens != 0 {
				t.Fatalf("new Plan has cumulative budget = %d", offer.Plan.Limits.MaxTokens)
			}
			current := offer.Plan.ModelAuthorization
			current.ModelProfileRevision++
			current.CredentialVersion++
			current.CredentialBindingDigest = digestValue(test.credentialDigest)
			current.MaximumOutputTokens = test.newMaximum
			if err = current.Seal(); err != nil {
				t.Fatal(err)
			}
			command, err := compileRequoteOffer(
				context.Background(), quoter, defaults.Limits, offer.Plan,
				RequoteReasonDrift, now.Add(time.Second), offer.Plan.AWS, current,
			)
			if err != nil {
				t.Fatal(err)
			}
			if command.Plan.Limits.MaxTokens != 0 ||
				command.Plan.Quote.BasisDigest != command.Plan.AuthorizationBasisDigest ||
				command.Plan.Digest == offer.Plan.Digest {
				t.Fatalf("replacement limit/digest drift: old=%+v replacement=%+v", offer.Plan, command.Plan)
			}
		})
	}
}
