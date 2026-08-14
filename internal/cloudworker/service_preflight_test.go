package cloudworker

import (
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type preflightStore struct {
	intrinsicStore
	replacements []RequoteOfferCommand
}

func (store *preflightStore) ReplaceWithRequote(_ context.Context, _ coretask.Task, command RequoteOfferCommand) (Offer, error) {
	store.replacements = append(store.replacements, command)
	return Offer{Plan: command.Plan, Execution: command.Execution}, nil
}

type preflightQuoter struct {
	now    *time.Time
	amount int64
}

type fixedReuseResolver struct{ compute ComputeSpec }

func (resolver fixedReuseResolver) ResolveIdleWorker(context.Context, string, uint64, AWSBinding, ComputeSpec) (ComputeSpec, bool, error) {
	return resolver.compute, true, nil
}

func (quoter *preflightQuoter) fake() FakeQuoter {
	return FakeQuoter{AmountMicros: quoter.amount, MaximumAuthorizedMicros: quoter.amount * 2, TTL: 5 * time.Minute,
		Now: func() time.Time { return *quoter.now }}
}
func (quoter *preflightQuoter) Quote(ctx context.Context, request QuoteRequest) (Quote, error) {
	return quoter.fake().Quote(ctx, request)
}
func (quoter *preflightQuoter) Validate(ctx context.Context, plan Plan) (Quote, error) {
	return quoter.fake().Validate(ctx, plan)
}

func TestServicePreflightLaunchRequotesExpiredOrDriftedPrice(t *testing.T) {
	for _, test := range []struct {
		name   string
		reason string
		change func(*time.Time, *preflightQuoter)
	}{
		{name: "expired", reason: RequoteReasonExpired, change: func(now *time.Time, _ *preflightQuoter) { *now = (*now).Add(6 * time.Minute) }},
		{name: "drift", reason: RequoteReasonDrift, change: func(_ *time.Time, quoter *preflightQuoter) { quoter.amount = 1500 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 8, 14, 8, 0, 0, 0, time.UTC)
			defaults := intrinsicDefaults(now)
			store := &preflightStore{}
			quoter := &preflightQuoter{now: &now, amount: 1000}
			service, err := NewService(store, defaults, quoter, func() time.Time { return now })
			if err != nil {
				t.Fatal(err)
			}
			snapshot := coremodel.ExecutionSnapshot{ProfileID: "22222222-2222-4222-8222-222222222222", Revision: 2,
				CredentialVersion: 4, Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://model.example.test/v1", Model: "gpt-test", APIKey: "secret"}
			command := credentialProposalCommand()
			command.ModelAuthorization, err = ModelAuthorizationFromSnapshot(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			offer, err := service.Propose(context.Background(), command)
			if err != nil {
				t.Fatal(err)
			}
			test.change(&now, quoter)
			requoted, err := service.PreflightLaunch(context.Background(), coretask.Task{}, offer.Plan, snapshot)
			if err != nil || !requoted || len(store.replacements) != 1 || store.replacements[0].Reason != test.reason ||
				store.replacements[0].OldExecutionID != offer.Plan.ExecutionID {
				t.Fatalf("requoted=%t err=%v replacements=%+v", requoted, err, store.replacements)
			}
		})
	}
}

func TestServicePreflightLaunchKeepsCurrentQuote(t *testing.T) {
	now := time.Date(2026, 8, 14, 8, 0, 0, 0, time.UTC)
	store := &preflightStore{}
	quoter := &preflightQuoter{now: &now, amount: 1000}
	service, err := NewService(store, intrinsicDefaults(now), quoter, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	snapshot := coremodel.ExecutionSnapshot{ProfileID: "22222222-2222-4222-8222-222222222222", Revision: 2,
		CredentialVersion: 4, Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://model.example.test/v1", Model: "gpt-test", APIKey: "secret"}
	command := credentialProposalCommand()
	command.ModelAuthorization, _ = ModelAuthorizationFromSnapshot(snapshot)
	offer, err := service.Propose(context.Background(), command)
	if err != nil {
		t.Fatal(err)
	}
	requoted, err := service.PreflightLaunch(context.Background(), coretask.Task{}, offer.Plan, snapshot)
	if err != nil || requoted || len(store.replacements) != 0 {
		t.Fatalf("requoted=%t err=%v replacements=%+v", requoted, err, store.replacements)
	}
}

func TestServiceProposalReportsActualLargerReusedWorkerCompute(t *testing.T) {
	now := time.Date(2026, 8, 14, 8, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	defaults.Compute.VCPU, defaults.Compute.MemoryGiB = 2, 2
	service, err := NewService(&preflightStore{}, defaults, FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, ComputeMicrosPerHour: 42_000, TTL: 5 * time.Minute, Now: func() time.Time { return now }}, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	actual := defaults.Compute
	actual.InstanceType, actual.VCPU, actual.MemoryGiB, actual.VolumeGiB = "m7i-flex.xlarge", 4, 16, 80
	if err = service.EnablePersistentWorkerReuse(fixedReuseResolver{compute: actual}); err != nil {
		t.Fatal(err)
	}
	offer, err := service.Propose(context.Background(), credentialProposalCommand())
	if err != nil {
		t.Fatal(err)
	}
	public, err := offer.Plan.Public()
	if err != nil || !offer.Plan.PersistentWorkerReuse || public.Compute.InstanceType != actual.InstanceType || public.Compute.VCPU != actual.VCPU ||
		public.Compute.MemoryGiB != actual.MemoryGiB || public.Compute.VolumeGiB != actual.VolumeGiB || public.Quote.AmountMicros != 0 || public.Quote.MaximumAuthorizedCostMicros != 0 || public.Quote.ComputeMicrosPerHour != 42_000 {
		t.Fatalf("plan=%+v public=%+v err=%v", offer.Plan, public, err)
	}
}
