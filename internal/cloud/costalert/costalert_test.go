package costalert

import (
	"context"
	"strings"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudexecution"
	"github.com/google/uuid"
)

func TestControllerUsesSelectedQuoteAndActiveRuntimeAndRaisesOnce(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	facts := costFacts(t, now)
	repository := &policyFake{}
	controller, err := NewController(facts.plan.AgentInstanceID, facts, repository)
	if err != nil {
		t.Fatal(err)
	}
	request := EvaluateRequest{
		OwnerID: facts.plan.OwnerID, DeploymentID: facts.launch.DeploymentID,
		ThresholdAmountMinor: 50, ObservedAt: now,
	}
	first, emitted, err := controller.Evaluate(context.Background(), request)
	if err != nil || !emitted || first.Status != StatusAlerted || first.ProjectedAccruedMicros != 1_000_000 {
		t.Fatalf("first evaluation = %#v emitted=%t err=%v", first, emitted, err)
	}
	second, emitted, err := controller.Evaluate(context.Background(), request)
	if err != nil || emitted || second.Revision != first.Revision {
		t.Fatalf("exact replay = %#v emitted=%t err=%v", second, emitted, err)
	}
	if repository.activations != 2 || repository.events != 1 {
		t.Fatalf("activations=%d events=%d", repository.activations, repository.events)
	}
}

func TestControllerRejectsMutableOrUnsupportedCostFacts(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*factFake)
	}{
		{"not active", func(v *factFake) { v.launch.State = cloudexecution.StateProvisioning }},
		{"plan drift", func(v *factFake) { v.plan.Quote.CandidateID = "other" }},
		{"unsupported currency exponent", func(v *factFake) { v.quote.Currency = "JPY" }},
		{"future active time", func(v *factFake) { v.launch.UpdatedAt = now.Add(time.Second) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := costFacts(t, now)
			test.mutate(facts)
			controller, _ := NewController(facts.plan.AgentInstanceID, facts, &policyFake{})
			if _, _, err := controller.Evaluate(context.Background(), EvaluateRequest{
				OwnerID: facts.plan.OwnerID, DeploymentID: facts.launch.DeploymentID,
				ThresholdAmountMinor: 50, ObservedAt: now,
			}); err == nil {
				t.Fatal("invalid cost facts were accepted")
			}
		})
	}
}

type factFake struct {
	plan   cloudapproval.PlanV1
	quote  cloudquote.QuoteV1
	launch cloudexecution.Operation
}

func (fake *factFake) LoadPlan(context.Context, string, string) (cloudapproval.PlanV1, error) {
	return fake.plan, nil
}
func (fake *factFake) LoadQuote(context.Context, string, string) (cloudquote.QuoteV1, error) {
	return fake.quote, nil
}
func (fake *factFake) GetByDeployment(context.Context, string) (cloudexecution.Operation, error) {
	return fake.launch, nil
}

type policyFake struct {
	current     *PolicyV1
	activations int
	events      int
}

func (fake *policyFake) Activate(_ context.Context, policy PolicyV1) (PolicyV1, error) {
	fake.activations++
	if fake.current != nil {
		return *fake.current, nil
	}
	policy.CreatedAt, policy.UpdatedAt = policy.RunningSince, policy.RunningSince
	fake.current = &policy
	return policy, nil
}

func (fake *policyFake) Get(_ context.Context, ownerID, deploymentID string) (PolicyV1, error) {
	if fake.current == nil || fake.current.OwnerID != ownerID || fake.current.DeploymentID != deploymentID {
		return PolicyV1{}, ErrNotReady
	}
	return *fake.current, nil
}

func (fake *policyFake) Evaluate(_ context.Context, _ string, _ int64, accrued uint64, observedAt time.Time) (PolicyV1, bool, error) {
	if fake.current.LastObservedAt.Equal(observedAt) && fake.current.ProjectedAccruedMicros == accrued {
		return *fake.current, false, nil
	}
	threshold, _ := ThresholdMicros(fake.current.ThresholdAmountMinor, fake.current.Currency)
	fake.current.ProjectedAccruedMicros, fake.current.LastObservedAt = accrued, observedAt
	fake.current.Revision++
	emitted := fake.current.Status == StatusActive && accrued >= threshold
	if emitted {
		fake.current.Status, fake.current.AlertedAt = StatusAlerted, observedAt
		fake.events++
	}
	return *fake.current, emitted, nil
}

func costFacts(t *testing.T, now time.Time) *factFake {
	t.Helper()
	digest := "sha256:" + strings.Repeat("a", 64)
	agentID, ownerID, planID, quoteID, deploymentID := uuid.NewString(), "owner-a", uuid.NewString(), uuid.NewString(), uuid.NewString()
	quote := cloudquote.QuoteV1{
		SchemaVersion: cloudquote.SchemaV1, QuoteID: quoteID, QuotedAt: now.Add(-2 * time.Hour),
		ValidUntil: now.Add(-2 * time.Hour).Add(cloudquote.Validity), Currency: "USD",
		Candidates: []cloudquote.CandidateV1{{
			CandidateID: cloudquote.CandidateRecommended, ScopeDigest: digest,
			HourlyEstimateMicros: 2_000_000, MonthlyEstimateMicros: 1_460_000_000, MaximumLaunchAmountMicros: 2_000_000,
		}},
	}
	plan := cloudapproval.PlanV1{
		SchemaVersion: cloudapproval.PlanSchemaV1, AgentInstanceID: agentID, OwnerID: ownerID, PlanID: planID,
		Revision: 2, Status: cloudapproval.PlanApproved,
		Quote: cloudapproval.QuoteBindingV1{
			QuoteID: quoteID, Digest: digest, ScopeDigest: digest,
			CandidateID: string(cloudquote.CandidateRecommended), ValidUntil: quote.ValidUntil,
		},
	}
	return &factFake{
		plan: plan, quote: quote,
		launch: cloudexecution.Operation{
			Intent: cloudexecution.Intent{
				Launch: cloudexecution.LaunchRequest{OwnerID: ownerID, PlanID: planID}, DeploymentID: deploymentID,
			},
			State: cloudexecution.StateActive, UpdatedAt: now.Add(-30 * time.Minute),
		},
	}
}
