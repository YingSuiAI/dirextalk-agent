package postgres

import (
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
)

func TestCloudCreateDigestsBindStableRequestInputsOnly(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	quoteOne := cloudquote.QuoteV1{
		QuoteID: "generated-quote-one", QuotedAt: now, ValidUntil: now.Add(cloudquote.Validity),
		Usage: cloudquote.UsageV1{RuntimeHoursPerMonth: 730},
		Candidates: []cloudquote.CandidateV1{
			{Scope: cloudquote.ScopeV1{Resource: cloudquote.ResourceScopeV1{CandidateID: cloudquote.CandidateEconomic}}},
			{Scope: cloudquote.ScopeV1{Resource: cloudquote.ResourceScopeV1{CandidateID: cloudquote.CandidateRecommended}}},
			{Scope: cloudquote.ScopeV1{Resource: cloudquote.ResourceScopeV1{CandidateID: cloudquote.CandidatePerformance}}},
		},
	}
	quoteTwo := quoteOne
	quoteTwo.QuoteID = "generated-quote-two"
	quoteTwo.QuotedAt = now.Add(time.Second)
	quoteTwo.ValidUntil = quoteTwo.QuotedAt.Add(cloudquote.Validity)
	quoteTwo.Candidates = append([]cloudquote.CandidateV1(nil), quoteOne.Candidates...)
	quoteTwo.Candidates[0].HourlyEstimateMicros = 999999
	firstQuoteDigest, err := (CreateQuoteCommand{ExpectedRevision: 0, Quote: quoteOne}).digest()
	if err != nil {
		t.Fatal(err)
	}
	secondQuoteDigest, err := (CreateQuoteCommand{ExpectedRevision: 0, Quote: quoteTwo}).digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstQuoteDigest != secondQuoteDigest {
		t.Fatal("Quote ID, timestamps, and provider prices changed the stable quote request digest")
	}
	quoteTwo.Candidates[0].Scope.Resource.DiskGiB++
	changedQuoteDigest, err := (CreateQuoteCommand{ExpectedRevision: 0, Quote: quoteTwo}).digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstQuoteDigest == changedQuoteDigest {
		t.Fatal("price-sensitive scope drift did not change the quote request digest")
	}

	challengeOne := cloudapproval.ChallengeV1{
		ChallengeID: "generated-challenge-one", AgentInstanceID: "agent", OwnerID: "owner", PlanID: "plan",
		PlanRevision: 1, PlanHash: "plan-hash", ConnectionID: "connection", RecipeDigest: "recipe-digest",
		QuoteID: "quote", QuoteDigest: "quote-digest", QuoteScopeDigest: "scope-digest",
		QuoteCandidateID: "recommended", SignerKeyID: "device", IssuedAt: now, ExpiresAt: now.Add(time.Minute),
	}
	challengeTwo := challengeOne
	challengeTwo.ChallengeID = "generated-challenge-two"
	challengeTwo.IssuedAt = now.Add(time.Second)
	challengeTwo.ExpiresAt = now.Add(2 * time.Minute)
	firstChallengeDigest, err := (CreateApprovalChallengeCommand{Challenge: challengeOne}).digest()
	if err != nil {
		t.Fatal(err)
	}
	secondChallengeDigest, err := (CreateApprovalChallengeCommand{Challenge: challengeTwo}).digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstChallengeDigest != secondChallengeDigest {
		t.Fatal("challenge entropy and server timestamps changed the stable challenge request digest")
	}
	challengeTwo.SignerKeyID = "different-device"
	changedChallengeDigest, err := (CreateApprovalChallengeCommand{Challenge: challengeTwo}).digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstChallengeDigest == changedChallengeDigest {
		t.Fatal("approval-device binding did not change the challenge request digest")
	}
}
