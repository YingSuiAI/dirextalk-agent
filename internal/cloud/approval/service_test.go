package approval

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
)

func TestServiceVerifiesDeviceOwnerPlanAndConsumesChallengeOnce(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := validPlan()
	pricedQuote := pricedQuoteForPlan(t, &plan, now)
	registry, publicKey, privateKey := approvalRegistry(t, now, plan)
	service, err := NewService(registry, registry, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	service.random = bytes.NewReader(bytes.Repeat([]byte{0x42}, 32))
	challenge, err := service.CreateChallenge(context.Background(), plan, pricedQuote, "device-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(challenge.ChallengeID) < 40 || challenge.ExpiresAt.Sub(challenge.IssuedAt) != ChallengeValidity {
		t.Fatalf("challenge lacks entropy/short validity: %#v", challenge)
	}
	approval := signedApproval(t, plan, challenge, privateKey)
	if err := approval.Verify(publicKey, now); err != nil {
		t.Fatal(err)
	}
	if err := service.VerifyAndConsume(context.Background(), approval, plan, pricedQuote); err != nil {
		t.Fatalf("VerifyAndConsume() error = %v", err)
	}
	if err := service.VerifyAndConsume(context.Background(), approval, plan, pricedQuote); !errors.Is(err, ErrChallengeConsumed) {
		t.Fatalf("replay error = %v, want ErrChallengeConsumed", err)
	}
}

func TestServiceDraftAndVerifyDoNotPersistOrConsume(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := validPlan()
	pricedQuote := pricedQuoteForPlan(t, &plan, now)
	registry, _, privateKey := approvalRegistry(t, now, plan)
	service, err := NewService(registry, registry, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	service.random = bytes.NewReader(bytes.Repeat([]byte{0x24}, 32))

	draft, err := service.DraftChallenge(context.Background(), plan, pricedQuote, "device-key-1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.GetChallenge(context.Background(), draft.ChallengeID); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("DraftChallenge persisted state: %v", err)
	}
	if err := registry.CreateChallenge(context.Background(), draft); err != nil {
		t.Fatal(err)
	}

	signed := signedApproval(t, plan, draft, privateKey)
	if err := service.Verify(context.Background(), signed, plan, pricedQuote); err != nil {
		t.Fatal(err)
	}
	stored, err := registry.GetChallenge(context.Background(), draft.ChallengeID)
	if err != nil {
		t.Fatal(err)
	}
	if stored.ConsumedAt != nil || stored.Revision != draft.Revision {
		t.Fatalf("Verify mutated challenge: %#v", stored)
	}
}

func TestDraftChallengeNormalizesAuthorityTimeToPostgresPrecision(t *testing.T) {
	clock := time.Date(2026, time.July, 16, 8, 0, 0, 123456789, time.UTC)
	plan := validPlan()
	plan.Quote.ValidUntil = clock.Add(cloudquote.Validity)
	pricedQuote := pricedQuoteForPlan(t, &plan, clock)
	registry, _, _ := approvalRegistry(t, clock, plan)
	service, err := NewService(registry, registry, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	service.random = bytes.NewReader(bytes.Repeat([]byte{0x25}, 32))

	challenge, err := service.DraftChallenge(context.Background(), plan, pricedQuote, "device-key-1")
	if err != nil {
		t.Fatal(err)
	}
	want := clock.Truncate(time.Microsecond)
	if !challenge.IssuedAt.Equal(want) || !challenge.ExpiresAt.Equal(want.Add(ChallengeValidity)) {
		t.Fatalf("challenge times=(%s,%s), want PostgreSQL-stable (%s,%s)", challenge.IssuedAt, challenge.ExpiresAt, want, want.Add(ChallengeValidity))
	}
}

func TestServiceRejectsUnsignedExpiredOldRevisionOwnerAndScopeTampering(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*ApprovalV1, *PlanV1, *time.Time)
	}{
		{"unsigned", func(a *ApprovalV1, _ *PlanV1, _ *time.Time) { a.Signature = "" }},
		{"expired", func(_ *ApprovalV1, _ *PlanV1, clock *time.Time) { *clock = (*clock).Add(6 * time.Minute) }},
		{"old revision", func(_ *ApprovalV1, p *PlanV1, _ *time.Time) { p.Revision++ }},
		{"different owner", func(_ *ApprovalV1, p *PlanV1, _ *time.Time) {
			p.OwnerID = "owner-2"
			p.Quote.ScopeDigest, _ = p.PricingScopeDigest()
		}},
		{"resource scope", func(_ *ApprovalV1, p *PlanV1, _ *time.Time) {
			p.ResourceScope.DiskGiB++
			p.Quote.ScopeDigest, _ = p.PricingScopeDigest()
		}},
		{"network scope", func(_ *ApprovalV1, p *PlanV1, _ *time.Time) {
			p.NetworkScope.SubnetID = "subnet-0bbbbbbbbbbbbbbbb"
			p.Quote.ScopeDigest, _ = p.PricingScopeDigest()
		}},
		{"secret scope", func(_ *ApprovalV1, p *PlanV1, _ *time.Time) {
			p.SecretScope[0].Purpose = "different purpose"
			p.Quote.ScopeDigest, _ = p.PricingScopeDigest()
		}},
		{"integration scope", func(_ *ApprovalV1, p *PlanV1, _ *time.Time) {
			p.IntegrationScope[0].Scopes = []string{"admin"}
			p.Quote.ScopeDigest, _ = p.PricingScopeDigest()
		}},
		{"retention scope", func(_ *ApprovalV1, p *PlanV1, _ *time.Time) {
			p.RetentionScope.GracePeriodSeconds++
			p.Quote.ScopeDigest, _ = p.PricingScopeDigest()
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clock := now
			plan := validPlan()
			pricedQuote := pricedQuoteForPlan(t, &plan, now)
			registry, _, privateKey := approvalRegistry(t, now, plan)
			service, _ := NewService(registry, registry, func() time.Time { return clock })
			service.random = bytes.NewReader(bytes.Repeat([]byte(test.name), 64))
			challenge, err := service.CreateChallenge(context.Background(), plan, pricedQuote, "device-key-1")
			if err != nil {
				t.Fatal(err)
			}
			approval := signedApproval(t, plan, challenge, privateKey)
			test.mutate(&approval, &plan, &clock)
			if err := service.VerifyAndConsume(context.Background(), approval, plan, pricedQuote); err == nil {
				t.Fatal("tampered/expired approval was accepted")
			}
			stored, err := registry.GetChallenge(context.Background(), challenge.ChallengeID)
			if err != nil {
				t.Fatal(err)
			}
			if stored.ConsumedAt != nil {
				t.Fatal("failed verification consumed challenge")
			}
		})
	}
}

func TestServiceChallengeConsumptionIsAtomicUnderReplayRace(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := validPlan()
	pricedQuote := pricedQuoteForPlan(t, &plan, now)
	registry, _, privateKey := approvalRegistry(t, now, plan)
	service, _ := NewService(registry, registry, func() time.Time { return now })
	service.random = bytes.NewReader(bytes.Repeat([]byte{0x7f}, 32))
	challenge, err := service.CreateChallenge(context.Background(), plan, pricedQuote, "device-key-1")
	if err != nil {
		t.Fatal(err)
	}
	approval := signedApproval(t, plan, challenge, privateKey)

	var successes atomic.Int32
	var consumed atomic.Int32
	var group sync.WaitGroup
	for index := 0; index < 16; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			err := service.VerifyAndConsume(context.Background(), approval, plan, pricedQuote)
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrChallengeConsumed):
				consumed.Add(1)
			default:
				t.Errorf("unexpected replay error: %v", err)
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 || consumed.Load() != 15 {
		t.Fatalf("successes=%d consumed=%d, want 1/15", successes.Load(), consumed.Load())
	}
}

func TestServiceRejectsRevokedDeviceBeforeChallenge(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := validPlan()
	pricedQuote := pricedQuoteForPlan(t, &plan, now)
	registry, _, _ := approvalRegistry(t, now, plan)
	device, err := registry.GetDeviceKey(context.Background(), "device-key-1")
	if err != nil {
		t.Fatal(err)
	}
	device.Status = DeviceKeyRevoked
	device.RevokedAt = &now
	if err := registry.PutDeviceKey(device); err != nil {
		t.Fatal(err)
	}
	service, _ := NewService(registry, registry, func() time.Time { return now })
	if _, err := service.CreateChallenge(context.Background(), plan, pricedQuote, "device-key-1"); err == nil {
		t.Fatal("revoked device created an approval challenge")
	}
}

func TestPlanValidateQuoteBindsCostAvailabilityAndAssumptions(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	plan := validPlan()
	pricedQuote := pricedQuoteForPlan(t, &plan, now)
	if err := plan.ValidateQuote(pricedQuote, now); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*cloudquote.QuoteV1)
	}{
		{"cost", func(q *cloudquote.QuoteV1) {
			q.Candidates[1].CostItems[0].HourlyEstimateMicros++
			q.Candidates[1].HourlyEstimateMicros++
		}},
		{"offering", func(q *cloudquote.QuoteV1) { q.Candidates[1].OfferedAvailabilityZones = []string{"us-east-1b"} }},
		{"assumption", func(q *cloudquote.QuoteV1) { q.Assumptions = []string{"different runtime assumption"} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := pricedQuote
			changed.Candidates = append([]cloudquote.CandidateV1(nil), pricedQuote.Candidates...)
			for index := range changed.Candidates {
				changed.Candidates[index].CostItems = append([]cloudquote.CostItemV1(nil), pricedQuote.Candidates[index].CostItems...)
				changed.Candidates[index].OfferedAvailabilityZones = append([]string(nil), pricedQuote.Candidates[index].OfferedAvailabilityZones...)
			}
			changed.Assumptions = append([]string(nil), pricedQuote.Assumptions...)
			test.mutate(&changed)
			if err := changed.Validate(); err != nil {
				t.Fatalf("test mutation must remain a structurally valid quote: %v", err)
			}
			if err := plan.ValidateQuote(changed, now); err == nil {
				t.Fatal("changed quote evidence matched approved quote digest")
			}
		})
	}
}

func approvalRegistry(t *testing.T, now time.Time, plan PlanV1) (*MemoryRegistry, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	registry := NewMemoryRegistry()
	if err := registry.PutDeviceKey(DeviceKeyV1{
		KeyID: "device-key-1", AgentInstanceID: plan.AgentInstanceID, OwnerID: plan.OwnerID, Revision: 1,
		Status: DeviceKeyActive, PublicKey: publicKey, NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(24 * time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	return registry, publicKey, privateKey
}

func signedApproval(t *testing.T, plan PlanV1, challenge ChallengeV1, privateKey ed25519.PrivateKey) ApprovalV1 {
	t.Helper()
	approval, err := NewApprovalV1(plan, "approval-1", challenge.ChallengeID, challenge.SignerKeyID, challenge.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := approval.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	approval.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return approval
}

func pricedQuoteForPlan(t *testing.T, plan *PlanV1, now time.Time) cloudquote.QuoteV1 {
	t.Helper()
	value := cloudquote.QuoteV1{
		SchemaVersion: cloudquote.SchemaV1,
		QuoteID:       plan.Quote.QuoteID,
		QuotedAt:      now,
		ValidUntil:    plan.Quote.ValidUntil,
		Currency:      "USD",
		Usage:         cloudquote.UsageV1{RuntimeHoursPerMonth: 730},
		Assumptions:   []string{"one exclusive Worker instance"},
		Exclusions:    []string{"taxes and unplanned transfer"},
	}
	for _, profile := range []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance} {
		scope := plan.PricingScope()
		scope.Resource.CandidateID = profile
		scopeDigest, err := scope.Digest()
		if err != nil {
			t.Fatal(err)
		}
		items := []cloudquote.CostItemV1{
			approvalCost(cloudquote.CostComputeOnDemand, "EC2 compute", "compute-"+string(profile), 100000, 73000000, 100000),
			approvalCost(cloudquote.CostEBS, "encrypted EBS", "ebs-"+string(profile), 10000, 7300000, 10000),
			approvalCost(cloudquote.CostPublicIPv4, "public IPv4", "ipv4-"+string(profile), 0, 0, 0),
			approvalCost(cloudquote.CostLogs, "CloudWatch logs", "logs-"+string(profile), 1000, 730000, 1000),
			approvalCost(cloudquote.CostSnapshot, "EBS snapshots", "snapshot-"+string(profile), 1000, 730000, 1000),
			approvalCost(cloudquote.CostEntry, "public entry", "entry-"+string(profile), 0, 0, 0),
			approvalCost(cloudquote.CostTraffic, "data transfer", "traffic-"+string(profile), 1000, 730000, 1000),
		}
		candidate := cloudquote.CandidateV1{
			CandidateID: profile, Scope: scope, ScopeDigest: scopeDigest,
			OfferedAvailabilityZones: []string{"us-east-1a", "us-east-1b"},
			Quotas:                   []cloudquote.QuotaEvidenceV1{{ServiceCode: "ec2", QuotaCode: "L-1216C47A", LimitUnits: 64, UsedUnits: 4, RequiredUnits: 4}},
			CostItems:                items, HourlyEstimateMicros: 113000, MonthlyEstimateMicros: 82490000, MaximumLaunchAmountMicros: 113000,
		}
		value.Candidates = append(value.Candidates, candidate)
	}
	digest, err := value.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.Digest = digest
	return value
}

func approvalCost(category cloudquote.CostCategory, description, source string, hourly, monthly, launch uint64) cloudquote.CostItemV1 {
	return cloudquote.CostItemV1{Category: category, Description: description, SourceID: source, HourlyEstimateMicros: hourly, MonthlyEstimateMicros: monthly, MaximumLaunchAmountMicros: launch}
}
