package postgres_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	cloudquote "github.com/YingSuiAI/dirextalk-agent/internal/cloud/quote"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCloudPlanApprovalFactsReplayRestartAndAtomicApproval(t *testing.T) {
	pool, store, instanceID := newPlanningTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	scope := task.MutationScope{ClientID: "cloud-control-test", CredentialID: uuid.NewString()}
	now := time.Now().UTC().Truncate(time.Second)
	plan := cloudApprovalPlanFixture(instanceID)
	expiredQuote := cloudApprovalQuoteFixture(t, plan, uuid.NewString(), now.Add(-16*time.Minute))
	if _, err := store.CreateQuote(ctx, scope, postgres.CreateQuoteCommand{
		IdempotencyKey: uuid.NewString(), Quote: expiredQuote,
	}); !errors.Is(err, postgres.ErrCloudFactInvalid) {
		t.Fatalf("expired Quote creation error = %v", err)
	}
	quoted := cloudApprovalQuoteFixture(t, plan, uuid.NewString(), now.Add(-time.Minute))
	quoteDigest, err := quoted.Digest()
	if err != nil {
		t.Fatal(err)
	}
	plan.Quote.QuoteID = quoted.QuoteID
	plan.Quote.Digest = quoteDigest
	plan.Quote.ValidUntil = quoted.ValidUntil

	quoteKey := uuid.NewString()
	createdQuote, err := store.CreateQuote(ctx, scope, postgres.CreateQuoteCommand{IdempotencyKey: quoteKey, Quote: quoted})
	if err != nil {
		t.Fatal(err)
	}
	repriced := cloudApprovalQuoteFixture(t, plan, uuid.NewString(), quoted.QuotedAt.Add(time.Second))
	replayedQuote, err := store.CreateQuote(ctx, scope, postgres.CreateQuoteCommand{IdempotencyKey: quoteKey, Quote: repriced})
	if err != nil {
		t.Fatal(err)
	}
	if replayedQuote.QuoteID != createdQuote.QuoteID || !replayedQuote.QuotedAt.Equal(createdQuote.QuotedAt) {
		t.Fatalf("quote replay did not return the stored response: %#v", replayedQuote)
	}
	conflictingQuote := cloudApprovalQuoteFixture(t, plan, uuid.NewString(), quoted.QuotedAt)
	// Keep the candidate ladder valid while changing the request-bound scope.
	// Raising only the economic candidate would make recommended smaller and
	// correctly fail Quote validation before exercising idempotency conflict.
	conflictingQuote.Candidates[2].Scope.Resource.DiskGiB++
	conflictingQuote.Candidates[2].ScopeDigest, err = conflictingQuote.Candidates[2].Scope.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreateQuote(ctx, scope, postgres.CreateQuoteCommand{IdempotencyKey: quoteKey, Quote: conflictingQuote}); !errors.Is(err, task.ErrIdempotencyConflict) {
		t.Fatalf("quote idempotency conflict error = %v", err)
	}

	planKey := uuid.NewString()
	createdPlan, err := store.CreatePlan(ctx, scope, postgres.CreatePlanCommand{IdempotencyKey: planKey, Plan: plan})
	if err != nil {
		t.Fatal(err)
	}
	replanned := plan
	replanned.PlanID = uuid.NewString()
	replayedPlan, err := store.CreatePlan(ctx, scope, postgres.CreatePlanCommand{IdempotencyKey: planKey, Plan: replanned})
	if err != nil {
		t.Fatal(err)
	}
	if replayedPlan.PlanID != createdPlan.PlanID {
		t.Fatalf("Plan replay ID = %q, want %q", replayedPlan.PlanID, createdPlan.PlanID)
	}
	conflictingPlan := replanned
	conflictingPlan.RetentionScope.GracePeriodSeconds++
	conflictingPlan.Quote.ScopeDigest, err = conflictingPlan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.CreatePlan(ctx, scope, postgres.CreatePlanCommand{IdempotencyKey: planKey, Plan: conflictingPlan}); !errors.Is(err, task.ErrIdempotencyConflict) {
		t.Fatalf("Plan idempotency conflict error = %v", err)
	}
	secondPlan := cloudApprovalPlanFixture(instanceID)
	secondQuote := cloudApprovalQuoteFixture(t, secondPlan, uuid.NewString(), now.Add(-30*time.Second))
	secondDigest, err := secondQuote.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondPlan.Quote.QuoteID = secondQuote.QuoteID
	secondPlan.Quote.Digest = secondDigest
	secondPlan.Quote.ValidUntil = secondQuote.ValidUntil
	if _, err = store.CreateQuote(ctx, scope, postgres.CreateQuoteCommand{IdempotencyKey: uuid.NewString(), Quote: secondQuote}); err != nil {
		t.Fatal(err)
	}
	if _, err = store.CreatePlan(ctx, scope, postgres.CreatePlanCommand{IdempotencyKey: uuid.NewString(), Plan: secondPlan}); err != nil {
		t.Fatal(err)
	}
	statuses, err := postgres.NewCloudStatusStore(store)
	if err != nil {
		t.Fatal(err)
	}
	firstPage, err := statuses.ListPlans(ctx, cloudstatus.ListQuery{OwnerID: plan.OwnerID, PageSize: 1})
	if err != nil || len(firstPage.Plans) != 1 || firstPage.NextPageToken == "" {
		t.Fatalf("first Plan page=%#v err=%v", firstPage, err)
	}
	secondPage, err := statuses.ListPlans(ctx, cloudstatus.ListQuery{OwnerID: plan.OwnerID, PageSize: 1, PageToken: firstPage.NextPageToken})
	if err != nil || len(secondPage.Plans) != 1 || secondPage.NextPageToken != "" || secondPage.Plans[0].PlanID == firstPage.Plans[0].PlanID {
		t.Fatalf("second Plan page=%#v err=%v", secondPage, err)
	}
	if _, err = statuses.ListPlans(ctx, cloudstatus.ListQuery{OwnerID: "different-owner", PageSize: 1, PageToken: firstPage.NextPageToken}); !errors.Is(err, cloudstatus.ErrInvalid) {
		t.Fatalf("cross-owner Plan cursor error=%v", err)
	}

	seed := bytes.Repeat([]byte{0x31}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	device := cloudapproval.DeviceKeyV1{
		KeyID: "approval-device-1", AgentInstanceID: instanceID, OwnerID: plan.OwnerID,
		Revision: 1, Status: cloudapproval.DeviceKeyActive, PublicKey: publicKey,
		NotBefore: now.Add(-time.Hour), ExpiresAt: now.Add(time.Hour),
	}
	registered, err := store.RegisterApprovalDevice(ctx, scope, postgres.RegisterApprovalDeviceCommand{
		IdempotencyKey: uuid.NewString(), Device: device,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(registered.PublicKey, publicKey) {
		t.Fatal("registered device public key changed")
	}

	adapter, err := postgres.NewApprovalRepositoryAdapter(store, scope, uuid.NewString(), uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	approvalService, err := cloudapproval.NewService(adapter, adapter, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	draft, err := approvalService.DraftChallenge(ctx, plan, createdQuote, device.KeyID)
	if err != nil {
		t.Fatal(err)
	}
	challengeKey := uuid.NewString()
	createdChallenge, err := store.CreateApprovalChallenge(ctx, scope, postgres.CreateApprovalChallengeCommand{
		IdempotencyKey: challengeKey, Challenge: draft,
	})
	if err != nil {
		t.Fatal(err)
	}
	reissued := draft
	reissued.ChallengeID = deterministicChallengeID(0x52)
	reissued.IssuedAt = draft.IssuedAt.Add(time.Second)
	reissued.ExpiresAt = draft.ExpiresAt.Add(-time.Second)
	replayedChallenge, err := store.CreateApprovalChallenge(ctx, scope, postgres.CreateApprovalChallengeCommand{
		IdempotencyKey: challengeKey, Challenge: reissued,
	})
	if err != nil {
		t.Fatal(err)
	}
	if replayedChallenge.ChallengeID != createdChallenge.ChallengeID || !replayedChallenge.IssuedAt.Equal(createdChallenge.IssuedAt) {
		t.Fatalf("challenge replay did not return stored response: %#v", replayedChallenge)
	}
	conflictingChallenge := reissued
	conflictingChallenge.SignerKeyID = "another-device"
	if _, err := store.CreateApprovalChallenge(ctx, scope, postgres.CreateApprovalChallengeCommand{
		IdempotencyKey: challengeKey, Challenge: conflictingChallenge,
	}); !errors.Is(err, task.ErrIdempotencyConflict) {
		t.Fatalf("challenge idempotency conflict error = %v", err)
	}

	firstApproval := signedCloudApproval(t, plan, createdChallenge, privateKey)
	secondApproval := signedCloudApproval(t, plan, createdChallenge, privateKey)
	commands := []postgres.ApprovePlanCommand{
		{IdempotencyKey: uuid.NewString(), ExpectedChallengeRevision: 1, ExpectedPlanRevision: 1, Approval: firstApproval},
		{IdempotencyKey: uuid.NewString(), ExpectedChallengeRevision: 1, ExpectedPlanRevision: 1, Approval: secondApproval},
	}
	results := make([]cloudapproval.PlanV1, len(commands))
	errorsByAttempt := make([]error, len(commands))
	var group sync.WaitGroup
	for index := range commands {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			results[index], errorsByAttempt[index] = store.ApprovePlan(ctx, scope, commands[index])
		}(index)
	}
	group.Wait()
	winner := -1
	for index, attemptErr := range errorsByAttempt {
		if attemptErr == nil {
			if winner != -1 {
				t.Fatalf("two approval transactions succeeded: %#v", errorsByAttempt)
			}
			winner = index
			continue
		}
		if !errors.Is(attemptErr, postgres.ErrCloudFactRevision) && !errors.Is(attemptErr, postgres.ErrCloudChallengeConsumed) {
			t.Fatalf("approval attempt %d failed unexpectedly: %v", index, attemptErr)
		}
	}
	if winner == -1 || results[winner].Status != cloudapproval.PlanApproved || results[winner].Revision != 2 {
		t.Fatalf("atomic approval result = %#v, errors=%#v", results, errorsByAttempt)
	}
	replayedApprovalPlan, err := store.ApprovePlan(ctx, scope, commands[winner])
	if err != nil {
		t.Fatal(err)
	}
	if replayedApprovalPlan.Status != cloudapproval.PlanApproved || replayedApprovalPlan.Revision != 2 {
		t.Fatalf("approval replay = %#v", replayedApprovalPlan)
	}

	restarted, err := postgres.New(pool, instanceID)
	if err != nil {
		t.Fatal(err)
	}
	storedPlan, err := restarted.GetPlan(ctx, plan.OwnerID, plan.PlanID)
	if err != nil {
		t.Fatal(err)
	}
	if storedPlan.Status != cloudapproval.PlanApproved || storedPlan.Revision != 2 {
		t.Fatalf("restarted Plan = %#v", storedPlan)
	}
	storedChallenge, err := restarted.GetChallenge(ctx, createdChallenge.ChallengeID)
	if err != nil {
		t.Fatal(err)
	}
	if storedChallenge.ConsumedAt == nil || storedChallenge.Revision != 2 {
		t.Fatalf("stored challenge = %#v", storedChallenge)
	}
	storedApproval, err := restarted.GetApproval(ctx, plan.OwnerID, commands[winner].Approval.ApprovalID)
	if err != nil {
		t.Fatal(err)
	}
	if storedApproval.Signature != commands[winner].Approval.Signature {
		t.Fatal("stored signed Approval changed")
	}
	if _, err := restarted.GetPlan(ctx, "different-owner", plan.PlanID); !errors.Is(err, postgres.ErrCloudFactScope) {
		t.Fatalf("cross-owner Plan read error = %v", err)
	}

	revokeKey := uuid.NewString()
	revoked, err := restarted.RevokeApprovalDevice(ctx, scope, postgres.RevokeApprovalDeviceCommand{
		IdempotencyKey: revokeKey, ExpectedRevision: 1, KeyID: device.KeyID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Status != cloudapproval.DeviceKeyRevoked || revoked.Revision != 2 || revoked.RevokedAt == nil {
		t.Fatalf("revoked device = %#v", revoked)
	}
	replayedRevocation, err := restarted.RevokeApprovalDevice(ctx, scope, postgres.RevokeApprovalDeviceCommand{
		IdempotencyKey: revokeKey, ExpectedRevision: 1, KeyID: device.KeyID,
	})
	if err != nil || replayedRevocation.Revision != 2 {
		t.Fatalf("revocation replay = %#v, %v", replayedRevocation, err)
	}
	if _, err := restarted.RevokeApprovalDevice(ctx, scope, postgres.RevokeApprovalDeviceCommand{
		IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, KeyID: device.KeyID,
	}); !errors.Is(err, postgres.ErrCloudFactRevision) {
		t.Fatalf("stale device revision error = %v", err)
	}

	assertCloudApprovalStorageSafety(t, ctx, pool, plan.SecretScope[0].SecretRef, storedApproval.Signature)
}

func cloudApprovalPlanFixture(instanceID string) cloudapproval.PlanV1 {
	plan := cloudapproval.PlanV1{
		SchemaVersion: cloudapproval.PlanSchemaV1, AgentInstanceID: instanceID, OwnerID: "owner-cloud-approval",
		PlanID: uuid.NewString(), Revision: 1, Status: cloudapproval.PlanReadyForConfirmation, ConnectionID: "connection-cloud-approval",
		Recipe: cloudapproval.RecipeBindingV1{RecipeID: "recipe-cloud-approval", Digest: cloudTestDigest("a"), Maturity: recipe.MaturityExperimental},
		Quote:  cloudapproval.QuoteBindingV1{Digest: cloudTestDigest("b"), ScopeDigest: cloudTestDigest("c"), CandidateID: string(cloudquote.CandidateRecommended), ValidUntil: time.Now().UTC().Add(15 * time.Minute)},
		ResourceScope: cloudapproval.ResourceScopeV1{
			Region: "us-east-1", AvailabilityZones: []string{"us-east-1a", "us-east-1b"}, InstanceType: "m7i.xlarge",
			InstanceCount: 1, Architecture: recipe.ArchitectureAMD64, VCPU: 4, MemoryMiB: 16384,
			DiskGiB: 80, VolumeType: "gp3", VolumeIOPS: 3000, VolumeThroughputMiBPS: 125, VolumeEncrypted: true,
			PurchaseOption: cloudapproval.PurchaseOnDemand, WorkerImageID: "ami-0123456789abcdef0", WorkerImageDigest: cloudTestDigest("d"),
		},
		NetworkScope: cloudapproval.NetworkScopeV1{
			VPCID: "vpc-0123456789abcdef0", SubnetID: "subnet-0123456789abcdef0", SecurityGroupID: "sg-0123456789abcdef0",
			EntryPoint: cloudapproval.EntryPointNone,
		},
		SecretScope:      []cloudapproval.SecretReferenceV1{{SecretRef: "secret_ref:approval/event-canary", Purpose: "model access", Delivery: recipe.SecretDeliveryFile}},
		IntegrationScope: []cloudapproval.IntegrationScopeV1{{Kind: cloudapproval.IntegrationMCP, Name: "service tools", Scopes: []string{"status.read"}}},
		RetentionScope:   cloudapproval.RetentionScopeV1{Class: cloudapproval.RetentionEphemeral, AutoDestroy: true, GracePeriodSeconds: 1800, MaxLifetimeSeconds: 86400},
	}
	plan.Quote.ScopeDigest, _ = plan.PricingScopeDigest()
	return plan
}

func cloudApprovalQuoteFixture(t *testing.T, plan cloudapproval.PlanV1, quoteID string, quotedAt time.Time) cloudquote.QuoteV1 {
	t.Helper()
	value := cloudquote.QuoteV1{
		SchemaVersion: cloudquote.SchemaV1, QuoteID: quoteID, QuotedAt: quotedAt.UTC(), ValidUntil: quotedAt.UTC().Add(cloudquote.Validity), Currency: "USD",
		Usage: cloudquote.UsageV1{RuntimeHoursPerMonth: 730}, Assumptions: []string{"one exclusive Worker instance"}, Exclusions: []string{"taxes and unplanned transfer"},
	}
	for _, profile := range []cloudquote.CandidateProfile{cloudquote.CandidateEconomic, cloudquote.CandidateRecommended, cloudquote.CandidatePerformance} {
		scope := plan.PricingScope()
		scope.Resource.CandidateID = profile
		scopeDigest, err := scope.Digest()
		if err != nil {
			t.Fatal(err)
		}
		items := []cloudquote.CostItemV1{
			cloudApprovalCost(cloudquote.CostComputeOnDemand, "EC2 compute", "compute-"+string(profile), 100000, 73000000, 100000),
			cloudApprovalCost(cloudquote.CostEBS, "encrypted EBS", "ebs-"+string(profile), 10000, 7300000, 10000),
			cloudApprovalCost(cloudquote.CostPublicIPv4, "public IPv4", "ipv4-"+string(profile), 0, 0, 0),
			cloudApprovalCost(cloudquote.CostLogs, "CloudWatch logs", "logs-"+string(profile), 1000, 730000, 1000),
			cloudApprovalCost(cloudquote.CostSnapshot, "EBS snapshots", "snapshot-"+string(profile), 1000, 730000, 1000),
			cloudApprovalCost(cloudquote.CostEntry, "public entry", "entry-"+string(profile), 0, 0, 0),
			cloudApprovalCost(cloudquote.CostTraffic, "data transfer", "traffic-"+string(profile), 1000, 730000, 1000),
		}
		value.Candidates = append(value.Candidates, cloudquote.CandidateV1{
			CandidateID: profile, Scope: scope, ScopeDigest: scopeDigest, OfferedAvailabilityZones: append([]string(nil), scope.Resource.AvailabilityZones...),
			Quotas:    []cloudquote.QuotaEvidenceV1{{ServiceCode: "ec2", QuotaCode: "L-1216C47A", LimitUnits: 64, UsedUnits: 4, RequiredUnits: 4}},
			CostItems: items, HourlyEstimateMicros: 113000, MonthlyEstimateMicros: 82490000, MaximumLaunchAmountMicros: 113000,
		})
	}
	if err := value.Validate(); err != nil {
		t.Fatalf("invalid cloud Quote fixture: %v", err)
	}
	return value
}

func cloudApprovalCost(category cloudquote.CostCategory, description, source string, hourly, monthly, launch uint64) cloudquote.CostItemV1 {
	return cloudquote.CostItemV1{Category: category, Description: description, SourceID: source, HourlyEstimateMicros: hourly, MonthlyEstimateMicros: monthly, MaximumLaunchAmountMicros: launch}
}

func signedCloudApproval(t *testing.T, plan cloudapproval.PlanV1, challenge cloudapproval.ChallengeV1, privateKey ed25519.PrivateKey) cloudapproval.ApprovalV1 {
	t.Helper()
	value, err := cloudapproval.NewApprovalV1(plan, uuid.NewString(), challenge.ChallengeID, challenge.SignerKeyID, challenge.ExpiresAt)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := value.SigningPayload()
	if err != nil {
		t.Fatal(err)
	}
	value.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return value
}

func deterministicChallengeID(fill byte) string {
	return "challenge_" + base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{fill}, 32))
}

func cloudTestDigest(fill string) string {
	return "sha256:" + strings.Repeat(fill, 64)
}

func assertCloudApprovalStorageSafety(t *testing.T, ctx context.Context, pool *pgxpool.Pool, secretReference, signature string) {
	t.Helper()
	var eventText string
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(string_agg(summary_json::text, ' '), '')
		FROM task_events WHERE aggregate_type IN ('cloud_quote','cloud_plan','approval_device','approval_challenge','cloud_approval')`).Scan(&eventText); err != nil {
		t.Fatal(err)
	}
	var outboxText string
	if err := pool.QueryRow(ctx, `
		SELECT COALESCE(string_agg(payload_json::text, ' '), '')
		FROM outbox_events WHERE topic LIKE 'cloud.%'`).Scan(&outboxText); err != nil {
		t.Fatal(err)
	}
	for _, persisted := range []string{eventText, outboxText} {
		if strings.Contains(persisted, secretReference) || strings.Contains(persisted, signature) {
			t.Fatal("event/outbox leaked secret reference detail or approval signature")
		}
	}
	var privateColumns int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema=current_schema() AND table_name='cloud_approval_devices' AND column_name LIKE '%private%'`).Scan(&privateColumns); err != nil {
		t.Fatal(err)
	}
	if privateColumns != 0 {
		t.Fatalf("approval device table has %d private-key columns", privateColumns)
	}
	var hourlyMicros int64
	if err := pool.QueryRow(ctx, `SELECT (quote_json #>> '{candidates,0,hourly_estimate_micros}')::bigint FROM cloud_quotes LIMIT 1`).Scan(&hourlyMicros); err != nil {
		t.Fatal(err)
	}
	if hourlyMicros != 113000 {
		t.Fatalf("stored exact hourly micros = %d", hourlyMicros)
	}
}
