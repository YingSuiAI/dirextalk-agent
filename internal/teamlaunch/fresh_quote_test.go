package teamlaunch

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

func TestFreshQuoteRepricesApprovedFactsWithoutExpandingBudget(
	t *testing.T,
) {
	t.Parallel()
	plan := validTeamPlan()
	authorization := validAuthorization(t)
	capturedAt := authorization.LaunchNotBefore
	snapshot := freshQuoteSnapshot(t, plan, capturedAt, 100_000, 2_000_000, 8_000_000)
	now := capturedAt.Add(time.Minute)

	quote, err := NewFreshQuoteV1(
		authorization,
		plan,
		snapshot,
		now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(quote.Roles) != 1 ||
		quote.Roles[0].RoleID != "implementation" ||
		quote.Roles[0].ComputeMaximumMicros != 77_500 ||
		quote.Roles[0].ModelMaximumMicros != 320_000 ||
		quote.Roles[0].FixedOverheadMicros != 10_000 ||
		quote.Roles[0].TotalMaximumMicros != 407_500 ||
		quote.TotalMaximumMicros != 407_500 ||
		quote.HardBudgetMicros != authorization.HardBudgetMicros ||
		!quote.ValidUntil.Equal(capturedAt.Add(15*time.Minute)) {
		t.Fatalf("unexpected fresh quote: %#v", quote)
	}
	if err := quote.ValidateAgainst(
		authorization,
		plan,
		snapshot,
		now,
	); err != nil {
		t.Fatalf("ValidateAgainst() error = %v", err)
	}
	digest, err := quote.Digest()
	if err != nil || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("Digest() = %q, %v", digest, err)
	}

	tampered := quote
	tampered.Roles = append([]FreshRoleQuoteV1(nil), quote.Roles...)
	tampered.Roles[0].TotalMaximumMicros--
	if err := tampered.ValidateAgainst(
		authorization,
		plan,
		snapshot,
		now,
	); !errors.Is(err, ErrQuoteChanged) {
		t.Fatalf(
			"tampered ValidateAgainst() error = %v, want ErrQuoteChanged",
			err,
		)
	}
}

func TestFreshQuoteRejectsCostIdentityCapacityAndFreshnessDrift(
	t *testing.T,
) {
	t.Parallel()
	plan := validTeamPlan()
	baseAuthorization := validAuthorization(t)
	capturedAt := baseAuthorization.LaunchNotBefore
	tests := []struct {
		name          string
		authorization func() AuthorizationV1
		snapshot      func(*testing.T) *teamplan.OfferSnapshot
		now           time.Time
		want          error
	}{
		{
			name: "role maximum exceeded",
			authorization: func() AuthorizationV1 {
				return baseAuthorization
			},
			snapshot: func(t *testing.T) *teamplan.OfferSnapshot {
				return freshQuoteSnapshot(
					t,
					plan,
					capturedAt,
					200_000,
					5_000_000,
					25_000_000,
				)
			},
			now:  capturedAt.Add(time.Minute),
			want: ErrQuoteBudgetExceeded,
		},
		{
			name: "model identity changed",
			authorization: func() AuthorizationV1 {
				return baseAuthorization
			},
			snapshot: func(t *testing.T) *teamplan.OfferSnapshot {
				document := freshQuoteSnapshotDocument(
					plan,
					capturedAt,
					100_000,
					2_000_000,
					8_000_000,
				)
				document.ModelOffers[0].Model = "substituted-model"
				snapshot, err := teamplan.NewOfferSnapshot(document)
				if err != nil {
					t.Fatal(err)
				}
				return snapshot
			},
			now:  capturedAt.Add(time.Minute),
			want: teamplan.ErrPricingChanged,
		},
		{
			name: "capacity unavailable",
			authorization: func() AuthorizationV1 {
				return baseAuthorization
			},
			snapshot: func(t *testing.T) *teamplan.OfferSnapshot {
				document := freshQuoteSnapshotDocument(
					plan,
					capturedAt,
					100_000,
					2_000_000,
					8_000_000,
				)
				document.ComputeOffers[0].Available = false
				snapshot, err := teamplan.NewOfferSnapshot(document)
				if err != nil {
					t.Fatal(err)
				}
				return snapshot
			},
			now:  capturedAt.Add(time.Minute),
			want: teamplan.ErrPricingChanged,
		},
		{
			name: "quote older than authorization maximum",
			authorization: func() AuthorizationV1 {
				value := baseAuthorization
				value.MaximumQuoteAgeSeconds = 60
				return value
			},
			snapshot: func(t *testing.T) *teamplan.OfferSnapshot {
				return freshQuoteSnapshot(
					t,
					plan,
					capturedAt,
					100_000,
					2_000_000,
					8_000_000,
				)
			},
			now:  capturedAt.Add(61 * time.Second),
			want: ErrQuoteChanged,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewFreshQuoteV1(
				test.authorization(),
				plan,
				test.snapshot(t),
				test.now,
			)
			if !errors.Is(err, test.want) {
				t.Fatalf(
					"NewFreshQuoteV1() error = %v, want %v",
					err,
					test.want,
				)
			}
		})
	}
}

func freshQuoteSnapshot(
	t *testing.T,
	plan teamplan.Plan,
	capturedAt time.Time,
	hourlyMicros,
	inputMicros,
	outputMicros uint64,
) *teamplan.OfferSnapshot {
	t.Helper()
	snapshot, err := teamplan.NewOfferSnapshot(
		freshQuoteSnapshotDocument(
			plan,
			capturedAt,
			hourlyMicros,
			inputMicros,
			outputMicros,
		),
	)
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func freshQuoteSnapshotDocument(
	plan teamplan.Plan,
	capturedAt time.Time,
	hourlyMicros,
	inputMicros,
	outputMicros uint64,
) teamplan.OfferSnapshotDocument {
	assignment := plan.Assignments[0]
	digest := func(value string) string {
		return "sha256:" + strings.Repeat(value, 64)
	}
	return teamplan.OfferSnapshotDocument{
		SchemaVersion: teamplan.OfferSnapshotSchemaV1,
		SnapshotID:    "99999999-9999-4999-8999-999999999999",
		ProviderScope: plan.ProviderScope,
		Region:        plan.Region,
		Currency:      plan.Cost.Currency,
		CapturedAt:    capturedAt,
		ValidUntil:    capturedAt.Add(teamplan.OfferSnapshotValidity),
		Sources: []teamplan.OfferSourceReceipt{
			{
				Kind:       teamplan.OfferSourceModelPricing,
				SourceID:   "test:model-pricing",
				Digest:     digest("1"),
				CapturedAt: capturedAt,
			},
			{
				Kind:       teamplan.OfferSourceComputePricing,
				SourceID:   "test:compute-pricing",
				Digest:     digest("2"),
				CapturedAt: capturedAt,
			},
			{
				Kind:       teamplan.OfferSourceComputeCapacity,
				SourceID:   "test:compute-capacity",
				Digest:     digest("3"),
				CapturedAt: capturedAt,
			},
			{
				Kind:       teamplan.OfferSourceComputeConfig,
				SourceID:   "test:compute-config",
				Digest:     digest("4"),
				CapturedAt: capturedAt,
			},
		},
		ModelOffers: []teamplan.ModelOffer{{
			ProfileID:              assignment.ModelProfileID,
			Provider:               assignment.ModelProvider,
			Model:                  assignment.Model,
			Interface:              assignment.ModelInterface,
			Quality:                teamplan.QualityPremium,
			ContextTokens:          256_000,
			InputMicrosPerMillion:  inputMicros,
			OutputMicrosPerMillion: outputMicros,
			CredentialRef:          assignment.ModelCredentialRef,
			Enabled:                true,
			CredentialReady:        true,
		}},
		ComputeOffers: []teamplan.ComputeOffer{{
			OfferID:        assignment.ComputeOfferID,
			Region:         plan.Region,
			InstanceType:   assignment.InstanceType,
			Architecture:   assignment.Resources.Arch,
			VCPU:           assignment.Resources.VCPU,
			MemoryMiB:      assignment.Resources.MemoryMiB,
			DiskGiB:        assignment.Resources.DiskGiB,
			HourlyMicros:   hourlyMicros,
			PurchaseOption: "on_demand",
			CapacityPool:   "aws:ec2-quota:L-1216C47A",
			CapacityUnits:  uint64(assignment.Resources.VCPU),
			AvailableUnits: 64,
			Available:      true,
		}},
	}
}
