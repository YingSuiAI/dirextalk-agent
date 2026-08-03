package teamlaunch

import (
	"errors"
	"math"
	"slices"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

const FreshQuoteSchemaV1 = "dirextalk.agent.team-fresh-launch-quote/v1"

var (
	ErrQuoteChanged        = errors.New("Team fresh launch quote changed")
	ErrQuoteBudgetExceeded = errors.New("Team fresh launch quote exceeds approval")
)

type FreshRoleQuoteV1 struct {
	RoleID               string `json:"role_id"`
	ComputeMaximumMicros uint64 `json:"compute_maximum_micros"`
	ModelMaximumMicros   uint64 `json:"model_maximum_micros"`
	FixedOverheadMicros  uint64 `json:"fixed_overhead_micros"`
	TotalMaximumMicros   uint64 `json:"total_maximum_micros"`
}

// FreshQuoteV1 is the exact, content-addressed price and capacity evidence
// required immediately before a provider create. It can reduce an approved
// cost, but it cannot expand any role or Team budget.
type FreshQuoteV1 struct {
	SchemaVersion          string                 `json:"schema_version"`
	AuthorizationID        string                 `json:"authorization_id"`
	AuthorizationDigest    string                 `json:"authorization_digest"`
	PlanID                 string                 `json:"plan_id"`
	PlanRevision           uint64                 `json:"plan_revision"`
	PlanDigest             string                 `json:"plan_digest"`
	ProviderScope          teamplan.ProviderScope `json:"provider_scope"`
	Region                 string                 `json:"region"`
	Currency               string                 `json:"currency"`
	SnapshotID             string                 `json:"snapshot_id"`
	SnapshotDigest         string                 `json:"snapshot_digest"`
	CapturedAt             time.Time              `json:"captured_at"`
	ValidUntil             time.Time              `json:"valid_until"`
	MaximumQuoteAgeSeconds uint64                 `json:"maximum_quote_age_seconds"`
	Roles                  []FreshRoleQuoteV1     `json:"roles"`
	TotalMaximumMicros     uint64                 `json:"total_maximum_micros"`
	HardBudgetMicros       uint64                 `json:"hard_budget_micros"`
}

func NewFreshQuoteV1(
	authorization AuthorizationV1,
	plan teamplan.Plan,
	snapshot *teamplan.OfferSnapshot,
	now time.Time,
) (FreshQuoteV1, error) {
	quote, err := buildFreshQuoteWithoutValidation(
		authorization,
		plan,
		snapshot,
		now,
	)
	if err != nil {
		return FreshQuoteV1{}, err
	}
	if quote.ValidateAgainst(authorization, plan, snapshot, now) != nil {
		return FreshQuoteV1{}, ErrQuoteChanged
	}
	return quote, nil
}

func (quote FreshQuoteV1) ValidateAgainst(
	authorization AuthorizationV1,
	plan teamplan.Plan,
	snapshot *teamplan.OfferSnapshot,
	now time.Time,
) error {
	if quote.Validate() != nil ||
		authorization.ValidateAt(now) != nil ||
		quote.ValidateAgainstAuthorization(authorization) != nil ||
		authorization.ValidateAgainst(plan) != nil ||
		snapshot == nil ||
		plan.Validate() != nil {
		return ErrQuoteChanged
	}
	expected, err := buildFreshQuoteWithoutValidation(
		authorization,
		plan,
		snapshot,
		now,
	)
	if err != nil {
		return err
	}
	left, err := canonical.Digest(quote)
	if err != nil {
		return ErrQuoteChanged
	}
	right, err := canonical.Digest(expected)
	if err != nil || left != right {
		return ErrQuoteChanged
	}
	return nil
}

// ValidateAgainstAuthorization verifies the immutable approval and budget
// boundaries without requiring the mutable offer snapshot. Recovery uses this
// to audit a persisted historic quote; it does not make an expired quote
// eligible for a new provider mutation.
func (quote FreshQuoteV1) ValidateAgainstAuthorization(
	authorization AuthorizationV1,
) error {
	if quote.Validate() != nil ||
		authorization.Validate() != nil {
		return ErrQuoteChanged
	}
	authorizationDigest, err := authorization.Digest()
	if err != nil ||
		quote.AuthorizationID != authorization.AuthorizationID ||
		quote.AuthorizationDigest != authorizationDigest ||
		quote.PlanID != authorization.PlanID ||
		quote.PlanRevision != authorization.PlanRevision ||
		quote.PlanDigest != authorization.PlanDigest ||
		quote.ProviderScope != authorization.ProviderScope ||
		quote.Region != authorization.Region ||
		quote.Currency != authorization.Currency ||
		quote.MaximumQuoteAgeSeconds !=
			authorization.MaximumQuoteAgeSeconds ||
		quote.HardBudgetMicros != authorization.HardBudgetMicros ||
		quote.CapturedAt.Before(authorization.LaunchNotBefore) ||
		!quote.CapturedAt.Before(authorization.LaunchNotAfter) ||
		quote.ValidUntil.After(authorization.LaunchNotAfter) ||
		len(quote.Roles) != len(authorization.Roles) {
		return ErrQuoteChanged
	}
	for index, role := range quote.Roles {
		approved := authorization.Roles[index]
		if role.RoleID != approved.RoleID ||
			role.TotalMaximumMicros >
				approved.MaximumApprovedCostMicros {
			return ErrQuoteBudgetExceeded
		}
	}
	return nil
}

func (quote FreshQuoteV1) Validate() error {
	if quote.SchemaVersion != FreshQuoteSchemaV1 ||
		!canonicalUUID(quote.AuthorizationID) ||
		!digestPattern.MatchString(quote.AuthorizationDigest) ||
		!canonicalUUID(quote.PlanID) ||
		quote.PlanRevision == 0 ||
		quote.PlanRevision > uint64(math.MaxInt64) ||
		!digestPattern.MatchString(quote.PlanDigest) ||
		quote.ProviderScope.Validate() != nil ||
		quote.ProviderScope.Provider != teamplan.CloudProviderAWS ||
		!validRegion(quote.Region) ||
		!currencyPattern.MatchString(quote.Currency) ||
		!canonicalUUID(quote.SnapshotID) ||
		!digestPattern.MatchString(quote.SnapshotDigest) ||
		!utcMicrosecond(quote.CapturedAt) ||
		!utcMicrosecond(quote.ValidUntil) ||
		!quote.CapturedAt.Before(quote.ValidUntil) ||
		quote.MaximumQuoteAgeSeconds == 0 ||
		quote.MaximumQuoteAgeSeconds > maximumQuoteAgeSeconds ||
		quote.ValidUntil.Sub(quote.CapturedAt) > time.Duration(
			quote.MaximumQuoteAgeSeconds,
		)*time.Second ||
		len(quote.Roles) == 0 ||
		len(quote.Roles) > 8 ||
		!slices.IsSortedFunc(
			quote.Roles,
			func(left, right FreshRoleQuoteV1) int {
				switch {
				case left.RoleID < right.RoleID:
					return -1
				case left.RoleID > right.RoleID:
					return 1
				default:
					return 0
				}
			},
		) ||
		quote.HardBudgetMicros == 0 ||
		quote.HardBudgetMicros > maximumPlanCostMicros {
		return ErrQuoteChanged
	}
	var total uint64
	seen := make(map[string]struct{}, len(quote.Roles))
	for _, role := range quote.Roles {
		if !validRoleID(role.RoleID) ||
			role.ComputeMaximumMicros == 0 ||
			role.TotalMaximumMicros == 0 {
			return ErrQuoteChanged
		}
		if _, duplicate := seen[role.RoleID]; duplicate {
			return ErrQuoteChanged
		}
		base, err := checkedFreshQuoteSum(
			role.ComputeMaximumMicros,
			role.ModelMaximumMicros,
			role.FixedOverheadMicros,
		)
		if err != nil || base != role.TotalMaximumMicros ||
			math.MaxUint64-total < role.TotalMaximumMicros {
			return ErrQuoteChanged
		}
		seen[role.RoleID] = struct{}{}
		total += role.TotalMaximumMicros
	}
	if total != quote.TotalMaximumMicros ||
		total > quote.HardBudgetMicros {
		return ErrQuoteBudgetExceeded
	}
	return nil
}

func (quote FreshQuoteV1) Digest() (string, error) {
	if quote.Validate() != nil {
		return "", ErrQuoteChanged
	}
	return canonical.Digest(quote)
}

func checkedFreshQuoteSum(values ...uint64) (uint64, error) {
	var result uint64
	for _, value := range values {
		if math.MaxUint64-result < value {
			return 0, ErrQuoteChanged
		}
		result += value
	}
	return result, nil
}

func buildFreshQuoteWithoutValidation(
	authorization AuthorizationV1,
	plan teamplan.Plan,
	snapshot *teamplan.OfferSnapshot,
	now time.Time,
) (FreshQuoteV1, error) {
	if authorization.ValidateAt(now) != nil ||
		authorization.ValidateAgainst(plan) != nil ||
		snapshot == nil {
		return FreshQuoteV1{}, ErrQuoteChanged
	}
	current, err := snapshot.QuoteCurrentPlan(plan, now)
	if err != nil {
		return FreshQuoteV1{}, err
	}
	authorizationDigest, err := authorization.Digest()
	if err != nil ||
		now.UTC().Before(current.CapturedAt) ||
		now.UTC().Sub(current.CapturedAt) >
			time.Duration(authorization.MaximumQuoteAgeSeconds)*time.Second {
		return FreshQuoteV1{}, ErrQuoteChanged
	}
	approvedByRole := make(map[string]RoleLaunchV1, len(authorization.Roles))
	for _, role := range authorization.Roles {
		approvedByRole[role.RoleID] = role
	}
	roles := make([]FreshRoleQuoteV1, 0, len(current.Roles))
	for _, role := range current.Roles {
		approved, found := approvedByRole[role.RoleID]
		if !found {
			return FreshQuoteV1{}, ErrQuoteChanged
		}
		if role.TotalMaximumMicros >
			approved.MaximumApprovedCostMicros {
			return FreshQuoteV1{}, ErrQuoteBudgetExceeded
		}
		roles = append(roles, FreshRoleQuoteV1{
			RoleID:               role.RoleID,
			ComputeMaximumMicros: role.ComputeMaximumMicros,
			ModelMaximumMicros:   role.ModelMaximumMicros,
			FixedOverheadMicros:  role.FixedOverheadMicros,
			TotalMaximumMicros:   role.TotalMaximumMicros,
		})
	}
	if len(roles) != len(authorization.Roles) ||
		current.TotalMaximumMicros > authorization.HardBudgetMicros {
		return FreshQuoteV1{}, ErrQuoteBudgetExceeded
	}
	validUntil := current.CapturedAt.Add(
		time.Duration(authorization.MaximumQuoteAgeSeconds) * time.Second,
	)
	if current.ValidUntil.Before(validUntil) {
		validUntil = current.ValidUntil
	}
	if authorization.LaunchNotAfter.Before(validUntil) {
		validUntil = authorization.LaunchNotAfter
	}
	return FreshQuoteV1{
		SchemaVersion:          FreshQuoteSchemaV1,
		AuthorizationID:        authorization.AuthorizationID,
		AuthorizationDigest:    authorizationDigest,
		PlanID:                 authorization.PlanID,
		PlanRevision:           authorization.PlanRevision,
		PlanDigest:             authorization.PlanDigest,
		ProviderScope:          current.ProviderScope,
		Region:                 current.Region,
		Currency:               current.Currency,
		SnapshotID:             current.SnapshotID,
		SnapshotDigest:         current.SnapshotDigest,
		CapturedAt:             current.CapturedAt,
		ValidUntil:             validUntil,
		MaximumQuoteAgeSeconds: authorization.MaximumQuoteAgeSeconds,
		Roles:                  roles,
		TotalMaximumMicros:     current.TotalMaximumMicros,
		HardBudgetMicros:       authorization.HardBudgetMicros,
	}, nil
}
