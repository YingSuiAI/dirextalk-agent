package teamapproval

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/google/uuid"
)

var (
	ErrInvalid          = errors.New("invalid Team Plan approval")
	ErrExpired          = errors.New("Team Plan approval expired")
	ErrPlanChanged      = errors.New("Team Plan changed after challenge")
	ErrSignatureInvalid = errors.New("invalid Team Plan approval signature")
)

var (
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	currencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
	keyIDPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
)

const (
	maximumPlanCostMicros = 10_000_000_000_000
	maximumWallSeconds    = 64 * 24 * 60 * 60
)

type signingDocumentV1 struct {
	PayloadSchema        string    `json:"payload_schema"`
	HashAlgorithm        string    `json:"hash_algorithm"`
	ChallengeSchema      string    `json:"challenge_schema"`
	Revision             uint64    `json:"revision"`
	ApprovalID           string    `json:"approval_id"`
	ChallengeID          string    `json:"challenge_id"`
	AgentInstanceID      string    `json:"agent_instance_id"`
	OwnerID              string    `json:"owner_id"`
	PlanID               string    `json:"plan_id"`
	PlanRevision         uint64    `json:"plan_revision"`
	PlanDigest           string    `json:"plan_digest"`
	GoalDigest           string    `json:"goal_digest"`
	CatalogRevision      string    `json:"catalog_revision"`
	PricingSnapshotID    string    `json:"pricing_snapshot_id"`
	QuotedAt             time.Time `json:"quoted_at"`
	QuoteValidUntil      time.Time `json:"quote_valid_until"`
	WorkerCount          uint32    `json:"worker_count"`
	MaxConcurrentWorkers uint32    `json:"max_concurrent_workers"`
	Currency             string    `json:"currency"`
	MinimumCostMicros    uint64    `json:"minimum_cost_micros"`
	ExpectedCostMicros   uint64    `json:"expected_cost_micros"`
	MaximumCostMicros    uint64    `json:"maximum_cost_micros"`
	HardBudgetMicros     uint64    `json:"hard_budget_micros"`
	MinimumWallSeconds   uint64    `json:"minimum_wall_seconds"`
	ExpectedWallSeconds  uint64    `json:"expected_wall_seconds"`
	MaximumWallSeconds   uint64    `json:"maximum_wall_seconds"`
	SignerKeyID          string    `json:"signer_key_id"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

func NewChallengeV1(
	plan teamplan.Plan,
	agentInstanceID,
	approvalID,
	challengeID,
	signerKeyID string,
	issuedAt time.Time,
) (ChallengeV1, error) {
	if err := plan.Validate(); err != nil ||
		!canonicalUUID(agentInstanceID) ||
		!canonicalUUID(approvalID) ||
		!canonicalUUID(challengeID) ||
		!safeKeyID(signerKeyID) ||
		issuedAt.IsZero() {
		return ChallengeV1{}, ErrInvalid
	}
	issuedAt = issuedAt.UTC().Truncate(time.Microsecond)
	if !issuedAt.Before(plan.ValidUntil) {
		return ChallengeV1{}, ErrExpired
	}
	expiresAt := issuedAt.Add(ChallengeValidity)
	if plan.ValidUntil.Before(expiresAt) {
		expiresAt = plan.ValidUntil.UTC()
	}
	planDigest, err := plan.Digest()
	if err != nil {
		return ChallengeV1{}, ErrInvalid
	}
	challenge := ChallengeV1{
		SchemaVersion: ChallengeSchemaV1, Revision: 1,
		ApprovalID: approvalID, ChallengeID: challengeID,
		AgentInstanceID: agentInstanceID, OwnerID: plan.OwnerID,
		PlanID: plan.PlanID, PlanRevision: plan.Revision,
		PlanDigest: planDigest, GoalDigest: plan.GoalDigest,
		CatalogRevision:   plan.CatalogRevision,
		PricingSnapshotID: plan.PricingSnapshotID,
		QuotedAt:          plan.QuotedAt.UTC(), QuoteValidUntil: plan.ValidUntil.UTC(),
		WorkerCount:          plan.WorkerCount,
		MaxConcurrentWorkers: plan.MaxConcurrentWorkers,
		Currency:             plan.Cost.Currency,
		MinimumCostMicros:    plan.Cost.MinimumMicros,
		ExpectedCostMicros:   plan.Cost.ExpectedMicros,
		MaximumCostMicros:    plan.Cost.MaximumMicros,
		HardBudgetMicros:     plan.Cost.HardBudgetMicros,
		MinimumWallSeconds:   seconds(plan.Schedule.MinimumWallTime),
		ExpectedWallSeconds:  seconds(plan.Schedule.ExpectedWallTime),
		MaximumWallSeconds:   seconds(plan.Schedule.MaximumWallTime),
		SignerKeyID:          signerKeyID, IssuedAt: issuedAt, ExpiresAt: expiresAt,
	}
	if err := challenge.ValidateAt(issuedAt); err != nil {
		return ChallengeV1{}, err
	}
	return challenge, nil
}

func (challenge ChallengeV1) ValidateAt(now time.Time) error {
	if challenge.SchemaVersion != ChallengeSchemaV1 ||
		challenge.Revision != 1 ||
		!canonicalUUID(challenge.ApprovalID) ||
		!canonicalUUID(challenge.ChallengeID) ||
		!canonicalUUID(challenge.AgentInstanceID) ||
		!safeOwnerID(challenge.OwnerID) ||
		!canonicalUUID(challenge.PlanID) ||
		challenge.PlanRevision == 0 ||
		!digestPattern.MatchString(challenge.PlanDigest) ||
		!digestPattern.MatchString(challenge.GoalDigest) ||
		!digestPattern.MatchString(challenge.CatalogRevision) ||
		!canonicalUUID(challenge.PricingSnapshotID) ||
		!utcMicrosecond(challenge.QuotedAt) ||
		!utcMicrosecond(challenge.QuoteValidUntil) ||
		challenge.WorkerCount == 0 ||
		challenge.WorkerCount > 8 ||
		challenge.MaxConcurrentWorkers == 0 ||
		challenge.MaxConcurrentWorkers > challenge.WorkerCount ||
		!currencyPattern.MatchString(challenge.Currency) ||
		challenge.MinimumCostMicros > challenge.ExpectedCostMicros ||
		challenge.ExpectedCostMicros > challenge.MaximumCostMicros ||
		challenge.HardBudgetMicros == 0 ||
		challenge.HardBudgetMicros > maximumPlanCostMicros ||
		challenge.MaximumCostMicros > challenge.HardBudgetMicros ||
		challenge.MinimumWallSeconds == 0 ||
		challenge.MinimumWallSeconds > challenge.ExpectedWallSeconds ||
		challenge.ExpectedWallSeconds > challenge.MaximumWallSeconds ||
		challenge.MaximumWallSeconds > maximumWallSeconds ||
		!safeKeyID(challenge.SignerKeyID) ||
		!utcMicrosecond(challenge.IssuedAt) ||
		!utcMicrosecond(challenge.ExpiresAt) ||
		!challenge.QuotedAt.Before(challenge.QuoteValidUntil) ||
		challenge.IssuedAt.Before(challenge.QuotedAt) ||
		!challenge.IssuedAt.Before(challenge.ExpiresAt) ||
		challenge.ExpiresAt.After(challenge.QuoteValidUntil) ||
		challenge.ExpiresAt.Sub(challenge.IssuedAt) > ChallengeValidity {
		return ErrInvalid
	}
	if now.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	if now.Before(challenge.IssuedAt.Add(-30*time.Second)) ||
		!now.Before(challenge.ExpiresAt) ||
		!now.Before(challenge.QuoteValidUntil) {
		return ErrExpired
	}
	return nil
}

func (challenge ChallengeV1) SigningPayload() ([]byte, error) {
	if err := challenge.ValidateAt(challenge.IssuedAt); err != nil {
		return nil, err
	}
	return canonical.Marshal(signingDocumentV1{
		PayloadSchema:   SigningPayloadSchemaV1,
		HashAlgorithm:   canonical.Algorithm,
		ChallengeSchema: challenge.SchemaVersion,
		Revision:        challenge.Revision,
		ApprovalID:      challenge.ApprovalID,
		ChallengeID:     challenge.ChallengeID,
		AgentInstanceID: challenge.AgentInstanceID,
		OwnerID:         challenge.OwnerID,
		PlanID:          challenge.PlanID, PlanRevision: challenge.PlanRevision,
		PlanDigest: challenge.PlanDigest, GoalDigest: challenge.GoalDigest,
		CatalogRevision:   challenge.CatalogRevision,
		PricingSnapshotID: challenge.PricingSnapshotID,
		QuotedAt:          challenge.QuotedAt, QuoteValidUntil: challenge.QuoteValidUntil,
		WorkerCount:          challenge.WorkerCount,
		MaxConcurrentWorkers: challenge.MaxConcurrentWorkers,
		Currency:             challenge.Currency,
		MinimumCostMicros:    challenge.MinimumCostMicros,
		ExpectedCostMicros:   challenge.ExpectedCostMicros,
		MaximumCostMicros:    challenge.MaximumCostMicros,
		HardBudgetMicros:     challenge.HardBudgetMicros,
		MinimumWallSeconds:   challenge.MinimumWallSeconds,
		ExpectedWallSeconds:  challenge.ExpectedWallSeconds,
		MaximumWallSeconds:   challenge.MaximumWallSeconds,
		SignerKeyID:          challenge.SignerKeyID,
		IssuedAt:             challenge.IssuedAt, ExpiresAt: challenge.ExpiresAt,
	})
}

func Verify(
	challenge ChallengeV1,
	signature SignatureV1,
	plan teamplan.Plan,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if err := challenge.ValidateAt(now); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize ||
		signature.SchemaVersion != SignatureSchemaV1 ||
		signature.ApprovalID != challenge.ApprovalID ||
		signature.ChallengeID != challenge.ChallengeID ||
		signature.PlanID != challenge.PlanID ||
		signature.PlanRevision != challenge.PlanRevision ||
		signature.PlanDigest != challenge.PlanDigest ||
		signature.SignerKeyID != challenge.SignerKeyID {
		return ErrSignatureInvalid
	}
	if err := challenge.matchesPlan(plan); err != nil {
		return err
	}
	decoded, err := base64.RawURLEncoding.DecodeString(
		signature.SignatureBase64URL,
	)
	if err != nil || len(decoded) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(decoded) !=
			signature.SignatureBase64URL {
		return ErrSignatureInvalid
	}
	payload, err := challenge.SigningPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, decoded) {
		return ErrSignatureInvalid
	}
	return nil
}

func (challenge ChallengeV1) matchesPlan(plan teamplan.Plan) error {
	if err := plan.Validate(); err != nil {
		return ErrPlanChanged
	}
	digest, err := plan.Digest()
	if err != nil ||
		plan.PlanID != challenge.PlanID ||
		plan.Revision != challenge.PlanRevision ||
		plan.OwnerID != challenge.OwnerID ||
		digest != challenge.PlanDigest ||
		plan.GoalDigest != challenge.GoalDigest ||
		plan.CatalogRevision != challenge.CatalogRevision ||
		plan.PricingSnapshotID != challenge.PricingSnapshotID ||
		!plan.QuotedAt.Equal(challenge.QuotedAt) ||
		!plan.ValidUntil.Equal(challenge.QuoteValidUntil) ||
		plan.WorkerCount != challenge.WorkerCount ||
		plan.MaxConcurrentWorkers != challenge.MaxConcurrentWorkers ||
		plan.Cost.Currency != challenge.Currency ||
		plan.Cost.MinimumMicros != challenge.MinimumCostMicros ||
		plan.Cost.ExpectedMicros != challenge.ExpectedCostMicros ||
		plan.Cost.MaximumMicros != challenge.MaximumCostMicros ||
		plan.Cost.HardBudgetMicros != challenge.HardBudgetMicros ||
		seconds(plan.Schedule.MinimumWallTime) !=
			challenge.MinimumWallSeconds ||
		seconds(plan.Schedule.ExpectedWallTime) !=
			challenge.ExpectedWallSeconds ||
		seconds(plan.Schedule.MaximumWallTime) !=
			challenge.MaximumWallSeconds {
		return ErrPlanChanged
	}
	return nil
}

func canonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func safeOwnerID(value string) bool {
	if value != strings.TrimSpace(value) ||
		len(value) == 0 || len(value) > 255 ||
		!utf8.ValidString(value) ||
		security.ContainsLikelySecret(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func safeKeyID(value string) bool {
	return keyIDPattern.MatchString(value) &&
		!security.ContainsLikelySecret(value)
}

func utcMicrosecond(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC &&
		value.Nanosecond()%1000 == 0
}

func seconds(value time.Duration) uint64 {
	return uint64(value / time.Second)
}
