package teamapproval

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamlaunch"
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
	PayloadSchema         string                 `json:"payload_schema"`
	HashAlgorithm         string                 `json:"hash_algorithm"`
	ChallengeSchema       string                 `json:"challenge_schema"`
	Revision              uint64                 `json:"revision"`
	ApprovalID            string                 `json:"approval_id"`
	ChallengeID           string                 `json:"challenge_id"`
	AgentInstanceID       string                 `json:"agent_instance_id"`
	OwnerID               string                 `json:"owner_id"`
	PlanID                string                 `json:"plan_id"`
	PlanRevision          uint64                 `json:"plan_revision"`
	PlanDigest            string                 `json:"plan_digest"`
	GoalDigest            string                 `json:"goal_digest"`
	ProviderScope         teamplan.ProviderScope `json:"provider_scope"`
	CatalogRevision       string                 `json:"catalog_revision"`
	PolicyRevision        string                 `json:"policy_revision"`
	PricingSnapshotID     string                 `json:"pricing_snapshot_id"`
	PricingSnapshotDigest string                 `json:"pricing_snapshot_digest"`
	QuotedAt              time.Time              `json:"quoted_at"`
	QuoteValidUntil       time.Time              `json:"quote_valid_until"`
	WorkerCount           uint32                 `json:"worker_count"`
	MaxConcurrentWorkers  uint32                 `json:"max_concurrent_workers"`
	Currency              string                 `json:"currency"`
	MinimumCostMicros     uint64                 `json:"minimum_cost_micros"`
	ExpectedCostMicros    uint64                 `json:"expected_cost_micros"`
	MaximumCostMicros     uint64                 `json:"maximum_cost_micros"`
	HardBudgetMicros      uint64                 `json:"hard_budget_micros"`
	MinimumWallSeconds    uint64                 `json:"minimum_wall_seconds"`
	ExpectedWallSeconds   uint64                 `json:"expected_wall_seconds"`
	MaximumWallSeconds    uint64                 `json:"maximum_wall_seconds"`
	SignerKeyID           string                 `json:"signer_key_id"`
	IssuedAt              time.Time              `json:"issued_at"`
	ExpiresAt             time.Time              `json:"expires_at"`
}

type signingDocumentV2 struct {
	PayloadSchema             string                 `json:"payload_schema"`
	HashAlgorithm             string                 `json:"hash_algorithm"`
	ChallengeSchema           string                 `json:"challenge_schema"`
	Revision                  uint64                 `json:"revision"`
	ApprovalID                string                 `json:"approval_id"`
	ChallengeID               string                 `json:"challenge_id"`
	AgentInstanceID           string                 `json:"agent_instance_id"`
	OwnerID                   string                 `json:"owner_id"`
	PlanID                    string                 `json:"plan_id"`
	PlanRevision              uint64                 `json:"plan_revision"`
	PlanDigest                string                 `json:"plan_digest"`
	GoalDigest                string                 `json:"goal_digest"`
	ProviderScope             teamplan.ProviderScope `json:"provider_scope"`
	CatalogRevision           string                 `json:"catalog_revision"`
	PolicyRevision            string                 `json:"policy_revision"`
	PricingSnapshotID         string                 `json:"pricing_snapshot_id"`
	PricingSnapshotDigest     string                 `json:"pricing_snapshot_digest"`
	QuotedAt                  time.Time              `json:"quoted_at"`
	QuoteValidUntil           time.Time              `json:"quote_valid_until"`
	WorkerCount               uint32                 `json:"worker_count"`
	MaxConcurrentWorkers      uint32                 `json:"max_concurrent_workers"`
	Currency                  string                 `json:"currency"`
	MinimumCostMicros         uint64                 `json:"minimum_cost_micros"`
	ExpectedCostMicros        uint64                 `json:"expected_cost_micros"`
	MaximumCostMicros         uint64                 `json:"maximum_cost_micros"`
	HardBudgetMicros          uint64                 `json:"hard_budget_micros"`
	MinimumWallSeconds        uint64                 `json:"minimum_wall_seconds"`
	ExpectedWallSeconds       uint64                 `json:"expected_wall_seconds"`
	MaximumWallSeconds        uint64                 `json:"maximum_wall_seconds"`
	LaunchAuthorizationID     string                 `json:"launch_authorization_id"`
	LaunchAuthorizationDigest string                 `json:"launch_authorization_digest"`
	SignerKeyID               string                 `json:"signer_key_id"`
	IssuedAt                  time.Time              `json:"issued_at"`
	ExpiresAt                 time.Time              `json:"expires_at"`
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
		ProviderScope:         plan.ProviderScope,
		CatalogRevision:       plan.CatalogRevision,
		PolicyRevision:        plan.PolicyRevision,
		PricingSnapshotID:     plan.PricingSnapshotID,
		PricingSnapshotDigest: plan.PricingSnapshotDigest,
		QuotedAt:              plan.QuotedAt.UTC(), QuoteValidUntil: plan.ValidUntil.UTC(),
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

// NewChallengeV2 binds the exact AWS launch authorization into the same device
// signature as the Team Plan. It intentionally does not bind an Execution
// digest because Execution is derived only after this approval exists.
func NewChallengeV2(
	plan teamplan.Plan,
	authorization teamlaunch.AuthorizationV1,
	agentInstanceID,
	approvalID,
	challengeID,
	signerKeyID string,
	issuedAt time.Time,
) (ChallengeV1, error) {
	challenge, err := NewChallengeV1(
		plan,
		agentInstanceID,
		approvalID,
		challengeID,
		signerKeyID,
		issuedAt,
	)
	if err != nil {
		return ChallengeV1{}, err
	}
	issuedAt = issuedAt.UTC().Truncate(time.Microsecond)
	if authorization.ValidateAt(issuedAt) != nil ||
		authorization.ValidateAgainst(plan) != nil ||
		authorization.AgentInstanceID != agentInstanceID ||
		authorization.OwnerID != plan.OwnerID ||
		authorization.ApprovalID != approvalID {
		return ChallengeV1{}, ErrInvalid
	}
	authorizationDigest, err := authorization.Digest()
	if err != nil {
		return ChallengeV1{}, ErrInvalid
	}
	challenge.SchemaVersion = ChallengeSchemaV2
	challenge.LaunchAuthorizationID = authorization.AuthorizationID
	challenge.LaunchAuthorizationDigest = authorizationDigest
	if authorization.LaunchNotAfter.Before(challenge.ExpiresAt) {
		challenge.ExpiresAt = authorization.LaunchNotAfter
	}
	if err := challenge.ValidateAt(issuedAt); err != nil {
		return ChallengeV1{}, err
	}
	return challenge, nil
}

func (challenge ChallengeV1) ValidateAt(now time.Time) error {
	if err := challenge.Validate(); err != nil {
		return err
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

// Validate checks the immutable challenge document without applying a
// current-time expiry decision. Persistence readers use it to verify historic
// consumed or expired records.
func (challenge ChallengeV1) Validate() error {
	if (challenge.SchemaVersion != ChallengeSchemaV1 &&
		challenge.SchemaVersion != ChallengeSchemaV2) ||
		challenge.Revision != 1 ||
		!canonicalUUID(challenge.ApprovalID) ||
		!canonicalUUID(challenge.ChallengeID) ||
		!canonicalUUID(challenge.AgentInstanceID) ||
		!safeOwnerID(challenge.OwnerID) ||
		!canonicalUUID(challenge.PlanID) ||
		challenge.PlanRevision == 0 ||
		challenge.PlanRevision > uint64(math.MaxInt64) ||
		!digestPattern.MatchString(challenge.PlanDigest) ||
		!digestPattern.MatchString(challenge.GoalDigest) ||
		challenge.ProviderScope.Validate() != nil ||
		!digestPattern.MatchString(challenge.CatalogRevision) ||
		!digestPattern.MatchString(challenge.PolicyRevision) ||
		!canonicalUUID(challenge.PricingSnapshotID) ||
		!digestPattern.MatchString(challenge.PricingSnapshotDigest) ||
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
	switch challenge.SchemaVersion {
	case ChallengeSchemaV1:
		if challenge.LaunchAuthorizationID != "" ||
			challenge.LaunchAuthorizationDigest != "" {
			return ErrInvalid
		}
	case ChallengeSchemaV2:
		if !canonicalUUID(challenge.LaunchAuthorizationID) ||
			!digestPattern.MatchString(
				challenge.LaunchAuthorizationDigest,
			) {
			return ErrInvalid
		}
	}
	return nil
}

func (challenge ChallengeV1) SigningPayload() ([]byte, error) {
	if err := challenge.ValidateAt(challenge.IssuedAt); err != nil {
		return nil, err
	}
	switch challenge.SchemaVersion {
	case ChallengeSchemaV1:
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
			ProviderScope:         challenge.ProviderScope,
			CatalogRevision:       challenge.CatalogRevision,
			PolicyRevision:        challenge.PolicyRevision,
			PricingSnapshotID:     challenge.PricingSnapshotID,
			PricingSnapshotDigest: challenge.PricingSnapshotDigest,
			QuotedAt:              challenge.QuotedAt, QuoteValidUntil: challenge.QuoteValidUntil,
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
	case ChallengeSchemaV2:
		return canonical.Marshal(signingDocumentV2{
			PayloadSchema:             SigningPayloadSchemaV2,
			HashAlgorithm:             canonical.Algorithm,
			ChallengeSchema:           challenge.SchemaVersion,
			Revision:                  challenge.Revision,
			ApprovalID:                challenge.ApprovalID,
			ChallengeID:               challenge.ChallengeID,
			AgentInstanceID:           challenge.AgentInstanceID,
			OwnerID:                   challenge.OwnerID,
			PlanID:                    challenge.PlanID,
			PlanRevision:              challenge.PlanRevision,
			PlanDigest:                challenge.PlanDigest,
			GoalDigest:                challenge.GoalDigest,
			ProviderScope:             challenge.ProviderScope,
			CatalogRevision:           challenge.CatalogRevision,
			PolicyRevision:            challenge.PolicyRevision,
			PricingSnapshotID:         challenge.PricingSnapshotID,
			PricingSnapshotDigest:     challenge.PricingSnapshotDigest,
			QuotedAt:                  challenge.QuotedAt,
			QuoteValidUntil:           challenge.QuoteValidUntil,
			WorkerCount:               challenge.WorkerCount,
			MaxConcurrentWorkers:      challenge.MaxConcurrentWorkers,
			Currency:                  challenge.Currency,
			MinimumCostMicros:         challenge.MinimumCostMicros,
			ExpectedCostMicros:        challenge.ExpectedCostMicros,
			MaximumCostMicros:         challenge.MaximumCostMicros,
			HardBudgetMicros:          challenge.HardBudgetMicros,
			MinimumWallSeconds:        challenge.MinimumWallSeconds,
			ExpectedWallSeconds:       challenge.ExpectedWallSeconds,
			MaximumWallSeconds:        challenge.MaximumWallSeconds,
			LaunchAuthorizationID:     challenge.LaunchAuthorizationID,
			LaunchAuthorizationDigest: challenge.LaunchAuthorizationDigest,
			SignerKeyID:               challenge.SignerKeyID,
			IssuedAt:                  challenge.IssuedAt,
			ExpiresAt:                 challenge.ExpiresAt,
		})
	default:
		return nil, ErrInvalid
	}
}

// ValidateSignerKeyID applies the same bounded, secret-aware identifier
// contract used by challenges and signatures.
func ValidateSignerKeyID(value string) error {
	if !safeKeyID(value) {
		return ErrInvalid
	}
	return nil
}

// Validate checks only the immutable signature envelope. Verify additionally
// binds that envelope to one challenge, Plan, public key, and current time.
func (signature SignatureV1) Validate() error {
	decoded, err := base64.RawURLEncoding.DecodeString(
		signature.SignatureBase64URL,
	)
	if (signature.SchemaVersion != SignatureSchemaV1 &&
		signature.SchemaVersion != SignatureSchemaV2) ||
		!canonicalUUID(signature.ApprovalID) ||
		!canonicalUUID(signature.ChallengeID) ||
		!canonicalUUID(signature.PlanID) ||
		signature.PlanRevision == 0 ||
		signature.PlanRevision > uint64(math.MaxInt64) ||
		!digestPattern.MatchString(signature.PlanDigest) ||
		!safeKeyID(signature.SignerKeyID) ||
		err != nil ||
		len(decoded) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(decoded) !=
			signature.SignatureBase64URL {
		return ErrInvalid
	}
	switch signature.SchemaVersion {
	case SignatureSchemaV1:
		if signature.LaunchAuthorizationID != "" ||
			signature.LaunchAuthorizationDigest != "" {
			return ErrInvalid
		}
	case SignatureSchemaV2:
		if !canonicalUUID(signature.LaunchAuthorizationID) ||
			!digestPattern.MatchString(
				signature.LaunchAuthorizationDigest,
			) {
			return ErrInvalid
		}
	}
	return nil
}

func Verify(
	challenge ChallengeV1,
	signature SignatureV1,
	plan teamplan.Plan,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if challenge.SchemaVersion != ChallengeSchemaV1 ||
		signature.SchemaVersion != SignatureSchemaV1 {
		return ErrSignatureInvalid
	}
	return verify(
		challenge,
		signature,
		plan,
		nil,
		publicKey,
		now,
	)
}

// VerifyWithLaunch verifies a v2 signature against both immutable documents.
// A caller cannot fall back to Verify and thereby omit provider-launch facts.
func VerifyWithLaunch(
	challenge ChallengeV1,
	signature SignatureV1,
	plan teamplan.Plan,
	authorization teamlaunch.AuthorizationV1,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if challenge.SchemaVersion != ChallengeSchemaV2 ||
		signature.SchemaVersion != SignatureSchemaV2 {
		return ErrSignatureInvalid
	}
	return verify(
		challenge,
		signature,
		plan,
		&authorization,
		publicKey,
		now,
	)
}

func verify(
	challenge ChallengeV1,
	signature SignatureV1,
	plan teamplan.Plan,
	authorization *teamlaunch.AuthorizationV1,
	publicKey ed25519.PublicKey,
	now time.Time,
) error {
	if err := challenge.ValidateAt(now); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize ||
		signature.Validate() != nil ||
		signature.ApprovalID != challenge.ApprovalID ||
		signature.ChallengeID != challenge.ChallengeID ||
		signature.PlanID != challenge.PlanID ||
		signature.PlanRevision != challenge.PlanRevision ||
		signature.PlanDigest != challenge.PlanDigest ||
		signature.LaunchAuthorizationID !=
			challenge.LaunchAuthorizationID ||
		signature.LaunchAuthorizationDigest !=
			challenge.LaunchAuthorizationDigest ||
		signature.SignerKeyID != challenge.SignerKeyID {
		return ErrSignatureInvalid
	}
	if err := challenge.matchesPlan(plan); err != nil {
		return err
	}
	if authorization != nil {
		if err := challenge.matchesLaunch(
			plan,
			*authorization,
			now,
		); err != nil {
			return err
		}
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

func (challenge ChallengeV1) matchesLaunch(
	plan teamplan.Plan,
	authorization teamlaunch.AuthorizationV1,
	now time.Time,
) error {
	digest, err := authorization.Digest()
	if err != nil ||
		authorization.ValidateAt(now) != nil ||
		authorization.ValidateAgainst(plan) != nil ||
		authorization.AuthorizationID !=
			challenge.LaunchAuthorizationID ||
		digest != challenge.LaunchAuthorizationDigest ||
		authorization.AgentInstanceID != challenge.AgentInstanceID ||
		authorization.OwnerID != challenge.OwnerID ||
		authorization.PlanID != challenge.PlanID ||
		authorization.PlanRevision != challenge.PlanRevision ||
		authorization.PlanDigest != challenge.PlanDigest ||
		authorization.ApprovalID != challenge.ApprovalID ||
		authorization.ProviderScope != challenge.ProviderScope {
		return ErrPlanChanged
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
		plan.ProviderScope != challenge.ProviderScope ||
		plan.CatalogRevision != challenge.CatalogRevision ||
		plan.PolicyRevision != challenge.PolicyRevision ||
		plan.PricingSnapshotID != challenge.PricingSnapshotID ||
		plan.PricingSnapshotDigest != challenge.PricingSnapshotDigest ||
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
