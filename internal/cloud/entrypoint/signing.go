package entrypoint

import (
	"crypto/ed25519"
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

type planHashDocumentV1 struct {
	PayloadSchema string  `json:"payload_schema"`
	HashAlgorithm string  `json:"hash_algorithm"`
	EntryPlanID   string  `json:"entry_plan_id"`
	Revision      uint64  `json:"revision"`
	Scope         ScopeV1 `json:"scope"`
	ScopeDigest   string  `json:"scope_digest"`
}

// NewPlanV1 constructs a normalized immutable entry plan. It does not persist
// it and cannot authorize an AWS mutation.
func NewPlanV1(entryPlanID string, revision uint64, status PlanStatus, scope ScopeV1) (PlanV1, error) {
	normalizedScope := NormalizeScope(scope)
	scopeDigest, err := ScopeDigest(normalizedScope)
	if err != nil {
		return PlanV1{}, err
	}
	value := PlanV1{
		SchemaVersion: PlanSchemaV1,
		EntryPlanID:   entryPlanID,
		Revision:      revision,
		Status:        status,
		Scope:         normalizedScope,
		ScopeDigest:   scopeDigest,
	}
	if err := value.Validate(); err != nil {
		return PlanV1{}, err
	}
	return value, nil
}

// CanonicalCBOR returns the deterministic projection whose digest is PlanHash.
// Plan status is intentionally excluded because a lifecycle transition must not
// alter what a user device signed.
func (value PlanV1) CanonicalCBOR() ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return canonical.Marshal(value.hashDocument())
}

func (value PlanV1) Hash() (string, error) {
	if err := value.Validate(); err != nil {
		return "", err
	}
	return canonical.Digest(value.hashDocument())
}

func (value PlanV1) hashDocument() planHashDocumentV1 {
	normalizedScope := NormalizeScope(value.Scope)
	return planHashDocumentV1{
		PayloadSchema: PlanHashSchemaV1,
		HashAlgorithm: canonical.Algorithm,
		EntryPlanID:   value.EntryPlanID,
		Revision:      value.Revision,
		Scope:         normalizedScope,
		ScopeDigest:   value.ScopeDigest,
	}
}

// ValidateAgainstPlan prevents a fresh entry challenge from being replayed
// against a replacement Worker, quote, certificate, or public-health scope.
func (value ChallengeV1) ValidateAgainstPlan(plan PlanV1) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.Status != PlanReadyForApproval && plan.Status != PlanApproved {
		return ErrApprovalRequired
	}
	planHash, err := plan.Hash()
	if err != nil {
		return err
	}
	if value.EntryPlanID != plan.EntryPlanID || value.EntryPlanRevision != plan.Revision || value.PlanHash != planHash || value.ScopeDigest != plan.ScopeDigest {
		return ErrApprovalRequired
	}
	if !value.ExpiresAt.Before(plan.Scope.Cost.ValidUntil) {
		return ErrApprovalRequired
	}
	return nil
}

func ScopeDigest(value ScopeV1) (string, error) {
	normalized := NormalizeScope(value)
	if err := validateScope(normalized); err != nil {
		return "", err
	}
	return canonical.Digest(normalized)
}

// ScopeFactDigest returns the stable identity of independently read-back
// entrypoint facts.  A plan hash deliberately includes the observation times
// that were shown to the approving device.  Revalidation, however, must be
// able to prove that a fresh AWS observation reports the *same* resource
// facts; a later ObservedAt alone is not a replacement Worker, certificate, or
// subnet.  This digest therefore excludes only volatile AWS observation
// timestamps after validating the complete current scope.
//
// SucceededAt is intentionally retained: it is a durable execution fact, not
// a timestamp emitted by a repeated provider read-back.
func ScopeFactDigest(value ScopeV1) (string, error) {
	normalized := NormalizeScope(value)
	if err := validateScope(normalized); err != nil {
		return "", err
	}
	normalized.Worker.ReadBack.ObservedAt = time.Time{}
	normalized.Certificate.ObservedAt = time.Time{}
	for index := range normalized.ALB.PublicSubnets {
		normalized.ALB.PublicSubnets[index].ObservedAt = time.Time{}
	}
	return canonical.Digest(normalized)
}

// NewChallengeV1 creates the exact short-lived payload a device must sign.
// It only accepts a separately ready entry plan; the original Worker approval
// cannot be replayed as a public-entry approval.
func NewChallengeV1(plan PlanV1, operationID, challengeID, approvalID, signerKeyID string, issuedAt, expiresAt time.Time) (ChallengeV1, error) {
	if err := plan.Validate(); err != nil {
		return ChallengeV1{}, err
	}
	if plan.Status != PlanReadyForApproval {
		return ChallengeV1{}, invalidf("entry plan must be ready_for_approval")
	}
	if !expiresAt.Before(plan.Scope.Cost.ValidUntil) {
		return ChallengeV1{}, invalidf("entry challenge cannot outlive its quote")
	}
	planHash, err := plan.Hash()
	if err != nil {
		return ChallengeV1{}, err
	}
	value := ChallengeV1{
		OperationID:       operationID,
		ChallengeID:       challengeID,
		ApprovalID:        approvalID,
		EntryPlanID:       plan.EntryPlanID,
		EntryPlanRevision: plan.Revision,
		PlanHash:          planHash,
		ScopeDigest:       plan.ScopeDigest,
		SignerKeyID:       signerKeyID,
		IssuedAt:          issuedAt.UTC(),
		ExpiresAt:         expiresAt.UTC(),
		Revision:          1,
	}
	if err := value.Validate(); err != nil {
		return ChallengeV1{}, err
	}
	payload, err := value.SigningPayload()
	if err != nil {
		return ChallengeV1{}, err
	}
	value.SigningCBOR = append([]byte(nil), payload...)
	return value, nil
}

type signingDocumentV1 struct {
	PayloadSchema     string    `json:"payload_schema"`
	HashAlgorithm     string    `json:"hash_algorithm"`
	OperationID       string    `json:"operation_id"`
	ChallengeID       string    `json:"challenge_id"`
	ApprovalID        string    `json:"approval_id"`
	EntryPlanID       string    `json:"entry_plan_id"`
	EntryPlanRevision uint64    `json:"entry_plan_revision"`
	PlanHash          string    `json:"plan_hash"`
	ScopeDigest       string    `json:"scope_digest"`
	SignerKeyID       string    `json:"signer_key_id"`
	ExpiresAt         time.Time `json:"expires_at"`
}

func (value ChallengeV1) SigningPayload() ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	return canonical.Marshal(signingDocumentV1{
		PayloadSchema:     SigningPayloadV1,
		HashAlgorithm:     canonical.Algorithm,
		OperationID:       value.OperationID,
		ChallengeID:       value.ChallengeID,
		ApprovalID:        value.ApprovalID,
		EntryPlanID:       value.EntryPlanID,
		EntryPlanRevision: value.EntryPlanRevision,
		PlanHash:          value.PlanHash,
		ScopeDigest:       value.ScopeDigest,
		SignerKeyID:       value.SignerKeyID,
		ExpiresAt:         value.ExpiresAt.UTC(),
	})
}

// VerifyDeviceSignature verifies a fully bound one-time device signature.
// Callers must additionally atomically verify device registration and consume
// the challenge in their persistence transaction.
func VerifyDeviceSignature(challenge ChallengeV1, signature SignatureV1, publicKey ed25519.PublicKey, now time.Time) error {
	if len(publicKey) != ed25519.PublicKeySize || now.IsZero() {
		return ErrApprovalRequired
	}
	if err := challenge.Validate(); err != nil {
		return err
	}
	if err := signature.Validate(); err != nil {
		return err
	}
	if !signatureMatchesChallenge(challenge, signature) {
		return ErrApprovalRequired
	}
	if !now.Before(challenge.ExpiresAt) {
		return ErrApprovalExpired
	}
	payload, err := challenge.SigningPayload()
	if err != nil {
		return err
	}
	if len(challenge.SigningCBOR) != 0 && subtle.ConstantTimeCompare(challenge.SigningCBOR, payload) != 1 {
		return fmt.Errorf("%w: cached entry signing payload does not match canonical payload", ErrApprovalRequired)
	}
	if !ed25519.Verify(publicKey, payload, signature.Signature) {
		return ErrApprovalRequired
	}
	return nil
}

func signatureMatchesChallenge(challenge ChallengeV1, signature SignatureV1) bool {
	return signature.ApprovalID == challenge.ApprovalID &&
		signature.ChallengeID == challenge.ChallengeID &&
		signature.EntryPlanID == challenge.EntryPlanID &&
		signature.EntryPlanRevision == challenge.EntryPlanRevision &&
		signature.PlanHash == challenge.PlanHash &&
		signature.ScopeDigest == challenge.ScopeDigest &&
		signature.SignerKeyID == challenge.SignerKeyID &&
		signature.ExpiresAt.Equal(challenge.ExpiresAt)
}

// VerifyApproval verifies an operation after the persistence layer has loaded
// its registered device public key. Awaiting operations intentionally do not
// verify because they have no signature yet.
func (value OperationV1) VerifyApproval(publicKey ed25519.PublicKey, now time.Time) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if value.Signature == nil {
		return ErrApprovalRequired
	}
	return VerifyDeviceSignature(value.Challenge, *value.Signature, publicKey, now)
}
