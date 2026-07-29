package canonicalmemory

import (
	"crypto/ed25519"
	"encoding/base64"
	"math"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

const (
	ChallengeSchemaV1      = "dirextalk.agent.canonical-memory-challenge/v1"
	SignatureSchemaV1      = "dirextalk.agent.canonical-memory-signature/v1"
	SigningPayloadSchemaV1 = "dirextalk.agent.canonical-memory-signing-payload/v1"
	ChallengeValidity      = 5 * time.Minute
)

type ChallengeV1 struct {
	SchemaVersion          string     `json:"schema_version"`
	Revision               uint64     `json:"revision"`
	ApprovalID             string     `json:"approval_id"`
	ChallengeID            string     `json:"challenge_id"`
	AgentInstanceID        string     `json:"agent_instance_id"`
	OwnerID                string     `json:"owner_id"`
	CandidateID            string     `json:"candidate_id"`
	CandidateRevision      int64      `json:"candidate_revision"`
	CandidateDigest        string     `json:"candidate_digest"`
	EvidenceDigest         string     `json:"evidence_digest"`
	MemoryID               string     `json:"memory_id"`
	ExpectedMemoryRevision int64      `json:"expected_memory_revision"`
	Namespace              string     `json:"namespace"`
	MemoryKey              string     `json:"memory_key"`
	Kind                   MemoryKind `json:"kind"`
	HasValidUntil          bool       `json:"has_valid_until"`
	ValidUntil             time.Time  `json:"valid_until"`
	SignerKeyID            string     `json:"signer_key_id"`
	IssuedAt               time.Time  `json:"issued_at"`
	ExpiresAt              time.Time  `json:"expires_at"`
}

type SignatureV1 struct {
	SchemaVersion          string `json:"schema_version"`
	ApprovalID             string `json:"approval_id"`
	ChallengeID            string `json:"challenge_id"`
	CandidateID            string `json:"candidate_id"`
	CandidateRevision      int64  `json:"candidate_revision"`
	CandidateDigest        string `json:"candidate_digest"`
	MemoryID               string `json:"memory_id"`
	ExpectedMemoryRevision int64  `json:"expected_memory_revision"`
	SignerKeyID            string `json:"signer_key_id"`
	SignatureBase64URL     string `json:"signature_base64url"`
}

type signingDocumentV1 struct {
	PayloadSchema          string     `json:"payload_schema"`
	HashAlgorithm          string     `json:"hash_algorithm"`
	ChallengeSchema        string     `json:"challenge_schema"`
	Revision               uint64     `json:"revision"`
	ApprovalID             string     `json:"approval_id"`
	ChallengeID            string     `json:"challenge_id"`
	AgentInstanceID        string     `json:"agent_instance_id"`
	OwnerID                string     `json:"owner_id"`
	CandidateID            string     `json:"candidate_id"`
	CandidateRevision      int64      `json:"candidate_revision"`
	CandidateDigest        string     `json:"candidate_digest"`
	EvidenceDigest         string     `json:"evidence_digest"`
	MemoryID               string     `json:"memory_id"`
	ExpectedMemoryRevision int64      `json:"expected_memory_revision"`
	Namespace              string     `json:"namespace"`
	MemoryKey              string     `json:"memory_key"`
	Kind                   MemoryKind `json:"kind"`
	HasValidUntil          bool       `json:"has_valid_until"`
	ValidUntil             time.Time  `json:"valid_until"`
	SignerKeyID            string     `json:"signer_key_id"`
	IssuedAt               time.Time  `json:"issued_at"`
	ExpiresAt              time.Time  `json:"expires_at"`
}

func NewChallengeV1(candidate Candidate, agentInstanceID, approvalID,
	challengeID, memoryID, signerKeyID string, expectedMemoryRevision int64,
	validUntil, issuedAt time.Time) (ChallengeV1, error) {
	if candidate.Validate() != nil ||
		!canonicalUUID(agentInstanceID) ||
		!canonicalUUID(approvalID) ||
		!canonicalUUID(challengeID) ||
		!canonicalUUID(memoryID) ||
		!validSignerKeyID(signerKeyID) ||
		expectedMemoryRevision < 0 ||
		issuedAt.IsZero() {
		return ChallengeV1{}, ErrInvalid
	}
	issuedAt = issuedAt.UTC().Truncate(time.Microsecond)
	validUntil = normalizeOptionalTime(validUntil)
	if !candidate.PendingAt(issuedAt) ||
		ValidatePromotion(candidate, validUntil, issuedAt) != nil {
		return ChallengeV1{}, ErrEvidence
	}
	expectedMemoryID, err := DeriveMemoryID(agentInstanceID,
		candidate.OwnerID, candidate.Namespace, candidate.MemoryKey)
	if err != nil || expectedMemoryID != memoryID {
		return ChallengeV1{}, ErrInvalid
	}
	expiresAt := issuedAt.Add(ChallengeValidity)
	if candidate.ExpiresAt.Before(expiresAt) {
		expiresAt = candidate.ExpiresAt.UTC()
	}
	challenge := ChallengeV1{
		SchemaVersion:          ChallengeSchemaV1,
		Revision:               1,
		ApprovalID:             approvalID,
		ChallengeID:            challengeID,
		AgentInstanceID:        agentInstanceID,
		OwnerID:                candidate.OwnerID,
		CandidateID:            candidate.CandidateID,
		CandidateRevision:      candidate.Revision,
		CandidateDigest:        candidate.CandidateDigest,
		EvidenceDigest:         candidate.EvidenceDigest,
		MemoryID:               memoryID,
		ExpectedMemoryRevision: expectedMemoryRevision,
		Namespace:              candidate.Namespace,
		MemoryKey:              candidate.MemoryKey,
		Kind:                   candidate.Kind,
		HasValidUntil:          !validUntil.IsZero(),
		ValidUntil:             validUntil,
		SignerKeyID:            signerKeyID,
		IssuedAt:               issuedAt,
		ExpiresAt:              expiresAt.UTC().Truncate(time.Microsecond),
	}
	if err := challenge.ValidateAt(issuedAt); err != nil {
		return ChallengeV1{}, err
	}
	return challenge, nil
}

func (challenge ChallengeV1) Validate() error {
	if challenge.SchemaVersion != ChallengeSchemaV1 ||
		challenge.Revision != 1 ||
		!canonicalUUID(challenge.ApprovalID) ||
		!canonicalUUID(challenge.ChallengeID) ||
		!canonicalUUID(challenge.AgentInstanceID) ||
		!validOwnerID(challenge.OwnerID) ||
		!canonicalUUID(challenge.CandidateID) ||
		challenge.CandidateRevision < 1 ||
		!validDigest(challenge.CandidateDigest) ||
		!validDigest(challenge.EvidenceDigest) ||
		!canonicalUUID(challenge.MemoryID) ||
		challenge.ExpectedMemoryRevision < 0 ||
		challenge.ExpectedMemoryRevision > math.MaxInt64 ||
		!validNamespace(challenge.Namespace) ||
		!validMemoryKey(challenge.MemoryKey) ||
		!validMemoryKind(challenge.Kind) ||
		!validSignerKeyID(challenge.SignerKeyID) ||
		!utcMicrosecond(challenge.IssuedAt) ||
		!utcMicrosecond(challenge.ExpiresAt) ||
		!challenge.IssuedAt.Before(challenge.ExpiresAt) ||
		challenge.ExpiresAt.Sub(challenge.IssuedAt) > ChallengeValidity {
		return ErrInvalid
	}
	if challenge.HasValidUntil {
		if !utcMicrosecond(challenge.ValidUntil) ||
			!challenge.IssuedAt.Before(challenge.ValidUntil) {
			return ErrInvalid
		}
	} else if !challenge.ValidUntil.IsZero() {
		return ErrInvalid
	}
	expectedMemoryID, err := DeriveMemoryID(challenge.AgentInstanceID,
		challenge.OwnerID, challenge.Namespace, challenge.MemoryKey)
	if err != nil || expectedMemoryID != challenge.MemoryID {
		return ErrInvalid
	}
	return nil
}

func (challenge ChallengeV1) ValidateAt(now time.Time) error {
	if challenge.Validate() != nil || now.IsZero() {
		return ErrInvalid
	}
	now = now.UTC()
	if now.Before(challenge.IssuedAt.Add(-30*time.Second)) ||
		!now.Before(challenge.ExpiresAt) {
		return ErrApprovalExpired
	}
	return nil
}

func (challenge ChallengeV1) SigningPayload() ([]byte, error) {
	if challenge.ValidateAt(challenge.IssuedAt) != nil {
		return nil, ErrInvalid
	}
	return canonical.Marshal(signingDocumentV1{
		PayloadSchema:          SigningPayloadSchemaV1,
		HashAlgorithm:          canonical.Algorithm,
		ChallengeSchema:        challenge.SchemaVersion,
		Revision:               challenge.Revision,
		ApprovalID:             challenge.ApprovalID,
		ChallengeID:            challenge.ChallengeID,
		AgentInstanceID:        challenge.AgentInstanceID,
		OwnerID:                challenge.OwnerID,
		CandidateID:            challenge.CandidateID,
		CandidateRevision:      challenge.CandidateRevision,
		CandidateDigest:        challenge.CandidateDigest,
		EvidenceDigest:         challenge.EvidenceDigest,
		MemoryID:               challenge.MemoryID,
		ExpectedMemoryRevision: challenge.ExpectedMemoryRevision,
		Namespace:              challenge.Namespace,
		MemoryKey:              challenge.MemoryKey,
		Kind:                   challenge.Kind,
		HasValidUntil:          challenge.HasValidUntil,
		ValidUntil:             challenge.ValidUntil,
		SignerKeyID:            challenge.SignerKeyID,
		IssuedAt:               challenge.IssuedAt,
		ExpiresAt:              challenge.ExpiresAt,
	})
}

func (challenge ChallengeV1) MatchesCandidate(candidate Candidate) error {
	revisionMatches := candidate.Status == CandidatePending &&
		candidate.Revision == challenge.CandidateRevision
	if candidate.Status == CandidatePromoted {
		revisionMatches =
			candidate.Revision == challenge.CandidateRevision+1 &&
				candidate.PromotedMemoryID == challenge.MemoryID &&
				candidate.PromotedMemoryRevision ==
					challenge.ExpectedMemoryRevision+1
	}
	if challenge.Validate() != nil ||
		candidate.Validate() != nil ||
		challenge.OwnerID != candidate.OwnerID ||
		challenge.CandidateID != candidate.CandidateID ||
		!revisionMatches ||
		challenge.CandidateDigest != candidate.CandidateDigest ||
		challenge.EvidenceDigest != candidate.EvidenceDigest ||
		challenge.Namespace != candidate.Namespace ||
		challenge.MemoryKey != candidate.MemoryKey ||
		challenge.Kind != candidate.Kind {
		return ErrFactMismatch
	}
	return nil
}

func (signature SignatureV1) Validate() error {
	decoded, err := base64.RawURLEncoding.DecodeString(
		signature.SignatureBase64URL)
	if signature.SchemaVersion != SignatureSchemaV1 ||
		!canonicalUUID(signature.ApprovalID) ||
		!canonicalUUID(signature.ChallengeID) ||
		!canonicalUUID(signature.CandidateID) ||
		signature.CandidateRevision < 1 ||
		!validDigest(signature.CandidateDigest) ||
		!canonicalUUID(signature.MemoryID) ||
		signature.ExpectedMemoryRevision < 0 ||
		!validSignerKeyID(signature.SignerKeyID) ||
		err != nil ||
		len(decoded) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(decoded) !=
			signature.SignatureBase64URL {
		return ErrInvalid
	}
	return nil
}

func VerifyApproval(challenge ChallengeV1, signature SignatureV1,
	candidate Candidate, publicKey ed25519.PublicKey, now time.Time) error {
	if challenge.ValidateAt(now) != nil {
		return ErrApprovalExpired
	}
	if len(publicKey) != ed25519.PublicKeySize ||
		signature.Validate() != nil ||
		challenge.MatchesCandidate(candidate) != nil ||
		signature.ApprovalID != challenge.ApprovalID ||
		signature.ChallengeID != challenge.ChallengeID ||
		signature.CandidateID != challenge.CandidateID ||
		signature.CandidateRevision != challenge.CandidateRevision ||
		signature.CandidateDigest != challenge.CandidateDigest ||
		signature.MemoryID != challenge.MemoryID ||
		signature.ExpectedMemoryRevision !=
			challenge.ExpectedMemoryRevision ||
		signature.SignerKeyID != challenge.SignerKeyID {
		return ErrSignature
	}
	decoded, err := base64.RawURLEncoding.DecodeString(
		signature.SignatureBase64URL)
	if err != nil || len(decoded) != ed25519.SignatureSize {
		return ErrSignature
	}
	payload, err := challenge.SigningPayload()
	if err != nil || !ed25519.Verify(publicKey, payload, decoded) {
		return ErrSignature
	}
	return nil
}

type ChallengeFact struct {
	Challenge      ChallengeV1
	RecordRevision int64
	ConsumedAt     time.Time
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

func (fact ChallengeFact) Validate() error {
	if fact.Challenge.Validate() != nil ||
		fact.RecordRevision < 1 ||
		fact.RecordRevision > 2 ||
		!utcMicrosecond(fact.CreatedAt) ||
		!utcMicrosecond(fact.UpdatedAt) ||
		fact.UpdatedAt.Before(fact.CreatedAt) {
		return ErrInvalid
	}
	if fact.RecordRevision == 1 {
		if !fact.ConsumedAt.IsZero() {
			return ErrInvalid
		}
	} else if !utcMicrosecond(fact.ConsumedAt) {
		return ErrInvalid
	}
	return nil
}

type ApprovalFact struct {
	ApprovalID     string
	ChallengeID    string
	CandidateID    string
	MemoryID       string
	SignerKeyID    string
	Signature      []byte
	SigningPayload []byte
	ApprovedAt     time.Time
	CreatedAt      time.Time
}

func (fact ApprovalFact) Validate() error {
	if !canonicalUUID(fact.ApprovalID) ||
		!canonicalUUID(fact.ChallengeID) ||
		!canonicalUUID(fact.CandidateID) ||
		!canonicalUUID(fact.MemoryID) ||
		!validSignerKeyID(fact.SignerKeyID) ||
		len(fact.Signature) != ed25519.SignatureSize ||
		len(fact.SigningPayload) == 0 ||
		!utcMicrosecond(fact.ApprovedAt) ||
		!utcMicrosecond(fact.CreatedAt) {
		return ErrInvalid
	}
	return nil
}

type CreateChallengeCommand struct {
	IdempotencyKey            string
	ChallengeID               string
	ApprovalID                string
	OwnerID                   string
	CandidateID               string
	ExpectedCandidateRevision int64
	MemoryID                  string
	ExpectedMemoryRevision    int64
	SignerKeyID               string
	ValidUntil                time.Time
}

func (command CreateChallengeCommand) Validate() error {
	if !canonicalUUID(command.IdempotencyKey) ||
		!canonicalUUID(command.ChallengeID) ||
		!canonicalUUID(command.ApprovalID) ||
		!validOwnerID(command.OwnerID) ||
		!canonicalUUID(command.CandidateID) ||
		command.ExpectedCandidateRevision < 1 ||
		!canonicalUUID(command.MemoryID) ||
		command.ExpectedMemoryRevision < 0 ||
		!validSignerKeyID(command.SignerKeyID) ||
		(!command.ValidUntil.IsZero() &&
			!utcMicrosecond(command.ValidUntil)) {
		return ErrInvalid
	}
	return nil
}

func (command CreateChallengeCommand) Digest() ([32]byte, error) {
	if command.Validate() != nil {
		return [32]byte{}, ErrInvalid
	}
	return digestJSON(struct {
		OwnerID                   string    `json:"owner_id"`
		CandidateID               string    `json:"candidate_id"`
		ExpectedCandidateRevision int64     `json:"expected_candidate_revision"`
		MemoryID                  string    `json:"memory_id"`
		ExpectedMemoryRevision    int64     `json:"expected_memory_revision"`
		SignerKeyID               string    `json:"signer_key_id"`
		ValidUntil                time.Time `json:"valid_until"`
	}{
		command.OwnerID, command.CandidateID,
		command.ExpectedCandidateRevision, command.MemoryID,
		command.ExpectedMemoryRevision, command.SignerKeyID,
		command.ValidUntil,
	})
}

type ApproveCommand struct {
	IdempotencyKey            string
	OwnerID                   string
	ExpectedCandidateRevision int64
	Signature                 SignatureV1
}

func (command ApproveCommand) Validate() error {
	if !canonicalUUID(command.IdempotencyKey) ||
		!validOwnerID(command.OwnerID) ||
		command.ExpectedCandidateRevision < 1 ||
		command.Signature.Validate() != nil ||
		command.ExpectedCandidateRevision !=
			command.Signature.CandidateRevision {
		return ErrInvalid
	}
	return nil
}

func (command ApproveCommand) Digest() ([32]byte, error) {
	if command.Validate() != nil {
		return [32]byte{}, ErrInvalid
	}
	return digestJSON(command)
}

func normalizeOptionalTime(value time.Time) time.Time {
	if value.IsZero() {
		return time.Time{}
	}
	return value.UTC().Truncate(time.Microsecond)
}
