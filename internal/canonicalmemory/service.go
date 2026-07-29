package canonicalmemory

import (
	"context"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/google/uuid"
)

type Clock func() time.Time
type IDFactory func() (string, error)

type Service struct {
	agentInstanceID string
	store           Store
	now             Clock
	newID           IDFactory
}

func NewService(agentInstanceID string, store Store, now Clock,
	newID IDFactory) (*Service, error) {
	if !canonicalUUID(agentInstanceID) ||
		store == nil ||
		now == nil ||
		newID == nil {
		return nil, ErrInvalid
	}
	return &Service{
		agentInstanceID: agentInstanceID,
		store:           store,
		now:             now,
		newID:           newID,
	}, nil
}

func NewDefaultService(agentInstanceID string, store Store) (*Service, error) {
	return NewService(agentInstanceID, store, time.Now, func() (string, error) {
		value, err := uuid.NewV7()
		if err != nil {
			return "", err
		}
		return value.String(), nil
	})
}

type RecordWorkerEvidenceRequest struct {
	IdempotencyKey string
	OwnerID        string
	Namespace      string
	DeploymentID   string
	Artifact       Artifact
	Attempt        int32
	LeaseEpoch     int64
}

func (service *Service) RecordWorkerEvidence(ctx context.Context,
	scope task.MutationScope,
	request RecordWorkerEvidenceRequest) (Evidence, error) {
	if service == nil || service.store == nil || ctx == nil ||
		scope.Validate() != nil {
		return Evidence{}, ErrInvalid
	}
	evidenceID, err := service.generateID()
	if err != nil {
		return Evidence{}, err
	}
	command := RecordWorkerEvidenceCommand{
		IdempotencyKey: request.IdempotencyKey,
		EvidenceID:     evidenceID,
		OwnerID:        request.OwnerID,
		Namespace:      request.Namespace,
		DeploymentID:   request.DeploymentID,
		Artifact:       request.Artifact,
		Attempt:        request.Attempt,
		LeaseEpoch:     request.LeaseEpoch,
	}
	if command.Validate() != nil {
		return Evidence{}, ErrInvalid
	}
	evidence, err := service.store.RecordWorkerEvidence(ctx, scope, command)
	if err != nil {
		return Evidence{}, err
	}
	if evidence.Validate() != nil ||
		evidence.OwnerID != request.OwnerID ||
		evidence.Namespace != request.Namespace ||
		evidence.Kind != EvidenceWorkerClaim ||
		evidence.Trust != TrustUntrusted ||
		evidence.DeploymentID != request.DeploymentID ||
		evidence.Artifact != request.Artifact ||
		evidence.Attempt != request.Attempt ||
		evidence.LeaseEpoch != request.LeaseEpoch {
		return Evidence{}, ErrFactMismatch
	}
	return evidence, nil
}

type RecordTurnEvidenceRequest struct {
	IdempotencyKey string
	OwnerID        string
	Namespace      string
	Kind           EvidenceKind
	TurnID         string
	TurnRevision   int64
	Artifact       Artifact
}

func (service *Service) RecordTurnEvidence(ctx context.Context,
	scope task.MutationScope,
	request RecordTurnEvidenceRequest) (Evidence, error) {
	if service == nil || service.store == nil || ctx == nil ||
		scope.Validate() != nil {
		return Evidence{}, ErrInvalid
	}
	evidenceID, err := service.generateID()
	if err != nil {
		return Evidence{}, err
	}
	command := RecordTurnEvidenceCommand{
		IdempotencyKey: request.IdempotencyKey,
		EvidenceID:     evidenceID,
		OwnerID:        request.OwnerID,
		Namespace:      request.Namespace,
		Kind:           request.Kind,
		TurnID:         request.TurnID,
		TurnRevision:   request.TurnRevision,
		Artifact:       request.Artifact,
	}
	if command.Validate() != nil {
		return Evidence{}, ErrInvalid
	}
	evidence, err := service.store.RecordTurnEvidence(ctx, scope, command)
	if err != nil {
		return Evidence{}, err
	}
	expectedTrust := TrustCorroborating
	if request.Kind == EvidenceTurnValidation {
		expectedTrust = TrustVerified
	}
	if evidence.Validate() != nil ||
		evidence.OwnerID != request.OwnerID ||
		evidence.Namespace != request.Namespace ||
		evidence.Kind != request.Kind ||
		evidence.Trust != expectedTrust ||
		evidence.TurnID != request.TurnID ||
		evidence.TurnRevision != request.TurnRevision ||
		evidence.Artifact != request.Artifact {
		return Evidence{}, ErrFactMismatch
	}
	return evidence, nil
}

type ProposeRequest struct {
	IdempotencyKey string
	OwnerID        string
	Namespace      string
	MemoryKey      string
	Kind           MemoryKind
	Title          string
	Statement      string
	Origin         CandidateOrigin
	Source         Artifact
	EvidenceIDs    []string
}

func (service *Service) Propose(ctx context.Context, scope task.MutationScope,
	request ProposeRequest) (Candidate, error) {
	if service == nil || service.store == nil || ctx == nil ||
		scope.Validate() != nil {
		return Candidate{}, ErrInvalid
	}
	candidateID, err := service.generateID()
	if err != nil {
		return Candidate{}, err
	}
	now, err := service.currentTime()
	if err != nil {
		return Candidate{}, err
	}
	command, err := (ProposeCommand{
		IdempotencyKey: request.IdempotencyKey,
		CandidateID:    candidateID,
		OwnerID:        request.OwnerID,
		Namespace:      request.Namespace,
		MemoryKey:      request.MemoryKey,
		Kind:           request.Kind,
		Title:          request.Title,
		Statement:      request.Statement,
		Origin:         request.Origin,
		Source:         request.Source,
		EvidenceIDs:    append([]string(nil), request.EvidenceIDs...),
		ExpiresAt: now.Add(CandidateLifetime).UTC().
			Truncate(time.Microsecond),
	}).Validated()
	if err != nil {
		return Candidate{}, err
	}
	candidate, err := service.store.ProposeCandidate(ctx, scope, command)
	if err != nil {
		return Candidate{}, err
	}
	if candidate.Validate() != nil ||
		candidate.OwnerID != command.OwnerID ||
		candidate.Namespace != command.Namespace ||
		candidate.MemoryKey != command.MemoryKey ||
		candidate.Kind != command.Kind ||
		candidate.Title != command.Title ||
		candidate.Statement != command.Statement ||
		candidate.Origin != command.Origin ||
		candidate.Source != command.Source ||
		candidate.Status != CandidatePending ||
		candidate.Revision != 1 {
		return Candidate{}, ErrFactMismatch
	}
	return candidate, nil
}

type ChallengeRequest struct {
	IdempotencyKey            string
	OwnerID                   string
	CandidateID               string
	ExpectedCandidateRevision int64
	ExpectedMemoryRevision    int64
	SignerKeyID               string
	ValidUntil                time.Time
}

func (service *Service) CreateChallenge(ctx context.Context,
	scope task.MutationScope,
	request ChallengeRequest) (ChallengeFact, error) {
	if service == nil || service.store == nil || ctx == nil ||
		scope.Validate() != nil {
		return ChallengeFact{}, ErrInvalid
	}
	candidate, err := service.store.GetCandidate(ctx, request.OwnerID,
		request.CandidateID)
	if err != nil {
		return ChallengeFact{}, err
	}
	now, err := service.currentTime()
	if err != nil {
		return ChallengeFact{}, err
	}
	validUntil := normalizeOptionalTime(request.ValidUntil)
	if candidate.Validate() != nil ||
		candidate.Revision != request.ExpectedCandidateRevision ||
		ValidatePromotion(candidate, validUntil, now) != nil {
		return ChallengeFact{}, ErrEvidence
	}
	memoryID, err := DeriveMemoryID(service.agentInstanceID,
		candidate.OwnerID, candidate.Namespace, candidate.MemoryKey)
	if err != nil {
		return ChallengeFact{}, err
	}
	challengeID, err := service.generateID()
	if err != nil {
		return ChallengeFact{}, err
	}
	approvalID, err := service.generateID()
	if err != nil {
		return ChallengeFact{}, err
	}
	command := CreateChallengeCommand{
		IdempotencyKey: request.IdempotencyKey,
		ChallengeID:    challengeID, ApprovalID: approvalID,
		OwnerID: request.OwnerID, CandidateID: request.CandidateID,
		ExpectedCandidateRevision: request.ExpectedCandidateRevision,
		MemoryID:                  memoryID,
		ExpectedMemoryRevision:    request.ExpectedMemoryRevision,
		SignerKeyID:               request.SignerKeyID,
		ValidUntil:                validUntil,
	}
	if command.Validate() != nil {
		return ChallengeFact{}, ErrInvalid
	}
	fact, err := service.store.CreateCanonicalMemoryChallenge(
		ctx, scope, command)
	if err != nil {
		return ChallengeFact{}, err
	}
	if fact.Validate() != nil ||
		fact.RecordRevision != 1 ||
		!fact.ConsumedAt.IsZero() ||
		fact.Challenge.AgentInstanceID != service.agentInstanceID ||
		fact.Challenge.OwnerID != request.OwnerID ||
		fact.Challenge.CandidateID != request.CandidateID ||
		fact.Challenge.CandidateRevision !=
			request.ExpectedCandidateRevision ||
		fact.Challenge.MemoryID != memoryID ||
		fact.Challenge.ExpectedMemoryRevision !=
			request.ExpectedMemoryRevision ||
		fact.Challenge.SignerKeyID != request.SignerKeyID ||
		fact.Challenge.MatchesCandidate(candidate) != nil {
		return ChallengeFact{}, ErrFactMismatch
	}
	return fact, nil
}

type ApproveRequest struct {
	IdempotencyKey string
	OwnerID        string
	Signature      SignatureV1
}

func (service *Service) Approve(ctx context.Context,
	scope task.MutationScope, request ApproveRequest) (Fact, error) {
	if service == nil || service.store == nil || ctx == nil ||
		scope.Validate() != nil {
		return Fact{}, ErrInvalid
	}
	command := ApproveCommand{
		IdempotencyKey:            request.IdempotencyKey,
		OwnerID:                   request.OwnerID,
		ExpectedCandidateRevision: request.Signature.CandidateRevision,
		Signature:                 request.Signature,
	}
	if command.Validate() != nil {
		return Fact{}, ErrInvalid
	}
	fact, err := service.store.ApproveCandidate(ctx, scope, command)
	if err != nil {
		return Fact{}, err
	}
	if fact.Validate() != nil ||
		fact.Memory.OwnerID != request.OwnerID ||
		fact.Memory.MemoryID != request.Signature.MemoryID ||
		fact.Revision.CandidateID != request.Signature.CandidateID ||
		fact.Revision.CandidateDigest !=
			request.Signature.CandidateDigest ||
		fact.Memory.Status != MemoryActive {
		return Fact{}, ErrFactMismatch
	}
	return fact, nil
}

func (service *Service) Reject(ctx context.Context,
	scope task.MutationScope, command RejectCommand) (Candidate, error) {
	if service == nil || service.store == nil || ctx == nil ||
		scope.Validate() != nil || command.Validate() != nil {
		return Candidate{}, ErrInvalid
	}
	candidate, err := service.store.RejectCandidate(ctx, scope, command)
	if err != nil {
		return Candidate{}, err
	}
	if candidate.Validate() != nil ||
		candidate.OwnerID != command.OwnerID ||
		candidate.CandidateID != command.CandidateID ||
		candidate.Status != CandidateRejected ||
		candidate.RejectionReason != command.ReasonCode {
		return Candidate{}, ErrFactMismatch
	}
	return candidate, nil
}

// Revoke is intentionally an internal control-plane API in this slice. It is
// not safe to expose through Message Server until a device-signed revocation
// challenge is added to the public contract.
func (service *Service) Revoke(ctx context.Context,
	scope task.MutationScope, command RevokeCommand) (Fact, error) {
	if service == nil || service.store == nil || ctx == nil ||
		scope.Validate() != nil || command.Validate() != nil {
		return Fact{}, ErrInvalid
	}
	fact, err := service.store.RevokeMemory(ctx, scope, command)
	if err != nil {
		return Fact{}, err
	}
	if fact.Validate() != nil ||
		fact.Memory.OwnerID != command.OwnerID ||
		fact.Memory.MemoryID != command.MemoryID ||
		fact.Memory.Status != MemoryRevoked ||
		fact.Memory.RecordRevision != command.ExpectedRecordRevision+1 {
		return Fact{}, ErrFactMismatch
	}
	return fact, nil
}

func (service *Service) GetCandidate(ctx context.Context, ownerID,
	candidateID string) (Candidate, error) {
	if service == nil || service.store == nil || ctx == nil {
		return Candidate{}, ErrInvalid
	}
	candidate, err := service.store.GetCandidate(ctx, ownerID, candidateID)
	if err != nil {
		return Candidate{}, err
	}
	if candidate.Validate() != nil ||
		candidate.OwnerID != ownerID ||
		candidate.CandidateID != candidateID {
		return Candidate{}, ErrFactMismatch
	}
	return candidate, nil
}

func (service *Service) Get(ctx context.Context, ownerID,
	memoryID string) (Fact, error) {
	if service == nil || service.store == nil || ctx == nil {
		return Fact{}, ErrInvalid
	}
	fact, err := service.store.GetMemory(ctx, ownerID, memoryID)
	if err != nil {
		return Fact{}, err
	}
	if fact.Validate() != nil ||
		fact.Memory.OwnerID != ownerID ||
		fact.Memory.MemoryID != memoryID {
		return Fact{}, ErrFactMismatch
	}
	return fact, nil
}

func (service *Service) ListActive(ctx context.Context, ownerID, namespace,
	afterMemoryID string, pageSize int) (Page, error) {
	if service == nil || service.store == nil || ctx == nil {
		return Page{}, ErrInvalid
	}
	now, err := service.currentTime()
	if err != nil {
		return Page{}, err
	}
	query, err := (ListQuery{
		OwnerID: ownerID, Namespace: namespace, PageSize: pageSize,
		AfterMemoryID: afterMemoryID, Now: now,
	}).Validated()
	if err != nil {
		return Page{}, err
	}
	page, err := service.store.ListActiveMemories(ctx, query)
	if err != nil {
		return Page{}, err
	}
	for _, fact := range page.Facts {
		if fact.Validate() != nil ||
			fact.Memory.OwnerID != ownerID ||
			fact.Memory.Namespace != namespace ||
			fact.Memory.Status != MemoryActive ||
			!fact.Revision.ValidAt(now) {
			return Page{}, ErrFactMismatch
		}
	}
	if page.NextAfterMemoryID != "" &&
		!canonicalUUID(page.NextAfterMemoryID) {
		return Page{}, ErrFactMismatch
	}
	return page, nil
}

func (service *Service) currentTime() (time.Time, error) {
	if service == nil || service.now == nil {
		return time.Time{}, ErrInvalid
	}
	now := service.now().UTC().Truncate(time.Microsecond)
	if !utcMicrosecond(now) {
		return time.Time{}, ErrInvalid
	}
	return now, nil
}

func (service *Service) generateID() (string, error) {
	if service == nil || service.newID == nil {
		return "", ErrInvalid
	}
	value, err := service.newID()
	if err != nil || !canonicalUUID(value) {
		return "", ErrInvalid
	}
	return value, nil
}
