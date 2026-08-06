package coreteamworker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
)

type Config struct {
	Now           func() time.Time
	NewID         func() string
	ChallengeTTL  time.Duration
	EnrollmentTTL time.Duration
	LeaseTTL      time.Duration
}

type Service struct {
	repository Repository
	verifier   IdentityVerifier
	config     Config
}

func NewService(repository Repository, verifier IdentityVerifier, config Config) (*Service, error) {
	if repository == nil || verifier == nil || config.Now == nil || config.NewID == nil ||
		config.ChallengeTTL < 30*time.Second || config.ChallengeTTL > 15*time.Minute ||
		config.EnrollmentTTL < time.Minute || config.EnrollmentTTL > 24*time.Hour ||
		config.LeaseTTL < 10*time.Second || config.LeaseTTL > 5*time.Minute {
		return nil, ErrInvalid
	}
	return &Service{repository: repository, verifier: verifier, config: config}, nil
}

func (s *Service) CreateIdentityChallenge(ctx context.Context, request ChallengeRequest) (Challenge, error) {
	if s == nil || s.repository == nil || ctx == nil || request.Scope.Validate() != nil || !validUUID(request.ExecutionID) ||
		!validRoleID(request.RoleID) || request.Attempt == 0 || !validDigest(request.IdentityDigest) || !validUUID(request.IdempotencyKey) {
		return Challenge{}, ErrInvalid
	}
	now := s.now()
	requestDigest := challengeRequestDigest(request)
	challenge := Challenge{
		ChallengeID: s.config.NewID(), WorkerID: s.config.NewID(), Scope: request.Scope, ExecutionID: request.ExecutionID,
		RoleID: request.RoleID, Attempt: request.Attempt, IdentityDigest: request.IdentityDigest,
		IdempotencyKey: request.IdempotencyKey, RequestDigest: requestDigest,
		CreatedAt: now, ExpiresAt: now.Add(s.config.ChallengeTTL),
	}
	if challenge.Validate() != nil {
		return Challenge{}, ErrInvalid
	}
	stored, replay, err := s.repository.CreateChallenge(ctx, challenge)
	if err != nil {
		return Challenge{}, safeRepositoryError(err)
	}
	stored.Replay = replay
	if stored.Validate() != nil || stored.Scope != challenge.Scope || stored.ExecutionID != challenge.ExecutionID ||
		stored.RoleID != challenge.RoleID || stored.Attempt != challenge.Attempt || stored.IdentityDigest != challenge.IdentityDigest ||
		stored.IdempotencyKey != challenge.IdempotencyKey || stored.RequestDigest != challenge.RequestDigest ||
		(!replay && (stored.ChallengeID != challenge.ChallengeID || stored.WorkerID != challenge.WorkerID || !stored.CreatedAt.Equal(challenge.CreatedAt) || !stored.ExpiresAt.Equal(challenge.ExpiresAt))) {
		return Challenge{}, ErrRuntimeUnavailable
	}
	return stored, nil
}

func (s *Service) Enroll(ctx context.Context, request EnrollmentRequest) (Enrollment, error) {
	if s == nil || s.repository == nil || s.verifier == nil || ctx == nil || !validUUID(request.ChallengeID) || !validUUID(request.WorkerID) || request.ChallengeID == request.WorkerID {
		return Enrollment{}, ErrInvalid
	}
	challenge, err := s.repository.GetChallenge(ctx, request.ChallengeID)
	if err != nil {
		return Enrollment{}, safeRepositoryError(err)
	}
	now := s.now()
	if challenge.Validate() != nil || challenge.ChallengeID != request.ChallengeID || challenge.WorkerID != request.WorkerID {
		return Enrollment{}, ErrUnauthorized
	}
	if !challenge.ExpiresAt.After(now) && challenge.ConsumedAt.IsZero() {
		return Enrollment{}, ErrExpired
	}
	identity, err := s.verifier.VerifyEnrollment(ctx, challenge)
	if err != nil || identity.Validate() != nil || identity.WorkerID != challenge.WorkerID || identity.Digest != challenge.IdentityDigest {
		return Enrollment{}, safeIdentityError(err)
	}
	expiresAt := now.Add(s.config.EnrollmentTTL)
	enrollment, replay, err := s.repository.Enroll(ctx, EnrollmentCommand{
		ChallengeID: challenge.ChallengeID, WorkerID: challenge.WorkerID, IdentityDigest: identity.Digest,
		At: now, ExpiresAt: expiresAt,
	})
	if err != nil {
		return Enrollment{}, safeRepositoryError(err)
	}
	enrollment.Replay = replay
	if enrollment.ValidateReceipt() != nil || (!replay && enrollment.Validate(now) != nil) || enrollment.WorkerID != challenge.WorkerID || enrollment.ExecutionID != challenge.ExecutionID ||
		enrollment.RoleID != challenge.RoleID || enrollment.Attempt != challenge.Attempt || (!replay && !enrollment.ExpiresAt.Equal(expiresAt)) {
		return Enrollment{}, ErrRuntimeUnavailable
	}
	return enrollment, nil
}

func (s *Service) GetAssignment(ctx context.Context, request AssignmentRequest) (Assignment, error) {
	access, err := s.authenticate(ctx, request.WorkerID)
	if err != nil {
		return Assignment{}, err
	}
	assignment, err := s.repository.GetAssignment(ctx, access)
	if err != nil {
		return Assignment{}, safeRepositoryError(err)
	}
	if assignment.Validate() != nil || assignment.WorkerID != request.WorkerID {
		return Assignment{}, ErrRuntimeUnavailable
	}
	assignment.Capabilities = append([]coreteam.Capability(nil), assignment.Capabilities...)
	return assignment, nil
}

func (s *Service) Claim(ctx context.Context, request ClaimRequest) (Lease, error) {
	if !validUUID(request.WorkerID) || !validUUID(request.ExecutionID) || !validRoleID(request.RoleID) || request.Attempt == 0 || !validUUID(request.ClaimID) {
		return Lease{}, ErrInvalid
	}
	access, err := s.authenticate(ctx, request.WorkerID)
	if err != nil {
		return Lease{}, err
	}
	lease, replay, err := s.repository.Claim(ctx, ClaimCommand{
		Access: access, ExecutionID: request.ExecutionID, RoleID: request.RoleID,
		Attempt: request.Attempt, ClaimID: request.ClaimID, TTL: s.config.LeaseTTL,
	})
	if err != nil {
		return Lease{}, safeRepositoryError(err)
	}
	lease.Replay = replay
	if lease.ValidateReceipt() != nil || (!replay && lease.Validate(access.At) != nil) || (!replay && !lease.ExpiresAt.Equal(access.At.Add(s.config.LeaseTTL))) ||
		lease.Fence.WorkerID != request.WorkerID || lease.Fence.ExecutionID != request.ExecutionID ||
		lease.Fence.RoleID != request.RoleID || lease.Fence.Attempt != request.Attempt {
		return Lease{}, ErrRuntimeUnavailable
	}
	return lease, nil
}

func (s *Service) Heartbeat(ctx context.Context, request HeartbeatRequest) (Lease, error) {
	if request.Fence.Validate() != nil || !validUUID(request.HeartbeatID) {
		return Lease{}, ErrInvalid
	}
	access, err := s.authenticate(ctx, request.Fence.WorkerID)
	if err != nil {
		return Lease{}, err
	}
	lease, replay, err := s.repository.Heartbeat(ctx, HeartbeatCommand{Access: access, Fence: request.Fence, HeartbeatID: request.HeartbeatID, TTL: s.config.LeaseTTL})
	if err != nil {
		return Lease{}, safeRepositoryError(err)
	}
	lease.Replay = replay
	if lease.ValidateReceipt() != nil || lease.Fence != request.Fence {
		return Lease{}, ErrRuntimeUnavailable
	}
	if !replay {
		upperBase := s.now()
		if upperBase.Before(access.At) {
			upperBase = access.At
		}
		if lease.Validate(access.At) != nil || lease.ExpiresAt.Before(access.At.Add(s.config.LeaseTTL)) || lease.ExpiresAt.After(upperBase.Add(s.config.LeaseTTL)) {
			return Lease{}, ErrRuntimeUnavailable
		}
	}
	return lease, nil
}

func (s *Service) EmitMilestone(ctx context.Context, request MilestoneRequest) (MilestoneReceipt, error) {
	if request.Fence.Validate() != nil || !validUUID(request.EventID) || request.Sequence == 0 || !validStage(request.Stage) ||
		!validHealth(request.Health) || !validDigest(request.EventDigest) {
		return MilestoneReceipt{}, ErrInvalid
	}
	access, err := s.authenticate(ctx, request.Fence.WorkerID)
	if err != nil {
		return MilestoneReceipt{}, err
	}
	receipt, replay, err := s.repository.EmitMilestone(ctx, MilestoneCommand{
		Access: access, Fence: request.Fence, EventID: request.EventID, Sequence: request.Sequence,
		Stage: request.Stage, Health: request.Health, EventDigest: request.EventDigest,
	})
	if err != nil {
		return MilestoneReceipt{}, safeRepositoryError(err)
	}
	receipt.Replay = replay
	if receipt.Validate() != nil || receipt.EventID != request.EventID || receipt.Sequence != request.Sequence || (!replay && !receipt.AcceptedAt.Equal(access.At)) {
		return MilestoneReceipt{}, ErrRuntimeUnavailable
	}
	return receipt, nil
}

func (s *Service) Complete(ctx context.Context, request CompleteRequest) (CompletionReceipt, error) {
	if request.Fence.Validate() != nil || !validUUID(request.CompletionID) || !validCompletion(request) {
		return CompletionReceipt{}, ErrInvalid
	}
	access, err := s.authenticate(ctx, request.Fence.WorkerID)
	if err != nil {
		return CompletionReceipt{}, err
	}
	receipt, replay, err := s.repository.Complete(ctx, CompleteCommand{
		Access: access, Fence: request.Fence, CompletionID: request.CompletionID,
		Outcome: request.Outcome, Result: cloneResultMetadata(request.Result), FailureCode: request.FailureCode,
	})
	if err != nil {
		return CompletionReceipt{}, safeRepositoryError(err)
	}
	receipt.Replay = replay
	if receipt.Validate() != nil || receipt.CompletionID != request.CompletionID || receipt.Outcome != request.Outcome || (!replay && !receipt.AcceptedAt.Equal(access.At)) {
		return CompletionReceipt{}, ErrRuntimeUnavailable
	}
	return receipt, nil
}

func (s *Service) authenticate(ctx context.Context, workerID string) (WorkerAccess, error) {
	if s == nil || s.repository == nil || s.verifier == nil || ctx == nil || !validUUID(workerID) {
		return WorkerAccess{}, ErrInvalid
	}
	identity, err := s.verifier.VerifyWorker(ctx)
	if err != nil || identity.Validate() != nil || identity.WorkerID != workerID {
		return WorkerAccess{}, safeIdentityError(err)
	}
	access := WorkerAccess{WorkerID: workerID, IdentityDigest: identity.Digest, At: s.now()}
	if access.Validate() != nil {
		return WorkerAccess{}, ErrUnauthorized
	}
	return access, nil
}

func (s *Service) now() time.Time { return s.config.Now().UTC() }

func challengeRequestDigest(request ChallengeRequest) string {
	payload, _ := json.Marshal(struct {
		OwnerID           string `json:"owner_id"`
		AccountGeneration int64  `json:"account_generation"`
		ExecutionID       string `json:"execution_id"`
		RoleID            string `json:"role_id"`
		Attempt           uint32 `json:"attempt"`
		IdentityDigest    string `json:"identity_digest"`
	}{request.Scope.OwnerID, request.Scope.AccountGeneration, request.ExecutionID, request.RoleID, request.Attempt, request.IdentityDigest})
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func validCompletion(request CompleteRequest) bool {
	switch request.Outcome {
	case OutcomeSucceeded:
		return request.Result.Validate() == nil && request.FailureCode == ""
	case OutcomeFailed:
		return request.Result.IsZero() && validFailure(request.FailureCode)
	default:
		return false
	}
}

func cloneResultMetadata(result ResultMetadata) ResultMetadata {
	result.PayloadJSON = append([]byte(nil), result.PayloadJSON...)
	return result
}

func safeIdentityError(err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return ErrUnauthorized
}

func safeRepositoryError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	for _, known := range []error{ErrInvalid, ErrNotFound, ErrConflict, ErrExpired, ErrUnauthorized, ErrLeaseConflict, ErrRuntimeUnavailable} {
		if errors.Is(err, known) {
			return known
		}
	}
	return ErrRuntimeUnavailable
}
