package control

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	defaultIdentityVerificationRetryTimeout        = 30 * time.Second
	defaultIdentityVerificationRetryInitialBackoff = time.Second
	defaultIdentityVerificationRetryMaximumBackoff = 5 * time.Second
)

type identityVerificationRetryPolicy struct {
	timeout        time.Duration
	initialBackoff time.Duration
	maximumBackoff time.Duration
}

type Service struct {
	store                Store
	verifier             IdentityVerifier
	leases               LeaseAuthority
	clock                func() time.Time
	random               func([]byte) error
	identityRetry        identityVerificationRetryPolicy
	waitForIdentityRetry func(context.Context, time.Duration) error
}

func NewService(store Store, verifier IdentityVerifier, leases LeaseAuthority) (*Service, error) {
	if store == nil || verifier == nil || leases == nil {
		return nil, ErrInvalid
	}
	return &Service{
		store: store, verifier: verifier, leases: leases,
		clock:  func() time.Time { return time.Now().UTC() },
		random: func(value []byte) error { _, err := rand.Read(value); return err },
		identityRetry: identityVerificationRetryPolicy{
			timeout:        defaultIdentityVerificationRetryTimeout,
			initialBackoff: defaultIdentityVerificationRetryInitialBackoff,
			maximumBackoff: defaultIdentityVerificationRetryMaximumBackoff,
		},
		waitForIdentityRetry: waitForIdentityVerificationRetry,
	}, nil
}

func (s *Service) IssueIdentityChallenge(ctx context.Context, request IssueChallengeRequest) (Challenge, error) {
	if s == nil || request.Fence.validate() != nil {
		return Challenge{}, ErrInvalid
	}
	expectation, err := request.Expectation.normalize()
	if err != nil {
		return Challenge{}, err
	}
	ttl := request.TTL
	if ttl == 0 {
		ttl = DefaultChallengeTTL
	}
	if ttl < time.Second || ttl > DefaultChallengeTTL {
		return Challenge{}, ErrInvalid
	}
	if err := s.leases.ValidateCloudWorkerLease(ctx, request.Fence); err != nil {
		return Challenge{}, ErrStaleLease
	}
	nonce, err := s.randomValue(32)
	if err != nil {
		return Challenge{}, fmt.Errorf("issue cloud Worker identity challenge: %w", ErrConflict)
	}
	now := s.clock().UTC()
	challenge := Challenge{ChallengeID: uuid.NewString(), Nonce: nonce, Fence: request.Fence, ExpiresAt: now.Add(ttl)}
	record := ChallengeRecord{
		ChallengeID: challenge.ChallengeID, NonceDigest: digestToken([]byte(nonce)), Fence: request.Fence,
		Expectation: expectation, ExpiresAt: challenge.ExpiresAt, CreatedAt: now,
	}
	if err := s.store.CreateChallenge(ctx, record); err != nil {
		return Challenge{}, err
	}
	return challenge, nil
}

func (s *Service) Claim(ctx context.Context, request ClaimRequest) (ClaimResult, error) {
	if s == nil || !validUUID(request.ChallengeID) || request.Fence.validate() != nil || strings.TrimSpace(request.Nonce) != request.Nonce || len(request.Nonce) < 32 || validateProof(request.Proof) != nil {
		return ClaimResult{}, ErrInvalid
	}
	defer clear(request.Proof.Payload)
	if err := s.leases.ValidateCloudWorkerLease(ctx, request.Fence); err != nil {
		logClaimRejected(request, "lease", ErrStaleLease)
		return ClaimResult{}, ErrStaleLease
	}
	challenge, err := s.store.GetChallenge(ctx, request.ChallengeID)
	if err != nil {
		logClaimRejected(request, "challenge_lookup", err)
		return ClaimResult{}, err
	}
	now := s.clock().UTC()
	if !challenge.ConsumedAt.IsZero() {
		logClaimRejected(request, "challenge_consumed", ErrChallengeConsumed)
		return ClaimResult{}, ErrChallengeConsumed
	}
	if !now.Before(challenge.ExpiresAt) {
		logClaimRejected(request, "challenge_expired", ErrChallengeExpired)
		return ClaimResult{}, ErrChallengeExpired
	}
	if challenge.Fence != request.Fence || !equalDigest(challenge.NonceDigest, digestToken([]byte(request.Nonce))) {
		logClaimRejected(request, "challenge_binding", ErrIdentityRejected)
		return ClaimResult{}, ErrIdentityRejected
	}
	claims, err := s.verifyIdentityWithRetry(ctx, request, challenge.ExpiresAt)
	if err != nil {
		logClaimRejected(request, "identity_verifier", err)
		return ClaimResult{}, redactedVerifierError(err)
	}
	now = s.clock().UTC()
	if !now.Before(challenge.ExpiresAt) {
		logClaimRejected(request, "post_verification_challenge_expired", ErrChallengeExpired)
		return ClaimResult{}, ErrChallengeExpired
	}
	if err := s.leases.ValidateCloudWorkerLease(ctx, request.Fence); err != nil {
		logClaimRejected(request, "post_verification_lease", ErrStaleLease)
		return ClaimResult{}, ErrStaleLease
	}
	if err := validateClaims(challenge.Expectation, claims); err != nil {
		logClaimRejected(request, "identity_claims", err)
		return ClaimResult{}, err
	}
	token, err := s.randomBytes(48)
	if err != nil {
		return ClaimResult{}, fmt.Errorf("claim cloud Worker identity: %w", ErrConflict)
	}
	mutation := ClaimMutation{
		ChallengeID: request.ChallengeID, NonceDigest: digestToken([]byte(request.Nonce)), Fence: request.Fence,
		Identity: claims, SessionID: uuid.NewString(), TokenDigest: digestToken(token), At: now,
	}
	session, err := s.store.Claim(ctx, mutation)
	if err != nil {
		logClaimRejected(request, "session_claim", err)
		return ClaimResult{}, err
	}
	if err := validateClaims(session.Expectation, claims); err != nil {
		logClaimRejected(request, "session_claims", err)
		return ClaimResult{}, err
	}
	return ClaimResult{Session: session, SessionToken: append([]byte(nil), token...)}, nil
}

// verifyIdentityWithRetry absorbs short AWS identity/read-back convergence
// after the durable challenge and fence have already been validated. Every
// attempt runs the complete verifier against a private proof copy; no identity
// mismatch is accepted and the challenge remains unconsumed until verification
// and the atomic session claim both succeed.
func (s *Service) verifyIdentityWithRetry(
	ctx context.Context,
	request ClaimRequest,
	challengeExpiresAt time.Time,
) (IdentityClaims, error) {
	policy := s.identityRetry
	if policy.timeout <= 0 || policy.initialBackoff <= 0 ||
		policy.maximumBackoff < policy.initialBackoff || s.waitForIdentityRetry == nil {
		return IdentityClaims{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return IdentityClaims{}, err
	}
	start := s.clock().UTC()
	deadline := start.Add(policy.timeout)
	if challengeExpiresAt.Before(deadline) {
		deadline = challengeExpiresAt
	}
	retryDuration := deadline.Sub(start)
	if retryDuration <= 0 {
		return IdentityClaims{}, ErrIdentityRejected
	}
	retryCtx, cancel := context.WithTimeout(ctx, retryDuration)
	defer cancel()
	backoff := policy.initialBackoff
	attempt := 0
	for {
		if err := ctx.Err(); err != nil {
			return IdentityClaims{}, err
		}
		if retryCtx.Err() != nil || !s.clock().UTC().Before(deadline) {
			return IdentityClaims{}, ErrIdentityRejected
		}
		attempt++
		proof := IdentityProof{
			Method:  request.Proof.Method,
			Payload: bytes.Clone(request.Proof.Payload),
		}
		claims, err := s.verifier.Verify(retryCtx, request.Nonce, proof)
		clear(proof.Payload)
		if err == nil {
			return claims, nil
		}
		if ctx.Err() != nil {
			return IdentityClaims{}, ctx.Err()
		}
		if !errors.Is(err, ErrIdentityRejected) {
			return IdentityClaims{}, err
		}
		remaining := deadline.Sub(s.clock().UTC())
		if retryCtx.Err() != nil || remaining <= 0 {
			return IdentityClaims{}, ErrIdentityRejected
		}
		delay := min(backoff, remaining)
		slog.Warn(
			"[cloud-worker.control] identity_verification_retry",
			"execution_id", request.Fence.ExecutionID,
			"task_id", request.Fence.TaskID,
			"verification_attempt", attempt,
			"delay_ms", delay.Milliseconds(),
		)
		if err := s.waitForIdentityRetry(retryCtx, delay); err != nil {
			if ctx.Err() != nil {
				return IdentityClaims{}, ctx.Err()
			}
			return IdentityClaims{}, ErrIdentityRejected
		}
		if backoff < policy.maximumBackoff {
			backoff = min(backoff*2, policy.maximumBackoff)
		}
	}
}

func waitForIdentityVerificationRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func logClaimRejected(request ClaimRequest, stage string, err error) {
	slog.Warn(
		"[cloud-worker.control] claim_rejected",
		"execution_id", request.Fence.ExecutionID,
		"task_id", request.Fence.TaskID,
		"attempt", request.Fence.Attempt,
		"lease_epoch", request.Fence.LeaseEpoch,
		"stage", stage,
		"class", claimErrorClass(err),
	)
}

func claimErrorClass(err error) string {
	switch {
	case errors.Is(err, ErrNotFound):
		return "not_found"
	case errors.Is(err, ErrChallengeExpired):
		return "challenge_expired"
	case errors.Is(err, ErrChallengeConsumed):
		return "challenge_consumed"
	case errors.Is(err, ErrIdentityRejected):
		return "identity_rejected"
	case errors.Is(err, ErrStaleLease):
		return "stale_lease"
	case errors.Is(err, ErrConflict):
		return "conflict"
	case errors.Is(err, context.Canceled):
		return "canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline_exceeded"
	default:
		return "unavailable"
	}
}

func (s *Service) Heartbeat(ctx context.Context, request HeartbeatRequest) (Session, error) {
	if s == nil || !validUUID(request.SessionID) || !validIdempotencyKey(request.IdempotencyKey) || request.Fence.validate() != nil || request.ProgressSequence == 0 {
		return Session{}, ErrInvalid
	}
	if err := s.leases.ValidateCloudWorkerLease(ctx, request.Fence); err != nil {
		return Session{}, ErrStaleLease
	}
	mutation := SessionMutation{
		SessionID: request.SessionID, TokenDigest: digestToken(request.SessionToken), Fence: request.Fence,
		ProgressSequence: request.ProgressSequence, IdempotencyKey: request.IdempotencyKey, At: s.clock().UTC(),
	}
	mutation.RequestDigest = mutationDigest("heartbeat", mutation)
	return s.store.Heartbeat(ctx, mutation)
}

func (s *Service) Complete(ctx context.Context, request CompleteRequest) (Session, error) {
	if s == nil || !validUUID(request.SessionID) || !validIdempotencyKey(request.IdempotencyKey) || request.Fence.validate() != nil {
		return Session{}, ErrInvalid
	}
	claim, err := request.Claim.normalize()
	if err != nil {
		return Session{}, err
	}
	if request.RuntimeTopology.ValidateTerminal() != nil ||
		request.RuntimeTopology.ExecutionID != request.Fence.ExecutionID ||
		request.RuntimeTopology.TaskID != request.Fence.TaskID ||
		request.RuntimeTopology.Attempt != request.Fence.Attempt ||
		request.RuntimeTopology.LeaseEpoch != request.Fence.LeaseEpoch {
		return Session{}, ErrInvalid
	}
	topologyDigest, err := request.RuntimeTopology.Digest()
	if err != nil {
		return Session{}, ErrInvalid
	}
	if err := s.leases.ValidateCloudWorkerLease(ctx, request.Fence); err != nil {
		return Session{}, ErrStaleLease
	}
	mutation := SessionMutation{
		SessionID: request.SessionID, TokenDigest: digestToken(request.SessionToken), Fence: request.Fence,
		Claim: &claim, RuntimeTopology: &request.RuntimeTopology, TopologyDigest: topologyDigest,
		IdempotencyKey: request.IdempotencyKey, At: s.clock().UTC(),
	}
	mutation.RequestDigest = mutationDigest("complete", mutation)
	return s.store.Complete(ctx, mutation)
}

func (s *Service) Fail(ctx context.Context, request FailRequest) (Session, error) {
	if s == nil || !validUUID(request.SessionID) || !validIdempotencyKey(request.IdempotencyKey) || request.Fence.validate() != nil {
		return Session{}, ErrInvalid
	}
	code, summary, err := normalizeFailure(request.Code, request.Summary)
	if err != nil {
		return Session{}, err
	}
	if err := s.leases.ValidateCloudWorkerLease(ctx, request.Fence); err != nil {
		return Session{}, ErrStaleLease
	}
	mutation := SessionMutation{
		SessionID: request.SessionID, TokenDigest: digestToken(request.SessionToken), Fence: request.Fence,
		FailureCode: code, FailureSummary: summary, IdempotencyKey: request.IdempotencyKey, At: s.clock().UTC(),
	}
	mutation.RequestDigest = mutationDigest("fail", mutation)
	return s.store.Fail(ctx, mutation)
}

func (s *Service) GetSession(ctx context.Context, sessionID string) (Session, error) {
	if s == nil || !validUUID(sessionID) {
		return Session{}, ErrInvalid
	}
	return s.store.GetSession(ctx, sessionID)
}

func (s *Service) FindSessionByFence(ctx context.Context, fence TaskFence) (Session, error) {
	if s == nil || fence.validate() != nil {
		return Session{}, ErrInvalid
	}
	return s.store.FindSessionByFence(ctx, fence)
}

// FenceSession is used by the durable controller before cancellation cleanup.
// Store, not this early service check, owns the same-transaction CoreTask
// revalidation so a concurrent reclaim or replacement claim cannot escape.
func (s *Service) FenceSession(ctx context.Context, fence TaskFence, reason string) (Session, error) {
	if s == nil || fence.validate() != nil {
		return Session{}, ErrInvalid
	}
	reason = strings.TrimSpace(reason)
	if reason == "" || len(reason) > 512 {
		return Session{}, ErrInvalid
	}
	return s.store.FenceSession(ctx, SessionFenceMutation{Fence: fence, Reason: reason, At: s.clock().UTC()})
}

func (s *Service) randomValue(size int) (string, error) {
	value, err := s.randomBytes(size)
	if err != nil {
		return "", err
	}
	defer clear(value)
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func (s *Service) randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if err := s.random(value); err != nil {
		clear(value)
		return nil, err
	}
	return value, nil
}

func mutationDigest(operation string, mutation SessionMutation) string {
	claim := mutation.Claim
	payload := struct {
		Operation        string       `json:"operation"`
		SessionID        string       `json:"session_id"`
		TokenDigest      string       `json:"token_digest"`
		Fence            TaskFence    `json:"fence"`
		ProgressSequence uint64       `json:"progress_sequence,omitempty"`
		Claim            *ObjectClaim `json:"claim,omitempty"`
		RuntimeTopology  any          `json:"runtime_topology,omitempty"`
		TopologyDigest   string       `json:"topology_digest,omitempty"`
		FailureCode      string       `json:"failure_code,omitempty"`
		FailureSummary   string       `json:"failure_summary,omitempty"`
	}{operation, mutation.SessionID, digestHex(mutation.TokenDigest[:]), mutation.Fence, mutation.ProgressSequence, claim, mutation.RuntimeTopology, mutation.TopologyDigest, mutation.FailureCode, mutation.FailureSummary}
	raw, _ := json.Marshal(payload)
	return digestHex(raw)
}
