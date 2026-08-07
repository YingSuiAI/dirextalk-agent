package control

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

type replay struct {
	digest  string
	session Session
}

type MemoryStore struct {
	mu         sync.Mutex
	challenges map[string]ChallengeRecord
	sessions   map[string]Session
	tokens     map[string][32]byte
	replays    map[string]replay
	fences     map[string]bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		challenges: make(map[string]ChallengeRecord), sessions: make(map[string]Session),
		tokens: make(map[string][32]byte), replays: make(map[string]replay),
		fences: make(map[string]bool),
	}
}

func (s *MemoryStore) CreateChallenge(_ context.Context, record ChallengeRecord) error {
	if s == nil || !validUUID(record.ChallengeID) || record.Fence.validate() != nil || record.CreatedAt.IsZero() || !record.ExpiresAt.After(record.CreatedAt) {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.challenges[record.ChallengeID]; exists {
		return ErrConflict
	}
	record.Expectation.RequiredTags = cloneTags(record.Expectation.RequiredTags)
	s.challenges[record.ChallengeID] = record
	return nil
}

func (s *MemoryStore) GetChallenge(_ context.Context, challengeID string) (ChallengeRecord, error) {
	if s == nil || !validUUID(challengeID) {
		return ChallengeRecord{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, ok := s.challenges[challengeID]
	if !ok {
		return ChallengeRecord{}, ErrNotFound
	}
	record.Expectation.RequiredTags = cloneTags(record.Expectation.RequiredTags)
	return record, nil
}

func (s *MemoryStore) Claim(_ context.Context, mutation ClaimMutation) (Session, error) {
	if s == nil || !validUUID(mutation.ChallengeID) || !validUUID(mutation.SessionID) || mutation.Fence.validate() != nil || mutation.At.IsZero() {
		return Session{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge, ok := s.challenges[mutation.ChallengeID]
	if !ok {
		return Session{}, ErrNotFound
	}
	if !challenge.ConsumedAt.IsZero() {
		return Session{}, ErrChallengeConsumed
	}
	if s.fences[memoryFenceKey(mutation.Fence)] {
		return Session{}, ErrStaleLease
	}
	if !mutation.At.Before(challenge.ExpiresAt) {
		return Session{}, ErrChallengeExpired
	}
	if !equalDigest(challenge.NonceDigest, mutation.NonceDigest) || challenge.Fence != mutation.Fence {
		return Session{}, ErrIdentityRejected
	}
	if err := validateClaims(challenge.Expectation, mutation.Identity); err != nil {
		return Session{}, err
	}
	// A Claim response can be lost after the server has consumed the
	// challenge.  The Worker recovers by issuing a fresh challenge for the
	// same durable task fence.  Atomically supersede the previous active
	// session before publishing the replacement so two tokens for one fence
	// can never both complete work.
	for _, current := range s.sessions {
		if current.Fence != mutation.Fence {
			continue
		}
		if !equalExpectation(current.Expectation, challenge.Expectation) {
			return Session{}, ErrIdentityRejected
		}
		switch current.State {
		case SessionActive:
		case SessionFailed:
			if current.FailureCode != "session_superseded" {
				return Session{}, ErrTerminal
			}
		case SessionCompleted:
			return Session{}, ErrTerminal
		default:
			return Session{}, ErrConflict
		}
	}
	for id, current := range s.sessions {
		if current.Fence == mutation.Fence && current.State == SessionActive {
			current.State = SessionFailed
			current.FailureCode = "session_superseded"
			current.FailureSummary = "replaced by a fresh identity claim"
			current.FinishedAt = mutation.At
			current.Revision++
			s.sessions[id] = cloneSession(current)
		}
	}
	challenge.ConsumedAt = mutation.At
	s.challenges[mutation.ChallengeID] = challenge
	session := Session{
		SessionID: mutation.SessionID, Fence: mutation.Fence, Expectation: challenge.Expectation,
		Identity: cloneClaims(mutation.Identity), State: SessionActive, Revision: 1, ClaimedAt: mutation.At, HeartbeatAt: mutation.At,
	}
	s.sessions[session.SessionID] = cloneSession(session)
	s.tokens[session.SessionID] = mutation.TokenDigest
	return cloneSession(session), nil
}

func equalExpectation(a, b IdentityExpectation) bool {
	if a.OwnerID != b.OwnerID || a.AccountGeneration != b.AccountGeneration ||
		a.AccountID != b.AccountID || a.Region != b.Region ||
		a.InstanceID != b.InstanceID || a.LaunchIdentity != b.LaunchIdentity ||
		a.RoleARN != b.RoleARN || a.RoleID != b.RoleID || a.InstanceProfileID != b.InstanceProfileID ||
		len(a.RequiredTags) != len(b.RequiredTags) {
		return false
	}
	for key, value := range a.RequiredTags {
		if b.RequiredTags[key] != value {
			return false
		}
	}
	return true
}

func (s *MemoryStore) Heartbeat(_ context.Context, mutation SessionMutation) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, replayed, err := s.prepareMutation("heartbeat", mutation)
	if err != nil || replayed {
		return session, err
	}
	if mutation.ProgressSequence <= session.ProgressSequence {
		return Session{}, ErrConflict
	}
	session.ProgressSequence = mutation.ProgressSequence
	session.HeartbeatAt = mutation.At
	session.Revision++
	s.saveMutation("heartbeat", mutation, session)
	return cloneSession(session), nil
}

func (s *MemoryStore) Complete(_ context.Context, mutation SessionMutation) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, replayed, err := s.prepareMutation("complete", mutation)
	if err != nil || replayed {
		return session, err
	}
	if mutation.Claim == nil || mutation.RuntimeTopology == nil ||
		mutation.RuntimeTopology.ValidateTerminal() != nil ||
		!digestPattern.MatchString(mutation.TopologyDigest) {
		return Session{}, ErrInvalid
	}
	claim := *mutation.Claim
	topology := *mutation.RuntimeTopology
	session.State = SessionCompleted
	session.Result = &claim
	session.RuntimeTopology = &topology
	session.TopologyDigest = mutation.TopologyDigest
	session.FinishedAt = mutation.At
	session.Revision++
	s.saveMutation("complete", mutation, session)
	return cloneSession(session), nil
}

func (s *MemoryStore) Fail(_ context.Context, mutation SessionMutation) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	session, replayed, err := s.prepareMutation("fail", mutation)
	if err != nil || replayed {
		return session, err
	}
	if mutation.FailureCode == "" {
		return Session{}, ErrInvalid
	}
	session.State = SessionFailed
	session.FailureCode = mutation.FailureCode
	session.FailureSummary = mutation.FailureSummary
	session.FinishedAt = mutation.At
	session.Revision++
	s.saveMutation("fail", mutation, session)
	return cloneSession(session), nil
}

func (s *MemoryStore) GetSession(_ context.Context, sessionID string) (Session, error) {
	if s == nil {
		return Session{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[sessionID]
	if !ok {
		return Session{}, ErrNotFound
	}
	return cloneSession(session), nil
}

func (s *MemoryStore) FindSessionByFence(_ context.Context, fence TaskFence) (Session, error) {
	if s == nil || fence.validate() != nil {
		return Session{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findSessionByFence(fence)
}

func (s *MemoryStore) FindLatestSessionByExecution(_ context.Context, executionID, taskID string, accountGeneration uint64) (Session, error) {
	if s == nil || !validUUID(executionID) || !validUUID(taskID) || accountGeneration == 0 {
		return Session{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var selected Session
	for _, current := range s.sessions {
		if current.Fence.ExecutionID != executionID || current.Fence.TaskID != taskID || current.Fence.AccountGeneration != accountGeneration {
			continue
		}
		if selected.SessionID == "" || current.ClaimedAt.After(selected.ClaimedAt) || (current.ClaimedAt.Equal(selected.ClaimedAt) && current.Revision > selected.Revision) {
			selected = current
		}
	}
	if selected.SessionID == "" {
		// Cancellation before launch/claim still has to establish the current
		// task fence, but there is no Worker session to return. Treat that as a
		// successful no-op so the controller can continue directly to cleanup.
		return Session{}, nil
	}
	return cloneSession(selected), nil
}

func (s *MemoryStore) FenceSession(_ context.Context, mutation SessionFenceMutation) (Session, error) {
	if s == nil || mutation.Fence.validate() != nil || mutation.At.IsZero() || mutation.At != mutation.At.UTC() {
		return Session{}, ErrInvalid
	}
	_, reason, normalizeErr := normalizeFailure("session_fenced", mutation.Reason)
	if normalizeErr != nil || reason == "" {
		return Session{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fences[memoryFenceKey(mutation.Fence)] = true
	current, err := s.findSessionByFence(mutation.Fence)
	if err != nil {
		return Session{}, err
	}
	if current.State != SessionActive {
		return current, nil
	}
	current.State = SessionFailed
	current.FailureCode = "session_fenced"
	current.FailureSummary = reason
	current.FinishedAt = mutation.At
	current.Revision++
	s.sessions[current.SessionID] = cloneSession(current)
	return cloneSession(current), nil
}

func (s *MemoryStore) FenceExecutionSessions(_ context.Context, task coretask.Task, executionID, reason string) (Session, error) {
	if s == nil || task.Spec.Payload.CloudWorker == nil || task.Lease == nil || task.Status != coretask.StatusRunning ||
		!coretask.ValidUUID(task.ID) || task.Spec.Payload.CloudWorker.ExecutionID != executionID ||
		task.Attempt == 0 || task.LeaseEpoch == 0 || !task.Lease.ExpiresAt.After(time.Now().UTC()) {
		return Session{}, ErrInvalid
	}
	_, normalizedReason, err := normalizeFailure("session_fenced", reason)
	if err != nil || normalizedReason == "" {
		return Session{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	currentFence := TaskFence{ExecutionID: executionID, TaskID: task.ID, AccountGeneration: task.Spec.Payload.CloudWorker.AccountGeneration, Attempt: task.Attempt, LeaseEpoch: task.LeaseEpoch}
	s.fences[memoryFenceKey(currentFence)] = true
	var selected Session
	for id, current := range s.sessions {
		if current.Fence.ExecutionID != executionID || current.Fence.TaskID != task.ID || current.Fence.AccountGeneration != task.Spec.Payload.CloudWorker.AccountGeneration {
			continue
		}
		if current.State == SessionActive {
			current.State, current.FailureCode, current.FailureSummary = SessionFailed, "session_fenced", normalizedReason
			current.FinishedAt, current.Revision = time.Now().UTC(), current.Revision+1
			s.sessions[id] = cloneSession(current)
		}
		if selected.SessionID == "" || current.ClaimedAt.After(selected.ClaimedAt) {
			selected = current
		}
	}
	if selected.SessionID == "" {
		return Session{}, ErrNotFound
	}
	return cloneSession(selected), nil
}

func memoryFenceKey(fence TaskFence) string {
	return fence.ExecutionID + ":" + fence.TaskID + ":" + fmt.Sprint(fence.AccountGeneration) + ":" + fmt.Sprint(fence.Attempt) + ":" + fmt.Sprint(fence.LeaseEpoch)
}

func (s *MemoryStore) findSessionByFence(fence TaskFence) (Session, error) {
	var selected Session
	for _, current := range s.sessions {
		if current.Fence != fence {
			continue
		}
		if current.State == SessionActive {
			return cloneSession(current), nil
		}
		if selected.SessionID == "" || current.ClaimedAt.After(selected.ClaimedAt) {
			selected = current
		}
	}
	if selected.SessionID == "" {
		return Session{}, ErrNotFound
	}
	return cloneSession(selected), nil
}

func (s *MemoryStore) prepareMutation(operation string, mutation SessionMutation) (Session, bool, error) {
	if s == nil || !validUUID(mutation.SessionID) || !validIdempotencyKey(mutation.IdempotencyKey) || mutation.Fence.validate() != nil || mutation.At.IsZero() || !digestPattern.MatchString(mutation.RequestDigest) {
		return Session{}, false, ErrInvalid
	}
	replayKey := operation + ":" + mutation.SessionID + ":" + mutation.IdempotencyKey
	if value, ok := s.replays[replayKey]; ok {
		if subtle.ConstantTimeCompare([]byte(value.digest), []byte(mutation.RequestDigest)) != 1 {
			return Session{}, false, ErrConflict
		}
		return cloneSession(value.session), true, nil
	}
	session, ok := s.sessions[mutation.SessionID]
	if !ok {
		return Session{}, false, ErrNotFound
	}
	token, ok := s.tokens[mutation.SessionID]
	if !ok || !equalDigest(token, mutation.TokenDigest) || session.Fence != mutation.Fence {
		return Session{}, false, ErrSessionRejected
	}
	if session.State != SessionActive {
		return Session{}, false, ErrTerminal
	}
	return session, false, nil
}

func (s *MemoryStore) saveMutation(operation string, mutation SessionMutation, session Session) {
	s.sessions[session.SessionID] = cloneSession(session)
	key := operation + ":" + mutation.SessionID + ":" + mutation.IdempotencyKey
	s.replays[key] = replay{digest: mutation.RequestDigest, session: cloneSession(session)}
}

func cloneTags(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneClaims(source IdentityClaims) IdentityClaims {
	source.Tags = cloneTags(source.Tags)
	return source
}

func cloneSession(source Session) Session {
	source.Expectation.RequiredTags = cloneTags(source.Expectation.RequiredTags)
	source.Identity = cloneClaims(source.Identity)
	if source.Result != nil {
		claim := *source.Result
		source.Result = &claim
	}
	if source.RuntimeTopology != nil {
		topology := *source.RuntimeTopology
		source.RuntimeTopology = &topology
	}
	source.FailureSummary = strings.Clone(source.FailureSummary)
	return source
}
