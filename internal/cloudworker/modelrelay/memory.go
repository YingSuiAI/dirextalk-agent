package modelrelay

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Authority is mutable fake external state used by MemoryStore tests. The
// production PostgresStore reads the real execution, CoreTask and Worker
// session rows inside each reservation transaction.
type Authority struct {
	Fence          Fence
	ExecutionState string
	TaskRunning    bool
	SessionActive  bool
}

func (a Authority) validate() error {
	if a.Fence.Validate() != nil || !validExecutionState(a.ExecutionState) {
		return ErrInvalid
	}
	return nil
}

type memoryGrant struct {
	grant       Grant
	tokenDigest [32]byte
}

type MemoryStore struct {
	mu          sync.Mutex
	budgets     map[string]executionBudget
	grants      map[string]memoryGrant
	tokens      map[string]string
	invocations map[string]Invocation
	authorities map[string]Authority
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		budgets: make(map[string]executionBudget), grants: make(map[string]memoryGrant), tokens: make(map[string]string),
		invocations: make(map[string]Invocation), authorities: make(map[string]Authority),
	}
}

func (s *MemoryStore) SetAuthority(authority Authority) error {
	if s == nil || authority.validate() != nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorities[authority.Fence.ExecutionID] = authority
	return nil
}

func (s *MemoryStore) Activate(_ context.Context, mutation ActivationMutation) (Grant, error) {
	if s == nil || mutation.Grant.Validate() != nil || mutation.Grant.State != GrantActive {
		return Grant{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.authorize(mutation.Grant.Fence); err != nil {
		return Grant{}, err
	}
	if _, exists := s.grants[mutation.Grant.GrantID]; exists {
		return Grant{}, ErrConflict
	}
	tokenKey := hex.EncodeToString(mutation.TokenDigest[:])
	if _, exists := s.tokens[tokenKey]; exists {
		return Grant{}, ErrConflict
	}
	budget, exists := s.budgets[mutation.Grant.Fence.ExecutionID]
	if !exists {
		budget = executionBudget{
			ExecutionID: mutation.Grant.Fence.ExecutionID, LimitDigest: mutation.Grant.LimitDigest,
			MaxTokens: mutation.Grant.MaxTokens, Revision: 1,
			CreatedAt: mutation.Grant.ActivatedAt, UpdatedAt: mutation.Grant.ActivatedAt,
		}
	} else if budget.validate() != nil || budget.LimitDigest != mutation.Grant.LimitDigest ||
		budget.MaxTokens != mutation.Grant.MaxTokens {
		return Grant{}, ErrConflict
	}
	if budget.availableTokens() == 0 {
		return Grant{}, ErrBudgetExhausted
	}
	for id, stored := range s.grants {
		if stored.grant.Fence.ExecutionID != mutation.Grant.Fence.ExecutionID ||
			stored.grant.State != GrantActive {
			continue
		}
		stored.grant = fenceGrant(stored.grant, "superseded", false, mutation.Grant.ActivatedAt)
		s.grants[id] = stored
	}
	s.grants[mutation.Grant.GrantID] = memoryGrant{
		grant: mutation.Grant, tokenDigest: mutation.TokenDigest,
	}
	s.tokens[tokenKey] = mutation.Grant.GrantID
	s.budgets[budget.ExecutionID] = budget
	return mutation.Grant, nil
}

func (s *MemoryStore) BeginInvocation(_ context.Context, mutation BeginMutation) (Grant, Invocation, error) {
	if s == nil || !canonicalUUID(mutation.InvocationID) || !validPath(mutation.Path) ||
		!validDigest(mutation.RequestDigest) || mutation.RequestedTokens == 0 ||
		mutation.RequestedTokens > MaximumTokens || mutation.At.IsZero() || mutation.At != mutation.At.UTC() {
		return Grant{}, Invocation{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	grantID, ok := s.tokens[hex.EncodeToString(mutation.TokenDigest[:])]
	if !ok {
		return Grant{}, Invocation{}, ErrUnauthorized
	}
	stored := s.grants[grantID]
	if !equalDigest(stored.tokenDigest, mutation.TokenDigest) {
		return Grant{}, Invocation{}, ErrUnauthorized
	}
	if _, duplicate := s.invocations[mutation.InvocationID]; duplicate {
		return Grant{}, Invocation{}, ErrConflict
	}
	grant := stored.grant
	if grant.State == GrantTerminal {
		return grant, Invocation{}, ErrTerminal
	}
	if grant.State != GrantActive {
		return grant, Invocation{}, ErrFenced
	}
	if !mutation.At.Before(grant.ExpiresAt) {
		grant = fenceGrant(grant, "expired", false, mutation.At)
		stored.grant = grant
		s.grants[grantID] = stored
		return grant, Invocation{}, ErrExpired
	}
	if err := s.authorize(grant.Fence); err != nil {
		terminal := err == ErrTerminal
		reason := "stale_fence"
		if terminal {
			reason = "execution_terminal"
		}
		grant = fenceGrant(grant, reason, terminal, mutation.At)
		stored.grant = grant
		s.grants[grantID] = stored
		return grant, Invocation{}, err
	}
	if mutation.Path != grant.Profile.Path() {
		return grant, Invocation{}, ErrUnauthorized
	}
	budget, ok := s.budgets[grant.Fence.ExecutionID]
	if !ok || budget.validate() != nil || budget.LimitDigest != grant.LimitDigest ||
		budget.MaxTokens != grant.MaxTokens {
		return Grant{}, Invocation{}, ErrConflict
	}
	available := budget.availableTokens()
	if grantAvailable := grant.AvailableTokens(); grantAvailable < available {
		available = grantAvailable
	}
	if available == 0 {
		return grant, Invocation{}, ErrBudgetExhausted
	}
	reserved := mutation.RequestedTokens
	if reserved > available {
		reserved = available
	}
	invocation := Invocation{
		InvocationID: mutation.InvocationID, GrantID: grant.GrantID,
		Path: mutation.Path, RequestDigest: mutation.RequestDigest,
		ReservedTokens: reserved, State: InvocationReserved,
		CreatedAt: mutation.At, UpdatedAt: mutation.At,
	}
	grant.ReservedTokens += reserved
	grant.Revision++
	grant.UpdatedAt = mutation.At
	budget.ReservedTokens += reserved
	budget.Revision++
	budget.UpdatedAt = mutation.At
	if grant.Validate() != nil || invocation.Validate() != nil || budget.validate() != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	stored.grant = grant
	s.grants[grantID] = stored
	s.invocations[invocation.InvocationID] = invocation
	s.budgets[budget.ExecutionID] = budget
	return grant, invocation, nil
}

func (s *MemoryStore) Settle(_ context.Context, mutation SettleMutation) (Grant, Invocation, error) {
	if s == nil || !canonicalUUID(mutation.InvocationID) || mutation.ActualTokens > MaximumTokens ||
		mutation.At.IsZero() || mutation.At != mutation.At.UTC() {
		return Grant{}, Invocation{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	invocation, ok := s.invocations[mutation.InvocationID]
	if !ok {
		return Grant{}, Invocation{}, ErrNotFound
	}
	stored := s.grants[invocation.GrantID]
	if invocation.State != InvocationReserved {
		return stored.grant, invocation, ErrConflict
	}
	grant := stored.grant
	var outcomeErr error
	switch grant.State {
	case GrantTerminal:
		outcomeErr = ErrTerminal
	case GrantFenced:
		outcomeErr = ErrFenced
	case GrantActive:
		if !mutation.At.Before(grant.ExpiresAt) {
			outcomeErr = ErrExpired
		} else if err := s.authorize(grant.Fence); err != nil {
			outcomeErr = err
		}
	default:
		return Grant{}, Invocation{}, ErrConflict
	}
	if grant.ReservedTokens < invocation.ReservedTokens {
		return Grant{}, Invocation{}, ErrConflict
	}
	budget, ok := s.budgets[grant.Fence.ExecutionID]
	if !ok || budget.validate() != nil || budget.LimitDigest != grant.LimitDigest ||
		budget.MaxTokens != grant.MaxTokens || budget.ReservedTokens < invocation.ReservedTokens {
		return Grant{}, Invocation{}, ErrConflict
	}
	actual := mutation.ActualTokens
	overrun := actual > invocation.ReservedTokens
	if overrun {
		actual = invocation.ReservedTokens
	}
	grant.ReservedTokens -= invocation.ReservedTokens
	grant.SettledTokens += actual
	grant.Revision++
	grant.UpdatedAt = mutation.At
	budget.ReservedTokens -= invocation.ReservedTokens
	budget.SettledTokens += actual
	budget.Revision++
	budget.UpdatedAt = mutation.At
	invocation.ActualTokens = actual
	invocation.State = InvocationSettled
	invocation.UpdatedAt = mutation.At
	if overrun {
		outcomeErr = ErrBudgetExhausted
		if grant.State == GrantActive {
			grant.State = GrantFenced
			grant.ReasonCode = "provider_token_overrun"
			grant.FencedAt = mutation.At
		}
	} else if outcomeErr != nil && grant.State == GrantActive {
		reason, terminal := "stale_fence", false
		switch {
		case errors.Is(outcomeErr, ErrExpired):
			reason = "expired"
		case errors.Is(outcomeErr, ErrTerminal):
			reason, terminal = "execution_terminal", true
		}
		grant.State = GrantFenced
		grant.ReasonCode = reason
		grant.FencedAt = mutation.At
		if terminal {
			grant.State = GrantTerminal
			grant.TerminalAt = mutation.At
		}
	}
	if grant.Validate() != nil || invocation.Validate() != nil || budget.validate() != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	stored.grant = grant
	s.grants[grant.GrantID] = stored
	s.invocations[invocation.InvocationID] = invocation
	s.budgets[budget.ExecutionID] = budget
	if outcomeErr != nil {
		return grant, invocation, outcomeErr
	}
	return grant, invocation, nil
}

func (s *MemoryStore) Refund(_ context.Context, mutation RefundMutation) (Grant, Invocation, error) {
	if s == nil || !canonicalUUID(mutation.InvocationID) || mutation.At.IsZero() || mutation.At != mutation.At.UTC() {
		return Grant{}, Invocation{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	invocation, ok := s.invocations[mutation.InvocationID]
	if !ok {
		return Grant{}, Invocation{}, ErrNotFound
	}
	stored := s.grants[invocation.GrantID]
	if invocation.State != InvocationReserved || stored.grant.ReservedTokens < invocation.ReservedTokens {
		return stored.grant, invocation, ErrConflict
	}
	grant := stored.grant
	budget, ok := s.budgets[grant.Fence.ExecutionID]
	if !ok || budget.validate() != nil || budget.LimitDigest != grant.LimitDigest ||
		budget.MaxTokens != grant.MaxTokens || budget.ReservedTokens < invocation.ReservedTokens {
		return Grant{}, Invocation{}, ErrConflict
	}
	grant.ReservedTokens -= invocation.ReservedTokens
	grant.Revision++
	grant.UpdatedAt = mutation.At
	budget.ReservedTokens -= invocation.ReservedTokens
	budget.Revision++
	budget.UpdatedAt = mutation.At
	invocation.State = InvocationRefunded
	invocation.UpdatedAt = mutation.At
	if grant.Validate() != nil || invocation.Validate() != nil || budget.validate() != nil {
		return Grant{}, Invocation{}, ErrConflict
	}
	stored.grant = grant
	s.grants[grant.GrantID] = stored
	s.invocations[invocation.InvocationID] = invocation
	s.budgets[budget.ExecutionID] = budget
	return grant, invocation, nil
}

func (s *MemoryStore) FenceExecution(_ context.Context, mutation FenceMutation) error {
	if s == nil || mutation.Fence.Validate() != nil || mutation.ReasonCode == "" ||
		!validReason(mutation.ReasonCode) || mutation.At.IsZero() || mutation.At != mutation.At.UTC() {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	found := false
	for id, stored := range s.grants {
		if stored.grant.Fence != mutation.Fence {
			continue
		}
		found = true
		if stored.grant.State == GrantActive ||
			(mutation.Terminal && stored.grant.State == GrantFenced) {
			stored.grant = fenceGrant(stored.grant, mutation.ReasonCode, mutation.Terminal, mutation.At)
			s.grants[id] = stored
		}
	}
	if !found {
		return ErrNotFound
	}
	return nil
}

func (s *MemoryStore) GetGrant(_ context.Context, grantID string) (Grant, error) {
	if s == nil || !canonicalUUID(grantID) {
		return Grant{}, ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.grants[grantID]
	if !ok {
		return Grant{}, ErrNotFound
	}
	return stored.grant, nil
}

func (s *MemoryStore) authorize(fence Fence) error {
	authority, ok := s.authorities[fence.ExecutionID]
	if !ok || authority.Fence != fence || !authority.TaskRunning || !authority.SessionActive {
		return ErrStaleFence
	}
	switch authority.ExecutionState {
	case "awaiting_worker", "running":
		return nil
	case "succeeded", "failed", "canceled", "rejected", "expired":
		return ErrTerminal
	default:
		return ErrStaleFence
	}
}

func fenceGrant(grant Grant, reason string, terminal bool, at time.Time) Grant {
	grant.State = GrantFenced
	grant.ReasonCode = reason
	grant.FencedAt = at
	grant.TerminalAt = time.Time{}
	if terminal {
		grant.State = GrantTerminal
		grant.TerminalAt = at
	}
	grant.UpdatedAt = at
	grant.Revision++
	return grant
}

func validExecutionState(value string) bool {
	switch value {
	case "waiting_user", "queued", "provisioning", "awaiting_worker", "running",
		"collecting", "validating", "cleaning", "succeeded", "failed", "canceled",
		"rejected", "expired":
		return true
	default:
		return false
	}
}

var _ Store = (*MemoryStore)(nil)
