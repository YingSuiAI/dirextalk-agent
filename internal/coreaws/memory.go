package coreaws

import (
	"context"
	"encoding/base64"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	"github.com/google/uuid"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

func encodeChangeCursor(planID, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(planID + "\x00" + id))
}
func decodeChangeCursor(planID, token string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) != 2 || parts[0] != planID || uuid.Validate(parts[1]) != nil {
		return "", ErrInvalid
	}
	return parts[1], nil
}

type MemoryRepository struct {
	mu               sync.RWMutex
	credentials      map[string]Credentials
	credentialScopes map[string]coreteam.Scope
	plans            map[string]Plan
	changes          map[string]Change
	tasks            map[string]Task
	confirmations    map[string]coreconfirmation.Confirmation
	reservations     map[string]Reservation
	events           []ChangeEvent
	replays          map[string]memoryReplay
	testClaims       map[string]memoryCredentialTestClaim
}

type ChangeEvent struct {
	ChangeID string
	TaskID   string
	Kind     string
	Revision int64
	At       time.Time
}

type memoryReplay struct {
	digest     string
	err        error
	credential *CredentialView
	plan       *PlanView
	change     *ChangeRequestResult
	test       *CredentialTest
	deleted    bool
}

type memoryCredentialTestClaim struct {
	claim  CredentialTestClaim
	digest string
	state  string
	test   *CredentialTest
}

const (
	memoryCredentialTestInProgress = "in_progress"
	memoryCredentialTestUncertain  = "uncertain"
	memoryCredentialTestFailed     = "failed"
	memoryCredentialTestCompleted  = "completed"
)

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{credentials: map[string]Credentials{}, credentialScopes: map[string]coreteam.Scope{}, plans: map[string]Plan{}, changes: map[string]Change{}, tasks: map[string]Task{}, confirmations: map[string]coreconfirmation.Confirmation{}, reservations: map[string]Reservation{}, replays: map[string]memoryReplay{}, testClaims: map[string]memoryCredentialTestClaim{}}
}

func replayKey(op, key string) string { return op + ":" + key }

// ReplayCredential and ReplayPlan expose the durable idempotency snapshot for
// restart/recovery tests without exposing credential secret bytes.
func (r *MemoryRepository) ReplayCredential(_ context.Context, operation, key, digest string) (CredentialView, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok, err := r.replayLocked(operation, key, digest)
	if !ok || err != nil {
		return CredentialView{}, ok, err
	}
	if v.credential == nil {
		return CredentialView{}, true, ErrConflict
	}
	return *v.credential, true, nil
}
func (r *MemoryRepository) ReplayPlan(_ context.Context, operation, key, digest string) (PlanView, bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok, err := r.replayLocked(operation, key, digest)
	if !ok || err != nil {
		return PlanView{}, ok, err
	}
	if v.plan == nil {
		return PlanView{}, true, ErrConflict
	}
	return *v.plan, true, nil
}

func (r *MemoryRepository) GetTask(_ context.Context, id string) (Task, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tasks[id]
	if !ok {
		return Task{}, ErrNotFound
	}
	return t, nil
}

func (r *MemoryRepository) GetConfirmation(_ context.Context, id string) (coreconfirmation.Confirmation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.confirmations[id]
	if !ok {
		return coreconfirmation.Confirmation{}, ErrNotFound
	}
	return c, nil
}

func (r *MemoryRepository) GetReservation(_ context.Context, id string) (Reservation, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, ok := r.reservations[id]
	if !ok {
		return Reservation{}, ErrNotFound
	}
	return value, nil
}

func (r *MemoryRepository) Events() []ChangeEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return append([]ChangeEvent(nil), r.events...)
}

func (r *MemoryRepository) changesByConfirmationLocked(id string) (Change, bool) {
	for _, c := range r.changes {
		if c.ConfirmationID == id {
			return c, true
		}
	}
	return Change{}, false
}
func (r *MemoryRepository) replayLocked(op, key, digest string) (memoryReplay, bool, error) {
	v, ok := r.replays[replayKey(op, key)]
	if !ok {
		return memoryReplay{}, false, nil
	}
	if v.digest != digest {
		return memoryReplay{}, true, ErrIdempotencyConflict
	}
	if v.err != nil {
		return v, true, v.err
	}
	return v, true, nil
}
func scopedReplayOperation(operation string, scope coreteam.Scope) string {
	return operation + ":" + canonicalDigest(scope)
}
func (r *MemoryRepository) saveCredentialIdempotent(_ context.Context, scope coreteam.Scope, c Credentials, key, digest string) (CredentialView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replays == nil {
		r.replays = map[string]memoryReplay{}
	}
	operation := scopedReplayOperation("credential-save", scope)
	if v, ok, e := r.replayLocked(operation, key, digest); ok {
		if e != nil {
			return CredentialView{}, e
		}
		return *v.credential, nil
	}
	if _, ok := r.credentials[c.ID]; ok {
		return CredentialView{}, ErrConflict
	}
	r.credentials[c.ID] = cloneCredential(c)
	r.credentialScopes[c.ID] = scope
	v := c.View()
	r.replays[replayKey(operation, key)] = memoryReplay{digest: digest, credential: &v}
	return v, nil
}
func (r *MemoryRepository) replaceCredentialIdempotent(_ context.Context, scope coreteam.Scope, c Credentials, expected int64, key, digest string) (CredentialView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replays == nil {
		r.replays = map[string]memoryReplay{}
	}
	operation := scopedReplayOperation("credential-replace", scope)
	if v, ok, e := r.replayLocked(operation, key, digest); ok {
		if e != nil {
			return CredentialView{}, e
		}
		return *v.credential, nil
	}
	old, ok := r.credentials[c.ID]
	if !ok {
		return CredentialView{}, ErrNotFound
	}
	if r.credentialScopes[c.ID] != scope {
		return CredentialView{}, ErrNotFound
	}
	if old.Revision != expected || c.Revision != expected+1 {
		return CredentialView{}, ErrRevisionConflict
	}
	r.credentials[c.ID] = cloneCredential(c)
	v := c.View()
	r.replays[replayKey(operation, key)] = memoryReplay{digest: digest, credential: &v}
	return v, nil
}
func (r *MemoryRepository) deleteCredentialIdempotent(_ context.Context, scope coreteam.Scope, id string, expected int64, key, digest string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replays == nil {
		r.replays = map[string]memoryReplay{}
	}
	operation := scopedReplayOperation("credential-delete", scope)
	if v, ok, e := r.replayLocked(operation, key, digest); ok {
		if e != nil {
			return e
		}
		if v.deleted {
			return nil
		}
	}
	old, ok := r.credentials[id]
	if !ok {
		return ErrNotFound
	}
	if r.credentialScopes[id] != scope {
		return ErrNotFound
	}
	if old.Revision != expected {
		return ErrRevisionConflict
	}
	delete(r.credentials, id)
	delete(r.credentialScopes, id)
	for claimKey, claim := range r.testClaims {
		if claim.claim.CredentialID == id {
			delete(r.testClaims, claimKey)
		}
	}
	v := old.View()
	r.replays[replayKey(operation, key)] = memoryReplay{digest: digest, deleted: true, credential: &v}
	return nil
}
func (r *MemoryRepository) createPlanIdempotent(_ context.Context, p Plan, key, digest string) (PlanView, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replays == nil {
		r.replays = map[string]memoryReplay{}
	}
	scope := coreteam.Scope{OwnerID: p.OwnerID, AccountGeneration: p.AccountGeneration}
	operation := scopedReplayOperation("plan-create", scope)
	if v, ok, e := r.replayLocked(operation, key, digest); ok {
		if e != nil {
			return PlanView{}, e
		}
		return *v.plan, nil
	}
	if r.credentialScopes[p.CredentialID] != scope {
		return PlanView{}, ErrNotFound
	}
	if _, ok := r.plans[p.ID]; ok {
		return PlanView{}, ErrConflict
	}
	r.plans[p.ID] = clonePlan(p)
	v := p.View()
	r.replays[replayKey(operation, key)] = memoryReplay{digest: digest, plan: &v}
	return v, nil
}
func (r *MemoryRepository) CreateCredential(_ context.Context, c Credentials) (Credentials, error) {
	if r == nil || c.Validate() != nil {
		return Credentials{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.credentials[c.ID]; ok {
		return Credentials{}, ErrConflict
	}
	r.credentials[c.ID] = cloneCredential(c)
	return cloneCredential(c), nil
}
func (r *MemoryRepository) GetCredential(_ context.Context, id string) (Credentials, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.credentials[id]
	if !ok {
		return Credentials{}, ErrNotFound
	}
	return cloneCredential(c), nil
}
func (r *MemoryRepository) ListCredentials(_ context.Context, size int, token string) (CredentialPage, error) {
	if size < 0 || size > 100 {
		return CredentialPage{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.credentials))
	for id := range r.credentials {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	start, err := startAfter(ids, token)
	if err != nil {
		return CredentialPage{}, ErrInvalid
	}
	if start > len(ids) {
		return CredentialPage{}, ErrInvalid
	}
	end := len(ids)
	if size > 0 && end > start+size {
		end = start + size
	}
	out := make([]CredentialView, 0, end-start)
	for _, id := range ids[start:end] {
		out = append(out, r.credentials[id].View())
	}
	next := ""
	if end < len(ids) {
		next = ids[end-1]
	}
	return CredentialPage{Items: out, NextPageToken: next}, nil
}
func (r *MemoryRepository) UpdateCredential(_ context.Context, c Credentials, expected int64) (Credentials, error) {
	if c.Validate() != nil {
		return Credentials{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.credentials[c.ID]
	if !ok {
		return Credentials{}, ErrNotFound
	}
	if old.Revision != expected {
		return Credentials{}, ErrRevisionConflict
	}
	if c.Revision != expected+1 {
		return Credentials{}, ErrRevisionConflict
	}
	r.credentials[c.ID] = cloneCredential(c)
	return cloneCredential(c), nil
}
func (r *MemoryRepository) DeleteCredential(_ context.Context, id string, expected int64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.credentials[id]
	if !ok {
		return ErrNotFound
	}
	if old.Revision != expected {
		return ErrRevisionConflict
	}
	delete(r.credentials, id)
	for claimKey, claim := range r.testClaims {
		if claim.claim.CredentialID == id {
			delete(r.testClaims, claimKey)
		}
	}
	return nil
}

func (r *MemoryRepository) CreateCredentialGuarded(ctx context.Context, scope coreteam.Scope, credential Credentials) (Credentials, error) {
	if scope.Validate() != nil || credential.Validate() != nil {
		return Credentials{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.credentials[credential.ID]; exists {
		return Credentials{}, ErrConflict
	}
	if r.credentialScopes == nil {
		r.credentialScopes = map[string]coreteam.Scope{}
	}
	r.credentials[credential.ID] = cloneCredential(credential)
	r.credentialScopes[credential.ID] = scope
	return cloneCredential(credential), nil
}

func (r *MemoryRepository) UpdateCredentialGuarded(ctx context.Context, scope coreteam.Scope, credential Credentials, expected int64) (Credentials, error) {
	if scope.Validate() != nil || credential.Validate() != nil || credential.Revision != expected+1 {
		return Credentials{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old, exists := r.credentials[credential.ID]
	if !exists || r.credentialScopes[credential.ID] != scope {
		return Credentials{}, ErrNotFound
	}
	if old.Revision != expected {
		return Credentials{}, ErrRevisionConflict
	}
	r.credentials[credential.ID] = cloneCredential(credential)
	return cloneCredential(credential), nil
}

func (r *MemoryRepository) DeleteCredentialGuarded(ctx context.Context, scope coreteam.Scope, id string, expected int64) error {
	if scope.Validate() != nil {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old, exists := r.credentials[id]
	if !exists || r.credentialScopes[id] != scope {
		return ErrNotFound
	}
	if old.Revision != expected {
		return ErrRevisionConflict
	}
	delete(r.credentials, id)
	delete(r.credentialScopes, id)
	return nil
}

var _ GuardedCredentialRepository = (*MemoryRepository)(nil)

func (r *MemoryRepository) GetCredentialScoped(_ context.Context, scope coreteam.Scope, id string) (Credentials, error) {
	if scope.Validate() != nil {
		return Credentials{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	credential, exists := r.credentials[id]
	if !exists || r.credentialScopes[id] != scope {
		return Credentials{}, ErrNotFound
	}
	return cloneCredential(credential), nil
}

func (r *MemoryRepository) ListCredentialsScoped(_ context.Context, scope coreteam.Scope, size int, token string) (CredentialPage, error) {
	if scope.Validate() != nil || size < 0 || size > 100 {
		return CredentialPage{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.credentials))
	for id := range r.credentials {
		if r.credentialScopes[id] == scope {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	start, err := startAfter(ids, token)
	if err != nil || start > len(ids) {
		return CredentialPage{}, ErrInvalid
	}
	end := len(ids)
	if size > 0 && end > start+size {
		end = start + size
	}
	items := make([]CredentialView, 0, end-start)
	for _, id := range ids[start:end] {
		items = append(items, r.credentials[id].View())
	}
	next := ""
	if end < len(ids) {
		next = ids[end-1]
	}
	return CredentialPage{Items: items, NextPageToken: next}, nil
}

func (r *MemoryRepository) RecordCredentialIdentityScoped(_ context.Context, scope coreteam.Scope, id string, expected int64, identity Identity, testedAt time.Time) (Credentials, error) {
	if scope.Validate() != nil || testedAt.IsZero() {
		return Credentials{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	credential, exists := r.credentials[id]
	if !exists || r.credentialScopes[id] != scope {
		return Credentials{}, ErrNotFound
	}
	if credential.Revision != expected {
		return Credentials{}, ErrRevisionConflict
	}
	credential.AccountID, credential.UserARN, credential.VerifiedRevision = identity.AccountID, identity.UserARN, credential.Revision
	credential.TestedAt, credential.UpdatedAt = testedAt.UTC(), testedAt.UTC()
	r.credentials[id] = cloneCredential(credential)
	return cloneCredential(credential), nil
}

func (r *MemoryRepository) CreatePlanScoped(ctx context.Context, scope coreteam.Scope, plan Plan, idempotencyKey, requestDigest string) (Plan, error) {
	if scope.Validate() != nil || plan.Validate() != nil || plan.OwnerID != scope.OwnerID || plan.AccountGeneration != scope.AccountGeneration || !validUUID(idempotencyKey) || len(requestDigest) != 64 || strings.IndexFunc(requestDigest, func(r rune) bool { return r < '0' || r > '9' && r < 'a' || r > 'f' }) >= 0 {
		return Plan{}, ErrInvalid
	}
	view, err := r.createPlanIdempotent(ctx, plan, idempotencyKey, requestDigest)
	if err != nil {
		return Plan{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return clonePlan(r.plans[view.ID]), nil
}

func (r *MemoryRepository) GetPlanScoped(_ context.Context, scope coreteam.Scope, id string) (Plan, error) {
	if scope.Validate() != nil {
		return Plan{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	plan, exists := r.plans[id]
	if !exists || plan.OwnerID != scope.OwnerID || plan.AccountGeneration != scope.AccountGeneration {
		return Plan{}, ErrNotFound
	}
	return clonePlan(plan), nil
}

func (r *MemoryRepository) ListPlansScoped(_ context.Context, scope coreteam.Scope, size int, token string) (PlanPage, error) {
	if scope.Validate() != nil || size < 0 || size > 100 {
		return PlanPage{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.plans))
	for id, plan := range r.plans {
		if plan.OwnerID == scope.OwnerID && plan.AccountGeneration == scope.AccountGeneration {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	start, err := startAfter(ids, token)
	if err != nil || start > len(ids) {
		return PlanPage{}, ErrInvalid
	}
	end := len(ids)
	if size > 0 && end > start+size {
		end = start + size
	}
	items := make([]PlanView, 0, end-start)
	for _, id := range ids[start:end] {
		items = append(items, r.plans[id].View())
	}
	next := ""
	if end < len(ids) {
		next = ids[end-1]
	}
	return PlanPage{Items: items, NextPageToken: next}, nil
}

func (r *MemoryRepository) GetChangeScoped(_ context.Context, scope coreteam.Scope, id string) (Change, error) {
	if scope.Validate() != nil {
		return Change{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	change, exists := r.changes[id]
	plan, planExists := r.plans[change.PlanID]
	if !exists || !planExists || plan.OwnerID != scope.OwnerID || plan.AccountGeneration != scope.AccountGeneration {
		return Change{}, ErrNotFound
	}
	return change, nil
}

func (r *MemoryRepository) ListChangesScoped(_ context.Context, scope coreteam.Scope, size int, planID, token string) (ChangePage, error) {
	if scope.Validate() != nil || size < 0 || size > 100 {
		return ChangePage{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.changes))
	for id, change := range r.changes {
		plan, exists := r.plans[change.PlanID]
		if exists && plan.OwnerID == scope.OwnerID && plan.AccountGeneration == scope.AccountGeneration && (planID == "" || change.PlanID == planID) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	lastID, err := decodeChangeCursor(planID, token)
	if err != nil {
		return ChangePage{}, ErrInvalid
	}
	start, err := startAfter(ids, lastID)
	if err != nil || start > len(ids) {
		return ChangePage{}, ErrInvalid
	}
	end := len(ids)
	if size > 0 && end > start+size {
		end = start + size
	}
	items := make([]Change, 0, end-start)
	for _, id := range ids[start:end] {
		items = append(items, r.changes[id])
	}
	next := ""
	if end < len(ids) {
		next = encodeChangeCursor(planID, ids[end-1])
	}
	return ChangePage{Items: items, NextPageToken: next}, nil
}

var _ ScopedRepository = (*MemoryRepository)(nil)

func (r *MemoryRepository) RecordCredentialIdentity(_ context.Context, id string, expected int64, identity Identity, testedAt time.Time) (Credentials, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.credentials[id]
	if !ok {
		return Credentials{}, ErrNotFound
	}
	if c.Revision != expected {
		return Credentials{}, ErrRevisionConflict
	}
	if testedAt.IsZero() {
		return Credentials{}, ErrInvalid
	}
	c.AccountID, c.UserARN, c.VerifiedRevision, c.TestedAt, c.UpdatedAt = identity.AccountID, identity.UserARN, c.Revision, testedAt.UTC(), testedAt.UTC()
	r.credentials[id] = cloneCredential(c)
	return cloneCredential(c), nil
}

// BeginCredentialTest persists the provider-call claim without invoking the
// provider while the repository mutex is held. Existing in-progress claims
// are reported to bounded same-key waiters; uncertain claims fail closed so a
// retry can never issue a second provider request after an ambiguous crash.
func (r *MemoryRepository) BeginCredentialTest(_ context.Context, scope coreteam.Scope, id string, expected int64, key string, leaseTimes ...time.Time) (CredentialTestClaim, *CredentialTest, error) {
	if r == nil || scope.Validate() != nil || !validUUID(id) || !validUUID(key) || expected < 1 {
		return CredentialTestClaim{}, nil, ErrInvalid
	}
	leaseExpiresAt, completionGraceUntil, err := CredentialTestLeaseTimes(time.Now(), leaseTimes...)
	if err != nil {
		return CredentialTestClaim{}, nil, err
	}
	digest := CredentialTestBindingDigest(id, expected)
	claimKey := replayKey(scopedReplayOperation("test-credential-claim", scope), key)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.testClaims == nil {
		r.testClaims = make(map[string]memoryCredentialTestClaim)
	}
	if existing, ok := r.testClaims[claimKey]; ok {
		if existing.digest != digest {
			return CredentialTestClaim{}, nil, ErrIdempotencyConflict
		}
		switch existing.state {
		case memoryCredentialTestCompleted:
			if existing.test == nil {
				return CredentialTestClaim{}, nil, ErrConflict
			}
			replay := *existing.test
			return CredentialTestClaim{}, &replay, nil
		case memoryCredentialTestInProgress, memoryCredentialTestUncertain:
			if existing.state == memoryCredentialTestInProgress {
				return CredentialTestClaim{}, nil, &CredentialTestInProgressError{LeaseExpiresAt: existing.claim.LeaseExpiresAt, CompletionGraceUntil: existing.claim.CompletionGraceUntil}
			}
			return CredentialTestClaim{}, nil, ErrResponseUncertain
		case memoryCredentialTestFailed:
			return CredentialTestClaim{}, nil, ErrProvider
		default:
			return CredentialTestClaim{}, nil, ErrConflict
		}
	}
	credential, ok := r.credentials[id]
	if !ok || r.credentialScopes[id] != scope {
		return CredentialTestClaim{}, nil, ErrNotFound
	}
	if credential.Revision != expected {
		return CredentialTestClaim{}, nil, ErrRevisionConflict
	}
	claim := CredentialTestClaim{ClaimID: newUUID(), IdempotencyKey: key, OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, CredentialID: id, ExpectedRevision: expected, LeaseExpiresAt: leaseExpiresAt, CompletionGraceUntil: completionGraceUntil, Credential: cloneCredential(credential)}
	r.testClaims[claimKey] = memoryCredentialTestClaim{claim: claim, digest: digest, state: memoryCredentialTestInProgress}
	return claim, nil, nil
}

func (r *MemoryRepository) CompleteCredentialTest(_ context.Context, claim CredentialTestClaim, identity Identity, testedAt time.Time) (CredentialTest, error) {
	scope := coreteam.Scope{OwnerID: claim.OwnerID, AccountGeneration: claim.AccountGeneration}
	if r == nil || scope.Validate() != nil || !validUUID(claim.ClaimID) || !validUUID(claim.IdempotencyKey) || !validUUID(claim.CredentialID) || claim.ExpectedRevision < 1 || testedAt.IsZero() {
		return CredentialTest{}, ErrInvalid
	}
	digest := CredentialTestBindingDigest(claim.CredentialID, claim.ExpectedRevision)
	r.mu.Lock()
	defer r.mu.Unlock()
	claimKey := replayKey(scopedReplayOperation("test-credential-claim", scope), claim.IdempotencyKey)
	existing, ok := r.testClaims[claimKey]
	if !ok || existing.digest != digest || existing.claim.ClaimID != claim.ClaimID {
		return CredentialTest{}, ErrResponseUncertain
	}
	if existing.state == memoryCredentialTestCompleted {
		if existing.test == nil {
			return CredentialTest{}, ErrConflict
		}
		return *existing.test, nil
	}
	if existing.state != memoryCredentialTestInProgress {
		return CredentialTest{}, ErrResponseUncertain
	}
	credential, ok := r.credentials[claim.CredentialID]
	if !ok || r.credentialScopes[claim.CredentialID] != scope {
		return CredentialTest{}, ErrNotFound
	}
	if credential.Revision != claim.ExpectedRevision {
		return CredentialTest{}, ErrRevisionConflict
	}
	testedAt = testedAt.UTC()
	persistedTestedAt := laterTime(credential.TestedAt, testedAt)
	persistedUpdatedAt := laterTime(credential.UpdatedAt, testedAt)
	if !credential.TestedAt.After(testedAt) {
		credential.AccountID, credential.UserARN = identity.AccountID, identity.UserARN
	}
	credential.VerifiedRevision = credential.Revision
	credential.TestedAt, credential.UpdatedAt = persistedTestedAt, persistedUpdatedAt
	r.credentials[claim.CredentialID] = cloneCredential(credential)
	persistedIdentity := identity
	if credential.TestedAt.After(testedAt) {
		persistedIdentity.AccountID, persistedIdentity.UserARN = credential.AccountID, credential.UserARN
	}
	test := CredentialTest{CredentialID: claim.CredentialID, Identity: persistedIdentity, CredentialRevision: credential.Revision, TestedAt: persistedTestedAt}
	existing.state, existing.test = memoryCredentialTestCompleted, &test
	r.testClaims[claimKey] = existing
	if r.replays == nil {
		r.replays = make(map[string]memoryReplay)
	}
	r.replays[replayKey(scopedReplayOperation("test_credential", scope), claim.IdempotencyKey)] = memoryReplay{digest: digest, test: &test}
	return test, nil
}

func laterTime(current, candidate time.Time) time.Time {
	if current.After(candidate) {
		return current
	}
	return candidate
}

func (r *MemoryRepository) MarkCredentialTestUncertain(_ context.Context, claim CredentialTestClaim) error {
	scope := coreteam.Scope{OwnerID: claim.OwnerID, AccountGeneration: claim.AccountGeneration}
	if r == nil || scope.Validate() != nil || !validUUID(claim.ClaimID) || !validUUID(claim.IdempotencyKey) || !validUUID(claim.CredentialID) || claim.ExpectedRevision < 1 {
		return ErrInvalid
	}
	digest := CredentialTestBindingDigest(claim.CredentialID, claim.ExpectedRevision)
	r.mu.Lock()
	defer r.mu.Unlock()
	claimKey := replayKey(scopedReplayOperation("test-credential-claim", scope), claim.IdempotencyKey)
	existing, ok := r.testClaims[claimKey]
	if !ok || existing.digest != digest || existing.claim.ClaimID != claim.ClaimID {
		return ErrResponseUncertain
	}
	if existing.state == memoryCredentialTestCompleted || existing.state == memoryCredentialTestUncertain {
		return nil
	}
	if existing.state != memoryCredentialTestInProgress {
		return ErrResponseUncertain
	}
	existing.state = memoryCredentialTestUncertain
	r.testClaims[claimKey] = existing
	return nil
}

func (r *MemoryRepository) MarkCredentialTestFailed(_ context.Context, claim CredentialTestClaim) error {
	scope := coreteam.Scope{OwnerID: claim.OwnerID, AccountGeneration: claim.AccountGeneration}
	if r == nil || scope.Validate() != nil || !validUUID(claim.ClaimID) || !validUUID(claim.IdempotencyKey) || !validUUID(claim.CredentialID) || claim.ExpectedRevision < 1 {
		return ErrInvalid
	}
	digest := CredentialTestBindingDigest(claim.CredentialID, claim.ExpectedRevision)
	r.mu.Lock()
	defer r.mu.Unlock()
	claimKey := replayKey(scopedReplayOperation("test-credential-claim", scope), claim.IdempotencyKey)
	existing, ok := r.testClaims[claimKey]
	if !ok || existing.digest != digest || existing.claim.ClaimID != claim.ClaimID {
		return ErrResponseUncertain
	}
	if existing.state == memoryCredentialTestCompleted || existing.state == memoryCredentialTestUncertain || existing.state == memoryCredentialTestFailed {
		return nil
	}
	if existing.state != memoryCredentialTestInProgress {
		return ErrResponseUncertain
	}
	existing.state = memoryCredentialTestFailed
	r.testClaims[claimKey] = existing
	return nil
}
func (r *MemoryRepository) CreatePlan(_ context.Context, p Plan) (Plan, error) {
	if p.Validate() != nil {
		return Plan{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.plans[p.ID]; ok {
		return Plan{}, ErrConflict
	}
	r.plans[p.ID] = clonePlan(p)
	return clonePlan(p), nil
}
func (r *MemoryRepository) GetPlan(_ context.Context, id string) (Plan, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.plans[id]
	if !ok {
		return Plan{}, ErrNotFound
	}
	return clonePlan(p), nil
}
func (r *MemoryRepository) ListPlans(_ context.Context, size int, token string) (PlanPage, error) {
	if size < 0 || size > 100 {
		return PlanPage{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.plans))
	for id := range r.plans {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	start, e := startAfter(ids, token)
	if e != nil || start > len(ids) {
		return PlanPage{}, ErrInvalid
	}
	end := len(ids)
	if size > 0 && end > start+size {
		end = start + size
	}
	out := make([]PlanView, 0, end-start)
	for _, id := range ids[start:end] {
		out = append(out, r.plans[id].View())
	}
	next := ""
	if end < len(ids) {
		next = ids[end-1]
	}
	return PlanPage{Items: out, NextPageToken: next}, nil
}
func (r *MemoryRepository) CreateChange(_ context.Context, c Change) (Change, error) {
	if !validUUID(c.ID) || !validUUID(c.PlanID) || !validUUID(c.CredentialID) || !validUUID(c.TaskID) || !validUUID(c.ConfirmationID) || !validOperation(c.Operation) || !validStage(c.Stage) || c.Revision < 1 {
		return Change{}, ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.changes[c.ID]; ok {
		return Change{}, ErrConflict
	}
	r.changes[c.ID] = c
	return c, nil
}
func (r *MemoryRepository) GetChange(_ context.Context, id string) (Change, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.changes[id]
	if !ok {
		return Change{}, ErrNotFound
	}
	return c, nil
}
func (r *MemoryRepository) GetChangeByConfirmation(_ context.Context, id string) (Change, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, c := range r.changes {
		if c.ConfirmationID == id {
			return c, nil
		}
	}
	return Change{}, ErrNotFound
}
func (r *MemoryRepository) ListChanges(_ context.Context, size int, planID, token string) (ChangePage, error) {
	if size < 0 || size > 100 {
		return ChangePage{}, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.changes))
	for id, change := range r.changes {
		if planID == "" || change.PlanID == planID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	lastID, err := decodeChangeCursor(planID, token)
	if err != nil {
		return ChangePage{}, ErrInvalid
	}
	start, err := startAfter(ids, lastID)
	if err != nil || start > len(ids) {
		return ChangePage{}, ErrInvalid
	}
	end := len(ids)
	if size > 0 && end > start+size {
		end = start + size
	}
	out := make([]Change, 0, end-start)
	for _, id := range ids[start:end] {
		out = append(out, r.changes[id])
	}
	next := ""
	if end < len(ids) {
		next = encodeChangeCursor(planID, ids[end-1])
	}
	return ChangePage{Items: out, NextPageToken: next}, nil
}
func (r *MemoryRepository) UpdateChange(_ context.Context, c Change, expected int64) (Change, error) {
	if !validStage(c.Stage) {
		return Change{}, ErrInvalid
	}
	if c.Revision != expected+1 {
		return Change{}, ErrRevisionConflict
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	old, ok := r.changes[c.ID]
	if !ok {
		return Change{}, ErrNotFound
	}
	if old.Revision != expected {
		return Change{}, ErrRevisionConflict
	}
	if (old.Stage == StageSucceeded || old.Stage == StageFailed || old.Stage == StageCanceled || old.Status == ChangeSucceeded || old.Status == ChangeFailed || old.Status == ChangeCanceled) && (c.Stage != old.Stage || c.Status != old.Status) {
		return Change{}, ErrConflict
	}
	r.changes[c.ID] = c
	return c, nil
}
func pageStart(token string) (int, error) {
	if strings.TrimSpace(token) == "" {
		return 0, nil
	}
	return strconv.Atoi(token)
}
func startAfter(ids []string, token string) (int, error) {
	if strings.TrimSpace(token) == "" {
		return 0, nil
	}
	for i, id := range ids {
		if id > token {
			return i, nil
		}
	}
	return len(ids), nil
}
func cloneCredential(c Credentials) Credentials {
	if c.private != nil {
		c.private = &credentialPayload{accessKeyID: c.private.accessKeyID, secretAccessKey: c.private.secretAccessKey, sessionToken: c.private.sessionToken}
	}
	return c
}
func clonePlan(p Plan) Plan {
	p.Template = append([]byte(nil), p.Template...)
	p.Parameters = cloneMap(p.Parameters)
	p.Tags = cloneMap(p.Tags)
	p.Capabilities = append([]string(nil), p.Capabilities...)
	return p
}
