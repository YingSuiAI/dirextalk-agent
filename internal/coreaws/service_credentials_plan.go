package coreaws

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
)

const (
	credentialTestPollInterval    = 20 * time.Millisecond
	credentialTestFinalizeTimeout = 5 * time.Second
)

func (s *Service) SaveCredential(ctx context.Context, in CredentialInput) (CredentialView, error) {
	if s == nil || s.repo == nil {
		return CredentialView{}, ErrInvalid
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return CredentialView{}, err
	}
	guarded, ok := s.repo.(GuardedCredentialRepository)
	if !ok {
		return CredentialView{}, ErrInvalid
	}
	if in.IdempotencyKey == "" {
		in.IdempotencyKey = newUUID()
	}
	if !validUUID(in.IdempotencyKey) {
		return CredentialView{}, ErrInvalid
	}
	digest := canonicalDigest(struct {
		Scope       coreteam.Scope
		InputDigest string
	}{scope, credentialInputDigest(in)})
	if durable, ok := s.repo.(DurableCredentialMutationRepository); ok {
		if replay, found, replayErr := durable.ReplayCredentialMutation(ctx, scope, CredentialMutationCreate, in.IdempotencyKey, digest); found || replayErr != nil {
			return replay.Credential, replayErr
		}
	}
	if mr, ok := s.repo.(*MemoryRepository); ok {
		mr.mu.Lock()
		if v, hit, e := mr.replayLocked(scopedReplayOperation("credential-save", scope), in.IdempotencyKey, digest); hit {
			mr.mu.Unlock()
			if e != nil {
				return CredentialView{}, e
			}
			return *v.credential, nil
		}
		mr.mu.Unlock()
	}
	id := in.ID
	if id == "" {
		id = newUUID()
	}
	now := s.now().UTC()
	c := Credentials{ID: id, Name: strings.TrimSpace(in.Name), Region: strings.TrimSpace(in.Region), private: &credentialPayload{accessKeyID: in.AccessKeyID, secretAccessKey: in.SecretAccessKey, sessionToken: in.SessionToken}, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := c.Validate(); err != nil {
		return CredentialView{}, err
	}
	if mr, ok := s.repo.(*MemoryRepository); ok {
		view, e := mr.saveCredentialIdempotent(ctx, scope, c, in.IdempotencyKey, digest)
		return view, e
	}
	if durable, ok := s.repo.(DurableCredentialMutationRepository); ok {
		return durable.CreateCredentialGuardedIdempotent(ctx, scope, c, in.IdempotencyKey, digest)
	}
	v, e := guarded.CreateCredentialGuarded(ctx, scope, c)
	return v.View(), e
}
func (s *Service) GetCredential(ctx context.Context, id string) (CredentialView, error) {
	if s == nil || s.repo == nil || !validUUID(id) {
		return CredentialView{}, ErrInvalid
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return CredentialView{}, err
	}
	repository, err := scopedRepository(s.repo)
	if err != nil {
		return CredentialView{}, err
	}
	c, e := repository.GetCredentialScoped(ctx, scope, id)
	if e != nil {
		return CredentialView{}, e
	}
	return c.View(), nil
}
func (s *Service) ListCredentials(ctx context.Context, size int, token string) (CredentialPage, error) {
	if s == nil || s.repo == nil {
		return CredentialPage{}, ErrInvalid
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return CredentialPage{}, err
	}
	repository, err := scopedRepository(s.repo)
	if err != nil {
		return CredentialPage{}, err
	}
	return repository.ListCredentialsScoped(ctx, scope, size, token)
}
func (s *Service) ReplaceCredential(ctx context.Context, in CredentialInput, expected int64, idem ...string) (CredentialView, error) {
	if s == nil || s.repo == nil {
		return CredentialView{}, ErrInvalid
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return CredentialView{}, err
	}
	guarded, ok := s.repo.(GuardedCredentialRepository)
	if !ok {
		return CredentialView{}, ErrInvalid
	}
	key := ""
	if len(idem) > 0 {
		key = idem[0]
	}
	if key == "" {
		key = newUUID()
	}
	if !validUUID(key) {
		return CredentialView{}, ErrInvalid
	}
	digest := canonicalDigest(struct {
		Scope       coreteam.Scope
		InputDigest string
		Expected    int64
	}{scope, credentialInputDigest(in), expected})
	if durable, ok := s.repo.(DurableCredentialMutationRepository); ok {
		if replay, found, replayErr := durable.ReplayCredentialMutation(ctx, scope, CredentialMutationReplace, key, digest); found || replayErr != nil {
			return replay.Credential, replayErr
		}
	}
	if mr, ok := s.repo.(*MemoryRepository); ok {
		mr.mu.Lock()
		if v, hit, e := mr.replayLocked(scopedReplayOperation("credential-replace", scope), key, digest); hit {
			mr.mu.Unlock()
			if e != nil {
				return CredentialView{}, e
			}
			return *v.credential, nil
		}
		mr.mu.Unlock()
	}
	if !validUUID(in.ID) {
		return CredentialView{}, ErrInvalid
	}
	repository, err := scopedRepository(s.repo)
	if err != nil {
		return CredentialView{}, err
	}
	old, e := repository.GetCredentialScoped(ctx, scope, in.ID)
	if e != nil {
		return CredentialView{}, e
	}
	c := old
	c.Name = strings.TrimSpace(in.Name)
	c.Region = strings.TrimSpace(in.Region)
	if c.private == nil {
		c.private = &credentialPayload{}
	}
	if in.AccessKeyID != "" {
		c.private.accessKeyID = in.AccessKeyID
	}
	if in.SecretAccessKey != "" {
		c.private.secretAccessKey = in.SecretAccessKey
	}
	if in.SessionToken != "" {
		c.private.sessionToken = in.SessionToken
	}
	c.Revision = expected + 1
	c.AccountID, c.UserARN, c.VerifiedRevision, c.TestedAt = "", "", 0, time.Time{}
	c.UpdatedAt = s.now().UTC()
	if err := c.Validate(); err != nil {
		return CredentialView{}, err
	}
	if mr, ok := s.repo.(*MemoryRepository); ok {
		view, e := mr.replaceCredentialIdempotent(ctx, scope, c, expected, key, digest)
		return view, e
	}
	if durable, ok := s.repo.(DurableCredentialMutationRepository); ok {
		return durable.UpdateCredentialGuardedIdempotent(ctx, scope, c, expected, key, digest)
	}
	v, e := guarded.UpdateCredentialGuarded(ctx, scope, c, expected)
	if e != nil {
		return CredentialView{}, e
	}
	view := v.View()
	return view, nil
}
func (s *Service) DeleteCredential(ctx context.Context, id string, expected int64, idem ...string) error {
	if s == nil || s.repo == nil {
		return ErrInvalid
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return err
	}
	guarded, ok := s.repo.(GuardedCredentialRepository)
	if !ok {
		return ErrInvalid
	}
	key := ""
	if len(idem) > 0 {
		key = idem[0]
	}
	if key == "" {
		key = newUUID()
	}
	if !validUUID(key) {
		return ErrInvalid
	}
	digest := canonicalDigest(struct {
		Scope    coreteam.Scope
		ID       string
		Expected int64
	}{scope, id, expected})
	if durable, ok := s.repo.(DurableCredentialMutationRepository); ok {
		if _, found, replayErr := durable.ReplayCredentialMutation(ctx, scope, CredentialMutationDelete, key, digest); found || replayErr != nil {
			return replayErr
		}
	}
	if !validUUID(id) || expected < 1 {
		return ErrInvalid
	}
	repository, err := scopedRepository(s.repo)
	if err != nil {
		return err
	}
	credential, err := repository.GetCredentialScoped(ctx, scope, id)
	if err != nil {
		return err
	}
	if credential.Revision != expected {
		return ErrRevisionConflict
	}
	if mr, ok := s.repo.(*MemoryRepository); ok {
		return mr.deleteCredentialIdempotent(ctx, scope, id, expected, key, digest)
	}
	if durable, ok := s.repo.(DurableCredentialMutationRepository); ok {
		return durable.DeleteCredentialGuardedIdempotent(ctx, scope, id, expected, key, digest)
	}
	return guarded.DeleteCredentialGuarded(ctx, scope, id, expected)
}
func (s *Service) TestCredential(ctx context.Context, id string) (CredentialTest, error) {
	if s.sts == nil {
		return CredentialTest{}, ErrProvider
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return CredentialTest{}, err
	}
	repository, err := scopedRepository(s.repo)
	if err != nil {
		return CredentialTest{}, err
	}
	c, e := repository.GetCredentialScoped(ctx, scope, id)
	if e != nil {
		return CredentialTest{}, e
	}
	identity, e := s.sts.GetCallerIdentity(ctx, c.handle())
	if e != nil {
		return CredentialTest{}, ErrProvider
	}
	testedAt := s.now().UTC()
	updated, ue := repository.RecordCredentialIdentityScoped(ctx, scope, id, c.Revision, identity, testedAt)
	if ue != nil {
		return CredentialTest{}, ue
	}
	c = updated
	return CredentialTest{CredentialID: id, Identity: identity, CredentialRevision: c.Revision, TestedAt: testedAt}, nil
}

// TestCredentialIdempotent is the neutral Capability-only credential test.
// Unlike the legacy gRPC TestCredential method, it requires an explicit UUID
// key and expected revision.  The repository first commits a durable claim,
// then this service performs the provider call with no database transaction,
// row lock, or process-global mutex held.  A crash or failed completion leaves
// the claim in an uncertain state and future retries fail closed rather than
// issuing a second provider request.
func (s *Service) TestCredentialIdempotent(ctx context.Context, id string, expectedRevision int64, idempotencyKey string) (CredentialTest, error) {
	if s == nil || s.repo == nil || !validUUID(id) || !validUUID(idempotencyKey) || expectedRevision < 1 {
		return CredentialTest{}, ErrInvalid
	}
	if s.sts == nil {
		return CredentialTest{}, ErrProvider
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return CredentialTest{}, err
	}
	repository, ok := s.repo.(CredentialIdentityIdempotencyRepository)
	if !ok {
		return CredentialTest{}, ErrConflict
	}
	leaseStart := s.now().UTC()
	leaseExpiresAt, completionGraceUntil, err := CredentialTestLeaseTimes(leaseStart)
	if err != nil {
		return CredentialTest{}, err
	}
	for {
		claim, replay, err := repository.BeginCredentialTest(ctx, scope, id, expectedRevision, idempotencyKey, leaseExpiresAt, completionGraceUntil)
		if err == nil {
			if replay != nil {
				return *replay, nil
			}
			return s.runCredentialTestProvider(ctx, repository, claim)
		}
		if !errors.Is(err, ErrCredentialTestInProgress) {
			return CredentialTest{}, err
		}
		deadline := completionGraceUntil
		var inProgress *CredentialTestInProgressError
		if errors.As(err, &inProgress) {
			if !inProgress.CompletionGraceUntil.IsZero() {
				deadline = inProgress.CompletionGraceUntil.UTC()
			} else if !inProgress.LeaseExpiresAt.IsZero() {
				deadline = inProgress.LeaseExpiresAt.UTC()
			}
		}
		now := s.now().UTC()
		if !deadline.IsZero() && !now.Before(deadline) {
			return CredentialTest{}, ErrResponseUncertain
		}
		pollDuration := credentialTestPollInterval
		if !deadline.IsZero() {
			remaining := deadline.Sub(now)
			if remaining <= 0 {
				return CredentialTest{}, ErrResponseUncertain
			}
			if remaining < pollDuration {
				pollDuration = remaining
			}
		}
		timer := time.NewTimer(pollDuration)
		select {
		case <-ctx.Done():
			stopCredentialReplayTimer(timer)
			return CredentialTest{}, ErrResponseUncertain
		case <-timer.C:
		}
	}
}

func stopCredentialReplayTimer(timer *time.Timer) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}

func (s *Service) runCredentialTestProvider(ctx context.Context, repository CredentialIdentityIdempotencyRepository, claim CredentialTestClaim) (CredentialTest, error) {
	identity, providerErr := s.sts.GetCallerIdentity(ctx, claim.Credential.handle())
	if providerErr != nil {
		if ctx.Err() != nil {
			if markErr := s.finalizeCredentialTest(func(finalizeCtx context.Context) error {
				return repository.MarkCredentialTestUncertain(finalizeCtx, claim)
			}); markErr != nil {
				return CredentialTest{}, ErrResponseUncertain
			}
			return CredentialTest{}, ErrResponseUncertain
		}
		if markErr := s.finalizeCredentialTest(func(finalizeCtx context.Context) error {
			return repository.MarkCredentialTestFailed(finalizeCtx, claim)
		}); markErr != nil {
			return CredentialTest{}, ErrResponseUncertain
		}
		return CredentialTest{}, ErrProvider
	}
	testedAt := s.now().UTC()
	if testedAt.IsZero() {
		if markErr := s.finalizeCredentialTest(func(finalizeCtx context.Context) error {
			return repository.MarkCredentialTestUncertain(finalizeCtx, claim)
		}); markErr != nil {
			return CredentialTest{}, ErrResponseUncertain
		}
		return CredentialTest{}, ErrInvalid
	}
	var test CredentialTest
	completeErr := s.finalizeCredentialTest(func(finalizeCtx context.Context) error {
		var err error
		test, err = repository.CompleteCredentialTest(finalizeCtx, claim, identity, testedAt)
		return err
	})
	if completeErr != nil {
		// The provider has already run.  Do not let a transaction/connection
		// failure turn into a retryable second provider call.
		_ = s.finalizeCredentialTest(func(finalizeCtx context.Context) error {
			return repository.MarkCredentialTestUncertain(finalizeCtx, claim)
		})
		return CredentialTest{}, ErrResponseUncertain
	}
	return test, nil
}

func (s *Service) finalizeCredentialTest(fn func(context.Context) error) error {
	timeout := credentialTestFinalizeTimeout
	if s != nil && s.credentialTestFinalizeTimeout > 0 {
		timeout = s.credentialTestFinalizeTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return fn(ctx)
}

func (s *Service) CreatePlan(ctx context.Context, in PlanInput) (PlanView, error) {
	if s == nil || s.repo == nil {
		return PlanView{}, ErrInvalid
	}
	if in.IdempotencyKey == "" {
		in.IdempotencyKey = newUUID()
	}
	if !validUUID(in.IdempotencyKey) {
		return PlanView{}, ErrInvalid
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return PlanView{}, err
	}
	repository, err := scopedRepository(s.repo)
	if err != nil {
		return PlanView{}, err
	}
	dig := canonicalDigest(struct {
		Scope coreteam.Scope
		Input PlanInput
	}{scope, in})
	if !validUUID(in.CredentialID) {
		return PlanView{}, ErrInvalid
	}
	cred, e := repository.GetCredentialScoped(ctx, scope, in.CredentialID)
	if e != nil {
		return PlanView{}, e
	}
	norm, digest, e := normalizeTemplate(in.Template)
	if e != nil {
		return PlanView{}, e
	}
	id := in.ID
	if id == "" {
		id = newUUID()
	}
	p := Plan{ID: id, OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration, CredentialID: in.CredentialID, Region: in.Region, StackName: in.StackName, Operation: in.Operation, Template: norm, TemplateSHA256: digest, Parameters: cloneMap(in.Parameters), Tags: cloneMap(in.Tags), Capabilities: append([]string(nil), in.Capabilities...), Revision: 1, CreatedAt: s.now().UTC()}
	if p.Region == "" {
		p.Region = cred.Region
	}
	if err := p.Validate(); err != nil {
		return PlanView{}, err
	}
	if p.Region != cred.Region {
		return PlanView{}, ErrConflict
	}
	v, e := repository.CreatePlanScoped(ctx, scope, p, in.IdempotencyKey, dig)
	if e != nil {
		return PlanView{}, e
	}
	view := v.View()
	return view, nil
}
func (s *Service) GetPlan(ctx context.Context, id string) (PlanView, error) {
	if s == nil || s.repo == nil || !validUUID(id) {
		return PlanView{}, ErrInvalid
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return PlanView{}, err
	}
	repository, err := scopedRepository(s.repo)
	if err != nil {
		return PlanView{}, err
	}
	p, e := repository.GetPlanScoped(ctx, scope, id)
	if e != nil {
		return PlanView{}, e
	}
	return p.View(), nil
}
func (s *Service) ListPlans(ctx context.Context, size int, token string) (PlanPage, error) {
	if s == nil || s.repo == nil {
		return PlanPage{}, ErrInvalid
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return PlanPage{}, err
	}
	repository, err := scopedRepository(s.repo)
	if err != nil {
		return PlanPage{}, err
	}
	return repository.ListPlansScoped(ctx, scope, size, token)
}
func (s *Service) Quote(ctx context.Context, id string) (Quote, error) {
	if s == nil || s.repo == nil || !validUUID(id) {
		return Quote{}, ErrInvalid
	}
	scope, err := credentialMutationScope(ctx)
	if err != nil {
		return Quote{}, err
	}
	repository, err := scopedRepository(s.repo)
	if err != nil {
		return Quote{}, err
	}
	p, e := repository.GetPlanScoped(ctx, scope, id)
	if e != nil {
		return Quote{}, e
	}
	return quoteFor(p), nil
}
