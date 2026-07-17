package pairing

import (
	"context"
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/base64"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRetrieveReplaysSameEncryptedPayloadWithoutRepeatingBegin(t *testing.T) {
	fixture := newServiceFixture(t)
	session, err := fixture.service.Create(context.Background(), fixture.create)
	if err != nil {
		t.Fatal(err)
	}
	command := RetrieveCommand{
		OwnerID: fixture.create.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: session.SessionID,
		DeploymentID: session.DeploymentID, ExpectedRevision: 1, RecipientPublicKey: fixture.recipient,
	}
	first, payload, err := fixture.service.Retrieve(context.Background(), command)
	if err != nil || first.Status != StatusWaitingUser || payload.PayloadDigest != digest("d") {
		t.Fatalf("first retrieval = %#v %#v err=%v", first, payload, err)
	}
	second, replay, err := fixture.service.Retrieve(context.Background(), command)
	if err != nil || second.Revision != first.Revision || replay.Envelope != payload.Envelope || fixture.executor.BeginCalls() != 1 {
		t.Fatalf("replay = %#v %#v calls=%d err=%v", second, replay, fixture.executor.BeginCalls(), err)
	}
	other, _ := ecdh.X25519().GenerateKey(cryptorand.Reader)
	command.RecipientPublicKey = encodeRecipient(other.PublicKey().Bytes())
	if _, _, err := fixture.service.Retrieve(context.Background(), command); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("different recipient error = %v", err)
	}
}

func TestResumeRecoversSucceededResultWithoutRepeatingRootCommand(t *testing.T) {
	fixture := newServiceFixture(t)
	session, err := fixture.service.Create(context.Background(), fixture.create)
	if err != nil {
		t.Fatal(err)
	}
	retrieved, _, err := fixture.service.Retrieve(context.Background(), RetrieveCommand{
		OwnerID: session.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: session.SessionID,
		DeploymentID: session.DeploymentID, ExpectedRevision: 1, RecipientPublicKey: fixture.recipient,
	})
	if err != nil {
		t.Fatal(err)
	}
	command := ResumeCommand{OwnerID: session.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: session.SessionID,
		DeploymentID: session.DeploymentID, ExpectedRevision: retrieved.Revision}
	completed, err := fixture.service.Resume(context.Background(), command)
	if err != nil || completed.Status != StatusSucceeded {
		t.Fatalf("resume = %#v err=%v", completed, err)
	}
	replayed, err := fixture.service.Resume(context.Background(), command)
	if err != nil || replayed.Status != StatusSucceeded || fixture.executor.ResumeCalls() != 1 {
		t.Fatalf("resume replay = %#v calls=%d err=%v", replayed, fixture.executor.ResumeCalls(), err)
	}
}

func TestResumeRetainsJournaledStateAfterAmbiguousDispatchFailure(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		failure error
		matches func(error) bool
	}{
		{name: "caller canceled", failure: context.Canceled, matches: func(err error) bool { return errors.Is(err, context.Canceled) }},
		{name: "caller deadline", failure: context.DeadlineExceeded, matches: func(err error) bool { return errors.Is(err, context.DeadlineExceeded) }},
		{name: "grpc unavailable", failure: status.Error(codes.Unavailable, "worker response lost"), matches: func(err error) bool { return status.Code(err) == codes.Unavailable }},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newServiceFixture(t)
			session, err := fixture.service.Create(context.Background(), fixture.create)
			if err != nil {
				t.Fatal(err)
			}
			retrieved, _, err := fixture.service.Retrieve(context.Background(), RetrieveCommand{
				OwnerID: session.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: session.SessionID,
				DeploymentID: session.DeploymentID, ExpectedRevision: session.Revision, RecipientPublicKey: fixture.recipient,
			})
			if err != nil {
				t.Fatal(err)
			}
			var commands []SessionV1
			fixture.executor.resume = func(_ context.Context, value SessionV1) error {
				commands = append(commands, value.Clone())
				if len(commands) == 1 {
					return testCase.failure
				}
				return nil
			}
			command := ResumeCommand{OwnerID: retrieved.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: retrieved.SessionID,
				DeploymentID: retrieved.DeploymentID, ExpectedRevision: retrieved.Revision}
			if _, err := fixture.service.Resume(context.Background(), command); !testCase.matches(err) {
				t.Fatalf("first ambiguous resume error = %v", err)
			}
			resuming, err := fixture.repository.Get(context.Background(), retrieved.OwnerID, retrieved.SessionID)
			if err != nil || resuming.Status != StatusResuming || resuming.Revision != retrieved.Revision+1 {
				t.Fatalf("ambiguous dispatch terminalized session: %#v err=%v", resuming, err)
			}
			completed, err := fixture.service.Resume(context.Background(), command)
			if err != nil || completed.Status != StatusSucceeded || fixture.executor.ResumeCalls() != 2 {
				t.Fatalf("journal replay = %#v calls=%d err=%v", completed, fixture.executor.ResumeCalls(), err)
			}
			if len(commands) != 2 || !sameResumeDispatch(commands[0], commands[1]) {
				t.Fatalf("retry changed root command: %#v", commands)
			}
		})
	}
}

func sameResumeDispatch(left, right SessionV1) bool {
	return left.SessionID == right.SessionID && left.DeploymentID == right.DeploymentID &&
		left.DeploymentRevision == right.DeploymentRevision && left.OwnerID == right.OwnerID &&
		left.TaskID == right.TaskID && left.StepID == right.StepID && left.RecipeID == right.RecipeID &&
		left.RecipeDigest == right.RecipeDigest && left.RecipeRevision == right.RecipeRevision &&
		left.ExecutionManifestDigest == right.ExecutionManifestDigest && left.ResumeCommand == right.ResumeCommand &&
		left.PayloadScopeRevision == right.PayloadScopeRevision && left.ExpiresAt.Equal(right.ExpiresAt) &&
		left.Status == StatusResuming && right.Status == StatusResuming && left.Revision == right.Revision
}

func TestRetrieveReservesFirstRecipientBeforeWorkerDispatch(t *testing.T) {
	fixture := newServiceFixture(t)
	session, err := fixture.service.Create(context.Background(), fixture.create)
	if err != nil {
		t.Fatal(err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	fixture.executor.begin = func(ctx context.Context, _ SessionV1, _ string, _ int64) (PayloadResult, error) {
		close(started)
		select {
		case <-release:
			return fixture.executor.result, nil
		case <-ctx.Done():
			return PayloadResult{}, ctx.Err()
		}
	}
	type outcome struct {
		value SessionV1
		err   error
	}
	firstDone := make(chan outcome, 1)
	go func() {
		value, _, retrieveErr := fixture.service.Retrieve(context.Background(), RetrieveCommand{
			OwnerID: session.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: session.SessionID,
			DeploymentID: session.DeploymentID, ExpectedRevision: session.Revision, RecipientPublicKey: fixture.recipient,
		})
		firstDone <- outcome{value: value, err: retrieveErr}
	}()
	<-started
	other, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.service.Retrieve(context.Background(), RetrieveCommand{
		OwnerID: session.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: session.SessionID,
		DeploymentID: session.DeploymentID, ExpectedRevision: session.Revision, RecipientPublicKey: encodeRecipient(other.PublicKey().Bytes()),
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("second recipient error = %v, want reservation conflict", err)
	}
	if calls := fixture.executor.BeginCalls(); calls != 1 {
		t.Fatalf("begin dispatches = %d, want exactly 1", calls)
	}
	close(release)
	first := <-firstDone
	if first.err != nil || first.value.Status != StatusWaitingUser {
		t.Fatalf("first retrieval = %#v err=%v", first.value, first.err)
	}
}

func TestRetrieveSameRecipientReusesDurableReservationForRecovery(t *testing.T) {
	fixture := newServiceFixture(t)
	session, err := fixture.service.Create(context.Background(), fixture.create)
	if err != nil {
		t.Fatal(err)
	}
	var attempts int
	fixture.executor.begin = func(_ context.Context, _ SessionV1, _ string, _ int64) (PayloadResult, error) {
		attempts++
		if attempts == 1 {
			return PayloadResult{}, errors.New("lost worker response")
		}
		return fixture.executor.result, nil
	}
	first := RetrieveCommand{OwnerID: session.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: session.SessionID,
		DeploymentID: session.DeploymentID, ExpectedRevision: session.Revision, RecipientPublicKey: fixture.recipient}
	if _, _, err := fixture.service.Retrieve(context.Background(), first); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("first interrupted retrieval error = %v", err)
	}
	fixture.repository.mu.Lock()
	if fixture.repository.reservation == nil || len(fixture.repository.reservationHistory) != 1 {
		fixture.repository.mu.Unlock()
		t.Fatalf("reservation was not retained for recovery: %#v", fixture.repository.reservationHistory)
	}
	reserved := *fixture.repository.reservation
	fixture.repository.mu.Unlock()
	second := first
	second.IdempotencyKey = uuid.NewString()
	completed, _, err := fixture.service.Retrieve(context.Background(), second)
	if err != nil || completed.Status != StatusWaitingUser || fixture.executor.BeginCalls() != 2 {
		t.Fatalf("same-recipient recovery = %#v calls=%d err=%v", completed, fixture.executor.BeginCalls(), err)
	}
	operationID, err := PayloadOperationID(session.SessionID, session.Revision, digestText(fixture.recipient))
	if err != nil || reserved.OperationID != operationID {
		t.Fatalf("reservation operation = %#v expected=%q err=%v", reserved, operationID, err)
	}
}

func TestRetrieveRejectsDelayedWorkerPayloadAfterExpiryAndScrubsSession(t *testing.T) {
	fixture := newServiceFixture(t)
	session, err := fixture.service.Create(context.Background(), fixture.create)
	if err != nil {
		t.Fatal(err)
	}
	fixture.executor.begin = func(_ context.Context, value SessionV1, _ string, _ int64) (PayloadResult, error) {
		fixture.clock.Set(value.ExpiresAt)
		return fixture.executor.result, nil
	}
	if _, _, err := fixture.service.Retrieve(context.Background(), RetrieveCommand{
		OwnerID: session.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: session.SessionID,
		DeploymentID: session.DeploymentID, ExpectedRevision: session.Revision, RecipientPublicKey: fixture.recipient,
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("delayed result error = %v, want expiry fence", err)
	}
	timedOut, err := fixture.service.Get(context.Background(), session.OwnerID, session.SessionID)
	if err != nil || timedOut.Status != StatusTimedOut || timedOut.Envelope != nil || timedOut.PayloadScopeRevision != 0 {
		t.Fatalf("timed out session = %#v err=%v", timedOut, err)
	}
	fixture.repository.mu.Lock()
	reservation := fixture.repository.reservation
	fixture.repository.mu.Unlock()
	if reservation != nil {
		t.Fatalf("expiry retained payload reservation: %#v", reservation)
	}
}

func TestResumeFailsClosedAfterExpiryAndDoesNotDispatch(t *testing.T) {
	fixture := newServiceFixture(t)
	session, err := fixture.service.Create(context.Background(), fixture.create)
	if err != nil {
		t.Fatal(err)
	}
	retrieved, _, err := fixture.service.Retrieve(context.Background(), RetrieveCommand{
		OwnerID: session.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: session.SessionID,
		DeploymentID: session.DeploymentID, ExpectedRevision: session.Revision, RecipientPublicKey: fixture.recipient,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.clock.Set(retrieved.ExpiresAt)
	if _, err := fixture.service.Resume(context.Background(), ResumeCommand{
		OwnerID: retrieved.OwnerID, IdempotencyKey: uuid.NewString(), SessionID: retrieved.SessionID,
		DeploymentID: retrieved.DeploymentID, ExpectedRevision: retrieved.Revision,
	}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("expired resume error = %v, want closed fence", err)
	}
	if calls := fixture.executor.ResumeCalls(); calls != 0 {
		t.Fatalf("expired resume dispatched %d root commands", calls)
	}
	timedOut, err := fixture.service.Get(context.Background(), retrieved.OwnerID, retrieved.SessionID)
	if err != nil || timedOut.Status != StatusTimedOut || timedOut.Envelope != nil {
		t.Fatalf("expired resume did not project scrubbed timeout: %#v err=%v", timedOut, err)
	}
}

type serviceFixture struct {
	service    *Service
	repository *memoryPairingRepository
	executor   *pairingExecutorFake
	clock      *pairingTestClock
	create     CreateCommand
	recipient  string
}

func encodeRecipient(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

func newServiceFixture(t *testing.T) serviceFixture {
	t.Helper()
	clock := &pairingTestClock{now: time.Now().UTC().Truncate(time.Microsecond)}
	repository := &memoryPairingRepository{}
	executor := &pairingExecutorFake{result: PayloadResult{
		Envelope: secretbootstrap.RecipientEnvelopeV1{SchemaVersion: secretbootstrap.RecipientEnvelopeSchemaV1,
			ServerPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Nonce: "BBBBBBBBBBBBBBBB", Ciphertext: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"},
		AssociatedDataCBOR: []byte{0xa1, 0x61, 0x61, 0x61, 0x62}, PayloadDigest: digest("d"),
	}}
	service, err := NewService(repository, executor, clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return serviceFixture{service: service, repository: repository, executor: executor, clock: clock,
		recipient: encodeRecipient(privateKey.PublicKey().Bytes()),
		create: CreateCommand{OwnerID: "owner-a", IdempotencyKey: uuid.NewString(), SessionID: uuid.NewString(),
			DeploymentID: uuid.NewString(), DeploymentRevision: 7, PlanID: uuid.NewString(), ConnectionID: uuid.NewString(), TaskID: uuid.NewString(), StepID: uuid.NewString(),
			RecipeID: "recipe-a", RecipeDigest: digest("a"), RecipeRevision: 2, ExecutionManifestDigest: digest("b"),
			BeginCommand: "pairing-begin", ResumeCommand: "pairing-resume", Timeout: time.Hour},
	}
}

type pairingExecutorFake struct {
	mu          sync.Mutex
	result      PayloadResult
	beginCalls  int
	resumeCalls int
	begin       func(context.Context, SessionV1, string, int64) (PayloadResult, error)
	resume      func(context.Context, SessionV1) error
}

func (executor *pairingExecutorFake) Begin(ctx context.Context, session SessionV1, recipient string, scope int64) (PayloadResult, error) {
	executor.mu.Lock()
	executor.beginCalls++
	begin, result := executor.begin, executor.result
	executor.mu.Unlock()
	if begin != nil {
		return begin(ctx, session, recipient, scope)
	}
	return result, nil
}
func (executor *pairingExecutorFake) Resume(ctx context.Context, session SessionV1) error {
	executor.mu.Lock()
	executor.resumeCalls++
	resume := executor.resume
	executor.mu.Unlock()
	if resume != nil {
		return resume(ctx, session)
	}
	return nil
}

func (executor *pairingExecutorFake) BeginCalls() int {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.beginCalls
}

func (executor *pairingExecutorFake) ResumeCalls() int {
	executor.mu.Lock()
	defer executor.mu.Unlock()
	return executor.resumeCalls
}

type pairingTestClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *pairingTestClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *pairingTestClock) Set(value time.Time) {
	clock.mu.Lock()
	clock.now = value
	clock.mu.Unlock()
}

type memoryPairingRepository struct {
	mu                 sync.Mutex
	session            SessionV1
	reservation        *PayloadReservationV1
	reservationHistory []PayloadReservationV1
}

func (repository *memoryPairingRepository) Create(_ context.Context, _ Mutation, expected int64, value SessionV1) (SessionV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if expected != 0 || repository.session.SessionID != "" {
		return SessionV1{}, ErrRevisionConflict
	}
	repository.session = value.Clone()
	return value.Clone(), nil
}
func (repository *memoryPairingRepository) Get(_ context.Context, ownerID, sessionID string) (SessionV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.session.OwnerID != ownerID || repository.session.SessionID != sessionID {
		return SessionV1{}, ErrNotFound
	}
	return repository.session.Clone(), nil
}
func (repository *memoryPairingRepository) ReservePayload(_ context.Context, mutation Mutation, sessionID string, expected int64,
	recipientDigest, operationID string, at time.Time,
) (SessionV1, PayloadReservationV1, bool, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.session.SessionID != sessionID || repository.session.OwnerID != mutation.OwnerID ||
		repository.session.Revision != expected || repository.session.Status != StatusWaitingPayload || !at.Before(repository.session.ExpiresAt) {
		return SessionV1{}, PayloadReservationV1{}, false, ErrRevisionConflict
	}
	if repository.reservation != nil {
		if repository.reservation.PayloadScopeRevision != expected || repository.reservation.RecipientKeyDigest != recipientDigest ||
			repository.reservation.OperationID != operationID {
			return SessionV1{}, PayloadReservationV1{}, false, ErrRevisionConflict
		}
		return repository.session.Clone(), *repository.reservation, false, nil
	}
	value := PayloadReservationV1{SessionID: sessionID, OwnerID: mutation.OwnerID, PayloadScopeRevision: expected,
		RecipientKeyDigest: recipientDigest, OperationID: operationID, CreatedAt: at}
	if value.Validate() != nil {
		return SessionV1{}, PayloadReservationV1{}, false, ErrInvalid
	}
	repository.reservation = &value
	repository.reservationHistory = append(repository.reservationHistory, value)
	return repository.session.Clone(), value, true, nil
}
func (repository *memoryPairingRepository) RecordEnvelope(_ context.Context, _ Mutation, sessionID string, expected int64,
	recipientDigest, operationID string, envelope secretbootstrap.RecipientEnvelopeV1, aad []byte, payloadDigest string, at time.Time) (SessionV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.session.SessionID != sessionID || repository.session.Revision != expected || !CanRecordEnvelope(repository.session.Status) {
		return SessionV1{}, ErrRevisionConflict
	}
	if repository.reservation == nil || repository.reservation.PayloadScopeRevision != expected ||
		repository.reservation.RecipientKeyDigest != recipientDigest || repository.reservation.OperationID != operationID ||
		!at.Before(repository.session.ExpiresAt) {
		return SessionV1{}, ErrRevisionConflict
	}
	repository.session.Status = StatusWaitingUser
	repository.session.RecipientKeyDigest, repository.session.Envelope = recipientDigest, &envelope
	repository.session.AssociatedDataCBOR, repository.session.PayloadDigest = append([]byte(nil), aad...), payloadDigest
	repository.session.PayloadScopeRevision, repository.session.Revision, repository.session.UpdatedAt = expected, expected+1, at
	repository.reservation = nil
	return repository.session.Clone(), nil
}
func (repository *memoryPairingRepository) Expire(_ context.Context, ownerID, sessionID string, at time.Time) (SessionV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.session.OwnerID != ownerID || repository.session.SessionID != sessionID || at.Before(repository.session.ExpiresAt) {
		return SessionV1{}, ErrRevisionConflict
	}
	if !IsTerminal(repository.session.Status) {
		completed := at
		repository.session.Status, repository.session.RecipientKeyDigest, repository.session.Envelope = StatusTimedOut, "", nil
		repository.session.AssociatedDataCBOR, repository.session.PayloadDigest, repository.session.PayloadScopeRevision = nil, "", 0
		repository.session.FailureCode, repository.session.CompletedAt = "pairing_timed_out", &completed
		repository.session.Revision, repository.session.UpdatedAt = repository.session.Revision+1, at
	}
	repository.reservation = nil
	return repository.session.Clone(), nil
}
func (repository *memoryPairingRepository) BeginResume(_ context.Context, _ Mutation, sessionID string, expected int64, at time.Time) (SessionV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.session.SessionID != sessionID || repository.session.Revision != expected || !CanBeginResume(repository.session.Status) || !at.Before(repository.session.ExpiresAt) {
		return SessionV1{}, ErrRevisionConflict
	}
	repository.session.Status, repository.session.Revision, repository.session.UpdatedAt = StatusResuming, expected+1, at
	repository.session.ResumeStartedAt = &at
	return repository.session.Clone(), nil
}
func (repository *memoryPairingRepository) CompleteResume(_ context.Context, _ Mutation, sessionID string, expected int64,
	status Status, failure string, at time.Time) (SessionV1, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.session.SessionID != sessionID || repository.session.Revision != expected || repository.session.Status != StatusResuming ||
		(status == StatusTimedOut && at.Before(repository.session.ExpiresAt)) || (status != StatusTimedOut && !at.Before(repository.session.ExpiresAt)) {
		return SessionV1{}, ErrRevisionConflict
	}
	repository.session.Status, repository.session.FailureCode = status, failure
	if status == StatusTimedOut {
		repository.session.RecipientKeyDigest, repository.session.Envelope, repository.session.AssociatedDataCBOR = "", nil, nil
		repository.session.PayloadDigest, repository.session.PayloadScopeRevision = "", 0
	}
	repository.session.Revision, repository.session.UpdatedAt, repository.session.CompletedAt = expected+1, at, &at
	return repository.session.Clone(), nil
}
