package coreconfirmation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testBinding() Binding {
	return Binding{OperationDomain: "mcp", TargetID: "server-1", TargetRevision: 3, SourceVersion: "1.2.3", ContentDigest: Digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), ParameterDigest: Digest("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"), NetworkDigest: Digest("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"), SecretGrantDigest: Digest("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"), NetworkGrants: []string{" z.example ", "a.example", "a.example"}, SecretGrants: []SecretGrant{{ReferenceID: "33333333-3333-4333-8333-333333333333", Purpose: SecretPurposeMCPCredential, BindingDigest: Digest("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")}}}
}

func testRequest(now time.Time) RequestCommand {
	return RequestCommand{IdempotencyKey: "11111111-1111-4111-8111-111111111111", RequestDigest: Digest("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"), Binding: testBinding(), TaskID: "22222222-2222-4222-8222-222222222222", ExpiresAt: now.Add(time.Hour), At: now}
}

func TestMemoryTransitionsReplayAndBinding(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	r := NewMemoryRepository(func() time.Time { return now })
	s, err := NewService(r, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Request(context.Background(), testRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.Request(context.Background(), testRequest(now))
	if err != nil || replay.ConfirmationID != c.ConfirmationID || replay.State != StatePending {
		t.Fatalf("request replay: %#v %v", replay, err)
	}
	changed := testRequest(now)
	changed.Binding.TargetRevision++
	changed.RequestDigest = testRequest(now).RequestDigest
	if _, err := s.Request(context.Background(), changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("changed replay: %v", err)
	}
	if _, err := s.Request(context.Background(), RequestCommand{IdempotencyKey: "33333333-3333-4333-8333-333333333333", RequestDigest: changed.RequestDigest, Binding: testBinding(), TaskID: "44444444-4444-4444-8444-444444444444", ExpiresAt: now.Add(time.Hour), At: now}); !errors.Is(err, ErrConflict) {
		t.Fatalf("live uniqueness: %v", err)
	}
	confirm := ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: "55555555-5555-4555-8555-555555555555", RequestDigest: Digest("9999999999999999999999999999999999999999999999999999999999999999"), ExpectedRevision: 1, Binding: testBinding(), At: now}
	confirmed, err := s.Confirm(context.Background(), confirm)
	if err != nil || confirmed.State != StateConfirmed || confirmed.Revision != 2 {
		t.Fatalf("confirm: %#v %v", confirmed, err)
	}
	replayConfirm, err := s.Confirm(context.Background(), confirm)
	if err != nil || replayConfirm.State != StateConfirmed {
		t.Fatalf("confirm replay: %#v %v", replayConfirm, err)
	}
	if _, err := s.Confirm(context.Background(), confirm); err != nil {
		t.Fatalf("same replay must win before mutable read: %v", err)
	}
	if err := r.SetTaskFence(TaskFence{TaskID: c.TaskID, State: "running", Attempt: 1, LeaseEpoch: 1, Revision: 7}); err != nil {
		t.Fatal(err)
	}
	consume, err := s.Consume(context.Background(), ConsumeCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.New().String(), TaskID: c.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: 2, ExpectedTaskRevision: 7, Binding: testBinding(), At: now})
	if err != nil || consume.State != StateConsumed {
		t.Fatalf("consume: %#v %v", consume, err)
	}
	if _, err := s.Consume(context.Background(), ConsumeCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.New().String(), TaskID: c.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: 3, ExpectedTaskRevision: 7, Binding: testBinding(), At: now}); !errors.Is(err, ErrTaskFenceConflict) {
		t.Fatalf("double consume: %v", err)
	}
	if _, err := s.Request(context.Background(), func() RequestCommand {
		v := testRequest(now)
		v.IdempotencyKey = uuid.New().String()
		v.TaskID = uuid.New().String()
		return v
	}()); !errors.Is(err, ErrConflict) {
		t.Fatalf("active reservation should block request: %v", err)
	}
	if err := r.SetTaskFence(TaskFence{TaskID: c.TaskID, State: "succeeded", Attempt: 1, LeaseEpoch: 2, Revision: 8}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReleaseReservation(context.Background(), ReleaseReservationCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.New().String(), TaskID: c.TaskID, AcquiredAttempt: 9, AcquiredLeaseEpoch: 9, TerminalAttempt: 1, TerminalLeaseEpoch: 2, ExpectedTaskRevision: 8}); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong acquisition accepted: %v", err)
	}
	if _, err := s.ReleaseReservation(context.Background(), ReleaseReservationCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.New().String(), TaskID: c.TaskID, AcquiredAttempt: 1, AcquiredLeaseEpoch: 1, TerminalAttempt: 1, TerminalLeaseEpoch: 2, ExpectedTaskRevision: 7}); !errors.Is(err, ErrTaskFenceConflict) {
		t.Fatalf("stale terminal revision accepted: %v", err)
	}
	released, err := s.ReleaseReservation(context.Background(), ReleaseReservationCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.New().String(), TaskID: c.TaskID, AcquiredAttempt: 1, AcquiredLeaseEpoch: 1, TerminalAttempt: 1, TerminalLeaseEpoch: 2, ExpectedTaskRevision: 8})
	if err != nil {
		t.Fatalf("release reservation: %#v %v", released, err)
	}
	afterRelease := testRequest(now)
	afterRelease.IdempotencyKey = uuid.New().String()
	afterRelease.TaskID = uuid.New().String()
	if _, err := s.Request(context.Background(), afterRelease); err != nil {
		t.Fatalf("released reservation should allow next request: %v", err)
	}
	unchanged, _ := s.Get(context.Background(), c.ConfirmationID)
	if unchanged.State != StateConsumed || unchanged.Revision != 3 {
		t.Fatalf("consumed confirmation mutated: %#v", unchanged)
	}
}

func TestConfirmStaleAndExpiryReasons(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	r := NewMemoryRepository(func() time.Time { return now })
	s, _ := NewService(r, func() time.Time { return now })
	c, err := s.Request(context.Background(), testRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	stale := testBinding()
	stale.TargetRevision++
	if err := r.SetTargetBinding(c.ConfirmationID, stale); err != nil {
		t.Fatal(err)
	}
	_, err = s.Confirm(context.Background(), ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: "66666666-6666-4666-8666-666666666666", RequestDigest: Digest("9999999999999999999999999999999999999999999999999999999999999999"), ExpectedRevision: 1, Binding: stale, At: now})
	if !errors.Is(err, ErrStale) {
		t.Fatalf("stale: %v", err)
	}
	got, _ := s.Get(context.Background(), c.ConfirmationID)
	if got.State != StateExpired || got.TerminalReason != "confirmation_stale" {
		t.Fatalf("stale state: %#v", got)
	}

	now = now.Add(time.Hour)
	second := testRequest(now)
	second.IdempotencyKey = uuid.New().String()
	second.TaskID = uuid.New().String()
	second.ExpiresAt = now.Add(time.Nanosecond)
	c2, err := s.Request(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	_, err = s.Confirm(context.Background(), ConfirmCommand{ConfirmationID: c2.ConfirmationID, IdempotencyKey: uuid.New().String(), RequestDigest: Digest("9999999999999999999999999999999999999999999999999999999999999999"), ExpectedRevision: 1, Binding: testBinding(), At: now})
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("expiry: %v", err)
	}
}

func TestRejectUsesStableCodeAndKeepsOptionalNote(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	r := NewMemoryRepository(func() time.Time { return now })
	s, _ := NewService(r, func() time.Time { return now })
	c, err := s.Request(context.Background(), testRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := s.Reject(context.Background(), RejectCommand{
		ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.New().String(),
		RequestDigest:    Digest("9999999999999999999999999999999999999999999999999999999999999999"),
		ExpectedRevision: 1, Reason: "declined by user", At: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rejected.State != StateRejected || rejected.TerminalCode != ReasonUserRejected || rejected.TerminalReason != ReasonUserRejected || rejected.TerminalNote != "declined by user" {
		t.Fatalf("unstable rejection: %#v", rejected)
	}
}

func TestReplayPrecedesDriftAndTerminalStatesStayImmutable(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	r := NewMemoryRepository(func() time.Time { return now })
	s, _ := NewService(r, func() time.Time { return now })
	c, err := s.Request(context.Background(), testRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	confirm := ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.New().String(), ExpectedRevision: 1, Binding: testBinding(), At: now}
	confirmed, err := s.Confirm(context.Background(), confirm)
	if err != nil {
		t.Fatal(err)
	}
	drift := testBinding()
	drift.TargetRevision++
	if err := r.SetTargetBinding(c.ConfirmationID, drift); err != nil {
		t.Fatal(err)
	}
	replayed, err := s.Confirm(context.Background(), confirm)
	if err != nil || replayed.Revision != confirmed.Revision {
		t.Fatalf("drift replay: %#v %v", replayed, err)
	}

	c2req := testRequest(now)
	c2req.IdempotencyKey = uuid.New().String()
	c2req.TaskID = uuid.New().String()
	c2req.Binding.TargetID = "server-2"
	c2, err := s.Request(context.Background(), c2req)
	if err != nil {
		t.Fatal(err)
	}
	rejected, err := s.Reject(context.Background(), RejectCommand{ConfirmationID: c2.ConfirmationID, IdempotencyKey: uuid.New().String(), ExpectedRevision: 1, At: now})
	if err != nil {
		t.Fatal(err)
	}
	drift2 := c2req.Binding
	drift2.TargetRevision++
	if err := r.SetTargetBinding(c2.ConfirmationID, drift2); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Confirm(context.Background(), ConfirmCommand{ConfirmationID: c2.ConfirmationID, IdempotencyKey: uuid.New().String(), ExpectedRevision: 2, Binding: drift2, At: now}); !errors.Is(err, ErrConflict) {
		t.Fatalf("terminal drift should conflict: %v", err)
	}
	current, _ := s.Get(context.Background(), c2.ConfirmationID)
	if current.State != StateRejected || current.Revision != rejected.Revision {
		t.Fatalf("terminal mutated: %#v", current)
	}
}

func TestSecretGrantReferenceMustBeUUIDAndPurposeClosed(t *testing.T) {
	binding := testBinding()
	binding.SecretGrants = []SecretGrant{{ReferenceID: "token-value", Purpose: SecretPurposeMCPCredential, BindingDigest: binding.SecretGrantDigest}}
	if _, err := binding.normalized(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("secret-shaped reference accepted: %v", err)
	}
	binding.SecretGrants = []SecretGrant{{ReferenceID: "33333333-3333-4333-8333-333333333333", Purpose: SecretPurpose("arbitrary"), BindingDigest: binding.SecretGrantDigest}}
	if _, err := binding.normalized(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("open purpose accepted: %v", err)
	}
}

func TestOldConsumerFenceCannotExpireConfirmedOnBindingDrift(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	r := NewMemoryRepository(func() time.Time { return now })
	s, _ := NewService(r, func() time.Time { return now })
	c, err := s.Request(context.Background(), testRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	confirmed, err := s.Confirm(context.Background(), ConfirmCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.New().String(), ExpectedRevision: 1, Binding: testBinding(), At: now})
	if err != nil {
		t.Fatal(err)
	}
	drift := testBinding()
	drift.TargetRevision++
	if err := r.SetTargetBinding(c.ConfirmationID, drift); err != nil {
		t.Fatal(err)
	}
	if err := r.SetTaskFence(TaskFence{TaskID: c.TaskID, State: "running", Attempt: 1, LeaseEpoch: 2, Revision: 4}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Consume(context.Background(), ConsumeCommand{ConfirmationID: c.ConfirmationID, IdempotencyKey: uuid.New().String(), TaskID: c.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: confirmed.Revision, ExpectedTaskRevision: 3, Binding: drift, At: now})
	if !errors.Is(err, ErrTaskFenceConflict) {
		t.Fatalf("old fence result: %v", err)
	}
	current, _ := s.Get(context.Background(), c.ConfirmationID)
	if current.State != StateConfirmed || current.Revision != confirmed.Revision {
		t.Fatalf("confirmed mutated by old fence: %#v", current)
	}
}

func TestMemoryConcurrentRequestsOnlyOneLive(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	r := NewMemoryRepository(func() time.Time { return now })
	s, _ := NewService(r, func() time.Time { return now })
	var wg sync.WaitGroup
	successes := make(chan string, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cmd := testRequest(now)
			cmd.IdempotencyKey = uuid.New().String()
			cmd.TaskID = uuid.New().String()
			if c, err := s.Request(context.Background(), cmd); err == nil {
				successes <- c.ConfirmationID
			}
		}(i)
	}
	wg.Wait()
	close(successes)
	count := 0
	for range successes {
		count++
	}
	if count != 1 {
		t.Fatalf("concurrent live confirmations=%d", count)
	}
}

func TestListCursorBindsFiltersAndCreationTuple(t *testing.T) {
	now := time.Date(2026, 7, 25, 0, 0, 0, 0, time.UTC)
	r := NewMemoryRepository(func() time.Time { return now })
	s, _ := NewService(r, func() time.Time { return now })
	_, err := s.Request(context.Background(), testRequest(now))
	if err != nil {
		t.Fatal(err)
	}
	secondReq := testRequest(now)
	secondReq.IdempotencyKey = uuid.New().String()
	secondReq.TaskID = uuid.New().String()
	secondReq.Binding.TargetID = "server-2"
	_, err = s.Request(context.Background(), secondReq)
	if err != nil {
		t.Fatal(err)
	}
	page, err := s.List(context.Background(), ListQuery{PageSize: 1})
	if err != nil || len(page.Confirmations) != 1 || page.NextPageToken == "" {
		t.Fatalf("first page %#v %v", page, err)
	}
	if _, err := s.List(context.Background(), ListQuery{PageSize: 1, PageToken: page.NextPageToken, Domain: "other"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("cursor filter mismatch: %v", err)
	}
	thirdReq := testRequest(now)
	thirdReq.IdempotencyKey = uuid.New().String()
	thirdReq.TaskID = uuid.New().String()
	thirdReq.Binding.TargetID = "server-3"
	_, err = s.Request(context.Background(), thirdReq)
	if err != nil {
		t.Fatal(err)
	}
	next, err := s.List(context.Background(), ListQuery{PageSize: 5, PageToken: page.NextPageToken})
	if err != nil {
		t.Fatal(err)
	}
	pageID := page.Confirmations[0].ConfirmationID
	if len(next.Confirmations) == 0 {
		t.Fatalf("cursor dropped all remaining rows")
	}
	for _, row := range next.Confirmations {
		if row.ConfirmationID == pageID {
			t.Fatalf("cursor repeated page row %s", pageID)
		}
	}
}
