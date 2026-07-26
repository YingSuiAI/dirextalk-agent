package coretask

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGenericTaskPayloadBranchesAndRoundTrip(t *testing.T) {
	s := TaskSpec{Kind: TaskKindExtension, Goal: "run", IdempotencyKey: testID, Payload: TaskPayload{Extension: &ExtensionTaskPayload{Operation: ExtensionOperationExecuteTool, InstallationID: testID2, ExpectedRevision: 2, Version: "1.0.0", Digest: strings.Repeat("a", 64), ConfirmationID: uuid.NewString(), ToolName: "echo", CanonicalInputJSON: json.RawMessage(`{"z":1,"a":2}`)}}}
	n, err := s.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if string(n.Payload.Extension.CanonicalInputJSON) != `{"a":2,"z":1}` {
		t.Fatalf("input was not canonical: %s", n.Payload.Extension.CanonicalInputJSON)
	}
	b, err := json.Marshal(n)
	if err != nil {
		t.Fatal(err)
	}
	var round TaskSpec
	if err := json.Unmarshal(b, &round); err != nil {
		t.Fatal(err)
	}
	if _, err := round.Normalize(); err != nil {
		t.Fatal(err)
	}
	changed := n
	changed.Payload.Extension = &ExtensionTaskPayload{Operation: n.Payload.Extension.Operation, InstallationID: n.Payload.Extension.InstallationID, ExpectedRevision: n.Payload.Extension.ExpectedRevision, Version: n.Payload.Extension.Version, Digest: n.Payload.Extension.Digest, ConfirmationID: n.Payload.Extension.ConfirmationID, ToolName: "other", CanonicalInputJSON: append([]byte(nil), n.Payload.Extension.CanonicalInputJSON...)}
	d1, _ := n.MutationDigest()
	d2, _ := changed.MutationDigest()
	if d1 == d2 {
		t.Fatal("payload change must alter digest")
	}
	bad := n
	bad.Payload.AWSChange = &AWSChangeTaskPayload{ChangeID: testID}
	if _, err := bad.Normalize(); !errors.Is(err, ErrInvalid) {
		t.Fatal("multiple payload branches accepted")
	}
}

var testID = "00000000-0000-4000-8000-000000000001"
var testID2 = "00000000-0000-4000-8000-000000000002"

func baseSpec() TaskSpec {
	return TaskSpec{Goal: " do work ", ModelProfileID: testID2, IdempotencyKey: testID, AttachmentRefs: []string{"b", "a", "a"}}
}
func baseTemplate() TaskTemplate {
	s := baseSpec()
	return TaskTemplate{Goal: s.Goal, ConversationID: s.ConversationID, AttachmentRefs: s.AttachmentRefs, ModelProfileID: s.ModelProfileID, Extensions: s.Extensions, KnowledgeRefs: s.KnowledgeRefs, TimeoutSeconds: s.TimeoutSeconds}
}
func baseTask() Task {
	now := time.Now().UTC()
	s, _ := baseSpec().Normalize()
	return Task{ID: testID, Spec: s, Status: StatusQueued, Revision: 1, CreatedAt: now, UpdatedAt: now, AvailableAt: now}
}

func TestSpecNormalizeAndDigest(t *testing.T) {
	if ValidUUID("00000000-0000-0000-0000-000000000000") {
		t.Fatal("nil UUID must be invalid")
	}
	n, err := baseSpec().Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if n.Goal != " do work " || len(n.AttachmentRefs) != 2 || n.AttachmentRefs[0] != "a" {
		t.Fatalf("normalized refs=%v", n.AttachmentRefs)
	}
	d1, err := baseSpec().MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	d2, err := (TaskSpec{Goal: " do work ", ModelProfileID: testID2, IdempotencyKey: testID, AttachmentRefs: []string{"a", "b"}}).MutationDigest()
	if err != nil {
		t.Fatal(err)
	}
	if d1 != d2 {
		t.Fatal("digest must be normalization invariant")
	}
	ext := ExtensionSelection{Kind: ExtensionMCP, ID: testID2, Version: "1.2.3", Digest: strings.Repeat("a", 64), AllowedTools: []string{"z", "a", "a"}}
	baseSpecWithExt := baseSpec()
	baseSpecWithExt.Extensions = []ExtensionSelection{ext}
	next, err := baseSpecWithExt.Normalize()
	if err != nil || len(next.Extensions) != 1 || next.Extensions[0].AllowedTools[0] != "a" {
		t.Fatalf("extension normalization err=%v value=%+v", err, next.Extensions)
	}
	reordered := baseSpecWithExt
	reordered.Extensions[0].AllowedTools = []string{"a", "z"}
	da, _ := baseSpecWithExt.MutationDigest()
	db, _ := reordered.MutationDigest()
	if da != db {
		t.Fatal("extension order must not affect digest")
	}
	bad := ext
	bad.Kind = "other"
	if _, err := (TaskSpec{Goal: "x", ModelProfileID: testID2, IdempotencyKey: testID, Extensions: []ExtensionSelection{bad}}).Normalize(); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid extension kind accepted")
	}
	for _, mutate := range []func(*ExtensionSelection){func(e *ExtensionSelection) { e.Digest = strings.Repeat("A", 64) }, func(e *ExtensionSelection) { e.Version = "" }, func(e *ExtensionSelection) { e.AllowedTools = []string{""} }} {
		bad = ext
		mutate(&bad)
		if _, err := (TaskSpec{Goal: "x", ModelProfileID: testID2, IdempotencyKey: testID, Extensions: []ExtensionSelection{bad}}).Normalize(); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid extension field accepted")
		}
	}
	secretA, _ := CanonicalMutationDigest(map[string]any{"goal": "x", "api_key": "one"})
	secretB, _ := CanonicalMutationDigest(map[string]any{"goal": "x", "api_key": "two"})
	if secretA == secretB {
		t.Fatal("changed secrets must conflict")
	}
}

func TestTransitionsAndTerminalImmutability(t *testing.T) {
	task := baseTask()
	now := task.CreatedAt
	lease, err := Claim(&task, ClaimCommand{TaskID: testID, Holder: "worker", ExpectedRevision: 1, LeaseEpoch: 1, LeaseTTL: time.Minute, At: now})
	if err != nil {
		t.Fatal(err)
	}
	f := Fence{TaskID: testID, Attempt: 1, LeaseEpoch: lease.Epoch, ExpectedRevision: task.Revision}
	if err := WaitForUser(&task, WaitUserCommand{Fence: f, Reason: "confirm", At: now}); err != nil {
		t.Fatal(err)
	}
	if task.Lease != nil || task.Status != StatusWaitingUser {
		t.Fatal("waiting_user must release lease")
	}
	if err := Resume(&task, ResumeCommand{TaskID: testID, ExpectedRevision: task.Revision}); err != nil {
		t.Fatal(err)
	}
	if task.Status != StatusQueued {
		t.Fatal(task.Status)
	}
	lease, err = Claim(&task, ClaimCommand{TaskID: testID, Holder: "worker", ExpectedRevision: task.Revision, LeaseEpoch: 2, LeaseTTL: time.Minute, At: now})
	if err != nil {
		t.Fatal(err)
	}
	f = Fence{TaskID: testID, Attempt: 1, LeaseEpoch: lease.Epoch, ExpectedRevision: task.Revision}
	if err := Complete(&task, CompleteCommand{Fence: f, Result: Result{Text: "ok"}, At: now}); err != nil {
		t.Fatal(err)
	}
	if task.Status != StatusSucceeded || task.Lease != nil {
		t.Fatal("completion")
	}
	if err := task.Validate(); err != nil {
		t.Fatalf("complete produced invalid task: %v", err)
	}
	if err := task.Transition(StatusCanceled); !errors.Is(err, ErrTerminal) {
		t.Fatalf("terminal mutation err=%v", err)
	}
}

func TestFenceRejectsStaleRevisionAndExpiredLease(t *testing.T) {
	task := baseTask()
	now := task.CreatedAt
	lease, _ := Claim(&task, ClaimCommand{TaskID: testID, Holder: "worker", ExpectedRevision: 1, LeaseEpoch: 1, LeaseTTL: time.Minute, At: now})
	p := Progress{TaskID: testID, Attempt: 1, Sequence: 1, At: now, Status: StatusRunning, Message: "x"}
	if err := ValidateProgress(task, ProgressCommand{Fence: Fence{TaskID: testID, Attempt: 1, LeaseEpoch: lease.Epoch, ExpectedRevision: 1}, Progress: p}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("want revision conflict, got %v", err)
	}
	task.Lease.ExpiresAt = now.Add(-time.Second)
	if err := ValidateProgress(task, ProgressCommand{Fence: Fence{TaskID: testID, Attempt: 1, LeaseEpoch: lease.Epoch, ExpectedRevision: task.Revision}, Progress: p}); !errors.Is(err, ErrLeaseConflict) {
		t.Fatalf("want lease conflict, got %v", err)
	}
}

func TestAllocateProgressFencesDurableCursor(t *testing.T) {
	task := baseTask()
	now := task.CreatedAt
	lease, _ := Claim(&task, ClaimCommand{TaskID: testID, Holder: "worker", ExpectedRevision: 1, LeaseEpoch: 1, LeaseTTL: time.Minute, At: now})
	command := ProgressCommand{Fence: Fence{TaskID: testID, Attempt: 1, LeaseEpoch: lease.Epoch, ExpectedRevision: task.Revision}, ExpectedSequence: 0, Progress: Progress{TaskID: testID, Attempt: 1, At: now, Status: StatusRunning, Message: "step"}}
	p, err := AllocateProgress(task, command)
	if err != nil || p.Sequence != 1 {
		t.Fatalf("allocation=%+v err=%v", p, err)
	}
	stale := command
	stale.ExpectedSequence = 1
	if _, err := AllocateProgress(task, stale); !errors.Is(err, ErrConflict) {
		t.Fatal("out-of-order cursor accepted")
	}
	if err := ApplyProgress(&task, command); err != nil || task.ProgressSequence != 1 {
		t.Fatalf("apply progress err=%v cursor=%d", err, task.ProgressSequence)
	}
}

func TestReclaimUsesProvidedTimeAndPreservesAttempt(t *testing.T) {
	task := baseTask()
	now := task.CreatedAt
	lease, err := Claim(&task, ClaimCommand{TaskID: testID, Holder: "first", ExpectedRevision: 1, LeaseEpoch: 1, LeaseTTL: time.Minute, At: now})
	if err != nil {
		t.Fatal(err)
	}
	reclaimAt := lease.ExpiresAt.Add(time.Second)
	reclaimed, err := Reclaim(&task, ReclaimCommand{TaskID: testID, Holder: "second", ExpectedRevision: task.Revision, LeaseEpoch: 2, LeaseTTL: time.Minute, At: reclaimAt})
	if err != nil {
		t.Fatal(err)
	}
	if task.Attempt != 1 || task.LeaseEpoch != 2 || reclaimed.Holder != "second" || task.Revision != 3 {
		t.Fatalf("reclaim state: %+v", task)
	}
	if err := ValidateRenewLease(task, RenewLeaseCommand{Fence: Fence{TaskID: testID, Attempt: 1, LeaseEpoch: 2, ExpectedRevision: task.Revision}, Holder: "second", LeaseTTL: time.Minute, At: reclaimAt}); err != nil {
		t.Fatal(err)
	}
	if _, err := Reclaim(&task, ReclaimCommand{TaskID: testID, Holder: "stale", ExpectedRevision: task.Revision, LeaseEpoch: 2, LeaseTTL: time.Minute, At: reclaimAt.Add(time.Minute)}); !errors.Is(err, ErrConflict) {
		t.Fatal("stale reclaim epoch accepted")
	}
}

func TestTaskAttemptAndDeletedScheduleInvariants(t *testing.T) {
	task := baseTask()
	task.Status = StatusSucceeded
	task.Attempt = 0
	task.Result = &Result{Text: "ok"}
	if task.Validate() == nil {
		t.Fatal("terminal success without attempt must be invalid")
	}
	now := task.CreatedAt
	schedule := Schedule{ID: testID, Name: "deleted", Spec: baseTemplate(), Cron: "0 0 * * *", Revision: 1, CreatedAt: now, UpdatedAt: now, Deleted: true}
	if _, err := TriggerNow(schedule, TriggerNowRequest{ScheduleID: testID, IdempotencyKey: testID2, At: now}); err == nil {
		t.Fatal("deleted schedule must not trigger")
	}
}

func TestSoftDeleteAndMutationRecord(t *testing.T) {
	task := baseTask()
	at := task.CreatedAt
	if err := SoftDelete(&task, task.Revision, at); err != nil || task.DeletedAt == nil {
		t.Fatalf("soft delete err=%v", err)
	}
	if err := SoftDelete(&task, task.Revision, at); err != nil {
		t.Fatal(err)
	}
	r := MutationRecord{Operation: "delete_task", IdempotencyKey: testID, Digest: strings.Repeat("a", 64), Response: []byte(`{"ok":true}`), CreatedAt: at}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	create := CreateTaskCommand{Spec: baseSpec(), Mutation: MutationCommand{IdempotencyKey: testID, RequestDigest: strings.Repeat("c", 64)}}
	if err := create.Validate(); err != nil {
		t.Fatal(err)
	}
	command := MutationCommand{IdempotencyKey: testID, RequestDigest: strings.Repeat("a", 64), ExpectedRevision: 99}
	replayed, ok, err := ReplayMutation(r, "delete_task", command)
	if err != nil || !ok || string(replayed) != string(r.Response) {
		t.Fatalf("replay err=%v ok=%v", err, ok)
	}
	command.RequestDigest = strings.Repeat("b", 64)
	if _, _, err := ReplayMutation(r, "delete_task", command); !errors.Is(err, ErrConflict) {
		t.Fatal("changed digest must conflict")
	}
}

func TestMutationCommandAggregateAndIdentityChecks(t *testing.T) {
	task := baseTask()
	now := task.CreatedAt
	deleteCmd := DeleteTaskCommand{TaskID: testID2, Mutation: MutationCommand{IdempotencyKey: testID, RequestDigest: strings.Repeat("a", 64), ExpectedRevision: task.Revision}, At: now}
	if err := ValidateDeleteCommand(task, deleteCmd); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong aggregate delete err=%v", err)
	}
	badCreate := CreateTaskCommand{Spec: baseSpec(), Mutation: MutationCommand{IdempotencyKey: testID2, RequestDigest: strings.Repeat("a", 64)}}
	if err := badCreate.Validate(); !errors.Is(err, ErrConflict) {
		t.Fatalf("mismatched create identity err=%v", err)
	}
	if err := ValidateCancel(task, CancelCommand{TaskID: testID, At: now}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("missing cancel mutation err=%v", err)
	}
}

func TestCancelFencesStoredLeaseWithoutCallerEpoch(t *testing.T) {
	task := baseTask()
	now := task.CreatedAt
	_, err := Claim(&task, ClaimCommand{TaskID: testID, Holder: "worker", ExpectedRevision: 1, LeaseEpoch: 1, LeaseTTL: time.Minute, At: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := Cancel(&task, CancelCommand{TaskID: testID, Mutation: MutationCommand{IdempotencyKey: testID2, RequestDigest: strings.Repeat("e", 64), ExpectedRevision: task.Revision}, Reason: "user", At: now}); err != nil {
		t.Fatal(err)
	}
	if task.Status != StatusCanceled || task.Lease != nil || task.LeaseEpoch != 2 {
		t.Fatal("cancel must fence stored lease")
	}
}

func TestResultAndProgressBounds(t *testing.T) {
	if (Result{JSON: []byte("{"), Files: []FileRef{{Path: "../escape", Digest: strings.Repeat("a", 64)}}}).Validate() == nil {
		t.Fatal("invalid result accepted")
	}
	pct := math.NaN()
	task := baseTask()
	now := task.CreatedAt
	lease, _ := Claim(&task, ClaimCommand{TaskID: testID, Holder: "w", ExpectedRevision: 1, LeaseEpoch: 1, LeaseTTL: time.Minute, At: now})
	if err := ValidateProgress(task, ProgressCommand{Fence: Fence{TaskID: testID, Attempt: 1, LeaseEpoch: lease.Epoch, ExpectedRevision: task.Revision}, Progress: Progress{TaskID: testID, Attempt: 1, Sequence: 1, At: now, Status: StatusRunning, Percent: &pct}}); err == nil {
		t.Fatal("NaN progress accepted")
	}
}

func TestFIFOAndRetry(t *testing.T) {
	a := baseTask()
	b := a
	b.ID = testID2
	b.CreatedAt = b.CreatedAt.Add(time.Second)
	b.AvailableAt = a.AvailableAt
	ordered := FIFO([]Task{b, a})
	if ordered[0].ID != a.ID {
		t.Fatal("FIFO ordering")
	}
	if _, ok := ClaimNext([]Task{a}, 1, ClaimPolicy{MaxConcurrent: 1}, a.AvailableAt); ok {
		t.Fatal("full concurrency must not claim")
	}
	future := a
	future.ID = testID2
	future.AvailableAt = a.AvailableAt.Add(time.Hour)
	if _, ok := ClaimNext([]Task{future}, 0, ClaimPolicy{MaxConcurrent: 1}, a.AvailableAt); ok {
		t.Fatal("future task must not claim")
	}
	a.Status = StatusFailed
	r, err := RetryTask(a, RetryRequest{TaskID: a.ID, IdempotencyKey: testID2, RequestDigest: strings.Repeat("d", 64), ExpectedRevision: a.Revision, At: a.UpdatedAt.Add(time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if r.ID == a.ID || r.RetryOfTaskID != a.ID || r.Status != StatusQueued {
		t.Fatal("retry provenance")
	}
}

func TestRetryRejectsUncertainProviderOutcome(t *testing.T) {
	a := baseTask()
	a.Status = StatusFailed
	for _, code := range []string{"tool_uncertain", "model_uncertain"} {
		a.FailureCode = code
		if _, err := RetryTask(a, RetryRequest{TaskID: a.ID, IdempotencyKey: testID2, RequestDigest: strings.Repeat("d", 64), ExpectedRevision: a.Revision, At: a.UpdatedAt.Add(time.Second)}); err != ErrConflict {
			t.Fatalf("failure code %q retry err=%v, want ErrConflict", code, err)
		}
	}
}

func TestRetryRejectsNonAgentTask(t *testing.T) {
	a := baseTask()
	a.Spec.Kind = TaskKindAWSChange
	a.Status = StatusFailed
	if _, err := RetryTask(a, RetryRequest{TaskID: a.ID, IdempotencyKey: testID2, RequestDigest: strings.Repeat("d", 64), ExpectedRevision: a.Revision, At: a.UpdatedAt.Add(time.Second)}); err != ErrConflict {
		t.Fatalf("non-Agent retry err=%v, want ErrConflict", err)
	}
}

func TestScheduleValidationAndTriggerNow(t *testing.T) {
	now := time.Date(2026, 7, 24, 0, 0, 0, 0, time.UTC)
	s := Schedule{ID: testID, Name: "daily", Spec: baseTemplate(), Cron: "0 0 * * *", Timezone: "Asia/Shanghai", Revision: 1, CreatedAt: now, UpdatedAt: now}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	occ, err := TriggerNow(s, TriggerNowRequest{ScheduleID: testID, IdempotencyKey: testID2, At: now})
	if err != nil {
		t.Fatal(err)
	}
	if err := occ.Validate(); err != nil {
		t.Fatal(err)
	}
	spec, err := MaterializeOccurrence(s, occ)
	if err != nil || spec.IdempotencyKey == "" || spec.AvailableAt.IsZero() {
		t.Fatalf("materialization err=%v spec=%+v", err, spec)
	}
	if _, err := s.Spec.Materialize(testID2, now); err != nil {
		t.Fatal(err)
	}
	occ2, _ := TriggerNow(s, TriggerNowRequest{ScheduleID: testID, IdempotencyKey: testID2, At: now.Add(time.Hour)})
	if occ.ID != occ2.ID || occ.TaskID != occ2.TaskID {
		t.Fatal("TriggerNow must be idempotent")
	}
	occ3, err := TriggerNow(s, TriggerNowRequest{ScheduleID: testID, IdempotencyKey: "00000000-0000-4000-8000-000000000003", At: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	spec3, err := MaterializeOccurrence(s, occ3)
	if err != nil || spec3.IdempotencyKey == spec.IdempotencyKey {
		t.Fatal("occurrences must have independent task identity")
	}
	if err := ValidateCron("0 0 *"); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid cron")
	}
	if err := ValidateCron("99 99 99 99 99"); !errors.Is(err, ErrInvalid) {
		t.Fatal("out-of-range cron")
	}
	for _, expr := range []string{"0 0 * MON-FRI", "0 0 * JAN-MAR MON-FRI", "0 0 * FRI-MON *", "0 0 * DEC-JAN *"} {
		if err := ValidateCron(expr); !errors.Is(err, ErrInvalid) {
			t.Fatalf("non-numeric cron accepted: %s", expr)
		}
	}
	parsed, err := ParseCron("*/15 1-5 1,10 * 0-6")
	if err != nil || parsed.Fields[0] != "*/15" {
		t.Fatalf("numeric cron parse failed: %+v err=%v", parsed, err)
	}
	for _, expr := range []string{"*/60 * * * *", "* */24 * * *", "* * 10-1 * *"} {
		if err := ValidateCron(expr); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid range/step accepted: %s", expr)
		}
	}
	for _, expr := range []string{"0 0 ? * *", "0 0 L * *", "0 0 * * 1#2"} {
		if err := ValidateCron(expr); !errors.Is(err, ErrInvalid) {
			t.Fatalf("non-standard modifier accepted: %s", expr)
		}
	}
}

type occurrenceStoreFake struct {
	occurrence Occurrence
	found      bool
	creates    int
}

func (s *occurrenceStoreFake) FindOccurrence(_ context.Context, _ string, key string) (Occurrence, error) {
	if !s.found || s.occurrence.TriggerKey != key {
		return Occurrence{}, ErrNotFound
	}
	return s.occurrence, nil
}
func (s *occurrenceStoreFake) CreateOccurrence(_ context.Context, _ Schedule, _ TriggerNowCommand, candidate Occurrence) (Occurrence, error) {
	s.creates++
	s.occurrence = candidate
	s.found = true
	return candidate, nil
}

func TestTriggerNowStoreReplayReturnsImmutableOccurrence(t *testing.T) {
	now := time.Now().UTC()
	schedule := Schedule{ID: testID, Name: "manual", Spec: baseTemplate(), Cron: "0 0 * * *", Revision: 1, CreatedAt: now, UpdatedAt: now}
	store := &occurrenceStoreFake{}
	first, err := TriggerNowWithStore(context.Background(), store, schedule, TriggerNowCommand{ScheduleID: testID, IdempotencyKey: testID2, At: now})
	if err != nil {
		t.Fatal(err)
	}
	replay, err := TriggerNowWithStore(context.Background(), store, schedule, TriggerNowCommand{ScheduleID: testID, IdempotencyKey: testID2, At: now.Add(24 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, replay) || store.creates != 1 {
		t.Fatalf("replay changed occurrence: first=%+v replay=%+v creates=%d", first, replay, store.creates)
	}
	schedule.Deleted = true
	replay, err = TriggerNowWithStore(context.Background(), store, schedule, TriggerNowCommand{ScheduleID: testID, IdempotencyKey: testID2, At: now.Add(48 * time.Hour)})
	if err != nil || !reflect.DeepEqual(first, replay) {
		t.Fatalf("deleted schedule replay must return original: err=%v replay=%+v", err, replay)
	}
	if _, err := TriggerNowWithStore(context.Background(), store, schedule, TriggerNowCommand{ScheduleID: testID, IdempotencyKey: "00000000-0000-4000-8000-000000000003", At: now}); !errors.Is(err, ErrInvalid) {
		t.Fatal("fresh trigger on deleted schedule must reject")
	}
}
