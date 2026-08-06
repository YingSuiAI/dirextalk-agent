package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/agentcapability"
	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

func TestCoreScheduleStorePostgresAtomicMaterialization(t *testing.T) {
	ctx, store, profile, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	schedules, tasks := NewCoreScheduleStore(store), NewCoreTaskStore(store)
	now := time.Now().UTC().Truncate(time.Minute)
	runAt := now.Add(-time.Minute)
	key := uuid.NewString()
	s := coretask.Schedule{ID: uuid.NewString(), Name: "once", Spec: coretask.TaskTemplate{Goal: "scheduled", ModelProfileID: profile}, RunAt: &runAt, Timezone: "UTC", NextRunAt: runAt, Revision: 1, CreatedAt: now, UpdatedAt: now}
	created, err := schedules.CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: s, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: strings.Repeat("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := schedules.CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: s, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: strings.Repeat("a", 64)}})
	if err != nil || replayed.ID != created.ID {
		t.Fatalf("schedule replay = %#v %v", replayed, err)
	}
	if _, err = schedules.PauseSchedule(ctx, coretask.ScheduleMutationCommand{ScheduleID: s.ID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("b", 64), ExpectedRevision: 99}, At: now}); !errors.Is(err, coretask.ErrRevisionConflict) {
		t.Fatalf("schedule CAS = %v", err)
	}
	paused, err := schedules.PauseSchedule(ctx, coretask.ScheduleMutationCommand{ScheduleID: s.ID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("b", 64), ExpectedRevision: created.Revision}, At: now})
	if err != nil || !paused.Paused {
		t.Fatalf("pause = %#v %v", paused, err)
	}
	resumed, err := schedules.ResumeSchedule(ctx, coretask.ScheduleMutationCommand{ScheduleID: s.ID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("c", 64), ExpectedRevision: paused.Revision}, At: now})
	if err != nil || resumed.Paused {
		t.Fatalf("resume = %#v %v", resumed, err)
	}
	cursor := resumed.NextRunAt
	_, occ, triggered, err := schedules.TriggerNow(ctx, coretask.TriggerScheduleCommand{ScheduleID: s.ID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("d", 64)}, At: now.Add(time.Second)})
	if err != nil || occ.TaskID != triggered.ID {
		t.Fatalf("trigger = %#v %#v %v", occ, triggered, err)
	}
	current, _ := schedules.GetSchedule(ctx, s.ID)
	if !current.NextRunAt.Equal(cursor) {
		t.Fatalf("trigger changed cron cursor: %s -> %s", cursor, current.NextRunAt)
	}
	// Competing schedulers serialize the one-shot occurrence through its locked
	// cursor and never create a duplicate task/event pair.
	var wg sync.WaitGroup
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := schedules.MaterializeNextDue(ctx, now, minuteCron{}); err != nil {
				t.Errorf("materialize: %v", err)
			}
		}()
	}
	wg.Wait()
	var occurrences, initialEvents int
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_schedule_occurrences WHERE schedule_id=$1 AND trigger_key IS NULL`, s.ID).Scan(&occurrences); err != nil {
		t.Fatal(err)
	}
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_task_events e JOIN core_schedule_occurrences o ON o.task_id=e.task_id WHERE o.schedule_id=$1 AND o.trigger_key IS NULL AND e.sequence=1`, s.ID).Scan(&initialEvents); err != nil {
		t.Fatal(err)
	}
	if occurrences != 1 || initialEvents != 1 {
		t.Fatalf("atomic occurrence/task/event = %d/%d", occurrences, initialEvents)
	}
	completed, _ := schedules.GetSchedule(ctx, s.ID)
	if !completed.NextRunAt.IsZero() || !completed.LastScheduledFor.Equal(runAt) {
		t.Fatalf("one-shot cursor = %#v", completed)
	}
	// A calculator error is an injected rollback before the cron occurrence,
	// task and cursor commit; a retry after that error creates it exactly once.
	cronKey := uuid.NewString()
	cron := coretask.Schedule{ID: uuid.NewString(), Name: "cron", Spec: s.Spec, Cron: "* * * * *", Timezone: "UTC", NextRunAt: now.Add(-time.Minute), Revision: 1, CreatedAt: now, UpdatedAt: now}
	cronCreated, err := schedules.CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: cron, Mutation: coretask.MutationCommand{IdempotencyKey: cronKey, RequestDigest: strings.Repeat("f", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = schedules.MaterializeNextDue(ctx, now, failingCron{}); err == nil {
		t.Fatal("expected injected calculation failure")
	}
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_schedule_occurrences WHERE schedule_id=$1`, cron.ID).Scan(&occurrences); err != nil || occurrences != 0 {
		t.Fatalf("rollback occurrence = %d, %v", occurrences, err)
	}
	rolledBack, _ := schedules.GetSchedule(ctx, cron.ID)
	if !rolledBack.NextRunAt.Equal(cronCreated.NextRunAt) {
		t.Fatalf("rollback cursor changed: %s -> %s", cronCreated.NextRunAt, rolledBack.NextRunAt)
	}
	if _, err = schedules.MaterializeNextDue(ctx, now, minuteCron{}); err != nil {
		t.Fatal(err)
	}
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_schedule_occurrences WHERE schedule_id=$1`, cron.ID).Scan(&occurrences); err != nil || occurrences != 1 {
		t.Fatalf("cron retry occurrence = %d, %v", occurrences, err)
	}
	if _, _, err = tasks.ClaimNextDue(ctx, "delete-check", now.Add(time.Minute), time.Second, 5); err != nil {
		t.Fatal(err)
	}
	if _, err = tasks.DeleteTask(ctx, coretask.DeleteTaskCommand{TaskID: triggered.ID, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("e", 64), ExpectedRevision: triggered.Revision}, At: now}); !errors.Is(err, coretask.ErrConflict) {
		t.Fatalf("running delete = %v", err)
	}
}

func TestCoreScheduleReplayIdentityIsOwnerGenerationScoped(t *testing.T) {
	ctx, store, profile, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	schedules := NewCoreScheduleStore(store)
	ctxA, err := coretask.WithOwnerScope(ctx, coretask.OwnerScope{OwnerID: "@schedule-replay-a:example.test", AccountGeneration: 2})
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := coretask.WithOwnerScope(ctx, coretask.OwnerScope{OwnerID: "@schedule-replay-b:example.test", AccountGeneration: 7})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	key := uuid.NewString()
	create := func(callCtx context.Context, name, digest string) coretask.Schedule {
		runAt := now.Add(time.Hour)
		value := coretask.Schedule{
			ID: uuid.NewString(), Name: name,
			Spec:  coretask.TaskTemplate{Goal: name, ModelProfileID: profile},
			RunAt: &runAt, NextRunAt: runAt, Timezone: "UTC",
			Revision: 1, CreatedAt: now, UpdatedAt: now,
		}
		created, createErr := schedules.CreateSchedule(callCtx, coretask.CreateScheduleCommand{
			Schedule: value,
			Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest},
		})
		if createErr != nil {
			t.Fatalf("create %s: %v", name, createErr)
		}
		return created
	}
	a := create(ctxA, "owner-a", strings.Repeat("a", 64))
	b := create(ctxB, "owner-b", strings.Repeat("b", 64))
	if a.ID == b.ID || a.Name != "owner-a" || b.Name != "owner-b" {
		t.Fatalf("cross-owner schedule replay a=%#v b=%#v", a, b)
	}
	var receipts int
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_schedule_replays WHERE operation='create' AND idempotency_key=$1`, key).Scan(&receipts); err != nil {
		t.Fatal(err)
	}
	if receipts != 2 {
		t.Fatalf("schedule replay receipts=%d, want 2", receipts)
	}
}

func TestPublicScheduleGeneratedIDIsOwnerGenerationScoped(t *testing.T) {
	ctx, store, profile, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	registry := agentcapability.NewCoreRegistry(agentcapability.CoreBindings{Schedules: NewCoreScheduleStore(store)})
	capability, ok := registry.Get("agent.schedules.v1")
	if !ok {
		t.Fatal("Schedule capability is not registered")
	}
	publicContext := func(owner string, generation int64) context.Context {
		return capabilityclient.WithCallContext(ctx, &capv1.CallContext{}, &capv1.PermissionContext{AuthenticatedOwnerId: owner, AccountGeneration: generation})
	}
	key := uuid.NewString()
	runAt := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
	request := []byte(fmt.Sprintf(`{"idempotency_key":%q,"name":"public generated","run_at":%q,"timezone":"UTC","spec":{"goal":"public generated","model_profile_id":%q}}`, key, runAt, profile))
	create := func(callCtx context.Context) coretask.Schedule {
		raw, err := capability.HandleOperation(callCtx, "create_schedule", request)
		if err != nil {
			t.Fatal(err)
		}
		var result struct {
			Schedule coretask.Schedule `json:"schedule"`
		}
		if err = json.Unmarshal(raw, &result); err != nil {
			t.Fatal(err)
		}
		return result.Schedule
	}
	a := create(publicContext("@schedule-generated-a:example.test", 3))
	b := create(publicContext("@schedule-generated-b:example.test", 9))
	if a.ID == "" || b.ID == "" || a.ID == b.ID {
		t.Fatalf("generated Schedule IDs a=%q b=%q", a.ID, b.ID)
	}
}

func TestCoreScheduleStorePostgresDrainsConcurrentDueSchedules(t *testing.T) {
	ctx, store, profile, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	now := time.Now().UTC().Truncate(time.Minute)
	create := func(schedule coretask.Schedule) string {
		digest := strings.Repeat("a", 64)
		created, err := NewCoreScheduleStore(store).CreateSchedule(ctx, coretask.CreateScheduleCommand{
			Schedule: schedule,
			Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: digest},
		})
		if err != nil {
			t.Fatal(err)
		}
		return created.ID
	}
	var scheduleIDs []string
	for i := 0; i < 2; i++ {
		runAt := now.Add(-time.Minute)
		scheduleIDs = append(scheduleIDs, create(coretask.Schedule{
			ID: uuid.NewString(), Name: "one-shot", Spec: coretask.TaskTemplate{Goal: "scheduled", ModelProfileID: profile},
			RunAt: &runAt, NextRunAt: runAt, Timezone: "UTC", Revision: 1, CreatedAt: now, UpdatedAt: now,
		}))
	}
	for i := 0; i < 2; i++ {
		next := now.Add(-2 * time.Minute)
		scheduleIDs = append(scheduleIDs, create(coretask.Schedule{
			ID: uuid.NewString(), Name: "cron", Spec: coretask.TaskTemplate{Goal: "scheduled", ModelProfileID: profile},
			Cron: "* * * * *", NextRunAt: next, Timezone: "UTC", Revision: 1, CreatedAt: now, UpdatedAt: now,
		}))
	}

	// Multiple schedulers may race on the same due set. SKIP LOCKED lets them
	// claim different rows, while a later sweep catches rows skipped by an
	// overlapping transaction.
	schedules := NewCoreScheduleStore(store)
	var wg sync.WaitGroup
	for i := 0; i < len(scheduleIDs); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := schedules.MaterializeNextDue(ctx, now, minuteCron{}); err != nil {
				t.Errorf("concurrent materialize: %v", err)
			}
		}()
	}
	wg.Wait()
	// A restart-like fresh store and repeated sweeps must drain any rows that
	// were skipped by the concurrent pass, then become stable and idempotent.
	for i := 0; i < len(scheduleIDs)+1; i++ {
		fresh := NewCoreScheduleStore(store)
		materialized, err := fresh.MaterializeNextDue(ctx, now, minuteCron{})
		if err != nil {
			t.Fatal(err)
		}
		if !materialized {
			break
		}
	}
	for i := 0; i < 3; i++ {
		materialized, err := NewCoreScheduleStore(store).MaterializeNextDue(ctx, now, minuteCron{})
		if err != nil {
			t.Fatal(err)
		}
		if materialized {
			t.Fatalf("repeat sweep materialized an already drained schedule on pass %d", i)
		}
	}
	var occurrences, tasks, events int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM core_schedule_occurrences WHERE schedule_id = ANY($1::uuid[])`, scheduleIDs).Scan(&occurrences); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM core_tasks t JOIN core_schedule_occurrences o ON o.task_id=t.task_id WHERE o.schedule_id = ANY($1::uuid[])`, scheduleIDs).Scan(&tasks); err != nil {
		t.Fatal(err)
	}
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM core_task_events e JOIN core_schedule_occurrences o ON o.task_id=e.task_id WHERE o.schedule_id = ANY($1::uuid[]) AND e.sequence=1`, scheduleIDs).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if occurrences != len(scheduleIDs) || tasks != len(scheduleIDs) || events != len(scheduleIDs) {
		t.Fatalf("drain counts occurrences=%d tasks=%d events=%d want=%d", occurrences, tasks, events, len(scheduleIDs))
	}
	for _, id := range scheduleIDs {
		got, err := schedules.GetSchedule(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if got.RunAt != nil && !got.NextRunAt.IsZero() {
			t.Fatalf("one-shot cursor not consumed: %#v", got)
		}
		if got.Cron != "" && !got.NextRunAt.After(now) {
			t.Fatalf("cron cursor remains due: %#v", got)
		}
	}
}

func TestCoreScheduleMaterializationPreservesPublicOwnerScope(t *testing.T) {
	ctx, store, profile, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	ownerA := coretask.OwnerScope{OwnerID: "@schedule-owner-a:example.test", AccountGeneration: 3}
	ownerB := coretask.OwnerScope{OwnerID: "@schedule-owner-b:example.test", AccountGeneration: 8}
	ctxA, err := coretask.WithOwnerScope(ctx, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := coretask.WithOwnerScope(ctx, ownerB)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Minute)
	runAt := now.Add(-time.Minute)
	schedule := coretask.Schedule{
		ID: uuid.NewString(), Name: "owner-scoped once",
		Spec:  coretask.TaskTemplate{Goal: "owner-scoped scheduled task", ModelProfileID: profile},
		RunAt: &runAt, Timezone: "UTC", NextRunAt: runAt, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	schedules := NewCoreScheduleStore(store)
	if _, err = schedules.CreateSchedule(ctxA, coretask.CreateScheduleCommand{
		Schedule: schedule,
		Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("a", 64)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = schedules.GetSchedule(ctxB, schedule.ID); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("foreign owner read schedule err=%v", err)
	}
	if materialized, materializeErr := schedules.MaterializeNextDue(ctx, now, minuteCron{}); materializeErr != nil || !materialized {
		t.Fatalf("background materialization=%v err=%v", materialized, materializeErr)
	}
	var taskID string
	if err = store.pool.QueryRow(ctx, `SELECT task_id::text FROM core_schedule_occurrences WHERE schedule_id=$1`, schedule.ID).Scan(&taskID); err != nil {
		t.Fatal(err)
	}
	if _, err = NewCoreTaskStore(store).GetTask(ctxB, taskID); !errors.Is(err, coretask.ErrNotFound) {
		t.Fatalf("foreign owner read materialized Task err=%v", err)
	}
	if task, ownerErr := NewCoreTaskStore(store).GetTask(ctxA, taskID); ownerErr != nil || task.ID != taskID {
		t.Fatalf("owner read materialized Task=%#v err=%v", task, ownerErr)
	}
}

func TestCoreTaskSchedulePostgresConcurrentReplayAndCAS(t *testing.T) {
	ctx, store, profile, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	tasks, schedules := NewCoreTaskStore(store), NewCoreScheduleStore(store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	key := uuid.NewString()
	spec := coretask.TaskSpec{Goal: "once", ModelProfileID: profile, IdempotencyKey: key, AvailableAt: now}
	digest, _ := spec.MutationDigest()
	cmd := coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: digest}}
	var wg sync.WaitGroup
	results := make(chan coretask.Task, 2)
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); v, e := tasks.CreateTask(ctx, cmd); results <- v; errs <- e }()
	}
	wg.Wait()
	close(results)
	close(errs)
	var id string
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	for v := range results {
		if id != "" && id != v.ID {
			t.Fatalf("replay ids %s %s", id, v.ID)
		}
		id = v.ID
	}
	if _, e := tasks.CreateTask(ctx, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: key, RequestDigest: strings.Repeat("f", 64)}}); !errors.Is(e, coretask.ErrConflict) {
		t.Fatalf("task changed digest=%v", e)
	}
	runAt := now.Add(time.Hour)
	s := coretask.Schedule{ID: uuid.NewString(), Name: "cas", Spec: coretask.TaskTemplate{Goal: "scheduled", ModelProfileID: profile}, RunAt: &runAt, Timezone: "UTC", Revision: 1, CreatedAt: now, UpdatedAt: now}
	created, e := schedules.CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: s, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("a", 64)}})
	if e != nil {
		t.Fatal(e)
	}
	base := coretask.ScheduleMutationCommand{ScheduleID: s.ID, At: now, Mutation: coretask.MutationCommand{ExpectedRevision: created.Revision, RequestDigest: strings.Repeat("b", 64)}}
	cas := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := base
			c.Mutation.IdempotencyKey = uuid.NewString()
			_, e := schedules.PauseSchedule(ctx, c)
			cas <- e
		}()
	}
	wg.Wait()
	close(cas)
	wins := 0
	for e := range cas {
		if e == nil {
			wins++
		} else if !errors.Is(e, coretask.ErrRevisionConflict) {
			t.Fatal(e)
		}
	}
	if wins != 1 {
		t.Fatalf("CAS winners=%d", wins)
	}
	triggerKey := uuid.NewString()
	trigger := coretask.TriggerScheduleCommand{ScheduleID: s.ID, At: now, Mutation: coretask.MutationCommand{IdempotencyKey: triggerKey, RequestDigest: strings.Repeat("c", 64)}}
	// Resume first so TriggerNow is permitted, then concurrent exact replays must
	// return one durable occurrence/task pair.
	paused, _ := schedules.GetSchedule(ctx, s.ID)
	_, e = schedules.ResumeSchedule(ctx, coretask.ScheduleMutationCommand{ScheduleID: s.ID, At: now, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("d", 64), ExpectedRevision: paused.Revision}})
	if e != nil {
		t.Fatal(e)
	}
	tocc := make(chan coretask.Occurrence, 2)
	terr := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() { defer wg.Done(); _, o, _, e := schedules.TriggerNow(ctx, trigger); tocc <- o; terr <- e }()
	}
	wg.Wait()
	close(tocc)
	close(terr)
	var oid string
	for e := range terr {
		if e != nil {
			t.Fatal(e)
		}
	}
	for o := range tocc {
		if oid != "" && oid != o.ID {
			t.Fatal("trigger replay mismatch")
		}
		oid = o.ID
	}
	trigger.Mutation.RequestDigest = strings.Repeat("e", 64)
	if _, _, _, e = schedules.TriggerNow(ctx, trigger); !errors.Is(e, coretask.ErrConflict) {
		t.Fatalf("trigger changed digest=%v", e)
	}
}
