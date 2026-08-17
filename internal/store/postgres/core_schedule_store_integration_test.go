package postgres

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
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

func TestCoreScheduleProfileFenceSerializesCreateUpdateAndDeletePostgres(t *testing.T) {
	ctx, store, originalProfileID, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	schedules := NewCoreScheduleStore(store)
	now := time.Now().UTC().Truncate(time.Microsecond)
	newSchedule := func(profileID string) coretask.Schedule {
		runAt := now.Add(time.Hour)
		return coretask.Schedule{ID: uuid.NewString(), Name: "profile fence", Spec: coretask.TaskTemplate{Goal: "scheduled", ModelProfileID: profileID}, RunAt: &runAt, NextRunAt: runAt, Timezone: "UTC", Revision: 1, CreatedAt: now, UpdatedAt: now}
	}
	runCreateDeleteRace := func(profileID string, schedule coretask.Schedule) {
		start := make(chan struct{})
		var createErr, deleteErr error
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, createErr = schedules.CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: schedule, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("7", 64)}})
		}()
		go func() {
			defer wg.Done()
			<-start
			_, deleteErr = store.DeleteProfile(ctx, profileID, uuid.NewString(), strings.Repeat("8", 64), 1)
		}()
		close(start)
		wg.Wait()
		if !((createErr == nil && errors.Is(deleteErr, coremodel.ErrProfileInUse)) || (deleteErr == nil && errors.Is(createErr, coretask.ErrNotFound))) {
			t.Fatalf("create/delete race: create=%v delete=%v", createErr, deleteErr)
		}
	}

	createProfileID := uuid.NewString()
	createTestProfile(ctx, t, store, createProfileID, "create-race", "secret")
	runCreateDeleteRace(createProfileID, newSchedule(createProfileID))

	updateProfileID := uuid.NewString()
	createTestProfile(ctx, t, store, updateProfileID, "update-race", "secret")
	base := newSchedule(originalProfileID)
	created, err := schedules.CreateSchedule(ctx, coretask.CreateScheduleCommand{Schedule: base, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("9", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	updated := created
	updated.Spec.ModelProfileID = updateProfileID
	updated.UpdatedAt = now.Add(time.Second)
	start := make(chan struct{})
	var updateErr, deleteErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, updateErr = schedules.UpdateSchedule(ctx, coretask.UpdateScheduleCommand{Schedule: updated, Mutation: coretask.MutationCommand{IdempotencyKey: uuid.NewString(), RequestDigest: strings.Repeat("a", 64), ExpectedRevision: created.Revision}})
	}()
	go func() {
		defer wg.Done()
		<-start
		_, deleteErr = store.DeleteProfile(ctx, updateProfileID, uuid.NewString(), strings.Repeat("b", 64), 1)
	}()
	close(start)
	wg.Wait()
	if !((updateErr == nil && errors.Is(deleteErr, coremodel.ErrProfileInUse)) || (deleteErr == nil && errors.Is(updateErr, coretask.ErrNotFound))) {
		t.Fatalf("update/delete race: update=%v delete=%v", updateErr, deleteErr)
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
