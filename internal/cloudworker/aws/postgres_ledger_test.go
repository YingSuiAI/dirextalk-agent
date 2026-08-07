package aws

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresLedgerConcurrentExecutionIntentAndRestart(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	original := postgresTestRecord(t, testPlan(t, now), now)
	reclaimedPlan := original.Plan
	reclaimedPlan.Identity.TaskAttempt++
	reclaimedPlan.Identity.LeaseEpoch++
	reclaimedPlan.Identity.LaunchIdentity = DeriveLaunchIdentity(reclaimedPlan.Identity)
	reclaimedPlan.InfrastructureDigest = ""
	var err error
	reclaimedPlan, err = SealPlan(reclaimedPlan)
	if err != nil {
		t.Fatal(err)
	}
	reclaimed := postgresTestRecord(t, reclaimedPlan, now)

	db := newFakeLedgerDB()
	ledger, _ := newPostgresLedger(db)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, record := range []LedgerRecord{original, reclaimed} {
		record := record
		go func() {
			<-start
			_, createErr := ledger.CreateIntent(context.Background(), record)
			results <- createErr
		}()
	}
	close(start)
	succeeded, conflicted := 0, 0
	for range 2 {
		switch err := <-results; {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrConflict):
			conflicted++
		default:
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if succeeded != 1 || conflicted != 1 {
		t.Fatalf("concurrent results success=%d conflict=%d", succeeded, conflicted)
	}

	restarted, _ := newPostgresLedger(db)
	stored, err := restarted.GetByExecution(context.Background(), LookupFor(original.Identity))
	if err != nil || !stored.Identity.SameDispatch(original.Identity) || stored.Revision != 1 {
		t.Fatalf("restart did not recover first dispatch: record=%+v err=%v", stored.Identity, err)
	}
	if _, err := restarted.Get(context.Background(), stored.Identity); err != nil {
		t.Fatalf("strong identity read after restart: %v", err)
	}
}

func TestPostgresLedgerCASAndVerifiedDestroyedAreFenced(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	record := postgresTestRecord(t, testPlan(t, now), now)
	db := newFakeLedgerDB()
	ledger, _ := newPostgresLedger(db)
	if _, err := ledger.CreateIntent(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	next := record.clone()
	next.State, next.Revision, next.UpdatedAt = LifecycleProvisioning, 2, now.Add(time.Second)
	next.CreateMutation = MutationRecord{Token: next.Intent.ClientToken, StartedAt: now, LeaseUntil: now.Add(30 * time.Second),
		DispatchedAt: now, CompletedAt: now.Add(time.Second), AcceptedAt: now.Add(time.Second), Attempts: 1}
	if _, err := ledger.CompareAndSwap(context.Background(), next, 1); err != nil {
		t.Fatal(err)
	}
	stale := next.clone()
	stale.Revision, stale.UpdatedAt = 2, now.Add(2*time.Second)
	if _, err := ledger.CompareAndSwap(context.Background(), stale, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS = %v", err)
	}

	terminal := next.clone()
	terminal.State, terminal.Revision, terminal.UpdatedAt = LifecycleVerifiedDestroyed, 3, now.Add(3*time.Second)
	terminal.CleanupRequestedAt = now.Add(2 * time.Second)
	for kind, entry := range terminal.Resources {
		entry.State = ResourceVerifiedDestroyed
		terminal.Resources[kind] = entry
	}
	terminal.VerifiedDestroyedAt = terminal.UpdatedAt
	terminal.LastTombstoneAuditAt = terminal.UpdatedAt
	terminal.TombstoneAuditUntil = terminal.UpdatedAt.Add(verifiedTombstoneAuditRetention)
	if _, err := ledger.CompareAndSwap(context.Background(), terminal, 2); err != nil {
		t.Fatal(err)
	}
	regression := terminal.clone()
	regression.State, regression.Revision, regression.UpdatedAt = LifecycleActive, 4, now.Add(4*time.Second)
	if _, err := ledger.CompareAndSwap(context.Background(), regression, 3); !errors.Is(err, ErrConflict) {
		t.Fatalf("verified_destroyed regressed: %v", err)
	}
	reopened := terminal.clone()
	reopened.State, reopened.Revision, reopened.UpdatedAt = LifecycleDestroying, 4, now.Add(4*time.Second)
	reopened.VerifiedDestroyedAt, reopened.TombstoneAuditUntil, reopened.LastTombstoneAuditAt = time.Time{}, time.Time{}, time.Time{}
	late := reopened.Resources[ResourceEC2]
	late.State = ResourceDestroyPending
	reopened.Resources[ResourceEC2] = late
	if _, err := ledger.CompareAndSwap(context.Background(), reopened, 3); err != nil {
		t.Fatalf("verified tombstone could not reopen for a late exact resource: %v", err)
	}
}

func TestPostgresLedgerPersistsStackCreationAndIAMImmutableIDs(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	record := postgresTestRecord(t, testPlan(t, now), now)
	db := newFakeLedgerDB()
	ledger, _ := newPostgresLedger(db)
	if _, err := ledger.CreateIntent(context.Background(), record); err != nil {
		t.Fatal(err)
	}
	next := record.clone()
	next.State, next.Revision, next.UpdatedAt = LifecycleProvisioning, 2, now.Add(time.Second)
	next.CreateMutation = MutationRecord{Token: next.Intent.ClientToken, StartedAt: now, LeaseUntil: now.Add(30 * time.Second),
		DispatchedAt: now, CompletedAt: now.Add(time.Second), AcceptedAt: now.Add(time.Second), Attempts: 1}
	next.StackProviderID = "arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-pi/11111111"
	next.StackCreationIdentity = StackCreationIdentity{
		StackID: next.StackProviderID, StackName: next.Intent.StackName, ClientRequestToken: next.Intent.ClientToken,
		CreationEventID: "event-create-ledger", CreationTime: now, ObservedAt: now.Add(time.Second),
	}
	stack := next.Resources[ResourceStack]
	stack.ProviderID = next.StackProviderID
	next.Resources[ResourceStack] = stack
	role := next.Resources[ResourceIAMRole]
	role.ProviderID = "AROA1234567890ABCDEFG"
	next.Resources[ResourceIAMRole] = role
	profile := next.Resources[ResourceInstanceProfile]
	profile.ProviderID = "AIPA1234567890ABCDEFG"
	next.Resources[ResourceInstanceProfile] = profile
	if _, err := ledger.CompareAndSwap(context.Background(), next, 1); err != nil {
		t.Fatal(err)
	}
	restarted, _ := newPostgresLedger(db)
	stored, err := restarted.Get(context.Background(), record.Identity)
	if err != nil || stored.StackCreationIdentity != next.StackCreationIdentity ||
		stored.Resources[ResourceIAMRole].ProviderID != role.ProviderID ||
		stored.Resources[ResourceInstanceProfile].ProviderID != profile.ProviderID {
		t.Fatalf("immutable AWS identities did not survive restart: stack=%+v role=%q profile=%q err=%v",
			stored.StackCreationIdentity, stored.Resources[ResourceIAMRole].ProviderID,
			stored.Resources[ResourceInstanceProfile].ProviderID, err)
	}
	tampered := stored.clone()
	tampered.SchemaVersion = 1
	if _, err := encodeLedgerRecord(tampered); !errors.Is(err, ErrInvalid) {
		t.Fatalf("superseded ledger schema was accepted: %v", err)
	}
}

func TestPostgresLedgerReadyReapFilterAndStrictJSON(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	db := newFakeLedgerDB()
	ledger, _ := newPostgresLedger(db)
	if err := ledger.Ready(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing table readiness = %v", err)
	}
	db.ready = true
	if err := ledger.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}

	past := postgresTestRecord(t, testPlanWithExecution(t, now, "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", now.Add(-time.Minute)), now)
	future := postgresTestRecord(t, testPlanWithExecution(t, now, "33333333-3333-4333-8333-333333333333", "44444444-4444-4444-8444-444444444444", now.Add(time.Hour)), now)
	cleanup := postgresTestRecord(t, testPlanWithExecution(t, now, "55555555-5555-4555-8555-555555555555", "66666666-6666-4666-8666-666666666666", now.Add(time.Hour)), now)
	cleanup.CleanupRequestedAt = now.Add(-time.Second)
	tombstone := postgresTestRecord(t, testPlanWithExecution(t, now, "77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888", now.Add(-time.Hour)), now)
	tombstone.State, tombstone.CleanupRequestedAt = LifecycleVerifiedDestroyed, now.Add(-time.Minute)
	for kind, entry := range tombstone.Resources {
		entry.State = ResourceVerifiedDestroyed
		tombstone.Resources[kind] = entry
	}
	tombstone.VerifiedDestroyedAt, tombstone.LastTombstoneAuditAt = now, now
	tombstone.TombstoneAuditUntil = now.Add(verifiedTombstoneAuditRetention)
	for _, record := range []LedgerRecord{past, future, cleanup, tombstone} {
		if _, err := ledger.CreateIntent(context.Background(), record); err != nil {
			t.Fatal(err)
		}
	}
	reapable, err := ledger.ListReapable(context.Background(), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(reapable) != 2 || reapable[0].Identity.ExecutionID != past.Identity.ExecutionID || reapable[1].Identity.ExecutionID != cleanup.Identity.ExecutionID {
		t.Fatalf("strict reaper filter/order failed: %+v", reapable)
	}
	reapable, err = ledger.ListReapable(context.Background(), now.Add(verifiedTombstoneAuditInterval))
	if err != nil || !containsLedgerExecution(reapable, tombstone.Identity.ExecutionID) {
		t.Fatalf("due verified tombstone was not scheduled for low-frequency audit: %+v err=%v", reapable, err)
	}

	encoded, err := encodeLedgerRecord(past)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeLedgerRecord(append(encoded, []byte(` {"trailing":true}`)...)); !errors.Is(err, ErrIdentityMismatch) {
		t.Fatalf("trailing ledger JSON accepted: %v", err)
	}
}

func containsLedgerExecution(records []LedgerRecord, executionID string) bool {
	for _, record := range records {
		if record.Identity.ExecutionID == executionID {
			return true
		}
	}
	return false
}

func postgresTestRecord(t *testing.T, plan Plan, now time.Time) LedgerRecord {
	t.Helper()
	intent, err := NewDispatchIntent(plan, testAuthorization(now), now)
	if err != nil {
		t.Fatal(err)
	}
	record, err := NewLedgerRecord(plan, intent, now)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func testPlanWithExecution(t *testing.T, now time.Time, executionID, taskID string, destroyDeadline time.Time) Plan {
	t.Helper()
	plan := testPlan(t, now)
	plan.Identity.ExecutionID = executionID
	plan.Identity.TaskID = taskID
	plan.Identity.LaunchIdentity = DeriveLaunchIdentity(plan.Identity)
	plan.DestroyDeadline = destroyDeadline
	plan.IAMRoleName, plan.InstanceProfileName, plan.BootstrapDigest, plan.InfrastructureDigest = "", "", "", ""
	sealed, err := SealPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

type fakeLedgerDB struct {
	mu          sync.Mutex
	ready       bool
	records     map[string][]byte
	byExecution map[string]string
}

func newFakeLedgerDB() *fakeLedgerDB {
	return &fakeLedgerDB{records: make(map[string][]byte), byExecution: make(map[string]string)}
}

func (db *fakeLedgerDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch sql {
	case insertLedgerSQL:
		key := args[0].(string)
		executionKey := fakeExecutionKey(args[2].(string), args[3].(uint64), args[1].(string), args[5].(string))
		if _, exists := db.records[key]; exists {
			return pgconn.NewCommandTag("INSERT 0 0"), nil
		}
		if _, exists := db.byExecution[executionKey]; exists {
			return pgconn.CommandTag{}, &pgconn.PgError{Code: "23505", Message: "execution unique violation"}
		}
		db.records[key] = append([]byte(nil), args[19].([]byte)...)
		db.byExecution[executionKey] = key
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	case casLedgerSQL:
		key := args[0].(string)
		encoded, exists := db.records[key]
		if !exists {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		stored, err := decodeLedgerRecord(encoded)
		if err != nil || stored.Revision != args[20].(uint64) || stored.Plan.Digest != args[12].(string) ||
			stored.Plan.InfrastructureDigest != args[13].(string) || stored.Intent.IntentDigest != args[14].(string) ||
			(stored.State == LifecycleVerifiedDestroyed && LifecycleState(args[15].(string)) != LifecycleVerifiedDestroyed && LifecycleState(args[15].(string)) != LifecycleDestroying) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		db.records[key] = append([]byte(nil), args[18].([]byte)...)
		return pgconn.NewCommandTag("UPDATE 1"), nil
	default:
		return pgconn.CommandTag{}, errors.New("unexpected exec")
	}
}

func (db *fakeLedgerDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch sql {
	case ledgerReadySQL:
		if db.ready {
			return fakeRow{value: PostgresLedgerTable}
		}
		return fakeRow{value: ""}
	case getLedgerSQL:
		encoded, exists := db.records[args[0].(string)]
		if !exists {
			return fakeRow{err: pgx.ErrNoRows}
		}
		return fakeRow{value: append([]byte(nil), encoded...)}
	case getLedgerByExecutionSQL:
		key, exists := db.byExecution[fakeExecutionKey(args[0].(string), args[1].(uint64), args[2].(string), args[3].(string))]
		if !exists {
			return fakeRow{err: pgx.ErrNoRows}
		}
		return fakeRow{value: append([]byte(nil), db.records[key]...)}
	default:
		return fakeRow{err: errors.New("unexpected query row")}
	}
}

func (db *fakeLedgerDB) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	if sql == lookupWorkerIdentitySQL {
		values := make([][]byte, 0, 2)
		for _, encoded := range db.records {
			record, err := decodeLedgerRecord(encoded)
			if err != nil {
				return nil, err
			}
			if record.Identity.AccountID == args[0].(string) && record.Identity.Region == args[1].(string) &&
				record.State == LifecycleActive && record.Resources[ResourceEC2].ProviderID == args[2].(string) {
				values = append(values, append([]byte(nil), encoded...))
			}
		}
		return &fakeRows{values: values, index: -1}, nil
	}
	if sql != listReapableLedgerSQL {
		return nil, errors.New("unexpected query")
	}
	before := args[0].(time.Time)
	values := make([][]byte, 0)
	for _, encoded := range db.records {
		record, err := decodeLedgerRecord(encoded)
		if err != nil {
			return nil, err
		}
		if record.State == LifecycleVerifiedDestroyed {
			if record.tombstoneAuditDue(before) {
				values = append(values, append([]byte(nil), encoded...))
			}
		} else if !record.CleanupRequestedAt.IsZero() || !record.Plan.DestroyDeadline.After(before) {
			values = append(values, append([]byte(nil), encoded...))
		}
	}
	// The production SQL orders by deadline and identity key; preserve that
	// contract in the fake by decoding and sorting through the same fields.
	sortLedgerJSON(values)
	return &fakeRows{values: values, index: -1}, nil
}

func fakeExecutionKey(account string, generation uint64, owner, execution string) string {
	return account + "/" + string(rune(generation)) + "/" + owner + "/" + execution
}

type fakeRow struct {
	value any
	err   error
}

func (row fakeRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != 1 {
		return errors.New("unexpected scan")
	}
	switch target := dest[0].(type) {
	case *string:
		*target = row.value.(string)
	case *[]byte:
		*target = append((*target)[:0], row.value.([]byte)...)
	default:
		return errors.New("unsupported scan target")
	}
	return nil
}

type fakeRows struct {
	values [][]byte
	index  int
	closed bool
}

func (rows *fakeRows) Close()                                       { rows.closed = true }
func (rows *fakeRows) Err() error                                   { return nil }
func (rows *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT") }
func (rows *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *fakeRows) Next() bool {
	rows.index++
	if rows.index >= len(rows.values) {
		rows.closed = true
		return false
	}
	return true
}
func (rows *fakeRows) Scan(dest ...any) error {
	if rows.index < 0 || rows.index >= len(rows.values) || len(dest) != 1 {
		return errors.New("invalid rows scan")
	}
	value, ok := dest[0].(*[]byte)
	if !ok {
		return errors.New("unsupported rows target")
	}
	*value = append((*value)[:0], rows.values[rows.index]...)
	return nil
}
func (rows *fakeRows) Values() ([]any, error) { return []any{rows.values[rows.index]}, nil }
func (rows *fakeRows) RawValues() [][]byte    { return [][]byte{rows.values[rows.index]} }
func (rows *fakeRows) Conn() *pgx.Conn        { return nil }

func sortLedgerJSON(values [][]byte) {
	for index := 1; index < len(values); index++ {
		for current := index; current > 0; current-- {
			left, _ := decodeLedgerRecord(values[current-1])
			right, _ := decodeLedgerRecord(values[current])
			leftKey, rightKey := ledgerKey(left.Identity), ledgerKey(right.Identity)
			if left.Plan.DestroyDeadline.Before(right.Plan.DestroyDeadline) ||
				(left.Plan.DestroyDeadline.Equal(right.Plan.DestroyDeadline) && leftKey < rightKey) {
				break
			}
			values[current-1], values[current] = values[current], values[current-1]
		}
	}
}

var _ postgresLedgerDB = (*fakeLedgerDB)(nil)
var _ pgx.Rows = (*fakeRows)(nil)
