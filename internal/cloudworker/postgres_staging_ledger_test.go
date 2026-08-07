package cloudworker

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresStagingLedgerConcurrentIntentRestartAndCAS(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, _, _, _ := stagingFixture(t, now)
	identity := stagingIdentity(plan, plan.InputManifest.Items[0])
	record := StagingRecord{Identity: identity, State: StagingIntentRecorded, Revision: 1, CreatedAt: now, UpdatedAt: now}
	db := newFakeStagingDB()
	ledger, _ := newPostgresStagingLedger(db)

	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, err := ledger.CreateIntent(context.Background(), record)
			results <- err
		}()
	}
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("same-intent replay failed: %v", err)
		}
	}

	restarted, _ := newPostgresStagingLedger(db)
	stored, err := restarted.Get(context.Background(), identity)
	if err != nil || stored.Revision != 1 || stored.State != StagingIntentRecorded {
		t.Fatalf("restart read=%+v err=%v", stored, err)
	}
	next := stored
	next.State, next.MutationAttempts, next.MutationLeaseUntil = StagingPutStarted, 1, now.Add(time.Minute)
	next.Revision, next.UpdatedAt = 2, now.Add(time.Second)
	if _, err := restarted.CompareAndSwap(context.Background(), next, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.CompareAndSwap(context.Background(), next, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale CAS accepted: %v", err)
	}
}

func TestPostgresStagingLedgerIdentityTerminalReadyAndStrictJSON(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	plan, _, _, _ := stagingFixture(t, now)
	identity := stagingIdentity(plan, plan.InputManifest.Items[0])
	record := StagingRecord{Identity: identity, State: StagingIntentRecorded, Revision: 1, CreatedAt: now, UpdatedAt: now}
	db := newFakeStagingDB()
	ledger, _ := newPostgresStagingLedger(db)
	if err := ledger.Ready(context.Background()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing table readiness=%v", err)
	}
	db.ready = true
	if err := ledger.Ready(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.CreateIntent(context.Background(), record); err != nil {
		t.Fatal(err)
	}

	foreign := identity
	foreign.SourceRevision++
	if _, err := ledger.Get(context.Background(), foreign); !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign identity read=%v", err)
	}
	terminal := record
	terminal.State, terminal.Revision, terminal.UpdatedAt = StagingVerifiedDestroyed, 2, now.Add(time.Second)
	if _, err := ledger.CompareAndSwap(context.Background(), terminal, 1); err != nil {
		t.Fatal(err)
	}
	regression := terminal
	regression.State, regression.MutationAttempts, regression.MutationLeaseUntil = StagingPutStarted, 1, now.Add(time.Minute)
	regression.Revision, regression.UpdatedAt = 3, now.Add(2*time.Second)
	if _, err := ledger.CompareAndSwap(context.Background(), regression, 2); !errors.Is(err, ErrConflict) {
		t.Fatalf("terminal record regressed: %v", err)
	}

	encoded, _ := encodeStagingRecord(terminal)
	if _, err := decodeStagingRecord(append(encoded, []byte(` {"trailing":true}`)...)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing JSON accepted: %v", err)
	}
	rows, err := ledger.ListExecution(context.Background(), identity.OwnerID, identity.AccountGeneration, identity.ExecutionID)
	if err != nil || len(rows) != 1 || rows[0].State != StagingVerifiedDestroyed {
		t.Fatalf("list=%+v err=%v", rows, err)
	}
}

type fakeStagingDB struct {
	mu      sync.Mutex
	ready   bool
	records map[string]fakeStagingRowValue
}

type fakeStagingRowValue struct {
	digest string
	json   []byte
}

func newFakeStagingDB() *fakeStagingDB {
	return &fakeStagingDB{records: make(map[string]fakeStagingRowValue)}
}

func (db *fakeStagingDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch sql {
	case insertStagingRecordSQL:
		key := args[0].(string)
		if _, exists := db.records[key]; exists {
			return pgconn.NewCommandTag("INSERT 0 0"), nil
		}
		db.records[key] = fakeStagingRowValue{digest: args[1].(string), json: append([]byte(nil), args[16].([]byte)...)}
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	case casStagingRecordSQL:
		key := args[0].(string)
		stored, exists := db.records[key]
		if !exists || stored.digest != args[1].(string) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		current, err := decodeStagingRecord(stored.json)
		next, nextErr := decodeStagingRecord(args[8].([]byte))
		if err != nil || nextErr != nil || current.Revision != args[10].(uint64) || !validStagingTransition(current, next) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		db.records[key] = fakeStagingRowValue{digest: stored.digest, json: append([]byte(nil), args[8].([]byte)...)}
		return pgconn.NewCommandTag("UPDATE 1"), nil
	default:
		return pgconn.CommandTag{}, errors.New("unexpected exec")
	}
}

func (db *fakeStagingDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch sql {
	case stagingLedgerReadySQL:
		if db.ready {
			return stagingFakeRow{value: PostgresStagingLedgerTable}
		}
		return stagingFakeRow{value: ""}
	case getStagingRecordSQL:
		stored, exists := db.records[args[0].(string)]
		if !exists || stored.digest != args[1].(string) {
			return stagingFakeRow{err: pgx.ErrNoRows}
		}
		return stagingFakeRow{value: append([]byte(nil), stored.json...)}
	default:
		return stagingFakeRow{err: errors.New("unexpected query row")}
	}
}

func (db *fakeStagingDB) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	if sql != listStagingExecutionSQL {
		return nil, errors.New("unexpected query")
	}
	db.mu.Lock()
	defer db.mu.Unlock()
	values := make([][]byte, 0)
	for _, stored := range db.records {
		record, err := decodeStagingRecord(stored.json)
		if err != nil {
			return nil, err
		}
		if record.Identity.OwnerID == args[0].(string) && record.Identity.AccountGeneration == args[1].(uint64) && record.Identity.ExecutionID == args[2].(string) {
			values = append(values, append([]byte(nil), stored.json...))
		}
	}
	sort.Slice(values, func(i, j int) bool {
		left, _ := decodeStagingRecord(values[i])
		right, _ := decodeStagingRecord(values[j])
		return left.Identity.InputID < right.Identity.InputID
	})
	return &stagingFakeRows{values: values, index: -1}, nil
}

type stagingFakeRow struct {
	value any
	err   error
}

func (row stagingFakeRow) Scan(dest ...any) error {
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
		return errors.New("unsupported scan")
	}
	return nil
}

type stagingFakeRows struct {
	values [][]byte
	index  int
}

func (rows *stagingFakeRows) Close()                                       {}
func (rows *stagingFakeRows) Err() error                                   { return nil }
func (rows *stagingFakeRows) CommandTag() pgconn.CommandTag                { return pgconn.NewCommandTag("SELECT") }
func (rows *stagingFakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (rows *stagingFakeRows) Next() bool {
	rows.index++
	return rows.index < len(rows.values)
}
func (rows *stagingFakeRows) Scan(dest ...any) error {
	if rows.index < 0 || rows.index >= len(rows.values) || len(dest) != 1 {
		return errors.New("invalid rows scan")
	}
	target, ok := dest[0].(*[]byte)
	if !ok {
		return errors.New("unsupported rows target")
	}
	*target = append((*target)[:0], rows.values[rows.index]...)
	return nil
}
func (rows *stagingFakeRows) Values() ([]any, error) { return []any{rows.values[rows.index]}, nil }
func (rows *stagingFakeRows) RawValues() [][]byte    { return [][]byte{rows.values[rows.index]} }
func (rows *stagingFakeRows) Conn() *pgx.Conn        { return nil }

var _ stagingLedgerDB = (*fakeStagingDB)(nil)
var _ pgx.Rows = (*stagingFakeRows)(nil)
