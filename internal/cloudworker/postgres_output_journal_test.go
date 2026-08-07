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

func TestPostgresOutputJournalRestartReplayAndCAS(t *testing.T) {
	now := time.Date(2026, 8, 8, 13, 0, 0, 0, time.UTC)
	plan, _, _, source := stagingFixture(t, now)
	if source.Body != nil {
		_ = source.Body.Close()
	}
	execution, err := outputExecutionIdentity(plan)
	if err != nil {
		t.Fatal(err)
	}
	journal := OutputJournalRecord{
		Identity: OutputJournalIdentity{OutputExecutionIdentity: execution, Attempt: 1, LeaseEpoch: 1},
		State:    OutputJournalApproved, Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	db := newFakeOutputJournalDB()
	ledger, _ := newPostgresOutputJournalLedger(db)
	if err = ledger.Ready(t.Context()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing tables readiness=%v", err)
	}
	db.ready = true
	if err = ledger.Ready(t.Context()); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for range 2 {
		go func() {
			<-start
			_, createErr := ledger.EnsureJournal(context.Background(), journal)
			results <- createErr
		}()
	}
	close(start)
	for range 2 {
		if createErr := <-results; createErr != nil {
			t.Fatalf("same journal replay=%v", createErr)
		}
	}
	restarted, _ := newPostgresOutputJournalLedger(db)
	journals, err := restarted.ListJournals(t.Context(), execution)
	if err != nil || len(journals) != 1 || journals[0].Revision != 1 {
		t.Fatalf("restart journals=%+v err=%v", journals, err)
	}
	cleaning := journals[0]
	cleaning.State, cleaning.InventoryAttempts = OutputJournalCleaning, 1
	cleaning.Revision, cleaning.UpdatedAt = 2, now.Add(time.Second)
	if _, err = restarted.CompareAndSwapJournal(t.Context(), cleaning, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.CompareAndSwapJournal(t.Context(), cleaning, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale journal CAS=%v", err)
	}

	observation := outputObservation(execution, "unknown.bin", "unknown-version-1", 16, false, now)
	version := OutputVersionRecord{Observation: observation, State: OutputVersionDiscovered, Revision: 1, CreatedAt: now, UpdatedAt: now}
	if _, err = restarted.DiscoverVersion(t.Context(), version); err != nil {
		t.Fatal(err)
	}
	if replay, replayErr := restarted.DiscoverVersion(t.Context(), version); replayErr != nil || replay.Revision != 1 {
		t.Fatalf("version replay=%+v err=%v", replay, replayErr)
	}
	deleting := version
	deleting.State, deleting.DeleteAttempts = OutputVersionDeleteStarted, 1
	deleting.Revision, deleting.UpdatedAt = 2, now.Add(time.Second)
	if _, err = restarted.CompareAndSwapVersion(t.Context(), deleting, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.CompareAndSwapVersion(t.Context(), deleting, 1); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale version CAS=%v", err)
	}
	versions, err := ledger.ListVersions(t.Context(), execution)
	if err != nil || len(versions) != 1 || versions[0].State != OutputVersionDeleteStarted {
		t.Fatalf("restart versions=%+v err=%v", versions, err)
	}
	encoded, _ := encodeOutputRecord(deleting)
	var decoded OutputVersionRecord
	if err = decodeOutputRecord(append(encoded, []byte(` {"trailing":true}`)...), &decoded); !errors.Is(err, ErrInvalid) {
		t.Fatalf("trailing output JSON accepted: %v", err)
	}
}

type fakeOutputJournalDB struct {
	mu       sync.Mutex
	ready    bool
	journals map[string]fakeOutputRowValue
	versions map[string]fakeOutputRowValue
}

type fakeOutputRowValue struct {
	identityDigest  string
	executionDigest string
	json            []byte
}

func newFakeOutputJournalDB() *fakeOutputJournalDB {
	return &fakeOutputJournalDB{journals: make(map[string]fakeOutputRowValue), versions: make(map[string]fakeOutputRowValue)}
}

func (db *fakeOutputJournalDB) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch sql {
	case insertOutputJournalSQL:
		return db.insert(db.journals, args[0].(string), args[1].(string), args[2].(string), args[22].([]byte))
	case insertOutputVersionSQL:
		return db.insert(db.versions, args[0].(string), args[1].(string), args[2].(string), args[24].([]byte))
	case casOutputJournalSQL:
		stored, ok := db.journals[args[0].(string)]
		if !ok || stored.identityDigest != args[1].(string) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		var current, next OutputJournalRecord
		if decodeOutputRecord(stored.json, &current) != nil || decodeOutputRecord(args[5].([]byte), &next) != nil ||
			current.Revision != args[8].(uint64) || !validOutputJournalTransition(current, next) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		stored.json = append([]byte(nil), args[5].([]byte)...)
		db.journals[args[0].(string)] = stored
		return pgconn.NewCommandTag("UPDATE 1"), nil
	case casOutputVersionSQL:
		stored, ok := db.versions[args[0].(string)]
		if !ok || stored.identityDigest != args[1].(string) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		var current, next OutputVersionRecord
		if decodeOutputRecord(stored.json, &current) != nil || decodeOutputRecord(args[5].([]byte), &next) != nil ||
			current.Revision != args[8].(uint64) || !validOutputVersionTransition(current, next) {
			return pgconn.NewCommandTag("UPDATE 0"), nil
		}
		stored.json = append([]byte(nil), args[5].([]byte)...)
		db.versions[args[0].(string)] = stored
		return pgconn.NewCommandTag("UPDATE 1"), nil
	default:
		return pgconn.CommandTag{}, errors.New("unexpected output journal exec")
	}
}

func (db *fakeOutputJournalDB) insert(target map[string]fakeOutputRowValue, key, identityDigest, executionDigest string, raw []byte) (pgconn.CommandTag, error) {
	if _, exists := target[key]; exists {
		return pgconn.NewCommandTag("INSERT 0 0"), nil
	}
	target[key] = fakeOutputRowValue{identityDigest: identityDigest, executionDigest: executionDigest, json: append([]byte(nil), raw...)}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (db *fakeOutputJournalDB) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	db.mu.Lock()
	defer db.mu.Unlock()
	switch sql {
	case outputJournalReadySQL:
		if db.ready {
			return outputJournalFakeRow{values: []any{PostgresOutputJournalTable, PostgresOutputVersionTable}}
		}
		return outputJournalFakeRow{values: []any{"", ""}}
	case getOutputJournalSQL:
		return db.row(db.journals, args[0].(string), args[1].(string))
	case getOutputVersionSQL:
		return db.row(db.versions, args[0].(string), args[1].(string))
	default:
		return outputJournalFakeRow{err: errors.New("unexpected output journal query row")}
	}
}

func (db *fakeOutputJournalDB) row(target map[string]fakeOutputRowValue, key, digest string) pgx.Row {
	stored, exists := target[key]
	if !exists || stored.identityDigest != digest {
		return outputJournalFakeRow{err: pgx.ErrNoRows}
	}
	return outputJournalFakeRow{values: []any{append([]byte(nil), stored.json...)}}
}

func (db *fakeOutputJournalDB) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	db.mu.Lock()
	defer db.mu.Unlock()
	var target map[string]fakeOutputRowValue
	switch sql {
	case listOutputJournalsSQL:
		target = db.journals
	case listOutputVersionsSQL:
		target = db.versions
	default:
		return nil, errors.New("unexpected output journal query")
	}
	values := make([][]byte, 0)
	for _, stored := range target {
		if stored.executionDigest == args[0].(string) {
			values = append(values, append([]byte(nil), stored.json...))
		}
	}
	sort.Slice(values, func(i, j int) bool { return string(values[i]) < string(values[j]) })
	return &stagingFakeRows{values: values, index: -1}, nil
}

type outputJournalFakeRow struct {
	values []any
	err    error
}

func (row outputJournalFakeRow) Scan(dest ...any) error {
	if row.err != nil {
		return row.err
	}
	if len(dest) != len(row.values) {
		return errors.New("unexpected output journal scan")
	}
	for index, target := range dest {
		switch value := target.(type) {
		case *string:
			*value = row.values[index].(string)
		case *[]byte:
			*value = append((*value)[:0], row.values[index].([]byte)...)
		default:
			return errors.New("unsupported output journal scan")
		}
	}
	return nil
}

var _ outputJournalDB = (*fakeOutputJournalDB)(nil)
