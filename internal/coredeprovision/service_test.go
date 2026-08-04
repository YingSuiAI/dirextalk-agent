package coredeprovision

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
)

type fakeStore struct {
	command Command
	called  int
}

func (s *fakeStore) Deprovision(_ context.Context, command Command, external func(context.Context) error) (Result, error) {
	s.command = command
	s.called++
	if err := external(context.Background()); err != nil {
		return Result{}, err
	}
	return Result{Status: "deprovisioned", DatabasePurged: true, ExternalPurged: true}, nil
}

func TestServiceRequiresExplicitConfirmationAndIdentity(t *testing.T) {
	store := &fakeStore{}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	base := Command{OwnerID: "owner", AccountGeneration: 4, IdempotencyKey: uuid.NewString(), Confirmation: Confirmation}
	if _, err := service.Deprovision(context.Background(), base, func(context.Context) error { return nil }); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	if store.called != 1 || store.command.OwnerID != "owner" || store.command.AccountGeneration != 4 {
		t.Fatalf("identity did not reach durable store: %+v calls=%d", store.command, store.called)
	}
	for name, invalid := range map[string]Command{
		"missing owner":      {AccountGeneration: 4, IdempotencyKey: uuid.NewString(), Confirmation: Confirmation},
		"zero generation":    {OwnerID: "owner", IdempotencyKey: uuid.NewString(), Confirmation: Confirmation},
		"bad key":            {OwnerID: "owner", AccountGeneration: 4, IdempotencyKey: "not-a-uuid", Confirmation: Confirmation},
		"wrong confirmation": {OwnerID: "owner", AccountGeneration: 4, IdempotencyKey: uuid.NewString(), Confirmation: "yes"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := service.Deprovision(context.Background(), invalid, func(context.Context) error { return nil }); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v, want ErrInvalid", err)
			}
		})
	}
}

func TestServicePropagatesExternalPurgeFailure(t *testing.T) {
	service, err := NewService(&fakeStore{})
	if err != nil {
		t.Fatal(err)
	}
	want := errors.New("qdrant unavailable")
	result, err := service.Deprovision(context.Background(), Command{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), Confirmation: Confirmation}, func(context.Context) error { return want })
	if !errors.Is(err, want) {
		t.Fatalf("external error=%v, want %v", err, want)
	}
	if result.ExternalPurged || result.DatabasePurged {
		t.Fatalf("partial external purge reported success: %+v", result)
	}
}

type fenceStateStore struct {
	fenced bool
}

func (s fenceStateStore) Deprovision(context.Context, Command, func(context.Context) error) (Result, error) {
	return Result{}, nil
}
func (s fenceStateStore) HasDeprovisionFence(context.Context) (bool, error) { return s.fenced, nil }

func TestServiceRestoresDurableFenceBeforeAdmission(t *testing.T) {
	service, err := NewService(fenceStateStore{fenced: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RestoreFence(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Enter(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("restored fence admission err=%v, want ErrClosed", err)
	}
}

type fencedPurgeStore struct {
	mu        sync.Mutex
	dbRows    int
	purgeSeen chan struct{}
}

func (s *fencedPurgeStore) Deprovision(_ context.Context, _ Command, external func(context.Context) error) (Result, error) {
	s.mu.Lock()
	s.dbRows = 0
	s.mu.Unlock()
	if s.purgeSeen != nil {
		close(s.purgeSeen)
	}
	if err := external(context.Background()); err != nil {
		return Result{DatabasePurged: true}, err
	}
	return Result{Status: "deprovisioned", DatabasePurged: true, ExternalPurged: true}, nil
}

func TestServicePurgeDrainsAdmittedMutationBeforeDBAndExternalCleanup(t *testing.T) {
	root := t.TempDir()
	qdrantMarker := filepath.Join(root, "qdrant.marker")
	fileMarker := filepath.Join(root, "file.marker")
	if err := os.WriteFile(qdrantMarker, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fileMarker, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := &fencedPurgeStore{dbRows: 1, purgeSeen: make(chan struct{})}
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	release, err := service.Enter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	deprovisionDone := make(chan struct{})
	var result Result
	var deprovisionErr error
	go func() {
		result, deprovisionErr = service.Deprovision(context.Background(), Command{OwnerID: "owner", AccountGeneration: 1, IdempotencyKey: uuid.NewString(), Confirmation: Confirmation}, func(context.Context) error {
			_ = os.Remove(qdrantMarker)
			_ = os.Remove(fileMarker)
			return nil
		})
		close(deprovisionDone)
	}()
	mutationDone := make(chan struct{})
	go func() {
		// This models an already-admitted worker/handler crossing its external
		// side-effect boundary immediately before the purge starts waiting.
		_ = os.WriteFile(qdrantMarker, []byte("new"), 0o600)
		_ = os.WriteFile(fileMarker, []byte("new"), 0o600)
		store.mu.Lock()
		store.dbRows = 1
		store.mu.Unlock()
		close(mutationDone)
	}()
	<-mutationDone
	select {
	case <-store.purgeSeen:
		t.Fatal("external purge crossed an admitted handler before its release")
	default:
	}
	// The explicit release is the deterministic commit point for the admitted
	// handler; the writer cannot reach external purge before this point.
	release()
	<-deprovisionDone
	if deprovisionErr != nil || !result.DatabasePurged || !result.ExternalPurged {
		t.Fatalf("deprovision result=%+v err=%v", result, deprovisionErr)
	}
	if _, err := os.Stat(qdrantMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("qdrant residue=%v", err)
	}
	if _, err := os.Stat(fileMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("filesystem residue=%v", err)
	}
	store.mu.Lock()
	rows := store.dbRows
	store.mu.Unlock()
	if rows != 0 {
		t.Fatalf("database residue=%d", rows)
	}
	if _, err := service.Enter(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("new mutation after purge err=%v", err)
	}
}
