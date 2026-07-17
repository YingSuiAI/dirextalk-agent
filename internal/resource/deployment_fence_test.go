package resource

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// fencedResourceRepository deliberately uses a non-reentrant gate. The tests
// therefore prove Service uses the private lifecycle bodies while a fence is
// held, rather than recursively re-entering a public fenced method.
type fencedResourceRepository struct {
	*fakeResourceRepository

	gate sync.Mutex

	mu        sync.Mutex
	held      map[string]int
	entered   []string
	requested chan string
	fenceErr  error
}

func newFencedResourceRepository(repository *fakeResourceRepository) *fencedResourceRepository {
	return &fencedResourceRepository{
		fakeResourceRepository: repository,
		held:                   make(map[string]int),
		requested:              make(chan string, 8),
	}
}

func (repository *fencedResourceRepository) WithDeploymentFence(ctx context.Context, deploymentID string, run func(context.Context) error) error {
	select {
	case repository.requested <- deploymentID:
	default:
	}
	repository.gate.Lock()
	defer repository.gate.Unlock()

	repository.mu.Lock()
	repository.held[deploymentID]++
	repository.entered = append(repository.entered, deploymentID)
	fenceErr := repository.fenceErr
	repository.mu.Unlock()
	defer func() {
		repository.mu.Lock()
		repository.held[deploymentID]--
		repository.mu.Unlock()
	}()
	if fenceErr != nil {
		return fenceErr
	}
	return run(ctx)
}

func (repository *fencedResourceRepository) isHeld(deploymentID string) bool {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return repository.held[deploymentID] > 0
}

func (repository *fencedResourceRepository) enteredDeployments() []string {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	return append([]string(nil), repository.entered...)
}

type fenceAwareProvider struct {
	*fakeProvider

	beforeCreate   func() error
	beforeReadBack func() error
}

func (provider *fenceAwareProvider) Create(ctx context.Context, request ProviderCreateRequest) (ProviderObservation, error) {
	if provider.beforeCreate != nil {
		if err := provider.beforeCreate(); err != nil {
			return ProviderObservation{}, err
		}
	}
	return provider.fakeProvider.Create(ctx, request)
}

func (provider *fenceAwareProvider) ReadBack(ctx context.Context, kind Type, providerID, region string) (ProviderObservation, error) {
	if provider.beforeReadBack != nil {
		if err := provider.beforeReadBack(); err != nil {
			return ProviderObservation{}, err
		}
	}
	return provider.fakeProvider.ReadBack(ctx, kind, providerID, region)
}

type fencedResourceFixture struct {
	resourceFixture
	fencer   *fencedResourceRepository
	provider *fenceAwareProvider
}

func newFencedResourceFixture(t *testing.T) fencedResourceFixture {
	t.Helper()
	fixture := newResourceFixture(t)
	fencer := newFencedResourceRepository(fixture.repository)
	provider := &fenceAwareProvider{fakeProvider: fixture.provider}
	service, err := NewService(fencer, provider, fixture.mirror)
	if err != nil {
		t.Fatal(err)
	}
	service.now = fixture.service.now
	fixture.service = service
	return fencedResourceFixture{resourceFixture: fixture, fencer: fencer, provider: provider}
}

func requireFenceRequest(t *testing.T, fencer *fencedResourceRepository, deploymentID string) {
	t.Helper()
	select {
	case got := <-fencer.requested:
		if got != deploymentID {
			t.Fatalf("fence deployment=%q, want %q", got, deploymentID)
		}
	case <-time.After(time.Second):
		t.Fatal("expected deployment fence request")
	}
}

func managedContractFor(fixture resourceFixture) ManagedContractV1 {
	return ManagedContractV1{
		DeploymentID: fixture.deploymentID, OwnerID: fixture.ownerID, AcceptanceApprovalID: uuid.NewString(),
		Currency: "USD", CostAlertAmountMinor: 5_000, MonitorRef: "monitor://service/health",
		MaintenanceRef: "runbook://service/maintenance", RestartRef: "runbook://service/restart",
		BackupRef: "runbook://service/backup", RestoreRef: "runbook://service/restore",
		UpgradeRef: "runbook://service/upgrade", RollbackRef: "runbook://service/rollback",
		DestroyRef: "runbook://service/destroy", AcceptedAt: fixture.now,
	}
}

func TestDeploymentFenceSerializesProvisionAndScheduleDestroy(t *testing.T) {
	fixture := newFencedResourceFixture(t)
	spec := fixture.spec(TypeEBS, "fenced-volume")
	createStarted := make(chan struct{})
	releaseCreate := make(chan struct{})
	fixture.provider.beforeCreate = func() error {
		if !fixture.fencer.isHeld(spec.DeploymentID) {
			return errors.New("provider Create ran outside deployment fence")
		}
		close(createStarted)
		<-releaseCreate
		return nil
	}
	fixture.provider.beforeReadBack = func() error {
		if !fixture.fencer.isHeld(spec.DeploymentID) {
			return errors.New("provider ReadBack ran outside deployment fence")
		}
		return nil
	}

	type provisionResult struct {
		resource ResourceV1
		err      error
	}
	provisionDone := make(chan provisionResult, 1)
	go func() {
		created, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
		provisionDone <- provisionResult{resource: created, err: err}
	}()
	select {
	case <-createStarted:
	case <-time.After(time.Second):
		t.Fatal("provider Create did not begin")
	}
	requireFenceRequest(t, fixture.fencer, spec.DeploymentID)

	type destroyResult struct {
		resources []ResourceV1
		err       error
	}
	destroyDone := make(chan destroyResult, 1)
	go func() {
		resources, err := fixture.service.ScheduleDestroy(context.Background(), spec.DeploymentID, fixture.ownerID)
		destroyDone <- destroyResult{resources: resources, err: err}
	}()
	requireFenceRequest(t, fixture.fencer, spec.DeploymentID)
	if entered := fixture.fencer.enteredDeployments(); len(entered) != 1 {
		t.Fatalf("ScheduleDestroy acquired fence during provider lifecycle: %v", entered)
	}
	stored, err := fixture.repository.Get(context.Background(), spec.ResourceID)
	if err != nil || stored.State != StateProvisioning {
		t.Fatalf("destroy changed provision before fence handoff: resource=%+v error=%v", stored, err)
	}

	close(releaseCreate)
	created := <-provisionDone
	if created.err != nil || created.resource.State != StateActive {
		t.Fatalf("Provision() resource=%+v error=%v", created.resource, created.err)
	}
	destroyed := <-destroyDone
	if destroyed.err != nil || len(destroyed.resources) != 1 || destroyed.resources[0].State != StateDestroyScheduled {
		t.Fatalf("ScheduleDestroy() resources=%+v error=%v", destroyed.resources, destroyed.err)
	}
	if entered := fixture.fencer.enteredDeployments(); len(entered) != 2 || entered[0] != spec.DeploymentID || entered[1] != spec.DeploymentID {
		t.Fatalf("unexpected deployment fence sequence: %v", entered)
	}
}

func TestScheduleDestroyFencesProvisioningIntentAndPreventsReactivation(t *testing.T) {
	fixture := newFencedResourceFixture(t)
	spec := fixture.spec(TypeEBS, "pending-volume")
	expired := fixture.createAuthorization()
	expired.ApprovalExpiresAt = fixture.now
	provisioning, err := fixture.service.Provision(context.Background(), spec, expired)
	if !errors.Is(err, ErrCreateAuthorizationExpired) || provisioning.State != StateProvisioning {
		t.Fatalf("Provision() resource=%+v error=%v, want persisted provisioning intent", provisioning, err)
	}
	requireFenceRequest(t, fixture.fencer, spec.DeploymentID)

	scheduled, err := fixture.service.ScheduleDestroy(context.Background(), spec.DeploymentID, fixture.ownerID)
	if err != nil || len(scheduled) != 1 || scheduled[0].State != StateDestroyScheduled {
		t.Fatalf("ScheduleDestroy() resources=%+v error=%v", scheduled, err)
	}
	requireFenceRequest(t, fixture.fencer, spec.DeploymentID)
	retry, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
	if !errors.Is(err, ErrDestroyBlocked) || retry.State != StateDestroyScheduled || fixture.provider.createCount != 0 {
		t.Fatalf("destroyed intent reactivated: resource=%+v error=%v creates=%d", retry, err, fixture.provider.createCount)
	}
	requireFenceRequest(t, fixture.fencer, spec.DeploymentID)
}

func TestDeploymentFencePreservesProviderErrorAndManagedSemantics(t *testing.T) {
	t.Run("provider error remains observable", func(t *testing.T) {
		fixture := newFencedResourceFixture(t)
		spec := fixture.spec(TypeEBS, "failed-volume")
		providerErr := errors.New("provider create failed")
		fixture.provider.beforeCreate = func() error {
			if !fixture.fencer.isHeld(spec.DeploymentID) {
				return fmt.Errorf("provider error path escaped deployment fence")
			}
			return providerErr
		}

		created, err := fixture.service.Provision(context.Background(), spec, fixture.createAuthorization())
		if !errors.Is(err, providerErr) || created.State != StateProvisioning {
			t.Fatalf("Provision() resource=%+v error=%v", created, err)
		}
		requireFenceRequest(t, fixture.fencer, spec.DeploymentID)
		if fixture.fencer.isHeld(spec.DeploymentID) {
			t.Fatal("deployment fence was not released after provider error")
		}
	})

	t.Run("managed deployment remains fail closed", func(t *testing.T) {
		fixture := newFencedResourceFixture(t)
		created, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEBS, "managed-volume"), fixture.createAuthorization())
		if err != nil {
			t.Fatal(err)
		}
		requireFenceRequest(t, fixture.fencer, fixture.deploymentID)
		if _, _, err := fixture.service.AcceptManaged(context.Background(), managedContractFor(fixture.resourceFixture)); err != nil {
			t.Fatal(err)
		}

		_, err = fixture.service.ScheduleDestroy(context.Background(), fixture.deploymentID, fixture.ownerID)
		if !errors.Is(err, ErrManaged) {
			t.Fatalf("ScheduleDestroy() error=%v, want ErrManaged", err)
		}
		requireFenceRequest(t, fixture.fencer, fixture.deploymentID)
		stored, getErr := fixture.repository.Get(context.Background(), created.ResourceID)
		if getErr != nil || stored.State != StateRetainedManaged {
			t.Fatalf("managed resource changed by ScheduleDestroy: resource=%+v error=%v", stored, getErr)
		}
	})
}
