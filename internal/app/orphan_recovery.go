package app

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/YingSuiAI/dirextalk-agent/internal/store/postgres"
	"github.com/google/uuid"
)

const orphanRecoveryBatchSize = 64

var errOrphanRecoveryRunning = errors.New("orphan recovery controller is already running")

// orphanRecoveryStateStore owns only durable scheduling, retry, and alert
// facts. It never supplies an authorization decision for a provider object.
type orphanRecoveryStateStore interface {
	ClaimDueOrphanRecoveryControllers(context.Context, time.Time, time.Time, int) ([]postgres.OrphanRecoveryControllerRecord, error)
	ConfirmActiveOrphanRecoveryConnection(context.Context, string, string, int64, int64) (cloudapp.Connection, error)
	RecordOrphanRecoverySuccess(context.Context, string, int64, time.Time, time.Time) (postgres.OrphanRecoveryControllerRecord, error)
	RecordOrphanRecoveryFailure(context.Context, string, int64, time.Time, time.Time, postgres.OrphanRecoveryErrorCode) (postgres.OrphanRecoveryControllerRecord, error)
}

type orphanOwnedRecoverer interface {
	RecoverOwned(context.Context, string, string) ([]resource.ResourceV1, error)
}

type orphanRecoveryServiceFactory interface {
	ForConnection(context.Context, cloudapp.Connection) (orphanOwnedRecoverer, error)
}

type orphanRecoveryProviderFactory interface {
	Provider(context.Context, cloudapp.Connection) (resource.Provider, error)
}

// orphanRecoveryResourceFactory constructs the existing Resource Service from
// a Connection-scoped typed provider. RecoverOwned only calls ListOwned and
// ImportOrphan, so the intentionally inert mirror is never a source of cloud
// inventory or authorization.
type orphanRecoveryResourceFactory struct {
	repository resource.Repository
	providers  orphanRecoveryProviderFactory
}

func (factory orphanRecoveryResourceFactory) ForConnection(ctx context.Context, connection cloudapp.Connection) (orphanOwnedRecoverer, error) {
	if factory.repository == nil || factory.providers == nil {
		return nil, cloudapp.ErrUnavailable
	}
	provider, err := factory.providers.Provider(ctx, connection)
	if err != nil {
		return nil, err
	}
	service, err := resource.NewService(factory.repository, provider, orphanRecoveryInertMirror{})
	if err != nil {
		return nil, cloudapp.ErrUnavailable
	}
	return service, nil
}

// orphanRecoveryInertMirror exists only because Resource Service has one
// constructor for provisioning and recovery. RecoverOwned never invokes it;
// keeping it inert makes it impossible for this controller to use DynamoDB as
// a recovery inventory or authorization source.
type orphanRecoveryInertMirror struct{}

func (orphanRecoveryInertMirror) Put(context.Context, resource.Manifest) error {
	return cloudapp.ErrInvalid
}
func (orphanRecoveryInertMirror) Get(context.Context, string) (resource.Manifest, error) {
	return resource.Manifest{}, resource.ErrNotFound
}
func (orphanRecoveryInertMirror) ListExpired(context.Context, time.Time) ([]resource.Manifest, error) {
	return nil, cloudapp.ErrInvalid
}

type orphanRecoveryController struct {
	agentInstanceID string
	states          orphanRecoveryStateStore
	services        orphanRecoveryServiceFactory
	pollInterval    time.Duration
	backoffMin      time.Duration
	backoffMax      time.Duration
	claimLease      time.Duration
	now             func() time.Time

	cycleMu sync.Mutex
	stateMu sync.Mutex
	running bool
}

func newOrphanRecoveryController(
	agentInstanceID string,
	states orphanRecoveryStateStore,
	services orphanRecoveryServiceFactory,
	pollInterval, backoffMin, backoffMax, claimLease time.Duration,
	now func() time.Time,
) (*orphanRecoveryController, error) {
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed == uuid.Nil || parsed.String() != agentInstanceID || states == nil || services == nil || now == nil ||
		pollInterval <= 0 || pollInterval > 5*time.Minute || backoffMin <= 0 || backoffMin > backoffMax || backoffMax > 30*time.Minute ||
		claimLease < pollInterval || claimLease > 30*time.Minute {
		return nil, cloudapp.ErrInvalid
	}
	return &orphanRecoveryController{
		agentInstanceID: agentInstanceID, states: states, services: services, pollInterval: pollInterval,
		backoffMin: backoffMin, backoffMax: backoffMax, claimLease: claimLease, now: now,
	}, nil
}

// RunOnce persists provider failures as retryable controller state and returns
// only state-store failures. This lets startup and the long-running loop stay
// available during a transient STS/provider outage or when no Connection is
// active.
func (controller *orphanRecoveryController) RunOnce(ctx context.Context) error {
	if controller == nil || controller.states == nil || controller.services == nil || controller.now == nil || ctx == nil {
		return cloudapp.ErrInvalid
	}
	controller.cycleMu.Lock()
	defer controller.cycleMu.Unlock()
	now := controller.now().UTC()
	if now.IsZero() {
		return cloudapp.ErrInvalid
	}
	controllers, err := controller.states.ClaimDueOrphanRecoveryControllers(ctx, now, now.Add(controller.claimLease), orphanRecoveryBatchSize)
	if err != nil {
		return err
	}
	var result error
	for _, state := range controllers {
		if err := controller.recoverController(ctx, now, state); err != nil {
			if ctx.Err() != nil {
				return errors.Join(result, ctx.Err())
			}
			if !errors.Is(err, cloudapp.ErrRevisionConflict) {
				result = errors.Join(result, err)
			}
		}
	}
	return result
}

func (controller *orphanRecoveryController) recoverController(ctx context.Context, now time.Time, state postgres.OrphanRecoveryControllerRecord) error {
	// Re-read the exact claimed Connection immediately before constructing any
	// AWS client. A claim is only scheduling evidence; a degraded/revised
	// Connection must never result in even a read-only AWS discovery call.
	connection, err := controller.states.ConfirmActiveOrphanRecoveryConnection(
		ctx, state.Connection.ConnectionID, state.Connection.OwnerID, state.Revision, state.Connection.Revision,
	)
	if err == nil {
		recoverer, factoryErr := controller.services.ForConnection(ctx, connection)
		err = factoryErr
		if err == nil {
			_, err = recoverer.RecoverOwned(ctx, controller.agentInstanceID, connection.OwnerID)
		}
	}
	if err == nil {
		_, saveErr := controller.states.RecordOrphanRecoverySuccess(
			ctx, state.Connection.ConnectionID, state.Revision, now, now.Add(controller.pollInterval),
		)
		return saveErr
	}
	// The actual provider error is intentionally not persisted, returned in an
	// event, or used as an alert summary. Only this small fixed code survives.
	code := classifyOrphanRecoveryFailure(err)
	_, saveErr := controller.states.RecordOrphanRecoveryFailure(
		ctx, state.Connection.ConnectionID, state.Revision, now,
		now.Add(orphanRecoveryBackoff(state.Attempt+1, controller.backoffMin, controller.backoffMax)), code,
	)
	return saveErr
}

func (controller *orphanRecoveryController) Run(ctx context.Context) error {
	if controller == nil || ctx == nil {
		return cloudapp.ErrInvalid
	}
	controller.stateMu.Lock()
	if controller.running {
		controller.stateMu.Unlock()
		return errOrphanRecoveryRunning
	}
	controller.running = true
	controller.stateMu.Unlock()
	defer func() {
		controller.stateMu.Lock()
		controller.running = false
		controller.stateMu.Unlock()
	}()

	ticker := time.NewTicker(controller.pollInterval)
	defer ticker.Stop()
	for {
		// Every failure is represented by the durable state record when possible.
		// It must never take down the Controller loop just because AWS/STS is
		// temporarily unavailable.
		_ = controller.RunOnce(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func orphanRecoveryBackoff(attempt int, minimum, maximum time.Duration) time.Duration {
	if attempt <= 1 {
		return minimum
	}
	delay := minimum
	for index := 1; index < attempt && delay < maximum; index++ {
		if delay > maximum/2 {
			return maximum
		}
		delay *= 2
	}
	return delay
}

func classifyOrphanRecoveryFailure(err error) postgres.OrphanRecoveryErrorCode {
	switch {
	case errors.Is(err, resource.ErrInvalid):
		return postgres.OrphanRecoveryErrorInvalid
	case errors.Is(err, cloudapp.ErrUnavailable):
		return postgres.OrphanRecoveryErrorProviderUnavailable
	default:
		return postgres.OrphanRecoveryErrorUnavailable
	}
}
