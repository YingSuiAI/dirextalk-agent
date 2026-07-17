package app

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/entrypoint"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
)

const (
	entrypointHealthProbeInterval      = time.Minute
	entrypointHealthProbeTimeoutMillis = uint32(5_000)
	entrypointHealthProbeAttempts      = 2
)

var (
	errEntrypointHealthInvalid     = errors.New("entrypoint health scope is invalid")
	errEntrypointHealthUnavailable = errors.New("entrypoint health monitor is unavailable")
)

// entrypointHealthState is deliberately smaller than the ProbeService health
// axis. Entry execution only needs to know whether independently collected
// evidence has verified the device-approved public route; a failed probe stays
// pending verification rather than becoming a successful service declaration.
type entrypointHealthState string

const (
	entrypointHealthPending entrypointHealthState = "pending_verification"
	entrypointHealthHealthy entrypointHealthState = "healthy"
)

// entrypointHealthResult is safe for the entry executor's durable operation
// state: it intentionally contains neither the public endpoint nor transport
// diagnostics. Detailed evidence remains in the health monitor's protected
// persistence/projection path.
type entrypointHealthResult struct {
	State    entrypointHealthState
	Revision int64
}

type entrypointProbeRunner interface {
	Configure(context.Context, resource.ProbeConfigureRequest) (resource.ProbeMonitorRecord, error)
	RunStored(context.Context, string) (resource.ProbeMonitorRecord, error)
}

// entrypointProbeReader is intentionally narrower than resource.ProbeRepository.
// The adapter can inspect an existing monitor only to fence its configuration;
// it cannot write evidence or synthesize an external health result.
type entrypointProbeReader interface {
	GetProbe(context.Context, string) (resource.ProbeMonitorRecord, error)
}

// entrypointHealthProbeAdapter turns a separately approved public-entry scope
// into one external readiness monitor. It never accepts an endpoint from a
// Worker, a log, a resource ID, or caller input: its sole target source is the
// signed certificate hostname plus signed no-credential health path.
type entrypointHealthProbeAdapter struct {
	probes   entrypointProbeRunner
	monitors entrypointProbeReader
	interval time.Duration
}

func newEntrypointHealthProbeAdapter(probes entrypointProbeRunner, monitors entrypointProbeReader) (*entrypointHealthProbeAdapter, error) {
	if probes == nil || monitors == nil {
		return nil, errEntrypointHealthInvalid
	}
	return &entrypointHealthProbeAdapter{probes: probes, monitors: monitors, interval: entrypointHealthProbeInterval}, nil
}

// Verify is the narrow entry-executor seam. An unhealthy yet successfully
// persisted external observation is a stable false result, not an error and
// never a successful service declaration.
func (adapter *entrypointHealthProbeAdapter) Verify(ctx context.Context, plan entrypoint.PlanV1) (bool, error) {
	result, err := adapter.ConfigureAndRun(ctx, plan)
	if err != nil {
		return false, err
	}
	return result.State == entrypointHealthHealthy, nil
}

// ConfigureAndRun atomically uses the persisted monitor definition as the
// evidence source. It makes at most two attempts across a narrow revision race; all other
// provider/store detail is deliberately reduced to a stable safe error.
func (adapter *entrypointHealthProbeAdapter) ConfigureAndRun(ctx context.Context, plan entrypoint.PlanV1) (entrypointHealthResult, error) {
	if adapter == nil || adapter.probes == nil || adapter.monitors == nil || ctx == nil || adapter.interval < 5*time.Second || adapter.interval > 24*time.Hour || adapter.interval%time.Second != 0 {
		return entrypointHealthResult{}, errEntrypointHealthInvalid
	}
	suite, err := entrypointExternalHealthSuite(plan)
	if err != nil {
		return entrypointHealthResult{}, err
	}

	for attempt := 0; attempt < entrypointHealthProbeAttempts; attempt++ {
		if _, err := adapter.configure(ctx, plan.Scope.OwnerID, suite); err != nil {
			if errors.Is(err, resource.ErrRevisionConflict) {
				continue
			}
			return entrypointHealthResult{}, safeEntrypointHealthError(ctx, err)
		}
		record, err := adapter.probes.RunStored(ctx, plan.Scope.Worker.DeploymentID)
		if err != nil {
			if errors.Is(err, resource.ErrRevisionConflict) || errors.Is(err, resource.ErrNotFound) {
				continue
			}
			return entrypointHealthResult{}, safeEntrypointHealthError(ctx, err)
		}
		result, resultErr := entrypointHealthResultFor(record, plan.Scope.OwnerID, suite)
		if resultErr != nil {
			return entrypointHealthResult{}, resultErr
		}
		return result, nil
	}
	return entrypointHealthResult{}, errEntrypointHealthUnavailable
}

func (adapter *entrypointHealthProbeAdapter) configure(ctx context.Context, ownerID string, suite healthprobe.SuiteV1) (resource.ProbeMonitorRecord, error) {
	deploymentID := suite.Probes[0].Binding.DeploymentID
	current, err := adapter.monitors.GetProbe(ctx, deploymentID)
	if errors.Is(err, resource.ErrNotFound) {
		return adapter.probes.Configure(ctx, resource.ProbeConfigureRequest{OwnerID: ownerID, Suite: suite, Interval: adapter.interval})
	}
	if err != nil {
		return resource.ProbeMonitorRecord{}, err
	}
	if !entrypointMonitorMatchesBinding(current, ownerID, suite) {
		return resource.ProbeMonitorRecord{}, errEntrypointHealthInvalid
	}
	if current.Interval == adapter.interval && reflect.DeepEqual(current.Suite, suite) {
		return current, nil
	}
	return adapter.probes.Configure(ctx, resource.ProbeConfigureRequest{
		OwnerID: ownerID, Suite: suite, Interval: adapter.interval, ExpectedRevision: current.Revision,
	})
}

func entrypointExternalHealthSuite(plan entrypoint.PlanV1) (healthprobe.SuiteV1, error) {
	if plan.Validate() != nil || plan.Status != entrypoint.PlanApproved {
		return healthprobe.SuiteV1{}, errEntrypointHealthInvalid
	}
	scope := entrypoint.NormalizeScope(plan.Scope)
	if scope.Validate() != nil || scope.Health.ExpectedStatusCode != 200 || !scope.Health.NoCredentialRoute {
		return healthprobe.SuiteV1{}, errEntrypointHealthInvalid
	}
	// Scope validation fixes the DNS hostname and rejects query/fragment or
	// secret-like health paths; healthprobe then rejects URL authority/options
	// and its network transport independently rejects private DNS answers.
	// Concatenating only these two signed fields preserves the canonical
	// https://hostname/path target and leaves no surface for a Worker-provided
	// address, header, body, or request option.
	spec, err := healthprobe.Bind(healthprobe.SpecV1{
		SchemaVersion: healthprobe.SchemaV1,
		Binding: healthprobe.BindingV1{
			DeploymentID: scope.Worker.DeploymentID,
			PlanHash:     scope.Worker.OriginalPlanHash,
			RecipeDigest: scope.Recipe.RecipeDigest,
		},
		Purpose:            healthprobe.PurposeReadiness,
		Protocol:           healthprobe.ProtocolHTTPS,
		Target:             "https://" + scope.Certificate.Hostname + scope.Health.Path,
		TimeoutMillis:      entrypointHealthProbeTimeoutMillis,
		MaxAttempts:        1,
		ExpectedStatusCode: 200,
	})
	if err != nil {
		return healthprobe.SuiteV1{}, errEntrypointHealthInvalid
	}
	suite := healthprobe.SuiteV1{SchemaVersion: healthprobe.SuiteSchemaV1, Probes: []healthprobe.SpecV1{spec}}
	if suite.Validate() != nil {
		return healthprobe.SuiteV1{}, errEntrypointHealthInvalid
	}
	return suite, nil
}

func entrypointMonitorMatchesBinding(record resource.ProbeMonitorRecord, ownerID string, expected healthprobe.SuiteV1) bool {
	if record.Validate() != nil || record.OwnerID != ownerID || record.DeploymentID != expected.Probes[0].Binding.DeploymentID || len(record.Suite.Probes) == 0 {
		return false
	}
	expectedBinding := expected.Probes[0].Binding
	for _, spec := range record.Suite.Probes {
		if spec.Binding.DeploymentID != expectedBinding.DeploymentID || spec.Binding.PlanHash != expectedBinding.PlanHash || spec.Binding.RecipeDigest != expectedBinding.RecipeDigest {
			return false
		}
	}
	return true
}

func entrypointHealthResultFor(record resource.ProbeMonitorRecord, ownerID string, expected healthprobe.SuiteV1) (entrypointHealthResult, error) {
	if !entrypointMonitorMatchesBinding(record, ownerID, expected) || record.Interval != entrypointHealthProbeInterval || !reflect.DeepEqual(record.Suite, expected) {
		return entrypointHealthResult{}, errEntrypointHealthInvalid
	}
	if record.Status == healthprobe.AggregateHealthy && record.Evidence != nil && record.Evidence.Healthy {
		return entrypointHealthResult{State: entrypointHealthHealthy, Revision: record.Revision}, nil
	}
	return entrypointHealthResult{State: entrypointHealthPending, Revision: record.Revision}, nil
}

func safeEntrypointHealthError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, errEntrypointHealthInvalid) || errors.Is(err, resource.ErrInvalid) {
		return errEntrypointHealthInvalid
	}
	return errEntrypointHealthUnavailable
}
