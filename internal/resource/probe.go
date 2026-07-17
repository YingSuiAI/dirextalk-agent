package resource

import (
	"context"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/google/uuid"
)

const (
	minimumProbeInterval = 5 * time.Second
	maximumProbeInterval = 24 * time.Hour
	probePersistTimeout  = 5 * time.Second
)

type ProbeMonitorKind string

const (
	// ProbeMonitorService is the original deployment-wide liveness/readiness/
	// semantic suite and remains the sole source of the public health summary.
	ProbeMonitorService ProbeMonitorKind = "service"
	// ProbeMonitorPublicEntry is the private, device-approved public-route
	// readiness witness. It must not replace service evidence or drive Managed
	// service health on its own.
	ProbeMonitorPublicEntry ProbeMonitorKind = "public_entry"
)

func NormalizeProbeMonitorKind(kind ProbeMonitorKind) (ProbeMonitorKind, bool) {
	switch kind {
	case "", ProbeMonitorService:
		return ProbeMonitorService, true
	case ProbeMonitorPublicEntry:
		return ProbeMonitorPublicEntry, true
	default:
		return "", false
	}
}

// ProbeMonitorRecord is the durable health axis for one Deployment. It does
// not contain Worker execution, outcome, or cloud-resource state.
type ProbeMonitorRecord struct {
	DeploymentID string
	MonitorKind  ProbeMonitorKind
	OwnerID      string
	Suite        healthprobe.SuiteV1
	Interval     time.Duration
	Status       healthprobe.AggregateStatus
	Evidence     *healthprobe.SuiteEvidence
	NextRunAt    time.Time
	Revision     int64
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type ProbeConfigureRequest struct {
	OwnerID          string
	MonitorKind      ProbeMonitorKind
	Suite            healthprobe.SuiteV1
	Interval         time.Duration
	ExpectedRevision int64
}

func (request ProbeConfigureRequest) Validate() error {
	owner := strings.TrimSpace(request.OwnerID)
	monitorKind, validKind := NormalizeProbeMonitorKind(request.MonitorKind)
	if !validKind || owner == "" || owner != request.OwnerID || len(owner) > 255 || security.ContainsLikelySecret(owner) ||
		!validProbeMonitorSuite(monitorKind, request.Suite) || request.Interval < minimumProbeInterval || request.Interval > maximumProbeInterval ||
		request.Interval%time.Second != 0 || request.ExpectedRevision < 0 {
		return ErrInvalid
	}
	return nil
}

// ProbeRepository atomically persists external evidence, the health revision,
// and its event/outbox projection. The opaque evidence value can only be
// produced by the control-plane healthprobe Engine.
type ProbeRepository interface {
	ConfigureProbe(context.Context, ProbeConfigureRequest, time.Time) (ProbeMonitorRecord, error)
	GetProbe(context.Context, string) (ProbeMonitorRecord, error)
	GetProbeMonitor(context.Context, string, ProbeMonitorKind) (ProbeMonitorRecord, error)
	ListDueProbes(context.Context, time.Time, int) ([]ProbeMonitorRecord, error)
	SaveExternalProbe(context.Context, ProbeMonitorRecord, healthprobe.ExternalEvidence, time.Time) (ProbeMonitorRecord, error)
}

type ProbeService struct {
	engine     *healthprobe.Engine
	repository ProbeRepository
	now        func() time.Time
}

func NewProbeService(engine *healthprobe.Engine, repository ProbeRepository) (*ProbeService, error) {
	if engine == nil || repository == nil {
		return nil, ErrInvalid
	}
	return &ProbeService{engine: engine, repository: repository, now: time.Now}, nil
}

func (service *ProbeService) Configure(ctx context.Context, request ProbeConfigureRequest) (ProbeMonitorRecord, error) {
	if service == nil || service.repository == nil || ctx == nil || request.Validate() != nil {
		return ProbeMonitorRecord{}, ErrInvalid
	}
	request.MonitorKind, _ = NormalizeProbeMonitorKind(request.MonitorKind)
	return service.repository.ConfigureProbe(ctx, request, service.now().UTC())
}

// RunStored reloads the durable definition before each run. SaveExternalProbe
// uses that revision as a fence, so concurrent or late observations cannot
// overwrite newer evidence.
func (service *ProbeService) RunStored(ctx context.Context, deploymentID string) (ProbeMonitorRecord, error) {
	return service.RunStoredMonitor(ctx, deploymentID, ProbeMonitorService)
}

func (service *ProbeService) RunStoredMonitor(ctx context.Context, deploymentID string, monitorKind ProbeMonitorKind) (ProbeMonitorRecord, error) {
	normalizedKind, validKind := NormalizeProbeMonitorKind(monitorKind)
	if service == nil || service.repository == nil || service.engine == nil || ctx == nil || !validKind || !validProbeUUID(deploymentID) {
		return ProbeMonitorRecord{}, ErrInvalid
	}
	record, err := service.repository.GetProbeMonitor(ctx, deploymentID, normalizedKind)
	if err != nil {
		return ProbeMonitorRecord{}, err
	}
	trusted, err := service.engine.RunExternalSuite(ctx, record.Suite)
	if err != nil {
		return ProbeMonitorRecord{}, err
	}
	// Cancellation is a health result, not permission to silently discard it.
	// The detached context is bounded and performs no provider/cloud mutation.
	persistContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), probePersistTimeout)
	defer cancel()
	return service.repository.SaveExternalProbe(persistContext, record, trusted, service.now().UTC())
}

// ResumeDue is the Agent restart recovery entry point.
func (service *ProbeService) ResumeDue(ctx context.Context, limit int) ([]ProbeMonitorRecord, error) {
	if service == nil || service.repository == nil || ctx == nil || limit < 1 || limit > 256 {
		return nil, ErrInvalid
	}
	due, err := service.repository.ListDueProbes(ctx, service.now().UTC(), limit)
	if err != nil {
		return nil, err
	}
	completed := make([]ProbeMonitorRecord, 0, len(due))
	for _, record := range due {
		updated, runErr := service.RunStoredMonitor(ctx, record.DeploymentID, record.MonitorKind)
		if runErr != nil {
			return completed, runErr
		}
		completed = append(completed, updated)
	}
	return completed, nil
}

func (record ProbeMonitorRecord) Validate() error {
	owner := strings.TrimSpace(record.OwnerID)
	monitorKind, validKind := NormalizeProbeMonitorKind(record.MonitorKind)
	if !validKind || !validProbeUUID(record.DeploymentID) || owner == "" || owner != record.OwnerID || len(owner) > 255 || security.ContainsLikelySecret(owner) ||
		!validProbeMonitorSuite(monitorKind, record.Suite) || record.Interval < minimumProbeInterval || record.Interval > maximumProbeInterval ||
		record.Interval%time.Second != 0 || record.NextRunAt.IsZero() || record.Revision < 1 ||
		record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() || record.UpdatedAt.Before(record.CreatedAt) {
		return ErrInvalid
	}
	if record.Suite.Probes[0].Binding.DeploymentID != record.DeploymentID {
		return ErrInvalid
	}
	if record.Evidence == nil {
		if record.Status != healthprobe.AggregatePending {
			return ErrInvalid
		}
		return nil
	}
	if record.Status != record.Evidence.Status {
		return ErrInvalid
	}
	if healthprobe.ValidateSuiteEvidence(record.Suite, *record.Evidence) != nil {
		return ErrInvalid
	}
	return nil
}

func validProbeUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}

func validProbeMonitorSuite(kind ProbeMonitorKind, suite healthprobe.SuiteV1) bool {
	if suite.Validate() != nil {
		return false
	}
	if kind != ProbeMonitorPublicEntry {
		return true
	}
	return len(suite.Probes) == 1 &&
		suite.Probes[0].Purpose == healthprobe.PurposeReadiness &&
		suite.Probes[0].Protocol == healthprobe.ProtocolHTTPS &&
		suite.Probes[0].ExpectedStatusCode == 200
}

func cloneProbeMonitor(record ProbeMonitorRecord) ProbeMonitorRecord {
	record.Suite.Probes = append([]healthprobe.SpecV1(nil), record.Suite.Probes...)
	if record.Evidence != nil {
		value := *record.Evidence
		value.Probes = append([]healthprobe.ProbeEvidence(nil), value.Probes...)
		for index := range value.Probes {
			value.Probes[index].Attempts = append([]healthprobe.AttemptEvidence(nil), value.Probes[index].Attempts...)
		}
		record.Evidence = &value
	}
	return record
}
