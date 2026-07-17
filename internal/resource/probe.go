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

// ProbeMonitorRecord is the durable health axis for one Deployment. It does
// not contain Worker execution, outcome, or cloud-resource state.
type ProbeMonitorRecord struct {
	DeploymentID string
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
	Suite            healthprobe.SuiteV1
	Interval         time.Duration
	ExpectedRevision int64
}

func (request ProbeConfigureRequest) Validate() error {
	owner := strings.TrimSpace(request.OwnerID)
	if owner == "" || owner != request.OwnerID || len(owner) > 255 || security.ContainsLikelySecret(owner) ||
		request.Suite.Validate() != nil || request.Interval < minimumProbeInterval || request.Interval > maximumProbeInterval ||
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
	return service.repository.ConfigureProbe(ctx, request, service.now().UTC())
}

// RunStored reloads the durable definition before each run. SaveExternalProbe
// uses that revision as a fence, so concurrent or late observations cannot
// overwrite newer evidence.
func (service *ProbeService) RunStored(ctx context.Context, deploymentID string) (ProbeMonitorRecord, error) {
	if service == nil || service.repository == nil || service.engine == nil || ctx == nil || !validProbeUUID(deploymentID) {
		return ProbeMonitorRecord{}, ErrInvalid
	}
	record, err := service.repository.GetProbe(ctx, deploymentID)
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
		updated, runErr := service.RunStored(ctx, record.DeploymentID)
		if runErr != nil {
			return completed, runErr
		}
		completed = append(completed, updated)
	}
	return completed, nil
}

func (record ProbeMonitorRecord) Validate() error {
	owner := strings.TrimSpace(record.OwnerID)
	if !validProbeUUID(record.DeploymentID) || owner == "" || owner != record.OwnerID || len(owner) > 255 || security.ContainsLikelySecret(owner) ||
		record.Suite.Validate() != nil || record.Interval < minimumProbeInterval || record.Interval > maximumProbeInterval ||
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
