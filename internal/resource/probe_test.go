package resource

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/google/uuid"
)

func TestProbeServiceRestartRecoverySeparatedEvidenceAndRevisionFence(t *testing.T) {
	now := time.Date(2026, 7, 17, 4, 0, 0, 0, time.UTC)
	digest := probeTestDigest("response")
	engine, err := healthprobe.NewEngine(probeTestTransport{digest: digest})
	if err != nil {
		t.Fatal(err)
	}
	repository := &probeMemoryRepository{}
	service, err := NewProbeService(engine, repository)
	if err != nil {
		t.Fatal(err)
	}
	service.now = func() time.Time { return now }
	suite := probeTestSuite(t)
	privateSuite := suite
	privateSuite.Probes = append([]healthprobe.SpecV1(nil), suite.Probes...)
	privateSuite.Probes[0].Target = "https://127.0.0.1/ready"
	if _, err := service.Configure(context.Background(), ProbeConfigureRequest{
		OwnerID: "owner-health", Suite: privateSuite, Interval: time.Minute,
	}); !errors.Is(err, ErrInvalid) || repository.record.Revision != 0 {
		t.Fatalf("private probe was not fail-closed before persistence: record=%+v err=%v", repository.record, err)
	}
	configured, err := service.Configure(context.Background(), ProbeConfigureRequest{
		OwnerID: "owner-health", Suite: suite, Interval: time.Minute,
	})
	if err != nil || configured.Status != healthprobe.AggregatePending || configured.Revision != 1 {
		t.Fatalf("configured=%+v err=%v", configured, err)
	}

	// A new service instance around the same repository models Agent restart.
	restarted, _ := NewProbeService(engine, repository)
	restarted.now = service.now
	completed, err := restarted.ResumeDue(context.Background(), 8)
	if err != nil || len(completed) != 1 {
		t.Fatalf("restart recovery=%+v err=%v", completed, err)
	}
	updated := completed[0]
	if updated.Status != healthprobe.AggregateDegraded || updated.Revision != 2 || updated.Evidence == nil || len(updated.Evidence.Probes) != 2 {
		t.Fatalf("updated monitor=%+v", updated)
	}
	if updated.Evidence.Probes[0].Purpose != healthprobe.PurposeLiveness || updated.Evidence.Probes[1].Purpose != healthprobe.PurposeReadiness {
		t.Fatalf("probe purposes were not persisted separately: %+v", updated.Evidence.Probes)
	}
	for _, evidence := range updated.Evidence.Probes {
		if evidence.Trust != healthprobe.TrustIndependentControlPlane {
			t.Fatalf("unexpected evidence trust %q", evidence.Trust)
		}
	}
	if _, err := repository.SaveExternalProbe(context.Background(), configured, repository.lastEvidence, now.Add(time.Second)); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("late result error=%v", err)
	}
	if _, err := repository.SaveExternalProbe(context.Background(), updated, healthprobe.ExternalEvidence{}, now.Add(time.Second)); !errors.Is(err, healthprobe.ErrInvalidEvidence) {
		t.Fatalf("Worker-local evidence error=%v", err)
	}
}

func probeTestSuite(t *testing.T) healthprobe.SuiteV1 {
	t.Helper()
	deploymentID := uuid.NewString()
	planHash, recipeDigest := probeTestDigest("plan"), probeTestDigest("recipe")
	bind := func(purpose healthprobe.Purpose, target string) healthprobe.SpecV1 {
		spec, err := healthprobe.Bind(healthprobe.SpecV1{
			SchemaVersion: healthprobe.SchemaV1,
			Binding:       healthprobe.BindingV1{DeploymentID: deploymentID, PlanHash: planHash, RecipeDigest: recipeDigest},
			Purpose:       purpose, Protocol: healthprobe.ProtocolHTTPS, Target: target,
			TimeoutMillis: 500, MaxAttempts: 1,
		})
		if err != nil {
			t.Fatal(err)
		}
		return spec
	}
	return healthprobe.SuiteV1{SchemaVersion: healthprobe.SuiteSchemaV1, Probes: []healthprobe.SpecV1{
		bind(healthprobe.PurposeReadiness, "https://service.example.com/ready"),
		bind(healthprobe.PurposeLiveness, "https://service.example.com/live"),
	}}
}

func probeTestDigest(value string) string {
	digest := sha256.Sum256([]byte(value))
	return fmt.Sprintf("sha256:%x", digest[:])
}

type probeTestTransport struct{ digest string }

func (transport probeTestTransport) Probe(_ context.Context, request healthprobe.Request) (healthprobe.Observation, error) {
	status := 200
	if strings.HasSuffix(request.Target, "/ready") {
		status = 503
	}
	return healthprobe.Observation{StatusCode: status, SummaryDigest: transport.digest}, nil
}

type probeMemoryRepository struct {
	record       ProbeMonitorRecord
	lastEvidence healthprobe.ExternalEvidence
}

func (repository *probeMemoryRepository) ConfigureProbe(_ context.Context, request ProbeConfigureRequest, configuredAt time.Time) (ProbeMonitorRecord, error) {
	if request.Validate() != nil || repository.record.Revision != 0 {
		return ProbeMonitorRecord{}, ErrInvalid
	}
	repository.record = ProbeMonitorRecord{
		DeploymentID: request.Suite.Probes[0].Binding.DeploymentID, OwnerID: request.OwnerID,
		Suite: request.Suite, Interval: request.Interval, Status: healthprobe.AggregatePending,
		NextRunAt: configuredAt, Revision: 1, CreatedAt: configuredAt, UpdatedAt: configuredAt,
	}
	return cloneProbeMonitor(repository.record), nil
}

func (repository *probeMemoryRepository) GetProbe(_ context.Context, deploymentID string) (ProbeMonitorRecord, error) {
	if repository.record.DeploymentID != deploymentID {
		return ProbeMonitorRecord{}, ErrNotFound
	}
	return cloneProbeMonitor(repository.record), nil
}

func (repository *probeMemoryRepository) ListDueProbes(_ context.Context, dueAt time.Time, limit int) ([]ProbeMonitorRecord, error) {
	if limit < 1 || repository.record.Revision == 0 || repository.record.NextRunAt.After(dueAt) {
		return nil, nil
	}
	return []ProbeMonitorRecord{cloneProbeMonitor(repository.record)}, nil
}

func (repository *probeMemoryRepository) SaveExternalProbe(_ context.Context, expected ProbeMonitorRecord, trusted healthprobe.ExternalEvidence, completedAt time.Time) (ProbeMonitorRecord, error) {
	if expected.Revision != repository.record.Revision {
		return ProbeMonitorRecord{}, ErrRevisionConflict
	}
	evidence, err := trusted.SnapshotFor(expected.Suite)
	if err != nil {
		return ProbeMonitorRecord{}, err
	}
	if repository.record.Evidence != nil && !evidence.ObservedAt.After(repository.record.Evidence.ObservedAt) {
		return ProbeMonitorRecord{}, ErrStaleProbeEvidence
	}
	repository.lastEvidence = trusted
	repository.record.Status = evidence.Status
	repository.record.Evidence = &evidence
	repository.record.Revision++
	repository.record.UpdatedAt = completedAt
	repository.record.NextRunAt = completedAt.Add(repository.record.Interval)
	return cloneProbeMonitor(repository.record), nil
}
