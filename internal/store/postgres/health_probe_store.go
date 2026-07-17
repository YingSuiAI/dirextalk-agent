package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudstatus"
	"github.com/YingSuiAI/dirextalk-agent/internal/healthprobe"
	"github.com/YingSuiAI/dirextalk-agent/internal/resource"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type HealthProbeStore struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
}

var _ resource.ProbeRepository = (*HealthProbeStore)(nil)
var _ cloudstatus.HealthReader = (*HealthProbeStore)(nil)

func (store *Store) NewHealthProbeStore() (*HealthProbeStore, error) {
	if store == nil || store.pool == nil {
		return nil, resource.ErrInvalid
	}
	return &HealthProbeStore{pool: store.pool, instanceID: store.instanceID}, nil
}

func (store *HealthProbeStore) ConfigureProbe(ctx context.Context, request resource.ProbeConfigureRequest, configuredAt time.Time) (resource.ProbeMonitorRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || request.Validate() != nil || configuredAt.IsZero() {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}
	configuredAt = configuredAt.UTC()
	monitorKind, _ := resource.NormalizeProbeMonitorKind(request.MonitorKind)
	request.MonitorKind = monitorKind
	deploymentID, _ := uuid.Parse(request.Suite.Probes[0].Binding.DeploymentID)
	suiteJSON, err := json.Marshal(request.Suite)
	if err != nil {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return resource.ProbeMonitorRecord{}, fmt.Errorf("begin health probe configuration: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	ownerID, planHash, recipeDigest, err := loadHealthBinding(ctx, tx, store.instanceID, deploymentID)
	if err != nil {
		return resource.ProbeMonitorRecord{}, err
	}
	first := request.Suite.Probes[0].Binding
	if ownerID != request.OwnerID || first.PlanHash != planHash || first.RecipeDigest != recipeDigest {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}

	current, loadErr := loadHealthMonitor(ctx, tx, store.instanceID, deploymentID, monitorKind, true)
	if loadErr == nil {
		currentJSON, marshalErr := json.Marshal(current.Suite)
		if marshalErr != nil {
			return resource.ProbeMonitorRecord{}, resource.ErrInvalid
		}
		if request.ExpectedRevision == 0 && current.OwnerID == request.OwnerID && current.Interval == request.Interval && bytes.Equal(currentJSON, suiteJSON) {
			if err := tx.Commit(ctx); err != nil {
				return resource.ProbeMonitorRecord{}, fmt.Errorf("commit health probe replay: %w", err)
			}
			return current, nil
		}
		if request.ExpectedRevision != current.Revision {
			return resource.ProbeMonitorRecord{}, resource.ErrRevisionConflict
		}
		next := resource.ProbeMonitorRecord{
			DeploymentID: deploymentID.String(), MonitorKind: monitorKind, OwnerID: request.OwnerID, Suite: request.Suite, Interval: request.Interval,
			Status: healthprobe.AggregatePending, NextRunAt: configuredAt, Revision: current.Revision + 1,
			CreatedAt: current.CreatedAt, UpdatedAt: configuredAt,
		}
		if next.Validate() != nil {
			return resource.ProbeMonitorRecord{}, resource.ErrInvalid
		}
		result, updateErr := tx.Exec(ctx, `
			UPDATE deployment_health_monitors SET
				owner_id=$5, plan_hash=$6, recipe_digest=$7, suite_json=$8, interval_seconds=$9,
				aggregate_status='pending', latest_evidence_json=NULL, latest_observed_at=NULL,
				next_run_at=$10, revision=$11, updated_at=$12
			WHERE deployment_id=$1 AND agent_instance_id=$2 AND monitor_kind=$3 AND revision=$4`,
			deploymentID, store.instanceID, monitorKind, current.Revision, request.OwnerID, planHash, recipeDigest, suiteJSON,
			int64(request.Interval/time.Second), next.NextRunAt, next.Revision, next.UpdatedAt,
		)
		if updateErr != nil {
			return resource.ProbeMonitorRecord{}, fmt.Errorf("update health probe definition: %w", updateErr)
		}
		if result.RowsAffected() != 1 {
			return resource.ProbeMonitorRecord{}, resource.ErrRevisionConflict
		}
		if err := appendHealthMonitorEvent(ctx, tx, next); err != nil {
			return resource.ProbeMonitorRecord{}, err
		}
		if err := updateManagedServiceHealth(ctx, tx, deploymentID, next); err != nil {
			return resource.ProbeMonitorRecord{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return resource.ProbeMonitorRecord{}, fmt.Errorf("commit health probe reconfiguration: %w", err)
		}
		return next, nil
	}
	if !errors.Is(loadErr, resource.ErrNotFound) {
		return resource.ProbeMonitorRecord{}, loadErr
	}
	if request.ExpectedRevision != 0 {
		return resource.ProbeMonitorRecord{}, resource.ErrRevisionConflict
	}
	record := resource.ProbeMonitorRecord{
		DeploymentID: deploymentID.String(), MonitorKind: monitorKind, OwnerID: request.OwnerID, Suite: request.Suite, Interval: request.Interval,
		Status: healthprobe.AggregatePending, NextRunAt: configuredAt, Revision: 1,
		CreatedAt: configuredAt, UpdatedAt: configuredAt,
	}
	if record.Validate() != nil {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO deployment_health_monitors (
			deployment_id,monitor_kind,agent_instance_id,owner_id,plan_hash,recipe_digest,suite_json,interval_seconds,
			aggregate_status,next_run_at,revision,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'pending',$9,1,$9,$9)`,
		deploymentID, monitorKind, store.instanceID, request.OwnerID, planHash, recipeDigest, suiteJSON,
		int64(request.Interval/time.Second), configuredAt,
	); err != nil {
		if isUniqueViolation(err) {
			return resource.ProbeMonitorRecord{}, resource.ErrRevisionConflict
		}
		return resource.ProbeMonitorRecord{}, fmt.Errorf("insert health probe definition: %w", err)
	}
	if err := appendHealthMonitorEvent(ctx, tx, record); err != nil {
		return resource.ProbeMonitorRecord{}, err
	}
	if err := updateManagedServiceHealth(ctx, tx, deploymentID, record); err != nil {
		return resource.ProbeMonitorRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return resource.ProbeMonitorRecord{}, fmt.Errorf("commit health probe configuration: %w", err)
	}
	return record, nil
}

func (store *HealthProbeStore) GetProbe(ctx context.Context, deploymentID string) (resource.ProbeMonitorRecord, error) {
	return store.GetProbeMonitor(ctx, deploymentID, resource.ProbeMonitorService)
}

func (store *HealthProbeStore) GetProbeMonitor(ctx context.Context, deploymentID string, monitorKind resource.ProbeMonitorKind) (resource.ProbeMonitorRecord, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(deploymentID))
	normalizedKind, validKind := resource.NormalizeProbeMonitorKind(monitorKind)
	if store == nil || store.pool == nil || ctx == nil || err != nil || parsed == uuid.Nil || parsed.String() != deploymentID || !validKind {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}
	return loadHealthMonitor(ctx, store.pool, store.instanceID, parsed, normalizedKind, false)
}

func (store *HealthProbeStore) GetDeploymentHealth(ctx context.Context, ownerID, deploymentID string) (cloudstatus.HealthSummary, error) {
	owner := strings.TrimSpace(ownerID)
	if cloudstatus.ValidateOwnerID(owner) != nil || owner != ownerID {
		return cloudstatus.HealthSummary{}, cloudstatus.ErrInvalid
	}
	record, err := store.GetProbe(ctx, deploymentID)
	if errors.Is(err, resource.ErrNotFound) {
		return cloudstatus.HealthSummary{Status: cloudstatus.HealthUnknown, EvidenceType: cloudstatus.HealthEvidenceNone}, nil
	}
	if err != nil {
		return cloudstatus.HealthSummary{}, err
	}
	if record.OwnerID != owner {
		return cloudstatus.HealthSummary{}, cloudstatus.ErrNotFound
	}
	return healthSummaryForRecord(record)
}

// healthSummaryForRecord is the sole public projection of a persisted probe
// monitor. The monitor's Suite and SuiteEvidence deliberately remain out of
// this value: both contain the approved endpoint, and evidence may contain
// capability-adjacent transport details. Reuse this exact projection for the
// API and the event/outbox path so they cannot drift into separate public
// facts.
func healthSummaryForRecord(record resource.ProbeMonitorRecord) (cloudstatus.HealthSummary, error) {
	monitorKind, valid := resource.NormalizeProbeMonitorKind(record.MonitorKind)
	if record.Validate() != nil || !valid || monitorKind != resource.ProbeMonitorService {
		return cloudstatus.HealthSummary{}, resource.ErrInvalid
	}
	summary := cloudstatus.HealthSummary{
		Status: mapHealthSummaryStatus(record.Status), Revision: record.Revision, NextDueAt: record.NextRunAt,
		ProbeCounts:  make([]cloudstatus.HealthProbeCount, 0, len(record.Suite.Probes)),
		EvidenceType: cloudstatus.HealthEvidenceNone,
	}
	counts := make(map[healthprobe.Purpose]uint32, len(record.Suite.Probes))
	for _, probe := range record.Suite.Probes {
		counts[probe.Purpose]++
		summary.ProbeCount++
	}
	for _, purpose := range []healthprobe.Purpose{healthprobe.PurposeLiveness, healthprobe.PurposeReadiness, healthprobe.PurposeSemantic} {
		if count := counts[purpose]; count > 0 {
			summary.ProbeCounts = append(summary.ProbeCounts, cloudstatus.HealthProbeCount{Kind: mapHealthProbeKind(purpose), Count: count})
		}
	}
	if record.Evidence != nil {
		digest, digestErr := healthprobe.EvidenceDigest(record.Suite, *record.Evidence)
		if digestErr != nil {
			return cloudstatus.HealthSummary{}, resource.ErrInvalid
		}
		summary.ObservedAt = record.Evidence.ObservedAt
		summary.EvidenceDigest = digest
		summary.EvidenceType = cloudstatus.HealthEvidenceIndependent
	}
	return summary, nil
}

func mapHealthSummaryStatus(status healthprobe.AggregateStatus) cloudstatus.HealthStatus {
	switch status {
	case healthprobe.AggregatePending:
		return cloudstatus.HealthPending
	case healthprobe.AggregateHealthy:
		return cloudstatus.HealthHealthy
	case healthprobe.AggregateDegraded:
		return cloudstatus.HealthDegraded
	case healthprobe.AggregateUnhealthy:
		return cloudstatus.HealthUnhealthy
	case healthprobe.AggregateCanceled:
		return cloudstatus.HealthCanceled
	default:
		return cloudstatus.HealthUnknown
	}
}

func mapHealthProbeKind(purpose healthprobe.Purpose) cloudstatus.HealthProbeKind {
	switch purpose {
	case healthprobe.PurposeLiveness:
		return cloudstatus.HealthProbeLiveness
	case healthprobe.PurposeReadiness:
		return cloudstatus.HealthProbeReadiness
	case healthprobe.PurposeSemantic:
		return cloudstatus.HealthProbeSemantic
	default:
		return ""
	}
}

func (store *HealthProbeStore) ListDueProbes(ctx context.Context, dueAt time.Time, limit int) ([]resource.ProbeMonitorRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || dueAt.IsZero() || limit < 1 || limit > 256 {
		return nil, resource.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, healthMonitorSelectSQL+`
		WHERE monitor.agent_instance_id=$1 AND monitor.next_run_at <= $2
		  AND (service.state IS NULL OR service.state IN ('active','degraded'))
		ORDER BY monitor.next_run_at, monitor.deployment_id, monitor.monitor_kind LIMIT $3`, store.instanceID, dueAt.UTC(), limit)
	if err != nil {
		return nil, fmt.Errorf("list due health probes: %w", err)
	}
	defer rows.Close()
	records := make([]resource.ProbeMonitorRecord, 0, limit)
	for rows.Next() {
		record, scanErr := scanHealthMonitor(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate due health probes: %w", err)
	}
	return records, nil
}

func (store *HealthProbeStore) SaveExternalProbe(ctx context.Context, expected resource.ProbeMonitorRecord, trusted healthprobe.ExternalEvidence, completedAt time.Time) (resource.ProbeMonitorRecord, error) {
	if store == nil || store.pool == nil || ctx == nil || expected.Validate() != nil || completedAt.IsZero() {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}
	evidence, err := trusted.SnapshotFor(expected.Suite)
	if err != nil {
		return resource.ProbeMonitorRecord{}, err
	}
	completedAt = completedAt.UTC()
	if completedAt.Before(evidence.ObservedAt) {
		completedAt = evidence.ObservedAt.UTC()
	}
	deploymentID, _ := uuid.Parse(expected.DeploymentID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return resource.ProbeMonitorRecord{}, fmt.Errorf("begin health evidence write: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	monitorKind, _ := resource.NormalizeProbeMonitorKind(expected.MonitorKind)
	current, err := loadHealthMonitor(ctx, tx, store.instanceID, deploymentID, monitorKind, true)
	if err != nil {
		return resource.ProbeMonitorRecord{}, err
	}
	if current.Revision != expected.Revision || !sameHealthDefinition(current, expected) {
		return resource.ProbeMonitorRecord{}, resource.ErrRevisionConflict
	}
	if current.Evidence != nil && !evidence.ObservedAt.After(current.Evidence.ObservedAt) {
		return resource.ProbeMonitorRecord{}, resource.ErrStaleProbeEvidence
	}
	evidenceJSON, err := json.Marshal(evidence)
	if err != nil {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}
	next := resource.ProbeMonitorRecord{
		DeploymentID: current.DeploymentID, MonitorKind: monitorKind, OwnerID: current.OwnerID, Suite: current.Suite, Interval: current.Interval,
		Status: evidence.Status, Evidence: &evidence, NextRunAt: completedAt.Add(current.Interval),
		Revision: current.Revision + 1, CreatedAt: current.CreatedAt, UpdatedAt: completedAt,
	}
	if next.Validate() != nil {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}
	result, err := tx.Exec(ctx, `
		UPDATE deployment_health_monitors SET aggregate_status=$5,latest_evidence_json=$6,
			latest_observed_at=$7,next_run_at=$8,revision=$9,updated_at=$10
		WHERE deployment_id=$1 AND agent_instance_id=$2 AND monitor_kind=$3 AND revision=$4`,
		deploymentID, store.instanceID, monitorKind, current.Revision, next.Status, evidenceJSON,
		evidence.ObservedAt, next.NextRunAt, next.Revision, next.UpdatedAt,
	)
	if err != nil {
		return resource.ProbeMonitorRecord{}, fmt.Errorf("update health evidence: %w", err)
	}
	if result.RowsAffected() != 1 {
		return resource.ProbeMonitorRecord{}, resource.ErrRevisionConflict
	}
	for _, probe := range evidence.Probes {
		encoded, marshalErr := json.Marshal(probe)
		if marshalErr != nil {
			return resource.ProbeMonitorRecord{}, resource.ErrInvalid
		}
		evidenceID, idErr := uuid.NewV7()
		if idErr != nil {
			return resource.ProbeMonitorRecord{}, fmt.Errorf("create health evidence id: %w", idErr)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO deployment_health_evidence (
				evidence_id,deployment_id,monitor_kind,agent_instance_id,purpose,plan_hash,recipe_digest,probe_digest,
				evidence_source,status,evidence_json,observed_at,health_revision,created_at
			) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			evidenceID, deploymentID, monitorKind, store.instanceID, probe.Purpose, probe.Binding.PlanHash,
			probe.Binding.RecipeDigest, probe.Binding.ProbeDigest, probe.Trust, probe.Status, encoded,
			probe.ObservedAt, next.Revision, completedAt,
		); err != nil {
			return resource.ProbeMonitorRecord{}, fmt.Errorf("insert separated health evidence: %w", err)
		}
	}
	if err := appendHealthMonitorEvent(ctx, tx, next); err != nil {
		return resource.ProbeMonitorRecord{}, err
	}
	if err := updateManagedServiceHealth(ctx, tx, deploymentID, next); err != nil {
		return resource.ProbeMonitorRecord{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return resource.ProbeMonitorRecord{}, fmt.Errorf("commit health evidence: %w", err)
	}
	return next, nil
}

const healthMonitorSelectSQL = `
	SELECT monitor.deployment_id,monitor.monitor_kind,monitor.owner_id,monitor.suite_json,monitor.interval_seconds,
	       monitor.aggregate_status,monitor.latest_evidence_json,monitor.next_run_at,
	       monitor.revision,monitor.created_at,monitor.updated_at
	FROM deployment_health_monitors monitor
	LEFT JOIN managed_services service ON service.deployment_id=monitor.deployment_id `

type healthMonitorRow interface{ Scan(...any) error }

func loadHealthMonitor(ctx context.Context, query rowQuerier, instanceID, deploymentID uuid.UUID, monitorKind resource.ProbeMonitorKind, lock bool) (resource.ProbeMonitorRecord, error) {
	suffix := ` WHERE monitor.agent_instance_id=$1 AND monitor.deployment_id=$2 AND monitor.monitor_kind=$3`
	if lock {
		suffix += ` FOR UPDATE OF monitor`
	}
	record, err := scanHealthMonitor(query.QueryRow(ctx, healthMonitorSelectSQL+suffix, instanceID, deploymentID, monitorKind))
	if errors.Is(err, pgx.ErrNoRows) {
		return resource.ProbeMonitorRecord{}, resource.ErrNotFound
	}
	return record, err
}

func scanHealthMonitor(row healthMonitorRow) (resource.ProbeMonitorRecord, error) {
	var record resource.ProbeMonitorRecord
	var deploymentID uuid.UUID
	var monitorKind string
	var suiteJSON []byte
	var intervalSeconds int64
	var evidenceJSON []byte
	if err := row.Scan(&deploymentID, &monitorKind, &record.OwnerID, &suiteJSON, &intervalSeconds, &record.Status,
		&evidenceJSON, &record.NextRunAt, &record.Revision, &record.CreatedAt, &record.UpdatedAt); err != nil {
		return resource.ProbeMonitorRecord{}, err
	}
	record.DeploymentID = deploymentID.String()
	record.MonitorKind = resource.ProbeMonitorKind(monitorKind)
	record.Interval = time.Duration(intervalSeconds) * time.Second
	if json.Unmarshal(suiteJSON, &record.Suite) != nil {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}
	if len(evidenceJSON) > 0 {
		var evidence healthprobe.SuiteEvidence
		if json.Unmarshal(evidenceJSON, &evidence) != nil {
			return resource.ProbeMonitorRecord{}, resource.ErrInvalid
		}
		record.Evidence = &evidence
	}
	record.NextRunAt, record.CreatedAt, record.UpdatedAt = record.NextRunAt.UTC(), record.CreatedAt.UTC(), record.UpdatedAt.UTC()
	if record.Validate() != nil {
		return resource.ProbeMonitorRecord{}, resource.ErrInvalid
	}
	return record, nil
}

func loadHealthBinding(ctx context.Context, query rowQuerier, instanceID, deploymentID uuid.UUID) (string, string, string, error) {
	var ownerID, planHash, recipeDigest string
	err := query.QueryRow(ctx, `
		SELECT deployment.owner_id, plan.plan_hash, 'sha256:' || encode(deployment.recipe_bundle_sha256, 'hex')
		FROM worker_deployments deployment
		JOIN cloud_launch_operations launch ON launch.deployment_id=deployment.deployment_id
		  AND launch.agent_instance_id=deployment.agent_instance_id
		JOIN cloud_plans plan ON plan.plan_id=launch.plan_id AND plan.agent_instance_id=deployment.agent_instance_id
		WHERE deployment.deployment_id=$1 AND deployment.agent_instance_id=$2`, deploymentID, instanceID,
	).Scan(&ownerID, &planHash, &recipeDigest)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", resource.ErrNotFound
	}
	if err != nil {
		return "", "", "", fmt.Errorf("load health probe binding: %w", err)
	}
	return ownerID, planHash, recipeDigest, nil
}

func sameHealthDefinition(left, right resource.ProbeMonitorRecord) bool {
	leftKind, leftValid := resource.NormalizeProbeMonitorKind(left.MonitorKind)
	rightKind, rightValid := resource.NormalizeProbeMonitorKind(right.MonitorKind)
	if !leftValid || !rightValid || leftKind != rightKind || left.DeploymentID != right.DeploymentID || left.OwnerID != right.OwnerID || left.Interval != right.Interval {
		return false
	}
	leftJSON, leftErr := json.Marshal(left.Suite)
	rightJSON, rightErr := json.Marshal(right.Suite)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}

func appendHealthMonitorEvent(ctx context.Context, tx pgx.Tx, record resource.ProbeMonitorRecord) error {
	monitorKind, valid := resource.NormalizeProbeMonitorKind(record.MonitorKind)
	if !valid {
		return resource.ErrInvalid
	}
	if monitorKind != resource.ProbeMonitorService {
		return nil
	}
	summary, err := healthSummaryForRecord(record)
	if err != nil {
		return err
	}
	return appendCloudFactEvent(ctx, tx, uuid.MustParse(record.DeploymentID), "deployment_health", "cloud.deployment.health.changed", uint64(record.Revision), summary)
}

func updateManagedServiceHealth(ctx context.Context, tx pgx.Tx, deploymentID uuid.UUID, health resource.ProbeMonitorRecord) error {
	monitorKind, valid := resource.NormalizeProbeMonitorKind(health.MonitorKind)
	if !valid {
		return resource.ErrInvalid
	}
	if monitorKind != resource.ProbeMonitorService {
		return nil
	}
	var serviceID uuid.UUID
	var ownerID, state string
	var revision int64
	err := tx.QueryRow(ctx, `
		SELECT service_id,owner_id,state,revision FROM managed_services
		WHERE deployment_id=$1 FOR UPDATE`, deploymentID,
	).Scan(&serviceID, &ownerID, &state, &revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lock managed service health: %w", err)
	}
	if state != "active" && state != "degraded" {
		return nil
	}
	desired := "degraded"
	if health.Status == healthprobe.AggregateHealthy {
		desired = "active"
	}
	if state == desired {
		return nil
	}
	revision++
	result, err := tx.Exec(ctx, `UPDATE managed_services SET state=$3,revision=$4,updated_at=$5
		WHERE service_id=$1 AND deployment_id=$2 AND revision=$6`, serviceID, deploymentID, desired, revision, health.UpdatedAt, revision-1)
	if err != nil {
		return fmt.Errorf("update managed service health: %w", err)
	}
	if result.RowsAffected() != 1 {
		return resource.ErrRevisionConflict
	}
	var externalEvidenceAt *time.Time
	if health.Evidence != nil {
		observedAt := health.Evidence.ObservedAt
		externalEvidenceAt = &observedAt
	}
	summary := struct {
		ServiceID          string                      `json:"service_id"`
		DeploymentID       string                      `json:"deployment_id"`
		OwnerID            string                      `json:"owner_id"`
		State              string                      `json:"state"`
		HealthStatus       healthprobe.AggregateStatus `json:"health_status"`
		ExternalEvidenceAt *time.Time                  `json:"external_evidence_at,omitempty"`
		Revision           int64                       `json:"revision"`
		UpdatedAt          time.Time                   `json:"updated_at"`
	}{serviceID.String(), deploymentID.String(), ownerID, desired, health.Status, externalEvidenceAt, revision, health.UpdatedAt}
	return appendCloudFactEvent(ctx, tx, serviceID, "managed_service", "cloud.service.changed", uint64(revision), summary)
}
