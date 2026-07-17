package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/costalert"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ManagedCostAlertStore struct {
	pool       *pgxpool.Pool
	instanceID uuid.UUID
}

func NewManagedCostAlertStore(store *Store) (*ManagedCostAlertStore, error) {
	if store == nil || store.pool == nil || store.instanceID == uuid.Nil {
		return nil, costalert.ErrInvalid
	}
	return &ManagedCostAlertStore{pool: store.pool, instanceID: store.instanceID}, nil
}

func (store *ManagedCostAlertStore) Activate(ctx context.Context, policy costalert.PolicyV1) (costalert.PolicyV1, error) {
	if store == nil || store.pool == nil || policy.AgentInstanceID != store.instanceID.String() ||
		policy.Status != costalert.StatusActive || policy.Revision != 1 || !policy.AlertedAt.IsZero() {
		return costalert.PolicyV1{}, costalert.ErrInvalid
	}
	now := time.Now().UTC()
	policy.CreatedAt, policy.UpdatedAt = now, now
	if err := policy.Validate(); err != nil {
		return costalert.PolicyV1{}, err
	}
	row := store.pool.QueryRow(ctx, `
		INSERT INTO managed_cost_alert_policies (
		    policy_id,agent_instance_id,owner_id,deployment_id,plan_id,plan_revision,quote_id,currency,
		    threshold_amount_minor,hourly_estimate_micros,running_since,status,revision,created_at,updated_at)
		SELECT $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14
		WHERE EXISTS (
		    SELECT 1 FROM cloud_launch_operations launch
		    WHERE launch.agent_instance_id=$2 AND launch.owner_id=$3 AND launch.deployment_id=$4
		      AND launch.plan_id=$5 AND launch.state='active' AND launch.updated_at=$11)
		ON CONFLICT (agent_instance_id,deployment_id) DO NOTHING
		RETURNING `+managedCostAlertColumns,
		policy.PolicyID, store.instanceID, policy.OwnerID, policy.DeploymentID, policy.PlanID, int64(policy.PlanRevision),
		policy.QuoteID, policy.Currency, policy.ThresholdAmountMinor, int64(policy.HourlyEstimateMicros),
		policy.RunningSince, string(policy.Status), policy.Revision, now)
	result, err := scanManagedCostAlert(row)
	if err == nil {
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return costalert.PolicyV1{}, costalert.ErrUnavailable
	}
	current, err := store.get(ctx, policy.PolicyID, false)
	if err != nil {
		return costalert.PolicyV1{}, costalert.ErrNotReady
	}
	if !sameManagedCostPolicy(current, policy) {
		return costalert.PolicyV1{}, costalert.ErrRevisionConflict
	}
	return current, nil
}

func (store *ManagedCostAlertStore) Evaluate(ctx context.Context, policyID string, expectedRevision int64, accrued uint64, observedAt time.Time) (costalert.PolicyV1, bool, error) {
	if store == nil || store.pool == nil || expectedRevision < 1 || accrued > math.MaxInt64 ||
		observedAt.IsZero() || observedAt.Location() != time.UTC {
		return costalert.PolicyV1{}, false, costalert.ErrInvalid
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return costalert.PolicyV1{}, false, costalert.ErrUnavailable
	}
	defer func() { _ = tx.Rollback(ctx) }()
	current, err := readManagedCostAlert(ctx, tx, store.instanceID, policyID, true)
	if err != nil {
		return costalert.PolicyV1{}, false, mapManagedCostAlertReadError(err)
	}
	if current.LastObservedAt.Equal(observedAt) && current.ProjectedAccruedMicros == accrued {
		return current, false, nil
	}
	if current.Revision != expectedRevision || observedAt.Before(current.RunningSince) ||
		!current.LastObservedAt.IsZero() && !observedAt.After(current.LastObservedAt) {
		return costalert.PolicyV1{}, false, costalert.ErrRevisionConflict
	}
	threshold, err := costalert.ThresholdMicros(current.ThresholdAmountMinor, current.Currency)
	if err != nil {
		return costalert.PolicyV1{}, false, err
	}
	alertChanged := current.Status == costalert.StatusActive && accrued >= threshold
	nextStatus, alertedAt := current.Status, current.AlertedAt
	if alertChanged {
		nextStatus, alertedAt = costalert.StatusAlerted, observedAt
	}
	nextRevision := current.Revision + 1
	row := tx.QueryRow(ctx, `
		UPDATE managed_cost_alert_policies SET
		    status=$4,projected_accrued_micros=$5,last_observed_at=$6,alerted_at=$7,revision=$8,updated_at=$6
		WHERE agent_instance_id=$1 AND policy_id=$2 AND revision=$3
		RETURNING `+managedCostAlertColumns,
		store.instanceID, policyID, expectedRevision, string(nextStatus), int64(accrued), observedAt,
		nullableManagedCostAlertTime(alertedAt), nextRevision)
	next, err := scanManagedCostAlert(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return costalert.PolicyV1{}, false, costalert.ErrRevisionConflict
	}
	if err != nil {
		return costalert.PolicyV1{}, false, costalert.ErrUnavailable
	}
	if alertChanged {
		summary := struct {
			PolicyID               string    `json:"policy_id"`
			DeploymentID           string    `json:"deployment_id"`
			Currency               string    `json:"currency"`
			ThresholdAmountMinor   int64     `json:"threshold_amount_minor"`
			ProjectedAccruedMicros uint64    `json:"projected_accrued_micros"`
			ObservedAt             time.Time `json:"observed_at"`
		}{
			PolicyID: next.PolicyID, DeploymentID: next.DeploymentID, Currency: next.Currency,
			ThresholdAmountMinor: next.ThresholdAmountMinor, ProjectedAccruedMicros: next.ProjectedAccruedMicros,
			ObservedAt: next.LastObservedAt,
		}
		deploymentID, parseErr := uuid.Parse(next.DeploymentID)
		if parseErr != nil || appendCloudFactEvent(ctx, tx, deploymentID, "managed_cost_alert", "cloud.cost_alert.raised", uint64(next.Revision), summary) != nil {
			return costalert.PolicyV1{}, false, costalert.ErrUnavailable
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return costalert.PolicyV1{}, false, costalert.ErrUnavailable
	}
	return next, alertChanged, nil
}

func (store *ManagedCostAlertStore) Get(ctx context.Context, ownerID, deploymentID string) (costalert.PolicyV1, error) {
	if store == nil || store.pool == nil || strings.TrimSpace(ownerID) == "" {
		return costalert.PolicyV1{}, costalert.ErrInvalid
	}
	value, err := store.get(ctx, deploymentID, false)
	if err != nil {
		return costalert.PolicyV1{}, mapManagedCostAlertReadError(err)
	}
	if value.OwnerID != strings.TrimSpace(ownerID) || value.DeploymentID != deploymentID {
		return costalert.PolicyV1{}, costalert.ErrNotReady
	}
	return value, nil
}

func (store *ManagedCostAlertStore) get(ctx context.Context, policyID string, lock bool) (costalert.PolicyV1, error) {
	return readManagedCostAlert(ctx, store.pool, store.instanceID, policyID, lock)
}

const managedCostAlertColumns = `
	policy_id,agent_instance_id,owner_id,deployment_id,plan_id,plan_revision,quote_id,currency,
	threshold_amount_minor,hourly_estimate_micros,running_since,status,projected_accrued_micros,
	last_observed_at,alerted_at,revision,created_at,updated_at`

type managedCostAlertQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

func readManagedCostAlert(ctx context.Context, query managedCostAlertQuerier, instanceID uuid.UUID, policyID string, lock bool) (costalert.PolicyV1, error) {
	parsed, err := uuid.Parse(strings.TrimSpace(policyID))
	if err != nil || parsed == uuid.Nil {
		return costalert.PolicyV1{}, costalert.ErrInvalid
	}
	suffix := ""
	if lock {
		suffix = " FOR UPDATE"
	}
	return scanManagedCostAlert(query.QueryRow(ctx, `SELECT `+managedCostAlertColumns+`
		FROM managed_cost_alert_policies WHERE agent_instance_id=$1 AND policy_id=$2`+suffix, instanceID, parsed))
}

func scanManagedCostAlert(row pgx.Row) (costalert.PolicyV1, error) {
	var value costalert.PolicyV1
	var policyID, agentID, deploymentID, planID, quoteID uuid.UUID
	var planRevision, hourly, accrued int64
	var lastObservedAt, alertedAt *time.Time
	if err := row.Scan(
		&policyID, &agentID, &value.OwnerID, &deploymentID, &planID, &planRevision, &quoteID, &value.Currency,
		&value.ThresholdAmountMinor, &hourly, &value.RunningSince, &value.Status, &accrued,
		&lastObservedAt, &alertedAt, &value.Revision, &value.CreatedAt, &value.UpdatedAt,
	); err != nil {
		return costalert.PolicyV1{}, err
	}
	if planRevision < 1 || hourly < 1 || accrued < 0 {
		return costalert.PolicyV1{}, costalert.ErrInvalid
	}
	value.SchemaVersion, value.PolicyID, value.AgentInstanceID = costalert.SchemaV1, policyID.String(), agentID.String()
	value.DeploymentID, value.PlanID, value.QuoteID = deploymentID.String(), planID.String(), quoteID.String()
	value.PlanRevision, value.HourlyEstimateMicros, value.ProjectedAccruedMicros = uint64(planRevision), uint64(hourly), uint64(accrued)
	value.RunningSince, value.CreatedAt, value.UpdatedAt = value.RunningSince.UTC(), value.CreatedAt.UTC(), value.UpdatedAt.UTC()
	if lastObservedAt != nil {
		value.LastObservedAt = lastObservedAt.UTC()
	}
	if alertedAt != nil {
		value.AlertedAt = alertedAt.UTC()
	}
	if err := value.Validate(); err != nil {
		return costalert.PolicyV1{}, err
	}
	return value, nil
}

func sameManagedCostPolicy(current, requested costalert.PolicyV1) bool {
	return current.PolicyID == requested.PolicyID && current.AgentInstanceID == requested.AgentInstanceID &&
		current.OwnerID == requested.OwnerID && current.DeploymentID == requested.DeploymentID &&
		current.PlanID == requested.PlanID && current.PlanRevision == requested.PlanRevision &&
		current.QuoteID == requested.QuoteID && current.Currency == requested.Currency &&
		current.ThresholdAmountMinor == requested.ThresholdAmountMinor &&
		current.HourlyEstimateMicros == requested.HourlyEstimateMicros &&
		current.RunningSince.Equal(requested.RunningSince)
}

func mapManagedCostAlertReadError(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return costalert.ErrNotReady
	}
	if errors.Is(err, costalert.ErrInvalid) {
		return err
	}
	return fmt.Errorf("%w: read policy", costalert.ErrUnavailable)
}

func nullableManagedCostAlertTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value
}
