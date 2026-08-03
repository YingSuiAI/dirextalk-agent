package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamcontroller"
	"github.com/google/uuid"
)

func (store *Store) ListPlanExpiryWork(
	ctx context.Context,
	limit uint32,
) ([]teamcontroller.PlanExpiryWork, error) {
	if store == nil || store.pool == nil || ctx == nil ||
		limit == 0 || limit > 256 {
		return nil, teamcontroller.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		WITH latest_task_plan AS (
			SELECT DISTINCT ON (plan.task_id)
			       plan.owner_id,
			       plan.task_id,
			       plan.plan_id,
			       plan.plan_revision,
			       plan.record_revision,
			       plan.status,
			       plan.valid_until
			FROM team_plans AS plan
			WHERE plan.agent_instance_id=$1
			  AND plan.task_id IS NOT NULL
			ORDER BY plan.task_id,
			         plan.created_at DESC,
			         plan.plan_revision DESC,
			         plan.plan_id DESC
		)
		SELECT plan.owner_id,
		       plan.task_id,
		       plan.plan_id,
		       plan.plan_revision,
		       plan.record_revision,
		       plan.status,
		       plan.valid_until
		FROM latest_task_plan AS plan
		JOIN tasks AS task ON task.task_id=plan.task_id
		WHERE (
		        plan.status='ready_for_confirmation'
		        AND plan.valid_until<=clock_timestamp()
		      )
		   OR (
		        plan.status='expired'
		        AND task.execution_status<>'finished'
		      )
		ORDER BY plan.valid_until, plan.plan_id, plan.plan_revision
		LIMIT $2`,
		store.instanceID,
		int64(limit),
	)
	if err != nil {
		return nil, fmt.Errorf("query Team Plan expiry work: %w", err)
	}
	defer rows.Close()
	result := make([]teamcontroller.PlanExpiryWork, 0, limit)
	for rows.Next() {
		var (
			item       teamcontroller.PlanExpiryWork
			taskID     uuid.UUID
			planID     uuid.UUID
			status     string
			validUntil time.Time
		)
		if err := rows.Scan(
			&item.OwnerID,
			&taskID,
			&planID,
			&item.PlanRevision,
			&item.RecordRevision,
			&status,
			&validUntil,
		); err != nil {
			return nil, fmt.Errorf("scan Team Plan expiry work: %w", err)
		}
		item.TaskID = taskID.String()
		item.PlanID = planID.String()
		item.Status = teamcontroller.PlanExpiryStatus(status)
		item.ValidUntil = validUntil.UTC()
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate Team Plan expiry work: %w", err)
	}
	return result, nil
}

func (store *Store) ExpireReadyPlan(
	ctx context.Context,
	scope task.MutationScope,
	request teamcontroller.ExpireReadyPlanRequest,
) error {
	record, err := store.ExpireTeamPlan(
		ctx,
		scope,
		ExpireTeamPlanCommand{
			IdempotencyKey:         request.IdempotencyKey,
			OwnerID:                request.OwnerID,
			PlanID:                 request.PlanID,
			PlanRevision:           request.PlanRevision,
			ExpectedRecordRevision: request.ExpectedRecordRevision,
		},
	)
	if err != nil {
		return err
	}
	if record.Plan.OwnerID != request.OwnerID ||
		record.Plan.PlanID != request.PlanID ||
		record.Plan.Revision != request.PlanRevision ||
		record.Status != TeamPlanExpired ||
		record.RecordRevision != request.ExpectedRecordRevision+1 {
		return ErrTeamFactCorrupt
	}
	return nil
}

var _ teamcontroller.PlanExpiryControl = (*Store)(nil)
