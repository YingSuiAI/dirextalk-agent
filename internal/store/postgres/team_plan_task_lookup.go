package postgres

import (
	"context"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// FindTeamPlanByTask resolves the latest immutable Team Plan bound to one
// owner-scoped Task. Task status surfaces use this read path so the client can
// render the exact approval card instead of guessing a Plan from Task state.
func (store *Store) FindTeamPlanByTask(
	ctx context.Context,
	ownerID,
	taskID string,
) (teamorchestration.PlanFact, bool, error) {
	parsedTaskID, err := uuid.Parse(taskID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		err != nil ||
		parsedTaskID == uuid.Nil ||
		parsedTaskID.String() != taskID ||
		ownerID == "" ||
		strings.TrimSpace(ownerID) != ownerID {
		return teamorchestration.PlanFact{}, false,
			ErrTeamFactInvalid
	}
	var (
		planID       uuid.UUID
		planRevision int64
	)
	err = store.pool.QueryRow(ctx, `
		SELECT plan_id, plan_revision
		FROM team_plans
		WHERE agent_instance_id=$1
		  AND owner_id=$2
		  AND task_id=$3
		ORDER BY plan_revision DESC, created_at DESC, plan_id DESC
		LIMIT 1`,
		store.instanceID,
		ownerID,
		parsedTaskID,
	).Scan(&planID, &planRevision)
	if errors.Is(err, pgx.ErrNoRows) {
		return teamorchestration.PlanFact{}, false, nil
	}
	if err != nil {
		return teamorchestration.PlanFact{}, false, err
	}
	if planID == uuid.Nil || planRevision <= 0 {
		return teamorchestration.PlanFact{}, false,
			ErrTeamFactCorrupt
	}
	record, err := store.GetTeamPlan(
		ctx,
		ownerID,
		planID.String(),
		uint64(planRevision),
	)
	if err != nil {
		return teamorchestration.PlanFact{}, false, err
	}
	if record.TaskID != taskID {
		return teamorchestration.PlanFact{}, false,
			ErrTeamFactCorrupt
	}
	fact, err := orchestrationPlanFact(record)
	if err != nil {
		return teamorchestration.PlanFact{}, false, err
	}
	return fact, true, nil
}
