package coreexecutionv2

import (
	"context"
	"fmt"
	"strings"
)

// Stage records are first-class execution-v2 snapshots.  The public API uses
// deterministic reconcile rather than a hidden worker, so the stage binds the
// run, task identity, confirmation, plan revision, and operation in one
// owner-scoped durable record.
func stageIDForRun(owner, runID, planID, operation string) string {
	return deterministicID(owner, "execution-v2-stage", runID+"\x00"+planID+"\x00"+operation)
}

func taskIDForStage(owner, stageID string) string {
	return deterministicID(owner, "execution-v2-task", stageID)
}

func stagePayload(runID, planID, operation, taskID, confirmationID string, planRevision uint64) map[string]any {
	return map[string]any{
		"run_id": runID, "plan_id": planID, "plan_revision": planRevision, "operation": operation,
		"task_id": taskID, "confirmation_id": confirmationID, "status": "waiting_user",
		"dispatch_mode": "public_reconcile", "requires_confirmation": true,
		"binding": map[string]any{"run_id": runID, "plan_id": planID, "operation": operation, "task_id": taskID, "confirmation_id": confirmationID},
	}
}

func stageRecordPayload(owner, runID, planID, operation, taskID, confirmationID string, planRevision uint64) map[string]any {
	payload := stagePayload(runID, planID, operation, taskID, confirmationID, planRevision)
	payload["binding"].(map[string]any)["stage_id"] = stageIDForRun(owner, runID, planID, operation)
	return payload
}

func stageForRun(ctx context.Context, store Store, owner string, run Record) (Record, error) {
	if store == nil || run.Kind != "run" {
		return Record{}, ErrInvalid
	}
	stageID := stringParam(run.Payload, "stage_id")
	if stageID == "" {
		return Record{}, ErrNotFound
	}
	stage, err := store.Read(ctx, owner, "stage", stageID, 0)
	if err != nil {
		return Record{}, err
	}
	if stage.OwnerID != owner || stringParam(stage.Payload, "run_id") != run.ID || stage.ID != stageID {
		return Record{}, fmt.Errorf("%w: stage binding mismatch", ErrConflict)
	}
	return stage, nil
}

func stageView(record Record) map[string]any {
	return publicRecord(record)
}

func stageTerminal(status string) bool {
	switch strings.TrimSpace(status) {
	case "succeeded", "failed", "canceled", "rejected", "expired":
		return true
	default:
		return false
	}
}
