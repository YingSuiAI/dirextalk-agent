package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamexecution"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const teamExecutionCompletedEvent = "team.execution.completed"

func appendTeamExecutionCompletedEvent(
	ctx context.Context,
	tx pgx.Tx,
	execution teamexecution.Fact,
	report teamreport.Fact,
) error {
	if execution.Status != teamexecution.StatusCompleted ||
		execution.RecordRevision == 0 ||
		report.Validate() != nil ||
		report.Report.ExecutionID != execution.Execution.ExecutionID ||
		report.Report.OwnerID != execution.Execution.OwnerID ||
		report.Report.TaskID != execution.Execution.TaskID ||
		report.Report.PlanID != execution.Execution.PlanID ||
		report.Report.PlanRevision != execution.Execution.PlanRevision ||
		report.Report.PlanDigest != execution.Execution.PlanDigest {
		return teamexecution.ErrFactMismatch
	}
	conversationID, err := uniqueTeamExecutionConversationID(
		ctx,
		tx,
		execution.Execution.OwnerID,
		execution.Execution.TaskID,
	)
	if err != nil {
		return err
	}
	summary := struct {
		SchemaVersion   int                  `json:"schema_version"`
		ExecutionID     string               `json:"execution_id"`
		OwnerID         string               `json:"owner_id"`
		TaskID          string               `json:"task_id"`
		PlanID          string               `json:"plan_id"`
		PlanRevision    uint64               `json:"plan_revision"`
		PlanDigest      string               `json:"plan_digest"`
		Status          teamexecution.Status `json:"status"`
		RecordRevision  uint64               `json:"record_revision"`
		ConversationID  string               `json:"conversation_id"`
		ReportDigest    string               `json:"report_digest"`
		ReportGenerated time.Time            `json:"report_generated_at"`
		CleanupVerified bool                 `json:"cleanup_verified"`
	}{
		SchemaVersion:   teamFactSnapshotSchemaV1,
		ExecutionID:     execution.Execution.ExecutionID,
		OwnerID:         execution.Execution.OwnerID,
		TaskID:          execution.Execution.TaskID,
		PlanID:          execution.Execution.PlanID,
		PlanRevision:    execution.Execution.PlanRevision,
		PlanDigest:      execution.Execution.PlanDigest,
		Status:          execution.Status,
		RecordRevision:  execution.RecordRevision,
		ConversationID:  conversationID,
		ReportDigest:    report.ReportDigest,
		ReportGenerated: report.GeneratedAt,
		CleanupVerified: true,
	}
	return appendCloudFactEvent(
		ctx,
		tx,
		uuid.MustParse(execution.Execution.ExecutionID),
		"team_execution",
		teamExecutionCompletedEvent,
		execution.RecordRevision,
		summary,
	)
}

// A Task can be mentioned by later status tools in other chats. Only the
// original plan-preparation receipt is eligible to bind an automatic result
// to a conversation. Ambiguous or absent bindings suppress chat delivery but
// never invalidate an otherwise completed execution.
func uniqueTeamExecutionConversationID(
	ctx context.Context,
	tx pgx.Tx,
	ownerID string,
	taskID string,
) (string, error) {
	rows, err := tx.Query(ctx, `
		SELECT DISTINCT conversation_id
		FROM runtime_tool_executions execution
		WHERE owner_id=$1
		  AND state='completed'
		  AND conversation_id<>''
		  AND tool_name='team_plan_prepare'
		  AND result_schema_version=1
		  AND jsonb_typeof(
		        result_json->'execution'->'RelatedTaskIDs'
		      )='array'
		  AND EXISTS (
		        SELECT 1
		        FROM jsonb_array_elements_text(
		          result_json->'execution'->'RelatedTaskIDs'
		        ) AS related(task_id)
		        WHERE related.task_id=$2
		      )
		ORDER BY conversation_id
		LIMIT 2`,
		strings.TrimSpace(ownerID),
		strings.TrimSpace(taskID),
	)
	if err != nil {
		return "", fmt.Errorf(
			"read Team execution conversation binding: %w",
			err,
		)
	}
	defer rows.Close()
	values := make([]string, 0, 2)
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return "", fmt.Errorf(
				"scan Team execution conversation binding: %w",
				err,
			)
		}
		value = strings.TrimSpace(value)
		if value != "" {
			values = append(values, value)
		}
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf(
			"iterate Team execution conversation binding: %w",
			err,
		)
	}
	if len(values) != 1 {
		return "", nil
	}
	return values[0], nil
}
