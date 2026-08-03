package postgres

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamreport"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (store *Store) GetTeamExecutionReport(
	ctx context.Context,
	ownerID,
	executionID string,
) (teamreport.Fact, error) {
	parsed, err := uuid.Parse(executionID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		!validTeamOwnerID(ownerID) ||
		err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != executionID {
		return teamreport.Fact{}, teamreport.ErrInvalid
	}
	var (
		status      string
		digest      *string
		encoded     []byte
		generatedAt *time.Time
	)
	err = store.pool.QueryRow(ctx, `
		SELECT status, report_digest, report_json, report_generated_at
		FROM team_executions
		WHERE execution_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3`,
		parsed,
		store.instanceID,
		ownerID,
	).Scan(
		&status,
		&digest,
		&encoded,
		&generatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return teamreport.Fact{}, teamreport.ErrNotFound
	}
	if err != nil {
		return teamreport.Fact{},
			fmt.Errorf("read Team execution report: %w", err)
	}
	return decodeTeamExecutionReportFact(
		status,
		digest,
		encoded,
		generatedAt,
		ownerID,
		executionID,
	)
}

// FindTeamExecutionReportByTask returns the immutable report only after the
// execution has completed. A successful Task can briefly have no report while
// the controller is finalizing verified result evidence and cleanup.
func (store *Store) FindTeamExecutionReportByTask(
	ctx context.Context,
	ownerID,
	taskID string,
) (teamreport.Fact, bool, error) {
	parsed, err := uuid.Parse(taskID)
	if store == nil ||
		store.pool == nil ||
		ctx == nil ||
		!validTeamOwnerID(ownerID) ||
		err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != taskID {
		return teamreport.Fact{}, false, teamreport.ErrInvalid
	}
	rows, err := store.pool.Query(ctx, `
		SELECT execution_id, status, report_digest, report_json,
		       report_generated_at
		FROM team_executions
		WHERE task_id=$1
		  AND agent_instance_id=$2
		  AND owner_id=$3
		  AND status='completed'
		ORDER BY updated_at DESC, execution_id DESC
		LIMIT 2`,
		parsed,
		store.instanceID,
		ownerID,
	)
	if err != nil {
		return teamreport.Fact{}, false,
			fmt.Errorf("find Team execution report by Task: %w", err)
	}
	defer rows.Close()
	var facts []teamreport.Fact
	for rows.Next() {
		var (
			executionID uuid.UUID
			status      string
			digest      *string
			encoded     []byte
			generatedAt *time.Time
		)
		if err := rows.Scan(
			&executionID,
			&status,
			&digest,
			&encoded,
			&generatedAt,
		); err != nil {
			return teamreport.Fact{}, false,
				fmt.Errorf("scan Team execution report by Task: %w", err)
		}
		fact, err := decodeTeamExecutionReportFact(
			status,
			digest,
			encoded,
			generatedAt,
			ownerID,
			executionID.String(),
		)
		if err != nil {
			return teamreport.Fact{}, false, err
		}
		if fact.Report.TaskID != taskID {
			return teamreport.Fact{}, false,
				teamreport.ErrFactMismatch
		}
		facts = append(facts, fact)
	}
	if err := rows.Err(); err != nil {
		return teamreport.Fact{}, false,
			fmt.Errorf("iterate Team execution reports by Task: %w", err)
	}
	if len(facts) == 0 {
		return teamreport.Fact{}, false, nil
	}
	if len(facts) != 1 {
		return teamreport.Fact{}, false, teamreport.ErrFactMismatch
	}
	return facts[0], true, nil
}

func decodeTeamExecutionReportFact(
	status string,
	digest *string,
	encoded []byte,
	generatedAt *time.Time,
	ownerID,
	executionID string,
) (teamreport.Fact, error) {
	if status != "completed" ||
		digest == nil ||
		generatedAt == nil ||
		len(encoded) == 0 {
		return teamreport.Fact{}, teamreport.ErrNotReady
	}
	var report teamreport.ReportV1
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		return teamreport.Fact{}, teamreport.ErrFactMismatch
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return teamreport.Fact{}, teamreport.ErrFactMismatch
	}
	fact := teamreport.Fact{
		Report:       report,
		ReportDigest: *digest,
		GeneratedAt:  generatedAt.UTC(),
	}
	if fact.Validate() != nil ||
		fact.Report.OwnerID != ownerID ||
		fact.Report.ExecutionID != executionID {
		return teamreport.Fact{}, teamreport.ErrFactMismatch
	}
	return fact, nil
}

var _ teamreport.Reader = (*Store)(nil)
