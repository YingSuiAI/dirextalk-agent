package postgres

import (
	"context"
	"encoding/json"
	"slices"

	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/publicweb"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
	"github.com/jackc/pgx/v5"
)

const runtimeToolExecutionSnapshotV1 = 1

type persistedToolExecutionSnapshot struct {
	SchemaVersion int `json:"schema_version"`
	Execution     struct {
		ToolCallID string
		Name       string
		Content    string
		IsError    bool
	} `json:"execution"`
}

type completedOfficialSourceReceipt struct {
	toolCallID string
	evidence   publicweb.Evidence
}

func (store *Store) BindOfficialSourceEvidence(
	ctx context.Context,
	scope task.MutationScope,
	command planning.BindOfficialSourceEvidenceCommand,
) (planning.OfficialSourceEvidenceSet, error) {
	caller, err := parseIdempotencyCaller(scope)
	if err != nil {
		return planning.OfficialSourceEvidenceSet{}, err
	}
	if err := command.Validate(); err != nil {
		return planning.OfficialSourceEvidenceSet{}, err
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return planning.OfficialSourceEvidenceSet{}, planning.ErrPersistence
	}
	defer func() { _ = tx.Rollback(ctx) }()

	session, storedCaller, _, err := lockResearchByBinding(ctx, tx, command.Binding)
	if err != nil {
		return planning.OfficialSourceEvidenceSet{}, err
	}
	if storedCaller != caller {
		return planning.OfficialSourceEvidenceSet{}, planning.ErrScopeMismatch
	}
	if session.Binding != command.Binding {
		return planning.OfficialSourceEvidenceSet{}, planning.ErrIdempotencyConflict
	}
	if session.TaskID == "" || session.TaskID != command.TaskID {
		return planning.OfficialSourceEvidenceSet{}, planning.ErrTaskOperation
	}

	receipts, err := loadCompletedOfficialSourceReceipts(ctx, tx, caller, command.Binding)
	if err != nil {
		return planning.OfficialSourceEvidenceSet{}, err
	}
	selected := make([]planning.OfficialSourceEvidence, 0, len(command.Sources))
	usedToolCalls := make(map[string]struct{}, len(command.Sources))
	for _, source := range command.Sources {
		matched := false
		for _, receipt := range receipts {
			if _, used := usedToolCalls[receipt.toolCallID]; used || receipt.evidence.URL != source.URL ||
				!receipt.evidence.RetrievedAt.Equal(source.RetrievedAt) || receipt.evidence.ContentDigest != source.ContentDigest {
				continue
			}
			selected = append(selected, planning.OfficialSourceEvidence{
				TaskID: command.TaskID, ToolCallID: receipt.toolCallID, URL: receipt.evidence.URL,
				RetrievedAt: receipt.evidence.RetrievedAt, ContentDigest: receipt.evidence.ContentDigest,
			})
			usedToolCalls[receipt.toolCallID] = struct{}{}
			matched = true
			break
		}
		if !matched {
			return planning.OfficialSourceEvidenceSet{}, planning.ErrResearchEvidenceMissing
		}
	}

	for _, evidence := range selected {
		if _, err := tx.Exec(ctx, `
			INSERT INTO planning_official_source_evidence
			    (session_id, task_id, caller_client_id, caller_credential_id, request_id,
			     tool_call_id, source_url, retrieved_at, content_digest)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
			ON CONFLICT DO NOTHING`,
			session.SessionID, command.TaskID, caller.ClientID, caller.CredentialID, command.Binding.RequestID,
			evidence.ToolCallID, evidence.URL, evidence.RetrievedAt, evidence.ContentDigest,
		); err != nil {
			return planning.OfficialSourceEvidenceSet{}, planning.ErrPersistence
		}
	}

	bound, err := loadBoundOfficialSourceEvidence(ctx, tx, session.SessionID, command.TaskID)
	if err != nil {
		return planning.OfficialSourceEvidenceSet{}, err
	}
	wanted, err := planning.BuildOfficialSourceEvidenceSet(command.TaskID, selected)
	if err != nil {
		return planning.OfficialSourceEvidenceSet{}, planning.ErrInvalid
	}
	actual, err := planning.BuildOfficialSourceEvidenceSet(command.TaskID, bound)
	if err != nil || !slices.Equal(actual.Evidence, wanted.Evidence) || actual.Digest != wanted.Digest {
		return planning.OfficialSourceEvidenceSet{}, planning.ErrIdempotencyConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return planning.OfficialSourceEvidenceSet{}, planning.ErrPersistence
	}
	return actual, nil
}

func loadCompletedOfficialSourceReceipts(
	ctx context.Context,
	query planningQuerier,
	caller idempotencyCaller,
	binding planning.Binding,
) ([]completedOfficialSourceReceipt, error) {
	rows, err := query.Query(ctx, `
		SELECT tool_call_id, result_json
		FROM runtime_tool_executions
		WHERE caller_client_id=$1 AND caller_credential_id=$2 AND request_id=$3
		  AND owner_id=$4 AND conversation_id=$5 AND tool_name=$6
		  AND state='completed' AND result_schema_version=$7
		ORDER BY tool_call_id`, caller.ClientID, caller.CredentialID, binding.RequestID,
		binding.OwnerID, binding.ConversationID, publicweb.ToolName, runtimeToolExecutionSnapshotV1)
	if err != nil {
		return nil, planning.ErrPersistence
	}
	defer rows.Close()
	receipts := make([]completedOfficialSourceReceipt, 0)
	for rows.Next() {
		var toolCallID string
		var encoded []byte
		if err := rows.Scan(&toolCallID, &encoded); err != nil {
			return nil, planning.ErrPersistence
		}
		var snapshot persistedToolExecutionSnapshot
		if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != runtimeToolExecutionSnapshotV1 ||
			snapshot.Execution.ToolCallID != toolCallID || snapshot.Execution.Name != publicweb.ToolName {
			return nil, planning.ErrPersistence
		}
		if snapshot.Execution.IsError {
			continue
		}
		evidence, err := publicweb.ParseEvidenceResult(snapshot.Execution.Content)
		if err != nil {
			return nil, planning.ErrPersistence
		}
		receipts = append(receipts, completedOfficialSourceReceipt{toolCallID: toolCallID, evidence: evidence})
	}
	if err := rows.Err(); err != nil {
		return nil, planning.ErrPersistence
	}
	return receipts, nil
}

func loadBoundOfficialSourceEvidence(
	ctx context.Context,
	query planningQuerier,
	sessionID, taskID string,
) ([]planning.OfficialSourceEvidence, error) {
	rows, err := query.Query(ctx, `
		SELECT tool_call_id, source_url, retrieved_at, content_digest
		FROM planning_official_source_evidence
		WHERE session_id=$1 AND task_id=$2
		ORDER BY source_url, content_digest`, sessionID, taskID)
	if err != nil {
		return nil, planning.ErrPersistence
	}
	defer rows.Close()
	values := make([]planning.OfficialSourceEvidence, 0)
	for rows.Next() {
		value := planning.OfficialSourceEvidence{TaskID: taskID}
		if err := rows.Scan(&value.ToolCallID, &value.URL, &value.RetrievedAt, &value.ContentDigest); err != nil {
			return nil, planning.ErrPersistence
		}
		value.RetrievedAt = value.RetrievedAt.UTC()
		values = append(values, value)
	}
	if err := rows.Err(); err != nil {
		return nil, planning.ErrPersistence
	}
	if len(values) == 0 {
		return nil, planning.ErrPersistence
	}
	return values, nil
}
