package postgres

import (
	"context"
	"encoding/json"
	"errors"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *CoreConversationStore) CommitChatCompletion(ctx context.Context, a core.AtomicCompletion) (core.ChatResponse, error) {
	tx, e := s.pool.Begin(ctx)
	if e != nil {
		return core.ChatResponse{}, e
	}
	defer tx.Rollback(ctx)
	raw, _ := json.Marshal(a.Response)
	var leaseResult pgconn.CommandTag
	leaseResult, e = tx.Exec(ctx, `UPDATE core_chat_request_leases SET state='completed',response_json=$5,lease_id=NULL,lease_expires_at=NULL WHERE request_id=$1 AND lease_id=$2 AND lease_epoch=$3 AND request_fingerprint=$4 AND state='in_flight'`, a.RequestID, a.LeaseID, a.Epoch, a.Fingerprint, raw)
	if e != nil {
		return core.ChatResponse{}, core.ErrConflict
	}
	if leaseResult.RowsAffected() != 1 {
		return core.ChatResponse{}, core.ErrConflict
	}
	convResult, e := tx.Exec(ctx, `INSERT INTO core_conversations(conversation_id,title,revision,created_at,updated_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(conversation_id) DO UPDATE SET title=EXCLUDED.title,revision=EXCLUDED.revision,updated_at=EXCLUDED.updated_at WHERE core_conversations.revision=$6`, a.Conversation.ID, a.Conversation.Title, a.Conversation.Revision, a.Conversation.CreatedAt, a.Conversation.UpdatedAt, a.ExpectedRevision)
	if e != nil {
		return core.ChatResponse{}, e
	}
	if convResult.RowsAffected() != 1 {
		return core.ChatResponse{}, core.ErrConflict
	}
	if a.Conversation.ContextMessageOffset > uint64(^uint64(0)>>1) || len(a.Conversation.Summary) > core.MaxSummaryBytes {
		return core.ChatResponse{}, core.ErrInvalid
	}
	if _, e = tx.Exec(ctx, `INSERT INTO core_conversation_contexts(conversation_id,summary,message_offset,updated_at) VALUES($1,$2,$3,$4) ON CONFLICT(conversation_id) DO UPDATE SET summary=$2,message_offset=$3,updated_at=$4`, a.Conversation.ID, a.Conversation.Summary, int64(a.Conversation.ContextMessageOffset), a.Conversation.UpdatedAt); e != nil {
		return core.ChatResponse{}, e
	}
	for i, m := range a.Conversation.Messages {
		payload, _ := json.Marshal(m)
		tasks, _ := stringArrayJSONPG(m.RelatedTaskIDs)
		plans, _ := stringArrayJSONPG(m.RelatedPlanIDs)
		references, _ := referenceArrayJSONPG(m.References)
		sums, _ := stringArrayJSONPG(m.ToolSummaries)
		if _, e = tx.Exec(ctx, `INSERT INTO core_messages(message_id,conversation_id,sequence,role,content,model_profile_id,payload_json,related_task_ids,related_plan_ids,references_json,tool_summaries,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT(message_id) DO NOTHING`, m.ID, a.Conversation.ID, i+1, m.Role, m.Content, nullableUUIDPG(m.ModelProfileID), payload, tasks, plans, references, sums, m.CreatedAt); e != nil {
			return core.ChatResponse{}, e
		}
		if m.ModelProfileID != "" {
			if _, e = tx.Exec(ctx, `INSERT INTO core_model_profile_active_refs(owner_kind,owner_id,profile_id) VALUES('conversation',$1,$2) ON CONFLICT DO NOTHING`, a.Conversation.ID, m.ModelProfileID); e != nil {
				return core.ChatResponse{}, e
			}
		}
		for j, c := range m.ToolCalls {
			args := []byte(c.Arguments)
			if _, e = tx.Exec(ctx, `INSERT INTO core_message_tool_calls(message_id,call_index,tool_call_id,tool_name,arguments_json) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING`, m.ID, j, c.ID, c.Name, args); e != nil {
				return core.ChatResponse{}, e
			}
		}
		for j, r := range m.ToolResults {
			raw, _ := json.Marshal(r)
			if _, e = tx.Exec(ctx, `INSERT INTO core_message_tool_results(message_id,result_index,tool_call_id,result_json) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, m.ID, j, r.CallID, raw); e != nil {
				return core.ChatResponse{}, e
			}
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return core.ChatResponse{}, e
	}
	return a.Response, nil
}
func (s *CoreConversationStore) LoadModelStep(ctx context.Context, req, lease, fp string, epoch uint64, profile string, step int) (core.ModelRunResult, bool, error) {
	var raw []byte
	e := s.pool.QueryRow(ctx, `SELECT result_json FROM core_model_steps l JOIN core_chat_request_leases r USING(request_id) WHERE l.request_id=$1 AND step_index=$2 AND r.lease_id=$3 AND r.lease_epoch=$4 AND r.request_fingerprint=$5 AND l.input_fingerprint=$5 AND l.profile_id=$6 AND l.state='completed' AND l.epoch=$4`, req, step, lease, epoch, fp, profile).Scan(&raw)
	if errors.Is(e, pgx.ErrNoRows) {
		return core.ModelRunResult{}, false, nil
	}
	if e != nil {
		return core.ModelRunResult{}, false, e
	}
	var r core.ModelRunResult
	e = json.Unmarshal(raw, &r)
	return r, true, e
}
func (s *CoreConversationStore) RecordModelStep(ctx context.Context, req, lease, fp string, epoch uint64, profile string, step int, r core.ModelRunResult) error {
	raw, _ := json.Marshal(r)
	result, e := s.pool.Exec(ctx, `INSERT INTO core_model_steps(request_id,step_index,input_fingerprint,profile_id,state,epoch,result_json) SELECT $1,$2,$3,$4,'completed',$5,$6 WHERE EXISTS(SELECT 1 FROM core_chat_request_leases WHERE request_id=$1 AND lease_id=$7 AND lease_epoch=$5 AND request_fingerprint=$3) ON CONFLICT(request_id,step_index) DO NOTHING`, req, step, fp, profile, epoch, raw, lease)
	if e != nil {
		return e
	}
	if result.RowsAffected() != 1 {
		// A stale lease/epoch (or a competing completed step) must never be
		// reported as a successful persistence operation. The caller can then
		// fence the worker instead of proceeding toward completion.
		return core.ErrConflict
	}
	return nil
}

var _ core.Store = (*CoreConversationStore)(nil)
