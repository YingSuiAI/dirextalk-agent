package coreconversation

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

// Final-answer ownership is selected by the parent in the durable tool call,
// never by instructions in a Worker report. Only the latest completed tool can
// deliver; an unfinished tool or subsequent user steer needs the parent loop.
func delegatedWorkerReply(authorities map[string]turnToolCallAuthority, prompt string) (string, bool) {
	var latest *turnToolCallAuthority
	for _, authority := range authorities {
		if authority.state != turnToolCallTerminal || authority.result == nil {
			return "", false
		}
		if latest == nil || authority.resultSequence > latest.resultSequence {
			copy := authority
			latest = &copy
		}
	}
	if latest == nil || !coremodel.IsCloudWorkerExecutionTool(latest.call.Name) || latest.result.CallID != latest.call.ID || latest.result.ToolName != latest.call.Name || latest.result.Validate() != nil || latest.result.Outcome != ToolOutcomeSuccess {
		return "", false
	}
	var args struct {
		ResponseMode string `json:"response_mode"`
	}
	if json.Unmarshal([]byte(latest.call.Arguments), &args) != nil || args.ResponseMode != "reply_to_user" {
		return "", false
	}
	var result struct {
		Schema              string `json:"schema"`
		Status              string `json:"status"`
		ExecutionID         string `json:"execution_id"`
		WorkerID            string `json:"worker_id"`
		PersistentWorker    bool   `json:"persistent_worker"`
		Report              string `json:"worker_report"`
		ServiceVerification string `json:"service_verification"`
		ServiceURL          string `json:"service_url"`
	}
	if json.Unmarshal([]byte(latest.result.Content), &result) != nil || result.Schema != "dirextalk.ssh-worker-completion/v1" || result.Status != "succeeded" || !validUUID(result.ExecutionID) || !validUUID(result.WorkerID) {
		return "", false
	}
	content := strings.TrimSpace(result.Report)
	if content == "" || len(content) > MaxContentBytes/2 || coremodel.ContainsUnquotedToolCallEnvelope(content) ||
		strings.Contains(content, "[Worker report truncated;") || strings.Contains(content, "/var/lib/dirextalk-worker/") || strings.Contains(content, "sandbox:") || strings.Contains(content, "file://") || strings.Contains(content, "dirextalk-artifact://") || strings.Contains(strings.ToLower(content), "<think>") {
		return "", false
	}
	if result.ServiceURL != "" {
		address, err := url.Parse(result.ServiceURL)
		if err != nil || address.Scheme != "https" || address.Host == "" || address.User != nil || strings.ContainsAny(result.ServiceURL, "\r\n()<>") {
			return "", false
		}
		label := "Open website"
		if ResponseLanguage(prompt) == "zh" {
			label = "打开网站"
		}
		content += "\n\n[" + label + "](" + result.ServiceURL + ")"
	} else if result.ServiceVerification != "" {
		// Publication still needing DNS/TLS work needs the parent to explain
		// the remaining action, not a premature whole-task completion.
		return "", false
	}
	escape := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "[", "\\[", "]", "\\]", "`", "\\`", "\\", "\\\\")
	for _, reference := range latest.result.References {
		if reference.Kind == "execution_artifact" && reference.RecordKind == "cloud_worker" && reference.ExecutionID == result.ExecutionID && reference.Validate() == nil {
			content += "\n\n- [" + escape.Replace(reference.Name) + "](dirextalk-artifact://cloud_worker/" + reference.ArtifactID + ")"
		}
	}
	if result.PersistentWorker {
		switch ResponseLanguage(prompt) {
		case "zh":
			content += "\n\n运行环境已保留，可能继续计费；实际费用尚未确认。需要我把它删除吗？"
		case "ja":
			content += "\n\n実行環境は保持されており、料金が発生し続ける可能性があります。実際の費用は未確認です。削除しますか？"
		case "ko":
			content += "\n\n실행 환경은 보존되어 추가 요금이 발생할 수 있습니다. 실제 비용은 아직 확인되지 않았습니다. 삭제할까요?"
		default:
			content += "\n\nThe environment is retained and may keep incurring charges; actual cost is not yet confirmed. Would you like it deleted?"
		}
	}
	return content, true
}

func (s *Service) commitWorkerReply(ctx context.Context, lease TurnLease, conv Conversation, first int, titleSource, content string) error {
	store, ok := s.turns.(TurnWorkerReplyStore)
	if !ok {
		return ErrInvalid
	}
	tasks, plans, references, summaries, results := turnToolMetadata(conv.Messages[first:])
	references = answerReferences(content, references, conv.Messages)
	message := Message{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-turn-worker-assistant:"+lease.Turn.RequestID)).String(), Role: RoleAssistant, Content: content, ModelProfileID: lease.Turn.ProfileID,
		CreatedAt: nextMessageTime(conv, s.clock()).Add(time.Microsecond), RelatedTaskIDs: tasks, RelatedPlanIDs: plans, References: references, ToolSummaries: summaries}
	if message.Validate() != nil {
		return ErrInvalid
	}
	_, err := store.CommitTurnWorkerReply(ctx, lease, ChatResponse{RequestID: lease.Turn.RequestID, ConversationID: lease.Turn.ConversationID, Revision: conv.Revision + 1, Message: message, Done: true, ModelProfileID: lease.Turn.ProfileID,
		RelatedTaskIDs: tasks, RelatedPlanIDs: plans, References: references, ToolSummaries: summaries, ToolResults: results, ConversationTitle: conversationTitleFallback(titleSource), ConversationTitleSource: titleSource})
	return err
}
