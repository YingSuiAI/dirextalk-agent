package postgres

import (
	"context"
	"encoding/json"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/jackc/pgx/v5"
)

func equalGroupOriginPG(left, right *core.GroupOrigin) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func decodeConversationGroupScope(raw []byte, conversation *core.Conversation) error {
	if len(raw) == 0 {
		return nil
	}
	var scope core.GroupConversationScope
	if json.Unmarshal(raw, &scope) != nil || scope.Validate() != nil || conversation.ID != scope.ConversationID() {
		return core.ErrConflict
	}
	conversation.GroupScope = &scope
	return nil
}

// The row lock serializes private/group admission and rejects namespace
// collisions. Its scope is insert-only, also enforced by the schema trigger.
func validateConversationGroupScopeTx(ctx context.Context, tx pgx.Tx, conversationID string, origin *core.GroupOrigin) error {
	var raw []byte
	if err := tx.QueryRow(ctx, `SELECT group_scope_json FROM core_conversations WHERE conversation_id=$1 AND deleted_at IS NULL FOR UPDATE`, conversationID).Scan(&raw); err != nil {
		return core.ErrConflict
	}
	conversation := core.Conversation{ID: conversationID}
	if err := decodeConversationGroupScope(raw, &conversation); err != nil {
		return err
	}
	if origin == nil && conversation.GroupScope == nil {
		return nil
	}
	if origin == nil || conversation.GroupScope == nil || *conversation.GroupScope != origin.Scope() {
		return core.ErrGroupAuthorization
	}
	return nil
}

func (s *CoreConversationStore) ListActiveGroupTurns(ctx context.Context) ([]core.Turn, error) {
	rows, err := s.pool.Query(ctx, `SELECT t.turn_id FROM core_conversation_turns t
		JOIN core_conversations c ON c.conversation_id=t.conversation_id
		WHERE c.group_scope_json IS NOT NULL AND t.state IN ('accepted','running','waiting_confirmation')
		ORDER BY t.created_at,t.turn_id`)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	turns := make([]core.Turn, 0, len(ids))
	for _, id := range ids {
		turn, err := s.GetTurn(ctx, id)
		if err != nil {
			return nil, err
		}
		if turn.GroupOrigin == nil {
			return nil, core.ErrGroupAuthorization
		}
		if turn.State == core.TurnAccepted || turn.State == core.TurnRunning || turn.State == core.TurnWaitingConfirmation {
			turns = append(turns, turn)
		}
	}
	return turns, nil
}
