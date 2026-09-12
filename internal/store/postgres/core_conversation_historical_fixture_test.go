package postgres

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

// Migration tests populate actual pre-group schemas with their historical row
// shape. Current admission always requires the latest scope schema and must not
// acquire a production fallback solely to construct old migration fixtures.
func insertHistoricalAdmittedTurnPG(t *testing.T, h *turnDBHarness, command core.TurnStartCommand, runtime core.TurnRuntimeSnapshot) core.Turn {
	t.Helper()
	if command.GroupOrigin != nil || runtime.GroupOrigin != nil || command.Validate() != nil || runtime.Validate() != nil {
		t.Fatal("invalid historical private turn fixture")
	}
	ctx := context.Background()
	turnID := command.TurnID
	if turnID == "" {
		turnID = uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-turn:"+command.RequestID)).String()
	}
	metadata := command.ProfileSnapshot
	metadata.APIKey = ""
	profileRaw, _ := json.Marshal(metadata)
	runtimeRaw, _ := json.Marshal(runtime)
	envelope, err := h.store.sealDurableSecret("core_conversation_turns", turnID, command.ProfileSnapshot.Revision,
		"profile_snapshot_api_key", []byte(command.ProfileSnapshot.APIKey))
	if err != nil {
		t.Fatal(err)
	}
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx, `INSERT INTO core_conversations(conversation_id,title,revision,created_at,updated_at) VALUES($1,$2,1,$3,$3)`,
		command.ConversationID, core.ProvisionalConversationTitle(command.Prompt), now); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO core_conversation_turns(
		turn_id,request_id,conversation_id,request_fingerprint,owner_id,account_generation,prompt,profile_id,
		profile_snapshot_json,profile_snapshot_digest,profile_snapshot_key_version,profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext,
		extension_snapshot_json,extension_snapshot_digest,attachment_snapshot_json,attachment_snapshot_digest,
		runtime_snapshot_json,runtime_snapshot_digest,state,revision,last_sequence,lease_epoch,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,'[]','', '[]','',$14,$15,'accepted',1,1,1,$16,$16)`,
		turnID, command.RequestID, command.ConversationID, command.Fingerprint(), command.OwnerID, command.AccountGeneration,
		command.Prompt, command.ProfileID, profileRaw, command.ProfileSnapshot.Digest(), envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext,
		runtimeRaw, runtime.Digest(), now); err != nil {
		t.Fatal(err)
	}
	eventRaw, _ := json.Marshal(core.TurnEvent{TurnID: turnID, Sequence: 1, Revision: 1, Kind: core.TurnEventAccepted, CreatedAt: now})
	if _, err := tx.Exec(ctx, `INSERT INTO core_conversation_turn_events(turn_id,sequence,kind,payload_json,created_at) VALUES($1,1,'accepted',$2,$3)`,
		turnID, eventRaw, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	turn, err := h.store.GetTurn(ctx, turnID)
	if err != nil {
		t.Fatal(err)
	}
	return turn
}
