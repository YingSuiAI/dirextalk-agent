package postgres

import (
	"context"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

func conversationStaticSiteCommand(t *testing.T, h *turnDBHarness) core.ConversationStaticSiteCommand {
	t.Helper()
	start := turnCommand()
	start.OwnerID = "@owner:example.test"
	start.AccountGeneration = 7
	turn, err := h.store.StartTurn(context.Background(), start)
	if err != nil {
		t.Fatal(err)
	}
	createTestProfile(context.Background(), t, h.store.Store, turn.ProfileID, "test", "integration-secret")
	lease, err := h.store.ClaimTurn(context.Background(), turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	siteID, releaseID := uuid.NewString(), uuid.NewString()
	receipt := core.StaticSiteReceipt{
		SiteID: siteID, ReleaseID: releaseID, PublicPath: "/.sites/" + siteID + "/" + releaseID + "/",
		SHA256: strings.Repeat("a", 64), SizeBytes: 29,
	}
	response := core.ChatResponse{
		RequestID: turn.RequestID, ConversationID: turn.ConversationID, Revision: 2, Done: true, ModelProfileID: turn.ProfileID,
		Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "Published the static page: " + receipt.PublicPath, ModelProfileID: turn.ProfileID, CreatedAt: now},
	}
	return core.ConversationStaticSiteCommand{Lease: lease, Receipt: receipt, Response: response}
}

func TestConversationStaticSiteCommitPersistsReceiptAndReplaysPostgres(t *testing.T) {
	h := openTurnDB(t)
	command := conversationStaticSiteCommand(t, h)
	created, err := h.store.CommitConversationStaticSite(context.Background(), command)
	if err != nil || created.AlreadyExists || created.SHA256 != command.Receipt.SHA256 {
		t.Fatalf("created=%+v err=%v", created, err)
	}
	replayed, err := h.store.CommitConversationStaticSite(context.Background(), command)
	if err != nil || !replayed.AlreadyExists || replayed != (core.StaticSiteReceipt{
		SiteID: command.Receipt.SiteID, ReleaseID: command.Receipt.ReleaseID, PublicPath: command.Receipt.PublicPath,
		SHA256: command.Receipt.SHA256, SizeBytes: command.Receipt.SizeBytes, AlreadyExists: true,
	}) {
		t.Fatalf("replayed=%+v err=%v", replayed, err)
	}
	var count int
	if err = h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_static_site_releases WHERE release_id=$1 AND turn_id=$2 AND owner_id=$3 AND account_generation=$4`, command.Receipt.ReleaseID, command.Lease.Turn.ID, command.Lease.Turn.OwnerID, command.Lease.Turn.AccountGeneration).Scan(&count); err != nil {
		t.Fatal(err)
	}
	turn, err := h.store.GetTurn(context.Background(), command.Lease.Turn.ID)
	if err != nil || count != 1 || turn.State != core.TurnCompleted || turn.Response == nil || turn.Response.Message.Content != command.Response.Message.Content {
		t.Fatalf("count=%d turn=%+v err=%v", count, turn, err)
	}
	changed := command
	changed.Receipt.SHA256 = strings.Repeat("b", 64)
	if _, err = h.store.CommitConversationStaticSite(context.Background(), changed); err != core.ErrConflict {
		t.Fatalf("changed receipt err=%v", err)
	}
}

func TestConversationStaticSiteCommitRollsBackReceiptOnTurnConflictPostgres(t *testing.T) {
	h := openTurnDB(t)
	command := conversationStaticSiteCommand(t, h)
	command.Response.Revision = 99
	if _, err := h.store.CommitConversationStaticSite(context.Background(), command); err == nil {
		t.Fatal("invalid conversation revision unexpectedly committed")
	}
	var count int
	if err := h.pool.QueryRow(context.Background(), `SELECT count(*) FROM core_static_site_releases WHERE release_id=$1`, command.Receipt.ReleaseID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	turn, err := h.store.GetTurn(context.Background(), command.Lease.Turn.ID)
	if err != nil || count != 0 || turn.State != core.TurnRunning || turn.Response != nil {
		t.Fatalf("partial commit count=%d turn=%+v err=%v", count, turn, err)
	}
}
