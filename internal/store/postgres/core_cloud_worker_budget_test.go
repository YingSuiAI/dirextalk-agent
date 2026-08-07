package postgres

import (
	"testing"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/google/uuid"
)

func TestWorkspaceArchiveBudgetEvidenceIsDeterministicAndTurnBound(t *testing.T) {
	turn := core.Turn{
		ID: uuid.NewString(), RequestID: uuid.NewString(), ConversationID: uuid.NewString(),
		OwnerID: "@owner:example.test", AccountGeneration: 7, Revision: 3,
		ProfileID: uuid.NewString(), AttachmentSnapshotDigest: budgetTestDigest("attachments"),
	}
	first, err := newCloudWorkerWorkspaceBudgetEvidence(turn, "analyze this workspace", turn.ProfileID, budgetTestDigest("profile"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := newCloudWorkerWorkspaceBudgetEvidence(turn, "analyze this workspace", turn.ProfileID, budgetTestDigest("profile"))
	if err != nil || *first != *second || first.Revision != cloudWorkerLocalWorkspaceBudgetPolicyRevision {
		t.Fatalf("evidence first=%+v second=%+v err=%v", first, second, err)
	}
	mutations := []func(*core.Turn){
		func(value *core.Turn) { value.OwnerID = "@other:example.test" },
		func(value *core.Turn) { value.AccountGeneration++ },
		func(value *core.Turn) { value.ID = uuid.NewString() },
		func(value *core.Turn) { value.Revision++ },
		func(value *core.Turn) { value.RequestID = uuid.NewString() },
		func(value *core.Turn) { value.ConversationID = uuid.NewString() },
		func(value *core.Turn) { value.ProfileID = uuid.NewString() },
		func(value *core.Turn) { value.AttachmentSnapshotDigest = budgetTestDigest("other attachments") },
	}
	for index, mutate := range mutations {
		changed := turn
		mutate(&changed)
		evidence, mutationErr := newCloudWorkerWorkspaceBudgetEvidence(changed, "analyze this workspace", changed.ProfileID, budgetTestDigest("profile"))
		if mutationErr != nil || evidence.Digest == first.Digest {
			t.Fatalf("mutation %d did not change evidence: %+v err=%v", index, evidence, mutationErr)
		}
	}
	changedPrompt, _ := newCloudWorkerWorkspaceBudgetEvidence(turn, "different prompt", turn.ProfileID, budgetTestDigest("profile"))
	changedProfile, _ := newCloudWorkerWorkspaceBudgetEvidence(turn, "analyze this workspace", turn.ProfileID, budgetTestDigest("different profile"))
	if changedPrompt.Digest == first.Digest || changedProfile.Digest == first.Digest {
		t.Fatal("prompt or profile snapshot drift did not change evidence")
	}
}

func budgetTestDigest(value string) string {
	return pgCloudDigest(value)
}
