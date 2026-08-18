package coreconversation

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestWorkingContextRejectsProtectedCompressorRewrite(t *testing.T) {
	current := NewWorkingContext()
	current.OriginalGoal = "ship the requested repair"
	current.ExactUserConstraints = []string{"do not deploy production"}
	current.ExternalResources = []Reference{{Kind: "room", RoomID: "!ops:example.test", RoomType: "agent"}}
	current.ToolReceipts = cloneReferences(current.ExternalResources)
	proposal := current.Snapshot()
	proposal.Decisions = []string{"use the durable transaction seam"}
	proposal.CompletedSteps = []string{"added a regression test"}
	merged, err := ApplyWorkingContextCompression(current, proposal)
	if err != nil || !reflect.DeepEqual(merged.Decisions, proposal.Decisions) || merged.OriginalGoal != current.OriginalGoal {
		t.Fatalf("valid compressor merge=%+v err=%v", merged, err)
	}
	proposal.OriginalGoal = "replace the user's goal"
	if _, err = ApplyWorkingContextCompression(current, proposal); !errors.Is(err, ErrConflict) {
		t.Fatalf("protected goal rewrite err=%v", err)
	}
	proposal = current.Snapshot()
	proposal.ExternalResources[0].RoomType = "replacement"
	if _, err = ApplyWorkingContextCompression(current, proposal); !errors.Is(err, ErrConflict) {
		t.Fatalf("protected resource rewrite err=%v", err)
	}
}

func TestWorkingContextRetainsExactInputsAndRuntimeIdentitiesAcrossRounds(t *testing.T) {
	now := time.Now().UTC()
	profileID := uuid.NewString()
	size := uint64(42)
	artifact := Reference{Kind: "execution_artifact", AccountGeneration: 1, RecordKind: "local_sandbox", ArtifactID: uuid.NewString(), ExecutionID: uuid.NewString(), Name: "report.txt", MediaType: "text/plain", SizeBytes: &size, SHA256: strings.Repeat("a", 64)}
	first, err := AdvanceWorkingContextFromTranscript(NewWorkingContext(), []Message{
		{ID: uuid.NewString(), Role: RoleUser, Content: "original goal exactly", ModelProfileID: profileID, CreatedAt: now},
		{ID: uuid.NewString(), Role: RoleUser, Content: "keep this exact constraint", ModelProfileID: profileID, CreatedAt: now.Add(time.Second)},
		{ID: uuid.NewString(), Role: RoleTool, ToolResults: []ToolResult{{CallID: "call", ToolName: "write", Content: "written", Summary: "artifact written", References: []Reference{artifact}}}, ModelProfileID: profileID, CreatedAt: now.Add(2 * time.Second)},
	})
	if err != nil {
		t.Fatal(err)
	}
	second, err := AdvanceWorkingContextFromTranscript(first, []Message{{ID: uuid.NewString(), Role: RoleAssistant, Content: "verified the result", ModelProfileID: profileID, CreatedAt: now.Add(3 * time.Second)}})
	if err != nil {
		t.Fatal(err)
	}
	if second.OriginalGoal != "original goal exactly" || !reflect.DeepEqual(second.ExactUserConstraints, []string{"keep this exact constraint"}) ||
		!reflect.DeepEqual(second.Artifacts, []Reference{artifact}) || !reflect.DeepEqual(second.SideEffectIdentities, []Reference{artifact}) ||
		!reflect.DeepEqual(second.ToolReceipts, []Reference{artifact}) || !reflect.DeepEqual(second.CompletedSteps, []string{"artifact written"}) {
		t.Fatalf("working context lost protected state: %+v", second)
	}
}
