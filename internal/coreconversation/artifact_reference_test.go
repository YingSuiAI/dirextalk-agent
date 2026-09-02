package coreconversation

import (
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestExecutionArtifactReferencePreservesFencesForBothRecords(t *testing.T) {
	for _, kind := range []string{"local_sandbox", "cloud_worker"} {
		t.Run(kind, func(t *testing.T) {
			size := uint64(4)
			valid := Reference{Kind: "execution_artifact", AccountGeneration: 7, RecordKind: kind, ArtifactID: uuid.NewString(), ExecutionID: uuid.NewString(), Name: "results/a.txt", MediaType: "text/plain", SizeBytes: &size, SHA256: strings.Repeat("a", 64)}
			if valid.Validate() != nil {
				t.Fatal("valid reference rejected")
			}
			for name, mutate := range map[string]func(*Reference){
				"missing generation":     func(r *Reference) { r.AccountGeneration = 0 },
				"invalid artifact UUID":  func(r *Reference) { r.ArtifactID = "bad" },
				"invalid execution UUID": func(r *Reference) { r.ExecutionID = "bad" },
				"unsupported record":     func(r *Reference) { r.RecordKind = "other" },
				"path traversal":         func(r *Reference) { r.Name = "../secret" },
				"absolute path":          func(r *Reference) { r.Name = "/secret" },
				"backslash":              func(r *Reference) { r.Name = `a\b` },
				"oversized name":         func(r *Reference) { r.Name = strings.Repeat("a", 1025) },
				"media injection":        func(r *Reference) { r.MediaType = "text/plain\r\nX: bad" },
				"missing size":           func(r *Reference) { r.SizeBytes = nil },
				"oversized artifact":     func(r *Reference) { size := uint64(64<<20 + 1); r.SizeBytes = &size },
				"bad digest":             func(r *Reference) { r.SHA256 = strings.Repeat("A", 64) },
				"unrelated authority":    func(r *Reference) { r.TaskID = uuid.NewString() },
			} {
				t.Run(name, func(t *testing.T) {
					invalid := valid
					mutate(&invalid)
					if invalid.Validate() == nil {
						t.Fatal("invalid reference accepted")
					}
				})
			}
		})
	}
}

func TestAnswerReferencesPrioritizeOnlyKnownCanonicalArtifactURIs(t *testing.T) {
	size := uint64(4)
	artifact := Reference{Kind: "execution_artifact", AccountGeneration: 7, RecordKind: "cloud_worker", ArtifactID: uuid.NewString(), ExecutionID: uuid.NewString(), Name: "result.txt", MediaType: "text/plain", SizeBytes: &size, SHA256: strings.Repeat("a", 64)}
	uri := "dirextalk-artifact://cloud_worker/" + artifact.ArtifactID
	rooms := make([]Reference, MaxReferences)
	for i := range rooms {
		rooms[i] = Reference{Kind: "room", RoomID: "!" + uuid.NewString() + ":example.test"}
	}
	transcript := []Message{{Role: RoleTool, ToolResults: []ToolResult{{References: []Reference{artifact}}}}}
	for _, target := range []string{uri, "<" + uri + ">", uri + ` "Result"`} {
		got := answerReferences("[Result]("+target+")", rooms, transcript)
		want := append([]Reference{artifact}, rooms[:MaxReferences-1]...)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("known target %q lost reference", target)
		}
	}
	for _, target := range []string{
		uri + "?token=secret", uri + "#fragment", uri + "/extra", uri + "%20", "dirextalk-artifact://owner@cloud_worker/" + artifact.ArtifactID,
		"dirextalk-artifact://cloud_worker/" + uuid.NewString(), "sandbox:/cloud-worker/artifacts/result.txt",
	} {
		if got := answerReferences("[Result]("+target+")", rooms, transcript); !reflect.DeepEqual(got, rooms) {
			t.Fatalf("noncanonical/unknown target %q gained authority", target)
		}
	}
	for _, mutate := range []func(*Reference){
		func(r *Reference) { r.ArtifactID = uuid.NewString() },
		func(r *Reference) { r.AccountGeneration++ },
		func(r *Reference) { r.SHA256 = strings.Repeat("b", 64) },
	} {
		forged := artifact
		mutate(&forged)
		if got := answerReferences("done", []Reference{forged}, transcript); len(got) != 0 {
			t.Fatalf("model metadata created authority: %+v", got)
		}
	}
	// A user message with a syntactically valid reference is not a receipt.
	if got := answerReferences("[Result]("+uri+")", []Reference{artifact}, []Message{{Role: RoleUser, References: []Reference{artifact}}}); len(got) != 0 {
		t.Fatal("user reference became a verified receipt")
	}
}
