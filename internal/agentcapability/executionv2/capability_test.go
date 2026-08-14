package executionv2

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestArtifactOperationsPublishBothRecordKindsAndDeleteIsMutation(t *testing.T) {
	for _, action := range []string{
		"agent.execution.v2.artifacts.get",
		"agent.execution.v2.artifacts.download",
		"agent.execution.v2.artifacts.delete",
	} {
		var schema struct {
			Properties map[string]struct {
				Enum []string `json:"enum"`
			} `json:"properties"`
		}
		if err := json.Unmarshal([]byte(inputSchema(action)), &schema); err != nil {
			t.Fatal(err)
		}
		if got, want := schema.Properties["record_kind"].Enum, []string{"cloud_worker", "local_sandbox"}; !reflect.DeepEqual(got, want) {
			t.Fatalf("%s record kinds = %v", action, got)
		}
	}
	if isRead("agent.execution.v2.artifacts.delete") {
		t.Fatal("artifact delete must be published as a mutation")
	}
	if action, ok := actionForOperation("artifacts_delete"); !ok || action != "agent.execution.v2.artifacts.delete" {
		t.Fatalf("artifacts_delete mapping = %q, %v", action, ok)
	}
	var result struct {
		Properties map[string]struct {
			Const *bool `json:"const"`
		} `json:"properties"`
		Required []string `json:"required"`
	}
	if err := json.Unmarshal([]byte(resultSchema("agent.execution.v2.artifacts.delete")), &result); err != nil {
		t.Fatal(err)
	}
	if _, ok := result.Properties["artifact"]; !ok {
		t.Fatal("artifact delete result does not publish deleted artifact identity")
	}
	deleted, ok := result.Properties["deleted"]
	if !ok || deleted.Const == nil || !*deleted.Const {
		t.Fatal("artifact delete result does not publish deleted=true")
	}
	if !reflect.DeepEqual(result.Required, []string{"artifact", "deleted"}) {
		t.Fatalf("artifact delete required fields = %v", result.Required)
	}
}
