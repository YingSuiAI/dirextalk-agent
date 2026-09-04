package postgres

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

func TestDurableTurnDispatchEnvelopeExcludesTransientProviderReasoning(t *testing.T) {
	result := core.ModelRunResult{TransientProviderReasoning: "private provider reasoning"}
	envelope, err := newDurableTurnDispatchEnvelope(result)
	if err != nil {
		t.Fatal(err)
	}
	if envelope.Result.TransientProviderReasoning != "" {
		t.Fatalf("durable envelope retained transient reasoning: %+v", envelope.Result)
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("reasoning")) {
		t.Fatalf("durable envelope JSON exposed transient reasoning: %s", raw)
	}
}

func TestReferenceArrayJSONPGAlwaysEncodesJSONArray(t *testing.T) {
	tests := []struct {
		name   string
		values []core.Reference
		length int
	}{
		{name: "nil", values: nil, length: 0},
		{name: "empty", values: []core.Reference{}, length: 0},
		{name: "value", values: []core.Reference{{Kind: "conversation"}}, length: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw, err := referenceArrayJSONPG(test.values)
			if err != nil {
				t.Fatal(err)
			}
			var decoded []json.RawMessage
			if err := json.Unmarshal(raw, &decoded); err != nil || decoded == nil || len(decoded) != test.length {
				t.Fatalf("encoded=%s length=%d err=%v", raw, len(decoded), err)
			}
		})
	}
}

func TestProjectCloudWorkerRunReferencesRequiresDurableRunPresence(t *testing.T) {
	reference := core.Reference{
		Kind: "execution_run", AccountGeneration: 7, TaskID: "task", PlanID: "plan", PlanRevision: 3,
		RunID: "run", RunRevision: 5, ExecutionID: "execution", WorkerID: "worker", Status: "succeeded",
	}
	execution := cloudworker.Execution{
		OwnerID: "owner", AccountGeneration: 7, TaskID: "task", PlanID: "plan", PlanRevision: 3,
		RunID: "run", Revision: 5, ExecutionID: "execution", WorkerID: "worker", State: cloudworker.StateSucceeded,
		ConversationID: "conversation",
	}
	conversation := func() core.Conversation {
		return core.Conversation{ID: "conversation", Messages: []core.Message{{References: []core.Reference{
			{Kind: "execution_plan", TaskID: "task", PlanID: "plan"},
			reference,
			{Kind: "execution_run", RunID: "generic-run"},
		}}}}
	}

	available := conversation()
	projectCloudWorkerRunReferences(&available, map[string]cloudworker.Execution{"run": execution})
	if len(available.Messages[0].References) != 3 {
		t.Fatalf("available references = %+v", available.Messages[0].References)
	}

	missing := conversation()
	projectCloudWorkerRunReferences(&missing, nil)
	if references := missing.Messages[0].References; len(references) != 2 || references[0].Kind != "execution_plan" || references[1].RunID != "generic-run" {
		t.Fatalf("missing authority references = %+v", references)
	}

	historical := conversation()
	execution.Revision++
	projectCloudWorkerRunReferences(&historical, map[string]cloudworker.Execution{"run": execution})
	if len(historical.Messages[0].References) != 3 {
		t.Fatalf("historical references = %+v", historical.Messages[0].References)
	}

	foreign := conversation()
	execution.ConversationID = "other-conversation"
	projectCloudWorkerRunReferences(&foreign, map[string]cloudworker.Execution{"run": execution})
	if len(foreign.Messages[0].References) != 2 {
		t.Fatalf("foreign references = %+v", foreign.Messages[0].References)
	}
}
