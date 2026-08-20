package postgres

import (
	"bytes"
	"encoding/json"
	"testing"

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
