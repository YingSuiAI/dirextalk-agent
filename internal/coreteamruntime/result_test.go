package coreteamruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
)

func TestBuildResultProducesCanonicalCoreTeamPayload(t *testing.T) {
	t.Parallel()

	result, err := buildResult(piFinal{
		Status:       "completed",
		Summary:      "Implemented the requested change.",
		Deliverables: []string{"source patch"},
		Tests:        []string{"go test ./..."},
		Risks:        []string{},
	}, coreteamworker.ResultUsageV1{
		InputTokens:           140,
		CachedInputTokens:     20,
		OutputTokens:          24,
		ReasoningOutputTokens: 6,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion != coreteamworker.ResultSchemaVersion || result.Status != "completed" ||
		result.Summary != "Implemented the requested change." || result.Usage.InputTokens != 140 {
		t.Fatalf("result = %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coreteamworker.ParseResultPayloadV1(encoded); err != nil {
		t.Fatalf("core Team payload rejected: %v", err)
	}
}

func TestBuildResultMetadataBindsSizeDigestAndPayload(t *testing.T) {
	t.Parallel()

	result, err := buildResult(piFinal{
		Status: "partial", Summary: "Completed the bounded portion.",
		Deliverables: []string{}, Tests: []string{}, Risks: []string{"follow-up required"},
	}, coreteamworker.ResultUsageV1{})
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := BuildResultMetadata(result)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(metadata.PayloadJSON)
	if metadata.SchemaVersion != coreteamworker.ResultSchemaVersion ||
		metadata.SizeBytes != uint64(len(metadata.PayloadJSON)) ||
		metadata.Digest != hex.EncodeToString(digest[:]) || metadata.Validate() != nil {
		t.Fatalf("metadata = %+v", metadata)
	}

	metadata.PayloadJSON[0] ^= 1
	if metadata.Validate() == nil {
		t.Fatal("tampered result metadata was accepted")
	}
}

func TestBuildResultRejectsSecretAndOversizedFinal(t *testing.T) {
	t.Parallel()

	for name, final := range map[string]piFinal{
		"secret": {
			Status: "completed", Summary: "api_key=super-secret-provider-value", Deliverables: []string{}, Tests: []string{}, Risks: []string{},
		},
		"oversized": {
			Status: "completed", Summary: string(make([]byte, coreteamworker.MaxResultTextBytes+1)), Deliverables: []string{}, Tests: []string{}, Risks: []string{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := buildResult(final, coreteamworker.ResultUsageV1{}); err == nil {
				t.Fatal("unsafe Pi final was accepted")
			}
		})
	}
}
