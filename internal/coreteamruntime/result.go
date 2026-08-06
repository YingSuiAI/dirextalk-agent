package coreteamruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreteamworker"
)

// Result is the only value a runtime may return to the Team Worker protocol.
type Result = coreteamworker.ResultPayloadV1

type piFinal struct {
	Status       string   `json:"status"`
	Summary      string   `json:"summary"`
	Deliverables []string `json:"deliverables"`
	Tests        []string `json:"tests"`
	Risks        []string `json:"risks"`
}

func buildResult(final piFinal, usage coreteamworker.ResultUsageV1) (Result, error) {
	result := Result{
		SchemaVersion: coreteamworker.ResultSchemaVersion,
		Status:        final.Status,
		Summary:       final.Summary,
		Deliverables:  append([]string{}, final.Deliverables...),
		Tests:         append([]string{}, final.Tests...),
		Risks:         append([]string{}, final.Risks...),
		Usage:         usage,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		return Result{}, ErrInvalidResult
	}
	defer clear(encoded)
	validated, err := coreteamworker.ParseResultPayloadV1(encoded)
	if err != nil {
		return Result{}, ErrInvalidResult
	}
	return validated, nil
}

// BuildResultMetadata serializes and digest-binds one already validated result.
func BuildResultMetadata(result Result) (coreteamworker.ResultMetadata, error) {
	payload, err := json.Marshal(result)
	if err != nil {
		return coreteamworker.ResultMetadata{}, ErrInvalidResult
	}
	if _, err := coreteamworker.ParseResultPayloadV1(payload); err != nil {
		clear(payload)
		return coreteamworker.ResultMetadata{}, ErrInvalidResult
	}
	digest := sha256.Sum256(payload)
	metadata := coreteamworker.ResultMetadata{
		SchemaVersion: coreteamworker.ResultSchemaVersion,
		Digest:        hex.EncodeToString(digest[:]),
		SizeBytes:     uint64(len(payload)),
		PayloadJSON:   payload,
	}
	if metadata.Validate() != nil {
		clear(payload)
		return coreteamworker.ResultMetadata{}, ErrInvalidResult
	}
	return metadata, nil
}
