package corememory

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
)

type extractionEnvelope struct {
	SchemaVersion int         `json:"schema_version"`
	Candidates    []Candidate `json:"candidates"`
}

// ParseCandidates accepts only the versioned JSON extraction contract. It is
// intentionally strict because markdown or prose is not a durable protocol.
func ParseCandidates(raw string, limit int) ([]Candidate, error) {
	if limit < 1 || limit > MaxCandidates {
		return nil, ErrInvalid
	}
	value := strings.TrimSpace(raw)
	if strings.HasPrefix(value, "```") {
		lines := strings.Split(value, "\n")
		if len(lines) < 3 || strings.TrimSpace(lines[len(lines)-1]) != "```" {
			return nil, ErrInvalid
		}
		header := strings.ToLower(strings.TrimSpace(lines[0]))
		if header != "```" && header != "```json" {
			return nil, ErrInvalid
		}
		value = strings.TrimSpace(strings.Join(lines[1:len(lines)-1], "\n"))
	}
	decoder := json.NewDecoder(bytes.NewBufferString(value))
	decoder.DisallowUnknownFields()
	var envelope extractionEnvelope
	if err := decoder.Decode(&envelope); err != nil || envelope.SchemaVersion != CandidateSchemaVersion || len(envelope.Candidates) > MaxCandidates {
		return nil, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrInvalid
	}
	out := make([]Candidate, 0, min(limit, len(envelope.Candidates)))
	for _, candidate := range envelope.Candidates {
		candidate = candidate.Normalize()
		if err := candidate.Validate(); err != nil {
			return nil, err
		}
		if len(out) < limit {
			out = append(out, candidate)
		}
	}
	return out, nil
}
