// Package coreexecutionv2 exposes the Cloud Worker plan, run and artifact
// views through the stable Execution V2 action names.
package coreexecutionv2

import (
	"encoding/json"
	"errors"
)

const (
	CapabilityID    = "agent.execution.v2"
	SemanticVersion = "2.0.0"
	SchemaVersion   = "execution-plan/v2"
)

var (
	ErrInvalid      = errors.New("execution.v2: invalid request")
	ErrNotFound     = errors.New("execution.v2: record not found")
	ErrConflict     = errors.New("execution.v2: revision or idempotency conflict")
	ErrNotReady     = errors.New("execution.v2: capability is not ready")
	ErrUnsafeOutput = errors.New("execution.v2: unsafe provider output")
	ErrUnsupported  = errors.New("execution.v2: unsupported action")
	ErrMissingPort  = errors.New("execution.v2: provider port is not configured")
)

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	raw, err := json.Marshal(in)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if json.Unmarshal(raw, &out) != nil || out == nil {
		return map[string]any{}
	}
	return out
}
