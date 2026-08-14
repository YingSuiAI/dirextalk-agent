package coreexecutionv2

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
)

var actionNames = []string{
	"agent.execution.v2.plans.get",
	"agent.execution.v2.plans.list",
	"agent.execution.v2.runs.get",
	"agent.execution.v2.runs.list",
	"agent.execution.v2.runs.cancel",
	"agent.execution.v2.runs.events",
	"agent.execution.v2.artifacts.get",
	"agent.execution.v2.artifacts.download",
}

var actionSet = func() map[string]struct{} {
	result := make(map[string]struct{}, len(actionNames))
	for _, action := range actionNames {
		result[action] = struct{}{}
	}
	return result
}()

var sha256RE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func Actions() []string { return append([]string(nil), actionNames...) }

type Service struct{ cloudWorker CloudWorkerExecutionPort }

func NewService(cloudWorker CloudWorkerExecutionPort) (*Service, error) {
	if cloudWorker == nil {
		return nil, ErrInvalid
	}
	return &Service{cloudWorker: cloudWorker}, nil
}

func (s *Service) Ready() bool               { return s != nil && s.cloudWorker != nil }
func (s *Service) ReadyForPublication() bool { return s.Ready() }
func (s *Service) ReadinessReason() string {
	if s.Ready() {
		return ""
	}
	return "execution.v2 Cloud Worker route is not ready"
}
func (s *Service) ActionReady(action string) bool {
	_, known := actionSet[action]
	return known && s.Ready()
}

func (s *Service) Handle(ctx context.Context, owner, action string, params map[string]any) (map[string]any, error) {
	return s.HandleWithAuthority(ctx, Authority{OwnerID: owner}, action, params)
}

func (s *Service) HandleWithAuthority(ctx context.Context, authority Authority, action string, params map[string]any) (map[string]any, error) {
	if !s.Ready() {
		return nil, ErrNotReady
	}
	authority.OwnerID = strings.TrimSpace(authority.OwnerID)
	if authority.OwnerID == "" || authority.AccountGeneration == 0 {
		return nil, ErrInvalid
	}
	if _, known := actionSet[action]; !known {
		return nil, ErrInvalid
	}
	params = cloneMap(params)
	if stringParam(params, "record_kind") != RecordKindCloudWorker {
		return nil, ErrInvalid
	}
	if err := validateCloudWorkerInput(action, params); err != nil {
		return nil, err
	}
	return s.handleCloudWorker(ctx, authority, action, params)
}

func validateCloudWorkerInput(action string, in map[string]any) error {
	requireID := func(key string) error {
		_, err := idParam(in, key)
		return err
	}
	switch action {
	case "agent.execution.v2.plans.get":
		return requireID("plan_id")
	case "agent.execution.v2.plans.list", "agent.execution.v2.runs.list":
		if size := intParam(in, "page_size", 100); size < 1 || size > 200 {
			return ErrInvalid
		}
		return nil
	case "agent.execution.v2.runs.get":
		return requireID("run_id")
	case "agent.execution.v2.runs.cancel":
		if requireID("run_id") != nil || requireID("idempotency_key") != nil || uintParam(in, "expected_revision") == 0 {
			return ErrInvalid
		}
		return nil
	case "agent.execution.v2.runs.events":
		if requireID("run_id") != nil {
			return ErrInvalid
		}
		if limit := intParam(in, "limit", 100); limit < 1 || limit > 200 {
			return ErrInvalid
		}
		return nil
	case "agent.execution.v2.artifacts.get":
		return requireID("artifact_id")
	case "agent.execution.v2.artifacts.download":
		if requireID("artifact_id") != nil {
			return ErrInvalid
		}
		offset, offsetOK := uintParamChecked(in, "offset_bytes")
		chunk, chunkOK := uintParamChecked(in, "max_chunk_bytes")
		if !offsetOK || !chunkOK || offset > MaxCloudWorkerArtifactDownloadOffsetBytes || chunk == 0 || chunk > MaxCloudWorkerArtifactDownloadChunkBytes {
			return ErrInvalid
		}
		return nil
	default:
		return ErrUnsupported
	}
}

func stringParam(params map[string]any, key string) string {
	value, _ := params[key].(string)
	return strings.TrimSpace(value)
}

func idParam(params map[string]any, key string) (string, error) {
	value := stringParam(params, key)
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return "", fmt.Errorf("%w: %s must be a UUID", ErrInvalid, key)
	}
	return value, nil
}

func intParam(in map[string]any, key string, fallback int) int {
	value, present := in[key]
	if !present {
		return fallback
	}
	switch number := value.(type) {
	case float64:
		if number >= 0 && number == float64(int(number)) {
			return int(number)
		}
	case int:
		return number
	case int64:
		return int(number)
	case uint64:
		return int(number)
	}
	return -1
}

func uintParam(in map[string]any, key string) uint64 {
	value, _ := uintParamChecked(in, key)
	return value
}

func uintParamChecked(in map[string]any, key string) (uint64, bool) {
	value, present := in[key]
	if !present {
		return 0, false
	}
	switch number := value.(type) {
	case float64:
		if number >= 0 && number == float64(uint64(number)) {
			return uint64(number), true
		}
	case int:
		if number >= 0 {
			return uint64(number), true
		}
	case int64:
		if number >= 0 {
			return uint64(number), true
		}
	case uint64:
		return number, true
	}
	return 0, false
}

func validateSafeInput(value any) error {
	var walk func(any, int) bool
	walk = func(value any, depth int) bool {
		if depth > 16 {
			return false
		}
		switch item := value.(type) {
		case map[string]any:
			for _, nested := range item {
				if !walk(nested, depth+1) {
					return false
				}
			}
		case []any:
			for _, nested := range item {
				if !walk(nested, depth+1) {
					return false
				}
			}
		case string:
			return len(item) <= 16<<10
		case nil, bool, float64:
			return true
		default:
			return false
		}
		return true
	}
	if !walk(value, 0) {
		return ErrUnsafeOutput
	}
	return nil
}
