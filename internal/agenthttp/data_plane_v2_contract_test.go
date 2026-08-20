package agenthttp

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	agentdatav2 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/agent/data/v2"
	"github.com/google/uuid"
)

const capabilityAPIModule = "github.com/YingSuiAI/dirextalk-capability-api"
const capabilityAPIVersion = "v1.2.0"

type conformanceManifest struct {
	Contract string `json:"contract"`
	Version  int    `json:"version"`
	Vectors  []struct {
		File   string `json:"file"`
		Schema string `json:"schema"`
		Valid  bool   `json:"valid"`
		Rule   string `json:"rule,omitempty"`
	} `json:"vectors"`
}

func TestAgentDataPlaneV2SharedConformanceVectors(t *testing.T) {
	moduleDir := capabilityAPIModuleDir(t)
	vectorDir := filepath.Join(moduleDir, "conformance", "agent-data-plane", "v2")
	manifestRaw, err := os.ReadFile(filepath.Join(vectorDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest conformanceManifest
	if err := strictJSON(manifestRaw, &manifest); err != nil || manifest.Contract != "dirextalk-agent-data-plane" || manifest.Version != 2 || len(manifest.Vectors) == 0 {
		t.Fatalf("invalid shared conformance manifest: %+v, %v", manifest, err)
	}
	for _, vector := range manifest.Vectors {
		vector := vector
		t.Run(strings.ReplaceAll(vector.File, "/", "_"), func(t *testing.T) {
			raw, readErr := os.ReadFile(filepath.Join(vectorDir, filepath.FromSlash(vector.File)))
			if readErr != nil {
				t.Fatal(readErr)
			}
			err := validateSharedVector(vector.Schema, raw)
			if vector.Valid && err != nil {
				t.Fatalf("valid shared vector rejected: %v", err)
			}
			if !vector.Valid && err == nil {
				t.Fatal("invalid shared vector accepted")
			}
		})
	}
}

func capabilityAPIModuleDir(t *testing.T) string {
	t.Helper()
	command := exec.Command("go", "list", "-m", "-f", "{{if .Replace}}REPLACED{{else}}{{.Version}}{{end}}\t{{.Dir}}", capabilityAPIModule)
	command.Dir = filepath.Clean("../..")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("locate pinned Capability API module: %v", err)
	}
	fields := strings.SplitN(strings.TrimSpace(string(output)), "\t", 2)
	if len(fields) != 2 || fields[0] != capabilityAPIVersion || fields[1] == "" {
		t.Fatalf("Capability API must be an immutable %s module pin, got %q", capabilityAPIVersion, strings.TrimSpace(string(output)))
	}
	return fields[1]
}

func validateSharedVector(schema string, raw []byte) error {
	switch schema {
	case "AgentSessionResponse":
		var value agentdatav2.AgentSessionResponse
		if err := strictJSON(raw, &value); err != nil {
			return err
		}
		if value.Ticket == "" || value.ExpiresAt.IsZero() || value.ServerTime.IsZero() || value.SessionId == uuid.Nil || value.BasePath != agentdatav2.AgentSessionResponseBasePathAgentv1 || len(value.Scopes) == 0 {
			return errors.New("invalid AgentSessionResponse")
		}
		for _, scope := range value.Scopes {
			if scope != agentdatav2.AgentDataScopeAgentChatRead && scope != agentdatav2.AgentDataScopeAgentChatWrite {
				return errors.New("unexpected session scope")
			}
		}
		return nil
	case "OperationReceipt":
		var value agentdatav2.OperationReceipt
		if err := strictJSON(raw, &value); err != nil {
			return err
		}
		if value.OperationId == uuid.Nil || value.IdempotencyKey == uuid.Nil {
			return errors.New("invalid operation receipt identity")
		}
		_, err := dataPlaneOperationState(string(value.State))
		return err
	case "TurnOperationReceipt":
		var value agentdatav2.TurnOperationReceipt
		if err := strictJSON(raw, &value); err != nil {
			return err
		}
		if value.OperationId == uuid.Nil || value.TurnId == uuid.Nil || value.OperationId != value.TurnId || value.IdempotencyKey == uuid.Nil {
			return errors.New("invalid Turn receipt identity")
		}
		_, err := dataPlaneOperationState(string(value.State))
		return err
	case "OperationSnapshot":
		var value agentdatav2.OperationSnapshot
		if err := strictJSON(raw, &value); err != nil {
			return err
		}
		if value.OperationId == uuid.Nil || value.Sequence < 0 {
			return errors.New("invalid operation snapshot")
		}
		_, err := dataPlaneOperationState(string(value.State))
		return err
	case "ErrorEnvelope":
		var value agentdatav2.ErrorEnvelope
		if err := strictJSON(raw, &value); err != nil {
			return err
		}
		return validateErrorEnvelope(value)
	case "OperationSseEnvelope":
		var value agentdatav2.OperationSseEnvelope
		if err := strictJSON(raw, &value); err != nil {
			return err
		}
		if value.OperationId == uuid.Nil || value.Sequence < 0 || value.Type == "" || value.Payload == nil || value.CreatedAt.IsZero() {
			return errors.New("invalid operation SSE envelope")
		}
		return nil
	case "TurnSseEnvelope":
		var value agentdatav2.TurnSseEnvelope
		if err := strictJSON(raw, &value); err != nil {
			return err
		}
		if value.OperationId == uuid.Nil || value.TurnId == uuid.Nil || value.ConversationId == uuid.Nil || value.OperationId != value.TurnId || value.Sequence < 0 || value.Type == "" || value.Payload == nil || value.CreatedAt.IsZero() {
			return errors.New("invalid Turn SSE envelope")
		}
		return nil
	default:
		return errors.New("unknown conformance schema")
	}
}

func validateErrorEnvelope(value agentdatav2.ErrorEnvelope) error {
	if !regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`).MatchString(value.Code) || value.Message == "" || value.RequestId == "" {
		return errors.New("invalid error envelope fields")
	}
	switch value.Category {
	case agentdatav2.ErrorCategoryAuthentication, agentdatav2.ErrorCategoryAuthorization,
		agentdatav2.ErrorCategoryValidation, agentdatav2.ErrorCategoryNotFound,
		agentdatav2.ErrorCategoryConflict, agentdatav2.ErrorCategoryRateLimit,
		agentdatav2.ErrorCategoryUnavailable, agentdatav2.ErrorCategoryUpstream,
		agentdatav2.ErrorCategoryInternal:
	default:
		return errors.New("invalid error category")
	}
	if value.RetryAfterMs != nil && *value.RetryAfterMs < 0 {
		return errors.New("invalid retry delay")
	}
	return nil
}

func TestRetryAfterHeaderMatchesErrorEnvelopeDelay(t *testing.T) {
	recorder := httptest.NewRecorder()
	envelope := dataPlaneError(http.StatusTooManyRequests, "AGENT_OPERATION_RESOURCE_EXHAUSTED", "Agent provider rate limit was reached", withRetryAfter(1500*time.Millisecond))
	writeDataPlaneError(recorder, http.StatusTooManyRequests, envelope)
	var decoded agentdatav2.ErrorEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if recorder.Header().Get("Retry-After") != "2" || decoded.RetryAfterMs == nil || *decoded.RetryAfterMs != 1500 || !decoded.Retryable || decoded.Category != agentdatav2.ErrorCategoryRateLimit {
		t.Fatalf("response=%d headers=%v body=%s", recorder.Code, recorder.Header(), recorder.Body.String())
	}
}

func TestAuthoritativeScopeAdapterRejectsUnknownDescriptorScope(t *testing.T) {
	for _, expected := range []agentdatav2.AgentDataScope{
		agentdatav2.AgentDataScopeAgentChatWrite,
		agentdatav2.AgentDataScopeAgentServersRead,
		agentdatav2.AgentDataScopeAgentServersWrite,
		agentdatav2.AgentDataScopeAgentServersDestroy,
	} {
		if scope, ok := authoritativeAgentDataScope(string(expected)); !ok || scope != expected {
			t.Fatalf("generated scope was not recognized: %q, %v", scope, ok)
		}
	}
	if scope, ok := authoritativeAgentDataScope("test:write"); ok || scope != "" {
		t.Fatalf("unknown scope crossed the generated enum boundary: %q, %v", scope, ok)
	}
}

func TestErrorAdapterEnforcesGeneratedCodeAndMessageBounds(t *testing.T) {
	envelope := dataPlaneError(http.StatusBadGateway, "9 provider.bad-code", strings.Repeat("界", 513))
	if envelope.Code != "AGENT_9_PROVIDER_BAD_CODE" || len([]rune(envelope.Message)) != 512 {
		t.Fatalf("bounded envelope = %+v", envelope)
	}
	if err := validateErrorEnvelope(envelope); err != nil {
		t.Fatal(err)
	}
}
