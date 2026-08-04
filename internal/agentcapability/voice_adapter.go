package agentcapability

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/corevoice"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
)

// VoiceProgress is wired to capability.Manager.Progress by the Agent
// composition. Keeping it optional makes the domain usable in deterministic
// unit tests while production stream operations fail closed when durable
// progress is not configured.
type VoiceProgress func(context.Context, string, []byte) error

type CoreVoiceCapability struct {
	service  *corevoice.Service
	progress VoiceProgress
}

func NewCoreVoiceCapability(service *corevoice.Service, progress VoiceProgress) *CoreVoiceCapability {
	return &CoreVoiceCapability{service: service, progress: progress}
}

func (c *CoreVoiceCapability) Descriptor() *capv1.CapabilityDescriptor {
	return &capv1.CapabilityDescriptor{
		CapabilityId: "agent.voice.v1", SemanticVersion: "1.0.0", ProtocolVersion: 1,
		DisplayName: "Voice", Description: "Agent-owned RTC voice sessions and transcript turns", Readiness: c != nil && c.service != nil,
		Operations: []*capv1.OperationDescriptor{
			voiceOperation("create_session", capv1.OperationType_OPERATION_TYPE_MUTATION, `{"type":"object","properties":{"conversation_id":{"type":"string"},"conversation_profile_id":{"type":"string"},"speech_profile_id":{"type":"string"}},"required":["conversation_id"]}`),
			voiceOperation("start_session", capv1.OperationType_OPERATION_TYPE_MUTATION, `{"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"]}`),
			voiceOperation("submit_transcript", capv1.OperationType_OPERATION_TYPE_MUTATION, `{"type":"object","properties":{"session_id":{"type":"string"},"transcript_delta":{"type":"string"},"transcript_final":{"type":"string"}},"required":["session_id"]}`),
			voiceOperation("interrupt_session", capv1.OperationType_OPERATION_TYPE_MUTATION, `{"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"]}`),
			voiceOperation("end_session", capv1.OperationType_OPERATION_TYPE_MUTATION, `{"type":"object","properties":{"session_id":{"type":"string"}},"required":["session_id"]}`),
			voiceOperation("stream_session", capv1.OperationType_OPERATION_TYPE_DURABLE_STREAM, `{"type":"object","properties":{"session_id":{"type":"string"},"after_seq":{"type":"integer","minimum":0}},"required":["session_id"]}`),
		},
	}
}

func voiceOperation(id string, typ capv1.OperationType, schema string) *capv1.OperationDescriptor {
	resultSchema := `{"type":"object","additionalProperties":true}`
	inputDigest := sha256.Sum256([]byte(schema))
	resultDigest := sha256.Sum256([]byte(resultSchema))
	return &capv1.OperationDescriptor{OperationId: id, DisplayName: id, Description: "Agent-owned voice session operation", OperationType: typ, Audience: []capv1.Audience{capv1.Audience_AUDIENCE_OWNER_CLIENT, capv1.Audience_AUDIENCE_NATIVE_AGENT}, RiskLevel: capv1.RiskLevel_RISK_LEVEL_SAFE, RequiredScopes: []string{"agent:voice:write"}, InputSchemaJson: schema, InputSchemaDigest: inputDigest[:], ResultSchemaJson: resultSchema, ResultSchemaDigest: resultDigest[:], MaxRequestSizeBytes: 1 << 20, TimeoutClass: "medium"}
}

func (c *CoreVoiceCapability) HandleOperation(ctx context.Context, operation string, raw []byte) ([]byte, error) {
	if c == nil || c.service == nil {
		return nil, corevoice.ErrUnavailable
	}
	owner, generation, key, err := voiceIdentity(ctx, raw)
	if err != nil {
		return nil, err
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, corevoice.ErrInvalid
	}
	sessionID := stringValue(in, "session_id")
	switch operation {
	case "create_session":
		value, err := c.service.Create(ctx, owner, generation, corevoice.CreateRequest{ConversationID: stringValue(in, "conversation_id"), ConversationProfileID: stringValue(in, "conversation_profile_id"), SpeechProfileID: stringValue(in, "speech_profile_id")}, key)
		return marshalVoice(value, err)
	case "start_session":
		value, err := c.service.Start(ctx, owner, generation, sessionID, key)
		return marshalVoice(value, err)
	case "submit_transcript":
		text := stringValue(in, "transcript_final")
		if text == "" {
			text = stringValue(in, "transcript_delta")
		}
		value, err := c.service.Transcript(ctx, owner, generation, sessionID, text, key)
		return marshalVoice(value, err)
	case "interrupt_session":
		value, err := c.service.Interrupt(ctx, owner, generation, sessionID, key)
		return marshalVoice(value, err)
	case "end_session":
		value, err := c.service.End(ctx, owner, generation, sessionID, key)
		return marshalVoice(value, err)
	case "stream_session":
		if c.progress == nil {
			return nil, fmt.Errorf("voice stream durable progress is not configured")
		}
		after := int64Value(in, "after_seq")
		err := c.service.Stream(ctx, owner, generation, sessionID, after, func(event corevoice.Event) error {
			payload := map[string]any{"session_id": event.SessionID, "sequence": event.Sequence, "event": event.Event, "data": json.RawMessage(event.Data)}
			eventJSON, marshalErr := json.Marshal(payload)
			if marshalErr != nil {
				return marshalErr
			}
			return c.progress(ctx, rootOperationID(ctx, key), eventJSON)
		})
		if err != nil {
			if ctx.Err() != nil {
				return marshalVoice(map[string]any{"ok": true, "session_id": sessionID, "stream_closed": true}, nil)
			}
			return nil, err
		}
		return marshalVoice(map[string]any{"ok": true, "session_id": sessionID, "stream_closed": true}, nil)
	default:
		return nil, fmt.Errorf("unknown voice operation %q", operation)
	}
}

func voiceIdentity(ctx context.Context, raw []byte) (string, int64, string, error) {
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil || strings.TrimSpace(permission.GetAuthenticatedOwnerId()) == "" || permission.GetAccountGeneration() <= 0 {
		return "", 0, "", corevoice.ErrForbidden
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return "", 0, "", corevoice.ErrInvalid
	}
	key := stringValue(in, "idempotency_key")
	if key == "" {
		key = rootOperationID(ctx, "")
	}
	if key == "" {
		return "", 0, "", corevoice.ErrInvalid
	}
	return permission.GetAuthenticatedOwnerId(), permission.GetAccountGeneration(), key, nil
}

func rootOperationID(ctx context.Context, fallback string) string {
	call, ok := capabilityclient.CallContextFromContext(ctx)
	if ok && call != nil && strings.TrimSpace(call.GetRootOperationId()) != "" {
		return call.GetRootOperationId()
	}
	return fallback
}

func marshalVoice(value any, err error) ([]byte, error) {
	if err != nil {
		return nil, err
	}
	return json.Marshal(value)
}

var _ Capability = (*CoreVoiceCapability)(nil)
