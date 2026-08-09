package runtime

import (
	"encoding/json"
	"strings"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	trustedTeamCompletionTool        = "central_team_completion_observation"
	trustedTeamCompletionCall        = "trusted-team-completion-observation"
	trustedTeamCompletionInstruction = "Respond to the user now using the trusted Team completion observation and the authoritative conversation context."
)

// NewTrustedTeamCompletionRequest creates the only runtime request shape that
// may advance a conversation without a new user utterance. The observation is
// retained as an assistant/tool evidence pair; the final user-role instruction
// exists only to satisfy provider chat framing and is removed before commit.
func NewTrustedTeamCompletionRequest(
	requestID string,
	ownerID string,
	conversationID string,
	expectedRevision int64,
	observationJSON string,
) (ChatRequest, error) {
	observationJSON = strings.TrimSpace(observationJSON)
	if observationJSON == "" || !json.Valid([]byte(observationJSON)) ||
		security.ContainsLikelySecret(observationJSON) {
		return ChatRequest{}, ErrInvalidRequest
	}
	request := ChatRequest{
		RequestID:                    strings.TrimSpace(requestID),
		OwnerID:                      strings.TrimSpace(ownerID),
		ConversationID:               strings.TrimSpace(conversationID),
		ExpectedConversationRevision: expectedRevision,
		TrustedObservation:           true,
		Messages: []modelapi.Message{
			{
				Role: modelapi.RoleAssistant,
				ToolCalls: []modelapi.ToolCall{{
					ID:   trustedTeamCompletionCall,
					Type: "function",
					Function: modelapi.FunctionCall{
						Name:      trustedTeamCompletionTool,
						Arguments: `{}`,
					},
				}},
			},
			{
				Role:       modelapi.RoleTool,
				Name:       trustedTeamCompletionTool,
				ToolCallID: trustedTeamCompletionCall,
				Content:    observationJSON,
			},
			{
				Role:    modelapi.RoleUser,
				Content: trustedTeamCompletionInstruction,
			},
		},
	}
	if err := validateTrustedObservationMessages(request.Messages); err != nil {
		return ChatRequest{}, err
	}
	return request, nil
}

func validateTrustedObservationMessages(messages []modelapi.Message) error {
	if len(messages) != 3 ||
		messages[0].Role != modelapi.RoleAssistant ||
		strings.TrimSpace(messages[0].Content) != "" ||
		len(messages[0].ToolCalls) != 1 ||
		messages[1].Role != modelapi.RoleTool ||
		messages[2].Role != modelapi.RoleUser ||
		messages[2].Content != trustedTeamCompletionInstruction {
		return ErrInvalidRequest
	}
	call := messages[0].ToolCalls[0]
	if call.ID != trustedTeamCompletionCall ||
		call.Type != "function" ||
		call.Function.Name != trustedTeamCompletionTool ||
		call.Function.Arguments != `{}` ||
		messages[1].Name != trustedTeamCompletionTool ||
		messages[1].ToolCallID != trustedTeamCompletionCall ||
		!json.Valid([]byte(messages[1].Content)) ||
		security.ContainsLikelySecret(messages[1].Content) {
		return ErrInvalidRequest
	}
	return nil
}
