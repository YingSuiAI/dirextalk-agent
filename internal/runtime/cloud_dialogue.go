package runtime

import (
	"strings"

	"github.com/google/uuid"
)

const (
	CloudDialogueToolResearch        = "cloud_dispatcher_research"
	CloudDialogueToolStatus          = "cloud_dispatcher_status"
	CloudDialogueToolRecipeDraft     = "cloud_dispatcher_recipe_draft"
	CloudDialogueToolSubmitPlanDraft = "cloud_dispatcher_submit_plan_draft"
)

// CloudDialogueScope is authenticated application state. It is included in
// the durable request digest but is never copied into model messages or tool
// arguments.
type CloudDialogueScope struct {
	ConnectionID string `json:"cloud_connection_id"`
}

// NewCloudDialogueScope accepts only the canonical lower-case UUID form used
// by persisted cloud connection facts.
func NewCloudDialogueScope(connectionID string) (*CloudDialogueScope, error) {
	trimmed := strings.TrimSpace(connectionID)
	parsed, err := uuid.Parse(trimmed)
	if err != nil || parsed == uuid.Nil || trimmed != connectionID || parsed.String() != trimmed {
		return nil, ErrInvalidRequest
	}
	return &CloudDialogueScope{ConnectionID: trimmed}, nil
}

// CloudDialogueToolNames is the fixed model capability set for restricted
// cloud dialogue. Planning beyond goal creation runs in the durable control
// loop; chat cannot submit a Recipe, approve, mutate AWS, or invoke arbitrary
// configured tools.
func CloudDialogueToolNames() []string {
	return []string{CloudDialogueToolResearch}
}

func cloneCloudDialogueScope(scope *CloudDialogueScope) (*CloudDialogueScope, error) {
	if scope == nil {
		return nil, nil
	}
	return NewCloudDialogueScope(scope.ConnectionID)
}
