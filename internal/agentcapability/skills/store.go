package skills

import (
	"context"
	"encoding/json"
)

// Skill represents a callable skill
type Skill struct {
	ID          string
	OwnerID     string
	Name        string
	Description string
	Config      map[string]interface{}
	Enabled     bool
	Type        string // builtin, mcp, custom
}

// MCPServer represents an MCP server configuration
type MCPServer struct {
	ID        string
	Name      string
	Endpoint  string
	Config    map[string]interface{}
	Connected bool
}

// SkillStore manages skills and MCP servers
type SkillStore struct {
	db interface{}
}

func NewSkillStore(db interface{}) *SkillStore {
	return &SkillStore{db: db}
}

// ListSkills lists all available skills
func (s *SkillStore) ListSkills(ctx context.Context, ownerID string) ([]*Skill, error) {
	// TODO: Migrate from native_agent skills logic
	builtinSkills := []*Skill{
		{
			ID:          "skill_web_search",
			Name:        "web_search",
			Description: "Search the web for information",
			Type:        "builtin",
			Enabled:     true,
		},
		{
			ID:          "skill_code_execution",
			Name:        "code_execution",
			Description: "Execute code safely",
			Type:        "builtin",
			Enabled:     false, // Disabled in embedded mode
		},
	}
	return builtinSkills, nil
}

// GetSkill retrieves a specific skill
func (s *SkillStore) GetSkill(ctx context.Context, ownerID, skillID string) (*Skill, error) {
	// TODO: Implement
	return nil, nil
}

// InvokeSkill invokes a skill with parameters
func (s *SkillStore) InvokeSkill(ctx context.Context, skillID string, params map[string]interface{}) (map[string]interface{}, error) {
	// TODO: Implement skill invocation logic
	return nil, nil
}

// ListMCPServers lists connected MCP servers
func (s *SkillStore) ListMCPServers(ctx context.Context, ownerID string) ([]*MCPServer, error) {
	// TODO: Migrate MCP logic
	return []*MCPServer{}, nil
}

// HandleOperation handles skill operations
func (c *Capability) HandleOperation(ctx context.Context, operationID string, inputJSON []byte) ([]byte, error) {
	store := NewSkillStore(nil)

	switch operationID {
	case "list_skills":
		skills, err := store.ListSkills(ctx, "owner")
		if err != nil {
			return nil, err
		}
		return json.Marshal(map[string]interface{}{"skills": skills})

	case "invoke_skill":
		var req struct {
			SkillID string                 `json:"skill_id"`
			Params  map[string]interface{} `json:"params"`
		}
		if err := json.Unmarshal(inputJSON, &req); err != nil {
			return nil, err
		}
		result, err := store.InvokeSkill(ctx, req.SkillID, req.Params)
		if err != nil {
			return nil, err
		}
		return json.Marshal(result)

	default:
		return nil, nil
	}
}
