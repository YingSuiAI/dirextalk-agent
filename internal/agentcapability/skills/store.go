package skills

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrSkillNotFound      = errors.New("skill not found")
	ErrSkillAlreadyExists = errors.New("skill already exists")
	ErrInvalidSkill       = errors.New("invalid skill")
	ErrSkillDisabled      = errors.New("skill is disabled")
	ErrMCPServerNotFound  = errors.New("mcp server not found")
	ErrToolNotFound       = errors.New("tool not found")
)

// SkillState represents the lifecycle state of a skill
type SkillState string

const (
	SkillStateInstalled SkillState = "installed"
	SkillStateEnabled   SkillState = "enabled"
	SkillStateDisabled  SkillState = "disabled"
)

// SkillType distinguishes between built-in and external skills
type SkillType string

const (
	SkillTypeBuiltIn SkillType = "builtin"
	SkillTypeExternal SkillType = "external"
	SkillTypeMCP     SkillType = "mcp"
)

// Skill represents a skill definition in the store
type Skill struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	Type           SkillType              `json:"type"`
	State          SkillState             `json:"state"`
	Description    string                 `json:"description"`
	Version        string                 `json:"version,omitempty"`
	Source         coreextension.Source   `json:"source,omitempty"`
	InstallationID string                 `json:"installation_id,omitempty"`
	Tools          []ToolDefinition       `json:"tools"`
	Config         map[string]interface{} `json:"config,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// ToolDefinition defines a tool provided by a skill
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Parameters  map[string]interface{} `json:"parameters"`
	Required    []string               `json:"required,omitempty"`
}

// MCPServer represents an MCP server configuration
type MCPServer struct {
	ID             string                 `json:"id"`
	Name           string                 `json:"name"`
	State          SkillState             `json:"state"`
	Endpoint       string                 `json:"endpoint"`
	Transport      string                 `json:"transport"`
	SecretRef      string                 `json:"secret_ref,omitempty"`
	InstallationID string                 `json:"installation_id,omitempty"`
	Config         map[string]interface{} `json:"config,omitempty"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}

// Store manages skills, MCP servers, and tool invocations
type Store struct {
	pool          *pgxpool.Pool
	mcpProvider   *mcphttp.Provider
	builtInSkills map[string]*Skill
}

// NewStore creates a new skills store
func NewStore(pool *pgxpool.Pool) (*Store, error) {
	if pool == nil {
		return nil, errors.New("pool is required")
	}

	store := &Store{
		pool:          pool,
		builtInSkills: make(map[string]*Skill),
	}

	// Register built-in skills
	store.registerBuiltInSkills()

	return store, nil
}

// SetMCPProvider sets the MCP provider for external tool invocation
func (s *Store) SetMCPProvider(provider *mcphttp.Provider) {
	s.mcpProvider = provider
}

// registerBuiltInSkills registers all built-in skills
func (s *Store) registerBuiltInSkills() {
	// Web Search skill
	s.builtInSkills["web_search"] = &Skill{
		ID:          "builtin:web_search",
		Name:        "web_search",
		Type:        SkillTypeBuiltIn,
		State:       SkillStateEnabled,
		Description: "Search the web for information",
		Version:     "1.0.0",
		Tools: []ToolDefinition{
			{
				Name:        "web_search",
				Description: "Search the web and return relevant results",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"query": map[string]interface{}{
							"type":        "string",
							"description": "Search query",
						},
						"max_results": map[string]interface{}{
							"type":        "integer",
							"description": "Maximum number of results to return",
							"default":     5,
						},
					},
				},
				Required: []string{"query"},
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Memory skills (remember/recall)
	s.builtInSkills["memory"] = &Skill{
		ID:          "builtin:memory",
		Name:        "memory",
		Type:        SkillTypeBuiltIn,
		State:       SkillStateEnabled,
		Description: "Store and retrieve information from long-term memory",
		Version:     "1.0.0",
		Tools: []ToolDefinition{
			{
				Name:        "remember",
				Description: "Store information in long-term memory",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"content": map[string]interface{}{
							"type":        "string",
							"description": "Content to remember",
						},
						"tags": map[string]interface{}{
							"type":        "array",
							"description": "Tags for categorization",
							"items": map[string]interface{}{
								"type": "string",
							},
						},
					},
				},
				Required: []string{"content"},
			},
			{
				Name:        "recall",
				Description: "Search and retrieve information from long-term memory",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"query": map[string]interface{}{
							"type":        "string",
							"description": "Search query",
						},
						"limit": map[string]interface{}{
							"type":        "integer",
							"description": "Maximum number of results",
							"default":     10,
						},
					},
				},
				Required: []string{"query"},
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}

// ListSkills returns all skills (built-in and external)
func (s *Store) ListSkills(ctx context.Context, filters map[string]interface{}) ([]Skill, error) {
	skills := make([]Skill, 0)

	// Add built-in skills
	for _, skill := range s.builtInSkills {
		if matchesFilter(skill, filters) {
			skills = append(skills, *skill)
		}
	}

	// Query external skills from database
	query := `
		SELECT id, name, type, state, description, version, source, installation_id,
		       tools, config, created_at, updated_at
		FROM agent_skills
		WHERE 1=1
	`
	args := []interface{}{}
	argIdx := 1

	if state, ok := filters["state"].(string); ok && state != "" {
		query += fmt.Sprintf(" AND state = $%d", argIdx)
		args = append(args, state)
		argIdx++
	}

	if skillType, ok := filters["type"].(string); ok && skillType != "" {
		query += fmt.Sprintf(" AND type = $%d", argIdx)
		args = append(args, skillType)
		argIdx++
	}

	query += " ORDER BY created_at DESC"

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query skills: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var skill Skill
		var toolsJSON, configJSON []byte

		err := rows.Scan(
			&skill.ID, &skill.Name, &skill.Type, &skill.State, &skill.Description,
			&skill.Version, &skill.Source, &skill.InstallationID,
			&toolsJSON, &configJSON, &skill.CreatedAt, &skill.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan skill: %w", err)
		}

		if len(toolsJSON) > 0 {
			if err := json.Unmarshal(toolsJSON, &skill.Tools); err != nil {
				return nil, fmt.Errorf("unmarshal tools: %w", err)
			}
		}

		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &skill.Config); err != nil {
				return nil, fmt.Errorf("unmarshal config: %w", err)
			}
		}

		if matchesFilter(&skill, filters) {
			skills = append(skills, skill)
		}
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate skills: %w", err)
	}

	return skills, nil
}

// GetSkill retrieves a skill by ID or name
func (s *Store) GetSkill(ctx context.Context, identifier string) (*Skill, error) {
	// Check built-in skills first
	if skill, ok := s.builtInSkills[identifier]; ok {
		return skill, nil
	}

	// Check if it's a built-in ID
	for _, skill := range s.builtInSkills {
		if skill.ID == identifier {
			return skill, nil
		}
	}

	// Query database
	query := `
		SELECT id, name, type, state, description, version, source, installation_id,
		       tools, config, created_at, updated_at
		FROM agent_skills
		WHERE id = $1 OR name = $1
		LIMIT 1
	`

	var skill Skill
	var toolsJSON, configJSON []byte

	err := s.pool.QueryRow(ctx, query, identifier).Scan(
		&skill.ID, &skill.Name, &skill.Type, &skill.State, &skill.Description,
		&skill.Version, &skill.Source, &skill.InstallationID,
		&toolsJSON, &configJSON, &skill.CreatedAt, &skill.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrSkillNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get skill: %w", err)
	}

	if len(toolsJSON) > 0 {
		if err := json.Unmarshal(toolsJSON, &skill.Tools); err != nil {
			return nil, fmt.Errorf("unmarshal tools: %w", err)
		}
	}

	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &skill.Config); err != nil {
			return nil, fmt.Errorf("unmarshal config: %w", err)
		}
	}

	return &skill, nil
}

// InstallSkill installs a new external skill
func (s *Store) InstallSkill(ctx context.Context, skill *Skill) error {
	if skill == nil {
		return ErrInvalidSkill
	}

	// Validate skill
	if err := s.validateSkill(skill); err != nil {
		return err
	}

	// Generate ID if not provided
	if skill.ID == "" {
		skill.ID = uuid.New().String()
	}

	now := time.Now()
	skill.CreatedAt = now
	skill.UpdatedAt = now

	if skill.State == "" {
		skill.State = SkillStateInstalled
	}

	toolsJSON, err := json.Marshal(skill.Tools)
	if err != nil {
		return fmt.Errorf("marshal tools: %w", err)
	}

	configJSON, err := json.Marshal(skill.Config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	query := `
		INSERT INTO agent_skills (
			id, name, type, state, description, version, source, installation_id,
			tools, config, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`

	_, err = s.pool.Exec(ctx, query,
		skill.ID, skill.Name, skill.Type, skill.State, skill.Description,
		skill.Version, skill.Source, skill.InstallationID,
		toolsJSON, configJSON, skill.CreatedAt, skill.UpdatedAt,
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return ErrSkillAlreadyExists
		}
		return fmt.Errorf("install skill: %w", err)
	}

	return nil
}

// UpdateSkill updates an existing skill
func (s *Store) UpdateSkill(ctx context.Context, skill *Skill) error {
	if skill == nil || skill.ID == "" {
		return ErrInvalidSkill
	}

	// Cannot update built-in skills
	if skill.Type == SkillTypeBuiltIn {
		return errors.New("cannot update built-in skill")
	}

	// Validate skill
	if err := s.validateSkill(skill); err != nil {
		return err
	}

	skill.UpdatedAt = time.Now()

	toolsJSON, err := json.Marshal(skill.Tools)
	if err != nil {
		return fmt.Errorf("marshal tools: %w", err)
	}

	configJSON, err := json.Marshal(skill.Config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	query := `
		UPDATE agent_skills
		SET name = $2, type = $3, state = $4, description = $5, version = $6,
		    source = $7, installation_id = $8, tools = $9, config = $10, updated_at = $11
		WHERE id = $1
	`

	result, err := s.pool.Exec(ctx, query,
		skill.ID, skill.Name, skill.Type, skill.State, skill.Description,
		skill.Version, skill.Source, skill.InstallationID,
		toolsJSON, configJSON, skill.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("update skill: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrSkillNotFound
	}

	return nil
}

// EnableSkill enables a skill
func (s *Store) EnableSkill(ctx context.Context, identifier string) error {
	return s.setSkillState(ctx, identifier, SkillStateEnabled)
}

// DisableSkill disables a skill
func (s *Store) DisableSkill(ctx context.Context, identifier string) error {
	return s.setSkillState(ctx, identifier, SkillStateDisabled)
}

// setSkillState updates the state of a skill
func (s *Store) setSkillState(ctx context.Context, identifier string, state SkillState) error {
	// Cannot change built-in skill state this way
	if _, ok := s.builtInSkills[identifier]; ok {
		return errors.New("cannot change built-in skill state")
	}

	query := `
		UPDATE agent_skills
		SET state = $2, updated_at = $3
		WHERE id = $1 OR name = $1
	`

	result, err := s.pool.Exec(ctx, query, identifier, state, time.Now())
	if err != nil {
		return fmt.Errorf("set skill state: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrSkillNotFound
	}

	return nil
}

// UninstallSkill removes a skill
func (s *Store) UninstallSkill(ctx context.Context, identifier string) error {
	// Cannot uninstall built-in skills
	if _, ok := s.builtInSkills[identifier]; ok {
		return errors.New("cannot uninstall built-in skill")
	}

	query := `DELETE FROM agent_skills WHERE id = $1 OR name = $1`

	result, err := s.pool.Exec(ctx, query, identifier)
	if err != nil {
		return fmt.Errorf("uninstall skill: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrSkillNotFound
	}

	return nil
}

// ListMCPServers returns all configured MCP servers
func (s *Store) ListMCPServers(ctx context.Context) ([]MCPServer, error) {
	query := `
		SELECT id, name, state, endpoint, transport, secret_ref, installation_id,
		       config, created_at, updated_at
		FROM agent_mcp_servers
		ORDER BY created_at DESC
	`

	rows, err := s.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query mcp servers: %w", err)
	}
	defer rows.Close()

	servers := make([]MCPServer, 0)
	for rows.Next() {
		var server MCPServer
		var configJSON []byte

		err := rows.Scan(
			&server.ID, &server.Name, &server.State, &server.Endpoint,
			&server.Transport, &server.SecretRef, &server.InstallationID,
			&configJSON, &server.CreatedAt, &server.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan mcp server: %w", err)
		}

		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &server.Config); err != nil {
				return nil, fmt.Errorf("unmarshal config: %w", err)
			}
		}

		servers = append(servers, server)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate mcp servers: %w", err)
	}

	return servers, nil
}

// GetMCPServer retrieves an MCP server by ID or name
func (s *Store) GetMCPServer(ctx context.Context, identifier string) (*MCPServer, error) {
	query := `
		SELECT id, name, state, endpoint, transport, secret_ref, installation_id,
		       config, created_at, updated_at
		FROM agent_mcp_servers
		WHERE id = $1 OR name = $1
		LIMIT 1
	`

	var server MCPServer
	var configJSON []byte

	err := s.pool.QueryRow(ctx, query, identifier).Scan(
		&server.ID, &server.Name, &server.State, &server.Endpoint,
		&server.Transport, &server.SecretRef, &server.InstallationID,
		&configJSON, &server.CreatedAt, &server.UpdatedAt,
	)

	if err == pgx.ErrNoRows {
		return nil, ErrMCPServerNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get mcp server: %w", err)
	}

	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &server.Config); err != nil {
			return nil, fmt.Errorf("unmarshal config: %w", err)
		}
	}

	return &server, nil
}

// InstallMCPServer registers a new MCP server
func (s *Store) InstallMCPServer(ctx context.Context, server *MCPServer) error {
	if server == nil {
		return errors.New("server is required")
	}

	if server.ID == "" {
		server.ID = uuid.New().String()
	}

	now := time.Now()
	server.CreatedAt = now
	server.UpdatedAt = now

	if server.State == "" {
		server.State = SkillStateInstalled
	}

	if server.Transport == "" {
		server.Transport = "streamable_http"
	}

	configJSON, err := json.Marshal(server.Config)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	query := `
		INSERT INTO agent_mcp_servers (
			id, name, state, endpoint, transport, secret_ref, installation_id,
			config, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
	`

	_, err = s.pool.Exec(ctx, query,
		server.ID, server.Name, server.State, server.Endpoint,
		server.Transport, server.SecretRef, server.InstallationID,
		configJSON, server.CreatedAt, server.UpdatedAt,
	)

	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return errors.New("mcp server already exists")
		}
		return fmt.Errorf("install mcp server: %w", err)
	}

	return nil
}

// EnableMCPServer enables an MCP server
func (s *Store) EnableMCPServer(ctx context.Context, identifier string) error {
	return s.setMCPServerState(ctx, identifier, SkillStateEnabled)
}

// DisableMCPServer disables an MCP server
func (s *Store) DisableMCPServer(ctx context.Context, identifier string) error {
	return s.setMCPServerState(ctx, identifier, SkillStateDisabled)
}

// setMCPServerState updates the state of an MCP server
func (s *Store) setMCPServerState(ctx context.Context, identifier string, state SkillState) error {
	query := `
		UPDATE agent_mcp_servers
		SET state = $2, updated_at = $3
		WHERE id = $1 OR name = $1
	`

	result, err := s.pool.Exec(ctx, query, identifier, state, time.Now())
	if err != nil {
		return fmt.Errorf("set mcp server state: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrMCPServerNotFound
	}

	return nil
}

// UninstallMCPServer removes an MCP server
func (s *Store) UninstallMCPServer(ctx context.Context, identifier string) error {
	query := `DELETE FROM agent_mcp_servers WHERE id = $1 OR name = $1`

	result, err := s.pool.Exec(ctx, query, identifier)
	if err != nil {
		return fmt.Errorf("uninstall mcp server: %w", err)
	}

	if result.RowsAffected() == 0 {
		return ErrMCPServerNotFound
	}

	return nil
}

// InvokeTool invokes a tool from a skill
func (s *Store) InvokeTool(ctx context.Context, skillID, toolName string, input map[string]interface{}) (interface{}, error) {
	skill, err := s.GetSkill(ctx, skillID)
	if err != nil {
		return nil, err
	}

	if skill.State == SkillStateDisabled {
		return nil, ErrSkillDisabled
	}

	// Find the tool
	var tool *ToolDefinition
	for i := range skill.Tools {
		if skill.Tools[i].Name == toolName {
			tool = &skill.Tools[i]
			break
		}
	}

	if tool == nil {
		return nil, ErrToolNotFound
	}

	// Handle built-in skills
	if skill.Type == SkillTypeBuiltIn {
		return s.invokeBuiltInTool(ctx, skill, tool, input)
	}

	// Handle MCP skills
	if skill.Type == SkillTypeMCP {
		return s.invokeMCPTool(ctx, skill, tool, input)
	}

	// Handle external skills through installation
	if skill.InstallationID != "" {
		return s.invokeExternalTool(ctx, skill, tool, input)
	}

	return nil, errors.New("unsupported skill type")
}

// invokeBuiltInTool handles invocation of built-in tools
func (s *Store) invokeBuiltInTool(ctx context.Context, skill *Skill, tool *ToolDefinition, input map[string]interface{}) (interface{}, error) {
	switch skill.Name {
	case "web_search":
		return s.invokeWebSearch(ctx, input)
	case "memory":
		if tool.Name == "remember" {
			return s.invokeRemember(ctx, input)
		}
		return s.invokeRecall(ctx, input)
	default:
		return nil, errors.New("unknown built-in skill")
	}
}

// invokeMCPTool invokes a tool through MCP provider
func (s *Store) invokeMCPTool(ctx context.Context, skill *Skill, tool *ToolDefinition, input map[string]interface{}) (interface{}, error) {
	if s.mcpProvider == nil {
		return nil, errors.New("mcp provider not configured")
	}

	// MCP tool invocation would go here
	// This requires integration with the MCP provider's tool invocation
	return nil, errors.New("mcp tool invocation not yet implemented")
}

// invokeExternalTool invokes a tool through the extension system
func (s *Store) invokeExternalTool(ctx context.Context, skill *Skill, tool *ToolDefinition, input map[string]interface{}) (interface{}, error) {
	// External tool invocation through coreextension would go here
	return nil, errors.New("external tool invocation not yet implemented")
}

// invokeWebSearch implements web search functionality
func (s *Store) invokeWebSearch(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	query, ok := input["query"].(string)
	if !ok || query == "" {
		return nil, errors.New("query parameter is required")
	}

	maxResults := 5
	if mr, ok := input["max_results"].(float64); ok {
		maxResults = int(mr)
	}

	// Placeholder implementation - real implementation would integrate with search API
	return map[string]interface{}{
		"query":       query,
		"results":     []map[string]interface{}{},
		"count":       0,
		"max_results": maxResults,
		"message":     "Web search not yet implemented - placeholder response",
	}, nil
}

// invokeRemember implements memory storage
func (s *Store) invokeRemember(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	content, ok := input["content"].(string)
	if !ok || content == "" {
		return nil, errors.New("content parameter is required")
	}

	// Placeholder implementation - real implementation would store in knowledge base
	return map[string]interface{}{
		"success": true,
		"message": "Memory storage not yet implemented - placeholder response",
	}, nil
}

// invokeRecall implements memory retrieval
func (s *Store) invokeRecall(ctx context.Context, input map[string]interface{}) (interface{}, error) {
	query, ok := input["query"].(string)
	if !ok || query == "" {
		return nil, errors.New("query parameter is required")
	}

	// Placeholder implementation - real implementation would query knowledge base
	return map[string]interface{}{
		"query":   query,
		"results": []map[string]interface{}{},
		"count":   0,
		"message": "Memory recall not yet implemented - placeholder response",
	}, nil
}

// validateSkill validates a skill structure
func (s *Store) validateSkill(skill *Skill) error {
	if skill.Name == "" {
		return fmt.Errorf("%w: name is required", ErrInvalidSkill)
	}

	if skill.Type == "" {
		return fmt.Errorf("%w: type is required", ErrInvalidSkill)
	}

	if len(skill.Tools) == 0 {
		return fmt.Errorf("%w: at least one tool is required", ErrInvalidSkill)
	}

	for _, tool := range skill.Tools {
		if tool.Name == "" {
			return fmt.Errorf("%w: tool name is required", ErrInvalidSkill)
		}
		if tool.Description == "" {
			return fmt.Errorf("%w: tool description is required", ErrInvalidSkill)
		}
	}

	return nil
}

// matchesFilter checks if a skill matches the given filters
func matchesFilter(skill *Skill, filters map[string]interface{}) bool {
	if state, ok := filters["state"].(string); ok && state != "" {
		if string(skill.State) != state {
			return false
		}
	}

	if skillType, ok := filters["type"].(string); ok && skillType != "" {
		if string(skill.Type) != skillType {
			return false
		}
	}

	if name, ok := filters["name"].(string); ok && name != "" {
		if !strings.Contains(strings.ToLower(skill.Name), strings.ToLower(name)) {
			return false
		}
	}

	return true
}
