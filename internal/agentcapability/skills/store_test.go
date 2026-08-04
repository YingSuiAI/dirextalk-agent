package skills

import (
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

func TestBuiltInSkills(t *testing.T) {
	store := &Store{
		builtInSkills: make(map[string]*Skill),
	}
	store.registerBuiltInSkills()

	// Test web_search skill exists
	skill, err := store.GetSkill(context.Background(), "web_search")
	if err != nil {
		t.Fatalf("Failed to get web_search skill: %v", err)
	}

	if skill.Name != "web_search" {
		t.Errorf("Expected skill name 'web_search', got %s", skill.Name)
	}

	if skill.Type != SkillTypeBuiltIn {
		t.Errorf("Expected skill type 'builtin', got %s", skill.Type)
	}

	if len(skill.Tools) == 0 {
		t.Error("Expected web_search skill to have tools")
	}

	// Test memory skill exists
	skill, err = store.GetSkill(context.Background(), "memory")
	if err != nil {
		t.Fatalf("Failed to get memory skill: %v", err)
	}

	if len(skill.Tools) != 2 {
		t.Errorf("Expected memory skill to have 2 tools, got %d", len(skill.Tools))
	}
}

func TestSkillValidation(t *testing.T) {
	store := &Store{}

	tests := []struct {
		name    string
		skill   *Skill
		wantErr bool
	}{
		{
			name: "valid skill",
			skill: &Skill{
				Name:        "test_skill",
				Type:        SkillTypeExternal,
				Description: "Test skill",
				Tools: []ToolDefinition{
					{
						Name:        "test_tool",
						Description: "Test tool",
						Parameters:  map[string]interface{}{},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			skill: &Skill{
				Type: SkillTypeExternal,
				Tools: []ToolDefinition{
					{
						Name:        "test_tool",
						Description: "Test tool",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing type",
			skill: &Skill{
				Name: "test_skill",
				Tools: []ToolDefinition{
					{
						Name:        "test_tool",
						Description: "Test tool",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "no tools",
			skill: &Skill{
				Name:  "test_skill",
				Type:  SkillTypeExternal,
				Tools: []ToolDefinition{},
			},
			wantErr: true,
		},
		{
			name: "tool missing name",
			skill: &Skill{
				Name: "test_skill",
				Type: SkillTypeExternal,
				Tools: []ToolDefinition{
					{
						Description: "Test tool",
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := store.validateSkill(tt.skill)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateSkill() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestMatchesFilter(t *testing.T) {
	skill := &Skill{
		Name:  "test_skill",
		Type:  SkillTypeExternal,
		State: SkillStateEnabled,
	}

	tests := []struct {
		name    string
		filters map[string]interface{}
		want    bool
	}{
		{
			name:    "no filters",
			filters: map[string]interface{}{},
			want:    true,
		},
		{
			name: "matching state",
			filters: map[string]interface{}{
				"state": "enabled",
			},
			want: true,
		},
		{
			name: "non-matching state",
			filters: map[string]interface{}{
				"state": "disabled",
			},
			want: false,
		},
		{
			name: "matching type",
			filters: map[string]interface{}{
				"type": "external",
			},
			want: true,
		},
		{
			name: "non-matching type",
			filters: map[string]interface{}{
				"type": "builtin",
			},
			want: false,
		},
		{
			name: "matching name substring",
			filters: map[string]interface{}{
				"name": "test",
			},
			want: true,
		},
		{
			name: "non-matching name",
			filters: map[string]interface{}{
				"name": "other",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesFilter(skill, tt.filters)
			if got != tt.want {
				t.Errorf("matchesFilter() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestWebSearchInvocation(t *testing.T) {
	store := &Store{
		builtInSkills: make(map[string]*Skill),
	}
	store.registerBuiltInSkills()

	tests := []struct {
		name    string
		input   map[string]interface{}
		wantErr bool
	}{
		{
			name: "valid query",
			input: map[string]interface{}{
				"query": "test search",
			},
			wantErr: false,
		},
		{
			name: "valid query with max_results",
			input: map[string]interface{}{
				"query":       "test search",
				"max_results": float64(10),
			},
			wantErr: false,
		},
		{
			name:    "missing query",
			input:   map[string]interface{}{},
			wantErr: true,
		},
		{
			name: "empty query",
			input: map[string]interface{}{
				"query": "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := store.invokeWebSearch(context.Background(), tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("invokeWebSearch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && result == nil {
				t.Error("Expected result to be non-nil")
			}
		})
	}
}

func TestSkillStructure(t *testing.T) {
	now := time.Now()
	skill := Skill{
		ID:          "test-id",
		Name:        "test_skill",
		Type:        SkillTypeExternal,
		State:       SkillStateEnabled,
		Description: "Test skill",
		Version:     "1.0.0",
		Source:      coreextension.SourceSkillsSh,
		Tools: []ToolDefinition{
			{
				Name:        "test_tool",
				Description: "Test tool description",
				Parameters: map[string]interface{}{
					"type": "object",
					"properties": map[string]interface{}{
						"param1": map[string]interface{}{
							"type": "string",
						},
					},
				},
				Required: []string{"param1"},
			},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if skill.ID != "test-id" {
		t.Errorf("Expected ID 'test-id', got %s", skill.ID)
	}

	if len(skill.Tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(skill.Tools))
	}

	if skill.Tools[0].Name != "test_tool" {
		t.Errorf("Expected tool name 'test_tool', got %s", skill.Tools[0].Name)
	}
}

func TestMCPServerStructure(t *testing.T) {
	now := time.Now()
	server := MCPServer{
		ID:        "server-id",
		Name:      "test_server",
		State:     SkillStateEnabled,
		Endpoint:  "https://example.com/mcp",
		Transport: "streamable_http",
		Config: map[string]interface{}{
			"timeout": 30,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if server.ID != "server-id" {
		t.Errorf("Expected ID 'server-id', got %s", server.ID)
	}

	if server.Transport != "streamable_http" {
		t.Errorf("Expected transport 'streamable_http', got %s", server.Transport)
	}
}
