# Skills Store

Complete Skills Store implementation with MCP integration for dirextalk-agent.

## Overview

The Skills Store provides a unified framework for managing skills, MCP servers, and tool invocations in the agent system. It supports:

- **Built-in Skills**: Core skills like web_search and memory (remember/recall)
- **External Skills**: Skills installed from external sources (skills.sh, GitHub)
- **MCP Skills**: Skills provided by MCP servers via Streamable HTTP

## Architecture

### Components

1. **Store** (`store.go`): Main store implementation with CRUD operations
2. **Database Schema** (`migrations/003_skills_store_schema.sql`): PostgreSQL schema
3. **Tests** (`store_test.go`): Comprehensive unit tests

### Data Models

#### Skill
```go
type Skill struct {
    ID             string
    Name           string
    Type           SkillType      // builtin, external, mcp
    State          SkillState     // installed, enabled, disabled
    Description    string
    Version        string
    Source         coreextension.Source
    InstallationID string
    Tools          []ToolDefinition
    Config         map[string]interface{}
    CreatedAt      time.Time
    UpdatedAt      time.Time
}
```

#### MCPServer
```go
type MCPServer struct {
    ID             string
    Name           string
    State          SkillState
    Endpoint       string
    Transport      string
    SecretRef      string
    InstallationID string
    Config         map[string]interface{}
    CreatedAt      time.Time
    UpdatedAt      time.Time
}
```

#### ToolDefinition
```go
type ToolDefinition struct {
    Name        string
    Description string
    Parameters  map[string]interface{}
    Required    []string
}
```

## Usage

### Create Store

```go
import (
    "github.com/YingSuiAI/dirextalk-agent/internal/agentcapability/skills"
    "github.com/jackc/pgx/v5/pgxpool"
)

pool, err := pgxpool.New(ctx, databaseURL)
if err != nil {
    return err
}

store, err := skills.NewStore(pool)
if err != nil {
    return err
}

// Optional: Set MCP provider for external tool invocation
mcpProvider, _ := mcphttp.New(configs, secrets)
store.SetMCPProvider(mcpProvider)
```

### Skill Operations

#### List Skills
```go
// List all skills
allSkills, err := store.ListSkills(ctx, nil)

// Filter by state
enabledSkills, err := store.ListSkills(ctx, map[string]interface{}{
    "state": "enabled",
})

// Filter by type
builtinSkills, err := store.ListSkills(ctx, map[string]interface{}{
    "type": "builtin",
})
```

#### Get Skill
```go
// By ID or name
skill, err := store.GetSkill(ctx, "web_search")
if err == skills.ErrSkillNotFound {
    // Handle not found
}
```

#### Install Skill
```go
skill := &skills.Skill{
    Name:        "custom_skill",
    Type:        skills.SkillTypeExternal,
    Description: "Custom skill",
    Version:     "1.0.0",
    Source:      coreextension.SourceSkillsSh,
    Tools: []skills.ToolDefinition{
        {
            Name:        "custom_tool",
            Description: "Custom tool",
            Parameters: map[string]interface{}{
                "type": "object",
                "properties": map[string]interface{}{
                    "input": map[string]interface{}{
                        "type": "string",
                    },
                },
            },
            Required: []string{"input"},
        },
    },
}

err := store.InstallSkill(ctx, skill)
```

#### Update Skill
```go
skill.State = skills.SkillStateEnabled
err := store.UpdateSkill(ctx, skill)
```

#### Enable/Disable Skill
```go
err := store.EnableSkill(ctx, "custom_skill")
err := store.DisableSkill(ctx, "custom_skill")
```

#### Uninstall Skill
```go
err := store.UninstallSkill(ctx, "custom_skill")
```

### MCP Server Operations

#### List MCP Servers
```go
servers, err := store.ListMCPServers(ctx)
```

#### Get MCP Server
```go
server, err := store.GetMCPServer(ctx, "server_name")
```

#### Install MCP Server
```go
server := &skills.MCPServer{
    Name:      "example_server",
    Endpoint:  "https://mcp.example.com/api",
    Transport: "streamable_http",
    SecretRef: "credential-uuid",
    Config: map[string]interface{}{
        "timeout": 30,
    },
}

err := store.InstallMCPServer(ctx, server)
```

#### Enable/Disable MCP Server
```go
err := store.EnableMCPServer(ctx, "example_server")
err := store.DisableMCPServer(ctx, "example_server")
```

#### Uninstall MCP Server
```go
err := store.UninstallMCPServer(ctx, "example_server")
```

### Tool Invocation

```go
result, err := store.InvokeTool(ctx, "web_search", "web_search", map[string]interface{}{
    "query":       "golang best practices",
    "max_results": 5,
})
```

## Built-in Skills

### Web Search
```go
skill: "web_search"
tool: "web_search"
parameters:
  - query: string (required)
  - max_results: integer (optional, default: 5)
```

### Memory
```go
skill: "memory"
tools:
  - remember:
      parameters:
        - content: string (required)
        - tags: array of strings (optional)
  - recall:
      parameters:
        - query: string (required)
        - limit: integer (optional, default: 10)
```

## Database Schema

The store uses two main tables:

### agent_skills
- Stores external and MCP skills (built-in skills are in-memory)
- Columns: id, name, type, state, description, version, source, installation_id, tools, config, owner_id, enabled, created_at, updated_at
- Indices: type+state, name (unique when not deleted)

### agent_mcp_servers
- Stores MCP server configurations
- Columns: id, name, state, endpoint, transport, secret_ref, installation_id, config, created_at, updated_at
- Indices: state+created_at, name (unique)

Run migration:
```bash
# Migration file: migrations/003_skills_store_schema.sql
# Applied automatically on startup via ApplyMigrations
```

## Integration Points

### MCP Provider Integration
The store integrates with `internal/mcphttp.Provider` for MCP tool invocation:

```go
provider, err := mcphttp.New(serverConfigs, secretResolver)
store.SetMCPProvider(provider)
```

### Core Extension Integration
External skills can be linked to `coreextension.Installation`:

```go
skill.InstallationID = installation.ID
```

### Tool Runtime Integration
For native agent tool integration, see reference implementation:
- `dirextalk-message-server/p2p/nativeagent/native_agent_tools.go`

## Error Handling

```go
var (
    ErrSkillNotFound      = errors.New("skill not found")
    ErrSkillAlreadyExists = errors.New("skill already exists")
    ErrInvalidSkill       = errors.New("invalid skill")
    ErrSkillDisabled      = errors.New("skill is disabled")
    ErrMCPServerNotFound  = errors.New("mcp server not found")
    ErrToolNotFound       = errors.New("tool not found")
)
```

## Testing

Run tests:
```bash
cd /home/adam/dirextalk/dirextalk-agent
go test ./internal/agentcapability/skills/ -v
```

All tests pass:
- TestBuiltInSkills: Verifies built-in skills registration
- TestSkillValidation: Tests skill validation logic
- TestMatchesFilter: Tests filter matching
- TestWebSearchInvocation: Tests web search tool invocation
- TestSkillStructure: Verifies data structures
- TestMCPServerStructure: Verifies MCP server structure

## Future Enhancements

1. **Web Search Integration**: Connect to actual search API (currently placeholder)
2. **Memory Integration**: Connect to knowledge base storage (currently placeholder)
3. **MCP Tool Invocation**: Complete MCP provider tool invocation flow
4. **External Tool Invocation**: Complete coreextension integration for external skills
5. **Tool Result Caching**: Cache frequently used tool results
6. **Rate Limiting**: Add rate limiting for external tool invocations
7. **Metrics**: Add instrumentation for tool usage tracking

## References

- Reference implementation: `dirextalk-message-server/p2p/nativeagent/native_agent_tools.go`
- MCP Provider: `internal/mcphttp/provider.go`
- Core Extension: `internal/coreextension/types.go`
- Skills Source: `internal/coreextension/source/skills.go`
