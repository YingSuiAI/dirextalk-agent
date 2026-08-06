package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreteam"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

const (
	teamPlanPrepareTool   = "team_plan_prepare"
	teamTaskStatusTool    = "team_task_status"
	teamToolVersion       = "1.0.0"
	teamPlanPrepareSchema = `{"additionalProperties":false,"properties":{"goal":{"maxLength":16384,"minLength":1,"type":"string"},"roles":{"items":{"additionalProperties":false,"properties":{"capabilities":{"items":{"enum":["repository.read","repository.write","code.review","shell","git","test","web.research","browser","mcp.client","result.structured"],"type":"string"},"maxItems":10,"minItems":1,"type":"array","uniqueItems":true},"depends_on":{"items":{"pattern":"^[a-z][a-z0-9-]{0,62}$","type":"string"},"maxItems":2,"type":"array","uniqueItems":true},"goal":{"maxLength":4096,"minLength":1,"type":"string"},"role_id":{"pattern":"^[a-z][a-z0-9-]{0,62}$","type":"string"}},"required":["role_id","goal","capabilities"],"type":"object"},"maxItems":3,"minItems":1,"type":"array"}},"required":["goal","roles"],"type":"object"}`
	teamTaskStatusSchema  = `{"additionalProperties":false,"oneOf":[{"required":["task_id"]},{"required":["execution_id"]}],"properties":{"execution_id":{"format":"uuid","type":"string"},"task_id":{"format":"uuid","type":"string"}},"type":"object"}`
)

var reservedTeamToolNames = map[string]struct{}{teamPlanPrepareTool: {}, teamTaskStatusTool: {}}

type teamConversationService interface {
	PreparePlan(context.Context, coreteam.PrepareCommand) (coreteam.PlanProjection, error)
	TaskStatus(context.Context, coreteam.StatusQuery) (coreteam.ExecutionProjection, error)
	ReadyForPublication() bool
}

type teamConversationResolver struct {
	base coreconversation.ExtensionResolver
	team teamConversationService
}

func (r *teamConversationResolver) ResolveExtensions(ctx context.Context, selections []coreconversation.ExtensionSelection) ([]coreconversation.ResolvedExtension, error) {
	var resolved []coreconversation.ResolvedExtension
	if r != nil && r.base != nil {
		base, err := r.base.ResolveExtensions(ctx, selections)
		if err != nil {
			return nil, err
		}
		resolved = append(resolved, base...)
	}
	if hasReservedTeamTool(resolved) {
		return nil, coreconversation.ErrConflict
	}
	if r == nil || r.team == nil || !r.team.ReadyForPublication() {
		return resolved, nil
	}
	scope, err := teamScope(ctx)
	if err != nil {
		return resolved, nil
	}
	prepareSchema, err := parseTeamSchema(teamPlanPrepareSchema)
	if err != nil {
		return nil, err
	}
	statusSchema, err := parseTeamSchema(teamTaskStatusSchema)
	if err != nil {
		return nil, err
	}
	tools := []coremodel.Tool{
		{Name: teamPlanPrepareTool, Description: "Prepare a bounded one-to-three role Pi Worker plan that requires owner confirmation.", InputSchema: prepareSchema},
		{Name: teamTaskStatusTool, Description: "Read the safe status summary of one owner-scoped Team task or execution.", InputSchema: statusSchema},
	}
	toolNames := []string{teamPlanPrepareTool, teamTaskStatusTool}
	toolSchemaDigest := teamToolsSchemaDigest(tools)
	contentPayload, _ := json.Marshal(map[string]string{"tool_schema_digest": toolSchemaDigest, "version": teamToolVersion})
	contentDigest := digestBytes(contentPayload)
	artifactDigest := digestBytes([]byte("dirextalk-agent:builtin:agent-team:v1"))
	selectionID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-agent:builtin:agent-team:v1")).String()
	selection := coreconversation.ExtensionSelection{
		Kind: coreconversation.ExtensionMCP, ID: selectionID, Version: teamToolVersion,
		Digest: contentDigest, AllowedTools: append([]string(nil), toolNames...),
	}
	resolved = append(resolved, coreconversation.ResolvedExtension{
		Selection: selection,
		Snapshot: coreconversation.ExtensionExecutionSnapshot{
			Selection: selection, InstallationID: selectionID, VersionID: teamToolVersion, Source: "builtin:agent-team:v1",
			ContentDigest: contentDigest, ArtifactDigest: artifactDigest, ToolSchemaDigest: toolSchemaDigest,
			ToolNames: append([]string(nil), toolNames...), ReadOnly: false, RequiresConfirmation: false, PrivateArguments: true,
		},
		Tools: tools,
		Execute: func(toolCtx context.Context, request coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
			return r.execute(toolCtx, scope, request)
		},
	})
	return resolved, nil
}

func (r *teamConversationResolver) execute(ctx context.Context, resolvedScope coreteam.Scope, request coreconversation.ToolExecutionRequest) (coreconversation.ToolResult, error) {
	if r == nil || r.team == nil || !r.team.ReadyForPublication() {
		return coreconversation.ToolResult{}, coreteam.ErrRuntimeUnavailable
	}
	currentScope, err := teamScope(ctx)
	if err != nil {
		return coreconversation.ToolResult{}, coreteam.ErrInvalid
	}
	if currentScope != resolvedScope {
		return coreconversation.ToolResult{}, coreconversation.ErrConflict
	}
	canonical, err := validateTeamToolRequest(request)
	if err != nil {
		return coreconversation.ToolResult{}, err
	}
	switch request.Call.Name {
	case teamPlanPrepareTool:
		var input teamPlanInput
		if decodeTeamArguments(canonical, &input) != nil {
			return coreconversation.ToolResult{}, coreteam.ErrInvalid
		}
		command := coreteam.PrepareCommand{
			Scope: resolvedScope, ConversationID: request.ConversationID, Goal: input.Goal,
			Roles: input.roleProposals(), IdempotencyKey: request.ExecutionID,
			RequestDigest: teamPrepareRequestDigest(resolvedScope, request.ConversationID, request.ArgsDigest),
		}
		if command.Validate() != nil {
			return coreconversation.ToolResult{}, coreteam.ErrInvalid
		}
		projection, err := r.team.PreparePlan(ctx, command)
		if err != nil {
			return coreconversation.ToolResult{}, safeTeamToolError(err)
		}
		if projection.Validate() != nil || projection.Status != coreteam.PlanWaitingUser {
			return coreconversation.ToolResult{}, coreconversation.ErrChatFailed
		}
		projection.Summary = "Team plan is waiting for user confirmation."
		content, err := json.Marshal(projection)
		if err != nil {
			return coreconversation.ToolResult{}, coreconversation.ErrChatFailed
		}
		return coreconversation.ToolResult{
			CallID: request.Call.ID, ToolName: request.Call.Name, Content: string(content),
			RelatedTaskIDs: []string{projection.TaskID}, Summary: "Team plan prepared; confirmation is required",
		}, nil
	case teamTaskStatusTool:
		var input teamStatusInput
		if decodeTeamArguments(canonical, &input) != nil {
			return coreconversation.ToolResult{}, coreteam.ErrInvalid
		}
		query := coreteam.StatusQuery{Scope: resolvedScope, TaskID: input.TaskID, ExecutionID: input.ExecutionID}
		if query.Validate() != nil {
			return coreconversation.ToolResult{}, coreteam.ErrInvalid
		}
		projection, err := r.team.TaskStatus(ctx, query)
		if err != nil {
			return coreconversation.ToolResult{}, safeTeamToolError(err)
		}
		if projection.Validate() != nil || (input.TaskID != "" && projection.TaskID != input.TaskID) ||
			(input.ExecutionID != "" && projection.ExecutionID != input.ExecutionID) {
			return coreconversation.ToolResult{}, coreconversation.ErrChatFailed
		}
		projection.Summary = "Team execution is " + string(projection.Status) + "."
		content, err := json.Marshal(projection)
		if err != nil {
			return coreconversation.ToolResult{}, coreconversation.ErrChatFailed
		}
		return coreconversation.ToolResult{
			CallID: request.Call.ID, ToolName: request.Call.Name, Content: string(content),
			RelatedTaskIDs: []string{projection.TaskID}, Summary: "Team execution status: " + string(projection.Status),
		}, nil
	default:
		return coreconversation.ToolResult{}, coreteam.ErrInvalid
	}
}

type teamPlanInput struct {
	Goal  string          `json:"goal"`
	Roles []teamRoleInput `json:"roles"`
}

type teamRoleInput struct {
	RoleID       string                `json:"role_id"`
	Goal         string                `json:"goal"`
	DependsOn    []string              `json:"depends_on"`
	Capabilities []coreteam.Capability `json:"capabilities"`
}

func (input teamPlanInput) roleProposals() []coreteam.RoleProposal {
	roles := make([]coreteam.RoleProposal, len(input.Roles))
	for index, role := range input.Roles {
		roles[index] = coreteam.RoleProposal{
			RoleID: role.RoleID, Goal: role.Goal, DependsOn: append([]string(nil), role.DependsOn...),
			Capabilities: append([]coreteam.Capability(nil), role.Capabilities...),
		}
	}
	return roles
}

type teamStatusInput struct {
	TaskID      string `json:"task_id"`
	ExecutionID string `json:"execution_id"`
}

func hasReservedTeamTool(resolved []coreconversation.ResolvedExtension) bool {
	for _, extension := range resolved {
		for _, name := range extension.Selection.AllowedTools {
			if _, reserved := reservedTeamToolNames[name]; reserved {
				return true
			}
		}
		for _, name := range extension.Snapshot.ToolNames {
			if _, reserved := reservedTeamToolNames[name]; reserved {
				return true
			}
		}
		for _, tool := range extension.Tools {
			if _, reserved := reservedTeamToolNames[tool.Name]; reserved {
				return true
			}
		}
	}
	return false
}

func teamScope(ctx context.Context) (coreteam.Scope, error) {
	permission, ok := capabilityclient.PermissionFromContext(ctx)
	if !ok || permission == nil {
		return coreteam.Scope{}, coreteam.ErrInvalid
	}
	scope := coreteam.Scope{OwnerID: permission.GetAuthenticatedOwnerId(), AccountGeneration: permission.GetAccountGeneration()}
	if scope.Validate() != nil {
		return coreteam.Scope{}, coreteam.ErrInvalid
	}
	return scope, nil
}

func validateTeamToolRequest(request coreconversation.ToolExecutionRequest) ([]byte, error) {
	if !validCanonicalUUID(request.RequestID) || !validCanonicalUUID(request.ConversationID) || !validCanonicalUUID(request.ExecutionID) ||
		strings.TrimSpace(request.ToolCallID) == "" || request.ToolCallID != request.Call.ID || request.Call.Name == "" {
		return nil, coreteam.ErrInvalid
	}
	if _, reserved := reservedTeamToolNames[request.Call.Name]; !reserved {
		return nil, coreteam.ErrInvalid
	}
	raw := []byte(request.Call.Arguments)
	canonical, err := capv1.CanonicalizeJSON(raw)
	if err != nil || !bytes.Equal(canonical, raw) {
		return nil, coreteam.ErrInvalid
	}
	digest := sha256.Sum256(raw)
	if request.ArgsDigest != hex.EncodeToString(digest[:]) {
		return nil, coreteam.ErrInvalid
	}
	return canonical, nil
}

func decodeTeamArguments(raw []byte, value any) error {
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return coreteam.ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil {
		return coreteam.ErrInvalid
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return coreteam.ErrInvalid
	}
	return nil
}

func parseTeamSchema(raw string) (map[string]any, error) {
	var schema map[string]any
	if json.Unmarshal([]byte(raw), &schema) != nil || schema == nil {
		return nil, coreteam.ErrInvalid
	}
	return schema, nil
}

func teamToolsSchemaDigest(tools []coremodel.Tool) string {
	ordered := append([]coremodel.Tool(nil), tools...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Name < ordered[j].Name })
	payload, _ := json.Marshal(ordered)
	return digestBytes(payload)
}

func safeTeamToolError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	switch {
	case errors.Is(err, coreteam.ErrInvalid):
		return coreteam.ErrInvalid
	case errors.Is(err, coreteam.ErrNotFound):
		return coreteam.ErrNotFound
	case errors.Is(err, coreteam.ErrConflict), errors.Is(err, coreteam.ErrRevisionConflict), errors.Is(err, coreteam.ErrExecutionActive):
		return coreconversation.ErrConflict
	case errors.Is(err, coreteam.ErrRuntimeUnavailable), errors.Is(err, coreteam.ErrQuoteUnavailable), errors.Is(err, coreteam.ErrIdentityUnavailable):
		return coreteam.ErrRuntimeUnavailable
	default:
		return coreconversation.ErrChatFailed
	}
}

func teamPrepareRequestDigest(scope coreteam.Scope, conversationID, argumentsDigest string) string {
	payload, _ := json.Marshal(struct {
		OwnerID           string `json:"owner_id"`
		AccountGeneration int64  `json:"account_generation"`
		ConversationID    string `json:"conversation_id"`
		ArgumentsDigest   string `json:"arguments_digest"`
	}{
		OwnerID: scope.OwnerID, AccountGeneration: scope.AccountGeneration,
		ConversationID: conversationID, ArgumentsDigest: argumentsDigest,
	})
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

func validCanonicalUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed.String() == value
}
