package cloudworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

// Existing-host work has no machine-creation or sizing controls. Maintenance
// defaults to a job; registering a service on the same host is explicit.
// Both entrypoints use the same durable Task/Worker execution implementation.
func (p *ProposeIntrinsic) runTool(bound core.TurnLease, serviceSchema, responseModeSchema any) core.ResolvedIntrinsic {
	properties := map[string]any{
		"worker_id":                 map[string]any{"type": "string", "format": "uuid", "description": "Existing worker_id from inventory. Infer it from the user's server, domain, service or recent task; do not ask the user for an ID when the target is clear. May be omitted only when exactly one owned Worker exists."},
		"objective":                 map[string]any{"type": "string", "minLength": 1, "maxLength": coretask.MaxGoalBytes, "description": "Work to perform in place on this existing Worker. Preserve unrelated services, data and platform-managed network configuration. Include the requested answer language."},
		"estimated_runtime_minutes": map[string]any{"type": "integer", "minimum": 1, "maximum": 1440, "default": 15},
		"response_mode":             responseModeSchema,
		"workspace_mode":            map[string]any{"type": "string", "enum": []any{"none", "read_only", "write"}, "default": "none"},
		"workload_kind":             map[string]any{"type": "string", "enum": []any{"job", "service"}, "default": "job", "description": "Routine maintenance, optimization, configuration edits and restarts are job, even when the existing application is a persistent service. Use service only when explicitly deploying/registering a persistent service on this same Worker."},
		"service":                   serviceSchema,
	}
	if schema := frozenTurnAttachmentSchema(bound.Turn); schema != nil {
		properties["attachment_ids"] = schema
	}
	return core.ResolvedIntrinsic{Tool: coremodel.Tool{Name: coremodel.IntrinsicCloudWorkerRunToolName, Description: "Run authorized work directly on an existing Worker: inspect, optimize, repair, change files/configuration, restart applications, or perform follow-up work. Resolve the target from inventory and conversation context. No new machine or additional creation confirmation is possible. Running a maintenance job does not redeclare the deployed service's port, health path or hostname. If the target is busy/unavailable, wait or explain; never substitute another Worker or call cloud_worker_propose unless the user requests a new machine.", InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []any{"objective"}, "properties": properties}}, Execute: func(ctx context.Context, r core.IntrinsicExecutionRequest) (core.IntrinsicExecutionResult, error) {
		if r.Call.Name != coremodel.IntrinsicCloudWorkerRunToolName {
			return core.IntrinsicExecutionResult{}, core.ErrInvalid
		}
		var input struct {
			WorkerID      string                  `json:"worker_id"`
			Objective     string                  `json:"objective"`
			Minutes       uint64                  `json:"estimated_runtime_minutes"`
			ResponseMode  string                  `json:"response_mode"`
			WorkspaceMode string                  `json:"workspace_mode"`
			Attachments   []string                `json:"attachment_ids"`
			WorkloadKind  string                  `json:"workload_kind"`
			Service       *workerServiceArguments `json:"service"`
		}
		if len(r.CanonicalArguments) == 0 || len(r.CanonicalArguments) > core.MaxToolArgumentsBytes {
			return core.IntrinsicExecutionResult{}, core.ErrInvalid
		}
		decoder := json.NewDecoder(bytes.NewReader(r.CanonicalArguments))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) {
			return core.IntrinsicExecutionResult{}, core.ErrInvalid
		}
		if input.Minutes == 0 {
			input.Minutes = 15
		}
		if input.WorkspaceMode == "" {
			input.WorkspaceMode = "none"
		}
		args, err := validateProposeIntrinsicArguments(proposeIntrinsicArguments{Intent: "execute", WorkerID: input.WorkerID, Objective: input.Objective, ResponseMode: input.ResponseMode, WorkspaceMode: input.WorkspaceMode, AttachmentIDs: input.Attachments, EstimatedRuntimeMinutes: input.Minutes, WorkloadKind: input.WorkloadKind, Service: input.Service, MinVCPU: 1, MinMemoryGiB: 1, DiskGiB: 8})
		if err != nil {
			return core.IntrinsicExecutionResult{}, core.ErrInvalid
		}
		return p.executeArguments(ctx, bound, r, args)
	}}
}

// A prohibition on creating another machine is satisfied structurally by run;
// it is not a prohibition on using the user's existing Worker. Remove only
// the exact creation-only phrase, leaving any execution veto intact.
var creationOnlyVeto = regexp.MustCompile(`(?i)(?:不要|不用|无需|禁止)(?:再|重新)?(?:新建|创建|申请)(?:新的?|另一台)?(?:云服务器|云主机|云worker|worker|ec2实例)|\b(?:do not|don't|never|without)\s+(?:create|creating|provision|provisioning|allocate|allocating)\s+(?:(?:a|an|another|new|any)\s+)*(?:(?:cloud|aws|ec2)\s+)?(?:servers?|workers?|instances?|machines?)\b`)

func hasExistingWorkerExecutionVeto(prompt string) bool {
	return hasCloudExecutionVeto(creationOnlyVeto.ReplaceAllString(prompt, ""))
}
