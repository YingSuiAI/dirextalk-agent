package cloudworker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/remoteservice"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type RetainedWorkerDomainResult struct {
	WorkerID    string `json:"worker_id"`
	WorkloadID  string `json:"workload_id"`
	Hostname    string `json:"hostname"`
	TargetIPv4  string `json:"target_ipv4"`
	ZoneID      string `json:"zone_id"`
	RecordState string `json:"record_status"`
}

const retainedWorkerPublicRoute53Correction = "The hostname is not owned by a public Route53 hosted zone in the current AWS account; only Route53-hosted domains are supported."

type retainedWorkerPublicRoute53Error struct{}

func (retainedWorkerPublicRoute53Error) Error() string { return retainedWorkerPublicRoute53Correction }
func (retainedWorkerPublicRoute53Error) Unwrap() error { return coreconversation.ErrInvalid }
func (retainedWorkerPublicRoute53Error) IntrinsicCorrection() string {
	return retainedWorkerPublicRoute53Correction
}

// ErrRetainedWorkerPublicRoute53Required is a stable, correctable model-tool
// error for hostnames outside the current verified account's public zones.
var ErrRetainedWorkerPublicRoute53Required error = retainedWorkerPublicRoute53Error{}

// RetainedWorkerDomainIntent is the exact, secret-free provider authority
// resolved from one authoritative Native conversation tool call. The manager
// revalidates every field before and around Route53 mutation.
type RetainedWorkerDomainIntent struct {
	Operation          string
	OwnerID            string
	AccountGeneration  uint64
	CredentialID       string
	CredentialRevision uint64
	AWSAccountID       string
	Region             string
	WorkerID           string
	InstanceID         string
	KeyPairID          string
	SecurityGroupID    string
	WorkloadID         string
	Hostname           string
	ZoneID             string
	TargetIPv4         string
	TTL                uint32
	IntentDigest       string
}

// RetainedWorkerDomainManager resolves a model-visible ID pair into one exact,
// secret-free provider authority and later revalidates it before mutation.
type RetainedWorkerDomainManager interface {
	ResolveRetainedWorkerDomain(context.Context, string, uint64, string, string, string, string) (RetainedWorkerDomainIntent, error)
	ApplyRetainedWorkerDomain(context.Context, RetainedWorkerDomainIntent) (RetainedWorkerDomainResult, error)
}

func (p *ProposeIntrinsic) EnableRetainedWorkerDomains(manager RetainedWorkerDomainManager, turns IntrinsicTurnCommitter) error {
	if p == nil || manager == nil || turns == nil {
		return ErrInvalid
	}
	p.domains, p.domainTurns = manager, turns
	return nil
}

func cloudWorkerDomainTools(p *ProposeIntrinsic, bound coreconversation.TurnLease) []coreconversation.ResolvedIntrinsic {
	if p == nil || p.domains == nil || p.domainTurns == nil {
		return nil
	}
	worker := map[string]any{"type": "string", "format": "uuid", "description": "Exact worker_id returned by cloud_worker_inventory."}
	workload := map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z0-9-]+$", "description": "Exact service workload_id returned by cloud_worker_inventory."}
	bind := coreconversation.ResolvedIntrinsic{Tool: coremodel.Tool{
		Name:        coremodel.IntrinsicCloudWorkerDomainBindToolName,
		Description: "Bind a hostname owned by a matching public Route53 hosted zone in the current verified AWS account to an already deployed retained Worker service. First call cloud_worker_inventory and pass its exact worker_id and workload_id. The authoritative Native turn executes this operation directly and verifies Route53 read-back. External/manual DNS, private zones, and cross-account zones are unsupported.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []any{"worker_id", "workload_id", "hostname"}, "properties": map[string]any{
			"worker_id": worker, "workload_id": workload,
			"hostname": map[string]any{"type": "string", "minLength": 1, "maxLength": 253, "description": "Hostname in a matching public Route53 hosted zone owned by the current verified AWS account."},
		}},
	}, Execute: func(ctx context.Context, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
		return p.executeDomain(ctx, bound, request, "bind")
	}}
	unbind := coreconversation.ResolvedIntrinsic{Tool: coremodel.Tool{
		Name:        coremodel.IntrinsicCloudWorkerDomainUnbindToolName,
		Description: "Remove the exact persisted Route53 record from an already deployed retained Worker service without destroying the Worker or service. First call cloud_worker_inventory. The authoritative Native turn executes this operation directly and verifies Route53 read-back.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []any{"worker_id", "workload_id"}, "properties": map[string]any{
			"worker_id": worker, "workload_id": workload,
		}},
	}, Execute: func(ctx context.Context, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
		return p.executeDomain(ctx, bound, request, "unbind")
	}}
	return []coreconversation.ResolvedIntrinsic{bind, unbind}
}

type domainIntrinsicArguments struct {
	WorkerID   string `json:"worker_id"`
	WorkloadID string `json:"workload_id"`
	Hostname   string `json:"hostname,omitempty"`
}

func (p *ProposeIntrinsic) executeDomain(ctx context.Context, bound coreconversation.TurnLease, request coreconversation.IntrinsicExecutionRequest, operation string) (coreconversation.IntrinsicExecutionResult, error) {
	wantTool := coremodel.IntrinsicCloudWorkerDomainBindToolName
	if operation == "unbind" {
		wantTool = coremodel.IntrinsicCloudWorkerDomainUnbindToolName
	}
	if ctx == nil || p == nil || p.domains == nil || p.domainTurns == nil || request.Call.Name != wantTool ||
		request.Lease.Turn.ID != bound.Turn.ID || request.Lease.Turn.RequestID != bound.Turn.RequestID || request.Lease.LeaseID != bound.LeaseID ||
		request.Lease.Epoch < bound.Epoch || request.Call.Validate() != nil || request.ConversationRevision == 0 || bound.Turn.CreatedAt.IsZero() {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	args, err := parseDomainIntrinsicArguments(request.CanonicalArguments, operation)
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, errors.Join(coreconversation.ErrInvalid, err)
	}
	owner, err := p.owners.ResolveCloudWorkerOwner(ctx, request.Lease)
	if err != nil || owner.OwnerID != bound.Turn.OwnerID || owner.AccountGeneration != bound.Turn.AccountGeneration {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	intent, err := p.domains.ResolveRetainedWorkerDomain(ctx, owner.OwnerID, owner.AccountGeneration, operation, args.WorkerID, args.WorkloadID, args.Hostname)
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, classifyRetainedWorkerDomainPreflightError(err)
	}
	result, err := p.domains.ApplyRetainedWorkerDomain(ctx, intent)
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	wantState := "current"
	content := fmt.Sprintf("Domain %s now points to Worker %s workload %s at %s.", result.Hostname, result.WorkerID, result.WorkloadID, result.TargetIPv4)
	if operation == "unbind" {
		wantState = "absent"
		content = fmt.Sprintf("Domain %s was removed from Worker %s workload %s.", result.Hostname, result.WorkerID, result.WorkloadID)
	}
	if result.WorkerID != intent.WorkerID || result.WorkloadID != intent.WorkloadID || result.Hostname != intent.Hostname ||
		result.TargetIPv4 != intent.TargetIPv4 || result.ZoneID != intent.ZoneID || result.RecordState != wantState {
		return coreconversation.IntrinsicExecutionResult{}, ErrConflict
	}
	message := coreconversation.Message{ID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("cloud-worker-domain-message:"+bound.Turn.ID+":"+request.Call.ID)).String(),
		Role: coreconversation.RoleAssistant, Content: content, CreatedAt: bound.Turn.CreatedAt.UTC().Add(time.Microsecond), ModelProfileID: bound.Turn.ProfileID}
	if message.Validate() != nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	response := coreconversation.ChatResponse{RequestID: bound.Turn.RequestID, ConversationID: bound.Turn.ConversationID,
		Revision: request.ConversationRevision + 1, Message: message, Done: true, ModelProfileID: bound.Turn.ProfileID}
	if _, err = p.domainTurns.CommitTurn(ctx, request.Lease, response); err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	return coreconversation.IntrinsicExecutionResult{TurnCommitted: true}, nil
}

func classifyRetainedWorkerDomainPreflightError(err error) error {
	if !errors.Is(err, remoteservice.ErrDNSConflict) {
		return err
	}
	return coreconversation.NewToolExecutionErrorWithMutation(coreconversation.ToolOutcomeUserInput, err.Error()+" No Worker, workload, security-group, or DNS resource was changed.", 0, coreconversation.ToolMutationUnchanged, err)
}

func parseDomainIntrinsicArguments(raw json.RawMessage, operation string) (domainIntrinsicArguments, error) {
	if len(raw) == 0 || len(raw) > coreconversation.MaxToolArgumentsBytes {
		return domainIntrinsicArguments{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var args domainIntrinsicArguments
	if decoder.Decode(&args) != nil {
		return domainIntrinsicArguments{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return domainIntrinsicArguments{}, ErrInvalid
	}
	args.WorkerID, args.WorkloadID, args.Hostname = strings.TrimSpace(args.WorkerID), strings.TrimSpace(args.WorkloadID), strings.TrimSpace(args.Hostname)
	if !coretask.ValidUUID(args.WorkerID) || args.WorkloadID == "" || len(args.WorkloadID) > 128 ||
		(operation == "bind" && !remoteservice.ValidHostname(args.Hostname)) || (operation == "unbind" && args.Hostname != "") {
		return domainIntrinsicArguments{}, ErrInvalid
	}
	return args, nil
}
