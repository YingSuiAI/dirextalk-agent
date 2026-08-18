package cloudworker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
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

// RetainedWorkerDomainManager resolves a model-visible ID pair into one exact,
// secret-free provider authority and later revalidates it before mutation.
type RetainedWorkerDomainManager interface {
	ResolveRetainedWorkerDomain(context.Context, string, uint64, string, string, string, string) (coretask.CloudWorkerDomainTaskPayload, error)
	ApplyRetainedWorkerDomain(context.Context, coretask.CloudWorkerDomainTaskPayload) (RetainedWorkerDomainResult, error)
}

func (p *ProposeIntrinsic) EnableRetainedWorkerDomains(manager RetainedWorkerDomainManager, store coreconversation.IntrinsicToolStore) error {
	if p == nil || manager == nil || store == nil {
		return ErrInvalid
	}
	p.domains, p.domainTools = manager, store
	return nil
}

func cloudWorkerDomainTools(p *ProposeIntrinsic, bound coreconversation.TurnLease) []coreconversation.ResolvedIntrinsic {
	if p == nil || p.domains == nil || p.domainTools == nil {
		return nil
	}
	worker := map[string]any{"type": "string", "format": "uuid", "description": "Exact worker_id returned by cloud_worker_inventory."}
	workload := map[string]any{"type": "string", "minLength": 1, "maxLength": 128, "pattern": "^[a-z0-9-]+$", "description": "Exact service workload_id returned by cloud_worker_inventory."}
	bind := coreconversation.ResolvedIntrinsic{Tool: coremodel.Tool{
		Name:        coremodel.IntrinsicCloudWorkerDomainBindToolName,
		Description: "Bind a Route53 hostname to an already deployed retained Worker service. First call cloud_worker_inventory and pass its exact worker_id and workload_id. This operation always pauses for explicit owner confirmation; tool arguments are never authorization.",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false, "required": []any{"worker_id", "workload_id", "hostname"}, "properties": map[string]any{
			"worker_id": worker, "workload_id": workload,
			"hostname": map[string]any{"type": "string", "minLength": 1, "maxLength": 253, "description": "Route53 hostname to bind."},
		}},
	}, Execute: func(ctx context.Context, request coreconversation.IntrinsicExecutionRequest) (coreconversation.IntrinsicExecutionResult, error) {
		return p.executeDomain(ctx, bound, request, "bind")
	}}
	unbind := coreconversation.ResolvedIntrinsic{Tool: coremodel.Tool{
		Name:        coremodel.IntrinsicCloudWorkerDomainUnbindToolName,
		Description: "Remove the exact persisted Route53 record from an already deployed retained Worker service without destroying the Worker or service. First call cloud_worker_inventory. This operation always pauses for explicit owner confirmation.",
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
	if ctx == nil || p == nil || p.domains == nil || p.domainTools == nil || request.Call.Name != wantTool ||
		request.Lease.Turn.ID != bound.Turn.ID || request.Lease.Turn.RequestID != bound.Turn.RequestID || request.Lease.LeaseID != bound.LeaseID ||
		request.Lease.Epoch < bound.Epoch || request.Call.Validate() != nil || request.ConversationRevision == 0 {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	args, err := parseDomainIntrinsicArguments(request.CanonicalArguments, operation)
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	owner, err := p.owners.ResolveCloudWorkerOwner(ctx, request.Lease)
	if err != nil || owner.OwnerID != bound.Turn.OwnerID || owner.AccountGeneration != bound.Turn.AccountGeneration {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	intent, err := p.domains.ResolveRetainedWorkerDomain(ctx, owner.OwnerID, owner.AccountGeneration, operation, args.WorkerID, args.WorkloadID, args.Hostname)
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	canonical := append(json.RawMessage(nil), request.CanonicalArguments...)
	argsSum := sha256.Sum256(canonical)
	argsDigest := hex.EncodeToString(argsSum[:])
	round := uint32(0)
	if recovery, ok := p.domainTools.(coreconversation.ConversationToolRecoveryStore); ok {
		if previous, observeErr := recovery.ObserveConversationTool(ctx, bound.Turn.ID); observeErr == nil {
			round = previous.Round + 1
		}
	}
	attemptID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fmt.Sprintf("cloud-worker-domain:%s:%d:%s", bound.Turn.RequestID, round, request.Call.ID))).String()
	zeroDigest := coreconfirmation.Digest(strings.Repeat("0", 64))
	credentialSum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", intent.CredentialID, intent.CredentialRevision)))
	binding := coreconfirmation.Binding{
		OwnerID: owner.OwnerID, AccountGeneration: owner.AccountGeneration,
		OperationDomain: "cloud_worker.domain." + operation, TargetID: attemptID, TargetRevision: 1,
		TargetKind: coreconfirmation.TargetKindPersistentService, SourceVersion: "cloud-worker-domain/v1",
		ContentDigest: coreconfirmation.Digest(intent.IntentDigest), ParameterDigest: coreconfirmation.Digest(argsDigest),
		NetworkDigest: coreconfirmation.Digest(intent.IntentDigest), SecretGrantDigest: coreconfirmation.Digest(hex.EncodeToString(credentialSum[:])),
		ManifestDigest: zeroDigest, ExecutionDigest: zeroDigest, PermissionDigest: zeroDigest, SelectedTool: wantTool,
	}
	binding, err = binding.Normalize()
	if err != nil {
		return coreconversation.IntrinsicExecutionResult{}, ErrInvalid
	}
	if err = p.domainTools.RecordConversationToolCall(ctx, request.Lease, request.Call); err != nil {
		return coreconversation.IntrinsicExecutionResult{}, err
	}
	payload := coretask.ConversationToolTaskPayload{
		TurnID: bound.Turn.ID, AttemptID: attemptID, Round: round, CallID: request.Call.ID,
		ToolName: wantTool, ArgumentsDigest: argsDigest, SafeSummary: "Cloud Worker domain " + operation,
		ExecutionTarget: coretask.ExtensionExecutionTargetCoreIntrinsic, CloudWorkerDomain: &intent,
	}
	_, _, confirmation, err := p.domainTools.PrepareIntrinsicTool(ctx, coreconversation.PrepareIntrinsicToolCommand{
		Lease: request.Lease, Round: round, Call: request.Call, CanonicalArguments: canonical, ArgumentsDigest: argsDigest,
		SafeSummary: payload.SafeSummary, IdempotencyKey: attemptID, ExpiresAt: time.Now().UTC().Add(10 * time.Minute), Payload: payload, Binding: binding,
	})
	if err != nil || confirmation.ConfirmationID == "" || confirmation.State != coreconfirmation.StatePending {
		return coreconversation.IntrinsicExecutionResult{}, errors.Join(err, ErrConflict)
	}
	return coreconversation.IntrinsicExecutionResult{TurnCommitted: true}, nil
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
		(operation == "bind" && args.Hostname == "") || (operation == "unbind" && args.Hostname != "") {
		return domainIntrinsicArguments{}, ErrInvalid
	}
	return args, nil
}
