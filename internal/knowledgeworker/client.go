package knowledgeworker

import (
	"bytes"
	"context"
	"errors"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/grpc/metadata"
)

type AdapterExecutor interface {
	Execute(context.Context, *agentv1.KnowledgeWorkerOperation) *agentv1.KnowledgeWorkerResult
}

// WorkerClient performs one outbound long-poll and one local sealed-adapter
// execution. A lost Complete response is safe: the same relay operation ID is
// re-leased and the adapter's durable idempotency ledger replays the exact
// mutation result.
type WorkerClient struct {
	RPC          agentv1.KnowledgeWorkerControlServiceClient
	Adapter      AdapterExecutor
	DeploymentID string
	WorkerID     string
	Lease        time.Duration
	Session      []byte
}

func (client *WorkerClient) Close() {
	if client != nil {
		clear(client.Session)
		client.Session = nil
	}
}

func (client *WorkerClient) RunNext(ctx context.Context) error {
	if client == nil || ctx == nil || client.RPC == nil || client.Adapter == nil || !canonicalUUID(client.DeploymentID) || !canonicalUUID(client.WorkerID) ||
		client.Lease < minimumLease || client.Lease > maximumLease || len(client.Session) < 32 || !bytes.HasPrefix(client.Session, []byte("dtxw-session.")) {
		return ErrInvalid
	}
	authorized := metadata.AppendToOutgoingContext(ctx, "authorization", "DTX-Worker-Session "+string(client.Session))
	response, err := client.RPC.AcquireKnowledgeOperation(authorized, &agentv1.AcquireKnowledgeOperationRequest{
		DeploymentId: client.DeploymentID, WorkerId: client.WorkerID, LeaseDurationSeconds: uint32(client.Lease / time.Second),
	})
	if err != nil {
		return err
	}
	operation := response.GetOperation()
	if operation == nil || operation.GetBinding() == nil || operation.GetBinding().GetDeploymentId() != client.DeploymentID ||
		!canonicalUUID(operation.GetOperationId()) || !canonicalUUID(operation.GetLeaseId()) || operation.GetLeaseExpiresAt() == nil ||
		!operation.GetLeaseExpiresAt().IsValid() || !time.Now().Before(operation.GetLeaseExpiresAt().AsTime()) {
		clearOperationContent(operation)
		return ErrInvalid
	}
	result := client.Adapter.Execute(ctx, operation)
	clearOperationContent(operation)
	if result == nil {
		return ErrInvalid
	}
	_, err = client.RPC.CompleteKnowledgeOperation(authorized, &agentv1.CompleteKnowledgeOperationRequest{
		DeploymentId: client.DeploymentID, WorkerId: client.WorkerID, OperationId: operation.GetOperationId(),
		LeaseId: operation.GetLeaseId(), Result: result,
	})
	clearKnowledgeResult(result)
	if err != nil && ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return ctx.Err()
	}
	return err
}

func clearKnowledgeResult(value *agentv1.KnowledgeWorkerResult) {
	if value == nil {
		return
	}
	for _, match := range value.Matches {
		if match != nil {
			match.SourceId = ""
			match.ChunkRef = ""
		}
	}
	value.Matches = nil
}
