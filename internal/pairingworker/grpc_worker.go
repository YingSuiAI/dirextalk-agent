package pairingworker

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/installer/roothelper"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// WorkerClient executes one acquired operation. Authorizing metadata is
// supplied by the caller's authenticated Worker transport interceptor.
type WorkerClient struct {
	RPC          agentv1.PairingWorkerOperationServiceClient
	Root         RootControl
	DeploymentID string
	WorkerID     string
	Lease        time.Duration
	Session      []byte
}

func (client WorkerClient) RunNext(ctx context.Context) error {
	if client.RPC == nil || client.Root == nil || client.Lease < 5*time.Second ||
		len(client.Session) < 32 || !bytes.HasPrefix(client.Session, []byte("dtxw-session.")) {
		return ErrInvalid
	}
	authorized := metadata.AppendToOutgoingContext(ctx, "authorization", "DTX-Worker-Session "+string(client.Session))
	response, err := client.RPC.AcquireNext(authorized, &agentv1.PairingWorkerOperationServiceAcquireNextRequest{
		DeploymentId: client.DeploymentID, WorkerId: client.WorkerID, IdempotencyKey: uuid.NewString(),
		LeaseDurationSeconds: int32(client.Lease / time.Second),
	})
	if err != nil {
		return err
	}
	assignment := response.GetAssignment()
	var delivery installer.DeliveryV1
	var capability installer.SignedRootHelperPairingCapabilityV1
	if assignment == nil || installer.DecodeCanonical(response.GetInstallerDeliveryCbor(), &delivery) != nil ||
		installer.DecodeCanonical(response.GetSignedCapabilityCbor(), &capability) != nil ||
		len(response.GetHelperPublicKey()) != ed25519.PublicKeySize {
		return ErrInvalid
	}
	var receipt []byte
	switch assignment.GetAction() {
	case agentv1.PairingWorkerOperationAction_PAIRING_WORKER_OPERATION_ACTION_BEGIN:
		value, callErr := client.Root.PairingBegin(ctx, delivery, capability, assignment.GetRecipientPublicKey(), response.GetHelperPublicKey())
		if callErr != nil {
			return retryableRootHelperError(ctx, callErr)
		}
		receipt, err = canonical.Marshal(value)
	case agentv1.PairingWorkerOperationAction_PAIRING_WORKER_OPERATION_ACTION_RESUME:
		value, callErr := client.Root.PairingResume(ctx, delivery, capability, response.GetHelperPublicKey())
		if callErr != nil {
			return retryableRootHelperError(ctx, callErr)
		}
		receipt, err = canonical.Marshal(value)
	default:
		return ErrInvalid
	}
	if err != nil {
		return status.Error(codes.Unavailable, "pairing root-helper receipt is temporarily unavailable")
	}
	_, err = client.RPC.Complete(authorized, &agentv1.PairingWorkerOperationServiceCompleteRequest{
		OperationId: assignment.GetOperationId(), DeploymentId: assignment.GetDeploymentId(),
		WorkerId: assignment.GetWorkerId(), LeaseEpoch: assignment.GetLeaseEpoch(),
		ExpectedRevision: assignment.GetRevision(), IdempotencyKey: uuid.NewSHA1(uuid.MustParse(assignment.GetOperationId()), []byte("complete")).String(),
		EncryptedRootHelperReceiptCbor: receipt,
	})
	clear(receipt)
	if err != nil {
		return retryableRootHelperError(ctx, err)
	}
	return nil
}

// A socket failure is ambiguous: the root daemon can have completed and
// journaled its signed receipt after the Worker loses the response. Never
// turn that ambiguity into a durable failed operation; let the maintenance
// loop acquire again and ask the root journal to replay it.
func retryableRootHelperError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
		return ctx.Err()
	}
	return status.Error(codes.Unavailable, "pairing root-helper operation is temporarily unavailable")
}

var _ RootControl = (*roothelper.SocketClient)(nil)
