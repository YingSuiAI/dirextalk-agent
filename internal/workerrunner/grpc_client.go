package workerrunner

import (
	"context"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/grpc/metadata"
)

const (
	enrollmentAuthorizationScheme = "DTX-Worker-Enroll"
	sessionAuthorizationScheme    = "DTX-Worker-Session"
)

type GRPCControlClient struct {
	client agentv1.WorkerControlServiceClient
}

func NewGRPCControlClient(client agentv1.WorkerControlServiceClient) *GRPCControlClient {
	return &GRPCControlClient{client: client}
}

func (client *GRPCControlClient) CreateIdentityChallenge(ctx context.Context, request *agentv1.CreateIdentityChallengeRequest) (*agentv1.CreateIdentityChallengeResponse, error) {
	return client.client.CreateIdentityChallenge(ctx, request)
}

func (client *GRPCControlClient) EnrollVerifiedIdentity(ctx context.Context, request *agentv1.EnrollVerifiedIdentityRequest) (*agentv1.EnrollVerifiedIdentityResponse, error) {
	return client.client.EnrollVerifiedIdentity(ctx, request)
}

func (client *GRPCControlClient) Enroll(ctx context.Context, token []byte, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	return client.client.Enroll(workerOutgoingContext(ctx, enrollmentAuthorizationScheme, token), request)
}

func (client *GRPCControlClient) Claim(ctx context.Context, token []byte, request *agentv1.WorkerControlServiceClaimRequest) (*agentv1.WorkerControlServiceClaimResponse, error) {
	return client.client.Claim(workerOutgoingContext(ctx, sessionAuthorizationScheme, token), request)
}

func (client *GRPCControlClient) GetCurrentAssignment(ctx context.Context, token []byte, request *agentv1.WorkerControlServiceGetCurrentAssignmentRequest) (*agentv1.WorkerControlServiceGetCurrentAssignmentResponse, error) {
	return client.client.GetCurrentAssignment(workerOutgoingContext(ctx, sessionAuthorizationScheme, token), request)
}

func (client *GRPCControlClient) Heartbeat(ctx context.Context, token []byte, request *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	return client.client.Heartbeat(workerOutgoingContext(ctx, sessionAuthorizationScheme, token), request)
}

func (client *GRPCControlClient) RecordEvidence(ctx context.Context, token []byte, request *agentv1.WorkerControlServiceRecordEvidenceRequest) (*agentv1.WorkerControlServiceRecordEvidenceResponse, error) {
	return client.client.RecordEvidence(workerOutgoingContext(ctx, sessionAuthorizationScheme, token), request)
}

func (client *GRPCControlClient) Complete(ctx context.Context, token []byte, request *agentv1.WorkerControlServiceCompleteRequest) (*agentv1.WorkerControlServiceCompleteResponse, error) {
	return client.client.Complete(workerOutgoingContext(ctx, sessionAuthorizationScheme, token), request)
}

func workerOutgoingContext(ctx context.Context, scheme string, token []byte) context.Context {
	return metadata.AppendToOutgoingContext(ctx, "authorization", scheme+" "+string(token))
}
