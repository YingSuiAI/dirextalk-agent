package worker

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/execgate"
	cloudprotocol "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/protocol"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRuntimeTopologyProtoRoundTripAllowsMultiplePiExecs(t *testing.T) {
	proof := execgate.Proof{
		SchemaVersion: execgate.ProofSchemaV2, State: execgate.ProofTerminal,
		RunID: uuid.NewString(), ExecutionID: uuid.NewString(), TaskID: uuid.NewString(),
		Attempt: 1, LeaseEpoch: 2, RuntimeTaskSHA256: strings.Repeat("1", 64),
		BootID: uuid.NewString(), CgroupSHA256: strings.Repeat("2", 64), PolicySHA256: strings.Repeat("3", 64),
		Worker:             execgate.ProcessIdentity{PID: 10, StartTimeTicks: 100, Device: 1, Inode: 10, SHA256: strings.Repeat("4", 64)},
		Pi:                 execgate.ProcessIdentity{PID: 11, StartTimeTicks: 101, Device: 1, Inode: 11, SHA256: strings.Repeat("5", 64)},
		WorkerProcessCount: 1, CgroupProcessCount: 1,
		TotalAllowedPiExecs: 7, ObservedAtUnixNano: time.Now().UTC().UnixNano(),
	}
	got, err := runtimeTopologyFromProto(runtimeTopologyToProto(proof))
	if err != nil || got != proof {
		t.Fatalf("multi-Agent topology round trip = %+v, %v", got, err)
	}
}

type claimVersionRPC struct {
	agentv1.WorkerControlServiceClient
	request *agentv1.WorkerControlServiceClaimRequest
}

func (rpc *claimVersionRPC) Claim(_ context.Context, request *agentv1.WorkerControlServiceClaimRequest, _ ...grpc.CallOption) (*agentv1.WorkerControlServiceClaimResponse, error) {
	rpc.request = request
	return nil, status.Error(codes.FailedPrecondition, "test stop")
}

func TestMapControlRPCErrorMapsNotFoundToNotReady(t *testing.T) {
	err := mapControlRPCError(status.Error(codes.NotFound, "launch expectation not published"))
	if !errors.Is(err, ErrNotReady) {
		t.Fatalf("mapControlRPCError() = %v, want ErrNotReady", err)
	}
}

func TestMapControlRPCErrorPreservesDeadlineCauseAsUnavailable(t *testing.T) {
	err := mapControlRPCError(status.Error(codes.DeadlineExceeded, "heartbeat deadline exceeded"))
	if !errors.Is(err, ErrUnavailable) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("mapControlRPCError() = %v, want unavailable deadline", err)
	}
}

func TestClaimedTaskResponseRequiresExactProtocolVersions(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	claimed := fixture.control.claimed
	runtimeTaskJSON, err := json.Marshal(claimed.Task)
	if err != nil {
		t.Fatal(err)
	}
	runtimeTaskDigest, err := claimed.Task.Digest()
	if err != nil {
		t.Fatal(err)
	}
	response := &agentv1.WorkerControlServiceClaimResponse{
		Session: &agentv1.CoreCloudWorkerSession{
			SessionId: claimed.SessionID, Fence: fenceToProto(claimed.Binding.Fence()),
			State:     agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_ACTIVE,
			ClaimedAt: timestamppb.New(fixture.clock.Now()),
		},
		SessionToken: claimed.SessionToken,
		ModelGrant: &agentv1.CoreCloudWorkerModelGrant{
			GrantId: claimed.ModelGrant.GrantID, BearerToken: claimed.ModelGrant.BearerToken,
			ModelBindingDigest: claimed.ModelGrant.ModelBindingSHA256,
			AudienceDigest:     claimed.ModelGrant.AudienceSHA256,
			ExpiresAt:          timestamppb.New(time.Unix(claimed.ModelGrant.ExpiresAtUnix, 0).UTC()),
			RelayUrl:           claimed.ModelGrant.RelayBaseURL, RelayBindingDigest: claimed.ModelGrant.RelayBindingSHA256,
			MaxTokens: claimed.ModelGrant.MaxOutputTokens, LimitDigest: claimed.ModelGrant.LimitSHA256,
		},
		RuntimeTaskJson: runtimeTaskJSON, RuntimeTaskDigest: runtimeTaskDigest,
		InputManifestJson: claimed.InputManifestJSON, InputManifestDigest: claimed.Task.InputManifestSHA256,
		ArtifactBucket: claimed.ArtifactScope.Bucket, ArtifactKeyPrefix: claimed.ArtifactScope.KeyPrefix,
		HeartbeatIntervalMillis: uint64(claimed.HeartbeatInterval / time.Millisecond),
		NotAfter:                timestamppb.New(claimed.NotAfter),
		WorkerProtocolVersion:   cloudprotocol.WorkerProtocolVersion, RuntimeContractVersion: cloudprotocol.RuntimeContractVersion,
	}
	client := &GRPCControlClient{now: fixture.clock.Now}
	parsed, err := client.claimedTaskFromProto(claimed.Binding, response)
	if err != nil {
		t.Fatalf("current versions rejected: %v", err)
	}
	parsed.Destroy()

	for name, mutate := range map[string]func(*agentv1.WorkerControlServiceClaimResponse){
		"missing Worker protocol":  func(value *agentv1.WorkerControlServiceClaimResponse) { value.WorkerProtocolVersion = "" },
		"unknown Worker protocol":  func(value *agentv1.WorkerControlServiceClaimResponse) { value.WorkerProtocolVersion = "unknown" },
		"missing runtime contract": func(value *agentv1.WorkerControlServiceClaimResponse) { value.RuntimeContractVersion = "" },
		"unknown runtime contract": func(value *agentv1.WorkerControlServiceClaimResponse) { value.RuntimeContractVersion = "unknown" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := proto.Clone(response).(*agentv1.WorkerControlServiceClaimResponse)
			mutate(copy)
			if _, parseErr := client.claimedTaskFromProto(claimed.Binding, copy); !errors.Is(parseErr, ErrInvalid) {
				t.Fatalf("response error = %v, want ErrInvalid", parseErr)
			}
		})
	}
}

func TestGRPCClaimDeclaresCurrentProtocolVersions(t *testing.T) {
	fixture := newWorkflowRetryFixture(t)
	rpc := &claimVersionRPC{}
	client, err := newGRPCControlClient(rpc, fixture.workflow.bootstrap, fixture.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	proof := IdentityProof{Challenge: fixture.control.challenge.Nonce}
	_, _ = client.Claim(
		context.Background(), fixture.control.claimed.Binding.Fence(),
		fixture.control.challenge.ChallengeID, &proof,
	)
	if rpc.request == nil || rpc.request.WorkerProtocolVersion != cloudprotocol.WorkerProtocolVersion ||
		rpc.request.RuntimeContractVersion != cloudprotocol.RuntimeContractVersion {
		t.Fatalf("Claim protocol versions = %#v", rpc.request)
	}
}

type pendingTerminalRPC struct {
	agentv1.WorkerControlServiceClient
	heartbeats   []*agentv1.WorkerControlServiceHeartbeatRequest
	completes    []*agentv1.WorkerControlServiceCompleteRequest
	fails        []*agentv1.WorkerControlServiceFailRequest
	replayErr    error
	mutateReplay func(*agentv1.CoreCloudWorkerSession)
}

func (rpc *pendingTerminalRPC) Heartbeat(_ context.Context, request *agentv1.WorkerControlServiceHeartbeatRequest, _ ...grpc.CallOption) (*agentv1.WorkerControlServiceHeartbeatResponse, error) {
	rpc.heartbeats = append(rpc.heartbeats, proto.Clone(request).(*agentv1.WorkerControlServiceHeartbeatRequest))
	if len(rpc.heartbeats) == 1 {
		return nil, status.Error(codes.Unavailable, "committed response was not observed")
	}
	if rpc.replayErr != nil {
		return nil, rpc.replayErr
	}
	session := &agentv1.CoreCloudWorkerSession{
		SessionId: request.SessionId, Fence: proto.Clone(request.Fence).(*agentv1.CoreCloudWorkerTaskFence),
		State:            agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_ACTIVE,
		ProgressSequence: request.ProgressSequence,
		LatestProgress:   proto.Clone(request.Progress).(*agentv1.CoreCloudWorkerProgressSnapshot),
	}
	if rpc.mutateReplay != nil {
		rpc.mutateReplay(session)
	}
	return &agentv1.WorkerControlServiceHeartbeatResponse{Session: session}, nil
}

func (rpc *pendingTerminalRPC) Complete(_ context.Context, request *agentv1.WorkerControlServiceCompleteRequest, _ ...grpc.CallOption) (*agentv1.WorkerControlServiceCompleteResponse, error) {
	rpc.completes = append(rpc.completes, proto.Clone(request).(*agentv1.WorkerControlServiceCompleteRequest))
	topology, err := runtimeTopologyFromProto(request.RuntimeTopology)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad topology")
	}
	digest, err := topology.Digest()
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "bad topology digest")
	}
	return &agentv1.WorkerControlServiceCompleteResponse{Session: &agentv1.CoreCloudWorkerSession{
		SessionId: request.SessionId, Fence: proto.Clone(request.Fence).(*agentv1.CoreCloudWorkerTaskFence),
		State:                 agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_COMPLETED,
		ProgressSequence:      request.ProgressSequence,
		LatestProgress:        proto.Clone(request.Progress).(*agentv1.CoreCloudWorkerProgressSnapshot),
		RuntimeTopology:       proto.Clone(request.RuntimeTopology).(*agentv1.CoreCloudWorkerRuntimeTopologyProof),
		RuntimeTopologyDigest: digest,
	}}, nil
}

func (rpc *pendingTerminalRPC) Fail(_ context.Context, request *agentv1.WorkerControlServiceFailRequest, _ ...grpc.CallOption) (*agentv1.WorkerControlServiceFailResponse, error) {
	rpc.fails = append(rpc.fails, proto.Clone(request).(*agentv1.WorkerControlServiceFailRequest))
	return &agentv1.WorkerControlServiceFailResponse{Session: &agentv1.CoreCloudWorkerSession{
		SessionId: request.SessionId, Fence: proto.Clone(request.Fence).(*agentv1.CoreCloudWorkerTaskFence),
		State:            agentv1.CoreCloudWorkerSessionState_CORE_CLOUD_WORKER_SESSION_STATE_FAILED,
		ProgressSequence: request.ProgressSequence,
		LatestProgress:   proto.Clone(request.Progress).(*agentv1.CoreCloudWorkerProgressSnapshot),
	}}, nil
}

func newPendingTerminalClient(t *testing.T, rpc *pendingTerminalRPC) (*GRPCControlClient, *workflowRetryFixture) {
	t.Helper()
	fixture := newWorkflowRetryFixture(t)
	client, err := newGRPCControlClient(rpc, fixture.workflow.bootstrap, fixture.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	claimed := fixture.control.claimed
	client.sessionID, client.fence, client.notAfter = claimed.SessionID, claimed.Binding.Fence(), claimed.NotAfter
	client.claimedAt, client.phase = fixture.clock.Now(), ProgressRunningPi
	return client, fixture
}

func createPendingHeartbeat(t *testing.T, client *GRPCControlClient, fixture *workflowRetryFixture) *agentv1.WorkerControlServiceHeartbeatRequest {
	t.Helper()
	claimed := fixture.control.claimed
	if _, err := client.Heartbeat(t.Context(), claimed.Binding.Fence(), claimed.SessionID, claimed.SessionToken, 1, uuid.NewString()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("initial unknown heartbeat error=%v", err)
	}
	rpc := client.rpc.(*pendingTerminalRPC)
	if len(rpc.heartbeats) != 1 {
		t.Fatalf("heartbeat calls=%d, want 1", len(rpc.heartbeats))
	}
	return rpc.heartbeats[0]
}

func TestGRPCTerminalResolvesUnknownHeartbeatBeforeNextProgressSequence(t *testing.T) {
	for _, terminal := range []string{"complete", "fail"} {
		t.Run(terminal, func(t *testing.T) {
			rpc := &pendingTerminalRPC{}
			client, fixture := newPendingTerminalClient(t, rpc)
			first := createPendingHeartbeat(t, client, fixture)
			claimed := fixture.control.claimed
			var err error
			switch terminal {
			case "complete":
				client.SetUploadedBytes(uint64(fixture.uploader.claim.SizeBytes))
				client.SetProgressPhase(ProgressCompleting)
				err = client.Complete(t.Context(), CompleteRequest{
					Fence: claimed.Binding.Fence(), SessionID: claimed.SessionID, SessionToken: claimed.SessionToken,
					ManifestClaim: fixture.uploader.claim, RuntimeTopology: fixture.executor.topology,
					IdempotencyKey: uuid.NewString(),
				})
			case "fail":
				client.SetOutputTruncated()
				err = client.Fail(t.Context(), FailRequest{
					Fence: claimed.Binding.Fence(), SessionID: claimed.SessionID, SessionToken: claimed.SessionToken,
					Code: "process_process_output_limit", Summary: "pi execution gate: runtime_topology_invalid",
					IdempotencyKey: uuid.NewString(),
				})
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(rpc.heartbeats) != 2 || !proto.Equal(first, rpc.heartbeats[1]) {
				t.Fatalf("pending replay changed: first=%#v replay=%#v", first, rpc.heartbeats)
			}
			if terminal == "complete" {
				if len(rpc.completes) != 1 || len(rpc.fails) != 0 || rpc.completes[0].ProgressSequence != 2 ||
					rpc.completes[0].Progress.Phase != agentv1.CoreCloudWorkerProgressPhase_CORE_CLOUD_WORKER_PROGRESS_PHASE_COMPLETING ||
					rpc.completes[0].Progress.UploadedBytes != uint64(fixture.uploader.claim.SizeBytes) {
					t.Fatalf("complete requests=%#v fail requests=%#v", rpc.completes, rpc.fails)
				}
			} else if len(rpc.fails) != 1 || len(rpc.completes) != 0 || rpc.fails[0].ProgressSequence != 2 ||
				!rpc.fails[0].Progress.OutputTruncated || rpc.fails[0].Summary != "pi execution gate: runtime_topology_invalid" {
				t.Fatalf("fail requests=%#v complete requests=%#v", rpc.fails, rpc.completes)
			}
		})
	}
}

func TestGRPCTerminalDoesNotSendWhilePendingHeartbeatReplayIsUnavailable(t *testing.T) {
	for _, terminal := range []string{"complete", "fail"} {
		t.Run(terminal, func(t *testing.T) {
			rpc := &pendingTerminalRPC{replayErr: status.Error(codes.Unavailable, "still unknown")}
			client, fixture := newPendingTerminalClient(t, rpc)
			createPendingHeartbeat(t, client, fixture)
			claimed := fixture.control.claimed
			var err error
			if terminal == "complete" {
				err = client.Complete(t.Context(), CompleteRequest{Fence: claimed.Binding.Fence(), SessionID: claimed.SessionID,
					SessionToken: claimed.SessionToken, ManifestClaim: fixture.uploader.claim,
					RuntimeTopology: fixture.executor.topology, IdempotencyKey: uuid.NewString()})
			} else {
				err = client.Fail(t.Context(), FailRequest{Fence: claimed.Binding.Fence(), SessionID: claimed.SessionID,
					SessionToken: claimed.SessionToken, Code: "runtime_failed", IdempotencyKey: uuid.NewString()})
			}
			if !errors.Is(err, ErrUnavailable) || len(rpc.heartbeats) != 2 || len(rpc.completes) != 0 || len(rpc.fails) != 0 {
				t.Fatalf("err=%v heartbeat/complete/fail=%d/%d/%d", err, len(rpc.heartbeats), len(rpc.completes), len(rpc.fails))
			}
		})
	}
}

func TestPendingHeartbeatReplayResponseDriftFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(*agentv1.CoreCloudWorkerSession){
		"session": func(session *agentv1.CoreCloudWorkerSession) { session.SessionId = uuid.NewString() },
		"fence":   func(session *agentv1.CoreCloudWorkerSession) { session.Fence.LeaseEpoch++ },
		"progress": func(session *agentv1.CoreCloudWorkerSession) {
			session.LatestProgress.Phase = agentv1.CoreCloudWorkerProgressPhase_CORE_CLOUD_WORKER_PROGRESS_PHASE_COMPLETING
		},
	} {
		t.Run(name, func(t *testing.T) {
			rpc := &pendingTerminalRPC{mutateReplay: mutate}
			client, fixture := newPendingTerminalClient(t, rpc)
			createPendingHeartbeat(t, client, fixture)
			claimed := fixture.control.claimed
			err := client.Complete(t.Context(), CompleteRequest{Fence: claimed.Binding.Fence(), SessionID: claimed.SessionID,
				SessionToken: claimed.SessionToken, ManifestClaim: fixture.uploader.claim,
				RuntimeTopology: fixture.executor.topology, IdempotencyKey: uuid.NewString()})
			if !errors.Is(err, ErrInvalid) || len(rpc.completes) != 0 || len(rpc.fails) != 0 {
				t.Fatalf("err=%v complete/fail=%d/%d", err, len(rpc.completes), len(rpc.fails))
			}
		})
	}
}
