package coreexecutionv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

const (
	cloudGeneration = uint64(7)
	cloudPlanID     = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	cloudRunID      = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	cloudArtifactID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	owner           = "@owner:example.test"
)

type cloudWorkerPortFake struct {
	calls         map[string]int
	lastAuthority Authority
	foreign       bool
	mutateChunk   func(*CloudWorkerArtifactChunk)
}

func (f *cloudWorkerPortFake) authority(value Authority) Authority {
	f.lastAuthority = value
	if f.foreign {
		return Authority{OwnerID: "@foreign:example.test", AccountGeneration: value.AccountGeneration + 1}
	}
	return value
}

func cloudPlanObject(authority Authority) CloudWorkerObject {
	return CloudWorkerObject{"owner_id": authority.OwnerID, "account_generation": authority.AccountGeneration, "plan_id": cloudPlanID, "revision": uint64(1), "status": "waiting_user"}
}

func cloudRunObject(authority Authority, revision uint64) CloudWorkerObject {
	return CloudWorkerObject{"owner_id": authority.OwnerID, "account_generation": authority.AccountGeneration, "run_id": cloudRunID, "execution_id": cloudRunID, "revision": revision, "status": "running"}
}

func (f *cloudWorkerPortFake) GetPlan(_ context.Context, request CloudWorkerPlanGetRequest) (CloudWorkerObject, error) {
	f.calls["plans.get"]++
	return cloudPlanObject(f.authority(request.Authority)), nil
}

func (f *cloudWorkerPortFake) ListPlans(_ context.Context, request CloudWorkerListRequest) (CloudWorkerPage, error) {
	f.calls["plans.list"]++
	return CloudWorkerPage{Items: []CloudWorkerObject{cloudPlanObject(f.authority(request.Authority))}, NextPageToken: "eyJjcmVhdGVkX2F0IjoiMjAzNS0wMS0wMVQwMDowMDowMFoiLCJpZCI6ImN1cnNvciJ9"}, nil
}

func (f *cloudWorkerPortFake) GetRun(_ context.Context, request CloudWorkerRunGetRequest) (CloudWorkerObject, error) {
	f.calls["runs.get"]++
	return cloudRunObject(f.authority(request.Authority), 3), nil
}

func (f *cloudWorkerPortFake) ListRuns(_ context.Context, request CloudWorkerListRequest) (CloudWorkerPage, error) {
	f.calls["runs.list"]++
	return CloudWorkerPage{Items: []CloudWorkerObject{cloudRunObject(f.authority(request.Authority), 3)}, NextPageToken: cloudRunID}, nil
}

func (f *cloudWorkerPortFake) CancelRun(_ context.Context, request CloudWorkerRunCancelRequest) (CloudWorkerObject, error) {
	f.calls["runs.cancel"]++
	return cloudRunObject(f.authority(request.Authority), request.ExpectedRevision+1), nil
}

func (f *cloudWorkerPortFake) RunEvents(_ context.Context, request CloudWorkerRunEventsRequest) (CloudWorkerEventPage, error) {
	f.calls["runs.events"]++
	authority := f.authority(request.Authority)
	next := request.AfterSequence + 1
	return CloudWorkerEventPage{Events: []CloudWorkerObject{{"owner_id": authority.OwnerID, "account_generation": authority.AccountGeneration, "run_id": request.RunID, "sequence": next, "event_id": "dddddddd-dddd-4ddd-8ddd-dddddddddddd"}}, NextSequence: next}, nil
}

func (f *cloudWorkerPortFake) GetArtifact(_ context.Context, request CloudWorkerArtifactGetRequest) (CloudWorkerObject, error) {
	f.calls["artifacts.get"]++
	authority := f.authority(request.Authority)
	return CloudWorkerObject{"owner_id": authority.OwnerID, "account_generation": authority.AccountGeneration,
		"artifact_id": cloudArtifactID, "execution_id": cloudRunID, "status": "verified"}, nil
}

func (f *cloudWorkerPortFake) DownloadArtifact(_ context.Context, request CloudWorkerArtifactDownloadRequest) (CloudWorkerArtifactChunk, error) {
	f.calls["artifacts.download"]++
	authority := f.authority(request.Authority)
	data := []byte("cloud-worker-chunk")
	digest := sha256.Sum256(data)
	chunk := CloudWorkerArtifactChunk{
		Authority: authority, ArtifactID: cloudArtifactID, ExecutionID: cloudRunID,
		OffsetBytes: request.OffsetBytes, Data: data, ChunkSHA256: hex.EncodeToString(digest[:]),
		ArtifactSHA256: hex.EncodeToString(digest[:]), SizeBytes: uint64(len(data)),
		NextOffsetBytes: request.OffsetBytes + uint64(len(data)), EOF: true,
	}
	if f.mutateChunk != nil {
		f.mutateChunk(&chunk)
	}
	return chunk, nil
}

func (f *cloudWorkerPortFake) DeleteArtifact(_ context.Context, request CloudWorkerArtifactDeleteRequest) (CloudWorkerObject, error) {
	f.calls["artifacts.delete"]++
	authority := f.authority(request.Authority)
	return CloudWorkerObject{"owner_id": authority.OwnerID, "account_generation": authority.AccountGeneration,
		"artifact_id": cloudArtifactID, "execution_id": cloudRunID, "status": "verified"}, nil
}

func newCloudRoutingService(t *testing.T, port CloudWorkerExecutionPort) *Service {
	t.Helper()
	service, err := NewService(port)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func TestCloudWorkerRecordKindRoutesEveryPublicReadAndCancel(t *testing.T) {
	port := &cloudWorkerPortFake{calls: map[string]int{}}
	service := newCloudRoutingService(t, port)
	authority := Authority{OwnerID: owner, AccountGeneration: cloudGeneration}
	tests := []struct {
		action string
		input  map[string]any
		key    string
	}{
		{"agent.execution.v2.plans.get", map[string]any{"plan_id": cloudPlanID}, "plans.get"},
		{"agent.execution.v2.plans.list", map[string]any{"page_size": 200}, "plans.list"},
		{"agent.execution.v2.runs.get", map[string]any{"run_id": cloudRunID}, "runs.get"},
		{"agent.execution.v2.runs.list", map[string]any{}, "runs.list"},
		{"agent.execution.v2.runs.cancel", map[string]any{"run_id": cloudRunID, "expected_revision": uint64(3), "idempotency_key": "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee"}, "runs.cancel"},
		{"agent.execution.v2.runs.events", map[string]any{"run_id": cloudRunID, "after_sequence": uint64(4)}, "runs.events"},
		{"agent.execution.v2.artifacts.get", map[string]any{"artifact_id": cloudArtifactID}, "artifacts.get"},
		{"agent.execution.v2.artifacts.download", map[string]any{"artifact_id": cloudArtifactID, "offset_bytes": uint64(0), "max_chunk_bytes": uint64(512 << 10)}, "artifacts.download"},
		{"agent.execution.v2.artifacts.delete", map[string]any{"artifact_id": cloudArtifactID, "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff"}, "artifacts.delete"},
	}
	for _, test := range tests {
		input := cloneMap(test.input)
		input["record_kind"] = RecordKindCloudWorker
		if _, err := service.HandleWithAuthority(context.Background(), authority, test.action, input); err != nil {
			t.Fatalf("%s: %v", test.action, err)
		}
		if port.calls[test.key] != 1 || port.lastAuthority != authority {
			t.Fatalf("%s calls=%d authority=%+v", test.action, port.calls[test.key], port.lastAuthority)
		}
	}
}

func TestLocalSandboxRecordKindRoutesOnlyArtifactOperations(t *testing.T) {
	port := &cloudWorkerPortFake{calls: map[string]int{}}
	service := newCloudRoutingService(t, port)
	authority := Authority{OwnerID: owner, AccountGeneration: cloudGeneration}
	for _, test := range []struct {
		action string
		input  map[string]any
		key    string
	}{
		{"agent.execution.v2.artifacts.get", map[string]any{"artifact_id": cloudArtifactID}, "artifacts.get"},
		{"agent.execution.v2.artifacts.download", map[string]any{"artifact_id": cloudArtifactID, "offset_bytes": uint64(0), "max_chunk_bytes": uint64(512 << 10)}, "artifacts.download"},
		{"agent.execution.v2.artifacts.delete", map[string]any{"artifact_id": cloudArtifactID, "idempotency_key": "ffffffff-ffff-4fff-8fff-ffffffffffff"}, "artifacts.delete"},
	} {
		test.input["record_kind"] = RecordKindLocalSandbox
		if _, err := service.HandleWithAuthority(context.Background(), authority, test.action, test.input); err != nil {
			t.Fatalf("%s: %v", test.action, err)
		}
		if port.calls[test.key] != 1 {
			t.Fatalf("%s calls = %d", test.action, port.calls[test.key])
		}
	}
	if _, err := service.HandleWithAuthority(context.Background(), authority, "agent.execution.v2.runs.list", map[string]any{"record_kind": RecordKindLocalSandbox}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("local sandbox run list error = %v", err)
	}
}

func TestCloudWorkerRoutingRejectsInvalidKindAuthorityAndProviderDrift(t *testing.T) {
	port := &cloudWorkerPortFake{calls: map[string]int{}}
	service := newCloudRoutingService(t, port)
	for _, kind := range []any{"", "legacy", 1} {
		if _, err := service.HandleWithAuthority(context.Background(), Authority{OwnerID: owner, AccountGeneration: cloudGeneration}, "agent.execution.v2.plans.get", map[string]any{"record_kind": kind, "plan_id": cloudPlanID}); !errors.Is(err, ErrInvalid) {
			t.Fatalf("record_kind=%v err=%v", kind, err)
		}
	}
	if _, err := service.HandleWithAuthority(context.Background(), Authority{OwnerID: owner, AccountGeneration: cloudGeneration}, "agent.execution.v2.artifacts.delete", map[string]any{
		"record_kind": RecordKindCloudWorker, "artifact_id": cloudArtifactID,
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("delete without idempotency key err=%v", err)
	}
	if _, err := service.Handle(context.Background(), owner, "agent.execution.v2.plans.get", map[string]any{"record_kind": RecordKindCloudWorker, "plan_id": cloudPlanID}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("zero account generation err=%v", err)
	}
	port.foreign = true
	if _, err := service.HandleWithAuthority(context.Background(), Authority{OwnerID: owner, AccountGeneration: cloudGeneration}, "agent.execution.v2.plans.get", map[string]any{"record_kind": RecordKindCloudWorker, "plan_id": cloudPlanID}); !errors.Is(err, ErrUnsafeOutput) {
		t.Fatalf("foreign provider projection err=%v", err)
	}
	if _, err := service.HandleWithAuthority(context.Background(), Authority{OwnerID: owner, AccountGeneration: cloudGeneration}, "agent.execution.v2.artifacts.get", map[string]any{"record_kind": RecordKindCloudWorker, "artifact_id": cloudArtifactID}); !errors.Is(err, ErrUnsafeOutput) {
		t.Fatalf("foreign artifact projection err=%v", err)
	}
	if _, err := service.HandleWithAuthority(context.Background(), Authority{OwnerID: owner, AccountGeneration: cloudGeneration}, "agent.execution.v2.artifacts.download", map[string]any{
		"record_kind": RecordKindCloudWorker, "artifact_id": cloudArtifactID,
		"offset_bytes": uint64(0), "max_chunk_bytes": MaxCloudWorkerArtifactDownloadChunkBytes,
	}); !errors.Is(err, ErrUnsafeOutput) {
		t.Fatalf("foreign artifact download err=%v", err)
	}
}

func TestValidateCloudWorkerEventsRejectsZeroSequenceOnTruncatedPage(t *testing.T) {
	authority := Authority{OwnerID: owner, AccountGeneration: cloudGeneration}
	page := CloudWorkerEventPage{
		Events: []CloudWorkerObject{{
			"owner_id":           authority.OwnerID,
			"account_generation": authority.AccountGeneration,
			"run_id":             cloudRunID,
			"sequence":           uint64(0),
		}},
		HistoryTruncated: true,
	}
	if _, err := validateCloudWorkerEvents(page, authority, cloudRunID, 0); !errors.Is(err, ErrUnsafeOutput) {
		t.Fatalf("zero sequence on truncated page err=%v", err)
	}
}

func TestCloudWorkerArtifactDownloadRejectsInvalidRangesBeforeProvider(t *testing.T) {
	port := &cloudWorkerPortFake{calls: map[string]int{}}
	service := newCloudRoutingService(t, port)
	authority := Authority{OwnerID: owner, AccountGeneration: cloudGeneration}
	tests := []struct {
		name  string
		input map[string]any
	}{
		{"negative offset", map[string]any{"offset_bytes": -1, "max_chunk_bytes": uint64(1)}},
		{"offset above output bound", map[string]any{"offset_bytes": MaxCloudWorkerArtifactDownloadOffsetBytes + 1, "max_chunk_bytes": uint64(1)}},
		{"zero chunk", map[string]any{"offset_bytes": uint64(0), "max_chunk_bytes": uint64(0)}},
		{"chunk above bound", map[string]any{"offset_bytes": uint64(0), "max_chunk_bytes": MaxCloudWorkerArtifactDownloadChunkBytes + 1}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := cloneMap(test.input)
			input["record_kind"] = RecordKindCloudWorker
			input["artifact_id"] = cloudArtifactID
			if _, err := service.HandleWithAuthority(context.Background(), authority, "agent.execution.v2.artifacts.download", input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err=%v", err)
			}
		})
	}
	if port.calls["artifacts.download"] != 0 {
		t.Fatalf("invalid ranges reached provider %d times", port.calls["artifacts.download"])
	}
}

func TestCloudWorkerArtifactDownloadRejectsUnsafeProviderChunk(t *testing.T) {
	authority := Authority{OwnerID: owner, AccountGeneration: cloudGeneration}
	tests := []struct {
		name   string
		mutate func(*CloudWorkerArtifactChunk)
	}{
		{"wrong offset", func(chunk *CloudWorkerArtifactChunk) { chunk.OffsetBytes++ }},
		{"bad chunk digest", func(chunk *CloudWorkerArtifactChunk) { chunk.ChunkSHA256 = strings.Repeat("0", 64) }},
		{"oversized data", func(chunk *CloudWorkerArtifactChunk) {
			chunk.Data = append(chunk.Data, 'x')
			chunk.NextOffsetBytes++
			chunk.SizeBytes++
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			port := &cloudWorkerPortFake{calls: map[string]int{}, mutateChunk: test.mutate}
			service := newCloudRoutingService(t, port)
			if _, err := service.HandleWithAuthority(context.Background(), authority, "agent.execution.v2.artifacts.download", map[string]any{
				"record_kind": RecordKindCloudWorker, "artifact_id": cloudArtifactID,
				"offset_bytes": uint64(0), "max_chunk_bytes": uint64(len("cloud-worker-chunk")),
			}); !errors.Is(err, ErrUnsafeOutput) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}
