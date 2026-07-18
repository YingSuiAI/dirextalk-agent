package installer

import (
	"context"
	"fmt"
	"testing"
)

type fakeProbe struct {
	requests []map[string]any
	failAt   int
	notReady bool
}

func (f *fakeProbe) RoundTrip(_ context.Context, request map[string]any) (map[string]any, error) {
	f.requests = append(f.requests, request)
	if f.failAt == len(f.requests) {
		return nil, fmt.Errorf("injected probe failure")
	}
	result := map[string]any{}
	switch request["operation"] {
	case "store_memory":
		result = map[string]any{
			"owner_id": probeOwnerID, "binding_id": probeBindingID, "point_id": probePointID,
			"source_id": probeMemoryID, "revision_id": probeRevision, "kind": "memory",
			"content_size": float64(49), "content_sha256": probeDigest, "indexed_segment_count": 1,
		}
	case "search":
		result = map[string]any{"results": []any{map[string]any{
			"point_id": probePointID, "owner_id": probeOwnerID, "binding_id": probeBindingID,
			"source_id": probeMemoryID, "revision_id": probeRevision, "kind": "memory",
			"content_size": float64(49), "content_sha256": probeDigest,
		}}}
	case "status":
		result = map[string]any{
			"owner_id": probeOwnerID, "binding_id": probeBindingID,
			"ready": !f.notReady, "model": "intfloat/multilingual-e5-small", "model_revision": ModelRevision,
			"dimensions": float64(384), "execution_provider": "CPUExecutionProvider",
			"collection": "dirextalk_knowledge_v1", "status": "green",
			"persistence": map[string]any{
				"point_id": probePointID, "source_id": probeMemoryID, "verified": true,
				"revision_id": probeRevision, "content_size": float64(49), "content_sha256": probeDigest,
			},
		}
	}
	return map[string]any{"ok": true, "operation_id": request["operation_id"], "result": result}, nil
}

func TestSemanticProbeExercisesStoreSearchAndPersistenceEvidence(t *testing.T) {
	t.Parallel()
	client := &fakeProbe{}
	if err := SemanticProbeV1(context.Background(), client); err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 3 {
		t.Fatalf("request count = %d", len(client.requests))
	}
	want := []any{"store_memory", "search", "status"}
	for index, request := range client.requests {
		if request["operation"] != want[index] {
			t.Fatalf("operation %d = %v", index, request["operation"])
		}
		body := request["body"].(map[string]any)
		if body["owner_id"] != probeOwnerID || body["binding_id"] != probeBindingID {
			t.Fatal("probe omitted owner/binding fence")
		}
	}
}

func TestSemanticProbeFailsClosed(t *testing.T) {
	t.Parallel()
	if err := SemanticProbeV1(context.Background(), &fakeProbe{failAt: 2}); err == nil {
		t.Fatal("expected injected probe failure")
	}
	if err := SemanticProbeV1(context.Background(), &fakeProbe{notReady: true}); err == nil {
		t.Fatal("expected not-ready status rejection")
	}
}

func TestProbeUUIDAndSegmentCountValidation(t *testing.T) {
	t.Parallel()
	if !isCanonicalUUID(probePointID) || isCanonicalUUID("EB886927-4108-5556-9F64-9C883DE47203") {
		t.Fatal("canonical UUID validation mismatch")
	}
	for _, value := range []any{0, 513, 1.5, float64(0)} {
		if positiveBoundedCount(value, 512) {
			t.Fatalf("accepted invalid segment count %v", value)
		}
	}
}
