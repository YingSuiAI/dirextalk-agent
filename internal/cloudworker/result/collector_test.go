package result

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

func TestCollectorUsesExactS3VersionsAndVerifiesCanonicalArtifacts(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	reader := &fakeObjectReader{objects: fixture.objects}
	collector, err := NewCollector(reader, fixture.scope)
	if err != nil {
		t.Fatal(err)
	}
	collected, err := collector.Collect(t.Context(), fixture.manifestClaim, fixture.expectation)
	if err != nil {
		t.Fatal(err)
	}
	defer collected.Destroy()
	if collected.Final.Status != "completed" || collected.Final.Summary != "Task complete." ||
		len(collected.Artifacts) != 2 || len(reader.requests) != 3 {
		t.Fatalf("collected=%+v requests=%+v", collected, reader.requests)
	}
	wantVersions := map[string]string{
		fixture.manifestClaim.Key:         fixture.manifestClaim.VersionID,
		fixture.manifest.Artifacts[0].Key: fixture.manifest.Artifacts[0].VersionID,
		fixture.manifest.Artifacts[1].Key: fixture.manifest.Artifacts[1].VersionID,
	}
	for _, request := range reader.requests {
		if request.Bucket != fixture.scope.Bucket ||
			request.VersionID != wantVersions[request.Key] || request.VersionID == "" ||
			request.MaximumBytes < 1 {
			t.Fatalf("non-exact object request=%+v", request)
		}
	}
}

func TestVerifierRejectsVersionMetadataDigestSizeAndMediaDrift(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	claim := fixture.manifest.Artifacts[0]
	for _, test := range []struct {
		name   string
		mutate func(*storedObject)
	}{
		{name: "version", mutate: func(object *storedObject) { object.versionID = "replacement-version" }},
		{name: "digest", mutate: func(object *storedObject) { object.content = []byte("tampered") }},
		{name: "size", mutate: func(object *storedObject) { object.sizeBytes++ }},
		{name: "media", mutate: func(object *storedObject) { object.mediaType = "text/plain; charset=utf-8" }},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			object := fixture.objects[objectMapKey(claim.Bucket, claim.Key, claim.VersionID)]
			copy := object.clone()
			test.mutate(&copy)
			reader := &fakeObjectReader{objects: map[string]storedObject{
				objectMapKey(claim.Bucket, claim.Key, claim.VersionID): copy,
			}}
			verifier, err := NewVerifier(reader, fixture.scope)
			if err != nil {
				t.Fatal(err)
			}
			verified, err := verifier.Verify(t.Context(), claim)
			verified.Destroy()
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("drift error=%v", err)
			}
		})
	}
}

func TestObjectClaimRequiresImmutableVersionAndExactScope(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	claim := fixture.manifest.Artifacts[0]
	for _, mutate := range []func(*ObjectClaim){
		func(value *ObjectClaim) { value.VersionID = "" },
		func(value *ObjectClaim) { value.VersionID = "null" },
		func(value *ObjectClaim) { value.Key = "other-execution/final.json" },
		func(value *ObjectClaim) { value.SHA256 = "sha256:" + value.SHA256 },
		func(value *ObjectClaim) { value.SHA256 = strings.ToUpper(value.SHA256) },
		func(value *ObjectClaim) { value.SizeBytes = MaxObjectBytes + 1 },
	} {
		candidate := claim
		mutate(&candidate)
		if candidate.Validate() == nil && fixture.scope.Contains(candidate) {
			t.Fatalf("unsafe claim accepted: %+v", candidate)
		}
	}
}

func TestCollectorRejectsNonCanonicalFinalAndManifestDrift(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	finalClaim := fixture.manifest.Artifacts[0]
	unsafeFinal := []byte(`{"schema_version":"dirextalk.agent.pi-final/v1","status":"completed","summary":"Task complete.","deliverables":[],"tests":[],"risks":[],"extra":true}`)
	replaceObjectAndClaim(t, &fixture, 0, unsafeFinal)
	collector, err := NewCollector(&fakeObjectReader{objects: fixture.objects}, fixture.scope)
	if err != nil {
		t.Fatal(err)
	}
	collected, err := collector.Collect(t.Context(), fixture.manifestClaim, fixture.expectation)
	collected.Destroy()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("non-canonical final error=%v original=%+v", err, finalClaim)
	}

	fixture = newFixture(t)
	manifestRaw, err := json.Marshal(map[string]any{
		"schema_version":   ManifestSchemaV1,
		"execution_id":     fixture.expectation.ExecutionID,
		"execution_sha256": fixture.expectation.ExecutionSHA256,
		"task_id":          fixture.expectation.TaskID,
		"task_sha256":      fixture.expectation.TaskSHA256,
		"session_id":       fixture.expectation.SessionID,
		"attempt":          fixture.expectation.Attempt,
		"lease_epoch":      fixture.expectation.LeaseEpoch,
		"adapter":          cloudruntime.AdapterPiJSONTaskV1,
		"workspace_mode":   fixture.expectation.WorkspaceMode,
		"status":           "succeeded", "usage": cloudruntime.Usage{},
		"artifacts": fixture.manifest.Artifacts, "unexpected": true,
	})
	if err != nil {
		t.Fatal(err)
	}
	replaceManifest(t, &fixture, manifestRaw)
	collector, _ = NewCollector(&fakeObjectReader{objects: fixture.objects}, fixture.scope)
	collected, err = collector.Collect(t.Context(), fixture.manifestClaim, fixture.expectation)
	collected.Destroy()
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("manifest drift error=%v", err)
	}
}

func TestManifestBindsExecutionTaskLeaseAndWorkspaceMode(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	for _, mutate := range []func(*Expectation){
		func(value *Expectation) { value.ExecutionSHA256 = strings.Repeat("b", 64) },
		func(value *Expectation) { value.TaskSHA256 = strings.Repeat("c", 64) },
		func(value *Expectation) { value.LeaseEpoch++ },
		func(value *Expectation) { value.WorkspaceMode = cloudruntime.WorkspaceReadOnly },
	} {
		expectation := fixture.expectation
		mutate(&expectation)
		if fixture.manifest.Validate(expectation, fixture.scope) == nil {
			t.Fatalf("mismatched expectation accepted: %+v", expectation)
		}
	}
	readOnly := fixture.manifest
	readOnly.WorkspaceMode = cloudruntime.WorkspaceReadOnly
	readOnlyExpectation := fixture.expectation
	readOnlyExpectation.WorkspaceMode = cloudruntime.WorkspaceReadOnly
	if readOnly.Validate(readOnlyExpectation, fixture.scope) == nil {
		t.Fatal("read-only manifest accepted a patch artifact")
	}
}

func TestVerifierMapsReaderFailureWithoutLeakingDiagnostics(t *testing.T) {
	t.Parallel()
	fixture := newFixture(t)
	reader := &fakeObjectReader{err: errors.New("sensitive storage diagnostic")}
	verifier, err := NewVerifier(reader, fixture.scope)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifier.Verify(t.Context(), fixture.manifestClaim)
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("reader error=%v", err)
	}
}

type resultFixture struct {
	scope         Scope
	expectation   Expectation
	manifest      Manifest
	manifestClaim ObjectClaim
	objects       map[string]storedObject
}

type storedObject struct {
	bucket    string
	key       string
	versionID string
	sizeBytes int64
	mediaType string
	content   []byte
}

func (object storedObject) clone() storedObject {
	object.content = bytes.Clone(object.content)
	return object
}

type fakeObjectReader struct {
	objects  map[string]storedObject
	requests []ObjectRequest
	err      error
}

func (reader *fakeObjectReader) ReadObject(_ context.Context, request ObjectRequest) (ObjectRead, error) {
	reader.requests = append(reader.requests, request)
	if reader.err != nil {
		return ObjectRead{}, reader.err
	}
	object, found := reader.objects[objectMapKey(request.Bucket, request.Key, request.VersionID)]
	if !found {
		return ObjectRead{}, errors.New("object unavailable")
	}
	return ObjectRead{
		Bucket: object.bucket, Key: object.key, VersionID: object.versionID,
		SizeBytes: object.sizeBytes, MediaType: object.mediaType,
		Body: io.NopCloser(bytes.NewReader(object.content)),
	}, nil
}

func newFixture(t *testing.T) resultFixture {
	t.Helper()
	scope := Scope{
		Bucket:    "dirextalk-worker-results",
		KeyPrefix: "executions/22222222-2222-4222-8222-222222222222/artifacts/",
	}
	expectation := Expectation{
		ExecutionID:     "22222222-2222-4222-8222-222222222222",
		ExecutionSHA256: strings.Repeat("e", 64),
		TaskID:          "11111111-1111-4111-8111-111111111111",
		TaskSHA256:      strings.Repeat("a", 64),
		SessionID:       "33333333-3333-4333-8333-333333333333",
		Attempt:         1, LeaseEpoch: 7, WorkspaceMode: cloudruntime.WorkspaceWrite,
	}
	final := []byte(`{"schema_version":"dirextalk.agent.pi-final/v1","status":"completed","summary":"Task complete.","deliverables":["Patch produced."],"tests":["Focused tests passed."],"risks":[]}`)
	patch := []byte("diff --git a/main.go b/main.go\n")
	finalClaim := claimFor(
		"final.json", scope, "runtime-final.json", "version-final-1",
		"application/json", final,
	)
	patchClaim := claimFor(
		"changes.patch", scope, "runtime-changes.patch", "version-patch-1",
		"text/plain; charset=utf-8", patch,
	)
	manifest := Manifest{
		SchemaVersion: ManifestSchemaV1,
		ExecutionID:   expectation.ExecutionID, ExecutionSHA256: expectation.ExecutionSHA256,
		TaskID: expectation.TaskID, TaskSHA256: expectation.TaskSHA256,
		SessionID: expectation.SessionID, Attempt: expectation.Attempt,
		LeaseEpoch: expectation.LeaseEpoch, Adapter: cloudruntime.AdapterPiJSONTaskV1,
		WorkspaceMode: expectation.WorkspaceMode, Status: "succeeded",
		Usage:     cloudruntime.Usage{InputTokens: 12, OutputTokens: 4},
		Artifacts: []ObjectClaim{finalClaim, patchClaim},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestClaim := claimFor(
		"result.json", scope, "result.json", "version-manifest-1",
		"application/json", manifestRaw,
	)
	objects := make(map[string]storedObject)
	for _, pair := range []struct {
		claim ObjectClaim
		raw   []byte
	}{{manifestClaim, manifestRaw}, {finalClaim, final}, {patchClaim, patch}} {
		objects[objectMapKey(pair.claim.Bucket, pair.claim.Key, pair.claim.VersionID)] = storedObject{
			bucket: pair.claim.Bucket, key: pair.claim.Key, versionID: pair.claim.VersionID,
			sizeBytes: pair.claim.SizeBytes, mediaType: pair.claim.MediaType,
			content: bytes.Clone(pair.raw),
		}
	}
	return resultFixture{
		scope: scope, expectation: expectation, manifest: manifest,
		manifestClaim: manifestClaim, objects: objects,
	}
}

func claimFor(name string, scope Scope, suffix, versionID, mediaType string, raw []byte) ObjectClaim {
	digest := sha256.Sum256(raw)
	return ObjectClaim{
		Name: name, Bucket: scope.Bucket, Key: scope.KeyPrefix + suffix,
		VersionID: versionID, SHA256: hex.EncodeToString(digest[:]),
		SizeBytes: int64(len(raw)), MediaType: mediaType,
	}
}

func replaceObjectAndClaim(t *testing.T, fixture *resultFixture, index int, raw []byte) {
	t.Helper()
	old := fixture.manifest.Artifacts[index]
	delete(fixture.objects, objectMapKey(old.Bucket, old.Key, old.VersionID))
	claim := claimFor(old.Name, fixture.scope, strings.TrimPrefix(old.Key, fixture.scope.KeyPrefix),
		old.VersionID, old.MediaType, raw)
	fixture.manifest.Artifacts[index] = claim
	fixture.objects[objectMapKey(claim.Bucket, claim.Key, claim.VersionID)] = storedObject{
		bucket: claim.Bucket, key: claim.Key, versionID: claim.VersionID,
		sizeBytes: claim.SizeBytes, mediaType: claim.MediaType, content: bytes.Clone(raw),
	}
	manifestRaw, err := json.Marshal(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	replaceManifest(t, fixture, manifestRaw)
}

func replaceManifest(t *testing.T, fixture *resultFixture, raw []byte) {
	t.Helper()
	old := fixture.manifestClaim
	delete(fixture.objects, objectMapKey(old.Bucket, old.Key, old.VersionID))
	fixture.manifestClaim = claimFor(
		"result.json", fixture.scope, "result.json", old.VersionID, "application/json", raw,
	)
	claim := fixture.manifestClaim
	fixture.objects[objectMapKey(claim.Bucket, claim.Key, claim.VersionID)] = storedObject{
		bucket: claim.Bucket, key: claim.Key, versionID: claim.VersionID,
		sizeBytes: claim.SizeBytes, mediaType: claim.MediaType, content: bytes.Clone(raw),
	}
}

func objectMapKey(bucket, key, versionID string) string {
	return bucket + "\x00" + key + "\x00" + versionID
}
