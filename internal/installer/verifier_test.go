package installer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

type fakeArtifactInspector struct {
	err   error
	paths []string
}

func (f *fakeArtifactInspector) Verify(_ context.Context, artifact ArtifactV1) error {
	f.paths = append(f.paths, artifact.TargetPath)
	return f.err
}

type verifierFixture struct {
	now       time.Time
	private   ed25519.PrivateKey
	public    ed25519.PublicKey
	binding   BindingV1
	plan      InstallerPlanV1
	request   RequestV1
	inspector *fakeArtifactInspector
	verifier  *Verifier
}

func newVerifierFixture(t *testing.T) verifierFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 17, 12, 0, 0, 0, time.UTC)
	binding := BindingV1{
		AgentInstanceID: "77777777-7777-4777-8777-777777777777",
		DeploymentID:    "11111111-1111-4111-8111-111111111111",
		TaskID:          "22222222-2222-4222-8222-222222222222",
		PlanHash:        "sha256:" + strings.Repeat("1", 64),
		ApprovalID:      "33333333-3333-4333-8333-333333333333",
		LeaseEpoch:      7,
		RecipeDigest:    "sha256:" + strings.Repeat("2", 64),
	}
	artifactContent := []byte("digest-pinned artifact")
	artifactDigest := sha256.Sum256(artifactContent)
	plan := InstallerPlanV1{
		SchemaVersion: PlanSchemaV1,
		Binding:       binding,
		Artifacts: []ArtifactV1{{
			Name:       "openclaw-bundle",
			SHA256:     digestString(artifactDigest),
			SizeBytes:  int64(len(artifactContent)),
			TargetPath: "/opt/dirextalk/deployments/11111111-1111-4111-8111-111111111111/artifacts/openclaw.tar.zst",
		}},
		SecretRefs: []string{"secret_ref:deployment/model-token"},
		Network: NetworkV1{
			PublicInbound:      false,
			OutboundHTTPSHosts: []string{"api.deepseek.com", "github.com"},
		},
		Ports:     []PortV1{{Name: "gateway", Protocol: "tcp", Direction: "loopback", Port: 18789}},
		Volumes:   []VolumeV1{{Name: "knowledge", MountPath: "/srv/knowledge", ReadOnly: false, SizeGiB: 40}},
		ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano),
	}
	payload, err := PlanSigningBytes(plan)
	if err != nil {
		t.Fatal(err)
	}
	request := RequestV1{
		SchemaVersion:  RequestSchemaV1,
		RequestID:      "44444444-4444-4444-8444-444444444444",
		IdempotencyKey: "55555555-5555-4555-8555-555555555555",
		Action:         ActionVerify,
		Binding:        binding,
		SignedPlan: SignedInstallerPlanV1{
			Plan:        plan,
			SignerKeyID: SignerKeyID(publicKey),
			Signature:   ed25519.Sign(privateKey, payload),
		},
		ArtifactName: "openclaw-bundle",
	}
	inspector := &fakeArtifactInspector{}
	verifier, err := NewVerifier(VerifierConfig{
		PublicKey: publicKey, ExpectedBinding: binding,
		TargetRoot: "/opt/dirextalk/deployments/11111111-1111-4111-8111-111111111111/artifacts",
		Now:        func() time.Time { return now }, Inspector: inspector, MaxIdempotencyEntries: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifierFixture{now: now, private: privateKey, public: publicKey, binding: binding, plan: plan, request: request, inspector: inspector, verifier: verifier}
}

func TestVerifierAcceptsExactSignedBindingAndReplaysIdempotently(t *testing.T) {
	fixture := newVerifierFixture(t)
	first, err := fixture.verifier.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusVerified || first.Replayed || first.ArtifactName != "openclaw-bundle" || first.SHA256 != fixture.plan.Artifacts[0].SHA256 {
		t.Fatalf("unexpected first response: %#v", first)
	}
	second, err := fixture.verifier.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || second.Status != StatusVerified || len(fixture.inspector.paths) != 1 {
		t.Fatalf("replay re-executed verification: response=%#v calls=%d", second, len(fixture.inspector.paths))
	}
}

func TestVerifierFencesConcurrentIdempotentReplays(t *testing.T) {
	fixture := newVerifierFixture(t)
	const callers = 16
	start := make(chan struct{})
	responses := make(chan ResponseV1, callers)
	errorsFound := make(chan error, callers)
	var wait sync.WaitGroup
	for range callers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			response, err := fixture.verifier.Verify(context.Background(), fixture.request)
			responses <- response
			errorsFound <- err
		}()
	}
	close(start)
	wait.Wait()
	close(responses)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	nonReplayed := 0
	for response := range responses {
		if !response.Replayed {
			nonReplayed++
		}
	}
	if nonReplayed != 1 || len(fixture.inspector.paths) != 1 {
		t.Fatalf("verification was not fenced: first=%d inspector_calls=%d", nonReplayed, len(fixture.inspector.paths))
	}
}

func TestVerifierRejectsSecurityBoundaryChanges(t *testing.T) {
	tests := []struct {
		name string
		code ErrorCode
		edit func(*verifierFixture)
	}{
		{name: "unknown action", code: CodeUnsupportedAction, edit: func(f *verifierFixture) { f.request.Action = "installer.exec" }},
		{name: "expired", code: CodePlanExpired, edit: func(f *verifierFixture) {
			f.now = f.now.Add(10 * time.Minute)
			f.verifier.now = func() time.Time { return f.now }
		}},
		{name: "request binding mismatch", code: CodeBindingMismatch, edit: func(f *verifierFixture) { f.request.Binding.LeaseEpoch++ }},
		{name: "signed plan binding mismatch", code: CodeBindingMismatch, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Binding.TaskID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			resignRequest(t, f)
		}},
		{name: "bad signature", code: CodeInvalidSignature, edit: func(f *verifierFixture) { f.request.SignedPlan.Signature[0] ^= 0xff }},
		{name: "wrong signer", code: CodeInvalidSignature, edit: func(f *verifierFixture) { f.request.SignedPlan.SignerKeyID = "sha256:" + strings.Repeat("f", 64) }},
		{name: "undeclared artifact", code: CodeArtifactNotAllowed, edit: func(f *verifierFixture) { f.request.ArtifactName = "other" }},
		{name: "path traversal", code: CodeInvalidPath, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Artifacts[0].TargetPath = "/opt/dirextalk/deployments/11111111-1111-4111-8111-111111111111/artifacts/../escape"
			resignRequest(t, f)
		}},
		{name: "outside target root", code: CodeInvalidPath, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Artifacts[0].TargetPath = "/etc/shadow"
			resignRequest(t, f)
		}},
		{name: "secret value instead of reference", code: CodeInvalidRequest, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.SecretRefs = []string{"sk-raw-secret-value"}
			resignRequest(t, f)
		}},
		{name: "non canonical agent instance", code: CodeInvalidRequest, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Binding.AgentInstanceID = "project-a"
			resignRequest(t, f)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerifierFixture(t)
			test.edit(&fixture)
			_, err := fixture.verifier.Verify(context.Background(), fixture.request)
			if !errors.Is(err, Error(test.code)) {
				t.Fatalf("error = %v, want code %s", err, test.code)
			}
			if len(fixture.inspector.paths) != 0 {
				t.Fatalf("artifact inspector called for rejected request: %#v", fixture.inspector.paths)
			}
		})
	}
}

func TestVerifierRejectsIdempotencyKeyReuseWithDifferentRequest(t *testing.T) {
	fixture := newVerifierFixture(t)
	if _, err := fixture.verifier.Verify(context.Background(), fixture.request); err != nil {
		t.Fatal(err)
	}
	fixture.request.RequestID = "66666666-6666-4666-8666-666666666666"
	if _, err := fixture.verifier.Verify(context.Background(), fixture.request); !errors.Is(err, Error(CodeIdempotencyConflict)) {
		t.Fatalf("error = %v, want idempotency conflict", err)
	}
}

func TestVerifierMapsArtifactFailureWithoutEchoingSensitiveData(t *testing.T) {
	fixture := newVerifierFixture(t)
	fixture.inspector.err = errors.New("digest mismatch at /secret/path using token super-secret")
	server := NewServer(fixture.verifier, ServerConfig{MaxRequestBytes: 256 << 10})
	raw, err := canonical.Marshal(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	var input, output bytes.Buffer
	writeTestFrame(&input, raw)
	if err := server.Handle(context.Background(), &input, &output); err != nil {
		t.Fatal(err)
	}
	responseBytes := readTestFrame(t, &output)
	if bytes.Contains(responseBytes, []byte("super-secret")) || bytes.Contains(responseBytes, []byte("/secret/path")) || bytes.Contains(responseBytes, []byte("secret_ref:")) {
		t.Fatalf("response leaked sensitive request or internal error: %x", responseBytes)
	}
	var response ResponseV1
	if err := DecodeCanonical(responseBytes, &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusRejected || response.ErrorCode != CodeArtifactVerification {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func TestDecodeCanonicalRejectsNonCanonicalEncoding(t *testing.T) {
	// {"a": 1} with 1 encoded in a non-shortest uint form.
	raw := []byte{0xa1, 0x61, 'a', 0x18, 0x01}
	var target struct {
		A uint64 `json:"a"`
	}
	if err := DecodeCanonical(raw, &target); !errors.Is(err, Error(CodeNonCanonicalCBOR)) {
		t.Fatalf("error = %v, want non-canonical CBOR", err)
	}
}

func TestServerRejectsOversizedFrameBeforeReadingPayload(t *testing.T) {
	fixture := newVerifierFixture(t)
	server := NewServer(fixture.verifier, ServerConfig{MaxRequestBytes: 64})
	var input, output bytes.Buffer
	_ = binary.Write(&input, binary.BigEndian, uint32(65))
	if err := server.Handle(context.Background(), &input, &output); err != nil {
		t.Fatal(err)
	}
	var response ResponseV1
	if err := DecodeCanonical(readTestFrame(t, &output), &response); err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != CodeRequestTooLarge {
		t.Fatalf("unexpected response: %#v", response)
	}
}

func resignRequest(t *testing.T, fixture *verifierFixture) {
	t.Helper()
	payload, err := PlanSigningBytes(fixture.request.SignedPlan.Plan)
	if err != nil {
		t.Fatal(err)
	}
	fixture.request.SignedPlan.Signature = ed25519.Sign(fixture.private, payload)
}

func writeTestFrame(buffer *bytes.Buffer, payload []byte) {
	_ = binary.Write(buffer, binary.BigEndian, uint32(len(payload)))
	_, _ = buffer.Write(payload)
}

func readTestFrame(t *testing.T, buffer *bytes.Buffer) []byte {
	t.Helper()
	var size uint32
	if err := binary.Read(buffer, binary.BigEndian, &size); err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, size)
	if _, err := buffer.Read(payload); err != nil {
		t.Fatal(err)
	}
	return payload
}
