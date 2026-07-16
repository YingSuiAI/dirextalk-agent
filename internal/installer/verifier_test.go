package installer

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
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

type fakeCommandRunner struct {
	executions []CommandExecution
	run        func(context.Context, CommandExecution) error
}

func (f *fakeCommandRunner) Run(ctx context.Context, execution CommandExecution) error {
	f.executions = append(f.executions, execution)
	if f.run != nil {
		return f.run(ctx, execution)
	}
	return nil
}

func (f *fakeArtifactInspector) Verify(_ context.Context, artifact ArtifactV1) error {
	f.paths = append(f.paths, artifact.TargetPath)
	return f.err
}

type verifierFixture struct {
	now            time.Time
	private        ed25519.PrivateKey
	public         ed25519.PublicKey
	binding        BindingV1
	plan           InstallerPlanV1
	request        RequestV1
	leaseEpoch     int64
	leaseExpiresAt time.Time
	inspector      *fakeArtifactInspector
	verifier       *Verifier
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
			TargetPath: PreinstalledArtifactRoot + "/openclaw.tar.zst",
		}},
		SecretRefs: []string{"secret_ref:deployment/model-token"},
		Network: NetworkV1{
			PublicInbound:      false,
			OutboundHTTPSHosts: []string{"api.deepseek.com", "github.com"},
		},
		Ports:   []PortV1{{Name: "gateway", Protocol: "tcp", Direction: "loopback", Port: 18789}},
		Volumes: []VolumeV1{{Name: "knowledge", MountPath: "/srv/knowledge", ReadOnly: false, SizeGiB: 40}},
		Commands: []CommandV1{{
			CommandID:        "install-openclaw",
			Argv:             []string{PreinstalledArtifactRoot + "/openclaw.tar.zst", "--mode", "ready"},
			WorkingDirectory: PreinstalledArtifactRoot,
			TimeoutSeconds:   300,
			ArtifactRefs:     []string{"openclaw-bundle"},
			VolumeRefs:       []string{"knowledge"},
			SecretRefs:       []string{"secret_ref:deployment/model-token"},
		}},
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
		TargetRoot: PreinstalledArtifactRoot,
		Now:        func() time.Time { return now }, Inspector: inspector, MaxIdempotencyEntries: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	return verifierFixture{
		now: now, private: privateKey, public: publicKey, binding: binding, plan: plan, request: request,
		leaseEpoch: 7, leaseExpiresAt: now.Add(time.Minute), inspector: inspector, verifier: verifier,
	}
}

func TestExecutorRunsOnlyExactSignedCommandAndReplaysFromPersistentJournal(t *testing.T) {
	fixture := newVerifierFixture(t)
	fixture.request.Action = ActionExecute
	fixture.request.ArtifactName = ""
	fixture.request.CommandID = "install-openclaw"
	resignRequest(t, &fixture)
	journalPath := filepath.Join(t.TempDir(), "execution.journal")
	journal, err := openExecutionJournal(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{}
	verifier, err := NewVerifier(VerifierConfig{
		PublicKey: fixture.public, ExpectedBinding: fixture.binding,
		TargetRoot: PreinstalledArtifactRoot,
		Now:        func() time.Time { return fixture.now }, Inspector: fixture.inspector,
		Runner: runner, Journal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := verifier.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusExecuted || first.CommandID != "install-openclaw" || first.Replayed || len(runner.executions) != 1 {
		t.Fatalf("unexpected first execution: response=%#v executions=%#v", first, runner.executions)
	}
	execution := runner.executions[0]
	want := fixture.plan.Commands[0]
	if !slices.Equal(execution.Argv, want.Argv) || execution.WorkingDirectory != want.WorkingDirectory || execution.Timeout != time.Minute ||
		!slices.Equal(execution.Environment, []string{SafePathEnvironment}) {
		t.Fatalf("execution escaped signed command: %#v", execution)
	}
	if len(fixture.inspector.paths) != 1 {
		t.Fatalf("referenced artifact was not verified exactly once: %#v", fixture.inspector.paths)
	}

	reopened, err := openExecutionJournal(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	replayRunner := &fakeCommandRunner{}
	fixture.now = fixture.now.Add(30 * time.Second)
	fixture.leaseEpoch++
	fixture.leaseExpiresAt = fixture.now.Add(time.Minute)
	resignRequest(t, &fixture)
	replayVerifier, err := NewVerifier(VerifierConfig{
		PublicKey: fixture.public, ExpectedBinding: fixture.binding,
		TargetRoot: PreinstalledArtifactRoot,
		Now:        func() time.Time { return fixture.now }, Inspector: &fakeArtifactInspector{},
		Runner: replayRunner, Journal: reopened,
	})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := replayVerifier.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if !replayed.Replayed || replayed.Status != StatusExecuted || len(replayRunner.executions) != 0 {
		t.Fatalf("persistent replay executed again: response=%#v executions=%d", replayed, len(replayRunner.executions))
	}
	changed := fixture.request
	changed.RequestID = "66666666-6666-4666-8666-666666666666"
	if _, err := replayVerifier.Verify(context.Background(), changed); !errors.Is(err, Error(CodeLeaseRejected)) {
		t.Fatalf("changed operation identity was accepted: %v", err)
	}
}

func TestExecutorRecoversRunningJournalAsNonReplayableInterruption(t *testing.T) {
	fixture := newVerifierFixture(t)
	fixture.request.Action = ActionExecute
	fixture.request.ArtifactName = ""
	fixture.request.CommandID = "install-openclaw"
	resignRequest(t, &fixture)
	digest, err := executionOperationDigest(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "execution.journal")
	journal, err := openExecutionJournal(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.FenceLease(fixture.leaseEpoch); err != nil {
		t.Fatal(err)
	}
	_, replayed, err := journal.Begin(fixture.request.IdempotencyKey, digest, ResponseV1{
		SchemaVersion: ResponseSchemaV1, RequestID: fixture.request.RequestID,
		Action: ActionExecute, CommandID: fixture.request.CommandID,
	})
	if err != nil || replayed {
		t.Fatalf("begin journal: replayed=%v err=%v", replayed, err)
	}
	file, err := os.OpenFile(journalPath, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte{0, 1}); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := openExecutionJournal(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{}
	fixture.now = fixture.now.Add(30 * time.Second)
	fixture.leaseEpoch++
	fixture.leaseExpiresAt = fixture.now.Add(time.Minute)
	resignRequest(t, &fixture)
	verifier, err := NewVerifier(VerifierConfig{
		PublicKey: fixture.public, ExpectedBinding: fixture.binding,
		TargetRoot: PreinstalledArtifactRoot,
		Now:        func() time.Time { return fixture.now }, Inspector: &fakeArtifactInspector{}, Runner: runner, Journal: reopened,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := verifier.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusInterrupted || response.ErrorCode != CodeExecutionInterrupted || !response.Replayed || len(runner.executions) != 0 {
		t.Fatalf("interrupted execution replayed automatically: response=%#v calls=%d", response, len(runner.executions))
	}
}

func TestExecutorRejectsRuntimeScopeAndSignedCommandChanges(t *testing.T) {
	tests := []struct {
		name string
		code ErrorCode
		edit func(*verifierFixture)
	}{
		{name: "relative working directory", code: CodeInvalidPath, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Commands[0].WorkingDirectory = "relative"
			resignRequest(t, f)
		}},
		{name: "nul argument", code: CodeInvalidRequest, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Commands[0].Argv[2] += "\x00hidden"
			resignRequest(t, f)
		}},
		{name: "plaintext secret in argument", code: CodeInvalidRequest, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Commands[0].Argv = append(f.request.SignedPlan.Plan.Commands[0].Argv, "sk-0123456789abcdef0123456789abcdef")
			resignRequest(t, f)
		}},
		{name: "missing artifact ref", code: CodeInvalidRequest, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Commands[0].ArtifactRefs = nil
			resignRequest(t, f)
		}},
		{name: "undeclared artifact ref", code: CodeInvalidRequest, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Commands[0].ArtifactRefs = []string{"other"}
			resignRequest(t, f)
		}},
		{name: "undeclared volume ref", code: CodeInvalidRequest, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Commands[0].VolumeRefs = []string{"other"}
			resignRequest(t, f)
		}},
		{name: "undeclared secret ref", code: CodeInvalidRequest, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Commands[0].SecretRefs = []string{"secret_ref:deployment/other"}
			resignRequest(t, f)
		}},
		{name: "runtime artifact", code: CodeInvalidRequest, edit: func(f *verifierFixture) { f.request.ArtifactName = "openclaw-bundle" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newVerifierFixture(t)
			fixture.request.Action = ActionExecute
			fixture.request.ArtifactName = ""
			fixture.request.CommandID = "install-openclaw"
			resignRequest(t, &fixture)
			test.edit(&fixture)
			journal, err := openExecutionJournal(filepath.Join(t.TempDir(), "execution.journal"), false)
			if err != nil {
				t.Fatal(err)
			}
			runner := &fakeCommandRunner{}
			verifier, err := NewVerifier(VerifierConfig{
				PublicKey: fixture.public, ExpectedBinding: fixture.binding,
				TargetRoot: PreinstalledArtifactRoot,
				Now:        func() time.Time { return fixture.now }, Inspector: fixture.inspector, Runner: runner, Journal: journal,
			})
			if err != nil {
				t.Fatal(err)
			}
			_, err = verifier.Verify(context.Background(), fixture.request)
			if !errors.Is(err, Error(test.code)) {
				t.Fatalf("error = %v, want code %s", err, test.code)
			}
			if len(runner.executions) != 0 {
				t.Fatalf("runner called for rejected request: %#v", runner.executions)
			}
		})
	}
}

func TestExecutorResponseAndJournalDoNotLeakCommandOrRunnerError(t *testing.T) {
	fixture := newVerifierFixture(t)
	fixture.request.Action = ActionExecute
	fixture.request.ArtifactName = ""
	fixture.request.CommandID = "install-openclaw"
	resignRequest(t, &fixture)
	journalPath := filepath.Join(t.TempDir(), "execution.journal")
	journal, err := openExecutionJournal(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{run: func(context.Context, CommandExecution) error {
		return errors.New("failed with token super-secret at /private/path")
	}}
	verifier, err := NewVerifier(VerifierConfig{
		PublicKey: fixture.public, ExpectedBinding: fixture.binding,
		TargetRoot: PreinstalledArtifactRoot,
		Now:        func() time.Time { return fixture.now }, Inspector: fixture.inspector, Runner: runner, Journal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(verifier, ServerConfig{})
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
	journalBytes, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"super-secret", "/private/path", "printf '%s'", "secret_ref:"} {
		if bytes.Contains(responseBytes, []byte(secret)) || bytes.Contains(journalBytes, []byte(secret)) {
			t.Fatalf("response or journal leaked %q", secret)
		}
	}
	var response ResponseV1
	if err := DecodeCanonical(responseBytes, &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusFailed || response.ErrorCode != CodeExecutionFailed || response.CommandID != "install-openclaw" {
		t.Fatalf("unexpected execution failure response: %#v", response)
	}
}

func TestExecutorEnforcesSignedTimeoutAndDoesNotRetry(t *testing.T) {
	fixture := newVerifierFixture(t)
	fixture.request.Action = ActionExecute
	fixture.request.ArtifactName = ""
	fixture.request.CommandID = "install-openclaw"
	fixture.request.SignedPlan.Plan.Commands[0].TimeoutSeconds = 1
	resignRequest(t, &fixture)
	journal, err := openExecutionJournal(filepath.Join(t.TempDir(), "execution.journal"), false)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{run: func(ctx context.Context, _ CommandExecution) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	verifier, err := NewVerifier(VerifierConfig{
		PublicKey: fixture.public, ExpectedBinding: fixture.binding,
		TargetRoot: PreinstalledArtifactRoot,
		Now:        func() time.Time { return fixture.now }, Inspector: fixture.inspector, Runner: runner, Journal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := verifier.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusFailed || first.ErrorCode != CodeExecutionTimedOut || len(runner.executions) != 1 {
		t.Fatalf("signed timeout was not enforced: response=%#v calls=%d", first, len(runner.executions))
	}
	second, err := verifier.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Replayed || second.ErrorCode != CodeExecutionTimedOut || len(runner.executions) != 1 {
		t.Fatalf("timed-out command was retried: response=%#v calls=%d", second, len(runner.executions))
	}
}

func TestExecutorCannotRunBeyondSignedLeaseExpiry(t *testing.T) {
	fixture := newVerifierFixture(t)
	fixture.leaseExpiresAt = fixture.now.Add(25 * time.Millisecond)
	fixture.request.Action = ActionExecute
	fixture.request.ArtifactName = ""
	fixture.request.CommandID = "install-openclaw"
	resignRequest(t, &fixture)
	journal, err := openExecutionJournal(filepath.Join(t.TempDir(), "execution.journal"), false)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{run: func(ctx context.Context, _ CommandExecution) error {
		<-ctx.Done()
		return ctx.Err()
	}}
	verifier, err := NewVerifier(VerifierConfig{
		PublicKey: fixture.public, ExpectedBinding: fixture.binding,
		TargetRoot: PreinstalledArtifactRoot,
		Now:        func() time.Time { return fixture.now }, Inspector: fixture.inspector, Runner: runner, Journal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	response, err := verifier.Verify(context.Background(), fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if response.Status != StatusFailed || response.ErrorCode != CodeExecutionTimedOut || len(runner.executions) != 1 ||
		runner.executions[0].Timeout > 25*time.Millisecond || time.Since(started) > time.Second {
		t.Fatalf("signed lease did not stop execution: response=%#v execution=%#v elapsed=%s", response, runner.executions, time.Since(started))
	}
}

func TestServerRejectsRequestSuppliedArgvAndEnvironment(t *testing.T) {
	fixture := newVerifierFixture(t)
	fixture.request.Action = ActionExecute
	fixture.request.ArtifactName = ""
	fixture.request.CommandID = "install-openclaw"
	resignRequest(t, &fixture)
	malicious := map[string]any{
		"schema_version":  fixture.request.SchemaVersion,
		"request_id":      fixture.request.RequestID,
		"idempotency_key": fixture.request.IdempotencyKey,
		"action":          fixture.request.Action,
		"binding":         fixture.request.Binding,
		"signed_plan":     fixture.request.SignedPlan,
		"command_id":      fixture.request.CommandID,
		"argv":            []string{"aws", "ec2", "terminate-instances"},
		"environment":     []string{"AWS_SECRET_ACCESS_KEY=must-not-enter"},
	}
	raw, err := canonical.Marshal(malicious)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(fixture.verifier, ServerConfig{})
	var input, output bytes.Buffer
	writeTestFrame(&input, raw)
	if err := server.Handle(context.Background(), &input, &output); err != nil {
		t.Fatal(err)
	}
	responseBytes := readTestFrame(t, &output)
	if bytes.Contains(responseBytes, []byte("AWS_SECRET")) || bytes.Contains(responseBytes, []byte("terminate-instances")) {
		t.Fatalf("rejected response echoed runtime parameters: %x", responseBytes)
	}
	var response ResponseV1
	if err := DecodeCanonical(responseBytes, &response); err != nil {
		t.Fatal(err)
	}
	if response.ErrorCode != CodeInvalidRequest {
		t.Fatalf("unexpected response: %#v", response)
	}
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

func TestVerifyContractRemainsCanonicalWithoutExecuteFields(t *testing.T) {
	fixture := newVerifierFixture(t)
	fixture.request.SignedPlan.Plan.Commands = nil
	resignRequest(t, &fixture)
	raw, err := canonical.Marshal(fixture.request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("commands")) || bytes.Contains(raw, []byte("command_id")) {
		t.Fatalf("verify-only V1 unexpectedly contains execute fields: %x", raw)
	}
	var decoded RequestV1
	if err := DecodeCanonical(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.verifier.Verify(context.Background(), decoded); err != nil {
		t.Fatal(err)
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
		{name: "request binding mismatch", code: CodeBindingMismatch, edit: func(f *verifierFixture) { f.request.Binding.TaskID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa" }},
		{name: "signed plan binding mismatch", code: CodeBindingMismatch, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Binding.TaskID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
			resignRequest(t, f)
		}},
		{name: "bad signature", code: CodeInvalidSignature, edit: func(f *verifierFixture) { f.request.SignedPlan.Signature[0] ^= 0xff }},
		{name: "wrong signer", code: CodeInvalidSignature, edit: func(f *verifierFixture) { f.request.SignedPlan.SignerKeyID = "sha256:" + strings.Repeat("f", 64) }},
		{name: "undeclared artifact", code: CodeArtifactNotAllowed, edit: func(f *verifierFixture) { f.request.ArtifactName = "other" }},
		{name: "path traversal", code: CodeInvalidPath, edit: func(f *verifierFixture) {
			f.request.SignedPlan.Plan.Artifacts[0].TargetPath = PreinstalledArtifactRoot + "/../escape"
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
	if fixture.request.Action != ActionExecute {
		return
	}
	delivery := DeliveryV1{
		SchemaVersion: DeliverySchemaV1, PublicKey: fixture.public,
		Config:     DaemonConfigV1{SchemaVersion: DaemonConfigSchema, Binding: fixture.request.SignedPlan.Plan.Binding, TargetRoot: PreinstalledArtifactRoot},
		SignedPlan: fixture.request.SignedPlan,
	}
	delivery.TrustID, err = deliveryDigest(delivery)
	if err != nil {
		t.Fatal(err)
	}
	planDigest, err := canonical.Digest(fixture.request.SignedPlan.Plan)
	if err != nil {
		t.Fatal(err)
	}
	operationID := installerOperationID(delivery.TrustID, fixture.request.CommandID)
	grant := LeaseGrantV1{
		SchemaVersion: LeaseGrantSchemaV1, TrustID: delivery.TrustID, Binding: fixture.request.SignedPlan.Plan.Binding,
		PlanDigest: planDigest, OperationID: operationID, CommandID: fixture.request.CommandID, LeaseEpoch: fixture.leaseEpoch,
		IssuedAt: fixture.now.UTC().Format(time.RFC3339Nano), ExpiresAt: fixture.leaseExpiresAt.UTC().Format(time.RFC3339Nano),
	}
	grantPayload, err := LeaseGrantSigningBytes(grant)
	if err != nil {
		t.Fatal(err)
	}
	fixture.request.RequestID = installerRequestID(operationID)
	fixture.request.IdempotencyKey = installerIdempotencyKey(operationID)
	fixture.request.OperationID = operationID
	fixture.request.LeaseGrant = &SignedLeaseGrantV1{
		Grant: grant, SignerKeyID: fixture.request.SignedPlan.SignerKeyID, Signature: ed25519.Sign(fixture.private, grantPayload),
	}
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
