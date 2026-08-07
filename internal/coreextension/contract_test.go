package coreextension

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	coreconfirmation "github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	"github.com/google/uuid"
)

type rejectCoordinator struct{}

func (rejectCoordinator) RequestLifecycle(context.Context, LifecycleRequest) (MutationResult, error) {
	return MutationResult{}, errors.New("reject")
}

// MemoryRepository intentionally models durable mutations only; production
// service tests add the source-search surface required by Repository.
type serviceTestRepository struct{ *MemoryRepository }

func (serviceTestRepository) Search(context.Context, SearchQuery) (Page, error) {
	return Page{}, ErrNotFound
}

func testInspection(t *testing.T, kind Kind, source Source) (Candidate, Inspection) {
	t.Helper()
	d := strings.Repeat("a", 64)
	pin := SourcePin{RegistryVersion: "1.0.0", RegistrySHA256: d}
	if source == SourceGitHub {
		pin = SourcePin{GitCommit: strings.Repeat("b", 40), GitSHA256: d}
	}
	transport := TransportStdioStatic
	exec := ExecutionDescriptor{Stdio: &StaticEntry{RelativePath: "bin/run", Digest: d, Argv: []string{"run"}}}
	if kind == KindSkill {
		transport = TransportSkillStatic
		exec = ExecutionDescriptor{Skill: &SkillEntry{RelativePath: "scripts/main", Digest: d}}
	}
	c := Candidate{ID: "pkg", Kind: kind, Source: source, Name: "pkg", Pin: pin, Transport: transport}
	i := Inspection{Candidate: c, ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, NetworkSchemaDigest: d, SecretSchemaDigest: d, Execution: exec}
	return c, i
}

func TestSourceMatrixAndSecretRedaction(t *testing.T) {
	c, i := testInspection(t, KindMCP, SourceOfficialRegistry)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
	s := SecretInput{ReferenceID: uuid.NewString(), Purpose: SecretPurposeMCPCredential, Value: "top-secret"}
	if strings.Contains(s.String(), s.Value) || strings.Contains(s.GoString(), s.Value) {
		t.Fatal("secret leaked")
	}
}

func TestAllSourceMatrices(t *testing.T) {
	for _, source := range []Source{SourceOfficialRegistry, SourceSmithery, SourceGlama, SourceGitHub} {
		c, i := testInspection(t, KindMCP, source)
		if err := i.Validate(); err != nil {
			t.Fatalf("%s: %v", source, err)
		}
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	c, i := testInspection(t, KindSkill, SourceSkillsSh)
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestGitHubSkillSourceMatrix(t *testing.T) {
	c, i := testInspection(t, KindSkill, SourceGitHub)
	if c.Source != SourceGitHub || c.Kind != KindSkill || c.Transport != TransportSkillStatic {
		t.Fatal("github skill matrix lost")
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestRemoteRequiresExactGrantAndCredential(t *testing.T) {
	d := strings.Repeat("a", 64)
	ref := uuid.NewString()
	c := Candidate{ID: "remote", Kind: KindMCP, Source: SourceOfficialRegistry, Name: "remote", Pin: SourcePin{RegistryVersion: "1", RegistrySHA256: d}, Transport: TransportStreamableHTTP}
	e := ExecutionDescriptor{Remote: &RemoteEndpoint{URL: "https://example.com/mcp", CredentialReferenceID: ref}}
	i := Inspection{Candidate: c, ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, NetworkSchemaDigest: d, SecretSchemaDigest: d, Execution: e, NetworkGrants: []NetworkGrant{{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/mcp", Digest: d}}, SecretGrants: []SecretGrantDescriptor{{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, BindingDigest: d}}}
	if err := i.Validate(); err != nil {
		t.Fatal(err)
	}
	i.NetworkGrants[0].PathPrefix = "/other"
	if i.Validate() == nil {
		t.Fatal("grant drift accepted")
	}
}

func TestRemoteWithoutCredentialRequiresNoSecretGrant(t *testing.T) {
	d := strings.Repeat("a", 64)
	c := Candidate{ID: "public-remote", Kind: KindMCP, Source: SourceOfficialRegistry, Name: "public-remote", Pin: SourcePin{RegistryVersion: "1", RegistrySHA256: d}, Transport: TransportStreamableHTTP}
	i := Inspection{
		Candidate: c, ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, NetworkSchemaDigest: d, SecretSchemaDigest: d,
		Execution:     ExecutionDescriptor{Remote: &RemoteEndpoint{URL: "https://example.com/mcp"}},
		NetworkGrants: []NetworkGrant{{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/mcp", Digest: d}},
	}
	if err := i.Validate(); err != nil {
		t.Fatalf("no-auth inspection: %v", err)
	}
	raw, err := json.Marshal(i.Execution.Remote)
	if err != nil || !strings.Contains(string(raw), `"credential_reference_id":""`) {
		t.Fatalf("public remote projection must retain empty credential reference: %s err=%v", raw, err)
	}
	i.SecretGrants = []SecretGrantDescriptor{{ReferenceID: uuid.NewString(), Purpose: SecretPurposeMCPCredential, BindingDigest: d}}
	if i.Validate() == nil {
		t.Fatal("no-auth remote accepted an unrelated MCP credential grant")
	}
}

func TestMemoryRepositoryReplayAndImmutableVersions(t *testing.T) {
	now := time.Unix(10, 0).UTC()
	r := NewMemoryRepository(func() time.Time { return now })
	c, i := testInspection(t, KindMCP, SourceOfficialRegistry)
	m := Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i}
	a, err := r.CreateMutation(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	b, err := r.CreateMutation(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if a.Installation.ID != b.Installation.ID || a.TaskID != b.TaskID {
		t.Fatal("idempotent replay changed result")
	}
	b.Installation.Versions[0].ContentDigest = strings.Repeat("b", 64)
	got, err := r.Get(context.Background(), a.Installation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Versions[0].ContentDigest != i.ContentDigest {
		t.Fatal("repository version mutated through projection")
	}
}

func TestLifecycleAtomicFailureLeavesRepositoryEmpty(t *testing.T) {
	r := NewMemoryRepository()
	r.SetRequestFailpoint(func() error { return errors.New("failpoint") })
	c, i := testInspection(t, KindMCP, SourceOfficialRegistry)
	_, err := r.CreateMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i})
	if err == nil {
		t.Fatal("expected coordinator failure")
	}
	if _, err := r.List(context.Background(), ListQuery{}); !errors.Is(err, nil) {
		t.Fatal(err)
	}
	p, _ := r.List(context.Background(), ListQuery{})
	if len(p.Installations) != 0 {
		t.Fatal("failed proposal mutated repository")
	}
}

func installForLifecycle(t *testing.T, r *MemoryRepository, kind Kind, source Source) (MutationResult, Installation) {
	t.Helper()
	c, i := testInspection(t, kind, source)
	res, err := r.CreateMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(context.Background(), res.Installation.ID)
	if err != nil {
		t.Fatal(err)
	}
	return res, got
}

func completeInstall(t *testing.T, r *MemoryRepository, res MutationResult, success bool) Installation {
	t.Helper()
	rec, _ := r.GetLifecycleRecord(context.Background(), res.Installation.ID)
	if _, err := r.ConfirmLifecycle(context.Background(), coreconfirmation.ConfirmCommand{ConfirmationID: res.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, Binding: rec.Binding}); err != nil {
		t.Fatal(err)
	}
	r.SetTaskFence(coreconfirmation.TaskFence{TaskID: res.TaskID, State: "running", Attempt: 1, LeaseEpoch: 1, Revision: 2})
	if _, err := r.ConsumeLifecycle(context.Background(), coreconfirmation.ConsumeCommand{ConfirmationID: res.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: 2, ExpectedTaskRevision: 2, Binding: rec.Binding}); err != nil {
		t.Fatal(err)
	}
	r.SetTerminalTaskFence(res.TaskID, 1, 2, 3)
	out, err := r.CompleteLifecycle(context.Background(), Completion{InstallationID: res.Installation.ID, Operation: OperationInstall, ConfirmationID: res.ConfirmationID, TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 2, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("c", 64), Success: success})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestLifecycleRecordContainsBindingAndFences(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	rec, err := r.GetLifecycleRecord(context.Background(), res.Installation.ID)
	if err != nil || rec.TaskID != res.TaskID || rec.ConfirmationID != res.ConfirmationID || rec.Binding.ParameterDigest == "" || rec.RequestDigest == "" {
		t.Fatalf("record: %#v %v", rec, err)
	}
}
func TestLifecycleInstallSuccessActivatesProposal(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	out := completeInstall(t, r, res, true)
	if out.State != StateInstalled || !out.Enabled || out.ActiveVersionID == "" || out.ProposedVersionID != "" {
		t.Fatalf("outcome: %#v", out)
	}
}

func TestEnableDisableRevisionAndReplay(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	installed := completeInstall(t, r, res, true)
	disableKey := uuid.NewString()
	disabled, err := r.SetEnabled(context.Background(), ToggleCommand{IdempotencyKey: disableKey, InstallationID: installed.ID, ExpectedRevision: installed.Revision, Enabled: false})
	if err != nil || disabled.Enabled || disabled.Revision != installed.Revision+1 {
		t.Fatalf("disable: %#v %v", disabled, err)
	}
	replay, err := r.SetEnabled(context.Background(), ToggleCommand{IdempotencyKey: disableKey, InstallationID: installed.ID, ExpectedRevision: installed.Revision, Enabled: false})
	if err != nil || replay.Revision != disabled.Revision || replay.Enabled {
		t.Fatalf("disable replay: %#v %v", replay, err)
	}
	if _, err = r.SetEnabled(context.Background(), ToggleCommand{IdempotencyKey: uuid.NewString(), InstallationID: installed.ID, ExpectedRevision: installed.Revision, Enabled: true}); !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("expected stale revision, got %v", err)
	}
	enable, err := r.SetEnabled(context.Background(), ToggleCommand{IdempotencyKey: uuid.NewString(), InstallationID: installed.ID, ExpectedRevision: disabled.Revision, Enabled: true})
	if err != nil || !enable.Enabled || enable.Revision != disabled.Revision+1 {
		t.Fatalf("enable: %#v %v", enable, err)
	}
}
func TestLifecycleInstallFailureClearsProposal(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	out := completeInstall(t, r, res, false)
	if out.State != StateFailed || out.ProposedVersionID != "" {
		t.Fatalf("outcome: %#v", out)
	}
}
func TestLifecycleCompletionExactReplay(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	first := completeInstall(t, r, res, true)
	second, err := r.CompleteLifecycle(context.Background(), Completion{InstallationID: res.Installation.ID, Operation: OperationInstall, ConfirmationID: res.ConfirmationID, TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 2, TerminalAttempt: 1, TerminalLeaseEpoch: 2, TerminalTaskRevision: 3, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("c", 64), Success: true})
	if err != nil || second.State != first.State {
		t.Fatalf("replay: %#v %v", second, err)
	}
}
func TestLifecycleCompletionChangedReplayConflicts(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	_ = completeInstall(t, r, res, true)
	_, err := r.CompleteLifecycle(context.Background(), Completion{InstallationID: res.Installation.ID, Operation: OperationInstall, ConfirmationID: res.ConfirmationID, TaskID: res.TaskID, Attempt: 2, LeaseEpoch: 1, TerminalAttempt: 1, TerminalLeaseEpoch: 2, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("c", 64), Success: true})
	if err == nil {
		t.Fatalf("expected conflict: %v", err)
	}
}
func TestLifecycleStaleFenceRejected(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	r.SetTaskFence(coreconfirmation.TaskFence{TaskID: res.TaskID, State: "running", Attempt: 2, LeaseEpoch: 1, Revision: 1})
	_, err := r.CompleteLifecycle(context.Background(), Completion{InstallationID: res.Installation.ID, Operation: OperationInstall, ConfirmationID: res.ConfirmationID, TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, TerminalAttempt: 1, TerminalLeaseEpoch: 2, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("c", 64), Success: true})
	if err == nil {
		t.Fatalf("stale accepted: %v", err)
	}
}
func TestConcurrentUpdateCAS(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	_ = completeInstall(t, r, res, true)
	c, i := testInspection(t, KindMCP, SourceOfficialRegistry)
	i.Candidate = c
	var wg sync.WaitGroup
	var mu sync.Mutex
	n := 0
	for j := 0; j < 2; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := r.UpdateMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), InstallationID: res.Installation.ID, ExpectedRevision: 2, Candidate: c, Inspection: i}, StateUpdating)
			if e == nil {
				mu.Lock()
				n++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if n != 1 {
		t.Fatalf("cas successes=%d", n)
	}
}
func TestUninstallUsesActiveVersionAndClearsVersions(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	_ = completeInstall(t, r, res, true)
	cur, _ := r.Get(context.Background(), res.Installation.ID)
	u, err := r.RemoveMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), InstallationID: cur.ID, ExpectedRevision: cur.Revision})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := r.GetLifecycleRecord(context.Background(), u.Installation.ID)
	if _, err := r.ConfirmLifecycle(context.Background(), coreconfirmation.ConfirmCommand{ConfirmationID: u.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, Binding: rec.Binding}); err != nil {
		t.Fatal(err)
	}
	r.SetTaskFence(coreconfirmation.TaskFence{TaskID: u.TaskID, State: "running", Attempt: 1, LeaseEpoch: 1, Revision: 4})
	if _, err := r.ConsumeLifecycle(context.Background(), coreconfirmation.ConsumeCommand{ConfirmationID: u.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: u.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: 2, ExpectedTaskRevision: 4, Binding: rec.Binding}); err != nil {
		t.Fatal(err)
	}
	r.SetTerminalTaskFence(u.TaskID, 1, 2, 5)
	out, err := r.CompleteLifecycle(context.Background(), Completion{InstallationID: cur.ID, Operation: OperationUninstall, ConfirmationID: u.ConfirmationID, TaskID: u.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 4, TerminalAttempt: 1, TerminalLeaseEpoch: 2, TerminalTaskRevision: 5, ExpectedRevision: u.Installation.Revision, OutcomeDigest: strings.Repeat("d", 64), Success: true})
	if err != nil || out.State != StateRemoved || len(out.Versions) == 0 || out.ActiveVersionID != "" || out.ProposedVersionID != "" || len(out.SecretGrants) != 0 || len(out.NetworkGrants) != 0 {
		t.Fatalf("uninstall: %#v %v", out, err)
	}
}
func TestCandidateIdentityDescriptionMismatchRejected(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	_ = completeInstall(t, r, res, true)
	c, i := testInspection(t, KindMCP, SourceOfficialRegistry)
	c.Description = "changed"
	i.Candidate = c
	_, err := r.UpdateMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), InstallationID: res.Installation.ID, ExpectedRevision: 2, Candidate: c, Inspection: i}, StateUpdating)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("identity drift accepted: %v", err)
	}
}

func TestLifecycleReplayDoesNotInvokeFailpoint(t *testing.T) {
	r := NewMemoryRepository()
	c, i := testInspection(t, KindMCP, SourceOfficialRegistry)
	m := Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i}
	first, err := r.CreateMutation(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	r.SetRequestFailpoint(func() error { return errors.New("must not run on replay") })
	replay, err := r.CreateMutation(context.Background(), m)
	if err != nil || replay.TaskID != first.TaskID {
		t.Fatalf("replay callback: %#v %v", replay, err)
	}
}

func TestLifecycleRejectsEveryZeroFence(t *testing.T) {
	r := NewMemoryRepository()
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	rec, _ := r.GetLifecycleRecord(context.Background(), res.Installation.ID)
	if _, err := r.ConfirmLifecycle(context.Background(), coreconfirmation.ConfirmCommand{ConfirmationID: res.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, Binding: rec.Binding}); err != nil {
		t.Fatal(err)
	}
	r.SetTaskFence(coreconfirmation.TaskFence{TaskID: res.TaskID, State: "running", Attempt: 1, LeaseEpoch: 1, Revision: 2})
	if _, err := r.ConsumeLifecycle(context.Background(), coreconfirmation.ConsumeCommand{ConfirmationID: res.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: 2, ExpectedTaskRevision: 0, Binding: rec.Binding}); err == nil {
		t.Fatal("zero task revision accepted")
	}
	if _, err := r.CompleteLifecycle(context.Background(), Completion{InstallationID: res.Installation.ID, Operation: OperationInstall, ConfirmationID: res.ConfirmationID, TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: 1, OutcomeDigest: strings.Repeat("e", 64), Success: true}); err == nil {
		t.Fatal("zero completion fences accepted")
	}
}

func TestConsumeAfterExpiryFailsTaskWithoutReservation(t *testing.T) {
	now := time.Now().UTC()
	r := NewMemoryRepository(func() time.Time { return now })
	res, _ := installForLifecycle(t, r, KindMCP, SourceOfficialRegistry)
	rec, _ := r.GetLifecycleRecord(context.Background(), res.Installation.ID)
	if _, err := r.ConfirmLifecycle(context.Background(), coreconfirmation.ConfirmCommand{ConfirmationID: res.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, Binding: rec.Binding}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Hour)
	r.SetTaskFence(coreconfirmation.TaskFence{TaskID: res.TaskID, State: "running", Attempt: 1, LeaseEpoch: 1, Revision: 3})
	consume := coreconfirmation.ConsumeCommand{ConfirmationID: res.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: res.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: 2, ExpectedTaskRevision: 3, Binding: rec.Binding}
	expired, err := r.ConsumeLifecycle(context.Background(), consume)
	if !errors.Is(err, coreconfirmation.ErrExpired) || expired.State != coreconfirmation.StateExpired {
		t.Fatalf("expiry: %v", err)
	}
	replayed, err := r.ConsumeLifecycle(context.Background(), consume)
	if !errors.Is(err, coreconfirmation.ErrExpired) || replayed.State != coreconfirmation.StateExpired {
		t.Fatalf("expiry replay: %#v %v", replayed, err)
	}
	consume.Binding.TargetRevision++
	if _, err := r.ConsumeLifecycle(context.Background(), consume); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expiry changed replay: %v", err)
	}
	if _, ok := r.reservations[res.ConfirmationID]; ok {
		t.Fatal("expired confirmation reserved")
	}
	task, _ := r.GetTask(res.TaskID)
	if task.State != "failed" || task.FailureCode != coreconfirmation.ReasonExpired {
		t.Fatalf("task: %#v", task)
	}
}

func TestCrossKindAndDuplicateSecretGrantsRejected(t *testing.T) {
	d := strings.Repeat("a", 64)
	ref := uuid.NewString()
	c, i := testInspection(t, KindSkill, SourceGitHub)
	i.SecretGrants = []SecretGrantDescriptor{{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, BindingDigest: d, Configured: true}}
	i.Candidate = c
	r := NewMemoryRepository()
	if _, err := r.CreateMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i, SecretInputs: []SecretInput{{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, Value: "x"}}}); err == nil {
		t.Fatal("cross-kind secret accepted")
	}
	i.SecretGrants = []SecretGrantDescriptor{{ReferenceID: ref, Purpose: SecretPurposeSkillSecret, BindingDigest: d, Configured: true}, {ReferenceID: ref, Purpose: SecretPurposeSkillSecret, BindingDigest: d, Configured: true}}
	if _, err := r.CreateMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i, SecretInputs: []SecretInput{{ReferenceID: ref, Purpose: SecretPurposeSkillSecret, Value: "x"}}}); err == nil {
		t.Fatal("duplicate grant accepted")
	}
}

func TestUninstallClearsActiveGrantsButRetainsVersionGrantHistory(t *testing.T) {
	ref := uuid.NewString()
	c, i := testInspection(t, KindMCP, SourceOfficialRegistry)
	secret := "history-secret"
	i.SecretGrants = []SecretGrantDescriptor{{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, BindingDigest: SecretInput{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, Value: secret}.Fingerprint(), Configured: true}}
	r := NewMemoryRepository()
	res, err := r.CreateMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i, SecretInputs: []SecretInput{{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, Value: secret}}})
	if err != nil {
		t.Fatal(err)
	}
	installed := completeInstall(t, r, res, true)
	cur, _ := r.Get(context.Background(), installed.ID)
	u, err := r.RemoveMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), InstallationID: cur.ID, ExpectedRevision: cur.Revision})
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := r.GetLifecycleRecord(context.Background(), u.Installation.ID)
	if _, err = r.ConfirmLifecycle(context.Background(), coreconfirmation.ConfirmCommand{ConfirmationID: u.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, Binding: rec.Binding}); err != nil {
		t.Fatal(err)
	}
	r.SetTaskFence(coreconfirmation.TaskFence{TaskID: u.TaskID, State: "running", Attempt: 1, LeaseEpoch: 1, Revision: 4})
	if _, err = r.ConsumeLifecycle(context.Background(), coreconfirmation.ConsumeCommand{ConfirmationID: u.ConfirmationID, IdempotencyKey: uuid.NewString(), TaskID: u.TaskID, Attempt: 1, LeaseEpoch: 1, ExpectedRevision: 2, ExpectedTaskRevision: 4, Binding: rec.Binding}); err != nil {
		t.Fatal(err)
	}
	r.SetTerminalTaskFence(u.TaskID, 1, 2, 5)
	out, err := r.CompleteLifecycle(context.Background(), Completion{InstallationID: u.Installation.ID, Operation: OperationUninstall, ConfirmationID: u.ConfirmationID, TaskID: u.TaskID, Attempt: 1, LeaseEpoch: 1, AcquiredTaskRevision: 4, TerminalAttempt: 1, TerminalLeaseEpoch: 2, TerminalTaskRevision: 5, ExpectedRevision: u.Installation.Revision, OutcomeDigest: strings.Repeat("f", 64), Success: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.SecretGrants) != 0 || len(out.Versions) == 0 || len(out.Versions[0].SecretGrants) == 0 {
		t.Fatalf("history grants lost: %#v", out)
	}
}

type testAdapter struct {
	inspection Inspection
	artifact   FetchArtifact
}

func (a testAdapter) Search(context.Context, SearchQuery) (Page, error) { return Page{}, nil }
func (a testAdapter) Inspect(context.Context, InspectRequest) (Inspection, error) {
	return a.inspection, nil
}
func (a testAdapter) Fetch(context.Context, Candidate) (FetchArtifact, error) { return a.artifact, nil }

type testArtifacts struct{ removed int }

func (s *testArtifacts) Materialize(context.Context, FetchArtifact) (ArtifactReceipt, error) {
	digest := digestBytes([]byte("artifact"))
	return ArtifactReceipt{RelativePath: "artifacts/x", ContentDigest: digest, ArtifactDigest: digest, CleanupToken: uuid.NewString()}, nil
}
func (s *testArtifacts) Remove(context.Context, ArtifactReceipt) error { s.removed++; return nil }

type countedAdapter struct {
	inspection Inspection
	artifact   FetchArtifact
	fetches    int
}

func (a *countedAdapter) Search(context.Context, SearchQuery) (Page, error) { return Page{}, nil }
func (a *countedAdapter) Inspect(context.Context, InspectRequest) (Inspection, error) {
	return a.inspection, nil
}
func (a *countedAdapter) Fetch(context.Context, Candidate) (FetchArtifact, error) {
	a.fetches++
	return a.artifact, nil
}

type countedArtifacts struct {
	receipt      ArtifactReceipt
	materialized int
}

func (s *countedArtifacts) Materialize(context.Context, FetchArtifact) (ArtifactReceipt, error) {
	s.materialized++
	return s.receipt, nil
}
func (s *countedArtifacts) Remove(context.Context, ArtifactReceipt) error { return nil }

type countedSecrets struct{ binds int }

func (s *countedSecrets) Bind(_ context.Context, in []SecretInput) ([]SecretReceipt, error) {
	s.binds++
	out := make([]SecretReceipt, 0, len(in))
	for _, input := range in {
		out = append(out, SecretReceipt{ReferenceID: input.ReferenceID, Purpose: input.Purpose, Fingerprint: input.Fingerprint()})
	}
	return out, nil
}

func TestServerSideInspectFetchAndArtifactReceipt(t *testing.T) {
	d := digestBytes([]byte("artifact"))
	c := Candidate{ID: "pkg", Kind: KindMCP, Source: SourceOfficialRegistry, Name: "pkg", Pin: SourcePin{RegistryVersion: "1", RegistrySHA256: d}, Transport: TransportStdioStatic}
	ins := Inspection{Candidate: c, ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, NetworkSchemaDigest: d, SecretSchemaDigest: d, Execution: ExecutionDescriptor{Stdio: &StaticEntry{RelativePath: "bin/run", Digest: d, Argv: []string{"run"}}}}
	a := testAdapter{inspection: ins, artifact: FetchArtifact{Candidate: c, Content: []byte("artifact"), ContentDigest: d, Inspection: ins}}
	reg := NewRegistry()
	if err := reg.Register(SourceOfficialRegistry, a); err != nil {
		t.Fatal(err)
	}
	r := NewMemoryRepository()
	svc := NewServiceWithStores(serviceTestRepository{r}, reg, nil, &testArtifacts{}, NewFingerprintSecretStore())
	res, err := svc.RequestInstall(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: ins})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := r.Get(context.Background(), res.Installation.ID)
	if got.Versions[0].ArtifactPath != "artifacts/x" || got.Versions[0].ArtifactDigest != d {
		t.Fatalf("artifact receipt: %#v", got.Versions[0])
	}
}

func TestServerSideInstallPublicRemoteWithoutSecret(t *testing.T) {
	d := digestBytes([]byte("artifact"))
	c := Candidate{ID: "public-remote", Kind: KindMCP, Source: SourceOfficialRegistry, Name: "public-remote", Pin: SourcePin{RegistryVersion: "1", RegistrySHA256: d}, Transport: TransportStreamableHTTP}
	ins := Inspection{
		Candidate: c, ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, NetworkSchemaDigest: d, SecretSchemaDigest: d,
		Execution:     ExecutionDescriptor{Remote: &RemoteEndpoint{URL: "https://example.com/mcp"}},
		NetworkGrants: []NetworkGrant{{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/mcp", Digest: d}},
	}
	a := testAdapter{inspection: ins, artifact: FetchArtifact{Candidate: c, Content: []byte("artifact"), ContentDigest: d, Inspection: ins}}
	reg := NewRegistry()
	if err := reg.Register(SourceOfficialRegistry, a); err != nil {
		t.Fatal(err)
	}
	r := NewMemoryRepository()
	svc := NewServiceWithStores(serviceTestRepository{r}, reg, nil, &testArtifacts{}, NewFingerprintSecretStore())
	res, err := svc.RequestInstall(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: ins})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(context.Background(), res.Installation.ID)
	if err != nil || len(got.Versions) != 1 || len(got.Versions[0].SecretGrants) != 0 || got.Versions[0].Execution.Remote == nil || got.Versions[0].Execution.Remote.CredentialReferenceID != "" {
		t.Fatalf("public remote installation=%#v err=%v", got, err)
	}
}

func TestPrepareMutationFencesReviewedInspectionBeforeSideEffects(t *testing.T) {
	d := digestBytes([]byte("artifact"))
	ref := uuid.NewString()
	ref2 := uuid.NewString()
	secret := SecretInput{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, Value: "reviewed-secret"}
	secret2 := SecretInput{ReferenceID: ref2, Purpose: SecretPurposeMCPCredential, Value: "reviewed-secret-two"}
	c := Candidate{ID: "remote", Kind: KindMCP, Source: SourceOfficialRegistry, Name: "remote", Pin: SourcePin{RegistryVersion: "1", RegistrySHA256: d}, Transport: TransportStreamableHTTP}
	ins := Inspection{
		Candidate: c, ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, NetworkSchemaDigest: d, SecretSchemaDigest: d,
		Execution:     ExecutionDescriptor{Remote: &RemoteEndpoint{URL: "https://example.com/mcp", CredentialReferenceID: ref}},
		NetworkGrants: []NetworkGrant{{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/mcp", Digest: d}, {Scheme: "https", Host: "backup.example.com", Port: 443, PathPrefix: "/", Digest: d}},
		// This is the real source shape: source-owned schema binding, unconfigured.
		SecretGrants: []SecretGrantDescriptor{{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, BindingDigest: d, Configured: false}, {ReferenceID: ref2, Purpose: SecretPurposeMCPCredential, BindingDigest: d, Configured: false}},
	}
	if err := ins.Validate(); err != nil {
		t.Fatal(err)
	}
	mutation := func() Mutation {
		return Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: ins, SecretInputs: []SecretInput{secret, secret2}}
	}
	newRepo := func(fresh, fetched Inspection) (Service, *MemoryRepository, *countedAdapter, *countedArtifacts, *countedSecrets) {
		a := &countedAdapter{inspection: fresh, artifact: FetchArtifact{Candidate: fetched.Candidate, Content: []byte("artifact"), ContentDigest: d, Inspection: fetched}}
		reg := NewRegistry()
		if err := reg.Register(SourceOfficialRegistry, a); err != nil {
			t.Fatal(err)
		}
		artifacts := &countedArtifacts{receipt: ArtifactReceipt{RelativePath: "artifacts/x", ContentDigest: d, ArtifactDigest: d, CleanupToken: uuid.NewString()}}
		secrets := &countedSecrets{}
		r := NewMemoryRepository()
		return NewServiceWithStores(serviceTestRepository{r}, reg, nil, artifacts, secrets), r, a, artifacts, secrets
	}
	mutations := map[string]func(*Inspection){
		"candidate": func(i *Inspection) { i.Candidate.Name = "other" },
		"pin":       func(i *Inspection) { i.Candidate.Pin.RegistryVersion = "2" },
		"transport": func(i *Inspection) {
			i.Candidate.Transport = TransportStdioStatic
			i.Execution = ExecutionDescriptor{Stdio: &StaticEntry{RelativePath: "bin/run", Digest: d, Argv: []string{"run"}}}
			i.NetworkGrants = nil
			i.SecretGrants = nil
		},
		"content digest":   func(i *Inspection) { i.ContentDigest = strings.Repeat("b", 64) },
		"manifest digest":  func(i *Inspection) { i.ManifestDigest = strings.Repeat("b", 64) },
		"execution digest": func(i *Inspection) { i.ExecutionDigest = strings.Repeat("b", 64) },
		"network digest":   func(i *Inspection) { i.NetworkSchemaDigest = strings.Repeat("b", 64) },
		"secret digest":    func(i *Inspection) { i.SecretSchemaDigest = strings.Repeat("b", 64) },
		"execution descriptor": func(i *Inspection) {
			i.Execution.Remote.URL = "https://example.com/other"
			i.NetworkGrants[0].PathPrefix = "/other"
		},
		"network grants":     func(i *Inspection) { i.NetworkGrants[0].Digest = strings.Repeat("b", 64) },
		"secret descriptors": func(i *Inspection) { i.SecretGrants[0].BindingDigest = strings.Repeat("b", 64) },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			fresh := ins
			fresh.NetworkGrants = append([]NetworkGrant(nil), ins.NetworkGrants...)
			fresh.SecretGrants = append([]SecretGrantDescriptor(nil), ins.SecretGrants...)
			remote := *ins.Execution.Remote
			fresh.Execution.Remote = &remote
			mutate(&fresh)
			svc, r, adapter, artifacts, secrets := newRepo(fresh, fresh)
			if _, err := svc.RequestInstall(context.Background(), mutation()); !errors.Is(err, ErrConflict) {
				t.Fatalf("drift accepted: %v", err)
			}
			if adapter.fetches != 0 || artifacts.materialized != 0 || secrets.binds != 0 || len(r.items) != 0 {
				t.Fatalf("drift caused side effects: fetch=%d materialize=%d bind=%d items=%d", adapter.fetches, artifacts.materialized, secrets.binds, len(r.items))
			}
		})
	}

	t.Run("exact reviewed inspection succeeds", func(t *testing.T) {
		svc, r, adapter, artifacts, secrets := newRepo(ins, ins)
		res, err := svc.RequestInstall(context.Background(), mutation())
		if err != nil {
			t.Fatal(err)
		}
		if adapter.fetches != 1 || artifacts.materialized != 1 || secrets.binds != 1 || len(r.items) != 1 {
			t.Fatalf("exact inspection did not complete: fetch=%d materialize=%d bind=%d items=%d", adapter.fetches, artifacts.materialized, secrets.binds, len(r.items))
		}
		got, err := r.Get(context.Background(), res.Installation.ID)
		if err != nil || len(got.Versions) != 1 || len(got.Versions[0].SecretGrants) != 2 {
			t.Fatalf("bound installation missing: %#v %v", got, err)
		}
		grant := got.Versions[0].SecretGrants[0]
		if !grant.Configured || grant.BindingDigest != secret.Fingerprint() || strings.Contains(got.String(), secret.Value) {
			t.Fatalf("server binding/redaction lost: %#v", grant)
		}
	})

	t.Run("invalid supplied inspection", func(t *testing.T) {
		svc, r, adapter, artifacts, secrets := newRepo(ins, ins)
		m := mutation()
		m.Inspection = Inspection{}
		if _, err := svc.RequestInstall(context.Background(), m); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid inspection accepted: %v", err)
		}
		if adapter.fetches != 0 || artifacts.materialized != 0 || secrets.binds != 0 || len(r.items) != 0 {
			t.Fatalf("invalid inspection caused side effects")
		}
	})

	t.Run("supplied candidate differs from inspection", func(t *testing.T) {
		svc, r, adapter, artifacts, secrets := newRepo(ins, ins)
		m := mutation()
		m.Inspection.Candidate.Name = "other"
		if _, err := svc.RequestInstall(context.Background(), m); !errors.Is(err, ErrInvalid) {
			t.Fatalf("candidate mismatch accepted: %v", err)
		}
		if adapter.fetches != 0 || artifacts.materialized != 0 || secrets.binds != 0 || len(r.items) != 0 {
			t.Fatalf("candidate mismatch caused side effects")
		}
	})

	fetchMutations := map[string]func(*Inspection){
		"candidate":        func(i *Inspection) { i.Candidate.Name = "other" },
		"content digest":   func(i *Inspection) { i.ContentDigest = strings.Repeat("b", 64) },
		"manifest digest":  func(i *Inspection) { i.ManifestDigest = strings.Repeat("b", 64) },
		"execution digest": func(i *Inspection) { i.ExecutionDigest = strings.Repeat("b", 64) },
		"network digest":   func(i *Inspection) { i.NetworkSchemaDigest = strings.Repeat("b", 64) },
		"secret digest":    func(i *Inspection) { i.SecretSchemaDigest = strings.Repeat("b", 64) },
		"execution": func(i *Inspection) {
			i.Execution.Remote.URL = "https://example.com/other"
			i.NetworkGrants[0].PathPrefix = "/other"
		},
		"network grants": func(i *Inspection) {
			i.NetworkGrants = append([]NetworkGrant{{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/mcp", Digest: d}}, i.NetworkGrants...)
		},
		"secret grants": func(i *Inspection) {
			i.SecretGrants = append([]SecretGrantDescriptor{{ReferenceID: uuid.NewString(), Purpose: SecretPurposeMCPCredential, BindingDigest: d}}, i.SecretGrants...)
		},
	}
	for name, mutate := range fetchMutations {
		t.Run("fetch drift "+name, func(t *testing.T) {
			fetched := ins
			fetched.NetworkGrants = append([]NetworkGrant(nil), ins.NetworkGrants...)
			fetched.SecretGrants = append([]SecretGrantDescriptor(nil), ins.SecretGrants...)
			remote := *ins.Execution.Remote
			fetched.Execution.Remote = &remote
			mutate(&fetched)
			svc, r, adapter, artifacts, secrets := newRepo(ins, fetched)
			if _, err := svc.RequestInstall(context.Background(), mutation()); !errors.Is(err, ErrConflict) {
				t.Fatalf("fetch drift accepted: %v", err)
			}
			if adapter.fetches != 1 || artifacts.materialized != 0 || secrets.binds != 0 || len(r.items) != 0 {
				t.Fatalf("fetch drift side effects: fetch=%d materialize=%d bind=%d items=%d", adapter.fetches, artifacts.materialized, secrets.binds, len(r.items))
			}
		})
	}
	for _, field := range []string{"network", "secret"} {
		t.Run("fresh order drift "+field, func(t *testing.T) {
			fresh := ins
			fresh.NetworkGrants = append([]NetworkGrant(nil), ins.NetworkGrants...)
			fresh.SecretGrants = append([]SecretGrantDescriptor(nil), ins.SecretGrants...)
			if field == "network" {
				fresh.NetworkGrants[0], fresh.NetworkGrants[1] = fresh.NetworkGrants[1], fresh.NetworkGrants[0]
			} else {
				fresh.SecretGrants[0], fresh.SecretGrants[1] = fresh.SecretGrants[1], fresh.SecretGrants[0]
			}
			svc, r, adapter, artifacts, secrets := newRepo(fresh, fresh)
			if _, err := svc.RequestInstall(context.Background(), mutation()); !errors.Is(err, ErrConflict) {
				t.Fatalf("order accepted: %v", err)
			}
			if adapter.fetches != 0 || artifacts.materialized != 0 || secrets.binds != 0 || len(r.items) != 0 {
				t.Fatal("order drift side effects")
			}
		})
	}

	t.Run("invalid fetched artifact is conflict without side effects", func(t *testing.T) {
		bad := ins
		bad.Candidate.ID = "other"
		svc, r, adapter, artifacts, secrets := newRepo(ins, bad)
		adapter.artifact.Candidate = c // FetchArtifact.Validate must reject this mismatch.
		if _, err := svc.RequestInstall(context.Background(), mutation()); !errors.Is(err, ErrConflict) {
			t.Fatalf("invalid fetched artifact accepted: %v", err)
		}
		if adapter.fetches != 1 || artifacts.materialized != 0 || secrets.binds != 0 || len(r.items) != 0 {
			t.Fatalf("invalid fetch side effects: fetch=%d materialize=%d bind=%d items=%d", adapter.fetches, artifacts.materialized, secrets.binds, len(r.items))
		}
	})
}
func TestRemoteSecretFingerprintMismatchRejected(t *testing.T) {
	d := strings.Repeat("a", 64)
	ref := uuid.NewString()
	c := Candidate{ID: "remote", Kind: KindMCP, Source: SourceOfficialRegistry, Name: "remote", Pin: SourcePin{RegistryVersion: "1", RegistrySHA256: d}, Transport: TransportStreamableHTTP}
	i := Inspection{Candidate: c, ContentDigest: d, ManifestDigest: d, ExecutionDigest: d, NetworkSchemaDigest: d, SecretSchemaDigest: d, Execution: ExecutionDescriptor{Remote: &RemoteEndpoint{URL: "https://example.com/mcp", CredentialReferenceID: ref}}, NetworkGrants: []NetworkGrant{{Scheme: "https", Host: "example.com", Port: 443, PathPrefix: "/mcp", Digest: d}}, SecretGrants: []SecretGrantDescriptor{{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, BindingDigest: d, Configured: true}}}
	r := NewMemoryRepository()
	_, err := r.CreateMutation(context.Background(), Mutation{IdempotencyKey: uuid.NewString(), Candidate: c, Inspection: i, SecretInputs: []SecretInput{{ReferenceID: ref, Purpose: SecretPurposeMCPCredential, Value: "different"}}})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("secret drift accepted: %v", err)
	}
}
