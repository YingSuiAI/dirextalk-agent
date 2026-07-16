package installer

import (
	"bytes"
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/canonical"
)

func TestTrustIssuerProducesDeterministicLeaseScopedDelivery(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	fixture, config := deliveryFixture(t, now)
	issuer, err := NewTrustIssuer(bytes.Repeat([]byte{0x31}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()

	first, err := issuer.Issue(fixture.plan, config, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := issuer.Issue(fixture.plan, config, now)
	if err != nil {
		t.Fatal(err)
	}
	firstBytes, _ := canonical.Marshal(first)
	secondBytes, _ := canonical.Marshal(second)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatal("exact publication retry changed installer trust delivery")
	}

	grant, err := issuer.IssueLeaseGrant(first, "install-openclaw", 7, now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	tamperedGrant := grant
	tamperedGrant.Signature = append([]byte(nil), grant.Signature...)
	tamperedGrant.Signature[0] ^= 0xff
	if err := ValidateLeaseGrantAt(first, tamperedGrant, "install-openclaw", now); !errors.Is(err, Error(CodeInvalidSignature)) {
		t.Fatalf("tampered lease grant error = %v", err)
	}
	if err := ValidateLeaseGrantAt(first, grant, "install-openclaw", now.Add(2*time.Minute)); !errors.Is(err, Error(CodeLeaseRejected)) {
		t.Fatalf("expired lease grant error = %v", err)
	}
	request, err := first.ExecuteRequest("install-openclaw", grant, now)
	if err != nil {
		t.Fatal(err)
	}
	replayedRequest, err := first.ExecuteRequest("install-openclaw", grant, now)
	if err != nil {
		t.Fatal(err)
	}
	if request.RequestID != replayedRequest.RequestID || request.IdempotencyKey != replayedRequest.IdempotencyKey ||
		request.Action != ActionExecute || request.CommandID != "install-openclaw" || request.ArtifactName != "" || request.Binding != config.Binding {
		t.Fatalf("execute selector is not deterministic and command-only: %#v", request)
	}

	material, err := first.RootTrustMaterial(now)
	if err != nil {
		t.Fatal(err)
	}
	var decodedConfig DaemonConfigV1
	if material.TrustID != first.TrustID || !bytes.Equal(material.PublicKey, first.PublicKey) ||
		DecodeCanonical(material.ConfigCBOR, &decodedConfig) != nil || decodedConfig != config {
		t.Fatalf("root trust material does not reproduce the signed delivery: %#v", material)
	}

	rotatedGrant, err := issuer.IssueLeaseGrant(first, "install-openclaw", 8, now.Add(2*time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	if rotatedGrant.Grant.OperationID != grant.Grant.OperationID || bytes.Equal(rotatedGrant.Signature, grant.Signature) ||
		rotatedGrant.Grant.LeaseEpoch == grant.Grant.LeaseEpoch {
		t.Fatal("new lease changed operation identity or reused the old grant")
	}
	changedPlan := fixture.plan
	changedPlan.Commands = append([]CommandV1(nil), fixture.plan.Commands...)
	changedPlan.Commands[0].Argv = append([]string(nil), fixture.plan.Commands[0].Argv...)
	changedPlan.Commands[0].Argv[len(changedPlan.Commands[0].Argv)-1] = "changed"
	changed, err := issuer.Issue(changedPlan, config, now)
	if err != nil {
		t.Fatal(err)
	}
	if changed.TrustID == first.TrustID || bytes.Equal(changed.PublicKey, first.PublicKey) {
		t.Fatal("changed signed command reused old installer trust")
	}
	unlockedPlan := fixture.plan
	unlockedPlan.Commands = append([]CommandV1(nil), fixture.plan.Commands...)
	unlockedPlan.Commands[0].Argv = []string{"/bin/sh", "-ceu", "exit 0"}
	if _, err := issuer.Issue(unlockedPlan, config, now); !errors.Is(err, Error(CodeCommandNotAllowed)) {
		t.Fatalf("non-digest-locked executable was accepted: %v", err)
	}
	shellPlan := fixture.plan
	shellPlan.Artifacts = append([]ArtifactV1(nil), fixture.plan.Artifacts...)
	shellPlan.Commands = append([]CommandV1(nil), fixture.plan.Commands...)
	shellPlan.Commands[0].Argv = []string{config.TargetRoot + "/bash", "-c", "exit 0"}
	shellPlan.Commands[0].ArtifactRefs = []string{"service-bundle"}
	shellPlan.Artifacts[0].TargetPath = config.TargetRoot + "/bash"
	if _, err := issuer.Issue(shellPlan, config, now); !errors.Is(err, Error(CodeCommandNotAllowed)) {
		t.Fatalf("digest-locked shell evaluator was accepted: %v", err)
	}
	stagedPlan := fixture.plan
	stagedPlan.Artifacts = append([]ArtifactV1(nil), fixture.plan.Artifacts...)
	stagedRoot := "/opt/dirextalk/deployments/" + fixture.binding.DeploymentID + "/artifacts"
	stagedPlan.Artifacts[0].TargetPath = stagedRoot + "/openclaw-installer"
	if _, err := issuer.Issue(stagedPlan, DaemonConfigV1{
		SchemaVersion: DaemonConfigSchema, Binding: fixture.binding, TargetRoot: stagedRoot,
	}, now); !errors.Is(err, Error(CodeInvalidPath)) {
		t.Fatalf("unstaged deployment artifact was executable: %v", err)
	}
}

func TestSocketClientExecutesSignedCommandOnceAcrossReplay(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	fixture, config := deliveryFixture(t, now)
	issuer, err := NewTrustIssuer(bytes.Repeat([]byte{0x52}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	delivery, err := issuer.Issue(fixture.plan, config, now)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := issuer.IssueLeaseGrant(delivery, "install-openclaw", 7, now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "execution.journal")
	journal, err := openExecutionJournal(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{}
	verifier, err := NewVerifier(VerifierConfig{
		PublicKey: delivery.PublicKey, ExpectedBinding: config.Binding, TargetRoot: config.TargetRoot,
		Now: time.Now, Inspector: fixture.inspector, Runner: runner, Journal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	client, err := newSocketClient(DefaultSocketPath, pipeDialer{server: NewServer(verifier, ServerConfig{})}, time.Now)
	if err != nil {
		t.Fatal(err)
	}

	first, err := client.Execute(context.Background(), delivery, grant, "install-openclaw")
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Execute(context.Background(), delivery, grant, "install-openclaw")
	if err != nil {
		t.Fatal(err)
	}
	if first.Status != StatusExecuted || first.Replayed || second.Status != StatusExecuted || !second.Replayed || len(runner.executions) != 1 {
		t.Fatalf("socket replay reran command: first=%#v second=%#v executions=%d", first, second, len(runner.executions))
	}
}

func TestRootVerifierRejectsOldTrustAndOldLease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	fixture, config := deliveryFixture(t, now)
	oldIssuer, _ := NewTrustIssuer(bytes.Repeat([]byte{0x61}, 32))
	newIssuer, _ := NewTrustIssuer(bytes.Repeat([]byte{0x62}, 32))
	defer oldIssuer.Close()
	defer newIssuer.Close()
	oldDelivery, err := oldIssuer.Issue(fixture.plan, config, now)
	if err != nil {
		t.Fatal(err)
	}
	newDelivery, err := newIssuer.Issue(fixture.plan, config, now)
	if err != nil {
		t.Fatal(err)
	}
	oldGrant, err := oldIssuer.IssueLeaseGrant(oldDelivery, "install-openclaw", 7, now.Add(time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	oldRequest, err := oldDelivery.ExecuteRequest("install-openclaw", oldGrant, now)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := NewVerifier(VerifierConfig{
		PublicKey: newDelivery.PublicKey, ExpectedBinding: config.Binding, TargetRoot: config.TargetRoot,
		Now: func() time.Time { return now }, Inspector: fixture.inspector,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.Verify(context.Background(), oldRequest); !errors.Is(err, Error(CodeInvalidSignature)) {
		t.Fatalf("old trust error = %v", err)
	}
	wrongRootTrust := oldDelivery.TrustID[:len(oldDelivery.TrustID)-1] + "0"
	if wrongRootTrust == oldDelivery.TrustID {
		wrongRootTrust = oldDelivery.TrustID[:len(oldDelivery.TrustID)-1] + "1"
	}
	trustVerifier, err := NewVerifier(VerifierConfig{
		PublicKey: oldDelivery.PublicKey, ExpectedTrustID: wrongRootTrust, ExpectedBinding: config.Binding, TargetRoot: config.TargetRoot,
		Now: func() time.Time { return now }, Inspector: fixture.inspector,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustVerifier.Verify(context.Background(), oldRequest); !errors.Is(err, Error(CodeLeaseRejected)) {
		t.Fatalf("mismatched root trust ID error = %v", err)
	}

	journalPath := filepath.Join(t.TempDir(), "execution.journal")
	journal, err := openExecutionJournal(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	runner := &fakeCommandRunner{}
	leaseVerifier, err := NewVerifier(VerifierConfig{
		PublicKey: oldDelivery.PublicKey, ExpectedBinding: config.Binding, TargetRoot: config.TargetRoot,
		Now: func() time.Time { return now }, Inspector: fixture.inspector, Runner: runner, Journal: journal,
	})
	if err != nil {
		t.Fatal(err)
	}
	first, err := leaseVerifier.Verify(context.Background(), oldRequest)
	if err != nil || first.Status != StatusExecuted {
		t.Fatalf("first lease execution = (%#v, %v)", first, err)
	}
	newGrant, err := oldIssuer.IssueLeaseGrant(oldDelivery, "install-openclaw", 8, now.Add(2*time.Minute), now)
	if err != nil {
		t.Fatal(err)
	}
	newRequest, err := oldDelivery.ExecuteRequest("install-openclaw", newGrant, now)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := leaseVerifier.Verify(context.Background(), newRequest)
	if err != nil || !replayed.Replayed || replayed.Status != StatusExecuted || len(runner.executions) != 1 {
		t.Fatalf("new lease reran completed operation: response=%#v error=%v calls=%d", replayed, err, len(runner.executions))
	}
	reopened, err := openExecutionJournal(journalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	restartedVerifier, err := NewVerifier(VerifierConfig{
		PublicKey: oldDelivery.PublicKey, ExpectedBinding: config.Binding, TargetRoot: config.TargetRoot,
		Now: func() time.Time { return now }, Inspector: fixture.inspector, Runner: &fakeCommandRunner{}, Journal: reopened,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restartedVerifier.Verify(context.Background(), oldRequest); !errors.Is(err, Error(CodeLeaseRejected)) {
		t.Fatalf("superseded lease error = %v", err)
	}
}

func TestServerExecutionConnectionDeadlineFollowsShortLease(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Millisecond)
	connection := &deadlineReader{}
	request := RequestV1{
		Action:     ActionExecute,
		SignedPlan: SignedInstallerPlanV1{Plan: InstallerPlanV1{ExpiresAt: now.Add(5 * time.Minute).Format(time.RFC3339Nano)}},
		LeaseGrant: &SignedLeaseGrantV1{Grant: LeaseGrantV1{ExpiresAt: now.Add(2 * time.Minute).Format(time.RFC3339Nano)}},
	}
	(&Server{}).extendExecutionDeadline(connection, request)
	want := now.Add(2*time.Minute + executionResponseGrace)
	if connection.deadline.Before(want.Add(-time.Second)) || connection.deadline.After(want.Add(time.Second)) ||
		connection.deadline.Before(now.Add(30*time.Second)) {
		t.Fatalf("execute connection retained verification-only deadline: got=%s want=%s", connection.deadline, want)
	}
}

func deliveryFixture(t *testing.T, now time.Time) (verifierFixture, DaemonConfigV1) {
	t.Helper()
	fixture := newVerifierFixture(t)
	fixture.now = now
	fixture.plan.Binding = fixture.binding
	fixture.plan.ExpiresAt = now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	fixture.plan.Artifacts[0].TargetPath = PreinstalledArtifactRoot + "/openclaw-installer"
	fixture.plan.Commands[0].Argv = []string{fixture.plan.Artifacts[0].TargetPath, "install"}
	fixture.plan.Commands[0].WorkingDirectory = PreinstalledArtifactRoot
	return fixture, DaemonConfigV1{
		SchemaVersion: DaemonConfigSchema, Binding: fixture.binding,
		TargetRoot: PreinstalledArtifactRoot,
	}
}

type pipeDialer struct{ server *Server }

func (dialer pipeDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if dialer.server == nil || network != "unix" || address != DefaultSocketPath {
		return nil, errors.New("unexpected installer socket dial")
	}
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		_ = dialer.server.Handle(ctx, server, server)
	}()
	return client, nil
}

type deadlineReader struct{ deadline time.Time }

func (*deadlineReader) Read([]byte) (int, error) { return 0, nil }

func (reader *deadlineReader) SetDeadline(value time.Time) error {
	reader.deadline = value
	return nil
}
