package cloudapp

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsfoundation"
	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	cloudapproval "github.com/YingSuiAI/dirextalk-agent/internal/cloud/approval"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
)

type connectionIdentities struct{ evidence AWSIdentityEvidence }

func (*connectionIdentities) PutAWSIdentityEvidence(context.Context, AWSIdentityEvidence) error {
	return nil
}
func (repository *connectionIdentities) GetAWSIdentityEvidence(context.Context, string, uint64) (AWSIdentityEvidence, error) {
	return repository.evidence, nil
}

type connectionSecrets struct {
	session      secretbootstrap.SessionV1
	getErr       error
	inspectErr   error
	inspectCalls int
	callerClient string
}

func (secrets *connectionSecrets) Get(_ context.Context, callerClient, _ string) (secretbootstrap.SessionV1, error) {
	secrets.callerClient = callerClient
	return secrets.session, secrets.getErr
}
func (secrets *connectionSecrets) Inspect(_ context.Context, callerClient, _ string, _ uint64, consumer secretbootstrap.SecretConsumer) (secretbootstrap.SessionV1, error) {
	secrets.callerClient = callerClient
	secrets.inspectCalls++
	if secrets.inspectErr != nil {
		return secretbootstrap.SessionV1{}, secrets.inspectErr
	}
	return secrets.session, consumer([]byte("synthetic encrypted bootstrap plaintext"))
}

type connectionFoundation struct {
	result  awsfoundation.EstablishResult
	err     error
	calls   int
	request awsfoundation.EstablishRequest
}

func (foundation *connectionFoundation) Establish(_ context.Context, payload []byte, request awsfoundation.EstablishRequest) (awsfoundation.EstablishResult, error) {
	foundation.calls++
	foundation.request = request
	clear(payload)
	return foundation.result, foundation.err
}

type connectionOperations struct {
	intent          FoundationOperationIntent
	connection      Connection
	finalizeCalls   int
	finalizedSecret string
	finalizedRev    uint64
	replay          bool
	recoverable     []FoundationOperation
	failBlocked     bool
	failReason      string
}

func (operations *connectionOperations) BeginFoundationOperation(_ context.Context, _ MutationScope, intent FoundationOperationIntent) (FoundationOperation, bool, error) {
	operations.intent = intent
	if operations.replay {
		value := operations.connection
		return FoundationOperation{FoundationOperationIntent: intent, Status: FoundationOperationSucceeded, Connection: &value, Revision: 3}, false, nil
	}
	return FoundationOperation{FoundationOperationIntent: intent, Status: FoundationOperationIntentStatus, Revision: 1}, true, nil
}
func (operations *connectionOperations) ListRecoverableFoundationOperations(context.Context, int) ([]FoundationOperation, error) {
	return append([]FoundationOperation(nil), operations.recoverable...), nil
}
func (operations *connectionOperations) MarkFoundationOperationRunning(_ context.Context, id string, revision int64) (FoundationOperation, error) {
	intent := operations.intent
	intent.OperationID = id
	return FoundationOperation{FoundationOperationIntent: intent, Status: FoundationOperationRunning, Revision: revision + 1}, nil
}
func (operations *connectionOperations) FinalizeFoundationOperation(_ context.Context, _ string, _ int64, sessionID string, sessionRevision uint64, value Connection) (FoundationOperation, error) {
	operations.finalizeCalls++
	operations.finalizedSecret, operations.finalizedRev, operations.connection = sessionID, sessionRevision, value
	return FoundationOperation{Status: FoundationOperationSucceeded, Connection: &value, Revision: 3}, nil
}
func (operations *connectionOperations) FailFoundationOperation(_ context.Context, id string, revision int64, blocked bool, reason string) (FoundationOperation, error) {
	operations.failBlocked, operations.failReason = blocked, reason
	intent := operations.intent
	intent.OperationID = id
	status := FoundationOperationFailedRetriable
	if blocked {
		status = FoundationOperationDestroyBlocked
	}
	return FoundationOperation{FoundationOperationIntent: intent, Status: status, Revision: revision + 1, RedactedError: reason}, nil
}

func TestAWSConnectionPersistsIntentAndAtomicallyFinalizesBootstrapSecret(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	ready := coordinatorPlan(now)
	unsigned, err := cloudapproval.NewApprovalV1(
		ready, "019b2d57-b3c0-7e65-a1d2-10c43de26718", "challenge_"+strings.Repeat("c", 43), "device-key-1", now.Add(5*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	unsigned.Signature = base64.RawURLEncoding.EncodeToString(signature)
	approved := ready
	approved.Status, approved.Revision = cloudapproval.PlanApproved, ready.Revision+1
	facts := &coordinatorFacts{plan: approved, approval: unsigned}
	sessionID := "019b2d57-b3c0-7e65-a1d2-10c43de26719"
	session := secretbootstrap.SessionV1{
		SessionID: sessionID, AgentInstanceID: testAgentID, OwnerID: ready.OwnerID,
		Purpose: "aws_connection", TargetID: ready.ConnectionID, Status: secretbootstrap.StatusUploaded,
		Revision: 2, CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(9 * time.Minute),
	}
	identities := &connectionIdentities{evidence: AWSIdentityEvidence{
		BootstrapSessionID: sessionID, SessionRevision: 2, AgentInstanceID: testAgentID,
		OwnerID: ready.OwnerID, TargetID: ready.ConnectionID,
		Identity:   AWSIdentity{AccountID: "123456789012", PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012", Region: "us-east-1", RootIdentity: true},
		ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
	}}
	operations := &connectionOperations{}
	foundation := &connectionFoundation{result: awsfoundation.EstablishResult{
		Identity:                   awsprovider.CallerIdentity{Partition: "aws", AccountID: "123456789012", ARN: "arn:aws:iam::123456789012:root", UserID: "123456789012", Region: "us-east-1"},
		SourceCredentialGeneration: 1,
		Stack:                      awsprovider.FoundationStackReceipt{StackID: "arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-agent-foundation/id", Status: awsprovider.FoundationStackReadyStatus, ObservedAt: now},
	}}
	secrets := &connectionSecrets{session: session}
	currentTime := now
	service, err := NewAWSConnectionService(
		testAgentID, "registry.example/reaper:v0.1@sha256:"+strings.Repeat("d", 64), facts,
		identities, operations, secrets, foundation, func() time.Time { return currentTime },
	)
	if err != nil {
		t.Fatal(err)
	}
	command := EstablishConnectionCommand{
		IdempotencyKey: "019b2d57-b3c0-7e65-a1d2-10c43de26720", OwnerID: ready.OwnerID,
		BootstrapSessionID: sessionID, ExpectedSessionRevision: 2,
		PlanID: approved.PlanID, ExpectedPlanRevision: approved.Revision,
		Approval: ApprovalSignature{
			ApprovalID: unsigned.ApprovalID, ChallengeID: unsigned.ChallengeID, SignerKeyID: unsigned.SignerKeyID,
			ExpiresAt: unsigned.ExpiresAt, Signature: signature,
		},
	}
	connection, err := service.EstablishAWSConnection(context.Background(), MutationScope{ClientID: "message-server", CredentialID: testCredentialID}, command)
	if err != nil {
		t.Fatal(err)
	}
	if connection.Status != "active" || foundation.calls != 1 || secrets.inspectCalls != 1 || secrets.callerClient != "message-server" || operations.finalizeCalls != 1 {
		t.Fatalf("connection=%#v foundation=%d inspect=%d finalize=%d", connection, foundation.calls, secrets.inspectCalls, operations.finalizeCalls)
	}
	if operations.finalizedSecret != sessionID || operations.finalizedRev != 2 || operations.intent.RequestHash == ([32]byte{}) {
		t.Fatalf("atomic finalization did not bind session/revision/intent: %#v", operations)
	}
	operations.replay = true
	secrets.session.Status, secrets.session.Revision = secretbootstrap.StatusConsumed, 3
	currentTime = now.Add(30 * time.Minute)
	replayed, err := service.EstablishAWSConnection(context.Background(), MutationScope{ClientID: "message-server", CredentialID: testCredentialID}, command)
	if err != nil || replayed.ConnectionID != connection.ConnectionID {
		t.Fatalf("terminal idempotency replay connection=%#v err=%v", replayed, err)
	}
	if foundation.calls != 1 || secrets.inspectCalls != 1 || operations.finalizeCalls != 1 {
		t.Fatalf("terminal replay repeated side effects: foundation=%d inspect=%d finalize=%d", foundation.calls, secrets.inspectCalls, operations.finalizeCalls)
	}
}

func TestAWSConnectionRecoveryUsesDurableCallerSessionAndIdentityBinding(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	sessionID := "019b2d57-b3c0-7e65-a1d2-10c43de26721"
	connectionID := "019b2d57-b3c0-7e65-a1d2-10c43de26722"
	operationID := "019b2d57-b3c0-7e65-a1d2-10c43de26723"
	caller := MutationScope{ClientID: "message-server", CredentialID: testCredentialID}
	intent := FoundationOperationIntent{
		Caller: caller, OperationID: operationID, IdempotencyKey: "019b2d57-b3c0-7e65-a1d2-10c43de26724",
		RequestHash: [32]byte{1}, OwnerID: "owner-recovery", BootstrapSessionID: sessionID,
		PlanID: "019b2d57-b3c0-7e65-a1d2-10c43de26725", ConnectionID: connectionID,
		AccountID: "123456789012", Region: "us-east-1", ExpectedSessionRevision: 2,
		ReaperImageURI: "registry.example/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("d", 64),
	}
	operations := &connectionOperations{intent: intent, recoverable: []FoundationOperation{{
		FoundationOperationIntent: intent, Status: FoundationOperationRunning, Revision: 2,
	}}}
	secrets := &connectionSecrets{session: secretbootstrap.SessionV1{
		SessionID: sessionID, AgentInstanceID: testAgentID, OwnerID: intent.OwnerID, Purpose: "aws_connection",
		TargetID: connectionID, Status: secretbootstrap.StatusUploaded, Revision: 2,
		CreatedAt: now.Add(-time.Minute), ExpiresAt: now.Add(9 * time.Minute),
	}}
	identities := &connectionIdentities{evidence: AWSIdentityEvidence{
		BootstrapSessionID: sessionID, SessionRevision: 2, AgentInstanceID: testAgentID,
		OwnerID: intent.OwnerID, TargetID: connectionID,
		Identity:   AWSIdentity{AccountID: intent.AccountID, PrincipalARN: "arn:aws:iam::123456789012:root", PrincipalID: "123456789012", Region: intent.Region, RootIdentity: true},
		ObservedAt: now.Add(-time.Minute), ExpiresAt: now.Add(5 * time.Minute),
	}}
	foundation := &connectionFoundation{result: awsfoundation.EstablishResult{
		Identity:                   awsprovider.CallerIdentity{Partition: "aws", AccountID: intent.AccountID, ARN: "arn:aws:iam::123456789012:root", UserID: "123456789012", Region: intent.Region},
		SourceCredentialGeneration: 1,
		Stack:                      awsprovider.FoundationStackReceipt{StackID: "arn:aws:cloudformation:us-east-1:123456789012:stack/dtx-agent-foundation/id", Status: awsprovider.FoundationStackReadyStatus, ObservedAt: now},
	}}
	service, err := NewAWSConnectionService(testAgentID, intent.ReaperImageURI, &coordinatorFacts{}, identities, operations, secrets, foundation, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RecoverPendingFoundationOperations(context.Background(), 16); err != nil {
		t.Fatal(err)
	}
	if foundation.calls != 1 || !foundation.request.ResumeExistingGeneration || foundation.request.AdminAuthorization.SessionID != operationID ||
		foundation.request.ConfirmedAccountID != intent.AccountID || foundation.request.Region != intent.Region {
		t.Fatalf("recovery request was not durably bound: %#v", foundation.request)
	}
	if secrets.callerClient != caller.ClientID || operations.finalizeCalls != 1 || operations.finalizedRev != 2 {
		t.Fatalf("recovery caller/finalization mismatch: caller=%q operations=%#v", secrets.callerClient, operations)
	}
	canary := "sk-" + strings.Repeat("z", 24)
	foundation.calls, foundation.err = 0, errors.New("provider unavailable: "+canary)
	operations.failReason = ""
	if err := service.RecoverPendingFoundationOperations(context.Background(), 16); err != nil {
		t.Fatal(err)
	}
	if foundation.calls != 1 || operations.failReason == "" || strings.Contains(operations.failReason, canary) {
		t.Fatalf("provider failure was not durably redacted: calls=%d reason=%q", foundation.calls, operations.failReason)
	}
}

func TestAWSConnectionRecoveryFailsClosedBeforeProviderForExpiredOrMismatchedEvidence(t *testing.T) {
	now := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	intent := FoundationOperationIntent{
		Caller:      MutationScope{ClientID: "message-server", CredentialID: testCredentialID},
		OperationID: "019b2d57-b3c0-7e65-a1d2-10c43de26731", IdempotencyKey: "019b2d57-b3c0-7e65-a1d2-10c43de26732",
		RequestHash: [32]byte{1}, OwnerID: "owner-recovery", BootstrapSessionID: "019b2d57-b3c0-7e65-a1d2-10c43de26733",
		PlanID: "019b2d57-b3c0-7e65-a1d2-10c43de26734", ConnectionID: "019b2d57-b3c0-7e65-a1d2-10c43de26735",
		AccountID: "123456789012", Region: "us-east-1", ExpectedSessionRevision: 2,
		ReaperImageURI: "registry.example/reaper:v0.1.0-alpha.1@sha256:" + strings.Repeat("d", 64),
	}
	operations := &connectionOperations{intent: intent, recoverable: []FoundationOperation{{FoundationOperationIntent: intent, Status: FoundationOperationIntentStatus, Revision: 1}}}
	secrets := &connectionSecrets{session: secretbootstrap.SessionV1{
		SessionID: intent.BootstrapSessionID, AgentInstanceID: testAgentID, OwnerID: intent.OwnerID, Purpose: "aws_connection", TargetID: intent.ConnectionID,
		Status: secretbootstrap.StatusUploaded, Revision: 2, CreatedAt: now.Add(-11 * time.Minute), ExpiresAt: now.Add(-time.Minute),
	}}
	identities := &connectionIdentities{evidence: AWSIdentityEvidence{
		BootstrapSessionID: intent.BootstrapSessionID, SessionRevision: 2, AgentInstanceID: testAgentID,
		OwnerID: intent.OwnerID, TargetID: intent.ConnectionID,
		Identity:   AWSIdentity{AccountID: intent.AccountID, Region: "eu-west-1"},
		ObservedAt: now.Add(-11 * time.Minute), ExpiresAt: now.Add(-time.Minute),
	}}
	foundation := &connectionFoundation{err: errors.New("provider error contains synthetic-secret-value")}
	service, err := NewAWSConnectionService(testAgentID, intent.ReaperImageURI, &coordinatorFacts{}, identities, operations, secrets, foundation, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if err := service.RecoverPendingFoundationOperations(context.Background(), 16); err != nil {
		t.Fatal(err)
	}
	if foundation.calls != 0 || !operations.failBlocked || operations.failReason == "" || strings.Contains(operations.failReason, "synthetic-secret-value") {
		t.Fatalf("unsafe recovery was not blocked: calls=%d blocked=%t reason=%q", foundation.calls, operations.failBlocked, operations.failReason)
	}
}
