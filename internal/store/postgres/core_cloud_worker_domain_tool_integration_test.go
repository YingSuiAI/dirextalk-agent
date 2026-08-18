package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

type intrinsicDomainPrepareFixture struct {
	h            *turnDBHarness
	lease        core.TurnLease
	command      core.PrepareIntrinsicToolCommand
	initialEvent int
}

func newIntrinsicDomainPrepareFixture(t *testing.T) *intrinsicDomainPrepareFixture {
	t.Helper()
	ctx := context.Background()
	h := openTurnDB(t)
	cmd := turnCommand()
	cmd.OwnerID, cmd.AccountGeneration = "@domain-tool:test", 7
	createTestProfile(ctx, t, h.store.Store, cmd.ProfileID, "test", "integration-secret")
	candidate, err := h.store.PrepareTurnRuntimeAdmission(ctx, cmd)
	if err != nil {
		t.Fatal(err)
	}
	tool := coremodel.Tool{Name: coremodel.IntrinsicCloudWorkerDomainBindToolName, Description: "bind domain",
		InputSchema: map[string]any{"type": "object", "additionalProperties": false}}
	intrinsics := []core.ResolvedIntrinsic{{Tool: tool, Execute: func(context.Context, core.IntrinsicExecutionRequest) (core.IntrinsicExecutionResult, error) {
		return core.IntrinsicExecutionResult{}, nil
	}}}
	runtime, err := core.NewTurnRuntimeSnapshot("domain tool fixture", cmd.ProfileSnapshot, intrinsics, candidate.ExtensionSnapshotDigest, candidate.AttachmentSnapshotDigest)
	if err != nil {
		t.Fatal(err)
	}
	turn, err := h.store.StartTurnWithRuntime(ctx, cmd, runtime)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := h.store.ClaimTurn(ctx, turn.ID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := h.store.PrepareTurnModel(ctx, lease)
	if err != nil || prepared.RuntimeSnapshot == nil {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	if err = h.store.BindTurnModelRuntime(ctx, lease, *prepared.RuntimeSnapshot); err != nil {
		t.Fatal(err)
	}
	workerID := uuid.NewString()
	arguments, _ := json.Marshal(map[string]any{"worker_id": workerID, "workload_id": "web", "hostname": "app.example.test"})
	call := core.ToolCall{ID: "domain-bind-call", Name: tool.Name, Arguments: string(arguments)}
	if err = h.store.RecordTurnModelResult(ctx, lease, core.ModelRunResult{ToolCalls: []core.ToolCall{call}}); err != nil {
		t.Fatal(err)
	}
	if err = h.store.RecordConversationToolCall(ctx, lease, call); err != nil {
		t.Fatal(err)
	}
	intent := coretask.CloudWorkerDomainTaskPayload{Operation: "bind", OwnerID: cmd.OwnerID, AccountGeneration: cmd.AccountGeneration,
		CredentialID: uuid.NewString(), CredentialRevision: 3, AWSAccountID: "123456789012", Region: "us-east-1",
		WorkerID: workerID, InstanceID: "i-domain", KeyPairID: "key-domain", SecurityGroupID: "sg-domain", WorkloadID: "web",
		Hostname: "app.example.test", ZoneID: "Z123", TargetIPv4: "203.0.113.10", TTL: 300}
	intentRaw, _ := json.Marshal(intent)
	intentSum := sha256.Sum256(intentRaw)
	intent.IntentDigest = hex.EncodeToString(intentSum[:])
	argumentsDigest := conversationArgsDigest(arguments)
	attemptID := uuid.NewString()
	credentialSum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", intent.CredentialID, intent.CredentialRevision)))
	zeroDigest := coreconfirmation.Digest(strings.Repeat("0", 64))
	binding, err := (coreconfirmation.Binding{OwnerID: intent.OwnerID, AccountGeneration: intent.AccountGeneration,
		OperationDomain: "cloud_worker.domain.bind", TargetID: attemptID, TargetRevision: 1,
		TargetKind: coreconfirmation.TargetKindPersistentService, SourceVersion: "cloud-worker-domain/v1",
		ContentDigest: coreconfirmation.Digest(intent.IntentDigest), ParameterDigest: coreconfirmation.Digest(argumentsDigest),
		NetworkDigest: coreconfirmation.Digest(intent.IntentDigest), SecretGrantDigest: coreconfirmation.Digest(hex.EncodeToString(credentialSum[:])),
		ManifestDigest: zeroDigest, ExecutionDigest: zeroDigest, PermissionDigest: zeroDigest, SelectedTool: call.Name}).Normalize()
	if err != nil {
		t.Fatal(err)
	}
	payload := coretask.ConversationToolTaskPayload{TurnID: turn.ID, AttemptID: attemptID, Round: 0, CallID: call.ID,
		ToolName: call.Name, ArgumentsDigest: argumentsDigest, SafeSummary: "Cloud Worker domain bind",
		ExecutionTarget: coretask.ExtensionExecutionTargetCoreIntrinsic, CloudWorkerDomain: &intent}
	events, err := h.store.LoadTurnEvents(ctx, turn.ID, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	return &intrinsicDomainPrepareFixture{h: h, lease: lease, initialEvent: len(events), command: core.PrepareIntrinsicToolCommand{
		Lease: lease, Round: 0, Call: call, CanonicalArguments: arguments, ArgumentsDigest: argumentsDigest,
		SafeSummary: payload.SafeSummary, IdempotencyKey: attemptID, ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
		Payload: payload, Binding: binding,
	}}
}

func TestCoreIntrinsicDomainToolDurableConfirmationLifecyclePostgres(t *testing.T) {
	t.Run("atomic prepare replay and confirm", func(t *testing.T) {
		fixture := newIntrinsicDomainPrepareFixture(t)
		ctx := context.Background()
		attempt, task, confirmation, err := fixture.h.store.PrepareIntrinsicTool(ctx, fixture.command)
		if err != nil {
			t.Fatal(err)
		}
		if attempt.ID != fixture.command.Payload.AttemptID || attempt.State != "waiting_confirmation" || task.Status != coretask.StatusWaitingUser ||
			confirmation.State != coreconfirmation.StatePending || confirmation.Binding.OperationDomain != "cloud_worker.domain.bind" {
			t.Fatalf("attempt=%+v task=%+v confirmation=%+v", attempt, task, confirmation)
		}
		events, err := fixture.h.store.LoadTurnEvents(ctx, fixture.lease.Turn.ID, 0, 20)
		if err != nil || len(events) != fixture.initialEvent+1 || events[len(events)-2].Kind != core.TurnEventToolCall ||
			events[len(events)-1].Kind != core.TurnEventWaitingConfirmation || events[len(events)-1].ConfirmationID != confirmation.ConfirmationID {
			t.Fatalf("events=%+v err=%v", events, err)
		}
		restarted, err := NewCoreConversationStore(fixture.h.store.Store)
		if err != nil {
			t.Fatal(err)
		}
		replayedAttempt, replayedTask, replayedConfirmation, err := restarted.PrepareIntrinsicTool(ctx, fixture.command)
		if err != nil || replayedAttempt.ID != attempt.ID || replayedTask.ID != task.ID || replayedConfirmation.ConfirmationID != confirmation.ConfirmationID {
			t.Fatalf("attempt=%+v task=%+v confirmation=%+v err=%v", replayedAttempt, replayedTask, replayedConfirmation, err)
		}
		afterReplay, _ := restarted.LoadTurnEvents(ctx, fixture.lease.Turn.ID, 0, 20)
		if len(afterReplay) != len(events) {
			t.Fatalf("replay duplicated events: before=%d after=%d", len(events), len(afterReplay))
		}
		service, err := coreconfirmation.NewService(NewCoreConfirmationStore(fixture.h.store.Store))
		if err != nil {
			t.Fatal(err)
		}
		confirmed, err := service.Confirm(ctx, coreconfirmation.ConfirmCommand{ConfirmationID: confirmation.ConfirmationID,
			IdempotencyKey: uuid.NewString(), ExpectedRevision: confirmation.Revision, At: time.Now().UTC()})
		queued, loadErr := NewCoreTaskStore(fixture.h.store.Store).GetTask(ctx, task.ID)
		if err != nil || loadErr != nil || confirmed.State != coreconfirmation.StateConfirmed || queued.ID != task.ID || queued.Status != coretask.StatusQueued {
			t.Fatalf("confirmed=%+v queued=%+v err=%v load_err=%v", confirmed, queued, err, loadErr)
		}
	})

	for _, terminal := range []string{"reject", "expire"} {
		t.Run(terminal+" resumes exact turn", func(t *testing.T) {
			fixture := newIntrinsicDomainPrepareFixture(t)
			ctx := context.Background()
			attempt, task, confirmation, err := fixture.h.store.PrepareIntrinsicTool(ctx, fixture.command)
			if err != nil {
				t.Fatal(err)
			}
			service, err := coreconfirmation.NewService(NewCoreConfirmationStore(fixture.h.store.Store))
			if err != nil {
				t.Fatal(err)
			}
			if terminal == "reject" {
				_, err = service.Reject(ctx, coreconfirmation.RejectCommand{ConfirmationID: confirmation.ConfirmationID,
					IdempotencyKey: uuid.NewString(), ExpectedRevision: confirmation.Revision, Reason: "owner rejected", At: time.Now().UTC()})
			} else {
				_, err = service.Expire(ctx, coreconfirmation.ExpireCommand{ConfirmationID: confirmation.ConfirmationID,
					IdempotencyKey: uuid.NewString(), ExpectedRevision: confirmation.Revision, Reason: coreconfirmation.ReasonExpired, At: time.Now().UTC()})
			}
			if err != nil {
				t.Fatal(err)
			}
			restarted, err := NewCoreConversationStore(fixture.h.store.Store)
			if err != nil {
				t.Fatal(err)
			}
			if err = restarted.ResumeConversationTurn(ctx, fixture.lease.Turn.ID); err != nil {
				t.Fatal(err)
			}
			observed, err := restarted.ObserveConversationTool(ctx, fixture.lease.Turn.ID)
			storedTask, taskErr := NewCoreTaskStore(fixture.h.store.Store).GetTask(ctx, task.ID)
			turn, turnErr := restarted.GetTurn(ctx, fixture.lease.Turn.ID)
			expectedTaskStatus := coretask.StatusFailed
			if terminal == "reject" {
				expectedTaskStatus = coretask.StatusCanceled
			}
			if err != nil || taskErr != nil || turnErr != nil || observed.ID != attempt.ID || observed.State != "denied" ||
				storedTask.Status != expectedTaskStatus || turn.State != core.TurnAccepted {
				t.Fatalf("attempt=%s/%s task=%s/%s turn=%s err=%v task_err=%v turn_err=%v", observed.ID, observed.State,
					storedTask.ID, storedTask.Status, turn.State, err, taskErr, turnErr)
			}
		})
	}
}
