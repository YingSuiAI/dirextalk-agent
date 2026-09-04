package postgres

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/localartifact"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshflow"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconfirmation"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

type cloudWorkerReferenceSourceFunc func(context.Context, string, uint64, string) (bool, error)

func (resolve cloudWorkerReferenceSourceFunc) CloudWorkerReferenceAvailable(ctx context.Context, ownerID string, accountGeneration uint64, workerID string) (bool, error) {
	return resolve(ctx, ownerID, accountGeneration, workerID)
}

func completionFixture() (*core.ModelRunResult, cloudworker.Plan, cloudworker.Execution) {
	call := core.ToolCall{ID: uuid.NewString(), Name: coremodel.IntrinsicCloudWorkerProposeToolName, Arguments: `{}`}
	plan := cloudworker.Plan{OwnerID: "owner", AccountGeneration: 7, TaskID: uuid.NewString(), PlanID: uuid.NewString(), ExecutionID: uuid.NewString(), Revision: 1, Status: "waiting_user", WorkloadKind: cloudworker.WorkloadJob}
	execution := cloudworker.Execution{ExecutionID: plan.ExecutionID, RunID: uuid.NewString(), Revision: 2, State: cloudworker.StateSucceeded}
	return &core.ModelRunResult{ToolCalls: []core.ToolCall{call}}, plan, execution
}

func TestSSHWorkerCompletionLinksCollectedArtifactWithoutFilesystemAuthority(t *testing.T) {
	dispatch, plan, execution := completionFixture()
	repository, err := localartifact.NewRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authority := localartifact.Authority{OwnerID: plan.OwnerID, AccountGeneration: plan.AccountGeneration}
	sink, err := repository.Bind(authority, plan.ExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if err = sink.StoreArtifact(context.Background(), "results/output.txt", strings.NewReader("data"), 4); err != nil {
		t.Fatal(err)
	}
	collected, _, err := repository.List(context.Background(), authority, plan.ExecutionID, "", 10)
	if err != nil || len(collected) != 1 {
		t.Fatalf("collected=%+v err=%v", collected, err)
	}
	a := collected[0]
	artifacts := []sshflow.Artifact{{ArtifactID: a.ArtifactID, ExecutionID: a.ExecutionID, Kind: a.Kind, Name: a.Name, MediaType: a.MediaType, SizeBytes: a.SizeBytes, SHA256: a.SHA256, RelativePath: "cloud-worker/artifacts/" + plan.ExecutionID + "/" + a.Name}}
	_, result, err := sshWorkerContinuation(dispatch, plan, execution, "completed", sshflow.Result{WorkerID: plan.ExecutionID}, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	var completion struct {
		Artifacts []struct {
			core.Reference
			URI string `json:"uri"`
		} `json:"artifacts"`
	}
	if err = json.Unmarshal([]byte(result.Content), &completion); err != nil {
		t.Fatal(err)
	}
	if len(result.References) != 3 || len(completion.Artifacts) != 1 {
		t.Fatalf("refs=%+v content=%s", result.References, result.Content)
	}
	ref := result.References[2]
	wantSize := uint64(a.SizeBytes)
	want := core.Reference{Kind: "execution_artifact", AccountGeneration: plan.AccountGeneration, RecordKind: "cloud_worker", ArtifactID: a.ArtifactID, ExecutionID: a.ExecutionID, Name: a.Name, MediaType: a.MediaType, SizeBytes: &wantSize, SHA256: a.SHA256}
	if ref.Validate() != nil || !reflect.DeepEqual(ref, want) || !reflect.DeepEqual(completion.Artifacts[0].Reference, want) || completion.Artifacts[0].URI != "dirextalk-artifact://cloud_worker/"+a.ArtifactID {
		t.Fatalf("reference=%+v artifact=%+v", ref, completion.Artifacts[0])
	}
	if strings.Contains(result.Content, "relative_path") || strings.Contains(result.Content, "cloud-worker/artifacts/") {
		t.Fatalf("filesystem authority leaked: %s", result.Content)
	}
	// The public identity resolves to the same owner-bound bytes, not the server catalog ID.
	chunk, err := repository.Download(context.Background(), authority, ref.ArtifactID, 0, 512)
	if err != nil || string(chunk.Data) != "data" || chunk.Artifact.SHA256 != ref.SHA256 {
		t.Fatalf("download=%+v err=%v", chunk, err)
	}
	if _, err = repository.Get(context.Background(), localartifact.Authority{OwnerID: "other", AccountGeneration: authority.AccountGeneration}, ref.ArtifactID); err == nil {
		t.Fatal("foreign owner resolved artifact")
	}
	if _, err = repository.Get(context.Background(), localartifact.Authority{OwnerID: authority.OwnerID, AccountGeneration: authority.AccountGeneration + 1}, ref.ArtifactID); err == nil {
		t.Fatal("foreign generation resolved artifact")
	}
}

func TestSSHWorkerCompletionRejectsMalformedOrForeignDeliverable(t *testing.T) {
	for name, mutate := range map[string]func(*sshflow.Artifact){
		"foreign execution": func(a *sshflow.Artifact) { a.ExecutionID = uuid.NewString() },
		"invalid UUID":      func(a *sshflow.Artifact) { a.ArtifactID = "bad" },
		"path traversal":    func(a *sshflow.Artifact) { a.Name = "../secret" },
		"invalid digest":    func(a *sshflow.Artifact) { a.SHA256 = "bad" },
		"negative size":     func(a *sshflow.Artifact) { a.SizeBytes = -1 },
		"oversize":          func(a *sshflow.Artifact) { a.SizeBytes = 64<<20 + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			dispatch, plan, execution := completionFixture()
			a := sshflow.Artifact{ArtifactID: uuid.NewString(), ExecutionID: plan.ExecutionID, Kind: "file", Name: "output.txt", MediaType: "text/plain", SizeBytes: 4, SHA256: strings.Repeat("a", 64)}
			mutate(&a)
			if _, _, err := sshWorkerContinuation(dispatch, plan, execution, "complete", sshflow.Result{WorkerID: plan.ExecutionID}, []sshflow.Artifact{a}); err == nil {
				t.Fatal("invalid deliverable accepted")
			}
		})
	}
}

func TestSSHWorkerCompletionBoundsLinksAndReferencesTogether(t *testing.T) {
	dispatch, plan, execution := completionFixture()
	artifacts := make([]sshflow.Artifact, core.MaxReferences)
	for i := range artifacts {
		artifacts[i] = sshflow.Artifact{ArtifactID: uuid.NewString(), ExecutionID: plan.ExecutionID, Kind: "file", Name: "result.txt", MediaType: "text/plain", SizeBytes: 4, SHA256: strings.Repeat("a", 64)}
	}
	_, result, err := sshWorkerContinuation(dispatch, plan, execution, "complete", sshflow.Result{WorkerID: plan.ExecutionID}, artifacts)
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		Artifacts []struct {
			ArtifactID string `json:"artifact_id"`
			URI        string `json:"uri"`
		} `json:"artifacts"`
		Omitted int `json:"artifacts_omitted"`
	}
	if err = json.Unmarshal([]byte(result.Content), &body); err != nil {
		t.Fatal(err)
	}
	if result.Validate() != nil || len(result.References) != core.MaxReferences || len(body.Artifacts) != core.MaxReferences-2 || body.Omitted != 2 {
		t.Fatalf("result=%+v body=%+v", result, body)
	}
	for i, a := range body.Artifacts {
		if result.References[i+2].ArtifactID != a.ArtifactID || a.URI != "dirextalk-artifact://cloud_worker/"+a.ArtifactID {
			t.Fatal("unbacked link")
		}
	}
}

func TestSSHWorkerCompletionPersistsArtifactThroughTerminalAndHistory(t *testing.T) {
	h := newPGCloudWorkerHarness(t)
	defer h.cleanup()
	offer := h.propose(t)
	confirmations, err := coreconfirmation.NewService(h.confirmations)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = confirmations.Confirm(h.ctx, coreconfirmation.ConfirmCommand{ConfirmationID: offer.Confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: offer.Confirmation.Revision, At: h.now}); err != nil {
		t.Fatal(err)
	}
	task, _, err := NewCoreTaskStore(h.store).ClaimNextDue(h.ctx, "artifact-continuation", h.now, 2*time.Minute, 1)
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewSSHWorkerStore(h.store, "cloud-worker/artifacts")
	if err != nil {
		t.Fatal(err)
	}
	run, err := store.Begin(h.ctx, task)
	if err != nil {
		t.Fatal(err)
	}
	artifact := sshflow.Artifact{ArtifactID: uuid.NewString(), ExecutionID: offer.Plan.ExecutionID, Kind: "file", Name: "result.txt", MediaType: "text/plain", SizeBytes: 4, SHA256: strings.Repeat("a", 64), RelativePath: "cloud-worker/artifacts/" + offer.Plan.ExecutionID + "/result.txt"}
	foreign := artifact
	foreign.ExecutionID = uuid.NewString()
	if err = store.Complete(h.ctx, run, sshflow.Result{Summary: "done", WorkerID: run.Plan.ExecutionID, Artifacts: []sshflow.Artifact{foreign}}); err == nil {
		t.Fatal("foreign execution terminalized")
	}
	if err = store.Complete(h.ctx, run, sshflow.Result{Summary: "done", WorkerID: run.Plan.ExecutionID, Artifacts: []sshflow.Artifact{artifact}}); err != nil {
		t.Fatal(err)
	}
	events, err := h.conversation.LoadTurnEvents(h.ctx, offer.Plan.TurnID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	var result *core.ToolResult
	for _, event := range events {
		if event.ToolResult != nil {
			result = event.ToolResult
		}
	}
	if result == nil || result.Validate() != nil || len(result.References) != 3 || result.References[2].ArtifactID != artifact.ArtifactID {
		t.Fatalf("result=%+v", result)
	}
	lease, err := h.conversation.ClaimTurn(h.ctx, offer.Plan.TurnID, time.Now().UTC(), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	before, err := h.conversation.LoadConversation(h.ctx, offer.Plan.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	response := core.ChatResponse{RequestID: lease.Turn.RequestID, ConversationID: lease.Turn.ConversationID, Revision: before.Revision + 1,
		Message: core.Message{ID: uuid.NewString(), Role: core.RoleAssistant, Content: "[Result](dirextalk-artifact://cloud_worker/" + artifact.ArtifactID + ")", ModelProfileID: lease.Turn.ProfileID, CreatedAt: time.Now().UTC(), References: result.References}, References: result.References}
	terminal, err := h.conversation.CommitTurn(h.ctx, lease, response)
	if err != nil || terminal.Response == nil || !reflect.DeepEqual(terminal.Response.References, result.References) {
		t.Fatalf("terminal=%+v err=%v", terminal, err)
	}
	history, err := h.conversation.LoadConversation(h.ctx, offer.Plan.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	last := history.Messages[len(history.Messages)-1]
	if last.Validate() != nil || last.Content != response.Message.Content || !reflect.DeepEqual(last.References, result.References) {
		t.Fatalf("history=%+v", last)
	}

	var resolvedWorkerID string
	h.conversation.SetCloudWorkerReferenceSource(cloudWorkerReferenceSourceFunc(
		func(_ context.Context, ownerID string, accountGeneration uint64, workerID string) (bool, error) {
			if ownerID != run.Plan.OwnerID || accountGeneration != run.Plan.AccountGeneration {
				t.Fatalf("reference authority = %q/%d", ownerID, accountGeneration)
			}
			resolvedWorkerID = workerID
			return false, nil
		},
	))
	retiredHistory, err := h.conversation.LoadConversation(h.ctx, offer.Plan.ConversationID)
	if err != nil {
		t.Fatal(err)
	}
	var runReferences, artifactReferences, planReferences int
	for _, message := range retiredHistory.Messages {
		for _, reference := range message.References {
			switch reference.Kind {
			case "execution_run":
				runReferences++
			case "execution_artifact":
				artifactReferences++
			case "execution_plan":
				planReferences++
			}
		}
	}
	if resolvedWorkerID != run.Plan.ExecutionID || runReferences != 0 || artifactReferences != 0 || planReferences != 2 || retiredHistory.Messages[len(retiredHistory.Messages)-1].Content != response.Message.Content {
		t.Fatalf("resolved_worker=%q run_refs=%d artifact_refs=%d plan_refs=%d history=%+v", resolvedWorkerID, runReferences, artifactReferences, planReferences, retiredHistory)
	}
}

func TestSSHWorkerCompletionCostEvidenceDistinguishesMissingZeroAndEstimate(t *testing.T) {
	for _, scenario := range []string{"missing", "zero reuse", "quoted job", "quoted service", "unsealed quote"} {
		t.Run(scenario, func(t *testing.T) {
			dispatch, plan, execution := completionFixture()
			if scenario != "missing" {
				plan.Quote = cloudworker.Quote{AmountMicros: 500, MaximumAuthorizedCostMicros: 1000, ComputeMicrosPerHour: 12345, Currency: "USD", SourceTime: time.Now().UTC(), ExpiresAt: time.Now().UTC().Add(time.Hour), BasisDigest: strings.Repeat("a", 64), CatalogRevisionDigest: strings.Repeat("b", 64)}
				if scenario == "zero reuse" {
					plan.PersistentWorkerReuse = true
					plan.Quote.AmountMicros = 0
					plan.Quote.MaximumAuthorizedCostMicros = 0
				}
				if scenario == "quoted service" {
					plan.WorkloadKind = cloudworker.WorkloadService
				}
				if scenario != "unsealed quote" {
					if err := plan.Quote.Seal(); err != nil {
						t.Fatal(err)
					}
				}
			}
			_, result, err := sshWorkerContinuation(dispatch, plan, execution, "Worker claims free", sshflow.Result{WorkerID: plan.ExecutionID}, nil)
			if err != nil {
				t.Fatal(err)
			}
			var body map[string]json.RawMessage
			if err = json.Unmarshal([]byte(result.Content), &body); err != nil {
				t.Fatal(err)
			}
			var cost struct {
				ActualCostStatus string `json:"actual_cost_status"`
				Quote            *struct {
					Compute    uint64 `json:"compute_micros_per_hour"`
					Estimated  *int64 `json:"estimated_job_cost_micros"`
					Authorized *int64 `json:"maximum_new_allocation_authorized_cost_micros"`
				} `json:"quote"`
			}
			if err = json.Unmarshal(body["cost_evidence"], &cost); err != nil || cost.ActualCostStatus != "unavailable" {
				t.Fatalf("cost=%s err=%v", body["cost_evidence"], err)
			}
			if scenario == "missing" || scenario == "unsealed quote" {
				if cost.Quote != nil {
					t.Fatal("missing quote invented zero")
				}
				return
			}
			if cost.Quote == nil || cost.Quote.Compute != plan.Quote.ComputeMicrosPerHour {
				t.Fatalf("quote=%s", body["cost_evidence"])
			}
			if scenario == "quoted job" && (cost.Quote.Estimated == nil || *cost.Quote.Estimated != 500 || cost.Quote.Authorized == nil || *cost.Quote.Authorized != 1000) {
				t.Fatalf("quote=%s", body["cost_evidence"])
			}
			if scenario == "zero reuse" && (cost.Quote.Estimated != nil || cost.Quote.Authorized == nil || *cost.Quote.Authorized != 0) {
				t.Fatalf("reuse zero was treated as actual cost: %s", body["cost_evidence"])
			}
			if scenario == "quoted service" && (cost.Quote.Estimated != nil || cost.Quote.Authorized != nil) {
				t.Fatalf("service has finite lifetime quote: %s", body["cost_evidence"])
			}
		})
	}
}
