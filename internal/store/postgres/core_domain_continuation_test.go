package postgres

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

type domainContinuationModel struct {
	calls  atomic.Int64
	writes *atomic.Int64
}

func (m *domainContinuationModel) Run(context.Context, core.ModelRunRequest) (core.ModelRunResult, error) {
	return core.ModelRunResult{}, fmt.Errorf("unexpected unary call")
}
func (m *domainContinuationModel) Stream(_ context.Context, req core.ModelRunRequest, _ func(core.ModelDelta) error) (core.ModelRunResult, error) {
	if m.calls.Add(1) == 1 {
		return core.ModelRunResult{ToolCalls: []core.ToolCall{{ID: "bind-domain", Name: coremodel.IntrinsicCloudWorkerDomainBindToolName, Arguments: `{"hostname":"ge.example.test"}`}}}, nil
	}
	if m.writes.Load() != 1 {
		return core.ModelRunResult{}, fmt.Errorf("missing successful domain receipt")
	}
	for _, message := range req.Conversation.Messages {
		for _, result := range message.ToolResults {
			if result.CallID == "bind-domain" && result.Outcome == core.ToolOutcomeSuccess {
				return core.ModelRunResult{Done: true, Message: core.Message{Content: "域名已绑定，后续步骤已收到绑定结果。"}}, nil
			}
		}
	}
	return core.ModelRunResult{}, fmt.Errorf("domain result was not delivered to parent")
}

func TestDomainObservationPersistsAndContinuesWithoutDuplicateMutationPostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	createTestProfile(context.Background(), t, h.store.Store, cmd.ProfileID, "test", "integration-secret")
	var writes atomic.Int64
	model := &domainContinuationModel{writes: &writes}
	service, err := core.NewService(h.store, model, nil, staticConversationProfile{snapshot: cmd.ProfileSnapshot})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Close()
	service.SetIntrinsicResolver(coreIntrinsicResolverFunc(func(context.Context, core.TurnLease) ([]core.ResolvedIntrinsic, error) {
		return []core.ResolvedIntrinsic{{Tool: coremodel.Tool{Name: coremodel.IntrinsicCloudWorkerDomainBindToolName, InputSchema: map[string]any{"type": "object"}}, ReturnsObservation: true, Execute: func(_ context.Context, r core.IntrinsicExecutionRequest) (core.IntrinsicExecutionResult, error) {
			writes.Add(1)
			result := (core.ToolResult{CallID: r.Call.ID, ToolName: r.Call.Name, Content: `{"hostname":"ge.example.test","record_status":"current"}`, StateChanged: true}).WithObservation(core.ToolOutcomeSuccess, "域名已绑定", core.ToolMutationChanged)
			return core.IntrinsicExecutionResult{ToolResult: &result}, nil
		}}}, nil
	}))
	turn, err := service.StartTurn(context.Background(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	done := waitConversationTurnState(t, h.store, turn.ID, core.TurnCompleted, 5*time.Second)
	if model.calls.Load() != 2 || writes.Load() != 1 || done.Response == nil || done.Response.Message.Content != "域名已绑定，后续步骤已收到绑定结果。" {
		t.Fatalf("calls=%d writes=%d response=%+v", model.calls.Load(), writes.Load(), done.Response)
	}
	if err := service.RecoverTurns(context.Background()); err != nil {
		t.Fatal(err)
	}
	if writes.Load() != 1 {
		t.Fatal("restart repeated domain mutation")
	}
}

func TestDeepSeekDialectMigrationPersistsExplicitSelectionPostgres(t *testing.T) {
	h := openTurnDB(t)
	cmd := turnCommand()
	createTestProfile(context.Background(), t, h.store.Store, cmd.ProfileID, "deepseek-v4-pro", "integration-secret")
	if _, err := h.pool.Exec(context.Background(), `UPDATE core_model_profiles SET request_dialect='deepseek_dsml_v4' WHERE profile_id=$1`, cmd.ProfileID); err != nil {
		t.Fatal(err)
	}
	var dialect string
	if err := h.pool.QueryRow(context.Background(), `SELECT request_dialect FROM core_model_profiles WHERE profile_id=$1`, cmd.ProfileID).Scan(&dialect); err != nil || dialect != "deepseek_dsml_v4" {
		t.Fatalf("dialect=%q err=%v", dialect, err)
	}
}
