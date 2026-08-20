package coreconversation

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

func TestAdmittedExecutionPoliciesAreVersionedBoundedAndModeSpecific(t *testing.T) {
	modes := []TurnExecutionMode{
		TurnExecutionInteractive,
		TurnExecutionDeep,
		TurnExecutionScheduled,
		TurnExecutionWorkerOrchestration,
	}
	policies := make(map[TurnExecutionMode]TurnExecutionPolicy, len(modes))
	for _, mode := range modes {
		policy, err := AdmittedTurnExecutionPolicy(mode)
		if err != nil || policy.Validate() != nil || policy.Version != TurnExecutionPolicyVersion || policy.Mode != mode {
			t.Fatalf("mode=%q policy=%+v err=%v", mode, policy, err)
		}
		policies[mode] = policy
	}
	interactive := policies[TurnExecutionInteractive]
	for _, mode := range modes[1:] {
		larger := policies[mode]
		if interactive.MaxModelDispatches >= larger.MaxModelDispatches ||
			interactive.MaxModelActiveMilliseconds >= larger.MaxModelActiveMilliseconds ||
			interactive.MaxToolCalls >= larger.MaxToolCalls {
			t.Fatalf("interactive policy=%+v is not materially below %s policy=%+v", interactive, mode, larger)
		}
	}

	historical := policies[TurnExecutionDeep]
	historical.MaxModelDispatches--
	historical.MaxModelActiveMilliseconds -= uint64(time.Minute.Milliseconds())
	historical.MaxToolCalls--
	if historical.Validate() != nil {
		t.Fatalf("safe admitted values were compared to current defaults: %+v", historical)
	}

	unsafe := policies[TurnExecutionDeep]
	unsafe.MaxModelDispatches = MaxAdmittedTurnModelDispatches + 1
	if !errors.Is(unsafe.Validate(), ErrInvalid) {
		t.Fatalf("unsafe policy accepted: %+v", unsafe)
	}
	unsupported := policies[TurnExecutionDeep]
	unsupported.Version++
	if !errors.Is(unsupported.Validate(), ErrInvalid) {
		t.Fatalf("unsupported policy accepted: %+v", unsupported)
	}
	if _, err := AdmittedTurnExecutionPolicy("future"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown execution mode err=%v", err)
	}
}

func TestWorkerOrchestrationPolicyContainsOnlyMainTurnReactBudget(t *testing.T) {
	policy, err := AdmittedTurnExecutionPolicy(TurnExecutionWorkerOrchestration)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	for _, workerOwnedField := range []string{"max_runtime_seconds", "max_tokens", "max_output_bytes"} {
		if json.Valid(raw) && containsJSONField(raw, workerOwnedField) {
			t.Fatalf("conversation policy captured Worker-owned limit %q: %s", workerOwnedField, raw)
		}
	}
}

func TestClientExecutionModeDefaultsInteractiveAndBindsChatFingerprint(t *testing.T) {
	base := ChatCommand{
		RequestID: uuid.NewString(), Prompt: "investigate", ProfileID: uuid.NewString(),
		ExpectedProfileRevision: 1, ExpectedCredentialVersion: 1,
	}
	implicit, err := base.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	explicit := base
	explicit.ExecutionMode = TurnExecutionInteractive
	explicitFingerprint, err := explicit.Fingerprint()
	if err != nil || explicitFingerprint != implicit {
		t.Fatalf("omitted mode is not interactive: implicit=%s explicit=%s err=%v", implicit, explicitFingerprint, err)
	}
	deep := base
	deep.ExecutionMode = TurnExecutionDeep
	deepFingerprint, err := deep.Fingerprint()
	if err != nil || deepFingerprint == implicit {
		t.Fatalf("deep mode was not fingerprint-bound: deep=%s implicit=%s err=%v", deepFingerprint, implicit, err)
	}
	for _, rejected := range []TurnExecutionMode{TurnExecutionScheduled, "future"} {
		invalid := base
		invalid.ExecutionMode = rejected
		if !errors.Is(invalid.Validate(), ErrInvalid) {
			t.Fatalf("public mode %q accepted", rejected)
		}
	}
}

func TestScheduledTurnAdmissionPersistsScheduledExecutionPolicy(t *testing.T) {
	profile := testTurnSnapshot()
	base := newFakeStore()
	store := &terminalAdmissionStore{publicActiveTurnStore: &publicActiveTurnStore{fakeStore: base}}
	service, err := NewService(store, &fakeModel{}, nil, snapshotResolverFunc(func(context.Context, string) (coremodel.ExecutionSnapshot, error) {
		return profile, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	command := TurnStartCommand{
		RequestID: uuid.NewString(), Prompt: "scheduled work", ProfileID: profile.ProfileID,
		ExpectedProfileRevision: profile.Revision, ExpectedCredentialVersion: profile.CredentialVersion,
		ProfileSnapshot: profile, ExtensionSnapshotsPinned: true, IntrinsicPolicy: TurnIntrinsicPolicyNone,
		ExecutionMode: TurnExecutionScheduled,
	}
	if _, err = service.StartTurn(context.Background(), command); err != nil {
		t.Fatal(err)
	}
	if len(store.runtimes) != 1 || store.runtimes[0].ExecutionPolicy.Mode != TurnExecutionScheduled ||
		store.runtimes[0].ExecutionPolicy.MaxModelDispatches != MaxAdmittedTurnModelDispatches ||
		store.runtimes[0].ExecutionPolicy.MaxToolCalls != MaxAdmittedTurnToolCalls {
		t.Fatalf("scheduled runtime=%+v", store.runtimes)
	}
}

func containsJSONField(raw []byte, field string) bool {
	var value map[string]json.RawMessage
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	_, ok := value[field]
	return ok
}

type policyPreflightStore struct {
	*readOnlyTurnStore
	claims int
	events int
}

func (s *policyPreflightStore) ClaimTurn(ctx context.Context, id string, now time.Time, ttl time.Duration) (TurnLease, error) {
	s.claims++
	return s.readOnlyTurnStore.ClaimTurn(ctx, id, now, ttl)
}

func (s *policyPreflightStore) AppendTurnEvent(ctx context.Context, id string, event TurnEvent) (TurnEvent, error) {
	s.events++
	return s.readOnlyTurnStore.AppendTurnEvent(ctx, id, event)
}

func TestExecuteTurnRejectsUnsupportedAdmittedPolicyBeforeTurnMutation(t *testing.T) {
	service, baseStore, turn := newTerminalFinalizationFixture(t, &terminalResultTurnModel{})
	policy, err := AdmittedTurnExecutionPolicy(TurnExecutionInteractive)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newTurnRuntimeSnapshotWithPolicy("", turn.ProfileSnapshot, nil, turn.ExtensionSnapshotDigest, turn.AttachmentSnapshotDigest, "", policy)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ExecutionPolicy.Version++
	turn.RuntimeSnapshot = &runtime
	baseStore.turn = turn
	store := &policyPreflightStore{readOnlyTurnStore: baseStore.readOnlyTurnStore}
	service.turns = store
	service.store = store

	service.executeTurn(context.Background(), turn.ID)

	if store.claims != 0 || store.events != 0 || store.turn.State != TurnAccepted || store.turn.Revision != turn.Revision {
		t.Fatalf("unsupported policy mutated turn: claims=%d events=%d turn=%+v", store.claims, store.events, store.turn)
	}
}
