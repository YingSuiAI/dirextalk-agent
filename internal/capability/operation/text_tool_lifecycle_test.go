package operation

import (
	"context"
	"strings"
	"testing"
)

func TestTextToolLedgerRedactsSelectedTextPersistsBoundedResultAndNeverRecoversByRedispatch(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	manager := NewManager(db)
	selected := "private selected text sentinel"
	op := &Operation{ID: "text-tool-op", CapabilityID: "agent.text_tools.v1", OperationName: "execute", RequestJSON: []byte(`{"tool_id":"summary","selected_text":"` + selected + `","output_language":"zh"}`), RootRequestDigest: []byte("root"), RequestDigest: []byte("grant"), OwnerID: "owner", AccountGeneration: 1}
	if _, created, err := manager.StartOrGet(context.Background(), op); err != nil || !created {
		t.Fatalf("admit text tool: created=%v err=%v", created, err)
	}
	var durableRequest string
	if err := db.QueryRow(`SELECT CAST(request_json AS TEXT) FROM operations WHERE id=?`, op.ID).Scan(&durableRequest); err != nil {
		t.Fatal(err)
	}
	if durableRequest != "{}" || strings.Contains(durableRequest, selected) {
		t.Fatalf("selected text persisted: %s", durableRequest)
	}
	result := `{"tool_id":"summary","output":"bounded result","sources":[]}`
	if err := manager.Complete(context.Background(), op.ID, []byte(result)); err != nil {
		t.Fatal(err)
	}
	var durableResult string
	if err := db.QueryRow(`SELECT CAST(result_json AS TEXT) FROM operations WHERE id=?`, op.ID).Scan(&durableResult); err != nil || durableResult != result {
		t.Fatalf("result receipt=%q err=%v", durableResult, err)
	}

	pending := &Operation{ID: "text-tool-pending", CapabilityID: "agent.text_tools.v1", OperationName: "execute", RequestJSON: []byte(`{"tool_id":"summary","selected_text":"other","output_language":"en"}`), RootRequestDigest: []byte("root-2"), RequestDigest: []byte("grant-2"), OwnerID: "owner", AccountGeneration: 1}
	if _, _, err := manager.StartOrGet(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	if err := manager.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	recovered, err := manager.Get(context.Background(), pending.ID)
	if err != nil || recovered.State != StateUncertain {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	called := false
	manager.Execute(context.Background(), pending.ID, func(context.Context, *Operation) ([]byte, error) {
		called = true
		return nil, nil
	})
	if called {
		t.Fatal("uncertain text tool operation was automatically redispatched")
	}
}
