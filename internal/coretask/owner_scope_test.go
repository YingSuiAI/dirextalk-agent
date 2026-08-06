package coretask

import (
	"context"
	"errors"
	"testing"
)

func TestOwnerScopeRejectsReservedInternalNamespace(t *testing.T) {
	reserved := OwnerScope{OwnerID: ReservedInternalOwnerPrefix + "legacy_task", AccountGeneration: 1}
	if !errors.Is(reserved.Validate(), ErrInvalid) {
		t.Fatal("reserved internal owner namespace was accepted")
	}
	if _, err := WithOwnerScope(context.Background(), reserved); !errors.Is(err, ErrInvalid) {
		t.Fatalf("reserved internal owner entered a public context: %v", err)
	}
	public := OwnerScope{OwnerID: "@owner:example.test", AccountGeneration: 2}
	ctx, err := WithOwnerScope(context.Background(), public)
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := OwnerScopeFromContext(ctx); !ok || got != public {
		t.Fatalf("public owner scope=%+v ok=%v", got, ok)
	}
}
