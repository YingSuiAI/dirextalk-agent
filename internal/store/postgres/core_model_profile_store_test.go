package postgres

import (
	"errors"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

func TestProfileStoreKeyBindingAndStableErrors(t *testing.T) {
	if nullableKey("") != nil || nullableKey("secret") != "secret" {
		t.Fatal("unexpected key binding")
	}
	if !errors.Is(mapProfileDBError(coremodel.ErrProfileNotFound), ErrProfileStoreUnavailable) {
		t.Fatal("unexpected safe error mapping")
	}
}

func TestProfileStoreOperationNamespacing(t *testing.T) {
	for short, namespaced := range map[string]string{
		"create": profileCreateOp,
		"update": profileUpdateOp,
		"delete": profileDeleteOp,
	} {
		if got := normalizeProfileOperation(short); got != namespaced {
			t.Fatalf("normalize %q = %q, want %q", short, got, namespaced)
		}
	}
	if got := normalizeProfileOperation(profileCreateOp); got != profileCreateOp {
		t.Fatalf("namespaced operation changed: %q", got)
	}
}
