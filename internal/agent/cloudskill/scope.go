package cloudskill

import (
	"context"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/task"
)

type callScopeContextKey struct{}

// BindCallScope attaches trusted, normalized capability scope to one runtime
// call. Callers must never build it from model tool arguments.
func BindCallScope(ctx context.Context, scope CallScope) (context.Context, error) {
	if ctx == nil {
		return nil, ErrInvalidCallScope
	}
	scope.OwnerID = strings.TrimSpace(scope.OwnerID)
	scope.ConnectionID = strings.TrimSpace(scope.ConnectionID)
	scope.RecipeID = strings.TrimSpace(scope.RecipeID)
	if !validOpaqueID(scope.OwnerID, 255) || (scope.ConnectionID != "" && !validOpaqueID(scope.ConnectionID, 255)) || !validOpaqueID(scope.RecipeID, 128) {
		return nil, ErrInvalidCallScope
	}
	if scope.Retention != task.RetentionEphemeralAutoDestroy && scope.Retention != task.RetentionManaged {
		return nil, ErrInvalidCallScope
	}
	return context.WithValue(ctx, callScopeContextKey{}, scope), nil
}

func callScopeFromContext(ctx context.Context) (CallScope, error) {
	if ctx == nil {
		return CallScope{}, ErrMissingCallScope
	}
	scope, ok := ctx.Value(callScopeContextKey{}).(CallScope)
	if !ok {
		return CallScope{}, ErrMissingCallScope
	}
	return scope, nil
}

func validOpaqueID(value string, maxRunes int) bool {
	count := utf8.RuneCountInString(value)
	if count < 1 || count > maxRunes {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return !security.ContainsLikelySecret(value)
}
