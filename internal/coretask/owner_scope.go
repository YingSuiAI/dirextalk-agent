package coretask

import (
	"context"
	"strings"
)

const ReservedInternalOwnerPrefix = "__dirextalk_internal_"

type OwnerScope struct {
	OwnerID           string
	AccountGeneration int64
}

func (scope OwnerScope) Validate() error {
	owner := strings.TrimSpace(scope.OwnerID)
	if owner == "" || len(owner) > 256 || strings.HasPrefix(owner, ReservedInternalOwnerPrefix) || strings.ContainsAny(owner, "\r\n\x00") || scope.AccountGeneration <= 0 {
		return ErrInvalid
	}
	return nil
}

type ownerScopeContextKey struct{}

func WithOwnerScope(ctx context.Context, scope OwnerScope) (context.Context, error) {
	if ctx == nil || scope.Validate() != nil {
		return nil, ErrInvalid
	}
	scope.OwnerID = strings.TrimSpace(scope.OwnerID)
	return context.WithValue(ctx, ownerScopeContextKey{}, scope), nil
}

func OwnerScopeFromContext(ctx context.Context) (OwnerScope, bool) {
	if ctx == nil {
		return OwnerScope{}, false
	}
	scope, ok := ctx.Value(ownerScopeContextKey{}).(OwnerScope)
	return scope, ok && scope.Validate() == nil
}
