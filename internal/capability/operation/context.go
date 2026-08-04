package operation

import "context"

type operationIDContextKey struct{}

// WithOperationID carries the durable capability operation identity into a
// typed handler. Descriptor operation names are not ledger IDs and must never
// be used for progress events or replay lookup.
func WithOperationID(ctx context.Context, operationID string) context.Context {
	return context.WithValue(ctx, operationIDContextKey{}, operationID)
}

func OperationIDFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	value, ok := ctx.Value(operationIDContextKey{}).(string)
	return value, ok && value != ""
}
