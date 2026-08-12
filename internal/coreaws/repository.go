package coreaws

import (
	"context"
	"time"
)

const (
	// CredentialTestLeaseDuration bounds the provider-call ownership window.
	// It is deliberately long enough for normal production STS latency while
	// still giving waiters a finite outcome boundary after a crashed worker.
	CredentialTestLeaseDuration = 30 * time.Second
	// CredentialTestCompletionGrace gives a provider that returned at the
	// lease edge a short window to commit its durable receipt. It never permits
	// a second provider call for the same key.
	CredentialTestCompletionGrace = 5 * time.Second
)

func CredentialTestLeaseTimes(now time.Time, supplied ...time.Time) (time.Time, time.Time, error) {
	now = now.UTC()
	if now.IsZero() {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	if len(supplied) == 0 {
		leaseExpiresAt := now.Add(CredentialTestLeaseDuration)
		return leaseExpiresAt, leaseExpiresAt.Add(CredentialTestCompletionGrace), nil
	}
	if len(supplied) != 2 {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	leaseExpiresAt := supplied[0].UTC()
	completionGraceUntil := supplied[1].UTC()
	if leaseExpiresAt.IsZero() || completionGraceUntil.IsZero() || completionGraceUntil.Before(leaseExpiresAt) {
		return time.Time{}, time.Time{}, ErrInvalid
	}
	return leaseExpiresAt, completionGraceUntil, nil
}

// Repository is the persistence boundary for AWS profiles, immutable plans
// and change records. Implementations must serialize mutations and replay
// identical idempotency keys without exposing credential bytes.
type Repository interface {
	CreateCredential(context.Context, Credentials) (Credentials, error)
	GetCredential(context.Context, string) (Credentials, error)
	GetCredentialRevision(context.Context, string, int64) (Credentials, error)
	ListCredentials(context.Context, int, string) (CredentialPage, error)
	UpdateCredential(context.Context, Credentials, int64) (Credentials, error)
	DeleteCredential(context.Context, string, int64) error
	RecordCredentialIdentity(context.Context, string, int64, Identity, time.Time) (Credentials, error)
	CreatePlan(context.Context, Plan) (Plan, error)
	GetPlan(context.Context, string) (Plan, error)
	ListPlans(context.Context, int, string) (PlanPage, error)
	CreateChange(context.Context, Change) (Change, error)
	GetChange(context.Context, string) (Change, error)
	GetChangeByConfirmation(context.Context, string) (Change, error)
	ListChanges(context.Context, int, string, string) (ChangePage, error)
	UpdateChange(context.Context, Change, int64) (Change, error)
}

// CredentialIdentityIdempotencyRepository is the durable neutral-capability
// boundary for credential tests. Implementations commit a claim before the
// provider call and commit the tested identity plus replay receipt afterward;
// no provider callback runs inside the repository transaction. The legacy gRPC
// Credential verification deliberately does not use this optional
// interface and remains non-keyed.
type CredentialIdentityIdempotencyRepository interface {
	BeginCredentialTest(context.Context, string, int64, string, ...time.Time) (CredentialTestClaim, *CredentialTest, error)
	CompleteCredentialTest(context.Context, CredentialTestClaim, Identity, time.Time) (CredentialTest, error)
	MarkCredentialTestUncertain(context.Context, CredentialTestClaim) error
	MarkCredentialTestFailed(context.Context, CredentialTestClaim) error
}

// CredentialTestClaim is a short-lived provider-call fence.  The claim is
// durably recorded before the provider call and completed only after the
// identity plus verification metadata are committed.  Credentials are
// materialized here solely for the request-local provider call; they are never
// serialized into the claim or replay response.
type CredentialTestClaim struct {
	ClaimID              string
	IdempotencyKey       string
	CredentialID         string
	ExpectedRevision     int64
	LeaseExpiresAt       time.Time
	CompletionGraceUntil time.Time
	Credential           Credentials
}
