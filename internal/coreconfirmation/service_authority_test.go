package coreconfirmation

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func cloudWorkerAuthorityBinding(owner string, generation uint64) Binding {
	binding := testBinding()
	executionID := "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	binding.OwnerID = owner
	binding.AccountGeneration = generation
	binding.OperationDomain = "cloud_worker.execute"
	binding.TargetID = executionID
	binding.TargetRevision = 1
	binding.TargetKind = "cloud_worker_execution"
	binding.SourceVersion = "ephemeral-pi-task/v1"
	binding.NetworkGrants = []string{"a.example", "z.example"}
	binding.ManifestDigest = Digest(strings.Repeat("1", 64))
	binding.ExecutionDigest = Digest(strings.Repeat("2", 64))
	binding.PermissionDigest = Digest(strings.Repeat("3", 64))
	binding.ExecutionID = executionID
	binding.PlanID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	binding.PlanRevision = 1
	binding.PlanDigest = Digest(strings.Repeat("4", 64))
	binding.RunID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	binding.RunRevision = 1
	binding.RunDigest = Digest(strings.Repeat("5", 64))
	binding.QuoteDigest = Digest(strings.Repeat("6", 64))
	binding.Quote = &LiveQuote{AmountMicros: 100, Currency: "USD", SourceTime: time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC), ExpiresAt: time.Date(2035, 1, 2, 4, 4, 5, 0, time.UTC), MaximumAuthorizedCostMicros: 200}
	binding.Digest = ""
	binding.Digest = canonicalDigest(binding)
	return binding
}

func TestCloudWorkerConfirmationAuthorityFencesBeforeMutation(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2035, 1, 2, 3, 4, 5, 0, time.UTC)
	repository := NewMemoryRepository(func() time.Time { return now })
	service, err := NewService(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	const owner = "@owner:example.test"
	confirmation, err := service.Request(ctx, RequestCommand{
		IdempotencyKey: uuid.NewString(),
		Binding:        cloudWorkerAuthorityBinding(owner, 7),
		TaskID:         uuid.NewString(),
		ExpiresAt:      now.Add(time.Hour),
		At:             now,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = service.ConfirmAuthorized(ctx, Authority{OwnerID: "@foreign:example.test", AccountGeneration: 7}, ConfirmCommand{
		ConfirmationID: confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, At: now,
	})
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("foreign owner confirm error = %v", err)
	}
	_, err = service.RejectAuthorized(ctx, Authority{OwnerID: owner, AccountGeneration: 8}, RejectCommand{
		ConfirmationID: confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1,
		Reason: ReasonUserRejected, At: now,
	})
	if !errors.Is(err, ErrStale) {
		t.Fatalf("stale generation reject error = %v", err)
	}
	unchanged, err := service.Get(ctx, confirmation.ConfirmationID)
	if err != nil || unchanged.State != StatePending || unchanged.Revision != 1 {
		t.Fatalf("unauthorized mutation changed confirmation: %+v err=%v", unchanged, err)
	}

	for name, authority := range map[string]Authority{
		"foreign": {OwnerID: "@foreign:example.test", AccountGeneration: 7},
		"stale":   {OwnerID: owner, AccountGeneration: 8},
	} {
		page, listErr := service.ListAuthorized(ctx, authority, ListQuery{PageSize: 10})
		if listErr != nil || len(page.Confirmations) != 0 {
			t.Fatalf("%s list leaked confirmation: %+v err=%v", name, page, listErr)
		}
	}

	confirmed, err := service.ConfirmAuthorized(ctx, Authority{OwnerID: owner, AccountGeneration: 7}, ConfirmCommand{
		ConfirmationID: confirmation.ConfirmationID, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1, At: now,
	})
	if err != nil || confirmed.State != StateConfirmed || confirmed.Revision != 2 {
		t.Fatalf("authorized confirm = %+v err=%v", confirmed, err)
	}
}
