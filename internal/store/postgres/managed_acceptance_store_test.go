package postgres

import (
	"context"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/google/uuid"
)

func TestManagedAcceptanceStoreInputAndTransitionPolicy(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	valid := managed.Mutation{
		ClientID:       "message-server",
		CredentialID:   uuid.NewString(),
		IdempotencyKey: uuid.NewString(),
		RequestHash:    digest,
	}
	if err := validateManagedMutation(context.Background(), valid); err != nil {
		t.Fatalf("valid mutation rejected: %v", err)
	}
	tests := []struct {
		name   string
		mutate func(*managed.Mutation)
	}{
		{"nil context", nil},
		{"blank client", func(value *managed.Mutation) { value.ClientID = "" }},
		{"secret client", func(value *managed.Mutation) { value.ClientID = "AKIAIOSFODNN7EXAMPLE" }},
		{"bad credential", func(value *managed.Mutation) { value.CredentialID = "credential" }},
		{"bad idempotency", func(value *managed.Mutation) { value.IdempotencyKey = uuid.Nil.String() }},
		{"bad request hash", func(value *managed.Mutation) { value.RequestHash = "sha256:" + strings.Repeat("g", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			ctx := context.Background()
			if test.mutate == nil {
				ctx = nil
			} else {
				test.mutate(&value)
			}
			if err := validateManagedMutation(ctx, value); err != managed.ErrInvalid {
				t.Fatalf("error=%v, want ErrInvalid", err)
			}
		})
	}
	allowed := [][2]managed.Status{
		{managed.StatusApproved, managed.StatusRunning},
		{managed.StatusRunning, managed.StatusSucceeded},
		{managed.StatusRunning, managed.StatusFailedTerminal},
	}
	for _, transition := range allowed {
		if !validManagedTransition(transition[0], transition[1]) {
			t.Fatalf("allowed transition rejected: %s -> %s", transition[0], transition[1])
		}
	}
	for _, transition := range [][2]managed.Status{
		{managed.StatusAwaitingApproval, managed.StatusRunning},
		{managed.StatusApproved, managed.StatusSucceeded},
		{managed.StatusSucceeded, managed.StatusRunning},
		{managed.StatusFailedTerminal, managed.StatusRunning},
	} {
		if validManagedTransition(transition[0], transition[1]) {
			t.Fatalf("illegal transition accepted: %s -> %s", transition[0], transition[1])
		}
	}
}
