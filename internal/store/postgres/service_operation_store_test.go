package postgres

import (
	"context"
	"strings"
	"testing"

	serviceoperation "github.com/YingSuiAI/dirextalk-agent/internal/cloud/serviceoperation"
	"github.com/google/uuid"
)

func TestServiceOperationStoreRejectsAmbiguousMutationIdentity(t *testing.T) {
	valid := serviceoperation.Mutation{
		ClientID: "message-server", CredentialID: uuid.NewString(), IdempotencyKey: uuid.NewString(),
		RequestHash: "sha256:" + strings.Repeat("a", 64),
	}
	if err := validateServiceOperationMutation(context.Background(), valid); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*serviceoperation.Mutation)
	}{
		{"blank client", func(value *serviceoperation.Mutation) { value.ClientID = "" }},
		{"secret-like client", func(value *serviceoperation.Mutation) { value.ClientID = "AKIAIOSFODNN7EXAMPLE" }},
		{"invalid credential", func(value *serviceoperation.Mutation) { value.CredentialID = "credential" }},
		{"nil idempotency", func(value *serviceoperation.Mutation) { value.IdempotencyKey = uuid.Nil.String() }},
		{"invalid request digest", func(value *serviceoperation.Mutation) { value.RequestHash = "sha256:" + strings.Repeat("g", 64) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := valid
			test.mutate(&value)
			if err := validateServiceOperationMutation(context.Background(), value); err != serviceoperation.ErrInvalid {
				t.Fatalf("error=%v, want ErrInvalid", err)
			}
		})
	}
	if err := validateServiceOperationMutation(nil, valid); err != serviceoperation.ErrInvalid {
		t.Fatalf("nil context error=%v", err)
	}
}

var _ serviceoperation.Repository = (*Store)(nil)
