package task

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestCreateCommandRejectsRawSecretsAndInvalidRetention(t *testing.T) {
	t.Parallel()
	base := CreateCommand{IdempotencyKey: uuid.NewString(), OwnerID: "owner", Goal: "compile the project", Retention: RetentionEphemeralAutoDestroy}
	if err := base.Validate(); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	withSecret := base
	withSecret.Goal = "use sk-abcdefghijklmnopqrstuvwxyz"
	if err := withSecret.Validate(); !errors.Is(err, ErrRawSecret) {
		t.Fatalf("secret error = %v, want ErrRawSecret", err)
	}
	withoutRetention := base
	withoutRetention.Retention = ""
	if err := withoutRetention.Validate(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("retention error = %v, want ErrInvalid", err)
	}
}

func TestCommandDigestsBindMutationInputs(t *testing.T) {
	t.Parallel()
	first := CreateCommand{OwnerID: "owner", Goal: "goal", Retention: RetentionManaged}
	second := first
	second.Goal = "different"
	if first.Digest() == second.Digest() {
		t.Fatal("create digest did not bind goal")
	}
}
