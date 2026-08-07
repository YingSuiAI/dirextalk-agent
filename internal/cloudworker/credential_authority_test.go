package cloudworker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

type proposalAWSBindingResolver struct {
	binding AWSBinding
	err     error
	calls   int
}

func (resolver *proposalAWSBindingResolver) ResolveCurrentAWSBinding(context.Context) (AWSBinding, error) {
	resolver.calls++
	return resolver.binding, resolver.err
}

func credentialProposalCommand() ProposeCommand {
	return ProposeCommand{
		OwnerID: "@owner:example.test", AccountGeneration: 7,
		IdempotencyKey: uuid.NewString(), ConversationID: uuid.NewString(), TurnID: uuid.NewString(),
		TurnLeaseID: uuid.NewString(), TurnLeaseEpoch: 2, ExpectedTurnRevision: 1,
		Objective: "run an exact cloud task", ObjectiveSummary: "run an exact cloud task",
		UserPromptDigest: digestValue("credential-authority-prompt"),
		ProposalReason:   ProposalReasonExplicitUserCloud,
		InputManifest:    InputManifest{Schema: InputManifestSchema, Items: []InputManifestItem{}},
		WorkspaceMode:    WorkspaceNone,
		ModelAuthorization: ModelAuthorization{
			ModelProfileID: uuid.NewString(), ModelProfileRevision: 2,
			Provider: "openai_compatible", Model: "gpt-test", Interface: "openai_compatible",
			CredentialVersion: 4, CredentialBindingDigest: digestValue("model-credential"),
		},
	}
}

func TestServiceProposalRevalidatesCurrentAWSBinding(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	current := defaults.AWS
	current.CredentialRevision++
	resolver := &proposalAWSBindingResolver{binding: current}
	store := &intrinsicStore{}
	service, err := NewServiceWithAWSBindingResolver(
		store, defaults,
		FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }},
		resolver, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := service.Propose(context.Background(), credentialProposalCommand())
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 || len(store.commands) != 1 || offer.Plan.AWS != current ||
		offer.Plan.AWS == defaults.AWS || offer.Plan.AuthorizationBasisDigest == "" {
		t.Fatalf("proposal did not bind current credential: calls=%d plan=%+v", resolver.calls, offer.Plan)
	}
}

func TestServiceProposalFailsClosedWhenCredentialAuthorityIsStale(t *testing.T) {
	now := time.Date(2026, 8, 7, 10, 0, 0, 0, time.UTC)
	defaults := intrinsicDefaults(now)
	resolver := &proposalAWSBindingResolver{binding: defaults.AWS, err: ErrStaleAuthorization}
	store := &intrinsicStore{}
	service, err := NewServiceWithAWSBindingResolver(
		store, defaults,
		FakeQuoter{AmountMicros: 1000, MaximumAuthorizedMicros: 2000, TTL: 5 * time.Minute, Now: func() time.Time { return now }},
		resolver, func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Propose(context.Background(), credentialProposalCommand()); !errors.Is(err, ErrStaleAuthorization) {
		t.Fatalf("stale credential authority err=%v", err)
	}
	if resolver.calls != 1 || len(store.commands) != 0 {
		t.Fatalf("stale credential authority persisted an offer: calls=%d commands=%d", resolver.calls, len(store.commands))
	}
}
