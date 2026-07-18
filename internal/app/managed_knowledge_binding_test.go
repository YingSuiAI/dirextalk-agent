package app

import (
	"context"
	"errors"
	"testing"
	"time"

	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledgeprofile"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/google/uuid"
)

func TestManagedKnowledgeBindingCreatesExactImmutableConfigAndReplays(t *testing.T) {
	t.Parallel()
	agentID, deploymentID, serviceID, acceptanceID := uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	retained := retainedKnowledgeRecipeFixture(t)
	digest, err := retained.Digest()
	if err != nil {
		t.Fatal(err)
	}
	configs := &managedKnowledgeConfigFake{losePutResponse: true}
	binder, err := newManagedKnowledgeBinder(agentID, managedKnowledgeRecipeReaderFake{value: retained}, configs)
	if err != nil {
		t.Fatal(err)
	}
	scope := cloudmanaged.ScopeV1{
		AcceptanceID: acceptanceID, OwnerID: "owner-knowledge", DeploymentID: deploymentID,
		ServiceID: serviceID, RecipeID: retained.RecipeID, RecipeDigest: digest,
	}
	if err := binder.EnsureManagedKnowledgeBinding(context.Background(), scope, serviceID); err != nil {
		t.Fatal(err)
	}
	if err := binder.EnsureManagedKnowledgeBinding(context.Background(), scope, serviceID); err != nil {
		t.Fatal(err)
	}
	if configs.putCalls != 2 || configs.command.ExpectedRevision != 0 || configs.command.BindingID != serviceID ||
		configs.command.OwnerID != scope.OwnerID || configs.command.Spec != (knowledge.ConfigSpec{
		DeploymentID: deploymentID, ManagedServiceID: serviceID, RecipeDigest: digest,
		EmbeddingProfileID: knowledgeprofile.EmbeddingProfileID, Enabled: true,
	}) || configs.scope.ClientID != "internal.managed-knowledge-binding" || configs.scope.CredentialID == "" {
		t.Fatalf("managed Knowledge binding call = scope=%+v command=%+v calls=%d", configs.scope, configs.command, configs.putCalls)
	}
	firstKey := configs.command.IdempotencyKey
	scope.AcceptanceID = uuid.NewString()
	if err := binder.EnsureManagedKnowledgeBinding(context.Background(), scope, serviceID); err != nil {
		t.Fatalf("exact later acceptance was not idempotent: %v", err)
	}
	if configs.command.IdempotencyKey == firstKey {
		t.Fatal("a distinct acceptance reused the old mutation identity")
	}
}

func TestManagedKnowledgeBindingRejectsImmutableDriftAndIgnoresOtherRecipes(t *testing.T) {
	t.Parallel()
	retained := retainedKnowledgeRecipeFixture(t)
	digest, _ := retained.Digest()
	serviceID := uuid.NewString()
	configs := &managedKnowledgeConfigFake{stored: &knowledge.Config{
		OwnerID: "owner-knowledge", BindingID: serviceID, Revision: 1,
		Spec: knowledge.ConfigSpec{DeploymentID: uuid.NewString(), ManagedServiceID: serviceID, RecipeDigest: digest,
			EmbeddingProfileID: knowledgeprofile.EmbeddingProfileID, Enabled: true},
	}}
	binder, err := newManagedKnowledgeBinder(uuid.NewString(), managedKnowledgeRecipeReaderFake{value: retained}, configs)
	if err != nil {
		t.Fatal(err)
	}
	scope := cloudmanaged.ScopeV1{AcceptanceID: uuid.NewString(), OwnerID: "owner-knowledge", DeploymentID: uuid.NewString(), ServiceID: serviceID,
		RecipeID: retained.RecipeID, RecipeDigest: digest}
	if err := binder.EnsureManagedKnowledgeBinding(context.Background(), scope, serviceID); !errors.Is(err, cloudmanaged.ErrRevisionConflict) {
		t.Fatalf("immutable drift error = %v", err)
	}

	other := retained
	other.Name = "another valid experimental service"
	otherDigest, _ := other.Digest()
	configs = &managedKnowledgeConfigFake{}
	binder, _ = newManagedKnowledgeBinder(uuid.NewString(), managedKnowledgeRecipeReaderFake{value: other}, configs)
	scope.RecipeDigest = otherDigest
	if err := binder.EnsureManagedKnowledgeBinding(context.Background(), scope, serviceID); err != nil || configs.putCalls != 0 {
		t.Fatalf("non-retained Recipe created Knowledge binding: error=%v calls=%d", err, configs.putCalls)
	}
}

func retainedKnowledgeRecipeFixture(t *testing.T) recipe.RecipeV1 {
	t.Helper()
	hints := knowledgeprofile.ResearchHints()
	evidence := make([]knowledgeprofile.Evidence, 0, len(hints))
	for _, hint := range hints {
		evidence = append(evidence, knowledgeprofile.Evidence{URL: hint.ResearchURL,
			RetrievedAt: time.Date(2026, 7, 19, 3, 0, 0, 0, time.UTC), ContentDigest: "sha256:" + knowledgeprofile.ManifestSHA256})
	}
	value, ok := knowledgeprofile.BindExperimentalRecipe(uuid.NewString(), evidence)
	if !ok {
		t.Fatal("retained Knowledge fixture did not bind")
	}
	return value
}

type managedKnowledgeRecipeReaderFake struct{ value recipe.RecipeV1 }

func (fake managedKnowledgeRecipeReaderFake) ResolveRecipe(context.Context, string, string, string) (recipe.RecipeV1, error) {
	return fake.value, nil
}

type managedKnowledgeConfigFake struct {
	stored          *knowledge.Config
	scope           knowledge.MutationScope
	command         knowledge.PutConfigCommand
	putCalls        int
	losePutResponse bool
}

func (fake *managedKnowledgeConfigFake) GetConfig(context.Context, string, string) (knowledge.Config, error) {
	if fake.stored == nil {
		return knowledge.Config{}, knowledge.ErrNotFound
	}
	return *fake.stored, nil
}

func (fake *managedKnowledgeConfigFake) PutConfig(_ context.Context, scope knowledge.MutationScope, command knowledge.PutConfigCommand) (knowledge.Config, error) {
	fake.scope, fake.command, fake.putCalls = scope, command, fake.putCalls+1
	if fake.stored != nil {
		if fake.stored.OwnerID == command.OwnerID && fake.stored.BindingID == command.BindingID && fake.stored.Spec.SameIdentity(command.Spec) && fake.stored.Spec.Enabled {
			return *fake.stored, nil
		}
		return knowledge.Config{}, knowledge.ErrConflict
	}
	value := knowledge.Config{OwnerID: command.OwnerID, BindingID: command.BindingID, Spec: command.Spec, Revision: 1}
	fake.stored = &value
	if fake.losePutResponse {
		fake.losePutResponse = false
		return knowledge.Config{}, errors.New("simulated lost config response")
	}
	return value, nil
}
