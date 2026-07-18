package app

import (
	"context"
	"errors"

	cloudmanaged "github.com/YingSuiAI/dirextalk-agent/internal/cloud/managed"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledge"
	"github.com/YingSuiAI/dirextalk-agent/internal/knowledgeprofile"
	"github.com/YingSuiAI/dirextalk-agent/internal/planning"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/google/uuid"
)

const managedKnowledgeBindingClientID = "internal.managed-knowledge-binding"

type managedKnowledgeRecipeReader interface {
	ResolveRecipe(context.Context, string, string, string) (recipe.RecipeV1, error)
}

type managedKnowledgeConfigCoordinator interface {
	GetConfig(context.Context, string, string) (knowledge.Config, error)
	PutConfig(context.Context, knowledge.MutationScope, knowledge.PutConfigCommand) (knowledge.Config, error)
}

type managedKnowledgeBinder struct {
	recipes    managedKnowledgeRecipeReader
	configs    managedKnowledgeConfigCoordinator
	credential string
}

func newManagedKnowledgeBinder(agentInstanceID string, recipes managedKnowledgeRecipeReader, configs managedKnowledgeConfigCoordinator) (*managedKnowledgeBinder, error) {
	parsed, err := uuid.Parse(agentInstanceID)
	if err != nil || parsed == uuid.Nil || parsed.String() != agentInstanceID || recipes == nil || configs == nil {
		return nil, cloudmanaged.ErrInvalid
	}
	return &managedKnowledgeBinder{
		recipes: recipes, configs: configs,
		credential: uuid.NewSHA1(parsed, []byte("dirextalk.agent/managed-knowledge-binding/v1")).String(),
	}, nil
}

func (binder *managedKnowledgeBinder) EnsureManagedKnowledgeBinding(ctx context.Context, scope cloudmanaged.ScopeV1, managedServiceID string) error {
	if binder == nil || ctx == nil || scope.OwnerID == "" || scope.RecipeID == "" || scope.RecipeDigest == "" ||
		!canonicalManagedKnowledgeUUID(scope.AcceptanceID) || !canonicalManagedKnowledgeUUID(scope.DeploymentID) ||
		!canonicalManagedKnowledgeUUID(scope.ServiceID) || managedServiceID != scope.ServiceID {
		return cloudmanaged.ErrInvalid
	}
	value, err := binder.recipes.ResolveRecipe(ctx, scope.OwnerID, scope.RecipeID, scope.RecipeDigest)
	if err != nil {
		if errors.Is(err, planning.ErrInvalid) || errors.Is(err, planning.ErrNotFound) || errors.Is(err, planning.ErrScopeMismatch) {
			return cloudmanaged.ErrRevisionConflict
		}
		return err
	}
	computed, digestErr := value.Digest()
	if digestErr != nil || value.RecipeID != scope.RecipeID || computed != scope.RecipeDigest {
		return cloudmanaged.ErrRevisionConflict
	}
	profileID, retained := knowledgeprofile.RetainedRecipeProfile(value)
	if !retained {
		return nil
	}
	command := knowledge.PutConfigCommand{
		IdempotencyKey: uuid.NewSHA1(uuid.MustParse(scope.AcceptanceID), []byte("dirextalk.agent/managed-knowledge-binding/v1")).String(),
		OwnerID:        scope.OwnerID, BindingID: managedServiceID, ExpectedRevision: 0,
		Spec: knowledge.ConfigSpec{
			DeploymentID: scope.DeploymentID, ManagedServiceID: managedServiceID, RecipeDigest: scope.RecipeDigest,
			EmbeddingProfileID: profileID, Enabled: true,
		},
	}
	mutation := knowledge.MutationScope{ClientID: managedKnowledgeBindingClientID, CredentialID: binder.credential}
	config, putErr := binder.configs.PutConfig(ctx, mutation, command)
	if putErr == nil && exactManagedKnowledgeConfig(config, command) {
		return nil
	}
	stored, readErr := binder.configs.GetConfig(ctx, command.OwnerID, command.BindingID)
	if readErr == nil && exactManagedKnowledgeConfig(stored, command) {
		return nil
	}
	if putErr == nil || errors.Is(putErr, knowledge.ErrInvalid) || errors.Is(putErr, knowledge.ErrNotFound) ||
		errors.Is(putErr, knowledge.ErrRevision) || errors.Is(putErr, knowledge.ErrConflict) ||
		errors.Is(putErr, knowledge.ErrImmutableConfig) ||
		errors.Is(readErr, knowledge.ErrInvalid) || errors.Is(readErr, knowledge.ErrRevision) ||
		(readErr == nil && !exactManagedKnowledgeConfig(stored, command)) {
		return cloudmanaged.ErrRevisionConflict
	}
	if putErr != nil {
		return putErr
	}
	return readErr
}

func exactManagedKnowledgeConfig(config knowledge.Config, command knowledge.PutConfigCommand) bool {
	return config.OwnerID == command.OwnerID && config.BindingID == command.BindingID && config.Revision == 1 &&
		config.Spec.SameIdentity(command.Spec) && config.Spec.Enabled
}

func canonicalManagedKnowledgeUUID(value string) bool {
	parsed, err := uuid.Parse(value)
	return err == nil && parsed != uuid.Nil && parsed.String() == value
}
