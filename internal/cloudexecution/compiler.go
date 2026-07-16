package cloudexecution

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
)

func compileBundles(value recipe.RecipeV1) ([]byte, []byte, error) {
	if err := value.Validate(); err != nil {
		return nil, nil, ErrInvalid
	}
	recipeBytes, err := value.CanonicalCBOR()
	if err != nil {
		return nil, nil, ErrInvalid
	}
	recipeDigest := sha256.Sum256(recipeBytes)
	actions := make([]workerrunner.ActionV1, 0, len(value.Install.Steps))
	for _, step := range value.Install.Steps {
		// The first validation Worker intentionally supports only the harmless
		// typed no-op. OCI, package, model, and service actions are added to the
		// registry as typed unions; unknown recipe actions never fall back to a
		// shell or command string.
		if strings.TrimSpace(step.Action) != (workerrunner.NoopAction{}).Kind() || len(step.Inputs) != 0 {
			return nil, nil, ErrUnsupportedRecipe
		}
		actions = append(actions, workerrunner.ActionV1{
			ID: step.ID, Kind: step.Action, TimeoutSeconds: step.TimeoutSeconds,
			Noop: &workerrunner.NoopInputV1{},
		})
	}
	encoded, err := json.Marshal(workerrunner.ExecutionBundleV1{
		SchemaVersion: 1, RecipeSHA256: hex.EncodeToString(recipeDigest[:]), Actions: actions,
	})
	if err != nil {
		return nil, nil, ErrInvalid
	}
	return recipeBytes, encoded, nil
}
