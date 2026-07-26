package workerprofile

import (
	"strings"
	"testing"
	"time"
)

func TestDiagnosticProfileIsExplicitMinimalAndExecutable(t *testing.T) {
	t.Parallel()
	recipeID := RecipeIDPrefix + strings.Repeat("a", 32)
	if !IsDiagnosticRecipeID(recipeID) || IsDiagnosticRecipeID("generic-recipe") {
		t.Fatal("diagnostic Recipe selector is not explicit")
	}
	value, matched := BindExperimentalRecipe(recipeID, []Evidence{{
		URL: SourceURL, RetrievedAt: time.Date(2026, 7, 26, 1, 0, 0, 0, time.UTC),
		ContentDigest: "sha256:" + strings.Repeat("b", 64),
	}})
	if !matched || value.Validate() != nil {
		t.Fatalf("diagnostic Recipe did not bind: matched=%v err=%v", matched, value.Validate())
	}
	if len(value.Sources) != 1 || len(value.Install.Steps) != 1 ||
		value.Install.Steps[0].Action != "worker.noop" || value.Install.Installer != nil ||
		len(value.SecretSlots) != 0 || len(value.VolumeSlots) != 0 || len(value.DataSlots) != 0 ||
		value.Network != nil || value.Restart != nil || value.Pairing != nil ||
		len(value.Integrations) != 0 || value.ManagedAcceptance != nil {
		t.Fatalf("diagnostic Recipe widened its capability: %#v", value)
	}
	candidates, ok := ResourceCandidates(value)
	if !ok || len(candidates) != 3 || candidates[0].VCPU != 1 ||
		candidates[0].MemoryMiB != 1024 || candidates[0].DiskGiB != 8 {
		t.Fatalf("diagnostic candidates = %#v, %v", candidates, ok)
	}
}

func TestDiagnosticProfileRejectsGenericIdentityAndEvidenceDrift(t *testing.T) {
	t.Parallel()
	evidence := []Evidence{{
		URL: SourceURL, RetrievedAt: time.Now().UTC(),
		ContentDigest: "sha256:" + strings.Repeat("c", 64),
	}}
	if _, matched := BindExperimentalRecipe("generic-recipe", evidence); matched {
		t.Fatal("generic Recipe activated diagnostic profile")
	}
	evidence[0].URL = "https://example.com/other"
	if _, matched := BindExperimentalRecipe(RecipeIDPrefix+strings.Repeat("d", 32), evidence); matched {
		t.Fatal("drifted diagnostic evidence was accepted")
	}
}
