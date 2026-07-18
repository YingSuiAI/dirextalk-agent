package knowledgeprofile

import (
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
)

func TestRetainedKnowledgeRecipeBindsSmallResearchManifestToExactArtifacts(t *testing.T) {
	t.Parallel()
	hints := ResearchHints()
	if len(hints) != 5 {
		t.Fatalf("research hint count = %d", len(hints))
	}
	retrieved := time.Date(2026, 7, 19, 1, 2, 3, 0, time.UTC)
	evidence := make([]Evidence, 0, len(hints))
	for _, hint := range hints {
		if hint.ResearchURL == hint.ArtifactURL || !strings.HasPrefix(hint.ResearchURL, ManifestURL()+"?artifact=") || strings.Contains(hint.ArtifactURL, "?") {
			t.Fatalf("research/artifact URL separation failed: %#v", hint)
		}
		evidence = append(evidence, Evidence{URL: hint.ResearchURL, RetrievedAt: retrieved, ContentDigest: "sha256:" + ManifestSHA256})
	}
	value, matched := BindExperimentalRecipe("knowledge-recipe-1", evidence)
	if !matched || value.Validate() != nil {
		t.Fatalf("retained Recipe did not bind: matched=%v err=%v", matched, value.Validate())
	}
	if value.Install.Installer == nil || len(value.Install.Installer.Artifacts) != 5 || len(value.Install.Installer.Commands) != 9 || len(value.Install.Steps) != 2 {
		t.Fatalf("installer contract = %#v", value.Install)
	}
	if value.VolumeSlots[0].MountPath != "/var/lib/dirextalk-knowledge" || !value.VolumeSlots[0].Persistent || !value.VolumeSlots[0].EncryptionRequired {
		t.Fatal("persistent encrypted Knowledge volume is not exact")
	}
	if value.SecretSlots[0].TargetPath != "/etc/dirextalk-service-secrets/qdrant-api-key" || value.SecretSlots[0].FileMode != 0o400 {
		t.Fatal("Qdrant API-key SecretSlot is not exact")
	}
	for _, artifact := range value.Install.Installer.Artifacts {
		if !strings.HasPrefix(artifact.TargetPath, installer.PreinstalledArtifactRoot+"/") {
			t.Fatalf("artifact escaped signed bootstrap root: %s", artifact.TargetPath)
		}
	}
	if value.Install.Steps[1].Action != installer.ActionExecute || value.Install.Steps[1].Inputs[0].Ref != SemanticProbeCommandID ||
		value.Health.Semantic.Kind != recipe.ProbeAction || value.Lifecycle.Restart != RestartCommandID ||
		value.Lifecycle.Stop != StopCommandID || value.Lifecycle.Maintenance != StopCommandID || value.Lifecycle.Backup != BackupCommandID ||
		value.Lifecycle.Restore != RestoreCommandID || value.Lifecycle.Upgrade != UpgradeCommandID || value.Lifecycle.Rollback != RollbackCommandID ||
		value.Lifecycle.Destroy != DestroyCommandID {
		t.Fatal("restart or semantic acceptance command is not bound")
	}
}

func TestRetainedKnowledgeRecipeRejectsUnfetchedOrDriftedManifest(t *testing.T) {
	t.Parallel()
	hints := ResearchHints()
	evidence := make([]Evidence, 0, len(hints))
	for _, hint := range hints {
		evidence = append(evidence, Evidence{URL: hint.ResearchURL, RetrievedAt: time.Now().UTC(), ContentDigest: "sha256:" + ManifestSHA256})
	}
	evidence[0].ContentDigest = "sha256:" + strings.Repeat("0", 64)
	if _, matched := BindExperimentalRecipe("knowledge-recipe-1", evidence); matched {
		t.Fatal("drifted research manifest was accepted")
	}
}

func TestRetainedRecipeProfileRecognizesOnlyTheExactServerOwnedRecipe(t *testing.T) {
	t.Parallel()
	hints := ResearchHints()
	evidence := make([]Evidence, 0, len(hints))
	for _, hint := range hints {
		evidence = append(evidence, Evidence{
			URL: hint.ResearchURL, RetrievedAt: time.Date(2026, 7, 19, 3, 0, 0, 0, time.UTC),
			ContentDigest: "sha256:" + ManifestSHA256,
		})
	}
	value, matched := BindExperimentalRecipe("knowledge-recipe-1", evidence)
	if !matched {
		t.Fatal("fixed Knowledge evidence did not bind")
	}
	if profile, ok := RetainedRecipeProfile(value); !ok || profile != EmbeddingProfileID {
		t.Fatalf("exact retained Recipe profile = %q, %v", profile, ok)
	}
	value.Lifecycle.Destroy = "other-destroy"
	if _, ok := RetainedRecipeProfile(value); ok {
		t.Fatal("drifted Recipe was recognized as the retained profile")
	}
}
