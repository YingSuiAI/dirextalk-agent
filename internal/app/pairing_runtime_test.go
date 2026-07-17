package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"github.com/YingSuiAI/dirextalk-agent/internal/pairing"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/google/uuid"
)

func TestPairingRuntimeBindsApprovedPlanRecipeAndWorkerStep(t *testing.T) {
	fixture := newManagedPreparationScopeFixture(t)
	beginID, resumeID := "pairing-begin", "pairing-resume"
	fixture.facts.draft.Recipe.Pairing = &recipe.PairingContractV1{
		BeginAction: "begin", ResumeAction: "resume", PayloadDelivery: "on_demand_encrypted",
		TimeoutSeconds: 300, BeginCommandID: beginID, ResumeCommandID: resumeID,
	}
	root := "/usr/local/share/dirextalk-worker/artifacts"
	fixture.facts.draft.Recipe.Install.Installer = &recipe.InstallerCapabilityV1{
		Artifacts: []recipe.InstallerArtifactV1{{Name: "service-installer", SourceID: "primary", SizeBytes: 1024, TargetPath: root + "/service-installer"}},
		Commands: []recipe.InstallerCommandV1{
			{CommandID: beginID, Argv: []string{root + "/service-installer", "pairing-begin"}, WorkingDirectory: root, TimeoutSeconds: 60, ArtifactRefs: []string{"service-installer"}},
			{CommandID: resumeID, Argv: []string{root + "/service-installer", "pairing-resume"}, WorkingDirectory: root, TimeoutSeconds: 60, ArtifactRefs: []string{"service-installer"}},
		},
	}
	digest, err := fixture.facts.draft.Recipe.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.facts.draft.Digest = digest
	fixture.facts.plan.Recipe.Digest = digest
	fixture.facts.plan.Quote.ScopeDigest, err = fixture.facts.plan.PricingScopeDigest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.facts.quote = managedPreparationQuote(t, fixture.facts.plan.Quote.ValidUntil.Add(-15*time.Minute), fixture.facts.plan.Quote.QuoteID, fixture.facts.plan)
	fixture.facts.plan.Quote.Digest, err = fixture.facts.quote.Digest()
	if err != nil {
		t.Fatal(err)
	}
	fixture.current.deployment.Worker.StepID = uuid.NewString()
	fixture.current.deployment.Worker.InstallerDelivery.SignedPlan.Plan.Commands = append(
		fixture.current.deployment.Worker.InstallerDelivery.SignedPlan.Plan.Commands,
		installer.CommandV1{CommandID: beginID}, installer.CommandV1{CommandID: resumeID},
	)
	if err := fixture.facts.draft.Recipe.Validate(); err != nil {
		t.Fatalf("pairing recipe invalid: %v", err)
	}
	if err := fixture.facts.plan.Validate(); err != nil {
		t.Fatalf("pairing plan invalid: %v", err)
	}
	runtime := &pairingRuntime{agentInstanceID: fixture.agentID, facts: fixture.facts, current: fixture.current}
	deployment, draft, manifestDigest, err := runtime.currentFacts(context.Background(), fixture.ownerID, fixture.deploymentID)
	if err != nil || deployment.Worker.StepID == "" || draft.Digest != digest || manifestDigest == "" {
		t.Fatalf("facts deployment=%#v draft=%#v manifest=%q err=%v", deployment, draft, manifestDigest, err)
	}
	sessionNow := time.Date(2026, time.July, 17, 16, 0, 0, 0, time.UTC)
	session := pairing.SessionV1{SchemaVersion: pairing.SchemaV1, SessionID: uuid.NewString(), OwnerID: fixture.ownerID,
		DeploymentID: fixture.deploymentID, DeploymentRevision: deployment.Worker.Revision, PlanID: deployment.PlanID, ConnectionID: deployment.ConnectionID,
		TaskID: deployment.Worker.TaskID, StepID: deployment.Worker.StepID, RecipeID: draft.RecipeID, RecipeDigest: draft.Digest,
		RecipeRevision: draft.Revision, ExecutionManifestDigest: manifestDigest, BeginCommand: beginID, ResumeCommand: resumeID,
		Status: pairing.StatusWaitingPayload, ExpiresAt: sessionNow.Add(time.Hour), Revision: 1, CreatedAt: sessionNow, UpdatedAt: sessionNow}
	if err := runtime.validateCurrentSession(context.Background(), session); err != nil {
		t.Fatalf("current session validation error=%v", err)
	}
	fixture.current.deployment.Worker.Revision++
	if err := runtime.validateCurrentSession(context.Background(), session); !errors.Is(err, pairing.ErrRevisionConflict) {
		t.Fatalf("deployment revision drift error=%v", err)
	}
	fixture.current.deployment.Worker.Revision--

	fixture.facts.plan.Recipe.Digest = managedPreparationDigest('9')
	if _, _, _, err := runtime.currentFacts(context.Background(), fixture.ownerID, fixture.deploymentID); !errors.Is(err, pairing.ErrRevisionConflict) {
		t.Fatalf("recipe drift error=%v", err)
	}
}

func TestPairingDeviceAdapterPreservesValidityWindow(t *testing.T) {
	now := time.Date(2026, time.July, 17, 18, 0, 0, 0, time.UTC)
	key := pairing.DeviceKeyV1{KeyID: "key-a", AgentInstanceID: uuid.NewString(), OwnerID: "owner-a",
		PublicKey: make([]byte, 32), Active: true, NotBefore: now.Add(time.Second), ExpiresAt: now.Add(time.Hour)}
	if key.ValidAt(now) || !key.ValidAt(now.Add(time.Minute)) {
		t.Fatal("pairing device validity window is not enforced")
	}
}
