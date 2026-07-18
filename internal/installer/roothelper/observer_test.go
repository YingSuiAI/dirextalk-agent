package roothelper

import (
	"context"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

func TestLocalObserverVerifiesEveryArtifactAndRejectsUndeclaredCommand(t *testing.T) {
	fixture := newFixture(t)
	inspector := &observerInspector{}
	observer := LocalObserver{Artifacts: inspector, Now: func() time.Time {
		return time.Date(2026, 7, 17, 8, 0, 0, 0, time.UTC)
	}}
	digest, err := observer.InstalledManifestDigest(context.Background(), fixture.delivery)
	if err != nil || digest == "" || inspector.calls != len(fixture.delivery.ArtifactManifest.Manifest.Artifacts) {
		t.Fatalf("digest=%q calls=%d err=%v", digest, inspector.calls, err)
	}
	command := fixture.delivery.SignedPlan.Plan.Commands[0]
	if digest, err := observer.RestartObservationDigest(context.Background(), fixture.delivery, command); err != nil || digest == "" {
		t.Fatalf("restart observation digest=%q err=%v", digest, err)
	}
	command.CommandID = "undeclared"
	if _, err := observer.RestartObservationDigest(context.Background(), fixture.delivery, command); err != ErrUnauthorized {
		t.Fatalf("undeclared command err=%v", err)
	}
}

func TestLocalObserverRequiresSecretAndVolumeReadBackBeforeFullManifestDigest(t *testing.T) {
	fixture := newFixture(t)
	plan := fixture.delivery.SignedPlan.Plan
	plan.SecretRefs = []string{"secret_ref:deployment/model-token"}
	plan.Secrets = []installer.SecretV1{{
		SlotID: "model-token", SecretRef: "secret_ref:deployment/model-token",
		SecretName: "dtx/" + plan.Binding.AgentInstanceID + "/deployments/" + plan.Binding.DeploymentID + "/model-token",
		VersionID:  "88888888-8888-4888-8888-888888888888",
		TargetPath: installer.PreinstalledSecretRoot + "/model-token", FileMode: 0o400,
	}}
	plan.Volumes = []installer.VolumeV1{{
		Name: "knowledge", DeviceName: "/dev/sdf", MountPath: "/srv/knowledge",
		Persistent: true, Disposition: "retain_with_managed_service", SizeGiB: 40,
	}}
	delivery, err := fixture.issuer.Issue(plan, fixture.delivery.Config, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	observer := LocalObserver{Artifacts: &observerInspector{}, Now: func() time.Time { return fixture.now }}
	if _, err := observer.InstalledManifestDigest(context.Background(), delivery); err != ErrUnavailable {
		t.Fatalf("full manifest without state inspector err=%v", err)
	}
	state := &observerStateInspector{}
	observer.State = state
	if digest, err := observer.InstalledManifestDigest(context.Background(), delivery); err != nil || digest == "" ||
		state.secrets != 1 || state.volumes != 1 {
		t.Fatalf("digest=%q secrets=%d volumes=%d err=%v", digest, state.secrets, state.volumes, err)
	}
}

func TestLocalObserverBindsKnowledgeLifecycleReceiptToExactDataGeneration(t *testing.T) {
	fixture := newFixture(t)
	plan := fixture.delivery.SignedPlan.Plan
	plan.Commands[0].CommandID = "knowledge-backup-v1"
	delivery, err := fixture.issuer.Issue(plan, fixture.delivery.Config, fixture.now)
	if err != nil {
		t.Fatal(err)
	}
	generation := &observerGenerationInspector{digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	observer := LocalObserver{
		Artifacts: &observerInspector{}, KnowledgeGeneration: generation,
		Now: func() time.Time { return fixture.now },
	}
	digest, err := observer.RestartObservationDigest(context.Background(), delivery, plan.Commands[0])
	if err != nil || digest != generation.digest || generation.calls != 1 {
		t.Fatalf("generation digest=%q calls=%d error=%v", digest, generation.calls, err)
	}
	observer.KnowledgeGeneration = nil
	if _, err := observer.RestartObservationDigest(context.Background(), delivery, plan.Commands[0]); err != ErrUnavailable {
		t.Fatalf("missing generation observer error=%v", err)
	}
}

type observerInspector struct{ calls int }

func (inspector *observerInspector) Verify(context.Context, installer.ArtifactV1) error {
	inspector.calls++
	return nil
}

type observerStateInspector struct {
	secrets int
	volumes int
}

func (inspector *observerStateInspector) VerifySecret(context.Context, installer.SecretV1) error {
	inspector.secrets++
	return nil
}

func (inspector *observerStateInspector) VerifyVolume(context.Context, installer.VolumeV1) error {
	inspector.volumes++
	return nil
}

type observerGenerationInspector struct {
	digest string
	calls  int
}

func (inspector *observerGenerationInspector) CurrentGeneration(context.Context) (string, error) {
	inspector.calls++
	return inspector.digest, nil
}
