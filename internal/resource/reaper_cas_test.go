package resource

import (
	"context"
	"errors"
	"testing"
	"time"
)

type conflictingManifestMirror struct{ *fakeMirror }

func (mirror *conflictingManifestMirror) PutIfRevision(context.Context, Manifest, int64) error {
	return ErrRevisionConflict
}

func TestReaperFencesConcurrentManifestTransitionBeforeDelete(t *testing.T) {
	fixture := newResourceFixture(t)
	created, err := fixture.service.Provision(context.Background(), fixture.spec(TypeEC2, "fenced-worker"), fixture.createAuthorization())
	if err != nil {
		t.Fatal(err)
	}
	manifest := fixture.mirror.manifests[fixture.deploymentID]
	manifest.DestroyDeadline = fixture.now.Add(-time.Minute)
	manifest.Resources[0].DestroyDeadline = manifest.DestroyDeadline
	manifest.Resources[0].Tags[TagDestroyDeadline] = manifest.DestroyDeadline.Format(time.RFC3339)
	fixture.mirror.manifests[fixture.deploymentID] = manifest

	reaper, err := NewReaper(fixture.provider, &conflictingManifestMirror{fakeMirror: fixture.mirror})
	if err != nil {
		t.Fatal(err)
	}
	reaper.now = func() time.Time { return fixture.now }
	_, err = reaper.Sweep(context.Background())
	if !errors.Is(err, ErrRevisionConflict) {
		t.Fatalf("Sweep error = %v, want revision conflict", err)
	}
	if len(fixture.provider.deleteOrder) != 0 || !fixture.provider.resources[created.ProviderID].Exists {
		t.Fatalf("reaper deleted after losing manifest CAS: order=%v observation=%+v", fixture.provider.deleteOrder, fixture.provider.resources[created.ProviderID])
	}
}
