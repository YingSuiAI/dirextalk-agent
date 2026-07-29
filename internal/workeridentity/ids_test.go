package workeridentity

import (
	"testing"

	"github.com/google/uuid"
)

func TestDeriveWorkerIDIsStableAndDeploymentScoped(t *testing.T) {
	t.Parallel()
	firstDeployment := uuid.NewString()
	first, err := DeriveWorkerID(firstDeployment)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := DeriveWorkerID(firstDeployment)
	if err != nil || replayed != first {
		t.Fatalf("replayed Worker ID=%q error=%v, want %q", replayed, err, first)
	}
	second, err := DeriveWorkerID(uuid.NewString())
	if err != nil || second == first {
		t.Fatalf("second Worker ID=%q error=%v", second, err)
	}
	if _, err := DeriveWorkerID("not-a-deployment"); err == nil {
		t.Fatal("invalid deployment identity was accepted")
	}
}
