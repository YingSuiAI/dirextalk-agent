package taskinput

import (
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestEmptySnapshotBindsOwnerTaskGoalAndWorkspace(t *testing.T) {
	taskID := uuid.NewString()
	goalDigest := "sha256:" + strings.Repeat("a", 64)
	snapshot, err := NewEmpty("owner-a", taskID, goalDigest)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := snapshot.Binding()
	if err != nil {
		t.Fatal(err)
	}
	content, digest := EmptyWorkspace()
	if snapshot.TaskID != taskID ||
		snapshot.GoalDigest != goalDigest ||
		snapshot.WorkspaceDigest != digest ||
		snapshot.WorkspaceSizeBytes != int64(len(content)) ||
		!binding.Matches(snapshot) ||
		!IsEmpty(binding) {
		t.Fatalf("snapshot=%#v binding=%#v", snapshot, binding)
	}

	changed := snapshot
	changed.OwnerID = "owner-b"
	changedBinding, err := changed.Binding()
	if err != nil {
		t.Fatal(err)
	}
	if changedBinding.SnapshotDigest == binding.SnapshotDigest {
		t.Fatal("owner drift did not change snapshot digest")
	}
	changed = snapshot
	changed.GoalDigest = "sha256:" + strings.Repeat("b", 64)
	changedBinding, err = changed.Binding()
	if err != nil {
		t.Fatal(err)
	}
	if changedBinding.SnapshotDigest == binding.SnapshotDigest {
		t.Fatal("goal drift did not change snapshot digest")
	}
}

func TestSnapshotRejectsRebindingOrInvalidWorkspace(t *testing.T) {
	snapshot, err := NewEmpty(
		"owner-a",
		uuid.NewString(),
		"sha256:"+strings.Repeat("c", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []func(*SnapshotV1){
		func(value *SnapshotV1) { value.SnapshotID = uuid.NewString() },
		func(value *SnapshotV1) { value.WorkspaceDigest = "sha256:bad" },
		func(value *SnapshotV1) { value.WorkspaceSizeBytes = 0 },
		func(value *SnapshotV1) { value.WorkspaceMediaType = "application/zip" },
	}
	for index, mutate := range tests {
		value := snapshot
		mutate(&value)
		if value.Validate() == nil {
			t.Fatalf("mutation %d accepted", index)
		}
	}
}
