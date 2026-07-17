package managed

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestCompatibilityServiceRequiresExactBackupAndRestoreFacts(t *testing.T) {
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	scope := testScope(uuid.NewString(), uuid.NewString(), uuid.NewString(), now)
	service := compatibilityServiceFixture(scope, now.Add(-time.Hour).UnixMilli(), now.UnixMilli())
	if err := service.Validate(scope); err != nil {
		t.Fatalf("valid service: %v", err)
	}
	withoutSnapshotResource := scope
	withoutSnapshotResource.Resources = append([]ResourceV1(nil), scope.Resources[:len(scope.Resources)-1]...)
	if err := service.Validate(withoutSnapshotResource); err != ErrInvalid {
		t.Fatalf("unsigned snapshot compatibility error=%v", err)
	}

	tests := []struct {
		name   string
		mutate func(*CompatibilityServiceV1)
	}{
		{"missing backup", func(value *CompatibilityServiceV1) { value.Backups = nil }},
		{"wrong backup revision", func(value *CompatibilityServiceV1) { value.Backups[0].Revision++ }},
		{"unsorted snapshots", func(value *CompatibilityServiceV1) {
			value.Backups[0].SnapshotIDs = []string{"snap-1123456789abcdef0", "snap-0123456789abcdef0"}
		}},
		{"missing restore", func(value *CompatibilityServiceV1) { value.Restores = nil }},
		{"wrong restore backup", func(value *CompatibilityServiceV1) { value.Restores[0].BackupID = uuid.NewString() }},
		{"mismatched volume pairs", func(value *CompatibilityServiceV1) {
			value.Restores[0].ReplacementVolumeIDs = append(value.Restores[0].ReplacementVolumeIDs, "vol-2123456789abcdef0")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := service
			value.Backups = append([]CompatibilityBackupV1(nil), service.Backups...)
			value.Restores = append([]CompatibilityRestoreV1(nil), service.Restores...)
			test.mutate(&value)
			if err := value.Validate(scope); err != ErrInvalid {
				t.Fatalf("error=%v", err)
			}
		})
	}
}
