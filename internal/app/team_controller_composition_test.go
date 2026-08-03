package app

import "testing"

func TestNormalizeGitHubSourceSnapshotterKeepsDisabledSourceNil(
	t *testing.T,
) {
	t.Parallel()
	if normalized := normalizeGitHubSourceSnapshotter(nil); normalized != nil {
		t.Fatalf("disabled GitHub source became non-nil: %T", normalized)
	}
}
