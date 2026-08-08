package migrations

import (
	"strings"
	"testing"
)

func TestImageToolMigrationOwnsEphemeralBytesAndReplay(t *testing.T) {
	raw, err := Files.ReadFile("000006_image_tools_v1.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, want := range []string{"CREATE TABLE core_image_tool_uploads", "image_request_id uuid NOT NULL", "mime_type IN ('image/jpeg','image/png','image/webp')", "declared_size BETWEEN 1 AND 8388608", "content_bytes bytea", "status IN ('receiving','committed','consumed')", "CREATE TABLE core_image_tool_replays", "ON DELETE CASCADE"} {
		if !strings.Contains(s, want) {
			t.Fatalf("migration missing %q", want)
		}
	}
}
