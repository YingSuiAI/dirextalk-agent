package migrations

import (
	"strings"
	"testing"
)

func TestPairingPayloadReservationMigrationStoresOnlyRecipientDigest(t *testing.T) {
	raw, err := Files.ReadFile("000038_pairing_payload_reservations.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	script := strings.ToLower(string(raw))
	for _, required := range []string{
		"create table pairing_payload_reservations",
		"recipient_key_digest text not null",
		"payload_scope_revision bigint not null",
		"operation_id uuid not null",
		"foreign key (agent_instance_id, owner_id, session_id)",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("reservation migration missing %q", required)
		}
	}
	for _, forbidden := range []string{"recipient_public_key", "private_key", "plaintext", "password"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("reservation migration persists forbidden material %q", forbidden)
		}
	}
}
