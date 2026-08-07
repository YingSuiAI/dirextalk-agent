package execgate

import (
	"bytes"
	"testing"
)

func TestProtocolIsCanonicalAndClosed(t *testing.T) {
	request := wireRequest{Schema: ProtocolSchemaV1, Operation: operationPing}
	raw, err := encodeCanonical(request)
	if err != nil {
		t.Fatal(err)
	}
	var decoded wireRequest
	if err := decodeCanonical(raw, &decoded); err != nil || decoded != request {
		t.Fatalf("canonical request failed: decoded=%+v err=%v", decoded, err)
	}
	for name, invalid := range map[string][]byte{
		"whitespace": append(append([]byte(nil), raw...), '\n'),
		"unknown":    []byte(`{"schema":"dirextalk.agent.pi-exec-gate/v1","operation":"ping","extra":true}`),
		"duplicate":  []byte(`{"schema":"dirextalk.agent.pi-exec-gate/v1","schema":"dirextalk.agent.pi-exec-gate/v1","operation":"ping"}`),
	} {
		t.Run(name, func(t *testing.T) {
			var target wireRequest
			if err := decodeCanonical(invalid, &target); err == nil {
				t.Fatalf("noncanonical request accepted: %s", bytes.TrimSpace(invalid))
			}
		})
	}
}
