package canonical

import (
	"encoding/hex"
	"testing"
)

func TestMarshalRFC8949DeterministicMapOrder(t *testing.T) {
	got, err := Marshal(map[string]any{"aa": uint64(1), "b": uint64(2)})
	if err != nil {
		t.Fatal(err)
	}
	const want = "a261620262616101"
	if encoded := hex.EncodeToString(got); encoded != want {
		t.Fatalf("Marshal() = %s, want RFC 8949 vector %s", encoded, want)
	}
}

func TestMarshalRejectsFloatingPointContracts(t *testing.T) {
	if _, err := Marshal(struct {
		Value float64 `json:"value"`
	}{Value: 1}); err == nil {
		t.Fatal("Marshal() accepted a floating-point contract")
	}
}

func TestMarshalRejectsJSONCoercionOfNonStringMapKeys(t *testing.T) {
	if _, err := Marshal(map[int]string{1: "coerced"}); err == nil {
		t.Fatal("Marshal() accepted a non-string map key that JSON would coerce")
	}
}

func TestDigestUsesNamedLowercaseSHA256(t *testing.T) {
	got, err := Digest(map[string]any{"a": uint64(1), "b": "x"})
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:1cbbcca5a712624fb98575c455763651a013627c0845e4f4ce2c53a23f39ca16"
	if got != want {
		t.Fatalf("Digest() = %q, want %q", got, want)
	}
}
