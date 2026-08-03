package workermarket

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestSignRegistryPayloadJSONProducesVerifiableCanonicalDocument(
	t *testing.T,
) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := validRegistryPayload(t, publicKey)
	payload.SignerKeyID = SignerKeyID(publicKey)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignRegistryPayloadJSON(raw, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := ParseRegistryJSON(signed, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	if registry.RegistryID() != payload.RegistryID ||
		registry.ValidateAt(payload.GeneratedAt) != nil {
		t.Fatalf("signed registry=%#v", registry)
	}
}

func TestSignRegistryPayloadJSONRejectsUntrustedInput(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload := validRegistryPayload(t, publicKey)
	payload.SignerKeyID = SignerKeyID(publicKey)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func() ([]byte, ed25519.PrivateKey){
		"unknown field": func() ([]byte, ed25519.PrivateKey) {
			input := append([]byte(nil), raw[:len(raw)-1]...)
			return append(input, []byte(`,"unexpected":true}`)...), privateKey
		},
		"wrong key": func() ([]byte, ed25519.PrivateKey) {
			_, other, keyErr := ed25519.GenerateKey(rand.Reader)
			if keyErr != nil {
				t.Fatal(keyErr)
			}
			return raw, other
		},
		"trailing data": func() ([]byte, ed25519.PrivateKey) {
			return append(append([]byte(nil), raw...), []byte(`{}`)...), privateKey
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			input, key := build()
			if _, signErr := SignRegistryPayloadJSON(input, key); signErr == nil {
				t.Fatal("untrusted registry payload was signed")
			}
		})
	}
}
