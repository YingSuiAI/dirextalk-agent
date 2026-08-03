package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestDecodePrivateKeyAcceptsCanonicalSeedAndExpandedKey(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"seed":     privateKey.Seed(),
		"expanded": privateKey,
	} {
		t.Run(name, func(t *testing.T) {
			encoded := []byte(base64.RawURLEncoding.EncodeToString(raw))
			decoded, decodeErr := decodePrivateKey(encoded)
			if decodeErr != nil || !decoded.Equal(privateKey) {
				t.Fatalf("decoded key did not match: %v", decodeErr)
			}
			clear(decoded)
		})
	}
}

func TestDecodePrivateKeyRejectsNonCanonicalOrWrongLength(t *testing.T) {
	for name, encoded := range map[string][]byte{
		"padding":      []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
		"wrong length": []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 31))),
	} {
		t.Run(name, func(t *testing.T) {
			if decoded, err := decodePrivateKey(encoded); err == nil {
				clear(decoded)
				t.Fatal("invalid private key was accepted")
			}
		})
	}
}
