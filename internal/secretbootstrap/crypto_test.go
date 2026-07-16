package secretbootstrap

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestEnvelopeRoundTripAndContextAAD(t *testing.T) {
	serverKeyBytes := sequence(1, 32)
	serverKey, err := ecdh.X25519().NewPrivateKey(serverKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	session := SessionV1{
		SchemaVersion:   SessionSchemaV1,
		SessionID:       "018f6f16-2f90-7c21-8b00-000000000001",
		AgentInstanceID: "agent-instance-1",
		OwnerID:         "owner-1",
		Purpose:         "aws_connection",
		TargetID:        "connection-1",
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
		CreatedAt:       time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC),
		ExpiresAt:       time.Date(2026, time.July, 16, 8, 10, 0, 0, time.UTC),
		Status:          StatusAwaitingUpload,
		Revision:        1,
	}
	plaintext := []byte("synthetic bootstrap payload")
	envelope, err := Seal(session, plaintext, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := openEnvelope(session, serverKeyBytes, envelope)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(opened)
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %q, want original", opened)
	}

	drifted := session
	drifted.OwnerID = "owner-2"
	if _, err := openEnvelope(drifted, serverKeyBytes, envelope); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("context drift error = %v, want ErrInvalidEnvelope", err)
	}
	if _, err := openEnvelope(session, serverKeyBytes, EnvelopeV1{
		SchemaVersion:   envelope.SchemaVersion,
		SessionID:       envelope.SessionID,
		ClientPublicKey: envelope.ClientPublicKey + "=",
		Nonce:           envelope.Nonce,
		Ciphertext:      envelope.Ciphertext,
	}); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("padded key error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestEnvelopeGoldenVector(t *testing.T) {
	serverKeyBytes := sequence(1, 32)
	serverKey, err := ecdh.X25519().NewPrivateKey(serverKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	session := SessionV1{
		SchemaVersion: SessionSchemaV1, SessionID: "018f6f16-2f90-7c21-8b00-000000000001",
		AgentInstanceID: "agent-instance-1", OwnerID: "owner-1", Purpose: "aws_connection", TargetID: "connection-1",
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(serverKey.PublicKey().Bytes()),
		CreatedAt:       time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2026, time.July, 16, 8, 10, 0, 0, time.UTC),
		Status: StatusAwaitingUpload, Revision: 1,
	}
	envelope, err := sealWithClientPrivateKey(session, []byte("golden secret"), sequence(33, 32), sequence(65, nonceSize))
	if err != nil {
		t.Fatal(err)
	}
	aad, err := AssociatedData(session, envelope.ClientPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	aadHash := sha256.Sum256(aad)
	if got, want := envelope.ClientPublicKey, "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns"; got != want {
		t.Fatalf("client public key = %q, want golden %q", got, want)
	}
	if got, want := envelope.Nonce, "QUJDREVGR0hJSktM"; got != want {
		t.Fatalf("nonce = %q, want golden %q", got, want)
	}
	if got, want := envelope.Ciphertext, "oXGFycRdUSf7qM-9rPjDU2olJgtH9CwSkHT4_84"; got != want {
		t.Fatalf("ciphertext = %q, want golden %q", got, want)
	}
	if got, want := hex.EncodeToString(aadHash[:]), "84b0a62a346e03c111645d31b4437b2286fc2b2f170c63375a3f5d6a4e3487b1"; got != want {
		t.Fatalf("AAD SHA-256 = %q, want golden %q", got, want)
	}
}

func TestSealToRecipientRoundTripAndAADBinding(t *testing.T) {
	recipientPrivateBytes := sequence(90, 32)
	recipientPrivate, err := ecdh.X25519().NewPrivateKey(recipientPrivateBytes)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic := base64.RawURLEncoding.EncodeToString(recipientPrivate.PublicKey().Bytes())
	aad := []byte("admin.create-service-key/v1|agent-instance-1|client-1|key-1|2026-07-16T08:10:00Z")
	plaintext := []byte("generated service credential")
	envelope, err := SealToRecipient(recipientPublic, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := OpenRecipientEnvelope(recipientPrivateBytes, envelope, aad)
	if err != nil {
		t.Fatal(err)
	}
	defer Wipe(opened)
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %q, want original", opened)
	}
	if strings.Contains(envelope.Ciphertext, string(plaintext)) {
		t.Fatal("recipient envelope exposed plaintext")
	}
	if _, err := OpenRecipientEnvelope(recipientPrivateBytes, envelope, append(aad, '!')); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("AAD drift error = %v, want ErrInvalidEnvelope", err)
	}
	if _, err := SealToRecipient(recipientPublic+"=", plaintext, aad); !errors.Is(err, ErrInvalidContext) {
		t.Fatalf("padded recipient key error = %v, want ErrInvalidContext", err)
	}
	if _, err := SealToRecipient(recipientPublic, plaintext, nil); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("empty AAD error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestRecipientEnvelopeGoldenVector(t *testing.T) {
	recipientPrivateBytes := sequence(90, 32)
	recipientPrivate, err := ecdh.X25519().NewPrivateKey(recipientPrivateBytes)
	if err != nil {
		t.Fatal(err)
	}
	recipientPublic := base64.RawURLEncoding.EncodeToString(recipientPrivate.PublicKey().Bytes())
	aad := []byte("admin.create-service-key/v1|agent-instance-1|client-1|key-1|2026-07-16T08:10:00Z")
	envelope, err := sealToRecipientWithPrivateKey(recipientPublic, []byte("generated service credential"), aad, sequence(33, 32), sequence(65, nonceSize))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := envelope.ServerPublicKey, "WGmv9FBUlzLLqu1eXfmzCm2jHLDldCutWtShp2jxpns"; got != want {
		t.Fatalf("server public key = %q, want golden %q", got, want)
	}
	if got, want := envelope.Nonce, "QUJDREVGR0hJSktM"; got != want {
		t.Fatalf("nonce = %q, want golden %q", got, want)
	}
	if got, want := envelope.Ciphertext, "zLt5A4e1dqBXLLhPjUYlFCMLToqesuY392klEQsvVKwU-v3dQ5juCTEi4Y0"; got != want {
		t.Fatalf("ciphertext = %q, want golden %q", got, want)
	}
}

func TestRecipientEnvelopeContractContainsOnlyPublicCiphertextFields(t *testing.T) {
	typeOf := reflect.TypeOf(RecipientEnvelopeV1{})
	for index := 0; index < typeOf.NumField(); index++ {
		field := typeOf.Field(index)
		name := strings.ToLower(field.Name + " " + field.Tag.Get("json"))
		if strings.Contains(name, "plaintext") || strings.Contains(name, "private") || strings.Contains(name, "secret") {
			t.Fatalf("recipient envelope exposes sensitive field %s", field.Name)
		}
	}
}

func sequence(start, count byte) []byte {
	result := make([]byte, int(count))
	for index := range result {
		result[index] = start + byte(index)
	}
	return result
}
