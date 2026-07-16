package secretbootstrap

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"io"
	"time"
)

const (
	nonceSize         = 12
	gcmTagSize        = 16
	uploadTokenSize   = 32
	aadDomain         = "dirextalk.agent.secret-bootstrap/aad/v1"
	hkdfInfo          = "dirextalk.agent.secret-bootstrap/x25519-hkdf-sha256-aes256gcm/v1"
	recipientHKDFInfo = "dirextalk.agent.recipient-envelope/x25519-hkdf-sha256-aes256gcm/v1"
)

// SealToRecipient encrypts plaintext to a recipient X25519 public key. The
// caller retains ownership of plaintext and should Wipe it immediately after
// this call. AAD must bind the response identity, owner, operation, and expiry.
func SealToRecipient(recipientX25519PublicKey string, plaintext, aad []byte) (RecipientEnvelopeV1, error) {
	return sealToRecipient(recipientX25519PublicKey, plaintext, aad, cryptorand.Reader)
}

func sealToRecipient(recipientX25519PublicKey string, plaintext, aad []byte, random io.Reader) (RecipientEnvelopeV1, error) {
	if random == nil || len(plaintext) == 0 || len(plaintext) > MaxPlaintextSize || len(aad) == 0 || len(aad) > MaxAADSize {
		return RecipientEnvelopeV1{}, ErrInvalidEnvelope
	}
	curve := ecdh.X25519()
	recipientPublicBytes, err := decodeRawURL(recipientX25519PublicKey, 32)
	if err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidContext
	}
	if _, err := curve.NewPublicKey(recipientPublicBytes); err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidContext
	}
	serverPrivate, err := curve.GenerateKey(random)
	if err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidEnvelope
	}
	serverPrivateBytes := serverPrivate.Bytes()
	defer Wipe(serverPrivateBytes)
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidEnvelope
	}
	return sealToRecipientWithPrivateKey(recipientX25519PublicKey, plaintext, aad, serverPrivateBytes, nonce)
}

func sealToRecipientWithPrivateKey(recipientX25519PublicKey string, plaintext, aad, serverPrivateBytes, nonce []byte) (RecipientEnvelopeV1, error) {
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintextSize || len(aad) == 0 || len(aad) > MaxAADSize || len(serverPrivateBytes) != 32 || len(nonce) != nonceSize {
		return RecipientEnvelopeV1{}, ErrInvalidEnvelope
	}
	curve := ecdh.X25519()
	recipientPublicBytes, err := decodeRawURL(recipientX25519PublicKey, 32)
	if err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidContext
	}
	recipientPublic, err := curve.NewPublicKey(recipientPublicBytes)
	if err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidContext
	}
	serverPrivate, err := curve.NewPrivateKey(serverPrivateBytes)
	if err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidEnvelope
	}
	shared, err := serverPrivate.ECDH(recipientPublic)
	if err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidEnvelope
	}
	defer Wipe(shared)
	key, err := deriveKeyWithInfo(shared, aad, recipientHKDFInfo)
	if err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidEnvelope
	}
	defer Wipe(key)
	gcm, err := newGCM(key)
	if err != nil {
		return RecipientEnvelopeV1{}, ErrInvalidEnvelope
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return RecipientEnvelopeV1{
		SchemaVersion:   RecipientEnvelopeSchemaV1,
		ServerPublicKey: base64.RawURLEncoding.EncodeToString(serverPrivate.PublicKey().Bytes()),
		Nonce:           base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:      base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

// OpenRecipientEnvelope is the Go client reference for decrypting a generated
// credential delivery. The caller owns the returned plaintext and must wipe it.
func OpenRecipientEnvelope(recipientPrivateBytes []byte, envelope RecipientEnvelopeV1, aad []byte) ([]byte, error) {
	if envelope.SchemaVersion != RecipientEnvelopeSchemaV1 || len(recipientPrivateBytes) != 32 || len(aad) == 0 || len(aad) > MaxAADSize {
		return nil, ErrInvalidEnvelope
	}
	serverPublicBytes, err := decodeRawURL(envelope.ServerPublicKey, 32)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	nonce, err := decodeRawURL(envelope.Nonce, nonceSize)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	ciphertext, err := decodeRawURLRange(envelope.Ciphertext, gcmTagSize+1, MaxPlaintextSize+gcmTagSize)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	curve := ecdh.X25519()
	recipientPrivate, err := curve.NewPrivateKey(recipientPrivateBytes)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	serverPublic, err := curve.NewPublicKey(serverPublicBytes)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	shared, err := recipientPrivate.ECDH(serverPublic)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	defer Wipe(shared)
	key, err := deriveKeyWithInfo(shared, aad, recipientHKDFInfo)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	defer Wipe(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil || len(plaintext) == 0 || len(plaintext) > MaxPlaintextSize {
		Wipe(plaintext)
		return nil, ErrInvalidEnvelope
	}
	return plaintext, nil
}

// Seal is the reference envelope producer used by Go clients and golden-vector
// tests. Other clients must reproduce AssociatedData and the documented
// X25519/HKDF-SHA256/AES-256-GCM construction.
func Seal(session SessionV1, plaintext []byte, random io.Reader) (EnvelopeV1, error) {
	if err := validateSession(session); err != nil || session.Status != StatusAwaitingUpload || random == nil {
		return EnvelopeV1{}, ErrInvalidContext
	}
	if len(plaintext) == 0 || len(plaintext) > MaxPlaintextSize {
		return EnvelopeV1{}, ErrInvalidEnvelope
	}
	curve := ecdh.X25519()
	clientPrivate, err := curve.GenerateKey(random)
	if err != nil {
		return EnvelopeV1{}, ErrInvalidEnvelope
	}
	clientPrivateBytes := clientPrivate.Bytes()
	defer Wipe(clientPrivateBytes)
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(random, nonce); err != nil {
		return EnvelopeV1{}, ErrInvalidEnvelope
	}
	return sealWithClientPrivateKey(session, plaintext, clientPrivateBytes, nonce)
}

func sealWithClientPrivateKey(session SessionV1, plaintext, clientPrivateBytes, nonce []byte) (EnvelopeV1, error) {
	if err := validateSession(session); err != nil || session.Status != StatusAwaitingUpload || len(plaintext) == 0 || len(plaintext) > MaxPlaintextSize || len(clientPrivateBytes) != 32 || len(nonce) != nonceSize {
		return EnvelopeV1{}, ErrInvalidEnvelope
	}
	curve := ecdh.X25519()
	serverPublicBytes, err := decodeRawURL(session.ServerPublicKey, 32)
	if err != nil {
		return EnvelopeV1{}, ErrInvalidContext
	}
	serverPublic, err := curve.NewPublicKey(serverPublicBytes)
	if err != nil {
		return EnvelopeV1{}, ErrInvalidContext
	}
	clientPrivate, err := curve.NewPrivateKey(clientPrivateBytes)
	if err != nil {
		return EnvelopeV1{}, ErrInvalidEnvelope
	}
	clientPublicBytes := clientPrivate.PublicKey().Bytes()
	shared, err := clientPrivate.ECDH(serverPublic)
	if err != nil {
		return EnvelopeV1{}, ErrInvalidEnvelope
	}
	defer Wipe(shared)
	aad, err := associatedData(session, clientPublicBytes)
	if err != nil {
		return EnvelopeV1{}, err
	}
	key, err := deriveKey(shared, aad)
	if err != nil {
		return EnvelopeV1{}, ErrInvalidEnvelope
	}
	defer Wipe(key)
	gcm, err := newGCM(key)
	if err != nil {
		return EnvelopeV1{}, ErrInvalidEnvelope
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return EnvelopeV1{
		SchemaVersion:   EnvelopeSchemaV1,
		SessionID:       session.SessionID,
		ClientPublicKey: base64.RawURLEncoding.EncodeToString(clientPublicBytes),
		Nonce:           base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:      base64.RawURLEncoding.EncodeToString(ciphertext),
	}, nil
}

// AssociatedData returns the exact binary AAD for cross-language clients.
func AssociatedData(session SessionV1, clientPublicKey string) ([]byte, error) {
	if err := validateSession(session); err != nil {
		return nil, ErrInvalidContext
	}
	clientPublicBytes, err := decodeRawURL(clientPublicKey, 32)
	if err != nil {
		return nil, ErrInvalidContext
	}
	if _, err := ecdh.X25519().NewPublicKey(clientPublicBytes); err != nil {
		return nil, ErrInvalidContext
	}
	return associatedData(session, clientPublicBytes)
}

func openEnvelope(session SessionV1, serverPrivateBytes []byte, envelope EnvelopeV1) ([]byte, error) {
	if err := validateSession(session); err != nil || len(serverPrivateBytes) != 32 {
		return nil, ErrInvalidEnvelope
	}
	clientPublicBytes, nonce, ciphertext, err := validateEnvelope(session, envelope)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	curve := ecdh.X25519()
	serverPrivate, err := curve.NewPrivateKey(serverPrivateBytes)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	serverPublicBytes, err := decodeRawURL(session.ServerPublicKey, 32)
	if err != nil || subtle.ConstantTimeCompare(serverPrivate.PublicKey().Bytes(), serverPublicBytes) != 1 {
		return nil, ErrInvalidEnvelope
	}
	clientPublic, err := curve.NewPublicKey(clientPublicBytes)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	shared, err := serverPrivate.ECDH(clientPublic)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	defer Wipe(shared)
	aad, err := associatedData(session, clientPublicBytes)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	key, err := deriveKey(shared, aad)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	defer Wipe(key)
	gcm, err := newGCM(key)
	if err != nil {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil || len(plaintext) == 0 || len(plaintext) > MaxPlaintextSize {
		Wipe(plaintext)
		return nil, ErrInvalidEnvelope
	}
	return plaintext, nil
}

func associatedData(session SessionV1, clientPublicBytes []byte) ([]byte, error) {
	serverPublicBytes, err := decodeRawURL(session.ServerPublicKey, 32)
	if err != nil || len(clientPublicBytes) != 32 {
		return nil, ErrInvalidContext
	}
	fields := [][]byte{
		[]byte(aadDomain),
		[]byte(SessionSchemaV1),
		[]byte(EnvelopeSchemaV1),
		[]byte(session.SessionID),
		[]byte(session.AgentInstanceID),
		[]byte(session.OwnerID),
		[]byte(session.Purpose),
		[]byte(session.TargetID),
		serverPublicBytes,
		clientPublicBytes,
		[]byte(utc(session.CreatedAt).Format(time.RFC3339Nano)),
		[]byte(utc(session.ExpiresAt).Format(time.RFC3339Nano)),
	}
	var result bytes.Buffer
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		result.Write(length[:])
		result.Write(field)
	}
	return result.Bytes(), nil
}

func deriveKey(shared, aad []byte) ([]byte, error) {
	return deriveKeyWithInfo(shared, aad, hkdfInfo)
}

func deriveKeyWithInfo(shared, aad []byte, info string) ([]byte, error) {
	salt := sha256.Sum256(aad)
	return hkdf.Key(sha256.New, shared, salt[:], info, 32)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
