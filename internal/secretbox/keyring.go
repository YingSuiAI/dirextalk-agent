// Package secretbox provides the Agent's small, authenticated-encryption
// boundary for durable secret values.  The key is intentionally represented
// by an opaque keyring; callers can seal/open one value at a time but cannot
// inspect or serialize the master key.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const (
	MasterKeySize = 32
	KeyVersionMin = uint32(1)
)

var (
	ErrInvalidKey         = errors.New("secretbox: invalid key")
	ErrInvalidEnvelope    = errors.New("secretbox: invalid envelope")
	ErrKeyVersionMismatch = errors.New("secretbox: key version mismatch")
	ErrDecrypt            = errors.New("secretbox: decrypt failed")
	ErrInvalidAAD         = errors.New("secretbox: invalid associated data")
)

// Envelope is the complete durable representation of one encrypted value.
// It contains no plaintext and is safe for a persistence adapter to split
// into key_version, nonce, and ciphertext columns.
type Envelope struct {
	KeyVersion uint32
	Nonce      []byte
	Ciphertext []byte
}

// Keyring owns one master key version.  The key bytes are never exposed to
// callers and are not accepted from process YAML or environment variables.
type Keyring struct {
	version uint32
	key     [MasterKeySize]byte
}

// mountedKeyBeforeOpenHook is test-only synchronization for the Linux
// lstat/open identity check. Production code leaves it nil.
var mountedKeyBeforeOpenHook func(string)

// New constructs a keyring from exactly one raw 32-byte key.  The input is
// copied and should be cleared by the caller after this function returns.
func New(version uint32, raw []byte) (*Keyring, error) {
	if version < KeyVersionMin || len(raw) != MasterKeySize {
		return nil, ErrInvalidKey
	}
	ring := &Keyring{version: version}
	copy(ring.key[:], raw)
	return ring, nil
}

// Version returns the durable key version without exposing key material.
func (k *Keyring) Version() uint32 {
	if k == nil {
		return 0
	}
	return k.version
}

// BindAAD creates canonical associated data for a domain record.  Every
// encrypted field must bind its own domain, record ID, revision, and field
// name so ciphertext cannot be transplanted across rows, revisions, or
// fields.
func BindAAD(domain, recordID string, revision int64, field string) ([]byte, error) {
	for _, value := range []string{domain, recordID, field} {
		if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
			return nil, ErrInvalidAAD
		}
	}
	if revision <= 0 {
		return nil, ErrInvalidAAD
	}
	// Length-prefix each component so the binding is unambiguous even when
	// future names contain separators.
	parts := []string{domain, recordID, strconv.FormatInt(revision, 10), field}
	var b strings.Builder
	for _, part := range parts {
		b.WriteString(strconv.Itoa(len(part)))
		b.WriteByte(':')
		b.WriteString(part)
	}
	return []byte(b.String()), nil
}

// Seal authenticates and encrypts plaintext using a fresh random nonce.
// Plaintext is not retained by the keyring after this call.
func (k *Keyring) Seal(plaintext, aad []byte) (Envelope, error) {
	if k == nil || k.version < KeyVersionMin || len(aad) == 0 {
		return Envelope{}, ErrInvalidEnvelope
	}
	block, err := aes.NewCipher(k.key[:])
	if err != nil {
		return Envelope{}, ErrInvalidKey
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, ErrInvalidKey
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("secretbox: generate nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	return Envelope{KeyVersion: k.version, Nonce: nonce, Ciphertext: ciphertext}, nil
}

// Open authenticates and decrypts one envelope.  A wrong key, version, nonce,
// ciphertext, or AAD always fails closed with a generic decryption error.
func (k *Keyring) Open(envelope Envelope, aad []byte) ([]byte, error) {
	if k == nil || k.version < KeyVersionMin || len(aad) == 0 {
		return nil, ErrInvalidEnvelope
	}
	if envelope.KeyVersion != k.version {
		return nil, ErrKeyVersionMismatch
	}
	block, err := aes.NewCipher(k.key[:])
	if err != nil {
		return nil, ErrInvalidKey
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalidKey
	}
	if len(envelope.Nonce) != gcm.NonceSize() || len(envelope.Ciphertext) < gcm.Overhead() {
		return nil, ErrInvalidEnvelope
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrDecrypt
	}
	return plaintext, nil
}

// ValidateMountedFile checks the non-secret boundary without reading key
// bytes. Linux deployments require a single-link, regular, exact-mode 0400
// file owned by the serving UID; this rejects symlink swaps and
// group/world-readable key material.
func ValidateMountedFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" || strings.ContainsAny(path, "\x00\r\n") {
		return ErrInvalidKey
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return ErrInvalidKey
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalidKey
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o400 {
		return ErrInvalidKey
	}
	return nil
}

// LoadMountedFile loads exactly 32 raw bytes from a strict mode-0400 mounted
// file.  No text/base64 fallback is accepted, avoiding ambiguous key
// encodings and accidental newline-padded secrets.
func LoadMountedFile(path string, version uint32) (*Keyring, error) {
	f, identity, err := openMountedKey(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw := make([]byte, MasterKeySize)
	defer clear(raw)
	n, readErr := io.ReadFull(f, raw)
	if readErr != nil || n != MasterKeySize {
		return nil, ErrInvalidKey
	}
	var extra [1]byte
	if n, err := f.Read(extra[:]); err != io.EOF || n != 0 {
		return nil, ErrInvalidKey
	}
	if err := verifyMountedKey(f, identity); err != nil {
		return nil, err
	}
	return New(version, raw)
}

func clear(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
