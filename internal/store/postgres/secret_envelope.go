package postgres

import (
	"errors"

	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
)

// errSecretKeyUnavailable is deliberately shared by every encrypted Agent
// persistence adapter. A missing key is a hard startup/operation boundary,
// never a reason to fall back to plaintext.
var errSecretKeyUnavailable = errors.New("postgres: encrypted secret key unavailable")

func (s *Store) secretKeyring() (*secretbox.Keyring, error) {
	if s == nil || s.secretKey == nil || s.secretKey.Version() < secretbox.KeyVersionMin {
		return nil, errSecretKeyUnavailable
	}
	return s.secretKey, nil
}

func (s *Store) sealDurableSecret(domain, recordID string, revision int64, field string, plaintext []byte) (secretbox.Envelope, error) {
	key, err := s.secretKeyring()
	if err != nil {
		return secretbox.Envelope{}, err
	}
	aad, err := secretbox.BindAAD(domain, recordID, revision, field)
	if err != nil {
		return secretbox.Envelope{}, err
	}
	return key.Seal(plaintext, aad)
}

func (s *Store) openDurableSecret(domain, recordID string, revision int64, field string, version uint32, nonce, ciphertext []byte) ([]byte, error) {
	key, err := s.secretKeyring()
	if err != nil {
		return nil, err
	}
	aad, err := secretbox.BindAAD(domain, recordID, revision, field)
	if err != nil {
		return nil, err
	}
	return key.Open(secretbox.Envelope{KeyVersion: version, Nonce: nonce, Ciphertext: ciphertext}, aad)
}
