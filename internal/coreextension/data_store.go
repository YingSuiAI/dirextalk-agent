package coreextension

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FileArtifactStore materializes verified fetched bytes under the Agent data
// directory. Paths are relative receipts; writes use a temp file + rename.
type FileArtifactStore struct{ Root string }

func NewFileArtifactStore(root string) (*FileArtifactStore, error) {
	if strings.TrimSpace(root) == "" {
		return nil, ErrInvalid
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	return &FileArtifactStore{Root: root}, nil
}
func (s *FileArtifactStore) Materialize(_ context.Context, f FetchArtifact) (ArtifactReceipt, error) {
	if err := f.Validate(); err != nil {
		return ArtifactReceipt{}, err
	}
	name := f.ContentDigest + ".pkg"
	dst := filepath.Join(s.Root, name)
	tmp := dst + "." + uuid.NewString() + ".tmp"
	if err := os.WriteFile(tmp, f.Content, 0600); err != nil {
		return ArtifactReceipt{}, err
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return ArtifactReceipt{}, err
	}
	return ArtifactReceipt{RelativePath: name, Digest: f.ContentDigest}, nil
}
func (s *FileArtifactStore) Remove(_ context.Context, r ArtifactReceipt) error {
	if r.RelativePath == "" || filepath.Base(r.RelativePath) != r.RelativePath {
		return ErrInvalid
	}
	err := os.Remove(filepath.Join(s.Root, r.RelativePath))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// FingerprintSecretStore is deliberately stateless: Bind is a pure receipt
// validator and cannot leave durable secret state behind when a later install
// precondition or repository write fails. Plaintext never crosses this
// boundary or reaches PostgreSQL.
type FingerprintSecretStore struct{}

func NewFingerprintSecretStore() *FingerprintSecretStore { return &FingerprintSecretStore{} }
func (s *FingerprintSecretStore) Bind(_ context.Context, in []SecretInput) ([]SecretReceipt, error) {
	out := make([]SecretReceipt, 0, len(in))
	for _, v := range in {
		if err := v.Validate(); err != nil {
			return nil, err
		}
		out = append(out, SecretReceipt{ReferenceID: v.ReferenceID, Purpose: v.Purpose, Fingerprint: v.Fingerprint()})
	}
	return out, nil
}
func (s *FingerprintSecretStore) String() string { return "FingerprintSecretStore{}" }
