package coreextension

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// FingerprintSecretStore records only receipt metadata; plaintext values never
// cross this boundary or reach PostgreSQL.
type FingerprintSecretStore struct {
	mu       sync.Mutex
	receipts map[string]SecretReceipt
}

func NewFingerprintSecretStore() *FingerprintSecretStore {
	return &FingerprintSecretStore{receipts: map[string]SecretReceipt{}}
}
func (s *FingerprintSecretStore) Bind(_ context.Context, in []SecretInput) ([]SecretReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]SecretReceipt, 0, len(in))
	for _, v := range in {
		if err := v.Validate(); err != nil {
			return nil, err
		}
		h := sha256.Sum256([]byte(v.Value))
		r := SecretReceipt{ReferenceID: v.ReferenceID, Purpose: v.Purpose, Fingerprint: hex.EncodeToString(h[:])}
		s.receipts[v.ReferenceID] = r
		out = append(out, r)
	}
	return out, nil
}
func (s *FingerprintSecretStore) String() string {
	return fmt.Sprintf("FingerprintSecretStore{receipts:%d}", len(s.receipts))
}
