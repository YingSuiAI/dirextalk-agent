package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type CoreExtensionSecretStore struct{ store *Store }

func NewCoreExtensionSecretStore(s *Store) *CoreExtensionSecretStore {
	return &CoreExtensionSecretStore{store: s}
}
func (s *CoreExtensionSecretStore) Stage(ctx context.Context, installationID, versionID string, in []coreextension.SecretInput) error {
	tx, e := s.store.pool.BeginTx(ctx, pgx.TxOptions{})
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	for _, v := range in {
		if e = v.Validate(); e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO core_extension_secret_revisions(revision_id,installation_id,version_id,reference_id,purpose,secret_value,fingerprint,state) VALUES($1,$2,$3,$4,$5,$6,$7,'staged')`, uuid.New(), installationID, versionID, v.ReferenceID, string(v.Purpose), []byte(v.Value), v.Fingerprint()); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
func (s *CoreExtensionSecretStore) Bind(ctx context.Context, in []coreextension.SecretInput) ([]coreextension.SecretReceipt, error) {
	out := make([]coreextension.SecretReceipt, 0, len(in))
	for _, v := range in {
		if e := v.Validate(); e != nil {
			return nil, e
		}
		r := coreextension.SecretReceipt{ReferenceID: v.ReferenceID, Purpose: v.Purpose, Fingerprint: v.Fingerprint()}
		out = append(out, r)
	}
	_ = ctx
	return out, nil
}

// ResolveExactBound is the production execution seam. Every identity and the
// declared secret purpose are checked against the immutable version snapshot
// before the promoted value is returned.
func (s *CoreExtensionSecretStore) ResolveExactBound(ctx context.Context, installationID, versionID, ref, purpose, bindingDigest string) ([]byte, error) {
	v, err := s.resolveExactBound(ctx, installationID, versionID, ref, purpose, bindingDigest)
	if err != nil {
		return nil, err
	}
	return []byte(v), nil
}

func (s *CoreExtensionSecretStore) resolveExactBound(ctx context.Context, installationID, versionID, ref, requestedPurpose, bindingDigest string) (string, error) {
	if uuid.Validate(installationID) != nil || uuid.Validate(versionID) != nil || uuid.Validate(ref) != nil || strings.TrimSpace(requestedPurpose) == "" || len(bindingDigest) != 64 {
		return "", coreextension.ErrInvalid
	}
	var exists bool
	if e := s.store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_extension_installations WHERE installation_id=$1)`, installationID).Scan(&exists); e != nil {
		return "", coreextension.ErrNotFound
	}
	if !exists {
		return "", coreextension.ErrNotFound
	}
	// A task owns an immutable version snapshot. Do not require that version
	// to remain the installation's current active pointer: updates and
	// uninstall only change the projection, while promoted secret revisions
	// remain readable until the last task snapshot is deleted.
	var versionExists bool
	if e := s.store.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2)`, installationID, versionID).Scan(&versionExists); e != nil || !versionExists {
		return "", coreextension.ErrConflict
	}
	var purpose string
	var raw []byte
	if e := s.store.pool.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE installation_id=$1 AND version_id=$2`, installationID, versionID).Scan(&raw); e != nil {
		return "", coreextension.ErrNotFound
	}
	var v coreextension.VersionRecord
	if json.Unmarshal(raw, &v) != nil {
		return "", coreextension.ErrConflict
	}
	for _, g := range v.SecretGrants {
		if g.ReferenceID == ref && g.BindingDigest == bindingDigest && string(g.Purpose) == requestedPurpose {
			purpose = string(g.Purpose)
			break
		}
	}
	if purpose == "" {
		return "", coreextension.ErrConflict
	}
	var value []byte
	if e := s.store.pool.QueryRow(ctx, `SELECT secret_value FROM core_extension_secret_revisions WHERE installation_id=$1 AND version_id=$2 AND reference_id=$3 AND purpose=$4 AND fingerprint=$5 AND state='promoted'`, installationID, versionID, ref, purpose, bindingDigest).Scan(&value); e != nil {
		if errors.Is(e, pgx.ErrNoRows) {
			return "", coreextension.ErrConflict
		}
		return "", e
	}
	return string(append([]byte(nil), value...)), nil
}
