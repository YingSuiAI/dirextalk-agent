package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/google/uuid"
)

// CoreExtensionArtifactCleaner converges digest-addressed Agent staging after
// lifecycle rejection/failure or successful runner publication.
type CoreExtensionArtifactCleaner struct {
	Store         *Store
	Root          string
	Interval      time.Duration
	done          chan struct{}
	mutationGuard coreruntime.MutationGuard
}

func (c *CoreExtensionArtifactCleaner) SetMutationGuard(guard coreruntime.MutationGuard) {
	if c != nil {
		c.mutationGuard = guard
	}
}

func NewCoreExtensionArtifactCleaner(store *Store, root string, interval time.Duration) (*CoreExtensionArtifactCleaner, error) {
	if store == nil || !filepath.IsAbs(root) || filepath.Clean(root) != root || interval <= 0 {
		return nil, coreextension.ErrInvalid
	}
	return &CoreExtensionArtifactCleaner{Store: store, Root: root, Interval: interval, done: make(chan struct{})}, nil
}

func (c *CoreExtensionArtifactCleaner) Run(ctx context.Context) error {
	if c == nil || c.done == nil {
		return coreextension.ErrInvalid
	}
	defer close(c.done)
	if _, err := c.Sweep(ctx, 128); err != nil {
		if errors.Is(err, coredeprovision.ErrClosed) {
			<-ctx.Done()
			return ctx.Err()
		}
		return err
	}
	t := time.NewTicker(c.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			if _, err := c.Sweep(ctx, 128); err != nil {
				if errors.Is(err, coredeprovision.ErrClosed) {
					<-ctx.Done()
					return ctx.Err()
				}
				return err
			}
		}
	}
}

func (c *CoreExtensionArtifactCleaner) Wait(ctx context.Context) error {
	if c == nil || c.done == nil {
		return nil
	}
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *CoreExtensionArtifactCleaner) Enqueue(ctx context.Context, version coreextension.VersionRecord, installationID, reason string) error {
	if c == nil || c.Store == nil || uuid.Validate(installationID) != nil || uuid.Validate(version.VersionID) != nil || len(version.ArtifactDigest) != 64 || version.ArtifactPath == "" || filepath.Base(version.ArtifactPath) != version.ArtifactDigest || !validCleanupReason(reason) {
		return coreextension.ErrInvalid
	}
	_, err := c.Store.pool.Exec(ctx, `INSERT INTO core_extension_artifact_cleanup(cleanup_id,installation_id,version_id,artifact_digest,staging_relative_path,reason) VALUES($1,$2,$3,$4,$4,$5) ON CONFLICT (installation_id,version_id,artifact_digest) WHERE state IN ('pending','running','failed') DO NOTHING`, uuid.New(), installationID, version.VersionID, version.ArtifactDigest, reason)
	return err
}

// Sweep claims due rows and removes only a validated digest child of Root.
// Every claim is CAS-fenced and safe to repeat after process restart.
func (c *CoreExtensionArtifactCleaner) Sweep(ctx context.Context, limit int) (int, error) {
	if c == nil || c.Store == nil || !filepath.IsAbs(c.Root) || filepath.Clean(c.Root) != c.Root || limit <= 0 || limit > 128 {
		return 0, coreextension.ErrInvalid
	}
	if c.mutationGuard != nil {
		release, err := c.mutationGuard.Enter(ctx)
		if err != nil {
			return 0, err
		}
		defer release()
	}
	return c.sweep(ctx, limit)
}

func (c *CoreExtensionArtifactCleaner) sweep(ctx context.Context, limit int) (int, error) {
	rows, err := c.Store.pool.Query(ctx, `SELECT cleanup_id,artifact_digest FROM core_extension_artifact_cleanup WHERE ((state IN ('pending','failed') AND next_attempt_at<=clock_timestamp()) OR (state='running' AND updated_at<clock_timestamp()-interval '5 minutes')) ORDER BY next_attempt_at,cleanup_id LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	type item struct{ id, digest string }
	var items []item
	for rows.Next() {
		var x item
		if err = rows.Scan(&x.id, &x.digest); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, x)
	}
	if err = rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()
	completed := 0
	for _, x := range items {
		var claimed bool
		if err = c.Store.pool.QueryRow(ctx, `UPDATE core_extension_artifact_cleanup SET state='running',attempt=attempt+1,updated_at=clock_timestamp() WHERE cleanup_id=$1 AND ((state IN ('pending','failed') AND next_attempt_at<=clock_timestamp()) OR (state='running' AND updated_at<clock_timestamp()-interval '5 minutes')) RETURNING true`, x.id).Scan(&claimed); err != nil {
			continue
		}
		path, pathErr := cleanupPath(c.Root, x.digest)
		if pathErr == nil {
			pathErr = os.RemoveAll(path)
		}
		if pathErr == nil {
			_, err = c.Store.pool.Exec(ctx, `UPDATE core_extension_artifact_cleanup SET state='succeeded',last_error='',completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE cleanup_id=$1 AND state='running'`, x.id)
			if err == nil {
				completed++
			}
			continue
		}
		_, _ = c.Store.pool.Exec(ctx, `UPDATE core_extension_artifact_cleanup SET state='failed',last_error=$2,next_attempt_at=clock_timestamp()+interval '1 minute',updated_at=clock_timestamp() WHERE cleanup_id=$1 AND state='running'`, x.id, pathErr.Error())
	}
	return completed, nil
}

func cleanupPath(root, digest string) (string, error) {
	if len(digest) != 64 {
		return "", coreextension.ErrInvalid
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return "", coreextension.ErrInvalid
	}
	path := filepath.Join(root, digest)
	if filepath.Dir(path) != root || filepath.Base(path) != digest {
		return "", coreextension.ErrInvalid
	}
	return path, nil
}

func validCleanupReason(reason string) bool {
	switch reason {
	case "reject", "expire", "failure", "promotion_success", "promotion_failure":
		return true
	default:
		return false
	}
}
