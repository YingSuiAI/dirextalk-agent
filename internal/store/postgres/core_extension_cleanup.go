package postgres

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coredeprovision"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/execution"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
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
	cleanupID := extensionArtifactCleanupID(installationID, version.VersionID, version.ArtifactDigest)
	_, err := c.Store.pool.Exec(ctx, `INSERT INTO core_extension_artifact_cleanup(cleanup_id,installation_id,version_id,artifact_digest,staging_relative_path,reason) VALUES($1,$2,$3,$4,$4,$5) ON CONFLICT (cleanup_id) DO NOTHING`, cleanupID, installationID, version.VersionID, version.ArtifactDigest, reason)
	return err
}

func extensionArtifactCleanupID(installationID, versionID, artifactDigest string) string {
	return uuid.NewSHA1(uuid.NameSpaceURL, []byte("dirextalk-agent/core-extension-cleanup/v1\x00"+installationID+"\x00"+versionID+"\x00"+artifactDigest)).String()
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
	if err := c.recoverStagedCleanupMarkers(ctx); err != nil {
		return 0, err
	}
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
		pathErr := removeStagedExtensionArtifact(c.Root, x.digest, x.id)
		if pathErr == nil {
			tag, updateErr := c.Store.pool.Exec(ctx, `UPDATE core_extension_artifact_cleanup SET state='succeeded',last_error='',completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE cleanup_id=$1 AND state='running'`, x.id)
			if updateErr != nil {
				return completed, updateErr
			}
			if tag.RowsAffected() == 1 {
				completed++
				if err = removeStagedExtensionArtifactCompletion(c.Root, x.id, "succeeded"); err != nil {
					return completed, err
				}
			}
			continue
		}
		_, _ = c.Store.pool.Exec(ctx, `UPDATE core_extension_artifact_cleanup SET state='failed',last_error=$2,next_attempt_at=clock_timestamp()+interval '1 minute',updated_at=clock_timestamp() WHERE cleanup_id=$1 AND state='running'`, x.id, pathErr.Error())
	}
	return completed, nil
}

func removeStagedExtensionArtifact(root, digest, cleanupID string) error {
	path, err := cleanupPath(root, digest)
	if err != nil {
		return err
	}
	if uuid.Validate(cleanupID) != nil {
		return coreextension.ErrInvalid
	}
	return execution.RemoveStagedArtifact(root, filepath.Base(path), cleanupID)
}

func removeStagedExtensionArtifactCompletion(root, cleanupID, state string) error {
	if state != "succeeded" {
		return nil
	}
	return execution.RemoveStagedArtifactMarker(root, cleanupID)
}

func (c *CoreExtensionArtifactCleaner) recoverStagedCleanupMarkers(ctx context.Context) error {
	entries, err := os.ReadDir(c.Root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		name := entry.Name()
		removing := strings.HasPrefix(name, ".remove-")
		removed := strings.HasPrefix(name, ".removed-")
		if !removing && !removed {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.IsDir() {
			continue
		}
		prefix := ".removed-"
		if removing {
			prefix = ".remove-"
		}
		cleanupID := strings.TrimPrefix(name, prefix)
		parsed, parseErr := uuid.Parse(cleanupID)
		if parseErr != nil || parsed.String() != cleanupID {
			continue
		}
		var state string
		hasDurableRow := true
		if err := c.Store.pool.QueryRow(ctx, `SELECT state FROM core_extension_artifact_cleanup WHERE cleanup_id=$1`, cleanupID).Scan(&state); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			hasDurableRow = false
		}
		if removing {
			if hasDurableRow {
				continue
			}
			if err := execution.ResumeStagedArtifactRemoval(c.Root, cleanupID); err != nil {
				return err
			}
			if err := execution.RemoveStagedArtifactMarker(c.Root, cleanupID); err != nil {
				return err
			}
			continue
		}
		if hasDurableRow && state != "succeeded" {
			continue
		}
		if err := execution.RemoveStagedArtifactMarker(c.Root, cleanupID); err != nil {
			return err
		}
	}
	return nil
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
