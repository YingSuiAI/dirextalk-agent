package postgres

import (
	"context"
	"encoding/hex"
	"encoding/json"
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
	Store             *Store
	Root              string
	Interval          time.Duration
	done              chan struct{}
	mutationGuard     coreruntime.MutationGuard
	lifecyclePromoter coreextension.LifecycleArtifactPromoter
	artifactStore     coreextension.ArtifactStore
}

func (c *CoreExtensionArtifactCleaner) SetMutationGuard(guard coreruntime.MutationGuard) {
	if c != nil {
		c.mutationGuard = guard
	}
}

// SetLifecyclePromoter enables restart-safe cleanup of retired managed Node
// active references and terminally rejected post-Promote references. The
// durable row carries the immutable version receipt and cleanup-token fence;
// the cleaner never reconstructs either from mutable state.
func (c *CoreExtensionArtifactCleaner) SetLifecyclePromoter(promoter coreextension.LifecycleArtifactPromoter) {
	if c != nil {
		c.lifecyclePromoter = promoter
	}
}

// SetArtifactStore enables cleanup of failed managed Node proposals from the
// runner's prepared root. The durable row carries the exact cleanup token and
// immutable Node receipt; no path or generation is reconstructed from a name.
func (c *CoreExtensionArtifactCleaner) SetArtifactStore(store coreextension.ArtifactStore) {
	if c != nil {
		c.artifactStore = store
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
	rows, err := c.Store.pool.Query(ctx, `SELECT cleanup_id::text,installation_id::text,version_id::text,artifact_digest,COALESCE(cleanup_token::text,''),node_artifact,COALESCE(version_json,'{}'::jsonb)
		FROM core_extension_artifact_cleanup
		WHERE ((state IN ('pending','failed') AND next_attempt_at<=clock_timestamp()) OR (state='running' AND updated_at<clock_timestamp()-interval '5 minutes'))
		ORDER BY next_attempt_at,cleanup_id LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	type item struct {
		id, installationID, versionID, digest, cleanupToken string
		nodeArtifact                                        bool
		versionRaw                                          []byte
	}
	var items []item
	for rows.Next() {
		var x item
		if err = rows.Scan(&x.id, &x.installationID, &x.versionID, &x.digest, &x.cleanupToken, &x.nodeArtifact, &x.versionRaw); err != nil {
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
		var pathErr error
		if x.nodeArtifact {
			pathErr = c.removePreparedNodeArtifact(ctx, x.id, x.installationID, x.versionID, x.digest, x.cleanupToken, x.versionRaw)
		} else {
			pathErr = removeStagedExtensionArtifact(c.Root, x.digest, x.id)
		}
		if pathErr == nil {
			tag, updateErr := c.Store.pool.Exec(ctx, `UPDATE core_extension_artifact_cleanup SET state='succeeded',last_error='',completed_at=clock_timestamp(),updated_at=clock_timestamp() WHERE cleanup_id=$1 AND state='running'`, x.id)
			if updateErr != nil {
				return completed, updateErr
			}
			if tag.RowsAffected() == 1 {
				completed++
				if !x.nodeArtifact {
					if err = removeStagedExtensionArtifactCompletion(c.Root, x.id, "succeeded"); err != nil {
						return completed, err
					}
				}
			}
			continue
		}
		_, _ = c.Store.pool.Exec(ctx, `UPDATE core_extension_artifact_cleanup SET state='failed',last_error=$2,next_attempt_at=clock_timestamp()+interval '1 minute',updated_at=clock_timestamp() WHERE cleanup_id=$1 AND state='running'`, x.id, pathErr.Error())
	}
	if c.lifecyclePromoter != nil {
		nodeCompleted, nodeErr := c.sweepNode(ctx, limit)
		completed += nodeCompleted
		if nodeErr != nil {
			return completed, nodeErr
		}
	}
	return completed, nil
}

func (c *CoreExtensionArtifactCleaner) removePreparedNodeArtifact(ctx context.Context, cleanupID, installationID, versionID, digest, cleanupToken string, intentRaw []byte) error {
	if c == nil || c.artifactStore == nil || uuid.Validate(cleanupID) != nil || uuid.Validate(installationID) != nil || uuid.Validate(versionID) != nil || uuid.Validate(cleanupToken) != nil || len(digest) != 64 {
		return coreextension.ErrInvalid
	}
	var activeVersionID, proposedVersionID string
	var currentRaw []byte
	var publishedAt *time.Time
	err := c.Store.pool.QueryRow(ctx, `SELECT COALESCE(i.active_version_id::text,''),COALESCE(i.proposed_version_id::text,''),v.version_json,v.published_at
		FROM core_extension_artifact_cleanup c
		JOIN core_extension_installations i ON i.installation_id=c.installation_id
		JOIN core_extension_versions v ON v.installation_id=c.installation_id AND v.version_id=c.version_id
		WHERE c.cleanup_id=$1 AND c.state='running' AND c.installation_id=$2 AND c.version_id=$3
		  AND c.artifact_digest=$4 AND c.cleanup_token=$5 AND c.node_artifact=true`, cleanupID, installationID, versionID, digest, cleanupToken).Scan(&activeVersionID, &proposedVersionID, &currentRaw, &publishedAt)
	if err != nil {
		return err
	}
	var intent, current coreextension.VersionRecord
	if publishedAt != nil || activeVersionID == versionID || proposedVersionID == versionID || json.Unmarshal(intentRaw, &intent) != nil || json.Unmarshal(currentRaw, &current) != nil {
		return coreextension.ErrConflict
	}
	if intent.VersionID != versionID || current.VersionID != versionID || intent.ContentDigest != current.ContentDigest || intent.ArtifactDigest != digest || current.ArtifactDigest != digest || intent.ArtifactCleanupToken != cleanupToken || current.ArtifactCleanupToken != cleanupToken || intent.NodeArtifact == nil || current.NodeArtifact == nil || intent.NodeArtifact.ArtifactDigest != digest || current.NodeArtifact.ArtifactDigest != digest || !intent.PublishedAt.IsZero() || !current.PublishedAt.IsZero() {
		return coreextension.ErrConflict
	}
	receipt := coreextension.ArtifactReceipt{RelativePath: digest, ContentDigest: intent.ContentDigest, ArtifactDigest: digest, CleanupToken: cleanupToken, NodeArtifact: intent.NodeArtifact}
	return c.artifactStore.Remove(ctx, receipt)
}

// SweepNode converges durable post-commit Node active-reference cleanup. It is
// also called once by the lifecycle handler after a successful or failed
// terminal commit; the regular cleaner loop owns retries after process restart
// or runner/SQL failure.
func (c *CoreExtensionArtifactCleaner) SweepNode(ctx context.Context, limit int) (int, error) {
	if c == nil || c.Store == nil || c.lifecyclePromoter == nil || limit <= 0 || limit > 128 {
		return 0, coreextension.ErrInvalid
	}
	if c.mutationGuard != nil {
		release, err := c.mutationGuard.Enter(ctx)
		if err != nil {
			return 0, err
		}
		defer release()
	}
	return c.sweepNode(ctx, limit)
}

type nodeArtifactCleanupItem struct {
	cleanupID, installationID, versionID, artifactDigest, cleanupToken string
	installationRevision                                               int64
	versionRaw                                                         []byte
}

func (c *CoreExtensionArtifactCleaner) sweepNode(ctx context.Context, limit int) (int, error) {
	rows, err := c.Store.pool.Query(ctx, `SELECT cleanup_id::text,installation_id::text,version_id::text,artifact_digest,cleanup_token::text,installation_revision,version_json
		FROM core_extension_node_artifact_cleanup
		WHERE ((state IN ('pending','failed') AND next_attempt_at<=clock_timestamp())
		    OR (state='running' AND updated_at<clock_timestamp()-interval '5 minutes'))
		ORDER BY next_attempt_at,cleanup_id LIMIT $1`, limit)
	if err != nil {
		return 0, err
	}
	items := make([]nodeArtifactCleanupItem, 0, limit)
	for rows.Next() {
		var current nodeArtifactCleanupItem
		if err = rows.Scan(&current.cleanupID, &current.installationID, &current.versionID, &current.artifactDigest, &current.cleanupToken, &current.installationRevision, &current.versionRaw); err != nil {
			rows.Close()
			return 0, err
		}
		items = append(items, current)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	completed := 0
	for _, current := range items {
		var claimed bool
		if err = c.Store.pool.QueryRow(ctx, `UPDATE core_extension_node_artifact_cleanup
			SET state='running',attempt=attempt+1,updated_at=clock_timestamp()
			WHERE cleanup_id=$1 AND ((state IN ('pending','failed') AND next_attempt_at<=clock_timestamp())
			 OR (state='running' AND updated_at<clock_timestamp()-interval '5 minutes')) RETURNING true`, current.cleanupID).Scan(&claimed); err != nil {
			continue
		}
		version, removeErr := c.validateNodeCleanupAuthority(ctx, current)
		if removeErr == nil {
			removeErr = c.lifecyclePromoter.Remove(ctx, version)
		}
		if removeErr == nil {
			if removeErr = c.finalizeNodeCleanup(ctx, current); removeErr == nil {
				completed++
				continue
			}
		}
		message := removeErr.Error()
		if len(message) > 4096 {
			message = message[:4096]
		}
		if _, updateErr := c.Store.pool.Exec(ctx, `UPDATE core_extension_node_artifact_cleanup
			SET state='failed',last_error=$2,next_attempt_at=clock_timestamp()+interval '1 minute',updated_at=clock_timestamp()
			WHERE cleanup_id=$1 AND state='running'`, current.cleanupID, message); updateErr != nil {
			return completed, updateErr
		}
	}
	return completed, nil
}

func (c *CoreExtensionArtifactCleaner) validateNodeCleanupAuthority(ctx context.Context, item nodeArtifactCleanupItem) (coreextension.VersionRecord, error) {
	var activeVersionID, proposedVersionID string
	var currentRevision int64
	var currentRaw []byte
	var publishedAt *time.Time
	err := c.Store.pool.QueryRow(ctx, `SELECT COALESCE(i.active_version_id::text,''),COALESCE(i.proposed_version_id::text,''),i.revision,v.version_json,v.published_at
		FROM core_extension_node_artifact_cleanup c
		JOIN core_extension_installations i ON i.installation_id=c.installation_id
		JOIN core_extension_versions v ON v.installation_id=c.installation_id AND v.version_id=c.version_id
		WHERE c.cleanup_id=$1 AND c.state='running' AND c.installation_id=$2 AND c.version_id=$3
		  AND c.artifact_digest=$4 AND c.cleanup_token=$5 AND c.installation_revision=$6`, item.cleanupID, item.installationID, item.versionID, item.artifactDigest, item.cleanupToken, item.installationRevision).Scan(&activeVersionID, &proposedVersionID, &currentRevision, &currentRaw, &publishedAt)
	if err != nil {
		return coreextension.VersionRecord{}, err
	}
	return validateNodeCleanupVersions(item, activeVersionID, proposedVersionID, currentRevision, currentRaw, publishedAt)
}

func validateNodeCleanupVersions(item nodeArtifactCleanupItem, activeVersionID, proposedVersionID string, currentRevision int64, currentRaw []byte, publishedAt *time.Time) (coreextension.VersionRecord, error) {
	var intentVersion, currentVersion coreextension.VersionRecord
	if uuid.Validate(item.cleanupID) != nil || uuid.Validate(item.installationID) != nil || uuid.Validate(item.versionID) != nil || uuid.Validate(item.cleanupToken) != nil || item.installationRevision < 1 || currentRevision < item.installationRevision || activeVersionID == item.versionID || proposedVersionID == item.versionID || json.Unmarshal(item.versionRaw, &intentVersion) != nil || json.Unmarshal(currentRaw, &currentVersion) != nil {
		return coreextension.VersionRecord{}, coreextension.ErrConflict
	}
	if intentVersion.VersionID != item.versionID || intentVersion.ArtifactDigest != item.artifactDigest || intentVersion.ArtifactCleanupToken != item.cleanupToken || intentVersion.NodeArtifact == nil || intentVersion.NodeArtifact.ArtifactDigest != item.artifactDigest || currentVersion.VersionID != intentVersion.VersionID || currentVersion.ArtifactDigest != intentVersion.ArtifactDigest || currentVersion.ArtifactCleanupToken != intentVersion.ArtifactCleanupToken || currentVersion.NodeArtifact == nil || currentVersion.NodeArtifact.ArtifactDigest != item.artifactDigest {
		return coreextension.VersionRecord{}, coreextension.ErrConflict
	}
	if publishedAt == nil || intentVersion.PublishedAt.IsZero() || currentVersion.PublishedAt.IsZero() {
		return coreextension.VersionRecord{}, coreextension.ErrConflict
	}
	return intentVersion, nil
}

func (c *CoreExtensionArtifactCleaner) finalizeNodeCleanup(ctx context.Context, item nodeArtifactCleanupItem) error {
	tx, err := c.Store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var activeVersionID, proposedVersionID string
	var currentRevision int64
	var currentRaw []byte
	var publishedAt *time.Time
	if err = tx.QueryRow(ctx, `SELECT COALESCE(i.active_version_id::text,''),COALESCE(i.proposed_version_id::text,''),i.revision,v.version_json,v.published_at
		FROM core_extension_node_artifact_cleanup c
		JOIN core_extension_installations i ON i.installation_id=c.installation_id
		JOIN core_extension_versions v ON v.installation_id=c.installation_id AND v.version_id=c.version_id
		WHERE c.cleanup_id=$1 AND c.state='running' AND c.installation_id=$2 AND c.version_id=$3
		  AND c.artifact_digest=$4 AND c.cleanup_token=$5 AND c.installation_revision=$6
		FOR UPDATE OF c,i,v`, item.cleanupID, item.installationID, item.versionID, item.artifactDigest, item.cleanupToken, item.installationRevision).Scan(&activeVersionID, &proposedVersionID, &currentRevision, &currentRaw, &publishedAt); err != nil {
		return err
	}
	_, err = validateNodeCleanupVersions(item, activeVersionID, proposedVersionID, currentRevision, currentRaw, publishedAt)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, `core_extension_install_quota`); err != nil {
		return err
	}
	var currentVersion coreextension.VersionRecord
	if json.Unmarshal(currentRaw, &currentVersion) != nil {
		return coreextension.ErrConflict
	}
	currentVersion.PublishedAt = time.Time{}
	updatedRaw, marshalErr := json.Marshal(currentVersion)
	if marshalErr != nil {
		return coreextension.ErrConflict
	}
	versionTag, updateErr := tx.Exec(ctx, `UPDATE core_extension_versions
		SET version_json=$3,artifact_bytes=0,file_count=0,lifecycle_scripts_disabled=false,native_addons_absent=false,published_at=NULL
		WHERE installation_id=$1 AND version_id=$2 AND published_at IS NOT NULL`, item.installationID, item.versionID, updatedRaw)
	if updateErr != nil || versionTag.RowsAffected() != 1 {
		if updateErr != nil {
			return updateErr
		}
		return coreextension.ErrConflict
	}
	cleanupTag, err := tx.Exec(ctx, `UPDATE core_extension_node_artifact_cleanup
		SET state='succeeded',last_error='',completed_at=clock_timestamp(),updated_at=clock_timestamp()
		WHERE cleanup_id=$1 AND state='running'`, item.cleanupID)
	if err != nil || cleanupTag.RowsAffected() != 1 {
		if err != nil {
			return err
		}
		return coreextension.ErrConflict
	}
	return tx.Commit(ctx)
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
