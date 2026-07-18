package installer

import (
	"fmt"
	"path/filepath"
	"strings"
)

const (
	// ArtifactRoot is the only root materialized by the signed Worker
	// bootstrap. Knowledge's fixed installer consumes the exact files from
	// this canonical digest-locked directory; it never copies from an
	// installer-specific staging surface.
	ArtifactRoot        = "/usr/local/share/dirextalk-worker/artifacts"
	InstallRoot         = "/opt/dirextalk/knowledge"
	ReleaseRoot         = "/opt/dirextalk/knowledge/releases/v1"
	PersistentRoot      = "/var/lib/dirextalk-knowledge"
	RuntimeRoot         = "/run/dirextalk-knowledge"
	SocketPath          = RuntimeRoot + "/adapter.sock"
	APIKeySourcePath    = "/etc/dirextalk-service-secrets/qdrant-api-key"
	APIKeyRuntimePath   = PersistentRoot + "/secrets/qdrant-api-key"
	QdrantArchivePath   = ArtifactRoot + "/qdrant-x86_64-unknown-linux-musl.tar.gz"
	AdapterArchivePath  = ArtifactRoot + "/dirextalk-knowledge-adapter.tar.gz"
	ModelArchivePath    = ArtifactRoot + "/multilingual-e5-small.tar.gz"
	ProvenancePath      = ArtifactRoot + "/provenance-v1.json"
	BackupRoot          = PersistentRoot + "/backups/v1"
	BackupCurrentRoot   = BackupRoot + "/current"
	BackupPreviousRoot  = BackupRoot + "/.previous-backup"
	BackupStageRoot     = BackupRoot + "/.next"
	BackupJournalPath   = BackupRoot + "/rotation-journal.json"
	RestoreStageRoot    = BackupRoot + "/.restore"
	RestorePreviousRoot = BackupRoot + "/.previous"
	RestoreJournalPath  = BackupRoot + "/restore-journal.json"
	// LifecycleLockPath remains outside every lifecycle cleanup root. Destroy
	// must not unlink the held lock and let a concurrent invocation acquire a
	// different inode while fixed-root removal is still in progress.
	LifecycleLockRoot = "/run/dirextalk-knowledge-lifecycle"
	LifecycleLockPath = LifecycleLockRoot + "/lifecycle.lock"
	QdrantConfigPath  = "/etc/dirextalk-knowledge/qdrant.yaml"
	SysusersPath      = "/usr/lib/sysusers.d/dirextalk-knowledge.conf"
	TmpfilesPath      = "/usr/lib/tmpfiles.d/dirextalk-knowledge.conf"
	QdrantUnitPath    = "/etc/systemd/system/dirextalk-qdrant.service"
	AdapterUnitPath   = "/etc/systemd/system/dirextalk-knowledge-adapter.service"
)

// Paths maps reviewed absolute production paths beneath a temporary test root.
// The production CLI always uses an empty Root and offers no path option.
type Paths struct {
	Root string
}

func ProductionPaths() Paths { return Paths{} }

func TestPaths(root string) (Paths, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
		return Paths{}, fmt.Errorf("test root must be a non-root absolute path")
	}
	return Paths{Root: filepath.Clean(root)}, nil
}

func (p Paths) Resolve(absolute string) string {
	if !filepath.IsAbs(absolute) || filepath.Clean(absolute) == string(filepath.Separator) {
		panic("installer path is not a reviewed absolute path")
	}
	if p.Root == "" {
		return filepath.Clean(absolute)
	}
	return filepath.Join(p.Root, strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)))
}
