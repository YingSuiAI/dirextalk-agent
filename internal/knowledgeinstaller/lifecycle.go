package installer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	backupSchemaV1               = "dirextalk.knowledge.backup/v1"
	backupRotationSchema         = "dirextalk.knowledge.backup-rotation/v1"
	backupRotationStaged         = "staged"
	backupRotationPrevious       = "previous"
	backupRotationPromoted       = "promoted"
	restoreJournalSchema         = "dirextalk.knowledge.restore-journal/v1"
	restorePrepared              = "prepared"
	restoreSwapped               = "swapped"
	maxBackupEntries             = 1_000_000
	maxBackupBytes         int64 = 1 << 40
)

type backupEntry struct {
	Path      string `json:"path"`
	Directory bool   `json:"directory"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256,omitempty"`
	Mode      uint32 `json:"mode"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
}

type backupManifest struct {
	SchemaVersion       string        `json:"schema_version"`
	ReleaseMarkerSHA256 string        `json:"release_marker_sha256"`
	Entries             []backupEntry `json:"entries"`
}

type backupRotationJournal struct {
	SchemaVersion  string `json:"schema_version"`
	Phase          string `json:"phase"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type restoreJournal struct {
	SchemaVersion  string `json:"schema_version"`
	Phase          string `json:"phase"`
	ManifestSHA256 string `json:"manifest_sha256"`
}

type lifecycleComponent struct {
	name string
	live string
}

type GenerationObserver struct {
	Paths Paths
}

func (observer GenerationObserver) CurrentGeneration(ctx context.Context) (string, error) {
	if ctx == nil || ctx.Err() != nil {
		return "", fmt.Errorf("observe Knowledge generation")
	}
	manifest, encoded, err := loadAndVerifyBackup(observer.Paths)
	if err != nil || verifyLiveKnowledgeGeneration(observer.Paths, manifest) != nil {
		return "", fmt.Errorf("live Knowledge generation does not match backup")
	}
	digest := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func verifyLiveKnowledgeGeneration(paths Paths, manifest backupManifest) error {
	if err := verifySnapshot(paths.Resolve(PersistentRoot), manifest); err != nil {
		return err
	}
	expected := make(map[string]struct{}, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		expected[entry.Path] = struct{}{}
	}
	seen := 0
	for _, component := range lifecycleComponents(paths) {
		err := filepath.Walk(component.live, func(path string, info os.FileInfo, walkErr error) error {
			if walkErr != nil || info.Mode()&os.ModeSymlink != 0 ||
				(!info.IsDir() && !info.Mode().IsRegular()) {
				return fmt.Errorf("live Knowledge generation is unsafe")
			}
			relative, err := filepath.Rel(component.live, path)
			if err != nil {
				return fmt.Errorf("resolve live Knowledge generation")
			}
			name := component.name
			if relative != "." {
				name += "/" + filepath.ToSlash(relative)
			}
			if _, ok := expected[name]; !ok {
				return fmt.Errorf("live Knowledge generation has an unexpected entry")
			}
			seen++
			return nil
		})
		if err != nil {
			return err
		}
	}
	if seen != len(expected) {
		return fmt.Errorf("live Knowledge generation is incomplete")
	}
	return nil
}

func lifecycleComponents(paths Paths) []lifecycleComponent {
	return []lifecycleComponent{
		{name: "adapter", live: paths.Resolve(PersistentRoot + "/adapter")},
		{name: "qdrant/storage", live: paths.Resolve(PersistentRoot + "/qdrant/storage")},
	}
}

func (i Installer) SemanticProbeV1(ctx context.Context) error {
	unlock, err := acquireLifecycleLock(i.Paths)
	if err != nil {
		return err
	}
	defer unlock()
	return i.semanticProbeV1Unlocked(ctx)
}

func (i Installer) semanticProbeV1Unlocked(ctx context.Context) error {
	if i.Probe == nil {
		return fmt.Errorf("semantic probe dependency is unavailable")
	}
	return SemanticProbeV1(ctx, i.Probe)
}

func (i Installer) StopV1(ctx context.Context) error {
	unlock, err := acquireLifecycleLock(i.Paths)
	if err != nil {
		return err
	}
	defer unlock()
	return i.stopV1Unlocked(ctx)
}

func (i Installer) stopV1Unlocked(ctx context.Context) error {
	if i.Runner == nil || ctx == nil {
		return fmt.Errorf("stop dependencies are incomplete")
	}
	if err := i.Runner.Run(ctx, "/usr/bin/systemctl", "stop", "dirextalk-knowledge-adapter.service"); err != nil {
		return err
	}
	return i.Runner.Run(ctx, "/usr/bin/systemctl", "stop", "dirextalk-qdrant.service")
}

func (i Installer) BackupV1(ctx context.Context) error {
	if i.Runner == nil || ctx == nil {
		return fmt.Errorf("backup dependencies are incomplete")
	}
	unlock, err := acquireLifecycleLock(i.Paths)
	if err != nil {
		return err
	}
	defer unlock()
	return i.backupV1Unlocked(ctx)
}

func (i Installer) backupV1Unlocked(ctx context.Context) error {
	if err := validateLifecycleBoundary(i.Paths); err != nil {
		return err
	}
	if err := i.stopV1Unlocked(ctx); err != nil {
		return errors.Join(err, i.restartV1Unlocked(ctx))
	}
	backupErr := createBackup(i.Paths)
	restartErr := i.restartV1Unlocked(ctx)
	return errors.Join(backupErr, restartErr)
}

func (i Installer) RestoreV1(ctx context.Context) error {
	if i.Runner == nil || i.Probe == nil || ctx == nil {
		return fmt.Errorf("restore dependencies are incomplete")
	}
	unlock, err := acquireLifecycleLock(i.Paths)
	if err != nil {
		return err
	}
	defer unlock()
	return i.restoreV1Unlocked(ctx)
}

func (i Installer) restoreV1Unlocked(ctx context.Context) error {
	manifest, manifestBytes, err := loadAndVerifyBackup(i.Paths)
	if err != nil {
		return err
	}
	if recovered, err := recoverRestore(i, ctx, manifest, manifestBytes); err != nil {
		return err
	} else if recovered {
		return nil
	}
	if err := prepareRestore(i.Paths, manifest, manifestBytes); err != nil {
		return err
	}
	if err := i.stopV1Unlocked(ctx); err != nil {
		_ = cleanupRestore(i.Paths)
		return errors.Join(err, i.restartV1Unlocked(ctx))
	}
	if err := swapRestore(i.Paths, manifestBytes); err != nil {
		rollbackErr := rollbackRestore(i.Paths)
		restartErr := i.restartV1Unlocked(ctx)
		return errors.Join(err, rollbackErr, restartErr)
	}
	verifyErr := i.restartV1Unlocked(ctx)
	if verifyErr == nil {
		verifyErr = i.semanticProbeV1Unlocked(ctx)
	}
	if verifyErr != nil {
		stopErr := i.stopV1Unlocked(ctx)
		if stopErr != nil {
			return errors.Join(verifyErr, stopErr)
		}
		rollbackErr := rollbackRestore(i.Paths)
		var recoveryBackupErr error
		if rollbackErr == nil {
			recoveryBackupErr = createBackup(i.Paths)
		}
		restartErr := i.restartV1Unlocked(ctx)
		var recoveryProbeErr error
		if rollbackErr == nil && recoveryBackupErr == nil && restartErr == nil {
			recoveryProbeErr = i.semanticProbeV1Unlocked(ctx)
		}
		if rollbackErr == nil && recoveryBackupErr == nil && restartErr == nil && recoveryProbeErr == nil {
			return nil
		}
		return errors.Join(verifyErr, rollbackErr, restartErr, recoveryBackupErr, recoveryProbeErr)
	}
	return cleanupRestore(i.Paths)
}

func (i Installer) UpgradeV1(ctx context.Context) error {
	if i.Runner == nil || i.Identities == nil || i.Materializer == nil || i.Probe == nil || ctx == nil {
		return fmt.Errorf("upgrade dependencies are incomplete")
	}
	unlock, err := acquireLifecycleLock(i.Paths)
	if err != nil {
		return err
	}
	defer unlock()
	if err := validateFixedInstallBoundary(i.Paths); err != nil {
		return err
	}
	if err := i.backupV1Unlocked(ctx); err != nil {
		return err
	}
	if err := i.installV1Unlocked(ctx); err != nil {
		return errors.Join(err, i.restoreV1Unlocked(ctx))
	}
	return nil
}

func (i Installer) RollbackV1(ctx context.Context) error {
	if i.Runner == nil || i.Probe == nil || ctx == nil {
		return fmt.Errorf("rollback dependencies are incomplete")
	}
	unlock, err := acquireLifecycleLock(i.Paths)
	if err != nil {
		return err
	}
	defer unlock()
	return i.restoreV1Unlocked(ctx)
}

func (i Installer) DestroyV1(ctx context.Context) error {
	if i.Runner == nil || ctx == nil {
		return fmt.Errorf("destroy dependencies are incomplete")
	}
	unlock, err := acquireLifecycleLock(i.Paths)
	if err != nil {
		return err
	}
	defer unlock()
	return i.destroyV1Unlocked(ctx)
}

func (i Installer) destroyV1Unlocked(ctx context.Context) error {
	units := []struct {
		path string
		name string
		data string
	}{{AdapterUnitPath, "dirextalk-knowledge-adapter.service", renderAdapterUnit()},
		{QdrantUnitPath, "dirextalk-qdrant.service", renderQdrantUnit()}}
	present := make([]bool, len(units))
	for index, unit := range units {
		found, err := validateDestroyUnit(i.Paths, unit.path, unit.data)
		if err != nil {
			return err
		}
		present[index] = found
	}
	if !present[0] || !present[1] {
		if present[0] || present[1] {
			return fmt.Errorf("fixed service unit drift")
		}
		for _, path := range []string{RuntimeRoot, PersistentRoot, InstallRoot, "/etc/dirextalk-knowledge", SysusersPath, TmpfilesPath} {
			if exists, err := pathExists(i.Paths.Resolve(path)); err != nil {
				return fmt.Errorf("inspect Knowledge-owned path before destroy")
			} else if exists {
				return fmt.Errorf("fixed service unit drift")
			}
		}
		return i.Runner.Run(ctx, "/usr/bin/systemctl", "daemon-reload")
	}
	for _, unit := range units {
		if runErr := i.Runner.Run(ctx, "/usr/bin/systemctl", "stop", unit.name); runErr != nil {
			return runErr
		}
		if runErr := i.Runner.Run(ctx, "/usr/bin/systemctl", "disable", unit.name); runErr != nil {
			return runErr
		}
		state, stateErr := i.Runner.UnitState(ctx, unit.name)
		if stateErr != nil || state.LoadState != "loaded" || state.ActiveState != "inactive" {
			return fmt.Errorf("fixed service did not reach inactive state")
		}
	}
	for _, path := range []string{RuntimeRoot, PersistentRoot, InstallRoot, "/etc/dirextalk-knowledge", QdrantUnitPath, AdapterUnitPath, SysusersPath, TmpfilesPath} {
		if err := removeExactLifecyclePath(i.Paths, path); err != nil {
			return err
		}
	}
	return i.Runner.Run(ctx, "/usr/bin/systemctl", "daemon-reload")
}

func validateDestroyUnit(paths Paths, logical, expected string) (bool, error) {
	path := paths.Resolve(logical)
	file, err := openRegularNoFollow(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("fixed service unit drift")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0o644 {
		return false, fmt.Errorf("fixed service unit drift")
	}
	uid, gid, ok := ownership(info)
	expectedUID, expectedGID := uint32(0), uint32(0)
	if paths.Root != "" {
		expectedUID, expectedGID = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	payload, readErr := io.ReadAll(io.LimitReader(file, 64<<10))
	if readErr != nil || len(payload) >= 64<<10 || !ok || uid != expectedUID || gid != expectedGID || string(payload) != expected {
		return false, fmt.Errorf("fixed service unit drift")
	}
	return true, nil
}

func validateLifecycleBoundary(paths Paths) error {
	for _, component := range lifecycleComponents(paths) {
		info, err := os.Lstat(component.live)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("live Knowledge state boundary is invalid")
		}
	}
	marker, err := openRegularNoFollow(paths.Resolve(ReleaseRoot + "/.provenance-sha256"))
	if err != nil {
		return fmt.Errorf("installed release boundary is invalid")
	}
	return marker.Close()
}

func acquireLifecycleLock(paths Paths) (func(), error) {
	lockPath := paths.Resolve(LifecycleLockPath)
	lockRoot := paths.Resolve(LifecycleLockRoot)
	if err := ensureSecureOwnedDirectory(paths, LifecycleLockRoot, 0o700, 0, 0); err != nil {
		return nil, err
	}
	expectedUID, expectedGID := uint32(0), uint32(0)
	if paths.Root != "" {
		expectedUID, expectedGID = uint32(os.Geteuid()), uint32(os.Getegid())
	}
	rootInfo, err := os.Lstat(lockRoot)
	if err != nil {
		return nil, fmt.Errorf("unsafe lifecycle lock root")
	}
	rootUID, rootGID, rootOwnership := ownership(rootInfo)
	if !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 || rootInfo.Mode().Perm() != 0o700 ||
		!rootOwnership || rootUID != expectedUID || rootGID != expectedGID {
		return nil, fmt.Errorf("unsafe lifecycle lock root")
	}
	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lifecycle lock")
	}
	info, err := file.Stat()
	uid, gid, owned := ownership(info)
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !owned ||
		uid != expectedUID || gid != expectedGID || !statOK || stat.Nlink != 1 {
		file.Close()
		return nil, fmt.Errorf("unsafe lifecycle lock")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("acquire lifecycle lock")
	}
	pathInfo, err := os.Lstat(lockPath)
	if err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
		return nil, fmt.Errorf("lifecycle lock inode changed")
	}
	pathStat, pathStatOK := pathInfo.Sys().(*syscall.Stat_t)
	if pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.Mode().IsRegular() ||
		!pathStatOK || pathStat.Dev != stat.Dev || pathStat.Ino != stat.Ino {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
		return nil, fmt.Errorf("lifecycle lock inode changed")
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}, nil
}

func createBackup(paths Paths) error {
	if err := recoverBackupRotation(paths); err != nil {
		return err
	}
	stage := paths.Resolve(BackupStageRoot)
	current := paths.Resolve(BackupCurrentRoot)
	previous := paths.Resolve(BackupPreviousRoot)
	if err := removeExactResolved(paths, BackupStageRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return fmt.Errorf("create backup stage")
	}
	manifest := backupManifest{SchemaVersion: backupSchemaV1}
	markerBytes, err := os.ReadFile(paths.Resolve(ReleaseRoot + "/.provenance-sha256"))
	if err != nil {
		return fmt.Errorf("read installed release marker")
	}
	markerDigest := sha256.Sum256(markerBytes)
	manifest.ReleaseMarkerSHA256 = hex.EncodeToString(markerDigest[:])
	for _, component := range lifecycleComponents(paths) {
		entries, copyErr := snapshotTree(component.live, filepath.Join(stage, filepath.FromSlash(component.name)), component.name)
		if copyErr != nil {
			_ = removeExactResolved(paths, BackupStageRoot)
			return copyErr
		}
		manifest.Entries = append(manifest.Entries, entries...)
	}
	sort.Slice(manifest.Entries, func(a, b int) bool { return manifest.Entries[a].Path < manifest.Entries[b].Path })
	encoded, err := encodeBackupManifest(manifest)
	if err != nil {
		return err
	}
	if err := writeExclusiveSynced(filepath.Join(stage, "manifest.json"), encoded, 0o600); err != nil {
		return err
	}
	if err := syncSnapshotDirectories(stage, manifest); err != nil {
		return err
	}
	if existing, _, loadErr := loadBackupManifest(filepath.Join(current, "manifest.json")); loadErr == nil {
		existingBytes, _ := encodeBackupManifest(existing)
		if string(existingBytes) == string(encoded) && verifySnapshot(current, existing) == nil {
			return removeExactResolved(paths, BackupStageRoot)
		}
	}
	manifestDigest := sha256.Sum256(encoded)
	digest := hex.EncodeToString(manifestDigest[:])
	if err := writeBackupRotationJournal(paths, backupRotationJournal{
		SchemaVersion: backupRotationSchema, Phase: backupRotationStaged, ManifestSHA256: digest,
	}); err != nil {
		return err
	}
	if _, err := os.Lstat(current); err == nil {
		if err := os.Rename(current, previous); err != nil {
			return fmt.Errorf("rotate durable backup")
		}
		if err := syncDirectory(paths.Resolve(BackupRoot)); err != nil {
			return err
		}
		if err := writeBackupRotationJournal(paths, backupRotationJournal{
			SchemaVersion: backupRotationSchema, Phase: backupRotationPrevious, ManifestSHA256: digest,
		}); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect durable backup")
	}
	if err := os.Rename(stage, current); err != nil {
		return fmt.Errorf("promote durable backup")
	}
	if err := syncDirectory(filepath.Dir(current)); err != nil {
		return err
	}
	if err := writeBackupRotationJournal(paths, backupRotationJournal{
		SchemaVersion: backupRotationSchema, Phase: backupRotationPromoted, ManifestSHA256: digest,
	}); err != nil {
		return err
	}
	if err := verifyBackupRoot(current, digest); err != nil {
		return err
	}
	return finishBackupRotation(paths)
}

func recoverBackupRotation(paths Paths) error {
	journal, found, err := loadBackupRotationJournal(paths)
	if err != nil {
		return err
	}
	current, previous, stage := paths.Resolve(BackupCurrentRoot), paths.Resolve(BackupPreviousRoot), paths.Resolve(BackupStageRoot)
	if !found {
		currentExists, currentErr := pathExists(current)
		previousExists, previousErr := pathExists(previous)
		if currentErr != nil || previousErr != nil {
			return fmt.Errorf("inspect backup recovery roots")
		}
		if !currentExists && previousExists {
			if err := os.Rename(previous, current); err != nil {
				return fmt.Errorf("recover last-known-good backup")
			}
			return syncDirectory(paths.Resolve(BackupRoot))
		}
		if currentExists && previousExists {
			if err := verifyBackupRoot(current, ""); err != nil {
				if removeErr := os.RemoveAll(current); removeErr != nil || os.Rename(previous, current) != nil {
					return fmt.Errorf("recover last-known-good backup")
				}
				return syncDirectory(paths.Resolve(BackupRoot))
			}
			if err := removeExactResolved(paths, BackupPreviousRoot); err != nil {
				return err
			}
		}
		return removeExactResolved(paths, BackupStageRoot)
	}
	switch journal.Phase {
	case backupRotationStaged:
		currentExists, currentErr := pathExists(current)
		previousExists, previousErr := pathExists(previous)
		if currentErr != nil || previousErr != nil {
			return fmt.Errorf("inspect staged backup recovery roots")
		}
		if currentExists && previousExists {
			return fmt.Errorf("ambiguous staged backup rotation")
		}
		if currentExists {
			if err := os.Rename(current, previous); err != nil {
				return fmt.Errorf("resume backup rotation")
			}
			previousExists = true
			if err := syncDirectory(paths.Resolve(BackupRoot)); err != nil {
				return err
			}
			if err := writeBackupRotationJournal(paths, backupRotationJournal{
				SchemaVersion: backupRotationSchema, Phase: backupRotationPrevious, ManifestSHA256: journal.ManifestSHA256,
			}); err != nil {
				return err
			}
		}
		if _, err := os.Lstat(stage); err != nil {
			if previousExists {
				return restorePreviousBackup(paths, fmt.Errorf("staged backup is unavailable"))
			}
			return fmt.Errorf("staged backup is unavailable")
		}
		if err := os.Rename(stage, current); err != nil {
			return fmt.Errorf("resume backup promotion")
		}
	case backupRotationPrevious:
		currentExists, currentErr := pathExists(current)
		if currentErr != nil {
			return fmt.Errorf("inspect promoted backup recovery root")
		}
		if !currentExists {
			if _, err := os.Lstat(stage); err != nil {
				return restorePreviousBackup(paths, fmt.Errorf("staged backup is unavailable"))
			}
			if err := os.Rename(stage, current); err != nil {
				return fmt.Errorf("resume backup promotion")
			}
		}
	case backupRotationPromoted:
	default:
		return fmt.Errorf("invalid backup rotation phase")
	}
	if err := syncDirectory(paths.Resolve(BackupRoot)); err != nil {
		return err
	}
	if err := writeBackupRotationJournal(paths, backupRotationJournal{
		SchemaVersion: backupRotationSchema, Phase: backupRotationPromoted, ManifestSHA256: journal.ManifestSHA256,
	}); err != nil {
		return err
	}
	if err := verifyBackupRoot(current, journal.ManifestSHA256); err != nil {
		return restorePreviousBackup(paths, err)
	}
	return finishBackupRotation(paths)
}

func restorePreviousBackup(paths Paths, cause error) error {
	current, previous := paths.Resolve(BackupCurrentRoot), paths.Resolve(BackupPreviousRoot)
	if _, err := os.Lstat(previous); err != nil {
		return errors.Join(cause, fmt.Errorf("last-known-good backup is unavailable"))
	}
	if err := os.RemoveAll(current); err != nil || os.Rename(previous, current) != nil {
		return errors.Join(cause, fmt.Errorf("restore last-known-good backup"))
	}
	if err := syncDirectory(paths.Resolve(BackupRoot)); err != nil {
		return errors.Join(cause, err)
	}
	_ = removeExactResolved(paths, BackupStageRoot)
	_ = removeExactResolved(paths, BackupJournalPath)
	return cause
}

func finishBackupRotation(paths Paths) error {
	if err := removeExactResolved(paths, BackupPreviousRoot); err != nil {
		return err
	}
	if err := removeExactResolved(paths, BackupStageRoot); err != nil {
		return err
	}
	return removeExactResolved(paths, BackupJournalPath)
}

func verifyBackupRoot(root, expectedDigest string) error {
	manifest, encoded, err := loadBackupManifest(filepath.Join(root, "manifest.json"))
	if err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	if expectedDigest != "" && hex.EncodeToString(digest[:]) != expectedDigest {
		return fmt.Errorf("backup rotation manifest mismatch")
	}
	return verifySnapshot(root, manifest)
}

func pathExists(path string) (bool, error) {
	_, err := os.Lstat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func writeBackupRotationJournal(paths Paths, value backupRotationJournal) error {
	if value.SchemaVersion != backupRotationSchema ||
		(value.Phase != backupRotationStaged && value.Phase != backupRotationPrevious && value.Phase != backupRotationPromoted) ||
		!validLifecycleSHA256(value.ManifestSHA256) {
		return fmt.Errorf("invalid backup rotation journal")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode backup rotation journal")
	}
	path := paths.Resolve(BackupJournalPath)
	if err := writeManagedFile(path, append(payload, '\n'), 0o600, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func loadBackupRotationJournal(paths Paths) (backupRotationJournal, bool, error) {
	path := paths.Resolve(BackupJournalPath)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return backupRotationJournal{}, false, nil
	}
	file, err := openRegularNoFollow(path)
	if err != nil {
		return backupRotationJournal{}, false, fmt.Errorf("open backup rotation journal")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4096))
	decoder.DisallowUnknownFields()
	var value backupRotationJournal
	if err := decoder.Decode(&value); err != nil || requireJSONEOF(decoder) != nil ||
		value.SchemaVersion != backupRotationSchema ||
		(value.Phase != backupRotationStaged && value.Phase != backupRotationPrevious && value.Phase != backupRotationPromoted) ||
		!validLifecycleSHA256(value.ManifestSHA256) {
		return backupRotationJournal{}, false, fmt.Errorf("invalid backup rotation journal")
	}
	return value, true, nil
}

func snapshotTree(source, destination, prefix string) ([]backupEntry, error) {
	entries := make([]backupEntry, 0)
	var total int64
	err := filepath.WalkDir(source, func(path string, item os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("read live Knowledge state")
		}
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("live Knowledge state contains an unsupported entry")
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return fmt.Errorf("resolve live Knowledge state")
		}
		name := prefix
		if relative != "." {
			name += "/" + filepath.ToSlash(relative)
		}
		uid, gid, ok := ownership(info)
		if !ok {
			return fmt.Errorf("inspect live Knowledge ownership")
		}
		entry := backupEntry{Path: name, Directory: info.IsDir(), Mode: uint32(info.Mode().Perm()), UID: uid, GID: gid}
		target := destination
		if relative != "." {
			target = filepath.Join(destination, relative)
		}
		if info.IsDir() {
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return fmt.Errorf("create backup directory")
			}
			if err := applyOwnershipAndMode(target, entry); err != nil {
				return err
			}
		} else {
			if len(entries) >= maxBackupEntries || info.Size() < 0 || total > maxBackupBytes-info.Size() {
				return fmt.Errorf("Knowledge backup exceeds fixed bounds")
			}
			total += info.Size()
			entry.Size = info.Size()
			digest, err := copyRegularNoFollow(path, target, entry)
			if err != nil {
				return err
			}
			entry.SHA256 = digest
		}
		entries = append(entries, entry)
		if len(entries) > maxBackupEntries {
			return fmt.Errorf("Knowledge backup exceeds fixed bounds")
		}
		return nil
	})
	return entries, err
}

func copyRegularNoFollow(source, destination string, entry backupEntry) (string, error) {
	input, err := openRegularNoFollow(source)
	if err != nil {
		return "", fmt.Errorf("open live Knowledge file")
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return "", fmt.Errorf("create backup parent")
	}
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(entry.Mode))
	if err != nil {
		return "", fmt.Errorf("create backup file")
	}
	ok := false
	defer func() {
		_ = output.Close()
		if !ok {
			_ = os.Remove(destination)
		}
	}()
	digest := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(output, digest), input)
	if copyErr != nil || written != entry.Size || output.Sync() != nil || applyOwnershipAndModeFile(output, entry) != nil || output.Close() != nil {
		return "", fmt.Errorf("copy live Knowledge file")
	}
	ok = true
	return hex.EncodeToString(digest.Sum(nil)), nil
}

func loadAndVerifyBackup(paths Paths) (backupManifest, []byte, error) {
	manifest, encoded, err := loadBackupManifest(paths.Resolve(BackupCurrentRoot + "/manifest.json"))
	if err != nil {
		return backupManifest{}, nil, err
	}
	markerBytes, err := os.ReadFile(paths.Resolve(ReleaseRoot + "/.provenance-sha256"))
	markerDigest := sha256.Sum256(markerBytes)
	if err != nil || manifest.ReleaseMarkerSHA256 != hex.EncodeToString(markerDigest[:]) {
		return backupManifest{}, nil, fmt.Errorf("backup release binding does not match")
	}
	if err := verifySnapshot(paths.Resolve(BackupCurrentRoot), manifest); err != nil {
		return backupManifest{}, nil, err
	}
	return manifest, encoded, nil
}

func loadBackupManifest(path string) (backupManifest, []byte, error) {
	file, err := openRegularNoFollow(path)
	if err != nil {
		return backupManifest{}, nil, fmt.Errorf("open durable backup manifest")
	}
	defer file.Close()
	payload, err := io.ReadAll(io.LimitReader(file, 32<<20))
	if err != nil || len(payload) == 0 || len(payload) >= 32<<20 {
		return backupManifest{}, nil, fmt.Errorf("read durable backup manifest")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var manifest backupManifest
	if err := decoder.Decode(&manifest); err != nil || requireJSONEOF(decoder) != nil || validateBackupManifest(manifest) != nil {
		return backupManifest{}, nil, fmt.Errorf("invalid durable backup manifest")
	}
	canonical, err := encodeBackupManifest(manifest)
	if err != nil || string(canonical) != string(payload) {
		return backupManifest{}, nil, fmt.Errorf("non-canonical durable backup manifest")
	}
	return manifest, canonical, nil
}

func validateBackupManifest(manifest backupManifest) error {
	if manifest.SchemaVersion != backupSchemaV1 || !validLifecycleSHA256(manifest.ReleaseMarkerSHA256) || len(manifest.Entries) < 2 || len(manifest.Entries) > maxBackupEntries {
		return fmt.Errorf("invalid backup manifest")
	}
	previous := ""
	var total int64
	for _, entry := range manifest.Entries {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(entry.Path)))
		if clean != entry.Path || entry.Path <= previous || (entry.Path != "adapter" && !strings.HasPrefix(entry.Path, "adapter/") && entry.Path != "qdrant/storage" && !strings.HasPrefix(entry.Path, "qdrant/storage/")) || entry.Mode > 0o777 {
			return fmt.Errorf("invalid backup entry")
		}
		if entry.Directory {
			if entry.Size != 0 || entry.SHA256 != "" {
				return fmt.Errorf("invalid backup directory")
			}
		} else {
			if entry.Size < 0 || !validLifecycleSHA256(entry.SHA256) || total > maxBackupBytes-entry.Size {
				return fmt.Errorf("invalid backup file")
			}
			total += entry.Size
		}
		previous = entry.Path
	}
	return nil
}

func encodeBackupManifest(manifest backupManifest) ([]byte, error) {
	if err := validateBackupManifest(manifest); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(manifest)
	if err != nil {
		return nil, fmt.Errorf("encode backup manifest")
	}
	return append(payload, '\n'), nil
}

func verifySnapshot(root string, manifest backupManifest) error {
	for _, entry := range manifest.Entries {
		path := filepath.Join(root, filepath.FromSlash(entry.Path))
		if !withinDirectory(root, path) {
			return fmt.Errorf("backup entry escapes fixed root")
		}
		info, err := os.Lstat(path)
		uid, gid, owned := ownership(info)
		if err != nil || !owned || info.Mode()&os.ModeSymlink != 0 || info.IsDir() != entry.Directory || uint32(info.Mode().Perm()) != entry.Mode || uid != entry.UID || gid != entry.GID {
			return fmt.Errorf("durable backup metadata mismatch")
		}
		if !entry.Directory {
			size, digest, err := fileDigest(path)
			if err != nil || size != entry.Size || digest != entry.SHA256 {
				return fmt.Errorf("durable backup content mismatch")
			}
		}
	}
	return nil
}

func prepareRestore(paths Paths, manifest backupManifest, manifestBytes []byte) error {
	if err := removeExactResolved(paths, RestoreStageRoot); err != nil {
		return err
	}
	stage := paths.Resolve(RestoreStageRoot)
	if err := os.MkdirAll(stage, 0o700); err != nil {
		return fmt.Errorf("create restore stage")
	}
	for _, entry := range manifest.Entries {
		source := filepath.Join(paths.Resolve(BackupCurrentRoot), filepath.FromSlash(entry.Path))
		target := filepath.Join(stage, filepath.FromSlash(entry.Path))
		if entry.Directory {
			if err := os.MkdirAll(target, os.FileMode(entry.Mode)); err != nil || applyOwnershipAndMode(target, entry) != nil {
				return fmt.Errorf("prepare restore directory")
			}
			continue
		}
		digest, err := copyRegularNoFollow(source, target, entry)
		if err != nil || digest != entry.SHA256 {
			return fmt.Errorf("prepare restore file")
		}
	}
	if err := verifySnapshot(stage, manifest); err != nil {
		return err
	}
	digest := sha256.Sum256(manifestBytes)
	return writeRestoreJournal(paths, restoreJournal{SchemaVersion: restoreJournalSchema, Phase: restorePrepared, ManifestSHA256: hex.EncodeToString(digest[:])})
}

func swapRestore(paths Paths, manifestBytes []byte) error {
	if err := removeExactResolved(paths, RestorePreviousRoot); err != nil {
		return err
	}
	previous := paths.Resolve(RestorePreviousRoot)
	if err := os.MkdirAll(previous, 0o700); err != nil {
		return fmt.Errorf("create restore rollback root")
	}
	for _, component := range lifecycleComponents(paths) {
		old := filepath.Join(previous, filepath.FromSlash(component.name))
		if err := os.MkdirAll(filepath.Dir(old), 0o700); err != nil {
			return fmt.Errorf("create restore rollback parent")
		}
		if err := os.Rename(component.live, old); err != nil {
			return fmt.Errorf("preserve live Knowledge state")
		}
		staged := filepath.Join(paths.Resolve(RestoreStageRoot), filepath.FromSlash(component.name))
		if err := os.Rename(staged, component.live); err != nil {
			return fmt.Errorf("promote restored Knowledge state")
		}
	}
	if err := syncRestoreMutation(paths); err != nil {
		return err
	}
	digest := sha256.Sum256(manifestBytes)
	return writeRestoreJournal(paths, restoreJournal{SchemaVersion: restoreJournalSchema, Phase: restoreSwapped, ManifestSHA256: hex.EncodeToString(digest[:])})
}

func recoverRestore(i Installer, ctx context.Context, manifest backupManifest, manifestBytes []byte) (bool, error) {
	journal, found, err := loadRestoreJournal(i.Paths)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	digest := sha256.Sum256(manifestBytes)
	if journal.ManifestSHA256 != hex.EncodeToString(digest[:]) {
		return false, fmt.Errorf("restore journal does not match durable backup")
	}
	if journal.Phase == restorePrepared {
		return false, rollbackRestore(i.Paths)
	}
	if journal.Phase != restoreSwapped {
		return false, fmt.Errorf("invalid restore journal phase")
	}
	liveRoot := i.Paths.Resolve(PersistentRoot)
	if verifyLiveSnapshot(liveRoot, manifest) == nil {
		if err := i.restartV1Unlocked(ctx); err == nil {
			if err := i.semanticProbeV1Unlocked(ctx); err == nil {
				return true, cleanupRestore(i.Paths)
			}
		}
	}
	stopErr := i.stopV1Unlocked(ctx)
	if stopErr != nil {
		return false, errors.Join(fmt.Errorf("recovered restore verification failed"), stopErr)
	}
	rollbackErr := rollbackRestore(i.Paths)
	var recoveryBackupErr error
	if rollbackErr == nil {
		recoveryBackupErr = createBackup(i.Paths)
	}
	restartErr := i.restartV1Unlocked(ctx)
	var recoveryProbeErr error
	if rollbackErr == nil && recoveryBackupErr == nil && restartErr == nil {
		recoveryProbeErr = i.semanticProbeV1Unlocked(ctx)
	}
	if rollbackErr == nil && recoveryBackupErr == nil && restartErr == nil && recoveryProbeErr == nil {
		return true, nil
	}
	return false, errors.Join(fmt.Errorf("recovered restore verification failed"), rollbackErr, restartErr,
		recoveryBackupErr, recoveryProbeErr)
}

func verifyLiveSnapshot(root string, manifest backupManifest) error {
	for _, entry := range manifest.Entries {
		path := filepath.Join(root, filepath.FromSlash(entry.Path))
		info, err := os.Lstat(path)
		uid, gid, owned := ownership(info)
		if err != nil || !owned || info.IsDir() != entry.Directory || info.Mode()&os.ModeSymlink != 0 || uint32(info.Mode().Perm()) != entry.Mode || uid != entry.UID || gid != entry.GID {
			return fmt.Errorf("restored state metadata mismatch")
		}
		if !entry.Directory {
			size, digest, err := fileDigest(path)
			if err != nil || size != entry.Size || digest != entry.SHA256 {
				return fmt.Errorf("restored state content mismatch")
			}
		}
	}
	return nil
}

func rollbackRestore(paths Paths) error {
	previous := paths.Resolve(RestorePreviousRoot)
	var result error
	for _, component := range lifecycleComponents(paths) {
		old := filepath.Join(previous, filepath.FromSlash(component.name))
		if _, err := os.Lstat(old); err == nil {
			if removeErr := os.RemoveAll(component.live); removeErr != nil {
				result = errors.Join(result, fmt.Errorf("remove failed restored state"))
				continue
			}
			if err := os.MkdirAll(filepath.Dir(component.live), 0o750); err != nil || os.Rename(old, component.live) != nil {
				result = errors.Join(result, fmt.Errorf("recover previous Knowledge state"))
			}
		} else if !os.IsNotExist(err) {
			result = errors.Join(result, fmt.Errorf("inspect previous Knowledge state"))
		}
	}
	if err := syncRestoreMutation(paths); err != nil {
		result = errors.Join(result, err)
	}
	if err := cleanupRestore(paths); err != nil {
		result = errors.Join(result, err)
	}
	return result
}

func cleanupRestore(paths Paths) error {
	var result error
	for _, path := range []string{RestoreStageRoot, RestorePreviousRoot, RestoreJournalPath} {
		if err := removeExactResolved(paths, path); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func writeRestoreJournal(paths Paths, value restoreJournal) error {
	if value.SchemaVersion != restoreJournalSchema || (value.Phase != restorePrepared && value.Phase != restoreSwapped) || !validLifecycleSHA256(value.ManifestSHA256) {
		return fmt.Errorf("invalid restore journal")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode restore journal")
	}
	path := paths.Resolve(RestoreJournalPath)
	if err := writeManagedFile(path, append(payload, '\n'), 0o600, os.Geteuid(), os.Getegid()); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func loadRestoreJournal(paths Paths) (restoreJournal, bool, error) {
	path := paths.Resolve(RestoreJournalPath)
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return restoreJournal{}, false, nil
	}
	file, err := openRegularNoFollow(path)
	if err != nil {
		return restoreJournal{}, false, fmt.Errorf("open restore journal")
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4096))
	decoder.DisallowUnknownFields()
	var value restoreJournal
	if err := decoder.Decode(&value); err != nil || requireJSONEOF(decoder) != nil || value.SchemaVersion != restoreJournalSchema ||
		(value.Phase != restorePrepared && value.Phase != restoreSwapped) || !validLifecycleSHA256(value.ManifestSHA256) {
		return restoreJournal{}, false, fmt.Errorf("invalid restore journal")
	}
	return value, true, nil
}

func writeExclusiveSynced(path string, payload []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("create lifecycle file")
	}
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(payload); err != nil || file.Sync() != nil || file.Close() != nil {
		return fmt.Errorf("persist lifecycle file")
	}
	ok = true
	return nil
}

func ownership(info os.FileInfo) (uint32, uint32, bool) {
	if info == nil {
		return 0, 0, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return stat.Uid, stat.Gid, true
}

func applyOwnershipAndMode(path string, entry backupEntry) error {
	if err := os.Chown(path, int(entry.UID), int(entry.GID)); err != nil || os.Chmod(path, os.FileMode(entry.Mode)) != nil {
		return fmt.Errorf("restore fixed metadata")
	}
	return nil
}

func applyOwnershipAndModeFile(file *os.File, entry backupEntry) error {
	if err := file.Chown(int(entry.UID), int(entry.GID)); err != nil || file.Chmod(os.FileMode(entry.Mode)) != nil {
		return fmt.Errorf("restore fixed file metadata")
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open lifecycle directory")
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync lifecycle directory")
	}
	return nil
}

func syncSnapshotDirectories(root string, manifest backupManifest) error {
	directories := map[string]struct{}{root: {}}
	for _, entry := range manifest.Entries {
		path := filepath.Join(root, filepath.FromSlash(entry.Path))
		if entry.Directory {
			directories[path] = struct{}{}
		}
		directories[filepath.Dir(path)] = struct{}{}
	}
	ordered := make([]string, 0, len(directories))
	for path := range directories {
		ordered = append(ordered, path)
	}
	sort.Slice(ordered, func(a, b int) bool {
		depthA, depthB := strings.Count(ordered[a], string(filepath.Separator)), strings.Count(ordered[b], string(filepath.Separator))
		if depthA == depthB {
			return ordered[a] < ordered[b]
		}
		return depthA > depthB
	})
	for _, path := range ordered {
		if err := syncDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func syncRestoreMutation(paths Paths) error {
	directories := map[string]struct{}{
		paths.Resolve(PersistentRoot):                  {},
		paths.Resolve(PersistentRoot + "/qdrant"):      {},
		paths.Resolve(RestorePreviousRoot):             {},
		paths.Resolve(RestorePreviousRoot + "/qdrant"): {},
		paths.Resolve(RestoreStageRoot):                {},
		paths.Resolve(RestoreStageRoot + "/qdrant"):    {},
	}
	var result error
	for path := range directories {
		if info, err := os.Lstat(path); err == nil && info.IsDir() {
			result = errors.Join(result, syncDirectory(path))
		} else if err != nil && !os.IsNotExist(err) {
			result = errors.Join(result, fmt.Errorf("inspect lifecycle directory"))
		}
	}
	return result
}

func removeExactResolved(paths Paths, logical string) error {
	return removeExactLifecyclePath(paths, logical)
}

func removeExactLifecyclePath(paths Paths, logical string) error {
	resolved := filepath.Clean(paths.Resolve(logical))
	if !filepath.IsAbs(logical) || logical == "/" || resolved == filepath.Clean(paths.Root) || resolved == "/" {
		return fmt.Errorf("refuse unsafe lifecycle cleanup")
	}
	if _, err := os.Lstat(resolved); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("inspect fixed lifecycle path")
	}
	if err := os.RemoveAll(resolved); err != nil {
		return fmt.Errorf("clean fixed lifecycle path")
	}
	return syncDirectory(filepath.Dir(resolved))
}

func validLifecycleSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && strings.ToLower(value) == value
}
