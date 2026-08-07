package execution

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

const stagedOpenResolve = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV

type stagedRemovalHooks struct {
	beforeTopRename  func(rootFD int, digest, tombstone string) error
	afterTopRename   func(rootFD int, digest, tombstone string) error
	afterEntryRemove func() error
}

// RemoveStagedArtifact removes exactly one immutable digest-addressed staging
// generation. cleanupToken is the durable generation fence: retries only
// continue its tombstone and never infer ownership from the digest name.
func RemoveStagedArtifact(root, digest, cleanupToken string) error {
	return removeStagedArtifact(root, digest, cleanupToken, nil)
}

func removeStagedArtifact(root, digest, cleanupToken string, hooks *stagedRemovalHooks) error {
	if !validStagedRootAndDigest(root, digest) || !validStagedCleanupToken(cleanupToken) {
		return core.ErrInvalid
	}
	rootFD, rootStat, owner, err := openStagedRoot(root)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	tombstone := stagedRemovalName(cleanupToken)
	completed := stagedRemovedName(cleanupToken)

	if exists, err := validateStagedMarker(rootFD, completed, rootStat.Dev, owner, true); err != nil {
		return err
	} else if exists {
		return nil
	}

	targetFD, targetStat, exists, err := openStagedDirectory(rootFD, tombstone, rootStat.Dev, owner)
	if err != nil {
		return err
	}
	if !exists {
		targetFD, targetStat, exists, err = openStagedDirectory(rootFD, digest, rootStat.Dev, owner)
		if err != nil {
			return err
		}
		if !exists {
			return unix.ENOENT
		}
		if hooks != nil && hooks.beforeTopRename != nil {
			if err := hooks.beforeTopRename(rootFD, digest, tombstone); err != nil {
				_ = unix.Close(targetFD)
				return err
			}
		}
		var current unix.Stat_t
		if err := unix.Fstatat(rootFD, digest, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = unix.Close(targetFD)
			return err
		}
		if !sameStagedIdentity(targetStat, current) {
			_ = unix.Close(targetFD)
			return core.ErrInvalid
		}
		if err := unix.Renameat2(rootFD, digest, rootFD, tombstone, unix.RENAME_NOREPLACE); err != nil {
			if !errors.Is(err, unix.EEXIST) {
				_ = unix.Close(targetFD)
				return err
			}
			ownedFD, ownedStat, owned, openErr := openStagedDirectory(rootFD, tombstone, rootStat.Dev, owner)
			if openErr != nil {
				_ = unix.Close(targetFD)
				return openErr
			}
			if owned {
				_ = unix.Close(ownedFD)
			}
			if !owned || !sameStagedIdentity(targetStat, ownedStat) {
				_ = unix.Close(targetFD)
				return core.ErrInvalid
			}
		}
		if err := unix.Fstatat(rootFD, tombstone, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			_ = unix.Close(targetFD)
			return err
		}
		if !sameStagedIdentity(targetStat, current) {
			_ = unix.Close(targetFD)
			return core.ErrInvalid
		}
		if hooks != nil && hooks.afterTopRename != nil {
			if err := hooks.afterTopRename(rootFD, digest, tombstone); err != nil {
				_ = unix.Close(targetFD)
				return err
			}
		}
	}
	return finishStagedArtifactRemoval(rootFD, rootStat, owner, tombstone, completed, targetFD, targetStat, hooks)
}

// ResumeStagedArtifactRemoval continues only a cleanupToken-owned tombstone.
// It never opens or claims a digest-addressed artifact path.
func ResumeStagedArtifactRemoval(root, cleanupToken string) error {
	if !validStagedRoot(root) || !validStagedCleanupToken(cleanupToken) {
		return core.ErrInvalid
	}
	rootFD, rootStat, owner, err := openStagedRoot(root)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	tombstone := stagedRemovalName(cleanupToken)
	completed := stagedRemovedName(cleanupToken)
	if exists, err := validateStagedMarker(rootFD, completed, rootStat.Dev, owner, true); err != nil {
		return err
	} else if exists {
		return nil
	}
	targetFD, targetStat, exists, err := openStagedDirectory(rootFD, tombstone, rootStat.Dev, owner)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	return finishStagedArtifactRemoval(rootFD, rootStat, owner, tombstone, completed, targetFD, targetStat, nil)
}

func finishStagedArtifactRemoval(rootFD int, rootStat unix.Stat_t, owner uint32, tombstone, completed string, targetFD int, targetStat unix.Stat_t, hooks *stagedRemovalHooks) error {
	defer unix.Close(targetFD)
	if err := unix.Fchmod(targetFD, 0o700); err != nil {
		return err
	}
	if err := removeStagedDirectoryContents(targetFD, rootStat.Dev, owner, hooks); err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(rootFD, tombstone, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameStagedIdentity(targetStat, current) {
		return core.ErrInvalid
	}
	if err := unix.Fchmod(targetFD, 0o500); err != nil {
		return err
	}
	if err := unix.Fstatat(rootFD, tombstone, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameStagedIdentity(targetStat, current) {
		return core.ErrInvalid
	}
	if err := unix.Renameat2(rootFD, tombstone, rootFD, completed, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return core.ErrInvalid
		}
		return err
	}
	if exists, err := validateStagedMarker(rootFD, completed, rootStat.Dev, owner, true); err != nil {
		return err
	} else if !exists {
		return core.ErrInvalid
	}
	return nil
}

// RemoveStagedArtifactMarker garbage-collects one sealed completion marker.
// It never reads, renames, or deletes the digest-addressed artifact path.
func RemoveStagedArtifactMarker(root, cleanupToken string) error {
	if !validStagedRoot(root) || !validStagedCleanupToken(cleanupToken) {
		return core.ErrInvalid
	}
	rootFD, rootStat, owner, err := openStagedRoot(root)
	if err != nil {
		return err
	}
	defer unix.Close(rootFD)
	name := stagedRemovedName(cleanupToken)
	markerFD, markerStat, exists, err := openStagedDirectory(rootFD, name, rootStat.Dev, owner)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	defer unix.Close(markerFD)
	empty, err := stagedDirectoryEmpty(markerFD)
	if err != nil {
		return err
	}
	if !empty {
		return core.ErrInvalid
	}
	var current unix.Stat_t
	if err := unix.Fstatat(rootFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameStagedIdentity(markerStat, current) {
		return core.ErrInvalid
	}
	return unix.Unlinkat(rootFD, name, unix.AT_REMOVEDIR)
}

func validStagedRootAndDigest(root, digest string) bool {
	if !validStagedRoot(root) || len(digest) != 64 || strings.ToLower(digest) != digest {
		return false
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

func validStagedRoot(root string) bool {
	return filepath.IsAbs(root) && filepath.Clean(root) == root
}

func validStagedCleanupToken(cleanupToken string) bool {
	parsed, err := uuid.Parse(cleanupToken)
	return err == nil && parsed.String() == cleanupToken
}

func stagedRemovalName(cleanupToken string) string { return ".remove-" + cleanupToken }
func stagedRemovedName(cleanupToken string) string { return ".removed-" + cleanupToken }

func openStagedRoot(root string) (int, unix.Stat_t, uint32, error) {
	var stat unix.Stat_t
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, stat, 0, err
	}
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, 0, err
	}
	owner := uint32(os.Geteuid())
	if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != owner || stat.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, 0, core.ErrInvalid
	}
	return fd, stat, owner, nil
}

func openStagedDirectory(parentFD int, name string, device uint64, owner uint32) (int, unix.Stat_t, bool, error) {
	var stat unix.Stat_t
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: stagedOpenResolve})
	if errors.Is(err, unix.ENOENT) {
		return -1, stat, false, nil
	}
	if stagedOpenIdentityMismatch(err) {
		return -1, stat, false, core.ErrInvalid
	}
	if err != nil {
		return -1, stat, false, err
	}
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, false, err
	}
	if !validStagedDirectory(stat, device, owner) {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, false, core.ErrInvalid
	}
	var current unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, false, err
	}
	if !sameStagedIdentity(stat, current) {
		_ = unix.Close(fd)
		return -1, unix.Stat_t{}, false, core.ErrInvalid
	}
	return fd, stat, true, nil
}

func validateStagedMarker(parentFD int, name string, device uint64, owner uint32, requireEmpty bool) (bool, error) {
	fd, _, exists, err := openStagedDirectory(parentFD, name, device, owner)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, nil
	}
	defer unix.Close(fd)
	if requireEmpty {
		empty, err := stagedDirectoryEmpty(fd)
		if err != nil {
			return false, err
		}
		if !empty {
			return false, core.ErrInvalid
		}
	}
	return true, nil
}

func stagedDirectoryEmpty(directoryFD int) (bool, error) {
	names, err := stagedDirectoryNames(directoryFD)
	return len(names) == 0, err
}

func stagedDirectoryNames(directoryFD int) ([]string, error) {
	readFD, err := unix.Openat(directoryFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(readFD), "staged-artifact")
	if directory == nil {
		_ = unix.Close(readFD)
		return nil, core.ErrInvalid
	}
	names, readErr := directory.Readdirnames(-1)
	closeErr := directory.Close()
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	return names, nil
}

func stagedEntryTombstoneName() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return ".entry-remove-" + hex.EncodeToString(nonce[:]), nil
}

func validStagedDirectory(stat unix.Stat_t, device uint64, owner uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFDIR && uint64(stat.Dev) == device && stat.Uid == owner
}

func validStagedFile(stat unix.Stat_t, device uint64, owner uint32) bool {
	return stat.Mode&unix.S_IFMT == unix.S_IFREG && uint64(stat.Dev) == device && stat.Uid == owner && stat.Nlink == 1
}

func sameStagedIdentity(expected, current unix.Stat_t) bool {
	return expected.Dev == current.Dev && expected.Ino == current.Ino && expected.Uid == current.Uid && expected.Mode&unix.S_IFMT == current.Mode&unix.S_IFMT
}

func stagedOpenIdentityMismatch(err error) bool {
	return errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EXDEV)
}

func removeStagedDirectoryContents(directoryFD int, device uint64, owner uint32, hooks *stagedRemovalHooks) error {
	names, err := stagedDirectoryNames(directoryFD)
	if err != nil {
		return err
	}
	for _, name := range names {
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, '/') {
			return core.ErrInvalid
		}
		var before unix.Stat_t
		if err := unix.Fstatat(directoryFD, name, &before, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		switch before.Mode & unix.S_IFMT {
		case unix.S_IFREG:
			if err := removeStagedFile(directoryFD, name, before, device, owner); err != nil {
				return err
			}
		case unix.S_IFDIR:
			if err := removeStagedChildDirectory(directoryFD, name, before, device, owner, hooks); err != nil {
				return err
			}
		default:
			return core.ErrInvalid
		}
		if hooks != nil && hooks.afterEntryRemove != nil {
			if err := hooks.afterEntryRemove(); err != nil {
				return err
			}
		}
	}
	return nil
}

func removeStagedFile(parentFD int, name string, before unix.Stat_t, device uint64, owner uint32) error {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: stagedOpenResolve})
	if stagedOpenIdentityMismatch(err) {
		return core.ErrInvalid
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if !validStagedFile(opened, device, owner) || !sameStagedIdentity(before, opened) {
		return core.ErrInvalid
	}
	tombstone, err := stagedEntryTombstoneName()
	if err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameStagedIdentity(opened, current) {
		return core.ErrInvalid
	}
	if err := unix.Renameat2(parentFD, name, parentFD, tombstone, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return core.ErrInvalid
		}
		return err
	}
	if err := unix.Fstatat(parentFD, tombstone, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameStagedIdentity(opened, current) {
		return core.ErrInvalid
	}
	return unix.Unlinkat(parentFD, tombstone, 0)
}

func removeStagedChildDirectory(parentFD int, name string, before unix.Stat_t, device uint64, owner uint32, hooks *stagedRemovalHooks) error {
	fd, err := unix.Openat2(parentFD, name, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: stagedOpenResolve})
	if stagedOpenIdentityMismatch(err) {
		return core.ErrInvalid
	}
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	var opened unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if !validStagedDirectory(opened, device, owner) || !sameStagedIdentity(before, opened) {
		return core.ErrInvalid
	}
	tombstone, err := stagedEntryTombstoneName()
	if err != nil {
		return err
	}
	var current unix.Stat_t
	if err := unix.Fstatat(parentFD, name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameStagedIdentity(opened, current) {
		return core.ErrInvalid
	}
	if err := unix.Renameat2(parentFD, name, parentFD, tombstone, unix.RENAME_NOREPLACE); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return core.ErrInvalid
		}
		return err
	}
	if err := unix.Fstatat(parentFD, tombstone, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameStagedIdentity(opened, current) {
		return core.ErrInvalid
	}
	if err := unix.Fchmod(fd, 0o700); err != nil {
		return err
	}
	if err := removeStagedDirectoryContents(fd, device, owner, hooks); err != nil {
		return err
	}
	if err := unix.Fstatat(parentFD, tombstone, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if !sameStagedIdentity(opened, current) {
		return core.ErrInvalid
	}
	return unix.Unlinkat(parentFD, tombstone, unix.AT_REMOVEDIR)
}
