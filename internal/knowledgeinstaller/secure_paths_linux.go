//go:build linux

package installer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const secureResolveFlags = unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS

type securePathRoot struct {
	fd    int
	paths Paths
}

func openSecurePathRoot(paths Paths) (*securePathRoot, error) {
	root := paths.Root
	if root == "" {
		root = "/"
	}
	fd, err := unix.Open(root, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open fixed installer root")
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("fixed installer root is unsafe")
	}
	return &securePathRoot{fd: fd, paths: paths}, nil
}

func (root *securePathRoot) close() { _ = unix.Close(root.fd) }

func secureRelative(logical string) (string, error) {
	if !filepath.IsAbs(logical) {
		return "", fmt.Errorf("fixed installer path must be absolute")
	}
	clean := filepath.Clean(logical)
	if clean == "/" {
		return ".", nil
	}
	relative := strings.TrimPrefix(clean, "/")
	if relative == "" || relative == "." || strings.HasPrefix(relative, "../") {
		return "", fmt.Errorf("fixed installer path is unsafe")
	}
	return relative, nil
}

func secureOpenat(dirfd int, relative string, flags int, mode uint32) (int, error) {
	return unix.Openat2(dirfd, relative, &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Mode:    uint64(mode),
		Resolve: secureResolveFlags,
	})
}

func (root *securePathRoot) openParent(logical string, create bool) (int, string, error) {
	relative, err := secureRelative(logical)
	if err != nil {
		return -1, "", err
	}
	components := strings.Split(relative, "/")
	if len(components) == 0 || components[len(components)-1] == "" {
		return -1, "", fmt.Errorf("fixed installer path is unsafe")
	}
	current, err := unix.Dup(root.fd)
	if err != nil {
		return -1, "", fmt.Errorf("duplicate fixed installer root")
	}
	for _, component := range components[:len(components)-1] {
		next, openErr := secureOpenat(current, component, unix.O_PATH|unix.O_DIRECTORY, 0)
		if errors.Is(openErr, unix.ENOENT) && create {
			if mkdirErr := unix.Mkdirat(current, component, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(current)
				return -1, "", fmt.Errorf("create fixed installer parent")
			}
			next, openErr = secureOpenat(current, component, unix.O_PATH|unix.O_DIRECTORY, 0)
		}
		if openErr != nil {
			_ = unix.Close(current)
			return -1, "", fmt.Errorf("walk fixed installer parent: %w", openErr)
		}
		var stat unix.Stat_t
		if unix.Fstat(next, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			_ = unix.Close(next)
			_ = unix.Close(current)
			return -1, "", fmt.Errorf("fixed installer parent is unsafe")
		}
		_ = unix.Close(current)
		current = next
	}
	return current, components[len(components)-1], nil
}

func expectedFixedOwnership(paths Paths, uid, gid int) (int, int) {
	if paths.Root != "" {
		if uid == 0 {
			uid = os.Geteuid()
		}
		if gid == 0 {
			gid = os.Getegid()
		}
	}
	return uid, gid
}

func ensureSecureOwnedDirectory(paths Paths, logical string, mode os.FileMode, uid, gid int) error {
	root, err := openSecurePathRoot(paths)
	if err != nil {
		return err
	}
	defer root.close()
	parent, base, err := root.openParent(logical, true)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	created := false
	fd, err := secureOpenat(parent, base, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if errors.Is(err, unix.ENOENT) {
		if err := unix.Mkdirat(parent, base, uint32(mode.Perm())); err != nil {
			return fmt.Errorf("create fixed persistent directory")
		}
		created = true
		fd, err = secureOpenat(parent, base, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	}
	if err != nil {
		return fmt.Errorf("open fixed persistent directory")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("fixed persistent directory is unsafe")
	}
	uid, gid = expectedFixedOwnership(paths, uid, gid)
	if created {
		if int(stat.Uid) != os.Geteuid() || int(stat.Gid) != os.Getegid() {
			return fmt.Errorf("new fixed persistent directory ownership is unsafe")
		}
		if err := unix.Fchown(fd, uid, gid); err != nil {
			return fmt.Errorf("own fixed persistent directory")
		}
		if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
			return fmt.Errorf("mode fixed persistent directory")
		}
		if unix.Fstat(fd, &stat) != nil {
			return fmt.Errorf("verify fixed persistent directory")
		}
	}
	if int(stat.Uid) != uid || int(stat.Gid) != gid || os.FileMode(stat.Mode).Perm() != mode.Perm() {
		return fmt.Errorf("fixed persistent directory ownership or mode drift")
	}
	return nil
}

func validateSecureFixedPath(paths Paths, logical string, directory, allowMissing bool) error {
	root, err := openSecurePathRoot(paths)
	if err != nil {
		return err
	}
	defer root.close()
	parent, base, err := root.openParent(logical, false)
	if err != nil {
		if allowMissing && errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	defer unix.Close(parent)
	flags := unix.O_PATH
	if directory {
		flags |= unix.O_DIRECTORY
	}
	fd, err := secureOpenat(parent, base, flags, 0)
	if errors.Is(err, unix.ENOENT) && allowMissing {
		return nil
	}
	if err != nil {
		return fmt.Errorf("fixed installer target is unsafe")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil {
		return fmt.Errorf("inspect fixed installer target")
	}
	if directory && stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("fixed installer target is not a directory")
	}
	if !directory && stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("fixed installer target is not a regular file")
	}
	return nil
}

func validateFixedInstallBoundary(paths Paths) error {
	directories := []string{
		InstallRoot, filepath.Dir(ReleaseRoot), ReleaseRoot, "/etc/dirextalk-knowledge",
		"/etc/systemd/system", "/usr/lib/sysusers.d", "/usr/lib/tmpfiles.d", RuntimeRoot,
		PersistentRoot, PersistentRoot + "/qdrant",
		PersistentRoot + "/qdrant/storage", PersistentRoot + "/adapter", PersistentRoot + "/secrets",
		PersistentRoot + "/tls", BackupRoot,
	}
	for _, logical := range directories {
		if err := validateSecureFixedPath(paths, logical, true, true); err != nil {
			return err
		}
	}
	files := []string{
		QdrantArchivePath, AdapterArchivePath, ModelArchivePath, ProvenancePath, APIKeySourcePath,
		APIKeyRuntimePath, CACertPath, ServerCertPath, ServerKeyPath, QdrantConfigPath,
		SysusersPath, TmpfilesPath, QdrantUnitPath, AdapterUnitPath,
	}
	for _, logical := range files {
		required := logical == QdrantArchivePath || logical == AdapterArchivePath ||
			logical == ModelArchivePath || logical == ProvenancePath || logical == APIKeySourcePath
		if err := validateSecureFixedPath(paths, logical, false, !required); err != nil {
			return err
		}
	}
	return nil
}

func writeSecureManagedFile(paths Paths, logical string, data []byte, mode os.FileMode, uid, gid int) error {
	root, err := openSecurePathRoot(paths)
	if err != nil {
		return err
	}
	defer root.close()
	parent, base, err := root.openParent(logical, true)
	if err != nil {
		return err
	}
	defer unix.Close(parent)
	uid, gid = expectedFixedOwnership(paths, uid, gid)
	var existing unix.Stat_t
	if err := unix.Fstatat(parent, base, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if existing.Mode&unix.S_IFMT != unix.S_IFREG || existing.Nlink != 1 ||
			int(existing.Uid) != uid || int(existing.Gid) != gid ||
			os.FileMode(existing.Mode).Perm() != mode.Perm() {
			return fmt.Errorf("managed target ownership, type, or mode drift")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect managed target")
	}
	temporary := base + ".dirextalk-new"
	var staged unix.Stat_t
	if err := unix.Fstatat(parent, temporary, &staged, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if staged.Mode&unix.S_IFMT != unix.S_IFREG || staged.Nlink != 1 ||
			int(staged.Uid) != os.Geteuid() || int(staged.Gid) != os.Getegid() {
			return fmt.Errorf("managed temporary target is unsafe")
		}
		if err := unix.Unlinkat(parent, temporary, 0); err != nil {
			return fmt.Errorf("clean managed temporary file")
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("inspect managed temporary file")
	}
	fd, err := unix.Openat(parent, temporary,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, uint32(mode.Perm()))
	if err != nil {
		return fmt.Errorf("create managed file")
	}
	file := os.NewFile(uintptr(fd), logical)
	if file == nil {
		_ = unix.Close(fd)
		return fmt.Errorf("create managed file")
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = unix.Unlinkat(parent, temporary, 0)
		}
	}()
	if _, err := file.Write(data); err != nil {
		return fmt.Errorf("write managed file")
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync managed file")
	}
	var created unix.Stat_t
	if unix.Fstat(fd, &created) != nil || created.Mode&unix.S_IFMT != unix.S_IFREG ||
		created.Nlink != 1 || int(created.Uid) != os.Geteuid() || int(created.Gid) != os.Getegid() {
		return fmt.Errorf("new managed file is unsafe")
	}
	if err := unix.Fchown(fd, uid, gid); err != nil {
		return fmt.Errorf("own managed file")
	}
	if err := unix.Fchmod(fd, uint32(mode.Perm())); err != nil {
		return fmt.Errorf("mode managed file")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close managed file")
	}
	if err := unix.Renameat(parent, temporary, parent, base); err != nil {
		return fmt.Errorf("promote managed file")
	}
	complete = true
	return nil
}
