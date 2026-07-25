//go:build linux

package extensionrunner

import (
	"os"

	"golang.org/x/sys/unix"
)

func openInstallRoot(root string) (int, error) {
	return unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func closeInstallFD(fd int) error { return unix.Close(fd) }

func openInstallEntry(rootFD int, path string) (int, error) {
	metaFD, err := openInstallPath(rootFD, path, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW)
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	err = unix.Fstat(metaFD, &st)
	_ = unix.Close(metaFD)
	if err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return -1, unix.EINVAL
	}
	// O_NONBLOCK makes a concurrent regular-file-to-FIFO/device replacement
	// nonblocking. The caller fstats and hashes this exact returned FD.
	return openInstallPath(rootFD, path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW)
}

func openInstallPath(rootFD int, path string, flags uint64) (int, error) {
	how := &unix.OpenHow{Flags: flags, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	fd, err := unix.Openat2(rootFD, path, how)
	if err == nil || err != unix.ENOSYS && err != unix.EINVAL {
		return fd, err
	}
	cur := rootFD
	for i, part := range splitRelativePath(path) {
		partFlags := int(flags)
		if i < len(splitRelativePath(path))-1 {
			partFlags = unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_DIRECTORY
		}
		next, openErr := unix.Openat(cur, part, partFlags, 0)
		if cur != rootFD {
			_ = unix.Close(cur)
		}
		if openErr != nil {
			return -1, openErr
		}
		cur = next
	}
	return cur, nil
}

func verifyInstallTree(rootFD int, manifest []ManifestEntry) error {
	expected := make(map[string]struct{}, len(manifest))
	directories := map[string]struct{}{"": {}}
	for _, entry := range manifest {
		expected[entry.Path] = struct{}{}
		parts := splitRelativePath(entry.Path)
		for i := 1; i < len(parts); i++ {
			path := parts[0]
			for j := 1; j < i; j++ {
				path += "/" + parts[j]
			}
			directories[path] = struct{}{}
		}
	}
	seen := make(map[string]struct{}, len(expected))
	start, err := unix.Openat(rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	if err := walkInstallTree(start, "", expected, directories, seen); err != nil {
		return err
	}
	if len(seen) != len(expected) {
		return unix.EINVAL
	}
	return nil
}

func walkInstallTree(dirFD int, prefix string, expected, directories, seen map[string]struct{}) error {
	file := os.NewFile(uintptr(dirFD), prefix)
	defer file.Close()
	entries, err := file.ReadDir(-1)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if name == "." || name == ".." || !safeName(name) {
			return unix.EINVAL
		}
		path := name
		if prefix != "" {
			path = prefix + "/" + name
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(dirFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		if stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o222 != 0 || stat.Mode&0o6000 != 0 {
			return unix.EPERM
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if _, ok := directories[path]; !ok {
				return unix.EINVAL
			}
			child, err := unix.Openat(dirFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			if err := walkInstallTree(child, path, expected, directories, seen); err != nil {
				return err
			}
		case unix.S_IFREG:
			if prefix == "" && name == installManifestName {
				if stat.Nlink != 1 {
					return unix.EINVAL
				}
				continue
			}
			if _, ok := expected[path]; !ok || stat.Nlink != 1 {
				return unix.EINVAL
			}
			seen[path] = struct{}{}
		default:
			return unix.EINVAL
		}
	}
	return nil
}
