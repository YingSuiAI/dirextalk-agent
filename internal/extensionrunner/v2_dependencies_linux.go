//go:build linux

package extensionrunner

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

type DiskInstallResolver struct{ Root string }

func (r DiskInstallResolver) ResolveInstall(digest string) (*AdmittedInstall, error) {
	return resolveDiskBundle(r.Root, digest, true)
}

type DiskBundleResolver struct{ Root string }

func (r DiskBundleResolver) ResolveBundle(digest string) (*AdmittedInstall, error) {
	return resolveDiskBundle(r.Root, digest, false)
}

func resolveDiskBundle(rootPath, digest string, requireEntry bool) (*AdmittedInstall, error) {
	if !filepath.IsAbs(rootPath) || !digestRE.MatchString(digest) {
		return nil, ErrInvalid
	}
	root, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	defer unix.Close(root)
	var st unix.Stat_t
	if unix.Fstat(root, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0o022 != 0 {
		return nil, ErrInvalid
	}
	installFD, err := unix.Openat(root, digest, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	defer unix.Close(installFD)
	if unix.Fstat(installFD, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0o222 != 0 {
		return nil, ErrInvalid
	}
	fd, err := unix.Openat(installFD, installManifestName, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	f := os.NewFile(uintptr(fd), installManifestName)
	defer f.Close()
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != uint32(os.Geteuid()) || st.Mode&0o222 != 0 || st.Size > MaxMessageBytes {
		return nil, ErrInvalid
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxMessageBytes+1))
	if err != nil {
		return nil, ErrInvalid
	}
	var m DiskInstallManifestV1
	if json.Unmarshal(b, &m) != nil || m.SchemaVersion != installManifestSchemaV1 {
		return nil, ErrInvalid
	}
	canonical, err := json.Marshal(m)
	if err != nil || !bytes.Equal(b, append(canonical, '\n')) || !validManifestEntries(m.Entries) || ManifestDigest(m.Entries) != digest {
		return nil, ErrInvalid
	}
	// The root was opened and checked above; all later use is descriptor-backed
	// through the admitted object.  The directory name is part of the ABI.
	bundleRoot := filepath.Join(rootPath, digest)
	if requireEntry {
		return OpenAdmittedInstall(bundleRoot, digest, m.Entries)
	}
	return OpenAdmittedBundle(bundleRoot, digest, m.Entries)
}

func validManifestEntries(es []ManifestEntry) bool {
	if len(es) == 0 {
		return false
	}
	last := ""
	for _, e := range es {
		if !safeRelativeSlash(e.Path) || e.Path == installManifestName || !digestRE.MatchString(e.SHA256) || e.Size < 0 || (last != "" && last >= e.Path) {
			return false
		}
		last = e.Path
	}
	return true
}

type DiskWorkspaceResolver struct{ Root string }

func (r DiskWorkspaceResolver) ResolveWorkspace(taskID, taskFence string) (int, error) {
	if !filepath.IsAbs(r.Root) {
		return -1, ErrInvalid
	}
	task, e := idPathPart(taskID)
	if e != nil {
		return -1, e
	}
	fence, e := idPathPart(taskFence)
	if e != nil {
		return -1, e
	}
	root, e := unix.Open(r.Root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, ErrInvalid
	}
	defer unix.Close(root)
	var st unix.Stat_t
	if unix.Fstat(root, &st) != nil || st.Uid != uint32(os.Geteuid()) || st.Mode&0o022 != 0 {
		return -1, ErrInvalid
	}
	if e = unix.Mkdirat(root, task, 0o700); e != nil && e != unix.EEXIST {
		return -1, ErrInvalid
	}
	tfd, e := unix.Openat(root, task, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, ErrInvalid
	}
	defer unix.Close(tfd)
	if e = unix.Mkdirat(tfd, fence, 0o700); e != nil && e != unix.EEXIST {
		return -1, ErrInvalid
	}
	fd, e := unix.Openat(tfd, fence, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, ErrInvalid
	}
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0o077 != 0 {
		unix.Close(fd)
		return -1, ErrInvalid
	}
	return fd, nil
}
