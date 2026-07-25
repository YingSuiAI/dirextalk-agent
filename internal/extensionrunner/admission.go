package extensionrunner

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

const installManifestName = ".dirextalk-install-v1.json"

// DiskInstallManifestV1 is deliberately a struct (rather than a map) so its
// marshalled representation remains the published install ABI.
type DiskInstallManifestV1 struct {
	SchemaVersion string          `json:"schema_version"`
	Entries       []ManifestEntry `json:"entries"`
}

const installManifestSchemaV1 = "dirextalk.extension.install-manifest/v1"

// AdmittedInstall is the immutable, descriptor-backed admission handoff. The
// backend must use only duplicated descriptors from this object, never reopen
// the user-controlled install path.
type AdmittedInstall struct {
	Digest              string
	RootDev, RootIno    uint64
	EntryDev, EntryIno  uint64
	EntryMode           uint32
	EntrySize           int64
	EntrySHA256         string
	EntryELF            elf.FileHeader
	rootFile, entryFile *os.File
	mu                  sync.Mutex
	once                sync.Once
	closeErr            error
}

func (a *AdmittedInstall) DupRootFD() (int, error) {
	if a == nil {
		return -1, ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.rootFile == nil {
		return -1, ErrInvalid
	}
	return unix.Dup(int(a.rootFile.Fd()))
}
func (a *AdmittedInstall) DupEntryFD() (int, error) {
	if a == nil {
		return -1, ErrInvalid
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.entryFile == nil {
		return -1, ErrInvalid
	}
	return unix.Dup(int(a.entryFile.Fd()))
}
func (a *AdmittedInstall) Close() error {
	if a == nil {
		return nil
	}
	a.once.Do(func() {
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.entryFile != nil {
			a.closeErr = a.entryFile.Close()
			a.entryFile = nil
		}
		if a.rootFile != nil {
			a.closeErr = errors.Join(a.closeErr, a.rootFile.Close())
			a.rootFile = nil
		}
	})
	return a.closeErr
}

func ManifestDigest(manifest []ManifestEntry) string {
	copyManifest := append([]ManifestEntry(nil), manifest...)
	sort.Slice(copyManifest, func(i, j int) bool { return copyManifest[i].Path < copyManifest[j].Path })
	h := sha256.New()
	for _, m := range copyManifest {
		h.Write([]byte(m.Path))
		h.Write([]byte{0})
		h.Write([]byte(m.SHA256))
		h.Write([]byte{0})
		h.Write([]byte(strconv.FormatInt(m.Size, 10)))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// AdmitInstall verifies a digest-bound, regular-file-only static install.
// The entry is fixed to the literal "entry"; no interpreter or symlink may
// enter the isolation boundary.
func AdmitInstall(root, digest string, manifest []ManifestEntry) error {
	a, err := OpenAdmittedInstall(root, digest, manifest)
	if err != nil {
		return err
	}
	return a.Close()
}

// OpenAdmittedInstall verifies each manifest member through the trusted root
// FD and retains the verified root and entry descriptors for later execution.
func OpenAdmittedInstall(root, digest string, manifest []ManifestEntry) (_ *AdmittedInstall, retErr error) {
	return openAdmittedBundle(root, digest, manifest, true)
}

// OpenAdmittedBundle verifies an immutable published bundle without requiring
// a native `entry`. Skill and remote-MCP packages use this path; local MCP
// execution continues to use OpenAdmittedInstall and therefore requires the
// statically linked ELF entry.
func OpenAdmittedBundle(root, digest string, manifest []ManifestEntry) (_ *AdmittedInstall, retErr error) {
	return openAdmittedBundle(root, digest, manifest, false)
}

func openAdmittedBundle(root, digest string, manifest []ManifestEntry, requireEntry bool) (_ *AdmittedInstall, retErr error) {
	if !filepath.IsAbs(root) || !digestRE.MatchString(digest) || len(manifest) == 0 {
		return nil, ErrInvalid
	}
	rootFD, err := openInstallRoot(root)
	if err != nil {
		return nil, ErrInvalid
	}
	a := &AdmittedInstall{Digest: digest, rootFile: os.NewFile(uintptr(rootFD), root)}
	defer func() {
		if retErr != nil {
			_ = a.Close()
		}
	}()
	var rootStat unix.Stat_t
	if unix.Fstat(int(a.rootFile.Fd()), &rootStat) != nil ||
		rootStat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		rootStat.Uid != uint32(os.Geteuid()) ||
		rootStat.Mode&0o222 != 0 {
		return nil, ErrInvalid
	}
	a.RootDev, a.RootIno = uint64(rootStat.Dev), rootStat.Ino
	seen := map[string]bool{}
	entries := append([]ManifestEntry(nil), manifest...)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	for _, m := range entries {
		if !safeRelativeSlash(m.Path) || seen[m.Path] || !digestRE.MatchString(m.SHA256) || m.Size < 0 {
			return nil, ErrInvalid
		}
		seen[m.Path] = true
		fd, err := openInstallEntry(int(a.rootFile.Fd()), m.Path)
		if err != nil {
			return nil, ErrInvalid
		}
		f := os.NewFile(uintptr(fd), m.Path)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil ||
			st.Mode&unix.S_IFMT != unix.S_IFREG ||
			st.Uid != uint32(os.Geteuid()) ||
			st.Mode&0o222 != 0 ||
			st.Mode&0o6000 != 0 ||
			st.Nlink != 1 {
			_ = f.Close()
			return nil, ErrInvalid
		}
		h := sha256.New()
		n, readErr := io.Copy(h, f)
		if readErr != nil || n != m.Size || hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
			_ = f.Close()
			return nil, ErrInvalid
		}
		if m.Path == "entry" {
			if st.Mode&0o111 == 0 {
				_ = f.Close()
				return nil, ErrInvalid
			}
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				_ = f.Close()
				return nil, ErrInvalid
			}
			elfFile, err := elf.NewFile(f)
			if err != nil {
				_ = f.Close()
				return nil, ErrInvalid
			}
			if elfFile.FileHeader.Type != elf.ET_EXEC && elfFile.FileHeader.Type != elf.ET_DYN {
				elfFile.Close()
				_ = f.Close()
				return nil, ErrInvalid
			}
			if elfFile.FileHeader.Class != elf.ELFCLASS64 || elfFile.FileHeader.Data != elf.ELFDATA2LSB || (elfFile.FileHeader.OSABI != elf.ELFOSABI_NONE && elfFile.FileHeader.OSABI != elf.ELFOSABI_LINUX) || !supportedMachine(elfFile.FileHeader.Machine) {
				elfFile.Close()
				_ = f.Close()
				return nil, ErrInvalid
			}
			for _, prog := range elfFile.Progs {
				if prog.Type == elf.PT_INTERP {
					elfFile.Close()
					_ = f.Close()
					return nil, ErrInvalid
				}
			}
			if needed, e := elfFile.DynString(elf.DT_NEEDED); e == nil && len(needed) > 0 {
				elfFile.Close()
				_ = f.Close()
				return nil, ErrInvalid
			}
			a.EntryELF = elfFile.FileHeader
			elfFile.Close()
			a.EntryDev, a.EntryIno = uint64(st.Dev), st.Ino
			a.EntryMode, a.EntrySize, a.EntrySHA256 = st.Mode, st.Size, m.SHA256
			a.entryFile = f
			continue
		}
		if err := f.Close(); err != nil {
			return nil, ErrInvalid
		}
	}
	if requireEntry && a.entryFile == nil {
		return nil, ErrInvalid
	}
	if ManifestDigest(entries) != digest {
		return nil, ErrInvalid
	}
	if err := verifyInstallTree(int(a.rootFile.Fd()), entries); err != nil {
		return nil, ErrInvalid
	}
	return a, nil
}

func supportedMachine(m elf.Machine) bool {
	switch runtime.GOARCH {
	case "amd64":
		return m == elf.EM_X86_64
	case "arm64":
		return m == elf.EM_AARCH64
	default:
		return false
	}
}

// VerifyRelativeManifest validates the portable manifest syntax. Filesystem
// resolution is deliberately performed only by AdmitInstall on trusted FDs.
func VerifyRelativeManifest(root string, manifest []ManifestEntry) error {
	if !filepath.IsAbs(root) {
		return ErrInvalid
	}
	for _, m := range manifest {
		if !safeRelativeSlash(m.Path) {
			return ErrInvalid
		}
	}
	return nil
}
