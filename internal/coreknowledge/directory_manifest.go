package coreknowledge

// Descriptor-rooted directory enumeration used by mounted Knowledge sources.
// Every component is opened with O_NOFOLLOW; the resulting manifest is a
// deterministic snapshot that workers can re-verify before promotion.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"mime"
	"os"
	"path"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	DefaultManifestMaxDepth            = 16
	DefaultManifestMaxFiles            = 4096
	DefaultManifestMaxFileBytes  int64 = MaxSourceBytes
	DefaultManifestMaxTotalBytes int64 = MaxSourceBytes
)

type DirectoryManifestLimits struct {
	MaxDepth, MaxFiles          int
	MaxFileBytes, MaxTotalBytes int64
}

func (l DirectoryManifestLimits) normalized() DirectoryManifestLimits {
	if l.MaxDepth == 0 {
		l.MaxDepth = DefaultManifestMaxDepth
	}
	if l.MaxFiles == 0 {
		l.MaxFiles = DefaultManifestMaxFiles
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = DefaultManifestMaxFileBytes
	}
	if l.MaxTotalBytes == 0 {
		l.MaxTotalBytes = DefaultManifestMaxTotalBytes
	}
	return l
}

type DirectoryManifestEntry struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"size_bytes"`
	MediaType string `json:"media_type"`
}

type DirectoryManifest struct {
	Root     string                   `json:"root"`
	Revision int64                    `json:"revision"`
	Digest   string                   `json:"digest"`
	Bytes    int64                    `json:"bytes"`
	Entries  []DirectoryManifestEntry `json:"entries"`
}

func (m DirectoryManifest) Validate() error {
	if validateRelativePath(m.Root) != nil || m.Revision <= 0 || len(m.Entries) == 0 || !validDigest(m.Digest) {
		return ErrInvalid
	}
	var total int64
	seen := make(map[string]struct{}, len(m.Entries))
	for _, e := range m.Entries {
		if validateRelativePath(e.Path) != nil || !validDigest(e.Digest) || e.SizeBytes < 0 || e.MediaType == "" {
			return ErrInvalid
		}
		if _, ok := seen[e.Path]; ok {
			return ErrConflict
		}
		seen[e.Path] = struct{}{}
		total += e.SizeBytes
	}
	if total != m.Bytes {
		return ErrConflict
	}
	return nil
}

func (o *RootManagedFileOpener) EnumerateManagedDirectory(ctx context.Context, relative string, limits DirectoryManifestLimits) (DirectoryManifest, error) {
	if o == nil || o.root == nil || ctx == nil || ctx.Err() != nil || validateRelativePath(relative) != nil {
		return DirectoryManifest{}, ErrPathTraversal
	}
	limits = limits.normalized()
	parts := strings.Split(relative, "/")
	fd, err := openDirComponents(int(o.root.Fd()), parts)
	if err != nil {
		return DirectoryManifest{}, ErrFilesystemUnavailable
	}
	defer unix.Close(fd)
	entries := make([]DirectoryManifestEntry, 0)
	var total int64
	var walk func(int, string, int) error
	walk = func(dirfd int, prefix string, depth int) error {
		if depth > limits.MaxDepth {
			return ErrLimitExceeded
		}
		dup, e := unix.Dup(dirfd)
		if e != nil {
			return ErrFilesystemUnavailable
		}
		f := os.NewFile(uintptr(dup), "manifest-dir")
		if f == nil {
			return ErrFilesystemUnavailable
		}
		names, e := f.Readdirnames(-1)
		_ = f.Close()
		if e != nil {
			return ErrFilesystemUnavailable
		}
		sort.Strings(names)
		for _, name := range names {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") {
				return ErrPathTraversal
			}
			var st unix.Stat_t
			if e := unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
				return ErrFilesystemUnavailable
			}
			rel := name
			if prefix != "" {
				rel = path.Join(prefix, name)
			}
			mode := st.Mode & unix.S_IFMT
			switch mode {
			case unix.S_IFDIR:
				if depth >= limits.MaxDepth {
					return ErrLimitExceeded
				}
				child, e := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if e != nil {
					return ErrFilesystemUnavailable
				}
				e = walk(child, rel, depth+1)
				_ = unix.Close(child)
				if e != nil {
					return e
				}
			case unix.S_IFREG:
				if len(entries) >= limits.MaxFiles || int64(st.Size) > limits.MaxFileBytes || total+int64(st.Size) > limits.MaxTotalBytes {
					return ErrLimitExceeded
				}
				file, e := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if e != nil {
					return ErrFilesystemUnavailable
				}
				fh := os.NewFile(uintptr(file), name)
				h := sha256.New()
				n, copyErr := io.CopyN(h, fh, limits.MaxFileBytes+1)
				_ = fh.Close()
				if copyErr != nil && copyErr != io.EOF {
					return ErrFilesystemUnavailable
				}
				if n > limits.MaxFileBytes {
					return ErrLimitExceeded
				}
				digest := hex.EncodeToString(h.Sum(nil))
				mt := mime.TypeByExtension(path.Ext(name))
				if mt == "" {
					mt = "application/octet-stream"
				}
				entries = append(entries, DirectoryManifestEntry{Path: rel, Digest: digest, SizeBytes: n, MediaType: mt})
				total += n
			default:
				return ErrFilesystemUnavailable
			}
		}
		return nil
	}
	if err := walk(fd, "", 0); err != nil {
		return DirectoryManifest{}, err
	}
	if len(entries) == 0 {
		return DirectoryManifest{}, ErrIneligible
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	canonical, _ := json.Marshal(entries)
	d := sha256.Sum256(canonical)
	return DirectoryManifest{Root: relative, Revision: 1, Digest: hex.EncodeToString(d[:]), Bytes: total, Entries: entries}, nil
}

// VerifyManagedDirectoryManifest re-enumerates a mounted directory and
// rejects any mutation (including additions, removals, symlink replacement or
// changed bytes) relative to the frozen descriptor snapshot.
func (o *RootManagedFileOpener) VerifyManagedDirectoryManifest(ctx context.Context, manifest DirectoryManifest, limits DirectoryManifestLimits) error {
	if err := manifest.Validate(); err != nil {
		return err
	}
	current, err := o.EnumerateManagedDirectory(ctx, manifest.Root, limits)
	if err != nil {
		return err
	}
	if current.Digest != manifest.Digest || current.Bytes != manifest.Bytes || len(current.Entries) != len(manifest.Entries) {
		return ErrRevisionConflict
	}
	for n := range manifest.Entries {
		if current.Entries[n] != manifest.Entries[n] {
			return ErrRevisionConflict
		}
	}
	return nil
}

func openDirComponents(root int, parts []string) (int, error) {
	cur := root
	owned := false
	for _, part := range parts {
		fd, err := unix.Openat(cur, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			if owned {
				_ = unix.Close(cur)
			}
			return -1, err
		}
		if owned {
			_ = unix.Close(cur)
		}
		cur, owned = fd, true
	}
	if !owned {
		return unix.Dup(root)
	}
	return cur, nil
}
