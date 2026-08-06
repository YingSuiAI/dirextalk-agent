package coredeprovision

// The external purge registry owns the process-lifetime descriptors used by
// account deprovisioning.  It deliberately does not accept paths at purge
// time: configured roots are resolved and opened once during composition, and
// every later operation is descriptor-relative.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

const (
	maxPurgeDepth  = 256
	maxPurgePasses = 4
)

var (
	ErrPurgeInvalid = errors.New("invalid external purge registry")
	ErrPurgeClosed  = errors.New("external purge registry is closed")
)

// RootSpec names one admitted filesystem root. Empty paths are omitted so
// disabled compositions may leave their optional roots unconfigured. A
// non-zero OwnerUID/WritableGroupGID pair admits the runner-owned shared
// workspace only when its ownership and mode are exactly bound.
type RootSpec struct {
	Name             string
	Path             string
	OwnerUID         uint32
	WritableGroupGID uint32
}

// CollectionPurger is the narrow external vector-store deletion boundary.
// Implementations must make DeleteCollection idempotent (including a missing
// collection) and must not accept a caller-supplied collection name.
type CollectionPurger interface {
	DeleteCollection(context.Context) error
}

type trustedRoot struct {
	name   string
	path   string
	file   *os.File
	dev    uint64
	ino    uint64
	uid    uint32
	gid    uint32
	shared bool
}

// PurgeRegistry binds every configured root and, optionally, one configured
// vector collection. Roots are held open until Close; replacement of a
// configured pathname cannot redirect descriptor-relative deletion.
type PurgeRegistry struct {
	mu         sync.Mutex
	roots      []trustedRoot
	collection CollectionPurger
	closed     bool
}

// NewPurgeRegistry validates and binds root directories. It rejects path
// aliases, unauthorized writable directories, duplicate/nested roots, and
// symlinked final path components. The one shared form requires exact pinned
// owner/group/mode identity. The caller must Close the returned registry.
func NewPurgeRegistry(specs []RootSpec, collection CollectionPurger) (*PurgeRegistry, error) {
	ordered := append([]RootSpec(nil), specs...)
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].Name == ordered[j].Name {
			return ordered[i].Path < ordered[j].Path
		}
		return ordered[i].Name < ordered[j].Name
	})

	registry := &PurgeRegistry{collection: collection}
	for _, spec := range ordered {
		name := strings.TrimSpace(spec.Name)
		path := strings.TrimSpace(spec.Path)
		if path == "" {
			continue
		}
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			registry.Close()
			return nil, fmt.Errorf("%w: root name", ErrPurgeInvalid)
		}
		root, err := bindTrustedRoot(RootSpec{Name: name, Path: path, OwnerUID: spec.OwnerUID, WritableGroupGID: spec.WritableGroupGID})
		if err != nil {
			registry.Close()
			return nil, err
		}
		for _, previous := range registry.roots {
			if previous.name == root.name {
				_ = root.file.Close()
				registry.Close()
				return nil, fmt.Errorf("%w: duplicate root %q", ErrPurgeInvalid, root.name)
			}
			if pathsOverlap(previous.path, root.path) {
				_ = root.file.Close()
				registry.Close()
				return nil, fmt.Errorf("%w: roots %q and %q overlap", ErrPurgeInvalid, previous.name, root.name)
			}
		}
		registry.roots = append(registry.roots, root)
	}
	return registry, nil
}

func bindTrustedRoot(spec RootSpec) (trustedRoot, error) {
	name, path := spec.Name, spec.Path
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return trustedRoot{}, fmt.Errorf("%w: root %q must be absolute and clean", ErrPurgeInvalid, name)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return trustedRoot{}, fmt.Errorf("%w: root %q must not use symlinks", ErrPurgeInvalid, name)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return trustedRoot{}, fmt.Errorf("%w: open root %q: %v", ErrPurgeInvalid, name, err)
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		_ = unix.Close(fd)
		return trustedRoot{}, fmt.Errorf("%w: stat root %q: %v", ErrPurgeInvalid, name, err)
	}
	shared := spec.OwnerUID != 0 || spec.WritableGroupGID != 0
	validIdentity := stat.Mode&unix.S_IFMT == unix.S_IFDIR
	if shared {
		validIdentity = validIdentity && spec.OwnerUID != 0 && spec.WritableGroupGID == uint32(os.Getegid()) && stat.Uid == spec.OwnerUID && stat.Gid == spec.WritableGroupGID && stat.Mode&0o777 == 0o770
	} else {
		validIdentity = validIdentity && stat.Uid == uint32(os.Geteuid()) && stat.Mode&0o022 == 0
	}
	if !validIdentity {
		_ = unix.Close(fd)
		return trustedRoot{}, fmt.Errorf("%w: root %q ownership or mode", ErrPurgeInvalid, name)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return trustedRoot{}, fmt.Errorf("%w: wrap root %q", ErrPurgeInvalid, name)
	}
	return trustedRoot{name: name, path: path, file: file, dev: uint64(stat.Dev), ino: stat.Ino, uid: stat.Uid, gid: stat.Gid, shared: shared}, nil
}

func pathsOverlap(a, b string) bool {
	return pathContains(a, b) || pathContains(b, a)
}

func pathContains(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return true
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

// Purge recursively removes all entries below each bound root without
// following symlinks. A root pathname replacement is detected before any
// deletion and again after each root, so success never silently refers to a
// same-name replacement. The optional collection is deleted only after all
// filesystem roots succeed.
func (r *PurgeRegistry) Purge(ctx context.Context) error {
	if r == nil || ctx == nil {
		return ErrPurgeInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrPurgeClosed
	}
	for i := range r.roots {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.roots[i].verify(); err != nil {
			return fmt.Errorf("verify external purge root %q: %w", r.roots[i].name, err)
		}
	}
	for i := range r.roots {
		if err := purgeTrustedDirectory(ctx, r.roots[i].file); err != nil {
			return fmt.Errorf("purge external root %q: %w", r.roots[i].name, err)
		}
		if err := r.roots[i].verify(); err != nil {
			return fmt.Errorf("verify purged root %q: %w", r.roots[i].name, err)
		}
	}
	if r.collection != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := r.collection.DeleteCollection(ctx); err != nil {
			return fmt.Errorf("purge external vector collection: %w", err)
		}
	}
	return nil
}

func (r *trustedRoot) verify() error {
	if r == nil || r.file == nil {
		return ErrPurgeClosed
	}
	var fdStat unix.Stat_t
	if err := unix.Fstat(int(r.file.Fd()), &fdStat); err != nil {
		return err
	}
	if uint64(fdStat.Dev) != r.dev || uint64(fdStat.Ino) != r.ino || !r.matches(fdStat) {
		return errors.New("bound root identity changed")
	}
	var pathStat unix.Stat_t
	if err := unix.Lstat(r.path, &pathStat); err != nil {
		return err
	}
	if uint64(pathStat.Dev) != r.dev || uint64(pathStat.Ino) != r.ino || !r.matches(pathStat) {
		return errors.New("configured root path was replaced")
	}
	return nil
}

func (r *trustedRoot) matches(stat unix.Stat_t) bool {
	if r == nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != r.uid {
		return false
	}
	if r.shared {
		return stat.Gid == r.gid && stat.Mode&0o777 == 0o770
	}
	return stat.Mode&0o022 == 0
}

func purgeTrustedDirectory(ctx context.Context, root *os.File) error {
	return purgeTrustedDirectoryAt(ctx, root, 0)
}

func purgeTrustedDirectoryAt(ctx context.Context, root *os.File, depth int) error {
	if root == nil {
		return ErrPurgeClosed
	}
	if depth > maxPurgeDepth {
		return errors.New("external purge directory depth exceeded")
	}
	for pass := 0; pass < maxPurgePasses; pass++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		names, err := readDirectoryNames(int(root.Fd()))
		if err != nil {
			return err
		}
		if len(names) == 0 {
			return nil
		}
		for _, name := range names {
			if err := removeEntry(ctx, int(root.Fd()), name, depth); err != nil {
				return err
			}
		}
	}
	return errors.New("external purge root remained non-empty")
}

func readDirectoryNames(fd int) ([]string, error) {
	dup, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(dup), "external-purge")
	if dir == nil {
		_ = unix.Close(dup)
		return nil, ErrPurgeInvalid
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || strings.ContainsAny(name, "/\x00\r\n") {
			return nil, ErrPurgeInvalid
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func removeEntry(ctx context.Context, parentFD int, name string, depth int) error {
	if depth > maxPurgeDepth {
		return errors.New("external purge directory depth exceeded")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		fd, err := openChildDirectory(parentFD, name)
		if err == nil {
			child := os.NewFile(uintptr(fd), "external-purge-child")
			if child == nil {
				_ = unix.Close(fd)
				return ErrPurgeInvalid
			}
			err = purgeTrustedDirectoryAt(ctx, child, depth+1)
			_ = child.Close()
			if err != nil {
				return err
			}
			err = unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR)
			if err == nil || errors.Is(err, unix.ENOENT) {
				return nil
			}
			if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EINVAL) {
				continue
			}
			return err
		}
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, unix.ELOOP) {
			return err
		}
		err = unix.Unlinkat(parentFD, name, 0)
		if err == nil || errors.Is(err, unix.ENOENT) {
			return nil
		}
		if errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENOTDIR) {
			continue
		}
		return err
	}
	return errors.New("external purge entry changed during deletion")
}

func openChildDirectory(parentFD int, name string) (int, error) {
	// Openat2's beneath/no-symlink/no-mount resolution closes the race where a
	// directory entry is replaced with a symlink or a mount while traversing.
	how := &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV}
	return unix.Openat2(parentFD, name, how)
}

// Close releases the startup-bound descriptors. It is safe to call more than
// once; an in-flight Purge is serialized with Close by the registry mutex.
func (r *PurgeRegistry) Close() error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var first error
	for i := len(r.roots) - 1; i >= 0; i-- {
		if err := r.roots[i].file.Close(); err != nil && first == nil {
			first = err
		}
		r.roots[i].file = nil
	}
	return first
}

// Roots returns the immutable names and resolved paths for diagnostics and
// focused composition tests. It does not expose descriptors.
func (r *PurgeRegistry) Roots() []RootSpec {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RootSpec, 0, len(r.roots))
	for _, root := range r.roots {
		out = append(out, RootSpec{Name: root.name, Path: root.path})
	}
	return out
}
