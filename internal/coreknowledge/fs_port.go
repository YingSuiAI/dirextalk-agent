package coreknowledge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

// RootManagedFileOpener resolves paths beneath root using descriptor-relative
// traversal and O_NOFOLLOW on every component.
type RootManagedFileOpener struct{ root *os.File }

func NewRootManagedFileOpener(root string) (*RootManagedFileOpener, error) {
	f, err := openTrustedRoot(root)
	if err != nil {
		return nil, ErrFilesystemUnavailable
	}
	return &RootManagedFileOpener{root: f}, nil
}

func (o *RootManagedFileOpener) Close() error {
	if o == nil || o.root == nil {
		return nil
	}
	err := o.root.Close()
	o.root = nil
	return err
}

// Purge removes every entry below the already-opened trusted mount root
// without following a pathname replacement or symlink. It is reserved for
// explicit account deprovisioning; ordinary mount deletion uses source-level
// cleanup instead.
func (o *RootManagedFileOpener) Purge(ctx context.Context) error {
	if o == nil || o.root == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalid
	}
	return purgeTrustedRoot(ctx, o.root)
}

func (o *RootManagedFileOpener) OpenManaged(ctx context.Context, relative string) (io.ReadCloser, error) {
	if o == nil || o.root == nil || ctx == nil || ctx.Err() != nil || validateRelativePath(relative) != nil {
		return nil, ErrPathTraversal
	}
	parts := strings.Split(relative, "/")
	cur := int(o.root.Fd())
	owned := false
	defer func() {
		if owned {
			_ = unix.Close(cur)
		}
	}()
	for i, part := range parts {
		flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
		if i < len(parts)-1 {
			flags |= unix.O_DIRECTORY
		}
		fd, err := unix.Openat(cur, part, flags, 0)
		if err != nil {
			return nil, ErrFilesystemUnavailable
		}
		if owned {
			_ = unix.Close(cur)
		}
		cur = fd
		owned = true
	}
	file := os.NewFile(uintptr(cur), filepath.Base(relative))
	if file == nil {
		return nil, ErrFilesystemUnavailable
	}
	owned = false
	return file, nil
}

type RootContentPort struct {
	root     *os.File
	quota    int64
	mu       sync.Mutex
	used     int64
	reserved int64
}

func NewRootContentPort(root string, quota int64) (*RootContentPort, error) {
	if quota < 1 {
		return nil, ErrInvalid
	}
	f, err := openTrustedRoot(root)
	if err != nil {
		return nil, ErrFilesystemUnavailable
	}
	used, err := scanFinalizedContent(f)
	if err != nil || used > quota {
		_ = f.Close()
		return nil, ErrFilesystemUnavailable
	}
	return &RootContentPort{root: f, quota: quota, used: used}, nil
}

// openTrustedRoot binds the port to the opened directory descriptor.  A later
// rename or symlink replacement of the configured pathname cannot redirect any
// openat operation below this boundary.
func openTrustedRoot(path string) (*os.File, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0o022 != 0 {
		_ = unix.Close(fd)
		return nil, ErrFilesystemUnavailable
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		_ = unix.Close(fd)
		return nil, ErrFilesystemUnavailable
	}
	return f, nil
}

// scanFinalizedContent accounts only regular finalized objects opened relative
// to the retained root descriptor. Staging files are reservations, not quota
// usage, and are reconstructed by their durable upload records.
func scanFinalizedContent(root *os.File) (int64, error) {
	dup, err := unix.Dup(int(root.Fd()))
	if err != nil {
		return 0, err
	}
	dir := os.NewFile(uintptr(dup), root.Name())
	if dir == nil {
		_ = unix.Close(dup)
		return 0, ErrFilesystemUnavailable
	}
	defer dir.Close()
	entries, err := dir.ReadDir(-1)
	if err != nil {
		return 0, err
	}
	var used int64
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "content-") || validateRelativePath(name) != nil {
			continue
		}
		fd, openErr := unix.Openat(int(root.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil {
			return 0, openErr
		}
		var st unix.Stat_t
		statErr := unix.Fstat(fd, &st)
		_ = unix.Close(fd)
		if statErr != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Size < 0 {
			return 0, ErrFilesystemUnavailable
		}
		if used > int64(^uint64(0)>>1)-st.Size {
			return 0, ErrLimitExceeded
		}
		used += st.Size
	}
	return used, nil
}

func (p *RootContentPort) Close() error {
	if p == nil || p.root == nil {
		return nil
	}
	err := p.root.Close()
	p.root = nil
	return err
}

// Purge removes all finalized/staging content below the trusted content root
// and resets quota accounting. The root descriptor remains open so a caller
// may finish a deprovision response before shutting the Agent down.
func (p *RootContentPort) Purge(ctx context.Context) error {
	if p == nil || p.root == nil || ctx == nil || ctx.Err() != nil {
		return ErrInvalid
	}
	if err := purgeTrustedRoot(ctx, p.root); err != nil {
		return err
	}
	p.mu.Lock()
	p.used, p.reserved = 0, 0
	p.mu.Unlock()
	return nil
}

func purgeTrustedRoot(ctx context.Context, root *os.File) error {
	if root == nil {
		return ErrFilesystemUnavailable
	}
	dup, err := unix.Dup(int(root.Fd()))
	if err != nil {
		return ErrFilesystemUnavailable
	}
	dir := os.NewFile(uintptr(dup), root.Name())
	if dir == nil {
		_ = unix.Close(dup)
		return ErrFilesystemUnavailable
	}
	entries, err := dir.ReadDir(-1)
	_ = dir.Close()
	if err != nil {
		return ErrFilesystemUnavailable
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		name := entry.Name()
		if validateRelativePath(name) != nil {
			return ErrPathTraversal
		}
		flags := 0
		if entry.IsDir() && entry.Type()&os.ModeSymlink == 0 {
			flags = unix.AT_REMOVEDIR
		}
		if err := unix.Unlinkat(int(root.Fd()), name, flags); err != nil && !errors.Is(err, unix.ENOENT) {
			return ErrCleanupPending
		}
	}
	return nil
}

func (p *RootContentPort) Begin(ctx context.Context, m UploadMetadata) (ContentSink, error) {
	if p == nil || ctx == nil || m.DeclaredSize < 1 || m.DeclaredSize > MaxUploadBytes {
		return nil, ErrInvalid
	}
	if m.UploadID == "" {
		m.UploadID = uuid.NewString()
	}
	p.mu.Lock()
	if p.used+p.reserved+m.DeclaredSize > p.quota {
		p.mu.Unlock()
		return nil, ErrLimitExceeded
	}
	p.reserved += m.DeclaredSize
	p.mu.Unlock()
	name := uploadTempName(m.UploadID)
	fd, err := unix.Openat(int(p.root.Fd()), name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err == nil {
		return &fileContentSink{port: p, file: os.NewFile(uintptr(fd), name), temp: name, uploadID: m.UploadID, max: m.DeclaredSize, h: sha256.New()}, nil
	}
	p.mu.Lock()
	p.reserved -= m.DeclaredSize
	p.mu.Unlock()
	return nil, ErrFilesystemUnavailable
}

// Resume reopens the deterministic upload staging object after a process
// restart. A tail written after the last durable chunk is truncated; a short
// or differently hashed prefix is rejected rather than silently repaired.
func (p *RootContentPort) Resume(ctx context.Context, m UploadMetadata, receivedSize int64, _ int32) (ContentSink, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || m.UploadID == "" || m.DeclaredSize < 1 || receivedSize < 0 || receivedSize > m.DeclaredSize {
		return nil, ErrInvalid
	}
	temp := uploadTempName(m.UploadID)
	fd, err := unix.Openat(int(p.root.Fd()), temp, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return nil, ErrFilesystemUnavailable
		}
		// A successful rename may have happened immediately before the database
		// commit became uncertain. Treat that final object as an idempotently
		// finalized sink and let the repository retry its metadata commit.
		finalName := contentName(m.ContentSHA256, m.UploadID)
		finalFD, finalErr := unix.Openat(int(p.root.Fd()), finalName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if finalErr != nil {
			if errors.Is(err, unix.ENOENT) && errors.Is(finalErr, unix.ENOENT) {
				return nil, ErrNotFound
			}
			return nil, ErrFilesystemUnavailable
		}
		file := os.NewFile(uintptr(finalFD), finalName)
		st, statErr := file.Stat()
		if statErr != nil || !st.Mode().IsRegular() || st.Size() != m.DeclaredSize {
			_ = file.Close()
			return nil, ErrChecksumMismatch
		}
		digest, hashErr := hashFilePrefix(file, st.Size())
		_ = file.Close()
		if hashErr != nil || !strings.EqualFold(digest, m.ContentSHA256) {
			return nil, ErrChecksumMismatch
		}
		return &fileContentSink{port: p, uploadID: m.UploadID, max: m.DeclaredSize, size: st.Size(), finalizedRef: finalName, finalizedDigest: strings.ToLower(digest), done: true}, nil
	}
	file := os.NewFile(uintptr(fd), temp)
	st, statErr := file.Stat()
	if statErr != nil || !st.Mode().IsRegular() {
		_ = file.Close()
		return nil, ErrFilesystemUnavailable
	}
	if st.Size() < receivedSize || st.Size() > m.DeclaredSize {
		_ = file.Close()
		return nil, ErrChecksumMismatch
	}
	if st.Size() > receivedSize {
		if err := file.Truncate(receivedSize); err != nil {
			_ = file.Close()
			return nil, ErrFilesystemUnavailable
		}
	}
	if _, err := file.Seek(receivedSize, io.SeekStart); err != nil {
		_ = file.Close()
		return nil, ErrFilesystemUnavailable
	}
	h := sha256.New()
	if receivedSize > 0 {
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			return nil, ErrFilesystemUnavailable
		}
		if _, err := io.CopyN(h, file, receivedSize); err != nil {
			_ = file.Close()
			return nil, ErrFilesystemUnavailable
		}
		if _, err := file.Seek(receivedSize, io.SeekStart); err != nil {
			_ = file.Close()
			return nil, ErrFilesystemUnavailable
		}
	}
	if receivedSize == m.DeclaredSize && !strings.EqualFold(hex.EncodeToString(h.Sum(nil)), m.ContentSHA256) {
		_ = file.Close()
		return nil, ErrChecksumMismatch
	}
	p.mu.Lock()
	if p.used+p.reserved+m.DeclaredSize > p.quota {
		p.mu.Unlock()
		_ = file.Close()
		return nil, ErrLimitExceeded
	}
	p.reserved += m.DeclaredSize
	p.mu.Unlock()
	return &fileContentSink{port: p, file: file, temp: temp, uploadID: m.UploadID, max: m.DeclaredSize, size: receivedSize, h: h}, nil
}

func uploadTempName(uploadID string) string { return ".upload-" + uploadID }
func contentName(digest, uploadID string) string {
	return "content-" + strings.ToLower(digest) + "-" + uploadID
}

func hashFilePrefix(file *os.File, size int64) (string, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	h := sha256.New()
	if size > 0 {
		if _, err := io.CopyN(h, file, size); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (p *RootContentPort) Delete(_ context.Context, ref ContentReference) error {
	if p == nil || p.root == nil || ref.Ref == "" || validateRelativePath(ref.Ref) != nil {
		return ErrPathTraversal
	}
	parts := strings.Split(ref.Ref, "/")
	parent := int(p.root.Fd())
	var opened []int
	defer func() {
		for _, fd := range opened {
			_ = unix.Close(fd)
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		fd, err := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return ErrNotFound
		}
		opened = append(opened, fd)
		parent = fd
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return ErrCleanupPending
	}
	file := os.NewFile(uintptr(fd), ref.Ref)
	if file == nil {
		_ = unix.Close(fd)
		return ErrCleanupPending
	}
	st, statErr := file.Stat()
	if statErr != nil || !st.Mode().IsRegular() || st.Size() != ref.SizeBytes {
		_ = file.Close()
		return ErrChecksumMismatch
	}
	digest, hashErr := hashFilePrefix(file, st.Size())
	_ = file.Close()
	if hashErr != nil || (ref.Digest != "" && !strings.EqualFold(digest, ref.Digest)) {
		return ErrChecksumMismatch
	}
	if err := unix.Unlinkat(parent, parts[len(parts)-1], 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return ErrCleanupPending
	}
	p.mu.Lock()
	p.used -= ref.SizeBytes
	if p.used < 0 {
		p.used = 0
	}
	p.mu.Unlock()
	return nil
}

// OpenContent reopens a finalized upload by its persisted descriptor. It is
// intentionally optional so the base StreamingContentPort contract remains
// small while restartable workers can consume immutable bytes safely.
func (p *RootContentPort) OpenContent(ctx context.Context, ref ContentReference) (io.ReadCloser, error) {
	if p == nil || p.root == nil || ctx == nil || ctx.Err() != nil || validateRelativePath(ref.Ref) != nil {
		return nil, ErrPathTraversal
	}
	fd, err := unix.Openat(int(p.root.Fd()), ref.Ref, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrFilesystemUnavailable
	}
	f := os.NewFile(uintptr(fd), ref.Ref)
	if f == nil {
		_ = unix.Close(fd)
		return nil, ErrFilesystemUnavailable
	}
	st, err := f.Stat()
	if err != nil || !st.Mode().IsRegular() || st.Size() != ref.SizeBytes {
		_ = f.Close()
		return nil, ErrChecksumMismatch
	}
	if ref.Digest != "" {
		digest, hashErr := hashFilePrefix(f, st.Size())
		if hashErr != nil || !strings.EqualFold(digest, ref.Digest) {
			_ = f.Close()
			return nil, ErrChecksumMismatch
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			_ = f.Close()
			return nil, ErrFilesystemUnavailable
		}
	}
	return f, nil
}

type fileContentSink struct {
	port             *RootContentPort
	file             *os.File
	temp             string
	uploadID         string
	max, size        int64
	h                hash.Hash
	finalizedRef     string
	finalizedDigest  string
	done             bool
	reservedReleased bool
}

// Rewind truncates an uncommitted append and rebuilds the running digest. It
// is intentionally optional on ContentSink; the PostgreSQL saga uses it when
// a definitive metadata write failure occurs, while an unknown commit outcome
// leaves the sink untouched for recovery.
func (s *fileContentSink) Rewind(_ context.Context, size int64) error {
	if s == nil || s.done || s.file == nil || size < 0 || size > s.size {
		return ErrInvalid
	}
	if err := s.file.Truncate(size); err != nil {
		return ErrFilesystemUnavailable
	}
	h := sha256.New()
	if _, err := s.file.Seek(0, io.SeekStart); err != nil {
		return ErrFilesystemUnavailable
	}
	if size > 0 {
		if _, err := io.CopyN(h, s.file, size); err != nil {
			return ErrFilesystemUnavailable
		}
	}
	if _, err := s.file.Seek(size, io.SeekStart); err != nil {
		return ErrFilesystemUnavailable
	}
	s.h, s.size = h, size
	return nil
}

func (s *fileContentSink) Write(p []byte) (int, error) {
	if s.done || s.size+int64(len(p)) > s.max {
		return 0, ErrLimitExceeded
	}
	n, err := s.file.Write(p)
	if err == nil {
		_, _ = s.h.Write(p)
		s.size += int64(n)
	}
	return n, err
}
func (s *fileContentSink) Size() int64 { return s.size }
func (s *fileContentSink) SHA256() string {
	if s.finalizedDigest != "" {
		return s.finalizedDigest
	}
	return hex.EncodeToString(s.h.Sum(nil))
}
func (s *fileContentSink) Finalize(_ context.Context, digest string, size int64) (ContentReference, error) {
	if s.done && s.finalizedRef != "" && s.size == size && strings.EqualFold(s.SHA256(), digest) {
		return ContentReference{Ref: s.finalizedRef, Digest: strings.ToLower(digest), SizeBytes: size}, nil
	}
	if s.done || s.size != size || !strings.EqualFold(s.SHA256(), digest) {
		_ = s.Abort(context.Background())
		return ContentReference{}, ErrChecksumMismatch
	}
	if err := s.file.Sync(); err != nil {
		_ = s.Abort(context.Background())
		return ContentReference{}, ErrFilesystemUnavailable
	}
	if err := s.file.Close(); err != nil {
		_ = s.Abort(context.Background())
		return ContentReference{}, ErrFilesystemUnavailable
	}
	name := contentName(digest, s.uploadID)
	if err := unix.Renameat(int(s.port.root.Fd()), s.temp, int(s.port.root.Fd()), name); err != nil {
		_ = s.Abort(context.Background())
		return ContentReference{}, ErrFilesystemUnavailable
	}
	_ = unix.Fsync(int(s.port.root.Fd()))
	s.done = true
	s.finalizedRef = name
	s.finalizedDigest = strings.ToLower(digest)
	s.port.mu.Lock()
	s.port.used += size
	s.port.mu.Unlock()
	s.releaseReservation()
	return ContentReference{Ref: name, Digest: strings.ToLower(digest), SizeBytes: size}, nil
}
func (s *fileContentSink) Abort(_ context.Context) error {
	if s == nil || s.done {
		return nil
	}
	if s.file != nil {
		_ = s.file.Close()
	}
	if s.temp != "" {
		_ = unix.Unlinkat(int(s.port.root.Fd()), s.temp, 0)
	}
	s.done = true
	s.releaseReservation()
	return nil
}

func (s *fileContentSink) releaseReservation() {
	if s == nil || s.port == nil || s.reservedReleased {
		return
	}
	s.port.mu.Lock()
	s.port.reserved -= s.max
	if s.port.reserved < 0 {
		s.port.reserved = 0
	}
	s.port.mu.Unlock()
	s.reservedReleased = true
}
