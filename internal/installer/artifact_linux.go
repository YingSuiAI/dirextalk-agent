//go:build linux

package installer

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

type rootOwnedArtifactInspector struct {
	root string
}

func NewRootOwnedArtifactInspector(root string) (ArtifactInspector, error) {
	clean, err := validateTargetRoot(root)
	if err != nil {
		return nil, err
	}
	return &rootOwnedArtifactInspector{root: clean}, nil
}

func (i *rootOwnedArtifactInspector) Verify(ctx context.Context, artifact ArtifactV1) error {
	if err := validateArtifactPath(i.root, artifact.TargetPath); err != nil {
		return err
	}
	if err := verifyRootOwnedPath(artifact.TargetPath, true); err != nil {
		return &protocolError{code: CodeArtifactVerification, err: err}
	}
	file, err := os.Open(filepath.FromSlash(artifact.TargetPath))
	if err != nil {
		return &protocolError{code: CodeArtifactVerification, err: fmt.Errorf("open approved artifact: %w", err)}
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.SizeBytes || !rootOwnedAndImmutable(info) {
		return errorf(CodeArtifactVerification, "approved artifact metadata changed")
	}
	expected, err := parseDigest(artifact.SHA256)
	if err != nil {
		return err
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, &contextReader{ctx: ctx, reader: file}); err != nil {
		return &protocolError{code: CodeArtifactVerification, err: fmt.Errorf("hash approved artifact: %w", err)}
	}
	actual := hasher.Sum(nil)
	if subtle.ConstantTimeCompare(actual, expected[:]) != 1 {
		return errorf(CodeArtifactVerification, "approved artifact digest mismatch")
	}
	return nil
}

// ReadRootOwnedFile loads a small daemon trust/config file only when the file
// and every path component are root-owned, non-symlink, and not writable by
// group or other users.
func ReadRootOwnedFile(name string, maxBytes int64) ([]byte, error) {
	if maxBytes < 1 {
		return nil, errorf(CodeInvalidRequest, "invalid root-owned file size limit")
	}
	if err := verifyRootOwnedPath(name, true); err != nil {
		return nil, err
	}
	file, err := os.Open(filepath.FromSlash(name))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maxBytes || !rootOwnedAndImmutable(info) {
		return nil, errorf(CodeInvalidRequest, "root-owned file metadata is invalid")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(content)) > maxBytes {
		return nil, errorf(CodeInvalidRequest, "read root-owned file within limit")
	}
	return content, nil
}

func verifyRootOwnedPath(name string, requireRegular bool) error {
	clean := filepath.Clean(filepath.FromSlash(name))
	if !filepath.IsAbs(clean) || clean != filepath.FromSlash(name) {
		return errorf(CodeInvalidPath, "path must be clean and absolute")
	}
	current := string(filepath.Separator)
	parts := strings.Split(strings.TrimPrefix(clean, current), current)
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect root-owned path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !rootOwnedAndImmutable(info) {
			return fmt.Errorf("path component is not immutable root-owned content")
		}
		last := index == len(parts)-1
		if !last && !info.IsDir() {
			return fmt.Errorf("path parent is not a directory")
		}
		if last && requireRegular && !info.Mode().IsRegular() {
			return fmt.Errorf("target is not a regular file")
		}
	}
	return nil
}

func rootOwnedAndImmutable(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && info.Mode().Perm()&0o022 == 0
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(buffer []byte) (int, error) {
	select {
	case <-r.ctx.Done():
		return 0, r.ctx.Err()
	default:
		return r.reader.Read(buffer)
	}
}
