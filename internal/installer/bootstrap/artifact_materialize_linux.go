//go:build linux

package bootstrap

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

type AtomicArtifactMaterializer struct{}

func NewAtomicArtifactMaterializer() *AtomicArtifactMaterializer {
	return &AtomicArtifactMaterializer{}
}

func (*AtomicArtifactMaterializer) Replace(ctx context.Context, spec ArtifactFileSpec, source io.Reader) (bool, error) {
	if ctx == nil || source == nil || os.Geteuid() != 0 || spec.Mode != 0o500 || spec.UID != 0 || spec.GID != 0 ||
		spec.SizeBytes < 1 || spec.SizeBytes > 8<<30 || !digestPattern.MatchString(spec.SHA256) || !validArtifactTarget(spec.Path) {
		return false, ErrMaterialize
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	target := filepath.FromSlash(spec.Path)
	parent := filepath.Dir(target)
	if !rootOwnedDirectoryChain(filepath.FromSlash(installer.PreinstalledArtifactRoot), parent) {
		return false, ErrMaterialize
	}
	temporary, err := os.CreateTemp(parent, ".dirextalk-artifact.tmp-")
	if err != nil {
		return false, ErrMaterialize
	}
	temporaryName := temporary.Name()
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = os.Remove(temporaryName)
		}
	}()
	if temporary.Chown(spec.UID, spec.GID) != nil || temporary.Chmod(0o600) != nil {
		return false, ErrMaterialize
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(&artifactContextReader{ctx: ctx, reader: source}, spec.SizeBytes+1))
	expected, decodeErr := hex.DecodeString(strings.TrimPrefix(spec.SHA256, "sha256:"))
	actual := hasher.Sum(nil)
	matched := decodeErr == nil && len(expected) == sha256.Size && subtle.ConstantTimeCompare(actual, expected) == 1
	clear(expected)
	clear(actual)
	if copyErr != nil || written != spec.SizeBytes || !matched || ctx.Err() != nil {
		return false, ErrMaterialize
	}
	if temporary.Sync() != nil || temporary.Chmod(spec.Mode) != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return false, ErrMaterialize
	}
	info, err := os.Lstat(temporaryName)
	if err != nil || !info.Mode().IsRegular() || !rootOwnedExact(info, spec.Mode) || info.Size() != spec.SizeBytes {
		return false, ErrMaterialize
	}
	if os.Rename(temporaryName, target) != nil {
		return false, ErrMaterialize
	}
	renamed = true
	directory, err := os.Open(parent)
	if err != nil {
		return false, ErrMaterialize
	}
	syncErr, closeErr := directory.Sync(), directory.Close()
	if syncErr != nil || closeErr != nil {
		return false, ErrMaterialize
	}
	inspector, err := installer.NewRootOwnedArtifactInspector(installer.PreinstalledArtifactRoot)
	if err != nil || inspector.Verify(ctx, installer.ArtifactV1{
		Name: path.Base(spec.Path), SHA256: spec.SHA256, SizeBytes: spec.SizeBytes, TargetPath: spec.Path,
	}) != nil {
		return false, ErrMaterialize
	}
	return true, nil
}

func validArtifactTarget(target string) bool {
	root := installer.PreinstalledArtifactRoot
	return path.IsAbs(target) && path.Clean(target) == target && target != root && strings.HasPrefix(target, root+"/") && !strings.Contains(target, "\\")
}

func rootOwnedDirectoryChain(root, parent string) bool {
	root = filepath.Clean(root)
	parent = filepath.Clean(parent)
	relative, err := filepath.Rel(root, parent)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	current := root
	parts := []string{}
	if relative != "." {
		parts = strings.Split(relative, string(filepath.Separator))
	}
	for _, part := range append([]string{""}, parts...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		info, statErr := os.Lstat(current)
		stat, ok := infoSyscall(info)
		if statErr != nil || !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || stat.Uid != 0 || stat.Gid != 0 || info.Mode().Perm()&0o022 != 0 {
			return false
		}
	}
	return true
}

func infoSyscall(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

type artifactContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *artifactContextReader) Read(buffer []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(buffer)
	}
}
