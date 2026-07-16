//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

type AtomicTrustMaterializer struct{}

func NewAtomicTrustMaterializer() *AtomicTrustMaterializer { return &AtomicTrustMaterializer{} }

func (*AtomicTrustMaterializer) Replace(ctx context.Context, spec TrustFileSpec, content []byte) (bool, error) {
	if ctx == nil || spec.Path != DefaultTrustFile || spec.Mode != 0o400 || spec.UID != 0 || spec.GID != 0 || len(content) == 0 || len(content) > 64<<10 || os.Geteuid() != 0 {
		return false, ErrMaterialize
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	parent := filepath.Dir(spec.Path)
	parentInfo, err := os.Lstat(parent)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || !rootOwnedExact(parentInfo, 0o700) {
		return false, ErrMaterialize
	}
	if existing, readErr := installer.ReadRootOwnedFile(spec.Path, 64<<10); readErr == nil {
		existingInfo, statErr := os.Lstat(spec.Path)
		same := statErr == nil && rootOwnedExact(existingInfo, spec.Mode) && bytes.Equal(existing, content)
		clear(existing)
		if same {
			return false, nil
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return false, ErrMaterialize
	}
	temporary, err := os.CreateTemp(parent, ".trust.cbor.tmp-")
	if err != nil {
		return false, ErrMaterialize
	}
	temporaryName := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chown(spec.UID, spec.GID); err != nil {
		return false, ErrMaterialize
	}
	if err := temporary.Chmod(0o600); err != nil {
		return false, ErrMaterialize
	}
	if _, err := temporary.Write(content); err != nil || ctx.Err() != nil {
		return false, ErrMaterialize
	}
	if err := temporary.Sync(); err != nil || temporary.Chmod(spec.Mode) != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return false, ErrMaterialize
	}
	temporaryInfo, err := os.Lstat(temporaryName)
	if err != nil || !temporaryInfo.Mode().IsRegular() || !rootOwnedExact(temporaryInfo, spec.Mode) {
		return false, ErrMaterialize
	}
	if err := os.Rename(temporaryName, spec.Path); err != nil {
		return false, ErrMaterialize
	}
	keep = true
	directory, err := os.Open(parent)
	if err != nil {
		return false, ErrMaterialize
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	if syncErr != nil || closeErr != nil {
		return false, ErrMaterialize
	}
	readBack, err := installer.ReadRootOwnedFile(spec.Path, 64<<10)
	if err != nil || !bytes.Equal(readBack, content) {
		clear(readBack)
		return false, ErrMaterialize
	}
	clear(readBack)
	return true, nil
}

func rootOwnedExact(info os.FileInfo, mode os.FileMode) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0 && info.Mode().Perm() == mode
}
