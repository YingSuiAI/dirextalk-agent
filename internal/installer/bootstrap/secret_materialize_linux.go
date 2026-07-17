//go:build linux

package bootstrap

import (
	"bytes"
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
)

type AtomicSecretMaterializer struct{}

func NewAtomicSecretMaterializer() *AtomicSecretMaterializer { return &AtomicSecretMaterializer{} }

func (*AtomicSecretMaterializer) ReplaceSecret(ctx context.Context, spec SecretFileSpec, content []byte) (bool, error) {
	if ctx == nil || os.Geteuid() != 0 || len(content) == 0 || len(content) > maxSecretBytes || !validSecretTarget(spec.Path) ||
		(spec.Mode != 0o400 && spec.Mode != 0o440) || spec.UID < 0 || spec.UID > 65535 || spec.GID < 0 || spec.GID > 65535 {
		return false, ErrMaterialize
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	target := filepath.FromSlash(spec.Path)
	parent := filepath.Dir(target)
	if !rootOwnedDirectoryChain(filepath.FromSlash(installer.PreinstalledSecretRoot), parent) {
		return false, ErrMaterialize
	}
	temporary, err := os.CreateTemp(parent, ".dirextalk-secret.tmp-")
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
	if _, err := temporary.Write(content); err != nil || ctx.Err() != nil || temporary.Sync() != nil || temporary.Chmod(spec.Mode) != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return false, ErrMaterialize
	}
	info, err := os.Lstat(temporaryName)
	if err != nil || !ownedExact(info, spec.Mode, uint32(spec.UID), uint32(spec.GID)) || info.Size() != int64(len(content)) {
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
	if syncErr, closeErr := directory.Sync(), directory.Close(); syncErr != nil || closeErr != nil {
		return false, ErrMaterialize
	}
	readBack, err := os.ReadFile(target)
	matched := err == nil && bytes.Equal(readBack, content)
	clear(readBack)
	finalInfo, statErr := os.Lstat(target)
	if !matched || statErr != nil || !ownedExact(finalInfo, spec.Mode, uint32(spec.UID), uint32(spec.GID)) {
		return false, ErrMaterialize
	}
	return true, nil
}

func validSecretTarget(target string) bool {
	root := installer.PreinstalledSecretRoot
	return path.IsAbs(target) && path.Clean(target) == target && target != root && strings.HasPrefix(target, root+"/") && !strings.Contains(target, "\\")
}

func ownedExact(info os.FileInfo, mode os.FileMode, uid, gid uint32) bool {
	stat, ok := infoSyscall(info)
	return ok && info.Mode().IsRegular() && stat.Uid == uid && stat.Gid == gid && info.Mode().Perm() == mode
}
