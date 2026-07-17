//go:build linux

package roothelper

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/helperkey"
)

// RootOwnedSigningKeyFile is the production fixed-path materializer. It has no
// configurable path, mode, uid, or gid surface.
type RootOwnedSigningKeyFile struct{}

func NewRootOwnedSigningKeyFile() *RootOwnedSigningKeyFile { return &RootOwnedSigningKeyFile{} }

func (*RootOwnedSigningKeyFile) ReplaceRootHelperSigningKey(ctx context.Context, content []byte) error {
	if ctx == nil || os.Geteuid() != 0 || len(content) != ed25519.PrivateKeySize || ctx.Err() != nil {
		return ErrUnavailable
	}
	parent := filepath.Dir(helperkey.SecretTarget)
	if err := ensureRootHelperDirectory(parent); err != nil {
		return ErrUnavailable
	}
	temporary, err := os.CreateTemp(parent, ".signing.key.tmp-")
	if err != nil {
		return ErrUnavailable
	}
	temporaryName := temporary.Name()
	renamed := false
	defer func() {
		_ = temporary.Close()
		if !renamed {
			_ = os.Remove(temporaryName)
		}
	}()
	if temporary.Chown(0, 0) != nil || temporary.Chmod(0o600) != nil {
		return ErrUnavailable
	}
	if _, err := temporary.Write(content); err != nil || ctx.Err() != nil ||
		temporary.Sync() != nil || temporary.Chmod(0o400) != nil ||
		temporary.Sync() != nil || temporary.Close() != nil {
		return ErrUnavailable
	}
	info, err := os.Lstat(temporaryName)
	if err != nil || !rootOwnedExact(info, 0o400, int64(len(content))) {
		return ErrUnavailable
	}
	if os.Rename(temporaryName, helperkey.SecretTarget) != nil {
		return ErrUnavailable
	}
	renamed = true
	directory, err := os.Open(parent)
	if err != nil {
		return ErrUnavailable
	}
	syncErr, closeErr := directory.Sync(), directory.Close()
	if syncErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	readBack, err := readRootOwnedSigningKey()
	matched := err == nil && bytes.Equal(readBack, content)
	clear(readBack)
	if !matched {
		return ErrUnavailable
	}
	return nil
}

func (*RootOwnedSigningKeyFile) ReadRootHelperSigningKey(ctx context.Context) ([]byte, error) {
	if ctx == nil || os.Geteuid() != 0 || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	return readRootOwnedSigningKey()
}

func ensureRootHelperDirectory(parent string) error {
	base := filepath.Dir(parent)
	baseInfo, err := os.Lstat(base)
	if err != nil || !baseInfo.IsDir() || !rootOwnedDirectory(baseInfo) {
		return ErrUnavailable
	}
	info, err := os.Lstat(parent)
	if os.IsNotExist(err) {
		if os.Mkdir(parent, 0o700) != nil {
			return ErrUnavailable
		}
		info, err = os.Lstat(parent)
	}
	if err != nil || !info.IsDir() || !rootOwnedExact(info, 0o700, -1) {
		return ErrUnavailable
	}
	return nil
}

func readRootOwnedSigningKey() ([]byte, error) {
	before, err := os.Lstat(helperkey.SecretTarget)
	if err != nil || !rootOwnedExact(before, 0o400, ed25519.PrivateKeySize) {
		return nil, ErrUnavailable
	}
	file, err := os.Open(helperkey.SecretTarget)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !rootOwnedExact(opened, 0o400, ed25519.PrivateKeySize) {
		return nil, ErrUnavailable
	}
	value := make([]byte, ed25519.PrivateKeySize)
	if count, err := file.Read(value); err != nil || count != len(value) {
		clear(value)
		return nil, ErrUnavailable
	}
	var extra [1]byte
	if count, _ := file.Read(extra[:]); count != 0 {
		clear(value)
		return nil, ErrUnavailable
	}
	return value, nil
}

func rootOwnedDirectory(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0 && info.Mode().IsDir() && info.Mode().Perm()&0o022 == 0
}

func rootOwnedExact(info os.FileInfo, mode os.FileMode, size int64) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && stat.Gid == 0 && info.Mode()&os.ModeSymlink == 0 &&
		info.Mode().Perm() == mode && (size < 0 || info.Size() == size)
}
