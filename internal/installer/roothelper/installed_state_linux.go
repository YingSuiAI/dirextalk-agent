//go:build linux

package roothelper

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"io"
	"os"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	"golang.org/x/sys/unix"
)

const (
	secretVersionXattr     = "trusted.dirextalk.version-id"
	secretDigestXattr      = "trusted.dirextalk.content-sha256"
	maxObservedSecretBytes = 64 << 10
)

func (*RootOwnedInstalledStateInspector) VerifySecret(ctx context.Context, secret installer.SecretV1) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	fd, err := unix.Open(secret.TargetPath, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnavailable
	}
	file := os.NewFile(uintptr(fd), secret.TargetPath)
	if file == nil {
		_ = unix.Close(fd)
		return ErrUnavailable
	}
	defer file.Close()
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		uint32(stat.Mode)&0o777 != secret.FileMode || stat.Uid != secret.OwnerUID ||
		stat.Gid != secret.OwnerGID || stat.Size < 1 || stat.Size > maxObservedSecretBytes {
		return ErrUnavailable
	}
	size, err := unix.Fgetxattr(fd, secretVersionXattr, nil)
	if err != nil || size < 1 || size > 1024 || size != len(secret.VersionID) {
		return ErrUnavailable
	}
	version := make([]byte, size)
	read, err := unix.Fgetxattr(fd, secretVersionXattr, version)
	matched := err == nil && read == size && string(version) == secret.VersionID
	clear(version)
	if !matched {
		return ErrUnavailable
	}
	expectedDigest := make([]byte, sha256.Size)
	read, err = unix.Fgetxattr(fd, secretDigestXattr, expectedDigest)
	if err != nil || read != sha256.Size {
		clear(expectedDigest)
		return ErrUnavailable
	}
	hasher := sha256.New()
	if _, err := io.CopyN(hasher, file, stat.Size); err != nil {
		clear(expectedDigest)
		return ErrUnavailable
	}
	actualDigest := hasher.Sum(nil)
	matched = subtle.ConstantTimeCompare(actualDigest, expectedDigest) == 1
	clear(actualDigest)
	clear(expectedDigest)
	if !matched {
		return ErrUnavailable
	}
	return nil
}
