package runtime

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
)

type PinnedFile struct {
	Path   string
	SHA256 string
}

func (pin PinnedFile) validate() error {
	if !cleanAbsolute(pin.Path) || !validDigest(pin.SHA256) {
		return ErrInvalid
	}
	return nil
}

// PiRelease pins both executable code paths admitted to the Cloud Worker.
// The result extension is the only extension Pi may load.
type PiRelease struct {
	Version         string
	Executable      PinnedFile
	ResultExtension PinnedFile
}

func (release PiRelease) validate() error {
	if !versionPattern.MatchString(release.Version) ||
		release.Executable.validate() != nil ||
		release.ResultExtension.validate() != nil ||
		release.Executable.Path == release.ResultExtension.Path {
		return ErrInvalid
	}
	return nil
}

func (release PiRelease) verify() error {
	if release.validate() != nil ||
		verifyPinnedFile(release.Executable, true) != nil ||
		verifyPinnedFile(release.ResultExtension, false) != nil {
		return ErrInvalid
	}
	return nil
}

func (release PiRelease) matches(task Task) bool {
	return release.Version == task.PiVersion &&
		release.Executable.SHA256 == task.PiExecutableSHA256 &&
		release.ResultExtension.SHA256 == task.ResultExtensionSHA256
}

func verifyPinnedFile(pin PinnedFile, executable bool) error {
	if pin.validate() != nil {
		return ErrInvalid
	}
	before, err := os.Lstat(pin.Path)
	if err != nil || before.Mode()&os.ModeSymlink != 0 ||
		!before.Mode().IsRegular() || before.Mode().Perm()&0o022 != 0 {
		return ErrInvalid
	}
	if executable && before.Mode().Perm()&0o111 == 0 {
		return ErrInvalid
	}
	if !executable && before.Mode().Perm()&0o111 != 0 {
		return ErrInvalid
	}
	file, err := os.Open(filepath.Clean(pin.Path))
	if err != nil {
		return ErrInvalid
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return ErrInvalid
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return ErrInvalid
	}
	after, err := os.Lstat(pin.Path)
	if err != nil || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, after) || after.Size() != before.Size() {
		return ErrInvalid
	}
	expected, err := hex.DecodeString(pin.SHA256)
	if err != nil || len(expected) != sha256.Size {
		clear(expected)
		return ErrInvalid
	}
	defer clear(expected)
	actual := hasher.Sum(nil)
	defer clear(actual)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return ErrInvalid
	}
	return nil
}
