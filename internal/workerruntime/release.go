package workerruntime

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"github.com/google/uuid"
)

type InstalledExtension struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func (extension InstalledExtension) Validate() error {
	if !validCatalogName(extension.Name) ||
		!cleanAbsolute(extension.Path) ||
		!validDigest(extension.SHA256) {
		return ErrInvalid
	}
	return nil
}

func (extension InstalledExtension) Verify() error {
	if extension.Validate() != nil {
		return ErrInvalid
	}
	return verifyInstalledFile(
		extension.Path,
		extension.SHA256,
		false,
	)
}

type InstalledRelease struct {
	ReleaseID        string  `json:"release_id"`
	Version          string  `json:"version"`
	ImageDigest      string  `json:"image_digest"`
	Adapter          Adapter `json:"adapter"`
	ExecutablePath   string  `json:"executable_path"`
	ExecutableSHA256 string  `json:"executable_sha256"`
}

func (release InstalledRelease) Validate() error {
	if !canonicalUUID(release.ReleaseID) ||
		!releaseVersion.MatchString(release.Version) ||
		!validDigest(release.ImageDigest) ||
		!validAdapter(release.Adapter) ||
		!cleanAbsolute(release.ExecutablePath) ||
		!validDigest(release.ExecutableSHA256) {
		return ErrInvalid
	}
	parsed, err := uuid.Parse(release.ReleaseID)
	if err != nil || parsed == uuid.Nil {
		return ErrInvalid
	}
	return nil
}

func (release InstalledRelease) VerifyExecutable() error {
	if release.Validate() != nil {
		return ErrInvalid
	}
	return verifyInstalledFile(
		release.ExecutablePath,
		release.ExecutableSHA256,
		true,
	)
}

func verifyInstalledFile(
	filePath,
	expectedDigest string,
	requireExecutable bool,
) error {
	before, err := os.Lstat(filePath)
	if err != nil || before.Mode()&os.ModeSymlink != 0 ||
		!before.Mode().IsRegular() ||
		before.Mode().Perm()&0o022 != 0 {
		return ErrInvalid
	}
	if requireExecutable && before.Mode().Perm()&0o111 == 0 {
		return ErrInvalid
	}
	if !requireExecutable && before.Mode().Perm()&0o111 != 0 {
		return ErrInvalid
	}
	file, err := os.Open(filepath.Clean(filePath))
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
	after, err := os.Lstat(filePath)
	if err != nil || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, after) || after.Size() != before.Size() {
		return ErrInvalid
	}
	expected, err := hex.DecodeString(
		expectedDigest[len("sha256:"):],
	)
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

func (release InstalledRelease) Matches(task TaskV1) bool {
	return task.RuntimeReleaseID == release.ReleaseID &&
		task.RuntimeVersion == release.Version &&
		task.RuntimeImageDigest == release.ImageDigest &&
		task.Adapter == release.Adapter
}
