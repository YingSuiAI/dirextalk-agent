//go:build linux

package extensionrunner

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// OpenVerifiedResultFilesFD reopens runner-verified outputs beneath the exact
// workspace descriptor and proves their size and digest again before handing
// read-only descriptors to the authenticated Agent client.
func OpenVerifiedResultFilesFD(workspaceFD int, verified []ResultFile) ([]*os.File, error) {
	if workspaceFD < 0 || len(verified) > maxV2ResultFiles {
		return nil, ErrInvalid
	}
	files := make([]*os.File, 0, len(verified))
	closeFiles := func() {
		for _, file := range files {
			_ = file.Close()
		}
	}
	for _, result := range verified {
		if !safeRelativeSlash(result.Path) || sandboxReservedResultPath(result.Path) || result.Size < 0 || result.Size > MaxOutputBytes || !digestRE.MatchString(result.SHA256) {
			closeFiles()
			return nil, ErrInvalid
		}
		how := &unix.OpenHow{Flags: uint64(unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW), Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS}
		fd, err := unix.Openat2(workspaceFD, result.Path, how)
		if err != nil {
			closeFiles()
			return nil, ErrInvalid
		}
		file := os.NewFile(uintptr(fd), result.Path)
		var stat unix.Stat_t
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(file, MaxOutputBytes+1))
		if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Size != result.Size ||
			readErr != nil || n != result.Size || hex.EncodeToString(hash.Sum(nil)) != result.SHA256 {
			_ = file.Close()
			closeFiles()
			return nil, ErrInvalid
		}
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			_ = file.Close()
			closeFiles()
			return nil, ErrInvalid
		}
		files = append(files, file)
	}
	return files, nil
}

// VerifyResultFilesFD performs the production result handoff without
// reconstructing a host path. openat2 makes every component stay beneath the
// already-authorized task workspace and rejects symlinks and magic links.
func VerifyResultFilesFD(workspaceFD int, registered []string, maxTotalBytes int64) ([]ResultFile, error) {
	files, err := collectResultFilesFD(workspaceFD, registered, maxTotalBytes, true)
	return files, err
}

func CollectAvailableResultFilesFD(workspaceFD int, registered []string, maxTotalBytes int64) ([]ResultFile, error) {
	return collectResultFilesFD(workspaceFD, registered, maxTotalBytes, false)
}

func collectResultFilesFD(workspaceFD int, registered []string, maxTotalBytes int64, requireAll bool) ([]ResultFile, error) {
	if workspaceFD < 0 || maxTotalBytes <= 0 || len(registered) > maxV2ResultFiles {
		return nil, ErrInvalid
	}
	files := make([]ResultFile, 0, len(registered))
	var totalBytes int64
	var result error
	for _, rel := range registered {
		if !safeRelativeSlash(rel) || sandboxReservedResultPath(rel) {
			if requireAll {
				return files, ErrInvalid
			}
			result = errors.Join(result, ErrInvalid)
			continue
		}
		how := &unix.OpenHow{
			// O_NONBLOCK makes opening an attacker-controlled FIFO or device
			// non-blocking; Fstat below accepts only an exact regular file.
			Flags:   uint64(unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW),
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_SYMLINKS,
		}
		fd, err := unix.Openat2(workspaceFD, rel, how)
		if err != nil {
			if !requireAll && err == unix.ENOENT {
				continue
			}
			if requireAll {
				return files, ErrInvalid
			}
			result = errors.Join(result, ErrInvalid)
			continue
		}
		var stat unix.Stat_t
		if err = unix.Fstat(fd, &stat); err != nil ||
			stat.Mode&unix.S_IFMT != unix.S_IFREG ||
			stat.Size < 0 ||
			stat.Size > MaxOutputBytes ||
			totalBytes > maxTotalBytes-stat.Size {
			_ = unix.Close(fd)
			if requireAll {
				return files, ErrInvalid
			}
			result = errors.Join(result, ErrInvalid)
			continue
		}
		file := os.NewFile(uintptr(fd), rel)
		hash := sha256.New()
		n, readErr := io.Copy(hash, io.LimitReader(file, MaxOutputBytes+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || n != stat.Size || n > MaxOutputBytes {
			if requireAll {
				return files, ErrInvalid
			}
			result = errors.Join(result, ErrInvalid)
			continue
		}
		files = append(files, ResultFile{
			Path:   rel,
			SHA256: hex.EncodeToString(hash.Sum(nil)),
			Size:   n,
		})
		totalBytes += n
	}
	return files, result
}
