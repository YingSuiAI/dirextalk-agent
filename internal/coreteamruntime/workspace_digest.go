package coreteamruntime

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	EmptyWorkspaceDigest   = "a6d96e7895784902e84ed50c4b78be199ba643b27b17e270ba684546d49ee07f"
	workspaceDigestDomain  = "dirextalk.agent.core-team-workspace/v1\x00"
	maxWorkspaceFiles      = 100_000
	maxWorkspaceBytes      = int64(4 << 30)
	maxWorkspacePathBytes  = 4096
	workspaceDirectoryKind = byte('d')
	workspaceFileKind      = byte('f')
	workspaceSymlinkKind   = byte('l')
)

// DigestWorkspace hashes the exact materialized tree without following
// symlinks. Paths, entry kinds, executable intent, symlink targets, and file
// bytes all enter the digest.
func DigestWorkspace(root string) (string, error) {
	if root == "" {
		return EmptyWorkspaceDigest, nil
	}
	if !cleanAbsolute(root) {
		return "", ErrInvalid
	}
	rootState, err := os.Lstat(root)
	if err != nil || rootState.Mode()&os.ModeSymlink != 0 || !rootState.IsDir() {
		return "", ErrInvalid
	}
	hasher := sha256.New()
	_, _ = io.WriteString(hasher, workspaceDigestDomain)
	files := 0
	var totalBytes int64
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrInvalid
		}
		if path == root {
			return nil
		}
		files++
		if files > maxWorkspaceFiles {
			return ErrInvalid
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return ErrInvalid
		}
		relative = filepath.ToSlash(relative)
		if len(relative) == 0 || len(relative) > maxWorkspacePathBytes || strings.Contains(relative, "\\") {
			return ErrInvalid
		}
		state, err := os.Lstat(path)
		if err != nil {
			return ErrInvalid
		}
		switch {
		case state.IsDir():
			writeWorkspaceDigestRecord(hasher, workspaceDirectoryKind, relative, false, 0, nil)
			return nil
		case state.Mode().IsRegular():
			if state.Size() < 0 || state.Size() > maxWorkspaceBytes-totalBytes {
				return ErrInvalid
			}
			content, err := stableWorkspaceFileDigest(path, state)
			if err != nil {
				return err
			}
			totalBytes += state.Size()
			writeWorkspaceDigestRecord(hasher, workspaceFileKind, relative, state.Mode().Perm()&0o111 != 0, state.Size(), content[:])
			return nil
		case state.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil || !safeWorkspaceDigestSymlink(relative, target) {
				return ErrInvalid
			}
			writeWorkspaceDigestRecord(hasher, workspaceSymlinkKind, relative, false, int64(len(target)), []byte(target))
			return nil
		default:
			return ErrInvalid
		}
	})
	if err != nil {
		return "", ErrInvalid
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func VerifyWorkspaceDigest(root, expected string) error {
	if !digestPattern.MatchString(expected) {
		return ErrInvalid
	}
	actual, err := DigestWorkspace(root)
	if err != nil || actual != expected {
		return ErrInvalid
	}
	return nil
}

func stableWorkspaceFileDigest(path string, before os.FileInfo) ([sha256.Size]byte, error) {
	var empty [sha256.Size]byte
	file, err := os.Open(path)
	if err != nil {
		return empty, ErrInvalid
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) || !opened.Mode().IsRegular() || opened.Size() != before.Size() {
		return empty, ErrInvalid
	}
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, before.Size()+1))
	if err != nil || written != before.Size() {
		return empty, ErrInvalid
	}
	after, err := os.Lstat(path)
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) || after.Size() != before.Size() {
		return empty, ErrInvalid
	}
	copy(empty[:], hasher.Sum(nil))
	return empty, nil
}

func writeWorkspaceDigestRecord(target io.Writer, kind byte, path string, executable bool, size int64, payload []byte) {
	var number [8]byte
	_, _ = target.Write([]byte{kind})
	binary.BigEndian.PutUint64(number[:], uint64(len(path)))
	_, _ = target.Write(number[:])
	_, _ = io.WriteString(target, path)
	if executable {
		_, _ = target.Write([]byte{1})
	} else {
		_, _ = target.Write([]byte{0})
	}
	binary.BigEndian.PutUint64(number[:], uint64(size))
	_, _ = target.Write(number[:])
	_, _ = target.Write(payload)
}

func safeWorkspaceDigestSymlink(name, target string) bool {
	if target == "" || len(target) > maxWorkspacePathBytes || filepath.IsAbs(target) || strings.Contains(target, "\\") || strings.IndexByte(target, 0) >= 0 {
		return false
	}
	resolved := filepath.Clean(filepath.Join(filepath.Dir(name), filepath.FromSlash(target)))
	return resolved != "." && resolved != ".." && !strings.HasPrefix(resolved, ".."+string(filepath.Separator))
}
