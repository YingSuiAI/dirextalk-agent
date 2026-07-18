package installer

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"syscall"
)

type archivePolicy struct {
	maxEntries int
	maxFile    int64
	maxTotal   int64
	allow      func(string, bool) bool
	verify     map[string]ModelFileEvidence
	modes      map[string]os.FileMode
}

func extractTarGzip(archivePath, destination string, policy archivePolicy) error {
	file, err := openRegularNoFollow(archivePath)
	if err != nil {
		return fmt.Errorf("open fixed archive: %w", err)
	}
	defer file.Close()
	gzipReader, err := gzip.NewReader(file)
	if err != nil {
		return fmt.Errorf("open gzip archive: %w", err)
	}
	defer gzipReader.Close()
	gzipReader.Multistream(false)
	reader := tar.NewReader(gzipReader)
	seen := make(map[string]bool)
	verified := make(map[string]bool)
	var total int64
	for count := 0; ; count++ {
		if count >= policy.maxEntries {
			return fmt.Errorf("archive entry limit exceeded")
		}
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read archive: %w", err)
		}
		isDirectory := header.Typeflag == tar.TypeDir
		name, err := cleanArchiveName(header.Name, isDirectory)
		if err != nil {
			return err
		}
		if !isDirectory && header.Typeflag != tar.TypeReg && header.Typeflag != tar.TypeRegA {
			return fmt.Errorf("archive links and special files are forbidden")
		}
		if seen[name] {
			return fmt.Errorf("duplicate archive member")
		}
		seen[name] = true
		if !policy.allow(name, isDirectory) {
			return fmt.Errorf("unexpected archive member")
		}
		if header.Size < 0 || header.Size > policy.maxFile {
			return fmt.Errorf("archive member size is invalid")
		}
		total += header.Size
		if total > policy.maxTotal {
			return fmt.Errorf("archive expanded size limit exceeded")
		}
		target := filepath.Join(destination, filepath.FromSlash(name))
		if !withinDirectory(destination, target) {
			return fmt.Errorf("archive member escapes destination")
		}
		if isDirectory {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return fmt.Errorf("create archive directory: %w", err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return fmt.Errorf("create archive parent: %w", err)
		}
		mode := os.FileMode(0o644)
		if fixed, ok := policy.modes[name]; ok {
			mode = fixed
		}
		output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return fmt.Errorf("create extracted file: %w", err)
		}
		digest := sha256.New()
		written, copyErr := io.Copy(io.MultiWriter(output, digest), io.LimitReader(reader, header.Size))
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil || written != header.Size {
			return fmt.Errorf("extract archive member")
		}
		if expected, ok := policy.verify[name]; ok {
			if written != expected.Size || hex.EncodeToString(digest.Sum(nil)) != expected.SHA256 {
				return fmt.Errorf("archive member provenance mismatch")
			}
			verified[name] = true
		}
	}
	if len(verified) != len(policy.verify) {
		return fmt.Errorf("archive is missing required members")
	}
	return nil
}

func cleanArchiveName(value string, directory bool) (string, error) {
	if value == "" || strings.Contains(value, "\\") || strings.IndexByte(value, 0) >= 0 || path.IsAbs(value) {
		return "", fmt.Errorf("unsafe archive path")
	}
	if directory {
		value = strings.TrimRight(value, "/")
	} else if strings.HasSuffix(value, "/") {
		return "", fmt.Errorf("unsafe archive path")
	}
	for strings.HasPrefix(value, "./") {
		value = strings.TrimPrefix(value, "./")
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || cleaned != value {
		return "", fmt.Errorf("unsafe archive path")
	}
	return cleaned, nil
}

func withinDirectory(root, target string) bool {
	relative, err := filepath.Rel(filepath.Clean(root), filepath.Clean(target))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func fileDigest(path string) (int64, string, error) {
	file, err := openRegularNoFollow(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, file)
	if err != nil {
		return 0, "", err
	}
	return size, hex.EncodeToString(digest.Sum(nil)), nil
}

func openRegularNoFollow(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("fixed input is not a regular file")
	}
	return file, nil
}
