// Package workspacearchive defines the single constrained workspace archive
// accepted by Native Agent turns and materialized by Cloud Workers.
package workspacearchive

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	MediaType        = "application/vnd.dirextalk.workspace+tar+gzip"
	MaxEntries       = 4096
	MaxExpandedBytes = int64(256 << 20)
	MaxEntryBytes    = int64(64 << 20)
	MaxPathBytes     = 1024
)

var ErrInvalid = errors.New("workspace archive: invalid")

// Validate fully consumes and validates a gzip-compressed tar archive. The
// accepted format contains only canonical directories and regular files.
func Validate(source io.Reader) error {
	return inspect(source, "", false)
}

// Extract repeats the complete validation at the Worker boundary and writes
// only below an already private, empty destination directory.
func Extract(source io.Reader, destination string) error {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return ErrInvalid
	}
	info, err := os.Lstat(destination)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrInvalid
	}
	entries, err := os.ReadDir(destination)
	if err != nil || len(entries) != 0 {
		return ErrInvalid
	}
	return inspect(source, destination, true)
}

func inspect(source io.Reader, destination string, extract bool) error {
	if source == nil {
		return ErrInvalid
	}
	buffered := bufio.NewReader(source)
	compressed := &countingByteReader{reader: buffered}
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return ErrInvalid
	}
	gz.Multistream(false)
	expanded := &limitedCounter{reader: gz, remaining: MaxExpandedBytes + 1}
	tape := tar.NewReader(expanded)
	seen := make(map[string]entryKind)
	seenFolded := make(map[string]string)
	entryCount := 0
	for {
		header, nextErr := tape.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil || header == nil {
			_ = gz.Close()
			return ErrInvalid
		}
		name, kind, skip, validateErr := validateHeader(header)
		if skip {
			continue
		}
		entryCount++
		if entryCount > MaxEntries {
			_ = gz.Close()
			return ErrInvalid
		}
		if validateErr != nil || validatePathSet(name, kind, seen, seenFolded) != nil {
			_ = gz.Close()
			return ErrInvalid
		}
		seen[name] = kind
		seenFolded[strings.ToLower(name)] = name
		if extract {
			if err := extractEntry(tape, destination, name, kind, header.Size); err != nil {
				_ = gz.Close()
				return err
			}
		} else if copied, err := io.Copy(io.Discard, tape); err != nil || copied != header.Size {
			_ = gz.Close()
			return ErrInvalid
		}
	}
	// tar.Reader must consume the exact decompressed tape, including its two
	// zero records. Any byte after the terminator is non-canonical trailing data.
	var one [1]byte
	if count, readErr := gz.Read(one[:]); count != 0 || !errors.Is(readErr, io.EOF) || expanded.exceeded ||
		(MaxExpandedBytes+1-expanded.remaining) > MaxExpandedBytes {
		_ = gz.Close()
		return ErrInvalid
	}
	if gz.Close() != nil || buffered.Buffered() != 0 {
		return ErrInvalid
	}
	// gzip is configured for one member. A second member or arbitrary suffix
	// remains in the underlying reader and is always rejected.
	if _, err := buffered.Peek(1); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	if entryCount == 0 {
		return ErrInvalid
	}
	return nil
}

type entryKind uint8

const (
	entryDirectory entryKind = iota + 1
	entryRegular
)

func validateHeader(header *tar.Header) (string, entryKind, bool, error) {
	name := header.Name
	if strings.HasPrefix(name, "./") {
		name = strings.TrimPrefix(name, "./")
		if strings.HasPrefix(name, "./") {
			return "", 0, false, ErrInvalid
		}
	}
	if header.Typeflag == tar.TypeDir {
		name = strings.TrimSuffix(name, "/")
	}
	if name == "" && header.Typeflag == tar.TypeDir {
		return "", 0, true, nil
	}
	if !validPath(name) || header.Linkname != "" || header.Xattrs != nil || !validPAX(header.PAXRecords) {
		return "", 0, false, ErrInvalid
	}
	switch header.Typeflag {
	case tar.TypeDir:
		if header.Size != 0 || header.Mode&^0o755 != 0 {
			return "", 0, false, ErrInvalid
		}
		return name, entryDirectory, false, nil
	case tar.TypeReg, tar.TypeRegA:
		if header.Size < 0 || header.Size > MaxEntryBytes || header.Mode&^0o755 != 0 {
			return "", 0, false, ErrInvalid
		}
		return name, entryRegular, false, nil
	default:
		// Symlinks, hardlinks, devices, FIFOs, sparse files, PAX and GNU
		// extension records are deliberately outside the workspace contract.
		return "", 0, false, ErrInvalid
	}
}

func validPAX(records map[string]string) bool {
	if len(records) == 0 {
		return true
	}
	if len(records) > 8 {
		return false
	}
	total := 0
	for key, value := range records {
		total += len(key) + len(value)
		if total > 4096 || len(key) > 128 || len(value) > MaxPathBytes {
			return false
		}
		switch key {
		case "path", "mtime", "atime", "ctime":
		default:
			return false
		}
	}
	return true
}

func validPath(value string) bool {
	if value == "" || len(value) > MaxPathBytes || value != strings.TrimSpace(value) ||
		!utf8.ValidString(value) || strings.Contains(value, "\\") || strings.HasPrefix(value, "/") ||
		path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") ||
		strings.IndexFunc(value, func(r rune) bool { return unicode.IsControl(r) }) >= 0 {
		return false
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." || strings.TrimSpace(component) != component {
			return false
		}
	}
	return true
}

func validatePathSet(name string, kind entryKind, seen map[string]entryKind, folded map[string]string) error {
	if _, duplicate := seen[name]; duplicate {
		return ErrInvalid
	}
	if existing, collision := folded[strings.ToLower(name)]; collision && existing != name {
		return ErrInvalid
	}
	components := strings.Split(name, "/")
	for index := 1; index < len(components); index++ {
		ancestor := strings.Join(components[:index], "/")
		if ancestorKind, exists := seen[ancestor]; exists && ancestorKind != entryDirectory {
			return ErrInvalid
		}
		if existing, collision := folded[strings.ToLower(ancestor)]; collision && existing != ancestor {
			return ErrInvalid
		}
	}
	if kind == entryRegular {
		prefix := name + "/"
		foldedPrefix := strings.ToLower(prefix)
		for existing := range seen {
			if strings.HasPrefix(existing, prefix) || strings.HasPrefix(strings.ToLower(existing), foldedPrefix) {
				return ErrInvalid
			}
		}
	}
	return nil
}

func extractEntry(reader io.Reader, root, name string, kind entryKind, size int64) error {
	target := filepath.Join(root, filepath.FromSlash(name))
	if !strings.HasPrefix(target, root+string(os.PathSeparator)) || filepath.Clean(target) != target {
		return ErrInvalid
	}
	if kind == entryDirectory {
		if err := os.MkdirAll(target, 0o700); err != nil {
			return fmt.Errorf("%w: create directory", ErrInvalid)
		}
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		return fmt.Errorf("%w: create parent", ErrInvalid)
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrInvalid
	}
	written, copyErr := io.Copy(file, reader)
	syncErr := file.Sync()
	closeErr := file.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || written != size {
		return ErrInvalid
	}
	return nil
}

type countingByteReader struct {
	reader *bufio.Reader
}

func (reader *countingByteReader) Read(value []byte) (int, error) { return reader.reader.Read(value) }
func (reader *countingByteReader) ReadByte() (byte, error)        { return reader.reader.ReadByte() }

type limitedCounter struct {
	reader    io.Reader
	remaining int64
	exceeded  bool
}

func (reader *limitedCounter) Read(value []byte) (int, error) {
	if reader.remaining <= 0 {
		reader.exceeded = true
		return 0, ErrInvalid
	}
	if int64(len(value)) > reader.remaining {
		value = value[:reader.remaining]
	}
	count, err := reader.reader.Read(value)
	reader.remaining -= int64(count)
	return count, err
}
