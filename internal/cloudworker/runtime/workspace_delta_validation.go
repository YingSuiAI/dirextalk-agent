package runtime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// ValidateWorkspaceDeltaArchive is shared by the Worker emitter and the
// central exact-version result validator. It treats gzip/tar as an untrusted
// transport and accepts only the one canonical delta layout emitted here.
func ValidateWorkspaceDeltaArchive(
	raw []byte,
	expectedInputManifestSHA256 string,
	maximumExpandedBytes uint64,
) error {
	if len(raw) == 0 || len(raw) > MaxArtifactBytes ||
		!validDigest(expectedInputManifestSHA256) || maximumExpandedBytes == 0 ||
		maximumExpandedBytes > MaxArtifactBytes {
		return ErrInvalid
	}
	source := bytes.NewBuffer(raw)
	gzipReader, err := gzip.NewReader(source)
	if err != nil {
		return ErrInvalid
	}
	gzipReader.Multistream(false)
	if gzipReader.Name != "" || gzipReader.Comment != "" || len(gzipReader.Extra) != 0 ||
		(!gzipReader.ModTime.IsZero() && !gzipReader.ModTime.Equal(time.Unix(0, 0).UTC())) ||
		gzipReader.OS != 255 {
		_ = gzipReader.Close()
		return ErrInvalid
	}
	archive := tar.NewReader(gzipReader)
	manifestHeader, err := archive.Next()
	if err != nil || !validDeltaTarHeader(
		manifestHeader, workspaceDeltaManifestPath, workspaceEntryFile, 0o444,
	) || manifestHeader.Size <= 0 || uint64(manifestHeader.Size) > maximumExpandedBytes {
		_ = gzipReader.Close()
		return ErrInvalid
	}
	manifestRaw, err := readBoundedTarEntry(archive, manifestHeader.Size)
	if err != nil {
		_ = gzipReader.Close()
		return err
	}
	manifest, err := parseWorkspaceDeltaManifest(
		manifestRaw, expectedInputManifestSHA256,
	)
	if err != nil {
		clear(manifestRaw)
		_ = gzipReader.Close()
		return err
	}
	defer clear(manifestRaw)
	changes := make([]workspaceEntry, 0, len(manifest.Changes))
	defer destroyWorkspaceEntries(changes)
	expanded := uint64(manifestHeader.Size)
	for _, change := range manifest.Changes {
		header, nextErr := archive.Next()
		expectedName := workspaceDeltaFilesRoot + "/" + change.Path
		mode, modeErr := parseWorkspaceMode(change.Mode)
		if change.Type == workspaceEntryDirectory {
			expectedName += "/"
		}
		if nextErr != nil || modeErr != nil || !validDeltaTarHeader(
			header, expectedName, change.Type, mode,
		) || header.Size != change.SizeBytes ||
			uint64(header.Size) > maximumExpandedBytes-expanded {
			_ = gzipReader.Close()
			return ErrInvalid
		}
		expanded += uint64(header.Size)
		content, readErr := readBoundedTarEntry(archive, header.Size)
		if readErr != nil {
			_ = gzipReader.Close()
			return readErr
		}
		if change.Type == workspaceEntryFile {
			digest := sha256DigestBytes(content)
			if digest != change.SHA256 {
				clear(content)
				_ = gzipReader.Close()
				return ErrInvalid
			}
		}
		changes = append(changes, workspaceEntry{
			Path: change.Path, Type: change.Type, Mode: mode,
			SizeBytes: change.SizeBytes, SHA256: change.SHA256, Content: content,
		})
	}
	if _, err := archive.Next(); !errors.Is(err, io.EOF) {
		_ = gzipReader.Close()
		return ErrInvalid
	}
	if err := gzipReader.Close(); err != nil || source.Len() != 0 {
		return ErrInvalid
	}
	canonical, err := archiveWorkspaceDelta(
		context.Background(), changes, manifestRaw, len(raw),
	)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return ErrInvalid
	}
	clear(canonical)
	return nil
}

func parseWorkspaceDeltaManifest(
	raw []byte,
	expectedInputManifestSHA256 string,
) (workspaceDeltaManifest, error) {
	if len(raw) == 0 || len(raw) > MaxArtifactBytes {
		return workspaceDeltaManifest{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest workspaceDeltaManifest
	if decoder.Decode(&manifest) != nil {
		return workspaceDeltaManifest{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return workspaceDeltaManifest{}, ErrInvalid
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, raw) {
		clear(canonical)
		return workspaceDeltaManifest{}, ErrInvalid
	}
	clear(canonical)
	if manifest.Schema != workspaceDeltaSchemaV1 ||
		manifest.InputManifestSHA256 != expectedInputManifestSHA256 ||
		!validDigest(manifest.BaselineSHA256) || manifest.Changes == nil ||
		manifest.Deletions == nil || len(manifest.Changes)+len(manifest.Deletions) > maxWorkspaceOutputEntries {
		return workspaceDeltaManifest{}, ErrInvalid
	}
	seen := make(map[string]struct{}, len(manifest.Changes)+len(manifest.Deletions))
	previous := ""
	for _, change := range manifest.Changes {
		if (change.Change != "added" && change.Change != "modified" && change.Change != "replaced") ||
			!validWorkspaceDeltaDescriptor(change.Path, change.Type, change.Mode, change.SizeBytes, change.SHA256) ||
			(previous != "" && change.Path <= previous) {
			return workspaceDeltaManifest{}, ErrInvalid
		}
		seen[change.Path] = struct{}{}
		previous = change.Path
	}
	previous = ""
	for _, deletion := range manifest.Deletions {
		if !validWorkspaceDeltaDescriptor(
			deletion.Path, deletion.Type, deletion.Mode, deletion.SizeBytes, deletion.SHA256,
		) || (previous != "" && deletion.Path <= previous) {
			return workspaceDeltaManifest{}, ErrInvalid
		}
		if _, conflict := seen[deletion.Path]; conflict {
			return workspaceDeltaManifest{}, ErrInvalid
		}
		seen[deletion.Path] = struct{}{}
		previous = deletion.Path
	}
	return manifest, nil
}

func validWorkspaceDeltaDescriptor(
	path string,
	typeName workspaceEntryType,
	mode string,
	size int64,
	digest string,
) bool {
	if !validWorkspaceDeltaPath(filepathFromCanonical(path)) {
		return false
	}
	parsedMode, err := parseWorkspaceMode(mode)
	if err != nil || parsedMode > 0o777 {
		return false
	}
	switch typeName {
	case workspaceEntryDirectory:
		return size == 0 && digest == ""
	case workspaceEntryFile:
		return size >= 0 && validDigest(digest)
	default:
		return false
	}
}

func parseWorkspaceMode(value string) (uint32, error) {
	if len(value) != 4 {
		return 0, ErrInvalid
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil || value != strings.ToLower(value) || parsed > 0o777 {
		return 0, ErrInvalid
	}
	return uint32(parsed), nil
}

func filepathFromCanonical(value string) string {
	// Runtime images are Linux-only, while unit tests also execute on Unix hosts.
	// Backslashes are rejected by validWorkspaceDeltaPath before this conversion.
	return filepath.FromSlash(value)
}

func validDeltaTarHeader(
	header *tar.Header,
	expectedName string,
	expectedType workspaceEntryType,
	expectedMode uint32,
) bool {
	if header == nil || header.Name != expectedName || header.Linkname != "" ||
		header.Mode != int64(expectedMode) || header.Uid != 0 || header.Gid != 0 ||
		header.Uname != "" || header.Gname != "" ||
		!header.ModTime.Equal(time.Unix(0, 0).UTC()) || !header.AccessTime.IsZero() ||
		!header.ChangeTime.IsZero() || !validDeltaPAXRecords(header) {
		return false
	}
	switch expectedType {
	case workspaceEntryDirectory:
		return header.Typeflag == tar.TypeDir && header.Size == 0 && strings.HasSuffix(header.Name, "/")
	case workspaceEntryFile:
		return header.Typeflag == tar.TypeReg && header.Size >= 0 && !strings.HasSuffix(header.Name, "/")
	default:
		return false
	}
}

func validDeltaPAXRecords(header *tar.Header) bool {
	for key, value := range header.PAXRecords {
		if key != "path" || value != header.Name {
			return false
		}
	}
	return true
}

func readBoundedTarEntry(reader io.Reader, size int64) ([]byte, error) {
	if reader == nil || size < 0 || size > MaxArtifactBytes {
		return nil, ErrInvalid
	}
	content, err := io.ReadAll(io.LimitReader(reader, size+1))
	if err != nil || int64(len(content)) != size {
		clear(content)
		return nil, ErrInvalid
	}
	return content, nil
}

func sha256DigestBytes(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
