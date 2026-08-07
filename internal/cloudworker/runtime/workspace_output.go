package runtime

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	maxWorkspaceOutputEntries  = 1024
	workspaceDeltaSchemaV1     = "dirextalk.agent.workspace-delta/v1"
	workspaceBaselineSchemaV1  = "dirextalk.agent.workspace-baseline/v1"
	workspaceDeltaManifestPath = "meta/delta.json"
	workspaceDeltaFilesRoot    = "files"
)

type workspaceEntryType string

const (
	workspaceEntryDirectory workspaceEntryType = "directory"
	workspaceEntryFile      workspaceEntryType = "file"
)

type workspaceEntry struct {
	Path      string
	Type      workspaceEntryType
	Mode      uint32
	SizeBytes int64
	SHA256    string
	Content   []byte
	Patchable bool
}

func (entry *workspaceEntry) destroy() {
	if entry == nil {
		return
	}
	clear(entry.Content)
	entry.Content = nil
}

// WorkspaceBaseline is an in-memory Worker-owned snapshot taken before Pi is
// started. Its fields are deliberately private so neither a claimed task nor
// Pi output can manufacture or rewrite the comparison authority.
type WorkspaceBaseline struct {
	directory           string
	root                *os.File
	rootInfo            os.FileInfo
	entries             map[string]workspaceEntry
	digest              string
	inputManifestSHA256 string
}

func (baseline *WorkspaceBaseline) Destroy() {
	if baseline == nil {
		return
	}
	for path, entry := range baseline.entries {
		entry.destroy()
		delete(baseline.entries, path)
	}
	if baseline.root != nil {
		_ = baseline.root.Close()
	}
	*baseline = WorkspaceBaseline{}
}

func (baseline WorkspaceBaseline) validFor(directory string) bool {
	if baseline.root == nil {
		return false
	}
	current, err := baseline.root.Stat()
	return err == nil && cleanAbsolute(directory) && baseline.directory == directory &&
		baseline.rootInfo != nil && baseline.rootInfo.IsDir() &&
		baseline.rootInfo.Mode()&os.ModeSymlink == 0 &&
		os.SameFile(baseline.rootInfo, current) &&
		validDigest(baseline.inputManifestSHA256) &&
		len(baseline.entries) <= maxWorkspaceOutputEntries &&
		matchesWorkspaceBaselineDigest(baseline)
}

// FilesystemOutputCollector snapshots an isolated write workspace before Pi
// starts and emits only its delta afterwards. Baseline content never goes into
// the archive unless Pi changed or deleted that exact path.
type FilesystemOutputCollector struct{}

func (FilesystemOutputCollector) Snapshot(
	ctx context.Context,
	workspace string,
	inputManifestSHA256 string,
	maximumBytes uint64,
) (WorkspaceBaseline, error) {
	if ctx == nil || !cleanAbsolute(workspace) || maximumBytes == 0 ||
		maximumBytes > MaxArtifactBytes || !validDigest(inputManifestSHA256) {
		return WorkspaceBaseline{}, ErrInvalid
	}
	root, rootInfo, err := openWorkspaceRoot(workspace)
	if err != nil {
		return WorkspaceBaseline{}, ErrInvalid
	}
	baseline := WorkspaceBaseline{
		directory:           workspace,
		root:                root,
		rootInfo:            rootInfo,
		entries:             make(map[string]workspaceEntry),
		inputManifestSHA256: inputManifestSHA256,
	}
	textRemaining := min(maximumBytes, uint64(MaxPatchBytes))
	directories := map[string]os.FileInfo{"": rootInfo}
	err = walkWorkspace(ctx, baseline.root, func(relative string, info os.FileInfo) error {
		if len(baseline.entries) >= maxWorkspaceOutputEntries {
			return ErrInvalid
		}
		entry := workspaceEntry{Path: relative, Mode: uint32(info.Mode().Perm())}
		switch {
		case info.IsDir():
			entry.Type = workspaceEntryDirectory
			directories[relative] = info
		case validWorkspaceRegularFile(info):
			entry.Type = workspaceEntryFile
			entry.SizeBytes = info.Size()
			captureLimit := int(min(textRemaining, uint64(MaxPatchBytes)))
			digest, content, captured, readErr := readStableWorkspaceFile(
				ctx, baseline.root, relative, info, captureLimit, nil,
			)
			if readErr != nil {
				clear(content)
				return readErr
			}
			entry.SHA256 = digest
			if captured && utf8.Valid(content) && bytes.IndexByte(content, 0) < 0 {
				entry.Content = content
				entry.Patchable = true
				textRemaining -= uint64(len(content))
			} else {
				clear(content)
			}
		default:
			return ErrInvalid
		}
		baseline.entries[relative] = entry
		return nil
	})
	if err != nil || verifyStableWorkspaceDirectories(baseline.root, directories) != nil ||
		verifyWorkspaceRoot(workspace, baseline.root, rootInfo) != nil {
		baseline.Destroy()
		if err != nil {
			return WorkspaceBaseline{}, err
		}
		return WorkspaceBaseline{}, ErrInvalid
	}
	baseline.digest, err = workspaceBaselineDigest(
		baseline.inputManifestSHA256, baseline.entries,
	)
	if err != nil {
		baseline.Destroy()
		return WorkspaceBaseline{}, err
	}
	return baseline, nil
}

func (FilesystemOutputCollector) Collect(
	ctx context.Context,
	workspace string,
	baseline WorkspaceBaseline,
	maximumBytes uint64,
) ([]Artifact, error) {
	if ctx == nil || maximumBytes == 0 || maximumBytes > MaxArtifactBytes ||
		!baseline.validFor(workspace) ||
		verifyWorkspaceRoot(workspace, baseline.root, baseline.rootInfo) != nil {
		return nil, ErrInvalid
	}
	changes, deletions, err := collectWorkspaceDelta(ctx, workspace, baseline, maximumBytes)
	if err != nil {
		destroyWorkspaceEntries(changes)
		return nil, err
	}
	defer destroyWorkspaceEntries(changes)

	manifest, err := canonicalWorkspaceDeltaManifest(baseline, changes, deletions)
	if err != nil {
		return nil, err
	}
	defer clear(manifest)
	expandedBytes := uint64(len(manifest))
	if expandedBytes > maximumBytes {
		return nil, ErrInvalid
	}
	for _, entry := range changes {
		if entry.Type == workspaceEntryFile {
			if uint64(len(entry.Content)) > maximumBytes-expandedBytes {
				return nil, ErrInvalid
			}
			expandedBytes += uint64(len(entry.Content))
		}
	}
	archive, err := archiveWorkspaceDelta(ctx, changes, manifest, int(maximumBytes))
	if err != nil {
		clear(archive)
		return nil, err
	}
	archiveArtifact := Artifact{
		Name: WorkspaceDeltaArtifactName, MediaType: "application/gzip", Content: archive,
	}
	if archiveArtifact.Validate() != nil || uint64(len(archive)) > maximumBytes ||
		ValidateWorkspaceDeltaArchive(archive, baseline.inputManifestSHA256, maximumBytes) != nil {
		clear(archive)
		return nil, ErrInvalid
	}

	patch := buildWorkspacePatch(changes, deletions, baseline, int(min(maximumBytes, uint64(MaxPatchBytes))))
	patchArtifact := Artifact{
		Name: "changes.patch", MediaType: "text/plain; charset=utf-8", Content: patch,
	}
	if len(patch) == 0 || patchArtifact.Validate() != nil ||
		uint64(len(patch))+uint64(len(archive)) > maximumBytes {
		clear(patch)
		return []Artifact{archiveArtifact}, nil
	}
	return []Artifact{patchArtifact, archiveArtifact}, nil
}

func collectWorkspaceDelta(
	ctx context.Context,
	root string,
	baseline WorkspaceBaseline,
	maximumBytes uint64,
) ([]workspaceEntry, []workspaceEntry, error) {
	current := make(map[string]workspaceEntry, len(baseline.entries))
	changes := make([]workspaceEntry, 0, 16)
	directories := make(map[string]os.FileInfo)
	rootInfo, err := baseline.root.Stat()
	if err != nil || !os.SameFile(rootInfo, baseline.rootInfo) ||
		verifyWorkspaceRoot(root, baseline.root, baseline.rootInfo) != nil {
		return nil, nil, ErrInvalid
	}
	directories[""] = rootInfo
	remaining := maximumBytes
	err = walkWorkspace(ctx, baseline.root, func(relative string, info os.FileInfo) error {
		if len(current) >= maxWorkspaceOutputEntries {
			return ErrInvalid
		}
		entry := workspaceEntry{Path: relative, Mode: uint32(info.Mode().Perm())}
		switch {
		case info.IsDir():
			entry.Type = workspaceEntryDirectory
			directories[relative] = info
		case validWorkspaceRegularFile(info):
			entry.Type = workspaceEntryFile
			entry.SizeBytes = info.Size()
			before, existed := baseline.entries[relative]
			metadataCouldMatch := existed && before.Type == workspaceEntryFile &&
				before.Mode == entry.Mode && before.SizeBytes == entry.SizeBytes
			captureLimit := int(min(remaining, uint64(MaxArtifactBytes)))
			if metadataCouldMatch && uint64(entry.SizeBytes) > remaining {
				captureLimit = 0
			}
			digest, content, captured, readErr := readStableWorkspaceFile(
				ctx, baseline.root, relative, info, captureLimit, nil,
			)
			if readErr != nil {
				clear(content)
				return readErr
			}
			entry.SHA256 = digest
			if metadataEqual(before, entry) {
				clear(content)
				current[relative] = entry
				return nil
			}
			if !captured || uint64(len(content)) > remaining {
				clear(content)
				return ErrInvalid
			}
			entry.Content = content
			remaining -= uint64(len(content))
		default:
			return ErrInvalid
		}
		current[relative] = entry
		before, existed := baseline.entries[relative]
		if !existed || !metadataEqual(before, entry) {
			changes = append(changes, entry)
		}
		return nil
	})
	if err != nil || verifyStableWorkspaceDirectories(baseline.root, directories) != nil ||
		verifyWorkspaceRoot(root, baseline.root, rootInfo) != nil {
		destroyWorkspaceEntries(changes)
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrInvalid
	}
	deletions := make([]workspaceEntry, 0, 8)
	for path, entry := range baseline.entries {
		if _, exists := current[path]; !exists {
			deletions = append(deletions, entry)
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	sort.Slice(deletions, func(i, j int) bool { return deletions[i].Path < deletions[j].Path })
	return changes, deletions, nil
}

func readStableWorkspaceFile(
	ctx context.Context,
	root *os.File,
	canonicalPath string,
	before os.FileInfo,
	captureLimit int,
	afterRead func(),
) (string, []byte, bool, error) {
	if ctx == nil || root == nil || !validWorkspaceDeltaPath(canonicalPath) ||
		!validWorkspaceRegularFile(before) || captureLimit < 0 {
		return "", nil, false, ErrInvalid
	}
	file, opened, err := openWorkspaceEntry(root, canonicalPath, true)
	if err != nil {
		return "", nil, false, ErrInvalid
	}
	defer file.Close()
	if !validWorkspaceRegularFile(opened) ||
		!os.SameFile(before, opened) || !stableFileInfo(before, opened) {
		return "", nil, false, ErrInvalid
	}
	hasher := sha256.New()
	capture := &boundedCaptureWriter{remaining: captureLimit}
	written, copyErr := io.Copy(
		io.MultiWriter(hasher, capture),
		io.LimitReader(&workspaceContextReader{ctx: ctx, reader: file}, before.Size()+1),
	)
	if afterRead != nil {
		afterRead()
	}
	openedAfter, statErr := file.Stat()
	pathAfter, after, reopenErr := openWorkspaceEntry(root, canonicalPath, false)
	if pathAfter != nil {
		defer pathAfter.Close()
	}
	if copyErr != nil || statErr != nil || reopenErr != nil || written != before.Size() ||
		!validWorkspaceRegularFile(openedAfter) || !validWorkspaceRegularFile(after) ||
		!os.SameFile(before, openedAfter) || !os.SameFile(before, after) ||
		!stableFileInfo(before, openedAfter) || !stableFileInfo(before, after) {
		capture.destroy()
		return "", nil, false, ErrInvalid
	}
	digest := hex.EncodeToString(hasher.Sum(nil))
	if capture.exceeded {
		capture.destroy()
		return digest, nil, false, nil
	}
	content := bytes.Clone(capture.buffer)
	capture.destroy()
	return digest, content, true, nil
}

func stableFileInfo(expected, actual os.FileInfo) bool {
	return expected != nil && actual != nil && expected.Mode() == actual.Mode() &&
		expected.Size() == actual.Size() && expected.ModTime().Equal(actual.ModTime()) &&
		stableWorkspaceSystemInfo(expected, actual)
}

func walkWorkspace(
	ctx context.Context,
	root *os.File,
	visit func(string, os.FileInfo) error,
) error {
	if ctx == nil || root == nil || visit == nil {
		return ErrInvalid
	}
	rootInfo, err := root.Stat()
	if err != nil || !rootInfo.IsDir() {
		return ErrInvalid
	}
	return walkWorkspaceDirectory(ctx, root, "", rootInfo, visit)
}

func walkWorkspaceDirectory(
	ctx context.Context,
	root *os.File,
	canonicalPath string,
	expected os.FileInfo,
	visit func(string, os.FileInfo) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	directory, before, err := openWorkspaceDirectory(root, canonicalPath)
	if err != nil {
		return err
	}
	defer directory.Close()
	if expected == nil || !os.SameFile(expected, before) ||
		!stableFileInfo(expected, before) {
		return ErrInvalid
	}
	children, err := directory.ReadDir(-1)
	if err != nil {
		return ErrInvalid
	}
	sort.Slice(children, func(i, j int) bool {
		return children[i].Name() < children[j].Name()
	})
	for _, child := range children {
		if err := ctx.Err(); err != nil {
			return err
		}
		childPath := child.Name()
		if canonicalPath != "" {
			childPath = canonicalPath + "/" + child.Name()
		}
		if !validWorkspaceDeltaPath(childPath) {
			return ErrInvalid
		}
		opened, info, err := openWorkspaceEntry(root, childPath, false)
		if err != nil {
			return err
		}
		_ = opened.Close()
		if info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		if err := visit(childPath, info); err != nil {
			return err
		}
		if info.IsDir() {
			if err := walkWorkspaceDirectory(ctx, root, childPath, info, visit); err != nil {
				return err
			}
		}
	}
	after, err := directory.Stat()
	if err != nil || !os.SameFile(before, after) || !stableFileInfo(before, after) {
		return ErrInvalid
	}
	reopened, current, err := openWorkspaceDirectory(root, canonicalPath)
	if reopened != nil {
		_ = reopened.Close()
	}
	if err != nil || !os.SameFile(before, current) || !stableFileInfo(before, current) {
		return ErrInvalid
	}
	return nil
}

func verifyStableWorkspaceDirectories(
	root *os.File,
	values map[string]os.FileInfo,
) error {
	if root == nil {
		return ErrInvalid
	}
	for path, before := range values {
		var (
			after os.FileInfo
			err   error
			file  *os.File
		)
		if path == "" {
			after, err = root.Stat()
		} else {
			file, after, err = openWorkspaceEntry(root, path, false)
		}
		if file != nil {
			_ = file.Close()
		}
		if err != nil || !after.IsDir() || after.Mode()&os.ModeSymlink != 0 ||
			!os.SameFile(before, after) || before.Mode() != after.Mode() ||
			!before.ModTime().Equal(after.ModTime()) {
			return ErrInvalid
		}
	}
	return nil
}

func verifyWorkspaceRoot(path string, root *os.File, expected os.FileInfo) error {
	if root == nil || expected == nil {
		return ErrInvalid
	}
	held, err := root.Stat()
	if err != nil || !os.SameFile(expected, held) || held.Mode() != expected.Mode() {
		return ErrInvalid
	}
	actual, actualInfo, err := openWorkspaceRoot(path)
	if actual != nil {
		defer actual.Close()
	}
	if err != nil || !actualInfo.IsDir() || actualInfo.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(expected, actualInfo) || expected.Mode() != actualInfo.Mode() {
		return ErrInvalid
	}
	return nil
}

func validWorkspaceDeltaPath(relative string) bool {
	clean := filepath.Clean(relative)
	canonical := filepath.ToSlash(clean)
	if relative == "" || clean != relative || clean == "." || clean == ".." ||
		filepath.IsAbs(relative) || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) ||
		strings.Contains(relative, "\\") || len(canonical) > 1024 || !utf8.ValidString(relative) ||
		strings.IndexFunc(relative, unicode.IsControl) >= 0 {
		return false
	}
	return true
}

func metadataEqual(left, right workspaceEntry) bool {
	return left.Path == right.Path && left.Type == right.Type && left.Mode == right.Mode &&
		left.SizeBytes == right.SizeBytes && left.SHA256 == right.SHA256
}

type workspaceEntryDescriptor struct {
	Path      string             `json:"path"`
	Type      workspaceEntryType `json:"type"`
	Mode      string             `json:"mode"`
	SizeBytes int64              `json:"size_bytes"`
	SHA256    string             `json:"sha256"`
}

func describeWorkspaceEntry(entry workspaceEntry) workspaceEntryDescriptor {
	return workspaceEntryDescriptor{
		Path: entry.Path, Type: entry.Type, Mode: fmt.Sprintf("%04o", entry.Mode),
		SizeBytes: entry.SizeBytes, SHA256: entry.SHA256,
	}
}

func workspaceBaselineDigest(
	inputManifestSHA256 string,
	entries map[string]workspaceEntry,
) (string, error) {
	if !validDigest(inputManifestSHA256) {
		return "", ErrInvalid
	}
	paths := make([]string, 0, len(entries))
	for path := range entries {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	descriptors := make([]workspaceEntryDescriptor, 0, len(paths))
	for _, path := range paths {
		descriptors = append(descriptors, describeWorkspaceEntry(entries[path]))
	}
	raw, err := json.Marshal(struct {
		Schema              string                     `json:"schema"`
		InputManifestSHA256 string                     `json:"input_manifest_sha256"`
		Entries             []workspaceEntryDescriptor `json:"entries"`
	}{
		Schema:              workspaceBaselineSchemaV1,
		InputManifestSHA256: inputManifestSHA256,
		Entries:             descriptors,
	})
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(digest[:]), nil
}

func matchesWorkspaceBaselineDigest(baseline WorkspaceBaseline) bool {
	digest, err := workspaceBaselineDigest(
		baseline.inputManifestSHA256, baseline.entries,
	)
	return err == nil && digest == baseline.digest
}

type workspaceDeltaChange struct {
	Change    string             `json:"change"`
	Path      string             `json:"path"`
	Type      workspaceEntryType `json:"type"`
	Mode      string             `json:"mode"`
	SizeBytes int64              `json:"size_bytes"`
	SHA256    string             `json:"sha256"`
}

type workspaceDeltaManifest struct {
	Schema              string                     `json:"schema"`
	InputManifestSHA256 string                     `json:"input_manifest_sha256"`
	BaselineSHA256      string                     `json:"baseline_sha256"`
	Changes             []workspaceDeltaChange     `json:"changes"`
	Deletions           []workspaceEntryDescriptor `json:"deletions"`
}

func canonicalWorkspaceDeltaManifest(
	baseline WorkspaceBaseline,
	changes []workspaceEntry,
	deletions []workspaceEntry,
) ([]byte, error) {
	if !validDigest(baseline.digest) || !matchesWorkspaceBaselineDigest(baseline) {
		return nil, ErrInvalid
	}
	manifest := workspaceDeltaManifest{
		Schema:              workspaceDeltaSchemaV1,
		InputManifestSHA256: baseline.inputManifestSHA256,
		BaselineSHA256:      baseline.digest,
		Changes:             make([]workspaceDeltaChange, 0, len(changes)),
		Deletions:           make([]workspaceEntryDescriptor, 0, len(deletions)),
	}
	for _, entry := range changes {
		change := "modified"
		before, existed := baseline.entries[entry.Path]
		if !existed {
			change = "added"
		} else if before.Type != entry.Type {
			change = "replaced"
		}
		manifest.Changes = append(manifest.Changes, workspaceDeltaChange{
			Change: change, Path: entry.Path, Type: entry.Type,
			Mode: fmt.Sprintf("%04o", entry.Mode), SizeBytes: entry.SizeBytes, SHA256: entry.SHA256,
		})
	}
	for _, entry := range deletions {
		manifest.Deletions = append(manifest.Deletions, describeWorkspaceEntry(entry))
	}
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) == 0 || len(raw) > MaxArtifactBytes {
		clear(raw)
		return nil, ErrInvalid
	}
	return raw, nil
}

func archiveWorkspaceDelta(
	ctx context.Context,
	changes []workspaceEntry,
	manifest []byte,
	maximumBytes int,
) ([]byte, error) {
	if ctx == nil || len(manifest) == 0 || maximumBytes < 1 || maximumBytes > MaxArtifactBytes {
		return nil, ErrInvalid
	}
	var encoded bytes.Buffer
	limited := &maximumWriter{writer: &encoded, remaining: maximumBytes}
	gzipWriter, err := gzip.NewWriterLevel(limited, gzip.BestCompression)
	if err != nil {
		return nil, ErrExecution
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0).UTC()
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	if err := appendDeltaTarEntry(ctx, tarWriter, workspaceEntry{
		Path: workspaceDeltaManifestPath, Type: workspaceEntryFile,
		Mode: 0o444, SizeBytes: int64(len(manifest)), Content: manifest,
	}); err != nil {
		_ = tarWriter.Close()
		_ = gzipWriter.Close()
		return nil, err
	}
	for _, entry := range changes {
		archived := entry
		archived.Path = workspaceDeltaFilesRoot + "/" + entry.Path
		if err := appendDeltaTarEntry(ctx, tarWriter, archived); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return nil, err
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return nil, ErrInvalid
	}
	if err := gzipWriter.Close(); err != nil || limited.exceeded {
		return nil, ErrInvalid
	}
	return bytes.Clone(encoded.Bytes()), nil
}

func appendDeltaTarEntry(ctx context.Context, archive *tar.Writer, entry workspaceEntry) error {
	if ctx == nil || archive == nil || !validWorkspaceDeltaArchivePath(entry.Path) ||
		(entry.Type != workspaceEntryFile && entry.Type != workspaceEntryDirectory) {
		return ErrInvalid
	}
	header := &tar.Header{
		Name: entry.Path, Mode: int64(entry.Mode), ModTime: time.Unix(0, 0).UTC(),
		AccessTime: time.Time{}, ChangeTime: time.Time{}, Uid: 0, Gid: 0,
		Uname: "", Gname: "", Format: tar.FormatPAX,
	}
	if entry.Type == workspaceEntryDirectory {
		header.Name += "/"
		header.Typeflag = tar.TypeDir
	} else {
		header.Typeflag = tar.TypeReg
		header.Size = int64(len(entry.Content))
		if entry.SizeBytes != header.Size {
			return ErrInvalid
		}
	}
	if err := archive.WriteHeader(header); err != nil {
		return ErrInvalid
	}
	if entry.Type == workspaceEntryDirectory {
		return nil
	}
	written, err := io.Copy(
		archive,
		&workspaceContextReader{ctx: ctx, reader: bytes.NewReader(entry.Content)},
	)
	if err != nil || written != int64(len(entry.Content)) {
		return ErrInvalid
	}
	return nil
}

func validWorkspaceDeltaArchivePath(path string) bool {
	if path == workspaceDeltaManifestPath {
		return true
	}
	prefix := workspaceDeltaFilesRoot + "/"
	return strings.HasPrefix(path, prefix) &&
		validWorkspaceDeltaPath(filepath.FromSlash(strings.TrimPrefix(path, prefix)))
}

func buildWorkspacePatch(
	changes []workspaceEntry,
	deletions []workspaceEntry,
	baseline WorkspaceBaseline,
	maximumBytes int,
) []byte {
	if maximumBytes < 1 || maximumBytes > MaxPatchBytes {
		return nil
	}
	if len(changes) == 0 && len(deletions) == 0 {
		value := []byte("# dirextalk workspace delta: no changes\n")
		if len(value) <= maximumBytes {
			return value
		}
		return nil
	}
	builder := &patchBuilder{maximum: maximumBytes}
	for _, current := range changes {
		if current.Type != workspaceEntryFile || !utf8.Valid(current.Content) ||
			bytes.IndexByte(current.Content, 0) >= 0 {
			continue
		}
		before, existed := baseline.entries[current.Path]
		if existed && (before.Type != workspaceEntryFile || !before.Patchable) {
			continue
		}
		appendWorkspaceFilePatch(builder, current.Path, before, current, existed, false)
		if builder.exceeded {
			return nil
		}
	}
	for _, before := range deletions {
		if before.Type != workspaceEntryFile || !before.Patchable {
			continue
		}
		appendWorkspaceFilePatch(builder, before.Path, before, workspaceEntry{}, true, true)
		if builder.exceeded {
			return nil
		}
	}
	if builder.buffer.Len() == 0 {
		return nil
	}
	return bytes.Clone(builder.buffer.Bytes())
}

func appendWorkspaceFilePatch(
	builder *patchBuilder,
	path string,
	before workspaceEntry,
	after workspaceEntry,
	existed bool,
	deleted bool,
) {
	aPath := strconv.Quote("a/" + path)
	bPath := strconv.Quote("b/" + path)
	builder.writeString("diff --git " + aPath + " " + bPath + "\n")
	switch {
	case !existed:
		builder.writeString(fmt.Sprintf("new file mode %06o\n", 0o100000|after.Mode))
	case deleted:
		builder.writeString(fmt.Sprintf("deleted file mode %06o\n", 0o100000|before.Mode))
	case before.Mode != after.Mode:
		builder.writeString(fmt.Sprintf("old mode %06o\nnew mode %06o\n", 0o100000|before.Mode, 0o100000|after.Mode))
	}
	if !deleted && existed && bytes.Equal(before.Content, after.Content) {
		return
	}
	oldContent := before.Content
	newContent := after.Content
	oldPath := aPath
	newPath := bPath
	if !existed {
		oldContent = nil
		oldPath = "/dev/null"
	}
	if deleted {
		newContent = nil
		newPath = "/dev/null"
	}
	builder.writeString("--- " + oldPath + "\n+++ " + newPath + "\n")
	oldLines := patchLineCount(oldContent)
	newLines := patchLineCount(newContent)
	oldStart, newStart := 1, 1
	if oldLines == 0 {
		oldStart = 0
	}
	if newLines == 0 {
		newStart = 0
	}
	builder.writeString(fmt.Sprintf("@@ -%d,%d +%d,%d @@\n", oldStart, oldLines, newStart, newLines))
	builder.writePatchLines('-', oldContent)
	builder.writePatchLines('+', newContent)
}

func patchLineCount(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	count := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		count++
	}
	return count
}

type patchBuilder struct {
	buffer   bytes.Buffer
	maximum  int
	exceeded bool
}

func (builder *patchBuilder) writeString(value string) {
	if builder.exceeded || len(value) > builder.maximum-builder.buffer.Len() {
		builder.exceeded = true
		return
	}
	builder.buffer.WriteString(value)
}

func (builder *patchBuilder) writePatchLines(prefix byte, content []byte) {
	for len(content) > 0 && !builder.exceeded {
		newline := bytes.IndexByte(content, '\n')
		if newline < 0 {
			builder.writeString(string([]byte{prefix}) + string(content) + "\n\\ No newline at end of file\n")
			return
		}
		builder.writeString(string([]byte{prefix}) + string(content[:newline+1]))
		content = content[newline+1:]
	}
}

type boundedCaptureWriter struct {
	buffer    []byte
	remaining int
	exceeded  bool
}

func (writer *boundedCaptureWriter) Write(value []byte) (int, error) {
	if writer.exceeded {
		return len(value), nil
	}
	if len(value) > writer.remaining {
		if writer.remaining > 0 {
			writer.buffer = append(writer.buffer, value[:writer.remaining]...)
		}
		writer.remaining = 0
		writer.exceeded = true
		return len(value), nil
	}
	writer.buffer = append(writer.buffer, value...)
	writer.remaining -= len(value)
	return len(value), nil
}

func (writer *boundedCaptureWriter) destroy() {
	clear(writer.buffer)
	*writer = boundedCaptureWriter{}
}

type maximumWriter struct {
	writer    io.Writer
	remaining int
	exceeded  bool
}

func (writer *maximumWriter) Write(value []byte) (int, error) {
	if writer.exceeded || len(value) > writer.remaining {
		writer.exceeded = true
		return 0, ErrInvalid
	}
	written, err := writer.writer.Write(value)
	writer.remaining -= written
	if err != nil || written != len(value) {
		return written, ErrInvalid
	}
	return written, nil
}

type workspaceContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *workspaceContextReader) Read(target []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(target)
	}
}

func destroyWorkspaceEntries(entries []workspaceEntry) {
	for index := range entries {
		entries[index].destroy()
	}
}

var _ OutputCollector = FilesystemOutputCollector{}
