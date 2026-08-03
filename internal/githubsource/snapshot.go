// Package githubsource prepares a deterministic, credential-free workspace
// snapshot from one approved GitHub repository source.
package githubsource

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/githubapp"
	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

const (
	SnapshotSchemaV1        = "dirextalk.agent.github-source-snapshot/v1"
	maximumCompressedBytes  = int64(1 << 30)
	maximumRepositoryFiles  = 100_000
	maximumRepositoryPath   = 4096
	maximumRedirectLocation = 8192
)

var (
	ErrInvalid     = errors.New("invalid GitHub source request")
	ErrUnavailable = errors.New("GitHub source is unavailable")
	ErrIntegrity   = errors.New("GitHub source integrity check failed")

	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type SnapshotV1 struct {
	SchemaVersion      string                    `json:"schema_version"`
	InputID            string                    `json:"input_id"`
	InputDigest        string                    `json:"input_digest"`
	InputBindingDigest string                    `json:"input_binding_digest"`
	SourceDigest       string                    `json:"source_digest"`
	Repository         taskinput.GitRepositoryV1 `json:"repository"`
	WorkspaceDigest    string                    `json:"workspace_digest"`
	SizeBytes          int64                     `json:"size_bytes"`
	FileCount          uint32                    `json:"file_count"`
}

func (snapshot SnapshotV1) Validate() error {
	binding := taskinput.BindingV2{
		SchemaVersion: taskinput.InputSchemaV2,
		InputID:       snapshot.InputID,
		InputDigest:   snapshot.InputDigest,
		SourceDigest:  snapshot.SourceDigest,
		SourceKind:    taskinput.SourceGitHubRepository,
		Repository:    snapshot.Repository,
	}
	bindingDigest, bindingErr := binding.Digest()
	if snapshot.SchemaVersion != SnapshotSchemaV1 ||
		bindingErr != nil ||
		snapshot.InputBindingDigest != bindingDigest ||
		!digestPattern.MatchString(snapshot.WorkspaceDigest) ||
		snapshot.SizeBytes < 1 ||
		snapshot.SizeBytes > workerrunner.MaxWorkspaceArchiveBytes ||
		snapshot.FileCount == 0 ||
		snapshot.FileCount > maximumRepositoryFiles {
		return ErrInvalid
	}
	return nil
}

// Prepared owns one protected temporary canonical tar. Destroy must be called
// after the snapshot has been durably published.
type Prepared struct {
	Snapshot  SnapshotV1
	directory string
	archive   string
}

func (prepared *Prepared) Open(
	ctx context.Context,
) (io.ReadSeekCloser, error) {
	if prepared == nil ||
		ctx == nil ||
		prepared.Snapshot.Validate() != nil ||
		prepared.directory == "" ||
		prepared.archive == "" {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(
		prepared.archive,
		os.O_RDONLY|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	info, err := file.Stat()
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Size() != prepared.Snapshot.SizeBytes {
		file.Close()
		return nil, ErrIntegrity
	}
	return file, nil
}

func (prepared *Prepared) Destroy() {
	if prepared == nil {
		return
	}
	directory := prepared.directory
	*prepared = Prepared{}
	if directory != "" {
		_ = os.RemoveAll(directory)
	}
}

type Snapshotter struct {
	broker   *githubapp.Broker
	http     *http.Client
	tempRoot string
}

func NewSnapshotter(
	broker *githubapp.Broker,
	transport http.RoundTripper,
	tempRoot string,
) (*Snapshotter, error) {
	if broker == nil || transport == nil {
		return nil, ErrInvalid
	}
	root, err := secureTemporaryRoot(tempRoot)
	if err != nil {
		return nil, err
	}
	return &Snapshotter{
		broker: broker,
		http: &http.Client{
			Transport: transport,
			CheckRedirect: func(
				*http.Request,
				[]*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
		tempRoot: root,
	}, nil
}

func (snapshotter *Snapshotter) Prepare(
	ctx context.Context,
	binding taskinput.BindingV2,
) (Prepared, error) {
	if snapshotter == nil ||
		snapshotter.broker == nil ||
		snapshotter.http == nil ||
		ctx == nil ||
		binding.Validate() != nil ||
		binding.SourceKind != taskinput.SourceGitHubRepository ||
		binding.Repository.Validate() != nil {
		return Prepared{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Prepared{}, err
	}
	token, err := snapshotter.broker.Issue(
		ctx,
		githubapp.IssueRequest{
			Repository: binding.Repository,
			Permission: githubapp.ContentsRead,
		},
	)
	if err != nil {
		return Prepared{}, ErrUnavailable
	}
	defer token.Destroy()
	var prepared Prepared
	err = token.Materialize(func(value []byte) error {
		response, downloadErr := snapshotter.openArchive(
			ctx,
			binding.Repository,
			value,
		)
		if downloadErr != nil {
			return downloadErr
		}
		defer response.Close()
		prepared, downloadErr = snapshotter.canonicalize(
			ctx,
			binding,
			response,
		)
		return downloadErr
	})
	if err != nil {
		prepared.Destroy()
		return Prepared{}, normalizeError(err)
	}
	return prepared, nil
}

func (snapshotter *Snapshotter) openArchive(
	ctx context.Context,
	repository taskinput.GitRepositoryV1,
	token []byte,
) (io.ReadCloser, error) {
	endpoint := "https://api.github.com/repos/" +
		url.PathEscape(repository.Owner) + "/" +
		url.PathEscape(repository.Name) + "/tarball/" +
		url.PathEscape(repository.BaseCommitSHA)
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		endpoint,
		nil,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("User-Agent", "dirextalk-agent")
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	response, err := snapshotter.http.Do(request)
	if err != nil {
		return nil, ErrUnavailable
	}
	if response.StatusCode == http.StatusOK {
		if !validContentLength(response.ContentLength) {
			response.Body.Close()
			return nil, ErrUnavailable
		}
		return response.Body, nil
	}
	if response.StatusCode != http.StatusFound &&
		response.StatusCode != http.StatusTemporaryRedirect &&
		response.StatusCode != http.StatusPermanentRedirect {
		response.Body.Close()
		return nil, ErrUnavailable
	}
	location := response.Header.Get("Location")
	response.Body.Close()
	redirect, err := validateArchiveRedirect(location)
	if err != nil {
		return nil, err
	}
	redirectRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		redirect.String(),
		nil,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	redirectRequest.Header.Set("Accept", "application/x-gzip")
	redirectRequest.Header.Set("User-Agent", "dirextalk-agent")
	response, err = snapshotter.http.Do(redirectRequest)
	if err != nil {
		return nil, ErrUnavailable
	}
	if response.StatusCode != http.StatusOK ||
		!validContentLength(response.ContentLength) {
		response.Body.Close()
		return nil, ErrUnavailable
	}
	return response.Body, nil
}

func (snapshotter *Snapshotter) canonicalize(
	ctx context.Context,
	binding taskinput.BindingV2,
	compressed io.Reader,
) (Prepared, error) {
	directory, err := os.MkdirTemp(
		snapshotter.tempRoot,
		".github-source-*",
	)
	if err != nil {
		return Prepared{}, ErrUnavailable
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		os.RemoveAll(directory)
		return Prepared{}, ErrUnavailable
	}
	prepared := Prepared{directory: directory}
	fail := func(err error) (Prepared, error) {
		prepared.Destroy()
		return Prepared{}, err
	}
	limited := &countingReader{
		reader: io.LimitReader(
			&contextReader{ctx: ctx, reader: compressed},
			maximumCompressedBytes+1,
		),
	}
	buffered := bufio.NewReader(limited)
	gzipReader, err := gzip.NewReader(buffered)
	if err != nil {
		return fail(ErrIntegrity)
	}
	gzipReader.Multistream(false)
	entries, err := stageArchive(
		ctx,
		tar.NewReader(gzipReader),
		directory,
	)
	if err != nil {
		gzipReader.Close()
		return fail(err)
	}
	if _, err := io.Copy(
		io.Discard,
		&contextReader{ctx: ctx, reader: gzipReader},
	); err != nil {
		gzipReader.Close()
		return fail(ErrIntegrity)
	}
	if err := gzipReader.Close(); err != nil {
		return fail(ErrIntegrity)
	}
	var trailing [1]byte
	count, trailingErr := buffered.Read(trailing[:])
	if count != 0 || !errors.Is(trailingErr, io.EOF) {
		if contextErr := ctx.Err(); contextErr != nil {
			return fail(contextErr)
		}
		return fail(ErrIntegrity)
	}
	if limited.total <= 0 ||
		limited.total > maximumCompressedBytes {
		return fail(ErrIntegrity)
	}
	archivePath := filepath.Join(directory, "workspace.tar")
	workspaceDigest, sizeBytes, err := writeCanonicalTar(
		ctx,
		archivePath,
		entries,
	)
	if err != nil {
		return fail(err)
	}
	bindingDigest, err := binding.Digest()
	if err != nil {
		return fail(ErrIntegrity)
	}
	prepared.archive = archivePath
	prepared.Snapshot = SnapshotV1{
		SchemaVersion:      SnapshotSchemaV1,
		InputID:            binding.InputID,
		InputDigest:        binding.InputDigest,
		InputBindingDigest: bindingDigest,
		SourceDigest:       binding.SourceDigest,
		Repository:         binding.Repository,
		WorkspaceDigest:    workspaceDigest,
		SizeBytes:          sizeBytes,
		FileCount:          uint32(len(entries)),
	}
	if prepared.Snapshot.Validate() != nil {
		return fail(ErrIntegrity)
	}
	return prepared, nil
}

type stagedEntry struct {
	name     string
	mode     int64
	typeflag byte
	size     int64
	linkname string
	content  string
}

func stageArchive(
	ctx context.Context,
	archive *tar.Reader,
	directory string,
) ([]stagedEntry, error) {
	if ctx == nil || archive == nil || directory == "" {
		return nil, ErrInvalid
	}
	entries := make([]stagedEntry, 0, 1024)
	seen := make(map[string]struct{})
	root := ""
	var contentBytes int64
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header == nil {
			return nil, ErrIntegrity
		}
		name, nextRoot, err := stripArchiveRoot(
			header.Name,
			root,
		)
		if err != nil {
			return nil, err
		}
		if root == "" {
			root = nextRoot
		}
		if name == "" {
			if header.Typeflag != tar.TypeDir || header.Size != 0 {
				return nil, ErrIntegrity
			}
			continue
		}
		if name == workerruntime.WorkspaceDigestMarker {
			return nil, ErrIntegrity
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, ErrIntegrity
		}
		seen[name] = struct{}{}
		if len(seen) > maximumRepositoryFiles ||
			header.Size < 0 {
			return nil, ErrIntegrity
		}
		entry := stagedEntry{name: name}
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return nil, ErrIntegrity
			}
			entry.typeflag = tar.TypeDir
			entry.mode = 0o755
		case tar.TypeReg, tar.TypeRegA:
			if header.Size >
				workerrunner.MaxWorkspaceArchiveBytes-contentBytes {
				return nil, ErrIntegrity
			}
			entry.typeflag = tar.TypeReg
			entry.mode = 0o644
			if header.Mode&0o111 != 0 {
				entry.mode = 0o755
			}
			entry.size = header.Size
			entry.content = filepath.Join(
				directory,
				fmt.Sprintf("content-%08d", len(entries)),
			)
			if err := stageRegularFile(
				ctx,
				archive,
				entry.content,
				entry.size,
			); err != nil {
				return nil, err
			}
			contentBytes += entry.size
		case tar.TypeSymlink:
			if header.Size != 0 ||
				!safeSymlink(name, header.Linkname) {
				return nil, ErrIntegrity
			}
			entry.typeflag = tar.TypeSymlink
			entry.mode = 0o777
			entry.linkname = header.Linkname
		default:
			return nil, ErrIntegrity
		}
		entries = append(entries, entry)
	}
	if root == "" || len(entries) == 0 {
		return nil, ErrIntegrity
	}
	slices.SortFunc(entries, func(left, right stagedEntry) int {
		return strings.Compare(left.name, right.name)
	})
	if !validEntryTopology(entries) {
		return nil, ErrIntegrity
	}
	return entries, nil
}

func validEntryTopology(entries []stagedEntry) bool {
	types := make(map[string]byte, len(entries))
	for _, entry := range entries {
		types[entry.name] = entry.typeflag
	}
	for _, entry := range entries {
		for parent := path.Dir(entry.name); parent != "."; parent = path.Dir(parent) {
			if kind, found := types[parent]; found && kind != tar.TypeDir {
				return false
			}
		}
	}
	return true
}

func stageRegularFile(
	ctx context.Context,
	archive io.Reader,
	target string,
	size int64,
) error {
	file, err := os.OpenFile(
		target,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return ErrUnavailable
	}
	written, copyErr := io.CopyN(
		file,
		&contextReader{ctx: ctx, reader: archive},
		size,
	)
	if copyErr == nil && written == size {
		copyErr = file.Sync()
	}
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || written != size {
		return ErrIntegrity
	}
	return nil
}

func writeCanonicalTar(
	ctx context.Context,
	target string,
	entries []stagedEntry,
) (string, int64, error) {
	if ctx == nil || target == "" || len(entries) == 0 {
		return "", 0, ErrInvalid
	}
	file, err := os.OpenFile(
		target,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		0o600,
	)
	if err != nil {
		return "", 0, ErrUnavailable
	}
	hasher := sha256.New()
	counted := &countingWriter{
		writer:  io.MultiWriter(file, hasher),
		maximum: workerrunner.MaxWorkspaceArchiveBytes,
	}
	writer := tar.NewWriter(counted)
	epoch := time.Unix(0, 0).UTC()
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			writer.Close()
			file.Close()
			return "", 0, err
		}
		header := &tar.Header{
			Name:       entry.name,
			Mode:       entry.mode,
			Size:       entry.size,
			Typeflag:   entry.typeflag,
			Linkname:   entry.linkname,
			ModTime:    epoch,
			AccessTime: epoch,
			ChangeTime: epoch,
			Format:     tar.FormatPAX,
		}
		if entry.typeflag == tar.TypeDir {
			header.Name += "/"
		}
		if err := writer.WriteHeader(header); err != nil {
			writer.Close()
			file.Close()
			return "", 0, ErrUnavailable
		}
		if entry.typeflag != tar.TypeReg {
			continue
		}
		source, err := os.OpenFile(
			entry.content,
			os.O_RDONLY|syscall.O_NOFOLLOW,
			0,
		)
		if err != nil {
			writer.Close()
			file.Close()
			return "", 0, ErrUnavailable
		}
		written, copyErr := io.CopyN(
			writer,
			&contextReader{ctx: ctx, reader: source},
			entry.size,
		)
		closeErr := source.Close()
		if copyErr != nil || closeErr != nil ||
			written != entry.size {
			writer.Close()
			file.Close()
			return "", 0, ErrIntegrity
		}
	}
	if err := writer.Close(); err != nil {
		file.Close()
		return "", 0, ErrUnavailable
	}
	if counted.total < 1 ||
		counted.total > workerrunner.MaxWorkspaceArchiveBytes {
		file.Close()
		return "", 0, ErrIntegrity
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return "", 0, ErrUnavailable
	}
	if err := file.Close(); err != nil {
		return "", 0, ErrUnavailable
	}
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)),
		counted.total,
		nil
}

func stripArchiveRoot(
	value string,
	expectedRoot string,
) (string, string, error) {
	if value == "" ||
		len(value) > maximumRepositoryPath ||
		strings.Contains(value, "\\") ||
		strings.HasPrefix(value, "/") {
		return "", "", ErrIntegrity
	}
	trimmed := strings.TrimSuffix(value, "/")
	if trimmed == "" ||
		path.Clean(trimmed) != trimmed ||
		strings.HasPrefix(trimmed, "../") {
		return "", "", ErrIntegrity
	}
	root, remainder, found := strings.Cut(trimmed, "/")
	if !found {
		remainder = ""
	}
	if root == "" ||
		expectedRoot != "" && root != expectedRoot {
		return "", "", ErrIntegrity
	}
	if remainder != "" && !safeRepositoryPath(remainder) {
		return "", "", ErrIntegrity
	}
	return remainder, root, nil
}

func safeRepositoryPath(value string) bool {
	return value != "" &&
		len(value) <= maximumRepositoryPath &&
		!strings.Contains(value, "\\") &&
		!strings.HasPrefix(value, "/") &&
		path.Clean(value) == value &&
		value != "." &&
		value != ".." &&
		!strings.HasPrefix(value, "../") &&
		!strings.Contains(value, "/../")
}

func safeSymlink(name, target string) bool {
	if target == "" ||
		len(target) > maximumRepositoryPath ||
		strings.Contains(target, "\\") ||
		path.IsAbs(target) {
		return false
	}
	resolved := path.Clean(path.Join(path.Dir(name), target))
	return resolved != "." &&
		resolved != ".." &&
		!strings.HasPrefix(resolved, "../") &&
		!strings.Contains(resolved, "/../")
}

func validateArchiveRedirect(value string) (*url.URL, error) {
	if value == "" ||
		len(value) > maximumRedirectLocation {
		return nil, ErrUnavailable
	}
	parsed, err := url.Parse(value)
	if err != nil ||
		parsed.Scheme != "https" ||
		parsed.Hostname() != "codeload.github.com" ||
		parsed.Port() != "" ||
		parsed.User != nil ||
		parsed.Fragment != "" {
		return nil, ErrUnavailable
	}
	return parsed, nil
}

func validContentLength(value int64) bool {
	return value == -1 ||
		value > 0 && value <= maximumCompressedBytes
}

func secureTemporaryRoot(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", ErrInvalid
	}
	real, err := filepath.EvalSymlinks(value)
	if err != nil {
		return "", ErrInvalid
	}
	real, err = filepath.Abs(real)
	if err != nil {
		return "", ErrInvalid
	}
	info, err := os.Stat(real)
	if err != nil ||
		!info.IsDir() ||
		runtime.GOOS != "windows" &&
			info.Mode().Perm()&0o077 != 0 {
		return "", ErrInvalid
	}
	return real, nil
}

func normalizeError(err error) error {
	switch {
	case errors.Is(err, context.Canceled),
		errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, ErrInvalid):
		return ErrInvalid
	case errors.Is(err, ErrIntegrity):
		return ErrIntegrity
	default:
		return ErrUnavailable
	}
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextReader) Read(target []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(target)
	}
}

type countingReader struct {
	reader io.Reader
	total  int64
}

func (reader *countingReader) Read(target []byte) (int, error) {
	count, err := reader.reader.Read(target)
	reader.total += int64(count)
	return count, err
}

type countingWriter struct {
	writer  io.Writer
	total   int64
	maximum int64
}

func (writer *countingWriter) Write(value []byte) (int, error) {
	if writer.maximum > 0 &&
		int64(len(value)) > writer.maximum-writer.total {
		return 0, ErrIntegrity
	}
	count, err := writer.writer.Write(value)
	writer.total += int64(count)
	return count, err
}
