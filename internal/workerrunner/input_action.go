package workerrunner

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

const (
	InputMaterializeActionKind = "worker.input.materialize"

	MaxWorkspaceArchiveBytes = 1 << 30
	maxWorkspaceExtractBytes = 4 << 30
	maxWorkspaceFiles        = 100_000
	maxWorkspacePathBytes    = 4096
)

var inputDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)

type MaterializeObjectV1 struct {
	ObjectName  string `json:"object_name"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	ContentType string `json:"content_type"`
	S3Ref       string `json:"-"`
}

type InputMaterializeInputV1 struct {
	Context   MaterializeObjectV1  `json:"context"`
	Workspace *MaterializeObjectV1 `json:"workspace,omitempty"`
}

type InputObjectStore interface {
	OpenInput(
		context.Context,
		string,
		int64,
	) (io.ReadCloser, int64, error)
}

type InputMaterializeAction struct {
	objects       InputObjectStore
	contextRoot   string
	workspaceRoot string
}

func NewInputMaterializeAction(
	objects InputObjectStore,
	contextRoot string,
	workspaceRoot string,
) (*InputMaterializeAction, error) {
	contextRoot, err := secureInputRoot(contextRoot)
	if err != nil {
		return nil, err
	}
	workspaceRoot, err = secureInputRoot(workspaceRoot)
	if err != nil || objects == nil || contextRoot == workspaceRoot {
		return nil, ErrInvalidBundle
	}
	return &InputMaterializeAction{
		objects:       objects,
		contextRoot:   contextRoot,
		workspaceRoot: workspaceRoot,
	}, nil
}

func (*InputMaterializeAction) Kind() string {
	return InputMaterializeActionKind
}

func (handler *InputMaterializeAction) Validate(action ActionV1) error {
	if handler == nil || handler.objects == nil ||
		action.Kind != InputMaterializeActionKind ||
		action.Input == nil || action.Noop != nil ||
		action.Installer != nil || action.Runtime != nil ||
		validateMaterializeObject(
			action.Input.Context,
			"application/json",
			workerruntime.MaxContextBytes,
		) != nil {
		return ErrInvalidBundle
	}
	if action.Input.Workspace != nil &&
		validateMaterializeObject(
			*action.Input.Workspace,
			"application/x-tar",
			MaxWorkspaceArchiveBytes,
		) != nil {
		return ErrInvalidBundle
	}
	return nil
}

func (handler *InputMaterializeAction) Execute(
	ctx context.Context,
	action ActionV1,
) (ActionResult, error) {
	if err := handler.Validate(action); err != nil {
		return ActionResult{}, err
	}
	if err := handler.materializeContext(ctx, action.Input.Context); err != nil {
		return ActionResult{}, errors.Join(ErrInvalidBundle, err)
	}
	if action.Input.Workspace != nil {
		if err := handler.materializeWorkspace(
			ctx,
			*action.Input.Workspace,
		); err != nil {
			return ActionResult{}, errors.Join(ErrInvalidBundle, err)
		}
	}
	return ActionResult{Status: "materialized"}, nil
}

func (handler *InputMaterializeAction) materializeContext(
	ctx context.Context,
	object MaterializeObjectV1,
) error {
	target := filepath.Join(
		handler.contextRoot,
		strings.TrimPrefix(object.SHA256, "sha256:")+".json",
	)
	if validMaterializedFile(ctx, target, object) {
		return nil
	}
	body, size, err := handler.objects.OpenInput(
		ctx,
		object.S3Ref,
		workerruntime.MaxContextBytes,
	)
	if err != nil {
		return err
	}
	defer body.Close()
	if size != object.SizeBytes {
		return ErrDigestMismatch
	}
	temporary, err := os.CreateTemp(handler.contextRoot, ".context-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	digest, copied, err := copyExact(
		ctx,
		temporary,
		body,
		object.SizeBytes,
		workerruntime.MaxContextBytes,
	)
	if err == nil {
		err = temporary.Sync()
	}
	closeErr := temporary.Close()
	if err != nil {
		return err
	}
	if closeErr != nil || copied != object.SizeBytes ||
		!matchesInputDigest(digest, object.SHA256) {
		return ErrDigestMismatch
	}
	raw, err := os.ReadFile(temporaryName)
	if err != nil || !jsonDocument(raw) {
		clear(raw)
		return ErrInvalidBundle
	}
	clear(raw)
	if err := installFileNoReplace(
		temporaryName,
		target,
		func() bool {
			return validMaterializedFile(ctx, target, object)
		},
	); err != nil {
		return err
	}
	return syncDirectory(handler.contextRoot)
}

func (handler *InputMaterializeAction) materializeWorkspace(
	ctx context.Context,
	object MaterializeObjectV1,
) error {
	target := filepath.Join(
		handler.workspaceRoot,
		strings.TrimPrefix(object.SHA256, "sha256:"),
	)
	if validMaterializedWorkspace(ctx, target, object.SHA256) {
		return nil
	}
	body, size, err := handler.objects.OpenInput(
		ctx,
		object.S3Ref,
		MaxWorkspaceArchiveBytes,
	)
	if err != nil {
		return err
	}
	defer body.Close()
	if size != object.SizeBytes {
		return ErrDigestMismatch
	}
	temporary, err := os.MkdirTemp(handler.workspaceRoot, ".workspace-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	digest, copied, err := extractWorkspace(
		ctx,
		body,
		object.SizeBytes,
		temporary,
	)
	if err != nil || copied != object.SizeBytes ||
		!matchesInputDigest(digest, object.SHA256) {
		if err != nil {
			return err
		}
		return ErrDigestMismatch
	}
	marker := filepath.Join(
		temporary,
		workerruntime.WorkspaceDigestMarker,
	)
	if err := writeSyncedExclusive(
		marker,
		[]byte(object.SHA256+"\n"),
		0o600,
	); err != nil {
		return err
	}
	if err := syncDirectory(temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, target); err != nil {
		if validMaterializedWorkspace(ctx, target, object.SHA256) {
			return nil
		}
		return err
	}
	return syncDirectory(handler.workspaceRoot)
}

func validateMaterializeObject(
	object MaterializeObjectV1,
	contentType string,
	maximum int64,
) error {
	if validateMaterializeDeclaration(
		object,
		contentType,
		maximum,
	) != nil {
		return ErrInvalidBundle
	}
	if _, _, err := splitS3Object(object.S3Ref); err != nil {
		return ErrInvalidBundle
	}
	return nil
}

func validateMaterializeDeclaration(
	object MaterializeObjectV1,
	contentType string,
	maximum int64,
) error {
	if !inputDigestPattern.MatchString(object.SHA256) ||
		!workerObjectNamePattern.MatchString(object.ObjectName) ||
		strings.Contains(object.ObjectName, "..") ||
		object.SizeBytes < 1 || object.SizeBytes > maximum ||
		object.ContentType != contentType {
		return ErrInvalidBundle
	}
	return nil
}

func secureInputRoot(root string) (string, error) {
	clean := filepath.Clean(root)
	if root == "" || clean != root || !filepath.IsAbs(clean) {
		return "", ErrInvalidBundle
	}
	info, err := os.Lstat(clean)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", ErrInvalidBundle
	}
	return clean, nil
}

func extractWorkspace(
	ctx context.Context,
	source io.Reader,
	expectedSize int64,
	targetRoot string,
) ([sha256.Size]byte, int64, error) {
	var empty [sha256.Size]byte
	hasher := sha256.New()
	counted := &countingReader{
		reader: io.TeeReader(
			io.LimitReader(
				&contextInputReader{ctx: ctx, reader: source},
				expectedSize+1,
			),
			hasher,
		),
	}
	archive := tar.NewReader(counted)
	seen := make(map[string]struct{})
	symlinks := make([]workspaceSymlink, 0)
	var extracted int64
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || header == nil {
			return empty, counted.total, ErrInvalidBundle
		}
		name, err := safeArchivePath(header.Name)
		if err != nil {
			return empty, counted.total, err
		}
		if name == workerruntime.WorkspaceDigestMarker {
			return empty, counted.total, ErrInvalidBundle
		}
		if _, duplicate := seen[name]; duplicate {
			return empty, counted.total, ErrInvalidBundle
		}
		seen[name] = struct{}{}
		if len(seen) > maxWorkspaceFiles || header.Size < 0 ||
			header.Size > maxWorkspaceExtractBytes-extracted {
			return empty, counted.total, ErrInvalidBundle
		}
		target := filepath.Join(targetRoot, filepath.FromSlash(name))
		switch header.Typeflag {
		case tar.TypeDir:
			if header.Size != 0 {
				return empty, counted.total, ErrInvalidBundle
			}
			if err := os.MkdirAll(target, 0o700); err != nil {
				return empty, counted.total, err
			}
			if err := os.Chmod(target, 0o700); err != nil {
				return empty, counted.total, err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return empty, counted.total, err
			}
			mode := os.FileMode(0o600)
			if header.Mode&0o111 != 0 {
				mode = 0o700
			}
			file, err := os.OpenFile(
				target,
				os.O_CREATE|os.O_EXCL|os.O_WRONLY,
				mode,
			)
			if err != nil {
				return empty, counted.total, err
			}
			written, copyErr := io.CopyN(
				file,
				&contextInputReader{ctx: ctx, reader: archive},
				header.Size,
			)
			if copyErr == nil && written == header.Size {
				copyErr = file.Sync()
			}
			closeErr := file.Close()
			if copyErr != nil || closeErr != nil || written != header.Size {
				if copyErr != nil {
					return empty, counted.total, copyErr
				}
				return empty, counted.total, ErrInvalidBundle
			}
			extracted += written
		case tar.TypeSymlink:
			if header.Size != 0 ||
				!safeWorkspaceSymlink(name, header.Linkname) {
				return empty, counted.total, ErrInvalidBundle
			}
			symlinks = append(symlinks, workspaceSymlink{
				name:   name,
				target: header.Linkname,
			})
		default:
			return empty, counted.total, ErrInvalidBundle
		}
	}
	if _, err := io.Copy(io.Discard, counted); err != nil ||
		counted.total != expectedSize {
		return empty, counted.total, ErrDigestMismatch
	}
	for _, symlink := range symlinks {
		if err := createWorkspaceSymlink(
			targetRoot,
			symlink,
		); err != nil {
			return empty, counted.total, err
		}
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, counted.total, nil
}

type workspaceSymlink struct {
	name   string
	target string
}

func safeArchivePath(name string) (string, error) {
	if name == "" || len(name) > maxWorkspacePathBytes ||
		strings.Contains(name, "\\") ||
		strings.HasPrefix(name, "/") {
		return "", ErrInvalidBundle
	}
	clean := filepath.ToSlash(filepath.Clean(name))
	if clean == "." || clean == ".." ||
		strings.HasPrefix(clean, "../") ||
		strings.Contains(clean, "/../") ||
		clean != strings.TrimSuffix(name, "/") {
		return "", ErrInvalidBundle
	}
	return clean, nil
}

func safeWorkspaceSymlink(name, target string) bool {
	if target == "" ||
		len(target) > maxWorkspacePathBytes ||
		strings.Contains(target, "\\") ||
		strings.ContainsRune(target, '\x00') ||
		path.IsAbs(target) {
		return false
	}
	resolved := path.Clean(path.Join(path.Dir(name), target))
	return resolved != "." &&
		resolved != ".." &&
		!strings.HasPrefix(resolved, "../") &&
		!strings.Contains(resolved, "/../") &&
		resolved != workerruntime.WorkspaceDigestMarker
}

func createWorkspaceSymlink(
	root string,
	link workspaceSymlink,
) error {
	target := filepath.Join(root, filepath.FromSlash(link.name))
	parent := filepath.Dir(target)
	relativeParent, err := filepath.Rel(root, parent)
	if err != nil ||
		relativeParent == ".." ||
		strings.HasPrefix(relativeParent, ".."+string(os.PathSeparator)) {
		return ErrInvalidBundle
	}
	current := root
	if relativeParent != "." {
		for _, component := range strings.Split(
			relativeParent,
			string(os.PathSeparator),
		) {
			current = filepath.Join(current, component)
			info, statErr := os.Lstat(current)
			if statErr != nil ||
				info.Mode()&os.ModeSymlink != 0 ||
				!info.IsDir() {
				return ErrInvalidBundle
			}
		}
	}
	if _, err := os.Lstat(target); err == nil {
		return ErrInvalidBundle
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(link.target, target); err != nil {
		return err
	}
	return syncDirectory(parent)
}

func copyExact(
	ctx context.Context,
	target io.Writer,
	source io.Reader,
	expected int64,
	maximum int64,
) ([sha256.Size]byte, int64, error) {
	var empty [sha256.Size]byte
	hasher := sha256.New()
	counted := &countingWriter{writer: io.MultiWriter(target, hasher)}
	_, err := io.Copy(
		counted,
		io.LimitReader(
			&contextInputReader{ctx: ctx, reader: source},
			maximum+1,
		),
	)
	if err != nil || counted.total != expected || counted.total > maximum {
		return empty, counted.total, ErrDigestMismatch
	}
	var digest [sha256.Size]byte
	copy(digest[:], hasher.Sum(nil))
	return digest, counted.total, nil
}

func validMaterializedFile(
	ctx context.Context,
	name string,
	object MaterializeObjectV1,
) bool {
	content, err := readBoundedFile(
		ctx,
		name,
		object.SizeBytes,
		workerruntime.MaxContextBytes,
	)
	if err != nil {
		clear(content)
		return false
	}
	defer clear(content)
	digest := sha256.Sum256(content)
	return int64(len(content)) == object.SizeBytes &&
		matchesInputDigest(digest, object.SHA256) &&
		jsonDocument(content)
}

func validMaterializedWorkspace(
	ctx context.Context,
	name string,
	expectedDigest string,
) bool {
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return false
	}
	marker, err := readBoundedFile(
		ctx,
		filepath.Join(name, workerruntime.WorkspaceDigestMarker),
		-1,
		128,
	)
	if err != nil {
		clear(marker)
		return false
	}
	defer clear(marker)
	return string(bytes.TrimSpace(marker)) == expectedDigest
}

func readBoundedFile(
	ctx context.Context,
	name string,
	expected int64,
	maximum int64,
) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() || info.Size() < 1 ||
		info.Size() > maximum ||
		expected >= 0 && info.Size() != expected {
		return nil, ErrInvalidBundle
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(
		&contextInputReader{ctx: ctx, reader: file},
		maximum+1,
	))
	if err != nil || int64(len(content)) != info.Size() {
		clear(content)
		return nil, ErrInvalidBundle
	}
	return content, nil
}

func installFileNoReplace(
	source string,
	target string,
	existingValid func() bool,
) error {
	if err := os.Link(source, target); err != nil {
		if errors.Is(err, os.ErrExist) && existingValid() {
			return nil
		}
		return err
	}
	return os.Remove(source)
}

func writeSyncedExclusive(
	name string,
	content []byte,
	mode os.FileMode,
) error {
	file, err := os.OpenFile(
		name,
		os.O_CREATE|os.O_EXCL|os.O_WRONLY,
		mode,
	)
	if err != nil {
		return err
	}
	if _, err = file.Write(content); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func syncDirectory(name string) error {
	directory, err := os.Open(name)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func matchesInputDigest(
	actual [sha256.Size]byte,
	expected string,
) bool {
	decoded, err := hex.DecodeString(
		strings.TrimPrefix(expected, "sha256:"),
	)
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return false
	}
	defer clear(decoded)
	return subtle.ConstantTimeCompare(actual[:], decoded) == 1
}

func jsonDocument(value []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return false
	}
	return decoder.Decode(&document) == io.EOF
}

type contextInputReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *contextInputReader) Read(target []byte) (int, error) {
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
	read, err := reader.reader.Read(target)
	reader.total += int64(read)
	return read, err
}

type countingWriter struct {
	writer io.Writer
	total  int64
}

func (writer *countingWriter) Write(content []byte) (int, error) {
	written, err := writer.writer.Write(content)
	writer.total += int64(written)
	return written, err
}
