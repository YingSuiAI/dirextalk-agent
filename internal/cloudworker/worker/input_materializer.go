package worker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
	"github.com/YingSuiAI/dirextalk-agent/internal/workspacearchive"
)

const (
	InputManifestSchemaV1 = "cloud_worker_input_manifest/v1"
	MaxInputItems         = 256
	MaxInputObjectBytes   = int64(8 << 20)
	MaxInputTotalBytes    = int64(8 << 20)
)

type InputManifest struct {
	Items  []InputManifestItem `json:"items"`
	Schema string              `json:"schema"`
}

type InputManifestItem struct {
	InputID     string `json:"input_id"`
	Kind        string `json:"kind"`
	MediaType   string `json:"media_type"`
	MountPath   string `json:"mount_path"`
	Name        string `json:"name"`
	S3Bucket    string `json:"s3_bucket"`
	S3Key       string `json:"s3_key"`
	S3VersionID string `json:"s3_version_id"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
}

type InputObjectRequest struct {
	Bucket, Key, VersionID string
	SizeBytes              int64
	MediaType              string
}

type InputObjectRead struct {
	Bucket, Key, VersionID string
	SizeBytes              int64
	MediaType              string
	Body                   io.ReadCloser
}

type ExactInputObjectReader interface {
	ReadExact(context.Context, Binding, InputObjectRequest) (InputObjectRead, error)
}

type FilesystemWorkspacePreparer struct {
	objects    ExactInputObjectReader
	root       string
	rootInfo   os.FileInfo
	runtimeGID uint32
}

func NewFilesystemWorkspacePreparer(
	objects ExactInputObjectReader,
	root string,
	runtimeGID uint32,
) (*FilesystemWorkspacePreparer, error) {
	if objects == nil || runtimeGID == 0 || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, ErrInvalid
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		info.Mode().Perm()&0o022 != 0 {
		return nil, ErrInvalid
	}
	return &FilesystemWorkspacePreparer{
		objects: objects, root: root, rootInfo: info, runtimeGID: runtimeGID,
	}, nil
}

func (preparer *FilesystemWorkspacePreparer) Prepare(
	ctx context.Context,
	claimed ClaimedTask,
) (cloudruntime.Workspace, func(), error) {
	if preparer == nil || ctx == nil {
		return cloudruntime.Workspace{}, nil, ErrInvalid
	}
	rootInfo, err := os.Lstat(preparer.root)
	if err != nil || preparer.rootInfo == nil || !os.SameFile(preparer.rootInfo, rootInfo) ||
		!rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 ||
		rootInfo.Mode().Perm()&0o022 != 0 {
		return cloudruntime.Workspace{}, nil, ErrIdentityChanged
	}
	manifest, err := parseInputManifest(
		claimed.InputManifestJSON, claimed.Task.InputManifestSHA256,
	)
	if err != nil {
		return cloudruntime.Workspace{}, nil, err
	}
	if claimed.Task.WorkspaceMode == cloudruntime.WorkspaceNone {
		if len(manifest.Items) != 0 {
			return cloudruntime.Workspace{}, nil, ErrInvalid
		}
		return cloudruntime.Workspace{}, nil, nil
	}
	if len(manifest.Items) == 0 && claimed.Task.WorkspaceMode != cloudruntime.WorkspaceWrite {
		return cloudruntime.Workspace{}, nil, ErrInvalid
	}
	directory, err := os.MkdirTemp(preparer.root, "workspace-")
	if err != nil {
		return cloudruntime.Workspace{}, nil, ErrUnavailable
	}
	cleanup := func() { cleanupWorkspaceTree(directory) }
	if os.Chmod(directory, 0o700) != nil {
		cleanup()
		return cloudruntime.Workspace{}, nil, ErrUnavailable
	}
	for _, item := range manifest.Items {
		if err := preparer.materialize(ctx, claimed.Binding, directory, item); err != nil {
			cleanup()
			return cloudruntime.Workspace{}, nil, err
		}
	}
	readOnly := claimed.Task.WorkspaceMode == cloudruntime.WorkspaceReadOnly
	if makeWorkspaceTreeAccessible(directory, preparer.runtimeGID, readOnly) != nil {
		cleanup()
		return cloudruntime.Workspace{}, nil, ErrUnavailable
	}
	return cloudruntime.Workspace{
		Directory: directory, Mode: claimed.Task.WorkspaceMode,
		SHA256: claimed.Task.WorkspaceSHA256, ReadOnly: readOnly,
		Isolated: claimed.Task.WorkspaceMode == cloudruntime.WorkspaceWrite,
	}, cleanup, nil
}

// cleanupWorkspaceTree restores only directory permissions inside the private
// worker-owned tree before removal. WalkDir never follows a Pi-created
// symlink, so cleanup cannot chmod a target outside the isolated workspace.
func cleanupWorkspaceTree(root string) {
	_ = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			_ = os.Chmod(path, 0o770)
		}
		return nil
	})
	_ = os.RemoveAll(root)
}

func (preparer *FilesystemWorkspacePreparer) materialize(
	ctx context.Context,
	binding Binding,
	root string,
	item InputManifestItem,
) error {
	read, err := preparer.objects.ReadExact(ctx, binding, InputObjectRequest{
		Bucket: item.S3Bucket, Key: item.S3Key, VersionID: item.S3VersionID,
		SizeBytes: item.SizeBytes, MediaType: item.MediaType,
	})
	if err != nil {
		return ErrUnavailable
	}
	if read.Body == nil {
		return ErrInvalid
	}
	defer read.Body.Close()
	if read.Bucket != item.S3Bucket || read.Key != item.S3Key ||
		read.VersionID != item.S3VersionID || read.SizeBytes != item.SizeBytes ||
		read.MediaType != item.MediaType {
		return ErrInvalid
	}
	target := filepath.Join(root, filepath.FromSlash(item.MountPath))
	if !strings.HasPrefix(target, root+string(os.PathSeparator)) ||
		filepath.Clean(target) != target || os.MkdirAll(filepath.Dir(target), 0o700) != nil {
		return ErrInvalid
	}
	if item.Kind == "archive" {
		compressed, readErr := io.ReadAll(io.LimitReader(
			&inputContextReader{ctx: ctx, reader: read.Body}, item.SizeBytes+1,
		))
		defer clear(compressed)
		digest := sha256.Sum256(compressed)
		expected, decodeErr := hex.DecodeString(item.SHA256)
		validDigest := decodeErr == nil && len(expected) == sha256.Size &&
			subtle.ConstantTimeCompare(expected, digest[:]) == 1
		clear(expected)
		if readErr != nil || int64(len(compressed)) != item.SizeBytes || !validDigest ||
			os.Mkdir(target, 0o700) != nil || workspacearchive.Extract(bytes.NewReader(compressed), target) != nil {
			return ErrInvalid
		}
		return nil
	}
	file, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return ErrUnavailable
	}
	hasher := sha256.New()
	written, copyErr := io.Copy(
		io.MultiWriter(file, hasher),
		io.LimitReader(&inputContextReader{ctx: ctx, reader: read.Body}, item.SizeBytes+1),
	)
	syncErr := file.Sync()
	closeErr := file.Close()
	expected, decodeErr := hex.DecodeString(item.SHA256)
	actual := hasher.Sum(nil)
	validDigest := decodeErr == nil && len(expected) == sha256.Size &&
		subtle.ConstantTimeCompare(expected, actual) == 1
	clear(expected)
	clear(actual)
	if copyErr != nil || syncErr != nil || closeErr != nil || written != item.SizeBytes ||
		!validDigest {
		return ErrInvalid
	}
	return nil
}

func parseInputManifest(raw []byte, expectedSHA256 string) (InputManifest, error) {
	if cloudruntime.ValidateInputManifestJSON(raw, expectedSHA256) != nil {
		return InputManifest{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest InputManifest
	if decoder.Decode(&manifest) != nil || manifest.Schema != InputManifestSchemaV1 ||
		len(manifest.Items) > MaxInputItems {
		return InputManifest{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return InputManifest{}, ErrInvalid
	}
	seenIDs := make(map[string]struct{}, len(manifest.Items))
	seenPaths := make(map[string]struct{}, len(manifest.Items))
	seenFoldedPaths := make(map[string]string, len(manifest.Items))
	archiveCount := 0
	var totalBytes int64
	for index, item := range manifest.Items {
		if !canonicalUUID(item.InputID) || (item.Kind != "file" && item.Kind != "archive") ||
			!validInputText(item.Name, 255) || !validMountPath(item.MountPath) ||
			!validInputText(item.MediaType, 255) || item.SizeBytes < 1 ||
			item.SizeBytes > MaxInputObjectBytes || !validDigest(item.SHA256) ||
			!validInputBucket(item.S3Bucket) || !validInputKey(item.S3Key) ||
			!validInputVersion(item.S3VersionID) {
			return InputManifest{}, ErrInvalid
		}
		if item.Kind == "archive" {
			archiveCount++
			if archiveCount > 1 || item.MountPath != "workspace" || item.MediaType != workspacearchive.MediaType {
				return InputManifest{}, ErrInvalid
			}
		} else if item.MediaType == workspacearchive.MediaType || item.MountPath == "workspace" ||
			strings.HasPrefix(item.MountPath, "workspace/") {
			return InputManifest{}, ErrInvalid
		}
		totalBytes += item.SizeBytes
		if totalBytes > MaxInputTotalBytes {
			return InputManifest{}, ErrInvalid
		}
		if _, duplicate := seenIDs[item.InputID]; duplicate {
			return InputManifest{}, ErrInvalid
		}
		if _, duplicate := seenPaths[item.MountPath]; duplicate {
			return InputManifest{}, ErrInvalid
		}
		folded := strings.ToLower(item.MountPath)
		if existing, collision := seenFoldedPaths[folded]; collision && existing != item.MountPath {
			return InputManifest{}, ErrInvalid
		}
		for existing := range seenPaths {
			if strings.HasPrefix(existing, item.MountPath+"/") || strings.HasPrefix(item.MountPath, existing+"/") ||
				strings.HasPrefix(strings.ToLower(existing), folded+"/") ||
				strings.HasPrefix(folded, strings.ToLower(existing)+"/") {
				return InputManifest{}, ErrInvalid
			}
		}
		seenIDs[item.InputID] = struct{}{}
		seenPaths[item.MountPath] = struct{}{}
		seenFoldedPaths[folded] = item.MountPath
		if index > 0 {
			previous := manifest.Items[index-1]
			if previous.MountPath > item.MountPath ||
				(previous.MountPath == item.MountPath && previous.InputID >= item.InputID) {
				return InputManifest{}, ErrInvalid
			}
		}
	}
	canonicalItems := append([]InputManifestItem(nil), manifest.Items...)
	sort.Slice(canonicalItems, func(i, j int) bool {
		if canonicalItems[i].MountPath == canonicalItems[j].MountPath {
			return canonicalItems[i].InputID < canonicalItems[j].InputID
		}
		return canonicalItems[i].MountPath < canonicalItems[j].MountPath
	})
	return manifest, nil
}

func makeWorkspaceTreeAccessible(root string, runtimeGID uint32, readOnly bool) error {
	if runtimeGID == 0 {
		return ErrInvalid
	}
	var directories []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		if os.Chown(path, -1, int(runtimeGID)) != nil {
			return ErrUnavailable
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		if !info.Mode().IsRegular() {
			return ErrInvalid
		}
		mode := os.FileMode(0o660)
		if readOnly {
			mode = 0o440
		}
		return os.Chmod(path, mode)
	})
	if err != nil {
		return err
	}
	for index := len(directories) - 1; index >= 0; index-- {
		mode := os.FileMode(0o770)
		if readOnly {
			mode = 0o550
		}
		if err := os.Chmod(directories[index], mode); err != nil {
			return err
		}
	}
	return nil
}

type inputContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader *inputContextReader) Read(target []byte) (int, error) {
	select {
	case <-reader.ctx.Done():
		return 0, reader.ctx.Err()
	default:
		return reader.reader.Read(target)
	}
}

func validInputText(value string, maximum int) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= maximum &&
		utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validMountPath(value string) bool {
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return value != "" && len(value) <= 1024 && clean == value && clean != "." &&
		clean != ".." && !strings.HasPrefix(clean, "../") && !strings.HasPrefix(clean, "/") &&
		!strings.Contains(value, "\\")
}

func validInputBucket(value string) bool {
	if len(value) < 3 || len(value) > 63 || value != strings.ToLower(value) ||
		strings.ContainsAny(value, "/:*?#\r\n\x00") || strings.Contains(value, "..") ||
		strings.HasPrefix(value, "xn--") || strings.HasSuffix(value, "-s3alias") ||
		strings.HasSuffix(value, "--ol-s3") {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') &&
			character != '.' && character != '-' {
			return false
		}
	}
	return value[0] != '.' && value[0] != '-' && value[len(value)-1] != '.' &&
		value[len(value)-1] != '-' && net.ParseIP(value) == nil
}

func validInputKey(value string) bool {
	return value != "" && len(value) <= 1024 && !strings.HasPrefix(value, "/") &&
		!strings.Contains(value, "\\") && !strings.Contains(value, "../") &&
		utf8.ValidString(value) && strings.IndexFunc(value, unicode.IsControl) < 0
}

func validInputVersion(value string) bool {
	return value != "" && value != "null" && len(value) <= 1024 &&
		value == strings.TrimSpace(value) && utf8.ValidString(value) &&
		strings.IndexFunc(value, func(character rune) bool {
			return unicode.IsControl(character) || unicode.IsSpace(character)
		}) < 0
}

var _ WorkspacePreparer = (*FilesystemWorkspacePreparer)(nil)
