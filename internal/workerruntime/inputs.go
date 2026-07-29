package workerruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	MaxContextBytes    = 512 << 10
	MaxCredentialBytes = 16 << 10
	workspaceMarker    = ".dirextalk-workspace-digest"
)

type ResolvedInputs struct {
	ContextJSON  []byte
	WorkspaceDir string
	Credential   []byte
}

func (inputs *ResolvedInputs) Destroy() {
	if inputs == nil {
		return
	}
	clear(inputs.ContextJSON)
	clear(inputs.Credential)
	*inputs = ResolvedInputs{}
}

type InputResolver interface {
	Resolve(context.Context, TaskV1) (ResolvedInputs, error)
}

// FilesystemResolver maps only digest and credential-slot identifiers to
// fixed roots prepared by the signed Worker Recipe. It does not accept paths
// from the execution bundle.
type FilesystemResolver struct {
	contextRoot    string
	workspaceRoot  string
	credentialRoot string
}

func NewFilesystemResolver(
	contextRoot string,
	workspaceRoot string,
	credentialRoot string,
) (*FilesystemResolver, error) {
	roots := []string{contextRoot, workspaceRoot, credentialRoot}
	for index, root := range roots {
		clean := filepath.Clean(root)
		if !filepath.IsAbs(clean) || clean != root {
			return nil, ErrInvalid
		}
		info, err := os.Lstat(clean)
		if err != nil || info.Mode()&os.ModeSymlink != 0 ||
			!info.IsDir() {
			return nil, ErrInvalid
		}
		roots[index] = clean
	}
	return &FilesystemResolver{
		contextRoot:    roots[0],
		workspaceRoot:  roots[1],
		credentialRoot: roots[2],
	}, nil
}

func (resolver *FilesystemResolver) Resolve(
	ctx context.Context,
	task TaskV1,
) (ResolvedInputs, error) {
	if resolver == nil || task.Validate() != nil {
		return ResolvedInputs{}, ErrInvalid
	}
	contextName := strings.TrimPrefix(task.ContextDigest, "sha256:") + ".json"
	contextPath := filepath.Join(resolver.contextRoot, contextName)
	contextJSON, err := readStableFile(ctx, contextPath, MaxContextBytes)
	if err != nil || !json.Valid(contextJSON) ||
		security.ContainsLikelySecret(string(contextJSON)) ||
		!matchesDigest(contextJSON, task.ContextDigest) {
		clear(contextJSON)
		return ResolvedInputs{}, ErrInvalid
	}

	workspaceDir := ""
	if task.WorkspaceMode != WorkspaceNone {
		workspaceDir = filepath.Join(
			resolver.workspaceRoot,
			strings.TrimPrefix(task.WorkspaceDigest, "sha256:"),
		)
		if err := validateWorkspace(
			ctx, workspaceDir, task.WorkspaceDigest,
		); err != nil {
			clear(contextJSON)
			return ResolvedInputs{}, err
		}
	}

	credentialPath := filepath.Join(resolver.credentialRoot, task.CredentialSlot)
	credential, err := readCredential(ctx, credentialPath)
	if err != nil {
		clear(contextJSON)
		return ResolvedInputs{}, err
	}
	return ResolvedInputs{
		ContextJSON: contextJSON, WorkspaceDir: workspaceDir,
		Credential: credential,
	}, nil
}

func validateWorkspace(
	ctx context.Context,
	name string,
	expectedDigest string,
) error {
	if ctx == nil {
		return ErrInvalid
	}
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrInvalid
	}
	markerPath := filepath.Join(name, workspaceMarker)
	marker, err := readStableFile(ctx, markerPath, 128)
	if err != nil {
		return ErrInvalid
	}
	defer clear(marker)
	if string(bytes.TrimSpace(marker)) != expectedDigest {
		return ErrInvalid
	}
	return nil
}

func readCredential(ctx context.Context, name string) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil || info.Mode()&os.ModeSymlink != 0 ||
		!info.Mode().IsRegular() ||
		(info.Mode().Perm() != 0o400 && info.Mode().Perm() != 0o440) {
		return nil, ErrInvalid
	}
	raw, err := readStableFile(ctx, name, MaxCredentialBytes)
	if err != nil {
		return nil, ErrInvalid
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) < 32 || len(trimmed) > MaxCredentialBytes ||
		bytes.IndexAny(trimmed, "\r\n\x00") >= 0 {
		clear(raw)
		return nil, ErrInvalid
	}
	value := bytes.Clone(trimmed)
	clear(raw)
	return value, nil
}

func readStableFile(
	ctx context.Context,
	name string,
	maximum int64,
) ([]byte, error) {
	if ctx == nil || maximum < 1 {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(name)
	if err != nil || before.Mode()&os.ModeSymlink != 0 ||
		!before.Mode().IsRegular() || before.Size() < 1 ||
		before.Size() > maximum {
		return nil, ErrInvalid
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrInvalid
	}
	content, err := io.ReadAll(io.LimitReader(
		&contextReader{ctx: ctx, reader: file},
		maximum+1,
	))
	if err != nil || int64(len(content)) > maximum ||
		int64(len(content)) != before.Size() {
		clear(content)
		return nil, ErrInvalid
	}
	after, err := os.Lstat(name)
	if err != nil || after.Mode()&os.ModeSymlink != 0 ||
		!os.SameFile(before, after) || after.Size() != before.Size() {
		clear(content)
		return nil, ErrInvalid
	}
	return content, nil
}

func matchesDigest(content []byte, expected string) bool {
	decoded, err := hex.DecodeString(strings.TrimPrefix(expected, "sha256:"))
	if err != nil || len(decoded) != sha256.Size {
		clear(decoded)
		return false
	}
	defer clear(decoded)
	actual := sha256.Sum256(content)
	return subtle.ConstantTimeCompare(actual[:], decoded) == 1
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
