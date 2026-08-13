// Package localartifact stores SSH Worker output on the Agent filesystem.
//
// It is intentionally independent of provider object storage: the temporary
// Worker is destroyed after SSH collection while these immutable local bytes
// remain available to the existing Agent read surface.
package localartifact

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

var (
	ErrInvalid  = errors.New("local artifact request is invalid")
	ErrNotFound = errors.New("local artifact not found")
	ErrConflict = errors.New("local artifact conflicts with stored output")
)

const (
	MaxArtifactBytes      int64 = 64 << 20
	MaxExecutionBytes     int64 = 192 << 20
	MaxExecutionArtifacts       = 1024
	MaxDownloadChunkBytes int64 = 512 << 10
	maxArtifactNameBytes        = 1024
)

type Authority struct {
	OwnerID           string `json:"owner_id"`
	AccountGeneration uint64 `json:"account_generation"`
}

func (authority Authority) validate() error {
	if strings.TrimSpace(authority.OwnerID) == "" || authority.OwnerID != strings.TrimSpace(authority.OwnerID) ||
		len(authority.OwnerID) > 512 || !utf8.ValidString(authority.OwnerID) || authority.AccountGeneration == 0 {
		return ErrInvalid
	}
	return nil
}

type Artifact struct {
	Authority
	ArtifactID  string    `json:"artifact_id"`
	ExecutionID string    `json:"execution_id"`
	Kind        string    `json:"kind"`
	Name        string    `json:"name"`
	MediaType   string    `json:"media_type"`
	SizeBytes   int64     `json:"size_bytes"`
	SHA256      string    `json:"sha256"`
	CreatedAt   time.Time `json:"created_at"`
}

func (artifact Artifact) validate() error {
	if artifact.Authority.validate() != nil || !validID(artifact.ArtifactID) || !validID(artifact.ExecutionID) ||
		(artifact.Kind != "stdout" && artifact.Kind != "stderr" && artifact.Kind != "file") ||
		!validName(artifact.Name) || strings.TrimSpace(artifact.MediaType) == "" || len(artifact.MediaType) > 255 ||
		strings.ContainsAny(artifact.MediaType, "\r\n\x00") || artifact.SizeBytes < 0 || artifact.SizeBytes > MaxArtifactBytes ||
		!validDigest(artifact.SHA256) || artifact.CreatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type ExecutionOutput struct {
	Authority
	ExecutionID      string    `json:"execution_id"`
	ExitCode         int       `json:"exit_code"`
	StdoutArtifactID string    `json:"stdout_artifact_id"`
	StderrArtifactID string    `json:"stderr_artifact_id"`
	UpdatedAt        time.Time `json:"updated_at"`
}

func (output ExecutionOutput) validate() error {
	if output.Authority.validate() != nil || !validID(output.ExecutionID) || !validID(output.StdoutArtifactID) ||
		!validID(output.StderrArtifactID) || output.UpdatedAt.IsZero() {
		return ErrInvalid
	}
	return nil
}

type Chunk struct {
	Artifact        Artifact
	OffsetBytes     int64
	Data            []byte
	ChunkSHA256     string
	NextOffsetBytes int64
	EOF             bool
}

type Repository struct {
	root string
	now  func() time.Time
	mu   sync.RWMutex
}

func NewRepository(root string) (*Repository, error) {
	if !filepath.IsAbs(root) {
		return nil, ErrInvalid
	}
	root = filepath.Clean(root)
	if info, err := os.Lstat(root); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrInvalid
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "objects"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(root, "executions"), 0o700); err != nil {
		return nil, err
	}
	return &Repository{root: root, now: func() time.Time { return time.Now().UTC() }}, nil
}

// Bind returns the execution-scoped ResultSink passed to sshworker.Execute.
func (repository *Repository) Bind(authority Authority, executionID string) (*Sink, error) {
	if repository == nil || authority.validate() != nil || !validID(executionID) {
		return nil, ErrInvalid
	}
	return &Sink{repository: repository, authority: authority, executionID: executionID}, nil
}

type Sink struct {
	repository  *Repository
	authority   Authority
	executionID string
}

func (sink *Sink) StoreText(ctx context.Context, stdout, stderr []byte, exitCode int) error {
	if sink == nil || sink.repository == nil || ctx == nil || ctx.Err() != nil ||
		int64(len(stdout)) > MaxArtifactBytes || int64(len(stderr)) > MaxArtifactBytes {
		return ErrInvalid
	}
	stdoutArtifact, err := sink.store(ctx, "stdout", "stdout.txt", "text/plain; charset=utf-8", int64(len(stdout)), bytes.NewReader(stdout))
	if err != nil {
		return err
	}
	stderrArtifact, err := sink.store(ctx, "stderr", "stderr.txt", "text/plain; charset=utf-8", int64(len(stderr)), bytes.NewReader(stderr))
	if err != nil {
		return err
	}
	output := ExecutionOutput{Authority: sink.authority, ExecutionID: sink.executionID, ExitCode: exitCode,
		StdoutArtifactID: stdoutArtifact.ArtifactID, StderrArtifactID: stderrArtifact.ArtifactID,
		UpdatedAt: sink.repository.now().UTC()}
	return sink.repository.saveExecution(output)
}

func (sink *Sink) StoreArtifact(ctx context.Context, name string, reader io.Reader, size int64) error {
	if sink == nil || reader == nil || !validName(name) || size < 0 || size > MaxArtifactBytes {
		return ErrInvalid
	}
	mediaType := mime.TypeByExtension(strings.ToLower(path.Ext(name)))
	if mediaType == "" {
		mediaType = "application/octet-stream"
	}
	_, err := sink.store(ctx, "file", name, mediaType, size, reader)
	return err
}

func (sink *Sink) store(ctx context.Context, kind, name, mediaType string, size int64, reader io.Reader) (Artifact, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil {
		return Artifact{}, ErrInvalid
	}
	artifactID := deterministicArtifactID(sink.executionID, kind, name)
	repository := sink.repository
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if existing, err := repository.loadArtifactLocked(artifactID); err == nil {
		if existing.Authority != sink.authority || existing.ExecutionID != sink.executionID || existing.Kind != kind ||
			existing.Name != name || existing.MediaType != mediaType || existing.SizeBytes != size {
			return Artifact{}, ErrConflict
		}
		supplied, suppliedBytes, digestErr := digestReader(reader, size)
		if digestErr != nil || suppliedBytes != size || supplied != existing.SHA256 {
			return Artifact{}, ErrConflict
		}
		actual, digestErr := digestFile(repository.dataPath(artifactID))
		if digestErr != nil || actual != existing.SHA256 {
			return Artifact{}, ErrConflict
		}
		return existing, nil
	} else if !errors.Is(err, ErrNotFound) {
		return Artifact{}, err
	}
	count, total, err := repository.executionUsageLocked(sink.authority, sink.executionID)
	if err != nil {
		return Artifact{}, err
	}
	if count >= MaxExecutionArtifacts || total+size > MaxExecutionBytes {
		return Artifact{}, ErrInvalid
	}
	temporary, err := os.CreateTemp(filepath.Join(repository.root, "objects"), ".artifact-*")
	if err != nil {
		return Artifact{}, err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err = temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return Artifact{}, err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(reader, size+1))
	syncErr := temporary.Sync()
	closeErr := temporary.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil {
		return Artifact{}, errors.Join(copyErr, syncErr, closeErr)
	}
	if written != size {
		return Artifact{}, ErrConflict
	}
	artifact := Artifact{Authority: sink.authority, ArtifactID: artifactID, ExecutionID: sink.executionID,
		Kind: kind, Name: name, MediaType: mediaType, SizeBytes: size,
		SHA256: hex.EncodeToString(hash.Sum(nil)), CreatedAt: repository.now().UTC()}
	if artifact.validate() != nil {
		return Artifact{}, ErrInvalid
	}
	if err = os.Rename(temporaryName, repository.dataPath(artifactID)); err != nil {
		return Artifact{}, err
	}
	if err = writeJSONAtomic(repository.metadataPath(artifactID), artifact); err != nil {
		_ = os.Remove(repository.dataPath(artifactID))
		return Artifact{}, err
	}
	return artifact, nil
}

func (repository *Repository) List(ctx context.Context, authority Authority, executionID, pageToken string, pageSize int) ([]Artifact, string, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || authority.validate() != nil || !validID(executionID) ||
		pageSize < 1 || pageSize > 200 {
		return nil, "", ErrInvalid
	}
	after, err := decodePageToken(pageToken)
	if err != nil {
		return nil, "", err
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	items, err := repository.listLocked(authority, executionID)
	if err != nil {
		return nil, "", err
	}
	start := sort.Search(len(items), func(index int) bool { return items[index].ArtifactID > after })
	end := start + pageSize
	if end > len(items) {
		end = len(items)
	}
	page := append([]Artifact(nil), items[start:end]...)
	next := ""
	if end < len(items) {
		next = base64.RawURLEncoding.EncodeToString([]byte(items[end-1].ArtifactID))
	}
	return page, next, nil
}

func (repository *Repository) Get(ctx context.Context, authority Authority, artifactID string) (Artifact, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || authority.validate() != nil || !validID(artifactID) {
		return Artifact{}, ErrInvalid
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	artifact, err := repository.loadArtifactLocked(artifactID)
	if err != nil {
		return Artifact{}, err
	}
	if artifact.Authority != authority {
		return Artifact{}, ErrNotFound
	}
	return artifact, nil
}

func (repository *Repository) Download(ctx context.Context, authority Authority, artifactID string, offset, maxBytes int64) (Chunk, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || authority.validate() != nil || !validID(artifactID) ||
		offset < 0 || maxBytes < 1 || maxBytes > MaxDownloadChunkBytes {
		return Chunk{}, ErrInvalid
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	artifact, err := repository.loadArtifactLocked(artifactID)
	if err != nil || artifact.Authority != authority {
		if err == nil {
			err = ErrNotFound
		}
		return Chunk{}, err
	}
	if offset > artifact.SizeBytes {
		return Chunk{}, ErrInvalid
	}
	file, err := os.Open(repository.dataPath(artifactID))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Chunk{}, ErrConflict
		}
		return Chunk{}, err
	}
	defer file.Close()
	if _, err = file.Seek(offset, io.SeekStart); err != nil {
		return Chunk{}, err
	}
	remaining := artifact.SizeBytes - offset
	want := min(remaining, maxBytes)
	data := make([]byte, want)
	if _, err = io.ReadFull(file, data); err != nil {
		return Chunk{}, ErrConflict
	}
	digest := sha256.Sum256(data)
	return Chunk{Artifact: artifact, OffsetBytes: offset, Data: data,
		ChunkSHA256: hex.EncodeToString(digest[:]), NextOffsetBytes: offset + int64(len(data)),
		EOF: offset+int64(len(data)) == artifact.SizeBytes}, nil
}

func (repository *Repository) GetExecution(ctx context.Context, authority Authority, executionID string) (ExecutionOutput, error) {
	if repository == nil || ctx == nil || ctx.Err() != nil || authority.validate() != nil || !validID(executionID) {
		return ExecutionOutput{}, ErrInvalid
	}
	repository.mu.RLock()
	defer repository.mu.RUnlock()
	var output ExecutionOutput
	if err := readJSON(repository.executionPath(executionID), &output); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ExecutionOutput{}, ErrNotFound
		}
		return ExecutionOutput{}, err
	}
	if output.validate() != nil {
		return ExecutionOutput{}, ErrConflict
	}
	if output.Authority != authority || output.ExecutionID != executionID {
		return ExecutionOutput{}, ErrNotFound
	}
	return output, nil
}

func (repository *Repository) saveExecution(output ExecutionOutput) error {
	if output.validate() != nil {
		return ErrInvalid
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	var existing ExecutionOutput
	err := readJSON(repository.executionPath(output.ExecutionID), &existing)
	if err == nil {
		if existing.Authority != output.Authority || existing.ExecutionID != output.ExecutionID ||
			existing.ExitCode != output.ExitCode || existing.StdoutArtifactID != output.StdoutArtifactID ||
			existing.StderrArtifactID != output.StderrArtifactID {
			return ErrConflict
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeJSONAtomic(repository.executionPath(output.ExecutionID), output)
}

func (repository *Repository) executionUsageLocked(authority Authority, executionID string) (int, int64, error) {
	items, err := repository.listLocked(authority, executionID)
	if err != nil {
		return 0, 0, err
	}
	var total int64
	for _, item := range items {
		total += item.SizeBytes
	}
	return len(items), total, nil
}

func (repository *Repository) listLocked(authority Authority, executionID string) ([]Artifact, error) {
	entries, err := os.ReadDir(filepath.Join(repository.root, "objects"))
	if err != nil {
		return nil, err
	}
	items := make([]Artifact, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		var artifact Artifact
		if err := readJSON(filepath.Join(repository.root, "objects", entry.Name()), &artifact); err != nil || artifact.validate() != nil {
			return nil, ErrConflict
		}
		if artifact.Authority == authority && artifact.ExecutionID == executionID {
			items = append(items, artifact)
		}
	}
	sort.Slice(items, func(left, right int) bool { return items[left].ArtifactID < items[right].ArtifactID })
	return items, nil
}

func (repository *Repository) loadArtifactLocked(artifactID string) (Artifact, error) {
	var artifact Artifact
	if err := readJSON(repository.metadataPath(artifactID), &artifact); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Artifact{}, ErrNotFound
		}
		return Artifact{}, err
	}
	if artifact.validate() != nil || artifact.ArtifactID != artifactID {
		return Artifact{}, ErrConflict
	}
	return artifact, nil
}

func (repository *Repository) dataPath(artifactID string) string {
	return filepath.Join(repository.root, "objects", artifactID+".data")
}

func (repository *Repository) metadataPath(artifactID string) string {
	return filepath.Join(repository.root, "objects", artifactID+".json")
}

func (repository *Repository) executionPath(executionID string) string {
	return filepath.Join(repository.root, "executions", executionID+".json")
}

func writeJSONAtomic(name string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(name), ".metadata-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err = temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err = temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err = temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, name)
}

func readJSON(name string, value any) error {
	body, err := os.ReadFile(name)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return ErrConflict
	}
	return nil
}

func digestFile(name string) (string, error) {
	file, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func digestReader(reader io.Reader, size int64) (string, int64, error) {
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(reader, size+1))
	if err != nil {
		return "", written, err
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func deterministicArtifactID(executionID, kind, name string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte("dirextalk-local-artifact:"+executionID+":"+kind+":"+name)).String()
}

func validName(name string) bool {
	clean := path.Clean(strings.TrimSpace(name))
	return name == strings.TrimSpace(name) && name != "" && len(name) <= maxArtifactNameBytes && utf8.ValidString(name) &&
		clean == name && clean != "." && !path.IsAbs(name) && !strings.HasPrefix(name, "../") &&
		!strings.ContainsAny(name, "\\\r\n\x00")
}

func validID(value string) bool { return coretask.ValidUUID(strings.TrimSpace(value)) }

func validDigest(value string) bool { return coretask.ValidDigest(strings.TrimSpace(value)) }

func decodePageToken(token string) (string, error) {
	if token == "" {
		return "", nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || !validID(string(raw)) {
		return "", ErrInvalid
	}
	return string(raw), nil
}

var _ sshworker.ResultSink = (*Sink)(nil)
