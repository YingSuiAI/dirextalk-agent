package execution

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/google/uuid"
)

const (
	maxArtifactFiles = 128
	maxArtifactBytes = 64 << 20
)

type materialFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type Materialized struct {
	Root      string
	Digest    string // runner install/manifest digest
	Files     []MaterializedFile
	EntryPath string
}

type MaterializedFile struct {
	Path string
	Data []byte
	Hash string
}

// Materializer decodes the canonical source artifact and creates an immutable
// digest-addressed install directory. It never invokes an interpreter.
type Materializer struct {
	Root      string
	Publisher Publisher
}
type ArtifactStoreAdapter struct {
	Materializer *Materializer
	RemoveFunc   func(context.Context, string, string) error
}

func (a ArtifactStoreAdapter) Materialize(ctx context.Context, f core.FetchArtifact) (core.ArtifactReceipt, error) {
	if a.Materializer == nil {
		return core.ArtifactReceipt{}, core.ErrInvalid
	}
	m, err := a.Materializer.Materialize(ctx, f)
	if err != nil {
		return core.ArtifactReceipt{}, err
	}
	return core.ArtifactReceipt{RelativePath: m.Digest, ContentDigest: f.ContentDigest, ArtifactDigest: m.Digest, CleanupToken: uuid.NewString()}, nil
}
func (a ArtifactStoreAdapter) Remove(ctx context.Context, r core.ArtifactReceipt) error {
	if r.RelativePath == "" || r.RelativePath != r.ArtifactDigest || len(r.ContentDigest) != 64 || uuid.Validate(r.CleanupToken) != nil {
		return core.ErrInvalid
	}
	if a.RemoveFunc == nil {
		return errors.New("runner cleanup unavailable")
	}
	return a.RemoveFunc(ctx, r.ArtifactDigest, r.CleanupToken)
}

type Publisher interface {
	Publish(context.Context, []extensionrunner.ManifestEntry, []extensionrunner.PublishFile) (extensionrunner.PublishResponse, error)
}

// StagedLifecyclePromoter publishes an immutable Agent-staged install through
// the authenticated runner only after confirmation consumption. The staged
// tree is never executed directly and Remove is kept as a separate idempotent
// runner operation.
type StagedLifecyclePromoter struct {
	Root       string
	Publisher  Publisher
	RemoveFunc func(context.Context, string) error
}

func (p StagedLifecyclePromoter) Promote(ctx context.Context, version core.VersionRecord) error {
	if p.Publisher == nil || !filepath.IsAbs(p.Root) || filepath.Clean(p.Root) != p.Root || len(version.ArtifactDigest) != 64 || version.ArtifactPath == "" || filepath.Base(version.ArtifactPath) != version.ArtifactDigest {
		return core.ErrInvalid
	}
	root := filepath.Join(p.Root, filepath.Base(version.ArtifactPath))
	if filepath.Dir(root) != p.Root {
		return core.ErrInvalid
	}
	manifest, err := os.ReadFile(filepath.Join(root, ".dirextalk-install-v1.json"))
	if err != nil {
		return err
	}
	var disk extensionrunner.DiskInstallManifestV1
	if json.Unmarshal(bytes.TrimSuffix(manifest, []byte{'\n'}), &disk) != nil || disk.SchemaVersion != "dirextalk.extension.install-manifest/v1" {
		return core.ErrConflict
	}
	canonicalManifest, _ := json.Marshal(disk)
	if !bytes.Equal(manifest, append(canonicalManifest, '\n')) || extensionrunner.ManifestDigest(disk.Entries) != version.ArtifactDigest {
		return core.ErrConflict
	}
	files := make([]extensionrunner.PublishFile, 0, len(disk.Entries))
	for _, entry := range disk.Entries {
		if entry.Path == "" || filepath.IsAbs(entry.Path) || strings.Contains(entry.Path, "..") || strings.ContainsAny(entry.Path, `\\\x00\r\n`) {
			return core.ErrInvalid
		}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil || extensionrunner.DigestBytes(data) != entry.SHA256 || int64(len(data)) != entry.Size {
			return core.ErrConflict
		}
		files = append(files, extensionrunner.PublishFile{Path: entry.Path, Data: data})
	}
	response, err := p.Publisher.Publish(ctx, disk.Entries, files)
	if err != nil {
		return err
	}
	if response.Digest != version.ArtifactDigest {
		return core.ErrConflict
	}
	return nil
}

func (p StagedLifecyclePromoter) Remove(ctx context.Context, version core.VersionRecord) error {
	if p.RemoveFunc == nil || len(version.ArtifactDigest) != 64 {
		return core.ErrInvalid
	}
	return p.RemoveFunc(ctx, version.ArtifactDigest)
}

func NewMaterializer(root string) (*Materializer, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return nil, errors.New("invalid artifact root")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return nil, err
	}
	return &Materializer{Root: root}, nil
}
func NewMaterializerWithPublisher(root string, publisher Publisher) (*Materializer, error) {
	m, err := NewMaterializer(root)
	if err != nil {
		return nil, err
	}
	m.Publisher = publisher
	return m, nil
}

func (m *Materializer) Materialize(ctx context.Context, artifact core.FetchArtifact) (Materialized, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return Materialized{}, err
	}
	if err := artifact.Validate(); err != nil {
		return Materialized{}, err
	}
	files, err := decodeCanonical(artifact.Content)
	if err != nil {
		return Materialized{}, err
	}
	if digestArtifact(artifact.Content) != artifact.ContentDigest {
		return Materialized{}, errors.New("artifact digest mismatch")
	}
	manifest := make([]map[string]string, 0, len(files))
	var total int64
	declaredFound := artifact.Inspection.Execution.Stdio == nil && artifact.Inspection.Execution.Skill == nil
	for _, f := range files {
		data, e := base64.RawStdEncoding.DecodeString(f.Content)
		if e != nil {
			return Materialized{}, errors.New("invalid artifact base64")
		}
		if len(data) > maxArtifactBytes || total+int64(len(data)) > maxArtifactBytes {
			return Materialized{}, errors.New("artifact exceeds size limit")
		}
		total += int64(len(data))
		h := digestArtifact(data)
		if artifact.Inspection.Execution.Stdio != nil && f.Path == artifact.Inspection.Execution.Stdio.RelativePath && h != artifact.Inspection.Execution.Stdio.Digest {
			return Materialized{}, errors.New("declared executable digest mismatch")
		}
		if artifact.Inspection.Execution.Stdio != nil && f.Path == artifact.Inspection.Execution.Stdio.RelativePath {
			declaredFound = true
		}
		if artifact.Inspection.Execution.Skill != nil && f.Path == artifact.Inspection.Execution.Skill.RelativePath && h != artifact.Inspection.Execution.Skill.Digest {
			return Materialized{}, errors.New("declared skill digest mismatch")
		}
		if artifact.Inspection.Execution.Skill != nil && f.Path == artifact.Inspection.Execution.Skill.RelativePath {
			declaredFound = true
		}
		manifest = append(manifest, map[string]string{"path": f.Path, "digest": h})
	}
	if !declaredFound {
		return Materialized{}, errors.New("declared execution entry missing")
	}
	mb, _ := json.Marshal(manifest)
	if digestArtifact(mb) != artifact.ManifestDigest {
		return Materialized{}, errors.New("artifact manifest digest mismatch")
	}

	if artifact.Inspection.Execution.Stdio != nil && artifact.Inspection.Execution.Stdio.RelativePath != "entry" {
		return Materialized{}, errors.New("static executable must be literal entry")
	}
	if artifact.Inspection.Execution.Skill != nil && artifact.Inspection.Execution.Skill.Executable && artifact.Inspection.Execution.Skill.RelativePath != "entry" {
		return Materialized{}, errors.New("executable skill must be literal entry")
	}
	entries := make([]extensionrunner.ManifestEntry, 0, len(files))
	for _, f := range files {
		data, _ := base64.RawStdEncoding.DecodeString(f.Content)
		entries = append(entries, extensionrunner.ManifestEntry{Path: f.Path, SHA256: digestArtifact(data), Size: int64(len(data))})
	}
	installDigest := extensionrunner.ManifestDigest(entries)
	if m.Publisher != nil {
		publishFiles := make([]extensionrunner.PublishFile, 0, len(files))
		for _, f := range toCoreFiles(files) {
			publishFiles = append(publishFiles, extensionrunner.PublishFile{Path: f.Path, Data: f.Data})
		}
		response, err := m.Publisher.Publish(ctx, entries, publishFiles)
		if err != nil {
			return Materialized{}, err
		}
		if response.Digest != installDigest {
			return Materialized{}, errors.New("publisher returned mismatched digest")
		}
		return Materialized{Root: filepath.Join(m.Root, installDigest), Digest: installDigest, Files: toCoreFiles(files), EntryPath: entryPath(artifact.Inspection)}, nil
	}
	dst := filepath.Join(m.Root, installDigest)
	if filepath.Dir(dst) != m.Root {
		return Materialized{}, errors.New("invalid materialized path")
	}
	if st, e := os.Stat(dst); e == nil {
		if !st.IsDir() {
			return Materialized{}, errors.New("materialized path is not a directory")
		}
		if err := verifyDiskManifest(dst, installDigest); err != nil {
			return Materialized{}, err
		}
		return Materialized{Root: dst, Digest: installDigest, Files: toCoreFiles(files), EntryPath: entryPath(artifact.Inspection)}, nil
	}
	tmp, err := os.MkdirTemp(m.Root, ".install-")
	if err != nil {
		return Materialized{}, err
	}
	defer os.RemoveAll(tmp)
	for i, f := range files {
		data, _ := base64.RawStdEncoding.DecodeString(f.Content)
		p := filepath.Join(tmp, filepath.FromSlash(f.Path))
		if filepath.Dir(p) != tmp && !strings.HasPrefix(filepath.Clean(p), filepath.Clean(tmp)+string(os.PathSeparator)) {
			return Materialized{}, errors.New("artifact path escaped root")
		}
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			return Materialized{}, err
		}
		mode := os.FileMode(0600)
		if artifact.Inspection.Execution.Stdio != nil && f.Path == artifact.Inspection.Execution.Stdio.RelativePath {
			mode = 0700
		}
		if artifact.Inspection.Execution.Skill != nil && artifact.Inspection.Execution.Skill.Executable && f.Path == artifact.Inspection.Execution.Skill.RelativePath {
			mode = 0700
		}
		if err := writeImmutable(p, data, mode); err != nil {
			return Materialized{}, err
		}
		_ = i
	}
	manifestPayload, _ := json.Marshal(extensionrunner.DiskInstallManifestV1{SchemaVersion: "dirextalk.extension.install-manifest/v1", Entries: entries})
	if err := os.WriteFile(filepath.Join(tmp, ".dirextalk-install-v1.json"), append(manifestPayload, '\n'), 0400); err != nil {
		return Materialized{}, err
	}
	if err := os.Chmod(tmp, 0500); err != nil {
		return Materialized{}, err
	}
	if artifact.Inspection.Execution.Stdio != nil {
		admitted, err := extensionrunner.OpenAdmittedInstall(tmp, installDigest, entries)
		if err != nil {
			return Materialized{}, errors.New("static entry is not runner-admission compatible")
		}
		_ = admitted.Close()
	}
	if artifact.Inspection.Execution.Skill != nil && artifact.Inspection.Execution.Skill.Executable {
		admitted, err := extensionrunner.OpenAdmittedInstall(tmp, installDigest, entries)
		if err != nil {
			return Materialized{}, errors.New("executable skill is not runner-admission compatible")
		}
		_ = admitted.Close()
	}
	if err := os.Rename(tmp, dst); err != nil {
		if st, statErr := os.Stat(dst); statErr == nil && st.IsDir() {
			return Materialized{Root: dst, Digest: installDigest, Files: toCoreFiles(files), EntryPath: entryPath(artifact.Inspection)}, nil
		}
		return Materialized{}, err
	}
	return Materialized{Root: dst, Digest: installDigest, Files: toCoreFiles(files), EntryPath: entryPath(artifact.Inspection)}, nil
}

func verifyDiskManifest(root, digest string) error {
	b, err := os.ReadFile(filepath.Join(root, ".dirextalk-install-v1.json"))
	if err != nil {
		return err
	}
	var m extensionrunner.DiskInstallManifestV1
	if json.Unmarshal(bytes.TrimSuffix(b, []byte{'\n'}), &m) != nil || m.SchemaVersion != "dirextalk.extension.install-manifest/v1" {
		return errors.New("invalid install manifest")
	}
	canonical, _ := json.Marshal(m)
	if !bytes.Equal(b, append(canonical, '\n')) || extensionrunner.ManifestDigest(m.Entries) != digest {
		return errors.New("install manifest digest mismatch")
	}
	return nil
}

func decodeCanonical(data []byte) ([]materialFile, error) {
	if len(data) == 0 || len(data) > maxArtifactBytes {
		return nil, errors.New("invalid artifact size")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var files []materialFile
	if err := dec.Decode(&files); err != nil || files == nil || len(files) == 0 || len(files) > maxArtifactFiles {
		return nil, errors.New("invalid artifact file list")
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return nil, errors.New("non canonical artifact")
	}
	canonical, err := json.Marshal(files)
	if err != nil || !bytes.Equal(canonical, data) {
		return nil, errors.New("non canonical artifact")
	}
	seen := map[string]bool{}
	last := ""
	for _, f := range files {
		if !validPath(f.Path) || seen[f.Path] || (last != "" && last >= f.Path) {
			return nil, errors.New("invalid artifact path")
		}
		if _, err := base64.RawStdEncoding.DecodeString(f.Content); err != nil {
			return nil, errors.New("invalid artifact base64")
		}
		seen[f.Path] = true
		last = f.Path
	}
	return files, nil
}

// PrepareLocal maps the declared executable to the runner's literal `entry`
// ABI and performs the same descriptor-backed admission checks as production.
func (m Materialized) PrepareLocal(i core.Inspection) (*extensionrunner.AdmittedInstall, error) {
	if i.Execution.Stdio == nil || m.Root == "" || i.Execution.Stdio.RelativePath == "" {
		return nil, errors.New("static executable is not declared")
	}
	entry := i.Execution.Stdio.RelativePath
	if entry != "entry" {
		return nil, errors.New("static executable must be literal entry")
	}
	manifest, err := manifestForRoot(m.Root)
	if err != nil {
		return nil, err
	}
	return extensionrunner.OpenAdmittedInstall(m.Root, extensionrunner.ManifestDigest(manifest), manifest)
}

func manifestForRoot(root string) ([]extensionrunner.ManifestEntry, error) {
	var out []extensionrunner.ManifestEntry
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if path == root {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if !validPath(filepath.ToSlash(rel)) {
			return errors.New("invalid installed path")
		}
		if filepath.ToSlash(rel) == ".dirextalk-install-v1.json" {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("special file in install")
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out = append(out, extensionrunner.ManifestEntry{Path: filepath.ToSlash(rel), SHA256: digestArtifact(b), Size: int64(len(b))})
		return nil
	})
	return out, err
}

func validPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\\\x00\r\n") || filepath.Clean(filepath.FromSlash(p)) != filepath.FromSlash(p) {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part {
			return false
		}
	}
	return true
}

func writeImmutable(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func entryPath(i core.Inspection) string {
	if i.Execution.Stdio != nil {
		return i.Execution.Stdio.RelativePath
	}
	if i.Execution.Skill != nil {
		return i.Execution.Skill.RelativePath
	}
	return ""
}

func toCoreFiles(in []materialFile) []MaterializedFile {
	out := make([]MaterializedFile, 0, len(in))
	for _, f := range in {
		b, _ := base64.RawStdEncoding.DecodeString(f.Content)
		out = append(out, MaterializedFile{Path: f.Path, Data: b, Hash: digestArtifact(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func digestArtifact(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
