package execution

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	"github.com/google/uuid"
	"golang.org/x/sys/unix"
)

func TestDecodeCanonicalArtifactRejectsUnsafeForms(t *testing.T) {
	for _, raw := range []string{
		`[{"path":"../x","content":"eA"}]`,
		`[{"path":"a","content":"eA"},{"path":"a","content":"eA"}]`,
		`[{"path":"a","content":"%%%"}]`,
		`[{"path":"a","content":"eA"}] `,
	} {
		if _, err := decodeCanonical([]byte(raw)); err == nil {
			t.Fatalf("accepted unsafe artifact %q", raw)
		}
	}
}

func TestMaterializerValidPathRejectsOnlyUnsafeCharacters(t *testing.T) {
	for _, path := range []string{"manifest.json", "nested/SKILL.md", "nested/deeper/entry"} {
		if !validPath(path) {
			t.Fatalf("valid path rejected: %q", path)
		}
	}
	for _, path := range []string{"nested\\entry", "nested\x00entry", "nested\rentry", "nested\nentry"} {
		if validPath(path) {
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
}

func TestWriteImmutableSealsRequestedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "entry")
	if err := writeImmutable(path, []byte("fixture"), 0500); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0500 || info.Mode().Perm()&0222 != 0 {
		t.Fatalf("immutable mode = %o", info.Mode().Perm())
	}
	if err := writeImmutable(filepath.Join(t.TempDir(), "bad"), []byte("fixture"), 0700); err == nil {
		t.Fatal("writable final mode accepted")
	}
}

func TestCanonicalArtifactFixtureIsExact(t *testing.T) {
	root := t.TempDir()
	content := []materialFile{{Path: "SKILL.md", Content: base64.RawStdEncoding.EncodeToString([]byte("hello"))}}
	b, _ := json.Marshal(content)
	h := sha256.Sum256(b)
	digest := hex.EncodeToString(h[:])
	manifest, _ := json.Marshal([]map[string]string{{"path": "SKILL.md", "digest": digestBytes([]byte("hello"))}})
	mh := sha256.Sum256(manifest)
	candidate := core.Candidate{ID: "skill", Kind: core.KindSkill, Source: core.SourceSkillsSh, Name: "skill", Pin: core.SourcePin{RegistryVersion: "1", RegistrySHA256: strings.Repeat("a", 64)}, Transport: core.TransportSkillStatic}
	inspection := core.Inspection{Candidate: candidate, ContentDigest: digest, ManifestDigest: hex.EncodeToString(mh[:]), NetworkSchemaDigest: digestBytes([]byte("[]")), SecretSchemaDigest: digestBytes([]byte("[]"))}
	inspection.Execution = core.ExecutionDescriptor{Skill: &core.SkillEntry{RelativePath: "SKILL.md", Digest: digestBytes([]byte("hello"))}}
	inspection.ExecutionDigest = digestJSON(inspection.Execution)
	artifact := core.FetchArtifact{Candidate: candidate, Content: b, ContentDigest: digest, ManifestDigest: inspection.ManifestDigest, Inspection: inspection}
	m, err := NewMaterializer(root)
	if err != nil {
		t.Fatal(err)
	}
	one, err := m.Materialize(context.Background(), artifact)
	if err != nil {
		t.Fatal(err)
	}
	two, err := m.Materialize(context.Background(), artifact)
	if err != nil || one.Root != two.Root {
		t.Fatalf("replay=%#v %#v err=%v", one, two, err)
	}
	_ = os.Chmod(one.Root, 0700)
}

func TestRemoveStagedArtifactRejectsSameNameSymlink(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("a", 64)
	cleanupID := uuid.NewString()
	outside := t.TempDir()
	marker := filepath.Join(outside, "keep")
	if err := os.WriteFile(marker, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, digest)); err != nil {
		t.Fatal(err)
	}
	if err := RemoveStagedArtifact(root, digest, cleanupID); !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("same-name symlink cleanup err=%v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("cleanup crossed staging ownership boundary: %v", err)
	}
}

func TestRemoveStagedArtifactRemovesNestedImmutableTree(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("b", 64)
	cleanupID := uuid.NewString()
	target := filepath.Join(root, digest)
	nested := filepath.Join(target, "nested", "deeper")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "SKILL.md"), []byte("# test\n"), 0400); err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{nested, filepath.Dir(nested), target} {
		if err := os.Chmod(directory, 0500); err != nil {
			t.Fatal(err)
		}
	}
	if err := RemoveStagedArtifact(root, digest, cleanupID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("nested staged artifact still exists: %v", err)
	}
}

func TestRemoveStagedArtifactPartialDeleteRetriesOwnedTombstone(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("d", 64)
	cleanupID := uuid.NewString()
	target := filepath.Join(root, digest)
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"one", "two"} {
		if err := os.WriteFile(filepath.Join(target, name), []byte(name), 0400); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(target, 0500); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := removeStagedArtifact(root, digest, cleanupID, &stagedRemovalHooks{afterEntryRemove: func() error {
		calls++
		if calls == 1 {
			return unix.EIO
		}
		return nil
	}})
	if !errors.Is(err, unix.EIO) || errors.Is(err, core.ErrInvalid) {
		t.Fatalf("partial cleanup syscall classification=%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, stagedRemovalName(cleanupID))); err != nil {
		t.Fatalf("owned tombstone was lost: %v", err)
	}
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partially deleted tombstone restored as authoritative digest: %v", err)
	}
	if err := RemoveStagedArtifact(root, digest, cleanupID); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, stagedRemovedName(cleanupID))); err != nil {
		t.Fatalf("retry did not persist completion marker: %v", err)
	}
}

func TestRemoveStagedArtifactPreservesSameNameReplacement(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("e", 64)
	cleanupID := uuid.NewString()
	target := filepath.Join(root, digest)
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "old"), []byte("old"), 0400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0500); err != nil {
		t.Fatal(err)
	}
	err := removeStagedArtifact(root, digest, cleanupID, &stagedRemovalHooks{afterTopRename: func(rootFD int, digest, _ string) error {
		if err := unix.Mkdirat(rootFD, digest, 0700); err != nil {
			return err
		}
		fd, err := unix.Openat(rootFD, digest+"/replacement", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0600)
		if err != nil {
			return err
		}
		_, writeErr := unix.Write(fd, []byte("replacement"))
		closeErr := unix.Close(fd)
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}})
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "replacement")
	if got, err := os.ReadFile(marker); err != nil || string(got) != "replacement" {
		t.Fatalf("same-name replacement changed: %q err=%v", got, err)
	}
	if err := RemoveStagedArtifact(root, digest, cleanupID); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "replacement" {
		t.Fatalf("stable retry crossed into replacement: %q err=%v", got, err)
	}
}

func TestRemoveStagedArtifactRenameCollisionIsIdentityMismatch(t *testing.T) {
	root := t.TempDir()
	digest := strings.Repeat("f", 64)
	cleanupID := uuid.NewString()
	target := filepath.Join(root, digest)
	if err := os.Mkdir(target, 0500); err != nil {
		t.Fatal(err)
	}
	err := removeStagedArtifact(root, digest, cleanupID, &stagedRemovalHooks{beforeTopRename: func(rootFD int, _, tombstone string) error {
		return unix.Mkdirat(rootFD, tombstone, 0500)
	}})
	if !errors.Is(err, core.ErrInvalid) {
		t.Fatalf("rename identity collision error=%v", err)
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("rename collision moved authoritative target: %v", err)
	}
}

func TestRemoveStagedArtifactPreservesInfrastructureErrors(t *testing.T) {
	missingRoot := filepath.Join(t.TempDir(), "missing")
	err := RemoveStagedArtifact(missingRoot, strings.Repeat("a", 64), uuid.NewString())
	if !errors.Is(err, unix.ENOENT) || errors.Is(err, core.ErrInvalid) {
		t.Fatalf("missing-root syscall classification=%v", err)
	}
}

type publicationFake struct {
	called int
	digest string
}

type productionSourceAdapter struct {
	inspection core.Inspection
	artifact   core.FetchArtifact
}

func (a productionSourceAdapter) Search(context.Context, core.SearchQuery) (core.Page, error) {
	return core.Page{}, nil
}
func (a productionSourceAdapter) Inspect(context.Context, core.InspectRequest) (core.Inspection, error) {
	return a.inspection, nil
}
func (a productionSourceAdapter) Fetch(context.Context, core.Candidate) (core.FetchArtifact, error) {
	return a.artifact, nil
}

type productionLifecycleCoordinator struct{}

func (productionLifecycleCoordinator) CreateTask(context.Context, core.ExecuteRequest) (string, error) {
	return uuid.NewString(), nil
}

type productionRepository struct{ *core.MemoryRepository }

func (productionRepository) Search(context.Context, core.SearchQuery) (core.Page, error) {
	return core.Page{}, nil
}

type failOnceProductionRepository struct {
	productionRepository
	failure error
}

func (r *failOnceProductionRepository) CreateMutation(ctx context.Context, mutation core.Mutation) (core.MutationResult, error) {
	if r.failure != nil {
		err := r.failure
		r.failure = nil
		return core.MutationResult{}, err
	}
	return r.productionRepository.CreateMutation(ctx, mutation)
}

type productionToolRuntime struct{}

func (productionToolRuntime) ListTools(context.Context, core.Installation, core.VersionRecord) ([]core.Tool, error) {
	return nil, nil
}
func (productionToolRuntime) CallTool(context.Context, core.Installation, core.VersionRecord, string, []byte) (string, error) {
	return "", nil
}

func TestProductionServiceCompensationCrashMarkerReclaimDoesNotCrossRetryGeneration(t *testing.T) {
	body := []byte("# compensation recovery\n")
	files := []materialFile{{Path: "SKILL.md", Content: base64.RawStdEncoding.EncodeToString(body)}}
	canonical, err := json.Marshal(files)
	if err != nil {
		t.Fatal(err)
	}
	contentDigest := digestBytes(canonical)
	entryDigest := digestBytes(body)
	candidate := core.Candidate{ID: "example/recovery", Kind: core.KindSkill, Source: core.SourceGitHub, Name: "example/recovery", Pin: core.SourcePin{GitCommit: strings.Repeat("a", 40), GitSHA256: contentDigest}, Transport: core.TransportSkillStatic}
	execution := core.ExecutionDescriptor{Skill: &core.SkillEntry{RelativePath: "SKILL.md", Digest: entryDigest}}
	inspection := core.Inspection{Candidate: candidate, ContentDigest: contentDigest, ManifestDigest: digestJSON([]map[string]string{{"path": "SKILL.md", "digest": entryDigest}}), ExecutionDigest: digestJSON(execution), NetworkSchemaDigest: digestJSON([]core.NetworkGrant(nil)), SecretSchemaDigest: digestJSON([]core.SecretGrantDescriptor{}), Execution: execution}
	artifact := core.FetchArtifact{Candidate: candidate, Content: canonical, ContentDigest: contentDigest, ManifestDigest: inspection.ManifestDigest, Inspection: inspection}
	registry := core.NewRegistry()
	if err := registry.Register(candidate.Source, productionSourceAdapter{inspection: inspection, artifact: artifact}); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	materializer, err := NewMaterializer(root)
	if err != nil {
		t.Fatal(err)
	}
	var failedCleanupToken string
	removeCalls := 0
	artifacts := ArtifactStoreAdapter{Materializer: materializer, RemoveFunc: func(_ context.Context, digest, cleanupToken string) error {
		removeCalls++
		if removeCalls == 1 {
			failedCleanupToken = cleanupToken
			return removeStagedArtifact(root, digest, cleanupToken, &stagedRemovalHooks{afterEntryRemove: func() error { return unix.EIO }})
		}
		return RemoveStagedArtifact(root, digest, cleanupToken)
	}}
	repository := &failOnceProductionRepository{productionRepository: productionRepository{MemoryRepository: core.NewMemoryRepository()}, failure: errors.New("injected repository failure")}
	service, err := core.NewProductionService(repository, registry, productionLifecycleCoordinator{}, artifacts, core.NewFingerprintSecretStore(), productionToolRuntime{})
	if err != nil {
		t.Fatal(err)
	}
	mutation := core.Mutation{IdempotencyKey: uuid.NewString(), Candidate: candidate, Inspection: inspection}
	if _, err := service.RequestInstall(context.Background(), mutation); err == nil {
		t.Fatal("repository failure was not returned")
	}
	if failedCleanupToken == "" {
		t.Fatal("compensation cleanup token was not retained")
	}
	if _, err := os.Stat(filepath.Join(root, stagedRemovalName(failedCleanupToken))); err != nil {
		t.Fatalf("EIO compensation tombstone missing: %v", err)
	}
	result, err := service.RequestInstall(context.Background(), mutation)
	if err != nil {
		t.Fatalf("same-idempotency retry failed: %v", err)
	}
	newGeneration := filepath.Join(root, result.Installation.Versions[0].ArtifactDigest, ".dirextalk-install-v1.json")
	if err := ResumeStagedArtifactRemoval(root, failedCleanupToken); err != nil {
		t.Fatalf("orphan compensation reclaim failed: %v", err)
	}
	if err := RemoveStagedArtifactMarker(root, failedCleanupToken); err != nil {
		t.Fatalf("orphan completion marker GC failed: %v", err)
	}
	if _, err := os.Stat(newGeneration); err != nil {
		t.Fatalf("old compensation reclaim crossed into retry generation: %v", err)
	}
	if err := os.Chmod(filepath.Dir(newGeneration), 0700); err != nil {
		t.Fatal(err)
	}
}

func TestProductionArtifactStoreAdapterPreservesDigestsAndCleanupTokenABA(t *testing.T) {
	tests := []struct {
		name      string
		candidate func(string) core.Candidate
		execution func(string) core.ExecutionDescriptor
		files     func() []materialFile
		network   func(string) []core.NetworkGrant
	}{
		{
			name: "mcp",
			candidate: func(contentDigest string) core.Candidate {
				return core.Candidate{ID: "calculator@1.0.0", Kind: core.KindMCP, Source: core.SourceOfficialRegistry, Name: "calculator", Pin: core.SourcePin{RegistryVersion: "1.0.0", RegistrySHA256: contentDigest}, Transport: core.TransportStreamableHTTP}
			},
			execution: func(string) core.ExecutionDescriptor {
				return core.ExecutionDescriptor{Remote: &core.RemoteEndpoint{URL: "https://calculator.example/mcp"}}
			},
			files: func() []materialFile {
				return []materialFile{{Path: "manifest.json", Content: base64.RawStdEncoding.EncodeToString([]byte(`{"name":"calculator"}`))}}
			},
			network: func(digest string) []core.NetworkGrant {
				return []core.NetworkGrant{{Scheme: "https", Host: "calculator.example", Port: 443, PathPrefix: "/mcp", Digest: digest}}
			},
		},
		{
			name: "skill",
			candidate: func(contentDigest string) core.Candidate {
				return core.Candidate{ID: "example/skill", Kind: core.KindSkill, Source: core.SourceGitHub, Name: "example/skill", Pin: core.SourcePin{GitCommit: strings.Repeat("a", 40), GitSHA256: contentDigest}, Transport: core.TransportSkillStatic}
			},
			execution: func(entryDigest string) core.ExecutionDescriptor {
				return core.ExecutionDescriptor{Skill: &core.SkillEntry{RelativePath: "SKILL.md", Digest: entryDigest}}
			},
			files: func() []materialFile {
				return []materialFile{{Path: "SKILL.md", Content: base64.RawStdEncoding.EncodeToString([]byte("# Acceptance skill\n"))}}
			},
			network: func(string) []core.NetworkGrant { return nil },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			files := tt.files()
			canonical, err := json.Marshal(files)
			if err != nil {
				t.Fatal(err)
			}
			contentDigest := digestBytes(canonical)
			entry, err := base64.RawStdEncoding.DecodeString(files[0].Content)
			if err != nil {
				t.Fatal(err)
			}
			entryDigest := digestBytes(entry)
			candidate := tt.candidate(contentDigest)
			manifestDigest := digestJSON([]map[string]string{{"path": files[0].Path, "digest": entryDigest}})
			execution := tt.execution(entryDigest)
			inspection := core.Inspection{
				Candidate:           candidate,
				ContentDigest:       contentDigest,
				ManifestDigest:      manifestDigest,
				ExecutionDigest:     digestJSON(execution),
				NetworkSchemaDigest: digestJSON(tt.network(contentDigest)),
				SecretSchemaDigest:  digestJSON([]core.SecretGrantDescriptor{}),
				Execution:           execution,
				NetworkGrants:       tt.network(contentDigest),
			}
			artifact := core.FetchArtifact{Candidate: candidate, Content: canonical, ContentDigest: contentDigest, ManifestDigest: manifestDigest, Inspection: inspection}
			registry := core.NewRegistry()
			if err := registry.Register(candidate.Source, productionSourceAdapter{inspection: inspection, artifact: artifact}); err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			materializer, err := NewMaterializer(root)
			if err != nil {
				t.Fatal(err)
			}
			artifacts := ArtifactStoreAdapter{Materializer: materializer, RemoveFunc: func(_ context.Context, digest, cleanupID string) error {
				return RemoveStagedArtifact(root, digest, cleanupID)
			}}
			repository := productionRepository{MemoryRepository: core.NewMemoryRepository()}
			service, err := core.NewProductionService(repository, registry, productionLifecycleCoordinator{}, artifacts, core.NewFingerprintSecretStore(), productionToolRuntime{})
			if err != nil {
				t.Fatal(err)
			}
			result, err := service.RequestInstall(context.Background(), core.Mutation{IdempotencyKey: uuid.NewString(), Candidate: candidate, Inspection: inspection})
			if err != nil {
				t.Fatal(err)
			}
			installation, err := repository.Get(context.Background(), result.Installation.ID)
			if err != nil || len(installation.Versions) != 1 {
				t.Fatalf("installation=%#v err=%v", installation, err)
			}
			version := installation.Versions[0]
			if version.ContentDigest != contentDigest || version.ArtifactDigest == contentDigest || version.ArtifactPath != version.ArtifactDigest {
				t.Fatalf("digest identities collapsed: content=%q path=%q artifact=%q", version.ContentDigest, version.ArtifactPath, version.ArtifactDigest)
			}
			if _, err := os.Stat(filepath.Join(root, version.ArtifactPath, ".dirextalk-install-v1.json")); err != nil {
				t.Fatalf("staged artifact missing: %v", err)
			}
			cleanupID := uuid.NewString()
			if err := artifacts.Remove(context.Background(), core.ArtifactReceipt{RelativePath: version.ArtifactPath, ContentDigest: version.ContentDigest, ArtifactDigest: version.ArtifactDigest, CleanupToken: cleanupID}); err != nil {
				t.Fatalf("staged artifact cleanup failed: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, stagedRemovedName(cleanupID))); err != nil {
				t.Fatalf("cleanup completion marker missing: %v", err)
			}
			rematerialized, err := materializer.Materialize(context.Background(), artifact)
			if err != nil {
				t.Fatalf("same-digest rematerialization failed: %v", err)
			}
			if rematerialized.Digest != version.ArtifactDigest {
				t.Fatalf("same-digest generation changed: %q", rematerialized.Digest)
			}
			if _, err := os.Stat(filepath.Join(root, stagedRemovedName(cleanupID))); err != nil {
				t.Fatalf("new generation changed old completion marker: %v", err)
			}
			if err := artifacts.Remove(context.Background(), core.ArtifactReceipt{RelativePath: version.ArtifactPath, ContentDigest: version.ContentDigest, ArtifactDigest: version.ArtifactDigest, CleanupToken: cleanupID}); err != nil {
				t.Fatalf("old cleanup retry failed: %v", err)
			}
			if _, err := os.Stat(filepath.Join(root, version.ArtifactDigest, ".dirextalk-install-v1.json")); err != nil {
				t.Fatalf("old cleanup retry crossed into new generation: %v", err)
			}
			if err := artifacts.Remove(context.Background(), core.ArtifactReceipt{RelativePath: version.ArtifactPath, ContentDigest: version.ContentDigest, ArtifactDigest: version.ArtifactDigest, CleanupToken: uuid.NewString()}); err != nil {
				t.Fatalf("rematerialized cleanup failed: %v", err)
			}
		})
	}
}

func (p *publicationFake) Publish(_ context.Context, entries []extensionrunner.ManifestEntry, files []extensionrunner.PublishFile) (extensionrunner.PublishResponse, error) {
	p.called++
	p.digest = extensionrunner.ManifestDigest(entries)
	if len(entries) != len(files) {
		return extensionrunner.PublishResponse{}, errors.New("file count mismatch")
	}
	return extensionrunner.PublishResponse{Digest: p.digest}, nil
}

func TestStagedLifecyclePromoterPublishesAfterConfirmation(t *testing.T) {
	root := t.TempDir()
	body := []byte("instructions")
	content := []materialFile{{Path: "runner.md", Content: base64.RawStdEncoding.EncodeToString(body)}}
	canonical, _ := json.Marshal(content)
	contentDigest := digestBytes(canonical)
	manifestDigest := digestJSON([]map[string]string{{"path": "runner.md", "digest": digestBytes(body)}})
	candidate := core.Candidate{ID: "skill", Kind: core.KindSkill, Source: core.SourceSkillsSh, Name: "skill", Pin: core.SourcePin{RegistryVersion: "1", RegistrySHA256: strings.Repeat("a", 64)}, Transport: core.TransportSkillStatic}
	inspection := core.Inspection{Candidate: candidate, ContentDigest: contentDigest, ManifestDigest: manifestDigest, NetworkSchemaDigest: digestBytes([]byte("[]")), SecretSchemaDigest: digestBytes([]byte("[]")), Execution: core.ExecutionDescriptor{Skill: &core.SkillEntry{RelativePath: "runner.md", Digest: digestBytes(body)}}}
	inspection.ExecutionDigest = digestJSON(inspection.Execution)
	m, err := NewMaterializer(root)
	if err != nil {
		t.Fatal(err)
	}
	materialized, err := m.Materialize(context.Background(), core.FetchArtifact{Candidate: candidate, Content: canonical, ContentDigest: contentDigest, ManifestDigest: manifestDigest, Inspection: inspection})
	if err != nil {
		t.Fatal(err)
	}
	publisher := &publicationFake{}
	promoter := StagedLifecyclePromoter{Root: root, Publisher: publisher}
	version := core.VersionRecord{ArtifactPath: materialized.Digest, ArtifactDigest: materialized.Digest}
	if err = promoter.Promote(context.Background(), version); err != nil || publisher.called != 1 || publisher.digest != materialized.Digest {
		t.Fatalf("promote err=%v calls=%d digest=%q", err, publisher.called, publisher.digest)
	}
	_ = os.Chmod(materialized.Root, 0700)
}

func TestSkillExecutorPinnedDigestAndBound(t *testing.T) {
	root := t.TempDir()
	body := []byte("instructions")
	if err := os.WriteFile(filepath.Join(root, "SKILL.md"), body, 0600); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(body)
	e := SkillExecutor{Root: root}
	r, err := e.Execute(context.Background(), core.SkillEntry{RelativePath: "SKILL.md", Digest: hex.EncodeToString(h[:])})
	if err != nil || r.Text != "instructions" {
		t.Fatalf("result=%#v err=%v", r, err)
	}
	if _, err = e.Execute(context.Background(), core.SkillEntry{RelativePath: "SKILL.md", Digest: strings.Repeat("0", 64)}); err == nil {
		t.Fatal("digest mismatch accepted")
	}
}

type fakeCoord struct {
	resolved       Invocation
	complete, fail int
	failCode       string
	failSummary    string
	err            error
}

type capturingLocalRunner struct {
	request         extensionrunner.RequestV2
	calls           int
	validateRequest bool
}

type fixedOutputLocalRunner struct{ stdout []byte }

func (r fixedOutputLocalRunner) RunV2(_ context.Context, request extensionrunner.RequestV2, _ []*os.File) (extensionrunner.StatusV1, error) {
	return extensionrunner.StatusV1{RunID: request.RunID, Phase: extensionrunner.PhaseTombstone, Status: "succeeded", Stdout: append([]byte(nil), r.stdout...)}, nil
}

type mcpCallRunner struct {
	request extensionrunner.RequestV2
	stdin   []byte
	stdout  []byte
}

func (r *mcpCallRunner) RunV2(_ context.Context, request extensionrunner.RequestV2, files []*os.File) (extensionrunner.StatusV1, error) {
	r.request = request
	if request.Stdin != nil {
		if request.Stdin.Index < 0 || request.Stdin.Index >= len(files) {
			return extensionrunner.StatusV1{}, extensionrunner.ErrInvalid
		}
		r.stdin = make([]byte, request.Stdin.Size)
		if _, err := files[request.Stdin.Index].ReadAt(r.stdin, 0); err != nil {
			return extensionrunner.StatusV1{}, err
		}
	}
	return extensionrunner.StatusV1{RunID: request.RunID, Phase: extensionrunner.PhaseTombstone, Status: "succeeded", Stdout: append([]byte(nil), r.stdout...)}, nil
}

func TestLocalExecutorListToolsCanonicalizesExactInputSchema(t *testing.T) {
	digest := strings.Repeat("a", 64)
	stdout := []byte(`{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"local_task","description":"bounded local task","inputSchema":{"z":{"type":"string"},"a":{"type":"integer"}}}]}}`)
	executor := &LocalExecutor{Runner: fixedOutputLocalRunner{stdout: stdout}}
	tools, err := executor.ListTools(context.Background(), LocalInvocation{
		TaskID: uuid.NewString(), TaskFence: uuid.NewString(), InstallationID: uuid.NewString(), VersionID: uuid.NewString(),
		InstallDigest: digest, ContentDigest: digest, ArtifactDigest: digest, EntryPath: "server", Workspace: t.TempDir(),
		Timeout: time.Minute, Limits: LocalSandboxLimitsV2(),
	})
	if err != nil || len(tools) != 1 {
		t.Fatalf("tools=%+v err=%v", tools, err)
	}
	want := `{"a":{"type":"integer"},"z":{"type":"string"}}`
	if string(tools[0].InputSchema) != want || tools[0].InputSchemaDigest != digestBytes([]byte(want)) {
		t.Fatalf("tool=%+v", tools[0])
	}
}

func (r *capturingLocalRunner) RunV2(_ context.Context, request extensionrunner.RequestV2, _ []*os.File) (extensionrunner.StatusV1, error) {
	r.calls++
	r.request = request
	if r.validateRequest {
		if err := extensionrunner.ValidateRequestV2(request); err != nil {
			return extensionrunner.StatusV1{}, err
		}
	}
	return extensionrunner.StatusV1{RunID: request.RunID, Phase: extensionrunner.PhaseTombstone, Status: "succeeded", Stdout: []byte("ok")}, nil
}

func (f *fakeCoord) Resolve(context.Context, coretask.Task) (Invocation, error) {
	if f.err != nil {
		return Invocation{}, f.err
	}
	return f.resolved, nil
}
func (f *fakeCoord) Complete(context.Context, coretask.Task, coretask.Result) (bool, error) {
	f.complete++
	return true, nil
}
func (f *fakeCoord) Fail(_ context.Context, _ coretask.Task, code, summary string) (bool, error) {
	f.fail++
	f.failCode = code
	f.failSummary = summary
	return true, nil
}

type fixedStatusLocalRunner struct {
	status extensionrunner.StatusV1
	err    error
}

func (r fixedStatusLocalRunner) RunV2(_ context.Context, request extensionrunner.RequestV2, _ []*os.File) (extensionrunner.StatusV1, error) {
	status := r.status
	status.RunID = request.RunID
	return status, r.err
}

func validLocalResourceInvocation(t *testing.T) LocalInvocation {
	t.Helper()
	digest := strings.Repeat("a", 64)
	return LocalInvocation{
		TaskID: uuid.NewString(), TaskFence: uuid.NewString(), InstallationID: uuid.NewString(), VersionID: uuid.NewString(),
		InstallDigest: digest, ContentDigest: digest, ArtifactDigest: digest, EntryPath: "entry", Workspace: t.TempDir(),
		Timeout: time.Minute, Limits: LocalSandboxLimitsV2(),
	}
}

func TestLocalExecutorClassifiesOnlyKnownTerminalResourceFailures(t *testing.T) {
	tests := []struct {
		name   string
		status extensionrunner.StatusV1
		runErr error
		want   error
	}{
		{name: "capacity", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorUnavailableBackend, Status: "capacity"}, want: ErrLocalResourceBusy},
		{name: "request limits", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorInvalidRequest, Status: "limits"}, want: ErrLocalResourceExhausted},
		{name: "wall timeout", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorTimeout}, want: ErrLocalResourceExhausted},
		{name: "cpu limit", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorExecution, Status: "cpu_limit"}, want: ErrLocalResourceExhausted},
		{name: "output limit", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorExecution, Status: "output_limit"}, want: ErrLocalResourceExhausted},
		{name: "transport remains unknown", runErr: context.DeadlineExceeded},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			executor := &LocalExecutor{Runner: fixedStatusLocalRunner{status: test.status, err: test.runErr}}
			status, err := executor.Execute(context.Background(), validLocalResourceInvocation(t))
			if test.want != nil {
				if !errors.Is(err, test.want) || status.Phase != extensionrunner.PhaseFailed {
					t.Fatalf("status=%+v err=%v want=%v", status, err, test.want)
				}
				return
			}
			if !errors.Is(err, test.runErr) || !errors.Is(err, ErrLocalOutcomeUncertain) || errors.Is(err, ErrLocalResourceBusy) || errors.Is(err, ErrLocalResourceExhausted) {
				t.Fatalf("status=%+v err=%v", status, err)
			}
		})
	}
}

func TestHandlerPublishesSafeLocalResourceFailures(t *testing.T) {
	tests := []struct {
		name        string
		status      extensionrunner.StatusV1
		wantErr     error
		wantCode    string
		wantSummary string
	}{
		{name: "busy", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorUnavailableBackend, Status: "capacity", Stderr: []byte("protected detail")}, wantErr: ErrLocalResourceBusy, wantCode: LocalResourceBusyCode, wantSummary: LocalResourceBusySummary},
		{name: "request limits", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorInvalidRequest, Status: "limits", Stderr: []byte("protected detail")}, wantErr: ErrLocalResourceExhausted, wantCode: LocalResourceExhaustedCode, wantSummary: LocalResourceExhaustedSummary},
		{name: "exhausted", status: extensionrunner.StatusV1{Phase: extensionrunner.PhaseFailed, Error: extensionrunner.ErrorExecution, Status: "output_limit", Stderr: []byte("protected detail")}, wantErr: ErrLocalResourceExhausted, wantCode: LocalResourceExhaustedCode, wantSummary: LocalResourceExhaustedSummary},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			invocation := validLocalResourceInvocation(t)
			invocation.Tool = "write_html"
			invocation.Input = json.RawMessage(`{"content":"ok"}`)
			coord := &fakeCoord{resolved: Invocation{Kind: core.KindMCP, Local: &invocation}}
			local := &LocalExecutor{Runner: fixedStatusLocalRunner{status: test.status}}
			out := (&Handler{Coordinator: coord, Local: local}).Handle(context.Background(), coretask.Task{ID: invocation.TaskID})
			if !errors.Is(out.Err, test.wantErr) || !out.TerminalOwned || coord.complete != 0 || coord.fail != 1 || coord.failCode != test.wantCode || coord.failSummary != test.wantSummary {
				t.Fatalf("out=%+v complete=%d fail=%d code=%q summary=%q", out, coord.complete, coord.fail, coord.failCode, coord.failSummary)
			}
			if strings.Contains(coord.failSummary, "protected detail") {
				t.Fatalf("runner diagnostics leaked in summary %q", coord.failSummary)
			}
		})
	}
}

func TestHandlerPersistsUnknownLocalTransportOutcomeForReconciliation(t *testing.T) {
	invocation := validLocalResourceInvocation(t)
	invocation.Tool = "write_html"
	invocation.Input = json.RawMessage(`{"content":"ok"}`)
	coord := &fakeCoord{resolved: Invocation{Kind: core.KindMCP, Local: &invocation}}
	transportErr := errors.New("runner transport closed: protected detail")
	out := (&Handler{Coordinator: coord, Local: &LocalExecutor{Runner: fixedStatusLocalRunner{err: transportErr}}}).Handle(context.Background(), coretask.Task{ID: invocation.TaskID})
	if !errors.Is(out.Err, ErrLocalOutcomeUncertain) || !errors.Is(out.Err, transportErr) || !out.TerminalOwned || coord.complete != 0 || coord.fail != 1 || coord.failCode != "extension_execution_uncertain" || coord.failSummary != "execution outcome is uncertain; reconciliation required" {
		t.Fatalf("out=%+v complete=%d fail=%d code=%q summary=%q", out, coord.complete, coord.fail, coord.failCode, coord.failSummary)
	}
	if strings.Contains(coord.failSummary, "protected detail") {
		t.Fatalf("transport diagnostic leaked in summary %q", coord.failSummary)
	}
}

func TestHandlerTerminalOwnershipAndReplay(t *testing.T) {
	id := uuid.NewString()
	now := time.Now().UTC()
	task := coretask.Task{ID: id, Status: coretask.StatusRunning, Revision: 1, Attempt: 1, LeaseEpoch: 1, CreatedAt: now, UpdatedAt: now, AvailableAt: now, Spec: coretask.TaskSpec{Goal: "x", ModelProfileID: "p", IdempotencyKey: uuid.NewString(), Kind: coretask.TaskKindExtension, Payload: coretask.TaskPayload{Extension: &coretask.ExtensionTaskPayload{Operation: coretask.ExtensionOperationExecuteSkill, InstallationID: uuid.NewString(), Version: "v", Digest: strings.Repeat("a", 64)}}}, Lease: &coretask.Lease{TaskID: id, Attempt: 1, Epoch: 1, Holder: "h", ExpiresAt: now.Add(time.Hour)}}
	f := &fakeCoord{resolved: Invocation{Skill: &SkillInvocation{Root: t.TempDir(), Entry: core.SkillEntry{RelativePath: "missing", Digest: strings.Repeat("0", 64)}}}}
	out := (&Handler{Coordinator: f}).Handle(context.Background(), task)
	if !out.TerminalOwned || f.fail != 1 || f.complete != 0 {
		t.Fatalf("out=%#v complete=%d fail=%d", out, f.complete, f.fail)
	}
	f.err = ErrStaleFence
	out = (&Handler{Coordinator: f}).Handle(context.Background(), task)
	if !out.TerminalOwned || !errors.Is(out.Err, ErrStaleFence) {
		t.Fatalf("stale fence outcome=%#v", out)
	}
}

func TestLocalMCPHandlerSendsExactToolCallAndRequiresResult(t *testing.T) {
	taskID, installationID, versionID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	digest := strings.Repeat("a", 64)
	input, err := json.Marshal(map[string]any{"content": "<h1>Hello from Dirextalk</h1>"})
	if err != nil {
		t.Fatal(err)
	}
	response := []byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"<h1>Hello from Dirextalk</h1>"}],"structuredContent":{"path":"index.html","size":29,"sha256":"b0012fd52e5edc0ce0ac66a4e4020d45a6a5226229276c961744d0d826776b84"}}}`)
	makeInvocation := func() Invocation {
		return Invocation{Kind: core.KindMCP, Local: &LocalInvocation{
			TaskID: taskID, TaskFence: uuid.NewString(), InstallationID: installationID, VersionID: versionID,
			InstallDigest: digest, ContentDigest: digest, ArtifactDigest: digest, EntryPath: "entry",
			Tool: "write_html", Input: append(json.RawMessage(nil), input...), Workspace: t.TempDir(),
			Timeout: time.Minute, Limits: LocalSandboxLimitsV2(),
		}}
	}

	t.Run("success", func(t *testing.T) {
		runner := &mcpCallRunner{stdout: response}
		coord := &fakeCoord{resolved: makeInvocation()}
		out := (&Handler{Coordinator: coord, Local: &LocalExecutor{Runner: runner}}).Handle(context.Background(), coretask.Task{ID: taskID})
		var envelope struct {
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal(response, &envelope) != nil {
			t.Fatal("invalid response fixture")
		}
		if out.Err != nil || !out.TerminalOwned || coord.complete != 1 || coord.fail != 0 || out.Result.Summary != "local MCP tool result" || string(out.Result.JSON) != string(envelope.Result) {
			t.Fatalf("out=%#v err=%v complete=%d fail=%d result=%s stdin=%q request=%+v", out, out.Err, coord.complete, coord.fail, out.Result.JSON, runner.stdin, runner.request)
		}
		lines := strings.Split(strings.TrimSpace(string(runner.stdin)), "\n")
		if len(lines) != 3 {
			t.Fatalf("MCP request lines=%d stdin=%q", len(lines), runner.stdin)
		}
		var initialize, initialized, call map[string]any
		if json.Unmarshal([]byte(lines[0]), &initialize) != nil || json.Unmarshal([]byte(lines[1]), &initialized) != nil || json.Unmarshal([]byte(lines[2]), &call) != nil {
			t.Fatal("MCP request is not valid NDJSON")
		}
		params, _ := call["params"].(map[string]any)
		if initialize["method"] != "initialize" || initialize["id"] != float64(1) || initialized["method"] != "notifications/initialized" ||
			call["method"] != "tools/call" || call["id"] != float64(2) || params["name"] != "write_html" ||
			!reflect.DeepEqual(params["arguments"], map[string]any{"content": "<h1>Hello from Dirextalk</h1>"}) {
			t.Fatalf("unexpected MCP protocol: initialize=%#v initialized=%#v call=%#v", initialize, initialized, call)
		}
	})

	t.Run("empty response fails", func(t *testing.T) {
		runner := &mcpCallRunner{}
		coord := &fakeCoord{resolved: makeInvocation()}
		out := (&Handler{Coordinator: coord, Local: &LocalExecutor{Runner: runner}}).Handle(context.Background(), coretask.Task{ID: taskID})
		if out.Err == nil || !out.TerminalOwned || coord.complete != 0 || coord.fail != 1 {
			t.Fatalf("out=%#v complete=%d fail=%d", out, coord.complete, coord.fail)
		}
	})

	t.Run("JSON-RPC error fails", func(t *testing.T) {
		runner := &mcpCallRunner{stdout: []byte(`{"jsonrpc":"2.0","id":2,"error":{"code":-32603,"message":"tool failed"}}`)}
		coord := &fakeCoord{resolved: makeInvocation()}
		out := (&Handler{Coordinator: coord, Local: &LocalExecutor{Runner: runner}}).Handle(context.Background(), coretask.Task{ID: taskID})
		if out.Err == nil || !out.TerminalOwned || coord.complete != 0 || coord.fail != 1 {
			t.Fatalf("out=%#v complete=%d fail=%d", out, coord.complete, coord.fail)
		}
	})

	t.Run("result without content fails", func(t *testing.T) {
		runner := &mcpCallRunner{stdout: []byte(`{"jsonrpc":"2.0","id":2,"result":{}}`)}
		coord := &fakeCoord{resolved: makeInvocation()}
		out := (&Handler{Coordinator: coord, Local: &LocalExecutor{Runner: runner}}).Handle(context.Background(), coretask.Task{ID: taskID})
		if out.Err == nil || !out.TerminalOwned || coord.complete != 0 || coord.fail != 1 {
			t.Fatalf("out=%#v complete=%d fail=%d", out, coord.complete, coord.fail)
		}
	})

	t.Run("tool error completes with stable summary", func(t *testing.T) {
		response := []byte(`{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"tool failed"}],"isError":true}}`)
		runner := &mcpCallRunner{stdout: response}
		coord := &fakeCoord{resolved: makeInvocation()}
		out := (&Handler{Coordinator: coord, Local: &LocalExecutor{Runner: runner}}).Handle(context.Background(), coretask.Task{ID: taskID})
		var envelope struct {
			Result json.RawMessage `json:"result"`
		}
		if json.Unmarshal(response, &envelope) != nil {
			t.Fatal("invalid response fixture")
		}
		if out.Err != nil || !out.TerminalOwned || coord.complete != 1 || coord.fail != 0 || out.Result.Summary != "local MCP tool returned an error" || string(out.Result.JSON) != string(envelope.Result) {
			t.Fatalf("out=%#v complete=%d fail=%d", out, coord.complete, coord.fail)
		}
	})
}

func TestExecutableSkillHandlerBindsExactLocalSandboxLimits(t *testing.T) {
	taskID := uuid.NewString()
	installationID := uuid.NewString()
	versionID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	runner := &capturingLocalRunner{validateRequest: true}
	coord := &fakeCoord{resolved: Invocation{Skill: &SkillInvocation{
		Entry:          core.SkillEntry{RelativePath: "entry", Digest: digest, Executable: true, Argv: []string{"entry"}},
		InstallDigest:  digest,
		TaskID:         taskID,
		TaskFence:      uuid.NewString(),
		InstallationID: installationID,
		VersionID:      versionID,
		ContentDigest:  digest,
		ArtifactDigest: digest,
		Workspace:      t.TempDir(),
		Limits:         LocalSandboxLimitsV2(),
	}}}
	out := (&Handler{Coordinator: coord, Local: &LocalExecutor{Runner: runner}}).Handle(context.Background(), coretask.Task{ID: taskID})
	if out.Err != nil || !out.TerminalOwned || coord.complete != 1 || coord.fail != 0 {
		t.Fatalf("out=%#v err=%v complete=%d fail=%d calls=%d", out, out.Err, coord.complete, coord.fail, runner.calls)
	}
	if runner.calls != 1 || runner.request.Limits != LocalSandboxLimitsV2() {
		t.Fatalf("calls=%d limits=%+v want=%+v", runner.calls, runner.request.Limits, LocalSandboxLimitsV2())
	}
}

func TestExecutableSkillHandlerDoesNotRepairMissingLimits(t *testing.T) {
	taskID := uuid.NewString()
	digest := strings.Repeat("a", 64)
	runner := &capturingLocalRunner{validateRequest: true}
	coord := &fakeCoord{resolved: Invocation{Skill: &SkillInvocation{
		Entry:          core.SkillEntry{RelativePath: "entry", Digest: digest, Executable: true, Argv: []string{"entry"}},
		InstallDigest:  digest,
		TaskID:         taskID,
		TaskFence:      uuid.NewString(),
		InstallationID: uuid.NewString(),
		VersionID:      uuid.NewString(),
		ContentDigest:  digest,
		ArtifactDigest: digest,
		Workspace:      t.TempDir(),
	}}}
	out := (&Handler{Coordinator: coord, Local: &LocalExecutor{Runner: runner}}).Handle(context.Background(), coretask.Task{ID: taskID})
	if out.Err == nil || !out.TerminalOwned || coord.complete != 0 || coord.fail != 1 || runner.calls != 0 {
		t.Fatalf("out=%#v complete=%d fail=%d calls=%d", out, coord.complete, coord.fail, runner.calls)
	}
}

func TestStableRunIDDeterministic(t *testing.T) {
	a := StableRunID("task", "attempt", "lease", "install", "version", "op")
	b := StableRunID("task", "attempt", "lease", "install", "version", "op")
	if a != b {
		t.Fatal("run id not deterministic")
	}
}

type testSecret struct{}

func (testSecret) ResolveExactBound(context.Context, string, string, string, string, string) ([]byte, error) {
	return []byte("token"), nil
}

func TestRemoteExecutorTLSListAndCall(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Fatalf("authorization=%q", r.Header.Get("Authorization"))
		}
		var req struct {
			Method string `json:"method"`
			ID     uint64 `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{}}}`, req.ID)
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"echo","description":"echo","inputSchema":{"type":"object"}}]}}`, req.ID)
		case "tools/call":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"content":[{"type":"text","text":"ok"}],"isError":false}}`, req.ID)
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{}}`))
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	installationID := uuid.NewString()
	versionID := uuid.NewString()
	purpose := string(core.SecretPurposeMCPCredential)
	bindingDigest := strings.Repeat("a", 64)
	endpoint := core.RemoteEndpoint{URL: u.String(), CredentialReferenceID: uuid.NewString()}
	e := &RemoteExecutor{Secrets: testSecret{}, Options: []mcphttp.Option{mcphttp.WithEndpointPolicy(mcphttp.EndpointPolicyFunc(func(context.Context, *url.URL) error { return nil })), mcphttp.WithRoundTripper(srv.Client().Transport)}}
	tools, err := e.ListToolsBoundExact(context.Background(), endpoint, installationID, versionID, purpose, bindingDigest)
	if err != nil || len(tools) != 1 || tools[0].Name != "mcp__mcp__echo" {
		t.Fatalf("tools=%#v err=%v", tools, err)
	}
	result, err := e.ExecuteBoundExact(context.Background(), endpoint, installationID, versionID, purpose, bindingDigest, "mcp__mcp__echo", json.RawMessage(`{}`))
	if err != nil || result.Text != "ok" {
		t.Fatalf("result=%#v err=%v", result, err)
	}
}

func TestRemoteExecutorWithoutCredentialOmitsAuthorization(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Fatalf("unexpected authorization=%q", got)
		}
		var req struct {
			Method string `json:"method"`
			ID     uint64 `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{}}}`, req.ID)
		case "tools/list":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{"tools":[{"name":"echo","inputSchema":{"type":"object"}}]}}`, req.ID)
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{}}`))
		}
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	e := &RemoteExecutor{Options: []mcphttp.Option{mcphttp.WithEndpointPolicy(mcphttp.EndpointPolicyFunc(func(context.Context, *url.URL) error { return nil })), mcphttp.WithRoundTripper(srv.Client().Transport)}}
	tools, err := e.ListToolsBoundExact(context.Background(), core.RemoteEndpoint{URL: u.String()}, uuid.NewString(), uuid.NewString(), "", "")
	if err != nil || len(tools) != 1 || tools[0].Name != "mcp__mcp__echo" {
		t.Fatalf("tools=%#v err=%v", tools, err)
	}
}

type testRemoteRuntimeSecret struct{ testSecret }

func (testRemoteRuntimeSecret) ResolveSecret(context.Context, string) ([]byte, error) {
	return []byte("token"), nil
}
