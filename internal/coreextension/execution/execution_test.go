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
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"github.com/YingSuiAI/dirextalk-agent/internal/mcphttp"
	"github.com/google/uuid"
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

type publicationFake struct {
	called int
	digest string
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
	content := []materialFile{{Path: "SKILL.md", Content: base64.RawStdEncoding.EncodeToString(body)}}
	canonical, _ := json.Marshal(content)
	contentDigest := digestBytes(canonical)
	manifestDigest := digestJSON([]map[string]string{{"path": "SKILL.md", "digest": digestBytes(body)}})
	candidate := core.Candidate{ID: "skill", Kind: core.KindSkill, Source: core.SourceSkillsSh, Name: "skill", Pin: core.SourcePin{RegistryVersion: "1", RegistrySHA256: strings.Repeat("a", 64)}, Transport: core.TransportSkillStatic}
	inspection := core.Inspection{Candidate: candidate, ContentDigest: contentDigest, ManifestDigest: manifestDigest, NetworkSchemaDigest: digestBytes([]byte("[]")), SecretSchemaDigest: digestBytes([]byte("[]")), Execution: core.ExecutionDescriptor{Skill: &core.SkillEntry{RelativePath: "SKILL.md", Digest: digestBytes(body)}}}
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
	err            error
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
func (f *fakeCoord) Fail(context.Context, coretask.Task, string, string) (bool, error) {
	f.fail++
	return true, nil
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

type testRemoteRuntimeSecret struct{ testSecret }

func (testRemoteRuntimeSecret) ResolveSecret(context.Context, string) ([]byte, error) {
	return []byte("token"), nil
}
