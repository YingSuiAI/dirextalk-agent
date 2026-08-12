package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

type nodeResolverFixture struct {
	calls    int
	resolve  func(NodeDependencyRequest) (NodeDependencyResolution, error)
	requests []NodeDependencyRequest
}

func (f *nodeResolverFixture) Resolve(_ context.Context, request NodeDependencyRequest) (NodeDependencyResolution, error) {
	f.calls++
	f.requests = append(f.requests, request)
	return f.resolve(request)
}

func nodeTarballFixture(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var compressed bytes.Buffer
	gz := gzip.NewWriter(&compressed)
	tw := tar.NewWriter(gz)
	paths := make([]string, 0, len(files))
	for name := range files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		content := []byte(files[name])
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(content)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return compressed.Bytes()
}

func nodeSRI(content []byte) string {
	sum := sha512.Sum512(content)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

func managedLockFixture(t *testing.T, packageName, version, tarballURL string, tarball []byte) []byte {
	t.Helper()
	lock := map[string]any{
		"name": "dirextalk-managed-mcp", "version": "0.0.0", "lockfileVersion": 3,
		"packages": map[string]any{
			"": map[string]any{"name": "dirextalk-managed-mcp", "version": "0.0.0", "hasInstallScript": true},
			"node_modules/" + packageName: map[string]any{
				"name": packageName, "version": version, "resolved": tarballURL, "integrity": nodeSRI(tarball), "hasInstallScript": true,
			},
		},
	}
	encoded, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestNPMSearchPreflightsDirectPackageWithoutResolvingDependencies(t *testing.T) {
	const packageName = "demo-mcp"
	const version = "1.2.3"
	directTarball := nodeTarballFixture(t, map[string]string{
		"package.json":   `{"name":"demo-mcp","version":"1.2.3","bin":"dist/server.js","scripts":{"postinstall":"touch marker; curl https://example.invalid; exit 99"}}`,
		"dist/server.js": "console.log('mcp')\n",
	})
	sha1sum := sha1.Sum(directTarball)
	var server *httptest.Server
	resolver := &nodeResolverFixture{}
	resolver.resolve = func(request NodeDependencyRequest) (NodeDependencyResolution, error) {
		lock := managedLockFixture(t, packageName, version, server.URL+"/demo-mcp/-/demo-mcp-1.2.3.tgz", directTarball)
		return NodeDependencyResolution{PackageLock: lock, Tarballs: []NodeResolvedTarball{{LockPath: "node_modules/demo-mcp", Content: directTarball}}}, nil
	}
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/-/v1/search":
			_ = json.NewEncoder(response).Encode(map[string]any{"total": 1, "objects": []any{map[string]any{"package": map[string]any{"name": packageName, "version": version, "description": "demo"}}}})
		case "/demo-mcp":
			_ = json.NewEncoder(response).Encode(map[string]any{
				"name": packageName, "versions": map[string]any{version: map[string]any{
					"name": packageName, "version": version, "description": "demo",
					"dist": map[string]any{"tarball": server.URL + "/demo-mcp/-/demo-mcp-1.2.3.tgz", "integrity": nodeSRI(directTarball), "shasum": hex.EncodeToString(sha1sum[:])},
				}},
			})
		case "/demo-mcp/-/demo-mcp-1.2.3.tgz":
			_, _ = response.Write(directTarball)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	adapter, err := NewNPMForTest(HTTPConfig{BaseURL: server.URL, Client: server.Client()}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.Search(context.Background(), core.SearchQuery{Kind: core.KindMCP, Source: core.SourceNPM, Text: "demo"})
	if err != nil || len(page.Candidates) != 1 {
		t.Fatalf("search=%+v err=%v", page, err)
	}
	if resolver.calls != 0 {
		t.Fatalf("Search performed dependency resolution: calls=%d", resolver.calls)
	}
	candidate := page.Candidates[0]
	inspection, err := adapter.Inspect(context.Background(), core.InspectRequest{Kind: core.KindMCP, Source: core.SourceNPM, ID: candidate.ID, Pin: candidate.Pin})
	if err != nil {
		t.Fatal(err)
	}
	if resolver.calls != 1 {
		t.Fatalf("Inspect resolver calls=%d, want 1", resolver.calls)
	}
	if inspection.Execution.Stdio == nil || inspection.Execution.Stdio.Runtime != "node" || inspection.Execution.Stdio.RelativePath != "node_modules/demo-mcp/dist/server.js" || inspection.Execution.Stdio.Argv == nil || len(inspection.Execution.Stdio.Argv) != 0 {
		t.Fatalf("execution=%+v", inspection.Execution)
	}
	if inspection.NetworkGrants == nil || inspection.SecretGrants == nil || len(inspection.NetworkGrants) != 0 || len(inspection.SecretGrants) != 0 {
		t.Fatalf("grant arrays must be explicit and empty: network=%#v secret=%#v", inspection.NetworkGrants, inspection.SecretGrants)
	}
	if inspection.Candidate.Pin.RegistrySHA256 != candidate.Pin.RegistrySHA256 || inspection.Candidate.Transport != core.TransportStdioNode {
		t.Fatalf("candidate=%+v", inspection.Candidate)
	}
}

func TestNPMRejectsRegistryIntegrityMismatchBeforeResolver(t *testing.T) {
	tarball := nodeTarballFixture(t, map[string]string{
		"package.json": `{"name":"demo-mcp","version":"1.2.3","bin":"server.js"}`,
		"server.js":    "export {}\n",
	})
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/-/v1/search":
			_, _ = response.Write([]byte(`{"total":1,"objects":[{"package":{"name":"demo-mcp","version":"1.2.3"}}]}`))
		case "/demo-mcp":
			_ = json.NewEncoder(response).Encode(map[string]any{"name": "demo-mcp", "versions": map[string]any{"1.2.3": map[string]any{
				"name": "demo-mcp", "version": "1.2.3", "dist": map[string]any{"tarball": "https://" + request.Host + "/demo.tgz", "integrity": nodeSRI([]byte("different"))},
			}}})
		case "/demo.tgz":
			_, _ = response.Write(tarball)
		default:
			http.NotFound(response, request)
		}
	}))
	defer server.Close()
	resolver := &nodeResolverFixture{resolve: func(NodeDependencyRequest) (NodeDependencyResolution, error) { return NodeDependencyResolution{}, nil }}
	adapter, err := NewNPMForTest(HTTPConfig{BaseURL: server.URL, Client: server.Client()}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Search(context.Background(), core.SearchQuery{Kind: core.KindMCP, Source: core.SourceNPM, Text: "demo"})
	if !errors.Is(err, ErrMalformed) || resolver.calls != 0 {
		t.Fatalf("err=%v resolver_calls=%d", err, resolver.calls)
	}
}

func TestNPMDefaultAllowsRegistryStreamBeyondCommonTimeout(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/slow.tgz" {
			http.NotFound(response, request)
			return
		}
		response.WriteHeader(http.StatusOK)
		_, _ = response.Write([]byte("a"))
		if flusher, ok := response.(http.Flusher); ok {
			flusher.Flush()
		}
		time.Sleep(DefaultTimeout + 100*time.Millisecond)
		_, _ = response.Write([]byte("b"))
	}))
	defer server.Close()
	resolver := &nodeResolverFixture{resolve: func(NodeDependencyRequest) (NodeDependencyResolution, error) { return NodeDependencyResolution{}, nil }}
	adapter, err := NewNPMForTest(HTTPConfig{BaseURL: server.URL, Client: server.Client()}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	body, err := adapter.downloadTarball(context.Background(), server.URL+"/slow.tgz")
	if err != nil || string(body) != "ab" {
		t.Fatalf("body=%q err=%v", body, err)
	}
	if elapsed := time.Since(started); elapsed <= DefaultTimeout {
		t.Fatalf("stream completed in %s; test did not cross common timeout", elapsed)
	}
	if adapter.c.timeout != nodeResolveTimeout || adapter.c.max != nodeMaxInputBytes {
		t.Fatalf("timeout=%s max=%d", adapter.c.timeout, adapter.c.max)
	}
}

func TestNPMRejectsBodyOver64MiBAndHigherConfiguredLimits(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Length", strconv.FormatInt(nodeMaxInputBytes+1, 10))
		response.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	resolver := &nodeResolverFixture{resolve: func(NodeDependencyRequest) (NodeDependencyResolution, error) { return NodeDependencyResolution{}, nil }}
	adapter, err := NewNPMForTest(HTTPConfig{BaseURL: server.URL, Client: server.Client()}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := adapter.downloadTarball(context.Background(), server.URL+"/oversize.tgz"); !errors.Is(err, ErrOversize) {
		t.Fatalf("oversize body err=%v", err)
	}
	if _, err := NewNPMForTest(HTTPConfig{BaseURL: server.URL, Client: server.Client(), MaxBodyBytes: nodeMaxInputBytes + 1}, resolver); err == nil {
		t.Fatal("configured body limit above 64MiB accepted")
	}
	if _, err := NewNPMForTest(HTTPConfig{BaseURL: server.URL, Client: server.Client(), Timeout: nodeResolveTimeout + time.Second}, resolver); err == nil {
		t.Fatal("configured timeout above 120s accepted")
	}
}

func TestNPMRejectsNonExactPinsWithoutNetwork(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
	defer server.Close()
	resolver := &nodeResolverFixture{resolve: func(NodeDependencyRequest) (NodeDependencyResolution, error) { return NodeDependencyResolution{}, nil }}
	adapter, err := NewNPMForTest(HTTPConfig{BaseURL: server.URL, Client: server.Client()}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{"latest", "^1.2.3", ">=1.2.3", "git+https://example.test/repo", "file:../demo", "https://example.test/demo.tgz"} {
		_, err := adapter.Inspect(context.Background(), core.InspectRequest{
			Kind: core.KindMCP, Source: core.SourceNPM, ID: "demo-mcp",
			Pin: core.SourcePin{RegistryVersion: version, RegistrySHA256: strings.Repeat("a", 64)},
		})
		if !errors.Is(err, core.ErrInvalid) {
			t.Fatalf("version %q err=%v", version, err)
		}
	}
	if requests != 0 || resolver.calls != 0 {
		t.Fatalf("requests=%d resolver_calls=%d", requests, resolver.calls)
	}
}

func TestNodeLockRejectsUnverifiedOrMutableDependencyLocations(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{
			"name": "root-mcp", "version": "1.0.0", "lockfileVersion": 3,
			"packages": map[string]any{
				"":                        map[string]any{"name": "root-mcp", "version": "1.0.0"},
				"node_modules/dependency": map[string]any{"name": "dependency", "version": "2.0.0", "resolved": "https://registry.example.test/dependency-2.0.0.tgz", "integrity": nodeSRI([]byte("fixture"))},
			},
		}
	}
	cases := map[string]func(map[string]any){
		"range": func(lock map[string]any) {
			lock["packages"].(map[string]any)["node_modules/dependency"].(map[string]any)["version"] = "^2.0.0"
		},
		"git": func(lock map[string]any) {
			lock["packages"].(map[string]any)["node_modules/dependency"].(map[string]any)["resolved"] = "git+https://example.test/dependency.git"
		},
		"file": func(lock map[string]any) {
			lock["packages"].(map[string]any)["node_modules/dependency"].(map[string]any)["resolved"] = "file:../dependency"
		},
		"http": func(lock map[string]any) {
			lock["packages"].(map[string]any)["node_modules/dependency"].(map[string]any)["resolved"] = "http://registry.example.test/dependency-2.0.0.tgz"
		},
	}
	for name, mutate := range cases {
		lock := base()
		mutate(lock)
		raw, _ := json.Marshal(lock)
		if _, err := parseAndValidateNodeLock(raw, "root-mcp", "1.0.0"); err == nil {
			t.Fatalf("%s lock accepted", name)
		}
	}
}

func TestNodeLockAllowsInstallScriptMetadataBecauseExecutionIsDisabled(t *testing.T) {
	lock := map[string]any{
		"name": "root-mcp", "version": "1.0.0", "lockfileVersion": 3,
		"packages": map[string]any{
			"":                        map[string]any{"name": "root-mcp", "version": "1.0.0", "hasInstallScript": true},
			"node_modules/dependency": map[string]any{"name": "dependency", "version": "2.0.0", "resolved": "https://registry.example.test/dependency-2.0.0.tgz", "integrity": nodeSRI([]byte("fixture")), "hasInstallScript": true},
		},
	}
	raw, _ := json.Marshal(lock)
	if _, err := parseAndValidateNodeLock(raw, "root-mcp", "1.0.0"); err != nil {
		t.Fatalf("install-script metadata rejected: %v", err)
	}
}

func TestNodePackageTarballRejectsUnsafeOrNonPureJSInput(t *testing.T) {
	symlinkTarball := func() []byte {
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		tw := tar.NewWriter(gz)
		_ = tw.WriteHeader(&tar.Header{Name: "package/package.json", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"})
		_ = tw.Close()
		_ = gz.Close()
		return compressed.Bytes()
	}()
	if _, err := parseNPMPackageTarball(symlinkTarball); err == nil {
		t.Fatalf("symlink err=%v", err)
	}
	unsafeTarball := nodeTarballFixture(t, map[string]string{"../escape": "x"})
	if _, err := parseNPMPackageTarball(unsafeTarball); !errors.Is(err, ErrMalformed) {
		t.Fatalf("traversal err=%v", err)
	}
	for name, packageJSON := range map[string]string{
		"typescript": `{"name":"demo","version":"1.0.0","bin":"server.ts"}`,
	} {
		files := []rawFile{{Path: "package.json", Content: packageJSON}, {Path: "server.js", Content: "x"}, {Path: "server.ts", Content: "x"}}
		if _, err := inspectNodePackage(files, false, "demo", "1.0.0"); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("%s err=%v", name, err)
		}
	}
	for _, native := range []string{"addon.node", "addon.so", "addon.dll", "addon.dylib", "addon.a", "addon.o", "binding.gyp"} {
		nativeFiles := []rawFile{{Path: "package.json", Content: `{"name":"demo","version":"1.0.0","bin":"server.js"}`}, {Path: "server.js", Content: "x"}, {Path: native, Content: "x"}}
		if _, err := inspectNodePackage(nativeFiles, false, "demo", "1.0.0"); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("native %q err=%v", native, err)
		}
	}
	gypfile := []rawFile{{Path: "package.json", Content: `{"name":"demo","version":"1.0.0","bin":"server.js","gypfile":true}`}, {Path: "server.js", Content: "x"}}
	if _, err := inspectNodePackage(gypfile, false, "demo", "1.0.0"); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("gypfile=true err=%v", err)
	}
}

func TestNodeDependencyPackageAllowsNonEntryMainMetadataButStillRejectsNativeBuilds(t *testing.T) {
	expected := nodeLockPackage{Name: "dunder-proto", Version: "1.0.1"}
	files := []rawFile{{Path: "package.json", Content: `{"name":"dunder-proto","version":"1.0.1","main":false}`}, {Path: "get.js", Content: "export {}\n"}}
	inspected, err := inspectNodeDependencyPackage(files, expected)
	if err != nil || inspected.Name != expected.Name || inspected.Version != expected.Version {
		t.Fatalf("valid dependency metadata rejected: inspected=%+v err=%v", inspected, err)
	}
	for _, mutate := range []func([]rawFile) []rawFile{
		func(value []rawFile) []rawFile {
			value[0].Content = `{"name":"dunder-proto","version":"1.0.1","main":false,"gypfile":true}`
			return value
		},
		func(value []rawFile) []rawFile {
			return append(value, rawFile{Path: "binding.gyp", Content: "{}"})
		},
	} {
		candidate := append([]rawFile(nil), files...)
		if _, err := inspectNodeDependencyPackage(mutate(candidate), expected); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("native dependency metadata accepted: %v", err)
		}
	}
}

func TestNodePackageTarballEnforcesFileAndExpandedByteLimits(t *testing.T) {
	oversizeHeader := func() []byte {
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		tw := tar.NewWriter(gz)
		_ = tw.WriteHeader(&tar.Header{Name: "package/huge.js", Mode: 0o644, Size: nodeMaxInputBytes + 1, Typeflag: tar.TypeReg})
		_ = gz.Close()
		return compressed.Bytes()
	}()
	if _, err := parseNPMPackageTarball(oversizeHeader); !errors.Is(err, ErrOversize) {
		t.Fatalf("expanded byte limit err=%v", err)
	}
	tooManyFiles := func() []byte {
		var compressed bytes.Buffer
		gz := gzip.NewWriter(&compressed)
		tw := tar.NewWriter(gz)
		for index := 0; index <= nodeMaxInputFiles; index++ {
			if err := tw.WriteHeader(&tar.Header{Name: "package/files/" + strconv.Itoa(index), Mode: 0o644, Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		return compressed.Bytes()
	}()
	if _, err := parseNPMPackageTarball(tooManyFiles); !errors.Is(err, ErrOversize) {
		t.Fatalf("file limit err=%v", err)
	}
}

func TestGitHubNodeRequiresExactLockAndProducesDeterministicSourceBundle(t *testing.T) {
	commit := strings.Repeat("a", 40)
	packageJSON := `{"name":"github-mcp","version":"2.0.0","bin":"dist/server.js","scripts":{"prepare":"touch marker; curl https://example.invalid; exit 99"}}`
	lock := `{"name":"github-mcp","version":"2.0.0","lockfileVersion":3,"packages":{"":{"name":"github-mcp","version":"2.0.0","hasInstallScript":true}}}`
	files := map[string]string{"package.json": packageJSON, "package-lock.json": lock, "dist/server.js": "console.log('ok')\n"}
	resolver := &nodeResolverFixture{resolve: func(request NodeDependencyRequest) (NodeDependencyResolution, error) {
		return NodeDependencyResolution{PackageLock: append([]byte(nil), request.ExistingPackageLock...)}, nil
	}}
	server := githubNodeServer(t, commit, files)
	defer server.Close()
	adapter, err := NewGitHubForTestWithNodeResolver(HTTPConfig{BaseURL: server.URL, Client: server.Client()}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.Search(context.Background(), core.SearchQuery{Kind: core.KindMCP, Source: core.SourceGitHub, Text: "mcp", PageSize: 1})
	if err != nil || len(page.Candidates) != 1 {
		t.Fatalf("search=%+v err=%v", page, err)
	}
	if resolver.calls != 0 {
		t.Fatalf("Search performed dependency resolution: calls=%d", resolver.calls)
	}
	inspection, err := adapter.Inspect(context.Background(), core.InspectRequest{
		Kind: core.KindMCP, Source: core.SourceGitHub, ID: page.Candidates[0].ID, Pin: page.Candidates[0].Pin,
	})
	if err != nil || resolver.calls != 1 || inspection.Candidate != page.Candidates[0] {
		t.Fatalf("inspection=%+v err=%v resolver_calls=%d", inspection, err, resolver.calls)
	}
	artifact, err := adapter.Fetch(context.Background(), page.Candidates[0])
	if err != nil {
		t.Fatal(err)
	}
	if artifact.Inspection.Execution.Stdio == nil || artifact.Inspection.Execution.Stdio.Runtime != "node" || artifact.Inspection.Execution.Stdio.RelativePath != "dist/server.js" {
		t.Fatalf("execution=%+v", artifact.Inspection.Execution)
	}
	if artifact.Candidate != page.Candidates[0] || resolver.calls != 2 {
		t.Fatalf("candidate=%+v resolver_calls=%d", artifact.Candidate, resolver.calls)
	}
}

func TestGitHubSearchSkipsUnsupportedNodeRepoWithoutResolvingPage(t *testing.T) {
	commit := strings.Repeat("d", 40)
	goodPackage := `{"name":"good-mcp","version":"1.0.0","bin":"server.js"}`
	goodLock := `{"name":"good-mcp","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"good-mcp","version":"1.0.0"}}}`
	repositories := map[string]map[string]string{
		"acme/unsupported": {"package.json": `{"name":"bad-mcp","version":"1.0.0","bin":"server.js"}`, "server.js": "x"},
		"acme/good":        {"package.json": goodPackage, "package-lock.json": goodLock, "server.js": "x"},
	}
	server := githubMultiRepoNodeServer(t, commit, repositories)
	defer server.Close()
	resolver := &nodeResolverFixture{resolve: func(NodeDependencyRequest) (NodeDependencyResolution, error) { return NodeDependencyResolution{}, nil }}
	adapter, err := NewGitHubForTestWithNodeResolver(HTTPConfig{BaseURL: server.URL, Client: server.Client()}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.Search(context.Background(), core.SearchQuery{Kind: core.KindMCP, Source: core.SourceGitHub, Text: "mcp", PageSize: 2})
	if err != nil || len(page.Candidates) != 1 || page.Candidates[0].ID != "acme/good" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
	if resolver.calls != 0 {
		t.Fatalf("Search performed dependency resolution: calls=%d", resolver.calls)
	}
}

func TestGitHubNodeRejectsMissingLockBeforeResolver(t *testing.T) {
	commit := strings.Repeat("b", 40)
	server := githubNodeServer(t, commit, map[string]string{
		"package.json": `{"name":"github-mcp","version":"2.0.0","bin":"server.js"}`,
		"server.js":    "export {}\n",
	})
	defer server.Close()
	resolver := &nodeResolverFixture{resolve: func(NodeDependencyRequest) (NodeDependencyResolution, error) { return NodeDependencyResolution{}, nil }}
	adapter, err := NewGitHubForTestWithNodeResolver(HTTPConfig{BaseURL: server.URL, Client: server.Client()}, resolver)
	if err != nil {
		t.Fatal(err)
	}
	_, err = adapter.Inspect(context.Background(), core.InspectRequest{Kind: core.KindMCP, Source: core.SourceGitHub, ID: "acme/demo", Pin: core.SourcePin{GitCommit: commit, GitSHA256: strings.Repeat("c", 64)}})
	if !errors.Is(err, ErrUnsupported) || resolver.calls != 0 {
		t.Fatalf("err=%v resolver_calls=%d", err, resolver.calls)
	}
}

func githubNodeServer(t *testing.T, commit string, files map[string]string) *httptest.Server {
	t.Helper()
	shaFiles := make(map[string]string, len(files))
	tree := make([]map[string]any, 0, len(files))
	paths := make([]string, 0, len(files))
	for filePath := range files {
		paths = append(paths, filePath)
	}
	sort.Strings(paths)
	for _, filePath := range paths {
		content := files[filePath]
		sha := fullBlobSHA([]byte(content))
		shaFiles[sha] = content
		tree = append(tree, map[string]any{"path": filePath, "mode": "100644", "type": "blob", "sha": sha, "url": "x", "size": len(content)})
	}
	return httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/search/repositories":
			_ = json.NewEncoder(response).Encode(map[string]any{"items": []any{map[string]any{"full_name": "acme/demo", "description": "search-only description", "default_branch": "main"}}})
		case strings.Contains(request.URL.Path, "/commits/"):
			_ = json.NewEncoder(response).Encode(map[string]any{"sha": commit})
		case strings.Contains(request.URL.Path, "/git/trees/"):
			_ = json.NewEncoder(response).Encode(map[string]any{"sha": commit, "url": "x", "truncated": false, "tree": tree})
		case strings.Contains(request.URL.Path, "/git/blobs/"):
			sha := request.URL.Path[strings.LastIndex(request.URL.Path, "/")+1:]
			content, ok := shaFiles[sha]
			if !ok {
				http.NotFound(response, request)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(content))})
		default:
			http.NotFound(response, request)
		}
	}))
}

func githubMultiRepoNodeServer(t *testing.T, commit string, repositories map[string]map[string]string) *httptest.Server {
	t.Helper()
	trees := make(map[string][]map[string]any, len(repositories))
	blobs := make(map[string]string)
	for repository, files := range repositories {
		paths := make([]string, 0, len(files))
		for filePath := range files {
			paths = append(paths, filePath)
		}
		sort.Strings(paths)
		for _, filePath := range paths {
			content := files[filePath]
			sha := fullBlobSHA([]byte(content))
			blobs[repository+"/"+sha] = content
			trees[repository] = append(trees[repository], map[string]any{"path": filePath, "mode": "100644", "type": "blob", "sha": sha, "url": "x", "size": len(content)})
		}
	}
	return httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/search/repositories":
			_ = json.NewEncoder(response).Encode(map[string]any{"items": []any{
				map[string]any{"full_name": "acme/unsupported", "default_branch": "main"},
				map[string]any{"full_name": "acme/good", "default_branch": "main"},
			}})
		case strings.Contains(request.URL.Path, "/commits/"):
			_ = json.NewEncoder(response).Encode(map[string]any{"sha": commit})
		case strings.Contains(request.URL.Path, "/git/trees/"):
			repository := strings.TrimPrefix(strings.Split(request.URL.Path, "/git/trees/")[0], "/repos/")
			_ = json.NewEncoder(response).Encode(map[string]any{"sha": commit, "url": "x", "truncated": false, "tree": trees[repository]})
		case strings.Contains(request.URL.Path, "/git/blobs/"):
			prefix, sha, _ := strings.Cut(strings.TrimPrefix(request.URL.Path, "/repos/"), "/git/blobs/")
			content, ok := blobs[prefix+"/"+sha]
			if !ok {
				http.NotFound(response, request)
				return
			}
			_ = json.NewEncoder(response).Encode(map[string]any{"encoding": "base64", "content": base64.StdEncoding.EncodeToString([]byte(content))})
		default:
			http.NotFound(response, request)
		}
	}))
}

func TestNodeAllowsEveryInstallTimeLifecycleDeclarationAndBindsOriginalBytes(t *testing.T) {
	for _, script := range []string{"preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare"} {
		packageJSON := `{"name":"demo","version":"1.0.0","bin":"server.js","scripts":{"` + script + `":"touch marker; curl https://example.invalid; exit 99"}}`
		files := []rawFile{{Path: "package.json", Content: packageJSON}, {Path: "server.js", Content: "x"}}
		inspected, err := inspectNodePackage(files, false, "demo", "1.0.0")
		if err != nil || string(inspected.PackageJSON) != packageJSON || digestBytes(inspected.PackageJSON) != digestBytes([]byte(packageJSON)) {
			t.Fatalf("script %q lost source binding: err=%v package=%q", script, err, inspected.PackageJSON)
		}
	}
}
