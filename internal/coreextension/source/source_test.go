package source

import (
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

type fixtureResolver struct{ ips []net.IPAddr }

func (r fixtureResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return r.ips, nil
}

func TestOfficialRegistryFixedResponses(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v0.1/servers" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"servers":[{"server":{"name":"io.example/demo","description":"demo","version":"1.2.3","remotes":[{"type":"streamable-http","url":"https://mcp.example.test/mcp"}]}}],"nextCursor":"opaque"}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/v0.1/servers/") && strings.Contains(r.URL.Path, "/versions/1.2.3") {
			_, _ = w.Write([]byte(`{"server":{"name":"io.example/demo","description":"demo","version":"1.2.3","remotes":[{"type":"streamable-http","url":"https://mcp.example.test/mcp"}]}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer ts.Close()
	a, err := NewOfficialRegistryForTest(HTTPConfig{BaseURL: ts.URL, Client: ts.Client()})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Search(context.Background(), core.SearchQuery{Kind: core.KindMCP, Source: core.SourceOfficialRegistry, Text: "demo"})
	if err != nil || len(p.Candidates) != 1 || p.NextPageToken == "" {
		t.Fatalf("search=%+v err=%v", p, err)
	}
	c := p.Candidates[0]
	i, err := a.Inspect(context.Background(), core.InspectRequest{Kind: core.KindMCP, Source: core.SourceOfficialRegistry, ID: c.ID, Pin: c.Pin})
	if err != nil {
		t.Fatal(err)
	}
	if err := i.Validate(); err != nil {
		t.Fatalf("inspection: %v", err)
	}
}

func TestHTTPBoundaryRejectsOversizeRedirectAndRedactsToken(t *testing.T) {
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://attacker.invalid/x", http.StatusFound)
	}))
	defer redirect.Close()
	a, err := NewOfficialRegistryForTest(HTTPConfig{BaseURL: redirect.URL, AllowHTTP: true, BearerToken: "fixture-token", MaxBodyBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	_, err = a.Search(context.Background(), core.SearchQuery{})
	if err == nil || strings.Contains(err.Error(), "fixture-token") {
		t.Fatalf("redirect err=%v", err)
	}
	big := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", 32))) }))
	defer big.Close()
	b, _ := NewOfficialRegistryForTest(HTTPConfig{BaseURL: big.URL, AllowHTTP: true, MaxBodyBytes: 16})
	_, err = b.Search(context.Background(), core.SearchQuery{})
	if err != ErrOversize {
		t.Fatalf("oversize err=%v", err)
	}
}

func TestSkillsRejectsDuplicateAndUnsafePaths(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"files":[{"path":"SKILL.md","content":"x"},{"path":"SKILL.md","content":"y"}]}`))
	}))
	defer ts.Close()
	a, _ := NewSkillsShForTest(HTTPConfig{BaseURL: ts.URL, Client: ts.Client()})
	_, err := a.Inspect(context.Background(), core.InspectRequest{Kind: core.KindSkill, Source: core.SourceSkillsSh, ID: "acme/demo", Pin: core.SourcePin{RegistryVersion: "1.0.0", RegistrySHA256: strings.Repeat("a", 64)}})
	if err == nil {
		t.Fatal("expected duplicate path rejection")
	}
}

func TestCursorIntegrityAndPageBinding(t *testing.T) {
	tok := encodeCursor(cursor{Source: string(core.SourceGlama), Kind: string(core.KindMCP), Query: "x", PageSize: 10, Offset: 10, Remote: "opaque"})
	if _, err := decodeCursorValue(tok, string(core.SourceGlama), "x", string(core.KindMCP), 10); err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCursorValue(tok+"x", string(core.SourceGlama), "x", string(core.KindMCP), 10); err == nil {
		t.Fatal("tampered cursor accepted")
	}
	if _, err := decodeCursorValue(tok, string(core.SourceGlama), "x", string(core.KindMCP), 20); err == nil {
		t.Fatal("page-size drift accepted")
	}
}

func TestCanonicalFilesRecomputesSuppliedDigest(t *testing.T) {
	_, _, err := canonicalFiles([]rawFile{{Path: "SKILL.md", Content: "body", Digest: strings.Repeat("a", 64)}}, 1024)
	if err != ErrMalformed {
		t.Fatalf("digest mismatch err=%v", err)
	}
}

func TestRemotePrivateResolutionRejected(t *testing.T) {
	c, err := newClient(HTTPConfig{BaseURL: "https://example.test", Resolver: fixtureResolver{ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.validateRemote(context.Background(), "https://mcp.example.test/mcp"); err != ErrUnsupported {
		t.Fatalf("private endpoint err=%v", err)
	}
}

func TestProductionRejectsInjectedClientAndDialer(t *testing.T) {
	if _, err := NewGitHub(HTTPConfig{BaseURL: GitHubAuthority, Client: &http.Client{}}); err == nil {
		t.Fatal("injected client accepted")
	}
	if _, err := NewGitHub(HTTPConfig{BaseURL: GitHubAuthority, Dialer: fixtureDialer{}}); err == nil {
		t.Fatal("injected dialer accepted")
	}
}

type fixtureDialer struct{}

func (fixtureDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	return nil, ErrUnsupported
}

func TestGitHubFetchesCanonicalFullTreeAndBindsCommitDigest(t *testing.T) {
	commit := strings.Repeat("a", 40)
	files := map[string]string{"SKILL.md": "title\n", "scripts/run.py": "print(1)\n"}
	blobs := map[string]string{"787215d4eaefab4509813ee9e7da067b48b8c1ff": files["SKILL.md"], "b917a726c93f902e43291d9009d6488385133b67": files["scripts/run.py"]}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/search/repositories":
			_, _ = w.Write([]byte(`{"items":[{"full_name":"acme/demo","default_branch":"main"}]}`))
		case strings.Contains(r.URL.Path, "/commits/"):
			_, _ = w.Write([]byte(`{"sha":"` + commit + `"}`))
		case strings.Contains(r.URL.Path, "/git/trees/"):
			_, _ = w.Write([]byte(`{"sha":"` + commit + `","url":"x","truncated":false,"tree":[{"path":"SKILL.md","mode":"100644","type":"blob","sha":"787215d4eaefab4509813ee9e7da067b48b8c1ff","url":"x","size":6},{"path":"scripts/run.py","mode":"100644","type":"blob","sha":"b917a726c93f902e43291d9009d6488385133b67","url":"x","size":9}]}`))
		case strings.Contains(r.URL.Path, "/git/blobs/"):
			sha := strings.TrimPrefix(r.URL.Path, "/repos/acme/demo/git/blobs/")
			_, _ = w.Write([]byte(`{"encoding":"base64","content":"` + base64.StdEncoding.EncodeToString([]byte(blobs[sha])) + `"}`))
		case strings.Contains(r.URL.Path, "/contents/"):
			p := strings.TrimPrefix(r.URL.Path, "/repos/acme/demo/contents/")
			_, _ = w.Write([]byte(`{"type":"file","content":"` + base64.StdEncoding.EncodeToString([]byte(files[p])) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	a, err := NewGitHubForTest(HTTPConfig{BaseURL: ts.URL, Client: ts.Client()})
	if err != nil {
		t.Fatal(err)
	}
	p, err := a.Search(context.Background(), core.SearchQuery{Kind: core.KindSkill, Source: core.SourceGitHub, Text: "demo", PageSize: 1})
	if err != nil || len(p.Candidates) != 1 {
		t.Fatalf("search=%+v err=%v", p, err)
	}
	f, err := a.Fetch(context.Background(), p.Candidates[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Validate(); err != nil {
		t.Fatalf("artifact validate: %v", err)
	}
	if f.Candidate.Transport != core.TransportSkillStatic || f.ContentDigest != p.Candidates[0].Pin.GitSHA256 {
		t.Fatalf("candidate=%+v", f.Candidate)
	}
}
