package source

import (
	"context"
	"net/url"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

// OfficialRegistry implements registry.modelcontextprotocol.io v0.1.
type OfficialRegistry struct{ c *client }

var _ core.SourceAdapter = (*OfficialRegistry)(nil)

func NewOfficialRegistry(cfg HTTPConfig) (*OfficialRegistry, error) {
	c, e := newProviderClient(cfg, OfficialRegistryAuthority)
	if e != nil {
		return nil, e
	}
	return &OfficialRegistry{c: c}, nil
}
func NewOfficialRegistryForTest(cfg HTTPConfig) (*OfficialRegistry, error) {
	cfg.TestOnly = true
	return NewOfficialRegistry(cfg)
}

func (a *OfficialRegistry) Search(ctx context.Context, q core.SearchQuery) (core.Page, error) {
	if q.Kind != "" && q.Kind != core.KindMCP || q.Source != "" && q.Source != core.SourceOfficialRegistry {
		return core.Page{}, core.ErrInvalid
	}
	query := strings.TrimSpace(q.Text)
	ps := q.PageSize
	if ps < 0 || ps > 100 {
		return core.Page{}, core.ErrInvalid
	}
	cv, err := decodeCursorValue(q.PageToken, string(core.SourceOfficialRegistry), query, string(core.KindMCP), ps)
	if err != nil {
		return core.Page{}, err
	}
	offset := cv.Offset
	v := url.Values{}
	if query != "" {
		v.Set("search", query)
	}
	if q.PageSize > 0 {
		v.Set("limit", itoa(q.PageSize))
	}
	if cv.Remote != "" {
		v.Set("cursor", cv.Remote)
	} else if offset > 0 {
		v.Set("cursor", itoa(offset))
	}
	b, err := a.c.get(ctx, "/v0.1/servers", v)
	if err != nil {
		return core.Page{}, err
	}
	var root map[string]any
	if err := parseJSON(b, &root); err != nil {
		return core.Page{}, err
	}
	arr := rawSlice(root["servers"])
	if arr == nil {
		arr = rawSlice(root["data"])
	}
	if arr == nil {
		return core.Page{}, ErrMalformed
	}
	page := core.Page{}
	for _, x := range arr {
		m := rawMap(x)
		if sm, ok := m["server"].(map[string]any); ok {
			m = sm
		}
		cand, ok := registryCandidate(m)
		if !ok {
			return core.Page{}, ErrMalformed
		}
		page.Candidates = append(page.Candidates, cand)
	}
	next := rawString(root, "nextCursor", "next_cursor")
	if next == "" {
		if p := rawMap(root["pagination"]); p != nil {
			next = rawString(p, "nextCursor", "next_cursor")
		}
	}
	if next != "" {
		page.NextPageToken = encodeCursor(cursor{Source: string(core.SourceOfficialRegistry), Kind: string(core.KindMCP), PageSize: ps, Query: query, Offset: offset + len(page.Candidates), Remote: next})
	}
	return page, nil
}

func registryCandidate(m map[string]any) (core.Candidate, bool) {
	name := rawString(m, "name", "qualifiedName")
	if name == "" {
		return core.Candidate{}, false
	}
	version := rawString(m, "version", "latestVersion")
	if version == "" {
		if v := rawMap(m["version"]); v != nil {
			version = rawString(v, "version", "name")
		}
	}
	if version == "" || strings.EqualFold(version, "latest") {
		return core.Candidate{}, false
	}
	desc := rawString(m, "description", "displayName")
	id := name + "@" + version
	remote := ""
	if rs := rawSlice(m["remotes"]); len(rs) > 0 {
		rm := rawMap(rs[0])
		typ := strings.ToLower(rawString(rm, "type", "transport"))
		if strings.Contains(typ, "sse") || strings.Contains(typ, "template") {
			return core.Candidate{}, false
		}
		if strings.Contains(typ, "streamable") || strings.Contains(typ, "http") {
			remote = rawString(rm, "url", "endpoint")
		}
	}
	transport := core.TransportStdioStatic
	if remote != "" {
		transport = core.TransportStreamableHTTP
	}
	pin := core.SourcePin{RegistryVersion: version, RegistrySHA256: providerDigest(m)}
	return core.Candidate{ID: candidateID(string(core.SourceOfficialRegistry), id), Kind: core.KindMCP, Source: core.SourceOfficialRegistry, Name: name, Description: desc, Pin: pin, Transport: transport}, true
}

// officialRemote resolves the only official-registry remote shape the Agent
// can execute without changing its semantics: one header-free Streamable HTTP
// endpoint. The current runtime can add only its own Bearer header; registry
// header declarations (including optional or secret ones) are not enough to
// prove that transformation is lossless, so they fail closed.
func officialRemote(m map[string]any) (string, bool, error) {
	rs := rawSlice(m["remotes"])
	if len(rs) != 1 {
		return "", false, ErrUnsupported
	}
	rm := rawMap(rs[0])
	if rm == nil || strings.ToLower(strings.TrimSpace(rawString(rm, "type", "transport"))) != "streamable-http" {
		return "", false, ErrUnsupported
	}
	remote := rawString(rm, "url", "endpoint")
	if remote == "" {
		return "", false, ErrUnsupported
	}
	rawHeaders, hasHeaders := rm["headers"]
	headers := rawSlice(rawHeaders)
	if hasHeaders && headers == nil {
		return "", false, ErrUnsupported
	}
	if len(headers) != 0 {
		return "", false, ErrUnsupported
	}
	return remote, false, nil
}

func (a *OfficialRegistry) Inspect(ctx context.Context, req core.InspectRequest) (core.Inspection, error) {
	if req.Kind != core.KindMCP || req.Source != core.SourceOfficialRegistry || req.ID == "" || req.Pin.RegistryVersion == "" {
		return core.Inspection{}, core.ErrInvalid
	}
	name := req.ID
	if i := strings.LastIndex(name, "@"); i > 0 {
		name = name[:i]
	}
	path := "/v0.1/servers/" + url.PathEscape(name) + "/versions/" + url.PathEscape(req.Pin.RegistryVersion)
	b, err := a.c.get(ctx, path, nil)
	if err != nil {
		return core.Inspection{}, err
	}
	var m map[string]any
	if err := parseJSON(b, &m); err != nil {
		return core.Inspection{}, err
	}
	if sm, ok := m["server"].(map[string]any); ok {
		m = sm
	}
	cand, ok := registryCandidate(m)
	if !ok {
		return core.Inspection{}, ErrMalformed
	}
	if cand.Pin != req.Pin || cand.ID != req.ID {
		return core.Inspection{}, ErrMalformed
	}
	files := []rawFile{{Path: "manifest.json", Content: string(b), Digest: digestBytes(b)}}
	remote, requiresCredential, err := officialRemote(m)
	if err != nil {
		return core.Inspection{}, err
	}
	if err := a.c.validateRemote(ctx, remote); err != nil {
		return core.Inspection{}, err
	}
	i, _, err := baseInspection(cand, files, remote, requiresCredential)
	return i, err
}

func (a *OfficialRegistry) Fetch(ctx context.Context, c core.Candidate) (core.FetchArtifact, error) {
	b, err := a.c.get(ctx, "/v0.1/servers/"+url.PathEscape(c.Name)+"/versions/"+url.PathEscape(c.Pin.RegistryVersion), nil)
	if err != nil {
		return core.FetchArtifact{}, err
	}
	var m map[string]any
	if err := parseJSON(b, &m); err != nil {
		return core.FetchArtifact{}, err
	}
	if sm, ok := m["server"].(map[string]any); ok {
		m = sm
	}
	cand, ok := registryCandidate(m)
	if !ok || cand.ID != c.ID || cand.Pin != c.Pin {
		return core.FetchArtifact{}, ErrMalformed
	}
	remote, requiresCredential, err := officialRemote(m)
	if err != nil {
		return core.FetchArtifact{}, err
	}
	if err := a.c.validateRemote(ctx, remote); err != nil {
		return core.FetchArtifact{}, err
	}
	i, artifact, err := baseInspection(cand, []rawFile{{Path: "manifest.json", Content: string(b)}}, remote, requiresCredential)
	if err != nil {
		return core.FetchArtifact{}, err
	}
	return core.FetchArtifact{Candidate: i.Candidate, Content: artifact, ContentDigest: i.ContentDigest, ManifestDigest: i.ManifestDigest, Inspection: i}, nil
}

func itoa(v int) string {
	if v <= 0 {
		return ""
	}
	const d = "0123456789"
	b := make([]byte, 0, 8)
	for v > 0 {
		b = append([]byte{d[v%10]}, b...)
		v /= 10
	}
	return string(b)
}
