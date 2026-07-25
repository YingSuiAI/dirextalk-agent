package source

import (
	"context"
	"net/url"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

type Glama struct{ c *client }

var _ core.SourceAdapter = (*Glama)(nil)

func NewGlama(cfg HTTPConfig) (*Glama, error) {
	c, e := newProviderClient(cfg, GlamaAuthority)
	if e != nil {
		return nil, e
	}
	return &Glama{c: c}, nil
}
func NewGlamaForTest(cfg HTTPConfig) (*Glama, error) { cfg.TestOnly = true; return NewGlama(cfg) }
func (a *Glama) Search(ctx context.Context, q core.SearchQuery) (core.Page, error) {
	if q.Kind != "" && q.Kind != core.KindMCP || q.Source != "" && q.Source != core.SourceGlama {
		return core.Page{}, core.ErrInvalid
	}
	query := strings.TrimSpace(q.Text)
	n := q.PageSize
	if n <= 0 {
		n = 10
	}
	if n > 100 {
		return core.Page{}, core.ErrInvalid
	}
	cv, err := decodeCursorValue(q.PageToken, string(core.SourceGlama), query, string(core.KindMCP), n)
	if err != nil {
		return core.Page{}, err
	}
	v := url.Values{}
	if query != "" {
		v.Set("query", query)
	}
	v.Set("first", itoa(n))
	if cv.Remote != "" {
		v.Set("after", cv.Remote)
	}
	b, err := a.c.get(ctx, "/api/mcp/v1/servers", v)
	if err != nil {
		return core.Page{}, err
	}
	var root map[string]any
	if parseJSON(b, &root) != nil {
		return core.Page{}, ErrMalformed
	}
	container := root
	if d := rawMap(root["data"]); len(d) > 0 {
		container = d
	}
	obj := rawMap(container["servers"])
	arr := rawSlice(container["servers"])
	if arr == nil && obj != nil {
		arr = rawSlice(obj["nodes"])
	}
	if arr == nil {
		return core.Page{}, ErrMalformed
	}
	page := core.Page{}
	for _, x := range arr {
		c, ok := glamaCandidate(rawMap(x))
		if !ok {
			return core.Page{}, ErrMalformed
		}
		page.Candidates = append(page.Candidates, c)
	}
	pi := rawMap(obj["pageInfo"])
	if pi == nil {
		pi = rawMap(container["pageInfo"])
	}
	if rawString(pi, "endCursor") != "" || pi["hasNextPage"] == true {
		page.NextPageToken = encodeCursor(cursor{Source: string(core.SourceGlama), Kind: string(core.KindMCP), PageSize: n, Query: query, Offset: len(page.Candidates), Remote: rawString(pi, "endCursor")})
	}
	return page, nil
}
func glamaCandidate(m map[string]any) (core.Candidate, bool) {
	owner := rawString(m, "owner", "namespace", "organization")
	name := rawString(m, "name", "slug")
	if owner == "" || name == "" {
		if id := rawString(m, "id"); strings.Contains(id, "/") {
			p := strings.SplitN(id, "/", 2)
			owner, name = p[0], p[1]
		}
	}
	if owner == "" || name == "" {
		return core.Candidate{}, false
	}
	id := owner + "/" + name
	desc := rawString(m, "description", "summary")
	version := rawString(m, "version", "latestVersion")
	if version == "" || strings.EqualFold(version, "latest") {
		return core.Candidate{}, false
	}
	remote := rawString(m, "url", "endpoint", "serverUrl", "deploymentUrl")
	if remote == "" {
		if rs := rawSlice(m["remotes"]); len(rs) > 0 {
			rm := rawMap(rs[0])
			typ := strings.ToLower(rawString(rm, "type", "transport"))
			if strings.Contains(typ, "sse") || strings.Contains(typ, "template") {
				return core.Candidate{}, false
			}
			remote = rawString(rm, "url", "endpoint")
		}
	}
	t := core.TransportStdioStatic
	if remote != "" {
		t = core.TransportStreamableHTTP
	}
	return core.Candidate{ID: candidateID(string(core.SourceGlama), id), Kind: core.KindMCP, Source: core.SourceGlama, Name: id, Description: desc, Pin: core.SourcePin{RegistryVersion: version, RegistrySHA256: providerDigest(m)}, Transport: t}, true
}
func (a *Glama) Inspect(ctx context.Context, req core.InspectRequest) (core.Inspection, error) {
	if req.Kind != core.KindMCP || req.Source != core.SourceGlama || req.ID == "" || req.Pin.RegistryVersion == "" {
		return core.Inspection{}, core.ErrInvalid
	}
	id := req.ID
	if i := strings.Index(id, ":"); i >= 0 {
		id = id[i+1:]
	}
	parts := strings.SplitN(id, "/", 2)
	if len(parts) != 2 {
		return core.Inspection{}, core.ErrInvalid
	}
	b, err := a.c.get(ctx, "/api/mcp/v1/servers/"+url.PathEscape(parts[0])+"/"+url.PathEscape(parts[1]), nil)
	if err != nil {
		return core.Inspection{}, err
	}
	var m map[string]any
	if parseJSON(b, &m) != nil {
		return core.Inspection{}, ErrMalformed
	}
	if d := rawMap(m["data"]); len(d) > 0 {
		m = d
	}
	c, ok := glamaCandidate(m)
	if !ok {
		return core.Inspection{}, ErrMalformed
	}
	if c.ID != req.ID || c.Pin != req.Pin {
		return core.Inspection{}, ErrMalformed
	}
	remote := rawString(m, "url", "endpoint", "serverUrl", "deploymentUrl")
	if rs := rawSlice(m["remotes"]); remote == "" && len(rs) > 0 {
		rm := rawMap(rs[0])
		typ := strings.ToLower(rawString(rm, "type", "transport"))
		if strings.Contains(typ, "sse") || strings.Contains(typ, "template") {
			return core.Inspection{}, ErrUnsupported
		}
		remote = rawString(rm, "url", "endpoint")
	}
	if remote == "" {
		return core.Inspection{}, ErrUnsupported
	}
	if err := a.c.validateRemote(ctx, remote); err != nil {
		return core.Inspection{}, err
	}
	i, _, e := baseInspection(c, []rawFile{{Path: "manifest.json", Content: string(b), Digest: digestBytes(b)}}, remote)
	return i, e
}
func (a *Glama) Fetch(ctx context.Context, c core.Candidate) (core.FetchArtifact, error) {
	parts := strings.SplitN(c.ID, "/", 2)
	if len(parts) != 2 {
		return core.FetchArtifact{}, core.ErrInvalid
	}
	b, e := a.c.get(ctx, "/api/mcp/v1/servers/"+url.PathEscape(parts[0])+"/"+url.PathEscape(parts[1]), nil)
	if e != nil {
		return core.FetchArtifact{}, e
	}
	var m map[string]any
	if parseJSON(b, &m) != nil {
		return core.FetchArtifact{}, ErrMalformed
	}
	if d := rawMap(m["data"]); len(d) > 0 {
		m = d
	}
	cand, ok := glamaCandidate(m)
	if !ok || cand.ID != c.ID || cand.Pin != c.Pin {
		return core.FetchArtifact{}, ErrMalformed
	}
	remote := rawString(m, "url", "endpoint", "serverUrl", "deploymentUrl")
	if remote == "" {
		return core.FetchArtifact{}, ErrUnsupported
	}
	if err := a.c.validateRemote(ctx, remote); err != nil {
		return core.FetchArtifact{}, err
	}
	i, artifact, e := baseInspection(cand, []rawFile{{Path: "manifest.json", Content: string(b)}}, remote)
	if e != nil {
		return core.FetchArtifact{}, e
	}
	return core.FetchArtifact{Candidate: i.Candidate, Content: artifact, ContentDigest: i.ContentDigest, ManifestDigest: i.ManifestDigest, Inspection: i}, nil
}
