package source

import (
	"context"
	"net/url"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

type Smithery struct{ c *client }

var _ core.SourceAdapter = (*Smithery)(nil)

func NewSmithery(cfg HTTPConfig) (*Smithery, error) {
	c, e := newProviderClient(cfg, SmitheryAuthority)
	if e != nil {
		return nil, e
	}
	return &Smithery{c: c}, nil
}
func NewSmitheryForTest(cfg HTTPConfig) (*Smithery, error) {
	cfg.TestOnly = true
	return NewSmithery(cfg)
}

func (a *Smithery) Search(ctx context.Context, q core.SearchQuery) (core.Page, error) {
	if q.Kind != "" && q.Kind != core.KindMCP || q.Source != "" && q.Source != core.SourceSmithery {
		return core.Page{}, core.ErrInvalid
	}
	query := strings.TrimSpace(q.Text)
	ps := q.PageSize
	if ps < 0 || ps > 100 {
		return core.Page{}, core.ErrInvalid
	}
	cv, err := decodeCursorValue(q.PageToken, string(core.SourceSmithery), query, string(core.KindMCP), ps)
	if err != nil {
		return core.Page{}, err
	}
	v := url.Values{}
	if query != "" {
		v.Set("q", query)
	}
	if q.PageSize > 0 {
		v.Set("pageSize", itoa(q.PageSize))
	}
	off := cv.Offset
	if cv.Remote != "" {
		v.Set("cursor", cv.Remote)
	} else if off > 0 {
		v.Set("cursor", itoa(off))
	}
	b, err := a.c.get(ctx, "/servers", v)
	if err != nil {
		return core.Page{}, err
	}
	var root map[string]any
	if parseJSON(b, &root) != nil {
		return core.Page{}, ErrMalformed
	}
	arr := rawSlice(root["servers"])
	if arr == nil {
		arr = rawSlice(root["items"])
	}
	if arr == nil {
		return core.Page{}, ErrMalformed
	}
	page := core.Page{}
	for _, x := range arr {
		c, ok := smitheryCandidate(rawMap(x))
		if !ok {
			return core.Page{}, ErrMalformed
		}
		page.Candidates = append(page.Candidates, c)
	}
	next := rawString(root, "nextCursor", "next_cursor")
	if next == "" {
		if p := rawMap(root["pagination"]); p != nil {
			next = rawString(p, "nextCursor", "next_cursor")
		}
	}
	if next != "" {
		page.NextPageToken = encodeCursor(cursor{Source: string(core.SourceSmithery), Kind: string(core.KindMCP), PageSize: ps, Query: query, Offset: off + len(page.Candidates), Remote: next})
	}
	return page, nil
}

func smitheryCandidate(m map[string]any) (core.Candidate, bool) {
	id := rawString(m, "qualifiedName", "name")
	if id == "" {
		return core.Candidate{}, false
	}
	name := rawString(m, "displayName", "name")
	desc := rawString(m, "description")
	version := rawString(m, "version", "latestVersion")
	if version == "" || strings.EqualFold(version, "latest") {
		return core.Candidate{}, false
	}
	remote := rawString(m, "deploymentUrl", "deploymentURL")
	if remote == "" {
		if cs := rawSlice(m["connections"]); len(cs) > 0 {
			cm := rawMap(cs[0])
			typ := strings.ToLower(rawString(cm, "type", "transport"))
			if strings.Contains(typ, "sse") || strings.Contains(typ, "template") {
				return core.Candidate{}, false
			}
			if strings.Contains(typ, "http") {
				remote = rawString(cm, "url", "endpoint", "deploymentUrl")
			}
		}
	}
	t := core.TransportStdioStatic
	if remote != "" {
		t = core.TransportStreamableHTTP
	}
	return core.Candidate{ID: candidateID(string(core.SourceSmithery), id), Kind: core.KindMCP, Source: core.SourceSmithery, Name: name, Description: desc, Pin: core.SourcePin{RegistryVersion: version, RegistrySHA256: providerDigest(m)}, Transport: t}, true
}
func (a *Smithery) Inspect(ctx context.Context, req core.InspectRequest) (core.Inspection, error) {
	if req.Kind != core.KindMCP || req.Source != core.SourceSmithery || req.ID == "" || req.Pin.RegistryVersion == "" {
		return core.Inspection{}, core.ErrInvalid
	}
	id := req.ID
	if i := strings.LastIndex(id, "@"); i > 0 {
		id = id[:i]
	}
	b, err := a.c.get(ctx, "/servers/"+url.PathEscape(id), nil)
	if err != nil {
		return core.Inspection{}, err
	}
	var m map[string]any
	if parseJSON(b, &m) != nil {
		return core.Inspection{}, ErrMalformed
	}
	c, ok := smitheryCandidate(m)
	if !ok {
		return core.Inspection{}, ErrMalformed
	}
	if c.ID != req.ID || c.Pin != req.Pin {
		return core.Inspection{}, ErrMalformed
	}
	remote := rawString(m, "deploymentUrl", "deploymentURL")
	if remote == "" {
		if cs := rawSlice(m["connections"]); len(cs) > 0 {
			cm := rawMap(cs[0])
			typ := strings.ToLower(rawString(cm, "type", "transport"))
			if strings.Contains(typ, "sse") || strings.Contains(typ, "template") {
				return core.Inspection{}, ErrUnsupported
			}
			remote = rawString(cm, "url", "endpoint", "deploymentUrl")
		}
	}
	if remote == "" {
		return core.Inspection{}, ErrUnsupported
	}
	if err := a.c.validateRemote(ctx, remote); err != nil {
		return core.Inspection{}, err
	}
	files := []rawFile{{Path: "manifest.json", Content: string(b), Digest: digestBytes(b)}}
	i, _, e := baseInspection(c, files, remote, true)
	return i, e
}
func (a *Smithery) Fetch(ctx context.Context, c core.Candidate) (core.FetchArtifact, error) {
	b, e := a.c.get(ctx, "/servers/"+url.PathEscape(c.ID), nil)
	if e != nil {
		return core.FetchArtifact{}, e
	}
	var m map[string]any
	if parseJSON(b, &m) != nil {
		return core.FetchArtifact{}, ErrMalformed
	}
	cand, ok := smitheryCandidate(m)
	if !ok || cand.ID != c.ID || cand.Pin != c.Pin {
		return core.FetchArtifact{}, ErrMalformed
	}
	remote := rawString(m, "deploymentUrl", "deploymentURL")
	if remote == "" {
		if cs := rawSlice(m["connections"]); len(cs) > 0 {
			remote = rawString(rawMap(cs[0]), "url", "endpoint")
		}
	}
	if remote == "" {
		return core.FetchArtifact{}, ErrUnsupported
	}
	if err := a.c.validateRemote(ctx, remote); err != nil {
		return core.FetchArtifact{}, err
	}
	i, artifact, e := baseInspection(cand, []rawFile{{Path: "manifest.json", Content: string(b)}}, remote, true)
	if e != nil {
		return core.FetchArtifact{}, e
	}
	return core.FetchArtifact{Candidate: i.Candidate, Content: artifact, ContentDigest: i.ContentDigest, ManifestDigest: i.ManifestDigest, Inspection: i}, nil
}
