package source

import (
	"context"
	"net/url"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

type SkillsSh struct{ c *client }

var _ core.SourceAdapter = (*SkillsSh)(nil)

func NewSkillsSh(cfg HTTPConfig) (*SkillsSh, error) {
	c, e := newProviderClient(cfg, SkillsShAuthority)
	if e != nil {
		return nil, e
	}
	return &SkillsSh{c: c}, nil
}
func NewSkillsShForTest(cfg HTTPConfig) (*SkillsSh, error) {
	cfg.TestOnly = true
	return NewSkillsSh(cfg)
}
func (a *SkillsSh) Search(ctx context.Context, q core.SearchQuery) (core.Page, error) {
	if q.Kind != "" && q.Kind != core.KindSkill || q.Source != "" && q.Source != core.SourceSkillsSh {
		return core.Page{}, core.ErrInvalid
	}
	query := strings.TrimSpace(q.Text)
	ps := q.PageSize
	if ps < 0 || ps > 100 {
		return core.Page{}, core.ErrInvalid
	}
	cv, err := decodeCursorValue(q.PageToken, string(core.SourceSkillsSh), query, string(core.KindSkill), ps)
	if err != nil {
		return core.Page{}, err
	}
	v := url.Values{}
	v.Set("q", query)
	if q.PageSize > 0 {
		v.Set("limit", itoa(q.PageSize))
	}
	off := cv.Offset
	if cv.Remote != "" {
		v.Set("cursor", cv.Remote)
	} else if off > 0 {
		v.Set("offset", itoa(off))
	}
	b, err := a.c.get(ctx, "/api/v1/skills/search", v)
	if err != nil {
		return core.Page{}, err
	}
	var root map[string]any
	if parseJSON(b, &root) != nil {
		return core.Page{}, ErrMalformed
	}
	arr := rawSlice(root["skills"])
	if arr == nil {
		arr = rawSlice(root["results"])
	}
	if arr == nil {
		return core.Page{}, ErrMalformed
	}
	page := core.Page{}
	for _, x := range arr {
		m := rawMap(x)
		source := rawString(m, "source", "repository", "repo")
		name := rawString(m, "skill", "name", "slug")
		if source == "" || name == "" {
			return core.Page{}, ErrMalformed
		}
		ver := rawString(m, "version", "ref")
		h := rawString(m, "sha256", "digest", "hash")
		if ver == "" || strings.EqualFold(ver, "latest") || !validDigest(h) {
			return core.Page{}, ErrMalformed
		}
		page.Candidates = append(page.Candidates, core.Candidate{ID: source + "/" + name, Kind: core.KindSkill, Source: core.SourceSkillsSh, Name: source + "/" + name, Description: rawString(m, "description", "summary"), Pin: core.SourcePin{RegistryVersion: ver, RegistrySHA256: h}, Transport: core.TransportSkillStatic})
	}
	next := rawString(root, "nextCursor", "next_cursor")
	if next == "" {
		if p := rawMap(root["pagination"]); p != nil {
			next = rawString(p, "nextCursor", "next_cursor")
		}
	}
	if next != "" || len(page.Candidates) > 0 {
		page.NextPageToken = encodeCursor(cursor{Source: string(core.SourceSkillsSh), Kind: string(core.KindSkill), PageSize: ps, Query: query, Offset: off + len(page.Candidates), Remote: next})
	}
	return page, nil
}
func (a *SkillsSh) Inspect(ctx context.Context, req core.InspectRequest) (core.Inspection, error) {
	if req.Kind != core.KindSkill || req.Source != core.SourceSkillsSh || req.ID == "" || req.Pin.RegistryVersion == "" || !validDigest(req.Pin.RegistrySHA256) {
		return core.Inspection{}, core.ErrInvalid
	}
	parts := strings.SplitN(req.ID, "/", 2)
	if len(parts) != 2 {
		return core.Inspection{}, core.ErrInvalid
	}
	b, err := a.c.get(ctx, "/api/v1/skills/"+url.PathEscape(parts[0])+"/"+url.PathEscape(parts[1]), nil)
	if err != nil {
		return core.Inspection{}, err
	}
	root, files, e := parseSkillPayload(b)
	if e != nil {
		return core.Inspection{}, e
	}
	c := core.Candidate{ID: req.ID, Kind: core.KindSkill, Source: core.SourceSkillsSh, Name: req.ID, Description: rawString(root, "description", "summary"), Pin: req.Pin, Transport: core.TransportSkillStatic}
	i, _, e := baseInspection(c, files, "", false)
	if e != nil {
		return core.Inspection{}, e
	}
	// The catalog hash is only accepted when it matches the recomputed
	// canonical file representation; a floating skill ID is never sufficient.
	if req.Pin.RegistrySHA256 != i.ManifestDigest && req.Pin.RegistrySHA256 != i.ContentDigest {
		return core.Inspection{}, ErrMalformed
	}
	return i, nil
}
func (a *SkillsSh) Fetch(ctx context.Context, c core.Candidate) (core.FetchArtifact, error) {
	parts := strings.SplitN(c.ID, "/", 2)
	if len(parts) != 2 {
		return core.FetchArtifact{}, core.ErrInvalid
	}
	b, e := a.c.get(ctx, "/api/v1/skills/"+url.PathEscape(parts[0])+"/"+url.PathEscape(parts[1]), nil)
	if e != nil {
		return core.FetchArtifact{}, e
	}
	root, files, e := parseSkillPayload(b)
	if e != nil {
		return core.FetchArtifact{}, e
	}
	c.Description = rawString(root, "description", "summary")
	i, artifact, e := baseInspection(c, files, "", false)
	if e != nil {
		return core.FetchArtifact{}, e
	}
	if c.Pin.RegistrySHA256 != i.ManifestDigest && c.Pin.RegistrySHA256 != i.ContentDigest {
		return core.FetchArtifact{}, ErrMalformed
	}
	return core.FetchArtifact{Candidate: i.Candidate, Content: artifact, ContentDigest: i.ContentDigest, ManifestDigest: i.ManifestDigest, Inspection: i}, nil
}
func parseSkillPayload(b []byte) (map[string]any, []rawFile, error) {
	var root map[string]any
	if parseJSON(b, &root) != nil {
		return nil, nil, ErrMalformed
	}
	if d := rawMap(root["skill"]); len(d) > 0 {
		root = d
	}
	files := []rawFile{}
	if arr := rawSlice(root["files"]); arr != nil {
		for _, x := range arr {
			m := rawMap(x)
			p := rawExactString(m, "path", "name")
			content := rawExactString(m, "content", "text")
			if content == "" {
				content = rawExactString(m, "body")
			}
			files = append(files, rawFile{Path: p, Content: content, Digest: rawString(m, "sha256", "digest", "hash"), Symlink: rawString(m, "type") == "symlink"})
		}
	}
	if len(files) == 0 {
		if sk := rawExactString(root, "content", "skill"); sk != "" {
			files = []rawFile{{Path: "SKILL.md", Content: sk}}
		}
	}
	if len(files) == 0 {
		return nil, nil, ErrMalformed
	}
	return root, files, nil
}
func validDigest(s string) bool { return len(s) == 64 && strings.Trim(s, "0123456789abcdef") == "" }
