package source

import (
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

type GitHub struct{ c *client }

var _ core.SourceAdapter = (*GitHub)(nil)

func NewGitHub(cfg HTTPConfig) (*GitHub, error) {
	c, e := newProviderClient(cfg, GitHubAuthority)
	if e != nil {
		return nil, e
	}
	return &GitHub{c: c}, nil
}
func NewGitHubForTest(cfg HTTPConfig) (*GitHub, error) { cfg.TestOnly = true; return NewGitHub(cfg) }

type githubTreeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	SHA  string `json:"sha"`
	URL  string `json:"url"`
	Size int64  `json:"size"`
}
type githubTreeResponse struct {
	SHA       string            `json:"sha"`
	URL       string            `json:"url"`
	Size      int64             `json:"size"`
	Tree      []githubTreeEntry `json:"tree"`
	Truncated bool              `json:"truncated"`
}

func decodeStrict(b []byte, out any) error {
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		return ErrMalformed
	}
	var x any
	if d.Decode(&x) != io.EOF {
		return ErrMalformed
	}
	return nil
}

func (a *GitHub) Search(ctx context.Context, q core.SearchQuery) (core.Page, error) {
	if q.Kind != "" && q.Kind != core.KindMCP && q.Kind != core.KindSkill || q.Source != "" && q.Source != core.SourceGitHub {
		return core.Page{}, core.ErrInvalid
	}
	query := strings.TrimSpace(q.Text)
	ps := q.PageSize
	if ps <= 0 {
		ps = 30
	}
	if ps > 100 {
		return core.Page{}, core.ErrInvalid
	}
	cv, err := decodeCursorValue(q.PageToken, string(core.SourceGitHub), query, string(q.Kind), ps)
	if err != nil {
		return core.Page{}, err
	}
	v := url.Values{"q": []string{query}, "per_page": []string{itoa(ps)}}
	if cv.Offset > 0 {
		v.Set("page", itoa(cv.Offset/ps+1))
	}
	b, err := a.c.get(ctx, "/search/repositories", v)
	if err != nil {
		return core.Page{}, err
	}
	var root struct {
		Items []struct {
			FullName      string `json:"full_name"`
			Description   string `json:"description"`
			DefaultBranch string `json:"default_branch"`
		} `json:"items"`
	}
	if err := parseJSON(b, &root); err != nil {
		return core.Page{}, err
	}
	page := core.Page{}
	for _, r := range root.Items {
		if !strings.Contains(r.FullName, "/") {
			return core.Page{}, ErrMalformed
		}
		branch := r.DefaultBranch
		if branch == "" {
			branch = "HEAD"
		}
		cb, e := a.c.get(ctx, "/repos/"+r.FullName+"/commits/"+url.PathEscape(branch), nil)
		if e != nil {
			return core.Page{}, e
		}
		var cm struct {
			SHA string `json:"sha"`
		}
		if parseJSON(cb, &cm) != nil || !fullCommit(cm.SHA) {
			return core.Page{}, ErrMalformed
		}
		pin := core.SourcePin{GitCommit: strings.ToLower(cm.SHA), GitSHA256: digestBytes([]byte(strings.ToLower(cm.SHA)))}
		kind := q.Kind
		if kind == "" {
			kind = core.KindMCP
		}
		ins, _, e := a.inspectRepo(ctx, r.FullName, kind, pin, false)
		if e != nil {
			return core.Page{}, e
		}
		pin.GitSHA256 = ins.ContentDigest
		transport := ins.Candidate.Transport
		page.Candidates = append(page.Candidates, core.Candidate{ID: r.FullName, Kind: kind, Source: core.SourceGitHub, Name: r.FullName, Description: r.Description, Pin: pin, Transport: transport})
	}
	if len(root.Items) == ps {
		page.NextPageToken = encodeCursor(cursor{Source: string(core.SourceGitHub), Kind: string(q.Kind), PageSize: ps, Query: query, Offset: cv.Offset + len(root.Items)})
	}
	return page, nil
}

func (a *GitHub) inspectRepo(ctx context.Context, repo string, kind core.Kind, pin core.SourcePin, verify bool) (core.Inspection, []byte, error) {
	treeB, err := a.c.get(ctx, "/repos/"+repo+"/git/trees/"+strings.ToLower(pin.GitCommit), url.Values{"recursive": []string{"1"}})
	if err != nil {
		return core.Inspection{}, nil, err
	}
	var tr githubTreeResponse
	if err := decodeStrict(treeB, &tr); err != nil {
		return core.Inspection{}, nil, err
	}
	if tr.Truncated {
		return core.Inspection{}, nil, ErrOversize
	}
	if tr.SHA == "" {
		return core.Inspection{}, nil, ErrMalformed
	}
	if len(tr.Tree) > 10000 {
		return core.Inspection{}, nil, ErrOversize
	}
	files := make([]rawFile, 0, len(tr.Tree))
	for _, e := range tr.Tree {
		if e.Path == "" {
			return core.Inspection{}, nil, ErrMalformed
		}
		if e.Type == "tree" {
			continue
		}
		if e.Type != "blob" || e.Mode == "120000" || e.Mode == "160000" || e.Type == "commit" {
			return core.Inspection{}, nil, ErrUnsupported
		}
		if !fullCommit(e.SHA) {
			return core.Inspection{}, nil, ErrMalformed
		}
		data, e2 := a.fetchBlob(ctx, repo, e, pin.GitCommit)
		if e2 != nil {
			return core.Inspection{}, nil, e2
		}
		if int64(len(data)) > a.c.max {
			return core.Inspection{}, nil, ErrOversize
		}
		files = append(files, rawFile{Path: e.Path, Content: string(data), Mode: e.Mode})
	}
	transport := core.TransportStdioStatic
	remote := ""
	if kind == core.KindSkill {
		transport = core.TransportSkillStatic
	}
	for _, f := range files {
		if strings.EqualFold(f.Path, "SKILL.md") || strings.HasSuffix(strings.ToLower(f.Path), "/skill.md") {
			kind = core.KindSkill
			transport = core.TransportSkillStatic
		}
		if strings.HasSuffix(strings.ToLower(f.Path), "mcp.json") || strings.HasSuffix(strings.ToLower(f.Path), "manifest.json") {
			var mm map[string]any
			if parseJSON([]byte(f.Content), &mm) == nil {
				typ := strings.ToLower(rawString(mm, "transport", "type"))
				if strings.Contains(typ, "sse") || strings.Contains(typ, "template") {
					return core.Inspection{}, nil, ErrUnsupported
				}
				remote = rawString(mm, "url", "endpoint", "deploymentUrl")
			}
		}
	}
	c := core.Candidate{ID: repo, Kind: core.Kind(kind), Source: core.SourceGitHub, Name: repo, Pin: pin, Transport: transport}
	if remote != "" {
		if err := a.c.validateRemote(ctx, remote); err != nil {
			return core.Inspection{}, nil, err
		}
	}
	i, artifact, e := baseInspectionLimit(c, files, remote, a.c.max)
	if e != nil {
		return core.Inspection{}, nil, e
	}
	if verify && i.ContentDigest != pin.GitSHA256 {
		return core.Inspection{}, nil, ErrMalformed
	}
	i.Candidate.Pin.GitSHA256 = i.ContentDigest
	return i, artifact, nil
}

func (a *GitHub) fetchBlob(ctx context.Context, repo string, e githubTreeEntry, commit string) ([]byte, error) {
	if e.SHA == "" {
		return nil, ErrMalformed
	}
	if b, err := a.c.get(ctx, "/repos/"+repo+"/git/blobs/"+e.SHA, nil); err == nil {
		var v struct {
			Content  string `json:"content"`
			Encoding string `json:"encoding"`
		}
		if parseJSON(b, &v) != nil || v.Encoding != "base64" {
			return nil, ErrMalformed
		}
		data, er := base64.StdEncoding.DecodeString(strings.ReplaceAll(v.Content, "\n", ""))
		if er != nil {
			return nil, ErrMalformed
		}
		if fullBlobSHA(data) != e.SHA {
			return nil, ErrMalformed
		}
		return data, nil
	}
	b, err := a.c.get(ctx, "/repos/"+repo+"/contents/"+url.PathEscape(e.Path), url.Values{"ref": []string{strings.ToLower(commit)}})
	if err != nil {
		return nil, err
	}
	var v map[string]any
	if parseJSON(b, &v) != nil {
		return nil, ErrMalformed
	}
	enc, ok := v["content"].(string)
	if !ok {
		return nil, ErrUnsupported
	}
	data, er := base64.StdEncoding.DecodeString(strings.ReplaceAll(enc, "\n", ""))
	if er != nil {
		return nil, ErrMalformed
	}
	if fullBlobSHA(data) != e.SHA {
		return nil, ErrMalformed
	}
	return data, nil
}
func fullBlobSHA(data []byte) string {
	h := sha1.New()
	fmt.Fprintf(h, "blob %d\x00", len(data))
	h.Write(data)
	return fmt.Sprintf("%x", h.Sum(nil))
}
func (a *GitHub) Inspect(ctx context.Context, req core.InspectRequest) (core.Inspection, error) {
	if req.Source != core.SourceGitHub || req.ID == "" || !fullCommit(req.Pin.GitCommit) {
		return core.Inspection{}, core.ErrInvalid
	}
	if !strings.Contains(req.ID, "/") || strings.ContainsAny(req.ID, " \t\r\n") || strings.Count(req.ID, "/") != 1 {
		return core.Inspection{}, core.ErrInvalid
	}
	i, _, e := a.inspectRepo(ctx, req.ID, req.Kind, req.Pin, true)
	return i, e
}
func (a *GitHub) Fetch(ctx context.Context, c core.Candidate) (core.FetchArtifact, error) {
	i, artifact, e := a.inspectRepo(ctx, c.ID, c.Kind, c.Pin, true)
	if e != nil {
		return core.FetchArtifact{}, e
	}
	return core.FetchArtifact{Candidate: i.Candidate, Content: artifact, ContentDigest: i.ContentDigest, ManifestDigest: i.ManifestDigest, Inspection: i}, nil
}
