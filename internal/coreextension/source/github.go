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

type GitHub struct {
	c        *client
	resolver NodeDependencyResolver
}

var _ core.SourceAdapter = (*GitHub)(nil)

func NewGitHub(cfg HTTPConfig) (*GitHub, error) {
	return newGitHub(cfg, nil)
}

func NewGitHubWithNodeResolver(cfg HTTPConfig, resolver NodeDependencyResolver) (*GitHub, error) {
	if resolver == nil {
		return nil, fmt.Errorf("Node dependency resolver is required")
	}
	if cfg.MaxBodyBytes == 0 {
		cfg.MaxBodyBytes = nodeMaxInputBytes
	}
	return newGitHub(cfg, resolver)
}

func newGitHub(cfg HTTPConfig, resolver NodeDependencyResolver) (*GitHub, error) {
	c, e := newProviderClient(cfg, GitHubAuthority)
	if e != nil {
		return nil, e
	}
	return &GitHub{c: c, resolver: resolver}, nil
}
func NewGitHubForTest(cfg HTTPConfig) (*GitHub, error) { cfg.TestOnly = true; return NewGitHub(cfg) }
func NewGitHubForTestWithNodeResolver(cfg HTTPConfig, resolver NodeDependencyResolver) (*GitHub, error) {
	cfg.TestOnly = true
	return NewGitHubWithNodeResolver(cfg, resolver)
}

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
		if kind == core.KindMCP {
			candidate, node, preflightErr := a.preflightNodeRepo(ctx, r.FullName, pin)
			if preflightErr != nil {
				if preflightErr == ErrUnsupported || preflightErr == ErrOversize {
					continue
				}
				return core.Page{}, preflightErr
			}
			if node {
				page.Candidates = append(page.Candidates, candidate)
				continue
			}
		}
		ins, _, e := a.inspectRepo(ctx, r.FullName, kind, pin, false)
		if e != nil {
			if e == ErrUnsupported || e == ErrOversize {
				continue
			}
			return core.Page{}, e
		}
		pin.GitSHA256 = ins.ContentDigest
		candidate := ins.Candidate
		candidate.Pin = pin
		page.Candidates = append(page.Candidates, candidate)
	}
	if len(root.Items) == ps {
		page.NextPageToken = encodeCursor(cursor{Source: string(core.SourceGitHub), Kind: string(q.Kind), PageSize: ps, Query: query, Offset: cv.Offset + len(root.Items)})
	}
	return page, nil
}

func (a *GitHub) inspectRepo(ctx context.Context, repo string, kind core.Kind, pin core.SourcePin, verify bool) (core.Inspection, []byte, error) {
	tr, err := a.loadTree(ctx, repo, pin.GitCommit)
	if err != nil {
		return core.Inspection{}, nil, err
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
	if kind == core.KindMCP && hasRawFile(files, "package.json") {
		if remote != "" {
			return core.Inspection{}, nil, ErrUnsupported
		}
		return a.inspectNodeRepo(ctx, repo, pin, verify, files)
	}
	c := core.Candidate{ID: repo, Kind: core.Kind(kind), Source: core.SourceGitHub, Name: repo, Pin: pin, Transport: transport}
	if remote != "" {
		if err := a.c.validateRemote(ctx, remote); err != nil {
			return core.Inspection{}, nil, err
		}
	}
	i, artifact, e := baseInspectionLimit(c, files, remote, true, a.c.max)
	if e != nil {
		return core.Inspection{}, nil, e
	}
	if verify && i.ContentDigest != pin.GitSHA256 {
		return core.Inspection{}, nil, ErrMalformed
	}
	i.Candidate.Pin.GitSHA256 = i.ContentDigest
	return i, artifact, nil
}

func (a *GitHub) loadTree(ctx context.Context, repo, commit string) (githubTreeResponse, error) {
	treeBytes, err := a.c.get(ctx, "/repos/"+repo+"/git/trees/"+strings.ToLower(commit), url.Values{"recursive": []string{"1"}})
	if err != nil {
		return githubTreeResponse{}, err
	}
	var tree githubTreeResponse
	if err := decodeStrict(treeBytes, &tree); err != nil {
		return githubTreeResponse{}, err
	}
	if tree.Truncated || len(tree.Tree) > 10000 {
		return githubTreeResponse{}, ErrOversize
	}
	if tree.SHA == "" {
		return githubTreeResponse{}, ErrMalformed
	}
	return tree, nil
}

func (a *GitHub) preflightNodeRepo(ctx context.Context, repo string, pin core.SourcePin) (core.Candidate, bool, error) {
	tree, err := a.loadTree(ctx, repo, pin.GitCommit)
	if err != nil {
		return core.Candidate{}, false, err
	}
	entries := make(map[string]githubTreeEntry, len(tree.Tree))
	for _, entry := range tree.Tree {
		if entry.Path == "" {
			return core.Candidate{}, false, ErrMalformed
		}
		if entry.Type == "tree" {
			continue
		}
		if entry.Type != "blob" || entry.Mode == "120000" || entry.Mode == "160000" || !fullCommit(entry.SHA) {
			return core.Candidate{}, false, ErrUnsupported
		}
		if _, duplicate := entries[entry.Path]; duplicate {
			return core.Candidate{}, false, ErrMalformed
		}
		entries[entry.Path] = entry
	}
	packageEntry, node := entries["package.json"]
	if !node {
		return core.Candidate{}, false, nil
	}
	if len(entries) > nodeMaxInputFiles {
		return core.Candidate{}, true, ErrOversize
	}
	if _, exists := entries[nodeSourceManifestPath]; exists {
		return core.Candidate{}, true, ErrUnsupported
	}
	for filePath := range entries {
		lower := strings.ToLower(filePath)
		if strings.HasPrefix(filePath, nodeTarballDir+"/") || isNativeNodePath(lower) {
			return core.Candidate{}, true, ErrUnsupported
		}
	}
	lockEntry, exists := entries["package-lock.json"]
	if !exists {
		return core.Candidate{}, true, ErrUnsupported
	}
	packageBytes, err := a.fetchBlob(ctx, repo, packageEntry, pin.GitCommit)
	if err != nil {
		return core.Candidate{}, true, err
	}
	var manifest nodePackageJSON
	if parseJSON(packageBytes, &manifest) != nil || !canonicalNPMPackageName(manifest.Name) || !exactNodeSemver(manifest.Version) || manifest.Gypfile {
		return core.Candidate{}, true, ErrUnsupported
	}
	entryPath, err := nodePackageEntry(manifest)
	if err != nil || !isPublishedJavaScript(entryPath) {
		return core.Candidate{}, true, ErrUnsupported
	}
	executionEntry, exists := entries[entryPath]
	if !exists {
		return core.Candidate{}, true, ErrUnsupported
	}
	lockBytes, err := a.fetchBlob(ctx, repo, lockEntry, pin.GitCommit)
	if err != nil {
		return core.Candidate{}, true, err
	}
	executionBytes, err := a.fetchBlob(ctx, repo, executionEntry, pin.GitCommit)
	if err != nil {
		return core.Candidate{}, true, err
	}
	if _, err := inspectNodePackage([]rawFile{
		{Path: "package.json", Content: string(packageBytes)},
		{Path: "package-lock.json", Content: string(lockBytes)},
		{Path: entryPath, Content: string(executionBytes)},
	}, true, "", ""); err != nil {
		return core.Candidate{}, true, err
	}
	return core.Candidate{
		ID: repo, Kind: core.KindMCP, Source: core.SourceGitHub, Name: repo,
		Pin: pin, Transport: core.TransportStdioNode,
	}, true, nil
}

func hasRawFile(files []rawFile, name string) bool {
	for _, file := range files {
		if file.Path == name {
			return true
		}
	}
	return false
}

func (a *GitHub) inspectNodeRepo(ctx context.Context, repo string, pin core.SourcePin, verify bool, files []rawFile) (core.Inspection, []byte, error) {
	if a.resolver == nil {
		return core.Inspection{}, nil, ErrUnsupported
	}
	if len(files) > nodeMaxInputFiles || hasRawFile(files, nodeSourceManifestPath) {
		return core.Inspection{}, nil, ErrUnsupported
	}
	for _, file := range files {
		if strings.HasPrefix(file.Path, nodeTarballDir+"/") {
			return core.Inspection{}, nil, ErrUnsupported
		}
	}
	direct, err := inspectNodePackage(files, true, "", "")
	if err != nil {
		return core.Inspection{}, nil, err
	}
	request := NodeDependencyRequest{
		Source: core.SourceGitHub, PackageName: direct.Name, PackageVersion: direct.Version,
		RootPackageJSON: append([]byte(nil), direct.PackageJSON...), ExistingPackageLock: append([]byte(nil), direct.PackageLock...),
	}
	resolution, err := a.resolver.Resolve(ctx, request)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	if !equalCompactJSON(direct.PackageLock, resolution.PackageLock) {
		return core.Inspection{}, nil, ErrMalformed
	}
	_, cacheFiles, bindings, err := validateNodeResolution(request, resolution)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	lock, err := compactJSON(resolution.PackageLock)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	manifest := nodeSourceManifest{
		SchemaVersion: "dirextalk.node-source/v1", Source: string(core.SourceGitHub), PackageName: direct.Name, PackageVersion: direct.Version,
		GitCommit: strings.ToLower(pin.GitCommit), EntryPath: direct.EntryPath, EntrySHA256: direct.EntryDigest,
		LockSHA256: digestBytes(lock), Tarballs: bindings,
	}
	manifestBytes, _ := json.Marshal(manifest)
	canonicalFiles := make([]rawFile, 0, len(files)+len(cacheFiles)+1)
	for _, file := range files {
		if file.Path == "package-lock.json" {
			file.Content = string(lock)
		}
		canonicalFiles = append(canonicalFiles, file)
	}
	canonicalFiles = append(canonicalFiles, cacheFiles...)
	canonicalFiles = append(canonicalFiles, rawFile{Path: nodeSourceManifestPath, Content: string(manifestBytes)})
	candidate := core.Candidate{ID: repo, Kind: core.KindMCP, Source: core.SourceGitHub, Name: repo, Pin: pin, Transport: core.TransportStdioNode}
	inspection, artifact, err := buildNodeInspection(candidate, direct.EntryPath, direct.EntryDigest, nil, canonicalFiles)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	if verify && pin.GitSHA256 != digestBytes([]byte(strings.ToLower(pin.GitCommit))) {
		return core.Inspection{}, nil, ErrMalformed
	}
	return inspection, artifact, nil
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
