package source

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

const NPMRegistryAuthority = "https://registry.npmjs.org"

type NPM struct {
	c        *client
	resolver NodeDependencyResolver
}

var _ core.SourceAdapter = (*NPM)(nil)

func NewNPM(cfg HTTPConfig, resolver NodeDependencyResolver) (*NPM, error) {
	if resolver == nil {
		return nil, errors.New("Node dependency resolver is required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = nodeResolveTimeout
	} else if cfg.Timeout > nodeResolveTimeout {
		return nil, errors.New("NPM source timeout exceeds limit")
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = nodeMaxInputBytes
	} else if cfg.MaxBodyBytes > nodeMaxInputBytes {
		return nil, errors.New("NPM source response limit exceeds maximum")
	}
	c, err := newProviderClient(cfg, NPMRegistryAuthority)
	if err != nil {
		return nil, err
	}
	return &NPM{c: c, resolver: resolver}, nil
}

func NewNPMForTest(cfg HTTPConfig, resolver NodeDependencyResolver) (*NPM, error) {
	cfg.TestOnly = true
	return NewNPM(cfg, resolver)
}

type npmPackument struct {
	Name        string                     `json:"name"`
	Description string                     `json:"description"`
	Versions    map[string]json.RawMessage `json:"versions"`
}

type npmVersionMetadata struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Dist        struct {
		Tarball   string `json:"tarball"`
		Integrity string `json:"integrity"`
		Shasum    string `json:"shasum"`
	} `json:"dist"`
}

type npmSearchResponse struct {
	Objects []struct {
		Package struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
		} `json:"package"`
	} `json:"objects"`
	Total int `json:"total"`
}

func (a *NPM) Search(ctx context.Context, query core.SearchQuery) (core.Page, error) {
	if query.Kind != "" && query.Kind != core.KindMCP || query.Source != "" && query.Source != core.SourceNPM {
		return core.Page{}, core.ErrInvalid
	}
	text := strings.TrimSpace(query.Text)
	if text == "" {
		return core.Page{}, core.ErrInvalid
	}
	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 10
	}
	if pageSize > 10 {
		return core.Page{}, core.ErrInvalid
	}
	cursorValue, err := decodeCursorValue(query.PageToken, string(core.SourceNPM), text, string(core.KindMCP), pageSize)
	if err != nil {
		return core.Page{}, err
	}
	values := url.Values{"text": []string{text}, "size": []string{itoa(pageSize)}, "from": []string{itoa(cursorValue.Offset)}}
	body, err := a.c.get(ctx, "/-/v1/search", values)
	if err != nil {
		return core.Page{}, err
	}
	var response npmSearchResponse
	if parseJSON(body, &response) != nil || response.Objects == nil || response.Total < 0 {
		return core.Page{}, ErrMalformed
	}
	page := core.Page{}
	for _, object := range response.Objects {
		name, version := object.Package.Name, object.Package.Version
		if !canonicalNPMPackageName(name) || !exactNodeSemver(version) {
			return core.Page{}, ErrMalformed
		}
		metadata, _, _, directSHA256, _, inspectErr := a.inspectDirectPackage(ctx, name, version)
		if inspectErr != nil {
			if errors.Is(inspectErr, ErrUnsupported) || errors.Is(inspectErr, ErrOversize) {
				continue
			}
			return core.Page{}, inspectErr
		}
		description := metadata.Description
		if description == "" {
			description = object.Package.Description
		}
		page.Candidates = append(page.Candidates, core.Candidate{
			ID: name, Kind: core.KindMCP, Source: core.SourceNPM, Name: name, Description: description,
			Pin: core.SourcePin{RegistryVersion: version, RegistrySHA256: directSHA256}, Transport: core.TransportStdioNode,
		})
	}
	consumed := len(response.Objects)
	if cursorValue.Offset+consumed < response.Total && consumed > 0 {
		page.NextPageToken = encodeCursor(cursor{Source: string(core.SourceNPM), Kind: string(core.KindMCP), Query: text, PageSize: pageSize, Offset: cursorValue.Offset + consumed})
	}
	return page, nil
}

func (a *NPM) Inspect(ctx context.Context, request core.InspectRequest) (core.Inspection, error) {
	if request.Kind != core.KindMCP || request.Source != core.SourceNPM || !canonicalNPMPackageName(request.ID) || !exactNodeSemver(request.Pin.RegistryVersion) || !validHexDigest(request.Pin.RegistrySHA256) {
		return core.Inspection{}, core.ErrInvalid
	}
	inspection, _, err := a.inspectPackage(ctx, request.ID, request.Pin, true)
	return inspection, err
}

func (a *NPM) Fetch(ctx context.Context, candidate core.Candidate) (core.FetchArtifact, error) {
	if candidate.Validate() != nil || candidate.Source != core.SourceNPM || candidate.Transport != core.TransportStdioNode {
		return core.FetchArtifact{}, core.ErrInvalid
	}
	inspection, artifact, err := a.inspectPackage(ctx, candidate.ID, candidate.Pin, true)
	if err != nil {
		return core.FetchArtifact{}, err
	}
	if inspection.Candidate != candidate {
		return core.FetchArtifact{}, ErrMalformed
	}
	return core.FetchArtifact{Candidate: candidate, Content: artifact, ContentDigest: inspection.ContentDigest, ManifestDigest: inspection.ManifestDigest, Inspection: inspection}, nil
}

func (a *NPM) inspectPackage(ctx context.Context, packageName string, pin core.SourcePin, verifyPin bool) (core.Inspection, []byte, error) {
	metadata, exactMetadata, tarball, tarSHA256Hex, direct, err := a.inspectDirectPackage(ctx, packageName, pin.RegistryVersion)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	if verifyPin && tarSHA256Hex != pin.RegistrySHA256 {
		return core.Inspection{}, nil, ErrMalformed
	}
	rootPackageJSON, err := managedNPMRootPackage(packageName, pin.RegistryVersion)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	resolution, err := a.resolver.Resolve(ctx, NodeDependencyRequest{
		Source: core.SourceNPM, PackageName: packageName, PackageVersion: pin.RegistryVersion,
		RootPackageJSON: rootPackageJSON, DirectTarball: append([]byte(nil), tarball...), DirectTarballSHA256: tarSHA256Hex,
	})
	if err != nil {
		return core.Inspection{}, nil, err
	}
	_, cacheFiles, bindings, err := validateNodeResolution(NodeDependencyRequest{Source: core.SourceNPM, PackageName: packageName, PackageVersion: pin.RegistryVersion, RootPackageJSON: rootPackageJSON}, resolution)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	lock, err := compactJSON(resolution.PackageLock)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	exactMetadata, err = compactJSON(exactMetadata)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	entryPath := "node_modules/" + packageName + "/" + direct.EntryPath
	manifest := nodeSourceManifest{
		SchemaVersion: "dirextalk.node-source/v1", Source: string(core.SourceNPM), PackageName: packageName, PackageVersion: pin.RegistryVersion,
		EntryPath: entryPath, EntrySHA256: direct.EntryDigest, LockSHA256: digestBytes(lock), DirectTarSHA256: tarSHA256Hex,
		RegistryMeta: exactMetadata, Tarballs: bindings,
	}
	manifestBytes, _ := json.Marshal(manifest)
	files := append(cacheFiles,
		rawFile{Path: "package.json", Content: string(rootPackageJSON)},
		rawFile{Path: "package-lock.json", Content: string(lock)},
		rawFile{Path: nodeSourceManifestPath, Content: string(manifestBytes)},
	)
	resolvedPin := pin
	resolvedPin.RegistrySHA256 = tarSHA256Hex
	candidate := core.Candidate{ID: packageName, Kind: core.KindMCP, Source: core.SourceNPM, Name: packageName, Description: metadata.Description, Pin: resolvedPin, Transport: core.TransportStdioNode}
	return buildNodeInspection(candidate, entryPath, direct.EntryDigest, []string{}, files)
}

func (a *NPM) inspectDirectPackage(ctx context.Context, packageName, version string) (npmVersionMetadata, []byte, []byte, string, inspectedNodePackage, error) {
	metadata, exactMetadata, err := a.loadVersionMetadata(ctx, packageName, version)
	if err != nil {
		return npmVersionMetadata{}, nil, nil, "", inspectedNodePackage{}, err
	}
	tarball, err := a.downloadTarball(ctx, metadata.Dist.Tarball)
	if err != nil {
		return npmVersionMetadata{}, nil, nil, "", inspectedNodePackage{}, err
	}
	if err := verifyNPMDist(metadata, tarball); err != nil {
		return npmVersionMetadata{}, nil, nil, "", inspectedNodePackage{}, err
	}
	packageFiles, err := parseNPMPackageTarball(tarball)
	if err != nil {
		return npmVersionMetadata{}, nil, nil, "", inspectedNodePackage{}, err
	}
	direct, err := inspectNodePackage(packageFiles, false, packageName, version)
	if err != nil {
		return npmVersionMetadata{}, nil, nil, "", inspectedNodePackage{}, err
	}
	sum := sha256.Sum256(tarball)
	return metadata, exactMetadata, tarball, hex.EncodeToString(sum[:]), direct, nil
}

func (a *NPM) loadVersionMetadata(ctx context.Context, packageName, version string) (npmVersionMetadata, []byte, error) {
	if !canonicalNPMPackageName(packageName) || !exactNodeSemver(version) {
		return npmVersionMetadata{}, nil, core.ErrInvalid
	}
	body, err := a.c.get(ctx, "/"+packageName, nil)
	if err != nil {
		return npmVersionMetadata{}, nil, err
	}
	var packument npmPackument
	if parseJSON(body, &packument) != nil || packument.Name != packageName || packument.Versions == nil {
		return npmVersionMetadata{}, nil, ErrMalformed
	}
	raw, found := packument.Versions[version]
	if !found || len(raw) == 0 {
		return npmVersionMetadata{}, nil, ErrMalformed
	}
	var metadata npmVersionMetadata
	if parseJSON(raw, &metadata) != nil || metadata.Name != packageName || metadata.Version != version || metadata.Dist.Tarball == "" {
		return npmVersionMetadata{}, nil, ErrMalformed
	}
	if metadata.Description == "" {
		metadata.Description = packument.Description
	}
	return metadata, append([]byte(nil), raw...), nil
}

func (a *NPM) downloadTarball(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != a.c.base.Scheme || !strings.EqualFold(parsed.Host, a.c.base.Host) || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || !strings.HasSuffix(strings.ToLower(parsed.Path), ".tgz") {
		return nil, ErrUnsupported
	}
	requestCtx, cancel := context.WithTimeout(ctx, a.c.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return nil, ErrMalformed
	}
	request.Header.Set("Accept", "application/octet-stream")
	if a.c.token != "" {
		request.Header.Set("Authorization", "Bearer "+a.c.token)
	}
	response, err := a.c.http.Do(request)
	if err != nil {
		if errors.Is(err, ErrRedirect) {
			return nil, ErrRedirect
		}
		return nil, errors.New("NPM tarball request failed")
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusUnauthorized || response.StatusCode == http.StatusForbidden {
		return nil, ErrUnauthorized
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, errors.New("NPM tarball request failed")
	}
	if response.ContentLength > nodeMaxInputBytes {
		return nil, ErrOversize
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, nodeMaxInputBytes+1))
	if err != nil {
		return nil, errors.New("NPM tarball response read failed")
	}
	if int64(len(body)) > nodeMaxInputBytes {
		return nil, ErrOversize
	}
	return body, nil
}

func verifyNPMDist(metadata npmVersionMetadata, tarball []byte) error {
	verified := false
	if metadata.Dist.Integrity != "" {
		if err := verifySRI(metadata.Dist.Integrity, tarball); err != nil {
			return err
		}
		verified = true
	}
	if metadata.Dist.Shasum != "" {
		if len(metadata.Dist.Shasum) != 40 || strings.Trim(metadata.Dist.Shasum, "0123456789abcdef") != "" {
			return ErrMalformed
		}
		sum := sha1.Sum(tarball)
		if hex.EncodeToString(sum[:]) != metadata.Dist.Shasum {
			return ErrMalformed
		}
		verified = true
	}
	if !verified {
		return ErrUnsupported
	}
	return nil
}

func managedNPMRootPackage(packageName, version string) ([]byte, error) {
	if !canonicalNPMPackageName(packageName) || !exactNodeSemver(version) {
		return nil, core.ErrInvalid
	}
	root := struct {
		Name         string            `json:"name"`
		Version      string            `json:"version"`
		Private      bool              `json:"private"`
		Dependencies map[string]string `json:"dependencies"`
	}{Name: "dirextalk-managed-mcp", Version: "0.0.0", Private: true, Dependencies: map[string]string{packageName: version}}
	return json.Marshal(root)
}

func canonicalResolutionTarballPaths(files []rawFile) []string {
	paths := make([]string, 0)
	for _, file := range files {
		if strings.HasPrefix(file.Path, nodeTarballDir+"/") {
			paths = append(paths, file.Path)
		}
	}
	sort.Strings(paths)
	return paths
}

func equalCompactJSON(left, right []byte) bool {
	a, errA := compactJSON(left)
	b, errB := compactJSON(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}
