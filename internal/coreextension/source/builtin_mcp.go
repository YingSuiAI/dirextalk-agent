package source

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

const builtinMCPVersion = "1.0.0"

type builtinMCPDefinition struct {
	ID          string
	Description string
	Argv        []string
}

var builtinMCPDefinitions = []builtinMCPDefinition{
	{ID: core.BuiltinLocalSandboxCandidateID, Description: "Run a small offline shell task in the local isolated sandbox (30 CPU seconds, 256 MiB memory, 32 processes, 16 MiB files, no network).", Argv: []string{"entry", "local_sandbox"}},
	{ID: "dirextalk-server-load", Description: "Read the server load, uptime, process count, and memory totals.", Argv: []string{"entry", "server_load"}},
	{ID: "dirextalk-server-time", Description: "Read the current server time in UTC.", Argv: []string{"entry", "server_time"}},
}

// BuiltinMCPs is the immutable, network-free source for Dirextalk-owned
// read-only default MCP servers. Each artifact executes through the ordinary
// isolated extension-runner path.
type BuiltinMCPs struct {
	artifacts map[string]core.FetchArtifact
	ordered   []core.Candidate
}

var _ core.SourceAdapter = (*BuiltinMCPs)(nil)

func NewBuiltinMCPs(executable, shell []byte) (*BuiltinMCPs, error) {
	if len(executable) == 0 || len(shell) == 0 {
		return nil, ErrMalformed
	}
	adapter := &BuiltinMCPs{artifacts: make(map[string]core.FetchArtifact, len(builtinMCPDefinitions))}
	for _, definition := range builtinMCPDefinitions {
		candidate := core.Candidate{
			ID: definition.ID, Kind: core.KindMCP, Source: core.SourceBuiltin,
			Name: definition.ID, Description: definition.Description,
			Pin:       core.SourcePin{RegistryVersion: builtinMCPVersion, RegistrySHA256: strings.Repeat("0", 64)},
			Transport: core.TransportStdioStatic,
		}
		artifact, err := builtinMCPArtifact(candidate, executable, shell, definition.Argv)
		if err != nil {
			return nil, err
		}
		candidate.Pin.RegistrySHA256 = artifact.ContentDigest
		artifact, err = builtinMCPArtifact(candidate, executable, shell, definition.Argv)
		if err != nil {
			return nil, err
		}
		if err := artifact.Validate(); err != nil {
			return nil, err
		}
		adapter.artifacts[definition.ID] = artifact
		adapter.ordered = append(adapter.ordered, candidate)
	}
	sort.Slice(adapter.ordered, func(i, j int) bool { return adapter.ordered[i].ID < adapter.ordered[j].ID })
	return adapter, nil
}

func builtinMCPArtifact(candidate core.Candidate, executable, shell []byte, argv []string) (core.FetchArtifact, error) {
	identity := []byte(candidate.ID + "\n")
	entryDigest := digestBytes(executable)
	manifestFiles := []map[string]string{
		{"path": "entry", "digest": entryDigest},
		{"path": "identity", "digest": digestBytes(identity)},
	}
	contentFiles := []canonicalContentFile{
		{Path: "entry", Content: base64.RawStdEncoding.EncodeToString(executable)},
		{Path: "identity", Content: base64.RawStdEncoding.EncodeToString(identity)},
	}
	if candidate.ID == core.BuiltinLocalSandboxCandidateID {
		manifestFiles = append(manifestFiles, map[string]string{"path": "shell", "digest": digestBytes(shell)})
		contentFiles = append(contentFiles, canonicalContentFile{Path: "shell", Content: base64.RawStdEncoding.EncodeToString(shell)})
	}
	manifest, _ := json.Marshal(manifestFiles)
	content, _ := json.Marshal(contentFiles)
	execution := core.ExecutionDescriptor{Stdio: &core.StaticEntry{RelativePath: "entry", Digest: entryDigest, Argv: append([]string(nil), argv...)}}
	inspection := core.Inspection{
		Candidate: candidate, ContentDigest: digestBytes(content), ManifestDigest: digestBytes(manifest),
		ExecutionDigest: digestJSON(execution), NetworkSchemaDigest: digestBytes([]byte("[]")), SecretSchemaDigest: digestBytes([]byte("[]")),
		Execution: execution, NetworkGrants: []core.NetworkGrant{}, SecretGrants: []core.SecretGrantDescriptor{},
	}
	artifact := core.FetchArtifact{Candidate: candidate, Content: content, ContentDigest: inspection.ContentDigest, ManifestDigest: inspection.ManifestDigest, Inspection: inspection}
	if err := artifact.Validate(); err != nil {
		return core.FetchArtifact{}, err
	}
	return artifact, nil
}

func (a *BuiltinMCPs) Search(_ context.Context, query core.SearchQuery) (core.Page, error) {
	if a == nil || query.Kind != "" && query.Kind != core.KindMCP || query.Source != "" && query.Source != core.SourceBuiltin || query.PageSize < 0 || query.PageSize > 100 || query.PageToken != "" {
		return core.Page{}, core.ErrInvalid
	}
	needle := strings.ToLower(strings.TrimSpace(query.Text))
	limit := query.PageSize
	if limit == 0 {
		limit = 50
	}
	page := core.Page{}
	for _, candidate := range a.ordered {
		if needle != "" && !strings.Contains(strings.ToLower(candidate.ID+" "+candidate.Name+" "+candidate.Description), needle) {
			continue
		}
		page.Candidates = append(page.Candidates, candidate)
		if len(page.Candidates) == limit {
			break
		}
	}
	return page, nil
}

func (a *BuiltinMCPs) Inspect(_ context.Context, request core.InspectRequest) (core.Inspection, error) {
	if a == nil || request.Kind != core.KindMCP || request.Source != core.SourceBuiltin {
		return core.Inspection{}, core.ErrInvalid
	}
	artifact, ok := a.artifacts[request.ID]
	if !ok {
		return core.Inspection{}, core.ErrNotFound
	}
	if request.Pin != artifact.Candidate.Pin {
		return core.Inspection{}, core.ErrConflict
	}
	return artifact.Inspection, nil
}

func (a *BuiltinMCPs) Fetch(_ context.Context, candidate core.Candidate) (core.FetchArtifact, error) {
	if a == nil || candidate.Source != core.SourceBuiltin || candidate.Kind != core.KindMCP {
		return core.FetchArtifact{}, core.ErrInvalid
	}
	artifact, ok := a.artifacts[candidate.ID]
	if !ok {
		return core.FetchArtifact{}, core.ErrNotFound
	}
	if candidate != artifact.Candidate {
		return core.FetchArtifact{}, core.ErrConflict
	}
	artifact.Content = append([]byte(nil), artifact.Content...)
	return artifact, nil
}

func (a *BuiltinMCPs) Artifacts() []core.FetchArtifact {
	if a == nil {
		return nil
	}
	out := make([]core.FetchArtifact, 0, len(a.ordered))
	for _, candidate := range a.ordered {
		artifact := a.artifacts[candidate.ID]
		artifact.Content = append([]byte(nil), artifact.Content...)
		out = append(out, artifact)
	}
	return out
}

// BuiltinCatalog routes the shared builtin source by extension kind.
type BuiltinCatalog struct {
	Skills *BuiltinSkills
	MCPs   *BuiltinMCPs
}

var _ core.SourceAdapter = (*BuiltinCatalog)(nil)

func (a *BuiltinCatalog) adapter(kind core.Kind) (core.SourceAdapter, error) {
	if a == nil {
		return nil, core.ErrInvalid
	}
	switch kind {
	case core.KindSkill:
		if a.Skills != nil {
			return a.Skills, nil
		}
	case core.KindMCP:
		if a.MCPs != nil {
			return a.MCPs, nil
		}
	}
	return nil, core.ErrInvalid
}

func (a *BuiltinCatalog) Search(ctx context.Context, query core.SearchQuery) (core.Page, error) {
	adapter, err := a.adapter(query.Kind)
	if err != nil {
		return core.Page{}, err
	}
	return adapter.Search(ctx, query)
}

func (a *BuiltinCatalog) Inspect(ctx context.Context, request core.InspectRequest) (core.Inspection, error) {
	adapter, err := a.adapter(request.Kind)
	if err != nil {
		return core.Inspection{}, err
	}
	return adapter.Inspect(ctx, request)
}

func (a *BuiltinCatalog) Fetch(ctx context.Context, candidate core.Candidate) (core.FetchArtifact, error) {
	adapter, err := a.adapter(candidate.Kind)
	if err != nil {
		return core.FetchArtifact{}, err
	}
	return adapter.Fetch(ctx, candidate)
}
