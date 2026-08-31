package source

import (
	"context"
	"embed"
	"io/fs"
	"sort"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

const builtinSkillVersion = "1.0.1"

//go:embed builtin_skills/*/SKILL.md builtin_skills/*/agents/openai.yaml
var builtinSkillFiles embed.FS

type builtinSkillDefinition struct {
	ID          string
	Directory   string
	Description string
}

var builtinSkillDefinitions = []builtinSkillDefinition{
	{ID: "dirextalk-research-and-verify", Directory: "research-and-verify", Description: "Research current topics and verify claims with authoritative sources."},
	{ID: "dirextalk-review-code", Directory: "review-code", Description: "Review code for correctness, security, reliability, and missing tests."},
	{ID: "dirextalk-size-model-deployment", Directory: "size-model-deployment", Description: "Verify model workloads and calculate accelerator, memory, storage, and server capacity."},
	{ID: "dirextalk-verify-delivery", Directory: "verify-delivery", Description: "Turn requirements into evidence-backed acceptance and release checks."},
	{ID: "dirextalk-write-technical-docs", Directory: "write-technical-docs", Description: "Create accurate API guides, runbooks, and architecture documentation."},
}

// BuiltinSkills is the immutable, network-free source for Dirextalk-owned
// default Skills. Installation and removal still use the normal extension
// lifecycle; the source only supplies reviewed bytes and exact pins.
type BuiltinSkills struct {
	artifacts map[string]core.FetchArtifact
	ordered   []core.Candidate
}

var _ core.SourceAdapter = (*BuiltinSkills)(nil)

func NewBuiltinSkills() (*BuiltinSkills, error) {
	adapter := &BuiltinSkills{artifacts: make(map[string]core.FetchArtifact, len(builtinSkillDefinitions))}
	for _, definition := range builtinSkillDefinitions {
		files, err := readBuiltinSkillFiles(definition.Directory)
		if err != nil {
			return nil, err
		}
		candidate := core.Candidate{
			ID: definition.ID, Kind: core.KindSkill, Source: core.SourceBuiltin,
			Name: definition.ID, Description: definition.Description,
			Pin:       core.SourcePin{RegistryVersion: builtinSkillVersion, RegistrySHA256: strings.Repeat("0", 64)},
			Transport: core.TransportSkillStatic,
		}
		inspection, _, err := baseInspection(candidate, files, "", false)
		if err != nil {
			return nil, err
		}
		candidate.Pin.RegistrySHA256 = inspection.ContentDigest
		inspection, content, err := baseInspection(candidate, files, "", false)
		if err != nil {
			return nil, err
		}
		artifact := core.FetchArtifact{Candidate: candidate, Content: content, ContentDigest: inspection.ContentDigest, ManifestDigest: inspection.ManifestDigest, Inspection: inspection}
		if err := artifact.Validate(); err != nil {
			return nil, err
		}
		adapter.artifacts[definition.ID] = artifact
		adapter.ordered = append(adapter.ordered, candidate)
	}
	sort.Slice(adapter.ordered, func(i, j int) bool { return adapter.ordered[i].ID < adapter.ordered[j].ID })
	return adapter, nil
}

func readBuiltinSkillFiles(id string) ([]rawFile, error) {
	root := "builtin_skills/" + id
	files := []rawFile{}
	err := fs.WalkDir(builtinSkillFiles, root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		body, readErr := fs.ReadFile(builtinSkillFiles, filePath)
		if readErr != nil {
			return readErr
		}
		files = append(files, rawFile{Path: strings.TrimPrefix(filePath, root+"/"), Content: string(body)})
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, ErrMalformed
	}
	return files, nil
}

func (a *BuiltinSkills) Search(_ context.Context, query core.SearchQuery) (core.Page, error) {
	if a == nil || query.Kind != "" && query.Kind != core.KindSkill || query.Source != "" && query.Source != core.SourceBuiltin || query.PageSize < 0 || query.PageSize > 100 || query.PageToken != "" {
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

func (a *BuiltinSkills) Inspect(_ context.Context, request core.InspectRequest) (core.Inspection, error) {
	if a == nil || request.Kind != core.KindSkill || request.Source != core.SourceBuiltin {
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

func (a *BuiltinSkills) Fetch(_ context.Context, candidate core.Candidate) (core.FetchArtifact, error) {
	if a == nil || candidate.Source != core.SourceBuiltin || candidate.Kind != core.KindSkill {
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

func (a *BuiltinSkills) Artifacts() []core.FetchArtifact {
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
