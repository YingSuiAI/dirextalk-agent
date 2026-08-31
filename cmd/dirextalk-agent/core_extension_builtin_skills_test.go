package main

import (
	"context"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension/source"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
)

type builtinSeedStoreFake struct {
	seeded  map[string]bool
	ensured int
}

func (s *builtinSeedStoreFake) BuiltinSkillSeeded(_ context.Context, candidateID string) (bool, error) {
	return s.seeded[candidateID], nil
}

func (s *builtinSeedStoreFake) EnsureBuiltinSkill(_ context.Context, artifact coreextension.FetchArtifact, digest string) (coreextension.Installation, error) {
	s.ensured++
	s.seeded[artifact.Candidate.ID] = true
	return coreextension.Installation{
		ID: "00000000-0000-4000-8000-000000000001", Candidate: artifact.Candidate,
		Kind: coreextension.KindSkill, Source: coreextension.SourceBuiltin,
		CandidateID: artifact.Candidate.ID, State: coreextension.StateInstalled,
		Enabled: true, ActiveVersionID: "00000000-0000-4000-8000-000000000002",
	}, nil
}

type builtinPublisherFake struct{ calls int }

func (p *builtinPublisherFake) Publish(_ context.Context, entries []extensionrunner.ManifestEntry, _ []extensionrunner.PublishFile) (extensionrunner.PublishResponse, error) {
	p.calls++
	return extensionrunner.PublishResponse{Digest: extensionrunner.ManifestDigest(entries)}, nil
}

type builtinMCPSeedStoreFake struct {
	ensured int
}

func (s *builtinMCPSeedStoreFake) EnsureBuiltinMCP(_ context.Context, artifact coreextension.FetchArtifact, _ string) (coreextension.Installation, error) {
	s.ensured++
	return coreextension.Installation{ID: "00000000-0000-4000-8000-000000000011", Candidate: artifact.Candidate, Kind: coreextension.KindMCP, Source: coreextension.SourceBuiltin, CandidateID: artifact.Candidate.ID, State: coreextension.StateInstalled, Enabled: true, ActiveVersionID: "00000000-0000-4000-8000-000000000012"}, nil
}

func TestEnsureDefaultBuiltinSkillsSeedsOnceAndHonorsRemovalFence(t *testing.T) {
	catalog, err := source.NewBuiltinSkills()
	if err != nil {
		t.Fatal(err)
	}
	store := &builtinSeedStoreFake{seeded: map[string]bool{}}
	publisher := &builtinPublisherFake{}
	if err := ensureDefaultBuiltinSkills(context.Background(), store, catalog, t.TempDir(), publisher); err != nil {
		t.Fatal(err)
	}
	if store.ensured != 5 || publisher.calls != 5 {
		t.Fatalf("first seed ensured=%d published=%d", store.ensured, publisher.calls)
	}
	// The durable seed survives uninstall. A restart must neither republish nor
	// recreate a removed default Skill.
	store.ensured = 0
	publisher.calls = 0
	if err := ensureDefaultBuiltinSkills(context.Background(), store, catalog, t.TempDir(), publisher); err != nil {
		t.Fatal(err)
	}
	if store.ensured != 0 || publisher.calls != 0 {
		t.Fatalf("restart recreated defaults: ensured=%d published=%d", store.ensured, publisher.calls)
	}
}

func TestEnsureDefaultBuiltinMCPsReconcilesShippedArtifacts(t *testing.T) {
	catalog, err := source.NewBuiltinMCPs([]byte("ELF fixture"), []byte("shell fixture"))
	if err != nil {
		t.Fatal(err)
	}
	store := &builtinMCPSeedStoreFake{}
	publisher := &builtinPublisherFake{}
	if err := ensureDefaultBuiltinMCPs(context.Background(), store, catalog, t.TempDir(), publisher); err != nil {
		t.Fatal(err)
	}
	if store.ensured != 3 || publisher.calls != 3 {
		t.Fatalf("first seed ensured=%d published=%d", store.ensured, publisher.calls)
	}
	store.ensured = 0
	publisher.calls = 0
	if err := ensureDefaultBuiltinMCPs(context.Background(), store, catalog, t.TempDir(), publisher); err != nil {
		t.Fatal(err)
	}
	if store.ensured != 3 || publisher.calls != 3 {
		t.Fatalf("restart did not reconcile defaults: ensured=%d published=%d", store.ensured, publisher.calls)
	}
}
