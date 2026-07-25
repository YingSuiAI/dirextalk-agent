package rpcapi

import (
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

func TestExecutableSkillMappingPreservesDescriptor(t *testing.T) {
	proto := &agentv1.CoreExecution{Descriptor_: &agentv1.CoreExecution_Skill{Skill: &agentv1.CoreSkillEntry{
		RelativePath: "entry", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Executable: true, Argv: []string{"--serve"},
	}}}
	domain := executionFrom(proto)
	if domain.Skill == nil || !domain.Skill.Executable || domain.Skill.RelativePath != "entry" || len(domain.Skill.Argv) != 1 || domain.Skill.Argv[0] != "--serve" {
		t.Fatalf("domain skill=%#v", domain.Skill)
	}
	roundTrip := executionTo(domain)
	got := roundTrip.GetSkill()
	if got == nil || !got.Executable || got.RelativePath != "entry" || len(got.Argv) != 1 || got.Argv[0] != "--serve" {
		t.Fatalf("round-trip skill=%#v", got)
	}
	if err := domain.Validate(coreextension.KindSkill, coreextension.TransportSkillStatic); err != nil {
		t.Fatalf("descriptor validation: %v", err)
	}
}
