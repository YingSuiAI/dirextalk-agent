package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

func TestExtensionExecutionTargetClosedBranches(t *testing.T) {
	digest := strings.Repeat("a", 64)
	tests := []struct {
		name       string
		descriptor coreextension.ExecutionDescriptor
		want       coretask.ExtensionExecutionTarget
	}{
		{name: "stdio MCP", descriptor: coreextension.ExecutionDescriptor{Stdio: &coreextension.StaticEntry{RelativePath: "entry", Digest: digest, Argv: []string{"entry"}}}, want: coretask.ExtensionExecutionTargetLocalSandbox},
		{name: "executable Skill", descriptor: coreextension.ExecutionDescriptor{Skill: &coreextension.SkillEntry{RelativePath: "entry", Digest: digest, Executable: true, Argv: []string{"entry"}}}, want: coretask.ExtensionExecutionTargetLocalSandbox},
		{name: "static Skill", descriptor: coreextension.ExecutionDescriptor{Skill: &coreextension.SkillEntry{RelativePath: "SKILL.md", Digest: digest}}, want: coretask.ExtensionExecutionTargetStaticSkill},
		{name: "remote MCP", descriptor: coreextension.ExecutionDescriptor{Remote: &coreextension.RemoteEndpoint{URL: "https://example.test/mcp"}}, want: coretask.ExtensionExecutionTargetRemoteExtension},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := extensionExecutionTarget(test.descriptor)
			if err != nil || got != test.want {
				t.Fatalf("target=%q err=%v want=%q", got, err, test.want)
			}
		})
	}
	if got, err := extensionExecutionTarget(coreextension.ExecutionDescriptor{}); got != "" || !errors.Is(err, coreextension.ErrConflict) {
		t.Fatalf("empty descriptor target=%q err=%v", got, err)
	}
	if got, err := extensionExecutionTarget(coreextension.ExecutionDescriptor{Stdio: &coreextension.StaticEntry{}, Remote: &coreextension.RemoteEndpoint{}}); got != "" || !errors.Is(err, coreextension.ErrConflict) {
		t.Fatalf("multi-branch descriptor target=%q err=%v", got, err)
	}
}
