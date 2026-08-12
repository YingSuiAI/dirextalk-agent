package coreextension

import "testing"

func TestCanonicalInspectionProjectsExplicitArraysWithoutMutatingInput(t *testing.T) {
	entry := &StaticEntry{RelativePath: "entry", Runtime: "node"}
	input := Inspection{Execution: ExecutionDescriptor{Stdio: entry}}

	got := canonicalInspection(input)
	if got.NetworkGrants == nil || got.SecretGrants == nil || got.Execution.Stdio == nil || got.Execution.Stdio.Argv == nil {
		t.Fatalf("canonical inspection retained null arrays: %#v", got)
	}
	if len(got.NetworkGrants) != 0 || len(got.SecretGrants) != 0 || len(got.Execution.Stdio.Argv) != 0 {
		t.Fatalf("canonical inspection changed empty array values: %#v", got)
	}
	if input.NetworkGrants != nil || input.SecretGrants != nil || input.Execution.Stdio.Argv != nil || got.Execution.Stdio == input.Execution.Stdio {
		t.Fatal("canonical inspection mutated or aliased the source descriptor")
	}
}
