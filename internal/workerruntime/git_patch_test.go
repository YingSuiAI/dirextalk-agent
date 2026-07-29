package workerruntime

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
)

func TestGitPatchCollectorIncludesTrackedAndUntrackedChanges(t *testing.T) {
	t.Parallel()
	process := &gitFakeProcess{
		outputs: [][]byte{
			[]byte("true\n"),
			[]byte("diff --git a/tracked.go b/tracked.go\n"),
			[]byte("new.go\x00"),
			[]byte("diff --git a/new.go b/new.go\n"),
		},
	}
	collector, err := NewGitPatchCollector("/usr/bin/git", process)
	if err != nil {
		t.Fatal(err)
	}
	patch, err := collector.Collect(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(patch)
	if !bytes.Contains(patch, []byte("tracked.go")) ||
		!bytes.Contains(patch, []byte("new.go")) ||
		process.calls != 4 ||
		!slices.Contains(process.specs[3].AllowedExitCodes, 1) {
		t.Fatalf("patch=%q calls=%d", patch, process.calls)
	}
}

func TestParseUntrackedPathsRejectsTraversalAndUnboundedLists(t *testing.T) {
	t.Parallel()
	for _, value := range [][]byte{
		[]byte("../outside\x00"),
		[]byte("/absolute\x00"),
		[]byte("duplicate\x00duplicate\x00"),
		[]byte("missing-terminator"),
	} {
		if _, err := parseUntrackedPaths(value); !errors.Is(err, ErrExecution) {
			t.Fatalf("unsafe untracked paths accepted: %q", value)
		}
	}
}

type gitFakeProcess struct {
	outputs [][]byte
	specs   []ProcessSpec
	calls   int
}

func (process *gitFakeProcess) Run(
	_ context.Context,
	spec ProcessSpec,
) (ProcessOutput, error) {
	process.specs = append(process.specs, cloneProcessSpec(spec))
	if process.calls >= len(process.outputs) {
		return ProcessOutput{}, ErrExecution
	}
	output := bytes.Clone(process.outputs[process.calls])
	process.calls++
	return ProcessOutput{Stdout: output}, nil
}
