package teamorchestration

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

func TestStaticPolicyResolverLoadsProtectedCanonicalPolicy(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "team-policy.json")
	document := staticPolicyDocumentFixture()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver, err := LoadStaticPolicyResolver(path)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := resolver.ResolveTeamPolicy(
		context.Background(),
		"owner-a",
	)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := policy.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if resolver.Revision() != digest ||
		policy.MaxWorkers != document.MaxWorkers {
		t.Fatalf(
			"resolver revision/policy = %q/%#v",
			resolver.Revision(),
			policy,
		)
	}
	policy.AllowedRuntimeFamilies[0] = teamplan.RuntimeOpenClaw
	second, err := resolver.ResolveTeamPolicy(
		context.Background(),
		"owner-a",
	)
	if err != nil ||
		second.AllowedRuntimeFamilies[0] != teamplan.RuntimeCodex {
		t.Fatalf("resolver exposed mutable policy: %#v error=%v", second, err)
	}
}

func TestStaticPolicyResolverRejectsUnsafeOrMalformedFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	document := staticPolicyDocumentFixture()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	valid := filepath.Join(directory, "valid.json")
	if err := os.WriteFile(valid, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink.json")
	if err := os.Symlink(valid, symlink); err != nil {
		t.Fatal(err)
	}
	writable := filepath.Join(directory, "writable.json")
	if err := os.WriteFile(writable, raw, 0o622); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o622); err != nil {
		t.Fatal(err)
	}
	unknown := filepath.Join(directory, "unknown.json")
	unknownRaw := append(
		append([]byte(nil), raw[:len(raw)-1]...),
		[]byte(`,"model_api_key":"forbidden"}`)...,
	)
	if err := os.WriteFile(unknown, unknownRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"symlink":        symlink,
		"group writable": writable,
		"unknown secret": unknown,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := LoadStaticPolicyResolver(path); !errors.Is(
				err,
				ErrInvalid,
			) {
				t.Fatalf(
					"LoadStaticPolicyResolver() error = %v, want ErrInvalid",
					err,
				)
			}
		})
	}
}

func staticPolicyDocumentFixture() StaticPolicyDocument {
	return StaticPolicyDocument{
		SchemaVersion:             StaticPolicySchemaV1,
		MaxWorkers:                4,
		MaxConcurrentWorkers:      3,
		MaxRoleDurationSeconds:    4 * 60 * 60,
		MaxVCPUPerWorker:          8,
		MaxMemoryMiBPerWorker:     16 * 1024,
		MaxDiskGiBPerWorker:       200,
		MaxPlanCostMicros:         100_000_000,
		SafetyMarginBasisPoints:   2000,
		FixedWorkerOverheadMicros: 10_000,
		AllowedRuntimeFamilies: []teamplan.RuntimeFamily{
			teamplan.RuntimeCodex,
			teamplan.RuntimeHermes,
		},
	}
}
