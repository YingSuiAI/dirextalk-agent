package releaseartifact

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const (
	testRevision = "0123456789abcdef0123456789abcdef01234567"
	testTag      = "v0.1.0-alpha.20260717.1-0123456789ab"
)

func TestReleaseManifestV1NormalizeAndDigestGolden(t *testing.T) {
	input := validManifest()
	input.SchemaVersion = "  " + SchemaVersionV1 + "  "
	input.GeneratedAt = "2026-07-17T08:09:10+08:00"

	normalized, err := Normalize(input)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if normalized.SchemaVersion != SchemaVersionV1 {
		t.Fatalf("SchemaVersion = %q", normalized.SchemaVersion)
	}
	if normalized.GeneratedAt != "2026-07-17T00:09:10Z" {
		t.Fatalf("GeneratedAt = %q", normalized.GeneratedAt)
	}

	first, err := normalized.CanonicalCBOR()
	if err != nil {
		t.Fatalf("CanonicalCBOR() error = %v", err)
	}
	second, err := normalized.CanonicalCBOR()
	if err != nil {
		t.Fatalf("CanonicalCBOR() second error = %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("CanonicalCBOR() is not deterministic")
	}
	digest, err := normalized.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	const wantDigest = "sha256:4d857c07fe586277f3f0094f4104b5020b3142173c6b3fba46cfd2e97a4135a3"
	if digest != wantDigest {
		t.Fatalf("Digest() = %q, want %q", digest, wantDigest)
	}
}

func TestReleaseManifestV1RejectsMutableOrUnboundArtifacts(t *testing.T) {
	otherTag := "v0.1.0-alpha.20260717.2-0123456789ab"
	tests := []struct {
		name   string
		mutate func(*ReleaseManifestV1)
	}{
		{name: "missing image digest", mutate: func(m *ReleaseManifestV1) { m.AgentImage = "registry.example/dirextalk-agent:" + testTag }},
		{name: "latest tag", mutate: func(m *ReleaseManifestV1) { m.AgentImage = imageRef("dirextalk-agent", "latest", 'a') }},
		{name: "forbidden v1.0.3", mutate: func(m *ReleaseManifestV1) { m.ReleaseTag = "v1.0.3" }},
		{name: "stable tag", mutate: func(m *ReleaseManifestV1) { m.ReleaseTag = "v0.2.0" }},
		{name: "tag digest binding mismatch", mutate: func(m *ReleaseManifestV1) { m.WorkerImage = imageRef("dirextalk-worker", otherTag, 'b') }},
		{name: "wrong revision suffix", mutate: func(m *ReleaseManifestV1) { m.ReleaseTag = "v0.1.0-alpha.20260717.1-fedcba987654" }},
		{name: "short revision", mutate: func(m *ReleaseManifestV1) { m.GitRevision = testRevision[:39] }},
		{name: "uppercase revision", mutate: func(m *ReleaseManifestV1) { m.GitRevision = strings.ToUpper(testRevision) }},
		{name: "non linux", mutate: func(m *ReleaseManifestV1) { m.OS = "windows" }},
		{name: "unsupported architecture", mutate: func(m *ReleaseManifestV1) { m.Architecture = "386" }},
		{name: "secret like image ref", mutate: func(m *ReleaseManifestV1) {
			m.ReaperImage = "https://token:super-secret@registry.example/dirextalk-reaper:" + testTag + "@sha256:" + strings.Repeat("c", 64)
		}},
		{name: "empty rootfs digest", mutate: func(m *ReleaseManifestV1) { m.WorkerRootFSDigest = "" }},
		{name: "empty binary digest", mutate: func(m *ReleaseManifestV1) { m.WorkerBinaryDigest = "" }},
		{name: "invalid generation time", mutate: func(m *ReleaseManifestV1) { m.GeneratedAt = "yesterday" }},
		{name: "unknown schema", mutate: func(m *ReleaseManifestV1) { m.SchemaVersion = "dirextalk.agent.release-manifest/v2" }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest()
			test.mutate(&manifest)
			if _, err := Normalize(manifest); err == nil {
				t.Fatal("Normalize() accepted an invalid release manifest")
			}
		})
	}
}

func TestParseJSONRejectsUnknownAndTrailingFields(t *testing.T) {
	valid, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}

	tests := [][]byte{
		bytes.Replace(valid, []byte("}"), []byte(`,"secret":"canary"}`), 1),
		bytes.Replace(valid, []byte("{"), []byte(`{"schema_version":"`+SchemaVersionV1+`",`), 1),
		append(append([]byte(nil), valid...), []byte(` {}`)...),
	}
	for _, input := range tests {
		if _, err := ParseJSON(input); err == nil {
			t.Fatal("ParseJSON() accepted ambiguous or unknown input")
		}
	}
}

func validManifest() ReleaseManifestV1 {
	return ReleaseManifestV1{
		SchemaVersion:      SchemaVersionV1,
		ReleaseTag:         testTag,
		GitRevision:        testRevision,
		OS:                 "linux",
		Architecture:       "amd64",
		AgentImage:         imageRef("dirextalk-agent", testTag, 'a'),
		WorkerImage:        imageRef("dirextalk-worker", testTag, 'b'),
		ReaperImage:        imageRef("dirextalk-reaper", testTag, 'c'),
		WorkerRootFSDigest: "sha256:" + strings.Repeat("d", 64),
		WorkerBinaryDigest: "sha256:" + strings.Repeat("e", 64),
		GeneratedAt:        "2026-07-17T00:09:10Z",
	}
}

func imageRef(name, tag string, digestByte byte) string {
	return "registry.example/" + name + ":" + tag + "@sha256:" + strings.Repeat(string(digestByte), 64)
}
