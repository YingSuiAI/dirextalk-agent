package releaseartifact

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const (
	testRevision = "0123456789abcdef0123456789abcdef01234567"
	testTag      = "v0.1.0-alpha.20260807.1-0123456789ab"
)

func TestReleaseManifestV1BindsCurrentLinuxAMD64Release(t *testing.T) {
	manifest := validManifest()
	manifest.SchemaVersion = "  " + SchemaVersionV1 + "  "
	manifest.GeneratedAt = "2026-08-07T08:09:10+08:00"

	normalized, err := Normalize(manifest)
	if err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if normalized.OS != "linux" || normalized.Architecture != "amd64" {
		t.Fatalf("platform = %s/%s", normalized.OS, normalized.Architecture)
	}
	if normalized.GeneratedAt != "2026-08-07T00:09:10Z" {
		t.Fatalf("GeneratedAt = %q", normalized.GeneratedAt)
	}
	if normalized.AgentImage == "" || normalized.WorkerImage == "" || normalized.ReaperImage == "" {
		t.Fatal("release image identity is incomplete")
	}
	if normalized.PiRuntime.Version != OfficialPiVersion {
		t.Fatalf("Pi version = %q", normalized.PiRuntime.Version)
	}

	first, err := normalized.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() error = %v", err)
	}
	second, err := normalized.CanonicalJSON()
	if err != nil {
		t.Fatalf("CanonicalJSON() second error = %v", err)
	}
	if !bytes.Equal(first, second) || bytes.Contains(first, []byte(" \n")) {
		t.Fatal("canonical release identity is not deterministic and compact")
	}
	firstDigest, err := normalized.Digest()
	if err != nil {
		t.Fatalf("Digest() error = %v", err)
	}
	secondDigest, err := normalized.Digest()
	const wantDigest = "sha256:9c0e31e4525ecf4ff8fb734e7bf5e2bea26281f53f69117d6ee98121a9670343"
	if err != nil || firstDigest != secondDigest || firstDigest != wantDigest {
		t.Fatalf("Digest() is not stable: first=%q second=%q err=%v", firstDigest, secondDigest, err)
	}
}

func TestReleaseManifestV1DigestIgnoresInputJSONKeyOrder(t *testing.T) {
	ordered, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	reordered := reverseTopLevelJSONKeys(t, ordered)
	if bytes.Equal(ordered, reordered) {
		t.Fatal("test input key order did not change")
	}
	first, err := ParseJSON(ordered)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseJSON(reordered)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := first.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := second.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest || firstDigest != "sha256:9c0e31e4525ecf4ff8fb734e7bf5e2bea26281f53f69117d6ee98121a9670343" {
		t.Fatalf("key order changed release identity: first=%q second=%q", firstDigest, secondDigest)
	}
}

func TestReleaseManifestV1RequiresThreeImmutableOCIReferences(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ReleaseManifestV1)
	}{
		{name: "Agent absent", mutate: func(m *ReleaseManifestV1) { m.AgentImage = "" }},
		{name: "Worker absent", mutate: func(m *ReleaseManifestV1) { m.WorkerImage = "" }},
		{name: "Reaper absent", mutate: func(m *ReleaseManifestV1) { m.ReaperImage = "" }},
		{name: "Agent mutable", mutate: func(m *ReleaseManifestV1) { m.AgentImage = "registry.example/dirextalk-agent:" + testTag }},
		{name: "Worker latest", mutate: func(m *ReleaseManifestV1) { m.WorkerImage = imageRef("dirextalk-worker", "latest", 'b') }},
		{name: "Reaper tag mismatch", mutate: func(m *ReleaseManifestV1) {
			m.ReaperImage = imageRef("dirextalk-reaper", "v0.1.0-alpha.20260807.2-0123456789ab", 'c')
		}},
		{name: "duplicate image", mutate: func(m *ReleaseManifestV1) { m.ReaperImage = m.WorkerImage }},
		{name: "secret-bearing image", mutate: func(m *ReleaseManifestV1) {
			m.ReaperImage = "https://token:secret@registry.example/reaper:" + testTag + "@sha256:" + strings.Repeat("c", 64)
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest()
			test.mutate(&manifest)
			if _, err := Normalize(manifest); err == nil {
				t.Fatal("Normalize() accepted an incomplete or mutable OCI identity")
			}
		})
	}
}

func TestReleaseManifestV1RejectsOtherPlatformsAndUnboundAssets(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ReleaseManifestV1)
	}{
		{name: "ARM64", mutate: func(m *ReleaseManifestV1) { m.Architecture = "arm64" }},
		{name: "Darwin", mutate: func(m *ReleaseManifestV1) { m.OS = "darwin" }},
		{name: "rootfs absent", mutate: func(m *ReleaseManifestV1) { m.WorkerRootFSDigest = "" }},
		{name: "Worker absent", mutate: func(m *ReleaseManifestV1) { m.WorkerBinaryDigest = "" }},
		{name: "sandbox absent", mutate: func(m *ReleaseManifestV1) { m.SandboxBinaryDigest = "" }},
		{name: "installation manifest absent", mutate: func(m *ReleaseManifestV1) { m.InstallationManifestDigest = "" }},
		{name: "wrong Pi version", mutate: func(m *ReleaseManifestV1) { m.PiRuntime.Version = "0.82.0" }},
		{name: "Pi archive absent", mutate: func(m *ReleaseManifestV1) { m.PiRuntime.ArchiveDigest = "" }},
		{name: "Pi executable absent", mutate: func(m *ReleaseManifestV1) { m.PiRuntime.ExecutableDigest = "" }},
		{name: "Pi package absent", mutate: func(m *ReleaseManifestV1) { m.PiRuntime.PackageJSONDigest = "" }},
		{name: "Pi WASM absent", mutate: func(m *ReleaseManifestV1) { m.PiRuntime.PhotonWASMDigest = "" }},
		{name: "Pi dark theme absent", mutate: func(m *ReleaseManifestV1) { m.PiRuntime.DarkThemeDigest = "" }},
		{name: "Pi light theme absent", mutate: func(m *ReleaseManifestV1) { m.PiRuntime.LightThemeDigest = "" }},
		{name: "Pi theme schema absent", mutate: func(m *ReleaseManifestV1) { m.PiRuntime.ThemeSchemaDigest = "" }},
		{name: "result extension absent", mutate: func(m *ReleaseManifestV1) { m.PiRuntime.ResultExtensionDigest = "" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest()
			test.mutate(&manifest)
			if _, err := Normalize(manifest); err == nil {
				t.Fatal("Normalize() accepted an unbound release asset")
			}
		})
	}
}

func TestReleaseManifestV1RejectsWellFormedSubstitutedPiDigests(t *testing.T) {
	replacement := "sha256:" + strings.Repeat("9", 64)
	tests := []struct {
		name   string
		mutate func(*PiRuntimeIdentityV1)
	}{
		{name: "archive", mutate: func(pi *PiRuntimeIdentityV1) { pi.ArchiveDigest = replacement }},
		{name: "executable", mutate: func(pi *PiRuntimeIdentityV1) { pi.ExecutableDigest = replacement }},
		{name: "package JSON", mutate: func(pi *PiRuntimeIdentityV1) { pi.PackageJSONDigest = replacement }},
		{name: "photon WASM", mutate: func(pi *PiRuntimeIdentityV1) { pi.PhotonWASMDigest = replacement }},
		{name: "dark theme", mutate: func(pi *PiRuntimeIdentityV1) { pi.DarkThemeDigest = replacement }},
		{name: "light theme", mutate: func(pi *PiRuntimeIdentityV1) { pi.LightThemeDigest = replacement }},
		{name: "theme schema", mutate: func(pi *PiRuntimeIdentityV1) { pi.ThemeSchemaDigest = replacement }},
		{name: "result extension", mutate: func(pi *PiRuntimeIdentityV1) { pi.ResultExtensionDigest = replacement }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest()
			test.mutate(&manifest.PiRuntime)
			if _, err := Normalize(manifest); err == nil {
				t.Fatal("Normalize() accepted a substituted official Pi asset")
			}
		})
	}
}

func TestParseJSONRejectsUnknownDuplicateAndTypedAbsentReaper(t *testing.T) {
	valid, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	tests := [][]byte{
		bytes.Replace(valid, []byte("}"), []byte(`,"reaper_state":"absent"}`), 1),
		bytes.Replace(valid, []byte("{"), []byte(`{"schema_version":"`+SchemaVersionV1+`",`), 1),
		append(append([]byte(nil), valid...), []byte(` {}`)...),
	}
	for _, input := range tests {
		if _, err := ParseJSON(input); err == nil {
			t.Fatal("ParseJSON() accepted ambiguous or out-of-schema input")
		}
	}
}

func TestCurrentContainerfilePinsCoreV1RootFSAssets(t *testing.T) {
	root := repositoryRoot(t)
	containerfile := readAsset(t, filepath.Join(root, "deploy/container/pi-worker/worker.Containerfile"))
	service := readAsset(t, filepath.Join(root, "deploy/container/pi-worker/dirextalk-cloud-worker.service"))
	extension := readAsset(t, filepath.Join(root, "deploy/container/pi-worker/dirextalk-result.ts"))

	required := []string{
		"AS rootfs-export",
		"./cmd/dirextalk-cloud-worker",
		"./cmd/dirextalk-pi-sandbox",
		OfficialPiVersion,
		OfficialPiArchiveDigest[7:],
		OfficialPiExecutableDigest[7:],
		OfficialPiPackageJSONDigest[7:],
		OfficialPiPhotonWASMDigest[7:],
		OfficialPiDarkThemeDigest[7:],
		OfficialPiLightThemeDigest[7:],
		OfficialPiThemeSchemaDigest[7:],
		OfficialPiResultExtensionDigest[7:],
		"usr/lib/sysusers.d/dirextalk-worker.conf",
		"usr/lib/tmpfiles.d/dirextalk-worker.conf",
		"usr/local/lib/systemd/system/dirextalk-cloud-worker.service",
		"pi-runtime-identity.json",
	}
	for _, value := range required {
		if !bytes.Contains(containerfile, []byte(value)) {
			t.Fatalf("current Containerfile does not bind %q", value)
		}
	}
	for _, forbidden := range []string{
		"dirextalk-worker-installer",
		"root-helper",
		"ubuntu:noble",
		"TARGETARCH=arm64",
		"knowledge-worker",
		"cloud-connection",
		"/out/etc/passwd",
		"/out/etc/group",
		"/out/run/dirextalk-worker",
		"systemctl enable",
		"systemctl start",
	} {
		if bytes.Contains(bytes.ToLower(containerfile), []byte(forbidden)) {
			t.Fatalf("current Containerfile contains forbidden legacy surface %q", forbidden)
		}
	}
	if digestBytes(extension) != OfficialPiResultExtensionDigest {
		t.Fatalf("current result extension digest = %s", digestBytes(extension))
	}
	if !bytes.Contains(service, []byte("User=65532")) || !bytes.Contains(service, []byte("Group=65532")) ||
		bytes.Contains(bytes.ToLower(service), []byte("installer")) {
		t.Fatal("current systemd unit is not the closed Core v1 Worker unit")
	}
}

func reverseTopLevelJSONKeys(t *testing.T, input []byte) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(input, &object); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
	var output bytes.Buffer
	output.WriteByte('{')
	for index, key := range keys {
		if index > 0 {
			output.WriteByte(',')
		}
		encodedKey, err := json.Marshal(key)
		if err != nil {
			t.Fatal(err)
		}
		output.Write(encodedKey)
		output.WriteByte(':')
		output.Write(object[key])
	}
	output.WriteByte('}')
	return output.Bytes()
}

func validManifest() ReleaseManifestV1 {
	return ReleaseManifestV1{
		SchemaVersion:              SchemaVersionV1,
		ReleaseTag:                 testTag,
		GitRevision:                testRevision,
		OS:                         "linux",
		Architecture:               "amd64",
		AgentImage:                 imageRef("dirextalk-agent", testTag, 'a'),
		WorkerImage:                imageRef("dirextalk-team-worker", testTag, 'b'),
		ReaperImage:                imageRef("dirextalk-team-reaper", testTag, 'c'),
		WorkerRootFSDigest:         "sha256:" + strings.Repeat("d", 64),
		WorkerBinaryDigest:         "sha256:" + strings.Repeat("e", 64),
		SandboxBinaryDigest:        "sha256:" + strings.Repeat("f", 64),
		InstallationManifestDigest: "sha256:" + strings.Repeat("1", 64),
		PiRuntime: PiRuntimeIdentityV1{
			Version:               OfficialPiVersion,
			ArchiveDigest:         OfficialPiArchiveDigest,
			ExecutableDigest:      OfficialPiExecutableDigest,
			PackageJSONDigest:     OfficialPiPackageJSONDigest,
			PhotonWASMDigest:      OfficialPiPhotonWASMDigest,
			DarkThemeDigest:       OfficialPiDarkThemeDigest,
			LightThemeDigest:      OfficialPiLightThemeDigest,
			ThemeSchemaDigest:     OfficialPiThemeSchemaDigest,
			ResultExtensionDigest: OfficialPiResultExtensionDigest,
		},
		GeneratedAt: "2026-08-07T00:09:10Z",
	}
}

func imageRef(name, tag string, digestByte byte) string {
	return "registry.example/" + name + ":" + tag + "@sha256:" + strings.Repeat(string(digestByte), 64)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readAsset(t *testing.T, path string) []byte {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return content
}
