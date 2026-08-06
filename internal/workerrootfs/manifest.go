package workerrootfs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
)

const (
	SchemaV1             = "dirextalk.agent.team-worker-rootfs/v1"
	InstallationSchemaV1 = "dirextalk.agent.team-worker-installation/v1"
	MaxInstallationBytes = 256 * 1024
	MaxArchiveBytes      = 768 << 20

	caBundlePath             = "etc/ssl/certs/ca-certificates.crt"
	piBinaryPath             = "opt/dirextalk-worker/runtimes/pi/bin/pi"
	piPackageJSONPath        = "opt/dirextalk-worker/runtimes/pi/bin/package.json"
	piPhotonWASMPath         = "opt/dirextalk-worker/runtimes/pi/bin/photon_rs_bg.wasm"
	piDarkThemePath          = "opt/dirextalk-worker/runtimes/pi/bin/theme/dark.json"
	piLightThemePath         = "opt/dirextalk-worker/runtimes/pi/bin/theme/light.json"
	piThemeSchemaPath        = "opt/dirextalk-worker/runtimes/pi/bin/theme/theme-schema.json"
	piExtensionPath          = "opt/dirextalk-worker/runtimes/pi/extensions/dirextalk-result.ts"
	sysusersPath             = "usr/lib/sysusers.d/dirextalk-worker.conf"
	tmpfilesPath             = "usr/lib/tmpfiles.d/dirextalk-worker.conf"
	workerBinaryPath         = "usr/local/bin/dirextalk-cloud-worker"
	sandboxBinaryPath        = "usr/local/bin/dirextalk-pi-sandbox"
	servicePath              = "usr/local/lib/systemd/system/dirextalk-cloud-worker.service"
	workerSidecarPath        = "usr/local/share/dirextalk-worker/dirextalk-cloud-worker.sha256"
	sandboxSidecarPath       = "usr/local/share/dirextalk-worker/dirextalk-pi-sandbox.sha256"
	installationManifestPath = "usr/local/share/dirextalk-worker/installation-manifest.json"
	piIdentityPath           = "usr/local/share/dirextalk-worker/pi-runtime-identity.json"

	workerAbsolutePath  = "/usr/local/bin/dirextalk-cloud-worker"
	sandboxAbsolutePath = "/usr/local/bin/dirextalk-pi-sandbox"
)

const expectedSysusers = "g dirextalk-worker 65532 -\n" +
	"u dirextalk-worker 65532:65532 \"Dirextalk Team Worker\" /var/lib/dirextalk-worker /usr/sbin/nologin\n" +
	"u dirextalk-pi 65533:65532 \"Dirextalk Pi Runtime\" /var/lib/dirextalk-worker /usr/sbin/nologin\n"

const expectedTmpfiles = "d /var/lib/dirextalk-worker 0770 65532 65532 -\n" +
	"d /var/lib/dirextalk-worker/receipts 0700 65532 65532 -\n" +
	"d /var/lib/dirextalk-worker/runtime-state 0770 65532 65532 -\n" +
	"d /var/lib/dirextalk-worker/tmp 0770 65532 65532 -\n" +
	"d /var/lib/dirextalk-worker/workspaces 0770 65532 65532 -\n" +
	"d /run/dirextalk-worker 0700 65532 65532 -\n" +
	"d /run/dirextalk-worker/secrets 0700 65532 65532 -\n"

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type entryKind uint8

const (
	directoryEntry entryKind = iota + 1
	regularEntry
)

type entrySpec struct {
	path     string
	kind     entryKind
	mode     int64
	uid      int
	gid      int
	maxBytes int64
}

// rootfsEntries is the complete immutable export contract. Mutable state and
// host account databases are deliberately absent; Task 9B applies sysusers and
// tmpfiles configuration on Amazon Linux 2023.
var rootfsEntries = []entrySpec{
	{path: "etc", kind: directoryEntry, mode: 0o755},
	{path: "etc/ssl", kind: directoryEntry, mode: 0o755},
	{path: "etc/ssl/certs", kind: directoryEntry, mode: 0o755},
	{path: caBundlePath, kind: regularEntry, mode: 0o444, maxBytes: 16 << 20},
	{path: "opt", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes/pi", kind: directoryEntry, mode: 0o755},
	{path: "opt/dirextalk-worker/runtimes/pi/bin", kind: directoryEntry, mode: 0o755},
	{path: piPackageJSONPath, kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: piPhotonWASMPath, kind: regularEntry, mode: 0o444, maxBytes: 64 << 20},
	{path: piBinaryPath, kind: regularEntry, mode: 0o555, maxBytes: 192 << 20},
	{path: "opt/dirextalk-worker/runtimes/pi/bin/theme", kind: directoryEntry, mode: 0o755},
	{path: piDarkThemePath, kind: regularEntry, mode: 0o444, maxBytes: 256 << 10},
	{path: piLightThemePath, kind: regularEntry, mode: 0o444, maxBytes: 256 << 10},
	{path: piThemeSchemaPath, kind: regularEntry, mode: 0o444, maxBytes: 256 << 10},
	{path: "opt/dirextalk-worker/runtimes/pi/extensions", kind: directoryEntry, mode: 0o755},
	{path: piExtensionPath, kind: regularEntry, mode: 0o444, maxBytes: 256 << 10},
	{path: "usr", kind: directoryEntry, mode: 0o755},
	{path: "usr/lib", kind: directoryEntry, mode: 0o755},
	{path: "usr/lib/sysusers.d", kind: directoryEntry, mode: 0o755},
	{path: sysusersPath, kind: regularEntry, mode: 0o444, maxBytes: 4 << 10},
	{path: "usr/lib/tmpfiles.d", kind: directoryEntry, mode: 0o755},
	{path: tmpfilesPath, kind: regularEntry, mode: 0o444, maxBytes: 8 << 10},
	{path: "usr/local", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/bin", kind: directoryEntry, mode: 0o755},
	{path: workerBinaryPath, kind: regularEntry, mode: 0o555, maxBytes: 256 << 20},
	{path: sandboxBinaryPath, kind: regularEntry, mode: 0o555, maxBytes: 64 << 20},
	{path: "usr/local/lib", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/lib/systemd", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/lib/systemd/system", kind: directoryEntry, mode: 0o755},
	{path: servicePath, kind: regularEntry, mode: 0o444, maxBytes: 64 << 10},
	{path: "usr/local/share", kind: directoryEntry, mode: 0o755},
	{path: "usr/local/share/dirextalk-worker", kind: directoryEntry, mode: 0o755},
	{path: workerSidecarPath, kind: regularEntry, mode: 0o444, maxBytes: 512},
	{path: sandboxSidecarPath, kind: regularEntry, mode: 0o444, maxBytes: 512},
	{path: piIdentityPath, kind: regularEntry, mode: 0o444, maxBytes: 8 << 10},
}

var installationSpec = entrySpec{
	path: installationManifestPath, kind: regularEntry, mode: 0o444, maxBytes: MaxInstallationBytes,
}

type ManifestV1 struct {
	Schema                     string                              `json:"schema"`
	OS                         string                              `json:"os"`
	Architecture               string                              `json:"architecture"`
	RootFSDigest               string                              `json:"rootfs_digest"`
	WorkerBinaryDigest         string                              `json:"worker_binary_digest"`
	SandboxBinaryDigest        string                              `json:"sandbox_binary_digest"`
	InstallationManifestDigest string                              `json:"installation_manifest_digest"`
	PiRuntime                  releaseartifact.PiRuntimeIdentityV1 `json:"pi_runtime"`
	Size                       int64                               `json:"size"`
}

type InstallationManifestV1 struct {
	SchemaVersion string                `json:"schema_version"`
	OS            string                `json:"os"`
	Architecture  string                `json:"architecture"`
	Entries       []InstallationEntryV1 `json:"entries"`
}

type InstallationEntryV1 struct {
	Path   string `json:"path"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	Mode   int64  `json:"mode"`
	UID    int    `json:"uid"`
	GID    int    `json:"gid"`
}

func (manifest InstallationManifestV1) CanonicalJSON() ([]byte, error) {
	normalized, err := normalizeInstallationManifest(manifest)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return nil, errors.New("encode installation manifest")
	}
	return encoded, nil
}

func ParseInstallationManifestJSON(input []byte) (InstallationManifestV1, error) {
	if len(input) == 0 || len(input) > MaxInstallationBytes || rejectDuplicateJSONKeys(input) != nil {
		return InstallationManifestV1{}, errors.New("invalid installation manifest")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var manifest InstallationManifestV1
	if err := decoder.Decode(&manifest); err != nil {
		return InstallationManifestV1{}, errors.New("invalid installation manifest")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return InstallationManifestV1{}, errors.New("invalid installation manifest")
	}
	normalized, err := normalizeInstallationManifest(manifest)
	if err != nil {
		return InstallationManifestV1{}, err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil || !bytes.Equal(input, canonical) {
		return InstallationManifestV1{}, errors.New("installation manifest is not canonical")
	}
	return normalized, nil
}

func normalizeInstallationManifest(input InstallationManifestV1) (InstallationManifestV1, error) {
	if input.SchemaVersion != InstallationSchemaV1 || input.OS != "linux" || input.Architecture != "amd64" || len(input.Entries) != len(rootfsEntries) {
		return InstallationManifestV1{}, errors.New("invalid installation manifest identity")
	}
	normalized := InstallationManifestV1{
		SchemaVersion: input.SchemaVersion,
		OS:            input.OS,
		Architecture:  input.Architecture,
		Entries:       make([]InstallationEntryV1, len(input.Entries)),
	}
	for index, spec := range rootfsEntries {
		entry := input.Entries[index]
		if entry.Path != spec.path || entry.Mode != spec.mode || entry.UID != spec.uid || entry.GID != spec.gid {
			return InstallationManifestV1{}, errors.New("installation manifest entry metadata does not match")
		}
		switch spec.kind {
		case directoryEntry:
			if entry.Kind != "directory" || entry.SHA256 != "" || entry.Size != 0 {
				return InstallationManifestV1{}, errors.New("installation directory entry does not match")
			}
		case regularEntry:
			if entry.Kind != "file" || !digestPattern.MatchString(entry.SHA256) || entry.Size <= 0 || entry.Size > spec.maxBytes {
				return InstallationManifestV1{}, errors.New("installation file entry does not match")
			}
		default:
			return InstallationManifestV1{}, errors.New("invalid installation manifest entry kind")
		}
		normalized.Entries[index] = entry
	}
	return normalized, nil
}

func rejectDuplicateJSONKeys(input []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	if err := walkJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("trailing JSON value")
	}
	return nil
}

func walkJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := walkJSONValue(decoder); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return fmt.Errorf("invalid JSON delimiter %q", delimiter)
	}
}

func normalizePiIdentityForPackage(input releaseartifact.PiRuntimeIdentityV1) (releaseartifact.PiRuntimeIdentityV1, error) {
	identity := releaseartifact.PiRuntimeIdentityV1{
		Version:               strings.TrimSpace(input.Version),
		ArchiveDigest:         strings.TrimSpace(input.ArchiveDigest),
		ExecutableDigest:      strings.TrimSpace(input.ExecutableDigest),
		PackageJSONDigest:     strings.TrimSpace(input.PackageJSONDigest),
		PhotonWASMDigest:      strings.TrimSpace(input.PhotonWASMDigest),
		DarkThemeDigest:       strings.TrimSpace(input.DarkThemeDigest),
		LightThemeDigest:      strings.TrimSpace(input.LightThemeDigest),
		ThemeSchemaDigest:     strings.TrimSpace(input.ThemeSchemaDigest),
		ResultExtensionDigest: strings.TrimSpace(input.ResultExtensionDigest),
	}
	if identity.Version != releaseartifact.OfficialPiVersion || identity.ArchiveDigest != releaseartifact.OfficialPiArchiveDigest {
		return releaseartifact.PiRuntimeIdentityV1{}, errors.New("invalid Pi package identity")
	}
	for _, digest := range []string{
		identity.ExecutableDigest,
		identity.PackageJSONDigest,
		identity.PhotonWASMDigest,
		identity.DarkThemeDigest,
		identity.LightThemeDigest,
		identity.ThemeSchemaDigest,
		identity.ResultExtensionDigest,
	} {
		if !digestPattern.MatchString(digest) {
			return releaseartifact.PiRuntimeIdentityV1{}, errors.New("invalid Pi package digest")
		}
	}
	return identity, nil
}
