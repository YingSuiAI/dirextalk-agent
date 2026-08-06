// Package workerrootfs creates and verifies the deterministic immutable
// rootfs archive consumed by the Agent Core v1 Team Worker AMI builder.
package workerrootfs

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/releaseartifact"
)

type packedEntry struct {
	spec  entrySpec
	data  []byte
	info  os.FileInfo
	links uint64
}

// Pack snapshots an exact rootfs-export directory and atomically publishes a
// deterministic USTAR archive. An existing output is never replaced.
func Pack(root, output string) (ManifestV1, error) {
	publication, err := PreparePublication(root, output)
	if err != nil {
		return ManifestV1{}, err
	}
	manifest := publication.Manifest()
	publication.Commit()
	return manifest, nil
}

// PreparePublication publishes an official rootfs and returns a token that may
// only commit or roll back that exact output identity.
func PreparePublication(root, output string) (*Publication, error) {
	return prepareWithExpectedPiIdentity(root, output, officialPiIdentity())
}

func packWithExpectedPiIdentity(root, output string, expectedPi releaseartifact.PiRuntimeIdentityV1) (ManifestV1, error) {
	publication, err := prepareWithExpectedPiIdentity(root, output, expectedPi)
	if err != nil {
		return ManifestV1{}, err
	}
	manifest := publication.Manifest()
	publication.Commit()
	return manifest, nil
}

func prepareWithExpectedPiIdentity(root, output string, expectedPi releaseartifact.PiRuntimeIdentityV1) (*Publication, error) {
	expectedPi, err := normalizePiIdentityForPackage(expectedPi)
	if err != nil {
		return nil, errors.New("invalid expected rootfs Pi identity")
	}
	rootPath, outputPath, err := validateArguments(root, output)
	if err != nil {
		return nil, err
	}
	entries, identity, err := snapshotRoot(rootPath)
	if err != nil {
		return nil, err
	}
	if identity.PiRuntime != expectedPi {
		return nil, errors.New("rootfs Pi identity does not match expected release")
	}
	published, err := writeArchive(outputPath, entries, identity)
	if err != nil {
		return nil, err
	}
	return newPublication(outputPath, published.manifest, published.info), nil
}

func officialPiIdentity() releaseartifact.PiRuntimeIdentityV1 {
	return releaseartifact.PiRuntimeIdentityV1{
		Version:               releaseartifact.OfficialPiVersion,
		ArchiveDigest:         releaseartifact.OfficialPiArchiveDigest,
		ExecutableDigest:      releaseartifact.OfficialPiExecutableDigest,
		PackageJSONDigest:     releaseartifact.OfficialPiPackageJSONDigest,
		PhotonWASMDigest:      releaseartifact.OfficialPiPhotonWASMDigest,
		DarkThemeDigest:       releaseartifact.OfficialPiDarkThemeDigest,
		LightThemeDigest:      releaseartifact.OfficialPiLightThemeDigest,
		ThemeSchemaDigest:     releaseartifact.OfficialPiThemeSchemaDigest,
		ResultExtensionDigest: releaseartifact.OfficialPiResultExtensionDigest,
	}
}

// VerifyArchive applies the complete public release boundary before parsing
// the rootfs. Package-local tests use verifyArchive with small fixture bytes;
// a published release always requires the exact official Pi identity.
func VerifyArchive(reader io.Reader, expected releaseartifact.ReleaseManifestV1) error {
	normalized, err := releaseartifact.Normalize(expected)
	if err != nil {
		return errors.New("invalid expected release identity")
	}
	return verifyArchive(reader, ManifestV1{
		Schema:                     SchemaV1,
		OS:                         normalized.OS,
		Architecture:               normalized.Architecture,
		RootFSDigest:               normalized.WorkerRootFSDigest,
		WorkerBinaryDigest:         normalized.WorkerBinaryDigest,
		SandboxBinaryDigest:        normalized.SandboxBinaryDigest,
		InstallationManifestDigest: normalized.InstallationManifestDigest,
		PiRuntime:                  normalized.PiRuntime,
	})
}

func verifyArchive(reader io.Reader, expected ManifestV1) error {
	if reader == nil || expected.Schema != SchemaV1 || expected.OS != "linux" || expected.Architecture != "amd64" ||
		!digestPattern.MatchString(expected.RootFSDigest) || !digestPattern.MatchString(expected.WorkerBinaryDigest) ||
		!digestPattern.MatchString(expected.SandboxBinaryDigest) || !digestPattern.MatchString(expected.InstallationManifestDigest) {
		return errors.New("invalid expected rootfs identity")
	}
	piIdentity, err := normalizePiIdentityForPackage(expected.PiRuntime)
	if err != nil {
		return errors.New("invalid expected rootfs Pi identity")
	}
	content, err := io.ReadAll(io.LimitReader(reader, MaxArchiveBytes+1))
	if err != nil || len(content) == 0 || int64(len(content)) > MaxArchiveBytes {
		return errors.New("read rootfs archive")
	}
	if expected.Size != 0 && expected.Size != int64(len(content)) {
		return errors.New("rootfs archive size does not match")
	}
	if sha256Digest(content) != expected.RootFSDigest {
		return errors.New("rootfs archive digest does not match")
	}

	specs := archiveEntrySpecs()
	archive := tar.NewReader(bytes.NewReader(content))
	files := make(map[string][]byte, len(specs))
	decoded := make([]packedEntry, 0, len(specs))
	for _, spec := range specs {
		header, err := archive.Next()
		if err != nil {
			return errors.New("rootfs archive is missing a required entry")
		}
		if err := validateHeader(header, spec); err != nil {
			return err
		}
		if spec.kind == directoryEntry {
			decoded = append(decoded, packedEntry{spec: spec})
			continue
		}
		entry, err := io.ReadAll(io.LimitReader(archive, spec.maxBytes+1))
		if err != nil || int64(len(entry)) != header.Size || int64(len(entry)) > spec.maxBytes {
			return errors.New("read rootfs archive entry")
		}
		files[spec.path] = entry
		decoded = append(decoded, packedEntry{spec: spec, data: entry})
	}
	if _, err := archive.Next(); err != io.EOF {
		return errors.New("rootfs archive contains an unexpected entry")
	}
	var canonical bytes.Buffer
	if err := writeCanonicalArchive(&canonical, decoded); err != nil || !bytes.Equal(canonical.Bytes(), content) {
		return errors.New("rootfs archive bytes are not canonical USTAR")
	}

	workerDigest, sandboxDigest, archivedPi, err := validateAssets(files)
	if err != nil {
		return err
	}
	if workerDigest != expected.WorkerBinaryDigest || sandboxDigest != expected.SandboxBinaryDigest || archivedPi != piIdentity {
		return errors.New("rootfs executable or Pi identity does not match release")
	}
	installationBytes := files[installationManifestPath]
	if sha256Digest(installationBytes) != expected.InstallationManifestDigest {
		return errors.New("installation manifest digest does not match release")
	}
	installation, err := ParseInstallationManifestJSON(installationBytes)
	if err != nil {
		return err
	}
	if err := verifyInstallationEntries(installation, files); err != nil {
		return err
	}
	return nil
}

func validateArguments(root, output string) (string, string, error) {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(output) == "" {
		return "", "", errors.New("root and output are required")
	}
	rootPath, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return "", "", errors.New("resolve root")
	}
	providedRoot, err := os.Lstat(rootPath)
	if err != nil || providedRoot.Mode()&os.ModeSymlink != 0 || !providedRoot.IsDir() {
		return "", "", errors.New("root must be a real directory")
	}
	rootPath, err = filepath.EvalSymlinks(rootPath)
	if err != nil {
		return "", "", errors.New("resolve root")
	}
	outputPath, err := filepath.Abs(filepath.Clean(output))
	if err != nil {
		return "", "", errors.New("resolve output")
	}
	outputParent, err := filepath.EvalSymlinks(filepath.Dir(outputPath))
	if err != nil {
		return "", "", errors.New("resolve output parent")
	}
	parentInfo, err := os.Lstat(outputParent)
	if err != nil || parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return "", "", errors.New("output parent must be a real directory")
	}
	outputPath = filepath.Join(outputParent, filepath.Base(outputPath))
	if withinRoot(rootPath, outputPath) {
		return "", "", errors.New("output must be outside root")
	}
	return rootPath, outputPath, nil
}

func withinRoot(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	if err != nil {
		return false
	}
	return relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))
}

func snapshotRoot(root string) ([]packedEntry, ManifestV1, error) {
	allowed := make(map[string]entrySpec, len(rootfsEntries))
	for _, spec := range rootfsEntries {
		allowed[spec.path] = spec
	}
	seen := make(map[string]packedEntry, len(rootfsEntries))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("walk rootfs")
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("rootfs path escapes root")
		}
		archivePath := filepath.ToSlash(relative)
		if archivePath == "" || strings.HasPrefix(archivePath, "/") || strings.Contains(archivePath, "\\") || strings.HasPrefix(filepath.Base(archivePath), "._") {
			return errors.New("rootfs contains an invalid path")
		}
		spec, accepted := allowed[archivePath]
		if !accepted {
			return errors.New("rootfs contains an unexpected path")
		}
		if _, duplicate := seen[archivePath]; duplicate {
			return errors.New("rootfs contains a duplicate path")
		}
		info, err := entry.Info()
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("inspect rootfs entry")
		}
		packed := packedEntry{spec: spec}
		switch spec.kind {
		case directoryEntry:
			if !info.IsDir() {
				return errors.New("rootfs directory has an invalid type")
			}
			captured, links, err := captureDirectory(path, info)
			if err != nil {
				return err
			}
			packed.info = captured
			packed.links = links
		case regularEntry:
			if !info.Mode().IsRegular() {
				return errors.New("rootfs file has an invalid type")
			}
			content, captured, links, err := readRegularFile(path, info, spec.maxBytes)
			if err != nil {
				return err
			}
			packed.data = content
			packed.info = captured
			packed.links = links
		default:
			return errors.New("rootfs allowlist has an invalid kind")
		}
		seen[archivePath] = packed
		return nil
	})
	if err != nil {
		return nil, ManifestV1{}, err
	}
	if len(seen) != len(rootfsEntries) {
		return nil, ManifestV1{}, errors.New("rootfs is missing a required path")
	}
	if err := reviewRootSnapshot(root, seen); err != nil {
		return nil, ManifestV1{}, err
	}
	entries := make([]packedEntry, 0, len(rootfsEntries)+1)
	files := make(map[string][]byte, len(rootfsEntries)+1)
	for _, spec := range rootfsEntries {
		entry, exists := seen[spec.path]
		if !exists {
			return nil, ManifestV1{}, errors.New("rootfs is missing a required path")
		}
		entries = append(entries, entry)
		if spec.kind == regularEntry {
			files[spec.path] = entry.data
		}
	}
	workerDigest, sandboxDigest, piIdentity, err := validateAssets(files)
	if err != nil {
		return nil, ManifestV1{}, err
	}
	installation, err := buildInstallationManifest(entries)
	if err != nil {
		return nil, ManifestV1{}, err
	}
	installationBytes, err := installation.CanonicalJSON()
	if err != nil {
		return nil, ManifestV1{}, err
	}
	entries = append(entries, packedEntry{spec: installationSpec, data: installationBytes})
	sort.Slice(entries, func(i, j int) bool { return entries[i].spec.path < entries[j].spec.path })
	return entries, ManifestV1{
		Schema:                     SchemaV1,
		OS:                         "linux",
		Architecture:               "amd64",
		WorkerBinaryDigest:         workerDigest,
		SandboxBinaryDigest:        sandboxDigest,
		InstallationManifestDigest: sha256Digest(installationBytes),
		PiRuntime:                  piIdentity,
	}, nil
}

func validateAssets(files map[string][]byte) (string, string, releaseartifact.PiRuntimeIdentityV1, error) {
	if len(files[caBundlePath]) == 0 || string(files[sysusersPath]) != expectedSysusers || string(files[tmpfilesPath]) != expectedTmpfiles {
		return "", "", releaseartifact.PiRuntimeIdentityV1{}, errors.New("rootfs host integration configuration does not match")
	}
	service := files[servicePath]
	lowerService := bytes.ToLower(service)
	for _, required := range [][]byte{[]byte("User=65532"), []byte("Group=65532"), []byte("ExecStart=/usr/local/bin/dirextalk-cloud-worker")} {
		if !bytes.Contains(service, required) {
			return "", "", releaseartifact.PiRuntimeIdentityV1{}, errors.New("rootfs systemd unit does not match")
		}
	}
	for _, forbidden := range [][]byte{[]byte("installer"), []byte("root-helper"), []byte("systemctl enable"), []byte("systemctl start")} {
		if bytes.Contains(lowerService, forbidden) {
			return "", "", releaseartifact.PiRuntimeIdentityV1{}, errors.New("rootfs systemd unit contains a forbidden surface")
		}
	}

	workerHex := sha256Hex(files[workerBinaryPath])
	sandboxHex := sha256Hex(files[sandboxBinaryPath])
	if string(files[workerSidecarPath]) != workerHex+"  "+workerAbsolutePath+"\n" ||
		string(files[sandboxSidecarPath]) != sandboxHex+"  "+sandboxAbsolutePath+"\n" {
		return "", "", releaseartifact.PiRuntimeIdentityV1{}, errors.New("rootfs binary digest sidecar does not match sha256sum format")
	}
	piIdentity, err := parsePiIdentity(files[piIdentityPath])
	if err != nil {
		return "", "", releaseartifact.PiRuntimeIdentityV1{}, err
	}
	assetDigests := []struct {
		path   string
		digest string
	}{
		{path: piBinaryPath, digest: piIdentity.ExecutableDigest},
		{path: piPackageJSONPath, digest: piIdentity.PackageJSONDigest},
		{path: piPhotonWASMPath, digest: piIdentity.PhotonWASMDigest},
		{path: piDarkThemePath, digest: piIdentity.DarkThemeDigest},
		{path: piLightThemePath, digest: piIdentity.LightThemeDigest},
		{path: piThemeSchemaPath, digest: piIdentity.ThemeSchemaDigest},
		{path: piExtensionPath, digest: piIdentity.ResultExtensionDigest},
	}
	for _, asset := range assetDigests {
		if sha256Digest(files[asset.path]) != asset.digest {
			return "", "", releaseartifact.PiRuntimeIdentityV1{}, errors.New("rootfs Pi asset digest does not match")
		}
	}
	if err := validatePiAssetShapes(files); err != nil {
		return "", "", releaseartifact.PiRuntimeIdentityV1{}, err
	}
	return "sha256:" + workerHex, "sha256:" + sandboxHex, piIdentity, nil
}

func parsePiIdentity(input []byte) (releaseartifact.PiRuntimeIdentityV1, error) {
	if len(input) == 0 || len(input) > 8<<10 || rejectDuplicateJSONKeys(input) != nil {
		return releaseartifact.PiRuntimeIdentityV1{}, errors.New("invalid Pi runtime identity")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var identity releaseartifact.PiRuntimeIdentityV1
	if err := decoder.Decode(&identity); err != nil {
		return releaseartifact.PiRuntimeIdentityV1{}, errors.New("invalid Pi runtime identity")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return releaseartifact.PiRuntimeIdentityV1{}, errors.New("invalid Pi runtime identity")
	}
	normalized, err := normalizePiIdentityForPackage(identity)
	if err != nil {
		return releaseartifact.PiRuntimeIdentityV1{}, err
	}
	canonical, err := json.Marshal(normalized)
	if err != nil {
		return releaseartifact.PiRuntimeIdentityV1{}, errors.New("encode Pi runtime identity")
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(input, canonical) {
		return releaseartifact.PiRuntimeIdentityV1{}, errors.New("Pi runtime identity is not canonical")
	}
	return normalized, nil
}

func validatePiAssetShapes(files map[string][]byte) error {
	var metadata struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		PIConfig struct {
			ConfigDirectory string `json:"configDir"`
		} `json:"piConfig"`
	}
	if json.Unmarshal(files[piPackageJSONPath], &metadata) != nil || metadata.Name != "@earendil-works/pi-coding-agent" ||
		metadata.Version != releaseartifact.OfficialPiVersion || metadata.PIConfig.ConfigDirectory != ".pi" {
		return errors.New("rootfs Pi package metadata does not match")
	}
	photon := files[piPhotonWASMPath]
	if len(photon) < 8 || !bytes.Equal(photon[:4], []byte{0x00, 0x61, 0x73, 0x6d}) {
		return errors.New("rootfs Pi photon runtime does not match")
	}
	for _, path := range []string{piDarkThemePath, piLightThemePath, piThemeSchemaPath} {
		if !json.Valid(files[path]) || bytes.Contains(files[path], []byte{0}) {
			return errors.New("rootfs Pi theme does not match")
		}
	}
	if len(files[piExtensionPath]) == 0 || bytes.Contains(files[piExtensionPath], []byte{0}) {
		return errors.New("rootfs Pi result extension does not match")
	}
	return nil
}

func buildInstallationManifest(entries []packedEntry) (InstallationManifestV1, error) {
	byPath := make(map[string]packedEntry, len(entries))
	for _, entry := range entries {
		byPath[entry.spec.path] = entry
	}
	manifest := InstallationManifestV1{
		SchemaVersion: InstallationSchemaV1,
		OS:            "linux",
		Architecture:  "amd64",
		Entries:       make([]InstallationEntryV1, 0, len(rootfsEntries)),
	}
	for _, spec := range rootfsEntries {
		entry, exists := byPath[spec.path]
		if !exists {
			return InstallationManifestV1{}, errors.New("build installation manifest: missing entry")
		}
		item := InstallationEntryV1{Path: spec.path, Mode: spec.mode, UID: spec.uid, GID: spec.gid}
		if spec.kind == directoryEntry {
			item.Kind = "directory"
		} else {
			item.Kind = "file"
			item.Size = int64(len(entry.data))
			item.SHA256 = sha256Digest(entry.data)
		}
		manifest.Entries = append(manifest.Entries, item)
	}
	return normalizeInstallationManifest(manifest)
}

func verifyInstallationEntries(manifest InstallationManifestV1, files map[string][]byte) error {
	for index, spec := range rootfsEntries {
		entry := manifest.Entries[index]
		if spec.kind == regularEntry && (int64(len(files[spec.path])) != entry.Size || sha256Digest(files[spec.path]) != entry.SHA256) {
			return errors.New("rootfs entry does not match installation manifest")
		}
	}
	return nil
}

func archiveEntrySpecs() []entrySpec {
	specs := append([]entrySpec(nil), rootfsEntries...)
	specs = append(specs, installationSpec)
	sort.Slice(specs, func(i, j int) bool { return specs[i].path < specs[j].path })
	return specs
}

func validateHeader(header *tar.Header, spec entrySpec) error {
	wantName := spec.path
	wantType := byte(tar.TypeReg)
	if spec.kind == directoryEntry {
		wantName += "/"
		wantType = tar.TypeDir
	}
	if header.Name != wantName || header.Typeflag != wantType || header.Mode != spec.mode || header.Uid != spec.uid || header.Gid != spec.gid ||
		header.Format != tar.FormatUSTAR || !header.ModTime.Equal(time.Unix(0, 0).UTC()) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() ||
		header.Linkname != "" || header.Uname != "" || header.Gname != "" || header.Devmajor != 0 || header.Devminor != 0 || len(header.PAXRecords) != 0 || len(header.Xattrs) != 0 {
		return errors.New("rootfs archive header is not canonical")
	}
	if spec.kind == directoryEntry && header.Size != 0 {
		return errors.New("rootfs archive directory has content")
	}
	if spec.kind == regularEntry && (header.Size <= 0 || header.Size > spec.maxBytes) {
		return errors.New("rootfs archive entry exceeds its fixed size limit")
	}
	return nil
}

func readRegularFile(path string, initial os.FileInfo, maxBytes int64) ([]byte, os.FileInfo, uint64, error) {
	if initial.Size() <= 0 || initial.Size() > maxBytes {
		return nil, nil, 0, errors.New("rootfs file exceeds its fixed size limit")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, 0, errors.New("open rootfs file")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !sameFileState(initial, opened) {
		return nil, nil, 0, errors.New("rootfs file changed during validation")
	}
	links, err := regularFileLinkCount(file, opened)
	if err != nil || links != 1 {
		return nil, nil, 0, errors.New("rootfs contains a hard link")
	}
	first, err := readOpenFile(file, opened.Size(), maxBytes)
	if err != nil {
		return nil, nil, 0, err
	}
	middle, err := file.Stat()
	if err != nil {
		return nil, nil, 0, errors.New("rootfs file changed during validation")
	}
	middleLinks, linkErr := regularFileLinkCount(file, middle)
	if linkErr != nil || middleLinks != links || !sameFileState(opened, middle) {
		return nil, nil, 0, errors.New("rootfs file changed during validation")
	}
	second, err := readOpenFile(file, opened.Size(), maxBytes)
	if err != nil {
		return nil, nil, 0, err
	}
	final, err := file.Stat()
	if err != nil {
		return nil, nil, 0, errors.New("rootfs file changed during validation")
	}
	finalLinks, linkErr := regularFileLinkCount(file, final)
	pathFinal, pathErr := os.Lstat(path)
	if linkErr != nil || pathErr != nil || finalLinks != links || !bytes.Equal(first, second) ||
		!final.Mode().IsRegular() || !pathFinal.Mode().IsRegular() || !sameFileState(opened, final) || !sameFileState(final, pathFinal) {
		return nil, nil, 0, errors.New("rootfs file changed during validation")
	}
	return first, final, finalLinks, nil
}

func readOpenFile(file *os.File, size, maxBytes int64) ([]byte, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, errors.New("seek rootfs file")
	}
	content, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil || int64(len(content)) != size || int64(len(content)) > maxBytes {
		return nil, errors.New("read rootfs file")
	}
	return content, nil
}

func captureDirectory(path string, initial os.FileInfo) (os.FileInfo, uint64, error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, 0, errors.New("open rootfs directory")
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil || !opened.IsDir() || !sameFileState(initial, opened) {
		return nil, 0, errors.New("rootfs directory changed during validation")
	}
	links, err := regularFileLinkCount(directory, opened)
	if err != nil {
		return nil, 0, errors.New("inspect rootfs directory links")
	}
	pathFinal, err := os.Lstat(path)
	if err != nil || !pathFinal.IsDir() || !sameFileState(opened, pathFinal) {
		return nil, 0, errors.New("rootfs directory changed during validation")
	}
	return pathFinal, links, nil
}

func reviewRootSnapshot(root string, snapshot map[string]packedEntry) error {
	seen := make(map[string]struct{}, len(snapshot))
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return errors.New("review rootfs snapshot")
		}
		if path == root {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("rootfs review path escapes root")
		}
		archivePath := filepath.ToSlash(relative)
		captured, exists := snapshot[archivePath]
		if !exists {
			return errors.New("rootfs changed after snapshot")
		}
		if _, duplicate := seen[archivePath]; duplicate {
			return errors.New("rootfs changed after snapshot")
		}
		seen[archivePath] = struct{}{}
		info, err := entry.Info()
		if err != nil {
			return errors.New("review rootfs entry")
		}
		var reviewed os.FileInfo
		var links uint64
		switch captured.spec.kind {
		case directoryEntry:
			if !info.IsDir() {
				return errors.New("rootfs changed after snapshot")
			}
			reviewed, links, err = captureDirectory(path, info)
		case regularEntry:
			if !info.Mode().IsRegular() {
				return errors.New("rootfs changed after snapshot")
			}
			var content []byte
			content, reviewed, links, err = readRegularFile(path, info, captured.spec.maxBytes)
			if err == nil && !bytes.Equal(content, captured.data) {
				return errors.New("rootfs file content changed after snapshot")
			}
		default:
			return errors.New("rootfs snapshot has an invalid kind")
		}
		if err != nil || links != captured.links || !sameFileState(captured.info, reviewed) {
			return errors.New("rootfs changed after snapshot")
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(seen) != len(snapshot) {
		return errors.New("rootfs changed after snapshot")
	}
	return nil
}

func sameFileState(left, right os.FileInfo) bool {
	return left != nil && right != nil && os.SameFile(left, right) && left.Size() == right.Size() &&
		left.Mode() == right.Mode() && left.ModTime().Equal(right.ModTime())
}

type publishedArchive struct {
	manifest ManifestV1
	info     os.FileInfo
}

func writeArchive(output string, entries []packedEntry, identity ManifestV1) (publishedArchive, error) {
	parent := filepath.Dir(output)
	temporary, file, err := createTemporary(parent)
	if err != nil {
		return publishedArchive{}, err
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
		if temporary != "" {
			_ = os.Remove(temporary)
		}
	}()
	hasher := sha256.New()
	if err := writeCanonicalArchive(io.MultiWriter(file, hasher), entries); err != nil {
		return publishedArchive{}, err
	}
	if err := file.Sync(); err != nil {
		return publishedArchive{}, errors.New("sync rootfs archive")
	}
	info, err := file.Stat()
	if err != nil || info.Size() <= 0 || info.Size() > MaxArchiveBytes {
		return publishedArchive{}, errors.New("inspect rootfs archive")
	}
	if err := file.Close(); err != nil {
		return publishedArchive{}, errors.New("close rootfs artifact")
	}
	file = nil
	if err := os.Link(temporary, output); err != nil {
		return publishedArchive{}, errors.New("publish rootfs archive without replacement")
	}
	if err := os.Remove(temporary); err != nil {
		_ = os.Remove(output)
		return publishedArchive{}, errors.New("finalize rootfs archive")
	}
	temporary = ""
	if err := syncDirectory(parent); err != nil {
		_ = os.Remove(output)
		return publishedArchive{}, errors.New("sync rootfs output directory")
	}
	identity.RootFSDigest = "sha256:" + hex.EncodeToString(hasher.Sum(nil))
	identity.Size = info.Size()
	return publishedArchive{manifest: identity, info: info}, nil
}

func writeCanonicalArchive(output io.Writer, entries []packedEntry) error {
	archive := tar.NewWriter(output)
	for _, entry := range entries {
		header := &tar.Header{
			Name:       entry.spec.path,
			Mode:       entry.spec.mode,
			Uid:        entry.spec.uid,
			Gid:        entry.spec.gid,
			ModTime:    time.Unix(0, 0).UTC(),
			AccessTime: time.Time{},
			ChangeTime: time.Time{},
			Format:     tar.FormatUSTAR,
		}
		if entry.spec.kind == directoryEntry {
			header.Name += "/"
			header.Typeflag = tar.TypeDir
		} else {
			header.Typeflag = tar.TypeReg
			header.Size = int64(len(entry.data))
		}
		if err := archive.WriteHeader(header); err != nil {
			return errors.New("write rootfs archive header")
		}
		if entry.spec.kind == regularEntry {
			if _, err := archive.Write(entry.data); err != nil {
				return errors.New("write rootfs archive content")
			}
		}
	}
	if err := archive.Close(); err != nil {
		return errors.New("close rootfs archive")
	}
	return nil
}

func createTemporary(parent string) (string, *os.File, error) {
	for attempt := 0; attempt < 32; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", nil, errors.New("generate rootfs temporary name")
		}
		path := filepath.Join(parent, ".rootfs-"+hex.EncodeToString(random[:])+".tmp")
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			if chmodErr := file.Chmod(0o600); chmodErr != nil {
				_ = file.Close()
				_ = os.Remove(path)
				return "", nil, errors.New("set rootfs temporary permissions")
			}
			return path, file, nil
		}
		if !os.IsExist(err) {
			return "", nil, errors.New("create rootfs temporary archive")
		}
	}
	return "", nil, errors.New("allocate rootfs temporary archive")
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func sha256Digest(content []byte) string {
	return "sha256:" + sha256Hex(content)
}

func sha256Hex(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}
