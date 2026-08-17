package source

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"sort"
	"strings"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

const (
	nodeSourceManifestPath = ".dirextalk-node-source-v1.json"
	nodeTarballDir         = ".dirextalk-npm-tarballs"
	nodeMaxInputBytes      = int64(64 << 20)
	nodeMaxInputFiles      = 8192
)

// NodeDependencyResolver is the only boundary allowed to invoke the managed
// package-lock-only resolver. It may resolve registry metadata and dependency
// tarballs, but must never install a package or execute package lifecycle code.
// Source adapters independently verify every returned lock entry and tarball.
type NodeDependencyResolver interface {
	Resolve(context.Context, NodeDependencyRequest) (NodeDependencyResolution, error)
}

type NodeDependencyRequest struct {
	Source              core.Source
	PackageName         string
	PackageVersion      string
	RootPackageJSON     []byte
	ExistingPackageLock []byte
	DirectTarball       []byte
	DirectTarballSHA256 string
}

type NodeDependencyResolution struct {
	PackageLock []byte
	Tarballs    []NodeResolvedTarball
}

type NodeResolvedTarball struct {
	LockPath string
	Content  []byte
}

type nodePackageJSON struct {
	Name    string          `json:"name"`
	Version string          `json:"version"`
	Main    string          `json:"main"`
	Bin     json.RawMessage `json:"bin"`
	Gypfile bool            `json:"gypfile"`
}

// Dependency packages are never selected as the managed execution entry.
// Parse only the fields needed for identity and native-build admission so
// valid ecosystem metadata such as `"main": false` cannot be mistaken for a
// native or otherwise unsupported package.
type nodeDependencyPackageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Gypfile bool   `json:"gypfile"`
}

type nodeLockPackage struct {
	Name             string `json:"name"`
	Version          string `json:"version"`
	Resolved         string `json:"resolved"`
	Integrity        string `json:"integrity"`
	Link             bool   `json:"link"`
	Dev              bool   `json:"dev"`
	HasInstallScript bool   `json:"hasInstallScript"`
}

type nodePackageLock struct {
	Name            string                     `json:"name"`
	Version         string                     `json:"version"`
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]nodeLockPackage `json:"packages"`
}

type inspectedNodePackage struct {
	Name        string
	Version     string
	EntryPath   string
	EntryDigest string
	PackageJSON []byte
	PackageLock []byte
	Files       []rawFile
}

type nodeSourceManifest struct {
	SchemaVersion   string                     `json:"schema_version"`
	Source          string                     `json:"source"`
	PackageName     string                     `json:"package_name"`
	PackageVersion  string                     `json:"package_version"`
	GitCommit       string                     `json:"git_commit,omitempty"`
	EntryPath       string                     `json:"entry_path"`
	EntrySHA256     string                     `json:"entry_sha256"`
	LockSHA256      string                     `json:"lock_sha256"`
	DirectTarSHA256 string                     `json:"direct_tar_sha256,omitempty"`
	RegistryMeta    json.RawMessage            `json:"registry_metadata,omitempty"`
	Tarballs        []nodeSourceTarballBinding `json:"tarballs"`
}

type nodeSourceTarballBinding struct {
	LockPath  string `json:"lock_path"`
	Path      string `json:"path"`
	Integrity string `json:"integrity"`
}

func inspectNodePackage(files []rawFile, requireLock bool, expectedName, expectedVersion string) (inspectedNodePackage, error) {
	if len(files) == 0 || len(files) > nodeMaxInputFiles {
		return inspectedNodePackage{}, ErrOversize
	}
	byPath := make(map[string]rawFile, len(files))
	var total int64
	for _, file := range files {
		if _, duplicate := byPath[file.Path]; duplicate {
			return inspectedNodePackage{}, ErrMalformed
		}
		byPath[file.Path] = file
		total += int64(len(file.Content))
		if total > nodeMaxInputBytes {
			return inspectedNodePackage{}, ErrOversize
		}
		if isNativeNodePath(file.Path) {
			return inspectedNodePackage{}, ErrUnsupported
		}
	}
	packageFile, ok := byPath["package.json"]
	if !ok {
		return inspectedNodePackage{}, ErrUnsupported
	}
	var manifest nodePackageJSON
	if parseJSON([]byte(packageFile.Content), &manifest) != nil || !canonicalNPMPackageName(manifest.Name) || !exactNodeSemver(manifest.Version) {
		return inspectedNodePackage{}, ErrMalformed
	}
	if expectedName != "" && manifest.Name != expectedName || expectedVersion != "" && manifest.Version != expectedVersion {
		return inspectedNodePackage{}, ErrMalformed
	}
	if manifest.Gypfile {
		return inspectedNodePackage{}, ErrUnsupported
	}
	entry, err := nodePackageEntry(manifest)
	if err != nil {
		return inspectedNodePackage{}, err
	}
	entryFile, ok := byPath[entry]
	if !ok || !isPublishedJavaScript(entry) {
		return inspectedNodePackage{}, ErrUnsupported
	}
	var lock []byte
	if lockFile, found := byPath["package-lock.json"]; found {
		lock = []byte(lockFile.Content)
		if _, err := parseAndValidateNodeLock(lock, manifest.Name, manifest.Version); err != nil {
			return inspectedNodePackage{}, err
		}
	} else if requireLock {
		return inspectedNodePackage{}, ErrUnsupported
	}
	return inspectedNodePackage{
		Name: manifest.Name, Version: manifest.Version, EntryPath: entry,
		EntryDigest: digestBytes([]byte(entryFile.Content)), PackageJSON: []byte(packageFile.Content),
		PackageLock: lock, Files: append([]rawFile(nil), files...),
	}, nil
}

func isNativeNodePath(value string) bool {
	lower := strings.ToLower(value)
	switch path.Ext(lower) {
	case ".node", ".so", ".dll", ".dylib", ".a", ".o":
		return true
	default:
		return path.Base(lower) == "binding.gyp"
	}
}

func nodePackageEntry(manifest nodePackageJSON) (string, error) {
	entry := ""
	if len(manifest.Bin) != 0 && string(manifest.Bin) != "null" {
		var single string
		if json.Unmarshal(manifest.Bin, &single) == nil {
			entry = single
		} else {
			var bins map[string]string
			if json.Unmarshal(manifest.Bin, &bins) != nil || len(bins) != 1 {
				return "", ErrUnsupported
			}
			for _, value := range bins {
				entry = value
			}
		}
	} else {
		entry = manifest.Main
	}
	entry = strings.TrimPrefix(strings.TrimSpace(entry), "./")
	if !safeNodePath(entry) || strings.HasPrefix(entry, "node_modules/") {
		return "", ErrUnsupported
	}
	return entry, nil
}

func isPublishedJavaScript(entry string) bool {
	switch strings.ToLower(path.Ext(entry)) {
	case ".js", ".mjs", ".cjs":
		return true
	default:
		return false
	}
}

func safeNodePath(value string) bool {
	if value == "" || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\\x00\r\n") || path.Clean(value) != value {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.TrimSpace(part) != part {
			return false
		}
	}
	return true
}

func canonicalNPMPackageName(value string) bool {
	if value == "" || len(value) > 214 || value != strings.ToLower(value) || strings.Contains(value, "..") {
		return false
	}
	validPart := func(part string) bool {
		if part == "" || !((part[0] >= 'a' && part[0] <= 'z') || (part[0] >= '0' && part[0] <= '9')) {
			return false
		}
		for _, char := range part {
			if char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || strings.ContainsRune("._-", char) {
				continue
			}
			return false
		}
		return true
	}
	if strings.HasPrefix(value, "@") {
		parts := strings.Split(value[1:], "/")
		return len(parts) == 2 && validPart(parts[0]) && validPart(parts[1])
	}
	return !strings.Contains(value, "/") && validPart(value)
}

func exactNodeSemver(value string) bool {
	corePart := value
	if plus := strings.IndexByte(corePart, '+'); plus >= 0 {
		if plus == len(corePart)-1 || !validSemverIdentifiers(corePart[plus+1:], false) {
			return false
		}
		corePart = corePart[:plus]
	}
	if dash := strings.IndexByte(corePart, '-'); dash >= 0 {
		if dash == len(corePart)-1 || !validSemverIdentifiers(corePart[dash+1:], true) {
			return false
		}
		corePart = corePart[:dash]
	}
	parts := strings.Split(corePart, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if !validSemverNumber(part) {
			return false
		}
	}
	return true
}

func validSemverNumber(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

func validSemverIdentifiers(value string, rejectLeadingZeroNumeric bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, char := range identifier {
			if char >= '0' && char <= '9' {
				continue
			}
			numeric = false
			if char < 'A' || char > 'Z' && char < 'a' || char > 'z' && char != '-' {
				return false
			}
		}
		if rejectLeadingZeroNumeric && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}

func parseAndValidateNodeLock(raw []byte, packageName, packageVersion string) (nodePackageLock, error) {
	var lock nodePackageLock
	if len(raw) == 0 || int64(len(raw)) > nodeMaxInputBytes || parseJSON(raw, &lock) != nil || lock.LockfileVersion < 2 || lock.LockfileVersion > 3 || lock.Packages == nil {
		return nodePackageLock{}, ErrMalformed
	}
	root, ok := lock.Packages[""]
	if !ok || lock.Name != packageName || lock.Version != packageVersion || root.Name != packageName || root.Version != packageVersion || root.Link {
		return nodePackageLock{}, ErrMalformed
	}
	for lockPath, pkg := range lock.Packages {
		if lockPath == "" {
			continue
		}
		packageName, validPath := nodePackageNameFromLockPath(lockPath)
		if !validPath || pkg.Name != "" && pkg.Name != packageName || pkg.Link || !exactNodeSemver(pkg.Version) {
			return nodePackageLock{}, ErrUnsupported
		}
		if pkg.Dev {
			continue
		}
		resolved, err := url.Parse(pkg.Resolved)
		if err != nil || resolved.Scheme != "https" || resolved.Host == "" || resolved.User != nil || resolved.RawQuery != "" || resolved.Fragment != "" || !strings.HasSuffix(strings.ToLower(resolved.Path), ".tgz") || validateSRI(pkg.Integrity) != nil {
			return nodePackageLock{}, ErrUnsupported
		}
	}
	return lock, nil
}

func validateNodeResolution(request NodeDependencyRequest, resolution NodeDependencyResolution) (nodePackageLock, []rawFile, []nodeSourceTarballBinding, error) {
	lock, err := parseAndValidateNodeLock(resolution.PackageLock, requestRootName(request.RootPackageJSON), requestRootVersion(request.RootPackageJSON))
	if err != nil {
		return nodePackageLock{}, nil, nil, err
	}
	provided := make(map[string]NodeResolvedTarball, len(resolution.Tarballs))
	for _, tarball := range resolution.Tarballs {
		if _, duplicate := provided[tarball.LockPath]; duplicate || tarball.LockPath == "" {
			return nodePackageLock{}, nil, nil, ErrMalformed
		}
		provided[tarball.LockPath] = tarball
	}
	filesByPath := make(map[string]rawFile)
	bindings := make([]nodeSourceTarballBinding, 0)
	var inputBytes int64
	var expandedFiles int
	for lockPath, pkg := range lock.Packages {
		if lockPath == "" || pkg.Dev {
			continue
		}
		tarball, ok := provided[lockPath]
		if !ok || int64(len(tarball.Content)) > nodeMaxInputBytes || verifySRI(pkg.Integrity, tarball.Content) != nil {
			return nodePackageLock{}, nil, nil, ErrMalformed
		}
		packageFiles, err := parseNPMPackageTarball(tarball.Content)
		if err != nil {
			return nodePackageLock{}, nil, nil, err
		}
		if pkg.Name == "" {
			pkg.Name, _ = nodePackageNameFromLockPath(lockPath)
		}
		inspected, err := inspectNodeDependencyPackage(packageFiles, pkg)
		if err != nil {
			return nodePackageLock{}, nil, nil, err
		}
		_ = inspected
		inputBytes += int64(len(tarball.Content))
		expandedFiles += len(packageFiles)
		if inputBytes > nodeMaxInputBytes || expandedFiles > nodeMaxInputFiles {
			return nodePackageLock{}, nil, nil, ErrOversize
		}
		sum := sha512.Sum512(tarball.Content)
		cachePath := nodeTarballDir + "/" + hex.EncodeToString(sum[:]) + ".tgz"
		if previous, exists := filesByPath[cachePath]; exists {
			if previous.Content != string(tarball.Content) {
				return nodePackageLock{}, nil, nil, ErrMalformed
			}
		} else {
			filesByPath[cachePath] = rawFile{Path: cachePath, Content: string(tarball.Content)}
		}
		bindings = append(bindings, nodeSourceTarballBinding{LockPath: lockPath, Path: cachePath, Integrity: pkg.Integrity})
		delete(provided, lockPath)
	}
	if len(provided) != 0 {
		return nodePackageLock{}, nil, nil, ErrMalformed
	}
	files := make([]rawFile, 0, len(filesByPath))
	for _, file := range filesByPath {
		files = append(files, file)
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].LockPath < bindings[j].LockPath })
	return lock, files, bindings, nil
}

func requestRootName(raw []byte) string {
	var pkg nodePackageJSON
	_ = parseJSON(raw, &pkg)
	return pkg.Name
}

func requestRootVersion(raw []byte) string {
	var pkg nodePackageJSON
	_ = parseJSON(raw, &pkg)
	return pkg.Version
}

func inspectNodeDependencyPackage(files []rawFile, expected nodeLockPackage) (inspectedNodePackage, error) {
	if len(files) == 0 || len(files) > nodeMaxInputFiles {
		return inspectedNodePackage{}, ErrOversize
	}
	byPath := make(map[string]rawFile, len(files))
	for _, file := range files {
		byPath[file.Path] = file
		if isNativeNodePath(file.Path) {
			return inspectedNodePackage{}, ErrUnsupported
		}
	}
	packageFile, ok := byPath["package.json"]
	if !ok {
		return inspectedNodePackage{}, ErrMalformed
	}
	var manifest nodeDependencyPackageJSON
	if parseJSON([]byte(packageFile.Content), &manifest) != nil || manifest.Version != expected.Version || expected.Name != "" && manifest.Name != expected.Name || manifest.Gypfile {
		return inspectedNodePackage{}, ErrUnsupported
	}
	return inspectedNodePackage{Name: manifest.Name, Version: manifest.Version, PackageJSON: []byte(packageFile.Content), Files: files}, nil
}

func nodePackageNameFromLockPath(lockPath string) (string, bool) {
	if !safeNodePath(lockPath) {
		return "", false
	}
	parts := strings.Split(lockPath, "/")
	var name string
	for index := 0; index < len(parts); {
		if parts[index] != "node_modules" || index+1 >= len(parts) {
			return "", false
		}
		index++
		if strings.HasPrefix(parts[index], "@") {
			if index+1 >= len(parts) {
				return "", false
			}
			name = parts[index] + "/" + parts[index+1]
			index += 2
		} else {
			name = parts[index]
			index++
		}
		if !canonicalNPMPackageName(name) {
			return "", false
		}
	}
	return name, name != ""
}

func parseNPMPackageTarball(raw []byte) ([]rawFile, error) {
	if len(raw) == 0 || int64(len(raw)) > nodeMaxInputBytes {
		return nil, ErrOversize
	}
	compressed := bytes.NewReader(raw)
	gz, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, ErrMalformed
	}
	defer gz.Close()
	gz.Multistream(false)
	reader := tar.NewReader(gz)
	files := make([]rawFile, 0)
	seen := make(map[string]struct{})
	var total int64
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil || header == nil || !strings.HasPrefix(header.Name, "package/") || header.Linkname != "" {
			return nil, ErrMalformed
		}
		relative := strings.TrimPrefix(header.Name, "package/")
		if relative == "" || !safeNodePath(relative) {
			return nil, ErrMalformed
		}
		switch header.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return nil, ErrUnsupported
		}
		if header.Size < 0 || header.Size > nodeMaxInputBytes || total+header.Size > nodeMaxInputBytes || len(files) >= nodeMaxInputFiles {
			return nil, ErrOversize
		}
		if _, duplicate := seen[relative]; duplicate {
			return nil, ErrMalformed
		}
		content := make([]byte, header.Size)
		if _, err := io.ReadFull(reader, content); err != nil {
			return nil, ErrMalformed
		}
		seen[relative] = struct{}{}
		total += header.Size
		files = append(files, rawFile{Path: relative, Content: string(content), Mode: fmt.Sprintf("%o", header.Mode)})
	}
	if _, err := io.Copy(io.Discard, gz); err != nil {
		return nil, ErrMalformed
	}
	if compressed.Len() != 0 {
		return nil, ErrMalformed
	}
	if len(files) == 0 {
		return nil, ErrMalformed
	}
	return files, nil
}

func validateSRI(value string) error {
	if strings.TrimSpace(value) != value || value == "" {
		return ErrMalformed
	}
	recognized := false
	for _, token := range strings.Fields(value) {
		parts := strings.SplitN(token, "-", 2)
		if len(parts) != 2 || strings.Contains(parts[1], "?") {
			return ErrMalformed
		}
		switch parts[0] {
		case "sha256", "sha384", "sha512":
			recognized = true
		default:
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(parts[1]); err != nil {
			return ErrMalformed
		}
	}
	if !recognized {
		return ErrUnsupported
	}
	return nil
}

func verifySRI(value string, content []byte) error {
	if err := validateSRI(value); err != nil {
		return err
	}
	matched := false
	for _, token := range strings.Fields(value) {
		parts := strings.SplitN(token, "-", 2)
		expected, _ := base64.StdEncoding.DecodeString(parts[1])
		var actual []byte
		switch parts[0] {
		case "sha256":
			sum := sha256.Sum256(content)
			actual = sum[:]
		case "sha384":
			sum := sha512.Sum384(content)
			actual = sum[:]
		case "sha512":
			sum := sha512.Sum512(content)
			actual = sum[:]
		default:
			continue
		}
		if !bytes.Equal(actual, expected) {
			return ErrMalformed
		}
		matched = true
	}
	if !matched {
		return ErrUnsupported
	}
	return nil
}

func buildNodeInspection(candidate core.Candidate, executionPath, executionDigest string, argv []string, files []rawFile) (core.Inspection, []byte, error) {
	if candidate.Validate() != nil || !safeNodePath(executionPath) || !validHexDigest(executionDigest) || len(files) == 0 || len(files) > nodeMaxInputFiles {
		return core.Inspection{}, nil, core.ErrInvalid
	}
	canonical, manifest, err := canonicalFiles(files, nodeMaxInputBytes)
	if err != nil {
		return core.Inspection{}, nil, err
	}
	contentFiles := make([]canonicalContentFile, 0, len(canonical))
	for _, file := range canonical {
		contentFiles = append(contentFiles, canonicalContentFile{Path: file.Path, Content: base64.RawStdEncoding.EncodeToString([]byte(file.Content))})
	}
	content, _ := json.Marshal(contentFiles)
	execution := core.ExecutionDescriptor{Stdio: &core.StaticEntry{RelativePath: executionPath, Digest: executionDigest, Argv: append([]string{}, argv...), Runtime: "node"}}
	inspection := core.Inspection{
		Candidate: candidate, ContentDigest: digestBytes(content), ManifestDigest: digestBytes(manifest),
		ExecutionDigest: digestJSON(execution), NetworkSchemaDigest: digestBytes([]byte("[]")), SecretSchemaDigest: digestBytes([]byte("[]")),
		Execution: execution, NetworkGrants: []core.NetworkGrant{}, SecretGrants: []core.SecretGrantDescriptor{},
	}
	if err := inspection.Validate(); err != nil {
		return core.Inspection{}, nil, err
	}
	return inspection, content, nil
}

func compactJSON(raw []byte) ([]byte, error) {
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return nil, ErrMalformed
	}
	return out.Bytes(), nil
}
