package installer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Materializer interface {
	Materialize(Paths) error
}

type RealMaterializer struct{}

func (RealMaterializer) Materialize(paths Paths) error {
	provenance, err := LoadProvenance(paths.Resolve(ProvenancePath))
	if err != nil {
		return err
	}
	provenanceBytes, err := os.ReadFile(paths.Resolve(ProvenancePath))
	if err != nil {
		return fmt.Errorf("read provenance: %w", err)
	}
	provenanceDigest := sha256.Sum256(provenanceBytes)
	marker := hex.EncodeToString(provenanceDigest[:]) + "\n"
	release := paths.Resolve(ReleaseRoot)
	qdrantArchive := paths.Resolve(QdrantArchivePath)
	if err := verifyArtifact(qdrantArchive, QdrantSize, QdrantSHA256); err != nil {
		return fmt.Errorf("verify qdrant artifact: %w", err)
	}
	adapterArchive := paths.Resolve(AdapterArchivePath)
	if err := verifyArtifact(adapterArchive, provenance.AdapterBundle.Size, provenance.AdapterBundle.SHA256); err != nil {
		return fmt.Errorf("verify adapter artifact: %w", err)
	}

	releases := filepath.Dir(release)
	if err := ensureSecureOwnedDirectory(paths, InstallRoot, 0o755, 0, 0); err != nil {
		return err
	}
	if err := ensureSecureOwnedDirectory(paths, filepath.Dir(ReleaseRoot), 0o755, 0, 0); err != nil {
		return err
	}
	replaced := filepath.Join(releases, ".v1-replaced")
	if err := recoverReleaseReplacement(release, replaced, releases); err != nil {
		return err
	}
	stage := filepath.Join(releases, ".v1-staging")
	if err := removeFixedStage(stage, releases); err != nil {
		return err
	}
	if err := os.Mkdir(stage, 0o755); err != nil {
		return fmt.Errorf("create release stage: %w", err)
	}
	complete := false
	defer func() {
		if !complete {
			_ = removeFixedStage(stage, releases)
		}
	}()

	if err := extractTarGzip(qdrantArchive, stage, archivePolicy{
		maxEntries: 4,
		maxFile:    128 * 1024 * 1024,
		maxTotal:   128 * 1024 * 1024,
		allow: func(name string, directory bool) bool {
			return !directory && name == "qdrant"
		},
		verify: map[string]ModelFileEvidence{},
		modes:  map[string]os.FileMode{"qdrant": 0o755},
	}); err != nil {
		return fmt.Errorf("extract qdrant: %w", err)
	}
	if err := extractTarGzip(adapterArchive, stage, archivePolicy{
		maxEntries: 100_000,
		maxFile:    128 * 1024 * 1024,
		maxTotal:   1024 * 1024 * 1024,
		allow:      allowedAdapterMember,
		verify:     map[string]ModelFileEvidence{},
		modes:      map[string]os.FileMode{},
	}); err != nil {
		return fmt.Errorf("extract adapter: %w", err)
	}
	modelRoot := filepath.Join(stage, "model")
	if err := os.Mkdir(modelRoot, 0o755); err != nil {
		return fmt.Errorf("create model root: %w", err)
	}
	if err := extractTarGzip(paths.Resolve(ModelArchivePath), modelRoot, archivePolicy{
		maxEntries: 16,
		maxFile:    512 * 1024 * 1024,
		maxTotal:   512 * 1024 * 1024,
		allow: func(name string, directory bool) bool {
			if directory {
				return name == "onnx"
			}
			_, ok := expectedModelFiles[name]
			return ok
		},
		verify: expectedModelFiles,
		modes:  map[string]os.FileMode{},
	}); err != nil {
		return fmt.Errorf("extract model: %w", err)
	}
	if err := os.WriteFile(filepath.Join(stage, ".provenance-sha256"), []byte(marker), 0o444); err != nil {
		return fmt.Errorf("write release marker: %w", err)
	}
	if exact, err := exactInstalledTree(release, stage); err != nil {
		return err
	} else if exact {
		if err := removeFixedStage(stage, releases); err != nil {
			return err
		}
		complete = true
		if err := removeFixedReplacement(replaced, releases); err != nil {
			return err
		}
		return ensureCurrentSymlink(paths)
	}
	if _, err := os.Lstat(replaced); err == nil {
		if err := os.RemoveAll(release); err != nil {
			return fmt.Errorf("remove drifted installed release: %w", err)
		}
	} else if os.IsNotExist(err) {
		if _, releaseErr := os.Lstat(release); releaseErr == nil {
			if err := os.Rename(release, replaced); err != nil {
				return fmt.Errorf("preserve drifted installed release: %w", err)
			}
		} else if !os.IsNotExist(releaseErr) {
			return fmt.Errorf("inspect installed release: %w", releaseErr)
		}
	} else {
		return fmt.Errorf("inspect preserved release: %w", err)
	}
	if err := os.Rename(stage, release); err != nil {
		return fmt.Errorf("promote release: %w", err)
	}
	if err := syncDirectory(releases); err != nil {
		return err
	}
	complete = true
	if err := removeFixedReplacement(replaced, releases); err != nil {
		return err
	}
	return ensureCurrentSymlink(paths)
}

func recoverReleaseReplacement(release, replaced, parent string) error {
	_, releaseErr := os.Lstat(release)
	_, replacedErr := os.Lstat(replaced)
	if os.IsNotExist(releaseErr) && replacedErr == nil {
		if err := os.Rename(replaced, release); err != nil {
			return fmt.Errorf("recover preserved installed release: %w", err)
		}
		return syncDirectory(parent)
	}
	if releaseErr != nil && !os.IsNotExist(releaseErr) {
		return fmt.Errorf("inspect installed release: %w", releaseErr)
	}
	if replacedErr != nil && !os.IsNotExist(replacedErr) {
		return fmt.Errorf("inspect preserved installed release: %w", replacedErr)
	}
	return nil
}

func exactInstalledTree(actualRoot, expectedRoot string) (bool, error) {
	if _, err := os.Lstat(actualRoot); os.IsNotExist(err) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("inspect installed release tree: %w", err)
	}
	expected := make(map[string]os.FileInfo)
	if err := filepath.Walk(expectedRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("inspect expected release tree")
		}
		relative, relErr := filepath.Rel(expectedRoot, path)
		if relErr != nil {
			return fmt.Errorf("resolve expected release tree")
		}
		expected[relative] = info
		return nil
	}); err != nil {
		return false, err
	}
	seen := make(map[string]bool, len(expected))
	err := filepath.Walk(actualRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("installed release tree is unsafe")
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return errInstalledTreeDrift
		}
		relative, relErr := filepath.Rel(actualRoot, path)
		if relErr != nil {
			return fmt.Errorf("resolve installed release tree")
		}
		want, ok := expected[relative]
		if !ok || want.IsDir() != info.IsDir() || want.Mode().Perm() != info.Mode().Perm() {
			return errInstalledTreeDrift
		}
		actualUID, actualGID, actualOwnership := ownership(info)
		expectedUID, expectedGID, expectedOwnership := ownership(want)
		if !actualOwnership || !expectedOwnership || actualUID != expectedUID || actualGID != expectedGID {
			return errInstalledTreeDrift
		}
		seen[relative] = true
		if info.Mode().IsRegular() {
			actualSize, actualDigest, digestErr := fileDigest(path)
			expectedSize, expectedDigest, expectedErr := fileDigest(filepath.Join(expectedRoot, relative))
			if digestErr != nil || expectedErr != nil || actualSize != expectedSize || actualDigest != expectedDigest {
				return errInstalledTreeDrift
			}
		}
		return nil
	})
	if errors.Is(err, errInstalledTreeDrift) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(seen) == len(expected), nil
}

var errInstalledTreeDrift = errors.New("installed release tree drift")

func verifyArtifact(path string, expectedSize int64, expectedDigest string) error {
	size, digest, err := fileDigest(path)
	if err != nil {
		return err
	}
	if size != expectedSize || digest != expectedDigest {
		return fmt.Errorf("artifact size or digest mismatch")
	}
	return nil
}

func allowedAdapterMember(name string, directory bool) bool {
	if name == "adapter-manifest.json" || name == "dependency-lock.json" || name == "sbom.spdx.json" {
		return !directory
	}
	if name == "adapter" || name == "pydeps" {
		return directory
	}
	if strings.HasPrefix(name, "adapter/") || strings.HasPrefix(name, "pydeps/") {
		return true
	}
	return false
}

func ensureCurrentSymlink(paths Paths) error {
	current := paths.Resolve(InstallRoot + "/current")
	release := paths.Resolve(ReleaseRoot)
	if target, err := os.Readlink(current); err == nil {
		if target != release {
			return fmt.Errorf("current release symlink points elsewhere")
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("current release path is not a symlink: %w", err)
	}
	if err := ensureSecureOwnedDirectory(paths, InstallRoot, 0o755, 0, 0); err != nil {
		return err
	}
	temporary := current + ".new"
	if err := os.Symlink(release, temporary); err != nil {
		return fmt.Errorf("create current release symlink: %w", err)
	}
	if err := os.Rename(temporary, current); err != nil {
		_ = os.Remove(temporary)
		return fmt.Errorf("promote current release symlink: %w", err)
	}
	return nil
}

func removeFixedStage(stage, parent string) error {
	if filepath.Dir(filepath.Clean(stage)) != filepath.Clean(parent) || filepath.Base(stage) != ".v1-staging" {
		return fmt.Errorf("refuse unsafe stage cleanup")
	}
	if err := os.RemoveAll(stage); err != nil {
		return fmt.Errorf("clean fixed release stage: %w", err)
	}
	return nil
}

func removeFixedReplacement(path, parent string) error {
	if filepath.Dir(filepath.Clean(path)) != filepath.Clean(parent) || filepath.Base(path) != ".v1-replaced" {
		return fmt.Errorf("refuse unsafe replacement cleanup")
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("clean fixed replaced release: %w", err)
	}
	return syncDirectory(parent)
}
