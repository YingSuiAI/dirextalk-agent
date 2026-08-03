// Package teambundle verifies the complete, immutable configuration required
// to enable the first production Pi Team Worker. It contains no credential
// bytes and performs no cloud operation.
package teambundle

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/security"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

const (
	SchemaV1                        = "dirextalk.agent.pi-team-bundle/v1"
	ManifestFilename                = "manifest.json"
	ModelProfilesFilename           = "model-profiles.json"
	RuntimeCatalogFilename          = "runtime-catalog.json"
	RuntimeCatalogPublicKeyFilename = "runtime-catalog-public-key"
	TeamPolicyFilename              = "team-policy.json"
	ModelOffersFilename             = "team-model-offers.json"
	ComputeCatalogFilename          = "team-compute-catalog.json"
	WorkerPublicationFilename       = "worker-ami-publication.json"
	RuntimeInstallationFilename     = "runtime-installation.json"

	qualificationDirectory          = "qualification"
	sbomFilename                    = "qualification/sbom.json"
	provenanceFilename              = "qualification/provenance.json"
	vulnerabilityScanFilename       = "qualification/vulnerability-scan.json"
	contractTestFilename            = "qualification/contract-test.json"
	licenseDecisionFilename         = "qualification/license-decision.json"
	maximumManifestBytes      int64 = 1 << 20
	maximumBundleFileBytes    int64 = 16 << 20
)

var (
	ErrInvalid = errors.New("invalid Pi Team bundle")

	digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

	requiredFiles = []string{
		ModelProfilesFilename,
		RuntimeCatalogFilename,
		RuntimeCatalogPublicKeyFilename,
		TeamPolicyFilename,
		ModelOffersFilename,
		ComputeCatalogFilename,
		WorkerPublicationFilename,
		RuntimeInstallationFilename,
		sbomFilename,
		provenanceFilename,
		vulnerabilityScanFilename,
		contractTestFilename,
		licenseDecisionFilename,
	}
)

type FileDigestV1 struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// ManifestV1 binds every mounted configuration file to the release facts
// independently revalidated by Load.
type ManifestV1 struct {
	SchemaVersion             string                  `json:"schema_version"`
	AgentInstanceID           string                  `json:"agent_instance_id"`
	AccountID                 string                  `json:"account_id"`
	Region                    string                  `json:"region"`
	Architecture              recipe.Architecture     `json:"architecture"`
	RuntimeCatalogRevision    string                  `json:"runtime_catalog_revision"`
	RuntimeCatalogSignerKeyID string                  `json:"runtime_catalog_signer_key_id"`
	TeamPolicyRevision        string                  `json:"team_policy_revision"`
	RuntimeReleaseID          string                  `json:"runtime_release_id"`
	RuntimeVersion            string                  `json:"runtime_version"`
	RuntimeImageDigest        string                  `json:"runtime_image_digest"`
	RuntimeAdapter            teamplan.RuntimeAdapter `json:"runtime_adapter"`
	RuntimeInstallationDigest string                  `json:"runtime_installation_digest"`
	RuntimeExecutableDigest   string                  `json:"runtime_executable_digest"`
	ModelProfileID            string                  `json:"model_profile_id"`
	WorkerPublicationDigest   string                  `json:"worker_publication_digest"`
	WorkerImageID             string                  `json:"worker_image_id"`
	WorkerImageDigest         string                  `json:"worker_image_digest"`
	Files                     []FileDigestV1          `json:"files"`
}

// Bundle contains only immutable, de-secreted startup configuration.
type Bundle struct {
	Manifest       ManifestV1
	ModelProfiles  *modelapi.ProfileCatalog
	RuntimeCatalog *teamplan.RuntimeCatalog
	Policy         *teamorchestration.StaticPolicyResolver
	ModelOffers    *teampricing.ModelOfferCatalog
	ComputeCatalog *awsprovider.TeamComputeCatalog
	WorkerRelease  workerrelease.ReleaseV1
}

// BuildManifest validates every bundle file and returns the exact manifest
// that must be written as manifest.json.
func BuildManifest(directory string) (ManifestV1, error) {
	inspected, err := inspect(directory, false)
	if err != nil {
		return ManifestV1{}, err
	}
	return inspected.Manifest, nil
}

// CanonicalManifestJSON returns the strict manifest representation used by the
// deployer digest and runtime comparison.
func CanonicalManifestJSON(manifest ManifestV1) ([]byte, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return nil, ErrInvalid
	}
	return encoded, nil
}

// Load verifies the manifest, every file digest, and all cross-artifact Pi
// release facts before any Team component is enabled.
func Load(directory string) (*Bundle, error) {
	rawManifest, err := readBundleFile(
		directory,
		ManifestFilename,
		maximumManifestBytes,
		true,
	)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(rawManifest))
	decoder.DisallowUnknownFields()
	var expected ManifestV1
	if err := decoder.Decode(&expected); err != nil {
		return nil, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) ||
		validateManifest(expected) != nil {
		return nil, ErrInvalid
	}
	actual, err := inspect(directory, true)
	if err != nil || !reflect.DeepEqual(expected, actual.Manifest) {
		return nil, ErrInvalid
	}
	actual.Manifest = expected
	return actual, nil
}

func inspect(directory string, requireManifest bool) (*Bundle, error) {
	if err := validateLayout(directory, requireManifest); err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(requiredFiles))
	digests := make([]FileDigestV1, 0, len(requiredFiles))
	for _, name := range requiredFiles {
		raw, err := readBundleFile(
			directory,
			name,
			maximumBundleFileBytes,
			false,
		)
		if err != nil {
			return nil, err
		}
		files[name] = raw
		digests = append(digests, FileDigestV1{
			Path:   name,
			SHA256: digestBytes(raw),
		})
	}
	slices.SortFunc(digests, func(left, right FileDigestV1) int {
		return strings.Compare(left.Path, right.Path)
	})

	profiles, err := modelapi.LoadProfileCatalog(
		filepath.Join(directory, ModelProfilesFilename),
	)
	if err != nil {
		return nil, ErrInvalid
	}
	publicKey, err := parseRuntimeCatalogPublicKey(
		files[RuntimeCatalogPublicKeyFilename],
	)
	if err != nil {
		return nil, err
	}
	runtimeCatalog, err := teamplan.ParseRuntimeCatalogJSON(
		files[RuntimeCatalogFilename],
		publicKey,
	)
	if err != nil {
		return nil, ErrInvalid
	}
	policy, err := teamorchestration.LoadStaticPolicyResolver(
		filepath.Join(directory, TeamPolicyFilename),
	)
	if err != nil {
		return nil, ErrInvalid
	}
	modelOffers, err := teampricing.LoadModelOfferCatalog(
		filepath.Join(directory, ModelOffersFilename),
		profiles,
	)
	if err != nil {
		return nil, ErrInvalid
	}
	computeCatalog, err := awsprovider.LoadTeamComputeCatalog(
		filepath.Join(directory, ComputeCatalogFilename),
	)
	if err != nil {
		return nil, ErrInvalid
	}
	workerRelease, err := workerrelease.ParsePublicationJSON(
		files[WorkerPublicationFilename],
	)
	if err != nil {
		return nil, ErrInvalid
	}
	installation, err := workerruntime.ParseInstallationJSON(
		files[RuntimeInstallationFilename],
	)
	if err != nil {
		return nil, ErrInvalid
	}
	for _, name := range []string{
		sbomFilename,
		provenanceFilename,
		vulnerabilityScanFilename,
		contractTestFilename,
		licenseDecisionFilename,
	} {
		if !json.Valid(files[name]) ||
			security.ContainsLikelySecret(string(files[name])) {
			return nil, ErrInvalid
		}
	}

	manifest, err := validateSemanticBindings(
		runtimeCatalog,
		policy,
		modelOffers,
		computeCatalog,
		profiles,
		workerRelease,
		installation,
		files,
		digests,
	)
	if err != nil {
		return nil, err
	}
	return &Bundle{
		Manifest:       manifest,
		ModelProfiles:  profiles,
		RuntimeCatalog: runtimeCatalog,
		Policy:         policy,
		ModelOffers:    modelOffers,
		ComputeCatalog: computeCatalog,
		WorkerRelease:  workerRelease,
	}, nil
}

func validateSemanticBindings(
	runtimeCatalog *teamplan.RuntimeCatalog,
	policyResolver *teamorchestration.StaticPolicyResolver,
	modelOffers *teampricing.ModelOfferCatalog,
	computeCatalog *awsprovider.TeamComputeCatalog,
	profiles *modelapi.ProfileCatalog,
	workerRelease workerrelease.ReleaseV1,
	installation workerruntime.Installation,
	files map[string][]byte,
	digests []FileDigestV1,
) (ManifestV1, error) {
	if runtimeCatalog == nil ||
		policyResolver == nil ||
		modelOffers == nil ||
		computeCatalog == nil ||
		profiles == nil ||
		runtimeCatalog.SchemaVersion() !=
			teamplan.RuntimeCatalogSchemaV2 ||
		len(runtimeCatalog.Releases()) != 1 ||
		len(runtimeCatalog.QualifiedReleases()) != 1 {
		return ManifestV1{}, ErrInvalid
	}
	release := runtimeCatalog.QualifiedReleases()[0]
	launch, launchFound := runtimeCatalog.LaunchEvidence(
		release.ReleaseID,
	)
	qualification, qualificationFound := runtimeCatalog.Evidence(
		release.ReleaseID,
	)
	if !launchFound ||
		!qualificationFound ||
		release.Family != teamplan.RuntimePi ||
		release.Adapter != teamplan.AdapterPiV1 ||
		release.Trust != teamplan.RuntimeTrustQualified ||
		release.Minimum.Arch != recipe.ArchitectureAMD64 ||
		release.Recommended.Arch != recipe.ArchitectureAMD64 ||
		installation.SchemaVersion !=
			workerruntime.InstallationSchemaV2 ||
		installation.RuntimeRelease.Adapter !=
			workerruntime.AdapterPiV1 ||
		installation.RuntimeRelease.ReleaseID != release.ReleaseID ||
		installation.RuntimeRelease.Version != release.Version ||
		installation.RuntimeRelease.ImageDigest != release.ImageDigest ||
		launch.InstallationManifestDigest !=
			digestBytes(files[RuntimeInstallationFilename]) ||
		launch.ExecutableDigest !=
			installation.RuntimeRelease.ExecutableSHA256 ||
		len(installation.Models) != 1 {
		return ManifestV1{}, ErrInvalid
	}
	if qualification.SBOMDigest != digestBytes(files[sbomFilename]) ||
		qualification.ProvenanceDigest !=
			digestBytes(files[provenanceFilename]) ||
		qualification.VulnerabilityScanDigest !=
			digestBytes(files[vulnerabilityScanFilename]) ||
		qualification.ContractTestDigest !=
			digestBytes(files[contractTestFilename]) ||
		qualification.LicenseDecisionDigest !=
			digestBytes(files[licenseDecisionFilename]) {
		return ManifestV1{}, ErrInvalid
	}

	policy, err := policyResolver.ResolveTeamPolicy(
		context.Background(),
		"pi-team-bundle-validator",
	)
	if err != nil ||
		policy.MaxWorkers != 1 ||
		policy.MaxConcurrentWorkers != 1 ||
		len(policy.AllowedRuntimeFamilies) != 1 ||
		policy.AllowedRuntimeFamilies[0] != teamplan.RuntimePi ||
		policy.MaxVCPUPerWorker < release.Recommended.VCPU ||
		policy.MaxMemoryMiBPerWorker <
			release.Recommended.MemoryMiB ||
		policy.MaxDiskGiBPerWorker < release.Recommended.DiskGiB {
		return ManifestV1{}, ErrInvalid
	}

	installedModel := installation.Models[0]
	offers := modelOffers.Offers()
	if len(offers) != 1 ||
		!offers[0].Enabled ||
		offers[0].ProfileID != installedModel.ProfileID ||
		offers[0].Provider != installedModel.Provider ||
		offers[0].Model != installedModel.Model ||
		offers[0].Interface !=
			teamplan.ModelInterface(installedModel.Interface) ||
		!validInstalledModelProfile(
			profiles,
			installedModel,
		) {
		return ManifestV1{}, ErrInvalid
	}

	if workerRelease.Architecture != recipe.ArchitectureAMD64 {
		return ManifestV1{}, ErrInvalid
	}
	zones, shapes, err := computeCatalog.Resolve(workerRelease.Region)
	if err != nil || len(zones) == 0 ||
		!hasCompatibleShape(shapes, release.Recommended) {
		return ManifestV1{}, ErrInvalid
	}

	return ManifestV1{
		SchemaVersion:             SchemaV1,
		AgentInstanceID:           workerRelease.AgentInstanceID,
		AccountID:                 workerRelease.AccountID,
		Region:                    workerRelease.Region,
		Architecture:              workerRelease.Architecture,
		RuntimeCatalogRevision:    runtimeCatalog.Revision(),
		RuntimeCatalogSignerKeyID: runtimeCatalog.SignerKeyID(),
		TeamPolicyRevision:        policyResolver.Revision(),
		RuntimeReleaseID:          release.ReleaseID,
		RuntimeVersion:            release.Version,
		RuntimeImageDigest:        release.ImageDigest,
		RuntimeAdapter:            release.Adapter,
		RuntimeInstallationDigest: launch.InstallationManifestDigest,
		RuntimeExecutableDigest:   launch.ExecutableDigest,
		ModelProfileID:            installedModel.ProfileID,
		WorkerPublicationDigest:   workerRelease.PublicationDigest,
		WorkerImageID:             workerRelease.ImageID,
		WorkerImageDigest:         workerRelease.ImageDigest,
		Files:                     digests,
	}, nil
}

func validInstalledModelProfile(
	profiles *modelapi.ProfileCatalog,
	installed workerruntime.QualifiedModel,
) bool {
	if profiles == nil {
		return false
	}
	profile, err := profiles.ResolveSelection(modelapi.Profile{
		ProfileID: installed.ProfileID,
	})
	if err != nil || profile.Model != installed.Model {
		return false
	}
	switch installed.Provider {
	case "openai":
		return installed.Interface ==
			workerruntime.ModelOpenAIResponses &&
			profile.Provider ==
				modelapi.ProviderOpenAICompatible
	case "deepseek":
		return installed.Interface ==
			workerruntime.ModelOpenAICompatible &&
			profile.Provider == modelapi.ProviderDeepSeek
	default:
		return false
	}
}

func hasCompatibleShape(
	shapes []awsprovider.TeamComputeShape,
	recommended teamplan.ResourceEnvelope,
) bool {
	for _, shape := range shapes {
		if shape.Architecture == recommended.Arch &&
			shape.DiskGiB >= recommended.DiskGiB {
			return true
		}
	}
	return false
}

func validateManifest(manifest ManifestV1) error {
	if manifest.SchemaVersion != SchemaV1 ||
		manifest.AgentInstanceID == "" ||
		manifest.AccountID == "" ||
		manifest.Region == "" ||
		manifest.Architecture != recipe.ArchitectureAMD64 ||
		!digestPattern.MatchString(manifest.RuntimeCatalogRevision) ||
		manifest.RuntimeCatalogSignerKeyID == "" ||
		!digestPattern.MatchString(manifest.TeamPolicyRevision) ||
		manifest.RuntimeReleaseID == "" ||
		manifest.RuntimeVersion == "" ||
		!digestPattern.MatchString(manifest.RuntimeImageDigest) ||
		manifest.RuntimeAdapter != teamplan.AdapterPiV1 ||
		!digestPattern.MatchString(
			manifest.RuntimeInstallationDigest,
		) ||
		!digestPattern.MatchString(manifest.RuntimeExecutableDigest) ||
		manifest.ModelProfileID == "" ||
		!digestPattern.MatchString(
			manifest.WorkerPublicationDigest,
		) ||
		manifest.WorkerImageID == "" ||
		!digestPattern.MatchString(manifest.WorkerImageDigest) ||
		len(manifest.Files) != len(requiredFiles) {
		return ErrInvalid
	}
	expected := append([]string(nil), requiredFiles...)
	slices.Sort(expected)
	for index, file := range manifest.Files {
		if index > 0 &&
			strings.Compare(
				manifest.Files[index-1].Path,
				file.Path,
			) >= 0 {
			return ErrInvalid
		}
		if file.Path != expected[index] ||
			!digestPattern.MatchString(file.SHA256) {
			return ErrInvalid
		}
	}
	return nil
}

func validateLayout(directory string, requireManifest bool) error {
	root, err := cleanBundleRoot(directory)
	if err != nil {
		return err
	}
	allowedFiles := make(map[string]struct{}, len(requiredFiles)+1)
	for _, name := range requiredFiles {
		allowedFiles[filepath.FromSlash(name)] = struct{}{}
	}
	if requireManifest {
		allowedFiles[ManifestFilename] = struct{}{}
	}
	seen := make(map[string]struct{}, len(allowedFiles))
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrInvalid
		}
		relative, relativeErr := filepath.Rel(root, path)
		if relativeErr != nil {
			return ErrInvalid
		}
		if relative == "." {
			return nil
		}
		info, infoErr := entry.Info()
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrInvalid
		}
		if entry.IsDir() {
			if relative != qualificationDirectory {
				return ErrInvalid
			}
			return nil
		}
		if !info.Mode().IsRegular() {
			return ErrInvalid
		}
		if _, allowed := allowedFiles[relative]; !allowed {
			return ErrInvalid
		}
		seen[relative] = struct{}{}
		return nil
	})
	if err != nil || len(seen) != len(allowedFiles) {
		return ErrInvalid
	}
	return nil
}

func readBundleFile(
	directory,
	name string,
	maximum int64,
	manifest bool,
) ([]byte, error) {
	root, err := cleanBundleRoot(directory)
	if err != nil {
		return nil, err
	}
	if filepath.Clean(name) != name ||
		filepath.IsAbs(name) ||
		name == "." ||
		strings.HasPrefix(name, ".."+string(filepath.Separator)) {
		return nil, ErrInvalid
	}
	path := filepath.Join(root, filepath.FromSlash(name))
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&0o022 != 0 ||
		info.Size() <= 0 ||
		info.Size() > maximum {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, ErrInvalid
	}
	if manifest && security.ContainsLikelySecret(string(raw)) {
		return nil, ErrInvalid
	}
	return raw, nil
}

func cleanBundleRoot(directory string) (string, error) {
	if strings.TrimSpace(directory) != directory || directory == "" {
		return "", ErrInvalid
	}
	absolute, err := filepath.Abs(filepath.Clean(directory))
	if err != nil {
		return "", ErrInvalid
	}
	info, err := os.Lstat(absolute)
	if err != nil ||
		info.Mode()&os.ModeSymlink != 0 ||
		!info.IsDir() ||
		info.Mode().Perm()&0o022 != 0 {
		return "", ErrInvalid
	}
	return absolute, nil
}

func parseRuntimeCatalogPublicKey(raw []byte) (ed25519.PublicKey, error) {
	encoded := strings.TrimSpace(string(raw))
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil ||
		len(decoded) != ed25519.PublicKeySize ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, ErrInvalid
	}
	return ed25519.PublicKey(decoded), nil
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}
