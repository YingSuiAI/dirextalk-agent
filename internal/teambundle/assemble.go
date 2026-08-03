package teambundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
)

const piSourceURL = "https://github.com/earendil-works/pi"

var sourceCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type AssemblyRequest struct {
	OutputDirectory          string
	RuntimeCatalogPrivateKey string
	SourceCommit             string
	QualificationID          string
	QualifiedAt              time.Time
	GeneratedAt              time.Time
	ColdStart                time.Duration
	ModelProfilesFile        string
	TeamPolicyFile           string
	ModelOffersFile          string
	ComputeCatalogFile       string
	WorkerPublicationFile    string
	RuntimeInstallationFile  string
	SBOMFile                 string
	ProvenanceFile           string
	VulnerabilityScanFile    string
	ContractTestFile         string
	LicenseDecisionFile      string
}

type AssemblyResult struct {
	Manifest       ManifestV1 `json:"manifest"`
	ManifestDigest string     `json:"manifest_digest"`
}

// AssemblePi creates a new, self-verifying release bundle. It never overwrites
// an existing directory and never copies the catalog private key.
func AssemblePi(request AssemblyRequest) (result AssemblyResult, err error) {
	if strings.TrimSpace(request.OutputDirectory) !=
		request.OutputDirectory ||
		request.OutputDirectory == "" ||
		!sourceCommitPattern.MatchString(request.SourceCommit) ||
		request.QualifiedAt.IsZero() ||
		request.QualifiedAt.Location() != time.UTC ||
		request.QualifiedAt.Nanosecond()%1000 != 0 ||
		request.GeneratedAt.IsZero() ||
		request.GeneratedAt.Location() != time.UTC ||
		request.GeneratedAt.Nanosecond()%1000 != 0 ||
		request.GeneratedAt.Before(request.QualifiedAt) ||
		request.ColdStart < 0 ||
		request.ColdStart > 30*time.Minute ||
		request.ColdStart%time.Second != 0 {
		return AssemblyResult{}, ErrInvalid
	}
	output, err := filepath.Abs(filepath.Clean(request.OutputDirectory))
	if err != nil {
		return AssemblyResult{}, ErrInvalid
	}
	if err := os.Mkdir(output, 0o700); err != nil {
		return AssemblyResult{}, ErrInvalid
	}
	complete := false
	defer func() {
		if !complete {
			_ = os.RemoveAll(output)
		}
	}()
	qualificationRoot := filepath.Join(output, qualificationDirectory)
	if err := os.Mkdir(qualificationRoot, 0o700); err != nil {
		return AssemblyResult{}, ErrInvalid
	}

	inputs := map[string]string{
		ModelProfilesFilename:       request.ModelProfilesFile,
		TeamPolicyFilename:          request.TeamPolicyFile,
		ModelOffersFilename:         request.ModelOffersFile,
		ComputeCatalogFilename:      request.ComputeCatalogFile,
		WorkerPublicationFilename:   request.WorkerPublicationFile,
		RuntimeInstallationFilename: request.RuntimeInstallationFile,
		sbomFilename:                request.SBOMFile,
		provenanceFilename:          request.ProvenanceFile,
		vulnerabilityScanFilename:   request.VulnerabilityScanFile,
		contractTestFilename:        request.ContractTestFile,
		licenseDecisionFilename:     request.LicenseDecisionFile,
	}
	rawInputs := make(map[string][]byte, len(inputs))
	for destination, source := range inputs {
		raw, readErr := readAssemblyFile(
			source,
			maximumBundleFileBytes,
			false,
		)
		if readErr != nil {
			return AssemblyResult{}, readErr
		}
		rawInputs[destination] = raw
	}
	installation, err := workerruntime.ParseInstallationJSON(
		rawInputs[RuntimeInstallationFilename],
	)
	if err != nil ||
		installation.SchemaVersion !=
			workerruntime.InstallationSchemaV2 ||
		installation.RuntimeRelease.Adapter !=
			workerruntime.AdapterPiV1 ||
		len(installation.Models) != 1 {
		return AssemblyResult{}, ErrInvalid
	}

	privateRaw, err := readAssemblyFile(
		request.RuntimeCatalogPrivateKey,
		256,
		true,
	)
	if err != nil {
		return AssemblyResult{}, err
	}
	privateKey, err := parsePrivateKey(privateRaw)
	clear(privateRaw)
	if err != nil {
		return AssemblyResult{}, err
	}
	defer clear(privateKey)

	qualification := teamplan.QualificationEvidence{
		QualificationID: request.QualificationID,
		SBOMDigest: digestBytes(
			rawInputs[sbomFilename],
		),
		ProvenanceDigest: digestBytes(
			rawInputs[provenanceFilename],
		),
		VulnerabilityScanDigest: digestBytes(
			rawInputs[vulnerabilityScanFilename],
		),
		ContractTestDigest: digestBytes(
			rawInputs[contractTestFilename],
		),
		LicenseDecisionDigest: digestBytes(
			rawInputs[licenseDecisionFilename],
		),
	}
	launch := teamplan.RuntimeLaunchEvidence{
		InstallationManifestDigest: digestBytes(
			rawInputs[RuntimeInstallationFilename],
		),
		ExecutableDigest: installation.RuntimeRelease.
			ExecutableSHA256,
	}
	runtimeRelease := teamplan.RuntimeRelease{
		ReleaseID:    installation.RuntimeRelease.ReleaseID,
		Family:       teamplan.RuntimePi,
		Version:      installation.RuntimeRelease.Version,
		SourceURL:    piSourceURL,
		SourceCommit: request.SourceCommit,
		License:      "MIT",
		ImageDigest:  installation.RuntimeRelease.ImageDigest,
		Adapter:      teamplan.AdapterPiV1,
		Capabilities: []teamplan.Capability{
			teamplan.CapabilityRepositoryRead,
			teamplan.CapabilityRepositoryWrite,
			teamplan.CapabilityCodeReview,
			teamplan.CapabilityShell,
			teamplan.CapabilityGit,
			teamplan.CapabilityTest,
			teamplan.CapabilityStructuredResults,
		},
		ModelInterfaces: []teamplan.ModelInterface{
			teamplan.ModelInterface(
				installation.Models[0].Interface,
			),
		},
		Suitability: []teamplan.Suitability{
			{
				WorkClass: teamplan.WorkSoftwareImplementation,
				Score:     95,
			},
			{
				WorkClass: teamplan.WorkSoftwareReview,
				Score:     90,
			},
			{
				WorkClass: teamplan.WorkSoftwareTest,
				Score:     94,
			},
			{
				WorkClass: teamplan.WorkGeneralTool,
				Score:     88,
			},
		},
		Minimum: teamplan.ResourceEnvelope{
			VCPU:      1,
			MemoryMiB: 1024,
			DiskGiB:   20,
			Arch:      recipe.ArchitectureAMD64,
		},
		Recommended: teamplan.ResourceEnvelope{
			VCPU:      2,
			MemoryMiB: 2048,
			DiskGiB:   20,
			Arch:      recipe.ArchitectureAMD64,
		},
		ColdStart:   request.ColdStart,
		Trust:       teamplan.RuntimeTrustQualified,
		QualifiedAt: request.QualifiedAt,
	}
	runtimeCatalog, publicKey, err := teamplan.SignRuntimeCatalogV2(
		request.GeneratedAt,
		[]teamplan.RuntimeCatalogReleaseSpec{{
			Runtime:       runtimeRelease,
			Qualification: &qualification,
			Launch:        &launch,
		}},
		privateKey,
	)
	if err != nil {
		return AssemblyResult{}, ErrInvalid
	}

	for destination, raw := range rawInputs {
		if err := writeExclusiveFile(
			filepath.Join(output, filepath.FromSlash(destination)),
			raw,
		); err != nil {
			return AssemblyResult{}, err
		}
	}
	if err := writeExclusiveFile(
		filepath.Join(output, RuntimeCatalogFilename),
		runtimeCatalog,
	); err != nil {
		return AssemblyResult{}, err
	}
	if err := writeExclusiveFile(
		filepath.Join(output, RuntimeCatalogPublicKeyFilename),
		publicKey,
	); err != nil {
		return AssemblyResult{}, err
	}

	manifest, err := BuildManifest(output)
	if err != nil {
		return AssemblyResult{}, err
	}
	manifestRaw, err := CanonicalManifestJSON(manifest)
	if err != nil {
		return AssemblyResult{}, err
	}
	if err := writeExclusiveFile(
		filepath.Join(output, ManifestFilename),
		manifestRaw,
	); err != nil {
		return AssemblyResult{}, err
	}
	verified, err := Load(output)
	if err != nil || !reflectManifestEqual(verified.Manifest, manifest) {
		return AssemblyResult{}, ErrInvalid
	}
	complete = true
	return AssemblyResult{
		Manifest:       manifest,
		ManifestDigest: digestBytes(manifestRaw),
	}, nil
}

func readAssemblyFile(
	path string,
	maximum int64,
	private bool,
) ([]byte, error) {
	if strings.TrimSpace(path) != path || path == "" {
		return nil, ErrInvalid
	}
	file, err := os.OpenFile(
		filepath.Clean(path),
		os.O_RDONLY|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&0o022 != 0 ||
		(private && info.Mode().Perm()&0o077 != 0) ||
		info.Size() <= 0 ||
		info.Size() > maximum {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, ErrInvalid
	}
	return raw, nil
}

func parsePrivateKey(raw []byte) (ed25519.PrivateKey, error) {
	encoded := strings.TrimSpace(string(raw))
	decoded, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil ||
		len(decoded) != ed25519.PrivateKeySize ||
		base64.RawURLEncoding.EncodeToString(decoded) != encoded {
		clear(decoded)
		return nil, ErrInvalid
	}
	derived := ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])
	defer clear(derived)
	if !equalBytes(derived, decoded) {
		clear(decoded)
		return nil, ErrInvalid
	}
	return ed25519.PrivateKey(decoded), nil
}

func writeExclusiveFile(path string, raw []byte) error {
	file, err := os.OpenFile(
		path,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		0o400,
	)
	if err != nil {
		return ErrInvalid
	}
	written, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil ||
		written != len(raw) ||
		syncErr != nil ||
		closeErr != nil {
		_ = os.Remove(path)
		return ErrInvalid
	}
	return nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	different := byte(0)
	for index := range left {
		different |= left[index] ^ right[index]
	}
	return different == 0
}

func reflectManifestEqual(left, right ManifestV1) bool {
	leftRaw, leftErr := CanonicalManifestJSON(left)
	rightRaw, rightErr := CanonicalManifestJSON(right)
	return leftErr == nil &&
		rightErr == nil &&
		equalBytes(leftRaw, rightRaw)
}
