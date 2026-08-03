package teambundle

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/awsprovider"
	"github.com/YingSuiAI/dirextalk-agent/internal/recipe"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamorchestration"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
	"github.com/YingSuiAI/dirextalk-agent/internal/teampricing"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerami"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerrelease"
	"github.com/YingSuiAI/dirextalk-agent/internal/workerruntime"
	"github.com/google/uuid"
)

func TestAssemblePiCreatesSelfVerifyingCompleteBundle(t *testing.T) {
	t.Parallel()
	fixture := writeAssemblyFixture(t)
	output := filepath.Join(t.TempDir(), "pi-team-bundle")
	result, err := AssemblePi(fixture.request(output))
	if err != nil {
		t.Fatalf("AssemblePi() error = %v", err)
	}
	if result.Manifest.SchemaVersion != SchemaV1 ||
		result.Manifest.RuntimeAdapter != teamplan.AdapterPiV1 ||
		result.Manifest.ModelProfileID != "openai-pi-worker" ||
		result.Manifest.WorkerImageID !=
			"ami-0123456789abcdef0" ||
		!digestPattern.MatchString(result.ManifestDigest) {
		t.Fatalf("assembly result = %#v", result)
	}
	bundle, err := Load(output)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if bundle.Manifest.RuntimeReleaseID !=
		fixture.installation.RuntimeRelease.ReleaseID ||
		len(bundle.RuntimeCatalog.QualifiedReleases()) != 1 ||
		bundle.WorkerRelease.AgentInstanceID !=
			fixture.publication.ImageManifest.AgentInstanceID ||
		len(bundle.ModelOffers.Offers()) != 1 {
		t.Fatalf("loaded bundle = %#v", bundle)
	}
	privateBase := filepath.Base(fixture.privateKeyPath)
	if _, err := os.Stat(
		filepath.Join(output, privateBase),
	); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("catalog private key entered the release bundle")
	}
}

func TestAssemblePiAcceptsQualifiedDeepSeekModel(t *testing.T) {
	t.Parallel()
	fixture := writeAssemblyFixture(t)
	fixture.installation.Models[0] = workerruntime.QualifiedModel{
		ProfileID:      "deepseek-v4-pro",
		Provider:       "deepseek",
		Model:          "deepseek-v4-pro",
		Interface:      workerruntime.ModelOpenAICompatible,
		CredentialSlot: "model-token",
	}
	writeJSON(
		t,
		filepath.Join(
			fixture.root,
			RuntimeInstallationFilename,
		),
		fixture.installation,
	)
	writeJSON(
		t,
		filepath.Join(fixture.root, ModelProfilesFilename),
		map[string]any{
			"schema_version": 1,
			"profiles": []any{map[string]any{
				"profile_id":        "deepseek-v4-pro",
				"provider":          "deepseek",
				"model":             "deepseek-v4-pro",
				"base_url":          "https://api.deepseek.com",
				"secret_ref":        "mounted:model-token",
				"context_window":    65536,
				"max_output_tokens": 8192,
			}},
		},
	)
	writeJSON(
		t,
		filepath.Join(fixture.root, ModelOffersFilename),
		teampricing.ModelOfferCatalogDocument{
			SchemaVersion: teampricing.ModelOfferCatalogSchemaV1,
			Currency:      "USD",
			Sources: []teampricing.ModelPriceSource{{
				SourceID:   "deepseek-pricing-review-2026-07",
				Digest:     testDigest("4"),
				CapturedAt: fixture.qualifiedAt,
			}},
			Offers: []teampricing.ModelOfferEntry{{
				ProfileID:              "deepseek-v4-pro",
				WorkerProvider:         "deepseek",
				Interface:              teamplan.ModelOpenAICompatible,
				Quality:                teamplan.QualityBalanced,
				InputMicrosPerMillion:  1_000_000,
				OutputMicrosPerMillion: 4_000_000,
				WorkerCredentialRef: "secret_ref:model/" +
					"deepseek-v4-pro",
				Enabled:  true,
				SourceID: "deepseek-pricing-review-2026-07",
			}},
		},
	)
	output := filepath.Join(t.TempDir(), "pi-deepseek-bundle")
	result, err := AssemblePi(fixture.request(output))
	if err != nil {
		t.Fatalf("AssemblePi() error = %v", err)
	}
	bundle, err := Load(output)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	releases := bundle.RuntimeCatalog.QualifiedReleases()
	if result.Manifest.ModelProfileID != "deepseek-v4-pro" ||
		len(releases) != 1 ||
		len(releases[0].ModelInterfaces) != 1 ||
		releases[0].ModelInterfaces[0] !=
			teamplan.ModelOpenAICompatible {
		t.Fatalf(
			"DeepSeek bundle = manifest=%#v releases=%#v",
			result.Manifest,
			releases,
		)
	}
}

func TestLoadPiBundleRejectsTamperAndUnexpectedFiles(t *testing.T) {
	t.Parallel()
	fixture := writeAssemblyFixture(t)
	t.Run("tampered runtime installation", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "bundle")
		if _, err := AssemblePi(fixture.request(output)); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(output, RuntimeInstallationFilename)
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-1] ^= 1
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(output); !errors.Is(err, ErrInvalid) {
			t.Fatalf("tampered Load() error = %v", err)
		}
	})
	t.Run("unexpected file", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "bundle")
		if _, err := AssemblePi(fixture.request(output)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(
			filepath.Join(output, "unreviewed.json"),
			[]byte(`{"enabled":true}`),
			0o400,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(output); !errors.Is(err, ErrInvalid) {
			t.Fatalf("unexpected-file Load() error = %v", err)
		}
	})
	t.Run("manifest substitution", func(t *testing.T) {
		output := filepath.Join(t.TempDir(), "bundle")
		if _, err := AssemblePi(fixture.request(output)); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(output, ManifestFilename)
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var manifest ManifestV1
		if err := json.Unmarshal(raw, &manifest); err != nil {
			t.Fatal(err)
		}
		manifest.Region = "us-west-2"
		raw, err = json.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(output); !errors.Is(err, ErrInvalid) {
			t.Fatalf("substituted manifest Load() error = %v", err)
		}
	})
}

type assemblyFixture struct {
	root            string
	privateKeyPath  string
	installation    workerruntime.InstallationV2
	publication     workerrelease.PublicationV1
	qualifiedAt     time.Time
	generatedAt     time.Time
	sourceCommit    string
	qualificationID string
}

func (fixture assemblyFixture) request(output string) AssemblyRequest {
	return AssemblyRequest{
		OutputDirectory:          output,
		RuntimeCatalogPrivateKey: fixture.privateKeyPath,
		SourceCommit:             fixture.sourceCommit,
		QualificationID:          fixture.qualificationID,
		QualifiedAt:              fixture.qualifiedAt,
		GeneratedAt:              fixture.generatedAt,
		ColdStart:                45 * time.Second,
		ModelProfilesFile: filepath.Join(
			fixture.root,
			ModelProfilesFilename,
		),
		TeamPolicyFile: filepath.Join(
			fixture.root,
			TeamPolicyFilename,
		),
		ModelOffersFile: filepath.Join(
			fixture.root,
			ModelOffersFilename,
		),
		ComputeCatalogFile: filepath.Join(
			fixture.root,
			ComputeCatalogFilename,
		),
		WorkerPublicationFile: filepath.Join(
			fixture.root,
			WorkerPublicationFilename,
		),
		RuntimeInstallationFile: filepath.Join(
			fixture.root,
			RuntimeInstallationFilename,
		),
		SBOMFile: filepath.Join(
			fixture.root,
			"sbom.json",
		),
		ProvenanceFile: filepath.Join(
			fixture.root,
			"provenance.json",
		),
		VulnerabilityScanFile: filepath.Join(
			fixture.root,
			"vulnerability-scan.json",
		),
		ContractTestFile: filepath.Join(
			fixture.root,
			"contract-test.json",
		),
		LicenseDecisionFile: filepath.Join(
			fixture.root,
			"license-decision.json",
		),
	}
}

func writeAssemblyFixture(t *testing.T) assemblyFixture {
	t.Helper()
	root := t.TempDir()
	qualifiedAt := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)
	generatedAt := qualifiedAt.Add(time.Minute)
	installation := workerruntime.InstallationV2{
		SchemaVersion:          workerruntime.InstallationSchemaV2,
		CredentialPolicy:       workerruntime.CredentialPolicyV1,
		ContextRoot:            workerruntime.DefaultContextRoot,
		WorkspaceRoot:          workerruntime.DefaultWorkspaceRoot,
		CredentialRoot:         workerruntime.DefaultCredentialRoot,
		StateRoot:              workerruntime.DefaultStateRoot,
		GitExecutable:          workerruntime.DefaultGitExecutable,
		SearchPath:             workerruntime.DefaultRuntimeSearchPath,
		PatchCollectionEnabled: true,
		RuntimeRelease: workerruntime.InstalledRelease{
			ReleaseID:        "511acecc-3e4e-4bc5-890e-89638945c72c",
			Version:          "0.83.0",
			ImageDigest:      testDigest("1"),
			Adapter:          workerruntime.AdapterPiV1,
			ExecutablePath:   workerruntime.DefaultPiExecutable,
			ExecutableSHA256: testDigest("2"),
		},
		Extensions: []workerruntime.InstalledExtension{{
			Name:   workerruntime.PiResultExtensionName,
			Path:   workerruntime.DefaultPiResultExtension,
			SHA256: testDigest("3"),
		}},
		Models: []workerruntime.QualifiedModel{{
			ProfileID:      "openai-pi-worker",
			Provider:       "openai",
			Model:          "gpt-5.3-codex",
			Interface:      workerruntime.ModelOpenAIResponses,
			CredentialSlot: "model-token",
		}},
	}
	writeJSON(t, filepath.Join(root, RuntimeInstallationFilename), installation)
	writeJSON(t, filepath.Join(root, ModelProfilesFilename), map[string]any{
		"schema_version": 1,
		"profiles": []any{map[string]any{
			"profile_id":        "openai-pi-worker",
			"provider":          "openai_compatible",
			"model":             "gpt-5.3-codex",
			"base_url":          "https://api.openai.com/v1",
			"secret_ref":        "mounted:model-token",
			"context_window":    128000,
			"max_output_tokens": 32000,
		}},
	})
	writeJSON(
		t,
		filepath.Join(root, TeamPolicyFilename),
		teamorchestration.StaticPolicyDocument{
			SchemaVersion:             teamorchestration.StaticPolicySchemaV1,
			MaxWorkers:                1,
			MaxConcurrentWorkers:      1,
			MaxRoleDurationSeconds:    3600,
			MaxVCPUPerWorker:          2,
			MaxMemoryMiBPerWorker:     2048,
			MaxDiskGiBPerWorker:       20,
			MaxPlanCostMicros:         10_000_000,
			SafetyMarginBasisPoints:   2000,
			FixedWorkerOverheadMicros: 1000,
			AllowedRuntimeFamilies: []teamplan.RuntimeFamily{
				teamplan.RuntimePi,
			},
		},
	)
	writeJSON(
		t,
		filepath.Join(root, ModelOffersFilename),
		teampricing.ModelOfferCatalogDocument{
			SchemaVersion: teampricing.ModelOfferCatalogSchemaV1,
			Currency:      "USD",
			Sources: []teampricing.ModelPriceSource{{
				SourceID:   "openai-pricing-review-2026-07",
				Digest:     testDigest("4"),
				CapturedAt: qualifiedAt,
			}},
			Offers: []teampricing.ModelOfferEntry{{
				ProfileID:              "openai-pi-worker",
				WorkerProvider:         "openai",
				Interface:              teamplan.ModelOpenAIResponses,
				Quality:                teamplan.QualityBalanced,
				InputMicrosPerMillion:  2_000_000,
				OutputMicrosPerMillion: 8_000_000,
				WorkerCredentialRef:    "secret_ref:model/openai-pi-worker",
				Enabled:                true,
				SourceID:               "openai-pricing-review-2026-07",
			}},
		},
	)
	writeJSON(
		t,
		filepath.Join(root, ComputeCatalogFilename),
		awsprovider.TeamComputeCatalogDocument{
			SchemaVersion: awsprovider.TeamComputeCatalogSchemaV1,
			Regions: []awsprovider.TeamComputeRegion{{
				Region:            "us-east-1",
				AvailabilityZones: []string{"us-east-1a"},
				Shapes: []awsprovider.TeamComputeShape{{
					InstanceType: "t3.small",
					Architecture: recipe.ArchitectureAMD64,
					DiskGiB:      20,
				}},
			}},
		},
	)
	publication := testPublication(t, qualifiedAt)
	writeJSON(
		t,
		filepath.Join(root, WorkerPublicationFilename),
		publication,
	)
	for _, name := range []string{
		"sbom.json",
		"provenance.json",
		"vulnerability-scan.json",
		"contract-test.json",
		"license-decision.json",
	} {
		writeJSON(t, filepath.Join(root, name), map[string]any{
			"schema_version": "dirextalk.test/" + name,
			"status":         "passed",
		})
	}
	seed := sha256.Sum256([]byte("pi team bundle test key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	privateKeyPath := filepath.Join(root, "runtime-catalog-private-key")
	if err := os.WriteFile(
		privateKeyPath,
		[]byte(base64.RawURLEncoding.EncodeToString(privateKey)),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	clear(privateKey)
	return assemblyFixture{
		root:            root,
		privateKeyPath:  privateKeyPath,
		installation:    installation,
		publication:     publication,
		qualifiedAt:     qualifiedAt,
		generatedAt:     generatedAt,
		sourceCommit:    strings.Repeat("a", 40),
		qualificationID: uuid.NewSHA1(uuid.NameSpaceOID, []byte("qualification")).String(),
	}
}

func testPublication(
	t *testing.T,
	createdAt time.Time,
) workerrelease.PublicationV1 {
	t.Helper()
	image := workerami.ImageManifestV1{
		SchemaVersion: workerami.ImageManifestSchemaV1,
		AgentInstanceID: "11111111-1111-4111-8111-" +
			"111111111111",
		ImageID:               "ami-0123456789abcdef0",
		ImageName:             "dtx-worker-ami-0123456789abcdef0123",
		RootSnapshotID:        "snap-0123456789abcdef0",
		AccountID:             "123456789012",
		Region:                "us-east-1",
		Architecture:          "amd64",
		BaseAMIID:             "ami-0abcdef0123456789",
		BaseAMIOwnerID:        "099720109477",
		RootDeviceName:        "/dev/sda1",
		ReleaseManifestDigest: testDigest("5"),
		WorkerRootFSDigest:    testDigest("6"),
		WorkerBinaryDigest:    testDigest("7"),
		CreatedAt:             createdAt.UTC().Format(time.RFC3339),
	}
	attestation := awsprovider.WorkerAMIAttestationV1{
		SchemaVersion:         awsprovider.WorkerAMIAttestationSchemaV1,
		AgentInstanceID:       image.AgentInstanceID,
		AMIID:                 image.ImageID,
		RootSnapshotID:        image.RootSnapshotID,
		AccountID:             image.AccountID,
		Region:                image.Region,
		Architecture:          recipe.ArchitectureAMD64,
		ReleaseManifestDigest: image.ReleaseManifestDigest,
		WorkerRootFSDigest:    image.WorkerRootFSDigest,
		WorkerBinaryDigest:    image.WorkerBinaryDigest,
		ObservedAt:            createdAt.Add(time.Minute),
	}
	imageDigest, err := attestation.ImageDigest()
	if err != nil {
		t.Fatal(err)
	}
	return workerrelease.PublicationV1{
		SchemaVersion: workerrelease.PublicationSchemaV1,
		ImageManifest: image,
		ImageDigest:   imageDigest,
		Attestation:   attestation,
	}
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func testDigest(fill string) string {
	return "sha256:" + strings.Repeat(fill, 64)
}
