package resource

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/installer"
	installerbootstrap "github.com/YingSuiAI/dirextalk-agent/internal/installer/bootstrap"
)

func TestAWSWorkerInstallerTrustIsApprovalBoundAndPartOfResourceDigest(t *testing.T) {
	spec := workerInstanceSpec()
	deploymentID := spec.Instance.Bootstrap.DeploymentID
	spec.Instance.Bootstrap.InstallerTrust = testAWSWorkerInstallerTrust(t, deploymentID, 0x41)
	spec.Instance.Bootstrap.InstallerArtifacts = testAWSWorkerInstallerSources(spec.Instance.Bootstrap.InstallerTrust, deploymentID, "ap-south-1")
	first, err := spec.Digest(TypeEC2)
	if err != nil {
		t.Fatal(err)
	}

	clone := spec.Clone()
	spec.Instance.Bootstrap.InstallerTrust = testAWSWorkerInstallerTrust(t, deploymentID, 0x42)
	spec.Instance.Bootstrap.InstallerArtifacts = testAWSWorkerInstallerSources(spec.Instance.Bootstrap.InstallerTrust, deploymentID, "ap-south-1")
	if bytes.Equal(clone.Instance.Bootstrap.InstallerTrust.PublicKey, spec.Instance.Bootstrap.InstallerTrust.PublicKey) {
		t.Fatal("resource clone retained mutable installer trust bytes")
	}
	second, err := spec.Digest(TypeEC2)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("installer trust change did not change the approved resource digest")
	}

	mismatched := workerInstanceSpec()
	mismatched.Instance.Bootstrap.InstallerTrust = testAWSWorkerInstallerTrust(t, "33333333-3333-4333-8333-333333333333", 0x42)
	mismatched.Instance.Bootstrap.InstallerArtifacts = testAWSWorkerInstallerSources(mismatched.Instance.Bootstrap.InstallerTrust, "33333333-3333-4333-8333-333333333333", "ap-south-1")
	if err := mismatched.Validate(TypeEC2); err == nil {
		t.Fatal("resource accepted installer trust for another deployment")
	}
}

func testAWSWorkerInstallerTrust(t *testing.T, deploymentID string, keyByte byte) *installerbootstrap.RootTrustMaterialV1 {
	t.Helper()
	config := installer.DaemonConfigV1{
		SchemaVersion: installer.DaemonConfigSchema,
		Binding: installer.BindingV1{
			AgentInstanceID: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			DeploymentID:    deploymentID,
			TaskID:          "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
			PlanHash:        "sha256:" + strings.Repeat("c", 64),
			ApprovalID:      "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
			RecipeDigest:    "sha256:" + strings.Repeat("e", 64),
		},
		TargetRoot: installer.PreinstalledArtifactRoot,
	}
	artifactDigest := sha256.Sum256([]byte("worker installer"))
	plan := installer.InstallerPlanV1{
		SchemaVersion: installer.PlanSchemaV1, Binding: config.Binding,
		Artifacts: []installer.ArtifactV1{{Name: "installer", SHA256: "sha256:" + hex.EncodeToString(artifactDigest[:]), SizeBytes: 16, TargetPath: installer.PreinstalledArtifactRoot + "/installer"}},
		Commands:  []installer.CommandV1{{CommandID: "install", Argv: []string{installer.PreinstalledArtifactRoot + "/installer"}, WorkingDirectory: installer.PreinstalledArtifactRoot, TimeoutSeconds: 30, ArtifactRefs: []string{"installer"}}},
		ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}
	issuer, err := installer.NewTrustIssuer(bytes.Repeat([]byte{keyByte}, 32))
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	delivery, err := issuer.Issue(plan, config, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	root, err := delivery.RootTrustMaterial(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	material, err := installerbootstrap.NewRootTrustMaterial(root)
	if err != nil {
		t.Fatal(err)
	}
	return &material
}

func testAWSWorkerInstallerSources(trust *installerbootstrap.RootTrustMaterialV1, deploymentID, region string) []installerbootstrap.ArtifactSourceV1 {
	artifact := trust.ArtifactManifest.Manifest.Artifacts[0]
	return []installerbootstrap.ArtifactSourceV1{{
		SchemaVersion: installerbootstrap.ArtifactSourceSchemaV1, Name: artifact.Name, Bucket: "dtx-artifacts",
		Key: "deployments/" + deploymentID + "/artifacts/" + artifact.Name, VersionID: "version-1",
		KMSKeyARN: "arn:aws:kms:" + region + ":123456789012:key/11111111-2222-4333-8444-555555555555",
		SHA256:    artifact.SHA256, SizeBytes: artifact.SizeBytes, TargetPath: artifact.TargetPath,
		RecipeDigest: trust.ArtifactManifest.Manifest.Binding.RecipeDigest,
	}}
}
