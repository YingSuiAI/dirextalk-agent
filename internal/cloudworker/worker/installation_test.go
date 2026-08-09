//go:build unix

package worker

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultInstallationUsesQualifiedSourceSystemTrust(t *testing.T) {
	t.Parallel()
	paths := DefaultInstallationPaths()
	if paths.SystemTrustBundle != "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem" {
		t.Fatalf("system trust bundle = %q", paths.SystemTrustBundle)
	}
}

func TestLoadInstallationBindsImagePolicyAndProxyTrust(t *testing.T) {
	t.Parallel()
	fixture := newInstallationFixture(t)
	installation, err := loadInstallation(
		fixture.document, fixture.paths, uint32(os.Geteuid()),
	)
	if err != nil {
		t.Fatal(err)
	}
	if installation.Release.Executable.Path != fixture.paths.PiExecutable ||
		installation.Release.ResultExtension.Path != fixture.paths.ResultExtension ||
		installation.TrustRoots == nil || installation.OutboundProxyRoots == nil ||
		installation.SystemTrustRoots == nil ||
		installation.ModelRelayTrustBundlePath != fixture.paths.ModelRelayTrustBundle {
		t.Fatalf("installation = %+v", installation)
	}
}

func TestLoadInstallationRejectsPolicyProxyAndPathDrift(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*testing.T, *installationFixture){
		"host policy content": func(t *testing.T, fixture *installationFixture) {
			rewriteInstallationFile(t, fixture.paths.HostNetworkPolicy, []byte("drifted-policy\n"), 0o400)
		},
		"host policy manifest": func(t *testing.T, fixture *installationFixture) {
			fixture.manifest.HostNetworkPolicySHA256 = installationTestDigest([]byte("other-policy"))
			fixture.writeManifest(t)
		},
		"proxy trust content": func(t *testing.T, fixture *installationFixture) {
			rewriteInstallationFile(t, fixture.paths.OutboundProxyTrustBundle, installationTestCA(t), 0o400)
		},
		"proxy trust manifest": func(t *testing.T, fixture *installationFixture) {
			fixture.manifest.OutboundProxyTrustBundleSHA256 = installationTestDigest([]byte("other-ca"))
			fixture.writeManifest(t)
		},
		"model relay trust content": func(t *testing.T, fixture *installationFixture) {
			rewriteInstallationFile(t, fixture.paths.ModelRelayTrustBundle, installationTestCA(t), 0o400)
		},
		"model relay trust manifest": func(t *testing.T, fixture *installationFixture) {
			fixture.manifest.ModelRelayTrustBundleSHA256 = installationTestDigest([]byte("other-relay-ca"))
			fixture.writeManifest(t)
		},
		"policy symlink": func(t *testing.T, fixture *installationFixture) {
			outside := filepath.Join(filepath.Dir(fixture.paths.TrustedRoot), "outside-policy")
			if err := os.WriteFile(outside, []byte("outside\n"), 0o400); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(fixture.paths.HostNetworkPolicy); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, fixture.paths.HostNetworkPolicy); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fixture := newInstallationFixture(t)
			mutate(t, &fixture)
			_, err := loadInstallation(
				fixture.document, fixture.paths, uint32(os.Geteuid()),
			)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("drift error = %v", err)
			}
		})
	}
}

func TestBootstrapRejectsArtifactKMSAccountAndRegionDrift(t *testing.T) {
	fixture := newInstallationFixture(t)
	for name, kmsARN := range map[string]string{
		"account": "arn:aws:kms:us-east-1:999999999999:key/11111111-1111-4111-8111-111111111111",
		"region":  "arn:aws:kms:us-west-2:123456789012:key/11111111-1111-4111-8111-111111111111",
	} {
		t.Run(name, func(t *testing.T) {
			document := fixture.document
			document.ArtifactKMSKeyARN = kmsARN
			raw, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := ParseBootstrapDocument(raw); !errors.Is(err, ErrInvalid) {
				t.Fatalf("KMS drift error = %v", err)
			}
		})
	}
}

type installationFixture struct {
	paths    InstallationPaths
	manifest InstallationManifest
	document BootstrapDocument
}

func newInstallationFixture(t *testing.T) installationFixture {
	t.Helper()
	root := filepath.Join(t.TempDir(), "trusted-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := InstallationPaths{
		Manifest:                 filepath.Join(root, "share", "installation.json"),
		TrustBundle:              filepath.Join(root, "share", "control-plane-ca.pem"),
		OutboundProxyTrustBundle: filepath.Join(root, "share", "outbound-proxy-ca.pem"),
		ModelRelayTrustBundle:    filepath.Join(root, "share", "model-relay-ca.pem"),
		SystemTrustBundle:        filepath.Join(root, "share", "system-ca.pem"),
		HostNetworkPolicy:        filepath.Join(root, "share", "pi-egress.nft"),
		WorkerExecutable:         filepath.Join(root, "bin", "dirextalk-cloud-worker"),
		PiExecutable:             filepath.Join(root, "lib", "pi"),
		ResultExtension:          filepath.Join(root, "lib", "dirextalk-result.ts"),
		TrustedRoot:              root,
	}
	workerRaw := []byte("#!/bin/sh\nexit 0\n")
	piRaw := []byte("#!/bin/sh\nexit 0\n")
	extensionRaw := []byte("export {};\n")
	policyRaw := []byte("table inet dirextalk_pi_egress {}\n")
	trustRaw := installationTestCA(t)
	writeInstallationFile(t, paths.WorkerExecutable, workerRaw, 0o500)
	writeInstallationFile(t, paths.PiExecutable, piRaw, 0o500)
	writeInstallationFile(t, paths.ResultExtension, extensionRaw, 0o400)
	writeInstallationFile(t, paths.HostNetworkPolicy, policyRaw, 0o400)
	writeInstallationFile(t, paths.TrustBundle, trustRaw, 0o400)
	writeInstallationFile(t, paths.OutboundProxyTrustBundle, trustRaw, 0o400)
	writeInstallationFile(t, paths.ModelRelayTrustBundle, trustRaw, 0o400)
	writeInstallationFile(t, paths.SystemTrustBundle, trustRaw, 0o400)
	manifest := InstallationManifest{
		SchemaVersion:                  InstallationSchemaV1,
		AMIDigest:                      installationTestDigest([]byte("ami")),
		WorkerDigest:                   installationTestDigest(workerRaw),
		HostNetworkPolicySHA256:        installationTestDigest(policyRaw),
		OutboundProxyTrustBundleSHA256: installationTestDigest(trustRaw),
		ModelRelayTrustBundleSHA256:    installationTestDigest(trustRaw),
		PiVersion:                      "0.83.0",
		WorkerExecutable:               paths.WorkerExecutable,
		PiExecutable:                   paths.PiExecutable,
		PiExecutableSHA256:             installationTestDigest(piRaw),
		ResultExtension:                paths.ResultExtension,
		ResultExtensionSHA256:          installationTestDigest(extensionRaw),
	}
	piDigest, err := installationPiDigest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.PiDigest = piDigest
	proxyURL := "https://proxy.example.test:443"
	proxyServerName := "proxy.example.test"
	proxyBindingRaw, err := json.Marshal(struct {
		URL               string `json:"url"`
		ServerName        string `json:"server_name"`
		TrustBundleSHA256 string `json:"trust_bundle_sha256"`
	}{proxyURL, proxyServerName, manifest.OutboundProxyTrustBundleSHA256})
	if err != nil {
		t.Fatal(err)
	}
	document := BootstrapDocument{
		SchemaVersion: BootstrapSchemaV1,
		OwnerID:       "installation-test-owner",
		AccountID:     "123456789012", AccountGeneration: 1,
		Region: "us-east-1", ExecutionID: "11111111-1111-4111-8111-111111111111",
		TaskID: "22222222-2222-4222-8222-222222222222", ProviderID: "provider-1",
		LaunchIdentity: installationTestDigest([]byte("launch")), Generation: 1,
		PlanDigest:      installationTestDigest([]byte("plan")),
		ExecutionSHA256: installationTestDigest([]byte("execution")),
		TaskSHA256:      installationTestDigest([]byte("task")),
		AMIDigest:       manifest.AMIDigest, WorkerDigest: manifest.WorkerDigest,
		PiDigest:                      manifest.PiDigest,
		ControlPlaneEndpoint:          "https://control.example.test:443",
		ControlPlaneServerName:        "control.example.test",
		ControlPlaneTrustBundleSHA256: installationTestDigest(trustRaw),
		ModelRelayServerName:          "model-relay.example.test",
		ModelRelayTrustBundleSHA256:   manifest.ModelRelayTrustBundleSHA256,
		OutboundProxyURL:              proxyURL,
		OutboundProxyServerName:       proxyServerName,
		OutboundProxyTrustSHA256:      manifest.OutboundProxyTrustBundleSHA256,
		OutboundProxyBindingSHA256:    installationTestDigest(proxyBindingRaw),
		HostNetworkPolicySHA256:       manifest.HostNetworkPolicySHA256,
		WorkspaceMode:                 "none",
		InputManifestDigest:           installationTestDigest([]byte("manifest")),
		ModelAuthorizationDigest:      installationTestDigest([]byte("model")),
		ArtifactBindingDigest:         installationTestDigest([]byte("artifact")),
		ArtifactKMSKeyARN:             "arn:aws:kms:us-east-1:123456789012:key/11111111-1111-4111-8111-111111111111",
	}
	fixture := installationFixture{paths: paths, manifest: manifest, document: document}
	fixture.writeManifest(t)
	return fixture
}

func (fixture installationFixture) writeManifest(t *testing.T) {
	t.Helper()
	raw, err := json.Marshal(fixture.manifest)
	if err != nil {
		t.Fatal(err)
	}
	rewriteInstallationFile(t, fixture.paths.Manifest, raw, 0o400)
}

func writeInstallationFile(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func rewriteInstallationFile(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		writeInstallationFile(t, path, raw, mode)
		return
	} else if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func installationTestDigest(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func installationTestCA(t *testing.T) []byte {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "Dirextalk installation test CA"},
		NotBefore:    now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	certificate, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
}
