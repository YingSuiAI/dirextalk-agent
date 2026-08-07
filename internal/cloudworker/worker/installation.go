package worker

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	cloudruntime "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/runtime"
)

const (
	InstallationSchemaV1  = "dirextalk.agent.cloud-worker-installation/v1"
	MaxInstallationBytes  = 16 << 10
	MaxInstalledFileBytes = int64(512 << 20)

	DefaultInstallationManifestPath = "/usr/local/share/dirextalk-cloud-worker/installation.json"
	DefaultTrustBundlePath          = "/usr/local/share/dirextalk-cloud-worker/control-plane-ca.pem"
	DefaultOutboundProxyTrustPath   = "/usr/local/share/dirextalk-cloud-worker/outbound-proxy-ca.pem"
	DefaultModelRelayTrustPath      = cloudruntime.PiModelRelayTrustBundlePath
	DefaultSystemTrustBundlePath    = "/etc/ssl/certs/ca-certificates.crt"
	DefaultHostNetworkPolicyPath    = "/usr/local/share/dirextalk-cloud-worker/pi-egress.nft"
	DefaultWorkerExecutablePath     = "/usr/local/bin/dirextalk-cloud-worker"
	DefaultPiExecutablePath         = "/usr/local/lib/dirextalk-cloud-worker/pi/pi"
	DefaultResultExtensionPath      = "/usr/local/lib/dirextalk-cloud-worker/pi/dirextalk-result.ts"
	DefaultStateRoot                = "/var/lib/dirextalk-cloud-worker/state"
	DefaultWorkspaceRoot            = "/var/lib/dirextalk-cloud-worker/workspaces"
)

type InstallationManifest struct {
	SchemaVersion                  string `json:"schema_version"`
	AMIDigest                      string `json:"ami_digest"`
	WorkerDigest                   string `json:"worker_digest"`
	PiDigest                       string `json:"pi_digest"`
	HostNetworkPolicySHA256        string `json:"host_network_policy_sha256"`
	OutboundProxyTrustBundleSHA256 string `json:"outbound_proxy_trust_bundle_sha256"`
	ModelRelayTrustBundleSHA256    string `json:"model_relay_trust_bundle_sha256"`
	PiVersion                      string `json:"pi_version"`
	WorkerExecutable               string `json:"worker_executable"`
	PiExecutable                   string `json:"pi_executable"`
	PiExecutableSHA256             string `json:"pi_executable_sha256"`
	ResultExtension                string `json:"result_extension"`
	ResultExtensionSHA256          string `json:"result_extension_sha256"`
}

type InstallationPaths struct {
	Manifest                 string
	TrustBundle              string
	OutboundProxyTrustBundle string
	ModelRelayTrustBundle    string
	SystemTrustBundle        string
	HostNetworkPolicy        string
	WorkerExecutable         string
	PiExecutable             string
	ResultExtension          string
	TrustedRoot              string
}

type Installation struct {
	Release                   cloudruntime.PiRelease
	TrustRoots                *x509.CertPool
	OutboundProxyRoots        *x509.CertPool
	SystemTrustRoots          *x509.CertPool
	ModelRelayTrustBundlePath string
}

func DefaultInstallationPaths() InstallationPaths {
	return InstallationPaths{
		Manifest: DefaultInstallationManifestPath, TrustBundle: DefaultTrustBundlePath,
		OutboundProxyTrustBundle: DefaultOutboundProxyTrustPath,
		ModelRelayTrustBundle:    DefaultModelRelayTrustPath,
		SystemTrustBundle:        DefaultSystemTrustBundlePath,
		HostNetworkPolicy:        DefaultHostNetworkPolicyPath,
		WorkerExecutable:         DefaultWorkerExecutablePath, PiExecutable: DefaultPiExecutablePath,
		ResultExtension: DefaultResultExtensionPath, TrustedRoot: "/",
	}
}

func LoadInstallation(document BootstrapDocument) (Installation, error) {
	return loadInstallation(document, DefaultInstallationPaths(), 0)
}

func loadInstallation(
	document BootstrapDocument,
	paths InstallationPaths,
	expectedOwner uint32,
) (Installation, error) {
	documentRaw, marshalErr := json.Marshal(document)
	parsedDocument, _, parseErr := ParseBootstrapDocument(documentRaw)
	clear(documentRaw)
	if marshalErr != nil || parseErr != nil || parsedDocument != document ||
		!cleanInstallationPaths(paths) {
		return Installation{}, ErrInvalid
	}
	manifestRaw, err := readPinnedInstallationFile(
		paths.Manifest, paths.TrustedRoot, expectedOwner, MaxInstallationBytes, false,
	)
	if err != nil {
		return Installation{}, err
	}
	defer clear(manifestRaw)
	manifest, err := parseInstallationManifest(manifestRaw)
	if err != nil || manifest.WorkerExecutable != paths.WorkerExecutable ||
		manifest.PiExecutable != paths.PiExecutable ||
		manifest.ResultExtension != paths.ResultExtension ||
		manifest.AMIDigest != document.AMIDigest ||
		manifest.WorkerDigest != document.WorkerDigest ||
		manifest.PiDigest != document.PiDigest ||
		manifest.HostNetworkPolicySHA256 != document.HostNetworkPolicySHA256 ||
		manifest.OutboundProxyTrustBundleSHA256 != document.OutboundProxyTrustSHA256 ||
		manifest.ModelRelayTrustBundleSHA256 != document.ModelRelayTrustBundleSHA256 {
		return Installation{}, ErrInvalid
	}
	piDigest, err := installationPiDigest(manifest)
	if err != nil || piDigest != manifest.PiDigest {
		return Installation{}, ErrInvalid
	}
	if err := verifyPinnedInstallationDigest(
		manifest.WorkerExecutable, paths.TrustedRoot, expectedOwner,
		manifest.WorkerDigest, true,
	); err != nil {
		return Installation{}, err
	}
	if err := verifyPinnedInstallationDigest(
		manifest.PiExecutable, paths.TrustedRoot, expectedOwner,
		manifest.PiExecutableSHA256, true,
	); err != nil {
		return Installation{}, err
	}
	if err := verifyPinnedInstallationDigest(
		manifest.ResultExtension, paths.TrustedRoot, expectedOwner,
		manifest.ResultExtensionSHA256, false,
	); err != nil {
		return Installation{}, err
	}
	trustBundle, err := readPinnedInstallationFile(
		paths.TrustBundle, paths.TrustedRoot, expectedOwner, 1<<20, false,
	)
	if err != nil {
		return Installation{}, err
	}
	defer clear(trustBundle)
	roots, err := VerifyTrustBundle(
		trustBundle, document.ControlPlaneTrustBundleSHA256,
	)
	if err != nil {
		return Installation{}, err
	}
	proxyTrustBundle, err := readPinnedInstallationFile(
		paths.OutboundProxyTrustBundle, paths.TrustedRoot, expectedOwner, 1<<20, false,
	)
	if err != nil {
		return Installation{}, err
	}
	defer clear(proxyTrustBundle)
	proxyRoots, err := VerifyTrustBundle(
		proxyTrustBundle, manifest.OutboundProxyTrustBundleSHA256,
	)
	if err != nil {
		return Installation{}, err
	}
	modelRelayTrustBundle, err := readPinnedInstallationFile(
		paths.ModelRelayTrustBundle, paths.TrustedRoot, expectedOwner, 1<<20, false,
	)
	if err != nil {
		return Installation{}, err
	}
	defer clear(modelRelayTrustBundle)
	if _, err := VerifyTrustBundle(
		modelRelayTrustBundle, manifest.ModelRelayTrustBundleSHA256,
	); err != nil {
		return Installation{}, err
	}
	systemTrustBundle, err := readPinnedInstallationFile(
		paths.SystemTrustBundle, paths.TrustedRoot, expectedOwner, 2<<20, false,
	)
	if err != nil {
		return Installation{}, err
	}
	defer clear(systemTrustBundle)
	systemRoots := x509.NewCertPool()
	if !systemRoots.AppendCertsFromPEM(systemTrustBundle) {
		return Installation{}, ErrInvalid
	}
	if err := verifyPinnedInstallationDigest(
		paths.HostNetworkPolicy, paths.TrustedRoot, expectedOwner,
		manifest.HostNetworkPolicySHA256, false,
	); err != nil {
		return Installation{}, err
	}
	return Installation{
		Release: cloudruntime.PiRelease{
			Version: manifest.PiVersion,
			Executable: cloudruntime.PinnedFile{
				Path: manifest.PiExecutable, SHA256: manifest.PiExecutableSHA256,
			},
			ResultExtension: cloudruntime.PinnedFile{
				Path: manifest.ResultExtension, SHA256: manifest.ResultExtensionSHA256,
			},
		},
		TrustRoots: roots, OutboundProxyRoots: proxyRoots, SystemTrustRoots: systemRoots,
		ModelRelayTrustBundlePath: paths.ModelRelayTrustBundle,
	}, nil
}

func parseInstallationManifest(raw []byte) (InstallationManifest, error) {
	if len(raw) == 0 || len(raw) > MaxInstallationBytes {
		return InstallationManifest{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest InstallationManifest
	if decoder.Decode(&manifest) != nil {
		return InstallationManifest{}, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return InstallationManifest{}, ErrInvalid
	}
	canonical, err := json.Marshal(manifest)
	if err != nil || !bytes.Equal(canonical, raw) ||
		manifest.SchemaVersion != InstallationSchemaV1 ||
		!validDigest(manifest.AMIDigest) || !validDigest(manifest.WorkerDigest) ||
		!validDigest(manifest.PiDigest) ||
		!validDigest(manifest.HostNetworkPolicySHA256) ||
		!validDigest(manifest.OutboundProxyTrustBundleSHA256) ||
		!validDigest(manifest.ModelRelayTrustBundleSHA256) ||
		manifest.PiVersion == "" || manifest.PiVersion != strings.TrimSpace(manifest.PiVersion) ||
		len(manifest.PiVersion) > 64 ||
		!cleanAbsoluteInstallationPath(manifest.WorkerExecutable) ||
		!cleanAbsoluteInstallationPath(manifest.PiExecutable) ||
		!validDigest(manifest.PiExecutableSHA256) ||
		!cleanAbsoluteInstallationPath(manifest.ResultExtension) ||
		!validDigest(manifest.ResultExtensionSHA256) {
		clear(canonical)
		return InstallationManifest{}, ErrInvalid
	}
	clear(canonical)
	return manifest, nil
}

func installationPiDigest(manifest InstallationManifest) (string, error) {
	if manifest.SchemaVersion != InstallationSchemaV1 || manifest.PiVersion == "" ||
		!cleanAbsoluteInstallationPath(manifest.PiExecutable) ||
		!validDigest(manifest.PiExecutableSHA256) ||
		!cleanAbsoluteInstallationPath(manifest.ResultExtension) ||
		!validDigest(manifest.ResultExtensionSHA256) {
		return "", ErrInvalid
	}
	descriptor := struct {
		PiVersion             string `json:"pi_version"`
		PiExecutable          string `json:"pi_executable"`
		PiExecutableSHA256    string `json:"pi_executable_sha256"`
		ResultExtension       string `json:"result_extension"`
		ResultExtensionSHA256 string `json:"result_extension_sha256"`
	}{
		manifest.PiVersion, manifest.PiExecutable, manifest.PiExecutableSHA256,
		manifest.ResultExtension, manifest.ResultExtensionSHA256,
	}
	raw, err := json.Marshal(descriptor)
	if err != nil {
		return "", ErrInvalid
	}
	digest := sha256.Sum256(raw)
	clear(raw)
	return hex.EncodeToString(digest[:]), nil
}

func verifyPinnedInstallationDigest(
	path string,
	trustedRoot string,
	expectedOwner uint32,
	expectedDigest string,
	executable bool,
) error {
	if !validDigest(expectedDigest) {
		return ErrInvalid
	}
	expected, err := hex.DecodeString(expectedDigest)
	if err != nil || len(expected) != sha256.Size {
		clear(expected)
		return ErrInvalid
	}
	defer clear(expected)
	if !pathWithinTrustedRoot(path, trustedRoot) ||
		verifyOwnedPath(path, trustedRoot, expectedOwner, executable) != nil {
		return ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 ||
		before.Size() > MaxInstalledFileBytes {
		return ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return ErrInvalid
	}
	hasher := sha256.New()
	written, hashErr := io.Copy(hasher, io.LimitReader(file, MaxInstalledFileBytes+1))
	after, statErr := os.Lstat(path)
	actual := hasher.Sum(nil)
	defer clear(actual)
	if hashErr != nil || statErr != nil || written != before.Size() ||
		!os.SameFile(before, after) || after.Size() != before.Size() ||
		!after.ModTime().Equal(before.ModTime()) ||
		verifyOwnedPath(path, trustedRoot, expectedOwner, executable) != nil {
		return ErrIdentityChanged
	}
	if subtle.ConstantTimeCompare(expected, actual) != 1 {
		return ErrInvalid
	}
	return nil
}

func readPinnedInstallationFile(
	path string,
	trustedRoot string,
	expectedOwner uint32,
	maximum int64,
	executable bool,
) ([]byte, error) {
	if maximum < 1 || !pathWithinTrustedRoot(path, trustedRoot) ||
		verifyOwnedPath(path, trustedRoot, expectedOwner, executable) != nil {
		return nil, ErrInvalid
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 ||
		before.Size() > maximum {
		return nil, ErrInvalid
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(raw) == 0 || int64(len(raw)) > maximum {
		clear(raw)
		return nil, ErrUnavailable
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() ||
		!after.ModTime().Equal(before.ModTime()) ||
		verifyOwnedPath(path, trustedRoot, expectedOwner, executable) != nil {
		clear(raw)
		return nil, ErrIdentityChanged
	}
	return raw, nil
}

func cleanInstallationPaths(paths InstallationPaths) bool {
	return cleanAbsoluteInstallationPath(paths.Manifest) &&
		cleanAbsoluteInstallationPath(paths.TrustBundle) &&
		cleanAbsoluteInstallationPath(paths.OutboundProxyTrustBundle) &&
		cleanAbsoluteInstallationPath(paths.ModelRelayTrustBundle) &&
		cleanAbsoluteInstallationPath(paths.SystemTrustBundle) &&
		cleanAbsoluteInstallationPath(paths.HostNetworkPolicy) &&
		cleanAbsoluteInstallationPath(paths.WorkerExecutable) &&
		cleanAbsoluteInstallationPath(paths.PiExecutable) &&
		cleanAbsoluteInstallationPath(paths.ResultExtension) &&
		filepath.IsAbs(paths.TrustedRoot) && filepath.Clean(paths.TrustedRoot) == paths.TrustedRoot &&
		pathWithinTrustedRoot(paths.Manifest, paths.TrustedRoot) &&
		pathWithinTrustedRoot(paths.TrustBundle, paths.TrustedRoot) &&
		pathWithinTrustedRoot(paths.OutboundProxyTrustBundle, paths.TrustedRoot) &&
		pathWithinTrustedRoot(paths.ModelRelayTrustBundle, paths.TrustedRoot) &&
		pathWithinTrustedRoot(paths.SystemTrustBundle, paths.TrustedRoot) &&
		pathWithinTrustedRoot(paths.HostNetworkPolicy, paths.TrustedRoot) &&
		pathWithinTrustedRoot(paths.WorkerExecutable, paths.TrustedRoot) &&
		pathWithinTrustedRoot(paths.PiExecutable, paths.TrustedRoot) &&
		pathWithinTrustedRoot(paths.ResultExtension, paths.TrustedRoot)
}

func pathWithinTrustedRoot(path, root string) bool {
	if !cleanAbsoluteInstallationPath(path) || !filepath.IsAbs(root) ||
		filepath.Clean(root) != root {
		return false
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != "." && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func cleanAbsoluteInstallationPath(value string) bool {
	return value != "" && value != "/" && filepath.IsAbs(value) &&
		filepath.Clean(value) == value
}
