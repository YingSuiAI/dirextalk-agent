// dirextalk-team-bundlectl creates and verifies the fixed Pi Team release
// bundle. It is offline operator tooling and has no AWS or Agent RPC client.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/teambundle"
	"github.com/YingSuiAI/dirextalk-agent/internal/teamplan"
)

const (
	usageMessage  = "team bundle usage error\n"
	actionMessage = "team bundle operation failed\n"
	outputMessage = "team bundle output failed\n"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	switch arguments[0] {
	case "keygen":
		return runKeygen(arguments[1:], stdout, stderr)
	case "assemble-pi":
		return runAssemble(arguments[1:], stdout, stderr)
	case "verify":
		return runVerify(arguments[1:], stdout, stderr)
	default:
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
}

func runKeygen(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := ""
	publicPath := ""
	flags.StringVar(&privatePath, "private-key-out", "", "")
	flags.StringVar(&publicPath, "public-key-out", "", "")
	if flags.Parse(arguments) != nil ||
		flags.NArg() != 0 ||
		privatePath == "" ||
		publicPath == "" ||
		filepath.Clean(privatePath) == filepath.Clean(publicPath) {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		_, _ = io.WriteString(stderr, actionMessage)
		return 1
	}
	defer clear(privateKey)
	privateRaw := []byte(base64.RawURLEncoding.EncodeToString(privateKey))
	defer clear(privateRaw)
	publicRaw := []byte(base64.RawURLEncoding.EncodeToString(publicKey))
	if writeNewFile(privatePath, privateRaw, 0o600) != nil {
		_, _ = io.WriteString(stderr, actionMessage)
		return 1
	}
	if writeNewFile(publicPath, publicRaw, 0o400) != nil {
		_ = os.Remove(privatePath)
		_, _ = io.WriteString(stderr, actionMessage)
		return 1
	}
	result := struct {
		SchemaVersion string `json:"schema_version"`
		SignerKeyID   string `json:"signer_key_id"`
	}{
		SchemaVersion: "dirextalk.agent.runtime-catalog-key/v1",
		SignerKeyID:   teamplan.RuntimeCatalogSignerKeyID(publicKey),
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		_, _ = io.WriteString(stderr, outputMessage)
		return 1
	}
	return 0
}

func runAssemble(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("assemble-pi", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	request := teambundle.AssemblyRequest{}
	qualifiedAt := ""
	generatedAt := ""
	coldStartSeconds := ""
	flags.StringVar(&request.OutputDirectory, "output-dir", "", "")
	flags.StringVar(
		&request.RuntimeCatalogPrivateKey,
		"runtime-catalog-private-key",
		"",
		"",
	)
	flags.StringVar(&request.SourceCommit, "source-commit", "", "")
	flags.StringVar(
		&request.QualificationID,
		"qualification-id",
		"",
		"",
	)
	flags.StringVar(&qualifiedAt, "qualified-at", "", "")
	flags.StringVar(&generatedAt, "generated-at", "", "")
	flags.StringVar(
		&coldStartSeconds,
		"cold-start-seconds",
		"",
		"",
	)
	flags.StringVar(
		&request.ModelProfilesFile,
		"model-profiles",
		"",
		"",
	)
	flags.StringVar(&request.TeamPolicyFile, "team-policy", "", "")
	flags.StringVar(
		&request.ModelOffersFile,
		"model-offers",
		"",
		"",
	)
	flags.StringVar(
		&request.ComputeCatalogFile,
		"compute-catalog",
		"",
		"",
	)
	flags.StringVar(
		&request.WorkerPublicationFile,
		"worker-ami-publication",
		"",
		"",
	)
	flags.StringVar(
		&request.RuntimeInstallationFile,
		"runtime-installation",
		"",
		"",
	)
	flags.StringVar(&request.SBOMFile, "sbom", "", "")
	flags.StringVar(&request.ProvenanceFile, "provenance", "", "")
	flags.StringVar(
		&request.VulnerabilityScanFile,
		"vulnerability-scan",
		"",
		"",
	)
	flags.StringVar(
		&request.ContractTestFile,
		"contract-test",
		"",
		"",
	)
	flags.StringVar(
		&request.LicenseDecisionFile,
		"license-decision",
		"",
		"",
	)
	if flags.Parse(arguments) != nil ||
		flags.NArg() != 0 ||
		hasMissingAssemblyInput(request, qualifiedAt, generatedAt, coldStartSeconds) {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	var err error
	request.QualifiedAt, err = parseTimestamp(qualifiedAt)
	if err != nil {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	request.GeneratedAt, err = parseTimestamp(generatedAt)
	if err != nil {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	seconds, err := strconv.ParseUint(coldStartSeconds, 10, 32)
	if err != nil {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	request.ColdStart = time.Duration(seconds) * time.Second
	result, err := teambundle.AssemblePi(request)
	if err != nil {
		_, _ = io.WriteString(stderr, actionMessage)
		return 1
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		_, _ = io.WriteString(stderr, outputMessage)
		return 1
	}
	return 0
}

func runVerify(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	directory := ""
	flags.StringVar(&directory, "bundle", "", "")
	if flags.Parse(arguments) != nil ||
		flags.NArg() != 0 ||
		strings.TrimSpace(directory) == "" {
		_, _ = io.WriteString(stderr, usageMessage)
		return 2
	}
	bundle, err := teambundle.Load(directory)
	if err != nil {
		_, _ = io.WriteString(stderr, actionMessage)
		return 1
	}
	raw, err := os.ReadFile(
		filepath.Join(directory, teambundle.ManifestFilename),
	)
	if err != nil {
		_, _ = io.WriteString(stderr, actionMessage)
		return 1
	}
	digest := sha256.Sum256(raw)
	result := teambundle.AssemblyResult{
		Manifest: bundle.Manifest,
		ManifestDigest: "sha256:" +
			hex.EncodeToString(digest[:]),
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		_, _ = io.WriteString(stderr, outputMessage)
		return 1
	}
	return 0
}

func hasMissingAssemblyInput(
	request teambundle.AssemblyRequest,
	qualifiedAt,
	generatedAt,
	coldStartSeconds string,
) bool {
	return request.OutputDirectory == "" ||
		request.RuntimeCatalogPrivateKey == "" ||
		request.SourceCommit == "" ||
		request.QualificationID == "" ||
		qualifiedAt == "" ||
		generatedAt == "" ||
		coldStartSeconds == "" ||
		request.ModelProfilesFile == "" ||
		request.TeamPolicyFile == "" ||
		request.ModelOffersFile == "" ||
		request.ComputeCatalogFile == "" ||
		request.WorkerPublicationFile == "" ||
		request.RuntimeInstallationFile == "" ||
		request.SBOMFile == "" ||
		request.ProvenanceFile == "" ||
		request.VulnerabilityScanFile == "" ||
		request.ContractTestFile == "" ||
		request.LicenseDecisionFile == ""
}

func parseTimestamp(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil ||
		parsed.Location() != time.UTC ||
		parsed.Nanosecond()%1000 != 0 ||
		parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, teambundle.ErrInvalid
	}
	return parsed, nil
}

func writeNewFile(path string, raw []byte, mode os.FileMode) error {
	if strings.TrimSpace(path) != path || path == "" {
		return teambundle.ErrInvalid
	}
	file, err := os.OpenFile(
		filepath.Clean(path),
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		mode,
	)
	if err != nil {
		return teambundle.ErrInvalid
	}
	written, writeErr := file.Write(raw)
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil ||
		written != len(raw) ||
		syncErr != nil ||
		closeErr != nil {
		_ = os.Remove(path)
		return teambundle.ErrInvalid
	}
	return nil
}
