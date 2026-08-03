// dirextalk-worker-marketctl signs and verifies an already reviewed Worker
// Marketplace registry. It is offline operator tooling and performs no cloud
// operation.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/workermarket"
)

const maximumInputBytes = int64(8 << 20)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		_, _ = io.WriteString(stderr, "worker market usage error\n")
		return 2
	}
	switch arguments[0] {
	case "sign":
		return runSign(arguments[1:], stdout, stderr)
	case "verify":
		return runVerify(arguments[1:], stdout, stderr)
	default:
		_, _ = io.WriteString(stderr, "worker market usage error\n")
		return 2
	}
}

func runSign(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	payloadPath := ""
	privateKeyPath := ""
	outputPath := ""
	flags.StringVar(&payloadPath, "payload", "", "")
	flags.StringVar(&privateKeyPath, "private-key", "", "")
	flags.StringVar(&outputPath, "out", "", "")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 ||
		payloadPath == "" || privateKeyPath == "" || outputPath == "" ||
		filepath.Clean(payloadPath) == filepath.Clean(outputPath) ||
		filepath.Clean(privateKeyPath) == filepath.Clean(outputPath) {
		_, _ = io.WriteString(stderr, "worker market usage error\n")
		return 2
	}
	payload, err := readProtected(payloadPath, maximumInputBytes)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker market input failed\n")
		return 1
	}
	encodedKey, err := readProtected(privateKeyPath, 256)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker market input failed\n")
		return 1
	}
	privateKey, err := decodePrivateKey(encodedKey)
	clear(encodedKey)
	if err != nil {
		clear(privateKey)
		_, _ = io.WriteString(stderr, "worker market input failed\n")
		return 1
	}
	signed, err := workermarket.SignRegistryPayloadJSON(
		payload,
		ed25519.PrivateKey(privateKey),
	)
	clear(privateKey)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker market signing failed\n")
		return 1
	}
	if writeExclusive(outputPath, signed) != nil {
		_, _ = io.WriteString(stderr, "worker market output failed\n")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "worker_market_registry=%s\n", outputPath)
	return 0
}

func runVerify(arguments []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	registryPath := ""
	publicKeyPath := ""
	organizationID := ""
	atText := ""
	flags.StringVar(&registryPath, "registry", "", "")
	flags.StringVar(&publicKeyPath, "public-key", "", "")
	flags.StringVar(&organizationID, "organization-id", "", "")
	flags.StringVar(&atText, "at", "", "")
	if flags.Parse(arguments) != nil || flags.NArg() != 0 ||
		registryPath == "" || publicKeyPath == "" || organizationID == "" {
		_, _ = io.WriteString(stderr, "worker market usage error\n")
		return 2
	}
	at := time.Now().UTC().Truncate(time.Second)
	if atText != "" {
		parsed, err := time.Parse(time.RFC3339, atText)
		if err != nil || parsed.Nanosecond() != 0 {
			_, _ = io.WriteString(stderr, "worker market usage error\n")
			return 2
		}
		at = parsed.UTC()
	}
	registry, err := workermarket.LoadRegistry(registryPath, publicKeyPath)
	if err != nil {
		_, _ = io.WriteString(stderr, "worker market verification failed\n")
		return 1
	}
	releases, err := registry.ListApproved(at, organizationID)
	if err != nil || len(releases) == 0 {
		_, _ = io.WriteString(stderr, "worker market has no approved release\n")
		return 1
	}
	_, _ = fmt.Fprintf(
		stdout,
		"worker_market_registry_id=%s\n"+
			"worker_market_revision=%s\n"+
			"worker_market_valid_until=%s\n"+
			"worker_market_approved_releases=%d\n",
		registry.RegistryID(),
		registry.Revision(),
		registry.ValidUntil().Format(time.RFC3339),
		len(releases),
	)
	return 0
}

func decodePrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(string(encoded))
	raw, err := base64.RawURLEncoding.DecodeString(trimmed)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != trimmed {
		clear(raw)
		return nil, workermarket.ErrInvalid
	}
	switch len(raw) {
	case ed25519.SeedSize:
		privateKey := ed25519.NewKeyFromSeed(raw)
		clear(raw)
		return privateKey, nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		clear(raw)
		return nil, workermarket.ErrInvalid
	}
}

func readProtected(name string, maximum int64) ([]byte, error) {
	file, err := os.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() ||
		info.Mode().Perm()&0o022 != 0 || info.Size() < 1 ||
		info.Size() > maximum {
		return nil, workermarket.ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, workermarket.ErrInvalid
	}
	return raw, nil
}

func writeExclusive(name string, value []byte) error {
	file, err := os.OpenFile(
		name,
		os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW,
		0o400,
	)
	if err != nil {
		return err
	}
	if _, err = file.Write(value); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
