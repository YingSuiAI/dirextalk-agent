package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeygenWritesProtectedDistinctKeyFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "catalog-private")
	publicPath := filepath.Join(directory, "catalog-public")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"keygen",
		"--private-key-out", privatePath,
		"--public-key-out", publicPath,
	}, &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf(
			"keygen code=%d stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
	var result struct {
		SchemaVersion string `json:"schema_version"`
		SignerKeyID   string `json:"signer_key_id"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.SchemaVersion !=
		"dirextalk.agent.runtime-catalog-key/v1" ||
		!strings.HasPrefix(
			result.SignerKeyID,
			"runtime-catalog-key-",
		) {
		t.Fatalf("keygen result = %#v", result)
	}
	privateKey := readEncodedKey(
		t,
		privatePath,
		ed25519.PrivateKeySize,
		0o600,
	)
	defer clear(privateKey)
	publicKey := readEncodedKey(
		t,
		publicPath,
		ed25519.PublicKeySize,
		0o400,
	)
	if !bytes.Equal(
		ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey),
		publicKey,
	) {
		t.Fatal("generated public and private keys do not match")
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"keygen",
		"--private-key-out", privatePath,
		"--public-key-out", publicPath,
	}, &stdout, &stderr)
	if code != 1 ||
		stderr.String() != actionMessage ||
		stdout.Len() != 0 {
		t.Fatalf(
			"duplicate keygen code=%d stdout=%q stderr=%q",
			code,
			stdout.String(),
			stderr.String(),
		)
	}
}

func TestTeamBundleCommandsFailClosedOnIncompleteInput(t *testing.T) {
	t.Parallel()
	for _, arguments := range [][]string{
		nil,
		{"keygen"},
		{"assemble-pi"},
		{"verify", "--bundle", filepath.Join(t.TempDir(), "missing")},
		{"unknown"},
	} {
		var stdout, stderr bytes.Buffer
		code := run(arguments, &stdout, &stderr)
		if code == 0 || stdout.Len() != 0 ||
			(stderr.String() != usageMessage &&
				stderr.String() != actionMessage) {
			t.Fatalf(
				"run(%v) code=%d stdout=%q stderr=%q",
				arguments,
				code,
				stdout.String(),
				stderr.String(),
			)
		}
	}
}

func readEncodedKey(
	t *testing.T,
	path string,
	size int,
	mode os.FileMode,
) []byte {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("%s mode = %o", path, info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(raw))
	if err != nil || len(decoded) != size {
		t.Fatalf("invalid encoded key at %s", path)
	}
	return decoded
}
