package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/artifactorigin"
)

func TestPrepareCommandUsesFixedExplicitCoordinatesAndProtectedReceipt(t *testing.T) {
	originalPrepare, originalWrite := prepareOrigin, writeReceiptFile
	defer func() { prepareOrigin, writeReceiptFile = originalPrepare, originalWrite }()
	want := artifactorigin.OriginReceipt{SchemaVersion: artifactorigin.OriginReceiptSchemaV1}
	prepareOrigin = func(_ context.Context, options artifactorigin.PrepareOptions, _ func() time.Time) (artifactorigin.OriginReceipt, error) {
		if options.AccountID != "123456789012" || options.Region != artifactorigin.StorageRegion || options.Domain != artifactorigin.DomainName || options.HostedZoneID != "Z123456789" {
			t.Fatalf("options = %#v", options)
		}
		return want, nil
	}
	written := false
	writeReceiptFile = func(name string, value any) error {
		written = name == "/protected/origin.json" && value == want
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"prepare", "--account-id", "123456789012", "--region", artifactorigin.StorageRegion, "--domain", artifactorigin.DomainName,
		"--hosted-zone-id", "Z123456789", "--receipt-output", "/protected/origin.json",
	}, &stdout, &stderr)
	if code != 0 || !written || stderr.Len() != 0 || !bytes.Contains(stdout.Bytes(), []byte(artifactorigin.OriginReceiptSchemaV1)) {
		t.Fatalf("code=%d written=%t stdout=%q stderr=%q", code, written, stdout.String(), stderr.String())
	}
}

func TestPrepareCommandRedactsProviderFailure(t *testing.T) {
	originalPrepare := prepareOrigin
	defer func() { prepareOrigin = originalPrepare }()
	prepareOrigin = func(context.Context, artifactorigin.PrepareOptions, func() time.Time) (artifactorigin.OriginReceipt, error) {
		return artifactorigin.OriginReceipt{}, errors.New("credential AKIAABCDEFGHIJKLMNOP")
	}
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{
		"prepare", "--account-id", "123456789012", "--region", artifactorigin.StorageRegion, "--domain", artifactorigin.DomainName,
		"--hosted-zone-id", "Z123456789", "--receipt-output", "/protected/origin.json",
	}, &stdout, &stderr)
	if code != 1 || stdout.Len() != 0 || stderr.String() != prepareMessage {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestCommandRejectsCoordinateOverrides(t *testing.T) {
	for _, arguments := range [][]string{
		{"prepare", "--account-id", "123456789012", "--region", "us-west-2", "--domain", artifactorigin.DomainName, "--hosted-zone-id", "Z123456789", "--receipt-output", "x"},
		{"prepare", "--account-id", "123456789012", "--region", artifactorigin.StorageRegion, "--domain", "artifacts.example.com", "--hosted-zone-id", "Z123456789", "--receipt-output", "x"},
		{"publish", "--account-id", "123456789012", "--region", "us-west-2", "--artifact-id", "qdrant-linux-amd64", "--file", "x", "--origin-receipt", "y", "--receipt-output", "z"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(context.Background(), arguments, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != usageMessage {
			t.Fatalf("arguments=%v code=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestWriteExclusiveJSONNeverOverwritesReceiptAndUses0600(t *testing.T) {
	name := filepath.Join(t.TempDir(), "receipt.json")
	first := map[string]string{"result": "first"}
	if err := writeExclusiveJSON(name, first); err != nil {
		t.Fatalf("writeExclusiveJSON() error = %v", err)
	}
	info, err := os.Stat(name)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("receipt mode info=%#v error=%v", info, err)
	}
	if err := writeExclusiveJSON(name, map[string]string{"result": "second"}); err == nil {
		t.Fatal("writeExclusiveJSON overwrote prior evidence")
	}
	payload, err := os.ReadFile(name)
	if err != nil || !bytes.Contains(payload, []byte(`"first"`)) || bytes.Contains(payload, []byte(`"second"`)) {
		t.Fatalf("receipt payload=%q error=%v", payload, err)
	}
}
