package migrations

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
)

// HistoricalChecksumManifestDigest is the SHA-256 of the ordered
// "<version>:<script-sha256>\n" records from the pre-bundle migration files.
const historicalChecksumManifestDigest = "787e61101e075b8d6072f0bdc19f200fd0b475dcaefce77eaa3a52d244947a6a"

func TestBundlePreservesOrderedVirtualSources(t *testing.T) {
	entries := Entries()
	if len(entries) != 41 {
		t.Fatalf("got %d migrations, want 41", len(entries))
	}
	for index, entry := range entries {
		wantVersion := int64(index + 1)
		version, err := migrationVersion(entry)
		if err != nil || version != wantVersion {
			t.Fatalf("entry %q has version %d, want %d (err=%v)", entry, version, wantVersion, err)
		}
		script, err := Files.ReadFile(entry)
		if err != nil {
			t.Fatal(err)
		}
		if len(script) == 0 || script[len(script)-1] != '\n' {
			t.Fatalf("entry %q lost its source newline", entry)
		}
	}
}

func TestBundlePreservesHistoricalChecksums(t *testing.T) {
	digest := sha256.New()
	for _, migration := range Ordered() {
		scriptChecksum := sha256.Sum256(migration.Script)
		_, _ = fmt.Fprintf(digest, "%d:%x\n", migration.Version, scriptChecksum)
	}
	if got := hex.EncodeToString(digest.Sum(nil)); got != historicalChecksumManifestDigest {
		t.Fatalf("historical migration checksum manifest changed: got %s, want %s", got, historicalChecksumManifestDigest)
	}
}

func TestParseBundleRejectsMalformedMarkers(t *testing.T) {
	raw, err := bundle.ReadFile(bundleName)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte(beginMarker + "000001_core.up.sql\n")
	second := []byte(beginMarker + "000002_task_execution.up.sql\n")
	cases := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{
			name: "duplicate",
			mutate: func(input []byte) []byte {
				return bytes.Replace(input, second, first, 1)
			},
		},
		{
			name: "noncontiguous",
			mutate: func(input []byte) []byte {
				return bytes.Replace(input, first, []byte(beginMarker+"000003_runtime.up.sql\n"), 1)
			},
		},
		{
			name: "missing-end",
			mutate: func(input []byte) []byte {
				marker := []byte(endMarker + "000001_core.up.sql\n")
				return bytes.Replace(input, marker, nil, 1)
			},
		},
		{
			name: "mismatched-end",
			mutate: func(input []byte) []byte {
				firstEnd := []byte(endMarker + "000001_core.up.sql\n")
				return bytes.Replace(input, firstEnd, []byte(endMarker+"000002_task_execution.up.sql\n"), 1)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseBundle(tc.mutate(append([]byte(nil), raw...))); err == nil {
				t.Fatal("ParseBundle accepted malformed marker input")
			}
		})
	}
}
