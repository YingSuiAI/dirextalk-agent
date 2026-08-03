package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/google/uuid"
)

func TestConnectionCatalogLoadsProtectedMetadataAndFencesInactiveEntries(
	t *testing.T,
) {
	t.Parallel()
	activeID := uuid.NewString()
	inactiveID := uuid.NewString()
	document := ConnectionCatalogDocumentV1{
		SchemaVersion: ConnectionCatalogSchemaV1,
		Connections: []ConnectionV1{
			connectionFixture(activeID, true),
			connectionFixture(inactiveID, false),
		},
	}
	path := writeConnectionCatalog(t, document, 0o600)
	catalog, err := LoadConnectionCatalog(path)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := catalog.LoadGitHubAppConnection(
		context.Background(),
		activeID,
	)
	if err != nil ||
		connection.ConnectionID != activeID ||
		connection.PrivateKeyRef != "mounted:github-app-key" {
		t.Fatalf("active connection=%+v error=%v", connection, err)
	}
	if _, err := catalog.LoadGitHubAppConnection(
		context.Background(),
		inactiveID,
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("inactive connection error=%v", err)
	}
}

func TestConnectionCatalogRejectsUnsafeOrAmbiguousMetadata(t *testing.T) {
	t.Parallel()
	connectionID := uuid.NewString()
	tests := map[string]func(*ConnectionCatalogDocumentV1){
		"duplicate connection": func(document *ConnectionCatalogDocumentV1) {
			document.Connections = append(
				document.Connections,
				document.Connections[0],
			)
		},
		"caller controlled host": func(document *ConnectionCatalogDocumentV1) {
			document.Connections[0].Host = "github.example"
		},
		"path secret reference": func(document *ConnectionCatalogDocumentV1) {
			document.Connections[0].PrivateKeyRef =
				"mounted:../../github-app-key"
		},
		"legacy broad reference": func(document *ConnectionCatalogDocumentV1) {
			document.Connections[0].PrivateKeyRef =
				"secret_ref:github/app-key"
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			document := ConnectionCatalogDocumentV1{
				SchemaVersion: ConnectionCatalogSchemaV1,
				Connections: []ConnectionV1{
					connectionFixture(connectionID, true),
				},
			}
			mutate(&document)
			if _, err := NewConnectionCatalog(document); !errors.Is(
				err,
				ErrInvalid,
			) {
				t.Fatalf("NewConnectionCatalog() error=%v", err)
			}
		})
	}
}

func TestConnectionCatalogRejectsLooseFileOrTrailingJSON(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix file-mode and no-follow semantics are required")
	}
	document := ConnectionCatalogDocumentV1{
		SchemaVersion: ConnectionCatalogSchemaV1,
		Connections: []ConnectionV1{
			connectionFixture(uuid.NewString(), true),
		},
	}
	if _, err := LoadConnectionCatalog(
		writeConnectionCatalog(t, document, 0o666),
	); !errors.Is(err, ErrInvalid) {
		t.Fatalf("loose catalog error=%v", err)
	}
	path := writeConnectionCatalog(t, document, 0o600)
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("\n{}\n"); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConnectionCatalog(path); !errors.Is(
		err,
		ErrInvalid,
	) {
		t.Fatalf("trailing catalog error=%v", err)
	}
}

func TestResolverPrivateKeySourceClearsResolvedBytes(t *testing.T) {
	t.Parallel()
	resolver := &privateKeyResolverStub{
		value: []byte("private-key-material"),
	}
	source, err := NewResolverPrivateKeySource(resolver)
	if err != nil {
		t.Fatal(err)
	}
	var observed []byte
	if err := source.MaterializeGitHubAppPrivateKey(
		context.Background(),
		"mounted:github-app-key",
		func(value []byte) error {
			observed = bytes.Clone(value)
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	defer clear(observed)
	if string(observed) != "private-key-material" ||
		resolver.reference != "mounted:github-app-key" {
		t.Fatalf(
			"materialized=%q reference=%q",
			observed,
			resolver.reference,
		)
	}
	for index, value := range resolver.returned {
		if value != 0 {
			t.Fatalf("resolved byte %d was not cleared", index)
		}
	}
}

func connectionFixture(
	connectionID string,
	active bool,
) ConnectionV1 {
	return ConnectionV1{
		ConnectionID:   connectionID,
		Provider:       taskinput.GitProviderGitHub,
		Host:           taskinput.GitHubHost,
		IssuerID:       "Iv1testclientid123",
		InstallationID: 987654,
		PrivateKeyRef:  "mounted:github-app-key",
		Active:         active,
	}
}

func writeConnectionCatalog(
	t *testing.T,
	document ConnectionCatalogDocumentV1,
	mode os.FileMode,
) string {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(raw)
	path := filepath.Join(t.TempDir(), "github-app-connections.json")
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

type privateKeyResolverStub struct {
	value     []byte
	returned  []byte
	reference string
}

func (resolver *privateKeyResolverStub) ResolveSecret(
	_ context.Context,
	reference string,
) ([]byte, error) {
	resolver.reference = reference
	resolver.returned = bytes.Clone(resolver.value)
	return resolver.returned, nil
}
