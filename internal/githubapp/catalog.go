package githubapp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"

	"github.com/YingSuiAI/dirextalk-agent/internal/security"
)

const (
	ConnectionCatalogSchemaV1 = "dirextalk.agent.github-app-connections/v1"
	maximumCatalogBytes       = int64(64 * 1024)
	maximumConnections        = 64
)

type ConnectionCatalogDocumentV1 struct {
	SchemaVersion string         `json:"schema_version"`
	Connections   []ConnectionV1 `json:"connections"`
}

// ConnectionCatalog is immutable after construction. It contains only
// installation metadata and opaque mounted-secret references.
type ConnectionCatalog struct {
	connections map[string]ConnectionV1
}

func LoadConnectionCatalog(path string) (*ConnectionCatalog, error) {
	raw, err := readProtectedCatalog(path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document ConnectionCatalogDocumentV1
	if err := decoder.Decode(&document); err != nil {
		return nil, ErrInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalid
	}
	return NewConnectionCatalog(document)
}

func NewConnectionCatalog(
	document ConnectionCatalogDocumentV1,
) (*ConnectionCatalog, error) {
	if document.SchemaVersion != ConnectionCatalogSchemaV1 ||
		len(document.Connections) == 0 ||
		len(document.Connections) > maximumConnections {
		return nil, ErrInvalid
	}
	connections := make(
		map[string]ConnectionV1,
		len(document.Connections),
	)
	for _, connection := range document.Connections {
		if connection.validateMetadata() != nil {
			return nil, ErrInvalid
		}
		if _, exists := connections[connection.ConnectionID]; exists {
			return nil, ErrInvalid
		}
		connections[connection.ConnectionID] = connection
	}
	return &ConnectionCatalog{connections: connections}, nil
}

func (catalog *ConnectionCatalog) LoadGitHubAppConnection(
	ctx context.Context,
	connectionID string,
) (ConnectionV1, error) {
	if catalog == nil ||
		ctx == nil ||
		strings.TrimSpace(connectionID) != connectionID ||
		connectionID == "" {
		return ConnectionV1{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return ConnectionV1{}, err
	}
	connection, found := catalog.connections[connectionID]
	if !found || connection.Validate() != nil {
		return ConnectionV1{}, ErrUnavailable
	}
	return connection, nil
}

func readProtectedCatalog(path string) ([]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, ErrInvalid
	}
	file, err := os.OpenFile(
		path,
		os.O_RDONLY|syscall.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return nil, ErrInvalid
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil ||
		!info.Mode().IsRegular() ||
		info.Mode().Perm()&0o022 != 0 ||
		info.Size() <= 0 ||
		info.Size() > maximumCatalogBytes {
		return nil, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(
		file,
		maximumCatalogBytes+1,
	))
	if err != nil ||
		int64(len(raw)) != info.Size() ||
		security.ContainsLikelySecret(string(raw)) {
		clear(raw)
		return nil, ErrInvalid
	}
	return raw, nil
}

var _ ConnectionSource = (*ConnectionCatalog)(nil)
