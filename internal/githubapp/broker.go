// Package githubapp exchanges a Central Agent-owned GitHub App identity for
// short-lived, repository-scoped installation credentials.
package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/google/uuid"
)

const (
	apiBaseURL       = "https://api.github.com"
	apiVersion       = "2026-03-10"
	maxResponseBytes = 1 << 20
	maxTokenBytes    = 16 << 10
	jwtLifetime      = 9 * time.Minute
	jwtClockSkew     = time.Minute
)

var (
	ErrInvalid     = errors.New("invalid GitHub App credential request")
	ErrUnavailable = errors.New("GitHub App credential is unavailable")

	issuerPattern    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	secretRefPattern = regexp.MustCompile(
		`^mounted:[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`,
	)
)

type ContentsPermission string

const (
	ContentsRead  ContentsPermission = "read"
	ContentsWrite ContentsPermission = "write"
)

type ConnectionV1 struct {
	ConnectionID   string `json:"connection_id"`
	Provider       string `json:"provider"`
	Host           string `json:"host"`
	IssuerID       string `json:"issuer_id"`
	InstallationID int64  `json:"installation_id"`
	PrivateKeyRef  string `json:"private_key_ref"`
	Active         bool   `json:"active"`
}

func (connection ConnectionV1) Validate() error {
	if connection.validateMetadata() != nil || !connection.Active {
		return ErrInvalid
	}
	return nil
}

func (connection ConnectionV1) validateMetadata() error {
	parsed, err := uuid.Parse(connection.ConnectionID)
	if err != nil ||
		parsed == uuid.Nil ||
		parsed.String() != connection.ConnectionID ||
		connection.Provider != taskinput.GitProviderGitHub ||
		connection.Host != taskinput.GitHubHost ||
		!issuerPattern.MatchString(connection.IssuerID) ||
		connection.InstallationID < 1 ||
		!secretRefPattern.MatchString(connection.PrivateKeyRef) {
		return ErrInvalid
	}
	return nil
}

type ConnectionSource interface {
	LoadGitHubAppConnection(
		context.Context,
		string,
	) (ConnectionV1, error)
}

// PrivateKeySource keeps the long-lived GitHub App key outside Broker state.
// The source must clear any temporary plaintext after use.
type PrivateKeySource interface {
	MaterializeGitHubAppPrivateKey(
		context.Context,
		string,
		func([]byte) error,
	) error
}

type IssueRequest struct {
	Repository taskinput.GitRepositoryV1
	Permission ContentsPermission
}

func (request IssueRequest) validate() error {
	if request.Repository.Validate() != nil ||
		(request.Permission != ContentsRead &&
			request.Permission != ContentsWrite) {
		return ErrInvalid
	}
	return nil
}

type InstallationToken struct {
	value        []byte
	RepositoryID string
	Permission   ContentsPermission
	ExpiresAt    time.Time
}

func (token *InstallationToken) Materialize(
	write func([]byte) error,
) error {
	if token == nil || write == nil ||
		!validToken(token.value) ||
		token.RepositoryID == "" ||
		(token.Permission != ContentsRead &&
			token.Permission != ContentsWrite) ||
		token.ExpiresAt.IsZero() {
		return ErrUnavailable
	}
	return write(token.value)
}

func (token *InstallationToken) Destroy() {
	if token == nil {
		return
	}
	clear(token.value)
	*token = InstallationToken{}
}

type Broker struct {
	connections ConnectionSource
	keys        PrivateKeySource
	http        *http.Client
	now         func() time.Time
}

func NewBroker(
	connections ConnectionSource,
	keys PrivateKeySource,
	client *http.Client,
	now func() time.Time,
) (*Broker, error) {
	if connections == nil || keys == nil || client == nil || now == nil {
		return nil, ErrInvalid
	}
	return &Broker{
		connections: connections,
		keys:        keys,
		http:        client,
		now:         now,
	}, nil
}

func (broker *Broker) Issue(
	ctx context.Context,
	request IssueRequest,
) (InstallationToken, error) {
	if broker == nil ||
		broker.connections == nil ||
		broker.keys == nil ||
		broker.http == nil ||
		broker.now == nil ||
		ctx == nil ||
		request.validate() != nil {
		return InstallationToken{}, ErrInvalid
	}
	connection, err := broker.connections.LoadGitHubAppConnection(
		ctx,
		request.Repository.ConnectionID,
	)
	if err != nil ||
		connection.Validate() != nil ||
		connection.ConnectionID != request.Repository.ConnectionID ||
		connection.Provider != request.Repository.Provider ||
		connection.Host != request.Repository.Host {
		return InstallationToken{}, ErrUnavailable
	}
	now := broker.now().UTC().Truncate(time.Second)
	if now.IsZero() {
		return InstallationToken{}, ErrUnavailable
	}
	var jwt []byte
	if err := broker.keys.MaterializeGitHubAppPrivateKey(
		ctx,
		connection.PrivateKeyRef,
		func(privateKey []byte) error {
			value, signErr := signAppJWT(
				privateKey,
				connection.IssuerID,
				now,
			)
			if signErr != nil {
				return signErr
			}
			jwt = value
			return nil
		},
	); err != nil || len(jwt) == 0 {
		return InstallationToken{}, ErrUnavailable
	}
	defer clear(jwt)
	repositoryID, err := strconv.ParseUint(
		request.Repository.RepositoryID,
		10,
		64,
	)
	if err != nil || repositoryID == 0 {
		return InstallationToken{}, ErrInvalid
	}
	body, err := json.Marshal(struct {
		RepositoryIDs []uint64          `json:"repository_ids"`
		Permissions   map[string]string `json:"permissions"`
	}{
		RepositoryIDs: []uint64{repositoryID},
		Permissions: map[string]string{
			"contents": string(request.Permission),
		},
	})
	if err != nil {
		return InstallationToken{}, ErrUnavailable
	}
	defer clear(body)
	endpoint := fmt.Sprintf(
		"%s/app/installations/%d/access_tokens",
		apiBaseURL,
		connection.InstallationID,
	)
	httpRequest, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint,
		bytes.NewReader(body),
	)
	if err != nil {
		return InstallationToken{}, ErrUnavailable
	}
	httpRequest.Header.Set("Accept", "application/vnd.github+json")
	httpRequest.Header.Set("Authorization", "Bearer "+string(jwt))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("X-GitHub-Api-Version", apiVersion)
	response, err := broker.http.Do(httpRequest)
	if err != nil {
		return InstallationToken{}, ErrUnavailable
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(
		response.Body,
		maxResponseBytes+1,
	))
	if err != nil ||
		len(raw) == 0 ||
		len(raw) > maxResponseBytes ||
		response.StatusCode != http.StatusCreated {
		clear(raw)
		return InstallationToken{}, ErrUnavailable
	}
	defer clear(raw)
	var issued struct {
		Token        string            `json:"token"`
		ExpiresAt    time.Time         `json:"expires_at"`
		Permissions  map[string]string `json:"permissions"`
		Repositories []struct {
			ID       uint64 `json:"id"`
			Name     string `json:"name"`
			FullName string `json:"full_name"`
		} `json:"repositories"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&issued); err != nil ||
		issued.Permissions["contents"] != string(request.Permission) ||
		len(issued.Repositories) != 1 ||
		issued.Repositories[0].ID != repositoryID ||
		issued.Repositories[0].Name != request.Repository.Name ||
		issued.Repositories[0].FullName !=
			request.Repository.Owner+"/"+request.Repository.Name ||
		!validToken([]byte(issued.Token)) {
		clear([]byte(issued.Token))
		return InstallationToken{}, ErrUnavailable
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		clear([]byte(issued.Token))
		return InstallationToken{}, ErrUnavailable
	}
	expiresAt := issued.ExpiresAt.UTC().Truncate(time.Second)
	if !expiresAt.After(now.Add(time.Minute)) ||
		expiresAt.After(now.Add(time.Hour+5*time.Minute)) {
		clear([]byte(issued.Token))
		return InstallationToken{}, ErrUnavailable
	}
	tokenBytes := []byte(issued.Token)
	issued.Token = ""
	return InstallationToken{
		value:        tokenBytes,
		RepositoryID: request.Repository.RepositoryID,
		Permission:   request.Permission,
		ExpiresAt:    expiresAt,
	}, nil
}

func signAppJWT(
	privateKeyPEM []byte,
	issuerID string,
	now time.Time,
) ([]byte, error) {
	if len(privateKeyPEM) == 0 ||
		len(privateKeyPEM) > 64<<10 ||
		!issuerPattern.MatchString(issuerID) ||
		now.IsZero() {
		return nil, ErrInvalid
	}
	block, rest := pem.Decode(privateKeyPEM)
	if block == nil ||
		len(bytes.TrimSpace(rest)) != 0 ||
		strings.Contains(block.Type, "ENCRYPTED") {
		return nil, ErrInvalid
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalid
		}
		key = parsed
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, ErrInvalid
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, ErrInvalid
		}
	default:
		return nil, ErrInvalid
	}
	if key.N.BitLen() < 2048 || key.Validate() != nil {
		return nil, ErrInvalid
	}
	header, err := json.Marshal(struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}{
		Algorithm: "RS256",
		Type:      "JWT",
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(header)
	claims, err := json.Marshal(struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}{
		IssuedAt:  now.Add(-jwtClockSkew).Unix(),
		ExpiresAt: now.Add(jwtLifetime).Unix(),
		Issuer:    issuerID,
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(header) +
		"." +
		base64.RawURLEncoding.EncodeToString(claims)
	digest := crypto.SHA256.New()
	_, _ = digest.Write([]byte(signingInput))
	hashed := digest.Sum(nil)
	defer clear(hashed)
	signature, err := rsa.SignPKCS1v15(
		rand.Reader,
		key,
		crypto.SHA256,
		hashed,
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer clear(signature)
	return []byte(
		signingInput + "." +
			base64.RawURLEncoding.EncodeToString(signature),
	), nil
}

func validToken(value []byte) bool {
	if len(value) < 20 ||
		len(value) > maxTokenBytes ||
		!utf8.Valid(value) {
		return false
	}
	for _, character := range string(value) {
		if unicode.IsSpace(character) ||
			unicode.IsControl(character) {
			return false
		}
	}
	return true
}
