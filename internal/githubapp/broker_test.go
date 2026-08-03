package githubapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/taskinput"
	"github.com/google/uuid"
)

func TestBrokerIssuesOneRepositoryLeastPrivilegeToken(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 30, 8, 0, 0, 0, time.UTC)
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	connectionID := uuid.NewString()
	repository := taskinput.GitRepositoryV1{
		Provider:      taskinput.GitProviderGitHub,
		Host:          taskinput.GitHubHost,
		ConnectionID:  connectionID,
		RepositoryID:  "1296269",
		Owner:         "octocat",
		Name:          "Hello-World",
		BaseCommitSHA: strings.Repeat("a", 40),
		BaseRef:       "refs/heads/main",
	}
	transport := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost ||
			request.URL.String() !=
				"https://api.github.com/app/installations/987654/access_tokens" ||
			request.Header.Get("Accept") !=
				"application/vnd.github+json" ||
			request.Header.Get("X-GitHub-Api-Version") != apiVersion {
			t.Fatalf("unexpected GitHub request: %#v", request)
		}
		verifyAppJWT(
			t,
			strings.TrimPrefix(
				request.Header.Get("Authorization"),
				"Bearer ",
			),
			&privateKey.PublicKey,
			"Iv1testclientid123",
			now,
		)
		raw, err := io.ReadAll(request.Body)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		var body struct {
			RepositoryIDs []uint64          `json:"repository_ids"`
			Permissions   map[string]string `json:"permissions"`
		}
		if json.Unmarshal(raw, &body) != nil ||
			len(body.RepositoryIDs) != 1 ||
			body.RepositoryIDs[0] != 1296269 ||
			len(body.Permissions) != 1 ||
			body.Permissions["contents"] != "write" {
			t.Fatalf("overbroad installation token request: %s", raw)
		}
		responseBody, err := json.Marshal(map[string]any{
			"token":      "ghs_stateless_test_token_value_123456789",
			"expires_at": now.Add(time.Hour).Format(time.RFC3339),
			"permissions": map[string]string{
				"contents": "write",
				"metadata": "read",
			},
			"repositories": []map[string]any{{
				"id":        1296269,
				"name":      "Hello-World",
				"full_name": "octocat/Hello-World",
				"private":   true,
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return &http.Response{
			StatusCode: http.StatusCreated,
			Header:     make(http.Header),
			Body:       io.NopCloser(bytes.NewReader(responseBody)),
		}, nil
	})
	broker, err := NewBroker(
		connectionSourceStub{connection: ConnectionV1{
			ConnectionID:   connectionID,
			Provider:       taskinput.GitProviderGitHub,
			Host:           taskinput.GitHubHost,
			IssuerID:       "Iv1testclientid123",
			InstallationID: 987654,
			PrivateKeyRef:  "mounted:github-app-key",
			Active:         true,
		}},
		privateKeySourceStub{content: keyPEM},
		&http.Client{Transport: transport},
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := broker.Issue(context.Background(), IssueRequest{
		Repository: repository,
		Permission: ContentsWrite,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer token.Destroy()
	var materialized []byte
	if err := token.Materialize(func(value []byte) error {
		materialized = bytes.Clone(value)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer clear(materialized)
	if string(materialized) !=
		"ghs_stateless_test_token_value_123456789" ||
		token.RepositoryID != repository.RepositoryID ||
		token.Permission != ContentsWrite ||
		!token.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Fatalf("issued token metadata drifted: %#v", token)
	}
}

func TestBrokerRejectsRepositoryOrPermissionExpansion(t *testing.T) {
	t.Parallel()
	repository := taskinput.GitRepositoryV1{
		Provider:      taskinput.GitProviderGitHub,
		Host:          taskinput.GitHubHost,
		ConnectionID:  uuid.NewString(),
		RepositoryID:  "42",
		Owner:         "octocat",
		Name:          "Hello-World",
		BaseCommitSHA: strings.Repeat("b", 40),
		BaseRef:       "refs/heads/main",
	}
	broker, err := NewBroker(
		connectionSourceStub{err: ErrUnavailable},
		privateKeySourceStub{},
		&http.Client{Transport: roundTripFunc(func(
			*http.Request,
		) (*http.Response, error) {
			t.Fatal("invalid request reached GitHub")
			return nil, nil
		})},
		time.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	request := IssueRequest{
		Repository: repository,
		Permission: ContentsPermission("admin"),
	}
	if _, err := broker.Issue(
		context.Background(),
		request,
	); err != ErrInvalid {
		t.Fatalf("permission expansion error = %v", err)
	}
	changed := repository
	changed.ConnectionID = uuid.NewString()
	request.Permission = ContentsRead
	request.Repository = changed
	if _, err := broker.Issue(
		context.Background(),
		request,
	); err != ErrUnavailable {
		t.Fatalf("connection substitution error = %v", err)
	}
}

func verifyAppJWT(
	t *testing.T,
	token string,
	publicKey *rsa.PublicKey,
	issuer string,
	now time.Time,
) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	defer clear(header)
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	defer clear(claims)
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	defer clear(signature)
	var headerValue map[string]string
	var claimsValue struct {
		IssuedAt  int64  `json:"iat"`
		ExpiresAt int64  `json:"exp"`
		Issuer    string `json:"iss"`
	}
	if json.Unmarshal(header, &headerValue) != nil ||
		json.Unmarshal(claims, &claimsValue) != nil ||
		headerValue["alg"] != "RS256" ||
		headerValue["typ"] != "JWT" ||
		claimsValue.Issuer != issuer ||
		claimsValue.IssuedAt != now.Add(-time.Minute).Unix() ||
		claimsValue.ExpiresAt != now.Add(9*time.Minute).Unix() {
		t.Fatalf("JWT claims drifted: %s %s", header, claims)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(
		publicKey,
		crypto.SHA256,
		digest[:],
		signature,
	); err != nil {
		t.Fatalf("JWT signature verification failed: %v", err)
	}
}

type connectionSourceStub struct {
	connection ConnectionV1
	err        error
}

func (source connectionSourceStub) LoadGitHubAppConnection(
	context.Context,
	string,
) (ConnectionV1, error) {
	return source.connection, source.err
}

type privateKeySourceStub struct {
	content []byte
	err     error
}

func (source privateKeySourceStub) MaterializeGitHubAppPrivateKey(
	_ context.Context,
	_ string,
	use func([]byte) error,
) error {
	if source.err != nil {
		return source.err
	}
	content := bytes.Clone(source.content)
	defer clear(content)
	return use(content)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(
	request *http.Request,
) (*http.Response, error) {
	return function(request)
}
