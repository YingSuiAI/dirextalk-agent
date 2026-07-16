package auth

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const authorizationScheme = "DTX-Service-Key"
const denyScope = "__unmapped_method__"

var ErrCredentialNotFound = errors.New("service credential not found")

type Credential struct {
	CredentialID string
	KeyID        string
	ClientID     string
	Scopes       []string
	SecretDigest []byte
	Active       bool
	ExpiresAt    *time.Time
	Revision     int64
}

type CredentialRepository interface {
	CredentialByKeyID(context.Context, string) (Credential, error)
}

type Principal struct {
	CredentialID string
	ClientID     string
	Scopes       map[string]struct{}
}

func (principal Principal) HasScope(scope string) bool {
	_, ok := principal.Scopes[scope]
	return ok
}

type principalContextKey struct{}

func PrincipalFromContext(ctx context.Context) (Principal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(Principal)
	return principal, ok
}

// ContextWithPrincipal is used by trusted transport adapters after successful
// authentication. It never grants scopes by itself; public handlers remain
// behind the fail-closed interceptors.
func ContextWithPrincipal(ctx context.Context, principal Principal) context.Context {
	return context.WithValue(ctx, principalContextKey{}, principal)
}

type Authenticator struct {
	repository CredentialRepository
	pepper     []byte
	now        func() time.Time
}

func NewAuthenticator(repository CredentialRepository, pepper []byte) (*Authenticator, error) {
	if repository == nil {
		return nil, errors.New("credential repository is required")
	}
	if len(pepper) < 32 {
		return nil, errors.New("service key pepper must contain at least 32 bytes")
	}
	return &Authenticator{repository: repository, pepper: append([]byte(nil), pepper...), now: time.Now}, nil
}

func Digest(pepper, secret []byte) []byte {
	mac := hmac.New(sha256.New, pepper)
	_, _ = mac.Write(secret)
	return mac.Sum(nil)
}

func FormatServiceKey(keyID string, secret []byte) string {
	return keyID + "." + base64.RawURLEncoding.EncodeToString(secret)
}

func ParseServiceKey(value string) (string, []byte, error) {
	parts := strings.Fields(value)
	if len(parts) != 2 || parts[0] != authorizationScheme {
		return "", nil, errors.New("invalid authorization scheme")
	}
	pair := strings.Split(parts[1], ".")
	if len(pair) != 2 || !serviceKeyIDPattern.MatchString(pair[0]) {
		return "", nil, errors.New("invalid service key")
	}
	secret, err := base64.RawURLEncoding.DecodeString(pair[1])
	if err != nil || len(secret) != sha256.Size {
		return "", nil, errors.New("invalid service key")
	}
	return pair[0], secret, nil
}

func (authenticator *Authenticator) Authenticate(ctx context.Context) (Principal, error) {
	values := metadata.ValueFromIncomingContext(ctx, "authorization")
	if len(values) != 1 {
		return Principal{}, status.Error(codes.Unauthenticated, "service authentication required")
	}
	keyID, secret, err := ParseServiceKey(values[0])
	if err != nil {
		return Principal{}, status.Error(codes.Unauthenticated, "invalid service authentication")
	}
	defer clear(secret)

	credential, repositoryErr := authenticator.repository.CredentialByKeyID(ctx, keyID)
	if repositoryErr != nil {
		credential.SecretDigest = make([]byte, sha256.Size)
	}
	expected := Digest(authenticator.pepper, secret)
	defer clear(expected)
	validDigest := len(credential.SecretDigest) == sha256.Size && subtle.ConstantTimeCompare(expected, credential.SecretDigest) == 1
	if repositoryErr != nil || !validDigest {
		return Principal{}, status.Error(codes.Unauthenticated, "invalid service authentication")
	}
	now := authenticator.now().UTC()
	if !credential.Active || (credential.ExpiresAt != nil && !now.Before(credential.ExpiresAt.UTC())) {
		return Principal{}, status.Error(codes.Unauthenticated, "service credential is inactive")
	}
	scopes := make(map[string]struct{}, len(credential.Scopes))
	for _, scope := range credential.Scopes {
		scopes[scope] = struct{}{}
	}
	return Principal{CredentialID: credential.CredentialID, ClientID: credential.ClientID, Scopes: scopes}, nil
}

type ScopeResolver func(fullMethod string) (scope string, authenticated bool)

func NewInterceptors(authenticator *Authenticator, resolve ScopeResolver) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	authorize := func(ctx context.Context, fullMethod string) (context.Context, error) {
		scope, authenticated := resolve(fullMethod)
		if !authenticated {
			return ctx, nil
		}
		if scope == denyScope {
			return nil, status.Error(codes.PermissionDenied, "gRPC method is not mapped to an authorization scope")
		}
		principal, err := authenticator.Authenticate(ctx)
		if err != nil {
			return nil, err
		}
		if scope != "" && !principal.HasScope(scope) && !principal.HasScope("admin") {
			return nil, status.Error(codes.PermissionDenied, "service credential lacks required scope")
		}
		incoming, _ := metadata.FromIncomingContext(ctx)
		redacted := incoming.Copy()
		redacted.Delete("authorization")
		ctx = metadata.NewIncomingContext(ctx, redacted)
		return ContextWithPrincipal(ctx, principal), nil
	}

	unary := func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		authorized, err := authorize(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(authorized, request)
	}
	stream := func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		authorized, err := authorize(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(server, &authorizedServerStream{ServerStream: stream, ctx: authorized})
	}
	return unary, stream
}

type authorizedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (stream *authorizedServerStream) Context() context.Context { return stream.ctx }

func StaticScopeResolver(scopes map[string]string) ScopeResolver {
	return func(fullMethod string) (string, bool) {
		if strings.HasPrefix(fullMethod, "/grpc.health.v1.Health/") {
			return "", false
		}
		scope, ok := scopes[fullMethod]
		if !ok {
			return denyScope, true
		}
		return scope, true
	}
}

func ReadSecretFileValue(raw []byte) (string, []byte, error) {
	defer clear(raw)
	value := bytes.TrimSpace(raw)
	separator := bytes.IndexByte(value, '.')
	if separator < 1 || separator > 128 || bytes.IndexByte(value[separator+1:], '.') >= 0 || !serviceKeyIDPattern.Match(value[:separator]) {
		return "", nil, errors.New("parse mounted service key: invalid service key")
	}
	encoded := value[separator+1:]
	secret := make([]byte, base64.RawURLEncoding.DecodedLen(len(encoded)))
	written, err := base64.RawURLEncoding.Decode(secret, encoded)
	if err != nil || written != sha256.Size {
		clear(secret)
		return "", nil, errors.New("parse mounted service key: invalid service key")
	}
	return string(value[:separator]), secret[:written], nil
}
