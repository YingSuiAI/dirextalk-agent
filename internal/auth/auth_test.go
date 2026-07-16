package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type credentialRepositoryStub struct {
	credential Credential
	err        error
}

func (repository credentialRepositoryStub) CredentialByKeyID(context.Context, string) (Credential, error) {
	return repository.credential, repository.err
}

func TestAuthenticatorRejectsInvalidInactiveAndExpiredKeys(t *testing.T) {
	t.Parallel()
	pepper := []byte("0123456789abcdef0123456789abcdef")
	secret := []byte("abcdef0123456789abcdef0123456789")
	validUntil := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name       string
		header     string
		credential Credential
		repoErr    error
		wantCode   string
	}{
		{name: "wrong scheme", header: "Bearer value", wantCode: "Unauthenticated"},
		{name: "unknown key", header: authorizationScheme + " " + FormatServiceKey("key", secret), repoErr: ErrCredentialNotFound, wantCode: "Unauthenticated"},
		{name: "wrong secret", header: authorizationScheme + " " + FormatServiceKey("key", secret), credential: Credential{Active: true, SecretDigest: Digest(pepper, []byte("0123456789abcdef0123456789abcdef"))}, wantCode: "Unauthenticated"},
		{name: "inactive", header: authorizationScheme + " " + FormatServiceKey("key", secret), credential: Credential{Active: false, SecretDigest: Digest(pepper, secret)}, wantCode: "Unauthenticated"},
		{name: "expired", header: authorizationScheme + " " + FormatServiceKey("key", secret), credential: Credential{Active: true, ExpiresAt: &validUntil, SecretDigest: Digest(pepper, secret)}, wantCode: "Unauthenticated"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authenticator, err := NewAuthenticator(credentialRepositoryStub{credential: test.credential, err: test.repoErr}, pepper)
			if err != nil {
				t.Fatal(err)
			}
			authenticator.now = func() time.Time { return validUntil }
			ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", test.header))
			_, err = authenticator.Authenticate(ctx)
			if got := status.Code(err).String(); got != test.wantCode {
				t.Fatalf("Authenticate() code = %s, want %s (err=%v)", got, test.wantCode, err)
			}
		})
	}
}

func TestAuthenticatorReturnsScopedPrincipal(t *testing.T) {
	t.Parallel()
	pepper := []byte("0123456789abcdef0123456789abcdef")
	secret := []byte("abcdef0123456789abcdef0123456789")
	authenticator, err := NewAuthenticator(credentialRepositoryStub{credential: Credential{
		CredentialID: "credential", ClientID: "message-server", Scopes: []string{"task.read"}, Active: true, SecretDigest: Digest(pepper, secret),
	}}, pepper)
	if err != nil {
		t.Fatal(err)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", authorizationScheme+" "+FormatServiceKey("key", secret)))
	principal, err := authenticator.Authenticate(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ClientID != "message-server" || !principal.HasScope("task.read") || principal.HasScope("task.write") {
		t.Fatalf("unexpected principal: %#v", principal)
	}
}

func TestNewAuthenticatorRequiresPepper(t *testing.T) {
	t.Parallel()
	_, err := NewAuthenticator(credentialRepositoryStub{err: errors.New("unused")}, []byte("short"))
	if err == nil {
		t.Fatal("expected short pepper to be rejected")
	}
}

func TestReadSecretFileValueParsesAndClearsMountedBuffer(t *testing.T) {
	t.Parallel()
	secret := []byte("0123456789abcdef0123456789abcdef")
	raw := []byte("  svc_example." + base64.RawURLEncoding.EncodeToString(secret) + "\n")
	keyID, parsed, err := ReadSecretFileValue(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(parsed)
	if keyID != "svc_example" || subtle.ConstantTimeCompare(parsed, secret) != 1 {
		t.Fatal("mounted service key parsed incorrectly")
	}
	for _, value := range raw {
		if value != 0 {
			t.Fatal("mounted service key buffer was not cleared")
		}
	}
}

func TestUnaryInterceptorEnforcesScopesAndDeniesUnmappedMethods(t *testing.T) {
	t.Parallel()
	pepper := []byte("0123456789abcdef0123456789abcdef")
	secret := []byte("abcdef0123456789abcdef0123456789")
	authenticator, err := NewAuthenticator(credentialRepositoryStub{credential: Credential{
		CredentialID: "credential", ClientID: "caller", Scopes: []string{"task.read"}, Active: true, SecretDigest: Digest(pepper, secret),
	}}, pepper)
	if err != nil {
		t.Fatal(err)
	}
	unary, _ := NewInterceptors(authenticator, StaticScopeResolver(map[string]string{"/task/read": "task.read", "/task/write": "task.write"}))
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", authorizationScheme+" "+FormatServiceKey("key", secret)))
	handler := func(ctx context.Context, _ any) (any, error) {
		if values := metadata.ValueFromIncomingContext(ctx, "authorization"); len(values) != 0 {
			t.Fatalf("authorization metadata reached handler: %v", values)
		}
		if principal, ok := PrincipalFromContext(ctx); !ok || principal.ClientID != "caller" {
			t.Fatalf("authenticated principal missing from handler context: %#v", principal)
		}
		return "ok", nil
	}

	result, err := unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/task/read"}, handler)
	if err != nil || result != "ok" {
		t.Fatalf("read authorization = (%v, %v), want ok", result, err)
	}
	for _, method := range []string{"/task/write", "/future/unmapped"} {
		_, err := unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method}, handler)
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("method %s code = %s, want PermissionDenied", method, status.Code(err))
		}
	}
}

func TestStreamInterceptorRemovesAuthorizationMetadata(t *testing.T) {
	t.Parallel()
	pepper := []byte("0123456789abcdef0123456789abcdef")
	secret := []byte("abcdef0123456789abcdef0123456789")
	authenticator, err := NewAuthenticator(credentialRepositoryStub{credential: Credential{
		CredentialID: "credential", ClientID: "caller", Scopes: []string{"event.read"}, Active: true, SecretDigest: Digest(pepper, secret),
	}}, pepper)
	if err != nil {
		t.Fatal(err)
	}
	_, streamInterceptor := NewInterceptors(authenticator, StaticScopeResolver(map[string]string{"/task/watch": "event.read"}))
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", authorizationScheme+" "+FormatServiceKey("key", secret)))
	stream := &serverStreamStub{ctx: ctx}
	err = streamInterceptor(nil, stream, &grpc.StreamServerInfo{FullMethod: "/task/watch"}, func(_ any, authorized grpc.ServerStream) error {
		if values := metadata.ValueFromIncomingContext(authorized.Context(), "authorization"); len(values) != 0 {
			t.Fatalf("authorization metadata reached stream handler: %v", values)
		}
		principal, ok := PrincipalFromContext(authorized.Context())
		if !ok || principal.ClientID != "caller" {
			t.Fatalf("authenticated principal missing from stream context: %#v", principal)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("stream authorization: %v", err)
	}
}

type serverStreamStub struct {
	grpc.ServerStream
	ctx context.Context
}

func (stream *serverStreamStub) Context() context.Context { return stream.ctx }
