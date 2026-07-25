package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func TestReadServiceTokenFileRejectsNonCanonicalMaterial(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	valid := base64.RawURLEncoding.EncodeToString(raw)
	for name, value := range map[string]string{
		"padding": valid + "=",
		"newline": valid + "\n",
		"raw":     string(raw),
		"extra":   valid + "x",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			if got, err := ReadServiceTokenFile(path); err == nil || got != "" {
				t.Fatalf("token=%q err=%v, want rejection", got, err)
			}
		})
	}
}

func TestAgentTokenInterceptorRequiresOneHeaderAndRedactsIt(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	authenticator, err := NewAgentTokenAuthenticator(token)
	if err != nil {
		t.Fatal(err)
	}
	unary, _ := authenticator.Interceptors()
	handler := func(ctx context.Context, _ any) (any, error) {
		if values := metadata.ValueFromIncomingContext(ctx, "authorization"); len(values) != 0 {
			t.Fatalf("authorization metadata reached handler: %v", values)
		}
		return "ok", nil
	}
	for _, values := range [][]string{{}, {AgentTokenAuthorizationScheme + " " + token, AgentTokenAuthorizationScheme + " " + token}, {"Bearer " + token}} {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.MD{"authorization": values})
		_, err := unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/dirextalk.agent.v1.AgentService/GetInstanceInfo"}, handler)
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("headers=%v code=%v, want unauthenticated", values, status.Code(err))
		}
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", AgentTokenAuthorizationScheme+" "+token))
	result, err := unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/dirextalk.agent.v1.AgentService/GetInstanceInfo"}, handler)
	if err != nil || result != "ok" {
		t.Fatalf("valid token result=(%v,%v)", result, err)
	}
}

func TestAgentTokenInterceptorHealthIsUnauthenticatedAndRedactsMetadata(t *testing.T) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatal(err)
	}
	authenticator, err := NewAgentTokenAuthenticator(base64.RawURLEncoding.EncodeToString(raw))
	if err != nil {
		t.Fatal(err)
	}
	unary, _ := authenticator.Interceptors()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "secret", "x-test", "present"))
	_, err = unary(ctx, nil, &grpc.UnaryServerInfo{FullMethod: "/grpc.health.v1.Health/Check"}, func(ctx context.Context, _ any) (any, error) {
		if metadata.ValueFromIncomingContext(ctx, "authorization") != nil {
			t.Fatal("health handler received authorization metadata")
		}
		if got := metadata.ValueFromIncomingContext(ctx, "x-test"); len(got) != 1 || got[0] != "present" {
			t.Fatalf("health metadata = %v", got)
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
