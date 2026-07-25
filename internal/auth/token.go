package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const AgentTokenAuthorizationScheme = "DTX-Agent-Token"

var errInvalidAgentToken = errors.New("invalid agent service token")

// ReadServiceTokenFile reads the exact 32-byte unpadded base64url token used
// by the Core gRPC boundary. Whitespace, padding, and trailing material are
// intentionally rejected.
func ReadServiceTokenFile(path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", errors.New("service_token_file is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open service token file: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("inspect service token file: %w", err)
	}
	if err := validateServiceTokenFileInfo(info); err != nil {
		return "", err
	}
	raw, err := io.ReadAll(io.LimitReader(file, 129))
	if err != nil {
		return "", fmt.Errorf("read service token file: %w", err)
	}
	if len(raw) > 128 {
		return "", errInvalidAgentToken
	}
	value := string(raw)
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return "", errInvalidAgentToken
	}
	return value, nil
}

func ValidateServiceTokenFile(path string) error {
	_, err := ReadServiceTokenFile(path)
	return err
}

type AgentTokenAuthenticator struct {
	token []byte
}

type authorizedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authorizedServerStream) Context() context.Context { return s.ctx }

func NewAgentTokenAuthenticator(token string) (*AgentTokenAuthenticator, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return nil, errInvalidAgentToken
	}
	return &AgentTokenAuthenticator{token: []byte(token)}, nil
}

func NewAgentTokenInterceptors(token string) (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor, error) {
	authenticator, err := NewAgentTokenAuthenticator(token)
	if err != nil {
		return nil, nil, err
	}
	unary, stream := authenticator.Interceptors()
	return unary, stream, nil
}

func (authenticator *AgentTokenAuthenticator) Interceptors() (grpc.UnaryServerInterceptor, grpc.StreamServerInterceptor) {
	check := func(ctx metadata.MD, fullMethod string) (contextMetadata metadata.MD, err error) {
		if strings.HasPrefix(fullMethod, "/grpc.health.v1.Health/") {
			redacted := ctx.Copy()
			redacted.Delete("authorization")
			return redacted, nil
		}
		values := ctx.Get("authorization")
		if len(values) != 1 {
			return nil, status.Error(codes.Unauthenticated, "agent authentication required")
		}
		value := values[0]
		prefix := AgentTokenAuthorizationScheme + " "
		if !strings.HasPrefix(value, prefix) {
			return nil, status.Error(codes.Unauthenticated, "invalid agent authentication")
		}
		candidate := value[len(prefix):]
		if len(candidate) != len(authenticator.token) || subtle.ConstantTimeCompare([]byte(candidate), authenticator.token) != 1 {
			return nil, status.Error(codes.Unauthenticated, "invalid agent authentication")
		}
		redacted := ctx.Copy()
		redacted.Delete("authorization")
		return redacted, nil
	}

	strip := func(ctx context.Context, fullMethod string) (context.Context, error) {
		incoming, _ := metadata.FromIncomingContext(ctx)
		redacted, err := check(incoming, fullMethod)
		if err != nil {
			return nil, err
		}
		return metadata.NewIncomingContext(ctx, redacted), nil
	}
	unary := func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		authorized, err := strip(ctx, info.FullMethod)
		if err != nil {
			return nil, err
		}
		return handler(authorized, req)
	}
	stream := func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		authorized, err := strip(stream.Context(), info.FullMethod)
		if err != nil {
			return err
		}
		return handler(srv, &authorizedServerStream{ServerStream: stream, ctx: authorized})
	}
	return unary, stream
}
