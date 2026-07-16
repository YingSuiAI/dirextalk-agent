package rpcapi

import (
	"context"
	"encoding/base64"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type SecretBootstrapManager interface {
	CreateIdempotent(context.Context, secretbootstrap.MutationScope, string, secretbootstrap.BindingV1) (secretbootstrap.CreateResult, error)
	Get(context.Context, string, string) (secretbootstrap.SessionV1, error)
	UploadIdempotent(context.Context, secretbootstrap.MutationScope, string, string, uint64, string, secretbootstrap.EnvelopeV1) (secretbootstrap.SessionV1, error)
}

type SecretBootstrapService struct {
	agentv1.UnimplementedSecretBootstrapServiceServer
	manager         SecretBootstrapManager
	agentInstanceID string
}

func NewSecretBootstrapService(manager SecretBootstrapManager, agentInstanceID string) *SecretBootstrapService {
	return &SecretBootstrapService{manager: manager, agentInstanceID: agentInstanceID}
}

func (service *SecretBootstrapService) CreateSession(ctx context.Context, request *agentv1.CreateSessionRequest) (*agentv1.CreateSessionResponse, error) {
	scope, err := secretMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.manager == nil {
		return nil, status.Error(codes.Unavailable, "secret bootstrap is not configured")
	}
	created, err := service.manager.CreateIdempotent(ctx, scope, request.GetIdempotencyKey(), secretbootstrap.BindingV1{
		AgentInstanceID: service.agentInstanceID,
		OwnerID:         request.GetOwnerId(),
		Purpose:         request.GetPurpose(),
		TargetID:        request.GetTargetId(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	publicKey, err := decodeBootstrapValue(created.Session.ServerPublicKey, 32)
	if err != nil {
		return nil, status.Error(codes.Internal, "stored bootstrap session is invalid")
	}
	uploadToken, err := decodeBootstrapValue(created.UploadToken.Reveal(), 32)
	if err != nil && created.UploadToken.Reveal() != "" {
		return nil, status.Error(codes.Internal, "stored bootstrap replay token is invalid")
	}
	return &agentv1.CreateSessionResponse{
		SessionId: created.Session.SessionID, ServerPublicKey: publicKey,
		UploadToken: uploadToken, ExpiresAt: timestamppb.New(created.Session.ExpiresAt),
		Session: secretBootstrapSessionToProto(created.Session),
	}, nil
}

func (service *SecretBootstrapService) GetSession(ctx context.Context, request *agentv1.SecretBootstrapServiceGetSessionRequest) (*agentv1.SecretBootstrapServiceGetSessionResponse, error) {
	scope, err := secretMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.manager == nil {
		return nil, status.Error(codes.Unavailable, "secret bootstrap is not configured")
	}
	session, err := service.manager.Get(ctx, scope.ClientID, request.GetSessionId())
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.SecretBootstrapServiceGetSessionResponse{Session: secretBootstrapSessionToProto(session)}, nil
}

func (service *SecretBootstrapService) UploadEncrypted(ctx context.Context, request *agentv1.UploadEncryptedRequest) (*agentv1.UploadEncryptedResponse, error) {
	scope, err := secretMutationScope(ctx)
	if err != nil {
		return nil, err
	}
	if service.manager == nil {
		return nil, status.Error(codes.Unavailable, "secret bootstrap is not configured")
	}
	if request.GetExpectedRevision() < 1 || len(request.GetUploadToken()) != 32 || len(request.GetClientPublicKey()) != 32 || len(request.GetNonce()) != 12 || len(request.GetCiphertext()) < 16 {
		return nil, status.Error(codes.InvalidArgument, "encrypted upload shape is invalid")
	}
	session, err := service.manager.UploadIdempotent(
		ctx, scope, request.GetIdempotencyKey(), request.GetSessionId(), uint64(request.GetExpectedRevision()),
		base64.RawURLEncoding.EncodeToString(request.GetUploadToken()),
		secretbootstrap.EnvelopeV1{
			SchemaVersion:   secretbootstrap.EnvelopeSchemaV1,
			SessionID:       request.GetSessionId(),
			ClientPublicKey: base64.RawURLEncoding.EncodeToString(request.GetClientPublicKey()),
			Nonce:           base64.RawURLEncoding.EncodeToString(request.GetNonce()),
			Ciphertext:      base64.RawURLEncoding.EncodeToString(request.GetCiphertext()),
		},
	)
	if err != nil {
		return nil, publicError(err)
	}
	return &agentv1.UploadEncryptedResponse{Revision: int64(session.Revision), Session: secretBootstrapSessionToProto(session)}, nil
}

// Complete is reserved for a future device-signed typed secret destination.
// It deliberately performs no lookup, delivery, consumption, or persistence
// until the public contract binds the session revision, owner, purpose, target,
// destination, expiry, and approval-device signature.
func (service *SecretBootstrapService) Complete(ctx context.Context, request *agentv1.CompleteRequest) (*agentv1.CompleteResponse, error) {
	if _, err := secretMutationScope(ctx); err != nil {
		return nil, err
	}
	return nil, status.Error(codes.Unimplemented, "secret bootstrap completion is reserved until device-signed destination binding is implemented")
}

func secretMutationScope(ctx context.Context) (secretbootstrap.MutationScope, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return secretbootstrap.MutationScope{}, status.Error(codes.Unauthenticated, "authenticated caller is required")
	}
	scope := secretbootstrap.MutationScope{ClientID: principal.ClientID, CredentialID: principal.CredentialID}
	if err := scope.Validate(); err != nil {
		return secretbootstrap.MutationScope{}, status.Error(codes.Unauthenticated, "authenticated caller identity is invalid")
	}
	return scope, nil
}

func secretBootstrapSessionToProto(session secretbootstrap.SessionV1) *agentv1.SecretBootstrapSession {
	publicKey, _ := decodeBootstrapValue(session.ServerPublicKey, 32)
	return &agentv1.SecretBootstrapSession{
		SessionId: session.SessionID, OwnerId: session.OwnerID, Purpose: session.Purpose,
		TargetId: session.TargetID, ServerPublicKey: publicKey,
		CreatedAt: timestamppb.New(session.CreatedAt), ExpiresAt: timestamppb.New(session.ExpiresAt),
		Status: secretBootstrapStatusToProto(session.Status), Revision: int64(session.Revision),
	}
}

func secretBootstrapStatusToProto(value secretbootstrap.Status) agentv1.SecretBootstrapSessionStatus {
	switch value {
	case secretbootstrap.StatusAwaitingUpload:
		return agentv1.SecretBootstrapSessionStatus_SECRET_BOOTSTRAP_SESSION_STATUS_AWAITING_UPLOAD
	case secretbootstrap.StatusUploaded:
		return agentv1.SecretBootstrapSessionStatus_SECRET_BOOTSTRAP_SESSION_STATUS_UPLOADED
	case secretbootstrap.StatusConsumed:
		return agentv1.SecretBootstrapSessionStatus_SECRET_BOOTSTRAP_SESSION_STATUS_CONSUMED
	case secretbootstrap.StatusExpired:
		return agentv1.SecretBootstrapSessionStatus_SECRET_BOOTSTRAP_SESSION_STATUS_EXPIRED
	default:
		return agentv1.SecretBootstrapSessionStatus_SECRET_BOOTSTRAP_SESSION_STATUS_UNSPECIFIED
	}
}

func decodeBootstrapValue(value string, expected int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != expected {
		secretbootstrap.Wipe(decoded)
		return nil, secretbootstrap.ErrInvalidContext
	}
	return decoded, nil
}
