package rpcapi

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"slices"
	"strings"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const serviceKeyDeliveryAADSchema = "dirextalk.agent.service-key-delivery.aad/v1"

type AdminService struct {
	agentv1.UnimplementedAdminServiceServer
	repository auth.CredentialManagerRepository
	pepper     []byte
	now        func() time.Time
}

func NewAdminService(repository auth.CredentialManagerRepository, pepper []byte) *AdminService {
	return &AdminService{repository: repository, pepper: append([]byte(nil), pepper...), now: time.Now}
}

func (service *AdminService) CreateServiceKey(ctx context.Context, request *agentv1.CreateServiceKeyRequest) (*agentv1.CreateServiceKeyResponse, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authenticated caller is required")
	}
	var expiresAt *time.Time
	if request.GetExpiresAt() != nil {
		if err := request.GetExpiresAt().CheckValid(); err != nil {
			return nil, status.Error(codes.InvalidArgument, "expires_at is invalid")
		}
		value := request.GetExpiresAt().AsTime().UTC()
		expiresAt = &value
	}
	recipientPublicKey := request.GetRecipientPublicKey()
	if len(recipientPublicKey) != base64.RawURLEncoding.EncodedLen(32) {
		return nil, status.Error(codes.InvalidArgument, "recipient_public_key must be an unpadded base64url X25519 public key")
	}
	recipientKeyBytes, err := base64.RawURLEncoding.DecodeString(recipientPublicKey)
	if err != nil || len(recipientKeyBytes) != 32 {
		return nil, status.Error(codes.InvalidArgument, "recipient_public_key must be an unpadded base64url X25519 public key")
	}
	clear(recipientKeyBytes)

	credentialID, err := uuid.NewV7()
	if err != nil {
		return nil, status.Error(codes.Internal, "could not generate credential id")
	}
	keyUUID, err := uuid.NewV7()
	if err != nil {
		return nil, status.Error(codes.Internal, "could not generate key id")
	}
	keyID := "svc_" + strings.ReplaceAll(keyUUID.String(), "-", "")
	scopes := append([]string(nil), request.GetScopes()...)
	slices.Sort(scopes)
	scopes = slices.Compact(scopes)
	aad, err := json.Marshal(struct {
		SchemaVersion      string   `json:"schema_version"`
		Operation          string   `json:"operation"`
		CallerCredentialID string   `json:"caller_credential_id"`
		CallerClientID     string   `json:"caller_client_id"`
		IdempotencyKey     string   `json:"idempotency_key"`
		CredentialID       string   `json:"credential_id"`
		KeyID              string   `json:"key_id"`
		ClientID           string   `json:"client_id"`
		Scopes             []string `json:"scopes"`
		ExpiresAt          string   `json:"expires_at,omitempty"`
		RecipientPublicKey string   `json:"recipient_public_key"`
	}{
		SchemaVersion: serviceKeyDeliveryAADSchema, Operation: "admin.service-key.create",
		CallerCredentialID: principal.CredentialID, CallerClientID: principal.ClientID, IdempotencyKey: request.GetIdempotencyKey(),
		CredentialID: credentialID.String(), KeyID: keyID, ClientID: request.GetClientId(), Scopes: scopes,
		ExpiresAt: formatOptionalTime(expiresAt), RecipientPublicKey: recipientPublicKey,
	})
	if err != nil {
		return nil, status.Error(codes.Internal, "could not encode credential delivery binding")
	}
	secret := make([]byte, 32)
	if _, err := cryptorand.Read(secret); err != nil {
		return nil, status.Error(codes.Internal, "could not generate service credential")
	}
	defer secretbootstrap.Wipe(secret)
	encodedSecretLength := base64.RawURLEncoding.EncodedLen(len(secret))
	serviceKey := make([]byte, len(keyID)+1+encodedSecretLength)
	copy(serviceKey, keyID)
	serviceKey[len(keyID)] = '.'
	base64.RawURLEncoding.Encode(serviceKey[len(keyID)+1:], secret)
	defer secretbootstrap.Wipe(serviceKey)
	envelope, err := secretbootstrap.SealToRecipient(recipientPublicKey, serviceKey, aad)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "recipient_public_key could not receive encrypted credential")
	}
	delivery := auth.EncryptedDelivery{
		SchemaVersion: envelope.SchemaVersion, ServerPublicKey: envelope.ServerPublicKey,
		Nonce: envelope.Nonce, Ciphertext: envelope.Ciphertext, AssociatedData: append([]byte(nil), aad...),
	}
	command := auth.CreateCredentialCommand{
		CallerCredentialID: principal.CredentialID, CallerClientID: principal.ClientID, IdempotencyKey: request.GetIdempotencyKey(),
		CredentialID: credentialID.String(), KeyID: keyID, ClientID: request.GetClientId(), Scopes: scopes,
		RecipientPublicKey: recipientPublicKey, SecretDigest: auth.Digest(service.pepper, secret),
		Delivery: delivery, ExpiresAt: expiresAt,
	}
	if err := command.Validate(service.now().UTC()); err != nil {
		return nil, publicError(err)
	}
	created, err := service.repository.CreateCredential(ctx, command)
	if err != nil {
		return nil, publicError(err)
	}
	return createServiceKeyResponse(created), nil
}

func (service *AdminService) RevokeServiceKey(ctx context.Context, request *agentv1.RevokeServiceKeyRequest) (*agentv1.RevokeServiceKeyResponse, error) {
	principal, ok := auth.PrincipalFromContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authenticated caller is required")
	}
	credential, err := service.repository.RevokeCredential(ctx, auth.RevokeCredentialCommand{
		CallerCredentialID: principal.CredentialID, CallerClientID: principal.ClientID, IdempotencyKey: request.GetIdempotencyKey(),
		CredentialID: request.GetCredentialId(), ExpectedRevision: request.GetExpectedRevision(),
	})
	if err != nil {
		return nil, publicError(err)
	}
	response := &agentv1.RevokeServiceKeyResponse{
		CredentialId: credential.CredentialID, KeyId: credential.KeyID, ClientId: credential.ClientID,
		Scopes: append([]string(nil), credential.Scopes...), Active: credential.Active, Revision: credential.Revision,
	}
	if credential.ExpiresAt != nil {
		response.ExpiresAt = timestamppb.New(*credential.ExpiresAt)
	}
	return response, nil
}

func createServiceKeyResponse(created auth.CreatedCredential) *agentv1.CreateServiceKeyResponse {
	credential := created.Credential
	response := &agentv1.CreateServiceKeyResponse{
		CredentialId: credential.CredentialID, KeyId: credential.KeyID, ClientId: credential.ClientID,
		Scopes: append([]string(nil), credential.Scopes...), Active: credential.Active, Revision: credential.Revision,
		Delivery: &agentv1.ServiceKeyDelivery{
			SchemaVersion: created.Delivery.SchemaVersion, ServerPublicKey: created.Delivery.ServerPublicKey,
			Nonce: created.Delivery.Nonce, Ciphertext: created.Delivery.Ciphertext,
			AssociatedData: append([]byte(nil), created.Delivery.AssociatedData...),
		},
	}
	if credential.ExpiresAt != nil {
		response.ExpiresAt = timestamppb.New(*credential.ExpiresAt)
	}
	return response
}

func formatOptionalTime(value *time.Time) string {
	if value == nil {
		return ""
	}
	return value.UTC().Format(time.RFC3339Nano)
}
