package rpcapi

import (
	"context"
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/base64"
	"strings"
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func TestCreateServiceKeyReturnsOnlyRecipientEncryptedRandomCredential(t *testing.T) {
	repository := &credentialManagerStub{}
	pepper := []byte("0123456789abcdef0123456789abcdef")
	service := NewAdminService(repository, pepper)
	recipientPrivate, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := &agentv1.CreateServiceKeyRequest{
		IdempotencyKey: uuid.NewString(), ClientId: "message-server",
		Scopes:             []string{"task.write", "task.read"},
		RecipientPublicKey: base64.RawURLEncoding.EncodeToString(recipientPrivate.PublicKey().Bytes()),
	}
	principal := auth.Principal{CredentialID: uuid.NewString(), ClientID: "bootstrap-admin", Scopes: map[string]struct{}{"admin": {}}}
	ctx := auth.ContextWithPrincipal(context.Background(), principal)

	created, err := service.CreateServiceKey(ctx, request)
	if err != nil {
		t.Fatalf("CreateServiceKey: %v", err)
	}
	if created.GetDelivery() == nil || created.GetDelivery().GetCiphertext() == "" {
		t.Fatal("encrypted delivery is missing")
	}
	delivery := created.GetDelivery()
	plaintext, err := secretbootstrap.OpenRecipientEnvelope(recipientPrivate.Bytes(), secretbootstrap.RecipientEnvelopeV1{
		SchemaVersion: delivery.GetSchemaVersion(), ServerPublicKey: delivery.GetServerPublicKey(),
		Nonce: delivery.GetNonce(), Ciphertext: delivery.GetCiphertext(),
	}, delivery.GetAssociatedData())
	if err != nil {
		t.Fatalf("decrypt delivery: %v", err)
	}
	defer secretbootstrap.Wipe(plaintext)
	if !strings.HasPrefix(string(plaintext), created.GetKeyId()+".") {
		t.Fatal("decrypted service key is not bound to returned key id")
	}
	_, parsedSecret, err := auth.ParseServiceKey("DTX-Service-Key " + string(plaintext))
	if err != nil {
		t.Fatalf("parse decrypted credential: %v", err)
	}
	defer secretbootstrap.Wipe(parsedSecret)
	if got, want := repository.created.Credential.SecretDigest, auth.Digest(pepper, parsedSecret); !equalBytes(got, want) {
		t.Fatal("persisted digest does not match delivered random secret")
	}
	if strings.Contains(delivery.GetCiphertext(), string(plaintext)) {
		t.Fatal("ciphertext contains plaintext service key")
	}

	replayed, err := service.CreateServiceKey(ctx, proto.Clone(request).(*agentv1.CreateServiceKeyRequest))
	if err != nil {
		t.Fatalf("replay CreateServiceKey: %v", err)
	}
	if !proto.Equal(created, replayed) {
		t.Fatal("idempotent replay did not return the original encrypted response")
	}
}

func TestCreateServiceKeyRequiresAuthenticatedPrincipalAndValidRecipient(t *testing.T) {
	service := NewAdminService(&credentialManagerStub{}, []byte("0123456789abcdef0123456789abcdef"))
	request := &agentv1.CreateServiceKeyRequest{
		IdempotencyKey: uuid.NewString(), ClientId: "client", Scopes: []string{"task.read"}, RecipientPublicKey: "invalid",
	}
	if _, err := service.CreateServiceKey(context.Background(), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("missing principal code = %v", status.Code(err))
	}
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{CredentialID: uuid.NewString()})
	if _, err := service.CreateServiceKey(ctx, request); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("invalid recipient code = %v", status.Code(err))
	}
}

func TestApprovalDeviceAdministrationFailsClosedForEveryServiceKeyScope(t *testing.T) {
	service := NewAdminService(&credentialManagerStub{}, []byte("0123456789abcdef0123456789abcdef"))
	for _, scopes := range []map[string]struct{}{
		{"admin": {}},
		{"admin.approval_devices": {}},
		{"cloud.approve": {}},
	} {
		ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{
			CredentialID: uuid.NewString(), ClientID: "message-server", Scopes: scopes,
		})
		if _, err := service.RegisterApprovalDevice(ctx, &agentv1.RegisterApprovalDeviceRequest{}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("RegisterApprovalDevice scopes=%v code=%v", scopes, status.Code(err))
		}
		if _, err := service.RevokeApprovalDevice(ctx, &agentv1.RevokeApprovalDeviceRequest{}); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("RevokeApprovalDevice scopes=%v code=%v", scopes, status.Code(err))
		}
	}
}

type credentialManagerStub struct {
	created auth.CreatedCredential
}

func (*credentialManagerStub) CredentialByKeyID(context.Context, string) (auth.Credential, error) {
	return auth.Credential{}, auth.ErrCredentialNotFound
}

func (*credentialManagerStub) EnsureBootstrapCredential(context.Context, auth.BootstrapCredential) (auth.Credential, error) {
	return auth.Credential{}, nil
}

func (stub *credentialManagerStub) CreateCredential(_ context.Context, command auth.CreateCredentialCommand) (auth.CreatedCredential, error) {
	if stub.created.Credential.CredentialID != "" {
		return stub.created, nil
	}
	stub.created = auth.CreatedCredential{
		Credential: auth.Credential{
			CredentialID: command.CredentialID, KeyID: command.KeyID, ClientID: command.ClientID,
			Scopes: append([]string(nil), command.Scopes...), SecretDigest: append([]byte(nil), command.SecretDigest...),
			Active: true, ExpiresAt: command.ExpiresAt, Revision: 1,
		},
		Delivery: auth.EncryptedDelivery{
			SchemaVersion: command.Delivery.SchemaVersion, ServerPublicKey: command.Delivery.ServerPublicKey,
			Nonce: command.Delivery.Nonce, Ciphertext: command.Delivery.Ciphertext,
			AssociatedData: append([]byte(nil), command.Delivery.AssociatedData...),
		},
	}
	return stub.created, nil
}

func (*credentialManagerStub) RevokeCredential(context.Context, auth.RevokeCredentialCommand) (auth.Credential, error) {
	return auth.Credential{}, nil
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var difference byte
	for index := range left {
		difference |= left[index] ^ right[index]
	}
	return difference == 0
}
