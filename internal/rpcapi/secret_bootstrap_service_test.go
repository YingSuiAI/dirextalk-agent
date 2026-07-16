package rpcapi

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type secretBootstrapManagerStub struct {
	created          secretbootstrap.CreateResult
	createdScope     secretbootstrap.MutationScope
	createdKey       string
	createdBind      secretbootstrap.BindingV1
	uploadedSession  secretbootstrap.SessionV1
	uploadedScope    secretbootstrap.MutationScope
	uploadedToken    string
	uploadedEnvelope secretbootstrap.EnvelopeV1
	getClientID      string
	allowedClientID  string
}

func (stub *secretBootstrapManagerStub) CreateIdempotent(_ context.Context, scope secretbootstrap.MutationScope, key string, binding secretbootstrap.BindingV1) (secretbootstrap.CreateResult, error) {
	stub.createdScope, stub.createdKey, stub.createdBind = scope, key, binding
	return stub.created, nil
}

func (stub *secretBootstrapManagerStub) Get(_ context.Context, clientID, _ string) (secretbootstrap.SessionV1, error) {
	stub.getClientID = clientID
	if stub.allowedClientID != "" && clientID != stub.allowedClientID {
		return secretbootstrap.SessionV1{}, secretbootstrap.ErrCallerMismatch
	}
	return stub.created.Session, nil
}

func (stub *secretBootstrapManagerStub) UploadIdempotent(_ context.Context, scope secretbootstrap.MutationScope, _ string, _ string, _ uint64, token string, envelope secretbootstrap.EnvelopeV1) (secretbootstrap.SessionV1, error) {
	stub.uploadedScope, stub.uploadedToken, stub.uploadedEnvelope = scope, token, envelope
	return stub.uploadedSession, nil
}

func TestSecretBootstrapServiceBindsCallerAndReturnsRawTransportValues(t *testing.T) {
	now := time.Date(2026, time.July, 16, 10, 0, 0, 0, time.UTC)
	publicKey := make([]byte, 32)
	for index := range publicKey {
		publicKey[index] = byte(index + 1)
	}
	uploadToken := bootstrapTokenForTest(bytesForBootstrapTest(0xa5))
	rawUploadToken, _ := base64.RawURLEncoding.DecodeString(uploadToken.Reveal())
	stub := &secretBootstrapManagerStub{created: secretbootstrap.CreateResult{
		Session: secretbootstrap.SessionV1{
			SchemaVersion: secretbootstrap.SessionSchemaV1, SessionID: uuid.NewString(),
			AgentInstanceID: uuid.NewString(), OwnerID: "owner-a", Purpose: "aws_connection", TargetID: uuid.NewString(),
			ServerPublicKey: base64.RawURLEncoding.EncodeToString(publicKey), CreatedAt: now,
			ExpiresAt: now.Add(secretbootstrap.SessionTTL), Status: secretbootstrap.StatusAwaitingUpload, Revision: 1,
		},
		UploadToken: uploadToken,
	}}
	service := NewSecretBootstrapService(stub, stub.created.Session.AgentInstanceID)
	request := &agentv1.CreateSessionRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "owner-a", Purpose: "aws_connection", TargetId: stub.created.Session.TargetID,
	}
	if _, err := service.CreateSession(context.Background(), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated CreateSession code=%v", status.Code(err))
	}
	credentialID := uuid.NewString()
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: credentialID})
	response, err := service.CreateSession(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if string(response.GetServerPublicKey()) != string(publicKey) || string(response.GetUploadToken()) != string(rawUploadToken) {
		t.Fatal("CreateSession did not return raw X25519/token bytes")
	}
	if stub.createdScope.ClientID != "message-server" || stub.createdScope.CredentialID != credentialID || stub.createdKey != request.IdempotencyKey {
		t.Fatalf("mutation scope was not bound: %#v", stub.createdScope)
	}
	if stub.createdBind.AgentInstanceID != stub.created.Session.AgentInstanceID || stub.createdBind.TargetID != request.TargetId {
		t.Fatalf("session binding was not server-owned: %#v", stub.createdBind)
	}
	if _, err := service.GetSession(ctx, &agentv1.SecretBootstrapServiceGetSessionRequest{SessionId: stub.created.Session.SessionID}); err != nil || stub.getClientID != "message-server" {
		t.Fatalf("GetSession caller binding=%q err=%v", stub.getClientID, err)
	}
}

func TestSecretBootstrapServiceEncodesEncryptedUploadWithoutPlaintext(t *testing.T) {
	stub := &secretBootstrapManagerStub{uploadedSession: secretbootstrap.SessionV1{
		SchemaVersion: secretbootstrap.SessionSchemaV1, SessionID: uuid.NewString(), Status: secretbootstrap.StatusUploaded, Revision: 2,
	}}
	service := NewSecretBootstrapService(stub, uuid.NewString())
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{ClientID: "message-server", CredentialID: uuid.NewString()})
	token, clientKey, nonce, ciphertext := make([]byte, 32), make([]byte, 32), make([]byte, 12), make([]byte, 48)
	request := &agentv1.UploadEncryptedRequest{
		SessionId: stub.uploadedSession.SessionID, UploadToken: token, ClientPublicKey: clientKey,
		Nonce: nonce, Ciphertext: ciphertext, IdempotencyKey: uuid.NewString(), ExpectedRevision: 1,
	}
	response, err := service.UploadEncrypted(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.GetRevision() != 2 || stub.uploadedToken != base64.RawURLEncoding.EncodeToString(token) {
		t.Fatalf("unexpected upload response/token encoding: %#v", response)
	}
	if stub.uploadedEnvelope.SchemaVersion != secretbootstrap.EnvelopeSchemaV1 || stub.uploadedEnvelope.SessionID != request.SessionId ||
		stub.uploadedEnvelope.Ciphertext != base64.RawURLEncoding.EncodeToString(ciphertext) {
		t.Fatalf("encrypted envelope was not normalized: %#v", stub.uploadedEnvelope)
	}
}

func TestSecretBootstrapCompleteRemainsReservedAndUnimplemented(t *testing.T) {
	stub := &secretBootstrapManagerStub{}
	service := NewSecretBootstrapService(stub, uuid.NewString())
	request := &agentv1.CompleteRequest{
		SessionId: uuid.NewString(), IdempotencyKey: uuid.NewString(), ExpectedRevision: 2,
	}
	if _, err := service.Complete(context.Background(), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated Complete code=%v", status.Code(err))
	}
	ctx := auth.ContextWithPrincipal(context.Background(), auth.Principal{
		ClientID: "message-server", CredentialID: uuid.NewString(), Scopes: map[string]struct{}{"admin": {}},
	})
	_, err := service.Complete(ctx, request)
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("Complete code=%v, want %v", status.Code(err), codes.Unimplemented)
	}
	if stub.getClientID != "" {
		t.Fatal("reserved Complete performed a session lookup")
	}
}

func bootstrapTokenForTest(raw []byte) secretbootstrap.UploadToken {
	store := secretbootstrap.NewMemoryStore()
	keys := secretbootstrap.NewMemoryKeyStore()
	manager, _ := secretbootstrap.NewManager(store, keys, &fixedBootstrapRandom{value: raw}, func() time.Time { return time.Now().UTC() })
	created, _ := manager.Create(context.Background(), "rpcapi-test", secretbootstrap.BindingV1{
		AgentInstanceID: uuid.NewString(), OwnerID: "test", Purpose: "test", TargetID: uuid.NewString(),
	})
	return created.UploadToken
}

type fixedBootstrapRandom struct{ value []byte }

func (random *fixedBootstrapRandom) Read(target []byte) (int, error) {
	for index := range target {
		target[index] = random.value[index%len(random.value)]
	}
	return len(target), nil
}

func bytesForBootstrapTest(value byte) []byte {
	result := make([]byte, 32)
	for index := range result {
		result[index] = value + byte(index)
	}
	return result
}
