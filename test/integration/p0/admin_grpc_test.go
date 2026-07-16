package p0_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"github.com/YingSuiAI/dirextalk-agent/internal/auth"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbootstrap"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestAdminCreateServiceKeyEncryptedDeliveryReplayAndScope(t *testing.T) {
	harness := newAdminBoundaryHarness(t)
	request := &agentv1.CreateServiceKeyRequest{
		IdempotencyKey: uuid.NewString(), ClientId: "p0-managed-task-client",
		Scopes: []string{"task.write"}, RecipientPublicKey: harness.recipientPublicKey,
	}
	created, serviceKey := harness.createServiceKey(t, harness.callerA, request)
	serviceSecret := strings.SplitN(serviceKey, ".", 2)[1]
	if created.GetDelivery() == nil || created.GetDelivery().GetCiphertext() == "" || created.GetDelivery().GetAssociatedData() == nil {
		t.Fatal("CreateServiceKey did not return an encrypted delivery")
	}
	if strings.Contains(created.String(), serviceKey) || strings.Contains(created.String(), serviceSecret) ||
		strings.Contains(string(created.GetDelivery().GetAssociatedData()), serviceKey) || strings.Contains(string(created.GetDelivery().GetAssociatedData()), serviceSecret) {
		t.Fatal("CreateServiceKey response exposed the plaintext Service Key")
	}
	tampered := proto.Clone(created.GetDelivery()).(*agentv1.ServiceKeyDelivery)
	tampered.AssociatedData = append([]byte(nil), tampered.GetAssociatedData()...)
	tampered.AssociatedData[0] ^= 1
	if plaintext, err := openServiceKeyDelivery(harness.recipientPrivateKey, tampered); err == nil {
		secretbootstrap.Wipe(plaintext)
		t.Fatal("encrypted delivery accepted modified associated data")
	}

	replayed, replayedKey := harness.createServiceKey(t, harness.callerA, request)
	if !proto.Equal(created, replayed) || serviceKey != replayedKey {
		t.Fatal("same caller and idempotency key did not return the exact original encrypted credential")
	}
	if err := invokeTaskWithServiceKey(harness.process.client, serviceKey, "Use the scoped managed Service Key."); err != nil {
		t.Fatalf("new task.write Service Key could not create a task: %v", status.Code(err))
	}

	snapshot := readAdminPersistenceSnapshot(t, harness.database.pool)
	if strings.Contains(snapshot, serviceKey) || strings.Contains(snapshot, serviceSecret) {
		t.Fatal("plaintext Service Key reached PostgreSQL, event, outbox, or idempotency state")
	}
}

func TestAdminCreateServiceKeyIdempotencyIsCallerScoped(t *testing.T) {
	harness := newAdminBoundaryHarness(t)
	sharedIdempotencyKey := uuid.NewString()
	request := &agentv1.CreateServiceKeyRequest{
		IdempotencyKey: sharedIdempotencyKey, ClientId: "p0-caller-scoped-client",
		Scopes: []string{"task.write"}, RecipientPublicKey: harness.recipientPublicKey,
	}
	first, firstKey := harness.createServiceKey(t, harness.callerA, request)
	second, secondKey := harness.createServiceKey(t, harness.callerB, request)
	if first.GetCredentialId() == second.GetCredentialId() || first.GetKeyId() == second.GetKeyId() || firstKey == secondKey {
		t.Fatal("different admin callers sharing a UUID received the same credential")
	}
	if err := invokeTaskWithServiceKey(harness.process.client, firstKey, "Use first caller-scoped credential."); err != nil {
		t.Fatalf("first caller credential was unusable: %v", status.Code(err))
	}
	if err := invokeTaskWithServiceKey(harness.process.client, secondKey, "Use second caller-scoped credential."); err != nil {
		t.Fatalf("second caller credential was unusable: %v", status.Code(err))
	}
}

func TestAdminServiceKeyRotationRevocationAndExpiry(t *testing.T) {
	harness := newAdminBoundaryHarness(t)
	first, firstKey := harness.createServiceKey(t, harness.callerA, &agentv1.CreateServiceKeyRequest{
		IdempotencyKey: uuid.NewString(), ClientId: "p0-rotation-client",
		Scopes: []string{"task.write"}, RecipientPublicKey: harness.recipientPublicKey,
	})
	_, secondKey := harness.createServiceKey(t, harness.callerA, &agentv1.CreateServiceKeyRequest{
		IdempotencyKey: uuid.NewString(), ClientId: "p0-rotation-client",
		Scopes: []string{"task.write"}, RecipientPublicKey: harness.recipientPublicKey,
	})
	if err := invokeTaskWithServiceKey(harness.process.client, firstKey, "Use first overlapping rotation key."); err != nil {
		t.Fatalf("first rotation key was unusable: %v", status.Code(err))
	}
	if err := invokeTaskWithServiceKey(harness.process.client, secondKey, "Use second overlapping rotation key."); err != nil {
		t.Fatalf("second rotation key was unusable: %v", status.Code(err))
	}

	ctx, cancel := rpcContext(harness.callerA.serviceKey, 5*time.Second)
	revoked, err := harness.admin.RevokeServiceKey(ctx, &agentv1.RevokeServiceKeyRequest{
		IdempotencyKey: uuid.NewString(), CredentialId: first.GetCredentialId(), ExpectedRevision: first.GetRevision(),
	})
	cancel()
	if err != nil || revoked.GetActive() || revoked.GetRevision() != first.GetRevision()+1 {
		t.Fatalf("RevokeServiceKey failed: code=%v active=%t revision=%d", status.Code(err), revoked.GetActive(), revoked.GetRevision())
	}
	if err := invokeTaskWithServiceKey(harness.process.client, firstKey, "Rejected revoked rotation key."); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("revoked key code = %v, want Unauthenticated", status.Code(err))
	}
	if err := invokeTaskWithServiceKey(harness.process.client, secondKey, "Use surviving rotation key."); err != nil {
		t.Fatalf("revoking one key broke its overlapping peer: %v", status.Code(err))
	}

	expiresAt := time.Now().UTC().Add(1500 * time.Millisecond)
	_, expiringKey := harness.createServiceKey(t, harness.callerA, &agentv1.CreateServiceKeyRequest{
		IdempotencyKey: uuid.NewString(), ClientId: "p0-expiring-client", Scopes: []string{"task.write"},
		ExpiresAt: timestamppb.New(expiresAt), RecipientPublicKey: harness.recipientPublicKey,
	})
	if err := invokeTaskWithServiceKey(harness.process.client, expiringKey, "Use short-lived key before expiry."); err != nil {
		t.Fatalf("short-lived key was unusable before expiry: %v", status.Code(err))
	}
	if wait := time.Until(expiresAt) + 150*time.Millisecond; wait > 0 {
		time.Sleep(wait)
	}
	if err := invokeTaskWithServiceKey(harness.process.client, expiringKey, "Reject short-lived key after expiry."); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("expired key code = %v, want Unauthenticated", status.Code(err))
	}
}

type adminBoundaryHarness struct {
	database            testDatabase
	process             *runningP0Process
	admin               agentv1.AdminServiceClient
	recipientPrivateKey *ecdh.PrivateKey
	recipientPublicKey  string
	callerA             adminCaller
	callerB             adminCaller
}

type adminCaller struct {
	serviceKey   string
	credentialID string
}

func newAdminBoundaryHarness(t *testing.T) adminBoundaryHarness {
	t.Helper()
	database := newMigratedDatabase(t)
	pepper := sha256.Sum256([]byte("dirextalk-agent-p0-admin-boundary-pepper"))
	callerA := ensureAdminCaller(t, database, pepper[:], "admin-a")
	callerB := ensureAdminCaller(t, database, pepper[:], "admin-b")
	certFile, keyFile, roots := writeTestCertificate(t)
	process := startP0Process(t, database.store, pepper[:], certFile, keyFile, roots)
	recipientPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal("generate recipient X25519 key failed")
	}
	return adminBoundaryHarness{
		database: database, process: process, admin: agentv1.NewAdminServiceClient(process.connection),
		recipientPrivateKey: recipientPrivateKey,
		recipientPublicKey:  base64.RawURLEncoding.EncodeToString(recipientPrivateKey.PublicKey().Bytes()),
		callerA:             callerA, callerB: callerB,
	}
}

func ensureAdminCaller(t *testing.T, database testDatabase, pepper []byte, alias string) adminCaller {
	t.Helper()
	secret := sha256.Sum256([]byte("dirextalk-agent-p0-admin-caller/" + alias + "/" + uuid.NewString()))
	keyID := "p0-admin-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	credential, err := database.store.EnsureBootstrapCredential(ctx, auth.BootstrapCredential{
		KeyID: keyID, ClientID: "p0-" + alias, Scopes: []string{"admin.credentials"},
		SecretDigest: auth.Digest(pepper, secret[:]),
	})
	cancel()
	if err != nil {
		t.Fatalf("create admin bootstrap caller failed (%T)", err)
	}
	return adminCaller{serviceKey: auth.FormatServiceKey(keyID, secret[:]), credentialID: credential.CredentialID}
}

func (h adminBoundaryHarness) createServiceKey(t *testing.T, caller adminCaller, request *agentv1.CreateServiceKeyRequest) (*agentv1.CreateServiceKeyResponse, string) {
	t.Helper()
	ctx, cancel := rpcContext(caller.serviceKey, 5*time.Second)
	response, err := h.admin.CreateServiceKey(ctx, request)
	cancel()
	if err != nil {
		t.Fatalf("CreateServiceKey failed: %v", status.Code(err))
	}
	plaintext, err := openServiceKeyDelivery(h.recipientPrivateKey, response.GetDelivery())
	if err != nil {
		t.Fatal("decrypt Service Key delivery failed")
	}
	serviceKey := string(plaintext)
	secretbootstrap.Wipe(plaintext)
	if !strings.HasPrefix(serviceKey, response.GetKeyId()+".") {
		t.Fatal("decrypted Service Key is not bound to response key_id")
	}
	parts := strings.SplitN(serviceKey, ".", 2)
	secret, decodeErr := base64.RawURLEncoding.DecodeString(parts[1])
	if decodeErr != nil || len(secret) != 32 || base64.RawURLEncoding.EncodeToString(secret) != parts[1] {
		secretbootstrap.Wipe(secret)
		t.Fatal("decrypted Service Key has an invalid secret component")
	}
	secretbootstrap.Wipe(secret)
	return response, serviceKey
}

func openServiceKeyDelivery(recipientPrivateKey *ecdh.PrivateKey, delivery *agentv1.ServiceKeyDelivery) ([]byte, error) {
	if delivery == nil {
		return nil, secretbootstrap.ErrInvalidEnvelope
	}
	return secretbootstrap.OpenRecipientEnvelope(recipientPrivateKey.Bytes(), secretbootstrap.RecipientEnvelopeV1{
		SchemaVersion:   delivery.GetSchemaVersion(),
		ServerPublicKey: delivery.GetServerPublicKey(),
		Nonce:           delivery.GetNonce(),
		Ciphertext:      delivery.GetCiphertext(),
	}, delivery.GetAssociatedData())
}

func invokeTaskWithServiceKey(client agentv1.TaskServiceClient, serviceKey, goal string) error {
	ctx, cancel := rpcContext(serviceKey, 5*time.Second)
	defer cancel()
	_, err := client.CreateTask(ctx, &agentv1.CreateTaskRequest{
		IdempotencyKey: uuid.NewString(), OwnerId: "owner-p0-managed-key", Goal: goal,
		RetentionPolicy: agentv1.RetentionPolicy_RETENTION_POLICY_EPHEMERAL_AUTO_DESTROY,
	})
	return err
}

func readAdminPersistenceSnapshot(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	queries := []string{
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM service_credentials AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM task_events AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM outbox_events AS item`,
		`SELECT COALESCE(string_agg(row_to_json(item)::text, E'\n'), '') FROM idempotency_records AS item`,
	}
	var snapshot strings.Builder
	for _, query := range queries {
		var relation string
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := pool.QueryRow(ctx, query).Scan(&relation)
		cancel()
		if err != nil {
			t.Fatalf("scan Admin persistence relation failed (%T)", err)
		}
		snapshot.WriteString(relation)
		snapshot.WriteByte('\n')
	}
	return snapshot.String()
}
