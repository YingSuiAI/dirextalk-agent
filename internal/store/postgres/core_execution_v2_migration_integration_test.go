package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestCoreExecutionV2LegacySecretMigrationDecryptsOnlyRecoveredGeneration(t *testing.T) {
	ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_execution_v2_secret_aad_")
	keyring := testSecretKeyring(t)
	scope := coretask.OwnerScope{OwnerID: "@legacy-secret-owner:example.test", AccountGeneration: 11}
	secretRef, value := seedLegacyExecutionV2Secret(t, ctx, pool, keyring, scope, nil)

	if err := ApplyMigrations(ctx, pool, instanceID); err != nil {
		t.Fatalf("migrate authentic legacy secret: %v", err)
	}
	store, err := coreexecutionv2.NewPostgresStore(pool, keyring)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := store.ReadSecret(ctx, scope, secretRef, 0)
	if err != nil || secret.Value != value || secret.AccountGeneration != scope.AccountGeneration {
		t.Fatalf("recovered secret=%+v err=%v", secret, err)
	}
	wrongScope := scope
	wrongScope.AccountGeneration++
	if _, err = store.ReadSecret(ctx, wrongScope, secretRef, 0); !errors.Is(err, coreexecutionv2.ErrSecretNotFound) {
		t.Fatalf("wrong generation read err=%v", err)
	}
}

func TestCoreExecutionV2LegacySecretMigrationRejectsMalformedProvenanceAtomically(t *testing.T) {
	tests := []struct {
		name       string
		generation int64
		mutate     func(map[string]any)
		conflict   bool
	}{
		{name: "missing immutable field", generation: 11, mutate: func(secret map[string]any) { delete(secret, "provider") }},
		{name: "mismatched immutable field", generation: 11, mutate: func(secret map[string]any) { secret["binding_digest"] = strings.Repeat("0", 64) }},
		{name: "missing account generation", generation: 0},
		{name: "conflicting account generations", generation: 11, conflict: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx, pool, instanceID := legacyV2MigrationFixture(t, "dtx_agent_execution_v2_secret_bad_")
			keyring := testSecretKeyring(t)
			scope := coretask.OwnerScope{OwnerID: "@legacy-secret-owner:example.test", AccountGeneration: tc.generation}
			secretRef, _ := seedLegacyExecutionV2Secret(t, ctx, pool, keyring, scope, tc.mutate)
			if tc.conflict {
				result := legacyExecutionV2SecretResult(t, pool, ctx, secretRef)
				insertLegacyExecutionV2SecretOperation(t, ctx, pool, scope.OwnerID, scope.AccountGeneration+1, result)
			}

			err := ApplyMigrations(ctx, pool, instanceID)
			if err == nil || !strings.Contains(err.Error(), "unrecoverable legacy ExecutionV2 secret account generation") {
				t.Fatalf("malformed legacy secret migration err=%v", err)
			}
			assertLegacyV4MigrationRolledBack(t, ctx, pool, "core_execution_v2_secrets", "account_generation")
		})
	}
}

func seedLegacyExecutionV2Secret(t *testing.T, ctx context.Context, pool *pgxpool.Pool, keyring *secretbox.Keyring, scope coretask.OwnerScope, mutate func(map[string]any)) (string, string) {
	t.Helper()
	secretRef := uuid.NewString()
	value := "legacy-execution-v2-secret"
	now := time.Date(2035, 2, 3, 4, 5, 6, 789000000, time.UTC)
	binding := sha256.Sum256([]byte(value))
	aad, err := secretbox.BindAAD("core_execution_v2_secrets", scope.OwnerID+"/"+secretRef, 1, "secret_value")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := keyring.Seal([]byte(value), aad)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO core_execution_v2_secrets(owner_id,secret_ref,revision,provider,purpose,secret_key_version,secret_value_nonce,secret_value_ciphertext,binding_digest,status,created_at,updated_at) VALUES($1,$2,1,'openai','ai_provider_api_key',$3,$4,$5,$6,'active',$7,$7)`, scope.OwnerID, secretRef, envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext, hex.EncodeToString(binding[:]), now); err != nil {
		t.Fatal(err)
	}
	result := map[string]any{
		"secret_ref":     secretRef,
		"revision":       uint64(1),
		"provider":       "openai",
		"purpose":        "ai_provider_api_key",
		"binding_digest": hex.EncodeToString(binding[:]),
		"status":         "active",
		"created_at":     now.Format(time.RFC3339Nano),
		"updated_at":     now.Format(time.RFC3339Nano),
	}
	if mutate != nil {
		mutate(result)
	}
	raw, err := json.Marshal(map[string]any{"secret": result})
	if err != nil {
		t.Fatal(err)
	}
	insertLegacyExecutionV2SecretOperation(t, ctx, pool, scope.OwnerID, scope.AccountGeneration, raw)
	return secretRef, value
}

func insertLegacyExecutionV2SecretOperation(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ownerID string, generation int64, result []byte) {
	t.Helper()
	if _, err := pool.Exec(ctx, `INSERT INTO agent_capability_operations(operation_id,capability_id,operation_name,state,root_request_digest,request_digest,result_json,owner_id,account_generation,completed_at) VALUES($1,'agent.execution.v2','secrets_create','completed',$2,$2,$3,$4,$5,$6)`, uuid.NewString(), make([]byte, 32), result, ownerID, generation, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
}

func legacyExecutionV2SecretResult(t *testing.T, pool *pgxpool.Pool, ctx context.Context, secretRef string) []byte {
	t.Helper()
	var provider, purpose, bindingDigest, status string
	var revision uint64
	var createdAt time.Time
	if err := pool.QueryRow(ctx, `SELECT revision,provider,purpose,binding_digest,status,created_at FROM core_execution_v2_secrets WHERE secret_ref=$1`, secretRef).Scan(&revision, &provider, &purpose, &bindingDigest, &status, &createdAt); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(map[string]any{"secret": map[string]any{
		"secret_ref": secretRef, "revision": revision, "provider": provider, "purpose": purpose,
		"binding_digest": bindingDigest, "status": status,
		"created_at": createdAt.UTC().Format(time.RFC3339Nano), "updated_at": createdAt.UTC().Format(time.RFC3339Nano),
	}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
