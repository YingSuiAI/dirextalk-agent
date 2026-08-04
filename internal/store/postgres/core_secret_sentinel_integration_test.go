package postgres

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreexecutionv2"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/secretbox"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// TestCoreSecretSentinelAcrossAgentTables is a real PostgreSQL boundary
// sentinel. A single canary is submitted through every secret-bearing Agent
// path that can be exercised without external providers, then every textual,
// JSON, and bytea column in the isolated schema is scanned. A hit means a
// request-local secret crossed a durable/public redaction boundary.
func TestCoreSecretSentinelAcrossAgentTables(t *testing.T) {
	ctx, store, _, cleanup := corePG18Fixture(t)
	defer cleanup()
	const canary = "agent-secret-sentinel-do-not-persist"
	now := time.Now().UTC().Truncate(time.Microsecond)
	profileID := uuid.NewString()
	profile := coremodel.Profile{
		ID: profileID, DisplayName: "sentinel", Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation,
		ProviderConfig: map[string]any{
			"api_key": canary,
			"nested":  map[string]any{"secret_access_key": canary, "safe": "metadata"},
		},
		ProviderSecrets: map[string]string{
			"voice_access_key_id":     canary,
			"voice_secret_access_key": canary,
			"rtc_app_key":             canary,
		},
		BaseURL: "https://example.invalid", Model: "sentinel", APIKey: canary,
		Revision: 1, CreatedAt: now, UpdatedAt: now,
	}
	if _, err := store.CreateProfile(ctx, profile, uuid.NewString(), strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.ResolveProfile(ctx, profileID)
	if err != nil || loaded.APIKey != canary || loaded.ProviderSecrets["rtc_app_key"] != canary {
		t.Fatalf("profile secret rehydrate=%#v err=%v", loaded, err)
	}
	public, err := store.GetProfile(ctx, profileID)
	if err != nil {
		t.Fatal(err)
	}
	if public.ProviderSecretStatus["rtc_app_key"] != true || strings.Contains(fmt.Sprint(public.ProviderConfig), canary) {
		t.Fatalf("profile redaction/status failed: %#v", public)
	}

	conversationStore, err := NewCoreConversationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := coremodel.SnapshotFromProfile(profile)
	requestID := uuid.NewString()
	fingerprint := strings.Repeat("b", 64)
	lease, err := conversationStore.ClaimChat(ctx, requestID, "", fingerprint, profileID, nil, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conversationStore.BindChatProfileSnapshot(ctx, requestID, lease.LeaseID, lease.Epoch, fingerprint, snapshot); err != nil {
		t.Fatal(err)
	}
	turnCommand := core.TurnStartCommand{RequestID: uuid.NewString(), ConversationID: uuid.NewString(), Prompt: "sentinel", ProfileID: profileID, ProfileSnapshot: snapshot}
	if _, err := conversationStore.StartTurn(ctx, turnCommand); err != nil {
		t.Fatal(err)
	}

	executionStore, err := coreexecutionv2.NewPostgresStore(store.Pool(), testSecretKeyring(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := executionStore.SaveSecret(ctx, coreexecutionv2.Secret{
		OwnerID: "sentinel-owner", Ref: uuid.NewString(), Revision: 1, Provider: "openai",
		Purpose: "ai_provider_api_key", Value: canary, BindingDigest: strings.Repeat("c", 64), Status: "active", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	installID, versionID, referenceID := uuid.New(), uuid.New(), uuid.New()
	if _, err := store.Pool().Exec(ctx, `INSERT INTO core_extension_installations(installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,active_version_id,network_grants_json,secret_grants_json,created_at,updated_at) VALUES($1,'{}'::jsonb,'skill','test','sentinel','sentinel','', 'stdio',1,'installed',true,$2,'[]'::jsonb,'[]'::jsonb,$3,$3)`, installID, versionID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool().Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,'{}'::jsonb,$3)`, versionID, installID, now); err != nil {
		t.Fatal(err)
	}
	purpose := "sentinel"
	plaintext := []byte(canary)
	envelope, err := store.sealDurableSecret("core_extension_secret_revisions", installID.String()+"/"+versionID.String()+"/"+referenceID.String()+"/"+purpose, 1, "secret_value", plaintext)
	clearTestBytes(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pool().Exec(ctx, `INSERT INTO core_extension_secret_revisions(revision_id,installation_id,version_id,reference_id,purpose,binding_revision,secret_key_version,secret_value_nonce,secret_value_ciphertext,fingerprint,state) VALUES($1,$2,$3,$4,$5,1,$6,$7,$8,$9,'promoted')`, uuid.New(), installID, versionID, referenceID, purpose, envelope.KeyVersion, envelope.Nonce, envelope.Ciphertext, strings.Repeat("d", 64)); err != nil {
		t.Fatal(err)
	}

	if hits, err := scanAgentColumnsForCanary(ctx, store.Pool(), canary); err != nil {
		t.Fatal(err)
	} else if len(hits) > 0 {
		t.Fatalf("plaintext secret sentinel found in durable columns: %v", hits)
	}
	wrongKey, err := secretbox.New(secretbox.KeyVersionMin, bytes.Repeat([]byte{0x11}, secretbox.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	wrongStore, err := New(store.Pool(), uuid.NewString(), wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wrongStore.ResolveProfile(ctx, profileID); err == nil {
		t.Fatal("wrong master key opened model/provider secrets")
	}
}

func scanAgentColumnsForCanary(ctx context.Context, pool interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}, canary string) ([]string, error) {
	rows, err := pool.Query(ctx, `SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema=current_schema() AND data_type IN ('text','character varying','character','json','jsonb','bytea') ORDER BY table_name,column_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type column struct{ table, name string }
	columns := make([]column, 0)
	for rows.Next() {
		var item column
		var dataType string
		if err := rows.Scan(&item.table, &item.name, &dataType); err != nil {
			return nil, err
		}
		columns = append(columns, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	hits := make([]string, 0)
	for _, item := range columns {
		qualified := pgx.Identifier{item.table}.Sanitize() + "." + pgx.Identifier{item.name}.Sanitize()
		var found bool
		if err := pool.QueryRow(ctx, fmt.Sprintf("SELECT EXISTS (SELECT 1 FROM %s WHERE CAST(%s AS text) LIKE $1)", pgx.Identifier{item.table}.Sanitize(), qualified), "%"+canary+"%").Scan(&found); err != nil {
			return nil, err
		}
		if found {
			hits = append(hits, item.table+"."+item.name)
		}
	}
	return hits, nil
}
