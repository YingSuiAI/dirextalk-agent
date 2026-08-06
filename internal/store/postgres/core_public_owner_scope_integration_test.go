package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	coreconversation "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/google/uuid"
)

func TestCoreConversationAndModelIdentityIsOwnerGenerationScoped(t *testing.T) {
	ctx, store, _, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	conversations, err := NewCoreConversationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	ownerA := coretask.OwnerScope{OwnerID: "@core-owner-a:example.test", AccountGeneration: 4}
	ownerB := coretask.OwnerScope{OwnerID: "@core-owner-b:example.test", AccountGeneration: 4}
	ownerANext := coretask.OwnerScope{OwnerID: ownerA.OwnerID, AccountGeneration: 5}
	ctxA, err := coretask.WithOwnerScope(ctx, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := coretask.WithOwnerScope(ctx, ownerB)
	if err != nil {
		t.Fatal(err)
	}
	ctxANext, err := coretask.WithOwnerScope(ctx, ownerANext)
	if err != nil {
		t.Fatal(err)
	}

	conversationKey := uuid.NewString()
	createConversation := func(scopedCtx context.Context, title string) coreconversation.ConversationMutationResponse {
		t.Helper()
		conversation := coreconversation.Conversation{ID: uuid.NewString(), Title: title, Revision: 1}
		command := coreconversation.CreateConversationCommand{RequestID: conversationKey, Conversation: conversation, Fingerprint: digestConversationPG(conversation)}
		result, createErr := conversations.CreateConversationMutation(scopedCtx, command)
		if createErr != nil {
			t.Fatalf("create Conversation %s: %v", title, createErr)
		}
		replay, replayErr := conversations.CreateConversationMutation(scopedCtx, command)
		if replayErr != nil || replay.Conversation.ID != result.Conversation.ID || !replay.Replayed {
			t.Fatalf("Conversation replay result=%#v replay=%#v err=%v", result, replay, replayErr)
		}
		return result
	}
	conversationA := createConversation(ctxA, "owner a")
	conversationB := createConversation(ctxB, "owner b")
	conversationANext := createConversation(ctxANext, "owner a next generation")
	if conversationA.Conversation.ID == conversationB.Conversation.ID || conversationA.Conversation.ID == conversationANext.Conversation.ID {
		t.Fatal("Conversation replay crossed owner scope")
	}
	if _, err = conversations.LoadConversation(ctxB, conversationA.Conversation.ID); !errors.Is(err, coreconversation.ErrConflict) {
		t.Fatalf("foreign Conversation read err=%v", err)
	}
	listB, _, err := conversations.ListConversations(ctxB, "", 50)
	if err != nil || len(listB) != 1 || listB[0].ID != conversationB.Conversation.ID {
		t.Fatalf("owner B Conversation list=%#v err=%v", listB, err)
	}

	modelKey := uuid.NewString()
	createModel := func(scopedCtx context.Context, name string) coremodel.MutationSnapshot {
		t.Helper()
		now := time.Now().UTC().Truncate(time.Microsecond)
		profile := coremodel.Profile{
			ID: uuid.NewString(), ClientProfileID: "shared-client-profile", DisplayName: name,
			Provider: coremodel.ProviderOpenAICompatible, ModelKind: coremodel.ModelKindConversation,
			BaseURL: "https://example.test/v1", Model: "fixture-model", APIKey: "fixture-secret",
			Revision: 1, CredentialVersion: 1, CreatedAt: now, UpdatedAt: now,
		}
		digest := sha256hexPG([]byte(name))
		result, createErr := store.CreateProfile(scopedCtx, profile, modelKey, digest)
		if createErr != nil {
			t.Fatalf("create Model %s: %v", name, createErr)
		}
		replay, replayErr := store.CreateProfile(scopedCtx, profile, modelKey, digest)
		if replayErr != nil || replay.Profile.ID != result.Profile.ID || !replay.Replay {
			t.Fatalf("Model replay result=%#v replay=%#v err=%v", result, replay, replayErr)
		}
		return result
	}
	modelA := createModel(ctxA, "owner a model")
	modelB := createModel(ctxB, "owner b model")
	modelANext := createModel(ctxANext, "owner a next model")
	if modelA.Profile.ID == modelB.Profile.ID || modelA.Profile.ID == modelANext.Profile.ID {
		t.Fatal("Model replay crossed owner scope")
	}
	if _, err = store.GetProfile(ctxB, modelA.Profile.ID); !errors.Is(err, coremodel.ErrProfileNotFound) {
		t.Fatalf("foreign Model read err=%v", err)
	}
	modelsB, _, err := store.ListProfiles(ctxB, "", 50)
	if err != nil || len(modelsB) != 1 || modelsB[0].ID != modelB.Profile.ID {
		t.Fatalf("owner B Model list=%#v err=%v", modelsB, err)
	}
}

func TestCoreChatRequestIdentityAndCompletionAreOwnerGenerationScoped(t *testing.T) {
	ctx, store, _, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	conversations, err := NewCoreConversationStore(store)
	if err != nil {
		t.Fatal(err)
	}
	ownerA := coretask.OwnerScope{OwnerID: "@chat-owner-a:example.test", AccountGeneration: 4}
	ownerB := coretask.OwnerScope{OwnerID: "@chat-owner-b:example.test", AccountGeneration: 9}
	ctxA, err := coretask.WithOwnerScope(ctx, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := coretask.WithOwnerScope(ctx, ownerB)
	if err != nil {
		t.Fatal(err)
	}

	requestID := uuid.NewString()
	conversationA, conversationB := uuid.NewString(), uuid.NewString()
	profileA, profileB := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC().Truncate(time.Microsecond)
	leaseA, err := conversations.ClaimChat(ctxA, requestID, conversationA, sha256hexPG([]byte("owner-a-chat")), profileA, nil, now, time.Minute)
	if err != nil || leaseA.Status != coreconversation.ClaimNew {
		t.Fatalf("owner A claim=%#v err=%v", leaseA, err)
	}
	leaseB, err := conversations.ClaimChat(ctxB, requestID, conversationB, sha256hexPG([]byte("owner-b-chat")), profileB, nil, now, time.Minute)
	if err != nil || leaseB.Status != coreconversation.ClaimNew {
		t.Fatalf("owner B claim=%#v err=%v", leaseB, err)
	}
	if leaseA.RequestID != requestID || leaseB.RequestID != requestID {
		t.Fatalf("public request identity changed: ownerA=%s ownerB=%s", leaseA.RequestID, leaseB.RequestID)
	}

	var requestRows, distinctStorageIDs int
	if err = store.pool.QueryRow(ctx, `SELECT count(*),count(DISTINCT request_id) FROM core_chat_request_leases WHERE idempotency_key=$1`, requestID).Scan(&requestRows, &distinctStorageIDs); err != nil {
		t.Fatal(err)
	}
	if requestRows != 2 || distinctStorageIDs != 2 {
		t.Fatalf("owner-scoped chat rows=%d distinct storage IDs=%d", requestRows, distinctStorageIDs)
	}

	snapshotA := coremodel.ExecutionSnapshot{
		ProfileID: profileA, Revision: 1, CredentialVersion: 1,
		Provider: coremodel.ProviderOpenAICompatible, BaseURL: "https://example.test/v1",
		Model: "fixture-model", APIKey: "fixture-secret",
	}
	leaseA, err = conversations.BindChatProfileSnapshot(ctxA, requestID, leaseA.LeaseID, leaseA.Epoch, sha256hexPG([]byte("owner-a-chat")), snapshotA)
	if err != nil {
		t.Fatal(err)
	}
	snapshotB := snapshotA
	snapshotB.ProfileID = profileB
	leaseB, err = conversations.BindChatProfileSnapshot(ctxB, requestID, leaseB.LeaseID, leaseB.Epoch, sha256hexPG([]byte("owner-b-chat")), snapshotB)
	if err != nil {
		t.Fatal(err)
	}
	var nonceA, ciphertextA, nonceB, ciphertextB []byte
	if err = store.pool.QueryRow(ctx, `SELECT profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext FROM core_chat_request_leases WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, ownerA.OwnerID, ownerA.AccountGeneration, requestID).Scan(&nonceA, &ciphertextA); err != nil {
		t.Fatal(err)
	}
	if err = store.pool.QueryRow(ctx, `SELECT profile_snapshot_api_key_nonce,profile_snapshot_api_key_ciphertext FROM core_chat_request_leases WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, ownerB.OwnerID, ownerB.AccountGeneration, requestID).Scan(&nonceB, &ciphertextB); err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_chat_request_leases SET profile_snapshot_api_key_nonce=$4,profile_snapshot_api_key_ciphertext=$5 WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, ownerB.OwnerID, ownerB.AccountGeneration, requestID, nonceA, ciphertextA); err != nil {
		t.Fatal(err)
	}
	if _, err = conversations.ClaimChat(ctxB, requestID, conversationB, sha256hexPG([]byte("owner-b-chat")), profileB, nil, now, time.Minute); !errors.Is(err, coreconversation.ErrConflict) {
		t.Fatalf("cross-owner snapshot ciphertext swap err=%v, want conflict", err)
	}
	if _, err = store.pool.Exec(ctx, `UPDATE core_chat_request_leases SET profile_snapshot_api_key_nonce=$4,profile_snapshot_api_key_ciphertext=$5 WHERE owner_id=$1 AND account_generation=$2 AND idempotency_key=$3`, ownerB.OwnerID, ownerB.AccountGeneration, requestID, nonceB, ciphertextB); err != nil {
		t.Fatal(err)
	}
	conversation := coreconversation.Conversation{ID: conversationB, Title: "owner B chat", Revision: 1, CreatedAt: now, UpdatedAt: now}
	response := coreconversation.ChatResponse{RequestID: requestID, ConversationID: conversationB, Revision: 1, Done: true, ModelProfileID: profileB}
	if _, err = conversations.CommitChatCompletion(ctxB, coreconversation.AtomicCompletion{
		RequestID: requestID, LeaseID: leaseB.LeaseID, Epoch: leaseB.Epoch,
		Fingerprint: sha256hexPG([]byte("owner-b-chat")), ExpectedRevision: 1,
		Conversation: conversation, Response: response,
	}); err != nil {
		t.Fatalf("owner B completion: %v", err)
	}
	var persistedOwner string
	var persistedGeneration int64
	if err = store.pool.QueryRow(ctx, `SELECT owner_id,account_generation FROM core_conversations WHERE conversation_id=$1`, conversationB).Scan(&persistedOwner, &persistedGeneration); err != nil {
		t.Fatal(err)
	}
	if persistedOwner != ownerB.OwnerID || persistedGeneration != ownerB.AccountGeneration {
		t.Fatalf("completed Conversation scope=(%s,%d), want=(%s,%d)", persistedOwner, persistedGeneration, ownerB.OwnerID, ownerB.AccountGeneration)
	}
}

func TestCoreTaskSnapshotRejectsForeignOwnerResources(t *testing.T) {
	ctx, store, _, closeFixture := coreTaskScheduleFixture(t)
	defer closeFixture()
	ownerA := coretask.OwnerScope{OwnerID: "@task-resource-owner-a:example.test", AccountGeneration: 4}
	ownerB := coretask.OwnerScope{OwnerID: "@task-resource-owner-b:example.test", AccountGeneration: 7}
	ctxA, err := coretask.WithOwnerScope(ctx, ownerA)
	if err != nil {
		t.Fatal(err)
	}
	ctxB, err := coretask.WithOwnerScope(ctx, ownerB)
	if err != nil {
		t.Fatal(err)
	}
	profileA, profileB := uuid.NewString(), uuid.NewString()
	createTestProfile(ctxA, t, store, profileA, "foreign-owner-model", "owner-a-secret")
	createTestProfile(ctxB, t, store, profileB, "task-owner-model", "owner-b-secret")

	now := time.Now().UTC().Truncate(time.Microsecond)
	extensionID, versionID := uuid.NewString(), uuid.NewString()
	contentDigest, artifactDigest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if _, err = store.pool.Exec(ctx, `INSERT INTO core_extension_installations(
		installation_id,candidate_json,kind,source,candidate_id,name,description,transport,revision,state,enabled,
		active_version_id,network_grants_json,secret_grants_json,created_at,updated_at,owner_id,account_generation
	) VALUES($1,'{}','mcp','official_registry','foreign-extension','foreign extension','','stdio_static',1,'installed',true,$2,'[]','[]',$3,$3,$4,$5)`,
		extensionID, versionID, now, ownerA.OwnerID, ownerA.AccountGeneration); err != nil {
		t.Fatal(err)
	}
	if _, err = store.pool.Exec(ctx, `INSERT INTO core_extension_versions(version_id,installation_id,version_json,created_at) VALUES($1,$2,$3,$4)`,
		versionID, extensionID, []byte(`{"version":"1.0.0","content_digest":"`+contentDigest+`","artifact_digest":"`+artifactDigest+`"}`), now); err != nil {
		t.Fatal(err)
	}

	sourceID := uuid.NewString()
	if _, err = store.pool.Exec(ctx, `INSERT INTO core_knowledge_sources(
		source_id,kind,status,title,relative_path,digest,size_bytes,media_type,revision,content_ref,
		directory_manifest_digest,promoted_generation,promoted_revision,promoted_profile_id,promoted_profile_revision,
		promoted_collection_config_digest,created_at,updated_at,owner_id,account_generation
	) VALUES($1,'upload','ready','foreign source','foreign.txt',$2,1,'text/plain',1,'foreign-ref',$3,'generation-1',1,$4,1,$5,$6,$6,$7,$8)`,
		sourceID, strings.Repeat("c", 64), strings.Repeat("d", 64), profileB, strings.Repeat("e", 64), now, ownerA.OwnerID, ownerA.AccountGeneration); err != nil {
		t.Fatal(err)
	}

	tasks := NewCoreTaskStore(store)
	assertRejected := func(name string, spec coretask.TaskSpec) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			spec.IdempotencyKey = uuid.NewString()
			digest, digestErr := spec.MutationDigest()
			if digestErr != nil {
				t.Fatal(digestErr)
			}
			_, createErr := tasks.CreateTask(ctxB, coretask.CreateTaskCommand{Spec: spec, Mutation: coretask.MutationCommand{IdempotencyKey: spec.IdempotencyKey, RequestDigest: digest}})
			if !errors.Is(createErr, coretask.ErrNotFound) {
				t.Fatalf("foreign resource Task creation err=%v, want not found", createErr)
			}
		})
	}
	assertRejected("model", coretask.TaskSpec{Goal: "foreign model", ModelProfileID: profileA})
	assertRejected("extension", coretask.TaskSpec{
		Goal: "foreign extension", ModelProfileID: profileB,
		Extensions: []coretask.ExtensionSelection{{Kind: coretask.ExtensionMCP, ID: extensionID, Version: "1.0.0", Digest: contentDigest}},
	})
	assertRejected("knowledge", coretask.TaskSpec{Goal: "foreign knowledge", ModelProfileID: profileB, KnowledgeRefs: []string{sourceID}})
	assertRejected("attachment", coretask.TaskSpec{Goal: "foreign attachment", ModelProfileID: profileB, AttachmentRefs: []string{sourceID}})

	var leakedTasks int
	if err = store.pool.QueryRow(ctx, `SELECT count(*) FROM core_task_scopes WHERE owner_id=$1 AND account_generation=$2`, ownerB.OwnerID, ownerB.AccountGeneration).Scan(&leakedTasks); err != nil {
		t.Fatal(err)
	}
	if leakedTasks != 0 {
		t.Fatalf("rejected foreign-resource requests left %d durable Tasks", leakedTasks)
	}
}
