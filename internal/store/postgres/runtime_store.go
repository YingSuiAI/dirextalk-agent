package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	modelapi "github.com/YingSuiAI/dirextalk-agent/internal/model"
	runtimeapi "github.com/YingSuiAI/dirextalk-agent/internal/runtime"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const runtimeConfigSnapshotSchemaV1 = 1

type runtimeConfigSnapshot struct {
	SchemaVersion int                      `json:"schema_version"`
	Config        runtimeapi.RuntimeConfig `json:"config"`
}

func (store *Store) SaveRuntimeConfig(ctx context.Context, scope runtimeapi.MutationScope, command runtimeapi.SaveRuntimeConfigCommand) (runtimeapi.RuntimeConfig, error) {
	if err := scope.Validate(); err != nil {
		return runtimeapi.RuntimeConfig{}, err
	}
	validated, err := command.Validated()
	if err != nil {
		return runtimeapi.RuntimeConfig{}, err
	}
	digest, err := validated.Digest()
	if err != nil {
		return runtimeapi.RuntimeConfig{}, err
	}
	credentialID, _ := uuid.Parse(scope.CredentialID)
	caller := idempotencyCaller{ClientID: strings.TrimSpace(scope.ClientID), CredentialID: credentialID}
	aggregateID, err := uuid.NewV7()
	if err != nil {
		return runtimeapi.RuntimeConfig{}, fmt.Errorf("generate runtime config aggregate id: %w", err)
	}
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return runtimeapi.RuntimeConfig{}, fmt.Errorf("begin save runtime config: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	existing, _, responseJSON, err := claimScopedIdempotency(ctx, tx, caller, "runtime.config.save", validated.IdempotencyKey, digest[:], aggregateID)
	if err != nil {
		return runtimeapi.RuntimeConfig{}, err
	}
	if existing {
		config, decodeErr := decodeRuntimeConfigSnapshot(responseJSON)
		if decodeErr != nil {
			return runtimeapi.RuntimeConfig{}, decodeErr
		}
		if err := tx.Commit(ctx); err != nil {
			return runtimeapi.RuntimeConfig{}, fmt.Errorf("commit idempotent runtime config replay: %w", err)
		}
		return config, nil
	}

	config := validated.Config
	if validated.ExpectedRevision == 0 {
		err = scanRuntimeConfig(tx.QueryRow(ctx, `
			INSERT INTO runtime_configs (
			    owner_id, profile_id, model_provider, model_name, base_url, secret_ref, temperature, top_p,
			    max_output_tokens, context_window, reasoning_effort, allow_insecure_http,
			    project_profile, context_message_limit, memory_message_limit, max_steps,
			    memory_disabled, enabled_tools, knowledge_refs, mcp_server_ids, recipe_ids)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21)
			ON CONFLICT (owner_id) DO NOTHING
			RETURNING profile_id, model_provider, model_name, base_url, secret_ref, temperature, top_p,
			          max_output_tokens, context_window, reasoning_effort, allow_insecure_http,
			          project_profile, context_message_limit, memory_message_limit, max_steps,
			          memory_disabled, enabled_tools, knowledge_refs, mcp_server_ids, recipe_ids, revision`, runtimeConfigArguments(validated.OwnerID, config)...), &config)
	} else {
		arguments := runtimeConfigArguments(validated.OwnerID, config)
		arguments = append(arguments, validated.ExpectedRevision)
		err = scanRuntimeConfig(tx.QueryRow(ctx, `
			UPDATE runtime_configs SET
			    profile_id=$2, model_provider=$3, model_name=$4, base_url=$5, secret_ref=$6, temperature=$7, top_p=$8,
			    max_output_tokens=$9, context_window=$10, reasoning_effort=$11, allow_insecure_http=$12,
			    project_profile=$13, context_message_limit=$14, memory_message_limit=$15, max_steps=$16,
			    memory_disabled=$17, enabled_tools=$18, knowledge_refs=$19, mcp_server_ids=$20,
			    recipe_ids=$21, revision=revision+1, updated_at=clock_timestamp()
			WHERE owner_id=$1 AND revision=$22
			RETURNING profile_id, model_provider, model_name, base_url, secret_ref, temperature, top_p,
			          max_output_tokens, context_window, reasoning_effort, allow_insecure_http,
			          project_profile, context_message_limit, memory_message_limit, max_steps,
			          memory_disabled, enabled_tools, knowledge_refs, mcp_server_ids, recipe_ids, revision`, arguments...), &config)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return runtimeapi.RuntimeConfig{}, runtimeapi.ErrRuntimeRevisionConflict
	}
	if err != nil {
		return runtimeapi.RuntimeConfig{}, fmt.Errorf("persist runtime config: %w", err)
	}
	if err := setScopedIdempotencyResponse(ctx, tx, caller, "runtime.config.save", validated.IdempotencyKey, runtimeConfigSnapshot{
		SchemaVersion: runtimeConfigSnapshotSchemaV1,
		Config:        config,
	}); err != nil {
		return runtimeapi.RuntimeConfig{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return runtimeapi.RuntimeConfig{}, fmt.Errorf("commit runtime config: %w", err)
	}
	return config, nil
}

func (store *Store) LoadRuntimeConfig(ctx context.Context, ownerID string) (runtimeapi.RuntimeConfig, error) {
	ownerID = strings.TrimSpace(ownerID)
	var config runtimeapi.RuntimeConfig
	err := scanRuntimeConfig(store.pool.QueryRow(ctx, `
		SELECT profile_id, model_provider, model_name, base_url, secret_ref, temperature, top_p,
		       max_output_tokens, context_window, reasoning_effort, allow_insecure_http,
		       project_profile, context_message_limit, memory_message_limit, max_steps,
		       memory_disabled, enabled_tools, knowledge_refs, mcp_server_ids, recipe_ids, revision
		FROM runtime_configs WHERE owner_id=$1`, ownerID), &config)
	if errors.Is(err, pgx.ErrNoRows) {
		return runtimeapi.RuntimeConfig{}, runtimeapi.ErrRuntimeConfigNotFound
	}
	if err != nil {
		return runtimeapi.RuntimeConfig{}, fmt.Errorf("load runtime config: %w", err)
	}
	if err := runtimeapi.ValidateRuntimeConfig(config); err != nil {
		return runtimeapi.RuntimeConfig{}, fmt.Errorf("stored runtime config is invalid: %w", err)
	}
	return config, nil
}

func runtimeConfigArguments(ownerID string, config runtimeapi.RuntimeConfig) []any {
	profile := config.ModelProfile
	return []any{
		ownerID, profile.ProfileID, profile.Provider, profile.Model, profile.BaseURL, profile.SecretRef, profile.Temperature, profile.TopP,
		profile.MaxOutputTokens, profile.ContextWindow, profile.ReasoningEffort, profile.AllowInsecureHTTP,
		config.ProjectProfile, config.ContextMessageLimit, config.MemoryMessageLimit, config.MaxSteps,
		config.MemoryDisabled, config.EnabledTools, config.KnowledgeRefs, config.MCPServerIDs, config.RecipeIDs,
	}
}

type runtimeConfigScanner interface{ Scan(...any) error }

func scanRuntimeConfig(scanner runtimeConfigScanner, config *runtimeapi.RuntimeConfig) error {
	return scanner.Scan(
		&config.ModelProfile.ProfileID, &config.ModelProfile.Provider, &config.ModelProfile.Model, &config.ModelProfile.BaseURL,
		&config.ModelProfile.SecretRef, &config.ModelProfile.Temperature, &config.ModelProfile.TopP,
		&config.ModelProfile.MaxOutputTokens, &config.ModelProfile.ContextWindow,
		&config.ModelProfile.ReasoningEffort, &config.ModelProfile.AllowInsecureHTTP,
		&config.ProjectProfile, &config.ContextMessageLimit, &config.MemoryMessageLimit, &config.MaxSteps,
		&config.MemoryDisabled, &config.EnabledTools, &config.KnowledgeRefs, &config.MCPServerIDs, &config.RecipeIDs, &config.Revision,
	)
}

func decodeRuntimeConfigSnapshot(encoded []byte) (runtimeapi.RuntimeConfig, error) {
	var snapshot runtimeConfigSnapshot
	if err := json.Unmarshal(encoded, &snapshot); err != nil || snapshot.SchemaVersion != runtimeConfigSnapshotSchemaV1 {
		return runtimeapi.RuntimeConfig{}, errors.New("invalid runtime config idempotency snapshot")
	}
	if err := runtimeapi.ValidateRuntimeConfig(snapshot.Config); err != nil {
		return runtimeapi.RuntimeConfig{}, errors.New("invalid runtime config idempotency snapshot")
	}
	return snapshot.Config, nil
}

func (store *Store) LoadConversation(ctx context.Context, ownerID, conversationID string) (runtimeapi.Conversation, bool, error) {
	ownerID = strings.TrimSpace(ownerID)
	conversationID = strings.TrimSpace(conversationID)
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return runtimeapi.Conversation{}, false, fmt.Errorf("begin load runtime conversation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	conversation := runtimeapi.Conversation{OwnerID: ownerID, ConversationID: conversationID}
	if err := tx.QueryRow(ctx, `
		SELECT summary, revision, updated_at FROM runtime_conversations
		WHERE owner_id=$1 AND conversation_id=$2`, ownerID, conversationID).Scan(&conversation.Summary, &conversation.Revision, &conversation.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			if err := tx.Commit(ctx); err != nil {
				return runtimeapi.Conversation{}, false, fmt.Errorf("commit missing runtime conversation read: %w", err)
			}
			return runtimeapi.Conversation{}, false, nil
		}
		return runtimeapi.Conversation{}, false, fmt.Errorf("load runtime conversation: %w", err)
	}
	rows, err := tx.Query(ctx, `
		SELECT role, content, name, tool_call_id, tool_calls
		FROM runtime_messages WHERE owner_id=$1 AND conversation_id=$2
		ORDER BY message_ordinal`, ownerID, conversationID)
	if err != nil {
		return runtimeapi.Conversation{}, false, fmt.Errorf("load runtime messages: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var message modelapi.Message
		var role string
		var toolCallsJSON []byte
		if err := rows.Scan(&role, &message.Content, &message.Name, &message.ToolCallID, &toolCallsJSON); err != nil {
			return runtimeapi.Conversation{}, false, fmt.Errorf("scan runtime message: %w", err)
		}
		message.Role = modelapi.Role(role)
		if err := json.Unmarshal(toolCallsJSON, &message.ToolCalls); err != nil {
			return runtimeapi.Conversation{}, false, errors.New("stored runtime tool calls are invalid")
		}
		if len(message.ToolCalls) == 0 {
			message.ToolCalls = nil
		}
		conversation.Messages = append(conversation.Messages, message)
	}
	if err := rows.Err(); err != nil {
		return runtimeapi.Conversation{}, false, fmt.Errorf("iterate runtime messages: %w", err)
	}
	conversation.UpdatedAt = conversation.UpdatedAt.UTC()
	if err := runtimeapi.ValidateConversationForPersistence(conversation); err != nil {
		return runtimeapi.Conversation{}, false, fmt.Errorf("stored runtime conversation is invalid: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return runtimeapi.Conversation{}, false, fmt.Errorf("commit runtime conversation read: %w", err)
	}
	return conversation, true, nil
}

func (store *Store) SaveConversation(ctx context.Context, conversation runtimeapi.Conversation, expectedRevision int64) (runtimeapi.Conversation, error) {
	tx, err := store.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return runtimeapi.Conversation{}, fmt.Errorf("begin save runtime conversation: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	conversation, err = saveRuntimeConversationOn(ctx, tx, conversation, expectedRevision)
	if err != nil {
		return runtimeapi.Conversation{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return runtimeapi.Conversation{}, fmt.Errorf("commit runtime conversation: %w", err)
	}
	return conversation, nil
}

func saveRuntimeConversationOn(ctx context.Context, tx pgx.Tx, conversation runtimeapi.Conversation, expectedRevision int64) (runtimeapi.Conversation, error) {
	conversation.OwnerID = strings.TrimSpace(conversation.OwnerID)
	conversation.ConversationID = strings.TrimSpace(conversation.ConversationID)
	if expectedRevision < 0 || conversation.Revision != expectedRevision {
		return runtimeapi.Conversation{}, runtimeapi.ErrRuntimeRevisionConflict
	}
	if err := runtimeapi.ValidateConversationForPersistence(conversation); err != nil {
		return runtimeapi.Conversation{}, err
	}
	var err error
	if expectedRevision == 0 {
		err = tx.QueryRow(ctx, `
			INSERT INTO runtime_conversations (owner_id, conversation_id, summary)
			VALUES ($1,$2,$3) ON CONFLICT (owner_id, conversation_id) DO NOTHING
			RETURNING revision, updated_at`, conversation.OwnerID, conversation.ConversationID, conversation.Summary,
		).Scan(&conversation.Revision, &conversation.UpdatedAt)
	} else {
		err = tx.QueryRow(ctx, `
			UPDATE runtime_conversations SET summary=$3, revision=revision+1, updated_at=clock_timestamp()
			WHERE owner_id=$1 AND conversation_id=$2 AND revision=$4
			RETURNING revision, updated_at`, conversation.OwnerID, conversation.ConversationID, conversation.Summary, expectedRevision,
		).Scan(&conversation.Revision, &conversation.UpdatedAt)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return runtimeapi.Conversation{}, runtimeapi.ErrRuntimeRevisionConflict
	}
	if err != nil {
		return runtimeapi.Conversation{}, fmt.Errorf("persist runtime conversation: %w", err)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM runtime_messages WHERE owner_id=$1 AND conversation_id=$2`, conversation.OwnerID, conversation.ConversationID); err != nil {
		return runtimeapi.Conversation{}, fmt.Errorf("replace runtime messages: %w", err)
	}
	for index, message := range conversation.Messages {
		toolCallsValue := message.ToolCalls
		if toolCallsValue == nil {
			toolCallsValue = []modelapi.ToolCall{}
		}
		toolCalls, err := json.Marshal(toolCallsValue)
		if err != nil {
			return runtimeapi.Conversation{}, fmt.Errorf("encode runtime tool calls: %w", err)
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO runtime_messages (
			    owner_id, conversation_id, message_ordinal, role, content,
			    name, tool_call_id, tool_calls)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8::text::jsonb)`,
			conversation.OwnerID, conversation.ConversationID, index, message.Role, message.Content,
			message.Name, message.ToolCallID, string(toolCalls),
		); err != nil {
			return runtimeapi.Conversation{}, fmt.Errorf("insert runtime message: %w", err)
		}
	}
	conversation.UpdatedAt = conversation.UpdatedAt.UTC()
	conversation.Messages = cloneRuntimeMessages(conversation.Messages)
	return conversation, nil
}

func cloneRuntimeMessages(messages []modelapi.Message) []modelapi.Message {
	if messages == nil {
		return nil
	}
	cloned := make([]modelapi.Message, len(messages))
	for index, message := range messages {
		cloned[index] = message
		cloned[index].ToolCalls = append([]modelapi.ToolCall(nil), message.ToolCalls...)
	}
	return cloned
}
