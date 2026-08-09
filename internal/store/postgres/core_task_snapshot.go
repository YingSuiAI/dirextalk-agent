package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	"github.com/jackc/pgx/v5"
)

// resolveTaskSnapshotTx is called from the CreateTask transaction. Every
// selected object is read under that transaction and copied into the
// immutable snapshot before the task row becomes visible.
func resolveTaskSnapshotTx(ctx context.Context, tx pgx.Tx, spec coretask.TaskSpec) (coretask.ExecutionSnapshot, error) {
	var snapshot coretask.ExecutionSnapshot
	boundProfileID := ""
	var boundProfileRevision int64
	if spec.Kind == coretask.TaskKindAgent || spec.Kind == coretask.TaskKindKnowledgeIndex || spec.Kind == coretask.TaskKindCloudWorker {
		var model coretask.ModelProfileSnapshot
		var provider, modelKind string
		var temperature, topP *float64
		var apiConfigured bool
		err := tx.QueryRow(ctx, `SELECT profile_id::text,revision,provider,model_kind,base_url,model_name,system_prompt,temperature,top_p,max_output_tokens,context_window,reasoning_effort,api_key_configured FROM core_model_profiles WHERE profile_id=$1 AND deleted_at IS NULL FOR SHARE`, spec.ModelProfileID).Scan(&model.ProfileID, &model.Revision, &provider, &modelKind, &model.BaseURL, &model.Model, &model.SystemPrompt, &temperature, &topP, &model.MaxOutputTokens, &model.ContextWindow, &model.ReasoningEffort, &apiConfigured)
		if err != nil || !apiConfigured {
			if errors.Is(err, pgx.ErrNoRows) {
				return coretask.ExecutionSnapshot{}, coretask.ErrNotFound
			}
			if err != nil {
				return coretask.ExecutionSnapshot{}, err
			}
			return coretask.ExecutionSnapshot{}, coretask.ErrConflict
		}
		switch spec.Kind {
		case coretask.TaskKindAgent, coretask.TaskKindCloudWorker:
			if modelKind != coremodel.ModelKindConversation {
				return coretask.ExecutionSnapshot{}, coretask.ErrConflict
			}
		case coretask.TaskKindKnowledgeIndex:
			if modelKind != coremodel.ModelKindEmbedding {
				return coretask.ExecutionSnapshot{}, coretask.ErrConflict
			}
		}
		model.Provider, model.Temperature, model.TopP = provider, temperature, topP
		model.SecretRef = "model-profile:" + model.ProfileID + ":" + fmt.Sprint(model.Revision)
		model.Digest = coreTaskModelSnapshotDigest(model)
		snapshot.Model = model
		boundProfileID, boundProfileRevision = model.ProfileID, model.Revision
	}

	for _, selected := range spec.Extensions {
		var revision int64
		var kind, state, activeVersion string
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT revision,kind,state,enabled,COALESCE(active_version_id::text,'') FROM core_extension_installations WHERE installation_id=$1 FOR SHARE`, selected.ID).Scan(&revision, &kind, &state, &enabled, &activeVersion); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coretask.ExecutionSnapshot{}, coretask.ErrNotFound
			}
			return coretask.ExecutionSnapshot{}, err
		}
		if state != "installed" || !enabled || revision <= 0 || activeVersion == "" {
			return coretask.ExecutionSnapshot{}, coretask.ErrConflict
		}
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE version_id=$1 AND installation_id=$2`, activeVersion, selected.ID).Scan(&raw); err != nil {
			return coretask.ExecutionSnapshot{}, err
		}
		var version struct {
			Pin            json.RawMessage `json:"pin"`
			Version        string          `json:"version"`
			ContentDigest  string          `json:"content_digest"`
			ArtifactDigest string          `json:"artifact_digest"`
			Tools          json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(raw, &version); err != nil || version.ContentDigest != selected.Digest || len(version.ArtifactDigest) != 64 {
			return coretask.ExecutionSnapshot{}, coretask.ErrRevisionConflict
		}
		if version.Version != "" && version.Version != selected.Version {
			return coretask.ExecutionSnapshot{}, coretask.ErrRevisionConflict
		}
		if len(version.Pin) > 0 {
			var pin struct {
				RegistryVersion string `json:"registry_version"`
				GitCommit       string `json:"git_commit"`
			}
			if json.Unmarshal(version.Pin, &pin) == nil {
				pinnedVersion := pin.RegistryVersion
				if pinnedVersion == "" {
					pinnedVersion = pin.GitCommit
				}
				if pinnedVersion != "" && pinnedVersion != selected.Version {
					return coretask.ExecutionSnapshot{}, coretask.ErrRevisionConflict
				}
			}
		}
		if kind != string(selected.Kind) {
			return coretask.ExecutionSnapshot{}, coretask.ErrConflict
		}
		tools, toolsErr := pinnedToolDescriptors(version.Tools)
		if toolsErr != nil {
			return coretask.ExecutionSnapshot{}, coretask.ErrRevisionConflict
		}
		snapshot.Extensions = append(snapshot.Extensions, coretask.ExtensionExecutionSnapshot{Kind: selected.Kind, InstallationID: selected.ID, Revision: revision, Version: selected.Version, ContentDigest: version.ContentDigest, ArtifactDigest: strings.ToLower(version.ArtifactDigest), AllowedTools: append([]string(nil), selected.AllowedTools...), Tools: tools})
		snapshot.Extensions[len(snapshot.Extensions)-1].VersionID = activeVersion
	}
	if spec.Kind == coretask.TaskKindExtension && spec.Payload.Extension != nil && spec.Payload.Extension.Operation != coretask.ExtensionOperationInstall && spec.Payload.Extension.Operation != coretask.ExtensionOperationUpdate && spec.Payload.Extension.Operation != coretask.ExtensionOperationUninstall {
		p := spec.Payload.Extension
		var revision int64
		var kind, state, activeVersion string
		var enabled bool
		if err := tx.QueryRow(ctx, `SELECT revision,kind,state,enabled,COALESCE(active_version_id::text,'') FROM core_extension_installations WHERE installation_id=$1 FOR SHARE`, p.InstallationID).Scan(&revision, &kind, &state, &enabled, &activeVersion); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coretask.ExecutionSnapshot{}, coretask.ErrNotFound
			}
			return coretask.ExecutionSnapshot{}, err
		}
		if state != "installed" || !enabled || revision != int64(p.ExpectedRevision) || activeVersion == "" {
			return coretask.ExecutionSnapshot{}, coretask.ErrRevisionConflict
		}
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT version_json FROM core_extension_versions WHERE version_id=$1 AND installation_id=$2`, activeVersion, p.InstallationID).Scan(&raw); err != nil {
			return coretask.ExecutionSnapshot{}, err
		}
		var version struct {
			ContentDigest  string          `json:"content_digest"`
			ArtifactDigest string          `json:"artifact_digest"`
			Version        string          `json:"version"`
			Tools          json.RawMessage `json:"tools"`
		}
		if json.Unmarshal(raw, &version) != nil || version.ContentDigest != p.Digest || len(version.ArtifactDigest) != 64 {
			return coretask.ExecutionSnapshot{}, coretask.ErrRevisionConflict
		}
		if version.Version != "" && version.Version != p.Version {
			return coretask.ExecutionSnapshot{}, coretask.ErrRevisionConflict
		}
		kindValue := coretask.ExtensionMCP
		if kind == "skill" {
			kindValue = coretask.ExtensionSkill
		}
		tools, toolsErr := pinnedToolDescriptors(version.Tools)
		if toolsErr != nil {
			return coretask.ExecutionSnapshot{}, coretask.ErrRevisionConflict
		}
		e := coretask.ExtensionExecutionSnapshot{Kind: kindValue, InstallationID: p.InstallationID, Revision: revision, VersionID: activeVersion, Version: p.Version, ContentDigest: version.ContentDigest, ArtifactDigest: strings.ToLower(version.ArtifactDigest), Tools: tools}
		snapshot.Extensions = append(snapshot.Extensions, e)
	}

	for _, id := range spec.KnowledgeRefs {
		var revision int64
		var status, digest, manifestDigest, generation string
		var promotedProfile string
		var promotedProfileRevision int64
		var promotedCollectionDigest string
		if err := tx.QueryRow(ctx, `SELECT revision,status,digest,directory_manifest_digest,promoted_generation,COALESCE(promoted_profile_id::text,''),promoted_profile_revision,promoted_collection_config_digest FROM core_knowledge_sources WHERE source_id=$1 FOR SHARE`, id).Scan(&revision, &status, &digest, &manifestDigest, &generation, &promotedProfile, &promotedProfileRevision, &promotedCollectionDigest); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coretask.ExecutionSnapshot{}, coretask.ErrNotFound
			}
			return coretask.ExecutionSnapshot{}, err
		}
		if status != "ready" || revision <= 0 || len(digest) != 64 || promotedProfile != boundProfileID || promotedProfileRevision != boundProfileRevision {
			return coretask.ExecutionSnapshot{}, coretask.ErrConflict
		}
		indexDigest := promotedCollectionDigest
		if len(indexDigest) != 64 {
			indexDigest = manifestDigest
		}
		if len(indexDigest) != 64 {
			if generation == "" {
				return coretask.ExecutionSnapshot{}, coretask.ErrConflict
			}
			indexDigest = digestSnapshotValue(generation)
		}
		snapshot.Knowledge = append(snapshot.Knowledge, coretask.KnowledgeExecutionSnapshot{SourceID: id, Revision: revision, ContentDigest: strings.ToLower(digest), IndexDigest: indexDigest, Ready: true})
	}
	for _, id := range spec.AttachmentRefs {
		var relative, digest, media, status, kind string
		var size, revision int64
		if err := tx.QueryRow(ctx, `SELECT relative_path,digest,media_type,size_bytes,status,revision,kind FROM core_knowledge_sources WHERE source_id=$1 FOR SHARE`, id).Scan(&relative, &digest, &media, &size, &status, &revision, &kind); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return coretask.ExecutionSnapshot{}, coretask.ErrNotFound
			}
			return coretask.ExecutionSnapshot{}, err
		}
		if kind != "upload" || status != "ready" || revision <= 0 || digest == "" {
			return coretask.ExecutionSnapshot{}, coretask.ErrConflict
		}
		snapshot.Attachments = append(snapshot.Attachments, coretask.AttachmentDescriptor{ID: id, RelativePath: relative, Digest: strings.ToLower(digest), Size: size, MediaType: media})
	}
	if err := snapshot.Seal(); err != nil {
		return coretask.ExecutionSnapshot{}, err
	}
	return snapshot, nil
}

func pinnedToolDescriptors(raw json.RawMessage) ([]coretask.ToolDescriptor, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var entries []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}
	out := make([]coretask.ToolDescriptor, 0, len(entries))
	for _, entry := range entries {
		var name, description, digest string
		_ = json.Unmarshal(entry["name"], &name)
		_ = json.Unmarshal(entry["description"], &description)
		_ = json.Unmarshal(entry["schema_digest"], &digest)
		if digest == "" {
			_ = json.Unmarshal(entry["input_schema_digest"], &digest)
		}
		schema := entry["input_schema"]
		if len(schema) == 0 {
			schema = entry["inputSchema"]
		}
		if len(schema) == 0 || name == "" {
			return nil, errors.New("invalid pinned tool descriptor")
		}
		out = append(out, coretask.ToolDescriptor{Name: name, Description: description, InputSchema: schema, SchemaDigest: digest})
	}
	return out, nil
}

func digestSnapshotValue(v any) string {
	b, _ := json.Marshal(v)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func coreTaskModelSnapshotDigest(model coretask.ModelProfileSnapshot) string {
	return digestSnapshotValue(struct {
		ProfileID       string
		Revision        int64
		Provider        string
		BaseURL         string
		Model           string
		SystemPrompt    string
		Temperature     *float64
		TopP            *float64
		MaxOutputTokens int
		ContextWindow   int
		ReasoningEffort string
	}{
		ProfileID:       model.ProfileID,
		Revision:        model.Revision,
		Provider:        model.Provider,
		BaseURL:         model.BaseURL,
		Model:           model.Model,
		SystemPrompt:    model.SystemPrompt,
		Temperature:     model.Temperature,
		TopP:            model.TopP,
		MaxOutputTokens: model.MaxOutputTokens,
		ContextWindow:   model.ContextWindow,
		ReasoningEffort: model.ReasoningEffort,
	})
}
