package coreconversation

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/google/uuid"
)

//go:embed skills/publish-static-site/SKILL.md
var staticSiteSkillDocument string

type staticSiteIntrinsicArguments struct {
	HTML string `json:"html"`
}

func staticSiteIntrinsic(store ConversationStaticSiteStore, publisher StaticSitePublisher, bound TurnLease) ResolvedIntrinsic {
	return ResolvedIntrinsic{
		Tool: coremodel.Tool{
			Name:        coremodel.IntrinsicStaticSitePublishToolName,
			Description: "Publish one self-contained, script-free HTML page at a durable URL under the Dirextalk main domain. Put all CSS and data in the HTML. JavaScript, external network requests, forms, archives, and model-supplied paths are not supported.",
			InputSchema: map[string]any{
				"type": "object", "additionalProperties": false,
				"required": []any{"html"},
				"properties": map[string]any{
					"html": map[string]any{"type": "string", "minLength": 1, "maxLength": MaxStaticSiteHTMLBytes},
				},
			},
		},
		Execute: func(ctx context.Context, request IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
			return executeStaticSiteIntrinsic(ctx, store, publisher, bound, request)
		},
	}
}

func executeStaticSiteIntrinsic(ctx context.Context, store ConversationStaticSiteStore, publisher StaticSitePublisher, bound TurnLease, request IntrinsicExecutionRequest) (IntrinsicExecutionResult, error) {
	if ctx == nil || store == nil || publisher == nil || ValidateIntrinsicLeaseRenewal(bound, request.Lease) != nil ||
		request.Call.Name != coremodel.IntrinsicStaticSitePublishToolName ||
		request.Call.Validate() != nil || request.ConversationRevision == 0 || request.ConversationRevision == ^uint64(0) {
		return IntrinsicExecutionResult{}, ErrInvalid
	}
	args, err := parseStaticSiteIntrinsicArguments(request.CanonicalArguments)
	if err != nil {
		return IntrinsicExecutionResult{}, err
	}
	turn := request.Lease.Turn
	if strings.TrimSpace(turn.OwnerID) == "" || turn.AccountGeneration == 0 || !validUUID(turn.ConversationID) || !validUUID(turn.ProfileID) || turn.CreatedAt.IsZero() {
		return IntrinsicExecutionResult{}, ErrInvalid
	}
	siteID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-static-site:"+turn.OwnerID+":"+turn.ConversationID)).String()
	releaseID := uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-static-site-release:"+turn.ID+":"+turn.RequestID+":"+request.Call.ID)).String()
	receipt, err := publisher.PublishSingleHTML(ctx, StaticSitePublication{SiteID: siteID, ReleaseID: releaseID, HTML: []byte(args.HTML)})
	if err != nil {
		return IntrinsicExecutionResult{}, err
	}
	if receipt.Validate() != nil || receipt.SiteID != siteID || receipt.ReleaseID != releaseID {
		return IntrinsicExecutionResult{}, ErrConflict
	}
	now := turn.CreatedAt.UTC().Add(time.Microsecond)
	message := Message{
		ID:   uuid.NewSHA1(uuid.NameSpaceOID, []byte("conversation-static-site-message:"+turn.ID+":"+request.Call.ID)).String(),
		Role: RoleAssistant, Content: fmt.Sprintf("Published the static page: %s", receipt.PublicPath),
		CreatedAt: now, ModelProfileID: turn.ProfileID,
	}
	response := ChatResponse{
		RequestID: turn.RequestID, ConversationID: turn.ConversationID,
		Revision: request.ConversationRevision + 1, Message: message, Done: true, ModelProfileID: turn.ProfileID,
	}
	command := ConversationStaticSiteCommand{Lease: request.Lease, Receipt: receipt, Response: response}
	if command.Validate() != nil {
		return IntrinsicExecutionResult{}, ErrInvalid
	}
	if _, err = store.CommitConversationStaticSite(ctx, command); err != nil {
		return IntrinsicExecutionResult{}, err
	}
	return IntrinsicExecutionResult{TurnCommitted: true}, nil
}

func parseStaticSiteIntrinsicArguments(raw json.RawMessage) (staticSiteIntrinsicArguments, error) {
	if len(raw) == 0 || len(raw) > MaxToolArgumentsBytes {
		return staticSiteIntrinsicArguments{}, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var args staticSiteIntrinsicArguments
	if decoder.Decode(&args) != nil || decoder.Decode(&struct{}{}) == nil {
		return staticSiteIntrinsicArguments{}, ErrInvalid
	}
	if args.HTML == "" || !utf8.ValidString(args.HTML) || len([]byte(args.HTML)) > MaxStaticSiteHTMLBytes || strings.IndexByte(args.HTML, 0) >= 0 {
		return staticSiteIntrinsicArguments{}, ErrInvalid
	}
	return args, nil
}

func staticSiteDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func staticSiteSystemPrompt(base string) string {
	parts := strings.SplitN(staticSiteSkillDocument, "---", 3)
	if len(parts) != 3 || strings.TrimSpace(parts[2]) == "" {
		return strings.TrimSpace(base)
	}
	guidance := strings.TrimSpace(parts[2])
	if strings.TrimSpace(base) == "" {
		return guidance
	}
	return strings.TrimSpace(base) + "\n\n" + guidance
}

func containsStaticSiteIntrinsic(tools []ResolvedIntrinsic) bool {
	for _, tool := range tools {
		if tool.Tool.Name == coremodel.IntrinsicStaticSitePublishToolName {
			return true
		}
	}
	return false
}
