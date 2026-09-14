package main

import (
	"context"
	"sort"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

// groupAgentAssetsPublisher keeps the group's own view of what its Agent built:
// the servers deployed for this group and the files delivered in this room. It
// publishes that view into room state, so every member reads the same one from
// their own node.
type groupAgentAssetsPublisher struct {
	product       groupAssetsProduct
	conversations groupAssetsConversationReader
}

type groupAssetsProduct interface {
	RecordGroupAssets(context.Context, string, []capabilityclient.GroupAgentAssetServer, []capabilityclient.GroupAgentAssetArtifact) error
}

type groupAssetsConversationReader interface {
	GetConversation(context.Context, string) (coreconversation.Conversation, error)
}

const (
	groupAssetsMax = 40
)

// Publish refreshes one group's servers and artifacts. A failure is reported by
// the caller and never blocks the group's answer.
func (p groupAgentAssetsPublisher) Publish(ctx context.Context, origin coreconversation.GroupOrigin) error {
	if p.product == nil || origin.Validate() != nil {
		return nil
	}
	// Servers stay in the owner's own Agent page; the group only ever shows
	// the files this group Agent delivered here.
	artifacts := p.conversationArtifacts(ctx, origin.ConversationID())
	return p.product.RecordGroupAssets(ctx, origin.RoomID, nil, artifacts)
}

// conversationArtifacts collects the files this group Agent delivered here. The
// conversation is the authority, so a member never sees another group's files.
func (p groupAgentAssetsPublisher) conversationArtifacts(ctx context.Context, conversationID string) []capabilityclient.GroupAgentAssetArtifact {
	if p.conversations == nil {
		return nil
	}
	conversation, err := p.conversations.GetConversation(ctx, conversationID)
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]capabilityclient.GroupAgentAssetArtifact, 0, groupAssetsMax)
	for _, message := range conversation.Messages {
		for _, reference := range message.References {
			if !strings.Contains(reference.Kind, "artifact") || reference.RecordKind == "" || reference.ArtifactID == "" {
				continue
			}
			if _, ok := seen[reference.ArtifactID]; ok {
				continue
			}
			seen[reference.ArtifactID] = struct{}{}
			name := strings.TrimSpace(reference.Name)
			if name == "" {
				name = reference.ArtifactID
			}
			artifact := capabilityclient.GroupAgentAssetArtifact{Name: name, MediaType: reference.MediaType,
				Link: "dirextalk-artifact://" + reference.RecordKind + "/" + reference.ArtifactID}
			if reference.SizeBytes != nil {
				artifact.SizeBytes = int64(*reference.SizeBytes)
			}
			out = append(out, artifact)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Link < out[j].Link })
	if len(out) > groupAssetsMax {
		out = out[:groupAssetsMax]
	}
	return out
}
