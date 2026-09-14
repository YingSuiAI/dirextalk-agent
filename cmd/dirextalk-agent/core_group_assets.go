package main

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

// groupAgentAssetsPublisher keeps the group's own view of what its Agent built:
// the servers deployed for this group and the files delivered in this room. It
// publishes that view into room state, so every member reads the same one from
// their own node.
type groupAgentAssetsPublisher struct {
	product       groupAssetsProduct
	plans         groupAssetsPlanLister
	conversations groupAssetsConversationReader
	workers       groupAssetsWorkerInventory
}

type groupAssetsProduct interface {
	RecordGroupAssets(context.Context, string, []capabilityclient.GroupAgentAssetServer, []capabilityclient.GroupAgentAssetArtifact) error
}

type groupAssetsPlanLister interface {
	ListPlansForAuthority(context.Context, string, uint64, string, int) ([]cloudworker.Plan, string, error)
}

type groupAssetsConversationReader interface {
	GetConversation(context.Context, string) (coreconversation.Conversation, error)
}

type groupAssetsWorkerInventory interface {
	ResolveRetainedWorkerInventory(context.Context, string, uint64) (cloudworker.RetainedWorkerInventory, error)
}

const (
	groupAssetsMax          = 40
	groupAssetsPlanPageMax  = 200
	groupAssetsPlanPageSize = 100
)

// Publish refreshes one group's servers and artifacts. A failure is reported by
// the caller and never blocks the group's answer.
func (p groupAgentAssetsPublisher) Publish(ctx context.Context, origin coreconversation.GroupOrigin) error {
	if p.product == nil || origin.Validate() != nil {
		return nil
	}
	artifacts := p.conversationArtifacts(ctx, origin.ConversationID())
	servers := p.conversationServers(ctx, origin)
	return p.product.RecordGroupAssets(ctx, origin.RoomID, servers, artifacts)
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

// conversationServers resolves the services this group's own worker plans
// created, with their live status and address when the Worker is still kept.
func (p groupAgentAssetsPublisher) conversationServers(ctx context.Context, origin coreconversation.GroupOrigin) []capabilityclient.GroupAgentAssetServer {
	if p.plans == nil {
		return nil
	}
	workloads := map[string]string{}
	for cursor, page := "", 0; page < groupAssetsPlanPageMax/groupAssetsPlanPageSize; page++ {
		plans, next, err := p.plans.ListPlansForAuthority(ctx, origin.OwnerID, origin.AccountGeneration, cursor, groupAssetsPlanPageSize)
		if err != nil {
			break
		}
		for _, plan := range plans {
			if plan.ConversationID != origin.ConversationID() || plan.Service == nil || strings.TrimSpace(plan.Service.WorkloadID) == "" {
				continue
			}
			workloads[plan.Service.WorkloadID] = strings.TrimSpace(plan.Objective)
		}
		if next == "" {
			break
		}
		cursor = next
	}
	if len(workloads) == 0 {
		return nil
	}
	out := make([]capabilityclient.GroupAgentAssetServer, 0, len(workloads))
	addresses := p.liveWorkloadAddresses(ctx, origin)
	for workloadID, objective := range workloads {
		server := capabilityclient.GroupAgentAssetServer{WorkloadID: workloadID, Name: workloadID, Status: "registered"}
		if objective != "" {
			server.Name = objective
		}
		if live, ok := addresses[workloadID]; ok {
			server.Status, server.Address = live.Status, live.Address
		}
		out = append(out, server)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WorkloadID < out[j].WorkloadID })
	if len(out) > groupAssetsMax {
		out = out[:groupAssetsMax]
	}
	return out
}

type groupAssetLiveWorkload struct{ Status, Address string }

func (p groupAgentAssetsPublisher) liveWorkloadAddresses(ctx context.Context, origin coreconversation.GroupOrigin) map[string]groupAssetLiveWorkload {
	if p.workers == nil {
		return nil
	}
	inventory, err := p.workers.ResolveRetainedWorkerInventory(ctx, origin.OwnerID, origin.AccountGeneration)
	if err != nil {
		slog.Warn("[group-assets] retained Worker inventory unavailable", "room_id", origin.RoomID, "error", groupAgentErrorSummary(err))
		return nil
	}
	out := map[string]groupAssetLiveWorkload{}
	for _, worker := range inventory.Workers {
		for _, workload := range worker.Workloads {
			address := strings.TrimSpace(workload.Hostname)
			if address == "" && strings.TrimSpace(worker.PublicIPv4) != "" && workload.Port != 0 {
				address = "http://" + strings.TrimSpace(worker.PublicIPv4) + ":" + itoa(workload.Port) + "/"
			} else if address != "" {
				address = "https://" + address + "/"
			}
			status := strings.TrimSpace(workload.Health)
			if status == "" {
				status = strings.TrimSpace(workload.Phase)
			}
			out[workload.WorkloadID] = groupAssetLiveWorkload{Status: status, Address: address}
		}
	}
	return out
}

func itoa(value uint16) string {
	if value == 0 {
		return ""
	}
	digits := make([]byte, 0, 5)
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}
