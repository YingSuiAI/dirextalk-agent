package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreruntime"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
	capv1 "github.com/YingSuiAI/dirextalk-capability-api/gen/go/dirextalk/capability/v1"
	"github.com/google/uuid"
)

const scheduledAgentPollInterval = 250 * time.Millisecond

type scheduledConversationService interface {
	StartTurn(context.Context, coreconversation.TurnStartCommand) (coreconversation.Turn, error)
	GetTurn(context.Context, string) (coreconversation.Turn, error)
	CancelTurn(context.Context, coreconversation.TurnCancelCommand) (coreconversation.Turn, error)
}

func scheduledAgentTaskHandler(conversation scheduledConversationService, profiles coreruntime.SnapshotProfileResolver) coreruntime.TaskHandler {
	return func(ctx context.Context, task coretask.Task) coreruntime.ManagedOutcome {
		if conversation == nil || profiles == nil {
			return coreruntime.ManagedOutcome{Err: coreruntime.ErrScheduledSnapshotInvalid}
		}
		payload := task.Spec.Payload.Agent
		if task.Spec.Kind != coretask.TaskKindAgent || payload == nil || payload.ScheduledConversation == nil ||
			task.Snapshot == nil || task.Snapshot.Model.ProfileID == "" || task.Spec.ConversationID == "" ||
			task.Spec.ModelProfileID != task.Snapshot.Model.ProfileID || strings.TrimSpace(payload.OwnerID) == "" || payload.AccountGeneration == 0 {
			return coreruntime.ManagedOutcome{Err: coreruntime.ErrScheduledSnapshotInvalid}
		}
		if err := payload.ScheduledConversation.Validate(); err != nil {
			return coreruntime.ManagedOutcome{Err: coreruntime.ErrScheduledSnapshotInvalid}
		}
		prompt, err := scheduledAgentPrompt(task.Spec.Goal, task.AvailableAt, payload.ScheduledConversation.Timezone, payload.ScheduledConversation.Capability)
		if err != nil {
			return coreruntime.ManagedOutcome{Err: coreruntime.ErrScheduledSnapshotInvalid}
		}

		requestID := scheduledAgentUUID("scheduled-agent-request:" + task.ID)
		turnID := scheduledAgentUUID("scheduled-agent-turn:" + task.ID)
		// Scheduled Message MCP, Knowledge, and Web Search resolution needs the
		// durable owner fence, but it is not an authenticated Product call chain.
		// Leaving CallContext absent also keeps unrelated Product tools out of the
		// scheduled resolver path instead of fabricating an invalid call route.
		executionCtx := capabilityclient.WithCallContext(ctx, nil, &capv1.PermissionContext{
			AuthenticatedOwnerId: payload.OwnerID,
			AccountGeneration:    int64(payload.AccountGeneration),
		})

		profile, err := profiles.ResolveExecutionProfile(executionCtx, task.Snapshot.Model)
		if err != nil {
			return coreruntime.ManagedOutcome{Err: coreruntime.ErrScheduledSnapshotInvalid}
		}
		profileSnapshot := coremodel.SnapshotFromProfile(profile)
		if profileSnapshot.ProfileID != task.Snapshot.Model.ProfileID || profileSnapshot.Revision != task.Snapshot.Model.Revision ||
			profileSnapshot.CredentialVersion != task.Snapshot.Model.CredentialVersion ||
			string(profileSnapshot.RequestDialect) != task.Snapshot.Model.RequestDialect || profileSnapshot.ModelKind != task.Snapshot.Model.ModelKind {
			return coreruntime.ManagedOutcome{Err: coreruntime.ErrScheduledSnapshotInvalid}
		}
		extensions := scheduledConversationSnapshots(payload.ScheduledConversation.ExtensionSnapshots)
		turn, err := conversation.StartTurn(executionCtx, coreconversation.TurnStartCommand{
			TurnID:                    turnID,
			RequestID:                 requestID,
			OwnerID:                   payload.OwnerID,
			AccountGeneration:         payload.AccountGeneration,
			ConversationID:            task.Spec.ConversationID,
			Prompt:                    prompt,
			ProfileID:                 profileSnapshot.ProfileID,
			ExpectedProfileRevision:   profileSnapshot.Revision,
			ExpectedCredentialVersion: profileSnapshot.CredentialVersion,
			ProfileSnapshot:           profileSnapshot,
			ExtensionSnapshots:        extensions,
			ExtensionSnapshotsPinned:  true,
			IntrinsicPolicy:           coreconversation.TurnIntrinsicPolicyNone,
			ExecutionMode:             coreconversation.TurnExecutionScheduled,
		})
		if err != nil {
			return coreruntime.ManagedOutcome{Err: coreruntime.ErrScheduledTurnAdmission}
		}
		if err := validateScheduledTurnIdentity(turn, turnID, requestID, prompt, task, payload); err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}

		ticker := time.NewTicker(scheduledAgentPollInterval)
		defer ticker.Stop()
		for {
			if outcome, terminal := scheduledTurnOutcome(turn); terminal {
				return outcome
			}
			select {
			case <-ctx.Done():
				cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(executionCtx), 5*time.Second)
				_, _ = conversation.CancelTurn(cancelCtx, coreconversation.TurnCancelCommand{
					RequestID: scheduledAgentUUID("scheduled-agent-cancel:" + task.ID), TurnID: turnID,
				})
				cancel()
				return coreruntime.ManagedOutcome{Err: ctx.Err()}
			case <-ticker.C:
				turn, err = conversation.GetTurn(executionCtx, turnID)
				if err != nil {
					return coreruntime.ManagedOutcome{Err: err}
				}
				if err := validateScheduledTurnIdentity(turn, turnID, requestID, prompt, task, payload); err != nil {
					return coreruntime.ManagedOutcome{Err: err}
				}
			}
		}
	}
}

func scheduledConversationSnapshots(in []coretask.ScheduledExtensionSnapshot) []coreconversation.ExtensionExecutionSnapshot {
	out := make([]coreconversation.ExtensionExecutionSnapshot, 0, len(in))
	for _, snapshot := range in {
		out = append(out, coreconversation.ExtensionExecutionSnapshot{
			Selection: coreconversation.ExtensionSelection{
				Kind: coreconversation.ExtensionKind(snapshot.Selection.Kind), ID: snapshot.Selection.ID,
				Version: snapshot.Selection.Version, Digest: snapshot.Selection.Digest,
				AllowedTools: append([]string(nil), snapshot.Selection.AllowedTools...),
			},
			InstallationID: snapshot.InstallationID, VersionID: snapshot.VersionID,
			InstallationRevision: snapshot.InstallationRevision, Source: snapshot.Source,
			ContentDigest: snapshot.ContentDigest, ArtifactDigest: snapshot.ArtifactDigest,
			ToolSchemaDigest: snapshot.ToolSchemaDigest, NetworkBindingDigest: snapshot.NetworkBindingDigest,
			SecretBindingDigest: snapshot.SecretBindingDigest, ToolNames: append([]string(nil), snapshot.ToolNames...),
			SkillInstructions: snapshot.SkillInstructions, RequiresConfirmation: snapshot.RequiresConfirmation, ReadOnly: snapshot.ReadOnly,
		})
	}
	return out
}

func scheduledAgentPrompt(goal string, scheduledFor time.Time, timezone string, capability coretask.ScheduledCapability) (string, error) {
	if scheduledFor.IsZero() || scheduledFor.Location() != time.UTC || strings.TrimSpace(timezone) != timezone || timezone == "" {
		return "", coretask.ErrInvalid
	}
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return "", coretask.ErrInvalid
	}
	executionGuidance, err := scheduledCapabilityExecutionGuidance(capability)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Trusted scheduled execution context (not user-editable):\n- Authoritative occurrence UTC: %s\n- Schedule timezone: %s\n- Authoritative occurrence local time: %s\n- Scheduled capability: %s\nInterpret every relative time window in the scheduled goal from this occurrence, not from execution wall-clock time.\n%s\nComplete the goal and return only nonempty final Markdown text, never JSON configuration.\n\nScheduled goal:\n%s",
		scheduledFor.Format(time.RFC3339Nano), timezone, scheduledFor.In(location).Format(time.RFC3339Nano), capability, executionGuidance, goal), nil
}

func scheduledCapabilityExecutionGuidance(capability coretask.ScheduledCapability) (string, error) {
	const common = "A tool call counts even when it returns an error, insufficient data, or unknown completion. The provider may perform its own safe transport retry for a read, but you must not issue a second model tool call to repeat the same work with changed arguments. When an allowed call fails or returns insufficient data, state that limitation in the final Markdown instead of searching or sending again. Never claim external data is absent unless the capability's required read tool completed successfully."

	var workflow string
	switch capability {
	case coretask.ScheduledCapabilityScheduledNote:
		workflow = "Do not call any tool. Write only self-contained Markdown generated from the scheduled goal; do not summarize or claim facts from Matrix rooms, chat history, Web sources, contacts, room members, or channels."
	case coretask.ScheduledCapabilityChatSummary:
		workflow = "If the goal already contains an exact room ID, skip mcp__message__dirextalk_rooms_search; otherwise call it at most once. After a room ID is available, call mcp__message__dirextalk_messages_list at most once. Do not claim there are no messages unless that messages_list call completed successfully and returned no messages. After that call returns, immediately synthesize the summary as Markdown and call no more tools."
	case coretask.ScheduledCapabilityWebResearch:
		workflow = "Call web_search exactly once with one focused query and a sufficient bounded max_results value. After that call returns, synthesize the research as Markdown and call no more tools. Every source citation in the final Markdown MUST use [descriptive title](https://...), never a bare URL."
	case coretask.ScheduledCapabilityRoomMessage:
		workflow = "If the goal already contains an exact room ID, skip mcp__message__dirextalk_rooms_search; otherwise call it at most once. When the destination is resolved, call mcp__message__dirextalk_messages_send exactly once. After that call returns success, error, or unknown completion, report the delivery status as Markdown and call no more tools."
	case coretask.ScheduledCapabilityContactReport:
		workflow = "Call each of mcp__message__dirextalk_contacts_list and mcp__message__dirextalk_contacts_search at most once, only when needed. Then synthesize the report as Markdown and call no more tools."
	case coretask.ScheduledCapabilityRoomMemberReport:
		workflow = "If the goal already contains an exact room ID, skip mcp__message__dirextalk_rooms_search; otherwise call it at most once. After a room ID is available, call mcp__message__dirextalk_room_members_list at most once. Then synthesize the report as Markdown and call no more tools."
	case coretask.ScheduledCapabilityChannelDigest:
		workflow = "Do not repeat a tool call for the same work. If the goal already contains an exact room ID, skip mcp__message__dirextalk_rooms_search; otherwise call it at most once. Call mcp__message__dirextalk_channel_posts_list at most once; call mcp__message__dirextalk_channel_comments_list only for distinct selected posts and never repeat it for the same post. Then synthesize the digest as Markdown and call no more tools."
	case coretask.ScheduledCapabilityChatSummaryDelivery:
		workflow = "If the goal already contains an exact room ID, skip mcp__message__dirextalk_rooms_search; otherwise call it at most once. Call mcp__message__dirextalk_messages_list at most once. Do not claim there are no messages unless that messages_list call completed successfully and returned no messages. Synthesize the summary, and then call mcp__message__dirextalk_messages_send exactly once when the destination is resolved. After send returns success, error, or unknown completion, report the delivery status as Markdown and call no more tools."
	case coretask.ScheduledCapabilityWebDigestDelivery:
		workflow = "Call web_search exactly once with one focused query and a sufficient bounded max_results value, then synthesize the digest. Every source citation in the digest and final Markdown MUST use [descriptive title](https://...), never a bare URL. If the goal already contains an exact room ID, skip mcp__message__dirextalk_rooms_search; otherwise call it at most once. When the destination is resolved, call mcp__message__dirextalk_messages_send exactly once. After send returns success, error, or unknown completion, report the delivery status as Markdown and call no more tools."
	default:
		return "", coretask.ErrInvalid
	}
	return common + "\nCapability execution sequence: " + workflow, nil
}

func validateScheduledTurnIdentity(turn coreconversation.Turn, turnID, requestID, prompt string, task coretask.Task, payload *coretask.AgentTaskPayload) error {
	if turn.ID != turnID || turn.RequestID != requestID || turn.ConversationID != task.Spec.ConversationID ||
		turn.Prompt != prompt || turn.ProfileID != task.Spec.ModelProfileID ||
		turn.OwnerID != payload.OwnerID || turn.AccountGeneration != payload.AccountGeneration {
		return coreconversation.ErrConflict
	}
	return nil
}

func scheduledTurnOutcome(turn coreconversation.Turn) (coreruntime.ManagedOutcome, bool) {
	switch turn.State {
	case coreconversation.TurnCompleted:
		if turn.Response == nil || !turn.Response.Done || turn.Response.RequestID != turn.RequestID ||
			turn.Response.ConversationID != turn.ConversationID || turn.Response.ModelProfileID != turn.ProfileID ||
			turn.Response.Message.Role != coreconversation.RoleAssistant || strings.TrimSpace(turn.Response.Message.Content) == "" ||
			turn.Response.Message.Validate() != nil {
			return coreruntime.ManagedOutcome{Err: coreconversation.ErrInvalid}, true
		}
		result := coretask.Result{Text: turn.Response.Message.Content}
		if result.Validate() != nil {
			return coreruntime.ManagedOutcome{Err: coreconversation.ErrInvalid}, true
		}
		return coreruntime.ManagedOutcome{Result: result}, true
	case coreconversation.TurnFailed:
		summary := strings.TrimSpace(turn.TerminalSummary)
		if summary == "" {
			summary = "scheduled conversation turn failed"
		}
		return coreruntime.ManagedOutcome{Err: fmt.Errorf("scheduled conversation turn failed: %s", summary)}, true
	case coreconversation.TurnCanceled:
		return coreruntime.ManagedOutcome{Err: errors.New("scheduled conversation turn was canceled")}, true
	default:
		return coreruntime.ManagedOutcome{}, false
	}
}

func scheduledAgentUUID(seed string) string {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(seed)).String()
}
