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
			return coreruntime.ManagedOutcome{Err: errors.New("scheduled Agent dependencies are unavailable")}
		}
		payload := task.Spec.Payload.Agent
		if task.Spec.Kind != coretask.TaskKindAgent || payload == nil || payload.ScheduledConversation == nil ||
			task.Snapshot == nil || task.Snapshot.Model.ProfileID == "" || task.Spec.ConversationID == "" ||
			task.Spec.ModelProfileID != task.Snapshot.Model.ProfileID || strings.TrimSpace(payload.OwnerID) == "" || payload.AccountGeneration == 0 {
			return coreruntime.ManagedOutcome{Err: coretask.ErrInvalid}
		}

		requestID := scheduledAgentUUID("scheduled-agent-request:" + task.ID)
		turnID := scheduledAgentUUID("scheduled-agent-turn:" + task.ID)
		chainID := scheduledAgentUUID("scheduled-agent-chain:" + task.ID)
		rootOperationID := scheduledAgentUUID("scheduled-agent-root-operation:" + task.ID)
		executionCtx := capabilityclient.WithCallContext(ctx, &capv1.CallContext{
			ChainId: chainID, RootOperationId: rootOperationID, Route: "scheduled-agent",
		}, &capv1.PermissionContext{
			AuthenticatedOwnerId: payload.OwnerID,
			AccountGeneration:    int64(payload.AccountGeneration),
		})

		profile, err := profiles.ResolveExecutionProfile(executionCtx, task.Snapshot.Model)
		if err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
		profileSnapshot := coremodel.SnapshotFromProfile(profile)
		if profileSnapshot.ProfileID != task.Snapshot.Model.ProfileID || profileSnapshot.Revision != task.Snapshot.Model.Revision {
			return coreruntime.ManagedOutcome{Err: coretask.ErrRevisionConflict}
		}
		extensions := scheduledConversationSnapshots(payload.ScheduledConversation.ExtensionSnapshots)
		turn, err := conversation.StartTurn(executionCtx, coreconversation.TurnStartCommand{
			TurnID:                    turnID,
			RequestID:                 requestID,
			OwnerID:                   payload.OwnerID,
			AccountGeneration:         payload.AccountGeneration,
			ConversationID:            task.Spec.ConversationID,
			Prompt:                    task.Spec.Goal,
			ProfileID:                 profileSnapshot.ProfileID,
			ExpectedProfileRevision:   profileSnapshot.Revision,
			ExpectedCredentialVersion: profileSnapshot.CredentialVersion,
			ProfileSnapshot:           profileSnapshot,
			ExtensionSnapshots:        extensions,
			ExtensionSnapshotsPinned:  true,
		})
		if err != nil {
			return coreruntime.ManagedOutcome{Err: err}
		}
		if err := validateScheduledTurnIdentity(turn, turnID, requestID, task, payload); err != nil {
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
				if err := validateScheduledTurnIdentity(turn, turnID, requestID, task, payload); err != nil {
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

func validateScheduledTurnIdentity(turn coreconversation.Turn, turnID, requestID string, task coretask.Task, payload *coretask.AgentTaskPayload) error {
	if turn.ID != turnID || turn.RequestID != requestID || turn.ConversationID != task.Spec.ConversationID ||
		turn.Prompt != task.Spec.Goal || turn.ProfileID != task.Spec.ModelProfileID ||
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
