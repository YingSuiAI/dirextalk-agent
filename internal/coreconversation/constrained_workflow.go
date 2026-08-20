package coreconversation

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
	"github.com/YingSuiAI/dirextalk-agent/internal/coretask"
)

const (
	TurnConstrainedWorkflowVersion   = 1
	turnConstrainedWorkflowScheduled = "scheduled"
)

// TurnConstrainedWorkflow is a closed supervisor policy compiled by a trusted
// internal adapter. It is deliberately not a generic graph or client-selected
// permission surface.
type TurnConstrainedWorkflow struct {
	Version             int                          `json:"version"`
	Kind                string                       `json:"kind"`
	ScheduledCapability coretask.ScheduledCapability `json:"scheduled_capability,omitempty"`
}

func NewScheduledTurnWorkflow(capability coretask.ScheduledCapability) TurnConstrainedWorkflow {
	return TurnConstrainedWorkflow{Version: TurnConstrainedWorkflowVersion, Kind: turnConstrainedWorkflowScheduled, ScheduledCapability: capability}
}

func (w TurnConstrainedWorkflow) IsZero() bool { return w == (TurnConstrainedWorkflow{}) }

func (w TurnConstrainedWorkflow) Validate() error {
	if w.Version != TurnConstrainedWorkflowVersion || w.Kind != turnConstrainedWorkflowScheduled {
		return ErrInvalid
	}
	if _, err := w.ScheduledCapability.RequiredBindings(); err != nil {
		return ErrInvalid
	}
	return nil
}

type scheduledWorkflowState struct {
	capability   coretask.ScheduledCapability
	counts       map[string]int
	completed    map[string]int
	actions      map[string]struct{}
	allowedPosts map[string]struct{}
}

func newScheduledWorkflowState(capability coretask.ScheduledCapability) (*scheduledWorkflowState, error) {
	if _, err := capability.RequiredBindings(); err != nil {
		return nil, ErrInvalid
	}
	return &scheduledWorkflowState{
		capability: capability, counts: make(map[string]int), completed: make(map[string]int),
		actions: make(map[string]struct{}), allowedPosts: make(map[string]struct{}),
	}, nil
}

func (s *scheduledWorkflowState) acceptCall(call ToolCall, result *ToolResult) error {
	if s == nil || s.counts == nil || s.completed == nil || s.actions == nil || s.allowedPosts == nil {
		return ErrInvalid
	}
	name := call.Name
	count := func(tool string) int { return s.counts[tool] }
	accept := false
	switch s.capability {
	case coretask.ScheduledCapabilityScheduledNote:
		accept = false
	case coretask.ScheduledCapabilityChatSummary:
		accept = (name == "mcp__message__dirextalk_rooms_search" && count(name) == 0 && count("mcp__message__dirextalk_messages_list") == 0) ||
			(name == "mcp__message__dirextalk_messages_list" && count(name) == 0)
	case coretask.ScheduledCapabilityWebResearch:
		accept = name == "web_search" && count(name) == 0
	case coretask.ScheduledCapabilityRoomMessage:
		accept = (name == "mcp__message__dirextalk_rooms_search" && count(name) == 0 && count("mcp__message__dirextalk_messages_send") == 0) ||
			(name == "mcp__message__dirextalk_messages_send" && count(name) == 0)
	case coretask.ScheduledCapabilityContactReport:
		accept = (name == "mcp__message__dirextalk_contacts_list" && count(name) == 0 && count("mcp__message__dirextalk_contacts_search") == 0) ||
			(name == "mcp__message__dirextalk_contacts_search" && count(name) == 0)
	case coretask.ScheduledCapabilityRoomMemberReport:
		accept = (name == "mcp__message__dirextalk_rooms_search" && count(name) == 0 && count("mcp__message__dirextalk_room_members_list") == 0) ||
			(name == "mcp__message__dirextalk_room_members_list" && count(name) == 0)
	case coretask.ScheduledCapabilityChannelDigest:
		switch name {
		case "mcp__message__dirextalk_rooms_search":
			accept = count(name) == 0 && count("mcp__message__dirextalk_channel_posts_list") == 0 && count("mcp__message__dirextalk_channel_comments_list") == 0
		case "mcp__message__dirextalk_channel_posts_list":
			accept = count(name) == 0 && count("mcp__message__dirextalk_channel_comments_list") == 0
		case "mcp__message__dirextalk_channel_comments_list":
			if count("mcp__message__dirextalk_channel_posts_list") == 1 {
				var arguments struct {
					PostID string `json:"post_id"`
				}
				if json.Unmarshal([]byte(call.Arguments), &arguments) != nil || arguments.PostID == "" || arguments.PostID != strings.TrimSpace(arguments.PostID) {
					return ErrInvalid
				}
				_, selected := s.allowedPosts[arguments.PostID]
				_, repeated := s.actions[arguments.PostID]
				accept = selected && !repeated
				if accept {
					s.actions[arguments.PostID] = struct{}{}
				}
			}
		}
	case coretask.ScheduledCapabilityChatSummaryDelivery:
		accept = (name == "mcp__message__dirextalk_rooms_search" && count(name) == 0 && count("mcp__message__dirextalk_messages_list") == 0 && count("mcp__message__dirextalk_messages_send") == 0) ||
			(name == "mcp__message__dirextalk_messages_list" && count(name) == 0 && count("mcp__message__dirextalk_messages_send") == 0) ||
			(name == "mcp__message__dirextalk_messages_send" && count(name) == 0 && count("mcp__message__dirextalk_messages_list") == 1)
	case coretask.ScheduledCapabilityWebDigestDelivery:
		accept = (name == "web_search" && count(name) == 0 && len(s.counts) == 0) ||
			(name == "mcp__message__dirextalk_rooms_search" && count(name) == 0 && count("web_search") == 1 && count("mcp__message__dirextalk_messages_send") == 0) ||
			(name == "mcp__message__dirextalk_messages_send" && count(name) == 0 && count("web_search") == 1)
	}
	if !accept {
		return ErrInvalid
	}
	s.counts[name]++
	if result != nil {
		s.completed[name]++
	}
	if name == "mcp__message__dirextalk_channel_posts_list" && result != nil {
		for _, reference := range result.References {
			if reference.Kind == "channel_post" && reference.Validate() == nil {
				s.allowedPosts[reference.PostID] = struct{}{}
			}
		}
	}
	return nil
}

func (s *scheduledWorkflowState) ReadyForFinal() bool {
	if s == nil {
		return false
	}
	switch s.capability {
	case coretask.ScheduledCapabilityScheduledNote:
		return len(s.counts) == 0
	case coretask.ScheduledCapabilityChatSummary:
		return s.completed["mcp__message__dirextalk_messages_list"] == 1
	case coretask.ScheduledCapabilityWebResearch:
		return s.completed["web_search"] == 1
	case coretask.ScheduledCapabilityRoomMessage:
		return s.completed["mcp__message__dirextalk_messages_send"] == 1
	case coretask.ScheduledCapabilityContactReport:
		return s.completed["mcp__message__dirextalk_contacts_list"] == 1 || s.completed["mcp__message__dirextalk_contacts_search"] == 1
	case coretask.ScheduledCapabilityRoomMemberReport:
		return s.completed["mcp__message__dirextalk_room_members_list"] == 1
	case coretask.ScheduledCapabilityChannelDigest:
		return s.completed["mcp__message__dirextalk_channel_posts_list"] == 1
	case coretask.ScheduledCapabilityChatSummaryDelivery:
		return s.completed["mcp__message__dirextalk_messages_list"] == 1 && s.completed["mcp__message__dirextalk_messages_send"] == 1
	case coretask.ScheduledCapabilityWebDigestDelivery:
		return s.completed["web_search"] == 1 && s.completed["mcp__message__dirextalk_messages_send"] == 1
	default:
		return false
	}
}

func (s *scheduledWorkflowState) RequiresToolFreeFinalization() bool {
	if !s.ReadyForFinal() {
		return false
	}
	switch s.capability {
	case coretask.ScheduledCapabilityChatSummary, coretask.ScheduledCapabilityWebResearch,
		coretask.ScheduledCapabilityRoomMessage, coretask.ScheduledCapabilityRoomMemberReport,
		coretask.ScheduledCapabilityChatSummaryDelivery, coretask.ScheduledCapabilityWebDigestDelivery:
		return true
	case coretask.ScheduledCapabilityContactReport:
		return s.completed["mcp__message__dirextalk_contacts_search"] == 1
	default:
		return false
	}
}

func scheduledWorkflowStateFor(workflow TurnConstrainedWorkflow, authorities map[string]turnToolCallAuthority) (*scheduledWorkflowState, error) {
	if workflow.Validate() != nil {
		return nil, ErrInvalid
	}
	state, err := newScheduledWorkflowState(workflow.ScheduledCapability)
	if err != nil {
		return nil, err
	}
	values := make([]turnToolCallAuthority, 0, len(authorities))
	for _, authority := range authorities {
		values = append(values, authority)
	}
	sort.Slice(values, func(i, j int) bool { return values[i].callSequence < values[j].callSequence })
	for _, authority := range values {
		if err = state.acceptCall(authority.call, authority.result); err != nil {
			return nil, ErrConflict
		}
	}
	return state, nil
}

func validateStaticSiteCorrectionCalls(forcedToolName string, calls []ToolCall) error {
	if forcedToolName != coremodel.IntrinsicStaticSitePublishToolName || len(calls) != 1 || calls[0].Name != forcedToolName {
		return ErrInvalid
	}
	return nil
}
