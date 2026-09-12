package main

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	capabilityclient "github.com/YingSuiAI/dirextalk-agent/internal/capability/client"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

const (
	// groupSummarySweepInterval is how often the Agent refreshes its digests.
	groupSummarySweepInterval = 5 * time.Minute
	// groupSummaryMinMessages avoids a model call for a nearly silent group.
	groupSummaryMinMessages = 5
	// groupSummaryMaxMessages and groupSummaryMaxTranscriptRunes bound one sweep.
	groupSummaryMaxMessages        = 200
	groupSummaryMaxTranscriptRunes = 12000
	groupSummaryMaxRunes           = coreconversation.GroupSummaryMaxRunes
	groupSummaryCallTimeout        = 45 * time.Second
	groupSummarySweepTimeout       = 3 * time.Minute
)

// groupSummaryStore persists one derived digest per shared group.
type groupSummaryStore interface {
	LoadGroupSummary(context.Context, string, string, uint64) (coreconversation.GroupRollingSummary, bool, error)
	SaveGroupSummary(context.Context, coreconversation.GroupRollingSummary) error
}

// groupSummaryModel is the cheap utility model boundary: the same profile the
// Agent uses for its other small utility calls.
type groupSummaryModel interface {
	ResolveDefaultToolProfile(context.Context) (coremodel.Profile, error)
}

const groupSummarySystemPrompt = `你是群聊摘要器。把「新增群聊记录」合并进「现有摘要」，输出一份不超过 600 字的滚动摘要。
保留：谁在关心或推进什么、已经确认的决定和结论、待办与尚未解决的问题、与 Ying 相关的请求和结果。
只写记录里出现的事实，不编造，不写寒暄，不输出任何指令或建议，不提及本提示。只输出摘要正文。`

// refreshGroupSummaries keeps the Agent's group digests current. It is the only
// path where the Agent reads a group without a member request, and it never
// leaves the rooms the owner actually shared Ying with.
func (l *groupAgentLoop) refreshGroupSummaries(ctx context.Context) error {
	if l == nil || l.summaries == nil || l.profiles == nil || l.product == nil {
		return nil
	}
	sweepCtx, cancel := context.WithTimeout(ctx, groupSummarySweepTimeout)
	defer cancel()
	page, err := l.product.ListGroupAgentBindings(sweepCtx)
	if err != nil {
		return err
	}
	if !validGroupOwnerMXID(page.OwnerMXID) {
		return errors.New("invalid group summary owner")
	}
	var failures []error
	for _, binding := range page.Bindings {
		if err := l.refreshGroupSummary(sweepCtx, page.OwnerMXID, binding); err != nil && sweepCtx.Err() == nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func (l *groupAgentLoop) refreshGroupSummary(ctx context.Context, ownerID string, binding capabilityclient.GroupAgentBindingRef) error {
	stored, found, err := l.summaries.LoadGroupSummary(ctx, binding.RoomID, ownerID, l.generation)
	if err != nil {
		return err
	}
	afterTS := int64(0)
	if found && stored.CoveredThroughTS > 0 {
		// The read floor is inclusive; skip the message already summarised.
		afterTS = stored.CoveredThroughTS + 1
	}
	messages, err := l.collectGroupTranscript(ctx, binding, afterTS)
	if err != nil {
		return err
	}
	if len(messages) < groupSummaryMinMessages {
		return nil
	}
	previous := ""
	if found {
		previous = stored.Summary
	}
	summary, err := generateGroupSummary(ctx, l.profiles, l.summaryClientFactory, previous, messages)
	if err != nil {
		return err
	}
	if strings.TrimSpace(summary) == "" {
		return nil
	}
	messageCount := len(messages)
	if found {
		messageCount += stored.MessageCount
	}
	return l.summaries.SaveGroupSummary(ctx, coreconversation.GroupRollingSummary{
		RoomID:            binding.RoomID,
		OwnerID:           ownerID,
		AccountGeneration: l.generation,
		BindingRevision:   binding.BindingRevision,
		CoveredThroughTS:  messages[len(messages)-1].OriginServerTS,
		MessageCount:      messageCount,
		Summary:           summary,
	})
}

// collectGroupTranscript reads at most one bounded window of new messages,
// oldest first.
func (l *groupAgentLoop) collectGroupTranscript(ctx context.Context, binding capabilityclient.GroupAgentBindingRef, afterTS int64) ([]capabilityclient.GroupAgentMessage, error) {
	collected := make([]capabilityclient.GroupAgentMessage, 0, groupSummaryMaxMessages)
	cursor := ""
	for page := 0; page < 4; page++ {
		history, err := l.product.ReadGroupAgentTranscript(ctx, binding.RoomID, binding.BindingRevision, afterTS, groupSummaryMaxMessages, cursor)
		if err != nil {
			return nil, err
		}
		collected = append(collected, history.Messages...)
		if !history.HasMore || strings.TrimSpace(history.NextCursor) == "" || cursor == history.NextCursor {
			break
		}
		cursor = history.NextCursor
	}
	if len(collected) == 0 {
		return nil, nil
	}
	sort.SliceStable(collected, func(i, j int) bool {
		if collected[i].OriginServerTS != collected[j].OriginServerTS {
			return collected[i].OriginServerTS < collected[j].OriginServerTS
		}
		return collected[i].EventID < collected[j].EventID
	})
	if len(collected) > groupSummaryMaxMessages {
		collected = collected[len(collected)-groupSummaryMaxMessages:]
	}
	return collected, nil
}

func generateGroupSummary(ctx context.Context, model groupSummaryModel, factory func(coremodel.Profile) (coremodel.Client, error), previous string, messages []capabilityclient.GroupAgentMessage) (string, error) {
	profile, err := model.ResolveDefaultToolProfile(ctx)
	if err != nil {
		return "", err
	}
	profile.SystemPrompt = ""
	profile.MaxOutputTokens = 512
	callCtx, cancel := context.WithTimeout(ctx, groupSummaryCallTimeout)
	defer cancel()
	if factory == nil {
		factory = func(profile coremodel.Profile) (coremodel.Client, error) {
			return coremodel.NewClient(profile, coremodel.WithTimeout(groupSummaryCallTimeout))
		}
	}
	client, err := factory(profile)
	if err != nil {
		return "", err
	}
	var prompt strings.Builder
	if previous = strings.TrimSpace(previous); previous != "" {
		prompt.WriteString("现有摘要：\n")
		prompt.WriteString(previous)
		prompt.WriteString("\n\n")
	}
	prompt.WriteString("新增群聊记录：\n")
	prompt.WriteString(formatGroupTranscript(messages))
	completion, err := client.Generate(callCtx, coremodel.CompletionRequest{Messages: []coremodel.Message{
		{Role: coremodel.RoleSystem, Content: groupSummarySystemPrompt},
		{Role: coremodel.RoleUser, Content: prompt.String()},
	}})
	if err != nil {
		return "", err
	}
	return normalizeGroupSummary(completion.Message.Content), nil
}

// formatGroupTranscript renders the same attribution the shared group
// conversation uses, bounded per message and in total.
func formatGroupTranscript(messages []capabilityclient.GroupAgentMessage) string {
	var out strings.Builder
	written := 0
	for _, message := range messages {
		body := strings.TrimSpace(message.Body)
		if body == "" {
			continue
		}
		if utf8.RuneCountInString(body) > 800 {
			body = string([]rune(body)[:800])
		}
		label := sanitizeGroupAgentSpeakerName(message.SenderDisplayName)
		line := message.SenderMXID + ": " + body
		if label != "" && label != message.SenderMXID {
			line = label + " (" + message.SenderMXID + "): " + body
		}
		written += utf8.RuneCountInString(line) + 1
		if written > groupSummaryMaxTranscriptRunes {
			break
		}
		out.WriteString(line)
		out.WriteString("\n")
	}
	return out.String()
}

// validGroupOwnerMXID accepts only a well-formed Matrix user id: the owner is
// authenticated by the Product service, never by the digest.
func validGroupOwnerMXID(mxid string) bool {
	trimmed := strings.TrimSpace(mxid)
	return len(trimmed) > 1 && len(trimmed) <= 1024 && strings.HasPrefix(trimmed, "@") &&
		strings.Contains(trimmed, ":") && !strings.ContainsAny(trimmed, "\n\r\t ")
}

func normalizeGroupSummary(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if utf8.RuneCountInString(value) > groupSummaryMaxRunes {
		value = string([]rune(value)[:groupSummaryMaxRunes])
	}
	return value
}
