package coreruntime

import (
	"strings"
	"unicode"
)

const (
	dsmlToolCallsEnvelope = "<｜｜DSML｜｜tool_calls>"
	dsmlInvokePrefix      = "<｜｜DSML｜｜invoke"

	modelToolCallFormatRecoveryInstruction = `The previous response used text markup for a tool call. If a tool is needed, return it only through the standard OpenAI-compatible message.tool_calls field. Do not put DSML, XML, or any other tool-call markup in message content. Do not describe or imitate a tool call in plain text. If no tool is needed, return a normal final answer.`
	modelToolFreeFormatRecoveryInstruction = `The previous response used text markup for a tool call, but tools are disabled for this final response. Return only a normal final answer. Do not put DSML, XML, or any other tool-call markup in message content. Do not describe or imitate a tool call in plain text.`
)

type toolCallTextGuard struct {
	enabled    bool
	safe       bool
	suspicious bool
	pending    strings.Builder
}

func newToolCallTextGuard(enabled bool) *toolCallTextGuard {
	return &toolCallTextGuard{enabled: enabled, safe: !enabled}
}

// Append holds only a possible leading DSML tool envelope. The guard never
// parses names or arguments and never turns text into an executable call.
func (g *toolCallTextGuard) Append(fragment string, emit func(string) error) error {
	if fragment == "" {
		return nil
	}
	if g.safe {
		return emitText(fragment, emit)
	}
	g.pending.WriteString(fragment)
	possible, suspicious := classifyLeadingDSMLToolEnvelope(g.pending.String())
	if suspicious {
		g.suspicious = true
		return nil
	}
	if possible {
		return nil
	}
	g.safe = true
	pending := g.pending.String()
	g.pending.Reset()
	return emitText(pending, emit)
}

// Finish returns true only when a complete leading DSML tool envelope was
// quarantined and the provider supplied no structured tool calls. Suspicious
// text is discarded when structured calls are present as well; structured
// calls remain the sole execution authority.
func (g *toolCallTextGuard) Finish(hasStructuredToolCalls bool, emit func(string) error) (bool, error) {
	if g.safe {
		return false, nil
	}
	if g.suspicious {
		g.pending.Reset()
		return !hasStructuredToolCalls, nil
	}
	pending := g.pending.String()
	g.pending.Reset()
	g.safe = true
	return false, emitText(pending, emit)
}

func (g *toolCallTextGuard) DiscardContent() bool {
	return g != nil && g.suspicious
}

func emitText(text string, emit func(string) error) error {
	if text == "" || emit == nil {
		return nil
	}
	return emit(text)
}

func classifyLeadingDSMLToolEnvelope(content string) (possible, suspicious bool) {
	trimmed := strings.TrimLeftFunc(content, unicode.IsSpace)
	if trimmed == "" || strings.HasPrefix(dsmlToolCallsEnvelope, trimmed) {
		return true, false
	}
	if !strings.HasPrefix(trimmed, dsmlToolCallsEnvelope) {
		return false, false
	}
	remainder := strings.TrimLeftFunc(strings.TrimPrefix(trimmed, dsmlToolCallsEnvelope), unicode.IsSpace)
	if remainder == "" || strings.HasPrefix(dsmlInvokePrefix, remainder) {
		return true, false
	}
	if strings.HasPrefix(remainder, dsmlInvokePrefix) {
		return true, true
	}
	return false, false
}

func isOpenAIToolProtocol(profileProvider string, requestDialect string, toolCount int, guardToolFree bool) bool {
	if (toolCount == 0 && !guardToolFree) || profileProvider != "openai_compatible" {
		return false
	}
	return requestDialect == "openai_compatible_chat_v1" || requestDialect == "openai_reasoning_chat_v1"
}

func appendToolCallFormatRecoveryInstruction(systemPrompt string, toolsAvailable bool) string {
	instruction := modelToolCallFormatRecoveryInstruction
	if !toolsAvailable {
		instruction = modelToolFreeFormatRecoveryInstruction
	}
	systemPrompt = strings.TrimSpace(systemPrompt)
	if systemPrompt == "" {
		return instruction
	}
	return systemPrompt + "\n\n" + instruction
}
