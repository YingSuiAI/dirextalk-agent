package coreruntime

import (
	"net/url"
	"strings"
)

const (
	dsmlToolCallsEnvelope = "<｜｜DSML｜｜tool_calls>"
	dsmlInvokePrefix      = "<｜｜DSML｜｜invoke"

	modelToolCallFormatRecoveryInstruction = `The previous response used text markup for a tool call. If a tool is needed, return it only through the standard OpenAI-compatible message.tool_calls field. Do not put DSML, XML, or any other tool-call markup in message content. Do not describe or imitate a tool call in plain text. If no tool is needed, return a normal final answer.`
	modelToolFreeFormatRecoveryInstruction = `The previous response used text markup for a tool call, but tools are disabled for this final response. Return only a normal final answer. Do not put DSML, XML, or any other tool-call markup in message content. Do not describe or imitate a tool call in plain text.`
	deepSeekStructuredToolInstruction      = `This request uses the OpenAI-compatible structured tool protocol. When a tool is needed, emit it only through message.tool_calls with a declared function name and JSON arguments. Never emit DSML, XML, or tool-call markup in message content. Ordinary message content is never interpreted as a tool call.`
)

type toolCallTextGuard struct {
	enabled        bool
	detectDSML     bool
	suspicious     bool
	suppressPublic bool
	discardContent bool
}

func newToolCallTextGuard(enabled, detectDSML bool) *toolCallTextGuard {
	return &toolCallTextGuard{enabled: enabled, detectDSML: detectDSML}
}

// Append withholds model-authored content until the complete provider
// response establishes whether it is a final answer or a tool-use step. The
// guard never parses names or arguments and never turns text into an
// executable call.
func (g *toolCallTextGuard) Append(fragment string, emit func(string) error) error {
	if fragment == "" {
		return nil
	}
	if !g.enabled {
		return emitText(fragment, emit)
	}
	return nil
}

// Finish publishes only a validated final answer. Model-authored content from
// a structured tool-use step stays private, while protocol-shaped DSML in the
// ordinary content channel is quarantined regardless of any natural-language
// prefix. Structured calls remain the sole execution authority.
func (g *toolCallTextGuard) Finish(content string, hasStructuredToolCalls bool, emit func(string) error) (bool, error) {
	if !g.enabled {
		return false, nil
	}
	g.suspicious = g.detectDSML && containsUnquotedDSMLToolEnvelope(content)
	g.suppressPublic = g.suspicious || hasStructuredToolCalls
	g.discardContent = g.suspicious
	if g.suppressPublic {
		return g.suspicious && !hasStructuredToolCalls, nil
	}
	return false, emitText(content, emit)
}

func (g *toolCallTextGuard) DiscardContent() bool {
	return g != nil && g.discardContent
}

func emitText(text string, emit func(string) error) error {
	if text == "" || emit == nil {
		return nil
	}
	return emit(text)
}

// containsUnquotedDSMLToolEnvelope recognizes only the provider's protocol
// shape outside Markdown code and quote blocks. A bare envelope is sufficient
// to quarantine a truncated response. Ordinary inline mentions remain text,
// and repository examples can be preserved by quoting or fencing them.
func containsUnquotedDSMLToolEnvelope(content string) bool {
	visible := markdownProtocolText(content)
	searchAt := 0
	for searchAt < len(visible) {
		relative := strings.Index(visible[searchAt:], dsmlToolCallsEnvelope)
		if relative < 0 {
			return false
		}
		start := searchAt + relative
		after := visible[start+len(dsmlToolCallsEnvelope):]
		trimmed := strings.TrimLeft(after, " \t\r\n")
		lineStart := strings.LastIndexByte(visible[:start], '\n') + 1
		protocolPosition := strings.TrimSpace(visible[lineStart:start]) == ""
		if protocolPosition || trimmed == "" || strings.HasPrefix(trimmed, dsmlInvokePrefix) {
			return true
		}
		searchAt = start + len(dsmlToolCallsEnvelope)
	}
	return false
}

func markdownProtocolText(content string) string {
	lines := strings.SplitAfter(content, "\n")
	var visible strings.Builder
	var fence byte
	var fenceWidth int
	for _, line := range lines {
		body := strings.TrimSuffix(line, "\n")
		trimmed := strings.TrimLeft(body, " \t")
		marker, width := markdownFenceMarker(trimmed)
		if fence != 0 {
			if marker == fence && width >= fenceWidth {
				fence, fenceWidth = 0, 0
			}
			visible.WriteByte('\n')
			continue
		}
		if marker != 0 {
			fence, fenceWidth = marker, width
			visible.WriteByte('\n')
			continue
		}
		if strings.HasPrefix(trimmed, ">") {
			visible.WriteByte('\n')
			continue
		}
		visible.WriteString(stripMarkdownCodeSpans(body))
		visible.WriteByte('\n')
	}
	return visible.String()
}

func markdownFenceMarker(line string) (byte, int) {
	if len(line) < 3 || line[0] != '`' && line[0] != '~' {
		return 0, 0
	}
	marker := line[0]
	width := 1
	for width < len(line) && line[width] == marker {
		width++
	}
	if width < 3 {
		return 0, 0
	}
	return marker, width
}

func stripMarkdownCodeSpans(line string) string {
	var visible strings.Builder
	for offset := 0; offset < len(line); {
		if line[offset] != '`' {
			visible.WriteByte(line[offset])
			offset++
			continue
		}
		width := 1
		for offset+width < len(line) && line[offset+width] == '`' {
			width++
		}
		closing := strings.Index(line[offset+width:], strings.Repeat("`", width))
		if closing < 0 {
			visible.WriteString(line[offset:])
			break
		}
		offset += width + closing + width
	}
	return visible.String()
}

func isOpenAIToolProtocol(profileProvider string, requestDialect string, toolCount int, guardToolFree bool) bool {
	if (toolCount == 0 && !guardToolFree) || profileProvider != "openai_compatible" {
		return false
	}
	return requestDialect == "openai_compatible_chat_v1" || requestDialect == "openai_reasoning_chat_v1"
}

// isDeepSeekToolProtocol recognizes both the first-party API and DeepSeek
// models routed through an OpenAI-compatible gateway. The result changes only
// provider protocol guidance; it does not expand the admitted tool set or
// trust model-authored content.
func isDeepSeekToolProtocol(baseURL, model string) bool {
	if parsed, err := url.Parse(strings.TrimSpace(baseURL)); err == nil && strings.EqualFold(parsed.Hostname(), "api.deepseek.com") {
		return true
	}
	model = strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(model, "deepseek-") || strings.HasPrefix(model, "deepseek/") || strings.Contains(model, "/deepseek-")
}

func appendDeepSeekStructuredToolInstruction(systemPrompt string) string {
	systemPrompt = strings.TrimSpace(systemPrompt)
	if systemPrompt == "" {
		return deepSeekStructuredToolInstruction
	}
	return systemPrompt + "\n\n" + deepSeekStructuredToolInstruction
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
