package coreruntime

import (
	"net/url"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
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
	g.suspicious = g.detectDSML && coremodel.ContainsUnquotedToolCallEnvelope(content)
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
