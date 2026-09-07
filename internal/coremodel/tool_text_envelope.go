package coremodel

import "strings"

const (
	dsmlToolCallsEnvelope = "<｜｜DSML｜｜tool_calls>"
	dsmlInvokePrefix      = "<｜｜DSML｜｜invoke"
)

var textToolCallEnvelopeMarkers = []string{
	dsmlToolCallsEnvelope,
	"<|dsml|tool_calls>",
	"<｜dsml｜tool_calls>",
	"<｜tool▁calls▁begin｜>",
	"<|tool_calls_begin|>",
	"<tool_calls>",
	"<tool_call>",
	"<function_calls>",
	"<function_call>",
}

// ContainsUnquotedToolCallEnvelope recognizes known provider text-protocol
// shapes outside Markdown code and quote blocks. A bare envelope at a protocol
// line is sufficient to quarantine a truncated response. Ordinary inline
// mentions remain text, and repository examples can be preserved by quoting or
// fencing them. The detector never parses a name or arguments.
func ContainsUnquotedToolCallEnvelope(content string) bool {
	visible := markdownProtocolText(content)
	lowerVisible := strings.ToLower(visible)
	for _, marker := range textToolCallEnvelopeMarkers {
		marker = strings.ToLower(marker)
		searchAt := 0
		for searchAt < len(lowerVisible) {
			relative := strings.Index(lowerVisible[searchAt:], marker)
			if relative < 0 {
				break
			}
			start := searchAt + relative
			after := lowerVisible[start+len(marker):]
			trimmed := strings.TrimLeft(after, " \t\r\n")
			lineStart := strings.LastIndexByte(lowerVisible[:start], '\n') + 1
			protocolPosition := strings.TrimSpace(lowerVisible[lineStart:start]) == ""
			if protocolPosition || trimmed == "" || strings.HasPrefix(trimmed, strings.ToLower(dsmlInvokePrefix)) {
				return true
			}
			searchAt = start + len(marker)
		}
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
