package coreconversation

import "strings"

// The provider may itself be unavailable. Keep the specific safe observation
// instead of dumping successful tool names or pretending all work completed.
func terminalToolFailureMarkdown(result ToolResult, prompt string) string {
	summary := strings.TrimSpace(result.Summary)
	if summary == "Core intrinsic operation failed" || summary == "tool execution failed" {
		if ResponseLanguage(prompt) == "zh" {
			summary = "这次工具操作未能完成，系统没有获得可核验的成功结果。"
		} else {
			summary = "The operation did not produce a verified successful result."
		}
	}
	if ResponseLanguage(prompt) == "zh" {
		if result.MutationState == ToolMutationUnknown {
			return boundedTerminalText(summary+"\n\n操作是否已部分生效还需确认，不能直接重复修改；后续任务尚未完成。", MaxContentBytes)
		}
		return boundedTerminalText(summary+"\n\n后续任务尚未完成。", MaxContentBytes)
	}
	if result.MutationState == ToolMutationUnknown {
		return boundedTerminalText(summary+"\n\nCheck whether any changes took effect before retrying. Follow-up work is incomplete.", MaxContentBytes)
	}
	return boundedTerminalText(summary+"\n\nFollow-up work is incomplete.", MaxContentBytes)
}
