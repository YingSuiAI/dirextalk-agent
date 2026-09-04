package coreconversation

import (
	"encoding/json"
	"strings"

	"github.com/YingSuiAI/dirextalk-agent/internal/coremodel"
)

// A Worker outcome proves the remote execution, not the rest of the user's
// request. Deterministic fallback never promotes partial model prose or the
// internal Worker report into evidence that a follow-up mutation succeeded.
func workerOutcomeFallback(results []ToolResult, prompt string) (string, bool) {
	for i := len(results) - 1; i >= 0; i-- {
		result := results[i]
		if result.ToolName != coremodel.IntrinsicCloudWorkerProposeToolName || result.Validate() != nil {
			continue
		}
		var outcome struct {
			Schema      string `json:"schema"`
			Status      string `json:"status"`
			ExecutionID string `json:"execution_id"`
		}
		if json.Unmarshal([]byte(result.Content), &outcome) != nil || outcome.Schema != "dirextalk.ssh-worker-completion/v1" ||
			!validUUID(outcome.ExecutionID) || (outcome.Status != "succeeded" && outcome.Status != "failed") {
			continue
		}
		language := terminalResponseLanguage(prompt)
		completed := "Worker execution " + outcome.Status + "."
		if language == "zh" {
			if outcome.Status == "succeeded" {
				completed = "Worker 执行成功。"
			} else {
				completed = "Worker 执行失败。"
			}
		} else if language == "ja" {
			if outcome.Status == "succeeded" {
				completed = "Worker の実行が成功しました。"
			} else {
				completed = "Worker の実行が失敗しました。"
			}
		} else if language == "ko" {
			if outcome.Status == "succeeded" {
				completed = "Worker 실행에 성공했습니다."
			} else {
				completed = "Worker 실행에 실패했습니다."
			}
		}
		escape := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\\", "\\\\", "[", "\\[", "]", "\\]", "`", "\\`", "*", "\\*", "_", "\\_")
		for _, reference := range result.References {
			if reference.Kind != "execution_artifact" || reference.RecordKind != "cloud_worker" ||
				reference.ExecutionID != outcome.ExecutionID || reference.Validate() != nil {
				continue
			}
			completed += "\n\n- [" + escape.Replace(reference.Name) + "](dirextalk-artifact://cloud_worker/" + reference.ArtifactID + ")"
		}
		switch language {
		case "zh":
			completed += "\n\n已保留可核验的 Worker 结果；仅凭该结果无法确认发送报告等后续操作已经完成。当前记录无法确定实际费用，仍在运行的计算资源和保留的存储可能继续计费。"
		case "ja":
			completed += "\n\n検証可能な Worker の結果は保存されています。この結果だけでは、レポート送信などの後続操作が完了したことは確認できません。実際の費用は現在の記録からは確認できず、稼働中の計算資源と保持されたストレージには引き続き料金が発生する可能性があります。"
		case "ko":
			completed += "\n\n검증 가능한 Worker 결과는 보존되었습니다. 이 결과만으로는 보고서 전송 같은 후속 작업의 완료를 확인할 수 없습니다. 현재 기록으로 실제 비용을 확인할 수 없으며, 실행 중인 컴퓨팅과 보존된 스토리지에는 계속 비용이 발생할 수 있습니다."
		default:
			completed += "\n\nThe recorded Worker outcome is preserved. The Worker result alone does not confirm requested follow-up actions, such as sending a report. Actual billed cost is unavailable; running compute and retained storage may continue to incur charges."
		}
		return boundedTerminalText(completed, MaxContentBytes), true
	}
	return "", false
}
