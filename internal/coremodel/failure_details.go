package coremodel

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// FailureDetails is a bounded public classification, never the provider body.
type FailureDetails struct {
	Code       string
	HTTPStatus int
}

func FailureFromCode(code string) (FailureDetails, bool) {
	switch code {
	case "model_request_invalid", "model_authentication_failed", "model_balance_insufficient", "model_permission_denied", "model_not_found", "model_context_limit", "model_rate_limited", "model_request_timeout", "model_connection_failed", "model_service_unavailable", "provider_rejected", "worker_protocol_invalid", "worker_execution_failed", "worker_runtime_timeout", "provider_request_failed":
		return FailureDetails{Code: code}, true
	}
	return FailureDetails{}, false
}

var safeHTTPStatus = regexp.MustCompile(`\bHTTP ([45][0-9]{2})\b`)

// Decode only our safe status marker, never expose or infer other summary text.
func FailureFromSummary(code, summary string) (FailureDetails, bool) {
	d, ok := FailureFromCode(code)
	if !ok {
		return d, false
	}
	if match := safeHTTPStatus.FindStringSubmatch(summary); len(match) == 2 {
		status, _ := strconv.Atoi(match[1])
		if HTTPFailureDetails(status).Code == code {
			d.HTTPStatus = status
		}
	}
	return d, true
}

func (d FailureDetails) RequiresUserAction() bool {
	switch d.Code {
	case "model_authentication_failed", "model_balance_insufficient", "model_permission_denied", "model_not_found", "model_request_invalid", "model_context_limit":
		return true
	}
	return false
}

func HTTPFailureDetails(status int) FailureDetails {
	code := "provider_rejected"
	switch status {
	case 400, 422:
		code = "model_request_invalid"
	case 401:
		code = "model_authentication_failed"
	case 402:
		code = "model_balance_insufficient"
	case 403:
		code = "model_permission_denied"
	case 404:
		code = "model_not_found"
	case 408, 504:
		code = "model_request_timeout"
	case 413:
		code = "model_context_limit"
	case 429:
		code = "model_rate_limited"
	default:
		if status >= 500 {
			code = "model_service_unavailable"
		}
	}
	return FailureDetails{Code: code, HTTPStatus: status}
}

func ProviderFailureDetails(err error) (FailureDetails, bool) {
	var status *providerHTTPStatusError
	if errors.As(err, &status) {
		return HTTPFailureDetails(status.statusCode), true
	}
	switch {
	case errors.Is(err, ErrProviderConnectFailure):
		return FailureDetails{Code: "model_connection_failed"}, true
	case errors.Is(err, ErrStreamIdleTimeout), errors.Is(err, ErrProviderTimeout), errors.Is(err, context.DeadlineExceeded):
		return FailureDetails{Code: "model_request_timeout"}, true
	case errors.Is(err, ErrModelToolCallFormatInvalid):
		return FailureDetails{Code: "MODEL_TOOL_CALL_FORMAT_INVALID"}, true
	}
	return FailureDetails{}, false
}

func (d FailureDetails) Message(language string) string {
	en, zh := "The operation failed. Check the error type before retrying.", "操作失败，请根据错误类型检查后重试。"
	switch d.Code {
	case "model_balance_insufficient":
		en, zh = "The model account has insufficient balance. Add credit or select an available model before retrying.", "模型账户余额不足，请充值或选择可用模型后再重试。"
	case "model_authentication_failed":
		en, zh = "The model credential was rejected. Check the API key.", "模型凭据验证失败，请检查 API Key。"
	case "model_permission_denied":
		en, zh = "The model provider denied access. Check model permissions or regional restrictions.", "模型服务拒绝访问，请检查模型权限或地区限制。"
	case "model_not_found":
		en, zh = "The configured model or API endpoint was not found.", "找不到配置的模型或 API 地址。"
	case "model_request_invalid":
		en, zh = "The model provider rejected the request format or parameters.", "模型服务拒绝了请求格式或参数。"
	case "model_context_limit":
		en, zh = "The request exceeds the model's input or context limit.", "请求超出模型的输入或上下文长度限制。"
	case "model_rate_limited":
		en, zh = "The model provider rate limit was reached. Wait before retrying.", "模型服务触发限流，请稍后重试。"
	case "model_request_timeout":
		en, zh = "The model request timed out.", "模型请求超时。"
	case "model_connection_failed":
		en, zh = "The model service could not be reached. Check its network connection.", "无法连接模型服务，请检查网络连接。"
	case "model_service_unavailable":
		en, zh = "The model provider is temporarily unavailable.", "模型服务暂时不可用。"
	case "MODEL_TOOL_CALL_FORMAT_INVALID":
		en, zh = "The model returned an invalid tool-call format.", "模型返回了无效的工具调用格式。"
	case "worker_protocol_invalid":
		en, zh = "The Worker runtime returned an invalid event stream.", "Worker 运行时返回了无效的事件流。"
	case "worker_execution_failed":
		en, zh = "The remote task exited unsuccessfully. Its completion could not be verified.", "远端任务异常退出，无法确认操作已完成。"
	case "worker_runtime_timeout":
		en, zh = "The remote task exceeded its execution time limit.", "远端任务超过执行时限。"
	case "provider_request_failed":
		en, zh = "The Worker model request failed without a provider HTTP status.", "Worker 模型请求失败，服务未返回 HTTP 状态。"
	}
	message := en
	if language == "zh" {
		message = zh
	}
	if d.HTTPStatus > 0 {
		return fmt.Sprintf("%s（%s，HTTP %d）", message, d.Code, d.HTTPStatus)
	}
	return fmt.Sprintf("%s（%s）", message, d.Code)
}
