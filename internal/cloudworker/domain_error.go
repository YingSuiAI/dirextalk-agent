package cloudworker

import (
	"context"
	"errors"
	"net"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworkload"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
	"github.com/aws/smithy-go"
)

// DomainOperationError retains the exact failing phase without exposing raw
// SSH/provider output. Cause remains available for typed classification.
type DomainOperationError struct {
	Stage string
	Cause error
}

func (e *DomainOperationError) Error() string { return "domain operation failed during " + e.Stage }
func (e *DomainOperationError) Unwrap() error { return e.Cause }

func domainToolError(err error, prompt string, preflight bool) error {
	if err == nil {
		return nil
	}
	var phase *DomainOperationError
	if errors.As(err, &phase) && phase.Stage == "preflight" {
		preflight = true
	}
	choose := func(en, zh string) string {
		if core.ResponseLanguage(prompt) == "zh" {
			return zh
		}
		return en
	}
	outcome, mutation := core.ToolOutcomeUnknownMutation, core.ToolMutationUnknown
	summary := choose("Domain binding is incomplete; check the current configuration before retrying.", "域名操作未完成，当前配置可能已有部分变更，需要先确认状态再重试。")
	if preflight {
		outcome, mutation = core.ToolOutcomeFatal, core.ToolMutationUnchanged
		summary = choose("Could not verify the Worker or DNS state; no binding operation was started.", "未能确认服务器或域名状态，因此没有开始修改域名。")
	}
	if errors.As(err, &phase) {
		switch phase.Stage {
		case "proxy":
			summary = choose("Reverse-proxy setup failed; the domain is not ready. Check the server configuration before retrying.", "服务器的反向代理配置失败，域名尚不可用，需要检查访问配置后再重试。")
		case "ports":
			summary = choose("Server network access could not be configured; the domain is not ready.", "服务器的访问端口未能配置完成，域名尚不可用。")
		case "dns":
			summary = choose("DNS configuration or read-back failed. Verify the current record before retrying.", "域名解析配置或核验失败，需要先确认当前解析记录，不能直接重复修改。")
		case "https":
			summary = choose("HTTPS verification failed after configuration. Check DNS and certificate readiness before retrying.", "域名配置后的 HTTPS 验证未通过，需要检查解析和证书状态；现有配置可能已部分生效。")
		case "persistence":
			summary = choose("Could not save the verified domain result. Check the current binding before retrying.", "域名结果未能保存，需要先核对已生效的绑定，避免重复操作。")
		}
	}
	var network net.Error
	var api smithy.APIError
	switch {
	case errors.Is(err, sshworker.ErrUnmanagedCaddyConfig):
		outcome, mutation = core.ToolOutcomeUserInput, core.ToolMutationChanged
		summary = choose("Domain binding stopped because the server has a custom Caddy configuration. It was preserved; an administrator must explicitly integrate this domain.", "域名绑定已停止：服务器存在自定义 Caddy 配置，系统没有覆盖它，需要管理员确认如何接入这个域名。")
	case errors.Is(err, sshworker.ErrCaddyBaselineUnavailable):
		outcome, mutation = core.ToolOutcomeUserInput, core.ToolMutationChanged
		summary = choose("The server's reverse-proxy baseline is missing or could not be verified. Repair the server environment before binding the domain.", "服务器的反向代理组件缺失，或无法核验其默认配置。需要先修复服务器环境，再绑定域名。")
	case errors.Is(err, ErrRetainedWorkerPublicRoute53Required):
		outcome, mutation = core.ToolOutcomeUserInput, core.ToolMutationUnchanged
		summary = choose("The requested hostname is not managed by a public Route53 zone in this AWS account. Check domain ownership and DNS hosting; no resources were changed.", "当前 AWS 账号没有管理这个域名的公共 Route53 区域。请确认域名归属和 DNS 托管配置；系统未修改资源。")
	case errors.As(err, &api) && (api.ErrorCode() == "AccessDenied" || api.ErrorCode() == "AccessDeniedException" || api.ErrorCode() == "UnauthorizedOperation" || api.ErrorCode() == "ExpiredToken"):
		outcome = core.ToolOutcomeAuth
		mutation = core.ToolMutationChanged
		if preflight {
			mutation = core.ToolMutationUnchanged
		}
		summary = choose("AWS denied the domain operation. Check the current credential and Route53/network permissions before retrying.", "AWS 拒绝了这次域名操作，请检查当前凭据及 Route53、网络操作权限，再确认配置状态。")
	case preflight && (errors.Is(err, sshworkload.ErrNotFound) || errors.Is(err, core.ErrInvalid) || errors.Is(err, ErrInvalid)):
		outcome = core.ToolOutcomeInvalid
		summary = choose("The Worker/service ID or hostname is invalid. Use the exact IDs from inventory and correct the arguments once; nothing was changed.", "服务器、服务标识或域名参数不正确，请使用库存查询返回的准确标识修正一次；系统未修改资源。")
	case preflight && (errors.Is(err, sshworker.ErrIdentity) || errors.Is(err, ErrStaleAuthorization)):
		outcome = core.ToolOutcomeUserInput
		summary = choose("The Worker or credential identity changed. Refresh inventory and verify authorization before trying again; nothing was changed.", "服务器或凭据身份已发生变化，需要刷新库存并核验权限后再尝试；系统未修改资源。")
	case preflight && (errors.As(err, &network) && network.Timeout() || errors.Is(err, context.DeadlineExceeded)):
		outcome = core.ToolOutcomeRetryable
		summary = choose("The read-only domain preflight timed out before any changes; one retry is allowed.", "域名操作前的只读检查暂时超时，尚未修改资源，可以重试一次。")
	case preflight && errors.As(err, &api) && (api.ErrorCode() == "Throttling" || api.ErrorCode() == "ThrottlingException" || api.ErrorCode() == "RequestLimitExceeded" || api.ErrorCode() == "ServiceUnavailable" || api.ErrorCode() == "InternalFailure"):
		outcome = core.ToolOutcomeRetryable
		summary = choose("The DNS provider is temporarily unavailable during read-only preflight; no changes were made and one retry is allowed.", "域名服务在只读检查阶段暂时不可用，尚未修改资源，可以重试一次。")
	default:
		if _, ok := core.ToolExecutionErrorObservation(err); ok {
			return err
		}
	}
	return core.NewToolExecutionErrorWithMutation(outcome, summary, 0, mutation, err)
}
