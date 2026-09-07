package cloudworker

import (
	"context"
	"errors"
	"github.com/aws/smithy-go"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/sshworker"
	core "github.com/YingSuiAI/dirextalk-agent/internal/coreconversation"
)

func TestDomainErrorsKeepActionableCauseAndMutationAuthority(t *testing.T) {
	for _, test := range []struct {
		name      string
		err       error
		preflight bool
		outcome   core.ToolObservationOutcome
		mutation  core.ToolMutationState
		want      string
	}{
		{"custom proxy", &DomainOperationError{Stage: "proxy", Cause: sshworker.ErrUnmanagedCaddyConfig}, false, core.ToolOutcomeUserInput, core.ToolMutationChanged, "自定义 Caddy"},
		{"missing baseline", &DomainOperationError{Stage: "proxy", Cause: sshworker.ErrCaddyBaselineUnavailable}, false, core.ToolOutcomeUserInput, core.ToolMutationChanged, "组件缺失"},
		{"read timeout", context.DeadlineExceeded, true, core.ToolOutcomeRetryable, core.ToolMutationUnchanged, "只读检查"},
		{"read throttled", &smithy.GenericAPIError{Code: "Throttling", Message: "private provider detail"}, true, core.ToolOutcomeRetryable, core.ToolMutationUnchanged, "暂时不可用"},
		{"write timeout", &DomainOperationError{Stage: "dns", Cause: context.DeadlineExceeded}, false, core.ToolOutcomeUnknownMutation, core.ToolMutationUnknown, "解析配置"},
		{"HTTPS timeout", &DomainOperationError{Stage: "https", Cause: context.DeadlineExceeded}, false, core.ToolOutcomeUnknownMutation, core.ToolMutationUnknown, "HTTPS 验证"},
		{"bad argument", core.ErrInvalid, true, core.ToolOutcomeInvalid, core.ToolMutationUnchanged, "参数不正确"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := domainToolError(test.err, "帮我绑定域名后搜索主页", test.preflight)
			d, ok := core.ToolExecutionErrorObservation(err)
			if !ok || d.Outcome != test.outcome || d.MutationState != test.mutation || !strings.Contains(d.Summary, test.want) || !errors.Is(err, test.err) {
				t.Fatalf("details=%+v err=%v", d, err)
			}
		})
	}
}
