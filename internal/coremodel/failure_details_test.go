package coremodel

import (
	"strings"
	"testing"
)

func TestHTTPFailureDetailsPreserveExactStatusAndMeaning(t *testing.T) {
	for _, test := range []struct {
		status   int
		code, zh string
	}{{400, "model_request_invalid", "参数"}, {401, "model_authentication_failed", "凭据"}, {402, "model_balance_insufficient", "余额"}, {403, "model_permission_denied", "权限"}, {404, "model_not_found", "找不到"}, {408, "model_request_timeout", "超时"}, {413, "model_context_limit", "上下文"}, {422, "model_request_invalid", "参数"}, {429, "model_rate_limited", "限流"}, {503, "model_service_unavailable", "不可用"}, {504, "model_request_timeout", "超时"}} {
		d := HTTPFailureDetails(test.status)
		if d.Code != test.code || d.HTTPStatus != test.status || !strings.Contains(d.Message("zh"), test.zh) {
			t.Fatalf("wrong failure: %+v", d)
		}
		restored, ok := FailureFromSummary(d.Code, d.Message("en"))
		if !ok || restored != d {
			t.Fatalf("status was collapsed in durable summary: %+v want=%+v", restored, d)
		}
	}
}
