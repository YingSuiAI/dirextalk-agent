package coreteamworker

import (
	"os"
	"strings"
	"testing"
)

func TestCoreTeamWorkerProtoExposesOnlyClosedPrivateProtocol(t *testing.T) {
	raw, err := os.ReadFile("../../api/proto/dirextalk/agent/v1/core_team_worker.proto")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, method := range []string{
		"rpc CreateIdentityChallenge(", "rpc Enroll(", "rpc GetAssignment(", "rpc Claim(",
		"rpc Heartbeat(", "rpc EmitMilestone(", "rpc Complete(",
	} {
		if strings.Count(text, method) != 1 {
			t.Fatalf("missing or duplicate Worker RPC %q", method)
		}
	}
	if strings.Count(text, "rpc ") != 7 {
		t.Fatalf("unexpected Worker RPC surface:\n%s", text)
	}
	lower := strings.ToLower(text)
	for _, forbidden := range []string{
		"access_key", "secret_key", "credential", "instance_id", "ami_id", "ip_address", "public_ip",
		"shell_command", "stdout", "stderr", "reasoning", "tool_payload", "log_reference", "provider_error",
		"string message",
	} {
		if strings.Contains(lower, forbidden) {
			t.Fatalf("Worker proto contains forbidden field %q", forbidden)
		}
	}
	for _, required := range []string{
		"message CoreTeamWorkerLeaseFence", "uint32 attempt", "uint64 lease_epoch", "string plan_digest",
		"string runtime_context_digest = 12;",
		"string event_digest", "string result_digest", "google.protobuf.Timestamp expires_at",
		"bytes result_json", "reserved 6;", `reserved "message";`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("Worker proto is missing %q", required)
		}
	}
}
