package cloudworker

import (
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestCloudWorkerPublicProtoUsesStrictSecretAndAuthorityProjections(t *testing.T) {
	file := agentv1.File_dirextalk_agent_v1_core_cloud_worker_proto
	if file == nil {
		t.Fatal("Cloud Worker descriptor is missing")
	}
	grant := file.Messages().ByName("CoreCloudWorkerSecretGrantProjection")
	if grant == nil || grant.Fields().Len() != 1 {
		t.Fatalf("public secret grant shape=%v", grant)
	}
	purpose := grant.Fields().ByName("purpose")
	if purpose == nil || purpose.Kind() != protoreflect.StringKind {
		t.Fatal("public secret grant must expose only a string purpose")
	}
	planGrant := file.Messages().ByName("CoreCloudWorkerPlan").Fields().ByName("secret_grants")
	if planGrant == nil || planGrant.Message() != grant || planGrant.Number() != 26 {
		t.Fatalf("plan secret grant field=%v", planGrant)
	}
	cancellation := file.Messages().ByName("CoreCloudWorkerExecution").Fields().ByName("cancellation_requested")
	if cancellation == nil || cancellation.Number() != 25 || cancellation.Kind() != protoreflect.BoolKind {
		t.Fatalf("execution cancellation field=%v", cancellation)
	}
	artifact := file.Messages().ByName("CoreCloudWorkerArtifact")
	if owner := artifact.Fields().ByName("owner_id"); owner == nil || owner.Kind() != protoreflect.StringKind {
		t.Fatal("artifact owner_id is missing")
	}
	if generation := artifact.Fields().ByName("account_generation"); generation == nil || generation.Kind() != protoreflect.Uint64Kind {
		t.Fatal("artifact account_generation is missing")
	}
}
