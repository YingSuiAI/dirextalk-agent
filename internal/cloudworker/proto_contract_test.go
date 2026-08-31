package cloudworker

import (
	"testing"

	agentv1 "github.com/YingSuiAI/dirextalk-agent/api/gen/dirextalk/agent/v1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestCloudWorkerPublicProtoMatchesDynamicSSHPublicProjection(t *testing.T) {
	file := agentv1.File_dirextalk_agent_v1_core_cloud_worker_proto
	if file == nil {
		t.Fatal("Cloud Worker descriptor is missing")
	}
	compute := file.Messages().ByName("CoreCloudWorkerComputeProjection")
	if compute.Fields().ByName("vcpu") == nil || compute.Fields().ByName("memory_gib") == nil || compute.Fields().ByName("accelerator_type") == nil ||
		compute.Fields().ByName("accelerator_name") == nil || compute.Fields().ByName("accelerator_memory_mib") == nil {
		t.Fatalf("compute projection=%v", compute)
	}
	quote := file.Messages().ByName("CoreCloudWorkerQuote")
	if hourly := quote.Fields().ByName("compute_micros_per_hour"); hourly == nil || hourly.Kind() != protoreflect.Uint64Kind {
		t.Fatalf("hourly compute price=%v", hourly)
	}
	execution := file.Messages().ByName("CoreCloudWorkerExecution")
	if execution.Fields().ByName("worker_id") == nil || execution.Fields().ByName("persistent_worker") == nil {
		t.Fatalf("execution projection=%v", execution)
	}
	artifact := file.Messages().ByName("CoreCloudWorkerArtifact")
	if owner := artifact.Fields().ByName("owner_id"); owner == nil || owner.Kind() != protoreflect.StringKind {
		t.Fatal("artifact owner_id is missing")
	}
	if generation := artifact.Fields().ByName("account_generation"); generation == nil || generation.Kind() != protoreflect.Uint64Kind {
		t.Fatal("artifact account_generation is missing")
	}
}
