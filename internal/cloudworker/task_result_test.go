package cloudworker

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	cloudaws "github.com/YingSuiAI/dirextalk-agent/internal/cloudworker/aws"
)

func TestTaskResultSnapshotRetainsDisplayConfigurationAfterCleanupWithoutAuthorityFields(t *testing.T) {
	plan, execution, awsPlan, intent := awsIntegrationFixture(t)
	active := activeAWSGraph(t, awsPlan, intent, intent.RecordedAt.Add(time.Second))
	for index := range active.Resources {
		switch active.Resources[index].Kind {
		case cloudaws.ResourceEC2:
			active.Resources[index].PrivateIP = "10.0.1.24"
		case cloudaws.ResourceEIP:
			active.Resources[index].PublicIP = "198.51.100.24"
		}
	}
	resources, err := ProjectAWSResourceGraph(plan, execution, awsPlan, intent, active, nil)
	if err != nil {
		t.Fatal(err)
	}
	destroyed := active
	destroyed.Resources = slices.Clone(active.Resources)
	destroyed.State = cloudaws.GraphVerifiedDestroyed
	destroyed.ObservedAt = active.ObservedAt.Add(time.Minute)
	for index := range destroyed.Resources {
		destroyed.Resources[index].Exists = false
		destroyed.Resources[index].PrivateIP = ""
		destroyed.Resources[index].PublicIP = ""
		destroyed.Resources[index].ObservedAt = destroyed.ObservedAt
	}
	resources, err = ProjectAWSResourceGraph(plan, execution, awsPlan, intent, destroyed, resources)
	if err != nil {
		t.Fatal(err)
	}
	artifactID := "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	snapshot, err := NewTaskResultSnapshot(plan, resources, []string{artifactID})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ExecutionID != plan.ExecutionID || !slices.Equal(snapshot.ArtifactIDs, []string{artifactID}) ||
		snapshot.ServerSnapshot.Name != intent.StackName || snapshot.ServerSnapshot.Region != plan.AWS.Region ||
		snapshot.ServerSnapshot.PrivateIP != "10.0.1.24" || snapshot.ServerSnapshot.PublicIP != "198.51.100.24" ||
		snapshot.ServerSnapshot.WorkerConfig.InstanceType != plan.Compute.InstanceType ||
		snapshot.ServerSnapshot.WorkerConfig.Architecture != plan.Compute.Architecture ||
		snapshot.ServerSnapshot.WorkerConfig.AMIID != plan.Compute.AMIID ||
		snapshot.ServerSnapshot.WorkerConfig.WorkerReleaseDigest != plan.Compute.WorkerReleaseDigest ||
		snapshot.ServerSnapshot.WorkerConfig.PiRuntimeDigest != plan.Compute.PiRuntimeDigest ||
		snapshot.ServerSnapshot.WorkerConfig.WorkspaceMode != plan.WorkspaceMode ||
		snapshot.ServerSnapshot.WorkerConfig.Limits != plan.Limits {
		t.Fatalf("snapshot did not retain the display configuration: %+v", snapshot)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"account_id", "account_generation", "instance_id", "provider_id", "generation"} {
		if strings.Contains(string(raw), `"`+forbidden+`"`) {
			t.Fatalf("display snapshot leaked authority field %q: %s", forbidden, raw)
		}
	}
}

func TestTaskResultSnapshotAllowsUnavailableWorkerAddresses(t *testing.T) {
	plan, _, _, intent := awsIntegrationFixture(t)
	snapshot, err := NewTaskResultSnapshot(plan, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ServerSnapshot.Name != intent.StackName || snapshot.ServerSnapshot.PrivateIP != "" || snapshot.ServerSnapshot.PublicIP != "" {
		t.Fatalf("snapshot should remain displayable without addresses: %+v", snapshot.ServerSnapshot)
	}
}
