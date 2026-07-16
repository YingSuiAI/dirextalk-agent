package awsreaper

import (
	"testing"

	"github.com/google/uuid"
)

func TestLoadConfigRequiresOnlyNonSecretRuntimeIdentity(t *testing.T) {
	values := map[string]string{
		"AGENT_INSTANCE_ID":       uuid.NewString(),
		"AWS_REGION":              "us-west-2",
		"RESOURCE_MANIFEST_TABLE": "dtx-agent-resources",
	}
	config, err := LoadConfig(func(key string) string { return values[key] })
	if err != nil {
		t.Fatal(err)
	}
	if config.AgentInstanceID != values["AGENT_INSTANCE_ID"] || config.Region != "us-west-2" || config.ManifestTable != "dtx-agent-resources" {
		t.Fatalf("unexpected config: %+v", config)
	}
	for _, key := range []string{"AGENT_INSTANCE_ID", "AWS_REGION", "RESOURCE_MANIFEST_TABLE"} {
		invalid := map[string]string{}
		for current, value := range values {
			invalid[current] = value
		}
		delete(invalid, key)
		if _, err := LoadConfig(func(current string) string { return invalid[current] }); err == nil {
			t.Fatalf("missing %s was accepted", key)
		}
	}
}
