package postgres

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/cloudworker"
)

func TestCloudWorkerPrivatePlanSerializesGitHubBindingWithoutPublicLeak(t *testing.T) {
	binding := &cloudworker.GitHubBinding{OwnerID: "@owner:example.test", AccountGeneration: 7, ConfigRevision: 3, CredentialVersion: 5}
	if err := binding.Seal(); err != nil {
		t.Fatal(err)
	}
	public, err := json.Marshal(cloudworker.Plan{GitHubBinding: binding})
	if err != nil {
		t.Fatal(err)
	}
	private, err := json.Marshal(privateCloudWorkerPlan{GitHubBinding: binding})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(public), "github_binding") || !strings.Contains(string(private), `"github_binding"`) || strings.Contains(string(private), "github_pat") || strings.Contains(string(private), "RIVER-LANTERN-PAT") {
		t.Fatalf("GitHub binding serialization leaked or omitted: public=%s private=%s", public, private)
	}
}
