package recipe

import (
	"strings"
	"testing"
	"time"
)

func TestRecipeDigestCanonicalizesSetLikeFields(t *testing.T) {
	left := validRecipe()
	leftDigest, err := left.Digest()
	if err != nil {
		t.Fatal(err)
	}

	right := left
	right.Sources = []SourceV1{left.Sources[1], left.Sources[0]}
	right.Install.CheckpointNames = []string{"verified", "installed"}
	right.Install.AllowedAdaptations = []string{"retry package download", "select compatible package mirror"}
	right.Install.Adaptations = []AdaptationRuleV1{left.Install.Adaptations[1], left.Install.Adaptations[0]}
	right.Install.Steps = append([]InstallStepV1(nil), left.Install.Steps...)
	right.Install.Steps[0].Inputs = []ActionInputV1{left.Install.Steps[0].Inputs[1], left.Install.Steps[0].Inputs[0]}
	right.Requirements.DataLocations = append([]DataLocationRequirementV1(nil), left.Requirements.DataLocations...)
	right.Requirements.DataLocations[0].Residency = []string{"aws:us-west-2", "aws:us-east-1"}
	right.VolumeSlots = []VolumeSlotRequirementV1{left.VolumeSlots[1], left.VolumeSlots[0]}
	right.SecretSlots = []SecretSlotRequirementV1{left.SecretSlots[1], left.SecretSlots[0]}
	right.Network = cloneNetwork(left.Network)
	right.Network.Outbound = []OutboundRuleV1{left.Network.Outbound[1], left.Network.Outbound[0]}
	right.Network.Listeners = []ListenerV1{left.Network.Listeners[1], left.Network.Listeners[0]}
	right.Restart = cloneRestart(left.Restart)
	right.Restart.RecoveryCheckpoints = []string{"verified", "installed"}
	right.Integrations = []IntegrationDeclarationV1{left.Integrations[1], left.Integrations[0]}

	rightDigest, err := right.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("set ordering changed recipe digest: %s != %s", leftDigest, rightDigest)
	}

	right.Install.Steps[0].Summary = "Install a different locked artifact"
	changed, err := right.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if changed == leftDigest {
		t.Fatal("material install change did not change recipe digest")
	}
}

func TestRecipeRejectsCredentialBearingSourcesAndText(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RecipeV1)
	}{
		{"source userinfo", func(r *RecipeV1) { r.Sources[0].URL = "https://user:pass@example.com/release" }},
		{"signed source", func(r *RecipeV1) { r.Sources[0].URL = "https://example.com/release?X-Amz-Signature=opaque" }},
		{"source fragment", func(r *RecipeV1) { r.Sources[0].URL = "https://example.com/release#access-token" }},
		{"credential canary", func(r *RecipeV1) { r.Install.Steps[0].Summary = "use sk_" + strings.Repeat("a", 32) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recipe := validRecipe()
			test.mutate(&recipe)
			if err := recipe.Validate(); err == nil {
				t.Fatal("Validate() accepted credential-bearing recipe data")
			}
		})
	}
}

func TestRecipeRequiresRetrievedContentDigestAlongsideArtifactDigest(t *testing.T) {
	t.Parallel()
	recipe := validRecipe()
	recipe.Sources[0].ContentDigest = ""
	if err := recipe.Validate(); err == nil || !strings.Contains(err.Error(), "content_digest") {
		t.Fatalf("missing retrieved content digest error = %v", err)
	}
}

func TestRecipeInstallerCapabilityBindsExactCommandWithoutShellSurface(t *testing.T) {
	value := validRecipe()
	value.Sources[0].ID = "service-release"
	root := "/usr/local/share/dirextalk-worker/artifacts"
	value.Install.Installer = &InstallerCapabilityV1{
		Artifacts: []InstallerArtifactV1{{Name: "service-installer", SourceID: "service-release", SizeBytes: 1024, TargetPath: root + "/service-installer"}},
		Commands: []InstallerCommandV1{{
			CommandID: "install-service", Argv: []string{root + "/service-installer", "install"}, WorkingDirectory: root,
			TimeoutSeconds: 120, ArtifactRefs: []string{"service-installer"},
		}},
	}
	value.Install.Steps[0].Action = "installer.execute"
	value.Install.Steps[0].TimeoutSeconds = 120
	value.Install.Steps[0].Inputs = []ActionInputV1{{Name: "command_id", Kind: ActionInputConfig, Ref: "install-service"}}
	if err := value.Validate(); err != nil {
		t.Fatalf("valid exact installer capability rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*RecipeV1)
	}{
		{name: "shell", mutate: func(recipe *RecipeV1) { recipe.Install.Installer.Commands[0].Argv[0] = "/bin/sh" }},
		{name: "unlocked executable", mutate: func(recipe *RecipeV1) { recipe.Install.Installer.Commands[0].Argv[0] = root + "/other" }},
		{name: "unknown artifact", mutate: func(recipe *RecipeV1) { recipe.Install.Installer.Commands[0].ArtifactRefs[0] = "other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := value
			installer := *value.Install.Installer
			installer.Artifacts = append([]InstallerArtifactV1(nil), value.Install.Installer.Artifacts...)
			installer.Commands = append([]InstallerCommandV1(nil), value.Install.Installer.Commands...)
			installer.Commands[0].Argv = append([]string(nil), value.Install.Installer.Commands[0].Argv...)
			installer.Commands[0].ArtifactRefs = append([]string(nil), value.Install.Installer.Commands[0].ArtifactRefs...)
			changed.Install.Installer = &installer
			test.mutate(&changed)
			if err := changed.Validate(); err == nil {
				t.Fatal("unsafe installer capability was accepted")
			}
		})
	}
}

func TestRecipeRejectsUnsafeNetworkAndExecutableActions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*RecipeV1)
	}{
		{"implicit allow", func(r *RecipeV1) { r.Network.DefaultDeny = false }},
		{"wildcard egress", func(r *RecipeV1) { r.Network.Outbound[0].Destination = "*" }},
		{"unencrypted egress", func(r *RecipeV1) { r.Network.Outbound[0].Protocol = NetworkProtocol("http") }},
		{"public worker bind", func(r *RecipeV1) { r.Network.Listeners[0].BindScope = ListenerBindScope("public") }},
		{"public ingress without tls", func(r *RecipeV1) {
			r.Network.PublicIngress = PublicIngressV1{Mode: PublicIngressManagedTLS, ListenerID: "service", AuthenticationRequired: true}
		}},
		{"private source address", func(r *RecipeV1) { r.Sources[0].URL = "https://127.0.0.1/repository" }},
		{"shell install action", func(r *RecipeV1) { r.Install.Steps[0].Action = "curl https://example.com | sh" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recipe := validRecipe()
			test.mutate(&recipe)
			if err := recipe.Validate(); err == nil {
				t.Fatal("Validate() accepted unsafe recipe capability")
			}
		})
	}
}

func TestRecipeManagedPromotionBindsCompleteExperimentalDigest(t *testing.T) {
	experimental := validRecipe()
	managed, err := experimental.PromoteToManaged(ManagedAcceptanceV1{
		AcceptanceRef:   "acceptance:owner-device:42",
		VerificationRef: "verification:managed-suite:17",
		AcceptedAt:      time.Date(2026, time.July, 16, 9, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatal(err)
	}
	if managed.Maturity != MaturityManaged || managed.ManagedAcceptance == nil {
		t.Fatal("promotion did not create a managed recipe with acceptance binding")
	}
	want, err := experimental.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if managed.ManagedAcceptance.ExperimentalDigest != want {
		t.Fatalf("acceptance digest = %q, want %q", managed.ManagedAcceptance.ExperimentalDigest, want)
	}
	if err := managed.Validate(); err != nil {
		t.Fatalf("promoted managed recipe rejected: %v", err)
	}
}

func TestRecipeRejectsInvalidManagedAcceptance(t *testing.T) {
	acceptance := ManagedAcceptanceV1{
		AcceptanceRef:   "acceptance:owner-device:42",
		VerificationRef: "verification:managed-suite:17",
		AcceptedAt:      time.Date(2026, time.July, 16, 9, 0, 0, 0, time.UTC),
	}
	tests := []struct {
		name   string
		mutate func(*RecipeV1)
	}{
		{"managed without acceptance", func(r *RecipeV1) { r.Maturity = MaturityManaged }},
		{"acceptance on experimental", func(r *RecipeV1) { r.ManagedAcceptance = &acceptance }},
		{"managed without explicit network", func(r *RecipeV1) { r.Network, r.Integrations = nil, nil }},
		{"managed without restart recovery", func(r *RecipeV1) { r.Restart = nil }},
		{"managed with untyped install", func(r *RecipeV1) {
			r.Install.Steps[0].Action, r.Install.Steps[0].Inputs = "", nil
		}},
		{"managed without official repository identity", func(r *RecipeV1) { r.Sources[0].Official = false }},
		{"managed without volume mapping", func(r *RecipeV1) { r.VolumeSlots[0].MountPath = "" }},
		{"managed persistent plaintext volume", func(r *RecipeV1) { r.VolumeSlots[0].EncryptionRequired = false }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recipe := validRecipe()
			if test.name == "managed without acceptance" || test.name == "acceptance on experimental" {
				test.mutate(&recipe)
				if err := recipe.Validate(); err == nil {
					t.Fatal("Validate() accepted invalid maturity/acceptance state")
				}
				return
			}
			test.mutate(&recipe)
			if _, err := recipe.PromoteToManaged(acceptance); err == nil {
				t.Fatal("PromoteToManaged() accepted incomplete managed contract")
			}
		})
	}

	managed, err := validRecipe().PromoteToManaged(acceptance)
	if err != nil {
		t.Fatal(err)
	}
	managed.ManagedAcceptance.ExperimentalDigest = testDigest("f")
	if err := managed.Validate(); err == nil {
		t.Fatal("Validate() accepted acceptance bound to another recipe digest")
	}
}

func TestRecipeGoldenDigest(t *testing.T) {
	got, err := validRecipe().Digest()
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:42fd1e82e06f8008c2838982a21b16f3c806f9ac76a17d7dd8fe669dd1a3e3ad"
	if got != want {
		t.Fatalf("recipe digest = %q, want golden %q", got, want)
	}
}

func validRecipe() RecipeV1 {
	retrieved := time.Date(2026, time.July, 16, 8, 0, 0, 0, time.UTC)
	return RecipeV1{
		SchemaVersion: SchemaV1,
		RecipeID:      "recipe-knowledge-node-1",
		Name:          "Knowledge node",
		Maturity:      MaturityExperimental,
		Sources: []SourceV1{
			{
				ID: "primary", URL: "https://github.com/example/knowledge-node", Version: "v1.2.3", Commit: strings.Repeat("a", 40), ArtifactDigest: testDigest("a"), ContentDigest: testDigest("c"), License: "Apache-2.0", RetrievedAt: retrieved, Official: true,
				Kind: SourceRepository, Repository: &RepositoryIdentityV1{Host: "github.com", Namespace: "example", Name: "knowledge-node"},
			},
			{ID: "docs", URL: "https://docs.example.com/knowledge-node", Version: "v1.2.3", Commit: strings.Repeat("b", 40), ArtifactDigest: testDigest("b"), ContentDigest: testDigest("d"), License: "Apache-2.0", RetrievedAt: retrieved, Official: true, Kind: SourceDocumentation},
		},
		Requirements: ResourceRequirementsV1{
			MinVCPU: 2, MinMemoryMiB: 4096, MinDiskGiB: 40, Architecture: ArchitectureAMD64,
			DataLocations: []DataLocationRequirementV1{{DataSlotID: "documents", Kind: DataLocationWorkerVolume, VolumeSlotID: "data", Residency: []string{"aws:us-east-1", "aws:us-west-2"}, EncryptionRequired: true}},
		},
		Install: InstallContractV1{
			RootRequired:       true,
			TimeoutSeconds:     1800,
			CheckpointNames:    []string{"installed", "verified"},
			AllowedAdaptations: []string{"select compatible package mirror", "retry package download"},
			Adaptations: []AdaptationRuleV1{
				{Action: "package.select_mirror", Summary: "Select an approved compatible package mirror", MaxAttempts: 1},
				{Action: "download.retry", Summary: "Retry a locked artifact download", MaxAttempts: 3},
			},
			Steps: []InstallStepV1{
				{ID: "install", Summary: "Install the digest-pinned service", TimeoutSeconds: 1200, Action: "artifact.install", Checkpoint: "installed", Inputs: []ActionInputV1{{Name: "artifact", Kind: ActionInputSource, Ref: "primary"}, {Name: "model_token", Kind: ActionInputSecretSlot, Ref: "model-token"}}},
				{ID: "verify", Summary: "Verify the declared service", TimeoutSeconds: 300, Action: "service.verify", Checkpoint: "verified"},
			},
		},
		Health: HealthContractV1{
			Liveness:  ProbeV1{Kind: ProbeHTTP, Target: "/health/live"},
			Readiness: ProbeV1{Kind: ProbeHTTP, Target: "/health/ready"},
			Semantic:  ProbeV1{Kind: ProbeAction, Target: "semantic_check"},
		},
		Lifecycle: LifecycleContractV1{Start: "start", Stop: "stop", Restart: "restart", Upgrade: "upgrade", Rollback: "rollback", Backup: "backup", Restore: "restore", Destroy: "destroy"},
		VolumeSlots: []VolumeSlotRequirementV1{
			{SlotID: "data", Purpose: "persistent index", MountPath: "/srv/service/data", Persistent: true, EncryptionRequired: true},
			{SlotID: "cache", Purpose: "rebuildable cache", MountPath: "/srv/service/cache"},
		},
		DataSlots: []DataSlotRequirementV1{{SlotID: "documents", Purpose: "knowledge documents", ReadOnly: true}},
		SecretSlots: []SecretSlotRequirementV1{
			{SlotID: "model-token", Purpose: "embedding model access", Delivery: SecretDeliveryFile},
			{SlotID: "integration-auth", Purpose: "service integration authentication", Delivery: SecretDeliveryFile},
		},
		Network: &NetworkContractV1{
			DefaultDeny: true,
			Outbound: []OutboundRuleV1{
				{ID: "dns", Protocol: NetworkDNS, Destination: "system-resolver", Port: 53},
				{ID: "model-api", Protocol: NetworkHTTPS, Destination: "api.example.com", Port: 443},
			},
			Listeners: []ListenerV1{
				{ID: "service", Protocol: ListenerHTTP, BindScope: BindPrivate, Port: 8080},
				{ID: "admin", Protocol: ListenerHTTP, BindScope: BindLoopback, Port: 8081},
			},
			PublicIngress: PublicIngressV1{Mode: PublicIngressNone},
		},
		Restart: &RestartContractV1{Mode: RestartOnFailure, Action: "restart", MaxAttempts: 3, RecoveryCheckpoints: []string{"installed", "verified"}},
		Pairing: &PairingContractV1{BeginAction: "pairing.begin", ResumeAction: "pairing.resume", PayloadDelivery: PairingPayloadOnDemandEncrypted, TimeoutSeconds: 86400},
		Integrations: []IntegrationDeclarationV1{
			{ID: "mcp", Kind: IntegrationMCP, Transport: TransportMCPStreamableHTTP, ListenerID: "service", SecretSlotID: "integration-auth", AuthenticationRequired: true},
			{ID: "web", Kind: IntegrationWeb, Transport: TransportWebHTTP, ListenerID: "service"},
		},
	}
}

func cloneNetwork(value *NetworkContractV1) *NetworkContractV1 {
	copy := *value
	copy.Outbound = append([]OutboundRuleV1(nil), value.Outbound...)
	copy.Listeners = append([]ListenerV1(nil), value.Listeners...)
	return &copy
}

func cloneRestart(value *RestartContractV1) *RestartContractV1 {
	copy := *value
	copy.RecoveryCheckpoints = append([]string(nil), value.RecoveryCheckpoints...)
	return &copy
}

func testDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
