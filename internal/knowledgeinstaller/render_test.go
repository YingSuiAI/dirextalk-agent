package installer

import (
	"strings"
	"testing"
)

func TestRenderServicesAreFixedAndHardened(t *testing.T) {
	t.Parallel()
	adapter := renderAdapterUnit()
	qdrant := renderQdrantUnit()
	for _, expected := range []string{
		"python3.12 -I -S -B /opt/dirextalk/knowledge/current/adapter/main.py",
		"SupplementaryGroups=dirextalk-worker",
		"RestrictAddressFamilies=AF_UNIX AF_INET",
		"IPAddressDeny=any",
		"IPAddressAllow=localhost",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
	} {
		if !strings.Contains(adapter, expected) {
			t.Fatalf("adapter unit missing %q", expected)
		}
	}
	if !strings.Contains(renderSysusers(), "g dirextalk-worker -") ||
		!strings.Contains(renderTmpfiles(), "dirextalk-knowledge dirextalk-worker") {
		t.Fatal("adapter socket group is not aligned with the Worker identity")
	}
	if strings.Contains(adapter, "Environment=") || strings.Contains(adapter, "0.0.0.0") {
		t.Fatal("adapter unit gained caller environment or wildcard listener")
	}
	for _, expected := range []string{
		"--config-path /etc/dirextalk-knowledge/qdrant.yaml",
		"User=dirextalk-qdrant",
		"ProtectSystem=strict",
	} {
		if !strings.Contains(qdrant, expected) {
			t.Fatalf("qdrant unit missing %q", expected)
		}
	}
}

func TestRenderQdrantIsTLSLoopbackOnlyAndKeyIsNotInUnits(t *testing.T) {
	t.Parallel()
	key := strings.Repeat("a", 32)
	config, err := renderQdrantConfig(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"host: 127.0.0.1", "grpc_port: null", "enable_tls: true", "enable_cors: false", "max_request_size_mb: 2", "api_key: \"" + key + "\"",
	} {
		if !strings.Contains(config, expected) {
			t.Fatalf("qdrant config missing %q", expected)
		}
	}
	if strings.Contains(renderQdrantUnit(), key) || strings.Contains(renderAdapterUnit(), key) {
		t.Fatal("API key leaked into a unit")
	}
	if _, err := renderQdrantConfig("bad key"); err == nil {
		t.Fatal("expected invalid key rejection")
	}
}
