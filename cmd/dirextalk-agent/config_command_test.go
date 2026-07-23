package main

import (
	"testing"

	"github.com/YingSuiAI/dirextalk-agent/internal/config"
)

func TestParseArgumentsConfigSelection(t *testing.T) {
	t.Setenv("AGENT_CONFIG_FILE", "/legacy/config.yaml")
	path, command, err := parseArguments([]string{"--config", "/explicit/config.yaml", "healthcheck"})
	if err != nil || path != "/explicit/config.yaml" || command != "healthcheck" {
		t.Fatalf("explicit config parse: path=%q command=%q err=%v", path, command, err)
	}
	path, command, err = parseArguments([]string{"serve"})
	if err != nil || path != "/legacy/config.yaml" || command != "serve" {
		t.Fatalf("legacy path override parse: path=%q command=%q err=%v", path, command, err)
	}
}

func TestHealthcheckConfigRejectsNonLoopbackYAMLAddress(t *testing.T) {
	_, err := healthcheckConfigFromConfig(config.Config{
		Server:                config.Server{ListenAddress: ":9443", TLSCertFile: "/tmp/cert"},
		HealthcheckAddress:    "192.0.2.10:9443",
		HealthcheckServerName: "agent-health.test",
	})
	if err == nil {
		t.Fatal("healthcheck accepted a non-loopback YAML endpoint")
	}
}
