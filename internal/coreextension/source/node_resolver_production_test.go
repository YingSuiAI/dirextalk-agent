package source

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	core "github.com/YingSuiAI/dirextalk-agent/internal/coreextension"
)

func TestProductionNodeResolverRejectsSecondInstallBeforeNPMOrNetwork(t *testing.T) {
	resolver, err := NewProductionNodeDependencyResolver(NodeDependencyResolverConfig{TestOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	resolver.installSlot <- struct{}{}
	_, err = resolver.Resolve(context.Background(), NodeDependencyRequest{PackageName: "fixture", PackageVersion: "1.2.3", RootPackageJSON: []byte(`{"name":"fixture","version":"1.2.3"}`)})
	if !errors.Is(err, core.ErrInstallBusy) {
		t.Fatalf("err=%v", err)
	}
}

func TestProductionNodeResolverEnvironmentDisablesLifecycleScripts(t *testing.T) {
	env := managedNodeResolverEnvironment("/tmp/node-root")
	if !slices.Contains(env, "npm_config_ignore_scripts=true") {
		t.Fatalf("resolver npm environment does not disable scripts: %q", env)
	}
	args := managedNodeResolverArguments("/runtime/node", "/runtime/npm-cli.js")
	if !slices.Contains(args, "--package-lock-only") || !slices.Contains(args, "--ignore-scripts") {
		t.Fatalf("resolver npm arguments do not enforce lock-only scripts-disabled policy: %q", args)
	}
}

func TestProductionNodeResolverLongStepEmitsSafeHeartbeat(t *testing.T) {
	var output bytes.Buffer
	resolver := &ProductionNodeDependencyResolver{logger: slog.New(slog.NewTextHandler(&output, nil)), heartbeatEvery: 5 * time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	stop := resolver.startHeartbeat(ctx, "download_cache", time.Now())
	time.Sleep(18 * time.Millisecond)
	stop()
	cancel()
	log := output.String()
	if !strings.Contains(log, "phase=download_cache") || !strings.Contains(log, "state=running") || strings.Contains(log, "fixture") || strings.Contains(log, "https://") {
		t.Fatalf("unsafe or missing heartbeat: %q", log)
	}
}
