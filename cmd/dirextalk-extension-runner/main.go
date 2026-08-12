// The extension runner is a separately deployed executable.  It has no Agent
// command dispatch hook, ensuring the Agent process cannot execute extensions.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/buildinfo"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"golang.org/x/sys/unix"
)

func main() {
	if buildinfo.IsVersionRequest(os.Args[1:]) {
		_, _ = fmt.Fprintln(os.Stdout, buildinfo.Version())
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "__sandbox-child-v1" {
		if err := extensionrunner.SandboxChildV1(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, extensionrunner.SandboxFailureDiagnostic(err))
			os.Exit(127)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "__sandbox-command-v1" {
		if err := extensionrunner.SandboxCommandV1(); err != nil {
			die("sandbox command failed")
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "__probe-child-v1" {
		probeChild()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "__sandbox-probe-v1" {
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "probe" {
		probe()
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		die("usage: dirextalk-extension-runner serve --socket ... --agent-uid ... --install-root ... --prepared-root ... --node-runtime-root ... --workspace-root ... --cgroup-root ...")
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", "", "")
	agentUID := fs.String("agent-uid", "", "")
	installRoot := fs.String("install-root", "", "")
	preparedRoot := fs.String("prepared-root", "", "")
	nodeRuntimeRoot := fs.String("node-runtime-root", "", "")
	workspaceRoot := fs.String("workspace-root", "", "")
	cgroupRoot := fs.String("cgroup-root", "", "")
	stateRoot := fs.String("state-root", "", "")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 0 || !allSet(fs, "socket", "agent-uid", "install-root", "prepared-root", "node-runtime-root", "workspace-root", "cgroup-root", "state-root") {
		die("all serve flags are required")
	}
	uid64, err := strconv.ParseUint(*agentUID, 10, 32)
	if err != nil || uint32(uid64) == uint32(os.Geteuid()) {
		die("invalid agent uid")
	}
	if err := validateSocket(*socket); err != nil {
		die(err.Error())
	}
	for _, p := range []string{*installRoot, *preparedRoot, *stateRoot} {
		if err := validateTrustedDir(p); err != nil {
			die(err.Error())
		}
	}
	if err := validateNodeRuntimeDir(*nodeRuntimeRoot); err != nil {
		die(err.Error())
	}
	if err := validateWorkspaceDir(*workspaceRoot, uint32(uid64)); err != nil {
		die(err.Error())
	}
	if err := validateCgroup(*cgroupRoot); err != nil {
		die(err.Error())
	}
	backend := extensionrunner.LinuxBackend{CgroupRoot: *cgroupRoot, ProbeRoot: *installRoot, NodeRuntimeRoot: *nodeRuntimeRoot}
	probeCtx, cancelProbe := context.WithTimeout(context.Background(), 10*time.Second)
	err = backend.Probe(probeCtx)
	cancelProbe()
	if err != nil {
		// Backend diagnostics contain only a fixed stage token. Running this
		// once at startup makes container failures actionable without polling
		// health checks emitting repeated messages.
		die(err.Error())
	}
	listener, err := extensionrunner.Listen(*socket, 0o660)
	if err != nil {
		die("listen: " + err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer listener.Close()
	r := extensionrunner.Runner{InstallResolver: extensionrunner.DiskInstallResolver{Root: *installRoot}, NodeInstallResolver: extensionrunner.DiskNodeInstallResolver{Root: *installRoot}, WorkspaceResolver: extensionrunner.DiskWorkspaceResolver{Root: *workspaceRoot, SharedGID: uint32(uid64)}, V2Backend: backend, Logger: slog.Default()}
	registry, err := extensionrunner.NewPersistentRunRegistry(*stateRoot)
	if err != nil {
		die("registry: " + err.Error())
	}
	nodeBuilder := &extensionrunner.NodeOfflineBuilder{PreparedRoot: *preparedRoot, PublicationRoot: *installRoot, RuntimeRoot: *nodeRuntimeRoot, CgroupRoot: *cgroupRoot, Logger: slog.Default()}
	s := extensionrunner.Server{Listener: listener, Authorizer: extensionrunner.UIDAllowlist{uint32(uid64): {}}, RunnerUID: uint32(os.Geteuid()), SharedWorkspaceGID: uint32(uid64), Runner: r, Registry: registry, PublicationRoot: *installRoot, NodeBuilder: nodeBuilder, NodeInstallSlots: make(chan struct{}, 1)}
	if err := s.ServeV2(ctx); err != nil {
		slog.Error("extension runner stopped", "error", err)
		os.Exit(1)
	}
}

func probeChild() {
	gate := os.NewFile(uintptr(3), "probe-release")
	if gate == nil {
		os.Exit(2)
	}
	var release [1]byte
	if n, err := gate.Read(release[:]); err != nil || n != 1 || release[0] != 1 {
		os.Exit(2)
	}
}

// probe validates the exact runner socket, peer UID, and nonce-bound readiness
// response without submitting an execution request.
func probe() {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	socket := fs.String("socket", "", "")
	uid := fs.String("runner-uid", "", "")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 0 || *socket == "" || *uid == "" {
		die("invalid probe flags")
	}
	wantUID, err := strconv.ParseUint(*uid, 10, 32)
	if err != nil || uint32(wantUID) == 0 || !filepath.IsAbs(*socket) || filepath.Clean(*socket) != *socket {
		die("probe unavailable")
	}
	client, err := extensionrunner.NewClient(*socket, uint32(wantUID))
	if err != nil {
		die("probe unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Probe(ctx); err != nil {
		die("probe unavailable")
	}
}
func allSet(fs *flag.FlagSet, names ...string) bool {
	ok := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { ok[f.Name] = true })
	for _, n := range names {
		if !ok[n] {
			return false
		}
	}
	return true
}
func validateSocket(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || strings.Contains(p, "\x00") {
		return fmt.Errorf("invalid socket")
	}
	return nil
}
func validateTrustedDir(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return fmt.Errorf("invalid trusted root")
	}
	var st unix.Stat_t
	if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0o022 != 0 {
		return fmt.Errorf("unsafe trusted root")
	}
	return nil
}

func validateNodeRuntimeDir(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" {
		return fmt.Errorf("invalid Node runtime root")
	}
	var st unix.Stat_t
	if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != 0 || st.Mode&0o022 != 0 {
		return fmt.Errorf("unsafe Node runtime root")
	}
	return nil
}
func validateWorkspaceDir(p string, agentGID uint32) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/" || agentGID == 0 {
		return fmt.Errorf("invalid trusted root")
	}
	var st unix.Stat_t
	if unix.Lstat(p, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Gid != agentGID || st.Mode&0o777 != 0o770 {
		return fmt.Errorf("unsafe trusted root")
	}
	return nil
}
func validateCgroup(p string) error {
	// Compose mounts only the deployment-created delegated cgroup-v2 subtree
	// here.  Do not accept a broader cgroup path: the runner must never gain
	// visibility of the daemon or host cgroup root.
	if p != "/cgroup" {
		return fmt.Errorf("invalid cgroup root")
	}
	var st unix.Stat_t
	var fs unix.Statfs_t
	if unix.Stat(p, &st) != nil || unix.Statfs(p, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || st.Mode&0o022 != 0 {
		return fmt.Errorf("unsafe cgroup root")
	}
	return nil
}
func die(s string) { fmt.Fprintln(os.Stderr, s); os.Exit(2) }
