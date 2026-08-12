// dirextalk-core-runner is a non-root, local-only workload supervisor.  It
// intentionally has no Agent DB, TCP listener, Docker socket, host mounts, or
// Agent credential inputs. It owns the isolated persistent executor and its
// authenticated receipt boundary only.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/buildinfo"
	"github.com/YingSuiAI/dirextalk-agent/internal/coreworkload/runner"
	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"os/signal"
	"path/filepath"
	"syscall"
)

func main() {
	if buildinfo.IsVersionRequest(os.Args[1:]) {
		_, _ = fmt.Fprintln(os.Stdout, buildinfo.Version())
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "__probe-child-v1" {
		probeChild()
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "__sandbox-probe-v1" {
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "__sandbox-child-v1" {
		if err := extensionrunner.SandboxChildV1(); err != nil {
			die(extensionrunner.SandboxFailureDiagnostic(err))
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "__sandbox-command-v1" {
		if err := extensionrunner.SandboxCommandV1(); err != nil {
			die("sandbox command failed")
		}
		return
	}
	if len(os.Args) >= 2 && os.Args[1] == "probe" {
		probe()
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		die("usage: dirextalk-core-runner serve --socket --agent-uid")
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	socket := fs.String("socket", "", "")
	uid := fs.String("agent-uid", "", "")
	installRoot := fs.String("install-root", "", "")
	workspaceRoot := fs.String("workspace-root", "", "")
	cgroupRoot := fs.String("cgroup-root", "", "")
	staticShell := fs.String("static-shell", "", "")
	stateRoot := fs.String("state-root", "", "")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 0 {
		die("invalid flags")
	}
	n, e := strconv.ParseUint(*uid, 10, 32)
	if e != nil || n == 0 || uint32(n) == uint32(os.Geteuid()) || !filepath.IsAbs(*socket) || filepath.Clean(*socket) != *socket || !absoluteClean(*installRoot) || !absoluteClean(*workspaceRoot) || !absoluteClean(*cgroupRoot) || !absoluteClean(*staticShell) || !absoluteClean(*stateRoot) {
		die("invalid runner identity")
	}
	l, e := runner.Listen(*socket, uint32(os.Geteuid()))
	if e != nil {
		die("unsafe socket")
	}
	defer l.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	executor := runner.LinuxExecutor{InstallRoot: *installRoot, WorkspaceRoot: *workspaceRoot, CgroupRoot: *cgroupRoot, StaticShell: *staticShell}
	supervisor, e := runner.NewPersistentSupervisor(uint32(n), *stateRoot, executor)
	if e != nil {
		die("unsafe state root")
	}
	if e = supervisor.Serve(ctx, l); e != nil {
		if stage, ok := runner.ReadinessStage(e); ok {
			die("runner readiness failed at " + stage)
		}
		die("runner stopped")
	}
}

func probeChild() {
	gate := os.NewFile(uintptr(3), "probe-release")
	if gate == nil {
		os.Exit(2)
	}
	defer gate.Close()
	var release [1]byte
	if n, err := gate.Read(release[:]); err != nil || n != 1 || release[0] != 1 {
		os.Exit(2)
	}
}

func probe() {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	socket := fs.String("socket", "", "")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 0 || *socket == "" {
		die("invalid probe flags")
	}
	transport, err := runner.NewSocketTransport(*socket, uint32(os.Geteuid()))
	if err != nil {
		die("probe unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := transport.Probe(ctx); err != nil {
		die("probe unavailable")
	}
}

func absoluteClean(v string) bool {
	return v != "" && filepath.IsAbs(v) && filepath.Clean(v) == v && v != "/"
}

func die(s string) { _, _ = fmt.Fprintln(os.Stderr, s); os.Exit(2) }
