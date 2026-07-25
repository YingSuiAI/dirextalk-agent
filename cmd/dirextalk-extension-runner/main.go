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

	"github.com/YingSuiAI/dirextalk-agent/internal/extensionrunner"
	"golang.org/x/sys/unix"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "__sandbox-child-v1" {
		if err := extensionrunner.SandboxChildV1(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, err.Error())
			os.Exit(127)
		}
		return
	}
	if len(os.Args) < 2 || os.Args[1] != "serve" {
		die("usage: dirextalk-extension-runner serve --socket ... --agent-uid ... --install-root ... --workspace-root ... --cgroup-root ...")
	}
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", "", "")
	agentUID := fs.String("agent-uid", "", "")
	installRoot := fs.String("install-root", "", "")
	workspaceRoot := fs.String("workspace-root", "", "")
	cgroupRoot := fs.String("cgroup-root", "", "")
	stateRoot := fs.String("state-root", "", "")
	if fs.Parse(os.Args[2:]) != nil || fs.NArg() != 0 || !allSet(fs, "socket", "agent-uid", "install-root", "workspace-root", "cgroup-root", "state-root") {
		die("all serve flags are required")
	}
	uid64, err := strconv.ParseUint(*agentUID, 10, 32)
	if err != nil || uint32(uid64) == uint32(os.Geteuid()) {
		die("invalid agent uid")
	}
	if err := validateSocket(*socket); err != nil {
		die(err.Error())
	}
	for _, p := range []string{*installRoot, *workspaceRoot, *stateRoot} {
		if err := validateTrustedDir(p); err != nil {
			die(err.Error())
		}
	}
	if err := validateCgroup(*cgroupRoot); err != nil {
		die(err.Error())
	}
	listener, err := extensionrunner.Listen(*socket, 0o660)
	if err != nil {
		die("listen: " + err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	defer listener.Close()
	r := extensionrunner.Runner{InstallResolver: extensionrunner.DiskInstallResolver{Root: *installRoot}, WorkspaceResolver: extensionrunner.DiskWorkspaceResolver{Root: *workspaceRoot}, V2Backend: extensionrunner.LinuxBackend{CgroupRoot: *cgroupRoot}}
	registry, err := extensionrunner.NewPersistentRunRegistry(*stateRoot)
	if err != nil {
		die("registry: " + err.Error())
	}
	s := extensionrunner.Server{Listener: listener, Authorizer: extensionrunner.UIDAllowlist{uint32(uid64): {}}, Runner: r, Registry: registry, PublicationRoot: *installRoot}
	if err := s.ServeV2(ctx); err != nil {
		slog.Error("extension runner stopped", "error", err)
		os.Exit(1)
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
func validateCgroup(p string) error {
	if !filepath.IsAbs(p) || filepath.Clean(p) != p || p == "/sys/fs/cgroup" || !strings.HasPrefix(p, "/sys/fs/cgroup/") {
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
