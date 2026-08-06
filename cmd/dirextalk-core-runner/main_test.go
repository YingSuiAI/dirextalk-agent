package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServeAcceptsRequiredFlagArguments(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "runner")
	build := exec.Command("go", "build", "-o", exe, ".")
	build.Dir = "."
	if out, e := build.CombinedOutput(); e != nil {
		t.Fatalf("build: %v %s", e, out)
	}
	root := t.TempDir()
	for _, n := range []string{"install", "work", "cg", "state"} {
		if e := os.Mkdir(filepath.Join(root, n), 0700); e != nil {
			t.Fatal(e)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	c := exec.CommandContext(ctx, exe, "serve", "--socket", filepath.Join(root, "runner.sock"), "--agent-uid", "65531", "--install-root", filepath.Join(root, "install"), "--workspace-root", filepath.Join(root, "work"), "--cgroup-root", filepath.Join(root, "cg"), "--static-shell", "/bin/sh", "--state-root", filepath.Join(root, "state"))
	out, e := c.CombinedOutput()
	if strings.Contains(string(out), "invalid flags") || strings.Contains(string(out), "invalid runner identity") {
		t.Fatalf("required argv rejected: %v %s", e, out)
	}
}

func TestProbeChildWaitsForReleaseByte(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "runner")
	build := exec.Command("go", "build", "-o", exe, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	releaseR, releaseW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer releaseW.Close()
	cmd := exec.Command(exe, "__probe-child-v1")
	cmd.ExtraFiles = []*os.File{releaseR}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	releaseR.Close()
	if _, err := releaseW.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	releaseW.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("probe child: %v", err)
	}
}

func TestSandboxProbeEntrySucceeds(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "runner")
	build := exec.Command("go", "build", "-o", exe, ".")
	build.Dir = "."
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	if out, err := exec.Command(exe, "__sandbox-probe-v1").CombinedOutput(); err != nil {
		t.Fatalf("sandbox probe: %v %s", err, out)
	}
}
