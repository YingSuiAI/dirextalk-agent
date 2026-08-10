package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"
)

type result struct {
	EmptyEnvironment bool `json:"empty_environment"`
	HostHidden       bool `json:"host_hidden"`
	ConfigHidden     bool `json:"config_hidden"`
	ProcHidden       bool `json:"proc_hidden"`
	UnapprovedHidden bool `json:"unapproved_hidden"`
	ApprovedReadable bool `json:"approved_readable"`
	InstallReadable  bool `json:"install_readable"`
	NetworkDenied    bool `json:"network_denied"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "html" {
		if err := os.WriteFile("/work/index.html", []byte("<h1>Hello from Dirextalk</h1>"), 0o600); err != nil {
			os.Exit(34)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "child" {
		_ = os.WriteFile("/work/child-started", []byte("child-started"), 0o600)
		for {
			time.Sleep(time.Second)
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "loop" {
		_ = os.WriteFile("/work/started", []byte("started"), 0o600)
		_ = os.WriteFile("/work/unregistered.tmp", []byte("remove"), 0o600)
		child := exec.Command("/app/entry", "child")
		if err := child.Start(); err != nil {
			_, _ = fmt.Fprintln(os.Stderr, "start child", childStartCause(err))
			os.Exit(31)
		}
		for {
			time.Sleep(time.Second)
		}
	}
	if len(os.Args) != 2 {
		os.Exit(32)
	}
	_, hostErr := os.ReadFile(os.Args[1])
	_, configErr := os.ReadFile("/etc/dirextalk-agent/config.yaml")
	_, procErr := os.ReadFile("/proc/self/environ")
	_, unapprovedErr := os.ReadFile("/run/secrets/unapproved")
	approved, approvedErr := os.ReadFile("/run/secrets/allowed")
	resource, resourceErr := os.ReadFile("/app/resource.txt")
	socket, socketErr := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if socketErr == nil {
		_ = syscall.Close(socket)
	}
	value := result{
		EmptyEnvironment: len(os.Environ()) == 0,
		HostHidden:       hostErr != nil,
		ConfigHidden:     configErr != nil,
		ProcHidden:       procErr != nil,
		UnapprovedHidden: unapprovedErr != nil,
		ApprovedReadable: approvedErr == nil && string(approved) == "approved-value",
		InstallReadable:  resourceErr == nil && string(resource) == "installed-resource",
		NetworkDenied:    socketErr != nil,
	}
	body, err := json.Marshal(value)
	if err != nil || os.WriteFile("/work/result.json", body, 0o600) != nil {
		os.Exit(33)
	}
	_ = os.WriteFile("/work/unregistered.tmp", []byte("remove"), 0o600)
}

func childStartCause(err error) string {
	switch {
	case errors.Is(err, syscall.EPERM), errors.Is(err, syscall.EACCES):
		return "denied"
	case errors.Is(err, syscall.ENOSYS):
		return "unsupported"
	case errors.Is(err, syscall.ENOENT):
		return "missing"
	default:
		return "other"
	}
}
