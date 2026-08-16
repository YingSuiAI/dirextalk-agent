package sshworker

import (
	"fmt"
	"path/filepath"
	"strings"
)

type WorkloadKind string

const (
	WorkloadJob     WorkloadKind = "job"
	WorkloadService WorkloadKind = "service"
)

func (kind WorkloadKind) valid() bool { return kind == WorkloadJob || kind == WorkloadService }

type RuntimeAction string

const (
	RuntimeStart         RuntimeAction = "start"
	RuntimeStop          RuntimeAction = "stop"
	RuntimeStatus        RuntimeAction = "status"
	RuntimeLog           RuntimeAction = "log"
	RuntimeArtifact      RuntimeAction = "artifact"
	RuntimeServerStatus  RuntimeAction = "server-status"
	RuntimeServiceStatus RuntimeAction = "service-status"
)

type RuntimeCommand struct {
	Shell string
	Stdin []byte
}

// RuntimeProtocol compiles short, resumable SSH commands for a retained host.
// Start detaches the workload and returns immediately. Status, Log, Artifact,
// and ServerStatus may be called after any SSH reconnect.
type RuntimeProtocol struct {
	TaskID          string
	encodedModelKey string
}

func (protocol RuntimeProtocol) Start() (RuntimeCommand, error) {
	if !protocol.valid() || protocol.encodedModelKey == "" {
		return RuntimeCommand{}, ErrInvalid
	}
	return RuntimeCommand{
		Shell: runnerCommand(RuntimeStart, protocol.TaskID),
		Stdin: []byte(protocol.encodedModelKey + "\n"),
	}, nil
}

func (protocol RuntimeProtocol) Status() (RuntimeCommand, error) {
	if !protocol.valid() {
		return RuntimeCommand{}, ErrInvalid
	}
	return RuntimeCommand{Shell: runnerCommand(RuntimeStatus, protocol.TaskID)}, nil
}

func (protocol RuntimeProtocol) Stop() (RuntimeCommand, error) {
	if !protocol.valid() {
		return RuntimeCommand{}, ErrInvalid
	}
	return RuntimeCommand{Shell: runnerCommand(RuntimeStop, protocol.TaskID)}, nil
}

func (protocol RuntimeProtocol) Log(offset int64) (RuntimeCommand, error) {
	if !protocol.valid() || offset < 0 {
		return RuntimeCommand{}, ErrInvalid
	}
	return RuntimeCommand{Shell: runnerCommand(RuntimeLog, protocol.TaskID, fmt.Sprint(offset))}, nil
}

// Artifact lists artifacts when name is empty and streams one regular file
// when name is supplied. Names are always relative to this task's directory.
func (protocol RuntimeProtocol) Artifact(name string) (RuntimeCommand, error) {
	if !protocol.valid() {
		return RuntimeCommand{}, ErrInvalid
	}
	name = filepath.ToSlash(filepath.Clean(strings.TrimSpace(name)))
	if name == "." {
		name = ""
	}
	if name != "" && (filepath.IsAbs(name) || strings.HasPrefix(name, "../") || strings.ContainsRune(name, '\x00')) {
		return RuntimeCommand{}, ErrInvalid
	}
	return RuntimeCommand{Shell: runnerCommand(RuntimeArtifact, protocol.TaskID, name)}, nil
}

func (protocol RuntimeProtocol) ServerStatus() (RuntimeCommand, error) {
	if !protocol.valid() {
		return RuntimeCommand{}, ErrInvalid
	}
	return RuntimeCommand{Shell: runnerCommand(RuntimeServerStatus)}, nil
}

func (protocol RuntimeProtocol) ServiceStatus() (RuntimeCommand, error) {
	if !protocol.valid() {
		return RuntimeCommand{}, ErrInvalid
	}
	return RuntimeCommand{Shell: runnerCommand(RuntimeServiceStatus, protocol.TaskID)}, nil
}

func (protocol RuntimeProtocol) valid() bool { return validID(protocol.TaskID) }

func runnerCommand(action RuntimeAction, arguments ...string) string {
	parts := []string{shellQuote("/tmp/dirextalk-worker/dirextalk-worker-runner"), shellQuote(string(action))}
	for _, argument := range arguments {
		parts = append(parts, shellQuote(argument))
	}
	return strings.Join(parts, " ")
}

type remoteTaskSpec struct {
	TaskID            string              `json:"task_id"`
	Workload          WorkloadKind        `json:"workload"`
	Model             string              `json:"model"`
	MaxRuntimeSeconds uint64              `json:"max_runtime_seconds"`
	Service           *RuntimeServiceSpec `json:"service,omitempty"`
}
