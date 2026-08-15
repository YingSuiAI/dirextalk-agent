package remoteservice

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
)

// CompileWorker compiles files and argv-only commands. The caller remains
// responsible for uploading files, resolving secret references, and executing
// the commands over an authenticated SSH connection.
func CompileWorker(worker Worker) ([]CompiledWorkload, error) {
	if worker.Validate() != nil {
		return nil, ErrInvalid
	}
	compiled := make([]CompiledWorkload, 0, len(worker.Workloads))
	for _, workload := range worker.Workloads {
		item, err := CompileWorkload(worker.ID, workload)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, item)
	}
	return compiled, nil
}

func CompileWorkload(workerID string, workload Workload) (CompiledWorkload, error) {
	if !idPattern.MatchString(workerID) || workload.validate() != nil {
		return CompiledWorkload{}, ErrInvalid
	}
	unitName := "dirextalk-" + workload.ID + ".service"
	unitPath := "/etc/systemd/system/" + unitName
	secretEnvPath := ""
	bindings := make([]SecretBinding, 0, len(workload.SecretEnv))
	if len(workload.SecretEnv) > 0 {
		secretEnvPath = "/run/dirextalk/secrets/" + workload.ID + ".env"
		for _, name := range sortedKeys(workload.SecretEnv) {
			bindings = append(bindings, SecretBinding{EnvironmentName: name, Reference: workload.SecretEnv[name]})
		}
	}
	unit := compileUnit(workload, secretEnvPath)
	result := CompiledWorkload{
		WorkloadID:     workload.ID,
		UnitName:       unitName,
		Files:          []File{{Path: unitPath, Mode: 0o644, Content: unit}},
		SecretEnvFile:  secretEnvPath,
		SecretBindings: bindings,
		Apply:          []RemoteCommand{{Executable: "/usr/bin/systemctl", Arguments: []string{"daemon-reload"}}},
		Status:         compileStatus(unitName, workload.Service),
	}
	if workload.Kind == WorkloadService {
		result.Apply = append(result.Apply, RemoteCommand{Executable: "/usr/bin/systemctl", Arguments: []string{"enable", "--now", unitName}})
	} else {
		result.Apply = append(result.Apply, RemoteCommand{Executable: "/usr/bin/systemctl", Arguments: []string{"start", unitName}})
	}
	if workload.Exposure != nil {
		caddy, err := compileCaddy(workerID, workload)
		if err != nil {
			return CompiledWorkload{}, err
		}
		result.Caddy = caddy
	}
	return result, nil
}

func compileUnit(workload Workload, secretEnvPath string) []byte {
	var unit bytes.Buffer
	unit.WriteString("[Unit]\n")
	unit.WriteString("Description=Dirextalk workload ")
	unit.WriteString(workload.ID)
	unit.WriteString("\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\n")
	if workload.Kind == WorkloadJob {
		unit.WriteString("Type=oneshot\n")
	} else {
		unit.WriteString("Type=simple\n")
	}
	unit.WriteString("User=")
	unit.WriteString(workload.User)
	unit.WriteString("\nWorkingDirectory=")
	unit.WriteString(systemdQuote(workload.WorkDir))
	unit.WriteByte('\n')
	for _, name := range sortedKeys(workload.Environment) {
		unit.WriteString("Environment=")
		unit.WriteString(systemdQuote(name + "=" + workload.Environment[name]))
		unit.WriteByte('\n')
	}
	if secretEnvPath != "" {
		unit.WriteString("EnvironmentFile=")
		unit.WriteString(systemdQuote(secretEnvPath))
		unit.WriteByte('\n')
	}
	unit.WriteString("ExecStart=")
	unit.WriteString(systemdQuote(workload.Command.Executable))
	for _, argument := range workload.Command.Arguments {
		unit.WriteByte(' ')
		unit.WriteString(systemdQuote(argument))
	}
	unit.WriteByte('\n')
	if workload.Kind == WorkloadService {
		unit.WriteString("Restart=on-failure\nRestartSec=3s\n")
	}
	unit.WriteString("NoNewPrivileges=true\nPrivateTmp=true\nProtectSystem=full\n\n")
	if workload.Kind == WorkloadService {
		unit.WriteString("[Install]\nWantedBy=multi-user.target\n")
	}
	return unit.Bytes()
}

func compileStatus(unitName string, service *Service) StatusCommands {
	logLines := uint16(200)
	if service != nil && service.LogLines != 0 {
		logLines = service.LogLines
	}
	status := StatusCommands{
		Active:  RemoteCommand{Executable: "/usr/bin/systemctl", Arguments: []string{"is-active", unitName}},
		LogTail: RemoteCommand{Executable: "/usr/bin/journalctl", Arguments: []string{"--unit", unitName, "--no-pager", "--output", "short-iso", "--lines", strconv.Itoa(int(logLines))}},
		Load:    RemoteCommand{Executable: "/usr/bin/cat", Arguments: []string{"/proc/loadavg"}},
	}
	if service != nil {
		healthURL := "http://127.0.0.1:" + strconv.Itoa(int(service.Port)) + service.HealthPath
		status.Health = &RemoteCommand{Executable: "/usr/bin/curl", Arguments: []string{"--fail", "--silent", "--show-error", "--max-time", "5", healthURL}}
	}
	return status
}

func compileCaddy(workerID string, workload Workload) (*CompiledCaddy, error) {
	exposure := *workload.Exposure
	if !exposure.Enabled {
		if exposure.Hostname != "" || exposure.TLS || exposure.Domain != nil || exposure.Confirmation != (ExactConfirmation{}) {
			return nil, ErrInvalid
		}
		return nil, nil
	}
	if workload.Kind != WorkloadService || workload.Service == nil || !validHostname(exposure.Hostname) {
		return nil, ErrInvalid
	}
	if err := requireExact(exposure.Confirmation, exposureDigest(workerID, workload.ID, workload.Service.Port, exposure)); err != nil {
		return nil, err
	}
	if exposure.Domain != nil {
		if err := exposure.Domain.validate(exposure.Hostname); err != nil {
			return nil, err
		}
	}
	siteAddress := canonicalHostname(exposure.Hostname)
	if !exposure.TLS {
		siteAddress = "http://" + siteAddress
	}
	content := fmt.Sprintf("%s {\n\treverse_proxy 127.0.0.1:%d\n}\n", siteAddress, workload.Service.Port)
	return &CompiledCaddy{
		File:  File{Path: "/etc/caddy/conf.d/dirextalk-" + workload.ID + ".caddy", Mode: 0o644, Content: []byte(content)},
		Apply: []RemoteCommand{{Executable: "/usr/bin/caddy", Arguments: []string{"validate", "--config", "/etc/caddy/Caddyfile"}}, {Executable: "/usr/bin/systemctl", Arguments: []string{"reload", "caddy.service"}}},
	}, nil
}

func systemdQuote(value string) string {
	value = strings.ReplaceAll(value, "%", "%%")
	value = strings.ReplaceAll(value, "$", "$$")
	value = strings.ReplaceAll(value, "\\", "\\\\")
	value = strings.ReplaceAll(value, "\"", "\\\"")
	return "\"" + value + "\""
}

func validHostname(value string) bool {
	hostname := canonicalHostname(value)
	if hostname == "" || len(hostname) > 253 || strings.Contains(hostname, "..") {
		return false
	}
	labels := strings.Split(hostname, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	return true
}

// ValidHostname reports whether value can be used as a DNS hostname by the
// remote-service and Route53 paths.
func ValidHostname(value string) bool { return validHostname(value) }

func CanonicalHostname(value string) string { return canonicalHostname(value) }
