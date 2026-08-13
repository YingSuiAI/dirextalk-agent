package sshworker

// remoteRunnerSource is compiled on the official base host during bootstrap.
// It intentionally uses only the Go standard library so there is no separate
// runner release, registry, daemon, callback, or inbound port to manage.
const remoteRunnerSource = `package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const root = "/tmp/dirextalk-worker"

type taskSpec struct {
	TaskID string ` + "`json:\"task_id\"`" + `
	Workload string ` + "`json:\"workload\"`" + `
	Model string ` + "`json:\"model\"`" + `
	Service *serviceSpec ` + "`json:\"service,omitempty\"`" + `
}

type serviceSpec struct {
	WorkloadID string ` + "`json:\"workload_id\"`" + `
	Port uint16 ` + "`json:\"port\"`" + `
	HealthPath string ` + "`json:\"health_path\"`" + `
}

type serviceRuntimeStatus struct {
	WorkloadID string ` + "`json:\"workload_id\"`" + `
	Kind string ` + "`json:\"kind\"`" + `
	Phase string ` + "`json:\"phase\"`" + `
	ActiveState string ` + "`json:\"active_state\"`" + `
	Health string ` + "`json:\"health\"`" + `
	Port uint16 ` + "`json:\"port\"`" + `
	HealthPath string ` + "`json:\"health_path\"`" + `
	ObservedAt string ` + "`json:\"observed_at\"`" + `
}

type taskStatus struct {
	TaskID string ` + "`json:\"task_id\"`" + `
	Workload string ` + "`json:\"workload\"`" + `
	Phase string ` + "`json:\"phase\"`" + `
	PID int ` + "`json:\"pid,omitempty\"`" + `
	ExitCode int ` + "`json:\"exit_code,omitempty\"`" + `
	StartedAt string ` + "`json:\"started_at,omitempty\"`" + `
	FinishedAt string ` + "`json:\"finished_at,omitempty\"`" + `
}

func main() {
	if len(os.Args) < 2 { fatal("missing action") }
	var err error
	switch os.Args[1] {
	case "start": err = start(arg(2))
	case "run": err = run(arg(2))
	case "status": err = status(arg(2))
	case "log": err = logOutput(arg(2), arg(3))
	case "artifact": err = artifact(arg(2), optionalArg(3))
	case "server-status": err = serverStatus()
	case "service-status": err = serviceStatus(arg(2))
	default: err = errors.New("unknown action")
	}
	if err != nil { fatal(err.Error()) }
}

func start(taskID string) error {
	spec, err := loadSpec(taskID); if err != nil { return err }
	if current, err := loadStatus(taskID); err == nil {
		if current.Phase == "running" && !alive(current.PID) { current.Phase = "failed"; current.ExitCode = 1; current.FinishedAt = time.Now().UTC().Format(time.RFC3339); _ = saveStatus(taskID, current) }
		return json.NewEncoder(os.Stdout).Encode(current)
	}
	encoded, err := bufio.NewReader(io.LimitReader(os.Stdin, 64<<10)).ReadString('\n')
	if err != nil && err != io.EOF { return err }
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(key) == 0 { return errors.New("missing model credential") }
	defer clear(key)
	logFile, err := os.OpenFile(taskPath(taskID, "runner.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil { return err }
	defer logFile.Close()
	command := exec.Command(os.Args[0], "run", taskID)
	command.Stdin = nil; command.Stdout = logFile; command.Stderr = logFile
	command.Env = append(os.Environ(), "DIREXTALK_MODEL_API_KEY="+string(key))
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil { return err }
	started := taskStatus{TaskID: taskID, Workload: spec.Workload, Phase: "running", PID: command.Process.Pid, StartedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := saveStatus(taskID, started); err != nil { _ = command.Process.Kill(); return err }
	_ = command.Process.Release()
	return json.NewEncoder(os.Stdout).Encode(started)
}

func run(taskID string) error {
	spec, err := loadSpec(taskID); if err != nil { return err }
	current, err := awaitStarted(taskID, os.Getpid()); if err != nil { return err }
	artifactRoot := filepath.Join(root, "artifacts", taskID)
	if err := os.MkdirAll(artifactRoot, 0700); err != nil { return finish(taskID, current, 1, err) }
	report, err := os.OpenFile(filepath.Join(artifactRoot, "final-report.md"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil { return finish(taskID, current, 1, err) }
	defer report.Close()
	prompt := "Complete the supplied objective on this retained remote host. This is a " + spec.Workload + " workload. Use shell and workspace tools as needed. Write every deliverable under " + artifactRoot + ". Your final response must concisely report work, deployment flow, verification, actual server load, and artifact paths. Never expose credentials or hidden configuration."
	if spec.Workload == "service" && spec.Service != nil {
		prompt += " Deploy the requested application as a persistent service that remains alive after this Pi process exits. It must listen on 0.0.0.0 port " + strconv.Itoa(int(spec.Service.Port)) + " and return HTTP success at " + spec.Service.HealthPath + "."
	}
	arguments := []string{"--mode", "text", "--print", "--no-session", "--provider", "dirextalk-worker", "--model", spec.Model, "--thinking", "medium", "--tools", "read,bash,edit,write,grep,find,ls", "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve", "--system-prompt", prompt}
	command := exec.Command(filepath.Join(root, "runtime", "pi"), arguments...)
	objective, err := os.Open(taskPath(taskID, "objective.txt")); if err != nil { return finish(taskID, current, 1, err) }
	defer objective.Close()
	command.Dir = filepath.Join(root, "workspace"); command.Stdin = objective
	command.Stdout = io.MultiWriter(os.Stdout, report); command.Stderr = os.Stderr
	command.Env = append(os.Environ(), "PI_CODING_AGENT_DIR="+filepath.Join(root, "pi-config"), "PI_TELEMETRY=0", "NO_COLOR=1", "TERM=dumb")
	err = command.Run(); code := 0
	if err != nil { code = 1; var exit *exec.ExitError; if errors.As(err, &exit) { code = exit.ExitCode() } }
	if err == nil && spec.Workload == "service" { err = verifyService(spec); if err != nil { code = 1 } }
	return finish(taskID, current, code, err)
}

func verifyService(spec taskSpec) error {
	if spec.Service == nil || spec.Service.WorkloadID == "" || spec.Service.Port == 0 || !strings.HasPrefix(spec.Service.HealthPath, "/") { return errors.New("invalid service spec") }
	client := http.Client{Timeout: 5 * time.Second}
	response, err := client.Get("http://127.0.0.1:" + strconv.Itoa(int(spec.Service.Port)) + spec.Service.HealthPath)
	if err != nil { return err }; defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 400 { return fmt.Errorf("service health returned %d", response.StatusCode) }
	return nil
}

func serviceStatus(taskID string) error {
	spec, err := loadSpec(taskID); if err != nil || spec.Workload != "service" || spec.Service == nil { return errors.New("service workload not found") }
	status := serviceRuntimeStatus{WorkloadID: spec.Service.WorkloadID, Kind: "service", Port: spec.Service.Port, HealthPath: spec.Service.HealthPath, ObservedAt: time.Now().UTC().Format(time.RFC3339), Phase: "stopped", ActiveState: "inactive", Health: "unhealthy"}
	if err := verifyService(spec); err == nil { status.Phase, status.ActiveState, status.Health = "running", "active", "healthy" }
	return json.NewEncoder(os.Stdout).Encode(status)
}

func finish(taskID string, current taskStatus, code int, runErr error) error {
	current.ExitCode, current.FinishedAt = code, time.Now().UTC().Format(time.RFC3339)
	if code == 0 { current.Phase = "completed" } else { current.Phase = "failed" }
	if err := saveStatus(taskID, current); err != nil { return err }
	return runErr
}

func status(taskID string) error {
	value, err := loadStatus(taskID); if err != nil { return err }
	if value.Phase == "running" && !alive(value.PID) { value.Phase = "failed"; value.ExitCode = 1; value.FinishedAt = time.Now().UTC().Format(time.RFC3339); _ = saveStatus(taskID, value) }
	return json.NewEncoder(os.Stdout).Encode(value)
}

func logOutput(taskID, rawOffset string) error {
	offset, err := strconv.ParseInt(rawOffset, 10, 64); if err != nil || offset < 0 { return errors.New("invalid log offset") }
	file, err := os.Open(taskPath(taskID, "runner.log")); if err != nil { return err }; defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil { return err }
	_, err = io.Copy(os.Stdout, io.LimitReader(file, 4<<20)); return err
}

func artifact(taskID, name string) error {
	directory := filepath.Join(root, "artifacts", taskID)
	if name == "" {
		return filepath.WalkDir(directory, func(path string, entry os.DirEntry, err error) error {
			if err != nil { return err }; if !entry.Type().IsRegular() { return nil }
			relative, err := filepath.Rel(directory, path); if err != nil { return err }
			info, err := entry.Info(); if err != nil { return err }
			return json.NewEncoder(os.Stdout).Encode(map[string]any{"name": filepath.ToSlash(relative), "size": info.Size()})
		})
	}
	clean := filepath.Clean(name); if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) { return errors.New("invalid artifact") }
	file, err := os.Open(filepath.Join(directory, clean)); if err != nil { return err }; defer file.Close()
	info, err := file.Stat(); if err != nil || !info.Mode().IsRegular() { return errors.New("invalid artifact") }
	_, err = io.Copy(os.Stdout, file); return err
}

func serverStatus() error {
	load, _ := os.ReadFile("/proc/loadavg"); uptime, _ := os.ReadFile("/proc/uptime"); memory, _ := os.ReadFile("/proc/meminfo")
	running, terminal := 0, 0
	entries, _ := os.ReadDir(filepath.Join(root, "tasks")); for _, entry := range entries { if !entry.IsDir() { continue }; value, err := loadStatus(entry.Name()); if err != nil { continue }; if value.Phase == "running" && alive(value.PID) { running++ } else { terminal++ } }
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"observed_at": time.Now().UTC().Format(time.RFC3339), "load_average": strings.TrimSpace(string(load)), "uptime": strings.TrimSpace(string(uptime)), "memory": memorySummary(string(memory)), "running_tasks": running, "terminal_tasks": terminal})
}

func memorySummary(body string) map[string]string { result := map[string]string{}; for _, line := range strings.Split(body, "\n") { fields := strings.Fields(line); if len(fields) < 2 { continue }; key := strings.TrimSuffix(fields[0], ":"); if key == "MemTotal" || key == "MemAvailable" { result[key] = strings.Join(fields[1:], " ") } }; return result }
func taskPath(taskID, name string) string { return filepath.Join(root, "tasks", taskID, name) }
func loadSpec(taskID string) (taskSpec, error) { var value taskSpec; body, err := os.ReadFile(taskPath(taskID, "spec.json")); if err == nil { err = json.Unmarshal(body, &value) }; if err != nil || value.TaskID != taskID || (value.Workload != "job" && value.Workload != "service") || (value.Workload == "job" && value.Service != nil) || (value.Workload == "service" && value.Service == nil) { return taskSpec{}, errors.New("invalid task") }; return value, nil }
func loadStatus(taskID string) (taskStatus, error) { var value taskStatus; body, err := os.ReadFile(taskPath(taskID, "status.json")); if err == nil { err = json.Unmarshal(body, &value) }; return value, err }
func saveStatus(taskID string, value taskStatus) error { body, err := json.Marshal(value); if err != nil { return err }; temporary := taskPath(taskID, "status.tmp"); if err = os.WriteFile(temporary, body, 0600); err != nil { return err }; return os.Rename(temporary, taskPath(taskID, "status.json")) }
func alive(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }
func awaitStarted(taskID string, pid int) (taskStatus, error) { for attempt := 0; attempt < 100; attempt++ { value, err := loadStatus(taskID); if err == nil && value.Phase == "running" && value.PID == pid { return value, nil }; time.Sleep(10*time.Millisecond) }; return taskStatus{}, errors.New("start state unavailable") }
func arg(index int) string { if len(os.Args) <= index { fatal("missing argument") }; return os.Args[index] }
func optionalArg(index int) string { if len(os.Args) <= index { return "" }; return os.Args[index] }
func fatal(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
`
