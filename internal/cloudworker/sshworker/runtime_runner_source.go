package sshworker

// remoteRunnerSource is compiled on the official base host during bootstrap.
// It intentionally uses only the Go standard library so there is no separate
// runner release, registry, daemon, callback, or inbound port to manage.
const remoteRunnerSource = `package main

import (
	"bufio"
	"bytes"
	"context"
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

const root = "/var/lib/dirextalk-worker"

type taskSpec struct {
	TaskID string ` + "`json:\"task_id\"`" + `
	Workload string ` + "`json:\"workload\"`" + `
	Model string ` + "`json:\"model\"`" + `
	MaxRuntimeSeconds uint64 ` + "`json:\"max_runtime_seconds\"`" + `
	Service *serviceSpec ` + "`json:\"service,omitempty\"`" + `
}

type serviceSpec struct {
	WorkloadID string ` + "`json:\"workload_id\"`" + `
	Port uint16 ` + "`json:\"port\"`" + `
	HealthPath string ` + "`json:\"health_path\"`" + `
	Hostname string ` + "`json:\"hostname,omitempty\"`" + `
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
	case "stop": err = stop(arg(2))
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

func stop(taskID string) error {
	current, err := loadStatus(taskID)
	if os.IsNotExist(err) { cleanupGitHubRuntime(filepath.Join(root, "tasks", taskID)); return json.NewEncoder(os.Stdout).Encode(taskStatus{TaskID: taskID, Phase: "not_started"}) }
	if err != nil { return err }
	if current.Phase != "running" { cleanupGitHubRuntime(filepath.Join(root, "tasks", taskID)); return json.NewEncoder(os.Stdout).Encode(current) }
	unit := "dirextalk-worker-" + taskID + ".scope"
	stopErr := exec.Command("systemctl", "--user", "stop", unit).Run()
	if current.PID > 0 {
		if killErr := syscall.Kill(-current.PID, syscall.SIGKILL); killErr != nil && !errors.Is(killErr, syscall.ESRCH) { stopErr = errors.Join(stopErr, killErr) }
	}
	cleanupGitHubRuntime(filepath.Join(root, "tasks", taskID))
	current.Phase, current.ExitCode, current.FinishedAt = "failed", 130, time.Now().UTC().Format(time.RFC3339)
	if err = saveStatus(taskID, current); err != nil { return errors.Join(stopErr, err) }
	if stopErr != nil { return stopErr }
	return json.NewEncoder(os.Stdout).Encode(current)
}

func start(taskID string) error {
	spec, err := loadSpec(taskID); if err != nil { return err }
	if current, err := loadStatus(taskID); err == nil {
		if current.Phase == "running" && !alive(current.PID) { current.Phase = "failed"; current.ExitCode = 1; current.FinishedAt = time.Now().UTC().Format(time.RFC3339); _ = saveStatus(taskID, current) }
		return json.NewEncoder(os.Stdout).Encode(current)
	}
	encoded, err := bufio.NewReader(io.LimitReader(os.Stdin, 64<<10)).ReadString('\n')
	if err != nil && err != io.EOF { return err }
	if len(encoded) == 0 || len(encoded) >= 64<<10 { return errors.New("invalid runtime secret envelope") }
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) == 0 || len(raw) > 24<<10 { return errors.New("missing runtime secret envelope") }
	defer clear(raw)
	var envelope struct { Version int ` + "`json:\"version\"`" + `; ModelAPIKey string ` + "`json:\"model_api_key\"`" + `; GitHubPAT string ` + "`json:\"github_pat\"`" + ` }
	decoder := json.NewDecoder(strings.NewReader(string(raw))); decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || decoder.Decode(&struct{}{}) != io.EOF || envelope.Version != 1 || strings.TrimSpace(envelope.ModelAPIKey) == "" || len(envelope.ModelAPIKey) > 16384 || len(envelope.GitHubPAT) > 4096 { return errors.New("invalid runtime secret envelope") }
	key := []byte(envelope.ModelAPIKey); defer clear(key)
	if envelope.GitHubPAT != "" { pat := []byte(envelope.GitHubPAT); defer clear(pat); if err := os.WriteFile(taskPath(taskID, "github-pat"), pat, 0600); err != nil { return err } }
	startedRun := false
	defer func() { if !startedRun { cleanupGitHubRuntime(filepath.Join(root, "tasks", taskID)) } }()
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
	startedRun = true
	return json.NewEncoder(os.Stdout).Encode(started)
}

func run(taskID string) error {
	spec, err := loadSpec(taskID); if err != nil { return err }
	taskRoot := filepath.Join(root, "tasks", taskID)
	defer cleanupGitHubRuntime(taskRoot)
	current, err := awaitStarted(taskID, os.Getpid()); if err != nil { return err }
	workspaceRoot, artifactRoot := filepath.Join(taskRoot, "workspace"), filepath.Join(taskRoot, "artifacts")
	if err := requireDirectory(workspaceRoot); err != nil { return finish(taskID, current, 1, err) }
	if err := os.MkdirAll(artifactRoot, 0700); err != nil { return finish(taskID, current, 1, err) }
	githubAvailable, err := githubRuntimeAvailable(taskRoot); if err != nil { return finish(taskID, current, 1, err) }
	prompt := "Complete the supplied objective on this retained remote host. This is a " + spec.Workload + " workload. Use shell and workspace tools as needed. Put genuine user-requested file deliverables under " + artifactRoot + ". Do not create final-report.md, completion-report.md, or another generic completion report merely to transport your final response. Your final stdout response is an internal report for Central: concisely record completed work, verification, and paths of genuine requested artifacts so Central can synthesize the user-facing answer. Use parallel subagents only for independent, non-overlapping scopes. Before concurrent writes create a separate git worktree and branch per writer; revalidate repository owner, remote, and base before push; integrate and test in the parent worktree. Never expose GitHub credentials, model credentials, or hidden configuration."
	if githubAvailable {
		prompt += " GitHub access is available for this task: HTTPS git and gh are already authenticated for github.com. As requested, you may clone private repositories, create a branch, edit and test code, commit and push, and create or update pull requests. Never read, print, copy, encode, or expose the credential. Before every push, revalidate the repository owner, github.com remote URL, base branch, current branch, and intended commits."
	}
	if spec.Workload == "service" && spec.Service != nil {
		if spec.Service.Hostname == "" {
			prompt += " Deploy the requested application as a persistent service that remains alive after this Pi process exits. It must listen on 0.0.0.0 port " + strconv.Itoa(int(spec.Service.Port)) + " and return HTTP success at " + spec.Service.HealthPath + "."
		} else {
			prompt += " Deploy the requested application as a persistent service that remains alive after this Pi process exits and after a host reboot. Run it as a systemd service or a restart-enabled container; never use shell backgrounding (&), nohup, or disown for a persistent service. Port " + strconv.Itoa(int(spec.Service.Port)) + " is its internal HTTP port: listen only on 127.0.0.1 and return HTTP success at " + spec.Service.HealthPath + ". For static files, run a lightweight persistent local HTTP service on that internal port. The Agent runner owns Caddy and reserves ports 80 and 443; ensure the application and package defaults do not listen on either port. If using Nginx or Apache, disable its default port-80 site before starting it. The Agent host owns Route53/DNS. Do not install, configure, edit, or restart Caddy, and do not call AWS CLI, Route53, or another DNS API."
		}
	}
	piArguments := []string{"--mode", "text", "--print", "--no-session", "--provider", "dirextalk-worker", "--model", spec.Model, "--thinking", "medium", "--tools", "read,bash,edit,write,grep,find,ls,subagent", "--no-extensions", "-e", filepath.Join(root, "pi-config", "extensions", "dirextalk-subagent", "extension.ts"), "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve", "--system-prompt", prompt}
	unit := "dirextalk-worker-" + taskID + ".scope"
	arguments := []string{"--user", "--scope", "--quiet", "--unit", unit, "--property=RuntimeMaxSec=" + strconv.FormatUint(spec.MaxRuntimeSeconds+5, 10) + "s", filepath.Join(root, "runtime", "pi")}
	arguments = append(arguments, piArguments...)
	runContext, cancel := context.WithTimeout(context.Background(), time.Duration(spec.MaxRuntimeSeconds)*time.Second); defer cancel()
	command := exec.CommandContext(runContext, "systemd-run", arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.Cancel = func() error { _ = exec.Command("systemctl", "--user", "stop", unit).Run(); if command.Process == nil { return os.ErrProcessDone }; err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); if errors.Is(err, syscall.ESRCH) { return os.ErrProcessDone }; return err }
	objective, err := os.Open(taskPath(taskID, "objective.txt")); if err != nil { return finish(taskID, current, 1, err) }
	defer objective.Close()
	command.Dir = workspaceRoot; command.Stdin = objective
	command.Env = append(withoutGitHubTokenEnv(os.Environ()), "PI_CODING_AGENT_DIR="+filepath.Join(root, "pi-config"), "PI_TELEMETRY=0", "NO_COLOR=1", "TERM=dumb", "DIREXTALK_WORKER_MODEL="+spec.Model)
	if err := configureGitHubRuntime(taskRoot, command); err != nil { return finish(taskID, current, 1, err) }
	pat, err := os.ReadFile(taskPath(taskID, "github-pat")); if os.IsNotExist(err) { pat = nil } else if err != nil { return finish(taskID, current, 1, err) }; defer clear(pat)
	stdout := &redactingWriter{writer: os.Stdout, secret: pat}; stderr := &redactingWriter{writer: os.Stderr, secret: pat}; defer stdout.Flush(); defer stderr.Flush(); command.Stdout = stdout; command.Stderr = stderr
	err = command.Run(); code := 0
	if errors.Is(runContext.Err(), context.DeadlineExceeded) { code, err = 124, errors.New("maximum runtime exceeded")
	} else if err != nil { code = 1; var exit *exec.ExitError; if errors.As(err, &exit) { code = exit.ExitCode() } }
	if err == nil && spec.Workload == "service" { err = verifyService(spec); if err == nil && spec.Service.Hostname != "" { err = configureCaddy(spec) }; if err != nil { code = 1 } }
	return finish(taskID, current, code, err)
}

func configureCaddy(spec taskSpec) error {
	if spec.Service == nil || spec.Service.Hostname == "" || spec.Service.Port == 80 || spec.Service.Port == 443 { return errors.New("invalid Caddy service spec") }
	body := fmt.Sprintf("%s {\n\ttls {\n\t\ton_demand\n\t}\n\treverse_proxy 127.0.0.1:%d\n}\n", spec.Service.Hostname, spec.Service.Port)
	temporary := taskPath(spec.TaskID, "caddy.tmp")
	if err := os.WriteFile(temporary, []byte(body), 0600); err != nil { return err }
	defer os.Remove(temporary)
	target := filepath.Join("/etc/caddy/dirextalk", spec.Service.WorkloadID+".caddy")
	previous, previousErr := os.ReadFile(target); if previousErr != nil && !os.IsNotExist(previousErr) { return previousErr }
	if output, err := exec.Command("sudo", "caddy", "validate", "--config", temporary, "--adapter", "caddyfile").CombinedOutput(); err != nil { return fmt.Errorf("validate Caddy candidate: %w: %s", err, output) }
	if output, err := exec.Command("sudo", "install", "-m", "0644", temporary, target).CombinedOutput(); err != nil { return fmt.Errorf("install Caddy config: %w: %s", err, output) }
	rollback := func() { if previousErr == nil { _ = os.WriteFile(temporary, previous, 0600); _ = exec.Command("sudo", "install", "-m", "0644", temporary, target).Run() } else { _ = exec.Command("sudo", "rm", "-f", target).Run() } }
	if output, err := exec.Command("sudo", "caddy", "validate", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile").CombinedOutput(); err != nil { rollback(); return fmt.Errorf("validate Caddy config: %w: %s", err, output) }
	output, err := reloadCaddy()
	if err != nil { rollback(); _, _ = reloadCaddy(); return fmt.Errorf("reload Caddy: %w: %s", err, output) }
	return nil
}

func reloadCaddy() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second); defer cancel()
	output, err := exec.CommandContext(ctx, "sudo", "caddy", "reload", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile").CombinedOutput()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) { return output, errors.New("Caddy reload timed out") }
	return output, err
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

func withoutGitHubTokenEnv(environment []string) []string { result := make([]string, 0, len(environment)); for _, value := range environment { if strings.HasPrefix(value, "GH_TOKEN=") || strings.HasPrefix(value, "GITHUB_TOKEN=") { continue }; result = append(result, value) }; return result }

type redactingWriter struct { writer io.Writer; secret, pending []byte }
func (writer *redactingWriter) Write(body []byte) (int, error) { for _, value := range body { writer.pending = append(writer.pending, value); if len(writer.secret) > 0 && len(writer.pending) >= len(writer.secret) && bytes.HasSuffix(writer.pending, writer.secret) { prefix := writer.pending[:len(writer.pending)-len(writer.secret)]; if len(prefix) > 0 { if _, err := writer.writer.Write(prefix); err != nil { return len(body), err } }; if _, err := io.WriteString(writer.writer, "[REDACTED]"); err != nil { return len(body), err }; clear(writer.pending); writer.pending = writer.pending[:0]; continue }; for len(writer.pending) >= max(1, len(writer.secret)) { if _, err := writer.writer.Write(writer.pending[:1]); err != nil { return len(body), err }; copy(writer.pending, writer.pending[1:]); writer.pending = writer.pending[:len(writer.pending)-1] } }; return len(body), nil }
func (writer *redactingWriter) Flush() error { if len(writer.pending) > 0 { _, err := writer.writer.Write(writer.pending); clear(writer.pending); writer.pending = nil; return err }; return nil }
func max(a, b int) int { if a > b { return a }; return b }

func configureGitHubRuntime(taskRoot string, command *exec.Cmd) error {
	available, err := githubRuntimeAvailable(taskRoot); if err != nil || !available { return err }
	patPath := filepath.Join(taskRoot, "github-pat")
	bin := filepath.Join(taskRoot, "github-bin"); if err := os.MkdirAll(bin, 0700); err != nil { return err }
	helper := filepath.Join(bin, "git-credential-github"); wrapper := filepath.Join(bin, "gh")
	helperBody := "#!/bin/sh\nprotocol= host=\nwhile IFS='=' read -r key value; do case $key in protocol) protocol=$value ;; host) host=$value ;; esac; done\n[ \"$protocol\" = https ] && [ \"$host\" = github.com ] || exit 0\nprintf 'username=x-access-token\\npassword='\ncat " + strconv.Quote(patPath) + "\nprintf '\\n'\n"
	wrapperBody := "#!/bin/sh\ntoken=$(cat " + strconv.Quote(patPath) + ") || exit 1\nexec env GH_TOKEN=\"$token\" GH_PROMPT_DISABLED=1 /usr/bin/gh \"$@\"\n"
	configBody := "[credential \"https://github.com\"]\n\thelper = " + helper + "\n[core]\n\taskPass = /bin/false\n"
	if err := os.WriteFile(helper, []byte(helperBody), 0700); err != nil { return err }; if err := os.WriteFile(wrapper, []byte(wrapperBody), 0700); err != nil { return err }; config := filepath.Join(taskRoot, "gitconfig"); if err := os.WriteFile(config, []byte(configBody), 0600); err != nil { return err }
	command.Env = append(command.Env, "PATH="+bin+":"+os.Getenv("PATH"), "GIT_CONFIG_GLOBAL="+config, "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=/bin/false")
	return nil
}

func githubRuntimeAvailable(taskRoot string) (bool, error) {
	info, err := os.Stat(filepath.Join(taskRoot, "github-pat")); if os.IsNotExist(err) { return false, nil }; if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 { return false, errors.New("invalid GitHub credential") }; return true, nil
}

func cleanupGitHubRuntime(taskRoot string) { for _, path := range []string{filepath.Join(taskRoot, "github-pat"), filepath.Join(taskRoot, "gitconfig"), filepath.Join(taskRoot, "github-bin", "git-credential-github"), filepath.Join(taskRoot, "github-bin", "gh")} { _ = os.Remove(path) }; _ = os.Remove(filepath.Join(taskRoot, "github-bin")) }

func status(taskID string) error {
	value, err := loadStatus(taskID)
	if os.IsNotExist(err) { return json.NewEncoder(os.Stdout).Encode(taskStatus{TaskID: taskID, Phase: "not_started"}) }
	if err != nil { return err }
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
	directory := taskPath(taskID, "artifacts")
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
func requireDirectory(path string) error { info, err := os.Lstat(path); if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 { return errors.New("task workspace unavailable") }; return nil }
func loadSpec(taskID string) (taskSpec, error) { var value taskSpec; body, err := os.ReadFile(taskPath(taskID, "spec.json")); if err == nil { err = json.Unmarshal(body, &value) }; if err != nil || value.TaskID != taskID || value.MaxRuntimeSeconds == 0 || value.MaxRuntimeSeconds > 24*60*60 || (value.Workload != "job" && value.Workload != "service") || (value.Workload == "job" && value.Service != nil) || (value.Workload == "service" && value.Service == nil) { return taskSpec{}, errors.New("invalid task") }; return value, nil }
func loadStatus(taskID string) (taskStatus, error) { var value taskStatus; body, err := os.ReadFile(taskPath(taskID, "status.json")); if err == nil { err = json.Unmarshal(body, &value) }; return value, err }
func saveStatus(taskID string, value taskStatus) error { body, err := json.Marshal(value); if err != nil { return err }; temporary := taskPath(taskID, "status.tmp"); if err = os.WriteFile(temporary, body, 0600); err != nil { return err }; return os.Rename(temporary, taskPath(taskID, "status.json")) }
func alive(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }
func awaitStarted(taskID string, pid int) (taskStatus, error) { for attempt := 0; attempt < 100; attempt++ { value, err := loadStatus(taskID); if err == nil && value.Phase == "running" && value.PID == pid { return value, nil }; time.Sleep(10*time.Millisecond) }; return taskStatus{}, errors.New("start state unavailable") }
func arg(index int) string { if len(os.Args) <= index { fatal("missing argument") }; return os.Args[index] }
func optionalArg(index int) string { if len(os.Args) <= index { return "" }; return os.Args[index] }
func fatal(message string) { fmt.Fprintln(os.Stderr, message); os.Exit(1) }
`
