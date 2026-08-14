// dirextalk-builtin-mcp is the immutable, network-free executable published
// as the default MCP installations.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/buildinfo"
	"golang.org/x/sys/unix"
)

const (
	localSandboxKind           = "local_sandbox"
	localSandboxToolName       = "local_sandbox_run"
	localSandboxShellPath      = "/app/shell"
	localSandboxWorkDir        = "/work"
	localSandboxBinDir         = "/work/.dirextalk-bin"
	localSandboxMaxScriptBytes = 64 << 10
	localSandboxMaxResultPaths = 16
	localSandboxMaxOutputBytes = 64 << 10
)

var newLocalSandboxCommand = func(script string) *exec.Cmd {
	cmd := exec.Command(localSandboxShellPath, "sh", "-c", script)
	cmd.Args[0] = "busybox"
	cmd.Dir = localSandboxWorkDir
	cmd.Env = []string{"HOME=/work", "TMPDIR=/work", "PATH=" + localSandboxBinDir}
	return cmd
}

var errLocalSandboxApplets = errors.New("local sandbox applets unavailable")

var prepareLocalSandboxApplets = func() error {
	list := exec.Command(localSandboxShellPath, "--list")
	list.Args[0] = "busybox"
	output, err := list.Output()
	if err != nil {
		return fmt.Errorf("%w: list", errLocalSandboxApplets)
	}
	if err = os.Mkdir(localSandboxBinDir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: directory", errLocalSandboxApplets)
	}
	for _, name := range strings.Fields(string(output)) {
		if name == "" || strings.Contains(name, "/") {
			continue
		}
		link := path.Join(localSandboxBinDir, name)
		if err = os.Symlink(localSandboxShellPath, link); err != nil && !errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w: links", errLocalSandboxApplets)
		}
	}
	return nil
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func main() {
	if buildinfo.IsVersionRequest(os.Args[1:]) {
		_, _ = fmt.Fprintln(os.Stdout, buildinfo.Version())
		return
	}
	if len(os.Args) != 2 || os.Args[1] != "server_time" && os.Args[1] != "server_load" && os.Args[1] != localSandboxKind {
		_, _ = fmt.Fprintln(os.Stderr, "usage: dirextalk-builtin-mcp <server_time|server_load|local_sandbox>")
		os.Exit(2)
	}
	if err := serve(os.Args[1]); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "builtin MCP failed")
		os.Exit(1)
	}
}

func serve(kind string) error {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var input request
		if json.Unmarshal(scanner.Bytes(), &input) != nil || input.JSONRPC != "2.0" || input.Method == "" {
			return errors.New("invalid MCP request")
		}
		if input.Method == "notifications/initialized" {
			continue
		}
		response := map[string]any{"jsonrpc": "2.0", "id": input.ID}
		switch input.Method {
		case "initialize":
			response["result"] = map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "dirextalk-" + kind, "version": buildinfo.Version()}}
		case "tools/list":
			response["result"] = map[string]any{"tools": []any{tool(kind)}}
		case "tools/call":
			result, err := call(kind, input.Params)
			if err != nil {
				message := "invalid tool call"
				if errors.Is(err, errLocalSandboxApplets) {
					message = err.Error()
				}
				response["error"] = map[string]any{"code": -32602, "message": message}
			} else {
				response["result"] = result
			}
		default:
			response["error"] = map[string]any{"code": -32601, "message": "method not found"}
		}
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func tool(kind string) map[string]any {
	description := "Return the current server time in UTC."
	if kind == "server_load" {
		description = "Return the current server load, uptime, process count, and memory totals."
	}
	if kind == localSandboxKind {
		return map[string]any{
			"name":        localSandboxToolName,
			"description": "Run a small offline shell script in an ephemeral isolated workspace. Use only for tasks that fit 30 CPU seconds, 256 MiB memory, 32 processes, and 16 MiB total files. Network access is unavailable; use cloud_worker_propose for network, build, deploy, long-running, or larger tasks.",
			"inputSchema": map[string]any{
				"type": "object", "additionalProperties": false,
				"properties": map[string]any{
					"script":       map[string]any{"type": "string", "minLength": 1, "maxLength": localSandboxMaxScriptBytes},
					"result_paths": map[string]any{"type": "array", "maxItems": localSandboxMaxResultPaths, "uniqueItems": true, "items": map[string]any{"type": "string", "minLength": 1, "maxLength": 512}},
				},
				"required": []string{"script"},
			},
		}
	}
	return map[string]any{"name": kind, "description": description, "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}}
}

func call(kind string, raw json.RawMessage) (map[string]any, error) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if json.Unmarshal(raw, &params) != nil {
		return nil, errors.New("invalid tool arguments")
	}
	if kind == localSandboxKind {
		if params.Name != localSandboxToolName {
			return nil, errors.New("invalid tool arguments")
		}
		return runLocalSandbox(params.Arguments)
	}
	if params.Name != kind || len(params.Arguments) != 0 {
		return nil, errors.New("invalid tool arguments")
	}
	var payload map[string]any
	if kind == "server_time" {
		now := time.Now().UTC()
		payload = map[string]any{"timezone": "UTC", "rfc3339": now.Format(time.RFC3339Nano), "unix_seconds": now.Unix()}
	} else {
		var info unix.Sysinfo_t
		if err := unix.Sysinfo(&info); err != nil {
			return nil, err
		}
		unit := uint64(info.Unit)
		if unit == 0 {
			unit = 1
		}
		payload = map[string]any{
			"load_1m":            float64(info.Loads[0]) / 65536,
			"load_5m":            float64(info.Loads[1]) / 65536,
			"load_15m":           float64(info.Loads[2]) / 65536,
			"uptime_seconds":     info.Uptime,
			"processes":          info.Procs,
			"total_memory_bytes": uint64(info.Totalram) * unit,
			"free_memory_bytes":  uint64(info.Freeram) * unit,
		}
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(encoded)}}, "structuredContent": payload, "isError": false}, nil
}

func runLocalSandbox(arguments map[string]any) (map[string]any, error) {
	if len(arguments) == 0 || len(arguments) > 2 {
		return nil, errors.New("invalid tool arguments")
	}
	script, ok := arguments["script"].(string)
	if !ok || strings.TrimSpace(script) == "" || len(script) > localSandboxMaxScriptBytes {
		return nil, errors.New("invalid tool arguments")
	}
	if raw, exists := arguments["result_paths"]; exists {
		values, ok := raw.([]any)
		if !ok || len(values) > localSandboxMaxResultPaths {
			return nil, errors.New("invalid tool arguments")
		}
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			item, ok := value.(string)
			if !ok || !validResultPath(item) {
				return nil, errors.New("invalid tool arguments")
			}
			if _, duplicate := seen[item]; duplicate {
				return nil, errors.New("invalid tool arguments")
			}
			seen[item] = struct{}{}
		}
	}
	if err := prepareLocalSandboxApplets(); err != nil {
		return nil, err
	}
	cmd := newLocalSandboxCommand(script)
	stdout, stderr := &boundedOutput{}, &boundedOutput{}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	err := cmd.Run()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return nil, err
		}
		exitCode = exitErr.ExitCode()
	}
	payload := map[string]any{"stdout": stdout.String(), "stderr": stderr.String(), "exit_code": exitCode, "result_files": []any{}}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return map[string]any{"content": []any{map[string]any{"type": "text", "text": string(encoded)}}, "structuredContent": payload, "isError": exitCode != 0}, nil
}

type boundedOutput struct{ bytes.Buffer }

func (w *boundedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := localSandboxMaxOutputBytes - w.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = w.Buffer.Write(p)
	}
	return n, nil
}

func validResultPath(value string) bool {
	return value != "" && len(value) <= 512 && !strings.HasPrefix(value, "/") && !strings.ContainsAny(value, "\\\x00") && path.Clean(value) == value && value != "." && value != ".." && !strings.HasPrefix(value, "../")
}
