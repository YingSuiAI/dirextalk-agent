// dirextalk-builtin-mcp is the immutable, network-free executable published
// as the two default read-only MCP installations.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/YingSuiAI/dirextalk-agent/internal/buildinfo"
	"golang.org/x/sys/unix"
)

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
	if len(os.Args) != 2 || os.Args[1] != "server_time" && os.Args[1] != "server_load" {
		_, _ = fmt.Fprintln(os.Stderr, "usage: dirextalk-builtin-mcp <server_time|server_load>")
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
			response["result"] = map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]any{"name": "dirextalk-" + kind, "version": "1.0.0"}}
		case "tools/list":
			response["result"] = map[string]any{"tools": []any{tool(kind)}}
		case "tools/call":
			result, err := call(kind, input.Params)
			if err != nil {
				response["error"] = map[string]any{"code": -32602, "message": "invalid tool call"}
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
	return map[string]any{"name": kind, "description": description, "inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false}}
}

func call(kind string, raw json.RawMessage) (map[string]any, error) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if json.Unmarshal(raw, &params) != nil || params.Name != kind || len(params.Arguments) != 0 {
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
