package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestToolsAreReadOnlyAndReturnLiveValues(t *testing.T) {
	for _, kind := range []string{"server_time", "server_load"} {
		definition := tool(kind)
		if definition["name"] != kind {
			t.Fatalf("tool(%s)=%#v", kind, definition)
		}
		result, err := call(kind, json.RawMessage(`{"name":"`+kind+`","arguments":{}}`))
		if err != nil || result["isError"] != false {
			t.Fatalf("call(%s)=%#v err=%v", kind, result, err)
		}
		payload := result["structuredContent"].(map[string]any)
		if kind == "server_time" {
			parsed, err := time.Parse(time.RFC3339Nano, payload["rfc3339"].(string))
			if err != nil || time.Since(parsed) > time.Minute || time.Until(parsed) > time.Minute {
				t.Fatalf("server time=%#v err=%v", payload, err)
			}
		} else if payload["uptime_seconds"].(int64) <= 0 || payload["total_memory_bytes"].(uint64) == 0 {
			t.Fatalf("server load=%#v", payload)
		}
	}
}

func TestToolCallRejectsArgumentsAndWrongName(t *testing.T) {
	for _, raw := range []string{`{"name":"server_time","arguments":{"zone":"local"}}`, `{"name":"other","arguments":{}}`} {
		if _, err := call("server_time", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
