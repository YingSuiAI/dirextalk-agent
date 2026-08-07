package modelrelay

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"mime"
	"strings"
)

const maximumProviderEventLineBytes = 2 << 20

func providerOutputTokens(path, contentType string, body []byte) (uint64, bool) {
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || len(body) == 0 {
		return 0, false
	}
	switch mediaType {
	case "application/json":
		value, ok := decodeProviderObject(body)
		if !ok {
			return 0, false
		}
		return outputTokensFromObject(path, value)
	case "text/event-stream":
		return outputTokensFromEvents(path, body)
	default:
		return 0, false
	}
}

func outputTokensFromEvents(path string, body []byte) (uint64, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maximumProviderEventLineBytes)
	var selected uint64
	found := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "" || payload == "[DONE]" {
			continue
		}
		value, ok := decodeProviderObject([]byte(payload))
		if !ok {
			return 0, false
		}
		if current, ok := outputTokensFromObject(path, value); ok {
			if !found || current > selected {
				selected = current
			}
			found = true
		}
	}
	if scanner.Err() != nil {
		return 0, false
	}
	return selected, found
}

func decodeProviderObject(raw []byte) (map[string]any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if decoder.Decode(&value) != nil || value == nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return value, true
}

func outputTokensFromObject(path string, value map[string]any) (uint64, bool) {
	if path == PathChatCompletions {
		return nestedUint(value, "usage", "completion_tokens")
	}
	if path != PathResponses {
		return 0, false
	}
	if tokens, ok := nestedUint(value, "usage", "output_tokens"); ok {
		return tokens, true
	}
	return nestedUint(value, "response", "usage", "output_tokens")
}

func nestedUint(value map[string]any, path ...string) (uint64, bool) {
	var current any = value
	for _, name := range path {
		object, ok := current.(map[string]any)
		if !ok {
			return 0, false
		}
		current, ok = object[name]
		if !ok {
			return 0, false
		}
	}
	return jsonUint(current)
}
