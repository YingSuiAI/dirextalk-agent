package mcphttp

import (
	"bytes"
	"encoding/json"
	"mime"
	"regexp"
	"runtime"
	"strings"
	"unicode/utf8"
)

var (
	credentialAssignmentPattern = regexp.MustCompile(`(?i)\b(authorization|proxy[_-]?authorization|api[_-]?key|access[_-]?token|refresh[_-]?token|secret(?:[_-]?ref)?|password|credential)\b\s*[:=]\s*("[^"]*"|'[^']*'|[^\s,;}\]]+)`)
	bearerPattern               = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`)
	awsAccessKeyPattern         = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b`)
	skTokenPattern              = regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{12,}\b`)
	secretReferencePattern      = regexp.MustCompile(`(?i)\b(?:secret|secretsmanager|kms)://[^\s,;}\]]+`)
	privateKeyPattern           = regexp.MustCompile(`(?s)-----BEGIN [^-\r\n]*PRIVATE KEY-----.*?-----END [^-\r\n]*PRIVATE KEY-----`)
)

func validateInputSchema(schema map[string]any) error {
	if schema == nil || schema["type"] != "object" {
		return ErrInvalidToolDefinition
	}
	encoded, err := json.Marshal(schema)
	if err != nil || len(encoded) > maxSchemaBytes {
		return ErrInvalidToolDefinition
	}
	nodes := 0
	if !safeSchemaNode(schema, 0, &nodes) {
		return ErrInvalidToolDefinition
	}
	return nil
}

func safeSchemaNode(value any, depth int, nodes *int) bool {
	*nodes++
	if depth > 24 || *nodes > 2048 {
		return false
	}
	switch typed := value.(type) {
	case map[string]any:
		if _, hasRef := typed["$ref"]; hasRef {
			return false
		}
		if propertiesValue, exists := typed["properties"]; exists {
			properties, ok := propertiesValue.(map[string]any)
			if !ok {
				return false
			}
			for propertyName, propertySchema := range properties {
				if reservedControlField(propertyName) {
					return false
				}
				if _, ok := propertySchema.(map[string]any); !ok {
					return false
				}
			}
		}
		if requiredValue, exists := typed["required"]; exists {
			required, ok := requiredValue.([]any)
			if !ok {
				return false
			}
			for _, item := range required {
				name, ok := item.(string)
				if !ok || reservedControlField(name) {
					return false
				}
			}
		}
		for _, nested := range typed {
			if !safeSchemaNode(nested, depth+1, nodes) {
				return false
			}
		}
	case []any:
		for _, nested := range typed {
			if !safeSchemaNode(nested, depth+1, nodes) {
				return false
			}
		}
	case string, float64, bool, nil:
		return true
	default:
		return false
	}
	return true
}

func validateToolArguments(raw json.RawMessage) (map[string]any, error) {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	if len(raw) > maxToolArguments || !json.Valid(raw) {
		return nil, ErrUnsafeToolArguments
	}
	var arguments map[string]any
	if err := json.Unmarshal(raw, &arguments); err != nil || arguments == nil {
		return nil, ErrUnsafeToolArguments
	}
	nodes := 0
	if !safeArgumentNode(arguments, 0, &nodes) {
		return nil, ErrUnsafeToolArguments
	}
	return arguments, nil
}

func safeArgumentNode(value any, depth int, nodes *int) bool {
	*nodes++
	if depth > 24 || *nodes > 4096 {
		return false
	}
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			if reservedControlField(key) || !safeArgumentNode(nested, depth+1, nodes) {
				return false
			}
		}
	case []any:
		for _, nested := range typed {
			if !safeArgumentNode(nested, depth+1, nodes) {
				return false
			}
		}
	case string, float64, bool, nil:
		return true
	default:
		return false
	}
	return true
}

func reservedControlField(key string) bool {
	normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(key)))
	switch normalized {
	case "authorization", "proxyauthorization", "apikey", "accesskey", "accesskeyid", "secretaccesskey",
		"accesstoken", "refreshtoken", "token", "password", "secret", "secretref", "credential", "credentials",
		"endpoint", "mcppendpoint", "mcpendpoint", "transport", "headers", "environment", "env":
		return true
	default:
		return false
	}
}

func sanitizeToolResult(content string) string {
	content = redactSensitiveText(content)
	content = strings.TrimSpace(content)
	if content == "" {
		return "{}"
	}
	return truncateUTF8(content, maxToolResultBytes)
}

func sanitizeToolMetadata(content string) string {
	content = strings.TrimSpace(redactSensitiveText(content))
	return truncateUTF8(content, 4096)
}

func redactSensitiveText(content string) string {
	content = strings.ReplaceAll(content, "\x00", "")
	content = privateKeyPattern.ReplaceAllString(content, "[REDACTED]")
	content = credentialAssignmentPattern.ReplaceAllString(content, "$1=[REDACTED]")
	content = bearerPattern.ReplaceAllString(content, "Bearer [REDACTED]")
	content = awsAccessKeyPattern.ReplaceAllString(content, "[REDACTED]")
	content = skTokenPattern.ReplaceAllString(content, "[REDACTED]")
	content = secretReferencePattern.ReplaceAllString(content, "[REDACTED]")
	return content
}

func truncateUTF8(value string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(value) <= limit {
		return value
	}
	suffix := "…"
	cut := limit - len(suffix)
	if cut <= 0 {
		return suffix[:limit]
	}
	for cut > 0 && !utf8.ValidString(value[:cut]) {
		cut--
	}
	return value[:cut] + suffix
}

func redactCredentialPayload(data []byte, contentType string, credential []byte) []byte {
	if len(credential) == 0 {
		return data
	}
	data = redactCredentialBytes(data, credential)
	mediaType, _, _ := mime.ParseMediaType(contentType)
	switch strings.ToLower(mediaType) {
	case "application/json":
		return redactCredentialJSON(data, string(credential))
	case "text/event-stream":
		lines := bytes.SplitAfter(data, []byte("\n"))
		for index, line := range lines {
			ending := []byte{}
			trimmed := line
			if bytes.HasSuffix(trimmed, []byte("\n")) {
				ending = []byte("\n")
				trimmed = bytes.TrimSuffix(trimmed, []byte("\n"))
			}
			carriage := []byte{}
			if bytes.HasSuffix(trimmed, []byte("\r")) {
				carriage = []byte("\r")
				trimmed = bytes.TrimSuffix(trimmed, []byte("\r"))
			}
			if !bytes.HasPrefix(trimmed, []byte("data:")) {
				continue
			}
			prefix := []byte("data:")
			payload := bytes.TrimPrefix(trimmed, prefix)
			if bytes.HasPrefix(payload, []byte(" ")) {
				prefix = []byte("data: ")
				payload = bytes.TrimPrefix(payload, []byte(" "))
			}
			redacted := redactCredentialJSON(payload, string(credential))
			lines[index] = bytes.Join([][]byte{prefix, redacted, carriage, ending}, nil)
		}
		return bytes.Join(lines, nil)
	default:
		return data
	}
}

func redactCredentialBytes(data []byte, credential []byte) []byte {
	redacted := []byte("[REDACTED]")
	data = bytes.ReplaceAll(data, credential, redacted)
	if encoded, err := json.Marshal(string(credential)); err == nil && len(encoded) >= 2 {
		data = bytes.ReplaceAll(data, encoded[1:len(encoded)-1], redacted)
	}
	return data
}

func redactCredentialJSON(data []byte, credential string) []byte {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return data
	}
	document = redactCredentialValue(document, credential)
	redacted, err := json.Marshal(document)
	if err != nil {
		return data
	}
	return redacted
}

func redactCredentialValue(value any, credential string) any {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			typed[key] = redactCredentialValue(nested, credential)
		}
		return typed
	case []any:
		for index, nested := range typed {
			typed[index] = redactCredentialValue(nested, credential)
		}
		return typed
	case string:
		return strings.ReplaceAll(typed, credential, "[REDACTED]")
	default:
		return value
	}
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}
