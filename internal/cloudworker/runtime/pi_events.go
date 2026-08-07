package runtime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"unicode/utf8"
)

const (
	PiResultExtensionName = "dirextalk_result_v1"
	PiResultToolName      = "dirextalk_submit_result"
	maxPiEventLineBytes   = 2 << 20
	maxFinalListItems     = 64
	maxFinalItemBytes     = 8 << 10
)

type piEvent struct {
	Type      string          `json:"type"`
	Version   int             `json:"version,omitempty"`
	Message   json.RawMessage `json:"message,omitempty"`
	ToolName  string          `json:"toolName,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	IsError   bool            `json:"isError,omitempty"`
	WillRetry bool            `json:"willRetry,omitempty"`
}

type piMessage struct {
	Role         string  `json:"role"`
	Usage        piUsage `json:"usage"`
	StopReason   string  `json:"stopReason"`
	ErrorMessage string  `json:"errorMessage"`
}

type piUsage struct {
	Input      int64 `json:"input"`
	Output     int64 `json:"output"`
	CacheRead  int64 `json:"cacheRead"`
	CacheWrite int64 `json:"cacheWrite"`
	Reasoning  int64 `json:"reasoning"`
}

type piToolResult struct {
	Details   json.RawMessage `json:"details"`
	Terminate bool            `json:"terminate"`
}

type piFinalDetails struct {
	Status       string   `json:"status"`
	Summary      string   `json:"summary"`
	Deliverables []string `json:"deliverables"`
	Tests        []string `json:"tests"`
	Risks        []string `json:"risks"`
}

type PiFinalV1 struct {
	SchemaVersion string   `json:"schema_version"`
	Status        string   `json:"status"`
	Summary       string   `json:"summary"`
	Deliverables  []string `json:"deliverables"`
	Tests         []string `json:"tests"`
	Risks         []string `json:"risks"`
}

func ParsePiEvents(stream []byte) (Usage, []byte, error) {
	if len(stream) == 0 || len(stream) > MaxProcessOutputBytes || !utf8.Valid(stream) {
		return Usage{}, nil, newFailure(FailureStagePi, FailureCodePiEventInvalid)
	}
	scanner := bufio.NewScanner(bytes.NewReader(stream))
	scanner.Buffer(make([]byte, 64<<10), maxPiEventLineBytes)
	sessionSeen := false
	agentStarted := false
	agentEnded := false
	agentSettled := false
	finalSeen := false
	var usage Usage
	var finalJSON []byte
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if agentSettled {
			clear(finalJSON)
			return Usage{}, nil, piEventInvalid()
		}
		var event piEvent
		if json.Unmarshal(line, &event) != nil || !validPiEventType(event.Type) {
			clear(finalJSON)
			return Usage{}, nil, piEventInvalid()
		}
		switch event.Type {
		case "session":
			if sessionSeen || agentStarted || event.Version != 3 {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			sessionSeen = true
		case "agent_start":
			if !sessionSeen || agentStarted || agentEnded {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			agentStarted = true
		case "message_end":
			if !agentStarted || agentEnded {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			var message piMessage
			if json.Unmarshal(event.Message, &message) != nil {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			if message.Role == "assistant" {
				switch message.StopReason {
				case "error":
					clear(finalJSON)
					return Usage{}, nil, classifyPiProviderFailure(message.ErrorMessage)
				case "aborted":
					clear(finalJSON)
					return Usage{}, nil, newFailure(FailureStagePi, FailureCodePiAborted)
				}
				if addPiUsage(&usage, message.Usage) != nil {
					clear(finalJSON)
					return Usage{}, nil, piEventInvalid()
				}
			}
		case "tool_execution_end":
			if !agentStarted || agentEnded {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			if event.ToolName != PiResultToolName {
				continue
			}
			if finalSeen || event.IsError {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			var result piToolResult
			if json.Unmarshal(event.Result, &result) != nil || !result.Terminate {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			canonical, err := canonicalPiFinal(result.Details)
			if err != nil {
				clear(finalJSON)
				return Usage{}, nil, err
			}
			finalJSON = canonical
			finalSeen = true
		case "agent_end":
			if !agentStarted || agentEnded || event.WillRetry {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			agentEnded = true
		case "agent_settled":
			if !agentEnded || agentSettled {
				clear(finalJSON)
				return Usage{}, nil, piEventInvalid()
			}
			agentSettled = true
		}
	}
	if scanner.Err() != nil || !sessionSeen || !agentStarted ||
		!agentEnded || !agentSettled || usage.Validate() != nil {
		clear(finalJSON)
		return Usage{}, nil, piEventInvalid()
	}
	if !finalSeen {
		return Usage{}, nil, newFailure(FailureStagePi, FailureCodePiFinalMissing)
	}
	return usage, finalJSON, nil
}

func ParsePiFinalV1(input []byte) (PiFinalV1, []byte, error) {
	if len(input) == 0 || len(input) > MaxFinalArtifactBytes {
		return PiFinalV1{}, nil, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.DisallowUnknownFields()
	var final PiFinalV1
	if decoder.Decode(&final) != nil {
		return PiFinalV1{}, nil, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return PiFinalV1{}, nil, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	if final.SchemaVersion != PiFinalSchemaV1 ||
		(final.Status != "completed" && final.Status != "partial" && final.Status != "blocked") ||
		!validText(final.Summary, maxFinalItemBytes) ||
		!validFinalList(final.Deliverables) ||
		!validFinalList(final.Tests) || !validFinalList(final.Risks) {
		return PiFinalV1{}, nil, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	encoded, err := json.Marshal(final)
	if err != nil {
		return PiFinalV1{}, nil, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	return final, encoded, nil
}

func canonicalPiFinal(detailsJSON []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(detailsJSON))
	decoder.DisallowUnknownFields()
	var details piFinalDetails
	if decoder.Decode(&details) != nil {
		return nil, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	encoded, err := json.Marshal(PiFinalV1{
		SchemaVersion: PiFinalSchemaV1,
		Status:        details.Status, Summary: details.Summary,
		Deliverables: details.Deliverables, Tests: details.Tests, Risks: details.Risks,
	})
	if err != nil {
		return nil, newFailure(FailureStageOutput, FailureCodeOutputInvalid)
	}
	_, canonical, err := ParsePiFinalV1(encoded)
	clear(encoded)
	return canonical, err
}

func validFinalList(values []string) bool {
	if values == nil || len(values) > maxFinalListItems {
		return false
	}
	for _, value := range values {
		if !validText(value, maxFinalItemBytes) {
			return false
		}
	}
	return true
}

func piEventInvalid() error {
	return newFailure(FailureStagePi, FailureCodePiEventInvalid)
}

func classifyPiProviderFailure(message string) error {
	normalized := strings.ToLower(strings.TrimSpace(message))
	code := FailureCodeProviderUnknown
	switch {
	case strings.HasPrefix(normalized, "401"),
		strings.Contains(normalized, "authentication"),
		strings.Contains(normalized, "unauthorized"),
		strings.Contains(normalized, "invalid api key"):
		code = FailureCodeProviderAuthentication
	case strings.HasPrefix(normalized, "402"),
		strings.Contains(normalized, "insufficient_balance"),
		strings.Contains(normalized, "quota"), strings.Contains(normalized, "billing"):
		code = FailureCodeProviderQuota
	case strings.HasPrefix(normalized, "429"), strings.Contains(normalized, "rate_limit"):
		code = FailureCodeProviderRateLimit
	case strings.HasPrefix(normalized, "400"), strings.HasPrefix(normalized, "404"),
		strings.HasPrefix(normalized, "422"), strings.Contains(normalized, "invalid_request"):
		code = FailureCodeProviderRequest
	case strings.HasPrefix(normalized, "500"), strings.HasPrefix(normalized, "502"),
		strings.HasPrefix(normalized, "503"), strings.HasPrefix(normalized, "504"),
		strings.Contains(normalized, "server_error"), strings.Contains(normalized, "service unavailable"):
		code = FailureCodeProviderServer
	case strings.Contains(normalized, "fetch failed"), strings.Contains(normalized, "connection"),
		strings.Contains(normalized, "network"), strings.Contains(normalized, "timed out"):
		code = FailureCodeProviderNetwork
	}
	return newFailure(FailureStagePi, code)
}

func validPiEventType(value string) bool {
	switch value {
	case "session", "agent_start", "agent_end", "agent_settled",
		"entry_appended", "session_info_changed", "thinking_level_changed",
		"turn_start", "turn_end", "message_start", "message_update", "message_end",
		"bash_execution_update", "tool_execution_start", "tool_execution_update",
		"tool_execution_end", "queue_update", "compaction_start", "compaction_end",
		"auto_retry_start", "auto_retry_end", "summarization_retry_scheduled",
		"summarization_retry_attempt_start", "summarization_retry_finished":
		return true
	default:
		return false
	}
}

func addPiUsage(total *Usage, value piUsage) error {
	if total == nil || value.Input < 0 || value.Output < 0 || value.CacheRead < 0 ||
		value.CacheWrite < 0 || value.Reasoning < 0 ||
		value.CacheRead > math.MaxInt64-value.Input ||
		value.CacheWrite > math.MaxInt64-value.Input-value.CacheRead {
		return ErrExecution
	}
	normalizedInput := value.Input + value.CacheRead + value.CacheWrite
	if total.InputTokens > math.MaxInt64-normalizedInput ||
		total.OutputTokens > math.MaxInt64-value.Output ||
		total.CachedInputTokens > math.MaxInt64-value.CacheRead ||
		total.ReasoningOutputTokens > math.MaxInt64-value.Reasoning {
		return ErrExecution
	}
	total.InputTokens += normalizedInput
	total.OutputTokens += value.Output
	total.CachedInputTokens += value.CacheRead
	total.ReasoningOutputTokens += value.Reasoning
	return nil
}
