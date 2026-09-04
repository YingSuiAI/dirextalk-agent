# Model tool compatibility probe

## Where it sits

```text
test_model / TestConnection RPC
        -> coremodel.Service
        -> connectionTester
        -> provider-neutral Client
        -> OpenAI / DeepSeek DSML / Anthropic / Gemini HTTP adapter
```

Basic reachability and tool compatibility answer different questions:

- `reachable`: can the Agent authenticate and reach the provider?
- `tool_compatibility.status`: can this profile complete Dirextalk's structured
  tool protocol?

The compatibility handshake runs only when the caller sets
`probe_tool_compatibility=true`. It may issue three billable model requests.

## The three stages

1. `structured_tool_call` sends one forced synthetic function and requires one
   structured call with `{"value":"probe-ok"}`.
2. `streaming_tool_call` sends the same contract through the streaming API and
   reconstructs fragments by tool-call index.
3. `tool_result_continuation` adds an assistant tool call plus a fabricated tool
   result, then requires the final marker `DIREXTALK_PROBE_COMPLETE`.

The synthetic function is never registered with the capability registry. The
probe only validates returned data in memory, so no tool, Worker, AWS resource,
repository, or file can be changed.

## DeepSeek DSML adapter

Select `request_dialect=deepseek_dsml_v4` only for a DeepSeek-compatible
profile that may return DSML in ordinary message content. The request is still
sent through the OpenAI-compatible Chat Completions contract. On the response
boundary, `internal/coremodel/deepseek_adapter.go` performs this translation:

```text
DeepSeek content/SSE fragments
        -> buffer one complete response
        -> require a complete DSML tool_calls envelope
        -> require a tool declared in this request
        -> parse typed parameters or one JSON object
        -> coremodel.ToolCall
        -> existing runtime validation and execution policy
```

Native provider `tool_calls` always win and pass through unchanged. The adapter
does not parse prose, Markdown examples, generic XML, incomplete DSML, unknown
tools, duplicate parameters, or invalid JSON. Those cases remain non-executable
and the runtime quarantine can return `model_tool_call_format_invalid`.

The compatibility probe needs no DeepSeek-specific branch. Its ordinary
`Generate` and `Stream` calls already cross the adapter, so all three stages
test the normalized contract seen by the rest of Core.

## Provider adapter audit

| Configuration platform | Current Core path | Additional adapter? |
| --- | --- | --- |
| OpenAI | OpenAI Chat Completions | No. The response already uses `message.tool_calls` and indexed streaming deltas. |
| Anthropic | Native Messages adapter | Already present. It maps `tool_use` and `tool_result` content blocks. |
| DeepSeek | OpenAI-compatible request plus opt-in DSML response adapter | Yes, `deepseek_dsml_v4`, when the selected model emits DSML content. |
| Gemini | Native GenerateContent adapter | Already present. It maps `functionCall` and `functionResponse` parts. |
| xAI | OpenAI-compatible Chat Completions | No for the current endpoint. A future move to xAI Responses would require a new request/response dialect. |
| OpenAI-compatible | OpenAI Chat Completions | Unknown by label alone. Run the probe; add an adapter only for a documented, exact wire protocol. |
| OpenRouter | Standardized OpenAI-compatible tool calls | No platform adapter. Tool support and reliability are model/provider-route properties. |

OpenRouter profiles should first confirm that the selected model advertises
`tools` in `supported_parameters`, then run Dirextalk's three-stage probe. The
metadata check avoids testing a model that declares no tool support; the probe
still matters because advertised support does not prove streaming and
continuation behavior. A DeepSeek model routed through OpenRouter may opt into
`deepseek_dsml_v4` only if an observed response actually contains the exact
DSML protocol.

References: [OpenAI Chat tool calls](https://developers.openai.com/api/reference/resources/chat),
[Anthropic tool-use blocks](https://platform.claude.com/docs/en/agents-and-tools/tool-use/define-tools),
[DeepSeek tool calls](https://api-docs.deepseek.com/guides/tool_calls/),
[Gemini FunctionCall](https://ai.google.dev/api/generate-content),
[xAI function calling](https://docs.x.ai/developers/tools/function-calling), and
[OpenRouter tool calling](https://openrouter.ai/docs/guides/features/tool-calling).

## Verdicts

| Status | Meaning |
| --- | --- |
| `compatible` | All three stages passed. |
| `incompatible` | A deterministic protocol stage failed. |
| `inconclusive` | A transient failure prevented a reliable conclusion. |
| `not_run` | The caller did not request the probe or the profile is not conversational. |

Probe error codes are closed diagnostic categories. They never contain the API
key, provider body, URL, prompt, or returned arguments.

## Reading order

1. `internal/coremodel/service.go`: opt-in and reachability separation.
2. `internal/coremodel/tool_compatibility.go`: the three-stage state machine.
3. `internal/coremodel/deepseek_adapter.go`: strict DSML-to-ToolCall normalization.
4. `internal/coremodel/http.go`: provider-specific request and response mapping.
5. `internal/rpcapi/core_model_profile_service.go`: public result projection.
6. `internal/coremodel/deepseek_adapter_test.go`: DSML and end-to-end probe examples.
7. `internal/coremodel/tool_compatibility_test.go`: executable examples of each
   verdict.
