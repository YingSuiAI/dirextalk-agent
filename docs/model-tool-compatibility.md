# Model tool compatibility probe

## Where it sits

```text
test_model / TestConnection RPC
        -> coremodel.Service
        -> connectionTester
        -> provider-neutral Client
        -> OpenAI / Anthropic / Gemini HTTP adapter
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
3. `internal/coremodel/http.go`: provider-specific request and response mapping.
4. `internal/rpcapi/core_model_profile_service.go`: public result projection.
5. `internal/coremodel/tool_compatibility_test.go`: executable examples of each
   verdict.
