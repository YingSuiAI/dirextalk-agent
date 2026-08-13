import {
  defineTool,
  estimateTokens,
  type ExtensionAPI,
} from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

interface DirextalkResultDetails {
  status: "completed" | "partial" | "blocked";
  summary: string;
  deliverables: string[];
  tests: string[];
  risks: string[];
}

const MIN_CONTEXT_WINDOW = 16384;
const PROVIDER_PROTOCOL_TOKEN_RESERVE = 2048;
const MODEL_RELAY_MAX_REQUEST_BYTES = 2 * 1024 * 1024;
const RECENT_TOOL_RESULTS = 2;
const RECENT_TOOL_ROUNDS = 2;
const OLD_TOOL_TEXT_CHARS = 1024;
const RECENT_TOOL_TEXT_CHARS = 4096;

type ContextRecord = Record<string, unknown>;

export function estimatedDirextalkContextTokens(value: unknown): number {
  try {
    const encoded = JSON.stringify(value) ?? "";
    // Pi 0.83 has no tokenizer bound to the selected model. UTF-8 bytes are a
    // conservative upper bound for byte-level provider tokenizers and avoid
    // undercounting Base64, random identifiers, code, or uncommon CJK. This
    // does not change Central's signed model window; it is only the fail-closed
    // fallback used to fit a request when an exact tokenizer is unavailable.
    return new TextEncoder().encode(encoded).byteLength;
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
}

function estimatedDirextalkMessageTokens(messages: unknown[]): number {
  return messages.reduce((total, message) => {
    try {
      return total + Math.max(
        estimateTokens(message as Parameters<typeof estimateTokens>[0]),
        estimatedDirextalkContextTokens(message),
      );
    } catch {
      return Number.MAX_SAFE_INTEGER;
    }
  }, 0);
}

function boundedText(value: string, maximum: number): string {
  if (value.length <= maximum) return value;
  const notice = `\n[Dirextalk context guard: ${value.length - maximum} characters omitted; re-read the source file or rerun the command if needed.]\n`;
  const available = Math.max(0, maximum - notice.length);
  const head = Math.ceil(available / 2);
  return value.slice(0, head) + notice + value.slice(value.length - (available - head));
}

function compactToolResult(message: ContextRecord, maximum: number): ContextRecord {
  const toolName = typeof message.toolName === "string" ? message.toolName : "tool";
  const content = Array.isArray(message.content)
    ? message.content.map((item) => {
        if (item && typeof item === "object" && (item as ContextRecord).type === "text") {
          const text = (item as ContextRecord).text;
          return {
            ...(item as ContextRecord),
            text: boundedText(typeof text === "string" ? text : "", maximum),
          };
        }
        return {
          type: "text",
          text: `[Dirextalk context guard: older ${toolName} binary/image output omitted; reopen the workspace file if needed.]`,
        };
      })
    : [{ type: "text", text: `[Dirextalk context guard: older ${toolName} output omitted.]` }];
  const compacted = { ...message, content };
  delete compacted.details;
  return compacted;
}

interface ToolRound {
  start: number;
  end: number;
}

function completedToolRounds(messages: ContextRecord[]): ToolRound[] {
  const rounds: ToolRound[] = [];
  for (let index = 0; index < messages.length; index++) {
    const message = messages[index];
    if (message?.role !== "assistant" || !Array.isArray(message.content)) continue;
    const callIDs = new Set(
      message.content
        .filter((item) => item && typeof item === "object" && (item as ContextRecord).type === "toolCall")
        .map((item) => (item as ContextRecord).id)
        .filter((id): id is string => typeof id === "string" && id.length > 0),
    );
    if (callIDs.size === 0) continue;

    const matched = new Set<string>();
    let end = index;
    for (let cursor = index + 1; cursor < messages.length; cursor++) {
      const candidate = messages[cursor];
      if (candidate?.role !== "toolResult") break;
      const resultID = candidate.toolCallId;
      if (typeof resultID !== "string" || !callIDs.has(resultID)) break;
      matched.add(resultID);
      end = cursor;
    }
    if (matched.size === callIDs.size) {
      rounds.push({ start: index, end });
      index = end;
    }
  }
  return rounds;
}

export function compactDirextalkContext<T>(
  messages: T[],
  contextWindow: number,
  maxTokens: number,
  requestOverheadTokens: number,
): T[] {
  if (!Number.isFinite(contextWindow) || !Number.isFinite(maxTokens) ||
      !Number.isFinite(requestOverheadTokens) || contextWindow < MIN_CONTEXT_WINDOW ||
      maxTokens <= 0 || maxTokens >= contextWindow || requestOverheadTokens < 0) {
    throw new Error("Dirextalk context guard received invalid authorized model limits");
  }
  const target = contextWindow - maxTokens - requestOverheadTokens - PROVIDER_PROTOCOL_TOKEN_RESERVE;
  if (target <= 0) {
    throw new Error("Dirextalk request overhead leaves no authorized message context");
  }
  if (estimatedDirextalkMessageTokens(messages) <= target) return messages;

  const result = messages.slice() as unknown as ContextRecord[];
  const toolResultIndexes = result
    .map((message, index) => message?.role === "toolResult" ? index : -1)
    .filter((index) => index >= 0);
  const protectedStart = Math.max(0, toolResultIndexes.length - RECENT_TOOL_RESULTS);

  const compactAt = (resultIndex: number, maximum: number) => {
    result[resultIndex] = compactToolResult(result[resultIndex], maximum);
  };

  for (let index = 0; index < protectedStart; index++) {
    compactAt(toolResultIndexes[index], OLD_TOOL_TEXT_CHARS);
    if (estimatedDirextalkMessageTokens(result) <= target) return result as unknown as T[];
  }

  // Drop only complete historical tool rounds. Removing the assistant call and
  // every paired result together preserves provider tool-call invariants while
  // retaining the original user objective and the most recent working state.
  for (;;) {
    const rounds = completedToolRounds(result);
    if (rounds.length <= RECENT_TOOL_ROUNDS) break;
    const oldest = rounds[0];
    result.splice(oldest.start, oldest.end - oldest.start + 1);
    if (estimatedDirextalkMessageTokens(result) <= target) return result as unknown as T[];
  }

  const remainingToolResultIndexes = result
    .map((message, index) => message?.role === "toolResult" ? index : -1)
    .filter((index) => index >= 0);
  for (const resultIndex of remainingToolResultIndexes) {
    compactAt(resultIndex, RECENT_TOOL_TEXT_CHARS);
    if (estimatedDirextalkMessageTokens(result) <= target) return result as unknown as T[];
  }
  throw new Error("Dirextalk context guard could not fit the conversation inside the authorized model window");
}

function providerOutputLimit(payload: unknown): number | undefined {
  if (!payload || typeof payload !== "object") return undefined;
  const value = payload as ContextRecord;
  for (const key of ["max_output_tokens", "max_completion_tokens", "max_tokens"]) {
    if (typeof value[key] === "number") return value[key];
  }
  return undefined;
}

export function validateDirextalkProviderPayload(
  payload: unknown,
  contextWindow: number,
  maxTokens: number,
): void {
  if (!Number.isFinite(contextWindow) || !Number.isFinite(maxTokens) ||
      contextWindow < MIN_CONTEXT_WINDOW || maxTokens <= 0 || maxTokens >= contextWindow) {
    throw new Error("Dirextalk provider guard received invalid authorized model limits");
  }
  const outputLimit = providerOutputLimit(payload);
  if (!Number.isFinite(outputLimit) || outputLimit! <= 0 || outputLimit! > maxTokens) {
    throw new Error("Dirextalk provider payload is missing the authorized output limit");
  }
  const encoded = JSON.stringify(payload);
  if (typeof encoded !== "string" ||
      new TextEncoder().encode(encoded).byteLength > MODEL_RELAY_MAX_REQUEST_BYTES) {
    throw new Error("Dirextalk provider payload exceeds the model relay transport limit");
  }
  const requestTokens = estimatedDirextalkContextTokens(payload) + PROVIDER_PROTOCOL_TOKEN_RESERVE;
  if (requestTokens > contextWindow - outputLimit!) {
    throw new Error("Dirextalk provider payload exceeds the authorized model context window");
  }
}

const submitResult = defineTool({
  name: "dirextalk_submit_result",
  label: "Submit result",
  description:
    "Submit the bounded final result for one authorized Dirextalk Cloud Worker task.",
  promptSnippet:
    "Submit exactly one final Dirextalk result as the last action.",
  promptGuidelines: [
    "Call dirextalk_submit_result exactly once as the final action.",
    "Report only completed, partial, or blocked status.",
    "Do not include credentials, secret references, raw logs, or hidden reasoning.",
    "Risks are Worker observations and are not a central security conclusion.",
  ],
  parameters: Type.Object(
    {
      status: Type.Union([
        Type.Literal("completed"),
        Type.Literal("partial"),
        Type.Literal("blocked"),
      ]),
      summary: Type.String(),
      deliverables: Type.Array(Type.String()),
      tests: Type.Array(Type.String()),
      risks: Type.Array(Type.String()),
    },
    { additionalProperties: false },
  ),
  async execute(_toolCallId, params) {
    return {
      content: [{ type: "text", text: "Final result submitted." }],
      details: params satisfies DirextalkResultDetails,
      terminate: true,
    };
  },
});

export default function registerDirextalkResult(pi: ExtensionAPI) {
  pi.registerTool(submitResult);
  pi.on("context", (event, ctx) => {
    try {
      if (!ctx.model) throw new Error("Dirextalk context guard requires an authorized model");
      const activeTools = new Set(pi.getActiveTools());
      const requestOverheadTokens = estimatedDirextalkContextTokens({
        systemPrompt: ctx.getSystemPrompt(),
        tools: pi.getAllTools()
          .filter((tool) => activeTools.has(tool.name))
          .map(({ name, description, parameters }) => ({ name, description, parameters })),
      });
      const messages = compactDirextalkContext(
        event.messages,
        ctx.model.contextWindow,
        ctx.model.maxTokens,
        requestOverheadTokens,
      );
      if (messages !== event.messages) return { messages };
    } catch {
      ctx.abort();
      return { messages: [] };
    }
  });
  pi.on("before_provider_request", (event, ctx) => {
    try {
      if (!ctx.model) throw new Error("Dirextalk provider guard requires an authorized model");
      validateDirextalkProviderPayload(event.payload, ctx.model.contextWindow, ctx.model.maxTokens);
    } catch {
      ctx.abort();
    }
    return event.payload;
  });
}
