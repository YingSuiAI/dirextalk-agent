import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

interface DirextalkResultDetails {
  status: "completed" | "partial" | "blocked";
  summary: string;
  deliverables: string[];
  tests: string[];
  risks: string[];
}

const MIN_CONTEXT_WINDOW = 16384;
const MIN_SAFETY_TOKENS = 4096;
const MAX_SAFETY_TOKENS = 16384;
const RECENT_TOOL_RESULTS = 2;
const OLD_TOOL_TEXT_CHARS = 1024;
const RECENT_TOOL_TEXT_CHARS = 4096;

type ContextRecord = Record<string, unknown>;

export function estimatedDirextalkContextTokens(value: unknown): number {
  try {
    const encoded = JSON.stringify(value) ?? "";
    // One UTF-8 byte per token is deliberately conservative across model
    // tokenizers, including code, identifiers, base64, and CJK text.
    return new TextEncoder().encode(encoded).byteLength;
  } catch {
    return Number.MAX_SAFE_INTEGER;
  }
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

export function compactDirextalkContext<T>(
  messages: T[],
  contextWindow: number,
  maxTokens: number,
): T[] {
  if (!Number.isFinite(contextWindow) || !Number.isFinite(maxTokens) ||
      contextWindow < MIN_CONTEXT_WINDOW || maxTokens <= 0 || maxTokens >= contextWindow) {
    return messages;
  }
  const safety = Math.max(
    MIN_SAFETY_TOKENS,
    Math.min(MAX_SAFETY_TOKENS, Math.floor(contextWindow / 4)),
  );
  const target = contextWindow - maxTokens - safety;
  if (target <= 0 || estimatedDirextalkContextTokens(messages) <= target) return messages;

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
    if (estimatedDirextalkContextTokens(result) <= target) return result as unknown as T[];
  }
  for (let index = protectedStart; index < toolResultIndexes.length; index++) {
    compactAt(toolResultIndexes[index], RECENT_TOOL_TEXT_CHARS);
    if (estimatedDirextalkContextTokens(result) <= target) return result as unknown as T[];
  }
  throw new Error("Dirextalk context guard could not fit the conversation inside the authorized model window");
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
    if (!ctx.model) return;
    try {
      const messages = compactDirextalkContext(
        event.messages,
        ctx.model.contextWindow,
        ctx.model.maxTokens,
      );
      if (messages !== event.messages) return { messages };
    } catch {
      ctx.abort();
      return { messages: [] };
    }
  });
}
