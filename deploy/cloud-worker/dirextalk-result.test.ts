import { beforeAll, describe, expect, mock, test } from "bun:test";

mock.module("@earendil-works/pi-coding-agent", () => ({
  defineTool: (definition: unknown) => definition,
  estimateTokens: () => 1,
}));

mock.module("typebox", () => ({
  Type: {
    Array: (value: unknown) => ({ type: "array", items: value }),
    Literal: (value: unknown) => ({ const: value }),
    Object: (properties: unknown) => ({ type: "object", properties }),
    String: () => ({ type: "string" }),
    Union: (values: unknown) => ({ anyOf: values }),
  },
}));

type ExtensionModule = typeof import("./dirextalk-result");
let extension: ExtensionModule;

beforeAll(async () => {
  extension = await import("./dirextalk-result");
});

describe("Dirextalk Pi output continuation", () => {
  test("continues only after a length stop before final submission", () => {
    expect(extension.shouldContinueDirextalkTurn("length", false)).toBe(true);
    expect(extension.shouldContinueDirextalkTurn("length", true)).toBe(false);
    expect(extension.shouldContinueDirextalkTurn("stop", false)).toBe(false);
  });

  test("queues continuation and stops queuing after submit_result", async () => {
    const handlers = new Map<string, (event: any, context?: any) => unknown>();
    const sent: Array<{ content: string; deliverAs?: string }> = [];
    let tool: any;
    const pi = {
      registerTool(value: unknown) {
        tool = value;
      },
      on(name: string, handler: (event: any, context?: any) => unknown) {
        handlers.set(name, handler);
      },
      sendUserMessage(content: string, options?: { deliverAs?: string }) {
        sent.push({ content, deliverAs: options?.deliverAs });
      },
      getActiveTools: () => [],
      getAllTools: () => [],
    };

    extension.default(pi as any);
    handlers.get("turn_end")?.({ message: { stopReason: "length" } });
    expect(sent).toHaveLength(1);
    expect(sent[0].deliverAs).toBe("followUp");

    await tool.execute("call-1", {
      status: "completed",
      summary: "done",
      deliverables: [],
      tests: [],
      risks: [],
    });
    handlers.get("turn_end")?.({ message: { stopReason: "length" } });
    expect(sent).toHaveLength(1);
  });

  test("compacts older length-stopped assistant text against the signed model window", () => {
    const objective = "Create the exact requested deliverables.";
    const latest = "L".repeat(30000);
    const messages = [
      { role: "user", content: objective },
      { role: "assistant", content: "O".repeat(30000) },
      { role: "user", content: "Continue without repeating completed work." },
      { role: "assistant", content: latest },
    ];

    const compacted = extension.compactDirextalkContext(
      messages,
      65536,
      8192,
      2048,
    );

    expect(compacted[0]).toEqual(messages[0]);
    expect((compacted[1] as { content: string }).content.length).toBeLessThan(
      30000,
    );
    expect(compacted[2]).toEqual(messages[2]);
    expect(compacted[3]).toEqual(messages[3]);
  });

  test("bounds the newest assistant text only when the exact request target requires it", () => {
    const objective = "O".repeat(30000);
    const messages = [
      { role: "user", content: objective },
      { role: "assistant", content: "A".repeat(30000) },
    ];

    const compacted = extension.compactDirextalkContext(
      messages,
      65536,
      8192,
      2048,
    );

    expect(compacted[0]).toEqual(messages[0]);
    expect(
      (compacted[1] as { content: string }).content.length,
    ).toBeLessThanOrEqual(8192);
  });
});
