import { beforeAll, describe, expect, mock, test } from "bun:test";

mock.module("@earendil-works/pi-coding-agent", () => ({
  defineTool: (definition: unknown) => definition,
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
    const handlers = new Map<string, (event: any) => unknown>();
    const sent: Array<{ content: string; deliverAs?: string }> = [];
    let tool: any;
    const pi = {
      registerTool(value: unknown) {
        tool = value;
      },
      on(name: string, handler: (event: any) => unknown) {
        handlers.set(name, handler);
      },
      sendUserMessage(content: string, options?: { deliverAs?: string }) {
        sent.push({ content, deliverAs: options?.deliverAs });
      },
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
});
