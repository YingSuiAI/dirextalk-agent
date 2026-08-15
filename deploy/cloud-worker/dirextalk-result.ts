import { defineTool, type ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";

interface DirextalkResultDetails {
  status: "completed" | "partial" | "blocked";
  summary: string;
  deliverables: string[];
  tests: string[];
  risks: string[];
}

function createSubmitResult(onSubmitted: () => void) {
  return defineTool({
    name: "dirextalk_submit_result",
    label: "Submit result",
    description:
      "Submit the final result for one authorized Dirextalk Cloud Worker task.",
    promptSnippet:
      "Submit exactly one final Dirextalk result as the last action.",
    promptGuidelines: [
      "Call dirextalk_submit_result exactly once as the final action.",
      "Report only completed, partial, or blocked status.",
      "Do not include credentials, secret references, raw logs, or hidden reasoning.",
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
      onSubmitted();
      return {
        content: [{ type: "text", text: "Final result submitted." }],
        details: params satisfies DirextalkResultDetails,
        terminate: true,
      };
    },
  });
}

export function shouldContinueDirextalkTurn(
  stopReason: unknown,
  finalSubmitted: boolean,
): boolean {
  return stopReason === "length" && !finalSubmitted;
}

export default function registerDirextalkResult(pi: ExtensionAPI) {
  let finalSubmitted = false;
  pi.registerTool(
    createSubmitResult(() => {
      finalSubmitted = true;
    }),
  );
  pi.on("turn_end", (event) => {
    if (!shouldContinueDirextalkTurn(event.message.stopReason, finalSubmitted))
      return;
    pi.sendUserMessage(
      "Continue the same task from the exact point where the previous response reached its per-request output limit. Do not repeat completed work. Inspect the workspace as needed, finish and verify every required deliverable, then call dirextalk_submit_result exactly once.",
      { deliverAs: "followUp" },
    );
  });
}
