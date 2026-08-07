import {
  defineTool,
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
}
