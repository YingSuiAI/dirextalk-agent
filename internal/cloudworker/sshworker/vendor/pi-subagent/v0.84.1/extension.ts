/*
 * Derived from earendil-works/pi v0.84.1 subagent example (MIT).
 * Server policy: only PI_CODING_AGENT_DIR/agents is discovered; no project
 * agent scopes, confirmations, prompts, or inherited extensions are allowed.
 */
import { spawn } from "node:child_process";
import * as fs from "node:fs";
import * as path from "node:path";
import { Type } from "typebox";
import { getAgentDir, parseFrontmatter, type ExtensionAPI } from "@earendil-works/pi-coding-agent";

const MAX_PARALLEL_TASKS = 8;
const MAX_CONCURRENCY = 4;
const CHILD_FLAGS = ["--mode", "json", "-p", "--no-session", "--no-extensions", "--no-skills", "--no-prompt-templates", "--no-themes", "--no-context-files", "--no-approve"];
type Agent = { name: string; description: string; tools: string[]; prompt: string };

function serverAgents(): Agent[] {
	const dir = path.join(getAgentDir(), "agents");
	let entries: fs.Dirent[]; try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return []; }
	return entries.filter((entry) => entry.isFile() && entry.name.endsWith(".md")).flatMap((entry) => {
		try { const parsed = parseFrontmatter<Record<string, string>>(fs.readFileSync(path.join(dir, entry.name), "utf8")); const name = parsed.frontmatter.name?.trim(); const description = parsed.frontmatter.description?.trim(); if (!name || !description) return []; return [{ name, description, tools: (parsed.frontmatter.tools ?? "").split(",").map((value) => value.trim()).filter(Boolean), prompt: parsed.body }]; } catch { return []; }
	});
}
function invocation(args: string[]) { const script = process.argv[1]; if (script && fs.existsSync(script)) return { command: process.execPath, args: [script, ...args] }; return { command: "pi", args }; }
async function run(agent: Agent, task: string, cwd: string, signal?: AbortSignal): Promise<string> {
	const args = [...CHILD_FLAGS]; if (agent.tools.length) args.push("--tools", agent.tools.join(",")); if (agent.prompt.trim()) args.push("--append-system-prompt", agent.prompt); args.push(`Task: ${task}`);
	return new Promise((resolve) => { const call = invocation(args); const child = spawn(call.command, call.args, { cwd, shell: false, stdio: ["ignore", "pipe", "pipe"] }); let output = ""; child.stdout.on("data", (chunk) => { output += chunk.toString(); }); child.stderr.on("data", (chunk) => { output += chunk.toString(); }); child.on("close", (code) => resolve(code === 0 ? output : `subagent failed: ${output}`)); child.on("error", () => resolve("subagent failed")); if (signal) signal.addEventListener("abort", () => child.kill("SIGTERM"), { once: true }); });
}
async function bounded<T>(items: T[], fn: (item: T) => Promise<string>): Promise<string[]> { const results = new Array<string>(items.length); let next = 0; await Promise.all(new Array(Math.min(MAX_CONCURRENCY, items.length)).fill(null).map(async () => { for (;;) { const index = next++; if (index >= items.length) return; results[index] = await fn(items[index]); } })); return results; }
const Item = Type.Object({ agent: Type.String(), task: Type.String() });
export default function (pi: ExtensionAPI) { pi.registerTool({ name: "subagent", label: "Subagent", description: "Run server-owned subagents for independent scopes only; max 8 tasks and 4 concurrent. Project agents are disabled.", parameters: Type.Object({ agent: Type.Optional(Type.String()), task: Type.Optional(Type.String()), tasks: Type.Optional(Type.Array(Item, { maxItems: MAX_PARALLEL_TASKS })) }), async execute(_id, params, signal, _update, ctx) { const agents = serverAgents(); const jobs = params.tasks ?? (params.agent && params.task ? [{ agent: params.agent, task: params.task }] : []); if (!jobs.length || jobs.length > MAX_PARALLEL_TASKS) return { content: [{ type: "text", text: "Provide one task or at most 8 parallel tasks." }], isError: true }; const results = await bounded(jobs, async (job) => { const agent = agents.find((item) => item.name === job.agent); return agent ? run(agent, job.task, ctx.cwd, signal) : `unknown server agent: ${job.agent}`; }); return { content: [{ type: "text", text: results.join("\n\n---\n\n") }], details: { maxConcurrency: MAX_CONCURRENCY, maxTasks: MAX_PARALLEL_TASKS, serverOwnedAgents: true } }; } }); }
