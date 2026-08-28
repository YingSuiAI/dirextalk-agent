import assert from "node:assert/strict";
import fs from "node:fs";
import { StringDecoder } from "node:string_decoder";

const source = fs.readFileSync(new URL("./extension.ts", import.meta.url), "utf8");
const limit = source.match(/function limit\([^\n]+/)[0].replace(/: string/g, "");
const parser = source.match(/function incrementalOutputParser\(\)[\s\S]*?\nasync function run/)[0].replace(/\nasync function run$/, "");
// The parser is intentionally dependency-free JavaScript embedded in the TS
// extension, so this evaluates its exact vendored source without Pi packages.
const makeParser = new Function("Buffer", "StringDecoder", `const MAX_OUTPUT_BYTES = 50 * 1024; ${limit}; ${parser}; return incrementalOutputParser;`)(Buffer, StringDecoder);
const parsed = makeParser();
for (let index = 0; index < 1200; index++) parsed.stdout(Buffer.from(JSON.stringify({ type: "tool_result", content: "x".repeat(64) }) + "\n"));
parsed.stdout(Buffer.from('{"message":{"role":"assistant","content":[{"text":"terminal answer"}]}}\n'));
assert.equal(parsed.finish().answer, "terminal answer");
const huge = makeParser(); huge.stdout(Buffer.from(JSON.stringify({ message: { role: "assistant", content: "z".repeat(70 * 1024) } }) + "\n"));
assert.match(huge.finish().answer, /\[output truncated\]$/);
const utf8 = makeParser(); const final = Buffer.from(JSON.stringify({ message: { role: "assistant", content: "终态" } }) + "\n"); for (const byte of final) utf8.stdout(Buffer.from([byte])); assert.equal(utf8.finish().answer, "终态");
const error = makeParser(); error.stdout(Buffer.from(JSON.stringify({ message: { role: "assistant", content: "earlier success" } }) + "\n")); error.stdout(Buffer.from(JSON.stringify({ stopReason: "error", errorMessage: "terminal provider failure" }) + "\n")); const failed = error.finish(); assert.equal(failed.failed, true); assert.equal(failed.answer, "terminal provider failure");
const aborted = makeParser(); aborted.stdout(Buffer.from(JSON.stringify({ message: { role: "assistant", content: "earlier success" } }) + "\n")); aborted.stdout(Buffer.from(JSON.stringify({ stopReason: "aborted" }) + "\n")); assert.equal(aborted.finish().answer, "subagent stopped: aborted");
const invocation = source.match(/function invocation\([^\n]+/)[0].replace(/: string\[\]/g, "");
const callInvocation = (execPath, script, exists = true) => new Function("fs", "process", `${invocation}; return invocation(["--flag"]);`)( { existsSync: () => exists }, { execPath, argv: [execPath, script] });
assert.deepEqual(callInvocation("/opt/pi", "/$bunfs/root/index.js"), { command: "/opt/pi", args: ["--flag"] });
assert.deepEqual(callInvocation("/usr/bin/node", "/$bunfs/root/index.js"), { command: "pi", args: ["--flag"] });
assert.deepEqual(callInvocation("/usr/bin/node", "/tmp/real-script.js"), { command: "/usr/bin/node", args: ["/tmp/real-script.js", "--flag"] });
console.log("incremental Pi JSON parser fixture passed");
