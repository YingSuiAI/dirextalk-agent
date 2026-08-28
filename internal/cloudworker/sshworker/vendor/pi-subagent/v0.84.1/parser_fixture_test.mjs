import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("./extension.ts", import.meta.url), "utf8");
const limit = source.match(/function limit\([^\n]+/)[0].replace(/: string/g, "");
const parser = source.match(/function incrementalOutputParser\(\)[\s\S]*?\nasync function run/)[0].replace(/\nasync function run$/, "");
// The parser is intentionally dependency-free JavaScript embedded in the TS
// extension, so this evaluates its exact vendored source without Pi packages.
const makeParser = new Function("Buffer", `const MAX_OUTPUT_BYTES = 50 * 1024; ${limit}; ${parser}; return incrementalOutputParser;`)(Buffer);
const parsed = makeParser();
for (let index = 0; index < 1200; index++) parsed.stdout(Buffer.from(JSON.stringify({ type: "tool_result", content: "x".repeat(64) }) + "\n"));
parsed.stdout(Buffer.from('{"message":{"role":"assistant","content":[{"text":"terminal answer"}]}}\n'));
assert.equal(parsed.finish().answer, "terminal answer");
const huge = makeParser(); huge.stdout(Buffer.from(JSON.stringify({ message: { role: "assistant", content: "z".repeat(70 * 1024) } }) + "\n"));
assert.match(huge.finish().answer, /\[output truncated\]$/);
console.log("incremental Pi JSON parser fixture passed");
