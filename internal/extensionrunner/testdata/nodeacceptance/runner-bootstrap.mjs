import fs from "node:fs";
import { spawnSync, spawn } from "node:child_process";

const uid = 65531;
const agentUID = 65532;
for (const [path, mode, gid] of [
  ["/run/dirextalk", 0o2750, agentUID],
  ["/data/install", 0o700, uid],
  ["/data/install/.prepared", 0o700, uid],
  ["/data/workspace", 0o770, agentUID],
  ["/data/state", 0o700, uid],
]) {
  fs.mkdirSync(path, { recursive: true, mode });
  fs.chownSync(path, uid, gid);
  fs.chmodSync(path, mode);
}
const membership = fs.readFileSync("/proc/self/cgroup", "utf8").trim().split("\n");
if (membership.length !== 1 || !membership[0].startsWith("0::/")) throw new Error("unexpected cgroup membership");
const relative = membership[0].slice(3);
if (!relative.startsWith("/") || relative.includes("..") || relative.includes("\0")) throw new Error("unsafe cgroup membership");
const current = "/sys/fs/cgroup" + relative;
const bootstrap = current + "/bootstrap";
const cgroup = current + "/dirextalk-node-acceptance";
fs.mkdirSync(bootstrap, { recursive: false });
fs.writeFileSync(bootstrap + "/cgroup.procs", "0");
fs.writeFileSync(current + "/cgroup.subtree_control", "+cpu +memory +pids");
fs.mkdirSync(cgroup, { recursive: false });
fs.writeFileSync(cgroup + "/cgroup.subtree_control", "+cpu +memory +pids");
fs.chownSync(cgroup, uid, uid);
fs.chmodSync(cgroup, 0o700);
fs.chownSync(current + "/cgroup.procs", uid, uid);
const mount = spawnSync("/usr/local/libexec/dirextalk-core-shell", ["--bind", cgroup, "/cgroup"], { argv0: "mount", stdio: "inherit" });
if (mount.status !== 0) process.exit(mount.status ?? 2);
const runner = spawn("/usr/local/bin/dirextalk-extension-runner", [
  "serve", "--socket", "/run/dirextalk/runner.sock", "--agent-uid", String(agentUID),
  "--install-root", "/data/install", "--prepared-root", "/data/install/.prepared",
  "--node-runtime-root", "/usr/local/libexec/dirextalk-node-runtime",
  "--workspace-root", "/data/workspace", "--cgroup-root", "/cgroup", "--state-root", "/data/state",
], { uid, gid: uid, stdio: "inherit" });
for (const signal of ["SIGTERM", "SIGINT"]) process.on(signal, () => runner.kill(signal));
runner.on("exit", code => process.exit(code ?? 0));
