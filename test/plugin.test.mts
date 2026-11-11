// The plugin itself (index.ts), driven through a stand-in for opencode's plugin context: the
// three hooks fire in opencode 2.2.7's order (tool.execute.before, shell.create.before,
// permission.evaluate). Run: npm test (test/run.mjs supplies a throwaway $HOME and XDG dirs).
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, afterEach, before, describe, mock, test } from "node:test";
import assert from "node:assert/strict";
import plugin from "../index.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const home = os.homedir();
const configFile = path.join(process.env.XDG_CONFIG_HOME!, "opencode", "automode.json");
const stateDir = path.join(process.env.XDG_STATE_HOME!, "opencode-automode");
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-plugin-")));
const project = path.join(tmp, "project");
// Lists reach lockwrite newline-separated.
const SEP = "\n";

assert.ok(configFile.startsWith(home) && !home.startsWith("/tmp"), "run through `npm test` (test/run.mjs), which supplies a throwaway $HOME");

type Hook = (event: any) => unknown;
interface Host {
  tool: Hook;
  shell: Hook;
  permission: Hook;
  emit(event: unknown): Promise<void>;
  stop(): Promise<void>;
}
const hosts: Host[] = [];

async function start(config?: unknown, options?: unknown, raw?: string): Promise<Host> {
  fs.mkdirSync(path.dirname(configFile), { recursive: true });
  if (raw !== undefined) fs.writeFileSync(configFile, raw);
  else if (config !== undefined) fs.writeFileSync(configFile, JSON.stringify(config));
  else fs.rmSync(configFile, { force: true });
  const hooks: Record<string, Hook> = {};
  const hook = (kind: string) => ({ hook: async (_name: string, fn: Hook) => ((hooks[kind] = fn), { dispose: async () => {} }) });
  const queue: unknown[] = [];
  let wake: (() => void) | undefined;
  const ctx = {
    options,
    location: { directory: project },
    tool: hook("tool"),
    shell: hook("shell"),
    permission: hook("permission"),
    event: {
      subscribe: ({ signal }: { signal: AbortSignal }) =>
        (async function* () {
          signal.addEventListener("abort", () => wake?.());
          while (!signal.aborted) {
            if (queue.length) yield queue.shift();
            else await new Promise<void>((r) => (wake = r));
          }
        })(),
    },
  };
  const dispose = await (plugin as any).setup(ctx);
  const host: Host = {
    tool: hooks.tool,
    shell: hooks.shell,
    permission: hooks.permission,
    async emit(event) {
      queue.push(event);
      wake?.();
      await new Promise((r) => setTimeout(r, 20));
    },
    stop: dispose,
  };
  hosts.push(host);
  return host;
}

let ids = 0;
const baseEnv = () => ({ PATH: process.env.PATH!, HOME: home, LANG: "C.UTF-8", TERM: "xterm-256color", OPENCODE_TERMINAL: "1" });
// One shell tool call, as opencode makes it.
async function call(host: Host, command: string, o: { shell?: string; env?: Record<string, string>; noShell?: boolean; sessionID?: string } = {}) {
  const id = `call-${++ids}`;
  const sessionID = o.sessionID ?? "s1";
  await host.tool({ tool: "shell", sessionID, messageID: "m1", id, input: { command } });
  const shell = { command, cwd: project, timeout: 120000, shell: o.shell ?? "/bin/bash", env: { ...baseEnv(), ...o.env } as Record<string, string | undefined> };
  if (!o.noShell) await host.shell(shell);
  const permission: any = { sessionID, action: "shell", resources: [command], source: { type: "tool", messageID: "m1", id }, effect: "allow" };
  await host.permission(permission);
  return { shell, permission, id };
}
const list = (env: Record<string, string | undefined>, name: string) => (env[name] ?? "").split(SEP).filter(Boolean);
const wrapped = (shell: { shell: string }) => shell.shell === path.join(ROOT, "sandbox", "bin", "bash");

before(() => {
  fs.mkdirSync(project);
  execFileSync("git", ["init", "-q", project]);
});
afterEach(async () => {
  for (const h of hosts.splice(0)) await h.stop();
  mock.timers.reset();
});
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe("K1: one shell tool call", () => {
  test("an allowed command gets a sandboxed shell, and runs in it", async () => {
    const host = await start();
    const { shell, permission } = await call(host, "echo hello > out.txt && cat out.txt");
    assert.equal(permission.effect, "allow");
    assert.ok(wrapped(shell));
    assert.equal(shell.env.AUTOMODE_SHELL, "/bin/bash");
    assert.ok(list(shell.env, "AUTOMODE_RW").includes(project));
    assert.ok(list(shell.env, "AUTOMODE_RO").includes(path.join(project, ".git")));
    const r = spawnSync(shell.shell, ["-c", shell.command], { cwd: project, env: shell.env as NodeJS.ProcessEnv, encoding: "utf8" });
    assert.equal(r.stdout, "hello\n", r.stderr);
  });

  test("a command that asks keeps its shell, and the prompt says why", async () => {
    const host = await start();
    const { shell, permission } = await call(host, "sudo ls");
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /automode: .*root/);
    assert.equal(shell.shell, "/bin/bash");
    assert.equal(shell.env.AUTOMODE_SHELL, undefined);
  });

  test("a denied command is denied", async () => {
    const { permission, shell } = await call(await start(), "rm -rf /");
    assert.equal(permission.effect, "deny");
    assert.ok(!wrapped(shell));
  });

  test("allowed but not wrapped asks: no shell was created through the hook", async () => {
    const { permission } = await call(await start(), "ls", { noShell: true });
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /could not be sandboxed/);
  });

  test("allowed but not wrapped asks: a shell the wrapper does not stand in for", async () => {
    const { permission, shell } = await call(await start(), "ls", { shell: "/usr/bin/fish" });
    assert.equal(shell.shell, "/usr/bin/fish");
    assert.equal(permission.effect, "ask");
  });

  test("the sandbox switched off: an allow runs in the plain shell", async () => {
    const { permission, shell } = await call(await start({ sandbox: false }), "ls");
    assert.equal(permission.effect, "allow");
    assert.equal(shell.shell, "/bin/bash");
  });

  test("identical commands in flight are paired with their own shells in order", async () => {
    const host = await start();
    const command = "ls -la";
    const event = (id: string) => ({ tool: "shell", sessionID: "s1", messageID: "m1", id, input: { command } });
    await host.tool(event("a"));
    await host.tool(event("b"));
    const shells = [1, 2].map(() => ({ command, cwd: project, timeout: 1, shell: "/bin/bash", env: baseEnv() as Record<string, string | undefined> }));
    for (const s of shells) await host.shell(s);
    assert.ok(shells.every(wrapped));
    for (const id of ["a", "b"]) {
      const permission: any = { sessionID: "s1", action: "shell", resources: [command], source: { type: "tool", messageID: "m1", id }, effect: "allow" };
      await host.permission(permission);
      assert.equal(permission.effect, "allow", id);
    }
  });

  test("H7: a call whose shell never came does not take the next identical command's sandbox", async () => {
    mock.timers.enable({ apis: ["Date"], now: Date.now() });
    const host = await start();
    await call(host, "ls -l", { noShell: true }); // orphaned: opencode never created its shell
    mock.timers.tick(60_000);
    const { permission, shell } = await call(host, "ls -l");
    assert.ok(wrapped(shell));
    assert.equal(permission.effect, "allow", permission.message);
  });

  test("model errors ask", async () => {
    const host = await start({ classifier: { endpoint: "http://127.0.0.1:9", timeoutMs: 500 } });
    const { permission } = await call(host, "frobnicate --all");
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /model gave no answer/);
  });

  test("the classifier switched off: what the rules leave open asks", async () => {
    const { permission } = await call(await start({ useClassifier: false }), "frobnicate --all");
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /model, which is off/);
  });

  test("a hook that throws asks instead of allowing", async () => {
    const host = await start();
    const permission: any = { sessionID: "s1", action: "edit", resources: [null], effect: "allow" };
    await host.permission(permission);
    assert.equal(permission.effect, "ask");
  });
});

describe("K1: edit and read only tighten", () => {
  const evaluate = async (action: string, resource: string, effect = "allow") => {
    const permission: any = { sessionID: "s1", action, resources: [resource], effect };
    await (await start()).permission(permission);
    return permission.effect;
  };
  test("an edit inside the project is left alone", async () => assert.equal(await evaluate("edit", "src/a.ts"), "allow"));
  test("an edit never turns opencode's ask into an allow", async () => assert.equal(await evaluate("edit", "src/a.ts", "ask"), "ask"));
  test("an edit outside the project asks", async () => assert.equal(await evaluate("edit", path.join(home, "notes.txt")), "ask"));
  test("J2: an edit of .git/config or a hook asks", async () => {
    assert.equal(await evaluate("edit", ".git/config"), "ask");
    assert.equal(await evaluate("edit", ".git/hooks/pre-commit"), "ask");
  });
  test("J2: an edit of the project's opencode config asks", async () => {
    assert.equal(await evaluate("edit", "opencode.json"), "ask");
    assert.equal(await evaluate("edit", ".opencode/plugin/x.ts"), "ask");
  });
  test("a read of a credential file asks", async () => assert.equal(await evaluate("read", path.join(home, ".ssh", "id_ed25519")), "ask"));
  test("an ordinary read is left alone", async () => assert.equal(await evaluate("read", "README.md"), "allow"));
});

describe("H5: scheduled checks", () => {
  const unattended = (run: string) => ({ sessionID: "s1", action: "shell", resources: [run], metadata: { schedule: "nightly", mode: "if", unattended: true, run }, effect: "allow" }) as any;
  test("a schedule's approval is judged whoever created the schedule, and at most asks", async () => {
    const host = await start();
    const harmless = unattended("ls");
    await host.permission(harmless);
    assert.equal(harmless.effect, "ask");
    assert.match(harmless.message, /scheduled check runs unsandboxed/);
    const risky = unattended("sudo systemctl restart nginx");
    await host.permission(risky);
    assert.equal(risky.effect, "ask");
    const wipe = unattended("rm -rf /");
    await host.permission(wipe);
    assert.equal(wipe.effect, "deny");
  });
  test("a later run of a check (no tool call, no metadata) cannot be sandboxed, so it never becomes an allow by rule", async () => {
    const host = await start();
    const tick: any = { sessionID: "s1", action: "shell", resources: ["ls"], effect: "ask" };
    await host.permission(tick);
    assert.equal(tick.effect, "ask");
  });
});

describe("K1: the Always-allow mirror", () => {
  test("plain patterns on the allowlist are saved per project, others are ignored", async () => {
    const host = await start();
    assert.equal((await call(host, "wc -l README")).permission.effect, "allow");
    const alwaysFile = path.join(stateDir, "always.json");
    await host.emit({ type: "permission.asked", data: { id: "per_1", action: "shell", save: ["tsc *", "curl *", "re:.*"] } });
    await host.emit({ type: "permission.replied", data: { requestID: "per_1", reply: "always" } });
    const saved = JSON.parse(fs.readFileSync(alwaysFile, "utf8"));
    assert.deepEqual(saved[project], ["tsc *"]);
    assert.equal(fs.statSync(alwaysFile).mode & 0o777, 0o600);
  });
  test("a reply of once saves nothing", async () => {
    const host = await start();
    await host.emit({ type: "permission.asked", data: { id: "per_2", action: "shell", save: ["jest *"] } });
    await host.emit({ type: "permission.replied", data: { requestID: "per_2", reply: "once" } });
    assert.ok(!JSON.stringify(JSON.parse(fs.readFileSync(path.join(stateDir, "always.json"), "utf8"))).includes("jest"));
  });
});

describe("I3/I4: what a sandboxed command can see of the session", () => {
  test("I3: credential-looking variables are removed, and lockwrite is told what may stay", async () => {
    const secrets = { DATABASE_URL: "postgres://u:p@h/db", PGPASSWORD: "hunter2", MY_APIKEY: "abc", SENTRY_DSN: "https://k@sentry.invalid/1", SLACK_WEBHOOK_URL: "https://hooks.invalid/x", DB_PWD: "x", CI_JOB_JWT: "eyJ", STRIPE_SK: "sk_live_x", GITHUB_TOKEN: "ghp_x" };
    const { shell } = await call(await start({ sandboxKeepEnv: ["MY_APIKEY"] }), "ls", { env: { ...secrets, NODE_ENV: "test" } });
    assert.ok(wrapped(shell));
    for (const name of Object.keys(secrets)) assert.equal(shell.env[name], name === "MY_APIKEY" ? "abc" : undefined, name);
    assert.equal(shell.env.NODE_ENV, "test");
    const keep = (shell.env.AUTOMODE_ENV_KEEP ?? "").split("\n");
    assert.ok(keep.includes("PATH") && keep.includes("MY_APIKEY") && keep.includes("OPENCODE_SESSION_ID") && !keep.includes("PGPASSWORD"));
    // Whatever environment the wrapper is started with, only the listed variables get through.
    const r = spawnSync(shell.shell, ["-c", "echo [$PGPASSWORD][$MY_APIKEY]"], { cwd: project, env: { ...shell.env, PGPASSWORD: "hunter2" } as NodeJS.ProcessEnv, encoding: "utf8" });
    assert.equal(r.stdout, "[][abc]\n", r.stderr);
  });
  test("I4: the decision log is private, and hidden from sandboxed commands", async () => {
    const { shell } = await call(await start(), "ls");
    const log = path.join(stateDir, "decisions.jsonl");
    assert.match(fs.readFileSync(log, "utf8"), /"command":"ls"/);
    assert.equal(fs.statSync(log).mode & 0o777, 0o600);
    assert.equal(fs.statSync(stateDir).mode & 0o777, 0o700);
    assert.ok(list(shell.env, "AUTOMODE_HIDE").includes(stateDir));
    const r = spawnSync(shell.shell, ["-c", `ls -A ${stateDir} | wc -l`], { cwd: project, env: shell.env as NodeJS.ProcessEnv, encoding: "utf8" });
    assert.equal(r.stdout.trim(), "0", r.stderr);
  });
  test("log: false writes no decisions", async () => {
    const log = path.join(stateDir, "decisions.jsonl");
    fs.rmSync(log, { force: true });
    await call(await start({ log: false }), "ls");
    assert.ok(!fs.existsSync(log));
  });
});

describe("D2/H3: settings", () => {
  const cache = path.join(home, ".cargo", "registry");
  before(() => fs.mkdirSync(cache, { recursive: true }));
  test("D2: no cache directory is writable unless sandboxWritable lists it", async () => {
    const plain = await call(await start(), "ls");
    assert.ok(!list(plain.shell.env, "AUTOMODE_RW").some((p) => p.startsWith(home)), plain.shell.env.AUTOMODE_RW);
    const opted = await call(await start({ sandboxWritable: ["~/.cargo/registry"] }), "ls");
    assert.ok(list(opted.shell.env, "AUTOMODE_RW").includes(cache));
  });
  test("a valid file is used: your own ask rule, allowedPaths", async () => {
    const host = await start({ rules: { ask: ["wc *"] }, allowedPaths: ["~/scratch"] });
    const asked = await call(host, "wc -l README");
    assert.equal(asked.permission.effect, "ask");
    assert.match(asked.permission.message, /your ask rule/);
    assert.equal((await call(host, `echo x > ${home}/scratch/f`)).permission.effect, "allow");
  });
  test("enabled: false changes nothing", async () => {
    const { permission, shell } = await call(await start({ enabled: false }), "sudo ls");
    assert.equal(permission.effect, "allow");
    assert.equal(shell.shell, "/bin/bash");
  });
  const invalid: [string, unknown, string?][] = [
    ["a file that is not JSON", undefined, '{ "enabled": false, '],
    ["sshHosts as a string", { sshHosts: "lab" }],
    ["a number as text", { classifier: { askAbove: "0.2" } }],
    ["askAbove out of range", { classifier: { askAbove: 7 } }],
    ["a rule list that is not a list", { rules: { ask: "sudo *" } }],
    ["a regex that does not compile", { rules: { deny: ["re:("] } }],
    ["an unknown setting (a typo)", { alowedPaths: [] }],
    ["a boolean as text", { sandbox: "false" }],
    ["not an object", ["enabled"]],
  ];
  for (const [name, config, raw] of invalid) {
    test(`H3: ${name} turns auto-allow off and says so`, async () => {
      const { permission, shell } = await call(await start(config, undefined, raw), "ls");
      assert.equal(permission.effect, "ask");
      assert.match(permission.message, /settings are invalid/);
      assert.ok(!wrapped(shell));
    });
  }
  test("H3: invalid plugin options count too", async () => {
    const { permission } = await call(await start(undefined, { sshHosts: "lab" }), "ls");
    assert.equal(permission.effect, "ask");
  });
  test("H3: sshHosts given as a string does not become the hosts l, a and b", async () => {
    const { permission } = await call(await start({ sshHosts: "lab" }), "ssh l uptime");
    assert.equal(permission.effect, "ask");
  });
  test("H6: an empty XDG variable counts as unset", () => {
    const cwd = fs.mkdtempSync(path.join(tmp, "cwd-"));
    const code = `
      const plugin = (await import(${JSON.stringify(path.join(ROOT, "index.ts"))})).default;
      const hooks = {};
      const hook = (k) => ({ hook: async (_n, fn) => ((hooks[k] = fn), { dispose: async () => {} }) });
      const dispose = await plugin.setup({ options: undefined, location: { directory: ${JSON.stringify(project)} }, tool: hook("tool"), shell: hook("shell"), permission: hook("permission"),
        event: { subscribe: () => (async function* () {})() } });
      await hooks.tool({ tool: "shell", sessionID: "s", messageID: "m", id: "1", input: { command: "ls" } });
      await dispose();`;
    const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], { cwd, env: { ...process.env, XDG_STATE_HOME: "", XDG_CONFIG_HOME: "" }, encoding: "utf8" });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(fs.readdirSync(cwd), [], "state was written relative to the working directory");
    assert.ok(fs.existsSync(path.join(home, ".local", "state", "opencode-automode", "decisions.jsonl")));
  });
});

describe("C10: a pause is reported with what was found", () => {
  test("the prompt names the planted path and how to resume, and resuming works", async () => {
    const host = await start();
    assert.equal((await call(host, "ls", { sessionID: "pause" })).permission.effect, "allow");
    const planted = path.join(project, "third_party", "x");
    execFileSync("git", ["init", "-q", planted]);
    try {
      const paused = await call(host, "ls", { sessionID: "pause" });
      assert.equal(paused.permission.effect, "ask");
      assert.ok(paused.permission.message.includes(path.join(planted, ".git")), paused.permission.message);
      assert.match(paused.permission.message, /touch .*opencode-automode\/resume/);
      const resume = path.join(stateDir, "resume");
      fs.writeFileSync(resume, "");
      fs.utimesSync(resume, new Date(Date.now() + 2000), new Date(Date.now() + 2000));
      assert.equal((await call(host, "ls", { sessionID: "pause" })).permission.effect, "allow");
    } finally {
      fs.rmSync(path.join(project, "third_party"), { recursive: true, force: true });
    }
  });
});
