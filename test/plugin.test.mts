// The plugin itself (index.ts), driven through a stand-in for opencode's plugin context: the
// three hooks fire in opencode 2.2.7's order (tool.execute.before, shell.create.before,
// permission.evaluate). Run: npm test (test/run.mjs supplies a throwaway $HOME and XDG dirs).
import { execFileSync, spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, afterEach, before, describe, mock, test } from "node:test";
import assert from "node:assert/strict";
import plugin from "../index.ts";
import { SessionState, takeMoment } from "../decide.ts";
// The session's moment is one per process, taken when decide.ts is loaded (round 4, B7-1). These
// tests make their files after that, so each SessionState here takes a moment of its own.
SessionState.moment = takeMoment;
import { walkCount } from "../sandbox.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const home = os.homedir();
const configFile = path.join(process.env.XDG_CONFIG_HOME!, "opencode", "automode.json");
const stateDir = path.join(process.env.XDG_STATE_HOME!, "opencode-automode");
// A resume as the user makes it: the resume file's time is set just ahead of every pause made so
// far (a file system's clock can lag Date.now() by a tick), and the test waits until the clock has
// passed it, so that a pause made after the resume is never read as resumed already. (It was set
// seconds ahead before; on a fast machine a later pause fell within them.)
function touchResume(file: string): void {
  const at = Date.now() + 20;
  fs.utimesSync(file, new Date(at), new Date(at));
  while (Date.now() <= at + 1) {
    // wait out the clock
  }
}
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-plugin-")));
const project = path.join(tmp, "project");
// Lists reach lockwrite newline-separated.
const SEP = "\n";

assert.ok(configFile.startsWith(home) && !home.startsWith("/tmp"), "run through `npm test` (test/run.mjs), which supplies a throwaway $HOME");

type Hook = (event: any) => unknown;
interface Host {
  tool: Hook;
  after: Hook;
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
  const hook = (kind: string) => ({ hook: async (name: string, fn: Hook) => ((hooks[`${kind}.${name}`] = fn), { dispose: async () => {} }) });
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
    tool: hooks["tool.execute.before"],
    after: hooks["tool.execute.after"],
    shell: hooks["shell.create.before"],
    permission: hooks["permission.evaluate"],
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
// The shell's environment as opencode builds it: the session's, which is the plugin's own
// process's unless the session has another. So it carries the variables this process's git reads
// its configuration by (the runner's GIT_CONFIG_GLOBAL and GIT_CONFIG_NOSYSTEM): a shell without
// them would read other configuration than the checks did, and its git calls ask (eighth pass).
const GIT_OWN = Object.fromEntries(Object.entries(process.env).filter(([name]) => /^GIT_(CONFIG_GLOBAL|CONFIG_SYSTEM|CONFIG_NOSYSTEM|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|NO_REPLACE_OBJECTS)$/.test(name))) as Record<string, string>;
const baseEnv = () => ({ PATH: process.env.PATH!, HOME: home, LANG: "C.UTF-8", TERM: "xterm-256color", OPENCODE_TERMINAL: "1", ...GIT_OWN });
// One shell tool call, as opencode makes it.
async function call(host: Host, command: string, o: { shell?: string; env?: Record<string, string | undefined>; noShell?: boolean; sessionID?: string } = {}) {
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
  // B8-5: each test is a world of its own: no session of an earlier test was ever seen (the
  // plugin keeps, per session id, the moment the session was first seen at).
  fs.rmSync(path.join(stateDir, "moments"), { recursive: true, force: true });
  // Nor a resume file an earlier test put ahead of the clock (resume() dates it seconds ahead,
  // and on a fast machine the next test's pause falls within them and reads as resumed).
  fs.rmSync(path.join(stateDir, "resume"), { force: true });
});
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe("K1: one shell tool call", () => {
  test("r4 N1: disposing of the plugin closes the snapshots of its sessions", async () => {
    const host = await start({ useClassifier: false });
    const original = fs.openSync;
    const held: number[] = [];
    fs.openSync = ((p: any, flags: any, ...rest: any[]) => {
      const fd = (original as any)(p, flags, ...rest);
      if (typeof flags === "number" && flags & 0x200000) held.push(fd);
      return fd;
    }) as any;
    try {
      await call(host, "ls");
      assert.ok(held.length);
      await host.stop();
      for (const fd of held) assert.throws(() => fs.fstatSync(fd), /EBADF/);
    } finally {
      fs.openSync = original;
    }
  });
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
  for (const hidden of [".aws", ".ssh", ".gnupg"]) test(`r4 8: edit protects a bare repository two levels below ${hidden}`, async () => {
    const base = path.join(project, hidden);
    const bare = path.join(base, "fixtures", "fixture.git");
    execFileSync("git", ["init", "-q", "--bare", bare]);
    try {
      const host = await start({ useClassifier: false });
      const permission: any = { sessionID: "s1", action: "edit", resources: [path.join(bare, "hooks", "pre-receive")], effect: "allow" };
      await host.permission(permission);
      assert.equal(permission.effect, "ask");
      // For the repository's sake, not for the credential directory's.
      assert.match(permission.message, /edit changes .*fixture\.git\/hooks, which git or opencode runs or loads/);
    } finally { fs.rmSync(base, { recursive: true, force: true }); }
  });
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
  test("r4 21 (tenth pass): a hook linked to a script of the project: a call is allowed and cannot rewrite the script, and an edit of the script asks", async () => {
    const script = path.join(project, "scripts", "pre-commit");
    const hook = path.join(project, ".git", "hooks", "pre-commit");
    fs.mkdirSync(path.dirname(script), { recursive: true });
    fs.writeFileSync(script, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    fs.symlinkSync("../../scripts/pre-commit", hook);
    try {
      const { shell, permission } = await call(await start(), "echo planted >> scripts/pre-commit");
      assert.equal(permission.effect, "allow", permission.message);
      assert.ok(wrapped(shell));
      assert.ok(list(shell.env, "AUTOMODE_RO").includes(script));
      const r = spawnSync(shell.shell, ["-c", shell.command], { cwd: project, env: shell.env as NodeJS.ProcessEnv, encoding: "utf8" });
      assert.notEqual(r.status, 0);
      assert.equal(fs.readFileSync(script, "utf8"), "#!/bin/sh\nexit 0\n");
      const permitted: any = { sessionID: "s1", action: "edit", resources: ["scripts/pre-commit"], effect: "allow" };
      await (await start()).permission(permitted);
      assert.equal(permitted.effect, "ask");
      assert.match(permitted.message, /edit changes .*scripts\/pre-commit, which git or opencode runs or loads/);
      assert.equal(await evaluate("edit", "src/a.ts"), "allow");
    } finally {
      fs.rmSync(hook);
      fs.rmSync(path.join(project, "scripts"), { recursive: true, force: true });
    }
  });
  test("r4 21 (eleventh pass): a checkout that would rewrite a linked hook's script asks, naming it; one that leaves it as it is, and a status, are allowed", async () => {
    const script = path.join(project, "scripts", "pre-commit");
    const hook = path.join(project, ".git", "hooks", "pre-commit");
    const git = (...args: string[]) => execFileSync("git", ["-C", project, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    fs.mkdirSync(path.dirname(script), { recursive: true });
    fs.writeFileSync(script, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    try {
      git("add", "scripts/pre-commit");
      git("commit", "-qm", "one");
      git("branch", "same");
      git("checkout", "-q", "-b", "other");
      fs.writeFileSync(script, "#!/bin/sh\necho other >/dev/null\nexit 0\n");
      git("commit", "-qam", "other");
      git("checkout", "-q", "-");
      fs.symlinkSync("../../scripts/pre-commit", hook);
      const host = await start();
      const other = await call(host, "git checkout other");
      assert.equal(other.permission.effect, "ask");
      assert.match(other.permission.message, /git checkout would rewrite .*scripts\/pre-commit, which the sandbox keeps read-only/);
      for (const command of ["git switch same", "git status"]) assert.equal((await call(host, command)).permission.effect, "allow", command);
    } finally {
      fs.rmSync(hook, { force: true });
      fs.rmSync(path.join(project, "scripts"), { recursive: true, force: true });
      // The project as the other tests have it: a repository with no commit.
      fs.rmSync(path.join(project, ".git"), { recursive: true, force: true });
      execFileSync("git", ["init", "-q", project]);
    }
  });
  test("r4 21 (twelfth pass): a merge after a fetch in the same call asks, saying why; the merge alone is allowed; a pull that asks says how to have it told", async () => {
    const agents = path.join(project, "AGENTS.md");
    const origin = `${project}-origin.git`;
    const git = (...args: string[]) => execFileSync("git", ["-C", project, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    fs.writeFileSync(agents, "# one\n");
    try {
      git("add", "AGENTS.md");
      git("commit", "-qm", "one");
      execFileSync("git", ["clone", "-q", "--bare", project, origin]);
      git("remote", "add", "origin", origin);
      git("fetch", "-q", "origin");
      git("branch", "-q", `--set-upstream-to=origin/${git("branch", "--show-current").trim()}`);
      // (Each in a session of its own: after an ask, the next git command is the model's.)
      const chained = await call(await start(), "git fetch && git merge --ff-only @{upstream}", { sessionID: "r4-12-chained" });
      assert.equal(chained.permission.effect, "ask");
      assert.match(chained.permission.message, /git merge may rewrite .*AGENTS\.md, which the sandbox keeps read-only.*git fetch in the same command/);
      const alone = await call(await start(), "git merge --ff-only @{upstream}", { sessionID: "r4-12-alone" });
      assert.equal(alone.permission.effect, "allow", alone.permission.message);
      const pulled = await call(await start(), "git pull", { sessionID: "r4-12-pulled" });
      assert.equal(pulled.permission.effect, "ask");
      assert.match(pulled.permission.message, /run `git fetch` first, then `git merge --ff-only @\{upstream\}` or `git rebase @\{upstream\}`, which can be told/);
    } finally {
      fs.rmSync(agents, { force: true });
      fs.rmSync(origin, { recursive: true, force: true });
      // The project as the other tests have it: a repository with no commit.
      fs.rmSync(path.join(project, ".git"), { recursive: true, force: true });
      execFileSync("git", ["init", "-q", project]);
    }
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
    const r = spawnSync(shell.shell, ["-c", "echo [$PGPASSWORD][$MY_APIKEY]"], { cwd: project, env: { ...shell.env, AUTOMODE_COMMAND: "echo [$PGPASSWORD][$MY_APIKEY]", PGPASSWORD: "hunter2" } as NodeJS.ProcessEnv, encoding: "utf8" });
    assert.equal(r.stdout, "[][abc]\n", r.stderr);
  });
  test("I4: the decision log is private, and hidden from sandboxed commands", async () => {
    const { shell } = await call(await start(), "ls");
    const log = path.join(stateDir, "decisions.jsonl");
    assert.match(fs.readFileSync(log, "utf8"), /"command":"ls"/);
    assert.equal(fs.statSync(log).mode & 0o777, 0o600);
    assert.equal(fs.statSync(stateDir).mode & 0o777, 0o700);
    assert.ok(list(shell.env, "AUTOMODE_HIDE").includes(stateDir));
    const r = spawnSync(shell.shell, ["-c", `ls -A ${stateDir} | wc -l`], { cwd: project, env: { ...shell.env, AUTOMODE_COMMAND: `ls -A ${stateDir} | wc -l` } as NodeJS.ProcessEnv, encoding: "utf8" });
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
      const hook = () => ({ hook: async (n, fn) => ((hooks[n] = fn), { dispose: async () => {} }) });
      const dispose = await plugin.setup({ options: undefined, location: { directory: ${JSON.stringify(project)} }, tool: hook("tool"), shell: hook("shell"), permission: hook("permission"),
        event: { subscribe: () => (async function* () {})() } });
      await hooks["execute.before"]({ tool: "shell", sessionID: "s", messageID: "m", id: "1", input: { command: "ls" } });
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
      touchResume(resume);
      assert.equal((await call(host, "ls", { sessionID: "pause" })).permission.effect, "allow");
    } finally {
      fs.rmSync(path.join(project, "third_party"), { recursive: true, force: true });
    }
  });
});

// ---- round 2 review findings ----

describe("r2 13: a new repository is expected only where an approved command put it", () => {
  const asked = async (host: Host, command: string, sessionID: string) => {
    const made = await call(host, command, { sessionID });
    assert.equal(made.permission.effect, "ask", command);
    return made;
  };
  const reply = async (host: Host, id: string, answer: string) => {
    await host.emit({ type: "permission.asked", data: { id: `per_${id}`, sessionID: "x", action: "shell", resources: [], source: { type: "tool", messageID: "m1", id } } });
    await host.emit({ type: "permission.replied", data: { requestID: `per_${id}`, reply: answer } });
  };
  const fresh = (name: string) => {
    const dir = path.join(project, name);
    fs.rmSync(dir, { recursive: true, force: true });
    return dir;
  };
  test("approved: the repository it names may appear, and nothing is paused", async () => {
    const host = await start();
    const first = await call(host, "ls", { sessionID: "e1" });
    assert.equal(first.permission.effect, "allow");
    // Over before the approval (r3 36: a call that may still run makes the approval expect nothing).
    await host.after({ tool: "shell", sessionID: "e1", messageID: "m1", id: first.id, status: "completed" });
    const dir = fresh("approved-repo");
    const { id } = await asked(host, "git init approved-repo", "e1");
    await reply(host, id, "once");
    execFileSync("git", ["init", "-q", dir]);
    await host.after({ tool: "shell", sessionID: "e1", messageID: "m1", id, status: "completed" });
    try {
      assert.equal((await call(host, "ls", { sessionID: "e1" })).permission.effect, "allow");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  // Round 4, finding 10: the command ends in a newline, as a model often writes it.
  test("r4 10: approved with a trailing newline: the repository it names may appear, and nothing is paused", async () => {
    const host = await start();
    const first = await call(host, "ls", { sessionID: "e1n" });
    assert.equal(first.permission.effect, "allow");
    await host.after({ tool: "shell", sessionID: "e1n", messageID: "m1", id: first.id, status: "completed" });
    const dir = fresh("approved-lines");
    const { id } = await asked(host, "git init approved-lines 2>&1\n", "e1n");
    await reply(host, id, "once");
    execFileSync("git", ["init", "-q", dir]);
    await host.after({ tool: "shell", sessionID: "e1n", messageID: "m1", id, status: "completed" });
    try {
      const next = await call(host, "ls", { sessionID: "e1n" });
      assert.equal(next.permission.effect, "allow", next.permission.message);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  test("asked but not approved: what appears pauses the session", async () => {
    const host = await start();
    assert.equal((await call(host, "ls", { sessionID: "e2" })).permission.effect, "allow");
    const dir = fresh("unapproved-repo");
    const { id } = await asked(host, "git init unapproved-repo", "e2");
    await reply(host, id, "reject");
    execFileSync("git", ["init", "-q", dir]);
    try {
      const next = await call(host, "ls", { sessionID: "e2" });
      assert.equal(next.permission.effect, "ask");
      assert.match(next.permission.message, /paused.*unapproved-repo/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  test("asked and still unanswered: a second call in the same message cannot use it", async () => {
    const host = await start();
    assert.equal((await call(host, "ls", { sessionID: "e3" })).permission.effect, "allow");
    const dir = fresh("planted-meanwhile");
    await asked(host, "git init /tmp/automode-elsewhere", "e3");
    execFileSync("git", ["init", "-q", dir]);
    try {
      assert.match((await call(host, "ls", { sessionID: "e3" })).permission.message, /paused/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  test("approved, but the repository appears somewhere else", async () => {
    const host = await start();
    assert.equal((await call(host, "ls", { sessionID: "e4" })).permission.effect, "allow");
    const dir = fresh("not-the-named-one");
    const { id } = await asked(host, "git init the-named-one", "e4");
    await reply(host, id, "always");
    execFileSync("git", ["init", "-q", dir]);
    try {
      assert.match((await call(host, "ls", { sessionID: "e4" })).permission.message, /paused.*not-the-named-one/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  test("a push to a branch called init-x explains nothing", async () => {
    const host = await start();
    assert.equal((await call(host, "ls", { sessionID: "e5" })).permission.effect, "allow");
    const dir = fresh("after-push");
    const { id } = await asked(host, "git push origin init-x", "e5");
    await reply(host, id, "once");
    execFileSync("git", ["init", "-q", dir]);
    try {
      assert.match((await call(host, "ls", { sessionID: "e5" })).permission.message, /paused/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("r2 26: a shell is sandboxed only when it cannot belong to a call that asks", () => {
  test("after a call whose shell never came, the next identical one runs sandboxed with its own plan, and is not asked about", async () => {
    const host = await start();
    await call(host, "ls -1", { noShell: true }); // orphaned
    const secret = path.join(project, ".env");
    fs.writeFileSync(secret, "TOKEN=x\n");
    try {
      const { permission, shell } = await call(host, "ls -1");
      assert.equal(permission.effect, "allow", permission.message);
      assert.ok(wrapped(shell));
      assert.ok(list(shell.env, "AUTOMODE_HIDE").includes(secret), "the plan is the one made for this call");
    } finally {
      fs.rmSync(secret);
    }
  });
  test("a call that is over leaves the queue", async () => {
    const host = await start();
    const first = await call(host, "ls -2", { noShell: true });
    await host.after({ tool: "shell", sessionID: "s1", messageID: "m1", id: first.id, status: "error" });
    const { permission, shell } = await call(host, "ls -2");
    assert.equal(permission.effect, "allow");
    assert.ok(wrapped(shell));
  });
  test("identical commands with different verdicts: no shell is sandboxed, and the allowed one asks", async () => {
    const host = await start();
    const command = "ls -3";
    assert.equal((await call(host, "ls", { sessionID: "mixed" })).permission.effect, "allow");
    const event = (id: string) => ({ tool: "shell", sessionID: "mixed", messageID: "m1", id, input: { command } });
    await host.tool(event("a")); // allowed
    const planted = path.join(project, "mixed-repo");
    execFileSync("git", ["init", "-q", planted]);
    try {
      await host.tool(event("b")); // asks: the session is paused now
      const shells = [1, 2].map(() => ({ command, cwd: project, timeout: 1, shell: "/bin/bash", env: baseEnv() as Record<string, string | undefined> }));
      for (const s of shells) await host.shell(s);
      assert.ok(!shells.some(wrapped), "a shell that may belong to the asked call was sandboxed");
      for (const id of ["a", "b"]) {
        const permission: any = { sessionID: "mixed", action: "shell", resources: [command], source: { type: "tool", messageID: "m1", id }, effect: "allow" };
        await host.permission(permission);
        assert.equal(permission.effect, "ask", id);
      }
    } finally {
      fs.rmSync(planted, { recursive: true, force: true });
    }
  });
});

describe("r2 32: schedules are never auto-allowed", () => {
  test("a later run of a check asks with the sandbox switched off too", async () => {
    const host = await start({ sandbox: false });
    const tick: any = { sessionID: "s1", action: "shell", resources: ["ls"], effect: "allow" };
    await host.permission(tick);
    assert.equal(tick.effect, "ask");
  });
});

describe("r2 E: what the sandbox would only make fail asks", () => {
  test("23: a commit after a test run in one call", async () => {
    const { permission } = await call(await start(), "npm test && git commit -am x");
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /cannot work in the sandbox.*read-only/);
  });
  test("23: the commit agents write runs, with a writable .git", async () => {
    const { permission, shell } = await call(await start(), "git commit --allow-empty -m \"$(cat <<'EOF'\nA message.\n\nIt's fine.\nEOF\n)\"");
    assert.equal(permission.effect, "allow", permission.message);
    assert.ok(!list(shell.env, "AUTOMODE_RO").includes(path.join(project, ".git")), "the git directory is not read-only as a whole");
    assert.ok(list(shell.env, "AUTOMODE_RO").includes(path.join(project, ".git", "hooks")));
  });
  test("with the sandbox off nothing would fail, so nothing extra asks", async () => {
    const { permission } = await call(await start({ sandbox: false }), "npm test && git commit -am x");
    assert.equal(permission.effect, "allow");
  });
  // Round 4, finding 12: gh, docker and the bus clients need what the sandbox hides from every
  // command, so they ask while it is on and an approved run happens outside it.
  for (const [command, tool] of [["gh pr view 123", "gh"], ["docker ps", "docker"], ["systemctl status x", "systemctl"], ["loginctl", "loginctl"]]) {
    test(`r4 12: ${command} asks while the sandbox is on, and says why`, async () => {
      const { permission } = await call(await start(), command);
      assert.equal(permission.effect, "ask");
      assert.match(permission.message, new RegExp(`cannot work in the sandbox: ${tool} .*an approved run happens outside the sandbox`));
    });
  }
  test("r4 12: with the sandbox off gh pr view and docker ps are allowed as before", async () => {
    const host = await start({ sandbox: false });
    for (const command of ["gh pr view 123", "docker ps"]) assert.equal((await call(host, command)).permission.effect, "allow", command);
  });
});

describe("r2 20/28: settings", () => {
  const settingsAsk = async (config: unknown, options?: unknown, raw?: string) => {
    const { permission } = await call(await start(config, options, raw), "ls");
    return permission;
  };
  test("20: a settings file that holds null is invalid", async () => {
    const permission = await settingsAsk(undefined, undefined, "null");
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /settings are invalid/);
  });
  test("20: no plugin options at all is fine", async () => {
    assert.equal((await settingsAsk(undefined, null)).effect, "allow");
  });
  test("28: rules in the plugin options add to the file's rules", async () => {
    const host = await start({ rules: { ask: ["wc *"] } }, { rules: { ask: ["du *"] } });
    assert.match((await call(host, "wc -l README")).permission.message, /your ask rule/);
    assert.match((await call(host, "du -sh .")).permission.message, /your ask rule/);
  });
  for (const [name, config] of [
    ["a relative allowedPaths entry", { allowedPaths: ["build"] }],
    ["allowedPaths: ~", { allowedPaths: ["~"] }],
    ["allowedPaths: /", { allowedPaths: ["/"] }],
    ["sandboxWritable: /usr", { sandboxWritable: ["/usr"] }],
    ["a relative sandboxWritable entry", { sandboxWritable: ["./cache"] }],
    ["a relative sandboxHidePaths entry", { sandboxHidePaths: ["secrets"] }],
  ] as [string, unknown][]) {
    test(`28: ${name} is invalid`, async () => assert.match((await settingsAsk(config)).message ?? "", /settings are invalid/));
  }
  test("28: paths below the home directory are fine", async () => {
    assert.equal((await settingsAsk({ allowedPaths: ["~/scratch"], sandboxWritable: ["~/.cargo/registry"], sandboxHidePaths: ["~/private"] })).effect, "allow");
  });
});

describe("r2 33: the model server's unit", () => {
  const unit = fs.readFileSync(path.join(ROOT, "systemd", "opencode-automode-kev.service"), "utf8");
  const setting = (name: string) => unit.split("\n").filter((line) => line.startsWith(`${name}=`)).map((line) => line.slice(name.length + 1));
  test("it sees none of the home directory but its own data, and none of the runtime directory but its own socket", () => {
    assert.deepEqual(setting("ProtectHome"), ["tmpfs"]);
    assert.deepEqual(setting("BindReadOnlyPaths"), ["%h/.local/share/opencode-automode"]);
    assert.deepEqual(setting("TemporaryFileSystem"), ["%t:ro"]);
    assert.deepEqual(setting("BindPaths"), ["%t/opencode-automode"]);
    assert.deepEqual(setting("PrivateNetwork"), ["yes"]);
  });
});

// Round 3, findings 18 and 36: opencode 2.2.7 decides and runs the tool calls of one message at the
// same time, and a call run in the background (or moved there) ends its tool call while the
// process still runs. Sessions in one directory (subagents) share the plugin.
describe("r3 18/36: calls that run at the same time", () => {
  const origin = path.join(tmp, "r3-origin.git");
  // (B9-8: the stand-in's directory lies in the throwaway home test/run.mjs makes, outside every
  // temp directory: a PATH entry in one turns the safe list off after a session write.)
  const bin = path.join(os.homedir(), `r3-bin-${process.pid}`);
  const pathBefore = process.env.PATH;
  const g = (...args: string[]) => execFileSync("git", ["-C", project, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  before(() => {
    // A stand-in ssh: the remote end runs in this machine's git.
    fs.mkdirSync(bin);
    fs.writeFileSync(path.join(bin, "ssh"), '#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -o|-p|-l|-i|-F) shift 2 ;; -*) shift ;; *) break ;; esac; done\nshift\nexec sh -c "$*"\n', { mode: 0o755 });
    process.env.PATH = `${bin}:${pathBefore}`;
    execFileSync("git", ["init", "-q", "--bare", "-b", "main", origin]);
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "init");
    g("remote", "add", "origin", `ssh://automode-test.invalid${origin}`);
    g("push", "-q", "origin", "HEAD:refs/heads/main");
    g("checkout", "-q", "-b", "feature/r3");
    g("push", "-q", "-u", "origin", "feature/r3");
  });
  after(() => {
    process.env.PATH = pathBefore;
    g("remote", "remove", "origin");
    fs.rmSync(bin, { recursive: true, force: true });
  });
  const PUSH = "git push";
  const WRITER = "git checkout main";
  let n = 0;
  // The hooks of one call, one at a time, so that a test can interleave two calls.
  const decided = (host: Host, command: string, o: { sessionID?: string; background?: boolean } = {}) => {
    const id = `r3-${++n}`;
    const sessionID = o.sessionID ?? "r3";
    const decision = host.tool({ tool: "shell", sessionID, messageID: "m3", id, input: { command, ...(o.background ? { background: true } : {}) } });
    const run = async () => {
      const shell = { command, cwd: project, timeout: 120000, shell: "/bin/bash", env: baseEnv() as Record<string, string | undefined> };
      await host.shell(shell);
      const permission: any = { sessionID, action: "shell", resources: [command], source: { type: "tool", messageID: "m3", id }, effect: "allow" };
      await host.permission(permission);
      return { shell, permission };
    };
    const over = () => host.after({ tool: "shell", sessionID, messageID: "m3", id, status: "completed" });
    return { id, decision, run, over };
  };
  const whole = async (host: Host, command: string, o: { sessionID?: string; background?: boolean } = {}) => {
    const c = decided(host, command, o);
    await c.decision;
    return { ...c, ...(await c.run()) };
  };
  const push = () => start({ allowFeatureBranchPush: true });

  test("r4 21: a call decided before a pause asks when its permission is applied, and says how to resume", async () => {
    const host = await start({ useClassifier: false });
    const pending = decided(host, "git status --short", { sessionID: "pending" });
    await pending.decision;
    const writer = await whole(host, "git status", { sessionID: "writer" });
    const file = path.join(project, ".git/config.worktree");
    fs.writeFileSync(file, "[core]\n");
    try {
      await writer.over();
      const result = await pending.run();
      assert.equal(result.permission.effect, "ask");
      assert.match(result.permission.message, /To resume.*touch/);
    } finally {
      fs.rmSync(file, { force: true });
      for (const n of fs.readdirSync(path.dirname(file))) if (n.startsWith("automode-quarantine-config.worktree-")) fs.rmSync(path.join(path.dirname(file), n));
    }
  });
  test("r4 21: a call whose process outlives its hook is checked again when the process is gone", async () => {
    const host = await start({ useClassifier: false });
    const c = await whole(host, "git status");
    assert.equal(c.permission.effect, "allow");
    const child = spawn("/bin/sleep", ["30"], { env: c.shell.env as NodeJS.ProcessEnv, stdio: "ignore" });
    await new Promise<void>((resolve) => child.once("spawn", resolve));
    const gone = new Promise((resolve) => child.once("exit", resolve));
    const file = path.join(project, ".git/config.worktree");
    try {
      await c.over();
      fs.writeFileSync(file, "[core]\n");
      child.kill();
      await gone;
      const next = await whole(host, "ls");
      assert.equal(next.permission.effect, "ask");
      assert.match(next.permission.message, /moved to/);
      assert.ok(!fs.existsSync(file));
    } finally {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill();
        await gone;
      }
      fs.rmSync(file, { force: true });
      for (const n of fs.readdirSync(path.dirname(file))) if (n.startsWith("automode-quarantine-config.worktree-")) fs.rmSync(path.join(path.dirname(file), n));
    }
  });

  test("r4 21: completion preserves a linked worktree commondir and ignores a removed plant", async () => {
    const wt = path.join(tmp, "r4-linked");
    g("worktree", "add", "-q", "--detach", wt);
    try {
      const pointer = fs.readFileSync(path.join(wt, ".git"), "utf8").trim().slice(8);
      const file = path.join(pointer, "commondir");
      const original = fs.readFileSync(file, "utf8");
      const host = await start({ useClassifier: false });
      const c = await call(host, "git status", { sessionID: "r4-21-neighbour" });
      assert.equal(c.permission.effect, "allow", c.permission.message);
      const transient = path.join(project, ".git", "config.worktree");
      fs.writeFileSync(transient, "[core]\nfsmonitor = ./plant\n");
      fs.rmSync(transient);
      await host.after({ tool: "shell", sessionID: "r4-21-neighbour", messageID: "m1", id: c.id, status: "completed" });
      assert.equal(fs.readFileSync(file, "utf8"), original);
      const next = await call(host, "git status", { sessionID: "r4-21-neighbour" });
      assert.equal(next.permission.effect, "allow", next.permission.message);
    } finally { g("worktree", "remove", "--force", wt); }
  });

  test("r4 21: a call whose shell never started renames nothing", async () => {
    const host = await start({ useClassifier: false });
    const c = decided(host, "git status", { sessionID: "c-second-never-ran" });
    await c.decision;
    const p = path.join(project, ".git/config.worktree");
    fs.writeFileSync(p, "[core]\n");
    try {
      await c.over();
      assert.ok(fs.existsSync(p));
    } finally {
      fs.rmSync(p, { force: true });
      for (const n of fs.readdirSync(path.dirname(p))) if (n.startsWith("automode-quarantine-config.worktree-")) fs.rmSync(path.join(path.dirname(p), n));
    }
  });
  test("r4 21: a renamed plant pauses every session", async () => {
    const host = await start({ useClassifier: false });
    await call(host, "git status", { sessionID: "c-second-other" });
    const c = await call(host, "git status", { sessionID: "c-second-writer" });
    const p = path.join(project, ".git/config.worktree");
    fs.writeFileSync(p, "[core]\n");
    try {
      await host.after({ tool: "shell", sessionID: "c-second-writer", messageID: "m1", id: c.id, status: "completed" });
      const next = await call(host, "ls", { sessionID: "c-second-other" });
      assert.equal(next.permission.effect, "ask");
      assert.match(next.permission.message, /moved to/);
    } finally {
      fs.rmSync(p, { force: true });
      for (const n of fs.readdirSync(path.dirname(p))) if (n.startsWith("automode-quarantine-config.worktree-")) fs.rmSync(path.join(path.dirname(p), n));
    }
  });
  for (const where of ["main", "nested", "module"]) for (const name of ["commondir", "config.worktree"]) for (const link of [false, true]) {
    test(`r4 21: completion quarantines ${where} ${name}${link ? " symlink" : ""}`, async () => {
      const base = where === "main" ? path.join(project, ".git") : where === "nested" ? path.join(project, "r4-nested", ".git") : path.join(project, ".git", "modules", "r4-module");
      if (where !== "main") execFileSync("git", where === "nested" ? ["init", "-q", path.dirname(base)] : ["init", "-q", "--bare", base]);
      const planted = path.join(base, name);
      const host = await start({ useClassifier: false });
      const c = await call(host, where === "nested" ? "git -C r4-nested status" : "git status", { sessionID: "r4-21" });
      assert.equal(c.permission.effect, "allow", c.permission.message);
      if (link) fs.symlinkSync(origin, planted);
      else fs.writeFileSync(planted, name === "commondir" ? origin + "\n" : "[core]\nfsmonitor = ./planted-program\n");
      try {
        await host.after({ tool: "shell", sessionID: "r4-21", messageID: "m1", id: c.id, status: "completed" });
        assert.equal(fs.existsSync(planted), false, "git must no longer see the planted file before after returns");
        const saved = fs.readdirSync(base).find((n) => n.startsWith(`automode-quarantine-${name}-`));
        assert.ok(saved, "the planted file is preserved under a name git never reads");
        assert.equal(fs.lstatSync(path.join(base, saved)).isSymbolicLink(), link);
        const next = await call(host, "ls", { sessionID: "r4-21" });
        assert.equal(next.permission.effect, "ask");
        assert.ok(next.permission.message.includes(planted));
        assert.ok(next.permission.message.includes(saved));
      } finally {
        fs.rmSync(planted, { force: true });
        for (const n of fs.readdirSync(base)) if (n.startsWith(`automode-quarantine-${name}-`)) fs.rmSync(path.join(base, n));
        if (where !== "main") fs.rmSync(where === "nested" ? path.join(project, "r4-nested") : base, { recursive: true, force: true });
      }
    });
  }

  test("r4 23: external diff can move HEAD beside a checked push", async () => {
    const file = path.join(project, "r4-diff.txt");
    const helper = path.join(project, "r4-external-diff");
    const head = path.join(project, ".git", "HEAD");
    const originalHead = fs.readFileSync(head);
    const global = process.env.GIT_CONFIG_GLOBAL!;
    const originalGlobal = fs.readFileSync(global);
    fs.writeFileSync(file, "before\n");
    g("add", "r4-diff.txt");
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "diff fixture");
    fs.writeFileSync(file, "after\n");
    fs.writeFileSync(helper, "#!/bin/sh\nprintf 'ref: refs/heads/main\\n' > .git/HEAD\n", { mode: 0o755 });
    fs.appendFileSync(global, `\n[diff]\n\texternal = ${helper}\n`);
    try {
      const host = await push();
      const p = await whole(host, PUSH);
      assert.equal(p.permission.effect, "allow", p.permission.message);
      const d = await whole(host, "git diff --ext-diff");
      if (d.permission.effect === "allow") {
        const r = spawnSync(d.shell.shell, ["-c", d.shell.command], { cwd: project, env: d.shell.env as NodeJS.ProcessEnv, encoding: "utf8" });
        assert.equal(r.status, 0, r.stderr);
        assert.equal(fs.readFileSync(head, "utf8"), "ref: refs/heads/main\n", "the external diff really moved HEAD");
      }
      assert.equal(d.permission.effect, "ask", "a writable .git must not run beside the push");
      await d.over();
      await p.over();
      assert.equal((await whole(host, "git diff --ext-diff")).permission.effect, "allow");
    } finally {
      fs.writeFileSync(head, originalHead);
      fs.writeFileSync(global, originalGlobal);
      fs.writeFileSync(file, "before\n");
      fs.rmSync(helper, { force: true });
    }
  });

  test("r3 18: the push and the git-only call are each allowed on their own", async () => {
    const host = await push();
    const p = await whole(host, PUSH);
    assert.equal(p.permission.effect, "allow", p.permission.message);
    await p.over();
    const w = await whole(host, WRITER);
    assert.equal(w.permission.effect, "allow", w.permission.message);
    await w.over();
  });
  test("r3 18: a push asks while a git-only call decided before it may still run", async () => {
    const host = await push();
    const w = await whole(host, WRITER);
    assert.equal(w.permission.effect, "allow");
    const p = await whole(host, PUSH);
    assert.equal(p.permission.effect, "ask", "the checkout could land between the dry run and the push");
    await p.over();
    await w.over();
    const after = await whole(host, PUSH);
    assert.equal(after.permission.effect, "allow", after.permission.message);
  });
  test("r3 18: a git-only call asks while an allowed push may still run", async () => {
    const host = await push();
    const p = await whole(host, PUSH);
    assert.equal(p.permission.effect, "allow");
    const w = await whole(host, WRITER);
    assert.equal(w.permission.effect, "ask", w.permission.message);
    const other = await whole(host, WRITER, { sessionID: "r3-subagent" });
    assert.equal(other.permission.effect, "ask", "another session in the same checkout");
    await p.over();
    assert.equal((await whole(host, WRITER)).permission.effect, "allow");
  });
  // Round 4 (cross-check of finding 16): the marks are read from the text that runs. A push or a
  // git-only call spelled so that only the printed text shows it holds the same marks.
  for (const spelled of ["git push # the feature branch", "git pu\\\nsh", "git {push,}", "g''it push"]) {
    test(`r4 16: a push spelled ${JSON.stringify(spelled)} holds the push mark`, async () => {
      const host = await push();
      const p = await whole(host, spelled);
      assert.equal(p.permission.effect, "allow", p.permission.message);
      const w = await whole(host, WRITER);
      assert.equal(w.permission.effect, "ask", w.permission.message);
      await p.over();
      const again = await whole(host, WRITER);
      assert.equal(again.permission.effect, "allow", again.permission.message);
      const late = await whole(host, spelled);
      assert.equal(late.permission.effect, "ask", "the checkout may still run");
      await again.over();
      await late.over();
    });
  }
  test("r4 16: with the sandbox off, a git call spelled with quotes still counts as one that can move HEAD", async () => {
    const host = await start({ allowFeatureBranchPush: true, sandbox: false });
    const w = await whole(host, "g''it checkout main");
    assert.equal(w.permission.effect, "allow", w.permission.message);
    const p = await whole(host, PUSH);
    assert.equal(p.permission.effect, "ask", p.permission.message);
    await p.over();
    await w.over();
  });
  test("r3 18: a git-only call decided while the push is being checked asks", async () => {
    const host = await push();
    const p = decided(host, PUSH);
    const w = decided(host, WRITER);
    await Promise.all([p.decision, w.decision]);
    const [pr, wr] = [await p.run(), await w.run()];
    assert.notEqual(pr.permission.effect === "allow" && wr.permission.effect === "allow", true, "both ran without a prompt");
    assert.equal(wr.permission.effect, "ask");
  });
  test("r3 18: a prompt shown while a checked push may still run says so", async () => {
    const host = await push();
    const p = await whole(host, PUSH);
    assert.equal(p.permission.effect, "allow");
    // Asked (git writing .git from a call that is not git-only), and run unsandboxed if approved.
    const a = await whole(host, "git checkout main && npm test");
    assert.equal(a.permission.effect, "ask");
    assert.match(a.permission.message, /push .*still running/);
    await p.over();
  });
  test("r3 18: a push run in the background asks", async () => {
    const host = await push();
    const p = await whole(host, PUSH, { background: true });
    assert.equal(p.permission.effect, "ask");
  });
  test("r3 18: a push moved to the background holds the mark until its process is gone", async () => {
    const host = await push();
    const p = await whole(host, PUSH);
    assert.equal(p.permission.effect, "allow");
    // Its shell is still running (a stand-in with the same environment) when the tool call ends.
    const child = spawn("sleep", ["30"], { env: p.shell.env as NodeJS.ProcessEnv, stdio: "ignore" });
    const gone = new Promise((r) => child.on("exit", r));
    try {
      await p.over();
      assert.equal((await whole(host, WRITER)).permission.effect, "ask");
    } finally {
      child.kill();
      await gone;
    }
    assert.equal((await whole(host, WRITER)).permission.effect, "allow");
  });

  test("r3 33: state a git-only call leaves that its subcommands do not explain pauses the session when the call is over", async () => {
    const host = await start();
    const merge = path.join(project, ".git", "rebase-merge");
    try {
      const status = await whole(host, "git status");
      assert.equal(status.permission.effect, "allow", status.permission.message);
      // What a hook run by the call could leave: a stopped rebase with a command in its todo.
      fs.mkdirSync(merge);
      fs.writeFileSync(path.join(merge, "git-rebase-todo"), "exec touch planted\n");
      await status.over();
      const next = await whole(host, "ls");
      assert.equal(next.permission.effect, "ask");
      assert.match(next.permission.message, /paused.*rebase-merge/);
    } finally {
      fs.rmSync(merge, { recursive: true, force: true });
    }
  });
  test("r3 33: state appearing after the git-only call is over is the user's own", async () => {
    const host = await start();
    const head = path.join(project, ".git", "MERGE_HEAD");
    try {
      const status = await whole(host, "git status");
      assert.equal(status.permission.effect, "allow", status.permission.message);
      await status.over();
      fs.writeFileSync(head, "0".repeat(40) + "\n");
      const next = await whole(host, "ls");
      assert.equal(next.permission.effect, "allow", next.permission.message);
    } finally {
      fs.rmSync(head, { force: true });
    }
  });

  // Round 4, finding 4, as the hooks carry it: what an approved command writes is recorded when
  // it has run, and a git call's changes to the work tree are settled once the call is over.
  test("r4 4: what an approved command wrote is the session's writing", async () => {
    const host = await start({ useClassifier: false });
    const script = path.join(project, "r4-approved.sh");
    // A script that was there before the session, in a directory of its own.
    const old = path.join(project, "r4-old");
    fs.mkdirSync(old);
    fs.writeFileSync(path.join(old, "old.sh"), "#!/bin/sh\necho old\n", { mode: 0o755 });
    g("add", "r4-old");
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "an old script");
    try {
      const before = await whole(host, "cd r4-old && ./old.sh");
      assert.equal(before.permission.effect, "allow", before.permission.message);
      await before.over();
      const asked = await whole(host, "git config user.name r4 && printf '#!/bin/sh\\necho hi\\n' > r4-approved.sh && chmod +x r4-approved.sh");
      assert.equal(asked.permission.effect, "ask", asked.permission.message);
      // The user approves, and the command does what it says.
      fs.writeFileSync(script, "#!/bin/sh\necho hi\n", { mode: 0o755 });
      await asked.over();
      // The file itself is caught by its change time (the first line) ...
      const run = await whole(host, "./r4-approved.sh");
      assert.equal(run.permission.effect, "ask");
      assert.match(run.permission.message, /runs r4-approved\.sh, changed since this session began/);
      // ... and the approval recorded the write (the second line): an old script that runs where
      // it lies goes to the model for it (B7-2), which nothing but the record makes it do.
      const beside = await whole(host, "cd r4-old && ./old.sh");
      assert.equal(beside.permission.effect, "ask");
      assert.match(beside.permission.message, /runs old\.sh after this session wrote \S*r4-approved\.sh/);
    } finally {
      fs.rmSync(script, { force: true });
      g("rm", "-q", "-r", "-f", "r4-old");
      g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "the old script gone");
    }
  });
  test("r4 4: once a git call is over, the files it changed are marked and the rest of the repository is not", async () => {
    const host = await start({ useClassifier: false });
    const here = g("rev-parse", "--abbrev-ref", "HEAD").toString().trim();
    // Two directories: the checkout changes a script in one of them. (B7-2: a script goes to the
    // model when the session wrote where it lives or runs, or above; so each is run where it lies.)
    for (const name of ["r4-a/same.sh", "r4-b/changed.sh", "r4-b/beside.sh"]) {
      fs.mkdirSync(path.dirname(path.join(project, name)), { recursive: true });
      fs.writeFileSync(path.join(project, name), "#!/bin/sh\necho one\n", { mode: 0o755 });
    }
    g("add", "r4-a", "r4-b");
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "three scripts");
    g("checkout", "-q", "-b", "r4-d1");
    fs.writeFileSync(path.join(project, "r4-b", "changed.sh"), "#!/bin/sh\necho two\n", { mode: 0o755 });
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qam", "one of them changes");
    g("checkout", "-q", here);
    try {
      const checkout = await whole(host, "git checkout r4-d1");
      assert.equal(checkout.permission.effect, "allow", checkout.permission.message);
      // While the call may still run, the whole repository counts as written. (The prompt is not
      // answered: an approved call that was the model's to judge marks the project, B7-2.)
      const during = await whole(host, "cd r4-a && ./same.sh");
      assert.equal(during.permission.effect, "ask", "a script run beside a git call that is still writing");
      assert.match(during.permission.message, /in a place where this session wrote files the guard cannot list/);
      g("checkout", "-q", "r4-d1");
      await checkout.over();
      // (B8-3: what git changed is a write of the session in the project, so the script in the
      // other directory goes to the model too. The record is now the file git changed, by name,
      // and no longer the whole repository.)
      const same = await whole(host, "cd r4-a && ./same.sh");
      assert.equal(same.permission.effect, "ask", same.permission.message);
      assert.match(same.permission.message, /runs same\.sh after this session wrote \.\.\/r4-b\/changed\.sh/);
      // The changed file is caught by its change time (the first line) ...
      const changed = await whole(host, "cd r4-b && ./changed.sh");
      assert.equal(changed.permission.effect, "ask");
      assert.match(changed.permission.message, /runs changed\.sh, changed since this session began/);
      // ... and git's change is recorded for it (D1, the second line): the script beside it, which
      // nothing changed, goes to the model because of that record.
      const beside = await whole(host, "cd r4-b && ./beside.sh");
      assert.equal(beside.permission.effect, "ask");
      assert.match(beside.permission.message, /runs beside\.sh after this session wrote changed\.sh/);
    } finally {
      g("checkout", "-q", "-f", here);
      g("branch", "-q", "-D", "r4-d1");
      g("rm", "-q", "-r", "-f", "r4-a", "r4-b");
      g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "scripts gone");
    }
  });

  const reply = async (host: Host, id: string) => {
    await host.emit({ type: "permission.asked", data: { id: `per_${id}`, sessionID: "x", action: "shell", resources: [], source: { type: "tool", messageID: "m3", id } } });
    await host.emit({ type: "permission.replied", data: { requestID: `per_${id}`, reply: "once" } });
  };
  const edit = async (host: Host, target: string) => {
    const event: any = { sessionID: "r3", action: "edit", resources: [target], effect: "allow" };
    await host.permission(event);
    return event.effect;
  };
  test("r3 36: while an approved command may create a repository, calls that could write there ask", async () => {
    const host = await start();
    const first = await whole(host, "ls");
    assert.equal(first.permission.effect, "allow");
    await first.over();
    const dir = path.join(project, "r3-window");
    const init = await whole(host, "git init r3-window");
    assert.equal(init.permission.effect, "ask");
    await reply(host, init.id);
    try {
      assert.equal((await whole(host, "ls")).permission.effect, "ask", "a sandboxed call could plant a repository there now");
      assert.equal((await whole(host, "ls", { sessionID: "r3-subagent" })).permission.effect, "ask");
      assert.equal(await edit(host, path.join(dir, "HEAD")), "ask");
      execFileSync("git", ["init", "-q", dir]);
      await init.over();
      const next = await whole(host, "ls");
      assert.equal(next.permission.effect, "allow", next.permission.message);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  test("r3 36: an approval while a sandboxed call is still running expects nothing", async () => {
    const host = await start();
    const running = await whole(host, "ls -R");
    assert.equal(running.permission.effect, "allow");
    const dir = path.join(project, "r3-window2");
    const init = await whole(host, "git init r3-window2");
    await reply(host, init.id);
    try {
      // The repository may be the running call's, planted in the place the approval named.
      execFileSync("git", ["init", "-q", dir]);
      await init.over();
      await running.over();
      const next = await whole(host, "ls");
      assert.equal(next.permission.effect, "ask");
      assert.match(next.permission.message, /paused.*r3-window2/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  // B10-9: the other edit that asks (an approved command may be creating a repository there):
  // approved, what it writes is the session's as well.
  test("r4 B10-9: an edit asked about while an approved command may create a repository, once approved, is a session write", async () => {
    fs.writeFileSync(path.join(project, "b10-window-run.sh"), "#!/bin/sh\n. ./r3-window3/b10.sh\n", { mode: 0o755 });
    g("add", "b10-window-run.sh");
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "b10 window script");
    const host = await start({ useClassifier: false });
    const dir = path.join(project, "r3-window3");
    try {
      const before = await whole(host, "./b10-window-run.sh", { sessionID: "b10w" });
      assert.equal(before.permission.effect, "allow", before.permission.message);
      await before.over();
      const init = await whole(host, "git init r3-window3", { sessionID: "b10w" });
      assert.equal(init.permission.effect, "ask");
      await reply(host, init.id);
      const target = path.join(dir, "b10.sh");
      const id = `b10w-${++n}`;
      const source = { type: "tool", messageID: "m10", id };
      const edited: any = { sessionID: "b10w", action: "edit", resources: [target], source, effect: "allow" };
      await host.permission(edited);
      assert.equal(edited.effect, "ask");
      assert.match(edited.message, /approved command may still be creating a repository/);
      await host.emit({ type: "permission.asked", data: { id: `per_${id}`, sessionID: "b10w", action: "edit", resources: [target], source } });
      await host.emit({ type: "permission.replied", data: { sessionID: "b10w", requestID: `per_${id}`, reply: "once" } });
      execFileSync("git", ["init", "-q", dir]);
      await init.over();
      const after = await whole(host, "./b10-window-run.sh", { sessionID: "b10w" });
      assert.equal(after.permission.effect, "ask", after.permission.message);
      assert.match(after.permission.message, /leave this to the model/);
      assert.match(after.permission.message, /b10\.sh/);
      // Council project review 1: another session of the project shares the record.
      const other = await whole(host, "./b10-window-run.sh", { sessionID: "b10w-other" });
      assert.equal(other.permission.effect, "ask", other.permission.message);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
      g("rm", "-q", "b10-window-run.sh");
      g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "b10 window script gone");
    }
  });
});

// Round 3, finding 37: only shells whose syntax the checks model are wrapped. bash is, and `sh`
// when it really is bash (after every symbolic link, /etc/alternatives included). dash (round 4,
// finding 15), zsh and any other shell (busybox, mksh, ksh, yash) is not: every allow asks through
// "its shell could not be sandboxed". A shell named bash that really is another program asks too.
describe("r3 37: which shells are wrapped", () => {
  const shells = path.join(tmp, "r3-37-shells");
  const which = (name: string) => ["/usr/bin", "/bin"].map((d) => path.join(d, name)).find((p) => fs.existsSync(p));
  // `<dir>/<name>` as a symbolic link to `target`.
  const link = (dir: string, name: string, target: string) => {
    fs.mkdirSync(path.join(shells, dir), { recursive: true });
    const p = path.join(shells, dir, name);
    fs.rmSync(p, { force: true });
    fs.symlinkSync(target, p);
    return p;
  };
  // A stand-in program called `name`: not a shell the checks model.
  const other = (name: string) => {
    fs.mkdirSync(path.join(shells, "progs"), { recursive: true });
    const p = path.join(shells, "progs", name);
    fs.copyFileSync(which("bash")!, p);
    fs.chmodSync(p, 0o755);
    return p;
  };
  const wrappedAs = (shell: { shell: string }, name: string) => shell.shell === path.join(ROOT, "sandbox", "bin", name);
  test("r3 37: zsh asks: its shell is left alone", async () => {
    const { permission, shell } = await call(await start(), "ls", { shell: "/usr/bin/zsh" });
    assert.equal(shell.shell, "/usr/bin/zsh");
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /could not be sandboxed/);
  });
  // Round 4, finding 15 (decided after three rounds each found text dash reads another way
  // than bash without being marked): nothing is allowed without a prompt under dash. The shell
  // is left alone, and the prompt says what to change.
  for (const config of [undefined, { sandbox: false }]) {
    test(`r4 15: sh that is dash asks, with the sandbox ${config ? "off" : "on"}, and says to use bash`, async (t) => {
      const dash = which("dash");
      if (!dash) return t.skip("no dash here");
      const sh = link("dash", "sh", dash);
      for (const command of ["echo hello", "ls", "git status"]) {
        const { permission, shell } = await call(await start(config), command, { shell: sh });
        assert.equal(permission.effect, "ask", command);
        assert.match(permission.message, /shell here is dash.*bash/s, command);
        assert.equal(shell.shell, sh, "the shell is left as it is");
        assert.equal(shell.command, command);
        assert.equal(shell.env.AUTOMODE_COMMAND, undefined);
      }
    });
  }
  test("r4 15: dash under its own name asks too", async (t) => {
    const dash = which("dash");
    if (!dash) return t.skip("no dash here");
    const { permission, shell } = await call(await start(), "ls", { shell: dash });
    assert.equal(permission.effect, "ask");
    assert.equal(shell.shell, dash);
  });
  // The log says why a command the rules allow was asked about after all.
  test("r4 15: the log records an allowed command that asked for want of its shell, with the reason", async (t) => {
    const dash = which("dash");
    if (!dash) return t.skip("no dash here");
    const log = path.join(stateDir, "decisions.jsonl");
    fs.rmSync(log, { force: true });
    const { permission } = await call(await start(), "ls", { shell: dash });
    assert.equal(permission.effect, "ask");
    const miss = fs.readFileSync(log, "utf8").trim().split("\n").map((line) => JSON.parse(line)).find((entry) => entry.sandboxMiss);
    assert.ok(miss, "a sandboxMiss record");
    assert.equal(miss.command, "ls");
    assert.match(miss.reason, /would be allowed .*shell here is dash/s);
  });
  test("r3 37: sh that is bash, through a chain of links like /etc/alternatives, is wrapped", async () => {
    const bash = which("bash")!;
    const alt = link("alternatives", "sh", bash);
    const sh = link("chain", "sh", alt);
    const { permission, shell } = await call(await start(), "ls", { shell: sh });
    assert.equal(permission.effect, "allow", permission.message);
    assert.ok(wrappedAs(shell, "sh"), shell.shell);
  });
  for (const name of ["busybox", "mksh", "ksh", "yash", "zsh", "posh"]) {
    test(`r3 37: sh that is ${name} asks`, async () => {
      const sh = link(`as-${name}`, "sh", other(name));
      const { permission, shell } = await call(await start(), "ls", { shell: sh });
      assert.equal(shell.shell, sh);
      assert.equal(permission.effect, "ask");
      assert.match(permission.message, /could not be sandboxed/);
    });
  }
  test("r3 37: a shell named bash that is another program asks", async () => {
    const bash = link("fake-bash", "bash", other("zsh"));
    const { permission, shell } = await call(await start(), "ls", { shell: bash });
    assert.equal(shell.shell, bash);
    assert.equal(permission.effect, "ask");
  });
  test("r3 37: bash is still wrapped", async () => {
    const { permission, shell } = await call(await start(), "ls", { shell: "/bin/bash" });
    assert.equal(permission.effect, "allow", permission.message);
    assert.ok(wrapped(shell));
  });
  test("r3 37: the wrapper has no zsh link to stand in for", () => {
    const build: string = JSON.parse(fs.readFileSync(path.join(ROOT, "package.json"), "utf8")).scripts["build:sandbox"];
    const links = /for s in ([^;]*);/.exec(build)?.[1].split(" ");
    assert.deepEqual(links, ["bash", "sh"], build);
  });
});

// Round 4, finding 16: an allow is an allow of the text canon.ts printed, and that text is what
// the shell runs. Sandboxed, the wrapper takes it from AUTOMODE_COMMAND in place of the command
// opencode hands it; with the sandbox off the shell is handed it as its command. Where neither
// can be done the allow asks.
describe("r4 16: what was judged is what runs", () => {
  const which = (name: string) => ["/usr/bin", "/bin"].map((d) => path.join(d, name)).find((p) => fs.existsSync(p));
  const run = (shell: { shell: string; command: string; env: Record<string, string | undefined> }) => spawnSync(shell.shell, ["-c", shell.command], { cwd: project, env: shell.env as NodeJS.ProcessEnv, encoding: "utf8" });
  test("the wrapper is handed the printed text, and runs it in place of the command", async () => {
    const command = 'echo "a  b" # said twice\necho {x,y}{1..2}';
    const { shell, permission } = await call(await start(), command);
    assert.equal(permission.effect, "allow", permission.message);
    assert.ok(wrapped(shell));
    assert.equal(shell.command, command, "opencode keeps the command as issued: its own rules and its record read that");
    assert.equal(shell.env.AUTOMODE_COMMAND, "echo 'a  b'\necho x1 x2 y1 y2");
    assert.equal(run(shell).stdout, "a  b\nx1 x2 y1 y2\n");
    // Whatever opencode's `-c` argument holds, the judged text is what runs.
    const other = spawnSync(shell.shell, ["-c", "echo not this"], { cwd: project, env: shell.env as NodeJS.ProcessEnv, encoding: "utf8" });
    assert.equal(other.stdout, "a  b\nx1 x2 y1 y2\n", other.stderr);
  });
  test("the command's own environment does not hold the text", async () => {
    const { shell } = await call(await start(), "env | grep -c AUTOMODE_ || true");
    // `env` asks (it prints the environment); use the wrapper directly with the same plan.
    const { shell: plain } = await call(await start(), "echo ok");
    const r = spawnSync(plain.shell, ["-c", "x"], { cwd: project, env: { ...plain.env, AUTOMODE_COMMAND: "echo [${AUTOMODE_COMMAND:-unset}][${AUTOMODE_SHELL:-unset}]" } as NodeJS.ProcessEnv, encoding: "utf8" });
    assert.equal(r.stdout, "[unset][unset]\n", r.stderr);
    assert.equal(shell.env.AUTOMODE_COMMAND, undefined, "a command that asks gets no text");
  });
  test("the wrapper runs nothing when its arguments are not the ones the text stands in for", async () => {
    const { shell } = await call(await start(), "echo ok");
    for (const args of [["-x", "-c", "echo ok"], ["-c", "echo ok", "extra"], ["script.sh"], ["-c"]]) {
      const r = spawnSync(shell.shell, args, { cwd: project, env: shell.env as NodeJS.ProcessEnv, encoding: "utf8" });
      assert.equal(r.status, 126, `${args.join(" ")}: ${r.stdout}${r.stderr}`);
      assert.equal(r.stdout, "");
    }
    const dashed = spawnSync(shell.shell, ["-c", "x"], { cwd: project, env: { ...shell.env, AUTOMODE_COMMAND: "-n ; echo ran" } as NodeJS.ProcessEnv, encoding: "utf8" });
    assert.equal(dashed.status, 126, dashed.stderr);
    assert.doesNotMatch(dashed.stdout, /ran/);
  });
  test("a command that cannot be printed asks, and says so", async () => {
    const { shell, permission } = await call(await start(), 'echo "$(cat <<EOF\n(\nEOF)" ; ls ; echo "\nEOF\n)"');
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /cannot be printed back.*heredoc line that starts with the delimiter/s);
    assert.equal(shell.shell, "/bin/bash");
    assert.equal(shell.env.AUTOMODE_COMMAND, undefined);
  });
  test("two identical commands issued together share one printed text and are both sandboxed", async () => {
    const host = await start();
    const command = "echo {a,b}";
    await host.tool({ tool: "shell", sessionID: "s1", messageID: "m9", id: "x1", input: { command } });
    await host.tool({ tool: "shell", sessionID: "s1", messageID: "m9", id: "x2", input: { command } });
    const shells = [1, 2].map(() => ({ command, cwd: project, timeout: 120000, shell: "/bin/bash", env: baseEnv() as Record<string, string | undefined> }));
    for (const shell of shells) await host.shell(shell);
    for (const shell of shells) assert.equal(shell.env.AUTOMODE_COMMAND, "echo a b");
    for (const id of ["x1", "x2"]) {
      const permission: any = { sessionID: "s1", action: "shell", resources: [command], source: { type: "tool", messageID: "m9", id }, effect: "allow" };
      await host.permission(permission);
      assert.equal(permission.effect, "allow", permission.message);
    }
  });
  test("under dash every command asks, text that relies on bash and plain text alike", async (t) => {
    const dash = which("dash");
    if (!dash) return t.skip("no dash here");
    const dir = path.join(tmp, "r4-16-dash");
    fs.mkdirSync(dir, { recursive: true });
    const sh = path.join(dir, "sh");
    fs.rmSync(sh, { force: true });
    fs.symlinkSync(dash, sh);
    for (const command of ["echo {a,b}", "[[ -d . ]] && ls", "cat <<< x", "ls &> out.txt", "echo 'a  b'; ls"]) {
      const { shell, permission } = await call(await start(), command, { shell: sh });
      assert.equal(permission.effect, "ask", command);
      assert.match(permission.message, /shell here is dash/, command);
      assert.equal(shell.shell, sh, command);
      assert.equal(shell.env.AUTOMODE_COMMAND, undefined, command);
    }
    // The same text under bash is fine.
    assert.equal((await call(await start(), "echo {a,b}")).permission.effect, "allow");
  });
  test("with the sandbox off the shell is handed the printed text as its command", async () => {
    const command = "echo {a,b}  # c";
    const { shell, permission } = await call(await start({ sandbox: false }), command);
    assert.equal(permission.effect, "allow", permission.message);
    assert.equal(shell.shell, "/bin/bash", "no wrapper");
    assert.equal(shell.command, "echo a b");
    assert.equal(shell.env.AUTOMODE_COMMAND, undefined);
    assert.equal(run(shell).stdout, "a b\n");
  });
  test("with the sandbox off an allow asks when its shell is not one the checks model", async () => {
    const { shell, permission } = await call(await start({ sandbox: false }), "ls", { shell: "/usr/bin/zsh" });
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /could not be handed the text that was judged/);
    assert.equal(shell.command, "ls");
  });
  test("with the sandbox off an allow asks when no shell came for it", async () => {
    const { permission } = await call(await start({ sandbox: false }), "ls", { noShell: true });
    assert.equal(permission.effect, "ask");
  });
  test("with the sandbox off a command that asks keeps its text", async () => {
    const command = "sudo  ls  # x";
    const { shell, permission } = await call(await start({ sandbox: false }), command);
    assert.equal(permission.effect, "ask");
    assert.equal(shell.command, command);
  });
  // Found by the round 4 cross-check (both reading reviews): with the sandbox off, a call whose
  // first shell was handed the printed text stayed allowed when a later shell for the same
  // command was left as written. Which shell is whose cannot be told, so neither may run on an
  // allow, as with the sandbox on.
  for (const [what, other] of [
    ["from another session", { sessionID: "s2", shell: "/bin/bash" }],
    ["under a shell the checks do not model", { sessionID: "s1", shell: "/usr/bin/zsh" }],
  ] as const) {
    test(`with the sandbox off an allow asks once a later shell for the same command, ${what}, is left as written`, async () => {
      const host = await start({ sandbox: false });
      const command = "echo {a,b}";
      const newShell = (shell: string) => ({ command, cwd: project, timeout: 120000, shell, env: baseEnv() as Record<string, string | undefined> });
      await host.tool({ tool: "shell", sessionID: "s1", messageID: "m9", id: "u1", input: { command } });
      const first = newShell("/bin/bash");
      await host.shell(first);
      assert.equal(first.command, "echo a b", "the first shell is handed the printed text");
      await host.tool({ tool: "shell", sessionID: other.sessionID, messageID: "m9", id: "u2", input: { command } });
      const second = newShell(other.shell);
      await host.shell(second);
      assert.equal(second.command, command, "the second shell is left as written");
      const permission: any = { sessionID: "s1", action: "shell", resources: [command], source: { type: "tool", messageID: "m9", id: "u1" }, effect: "allow" };
      await host.permission(permission);
      assert.equal(permission.effect, "ask", permission.message);
      assert.match(permission.message, /could not be handed the text that was judged/);
    });
  }
  test("the decision log holds the command as issued and the text that runs", async () => {
    await call(await start(), "echo {a,b}  # c");
    const lines = fs.readFileSync(path.join(stateDir, "decisions.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const entry = lines.findLast((l) => l.command === "echo {a,b}  # c");
    assert.equal(entry?.runs, "echo a b");
    assert.equal(entry?.printed, undefined);
  });
});

// Round 4, finding 37: index.ts cites opencode 2.2.7 for the order of its three hooks for one
// call: tool.execute.before, shell.create.before, permission.evaluate. In any other order an
// allow must not stand: the shell that runs would not be the one that was sandboxed.
describe("r4 37: the hooks in another order than opencode 2.2.7's", () => {
  const command = "echo ordered";
  const newShell = () => ({ command, cwd: project, timeout: 120000, shell: "/bin/bash", env: baseEnv() as Record<string, string | undefined> });
  const evaluate = async (host: Host, id: string) => {
    const permission: any = { sessionID: "s1", action: "shell", resources: [command], source: { type: "tool", messageID: "m7", id }, effect: "allow" };
    await host.permission(permission);
    return permission;
  };
  for (const config of [undefined, { sandbox: false }]) {
    const mode = config ? "sandbox off" : "sandbox on";
    test(`${mode}: the permission is evaluated before the shell is created: asks, and the later shell is left alone`, async () => {
      const host = await start(config);
      await host.tool({ tool: "shell", sessionID: "s1", messageID: "m7", id: "o1", input: { command } });
      const permission = await evaluate(host, "o1");
      assert.equal(permission.effect, "ask", permission.message);
      const shell = newShell();
      await host.shell(shell);
      assert.equal(shell.shell, "/bin/bash");
      assert.equal(shell.command, command);
      assert.equal(shell.env.AUTOMODE_COMMAND, undefined);
    });
    test(`${mode}: the shell is created before the tool hook: left alone, and the allow asks`, async () => {
      const host = await start(config);
      const shell = newShell();
      await host.shell(shell);
      assert.equal(shell.shell, "/bin/bash");
      assert.equal(shell.command, command);
      await host.tool({ tool: "shell", sessionID: "s1", messageID: "m7", id: "o2", input: { command } });
      const permission = await evaluate(host, "o2");
      assert.equal(permission.effect, "ask", permission.message);
    });
    test(`${mode}: the permission is evaluated with no tool hook before it: asks`, async () => {
      const host = await start(config);
      const permission = await evaluate(host, "o3");
      assert.equal(permission.effect, "ask", permission.message);
      assert.match(permission.message, /not a tool call the plugin saw start/);
    });
    test(`${mode}: the call is over before its permission is evaluated: asks`, async () => {
      const host = await start(config);
      await host.tool({ tool: "shell", sessionID: "s1", messageID: "m7", id: "o4", input: { command } });
      await host.after({ tool: "shell", sessionID: "s1", messageID: "m7", id: "o4", input: { command }, status: "completed", result: { content: [] } });
      const shell = newShell();
      await host.shell(shell);
      assert.equal(shell.shell, "/bin/bash", "a shell that comes after the call is over is not this call's");
      const permission = await evaluate(host, "o4");
      assert.equal(permission.effect, "ask", permission.message);
    });
    test(`${mode}: opencode 2.2.7's order allows`, async () => {
      const { permission } = await call(await start(config), command);
      assert.equal(permission.effect, "allow", permission.message);
    });
  }
});

// Round 3, finding 40, through the plugin's hooks: one allowed shell call (decision and plan) walks
// each root once, and so does one edit.
describe("r3 40: the plugin walks each root once per call", () => {
  test("r3 40: an allowed shell call", async () => {
    const host = await start();
    await call(host, "ls"); // the session's first call takes the snapshot
    walkCount.clear();
    const { permission, shell } = await call(host, "ls");
    assert.equal(permission.effect, "allow", permission.message);
    assert.ok(wrapped(shell));
    const counts = Object.fromEntries(walkCount);
    assert.equal(counts[project], 1, JSON.stringify(counts));
    for (const [root, n] of Object.entries(counts)) assert.equal(n, 1, `${root} walked ${n} times`);
  });
  test("r3 40: an edit", async () => {
    const host = await start();
    walkCount.clear();
    const permission: any = { sessionID: "s40", action: "edit", resources: ["src/a.ts"], effect: "allow" };
    await host.permission(permission);
    assert.equal(permission.effect, "allow");
    assert.deepEqual(Object.fromEntries(walkCount), { [project]: 1 });
  });
});

// Round 4, finding 21 (decision 1), through the plugin's hooks: the check of `commondir` and
// `config.worktree` belongs to one call, from the moment its shell may start to its end.
describe("r4 21: the per-call check of a git-only call, through the hooks", () => {
  // A repository in the temp directory: writable in every sandbox, and no part of the project,
  // so nothing but a call's own check looks at it.
  const other = path.join(tmp, "r4-21-other");
  const control = path.join(other, ".git", "config.worktree");
  const quarantined = (dir: string) => fs.readdirSync(dir).filter((n) => n.startsWith("automode-quarantine-"));
  const over = (host: Host, c: { id: string }, sessionID: string) => host.after({ tool: "shell", sessionID, messageID: "m1", id: c.id, status: "completed" });
  before(() => void execFileSync("git", ["init", "-q", other]));
  afterEach(() => {
    for (const dir of [path.join(other, ".git"), path.join(project, ".git")]) {
      fs.rmSync(path.join(dir, "config.worktree"), { force: true });
      for (const name of quarantined(dir)) fs.rmSync(path.join(dir, name));
    }
  });
  after(() => fs.rmSync(other, { recursive: true, force: true }));

  test("r4 21: a call still running after 500 later calls is checked when it completes", async () => {
    const host = await start({ useClassifier: false });
    const c = await call(host, `git -C ${other} status`, { sessionID: "r4-21-long" });
    assert.equal(c.permission.effect, "allow", c.permission.message);
    // Calls that are over at once (denied), enough to fill the table of calls.
    for (let i = 0; i < 501; i++) await host.tool({ tool: "shell", sessionID: "r4-21-long", messageID: "m1", id: `filler-${i}`, input: { command: "rm -rf /" } });
    fs.writeFileSync(control, "[core]\n");
    await over(host, c, "r4-21-long");
    assert.equal(fs.existsSync(control), false, "renamed before the completion hook returns");
    assert.equal(quarantined(path.dirname(control)).length, 1);
  });

  test("r4 21: a completion compares the record of its own call, not that of another call still running", async () => {
    const host = await start({ useClassifier: false });
    const early = await call(host, `git -C ${other} status`, { sessionID: "r4-21-two" });
    // The user's own, after the first call started and before the second.
    fs.writeFileSync(control, "[core]\n");
    const late = await call(host, `git -C ${other} status --short`, { sessionID: "r4-21-two" });
    assert.equal(late.permission.effect, "allow", late.permission.message);
    await over(host, late, "r4-21-two");
    assert.ok(fs.existsSync(control), "there before the call that completed started");
    await over(host, early, "r4-21-two");
    assert.equal(fs.existsSync(control), false, "it appeared while the first call ran");
  });

  test("r4 21: a call whose record of a git directory cannot be made asks, with the reason", async () => {
    const host = await start({ useClassifier: false });
    const command = `git -C ${other} log --oneline`;
    await host.tool({ tool: "shell", sessionID: "r4-21-closed", messageID: "m1", id: "closed-1", input: { command } });
    const shell = { command, cwd: project, timeout: 120000, shell: "/bin/bash", env: baseEnv() as Record<string, string | undefined> };
    await host.shell(shell);
    assert.ok(wrapped(shell));
    // opencode's own verdict is ask here: the message must be the plugin's all the same.
    const permission: any = { sessionID: "r4-21-closed", action: "shell", resources: [command], source: { type: "tool", messageID: "m1", id: "closed-1" }, effect: "ask" };
    const original = fs.lstatSync;
    fs.lstatSync = ((p: fs.PathLike, ...rest: unknown[]) => {
      if (String(p) === control) throw Object.assign(new Error(`EACCES: permission denied, lstat '${p}'`), { code: "EACCES" });
      return (original as (...args: unknown[]) => unknown)(p, ...rest);
    }) as typeof fs.lstatSync;
    try {
      await host.permission(permission);
    } finally {
      fs.lstatSync = original;
    }
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /would be allowed.*a git directory it could write cannot be looked into.*EACCES/);
  });
});

// Round 4, finding 21 (decision 1): a push also works in the repository it pushes to.
describe("r4 21: a push to a repository on this machine, through the hooks", () => {
  const dest = path.join(tmp, "r4-21-dest.git");
  const g = (...args: string[]) => execFileSync("git", ["-C", project, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  before(() => {
    execFileSync("git", ["init", "-q", "--bare", dest]);
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "to push");
    g("remote", "add", "r4local", dest);
  });
  after(() => {
    g("remote", "remove", "r4local");
    fs.rmSync(dest, { recursive: true, force: true });
  });
  // Your own allow rule: the rules ask about every push otherwise.
  const allowing = () => start({ useClassifier: false, rules: { allow: ["git push r4local *"] } });

  test("r4 21: the destination is writable for the push, its hooks and config are not, and the push works", async () => {
    const { permission, shell } = await call(await allowing(), "git push r4local HEAD:refs/heads/pushed", { sessionID: "r4-21-push" });
    assert.equal(permission.effect, "allow", permission.message);
    assert.ok(wrapped(shell));
    assert.ok(list(shell.env, "AUTOMODE_PIN").includes(dest));
    assert.ok(!list(shell.env, "AUTOMODE_RO").includes(dest));
    for (const name of ["hooks", "config"]) assert.ok(list(shell.env, "AUTOMODE_RO").includes(path.join(dest, name)), name);
    const r = spawnSync(shell.shell, ["-c", shell.command], { cwd: project, env: shell.env as NodeJS.ProcessEnv, encoding: "utf8", timeout: 30_000 });
    assert.equal(r.status, 0, r.stderr);
    assert.equal(execFileSync("git", ["--git-dir", dest, "rev-parse", "refs/heads/pushed"], { encoding: "utf8" }), execFileSync("git", ["-C", project, "rev-parse", "HEAD"], { encoding: "utf8" }));
  });

  test("r4 21: a commondir planted in the destination while the push runs is renamed when it completes, and the session pauses", async () => {
    const host = await allowing();
    const c = await call(host, "git push r4local HEAD:refs/heads/again", { sessionID: "r4-21-plant" });
    assert.equal(c.permission.effect, "allow", c.permission.message);
    // No hook and no config of the destination is involved: whatever in the push's sandbox can
    // write the destination's git directory can write this file. A plain write stands in for it.
    const planted = path.join(dest, "commondir");
    const r = spawnSync(c.shell.shell, ["-c", c.shell.command], { cwd: project, env: { ...c.shell.env, AUTOMODE_COMMAND: `printf '/tmp/elsewhere\\n' > ${planted}` } as NodeJS.ProcessEnv, encoding: "utf8", timeout: 30_000 });
    try {
      assert.equal(r.status, 0, r.stderr);
      assert.ok(fs.existsSync(planted), "the push's sandbox could write it");
      await host.after({ tool: "shell", sessionID: "r4-21-plant", messageID: "m1", id: c.id, status: "completed" });
      assert.equal(fs.existsSync(planted), false);
      const saved = fs.readdirSync(dest).find((n) => n.startsWith("automode-quarantine-commondir-"));
      assert.ok(saved);
      const next = await call(host, "ls", { sessionID: "r4-21-plant" });
      assert.equal(next.permission.effect, "ask");
      assert.ok(next.permission.message.includes(planted) && next.permission.message.includes(saved), next.permission.message);
    } finally {
      fs.rmSync(planted, { force: true });
      for (const n of fs.readdirSync(dest)) if (n.startsWith("automode-quarantine-")) fs.rmSync(path.join(dest, n));
    }
  });

  test("r4 21: a push to a repository outside the project, the allowed paths and the temp directories asks, naming it", async () => {
    const outside = path.join(home, "r4-21-outside.git");
    execFileSync("git", ["init", "-q", "--bare", outside]);
    g("remote", "add", "r4outside", outside);
    try {
      const host = await start({ useClassifier: false, rules: { allow: ["git push r4outside *"] } });
      const { permission, shell } = await call(host, "git push r4outside HEAD:refs/heads/pushed", { sessionID: "r4-21-outside" });
      assert.equal(permission.effect, "ask");
      assert.ok(!wrapped(shell));
      assert.match(permission.message, new RegExp(`the sandbox could not be prepared: the push goes to ${outside} on this machine.*read-only`));
    } finally {
      g("remote", "remove", "r4outside");
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

// Round 4, group C, fifth pass, through the plugin's hooks.
describe("r4 fifth pass: the URL a command names, one walk per root, approvals and resumes", () => {
  const sid = (name: string) => `r4-fifth-${name}`;
  const over = (host: Host, c: { id: string }, sessionID: string) => host.after({ tool: "shell", sessionID, messageID: "m1", id: c.id, status: "completed" });
  const dotGit = path.join(project, ".git");
  const quarantined = () => fs.readdirSync(dotGit).filter((n) => n.startsWith("automode-quarantine-"));
  const resume = () => {
    const file = path.join(stateDir, "resume");
    fs.writeFileSync(file, "");
    touchResume(file);
  };
  afterEach(() => {
    for (const name of ["config.worktree", "commondir", ...quarantined()]) fs.rmSync(path.join(dotGit, name), { force: true });
  });

  test("r4 12: an ssh URL on the command line asks, and the prompt says it is the agent", async () => {
    const host = await start({ useClassifier: false });
    const { permission, shell } = await call(host, "git ls-remote git@host.invalid:o/r.git", { sessionID: sid("ssh-url") });
    assert.equal(permission.effect, "ask");
    assert.ok(!wrapped(shell));
    assert.match(permission.message, /cannot work in the sandbox: git would need your ssh agent/);
    // An https URL with no helper for it runs sandboxed, without the agent.
    const plain = await call(host, "git ls-remote https://example.invalid/o/r.git", { sessionID: sid("ssh-url") });
    assert.equal(plain.permission.effect, "allow", plain.permission.message);
    assert.ok(wrapped(plain.shell));
  });

  test("r4 30: with an allowed path inside the project, an allowed shell call walks each root once", async () => {
    const nested = path.join(project, "vendor-allowed");
    fs.mkdirSync(nested, { recursive: true });
    try {
      const host = await start({ useClassifier: false, allowedPaths: [nested] });
      await call(host, "ls", { sessionID: sid("walks") }); // the session's first call takes the snapshot
      walkCount.clear();
      const { permission, shell } = await call(host, "ls", { sessionID: sid("walks") });
      assert.equal(permission.effect, "allow", permission.message);
      assert.ok(wrapped(shell));
      assert.ok(list(shell.env, "AUTOMODE_RW").includes(nested));
      const counts = Object.fromEntries(walkCount);
      assert.equal(counts[project], 1, JSON.stringify(counts));
      assert.equal(counts[nested], 1, JSON.stringify(counts));
      for (const [root, n] of Object.entries(counts)) assert.equal(n, 1, `${root} walked ${n} times`);
      // An edit, too.
      walkCount.clear();
      const permissionEdit: any = { sessionID: sid("walks-edit"), action: "edit", resources: ["src/a.ts"], effect: "allow" };
      await host.permission(permissionEdit);
      assert.equal(permissionEdit.effect, "allow");
      for (const [root, n] of walkCount) assert.equal(n, 1, `edit: ${root} walked ${n} times`);
    } finally {
      fs.rmSync(nested, { recursive: true, force: true });
    }
  });

  test("r4 21: an approval seen only when its call completes closes with it: the next git-only calls do not ask", async () => {
    const host = await start({ useClassifier: false });
    const asked = await call(host, "git sparse-checkout set src", { sessionID: sid("sparse") });
    assert.equal(asked.permission.effect, "ask");
    // The user approved and the command ran; no reply event reached the plugin before the hook.
    fs.writeFileSync(path.join(dotGit, "config.worktree"), "[core]\n\tsparseCheckout = true\n");
    await over(host, asked, sid("sparse"));
    for (const command of ["git status", "git diff", "ls"]) {
      const next = await call(host, command, { sessionID: sid("sparse") });
      assert.equal(next.permission.effect, "allow", `${command}: ${next.permission.message}`);
      await over(host, next, sid("sparse"));
    }
    assert.ok(fs.existsSync(path.join(dotGit, "config.worktree")), "what the approved command wrote is left");
  });

  test("r4 21: a quarantined commondir the user puts back and resumes with is named as it is once, and then stays accepted", async () => {
    const host = await start({ useClassifier: false });
    const c = await call(host, "git status", { sessionID: sid("restore") });
    assert.equal(c.permission.effect, "allow", c.permission.message);
    const file = path.join(dotGit, "commondir");
    fs.writeFileSync(file, ".\n");
    await over(host, c, sid("restore"));
    assert.equal(fs.existsSync(file), false, "renamed when the call completed");
    const [aside] = quarantined();
    assert.ok(aside);
    assert.equal((await call(host, "ls", { sessionID: sid("restore") })).permission.effect, "ask");
    // The user looks, decides it is theirs, puts it back and resumes.
    fs.renameSync(path.join(dotGit, aside), file);
    resume();
    // The pause named the path as it was then, moved away. What is there at the resume was not
    // shown as it is: it is named once more, and the next resume takes it in (seventh pass).
    const again = await call(host, "ls", { sessionID: sid("restore") });
    assert.equal(again.permission.effect, "ask");
    assert.match(again.permission.message, /\.git\/commondir appeared/);
    assert.ok(fs.existsSync(file), "the file the user put back was renamed again");
    resume();
    for (const command of ["ls", "git status", "git diff", "ls"]) {
      const next = await call(host, command, { sessionID: sid("restore") });
      assert.equal(next.permission.effect, "allow", `${command}: ${next.permission.message}`);
      await over(host, next, sid("restore"));
      assert.ok(fs.existsSync(file), `${command}: the file the user put back was renamed again`);
    }
  });
});

describe("r4 sixth pass: a local push with a hook, push hooks under a relative hooks path, a resume, what a shell inherits, a command too long for the wrapper", () => {
  const sid = (name: string) => `r4-sixth-${name}`;
  const over = (host: Host, c: { id: string }, sessionID: string) => host.after({ tool: "shell", sessionID, messageID: "m1", id: c.id, status: "completed" });
  const g = (...args: string[]) => execFileSync("git", ["-C", project, ...args], { stdio: ["ignore", "pipe", "pipe"] });
  const dotGit = path.join(project, ".git");
  const quarantined = () => fs.readdirSync(dotGit).filter((n) => n.startsWith("automode-quarantine-"));
  const resume = () => {
    const file = path.join(stateDir, "resume");
    fs.writeFileSync(file, "");
    touchResume(file);
  };
  afterEach(() => {
    for (const name of ["commondir", ".husky", ...quarantined()]) fs.rmSync(path.join(dotGit, name), { recursive: true, force: true });
  });

  test("r4 25: a push to a repository on this machine that has a receive-side hook asks, and says which hook", async () => {
    const dest = path.join(tmp, "r4-sixth-dest.git");
    execFileSync("git", ["init", "-q", "--bare", dest]);
    g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "to push");
    g("remote", "add", "r6local", dest);
    try {
      // Your own allow rule: the rules ask about every push otherwise.
      const host = await start({ useClassifier: false, rules: { allow: ["git push r6local *"] } });
      const plain = await call(host, "git push r6local HEAD:refs/heads/one", { sessionID: sid("push") });
      assert.equal(plain.permission.effect, "allow", plain.permission.message);
      assert.ok(wrapped(plain.shell));
      // A path on this machine: no agent, whatever the session's remotes were.
      assert.ok(list(plain.shell.env, "AUTOMODE_HIDE").includes(path.join(home, ".ssh")), "~/.ssh is hidden whole");
      fs.writeFileSync(path.join(dest, "hooks", "post-receive"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      const hooked = await call(host, "git push r6local HEAD:refs/heads/two", { sessionID: sid("push") });
      assert.equal(hooked.permission.effect, "ask");
      assert.ok(!wrapped(hooked.shell));
      assert.match(hooked.permission.message, /has a post-receive hook .*it would run inside this call's sandbox.*an approved run happens outside the sandbox/);
    } finally {
      g("remote", "remove", "r6local");
      fs.rmSync(dest, { recursive: true, force: true });
    }
  });

  test("r4 21: what a git-only call leaves where a push would run hooks from is renamed when it completes, and the session pauses", async () => {
    // What husky sets.
    fs.mkdirSync(path.join(project, ".husky", "_"), { recursive: true });
    g("config", "core.hooksPath", ".husky/_");
    try {
      const host = await start({ useClassifier: false });
      const c = await call(host, "git status", { sessionID: sid("hooks") });
      assert.equal(c.permission.effect, "allow", c.permission.message);
      assert.equal(fs.existsSync(path.join(dotGit, ".husky")), false, "the plan made the hook manager's directory inside .git");
      // While the call runs: what a hook inside it could write into the writable `.git`.
      fs.mkdirSync(path.join(dotGit, ".husky", "_"), { recursive: true });
      fs.writeFileSync(path.join(dotGit, ".husky", "_", "pre-receive"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
      await over(host, c, sid("hooks"));
      assert.equal(fs.existsSync(path.join(dotGit, ".husky")), false, "renamed when the call completed");
      assert.equal(quarantined().filter((n) => n.startsWith("automode-quarantine-hooks-")).length, 1);
      const next = await call(host, "ls", { sessionID: sid("hooks") });
      assert.equal(next.permission.effect, "ask");
      assert.match(next.permission.message, /\.git\/\.husky appeared \(a push into the repository would run hooks from it\) and was moved to /);
    } finally {
      g("config", "--unset", "core.hooksPath");
      fs.rmSync(path.join(project, ".husky"), { recursive: true, force: true });
    }
  });

  test("r4 21: a resume names what else appeared while the session was paused; a second resume takes it in", async () => {
    const host = await start({ useClassifier: false });
    const planted = path.join(project, "r4-sixth-planted");
    assert.equal((await call(host, "ls", { sessionID: sid("resume") })).permission.effect, "allow");
    execFileSync("git", ["init", "-q", planted]);
    try {
      const paused = await call(host, "ls", { sessionID: sid("resume") });
      assert.equal(paused.permission.effect, "ask");
      assert.match(paused.permission.message, /r4-sixth-planted\/\.git appeared/);
      // While it is paused: something no prompt has shown.
      fs.writeFileSync(path.join(dotGit, "commondir"), ".\n");
      resume();
      const again = await call(host, "ls", { sessionID: sid("resume") });
      assert.equal(again.permission.effect, "ask", "the resume took in a commondir nobody was shown");
      assert.match(again.permission.message, /\.git\/commondir appeared/);
      assert.doesNotMatch(again.permission.message, /r4-sixth-planted/);
      assert.equal((await call(host, "ls", { sessionID: sid("resume") })).permission.effect, "ask", "paused until resumed again");
      await new Promise((r) => setTimeout(r, 10));
      resume();
      for (const command of ["ls", "git status"]) {
        const next = await call(host, command, { sessionID: sid("resume") });
        assert.equal(next.permission.effect, "allow", `${command}: ${next.permission.message}`);
        await over(host, next, sid("resume"));
      }
    } finally {
      fs.rmSync(planted, { recursive: true, force: true });
    }
  });

  // bash's own variables that change how it reads a command, with values a user may have.
  const own = { BASH_ENV: path.join(home, ".bash_env"), ENV: path.join(home, ".shrc"), CDPATH: path.join(home, "src"), SHELLOPTS: "noglob", BASHOPTS: "dotglob", GLOBIGNORE: "x", POSIXLY_CORRECT: "1", BASH_COMPAT: "3.2", EXECIGNORE: "/usr/bin/*", PROMPT_COMMAND: "x", IFS: ":" };
  const none = (env: Record<string, string | undefined>, label: string) => {
    for (const name of Object.keys(own)) assert.equal(env[name], undefined, `${label}: ${name}`);
    assert.equal(env.LANG, "C.UTF-8", `${label}: the rest of the environment is as it was`);
  };

  test("r4 29: a sandboxed shell is handed none of bash's own variables, and the wrapper is told to keep none", async () => {
    const { shell, permission } = await call(await start(), "ls", { env: own, sessionID: sid("env") });
    assert.equal(permission.effect, "allow", permission.message);
    assert.ok(wrapped(shell));
    none(shell.env, "sandboxed");
    for (const name of Object.keys(own)) assert.ok(!list(shell.env, "AUTOMODE_ENV_KEEP").includes(name), name);
  });

  test("r4 29: with the sandbox off, the shell of an allowed command is handed none of them", async () => {
    const { shell, permission } = await call(await start({ sandbox: false }), "ls", { env: own, sessionID: sid("env-off") });
    assert.equal(permission.effect, "allow", permission.message);
    assert.equal(shell.shell, "/bin/bash", "no wrapper");
    none(shell.env, "sandbox off");
  });

  test("r4 29: the shell of a command that asks is handed none of them either", async () => {
    for (const sandbox of [true, false]) {
      const { shell, permission } = await call(await start({ sandbox, useClassifier: false }), "git push", { env: own, sessionID: sid(`env-ask-${sandbox}`) });
      assert.equal(permission.effect, "ask");
      assert.equal(shell.shell, "/bin/bash");
      none(shell.env, `asks, sandbox ${sandbox}`);
    }
  });

  test("r4 29: one that sandboxKeepEnv names stays, with the sandbox on or off", async () => {
    for (const sandbox of [true, false]) {
      const { shell, permission } = await call(await start({ sandbox, sandboxKeepEnv: ["BASH_ENV"] }), "ls", { env: own, sessionID: sid(`env-keep-${sandbox}`) });
      assert.equal(permission.effect, "allow", permission.message);
      assert.equal(shell.env.BASH_ENV, own.BASH_ENV, `sandbox ${sandbox}`);
      assert.equal(shell.env.CDPATH, undefined, `sandbox ${sandbox}`);
      if (sandbox) assert.ok(list(shell.env, "AUTOMODE_ENV_KEEP").includes("BASH_ENV") && !list(shell.env, "AUTOMODE_ENV_KEEP").includes("CDPATH"));
    }
  });

  // The seam of group B's seventh pass with this file (B7-10, C8-3): the checks read CDPATH for a
  // relative `cd` only where the shell is handed it, and the plugin tells the guard which of
  // bash's own variables its shells keep. With CDPATH in opencode's own environment a relative
  // `cd` is still followed, because the shell hook takes the variable out; where
  // `sandboxKeepEnv` names it, the shell has it and where `cd src` leads cannot be told.
  test("r4 B7-10: a relative cd is followed although opencode's environment holds CDPATH, unless sandboxKeepEnv hands it to the shell", async () => {
    const guardModule = await import("../guard.ts");
    fs.mkdirSync(path.join(project, "src"), { recursive: true });
    const plain = await call(await start(), "cd src && ls", { sessionID: sid("cdpath-plain") });
    assert.equal(plain.permission.effect, "allow", `without CDPATH anywhere: ${plain.permission.message}`);
    const before = process.env.CDPATH;
    process.env.CDPATH = path.join(home, "elsewhere");
    guardModule.shellKeeps(undefined);
    try {
      const followed = await call(await start(), "cd src && ls", { sessionID: sid("cdpath") });
      assert.equal(followed.permission.effect, "allow", followed.permission.message);
      const kept = await call(await start({ sandboxKeepEnv: ["CDPATH"], useClassifier: false }), "cd src && ls", { sessionID: sid("cdpath-kept") });
      assert.notEqual(kept.permission.effect, "allow", "the shell has CDPATH: where cd src leads cannot be told");
      // One guard serves every plugin instance of the process: what one of them hands its
      // shells counts for all of them from then on.
      const after = await call(await start({ useClassifier: false }), "cd src && ls", { sessionID: sid("cdpath-after") });
      assert.notEqual(after.permission.effect, "allow", "an instance that keeps CDPATH was started in this process");
    } finally {
      if (before === undefined) delete process.env.CDPATH;
      else process.env.CDPATH = before;
      guardModule.shellKeeps(undefined);
    }
  });

  // Ninth pass (the reading of the eighth, F4): the guard reads this process's CDPATH, and
  // opencode builds a shell's environment from its session's. Where `sandboxKeepEnv` names the
  // variable the shell keeps its own, and a call that holds a `cd` is not run as decided when
  // the two differ, whichever of them has one.
  test("r4 21: a shell whose CDPATH is not the one the checks read (set, unset or another value) does not run a cd as decided: it asks, saying why", async () => {
    const guardModule = await import("../guard.ts");
    fs.mkdirSync(path.join(project, "src"), { recursive: true });
    const elsewhere = path.join(home, "elsewhere");
    const before = process.env.CDPATH;
    guardModule.shellKeeps(undefined);
    const cases: { own: string | undefined; shell: string | undefined; command: string; says: RegExp }[] = [
      // The session has one, opencode has none: the checks followed `./src`.
      { own: undefined, shell: elsewhere, command: "cd src && ls", says: /its shell has CDPATH=\S*elsewhere and opencode's own environment has none/ },
      { own: undefined, shell: elsewhere, command: "ls && cd src && ls", says: /its shell has CDPATH=/ },
      // opencode has one, the session has none or another: the checks did not follow the plain
      // word, and what they did follow is not what this shell would do either way.
      { own: elsewhere, shell: undefined, command: "cd ./src && ls", says: /its shell has no CDPATH and opencode's own environment has \S*elsewhere/ },
      { own: elsewhere, shell: path.join(home, "third"), command: "cd ./src && ls", says: /its shell has CDPATH=\S*third and opencode's own environment has \S*elsewhere/ },
    ];
    try {
      for (const sandbox of [true, false]) {
        for (const [n, c] of cases.entries()) {
          if (c.own === undefined) delete process.env.CDPATH;
          else process.env.CDPATH = c.own;
          const host = await start({ sandbox, sandboxKeepEnv: ["CDPATH"], useClassifier: false });
          const { shell, permission } = await call(host, c.command, { env: { CDPATH: c.shell }, sessionID: sid(`cdpath-shell-${sandbox}-${n}`) });
          assert.equal(permission.effect, "ask", `sandbox ${sandbox}: ${c.command} (${c.own} / ${c.shell})`);
          assert.match(permission.message, /would be allowed/, c.command);
          assert.match(permission.message, c.says, c.command);
          assert.ok(!wrapped(shell), `${c.command} is left unwrapped`);
          assert.equal(shell.command, c.command, "the shell's command is left as it is");
          assert.equal(shell.env.CDPATH, c.shell, "the variable is the session's own, and stays");
          // A call with no cd in it is none of its business: `git -C` is a chdir.
          for (const other of ["ls", "git -C src status"]) {
            const plain = await call(host, other, { env: { CDPATH: c.shell }, sessionID: sid(`cdpath-shell-${sandbox}-${n}`) });
            assert.equal(plain.permission.effect, "allow", `sandbox ${sandbox}: ${other}: ${plain.permission.message}`);
          }
          // The same value on both sides is judged as it is (with one, a plain word is not followed).
          const same = await call(host, "cd ./src && ls", { env: { CDPATH: c.own }, sessionID: sid(`cdpath-shell-${sandbox}-${n}`) });
          assert.equal(same.permission.effect, "allow", `sandbox ${sandbox}, the same on both sides: ${same.permission.message}`);
          await host.stop();
          guardModule.shellKeeps(undefined);
        }
        // An instance that does not keep it, in a process where another does (one guard serves
        // both, and reads this process's CDPATH from then on): its shell has none, the checks
        // took it to have one and followed less, and its call stands as before.
        process.env.CDPATH = elsewhere;
        await start({ sandbox, sandboxKeepEnv: ["CDPATH"], useClassifier: false });
        const beside = await call(await start({ sandbox, useClassifier: false }), "cd ./src && ls", { env: { CDPATH: elsewhere }, sessionID: sid(`cdpath-shell-beside-${sandbox}`) });
        assert.equal(beside.permission.effect, "allow", `sandbox ${sandbox}: ${beside.permission.message}`);
        assert.equal(beside.shell.env.CDPATH, undefined);
        for (const h of hosts.splice(0)) await h.stop();
        guardModule.shellKeeps(undefined);
        // Not named in sandboxKeepEnv, the shell's is taken out, and the two agree as before.
        delete process.env.CDPATH;
        const host = await start({ sandbox, useClassifier: false });
        const taken = await call(host, "cd src && ls", { env: { CDPATH: elsewhere }, sessionID: sid(`cdpath-shell-out-${sandbox}`) });
        assert.equal(taken.permission.effect, "allow", `sandbox ${sandbox}: ${taken.permission.message}`);
        assert.equal(taken.shell.env.CDPATH, undefined);
        await host.stop();
        guardModule.shellKeeps(undefined);
      }
    } finally {
      if (before === undefined) delete process.env.CDPATH;
      else process.env.CDPATH = before;
      guardModule.shellKeeps(undefined);
    }
  });

  test("r4 29: enabled: false leaves a shell's environment as it is", async () => {
    const { shell } = await call(await start({ enabled: false }), "ls", { env: own, sessionID: sid("env-disabled") });
    for (const [name, value] of Object.entries(own)) assert.equal(shell.env[name], value, name);
  });

  // The printed text is capped well below the kernel's 128 KiB for one string (canon.ts, group
  // D), so the wrapper is never handed a command it could not be started with: pinned here.
  test("r4 24: a command too long to hand over in one string asks, and its shell is left alone", async () => {
    const command = `echo ${"x".repeat(128 * 1024)}`;
    const { shell, permission } = await call(await start({ useClassifier: false }), command, { sessionID: sid("long") });
    assert.equal(permission.effect, "ask");
    assert.ok(!wrapped(shell));
    assert.equal(shell.env.AUTOMODE_COMMAND, undefined);
    assert.match(permission.message, /a command too long to hand to the shell in one piece/);
    // One that fits runs sandboxed, as before.
    const fits = await call(await start({ useClassifier: false }), `echo ${"x".repeat(90_000)}`, { sessionID: sid("fits") });
    assert.equal(fits.permission.effect, "allow", fits.permission.message);
    assert.ok(wrapped(fits.shell));
    assert.ok(Buffer.byteLength(`AUTOMODE_COMMAND=${fits.shell.env.AUTOMODE_COMMAND}\0`) < 128 * 1024);
  });

  test("r4 24: more kept variable names than one environment string holds asks too", async () => {
    const env = Object.fromEntries(Array.from({ length: 20_000 }, (_, i) => [`V${String(i).padStart(6, "0")}`, "1"]));
    const { shell, permission } = await call(await start(), "ls", { env, sessionID: sid("names") });
    assert.equal(permission.effect, "ask");
    assert.ok(!wrapped(shell));
    assert.match(permission.message, /would be allowed .*AUTOMODE_ENV_KEEP exceeds the kernel environment string limit/);
  });
  // ---- seventh pass: git's own variables in the environment a shell inherits (finding 21) ----

  // Variables that make git work in another repository, or with another configuration, than the
  // one the checks read (their own lookups go to the repository in the command's directory).
  const redirecting: Record<string, string>[] = [
    { GIT_DIR: "/somewhere/else/.git" },
    { GIT_WORK_TREE: "/somewhere/else" },
    { GIT_INDEX_FILE: "/somewhere/else/index" },
    { GIT_COMMON_DIR: "/somewhere/else/.git" },
    { GIT_OBJECT_DIRECTORY: "/somewhere/else/objects" },
    { GIT_ALTERNATE_OBJECT_DIRECTORIES: "/somewhere/else/objects" },
    { GIT_NAMESPACE: "other" },
    { GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "core.fsmonitor", GIT_CONFIG_VALUE_0: "x" },
    { GIT_CONFIG_PARAMETERS: "'core.fsmonitor'='x'" },
    { GIT_EXEC_PATH: "/somewhere/else/libexec" },
    { GIT_CONFIG_GLOBAL: "/somewhere/else/gitconfig" },
    { GIT_CONFIG_SYSTEM: "/somewhere/else/gitconfig" },
    { GIT_CEILING_DIRECTORIES: "/somewhere" },
  ];

  test("r4 21: a call that holds a git command asks where its shell inherits a variable that points git elsewhere, and says which", async () => {
    for (const [n, env] of redirecting.entries()) {
      const name = Object.keys(env)[0];
      for (const sandbox of [true, false]) {
        const host = await start({ sandbox, useClassifier: false });
        for (const command of ["git status", "git log --oneline -3 | head -2", "ls && git diff --stat"]) {
          const { shell, permission } = await call(host, command, { env, sessionID: sid(`gitenv-${n}-${sandbox}`) });
          assert.equal(permission.effect, "ask", `${name}, sandbox ${sandbox}: ${command}`);
          assert.match(permission.message, new RegExp(`would be allowed .*its shell inherits ${name}\\b`), `${name}: ${command}`);
          assert.ok(!wrapped(shell), `${name}: ${command} is left unwrapped`);
          assert.equal(shell.command, command, `${name}: the shell's command is left as it is`);
          // The user's own setting: it is not dropped.
          for (const [key, value] of Object.entries(env)) assert.equal(shell.env[key], value, `${name}: ${key} stays in the shell`);
        }
        // A call with no git command is none of its business.
        const other = await call(host, "ls", { env, sessionID: sid(`gitenv-${n}-${sandbox}`) });
        assert.equal(other.permission.effect, "allow", `${name}, sandbox ${sandbox}: ${other.permission.message}`);
      }
    }
  });

  test("r4 21: a config variable the plugin's own git reads with the same value is judged as it is: nothing asks", async () => {
    // The plugin's lookups and the shell's git then read the same files.
    const same = Object.fromEntries(["GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM", "GIT_CEILING_DIRECTORIES"].flatMap((name) => (process.env[name] === undefined ? [] : [[name, process.env[name]!]])));
    assert.ok("GIT_CONFIG_GLOBAL" in same, "the test needs the runner's GIT_CONFIG_GLOBAL");
    const { shell, permission } = await call(await start(), "git status", { env: same, sessionID: sid("gitenv-same") });
    assert.equal(permission.effect, "allow", permission.message);
    assert.ok(wrapped(shell));
    // And plain git with none of them, as ever.
    const plain = await call(await start(), "git status", { sessionID: sid("gitenv-none") });
    assert.equal(plain.permission.effect, "allow", plain.permission.message);
  });

  test("r4 21: naming such a variable in sandboxKeepEnv keeps it in the shell and still asks: it cannot be judged as it is", async () => {
    const env = { GIT_DIR: "/somewhere/else/.git" };
    const { shell, permission } = await call(await start({ sandboxKeepEnv: ["GIT_DIR"], useClassifier: false }), "git status", { env, sessionID: sid("gitenv-keep") });
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /its shell inherits GIT_DIR\b.*sandboxKeepEnv/);
    assert.equal(shell.env.GIT_DIR, env.GIT_DIR);
    // With the plugin switched off nothing is looked at.
    const off = await call(await start({ enabled: false }), "git status", { env, sessionID: sid("gitenv-off") });
    assert.equal(off.permission.effect, "allow");
  });

  // ---- seventh pass: what index.ts wires (review lists of tests without force) ----

  test("r4 21: a git-only call's plan is handed to the wrapper with the list of directories made writable again inside a read-only one", async () => {
    const { shell, permission } = await call(await start(), "git status", { sessionID: sid("reopen") });
    assert.equal(permission.effect, "allow", permission.message);
    assert.ok(wrapped(shell));
    assert.equal(typeof shell.env.AUTOMODE_REOPEN, "string", "the wrapper is not told what to reopen");
  });
  test("r4 21: what one session's pause named is named for every session it paused: one touch resumes them all", async () => {
    const host = await start({ useClassifier: false });
    const a = sid("named-a");
    const b = sid("named-b");
    const file = path.join(dotGit, "commondir");
    const c = await call(host, "git status", { sessionID: a });
    assert.equal(c.permission.effect, "allow", c.permission.message);
    assert.equal((await call(host, "ls", { sessionID: b })).permission.effect, "allow");
    // What the call leaves cannot be moved away: the directory is closed to writing by then.
    fs.writeFileSync(file, ".\n");
    fs.chmodSync(dotGit, 0o555);
    try {
      await over(host, c, a);
    } finally {
      fs.chmodSync(dotGit, 0o755);
    }
    assert.ok(fs.existsSync(file), "the fixture: the rename failed");
    for (const sessionID of [a, b]) {
      const paused = await call(host, "ls", { sessionID });
      assert.equal(paused.permission.effect, "ask", sessionID);
      assert.match(paused.permission.message, /\.git\/commondir appeared but could not be moved/, sessionID);
    }
    // The user looks, leaves it, and resumes: it was shown to both sessions as it is.
    resume();
    for (const sessionID of [a, b]) {
      const next = await call(host, "ls", { sessionID });
      assert.equal(next.permission.effect, "allow", `${sessionID}: ${next.permission.message}`);
    }
  });

  test("r4 21: what the pause named goes to every session with what it held: rewritten before the touch, it is named again for each", async () => {
    // No resume file left ahead of the clock by a test before this one.
    fs.rmSync(path.join(stateDir, "resume"), { force: true });
    const host = await start({ useClassifier: false });
    const a = sid("held-a");
    const b = sid("held-b");
    const file = path.join(dotGit, "commondir");
    const c = await call(host, "git status", { sessionID: a });
    assert.equal(c.permission.effect, "allow", c.permission.message);
    assert.equal((await call(host, "ls", { sessionID: b })).permission.effect, "allow");
    fs.writeFileSync(file, ".\n");
    fs.chmodSync(dotGit, 0o555);
    try {
      await over(host, c, a);
    } finally {
      fs.chmodSync(dotGit, 0o755);
    }
    assert.ok(fs.existsSync(file), "the fixture: the rename failed");
    for (const sessionID of [a, b]) assert.equal((await call(host, "ls", { sessionID })).permission.effect, "ask", sessionID);
    // Between the pause and the touch the file is given other contents (the same directory,
    // spelled another way, so that git in the project still works): nobody was shown that.
    fs.writeFileSync(file, "./\n");
    resume();
    for (const sessionID of [a, b]) {
      const again = await call(host, "ls", { sessionID });
      assert.equal(again.permission.effect, "ask", `${sessionID}: resumed with a commondir that was not the one shown`);
      assert.match(again.permission.message, /\.git\/commondir appeared/, sessionID);
    }
    // Shown as it is now, and resumed with a later touch: taken in by both.
    const touched = path.join(stateDir, "resume");
    fs.utimesSync(touched, new Date(Date.now() + 10_000), new Date(Date.now() + 10_000));
    for (const sessionID of [a, b]) {
      const next = await call(host, "ls", { sessionID });
      assert.equal(next.permission.effect, "allow", `${sessionID}: ${next.permission.message}`);
    }
    fs.rmSync(touched, { force: true });
  });

  test("r4 21: a git command that only reads a repository outside the writable directories runs; one that writes it asks", async () => {
    const outside = fs.mkdtempSync(path.join(home, "r4-seventh-outside-"));
    try {
      execFileSync("git", ["init", "-q", outside]);
      execFileSync("git", ["-C", outside, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "one"]);
      // Your own allow rules: the rules ask about git in a repository outside the project.
      const host = await start({ useClassifier: false, rules: { allow: [`git -C ${outside} *`] } });
      const reads = await call(host, `git -C ${outside} log --oneline -1`, { sessionID: sid("outside") });
      assert.equal(reads.permission.effect, "allow", reads.permission.message);
      assert.ok(wrapped(reads.shell));
      const writes = await call(host, `git -C ${outside} commit --allow-empty -m two`, { sessionID: sid("outside") });
      assert.equal(writes.permission.effect, "ask");
      assert.match(writes.permission.message, /would write a git directory that lies outside the project/);
    } finally {
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });

  // ---- eighth pass ----

  test("r4 21: a call that holds a git command asks where its shell lacks a variable the plugin's own git reads its configuration by, and says which", async () => {
    // The runner sets both for this process (test/run.mjs); a session whose environment is not
    // the plugin's own (opencode hands the shell the session's) may have neither.
    for (const name of ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM"]) {
      assert.ok(process.env[name] !== undefined, `the test needs the runner's ${name}`);
      for (const sandbox of [true, false]) {
        const host = await start({ sandbox, useClassifier: false });
        for (const command of ["git status", "ls && git diff --stat"]) {
          const { shell, permission } = await call(host, command, { env: { [name]: undefined }, sessionID: sid(`gitenv-lacks-${name}-${sandbox}`) });
          assert.equal(permission.effect, "ask", `${name}, sandbox ${sandbox}: ${command}`);
          assert.match(permission.message, new RegExp(`would be allowed .*its shell does not inherit ${name}\\b`), `${name}: ${command}`);
          assert.ok(!wrapped(shell), `${name}: ${command} is left unwrapped`);
          assert.equal(shell.command, command, `${name}: the shell's command is left as it is`);
        }
        // A call with no git command is none of its business.
        const other = await call(host, "ls", { env: { [name]: undefined }, sessionID: sid(`gitenv-lacks-${name}-${sandbox}`) });
        assert.equal(other.permission.effect, "allow", `${name}, sandbox ${sandbox}: ${other.permission.message}`);
      }
    }
    // A shell that has all of them as the plugin has them is judged as it is.
    const same = await call(await start(), "git status", { sessionID: sid("gitenv-all") });
    assert.equal(same.permission.effect, "allow", same.permission.message);
    assert.ok(wrapped(same.shell));
  });

  test("r4 21: GIT_NO_REPLACE_OBJECTS in the shell alone changes which commit a ref names: a git call asks, and names it", async () => {
    const { shell, permission } = await call(await start({ useClassifier: false }), "git log --oneline -1", { env: { GIT_NO_REPLACE_OBJECTS: "1" }, sessionID: sid("gitenv-replace") });
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /its shell inherits GIT_NO_REPLACE_OBJECTS\b/);
    assert.ok(!wrapped(shell));
    assert.equal(shell.env.GIT_NO_REPLACE_OBJECTS, "1");
  });

  test("r4 21: the directories a plan makes writable again reach the wrapper from the plugin: a call in a submodule writes its module, and nothing around it", async () => {
    const upstream = path.join(tmp, "r4-eighth-upstream");
    const module = path.join(dotGit, "modules", "r8lib");
    execFileSync("git", ["init", "-q", "-b", "main", upstream]);
    execFileSync("git", ["-C", upstream, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "one"]);
    execFileSync("git", ["-C", project, "-c", "protocol.file.allow=always", "submodule", "add", "-q", upstream, "r8lib"], { stdio: ["ignore", "pipe", "pipe"] });
    try {
      assert.ok(fs.existsSync(path.join(module, "HEAD")), "the fixture: the module is kept under .git/modules");
      const { shell, permission } = await call(await start(), "git -C r8lib status --short", { sessionID: sid("reopen-module") });
      assert.equal(permission.effect, "allow", permission.message);
      assert.ok(wrapped(shell));
      assert.deepEqual(list(shell.env, "AUTOMODE_REOPEN"), [module]);
      assert.ok(list(shell.env, "AUTOMODE_RO").includes(dotGit), "the git directory around the module is read-only whole");
      // Under the wrapper, with what the plugin handed over: the module can be written, the
      // superproject's git directory around it cannot.
      const run = (command: string, env: Record<string, string> = {}) => spawnSync(shell.shell, ["-c", "x"], { cwd: project, env: { ...shell.env, ...env, AUTOMODE_COMMAND: command } as NodeJS.ProcessEnv, encoding: "utf8", timeout: 30_000 });
      const inside = run(`echo probe > ${module}/r8-probe`);
      assert.equal(inside.status, 0, inside.stderr);
      assert.ok(fs.existsSync(path.join(module, "r8-probe")));
      assert.notEqual(run(`echo probe > ${dotGit}/r8-probe`).status, 0);
      assert.equal(fs.existsSync(path.join(dotGit, "r8-probe")), false);
      // Without the list the same write fails: the list is what opens the module.
      assert.notEqual(run(`echo probe > ${module}/r8-probe-2`, { AUTOMODE_REOPEN: "" }).status, 0, "the fixture: the module is closed unless it is made writable again");
    } finally {
      for (const name of ["r8lib", ".gitmodules"]) spawnSync("git", ["-C", project, "rm", "-q", "-f", "--cached", name], { stdio: "ignore" });
      for (const p of [path.join(project, "r8lib"), path.join(project, ".gitmodules"), path.join(dotGit, "modules"), upstream]) fs.rmSync(p, { recursive: true, force: true });
      spawnSync("git", ["-C", project, "config", "--remove-section", "submodule.r8lib"], { stdio: "ignore" });
    }
  });
});

// ---- round 4, group B, eighth pass (B8), what needs the hooks ----
describe("r4 B8 (hooks)", () => {
  const moments = path.join(stateDir, "moments");
  const files = () => {
    fs.writeFileSync(path.join(project, "b8-f"), "x\n");
    execFileSync("tar", ["-cf", "b8.tar", "b8-f"], { cwd: project });
    fs.writeFileSync(path.join(project, "b8.diff"), "--- a/b8-f\n+++ b/b8-f\n@@ -1 +1 @@\n-x\n+y\n");
  };
  const WRITES = ["tar -xf b8.tar", "tar xf b8.tar", "tar --extract -f b8.tar -C .", "unzip b8.zip", "unzip -o b8.zip -d out", "patch -p1 -i b8.diff", "patch -p1 < b8.diff", "git apply b8.diff", "git apply --stat --apply b8.diff", "git am b8.patch", "timeout 5 tar -xf b8.tar", "ls && tar -xf b8.tar"];
  const READS = ["tar -tf b8.tar", "tar -cf b8-new.tar b8-f", "unzip -l b8.zip", "patch --dry-run -p1 -i b8.diff", "git apply --stat b8.diff", "git apply --check b8.diff", "ls", "cat b8.diff"];
  test("r4 B8-9: with the sandbox off, a command that unpacks an archive or applies a patch asks", async () => {
    files();
    // (Council project review 1: one plugin per command, since the sessions of one share the
    // record of what was written.)
    for (const c of WRITES) {
      const host = await start({ sandbox: false, useClassifier: false });
      const { permission } = await call(host, c, { sessionID: `b8-9-${ids}` });
      assert.equal(permission.effect, "ask", c);
      assert.match(permission.message ?? "", /named inside the file and cannot be seen without the sandbox/, c);
    }
    for (const c of READS) {
      const host = await start({ sandbox: false, useClassifier: false });
      const { permission } = await call(host, c, { sessionID: `b8-9-${ids}` });
      assert.equal(permission.effect, "allow", `${c}: ${permission.message}`);
    }
  });
  test("r4 B8-9: with the sandbox on nothing changes: the same commands are allowed, in the sandbox", async () => {
    files();
    // (`git am` writes inside .git, and asks for that with the sandbox on, as before. One plugin
    // per command, as with the sandbox off.)
    for (const c of [...WRITES.filter((w) => !w.startsWith("git am")), ...READS]) {
      const host = await start({ useClassifier: false });
      const { permission, shell } = await call(host, c, { sessionID: `b8-9on-${ids}` });
      assert.equal(permission.effect, "allow", `${c}: ${permission.message}`);
      assert.ok(wrapped(shell), c);
    }
  });
  test("r4 B8-5c: the plugin keeps, per session, the moment it was first seen at, and a restart measures from it", async () => {
    const git = (...args: string[]) => execFileSync("git", ["-C", project, "-c", "user.name=t", "-c", "user.email=t@t", ...args], { stdio: ["ignore", "pipe", "pipe"] });
    fs.mkdirSync(path.join(project, "b8s"), { recursive: true });
    const script = path.join(project, "b8s", "tidy.sh");
    const old = path.join(project, "b8s", "old.sh");
    for (const f of [script, old]) fs.writeFileSync(f, "#!/bin/sh\necho old\n", { mode: 0o755 });
    git("add", "b8s");
    git("commit", "-qm", "two scripts");
    try {
      let host = await start({ useClassifier: false });
      // The session is seen for the first time, then changes a script (the user approved it, say).
      assert.equal((await call(host, "ls", { sessionID: "b8-restart" })).permission.effect, "allow");
      const kept = fs.readdirSync(moments);
      assert.equal(kept.length, 1);
      assert.equal(fs.statSync(path.join(moments, kept[0])).mode & 0o777, 0o600);
      assert.equal(fs.statSync(moments).mode & 0o777, 0o700);
      await new Promise((r) => setTimeout(r, 20));
      fs.writeFileSync(script, "#!/bin/sh\necho new\n", { mode: 0o755 });
      // opencode is restarted: another instance of the plugin, the same session.
      await host.stop();
      host = await start({ useClassifier: false });
      const again = await call(host, "sh b8s/tidy.sh", { sessionID: "b8-restart" });
      assert.equal(again.permission.effect, "ask");
      assert.match(again.permission.message ?? "", /changed since this session began|cannot list/);
      // Council project review 1, round 2: a session an earlier process saw counts as having
      // written anywhere in the project (what it wrote then is not in this process's record), so
      // what nobody changed goes to the model too, and so it does for another session (the
      // record is the project's). A session seen for the first time now has a moment of its own.
      const untouched = await call(host, "sh b8s/old.sh", { sessionID: "b8-restart" });
      assert.equal(untouched.permission.effect, "ask", untouched.permission.message);
      assert.match(untouched.permission.message ?? "", /cannot list/);
      const other = await call(host, "sh ./b8s/tidy.sh", { sessionID: "b8-restart-other" });
      assert.equal(other.permission.effect, "ask", other.permission.message);
      assert.deepEqual(fs.readdirSync(moments).length, 2);
    } finally {
      git("rm", "-q", "-r", "-f", "b8s");
      git("commit", "-qm", "scripts gone");
    }
  });
});

describe("r4 B9 (hooks)", () => {
  test("r4 B9-1: with the sandbox off, unzip with a listing letter after the archive or in a -d value asks", async () => {
    fs.writeFileSync(path.join(project, "b9.zip"), "");
    const host = await start({ sandbox: false, useClassifier: false });
    for (const c of ["unzip b9.zip '*' -l", "unzip b9.zip '*' -Z", "unzip b9.zip .git/hooks/pre-commit -t", "unzip b9.zip '*' -x -l", "unzip -o b9.zip -dlib", "unzip -o b9.zip -dtools"]) {
      const { permission } = await call(host, c, { sessionID: `b9-1-${ids}` });
      assert.equal(permission.effect, "ask", c);
      assert.match(permission.message ?? "", /named inside the file and cannot be seen without the sandbox/, c);
    }
    for (const c of ["unzip -l b9.zip", "unzip -lv b9.zip", "unzip -Z b9.zip"]) {
      const { permission } = await call(host, c, { sessionID: `b9-1-${ids}` });
      assert.equal(permission.effect, "allow", `${c}: ${permission.message}`);
    }
  });
});

describe("r4 B10 (hooks)", () => {
  test("r4 B10-3: with the sandbox off, unzip with -P, -O or -I asks: their value is no listing letter", async () => {
    fs.writeFileSync(path.join(project, "b10.zip"), "");
    const host = await start({ sandbox: false, useClassifier: false });
    for (const c of ["unzip -Ptop b10.zip", "unzip -Psecret b10.zip", "unzip -o -Pinfected b10.zip", "unzip -Ocp437 b10.zip", "unzip -Ilatin1 b10.zip", "unzip -Pletmein -d lib b10.zip"]) {
      const { permission } = await call(host, c, { sessionID: `b10-3-${ids}` });
      assert.equal(permission.effect, "ask", c);
      assert.match(permission.message ?? "", /named inside the file and cannot be seen without the sandbox/, c);
    }
    for (const c of ["unzip -l -Ptop b10.zip", "unzip -Ptop -l b10.zip"]) {
      const { permission } = await call(host, c, { sessionID: `b10-3-${ids}` });
      assert.equal(permission.effect, "allow", `${c}: ${permission.message}`);
    }
  });
  // An edit that asks (here: a hook manager's file in the project), approved by the user, is the
  // session's write as an allowed edit is: a script that sources it then goes to the model. The
  // approval is learned from opencode's reply, or from the edit's completion.
  const b10Script = () => {
    const run = path.join(project, "b10-run.sh");
    if (!fs.existsSync(run)) {
      fs.writeFileSync(run, "#!/bin/sh\n. ./.husky/b10.sh\n", { mode: 0o755 });
      execFileSync("git", ["-C", project, "add", "b10-run.sh"]);
      execFileSync("git", ["-C", project, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "b10 script"]);
    }
    return path.join(project, ".husky", "b10.sh");
  };
  const b10Edit = async (host: Host, sessionID: string, id: string, target: string) => {
    const source = { type: "tool", messageID: "m10", id };
    await host.tool({ tool: "edit", sessionID, messageID: "m10", id, input: { filePath: target } });
    const edit: any = { sessionID, action: "edit", resources: [target], source, effect: "allow" };
    await host.permission(edit);
    return { edit, source };
  };
  for (const via of ["reply", "completed"] as const) test(`r4 B10-9: an edit the user approves (${via}) is a session write`, async () => {
    const target = b10Script();
    const host = await start({ useClassifier: false });
    const sessionID = `b10-9-${via}-${++ids}`;
    const id = `edit-${ids}`;
    assert.equal((await call(host, "./b10-run.sh", { sessionID })).permission.effect, "allow", "before the edit");
    const { edit, source } = await b10Edit(host, sessionID, id, target);
    assert.equal(edit.effect, "ask", edit.message);
    // Asked and not yet approved: as before.
    const waiting = (await call(host, "./b10-run.sh", { sessionID })).permission;
    assert.equal(waiting.effect, "allow", `asked, not approved: ${waiting.message}`);
    if (via === "reply") {
      await host.emit({ type: "permission.asked", data: { id: `per_${id}`, sessionID, action: "edit", resources: [target], source } });
      await host.emit({ type: "permission.replied", data: { sessionID, requestID: `per_${id}`, reply: "once" } });
    } else {
      await host.after({ tool: "edit", sessionID, messageID: "m10", id, status: "completed" });
    }
    const { permission } = await call(host, "./b10-run.sh", { sessionID });
    assert.equal(permission.effect, "ask", permission.message);
    assert.match(permission.message ?? "", /leave this to the model/);
    assert.match(permission.message ?? "", /b10\.sh/);
    // Council project review 1: another session of the project (a subagent's) shares the record.
    assert.equal((await call(host, "./b10-run.sh", { sessionID: `${sessionID}-other` })).permission.effect, "ask");
  });
  test("r4 B10-9: an edit the user rejects is no session write", async () => {
    const target = b10Script();
    const host = await start({ useClassifier: false });
    const sessionID = `b10-9-reject-${++ids}`;
    const id = `edit-${ids}`;
    const { edit, source } = await b10Edit(host, sessionID, id, target);
    assert.equal(edit.effect, "ask");
    await host.emit({ type: "permission.asked", data: { id: `per_${id}`, sessionID, action: "edit", resources: [target], source } });
    await host.emit({ type: "permission.replied", data: { sessionID, requestID: `per_${id}`, reply: "reject" } });
    await host.after({ tool: "edit", sessionID, messageID: "m10", id, status: "error" });
    const after = (await call(host, "./b10-run.sh", { sessionID })).permission;
    assert.equal(after.effect, "allow", after.message);
  });
});

// B10's reading: the checks judge a program's name by opencode's own PATH; a shell whose PATH
// holds an entry the session can write that opencode's does not asks, saying why.
describe("r4 B10 checks: the shell's PATH", () => {
  test("r4 B10 checks: a shell whose PATH holds a project, relative or empty entry opencode's does not asks", async () => {
    const host = await start({ useClassifier: false });
    const own = process.env.PATH ?? "";
    for (const [n, bent] of [`${project}/bin:${own}`, `${own}:./node_modules/.bin`, `${own}:`, `bin:${own}`].entries()) {
      const { permission, shell } = await call(host, "ls", { env: { PATH: bent }, sessionID: `r4-b10c-path-${n}` });
      assert.equal(permission.effect, "ask", `${bent}: ${permission.message}`);
      assert.match(permission.message, /its shell's PATH holds .*opencode's own PATH does not/);
      assert.ok(!wrapped(shell), "left unwrapped");
    }
    // The same PATH, or one that differs only by fixed directories outside the project: as before.
    for (const [n, plain] of [own, `/opt/none:${own}`].entries()) {
      const { permission } = await call(host, "ls", { env: { PATH: plain }, sessionID: `r4-b10c-plain-${n}` });
      assert.equal(permission.effect, "allow", `${plain}: ${permission.message}`);
    }
  });
});

// Council project review 1: a subagent works in a session of its own, on the same project.
describe("council project review 1: one record of what was written for every session", () => {
  test("a session runs what another session wrote: it goes to the model", async () => {
    const host = await start({ useClassifier: false });
    const pkg = path.join(project, "package.json");
    fs.writeFileSync(pkg, '{"name":"x","version":"1.0.0","scripts":{"test":"echo ok"}}\n');
    try {
      const before = await call(host, "npm test", { sessionID: "cp1-before" });
      assert.equal(before.permission.effect, "allow", before.permission.message);
      const wrote = await call(host, "sed -i 's/echo ok/echo changed/' package.json", { sessionID: "cp1-parent" });
      assert.equal(wrote.permission.effect, "allow", wrote.permission.message);
      for (const id of ["cp1-child", "cp1-before"]) {
        const { permission } = await call(host, "npm test", { sessionID: id });
        assert.equal(permission.effect, "ask", id);
        assert.match(permission.message, /package\.json/);
      }
    } finally {
      fs.rmSync(pkg, { force: true });
    }
  });
});

describe("council project review 1, round 2: what the record and the shell's environment carry", () => {
  const g = (...args: string[]) => execFileSync("git", ["-C", project, "-c", "user.name=t", "-c", "user.email=t@t", ...args], { stdio: ["ignore", "pipe", "pipe"] });
  const runShell = (shell: { shell: string; command: string; env: Record<string, string | undefined> }) => spawnSync(shell.shell, ["-c", shell.command], { cwd: project, env: shell.env as NodeJS.ProcessEnv, encoding: "utf8" });
  test("a git work-tree change one session made reaches the record of every session", async () => {
    const here = g("rev-parse", "--abbrev-ref", "HEAD").toString().trim();
    const pkg = path.join(project, "package.json");
    fs.writeFileSync(pkg, '{"scripts":{"test":"echo one"}}\n');
    g("add", "package.json");
    g("commit", "-qm", "cp1 r2 base");
    g("checkout", "-qb", "cp1-r2-other");
    fs.writeFileSync(pkg, '{"scripts":{"test":"echo two"}}\n');
    g("commit", "-qam", "cp1 r2 other");
    g("checkout", "-q", here);
    try {
      const host = await start({ useClassifier: false });
      assert.equal((await call(host, "npm test", { sessionID: "cp1r2-b" })).permission.effect, "allow");
      const sw = await call(host, "git switch cp1-r2-other", { sessionID: "cp1r2-a" });
      assert.equal(sw.permission.effect, "allow", sw.permission.message);
      assert.equal(runShell(sw.shell).status, 0);
      await host.after({ tool: "shell", sessionID: "cp1r2-a", messageID: "m1", id: sw.id, status: "completed" });
      const other = await call(host, "npm test", { sessionID: "cp1r2-b" });
      assert.equal(other.permission.effect, "ask", "the other session");
      assert.match(other.permission.message, /package\.json/);
    } finally {
      g("checkout", "-q", "-f", here);
      g("branch", "-q", "-D", "cp1-r2-other");
      g("rm", "-q", "-f", "package.json");
      g("commit", "-qm", "cp1 r2 cleanup");
    }
  });
  test("a session an earlier process saw counts as having written in the project", async () => {
    let host = await start({ useClassifier: false });
    assert.equal((await call(host, "git status", { sessionID: "cp1r2-restart" })).permission.effect, "allow");
    await host.stop();
    hosts.splice(hosts.indexOf(host), 1);
    host = await start({ useClassifier: false });
    const again = await call(host, "make", { sessionID: "cp1r2-restart" });
    assert.equal(again.permission.effect, "ask");
    assert.match(again.permission.message, /cannot list/);
    assert.equal((await call(host, "git status", { sessionID: "cp1r2-restart" })).permission.effect, "allow", "the safe list as before");
    assert.equal((await call(host, "make", { sessionID: "cp1r2-new" })).permission.effect, "ask", "the record is the project's");
  });
  test("a shell whose LESSOPEN names a place the session can write is not run as decided", async () => {
    const host = await start({ useClassifier: false });
    fs.writeFileSync(path.join(project, "cp1-f"), "x\n");
    try {
      const plain = await call(host, "less cp1-f", { sessionID: "cp1r2-less" });
      assert.equal(plain.permission.effect, "allow", plain.permission.message);
      for (const env of [{ LESSOPEN: "|./lp %s" }, { GIT_EXTERNAL_DIFF: "./differ" }, { EDITOR: `${project}/e` }]) {
        const { permission } = await call(host, "less cp1-f", { sessionID: "cp1r2-less", env });
        assert.equal(permission.effect, "ask", JSON.stringify(env));
        assert.match(permission.message, /names a place the session can write/);
      }
      assert.equal((await call(host, "less cp1-f", { sessionID: "cp1r2-less", env: { EDITOR: "vi", LESSOPEN: "| /usr/bin/lesspipe %s" } })).permission.effect, "allow");
    } finally {
      fs.rmSync(path.join(project, "cp1-f"), { force: true });
    }
  });
  test("a folded heredoc cat asks where the shell's PATH finds no cat", async () => {
    const host = await start({ useClassifier: false });
    const command = `printf '<%s>\\n' "$(cat <<'EOF'\nhello\nEOF\n)"`;
    assert.equal((await call(host, command, { sessionID: "cp1r2-cat" })).permission.effect, "allow");
    const empty = path.join(os.homedir(), "cp1-no-cat");
    fs.mkdirSync(empty, { recursive: true });
    const { permission } = await call(host, command, { sessionID: "cp1r2-cat", env: { PATH: empty } });
    assert.equal(permission.effect, "ask");
    assert.match(permission.message, /PATH/);
  });
});

describe("council project review 1, round 3: a plant one session made pauses the others", () => {
  test("a git directory a call made pauses every session once the call is over, and a session that starts later", async () => {
    const host = await start({ useClassifier: false });
    const dir = path.join(project, "cp1r3");
    try {
      const plant = await call(host, "mkdir -p cp1r3/objects cp1r3/refs && echo 'ref: refs/heads/main' > cp1r3/HEAD", { sessionID: "cp1r3-sub" });
      assert.equal(plant.permission.effect, "allow", plant.permission.message);
      execFileSync("bash", ["-c", plant.shell.command.startsWith("mkdir") ? plant.shell.command : "mkdir -p cp1r3/objects cp1r3/refs && echo 'ref: refs/heads/main' > cp1r3/HEAD"], { cwd: project });
      await host.after({ tool: "shell", sessionID: "cp1r3-sub", messageID: "m1", id: plant.id, status: "completed" });
      const later = await call(host, "ls", { sessionID: "cp1r3-parent" });
      assert.equal(later.permission.effect, "ask");
      assert.match(later.permission.message, /paused/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
