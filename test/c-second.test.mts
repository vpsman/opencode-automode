// Round 4, group C (trust and protection outside the shell text), second pass: what the first
// review of the group found in the sandbox plan, the session's check of the project's git
// layout and the per-call check for planted git files. Each test builds a repository of its own
// under the throwaway home (not under /tmp, which is tmpfs here and shared).
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-second.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { SessionState, projectRoots, quarantineGitFiles, gitTampered, noteGitCall, closeGitSnapshot, expectedRepos } from "../decide.ts";
import { plan, protectedPaths, limits, discover, type Plan } from "../sandbox.ts";

const options = (r: string) => ({ projectRoots: [r], allowedPaths: [], cacheDirs: [], gitWritable: true, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [], project: r });
// The environment sandbox/bin/bash takes its plan from.
const wrapperEnv = (p: Plan) => ({ ...process.env, AUTOMODE_SHELL: "/bin/bash", AUTOMODE_RW: p.rw.join("\n"), AUTOMODE_RO: p.ro.join("\n"), AUTOMODE_REOPEN: p.reopen.join("\n"), AUTOMODE_PIN: p.pin.join("\n"), AUTOMODE_HIDE: p.hide.join("\n"), AUTOMODE_TMPFS: p.tmpfs.join("\n") });
// A repository with one commit, removed afterwards; `g` runs git in it.
function fixture(fn: (r: string, g: (...a: string[]) => string) => void) {
  const r = fs.mkdtempSync(path.join(os.homedir(), "c-second-"));
  const g = (...a: string[]) => execFileSync("git", ["-C", r, ...a], { encoding: "utf8" });
  try {
    g("init", "-q");
    g("commit", "--allow-empty", "-qm", "one");
    fn(r, g);
  } finally {
    fs.rmSync(r, { recursive: true, force: true });
  }
}

for (const pointer of [true, false]) test(`r4 21: ${pointer ? "a .git pointer file whose target is gone" : "an empty directory named .git"} does not stop ordinary work`, () => fixture((r) => {
  const p = path.join(r, "vendor/stale/.git");
  fs.mkdirSync(path.dirname(p), { recursive: true });
  if (pointer) fs.writeFileSync(p, "gitdir: ../../.git/modules/gone\n");
  else fs.mkdirSync(p);
  const s = new SessionState(r);
  projectRoots(s);
  assert.equal(gitTampered(s), undefined);
  assert.equal(plan(options(r)).problem, undefined);
  if (!pointer) assert.ok(plan(options(r)).ro.includes(p), "an unusable Git fixture must not become a writable trusted repository");
  assert.deepEqual(protectedPaths(options(r)).problems, []);
}));

test("r4 22: a branch or tag named like a credential file stays readable, and a key file in .git is hidden", () => fixture((r, g) => {
  for (const n of ["secrets.json", "private.key", "feature/secret.txt"]) g("branch", n);
  g("tag", "v1.pem");
  fs.writeFileSync(path.join(r, ".git/private.pem"), "credential");
  const p = plan(options(r));
  assert.deepEqual(p.hide.filter((h) => /\.git\/(refs|logs)\//.test(h)), []);
  assert.ok(p.hide.includes(path.join(r, ".git/private.pem")));
  const out = spawnSync(path.resolve("sandbox/bin/bash"), ["-c", "git log -1 secrets.json && git checkout -q secrets.json && git log -1 v1.pem"], { cwd: r, timeout: 30_000, encoding: "utf8", env: wrapperEnv(p) });
  assert.equal(out.status, 0, out.stderr);
}));

test("r4 22: git-lfs's object store does not spend the walk's entry budget", () => fixture((r) => {
  const d = path.join(r, ".git/lfs/objects");
  fs.mkdirSync(d, { recursive: true });
  for (let i = 0; i < 200; i++) fs.writeFileSync(path.join(d, String(i)), "x");
  const old = limits.entries;
  limits.entries = 100;
  try {
    assert.deepEqual(discover([r], { secretsIn: [r] }).problems, []);
  } finally {
    limits.entries = old;
  }
}));

test("r4 21: a config.worktree made while no git-only call ran is left in place, and pauses the session", () => fixture((r) => {
  const s = new SessionState(r);
  projectRoots(s);
  const p = path.join(r, ".git/config.worktree");
  fs.writeFileSync(p, "[core]\n");
  quarantineGitFiles(s);
  assert.ok(fs.existsSync(p));
  assert.match(gitTampered(s) ?? "", /config.worktree/);
}));

test("r4 21: a commondir that is a link leading nowhere is renamed like any other", () => fixture((r) => {
  const s = new SessionState(r);
  projectRoots(s);
  noteGitCall(s, "git status");
  const p = path.join(r, ".git/commondir");
  fs.symlinkSync("missing-target", p);
  assert.match(quarantineGitFiles(s) ?? "", /moved to/);
  assert.throws(() => fs.lstatSync(p), /ENOENT/);
}));

test("r4 21: the config.worktree of an approved git sparse-checkout is left, and nothing pauses", () => fixture((r, g) => {
  fs.mkdirSync(path.join(r, "src"));
  fs.writeFileSync(path.join(r, "src/file"), "x");
  g("add", ".");
  g("commit", "-qm", "source");
  const s = new SessionState(r);
  projectRoots(s);
  s.expecting.push({ dirs: expectedRepos("git sparse-checkout set src", r)!, at: Date.now() });
  g("sparse-checkout", "set", "src");
  quarantineGitFiles(s);
  assert.equal(gitTampered(s), undefined);
  assert.ok(fs.existsSync(path.join(r, ".git/config.worktree")));
  assert.equal(g("config", "--worktree", "--get", "core.sparseCheckout").trim(), "true");
}));

test("r4 26: a POSIX message queue made outside the sandbox cannot be opened inside it", () => fixture((r) => {
  const helper = path.join(r, "mq.py");
  fs.writeFileSync(helper, `import ctypes, os, sys\nc=ctypes.CDLL(None,use_errno=True)\nn=sys.argv[2].encode()\nif sys.argv[1]=='create':\n d=c.mq_open(n, os.O_CREAT|os.O_EXCL|os.O_RDWR, 0o600, None)\n assert d>=0,ctypes.get_errno()\n c.mq_close(d)\nelif sys.argv[1]=='remove': c.mq_unlink(n)\nelse:\n try: os.open('/dev/mqueue/'+sys.argv[2][1:],os.O_RDONLY); print('visible')\n except OSError: print('hidden')\n`);
  const name = `/automode-c-second-${process.pid}`;
  execFileSync("python3", [helper, "create", name]);
  try {
    const p = plan(options(r));
    const out = spawnSync(path.resolve("sandbox/bin/bash"), ["-c", `python3 '${helper}' check '${name}'`], { cwd: r, timeout: 30_000, encoding: "utf8", env: wrapperEnv(p) });
    assert.equal(out.status, 0, out.stderr);
    assert.equal(out.stdout.trim(), "hidden");
  } finally {
    execFileSync("python3", [helper, "remove", name]);
  }
}));

test("r4 21: the plan names the git directories a call may write, and a plant in one of them is renamed", () => fixture((r) => fixture((external) => {
  const p = plan({ ...options(r), allowedPaths: [external], gitCwds: [external] });
  assert.ok(p.gitDirs.includes(path.join(external, ".git")));
  const s = new SessionState(r);
  projectRoots(s);
  noteGitCall(s, "git status", p.gitDirs);
  const plant = path.join(external, ".git/config.worktree");
  fs.writeFileSync(plant, "[core]\n");
  assert.match(quarantineGitFiles(s) ?? "", /moved to/);
  assert.equal(fs.existsSync(plant), false);
})));

test("r4 N1: where a filesystem gives no birth time, an ordinary git add does not pause the session", () => fixture((r, g) => {
  const original = fs.statSync;
  fs.statSync = ((...args: any[]) => {
    const st = (original as any)(...args);
    if (typeof st.birthtimeNs === "bigint") st.birthtimeNs = 0n;
    return st;
  }) as typeof fs.statSync;
  try {
    const s = new SessionState(r);
    projectRoots(s);
    fs.writeFileSync(path.join(r, "file"), "x");
    g("add", "file");
    assert.equal(gitTampered(s), undefined);
  } finally {
    fs.statSync = original;
  }
}));

test("r4 24: a core.hooksPath in config.worktree is protected even when that file switches extensions.worktreeConfig off", () => fixture((r, g) => {
  const hooks = path.join(r, "custom-hooks");
  fs.mkdirSync(hooks);
  g("config", "--local", "extensions.worktreeConfig", "true");
  g("config", "--worktree", "extensions.worktreeConfig", "false");
  g("config", "--file", path.join(r, ".git/config.worktree"), "core.hooksPath", hooks);
  assert.ok(plan(options(r)).ro.includes(hooks));
}));

test("r4 8: a repository below ~/.ssh that an ssh command may see keeps its protection", () => fixture((r) => {
  const entry = path.join(os.homedir(), ".ssh/c-second.pub");
  execFileSync("git", ["init", "-q", "--bare", entry]);
  try {
    const p = plan({ ...options(r), projectRoots: [os.homedir()], exposeSsh: true, gitWritable: false });
    assert.ok(p.ro.includes(entry));
  } finally {
    fs.rmSync(entry, { recursive: true, force: true });
  }
}));

test("r4 21: a planted file that cannot be renamed is named in the pause", () => fixture((r) => {
  const s = new SessionState(r);
  projectRoots(s);
  noteGitCall(s, "git status");
  const p = path.join(r, ".git/config.worktree");
  fs.writeFileSync(p, "[core]\n");
  const original = fs.renameSync;
  fs.renameSync = (() => {
    throw new Error("injected rename failure");
  }) as typeof fs.renameSync;
  try {
    assert.match(quarantineGitFiles(s) ?? "", /could not be moved.*injected rename failure/);
    assert.ok(s.tampered);
    assert.ok(fs.existsSync(p));
  } finally {
    fs.renameSync = original;
    closeGitSnapshot(s);
  }
}));

test("r4 N1: a git directory with the same inode number on another device counts as replaced", () => fixture((r) => {
  const s = new SessionState(r);
  projectRoots(s);
  const original = fs.lstatSync;
  fs.lstatSync = ((...args: any[]) => {
    const st = (original as any)(...args);
    if (typeof st.dev === "bigint") st.dev += 1n;
    return st;
  }) as typeof fs.lstatSync;
  try {
    assert.match(gitTampered(s) ?? "", /replaced/);
  } finally {
    fs.lstatSync = original;
    closeGitSnapshot(s);
  }
}));

// Since the seventh pass git itself reads the worktree's config when it is asked for the value
// it would use (one lookup, every scope): the lookup that can fail is that one.
test("r4 24: a failed lookup of the core.hooksPath git uses in the repository is a problem", () => fixture((r) => {
  const bin = path.join(r, "bin");
  fs.mkdirSync(bin);
  const git = execFileSync("which", ["git"], { encoding: "utf8" }).trim();
  fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\ncase " $* " in *" --git-dir "*" core.hooksPath "*) exit 128;; esac\nexec '${git}' "$@"\n`, { mode: 0o755 });
  const old = process.env.PATH;
  process.env.PATH = `${bin}:${old}`;
  try {
    assert.match(plan(options(r)).problem ?? "", /git could not read core\.hooksPath in .*\.git/);
  } finally {
    process.env.PATH = old;
  }
}));

test("r4 22: a socket the settings keep is not hidden for being named like a credential file", async () => {
  const r = fs.mkdtempSync(path.join(os.homedir(), "c-second-"));
  const socket = path.join(os.homedir(), ".ssh/private.key");
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(socket, resolve));
  try {
    const p = plan({ ...options(r), gitWritable: false, exposeSsh: true, keepSockets: [socket] });
    assert.ok(!p.hide.includes(socket));
    assert.ok(!p.hidden.has(socket));
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(r, { recursive: true, force: true });
  }
});

for (const nested of [false, true]) test(`r4 N1: a ${nested ? "nested" : "main"} git directory removed and made again counts as replaced, on any filesystem`, () => fixture((r) => {
  const base = nested ? path.join(r, "nested") : r;
  if (nested) execFileSync("git", ["init", "-q", base]);
  const s = new SessionState(r);
  projectRoots(s);
  fs.rmSync(path.join(base, ".git"), { recursive: true });
  execFileSync("git", ["init", "-q", base]);
  try {
    assert.match(gitTampered(s) ?? "", /replaced/);
  } finally {
    closeGitSnapshot(s);
  }
}));
