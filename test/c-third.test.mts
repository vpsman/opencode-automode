// Round 4, group C, third pass: the maintainer's three decisions after the second review.
//   1 (finding 21)  a git-only call gets a writable `.git` only in the repositories it works in,
//                   and `commondir` and `config.worktree` are compared there between the call's
//                   start and its end; the session's layout check covers the project alone.
//   2 (finding 22)  the walk skips only the stores of a git directory whose names are hashes.
//   3 (finding 25)  no ssh agent for a fetch or pull that may go into cloned submodules.
// With the smaller findings on the identity of a git directory (N1). Each test builds a
// repository of its own under the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-third.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import { plan, discover, limits } from "../sandbox.ts";

const opts = (r: string, other: string[] = []) => ({ project: r, projectRoots: [r], allowedPaths: other, cacheDirs: [], gitWritable: true, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [] });
// An empty repository, removed afterwards; `g` runs git in it.
function fixture(fn: (r: string, g: (...a: string[]) => string) => void) {
  const r = fs.mkdtempSync(path.join(os.homedir(), "c-third-"));
  const g = (...a: string[]) => execFileSync("git", ["-C", r, ...a], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  try {
    g("init", "-q");
    fn(r, g);
  } finally {
    fs.rmSync(r, { recursive: true, force: true });
  }
}

for (const sub of ["fetch", "pull"]) test(`r4 25: git ${sub} gets no ssh agent while submodules are cloned, and gets it with --no-recurse-submodules`, () => fixture((r, g) => {
  g("remote", "add", "origin", "git@example.invalid:team/x.git");
  const s = new d.SessionState(r);
  d.projectRoots(s);
  assert.ok(d.usesSsh(`git ${sub}`, r, s));
  fs.mkdirSync(path.join(r, ".git/modules/empty"), { recursive: true });
  assert.ok(d.usesSsh(`git ${sub}`, r, s));
  const mod = path.join(r, ".git/modules/nested/child");
  fs.mkdirSync(mod, { recursive: true });
  fs.writeFileSync(path.join(mod, "HEAD"), "ref: refs/heads/main\n");
  assert.equal(d.usesSsh(`git ${sub}`, r, s), false);
  assert.match(d.sandboxBreaks(`git ${sub}`, r, s) ?? "", /cloned submodules.*config and hooks.*--no-recurse-submodules/);
  for (const flag of ["--no-recurse-submodules", "--recurse-submodules=no", "--recurse-submodules=false", "--recurse-submodules=off", "--recurse-submodules=0"]) {
    assert.ok(d.gitOnly(`git ${sub} ${flag}`));
    assert.ok(d.usesSsh(`git ${sub} ${flag}`, r, s), flag);
  }
  d.closeGitSnapshot(s);
}));

test("r4 N1: a git directory's identity is held with O_PATH, which needs no read permission", () => fixture((r) => {
  const original = fs.openSync;
  let seen = false;
  fs.openSync = ((p: any, flags: any, ...rest: any[]) => {
    if (String(p).endsWith("/.git")) {
      assert.ok(flags & 0x200000, "O_PATH is required");
      seen = true;
    }
    return (original as any)(p, flags, ...rest);
  }) as any;
  const s = new d.SessionState(r);
  try {
    d.projectRoots(s);
    assert.ok(seen);
    assert.equal(d.gitTampered(s), undefined);
  } finally {
    fs.openSync = original;
    d.closeGitSnapshot(s);
  }
}));

test("r4 N1: a resume whose new snapshot fails keeps the pause and the old baseline", () => fixture((r) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  s.tampered = { reason: "original pause", at: 0 };
  const old = s.snapshot;
  const resume = path.join(r, "resume");
  fs.writeFileSync(resume, "");
  const original = fs.openSync;
  fs.openSync = (() => {
    throw Object.assign(new Error("EMFILE"), { code: "EMFILE" });
  }) as any;
  try {
    assert.throws(() => d.gitTampered(s, resume));
    assert.equal(s.tampered?.reason, "original pause");
    assert.equal(s.snapshot, old);
  } finally {
    fs.openSync = original;
    d.closeGitSnapshot(s);
  }
}));

test("r4 21: the missing target of a pointer file, once it appears, is explained by an approved command", () => fixture((r) => {
  const sub = path.join(r, "sub");
  fs.mkdirSync(sub);
  const target = path.join(r, ".git/modules/new");
  fs.writeFileSync(path.join(sub, ".git"), "gitdir: ../.git/modules/new\n");
  const s = new d.SessionState(r);
  d.projectRoots(s);
  s.expecting.push({ dirs: [target], at: Date.now() });
  execFileSync("git", ["init", "--bare", "-q", target]);
  assert.equal(d.gitTampered(s), undefined);
  d.closeGitSnapshot(s);
}));

test("r4 N1: a nested .git moved aside and replaced by a link to it counts as replaced", () => fixture((r) => {
  const sub = path.join(r, "sub");
  execFileSync("git", ["init", "-q", sub]);
  const s = new d.SessionState(r);
  d.projectRoots(s);
  fs.renameSync(path.join(sub, ".git"), path.join(sub, "saved"));
  fs.symlinkSync("saved", path.join(sub, ".git"));
  assert.match(d.gitTampered(s) ?? "", /replaced/);
  d.closeGitSnapshot(s);
}));

test("r4 21: the plan does not create the missing target of a pointer file", () => fixture((r) => {
  const sub = path.join(r, "sub");
  fs.mkdirSync(sub);
  const missing = path.join(r, ".git/modules/missing");
  fs.writeFileSync(path.join(sub, ".git"), "gitdir: ../.git/modules/missing\n");
  plan(opts(r));
  assert.ok(!fs.existsSync(missing));
}));

test("r4 21: a config.worktree that is a link leading nowhere pauses the session, and is not renamed with no call to blame", () => fixture((r) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  const file = path.join(r, ".git/config.worktree");
  fs.symlinkSync("absent", file);
  assert.match(d.gitTampered(s) ?? "", /config.worktree/);
  assert.ok(fs.lstatSync(file).isSymbolicLink());
  d.closeGitSnapshot(s);
}));

// What no approval explains to the per-call check.
const EXCLUDED: Record<string, string> = {
  tainted: "a tainted approval explains no config.worktree",
  expired: "an approval older than ten minutes explains no config.worktree",
  commondir: "no approval explains a commondir",
};

// Sixth pass: the approval names the very file, as an approval must to explain it at all (the
// fourth pass made that so; an approval of `.git` explained nothing whatever its taint or age,
// and these tests passed with both filters taken out). The last case is the control: the same
// approval, neither tainted nor expired, does explain a config.worktree.
for (const kind of ["tainted", "expired", "commondir", "control"]) test(`r4 21: ${EXCLUDED[kind] ?? "an approval that names config.worktree, untainted and in time, explains it"}`, () => fixture((r) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  d.noteGitCall(s, "git status");
  const file = path.join(r, ".git", kind === "commondir" ? "commondir" : "config.worktree");
  s.expecting.push({ dirs: [file], at: kind === "expired" ? Date.now() - d.EXPECT_MS - 100 : Date.now(), tainted: kind === "tainted" });
  fs.writeFileSync(file, "plant");
  if (kind === "control") assert.equal(d.quarantineGitFiles(s), undefined);
  else assert.match(d.quarantineGitFiles(s) ?? "", /moved to/);
  d.closeGitSnapshot(s);
}));

test("r4 21: a git-only call still running after ten minutes is still checked against the state it leaves", () => fixture((r) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  const c = d.noteGitCall(s, "git status")!;
  c.at = Date.now() - d.EXPECT_MS - 100;
  fs.writeFileSync(path.join(r, ".git/MERGE_HEAD"), "plant\n");
  assert.match(d.gitStateTampered(s) ?? "", /MERGE_HEAD/);
  d.closeGitSnapshot(s);
}));

test("r4 21: an approved git config --worktree names the one file it writes", () => fixture((r) => {
  assert.deepEqual(d.expectedRepos("git config --worktree core.sparseCheckout true", r), [path.join(r, ".git/config.worktree")]);
}));

test("r4 21: a call whose record of a git directory cannot be made is not noted as checked", () => fixture((r) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  const original = fs.lstatSync;
  fs.lstatSync = ((p: any, ...rest: any[]) => {
    if (String(p).endsWith("/config.worktree")) throw Object.assign(new Error("injected EACCES"), { code: "EACCES" });
    return (original as any)(p, ...rest);
  }) as any;
  try {
    assert.throws(() => d.noteGitCall(s, "git status"), /EACCES/);
    assert.equal(s.gitCalls.length, 0);
  } finally {
    fs.lstatSync = original;
    d.closeGitSnapshot(s);
  }
}));

test("r4 21: a file that cannot be looked at when the call is over is named in a pause", () => fixture((r) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  d.noteGitCall(s, "git status");
  const original = fs.lstatSync;
  fs.lstatSync = ((p: any, ...rest: any[]) => {
    if (String(p).endsWith("/config.worktree")) throw Object.assign(new Error("injected EACCES"), { code: "EACCES" });
    return (original as any)(p, ...rest);
  }) as any;
  try {
    assert.match(d.quarantineGitFiles(s) ?? "", /config.worktree.*could not be checked.*EACCES/);
    assert.ok(s.tampered);
  } finally {
    fs.lstatSync = original;
    d.closeGitSnapshot(s);
  }
}));

test("r4 N1: a resume closes the descriptors of the old snapshot, and disposal those of the new one", () => fixture((r) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  const fd = [...s.snapshot!.held.values()][0];
  s.tampered = { reason: "pause", at: 0 };
  const resume = path.join(r, "resume");
  fs.writeFileSync(resume, "");
  d.gitTampered(s, resume);
  // The new snapshot was acquired while the old descriptor was still held.
  assert.throws(() => fs.fstatSync(fd), /EBADF/);
  const next = [...s.snapshot!.held.values()][0];
  d.closeGitSnapshot(s);
  assert.throws(() => fs.fstatSync(next), /EBADF/);
}));

test("r4 N1: disposal closes the descriptors a snapshot holds", () => fixture((r) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  const fd = [...s.snapshot!.held.values()][0];
  d.closeGitSnapshot(s);
  assert.throws(() => fs.fstatSync(fd), /EBADF/);
}));

test("r4 N1: a project .git that cannot be looked at is an error, not a project without a repository", () => fixture((r) => {
  const s = new d.SessionState(r);
  const original = fs.lstatSync;
  fs.lstatSync = ((p: any, ...rest: any[]) => {
    if (String(p) === path.join(r, ".git")) throw Object.assign(new Error("entry EACCES"), { code: "EACCES" });
    return (original as any)(p, ...rest);
  }) as any;
  try {
    assert.throws(() => d.projectRoots(s), /entry EACCES/);
  } finally {
    fs.lstatSync = original;
    d.closeGitSnapshot(s);
  }
}));

test("r4 N1: a session dropped without disposal has its descriptors closed by the collector", () => fixture((r) => {
  // In a process of its own, so that the collector can be asked to run.
  const source = [
    'import fs from "node:fs";',
    'import { SessionState, projectRoots } from "./decide.ts";',
    "let fd;",
    "(() => {",
    "  const s = new SessionState(process.argv[1]);",
    "  projectRoots(s);",
    "  fd = [...s.snapshot.held.values()][0];",
    "})();",
    "let closed = false;",
    "for (let i = 0; i < 100 && !closed; i++) {",
    "  global.gc();",
    "  await new Promise(setImmediate);",
    "  try {",
    "    fs.fstatSync(fd);",
    "  } catch (e) {",
    '    if (e.code !== "EBADF") throw e;',
    "    closed = true;",
    "  }",
    "}",
    'if (!closed) throw new Error("finalizer did not close held descriptor");',
  ].join("\n");
  const out = spawnSync(process.execPath, ["--expose-gc", "--input-type=module", "-e", source, r], { cwd: path.resolve(import.meta.dirname, ".."), encoding: "utf8", timeout: 30_000 });
  assert.equal(out.status, 0, out.stderr);
}));

test("r4 N1: a snapshot that fails halfway closes what it had opened", () => fixture((r) => {
  execFileSync("git", ["init", "-q", path.join(r, "nested")]);
  const s = new d.SessionState(r);
  const original = fs.openSync;
  const opened: number[] = [];
  fs.openSync = ((p: any, flags: any, ...rest: any[]) => {
    if (String(p).endsWith("/nested/.git")) throw Object.assign(new Error("EMFILE"), { code: "EMFILE" });
    const fd = (original as any)(p, flags, ...rest);
    if (flags & 0x200000) opened.push(fd);
    return fd;
  }) as any;
  try {
    assert.throws(() => d.projectRoots(s), /identity/);
    assert.ok(opened.length);
    for (const fd of opened) assert.throws(() => fs.fstatSync(fd), /EBADF/);
  } finally {
    fs.openSync = original;
    d.closeGitSnapshot(s);
  }
}));

test("r4 21: a repository in the temp directory rebuilt between two calls does not pause the session", () => fixture((r) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "automode-c-third-"));
  const s = new d.SessionState(r);
  try {
    execFileSync("git", ["init", "-q", tmp]);
    d.projectRoots(s);
    const p = plan(opts(r));
    assert.ok(!p.gitDirs.includes(path.join(tmp, ".git")));
    fs.rmSync(path.join(tmp, ".git"), { recursive: true });
    execFileSync("git", ["init", "-q", tmp]);
    assert.equal(d.gitTampered(s), undefined);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
    d.closeGitSnapshot(s);
  }
}));

// Sixth pass: a git command that writes that git directory would only fail in the sandbox, so it
// asks; one that only reads it is as before.
test("r4 21: a project whose git directory lies outside the writable roots has no per-call record", () => fixture((r) => fixture((other) => {
  fs.rmSync(path.join(r, ".git"), { recursive: true });
  fs.writeFileSync(path.join(r, ".git"), `gitdir: ${other}/.git\n`);
  const p = plan({ ...opts(r), gitCwds: [r], gitWriteCwds: d.gitWriteDirectories("git status", r) });
  assert.equal(p.problem, undefined);
  assert.ok(!p.gitDirs.includes(path.join(other, ".git")));
  for (const writing of [plan(opts(r)), plan({ ...opts(r), gitCwds: [r], gitWriteCwds: d.gitWriteDirectories("git commit -m x", r) })]) {
    assert.match(writing.problem ?? "", /lies outside the project.*an approved run happens outside the sandbox/);
    assert.ok(!writing.gitDirs.includes(path.join(other, ".git")));
  }
})));

test("r4 21: an approved git submodule update and git worktree add do not pause", () => fixture((r, g) => fixture((source, sg) => {
  sg("-c", "user.name=t", "-c", "user.email=t@t", "commit", "--allow-empty", "-qm", "source");
  g("-c", "protocol.file.allow=always", "submodule", "add", "-q", source, "sub");
  g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "submodule");
  g("submodule", "deinit", "-f", "--", "sub");
  const s = new d.SessionState(r);
  d.projectRoots(s);
  assert.equal(d.gitOnly("git submodule update --init sub"), false);
  s.expecting.push({ dirs: d.expectedRepos("git submodule update --init sub", r)!, at: Date.now() });
  g("submodule", "update", "--init", "sub");
  assert.equal(d.gitTampered(s), undefined);
  assert.equal(d.gitOnly("git worktree add --detach linked"), false);
  s.expecting.push({ dirs: d.expectedRepos("git worktree add --detach linked", r)!, at: Date.now() });
  g("worktree", "add", "--detach", "-q", "linked");
  assert.equal(d.gitTampered(s), undefined);
  d.closeGitSnapshot(s);
})));

test("r4 21: a repository in an allowed path that the call does not work in is read-only, and rebuilding it does not pause", () => fixture((r) => fixture((other) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  const p = plan(opts(r, [other]));
  const out = spawnSync(path.resolve("sandbox/bin/bash"), ["-c", `echo plant > '${other}/.git/planted'`], { cwd: r, encoding: "utf8", timeout: 30_000, env: { ...process.env, AUTOMODE_SHELL: "/bin/bash", AUTOMODE_RW: p.rw.join("\n"), AUTOMODE_RO: p.ro.join("\n"), AUTOMODE_PIN: p.pin.join("\n"), AUTOMODE_HIDE: p.hide.join("\n"), AUTOMODE_TMPFS: p.tmpfs.join("\n") } });
  assert.notEqual(out.status, 0, out.stderr);
  assert.ok(!fs.existsSync(path.join(other, ".git/planted")));
  assert.ok(p.ro.includes(path.join(other, ".git")));
  assert.ok(!p.gitDirs.includes(path.join(other, ".git")));
  fs.rmSync(other, { recursive: true });
  execFileSync("git", ["init", "-q", other]);
  assert.equal(d.gitTampered(s), undefined);
  d.closeGitSnapshot(s);
})));

test("r4 21: from a subdirectory, a submodule and repeated -C, the grant holds the modules under the common directory; from a linked worktree it does not", () => fixture((r, g) => {
  g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "--allow-empty", "-qm", "initial");
  const wt = path.join(r, "linked");
  g("worktree", "add", "-qb", "other", wt);
  const module = path.join(r, ".git/modules/sub");
  execFileSync("git", ["init", "--bare", "-q", module]);
  const sub = path.join(r, "sub");
  fs.mkdirSync(sub);
  fs.writeFileSync(path.join(sub, ".git"), "gitdir: ../.git/modules/sub\n");
  fs.mkdirSync(path.join(r, "src"));
  for (const [command, cwd] of [["git status", wt], ["git status", path.join(r, "src")], ["git -C sub status", r], ["git -C src -C .. status", r]]) {
    const p = plan({ ...opts(r), gitCwds: d.gitDirectories(command, cwd) });
    assert.equal(p.problem, undefined, `${command} at ${cwd}: ${p.problem}`);
    assert.ok(p.gitDirs.includes(path.join(r, ".git")) || cwd === r && command.includes("sub"));
    // A call in a linked worktree gets its own admin directory and the common directory: the
    // main checkout's modules are not its (seventh pass).
    assert.equal(p.gitDirs.includes(module), cwd !== wt, command);
  }
}));

test("r4 22: a socket under .git/annex/ssh is hidden; a file named like a key under .git/annex is not", async () => {
  const r = fs.mkdtempSync(path.join(os.homedir(), "c-third-"));
  execFileSync("git", ["init", "-q", r]);
  const dir = path.join(r, ".git/annex/ssh");
  fs.mkdirSync(dir, { recursive: true });
  const socket = path.join(dir, "connection");
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(socket, resolve));
  fs.writeFileSync(path.join(r, ".git/annex/private.key"), "data");
  try {
    const p = plan(opts(r));
    assert.ok(p.hide.includes(socket));
    assert.ok(!p.hide.includes(path.join(r, ".git/annex/private.key")));
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(r, { recursive: true, force: true });
  }
});

for (const store of ["objects", "lfs/objects", "annex/objects", "rr-cache"]) test(`r4 22: ${store} in a git directory does not spend the walk's entry budget`, () => fixture((r) => {
  const dir = path.join(r, ".git", store);
  fs.mkdirSync(dir, { recursive: true });
  for (let i = 0; i < 200; i++) fs.writeFileSync(path.join(dir, String(i)), "x");
  const old = limits.entries;
  limits.entries = 100;
  try {
    assert.deepEqual(discover([r], { secretsIn: [r] }).problems, []);
  } finally {
    limits.entries = old;
  }
}));

test("r4 22: a linked worktree's own refs are not taken for credentials when its pointer file is outside the walk", () => fixture((r) => {
  const admin = path.join(r, ".git/worktrees/z");
  fs.mkdirSync(path.join(admin, "refs/worktree"), { recursive: true });
  fs.writeFileSync(path.join(admin, "HEAD"), "ref: refs/heads/main\n");
  fs.writeFileSync(path.join(admin, "commondir"), "../..\n");
  fs.writeFileSync(path.join(admin, "gitdir"), "/missing/.git\n");
  const ref = path.join(admin, "refs/worktree/private.key");
  fs.writeFileSync(ref, "data");
  const found = discover([r], { secretsIn: [r] });
  assert.ok(!found.secrets.has(ref));
  assert.ok(found.gitDirs.has(admin));
}));

test("r4 21: a call is checked at its hook and again at retirement, and a file the user puts back afterwards is left: named once more, then taken in", () => fixture((r) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  const c = d.noteGitCall(s, "git status")!;
  assert.equal(d.quarantineGitFiles(s), undefined);
  const file = path.join(r, ".git/config.worktree");
  fs.writeFileSync(file, "[core]\n");
  assert.match(d.quarantineGitFiles(s) ?? "", /moved to/);
  c.done = true;
  d.gitStateTampered(s);
  fs.writeFileSync(file, "[core]\n");
  assert.equal(d.quarantineGitFiles(s), undefined);
  const resume = path.join(r, "resume");
  fs.writeFileSync(resume, "");
  fs.utimesSync(resume, new Date(Date.now() + 2000), new Date(Date.now() + 2000));
  // The pause named the path as it was then, moved away. What is there at the resume is not
  // what was shown: it is named as it is, and the next resume takes it in (seventh pass).
  assert.match(d.gitTampered(s, resume) ?? "", /config\.worktree appeared/);
  assert.ok(fs.existsSync(file));
  fs.utimesSync(resume, new Date(Date.now() + 4000), new Date(Date.now() + 4000));
  assert.equal(d.gitTampered(s, resume), undefined);
  assert.ok(fs.existsSync(file));
  d.closeGitSnapshot(s);
}));

test("r4 21: an untainted approval in another session explains a config.worktree", () => fixture((r) => {
  const a = new d.SessionState(r), b = new d.SessionState(r);
  d.projectRoots(a);
  d.projectRoots(b);
  d.noteGitCall(a, "git status");
  b.expecting.push({ dirs: [path.join(r, ".git/config.worktree")], at: Date.now() });
  const file = path.join(r, ".git/config.worktree");
  fs.writeFileSync(file, "[core]\n");
  assert.equal(d.quarantineGitFiles(a, [a, b]), undefined);
  assert.ok(fs.existsSync(file));
  d.closeGitSnapshot(a);
  d.closeGitSnapshot(b);
}));

test("r4 21: a repository in an allowed path removed and made again: its own config.worktree is left, a later plant is renamed", () => fixture((r) => fixture((other) => {
  const s = new d.SessionState(r);
  d.projectRoots(s);
  fs.writeFileSync(path.join(other, ".git/config.worktree"), "[core]\n");
  let c = d.noteGitCall(s, "git status", [path.join(other, ".git")])!;
  assert.equal(d.quarantineGitFiles(s), undefined);
  c.done = true;
  d.gitStateTampered(s);
  fs.rmSync(other, { recursive: true });
  execFileSync("git", ["init", "-q", other]);
  c = d.noteGitCall(s, "git status", [path.join(other, ".git")])!;
  fs.writeFileSync(path.join(other, ".git/config.worktree"), "[core]\n");
  assert.match(d.quarantineGitFiles(s) ?? "", /moved to/);
  d.closeGitSnapshot(s);
})));
