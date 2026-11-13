// Round 4, group C, fourth pass: what the reviews of the third pass found (a project folder
// that is no repository, a repository outside the writable roots, a husky project with a linked
// worktree, submodules that git keeps in their own work tree), a push to a repository on this
// machine, and the points carried from the reviews of the first pass. Each test builds a
// repository of its own under the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-fourth.test.mts.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import { discover, plan } from "../sandbox.ts";

// An empty repository, removed afterwards; `g` runs git in it.
function fixture(fn: (r: string, g: (...args: string[]) => string) => void) {
  const r = fs.mkdtempSync(path.join(os.homedir(), "c-fourth-"));
  const g = (...args: string[]) => execFileSync("git", ["-C", r, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  try {
    g("init", "-q");
    fn(r, g);
  } finally {
    fs.rmSync(r, { recursive: true, force: true });
  }
}
const opts = (r: string) => ({ project: r, projectRoots: [r], allowedPaths: [], cacheDirs: [], gitWritable: true, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [] });

test("r4 21: only the directories git runs in are looked up, not the shell's or one a cd passes through", () => fixture((r) => {
  fs.mkdirSync(path.join(r, "sub"));
  fs.mkdirSync(path.join(r, "other"));
  assert.deepEqual(d.gitDirectories("cd /tmp && git -C " + r + " status", r), [r]);
  assert.deepEqual(d.gitDirectories("git -C sub -C ../other status", r), [path.join(r, "other")]);
}));

test("r4 21: a project folder that is no repository is no problem", () => fixture((r) => {
  const plain = path.join(r, "workspace");
  fs.mkdirSync(plain);
  // Outside a repository, not merely a directory beneath its checkout.
  fs.renameSync(path.join(r, ".git"), path.join(r, "saved"));
  assert.equal(plan({ ...opts(plain), gitCwds: [plain] }).problem, undefined);
}));

// Sixth pass: for a command that only reads it. One that writes its git directory would only
// fail there, and asks (test/c-sixth.test.mts).
test("r4 21: a repository outside the writable roots needs no grant and is no problem for a git command that only reads it", () => fixture((r) => fixture((outside) => {
  const p = plan({ ...opts(r), gitCwds: [outside], gitWriteCwds: d.gitWriteDirectories(`git -C ${outside} status`, r) });
  assert.equal(p.problem, undefined);
  assert.deepEqual(p.gitDirs, []);
})));

test("r4 25: a submodule kept in its own work tree refuses the agent for a fetch that may recurse", () => fixture((r, g) => {
  g("remote", "add", "origin", "git@example.invalid:team/x.git");
  execFileSync("git", ["init", "-q", path.join(r, "vendor")]);
  g("update-index", "--add", "--cacheinfo", "160000,1111111111111111111111111111111111111111,vendor");
  const s = new d.SessionState(r);
  try {
    d.projectRoots(s);
    assert.equal(d.usesSsh("git fetch", r, s), false);
    assert.equal(d.usesSsh("git fetch --no-recurse-submodules", r, s), true);
  } finally {
    d.closeGitSnapshot(s);
  }
}));

test("r4 25: a submodule cloned in a linked worktree refuses the agent for a fetch that may recurse", () => fixture((r, g) => {
  g("-c", "user.name=test", "-c", "user.email=test@example.invalid", "commit", "-q", "--allow-empty", "-m", "initial");
  g("remote", "add", "origin", "git@example.invalid:team/x.git");
  const wt = path.join(r, "linked");
  g("worktree", "add", "-q", "-b", "linked", wt);
  const gd = execFileSync("git", ["-C", wt, "rev-parse", "--absolute-git-dir"], { encoding: "utf8" }).trim();
  fs.mkdirSync(path.join(gd, "modules/child"), { recursive: true });
  fs.writeFileSync(path.join(gd, "modules/child/HEAD"), "ref: refs/heads/main\n");
  const s = new d.SessionState(wt);
  try {
    d.projectRoots(s);
    assert.equal(d.usesSsh("git fetch", wt, s), false);
  } finally {
    d.closeGitSnapshot(s);
  }
}));

test("r4 24: a hooks directory that cannot be listed refuses the agent", () => fixture((r, g) => {
  g("remote", "add", "origin", "git@example.invalid:team/x.git");
  const s = new d.SessionState(r);
  d.projectRoots(s);
  const original = fs.readdirSync;
  fs.readdirSync = ((p: any, ...args: any[]) => {
    if (String(p) === path.join(r, ".git/hooks")) throw Object.assign(new Error("EACCES"), { code: "EACCES" });
    return (original as any)(p, ...args);
  }) as any;
  try {
    assert.equal(d.usesSsh("git fetch", r, s), false);
  } finally {
    fs.readdirSync = original;
    d.closeGitSnapshot(s);
  }
}));

test("r4 24: a relative core.hooksPath from the system config is protected", () => fixture((r) => {
  const file = path.join(r, "system-config");
  fs.writeFileSync(file, "[core]\n hooksPath = system-hooks\n");
  const old = process.env.GIT_CONFIG_SYSTEM, no = process.env.GIT_CONFIG_NOSYSTEM;
  process.env.GIT_CONFIG_SYSTEM = file;
  delete process.env.GIT_CONFIG_NOSYSTEM;
  try {
    assert.ok(plan(opts(r)).ro.includes(path.join(r, "system-hooks")));
  } finally {
    if (old === undefined) delete process.env.GIT_CONFIG_SYSTEM;
    else process.env.GIT_CONFIG_SYSTEM = old;
    if (no !== undefined) process.env.GIT_CONFIG_NOSYSTEM = no;
  }
}));

test("r4 24: a list too long for one environment string is a problem", () => fixture((r) => {
  const dirs = Array.from({ length: 600 }, (_, i) => path.join(r, String(i).padEnd(240, "a")));
  const p = plan({ ...opts(r), cacheDirs: dirs });
  assert.match(p.problem ?? "", /AUTOMODE_RW.*environment/);
}));

// ---- the tops of a git directory (where git runs its hooks from) ----

const commit = (dir: string) => execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "--allow-empty", "-m", "one"]);
// Every path below `dir`, for "the plan created nothing here".
const tree = (dir: string): string[] => fs.readdirSync(dir, { recursive: true, encoding: "utf8" }).sort();
// What a session sees of one sandboxed `git status`: the plan's problem, what the plan made
// inside `watched`, and whether the next decision pauses.
function statusTwice(project: string, watched: string) {
  const session = new d.SessionState(project);
  try {
    d.projectRoots(session);
    const before = tree(watched);
    const p = plan({ ...opts(project), gitCwds: d.gitDirectories("git status", project) });
    const made = tree(watched).filter((name) => !before.includes(name));
    return { problem: p.problem, made, pause: d.gitTampered(session), ro: p.ro };
  } finally {
    d.closeGitSnapshot(session);
  }
}
const husky = (dir: string, g: (...args: string[]) => string) => {
  fs.mkdirSync(path.join(dir, ".husky", "_"), { recursive: true });
  fs.writeFileSync(path.join(dir, ".husky", "_", "pre-commit"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
  g("config", "core.hooksPath", ".husky/_");
};

test("r4 21: a husky project with a linked worktree elsewhere: the plan creates nothing in .git, and the next decision does not pause", () =>
  fixture((r, g) => {
    const elsewhere = fs.mkdtempSync(path.join(os.homedir(), "c-fourth-wt-"));
    try {
      husky(r, g);
      commit(r);
      g("worktree", "add", "-q", "-b", "feature", path.join(elsewhere, "feature"));
      const seen = statusTwice(r, path.join(r, ".git"));
      assert.deepEqual({ problem: seen.problem, made: seen.made, pause: seen.pause }, { problem: undefined, made: [], pause: undefined });
      assert.ok(seen.ro.includes(path.join(r, ".husky", "_")), "the hooks directory git runs is read-only");
    } finally {
      fs.rmSync(elsewhere, { recursive: true, force: true });
    }
  }));

test("r4 21: a husky project with no worktree: the plan creates nothing in .git, and the next decision does not pause", () =>
  fixture((r, g) => {
    husky(r, g);
    const seen = statusTwice(r, path.join(r, ".git"));
    assert.deepEqual({ problem: seen.problem, made: seen.made, pause: seen.pause }, { problem: undefined, made: [], pause: undefined });
  }));

test("r4 21: a husky project with a linked worktree inside it: the hooks path is protected in the worktree, not in its admin directory", () =>
  fixture((r, g) => {
    husky(r, g);
    g("add", ".husky");
    commit(r);
    g("worktree", "add", "-q", "-b", "feature", path.join(r, "feature"));
    const seen = statusTwice(r, path.join(r, ".git"));
    assert.deepEqual({ problem: seen.problem, made: seen.made, pause: seen.pause }, { problem: undefined, made: [], pause: undefined });
    assert.ok(seen.ro.includes(path.join(r, "feature", ".husky", "_")));
  }));

test("r4 21: a submodule with a relative hooks path: protected in its work tree, nothing created in its git directory", () =>
  fixture((r, g) => {
    const sub = path.join(r, "sub");
    execFileSync("git", ["init", "-q", sub]);
    husky(sub, (...args) => execFileSync("git", ["-C", sub, ...args], { encoding: "utf8" }));
    fs.mkdirSync(path.join(r, ".git", "modules"));
    fs.renameSync(path.join(sub, ".git"), path.join(r, ".git", "modules", "sub"));
    fs.writeFileSync(path.join(sub, ".git"), "gitdir: ../.git/modules/sub\n");
    const seen = statusTwice(r, path.join(r, ".git"));
    assert.deepEqual({ problem: seen.problem, made: seen.made, pause: seen.pause }, { problem: undefined, made: [], pause: undefined });
    assert.ok(seen.ro.includes(path.join(sub, ".husky", "_")));
  }));

// The walk with the entries of every directory in one order or the other: what it finds must
// not depend on the order the kernel lists them in.
function walked<T>(descending: boolean, fn: () => T): T {
  const original = fs.readdirSync;
  fs.readdirSync = ((p: fs.PathLike, ...rest: unknown[]) => {
    const list = (original as (...args: unknown[]) => fs.Dirent[])(p, ...rest);
    const name = (e: fs.Dirent | string) => (typeof e === "string" ? e : e.name);
    list.sort((a, b) => (name(a) < name(b) ? -1 : 1) * (descending ? -1 : 1));
    return list;
  }) as typeof fs.readdirSync;
  try {
    return fn();
  } finally {
    fs.readdirSync = original;
  }
}
const topsOf = (root: string, gitDir: string, descending: boolean) => [...(walked(descending, () => discover([root])).tops.get(gitDir) ?? [])].sort();

test("r4 21: a submodule's git directory has its work tree as its only top, whichever is listed first", () =>
  fixture((r) => {
    const module = path.join(r, ".git", "modules", "sub");
    execFileSync("git", ["init", "-q", "--bare", module]);
    for (const sub of [".a-before", "z-after"]) {
      fs.mkdirSync(path.join(r, sub));
      fs.writeFileSync(path.join(r, sub, ".git"), "gitdir: ../.git/modules/sub\n");
    }
    for (const descending of [false, true]) assert.deepEqual(topsOf(r, module, descending), [path.join(r, ".a-before"), path.join(r, "z-after")], `descending: ${descending}`);
    for (const descending of [false, true]) assert.deepEqual(topsOf(r, path.join(r, ".git"), descending), [r]);
  }));

test("r4 21: a bare repository named by a pointer file is its own top and the pointer's, listed before or after it", () =>
  fixture((r) => {
    const bare = path.join(r, "m-store.git");
    execFileSync("git", ["init", "-q", "--bare", bare]);
    for (const work of ["a-work", "z-work"]) {
      fs.mkdirSync(path.join(r, work));
      fs.writeFileSync(path.join(r, work, ".git"), "gitdir: ../m-store.git\n");
    }
    for (const descending of [false, true]) assert.deepEqual(topsOf(r, bare, descending), [path.join(r, "a-work"), bare, path.join(r, "z-work")], `descending: ${descending}`);
  }));

test("r4 21: a linked worktree's admin directory is a git directory with no top of its own", () =>
  fixture((r, g) => {
    commit(r);
    g("worktree", "add", "-q", "-b", "feature", path.join(r, "feature"));
    const admin = path.join(r, ".git", "worktrees", "feature");
    for (const descending of [false, true]) {
      assert.ok(walked(descending, () => discover([r])).gitDirs.has(admin));
      assert.deepEqual(topsOf(r, admin, descending), [path.join(r, "feature")]);
    }
  }));

// ---- which git directories a call may write ----

const gitIn = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
// A repository of its own in `dir`, with one commit, recorded in `parent`'s index as a gitlink:
// a submodule that git keeps in its own work tree.
function gitlink(parent: string, dir: string) {
  execFileSync("git", ["init", "-q", dir]);
  commit(dir);
  gitIn(parent, "update-index", "--add", "--cacheinfo", `160000,${gitIn(dir, "rev-parse", "HEAD").trim()},${path.relative(parent, dir)}`);
}

test("r4 21: a populated submodule kept in its own work tree is granted with the repository it belongs to, to any depth", () =>
  fixture((r) => {
    const lib = path.join(r, "lib");
    const deep = path.join(lib, "deep");
    gitlink(r, lib);
    gitlink(lib, deep);
    execFileSync("git", ["init", "-q", path.join(r, "unrelated")]);
    const p = plan({ ...opts(r), gitCwds: d.gitDirectories("git status", r) });
    assert.equal(p.problem, undefined);
    assert.deepEqual([...p.gitDirs].sort(), [path.join(r, ".git"), path.join(lib, ".git"), path.join(deep, ".git")].sort());
    // A repository that merely lies in the checkout is no part of it.
    assert.ok(p.ro.includes(path.join(r, "unrelated", ".git")));
    assert.ok(!p.ro.includes(path.join(lib, ".git")));
  }));

// Sixth pass: the git directory around the module is no longer granted. It is in the call's
// record (`gitDirs`) and shut entry by entry instead of read-only whole (test/c-sixth.test.mts).
test("r4 21: a call that works in a submodule under modules/ is granted its module; the git directory around it is read-only whole, with the module writable again inside it", () =>
  fixture((r) => {
    const sub = path.join(r, "sub");
    const module = path.join(r, ".git", "modules", "sub");
    execFileSync("git", ["init", "-q", sub]);
    fs.mkdirSync(path.dirname(module));
    fs.renameSync(path.join(sub, ".git"), module);
    fs.writeFileSync(path.join(sub, ".git"), "gitdir: ../.git/modules/sub\n");
    for (const [command, cwd] of [["git -C sub status", r], ["git status", sub]]) {
      const p = plan({ ...opts(r), gitCwds: d.gitDirectories(command, cwd) });
      assert.equal(p.problem, undefined);
      // Seventh pass: the wrapper makes the module writable again inside the read-only `.git`
      // (AUTOMODE_REOPEN), so nothing can be made at the top of the git directory around it.
      assert.deepEqual(p.gitDirs, [module], command);
      assert.ok(p.ro.includes(path.join(r, ".git")), `${command}: the git directory around the module is read-only whole`);
      assert.deepEqual(p.reopen, [module], command);
      assert.ok(p.pin.includes(module) && !p.pin.slice(p.pin.indexOf(module)).includes(path.join(r, ".git")), `${command}: only the module is held as a writable git directory`);
      for (const name of ["config", "hooks"]) assert.ok(p.ro.includes(path.join(module, name)), `${command}: the module's ${name}`);
    }
  }));

test("r4 21: a repository the walk cannot show is a problem for a call that would work in it", () =>
  fixture((r) => {
    // Below a credential directory the plan hides: found by the walk, and left out of the plan.
    const veiled = path.join(r, ".aws", "fixture");
    execFileSync("git", ["init", "-q", veiled]);
    assert.match(plan({ ...opts(r), gitCwds: [veiled] }).problem ?? "", /cannot locate a discovered repository for git in .*\.aws\/fixture/);
  }));

test("r4 21: git not answering is a problem, not a call without a grant", () =>
  fixture((r) => {
    const before = process.env.PATH;
    process.env.PATH = path.join(r, "no-programs-here");
    try {
      const p = plan({ ...opts(r), gitCwds: [r] });
      assert.deepEqual(p.gitDirs, []);
      assert.match(p.problem ?? "", /cannot locate a discovered repository for git in /);
    } finally {
      process.env.PATH = before;
    }
  }));

test("r4 21: a git directory without a HEAD has no per-call record", () =>
  fixture((r) => {
    // A pointer file whose target is a leftover directory under the common directory.
    fs.mkdirSync(path.join(r, ".git", "modules", "leftover"), { recursive: true });
    fs.mkdirSync(path.join(r, "sub"));
    fs.writeFileSync(path.join(r, "sub", ".git"), "gitdir: ../.git/modules/leftover\n");
    const p = plan({ ...opts(r), gitCwds: [r] });
    assert.equal(p.problem, undefined);
    assert.deepEqual(p.gitDirs, [path.join(r, ".git")]);
  }));

test("r4 21: the directory a git command ends in, through cd, ~ and cd -", () =>
  fixture((r) => {
    fs.mkdirSync(path.join(r, "sub"));
    const inHome = fs.mkdtempSync(path.join(os.homedir(), "c-fourth-home-"));
    const name = path.basename(inHome);
    try {
      assert.deepEqual(d.gitDirectories("cd sub && git status", r), [path.join(r, "sub")]);
      assert.deepEqual(d.gitDirectories(`cd ~/${name} && git status`, r), [inHome]);
      assert.deepEqual(d.gitDirectories(`git -C ~/${name} status`, r), [inHome]);
      // What cannot be told asks, and says why, for a command that writes its git directory.
      // Since the seventh pass the place is read by guard.ts (`located`), which does not follow
      // `cd -`. Since the eighth, a command that only reads there is given no directory and does
      // not ask (it needs no grant).
      assert.throws(() => d.gitDirectories("cd sub && cd - && git add -A", r), /cannot tell which directory git runs in/);
      assert.throws(() => d.gitDirectories("cd sub && git status && cd - && git add -A", r), /cannot tell which directory git runs in/);
      assert.throws(() => d.gitDirectories(`git -C '~/${name}' add -A`, r), /quoted ~/);
      assert.throws(() => d.gitDirectories(`cd '~/${name}' && git add -A`, r), /quoted ~|cannot tell which directory git runs in/);
      assert.throws(() => d.gitDirectories("cd - && git add -A", r), /cannot tell which directory git runs in/);
      assert.throws(() => d.gitDirectories("cd ~nobody && git add -A", r), /cannot tell which directory cd ~nobody names$/);
      assert.throws(() => d.gitDirectories("git -C ~nobody add -A", r), /cannot tell which directory git -C ~nobody names$/);
      assert.throws(() => d.gitDirectories("cd nowhere && git add -A", r), /cannot tell which directory git runs in/);
      assert.throws(() => d.gitDirectories("git -C nowhere add -A", r), /cannot tell which directory git -C nowhere leads to/);
      for (const text of ["cd sub && cd - && git status", "cd sub && git status && cd - && git status", `git -C '~/${name}' status`, `cd '~/${name}' && git status`, "cd - && git status", "cd ~nobody && git status", "git -C ~nobody status", "cd nowhere && git status", "git -C nowhere status"]) {
        assert.deepEqual(d.gitDirectories(text, r), [], text);
      }
    } finally {
      fs.rmSync(inHome, { recursive: true, force: true });
    }
  }));

// ---- the layout check and the approvals that explain a new config.worktree ----

// lstat failing with `code` for the paths `match` picks, while `fn` runs.
function lstatFailing<T>(match: (p: string) => boolean, code: string, fn: () => T): T {
  const original = fs.lstatSync;
  fs.lstatSync = ((p: fs.PathLike, ...rest: unknown[]) => {
    if (match(String(p))) throw Object.assign(new Error(`${code}: permission denied, lstat '${p}'`), { code });
    return (original as (...args: unknown[]) => unknown)(p, ...rest);
  }) as typeof fs.lstatSync;
  try {
    return fn();
  } finally {
    fs.lstatSync = original;
  }
}

test("r4 21: a git directory that cannot be looked into does not stop every decision, and what it holds is its baseline once it can be", () =>
  fixture((r) => {
    const nested = path.join(r, "vendor", ".git");
    execFileSync("git", ["init", "-q", path.dirname(nested)]);
    fs.writeFileSync(path.join(nested, "config.worktree"), "[core]\n");
    const closed = (p: string) => p.startsWith(nested + "/");
    const session = new d.SessionState(r);
    try {
      lstatFailing(closed, "EACCES", () => {
        d.projectRoots(session);
        assert.equal(d.gitTampered(session), undefined);
      });
      // Seen into for the first time: nothing appeared.
      assert.equal(d.gitTampered(session), undefined);
      // From then on it is watched like any other.
      fs.writeFileSync(path.join(nested, "commondir"), "/elsewhere\n");
      assert.match(d.gitTampered(session) ?? "", /vendor\/\.git\/commondir appeared/);
    } finally {
      d.closeGitSnapshot(session);
    }
  }));

test("r4 21: an error other than a closed directory still stops the layout check", () =>
  fixture((r) => {
    const session = new d.SessionState(r);
    try {
      assert.throws(() => lstatFailing((p) => p.endsWith("/.git/commondir"), "EIO", () => d.projectRoots(session)), /EIO/);
    } finally {
      d.closeGitSnapshot(session);
    }
  }));

for (const approved of ["git submodule update --init", "git worktree add ../elsewhere"]) {
  test(`r4 21: an approved ${approved.split(" ").slice(1, 3).join(" ")} does not explain a new config.worktree`, () =>
    fixture((r) => {
      commit(r);
      fs.writeFileSync(path.join(r, ".gitmodules"), '[submodule "sub"]\n\tpath = sub\n\turl = ./sub\n');
      const module = path.join(r, ".git", "modules", "old");
      execFileSync("git", ["init", "-q", "--bare", module]);
      const session = new d.SessionState(r);
      try {
        d.projectRoots(session);
        const dirs = d.expectedRepos(approved, r);
        assert.ok(dirs?.includes(path.join(r, ".git")), `the approval names the common directory: ${dirs}`);
        session.expecting.push({ dirs: dirs!, at: Date.now() });
        // In the per-call check: renamed.
        d.noteGitCall(session, "git status", [path.join(r, ".git"), module]);
        fs.writeFileSync(path.join(module, "config.worktree"), "[core]\n");
        assert.match(d.quarantineGitFiles(session) ?? "", /modules\/old\/config\.worktree appeared and was moved/);
        // In the layout check: named in a pause.
        session.tampered = undefined;
        fs.writeFileSync(path.join(r, ".git", "config.worktree"), "[core]\n");
        assert.match(d.gitTampered(session) ?? "", /\.git\/config\.worktree appeared/);
      } finally {
        d.closeGitSnapshot(session);
      }
    }));
}

test("r4 21: an approved sparse-checkout explains the config.worktree it names, in the layout check and from then on", () =>
  fixture((r) => {
    const file = path.join(r, ".git", "config.worktree");
    const session = new d.SessionState(r);
    try {
      d.projectRoots(session);
      session.expecting.push({ dirs: d.expectedRepos("git sparse-checkout set src", r)!, at: Date.now() });
      fs.writeFileSync(file, "[core]\n");
      assert.equal(d.gitTampered(session), undefined);
      // The approval is used up; the file is part of the baseline now.
      session.expecting = [];
      assert.equal(d.gitTampered(session), undefined);
    } finally {
      d.closeGitSnapshot(session);
    }
  }));

test("r4 21: a config.worktree the per-call check leaves as approved joins the session's own baseline", () =>
  fixture((r) => {
    const file = path.join(r, ".git", "config.worktree");
    const session = new d.SessionState(r);
    try {
      d.projectRoots(session);
      d.noteGitCall(session, "git status");
      session.expecting.push({ dirs: [file], at: Date.now() });
      fs.writeFileSync(file, "[core]\n");
      assert.equal(d.quarantineGitFiles(session), undefined);
      session.expecting = [];
      assert.equal(d.gitTampered(session), undefined, "the layout check does not report what the per-call check accepted");
    } finally {
      d.closeGitSnapshot(session);
    }
  }));

test("r4 21: a git-only call that is over still explains the state it left, however long it ran", () =>
  fixture((r) => {
    const session = new d.SessionState(r);
    try {
      d.projectRoots(session);
      const merge = d.noteGitCall(session, "git merge topic")!;
      d.noteGitCall(session, "git status");
      merge.at = Date.now() - d.EXPECT_MS - 1000;
      merge.done = true;
      fs.writeFileSync(path.join(r, ".git", "MERGE_HEAD"), "0000000000000000000000000000000000000000\n");
      assert.equal(d.gitStateTampered(session), undefined);
    } finally {
      d.closeGitSnapshot(session);
    }
  }));

// ---- the walk inside a git directory ----

test("r4 22: git-annex's creds directory is hidden by name; the rest of annex is not", () =>
  fixture((r) => {
    const annex = path.join(r, ".git", "annex");
    fs.mkdirSync(path.join(annex, "creds"), { recursive: true });
    fs.writeFileSync(path.join(annex, "creds", "0f0f0f0f-aaaa-bbbb-cccc-000000000000"), "user secret\n");
    fs.mkdirSync(path.join(annex, "journal"));
    fs.writeFileSync(path.join(annex, "journal", "creds"), "a name, not the directory\n");
    const p = plan(opts(r));
    assert.ok(p.hide.includes(path.join(annex, "creds")));
    assert.ok(!p.hide.some((h) => h.startsWith(path.join(annex, "journal"))));
    assert.equal(p.problem, undefined);
  }));

test("r4 22: only the objects directly below lfs and annex are skipped: a socket below a deeper one is found", async () => {
  const r = fs.mkdtempSync(path.join(os.homedir(), "c-fourth-"));
  const deep = path.join(r, ".git", "annex", "tmp", "objects");
  const socket = path.join(deep, "s");
  execFileSync("git", ["init", "-q", r]);
  fs.mkdirSync(deep, { recursive: true });
  const server = net.createServer();
  await new Promise<void>((resolve) => server.listen(socket, resolve));
  try {
    assert.ok(discover([r]).sockets.has(socket));
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    fs.rmSync(r, { recursive: true, force: true });
  }
});

// ---- the ssh agent and a fetch that goes into submodules ----

// A project whose `origin` is `url`, with one cloned submodule under `modules/` whose own remote
// is `subUrl`.
function withSubmodule(url: string, subUrl: string, fn: (r: string, session: d.SessionState) => void) {
  fixture((r, g) => {
    g("remote", "add", "origin", url);
    const module = path.join(r, ".git", "modules", "sub");
    execFileSync("git", ["init", "-q", "--bare", module]);
    execFileSync("git", ["--git-dir", module, "remote", "add", "origin", subUrl]);
    const session = new d.SessionState(r);
    try {
      d.projectRoots(session);
      fn(r, session);
    } finally {
      d.closeGitSnapshot(session);
    }
  });
}
const SUBMODULE_REASON = /cloned submodules whose config and hooks are not checked.*--no-recurse-submodules/;

test("r4 25: an https project with an ssh submodule asks about a fetch or pull that may go into it", () =>
  withSubmodule("https://example.invalid/team/x.git", "git@example.invalid:team/sub.git", (r, session) => {
    for (const sub of ["fetch", "pull"]) {
      assert.match(d.sandboxBreaks(`git ${sub}`, r, session) ?? "", SUBMODULE_REASON, sub);
      assert.equal(d.sandboxBreaks(`git ${sub} --no-recurse-submodules`, r, session), undefined, sub);
      // Not the whole tool call: still asked about, for the agent it would need.
      assert.match(d.sandboxBreaks(`git ${sub} && git status`, r, session) ?? "", /would need your ssh agent/, sub);
    }
  }));

test("r4 25: git's last word on recursion counts", () =>
  withSubmodule("https://example.invalid/team/x.git", "git@example.invalid:team/sub.git", (r, session) => {
    assert.equal(d.sandboxBreaks("git fetch --recurse-submodules=yes --no-recurse-submodules", r, session), undefined);
    assert.match(d.sandboxBreaks("git fetch --no-recurse-submodules --recurse-submodules=yes", r, session) ?? "", /ssh agent/);
  }));

test("r4 25: the submodules are given as the reason only when they are why the agent was refused", () =>
  withSubmodule("git@example.invalid:team/x.git", "git@example.invalid:team/sub.git", (r, session) => {
    assert.match(d.sandboxBreaks("git fetch", r, session) ?? "", SUBMODULE_REASON);
    // An option off the agent's list: adding --no-recurse-submodules would not help.
    const other = d.sandboxBreaks("git fetch --jobs=2", r, session) ?? "";
    assert.match(other, /would need your ssh agent/);
    assert.doesNotMatch(other, /submodules/);
    assert.match(d.sandboxBreaks("git fetch --jobs=2 --no-recurse-submodules", r, session) ?? "", /would need your ssh agent/);
  }));

test("r4 25: an https submodule with a credential helper asks like the project's own remote would", () =>
  withSubmodule("https://example.invalid/team/x.git", "https://modules.example.invalid/team/sub.git", (r, session) => {
    // Your own config names a helper for the submodule's host alone.
    const global = process.env.GIT_CONFIG_GLOBAL!;
    const original = fs.readFileSync(global);
    fs.appendFileSync(global, '[credential "https://modules.example.invalid"]\n\thelper = store\n');
    try {
      assert.match(d.sandboxBreaks("git fetch", r, session) ?? "", /credential helper/);
      assert.equal(d.sandboxBreaks("git fetch --no-recurse-submodules", r, session), undefined);
    } finally {
      fs.writeFileSync(global, original);
    }
  }));

test("r4 25: what cannot be told below modules/ refuses the agent: a symbolic link, a directory that cannot be listed", () =>
  fixture((r, g) => {
    g("remote", "add", "origin", "git@example.invalid:team/x.git");
    const modules = path.join(r, ".git", "modules");
    fs.mkdirSync(path.join(modules, "group"), { recursive: true });
    const session = new d.SessionState(r);
    try {
      d.projectRoots(session);
      assert.equal(d.usesSsh("git fetch", r, session), true);
      const original = fs.readdirSync;
      fs.readdirSync = ((p: fs.PathLike, ...rest: unknown[]) => {
        if (String(p) === path.join(modules, "group")) throw Object.assign(new Error("EACCES"), { code: "EACCES" });
        return (original as (...args: unknown[]) => unknown)(p, ...rest);
      }) as typeof fs.readdirSync;
      try {
        assert.equal(d.usesSsh("git fetch", r, session), false, "a directory that cannot be listed");
      } finally {
        fs.readdirSync = original;
      }
      fs.symlinkSync("/somewhere/else", path.join(modules, "group", "link"));
      assert.equal(d.usesSsh("git fetch", r, session), false, "a symbolic link");
      assert.equal(d.usesSsh("git fetch --no-recurse-submodules", r, session), true);
    } finally {
      d.closeGitSnapshot(session);
    }
  }));

// ---- legacy remote files (.git/remotes, .git/branches) ----

test("r4 25: a remote that only a legacy file defines gets neither the agent nor a grant, and one the config defines keeps its URL", () =>
  fixture((r, g) => {
    commit(r);
    g("remote", "add", "origin", "git@example.invalid:team/x.git");
    const session = new d.SessionState(r);
    try {
      d.projectRoots(session);
      // What a call with a writable .git could plant.
      fs.mkdirSync(path.join(r, ".git", "remotes"), { recursive: true });
      fs.mkdirSync(path.join(r, ".git", "branches"), { recursive: true });
      fs.writeFileSync(path.join(r, ".git", "remotes", "planted"), "URL: git@elsewhere.invalid:their/x.git\nPush: refs/heads/*:refs/heads/*\nPull: refs/heads/*:refs/remotes/planted/*\n");
      fs.writeFileSync(path.join(r, ".git", "branches", "older"), "git@elsewhere.invalid:their/x.git#main\n");
      fs.writeFileSync(path.join(r, ".git", "remotes", "origin"), "URL: git@elsewhere.invalid:their/x.git\n");
      // git itself reads the files for a name the config does not define, and the config otherwise.
      assert.equal(g("ls-remote", "--get-url", "planted").trim(), "git@elsewhere.invalid:their/x.git");
      assert.equal(g("ls-remote", "--get-url", "older").trim(), "git@elsewhere.invalid:their/x.git");
      assert.equal(g("ls-remote", "--get-url", "origin").trim(), "git@example.invalid:team/x.git");
      for (const name of ["planted", "older"]) {
        for (const sub of ["fetch", "pull", "push", "ls-remote"]) assert.equal(d.usesSsh(`git ${sub} ${name}`, r, session), false, `${sub} ${name}`);
        assert.match(d.sandboxBreaks(`git fetch ${name}`, r, session) ?? "", /would need your ssh agent/);
      }
      // The names the session started with are unchanged, so `origin` is still `origin`.
      assert.equal(d.usesSsh("git fetch origin", r, session), true);
      assert.equal(d.usesSsh("git fetch --all", r, session), true);
    } finally {
      d.closeGitSnapshot(session);
    }
  }));

// ---- a push to a repository on this machine ----

test("r4 21: where a push goes, read from the command line and the remote's push URLs", () =>
  fixture((r, g) => {
    commit(r);
    fs.mkdirSync(path.join(r, "src"));
    const bare = path.join(r, "bare.git");
    execFileSync("git", ["init", "-q", "--bare", bare]);
    g("remote", "add", "origin", "https://example.invalid/team/x.git");
    g("remote", "add", "local", "../somewhere/else.git");
    g("remote", "add", "both", "https://example.invalid/team/x.git");
    g("remote", "set-url", "--add", "--push", "both", "https://example.invalid/team/x.git");
    g("remote", "set-url", "--add", "--push", "both", bare);
    const to = (command: string, cwd = r) => d.pushDestinations(command, cwd);
    // A remote that is not on this machine is nothing to grant.
    assert.deepEqual(to("git push origin main"), []);
    assert.deepEqual(to("git push"), []);
    assert.deepEqual(to("git push git@example.invalid:team/x.git main"), []);
    assert.deepEqual(to("git push ssh://example.invalid/team/x.git"), []);
    // A path: absolute, relative (from the top of the work tree, wherever git is run), file://.
    assert.deepEqual(to(`git push ${bare} main`), [bare]);
    assert.deepEqual(to("git push ./bare.git main"), [bare]);
    assert.deepEqual(to("cd src && git push ./bare.git main"), [bare]);
    assert.deepEqual(to(`git push file://${bare}`), [bare]);
    assert.deepEqual(to("git push local"), [path.resolve(r, "../somewhere/else.git")]);
    // Every push URL of the remote, of which one is local.
    assert.deepEqual(to("git push both main"), [bare]);
    // The remote is the first word that is no option's value.
    assert.deepEqual(to("git push -o ci.skip both main"), [bare]);
    assert.deepEqual(to("git push --push-option ci.skip --force-with-lease -q both"), [bare]);
    assert.deepEqual(to("git push --repo=both"), [bare]);
    assert.deepEqual(to("git push --tags origin"), []);
    // The remote git picks.
    g("config", "remote.pushDefault", "both");
    assert.deepEqual(to("git push"), [bare]);
    assert.deepEqual(to("git status && git push -q"), [bare]);
    // Not a push, or not a git-only call: nothing.
    assert.deepEqual(to("git fetch both"), []);
    assert.deepEqual(to("git push both; ls"), []);
  }));

test("r4 21: a push to a repository the walk found is granted like the one it comes from; any other asks, naming it", () =>
  fixture((r, g) => {
    commit(r);
    const allowed = fs.mkdtempSync(path.join(os.homedir(), "c-fourth-allowed-"));
    const outside = fs.mkdtempSync(path.join(os.homedir(), "c-fourth-outside-"));
    try {
      for (const dir of [allowed, outside]) execFileSync("git", ["init", "-q", "--bare", path.join(dir, "store.git")]);
      execFileSync("git", ["init", "-q", path.join(allowed, "checkout")]);
      const planFor = (command: string) => plan({ ...opts(r), allowedPaths: [allowed], gitCwds: d.gitDirectories(command, r), gitPushTo: d.pushDestinations(command, r) });
      const bare = planFor(`git push ${allowed}/store.git main`);
      assert.equal(bare.problem, undefined);
      assert.deepEqual([...bare.gitDirs].sort(), [path.join(allowed, "store.git"), path.join(r, ".git")].sort());
      // Its hooks and config stay read-only, as in every git directory a call may write.
      for (const name of ["hooks", "config"]) assert.ok(bare.ro.includes(path.join(allowed, "store.git", name)), name);
      assert.ok(!bare.ro.includes(path.join(allowed, "store.git")));
      // git also takes the path without its `.git`, and a checkout's directory.
      assert.ok(planFor(`git push ${allowed}/store main`).gitDirs.includes(path.join(allowed, "store.git")));
      assert.ok(planFor(`git push ${allowed}/checkout main`).gitDirs.includes(path.join(allowed, "checkout", ".git")));
      // Any other command of the same call shape gets no such grant.
      assert.ok(!planFor(`git fetch ${allowed}/store.git`).gitDirs.includes(path.join(allowed, "store.git")));
      assert.ok(planFor("git status").ro.includes(path.join(allowed, "store.git")));
      // A destination outside the project, the allowed paths and the temp directories.
      assert.match(planFor(`git push ${outside}/store.git main`).problem ?? "", new RegExp(`the push goes to ${outside}/store\\.git on this machine.*lies outside.*read-only`));
      // No repository there.
      assert.match(planFor(`git push ${allowed}/nothing main`).problem ?? "", new RegExp(`the push goes to ${allowed}/nothing on this machine.*no repository is there.*read-only`));
      // Two push URLs, one of them local.
      g("remote", "add", "both", "https://example.invalid/team/x.git");
      g("remote", "set-url", "--add", "--push", "both", "https://example.invalid/team/x.git");
      g("remote", "set-url", "--add", "--push", "both", path.join(allowed, "store.git"));
      assert.ok(planFor("git push both main").gitDirs.includes(path.join(allowed, "store.git")));
    } finally {
      for (const dir of [allowed, outside]) fs.rmSync(dir, { recursive: true, force: true });
    }
  }));
