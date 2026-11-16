// Round 4, group C, ninth pass: what the two checks of the eighth pass found. A symbolic link at
// any depth of a git directory that is read-only whole; a named directory compared in the order
// that matters, with what git reads or runs first and whole; `git -C` through the shared walk; a
// store outside what the sandbox lets a call write; `--no-gpg-sign`. (`CDPATH` as the shell has
// it is held at the hooks, test/plugin.test.mts.) Each test builds a repository of its own under
// the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-ninth.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import * as sb from "../sandbox.ts";
import { envKept, plan, protectedPaths, type Plan } from "../sandbox.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), `c-ninth-${name}-`)));
const gitIn = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const commit = (dir: string, message = "one") => gitIn(dir, "commit", "-q", "--allow-empty", "-m", message);
const write = (file: string, text: string | Buffer, mode?: number) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  if (mode !== undefined) fs.chmodSync(file, mode);
};
const sleep = (ms: number) => new Promise((done) => setTimeout(done, ms));

// An empty repository on `main` with a session that has seen nothing yet, removed afterwards
// with everything beside it that carries its name; `g` runs git in it.
async function fixture(fn: (r: string, g: (...args: string[]) => string, session: d.SessionState) => void | Promise<void>) {
  const r = scratch("repo");
  const g = (...args: string[]) => gitIn(r, ...args);
  const session = new d.SessionState(r);
  try {
    g("init", "-q", "-b", "main");
    await fn(r, g, session);
  } finally {
    d.closeGitSnapshot(session);
    fs.rmSync(r, { recursive: true, force: true });
    for (const beside of fs.readdirSync(path.dirname(r))) if (beside.startsWith(`${path.basename(r)}-`)) fs.rmSync(path.join(path.dirname(r), beside), { recursive: true, force: true });
  }
}
const opts = (r: string) => ({ project: r, projectRoots: [r], allowedPaths: [] as string[], cacheDirs: [], gitWritable: true, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [] });
// What the wrapper is handed of a plan, as index.ts hands it over.
const planEnv = (p: Plan): Record<string, string> => ({
  AUTOMODE_RW: p.rw.join("\n"),
  AUTOMODE_RO: p.ro.join("\n"),
  AUTOMODE_HIDE: p.hide.join("\n"),
  AUTOMODE_PIN: p.pin.join("\n"),
  AUTOMODE_TMPFS: p.tmpfs.join("\n"),
  AUTOMODE_REOPEN: p.reopen.join("\n"),
});
// One command under the real wrapper with a plan, as index.ts starts it.
function sandboxed(p: Plan, command: string, cwd: string, extra: Record<string, string> = {}) {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  const env: Record<string, string | undefined> = { ...process.env, ...extra };
  delete env.NODE_TEST_CONTEXT;
  const { keep, dropped } = envKept(env, []);
  for (const name of dropped) delete env[name];
  Object.assign(env, { AUTOMODE_ENV_KEEP: keep.join("\n"), AUTOMODE_SHELL: "/bin/bash", AUTOMODE_COMMAND: command, ...planEnv(p) });
  return spawnSync(WRAPPER, ["-c", command], { cwd, env, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 120_000 });
}
// The plan index.ts makes for an allowed git-only call.
const planFor = (r: string, command: string, cwd = r, more: Partial<ReturnType<typeof opts>> = {}) =>
  plan({ ...opts(r), ...more, gitCwds: d.gitDirectories(command, cwd), gitWriteCwds: d.gitWriteDirectories(command, cwd), gitMaintainCwds: d.gitMaintainDirectories(command, cwd), gitPushTo: d.pushDestinations(command, cwd) });
// The plan of a call that is not git-only: every git directory is read-only whole.
const plainPlan = (r: string) => plan({ ...opts(r), gitWritable: false });
// What makes an edit ask there.
const editProblems = (r: string) => protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).problems;
// The resume file, touched so that it is newer than everything so far.
function resuming() {
  const file = path.join(scratch("resume"), "resume");
  let last = 0;
  return {
    file,
    touch() {
      last = Math.max(last, Date.now()) + 10;
      fs.writeFileSync(file, "");
      fs.utimesSync(file, new Date(last), new Date(last));
    },
    remove: () => fs.rmSync(path.dirname(file), { recursive: true, force: true }),
  };
}
// Whether `fn` throws (the call then asks), with what it says.
const asks = (fn: () => unknown): string | undefined => {
  try {
    fn();
    return undefined;
  } catch (e) {
    return (e as Error).message || "threw";
  }
};
const FILE = ["-c", "protocol.file.allow=always"];
const LINK = /symbolic link in a git directory that is read-only for this call/;

// A project with the submodules `lib` and `other`, added for real from a repository beside it
// (git keeps their git directories under `.git/modules/`), and two commits on `main`.
async function withLib(fn: (r: string, session: d.SessionState, g: (...args: string[]) => string) => void | Promise<void>) {
  await fixture(async (r, g, session) => {
    const upstream = `${r}-lib-upstream`;
    execFileSync("git", ["init", "-q", "-b", "main", upstream]);
    write(path.join(upstream, "tracked"), "one\n");
    gitIn(upstream, "add", "tracked");
    gitIn(upstream, "commit", "-qm", "lib one");
    commit(r);
    g(...FILE, "submodule", "add", "-q", upstream, "lib");
    g(...FILE, "submodule", "add", "-q", upstream, "other");
    g("commit", "-qm", "two submodules");
    await fn(r, session, g);
  });
}

// `at` (a path in a git directory) moved to `target` (made there, a directory, when it is not
// in the git directory) with a link left in its place, for the time of `fn`. `text`: what the
// link holds, where that is not `target` itself (a relative path).
function linkedOut(at: string, target: string, fn: () => void, text = target) {
  const had = fs.existsSync(at);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  if (had) fs.renameSync(at, target);
  else fs.mkdirSync(target, { recursive: true });
  fs.mkdirSync(path.dirname(at), { recursive: true });
  fs.symlinkSync(text, at);
  try {
    fn();
  } finally {
    fs.rmSync(at);
    if (had) fs.renameSync(target, at);
    else fs.rmSync(target, { recursive: true, force: true });
  }
}

// ---- 1. a symbolic link anywhere in a git directory that is read-only whole ----

// The directories git reads and writes through, below the top of a git directory.
const DEEP_DIRS = ["refs/heads", "refs/tags", "refs/remotes", "objects/pack", "objects/info", "logs/refs", "info/sub", "lfs/objects/aa", "refs/remotes/origin/deeper/still"];

test("r4 21: a link below the top of the git directory around a module that leads into the project makes the call ask, and an edit, whatever git keeps there", () =>
  withLib((r, session, g) => {
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    d.projectRoots(session);
    assert.equal(planFor(r, "git status", lib).problem, undefined, "the fixture: without a link the call is planned");
    assert.deepEqual(editProblems(r), [], "the fixture: without a link an edit is not asked about");
    // A loose object's directory, as git made it.
    const fanout = fs.readdirSync(path.join(dotGit, "objects")).find((name) => /^[0-9a-f]{2}$/.test(name))!;
    for (const name of [...DEEP_DIRS, `objects/${fanout}`]) {
      const at = path.join(dotGit, name);
      linkedOut(at, path.join(r, "store", name), () => {
        for (const [who, problem] of [
          ["a call in the submodule", planFor(r, "git status", lib).problem],
          ["a call that is not git-only", plainPlan(r).problem],
          ["an edit", editProblems(r).find((text) => LINK.test(text))],
        ] as const) {
          assert.match(problem ?? "", LINK, `${name}, ${who}`);
          assert.ok((problem ?? "").includes(at), `${name}, ${who}: ${problem}`);
        }
      });
      // A relative link is the same link.
      linkedOut(at, path.join(r, "store", name), () => assert.match(planFor(r, "git status", lib).problem ?? "", LINK, `${name}, relative`), path.relative(path.dirname(at), path.join(r, "store", name)));
    }
    assert.equal(planFor(r, "git status", lib).problem, undefined, "the fixture: put back, the call is planned again");
    assert.equal(g("status", "--short").trim(), "");
  }));

test("r4 21: a link that is a file: a ref, info/exclude, a reflog, a hook linked to a script of the project", () =>
  withLib((r, session, g) => {
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    d.projectRoots(session);
    gitIn(r, "config", "core.logAllRefUpdates", "true");
    commit(r, "with a reflog");
    for (const name of ["refs/heads/main", "info/exclude", "logs/HEAD", "hooks/pre-commit", "packed-refs", "objects/info/alternates"]) {
      const at = path.join(dotGit, name);
      const target = path.join(r, "files", name.replaceAll("/", "-"));
      if (fs.existsSync(at)) {
        write(target, fs.readFileSync(at));
        fs.rmSync(at);
      } else write(target, "");
      fs.symlinkSync(target, at);
      try {
        // (Tenth pass: a hook linked straight to a script of the project is the one link that
        // does not ask; the script is made read-only instead, test/c-tenth.test.mts.)
        if (name === "hooks/pre-commit") {
          for (const p of [planFor(r, "git status", lib), plainPlan(r)]) {
            assert.equal(p.problem, undefined, p.problem);
            assert.ok(p.ro.includes(target), `${name}: the script is not read-only`);
          }
          assert.deepEqual(editProblems(r), []);
          continue;
        }
        for (const [who, problem] of [
          ["a call in the submodule", planFor(r, "git status", lib).problem],
          ["a call that is not git-only", plainPlan(r).problem],
          ["an edit", editProblems(r).find((text) => LINK.test(text))],
        ] as const) {
          assert.match(problem ?? "", LINK, `${name}, ${who}`);
          assert.ok((problem ?? "").includes(at), `${name}, ${who}: ${problem}`);
        }
      } finally {
        fs.rmSync(at);
        if (fs.readFileSync(target).length || name === "refs/heads/main") fs.copyFileSync(target, at);
      }
    }
    fs.rmSync(path.join(r, "files"), { recursive: true });
    assert.equal(planFor(r, "git status", lib).problem, undefined, "the fixture: put back, the call is planned again");
    assert.equal(g("status", "--short").trim(), "");
  }));

test("r4 21: a link below the top of another module's git directory, from a call in the module beside it", () =>
  withLib((r, session) => {
    const dotGit = path.join(r, ".git");
    d.projectRoots(session);
    const at = path.join(dotGit, "modules", "lib", "refs", "heads");
    linkedOut(at, path.join(r, "lib-heads"), () => {
      const problem = planFor(r, "git status", path.join(r, "other")).problem ?? "";
      assert.match(problem, LINK);
      assert.ok(problem.includes(at), problem);
      // The module's own call may write its refs anyway: it is not asked about.
      assert.equal(planFor(r, "git status", path.join(r, "lib")).problem, undefined);
    });
  }));

// Tenth pass, the maintainer's decision "any link asks": nothing is followed, every link asks
// wherever it leads, and the one named is the link in the git directory.
test("r4 21: a chain of links asks, wherever it ends: one that passes through a link the call could replace, one back into the project, one around it, one to nowhere, one that never ends", () =>
  withLib((r, session, g) => {
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    const outside = `${r}-outside`;
    d.projectRoots(session);
    const main = g("rev-parse", "main").trim();
    for (const name of ["refs", "refs/heads"]) {
      const at = path.join(dotGit, name);
      // `.git/<name>` -> `<project>/hop/a` -> a place outside every writable directory.
      fs.mkdirSync(path.join(r, "hop"), { recursive: true });
      fs.mkdirSync(path.dirname(path.join(outside, name)), { recursive: true });
      fs.renameSync(at, path.join(outside, name));
      fs.symlinkSync(path.join(outside, name), path.join(r, "hop", "a"));
      fs.symlinkSync(path.join(r, "hop", "a"), at);
      try {
        assert.equal(g("rev-parse", "main").trim(), main, "the fixture: git follows the chain");
        for (const [who, problem] of [
          ["a call in the submodule", planFor(r, "git status", lib).problem],
          ["a call that is not git-only", plainPlan(r).problem],
          ["an edit", editProblems(r).find((text) => LINK.test(text))],
        ] as const) {
          assert.match(problem ?? "", LINK, `${name}, ${who}`);
          assert.ok((problem ?? "").includes(at), `${name}, ${who}: ${problem}`);
        }
      } finally {
        fs.rmSync(at);
        fs.rmSync(path.join(r, "hop", "a"));
        fs.renameSync(path.join(outside, name), at);
      }
    }
    // The other way round: a link outside that leads back into the project ends where the call writes.
    fs.mkdirSync(outside, { recursive: true });
    fs.mkdirSync(path.join(r, "back"));
    fs.symlinkSync(path.join(r, "back"), path.join(outside, "hop"));
    linkedOut(path.join(dotGit, "refs", "tags"), path.join(r, "unused"), () => assert.match(planFor(r, "git status", lib).problem ?? "", LINK), path.join(outside, "hop"));
    // One that ends in a directory around the project: what git reads below it lies in the project.
    linkedOut(path.join(dotGit, "refs", "tags"), path.join(r, "unused"), () => {
      const problem = planFor(r, "git status", lib).problem ?? "";
      assert.match(problem, LINK);
      assert.ok(problem.includes(path.join(dotGit, "refs", "tags")), problem);
    }, path.dirname(r));
    // A link that leads nowhere yet: the place a command could make.
    linkedOut(path.join(dotGit, "refs", "tags"), path.join(r, "unused"), () => assert.match(planFor(r, "git status", lib).problem ?? "", LINK), path.join(r, "not", "there", "yet"));
    // A chain that never ends is no place anybody can vouch for.
    fs.symlinkSync(path.join(outside, "loop-b"), path.join(outside, "loop-a"));
    fs.symlinkSync(path.join(outside, "loop-a"), path.join(outside, "loop-b"));
    linkedOut(path.join(dotGit, "refs", "tags"), path.join(r, "unused"), () => assert.match(planFor(r, "git status", lib).problem ?? "", LINK), path.join(outside, "loop-a"));
  }));

// Tenth pass, the maintainer's decision "any link asks": a shared store outside the project asks
// for every call that has it read-only (the cost the decision names), and for an edit.
test("r4 21: a link that leads nowhere the call may write asks too: a shared store outside the project, another place in the same git directory, the module the call may write", () =>
  withLib((r, session) => {
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    const outside = `${r}-outside`;
    d.projectRoots(session);
    const asks = (at: string, what: string) => {
      for (const [who, problem] of [
        ["a call in the submodule", planFor(r, "git status", lib).problem],
        ["a call in the module beside it", planFor(r, "git status", path.join(r, "other")).problem],
        ["a call that is not git-only", plainPlan(r).problem],
        ["an edit", editProblems(r).find((text) => text.includes(at))],
      ] as const) {
        assert.match(problem ?? "", LINK, `${what}, ${who}`);
        assert.ok((problem ?? "").includes(at), `${what}, ${who}: ${problem}`);
      }
    };
    for (const name of ["objects", "objects/pack", "objects/info", "refs/heads", "logs", "info"]) {
      const at = path.join(dotGit, name);
      linkedOut(at, path.join(outside, name), () => asks(at, name));
    }
    // A link to another place in the same read-only git directory, at any depth.
    fs.symlinkSync(path.join(dotGit, "refs", "heads"), path.join(dotGit, "refs", "alias"));
    asks(path.join(dotGit, "refs", "alias"), "refs/alias");
    fs.rmSync(path.join(dotGit, "refs", "alias"));
    fs.symlinkSync("../hooks", path.join(dotGit, "info", "also-hooks"));
    asks(path.join(dotGit, "info", "also-hooks"), "info/also-hooks");
    fs.rmSync(path.join(dotGit, "info", "also-hooks"));
    // One that leads into the module the call may write.
    fs.symlinkSync(path.join(dotGit, "modules", "lib", "refs"), path.join(dotGit, "refs", "alias"));
    asks(path.join(dotGit, "refs", "alias"), "into the module");
    fs.rmSync(path.join(dotGit, "refs", "alias"));
    assert.equal(planFor(r, "git status", lib).problem, undefined, "the fixture: put back");
  }));

test("r4 21: a temp directory is writable in every sandbox: a link into one asks, for a call and for an edit alike", () =>
  fixture((r, _g, session) => {
    commit(r);
    d.projectRoots(session);
    const inTmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "c-ninth-heads-")));
    try {
      fs.rmSync(inTmp, { recursive: true });
      for (const name of ["refs", "refs/heads"]) {
        linkedOut(path.join(r, ".git", name), inTmp, () => {
          assert.match(plainPlan(r).problem ?? "", LINK, name);
          assert.ok(editProblems(r).some((text) => LINK.test(text)), `${name}: an edit is not asked about where a call is`);
        });
      }
    } finally {
      fs.rmSync(inTmp, { recursive: true, force: true });
    }
  }));

// Tenth pass: nothing is judged by where a link leads, so a link in such a repository is left
// wherever it leads, as the rest of such a repository is: any call can build a new repository
// there anyway (the ninth pass asked for one that led into the project).
test("r4 21: a repository in a shared temp directory: a link there is left, wherever it leads, as the rest of such a repository is", () =>
  fixture((r, _g, session) => {
    commit(r);
    d.projectRoots(session);
    const shared = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "c-ninth-shared-")));
    try {
      execFileSync("git", ["init", "-q", "-b", "main", path.join(shared, "repo")]);
      const heads = path.join(shared, "repo", ".git", "refs", "heads");
      assert.equal(plainPlan(r).problem, undefined, "the fixture");
      linkedOut(heads, path.join(shared, "heads-store"), () => {
        assert.equal(plainPlan(r).problem, undefined);
        assert.deepEqual(editProblems(r), []);
      });
      linkedOut(heads, path.join(r, "heads-store"), () => {
        assert.equal(plainPlan(r).problem, undefined);
        assert.deepEqual(editProblems(r), []);
      });
      // More entries than the walk lists is nobody's problem there either.
      const before = sb.linkLimits.entries;
      for (let n = 0; n < 300; n++) write(path.join(shared, "repo", ".git", "branches", `a${n}`), "");
      sb.linkLimits.entries = 250;
      try {
        assert.equal(plainPlan(r).problem, undefined);
      } finally {
        sb.linkLimits.entries = before;
      }
    } finally {
      fs.rmSync(shared, { recursive: true, force: true });
    }
  }));

test("r4 21: the walk for links is bounded, and past its bound or its depth the call asks; loose objects are passed over, a link among them is not", () =>
  fixture((r, _g, session) => {
    commit(r);
    d.projectRoots(session);
    const dotGit = path.join(r, ".git");
    const limits = sb.linkLimits;
    const before = { ...limits };
    try {
      // The reading's probe D: nine directories down, below modules/.
      const deep = path.join(dotGit, "modules", "1", "2", "3", "4", "5", "6", "7", "8", "9");
      fs.mkdirSync(deep, { recursive: true });
      fs.mkdirSync(path.join(r, "elsewhere"));
      fs.symlinkSync(path.join(r, "elsewhere"), path.join(deep, "lib"));
      assert.match(plainPlan(r).problem ?? "", LINK);
      fs.rmSync(path.join(deep, "lib"));
      assert.equal(plainPlan(r).problem, undefined);
      // Deeper than the walk goes: said, not passed over.
      limits.depth = 6;
      assert.match(plainPlan(r).problem ?? "", /more than 6 directories deep/);
      assert.ok(editProblems(r).some((text) => /more than 6 directories deep/.test(text)));
      limits.depth = before.depth;
      fs.rmSync(path.join(dotGit, "modules"), { recursive: true });
      // More entries than the walk lists, wherever they are.
      for (const junk of ["branches", "refs/heads/junk", "info", "."]) {
        for (let n = 0; n < 300; n++) write(path.join(dotGit, junk, `a${String(n).padStart(6, "0")}`), "");
        limits.entries = 250;
        assert.match(plainPlan(r).problem ?? "", /holds more than 250 entries, too many to look for symbolic links/, junk);
        assert.ok(editProblems(r).some((text) => /too many to look for symbolic links/.test(text)), junk);
        limits.entries = before.entries;
        assert.equal(plainPlan(r).problem, undefined, junk);
        for (let n = 0; n < 300; n++) fs.rmSync(path.join(dotGit, junk, `a${String(n).padStart(6, "0")}`));
      }
      // Loose objects and packs are files, and files there are not counted: many of them change nothing.
      for (let n = 0; n < 300; n++) write(path.join(dotGit, "objects", "aa", `object-${n}`), "x");
      for (let n = 0; n < 300; n++) write(path.join(dotGit, "objects", "pack", `pack-${n}.pack`), "x");
      limits.entries = 250;
      assert.equal(plainPlan(r).problem, undefined);
      // A link among them is found, and a directory among them is looked into.
      fs.symlinkSync(path.join(r, "elsewhere"), path.join(dotGit, "objects", "aa", "zz-link"));
      assert.match(plainPlan(r).problem ?? "", LINK);
      fs.rmSync(path.join(dotGit, "objects", "aa", "zz-link"));
      fs.mkdirSync(path.join(dotGit, "objects", "pack", "zz-dir"));
      fs.symlinkSync(path.join(r, "elsewhere"), path.join(dotGit, "objects", "pack", "zz-dir", "link"));
      assert.match(plainPlan(r).problem ?? "", LINK);
      fs.rmSync(path.join(dotGit, "objects", "pack", "zz-dir"), { recursive: true });
      // A directory of the store that cannot be listed may hold one: said.
      fs.chmodSync(path.join(dotGit, "objects", "aa"), 0o000);
      try {
        assert.match(plainPlan(r).problem ?? "", /objects\/aa cannot be listed \(EACCES\), so the symbolic links in it cannot be looked for/);
      } finally {
        fs.chmodSync(path.join(dotGit, "objects", "aa"), 0o755);
      }
      assert.equal(plainPlan(r).problem, undefined);
      // They have a bound of their own.
      limits.objects = 500;
      assert.match(plainPlan(r).problem ?? "", /holds more than 500 objects, too many to look for symbolic links/);
      limits.objects = before.objects;
      assert.equal(plainPlan(r).problem, undefined);
    } finally {
      Object.assign(limits, before);
    }
  }));

test("r4 21: a repository the call works in: a link among its refs is its own; a hook linked to a script of the project has the script protected, and one linked outside asks for every call", () =>
  fixture((r, g, session) => {
    commit(r);
    d.projectRoots(session);
    const dotGit = path.join(r, ".git");
    // The call may write its own refs anyway: a link there is not asked about.
    linkedOut(path.join(dotGit, "refs", "heads"), path.join(r, "heads-store"), () => {
      const p = planFor(r, "git commit --allow-empty -m two");
      assert.equal(p.problem, undefined);
      assert.equal(sandboxed(p, "git commit -q --allow-empty -m two", r).status, 0);
      // Every other call has the directory read-only whole.
      assert.match(plainPlan(r).problem ?? "", LINK);
    });
    assert.equal(g("log", "-1", "--format=%s").trim(), "two");
    // A hook installed as a link to a script of the project (tenth pass, "protect the script"):
    // every call is planned with the script read-only, and an edit of the script asks.
    write(path.join(r, "scripts", "pre-commit"), "#!/bin/sh\nexit 0\n", 0o755);
    fs.symlinkSync("../../scripts/pre-commit", path.join(dotGit, "hooks", "pre-commit"));
    for (const p of [plainPlan(r), planFor(r, "git status")]) {
      assert.equal(p.problem, undefined, p.problem);
      assert.ok(p.ro.includes(path.join(r, "scripts", "pre-commit")));
    }
    assert.deepEqual(editProblems(r), []);
    // A call in a linked worktree has `modules/` and `worktrees/` of the common directory
    // closed, and no more: the refs it shares are its own too.
    const feature = `${r}-feature`;
    g("worktree", "add", "-q", "-b", "feature", feature);
    const inFeature = () => plan({ ...opts(r), projectRoots: [r, feature], gitCwds: [feature], gitWriteCwds: [feature], gitMaintainCwds: [], gitPushTo: [] });
    assert.match(inFeature().problem ?? "", /^$/, "the hook link has the one shape that is planned");
    fs.mkdirSync(path.join(dotGit, "modules", "deep"), { recursive: true });
    fs.symlinkSync(path.join(r, "scripts"), path.join(dotGit, "modules", "deep", "link"));
    assert.match(inFeature().problem ?? "", LINK, "below modules/, which is closed for it");
    fs.rmSync(path.join(dotGit, "modules"), { recursive: true });
    g("worktree", "remove", "--force", feature);
    // One that leads outside the project has no script that can be held (tenth pass, "any link
    // asks"): every call asks, a git-only one in the repository itself too, and an edit.
    fs.rmSync(path.join(dotGit, "hooks", "pre-commit"));
    write(`${r}-outside/pre-commit`, "#!/bin/sh\nexit 0\n", 0o755);
    fs.symlinkSync(`${r}-outside/pre-commit`, path.join(dotGit, "hooks", "pre-commit"));
    assert.match(plainPlan(r).problem ?? "", /symbolic link among the hooks/);
    assert.match(planFor(r, "git status").problem ?? "", /symbolic link among the hooks/);
    assert.ok(editProblems(r).some((text) => /symbolic link among the hooks/.test(text)));
  }));

// ---- 2. a named directory, compared in the order that matters ----

const junk = (dir: string, count: number) => {
  for (let n = 0; n < count; n++) write(path.join(dir, `a${String(n).padStart(6, "0")}`), "");
};
// What git reads or runs in a git directory: each a change made between the prompt and the touch.
const READ_OR_RUN: [string, (nested: string) => void][] = [
  ["a hook", (nested) => write(path.join(nested, "hooks", "pre-push"), "#!/bin/sh\ntouch /tmp/never\n", 0o755)],
  ["a config line", (nested) => fs.appendFileSync(path.join(nested, "config"), "[core]\n\tfsmonitor = touch /tmp/never\n")],
  ["info/attributes", (nested) => write(path.join(nested, "info", "attributes"), "* filter=evil\n")],
  ["a ref", (nested) => write(path.join(nested, "refs", "heads", "x"), "0000000000000000000000000000000000000001\n")],
  ["packed-refs", (nested) => write(path.join(nested, "packed-refs"), "0000000000000000000000000000000000000001 refs/heads/y\n")],
  ["HEAD, same size", (nested) => fs.writeFileSync(path.join(nested, "HEAD"), fs.readFileSync(path.join(nested, "HEAD"), "utf8").replace("main", "evil"))],
  ["a todo list", (nested) => write(path.join(nested, "rebase-merge", "git-rebase-todo"), "exec touch /tmp/never\n")],
  ["a sequencer todo", (nested) => write(path.join(nested, "sequencer", "todo"), "pick 0000001 x\n")],
  ["alternates", (nested) => write(path.join(nested, "objects", "info", "alternates"), "/tmp/elsewhere/objects\n")],
  ["a reflog", (nested) => write(path.join(nested, "logs", "HEAD"), "x\n")],
  ["config.worktree", (nested) => write(path.join(nested, "config.worktree"), "[core]\n\thooksPath = /tmp/never\n")],
];

test("r4 21: files that fill a named directory do not push what git reads or runs in it past the bound: each such change is named again, wherever the files are", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const before = { ...d.fingerprintLimits };
    try {
      commit(r);
      d.projectRoots(session);
      d.fingerprintLimits.entries = 120;
      let n = 0;
      for (const place of ["branches", ".", "objects/aa", "zzz-unknown"]) {
        for (const [what, change] of READ_OR_RUN) {
          const top = path.join(r, `n${n++}`);
          execFileSync("git", ["init", "-q", "-b", "main", top]);
          const nested = path.join(top, ".git");
          junk(path.join(nested, place), 300);
          const first = d.gitTampered(session, resume.file) ?? "";
          assert.ok(first.includes(`${nested} appeared`), `${place}, ${what}: ${first}`);
          change(nested);
          resume.touch();
          assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), `files in ${place}: ${what} joined the baseline unseen`);
          // The prompt says what is compared.
          assert.match(first, /holds more than 120 entries besides what git reads or runs in it: its hooks, config, HEAD, info\/, packed-refs, operation state, refs\/ and logs\/ are compared whole, and so are the hooks, config, state files and info\/ of each module and worktree in it, and of everything else only the first 120 entries/, `${place}, ${what}`);
          // Shown as it is now: taken in, with what lies past the bound, as the prompt said.
          write(path.join(nested, place, "zzzzzz-last"), "past the bound");
          resume.touch();
          assert.equal(d.gitTampered(session, resume.file), undefined, `${place}, ${what}`);
          fs.rmSync(top, { recursive: true });
          resume.touch();
          d.gitTampered(session, resume.file);
          resume.touch();
          assert.equal(d.gitTampered(session, resume.file), undefined, `${place}, ${what}: the fixture, removed again`);
        }
      }
    } finally {
      Object.assign(d.fingerprintLimits, before);
      resume.remove();
    }
  }));

test("r4 21: of everything else, an object store and a directory git does not know are compared last: a module's hook and a worktree's HEAD come before them", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const before = { ...d.fingerprintLimits };
    try {
      commit(r);
      d.projectRoots(session);
      d.fingerprintLimits.entries = 120;
      const changes: [string, (nested: string) => void][] = [
        ["a module's hook", (nested) => write(path.join(nested, "modules", "m", "hooks", "pre-push"), "#!/bin/sh\ntouch /tmp/never\n", 0o755)],
        ["a linked worktree's HEAD", (nested) => write(path.join(nested, "worktrees", "w", "HEAD"), "ref: refs/heads/evil\n")],
      ];
      let n = 0;
      for (const place of ["objects/aa", "lfs/objects/aa", "branches", "aaa-unknown/deep"]) {
        for (const [what, change] of changes) {
          const top = path.join(r, `n${n++}`);
          execFileSync("git", ["init", "-q", "-b", "main", top]);
          const nested = path.join(top, ".git");
          write(path.join(nested, "modules", "m", "hooks", "pre-commit.sample"), "");
          write(path.join(nested, "worktrees", "w", "gitdir"), "/nowhere\n");
          junk(path.join(nested, place), 300);
          const first = d.gitTampered(session, resume.file) ?? "";
          assert.ok(first.includes(`${nested} appeared`), `${place}, ${what}: ${first}`);
          assert.match(first, /only the first 120 entries/, `${place}, ${what}`);
          change(nested);
          resume.touch();
          assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), `files in ${place}: ${what} joined the baseline unseen`);
          resume.touch();
          assert.equal(d.gitTampered(session, resume.file), undefined, `${place}, ${what}`);
        }
      }
    } finally {
      Object.assign(d.fingerprintLimits, before);
      resume.remove();
    }
  }));

test("r4 21: where what git reads or runs does not fit its own allowance the prompt says which part, and no touch takes it in: it asks again until it fits", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const before = { ...d.fingerprintLimits };
    try {
      commit(r);
      d.projectRoots(session);
      d.fingerprintLimits.first = 120;
      const parts: [string, RegExp][] = [
        ["hooks", /its hooks \(more than 120 entries\)/],
        ["info", /info\/ \(more than 120 entries\)/],
        ["refs/heads", /refs\/ \(more than 120 entries\)/],
        ["logs/refs", /logs\/ \(more than 120 entries\)/],
        ["rebase-merge", /the state of an operation .* \(more than 120 entries\)/],
      ];
      for (const [n, [place, says]] of parts.entries()) {
        execFileSync("git", ["init", "-q", "-b", "main", path.join(r, `n${n}`)]);
        const nested = path.join(r, `n${n}`, ".git");
        junk(path.join(nested, place), 300);
        const first = d.gitTampered(session, resume.file) ?? "";
        assert.ok(first.includes(`${nested} appeared`), `${place}: ${first}`);
        assert.match(first, /cannot be compared whole where it matters/, place);
        assert.match(first, says, place);
        assert.match(first, /Nothing of it is taken in unseen/, place);
        // Nothing changed, and the touch does not resume: once, and again.
        for (const again of [1, 2]) {
          resume.touch();
          const next = d.gitTampered(session, resume.file) ?? "";
          assert.ok(next.includes(`${nested} appeared`), `${place}: taken in at touch ${again} with a part of it unseen`);
          assert.match(next, says, place);
        }
        // A hook added meanwhile is in nobody's baseline either.
        write(path.join(nested, "hooks", "pre-push"), "#!/bin/sh\ntouch /tmp/never\n", 0o755);
        resume.touch();
        assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), place);
        // Made to fit, it is shown as it is now, and the next touch takes it in.
        for (let k = 0; k < 300; k++) fs.rmSync(path.join(nested, place, `a${String(k).padStart(6, "0")}`));
        resume.touch();
        const fits = d.gitTampered(session, resume.file) ?? "";
        assert.ok(fits.includes(`${nested} appeared`), place);
        assert.doesNotMatch(fits, /cannot be compared whole/, place);
        resume.touch();
        assert.equal(d.gitTampered(session, resume.file), undefined, place);
      }
      // So is a part whose files are too much to read in all.
      Object.assign(d.fingerprintLimits, before);
      d.fingerprintLimits.firstBytes = 100 * 1024;
      execFileSync("git", ["init", "-q", "-b", "main", path.join(r, "much")]);
      for (const name of ["pre-push", "pre-commit"]) write(path.join(r, "much", ".git", "hooks", name), `#!/bin/sh\n${"#".repeat(60 * 1024)}\n`, 0o755);
      assert.match(d.gitTampered(session, resume.file) ?? "", /cannot be compared whole where it matters: its hooks \(more than 102400 bytes in all\)/);
      fs.rmSync(path.join(r, "much"), { recursive: true });
      resume.touch();
      d.gitTampered(session, resume.file);
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined, "the fixture, removed again");
      // A file of it too large to read is the same.
      Object.assign(d.fingerprintLimits, before);
      d.fingerprintLimits.firstBytes = 100 * 1024;
      execFileSync("git", ["init", "-q", "-b", "main", path.join(r, "large")]);
      const nested = path.join(r, "large", ".git");
      write(path.join(nested, "hooks", "pre-push"), `#!/bin/sh\n${"#".repeat(150 * 1024)}\n`, 0o755);
      const first = d.gitTampered(session, resume.file) ?? "";
      assert.match(first, /cannot be compared whole where it matters: its hooks \(.*pre-push is larger than 102400 bytes\)/);
      resume.touch();
      assert.match(d.gitTampered(session, resume.file) ?? "", /cannot be compared whole/);
      write(path.join(nested, "hooks", "pre-push"), "#!/bin/sh\nexit 0\n", 0o755);
      resume.touch();
      assert.doesNotMatch(d.gitTampered(session, resume.file) ?? "", /cannot be compared whole|^$/);
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
    } finally {
      Object.assign(d.fingerprintLimits, before);
      resume.remove();
    }
  }));

// A file rewritten in place: the same size, the same inode, its times set back.
function rewritten(file: string, text: string) {
  const st = fs.statSync(file);
  const fd = fs.openSync(file, "r+");
  fs.writeSync(fd, text, 0);
  fs.closeSync(fd);
  fs.utimesSync(file, st.atime, st.mtime);
  assert.equal(fs.statSync(file).size, st.size);
  assert.equal(fs.statSync(file).ino, st.ino);
}

test("r4 21: a hook, a config, a file under info/ or a todo list is known by its contents whatever its size: rewritten in place right after the prompt, it is named again", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      const pad = "#".repeat(70 * 1024);
      const kinds: [string, string, string][] = [
        ["hooks/pre-push", `#!/bin/sh\n${pad}\n`, "#!/bin/sh\ntouch /tmp/never\n#"],
        ["config", `[core]\n\tbare = false\n${pad}\n`, "[core]\n\tfsmonitor = touch /tmp/never\n#"],
        ["info/exclude", `${pad}\n`, "*\n"],
        ["rebase-merge/git-rebase-todo", `${pad}\n`, "exec touch /tmp/never\n"],
        ["refs/heads/big", `${pad}\n`, "0000000000000000000000000000000000000001\n"],
        ["modules/m/hooks/pre-push", `#!/bin/sh\n${pad}\n`, "#!/bin/sh\ntouch /tmp/never\n#"],
      ];
      // A rewrite that falls into the tick of the kernel's clock the file last changed in leaves
      // its size, inode and change time as they were (27 of 40 runs for a reviewer). Made so
      // here every time: the file's times are reported as they were before the rewrite.
      const original = fs.lstatSync;
      let frozen: { file: string; st: fs.BigIntStats } | undefined;
      fs.lstatSync = ((p: fs.PathLike, o?: fs.StatOptions) => {
        const st = (original as any)(p, o);
        if (frozen && p === frozen.file && o?.bigint) {
          assert.equal(st.size, frozen.st.size);
          assert.equal(st.ino, frozen.st.ino);
          return frozen.st;
        }
        return st;
      }) as typeof fs.lstatSync;
      try {
        for (const [n, [name, text, other]] of kinds.entries()) {
          const top = path.join(r, `n${n}`);
          execFileSync("git", ["init", "-q", "-b", "main", top]);
          const nested = path.join(top, ".git");
          const file = path.join(nested, name);
          write(file, text, 0o755);
          assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), name);
          frozen = { file, st: original(file, { bigint: true }) };
          rewritten(file, other);
          resume.touch();
          assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), `${name} rewritten in place joined the baseline unseen`);
          resume.touch();
          assert.equal(d.gitTampered(session, resume.file), undefined, name);
          frozen = undefined;
        }
      } finally {
        fs.lstatSync = original;
      }
    } finally {
      resume.remove();
    }
  }));

test("r4 21: what is known by size, inode and change time alone: a large file git does not read or run, and an object, rewritten in place a clock's tick later, is named by its change time", () =>
  fixture(async (r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      for (const [n, name] of ["lfs/tmp/blob", "objects/aa/object", "unknown-large"].entries()) {
        const top = path.join(r, `n${n}`);
        execFileSync("git", ["init", "-q", "-b", "main", top]);
        const nested = path.join(top, ".git");
        write(path.join(nested, name), "a".repeat(70 * 1024));
        assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), name);
        // Past the tick of the kernel's clock (about 4 ms): the change time is another.
        await sleep(60);
        rewritten(path.join(nested, name), "b");
        resume.touch();
        assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), `${name} rewritten in place joined the baseline unseen`);
        resume.touch();
        assert.equal(d.gitTampered(session, resume.file), undefined, name);
      }
    } finally {
      resume.remove();
    }
  }));

test("r4 21: an operation's own directory a pause named: files that fill it do not push what a continued rebase reads past the bound", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const before = { ...d.fingerprintLimits };
    try {
      commit(r);
      d.projectRoots(session);
      d.fingerprintLimits.entries = 120;
      const dotGit = path.join(r, ".git");
      const call = d.noteGitCall(session, "git status", [dotGit])!;
      junk(path.join(dotGit, "rebase-merge"), 300);
      write(path.join(dotGit, "rebase-merge", "git-rebase-todo"), "pick 0000001 x\n");
      call.done = true;
      assert.match(d.gitStateTampered(session) ?? "", /rebase-merge appeared/);
      // The merge strategy a continued rebase runs (`git-merge-<name>`, a program found by name).
      write(path.join(dotGit, "rebase-merge", "strategy"), "evil\n");
      resume.touch();
      const second = d.gitTampered(session, resume.file) ?? "";
      assert.match(second, /rebase-merge/, `the strategy joined the baseline unseen: ${JSON.stringify(second)}`);
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
    } finally {
      Object.assign(d.fingerprintLimits, before);
      resume.remove();
    }
  }));

test("r4 21: the hooks path a named repository configures and the files its config includes are compared with it, where they lie beside it", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      const changes: [string, (top: string) => void][] = [
        ["a hook under core.hooksPath", (top) => write(path.join(top, ".hk", "pre-commit"), "#!/bin/sh\ntouch /tmp/never\n", 0o755)],
        ["an included config file", (top) => fs.appendFileSync(path.join(top, "extra.cfg"), "[core]\n\tfsmonitor = touch /tmp/never\n")],
      ];
      for (const [n, [what, change]] of changes.entries()) {
        const top = path.join(r, `n${n}`);
        execFileSync("git", ["init", "-q", "-b", "main", top]);
        const nested = path.join(top, ".git");
        fs.mkdirSync(path.join(top, ".hk"));
        write(path.join(top, "extra.cfg"), "[user]\n\tname = x\n");
        gitIn(top, "config", "core.hooksPath", ".hk");
        gitIn(top, "config", "include.path", "../extra.cfg");
        const first = d.gitTampered(session, resume.file) ?? "";
        assert.ok(first.includes(`${nested} appeared`), `${what}: ${first}`);
        change(top);
        resume.touch();
        assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), `${what} joined the baseline unseen`);
        resume.touch();
        assert.equal(d.gitTampered(session, resume.file), undefined, what);
      }
    } finally {
      resume.remove();
    }
  }));

// ---- 3. git -C through the shared walk ----

test("r4 21: git -C through /proc/self is the walker's own directory to this process and git's own to git: it names no place, and never the plugin's directory", () =>
  fixture((r, _g, session) => {
    commit(r);
    d.projectRoots(session);
    assert.notEqual(fs.realpathSync(process.cwd()), r, "the fixture: this process is somewhere else");
    const mine = fs.realpathSync(process.cwd());
    for (const word of ["/proc/self/cwd", "/proc/self/cwd/.", "/proc/thread-self/cwd", `/proc/${process.pid}/cwd`, "/proc/self/root/proc/self/cwd"]) {
      // A command that only reads is granted nothing; one that writes asks.
      assert.deepEqual(d.gitDirectories(`git -C ${word} status`, r), [], word);
      assert.match(asks(() => d.gitDirectories(`git -C ${word} commit -m x`, r)) ?? "", /cannot tell which directory git -C/, word);
      assert.match(asks(() => d.gitWriteDirectories(`git -C ${word} add -A`, r)) ?? "", /cannot tell which directory git -C/, word);
      // What an approved command creates there is expected nowhere of this process's.
      for (const made of d.expectedRepos(`git -C ${word} init`, r) ?? []) assert.ok(!made.startsWith(mine), `${word}: ${made}`);
    }
    // The signing and recursion reads go to no other repository's config either: this
    // process's own directory is a repository that signs, the call's is not.
    const had = process.cwd();
    const signing = `${r}-signing`;
    execFileSync("git", ["init", "-q", "-b", "main", signing]);
    gitIn(signing, "config", "commit.gpgsign", "true");
    process.chdir(signing);
    try {
      assert.doesNotMatch(d.sandboxBreaks("git -C /proc/self/cwd commit -m x", r, session) ?? "", /signs/);
    } finally {
      process.chdir(had);
    }
    // The forms that were read before are read as before.
    fs.mkdirSync(path.join(r, "a", "b"), { recursive: true });
    assert.deepEqual(d.gitDirectories("git -C a add x.txt", r), [path.join(r, "a")]);
    assert.deepEqual(d.gitDirectories("git -C a -C b status", r), [path.join(r, "a", "b")]);
    assert.deepEqual(d.gitDirectories("git -C '' add -A", r), [r]);
    assert.deepEqual(d.gitDirectories("git -C a -C '' -C b add -A", r), [path.join(r, "a", "b")]);
    assert.deepEqual(d.gitDirectories("git -C ~ status", r), [fs.realpathSync(os.homedir())]);
    assert.deepEqual(d.expectedRepos("git -C a init", r), [path.join(r, "a")]);
    assert.deepEqual(d.expectedRepos("git -C '' init fresh", r), [path.join(r, "fresh")]);
    assert.match(asks(() => d.gitDirectories("git -C nowhere add -A", r)) ?? "", /cannot tell which directory git -C/);
    assert.match(asks(() => d.gitDirectories("git -C ~nobody add -A", r)) ?? "", /cannot tell|names/);
  }));

// ---- 5. what only fails in the sandbox asks ----

const STORE_OUTSIDE = /outside what the sandbox lets the call write/;

test("r4 21: a repository whose objects or refs is a link to a store outside every writable directory: a git command that writes there asks, and one that reads runs", () =>
  fixture((r, g, session) => {
    write(path.join(r, "a.txt"), "a\n");
    g("add", "a.txt");
    g("commit", "-qm", "one");
    d.projectRoots(session);
    const dotGit = path.join(r, ".git");
    const both = ["git commit -m x", "git commit --allow-empty -m x", "git stash", "git -C . commit -m x", "git fetch", "git gc", "git tag -a v2 -m x", "git merge topic"];
    // What a command writes of the two: the ones that plainly leave one alone work there.
    const only: Record<string, string[]> = { objects: ["git add a.txt", "git status && git add -A"], refs: ["git branch topic2", "git tag v1", "git reset HEAD", "git switch -c feat", "git checkout -b feat"] };
    const neither = ["git switch main", "git checkout main", "git mv a.txt b.txt", "git restore --staged a.txt", "git checkout -- a.txt"];
    const readers = ["git status", "git log --oneline -3", "git diff", "git branch", "git status && git log -1", "git tag -l", "git stash list", ...neither];
    for (const text of [...both, ...only.objects, ...only.refs, ...readers]) assert.equal(d.sandboxBreaks(text, r, session), undefined, `the fixture, ${text}`);
    for (const name of ["objects", "refs"]) {
      const writers = [...both, ...only[name]];
      const others = [...readers, ...only[name === "objects" ? "refs" : "objects"]];
      linkedOut(path.join(dotGit, name), `${r}-store/${name}`, () => {
        assert.equal(g("status", "--short").trim(), "", "the fixture: git follows the link");
        // Run for real: what is not asked about works with the store read-only.
        for (const text of name === "objects" ? ["git branch probe-1", "git tag probe-1", "git switch main", "git switch -c probe-2", "git switch main"] : ["git add a.txt", "git switch main"]) {
          assert.equal(d.sandboxBreaks(text, r, session), undefined, `${name}, ${text}`);
          const worked = sandboxed(planFor(r, text), text, r);
          assert.equal(worked.status, 0, `${name}, ${text}: ${worked.stderr}`);
        }
        for (const text of writers) {
          const broken = d.sandboxBreaks(text, r, session) ?? "";
          assert.match(broken, STORE_OUTSIDE, `${name}, ${text}`);
          assert.ok(broken.includes(`${r}-store/${name}`), broken);
          assert.match(broken, /an approved run happens outside the sandbox/);
        }
        for (const text of others) assert.equal(d.sandboxBreaks(text, r, session), undefined, `${name}, ${text}`);
        // What it is asked about for: the plan has no problem, and run for real the commit fails.
        fs.appendFileSync(path.join(r, "a.txt"), `${name}\n`);
        const p = planFor(r, "git add a.txt && git commit -m x");
        assert.equal(p.problem, undefined, name);
        const ran = sandboxed(p, "git add a.txt && git commit -m x", r);
        assert.notEqual(ran.status, 0, name);
        assert.match(ran.stderr, /Read-only file system/, name);
        assert.equal(sandboxed(p, "git status --short && git log --oneline -1", r).status, 0, name);
        // A store in a directory the sandbox leaves writable is written, and nobody asks.
        assert.equal(d.sandboxBreaks("git commit -m x", r, session, [`${r}-store`]), undefined, name);
        const open = planFor(r, "git add a.txt && git commit -m x", r, { allowedPaths: [`${r}-store`] });
        assert.equal(open.problem, undefined, name);
        const done = sandboxed(open, `git add a.txt && git commit -qm in-${name}`, r);
        assert.equal(done.status, 0, `${name}: ${done.stderr}`);
      });
      assert.equal(g("log", "-1", "--format=%s").trim(), `in-${name}`);
    }
    // In a linked worktree the store is the common directory's.
    const feature = `${r}-feature`;
    g("worktree", "add", "-q", "-b", "feature", feature);
    assert.equal(d.sandboxBreaks("git commit --allow-empty -m x", feature, session, [feature]), undefined);
    linkedOut(path.join(dotGit, "objects"), `${r}-store/objects`, () => {
      assert.match(d.sandboxBreaks("git commit --allow-empty -m x", feature, session, [feature]) ?? "", STORE_OUTSIDE);
      assert.equal(d.sandboxBreaks("git status", feature, session, [feature]), undefined);
    });
  }));

test("r4 27: --no-gpg-sign signs nothing, whatever the config says: the commit is not asked about for signing; the last of it and -S counts, and a message is no option", () =>
  fixture((r, g, session) => {
    commit(r);
    g("branch", "topic");
    d.projectRoots(session);
    const SIGNS = /git signs/;
    const plain = ["git commit -m x", "git commit --allow-empty -m x", "git merge topic", "git rebase topic", "git cherry-pick topic", "git revert --no-edit HEAD", "git pull"];
    for (const text of plain) assert.doesNotMatch(d.sandboxBreaks(text, r, session) ?? "", SIGNS, `the fixture, ${text}`);
    g("config", "commit.gpgsign", "true");
    for (const text of plain) assert.match(d.sandboxBreaks(text, r, session) ?? "", SIGNS, text);
    for (const text of [
      "git commit --no-gpg-sign -m x",
      "git commit -m x --no-gpg-sign",
      "git commit -S --no-gpg-sign -m x",
      "git commit --gpg-sign=ABCD --no-gpg-sign -m x",
      "git -c commit.gpgsign=false commit -m x",
      "git merge --no-gpg-sign topic",
      "git rebase --no-gpg-sign topic",
      "git cherry-pick --no-gpg-sign topic",
      "git revert --no-gpg-sign --no-edit HEAD",
      "git commit --amend --no-edit --no-gpg-sign",
      // (Tenth pass: git takes any prefix of it from --no-g on, xcheck/c10/probes/sign/probe.out.)
      "git commit --no-gpg-sig -m x",
    ]) assert.doesNotMatch(d.sandboxBreaks(text, r, session) ?? "", SIGNS, text);
    // It says nothing about the signatures a merge checks.
    assert.match(d.sandboxBreaks("git merge --no-gpg-sign --verify-signatures topic", r, session) ?? "", /git checks signatures here/);
    for (const text of [
      // -S after it signs again.
      "git commit --no-gpg-sign -S -m x",
      "git commit --no-gpg-sign --gpg-sign -m x",
      "git commit --no-gpg-sign -aS -m x",
      // A message, a pathspec and another command's option are no option of this one.
      "git commit -m --no-gpg-sign",
      "git commit -m x -- --no-gpg-sign",
      "git commit -m x -- a.txt --no-gpg-sign",
      "git commit --message=--no-gpg-sign",
      "git commit --message --no-gpg-sign",
      "git commit -am --no-gpg-sign",
      "git commit -F --no-gpg-sign",
      "git commit --author --no-gpg-sign -m x",
      "git status --no-gpg-sign; git commit -m x",
      "git commit --no-gpg-sign -m x && git commit -m y",
    ]) assert.match(d.sandboxBreaks(text, r, session) ?? "", SIGNS, text);
    // Without the config, -S alone signs, and --no-gpg-sign after it does not.
    g("config", "commit.gpgsign", "false");
    assert.match(d.sandboxBreaks("git commit -S -m x", r, session) ?? "", SIGNS);
    assert.doesNotMatch(d.sandboxBreaks("git commit -S --no-gpg-sign -m x", r, session) ?? "", SIGNS);
    // Run for real: with the config set, the sandboxed commit that names --no-gpg-sign is made.
    g("config", "commit.gpgsign", "true");
    const text = "git commit --allow-empty --no-gpg-sign -m unsigned";
    assert.equal(d.sandboxBreaks(text, r, session), undefined);
    const ran = sandboxed(planFor(r, text), text, r);
    assert.equal(ran.status, 0, ran.stderr);
    assert.equal(g("log", "-1", "--format=%s").trim(), "unsigned");
  }));

// ---- 6. tests with force ----

test("r4 21: a git directory the call is granted that lies under the hooks of another it is granted is not made writable again: the hooks stay closed", () =>
  withLib((r, session) => {
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    const module = path.join(dotGit, "modules", "lib");
    // What the walk takes for a git directory, planted under the module's hooks.
    const under = path.join(module, "hooks", "inner");
    execFileSync("git", ["init", "-q", "--bare", under]);
    d.projectRoots(session);
    const command = "git status --short && git add -A";
    const p = planFor(r, command, lib);
    assert.equal(p.problem, undefined);
    assert.ok(p.reopen.includes(module), JSON.stringify(p.reopen));
    assert.ok(!p.reopen.some((dir) => dir === under || dir.startsWith(`${under}/`)), `made writable again under hooks/: ${JSON.stringify(p.reopen)}`);
    const ran = sandboxed(p, command, lib);
    assert.equal(ran.status, 0, ran.stderr);
    for (const target of [path.join(under, "probe"), path.join(under, "HEAD"), path.join(module, "hooks", "pre-commit")]) {
      assert.notEqual(sandboxed(p, `echo planted >> ${target}`, lib).status, 0, target);
    }
    assert.equal(fs.existsSync(path.join(under, "probe")), false);
  }));
