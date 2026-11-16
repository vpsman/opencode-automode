// Round 4, group C, eleventh pass: the maintainer's decisions after the two checks of the tenth.
// The link and hard-link checks run on every hooks directory git runs from, wherever it lies (a
// bare repository's beside a worktree that is the project, your global core.hooksPath, a
// repository's absolute one), and the walk's bound asks anywhere; a git command that would
// rewrite a tracked file the sandbox keeps read-only asks; `.sample` hooks are no hooks to the
// hard-link check; the git directories below a named one are found by what they hold and
// compared with what they read elsewhere, and counted one by one; `core.hooksPath` and
// `core.worktree` are followed as the kernel follows them. (The checkout of a linked hook's
// script is held at the hooks too, test/plugin.test.mts.) Each test builds a repository of its
// own under the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-eleventh.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import { envKept, linkLimits, plan, protectedPaths, type Plan } from "../sandbox.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), `c-eleventh-${name}-`)));
const gitIn = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const commit = (dir: string, message = "one") => gitIn(dir, "commit", "-q", "--allow-empty", "-m", message);
const write = (file: string, text: string | Buffer, mode?: number) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  if (mode !== undefined) fs.chmodSync(file, mode);
};
const mkdir = (dir: string) => {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
};

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
const planEnv = (p: Plan): Record<string, string> => ({
  AUTOMODE_RW: p.rw.join("\n"),
  AUTOMODE_RO: p.ro.join("\n"),
  AUTOMODE_HIDE: p.hide.join("\n"),
  AUTOMODE_PIN: p.pin.join("\n"),
  AUTOMODE_TMPFS: p.tmpfs.join("\n"),
  AUTOMODE_REOPEN: p.reopen.join("\n"),
});
// One command under the real wrapper with a plan, as index.ts starts it.
function sandboxed(p: Plan, command: string, cwd: string) {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const { keep, dropped } = envKept(env, []);
  for (const name of dropped) delete env[name];
  Object.assign(env, { AUTOMODE_ENV_KEEP: keep.join("\n"), AUTOMODE_SHELL: "/bin/bash", AUTOMODE_COMMAND: command, ...planEnv(p) });
  return spawnSync(WRAPPER, ["-c", command], { cwd, env, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 120_000 });
}
// The plan index.ts makes for an allowed git-only call.
const planFor = (r: string, command: string, cwd = r) =>
  plan({ ...opts(r), gitCwds: d.gitDirectories(command, cwd), gitWriteCwds: d.gitWriteDirectories(command, cwd), gitMaintainCwds: d.gitMaintainDirectories(command, cwd), gitPushTo: d.pushDestinations(command, cwd) });
// The plan of a call that is not git-only: every git directory is read-only whole.
const plainPlan = (r: string) => plan({ ...opts(r), gitWritable: false });
// What makes an edit ask there, and what an edit asks about.
const editProblems = (r: string) => protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).problems;
const editPaths = (r: string) => protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).paths;
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
// Lines added to your global git config (the runner's throwaway one) for the length of `fn`.
async function withGlobal(lines: string, fn: () => void | Promise<void>) {
  const file = process.env.GIT_CONFIG_GLOBAL!;
  assert.ok(file && fs.existsSync(file), "run through test/run.mjs, which supplies a throwaway global config");
  const before = fs.readFileSync(file, "utf8");
  fs.appendFileSync(file, lines);
  try {
    await fn();
  } finally {
    fs.writeFileSync(file, before);
  }
}
const LINK = /symbolic link/;
const HARD = /hard links?/;
const SCRIPT = "#!/bin/sh\nexit 0\n";
const junk = (dir: string, count: number) => {
  for (let n = 0; n < count; n++) write(path.join(dir, `a${String(n).padStart(6, "0")}`), "");
};
// Each of the three ways of judging a call: a plain one, a git-only one, an edit.
const asked = (wt: string, at: string, what: RegExp) => {
  for (const [who, problem] of [
    ["a call that is not git-only", plainPlan(wt).problem],
    ["a git-only call", planFor(wt, "git status", wt).problem],
    ["an edit", editProblems(wt).find((text) => text.includes(at))],
  ] as const) {
    assert.match(problem ?? "", what, `${at}, ${who}`);
    assert.ok((problem ?? "").includes(at), `${who}: ${problem}`);
  }
};

// ---- 1. every hooks directory git runs from, wherever it lies ----

// A bare repository `repo.git` with a linked worktree `wt` that is the project: `git worktree
// list` leaves the bare entry out, so `repo.git` lies outside every writable directory, and its
// hooks are the ones git runs in `wt`.
async function bareAndWorktree(fn: (base: string, bare: string, wt: string, script: string) => void | Promise<void>) {
  const base = scratch("bare");
  try {
    const seed = path.join(base, "seed");
    gitIn(mkdir(seed), "init", "-q", "-b", "main");
    write(path.join(seed, "scripts", "pre-commit"), SCRIPT, 0o755);
    write(path.join(seed, "a.txt"), "a\n");
    gitIn(seed, "add", "-A");
    commit(seed);
    const bare = path.join(base, "repo.git");
    execFileSync("git", ["clone", "-q", "--bare", seed, bare]);
    const wt = path.join(base, "wt");
    gitIn(bare, "worktree", "add", "-q", wt, "main");
    assert.deepEqual(d.checkouts(wt), [wt], "the fixture: the bare repository is no root of the project");
    await fn(base, bare, wt, path.join(wt, "scripts", "pre-commit"));
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

test("r4 21: a bare repository beside a worktree that is the project: a hook there hard-linked to the project's script asks, and through the wrapper it is what a call rewrites", () =>
  bareAndWorktree((base, bare, wt, script) => {
    assert.equal(plainPlan(wt).problem, undefined, "the fixture");
    const hook = path.join(bare, "hooks", "pre-commit");
    fs.linkSync(script, hook);
    asked(wt, hook, HARD);
    // What it is asked about for: with the problem left out, a call rewrites the hook git runs.
    const loose = { ...plainPlan(wt), problem: undefined };
    assert.equal(sandboxed(loose, `echo planted >> ${script}`, wt).status, 0);
    assert.match(fs.readFileSync(hook, "utf8"), /planted/);
    fs.rmSync(hook);
    // A config of the bare repository, and its info/exclude, with another name: the same.
    for (const file of [path.join(bare, "config"), path.join(bare, "info", "exclude")]) {
      if (!fs.existsSync(file)) write(file, "\n");
      fs.linkSync(file, path.join(wt, "other-name"));
      try {
        asked(wt, file, HARD);
      } finally {
        fs.rmSync(path.join(wt, "other-name"));
      }
    }
    // A symbolic link straight to the project's script: the exception, here as anywhere. The
    // script is read-only, and a call cannot rewrite it.
    fs.writeFileSync(script, SCRIPT);
    fs.symlinkSync(script, hook);
    for (const p of [plainPlan(wt), planFor(wt, "git status", wt)]) {
      assert.equal(p.problem, undefined, p.problem);
      assert.ok(p.ro.includes(script), `the script is not read-only: ${p.ro.join(", ")}`);
    }
    assert.ok(editPaths(wt).includes(script));
    assert.notEqual(sandboxed(plainPlan(wt), `echo planted >> ${script}`, wt).status, 0);
    assert.equal(fs.readFileSync(script, "utf8"), SCRIPT);
    fs.rmSync(hook);
    // Any other link there asks.
    write(path.join(base, "elsewhere", "pre-commit"), SCRIPT, 0o755);
    fs.symlinkSync(path.join(base, "elsewhere", "pre-commit"), hook);
    asked(wt, hook, LINK);
    fs.rmSync(hook);
    // A relative core.hooksPath: where a push into the bare repository runs its hooks, in it.
    gitIn(bare, "config", "core.hooksPath", "hooks2");
    const receive = path.join(mkdir(path.join(bare, "hooks2")), "pre-receive");
    fs.linkSync(script, receive);
    try {
      asked(wt, receive, HARD);
    } finally {
      fs.rmSync(receive);
      gitIn(bare, "config", "--unset", "core.hooksPath");
    }
  }));

test("r4 21: your global core.hooksPath outside every writable directory, and a repository's absolute one: a hook there that is a link asks, unless it leads straight to a script of the project, which is then read-only; one with another name asks", () =>
  fixture(async (r, g, session) => {
    write(path.join(r, "scripts", "pre-commit"), SCRIPT, 0o755);
    g("add", "-A");
    commit(r);
    d.projectRoots(session);
    const script = path.join(r, "scripts", "pre-commit");
    const outside = mkdir(`${r}-outside`);
    write(path.join(outside, "pre-commit"), SCRIPT, 0o755);
    for (const [where, setUp] of [
      ["your global core.hooksPath", (dir: string, fn: () => void) => withGlobal(`[core]\n\thooksPath = ${dir}\n`, fn)],
      ["the repository's absolute core.hooksPath", async (dir: string, fn: () => void) => {
        g("config", "core.hooksPath", dir);
        try {
          await fn();
        } finally {
          g("config", "--unset", "core.hooksPath");
        }
      }],
    ] as const) {
      const hooks = mkdir(`${r}-hooks-${where.includes("global") ? "global" : "repo"}`);
      const hook = path.join(hooks, "pre-commit");
      await setUp(hooks, () => {
        assert.equal(plainPlan(r).problem, undefined, `${where}: the fixture`);
        fs.symlinkSync(script, hook);
        try {
          for (const p of [plainPlan(r), planFor(r, "git status")]) {
            assert.equal(p.problem, undefined, `${where}: ${p.problem}`);
            assert.ok(p.ro.includes(script), `${where}: the script is not read-only`);
          }
          assert.ok(editPaths(r).includes(script), `${where}: an edit of the script is not asked about`);
          const ran = sandboxed(plainPlan(r), `echo planted >> ${script}`, r);
          assert.notEqual(ran.status, 0, `${where}: the script was rewritten`);
          assert.equal(fs.readFileSync(script, "utf8"), SCRIPT);
        } finally {
          fs.rmSync(hook);
        }
        fs.symlinkSync(path.join(outside, "pre-commit"), hook);
        try {
          asked(r, hook, LINK);
          // Where no repository is found at all, your global one is still looked at.
          if (where.includes("global")) {
            const none = mkdir(`${r}-no-repository`);
            assert.match(plan({ ...opts(none), gitWritable: false }).problem ?? "", LINK, "a project with no repository");
          }
        } finally {
          fs.rmSync(hook);
        }
        fs.linkSync(script, hook);
        try {
          if (where.includes("global")) asked(r, hook, HARD);
          else {
            // A git-only call in the repository is its own (git writes a work tree's files anew,
            // never through another name), as for its `hooks/` (tenth pass); every other call asks.
            assert.equal(planFor(r, "git status").problem, undefined);
            for (const problem of [plainPlan(r).problem, editProblems(r).find((t) => t.includes(hook))]) {
              assert.match(problem ?? "", HARD, where);
              assert.ok((problem ?? "").includes(hook), problem);
            }
          }
        } finally {
          fs.rmSync(hook);
        }
        assert.equal(plainPlan(r).problem, undefined, `${where}: put back`);
      });
    }
  }));

test("r4 21: a file the project's config includes from outside every writable directory, with another name in the project, asks", () =>
  fixture((r, g) => {
    commit(r);
    const outside = mkdir(`${r}-outside`);
    const included = path.join(outside, "work.gitconfig");
    write(included, "[user]\n\tname = x\n");
    g("config", "include.path", included);
    assert.equal(plainPlan(r).problem, undefined, "the fixture");
    fs.linkSync(included, path.join(r, "work.gitconfig"));
    for (const problem of [plainPlan(r).problem, planFor(r, "git status", path.join(r, "..")).problem, editProblems(r).find((t) => t.includes(included))]) {
      assert.match(problem ?? "", HARD);
      assert.ok((problem ?? "").includes(included), problem);
    }
  }));

test("r4 21: a repository in the shared temp directory is left: a hook of it with another name in the project does not make a call ask", () =>
  fixture((r) => {
    commit(r);
    write(path.join(r, "pc"), SCRIPT, 0o755);
    const inTmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "c-eleventh-shared-")));
    try {
      execFileSync("git", ["init", "-q", inTmp]);
      fs.linkSync(path.join(r, "pc"), path.join(inTmp, ".git", "hooks", "pre-commit"));
      assert.equal(plainPlan(r).problem, undefined, plainPlan(r).problem);
    } finally {
      fs.rmSync(inTmp, { recursive: true, force: true });
    }
  }));

// ---- 2. over the bound, anywhere ----

test("r4 21: past the walk's bound in a git directory outside every writable directory, the call asks", () =>
  bareAndWorktree((_base, bare, wt) => {
    const before = { ...linkLimits };
    try {
      linkLimits.entries = 3;
      // (Its worktree's admin directory, also outside, is walked first.)
      assert.match(plainPlan(wt).problem ?? "", new RegExp(`^${bare.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(/worktrees/wt)? holds more than 3 entries`));
      assert.ok(editProblems(wt).some((t) => /holds more than 3 entries/.test(t)), "an edit");
    } finally {
      Object.assign(linkLimits, before);
    }
    assert.equal(plainPlan(wt).problem, undefined, "the fixture");
  }));

// ---- 3. a git command that would rewrite a tracked file the sandbox keeps read-only ----

test("r4 21: a git command that would rewrite a tracked file the sandbox keeps read-only (a linked hook's script, a hook manager's file, AGENTS.md) asks, naming it; where the file stays as it is, it does not", () =>
  fixture((r, g, session) => {
    const script = path.join(r, "scripts", "pre-commit");
    const manager = path.join(r, ".pre-commit-config.yaml");
    const agents = path.join(r, "AGENTS.md");
    write(path.join(r, "a.txt"), "a\n");
    // `old`: from a commit with an older script, adding a file of its own.
    write(script, "#!/bin/sh\necho zero >/dev/null\nexit 0\n", 0o755);
    g("add", "-A");
    g("commit", "-qm", "zero");
    g("checkout", "-q", "-b", "old");
    write(path.join(r, "b2.txt"), "b\n");
    g("add", "-A");
    g("commit", "-qm", "old");
    g("checkout", "-q", "main");
    write(script, SCRIPT, 0o755);
    write(manager, "repos: []\n");
    write(agents, "# one\n");
    g("add", "-A");
    g("commit", "-qm", "one");
    const branch = (name: string, file: string, text: string) => {
      g("checkout", "-q", "-b", name, "main");
      write(file, text);
      g("add", "-A");
      g("commit", "-qm", name);
    };
    branch("same", path.join(r, "b.txt"), "b\n");
    branch("other", script, "#!/bin/sh\necho other >/dev/null\nexit 0\n");
    branch("cfg", manager, "repos: [x]\n");
    branch("agents", agents, "# two\n");
    g("checkout", "-q", "main");
    fs.symlinkSync("../../scripts/pre-commit", path.join(r, ".git", "hooks", "pre-commit"));
    d.projectRoots(session);
    const HELD = /keeps read-only/;
    const asks = (text: string, file: string) => {
      const broken = d.sandboxBreaks(text, r, session) ?? "";
      assert.match(broken, HELD, text);
      assert.ok(broken.includes(file), `${text}: ${broken}`);
    };
    for (const text of ["git checkout other", "git switch other", "git merge other", "git merge --ff-only other", "git pull . other", "git rebase other", "git cherry-pick other", "git reset --keep other", "git rm scripts/pre-commit", "git mv scripts/pre-commit scripts/x"]) asks(text, script);
    // `old` has the older script: a checkout of it rewrites the script; a merge or a cherry-pick of
    // it brings only its own file (the merge base, the commit's parent).
    asks("git checkout old", script);
    asks("git checkout cfg", manager);
    asks("git switch agents", agents);
    // `git clean` removes files that are not tracked: the empty `.opencode` the plan makes is one.
    asks("git clean -fd", path.join(r, ".opencode"));
    assert.doesNotMatch(d.sandboxBreaks("git clean -fd", r, session) ?? "", /\/\.git(\/|,|$)/, "a git directory is no file of the work tree");
    // Where it can be told that the file stays: a commit with the same file, or no move at all.
    for (const text of ["git status", "git commit -m x", "git add a.txt", "git log --oneline", "git checkout same", "git switch same", "git merge same", "git merge old", "git cherry-pick same", "git cherry-pick old", "git rebase same", "git reset --keep same", "git checkout -b fresh", "git switch -c fresh2", "git checkout -b fresh3 --", "git rm a.txt", "git rm --cached scripts/pre-commit", "git mv a.txt c.txt", "git mv a.txt scripts", "git clean -n", "git stash", "git stash -m x", "git stash list", "git restore --staged scripts/pre-commit", "git branch topic"]) assert.equal(d.sandboxBreaks(text, r, session), undefined, text);
    // A stash of a change to the script would put it back; a pop of a stash brings what it holds.
    fs.appendFileSync(script, "# local\n");
    asks("git stash", script);
    fs.writeFileSync(script, SCRIPT);
    fs.appendFileSync(path.join(r, "a.txt"), "local\n");
    g("stash", "-q");
    assert.equal(d.sandboxBreaks("git stash pop", r, session), undefined, "a stash of a.txt");
    assert.equal(d.sandboxBreaks("git stash apply 0", r, session), undefined, "the stash numbered 0, of a.txt");
    g("stash", "pop", "-q");
    fs.writeFileSync(path.join(r, "a.txt"), "a\n");
    fs.appendFileSync(script, "# local\n");
    g("stash", "-q");
    asks("git stash pop", script);
    asks("git stash apply 0", script);
    g("stash", "drop", "-q");
    // A rebase replays commits of its own: one that changes the script and one that puts it back
    // leave HEAD and the upstream with the same script, and the replay rewrites it twice.
    g("checkout", "-q", "-b", "back", "main");
    write(script, "#!/bin/sh\necho back >/dev/null\nexit 0\n");
    g("commit", "-qam", "changed");
    write(script, SCRIPT);
    g("commit", "-qam", "put back");
    // (Onto `same`, which has moved on: onto `main`, an ancestor, there is nothing to replay, and
    // nothing is asked: twelfth pass.)
    asks("git rebase same", script);
    g("checkout", "-q", "main");
    // Without a read-only file among them, the same commands are left as they were.
    fs.rmSync(path.join(r, ".git", "hooks", "pre-commit"));
    fs.rmSync(manager);
    g("rm", "-q", "--cached", ".pre-commit-config.yaml");
    fs.rmSync(agents);
    g("rm", "-q", "--cached", "AGENTS.md");
    g("commit", "-qm", "without");
    for (const text of ["git checkout other", "git switch other", "git merge other", "git rebase other"]) assert.equal(d.sandboxBreaks(text, r, session), undefined, `without: ${text}`);
  }));

test("r4 21: a git command in a submodule is judged by the files of its own work tree: the superproject's read-only script is none of them", () =>
  fixture((r, g, session) => {
    write(path.join(r, "scripts", "pre-commit"), SCRIPT, 0o755);
    g("add", "-A");
    g("commit", "-qm", "one");
    const upstream = `${r}-up`;
    execFileSync("git", ["init", "-q", "-b", "main", upstream]);
    commit(upstream);
    g("-c", "protocol.file.allow=always", "submodule", "add", "-q", upstream, "lib");
    g("commit", "-qm", "lib");
    const lib = path.join(r, "lib");
    gitIn(lib, "branch", "b2");
    fs.symlinkSync("../../scripts/pre-commit", path.join(r, ".git", "hooks", "pre-commit"));
    d.projectRoots(session);
    assert.match(d.sandboxBreaks("git rm scripts/pre-commit", r, session) ?? "", /keeps read-only/, "the fixture");
    for (const text of ["git switch b2", "git checkout main", "git stash"]) assert.equal(d.sandboxBreaks(text, lib, session), undefined, text);
  }));

test("r4 21: what a checkout of a linked hook's script is asked about for: run for real it exits 0 and leaves the script as it was", () =>
  fixture((r, g, session) => {
    const script = path.join(r, "scripts", "pre-commit");
    write(script, SCRIPT, 0o755);
    g("add", "-A");
    g("commit", "-qm", "one");
    g("checkout", "-q", "-b", "other");
    write(script, "#!/bin/sh\necho other >/dev/null\nexit 0\n");
    g("commit", "-qam", "other");
    g("checkout", "-q", "main");
    fs.symlinkSync("../../scripts/pre-commit", path.join(r, ".git", "hooks", "pre-commit"));
    d.projectRoots(session);
    assert.match(d.sandboxBreaks("git checkout other", r, session) ?? "", /scripts\/pre-commit/);
    const ran = sandboxed(planFor(r, "git checkout other"), "git checkout other", r);
    assert.equal(ran.status, 0, ran.stderr);
    assert.equal(g("branch", "--show-current").trim(), "other");
    assert.equal(fs.readFileSync(script, "utf8"), SCRIPT, "the script was rewritten after all");
  }));

// ---- 4. `.sample` ----

test("r4 21: `cp -al` of a repository: its `.sample` hooks with two names no longer make a call ask; its config and info/exclude with two names still do", () =>
  fixture((r) => {
    commit(r);
    const dotGit = path.join(r, ".git");
    assert.ok(fs.readdirSync(path.join(dotGit, "hooks")).some((n) => n.endsWith(".sample")), "the fixture: git made its sample hooks");
    execFileSync("cp", ["-al", r, `${r}-backup`]);
    // The copy's names of the two files the decision keeps: what is asked about by them.
    for (const file of [path.join(dotGit, "config"), path.join(dotGit, "info", "exclude")]) {
      const problem = plainPlan(r).problem ?? "";
      assert.match(problem, HARD, problem);
      assert.doesNotMatch(problem, /\.sample/, problem);
      fs.rmSync(path.join(`${r}-backup`, path.relative(r, file)));
    }
    assert.ok(fs.statSync(path.join(dotGit, "hooks", "pre-commit.sample")).nlink > 1, "the fixture: the samples have two names");
    assert.equal(plainPlan(r).problem, undefined, plainPlan(r).problem);
    assert.deepEqual(editProblems(r), []);
    // A hook that is no sample still asks.
    fs.linkSync(path.join(dotGit, "hooks", "pre-commit.sample"), path.join(dotGit, "hooks", "pre-commit"));
    assert.match(plainPlan(r).problem ?? "", /hooks\/pre-commit \(/);
  }));

// ---- 5. the git directories below a named one ----

test("r4 21: the git directories below a named one: one without HEAD (its config, hooks, objects or refs), one with a hooks path or an include of its own outside, and those below a named directory without HEAD are compared first", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const before = { ...d.fingerprintLimits };
    try {
      commit(r);
      d.projectRoots(session);
      d.fingerprintLimits.entries = 120;
      let n = 0;
      // Each case: what is planted (`plant`: the directory the pause names, from `top`), and
      // what changes after the prompt.
      const CASES: [string, (top: string) => string, (named: string) => void][] = [
        ["a module without HEAD: its config", (top) => {
          execFileSync("git", ["init", "-q", "-b", "main", top]);
          write(path.join(top, ".git", "modules", "zzz", "config"), "[core]\n\tbare = true\n");
          junk(path.join(top, ".git", "modules", "aaa"), 300);
          return path.join(top, ".git");
        }, (named) => fs.appendFileSync(path.join(named, "modules", "zzz", "config"), "[core]\n\tfsmonitor = touch /tmp/never\n")],
        ["a module without HEAD: a hook", (top) => {
          execFileSync("git", ["init", "-q", "-b", "main", top]);
          mkdir(path.join(top, ".git", "modules", "zzz", "hooks"));
          junk(path.join(top, ".git", "modules", "aaa"), 300);
          return path.join(top, ".git");
        }, (named) => write(path.join(named, "modules", "zzz", "hooks", "pre-commit"), "#!/bin/sh\ntouch /tmp/never\n", 0o755)],
        ["a module's own core.hooksPath outside", (top) => {
          execFileSync("git", ["init", "-q", "-b", "main", top]);
          const module = path.join(top, ".git", "modules", "zzz");
          execFileSync("git", ["init", "-q", "--bare", module]);
          gitIn(module, "config", "core.hooksPath", mkdir(`${r}-hk${n}`));
          return path.join(top, ".git");
        }, () => write(path.join(`${r}-hk${n}`, "pre-commit"), "#!/bin/sh\ntouch /tmp/never\n", 0o755)],
        ["a module's own include outside", (top) => {
          execFileSync("git", ["init", "-q", "-b", "main", top]);
          const module = path.join(top, ".git", "modules", "zzz");
          execFileSync("git", ["init", "-q", "--bare", module]);
          write(`${r}-inc${n}.cfg`, "[user]\n\tname = x\n");
          gitIn(module, "config", "include.path", `${r}-inc${n}.cfg`);
          return path.join(top, ".git");
        }, () => fs.appendFileSync(`${r}-inc${n}.cfg`, "[core]\n\tfsmonitor = touch /tmp/never\n")],
        ["a `.git` file naming a directory of modules (no HEAD) outside", (top) => {
          const mods = mkdir(`${r}-mods${n}`);
          execFileSync("git", ["init", "-q", "--bare", path.join(mods, "zzz")]);
          junk(path.join(mods, "aaa"), 300);
          write(path.join(top, ".git"), `gitdir: ${mods}\n`);
          return mods;
        }, (named) => fs.appendFileSync(path.join(named, "zzz", "config"), "[core]\n\tfsmonitor = touch /tmp/never\n")],
      ];
      for (const [what, plant, change] of CASES) {
        n++;
        const top = mkdir(path.join(r, `zze${n}`));
        const named = plant(top);
        const first = d.gitTampered(session, resume.file) ?? "";
        assert.ok(first.includes(`${named} appeared`), `${what}: ${first}`);
        change(named);
        resume.touch();
        assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${named} appeared`), `${what}: taken in unseen`);
        for (let k = 0; k < 4 && d.gitTampered(session, resume.file); k++) resume.touch();
        assert.equal(d.gitTampered(session, resume.file), undefined, `${what}: settled`);
        fs.rmSync(top, { recursive: true });
        for (let k = 0; k < 4 && d.gitTampered(session, resume.file); k++) resume.touch();
      }
    } finally {
      Object.assign(d.fingerprintLimits, before);
      resume.remove();
    }
  }));

test("r4 21: the bound of the git directories below a named one counts git directories, not the names looked for in each: 150 modules fit an allowance of 200, 250 do not", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const before = { ...d.fingerprintLimits };
    try {
      commit(r);
      d.projectRoots(session);
      d.fingerprintLimits.first = 200;
      // (Each module's sample hooks hold some 25 KB, which git never runs: known by their size,
      // inode and change time, they are not read, and 150 of them do not fill a megabyte.)
      d.fingerprintLimits.firstBytes = 1 << 20;
      const top = path.join(r, "many");
      execFileSync("git", ["init", "-q", "-b", "main", top]);
      for (let k = 0; k < 150; k++) execFileSync("git", ["init", "-q", "--bare", path.join(top, ".git", "modules", `m${String(k).padStart(3, "0")}`)]);
      const first = d.gitTampered(session, resume.file) ?? "";
      assert.ok(first.includes(`${path.join(top, ".git")} appeared`), first);
      assert.doesNotMatch(first, /cannot be compared whole/, first);
      // A change to the last of them after the prompt prompts again.
      fs.appendFileSync(path.join(top, ".git", "modules", "m149", "config"), "[core]\n\tfsmonitor = touch /tmp/never\n");
      resume.touch();
      assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${path.join(top, ".git")} appeared`), "taken in unseen");
      // (Each module is named as well, five at a time.)
      for (let k = 0; k < 60 && d.gitTampered(session, resume.file); k++) resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined, "settled");
      // Past the allowance: said, and it stays.
      for (let k = 150; k < 250; k++) execFileSync("git", ["init", "-q", "--bare", path.join(top, ".git", "modules", `m${String(k).padStart(3, "0")}`)]);
      fs.rmSync(top, { recursive: true });
      execFileSync("git", ["init", "-q", "-b", "main", top]);
      for (let k = 0; k < 250; k++) execFileSync("git", ["init", "-q", "--bare", path.join(top, ".git", "modules", `m${String(k).padStart(3, "0")}`)]);
      resume.touch();
      const again = d.gitTampered(session, resume.file) ?? "";
      assert.match(again, /cannot be compared whole where it matters: the git directories below it/, again);
      resume.touch();
      assert.match(d.gitTampered(session, resume.file) ?? "", /cannot be compared whole/);
    } finally {
      Object.assign(d.fingerprintLimits, before);
      resume.remove();
    }
  }));

// ---- 6. core.hooksPath and core.worktree followed as the kernel follows them ----

const SSH = "git@example.invalid:team/x.git";
const HTTPS = "https://example.invalid/team/x.git";

test("r4 25: a core.hooksPath spelled with `..` after a link: the hook git runs there is seen, and the ssh agent is not handed to a push", () =>
  fixture(async (r, g, session) => {
    commit(r);
    g("remote", "add", "origin", SSH);
    const outside = mkdir(`${r}-outside`);
    mkdir(path.join(r, "work", "sub"));
    fs.symlinkSync(path.join(r, "work", "sub"), path.join(outside, "lnk"));
    // git takes `<outside>/lnk/../h` to `<r>/work/h`; by its text it is `<outside>/h`. (Your own
    // config: one of the repository's that names hooks gets no agent whatever it holds.)
    await withGlobal(`[core]\n\thooksPath = ${outside}/lnk/../h\n`, () => {
      write(path.join(outside, "h", "keep"), "");
      d.projectRoots(session);
      assert.equal(d.usesSsh("git push", r, session), true, "the fixture: no hook");
      write(path.join(r, "work", "h", "pre-push"), SCRIPT, 0o755);
      assert.equal(d.usesSsh("git push", r, session), false, "a pre-push hook runs, with the agent in reach");
    });
  }));

test("r4 25: a submodule's core.worktree spelled with `..` after a link is the work tree git uses: a repository where its text leads is not taken for its submodules", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "origin", HTTPS);
    const upstream = `${r}-up`;
    execFileSync("git", ["init", "-q", "-b", "main", upstream]);
    commit(upstream);
    mkdir(path.join(r, "x"));
    g("-c", "protocol.file.allow=always", "submodule", "add", "-q", upstream, "x/lib");
    g("commit", "-qm", "lib");
    const module = path.join(r, ".git", "modules", "x", "lib");
    gitIn(module, "remote", "set-url", "origin", HTTPS);
    // lib's core.worktree spelled `<r>/o/lnk/../lib`, `lnk` leading to `<r>/x/y`: git takes it
    // to `<r>/x/lib`, where lib is. By its text it is `<r>/o/lib`: a repository of its own
    // there, with a submodule reached over ssh.
    fs.symlinkSync(mkdir(path.join(r, "x", "y")), path.join(mkdir(path.join(r, "o")), "lnk"));
    gitIn(module, "config", "core.worktree", `${r}/o/lnk/../lib`);
    assert.equal(gitIn(path.join(r, "x", "lib"), "rev-parse", "--show-toplevel").trim(), path.join(r, "x", "lib"), "the fixture: git finds lib's work tree");
    const decoy = path.join(r, "o", "lib");
    execFileSync("git", ["init", "-q", "-b", "main", decoy]);
    const inner = path.join(decoy, "inner");
    execFileSync("git", ["init", "-q", "-b", "main", inner]);
    commit(inner);
    gitIn(inner, "remote", "add", "origin", SSH);
    gitIn(decoy, "add", "inner");
    commit(decoy);
    d.projectRoots(session);
    assert.equal(d.sandboxBreaks("git fetch --recurse-submodules", r, session), undefined);
  }));

// ---- 7. small ----

test("r4 21: `git checkout -b x --` makes a branch: with refs a link outside every writable directory it asks; `git checkout -- a.txt` does not", () =>
  fixture((r, g, session) => {
    write(path.join(r, "a.txt"), "a\n");
    g("add", "a.txt");
    g("commit", "-qm", "one");
    d.projectRoots(session);
    const refs = path.join(r, ".git", "refs");
    fs.renameSync(refs, `${r}-store-refs`);
    fs.symlinkSync(`${r}-store-refs`, refs);
    try {
      for (const text of ["git checkout -b x --", "git checkout -b x"]) {
        const broken = d.sandboxBreaks(text, r, session) ?? "";
        assert.match(broken, /that store lies outside what the sandbox lets the call write/, text);
        assert.ok(broken.includes(refs), broken);
      }
      for (const text of ["git checkout -- a.txt", "git checkout HEAD -- a.txt"]) assert.equal(d.sandboxBreaks(text, r, session), undefined, text);
    } finally {
      fs.rmSync(refs);
      fs.renameSync(`${r}-store-refs`, refs);
    }
  }));

// C11's reading, F1: deciding `git stash` read the work tree (`git diff --name-only HEAD`) in the
// plugin's own process, and a clean filter the repository's configuration names (a project
// program) ran there, unsandboxed. Where the configuration names such a program, the work tree is
// not read: the tracked read-only files are named as ones it may rewrite.
test("r4 21 (eleventh pass, its reading F1): deciding git stash runs no clean filter the repository names", async () => {
  await fixture((r, g, session) => {
    const marker = path.join(r, "filter-ran");
    write(path.join(r, "filt.sh"), `#!/bin/sh\ntouch '${marker}'\ncat\n`, 0o755);
    write(path.join(r, ".gitattributes"), "AGENTS.md filter=x\n");
    write(path.join(r, "AGENTS.md"), "# one\n");
    g("config", "filter.x.clean", "./filt.sh");
    g("add", "-A");
    fs.rmSync(marker, { force: true });
    g("-c", "filter.x.clean=cat", "commit", "-qm", "one");
    fs.rmSync(marker, { force: true });
    write(path.join(r, "AGENTS.md"), "# two\n");
    d.projectRoots(session);
    for (const text of ["git stash", "git stash -m wip", "git stash push"]) {
      const broken = d.sandboxBreaks(text, r, session) ?? "";
      assert.equal(fs.existsSync(marker), false, `${text}: the filter ran in the plugin's process`);
      assert.match(broken, /keeps read-only/, text);
    }
  });
});
