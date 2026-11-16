// Round 4, group C, twelfth pass: the maintainer's decisions after the two checks of the
// eleventh. A `core.hooksPath` that a conditional include sets asks; what git expands in a way
// that cannot be followed (or could not read) for a git directory outside every writable
// directory is said like everything else of it; the read-only-file check of git commands that
// write the work tree reads a git command after one that may move a ref, an autostash, a rename,
// a sparse checkout, `stash -u`, `--output` and the writers it counted as none; and asks less
// where nothing is to be done (`--abort` with nothing in progress, `apply --check`, a merge or
// rebase that is up to date). (The same at the hooks, test/plugin.test.mts.) Each test builds a
// repository of its own under the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-twelfth.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import { envKept, plan, protectedPaths, type Plan } from "../sandbox.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), `c-twelfth-${name}-`)));
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
// What makes an edit ask there.
const editProblems = (r: string) => protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).problems;
const editPaths = (r: string) => protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).paths;
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
// Each of the three ways of judging a call: a plain one, a git-only one, an edit; each names
// `at` and says `what`.
const asked = (wt: string, at: string, what: RegExp, gitOnly = "git status") => {
  for (const [who, problem] of [
    ["a call that is not git-only", plainPlan(wt).problem],
    ["a git-only call", planFor(wt, gitOnly, wt).problem],
    ["an edit", editProblems(wt).find((text) => text.includes(at))],
  ] as const) {
    assert.match(problem ?? "", what, `${at}, ${who}`);
    assert.ok((problem ?? "").includes(at), `${who}: ${problem}`);
  }
};
const quiet = (wt: string, why: string, gitOnly = "git status") => {
  assert.equal(plainPlan(wt).problem, undefined, `${why}: a plain call`);
  assert.equal(planFor(wt, gitOnly, wt).problem, undefined, `${why}: a git-only call`);
  assert.deepEqual(editProblems(wt), [], `${why}: an edit`);
};

// A bare repository `repo.git` with a linked worktree `wt` that is the project: `repo.git` lies
// outside every writable directory, and its hooks are the ones git runs in `wt`.
async function bareAndWorktree(fn: (base: string, bare: string, wt: string) => void | Promise<void>) {
  const base = scratch("bare");
  try {
    const seed = path.join(base, "seed");
    gitIn(mkdir(seed), "init", "-q", "-b", "main");
    write(path.join(seed, "a.txt"), "a\n");
    gitIn(seed, "add", "-A");
    commit(seed);
    const bare = path.join(base, "repo.git");
    execFileSync("git", ["clone", "-q", "--bare", seed, bare]);
    const wt = path.join(base, "wt");
    gitIn(bare, "worktree", "add", "-q", wt, "main");
    assert.deepEqual(d.checkouts(wt), [wt], "the fixture: the bare repository is no root of the project");
    await fn(base, bare, wt);
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
}

// ---- 1. a core.hooksPath that a conditional include sets ----

test("r4 21: a core.hooksPath set in a conditional include asks, whatever its condition, naming the file; one set in a plain include is read and protected as before", () =>
  fixture(async (r, g) => {
    write(path.join(r, "a.txt"), "a\n");
    g("add", "-A");
    commit(r);
    quiet(r, "the fixture");
    const HOOKS = /core\.hooksPath/;
    // C11's reading, p4a: `onbranch:feature`, on `main`. A plain call could write
    // `.hooks-feature/pre-commit` (exit 0 there), and `git switch -c feature` makes git run it.
    const feature = path.join(r, ".git", "feature.cfg");
    write(feature, "[core]\n\thooksPath = .hooks-feature\n");
    g("config", "includeIf.onbranch:feature.path", "feature.cfg");
    asked(r, feature, HOOKS, "git switch -c feature");
    assert.match(plainPlan(r).problem ?? "", /only under a condition/);
    g("config", "--unset", "includeIf.onbranch:feature.path");
    quiet(r, "put back");
    // A conditional include that sets no hooks path is no problem.
    write(path.join(r, ".git", "name.cfg"), "[user]\n\tname = x\n");
    g("config", "includeIf.onbranch:feature.path", "name.cfg");
    quiet(r, "a conditional include of something else");
    g("config", "--unset", "includeIf.onbranch:feature.path");
    // Behind a plain include, a conditional one; behind a conditional include, a plain one.
    const deep = path.join(r, ".git", "deep.cfg");
    write(deep, "[core]\n\thooksPath = /nowhere/hooks\n");
    write(path.join(r, ".git", "plain.cfg"), `[includeIf "gitdir:/nowhere/"]\n\tpath = deep.cfg\n`);
    g("config", "include.path", "plain.cfg");
    asked(r, deep, HOOKS);
    g("config", "--unset", "include.path");
    write(path.join(r, ".git", "cond.cfg"), "[include]\n\tpath = deep.cfg\n");
    g("config", "includeIf.hasconfig:remote.*.url:x.path", "cond.cfg");
    asked(r, deep, HOOKS);
    g("config", "--unset", "includeIf.hasconfig:remote.*.url:x.path");
    // From config.worktree.
    write(path.join(r, ".git", "config.worktree"), `[includeIf "onbranch:x"]\n\tpath = feature.cfg\n`);
    asked(r, feature, HOOKS);
    fs.rmSync(path.join(r, ".git", "config.worktree"));
    // From your own config.
    const mine = path.join(`${r}-global`, "hooks.cfg");
    write(mine, "[core]\n\thooksPath = /nowhere/global-hooks\n");
    await withGlobal(`[includeIf "gitdir:/nowhere/"]\n\tpath = ${mine}\n`, () => {
      for (const problem of [plainPlan(r).problem, planFor(r, "git status").problem, editProblems(r).find((t) => t.includes(mine))]) {
        assert.match(problem ?? "", HOOKS);
        assert.ok((problem ?? "").includes(mine), problem);
      }
    });
    quiet(r, "put back");
    // A plain include: its value is read, and the directory it names is made and protected.
    write(path.join(r, ".git", "inc.cfg"), "[core]\n\thooksPath = .hooks-inc\n");
    g("config", "include.path", "inc.cfg");
    quiet(r, "a plain include");
    for (const p of [plainPlan(r), planFor(r, "git status")]) assert.ok(p.ro.includes(path.join(r, ".hooks-inc")), p.ro.join(", "));
  }));

// ---- 2. what cannot be followed, for a git directory outside every writable directory ----

test("r4 21: a bare repository outside every writable directory with a core.hooksPath git expands in a way not followed here (`~user/`, `%(prefix)/`) asks, as one in the project does", () =>
  bareAndWorktree((base, bare, wt) => {
    quiet(wt, "the fixture");
    for (const value of ["~root/hooks", "%(prefix)/hooks"]) {
      gitIn(bare, "config", "core.hooksPath", value);
      asked(wt, bare, /cannot be followed here/);
      gitIn(bare, "config", "--unset", "core.hooksPath");
    }
    quiet(wt, "put back");
    // What git could not read there: an included file that is no config (git then stops for
    // every command): said for the bare repository, wherever the file lies.
    const inc = path.join(base, "broken.cfg");
    write(inc, "[user]\n\tname = x\n");
    gitIn(bare, "config", "include.path", inc);
    fs.writeFileSync(inc, "[[[ no config\n");
    const problems = editProblems(wt);
    assert.ok(problems.some((t) => t.includes(`could not read core.hooksPath in ${bare}`)), problems.join("\n"));
    assert.ok(problems.some((t) => t.includes(`could not say what ${inc} includes`)), problems.join("\n"));
  }));

// ---- 3. the read-only-file check: what it missed ----

const HELD = /keeps read-only/;
// A repository that tracks a linked hook's script (`scripts/pre-commit`), AGENTS.md and a.txt,
// on `main`: `anc` is its first commit, `main` changes AGENTS.md since; `same` (from main) changes
// b.txt alone, `other` the script. `origin` is a bare copy, fetched, `main`'s upstream.
function heldRepo(r: string, g: (...args: string[]) => string, session: d.SessionState) {
  const script = path.join(r, "scripts", "pre-commit");
  const agents = path.join(r, "AGENTS.md");
  write(path.join(r, "a.txt"), "a\n");
  write(script, SCRIPT, 0o755);
  write(agents, "# one\n");
  g("add", "-A");
  g("commit", "-qm", "one");
  g("branch", "anc");
  write(agents, "# two\n");
  g("commit", "-qam", "two");
  const branch = (name: string, file: string, text: string) => {
    g("checkout", "-q", "-b", name, "main");
    write(file, text);
    g("add", "-A");
    g("commit", "-qm", name);
  };
  branch("same", path.join(r, "b.txt"), "b\n");
  branch("other", script, "#!/bin/sh\necho other >/dev/null\nexit 0\n");
  g("checkout", "-q", "main");
  execFileSync("git", ["clone", "-q", "--bare", r, `${r}-origin`]);
  g("remote", "add", "origin", `${r}-origin`);
  g("fetch", "-q", "origin");
  g("branch", "-q", "--set-upstream-to=origin/main");
  fs.symlinkSync("../../scripts/pre-commit", path.join(r, ".git", "hooks", "pre-commit"));
  d.projectRoots(session);
  const asks = (text: string, file = script, why?: RegExp) => {
    const broken = d.sandboxBreaks(text, r, session) ?? "";
    assert.match(broken, HELD, text);
    assert.ok(broken.includes(file), `${text}: ${broken}`);
    if (why) assert.match(broken, why, text);
  };
  const none = (text: string) => assert.equal(d.sandboxBreaks(text, r, session), undefined, text);
  return { script, agents, asks, none };
}

test("r4 21: a git command after one in the same call that may move a ref or the work tree cannot be told: Sonnet's eight chains ask", () =>
  fixture((r, g, session) => {
    const { asks, none } = heldRepo(r, g, session);
    // Each part alone, as it stands: told.
    for (const text of ["git fetch", "git merge --ff-only origin/main", "git rebase origin/main", "git merge '@{u}'", "git rebase", "git checkout origin/main", "git switch --detach origin/main", "git cherry-pick same", "git remote update"]) none(text);
    const AFTER = /git [a-z-]+ in the same command/;
    for (const text of [
      "git fetch && git merge --ff-only origin/main",
      "git fetch origin && git rebase origin/main",
      // (`@{u}` as canon.ts prints it, quoted, which is what index.ts judges.)
      "git fetch && git merge '@{u}'",
      "git fetch && git rebase",
      "git fetch; git checkout origin/main",
      "git fetch -p && git switch --detach origin/main",
      "git fetch && git cherry-pick same",
      "git remote update && git merge origin/main",
      // Wide: anything that may move a ref, the index or the work tree.
      "git commit -qam x && git checkout same",
      "git stash && git switch same",
      "git reset -q HEAD^ && git merge --ff-only origin/main",
      "git branch -f same other && git checkout same",
      "git tag -f t other && git checkout t",
      "git -C . fetch && git merge --ff-only origin/main",
    ]) asks(text, path.join(r, "AGENTS.md"), AFTER);
    // (A pull asks for itself.)
    asks("git pull && git checkout same", path.join(r, "AGENTS.md"));
    // After what moves nothing, and before what may: as alone.
    for (const text of ["git fetch && git status", "git status && git merge --ff-only origin/main", "git log -1 && git checkout same", "git checkout same && git fetch", "git stash list && git switch same", "git branch && git switch same", "git branch --show-current && git switch same", "git tag -l && git switch same", "git fetch && git checkout -b fresh"]) none(text);
  }));

test("r4 21: merge.autoStash or rebase.autoStash (true, or what git cannot read as a boolean) makes a merge or a rebase one that cannot be told; --no-autostash, or a merge that is up to date, as before", () =>
  fixture((r, g, session) => {
    const { asks, none } = heldRepo(r, g, session);
    const agents = path.join(r, "AGENTS.md");
    for (const text of ["git rebase same", "git merge same"]) none(text);
    for (const [key, sub] of [["rebase.autoStash", "rebase"], ["merge.autoStash", "merge"]]) {
      for (const value of ["true", "maybe"]) {
        g("config", key, value);
        asks(`git ${sub} same`, agents);
        none(`git ${sub} --no-autostash same`);
        g("config", "--unset", key);
      }
      // As before: the flag.
      asks(`git ${sub} --autostash same`, agents);
    }
    // A merge that is up to date makes no autostash (run: "Already up to date.", no stash); a
    // rebase does, and puts it back (run: "Created autostash", "Applied autostash").
    g("config", "merge.autoStash", "true");
    g("config", "rebase.autoStash", "true");
    none("git merge anc");
    asks("git rebase anc", agents);
  }));

test("r4 21: a rename into a read-only file on our side, of a file the other side changes, is followed by git: the merge or cherry-pick asks (C11's reading, p3 A and B)", () =>
  fixture((r, g, session) => {
    const script = path.join(r, "scripts", "pre-commit");
    write(path.join(r, "old", "pre-commit"), SCRIPT, 0o755);
    write(path.join(r, "a.txt"), "a\n");
    g("add", "-A");
    g("commit", "-qm", "one");
    g("checkout", "-q", "-b", "side");
    fs.appendFileSync(path.join(r, "old", "pre-commit"), "# side\n");
    g("commit", "-qam", "side");
    g("checkout", "-q", "-b", "plain", "main");
    fs.appendFileSync(path.join(r, "a.txt"), "plain\n");
    g("commit", "-qam", "plain");
    g("checkout", "-q", "main");
    mkdir(path.join(r, "scripts"));
    g("mv", "old/pre-commit", "scripts/pre-commit");
    g("commit", "-qm", "moved");
    fs.symlinkSync("../../scripts/pre-commit", path.join(r, ".git", "hooks", "pre-commit"));
    d.projectRoots(session);
    for (const text of ["git merge --no-edit side", "git cherry-pick side"]) {
      const broken = d.sandboxBreaks(text, r, session) ?? "";
      assert.match(broken, HELD, text);
      assert.ok(broken.includes(script), `${text}: ${broken}`);
    }
    // What it is asked about for: run under the wrapper on the tree before, ort follows the rename
    // and the merge fails with the script held ("Merge with strategy ort failed").
    // A commit that changes something else: told, as before.
    for (const text of ["git merge --no-edit plain", "git cherry-pick plain"]) assert.equal(d.sandboxBreaks(text, r, session), undefined, text);
  }));

test("r4 21: their side moves a directory that holds a read-only file of ours: git moves our file along, and the merge asks", () =>
  fixture((r, g, session) => {
    write(path.join(r, "tools", "a.sh"), "a\n");
    write(path.join(r, "tools", "b.sh"), "b\n");
    g("add", "-A");
    g("commit", "-qm", "one");
    g("checkout", "-q", "-b", "side");
    g("mv", "tools", "bin");
    g("commit", "-qm", "moved");
    g("checkout", "-q", "main");
    write(path.join(r, "tools", "pre-commit"), SCRIPT, 0o755);
    g("add", "-A");
    g("commit", "-qm", "hook");
    fs.symlinkSync("../../tools/pre-commit", path.join(r, ".git", "hooks", "pre-commit"));
    d.projectRoots(session);
    const broken = d.sandboxBreaks("git merge --no-edit side", r, session) ?? "";
    assert.match(broken, HELD);
    assert.ok(broken.includes(path.join(r, "tools", "pre-commit")), broken);
    // A rename within the directory moves no directory: told, as before.
    g("checkout", "-q", "-b", "side2", "main~1");
    g("mv", "tools/a.sh", "tools/z.sh");
    g("commit", "-qm", "renamed within");
    g("checkout", "-q", "main");
    assert.equal(d.sandboxBreaks("git merge --no-edit side2", r, session), undefined);
    // What git does: the script follows the directory (with merge.directoryRenames at its
    // default, a conflict "suggesting it should perhaps be moved"; moved all the same).
    const truth = `${r}-truth`;
    execFileSync("git", ["clone", "-q", r, truth]);
    gitIn(truth, "checkout", "-q", "main");
    spawnSync("git", ["-C", truth, "merge", "-q", "--no-edit", "origin/side"], { stdio: "ignore" });
    assert.ok(!fs.existsSync(path.join(truth, "tools", "pre-commit")) && fs.existsSync(path.join(truth, "bin", "pre-commit")), "the fixture: git moved it");
  }));

test("r4 21: a revert of a commit that moved a directory moves it back, and our read-only file added there since along with it: the revert asks", () =>
  fixture((r, g, session) => {
    write(path.join(r, "tools", "a.sh"), "a\n");
    write(path.join(r, "tools", "b.sh"), "b\n");
    g("add", "-A");
    g("commit", "-qm", "one");
    g("mv", "tools", "bin");
    g("commit", "-qm", "moved");
    write(path.join(r, "bin", "pre-commit"), SCRIPT, 0o755);
    g("add", "-A");
    g("commit", "-qm", "hook");
    fs.symlinkSync("../../bin/pre-commit", path.join(r, ".git", "hooks", "pre-commit"));
    d.projectRoots(session);
    const broken = d.sandboxBreaks("git revert --no-edit HEAD~1", r, session) ?? "";
    assert.match(broken, HELD);
    assert.ok(broken.includes(path.join(r, "bin", "pre-commit")), broken);
    // What git does.
    const truth = `${r}-truth`;
    execFileSync("git", ["clone", "-q", r, truth]);
    spawnSync("git", ["-C", truth, "revert", "--no-edit", "HEAD~1"], { stdio: "ignore" });
    assert.ok(!fs.existsSync(path.join(truth, "bin", "pre-commit")), "the fixture: git moved it");
  }));

test("r4 21: in a sparse checkout (core.sparseCheckout, index.sparse, or a sparse-checkout file) a command that writes the work tree cannot be told (Sonnet's F-2)", () =>
  fixture((r, g, session) => {
    const { asks, none } = heldRepo(r, g, session);
    const agents = path.join(r, "AGENTS.md");
    none("git checkout same");
    g("config", "core.sparseCheckout", "true");
    asks("git checkout same", agents);
    asks("git merge same", agents);
    none("git checkout -b fresh");
    g("config", "--unset", "core.sparseCheckout");
    g("config", "index.sparse", "true");
    asks("git switch same", agents);
    g("config", "--unset", "index.sparse");
    write(path.join(r, ".git", "info", "sparse-checkout"), "/*\n!AGENTS.md\n");
    asks("git reset --keep same", agents);
    fs.rmSync(path.join(r, ".git", "info", "sparse-checkout"));
    none("git checkout same");
  }));

test("r4 21: `git stash -u` and `-a` ask for the read-only paths that are not tracked as well (the empty .opencode the plan makes); a stash's untracked part is checked (Sonnet's F-4)", () =>
  fixture((r, g, session) => {
    write(path.join(r, "a.txt"), "a\n");
    g("add", "-A");
    commit(r);
    plainPlan(r);
    d.projectRoots(session);
    const opencode = path.join(r, ".opencode");
    assert.ok(fs.existsSync(opencode), "the fixture: the plan made .opencode");
    // (Something to stash: with nothing, git writes nothing, test/c-thirteenth.test.mts.)
    write(path.join(r, "a.txt"), "changed\n");
    for (const text of ["git stash -u", "git stash -a", "git stash --include-untracked", "git stash --all", "git stash push -u", "git stash push -m x --all", "git stash save -u x"]) {
      const broken = d.sandboxBreaks(text, r, session) ?? "";
      assert.match(broken, HELD, text);
      assert.ok(broken.includes(opencode), `${text}: ${broken}`);
    }
    for (const text of ["git stash", "git stash push -m x"]) assert.equal(d.sandboxBreaks(text, r, session), undefined, text);
    // What it is asked about for, run under the wrapper: "failed to remove .opencode/".
    write(path.join(r, "n.txt"), "n\n");
    const ran = sandboxed(planFor(r, "git stash -u"), "git stash -u", r);
    assert.notEqual(ran.status, 0, ran.stderr);
    assert.match(ran.stderr, /\.opencode/);
    // A stash whose untracked part holds a file below .opencode: its pop writes it.
    write(path.join(opencode, "x.md"), "x\n");
    g("stash", "-q", "-u");
    assert.ok(!fs.existsSync(path.join(opencode, "x.md")), "the fixture: stashed");
    for (const text of ["git stash pop", "git stash apply", "git stash apply 0"]) {
      const broken = d.sandboxBreaks(text, r, session) ?? "";
      assert.match(broken, HELD, text);
      assert.ok(broken.includes(path.join(opencode, "x.md")), `${text}: ${broken}`);
    }
    g("stash", "drop", "-q");
    // One whose untracked part holds nothing read-only writes nothing read-only.
    write(path.join(r, "m.txt"), "m\n");
    g("stash", "-q", "-u");
    assert.equal(d.sandboxBreaks("git stash pop", r, session), undefined);
    // Where .opencode is ignored, `-u` leaves it (`-a` does not).
    write(path.join(r, ".gitignore"), ".opencode/\n");
    g("add", ".gitignore");
    commit(r, "ignore");
    write(path.join(r, "a.txt"), "changed again\n");
    assert.equal(d.sandboxBreaks("git stash -u", r, session), undefined);
    assert.ok((d.sandboxBreaks("git stash -a", r, session) ?? "").includes(opencode), "git stash -a");
  }));

test("r4 21: writers the check counted as writing nothing: `--output` onto a read-only file, git svn and p4 rebase, filter-branch, lfs pull and checkout", () =>
  fixture((r, g, session) => {
    const { asks, none, script, agents } = heldRepo(r, g, session);
    for (const [text, file] of [
      ["git show --output=scripts/pre-commit HEAD", script],
      ["git log -1 --output AGENTS.md", agents],
      ["git diff --output=AGENTS.md HEAD^", agents],
      ["git format-patch -1 -o .opencode", path.join(r, ".opencode")],
      ["git stash show --output=AGENTS.md", agents],
    ] as const) asks(text, file);
    for (const text of ["git show --output=out.txt HEAD", "git show HEAD -- --output=AGENTS.md", "git log -1 --output=/dev/null", "git format-patch -1 -o patches"]) none(text);
    for (const text of ["git svn rebase", "git svn dcommit", "git p4 rebase", "git p4 submit", "git filter-branch --tree-filter true HEAD", "git lfs pull", "git lfs checkout", "git lfs migrate import"]) asks(text, agents);
    for (const text of ["git svn info", "git lfs fetch", "git lfs ls-files"]) none(text);
  }));

test("r4 21: `git submodule update`/`deinit`, `git worktree add`, `git mergetool` and `git am` ask before the read-only-file check: they are no plain git commands and write .git (why C11's notes on them change nothing; `git am`'s idle forms ask no more, test/c-thirteenth.test.mts)", () =>
  fixture((r, g, session) => {
    heldRepo(r, g, session);
    for (const text of ["git submodule update", "git submodule deinit -f lib", "git worktree add .opencode/wt", "git mergetool", "git am x.patch", "git am -3 x.patch"]) assert.match(d.sandboxBreaks(text, r, session) ?? "", /writes inside \.git, which is read-only unless the tool call is made only of plain git commands/, text);
  }));

// ---- 4. costs eased ----

test("r4 21: --abort, --continue, --skip, --quit with no operation in progress, and `git bisect reset` with no bisect, write nothing; with one in progress they cannot be told", () =>
  fixture((r, g, session) => {
    const { asks, none, agents } = heldRepo(r, g, session);
    const IDLE = ["git merge --abort", "git merge --continue", "git rebase --continue", "git rebase --abort", "git rebase --skip", "git cherry-pick --continue", "git cherry-pick --abort", "git cherry-pick --skip", "git revert --continue", "git revert --abort", "git revert --skip", "git bisect reset"];
    for (const text of IDLE) none(text);
    // (`-q` alone is no such option: a merge of the upstream.)
    asks("git merge -q", agents);
    // After a call that may start one: cannot be told.
    asks("git merge same; git merge --abort", agents);
    // A merge stopped on a conflict.
    g("checkout", "-q", "-b", "c1", "main");
    write(path.join(r, "a.txt"), "c1\n");
    g("commit", "-qam", "c1");
    g("checkout", "-q", "main");
    write(path.join(r, "a.txt"), "main\n");
    g("commit", "-qam", "main");
    assert.throws(() => g("merge", "-q", "c1"));
    for (const text of ["git merge --abort", "git merge --continue", "git cherry-pick --abort", "git rebase --abort"]) asks(text, agents);
    g("merge", "--abort");
    for (const text of IDLE) none(text);
    // A rebase stopped on one.
    assert.throws(() => g("rebase", "-q", "c1"));
    for (const text of ["git rebase --continue", "git rebase --skip", "git merge --abort"]) asks(text, agents);
    g("rebase", "--abort");
    // A bisect.
    g("bisect", "start");
    asks("git bisect reset", agents);
    g("bisect", "reset");
    none("git bisect reset");
  }));

test("r4 21: `git apply --check`, `--stat`, `--numstat`, `--summary` alone write nothing; `git apply` and one with --apply cannot be told", () =>
  fixture((r, g, session) => {
    const { asks, none, agents } = heldRepo(r, g, session);
    fs.appendFileSync(path.join(r, "a.txt"), "more\n");
    write(path.join(r, "x.patch"), g("diff"));
    g("checkout", "--", "a.txt");
    for (const text of ["git apply --check x.patch", "git apply --stat x.patch", "git apply --numstat x.patch", "git apply --summary x.patch", "git apply --check --index x.patch", "git apply --stat --summary -p1 x.patch"]) none(text);
    for (const text of ["git apply x.patch", "git apply --index x.patch", "git apply --stat --apply x.patch", "git apply --check --appl x.patch", "git apply -3 x.patch"]) asks(text, agents);
  }));

test("r4 21: a merge or rebase whose target is HEAD or an ancestor of it has nothing to do: told without asking; a rebase over merge commits rewrites them, and asks", () =>
  fixture((r, g, session) => {
    const { asks, none, agents } = heldRepo(r, g, session);
    // `anc` is behind `main` by a commit that changes AGENTS.md.
    for (const text of ["git rebase anc", "git merge anc", "git merge --ff-only anc", "git rebase main", "git merge main", "git rebase HEAD", "git rebase -q anc"]) none(text);
    // With --fork-point git looks for where to start in the upstream's reflog: read as before.
    asks("git rebase --fork-point anc", agents);
    // FETCH_HEAD with one head for merge is that commit; with two, git merges both.
    g("fetch", "-q", "origin", "main");
    none("git merge FETCH_HEAD");
    g("fetch", "-q", "origin", "main", "other");
    asks("git merge FETCH_HEAD", agents);
    // A merge commit between: git makes the history straight, rewriting it.
    g("checkout", "-q", "-b", "mm", "anc");
    write(path.join(r, "m.txt"), "m\n");
    g("add", "-A");
    g("commit", "-qm", "mm");
    g("checkout", "-q", "main");
    g("merge", "-q", "--no-edit", "--no-ff", "mm");
    asks("git rebase anc", agents);
    none("git merge anc");
  }));

test("r4 21: a `git pull` that asks says how to have it told: fetch first, then merge or rebase", () =>
  fixture((r, g, session) => {
    const { asks } = heldRepo(r, g, session);
    for (const text of ["git pull", "git pull --rebase", "git pull --ff-only origin main"]) asks(text, path.join(r, "AGENTS.md"), /run `git fetch` first, then `git merge --ff-only @\{upstream\}` or `git rebase @\{upstream\}`, which can be told/);
  }));

// ---- 6. lines no test held ----

test("r4 21: a git directory outside every writable directory whose hooks directory lies in the shared temp directory: a link there asks (sayFor keyed to the git directory, not the file)", () =>
  bareAndWorktree((base, bare, wt) => {
    const hooks = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "c-twelfth-hooks-")));
    try {
      write(path.join(base, "elsewhere", "pre-commit"), SCRIPT, 0o755);
      gitIn(bare, "config", "core.hooksPath", hooks);
      quiet(wt, "the fixture");
      fs.symlinkSync(path.join(base, "elsewhere", "pre-commit"), path.join(hooks, "pre-commit"));
      for (const problem of [plainPlan(wt).problem, planFor(wt, "git status").problem]) {
        assert.match(problem ?? "", LINK);
        assert.ok((problem ?? "").includes(path.join(hooks, "pre-commit")), problem);
      }
    } finally {
      fs.rmSync(hooks, { recursive: true, force: true });
    }
  }));

test("r4 21: `.sample` is skipped only for a hook directly in a hooks directory whose name ends so: one in info/, in a subdirectory of hooks/, or named `.sample.bak` with two names asks", () =>
  fixture((r) => {
    commit(r);
    const dotGit = path.join(r, ".git");
    const other = mkdir(`${r}-names`);
    assert.equal(plainPlan(r).problem, undefined, "the fixture");
    let n = 0;
    for (const file of [path.join(dotGit, "info", "foo.sample"), path.join(dotGit, "hooks", "sub", "x.sample"), path.join(dotGit, "hooks", "pre-commit.sample.bak")]) {
      write(file, SCRIPT, 0o755);
      fs.linkSync(file, path.join(other, `n${n++}`));
      const problem = plainPlan(r).problem ?? "";
      assert.match(problem, HARD, file);
      assert.ok(problem.includes(file), problem);
      fs.rmSync(file);
    }
    // The one that is skipped.
    fs.linkSync(path.join(dotGit, "hooks", "pre-commit.sample"), path.join(other, "sample"));
    assert.equal(plainPlan(r).problem, undefined);
  }));

test("r4 21: `git apply` without --cached cannot be told; a read-only file whose name begins with `:` is matched as a name, not as pathspec magic", () =>
  fixture((r, g, session) => {
    const { asks, none, agents } = heldRepo(r, g, session);
    asks("git apply x.patch", agents);
    // A linked hook's script named `:pc` at the top, which `other2` changes.
    const colon = path.join(r, ":pc");
    write(colon, SCRIPT, 0o755);
    g("add", "-A");
    g("commit", "-qm", "colon");
    g("checkout", "-q", "-b", "other2");
    fs.appendFileSync(colon, "# other\n");
    g("commit", "-qam", "other2");
    g("checkout", "-q", "main");
    fs.symlinkSync("../../:pc", path.join(r, ".git", "hooks", "pre-push"));
    asks("git checkout other2", colon);
  }));

test("r4 21: each group of the first part costs an entry of the allowance: the state files of a named git directory past an allowance of 30 are said", () =>
  fixture((r, _g, session) => {
    const before = { ...d.fingerprintLimits };
    const resume = path.join(mkdir(`${r}-resume`), "resume");
    try {
      commit(r);
      d.projectRoots(session);
      d.gitTampered(session, resume);
      const top = path.join(r, "planted");
      execFileSync("git", ["init", "-q", "-b", "main", top]);
      d.fingerprintLimits.first = 30;
      const first = d.gitTampered(session, resume) ?? "";
      assert.match(first, /cannot be compared whole where it matters: HEAD, packed-refs and the other state files \(more than 30 entries\)/, first);
    } finally {
      Object.assign(d.fingerprintLimits, before);
    }
  }));
