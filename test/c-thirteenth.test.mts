// Round 4, group C, thirteenth pass: the holes the two checks of the twelfth found, closed as the
// maintainer decided ("keep asking, close holes"; "yes, in C13"). git expands the include paths
// (`~user/`, `%(prefix)/`); the system configuration is read like your own; an include that does
// not exist yet in a shared temp directory asks; `git bisect reset <rev>` is a checkout;
// `branch.<name>.mergeOptions` is read for `--autostash`; `git am`'s idle forms ask no more, and
// neither does a `git stash -u` that has nothing to stash. Each test builds a repository of its
// own under the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-thirteenth.test.mts.
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
const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), `c-thirteenth-${name}-`)));
const gitIn = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const commit = (dir: string, message = "one") => gitIn(dir, "commit", "-q", "--allow-empty", "-m", message);
const write = (file: string, text: string | Buffer, mode?: number) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  if (mode !== undefined) fs.chmodSync(file, mode);
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
const editProblems = (r: string) => protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).problems;
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
// A system configuration of `text` (GIT_CONFIG_SYSTEM, read as git reads /etc/gitconfig; the
// runner sets GIT_CONFIG_NOSYSTEM, which is taken away) for the length of `fn`.
async function withSystem(file: string, text: string, fn: () => void | Promise<void>) {
  const before = { system: process.env.GIT_CONFIG_SYSTEM, nosystem: process.env.GIT_CONFIG_NOSYSTEM };
  write(file, text);
  process.env.GIT_CONFIG_SYSTEM = file;
  delete process.env.GIT_CONFIG_NOSYSTEM;
  try {
    await fn();
  } finally {
    for (const [name, value] of [["GIT_CONFIG_SYSTEM", before.system], ["GIT_CONFIG_NOSYSTEM", before.nosystem]] as const) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  }
}
const SCRIPT = "#!/bin/sh\nexit 0\n";
// Each of the three ways of judging a call names `at` and says `what`.
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
const HOOKS = /core\.hooksPath and git reads it only under a condition/;
// `file` as `~<you>/…`: your own name, which git expands to your home as the password file has
// it (getpwnam), not to $HOME.
const byName = (file: string) => {
  const me = os.userInfo();
  assert.ok(file.startsWith(`${me.homedir}/`), `the fixture: ${file} lies in ${me.homedir}`);
  return `~${me.username}/${path.relative(me.homedir, file)}`;
};

// ---- 1. git expands the include paths ----

test("r4 21: include paths are read as git expands them: `~<you>/` in your config names the file it names for git (Opus's q3 asks, q4 is held read-only); a name git cannot expand asks", () =>
  fixture(async (r, g) => {
    write(path.join(r, "a.txt"), "a\n");
    g("add", "-A");
    commit(r);
    quiet(r, "the fixture");
    // q3: `[includeIf "onbranch:feature"] path = ~<you>/…/feature.cfg`, which sets a relative
    // core.hooksPath. On `main` nothing names `.hooks-feature`; on `feature` git runs hooks there.
    const feature = path.join(`${r}-mine`, "feature.cfg");
    write(feature, "[core]\n\thooksPath = .hooks-feature\n");
    await withGlobal(`[includeIf "onbranch:feature"]\n\tpath = ${byName(feature)}\n`, () => asked(r, feature, HOOKS, "git switch -c feature"));
    quiet(r, "put back");
    // The same spelling in the repository's own config: the file it names, not "does not exist".
    g("config", "includeIf.onbranch:feature.path", byName(feature));
    asked(r, feature, HOOKS, "git switch -c feature");
    g("config", "--unset", "includeIf.onbranch:feature.path");
    // A relative path stays relative to the file that includes it (`--type=path` leaves it).
    write(path.join(`${r}-mine`, "outer.cfg"), `[includeIf "onbranch:x"]\n\tpath = feature.cfg\n`);
    await withGlobal(`[include]\n\tpath = ${byName(path.join(`${r}-mine`, "outer.cfg"))}\n`, () => asked(r, feature, HOOKS));
    // q4: `[include] path = ~<you>/<project>/gitconfig`, a dotfiles repository as the project.
    const dotfile = path.join(r, "gitconfig");
    write(dotfile, "[user]\n\tname = x\n");
    await withGlobal(`[include]\n\tpath = ${byName(dotfile)}\n`, () => {
      quiet(r, "a plain include in the project");
      for (const p of [plainPlan(r), planFor(r, "git status")]) assert.ok(p.ro.includes(dotfile), p.ro.join(", "));
      const ran = sandboxed(plainPlan(r), `printf '[core]\\n\\tfsmonitor = touch ${r}-mark\\n' >> gitconfig`, r);
      assert.notEqual(ran.status, 0, "the write to the include fails");
      assert.match(ran.stderr, /Read-only file system/);
      assert.equal(fs.readFileSync(dotfile, "utf8"), "[user]\n\tname = x\n");
    });
    // A user git does not know: git cannot expand it ("failed to expand user dir"), and stops.
    await withGlobal(`[include]\n\tpath = ~nosuchuser-c13/x.cfg\n`, () => {
      // (git stops for every command then: the first problem is its config, read whole.)
      for (const p of [plainPlan(r), planFor(r, "git status")]) assert.ok(p.problem, "asks");
      const problems = editProblems(r);
      assert.ok(problems.some((t) => t.includes(`could not say what ${process.env.GIT_CONFIG_GLOBAL} includes`)), problems.join("\n"));
    });
    quiet(r, "put back");
  }));

// ---- 2. the system configuration ----

test("r4 21: the system configuration (GIT_CONFIG_SYSTEM, or /etc/gitconfig) is read like your own: a conditional include that sets core.hooksPath asks wherever it lies, a plain include is held read-only; none under GIT_CONFIG_NOSYSTEM", () =>
  fixture(async (r, g) => {
    write(path.join(r, "a.txt"), "a\n");
    g("add", "-A");
    commit(r);
    quiet(r, "the fixture");
    const system = path.join(`${r}-etc`, "gitconfig");
    // Sonnet's F-3 and Opus's F3: `includeIf "onbranch:feature"`, the file outside the project.
    const feature = path.join(`${r}-etc`, "feature.cfg");
    write(feature, `[core]\n\thooksPath = ${r}/.hp\n`);
    await withSystem(system, `[includeIf "onbranch:feature"]\n\tpath = ${feature}\n`, () => {
      asked(r, feature, HOOKS, "git switch feature");
      // GIT_CONFIG_NOSYSTEM: git reads no system file, and nothing of it is asked about.
      process.env.GIT_CONFIG_NOSYSTEM = "1";
      quiet(r, "GIT_CONFIG_NOSYSTEM");
    });
    // A plain include of the system configuration, in the project: read-only.
    const inc = path.join(r, "sys.cfg");
    write(inc, "[user]\n\tname = x\n");
    await withSystem(system, `[include]\n\tpath = ${inc}\n`, () => {
      quiet(r, "a plain include in the project");
      for (const p of [plainPlan(r), planFor(r, "git status")]) assert.ok(p.ro.includes(inc), p.ro.join(", "));
      const ran = sandboxed(plainPlan(r), "echo '[core]' >> sys.cfg", r);
      assert.notEqual(ran.status, 0);
      assert.match(ran.stderr, /Read-only file system/);
    });
    // What git cannot list there is said.
    await withSystem(system, "[[[ no config\n", () => {
      const problems = editProblems(r);
      assert.ok(problems.some((t) => t.includes(`could not say what ${system} includes`)), problems.join("\n"));
    });
    quiet(r, "put back");
    // Where it lies when nothing names it.
    const before = { system: process.env.GIT_CONFIG_SYSTEM, nosystem: process.env.GIT_CONFIG_NOSYSTEM };
    try {
      delete process.env.GIT_CONFIG_SYSTEM;
      delete process.env.GIT_CONFIG_NOSYSTEM;
      assert.equal(sb.systemGitConfig(), "/etc/gitconfig");
      process.env.GIT_CONFIG_NOSYSTEM = "true";
      assert.equal(sb.systemGitConfig(), undefined);
      process.env.GIT_CONFIG_NOSYSTEM = "0";
      process.env.GIT_CONFIG_SYSTEM = system;
      assert.equal(sb.systemGitConfig(), system);
    } finally {
      for (const [name, value] of [["GIT_CONFIG_SYSTEM", before.system], ["GIT_CONFIG_NOSYSTEM", before.nosystem]] as const) {
        if (value === undefined) delete process.env[name];
        else process.env[name] = value;
      }
    }
  }));

// ---- 3. an include that does not exist yet in a shared temp directory ----

test("r4 21: an include whose file does not exist yet and lies in the shared temp directory asks, naming it, conditional or not, from the repository's config or your own (Sonnet's F-2)", () =>
  fixture(async (r, g) => {
    write(path.join(r, "a.txt"), "a\n");
    g("add", "-A");
    commit(r);
    quiet(r, "the fixture");
    const tmp = fs.realpathSync(os.tmpdir());
    const missing = path.join(tmp, `c13-inc-${process.pid}.cfg`);
    const deeper = path.join(tmp, `c13-dir-${process.pid}`, "inc.cfg");
    const MISSING = /does not exist/;
    const plans = (at: string) => {
      for (const [who, problem] of [["a plain call", plainPlan(r).problem], ["a git-only call", planFor(r, "git status").problem]] as const) {
        assert.match(problem ?? "", MISSING, `${at}: ${who}`);
        assert.ok((problem ?? "").includes(at), `${who}: ${problem}`);
      }
    };
    try {
      for (const file of [missing, deeper]) {
        for (const key of ["include.path", `includeIf.gitdir:${r}/.git.path`, "includeIf.onbranch:feature.path", "includeIf.hasconfig:remote.*.url:x.path"]) {
          g("config", key, file);
          plans(file);
          g("config", "--unset", key);
        }
        await withGlobal(`[includeIf "gitdir:${r}/.git"]\n\tpath = ${file}\n[include]\n\tpath = ${file}\n`, () => plans(file));
        await withSystem(path.join(`${r}-etc`, "gitconfig"), `[includeIf "onbranch:feature"]\n\tpath = ${file}\n`, () => plans(file));
        // Behind an include that exists.
        write(path.join(r, ".git", "outer.cfg"), `[includeIf "onbranch:x"]\n\tpath = ${file}\n`);
        g("config", "include.path", "outer.cfg");
        plans(file);
        g("config", "--unset", "include.path");
        quiet(r, "put back");
      }
      // One that exists there is held read-only, as before; one that does not exist outside every
      // writable directory cannot be made by a call.
      write(missing, "[user]\n\tname = x\n");
      g("config", "includeIf.onbranch:feature.path", missing);
      quiet(r, "an include in the temp directory that exists");
      assert.ok(plainPlan(r).ro.includes(missing));
      g("config", "includeIf.onbranch:feature.path", path.join(`${r}-nowhere`, "inc.cfg"));
      quiet(r, "an include outside every writable directory");
    } finally {
      fs.rmSync(missing, { force: true });
      fs.rmSync(path.dirname(deeper), { recursive: true, force: true });
    }
  }));

// ---- 4 to 7. the read-only-file check ----

const HELD = /keeps read-only/;
// A repository that tracks a linked hook's script (`scripts/pre-commit`), AGENTS.md and a.txt,
// on `main`: `anc` is its first commit, `main` changes AGENTS.md since; `same` (from main) changes
// b.txt alone, `other` the script.
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
  fs.symlinkSync("../../scripts/pre-commit", path.join(r, ".git", "hooks", "pre-commit"));
  d.projectRoots(session);
  const asks = (text: string, file = script, why: RegExp = HELD) => {
    const broken = d.sandboxBreaks(text, r, session) ?? "";
    assert.match(broken, why, text);
    assert.ok(broken.includes(file), `${text}: ${broken}`);
  };
  const none = (text: string) => assert.equal(d.sandboxBreaks(text, r, session), undefined, text);
  return { script, agents, asks, none };
}

test("r4 21: `git bisect reset <commit>` with no bisect checks the commit out: it cannot be told; `git bisect reset` alone writes nothing (Sonnet's F-1)", () =>
  fixture((r, g, session) => {
    const { asks, none, agents } = heldRepo(r, g, session);
    none("git bisect reset");
    for (const text of ["git bisect reset other", "git bisect reset same", "git bisect reset HEAD"]) asks(text, agents);
  }));

test("r4 21: `branch.<name>.mergeOptions` that holds `--autostash` (in any spelling git takes) makes a merge on that branch one that cannot be told; `--no-autostash` on the line, a detached HEAD or another branch's, as before (Sonnet's F-4)", () =>
  fixture((r, g, session) => {
    const { asks, none, agents } = heldRepo(r, g, session);
    none("git merge same");
    for (const value of ["--autostash", "--au", "'--autostash'", "--no-ff --autostash", "\"--autostash\" --log"]) {
      g("config", "branch.main.mergeOptions", value);
      asks("git merge same", agents);
      none("git merge --no-autostash same");
      // ("Already up to date" comes first, as for merge.autoStash.)
      none("git merge anc");
      g("config", "--unset", "branch.main.mergeOptions");
    }
    g("config", "branch.main.mergeOptions", "--no-ff");
    none("git merge same");
    g("config", "branch.main.mergeOptions", "--autostash");
    g("config", "branch.other.mergeOptions", "--autostash");
    g("config", "--unset", "branch.main.mergeOptions");
    none("git merge same");
    // Detached, git reads no branch's options.
    g("config", "branch.main.mergeOptions", "--autostash");
    g("checkout", "-q", "--detach", "main");
    none("git merge same");
    g("checkout", "-q", "main");
    // What it is asked about for, run under the wrapper (Sonnet's X12-F4): a dirty AGENTS.md is
    // stashed and cannot be put back over the read-only file.
    fs.appendFileSync(agents, "dirty\n");
    const ran = sandboxed(plainPlan(r), "git merge --no-edit same", r);
    assert.notEqual(ran.status, 0, ran.stdout);
  }));

test("r4 21: `git am --abort`, `--continue`, `--skip`, `--quit` with nothing in progress write nothing and ask no more, as for merge and rebase; with an `am` in progress, after another git call, or applying a patch, they ask", () =>
  fixture((r, g, session) => {
    const { asks, none } = heldRepo(r, g, session);
    const IDLE = ["git am --abort", "git am --continue", "git am --skip", "git am --quit", "git am -q --abort", "git am --abort --quiet"];
    for (const text of IDLE) none(text);
    // Run under the wrapper as index.ts runs it (no git-only call: `.git` read-only whole), and
    // as git runs it outside: the same refusal, nothing written.
    const head = g("rev-parse", "HEAD");
    for (const text of IDLE.slice(0, 4)) {
      const ran = sandboxed(plainPlan(r), text, r);
      const outside = spawnSync("bash", ["-c", text], { cwd: r, encoding: "utf8" });
      assert.equal(ran.status, outside.status, `${text}: ${ran.stderr}`);
      assert.equal(ran.status, 128, text);
      assert.match(ran.stderr, /not in progress/);
    }
    assert.equal(g("rev-parse", "HEAD"), head);
    assert.equal(g("status", "--porcelain"), "");
    const INSIDE = /writes inside \.git/;
    for (const text of ["git am x.patch", "git am --show-current-patch", "git am --abort x.patch", "git am -3 --continue"]) asks(text, "git am", INSIDE);
    // After a git call that may move something (one not known here), and after one that writes.
    asks("git frobnicate; git am --abort", "git am", INSIDE);
    asks("git merge same; git am --abort", "git merge", INSIDE);
    none("git log -1; git am --abort");
    // An `am` in progress.
    fs.mkdirSync(path.join(r, ".git", "rebase-apply"));
    for (const text of IDLE) asks(text, "git am", INSIDE);
    fs.rmSync(path.join(r, ".git", "rebase-apply"), { recursive: true });
    // Or another operation.
    fs.writeFileSync(path.join(r, ".git", "MERGE_HEAD"), `${head}`);
    asks("git am --abort", "git am", INSIDE);
    fs.rmSync(path.join(r, ".git", "MERGE_HEAD"));
    for (const text of IDLE) none(text);
  }));

test("r4 21: `git stash -u`/`-a` with nothing to stash (nothing changed, nothing untracked as git lists it: the plan's empty .opencode is not) writes nothing and asks no more; anything to stash asks as before", () =>
  fixture((r, g, session) => {
    write(path.join(r, "a.txt"), "a\n");
    write(path.join(r, ".gitignore"), "*.log\n");
    g("add", "-A");
    commit(r);
    plainPlan(r);
    d.projectRoots(session);
    const opencode = path.join(r, ".opencode");
    assert.ok(fs.existsSync(opencode), "the fixture: the plan made .opencode");
    // (With the spellings git takes besides: a cluster of short options, a long one by a prefix;
    // xcheck/c13/probes/stash-spellings.log.)
    const UNTRACKED = ["git stash -u", "git stash -a", "git stash --include-untracked", "git stash --all", "git stash push -u", "git stash push -m x --all", "git stash save -u x", "git stash -qu", "git stash push -ku", "git stash push -qa", "git stash --incl", "git stash push --al", "git stash save -qu x"];
    const none = (text: string) => assert.equal(d.sandboxBreaks(text, r, session), undefined, text);
    const asks = (text: string) => {
      const broken = d.sandboxBreaks(text, r, session) ?? "";
      assert.match(broken, HELD, text);
      assert.ok(broken.includes(opencode), `${text}: ${broken}`);
    };
    for (const text of UNTRACKED) none(text);
    // Under the wrapper, as git runs it: "No local changes to save", .opencode left.
    const ran = sandboxed(planFor(r, "git stash -u"), "git stash -u", r);
    assert.equal(ran.status, 0, ran.stderr);
    assert.match(ran.stdout, /No local changes to save/);
    assert.ok(fs.existsSync(opencode));
    // After another git call that may change that: as before.
    asks("git add -A && git stash -u");
    // A tracked change: git stashes it and then cleans with -d, which takes the empty .opencode
    // away too (run, git 2.47.3).
    write(path.join(r, "a.txt"), "b\n");
    for (const text of UNTRACKED) asks(text);
    g("checkout", "--", "a.txt");
    // One in the index alone.
    write(path.join(r, "a.txt"), "c\n");
    g("add", "a.txt");
    write(path.join(r, "a.txt"), "a\n");
    for (const text of UNTRACKED) asks(text);
    g("reset", "-q");
    for (const text of UNTRACKED) none(text);
    // An untracked file.
    write(path.join(r, "n.txt"), "n\n");
    for (const text of UNTRACKED) asks(text);
    fs.rmSync(path.join(r, "n.txt"));
    // An ignored one: `-a` stashes it, `-u` leaves it.
    write(path.join(r, "x.log"), "x\n");
    for (const text of ["git stash -a", "git stash --all", "git stash push -m x --all", "git stash push -qa", "git stash push --al"]) asks(text);
    for (const text of ["git stash -u", "git stash --include-untracked", "git stash push -u", "git stash -qu", "git stash --incl"]) none(text);
    fs.rmSync(path.join(r, "x.log"));
    // Where the work tree cannot be read here without running a program of the project (a clean
    // filter), it is not read: as before.
    write(path.join(r, ".gitattributes"), "*.txt filter=f\n");
    g("add", ".gitattributes");
    commit(r, "attributes");
    g("config", "filter.f.clean", `${r}/clean.sh`);
    asks("git stash -u");
    g("config", "--unset", "filter.f.clean");
    for (const text of UNTRACKED) none(text);
    // Where .opencode is ignored, `-u` in any spelling leaves it, `-a` in any takes it.
    write(path.join(r, ".gitignore"), "*.log\n.opencode/\n");
    g("add", ".gitignore");
    commit(r, "ignore");
    write(path.join(r, "a.txt"), "d\n");
    for (const text of ["git stash -u", "git stash -qu", "git stash --incl"]) none(text);
    for (const text of ["git stash -a", "git stash push -qa", "git stash push --al"]) asks(text);
  }));
