// Round 4, group C, eighth pass: what the checks of the seventh pass found. A symbolic link in a
// git directory that is read-only whole; a git command whose place is not known and that only
// reads; the `cd` forms of the shape in a git-only call; `CDPATH` and `git -C`; a pull into a
// submodule whose git directory cannot be written; what a named directory holds; a hooks path
// that cannot be followed; a module inside the reopened one; git's variables the other way
// round (the hook-level half is in test/plugin.test.mts); `cd -` in an approved command; the
// aborts under `submodule.recurse`. Each test builds a repository of its own under the
// throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-eighth.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";
import { envKept, gitElsewhere, plan, protectedPaths, type Plan } from "../sandbox.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), `c-eighth-${name}-`)));
const gitIn = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const tryGit = (dir: string, ...args: string[]) => spawnSync("git", ["-C", dir, ...args], { encoding: "utf8" });
const commit = (dir: string, message = "one") => gitIn(dir, "commit", "-q", "--allow-empty", "-m", message);
const write = (file: string, text: string, mode?: number) => {
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
const guard = (allowedPaths: string[] = [], resumeFile?: string): d.Guard => ({
  rules: compileRules({ ask: d.DEFAULT_ASK }),
  guarded: [ROOT],
  configDirs: [path.join(os.homedir(), ".config", "opencode")],
  allowedPaths,
  classifier: DEFAULT_CLASSIFIER,
  useClassifier: false,
  sshHosts: [],
  allowFeatureBranchPush: false,
  ...(resumeFile ? { resumeFile } : {}),
});
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
function sandboxed(p: Plan, command: string, cwd: string, extra: Record<string, string> = {}, keepEnv: string[] = []) {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  const env: Record<string, string | undefined> = { ...process.env, ...extra };
  delete env.NODE_TEST_CONTEXT;
  const { keep, dropped } = envKept(env, keepEnv);
  for (const name of dropped) delete env[name];
  Object.assign(env, { AUTOMODE_ENV_KEEP: keep.join("\n"), AUTOMODE_SHELL: "/bin/bash", AUTOMODE_COMMAND: command, ...planEnv(p) });
  return spawnSync(WRAPPER, ["-c", command], { cwd, env, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 120_000 });
}
// The plan index.ts makes for an allowed git-only call.
const planFor = (r: string, command: string, cwd = r, more: Partial<ReturnType<typeof opts>> = {}) =>
  plan({ ...opts(r), ...more, gitCwds: d.gitDirectories(command, cwd), gitWriteCwds: d.gitWriteDirectories(command, cwd), gitMaintainCwds: d.gitMaintainDirectories(command, cwd), gitPushTo: d.pushDestinations(command, cwd) });
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

const OUTSIDE = /an approved run happens outside the sandbox/;
const HTTPS = "https://example.invalid/team/x.git";
const SSH = "git@example.invalid:team/x.git";
const FILE = ["-c", "protocol.file.allow=always"];
// `protocol.file.allow=always` for a fetch from a path, as the user's own environment.
const FILE_ENV = { GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "protocol.file.allow", GIT_CONFIG_VALUE_0: "always" };
// The terms this kernel gives, and the ones a kernel at the floor gives (Landlock ABI 5).
const ABIS: Record<string, string>[] = [{}, { AUTOMODE_FAKE_ABI: "5" }];

// A project with the submodule `lib`, added for real from a repository beside it (git keeps its
// git directory under `.git/modules/lib`), or with `inTree` in the submodule's own work tree.
async function withLib(inTree: boolean, fn: (r: string, session: d.SessionState, g: (...args: string[]) => string, upstream: string) => void | Promise<void>) {
  await fixture(async (r, g, session) => {
    const upstream = `${r}-lib-upstream`;
    execFileSync("git", ["init", "-q", "-b", "main", upstream]);
    write(path.join(upstream, "tracked"), "one\n");
    gitIn(upstream, "add", "tracked");
    gitIn(upstream, "commit", "-qm", "lib one");
    commit(r);
    if (inTree) execFileSync("git", ["clone", "-q", upstream, path.join(r, "lib")]);
    g(...FILE, "submodule", "add", "-q", upstream, "lib");
    g("commit", "-qm", "a submodule");
    assert.equal(fs.lstatSync(path.join(r, "lib", ".git")).isDirectory(), inTree);
    await fn(r, session, g, upstream);
  });
}

// ---- 1. a symbolic link in a git directory that is read-only whole ----

// `.git/<name>` moved to `<project>/store-<name>` (made there when it is not in `.git`) with a
// link left in its place, for the time of `fn`.
function linkedOut(dotGit: string, name: string, target: string, fn: () => void) {
  const at = path.join(dotGit, name);
  const had = fs.existsSync(at);
  if (had) fs.renameSync(at, target);
  else fs.mkdirSync(target, { recursive: true });
  fs.symlinkSync(target, at);
  try {
    fn();
  } finally {
    fs.rmSync(at);
    if (had) fs.renameSync(target, at);
    else fs.rmSync(target, { recursive: true, force: true });
  }
}

test("r4 21: a link at the top of the git directory around a module that leads into the project makes the call ask: nothing is written through it", () =>
  withLib(false, (r, session, g) => {
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    const first = g("rev-list", "--max-parents=0", "HEAD").trim();
    const main = g("rev-parse", "main").trim();
    assert.notEqual(first, main, "the fixture: two commits");
    d.projectRoots(session);
    assert.equal(planFor(r, "git status", lib).problem, undefined, "the fixture: without a link the call is planned");
    for (const name of ["refs", "info", "objects", "lfs", "logs"]) {
      linkedOut(dotGit, name, path.join(r, `store-${name}`), () => {
        const p = planFor(r, "git status", lib);
        // Either the call asks, or the sandbox keeps what lies behind the link read-only.
        if (p.problem === undefined) {
          const forged = sandboxed(p, name === "refs" ? `printf '%s\\n' ${first} > ${dotGit}/refs/heads/main` : `echo planted > ${dotGit}/${name}/probe`, lib);
          assert.notEqual(forged.status, 0, `${name}: a call in the submodule wrote the superproject's git directory through the link`);
        }
        assert.equal(g("rev-parse", "main").trim(), main, `${name}: the superproject's main was forged`);
        assert.match(p.problem ?? "", /symbolic link/, name);
        assert.ok((p.problem ?? "").includes(path.join(dotGit, name)), `${name}: ${p.problem}`);
      });
    }
    // A file behind a link, too: `config.worktree` as a link to a file of the project.
    write(path.join(r, "shared-config"), "");
    fs.symlinkSync(path.join(r, "shared-config"), path.join(dotGit, "config.worktree"));
    assert.match(planFor(r, "git status", lib).problem ?? "", /symbolic link/);
    fs.rmSync(path.join(dotGit, "config.worktree"));
    assert.equal(planFor(r, "git status", lib).problem, undefined, "the fixture: put back, the call is planned again");
  }));

test("r4 21: a link there whose target lies outside the writable directories changes nothing: the call is planned, runs, and cannot write through it", () =>
  withLib(false, (r, session, g) => {
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    const main = g("rev-parse", "main").trim();
    const first = g("rev-list", "--max-parents=0", "HEAD").trim();
    d.projectRoots(session);
    // Beside the project, in the home directory: read-only in every sandbox.
    linkedOut(dotGit, "refs", `${r}-refs`, () => {
      const p = planFor(r, "git status", lib);
      assert.equal(p.problem, undefined);
      assert.notEqual(sandboxed(p, `printf '%s\\n' ${first} > ${dotGit}/refs/heads/main`, lib).status, 0);
      assert.equal(g("rev-parse", "main").trim(), main);
      // The link itself cannot be replaced: its directory is read-only.
      assert.notEqual(sandboxed(p, `rm ${dotGit}/refs && ln -s /tmp ${dotGit}/refs`, lib).status, 0);
      assert.equal(fs.readlinkSync(path.join(dotGit, "refs")), `${r}-refs`);
      assert.equal(sandboxed(p, "git status --short", lib).status, 0);
    });
    // A temp directory is writable in every sandbox: a link there is the first case again.
    const inTmp = fs.mkdtempSync(path.join(os.tmpdir(), "c-eighth-refs-"));
    try {
      fs.rmSync(inTmp, { recursive: true });
      linkedOut(dotGit, "refs", inTmp, () => assert.match(planFor(r, "git status", lib).problem ?? "", /symbolic link/));
    } finally {
      fs.rmSync(inTmp, { recursive: true, force: true });
    }
    // And one that leads to another place inside the same read-only git directory.
    fs.symlinkSync(path.join(dotGit, "info"), path.join(dotGit, "lfs"));
    assert.equal(planFor(r, "git status", lib).problem, undefined);
    fs.rmSync(path.join(dotGit, "lfs"));
    // One that leads into the module the call may write is the first case again.
    fs.symlinkSync(path.join(dotGit, "modules", "lib", "refs"), path.join(dotGit, "lfs"));
    assert.match(planFor(r, "git status", lib).problem ?? "", /symbolic link/);
  }));

test("r4 21: the same for every call that has the git directory read-only whole, and not for the one that may write it anyway", () =>
  fixture((r, g, session) => {
    commit(r);
    const dotGit = path.join(r, ".git");
    d.projectRoots(session);
    linkedOut(dotGit, "refs", path.join(r, "store-refs"), () => {
      // An ordinary call: `.git` is read-only, and `store-refs/heads/main` is a file of the project.
      assert.match(plan({ ...opts(r), gitWritable: false }).problem ?? "", /symbolic link/);
      // The edit tool asks for the same reason.
      assert.ok(protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).problems.some((text) => /symbolic link/.test(text)));
      // A git-only call in the repository itself may write its refs anyway.
      const p = planFor(r, "git status");
      assert.equal(p.problem, undefined);
      assert.equal(sandboxed(p, "git commit -q --allow-empty -m two", r).status, 0);
    });
    assert.equal(g("log", "-1", "--format=%s").trim(), "two");
  }));

test("r4 21: one level down: a module's place that is a link, the way to the modules, and the linked worktree's grant", () =>
  withLib(false, async (r, session, g, upstream) => {
    g(...FILE, "submodule", "add", "-q", upstream, "other");
    g("commit", "-qm", "another submodule");
    const feature = `${r}-feature`;
    g("worktree", "add", "-q", "-b", "feature", feature);
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    const roots = d.projectRoots(session);
    const inFeature = (command: string) => plan({ ...opts(r), projectRoots: roots, gitCwds: d.gitDirectories(command, feature), gitWriteCwds: d.gitWriteDirectories(command, feature), gitMaintainCwds: [], gitPushTo: [] });
    assert.equal(inFeature("git status").problem, undefined, "the fixture: a call in the linked worktree is planned");
    // `.git/modules/evil` a link to a directory of the project that is no repository: a module's
    // name whose content any call can make.
    fs.mkdirSync(path.join(r, "elsewhere"));
    fs.symlinkSync(path.join(r, "elsewhere"), path.join(dotGit, "modules", "evil"));
    assert.match(planFor(r, "git status", lib).problem ?? "", /symbolic link/, "a call in a submodule");
    assert.match(inFeature("git status").problem ?? "", /symbolic link/, "a call in a linked worktree");
    fs.rmSync(path.join(dotGit, "modules", "evil"));
    // `.git/worktrees/evil` likewise.
    fs.symlinkSync(path.join(r, "elsewhere"), path.join(dotGit, "worktrees", "evil"));
    assert.match(planFor(r, "git status", lib).problem ?? "", /symbolic link/, "a call in a submodule");
    assert.match(inFeature("git status").problem ?? "", /symbolic link/, "a call in a linked worktree");
    fs.rmSync(path.join(dotGit, "worktrees", "evil"));
    // The way to the modules: `.git/modules` itself a link into the project. The module is then
    // a directory of the project, and so is the place of every module yet to be made.
    // (git ties a module to its work tree by a path from the module: made a full one, so that it
    // still holds from the module's new place.)
    gitIn(lib, "config", "core.worktree", lib);
    gitIn(path.join(r, "other"), "config", "core.worktree", path.join(r, "other"));
    fs.renameSync(path.join(dotGit, "modules"), path.join(r, "mods"));
    fs.symlinkSync(path.join(r, "mods"), path.join(dotGit, "modules"));
    assert.equal(gitIn(lib, "status", "--short").trim(), "", "the fixture: git follows the link to the module");
    const fresh = new d.SessionState(r);
    try {
      d.projectRoots(fresh);
      assert.match(planFor(r, "git status", lib).problem ?? "", /symbolic link/, "a call in a submodule");
      assert.match(inFeature("git status").problem ?? "", /symbolic link/, "a call in a linked worktree");
    } finally {
      d.closeGitSnapshot(fresh);
    }
  }));

// ---- 2. a git command whose place is not known, or is one of several ----

// A project with `a/b` and a nested repository `sub`.
async function withSub(fn: (r: string, session: d.SessionState, g: (...args: string[]) => string) => void | Promise<void>) {
  await fixture(async (r, g, session) => {
    commit(r);
    fs.mkdirSync(path.join(r, "a", "b"), { recursive: true });
    execFileSync("git", ["init", "-q", "-b", "main", path.join(r, "sub")]);
    commit(path.join(r, "sub"));
    await fn(r, session, g);
  });
}
// Texts whose git commands only read, in a place that is not known or is one of several: with
// what the call is granted (the directories of the commands whose place is known).
const READS_ANYWHERE: [string, string[]][] = [
  ["cd sub && cd - && git status", []],
  ["cd sub; cd -; git status", []],
  ["cd && git status", []],
  ["cd - && git log --oneline -3", []],
  ["cd nowhere && git status", []],
  ["cd /tmp; cd - ; git status", []],
  ["git status; cd sub; git status", ["."]],
  ["git status; cd sub; git log --oneline -1", ["."]],
  ["git add -A; cd sub; git status", ["."]],
  ["git -C '' status", ["."]],
  ["git -C nowhere status", []],
];
// The same with a command that writes its git directory there: the call asks.
const WRITES_ANYWHERE = ["cd sub && cd - && git add -A", "cd sub; cd -; git commit -m x", "cd && git add -A", "cd nowhere && git commit -m x", "git status; cd sub; git add -A", "git status; cd sub; git commit -m x", "git add -A; cd sub; git stash", "git -C nowhere add -A", "cd sub && cd - && git gc", "git status; cd sub; git fetch origin"];

test("r4 21: a git command that only reads needs no grant: where its place is not known, or one of several, the call does not ask at the plan", () =>
  withSub((r, session) => {
    d.projectRoots(session);
    for (const [text, granted] of READS_ANYWHERE) {
      assert.ok(d.gitOnly(text), `${JSON.stringify(text)} is git-only`);
      let dirs: string[] = [];
      assert.equal(asks(() => (dirs = d.gitDirectories(text, r))), undefined, text);
      assert.deepEqual(dirs.map((dir) => path.relative(r, dir) || "."), granted, text);
      assert.equal(asks(() => d.gitWriteDirectories(text, r)), undefined, text);
      assert.equal(asks(() => d.gitMaintainDirectories(text, r)), undefined, text);
      assert.equal(asks(() => d.pushDestinations(text, r)), undefined, text);
      // The functions index.ts calls outside its own `try` must not throw.
      assert.equal(asks(() => d.sandboxBreaks(text, r, session)), undefined, text);
      assert.equal(asks(() => d.expectedRepos(text, r)), undefined, text);
      const p = planFor(r, text);
      assert.equal(p.problem, undefined, text);
      // Only the repositories of the commands whose place is known are the call's.
      assert.deepEqual(p.gitDirs, granted.length ? [path.join(r, ".git")] : [], text);
    }
    // And they run: a reader works on a git directory that is read-only.
    for (const text of ["git status; cd sub; git status", "git -C '' status", "cd sub && cd - && git status", "git status; cd sub; git log --oneline -1"]) {
      const ran = sandboxed(planFor(r, text), text, r);
      assert.equal(ran.status, 0, `${text}: ${ran.stderr}`);
    }
  }));

test("r4 21: a command that writes its git directory in a place that is not known, or in one of several repositories, asks as before", () =>
  withSub((r, session) => {
    d.projectRoots(session);
    for (const text of WRITES_ANYWHERE) {
      assert.ok(d.gitOnly(text), `${JSON.stringify(text)} is git-only`);
      assert.match(asks(() => d.gitDirectories(text, r)) ?? "", /cannot tell/, text);
      assert.equal(asks(() => d.sandboxBreaks(text, r, session)), undefined, `${text}: sandboxBreaks must not throw`);
      assert.equal(asks(() => d.expectedRepos(text, r)), undefined, `${text}: expectedRepos must not throw`);
    }
  }));

test("r4 21: git -C '' is no move at all, to git: the command works where it stands, and its add is granted and runs", () =>
  withSub((r, session, g) => {
    d.projectRoots(session);
    write(path.join(r, "new"), "new\n");
    for (const text of ["git -C '' add -A new", "git -C '' -C '' add -A new", "cd a && git -C '' -C .. add -A new"]) {
      assert.deepEqual(d.gitWriteDirectories(text, r), [r], text);
      const ran = sandboxed(planFor(r, text), text, r);
      assert.equal(ran.status, 0, `${text}: ${ran.stderr}`);
    }
    assert.match(g("status", "--short"), /^A {2}new$/m);
    assert.deepEqual(d.gitDirectories("git -C '' -C a status", r), [path.join(r, "a")]);
  }));

test("r4 21: several places in one repository are one grant: the call is planned and runs", () =>
  withSub((r, session, g) => {
    d.projectRoots(session);
    write(path.join(r, "a", "new"), "new\n");
    // After `git status ;` the cd may have failed: the add runs in `a` or in the project, both
    // in the project's repository.
    const text = "git status; cd a; git add -A .";
    assert.deepEqual([...d.gitDirectories(text, r)].sort(), [r, path.join(r, "a")].sort());
    assert.equal(d.gitWriteDirectories(text, r).length, 1);
    const p = planFor(r, text);
    assert.equal(p.problem, undefined);
    assert.deepEqual(p.gitDirs, [path.join(r, ".git")]);
    const ran = sandboxed(p, text, r);
    assert.equal(ran.status, 0, ran.stderr);
    assert.match(g("status", "--short"), /^A {2}a\/new$/m);
  }));

// The `cd` forms of the shape (guard.ts, knownShape): each with where its git command ends from
// the directory `a` of the project.
const SHAPED = (r: string): [string, string][] => [
  ['cd "$(git rev-parse --show-toplevel)" && git commit -q --allow-empty -m x', r],
  ['cd "$(git rev-parse --show-toplevel)" && git add .', r],
  ["cd $(git rev-parse --show-toplevel) && git add .", r],
  ['cd "$(git rev-parse --show-toplevel)"; git add -A', r],
  ['cd "$(git rev-parse --show-toplevel)"\ngit add -A', r],
  ['cd "$(git rev-parse --show-toplevel)"/sub && git add -A', path.join(r, "sub")],
  ['cd "$(git rev-parse --show-toplevel)/a/b" && git add -A', path.join(r, "a", "b")],
  ['cd "$(pwd)" && git add -A', path.join(r, "a")],
  ['cd "$PWD" && git add -A', path.join(r, "a")],
  ['cd "$PWD"/b && git add -A', path.join(r, "a", "b")],
  ['cd "${PWD}/b" && git add -A', path.join(r, "a", "b")],
  ["cd $PWD/b && git add -A", path.join(r, "a", "b")],
  ['cd b && cd "$(git rev-parse --show-toplevel)" && git add -A', r],
  ['cd "$(git rev-parse --show-toplevel)" && cd sub && git add -A', path.join(r, "sub")],
  ['cd "$(git rev-parse --show-toplevel)" && git rev-parse --show-toplevel && git add -A', r],
];

test("r4 21: the reading of a git-only call takes the cd forms of the shape: the call gets its writable git directory, and runs", () =>
  withSub(async (r, session, g) => {
    d.projectRoots(session);
    const a = path.join(r, "a");
    for (const [text, end] of SHAPED(r)) {
      assert.ok(d.gitOnly(text), `${JSON.stringify(text)} is git-only`);
      assert.deepEqual(d.gitWriteDirectories(text, a), [end], text);
      assert.equal(d.sandboxBreaks(text, a, session), undefined, text);
    }
    // `cd "$HOME"` is of the shape too; git then runs in the home directory, in no repository.
    assert.ok(d.gitOnly('cd "$HOME" && git status'));
    assert.deepEqual(d.gitDirectories('cd "$HOME" && git status', a), [os.homedir()]);
    void g;
  }));

test("r4 21: cd to the top of the repository, then git add . and git commit: decided, planned and run from a directory below the top", () =>
  fixture(async (r, g, session) => {
    commit(r);
    const a = path.join(r, "a");
    write(path.join(a, "new"), "new\n");
    d.projectRoots(session);
    for (const text of ['cd "$(git rev-parse --show-toplevel)" && git add .', 'cd "$(git rev-parse --show-toplevel)" && git commit -q -m shaped']) {
      const decision = await d.decideShell(guard(), session, a, text);
      assert.equal(decision.effect, "allow", `${text}: ${decision.reason}`);
      const run = decision.printed ?? text;
      assert.ok(d.gitOnly(run), `the printed text is git-only: ${run}`);
      assert.equal(d.sandboxBreaks(run, a, session), undefined, run);
      const p = planFor(r, run, a);
      assert.equal(p.problem, undefined, run);
      assert.deepEqual(p.gitDirs, [path.join(r, ".git")], run);
      const ran = sandboxed(p, run, a);
      assert.equal(ran.status, 0, `${run}: ${ran.stderr}`);
    }
    assert.equal(g("log", "-1", "--format=%s").trim(), "shaped");
    assert.match(g("show", "--stat", "--format=", "HEAD"), /a\/new/);
  }));

test("r4 21: nothing else is taken with them: a substitution anywhere else, another one in a cd, or the same text inside a quoted word is no git-only call", () =>
  withSub((r) => {
    const not = [
      'cd "$(git rev-parse --show-toplevel)" && git add "$(git rev-parse --show-toplevel)"',
      'cd "$(git rev-parse --git-dir)" && git add -A',
      'cd "$(git  rev-parse --show-toplevel)" && git add -A',
      'cd "$(pwd; touch ran)" && git add -A',
      'cd "$HOME$(touch ran)" && git add -A',
      'cd "$OLDPWD" && git add -A',
      'cd "$PWD/$x" && git add -A',
      'cd "$PWD/a b" && git add -A',
      'cd "$PWD" extra && git add -A',
      'cd -P "$PWD" && git add -A',
      'git -C "$PWD" add -A',
      'git -C "$(git rev-parse --show-toplevel)" add -A',
      'git add "$PWD"',
      'echo "$(pwd)" && git add -A',
      'cd "$(git rev-parse --show-toplevel)" && git add -A && ls',
      'cd "$PWD" | git add -A',
      'cd "$PWD"x && git add -A',
      'cd x"$PWD" && git add -A',
      'cd "$PWD""$PWD" && git add -A',
      "cd '$PWD' && git add -A && git commit -m \"$(git log -1)\"",
    ];
    for (const text of not) assert.equal(d.gitOnly(text), false, text);
    // Inside a quoted word the same text is a message, as before: one command, in the directory
    // the call starts in.
    for (const text of ["git commit -m 'cd \"$PWD\" && git add -A'", "git commit -m 'x; cd \"$(git rev-parse --show-toplevel)\"; y'", "git commit -m 'x\ncd $PWD\ny'"]) {
      assert.ok(d.gitOnly(text), text);
      assert.deepEqual(d.gitDirectories(text, r), [r], text);
    }
    // A quoted `$PWD` is a directory of that name to bash: not there, so its writer asks.
    assert.match(asks(() => d.gitDirectories("cd '$PWD' && git add -A", r)) ?? "", /cannot tell/);
  }));

// ---- 3. CDPATH in the plugin's own environment ----

test("r4 21: git -C is a chdir and never reads CDPATH: with one in the plugin's environment its place is read as ever, and its add runs", () =>
  withSub((r, session, g) => {
    d.projectRoots(session);
    write(path.join(r, "a", "x.txt"), "x\n");
    const had = process.env.CDPATH;
    process.env.CDPATH = `.:${os.homedir()}/projects`;
    try {
      assert.deepEqual(d.gitDirectories("git -C a add x.txt", r), [path.join(r, "a")]);
      assert.deepEqual(d.gitDirectories("git -C a -C b status", r), [path.join(r, "a", "b")]);
      assert.deepEqual(d.gitDirectories("git -C sub log --oneline -1", r), [path.join(r, "sub")]);
      assert.equal(d.sandboxBreaks("git -C a add x.txt", r, session), undefined);
      // What an approved command there creates is expected where git makes it.
      assert.deepEqual(d.expectedRepos("git -C a init", r), [path.join(r, "a")]);
      assert.deepEqual(d.expectedRepos("git -C a clone https://example.invalid/x.git", r), [path.join(r, "a", "x")]);
      assert.deepEqual(d.expectedRepos("git -C a -C b init fresh", r), [path.join(r, "a", "b", "fresh")]);
      const text = "git -C a add x.txt";
      const p = planFor(r, text);
      assert.equal(p.problem, undefined);
      const ran = sandboxed(p, text, r);
      assert.equal(ran.status, 0, ran.stderr);
      assert.match(g("status", "--short"), /^A {2}a\/x\.txt$/m);
    } finally {
      if (had === undefined) delete process.env.CDPATH;
      else process.env.CDPATH = had;
    }
  }));

// ---- 4. a pull into a submodule whose git directory cannot be written ----

// A project whose submodule `lib` has its git directory where `gitDirOf` says (its `.git` is a
// pointer file), and whose origin is one commit ahead: that commit moves the submodule from
// `one` to `two`.
async function withPointer(gitDirOf: (r: string) => string, fn: (r: string, session: d.SessionState, g: (...args: string[]) => string, at: { lib: string; one: string; two: string; gitDir: string }) => void | Promise<void>) {
  await fixture(async (r, g, session) => {
    const upstream = `${r}-lib-upstream`;
    const origin = `${r}-origin.git`;
    execFileSync("git", ["init", "-q", "-b", "main", upstream]);
    commit(upstream, "lib one");
    commit(r);
    const gitDir = gitDirOf(r);
    const lib = path.join(r, "lib");
    fs.mkdirSync(path.dirname(gitDir), { recursive: true });
    execFileSync("git", ["clone", "-q", `--separate-git-dir=${gitDir}`, upstream, lib]);
    g(...FILE, "submodule", "add", "-q", upstream, "lib");
    g("commit", "-qm", "a submodule");
    assert.ok(fs.lstatSync(path.join(lib, ".git")).isFile() && !fs.existsSync(path.join(r, ".git", "modules", "lib")), "the fixture: a pointer file to a git directory outside modules/");
    const one = gitIn(lib, "rev-parse", "HEAD").trim();
    commit(upstream, "lib two");
    const two = gitIn(upstream, "rev-parse", "HEAD").trim();
    gitIn(lib, "fetch", "-q", "origin");
    gitIn(lib, "checkout", "-q", two);
    g("commit", "-qam", "move lib");
    execFileSync("git", ["clone", "-q", "--bare", r, origin]);
    g("remote", "add", "origin", origin);
    g("fetch", "-q", "origin");
    g("branch", "-q", "--set-upstream-to=origin/main");
    // Back to the commit before: the pull has a commit to bring, and it moves the submodule.
    g("reset", "-q", "--hard", "HEAD~1");
    gitIn(lib, "checkout", "-q", one);
    await fn(r, session, g, { lib, one, two, gitDir });
  });
}
const PULLS = ["git pull --recurse-submodules", "git pull --rebase --recurse-submodules=yes"];

test("r4 21: a pull that moves a submodule whose git directory is kept in the project outside modules/ works: it is not asked about, and the submodule moves", async () => {
  for (const command of PULLS) {
    await withPointer(
      (r) => path.join(r, "gitdirs", "lib.git"),
      (r, session, g, at) => {
        d.projectRoots(session);
        assert.equal(d.sandboxBreaks(command, r, session), undefined, command);
        const ran = sandboxed(planFor(r, command), command, r, FILE_ENV, Object.keys(FILE_ENV));
        assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
        assert.equal(g("log", "-1", "--format=%s").trim(), "move lib", "the pull brought the commit");
        assert.equal(gitIn(at.lib, "rev-parse", "HEAD").trim(), at.two, "the submodule moved");
        g("config", "submodule.recurse", "true");
        assert.equal(d.sandboxBreaks("git pull", r, session), undefined);
      },
    );
  }
});

test("r4 21: where that git directory lies outside the writable directories the pull would fail halfway: it asks", () =>
  withPointer(
    (r) => `${r}-gitdirs/lib.git`,
    (r, session, g) => {
      d.projectRoots(session);
      for (const command of PULLS) {
        const why = d.sandboxBreaks(command, r, session) ?? "";
        assert.match(why, /outside the project|read-only/, command);
        assert.match(why, OUTSIDE, command);
        assert.equal(d.sandboxBreaks(`${command.replace(/ --recurse-submodules\S*/, "")} --no-recurse-submodules`, r, session), undefined);
      }
      g("config", "submodule.recurse", "true");
      assert.match(d.sandboxBreaks("git pull", r, session) ?? "", OUTSIDE);
      // An allowed path makes it writable, when the caller says so.
      g("config", "--unset", "submodule.recurse");
      assert.equal(d.sandboxBreaks(PULLS[0], r, session, [`${r}-gitdirs`]), undefined);
    },
  ));

test("r4 21: where its config sets core.worktree, git rewrites that key on update (ensure_core_worktree), and the config is read-only: it asks", () =>
  withPointer(
    (r) => path.join(r, "gitdirs", "lib.git"),
    (r, session, g, at) => {
      gitIn(at.lib, "config", "core.worktree", at.lib);
      d.projectRoots(session);
      for (const command of PULLS) {
        const why = d.sandboxBreaks(command, r, session) ?? "";
        assert.match(why, /core\.worktree/, command);
        assert.match(why, OUTSIDE, command);
      }
      // git's own answer: under the wrapper the update stops at the config, and the submodule stays.
      const ran = sandboxed(planFor(r, PULLS[0]), PULLS[0], r, FILE_ENV, Object.keys(FILE_ENV));
      assert.notEqual(ran.status, 0, "the fixture: git rewrites core.worktree, and cannot");
      assert.match(ran.stderr, /core\.worktree/);
      assert.equal(gitIn(at.lib, "rev-parse", "HEAD").trim(), at.one);
      void g;
    },
  ));

// ---- 5. a named directory is known by what it holds ----

test("r4 21: a nested repository a pause named joins the baseline as it was shown: a hook added before the touch names it again", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      execFileSync("git", ["init", "-q", path.join(r, "zze")]);
      const nested = path.join(r, "zze", ".git");
      assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`));
      // Between the prompt and the touch.
      write(path.join(nested, "hooks", "pre-push"), "#!/bin/sh\ntouch /tmp/never\n", 0o755);
      resume.touch();
      const second = d.gitTampered(session, resume.file) ?? "";
      assert.ok(second.includes(`${nested} appeared`), `the hook joined the baseline unseen: ${JSON.stringify(second)}`);
      assert.equal(d.gitTampered(session, resume.file), second, "paused until resumed again");
      // Shown as it is now: the next touch takes it in.
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
      assert.equal(d.gitTampered(session, resume.file), undefined);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: the same for whatever git reads or runs in it: its config, a file under info/, a hook made executable, a file swapped for one of the same size", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      const changes: [string, (nested: string) => void][] = [
        ["config", (nested) => fs.appendFileSync(path.join(nested, "config"), "[core]\n\tfsmonitor = touch /tmp/never\n")],
        ["info/attributes", (nested) => write(path.join(nested, "info", "attributes"), "* filter=evil\n")],
        ["a hook's mode", (nested) => fs.chmodSync(path.join(nested, "hooks", "pre-commit.sample"), 0o700)],
        ["HEAD, same size", (nested) => fs.writeFileSync(path.join(nested, "HEAD"), fs.readFileSync(path.join(nested, "HEAD"), "utf8").replace("main", "evil"))],
        ["a new directory", (nested) => fs.mkdirSync(path.join(nested, "rebase-merge"))],
        ["a ref", (nested) => write(path.join(nested, "refs", "heads", "x"), "0000000000000000000000000000000000000001\n")],
        ["a file removed", (nested) => fs.rmSync(path.join(nested, "description"))],
        ["a link", (nested) => fs.symlinkSync("/tmp", path.join(nested, "lfs"))],
      ];
      for (const [n, [what, change]] of changes.entries()) {
        execFileSync("git", ["init", "-q", "-b", "main", path.join(r, `n${n}`)]);
        const nested = path.join(r, `n${n}`, ".git");
        assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), what);
        change(nested);
        resume.touch();
        assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), `${what} joined the baseline unseen`);
        resume.touch();
        assert.equal(d.gitTampered(session, resume.file), undefined, what);
      }
    } finally {
      resume.remove();
    }
  }));

test("r4 21: an unexpected rebase-merge/ a pause named: a todo list with an exec line added before the touch is named, not taken in", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      const dotGit = path.join(r, ".git");
      // A git-only call that leaves no such state ran, and left the directory.
      const call = d.noteGitCall(session, "git status", [dotGit])!;
      fs.mkdirSync(path.join(dotGit, "rebase-merge"));
      call.done = true;
      assert.match(d.gitStateTampered(session) ?? "", /rebase-merge appeared/);
      // While the session is paused, and with no git call of its own running.
      write(path.join(dotGit, "rebase-merge", "git-rebase-todo"), "exec touch /tmp/never\n");
      resume.touch();
      const second = d.gitTampered(session, resume.file) ?? "";
      assert.match(second, /rebase-merge/, `the todo list joined the baseline unseen: ${JSON.stringify(second)}`);
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: a named directory that is as it was shown resumes with one touch, whatever it holds", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      execFileSync("git", ["init", "-q", "-b", "main", path.join(r, "nested")]);
      commit(path.join(r, "nested"));
      write(path.join(r, "nested", ".git", "hooks", "pre-push"), "#!/bin/sh\nexit 0\n", 0o755);
      assert.match(d.gitTampered(session, resume.file) ?? "", /nested\/\.git appeared/);
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: a directory with more entries than the bound: the prompt says how much of it is compared, a change within that is named, and the session resumes", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const bound = d.fingerprintLimits.entries;
    try {
      commit(r);
      d.projectRoots(session);
      execFileSync("git", ["init", "-q", "-b", "main", path.join(r, "big")]);
      const nested = path.join(r, "big", ".git");
      // Many loose objects: the object store is looked at last.
      for (let n = 0; n < 300; n++) write(path.join(nested, "objects", "aa", `object-${n}`), "x");
      d.fingerprintLimits.entries = 120;
      const first = d.gitTampered(session, resume.file) ?? "";
      assert.ok(first.includes(`${nested} appeared`), first);
      assert.match(first, /more than 120 entries/, "the prompt does not say that the directory is compared in part");
      assert.match(first, /only the first 120/);
      // Within the bound: the hooks, the config and the refs come before the object store.
      write(path.join(nested, "hooks", "pre-push"), "#!/bin/sh\ntouch /tmp/never\n", 0o755);
      resume.touch();
      const second = d.gitTampered(session, resume.file) ?? "";
      assert.ok(second.includes(`${nested} appeared`), `a hook within the bound joined the baseline unseen: ${JSON.stringify(second)}`);
      assert.match(second, /more than 120 entries/);
      // Past the bound nothing is compared, as the prompt said: the session resumes.
      fs.writeFileSync(path.join(nested, "objects", "aa", "object-299"), "y");
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
    } finally {
      d.fingerprintLimits.entries = bound;
      resume.remove();
    }
  }));

// ---- 6. a hooks path the code does not expand ----

test("r4 21: a core.hooksPath git expands in a way that is not followed here is a problem for every call, and for an edit", () =>
  fixture((r, g, session) => {
    commit(r);
    d.projectRoots(session);
    for (const value of [`~${os.userInfo().username}/hooks`, "~root/hooks", "%(prefix)/hooks", "~nobody"]) {
      g("config", "core.hooksPath", value);
      for (const gitWritable of [false, true]) {
        const p = plan({ ...opts(r), gitWritable, gitCwds: [r] });
        assert.match(p.problem ?? "", /core\.hooksPath/, `${value}, gitWritable ${gitWritable}`);
        assert.match(p.problem ?? "", /cannot be followed/, `${value}, gitWritable ${gitWritable}`);
        assert.ok((p.problem ?? "").includes(value), `${value}: ${p.problem}`);
      }
      assert.ok(protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).problems.some((text) => /cannot be followed/.test(text)), value);
    }
    // The values that are followed stay as they were.
    for (const value of ["~/hooks-of-mine", "/usr/share/git-core/templates/hooks", ".husky/_", ""]) {
      g("config", "core.hooksPath", value);
      assert.equal(plan({ ...opts(r), gitWritable: false }).problem, undefined, JSON.stringify(value));
    }
  }));

// ---- 7. a module inside the reopened one, and submodules below a linked worktree's admin directory ----

test("r4 21: a call in a module that also works in a module inside it writes both, on ABI 5 terms too; the hooks and config of each stay read-only", () =>
  withLib(false, (r, _session, g, upstream) => {
    const lib = path.join(r, "lib");
    gitIn(lib, ...FILE, "submodule", "add", "-q", upstream, "inner");
    gitIn(lib, "commit", "-qm", "inner");
    g("commit", "-qam", "lib with inner");
    const dotGit = path.join(r, ".git");
    const module = path.join(dotGit, "modules", "lib");
    const inner = path.join(module, "modules", "inner");
    for (const [n, abi] of ABIS.entries()) {
      write(path.join(lib, "inner", `new-${n}`), "new\n");
      write(path.join(lib, `outer-${n}`), "new\n");
      const command = `git status --short && git -C inner add -A && git -C inner commit -qm inner-${n} && git add -A && git commit -qm outer-${n}`;
      const p = planFor(r, command, lib);
      assert.equal(p.problem, undefined);
      assert.deepEqual([...p.gitDirs].sort(), [module, inner].sort());
      const ran = sandboxed(p, command, lib, abi);
      assert.equal(ran.status, 0, `${JSON.stringify(abi)}: ${ran.stderr}`);
      assert.equal(gitIn(path.join(lib, "inner"), "log", "-1", "--format=%s").trim(), `inner-${n}`);
      assert.equal(gitIn(lib, "log", "-1", "--format=%s").trim(), `outer-${n}`);
      // What stays closed: each module's own hooks and config, and everything around the outer one.
      for (const target of [path.join(inner, "config"), path.join(inner, "hooks", "pre-commit"), path.join(module, "config"), path.join(module, "hooks", "pre-commit"), path.join(dotGit, "shallow"), path.join(dotGit, "HEAD"), path.join(dotGit, "modules", "evil")]) {
        assert.notEqual(sandboxed(p, `echo planted >> ${target}`, lib, abi).status, 0, `${target} (${JSON.stringify(abi)})`);
      }
      assert.equal(fs.existsSync(path.join(inner, "hooks", "pre-commit")), false);
      // The directory between the two modules is the outer module's own, as in a call that has
      // the outer module writable from the start: a module can be made beside the inner one.
      const beside = sandboxed(p, `mkdir ${module}/modules/beside-${n} && rmdir ${module}/modules/beside-${n}`, lib, abi);
      assert.equal(beside.status, 0, `${JSON.stringify(abi)}: ${beside.stderr}`);
    }
  }));

test("r4 21: a call in a linked worktree that also works in its populated submodule writes both; the main checkout's modules and the other worktrees stay closed", () =>
  withLib(false, (r, session, g) => {
    const feature = `${r}-feature`;
    const second = `${r}-second`;
    g("worktree", "add", "-q", "-b", "feature", feature);
    g("worktree", "add", "-q", "-b", "second", second);
    gitIn(feature, ...FILE, "submodule", "update", "-q", "--init");
    const dotGit = path.join(r, ".git");
    const admin = path.join(dotGit, "worktrees", path.basename(feature));
    const module = path.join(admin, "modules", "lib");
    assert.ok(fs.existsSync(path.join(module, "HEAD")), "the fixture: the worktree's submodule is kept under its admin directory");
    const roots = d.projectRoots(session);
    const planIn = (command: string) =>
      plan({ ...opts(r), projectRoots: roots, gitCwds: d.gitDirectories(command, feature), gitWriteCwds: d.gitWriteDirectories(command, feature), gitMaintainCwds: d.gitMaintainDirectories(command, feature), gitPushTo: d.pushDestinations(command, feature) });
    for (const [n, abi] of ABIS.entries()) {
      write(path.join(feature, "lib", `new-${n}`), "new\n");
      write(path.join(feature, `top-${n}`), "new\n");
      const command = `git status --short && git -C lib add -A && git -C lib commit -qm lib-${n} && git add -A && git commit -qm top-${n}`;
      const p = planIn(command);
      assert.equal(p.problem, undefined);
      assert.ok(p.gitDirs.includes(module) && p.gitDirs.includes(admin) && p.gitDirs.includes(dotGit), JSON.stringify(p.gitDirs));
      const ran = sandboxed(p, command, feature, abi);
      assert.equal(ran.status, 0, `${JSON.stringify(abi)}: ${ran.stderr}`);
      assert.equal(gitIn(path.join(feature, "lib"), "log", "-1", "--format=%s").trim(), `lib-${n}`);
      assert.equal(gitIn(feature, "log", "-1", "--format=%s").trim(), `top-${n}`);
      for (const target of [path.join(module, "config"), path.join(module, "hooks", "pre-commit"), path.join(dotGit, "modules", "lib", "HEAD"), path.join(dotGit, "modules", "evil"), path.join(dotGit, "worktrees", path.basename(second), "HEAD"), path.join(dotGit, "worktrees", "evil"), path.join(dotGit, "config")]) {
        assert.notEqual(sandboxed(p, `echo planted >> ${target}`, feature, abi).status, 0, `${target} (${JSON.stringify(abi)})`);
      }
    }
  }));

// ---- 8. git's variables, the other way round ----

test("r4 21: a variable that points the plugin's own git at other configuration than the shell's asks either way round", () => {
  const names = ["GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_NOSYSTEM", "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM", "GIT_NO_REPLACE_OBJECTS"];
  const base = { PATH: "/usr/bin", HOME: "/home/x" };
  for (const name of names) {
    // Set for the plugin, absent from the shell (or there with another value).
    assert.equal(gitElsewhere({ ...base }, { ...base, [name]: "/some/value" }), name, `${name}: the plugin's own`);
    assert.equal(gitElsewhere({ ...base, [name]: undefined }, { ...base, [name]: "1" }), name, `${name}: undefined in the shell`);
    assert.equal(gitElsewhere({ ...base, [name]: "0" }, { ...base, [name]: "1" }), name, `${name}: another value`);
    // Set for the shell and not for the plugin.
    assert.equal(gitElsewhere({ ...base, [name]: "1" }, { ...base }), name, `${name}: the shell's own`);
    // The same on both sides: both gits read the same.
    assert.equal(gitElsewhere({ ...base, [name]: "/some/value" }, { ...base, [name]: "/some/value" }), undefined, name);
  }
  assert.equal(gitElsewhere({ ...base }, { ...base }), undefined);
  // What the plugin's own lookups drop (gitEnv) is the shell's alone, as before.
  assert.equal(gitElsewhere({ ...base }, { ...base, GIT_DIR: "/x/.git" }), undefined);
  assert.equal(gitElsewhere({ ...base, GIT_DIR: "/x/.git" }, { ...base, GIT_DIR: "/x/.git" }), "GIT_DIR");
});

// ---- 9. an approval explains only what its command names ----

test("r4 21: an approved command names no place after a cd that leads where the shell was last: `-` is not a directory's name", () =>
  withSub((r) => {
    for (const text of ["cd sub && cd - && git init", "cd sub && cd - && git init fresh", "cd - && git init fresh", "cd sub; cd -; git clone https://example.invalid/x.git", "cd sub && cd - && cd nowhere && git init", "cd ~nobody && git init fresh", "cd -- - && git init fresh"]) {
      const expected = d.expectedRepos(text, r);
      assert.equal(expected, undefined, `${text}: ${JSON.stringify(expected)}`);
    }
    // What the words do spell is expected as before: a directory the call is to make.
    assert.deepEqual(d.expectedRepos("mkdir x && cd x && git init -q", r), [path.join(r, "x")]);
    assert.deepEqual(d.expectedRepos("cd sub && git init fresh", r), [path.join(r, "sub", "fresh")]);
    // After a place that is not known, a full path is a known place again.
    assert.deepEqual(d.expectedRepos(`cd sub && cd - && mkdir ${r}/y && cd ${r}/y && git init`, r), [path.join(r, "y")]);
    // A directory that is really called `-`, named by git's own `-C`, is a name.
    assert.deepEqual(d.expectedRepos("mkdir ./- && git -C ./- init", r), [path.join(r, "-")]);
  }));

// ---- 10. the aborts under submodule.recurse ----

for (const inTree of [false, true]) {
  const layout = inTree ? "kept in its own work tree" : "kept under .git/modules";
  test(`r4 21: under submodule.recurse the aborts that reset with --merge ask, with a submodule ${layout}; without it each runs in the sandbox`, () =>
    withLib(inTree, (r, session, g) => {
      write(path.join(r, "f"), "a\n");
      g("add", "f");
      g("commit", "-qm", "f a");
      g("branch", "other");
      write(path.join(r, "f"), "c\n");
      g("commit", "-qam", "f c");
      g("switch", "-q", "other");
      write(path.join(r, "f"), "b\n");
      g("commit", "-qam", "f b");
      g("switch", "-q", "main");
      d.projectRoots(session);
      const breaks = (command: string) => d.sandboxBreaks(command, r, session);
      const aborts = ["git merge --abort", "git cherry-pick --abort", "git revert --abort"];
      // Without recursion each is run for real, from the state it aborts.
      const states: Record<string, string[]> = { "git merge --abort": ["merge", "other"], "git cherry-pick --abort": ["cherry-pick", "other"], "git revert --abort": ["revert", "--no-edit", "HEAD~1"], "git rebase --abort": ["rebase", "other"] };
      for (const command of [...aborts, "git rebase --abort"]) {
        assert.equal(breaks(command), undefined, command);
        assert.notEqual(tryGit(r, ...states[command]).status, 0, `the fixture: ${states[command].join(" ")} stops on a conflict`);
        const ran = sandboxed(planFor(r, command), command, r);
        assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
        assert.equal(g("status", "--short", "--untracked-files=no").trim(), "", command);
      }
      g("config", "submodule.recurse", "true");
      for (const command of [...aborts, "git merge --abor", "git cherry-pick --ab", "git merge --abort -q"]) {
        assert.match(breaks(command) ?? "", /submodule/, command);
        assert.match(breaks(command) ?? "", OUTSIDE, command);
      }
      // `git am` asks whatever its words (it is no git-only command).
      assert.ok(breaks("git am --abort"));
      // The ones that do not reset with --merge stay: each run for real under recursion.
      for (const command of ["git rebase --abort", "git merge --quit"]) {
        assert.equal(breaks(command), undefined, command);
        const start = command === "git merge --quit" ? states["git merge --abort"] : states[command];
        assert.notEqual(tryGit(r, "-c", "submodule.recurse=false", ...start).status, 0, `the fixture: ${start.join(" ")} stops on a conflict`);
        const ran = sandboxed(planFor(r, command), command, r);
        assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
        tryGit(r, "-c", "submodule.recurse=false", "reset", "-q", "--hard", "main");
      }
      // A message that spells the word is no abort; neither is the option of another command.
      for (const command of ["git commit -q --allow-empty -m --abort", "git merge -m --abort other", "git rebase --abort"]) assert.equal(breaks(command), undefined, command);
    }));
}

// ---- 11. tests without force ----

test("r4 12: a HEAD that points outside refs/heads/ is on no branch: the remote git picks is origin, whatever a branch of that name is configured with", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "origin", HTTPS);
    g("remote", "add", "other", SSH);
    g("update-ref", "refs/x/topic", "HEAD");
    g("symbolic-ref", "HEAD", "refs/x/topic");
    // Keys a reading that takes the ref for a branch would find.
    for (const name of ["refs/x/topic", "x/topic", "topic"]) {
      g("config", `branch.${name}.remote`, "other");
      g("config", `branch.${name}.pushRemote`, "other");
    }
    assert.equal(execFileSync("git", ["-C", r, "ls-remote", "--get-url"], { encoding: "utf8" }).trim(), HTTPS, "the fixture: git picks origin");
    d.projectRoots(session);
    // origin is https and needs no agent: read as git reads it, nothing asks.
    assert.equal(d.sandboxBreaks("git fetch && git status", r, session), undefined);
    assert.equal(d.sandboxBreaks("git ls-remote && git status", r, session), undefined);
    assert.equal(d.usesSsh("git fetch", r, session), false);
    // On a branch of that name the key counts, and the remote is the ssh one.
    g("symbolic-ref", "HEAD", "refs/heads/topic");
    assert.match(d.sandboxBreaks("git fetch && git status", r, session) ?? "", /would need your ssh agent/);
  }));

test("r4 21: the cd - forms and git -C '' are texts that may ask: none of them throws where the hook does not catch, and none is denied", () =>
  withSub(async (r, session) => {
    for (const text of [...READS_ANYWHERE.map(([t]) => t), ...WRITES_ANYWHERE, "cd repo2; cd -; cd -; git status", "cd sub && git status; cd - ; git status", "cd sub && git status && cd - && git status", "cd sub && cd - >/dev/null && git status", "git -C '' status", "git -C '' -C '' log", "git -C '' commit -m x", "cd '' && git status", "cd - - && git status", "git -C - status", "git -C -- status"]) {
      let decision: d.Decision | undefined;
      await assert.doesNotReject(async () => (decision = await d.decideShell(guard(), session, r, text)), text);
      assert.ok(decision && ["allow", "ask"].includes(decision.effect), `${text}: ${decision?.effect}`);
      const run = decision!.printed ?? text;
      assert.equal(asks(() => d.sandboxBreaks(run, r, session)), undefined, `${text}: sandboxBreaks threw`);
      assert.equal(asks(() => d.expectedRepos(text, r)), undefined, `${text}: expectedRepos threw`);
      assert.equal(asks(() => d.gitOnly(run)), undefined, `${text}: gitOnly threw`);
      assert.equal(asks(() => d.usesSsh(run, r, session)), undefined, `${text}: usesSsh threw`);
      // The plan's inputs may throw (the hook catches that, and the call asks): with a reason.
      for (const read of [d.gitDirectories, d.gitWriteDirectories, d.gitMaintainDirectories, d.pushDestinations]) {
        try {
          read(run, r);
        } catch (e) {
          assert.ok(e instanceof Error && e.message.length > 20, `${text}: ${String(e)}`);
        }
      }
    }
  }));
