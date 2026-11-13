// Round 4, group C, sixth pass: what three reviews of the fourth and fifth passes found. The
// remote git picks when none is named (finding 12), a project whose submodule was removed, the
// grant for a call in a submodule and for a project that is one (finding 21), resets that go into
// submodules, push hooks under a relative core.hooksPath, an accepted `commondir`, a push to a
// repository on this machine (finding 25), what a sandboxed shell inherits (finding 29), layouts
// (findings 21 and 30) and the size of the wrapper's environment. Each test builds a repository
// of its own under the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-sixth.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";
import { dangerousName } from "../guard.ts";
import * as sandbox from "../sandbox.ts";
import { discover, envKept, plan, Scan, walkCount, type Plan } from "../sandbox.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), `c-sixth-${name}-`)));
const gitIn = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const commit = (dir: string, message = "one") => gitIn(dir, "commit", "-q", "--allow-empty", "-m", message);
const write = (file: string, text: string, mode?: number) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  if (mode !== undefined) fs.chmodSync(file, mode);
};

// An empty repository on `main` with a session that has seen nothing yet, removed afterwards;
// `g` runs git in it.
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
// Your own git config (the throwaway home's) with `text` added, for the time of `fn`.
async function withGlobal<T>(text: string, fn: () => T | Promise<T>): Promise<T> {
  const global = process.env.GIT_CONFIG_GLOBAL!;
  const original = fs.readFileSync(global);
  fs.appendFileSync(global, text);
  try {
    return await fn();
  } finally {
    fs.writeFileSync(global, original);
  }
}
// One command under the real wrapper with a plan, as index.ts starts it.
function sandboxed(p: Plan, command: string, cwd: string, extra: Record<string, string> = {}, keepEnv: string[] = []) {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  const env: Record<string, string | undefined> = { ...process.env, ...extra };
  delete env.NODE_TEST_CONTEXT;
  const { keep, dropped } = envKept(env, keepEnv);
  for (const name of dropped) delete env[name];
  Object.assign(env, { AUTOMODE_ENV_KEEP: keep.join("\n"), AUTOMODE_SHELL: "/bin/bash", AUTOMODE_COMMAND: command, AUTOMODE_RW: p.rw.join("\n"), AUTOMODE_RO: p.ro.join("\n"), AUTOMODE_REOPEN: p.reopen.join("\n"), AUTOMODE_HIDE: p.hide.join("\n"), AUTOMODE_PIN: p.pin.join("\n"), AUTOMODE_TMPFS: p.tmpfs.join("\n") });
  return spawnSync(WRAPPER, ["-c", command], { cwd, env, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 120_000 });
}
// The plan index.ts makes for an allowed git-only call.
const planFor = (r: string, command: string, cwd = r, more: Partial<ReturnType<typeof opts>> = {}) => plan({ ...opts(r), ...more, gitCwds: d.gitDirectories(command, cwd), gitPushTo: d.pushDestinations(command, cwd) });
const resumeFile = () => path.join(scratch("resume"), "resume");
const touch = (file: string) => {
  fs.writeFileSync(file, "");
  fs.utimesSync(file, new Date(Date.now() + 5000), new Date(Date.now() + 5000));
};

const AGENT = /would need your ssh agent/;
const HELPER = /credential helper/;
const OUTSIDE = /an approved run happens outside the sandbox/;
const HTTPS = "https://example.invalid/team/x.git";
const SSH = "git@example.invalid:team/x.git";
const FILE = ["-c", "protocol.file.allow=always"];

// ---- 1. the remote git picks when none is named ----

test("r4 12: where the only remote is not called origin, a call that names none is judged by that remote", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "upstream", SSH);
    d.projectRoots(session);
    const several = ["git fetch && git status", "git pull && git status", "git ls-remote | head -3", "git push && git status"];
    for (const command of several) assert.match(d.sandboxBreaks(command, r, session) ?? "", AGENT, command);
    // A single plain one at the top of the project gets the agent, as with a remote called origin.
    for (const command of ["git fetch", "git pull", "git ls-remote", "git push"]) {
      assert.equal(d.usesSsh(command, r, session), true, command);
      assert.equal(d.sandboxBreaks(command, r, session), undefined, command);
    }
    // On no branch at all (a detached HEAD) git still takes the only remote.
    g("checkout", "-q", "--detach");
    for (const command of several) assert.match(d.sandboxBreaks(command, r, session) ?? "", AGENT, `detached: ${command}`);
    assert.equal(d.usesSsh("git fetch", r, session), true);
  }));

test("r4 12: the only remote, https behind a credential helper, asks where no remote is named", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "gh", "https://private.invalid/o/r.git");
    g("config", "credential.https://private.invalid.helper", "store");
    d.projectRoots(session);
    for (const command of ["git fetch && git status", "git pull", "git fetch", "git ls-remote | head -3", "git push"]) assert.match(d.sandboxBreaks(command, r, session) ?? "", HELPER, command);
  }));

test("r4 12: with several remotes and none named, git takes the branch's, then origin; a push its pushRemote and remote.pushDefault first", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "one", HTTPS);
    g("remote", "add", "two", SSH);
    d.projectRoots(session);
    const breaks = (command: string) => d.sandboxBreaks(`${command} && git status`, r, session);
    // Two remotes, neither `origin`, no branch setting: git names `origin` and fails by itself.
    for (const command of ["git fetch", "git pull", "git push"]) assert.equal(breaks(command), undefined, command);
    g("config", "branch.main.remote", "two");
    for (const command of ["git fetch", "git pull", "git push"]) assert.match(breaks(command) ?? "", AGENT, command);
    g("config", "remote.pushDefault", "one");
    assert.equal(breaks("git push"), undefined);
    assert.match(breaks("git fetch") ?? "", AGENT);
    g("config", "branch.main.pushRemote", "two");
    assert.match(breaks("git push") ?? "", AGENT);
  }));

test("r4 21: a push that names no remote goes to the only remote, whatever it is called", () =>
  fixture((r, g) => {
    commit(r);
    const store = path.join(r, "store.git");
    execFileSync("git", ["init", "-q", "--bare", store]);
    g("remote", "add", "store", store);
    assert.deepEqual(d.pushDestinations("git push", r), [store]);
    assert.deepEqual(d.pushDestinations("git push -q", r), [store]);
    // A second remote: git falls back to `origin`, which is the other one here.
    g("remote", "add", "origin", HTTPS);
    assert.deepEqual(d.pushDestinations("git push", r), []);
    g("config", "remote.pushDefault", "store");
    assert.deepEqual(d.pushDestinations("git push", r), [store]);
  }));

test("r4 12: git fetch -m is --multiple: every remote it names is judged", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "origin", HTTPS);
    g("remote", "add", "private", SSH);
    g("remote", "add", "mirror", "https://mirror.invalid/team/x.git");
    d.projectRoots(session);
    const breaks = (command: string) => d.sandboxBreaks(`${command} && git status`, r, session);
    for (const command of ["git fetch -m origin private", "git fetch -qm origin private", "git fetch origin -m private", "git fetch --multiple origin private"]) assert.match(breaks(command) ?? "", AGENT, command);
    for (const command of ["git fetch -m origin mirror", "git fetch origin private"]) assert.equal(breaks(command), undefined, command);
  }));

test("r4 12: a group of remotes is any remotes.<word> key, a dotted word too, and comes before a remote of that name", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "origin", HTTPS);
    g("remote", "add", "up", SSH);
    g("remote", "add", "mirror", "https://mirror.invalid/team/x.git");
    // A remote called `pair`, and a group of the same name that holds the ssh remote.
    g("remote", "add", "pair", "https://pair.invalid/team/x.git");
    g("config", "remotes.team.all", "origin up");
    g("config", "remotes.pair", "origin up");
    g("config", "remotes.plain", "origin mirror");
    d.projectRoots(session);
    const breaks = (command: string) => d.sandboxBreaks(`${command} && git status`, r, session);
    for (const command of ["git fetch team.all", "git remote update team.all", "git fetch --multiple origin team.all", "git fetch pair", "git remote update pair", "git pull team.all"]) {
      assert.match(breaks(command) ?? "", AGENT, command);
    }
    // A group is the remotes it names, and no other.
    for (const command of ["git fetch plain", "git remote update plain", "git fetch mirror"]) assert.equal(breaks(command), undefined, command);
    // A push takes no group: `pair` is the remote there.
    assert.equal(breaks("git push pair main"), undefined);
  }));

test("r4 12: -u is no option of git ls-remote, so which word names the remote cannot be told", () =>
  fixture((r, g, session) => {
    g("remote", "add", "origin", HTTPS);
    d.projectRoots(session);
    for (const command of ["git ls-remote -u x origin", "git ls-remote -ux origin"]) assert.match(d.sandboxBreaks(command, r, session) ?? "", /cannot tell which remote/, command);
    assert.equal(d.sandboxBreaks("git ls-remote --upload-pack=x origin", r, session), undefined);
    assert.equal(d.sandboxBreaks("git ls-remote -o x origin", r, session), undefined);
  }));

// ---- 2. a project whose submodule was removed with `git rm` ----

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

test("r4 21: after git rm of a submodule the leftover module stops no plan, no fetch and no edit", () =>
  withLib(false, async (r, session, g) => {
    g("remote", "add", "origin", HTTPS);
    g("rm", "-q", "lib");
    g("commit", "-qm", "remove the submodule");
    const module = path.join(r, ".git", "modules", "lib");
    assert.ok(fs.existsSync(path.join(module, "HEAD")), "git keeps the module");
    assert.notEqual(spawnSync("git", ["--git-dir", module, "remote"], { encoding: "utf8" }).status, 0, "the fixture: its core.worktree names a directory that is gone");
    d.projectRoots(session);
    assert.equal(plan({ ...opts(r), gitWritable: false }).problem, undefined);
    assert.equal(planFor(r, "git status").problem, undefined);
    for (const command of ["git fetch", "git fetch origin", "git pull", "git fetch origin && git status"]) assert.equal(d.sandboxBreaks(command, r, session), undefined, command);
    write(path.join(r, "src.txt"), "x\n");
    assert.equal(d.decideFile(guard(), session, r, path.join(r, "src.txt")), undefined);
    assert.equal((await d.decideShell(guard(), session, r, "git status")).effect, "allow");
    // The leftover is still a module a fetch may go into: its remote counts.
    gitIn(r, "--git-dir", module, "--work-tree", module, "remote", "set-url", "origin", SSH);
    assert.match(d.sandboxBreaks("git fetch origin && git status", r, session) ?? "", AGENT);
    assert.equal(d.sandboxBreaks("git fetch --no-recurse-submodules origin && git status", r, session), undefined);
  }));

// ---- 3. the grant for a call that works in a submodule kept under .git/modules ----

test("r4 21: a call in a submodule under .git/modules may write its module, and nothing in the git directory around it", () =>
  withLib(false, (r, session, g, upstream) => {
    g(...FILE, "submodule", "add", "-q", upstream, "other");
    g("commit", "-qm", "another submodule");
    g("worktree", "add", "-q", "-b", "feature", `${r}-feature`);
    const lib = path.join(r, "lib");
    const dotGit = path.join(r, ".git");
    const module = path.join(dotGit, "modules", "lib");
    const admin = path.join(dotGit, "worktrees", path.basename(`${r}-feature`));
    write(path.join(lib, "tracked"), "two\n");
    write(path.join(lib, "new"), "new\n");
    d.projectRoots(session);
    for (const [command, cwd] of [["git status", lib], ["git -C lib status", r]]) {
      const p = planFor(r, command, cwd);
      assert.equal(p.problem, undefined, command);
      // The module is held in place and writable, minus its usual read-only list.
      assert.ok(p.pin.includes(module), command);
      for (const name of ["hooks", "config"]) assert.ok(p.ro.includes(path.join(module, name)), `${command}: the module's ${name}`);
      // The git directory around it is not selected: since the seventh pass it is read-only
      // whole, and the module is made writable again inside it (AUTOMODE_REOPEN).
      assert.ok(p.ro.includes(dotGit) && !p.ro.includes(module), `${command}: .git is read-only whole, the module is not`);
      assert.deepEqual(p.reopen, [module], command);
      for (const dir of [dotGit, path.join(dotGit, "modules")]) assert.ok(p.pin.includes(dir), `${command}: ${dir} is pinned`);
      // Nothing can appear around the module, so only the module is in the call's record.
      assert.deepEqual(p.gitDirs, [module], command);
    }
    const p = planFor(r, "git status", lib);
    // Through the real wrapper: nothing that is there in the superproject's git directory can be
    // written, nor in another module or a linked worktree's.
    const kept = [".git/HEAD", ".git/index", ".git/refs/heads/main", ".git/info/exclude", ".git/config", ".git/modules/other/HEAD", ".git/modules/lib/config", path.relative(r, path.join(admin, "HEAD"))];
    for (const target of kept) {
      const file = path.join(r, target);
      const before = fs.readFileSync(file);
      const ran = sandboxed(p, `echo planted >> ${file}`, lib);
      assert.notEqual(ran.status, 0, `${target} was written`);
      assert.deepEqual(fs.readFileSync(file), before, target);
    }
    for (const target of [".git/refs/heads/planted", ".git/objects/info/alternates", ".git/hooks/pre-commit", ".git/modules/other/hooks/pre-commit", ".git/modules/lib/hooks/pre-commit", ".git/worktrees/planted/HEAD"]) {
      const ran = sandboxed(p, `mkdir -p ${path.dirname(path.join(r, target))} && echo planted > ${path.join(r, target)}`, lib);
      assert.notEqual(ran.status, 0, `${target} was made`);
      assert.equal(fs.existsSync(path.join(r, target)), false, target);
    }
    // No new name can be made at its top either (seventh pass): nothing for a check to find.
    const call = d.noteGitCall(session, "git status", p.gitDirs)!;
    assert.notEqual(sandboxed(p, `echo . > ${path.join(dotGit, "commondir")}`, lib).status, 0);
    assert.equal(d.quarantineGitFiles(session, [session], call), undefined);
    assert.equal(fs.existsSync(path.join(dotGit, "commondir")), false);
    // And from inside the submodule the everyday commands work.
    for (const command of ["git add -A", "git stash", "git stash pop", "git commit -qam two", "git gc -q", "git status --short"]) {
      const ran = sandboxed(planFor(r, command, lib), command, lib);
      assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
    }
    assert.equal(gitIn(lib, "log", "-1", "--format=%s").trim(), "two");
  }));

test("r4 21: a module nested in a module: the call gets the inner one, and each git directory around it is read-only", () =>
  withLib(false, (r, _session, g, upstream) => {
    const lib = path.join(r, "lib");
    gitIn(lib, ...FILE, "submodule", "add", "-q", upstream, "inner");
    gitIn(lib, "commit", "-qm", "inner");
    g("commit", "-qam", "lib with inner");
    const dotGit = path.join(r, ".git");
    const module = path.join(dotGit, "modules", "lib");
    const inner = path.join(module, "modules", "inner");
    assert.ok(fs.existsSync(path.join(inner, "HEAD")));
    const p = planFor(r, "git status", path.join(lib, "inner"));
    assert.equal(p.problem, undefined);
    assert.deepEqual(p.gitDirs, [inner]);
    assert.ok(p.pin.includes(inner) && !p.ro.includes(inner) && p.ro.includes(module) && p.ro.includes(dotGit));
    assert.deepEqual(p.reopen, [inner]);
    write(path.join(lib, "inner", "new"), "new\n");
    const ran = sandboxed(p, "git add -A && git commit -qm inner-two", path.join(lib, "inner"));
    assert.equal(ran.status, 0, ran.stderr);
    assert.notEqual(sandboxed(p, `echo planted >> ${path.join(module, "HEAD")}`, lib).status, 0);
    // A call in the outer module still has the inner one, as a call in a superproject has its modules.
    assert.ok(planFor(r, "git status", lib).gitDirs.includes(inner));
  }));

test("r4 21: a directory that merely contains the repository is never granted, whatever names it as a git directory", () =>
  fixture((r) => {
    commit(r);
    execFileSync("git", ["init", "-q", path.join(r, "vendor")]);
    // A pointer file that names the project's own top as its git directory.
    write(path.join(r, "odd", ".git"), "gitdir: ..\n");
    const p = planFor(r, "git status");
    assert.ok(!p.gitDirs.includes(path.join(r, "vendor", ".git")), "a repository that merely lies beside it was granted");
    assert.ok(p.ro.includes(path.join(r, "vendor", ".git")));
    assert.ok(!p.gitDirs.includes(r));
    // It cannot be kept read-only around the repository either: the call asks.
    assert.match(p.problem ?? "", /named as a git directory/);
  }));

// ---- 4. a project that is itself a submodule ----

const OUTSIDE_ROOTS = /lies outside the project.*an approved run happens outside the sandbox/;

test("r4 21: a git command that writes a repository outside the writable roots asks; one that only reads it runs", () =>
  fixture(async (r) => {
    const out = scratch("outside");
    try {
      gitIn(out, "init", "-q", "-b", "main");
      commit(out);
      write(path.join(out, "new"), "new\n");
      // A caller that does not say which of its commands write: each counts as one that does.
      assert.match(plan({ ...opts(r), gitCwds: [out] }).problem ?? "", OUTSIDE_ROOTS);
      const planOf = (command: string) => plan({ ...opts(r), gitCwds: d.gitDirectories(command, r), gitWriteCwds: d.gitWriteDirectories(command, r) });
      for (const command of [`git -C ${out} commit --allow-empty -m x`, `git -C ${out} add -A`, `cd ${out} && git fetch`, `git -C ${out} status && git -C ${out} commit -qm x`, `git -C ${out} stash`, `git -C ${out} switch -c feature`]) {
        assert.match(planOf(command).problem ?? "", OUTSIDE_ROOTS, command);
      }
      for (const command of [`git -C ${out} status`, `git -C ${out} log --oneline | head -3`, `cd ${out} && git diff`, `git -C ${out} show --stat HEAD`, `git -C ${out} branch --show-current`, `git -C ${out} status && git status`]) {
        const p = planOf(command);
        assert.equal(p.problem, undefined, command);
        assert.ok(!p.gitDirs.some((dir) => dir.startsWith(out)), command);
        const ran = sandboxed(p, command, r);
        assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
      }
    } finally {
      fs.rmSync(out, { recursive: true, force: true });
    }
  }));

// git names a submodule's git directory as its main work tree (`git worktree list`), so the
// module is a root of such a project and a commit there works: pinned here, since the sixth
// pass's brief expected it to fail (probe: xcheck/c6/p4-own-submodule.mts).
test("r4 21: a project that is itself a submodule: its commands work, a commit among them", () =>
  withLib(false, (r) => {
    const lib = path.join(r, "lib");
    const own = new d.SessionState(lib);
    try {
      const roots = d.projectRoots(own);
      write(path.join(lib, "new"), "new\n");
      for (const command of ["git status", "git add -A", "git commit -qm two", "git log --oneline | head -3"]) {
        const p = plan({ ...opts(lib), projectRoots: roots, gitCwds: d.gitDirectories(command, lib) });
        assert.equal(p.problem, undefined, command);
        // The superproject's git directory is not among what it may write.
        assert.ok(!p.gitDirs.includes(path.join(r, ".git")), command);
        const ran = sandboxed(p, command, lib);
        assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
      }
      assert.equal(gitIn(lib, "log", "-1", "--format=%s").trim(), "two");
      assert.notEqual(sandboxed(plan({ ...opts(lib), projectRoots: roots, gitCwds: [lib] }), `echo planted >> ${path.join(r, ".git", "HEAD")}`, lib).status, 0);
    } finally {
      d.closeGitSnapshot(own);
    }
  }));

// ---- 5. resets that go into submodules, and a module nested under a submodule ----

// The branch `other` records another commit of `lib`, `same` the one `main` has.
function moveLib(r: string, g: (...args: string[]) => string) {
  g("branch", "same");
  g("switch", "-q", "-c", "other");
  commit(path.join(r, "lib"), "lib two");
  g("commit", "-qam", "move the submodule");
  g("switch", "-q", "main");
  gitIn(path.join(r, "lib"), "checkout", "-q", "HEAD~1");
}

for (const inTree of [false, true]) {
  const layout = inTree ? "a submodule kept in its own work tree" : "a submodule kept under .git/modules";
  test(`r4 21: a reset --keep or --merge that would move ${layout} asks where git goes into submodules; one that moves none does not`, () =>
    withLib(inTree, (r, session, g) => {
      moveLib(r, g);
      d.projectRoots(session);
      const breaks = (command: string) => d.sandboxBreaks(command, r, session);
      // Without recursion git leaves the submodule alone.
      for (const command of ["git reset --keep other", "git reset --merge other", "git reset --keep HEAD~1"]) assert.equal(breaks(command), undefined, command);
      for (const command of ["git reset --keep --recurse-submodules other", "git reset --recurse-submodules --merge other", "git reset --recurse-sub --keep other", "git reset --no-recurse-submodules --recurse-submodules --keep other"]) {
        assert.match(breaks(command) ?? "", /submodule/, command);
        assert.match(breaks(command) ?? "", OUTSIDE, command);
      }
      g("config", "submodule.recurse", "true");
      // `HEAD~1` is the commit before the submodule was added.
      for (const command of ["git reset --keep other", "git reset --merge other", "git reset --keep HEAD~1", "git reset -q --keep other", "git reset --soft --keep other"]) assert.match(breaks(command) ?? "", OUTSIDE, command);
      // Nothing recorded for a submodule differs, or the work tree is left alone.
      for (const command of ["git reset --keep same", "git reset --keep", "git reset --soft other", "git reset other", "git reset --mixed other", "git reset --keep --soft other", "git reset --no-recurse-submodules --keep other", "git reset -q", "git reset -- lib"]) {
        assert.equal(breaks(command), undefined, command);
      }
      // What cannot be shown to move none asks: a commit that cannot be read, an option git does
      // not have, a reset that discards changes.
      // `--merge` goes into the submodules whatever it names (seventh pass: run, it fails).
      for (const command of ["git reset --keep nowhere", "git reset --keep --frobnicate same", "git reset --hard same", "git reset --merge same", "git reset --merge"]) assert.match(breaks(command) ?? "", /submodule/, command);
    }));
}

test("r4 21: a pull that updates submodules asks where a module is nested under a submodule kept in its own work tree", () =>
  withLib(true, (r, session, g, upstream) => {
    const lib = path.join(r, "lib");
    gitIn(lib, ...FILE, "submodule", "add", "-q", upstream, "inner");
    gitIn(lib, "commit", "-qm", "inner");
    g("commit", "-qam", "lib with inner");
    assert.ok(fs.existsSync(path.join(lib, ".git", "modules", "inner", "HEAD")), "the fixture: lib/.git/modules/inner");
    d.projectRoots(session);
    const breaks = (command: string) => d.sandboxBreaks(command, r, session);
    for (const command of ["git pull --recurse-submodules", "git pull --rebase --recurse-submodules=yes"]) {
      assert.match(breaks(command) ?? "", /submodule/, command);
      assert.match(breaks(command) ?? "", OUTSIDE, command);
    }
    assert.equal(breaks("git pull"), undefined);
    g("config", "submodule.recurse", "true");
    assert.match(breaks("git pull") ?? "", OUTSIDE);
    assert.equal(breaks("git pull --no-recurse-submodules"), undefined);
  }));

// ---- 6. push hooks under a relative core.hooksPath ----

const HOOK = "#!/bin/sh\nexit 0\n";
// What husky sets: `core.hooksPath=.husky/_`, with the hooks in the work tree.
function husky(r: string) {
  write(path.join(r, ".husky", "_", "pre-commit"), HOOK, 0o755);
  gitIn(r, "config", "core.hooksPath", ".husky/_");
}
const PUSH_HOOKS = "appeared (a push into the repository would run hooks from it)";

test("r4 21: in a husky project nothing is made in .git, and what a call makes where a push would run hooks from is renamed", () =>
  fixture((r, g, session) => {
    commit(r);
    husky(r);
    d.projectRoots(session);
    const dotGit = path.join(r, ".git");
    const command = "git commit --allow-empty -m x";
    const p = planFor(r, command);
    assert.equal(p.problem, undefined);
    assert.equal(fs.existsSync(path.join(dotGit, ".husky")), false, "the plan made the hook manager's directory inside .git");
    assert.deepEqual(p.gitWatch, [path.join(dotGit, ".husky")]);
    // A call that is not git-only cannot write there at all: nothing to watch.
    assert.deepEqual(plan({ ...opts(r), gitWritable: false }).gitWatch, []);
    const call = d.noteGitCall(session, command, p.gitDirs, p.gitWatch)!;
    // What a hook that runs inside the call can do, through the real wrapper.
    const planted = sandboxed(p, `mkdir -p ${dotGit}/.husky/_ && printf '#!/bin/sh\\ntouch ${r}/ran\\n' > ${dotGit}/.husky/_/pre-receive && chmod +x ${dotGit}/.husky/_/pre-receive`, r);
    assert.equal(planted.status, 0, planted.stderr);
    const found = d.quarantineGitFiles(session, [session], call) ?? "";
    assert.ok(found.includes(`${path.join(dotGit, ".husky")} ${PUSH_HOOKS} and was moved to `), found);
    assert.equal(fs.existsSync(path.join(dotGit, ".husky")), false);
    assert.ok(session.tampered, "the session pauses");
    // git's own answer: a push into the repository now runs nothing.
    g("push", "-q", ".", "HEAD:refs/heads/pushed");
    assert.equal(fs.existsSync(path.join(r, "ran")), false);
  }));

test("r4 21: the layout check names the place a push would run hooks from when it appears: in .git, a module, a worktree's admin directory", () =>
  withLib(false, (r, session, g) => {
    husky(r);
    gitIn(path.join(r, "lib"), "config", "core.hooksPath", ".husky/_");
    g("worktree", "add", "-q", "-b", "feature", `${r}-feature`);
    d.projectRoots(session);
    assert.equal(d.gitTampered(session), undefined);
    for (const place of [path.join(r, ".git"), path.join(r, ".git", "modules", "lib"), path.join(r, ".git", "worktrees", path.basename(`${r}-feature`))]) {
      fs.mkdirSync(path.join(place, ".husky", "_"), { recursive: true });
      const found = d.gitTampered(session) ?? "";
      assert.ok(found.includes(`${path.join(place, ".husky")} ${PUSH_HOOKS}`), `${place}: ${found}`);
      fs.rmSync(path.join(place, ".husky"), { recursive: true });
      session.tampered = undefined;
    }
    assert.equal(d.gitTampered(session), undefined);
  }));

test("r4 21: where the place a push would run hooks from is there, it is read-only like any hooks directory", () =>
  fixture((r, _g, session) => {
    commit(r);
    husky(r);
    const inGit = path.join(r, ".git", ".husky", "_");
    write(path.join(inGit, "pre-receive"), HOOK, 0o755);
    d.projectRoots(session);
    for (const command of ["git commit --allow-empty -m x", "git status"]) {
      const p = planFor(r, command);
      assert.equal(p.problem, undefined, command);
      assert.ok(p.ro.includes(inGit), command);
      assert.deepEqual(p.gitWatch, [], command);
      const ran = sandboxed(p, `echo planted >> ${inGit}/pre-receive; echo planted > ${inGit}/update`, r);
      assert.notEqual(ran.status, 0, command);
      assert.equal(fs.readFileSync(path.join(inGit, "pre-receive"), "utf8"), HOOK, command);
      assert.equal(fs.existsSync(path.join(inGit, "update")), false, command);
    }
    // The husky fix of the fourth pass stands: the layout check has nothing to say.
    assert.equal(d.gitTampered(session), undefined);
  }));

// ---- 7. what a resume takes in, and an accepted commondir ----

// The resume file, touched so that it is newer than everything so far.
function resuming() {
  const file = resumeFile();
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

test("r4 21: a resume takes in what the pause named; what else changed meanwhile is named before it is taken in", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      d.projectRoots(session);
      execFileSync("git", ["init", "-q", path.join(r, "planted")]);
      assert.match(d.gitTampered(session, resume.file) ?? "", /planted\/\.git appeared/);
      // While the session is paused: something the pause does not name.
      fs.writeFileSync(path.join(r, ".git", "commondir"), ".\n");
      resume.touch();
      const second = d.gitTampered(session, resume.file) ?? "";
      assert.match(second, /\.git\/commondir appeared/, "the resume took in a commondir nobody was shown");
      assert.doesNotMatch(second, /planted/, "what the first pause named is taken in");
      assert.equal(d.gitTampered(session, resume.file), second, "paused until resumed again");
      resume.touch();
      for (const check of ["first", "second"]) assert.equal(d.gitTampered(session, resume.file), undefined, `the ${check} check after the second resume`);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: a pause shows five things; a resume names the rest before it takes them in", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      d.projectRoots(session);
      for (let i = 0; i < 7; i++) execFileSync("git", ["init", "-q", path.join(r, `planted-${i}`)]);
      assert.match(d.gitTampered(session, resume.file) ?? "", /and 2 more$/);
      resume.touch();
      const rest = d.gitTampered(session, resume.file) ?? "";
      assert.equal(rest.split("; ").length, 2, rest);
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: an accepted commondir is known by what it holds: rewritten it is named, and taken away it is new when it comes back", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const file = path.join(r, ".git", "commondir");
    try {
      d.projectRoots(session);
      fs.writeFileSync(file, ".\n");
      assert.match(d.gitTampered(session, resume.file) ?? "", /\.git\/commondir appeared/);
      resume.touch();
      for (const check of ["first", "second"]) assert.equal(d.gitTampered(session, resume.file), undefined, `the ${check} check after the resume`);
      // Pointed elsewhere.
      fs.writeFileSync(file, "/somewhere/else\n");
      assert.match(d.gitTampered(session, resume.file) ?? "", /\.git\/commondir was rewritten/);
      resume.touch();
      for (const check of ["first", "second"]) assert.equal(d.gitTampered(session, resume.file), undefined, `the ${check} check after the second resume`);
      // Taken away: nothing to say. Put back, as it was: new again.
      fs.rmSync(file);
      assert.equal(d.gitTampered(session, resume.file), undefined);
      fs.writeFileSync(file, "/somewhere/else\n");
      assert.match(d.gitTampered(session, resume.file) ?? "", /\.git\/commondir appeared/);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: a snapshot taken again keeps an accepted commondir accepted", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      d.projectRoots(session);
      fs.writeFileSync(path.join(r, ".git", "commondir"), ".\n");
      assert.match(d.gitTampered(session, resume.file) ?? "", /\.git\/commondir appeared/);
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
      // An approved command's repository appears: the snapshot is taken again.
      const before = session.snapshot;
      session.expecting.push({ dirs: [path.join(r, "new")], at: Date.now() });
      execFileSync("git", ["init", "-q", path.join(r, "new")]);
      assert.equal(d.gitTampered(session, resume.file), undefined);
      assert.notEqual(session.snapshot, before, "the test needs the snapshot to be taken again");
      for (const check of ["first", "second"]) assert.equal(d.gitTampered(session, resume.file), undefined, `the ${check} check after the retake`);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: a known git directory that cannot be looked into while the snapshot is taken again keeps its baseline", () =>
  fixture((r, _g, session) => {
    const nested = path.join(r, "nested", ".git");
    execFileSync("git", ["init", "-q", path.join(r, "nested")]);
    d.projectRoots(session);
    assert.equal(d.gitTampered(session), undefined);
    fs.chmodSync(nested, 0o000);
    try {
      assert.throws(() => fs.readdirSync(nested), /EACCES/, "the test needs a user that mode 000 keeps out");
      const before = session.snapshot;
      session.expecting.push({ dirs: [path.join(r, "new")], at: Date.now() });
      execFileSync("git", ["init", "-q", path.join(r, "new")]);
      assert.equal(d.gitTampered(session), undefined);
      assert.notEqual(session.snapshot, before, "the test needs the snapshot to be taken again");
    } finally {
      fs.chmodSync(nested, 0o755);
    }
    // What is put there before it can be seen into again is no baseline.
    fs.writeFileSync(path.join(nested, "commondir"), "/somewhere/else\n");
    assert.match(d.gitTampered(session) ?? "", /nested\/\.git\/commondir appeared/);
  }));

test("r4 21: a main checkout's git directory that could not be looked into at the start has no commondir for a baseline", () =>
  fixture((r, _g, session) => {
    const dotGit = path.join(r, ".git");
    fs.chmodSync(dotGit, 0o000);
    try {
      assert.throws(() => fs.readdirSync(dotGit), /EACCES/, "the test needs a user that mode 000 keeps out");
      d.projectRoots(session);
      assert.equal(d.gitTampered(session), undefined);
    } finally {
      fs.chmodSync(dotGit, 0o755);
    }
    fs.writeFileSync(path.join(dotGit, "commondir"), ".\n");
    assert.match(d.gitTampered(session) ?? "", /\.git\/commondir appeared/);
  }));

// ---- 8. a push to a repository on this machine ----

test("r4 25: only a call every URL of which is a network URL gets the ssh agent", () =>
  fixture((r, g, session) => {
    commit(r);
    const store = path.join(r, "store.git");
    execFileSync("git", ["init", "-q", "--bare", store]);
    g("remote", "add", "origin", SSH);
    g("remote", "add", "store", store);
    g("remote", "add", "helper", "ext::sh -c true");
    d.projectRoots(session);
    for (const command of ["git push origin main", "git fetch origin", "git ls-remote origin", "git pull origin main", "git push", "git fetch"]) assert.equal(d.usesSsh(command, r, session), true, command);
    for (const command of ["git push store main", "git fetch store", "git ls-remote store", "git pull store main", "git fetch helper", "git ls-remote helper", "git fetch --all"]) {
      assert.equal(d.usesSsh(command, r, session), false, command);
    }
  }));

test("r4 25: a push to a repository on this machine that has a receive-side hook asks; one that has none runs", () =>
  fixture(async (r, g, session) => {
    commit(r);
    const store = path.join(r, "store.git");
    execFileSync("git", ["init", "-q", "--bare", store]);
    g("remote", "add", "store", store);
    d.projectRoots(session);
    const command = "git push store HEAD:refs/heads/pushed";
    const problem = () => planFor(r, command).problem;
    // The samples `git init` leaves are no hooks.
    assert.equal(problem(), undefined);
    for (const name of ["pre-receive", "update", "post-receive", "post-update", "reference-transaction", "push-to-checkout", "proc-receive"]) {
      const file = path.join(store, "hooks", name);
      write(file, HOOK, 0o755);
      const found = problem() ?? "";
      assert.ok(found.includes(`has a ${name} hook (${file})`), `${name}: ${found}`);
      assert.match(found, OUTSIDE, name);
      fs.chmodSync(file, 0o644);
      assert.equal(problem(), undefined, `${name} that is not executable`);
      fs.rmSync(file);
    }
    // A hook git runs on the other side of a push is none of these.
    write(path.join(store, "hooks", "pre-push"), HOOK, 0o755);
    assert.equal(problem(), undefined);
    // Under its hooks path: its own, from its git directory; and yours.
    write(path.join(store, "custom", "update"), HOOK, 0o755);
    assert.equal(problem(), undefined);
    gitIn(store, "config", "core.hooksPath", "custom");
    assert.ok((problem() ?? "").includes(`has a update hook (${path.join(store, "custom", "update")})`));
    gitIn(store, "config", "--unset", "core.hooksPath");
    write(path.join(r, "mine", "post-receive"), HOOK, 0o755);
    await withGlobal(`[core]\n\thooksPath = ${path.join(r, "mine")}\n`, () => {
      assert.ok((problem() ?? "").includes(`has a post-receive hook (${path.join(r, "mine", "post-receive")})`));
    });
    // With none of them the push runs, through the real wrapper.
    const p = planFor(r, command);
    assert.equal(p.problem, undefined);
    const ran = sandboxed(p, command, r);
    assert.equal(ran.status, 0, ran.stderr);
    assert.equal(gitIn(store, "rev-parse", "refs/heads/pushed"), g("rev-parse", "HEAD"));
  }));

// ---- 9. what a sandboxed shell inherits ----

// bash's own variables that change how a command is read or what a word of it runs.
const SHELL_OWN = ["BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "POSIXLY_CORRECT", "BASH_COMPAT", "GLOBIGNORE", "GLOBSORT", "CDPATH", "EXECIGNORE", "BASH_LOADABLES_PATH", "IFS", "PROMPT_COMMAND", "histchars"];

test("r4 29: bash's own variables that change how it reads a command are not handed to a sandboxed shell, however plain their value", () => {
  // Short values, a number and a path: each passed for "plainly not a secret".
  const env = Object.fromEntries(SHELL_OWN.map((name, i) => [name, ["x", "1", "/home/u/.bash_env"][i % 3]]));
  const { keep, dropped } = envKept({ ...env, BASH_XTRACEFD: "7", EDITOR: "vi", PATH: "/usr/bin", HOME: "/home/u", CDPATHS: "x", MY_ENV: "x" }, []);
  for (const name of [...SHELL_OWN, "BASH_XTRACEFD"]) {
    assert.ok(dropped.includes(name), `${name} is dropped`);
    assert.ok(!keep.includes(name), `${name} is not kept`);
  }
  // The guard asks about a command that sets one of these: the two lists hold together.
  for (const name of [...SHELL_OWN, "PS4", "BASH_FUNC_git%%"]) assert.ok(dangerousName(name), `${name} is one the guard asks about`);
  for (const name of ["EDITOR", "PATH", "HOME", "CDPATHS", "MY_ENV"]) assert.ok(keep.includes(name), name);
  // Yours to keep, by name.
  for (const name of SHELL_OWN) assert.ok(envKept(env, [name]).keep.includes(name), `${name} named in sandboxKeepEnv`);
});

test("r4 29: a file BASH_ENV names is not sourced by the shell the wrapper starts, so git is git", () =>
  fixture((r) => {
    const startup = path.join(r, "startup.sh");
    write(startup, `git() { touch ${r}/hijacked; }\ntouch ${r}/sourced\n`);
    const p = plan({ ...opts(r), gitWritable: false });
    assert.equal(p.problem, undefined);
    const ran = sandboxed(p, "git --version", r, { BASH_ENV: startup });
    assert.equal(ran.status, 0, ran.stderr);
    assert.match(ran.stdout, /^git version /);
    for (const name of ["sourced", "hijacked"]) assert.equal(fs.existsSync(path.join(r, name)), false, `the startup file was ${name}`);
    // Named in sandboxKeepEnv it is yours to keep, and bash sources it.
    assert.equal(sandboxed(p, "git --version", r, { BASH_ENV: startup }, ["BASH_ENV"]).status, 0);
    assert.ok(fs.existsSync(path.join(r, "hijacked")));
  }));

test("r4 29: an inherited CDPATH, BASHOPTS, SHELLOPTS or GLOBIGNORE changes neither where cd goes nor what a glob matches", () =>
  fixture((r) => {
    fs.mkdirSync(path.join(r, "elsewhere", "src"), { recursive: true });
    fs.mkdirSync(path.join(r, "src"));
    for (const name of ["plain", ".dot"]) write(path.join(r, "src", name), "");
    const p = plan({ ...opts(r), gitWritable: false });
    const cd = sandboxed(p, "cd src && pwd", r, { CDPATH: path.join(r, "elsewhere") });
    assert.equal(cd.stdout, `${path.join(r, "src")}\n`, cd.stderr);
    for (const extra of [{ BASHOPTS: "dotglob" }, { SHELLOPTS: "noglob" }, { GLOBIGNORE: "x" }]) {
      const glob = sandboxed(p, "cd src && echo *", r, extra);
      assert.equal(glob.stdout, "plain\n", JSON.stringify(extra));
    }
  }));

// ---- 10. layouts ----

test("r4 21: a git directory kept apart from its work tree is no top of its own; a bare repository is", () =>
  fixture((r, _g, session) => {
    const sep = path.join(r, "store", "sep.git");
    const wt = path.join(r, "wt");
    const bare = path.join(r, "bare.git");
    fs.mkdirSync(path.join(r, "store"));
    execFileSync("git", ["init", "-q", "--separate-git-dir", sep, wt]);
    assert.ok(fs.lstatSync(path.join(wt, ".git")).isFile());
    husky(wt);
    execFileSync("git", ["init", "-q", "--bare", bare]);
    gitIn(bare, "config", "core.hooksPath", "myhooks");
    const found = discover([r]);
    assert.deepEqual([...found.tops.get(sep)!], [wt]);
    assert.deepEqual([...found.tops.get(bare)!], [bare]);
    d.projectRoots(session);
    const p = plan({ ...opts(r), gitWritable: false });
    assert.equal(p.problem, undefined);
    assert.equal(fs.existsSync(path.join(sep, ".husky")), false, "the plan made the hook manager's directory inside the git directory");
    assert.ok(p.ro.includes(path.join(wt, ".husky", "_")));
    assert.ok(p.ro.includes(path.join(bare, "myhooks")), "a bare repository runs its hooks from itself");
    assert.equal(d.gitTampered(session), undefined, "the plan made something the layout check takes for a plant");
  }));

test("r4 30: an allowed path that is the project's .git, or lies inside it, is walked once and keeps its git context", () =>
  fixture(async (r) => {
    commit(r);
    husky(r);
    gitIn(r, "branch", "id_rsa");
    const dotGit = path.join(r, ".git");
    const closed = path.join(dotGit, "closed");
    fs.mkdirSync(closed, { mode: 0o311 });
    try {
      assert.throws(() => fs.readdirSync(closed), /EACCES/, "the test needs a user that mode 0311 keeps from listing");
      for (const allowed of [dotGit, path.join(dotGit, "refs")]) {
        const found = discover([r], { scan: new Scan([allowed]), secretsIn: [r] });
        assert.deepEqual([...found.gitDirs], [dotGit], allowed);
        // A branch is no credential file, whatever it is called: below `refs` nothing is looked for.
        assert.deepEqual([...found.secrets], [], allowed);
        assert.deepEqual([...found.tops.get(dotGit)!], [r], `${allowed}: .git is no top of its own`);
        // What lies in `.git` is looked at by one walk, not by the project's and its own.
        assert.equal(found.problems.filter((text) => text.includes(closed)).length, 1, `${allowed}: ${JSON.stringify(found.problems)}`);
      }
    } finally {
      fs.chmodSync(closed, 0o755);
      fs.rmSync(closed, { recursive: true, force: true });
    }
    for (const allowed of [dotGit, path.join(dotGit, "refs")]) {
      const own = new d.SessionState(r);
      try {
        assert.equal((await d.decideShell(guard([allowed]), own, r, "ls")).effect, "allow");
        walkCount.clear();
        const scan = new Scan([allowed]);
        assert.equal((await d.decideShell(guard([allowed]), own, r, "ls", undefined, scan)).effect, "allow");
        const p = plan({ ...opts(r), allowedPaths: [allowed], gitWritable: false }, scan);
        assert.equal(p.problem, undefined, allowed);
        for (const [root, n] of walkCount) assert.equal(n, 1, `${allowed}: ${root} walked ${n} times`);
        assert.equal(fs.existsSync(path.join(dotGit, ".husky")), false, `${allowed}: the plan made the hook manager's directory inside .git`);
        const next = await d.decideShell(guard([allowed]), own, r, "ls");
        assert.equal(next.effect, "allow", `${allowed}: ${next.reason}`);
      } finally {
        d.closeGitSnapshot(own);
      }
    }
  }));

test("r4 25: a submodule whose .git file points outside modules/ is a cloned submodule: no agent for a fetch that may go into it, and it is granted with its superproject", () =>
  fixture((r, g, session) => {
    const upstream = `${r}-lib-upstream`;
    const kept = path.join(r, "store", "lib.git");
    execFileSync("git", ["init", "-q", "-b", "main", upstream]);
    commit(upstream, "lib one");
    commit(r);
    fs.mkdirSync(path.join(r, "store"));
    execFileSync("git", ["clone", "-q", "--separate-git-dir", kept, upstream, path.join(r, "lib")]);
    g(...FILE, "submodule", "add", "-q", upstream, "lib");
    g("commit", "-qm", "a submodule");
    assert.ok(fs.lstatSync(path.join(r, "lib", ".git")).isFile() && !fs.existsSync(path.join(r, ".git", "modules", "lib")), "the fixture: a pointer to a git directory outside modules/");
    g("remote", "add", "origin", SSH);
    d.projectRoots(session);
    assert.equal(d.usesSsh("git fetch", r, session), false);
    assert.equal(d.usesSsh("git fetch --no-recurse-submodules", r, session), true);
    assert.match(d.sandboxBreaks("git fetch", r, session) ?? "", /cloned submodules whose config and hooks are not checked/);
    const p = planFor(r, "git status");
    assert.equal(p.problem, undefined);
    assert.deepEqual([...p.gitDirs].sort(), [path.join(r, ".git"), kept].sort());
    // A pull that updates it works in the sandbox (seventh pass: run under the wrapper,
    // test/c-seventh.test.mts): what is left to ask about is the agent its ssh remote needs.
    assert.match(d.sandboxBreaks("git pull --recurse-submodules --no-rebase", r, session) ?? "", AGENT);
    g("remote", "set-url", "origin", HTTPS);
    assert.equal(d.sandboxBreaks("git pull --recurse-submodules --no-rebase", r, session), undefined);
  }));

// ---- 11. the size of what the wrapper is handed ----

test("r4 24: the command and the names of the kept variables are held to the kernel's limit for one environment string", () => {
  const { envStringProblem } = sandbox;
  assert.equal(envStringProblem("AUTOMODE_COMMAND", "ls"), undefined);
  // A string of exactly the limit, its NUL included, is one the kernel takes (seventh pass).
  assert.equal(envStringProblem("AUTOMODE_COMMAND", "x".repeat(128 * 1024 - "AUTOMODE_COMMAND=".length - 1)), undefined);
  assert.match(envStringProblem("AUTOMODE_COMMAND", "x".repeat(128 * 1024 - "AUTOMODE_COMMAND=".length)) ?? "", /AUTOMODE_COMMAND exceeds the kernel environment string limit/);
  // Bytes, not characters.
  assert.match(envStringProblem("AUTOMODE_ENV_KEEP", "é".repeat(70_000)) ?? "", /AUTOMODE_ENV_KEEP exceeds/);
});

// ---- 12. tests that had no force ----

test("r4 12: of several pushInsteadOf rules that match, the longest prefix says where a push goes", () =>
  fixture((r, g, session) =>
    withGlobal('[url "https://short.invalid/"]\n\tpushInsteadOf = https://host.invalid/\n[url "git@long.invalid:"]\n\tpushInsteadOf = https://host.invalid/team/\n[url "https://shorter.invalid/"]\n\tpushInsteadOf = https://host\n', () => {
      g("remote", "add", "origin", HTTPS);
      d.projectRoots(session);
      // git's own answer first (remote.c, the longest match), then the plugin's reading of it.
      g("remote", "add", "probe", "https://host.invalid/team/x.git");
      assert.equal(g("remote", "get-url", "--push", "probe").trim(), "git@long.invalid:x.git");
      assert.match(d.sandboxBreaks("git push https://host.invalid/team/x.git main && git status", r, session) ?? "", AGENT);
      assert.equal(d.sandboxBreaks("git push https://host.invalid/other/x.git main && git status", r, session), undefined);
    }),
  ));

test("r4 25: a credential helper in a cloned submodule's own config asks about a fetch that may go into it", () =>
  withLib(false, (r, session, g) => {
    const module = path.join(r, ".git", "modules", "lib");
    gitIn(r, "--git-dir", module, "remote", "set-url", "origin", "https://sub.invalid/o/lib.git");
    gitIn(r, "--git-dir", module, "config", "credential.https://sub.invalid.helper", "store");
    g("remote", "add", "origin", HTTPS);
    d.projectRoots(session);
    assert.match(d.sandboxBreaks("git fetch", r, session) ?? "", HELPER);
    assert.match(d.sandboxBreaks("git pull", r, session) ?? "", HELPER);
    assert.equal(d.sandboxBreaks("git fetch --no-recurse-submodules", r, session), undefined);
  }));

test("r4 30: an allowed path inside the project is the project's own: credentials are looked for in it, and a directory in it that cannot be listed is a problem", () =>
  fixture((r) => {
    const nested = path.join(r, "vendor", "allowed");
    const closed = path.join(nested, "closed");
    write(path.join(nested, "deep", ".env"), "TOKEN=x\n");
    fs.mkdirSync(closed, { mode: 0o311 });
    try {
      assert.throws(() => fs.readdirSync(closed), /EACCES/, "the test needs a user that mode 0311 keeps from listing");
      // Asked about the project alone, as the layout check asks: the nested root is walked as
      // itself, and takes "own" and "look for credentials" from the project around it.
      const found = discover([r], { scan: new Scan([nested]), secretsIn: [r] });
      assert.ok(found.secrets.has(path.join(nested, "deep", ".env")), "no credential was looked for in the nested root");
      assert.ok(found.problems.some((text) => text.includes(closed)), JSON.stringify(found.problems));
      assert.ok(!found.unlistable.has(closed));
      // In a root that is not the caller's own, the same directory is listed for the plan to cover.
      const other = discover([r], { scan: new Scan([nested]), own: [] });
      assert.ok(other.unlistable.has(closed) && !other.problems.some((text) => text.includes(closed)));
      assert.equal(other.secrets.size, 0, "credentials were looked for where nobody asked");
    } finally {
      fs.chmodSync(closed, 0o755);
    }
  }));
