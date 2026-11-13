// Round 4, group C, seventh pass: what the checks of the sixth pass found, and the older findings
// that waited for guard.ts's reading of where a command runs. A network URL as git reads one,
// where a git command ends as bash goes there, a repository's harmless settings, a relative
// hooks path with a bare repository, the remote git picks, `reset --merge`, the hooks path as
// git reads it, what joins a baseline, the git directory around a module, a call in a linked
// worktree, what a push to a repository on this machine runs. Each test builds a repository of
// its own under the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-seventh.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";
import { discover, envKept, envStringProblem, plan, type Plan } from "../sandbox.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), `c-seventh-${name}-`)));
const gitIn = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
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
  plan({ ...opts(r), ...more, gitCwds: d.gitDirectories(command, cwd), gitWriteCwds: d.gitWriteDirectories(command, cwd), gitPushTo: d.pushDestinations(command, cwd) });
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

const AGENT = /would need your ssh agent/;
const OUTSIDE = /an approved run happens outside the sandbox/;
const HTTPS = "https://example.invalid/team/x.git";
const SSH = "git@example.invalid:team/x.git";
const FILE = ["-c", "protocol.file.allow=always"];
const HOOK = "#!/bin/sh\nexit 0\n";

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

// ---- 1. a network URL as git reads one ----

test("r4 25: an scp-like URL with an absolute path, and a host alias with an underscore, are ssh to git and get the agent", () => {
  // connect.c, url_is_local_not_ssh: a colon before any slash is a host.
  const ssh = ["git@example.invalid:/srv/git/x.git", "example.invalid:/srv/git/x.git", "git@github_work:team/x.git", "github_work:team/x.git", SSH, "ssh://git@example.invalid/srv/git/x.git", "ssh://git@example.invalid:2222/srv/git/x.git"];
  return fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "origin", SSH);
    d.projectRoots(session);
    for (const url of ssh) {
      g("remote", "set-url", "origin", url);
      // The session knows the remote by the URL it had at the start.
      const fresh = new d.SessionState(r);
      try {
        d.projectRoots(fresh);
        for (const command of ["git fetch", "git pull", "git push", "git ls-remote origin"]) {
          assert.equal(d.usesSsh(command, r, fresh), true, `${url}: ${command}`);
          assert.equal(d.sandboxBreaks(command, r, fresh), undefined, `${url}: ${command}`);
        }
      } finally {
        d.closeGitSnapshot(fresh);
      }
    }
  });
});

test("r4 25: a transport helper, a path on this machine and a scheme git has a helper for get no agent, however they are spelled", () =>
  fixture((r, g) => {
    commit(r);
    fs.mkdirSync(path.join(r, "dir:with"), { recursive: true });
    const not = ["ext::sh -c true", "x::host:/path", "host::/path", "./host:/srv/x.git", "/srv/git/x.git", "../x.git", "file:///srv/x.git", "foo://example.invalid/x.git", "host://x", "-oProxyCommand=x@host:/x", "-host:/x", "git@-host:/x", "host:/a b"];
    g("remote", "add", "origin", SSH);
    for (const url of not) {
      g("config", "remote.origin.url", url);
      const fresh = new d.SessionState(r);
      try {
        d.projectRoots(fresh);
        for (const command of ["git fetch", "git push", "git ls-remote origin"]) assert.equal(d.usesSsh(command, r, fresh), false, `${url}: ${command}`);
      } finally {
        d.closeGitSnapshot(fresh);
      }
    }
  }));

// ---- 2. where a git command of the call ends, as bash goes there ----

// A project with: `a/b`; a nested repository `sub` with `sub/link` -> `a` (a directory of the
// project); a nested repository `vendor` with `vendor/inner`, and `link` -> `vendor/inner`.
async function withLinks(fn: (r: string, session: d.SessionState, g: (...args: string[]) => string) => void | Promise<void>) {
  await fixture(async (r, g, session) => {
    commit(r);
    fs.mkdirSync(path.join(r, "a", "b"), { recursive: true });
    for (const nested of ["sub", "vendor"]) {
      execFileSync("git", ["init", "-q", "-b", "main", path.join(r, nested)]);
      commit(path.join(r, nested));
    }
    fs.mkdirSync(path.join(r, "vendor", "inner"));
    fs.symlinkSync(path.join(r, "a"), path.join(r, "sub", "link"));
    fs.symlinkSync(path.join(r, "vendor", "inner"), path.join(r, "link"));
    await fn(r, session, g);
  });
}
// Where real bash runs each git command of `text`: a `git` that changes into its `-C` words as
// git does (chdir(2), the kernel's walk: `cd -P`) and prints the directory it is in.
function bashEnds(text: string, r: string): string[] {
  const bin = path.join(r, ".shim");
  const log = path.join(r, ".shim.log");
  write(path.join(bin, "git"), '#!/bin/bash\nwhile [ "$1" = "-C" ]; do cd -P "$2" || exit 1; shift 2; done\npwd -P >> "$SHIM_LOG"\n', 0o755);
  write(path.join(bin, "timeout"), '#!/bin/bash\nshift\nexec "$@"\n', 0o755);
  fs.rmSync(log, { force: true });
  const env: Record<string, string | undefined> = { ...process.env, PATH: `${bin}:${process.env.PATH}`, SHIM_LOG: log, PWD: r };
  for (const name of ["OLDPWD", "CDPATH", "NODE_TEST_CONTEXT"]) delete env[name];
  spawnSync("/bin/bash", ["-c", text], { cwd: r, env, stdio: "ignore" });
  const out = fs.existsSync(log) ? fs.readFileSync(log, "utf8").split("\n").filter(Boolean) : [];
  fs.rmSync(bin, { recursive: true, force: true });
  fs.rmSync(log, { force: true });
  return [...new Set(out)].sort();
}
// Texts whose directory can be told: each must be read, and read as bash goes.
const PLACED = (r: string) => [
  "git status",
  "cd a && git status",
  "cd a && cd b && git status",
  "cd a/b && cd .. && git status",
  "cd a/b && cd ../.. && git status",
  "cd sub/link && cd .. && git status",
  "cd link && cd .. && git add -A",
  "cd link && git status",
  "cd sub/link && git status",
  "cd a; git status",
  "cd a\ngit status",
  "cd a && git -C b status",
  "cd a && git -C .. status",
  "git -C a/b status",
  "git -C a -C b status",
  "git -C sub/link/.. status",
  "cd sub && git -C link/.. status",
  "cd link && git -C .. status",
  "cd sub/link && cd ../.. && git status",
  "cd ./a/./b && git status",
  "cd a//b && git status",
  "cd a/ && git status",
  `cd ${r}/a && git status`,
  `cd ${r}/sub/link && cd .. && git status`,
  "cd a && git status && cd b && git log",
  "cd a && git status; cd .. && git log",
  "timeout 5 git status",
  "cd a && timeout 5 git -C b status",
  "git status | head -3",
  "cd a && git log --oneline | head -3",
  "cd ~ && git status",
  `cd ~/${path.basename(r)}/a && git status`,
  "cd link/.. && git status",
  "cd sub/link/../.. && git status",
  "cd a/../sub && git status",
  "cd link && cd ../a && git status",
  "cd link && cd . && git status",
  "cd sub && cd link && cd .. && cd .. && git status",
  "cd a && cd ../link && cd .. && git status",
  "git -C link status",
  "git -C link/.. status",
  "git -C sub -C link -C .. status",
  "cd sub/link && git -C .. status",
];
// Texts that may ask (the directory cannot be told from here); where they are read, as bash goes.
// (A bare `cd` is not of the shape whose places count as known (guard.ts, knownShape; the
// maintainer's decision on where a command runs): its call asks here.)
const MAY_ASK = ["cd && git status", "cd nowhere && git status", "cd nowhere; git status", "cd - && git status", 'cd "~" && git status', "cd ~root && git status", "cd a && cd - && git status", "cd -P link && cd .. && git status", "(cd a && git status)", "(cd sub/link && cd ..; git status)", "cd a && (cd b && git status) && git log"];

test("r4 21: the directory each git command of a call ends in is the one bash and git go to, text by text against real bash", () =>
  withLinks((r) => {
    for (const text of PLACED(r)) {
      const real = bashEnds(text, r);
      assert.ok(real.length > 0, `the fixture: bash ran no git for ${JSON.stringify(text)}`);
      assert.ok(d.gitOnly(text), `${JSON.stringify(text)} is git-only`);
      let read: string[] = [];
      try {
        read = [...d.gitDirectories(text, r)].sort();
      } catch (e) {
        assert.fail(`${JSON.stringify(text)}: ${(e as Error).message}`);
      }
      assert.deepEqual(read, real, JSON.stringify(text));
    }
    for (const text of MAY_ASK) {
      let read: string[];
      try {
        read = d.gitDirectories(text, r);
      } catch {
        continue; // asks
      }
      // Not git-only: it gets no writable git directory at all.
      if (!d.gitOnly(text)) assert.deepEqual(read, [], JSON.stringify(text));
      // Eighth pass: a command that only reads, in a place that cannot be told, is given no
      // directory (it needs no grant); what is given is a directory bash runs git in.
      else for (const dir of read) assert.ok(bashEnds(text, r).includes(dir), `${JSON.stringify(text)}: ${dir}`);
    }
  }));

test("r4 21: cd link && cd .. ends where it started: the project's own repository is granted, and the add works (C4 F2)", () =>
  withLinks((r, session) => {
    d.projectRoots(session);
    write(path.join(r, "new"), "new\n");
    const command = "cd link && cd .. && git add -A new";
    assert.deepEqual(d.gitDirectories(command, r), [r]);
    assert.deepEqual(d.gitWriteDirectories(command, r), [r]);
    const p = planFor(r, command);
    assert.equal(p.problem, undefined);
    assert.ok(p.gitDirs.includes(path.join(r, ".git")), "the project's git directory");
    assert.ok(!p.gitDirs.includes(path.join(r, "vendor", ".git")), "the repository under the link's real parent");
    const ran = sandboxed(p, command, r);
    assert.equal(ran.status, 0, ran.stderr);
    assert.match(gitIn(r, "status", "--short"), /^A {2}new$/m);
  }));

test("r4 25: cd sub/link && cd .. runs git in the nested repository: its remote is the one judged, and it gets no agent (C4 F1)", () =>
  withLinks((r, session, g) => {
    const sub = path.join(r, "sub");
    g("remote", "add", "origin", SSH);
    gitIn(sub, "remote", "add", "origin", "git@nested.invalid:team/y.git");
    gitIn(sub, "config", "core.sshCommand", "sh -c 'touch ran'");
    d.projectRoots(session);
    const command = "cd sub/link && cd .. && git ls-remote origin";
    assert.deepEqual(d.gitDirectories("cd sub/link && cd .. && git fetch origin", r), [sub]);
    assert.equal(d.usesSsh(command, r, session), false);
    assert.match(d.sandboxBreaks(command, r, session) ?? "", AGENT);
    // The same at the top, plainly, is the project's own and gets it.
    assert.equal(d.usesSsh("git ls-remote origin", r, session), true);
    // `git -C` is a chdir, the kernel's walk: `sub/link/..` is the project, `link/..` is `vendor`.
    g("remote", "set-url", "origin", HTTPS);
    gitIn(path.join(r, "vendor"), "remote", "add", "origin", SSH);
    assert.equal(d.sandboxBreaks("git -C sub/link/.. ls-remote origin && git status", r, session), undefined);
    assert.match(d.sandboxBreaks("git -C link/.. ls-remote origin && git status", r, session) ?? "", AGENT);
    assert.match(d.sandboxBreaks("cd link && git -C .. ls-remote origin && git status", r, session) ?? "", AGENT);
  }));

test("r4 21: a push destination and an approved clone are placed from where bash is, not from the real directory behind a link", () =>
  withLinks((r, _session, g) => {
    // `link` leads to vendor/inner; after `cd ..` bash is back in the project.
    execFileSync("git", ["init", "-q", "--bare", path.join(r, "store.git")]);
    g("remote", "add", "store", "./store.git");
    assert.deepEqual(d.pushDestinations("cd link && cd .. && git push store main", r), [path.join(r, "store.git")]);
    assert.deepEqual(d.expectedRepos("cd link && cd .. && git clone https://example.invalid/x.git", r), [path.join(r, "x")]);
    assert.deepEqual(d.expectedRepos("cd sub/link && cd .. && git init fresh", r), [path.join(r, "sub", "fresh")]);
    assert.deepEqual(d.expectedRepos("cd a && git init fresh", r), [path.join(r, "a", "fresh")]);
    assert.deepEqual(d.expectedRepos("git -C link/.. init fresh", r), [path.join(r, "vendor", "fresh")]);
    // A directory the call itself is to make is the one its words spell (no link lies in what is
    // not there yet); test/d-fixes.test.mts holds the same on lines.
    assert.deepEqual(d.expectedRepos("mkdir x && cd x && git init -q", r), [path.join(r, "x")]);
    assert.deepEqual(d.expectedRepos("cd link && cd .. && mkdir -p x/y && cd x/y && git init -q", r), [path.join(r, "x", "y")]);
    assert.deepEqual(d.expectedRepos("mkdir x && git -C x init -q", r), [path.join(r, "x")]);
  }));

// ---- 3. a repository's own harmless settings ----

test("r4 25: a local submodule.recurse, fetch.recurseSubmodules, push.default or push.recurseSubmodules does not take the agent away (C4 F8)", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "origin", SSH);
    d.projectRoots(session);
    const settings = [["submodule.recurse", "true"], ["fetch.recurseSubmodules", "on-demand"], ["push.default", "current"], ["push.recurseSubmodules", "check"], ["push.recurseSubmodules", "no"]];
    for (const [key, value] of settings) {
      g("config", key, value);
      for (const command of ["git fetch", "git pull", "git push", "git fetch --no-recurse-submodules origin", "git ls-remote origin"]) {
        assert.equal(d.usesSsh(command, r, session), true, `${key}=${value}: ${command}`);
        assert.equal(d.sandboxBreaks(command, r, session), undefined, `${key}=${value}: ${command}`);
      }
      g("config", "--unset", key);
    }
    // A key that does change what git runs still takes it.
    g("config", "core.sshCommand", "ssh -v");
    assert.equal(d.usesSsh("git fetch", r, session), false);
  }));

test("r4 25: what those settings do is judged where it matters: with a cloned submodule a recursing fetch, pull or push gets no agent", () =>
  withLib(false, (r, session, g) => {
    g("remote", "add", "origin", SSH);
    d.projectRoots(session);
    const agent = (command: string) => d.usesSsh(command, r, session);
    // Whatever the config says, a fetch or pull may go into the cloned submodule unless told not to.
    for (const [key, value] of [["submodule.recurse", "true"], ["fetch.recurseSubmodules", "true"], ["fetch.recurseSubmodules", "on-demand"]]) {
      g("config", key, value);
      for (const command of ["git fetch", "git pull", "git fetch origin"]) {
        assert.equal(agent(command), false, `${key}=${value}: ${command}`);
        assert.match(d.sandboxBreaks(command, r, session) ?? "", /cloned submodules/, `${key}=${value}: ${command}`);
      }
      for (const command of ["git fetch --no-recurse-submodules", "git pull --no-recurse-submodules origin main"]) assert.equal(agent(command), true, `${key}=${value}: ${command}`);
      g("config", "--unset", key);
    }
    // A push goes into submodules by push.recurseSubmodules, or by submodule.recurse.
    assert.equal(agent("git push"), true);
    for (const [key, value] of [["push.recurseSubmodules", "on-demand"], ["push.recurseSubmodules", "check"], ["push.recurseSubmodules", "only"], ["submodule.recurse", "true"]]) {
      g("config", key, value);
      assert.equal(agent("git push"), false, `${key}=${value}`);
      assert.equal(agent("git push origin main"), false, `${key}=${value}`);
      assert.match(d.sandboxBreaks("git push", r, session) ?? "", AGENT, `${key}=${value}`);
      g("config", "--unset", key);
    }
    // Both keys set the one variable git reads: the later of them in its config counts.
    g("config", "submodule.recurse", "true");
    g("config", "push.recurseSubmodules", "no");
    assert.equal(agent("git push"), true);
    g("config", "--remove-section", "submodule");
    g("config", "submodule.recurse", "true");
    assert.match(g("config", "--list", "--local"), /push\.recursesubmodules=no\n(.*\n)*submodule\.recurse=true/, "the fixture: submodule.recurse comes last");
    assert.equal(agent("git push"), false);
    // push.default changes which branch goes, not where git connects or what it runs.
    g("config", "--unset", "submodule.recurse");
    g("config", "push.default", "upstream");
    assert.equal(agent("git push"), true);
  }));

// ---- 4. a relative hooks path with a bare repository ----

const HUSKY = ".husky/_";

test("r4 21: with core.hooksPath = .husky/_ in a bare repository, nothing the plan makes pauses the session (C4 F5)", async () => {
  const r = scratch("bare");
  const session = new d.SessionState(r);
  try {
    execFileSync("git", ["init", "-q", "--bare", "-b", "main", r]);
    gitIn(r, "config", "core.hooksPath", HUSKY);
    d.projectRoots(session);
    assert.equal(d.gitTampered(session), undefined);
    for (const command of ["git log --oneline -1", "git branch --list"]) {
      const p = planFor(r, command);
      assert.equal(p.problem, undefined, command);
      assert.equal(d.gitTampered(session), undefined, `after the plan for ${command}`);
      assert.equal((await d.decideShell(guard(), session, r, "ls")).effect, "allow", `the decision after the plan for ${command}`);
    }
    // Where git would run hooks from is protected or watched all the same: a hook planted there
    // is named.
    const hooks = path.join(r, ".husky", "_");
    const p = planFor(r, "git branch --list");
    assert.ok(p.ro.includes(hooks) || p.gitWatch.some((w) => hooks === w || hooks.startsWith(`${w}/`)), "the hooks place is neither read-only nor watched");
    if (!fs.existsSync(hooks)) {
      write(path.join(hooks, "pre-receive"), HOOK, 0o755);
      assert.match(d.gitTampered(session) ?? "", /\.husky/);
    } else {
      const ran = sandboxed(p, `echo planted > ${hooks}/pre-receive`, r);
      assert.notEqual(ran.status, 0);
      assert.equal(fs.existsSync(path.join(hooks, "pre-receive")), false);
    }
  } finally {
    d.closeGitSnapshot(session);
    fs.rmSync(r, { recursive: true, force: true });
  }
});

test("r4 21: the same in the .bare + pointer-file layout: neither the bare directory nor the one beside the pointer file pauses", async () => {
  const r = scratch("dotbare");
  const session = new d.SessionState(r);
  try {
    execFileSync("git", ["init", "-q", "--bare", "-b", "main", path.join(r, ".bare")]);
    write(path.join(r, ".git"), "gitdir: ./.bare\n");
    gitIn(r, "config", "core.hooksPath", HUSKY);
    execFileSync("git", ["-C", r, "worktree", "add", "-q", "--orphan", "-b", "main", path.join(r, "main")], { stdio: "ignore" });
    write(path.join(r, "main", ".husky", "_", "pre-commit"), HOOK, 0o755);
    const roots = d.projectRoots(session);
    assert.equal(d.gitTampered(session), undefined);
    for (const command of ["git status", "git commit --allow-empty -m x"]) {
      const p = plan({ ...opts(r), projectRoots: roots, gitCwds: d.gitDirectories(command, path.join(r, "main")) });
      assert.equal(p.problem, undefined, command);
      assert.equal(d.gitTampered(session), undefined, `after the plan for ${command}`);
      assert.equal((await d.decideShell(guard(), session, path.join(r, "main"), "ls")).effect, "allow", `the decision after the plan for ${command}`);
      const ran = sandboxed(p, command, path.join(r, "main"));
      assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
    }
  } finally {
    d.closeGitSnapshot(session);
    fs.rmSync(r, { recursive: true, force: true });
  }
});

test("r4 21: a hook manager's directory the plan made in a work tree does not pause either; one that is put there instead is named", () =>
  fixture(async (r, g, session) => {
    commit(r);
    g("config", "core.hooksPath", HUSKY);
    d.projectRoots(session);
    const p = planFor(r, "git status");
    assert.equal(p.problem, undefined);
    assert.ok(p.ro.includes(path.join(r, ".husky", "_")), "the plan protects the place git runs hooks from");
    assert.equal(d.gitTampered(session), undefined, "the plan's own directory paused the session");
    // Replaced by another directory of the same name: that one nobody made but a command.
    fs.rmSync(path.join(r, ".husky"), { recursive: true });
    write(path.join(r, ".husky", "pre-commit"), HOOK, 0o755);
    assert.match(d.gitTampered(session) ?? "", /\.husky appeared/);
  }));

// ---- 5. the remote git picks ----

test("r4 12: where a tag has the branch's name, the branch's own remote settings are still the ones read", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "origin", HTTPS);
    g("remote", "add", "up", SSH);
    g("config", "branch.main.remote", "up");
    g("config", "branch.main.merge", "refs/heads/main");
    g("tag", "main");
    assert.equal(g("symbolic-ref", "--short", "HEAD").trim(), "heads/main", "the fixture: git prints the ambiguous name in full");
    d.projectRoots(session);
    // git fetches from `up`: the call is judged by it, and a single plain one gets the agent.
    for (const command of ["git fetch", "git pull"]) {
      assert.equal(d.usesSsh(command, r, session), true, command);
      assert.match(d.sandboxBreaks(`${command} && git status`, r, session) ?? "", AGENT, command);
    }
    // A push goes where branch.main.pushRemote says, a path on this machine here.
    const dest = path.join(r, "dest.git");
    execFileSync("git", ["init", "-q", "--bare", dest]);
    g("config", "branch.main.pushRemote", "./dest.git");
    assert.deepEqual(d.pushDestinations("git push", r), [dest]);
  }));

test("r4 12: a group of remotes is found by its word exactly, as git compares it: Team is the remote, team the group", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "a", HTTPS);
    g("remote", "add", "b", "https://b.invalid/team/x.git");
    g("remote", "add", "Team", SSH);
    g("config", "remotes.team", "a b");
    d.projectRoots(session);
    const breaks = (command: string) => d.sandboxBreaks(`${command} && git status`, r, session);
    // `git fetch Team` fetches the remote `Team` (xcheck/reviewers/c6-opus/p1c.sh).
    for (const command of ["git fetch Team", "git remote update Team", "git pull Team main"]) assert.match(breaks(command) ?? "", AGENT, command);
    for (const command of ["git fetch team", "git remote update team"]) assert.equal(breaks(command), undefined, command);
    // A subsection keeps its case; the last part of a key does not.
    g("config", "remotes.Mixed.All", "a Team");
    assert.match(breaks("git fetch Mixed.all") ?? "", AGENT);
    g("remote", "add", "mixed.all", HTTPS);
    assert.equal(breaks("git fetch mixed.all"), undefined);
  }));

// ---- 6. git reset --merge under submodule.recurse ----

for (const inTree of [false, true]) {
  const layout = inTree ? "kept in its own work tree" : "kept under .git/modules";
  test(`r4 21: under submodule.recurse, git reset --merge asks with a submodule ${layout}; every reset called harmless runs in the sandbox`, () =>
    withLib(inTree, (r, session, g) => {
      g("config", "submodule.recurse", "true");
      d.projectRoots(session);
      const breaks = (command: string) => d.sandboxBreaks(command, r, session);
      // `--merge` goes into the submodules even where nothing moves (x-p5: exit 128).
      for (const command of ["git reset --merge", "git reset --merge HEAD", "git reset --merge HEAD~0", "git reset --merge -q HEAD", "git reset -q --merge", "git reset --keep --merge HEAD"]) {
        assert.match(breaks(command) ?? "", /submodule/, command);
        assert.match(breaks(command) ?? "", OUTSIDE, command);
      }
      assert.equal(breaks("git reset --no-recurse-submodules --merge HEAD"), undefined);
      // What is called harmless is run: through the real wrapper, with the plan the call gets.
      write(path.join(r, "file"), "x\n");
      g("add", "file");
      for (const command of ["git reset --keep", "git reset --keep HEAD", "git reset --keep HEAD~0", "git reset --keep -q HEAD", "git reset --soft HEAD", "git reset --mixed HEAD", "git reset", "git reset -q", "git reset -- file", "git reset --merge --keep HEAD", "git reset --no-recurse-submodules --merge HEAD", "git reset --merge --soft HEAD"]) {
        assert.equal(breaks(command), undefined, command);
        const ran = sandboxed(planFor(r, command), command, r);
        assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
      }
    }));
}

// ---- 7. two asks that need not be ----

test("r4 21: a pull that updates a submodule whose .git file points outside modules/ works, and does not ask", () =>
  fixture((r, g, session) => {
    const upstream = `${r}-lib-upstream`;
    const origin = `${r}-origin.git`;
    execFileSync("git", ["init", "-q", "-b", "main", upstream]);
    commit(upstream, "lib one");
    commit(r);
    // The submodule's git directory is kept beside the work tree (`--separate-git-dir`).
    fs.mkdirSync(path.join(r, "gitdirs"));
    execFileSync("git", ["clone", "-q", `--separate-git-dir=${path.join(r, "gitdirs", "lib.git")}`, upstream, path.join(r, "lib")]);
    g(...FILE, "submodule", "add", "-q", upstream, "lib");
    g("commit", "-qm", "a submodule");
    assert.ok(fs.lstatSync(path.join(r, "lib", ".git")).isFile() && !fs.existsSync(path.join(r, ".git", "modules", "lib")), "the fixture: a pointer file to a git directory outside modules/");
    execFileSync("git", ["clone", "-q", "--bare", r, origin]);
    g("remote", "add", "origin", origin);
    g("fetch", "-q", "origin");
    g("branch", "-q", "--set-upstream-to=origin/main");
    d.projectRoots(session);
    for (const command of ["git pull --recurse-submodules", "git pull --rebase --recurse-submodules=yes"]) {
      assert.equal(d.sandboxBreaks(command, r, session), undefined, command);
      const ran = sandboxed(planFor(r, command), `git ${FILE.join(" ")} ${command.slice(4)}`, r);
      assert.equal(ran.status, 0, `${command}: ${ran.stderr}`);
    }
    g("config", "submodule.recurse", "true");
    assert.equal(d.sandboxBreaks("git pull", r, session), undefined);
  }));

// A submodule kept in its own work tree (`lib/.git` a directory) that has a module of its own
// under `lib/.git/modules/inner`.
async function withInner(fn: (r: string, session: d.SessionState, g: (...args: string[]) => string, inner: string) => void | Promise<void>) {
  await withLib(true, async (r, session, g, upstream) => {
    const lib = path.join(r, "lib");
    gitIn(lib, ...FILE, "submodule", "add", "-q", upstream, "inner");
    gitIn(lib, "commit", "-qm", "inner");
    g("commit", "-qam", "lib with inner");
    const inner = path.join(lib, ".git", "modules", "inner");
    assert.ok(fs.existsSync(path.join(inner, "HEAD")), "the fixture: lib/.git/modules/inner");
    await fn(r, session, g, inner);
  });
}

test("r4 21: the walk for nested modules gives up as 'cannot tell' when its rounds run out, not with what it has so far", () =>
  withInner((r, session, g) => {
    g("remote", "add", "origin", HTTPS);
    d.projectRoots(session);
    const command = "git fetch origin && git status";
    assert.equal(d.sandboxBreaks(command, r, session), undefined, "with rounds to spare the fetch is judged in full");
    const rounds = d.submoduleRounds.max;
    d.submoduleRounds.max = 1;
    try {
      assert.match(d.sandboxBreaks(command, r, session) ?? "", /cannot tell which cloned submodules/);
      assert.match(d.sandboxBreaks("git pull --recurse-submodules", r, session) ?? "", /could not be read|cannot tell|submodule/);
    } finally {
      d.submoduleRounds.max = rounds;
    }
  }));

test("r4 25: a module under a submodule kept outside modules/ counts for a fetch although its work tree is gone", () =>
  withInner((r, session, g, inner) => {
    const lib = path.join(r, "lib");
    g("remote", "add", "origin", HTTPS);
    gitIn(lib, "rm", "-q", "inner");
    gitIn(lib, "commit", "-qm", "remove inner");
    g("commit", "-qam", "lib without inner");
    assert.ok(fs.existsSync(path.join(inner, "HEAD")) && !fs.existsSync(path.join(lib, "inner")), "the fixture: git keeps the module, the work tree is gone");
    d.projectRoots(session);
    const command = "git fetch origin && git status";
    assert.equal(d.sandboxBreaks(command, r, session), undefined);
    // Only the walk of `lib/.git/modules` finds it now: its remote counts.
    gitIn(r, "--git-dir", inner, "--work-tree", inner, "remote", "set-url", "origin", SSH);
    assert.match(d.sandboxBreaks(command, r, session) ?? "", AGENT);
    assert.equal(d.sandboxBreaks("git fetch --no-recurse-submodules origin && git status", r, session), undefined);
  }));

// ---- 8. the hooks path as git reads it ----

// A repository inside the project that pushes go to; `marker` is a hook that leaves a line.
const marker = (r: string, name: string) => `#!/bin/sh\necho ${name} >> ${r}/ran.log\n`;
const PUSH = "git push store HEAD:refs/heads/pushed";
async function withStore(fn: (r: string, store: string, g: (...args: string[]) => string, session: d.SessionState) => void | Promise<void>) {
  await fixture(async (r, g, session) => {
    commit(r);
    const store = path.join(r, "store.git");
    execFileSync("git", ["init", "-q", "--bare", store]);
    g("remote", "add", "store", store);
    await fn(r, store, g, session);
  });
}

test("r4 25: a core.hooksPath your config sets for one repository only (includeIf gitdir) is the one a push into it runs hooks from", () =>
  withStore(async (r, store) => {
    const included = path.join(path.dirname(r), `${path.basename(r)}-included.cfg`);
    write(path.join(r, "mine", "pre-receive"), marker(r, "pre-receive"), 0o755);
    write(included, `[core]\n\thooksPath = ${path.join(r, "mine")}\n`);
    await withGlobal(`[includeIf "gitdir:${store}/"]\n\tpath = ${included}\n`, () => {
      assert.equal(gitIn(store, "config", "--get", "core.hooksPath").trim(), path.join(r, "mine"), "the fixture: git reads the included value in the destination");
      assert.equal(spawnSync("git", ["config", "--global", "--get", "core.hooksPath"], { cwd: os.homedir() }).status, 1, "the fixture: and nowhere else");
      const found = planFor(r, PUSH).problem ?? "";
      assert.ok(found.includes(`has a pre-receive hook (${path.join(r, "mine", "pre-receive")})`), found);
    });
    assert.equal(planFor(r, PUSH).problem, undefined);
  }));

test("r4 21: a relative core.hooksPath your config sets for the project's repository only is protected in the work tree like its own", () =>
  fixture(async (r, _g, session) => {
    commit(r);
    const included = path.join(path.dirname(r), `${path.basename(r)}-included.cfg`);
    write(included, "[core]\n\thooksPath = .myhooks\n");
    write(path.join(r, ".myhooks", "pre-commit"), HOOK, 0o755);
    await withGlobal(`[includeIf "gitdir:${r}/.git"]\n\tpath = ${included}\n`, () => {
      assert.equal(gitIn(r, "config", "--get", "core.hooksPath").trim(), ".myhooks", "the fixture: git reads the included value in the project");
      d.projectRoots(session);
      const p = planFor(r, "git status");
      assert.equal(p.problem, undefined);
      assert.ok(p.ro.includes(path.join(r, ".myhooks")), "the hooks directory git uses here stayed writable");
      const ran = sandboxed(p, `echo planted >> ${r}/.myhooks/pre-commit`, r);
      assert.notEqual(ran.status, 0);
      assert.equal(fs.readFileSync(path.join(r, ".myhooks", "pre-commit"), "utf8"), HOOK);
    });
  }));

test("r4 25: a core.hooksPath is taken byte for byte: a trailing space names another directory, and an empty one is the root, not 'unset'", () =>
  withStore((r, store, g) => {
    write(path.join(store, "receive ", "pre-receive"), marker(r, "spaced"), 0o755);
    write(path.join(store, "receive", "update"), HOOK, 0o644);
    gitIn(store, "config", "core.hooksPath", "receive ");
    const found = planFor(r, PUSH).problem ?? "";
    assert.ok(found.includes(`has a pre-receive hook (${path.join(store, "receive ", "pre-receive")})`), found);
    // git's own answer: that hook runs.
    g("push", "-q", "store", "HEAD:refs/heads/one");
    assert.equal(fs.readFileSync(path.join(r, "ran.log"), "utf8"), "spaced\n");
    // An empty value: git looks for `/pre-receive`, and the hook in `hooks/` does not run.
    fs.rmSync(path.join(r, "ran.log"));
    gitIn(store, "config", "core.hooksPath", "");
    write(path.join(store, "hooks", "pre-receive"), marker(r, "default"), 0o755);
    g("push", "-q", "store", "HEAD:refs/heads/two");
    assert.equal(fs.existsSync(path.join(r, "ran.log")), false, "the fixture: git runs no hook from hooks/ under an empty core.hooksPath");
    assert.equal(planFor(r, PUSH).problem, undefined);
    // Unset, the hook in `hooks/` is the one.
    gitIn(store, "config", "--unset", "core.hooksPath");
    assert.ok((planFor(r, PUSH).problem ?? "").includes(`has a pre-receive hook (${path.join(store, "hooks", "pre-receive")})`));
  }));

const PUSH_HOOKS = "appeared (a push into the repository would run hooks from it)";

test("r4 21: a relative core.hooksPath that climbs out of the git directory: where a push would run hooks from is named when it appears, for any call", () =>
  fixture((r, g, session) => {
    commit(r);
    g("config", "core.hooksPath", "../receive");
    d.projectRoots(session);
    assert.equal(d.gitTampered(session), undefined);
    const place = path.join(r, "receive");
    // A call that is not git-only can write there: it is the work tree.
    const p = plan({ ...opts(r), gitWritable: false });
    assert.equal(p.problem, undefined);
    const planted = sandboxed(p, `mkdir ${place} && printf '#!/bin/sh\\ntouch ${r}/ran\\n' > ${place}/pre-receive && chmod +x ${place}/pre-receive`, r);
    assert.equal(planted.status, 0, planted.stderr);
    const found = d.gitTampered(session) ?? "";
    assert.ok(found.includes(`${place} ${PUSH_HOOKS}`), found);
    // git's own answer on what was planted: a push into the checkout runs it.
    g("push", "-q", ".", "HEAD:refs/heads/pushed");
    assert.ok(fs.existsSync(path.join(r, "ran")), "the fixture: git runs the hook from <work tree>/receive");
  }));

test("r4 21: where that place is there, it is read-only for every call; a deeper one is named by its first missing part", () =>
  fixture((r, g, session) => {
    commit(r);
    g("config", "core.hooksPath", "../receive");
    write(path.join(r, "receive", "pre-receive"), HOOK, 0o755);
    d.projectRoots(session);
    for (const gitWritable of [false, true]) {
      const p = plan({ ...opts(r), gitWritable, gitCwds: [r] });
      assert.equal(p.problem, undefined);
      assert.ok(p.ro.includes(path.join(r, "receive")), `gitWritable ${gitWritable}`);
      assert.notEqual(sandboxed(p, `echo planted > ${r}/receive/update`, r).status, 0);
    }
    assert.equal(d.gitTampered(session), undefined);
    g("config", "core.hooksPath", "../a/b/c");
    const fresh = new d.SessionState(r);
    try {
      d.projectRoots(fresh);
      assert.equal(d.gitTampered(fresh), undefined);
      fs.mkdirSync(path.join(r, "a", "b", "c"), { recursive: true });
      assert.ok((d.gitTampered(fresh) ?? "").includes(`${path.join(r, "a")} ${PUSH_HOOKS}`));
    } finally {
      d.closeGitSnapshot(fresh);
    }
  }));

// ---- 9. what joins a baseline unnamed ----

// Every pause from here until the session resumes for good, each resumed by a touch.
function pauses(session: d.SessionState, resume: ReturnType<typeof resuming>, first: string | undefined): string[] {
  const out: string[] = [];
  let reason = first;
  for (let n = 0; reason !== undefined && n < 12; n++) {
    out.push(reason);
    resume.touch();
    reason = d.gitTampered(session, resume.file);
  }
  assert.equal(reason, undefined, "the session never resumed");
  return out;
}

test("r4 21: operation state beyond the five a pause shows is named before it joins the baseline: an exec line among it", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      const dotGit = path.join(r, ".git");
      // A git-only call that leaves none of this ran meanwhile.
      const call = d.noteGitCall(session, "git status", [dotGit])!;
      for (const name of ["BISECT_ANCESTORS_OK", "BISECT_EXPECTED_REV", "BISECT_LOG", "BISECT_NAMES", "BISECT_START", "BISECT_TERMS", "CHERRY_PICK_HEAD", "REVERT_HEAD"]) write(path.join(dotGit, name), "x\n");
      write(path.join(dotGit, "rebase-merge", "git-rebase-todo"), "pick 1234567 one\nexec touch /tmp/never\n");
      call.done = true;
      const first = d.gitStateTampered(session) ?? "";
      assert.match(first, /; and \d+ more$/);
      const all = pauses(session, resume, first);
      assert.ok(all.length >= 2, `one pause took in everything: ${first}`);
      const text = all.join("\n");
      assert.match(text, /git-rebase-todo gained an exec line/, "the exec line joined the baseline unnamed");
      for (const name of ["BISECT_TERMS", "CHERRY_PICK_HEAD", "REVERT_HEAD", "rebase-merge appeared"]) assert.ok(text.includes(name), `${name} was never shown`);
      // Each pause shows five at most.
      for (const reason of all) assert.ok(reason.split("; ").filter((part) => !/^and \d+ more$/.test(part)).length <= 5, reason);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: state a call leaves while the session is paused is named at the resume, not taken in", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      const dotGit = path.join(r, ".git");
      const call = d.noteGitCall(session, "git status", [dotGit])!;
      execFileSync("git", ["init", "-q", path.join(r, "planted")]);
      assert.match(d.gitTampered(session, resume.file) ?? "", /planted\/\.git appeared/);
      // The call that was running ends while the session is paused, leaving a todo list.
      write(path.join(dotGit, "rebase-merge", "git-rebase-todo"), "exec touch /tmp/never\n");
      call.done = true;
      assert.match(d.gitStateTampered(session) ?? "", /planted/);
      resume.touch();
      assert.match(d.gitTampered(session, resume.file) ?? "", /gained an exec line/);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: of more than five quarantined plants, the pause names the five it shows; one that could not be moved is named again", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const nested = Array.from({ length: 7 }, (_, i) => path.join(r, `n${i}`, ".git"));
    try {
      commit(r);
      for (const dir of nested) execFileSync("git", ["init", "-q", path.dirname(dir)]);
      d.projectRoots(session);
      assert.equal(d.gitTampered(session, resume.file), undefined);
      const call = d.noteGitCall(session, "git status", nested)!;
      for (const dir of nested) fs.writeFileSync(path.join(dir, "commondir"), ".\n");
      // The last two cannot be renamed: their directory is closed to writing.
      for (const dir of nested.slice(5)) fs.chmodSync(dir, 0o555);
      const reason = d.quarantineGitFiles(session, [session], call) ?? "";
      assert.match(reason, /; and 2 more$/);
      const shown = nested.slice(0, 5).map((dir) => path.join(dir, "commondir"));
      assert.deepEqual([...(session.tampered?.named ?? [])].sort(), shown.sort(), "named is what was shown");
      for (const dir of nested.slice(5)) assert.ok(fs.existsSync(path.join(dir, "commondir")), "the fixture: the rename failed");
      resume.touch();
      const second = d.gitTampered(session, resume.file) ?? "";
      for (const dir of nested.slice(5)) assert.ok(second.includes(`${path.join(dir, "commondir")} appeared`), `${dir}: ${second}`);
    } finally {
      for (const dir of nested) if (fs.existsSync(dir)) fs.chmodSync(dir, 0o755);
      resume.remove();
    }
  }));

test("r4 21: a resume takes in a named path with what it held: a commondir rewritten between the pause and the touch is named again", () =>
  fixture((r, g, session) => {
    const resume = resuming();
    try {
      commit(r);
      d.projectRoots(session);
      const file = path.join(r, ".git", "commondir");
      fs.writeFileSync(file, ".\n");
      assert.match(d.gitTampered(session, resume.file) ?? "", /\.git\/commondir appeared/);
      // Before the touch: it now names a repository whose config runs a program.
      const evil = `${r}-evil.git`;
      execFileSync("git", ["init", "-q", "--bare", evil]);
      gitIn(evil, "config", "core.fsmonitor", "touch /tmp/never-ran");
      fs.writeFileSync(file, `${evil}\n`);
      resume.touch();
      const second = d.gitTampered(session, resume.file) ?? "";
      assert.match(second, /\.git\/commondir/, "the rewritten commondir joined the baseline unseen");
      assert.equal(d.gitTampered(session, resume.file), second, "paused until resumed again");
      // Seen as it is now, and resumed: taken in.
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
      fs.rmSync(file);
      assert.equal(g("config", "--get", "core.bare").trim(), "false");
    } finally {
      resume.remove();
    }
  }));

test("r4 21: the same for a pointer file and for a todo list: what is there at the resume is what was named, or it is named again", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      execFileSync("git", ["init", "-q", "--bare", `${r}-one.git`]);
      execFileSync("git", ["init", "-q", "--bare", `${r}-two.git`]);
      d.projectRoots(session);
      const pointer = path.join(r, "planted", ".git");
      write(pointer, `gitdir: ${r}-one.git\n`);
      assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${pointer} appeared`));
      write(pointer, `gitdir: ${r}-two.git\n`);
      resume.touch();
      assert.ok((d.gitTampered(session, resume.file) ?? "").includes(pointer), "the rewritten pointer file joined the baseline unseen");
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
      // A todo list that gained an exec line, rewritten to another before the touch.
      const dotGit = path.join(r, ".git");
      const call = d.noteGitCall(session, "git status", [dotGit])!;
      write(path.join(dotGit, "rebase-merge", "git-rebase-todo"), "exec true\n");
      call.done = true;
      assert.match(d.gitStateTampered(session) ?? "", /gained an exec line \("exec true"\)/);
      write(path.join(dotGit, "rebase-merge", "git-rebase-todo"), "exec touch /tmp/never\n");
      resume.touch();
      assert.match(d.gitTampered(session, resume.file) ?? "", /git-rebase-todo/, "the rewritten todo list joined the baseline unseen");
    } finally {
      resume.remove();
    }
  }));

test("r4 21: a session that had no snapshot when it was paused compares like a new one at the resume: a commondir in the main checkout is named", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    try {
      commit(r);
      // Paused by another session's finding before it decided anything (index.ts, pauseAll).
      session.tampered = { reason: "a plant elsewhere", at: Date.now(), named: [] };
      fs.writeFileSync(path.join(r, ".git", "commondir"), ".\n");
      resume.touch();
      assert.match(d.gitTampered(session, resume.file) ?? "", /\.git\/commondir appeared/, "the session took whatever was there for its baseline");
      assert.ok(session.snapshot, "it has a snapshot of the project from here on");
      assert.deepEqual(session.roots, [r]);
      resume.touch();
      assert.equal(d.gitTampered(session, resume.file), undefined);
    } finally {
      resume.remove();
    }
  }));

test("r4 21: a pause lists a path once: a new linked worktree takes one of the five places, not two", () =>
  fixture((r, g, session) => {
    commit(r);
    d.projectRoots(session);
    g("worktree", "add", "-q", "-b", "feature", `${r}-feature`);
    const admin = path.join(r, ".git", "worktrees", path.basename(`${r}-feature`));
    const reason = d.gitTampered(session) ?? "";
    assert.equal(reason.split(`${admin} appeared`).length - 1, 1, reason);
    assert.match(reason, /a new linked worktree/);
    assert.equal(new Set(session.tampered?.named).size, session.tampered?.named?.length, "a path is named once");
  }));

// ---- 10. the git directory around a module ----

// The superproject of `withLib`, with a second submodule and two linked worktrees.
interface Layout {
  dotGit: string;
  lib: string;
  module: string;
  feature: string;
  second: string;
  admin: (wt: string) => string;
}
async function withModules(fn: (r: string, session: d.SessionState, g: (...args: string[]) => string, at: Layout) => void | Promise<void>) {
  await withLib(false, async (r, session, g, upstream) => {
    g(...FILE, "submodule", "add", "-q", upstream, "other");
    g("commit", "-qm", "another submodule");
    const feature = `${r}-feature`;
    const second = `${r}-second`;
    g("worktree", "add", "-q", "-b", "feature", feature);
    g("worktree", "add", "-q", "-b", "second", second);
    const dotGit = path.join(r, ".git");
    await fn(r, session, g, { dotGit, lib: path.join(r, "lib"), module: path.join(dotGit, "modules", "lib"), feature, second, admin: (wt) => path.join(dotGit, "worktrees", path.basename(wt)) });
  });
}
// The terms this kernel gives, and the ones a kernel at the floor gives (Landlock ABI 5).
const ABIS: Record<string, string>[] = [{}, { AUTOMODE_FAKE_ABI: "5" }];
// `protocol.file.allow=always` for a fetch from a path, as the user's own environment.
const FILE_ENV = { GIT_CONFIG_COUNT: "1", GIT_CONFIG_KEY_0: "protocol.file.allow", GIT_CONFIG_VALUE_0: "always" };

test("r4 21: a call in a submodule under .git/modules can make no new name in the git directory around its module, on ABI 5 terms too", () =>
  withModules((r, session, g, at) => {
    d.projectRoots(session);
    const before = g("rev-list", "--count", "HEAD").trim();
    const head = g("rev-parse", "HEAD").trim();
    const p = planFor(r, "git status", at.lib);
    assert.equal(p.problem, undefined);
    // The module is the call's; the git directory around it is none of its record.
    assert.deepEqual(p.gitDirs, [at.module]);
    const names = ["shallow", "packed-refs", "HEAD.lock", "index.lock", "gc.log", "FETCH_HEAD", "commondir", "config.worktree", "index.new", "info/grafts", "info/attributes", "objects/info/alternates", "modules/evil/HEAD", "worktrees/evil/HEAD", "newdir/file"];
    for (const abi of ABIS) {
      for (const name of names) {
        const target = path.join(at.dotGit, name);
        const ran = sandboxed(p, `mkdir -p ${path.dirname(target)} && echo ${head} > ${target}`, at.lib, abi);
        assert.notEqual(ran.status, 0, `${name} was made (${JSON.stringify(abi)})`);
        assert.equal(fs.existsSync(target), false, name);
      }
      for (const dir of ["modules/evil", "newdir"]) assert.equal(fs.existsSync(path.join(at.dotGit, dir)), false, dir);
      // Nor can what is there be written or moved: in the superproject's git directory, another
      // module, a linked worktree's admin directory.
      for (const target of ["HEAD", "index", "refs/heads/main", "config", "modules/other/HEAD", "modules/lib/config", path.join("worktrees", path.basename(at.feature), "HEAD")]) {
        const file = path.join(at.dotGit, target);
        const was = fs.readFileSync(file);
        assert.notEqual(sandboxed(p, `echo planted >> ${file}`, at.lib, abi).status, 0, `${target} was written`);
        assert.notEqual(sandboxed(p, `mv ${file} ${file}.moved`, at.lib, abi).status, 0, `${target} was moved`);
        assert.deepEqual(fs.readFileSync(file), was, target);
      }
      assert.notEqual(sandboxed(p, `mv ${at.module} ${at.module}.moved`, at.lib, abi).status, 0, "the module was moved");
      // From inside the submodule the everyday commands work.
      write(path.join(at.lib, "new"), `new ${JSON.stringify(abi)}\n`);
      for (const command of ["git status --short", "git add -A", "git stash", "git stash pop", "git commit -qam two", "git gc -q", "git fetch -q origin", "git log --oneline -1", "git branch -f feature-x", "git switch -q feature-x", "git switch -q main", "git tag -f v1"]) {
        const ran = sandboxed(planFor(r, command, at.lib), command, at.lib, { ...abi, ...FILE_ENV }, Object.keys(FILE_ENV));
        assert.equal(ran.status, 0, `${command} (${JSON.stringify(abi)}): ${ran.stderr}`);
      }
    }
    // The superproject reads what it read before.
    assert.equal(g("rev-list", "--count", "HEAD").trim(), before);
    assert.equal(g("rev-parse", "--is-shallow-repository").trim(), "false");
  }));

// Eighth pass: only a link that leads outside the writable directories. One that leads into the
// project asks again (what git reads through it could be written there: test/c-eighth.test.mts).
test("r4 21: a symbolic link at the top of the superproject's git directory that leads outside the writable directories does not make a call in a submodule ask", () =>
  withModules((r, session, _g, at) => {
    fs.mkdirSync(`${r}-elsewhere`);
    fs.symlinkSync(`${r}-elsewhere`, path.join(at.dotGit, "lfs"));
    d.projectRoots(session);
    const p = planFor(r, "git status", at.lib);
    assert.equal(p.problem, undefined);
    assert.notEqual(sandboxed(p, `echo planted > ${at.dotGit}/lfs/probe`, at.lib).status, 0, "written through the link");
    // The link itself cannot be replaced: its directory is read-only.
    assert.notEqual(sandboxed(p, `rm ${at.dotGit}/lfs && ln -s /tmp ${at.dotGit}/lfs`, at.lib).status, 0);
    assert.equal(fs.readlinkSync(path.join(at.dotGit, "lfs")), `${r}-elsewhere`);
    assert.equal(sandboxed(p, "git status --short", at.lib).status, 0);
  }));

test("r4 21: a module nested in a module: the call gets the inner one, with both git directories around it read-only whole", () =>
  withLib(false, (r, _session, g, upstream) => {
    const lib = path.join(r, "lib");
    gitIn(lib, ...FILE, "submodule", "add", "-q", upstream, "inner");
    gitIn(lib, "commit", "-qm", "inner");
    g("commit", "-qam", "lib with inner");
    const dotGit = path.join(r, ".git");
    const module = path.join(dotGit, "modules", "lib");
    const inner = path.join(module, "modules", "inner");
    const p = planFor(r, "git status", path.join(lib, "inner"));
    assert.equal(p.problem, undefined);
    assert.deepEqual(p.gitDirs, [inner]);
    write(path.join(lib, "inner", "new"), "new\n");
    for (const abi of ABIS) {
      const ran = sandboxed(p, `git add -A && git commit -qm inner-${Object.keys(abi).length}`, path.join(lib, "inner"), abi);
      assert.equal(ran.status, 0, ran.stderr);
      for (const target of [path.join(module, "HEAD"), path.join(module, "packed-refs"), path.join(module, "shallow"), path.join(dotGit, "shallow"), path.join(module, "modules", "evil")]) {
        assert.notEqual(sandboxed(p, `echo planted >> ${target}`, lib, abi).status, 0, target);
      }
      write(path.join(lib, "inner", "new"), "newer\n");
    }
    // A call in the outer module has the inner one too, as a call in a superproject has its modules.
    const outer = planFor(r, "git status", lib);
    assert.deepEqual([...outer.gitDirs].sort(), [module, inner].sort());
    assert.equal(sandboxed(outer, "git status --short && git -C inner status --short", lib).status, 0);
    assert.notEqual(sandboxed(outer, `echo planted > ${path.join(dotGit, "shallow")}`, lib).status, 0);
  }));

test("r4 21: a git directory a pointer file names that encloses the repository the call works in is not granted: the call asks", () =>
  fixture((r, g) => {
    commit(r);
    execFileSync("git", ["init", "-q", path.join(r, "vendor")]);
    // The project's own top made to look like a git directory, named by a submodule's `.git` file.
    for (const name of ["objects", "refs"]) fs.mkdirSync(path.join(r, name));
    write(path.join(r, "HEAD"), "ref: refs/heads/main\n");
    write(path.join(r, "odd", ".git"), "gitdir: ..\n");
    g("update-index", "--add", "--cacheinfo", `160000,${g("rev-parse", "HEAD").trim()},odd`);
    const p = planFor(r, "git status");
    assert.match(p.problem ?? "", /encloses|holds the repository/);
    assert.ok(!p.gitDirs.includes(r), "the directory around the repository was granted");
    assert.ok(!p.gitDirs.includes(path.join(r, "vendor", ".git")), "a repository that merely lies beside it was granted");
  }));

test("r4 21: the wrapper makes writable again only a directory the call may write anyway: any other AUTOMODE_REOPEN runs nothing", () =>
  withModules((r, _session, _g, at) => {
    const p = planFor(r, "git status", at.lib);
    assert.deepEqual(p.reopen, [at.module]);
    const marker = path.join(r, "ran");
    const run = (reopen: string[]) => sandboxed({ ...p, reopen }, `touch ${marker}`, at.lib);
    // The plan's own list runs the command.
    assert.equal(run(p.reopen).status, 0);
    assert.ok(fs.existsSync(marker));
    fs.rmSync(marker);
    const refused: [string, RegExp][] = [
      // Outside every writable directory: the home directory, and a system one.
      [os.homedir(), /AUTOMODE_REOPEN names a path outside AUTOMODE_RW/],
      ["/usr", /AUTOMODE_REOPEN names a path outside AUTOMODE_RW/],
      // Inside one, and not a directory, or not there.
      [path.join(at.module, "HEAD"), /must be a directory to be made writable inside a read-only one/],
      [path.join(at.module, "nowhere"), /must be a directory to be made writable inside a read-only one/],
    ];
    for (const [target, why] of refused) {
      const ran = run([at.module, target]);
      assert.equal(ran.status, 126, `${target}: ${ran.stderr}`);
      assert.match(ran.stderr, why, target);
      assert.match(ran.stderr, /command not run/, target);
      assert.equal(fs.existsSync(marker), false, `${target}: the command ran`);
    }
  }));

// ---- 11. a call in a linked worktree ----

test("r4 21: a call in a linked worktree gets its own admin directory and the common directory, not the modules or the other worktrees", () =>
  withModules((r, session, _g, at) => {
    const roots = d.projectRoots(session);
    assert.deepEqual([...roots].sort(), [r, at.feature, at.second].sort());
    const planIn = (command: string) =>
      plan({ ...opts(r), projectRoots: roots, gitCwds: d.gitDirectories(command, at.feature), gitWriteCwds: d.gitWriteDirectories(command, at.feature), gitMaintainCwds: d.gitMaintainDirectories(command, at.feature), gitPushTo: d.pushDestinations(command, at.feature) });
    const p = planIn("git status");
    assert.equal(p.problem, undefined);
    assert.deepEqual([...p.gitDirs].sort(), [at.dotGit, at.admin(at.feature)].sort());
    const store = path.join(r, "store.git");
    execFileSync("git", ["init", "-q", "--bare", store]);
    execFileSync("git", ["--git-dir", store, "fetch", "-q", r, "main:main"]);
    const other = path.join("worktrees", path.basename(at.second));
    for (const abi of ABIS) {
      // The modules it does not work in, and the other worktrees' admin directories.
      for (const target of ["modules/lib/HEAD", "modules/lib/index", "modules/lib/refs/heads/main", "modules/other/HEAD", path.join(other, "HEAD"), path.join(other, "index")]) {
        const file = path.join(at.dotGit, target);
        const was = fs.readFileSync(file);
        assert.notEqual(sandboxed(p, `echo planted >> ${file}`, at.feature, abi).status, 0, `${target} was written`);
        assert.deepEqual(fs.readFileSync(file), was, target);
      }
      for (const target of [path.join(other, "config.worktree"), path.join(other, "MERGE_HEAD"), "modules/lib/refs/heads/planted", "modules/evil/HEAD", "worktrees/evil/HEAD"]) {
        const file = path.join(at.dotGit, target);
        assert.notEqual(sandboxed(p, `mkdir -p ${path.dirname(file)} && echo planted > ${file}`, at.feature, abi).status, 0, `${target} was made`);
        assert.equal(fs.existsSync(file), false, target);
      }
      // The everyday commands from inside the linked worktree work.
      write(path.join(at.feature, "new"), `new ${JSON.stringify(abi)}\n`);
      for (const command of ["git status --short", "git add -A", "git stash", "git stash pop", "git commit -qam work", "git gc -q", `git fetch -q ${store}`, "git worktree list", "git log --oneline -1", "git branch -f topic", "git tag -f wt", "git merge -q main", "git reset -q --soft HEAD"]) {
        const ran = sandboxed(planIn(command), command, at.feature, { ...abi, ...FILE_ENV }, Object.keys(FILE_ENV));
        assert.equal(ran.status, 0, `${command} (${JSON.stringify(abi)}): ${ran.stderr}`);
      }
    }
    assert.equal(gitIn(at.feature, "log", "-1", "--format=%s").trim(), "work");
    // `git gc` expires every worktree's reflog under a lock on its HEAD: that call alone has the
    // other worktrees' admin directories, as before, and still not the main checkout's modules.
    const gc = planIn("git gc -q");
    assert.deepEqual([...gc.gitDirs].sort(), [at.dotGit, at.admin(at.feature), at.admin(at.second)].sort());
    assert.notEqual(sandboxed(gc, `echo planted >> ${at.module}/HEAD`, at.feature).status, 0);
    assert.deepEqual(d.gitMaintainDirectories("git status && git commit -qm x", at.feature), []);
    // The main checkout's own calls keep what they had: its modules and its worktrees' directories.
    const main = planFor(r, "git gc -q");
    assert.equal(main.problem, undefined);
    assert.ok(main.gitDirs.includes(at.module) && main.gitDirs.includes(at.admin(at.second)));
    const ran = sandboxed(main, "git gc -q && git fetch -q --recurse-submodules=no . && git worktree prune", r);
    assert.equal(ran.status, 0, ran.stderr);
  }));

// ---- 12. what a push to a repository on this machine runs ----

test("r4 25: a push to a repository on this machine asks for the hooks receive-pack's own gc and checkout run, and for a program its config names", () =>
  withStore((r, store) => {
    assert.equal(planFor(r, PUSH).problem, undefined);
    for (const name of ["pre-auto-gc", "post-index-change"]) {
      const file = path.join(store, "hooks", name);
      write(file, HOOK, 0o755);
      const found = planFor(r, PUSH).problem ?? "";
      assert.ok(found.includes(`has a ${name} hook (${file})`), `${name}: ${found}`);
      assert.match(found, OUTSIDE, name);
      fs.rmSync(file);
    }
    for (const [key, value] of [["core.fsmonitor", path.join(r, "fsmonitor.sh")], ["core.fsmonitor", "sh -c 'touch ran'"], ["core.alternateRefsCommand", "sh -c 'touch ran'"]]) {
      gitIn(store, "config", key, value);
      const found = planFor(r, PUSH).problem ?? "";
      assert.ok(found.toLowerCase().includes(key.toLowerCase()), `${key}=${value}: ${found}`);
      assert.match(found, OUTSIDE, `${key}=${value}`);
      gitIn(store, "config", "--unset", key);
    }
    // git's own file-system monitor, switched on or off, is no program of the repository's naming.
    for (const value of ["true", "false"]) {
      gitIn(store, "config", "core.fsmonitor", value);
      assert.equal(planFor(r, PUSH).problem, undefined, `core.fsmonitor=${value}`);
    }
  }));

// ---- 13. smaller ----

test("r4 24: an environment string of exactly the kernel's limit is one the kernel takes; one byte more is refused", () => {
  const limit = 128 * 1024;
  // `NAME=value` and its closing NUL.
  const value = (bytes: number) => "x".repeat(bytes - "AUTOMODE_COMMAND=".length - 1);
  assert.equal(envStringProblem("AUTOMODE_COMMAND", value(limit)), undefined, "exactly the limit");
  assert.equal(envStringProblem("AUTOMODE_COMMAND", value(limit - 1)), undefined);
  assert.match(envStringProblem("AUTOMODE_COMMAND", value(limit + 1)) ?? "", /exceeds the kernel environment string limit/);
  // The kernel's own answer for the two sizes.
  for (const [bytes, ok] of [[limit, true], [limit + 1, false]] as const) {
    const ran = spawnSync("/bin/true", [], { env: { AUTOMODE_COMMAND: value(bytes) } });
    assert.equal(!ran.error && ran.status === 0, ok, `exec with a string of ${bytes} bytes`);
  }
});

test("r4 21: a core.bare lookup that fails is a problem in the project, not 'a bare repository'", () =>
  fixture((r) => {
    commit(r);
    const store = path.join(r, "store.git");
    execFileSync("git", ["init", "-q", "--bare", store]);
    assert.deepEqual(discover([r]).problems, []);
    fs.appendFileSync(path.join(store, "config"), "[core\n");
    const problems = discover([r]).problems;
    assert.ok(problems.some((text) => /core\.bare/.test(text) && text.includes(store)), JSON.stringify(problems));
    assert.match(plan({ ...opts(r), gitWritable: false }).problem ?? "", /store\.git/);
  }));

// ---- 14. tests that had no force ----

test("r4 25: a destination whose hooks cannot be looked up, or whose hooks directory cannot be listed, counts as one that has a hook", () =>
  withStore((r, store) => {
    assert.equal(planFor(r, PUSH).problem, undefined);
    // The lookup as the receiving git makes it fails.
    const bin = path.join(path.dirname(r), `${path.basename(r)}-bin`);
    const real = execFileSync("which", ["git"], { encoding: "utf8" }).trim();
    write(path.join(bin, "git"), `#!/bin/sh\ncase " $* " in *" --git-dir . "*" core.hooksPath "*) exit 128;; esac\nexec '${real}' "$@"\n`, 0o755);
    const before = process.env.PATH;
    process.env.PATH = `${bin}:${before}`;
    try {
      const found = planFor(r, PUSH).problem ?? "";
      assert.match(found, /the push goes to .*store\.git on this machine, which has hooks that could not be looked up \(git could not read core\.hooksPath/);
      assert.match(found, OUTSIDE);
    } finally {
      process.env.PATH = before;
    }
    // A hooks directory outside the project that this process cannot list.
    const closed = path.join(path.dirname(r), `${path.basename(r)}-closed-hooks`);
    write(path.join(closed, "pre-receive"), HOOK, 0o755);
    gitIn(store, "config", "core.hooksPath", closed);
    assert.ok((planFor(r, PUSH).problem ?? "").includes(`has a pre-receive hook (${path.join(closed, "pre-receive")})`));
    fs.chmodSync(closed, 0o000);
    try {
      assert.throws(() => fs.readdirSync(closed), /EACCES/, "the test needs a user that mode 000 keeps out");
      assert.ok((planFor(r, PUSH).problem ?? "").includes(`has a hooks directory that cannot be listed (${closed})`));
    } finally {
      fs.chmodSync(closed, 0o755);
    }
    // One that is not there has no hook in it.
    gitIn(store, "config", "core.hooksPath", path.join(closed, "nowhere"));
    assert.equal(planFor(r, PUSH).problem, undefined);
    // A value git expands in a way that is not followed here counts as one too.
    gitIn(store, "config", "core.hooksPath", "~nobody/hooks");
    assert.match(planFor(r, PUSH).problem ?? "", /a core\.hooksPath that cannot be followed here/);
  }));

test("r4 21: a pause that follows a resume is not resumed by the touch that brought it up, however far ahead the resume file's time is", () =>
  fixture((r, _g, session) => {
    const file = path.join(scratch("resume"), "resume");
    try {
      d.projectRoots(session);
      execFileSync("git", ["init", "-q", path.join(r, "planted")]);
      assert.match(d.gitTampered(session, file) ?? "", /planted\/\.git appeared/);
      fs.writeFileSync(path.join(r, ".git", "commondir"), ".\n");
      // A resume file a minute ahead of this machine's clock (another clock, a file system that
      // rounds up).
      fs.writeFileSync(file, "");
      fs.utimesSync(file, new Date(Date.now() + 60_000), new Date(Date.now() + 60_000));
      const second = d.gitTampered(session, file) ?? "";
      assert.match(second, /\.git\/commondir appeared/);
      for (const check of ["first", "second"]) assert.equal(d.gitTampered(session, file), second, `the ${check} check after it: the same touch resumed the pause it brought up`);
      fs.utimesSync(file, new Date(Date.now() + 120_000), new Date(Date.now() + 120_000));
      assert.equal(d.gitTampered(session, file), undefined);
    } finally {
      fs.rmSync(path.dirname(file), { recursive: true, force: true });
    }
  }));

test("r4 25: a push into the checkout itself asks once a hook is where its climbing hooks path leads (the build check's case E)", () =>
  fixture((r, g, session) => {
    commit(r);
    g("config", "core.hooksPath", "../hooks2");
    d.projectRoots(session);
    const command = "git push . HEAD:refs/heads/x";
    assert.equal(planFor(r, command).problem, undefined);
    write(path.join(r, "hooks2", "pre-receive"), HOOK, 0o755);
    const found = planFor(r, command).problem ?? "";
    assert.ok(found.includes(`has a pre-receive hook (${path.join(r, "hooks2", "pre-receive")})`), found);
  }));
