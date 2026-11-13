// Round 4, group C, fifth pass: the URL a git command names (finding 12), one walk per root with
// an allowed path inside the project (finding 30), git calls that go into submodules and cannot
// work in the sandbox, `PS4` in the sandboxed shell (finding 29), what the variant check of the
// third pass found (finding 21), and where a push goes in every spelling git takes. Each test
// builds a repository of its own under the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-fifth.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";
import { envKept, plan, Scan, walkCount, type Plan } from "../sandbox.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), `c-fifth-${name}-`)));
const gitIn = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const commit = (dir: string, message = "one") => gitIn(dir, "commit", "-q", "--allow-empty", "-m", message);

// An empty repository on `main` with a session that has seen it, removed afterwards; `g` runs
// git in it.
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
function sandboxed(p: Plan, command: string, cwd: string, extra: Record<string, string> = {}) {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  const env: Record<string, string | undefined> = { ...process.env, ...extra };
  delete env.NODE_TEST_CONTEXT;
  const { keep } = envKept(env, []);
  Object.assign(env, { AUTOMODE_ENV_KEEP: keep.join("\n"), AUTOMODE_SHELL: "/bin/bash", AUTOMODE_COMMAND: command, AUTOMODE_RW: p.rw.join("\n"), AUTOMODE_RO: p.ro.join("\n"), AUTOMODE_REOPEN: p.reopen.join("\n"), AUTOMODE_HIDE: p.hide.join("\n"), AUTOMODE_PIN: p.pin.join("\n"), AUTOMODE_TMPFS: p.tmpfs.join("\n") });
  return spawnSync(WRAPPER, ["-c", command], { cwd, env, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 120_000 });
}

const AGENT = /would need your ssh agent/;
const HELPER = /credential helper/;
const HTTPS = "https://example.invalid/team/x.git";
const SSH = "git@example.invalid:team/x.git";

// ---- the URL a git command names (finding 12, second bullet) ----

test("r4 12: a URL on the command line behind a credential helper scoped to it asks, whatever the project's remotes are", () =>
  fixture((r, g, session) =>
    withGlobal('[credential "https://private.invalid"]\n\thelper = store\n', () => {
      g("remote", "add", "origin", HTTPS);
      d.projectRoots(session);
      for (const command of [
        "git fetch https://private.invalid/o/private.git",
        "git fetch https://private.invalid/o/private.git main",
        "git pull https://private.invalid/o/private.git main",
        "git ls-remote https://private.invalid/o/private.git",
        "git ls-remote --heads https://private.invalid/o/private.git main",
        "git ls-remote -q --tags https://private.invalid/o/private.git | head -5",
        "git push https://private.invalid/o/private.git main",
        "git fetch -q --depth=1 https://private.invalid/o/private.git && git status",
      ]) {
        assert.match(d.sandboxBreaks(command, r, session) ?? "", HELPER, command);
      }
      // A host the helper is not for, and the project's own remote, are as before.
      for (const command of ["git fetch origin", "git ls-remote https://example.invalid/o/other.git", "git ls-remote origin", "git fetch https://example.invalid/o/other.git main"]) {
        assert.equal(d.sandboxBreaks(command, r, session), undefined, command);
      }
    }),
  ));

test("r4 12: an ssh URL on the command line, in a project whose remotes are https, asks for the agent it will not get", () =>
  fixture((r, g, session) => {
    g("remote", "add", "origin", HTTPS);
    d.projectRoots(session);
    for (const command of [
      "git ls-remote git@host.invalid:o/r.git",
      "git ls-remote host.invalid:o/r.git",
      "git ls-remote --symref ssh://git@host.invalid/o/r.git HEAD",
      "git fetch ssh://git@host.invalid/o/r.git",
      "git fetch git@host.invalid:o/r.git main",
      "git pull git@host.invalid:o/r.git main",
      "git push git@host.invalid:o/r.git main",
    ]) {
      assert.equal(d.usesSsh(command, r, session), false, command);
      assert.match(d.sandboxBreaks(command, r, session) ?? "", AGENT, command);
    }
  }));

test("r4 12: the remotes are read in the repository the call names, not in the session's project", () =>
  fixture((r, g, session) => {
    const sshChild = path.join(r, "ssh-child");
    const httpsChild = path.join(r, "https-child");
    execFileSync("git", ["init", "-q", "-b", "main", sshChild]);
    execFileSync("git", ["init", "-q", "-b", "main", httpsChild]);
    gitIn(sshChild, "remote", "add", "origin", SSH);
    gitIn(httpsChild, "remote", "add", "origin", HTTPS);
    // An https project: a call in the child whose remote is ssh needs the agent.
    g("remote", "add", "origin", HTTPS);
    d.projectRoots(session);
    for (const command of ["git -C ssh-child fetch", "cd ssh-child && git pull", "git -C ssh-child ls-remote origin", `git -C ${sshChild} fetch origin main`, "git -C ssh-child remote update"]) {
      assert.match(d.sandboxBreaks(command, r, session) ?? "", AGENT, command);
    }
    for (const command of ["git -C https-child fetch", "git fetch", "git fetch && git -C https-child fetch"]) assert.equal(d.sandboxBreaks(command, r, session), undefined, command);
  }));

test("r4 12: an ssh project does not make a call in an https repository ask", () =>
  fixture((r, g, session) => {
    const httpsChild = path.join(r, "https-child");
    execFileSync("git", ["init", "-q", "-b", "main", httpsChild]);
    gitIn(httpsChild, "remote", "add", "origin", HTTPS);
    g("remote", "add", "origin", SSH);
    d.projectRoots(session);
    for (const command of ["git -C https-child fetch", "git -C https-child fetch origin && git -C https-child status", "cd https-child && git pull origin main", "git ls-remote https://example.invalid/o/other.git"]) {
      assert.equal(d.sandboxBreaks(command, r, session), undefined, command);
    }
    // The project's own remote still needs the agent, which a call of two commands does not get.
    assert.match(d.sandboxBreaks("git fetch && git status", r, session) ?? "", AGENT);
    assert.equal(d.sandboxBreaks("git fetch", r, session), undefined, "a single plain fetch at the top of the project gets the agent");
  }));

test("r4 12: the remote git picks where none is named, a named one, every one, a group", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "origin", HTTPS);
    g("remote", "add", "up", SSH);
    g("remote", "add", "mirror", "https://mirror.invalid/team/x.git");
    d.projectRoots(session);
    const breaks = (command: string) => d.sandboxBreaks(`${command} && git status`, r, session);
    // No branch setting: `origin`.
    for (const command of ["git fetch", "git pull", "git fetch origin", "git fetch -q origin main", "git pull origin main", "git fetch --multiple origin mirror", "git remote update origin", "git remote prune origin mirror", "git push origin main", "git push"]) {
      assert.equal(breaks(command), undefined, command);
    }
    assert.equal(d.sandboxBreaks("git ls-remote | head -3", r, session), undefined);
    assert.equal(d.sandboxBreaks("git remote show origin | head -3", r, session), undefined);
    for (const command of ["git fetch up", "git pull up main", "git fetch --all", "git pull --all", "git fetch --multiple origin up", "git remote update", "git remote update up", "git remote prune up", "git push up main", "git push --repo up", "git push --repo=up"]) {
      assert.match(breaks(command) ?? "", AGENT, command);
    }
    assert.match(d.sandboxBreaks("git ls-remote up | head -3", r, session) ?? "", AGENT);
    assert.match(d.sandboxBreaks("git remote show up | head -3", r, session) ?? "", AGENT);
    // A group names remotes.
    g("config", "remotes.pair", "origin up");
    assert.match(breaks("git fetch pair") ?? "", AGENT);
    assert.match(breaks("git remote update pair") ?? "", AGENT);
    // The branch's own remote, then for a push its pushRemote and remote.pushDefault.
    g("config", "branch.main.remote", "up");
    for (const command of ["git fetch", "git pull"]) assert.match(breaks(command) ?? "", AGENT, command);
    assert.match(d.sandboxBreaks("git ls-remote | head -3", r, session) ?? "", AGENT);
    g("config", "remote.pushDefault", "origin");
    assert.equal(breaks("git push"), undefined);
    g("config", "branch.main.pushRemote", "up");
    assert.match(breaks("git push") ?? "", AGENT);
    // fetch.all makes a fetch with no remote contact every one.
    g("config", "branch.main.remote", "origin");
    assert.equal(breaks("git fetch"), undefined);
    g("config", "fetch.all", "true");
    assert.match(breaks("git fetch") ?? "", AGENT);
  }));

test("r4 12: a URL is judged as git rewrites it: insteadOf for both directions, pushInsteadOf for a push", () =>
  fixture((r, g, session) =>
    withGlobal('[url "ssh://git@rewritten.invalid/"]\n\tinsteadOf = https://plain.invalid/\n[url "git@pushed.invalid:"]\n\tpushInsteadOf = https://pushed.invalid/\n[url "https://example.invalid/"]\n\tinsteadOf = short:\n', () => {
      g("remote", "add", "origin", HTTPS);
      g("remote", "add", "pushed", "https://pushed.invalid/o/r.git");
      d.projectRoots(session);
      const breaks = (command: string) => d.sandboxBreaks(`${command} && git status`, r, session);
      assert.match(d.sandboxBreaks("git ls-remote https://plain.invalid/o/r.git", r, session) ?? "", AGENT);
      assert.match(breaks("git fetch https://plain.invalid/o/r.git main") ?? "", AGENT);
      assert.match(breaks("git push https://plain.invalid/o/r.git main") ?? "", AGENT);
      // pushInsteadOf rewrites what a push uses, by the remote's name or as a URL, and no fetch.
      assert.match(breaks("git push https://pushed.invalid/o/r.git main") ?? "", AGENT);
      assert.match(breaks("git push pushed main") ?? "", AGENT);
      assert.equal(breaks("git fetch https://pushed.invalid/o/r.git main"), undefined);
      assert.equal(breaks("git fetch pushed"), undefined);
      // A short form that names an https URL is that URL, not a host called `short`.
      assert.equal(d.sandboxBreaks("git ls-remote short:o/r.git", r, session), undefined);
    }),
  ));

test("r4 12: a credential helper in the named repository's own config counts, and one for another repository does not", () =>
  fixture((r, g, session) => {
    const child = path.join(r, "child");
    execFileSync("git", ["init", "-q", "-b", "main", child]);
    gitIn(child, "remote", "add", "origin", "https://child.invalid/o/r.git");
    gitIn(child, "config", "credential.https://child.invalid.helper", "store");
    g("remote", "add", "origin", "https://child.invalid/o/project.git");
    d.projectRoots(session);
    assert.match(d.sandboxBreaks("git -C child fetch", r, session) ?? "", HELPER);
    assert.match(d.sandboxBreaks("cd child && git ls-remote origin", r, session) ?? "", HELPER);
    assert.equal(d.sandboxBreaks("git fetch", r, session), undefined);
  }));

test("r4 12: a URL named outside any repository is judged with your own config", async () => {
  const plain = scratch("plain");
  try {
    await fixture((r, g, session) =>
      withGlobal('[credential "https://private.invalid"]\n\thelper = store\n', () => {
        d.projectRoots(session);
        assert.match(d.sandboxBreaks(`git -C ${plain} ls-remote https://private.invalid/o/r.git`, r, session) ?? "", HELPER);
        assert.match(d.sandboxBreaks(`cd ${plain} && git ls-remote git@host.invalid:o/r.git`, r, session) ?? "", AGENT);
        assert.equal(d.sandboxBreaks(`git -C ${plain} ls-remote https://example.invalid/o/r.git`, r, session), undefined);
        // No repository and no URL: git says so itself.
        assert.equal(d.sandboxBreaks(`git -C ${plain} fetch`, r, session), undefined);
      }),
    );
  } finally {
    fs.rmSync(plain, { recursive: true, force: true });
  }
});

test("r4 12: where the remote cannot be told, the call asks and says so", () =>
  fixture((r, g, session) => {
    g("remote", "add", "origin", HTTPS);
    d.projectRoots(session);
    for (const command of ["git fetch --frobnicate origin", "git pull --frobnicate origin", "git fetch --pr origin", "git ls-remote --frobnicate origin", "git ls-remote --s origin", "git push --frobnicate origin main"]) {
      assert.match(d.sandboxBreaks(command, r, session) ?? "", /cannot tell which remote/, command);
    }
  }));

// ---- one walk per root (finding 30) ----

test("r4 30: with an allowed path inside the project, a decision and its plan walk each root once", () =>
  fixture(async (r, g, session) => {
    const nested = path.join(r, "vendor", "allowed");
    fs.mkdirSync(nested, { recursive: true });
    execFileSync("git", ["init", "-q", path.join(nested, "repo")]);
    for (const allowedPaths of [[], [nested]]) {
      const own = new d.SessionState(r);
      try {
        await d.decideShell(guard(allowedPaths), own, r, "ls"); // the session's first call takes the snapshot
        walkCount.clear();
        const scan = new Scan(allowedPaths);
        const decision = await d.decideShell(guard(allowedPaths), own, r, "ls", undefined, scan);
        assert.equal(decision.effect, "allow", decision.reason);
        const p = plan({ ...opts(r), allowedPaths, gitWritable: false }, scan);
        assert.equal(p.problem, undefined);
        const counts = Object.fromEntries(walkCount);
        assert.equal(counts[r], 1, JSON.stringify(counts));
        for (const [root, n] of Object.entries(counts)) assert.equal(n, 1, `allowed paths ${JSON.stringify(allowedPaths)}: ${root} walked ${n} times`);
        // The repository inside the allowed path is protected either way.
        assert.ok(p.ro.includes(path.join(nested, "repo", ".git")));
      } finally {
        d.closeGitSnapshot(own);
      }
    }
    void g;
    void session;
  }));

test("r4 30: a repository that appears inside an allowed path in the project still pauses the session", () =>
  fixture(async (r) => {
    const nested = path.join(r, "vendor", "allowed");
    fs.mkdirSync(nested, { recursive: true });
    const own = new d.SessionState(r);
    try {
      assert.equal((await d.decideShell(guard([nested]), own, r, "ls")).effect, "allow");
      execFileSync("git", ["init", "-q", path.join(nested, "planted")]);
      const next = await d.decideShell(guard([nested]), own, r, "ls");
      assert.equal(next.effect, "ask");
      assert.ok(next.reason.includes(path.join(nested, "planted", ".git")), next.reason);
    } finally {
      d.closeGitSnapshot(own);
    }
  }));

// ---- git calls that go into submodules ----

const FILE = ["-c", "protocol.file.allow=always"];
// A project with the submodule `lib`, added for real from a repository beside it, and a branch
// `other` that records another commit of it. `inTree`: git keeps the submodule's git directory
// in its own work tree (`lib/.git` a directory) rather than under `.git/modules`.
async function withLib(inTree: boolean, fn: (r: string, session: d.SessionState, g: (...args: string[]) => string) => void | Promise<void>) {
  const upstream = scratch("lib-upstream");
  try {
    gitIn(upstream, "init", "-q", "-b", "main");
    commit(upstream, "lib one");
    await fixture(async (r, g, session) => {
      commit(r);
      if (inTree) execFileSync("git", ["clone", "-q", upstream, path.join(r, "lib")]);
      g(...FILE, "submodule", "add", "-q", upstream, "lib");
      g("commit", "-qm", "a submodule");
      assert.equal(fs.lstatSync(path.join(r, "lib", ".git")).isDirectory(), inTree);
      g("branch", "same");
      g("switch", "-q", "-c", "other");
      commit(path.join(r, "lib"), "lib two");
      g("commit", "-qam", "move the submodule");
      g("switch", "-q", "main");
      gitIn(path.join(r, "lib"), "checkout", "-q", "HEAD~1");
      d.projectRoots(session);
      await fn(r, session, g);
    });
  } finally {
    fs.rmSync(upstream, { recursive: true, force: true });
  }
}
const OUTSIDE = /an approved run happens outside the sandbox/;

for (const inTree of [false, true]) {
  const layout = inTree ? "a submodule kept in its own work tree" : "a submodule kept under .git/modules";
  test(`r4 21: a switch or checkout that would move ${layout} asks; one that moves none does not`, () =>
    withLib(inTree, (r, session, g) => {
      const breaks = (command: string) => d.sandboxBreaks(command, r, session);
      // Without recursion git leaves the submodule alone.
      for (const command of ["git switch other", "git checkout other", "git switch -c feature other"]) assert.equal(breaks(command), undefined, command);
      for (const command of ["git switch --recurse-submodules other", "git checkout --recurse-submodules other", "git switch --recurse-sub -c feature other", "git checkout --recurse-submodules -b feature other", "git switch --recurse-submodules --detach other", "git checkout --recurse-submodules other~0"]) {
        assert.match(breaks(command) ?? "", /submodule/, command);
        assert.match(breaks(command) ?? "", OUTSIDE, command);
      }
      // Nothing recorded for a submodule differs: nothing in it is touched.
      for (const command of ["git switch --recurse-submodules same", "git switch --recurse-submodules -c feature", "git checkout --recurse-submodules -b feature", "git checkout --recurse-submodules same", "git switch --recurse-submodules --detach", "git switch --recurse-submodules -c feature same"]) {
        assert.equal(breaks(command), undefined, command);
      }
      // Where the plugin cannot show that, it asks: a forced one, paths, a commit it cannot read.
      for (const command of ["git switch --recurse-submodules -f same", "git checkout --recurse-submodules same -- lib", "git switch --recurse-submodules nowhere", "git checkout --recurse-submodules --frobnicate same"]) {
        assert.match(breaks(command) ?? "", /submodule/, command);
      }
      // By config, and git's last word on the command line.
      g("config", "submodule.recurse", "true");
      for (const command of ["git switch other", "git checkout other", "git switch --no-recurse-submodules --recurse-submodules other"]) assert.match(breaks(command) ?? "", OUTSIDE, command);
      for (const command of ["git switch same", "git switch -c feature", "git checkout same", "git switch --no-recurse-submodules other", "git checkout --recurse-submodules --no-recurse-submodules other"]) {
        assert.equal(breaks(command), undefined, command);
      }
    }));
}

test("r4 21: a pull that updates submodules kept under .git/modules asks, by option and by submodule.recurse", () =>
  withLib(false, (r, session, g) => {
    const breaks = (command: string) => d.sandboxBreaks(command, r, session);
    for (const command of ["git pull --recurse-submodules", "git pull --recurse-submodules=yes", "git pull --recurse-submodules=on-demand", "git pull --rebase --recurse-sub", "git pull --no-recurse-submodules --recurse-submodules"]) {
      assert.match(breaks(command) ?? "", /submodule/, command);
      assert.match(breaks(command) ?? "", OUTSIDE, command);
      assert.match(breaks(command) ?? "", /--no-recurse-submodules/, command);
    }
    for (const command of ["git pull", "git pull --no-recurse-submodules", "git pull --recurse-submodules=no", "git pull --recurse-submodules --no-recurse-submodules", "git fetch --recurse-submodules"]) {
      assert.equal(breaks(command), undefined, command);
    }
    // fetch.recurseSubmodules is the fetch's alone: the pull updates nothing (run: xcheck/c5).
    g("config", "fetch.recurseSubmodules", "true");
    assert.equal(breaks("git pull"), undefined);
    g("config", "submodule.recurse", "true");
    assert.match(breaks("git pull") ?? "", OUTSIDE);
    assert.match(breaks("git pull --rebase origin main") ?? "", OUTSIDE);
    assert.equal(breaks("git pull --no-recurse-submodules"), undefined);
    assert.equal(breaks("git fetch"), undefined);
  }));

test("r4 21: a pull that updates a submodule kept in its own work tree works, so it does not ask", () =>
  withLib(true, (r, session, g) => {
    assert.equal(d.sandboxBreaks("git pull --recurse-submodules", r, session), undefined);
    g("config", "submodule.recurse", "true");
    assert.equal(d.sandboxBreaks("git pull", r, session), undefined);
  }));

test("r4 21: a repository with no cloned submodule is as before, recursion or not", () =>
  fixture((r, g, session) => {
    commit(r);
    g("branch", "other");
    g("config", "submodule.recurse", "true");
    d.projectRoots(session);
    for (const command of ["git pull", "git pull --recurse-submodules", "git switch other", "git checkout --recurse-submodules other"]) assert.equal(d.sandboxBreaks(command, r, session), undefined, command);
  }));

// ---- PS4 in the sandboxed shell (finding 29) ----

test("r4 29: PS0 to PS4 are not handed to a sandboxed shell, however short their value", () => {
  const env = Object.fromEntries(["PS0", "PS1", "PS2", "PS3", "PS4"].map((name) => [name, "+ "]));
  const { keep, dropped } = envKept({ ...env, PS5: "+ ", EDITOR: "vi" }, []);
  for (const name of Object.keys(env)) {
    assert.ok(dropped.includes(name), `${name} is dropped`);
    assert.ok(!keep.includes(name), `${name} is not kept`);
  }
  assert.ok(keep.includes("PS5") && keep.includes("EDITOR"));
  // Your own keepEnv overrides, as for every other name.
  assert.ok(envKept(env, ["PS4"]).keep.includes("PS4"));
});

// Round 4, finding 27 (a reviewer's point on the literal reading): bash imports a function from
// a variable named `BASH_FUNC_<name>%%`, and then `<name>` is that function wherever a command
// names it, whatever the rules take the word for.
test("r4 27: a function exported through the environment is not handed to a sandboxed shell", () => {
  const { keep, dropped } = envKept({ "BASH_FUNC_ls%%": "() { x=/; }", EDITOR: "vi" }, []);
  assert.ok(dropped.includes("BASH_FUNC_ls%%") && !keep.includes("BASH_FUNC_ls%%"));
  assert.ok(keep.includes("EDITOR"));
});

test("r4 29: an exported PS4 does not reach the shell the wrapper starts, so set -x expands nothing of it", () =>
  fixture((r) => {
    const p = plan({ ...opts(r), gitWritable: false });
    assert.equal(p.problem, undefined);
    // Twelve characters or fewer: a value that passed for "plainly not a secret".
    const ran = sandboxed(p, "set -x; : traced", r, { PS4: "$(touch m) " });
    assert.equal(ran.status, 0, ran.stderr);
    assert.equal(fs.existsSync(path.join(r, "m")), false, "the substitution in PS4 ran");
    assert.match(ran.stderr, /^\+ : traced$/m);
  }));

// ---- what the variant check of the third pass found (finding 21) ----

test("r4 21: a commondir in the main checkout that the user accepts by resuming is not reported again", () =>
  fixture((r, g, session) => {
    const resume = path.join(scratch("resume"), "resume");
    const file = path.join(r, ".git", "commondir");
    const touch = () => {
      fs.writeFileSync(resume, "");
      fs.utimesSync(resume, new Date(Date.now() + 5000), new Date(Date.now() + 5000));
    };
    try {
      d.projectRoots(session);
      assert.equal(d.gitTampered(session, resume), undefined);
      // The user's own, made between two calls.
      fs.writeFileSync(file, ".\n");
      assert.match(d.gitTampered(session, resume) ?? "", /\.git\/commondir appeared/);
      assert.match(d.gitTampered(session, resume) ?? "", /\.git\/commondir appeared/, "paused until resumed");
      touch();
      for (const check of ["first", "second", "third"]) assert.equal(d.gitTampered(session, resume), undefined, `the ${check} check after the resume`);
      // Taken away, there is nothing to name. (That it is new again when it comes back is held
      // in test/c-sixth.test.mts: here the resume file's time lies in the future, so a pause
      // after this point would be resumed by the next check.)
      fs.rmSync(file);
      assert.equal(d.gitTampered(session, resume), undefined);
      fs.writeFileSync(file, ".\n");
      assert.match(d.gitTampered(session) ?? "", /\.git\/commondir appeared/, "one that comes back is new again");
    } finally {
      fs.rmSync(path.dirname(resume), { recursive: true, force: true });
    }
    void g;
  }));

test("r4 21: a commondir in the main checkout when the session starts is reported once, and a resume takes it in", () =>
  fixture((r, g, session) => {
    const resume = path.join(scratch("resume"), "resume");
    try {
      fs.writeFileSync(path.join(r, ".git", "commondir"), ".\n");
      d.projectRoots(session);
      assert.match(d.gitTampered(session, resume) ?? "", /\.git\/commondir appeared/);
      fs.writeFileSync(resume, "");
      fs.utimesSync(resume, new Date(Date.now() + 5000), new Date(Date.now() + 5000));
      assert.equal(d.gitTampered(session, resume), undefined);
      assert.equal(d.gitTampered(session, resume), undefined);
    } finally {
      fs.rmSync(path.dirname(resume), { recursive: true, force: true });
    }
    void g;
  }));

test("r4 21: an approval whose command has finished explains nothing to the per-call check of another session", () =>
  fixture((r, g, session) => {
    const file = path.join(r, ".git", "config.worktree");
    const other = new d.SessionState(r);
    try {
      d.projectRoots(session);
      d.projectRoots(other);
      // The other session's approved `git sparse-checkout` is over, and that session is paused,
      // so its approval was never dropped.
      other.expecting.push({ dirs: [file], at: Date.now(), done: true });
      other.tampered = { reason: "something of its own", at: Date.now() };
      const call = d.noteGitCall(session, "git status", [path.join(r, ".git")])!;
      fs.writeFileSync(file, "[core]\n");
      assert.match(d.quarantineGitFiles(session, [session, other], call) ?? "", /config\.worktree appeared and was moved/);
      assert.equal(fs.existsSync(file), false);
      // One that is still running explains it, as before.
      session.tampered = undefined;
      other.expecting = [{ dirs: [file], at: Date.now() }];
      const next = d.noteGitCall(session, "git status", [path.join(r, ".git")])!;
      fs.writeFileSync(file, "[core]\n");
      assert.equal(d.quarantineGitFiles(session, [session, other], next), undefined);
      assert.ok(fs.existsSync(file));
    } finally {
      d.closeGitSnapshot(other);
    }
    void g;
  }));

test("r4 21: a linked worktree's admin directory that a call leaves behind is named by the next layout check", () =>
  fixture((r, g, session) => {
    commit(r);
    d.projectRoots(session);
    const call = d.noteGitCall(session, "git status", [path.join(r, ".git")])!;
    const admin = path.join(r, ".git", "worktrees", "evil");
    fs.mkdirSync(admin, { recursive: true });
    fs.writeFileSync(path.join(admin, "HEAD"), "ref: refs/heads/main\n");
    fs.writeFileSync(path.join(admin, "commondir"), "../..\n");
    fs.writeFileSync(path.join(admin, "gitdir"), `${path.join(r, "elsewhere", ".git")}\n`);
    // Not in the call's record (the directory was not there at its start): left where it is.
    assert.equal(d.quarantineGitFiles(session, [session], call), undefined);
    assert.ok(fs.existsSync(path.join(admin, "commondir")));
    assert.match(d.gitTampered(session) ?? "", /worktrees\/evil appeared/);
    void g;
  }));

test("r4 21: the main .git copied aside, removed and moved back pauses every one of twenty times", () =>
  fixture((r, g, session) => {
    const resume = path.join(scratch("resume"), "resume");
    const dotGit = path.join(r, ".git");
    try {
      commit(r);
      d.projectRoots(session);
      for (let i = 0; i < 20; i++) {
        assert.equal(d.gitTampered(session, resume), undefined, `before replacement ${i + 1}`);
        execFileSync("cp", ["-a", dotGit, `${dotGit}.aside`]);
        fs.rmSync(dotGit, { recursive: true });
        fs.renameSync(`${dotGit}.aside`, dotGit);
        assert.match(d.gitTampered(session, resume) ?? "", /\.git was replaced or rewritten/, `replacement ${i + 1}`);
        fs.writeFileSync(resume, "");
        fs.utimesSync(resume, new Date(Date.now() + 5000), new Date(Date.now() + 5000));
      }
    } finally {
      fs.rmSync(path.dirname(resume), { recursive: true, force: true });
    }
    void g;
  }));

test("r4 25: a hooks directory that cannot be listed counts as one whose hook would run: no agent for a push", () =>
  fixture((r, g, session) => {
    commit(r);
    g("remote", "add", "origin", SSH);
    d.projectRoots(session);
    assert.equal(d.usesSsh("git push", r, session), true);
    const hooks = path.join(r, ".git", "hooks");
    fs.mkdirSync(hooks, { recursive: true });
    fs.writeFileSync(path.join(hooks, "pre-push"), "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    fs.chmodSync(hooks, 0o311);
    try {
      assert.throws(() => fs.readdirSync(hooks), /EACCES/, "the test needs a user that mode 0311 keeps from listing");
      assert.equal(d.usesSsh("git push", r, session), false);
      assert.equal(d.usesSsh("git fetch", r, session), false);
    } finally {
      fs.chmodSync(hooks, 0o755);
    }
  }));

// ---- where a push goes (the options as git reads them) ----

test("r4 21: the remote of a push is the word git takes for it, in every spelling of its options", () =>
  fixture((r, g) => {
    commit(r);
    const bare = path.join(r, "bare.git");
    const second = path.join(r, "second.git");
    for (const dir of [bare, second]) execFileSync("git", ["init", "-q", "--bare", dir]);
    g("remote", "add", "origin", HTTPS);
    g("remote", "add", "both", HTTPS);
    g("remote", "set-url", "--add", "--push", "both", HTTPS);
    g("remote", "set-url", "--add", "--push", "both", bare);
    const to = (command: string) => d.pushDestinations(command, r);
    // A value attached to a shortened name, a value as the next word, clusters, `--no-` forms.
    assert.deepEqual(to(`git push --rep=${bare}`), [bare]);
    assert.deepEqual(to(`git push --rep ${bare}`), [bare]);
    assert.deepEqual(to("git push --repo both --no-repo"), []);
    assert.deepEqual(to(`git push --repo=${second} both main`), [bare], "the argument takes precedence over --repo");
    assert.deepEqual(to("git push -qo ci.skip both main"), [bare]);
    assert.deepEqual(to("git push -oci.skip -u both main"), [bare]);
    assert.deepEqual(to("git push --recurse-sub check both"), [bare]);
    assert.deepEqual(to("git push --no-verify --force-with-lease=main --no-thin --push-opt x both"), [bare]);
    assert.deepEqual(to("git push --signed=if-asked both"), [bare]);
    assert.deepEqual(to("git push -- both main"), [bare]);
    assert.deepEqual(to("git push both main -f"), [bare], "options may follow the operands");
    // An option git does not have, or a prefix of two: where the push goes cannot be told.
    for (const command of ["git push --frobnicate both", "git push --f both", "git push -Z both"]) assert.throws(() => to(command), /cannot tell which remote/, command);
  }));

test("r4 21: a push to a URL that pushInsteadOf rewrites to a repository on this machine is granted there, and works", () =>
  fixture(async (r, g, session) => {
    const allowed = scratch("allowed");
    try {
      commit(r);
      const store = path.join(allowed, "store.git");
      execFileSync("git", ["init", "-q", "--bare", store]);
      g("remote", "add", "stores", "https://stores.invalid/store.git");
      await withGlobal(`[url "${allowed}/"]\n\tpushInsteadOf = https://stores.invalid/\n`, () => {
        d.projectRoots(session);
        for (const command of ["git push https://stores.invalid/store.git HEAD:refs/heads/by-url", "git push stores HEAD:refs/heads/by-name", "git push --repo=https://stores.invalid/store.git"]) {
          assert.deepEqual(d.pushDestinations(command, r), [store], command);
        }
        // A fetch from the same URL is not rewritten: nothing here to grant, and no path.
        assert.deepEqual(d.pushDestinations("git fetch https://stores.invalid/store.git", r), []);
        const command = "git push https://stores.invalid/store.git HEAD:refs/heads/by-url";
        assert.equal(d.sandboxBreaks(command, r, session), undefined);
        const p = plan({ ...opts(r), allowedPaths: [allowed], gitCwds: d.gitDirectories(command, r), gitPushTo: d.pushDestinations(command, r) });
        assert.equal(p.problem, undefined);
        assert.ok(p.gitDirs.includes(store));
        // As in every git directory a call may write: its hooks and config stay read-only.
        for (const name of ["hooks", "config"]) assert.ok(p.ro.includes(path.join(store, name)), name);
        const planted = sandboxed(p, `echo planted > ${store}/hooks/post-receive`, r);
        assert.notEqual(planted.status, 0);
        assert.equal(fs.existsSync(path.join(store, "hooks", "post-receive")), false);
        const ran = sandboxed(p, command, r);
        assert.equal(ran.status, 0, ran.stderr);
        assert.equal(execFileSync("git", ["--git-dir", store, "rev-parse", "refs/heads/by-url"], { encoding: "utf8" }), g("rev-parse", "HEAD"));
      });
    } finally {
      fs.rmSync(allowed, { recursive: true, force: true });
    }
  }));
