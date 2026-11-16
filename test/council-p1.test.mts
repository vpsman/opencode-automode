// Council project review 1: bash's integer variables evaluate what they are given as arithmetic;
// a folded heredoc `cat` needs a `cat` on PATH; less and tar are on the safe list only where the
// environment hands them no program; the plugin's own git starts no transport (a lazy fetch ran a
// planted `uploadpack`); a directory with `HEAD` and `commondir` is a git directory.
// Run: node test/run.mjs test/council-p1.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideShell, SessionState, takeMoment, type Guard } from "../decide.ts";
import { gitRun, plan } from "../sandbox.ts";
SessionState.moment = takeMoment;
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

assert.ok(process.env.GIT_CONFIG_GLOBAL?.startsWith(os.homedir()), "run through test/run.mjs, which supplies a throwaway $HOME");
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), "council-p1-")));
const repo = path.join(base, "repo");
const guard: Guard = {
  rules: compileRules({ ask: DEFAULT_ASK }),
  guarded: [path.resolve(import.meta.dirname, "..")],
  configDirs: [path.join(os.homedir(), ".config", "opencode")],
  allowedPaths: [],
  classifier: DEFAULT_CLASSIFIER,
  useClassifier: false,
  sshHosts: [],
  allowFeatureBranchPush: false,
};

before(() => {
  fs.mkdirSync(repo, { recursive: true });
  fs.writeFileSync(path.join(repo, "f"), "x\n");
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  execFileSync("git", ["-C", repo, "add", "-A"]);
  execFileSync("git", ["-C", repo, "commit", "-qm", "init"]);
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

const effect = async (command: string, s = new SessionState(repo)) => (await decideShell(guard, s, repo, command)).effect;
const withEnv = async <T,>(vars: Record<string, string | undefined>, fn: () => Promise<T>): Promise<T> => {
  const before = Object.fromEntries(Object.keys(vars).map((k) => [k, process.env[k]]));
  for (const [k, v] of Object.entries(vars)) v === undefined ? delete process.env[k] : (process.env[k] = v);
  try {
    return await fn();
  } finally {
    for (const [k, v] of Object.entries(before)) v === undefined ? delete process.env[k] : (process.env[k] = v);
  }
};

test("a value given to one of bash's integer variables asks, however it is given", async () => {
  for (const name of ["RANDOM", "SRANDOM", "OPTIND", "HISTCMD", "SECONDS", "BASHPID", "BASH_XTRACEFD", "READLINE_MARK"]) {
    for (const c of [`${name}='a[$(id)]'`, `x='a[$(id)]'; ${name}=$x`, `${name}=$(cat f)`, `printf -v ${name} %s 'a[$(id)]'`, `for ${name} in 'a[$(id)]'; do :; done`, `git status; ${name}='x[$(id)]'`, `ls && ${name}=1`]) {
      assert.notEqual(await effect(c), "allow", c);
    }
  }
  // Reading one is as before.
  assert.equal(await effect("echo $RANDOM"), "allow");
});

test("a folded heredoc cat asks where PATH finds no cat at all", async () => {
  const command = `printf '%s\\n' "$(cat <<'EOF'\nhello\nEOF\n)"`;
  assert.equal(await effect(command), "allow");
  const empty = path.join(base, "no-cat");
  fs.mkdirSync(empty, { recursive: true });
  assert.notEqual(await withEnv({ PATH: empty }, () => effect(command)), "allow");
});

test("after a session write, less is on the safe list only where LESSOPEN and LESSCLOSE name no program a call can write", async () => {
  const wrote = async (vars: Record<string, string | undefined>) =>
    withEnv(vars, async () => {
      const s = new SessionState(repo);
      assert.equal(await effect("echo x > note.txt", s), "allow");
      return effect("less f", s);
    });
  assert.equal(await wrote({ LESSOPEN: undefined, LESSCLOSE: undefined }), "allow");
  assert.equal(await wrote({ LESSOPEN: "| /bin/cat %s", LESSCLOSE: undefined }), "allow");
  for (const value of ["|./lp %s", `|${repo}/lp %s`, "| lesspipe %s", "| /bin/cat %s; ./x", `|${os.tmpdir()}/lp %s`]) {
    assert.notEqual(await wrote({ LESSOPEN: value }), "allow", value);
    assert.notEqual(await wrote({ LESSOPEN: undefined, LESSCLOSE: value }), "allow", value);
  }
  // tar where your environment hands it options.
  const tar = async (value: string | undefined) =>
    withEnv({ TAR_OPTIONS: value }, async () => {
      const s = new SessionState(repo);
      await effect("echo x > note.txt", s);
      return effect("tar tf a.tar", s);
    });
  assert.equal(await tar(undefined), "allow");
  assert.notEqual(await tar("--to-command=./x"), "allow");
});

test("the plugin's own git starts no lazy fetch from a promisor remote a call wrote", () => {
  const bare = path.join(base, "promisor.git");
  const marker = path.join(base, "fetched");
  execFileSync("git", ["init", "-q", "--bare", bare]);
  fs.writeFileSync(path.join(bare, "config"), `[core]\n\trepositoryformatversion = 1\n\tbare = true\n[extensions]\n\tpartialClone = origin\n[remote "origin"]\n\turl = /dev/null\n\tpromisor = true\n\tuploadpack = "touch ${marker} #"\n`);
  const missing = "1111111111111111111111111111111111111111^{commit}";
  // Plain git runs it: the test is real.
  spawnSync("git", ["-C", bare, "rev-parse", "--verify", "-q", missing], { stdio: "ignore" });
  assert.ok(fs.existsSync(marker), "plain git lazy-fetches");
  fs.rmSync(marker);
  assert.notEqual(gitRun(["-C", bare, "rev-parse", "--verify", "-q", missing]).status, 0);
  assert.ok(!fs.existsSync(marker), "the plugin's git does not");
});

test("a directory with HEAD and commondir is a git directory to the layout check", async () => {
  const s = new SessionState(repo);
  try {
    for (const c of ["mkdir -p x y/objects y/refs/heads", "echo 'ref: refs/heads/main' > x/HEAD", "echo ../y > x/commondir"]) {
      assert.equal(await effect(c, s), "allow", c);
      execFileSync("bash", ["-c", c], { cwd: repo });
    }
    const next = await decideShell(guard, s, repo, "ls");
    assert.equal(next.effect, "ask");
    assert.match(next.reason, /x appeared/);
  } finally {
    fs.rmSync(path.join(repo, "x"), { recursive: true, force: true });
    fs.rmSync(path.join(repo, "y"), { recursive: true, force: true });
  }
});

// Round 2.
test("a variable set through a name built at run time asks", async () => {
  for (const c of [`x='RANDOM=a[$(id)]'; export "$x"`, `x='OPTIND=a[$(id)]'; declare "$x"`, `x=PATH=.; export "$x"; cat f`, `x=HOME=.; export "$x"; git status`, `f(){ local "$1"; }; f x`, `readonly "$x"`, `typeset "$x"`, "export ${x}", "export $(cat f)", `declare -x "$x"`, `export -- "$x"`]) {
    assert.notEqual(await effect(c), "allow", c);
  }
  assert.equal(await effect(`x=1; echo "$x"`), "allow");
});

test("after a session write, a variable of opencode's environment that names a place the session can write turns the safe list off", async () => {
  const after = async (vars: Record<string, string | undefined>, command: string) =>
    withEnv(vars, async () => {
      const s = new SessionState(repo);
      assert.equal(await effect("echo x > note.txt", s), "allow");
      return effect(command, s);
    });
  assert.equal(await after({ GIT_EXTERNAL_DIFF: undefined }, "git diff"), "allow");
  for (const [name, value] of [["GIT_EXTERNAL_DIFF", "./differ"], ["GIT_SSH_COMMAND", "./s"], ["EDITOR", `${repo}/e`], ["RIPGREP_CONFIG_PATH", "rc/x"], ["PAGER", `${os.tmpdir()}/p`], ["GIT_EXEC_PATH", repo]]) {
    assert.notEqual(await after({ [name]: value }, "git diff"), "allow", name);
  }
  assert.equal(await after({ EDITOR: "vi", PAGER: "/usr/bin/less -R" }, "git diff"), "allow");
});

test("the plugin's own git status runs no filter a repository's own config names, unless it is a known one", async () => {
  const r = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp1-filter-")));
  const marker = path.join(base, "filtered");
  try {
    execFileSync("git", ["init", "-q", "-b", "main", r]);
    fs.writeFileSync(path.join(r, "payload"), `Host h0st\n  ProxyCommand touch ${marker}\n`);
    execFileSync("git", ["-C", r, "add", "payload"]);
    execFileSync("git", ["-C", r, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "x"]);
    fs.writeFileSync(path.join(r, ".git", "info", "attributes"), "payload filter=x\n");
    execFileSync("git", ["-C", r, "config", "filter.x.clean", "ssh -F %f h0st"]);
    // An index without the files' times: status hashes each file through its filter.
    execFileSync("git", ["-C", r, "read-tree", "HEAD"]);
    spawnSync("git", ["-C", r, "status", "--porcelain"], { stdio: "ignore" });
    assert.ok(fs.existsSync(marker), "plain git status runs the filter: the test is real");
    fs.rmSync(marker);
    execFileSync("git", ["-C", r, "read-tree", "HEAD"]);
    for (const c of [`git -C ${r} checkout main`, `git -C ${r} switch main`, `git -C ${r} checkout -- payload`]) {
      await effect(c);
      assert.ok(!fs.existsSync(marker), c);
    }
  } finally {
    fs.rmSync(r, { recursive: true, force: true });
  }
});

test("the code caches include v8-compile-cache's and Jest's, and NODE_COMPILE_CACHE where it lies in a writable place", async () => {
  const moved = path.join(repo, "cc");
  const p = await withEnv({ NODE_COMPILE_CACHE: moved }, async () => plan({ projectRoots: [repo], allowedPaths: [], cacheDirs: [], gitWritable: false, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [], project: repo }));
  const uid = process.getuid!();
  for (const name of [`v8-compile-cache-${uid}`, `jest_${uid.toString(36)}`]) assert.ok(p.tmpfs.includes(path.join(fs.realpathSync(os.tmpdir()), name)), name);
  assert.ok(p.tmpfs.includes(moved), "NODE_COMPILE_CACHE");
  const relative = await withEnv({ NODE_COMPILE_CACHE: "cc" }, async () => plan({ projectRoots: [repo], allowedPaths: [], cacheDirs: [], gitWritable: false, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [], project: repo }));
  assert.match(relative.problem ?? "", /NODE_COMPILE_CACHE/);
  fs.rmSync(moved, { recursive: true, force: true });
});

// Round 3.
test("more values of opencode's environment that name a place the session can write", async () => {
  const after = async (vars: Record<string, string | undefined>, command: string) =>
    withEnv(vars, async () => {
      const s = new SessionState(repo);
      assert.equal(await effect("echo x > note.txt", s), "allow");
      return effect(command, s);
    });
  for (const [vars, command] of [
    [{ RIPGREP_CONFIG_PATH: "rgconfig" }, "rg x f"],
    [{ GIT_EXTERNAL_DIFF: "sh helper" }, "git diff"],
    [{ GIT_EDITOR: "sh x.sh" }, "git diff"],
    [{ LESS: "--lesskey-src=keys" }, "less f"],
    [{ LESSKEYIN: "keys" }, "less f"],
    [{ GIT_PROXY_COMMAND: "./proxy" }, "git diff"],
  ] as [Record<string, string>, string][]) {
    assert.notEqual(await after(vars, command), "allow", JSON.stringify(vars));
  }
  assert.equal(await after({ GIT_EXTERNAL_DIFF: "difft", LESS: "-R", PAGER: "less -FRX" }, "git diff"), "allow");
});

test("less with a lesskey option is off the safe list after a session write", async () => {
  for (const c of ["less --lesskey-src=keys f", "less '--lesskey-content=#env;LESSOPEN=|sh t.sh %s' f", "less -k keys f", "less --lessk=keys f"]) {
    const s = new SessionState(repo);
    assert.equal(await effect("echo x > note.txt", s), "allow");
    assert.notEqual(await effect(c, s), "allow", c);
  }
});

test("git writes of the work tree the record missed, and uniq's stdin operand", async () => {
  execFileSync("git", ["-C", repo, "branch", "-f", "incoming"]);
  for (const writer of ["git stash", "git checkout -bnb incoming", "git checkout -qbnb incoming", "git switch -cabc incoming", "git bisect broken incoming", "printf x | uniq - test.js"]) {
    const s = new SessionState(repo);
    await effect(writer, s);
    assert.notEqual(await effect("npm test", s), "allow", writer);
  }
  // A new branch at HEAD writes nothing, as before.
  const s = new SessionState(repo);
  assert.equal(await effect("git checkout -b nb", s), "allow");
  assert.equal(await effect("npm test", s), "allow");
});

test("NODE_COMPILE_CACHE that is a writable root itself is a problem", async () => {
  const p = await withEnv({ NODE_COMPILE_CACHE: "/tmp" }, async () => plan({ projectRoots: [repo], allowedPaths: [], cacheDirs: [], gitWritable: false, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [], project: repo }));
  assert.match(p.problem ?? "", /NODE_COMPILE_CACHE/);
});
