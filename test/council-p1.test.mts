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
import { gitRun } from "../sandbox.ts";
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
  for (const name of ["RANDOM", "SRANDOM", "OPTIND", "HISTCMD", "BASH_XTRACEFD", "READLINE_MARK"]) {
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
