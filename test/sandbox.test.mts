// Sandbox regression tests: the plan comes from sandbox.ts exactly as the plugin builds it, and
// commands run through sandbox/bin/bash the way opencode runs a swapped shell.
// Needs `npm run build:sandbox` first. Run: npm test (test/run.mjs supplies a throwaway $HOME).
//
// A test that says "cannot" checks two things: that the command ran (its last word is printed)
// and that the thing did not happen. A command that never started proves nothing.
import { spawn, spawnSync, execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { after, afterEach, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import * as sandbox from "../sandbox.ts";
import { gitOnly, usesSsh, SessionState } from "../decide.ts";

const { plan } = sandbox;
const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
// Lists reach lockwrite newline-separated.
const SEP = "\n";
const within = (p: string, dir: string) => p === dir || p.startsWith(dir + "/");
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-sbx-")));
const repo = path.join(tmp, "repo");
const home = os.homedir();
const runtime = process.env.XDG_RUNTIME_DIR!;
const cover = path.join(home, "empty-cover");
const outside = path.join(home, "outside.txt");
const abi = Number(/ABI (\d+)/.exec(execFileSync(path.join(ROOT, "sandbox", "lockwrite"), ["--selftest"], { encoding: "utf8" }))?.[1] ?? 0);

assert.ok(process.env.GIT_CONFIG_GLOBAL?.startsWith(home) && !home.startsWith("/tmp"), "run through `npm test` (test/run.mjs), which supplies a throwaway $HOME");

interface RunOptions {
  input?: string;
  extraFds?: number[];
  gitWritable?: boolean;
  env?: Record<string, string>;
  cacheDirs?: string[];
}
const planFor = (command: string, o: RunOptions = {}) =>
  plan({ projectRoots: [repo], allowedPaths: [], cacheDirs: o.cacheDirs ?? [], gitWritable: o.gitWritable ?? gitOnly(command), exposeSsh: usesSsh(command, repo, new SessionState(repo)), keepSockets: [], showPaths: [], hidePaths: [], project: repo });

function run(command: string, o: RunOptions = {}) {
  const p = planFor(command, o);
  assert.equal(p.problem, undefined);
  const env = {
    ...process.env,
    AUTOMODE_SHELL: "/bin/bash",
    AUTOMODE_RW: p.rw.join(SEP),
    AUTOMODE_RO: p.ro.join(SEP),
    AUTOMODE_HIDE: p.hide.join(SEP),
    AUTOMODE_PIN: p.pin.join(SEP),
    AUTOMODE_TMPFS: p.tmpfs.join(SEP),
    AUTOMODE_COVER: cover,
    ...o.env,
  };
  const r = spawnSync(WRAPPER, ["-c", command], { cwd: repo, env, input: o.input ?? "", encoding: "utf8", timeout: 30_000, stdio: ["pipe", "pipe", "pipe", ...(o.extraFds ?? [])] });
  return { status: r.status, out: (r.stdout ?? "") + (r.stderr ?? ""), stdout: r.stdout ?? "", plan: p };
}
// Runs `command; echo ran`, and fails unless it got that far.
function attempt(command: string, o: RunOptions = {}) {
  const r = run(`${command}; echo ran`, o);
  assert.match(r.stdout, /ran\n$/, `the command did not run: ${r.out}`);
  return r;
}
const git = (...args: string[]) => execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" });
const listen = (file: string) =>
  new Promise<net.Server>((resolve) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const server = net.createServer().listen(file, () => resolve(server));
  });

before(() => {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  execFileSync("git", ["init", "-q", repo]);
  fs.writeFileSync(cover, "", { mode: 0o400 });
  fs.writeFileSync(outside, "untouched\n", { mode: 0o644 });
});
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

describe("normal work inside the project", () => {
  test("writes work for ordinary commands", () => {
    const r = run("echo x > f && cat f");
    assert.equal(r.status, 0, r.out);
  });
  test("a git-only call can add and commit", () => {
    const r = run("git add f && git -c user.name=t -c user.email=t@t commit -qm m");
    assert.equal(r.status, 0, r.out);
    assert.match(git("log", "--oneline"), /m/);
  });
  test("stdin, stdout and the exit code pass through", () => {
    const r = run("cat; exit 7", { input: "piped-in\n" });
    assert.equal(r.status, 7);
    assert.match(r.out, /piped-in/);
  });
  test("a command killed by a signal reports it", () => assert.equal(run("kill -KILL $$").status, 137));
  test("the shell starts with default signal handling (SIGPIPE ends a writer whose reader left)", () => {
    assert.equal(run("yes | head -n 1 >/dev/null; echo ${PIPESTATUS[0]}").out.trim(), "141");
  });
  test("AUTOMODE_* variables do not reach the command", () => {
    assert.equal(run("env | grep -c '^AUTOMODE_' || true").out.trim(), "0");
  });
  test("/dev/shm is private and writable; /dev/null works", () => {
    const r = run("echo x > /dev/shm/automode-test && cat /dev/shm/automode-test && echo y > /dev/null && echo ok");
    assert.match(r.out, /ok/);
    assert.ok(!fs.existsSync("/dev/shm/automode-test"));
  });
  test("temp directories stay writable", () => {
    const r = run(`echo x > ${tmp}/t && cat ${tmp}/t`);
    assert.equal(r.out.trim(), "x");
  });
});

describe("containment", () => {
  test("cannot write outside the writable directories, from the shell or a child", () => {
    const probe = path.join(home, "probe");
    const r = attempt(`echo x > ${probe}; python3 -c "open('${probe}','w')"; bash -c 'touch ${probe}'`);
    assert.ok(!fs.existsSync(probe), r.out);
    assert.match(r.out, /Permission denied|Read-only file system/);
  });
  test("cannot create files in /dev (K4)", () => {
    const r = attempt("touch /dev/automode-test");
    assert.match(r.out, /Permission denied|Read-only file system/);
    assert.ok(!fs.existsSync("/dev/automode-test"));
  });
  test("cannot plant a git hook", () => {
    const r = attempt("echo 'touch /tmp/pwned' > .git/hooks/pre-push; chmod +x .git/hooks/pre-push");
    assert.match(r.out, /Read-only file system/);
    assert.ok(!fs.existsSync(path.join(repo, ".git/hooks/pre-push")));
  });
  test("cannot change .git/config", () => {
    attempt("git config core.hooksPath /tmp/evil; echo '[core]' >> .git/config");
    assert.ok(!/hooksPath|evil/.test(fs.readFileSync(path.join(repo, ".git/config"), "utf8")));
  });
  test("cannot rename or replace .git", () => {
    attempt("mv .git .git.old && cp -a .git.old .git && touch .git/hooks/x");
    assert.ok(!fs.existsSync(path.join(repo, ".git.old")));
    assert.ok(!fs.existsSync(path.join(repo, ".git/hooks/x")));
  });
  test("cannot rename a parent of a nested repository", () => {
    execFileSync("git", ["init", "-q", path.join(repo, "vendor", "lib")]);
    try {
      attempt("mv vendor vendor2; mv vendor/lib vendor/lib2");
      assert.ok(fs.existsSync(path.join(repo, "vendor", "lib", ".git")));
      assert.ok(!fs.existsSync(path.join(repo, "vendor2")));
    } finally {
      fs.rmSync(path.join(repo, "vendor"), { recursive: true, force: true });
    }
  });
  test("cannot plant .git/commondir", () => {
    attempt("echo /tmp > .git/commondir");
    assert.ok(!fs.existsSync(path.join(repo, ".git/commondir")));
  });
  test("cannot undo the read-only mounts", () => {
    const r = attempt("umount .git/hooks 2>&1; mount --bind /tmp .git/hooks 2>&1; echo x > .git/hooks/x 2>&1");
    assert.ok(!fs.existsSync(path.join(repo, ".git/hooks/x")), r.out);
  });
  test("cannot signal processes outside the sandbox", () => {
    const victim = spawn("sleep", ["30"]);
    try {
      const r = attempt(`kill -TERM ${victim.pid} 2>&1`);
      assert.match(r.out, /Operation not permitted|No such process/);
      assert.equal(victim.exitCode, null);
    } finally {
      victim.kill();
    }
  });
  test("cannot reach another process's filesystem view through /proc", () => {
    assert.match(attempt(`ls /proc/${process.pid}/root/ 2>&1 | head -1`).out, /Permission denied|No such file/);
  });
  test("inherited file descriptors are closed before the command runs", () => {
    const fd = fs.openSync(repo, "r");
    try {
      assert.match(run("[ -e /proc/self/fd/3 ] && echo OPEN || echo closed", { extraFds: [fd] }).out, /closed/);
    } finally {
      fs.closeSync(fd);
    }
  });
});

describe("K2: a git-only call may write in .git, but not its hooks or config", () => {
  // The plan a pure git command gets, with a command that stands for code such a call runs
  // (an existing hook, a filter): no redirect in the tool call itself is involved.
  const inGit = (command: string) => attempt(command, { gitWritable: true });
  test("the mode is in force: ordinary files in .git can be written", () => {
    inGit("touch .git/automode-marker");
    assert.ok(fs.existsSync(path.join(repo, ".git/automode-marker")));
    fs.rmSync(path.join(repo, ".git/automode-marker"));
  });
  test("cannot plant a hook", () => {
    assert.match(inGit("echo x > .git/hooks/pre-commit").out, /Read-only file system/);
    assert.ok(!fs.existsSync(path.join(repo, ".git/hooks/pre-commit")));
  });
  test("cannot change config", () => {
    inGit("echo '[core]\n\tfsmonitor = /tmp/x' >> .git/config; git config core.fsmonitor /tmp/x");
    assert.ok(!/fsmonitor/.test(fs.readFileSync(path.join(repo, ".git/config"), "utf8")));
  });
  test("cannot rename .git or its hooks", () => {
    inGit("mv .git .git2; mv .git/hooks .git/hooks2");
    assert.ok(fs.existsSync(path.join(repo, ".git/hooks")) && !fs.existsSync(path.join(repo, ".git2")) && !fs.existsSync(path.join(repo, ".git/hooks2")));
  });
  test("cannot plant hooks in a core.hooksPath directory", () => {
    git("config", "core.hooksPath", "tools/hooks");
    try {
      inGit("mkdir -p tools/hooks && echo x > tools/hooks/pre-commit");
      assert.ok(!fs.existsSync(path.join(repo, "tools/hooks/pre-commit")));
    } finally {
      git("config", "--unset", "core.hooksPath");
      fs.rmSync(path.join(repo, "tools"), { recursive: true, force: true });
    }
  });
});

describe("C: protections tied to a path", () => {
  test("C1: a parent of core.hooksPath cannot be renamed and rebuilt", () => {
    git("config", "core.hooksPath", "tools/h/_");
    try {
      const r = attempt("mv tools tools2; mkdir -p tools/h/_; echo x > tools/h/_/pre-commit");
      assert.ok(!fs.existsSync(path.join(repo, "tools2")), r.out);
      assert.ok(!fs.existsSync(path.join(repo, "tools/h/_/pre-commit")), r.out);
    } finally {
      git("config", "--unset", "core.hooksPath");
      fs.rmSync(path.join(repo, "tools"), { recursive: true, force: true });
    }
  });
  test("C2: the directory of a hidden socket cannot be moved out of sight", async () => {
    const dir = path.join(tmp, "agent-dir");
    const server = await listen(path.join(dir, "agent.sock"));
    try {
      const r = attempt(`mv ${dir} ${tmp}/moved; test -S ${dir}/agent.sock && echo VISIBLE; test -S ${tmp}/moved/agent.sock && echo VISIBLE`);
      assert.ok(r.plan.hide.includes(path.join(dir, "agent.sock")));
      assert.ok(fs.existsSync(dir) && !fs.existsSync(path.join(tmp, "moved")), r.out);
      assert.doesNotMatch(r.out, /VISIBLE/);
    } finally {
      server.close();
    }
  });
  test("C3: a relative global core.hooksPath is protected in the worktree", () => {
    const global = process.env.GIT_CONFIG_GLOBAL!;
    execFileSync("git", ["config", "--file", global, "core.hooksPath", ".githooks"]);
    try {
      const r = attempt("mkdir -p .githooks; echo x > .githooks/pre-commit");
      assert.ok(r.plan.ro.includes(path.join(repo, ".githooks")), JSON.stringify(r.plan.ro));
      assert.ok(!fs.existsSync(path.join(repo, ".githooks/pre-commit")), r.out);
    } finally {
      execFileSync("git", ["config", "--file", global, "--unset", "core.hooksPath"]);
      fs.rmSync(path.join(repo, ".githooks"), { recursive: true, force: true });
    }
  });
  test("C4: a file .git/config includes cannot be changed", () => {
    fs.writeFileSync(path.join(repo, "shared.gitconfig"), "[core]\n\tabbrev = 12\n");
    git("config", "include.path", "../shared.gitconfig");
    try {
      const r = attempt("echo '[core]\n\tfsmonitor = /tmp/x' >> shared.gitconfig");
      assert.match(r.out, /Read-only file system/);
      assert.ok(!/fsmonitor/.test(fs.readFileSync(path.join(repo, "shared.gitconfig"), "utf8")));
    } finally {
      git("config", "--unset", "include.path");
      fs.rmSync(path.join(repo, "shared.gitconfig"));
    }
  });
  test("C4: an include that does not exist yet inside the project cannot be protected, so the command asks", () => {
    git("config", "includeIf.onbranch:x.path", "../later.gitconfig");
    try {
      assert.match(planFor("ls").problem ?? "", /includes .*later\.gitconfig/);
    } finally {
      git("config", "--unset", "includeIf.onbranch:x.path");
    }
  });
  test("C6: a repository four levels below a temp directory is found", () => {
    const deep = path.join(tmp, "a", "b", "c");
    execFileSync("git", ["init", "-q", deep]);
    try {
      const r = attempt(`echo x > ${deep}/.git/hooks/pre-commit; mv ${tmp}/a ${tmp}/a2`);
      assert.ok(!fs.existsSync(path.join(deep, ".git/hooks/pre-commit")) && !fs.existsSync(path.join(tmp, "a2")), r.out);
    } finally {
      fs.rmSync(path.join(tmp, "a"), { recursive: true, force: true });
    }
  });
  test("C8: a core.hooksPath that leads through a symlink is not created outside the project, and asks", () => {
    const target = path.join(home, "symlink-target");
    fs.mkdirSync(target);
    fs.symlinkSync(target, path.join(repo, "link"));
    git("config", "core.hooksPath", "link/hooks");
    try {
      const p = planFor("ls");
      assert.ok(!fs.existsSync(path.join(target, "hooks")), "the plugin created a directory outside the project");
      // The symlink itself sits in the project and could be swapped for a directory: nothing
      // can protect that, so the command asks.
      assert.match(p.problem ?? "", /core\.hooksPath .* could not be created safely|symbolic link/);
    } finally {
      git("config", "--unset", "core.hooksPath");
      fs.rmSync(path.join(repo, "link"));
      fs.rmSync(target, { recursive: true });
    }
  });
  test("C9: hook-manager files are read-only", () => {
    fs.mkdirSync(path.join(repo, ".husky"));
    fs.writeFileSync(path.join(repo, ".husky", "pre-commit"), "npm test\n");
    fs.writeFileSync(path.join(repo, "lefthook.yml"), "pre-commit:\n");
    fs.writeFileSync(path.join(repo, ".pre-commit-config.yaml"), "repos: []\n");
    try {
      const r = attempt("echo evil >> .husky/pre-commit; echo evil > .husky/pre-push; echo evil >> lefthook.yml; echo evil >> .pre-commit-config.yaml; mv .husky .husky2");
      for (const f of [".husky/pre-commit", "lefthook.yml", ".pre-commit-config.yaml"]) assert.ok(!/evil/.test(fs.readFileSync(path.join(repo, f), "utf8")), f);
      assert.ok(!fs.existsSync(path.join(repo, ".husky/pre-push")) && !fs.existsSync(path.join(repo, ".husky2")), r.out);
    } finally {
      for (const f of [".husky", "lefthook.yml", ".pre-commit-config.yaml"]) fs.rmSync(path.join(repo, f), { recursive: true, force: true });
    }
  });
  test("J1: opencode's project config is read-only, and .opencode cannot be created later", () => {
    fs.writeFileSync(path.join(repo, "opencode.json"), "{}\n");
    try {
      const r = attempt("echo '{\"plugins\":[\"./x.ts\"]}' > opencode.json; mkdir -p .opencode/plugin; echo x > .opencode/plugin/x.ts; mv .opencode .oc2");
      assert.equal(fs.readFileSync(path.join(repo, "opencode.json"), "utf8"), "{}\n", r.out);
      assert.deepEqual(fs.readdirSync(path.join(repo, ".opencode")), [], r.out);
      assert.ok(!fs.existsSync(path.join(repo, ".oc2")));
    } finally {
      fs.rmSync(path.join(repo, "opencode.json"));
    }
  });
});

describe("D: build caches are read-only unless listed", () => {
  const caches = [".cargo/registry", ".cargo/git", ".npm/_cacache", ".cache/go-build", ".local/share/pnpm/store", ".gradle/caches", ".m2/repository", ".bun/install/cache", ".cache/pip/http"].map((p) => path.join(home, p));
  before(() => caches.forEach((d) => fs.mkdirSync(d, { recursive: true })));
  test("D1: no cache directory is writable by default", () => {
    assert.deepEqual(sandbox.DEFAULT_CACHE_DIRS, []);
    const r = attempt(caches.map((d) => `touch ${d}/planted`).join("; "), { cacheDirs: sandbox.DEFAULT_CACHE_DIRS });
    for (const d of caches) assert.ok(!fs.existsSync(path.join(d, "planted")), d);
    assert.match(r.out, /Read-only file system|Permission denied/);
  });
  test("sandboxWritable opts a directory in", () => {
    attempt(`touch ${caches[2]}/ok`, { cacheDirs: [caches[2]] });
    assert.ok(fs.existsSync(path.join(caches[2], "ok")));
  });
});

describe("F: lockwrite", () => {
  test("F1: a kernel without Landlock ABI 5 runs nothing", () => {
    for (const fake of ["1", "2", "4"]) {
      const r = run(`touch ${tmp}/ran-on-abi-${fake}`, { env: { AUTOMODE_FAKE_ABI: fake } });
      assert.equal(r.status, 126, r.out);
      assert.ok(!fs.existsSync(path.join(tmp, `ran-on-abi-${fake}`)));
    }
  });
  test("F1: truncate outside the writable directories fails", () => {
    const r = attempt(`truncate -s 0 ${outside}; python3 -c "import os; os.truncate('${outside}', 0)"`);
    assert.equal(fs.readFileSync(outside, "utf8"), "untouched\n", r.out);
  });
  test("F2: chmod, utime and setxattr outside the writable directories fail", () => {
    const beforeStat = fs.statSync(outside);
    const r = attempt(`chmod 600 ${outside}; touch -d 2001-01-01 ${outside}; python3 -c "import os; os.setxattr('${outside}', 'user.automode', b'x')"`);
    const afterStat = fs.statSync(outside);
    assert.equal(afterStat.mode, beforeStat.mode, r.out);
    assert.equal(afterStat.mtimeMs, beforeStat.mtimeMs, r.out);
    assert.match(r.out, /Read-only file system/);
    assert.throws(() => execFileSync("python3", ["-c", `import os; os.getxattr('${outside}', 'user.automode')`], { stdio: "ignore" }));
  });
  test("F3: terminals are not writable and device ioctls are denied", () => {
    const p = planFor("ls");
    for (const dev of ["/dev/tty", "/dev/ptmx", "/dev/pts"]) assert.ok(!p.rw.includes(dev), dev);
    const r = attempt(`python3 -c "
import fcntl, os, termios
for dev in ('/dev/ptmx', '/dev/tty', '/dev/null'):
    try:
        fd = os.open(dev, os.O_RDWR if dev != '/dev/null' else os.O_RDONLY)
    except OSError as e:
        print(dev, 'open:', e.strerror); continue
    try:
        fcntl.ioctl(fd, termios.TIOCGWINSZ, b'0' * 8); print(dev, 'IOCTL-WORKED')
    except OSError as e:
        print(dev, 'ioctl:', e.strerror)
"`);
    assert.match(r.out, /\/dev\/ptmx open: Permission denied/);
    assert.match(r.out, /\/dev\/null ioctl: Permission denied/);
    assert.doesNotMatch(r.out, /IOCTL-WORKED/);
  });
  test("F5: a background process does not outlive the tool call", async () => {
    const r = run("(sleep 31337 >/dev/null 2>&1 &) ; (setsid nohup sleep 31338 >/dev/null 2>&1 &) ; sleep 0.2; echo started");
    assert.match(r.out, /started/);
    await new Promise((resolve) => setTimeout(resolve, 300));
    const left = spawnSync("pgrep", ["-f", "^sleep 3133[78]$"], { encoding: "utf8" }).stdout.trim();
    if (left) spawnSync("pkill", ["-f", "^sleep 3133[78]$"]);
    assert.equal(left, "", "background processes survived the tool call");
  });
  test("I3: with a keep list, no other variable reaches the command", () => {
    const r = run("echo [$KEPT][$DATABASE_URL][$INHERITED]", { env: { AUTOMODE_ENV_KEEP: ["PATH", "HOME", "KEPT"].join("\n"), KEPT: "yes", DATABASE_URL: "postgres://u:p@h/db", INHERITED: "x" } });
    assert.equal(r.out.trim(), "[yes][][]");
  });
});

describe("H8/I: what is hidden", () => {
  test("H8: a socket with ':' in its name is hidden like any other", async () => {
    const file = path.join(tmp, "cm", "git@example.invalid:22");
    const server = await listen(file);
    try {
      const r = attempt(`test -S '${file}' && echo VISIBLE`);
      assert.ok(r.plan.hide.includes(file));
      assert.doesNotMatch(r.out, /VISIBLE/);
    } finally {
      server.close();
    }
  });
  test("I1: every socket in the runtime directory is hidden, D-Bus and the systemd manager included", async () => {
    const servers = await Promise.all(["bus", "systemd/private", "some-tool/ipc.sock"].map((n) => listen(path.join(runtime, n))));
    try {
      const r = attempt(`find ${runtime} -type s | grep -c . ; ls -A ${runtime} | wc -l`);
      assert.match(r.stdout, /^0\n0\nran/);
    } finally {
      servers.forEach((s) => s.close());
    }
  });
  const systemBus = "/run/dbus/system_bus_socket";
  test("I1: the system D-Bus socket is hidden", { skip: !fs.existsSync(systemBus) && "no system bus on this machine" }, () => {
    assert.match(attempt(`test -S ${systemBus} && echo VISIBLE || echo hidden`).out, /hidden/);
  });
  test("I1: git's credential-cache socket is hidden, and display variables are dropped", async () => {
    const server = await listen(path.join(home, ".cache", "git", "credential", "socket"));
    try {
      assert.match(attempt(`test -S ${home}/.cache/git/credential/socket && echo VISIBLE || echo hidden`).out, /hidden/);
    } finally {
      server.close();
    }
    const { keep, dropped } = sandbox.envKept({ DISPLAY: ":0", XAUTHORITY: "/x", WAYLAND_DISPLAY: "wayland-0", DBUS_SESSION_BUS_ADDRESS: "unix:path=/x", PATH: "/usr/bin" }, []);
    assert.deepEqual(dropped.sort(), ["DBUS_SESSION_BUS_ADDRESS", "DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY"]);
    assert.ok(keep.includes("PATH"));
  });
  test("I2: credential files the old list missed are hidden", () => {
    const files = [".config/git/credentials", ".config/glab-cli/config.yml", ".config/github-copilot/hosts.json", ".config/op/config", ".local/share/keyrings/login.keyring", ".bash_history", ".zsh_history", ".m2/settings.xml"];
    for (const f of files) {
      fs.mkdirSync(path.dirname(path.join(home, f)), { recursive: true });
      fs.writeFileSync(path.join(home, f), "SECRET-CONTENT\n");
    }
    const r = attempt(files.map((f) => `cat ${home}/${f} 2>&1`).join("; "));
    assert.doesNotMatch(r.out, /SECRET-CONTENT/);
  });
  test("I2: whatever the rules call a credential under $HOME or in the project is hidden", () => {
    const inHome = [".kube/config", "server.pem", "secrets.json", ".config/gcloud/credentials.db", ".docker/config.json", ".netrc"];
    const inRepo = [".env", "deploy/id_rsa", "config/credentials.json"];
    for (const [base, list] of [[home, inHome], [repo, inRepo]] as const) {
      for (const f of list) {
        fs.mkdirSync(path.dirname(path.join(base, f)), { recursive: true });
        fs.writeFileSync(path.join(base, f), "SECRET-CONTENT\n");
      }
    }
    fs.writeFileSync(path.join(repo, ".env.example"), "EXAMPLE=1\n");
    try {
      for (const f of [...inHome.map((f) => path.join(home, f)), ...inRepo.map((f) => path.join(repo, f))]) assert.ok(sandbox.isSecretPath(f), `the rules do not ask about ${f}`);
      const r = attempt([...inHome.map((f) => `cat ${home}/${f} 2>&1`), ...inRepo.map((f) => `cat ${f} 2>&1`), "cat .env.example", "echo X=1 >> .env"].join("; "));
      assert.doesNotMatch(r.out, /SECRET-CONTENT/);
      assert.match(r.out, /EXAMPLE=1/);
      // A write to a hidden file fails where it can be seen, rather than vanishing.
      assert.match(r.out, /\.env: (Read-only file system|Permission denied)/);
      assert.equal(fs.readFileSync(path.join(repo, ".env"), "utf8"), "SECRET-CONTENT\n");
    } finally {
      for (const f of [...inRepo, ".env.example"]) fs.rmSync(path.join(repo, f.split("/")[0]), { recursive: true, force: true });
    }
  });
  test("I3: only variables that plainly hold no credential are kept", () => {
    const env = {
      DATABASE_URL: "postgres://u:p@h/db", PGPASSWORD: "hunter2", MY_APIKEY: "abc", SENTRY_DSN: "https://k@sentry.invalid/1", SLACK_WEBHOOK_URL: "https://hooks.invalid/x", DB_PWD: "x",
      CI_JOB_JWT: "eyJ", STRIPE_SK: "sk_live_x", GITHUB_TOKEN: "ghp_x", UNKNOWN_BLOB: "0123456789abcdef0123456789abcdef",
      PATH: "/usr/bin:/bin", PWD: "/work", HOME: "/home/x", LANG: "C.UTF-8", NODE_ENV: "test", MY_FLAG: "1", TOOLS_DIR: "/opt/tools:/opt/more", CARGO_HOME: "/home/x/.cargo",
    };
    const { keep, dropped } = sandbox.envKept(env, ["UNKNOWN_BLOB"]);
    assert.deepEqual(dropped.sort(), ["CI_JOB_JWT", "DATABASE_URL", "DB_PWD", "GITHUB_TOKEN", "MY_APIKEY", "PGPASSWORD", "SENTRY_DSN", "SLACK_WEBHOOK_URL", "STRIPE_SK"]);
    for (const name of ["PATH", "PWD", "HOME", "LANG", "NODE_ENV", "MY_FLAG", "TOOLS_DIR", "CARGO_HOME", "UNKNOWN_BLOB"]) assert.ok(keep.includes(name), name);
    const proxies = sandbox.envKept({ NO_PROXY: "localhost,127.0.0.1,.internal.example", https_proxy: "http://proxy.internal:3128", HTTP_PROXY: "http://user:pw@proxy.internal:3128" }, []);
    assert.deepEqual(proxies.dropped, ["HTTP_PROXY"]);
  });
  test("an ssh agent socket outside the scanned directories is still hidden", async () => {
    const sock = path.join(home, "agent-elsewhere", "agent.sock");
    const server = await listen(sock);
    process.env.SSH_AUTH_SOCK = sock;
    try {
      assert.ok(planFor("ls").hide.includes(sock));
      assert.match(attempt(`test -S ${sock} && echo VISIBLE || echo hidden`).out, /hidden/);
    } finally {
      delete process.env.SSH_AUTH_SOCK;
      server.close();
    }
  });
  const sshDir = path.join(home, ".ssh");
  test("a command that uses ssh sees known_hosts and config, never private keys", () => {
    const p = plan({ projectRoots: [repo], allowedPaths: [], cacheDirs: [], gitWritable: true, exposeSsh: true, keepSockets: [], showPaths: [], hidePaths: [] });
    const names = fs.readdirSync(sshDir);
    assert.ok(names.includes("id_ed25519") && names.includes("known_hosts"));
    for (const name of names) assert.equal(p.hide.includes(path.join(sshDir, name)), !/^(known_hosts(\.old)?|config|authorized_keys|.*\.pub)$/.test(name), name);
  });
  test("a command that uses ssh keeps the agent while the rest of the runtime directory is hidden", async () => {
    const agent = path.join(runtime, "agent", "ssh.sock");
    const servers = await Promise.all([agent, path.join(runtime, "bus")].map(listen));
    process.env.SSH_AUTH_SOCK = agent;
    try {
      const p = plan({ projectRoots: [repo], allowedPaths: [], cacheDirs: [], gitWritable: true, exposeSsh: true, keepSockets: [], showPaths: [], hidePaths: [] });
      assert.ok(!p.hide.includes(agent) && !p.hide.includes(runtime) && !p.hide.includes(path.dirname(agent)));
      assert.ok(p.hide.includes(path.join(runtime, "bus")));
    } finally {
      delete process.env.SSH_AUTH_SOCK;
      servers.forEach((s) => s.close());
    }
  });
  test("~/.ssh is hidden unless the command uses ssh", () => {
    assert.equal(attempt(`ls -A ${sshDir} | wc -l`).out.split("\n")[0].trim(), "0");
  });
});

// ---- round 2 review findings ----

describe("r2 B: what a sandboxed command could plant", () => {
  const uid = process.getuid!();
  const cleanup: (() => void)[] = [];
  const made = (...paths: string[]) => cleanup.push(() => paths.forEach((p) => fs.rmSync(p, { recursive: true, force: true })));
  afterEach(() => {
    for (const undo of cleanup.splice(0).reverse()) undo();
  });

  test("7: a read-only git directory is read-only below its pinned children too", () => {
    const source = path.join(tmp, "sub-src");
    execFileSync("git", ["init", "-q", source]);
    execFileSync("git", ["-C", source, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "s"]);
    git("-c", "protocol.file.allow=always", "submodule", "add", "-q", source, "libsub");
    made(source, path.join(repo, "libsub"), path.join(repo, ".gitmodules"), path.join(repo, ".git", "modules"));
    cleanup.push(() => {
      git("reset", "-q");
      spawnSync("git", ["-C", repo, "config", "--remove-section", "submodule.libsub"]);
    });
    const r = attempt("mkdir -p .git/modules/other/hooks; echo x > .git/modules/planted; echo x > .git/modules/libsub/planted");
    assert.ok(r.plan.pin.includes(path.join(repo, ".git", "modules")), "the test needs .git/modules to be pinned");
    assert.match(r.out, /Read-only file system/);
    for (const name of ["other", "planted", "libsub/planted"]) assert.ok(!fs.existsSync(path.join(repo, ".git", "modules", name)), name);
  });

  test("7: opencode's project directories are read-only below a pinned child", () => {
    execFileSync("git", ["init", "-q", path.join(repo, ".claude", "skills", "x")]);
    made(path.join(repo, ".claude"));
    const r = attempt("echo x > .claude/skills/new.md; mkdir .claude/skills/y");
    assert.ok(r.plan.pin.includes(path.join(repo, ".claude", "skills")), "the test needs .claude/skills to be pinned");
    assert.ok(!fs.existsSync(path.join(repo, ".claude", "skills", "new.md")) && !fs.existsSync(path.join(repo, ".claude", "skills", "y")), r.out);
  });

  test("8: a .git that is a symbolic link cannot be protected: the plan says so, and its target is read-only", () => {
    const target = path.join(repo, "node_modules", ".cache", "r");
    for (const d of ["objects", "refs"]) fs.mkdirSync(path.join(target, d), { recursive: true });
    fs.writeFileSync(path.join(target, "HEAD"), "ref: refs/heads/main\n");
    fs.mkdirSync(path.join(repo, "src"), { recursive: true });
    fs.symlinkSync("../node_modules/.cache/r", path.join(repo, "src", ".git"));
    made(path.join(repo, "node_modules"), path.join(repo, "src"));
    const p = planFor("ls");
    assert.match(p.problem ?? "", /src\/\.git is a symbolic link/);
    assert.ok(p.ro.includes(target), JSON.stringify(p.ro));
  });

  test("9: a repository under node_modules is protected like any other", () => {
    const nested = path.join(repo, "node_modules", "pkg");
    execFileSync("git", ["init", "-q", nested]);
    made(path.join(repo, "node_modules"));
    const r = attempt("printf '[core]\\n\\tfsmonitor = /tmp/x\\n' >> node_modules/pkg/.git/config");
    assert.ok(r.plan.ro.includes(path.join(nested, ".git")), JSON.stringify(r.plan.ro));
    assert.ok(!/fsmonitor/.test(fs.readFileSync(path.join(nested, ".git", "config"), "utf8")));
  });

  test("10: a pointer file in a temp directory does not move a relative core.hooksPath away from the project", () => {
    // The project is outside the temp directories here, so they are walked after it.
    const project = path.join(home, "proj10");
    execFileSync("git", ["init", "-q", project]);
    execFileSync("git", ["-C", project, "config", "core.hooksPath", ".githooks"]);
    const decoy = path.join(tmp, "decoy");
    fs.mkdirSync(decoy);
    fs.writeFileSync(path.join(decoy, ".git"), `gitdir: ${path.join(project, ".git")}\n`);
    made(decoy, project);
    const p = plan({ projectRoots: [project], allowedPaths: [], cacheDirs: [], gitWritable: false, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [], project });
    assert.equal(p.problem, undefined);
    assert.ok(p.ro.includes(path.join(project, ".githooks")), JSON.stringify(p.ro));
  });

  test("11: config includes are followed as deep as git follows them", () => {
    const names = ["a.gitconfig", "b.gitconfig", "c.gitconfig", "d.gitconfig", "e.gitconfig"];
    names.forEach((name, i) => fs.writeFileSync(path.join(repo, name), i + 1 < names.length ? `[include]\n\tpath = ${names[i + 1]}\n` : "[core]\n\tabbrev = 12\n"));
    git("config", "include.path", "../a.gitconfig");
    made(...names.map((n) => path.join(repo, n)));
    cleanup.push(() => git("config", "--unset", "include.path"));
    const r = attempt("printf '[core]\\n\\tfsmonitor = /tmp/x\\n' >> e.gitconfig; printf x >> d.gitconfig");
    for (const name of names) assert.ok(r.plan.ro.includes(path.join(repo, name)), name);
    assert.ok(!/fsmonitor/.test(fs.readFileSync(path.join(repo, "e.gitconfig"), "utf8")));
  });

  test("11: an include that cannot be listed is a problem, not an empty list", () => {
    fs.writeFileSync(path.join(repo, "broken.gitconfig"), "[include\n\tpath = = =\n");
    git("config", "include.path", "../broken.gitconfig");
    // Undone in reverse: the file goes first, or git cannot read its own config to unset the key.
    cleanup.push(() => git("config", "--unset", "include.path"));
    made(path.join(repo, "broken.gitconfig"));
    assert.match(planFor("ls").problem ?? "", /broken\.gitconfig/);
  });

  test("12: a core.hooksPath behind a symbolic link in any component is a problem", () => {
    fs.mkdirSync(path.join(repo, "tools", "hooks"), { recursive: true });
    fs.symlinkSync("tools", path.join(repo, "link"));
    git("config", "core.hooksPath", "link/hooks");
    made(path.join(repo, "tools"), path.join(repo, "link"));
    cleanup.push(() => git("config", "--unset", "core.hooksPath"));
    assert.match(planFor("ls").problem ?? "", /symbolic link/);
  });

  test("12: lockwrite refuses to pin something that is not a directory", () => {
    fs.symlinkSync(tmp, path.join(repo, "not-a-dir"));
    made(path.join(repo, "not-a-dir"));
    const p = planFor("ls");
    const env = { ...process.env, AUTOMODE_SHELL: "/bin/bash", AUTOMODE_RW: p.rw.join(SEP), AUTOMODE_RO: p.ro.join(SEP), AUTOMODE_HIDE: p.hide.join(SEP), AUTOMODE_PIN: [...p.pin, path.join(repo, "not-a-dir")].join(SEP), AUTOMODE_TMPFS: p.tmpfs.join(SEP), AUTOMODE_COVER: cover };
    const r = spawnSync(WRAPPER, ["-c", "echo ran"], { cwd: repo, env, encoding: "utf8" });
    assert.equal(r.status, 126, r.stderr);
    assert.doesNotMatch(r.stdout, /ran/);
  });

  test("19: credential files are hidden at any depth, and a symbolic link's target with them", () => {
    const deep = path.join(repo, "a", "b", "c", "d", "e");
    fs.mkdirSync(deep, { recursive: true });
    fs.writeFileSync(path.join(deep, ".env"), "TOKEN=deep\n");
    fs.writeFileSync(path.join(repo, "real-settings.txt"), "TOKEN=linked\n");
    fs.symlinkSync("real-settings.txt", path.join(repo, ".env.production"));
    fs.mkdirSync(path.join(repo, "node_modules", "pkg"), { recursive: true });
    fs.writeFileSync(path.join(repo, "node_modules", "pkg", "server.key"), "KEY\n");
    made(path.join(repo, "a"), path.join(repo, "real-settings.txt"), path.join(repo, ".env.production"), path.join(repo, "node_modules"));
    const r = attempt("cat a/b/c/d/e/.env real-settings.txt .env.production node_modules/pkg/server.key");
    assert.doesNotMatch(r.out, /TOKEN|KEY/);
    assert.ok(r.plan.hide.includes(path.join(repo, "real-settings.txt")));
  });

  test("19: more credential files than the cap is a problem, not a silent stop", () => {
    for (let i = 0; i < 30; i++) fs.writeFileSync(path.join(repo, `.a${String(i).padStart(3, "0")}.key`), "k\n");
    fs.writeFileSync(path.join(repo, ".env"), "TOKEN=x\n");
    made(...Array.from({ length: 30 }, (_, i) => path.join(repo, `.a${String(i).padStart(3, "0")}.key`)), path.join(repo, ".env"));
    const before = { ...sandbox.limits };
    cleanup.push(() => Object.assign(sandbox.limits, before));
    assert.ok(planFor("ls").hide.includes(path.join(repo, ".env")));
    assert.equal(planFor("ls").problem, undefined);
    sandbox.limits.secrets = 10;
    assert.match(planFor("ls").problem ?? "", /credential/);
    Object.assign(sandbox.limits, before);
    sandbox.limits.entries = 5;
    assert.match(planFor("ls").problem ?? "", /stopped/);
  });

  test("19: a directory of the project that cannot be listed is a problem", () => {
    const dir = path.join(repo, "unlistable");
    fs.mkdirSync(dir, { mode: 0o300 });
    cleanup.push(() => {
      fs.chmodSync(dir, 0o700);
      fs.rmSync(dir, { recursive: true, force: true });
    });
    assert.match(planFor("ls").problem ?? "", /unlistable cannot be listed/);
  });

  test("31: histories, browser profiles and registry logins the old list missed are hidden", () => {
    const files = [".local/share/fish/fish_history", ".local/share/atuin/history.db", ".gem/credentials", ".config/composer/auth.json", ".composer/auth.json", ".config/containers/auth.json", ".mozilla/firefox/profiles.ini", ".config/google-chrome/Default/Cookies"];
    for (const f of files) {
      fs.mkdirSync(path.dirname(path.join(home, f)), { recursive: true });
      fs.writeFileSync(path.join(home, f), "private\n");
    }
    const ticket = `/tmp/krb5cc_${uid}_automodeTest`;
    fs.writeFileSync(ticket, "ticket\n");
    made(ticket);
    const r = attempt(`cat ${files.map((f) => path.join(home, f)).join(" ")} ${ticket}`);
    assert.doesNotMatch(r.out, /private|ticket/);
  });

  test("31: a socket deep below a temp directory is hidden", async () => {
    const dir = path.join(tmp, "s1", "s2", "s3", "s4", "s5");
    const server = await listen(path.join(dir, "deep.sock"));
    made(path.join(tmp, "s1"));
    try {
      assert.ok(planFor("ls").hide.includes(path.join(dir, "deep.sock")));
    } finally {
      server.close();
    }
  });
});

describe("r2 19: the cheap credential test lets through everything the rules know", () => {
  const names = [
    "id_rsa", "id_ed25519", "id_ecdsa_work", "id_dsa", "server.pem", "server.key", "store.p12", "cert.pfx", "trust.jks", "app.keystore", "vault.kdbx", ".env", ".env.local", ".env.production",
    "credentials.json", "credentials.yaml", "credentials.toml", "credentials.ini", "credentials.csv", "credentials.xml", "secrets.json", "secret.yml", "secrets.env", "secret.txt",
    "my-service-account.json", "service_principal-prod.json", "gcp-serviceaccount.json", ".netrc", ".npmrc", ".pypirc", ".git-credentials", ".vault-token", ".pgpass", ".htpasswd", ".bash_history", ".zsh_history",
    "login.keychain", "login.keychain-db", "SERVER.KEY", "Private.PEM",
  ];
  const places = [".ssh/anything", ".aws/credentials", ".gnupg/x", ".kube/config", ".azure/x", ".oci/x", ".password-store/x", ".config/gcloud/x", ".config/op/x", ".config/gh/hosts.yml", ".docker/config.json", ".cargo/credentials", ".cargo/credentials.toml", ".terraform.d/credentials.tfrc.json", ".local/share/keyrings/x"];
  test("names and places", () => {
    let secret = 0;
    for (const rel of [...names.map((n) => `src/${n}`), ...places]) {
      const parts = `/home/someone/project/${rel}`.split("/");
      // The walk tests every component as it meets it: one of them must pass both tests.
      const hit = parts.some((_, i) => i > 0 && sandbox.isSecretPath(parts.slice(0, i + 1).join("/")) && sandbox.maybeSecret(parts[i], parts[i - 1]));
      const known = parts.some((_, i) => i > 0 && sandbox.isSecretPath(parts.slice(0, i + 1).join("/")));
      if (known) secret++;
      assert.equal(hit, known, rel);
    }
    assert.ok(secret > 45, `only ${secret} of the samples are credentials for the rules`);
  });
});

describe("r2 30: an allowed push can do all of its work", () => {
  test("the remote-tracking ref is updated, which needs a writable git directory", () => {
    const remote = path.join(tmp, "push-remote.git");
    execFileSync("git", ["init", "-q", "--bare", remote]);
    git("remote", "add", "pushed", remote);
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "to push");
    const branch = git("rev-parse", "--abbrev-ref", "HEAD").trim();
    try {
      const r = run(`git push pushed ${branch}`);
      assert.equal(r.status, 0, r.out);
      assert.doesNotMatch(r.out, /Read-only file system|cannot lock ref|unable to/);
      assert.equal(git("rev-parse", `refs/remotes/pushed/${branch}`).trim(), git("rev-parse", "HEAD").trim());
    } finally {
      git("remote", "remove", "pushed");
      fs.rmSync(remote, { recursive: true, force: true });
    }
  });
});

// ---- round 3, group D ----

// Round 3, finding 26: a directory that cannot be listed is judged by what this process can do
// with it (access(2)), not by who owns it. No second user is available to an unprivileged test:
// process.getuid answers another uid while the plan is made, so this user's own directories
// stand in for someone else's (the kernel still answers access(2) for the real user).
describe("r3 26: a directory that can be entered or written but not listed", () => {
  const cleanup: (() => void)[] = [];
  afterEach(() => {
    for (const undo of cleanup.splice(0).reverse()) undo();
  });
  const unlistable = (dir: string, mode: number, inside?: () => void) => {
    fs.mkdirSync(dir, { recursive: true });
    inside?.();
    fs.chmodSync(dir, mode);
    cleanup.push(() => {
      fs.chmodSync(dir, 0o700);
      fs.rmSync(dir, { recursive: true, force: true });
    });
  };
  const asOther = <T>(fn: () => T): T => {
    const real = process.getuid;
    const other = process.getuid!() + 4242;
    process.getuid = () => other;
    try {
      return fn();
    } finally {
      process.getuid = real;
    }
  };
  for (const mode of [0o300, 0o100, 0o200]) {
    test(`r3 26: someone else's directory in the project, mode ${mode.toString(8)}, holding a bare repository, is a problem`, () => {
      const dir = path.join(repo, "shared");
      unlistable(dir, mode, () => execFileSync("git", ["init", "-q", "--bare", path.join(dir, "r.git")]));
      assert.match(asOther(() => planFor("ls")).problem ?? "", /shared cannot be listed/);
    });
  }
  test("r3 26: someone else's directory in a temp directory that can be entered is covered, and commands still run", () => {
    const dir = path.join(tmp, "r3-26-other");
    unlistable(dir, 0o100);
    const p = asOther(() => planFor("ls"));
    assert.equal(p.problem, undefined);
    assert.ok(p.hide.includes(dir), p.hide.join(" "));
    const env = { ...process.env, AUTOMODE_SHELL: "/bin/bash", AUTOMODE_RW: p.rw.join(SEP), AUTOMODE_RO: p.ro.join(SEP), AUTOMODE_HIDE: p.hide.join(SEP), AUTOMODE_PIN: p.pin.join(SEP), AUTOMODE_TMPFS: p.tmpfs.join(SEP), AUTOMODE_COVER: cover };
    const r = spawnSync(WRAPPER, ["-c", `touch ${dir}/planted 2>/dev/null; echo ran`], { cwd: repo, env, encoding: "utf8" });
    assert.match(r.stdout, /ran/, r.stderr);
    fs.chmodSync(dir, 0o700);
    assert.ok(!fs.existsSync(path.join(dir, "planted")));
  });
  test("r3 26: an unlistable directory under /run that can be entered is covered", (t) => {
    const found = ["/run/sudo", "/run/containerd", "/run/systemd/inaccessible"].find((d) => {
      try {
        fs.readdirSync(d);
        return false;
      } catch {
        try {
          fs.accessSync(d, fs.constants.X_OK);
          return fs.statSync(d).isDirectory();
        } catch {
          return false;
        }
      }
    });
    if (!found) return t.skip("no directory under /run here that can be entered and not listed");
    const p = planFor("ls");
    assert.equal(p.problem, undefined);
    assert.ok(p.hide.some((h) => within(found, h)), `${found} not covered: ${p.hide.filter((h) => h.startsWith("/run")).join(" ")}`);
  });
  test("r3 26: unchanged: someone else's directory closed both ways is no problem, this user's own is", () => {
    const dir = path.join(repo, "closed");
    unlistable(dir, 0o000);
    assert.equal(asOther(() => planFor("ls")).problem, undefined);
    // The owner can change the mode back.
    assert.match(planFor("ls").problem ?? "", /closed cannot be listed/);
  });
});

// Round 3, finding 34, and lockwrite started as root. opencode gives the shell /dev/null and
// sockets, never a terminal; a terminal on stdin, stdout or stderr would stay reachable from the
// sandbox (TIOCSTI where the kernel allows it, TIOCSWINSZ and tcsetattr everywhere), so lockwrite
// refuses to run anything. Started as uid 0 the command would keep its capabilities in the
// sandbox's user namespace and could make a read-only mount writable again: refused too.
describe("r3 34: lockwrite refuses a terminal and root", () => {
  const PTY = path.join(ROOT, "test", "pty-run.py");
  const marker = path.join(repo, "r3-34-ran");
  afterEach(() => fs.rmSync(marker, { force: true }));
  const envFor = () => {
    const p = planFor("ls");
    return { ...process.env, AUTOMODE_SHELL: "/bin/bash", AUTOMODE_RW: p.rw.join(SEP), AUTOMODE_RO: p.ro.join(SEP), AUTOMODE_HIDE: p.hide.join(SEP), AUTOMODE_PIN: p.pin.join(SEP), AUTOMODE_TMPFS: p.tmpfs.join(SEP), AUTOMODE_COVER: cover };
  };
  const onTerminal = (fds: string, args: string[], env: NodeJS.ProcessEnv = envFor()) => {
    const r = spawnSync("python3", ["-I", PTY, fds, ...args], { cwd: repo, env, encoding: "utf8", timeout: 30_000 });
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout) as { status: number; tty: string; stdout: string; stderr: string };
  };
  for (const fds of ["0,1,2", "0", "1", "2"]) {
    test(`r3 34: with descriptor(s) ${fds} on a terminal, the command does not run and lockwrite exits 126`, () => {
      const r = onTerminal(fds, [WRAPPER, "-c", `touch ${marker}; echo ran`]);
      assert.equal(r.status, 126, JSON.stringify(r));
      assert.match(r.tty + r.stderr, /terminal/);
      assert.ok(!fs.existsSync(marker), "the command ran");
    });
  }
  test("r3 34: --selftest still works from a terminal", () => {
    const r = onTerminal("0,1,2", [path.join(ROOT, "sandbox", "lockwrite"), "--selftest"], { PATH: process.env.PATH });
    assert.equal(r.status, 0, JSON.stringify(r));
    assert.match(r.tty, /lockwrite: ok/);
  });
  test("r3 34: with pipes and /dev/null, as opencode starts it, the command runs", () => {
    const r = spawnSync(WRAPPER, ["-c", `touch ${marker}; echo ran`], { cwd: repo, env: envFor(), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /ran/);
    assert.ok(fs.existsSync(marker));
  });
  const userns = spawnSync("unshare", ["-Ur", "true"]).status === 0;
  test("r3 34: started as uid 0 (unshare -Ur), lockwrite refuses, the selftest too", (t) => {
    if (!userns) return t.skip("unprivileged user namespaces (unshare -Ur) are not available here");
    const r = spawnSync("unshare", ["-Ur", WRAPPER, "-c", `touch ${marker}; echo ran`], { cwd: repo, env: envFor(), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assert.equal(r.status, 126, r.stdout + r.stderr);
    assert.match(r.stderr, /root|uid 0/);
    assert.ok(!fs.existsSync(marker), "the command ran");
    const self = spawnSync("unshare", ["-Ur", path.join(ROOT, "sandbox", "lockwrite"), "--selftest"], { encoding: "utf8" });
    assert.equal(self.status, 126, self.stdout + self.stderr);
  });
  test("r3 34: started with capabilities kept in a user namespace (not root), the command has none", (t) => {
    if (spawnSync("unshare", ["-U", "--map-current-user", "--keep-caps", "true"]).status !== 0) return t.skip("unshare --keep-caps is not available here");
    const r = spawnSync("unshare", ["-U", "--map-current-user", "--keep-caps", WRAPPER, "-c", "grep -E '^Cap(Eff|Prm|Amb)' /proc/self/status"], { cwd: repo, env: envFor(), encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
    assert.equal(r.status, 0, r.stderr);
    assert.deepEqual(r.stdout.trim().split("\n").map((l) => l.split(/\s+/)[1]), ["0000000000000000", "0000000000000000", "0000000000000000"], r.stdout);
  });
});
