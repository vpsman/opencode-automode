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
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import * as sandbox from "../sandbox.ts";
import { gitOnly, usesSsh, SessionState } from "../decide.ts";

const { plan } = sandbox;
const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
// Lists reach lockwrite newline-separated.
const SEP = "\n";
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
      assert.match(p.problem ?? "", /core\.hooksPath .* could not be created safely|symlink/);
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
