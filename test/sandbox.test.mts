// Sandbox regression tests: the plan comes from sandbox.ts exactly as the plugin builds it, and
// commands run through sandbox/bin/bash the way opencode runs a swapped shell.
// Needs `npm run build:sandbox` first. Run: npm test
import { spawn, spawnSync, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { plan } from "../sandbox.ts";
import { gitOnly, usesSsh, SessionState } from "../decide.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-sbx-")));
const repo = path.join(tmp, "repo");
const home = os.homedir();
const probe = path.join(home, `.automode-sandbox-probe-${process.pid}`);
const abi = Number(/ABI (\d+)/.exec(execFileSync(path.join(ROOT, "sandbox", "lockwrite"), ["--selftest"], { encoding: "utf8" }))?.[1] ?? 0);

function run(command: string, input = "", extraFds: number[] = []) {
  const p = plan({ projectRoots: [repo], allowedPaths: [], cacheDirs: [], gitWritable: gitOnly(command), exposeSsh: usesSsh(command, repo, new SessionState(repo)), keepSockets: [], showPaths: [], hidePaths: [] });
  const env = {
    ...process.env,
    AUTOMODE_SHELL: "/bin/bash",
    AUTOMODE_RW: p.rw.join(":"),
    AUTOMODE_RO: p.ro.join(":"),
    AUTOMODE_HIDE: p.hide.join(":"),
    AUTOMODE_PIN: p.pin.join(":"),
    AUTOMODE_TMPFS: p.tmpfs.join(":"),
  };
  const r = spawnSync(WRAPPER, ["-c", command], { cwd: repo, env, input, encoding: "utf8", stdio: ["pipe", "pipe", "pipe", ...extraFds] });
  return { status: r.status, out: (r.stdout ?? "") + (r.stderr ?? "") };
}

before(() => {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  execFileSync("git", ["init", "-q", repo]);
});
after(() => {
  fs.rmSync(tmp, { recursive: true, force: true });
  fs.rmSync(probe, { force: true });
});

describe("normal work inside the project", () => {
  test("writes work for ordinary commands", () => {
    const r = run("echo x > f && cat f");
    assert.equal(r.status, 0, r.out);
  });
  test("a git-only call can add and commit", () => {
    const r = run("git add f && git -c user.name=t -c user.email=t@t commit -qm m");
    assert.equal(r.status, 0, r.out);
    assert.match(execFileSync("git", ["-C", repo, "log", "--oneline"], { encoding: "utf8" }), /m/);
  });
  test("stdin, stdout and the exit code pass through", () => {
    const r = run("cat; exit 7", "piped-in\n");
    assert.equal(r.status, 7);
    assert.match(r.out, /piped-in/);
  });
  test("AUTOMODE_* variables do not reach the command", () => {
    assert.equal(run("env | grep -c '^AUTOMODE_' || true").out.trim(), "0");
  });
  test("/dev/shm is private and writable; /dev/null works", () => {
    const r = run("echo x > /dev/shm/automode-test && cat /dev/shm/automode-test && echo y > /dev/null && echo ok");
    assert.match(r.out, /ok/);
    assert.ok(!fs.existsSync("/dev/shm/automode-test"));
  });
});

describe("containment", () => {
  test("cannot write outside the writable directories, from the shell or a child", () => {
    const r = run(`echo x > ${probe}; python3 -c "open('${probe}','w')"; bash -c 'touch ${probe}'`);
    assert.ok(!fs.existsSync(probe), r.out);
  });
  test("cannot create device files or files in /dev", () => {
    run("touch /dev/automode-test");
    assert.ok(!fs.existsSync("/dev/automode-test"));
  });
  test("cannot plant a git hook", () => {
    run("echo 'touch /tmp/pwned' > .git/hooks/pre-push; chmod +x .git/hooks/pre-push");
    assert.ok(!fs.existsSync(path.join(repo, ".git/hooks/pre-push")));
  });
  test("cannot change .git/config", () => {
    run("git config core.hooksPath /tmp/evil; echo '[core]' >> .git/config");
    assert.ok(!/hooksPath|evil/.test(fs.readFileSync(path.join(repo, ".git/config"), "utf8")));
  });
  test("cannot rename or replace .git", () => {
    run("mv .git .git.old && cp -a .git.old .git && touch .git/hooks/x");
    assert.ok(!fs.existsSync(path.join(repo, ".git.old")));
    assert.ok(!fs.existsSync(path.join(repo, ".git/hooks/x")));
  });
  test("cannot rename a parent of a nested repository", () => {
    execFileSync("git", ["init", "-q", path.join(repo, "vendor", "lib")]);
    try {
      run("mv vendor vendor2; mv vendor/lib vendor/lib2");
      assert.ok(fs.existsSync(path.join(repo, "vendor", "lib", ".git")));
      assert.ok(!fs.existsSync(path.join(repo, "vendor2")));
    } finally {
      fs.rmSync(path.join(repo, "vendor"), { recursive: true, force: true });
    }
  });
  test("cannot plant .git/commondir", () => {
    run("echo /tmp > .git/commondir");
    assert.ok(!fs.existsSync(path.join(repo, ".git/commondir")));
  });
  test("cannot plant hooks in a repository-level core.hooksPath (husky style)", () => {
    execFileSync("git", ["-C", repo, "config", "core.hooksPath", ".husky/_"]);
    try {
      run("mkdir -p .husky/_ && echo 'touch /tmp/pwned' > .husky/_/pre-commit");
      assert.ok(!fs.existsSync(path.join(repo, ".husky/_/pre-commit")));
    } finally {
      execFileSync("git", ["-C", repo, "config", "--unset", "core.hooksPath"]);
    }
  });
  test("cannot undo the read-only mounts", () => {
    const r = run("umount .git/hooks 2>&1; mount --bind /tmp .git/hooks 2>&1; echo x > .git/hooks/x 2>&1; true");
    assert.ok(!fs.existsSync(path.join(repo, ".git/hooks/x")), r.out);
  });
  test("cannot signal processes outside the sandbox", { skip: abi < 6 && "needs Landlock ABI 6 (Linux 6.12)" }, () => {
    const victim = spawn("sleep", ["30"]);
    try {
      const r = run(`kill -TERM ${victim.pid} 2>&1; echo done`);
      assert.match(r.out, /Operation not permitted/);
      assert.equal(victim.exitCode, null);
    } finally {
      victim.kill();
    }
  });
  test("cannot reach another process's filesystem view through /proc", () => {
    assert.match(run(`ls /proc/${process.pid}/root/ 2>&1 | head -1`).out, /Permission denied/);
  });
  const userManager = `${process.env.XDG_RUNTIME_DIR || `/run/user/${process.getuid?.()}`}/systemd/private`;
  test("the systemd user manager socket is hidden", { skip: !fs.existsSync(userManager) }, () => {
    assert.match(run(`test -S ${userManager} && echo VISIBLE || echo hidden`).out, /hidden/);
  });
  const state = path.join(process.env.XDG_STATE_HOME || path.join(home, ".local", "state"), "opencode");
  test("opencode's state (server password) is hidden", { skip: !fs.existsSync(state) }, () => {
    assert.equal(run(`ls -A ${state} | wc -l`).out.trim(), "0");
  });
  test("inherited file descriptors are closed before the command runs", () => {
    const fd = fs.openSync(repo, "r");
    try {
      assert.match(run("[ -e /proc/self/fd/3 ] && echo OPEN || echo closed", "", [fd]).out, /closed/);
    } finally {
      fs.closeSync(fd);
    }
  });
  test("an ssh agent socket outside the scanned directories is still hidden", () => {
    const dir = fs.mkdtempSync(path.join(home, ".automode-agent-test-"));
    const sock = path.join(dir, "agent.sock");
    execFileSync("python3", ["-I", "-c", `import socket;s=socket.socket(socket.AF_UNIX);s.bind(${JSON.stringify(sock)})`]);
    const before = process.env.SSH_AUTH_SOCK;
    process.env.SSH_AUTH_SOCK = sock;
    try {
      const p = plan({ projectRoots: [repo], allowedPaths: [], cacheDirs: [], gitWritable: false, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [] });
      assert.ok(p.hide.includes(sock));
    } finally {
      if (before === undefined) delete process.env.SSH_AUTH_SOCK;
      else process.env.SSH_AUTH_SOCK = before;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
  const sshDir = path.join(home, ".ssh");
  test("a command that uses ssh sees known_hosts and config, never private keys", { skip: !fs.existsSync(sshDir) }, () => {
    const p = plan({ projectRoots: [repo], allowedPaths: [], cacheDirs: [], gitWritable: true, exposeSsh: true, keepSockets: [], showPaths: [], hidePaths: [] });
    for (const name of fs.readdirSync(sshDir)) {
      const hidden = p.hide.includes(path.join(sshDir, name));
      const visible = /^(known_hosts(\.old)?|config|authorized_keys|.*\.pub)$/.test(name);
      assert.equal(hidden, !visible, name);
    }
  });
  test("~/.ssh and the ssh agent are hidden unless the command uses ssh", { skip: !fs.existsSync(sshDir) }, () => {
    assert.equal(run(`ls -A ${sshDir} | wc -l`).out.trim(), "0");
    const agent = process.env.SSH_AUTH_SOCK;
    if (agent && fs.existsSync(agent)) assert.match(run(`test -S ${agent} && echo VISIBLE || echo hidden`).out, /hidden/);
  });
});
