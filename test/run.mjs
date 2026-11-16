// Runs the test files with a throwaway home: nothing is read from or written to the real
// $HOME, the global git config, the user's runtime directory or their ssh agent.
//
// The home cannot live in /tmp (the rules treat temp directories as writable project space), so
// it is made under ~/.cache/automode-tests (or $AUTOMODE_TEST_BASE) and removed after. The name
// must not hold "opencode-automode": a default ask rule matches that, so every tested command that
// expands $HOME would ask for that reason alone.
//
// Several files run at once, each in a process of its own with a home and a temp directory of its
// own (the files keep state in both: the plugin's state directory, its resume file, the session
// moments, the scratch repositories the sandbox plans scan): $AUTOMODE_TEST_JOBS of them (default:
// half the processors, at most 8). Each file's output is printed whole when it is over, and the
// counts of all of them at the end. AUTOMODE_TEST_JOBS=1 runs them one after another, as before.
// Usage: node test/run.mjs [test files...]
import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = path.dirname(import.meta.dirname);
const base = process.env.AUTOMODE_TEST_BASE || path.join(os.homedir(), ".cache", "automode-tests");
fs.mkdirSync(base, { recursive: true });

// A throwaway home (and, beside it, a temp directory of its own under $TMPDIR) for one process.
function world() {
  const home = fs.mkdtempSync(path.join(base, "h-"));
  const dirs = { config: path.join(home, ".config"), state: path.join(home, ".local", "state"), data: path.join(home, ".local", "share"), cache: path.join(home, ".cache"), run: path.join(home, "run") };
  for (const d of Object.values(dirs)) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  // What a real home has that the tests look for: ssh keys and config, and a global git identity.
  fs.mkdirSync(path.join(home, ".ssh"), { mode: 0o700 });
  for (const [name, text] of Object.entries({ id_ed25519: "not a real key\n", "id_ed25519.pub": "ssh-ed25519 AAAA test\n", known_hosts: "", config: "" })) {
    fs.writeFileSync(path.join(home, ".ssh", name), text, { mode: 0o600 });
  }
  fs.writeFileSync(path.join(home, ".gitconfig"), "[user]\n\tname = test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n");
  // (A short name: the tests make unix sockets under it, whose paths may not pass 107 bytes.)
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "r"));
  const env = { ...process.env, HOME: home, TMPDIR: tmp, XDG_CONFIG_HOME: dirs.config, XDG_STATE_HOME: dirs.state, XDG_DATA_HOME: dirs.data, XDG_CACHE_HOME: dirs.cache, XDG_RUNTIME_DIR: dirs.run, GIT_CONFIG_GLOBAL: path.join(home, ".gitconfig"), GIT_CONFIG_NOSYSTEM: "1" };
  for (const name of Object.keys(env)) if (/^(SSH_|GIT_(DIR|WORK_TREE|SSH)|OPENCODE|AUTOMODE_(?!TEST_))/.test(name)) delete env[name];
  // Under `npm test` npm hands down where the real user's and the machine's npmrc files are; the
  // decision for an `npx` reads the user's one (decide.ts, npxReading), so they go as well.
  for (const name of Object.keys(env)) if (/^npm_config_(userconfig|globalconfig)$/i.test(name)) delete env[name];
  const done = () => {
    fs.rmSync(home, { recursive: true, force: true });
    fs.rmSync(tmp, { recursive: true, force: true });
  };
  return { env, done };
}

// Options for node's test runner (`--test-name-pattern=…`) go to every file's run.
const options = process.argv.slice(2).filter((a) => a.startsWith("-"));
const given = process.argv.slice(2).filter((a) => !a.startsWith("-"));
const files = given.length ? given : fs.readdirSync(path.join(root, "test")).filter((f) => f.endsWith(".test.mts")).sort().map((f) => path.join("test", f));
const jobs = Math.max(1, Number(process.env.AUTOMODE_TEST_JOBS) || Math.min(8, Math.floor((os.availableParallelism?.() ?? os.cpus().length) / 2)));

// One file (or, with one job, all of them in one process as before).
function run(names, live) {
  return new Promise((resolve) => {
    const { env, done } = world();
    const child = spawn(process.execPath, ["--test", "--test-concurrency=1", ...options, ...names], { cwd: root, env, stdio: live ? "inherit" : ["ignore", "pipe", "pipe"] });
    let out = "";
    if (!live) {
      child.stdout.on("data", (b) => (out += b));
      child.stderr.on("data", (b) => (out += b));
    }
    child.on("close", (code, signal) => {
      done();
      resolve({ status: code ?? 1, signal, out });
    });
  });
}

let status = 0;
if (jobs === 1 || files.length === 1) {
  const r = await run(files, true);
  status = r.status;
} else {
  const counts = { tests: 0, suites: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
  const failed = [];
  const queue = [...files];
  const started = Date.now();
  await Promise.all(
    Array.from({ length: Math.min(jobs, files.length) }, async () => {
      for (let file = queue.shift(); file !== undefined; file = queue.shift()) {
        const r = await run([file], false);
        process.stdout.write(`\n▶▶ ${file}\n${r.out}`);
        for (const [key] of Object.entries(counts)) {
          const m = new RegExp(`^ℹ ${key} (\\d+)$`, "m").exec(r.out);
          if (m) counts[key] += Number(m[1]);
        }
        if (r.status !== 0) {
          status = 1;
          failed.push(`${file} (exit ${r.signal ?? r.status})`);
        }
      }
    }),
  );
  process.stdout.write(`\n── all ${files.length} files, ${jobs} at a time ──\n`);
  for (const [key, n] of Object.entries(counts)) process.stdout.write(`ℹ ${key} ${n}\n`);
  process.stdout.write(`ℹ duration_ms ${Date.now() - started}\n`);
  if (failed.length) process.stdout.write(`✖ files that failed:\n${failed.map((f) => `✖ ${f}`).join("\n")}\n`);
}
process.exit(status);
