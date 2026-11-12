// Runs the test files with a throwaway home: nothing is read from or written to the real
// $HOME, the global git config, the user's runtime directory or their ssh agent.
//
// The home cannot live in /tmp (the rules treat temp directories as writable project space), so
// it is made under ~/.cache/automode-tests (or $AUTOMODE_TEST_BASE) and removed after. The name
// must not hold "opencode-automode": a default ask rule matches that, so every tested command that
// expands $HOME would ask for that reason alone.
// Usage: node test/run.mjs [test files...]
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const root = path.dirname(import.meta.dirname);
const base = process.env.AUTOMODE_TEST_BASE || path.join(os.homedir(), ".cache", "automode-tests");
fs.mkdirSync(base, { recursive: true });
const home = fs.mkdtempSync(path.join(base, "h-"));
const dirs = { config: path.join(home, ".config"), state: path.join(home, ".local", "state"), data: path.join(home, ".local", "share"), cache: path.join(home, ".cache"), run: path.join(home, "run") };
for (const d of Object.values(dirs)) fs.mkdirSync(d, { recursive: true, mode: 0o700 });

// What a real home has that the tests look for: ssh keys and config, and a global git identity.
fs.mkdirSync(path.join(home, ".ssh"), { mode: 0o700 });
for (const [name, text] of Object.entries({ id_ed25519: "not a real key\n", "id_ed25519.pub": "ssh-ed25519 AAAA test\n", known_hosts: "", config: "" })) {
  fs.writeFileSync(path.join(home, ".ssh", name), text, { mode: 0o600 });
}
fs.writeFileSync(path.join(home, ".gitconfig"), "[user]\n\tname = test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n");

const env = { ...process.env, HOME: home, XDG_CONFIG_HOME: dirs.config, XDG_STATE_HOME: dirs.state, XDG_DATA_HOME: dirs.data, XDG_CACHE_HOME: dirs.cache, XDG_RUNTIME_DIR: dirs.run, GIT_CONFIG_GLOBAL: path.join(home, ".gitconfig"), GIT_CONFIG_NOSYSTEM: "1" };
for (const name of Object.keys(env)) if (/^(SSH_|GIT_(DIR|WORK_TREE|SSH)|OPENCODE|AUTOMODE_(?!TEST_))/.test(name)) delete env[name];

const files = process.argv.slice(2);
let status = 1;
try {
  const r = spawnSync(process.execPath, ["--test", "--test-concurrency=1", ...(files.length ? files : [path.join(root, "test", "*.test.mts")])], { cwd: root, env, stdio: "inherit" });
  status = r.status ?? 1;
} finally {
  fs.rmSync(home, { recursive: true, force: true });
}
process.exit(status);
