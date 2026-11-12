// The allow corpus: everyday commands that must be a rule allow, with no model call, and must
// work under the sandbox plan that allow gets. It fences the scanner and the guards from the
// over-asking side, as test/differential.test.mts fences them from the under-asking side.
//
// Each entry of test/allow-corpus.txt (one per `====` block; a leading `## ` line is its label,
// `<NL>` a trailing newline) runs in a fresh copy of a fixture project, the way index.ts handles
// a tool call: decideShell, then sandboxBreaks (an allow that cannot work asks), then plan()
// (a plan with a problem asks), then the command itself through sandbox/bin/bash with that plan
// and the environment envKept leaves. It must exit 0.
//
// Real tools: git, npm/node, cargo (through rustup), make, rg, jq, sed, awk, grep, coreutils.
// pytest, pnpm, yarn and go are stand-ins on PATH that exit 0 (not installed where this was
// written); clang is not needed, since the fixture's Makefile does not use $(CC).
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/allow-corpus.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideShell, gitOnly, projectRoots, sandboxBreaks, SessionState, usesSsh, type Decision, type Guard } from "../decide.ts";
import { compileRules } from "../rules.ts";
import { envKept, plan } from "../sandbox.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
assert.ok(process.env.GIT_CONFIG_GLOBAL?.startsWith(os.homedir()), "run through test/run.mjs, which supplies a throwaway $HOME");
// The project lives in the (throwaway) home, as a real one would, not in /tmp.
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), "corpus-")));
const fixture = path.join(base, "fixture");
const stubs = path.join(base, "stubs");
const cover = path.join(base, "cover");

const guard: Guard = {
  rules: compileRules({ ask: DEFAULT_ASK }),
  guarded: [ROOT],
  configDirs: [path.join(os.homedir(), ".config", "opencode")],
  allowedPaths: [],
  classifier: DEFAULT_CLASSIFIER,
  useClassifier: false,
  sshHosts: [],
  allowFeatureBranchPush: false,
};

const git = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const write = (file: string, text: string) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
};

// rustup finds its toolchains through $RUSTUP_HOME or $HOME/.rustup, and $HOME is a throwaway
// here: point it at the real one next to the cargo on PATH (read only; nothing is installed).
function rustupHome(): string | undefined {
  if (process.env.RUSTUP_HOME) return process.env.RUSTUP_HOME;
  const cargo = spawnSync("sh", ["-c", "command -v cargo"], { encoding: "utf8" }).stdout.trim();
  const guess = cargo && path.join(path.dirname(path.dirname(path.dirname(fs.realpathSync(cargo)))), ".rustup");
  return guess && fs.existsSync(guess) ? guess : undefined;
}

before(() => {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  fs.writeFileSync(cover, "", { mode: 0o400 });
  for (const name of ["pytest", "pnpm", "yarn", "go"]) write(path.join(stubs, name), `#!/bin/sh\necho "stand-in ${name} $*"\n`), fs.chmodSync(path.join(stubs, name), 0o755);

  const p = fixture;
  write(path.join(p, "f"), "alpha one\nbeta two foo\ngamma three\ndelta four\nepsilon five\nzeta six\n");
  write(path.join(p, "index.ts"), "export const x = 1;\n// TODO\n");
  write(path.join(p, "src", "a.ts"), "export const foo = 1;\n");
  write(path.join(p, "src", "b.ts"), "export const b = 2;\n");
  write(path.join(p, "src", "main.rs"), 'fn main() {\n    println!("hi");\n}\n');
  write(path.join(p, "Cargo.toml"), '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n');
  const pkg = (name: string) => JSON.stringify({ name, version: "1.0.0", private: true, scripts: { test: "node -e \"console.log('tests pass')\"", build: "node -e \"require('fs').writeFileSync('dist.txt', 'built')\"" } }, null, 2) + "\n";
  write(path.join(p, "package.json"), pkg("fixture"));
  write(path.join(p, "web", "package.json"), pkg("web"));
  write(path.join(p, "x", "package.json"), pkg("x"));
  write(path.join(p, "Makefile"), "all:\n\t@echo built > build.txt\n");
  write(path.join(p, "dir", "readme.md"), "# readme\n");
  write(path.join(p, "dir", "notes.md"), "# notes\n");
  write(path.join(p, "data.json"), '{"a": "x"}\n');
  write(path.join(p, "g"), "one\n");
  write(path.join(p, ".gitignore"), "target/\nnode_modules/\n");
  git(base, "init", "-q", "--bare", "-b", "main", "remote.git");
  git(base, "init", "-q", "-b", "main", p);
  git(p, "add", "-A");
  git(p, "commit", "-qm", "init");
  git(p, "remote", "add", "origin", path.join(base, "remote.git"));
  git(p, "push", "-q", "-u", "origin", "main");
  // A patch that applies to g.
  write(path.join(p, "g"), "one\ntwo\n");
  write(path.join(p, "p.diff"), git(p, "diff", "g"));
  git(p, "checkout", "-q", "g");
  // Something staged, something modified, something untracked.
  write(path.join(p, "CHANGELOG.md"), "# changes\n");
  git(p, "add", "CHANGELOG.md");
  write(path.join(p, "src", "b.ts"), "export const b = 3;\n");
  write(path.join(p, "notes.txt"), "untracked\n");
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

// Per-command setup in the fresh copy, before the decision.
const SETUP: Record<string, (dir: string) => void> = {
  // The copy gave every file a new inode, so the index's stat data is stale, and `apply --index`
  // reads that as "does not match index"; in a checkout of its own it is current.
  // (`git status` refreshes it.)
  "git apply --index p.diff": (dir) => void git(dir, "status", "--porcelain"),
  // A rebase stopped on a conflict, resolved and staged.
  "GIT_EDITOR=true git rebase --continue": (dir) => {
    git(dir, "reset", "-q", "--hard");
    git(dir, "checkout", "-q", "-b", "topic");
    write(path.join(dir, "conflict.txt"), "topic\n");
    git(dir, "add", "conflict.txt");
    git(dir, "commit", "-qm", "topic");
    git(dir, "checkout", "-q", "main");
    write(path.join(dir, "conflict.txt"), "main\n");
    git(dir, "add", "conflict.txt");
    git(dir, "commit", "-qm", "main side");
    git(dir, "checkout", "-q", "topic");
    assert.notEqual(spawnSync("git", ["-C", dir, "rebase", "-q", "main"], { encoding: "utf8" }).status, 0, "the rebase did not stop on its conflict");
    write(path.join(dir, "conflict.txt"), "resolved\n");
    git(dir, "add", "conflict.txt");
  },
};

interface Entry {
  label: string;
  command: string;
}
const corpus: Entry[] = fs
  .readFileSync(path.join(import.meta.dirname, "allow-corpus.txt"), "utf8")
  .split("\n====\n")
  .map((block) => {
    const text = block.replace(/\n$/, "");
    const label = /^## (.*)\n/.exec(text);
    return { label: label?.[1] ?? "", command: (label ? text.slice(label[0].length) : text).replaceAll("<NL>", "\n") };
  });

const describeDecision = (d: Decision) => `${d.by === "no-model" ? "left to the model" : `${d.effect} by ${d.by}`}: ${d.reason}`;

// What happens to one command, from the decision to its exit status. Undefined when it was
// allowed by the rules and worked.
async function attempt(command: string, index: number): Promise<string | undefined> {
  const dir = path.join(base, "work", String(index));
  fs.mkdirSync(path.dirname(dir), { recursive: true });
  execFileSync("cp", ["-a", fixture, dir]);
  SETUP[command]?.(dir);
  const session = new SessionState(dir);
  const d = await decideShell(guard, session, dir, command);
  if (d.effect !== "allow" || d.by !== "rules") return describeDecision(d);
  const broken = sandboxBreaks(command, dir, session);
  if (broken) return `allowed, then asks because it cannot work in the sandbox: ${broken}`;
  const p = plan({ projectRoots: projectRoots(session), allowedPaths: [], cacheDirs: [], gitWritable: gitOnly(command), exposeSsh: usesSsh(command, dir, session), keepSockets: [], showPaths: [], hidePaths: [], project: dir });
  if (p.problem) return `allowed, then asks because the sandbox could not be prepared: ${p.problem}`;
  const rustup = rustupHome();
  const env: Record<string, string | undefined> = { ...process.env, PATH: `${stubs}:${process.env.PATH}`, ...(rustup ? { RUSTUP_HOME: rustup } : {}) };
  delete env.NODE_TEST_CONTEXT;
  const { keep } = envKept(env, []);
  Object.assign(env, {
    AUTOMODE_ENV_KEEP: keep.join("\n"),
    AUTOMODE_SHELL: "/bin/bash",
    AUTOMODE_RW: p.rw.join("\n"),
    AUTOMODE_RO: p.ro.join("\n"),
    AUTOMODE_HIDE: p.hide.join("\n"),
    AUTOMODE_PIN: p.pin.join("\n"),
    AUTOMODE_TMPFS: p.tmpfs.join("\n"),
    AUTOMODE_COVER: cover,
  });
  // stdin is /dev/null, as opencode gives it (rg with no path then searches the directory).
  const r = spawnSync(WRAPPER, ["-c", command], { cwd: dir, env, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 180_000 });
  if (r.status === 0) return undefined;
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`.trim().split("\n").slice(-8).join("\n");
  return `allowed, but it failed under the plan (exit ${r.status ?? r.signal}):\n${out}`;
}

describe("allow corpus: everyday commands are a rule allow and work in the sandbox", () => {
  corpus.forEach(({ label, command }, i) => {
    test(`${label}: ${JSON.stringify(command)}`, async () => {
      const problem = await attempt(command, i);
      assert.equal(problem, undefined, `${JSON.stringify(command)} -> ${problem}`);
    });
  });
});
