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
// Real tools: git, npm/node, cargo (through rustup), make, cc, python3, rg, jq, sed, awk, grep,
// coreutils. Where they are installed, cargo, npm, node, make and python3 work on a fixture with one
// dependency each, taken from what the machine already holds, with no network (round 4, finding
// 32):
//   - cargo: a crate without dependencies of its own from the user's registry cache (DEPENDENCY
//     below), pinned by a Cargo.lock written here. $CARGO_HOME points at the real cargo home as
//     $RUSTUP_HOME points at the real toolchain; in the sandbox both are read-only, so these
//     entries are what shows that a build works against a read-only registry. CARGO_NET_OFFLINE
//     is set, so a cargo that wanted the network would fail rather than use it.
//   - npm and node: a small package copied from this repository's own node_modules into the
//     fixture's, named in its package.json and package-lock.json; `npm test` is `node --test` on
//     a test that requires it, `npm run build` a script that requires it.
//   - python3: a local package (greetlib) and a unittest that imports it.
//   - make: a target that compiles a C file and its header with cc.
// The entries labelled `real cargo`, `real npm`, `real cc` and `real python3` need those, and
// are skipped, with the reason, where the tool or its dependency is missing.
// STAND-INS: pytest, pnpm, yarn, go and bun are scripts on PATH that print their arguments and
// exit 0 (none is installed where this was written). An entry that runs a stand-in proves the
// decision only: that the command is a rule allow and that the sandbox checks do not turn it
// into an ask. It does not show that the tool works in the sandbox (with a read-only module or
// build cache, say). uv and gradle have no entry at all.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/allow-corpus.test.mts;
// CORPUS_ONLY=<regex> runs the entries whose label or command matches.
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideShell, gitOnly, gitDirectories, gitWriteDirectories, gitMaintainDirectories, projectRoots, pushDestinations, sandboxBreaks, SessionState, takeMoment, usesSsh, type Decision, type Guard } from "../decide.ts";
// The session's moment is one per process, taken when decide.ts is loaded (round 4, B7-1). These
// tests make their files after that, so each SessionState here takes a moment of its own.
SessionState.moment = takeMoment;
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
const onPath = (tool: string) => spawnSync("sh", ["-c", `command -v ${tool}`], { encoding: "utf8" }).stdout.trim();
function rustupHome(): string | undefined {
  if (process.env.RUSTUP_HOME) return process.env.RUSTUP_HOME;
  const cargo = onPath("cargo");
  const guess = cargo && path.join(path.dirname(path.dirname(path.dirname(fs.realpathSync(cargo)))), ".rustup");
  return guess && fs.existsSync(guess) ? guess : undefined;
}

// The real tools' dependencies (round 4, finding 32). Each is looked up once, when the file is
// loaded, and nothing outside the fixture is written: the registry and node_modules are read.
//
// cargo: a crate from the registry cache of the cargo home the cargo on PATH belongs to, with
// its archive (for the lock file's checksum), its unpacked source and its index entry all there,
// so that cargo has nothing to fetch and nothing to unpack.
const DEPENDENCY = "itoa";
interface Crate {
  home: string;
  version: string;
  checksum: string;
}
function cachedCrate(): Crate | undefined {
  const cargo = onPath("cargo");
  if (!cargo) return undefined;
  const home = process.env.CARGO_HOME ?? path.dirname(path.dirname(fs.realpathSync(cargo)));
  const registry = path.join(home, "registry");
  let indexes: string[];
  try {
    indexes = fs.readdirSync(path.join(registry, "cache")).filter((name) => name.startsWith("index.crates.io-"));
  } catch {
    return undefined;
  }
  for (const index of indexes) {
    const versions = fs
      .readdirSync(path.join(registry, "cache", index))
      .map((name) => new RegExp(`^${DEPENDENCY}-(\\d+\\.\\d+\\.\\d+)\\.crate$`).exec(name)?.[1])
      .filter((v): v is string => v !== undefined)
      .sort();
    for (const version of versions.reverse()) {
      const unpacked = path.join(registry, "src", index, `${DEPENDENCY}-${version}`, "Cargo.toml");
      const entry = path.join(registry, "index", index, ".cache", DEPENDENCY.slice(0, 2), DEPENDENCY.slice(2, 4), DEPENDENCY);
      if (!fs.existsSync(unpacked) || !fs.existsSync(entry)) continue;
      const checksum = createHash("sha256").update(fs.readFileSync(path.join(registry, "cache", index, `${DEPENDENCY}-${version}.crate`))).digest("hex");
      return { home, version, checksum };
    }
  }
  return undefined;
}
// npm: a package of this repository's node_modules that needs no other and can be `require`d.
interface Package {
  name: string;
  version: string;
  from: string;
  lock: Record<string, unknown>;
}
function installedPackage(): Package | undefined {
  if (!onPath("npm") || !onPath("node")) return undefined;
  let locked: Record<string, Record<string, unknown>> = {};
  try {
    locked = JSON.parse(fs.readFileSync(path.join(ROOT, "package-lock.json"), "utf8")).packages ?? {};
  } catch {}
  for (const name of ["color-name", "balanced-match", "ms", "abbrev"]) {
    const from = path.join(ROOT, "node_modules", name);
    try {
      const manifest = JSON.parse(fs.readFileSync(path.join(from, "package.json"), "utf8"));
      if (Object.keys(manifest.dependencies ?? {}).length) continue;
      return { name, version: manifest.version, from, lock: locked[`node_modules/${name}`] ?? { version: manifest.version } };
    } catch {}
  }
  return undefined;
}
const crate = cachedCrate();
const dependency = installedPackage();
// Why an entry cannot run here, by the tool its label names; undefined when it can.
const MISSING: [RegExp, string | undefined][] = [
  [/^real cargo\b/, crate ? undefined : onPath("cargo") ? `no ${DEPENDENCY} crate in the cargo registry cache` : "cargo is not installed"],
  [/^real npm\b/, dependency ? undefined : "npm or node is not installed, or node_modules holds none of the packages looked for"],
  [/^real cc\b/, onPath("make") && onPath("cc") ? undefined : "make or cc is not installed"],
  [/^real python3\b/, onPath("python3") ? undefined : "python3 is not installed"],
];
const missing = (label: string) => MISSING.find(([pattern, reason]) => reason && pattern.test(label))?.[1];

before(() => {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  fs.writeFileSync(cover, "", { mode: 0o400 });
  for (const name of ["pytest", "pnpm", "yarn", "go", "bun"]) write(path.join(stubs, name), `#!/bin/sh\necho "stand-in ${name} $*"\n`), fs.chmodSync(path.join(stubs, name), 0o755);

  const p = fixture;
  write(path.join(p, "f"), "alpha one\nbeta two foo\ngamma three\ndelta four\nepsilon five\nzeta six\n");
  write(path.join(p, "index.ts"), "export const x = 1;\n// TODO\n");
  write(path.join(p, "src", "a.ts"), "export const foo = 1;\n");
  write(path.join(p, "src", "b.ts"), "export const b = 2;\n");
  // cargo: one dependency from the registry cache, pinned (name, version, checksum) by a lock
  // file, and a test of its own. Without the crate the program has no dependency, as before.
  write(path.join(p, "src", "main.rs"), crate ? `fn answer() -> String {\n    ${DEPENDENCY}::Buffer::new().format(42u8).to_string()\n}\n\nfn main() {\n    println!("hi {}", answer());\n}\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn formats() {\n        assert_eq!(super::answer(), "42");\n    }\n}\n` : 'fn main() {\n    println!("hi");\n}\n');
  write(path.join(p, "Cargo.toml"), '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n' + (crate ? `\n[dependencies]\n${DEPENDENCY} = "=${crate.version}"\n` : ""));
  if (crate) write(path.join(p, "Cargo.lock"), `# This file is automatically @generated by Cargo.\n# It is not intended for manual editing.\nversion = 3\n\n[[package]]\nname = "fixture"\nversion = "0.1.0"\ndependencies = [\n "${DEPENDENCY}",\n]\n\n[[package]]\nname = "${DEPENDENCY}"\nversion = "${crate.version}"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\nchecksum = "${crate.checksum}"\n`);
  const pkg = (name: string) => JSON.stringify({ name, version: "1.0.0", private: true, scripts: { test: "node -e \"console.log('tests pass')\"", build: "node -e \"require('fs').writeFileSync('dist.txt', 'built')\"" } }, null, 2) + "\n";
  // npm: the top package has one installed dependency; its test script is node's own runner on a
  // test that requires the dependency, its build script a program that requires it.
  if (dependency) {
    const top = JSON.parse(pkg("fixture"));
    top.scripts = { test: "node --test", build: "node build.cjs" };
    top.dependencies = { [dependency.name]: dependency.version };
    write(path.join(p, "package.json"), JSON.stringify(top, null, 2) + "\n");
    write(path.join(p, "package-lock.json"), JSON.stringify({ name: "fixture", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "fixture", version: "1.0.0", dependencies: top.dependencies }, [`node_modules/${dependency.name}`]: dependency.lock } }, null, 2) + "\n");
    fs.mkdirSync(path.join(p, "node_modules"), { recursive: true });
    fs.cpSync(dependency.from, path.join(p, "node_modules", dependency.name), { recursive: true });
    write(path.join(p, "build.cjs"), `const dependency = require(${JSON.stringify(dependency.name)});\nif (!dependency) throw Error("the dependency is empty");\nrequire("fs").writeFileSync("dist.txt", "built with " + ${JSON.stringify(dependency.name)});\n`);
    write(path.join(p, "tests", "dependency.test.cjs"), `const test = require("node:test");\nconst assert = require("node:assert/strict");\ntest("the dependency loads", () => assert.ok(require(${JSON.stringify(dependency.name)})));\n`);
  } else write(path.join(p, "package.json"), pkg("fixture"));
  // python3: a local package and a unittest that imports it (`python3 -m unittest` finds it from
  // the top: tests/ is a package).
  write(path.join(p, "greetlib", "__init__.py"), 'def greet(name):\n    return "hello " + name\n');
  write(path.join(p, "tests", "__init__.py"), "");
  write(path.join(p, "tests", "test_greet.py"), 'import unittest\n\nfrom greetlib import greet\n\n\nclass GreetTest(unittest.TestCase):\n    def test_greet(self):\n        self.assertEqual(greet("x"), "hello x")\n\n\nif __name__ == "__main__":\n    unittest.main()\n');
  // make: a target that compiles a C file with its header (`all` stays a plain recipe, so the
  // entries that run it need no compiler).
  write(path.join(p, "csrc", "greet.h"), '#define GREETING "hello"\n');
  write(path.join(p, "csrc", "hello.c"), '#include <stdio.h>\n#include "greet.h"\n\nint main(void) {\n    puts(GREETING);\n    return 0;\n}\n');
  const ipcPackage = JSON.parse(pkg("ipc-fixture"));
  ipcPackage.scripts.build = "node build.cjs";
  write(path.join(p, "ipc", "package.json"), JSON.stringify(ipcPackage));
  write(path.join(p, "ipc", "build.cjs"), 'const fs = require("fs"); const p = "/dev/shm/automode-build-" + process.pid; fs.writeFileSync(p, "ok"); if (fs.readFileSync(p, "utf8") !== "ok") throw Error("shared memory"); fs.unlinkSync(p); require("child_process").execFileSync(process.execPath, ["-e", "process.exit(0)"]);\n');
  write(path.join(p, "web", "package.json"), pkg("web"));
  write(path.join(p, "x", "package.json"), pkg("x"));
  write(path.join(p, "Makefile"), "all:\n\t@echo built > build.txt\n\nhello: csrc/hello.c csrc/greet.h\n\tcc -Wall -Icsrc -o hello csrc/hello.c\n");
  write(path.join(p, "dir", "readme.md"), "# readme\n");
  write(path.join(p, "dir", "notes.md"), "# notes\n");
  write(path.join(p, "data.json"), '{"a": "x"}\n');
  write(path.join(p, "g"), "one\n");
  write(path.join(p, ".gitignore"), "target/\nnode_modules/\n__pycache__/\nhello\n");
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

// (Round 4, finding 32: `node --test` and `node --test tests/dependency.test.cjs` are not in the
// corpus. Neither is a rule allow: the rules leave both to the model ("runs code with node"),
// while `node build.cjs`, `npm test` (whose script is `node --test`) and `python3 -m unittest`
// are allows. Reported to the maintainer; no entry until that is decided.)
// (Round 4, finding 28, third pass: the corpus held four `npx` forms, `npx tsc --noEmit`,
// `npx eslint .`, `npx vitest run` and `npx --no-install tsc --noEmit`, as rule allows. By the
// maintainer's decision no `npx` is a rule allow: they go to the model, and
// test/d-fixes.test.mts holds them.)
// A project script the session has not written (round 4, finding 4).
const projectScript = (dir: string) => {
  write(path.join(dir, "scripts", "build.sh"), "#!/bin/sh\necho built\n");
  fs.chmodSync(path.join(dir, "scripts", "build.sh"), 0o755);
  // Tracked, as the rules require of a project script; the fixture's staged change stays staged.
  git(dir, "add", "scripts/build.sh");
  git(dir, "commit", "-qm", "build script", "--", "scripts/build.sh");
};
// A submodule that git keeps in its own work tree (`lib/.git` a directory), with something new
// to fetch for it and for the project (round 4, finding 21).
const submoduleInTree = (dir: string) => {
  const upstream = `${dir}-lib-upstream`;
  git(base, "init", "-q", "-b", "main", upstream);
  git(upstream, "commit", "-q", "--allow-empty", "-m", "one");
  git(base, "clone", "-q", upstream, path.join(dir, "lib"));
  git(dir, "-c", "protocol.file.allow=always", "submodule", "add", "-q", upstream, "lib");
  git(dir, "commit", "-qm", "a submodule", "--", ".gitmodules", "lib");
  git(dir, "push", "-q", "origin", `HEAD:refs/heads/with-lib-${path.basename(dir)}`);
  git(upstream, "commit", "-q", "--allow-empty", "-m", "two");
};
// Per-command setup in the fresh copy, before the decision.
const SETUP: Record<string, (dir: string) => void> = {
  "git fetch --recurse-submodules origin": submoduleInTree,
  "git -C lib status --short": submoduleInTree,
  // Round 4, finding 21: the repositories a git-only call works in.
  "git -C nested commit -m nested": (dir) => {
    const nested = path.join(dir, "nested");
    fs.mkdirSync(nested);
    git(nested, "init", "-q");
    write(path.join(nested, "new"), "new\n");
    git(nested, "add", "new");
  },
  "git -C linked add new": (dir) => {
    git(dir, "worktree", "add", "--detach", "-q", "linked");
    write(path.join(dir, "linked", "new"), "new\n");
  },
  // A submodule whose git directory is under the project's `.git/modules`.
  "git -C sub commit -m submodule": (dir) => {
    const sub = path.join(dir, "sub");
    fs.mkdirSync(sub);
    git(sub, "init", "-q");
    fs.mkdirSync(path.join(dir, ".git", "modules"), { recursive: true });
    fs.renameSync(path.join(sub, ".git"), path.join(dir, ".git", "modules", "sub"));
    write(path.join(sub, ".git"), "gitdir: ../.git/modules/sub\n");
    write(path.join(sub, "new"), "new\n");
    git(sub, "add", "new");
  },
  // What husky sets, and a worktree beside the project (round 4, finding 21).
  "git status --branch --short": (dir) => {
    // As husky lays it out: the project's hook is tracked, `.husky/_` is made at install.
    write(path.join(dir, ".husky", "pre-commit"), "npm test\n");
    git(dir, "add", ".husky/pre-commit");
    git(dir, "commit", "-qm", "husky", "--", ".husky/pre-commit");
    write(path.join(dir, ".husky", "_", "pre-commit"), '#!/bin/sh\n. "$(dirname "$0")/h"\n');
    write(path.join(dir, ".husky", "_", ".gitignore"), "*\n");
    fs.chmodSync(path.join(dir, ".husky", "_", "pre-commit"), 0o755);
    git(dir, "config", "core.hooksPath", ".husky/_");
    git(dir, "worktree", "add", "-q", "-b", "feature", `${dir}-feature`);
  },
  "git status --porcelain=v1": (dir) => {
    write(path.join(dir, "vendor/stale/.git"), "gitdir: ../../.git/modules/gone\n");
    fs.mkdirSync(path.join(dir, "testdata/x/.git"), { recursive: true });
  },
  // `git log -1 secrets.json` itself asks, before and after this round: the rules read a word
  // named like a credential file as a file. What must work is git reading the ref.
  "git branch --list | grep -c secrets": (dir) => void git(dir, "branch", "secrets.json"),
  // Round 4, group B.
  "./scripts/build.sh": projectScript,
  "bash scripts/build.sh": projectScript,
  "sed -i 's/readme/README/' dir/readme.md && cd scripts && ./build.sh": projectScript,
  // Round 4, group D.
  "git add café.txt": (dir) => write(path.join(dir, "café.txt"), "au lait\n"),
  "rg fish -c src": (dir) => write(path.join(dir, "src", "pets.md"), "one fish, two fish\n"),
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

// A submodule added for real (`git submodule add` from a repository beside the project; git keeps
// its git directory under the project's `.git/modules`), with a change to a tracked file and a
// new file in its work tree (round 4, finding 21, fifth pass).
const submoduleAdded = (dir: string) => {
  const upstream = `${dir}-subm-upstream`;
  git(base, "init", "-q", "-b", "main", upstream);
  write(path.join(upstream, "tracked"), "one\n");
  git(upstream, "add", "tracked");
  git(upstream, "commit", "-qm", "one");
  git(dir, "-c", "protocol.file.allow=always", "submodule", "add", "-q", upstream, "subm");
  git(dir, "commit", "-qm", "a submodule", "--", ".gitmodules", "subm");
  assert.ok(fs.lstatSync(path.join(dir, "subm", ".git")).isFile());
  write(path.join(dir, "subm", "tracked"), "two\n");
  write(path.join(dir, "subm", "new"), "new\n");
};
// A submodule added for real and then removed with `git rm`: git keeps `.git/modules/subm`,
// whose `core.worktree` names a directory that is gone (round 4, finding 21, sixth pass).
const submoduleRemoved = (dir: string) => {
  submoduleAdded(dir);
  git(dir, "rm", "-qf", "subm");
  git(dir, "commit", "-qm", "remove the submodule", "--", ".gitmodules", "subm");
  assert.ok(fs.existsSync(path.join(dir, ".git", "modules", "subm", "HEAD")) && !fs.existsSync(path.join(dir, "subm")));
};
// Seventh pass: a cloned submodule under `submodule.recurse`; a link into a directory of the
// project; a linked worktree inside the project with a second one beside it, and a change in it.
const recursing = (dir: string) => {
  submoduleAdded(dir);
  git(dir, "config", "submodule.recurse", "true");
};
const linkedDirectory = (dir: string) => {
  fs.mkdirSync(path.join(dir, "linked", "inner"), { recursive: true });
  fs.symlinkSync(path.join(dir, "linked", "inner"), path.join(dir, "link"));
};
const linkedWorktree = (dir: string) => {
  submoduleAdded(dir);
  git(dir, "worktree", "add", "-q", "-b", "wt-branch", "wt");
  git(dir, "worktree", "add", "-q", "-b", "wt-other", "wt-other");
  fs.appendFileSync(path.join(dir, "wt", "f"), "changed in the worktree\n");
};
// Eighth pass: a linked worktree whose own submodule is populated (git keeps it under the
// worktree's admin directory), with a change in it; a merge stopped on a conflict.
const linkedWorktreeWithSubmodule = (dir: string) => {
  linkedWorktree(dir);
  git(path.join(dir, "wt"), "-c", "protocol.file.allow=always", "submodule", "update", "-q", "--init");
  assert.ok(fs.existsSync(path.join(dir, ".git", "worktrees", "wt", "modules", "subm", "HEAD")));
  write(path.join(dir, "wt", "subm", "new"), "new\n");
};
const mergeStopped = (dir: string) => {
  git(dir, "reset", "-q", "--hard");
  git(dir, "checkout", "-q", "-b", "topic");
  write(path.join(dir, "conflict.txt"), "topic\n");
  git(dir, "add", "conflict.txt");
  git(dir, "commit", "-qm", "topic");
  git(dir, "checkout", "-q", "main");
  write(path.join(dir, "conflict.txt"), "main\n");
  git(dir, "add", "conflict.txt");
  git(dir, "commit", "-qm", "main side");
  assert.notEqual(spawnSync("git", ["-C", dir, "merge", "-q", "topic"], { encoding: "utf8" }).status, 0, "the merge did not stop on its conflict");
};
// Entries told apart by their label (the same command stands elsewhere in the corpus with
// another setup): the setup, and the shell's directory below the project.
const PLACED: Record<string, { setup: (dir: string) => void; cwd?: string }> = {
  "r4 21: after git rm of a submodule: a status": { setup: submoduleRemoved },
  "r4 21: after git rm of a submodule: a fetch": { setup: submoduleRemoved },
  "r4 21: after git rm of a submodule: an edit in place": { setup: submoduleRemoved },
  "r4 21: in a submodule's work tree: a commit of what changed": { setup: submoduleAdded, cwd: "subm" },
  "r4 21: in a submodule's work tree: everything staged": { setup: submoduleAdded, cwd: "subm" },
  "r4 21: in a submodule's work tree: a gc": { setup: submoduleAdded, cwd: "subm" },
  "r4 21: in a submodule's work tree: a stash": { setup: submoduleAdded, cwd: "subm" },
  "r4 21: in a submodule's work tree: a status": { setup: submoduleAdded, cwd: "subm" },
  // Git calls that go into submodules and work in the sandbox (fifth pass).
  "r4 21: a pull that updates a submodule kept in its own work tree": {
    setup: (dir) => {
      submoduleInTree(dir);
      // The remote gets a commit that moves the submodule; the project stays one behind.
      git(path.join(dir, "lib"), "pull", "-q");
      git(dir, "commit", "-qm", "move the submodule", "--", "lib");
      git(dir, "push", "-q", "origin", "HEAD:refs/heads/moved-lib");
      git(dir, "reset", "-q", "--soft", "HEAD~1");
      git(dir, "reset", "-q", "--", "lib");
      git(path.join(dir, "lib"), "checkout", "-q", "HEAD~1");
    },
  },
  "r4 21: a new branch where submodule.recurse is set": {
    setup: (dir) => {
      submoduleAdded(dir);
      git(dir, "config", "submodule.recurse", "true");
    },
  },
  // Seventh pass.
  "r4 21: a reset that keeps local changes where submodule.recurse is set": { setup: recursing },
  "r4 21: a reset of the index where submodule.recurse is set": { setup: recursing },
  "r4 21: into a linked directory and back: everything staged": { setup: linkedDirectory },
  "r4 21: into a linked directory and back: a status": { setup: linkedDirectory },
  "r4 21: a status in a directory the kernel reaches through a link": { setup: linkedDirectory },
  "r4 21: in a linked worktree: a status": { setup: linkedWorktree, cwd: "wt" },
  "r4 21: in a linked worktree: a commit of what changed": { setup: linkedWorktree, cwd: "wt" },
  "r4 21: in a linked worktree: a stash": { setup: linkedWorktree, cwd: "wt" },
  "r4 21: in a linked worktree: a gc": { setup: linkedWorktree, cwd: "wt" },
  "r4 21: in a linked worktree: the worktrees": { setup: linkedWorktree, cwd: "wt" },
  "r4 21: in a linked worktree: a fetch": { setup: linkedWorktree, cwd: "wt" },
  "r4 21: in a submodule's work tree: a fetch": { setup: submoduleAdded, cwd: "subm" },
  "r4 21: in a submodule's work tree: a new branch": { setup: submoduleAdded, cwd: "subm" },
  "r4 25: a fetch where the repository sets push.default and submodule.recurse": {
    setup: (dir) => {
      git(dir, "config", "push.default", "current");
      git(dir, "config", "submodule.recurse", "true");
      git(dir, "config", "push.recurseSubmodules", "check");
      git(dir, "config", "fetch.recurseSubmodules", "on-demand");
    },
  },
  // Eighth pass.
  "r4 21: to the top of the repository from a directory below it, then a commit": { setup: () => {}, cwd: "src" },
  "r4 21: to the top of the repository from a directory below it, then everything staged": { setup: () => {}, cwd: "src" },
  "r4 21: a status here and in a submodule, on one line": { setup: submoduleAdded },
  "r4 21: a status here and the log of a submodule, on lines": { setup: submoduleAdded },
  "r4 21: in a linked worktree: a status, and its submodule's changes staged": { setup: linkedWorktreeWithSubmodule, cwd: "wt" },
  "r4 21: a merge that stopped on a conflict, given up": { setup: mergeStopped },
  // The plan makes `.husky/_` to protect it; the decision after it must not pause (C4 F5).
  "r4 21: a status in a husky project whose hooks path is not there yet": { setup: (dir) => void git(dir, "config", "core.hooksPath", ".husky/_") },
  "r4 21: a pull where only the fetch goes into submodules": {
    setup: (dir) => {
      submoduleAdded(dir);
      git(dir, "config", "fetch.recurseSubmodules", "true");
    },
  },
};

// Commands that are decided a second time in the same session after they ran.
const AGAIN = new Set(["git status --branch --short"]);

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
async function attempt(command: string, index: number, label: string): Promise<string | undefined> {
  const project = path.join(base, "work", String(index));
  fs.mkdirSync(path.dirname(project), { recursive: true });
  execFileSync("cp", ["-a", fixture, project]);
  const placed = Object.hasOwn(PLACED, label) ? PLACED[label] : undefined;
  (placed?.setup ?? SETUP[command])?.(project);
  // The shell's directory: the project, or a directory below it.
  const dir = placed?.cwd ? path.join(project, placed.cwd) : project;
  const session = new SessionState(project);
  const d = await decideShell(guard, session, dir, command);
  if (d.effect !== "allow" || d.by !== "rules") return describeDecision(d);
  // An allow is an allow of the printed text (round 4, finding 16): the sandbox checks read it,
  // and the wrapper runs it in place of the command opencode hands over.
  const run = d.printed;
  if (run === undefined) return "allowed, but the decision carries no printed text";
  const broken = sandboxBreaks(run, dir, session);
  if (broken) return `allowed, then asks because it cannot work in the sandbox: ${broken}`;
  const p = plan({ projectRoots: projectRoots(session), allowedPaths: [], cacheDirs: [], gitWritable: gitOnly(run), gitCwds: gitDirectories(run, dir), gitWriteCwds: gitWriteDirectories(run, dir), gitMaintainCwds: gitMaintainDirectories(run, dir), gitPushTo: pushDestinations(run, dir), exposeSsh: usesSsh(run, dir, session), keepSockets: [], showPaths: [], hidePaths: [], project });
  if (p.problem) return `allowed, then asks because the sandbox could not be prepared: ${p.problem}`;
  const rustup = rustupHome();
  // No network for cargo, whatever the fixture holds; and the real cargo home, for its registry
  // cache (read-only in the sandbox). CORPUS_NO_CARGO_HOME=1 leaves cargo with the throwaway
  // home's empty one: the `real cargo` entries then fail, which is what shows they use the cache.
  const env: Record<string, string | undefined> = { ...process.env, PATH: `${stubs}:${process.env.PATH}`, CARGO_NET_OFFLINE: "true", ...(rustup ? { RUSTUP_HOME: rustup } : {}), ...(crate && !process.env.CORPUS_NO_CARGO_HOME ? { CARGO_HOME: crate.home } : {}) };
  delete env.NODE_TEST_CONTEXT;
  const { keep } = envKept(env, []);
  if (!keep.includes("CARGO_NET_OFFLINE")) return "the sandbox would drop CARGO_NET_OFFLINE: cargo could use the network";
  Object.assign(env, {
    AUTOMODE_ENV_KEEP: keep.join("\n"),
    AUTOMODE_SHELL: "/bin/bash",
    AUTOMODE_COMMAND: run,
    AUTOMODE_RW: p.rw.join("\n"),
    AUTOMODE_RO: p.ro.join("\n"), AUTOMODE_REOPEN: p.reopen.join("\n"),
    AUTOMODE_HIDE: p.hide.join("\n"),
    AUTOMODE_PIN: p.pin.join("\n"),
    AUTOMODE_TMPFS: p.tmpfs.join("\n"),
    AUTOMODE_COVER: cover,
  });
  // stdin is /dev/null, as opencode gives it (rg with no path then searches the directory).
  const r = spawnSync(WRAPPER, ["-c", command], { cwd: dir, env, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 180_000 });
  if (r.status === 0) {
    if (!AGAIN.has(command)) return undefined;
    // The same command once more in the same session: what the plan made must not pause it.
    const second = await decideShell(guard, session, dir, command);
    return second.effect === "allow" && second.by === "rules" ? undefined : `allowed and ran, then the second time: ${describeDecision(second)}`;
  }
  const out = `${r.stdout ?? ""}${r.stderr ?? ""}`.trim().split("\n").slice(-8).join("\n");
  return `allowed, but it failed under the plan (exit ${r.status ?? r.signal}):\n${out}`;
}

const only = process.env.CORPUS_ONLY ? new RegExp(process.env.CORPUS_ONLY) : undefined;
describe("allow corpus: everyday commands are a rule allow and work in the sandbox", () => {
  corpus.forEach(({ label, command }, i) => {
    if (only && !only.test(label) && !only.test(command)) return;
    test(`${label}: ${JSON.stringify(command)}`, { skip: missing(label) }, async () => {
      const problem = await attempt(command, i, label);
      assert.equal(problem, undefined, `${JSON.stringify(command)} -> ${problem}`);
    });
  });
});
