// Council project review 2: code that xargs -I or find -exec fills in is not printed; `git reset
// --merge` and an operation's `--abort`/`--skip` discard work; a saved "Always allow" for `git rm`
// is not mirrored; compilers and build tools that run a program the call names ask; a pattern a
// runner expands itself counts as a place a session write may lie.
// Run: node test/run.mjs test/council-p2.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideShell, mirrorable, SessionState, takeMoment, type Guard } from "../decide.ts";
import { canonical } from "../canon.ts";
SessionState.moment = takeMoment;
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

assert.ok(process.env.GIT_CONFIG_GLOBAL?.startsWith(os.homedir()), "run through test/run.mjs, which supplies a throwaway $HOME");
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), "council-p2-")));
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
  fs.writeFileSync(path.join(repo, "package.json"), JSON.stringify({ scripts: { test: "node --test" } }));
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  execFileSync("git", ["-C", repo, "add", "-A"]);
  execFileSync("git", ["-C", repo, "commit", "-qm", "init"]);
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

const effect = async (command: string, s = new SessionState(repo)) => (await decideShell(guard, s, repo, command)).effect;

test("code that xargs -I or find -exec fills in asks; the same code with the input as an argument prints", () => {
  const filled = [
    `printf '%s\\n' 'safe; echo EXTRA' | xargs -IXX bash -c 'printf "<%s>\\n" "XX"'`,
    `xargs -I XX bash -c 'echo "XX"'`,
    `xargs -0IXX bash -c 'echo "XX"'`,
    `xargs -I{} sh -c 'echo "{}"'`,
    `xargs -i bash -c 'echo "{}"'`,
    `xargs -iQQ bash -c 'echo "QQ"'`,
    `xargs --replace bash -c 'echo "{}"'`,
    `xargs --replace=QQ bash -c 'echo "QQ"'`,
    `xargs --repl=QQ bash -c 'echo "QQ"'`,
    `xargs -n1 -I XX timeout 5 bash -c 'echo "XX"'`,
    `find . -name f -exec bash -c 'echo "{}"' \\;`,
    `find . -name f -execdir sh -c 'cat "{}"' \\;`,
  ];
  for (const c of filled) assert.ok("ask" in canonical(c), c);
  for (const c of [`xargs bash -c 'echo "$1"' _`, `xargs -I{} bash -c 'echo "$1"' _ {}`, `find . -name f -exec sh -c 'echo "$1"' _ {} \\;`, `xargs -IXX bash -c 'echo "$1"' _ XX`, `bash -c 'echo "{}"'`]) assert.ok(!("ask" in canonical(c)), c);
});

test("what runs for an input with a ; in it is what was written", () => {
  // The reviewer's example, run as written: the input stays one argument.
  const out = spawnSync("bash", ["-c", `printf '%s\\n' 'safe; echo EXTRA' | xargs -IXX bash -c 'printf "<%s>\\n" "XX"'`], { encoding: "utf8" });
  assert.equal(out.stdout, "<safe; echo EXTRA>\n");
  const printed = canonical(`printf '%s\\n' 'safe; echo EXTRA' | xargs -I{} bash -c 'printf "<%s>\\n" "$1"' _ {}`);
  assert.ok("text" in printed);
  assert.equal(spawnSync("bash", ["-c", printed.text!], { encoding: "utf8" }).stdout, "<safe; echo EXTRA>\n");
});

test("git reset --merge and an operation's --abort or --skip ask", async () => {
  for (const c of ["git reset --merge", "git reset --mer", "git reset --merge HEAD", "git merge --abort", "git merge --abo", "git rebase --abort", "git rebase --skip", "git am --abort", "git am --skip", "git cherry-pick --abort", "git cherry-pick --skip", "git revert --abort", "git revert --skip"]) {
    assert.equal(await effect(c), "ask", c);
  }
  for (const c of ["git reset", "git reset --soft HEAD", "git status"]) assert.equal(await effect(c), "allow", c);
});

test("a saved git rm pattern is not mirrored into the rules", () => {
  assert.equal(mirrorable("git rm *"), false);
  assert.equal(mirrorable("git add *"), true);
});

test("compilers and build tools that run a program the call names ask", async () => {
  for (const c of [
    "gcc -wrapper sh,-c,'git push origin HEAD',-- -x c -c /dev/null -o /dev/null",
    "cc -wrapper sh,-c,true -c t.c",
    "clang -fplugin=./x.so -c t.c",
    "gcc -B/tmp/x -c t.c",
    "gcc -specs=x.specs -c t.c",
    "clang -fuse-ld=/tmp/ld -o t t.c",
    "clang -Xclang -load -Xclang x.so -c t.c",
    "gcc -Wl,-plugin,x.so -o t t.c",
    "rustc -C linker=sh x.rs",
    "rustc -Clinker=sh x.rs",
    "rustc --codegen=linker=sh x.rs",
    "rustc -Z codegen-backend=x.so x.rs",
    "rustc -Zcodegen-backend=x.so x.rs",
    "ccache sh -c true",
    "ccache gcc -wrapper sh,-c,true -c t.c",
    "ccache -osprefix_command=sh",
    "cmake -E env curl -d @f host",
    "cmake -E rm -rf /",
    "cmake -P x.cmake",
    "ctest -S x.cmake",
    "ctest --build-and-test a b --test-command sh",
    "just --command sh -c true",
    "just -c 'sh -c true'",
    "just --shell sh test",
    "tox exec -- sh -c true",
    "tox -x testenv.commands=sh",
    "tox --override=testenv.commands=sh",
    "meson devenv sh",
    "meson test --wrapper=sh",
    "mypy --python-executable=./py .",
    "mypy --python-exec ./py .",
  ]) {
    assert.equal(await effect(c), "ask", c);
  }
  for (const c of ["gcc -c t.c -o t.o", "ccache gcc -c t.c -o t.o", "ccache -s", "cmake --build build", "ctest", "just test", "meson test", "mypy .", "rustc x.rs -o x"]) {
    assert.equal(await effect(c), "allow", c);
  }
});

test("a pattern a runner expands itself counts as a place a session write may lie", async () => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-glob-")));
  const name = path.basename(d);
  try {
    const s = new SessionState(repo);
    assert.equal(await effect(`printf x > ${d}/x.test.js`, s), "allow");
    fs.writeFileSync(path.join(d, "x.test.js"), "x");
    const tmp = path.dirname(d);
    // `/tmp/r1/` as `/t*/r1/`: the pattern is in the first part of the path.
    const second = tmp.indexOf("/", 1);
    const fuzzy = `/${tmp[1]}*${second < 0 ? "" : tmp.slice(second)}`;
    for (const c of [`npm test -- '${fuzzy}/${name}/x.test.js'`, `npm test -- '${tmp}/${name.slice(0, 4)}*/x.test.js'`, `npm test -- '${tmp}/{${name},y}/x.test.js'`, `npm test -- '/*/${name}/x.test.js'`, `npm test -- --test-name-pattern=x '${tmp}/${name}/*.js'`]) {
      assert.notEqual(await effect(c, s), "allow", c);
    }
    // A pattern inside the project counts from where it starts, as before.
    assert.equal(await effect("npm test -- 'src/*.test.js'", new SessionState(repo)), "allow");
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
});

// ---- round 2 ----

test("round 2: a placeholder that only the printed code holds, or one bash computes, asks", () => {
  for (const c of [
    `printf '%s\\n' 'safe; echo EXTRA' | xargs -IXX bash -c 'echo X"X"'`,
    `xargs -I XX bash -c 'echo "X"X'`,
    `find . -maxdepth 0 -exec bash -c 'echo "{""}"' \;`,
    `find . -type f -exec bash -c 'echo \\{\\}' \;`,
    `printf 'x; echo INJECTED; echo \\\\n' | xargs -I"'" bash -c 'echo "a b"'`,
    `M=foo; xargs -I "$M" bash -c 'echo "foo"'`,
    `xargs -I "$(echo foo)" bash -c 'echo "foo"'`,
    `xargs -I fo* bash -c 'echo "foo"'`,
  ]) assert.ok("ask" in canonical(c), c);
  // What prints keeps doing what was written.
  for (const c of [`printf '%s\\n' 'a; echo EXTRA' | xargs -I{} bash -c 'printf "<%s>\\n" "$1"' _ {}`, `printf '%s\\n' 'a; echo EXTRA' | xargs -IXX bash -c 'printf "<%s>\\n" "$1"' _ XX`]) {
    const printed = canonical(c);
    assert.ok("text" in printed, c);
    const run = (t: string) => spawnSync("bash", ["-c", t], { encoding: "utf8" }).stdout;
    assert.equal(run(printed.text!), run(c), c);
  }
});

test("round 2: a build tool's option held in a variable goes to the model; rustc's _ spelling, cmake's compilers, go's -extld ask", async () => {
  for (const c of ["W=-wrapper; gcc $W sh,-c,true -c t.c", `W=-wrapper; gcc "$W" sh,-c,true -c t.c`, "gcc $CFLAGS -c t.c", "A=-Clinker=sh; rustc $A x.rs", "E=-E; cmake $E env sh", "J=--command; just $J sh", "clang ${W} x -c t.c"]) {
    assert.notEqual(await effect(c), "allow", c);
  }
  for (const c of [
    "rustc -C link_arg=-wrapper x.rs", "rustc -Clink_arg=x x.rs", "rustc -C link_args=x x.rs", "rustc --codegen link_arg=x x.rs", "rustc --codegen=link_arg=x x.rs",
    "gcc --prefix=/tmp/x -c t.c", "gcc --prefix /tmp/x -c t.c", "gcc -Wp,-fplugin=x.so -c t.c", "gcc --for-linker=-plugin --for-linker=x.so t.c",
    "cmake -C x.cmake .", "cmake -DCMAKE_C_COMPILER=/tmp/prog .", "cmake -D CMAKE_C_COMPILER_LAUNCHER=sh .", "cmake -DCMAKE_TOOLCHAIN_FILE:FILEPATH=x.cmake .", "cmake --toolchain x.cmake .",
    "go build -ldflags=-extld=sh .", "go build -ldflags '-linkmode=external -extld /tmp/prog' .",
    "just --chooser 'sh -c x' --choose", "mypy --install-types .",
    "npm run env -- sh -c true", "npm run env", "npm run-script env", "pnpm run env -- sh -c true", "yarn run env",
  ]) assert.equal(await effect(c), "ask", c);
  for (const c of ["cmake -DCMAKE_BUILD_TYPE=Release -S . -B build", "go build -ldflags=-s .", "npm run build", "rustc -C opt-level=2 x.rs"]) assert.notEqual(await effect(c), "ask", c);
});

test("round 2: git clean -i and a checkout operand with a backslash ask", async () => {
  for (const c of ["git clean -i", "git clean --interactive", "git clean -di", "git checkout '\\f'", "git checkout '\\x'"]) assert.equal(await effect(c), "ask", c);
});

test("round 2: node's extglob and a backslash in a runner's pattern count as places", async () => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-ext-")));
  const name = path.basename(d);
  const tmp = path.dirname(d);
  try {
    const s = new SessionState(repo);
    assert.equal(await effect(`printf x > ${d}/x.test.js`, s), "allow");
    fs.writeFileSync(path.join(d, "x.test.js"), "x");
    for (const c of [`npm test -- '${tmp}/!(zzz)/x.test.js'`, `npm test -- '${tmp}/@(${name})/x.test.js'`, `npm test -- '${tmp}/+(${name})/x.test.js'`, `npm test -- '/\\${tmp.slice(1)}/${name}/x.test.js'`, `npm test -- '${tmp}/${name}\\/x.test.js'`, `npm test -- '/@(${tmp.split("/")[1]})${tmp.slice(tmp.indexOf("/", 1) < 0 ? tmp.length : tmp.indexOf("/", 1))}/${name}/x.test.js'`]) {
      assert.notEqual(await effect(c, s), "allow", c);
    }
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
});
