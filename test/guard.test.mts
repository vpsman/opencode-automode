// Unit tests for guard.ts: the syntax check, the strict tokenizer and glob expansion.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { expandWord, gitCall, gitProblem, single, strict, unmodelled } from "../guard.ts";

describe("unmodelled", () => {
  for (const c of [
    "echo $'a'", "echo $\"a\"", "ls >&2#x", "ls 2>&1x", "echo a#b", "cat <<E\"OF\"\nx\nEOF", "cat <<\\EOF\nx\nEOF", "cat <<EOF\nx\n EOF\n", "cat <<-EOF\nx\n  EOF\n",
    "cat <<EOF", "echo `a \\` b`", "echo $(echo \")\")", "echo ${x@P}", "echo 'unterminated", "echo \"unterminated", "cat <<EOF\n$(echo ')')\nEOF",
  ]) test(`asks: ${JSON.stringify(c)}`, () => assert.ok(unmodelled(c), c));
  for (const c of [
    "echo a # b", "# only a comment", "echo 'a#b' \"$x#y\"", "echo $# ${#x} ${x#y} ${x%%z}", "ls 2>&1 | head", "ls >&2", "cat <<EOF\nx # y $'z'\nEOF\nls", "cat <<-'EOF'\n\tx\n\tEOF",
    "a <<A <<B\n1\nA\n2\nB\necho done", "echo $(ls (a) 2>/dev/null) `date`", "cat <<<word", "echo \"$(date)\" '$(not run)'", "for f in a b; do echo $f; done",
  ]) test(`reads: ${JSON.stringify(c)}`, () => assert.equal(unmodelled(c), undefined, c));
});

describe("strict", () => {
  test("plain words, quotes and separators", () => {
    assert.deepEqual(strict("git commit -m 'a (b) #1' && git push origin feature/x"), [["git", "commit", "-m", "a (b) #1"], ["git", "push", "origin", "feature/x"]]);
    assert.deepEqual(strict('echo "two words" a\'b\'c;'), [["echo", "two words", "abc"]]);
    assert.deepEqual(strict("df -h | grep sda 2>/dev/null || true", { pipes: true, nullRedirects: true }), [["df", "-h"], ["grep", "sda"], ["true"]]);
    assert.deepEqual(strict("ls >/dev/null 2>&1", { nullRedirects: true }), [["ls"]]);
  });
  for (const c of [
    "", "ls &&", "ls ;; ls", "ls | cat", "ls > f", "ls 2>/dev/null", "echo $x", "echo `x`", "echo $(x)", "echo *", "echo a{b,c}", "echo a\\ b", "echo \"$x\"", "echo \"a\\\"b\"", "ls & id",
    "ls\nid", "FOO=1 ls", "echo #x", "echo (x)", "echo 'x", "ls <f", "echo !x", "ls >/dev/nullx",
  ]) test(`refuses: ${JSON.stringify(c)}`, () => assert.equal(strict(c), undefined));
  test("null redirects only where asked for, and only to /dev/null", () => {
    assert.equal(strict("ls > /tmp/x", { nullRedirects: true }), undefined);
    assert.equal(strict("ls 2>&3", { nullRedirects: true }), undefined);
  });
});

describe("single", () => {
  test("one command, after cd and under timeout", () => {
    assert.deepEqual(single("cd sub && timeout 15 ssh lab uptime", "/work"), { dir: "/work/sub", argv: ["ssh", "lab", "uptime"], texts: ["timeout 15 ssh lab uptime", "ssh lab uptime"] });
    assert.equal(single("cd", "/work"), undefined);
    assert.equal(single("cd a b && ls", "/work"), undefined);
    assert.equal(single("ls && cd x", "/work"), undefined);
    assert.equal(single("ls; id", "/work"), undefined);
    assert.equal(single("cd ~root && ls", "/work"), undefined);
  });
});

describe("git calls", () => {
  test("global options come from an allowlist", () => {
    assert.deepEqual(gitCall(["-C", "x", "--no-pager", "-c", "user.name=a", "log", "-1"]), { dirs: ["x"], sub: "log", rest: ["-1"] });
    for (const words of [["--namespace", "status", "push"], ["--git-dir=.git", "status"], ["-c", "core.pager=x", "log"], ["--exec-path=/x", "status"], ["-p", "log"], ["--config-env=a=b", "log"]])
      assert.equal(typeof gitCall(words), "string", words.join(" "));
  });
  test("found wherever the word git is", () => {
    for (const c of ["xargs git --namespace status push", "echo $(git --namespace a b)", "env X=1 git --work-tree=/ status", "sh -c \"git --namespace status push\"", "git fetch --upload-pac=x ."])
      assert.ok(gitProblem(c), c);
    for (const c of ["git status", "git commit -m 'use git status'", "grep -r git .", "git log --exclude=x"]) assert.equal(gitProblem(c), undefined, c);
    // The price of reading quoted text as a possible command: a message that spells out a git
    // option asks.
    assert.ok(gitProblem("git commit -m 'git --amend is handy'"));
  });
});

describe("expandWord", () => {
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-glob-")));
  for (const f of [".env", ".env.local", "a.txt", "b.txt", "sub/c.pem"]) {
    fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    fs.writeFileSync(path.join(dir, f), "");
  }
  after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const names = (word: string) => expandWord(word, dir)?.map((p) => path.relative(dir, p)).sort();
  test("globs, braces and dotfiles expand as in bash", () => {
    assert.deepEqual(names(".env*"), [".env", ".env.local"]);
    assert.deepEqual(names(".en?"), [".env"]);
    assert.deepEqual(names("*"), ["a.txt", "b.txt", "sub"]);
    assert.deepEqual(names("*/*.pem"), ["sub/c.pem"]);
    assert.deepEqual(names("{a,b}.txt"), ["a.txt", "b.txt"]);
    assert.deepEqual(names(".{env,x}"), [".env", ".x"]);
    assert.deepEqual(names("[ab].txt"), ["a.txt", "b.txt"]);
    assert.deepEqual(names("[!a].txt"), ["b.txt"]);
    assert.deepEqual(names("nothing*"), []);
  });
  test("what cannot be known here is undefined", () => {
    for (const w of ["$f", "`x`", "{a..c}.txt", "x$()"]) assert.equal(expandWord(w, dir), undefined, w);
  });
});
