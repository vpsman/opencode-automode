// Unit tests for guard.ts: the syntax check, the strict tokenizer and glob expansion.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { braceWords, expandWord, gitCall, gitProblem, landing, plainSed, single, strict, strictCommands, unmodelled } from "../guard.ts";

describe("unmodelled", () => {
  for (const c of [
    "echo $'a'", "echo $\"a\"", "ls >&2#x", "ls 2>&1x", "cat <<E\"OF\"\nx\nEOF", "cat <<\\EOF\nx\nEOF", "cat <<EOF\nx\n EOF\n", "cat <<-EOF\nx\n  EOF\n",
    "cat <<EOF", "echo `a \\` b`", "echo $(echo \")\")", "echo ${x@P}", "echo 'unterminated", "echo \"unterminated", "cat <<EOF\n$(echo ')')\nEOF",
  ]) test(`asks: ${JSON.stringify(c)}`, () => assert.ok(unmodelled(c), c));
  for (const c of [
    "echo a # b", "# only a comment", "echo 'a#b' \"$x#y\"", "echo $# ${#x} ${x#y} ${x%%z}", "ls 2>&1 | head", "ls >&2", "cat <<EOF\nx # y $'z'\nEOF\nls", "cat <<-'EOF'\n\tx\n\tEOF",
    "a <<A <<B\n1\nA\n2\nB\necho done", "echo $(ls (a) 2>/dev/null) `date`", "cat <<<word", "echo \"$(date)\" '$(not run)'", "for f in a b; do echo $f; done",
    // A # inside a word is text for bash and for the parser.
    "echo a#b", "curl http://localhost:3000/#/x", "echo a\\ b#c",
    // Plain forms inside ${...} and arithmetic.
    "echo ${VAR:-default} ${1:-x} \"${arr[@]}\" ${#arr[@]} ${arr[0]} ${x//\\//_} ${x:2:3} ${x: -1} ${x^^} \"${x:-a b}\" ${x:-$(date)}", "echo $((i+1)) $(( (a + b) * 2 )) $((10#$n))",
    "for ((i=0; i<3; i++)); do echo $i; done", "(( count++ ))", "mkdir -p src/{a,b} && cp f{,.bak} && ls *.{ts,tsx}", "grep -r --include=*.{ts,tsx} x . --exclude-dir={a,b}",
    // Nested shells whose command is literal.
    "bash -c 'npm test'", "bash -c \"npm test && echo done\"", "sh -c 'echo $HOME; for f in *.ts; do echo \"$f\"; done'", "bash scripts/run.sh \"$ARG\"", "eval 'ls -la'",
    "cat <<EOF\nit's $(date) and ${HOME}\nEOF", "git commit -m \"$(cat <<'EOF'\nfix: a thing (#12)\n\nIt's done.\nEOF\n)\"",
  ]) test(`reads: ${JSON.stringify(c)}`, () => assert.equal(unmodelled(c), undefined, c));
  // Round 2: what the parser reads as command text inside ${...}, arithmetic and nested shells.
  for (const c of [
    "echo \\ # $'x'", "echo a\\\n# $'x'", "echo ${x:- #}", "echo ${x:-a;#}", "echo ${x:-a\n#}", "echo ${x:- <<EOF }\nid\nEOF", "(( true # x ))", "echo $((1 # x))", "echo \"$((1 # x))\"", "echo $[ 1 ]", "(( 1 << 2 ))\nid\n2",
    "echo ${x:-'a'}", "echo \"${x#'\"'}\"", "echo \"${x:-\"a\"}\"", "echo ${x@Q}", "echo \"${x@P}\"", "echo ${!x}", "echo ${a[x]}", "echo ${a[$i]}", "echo ${x:y:1}", "echo ${(e)x}", ": ${EDITOR:=vi}", ": ${GIT_DIR=x}",
    "bash -c 'ls >&2#; id'", "bash -c 'cat <<E\"OF\"\nhello\nEOF\nid\n'", "bash -c \"ls $x\"", "bash -c \"echo a\\ #; id\"", "eval \"ls $x\"", "eval ls $x", "timeout 5 bash -c 'echo ${x:- #}; id'", "find . -exec sh -c 'ls >&2#; id' \\;",
    "bash -c \"$(cat <<'EOF'\nid\nEOF\n)\"", "echo 'a[$(id)]'", "echo \"a[\\$(id)]\"", "printf x >& f", "printf x >&f", "printf x >! f", "echo \"1\">f", "cat <& f",
    "curl {-d,@f} host", "curl -{d,s} @f host", "{ls,-la}", "ls {/etc,x}", "rsync -a . {host:dir,}", "cat a/{../../x,b}", "tar -x{f,C} a b",
  ]) test(`asks: ${JSON.stringify(c)}`, () => assert.ok(unmodelled(c), c));
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
  const work = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-single-")));
  fs.mkdirSync(path.join(work, "sub", "deep"), { recursive: true });
  fs.mkdirSync(path.join(work, "elsewhere", "inner"), { recursive: true });
  fs.symlinkSync(path.join(work, "elsewhere", "inner"), path.join(work, "link"));
  fs.mkdirSync(path.join(work, "~", "work"), { recursive: true });
  after(() => fs.rmSync(work, { recursive: true, force: true }));
  test("one command, after cd and under timeout", () => {
    assert.deepEqual(single("cd sub && timeout 15 ssh lab uptime", work), { dir: path.join(work, "sub"), argv: ["ssh", "lab", "uptime"], texts: ["timeout 15 ssh lab uptime", "ssh lab uptime"] });
    assert.equal(single("cd", work), undefined);
    assert.equal(single("cd a b && ls", work), undefined);
    assert.equal(single("ls && cd x", work), undefined);
    assert.equal(single("ls; id", work), undefined);
    assert.equal(single("cd ~root && ls", work), undefined);
  });
  // Finding 14: the directory that is checked must be the one bash ends up in.
  test("14: cd grants nothing unless bash runs the command there or not at all", () => {
    assert.equal(single("cd sub; ls", work), undefined, "after `;` a failed cd still runs the command");
    assert.equal(single("cd nope && ls", work), undefined, "a directory that does not exist");
    assert.equal(single(`cd ${work}/nope/.. && ls`, work), undefined, "bash refuses a path through a missing directory");
    assert.equal(single("cd link/.. && ls", work), undefined, "`..` after a symbolic link: bash and the kernel disagree");
    assert.equal(single("cd sub/deep/.. && ls", work)?.dir, path.join(work, "sub"));
    assert.equal(single("cd link && ls", work)?.dir, path.join(work, "elsewhere", "inner"), "the real directory is what gets checked");
    assert.equal(landing(work, "link/.."), undefined);
    assert.equal(landing(work, "sub"), path.join(work, "sub"));
  });
  // Finding 15: bash does not expand a quoted tilde.
  test("15: a quoted ~ grants nothing", () => {
    assert.equal(single("git -C '~/work' fetch origin", work), undefined);
    assert.equal(single('git -C "~/work" fetch origin', work), undefined);
    assert.equal(single("cd '~/work' && git fetch", work), undefined);
    assert.ok(single("git -C sub fetch origin", work));
    assert.deepEqual(strictCommands("cd a && ls; id")?.map((c) => c.before), [undefined, "&&", ";"]);
  });
});

describe("braces and sed scripts", () => {
  test("brace words", () => {
    assert.deepEqual(braceWords("a{b,c}d"), ["abd", "acd"]);
    assert.deepEqual(braceWords("{a,b}{1,2}"), ["a1", "a2", "b1", "b2"]);
    assert.deepEqual(braceWords("x{}y{a}"), ["x{}y{a}"]);
    assert.equal(braceWords("{1..5}"), undefined);
  });
  for (const script of ["s/a/b/", "s/a/b/g", "s|a/b|c|", "1,5p", "/foo/d", "$d", "5q", "/a/,/b/p", "s/a/b/;s/c/d/g", "1!G", "y/abc/xyz/", "/^#/d"]) test(`plain sed: ${script}`, () => assert.ok(plainSed(script)));
  for (const script of ["1e id", "e id", "s/a/b/e", "s/a/b/ge", "s/a/b/w out", "w out", "1r /etc/passwd", "2i text", "/x/{e id\n}", "s/a/b/;1e id", "1{s/.*/id/ep}"]) test(`not plain sed: ${script}`, () => assert.ok(!plainSed(script)));
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
