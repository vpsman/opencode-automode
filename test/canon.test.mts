// The canonical printer (canon.ts; round 4, finding 16). Three things are held here:
//
//   - what it prints for the everyday forms, so a change of spelling shows in review;
//   - what it asks about;
//   - the two properties the design rests on, each against real bash over a table of words that
//     are hard to print: bash makes the same words of the printed text as of the input (the
//     printer read the input as bash does), and the rules' parser makes those same words of the
//     printed text (the two readers cannot differ on it).
//
// test/differential.test.mts holds the same two properties over whole commands (the review
// inputs and the generated ones), and test/allow-corpus.test.mts runs the everyday commands as
// their printed text.
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { canonical } from "../canon.ts";
import { parse } from "../rules.ts";

const text = (command: string) => {
  const printed = canonical(command);
  return "ask" in printed ? `ASK: ${printed.ask}` : printed.text;
};
const judged = (command: string) => {
  const printed = canonical(command);
  return "ask" in printed ? `ASK: ${printed.ask}` : printed.judged;
};

describe("the canonical printer: what it prints", () => {
  const same = ["git status", "ls -la", "npm test 2>&1 | tail -20", "cd dir && ls", "git add src/*.ts", "sed -n '5,$p' f", "awk '{print $1}' f", "echo ~/x", "x=1 y=2 cmd", "ls > out.txt 2>&1", "cat < in.txt", "echo $x ${y} \"$z\"", "sleep 0 & wait $!", "echo $! $? $# $$ $- $0 $1 $@ $*", "echo \"$@\" \"$?\" \"$#\"", "echo \"${v//\\//-}\"", "echo \"${x//\\./_}\"", "echo ${v//\\//-}", "echo \"${x%\\.*}\""];
  for (const c of same) test(`unchanged: ${c}`, () => assert.equal(text(c), c));
  const cases: [string, string][] = [
    // Quotes: plain text is bare, the rest in single quotes, a parenthesis and a quote backslashed.
    ['echo "a b" "c"', "echo 'a b' c"],
    ["echo \"it's (ok)\"", "echo it\\''s '\\(ok\\)"],
    ["echo a\\ b 'c'\"d\"", "echo a' 'b cd"],
    ['echo ""', "echo ''"],
    ['x="a b" cmd', "x='a b' cmd"],
    // Operators stand between blanks; comments and line continuations are gone.
    ["a;b&&c||d|e&", "a ; b && c || d | e &"],
    ["echo hi # a comment\nls", "echo hi\nls"],
    ["# only a comment\nls", "ls"],
    ["npm run build && \\\nnpm test", "npm run build && npm test"],
    ["ec\\\nho a\\\nb", "echo ab"],
    ["echo a |\\\n| cat", "echo a || cat"],
    ['echo "a \\\n b"', "echo 'a  b'"],
    // Expansions keep their quoting and get one form each.
    ['echo "$x/y" $1 "$@" `date`', 'echo "$x"/y $1 "$@" $(date)'],
    // Words braces make are plain arguments: a reserved word is nothing special there, and a
    // `~` that is not first in its word stays the character it is.
    ["mkdir -p {in,out}", "mkdir -p in out"],
    ["echo {if,then,time,do} x", "echo if then time do x"],
    ["git checkout -b {in,out}", "git checkout -b in out"],
    ["echo {x,y}=~/z", "echo x='~'/z y='~'/z"],
    ["export {x,y}=~/z", "export x='~'/z y='~'/z"],
    ["echo x={~,a} x=a:{~,b}/q", "echo x='~' x=a x=a:'~'/q x=a:b/q"],
    ["echo {~,x}/y {a,~}", "echo ~/y x/y a ~"],
    ["grep -rn function 'src/'", "grep -rn function src/"],
    // A case pattern that starts like an array element is a pattern: it prints.
    ["case $x in v[0-9]*|a[bc]) ls ;; esac", "case $x in v[0-9]* | a[bc] ) ls ;; esac"],
    ["case $x in a[bc]) ls ;; v[0-9]) pwd ;; esac", "case $x in a[bc] ) ls ;; v[0-9] ) pwd ;; esac"],
    // A special parameter is printed as written; `$10` is `${1}0` to bash.
    ["echo $10 $1a ${10} $!x", "echo ${1}0 $1a ${10} $!x"],
    ['echo "${x}abc" $x"abc" ${x:-d} "${x:-a b}"', 'echo "${x}"abc ${x}abc ${x:-d} "${x:-a b}"'],
    ["echo $(ls | wc -l)", "echo $(ls | wc -l)"],
    ["echo $\\\n(ls)", "echo $(ls)"],
    // A substitution that begins with a subshell keeps its blank (`$((` would be arithmetic).
    ["echo $( (ls) ) `ls` \"$( (x=1) )\"", 'echo $( ( ls ) ) $(ls) "$( ( x=1 ) )"'],
    ["cat <( (ls) )", "cat <( ( ls ) )"],
    // Empty quotes stay where they make a word of nothing, and go where they change nothing.
    ['set -- $x"" \'\'$y a""b g\'\'it', "set -- $x'' ''$y ab git"],
    // Quotes stay where they keep `NAME=` from being an assignment, or a word from being reserved.
    ['declare "a"=$x; for x in a; do echo "do" \'}\'; done', "declare 'a'=$x ; for x in a ; do echo 'do' '}' ; done"],
    // Braces are expanded here.
    ["echo {a,b}{1..2} x{}y --exclude={a,b}", "echo a1 a2 b1 b2 x'{}'y --exclude=a --exclude=b"],
    ["find build {,}{,}{-delete,}", "find build -delete -delete -delete -delete"],
    ["echo '{a,b}' \\{a,b\\}", "echo '{a,b}' '{'a,b'}'"],
    // What bash acts on stays unquoted, and what was quoted beside it stays quoted.
    ["ls *.ts 'a*' [ab]? ~/x '~/x' ~'/x'", "ls *.ts 'a*' [ab]? ~/x '~/x' ~'/x'"],
    // A quoted character inside a bracket is a plain member to bash, which the word without its
    // quotes cannot show (round 4, finding 6, second pass): `[a'-'z]` is a, - or z, not a range.
    ["ls [a'-'z]", "ASK: a quoted or escaped character inside a bracket of a glob, which bash reads as a plain member"],
    // Heredocs get a fresh delimiter; the commit message idiom becomes the literal it stands for.
    ["cat <<EOF > out\nhello $USER \\$5\nEOF", "cat <<AUTOMODE_EOF_1 > out\nhello ${USER} \\$5\nAUTOMODE_EOF_1\n"],
    ["cat <<'EOF'\nbody ( $x\nEOF\necho after", "cat <<'AUTOMODE_EOF_1'\nbody ( $x\nAUTOMODE_EOF_1\necho after"],
    ["cat <<-EOF\n\tindented\n\tEOF", "cat <<AUTOMODE_EOF_1\nindented\nAUTOMODE_EOF_1\n"],
    ["git commit -m \"$(cat <<'EOF'\nfix: a (thing\n\nBody with $x and `ticks`.\nEOF\n)\"", "git commit -m 'fix: a '\\('thing\n\nBody with $x and `ticks`.'"],
    ["git commit -m \"$(cat <<EOF\na \\\\ b\nEOF\n)\"", "git commit -m 'a \\ b'"],
    // The code of a nested shell and of eval is printed too, where a program runs.
    ["bash -c 'echo hi;   ls # c'", "bash -c 'echo hi ; ls'"],
    ["sudo sh -c \"echo a; id\"", "sudo sh -c 'echo a ; id'"],
    ["eval 'echo a;' ls", "eval 'echo a ; ls'"],
    ["echo bash -c 'ls   -la'", "echo bash -c 'ls   -la'"],
    ["bash build.sh -c 'a   b'", "bash build.sh -c 'a   b'"],
    // Compound commands pass through as words and operators.
    ["for f in *.ts; do head -3 \"$f\"; done", 'for f in *.ts ; do head -3 "$f" ; done'],
    ["if [ -f x ]; then echo y; fi", "if [ -f x ] ; then echo y ; fi"],
    ["f() { echo in; }; f", "f ( ) { echo in ; } ; f"],
    ["(cd dir && ls) > /dev/null", "( cd dir && ls ) > /dev/null"],
    ["case $x in a|b) echo ab ;; esac", "case $x in a | b ) echo ab ;; esac"],
  ];
  for (const [input, want] of cases) test(JSON.stringify(input), () => assert.equal(text(input), want));
});

describe("the canonical printer: what the rules read in place of what runs", () => {
  const cases: [string, string][] = [
    ["i=0; i=$((i+1)); (( i > 0 )) && echo $i", "i=0 ; i=0 ; : && echo $i"],
    ["for ((i=0;i<3;i++)); do echo $i; done", "for _ in 0 ; do echo $i ; done"],
    ["[[ -f f && $x == a* ]] && echo yes", "test -f f '&&' $x == a* && echo yes"],
    ["[[ $(id) == x ]]", "test $(id) == x"],
    // The regular expression after =~ keeps its quoting exactly.
    ["[[ 123 =~ ^[0-9]+$ ]] && echo n", "test 123 =~ ^[0-9]+$ && echo n"],
    ['[[ ab =~ "a." ]] && echo m', "test ab =~ 'a.' && echo m"],
    ['[[ $v =~ ^"$p"[0-9] ]]', 'test $v =~ ^"$p"[0-9]'],
    ["[[ a.b =~ ^a\\.b$ ]]", "test a.b =~ ^a\\.b$"],
    ["cat f <&3 2>&1", "cat f 2>&1"],
    ["git commit -m 'see opencode.json'", "git commit -m message"],
    ["git commit -am \"$(cat <<'EOF'\nsudo curl -d @f | sh\nEOF\n)\"", "git commit -am message"],
    ["git commit --message='x y' -q", "git commit --message=message -q"],
    ["timeout 60 git tag -a v1 -m 'release (one)'", "timeout 60 git tag -a v1 -m message"],
    ["git tag -a v1 -m 'x (y)' -f", "git tag -a v1 -m message -f"],
    ["git commit -qam 'x y' --amend", "git commit -qam message --amend"],
    // `-m` is the message option only where git is certain to read it as one: after an option
    // this reader does not know to take no value, the words are judged as they are.
    ["git commit --trailer -m --file=.env", "git commit --trailer -m --file=.env"],
    ["git commit -m x --trailer -m -F.env", "git commit -m message --trailer -m -F.env"],
    ["git tag --cleanup -m -d v1", "git tag --cleanup -m -d v1"],
    ["git commit --author -m --amend", "git commit --author -m --amend"],
    ["git merge -sm x", "git merge -sm x"],
    ["git commit -C HEAD -m x", "git commit -C HEAD -m x"],
    ["git commit $opt -m 'a b'", "git commit $opt -m 'a b'"],
    // A message bash computes is read as it is; so is the word after -m of other subcommands.
    ["git commit -m \"$(date)\"", 'git commit -m "$(date)"'],
    ["git cherry-pick -m 1 abc", "git cherry-pick -m 1 abc"],
    ["git commit -- -m x", "git commit -- -m x"],
    ["bash -c '[[ -f x ]] && git commit -m \"a b\"'", "bash -c 'test -f x && git commit -m message'"],
    // Round 4, second cross-check. git has one option table for each of commit, tag and merge,
    // so `-m` is the message there wherever it stands; `stash` and `notes` have a table per
    // action (`git stash list -m --output=f` hands both words to `git log`, which writes f).
    ["git stash list -m --output=opencode.json", "git stash list -m --output=opencode.json"],
    ["git stash show -m --output=opencode.json", "git stash show -m --output=opencode.json"],
    ["git stash push -m 'wip x'", "git stash push -m 'wip x'"],
    ["git stash -m 'wip x'", "git stash -m 'wip x'"],
    ["git notes add -m 'a b'", "git notes add -m 'a b'"],
    ["git notes list -m --output=x", "git notes list -m --output=x"],
    ["git tag -a v2 -m 'release (2)'", "git tag -a v2 -m message"],
    ["git merge --no-ff -m 'merge topic' topic", "git merge --no-ff -m message topic"],
    // A word bash expands into other words is no message: a glob can become options
    // (files named `-a`, `--amend`), and before the flag it can shift what `-m` belongs to.
    ["git commit -m *", "git commit -m *"],
    ["git commit -m m*", "git commit -m m*"],
    ["git commit -q * -m x", "git commit -q * -m x"],
    ["git tag -m ?? v9", "git tag -m ?? v9"],
    ["git commit -m [ab]", "git commit -m [ab]"],
    ["git commit -m ~", "git commit -m ~"],
    ["git commit ~/f -m x", "git commit ~/f -m x"],
    ["git commit -m 'a*b'", "git commit -m message"],
    ["git commit -m a\\*b", "git commit -m message"],
    ["git commit -m \"what? [x]\"", "git commit -m message"],
    // A command that defines its own `git` runs that, with the message as an argument.
    ["git() { $3; }; git commit -m 'rec ran'", "git ( ) { $3 ; } ; git commit -m 'rec ran'"],
    ["function git { ls; }; git commit -m 'a b'", "function git { ls ; } ; git commit -m 'a b'"],
    ["git () { ls; }\ngit commit -m 'a b'", "git ( ) { ls ; }\ngit commit -m 'a b'"],
    // Third pass (decided by the maintainer after a second round found `./git() {...}`): one
    // rule for any function. A command that defines a function, whatever its name, gets no
    // placeholder, no folded heredoc and no nested code printed as code.
    ["./git() { rec \"$3\"; }; ./git commit -m 'x y'", "./git ( ) { rec \"$3\" ; } ; ./git commit -m 'x y'"],
    ["/usr/bin/git() { ls; }; /usr/bin/git commit -m 'x y'", "/usr/bin/git ( ) { ls ; } ; /usr/bin/git commit -m 'x y'"],
    ["f() { ls; }; git commit -m 'x y'", "f ( ) { ls ; } ; git commit -m 'x y'"],
    ["function helper { ls; }; git tag -a v1 -m 'x y'", "function helper { ls ; } ; git tag -a v1 -m 'x y'"],
    ["g() { git() { ls; }; }; g; git commit -m 'x y'", "g ( ) { git ( ) { ls ; } ; } ; g ; git commit -m 'x y'"],
    // Fifth pass. Where a command begins is read in one place (`headOf`): `time` takes `-p` and
    // `--` with it, so a definition after them is a definition (the fourth round found
    // `time -p git() ...` a rule allow with the message hidden) ...
    ["time -p git() { rec \"$3\"; }; git commit -m 'x y'", "time -p git ( ) { rec \"$3\" ; } ; git commit -m 'x y'"],
    ["time -p -- git() { ls; }; git commit -m 'x y'", "time -p -- git ( ) { ls ; } ; git commit -m 'x y'"],
    ["time -- git() { ls; }; git commit -m 'x y'", "time -- git ( ) { ls ; } ; git commit -m 'x y'"],
    ["! time -p f() { ls; }; git commit -m 'x y'", "! time -p f ( ) { ls ; } ; git commit -m 'x y'"],
    ["time -p function f { ls; }; git commit -m 'x y'", "time -p function f { ls ; } ; git commit -m 'x y'"],
    // ... and `function` after a redirect or after a keyword written as an argument is a word.
    ["echo >out function helper; git commit -m 'x y'", "echo > out function helper ; git commit -m message"],
    ["echo time function helper; git commit -m 'x y'", "echo time function helper ; git commit -m message"],
    ["ls 2>/dev/null function; git commit -m 'x y'", "ls 2> /dev/null function ; git commit -m message"],
    // After an assignment or a redirect bash takes no reserved word: `[[` is a program there,
    // and the `||` after it an operator the rules must see (the scanner asks about these too).
    ["a=1 [[ -n x || ls ]]", "a=1 [[ -n x || ls ]]"],
    [">o [[ -n x || ls ]]", "> o [[ -n x || ls ]]"],
    ["time a=1 [[ -n x || ls ]]", "time a=1 [[ -n x || ls ]]"],
    ["a=1 time -p [[ -n x || ls ]]", "a=1 time -p [[ -n x || ls ]]"],
    // A heredoc and a duplicated descriptor are redirects like any other ...
    ["<<EOF [[ -n x || ls ]]\nEOF", "<<AUTOMODE_EOF_1 [[ -n x || ls ]]\nAUTOMODE_EOF_1\n"],
    ["2>&1 [[ -n x || ls ]]", "2>&1 [[ -n x || ls ]]"],
    ["ls <&3 [[ -n x || ls ]]", "ls [[ -n x || ls ]]"],
    // ... and an operator or a line break ends it: the next command begins as any other.
    ["a=1 ls; [[ -n x || ls ]]", "a=1 ls ; test -n x '||' ls"],
    ["a=1 ls\n[[ -n x || ls ]]", "a=1 ls\ntest -n x '||' ls"],
    [">o ls && [[ -n x || ls ]]", "> o ls && test -n x '||' ls"],
    ["a=1 ls | [[ -n x || ls ]]", "a=1 ls | test -n x '||' ls"],
    // An option of `time` after a redirect is the command's name (the asks are below); the
    // option before the redirect is the option.
    ["time -p >o ls", "time -p > o ls"],
    ["time >o ls -p", "time > o ls -p"],
    // A declaring builtin is one only as written plainly; as an argument its name is a word.
    ['echo "export" p=$x', "echo export p=$x"],
    ['command echo "export" p=$x', "command echo export p=$x"],
    ["command export p=$x", "command export p=$x"],
    ['"command" echo export p=$x', "command echo export p=$x"],
    // Nothing looks through `builtin`: its arguments are split as written and as printed.
    ['builtin "local" p=$x', "builtin local p=$x"],
    ["'builtin' \"local\" p=$x", "builtin local p=$x"],
    ["command ls {a,b}", "command ls a b"],
    ["time a=1 ls -p", "time a=1 ls -p"],
    ["time a=1 b=2 ls", "time a=1 b=2 ls"],
    // `-p` on a line of its own is a command's name, and the `[[` after it a word: the
    // operator in it stays an operator.
    ["time\n-p [[ -n x || ls ]]", "time\n-p [[ -n x || ls ]]"],
    ["time [[ -f x && -n y ]]", "time test -f x '&&' -n y"],
    // Only the program found as `git` (or at a system path) is git: a file reached by another
    // path is a project script, and the word after its `-m` is whatever the script makes of it.
    ["./git commit -m 'x y'", "./git commit -m 'x y'"],
    ["sub/git commit -m 'x y'", "sub/git commit -m 'x y'"],
    ["../git tag -a v9 -m 'x y'", "../git tag -a v9 -m 'x y'"],
    ["env ./git commit -m 'x y'", "env ./git commit -m 'x y'"],
    ["nice /tmp/git commit -m 'x y'", "nice /tmp/git commit -m 'x y'"],
    ["/usr/bin/git commit -m 'x y'", "/usr/bin/git commit -m message"],
    ["exec git commit -m 'x y'", "exec git commit -m message"],
    ["nohup git commit -m 'x y'", "nohup git commit -m message"],
    ["time git commit -m 'x y'", "time git commit -m message"],
    ["env git commit -m 'x y'", "env git commit -m message"],
    // `function` as an argument defines nothing: the placeholder and the fold stay.
    ["grep -rn function src && git commit -m 'x y'", "grep -rn function src && git commit -m message"],
    ["rg function \"foo\"; git commit -m \"$(cat <<'EOF'\nx y\nEOF\n)\"", "rg function foo ; git commit -m message"],
    ["echo function; git tag -a v1 -m 'x y'", "echo function ; git tag -a v1 -m message"],
    // A function that has nothing to do with cat still stops the fold.
    ["f() { ls; }; echo \"$(cat <<'EOF'\nx\nEOF\n)\"", "f ( ) { ls ; } ; echo \"$(cat <<'AUTOMODE_EOF_1'\nx\nAUTOMODE_EOF_1\n)\""],
    // Behind a wrapper that adds or replaces words the word after -m may be another's value.
    ["echo --cleanup | xargs -I{} git tag {} -m -d v1", "echo --cleanup | xargs -I'{}' git tag '{}' -m -d v1"],
    ["xargs git commit -m 'x y'", "xargs git commit -m 'x y'"],
    ["find . -name x -exec git commit -m 'x y' \\;", "find . -name x -exec git commit -m 'x y' ';'"],
    ["env -i git commit -m 'x y'", "env -i git commit -m 'x y'"],
    ["if true; then GIT_PAGER=cat git commit -m 'x y'; fi", "if true ; then GIT_PAGER=cat git commit -m message ; fi"],
    ["command git commit -m 'x y'", "command git commit -m message"],
    ["nice git merge -m 'x y' topic", "nice git merge -m message topic"],
    // A definition inside the nested code is that shell's own matter.
    ["bash -c 'git() { ls; }; git commit -m \"x y\"'", "bash -c 'git '\\(' '\\)' { ls ; } ; git commit -m '\\''x y'\\'"],
  ];
  for (const [input, want] of cases) test(JSON.stringify(input), () => assert.equal(judged(input), want));
  test("where nothing differs the two texts are the same", () => {
    for (const c of ["git status", "echo \"$(ls)\" > out", "cat <<EOF\n$x\nEOF", "bash -c 'ls -la'"]) {
      const printed = canonical(c);
      assert.ok(!("ask" in printed) && printed.text === printed.judged, c);
    }
  });
});

describe("the canonical printer: what it asks about", () => {
  const asks: [string, RegExp][] = [
    // Round 4, finding 1: inside a substitution bash ends a heredoc at a line that starts with
    // the delimiter and goes on.
    ['echo "$(cat <<EOF\n(\nEOF)" ; id ; echo "\nEOF\n)"', /heredoc line that starts with the delimiter/],
    ["echo $(cat <<'EOF'\nx\nEOF ) ; id", /heredoc line that starts with the delimiter/],
    ["cat <(cat <<EOF\nx\nEOF) ; id", /heredoc line that starts with the delimiter/],
    ["bash -c 'echo \"$(cat <<EOF\n(\nEOF)\" ; id ; echo \"\nEOF\n)\"'", /nested shell/],
    ["echo `cat <<EOF\nEOFx\nEOF\n`", /heredoc line that starts with the delimiter/],
    // What the parser's parenthesis count would misread.
    ["echo \"$(cat <<'EOF' | tr a b\nx (\nEOF\n)\"", /parenthesis in a heredoc body/],
    ["echo $(case x in x) id ;; esac)", /case statement inside a substitution/],
    // Forms with no fixed spelling.
    ["echo $'a\\nb'", /quoting/],
    ["echo $\"x\"", /quoting/],
    ["echo ${!x}", /indirect/],
    ["echo ${x@P}", /transformation/],
    ["echo ${x:-'a b'}", /quotes/],
    ["echo ${x:-a b}", /blank/],
    ["echo $[1+1]", /old/],
    ["echo $(( $(id) ))", /substitution inside arithmetic/],
    // Found by the round 4 cross-check.
    ["git checkout 2147483648>/dev/null", /too long for a descriptor/],
    ["echo x >*.ts", /glob in the target of a redirect/],
    ["bash -c ' -x' 'echo y'", /starts with - or \+ once printed/],
    ["bash -n -c ' +n' 'echo y'", /starts with - or \+ once printed/],
    ["eval ' -- echo hi'", /starts with - or \+ once printed/],
    ["[[ a =~ a$b$ ]]", /\$ inside a regular expression/],
    ["[[ a =~ a{2}$x ]]", /would have to quote/],
    ["x=(1 2)", /array assignment/],
    ["ls |& cat", /\|&/],
    ["echo a <> f", /<>/],
    ["cat <<E\"OF\"\nx\nEOF", /heredoc delimiter/],
    ["cat <<EOF\nnever closed", /no terminator/],
    ["cat <<EOF\ndata\n  EOF\nEOF", /whitespace around/],
    ["echo 'unterminated", /unterminated/],
    ["echo `echo \\`id\\``", /backslash inside backticks/],
    ["echo @(a|b)", /extglob/],
    ["echo a\rb", /control character/],
    ["2>&1 '2'>f", /quoted number/],
    ["echo $x{a,b}", /expansion and a brace/],
    ["x={a,b} cmd", /braces where bash expands none/],
    ["echo > {a,b}", /braces where bash expands none/],
    ["echo {1..100000}", /too large/],
    ["{,} ; ls", /braces where bash expands none/],
    ["x=1 {,}", /braces where bash expands none/],
    ["\"x=1\" cmd", /quoted word/],
    ["'if' true", /quoted word/],
    // The shell reads a leading - or + as its own options.
    ["-n ; ls", /starts with - or \+/],
    ["\\\n-n ; ls", /starts with - or \+/],
    ["# c\n+x", /starts with - or \+/],
    // Code for a nested shell must be literal; for sh it must not rely on bash.
    ["bash -c \"$x\"", /nested shell built from/],
    ["eval $x", /eval built from/],
    ["sh -c 'echo {a,b}'", /only bash reads/],
    // Round 4, second cross-check.
    // A range whose step does not fit a number: bash leaves the word as it is.
    ["echo {a..c..9999999999999999999999999999999999999999}", /brace expansion too large or too unusual/],
    ["echo {1..3..99999999999999999999}", /brace expansion too large or too unusual/],
    ["echo {3..1..9223372036854775808}", /brace expansion too large or too unusual/],
    // A heredoc inside `${...}`: its body is text the operand's reading does not cover.
    ['echo "${x:-$(cat <<\'E\'\n}" ; ls ; : "\nE\n)}"', /heredoc inside \$\{/],
    ['echo "${x:-$(cat <<\'E\'\n"\'$(ls)\'"\nE\n)}"', /heredoc inside \$\{/],
    ["echo \"${x:-$(cat <<E\nplain\nE\n)}\"", /heredoc inside \$\{/],
    // Code a glob or a tilde makes is not literal.
    ["bash -c *", /nested shell built from/],
    ["sh -c ~/x", /nested shell built from/],
    ["eval echo *", /eval built from/],
    // An eval that defines `cat` or `git` changes what a later word of the command runs.
    ["eval 'cat() { ls; }'; git commit -m \"$(cat <<'EOF'\nx\nEOF\n)\"", /eval that defines a function/],
    ["eval 'function git { ls; }'; git commit -m x", /eval that defines a function/],
    ["eval './git() { ls; }'; ./git commit -m x", /eval that defines a function/],
    ["eval 'helper() { ls; }'; helper", /eval that defines a function/],
    // In a command that defines a function a nested shell or eval asks: its word is code that
    // cannot be printed, since the name may be the function's.
    ["bash() { rec \"$2\"; }; bash -c 'echo   a  # b'", /in a command that defines a function/],
    ["f() { ls; }; bash -c 'echo   a  # b'", /in a command that defines a function/],
    ["eval() { rec \"$1\"; }; eval 'echo   a  # b'", /in a command that defines a function/],
    ["f() { sh -c \"$1\"; }; f ls", /in a command that defines a function/],
    // Fifth pass: the same behind `time` and its options.
    ["time -p f() { ls; }; bash -c 'f'", /in a command that defines a function/],
    ["time -p -- f() { ls; }; bash -c 'f'", /in a command that defines a function/],
    ["time -- f() { ls; }; eval 'f'", /in a command that defines a function/],
    ["time -p cat() { sh; }; x=\"$(cat <<'EOF'\nls\nEOF\n)\"", /in a command that defines a function/],
    // The name word after `time -p` is the name word: no braces are expanded in it.
    ["time -p {,} a=1 ls", /the word that names the command/],
    ["time -p {ls,-la}", /the word that names the command/],
    ["time -- {ls,-la}", /the word that names the command/],
    ["! time -p -- {a,}() { ls; }", /the word that names the command/],
    ["time \"-p\" ls", /quoted -p or -- after time/],
    // `[[` after an option of `time`: a conditional to bash; to bash called `sh`, `time` is a
    // program there and `||` ends its command (the fifth-pass review: `rec hidden ]]` ran).
    ["time -p [[ -n x || ls ]]", /after the -p or -- of time/],
    ["time -p -- [[ -f x ]]", /after the -p or -- of time/],
    ["time -- [[ -f x ]]", /after the -p or -- of time/],
    ["time -p ! [[ -f x ]]", /after the -p or -- of time/],
    // Straight after `|` bash does not take `time` for its keyword: it runs a program of that
    // name, `[[` is one of its arguments and the `||` in it an operator (the fourth round's
    // second reading review: `cat f | time [[ -s f || sh -c '...' ]]` was a rule allow and ran
    // the hidden command). After two line breaks bash refuses the text.
    // After a redirect bash takes `-p` and `--` for the program to run, not for options of
    // `time`: `time >o -p cmd` runs a program called -p, and the rules would judge `cmd`.
    ["time >o -p ls", /-p or -- after time and a redirect/],
    ["time 2>o -- ls", /-p or -- after time and a redirect/],
    ["time -p >o -- ls", /-p or -- after time and a redirect/],
    ["time <<EOF -p ls\nx\nEOF", /-p or -- after time and a redirect/],
    ["ls && time 2>&1 -p ls", /-p or -- after time and a redirect/],
    // ... and after an assignment, with or without a redirect before it.
    ["time a=1 -p ls", /-p or -- after time and a redirect or an assignment/],
    ["time >/dev/null a=1 -p ls", /-p or -- after time and a redirect or an assignment/],
    ["time -p a=1 b=2 -- ls", /-p or -- after time and a redirect or an assignment/],
    // `"export" p=$x` splits and globs `$x`; `export p=$x` does not. Also behind `command`,
    // through which bash as sh looks for the declaring builtin.
    ['"export" p=$x', /a quoted export, declare/],
    ["\\export p=$x", /a quoted export, declare/],
    ["'readonly' p=$x", /a quoted export, declare/],
    ['ex"port" p=$x', /a quoted export, declare/],
    ['"local" p=1', /a quoted export, declare/],
    ["f() { 'typeset' p=$x; }", /a quoted export, declare/],
    ['command "export" p=$x', /a quoted export, declare/],
    ["command command 'declare' p=$x", /a quoted export, declare/],
    // bash as sh looks through `command` only when it is written plainly.
    ['"command" export p=$x', /a quoted export, declare/],
    ["\\command export p=$x", /a quoted export, declare/],
    ['command "command" readonly p=$x', /a quoted export, declare/],
    // A brace in a word of the chain: bash as sh reads the word as written.
    ["command {export,} p=$x", /braces where bash expands none/],
    ["command {command,} export p=$x", /braces where bash expands none/],
    ["command command {readonly,} p=$x", /braces where bash expands none/],
    ["cat f | time [[ -s f || sh -c 'ls' ]]", /time straight after a \|/],
    ["ls | time [[ -n x || ls ]]", /time straight after a \|/],
    ["ls |\ntime [[ -n x || ls ]]", /time straight after a \|/],
    ["ls | # c\ntime [[ -n x || ls ]]", /time straight after a \|/],
    ["ls |\n\ntime [[ -n x || ls ]]", /time straight after a \|/],
    ["echo $(ls | time [[ -n x || ls ]])", /time straight after a \|/],
    ["ls | time time [[ -n x || ls ]]", /time straight after a \|/],
    ["ls | time wc -l", /time straight after a \|/],
    ["ls | >out time wc -l", /time straight after a \|/],
    ["cat <<EOF |\nx\nEOF\ntime [[ -n x || ls ]]", /time straight after a \|/],
    // A `$` that expands nothing as written becomes an expansion once the braces are gone.
    ["x=5; echo {$,a}x", /\$ in a word with braces/],
    ["echo {$,}{x,y}", /\$ in a word with braces/],
    ["echo a{b,$}c", /\$ in a word with braces/],
    // A coprocess: the reader does not follow where its command begins.
    ["coproc { ls; }", /coprocess/],
    ["coproc p { function f { ls; }; f; }", /coprocess/],
    ["time -p '--' ls", /quoted -p or -- after time/],
    // A process substitution joined to a heredoc's delimiter or to a descriptor's number is more
    // of that word to bash: `<<EOF<(ls)` has the delimiter `EOF<(ls)`, so no line `EOF` ends the
    // body and what follows it is data, not commands (found by the generator, seed 41000001).
    ["cat <<EOF<(ls)\nbody\nEOF\nls", /heredoc delimiter/],
    ["cat <<EOF>(ls)\nbody\nEOF", /heredoc delimiter/],
    ["cat <<'EOF'<(ls)\nbody\nEOF", /heredoc delimiter/],
    ["cat <<EOF<\\\n(ls)\nbody\nEOF", /heredoc delimiter/],
    ["ls 2>&1<(ls)", /descriptor that is not a plain number/],
    ["ls 2>&1>(ls)", /descriptor that is not a plain number/],
    // Backticks hold only plain commands: bash reads their text when it runs them, so a syntax
    // error there stops that substitution alone, and inside `$( )` it would stop the command
    // around it (found by the generator: as written the commands around `` `(})` `` ran).
    ["echo a; x=`(})`; ls", /backticks around more than plain commands/],
    ["echo `ls | #`", /backticks around more than plain commands/],
    ["echo `(ls|})`", /backticks around more than plain commands/],
    ["echo `(cd x && pwd)`", /backticks around more than plain commands/],
    ["echo `if true; then ls; fi`", /backticks around more than plain commands/],
    ["echo `ls ;; ls`", /backticks around more than plain commands/],
    ["echo `| ls`", /backticks around more than plain commands/],
    ["echo `ls &&`", /backticks around more than plain commands/],
    ["echo \"`{ ls; }`\"", /backticks around more than plain commands/],
    // ... and the same for a substitution inside the backticks.
    ["echo a; x=`echo $( (}) )`; echo b", /backticks around more than plain commands/],
    ["echo `echo $(ls &&)`", /backticks around more than plain commands/],
    ["echo `cat <( (}) )`", /backticks around more than plain commands/],
    ["echo `echo ${y:-$( (}) )}`", /backticks around more than plain commands/],
    ["echo `ls > $( (}) )`", /backticks around more than plain commands/],
    // Where an assignment may stand bash reads `name[` up to the matching `]` as one word,
    // blanks and operators included, and then runs the words after it (found by the generator
    // with another seed: `: | EOF[[ b[0]+ls | ]]a` is one command to bash).
    ["a[0]=1 ls", /array element/],
    ["a[ 0 ]=1 ls", /array element/],
    ["x=1 a[0]=2 ls", /array element/],
    ["a[ 0 ] ls", /array element/],
    ["a[ 0 | ls ]=1 ls", /array element/],
    [": | EOF[[ b[0]+ls | ]]a", /array element/],
    ["if a[0]=1; then ls; fi", /array element/],
    ["time -p a[0]=1 ls", /array element/],
    // In a case arm a command is cut at `|` like a pattern: only one bare word with its bracket
    // closed counts as a pattern.
    ["case x in x) a[ 0 | x ]=1 ls ;; esac", /array element/],
    ["case x in x) a[0|x]=1 ls ;; esac", /array element/],
    // From the variant check of the second round. A function's name must be written plainly:
    // bash and dash refuse a quoted one, and printed without its quotes it would define the
    // function the input failed to define.
    ["'cat'() { ls; }; echo \"$(cat <<'EOF'\nx\nEOF\n)\"", /function name/],
    ["ca\\t() { ls; }; cat f", /function name/],
    ["\"git\"() { ls; }; git status", /function name/],
    ["c''at() { ls; }", /function name/],
    ["function 'cat' { ls; }", /function name/],
    ["$x() { ls; }", /function name/],
    // A word made by braces is a plain word to bash, whatever it spells: written out it would
    // be an assignment, a reserved word, or a `~` bash expands after `=` or `:`.
    // Braces are expanded only in the words after the command's name (decided by the maintainer
    // after three rounds on what a made word must not become). bash reads the name word, a
    // function's name and the head of a loop before it expands braces: there a brace asks.
    ["{a,b}=1 ls", /braces where bash expands none/],
    ["{x=1,} ls a", /braces where bash expands none/],
    ["x=1 {a,b}=2 ls", /braces where bash expands none/],
    ["{!,} ls a", /braces where bash expands none/],
    ["{time,} ls a", /braces where bash expands none/],
    ["i{f,} true; then ls; fi", /braces where bash expands none/],
    ["for i in a; {do,x} ls; done", /braces where bash expands none/],
    ["{[[,x} -n a ]]", /braces where bash expands none/],
    ["{,} a=1 ls", /braces where bash expands none/],
    ["{,} time ls", /braces where bash expands none/],
    ["{,} if ls", /braces where bash expands none/],
    ["{,}{,} a=1 ls", /braces where bash expands none/],
    ["{ls,-la}", /braces where bash expands none/],
    ["{,}git status", /braces where bash expands none/],
    ["time {a,b} x", /braces where bash expands none/],
    ["f{a,b}() { ls; }", /braces where bash expands none/],
    ["{a,}() { ls; }; a", /braces where bash expands none/],
    ["{cat,}() { ls; }; cat f", /braces where bash expands none/],
    ["function {a,b} { ls; }", /braces where bash expands none/],
    ["for i {in,x} a; do ls; done", /braces where bash expands none/],
    ["for {i,j} in a; do ls; done", /braces where bash expands none/],
    ["select {i,j} in a; do ls; done", /braces where bash expands none/],
    // A word of the brace expander's own private characters would be taken for a quoted one.
    ["echo 'xy'{a,b}\ue001", /private-use character/],
    ["echo ''{a,b}\ue000", /private-use character/],
    // One budget for all the words the braces of a command make.
    [`echo ${"x".repeat(4000)}{1..2000}`, /brace expansion that makes more text/],
    [`echo ${"{1..2000} ".repeat(40)}`, /brace expansion that makes more text/],
    // `${...}` nested deeper than anyone writes.
    [`echo ${"${x:-".repeat(200)}y${"}".repeat(200)}`, /deeply nested/],
    [`echo ${"${x:-".repeat(33)}y${"}".repeat(33)}`, /deeply nested/],
    [`echo "${"${x:-".repeat(16000)}y${"}".repeat(16000)}"`, /deeply nested|too long/],
    // A shell reached by a path the checks do not know, with code to run.
    ["./bash -c 'ls'", /named like a shell/],
    ["sub/sh -c 'ls -la'", /named like a shell/],
    // A `~` word: a character to quote anywhere before the first slash, also after an expansion.
    ["echo ~root:$x,#", /~ word/],
    ["echo ~$x#/y", /~ word/],
    // A `~` word with a character the printer would have to quote: the quotes would stop the
    // expansion bash makes of it.
    ["echo ~root:#", /~ word/],
    ["echo ~:{}", /~ word/],
    // A printed text over the limit, from an input well under it.
    [`echo ${"x".repeat(60)}{1..2000}`, /brace expansion that makes more text/],
    [`echo '${"(".repeat(60_000)}'`, /too long .* once printed/],
    [`echo '${"\u00e9".repeat(60_000)}'`, /too long/],
    // A word too long for the brace expander (it used to overflow the stack and throw).
    [`echo ${"{1..1}".repeat(16_000)}`, /brace expansion too large or too unusual/],
    [`echo ${"{".repeat(40_000)}`, /brace expansion too large or too unusual/],
    [`echo a${"{x,y}".repeat(900)}`, /brace expansion too large or too unusual/],
    // In a case statement bash expands no braces in the word or in a pattern.
    ["case a in {a,b}) echo y;; esac", /braces where bash expands none/],
    ["case {a,b} in x) echo y;; esac", /braces where bash expands none/],
    ["case a in a|{b,c}) echo y;; esac", /braces where bash expands none/],
    ["case a in ({b,c}|a) echo y;; esac", /braces where bash expands none/],
    // A heredoc body inside a substitution may hold parentheses that balance (the rules' parser
    // counts them); one that does not balance asks.
    ["echo \"$(cat <<EOF\n) $y (\nEOF\n)\"", /parenthesis in a heredoc body/],
    ["echo \"$(cat <<EOF\n( $y\nEOF\n)\"", /parenthesis in a heredoc body/],
    ["echo \"$(cat <<EOF\n$y )\nEOF\n)\"", /parenthesis in a heredoc body/],
    // Inside ${...} a backslash and the character after it are kept; a backslash-newline is not.
    ["echo \"${x:-a\\\nb}\"", /\$\{/],
    // A command too long to hand over in one variable.
    [`echo ${"a ".repeat(70_000)}`, /too long/],
  ];
  for (const [input, why] of asks) test(JSON.stringify(input), () => assert.match(text(input), new RegExp(`^ASK: .*${why.source}`, "s")));
  test("the brace budget is one for the whole command, nested code included, and new for each command", () => {
    const outcome = (c: string) => {
      const p = canonical(c);
      return "ask" in p ? `ASK: ${p.ask}` : "printed";
    };
    // About 61,000 characters of made words: under the budget alone, over it twice.
    const half = `echo ${"x".repeat(27)}{1..2000}`;
    assert.equal(outcome(half), "printed");
    assert.match(outcome(`${half}; ${half}`), /^ASK: .*brace expansion that makes more text/);
    assert.match(outcome(`${half}; bash -c '${half}'`), /^ASK: .*brace expansion that makes more text/);
    assert.match(outcome(`${half}; echo "$(${half})"`), /^ASK: .*brace expansion that makes more text/);
    // The count starts again with each command: the same text prints a second and a third time.
    assert.equal(outcome(half), "printed");
    assert.equal(outcome(half), "printed");
  });
  test("${...} inside one another: 32 deep prints, 33 asks", () => {
    const nest = (n: number) => `echo ${"${x:-".repeat(n)}y${"}".repeat(n)}`;
    const at = (n: number) => canonical(nest(n));
    assert.ok(!("ask" in at(32)), JSON.stringify(at(32)).slice(0, 200));
    assert.match((at(33) as { ask: string }).ask, /deeply nested/);
  });
  test("a long word with many operands is read in no time", () => {
    // 64 readings of six operands, then an operand with 64 readings of its own: the cap must
    // hold before the product is built (17,000 characters times 4,160 readings took 13 seconds).
    const six = (names: string) => [...names].map((n, i) => `\${${n}:-${i}}`).join("");
    const word = `${"L".repeat(60_000)}${six("abcdef")}\${g:-${six("hijklm")}}`;
    const started = Date.now();
    const printed = canonical(`ls ${word}*`);
    assert.ok(Date.now() - started < 2000, `${Date.now() - started} ms`);
    assert.ok(!("ask" in printed) && printed.bashOnly);
  });
  test("a path segment with thousands of expansions is read in no time", () => {
    // Every pair of expansions in a segment is a piece to look at: ten thousand of them took a
    // quarter of a minute. Past 32 the segment is marked when it holds a glob character.
    const many = (n: number) => `ls ${"x${v}".repeat(n)}*z`;
    const started = Date.now();
    const long = canonical(many(15_000));
    assert.ok(Date.now() - started < 2000, `${Date.now() - started} ms`);
    assert.ok(!("ask" in long) && long.bashOnly);
    const short = canonical(many(32));
    assert.ok(!("ask" in short) && !short.bashOnly);
    const none = canonical(`ls ${"x${v}".repeat(15_000)}z`);
    assert.ok(!("ask" in none) && !none.bashOnly);
  });
  test("what relies on bash is marked, and nothing else", () => {
    const flag = (c: string) => {
      const printed = canonical(c);
      return !("ask" in printed) && printed.bashOnly;
    };
    for (const c of ["echo {a,b}", "[[ -f x ]]", "(( 1 ))", "cat <<< x", "ls &> out", "diff <(ls) f", "echo ${x//a/b}", "echo ${a[0]}", "function f { ls; }", "time ls", "ls [^a]*", "cd ~+", "echo a=~/x", "echo $((2**3))", "echo \"${x:-${y^^}}\"", "echo \"${x:-$((2**3))}\"", "echo ${x:-${a[0]}}", "cat <<EOF\n${y^^}\nEOF", "cat <<EOF\n$((2**3))\nEOF", "cat <<EOF\n${x:-${y,,}}\nEOF", "ls 10>/dev/null", "git tag 12>/dev/null", "ls 2>&10", "ls 10<<EOF\nx\nEOF", "echo \"$(< f)\"", "cat <<EOF\na\\\nb\nEOF", "cat <<EOF\nEO\\\nF\nls\n", "a+=x ls", "a+=x", "echo $((a[1]))", "chmod -R 700 .?", "ls -d .*", "rm -r .[.]", "cat .?/x", "ls src/.*", "echo ~:", "echo ~root:x", "echo ~0", "echo ~1/x", "ls $e.*", "ls -d \"$e\".?", "ls .*$x", "ls $d*", "ls .[[:punct:]]", "ls .[[:punct:][:alpha:]]x", "ls .[!.]*", "ls .[a-z]*rc", "ls x$e*", "ls \"$d\"*", "ls $d/.[a]", "ls '.'[a]", "time -p ls", "ls \u{1F600}\u{1F600}$e*", "du -sh ${u:-.*}", "ls ${d-.?}", "ls ${d:=.[a]}", "p=\".?\"; chmod -R 700 $p", "p=.?; ls $p", "p='x/.*'", "ls -d .?${e}repo", "ls -d .*${e}repo", "ls -d .?\"${e}\"repo", "ls -d .?$(echo /)repo", "ls ./.?${e}x", "ls -d .?$e.", "du -sh .${x:-*}", "ls .${x-?}", "ls ${d:-.}${y:-*}", "ls ${x:-\\.*}", "ls ${x:+.*}", "p=\"${u:-.*}\"; ls -d $p", "export p=.?", "local p='.*'", "ls | (( 1 ))\ntime ls", "ls .${x:-${y:-*}}", "ls ${x:-.${y:-*}}", "command export p=.?", "builtin declare p=\".*\"", "p=\"-d .?\"; ls $p", "p='a .*'", "p=\"a\t.?\"", "p='a\n.[.]'", "readonly \"p=.*\"", "export p\"=.?\"", "local 'p=x .?'", "command export \"p=.*\"", "ls -d .${x:-*${y+c}}", "ls .${x:-${y:-}*}", "ls ${d:-x}.${y:-*}", "ls ${d:-.}${y:-?}", "ls -d .${x:-${y:-*}${z+c}}", "ls .${x:-${y:-${z:-*}}${w+c}}", "ls .${a:-1}${b:-2}${c:-3}${d:-4}${e:-5}${f:-6}${g:-*}", "command -p export p=.?", "builtin command export p='a .*'", "ls x${a:-1}${b:-2}${c:-3}${d:-4}${e:-5}${f:-6}${g:-y*}", "command \"-p\" export p=.?", "command '--' export \"p=.*\"", "builtin \"--\" declare p=.?", "command -p \"export\" p=.?", "p=\"x .${a:-${b:-*}${c+y}}\""]) assert.ok(flag(c), c);
    for (const c of ["git status", "echo '{a,b}'", "echo $((1+1))", "echo ${x:-y} ${x%.*}", "cat <<EOF\nx\nEOF", "for f in *; do ls; done", "bash -c 'echo {a,b}'", "ls 2>/dev/null", "ls 2>&1 9>&2", "echo \"${x:-${y:-z}}\"", "cat <<EOF\n${x:-y} $((1+1))\nEOF", "sleep 0 & wait $!", "cat <<'EOF'\na\\\nb\nEOF", "echo $(( $# + 1 ))", "echo $((${#x} - 1))", "ls .git* .env", "ls ./*", "ls ~/x ~root/x", "ls '.?' \".*\"", "ls a.*", "ls .e*", "ls $dir/*.ts", "ls src/$x.ts", "ls .*.swp", "ls .??*", "ls $prefix*.log", "ls \"$dir\"/*.txt", "ls src/.*rc", "echo a[0]=1 b[ 1 ]", "ls a[0]*", "case $x in v[0-9]*) ls ;; a[bc]) ls ;; esac", "case $x in v[0-9]*|a[bc]) ls ;; esac", "echo ${x%.*} ${x#.?}", "echo \"${u:-.*}\"", "p='.env*'; ls $p", "p='*.ts'; ls $p", "ls && pwd | wc -l", "ls .env${x}", "ls .e*${x}.ts", "ls src/.x${e}y", "awk -v re=.* 1 f", "env PAT=.* true", "echo ${x:?.*}", "ls .${x}", "ls $a.$b", "p=\"a b\"; ls $p", "p='-d .e*'", "export \"p=a\"", "echo \"p=.*\"", "grep \"p=.*\" f", "ls -d ${x:-a${y+c}}", "ls .${x:-a*${y+c}}", "p='a.? b.*'", "command echo export \"p=.*\"", "ls ${x:-${y:-a}${z+c}}", "echo ${a:-1}${b:-2}${c:-3}${d:-4}${e:-5}${f:-6}${g:-7}", "ls .e${x:-${y:-*}${z+c}}", "ls x${a:-1}${b:-2}${c:-3}${d:-4}${e:-5}${f:-y*}"]) assert.ok(!flag(c), c);
  });
});

// The two properties, word by word. Each row is the text of one or more words; a stand-in
// records the words it is given, NUL between them.
const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-canon-")));
const WORDS = [
  "a", "'a b'", '"a b"', "a\\ b", "''", '""', "a''b", "'it'\\''s'", '"it\'s"', "'\"'", '"\\""', "\\'", "\\\"", "\\\\", "'\\'", '"\\\\"', '"a\\b"', '"\\$x"', "'$x'", "\\$x", '"`"', "'`'",
  "''~/x", '~""/x', '""~', "~", "~/", "a''", "''a''", "~nosuchuser/x", "x=~/y", "x='~'/y", "a:~/b", "~+", "\\~/x",
  "'('", "')'", '"()"', "\\(\\)", "'a(b)c'", "a'('b", "'#'", "a#b", "'a #b'", "'~'", "a~b", "~'/x'", "'~'/x", "\"~\"/x", "'*'", "\"*\"", "\\*", "'[a]'", "[a'-'c]", "'?'",
  "'{a,b}'", "\\{a,b\\}", "{a,b}", "a{b,c}d", "{a,b}{1,2}", "{1..3}", "{a..c}", "x{}y", "{a}", "{,}", "a{,}", "'a'{b,c}", "{a,'b c'}", "{a,\"b,c\"}", "--x={a,b}", "{a,b}'{c,d}'",
  "'a\nb'", '"a\nb"', "a\\\nb", '"a\\\nb"', "'a\\\nb'", "'\t'", "\"  \"", "'é'", "é", "a=b", "'a=b'", "a='b c'", "-x", "'-x'", "--", "'!'", "!x", "a!b", "'^'", "^a", "%", "a+b,c:d@e/f.g_h-i",
  "'&'", "'|'", "';'", "'<'", "'>'", "'&&'", "\\&", "\\;", "\\|", "\\<", "\\>", "'$'", "a'$'b", '"$"', '"a$"', "'$('", "'`id`'", "'$(id)'", "'${x}'", "\"\\`id\\`\"",
  '$z""', "''$z", '$x""', '{,a}""', "''{,}", "{,}''", "x''{,}", "{a}b,c}", "{a}{1..2},}", "x{a}b,c}", "{a}{b,c}", "{a}{,}", "g''h", "a=''", "''a=b",
  "$x", '"$x"', "${x}", '"${x}"', '"$x"a', "$x'a'", '${x}a', '"${y}"', "$y", '"$y"', "a$x", '"a $y b"', "$z", '"$z"', '"${z:-d e}"', "${z:-d}", "${x#a}", "${x%c}", '"${y% *}"', "${#x}", "$#", '"$#"', "$?",
  '"$(echo a b)"', "$(echo a b)", '"$(echo "a  b")"', "`echo a`", '"`echo a b`"', "$(echo '(')", '"$(echo \\))"', "$((1+2))", '"$((2*3))"', "a$((1+1))b",
];
const recorded = (stdout: string) => stdout.split("\x02").slice(0, -1).map((line) => line.split("\0").slice(0, -1));
describe("the canonical printer: bash and the rules' parser make the same words of what it prints", () => {
  let rec: string;
  before(() => {
    rec = path.join(dir, "rec");
    fs.writeFileSync(rec, '#!/bin/sh\nfor a in "$@"; do printf \'%s\\0\' "$a"; done; printf \'\\2\'\n', { mode: 0o755 });
    for (const name of ["ab.txt", "a", "b", "c"]) fs.writeFileSync(path.join(dir, name), "");
  });
  after(() => fs.rmSync(dir, { recursive: true, force: true }));
  // What bash hands the stand-in for each command line, one list of words per line of commands.
  const run = (commands: string[], shell = "/bin/bash") => {
    const out: (string[] | undefined)[] = [];
    for (const command of commands) {
      const r = spawnSync(shell, ["-c", command], { cwd: dir, encoding: "utf8", env: { PATH: `${dir}:/usr/bin:/bin`, HOME: "/home/nobody", x: "abc", y: "p q", LC_ALL: "C" } });
      // Every run of the stand-in, whatever the exit status: two runs that both fail must not
      // compare as equal for that reason alone.
      out.push(r.error ? undefined : [`exit ${r.status}`, ...recorded(r.stdout).flatMap((words) => ["|", ...words])]);
    }
    return out;
  };
  test("the printed text gives bash the words the input gives it", () => {
    const inputs = WORDS.map((w) => `rec ${w} end`);
    const printed = inputs.map((c) => canonical(c));
    const was = run(inputs);
    const now = run(printed.map((p) => ("ask" in p ? ":" : p.text)));
    const bad: string[] = [];
    let asked = 0;
    for (const [n, input] of inputs.entries()) {
      const p = printed[n];
      if ("ask" in p) asked++;
      else if (JSON.stringify(was[n]) !== JSON.stringify(now[n])) bad.push(`${JSON.stringify(input)} printed ${JSON.stringify(p.text)}: bash had ${JSON.stringify(was[n])}, now ${JSON.stringify(now[n])}`);
    }
    assert.deepEqual(bad, [], `${bad.length} of ${inputs.length} words change once printed:\n${bad.join("\n")}`);
    assert.ok(asked <= 6, `the printer asked about ${asked} of ${inputs.length} words`);
  });
  // Whole commands, for the places a word table cannot reach: what a declaration builtin makes of
  // its arguments, `[[ =~ ]]`, a subshell inside a substitution, empty words.
  test("the printed text does what the input does, for commands whose quoting carries meaning", () => {
    const commands = [
      "x='1 b=2'; declare \"a\"=$x; rec \"$a\" \"${b:-unset}\"",
      "x='1 b=2'; declare a=$x; rec \"$a\" \"${b:-unset}\"",
      "x='1 b=2'; export 'a'=$x; rec \"$a\" \"${b:-unset}\"",
      "[[ 123 =~ ^[0-9]+$ ]] && rec yes; rec end",
      "[[ 12a =~ ^[0-9]+$ ]] && rec yes; rec end",
      "[[ ab =~ \"a.\" ]] && rec yes; rec end",
      "[[ a.b =~ a\\.b ]] && rec yes; rec end",
      "[[ axb =~ a\\.b ]] && rec yes; rec end",
      "p='a.'; [[ ab =~ $p ]] && rec yes; [[ ab =~ \"$p\" ]] && rec quoted; rec end",
      "[[ abc == a* ]] && rec glob; [[ abc == \"a*\" ]] && rec literal; rec end",
      "u=; set -- $u\"\"; rec $# end",
      "u=; set -- ''$u a\"\"b; rec $# \"$@\" end",
      "set -- {,a}\"\"; rec $# end",
      "rec $( (echo a) ) end",
      "rec \"$( (v=1; echo $v) )\" \"[${v:-unset}]\"",
      "rec `echo a` end",
      "cat <<EOF | { read l; rec \"$l\"; }\n$( (echo a) )\nEOF",
      "for w in a; do rec 'do' \"done\" '}'; done",
      "rec 2147483647 end > /dev/null; rec after",
      "cd ''~ 2>/dev/null; rec \"${PWD##*/}\"",
      // Round 4, second cross-check: a command that defines its own `cat` runs it for
      // `"$(cat <<'EOF' ...)"`, so the heredoc is not folded into the text it would print.
      "cat() { rec replaced; }; rec \"$(cat <<'EOF'\nliteral\nEOF\n)\" end",
      "function cat { rec replaced; }; rec \"$(cat <<'EOF'\nliteral\nEOF\n)\" end",
      "cat () { rec replaced; }\nrec \"$(cat <<EOF\nliteral\nEOF\n)\" end",
      "f() { cat() { rec replaced; }; }; f; rec \"$(cat <<'EOF'\nliteral\nEOF\n)\" end",
      "rec \"$(cat <<'EOF'\nliteral (kept)\nEOF\n)\" end",
      // Special parameters, as written.
      "set -- p q; rec $# \"$@\" $* \"$1\" ${2}0 $1x; true; rec $? \"$?\" end",
      "sleep 0 & wait $!; rec \"$?\" end",
      // Braces in the commands of a case arm expand; the word and the patterns do not.
      "case x in x) rec {a,b} one;; esac; rec end",
      "case a in a) rec one; rec {x,y}\nesac",
      "case a\nin (a) rec {x,y};; esac",
      "case b in a) rec no;; b) for i in {1..2}; do rec $i; done;; esac",
      // A backslash pair inside ${...}, quoted and not.
      "v=a/b.c; rec \"${v//\\//-}\" \"${v//\\./_}\" ${v//\\//-} \"${v%\\.*}\" end",
      "q='a\"b'; rec \"${q//\\\"/}\" end",
      "b='a\\b'; rec \"${b//\\\\/\\/}\" end",
      "rec \"${z:-\\}}\" ${z:-a\\ b} \"${z:-\\$x}\" end",
      "rec \"${z:-`echo a b`}\" ${z:-`echo c`} \"${z:-`echo \"q r\"`}\" end",
      // A heredoc in a substitution whose body holds balanced parentheses and an expansion.
      "rec \"$(cat <<EOF\nfix (api): handle $x\nEOF\n)\" end",
      "v=$(cat <<EOF\n(a) $x ((b))\nEOF\n); rec \"$v\" end",
      // Braces as bash reads them (the brace table in test/glob.test.mts holds the expander).
      "rec x{},a}y .{},} {{a},b},c} {a,{b}}c,d} {{bb},a},.} {a{b},c}d,e} {},a} {}a,b} end",
      "rec {a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b} | wc -c | { read n; rec \"$n\"; }",
      // A function named like a shell, or like eval, is handed the word as written.
      "./git() { rec got \"$3\"; }; ./git commit -m 'x  (y)'; rec end",
      "f() { rec in-f; }; rec \"$(cat <<'EOF'\nliteral\nEOF\n)\" end",
      "rec {1..1}{1..1}{1..1}{a,b} end",
      "rec {x,y}=1 --opt={a,b} {~,x} {if,then}x end",
      "rec {in,out} {if,x} {time,} {x,y}=~/z x={~,a} a:{~,b}/q {~,x}/y end",
      "rec ''{a,b} {a,b}'' end",
      "export {r4x,r4y}=~/z; rec \"$r4x\" \"$r4y\" end",
      "for i in {a,b}; do rec $i; done",
      "grep -c function /dev/null; rec function \"x\" end",
      "f() { rec in-f; }; rec \"$(cat <<'EOF'\nliteral\nEOF\n)\" end",
      "rec ~/a ~root/b ~nosuchuser/c end",
    ];
    const printed = commands.map((c) => canonical(c));
    const was = run(commands);
    const now = run(printed.map((p) => ("ask" in p ? ":" : p.text)));
    const bad: string[] = [];
    for (const [n, command] of commands.entries()) {
      const p = printed[n];
      if ("ask" in p) bad.push(`${JSON.stringify(command)} asks: ${p.ask}`);
      else if (JSON.stringify(was[n]) !== JSON.stringify(now[n])) bad.push(`${JSON.stringify(command)} printed ${JSON.stringify(p.text)}: bash had ${JSON.stringify(was[n])}, now ${JSON.stringify(now[n])}`);
    }
    assert.deepEqual(bad, [], bad.join("\n"));
  });
  // `bashOnly` is the one thing that makes a call under dash ask, so what is not marked must do
  // under dash what it does under bash. (Round 4 cross-check: a descriptor of two digits, which
  // dash hands the command as an argument, `$(< file)`, and bash's forms inside `${...}` and in
  // a heredoc body were printed without the mark.)
  test("printed text that is not marked as relying on bash gives dash the words it gives bash", (t) => {
    if (!fs.existsSync("/bin/dash")) return t.skip("no dash here");
    fs.writeFileSync(path.join(dir, "data.txt"), "from-file\n");
    const commands = [
      ...WORDS.map((w) => `rec ${w} end`),
      "rec a 10>/dev/null end",
      "rec a 12>/dev/null",
      "rec a 9>/dev/null end",
      "rec a 2>&1 >/dev/null",
      "rec a 3>&1 1>&3 3>&-",
      "rec a 10<<EOF\nx\nEOF",
      "rec \"$(< data.txt)\" end",
      "rec \"$(cat < data.txt)\" end",
      "rec \"${z:-${x^^}}\" end",
      "rec \"${z:-$((2**3))}\" end",
      "rec \"${z:-${x:1:1}}\" end",
      "rec ${x^^} ${x/b/Z} ${x:1} end",
      "rec ${#x} ${x%c} ${x#a} ${z:-d} ${z:+e} ${x:+f} end",
      "n=1; rec $((n+1)) $((n*2)) $((n<2?5:6)) $((n|4)) $((n=7)) $n end",
      "n=1; rec $((n++)) $n end",
      "n=1; rec $((--n)) end",
      "rec $((2**3)) end",
      "rec $((16#ff)) end",
      "rec $((1,2)) end",
      "cat <<EOF | { read l; rec \"$l\"; }\n${x^^} $((2**3))\nEOF",
      "cat <<EOF | { read l; rec \"$l\"; }\n${x%c} $((2*3)) $(echo sub) $?\nEOF",
      "rec [^b] [!b] end",
      "rec ~+ a=~/x end",
      "for f in a b; do rec $f; done",
      "set -- p q; rec \"$@\" $# $1 end; true; rec $? end",
      "sleep 0 & wait $!; rec $? end",
      "f() { rec in-f \"$1\"; }; f x",
      "case x in x) rec {a,b};; esac",
      "rec {a,b} end",
      "[[ -d . ]] && rec yes",
      "v=a.b; rec \"${v%\\.*}\" \"${v#a\\.}\" end",
      "a=1; a+=2 rec x; rec \"$a\" end",
      "rec .? end",
      "rec .* end",
      "rec .[.] .?? end",
      "rec ~: ~root:x end",
      "set -- p q; rec $(( $# + 1 )) end",
      "a=1 b=2 rec x; rec end",
      // bash joins a line that ends in a backslash before it looks for the delimiter; dash does not.
      "cat <<EOF | { read l; rec \"$l\"; }\na\\\nb\nEOF",
      "cat <<EOF | { read l; rec \"$l\"; }\nEO\\\nF\nrec hidden\nEOF",
    ];
    const printed = commands.map((c) => canonical(c));
    const texts = printed.map((p) => ("ask" in p || p.bashOnly ? ":" : p.text));
    const [bash, dash] = [run(texts), run(texts, "/bin/dash")];
    const bad: string[] = [];
    let compared = 0;
    for (const [n, command] of commands.entries()) {
      const p = printed[n];
      if ("ask" in p || p.bashOnly) continue;
      compared++;
      if (JSON.stringify(bash[n]) !== JSON.stringify(dash[n])) bad.push(`${JSON.stringify(command)} printed ${JSON.stringify(p.text)}, not marked: bash ${JSON.stringify(bash[n])}, dash ${JSON.stringify(dash[n])}`);
    }
    assert.ok(compared > 140, `only ${compared} of ${commands.length} commands were compared`);
    assert.deepEqual(bad, [], `${bad.length} printed texts differ under dash:\n${bad.join("\n")}`);
  });
  // The trace and the stand-in show words, not where output went (second round 4 cross-check):
  // here each command runs in a directory of its own and the files it leaves are compared.
  test("the printed text writes the files the input writes", () => {
    const commands = [
      "rec a > out1; rec b >> out1; rec c 2> err1 >&2",
      "rec d > 'a b'; rec e > \"c d\"; rec f > e\\ f",
      "rec g >| o1; rec h 3> t3 >&3; rec i > o2 2>&1",
      "rec j &> both; rec k &>> both",
      "printf x > in1; cat < in1 > o3; cat <<< here > o4; cat <<EOF > o5\nbody $x\nEOF",
      "rec l > o6 > o7; rec m >o8 2>o9; : > empty",
      "rec n > {a,b}.txt || true; rec o > 'q{a,b}.txt'",
      "rec p > ~nosuchuser.txt; rec q > '~x'; rec r > \\#hash; rec s > '-dash'",
      "tee t1 t2 < /dev/null; tee {u1,u2} < /dev/null; tee {{w},x},y} < /dev/null",
      "exec 5> fd5; rec t >&5; exec 5>&-; rec u 9> nine",
    ];
    const snapshot = (command: string, n: number, tag: string) => {
      const work = path.join(dir, `files-${tag}-${n}`);
      fs.mkdirSync(work);
      spawnSync("/bin/bash", ["-c", command], { cwd: work, encoding: "utf8", env: { PATH: `${dir}:/usr/bin:/bin`, HOME: "/home/nobody", x: "abc", LC_ALL: "C" } });
      return JSON.stringify(fs.readdirSync(work).sort().map((name) => [name, fs.readFileSync(path.join(work, name), "utf8")]));
    };
    const bad: string[] = [];
    for (const [n, command] of commands.entries()) {
      const p = canonical(command);
      if ("ask" in p) continue;
      const [was, now] = [snapshot(command, n, "in"), snapshot(p.text, n, "out")];
      if (was !== now) bad.push(`${JSON.stringify(command)} printed ${JSON.stringify(p.text)}: the input left ${was}, the printed text ${now}`);
    }
    assert.deepEqual(bad, [], bad.join("\n"));
  });
  // Printing is linear in the length of the command (it was quadratic in its words and lines).
  test("a very long command is printed in good time", () => {
    const started = Date.now();
    const words = canonical(`git add ${Array.from({ length: 50_000 }, (_, n) => `src/f${n}.ts`).join(" ")}`);
    const lines = canonical(Array.from({ length: 50_000 }, () => "echo a").join("\n"));
    const took = Date.now() - started;
    // Both are longer than one variable can hold: they ask, and say so at once.
    assert.ok("ask" in words && "ask" in lines);
    const some = canonical(`git add ${Array.from({ length: 6_000 }, (_, n) => `src/f${n}.ts`).join(" ")}\n${Array.from({ length: 1_500 }, () => "echo a").join("\n")}`);
    assert.ok(!("ask" in some) && some.text.split(/[ \n]/).length === 6_002 + 3_000, "ask" in some ? some.ask : String(some.text.split(/[ \n]/).length));
    // As many words, and as many lines, as fit under the limit.
    const many = canonical(`echo ${"a ".repeat(49_000)}`);
    const long = canonical("echo a\n".repeat(14_000));
    assert.ok(!("ask" in many) && !("ask" in long));
    assert.ok(Date.now() - started < 3_000, `printing took ${took} ms and ${Date.now() - started} ms in all`);
  });
  test("the rules' parser reads the printed text as the words bash makes of it", () => {
    const bad: string[] = [];
    // Words with nothing for bash to expand at run time: the parser's words are the final ones.
    const fixed = WORDS.filter((w) => !/[$`]/.test(w.replace(/'[^']*'/g, "").replace(/\\./gs, "")) && !/[*?[~]/.test(w.replace(/'[^']*'|"[^"]*"/g, "").replace(/\\./gs, "")));
    const inputs = fixed.map((w) => `rec ${w} end`);
    const printed = inputs.map((c) => canonical(c));
    const now = run(printed.map((p) => ("ask" in p ? ":" : p.text)));
    for (const [n, input] of inputs.entries()) {
      const p = printed[n];
      if ("ask" in p) continue;
      for (const which of [p.text, p.judged]) {
        const parsed = parse(which);
        const argv = parsed.cmds.map((c) => c.argv);
        if (parsed.opaque || argv.length !== 1 || JSON.stringify(["exit 0", "|", ...argv[0].slice(1)]) !== JSON.stringify(now[n])) bad.push(`${JSON.stringify(input)} printed ${JSON.stringify(which)}: bash ${JSON.stringify(now[n])}, the parser ${JSON.stringify(argv)}`);
      }
    }
    assert.ok(fixed.length > 80, `only ${fixed.length} fixed words in the table`);
    assert.deepEqual(bad, [], `${bad.length} of ${inputs.length} printed words read differently:\n${bad.join("\n")}`);
  });
});

// Round 4, group B, third pass, second go (B3b).
describe("r4 B3b: the printer hands out what it reads", () => {
  // B3b-1: the target of every input redirect it prints (`<` with any descriptor number), at
  // every depth, as it prints it; not a descriptor copy, a here-string, a heredoc, or a process
  // substitution as a whole (its code is printed, and what it redirects is listed).
  const inputs = (command: string) => {
    const printed = canonical(command);
    return "ask" in printed ? `ASK: ${printed.ask}` : printed.inputs;
  };
  test("r4 B3b-1: the input redirects, at every depth", () => {
    const rows: [string, string[]][] = [
      ["cat < f", ["f"]],
      ["cat 0< f", ["f"]],
      ["cat 3< f <&3", ["f"]],
      ["{ cat; } < .env", [".env"]],
      ["( cat ) < .env", [".env"]],
      ["[[ -n $(cat) ]] < .env", [".env"]],
      ["echo \"$(< .env)\"", [".env"]],
      ["echo `< .env`", [".env"]],
      ["cat <(< .env)", [".env"]],
      ["cat < <(sort f)", []],
      ["cat <<EOF\n$( { cat; } < .env )\nEOF", [".env"]],
      ["bash -c 'tee o < .env'", [".env"]],
      ["eval 'tee o < .env'", [".env"]],
      ["echo \"$(bash -c 'exec < ~/.ssh/id_ed25519; cat')\"", ["~/.ssh/id_ed25519"]],
      ["cat < 'a b' < \"$f\" < $(echo x)", ["'a b'", "\"$f\"", "$(echo x)"]],
      ["f=x; cat < \"$f\"", ["\"$f\""]],
      ["cat <<< .env", []],
      ["cat <<'EOF'\n< .env\nEOF", []],
      ["cat <&3 > out 2>&1", []],
      ["echo '< .env'", []],
    ];
    const bad = rows.filter(([command, want]) => JSON.stringify(inputs(command)) !== JSON.stringify(want)).map(([command, want]) => `${JSON.stringify(command)}: ${JSON.stringify(inputs(command))}, want ${JSON.stringify(want)}`);
    assert.deepEqual(bad, [], bad.join("\n"));
  });
  // The text and the judged text are not changed by it.
  test("r4 B3b-1: the printed text stays as it was", () => {
    assert.equal(text("{ cat; } < .env"), "{ cat ; } < .env");
    assert.equal(judged("[[ -n $(cat) ]] < .env"), "test -n $(cat) < .env");
  });

  // B3b-3: an expansion where the first member of a bracket would stand may be empty, and the
  // `]` after it is then the first member (`[$x]\a]` with x empty is `[]\a]`: a bracket of `]`
  // and a quoted `a`); one that holds `!` or `^` makes the next character the first member too.
  // Every reading is followed: those that close the bracket there, and those that hold it open.
  test("r4 B3b-3: an expansion where the first member stands", () => {
    const bad: string[] = [];
    for (const word of ["[$x]\\a]", "[!$x]\\a]", "[^$x]\\a]", "[$x!]\\a]", "[$x^]'a]'", "[$x$y]'a']", "[${x}]\"a\"]", "[$(x)]'a']", "[$x][:a'b']", "[$x]'a'[b'c']"]) {
      const printed = canonical(`echo ${word}`);
      if (!("ask" in printed)) bad.push(`${word}: printed ${JSON.stringify(printed.text)}, no ask`);
    }
    for (const word of ["[$x]", "[$x]a", "[$x]'a'", "[$x]a]", "[!$x]a]", "[1]\"a]\"", "[$x]\"a\"x", "a$x]'b'", "[!$x!]'a']"]) {
      const printed = canonical(`echo ${word}`);
      if ("ask" in printed) bad.push(`${word}: asks (${printed.ask})`);
    }
    assert.deepEqual(bad, [], bad.join("\n"));
  });
});

// Round 4, group B, third pass, first part, third go (B3c).
describe("r4 B3c: the printer's input targets and brackets", () => {
  // B3c-4: beside each input target as it runs, the target in its judged spelling: a variable
  // that plainly holds a literal (constantsOf) is that literal there, quoted or not (a redirect's
  // target is one word: bash does not split it into several).
  const both = (command: string) => {
    const printed = canonical(command);
    return "ask" in printed ? `ASK: ${printed.ask}` : JSON.stringify([printed.inputs, (printed as { judgedInputs?: string[] }).judgedInputs]);
  };
  test("r4 B3c-4: the judged spelling of each input target", () => {
    const rows: [string, string[], string[]][] = [
      ["f=notes.txt; wc -l < \"$f\"", ["\"$f\""], ["notes.txt"]],
      ["file=README.md; wc -l < $file", ["$file"], ["README.md"]],
      ["f=secrets.json; cat < \"$f\"", ["\"$f\""], ["secrets.json"]],
      // A value that begins with `.` is no literal to constantsOf.
      ["f=.env; cat < \"$f\"", ["\"$f\""], ["\"$f\""]],
      ["d=src; wc -l < \"$d\"/main.c", ["\"$d\"/main.c"], ["src/main.c"]],
      ["f=notes.txt; echo \"$(wc -l < \"$f\")\"", ["\"$f\""], ["notes.txt"]],
      ["wc -l < \"$f\"", ["\"$f\""], ["\"$f\""]],
      ["f=notes.txt; f2=x; wc -l < \"$f$f2\"", ["\"$f\"\"$f2\""], ["notes.txtx"]],
      ["f=notes.txt; bash -c 'wc -l < \"$f\"'", ["\"$f\""], ["\"$f\""]],
      ["f=notes.txt; read f; wc -l < \"$f\"", ["\"$f\""], ["\"$f\""]],
      ["cat < 'price$USD.txt'", ["'price$USD.txt'"], ["'price$USD.txt'"]],
    ];
    const bad = rows.filter(([c, run, judged]) => both(c) !== JSON.stringify([run, judged])).map(([c, run, judged]) => `${JSON.stringify(c)}: ${both(c)}, want ${JSON.stringify([run, judged])}`);
    assert.deepEqual(bad, [], bad.join("\n"));
  });
  // B3c-5: a word with an expansion inside a bracket is printed without an ask (the guards never
  // match it as a literal pattern; decide.test.mts, B3c-5, has `cat` of each go to the model).
  test("r4 B3c-5: an expansion inside a bracket, away from the first member", () => {
    for (const word of ["[a$x[:a'-'z]", "p[a\"$x\"]"]) {
      const printed = canonical(`echo ${word}`);
      assert.ok(!("ask" in printed), `${word}: ${"ask" in printed ? printed.ask : ""}`);
    }
  });
});

// Round 4, found by the variant check of group B's fourth go: a descriptor copy `<&N` is left out
// of the judged text (the rules read the digit as a command), and one that fails keeps its
// command from running. On a command that moves the shell every later command is judged by
// where it went, so the printer asks there (`cd src <&9; cat x` was judged in `src`; before
// the round it went to the model as "unknown command 9").
describe("r4: a descriptor copy on a command that moves the shell", () => {
  test("cd, pushd and popd with <&N ask, in every spelling and at every depth", () => {
    const rows = [
      "cd src <&9; cat x",
      "cd src <&9 && cat x",
      "cd <&9 src; cat x",
      "<&9 cd src; cat x",
      "pushd src <&3; cat x",
      "popd <&3; cat x",
      "command cd src <&9; cat x",
      "builtin cd src <&9; cat x",
      "'cd' src <&9; cat x",
      "\\cd src <&9; cat x",
      "cd src <&-; cat x",
      "bash -c 'cd src <&9; cat x'",
      "echo \"$(cd src <&9; cat x)\"",
      "(cd src <&9; cat x)",
    ];
    const bad = rows.filter((c) => {
      const printed = canonical(c);
      return !("ask" in printed) || !/descriptor copy/.test(printed.ask);
    });
    assert.deepEqual(bad, []);
  });
  test("on any other command it is printed and left out of the judged text, as before", () => {
    for (const [c, judged] of [["ls <&3", "ls"], ["cat f <&3 2>&1", "cat f 2>&1"], ["cd src; cat x <&3", "cd src ; cat x"]] as const) {
      const printed = canonical(c);
      assert.ok(!("ask" in printed), `${c}: ${"ask" in printed ? printed.ask : ""}`);
      if (!("ask" in printed)) assert.equal(printed.judged, judged, c);
    }
  });
});

// Printer pass 6j (found by the variant check of group B's place shape): the same on a compound
// command. `{ true; cd src; } <&9; cat x`: the copy on the closing brace fails, the group does
// not run, and the judged text read as if it had. A copy that is left out of the judged text on
// a group, a loop, a branch or a function's body asks where the call moves the shell at all.
describe("r4: a descriptor copy on a compound command, in a call that moves the shell", () => {
  test("a copy from anything but a plain number asks by itself, on a mover and on a group", () => {
    for (const c of ["cd src <&$n; cat x", "cd src <&\"9\"; cat x", "cd src <&9-; cat x", "{ true; cd src; } <&$n; cat x", "{ true; cd src; } <&9-; cat x"]) {
      assert.ok("ask" in canonical(c), c);
    }
  });
  test("asks, whatever the compound command and wherever the cd stands in it", () => {
    const rows = [
      "{ true; cd src; } <&9; cat x",
      "{ :; cd src; } <&9; cat x",
      "{ true; cd src; true; } <&9; cat x",
      "{ true; pushd src; } <&9; cat x",
      "{ true; cd \"$PWD/src\"; } <&9; cat x",
      "bash -c '{ true; cd src; } <&9; cat x'",
      "sh -c '{ true; cd src; } <&9; cat x'",
      "while cd src; do break; done <&9; cat x",
      "if cd src; then :; fi <&9; cat x",
      "for d in src; do cd \"$d\"; done <&9; cat x",
      "case x in x) cd src;; esac <&9; cat x",
      "f() { cd src; } <&9; f; cat x",
      "( true; cd src ) <&9; cat x",
      "{ true; cd src; } <&9 >/dev/null; cat x",
      "{ { true; cd src; }; } <&9; cat x",
      "cd src; { true; } <&9; cat x",
      // The cd and the copy in different texts: each is seen from the other (the reading of
      // passes 6i and 6j: the eval rows fail when the flags are not handed out of eval's code).
      "eval '{ true; cd src; } <&9'; cat x",
      "eval 'cd src'; { true; } <&9; cat x",
      "bash -c 'cd src'; { true; } <&9; cat x",
      "{ true; } <&9; bash -c 'cd src; cat x'",
    ];
    const bad = rows.filter((c) => {
      const printed = canonical(c);
      return !("ask" in printed) || !/descriptor copy/.test(printed.ask);
    });
    assert.deepEqual(bad, []);
  });
  test("a copy on a program, or on a compound command in a call that moves nothing, is printed as before", () => {
    for (const [c, judged] of [
      ["cd src; cat x <&3", "cd src ; cat x"],
      ["{ ls; } <&3", "{ ls ; }"],
      ["{ true; } <&9; ls", "{ true ; } ; ls"],
      ["while read -r l; do echo \"$l\"; done <&3", undefined],
      ["cd src && make <&3", "cd src && make"],
      // An output copy stays in the judged text, where the guard's walker sees it and judges
      // what follows the group in both places (the variant check of passes 6i and 6j: nothing
      // held that `>&N` is not taken for the input copy).
      ["{ true; cd src; } >&9; cat x", "{ true ; cd src ; } >&9 ; cat x"],
      ["{ true; cd src; } 2>&9; cat x", "{ true ; cd src ; } 2>&9 ; cat x"],
    ] as const) {
      const printed = canonical(c);
      assert.ok(!("ask" in printed), `${c}: ${"ask" in printed ? printed.ask : ""}`);
      if (judged !== undefined && !("ask" in printed)) assert.equal(printed.judged, judged, c);
    }
  });
});
