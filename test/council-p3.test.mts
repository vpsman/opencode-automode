// Council project review 3: a writer's second name, which its command line fixes (a backup's
// suffix or prefix, a compressor's output in place), is held to the protected-name test like
// every target.
// Run: node test/run.mjs test/council-p3.test.mts.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideShell, SessionState, takeMoment, type Guard } from "../decide.ts";
SessionState.moment = takeMoment;
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

assert.ok(process.env.GIT_CONFIG_GLOBAL?.startsWith(os.homedir()), "run through test/run.mjs, which supplies a throwaway $HOME");
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), "council-p3-")));
const repo = path.join(base, "repo");
const under = path.join(base, ".claude", "worktrees", "p");
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
  fs.mkdirSync(path.join(repo, "sub"), { recursive: true });
  for (const d of ["a", "b/a", "c/a", "z", "src"]) fs.mkdirSync(path.join(repo, d), { recursive: true });
  for (const f of ["f", "AGENTS", ".gi", "sub/AGENTS.md.gz", "sub/a.txt.gz", "a/AGENTS", "b/a/AGENTS", "c/a/.gi", "z/AGENTS.md", "z/n.txt.gz", "src/x.ts"]) fs.writeFileSync(path.join(repo, f), "x\n");
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  // A project kept under a directory of a protected name (a worktree under `.claude/`).
  fs.mkdirSync(path.join(under, "src"), { recursive: true });
  for (const f of ["f", "g.txt.gz", "src/x.ts"]) fs.writeFileSync(path.join(under, f), "x\n");
  execFileSync("git", ["init", "-q", "-b", "main", under]);
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

const decide = async (command: string) => (await decideShell(guard, new SessionState(repo), repo, command)).effect;

test("round 2 (Mythos): a backup or a compressor's output with a protected name asks", async () => {
  for (const command of [
    "sed -it p sub/.gi",
    "sed -i.md p AGENTS",
    "sed --in-place=.md p AGENTS",
    "sed -ni.md p AGENTS",
    "cp -b -S t f sub/.gi",
    "cp -bSt f sub/.gi",
    "cp --backup --suffix=t f sub/.gi",
    "cp --backup --suf=t f sub/.gi",
    "cp -b -S t .gi sub",
    "cp -b -S t -t sub .gi",
    "cp -b -S .md f AGENTS",
    "mv -b -S t f sub/.gi",
    "install -b -S t f sub/.gi",
    "ln -sb -S t f sub/.gi",
    "patch -b -z t sub/.gi a.diff",
    "patch -b -Y .gi sub/t a.diff",
    "patch -b -B sub/.gi t a.diff",
    // (Round 3, Opus: the targets the diff names.)
    "patch -b -z .md -p0 < a.diff",
    "patch -b -z .md -p0 -i a.diff",
    "patch -b -Y . -p0 < g.diff",
    "patch -b -B .gi -p0 < d.diff",
    "gunzip AGENTS.md.gz",
    "gzip -d opencode.jsonc.gz",
    "xz -d opencode.json.xz",
    "zstd -d AGENTS.md.zst",
    "gunzip lefthook.yml.gz",
    "gunzip .claude/settings.json.gz",
    "gunzip sub/*.gz",
    "gzip AGENTS.md",
  ]) assert.equal(await decide(command), "ask", command);
});

test("round 2: the plain forms of the same writers stay allowed", async () => {
  for (const command of [
    "sed -i p f",
    "sed -i.bak p f",
    "cp -b f g",
    "cp -b -S t f sub",
    "cp --backup=numbered -S .bak f g",
    "patch -b f a.diff",
    "patch -p1 < a.diff",
    "patch -b -p1 -i a.diff",
    "gunzip x.txt.gz",
    "gunzip sub/a*.gz",
    "gzip f",
    "gzip -dc AGENTS.md.gz",
  ]) assert.equal(await decide(command), "allow", command);
});

test("round 3 (Mythos): names built from the call's variables, composed patch names, gzip's own completion, globs and recursive copies", async () => {
  for (const command of [
    "x=opencode; echo '{}' > $x.json",
    "x=opencode; echo '{}' | tee $x.json",
    "x=.git; printf 'gitdir: ../e\\n' > sub/$x",
    "x=.git; mkdir -p sub/$x/hooks",
    "x=.husk; echo hi > ${x}y/pre-commit",
    "x=hook; echo hi > left$x.yml",
    "x=.claude; echo hi > $x/settings.json",
    "x=.agents; mkdir -p $x/skills",
    "x=AGENTS.md.gz; gunzip $x",
    "x=AGENTS.md; gzip $x",
    "s=t; patch -b -z $s sub/.gi a.diff",
    "patch -b -Y .g -z t sub/i a.diff",
    "patch -b -B CLA -z .md UDE a.diff",
    "gunzip AGENTS.md",
    "gzip -d sub/CLAUDE.md",
    "sed -i.md p *",
    "cp -S .md a/* b/a",
    "mv -S .md a/* b/a/",
    "cp -rS t c b",
    // Round 16 (Neon #3): gunzip is now in READERS/KEYED (matching gzip), so an expanding
    // operand classifies (asks with model off).
    "x=f.gz; gunzip $x",
  ]) assert.equal(await decide(command), "ask", command);
  for (const command of [
    "x=out; echo hi > $x.txt",
    "x=build; mkdir -p $x/a",
    "gunzip f",
    "sed -i p *",
    "cp -r a b",
  ]) assert.equal(await decide(command), "allow", command);
});

test("round 3 (Mythos, on the fixes): a variable before a glob, a name the rules cannot resolve, a pattern for a file not there yet, bash's own variables", async () => {
  for (const command of [
    // A compressor's operand: the call's variable, then a glob (`sub/AGENTS.md.gz` is there).
    "x=sub; gunzip $x/*.gz",
    "x=sub; gunzip $x/A*",
    "x=z; gzip $x/*",
    // Round 16 (Neon #3): gunzip is now in READERS/KEYED (matching gzip).
    "x=z; gunzip $x/*.gz",
    "x=sub; gunzip $x/a*.gz",
    // A backup's pattern is held to the test where the file is made by the same call.
    "echo hi > CLAUDE; sed -i.md p CLAUD?",
    "cp f CLAUDE; cp -S .md f CLAUD?",
    "x=AGENTS; touch $x.m?",
    // A variable bash gives a value of its own is not the text the call assigned.
    "FUNCNAME=x; mkdir -p sub/.git$FUNCNAME/hooks",
    "FUNCNAME=x; echo hi > AGENTS${FUNCNAME}.md",
    "REPLY=out; read < f; echo hi > $REPLY",
    "cd .git/hooks && DIRSTACK=/tmp; echo payload > $DIRSTACK/pre-commit",
    "rsync -ab --suffix=t c/ b/",
    // A name the command line does not show, with a suffix that can end a protected name.
    "cp -a -S .md a b",
    "cp -r -S n src sub",
    "cp -r -S x/y src sub",
    "x=AGENTS; cp -S .md f $x",
  ]) assert.equal(await decide(command), "ask", command);
  // A name the rules cannot resolve asks by the rules' own word, the model on or off.
  for (const command of ["for x in AGENTS.md.gz; do gunzip $x; done", "gunzip $y", "x=$(cat n); gzip $x"]) {
    const d = await decideShell(guard, new SessionState(repo), repo, command);
    assert.equal(d.effect, "ask", command);
    assert.match(d.reason, /built at run time/, command);
  }
  for (const command of [
    // The names a glob matches, each less its suffix: not every name beside them.
    "gunzip z/*.gz",
    "sed -i.bak p src/*.ts",
    "OUT=sub; echo hi > $OUT/o.txt",
    // ln's -r is --relative.
    "ln -sr -S .bak f sub/l",
    // No protected name ends in the suffix: nothing a recursive copy backs up can be one.
    "cp -r -S .bak src sub",
    "cp -a --suffix=.orig a b",
  ]) assert.equal(await decide(command), "allow", command);
});

test("round 3 (Mythos, on the fixes): in a project under a directory of a protected name, a glob's names are read from where the command runs", async () => {
  const decideUnder = async (command: string) => (await decideShell(guard, new SessionState(under), under, command)).effect;
  for (const command of ["gunzip g*.gz", "sed -i.bak p src/*.ts", "patch -b -z .orig src/*.ts a.diff", "x=out; echo hi > $x.txt"]) assert.equal(await decideUnder(command), "allow", command);
  for (const command of ["sed -i.md p src/../AGENT*", "x=opencode; echo '{}' > $x.json", "gunzip AGENTS.md"]) assert.equal(await decideUnder(command), "ask", command);
});

test("round 4 (Mythos): an expansion that assigns, and a place an option names with a variable or a glob", async () => {
  for (const command of [
    // `${x:=V}` is a second assignment: bash writes AGENTS.md, and runs `rm -rf -- *`.
    'x=; : "${x:=.md}"; echo hi > AGENTS$x',
    'x=; : "${x=.md}"; echo hi > AGENTS$x',
    'x=; : "${x[0]:=.md}"; echo hi > AGENTS$x',
    'x=; : "${y:-${x:=.md}}"; echo hi > AGENTS$x',
    'x=; echo "${x:=.md}" > /dev/null; echo hi > AGENTS$x',
    'x=; y=${x:=.md}; echo hi > AGENTS$x',
    "x=; : <<E\n${x:=.md}\nE\necho hi > AGENTS$x",
    'x=; : <<< "${x:=.md}"; echo hi > AGENTS$x',
    'x=; : "${x:=.git}"; mkdir -p sub/$x/hooks',
    'x=; : "${x:=-rf -- *}"; rm $x f',
    // The directory `unzip -d` and `tar -C` name, built at run time or by a glob.
    "x=git; unzip -o a.zip -d sub/.$x",
    "x=git; unzip -o a.zip -dsub/.$x",
    "x=hooks; unzip -o a.zip -d .git/$x",
    "x=..; unzip -o a.zip -d$x/o",
    "for x in git; do unzip -o a.zip -d sub/.$x; done",
    "unzip -o a.zip -d sub/.husk?",
    "unzip -o a.zip -d sub/.gi[t]",
    "tar xf a.tar -C sub/.husk?",
    "tar xf a.tar -C .gi?",
    "tar xf a.tar --directory=sub/.husk?",
    "x=git; tar xf a.tar -C sub/.$x",
    "x=git; unzip -od sub/.$x a.zip",
    "x=opencode; unzip -o a.zip -d sub/.$x",
    "x=.claude; unzip -o a.zip -d $x/skills",
    "x=sub; unzip -o a.zip -d $x/.gi?",
    "x=/etc; unzip -o a.zip -d$x",
    "x=-d; unzip -o a.zip $x sub/.git",
    "x=-od; unzip $x sub/.git a.zip",
    "unzip -o a.zip -d .git/$y",
    "tar xf a.tar -C .git/$y",
  ]) assert.equal(await decide(command), "ask", command);
  // A place the rules resolve to a protected name asks by the rules' own word, the model on or off.
  for (const command of ["x=git; unzip -o a.zip -d sub/.$x", "x=git; tar xf a.tar -C sub/.$x"]) {
    const d = await decideShell(guard, new SessionState(repo), repo, command);
    assert.match(d.reason, /^(unzip|tar) writes in a \.git directory/, command);
  }
  for (const command of [
    "x=.md; echo hi > notes$x",
    'x=.md; : "${y:=1}"; echo hi > notes$x',
    ': "${CI:=false}"; echo hi > notes.txt',
    "unzip -o a.zip -d z",
    'unzip -o a.zip -d "$PWD/z"',
    "x=z; unzip -o a.zip -d $x",
    "unzip -o a.zip -d s*",
    "tar xf a.tar -C z",
    "tar xf a.tar -C s*",
    "tar tf a.tar -C sub/.gi?",
    "unzip -l a.zip -d .gi?",
    "cp -r a b",
  ]) assert.equal(await decide(command), "allow", command);
});

test("round 5 (Mythos): an assignment or a cd the call may not reach, a name on its option's letter, arithmetic that assigns", async () => {
  // The redirect after a `cd` the call may not reach asks by where it lands without the `cd`.
  const d = await decideShell(guard, new SessionState(repo), repo, "true || cd sub; echo hi > ../o.txt");
  assert.match(d.reason, /redirect writes outside the working directory: \.\.\/o\.txt \(where it runs: /);
  for (const command of [
    // Behind `&&` or `||` the assignment may not run: `$x` is then empty, and bash writes
    // `.git/hooks/pre-commit`, `AGENTS.md`, and removes `/home`.
    "false && x=foo; echo hi > .git$x/hooks/pre-commit",
    "true || x=foo; echo hi > AGENTS.md$x",
    "false && x=foo; rm -rf $x/home",
    "false && true && x=foo; echo hi > AGENTS.md$x",
    "false && x=foo && true; echo hi > AGENTS.md$x",
    "{ false && x=foo; }; echo hi > AGENTS.md$x",
    "false &&\nx=foo\necho hi > AGENTS.md$x",
    "mkdir -p b && x=b; echo hi > $x/f",
    // The same inside a branch, a loop or a group, wherever the assignment stands in it.
    "if false; then :; x=foo; fi; echo hi > AGENTS.md$x",
    "if false; then\nx=foo\nfi\necho hi > AGENTS.md$x",
    "if true; then :; else\nx=foo\nfi; echo hi > AGENTS.md$x",
    "while false; do\nx=foo\ndone; echo hi > AGENTS.md$x",
    "for y in; do :; x=foo; done; echo hi > AGENTS.md$x",
    "for fi in a; do\nx=foo\ndone; echo hi > AGENTS.md$x",
    "false && { :; x=foo; }; echo hi > AGENTS.md$x",
    "false || {\nx=foo\n}; echo hi > .git$x/hooks/pre-commit",
    // Behind a command the rules do not list: arithmetic, a redirect with no command.
    "((0)) && x=foo; echo hi > AGENTS.md$x",
    "< nope && x=foo; echo hi > AGENTS.md$x",
    // A `cd` the call may not reach: the redirect is written from where the call starts, and
    // is judged in each place the command may run in.
    "true || cd sub; echo hi > ../o.txt",
    "false && cd sub; echo hi > ../o.txt",
    "true || cd sub && echo hi > ../o.txt",
    "true && false || cd sub && echo hi > ../o.txt",
    "false && { :; cd sub; }; echo hi > ../o.txt",
    "((0)) && cd sub; echo hi > ../o.txt",
    "< nope && cd sub; echo hi > ../o.txt",
    "true || cd sub; > ../o.txt",
    "true || cd sub; echo hi >> ../o.txt",
    "true || cd sub; echo hi 2> ../o.txt",
    "true || cd sub; echo hi > ../sub/o.txt",
    "x=..; true || cd sub; echo hi > $x/o.txt",
    // The name a builtin sets, on its option's letter.
    "x=foo; printf -vx %s ''; echo hi > AGENTS.md$x",
    "x=foo; printf -vx ''; echo hi > AGENTS.md$x",
    "x=foo; command printf -vx ''; echo hi > AGENTS.md$x",
    'x=foo; "printf" -vx \'\'; echo hi > AGENTS.md$x',
    "x=foo; printf -v{x,} ''; echo hi > AGENTS.md$x",
    "x=foo; wait -px; echo hi > AGENTS.md$x",
    "x=foo; wait -fpx; echo hi > AGENTS.md$x",
    "x=foo; wait -npx; echo hi > AGENTS.md$x",
    // Arithmetic that assigns: `$x` is a number afterwards.
    "x=foo; : $((x=5)); echo hi > AGENTS$x",
    "x=foo; ((x=1)); echo hi > AGENTS.md$x",
    "x=foo; (( y = x = 0 )); echo hi > AGENTS.md$x",
    "x=5; ((x+=1)); echo hi > f$x.txt",
    "x=5; : $((--x)); echo hi > f$x.txt",
    "x=foo; : <<E\n$((x=5))\nE\necho hi > AGENTS.md$x",
    'x=foo; : "${y:-$((x=5))}"; echo hi > AGENTS.md$x',
  ]) assert.equal(await decide(command), "ask", command);
  for (const command of [
    "x=out; echo hi > $x.txt",
    "x=b && echo hi > $x/f",
    "x=out; true && echo hi > $x.txt",
    "x=out; if true; then echo hi > $x.txt; fi",
    "if true; then :; fi; x=out; echo hi > $x.txt",
    "x=foo && false; echo hi > notes$x",
    "printf -v x %s out; echo hi > out.txt",
    "x=out; printf -v y %s out; echo hi > $x.txt",
    "x=out; wait -p y; echo hi > $x.txt",
    "x=3; echo $((x+1)) > out.txt",
    "n=1; echo $((n*2)) > $n.txt",
    "x=5; ((y=x+1)); echo hi > f$x.txt",
    "x=5; : $((x<=1)); echo hi > f$x.txt",
    "i=0; i=$((i+1)); echo $i",
    "cd sub && echo hi > out.txt",
    "cd sub || exit 1; echo hi > out.txt",
    "mkdir -p build && cd build && echo hi > out.txt",
    "test -d sub && cd sub; ls",
    "true || cd sub; echo hi > o.txt",
    "test -d sub && cd sub; echo hi > out.txt",
    "true || cd sub; echo hi > /dev/null",
    "cd sub && echo hi > ../o.txt",
    "OUT=out; cd sub && echo hi > $OUT.txt",
  ]) assert.equal(await decide(command), "allow", command);
});

test("round 6 (Mythos): an assignment or a cd in a background list, or on a line a failure before it ends", async () => {
  const d = await decideShell(guard, new SessionState(repo), repo, ": $((1/0)); cd sub\necho hi > ../o.txt");
  assert.match(d.reason, /a cd on a line that an expansion or an assignment before it may end/);
  for (const command of [
    // The whole list is the job: bash assigns in the job's shell, `$x` is empty in the call's,
    // and it writes `AGENTS.md` and `.git/hooks/pre-commit`, and removes `/home`.
    "x=foo && true & wait; echo hi > AGENTS.md$x",
    "x=foo || true & wait; echo hi > AGENTS.md$x",
    "x=foo && true && true & wait; echo hi > AGENTS.md$x",
    "x=foo || true && true & wait; echo hi > AGENTS.md$x",
    "x=foo && true | cat & wait; echo hi > AGENTS.md$x",
    "x=foo &&\ntrue & wait; echo hi > AGENTS.md$x",
    "x=foo &&\n# c\ntrue & wait; echo hi > AGENTS.md$x",
    "x=foo && true &\necho hi > .git$x/hooks/pre-commit",
    "x=foo && true &\nwait\necho hi > AGENTS.md$x",
    "x=foo && sleep 0 & echo hi > .git$x/hooks/pre-commit",
    "x=foo && true & rm -rf $x/home",
    "x=foo && true&wait; echo hi > AGENTS.md$x",
    "x=foo && true&&true& wait; echo hi > AGENTS.md$x",
    "x=foo && true 2>&1 & wait; echo hi > AGENTS.md$x",
    "x=foo && true &> /dev/null & wait; echo hi > AGENTS.md$x",
    "x=foo && cat <<E &\na\nE\nwait; echo hi > AGENTS.md$x",
    // The list ends in a compound command, or in one the rules do not list.
    "x=foo && { true; } & wait; echo hi > AGENTS.md$x",
    "x=foo && { true; } | cat & wait; echo hi > AGENTS.md$x",
    "x=foo && { true; } 2>/dev/null & wait; echo hi > AGENTS.md$x",
    "x=foo && ! { true; } & wait; echo hi > AGENTS.md$x",
    "x=foo && if true; then :; fi & wait; echo hi > AGENTS.md$x",
    "x=foo && if true; then :; elif true; then :; else :; fi & wait; echo hi > AGENTS.md$x",
    "x=foo && for i in 1; do :; done & wait; echo hi > AGENTS.md$x",
    "x=foo && for ((;;)); do break; done & wait; echo hi > AGENTS.md$x",
    "x=foo && while false; do :; done & wait; echo hi > AGENTS.md$x",
    "x=foo && until true; do :; done & wait; echo hi > AGENTS.md$x",
    "x=foo && case a in a) :;; esac & wait; echo hi > AGENTS.md$x",
    "x=foo && [[ a ]] & wait; echo hi > AGENTS.md$x",
    "x=foo && [[ a && b ]] & wait; echo hi > AGENTS.md$x",
    "x=foo && ! true & wait; echo hi > AGENTS.md$x",
    "x=foo && time true & wait; echo hi > AGENTS.md$x",
    "x=foo && ((1)) & wait; echo hi > AGENTS.md$x",
    "x=foo && < f & wait; echo hi > AGENTS.md$x",
    "x=foo && > f & wait; echo hi > AGENTS.md$x",
    // The same where the printer reads a quoted `$x` as the literal the call begins with
    // (canon.ts, constantsOf): the assignment is the job's.
    "x=foo && true & cp f \".git$x/hooks/pre-commit\"",
    "x=foo && true &&\ntrue & cp f \".git$x/hooks/pre-commit\"",
    "a=bar; x=foo && true & cp f \".git$x/hooks/pre-commit\"",
    "x=foo && y=bar && true & cp f \".git$x/hooks/pre-commit\"",
    "x=foo && true | cat & cp f \".git$x/hooks/pre-commit\"",
    "x=foo && true 2>&1 & cp f \".git$x/hooks/pre-commit\"",
    "x=foo && { true; } & cp f \".git$x/hooks/pre-commit\"",
    "x=foo && if true; then :; fi & cp f \".git$x/hooks/pre-commit\"",
    "x=foo && [[ a ]] & cp f \".git$x/hooks/pre-commit\"",
    "x=foo && < f & cp f \".git$x/hooks/pre-commit\"",
    "x=foo && ! true & cp f \".git$x/hooks/pre-commit\"",
    // Arithmetic that fails ends the line: bash skips `x=foo` and runs the next line, where
    // `$x` is empty.
    ": $((1/0)); x=foo\necho hi > AGENTS.md$x",
    ": $((1 +)); x=foo\necho hi > AGENTS.md$x",
    ": $((08)); x=foo\necho hi > AGENTS.md$x",
    ": $((2**-1)); x=foo\necho hi > AGENTS.md$x",
    ": \"$((1/0))\"; x=foo\necho hi > AGENTS.md$x",
    "echo $((1+2)); x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); x=foo #\necho hi > AGENTS.md$x",
    ": $((1/0)) || true; x=foo\necho hi > AGENTS.md$x",
    "time : $((1/0)); x=foo\necho hi > AGENTS.md$x",
    "! : $((1/0)); x=foo\necho hi > AGENTS.md$x",
    "y=$((1/0)); x=foo\necho hi > AGENTS.md$x",
    "y=$((1/0)) x=foo\necho hi > AGENTS.md$x",
    "x=foo$((1/0))\necho hi > AGENTS.md$x",
    "[[ $((1/0)) ]]; x=foo\necho hi > AGENTS.md$x",
    "for i in $((1/0)); do :; done; x=foo\necho hi > AGENTS.md$x",
    "(( $((1/0)) )); x=foo\necho hi > AGENTS.md$x",
    "for (( i=$((1/0)); i<1; i++ )); do :; done; x=foo\necho hi > AGENTS.md$x",
    "echo \"${y:-$((1/0))}\"; x=foo\necho hi > AGENTS.md$x",
    ": <<E; x=foo\n$((1/0))\nE\necho hi > AGENTS.md$x",
    ": <<< $((1/0)); x=foo\necho hi > AGENTS.md$x",
    // The line goes on past a newline inside a compound command, a quote or a pipeline.
    "if : $((1/0)); then :; fi; x=foo\necho hi > AGENTS.md$x",
    "{ : $((1/0)); }; x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); { :\n}; x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); if true\nthen :; fi; x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); for i in 1\ndo :; done; x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); while false\ndo :; done; x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); echo \"a\nb\"; x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); echo a \\\n b; x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); \\\nx=foo\necho hi > AGENTS.md$x",
    ": $((1/0)) &&\ntrue; x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); true |\ncat; x=foo\necho hi > AGENTS.md$x",
    ": $((1/0)); cat <<E; x=foo\nbody\nE\necho hi > AGENTS.md$x",
    // The other failures that end a line: a length below zero, an assignment bash refuses.
    "y=ab; : \"${y:0:-5}\"; x=foo\necho hi > AGENTS.md$x",
    ": \"${FUNCNAME:=1}\"; x=foo\necho hi > AGENTS.md$x",
    "UID=1; x=foo\necho hi > AGENTS.md$x",
    "EUID=1; x=foo\necho hi > AGENTS.md$x",
    "PPID=1; x=foo\necho hi > AGENTS.md$x",
    "UID+=1; x=foo\necho hi > AGENTS.md$x",
    "UID=1 x=foo\necho hi > AGENTS.md$x",
    "PPID=1 > /dev/null; x=foo\necho hi > AGENTS.md$x",
    "readonly y; y=1; x=foo\necho hi > AGENTS.md$x",
    "readonly y\ny=1; x=foo\necho hi > AGENTS.md$x",
    "readonly y=2; y=1; x=foo\necho hi > AGENTS.md$x",
    "readonly y; y+=1; x=foo\necho hi > AGENTS.md$x",
    "readonly y; : ${y:=1}; x=foo\necho hi > AGENTS.md$x",
    "declare -r y; y=1; x=foo\necho hi > AGENTS.md$x",
    "typeset -r y; y=1; x=foo\necho hi > AGENTS.md$x",
    "command readonly y; y=1; x=foo\necho hi > AGENTS.md$x",
    // A `cd` the line's end takes with it: the next line runs where the call started.
    ": $((1/0)); cd sub\necho hi > ../o.txt",
    ": $((1/0)); cd sub && echo hi > o.txt\necho hi > ../o2.txt",
    ": $((1/0)); { cd sub; }\necho hi > ../o.txt",
    "(( $((1/0)) )); cd sub\necho hi > ../o.txt",
    ": <<E; cd sub\n$((1/0))\nE\necho hi > ../o.txt",
    "y=ab; : \"${y:0:-5}\"; cd sub\necho hi > ../o.txt",
    "UID=1; cd sub\necho hi > ../o.txt",
    "PPID=1; cd sub\necho hi > ../o.txt",
    "readonly y; y=1; cd sub\necho hi > ../o.txt",
    "bash -c ': $((1/0)); cd sub\necho hi > ../o.txt'",
    // In a background list the `cd` moves the job alone.
    "cd sub && true & wait; echo hi > ../o.txt",
    "cd sub || true & wait; echo hi > ../o.txt",
    "cd sub && true | cat & wait; echo hi > ../o.txt",
  ]) assert.equal(await decide(command), "ask", command);
  for (const command of [
    "x=out; echo hi > $x.txt",
    "x=out && echo hi > $x.txt",
    "sleep 1 & wait; echo hi > out.txt",
    "x=out; sleep 1 & echo hi > $x.txt",
    "x=out; true && true & wait; echo hi > $x.txt",
    "x=out && { true & }; echo hi > $x.txt",
    "x=out && true; sleep 1 & echo hi > $x.txt",
    "x=foo && true | cat; echo hi > notes$x",
    "x=out; npm run dev > $x.log 2>&1 &",
    "x=foo && cp f \"notes$x\"",
    "x=foo && true; cp f \"notes$x\"",
    "x=foo && true | cat; cp f \"notes$x\"",
    "x=foo && { true; }; cp f \"notes$x\"",
    "x=foo; true & cp f \"notes$x\"",
    "x=foo && true; sleep 1 & cp f \"notes$x\"",
    "name=foo && grep -rn \"$name\" src",
    "n=$((1+2)); echo $n",
    "i=0; i=$((i+1)); echo $i",
    "x=out; echo $((1+2)) > $x.txt",
    "x=5; : $((x<=1)); echo hi > f$x.txt",
    "n=1; echo $((n*2)) > $n.txt",
    "x=out; echo hi > $x.txt\necho $((1+2))",
    // The next line is run whatever the one before did.
    "echo $((1+2))\nx=out; echo hi > $x.txt",
    "n=$((1+2))\nx=out; echo hi > $x.txt",
    "if : $((1+2)); then :; fi\nx=out\necho hi > $x.txt",
    "cat <<E\n$((1+2))\nE\nx=out; echo hi > $x.txt",
    // A call of one line has no next line: what a failure skips, nothing after it misses.
    "n=$((1+2)); cd sub && ls",
    "echo $((1+2)); x=out; echo hi > $x.txt",
    "readonly y; x=out; echo hi > $x.txt",
    // An arithmetic command's own error ends nothing.
    "((1/0)); x=out; echo hi > $x.txt",
    "sha=abcdef0; x=out\necho \"${sha:0:7}\" > $x.txt",
    "cd sub && echo hi > o.txt",
    "cd sub && echo $((1+2)) > o.txt",
    "n=$((1+2))\ncd sub && ls",
    "cat <<E\n$((1+2))\nE\ncd sub && ls",
    "cd sub && npm run dev &",
    "cd sub && ls & wait; ls",
    "readonly y; y=1",
    "declare -r y=1",
  ]) assert.equal(await decide(command), "allow", command);
});

test("closing round (Opus): a compressor's glob for a file the call itself makes is held as written", async () => {
  for (const command of [
    "gzip -c f > sub/AGENTS.md.gz; gunzip -f sub/AGENTS.md.g?",
    "gzip -c f > opencode.json.gz; gunzip opencode.json.g?",
    "gzip -c f > AGENTS.md.gz; gunzip AGENTS*",
    "gzip -c f > AGENTS.md.gz; gunzip -k AGENTS*",
    "gzip -c f > AGENTS.md.gz; gzip -d AGENTS*",
    "gzip -c f > lefthook.yml.gz; gunzip lefthook*",
    "gzip -c f > CLAUDE.md.gz; gunzip CLAUDE.md.*",
    "gzip -c f > sub/CLAUDE.md.gz; gunzip sub/CLAUD?.md.gz",
    "xz -c f > AGENTS.md.xz; unxz AGENTS*",
    "zstd -c f > opencode.json.zst; unzstd opencode*",
    "bzip2 -c f > AGENTS.md.bz2; bunzip2 AGENTS.md.b*",
  ]) assert.equal(await decide(command), "ask", command);
  // A glob that can name an ordinary file is held to the names on disk alone (z/ holds an AGENTS.md).
  for (const command of [
    "gunzip z/*.gz",
    "gunzip -k z/*.gz",
    "gzip -d z/*.gz",
    "gunzip sub/a.txt.g?",
    "gzip z/*.txt",
    "zcat z/*.gz",
  ]) assert.equal(await decide(command), "allow", command);
});

test("closing round (Opus re-check): a glob matches the files the call's earlier commands make", async () => {
  for (const command of [
    "printf '{}' | gzip > opencode.json.gz; gunzip ./*.gz",
    "gzip -c f > lefthook.yml.gz; gunzip ./*.gz",
    "gzip -c f > AGENTS.md.gz; gzip -d ./*.gz",
    "gzip -c f > AGENTS.md.gz; gunzip -f ./*",
    "gzip -c f > z/AGENTS.md.gz; gunzip -f z/*.gz",
    "gzip -c f > sub/CLAUDE.md.gz; gunzip sub/*.gz",
    "gzip -c f > .lefthook.yml.gz; gunzip .*.gz",
    "gzip -c f | tee opencode.json.gz >/dev/null; gunzip ./*.gz",
    "gzip -c f > ./opencode.json.gz && gunzip *.json.gz",
    "xz -c f > AGENTS.md.xz; unxz ./*.xz",
  ]) assert.equal(await decide(command), "ask", command);
  for (const command of [
    "echo hi > notes.txt; gzip ./*.txt",
    "gzip -c f > logs.gz; zcat ./*.gz",
  ]) assert.equal(await decide(command), "allow", command);
});

test("closing round (Opus, second re-check): a decompression's glob after the call may have made files asks", async () => {
  for (const command of [
    "gzip -c f > sub/AGENTS.md.gz; cd sub; gunzip ./*.gz",
    "cd sub; gzip -c f > ../opencode.json.gz; cd ..; gunzip ./*.gz",
    "gzip -c f > \"$PWD/opencode.json.gz\"; gunzip ./*.gz",
    "cp sub/AGENTS.md.gz .; gunzip ./*.gz",
    "cp -t . sub/AGENTS.md.gz; gunzip ./*.gz",
    "ln sub/AGENTS.md.gz .; gunzip ./*.gz",
    "tar xzf a.tgz; gunzip ./*.gz",
    // By design: any file the call makes first, whatever its name.
    "gzip -c f > out.gz; gunzip out.g?",
    "gzip -c f > out.json.gz; gunzip ./*.gz",
    "gzip -c f > n.txt.gz; gunzip -k ./*.gz",
  ]) assert.equal(await decide(command), "ask", command);
  for (const command of [
    "gunzip ./*.gz",
    "cd z && gunzip *.gz",
    "ls; gunzip ./*.gz",
    "gunzip ./*.gz 2>/dev/null; ls",
    "gzip -c f > logs.gz; zcat ./*.gz",
  ]) assert.equal(await decide(command), "allow", command);
});

test("closing round (Opus, third re-check): a file-making command anywhere in the call makes a decompression or backup glob ask", async () => {
  for (const command of [
    // Opus re-check 3: maker appears later in the text but runs beside or before the decompression.
    "(sleep 1; gunzip ./*.gz) | cp d/opencode.json.gz .",
    "(sleep 1; gunzip ./*.gz) | gzip -c f > opencode.json.gz",
    "(sleep 1; gunzip ./*.gz) & cp d/opencode.json.gz .; wait",
    "echo <(sleep 1; gunzip ./*.gz); cp d/opencode.json.gz .; sleep 2",
    "sleep 1 | gunzip ./*.gz | cp d/opencode.json.gz .",
    "cat <(sleep 1; gunzip ./*.gz) & tar xzf a.tgz; wait",
    // Nearby ordering cases: brace group, bare pipeline/background, loop, function.
    "{ gunzip ./*.gz; } | cp d/opencode.json.gz .",
    "gunzip ./*.gz | cp d/opencode.json.gz .",
    "gunzip ./*.gz & cp d/opencode.json.gz .; wait",
    "for i in 1 2; do gunzip ./*.gz; cp d/opencode.json.gz .; done",
    "ls() { gunzip ./*.gz; }; cp d/opencode.json.gz .; ls",
    // Bare ONLY_READS names and normalised device redirects only.
    "./ls; gunzip ./*.gz",
    `cat sub/AGENTS.md.gz > /dev/..${repo}/opencode.json.gz; gunzip ./*.gz`,
    "cat sub/AGENTS.md.gz > '&/opencode.json.gz'; cd '&'; gunzip ./*.gz",
    // Variable + glob in a decompression when another command makes files.
    "x=gz; cp sub/AGENTS.md.gz .; gunzip ./*.$x",
    "x=g; gzip -c f > opencode.json.gz; gunzip ./opencode.json.${x}?",
    "x=z; gzip -c f > z/opencode.json.gz; gunzip ./$x/*.gz",
    // Backup writers with a glob and a protected-ending suffix when another command makes files.
    "cp a/AGENTS .; sed -i.md p ./*",
    "echo hi > z/CLAUDE; cd z; sed -i.md p ./*",
    "tar xzf a.tgz; sed -i.md p ./*",
    "(sleep 1; sed -i.md p ./*) & echo hi > AGENTS; wait",
    "cp a/AGENTS z/; cp -b -S .md f z/*",
    "cp a/AGENTS .; mv -b -S .md f ./*",
    "echo hi > z/CLAUDE; cd z; patch -b -z .md ./* a.diff",
    // Round 16 (Neon #3): gunzip is now in READERS/KEYED (matching gzip).
    "x=z; gunzip $x/*.gz",
  ]) assert.equal(await decide(command), "ask", command);
  for (const command of [
    "gunzip *.gz",
    "gunzip ./*.gz",
    "cd z && gunzip *.gz",
    "ls; gunzip ./*.gz",
    "gunzip *.gz; ls",
    "gzip -c f > logs.gz; zcat ./*.gz",
    "gunzip ./*.gz 2>/dev/null; ls",
    "ls >/dev/null; gunzip ./*.gz",
    "echo hi > notes.txt; sed -i.bak p ./*",
  ]) assert.equal(await decide(command), "allow", command);
});

test("round 8 (Neon): readonly after keywords, invalid octal substrings, and one-glob writers ask", async () => {
  const repo8 = path.join(base, "repo8");
  for (const d of ["sub", "sub2", "sub3", "slink", "src", "dst", "a", "b"]) fs.mkdirSync(path.join(repo8, d), { recursive: true });
  fs.writeFileSync(path.join(repo8, "sub", "a"), "hello\n");
  fs.writeFileSync(path.join(repo8, "sub", "AGENTS.md"), "orig\n");
  fs.writeFileSync(path.join(repo8, "sub2", "a"), "hello\n");
  fs.writeFileSync(path.join(repo8, "sub2", "AGENTS"), "orig\n");
  fs.writeFileSync(path.join(repo8, "sub3", "a"), "hello\n");
  fs.writeFileSync(path.join(repo8, "sub3", "x.test.js"), "orig\n");
  fs.writeFileSync(path.join(repo8, "f"), "hello\n");
  fs.writeFileSync(path.join(repo8, "notes.txt"), "hello\n");
  fs.writeFileSync(path.join(repo8, "src", "a.ts"), "export {};\n");
  fs.writeFileSync(path.join(repo8, "package.json"), '{"scripts":{"test":"echo ok"}}\n');
  execFileSync("git", ["init", "-q", "-b", "main", repo8]);
  fs.writeFileSync(path.join(repo8, "slink", "a"), "hello\n");
  fs.symlinkSync(path.join(repo8, ".git", "hooks", "pre-commit"), path.join(repo8, "slink", "z"));
  const decide8 = async (command: string) => (await decideShell(guard, new SessionState(repo8), repo8, command)).effect;

  for (const command of [
    // Finding 1: readonly assignment after leading keywords aborts the line.
    "! UID=1; x=foo\nrm -rf $x/home",
    "{ UID=1; }; x=foo\nrm -rf $x/home",
    "if true; then UID=1; fi; x=foo\nrm -rf $x/home",
    "while UID=1; do :; done; x=foo\nrm -rf $x/home",
    "time UID=1; x=foo\nrm -rf $x/home",
    "time -p UID=1; x=foo\nrm -rf $x/home",
    "! UID=1; cd sub\nrm -rf x",
    // Finding 2: invalid octal literals in substring offsets/lengths.
    'y=abc; : "${y:0:08}"; x=foo\nrm -rf $x/home',
    'y=abc; : "${y:08}"; x=foo\nrm -rf $x/home',
    'y=abc; : "${y: -08}"; x=foo\nrm -rf $x/home',
    'y=abc; : "${y:0:09}"; x=foo\nrm -rf $x/home',
    // Finding 3: rsync with one expanding operand does not copy nothing.
    "rsync sub/*",
    "rsync sub3/*",
    "rsync ../*",
    // Finding 4: two-operand writers with one expanding operand, and glob targets matching symlinks.
    "cp -b -S .md sub2/*",
    "uniq sub/*",
    "uniq sub3/*",
    "xxd sub/*",
    "xxd sub3/*",
    "python3 -m json.tool sub/*",
    "python3 -m json.tool sub3/*",
    "cp sub3/*",
    "cp slink/*",
    "cp f slink/*",
    "sed -i 's/a/b/' slink/*",
    "tee slink/*",
    "mv sub3/*",
    "install sub3/*",
    "ln sub3/*",
  ]) assert.equal(await decide8(command), "ask", command);

  // Even if approved or followed in a session, `cp sub3/*` asks directly and cannot silently leave `npm test` allowed.
  const ss = new SessionState(repo8);
  const d1 = await decideShell(guard, ss, repo8, "cp sub3/*");
  assert.equal(d1.effect, "ask");
  d1.approve?.();
  assert.equal((await decideShell(guard, ss, repo8, "npm test")).effect, "ask");

  for (const command of [
    "rsync -a src/ dst/",
    "rsync -n -a src/ dst/",
    "cp -r a b",
    "cp src/*.ts dst/",
    "cp -t dst src/*",
    "cp --target-directory=dst src/*",
    "install -d dst/*",
    "uniq notes.txt",
    "uniq -f 1 notes.txt",
    "xxd f",
    "xxd -l 16 f",
    "python3 -m json.tool package.json",
    "python3 -m json.tool --indent 2 package.json",
    'y=abc; echo "${y:0:2}"',
    'y=abc; echo "${y: -1}"',
  ]) assert.equal(await decide8(command), "allow", command);
});

test("round 9 (Opus, Neon)", async () => {
  const repo9 = path.join(base, "repo9");
  const outsideFile = path.join(base, "outside9.txt");
  const outsideDir = path.join(base, "outside9-dir");
  const guardedDir = path.join(base, "guarded9");
  const configDir = path.join(os.homedir(), ".config", "opencode");
  for (const d of ["sub", "sub3", "tdir", "tdir2", "dst", "dir", "src", "outlink", "outdirlink", "grdlnk", "cfglnk"]) fs.mkdirSync(path.join(repo9, d), { recursive: true });
  for (const d of [outsideDir, guardedDir, configDir]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(outsideFile, "outside\n");
  fs.writeFileSync(path.join(guardedDir, "guard.ts"), "export {};\n");
  fs.writeFileSync(path.join(configDir, "settings.json"), "{}\n");
  for (const f of ["sub/a", "sub3/a", "sub3/b", "tdir/x", "tdir2/y", "f", "in", "a", "b", "file", "notes.txt", "src/a.ts"]) fs.writeFileSync(path.join(repo9, f), "hello\n");
  fs.writeFileSync(path.join(repo9, "package.json"), '{"name":"t"}\n');
  execFileSync("git", ["init", "-q", "-b", "main", repo9]);
  // Regular directories holding symlinks outside the project, to a guarded file, and to configDir.
  fs.symlinkSync(outsideFile, path.join(repo9, "outlink", "z"));
  fs.symlinkSync(outsideDir, path.join(repo9, "outdirlink", "z"));
  fs.symlinkSync(path.join(guardedDir, "guard.ts"), path.join(repo9, "grdlnk", "z"));
  fs.symlinkSync(path.join(configDir, "settings.json"), path.join(repo9, "cfglnk", "z"));
  const guard9: Guard = { ...guard, guarded: [...guard.guarded, guardedDir] };
  const decide9 = async (command: string) => (await decideShell(guard9, new SessionState(repo9), repo9, command)).effect;

  for (const command of [
    // Finding 1: abbreviated long options (and xxd prefix options) hide the output file.
    "python3 -m json.tool --ind 2 - .git/hooks/pre-commit",
    "uniq in AGENTS.md --skip-f 0",
    "uniq --skip-f 0 sub/*",
    "xxd -co 8 sub3/*",
    "xxd --co 8 sub3/*",
    // Finding 2: substring length/offset past 2^63-1 wraps negative and aborts the line.
    'y=abc; : "${y:0:9223372036854775808}"; x=foo\nrm -rf $x/home',
    'y=abc; : "${y:9223372036854775808}"; x=foo\nrm -rf $x/home',
    // Finding 3: -t given a glob, valued options before one glob, and unknown options on copiers.
    "cp -b -S .md -t tdir/*",
    "cp -rt tdir2/*",
    "cp -S .bak sub3/*",
    "install -m 644 sub3/*",
    "cp --sparse always sub3/*",
    "cp --bogus a b",
    "mv -t tdir/*",
    "ln -t tdir/*",
    "install -t tdir/*",
    // Finding 4: glob write target matching a symlink outside the project, to a guarded file, or to a config dir.
    "cp f outlink/*",
    "cp f outdirlink/*",
    "tee grdlnk/*",
    "tee cfglnk/*",
    "rsync f outlink/*",
    "sed -i 's/a/b/' outlink/*",
    "uniq f outlink/*",
    "sort -o outlink/* f",
    "chmod 644 outlink/*",
    // Finding 5: GNU sed permutes trailing -i / --in-place and abbreviates --in / --in-pl.
    "sed 's/a/b/' ../outside.txt -i",
    "sed 's/a/b/' ../outside.txt --in-place",
    "sed 's/a/b/' ../outside.txt -ni",
    "sed 's/a/b/' ../outside.txt -Ei",
    "sed 's/a/b/' ../outside.txt -i.bak",
    "sed 's/a/b/' ../outside.txt --in",
    "sed 's/a/b/' ../outside.txt --in-pl",
    // Same-shape: abbreviated --recursive on rm, and yq --in-place.
    "rm --rec .",
    "rm --rec *",
    "yq --in-place '.a=1' ../outside.yml",
  ]) assert.equal(await decide9(command), "ask", command);

  for (const command of [
    "cp -r a b",
    "cp src/*.ts dst/",
    "cp -t dst a b",
    "install -m 644 a b",
    "install -C -D a b",
    "mv a b",
    "uniq notes.txt",
    "uniq -c in out",
    "uniq --skip-fields 1 in",
    "python3 -m json.tool --indent 2 package.json",
    'y=abc; echo "${y:0:2}"',
    "sed -n 1p file",
    "sed -i 's/a/b/' file",
    "tee out.log",
    "cp f dir/",
  ]) assert.equal(await decide9(command), "allow", command);
});

test("round 10 (Opus, Neon)", async () => {
  const repo10 = path.join(base, "repo10");
  const outsideDir = path.join(base, "outside10-dir");
  const nodeModTarget = path.join(base, "nm10-target");
  for (const d of ["sub", "sub2", "dist", "build", "scripts", "src", "dst", "node_modules"]) fs.mkdirSync(path.join(repo10, d), { recursive: true });
  for (const d of [outsideDir, nodeModTarget]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(outsideDir, "plain.txt"), "outside\n");
  fs.writeFileSync(path.join(nodeModTarget, "index.js"), "export {};\n");
  for (const f of ["md", "f", "a", "b", "in", "AGENTS.md", "dist/app.js", "build/a.o", "scripts/run.sh", "src/a.ts", "sub2/a", "sub2/b"]) fs.writeFileSync(path.join(repo10, f), "hello\n");
  execFileSync("git", ["init", "-q", "-b", "main", repo10]);
  fs.symlinkSync("../AGENTS.md", path.join(repo10, "sub", "aglink"));
  fs.symlinkSync(outsideDir, path.join(repo10, "sub", "outdir"));
  fs.symlinkSync(os.homedir(), path.join(repo10, "sub", "homedir"));
  fs.symlinkSync(nodeModTarget, path.join(repo10, "node_modules", "extpkg"));
  const decide10 = async (command: string) => (await decideShell(guard, new SessionState(repo10), repo10, command)).effect;

  assert.equal(await decide10("chmod -R -u /"), "deny", "chmod -R -u /");

  for (const command of [
    // Finding 1 (Opus, regression): sed -bi with `*` backup suffix (leading or trailing).
    "sed -bi'AGENTS.*' s/a/b/ md",
    "sed s/a/b/ md -bi'AGENTS.*'",
    // Finding 2 (Neon): same-call symlink/hardlink creator + glob write/remove/move target.
    "ln -s AGENTS.md aglink; echo evil | tee agl*",
    "cp -s AGENTS.md aglink; echo evil | tee agl*",
    "cp -l AGENTS.md aglink; echo evil | tee agl*",
    "cp --symbolic-link AGENTS.md aglink; echo evil | tee agl*",
    "cp --link AGENTS.md aglink; echo evil | tee agl*",
    `ln -s ${outsideDir} sub/newout; rm -rf sub/newo*/*`,
    // Finding 3 (Neon): chmod modes that look like options (`-u`, `-00644`, unknown `-z`).
    "chmod -u ../outside.txt",
    "chmod -00644 ../o.txt",
    "chmod -z a",
    // Finding 4 (Neon): globs through a symlinked directory on removers and mv sources.
    "rm -f sub/outd*/*",
    "rm -rf sub/homed*/*",
    "mv sub/outd*/* dst/",
    // Finding 5 (Neon): write/remove targets combining expansion and glob characters.
    "x=sub; echo hi | tee $x/ag*",
    "x=sub; truncate -s 0 $x/ag*",
    "x=sub; shred $x/ag*",
    "x=sub; unlink $x/ag*",
    "x=sub; rm -f $x/ag*",
    "x=sub; touch $x/ag*",
    "x=sub; mkdir $x/ag*",
    "x=sub; rmdir $x/ag*",
    // Finding 6 (Neon): uniq obsolete +N and xxd trailing `-` word after first operand.
    "uniq +1 sub2/*",
    "xxd sub2/a -o",
    "xxd sub2/a -c 8",
  ]) assert.equal(await decide10(command), "ask", command);

  for (const command of [
    "rm -rf dist/*",
    "rm -rf node_modules/*",
    "rm -f build/*.o",
    "chmod +x scripts/*",
    "chmod 644 a",
    "chmod -R u+w sub",
    "chmod -v 644 a",
    "ln -s a b",
    "ln -sf a b; cat b",
    "tee out.log",
    "sed -i.bak s/a/b/ f",
    "sed -bi.bak s/a/b/ f",
    "uniq -c in out",
    "xxd f",
    "xxd -c 8 f out.hex",
    "mv a b",
    "mv src/*.ts dst/",
  ]) assert.equal(await decide10(command), "allow", command);
});

test("round 11 (Opus, Neon)", async () => {
  const repo11 = path.join(base, "repo11");
  const outsideDir = path.join(base, "outside11-dir");
  const guardedDir = path.join(base, "guarded11");
  for (const d of ["sub", "d", "dst", "src", "scripts", "dist", "logs", "node_modules/.pnpm/pkg"]) fs.mkdirSync(path.join(repo11, d), { recursive: true });
  for (const d of [outsideDir, guardedDir]) fs.mkdirSync(d, { recursive: true });
  fs.writeFileSync(path.join(outsideDir, "f.txt"), "outside\n");
  fs.writeFileSync(path.join(guardedDir, "guard.ts"), "export {};\n");
  for (const f of ["a", "b", "f", ".env", "AGENTS.md", "sub/a", "src/a.ts", "scripts/run.sh", "dist/app.js", "logs/app.log", "app.log", "node_modules/.pnpm/pkg/index.js"]) {
    fs.writeFileSync(path.join(repo11, f), "hello\n");
  }
  execFileSync("git", ["init", "-q", "-b", "main", repo11]);
  fs.symlinkSync(".", path.join(repo11, "lnk"));
  fs.symlinkSync("../AGENTS.md", path.join(repo11, "sub", "aglink"));
  fs.symlinkSync("../.git/hooks", path.join(repo11, "sub", "gitlink"));
  fs.symlinkSync(outsideDir, path.join(repo11, "sub", "outdir"));
  fs.symlinkSync(guardedDir, path.join(repo11, "sub", "grddir"));
  fs.symlinkSync(".pnpm/pkg", path.join(repo11, "node_modules", "pkg"));
  const guard11: Guard = { ...guard, guarded: [...guard.guarded, guardedDir] };
  const decide11 = async (command: string) => (await decideShell(guard11, new SessionState(repo11), repo11, command)).effect;

  for (const command of [
    // Finding A (Opus, Neon): link carried by mv, cp -P/-a/-d/-r/--preserve=links, link, or rsync.
    "mv lnk d; echo x | tee d/*.md",
    "mv sub sub2; echo hi | tee sub2/ag*",
    "cp -P sub/aglink sub/newlink; echo hi | tee sub/newl*",
    "cp -a sub/aglink sub/newlink; echo hi | tee sub/newl*",
    "cp -d sub/aglink sub/newlink; echo hi | tee sub/newl*",
    "cp -r sub sub2; echo hi | tee sub2/ag*",
    "cp --no-dereference sub/aglink sub/newlink; echo hi | tee sub/newl*",
    "cp --preserve=links sub/aglink sub/newlink; echo hi | tee sub/newl*",
    "link AGENTS.md sub/hlink; echo hi | tee sub/hl*",
    "rsync -a sub/ sub2/; echo hi | tee sub2/ag*",
    "mv lnk d; gzip d/*.md",
    // Finding B (Neon): glob arguments through symlinked dirs or to protected targets on non-readers.
    "curl -s https://example.com/x -o sub/outd*/y",
    "curl -s https://example.com/x -osub/outd*/y",
    "curl -sLosub/outd*/y https://example.com/x",
    "wget -q https://example.com/x -P sub/outd*",
    "wget -qPsub/outd* https://example.com/x",
    "gzip sub/outd*/*",
    "xz -k sub/outd*/*",
    "zstd sub/outd*/*",
    "python3 -m compileall sub/outd*",
    "python3 -m venv --clear sub/outd*",
    "uv venv sub/outd*",
    "pytest --basetemp=sub/outd*",
    "journalctl --cursor-file sub/ag*",
    "journalctl --cursor-file=sub/gitl*",
    "gzip sub/grdd*/*",
    "x=sub; pytest --basetemp=$x/outd*",
    "x=sub; gzip $x/outd*/*",
    // Finding C (Neon): install -d / --directory creates every operand.
    "install -d .git/hooks/x local",
    "install -d ../outside/x local",
    "install --directory .git/hooks/x local",
    "install --directory ../outside/x local",
    "install -d ../outside/x",
    // Finding D (Neon): sed -i --debug prints every input line.
    "sed -i --debug s/a/b/ .env",
    "sed -i --debug -e s/a/b/ .env",
    "sed --debug -i s/a/b/ .env",
  ]) assert.equal(await decide11(command), "ask", command);

  for (const command of [
    "rm -rf dist/*",
    "rm -rf node_modules/*",
    "rm -f *.log",
    "chmod +x scripts/*",
    "mv src/*.ts dst/",
    "gzip -k logs/*.log",
    "python3 -m compileall src",
    "cp -r src dst",
    "cp -a src dst",
    "mv a b",
    "mv a b; rm -f dist/*",
    "curl -s https://example.com/x -o out.json",
    "git add src/*",
    "cat sub/outd*/f.txt",
    "ls sub/*",
    "install -d local1 local2",
    "install --directory local1 local2",
    "sed -i --debug s/a/b/ f",
    "find . -name '*.ts'",
    "pytest -k 'test_*'",
  ]) assert.equal(await decide11(command), "allow", command);
});

test("round 12 (Opus, Neon)", async () => {
  const repo12 = path.join(base, "repo12");
  const outsideDir = path.join(base, "outside12-dir");
  for (const d of ["sub", "src", "dst"]) fs.mkdirSync(path.join(repo12, d), { recursive: true });
  fs.mkdirSync(outsideDir, { recursive: true });
  fs.writeFileSync(path.join(outsideDir, "f.txt"), "outside\n");
  fs.writeFileSync(path.join(outsideDir, "a.yaml"), "a: 1\n");
  for (const f of ["a", "b", "f", "s.yq", "a.yaml", "a.json", "a=b.log", "AGENTS.md", "src/a.ts"]) {
    fs.writeFileSync(path.join(repo12, f), "hello\n");
  }
  execFileSync("git", ["init", "-q", "-b", "main", repo12]);
  fs.symlinkSync(".", path.join(repo12, "lnk"));
  fs.symlinkSync(outsideDir, path.join(repo12, "sub", "outdir"));
  fs.symlinkSync(outsideDir, path.join(repo12, "a=outdir"));
  fs.symlinkSync(path.join(outsideDir, "f.txt"), path.join(repo12, "src", "extlink"));
  fs.symlinkSync("../AGENTS.md", path.join(repo12, "sub", "aglink"));
  const decide12 = async (command: string) => (await decideShell(guard, new SessionState(repo12), repo12, command)).effect;

  for (const command of [
    // Finding 1 (Neon): ~+/ and other ~word forms in glob checks.
    "echo hi | tee ~+/sub/outd*/f.txt",
    "echo hi | tee ~-/sub/outd*/f.txt",
    "rm -f ~+/sub/outd*/*",
    "gzip ~+/sub/outd*/*",
    // Finding 2 (Neon): globCandidates keeps raw word when first path segment has `=`.
    "gzip a=out*/*",
    // Finding 3 (Neon): mv --exchange (any prefix) swaps both operands and carries links.
    "mv --exchange a lnk; echo x | tee a/*.md",
    "mv --exc a lnk; echo x | tee a/*.md",
    "mv --exchange a lnk; chmod 644 a/*.md",
    "mv --exchange a sub; chmod 644 a/ag*",
    // Finding 4 (Neon): yq/jq in place with -f/--from-file or a single operand.
    "yq -i --from-file=s.yq ../outside/a.yaml",
    "yq -i -fs.yq AGENTS.md",
    "yq -i -o=json ../outside/a.yaml",
    "yq -if s.yq AGENTS.md",
    // Finding 5 (Opus): call-level link rule and archive output still ask for git add / tar / zip.
    "tar czf sub/outd*/a.tgz src/*",
    "zip -r sub/outd*/a.zip src/*",
    "zip -rm a.zip src/*",
    "ln -s /tmp/x src/l; git add src/*",
    "ln -s /tmp/x src/l; tar czf a.tgz src/*",
    "ln -s /tmp/x src/l; zip -r a.zip src/*",
  ]) assert.equal(await decide12(command), "ask", command);

  // Finding 6 (Opus): sed -f/--file credential script asks via rules, not model fallback.
  for (const command of [
    "sed -e p -f .env f",
    "sed -f .env f",
    "sed --file=.env f",
    "sed -i -f .env f",
  ]) {
    const d = await decideShell(guard, new SessionState(repo12), repo12, command);
    assert.equal(d.effect, "ask", command);
    assert.equal(d.by, "rules", `${command}: got ${d.by} (${d.reason})`);
  }

  for (const command of [
    "git add src/*",
    "git add *",
    "tar czf a.tgz src/*",
    "zip -r a.zip src/*",
    "yq -i '.a=1' a.yaml",
    "jq . a.json",
    "mv a b",
    "echo hi | tee ~+/out.log",
    "gzip a=b.log",
  ]) assert.equal(await decide12(command), "allow", command);
});

test("round 13 (Opus, Neon)", async () => {
  const repo13 = path.join(base, "repo13");
  const outsideDir = path.join(base, "outside13-dir");
  for (const d of ["d", "src", "dist", "docs", "sub"]) fs.mkdirSync(path.join(repo13, d), { recursive: true });
  fs.mkdirSync(outsideDir, { recursive: true });
  fs.writeFileSync(path.join(outsideDir, "f.txt"), "outside\n");
  for (const f of ["a", "b", "f", "d/a", "src/a.ts", "dist/app.js", "docs/readme.md", "a.yaml", "b.yaml", "s.yq", "AGENTS.md", ".env", "package.json"]) {
    fs.writeFileSync(path.join(repo13, f), "hello\n");
  }
  execFileSync("git", ["init", "-q", "-b", "main", repo13]);
  fs.symlinkSync(outsideDir, path.join(repo13, "sub", "outdir"));
  const decide13 = async (command: string) => (await decideShell(guard, new SessionState(repo13), repo13, command)).effect;

  for (const command of [
    // Opus: zip -lf / --logfile-path takes a value and shifts the archive operand.
    "zip -lf z.log AGENTS.md d/a",
    "zip -lf z.log .git/hooks/pre-commit d/a",
    "zip --logfile-path z.log AGENTS.md d/a",
    // Neon 1: zip --out / -O after archive or --out= and glob in --out.
    "zip -r a.zip --out sub/outd*/f.txt src/a.ts",
    "zip -r /tmp/a.zip --out package.json src/a.ts && npm test",
    "zip -r a.zip --out=AGENTS.md src/a.ts",
    "zip -r a.zip -O AGENTS.md src/a.ts",
    // Neon 3: zip -m / --move deletes sources, and -lf after archive.
    "zip -r a.zip -m AGENTS.md",
    "zip -r a.zip --move AGENTS.md",
    "zip -r a.zip -lf AGENTS.md src/a.ts",
    "zip -r - a.zip src/a.ts",
    "zip -r -y a.zip src/a.ts",
    // Neon 2: yq -i with a trailing valued plain option after a single file operand.
    "yq -i AGENTS.md --indent 2",
    "yq -i AGENTS.md -o json",
    "yq -i AGENTS.md -I 2",
    "yq -i eval AGENTS.md --indent 2",
    "yq -i ../outside13.yaml -o json",
    // Neon 4: yq -s / --split-exp / --split-exp-file writes files named by the expression.
    'yq -s \'"AGENTS.md"\' a.yaml',
    'yq --split-exp \'"AGENTS.md"\' a.yaml',
    "yq --split-exp-file s.yq a.yaml",
    // Neon 5: yq -f / --from-file reads a script file.
    "yq -f .env a.yaml",
    "yq --from-file=.env a.yaml",
    "yq --from-file .env a.yaml",
  ]) assert.equal(await decide13(command), "ask", command);

  for (const command of [
    "zip -r a.zip src",
    "zip -rq build.zip dist",
    "zip -9 a.zip f",
    "zip a.zip a b",
    "zip -r archive.zip docs/",
    "yq '.a' a.yaml",
    "yq -i '.a=1' a.yaml",
    "yq -o json '.' a.yaml",
    "yq -P '.' a.yaml",
    "yq e '.a' a.yaml",
    "cat a.yaml | yq '.a'",
    "yq -i '.a=1' a.yaml --indent 2",
    "yq -i a.yaml -o json",
    "yq eval-all '.a' a.yaml b.yaml",
  ]) assert.equal(await decide13(command), "allow", command);
});

test("round 14 (Opus, Neon)", async () => {
  const repo14 = path.join(base, "repo14");
  const outside14 = path.join(base, "outside14.yaml");
  fs.mkdirSync(path.join(repo14, "src"), { recursive: true });
  fs.writeFileSync(outside14, "a: 1\n");
  for (const f of ["a.txt", "f", "a.yaml", "x.yaml", "a.json", "secrets.json", ".env", ".env.example", "pat.txt", "f.jq", "AGENTS.md", "src/a.ts"]) {
    fs.writeFileSync(path.join(repo14, f), "hello\n");
  }
  execFileSync("git", ["init", "-q", "-b", "main", repo14]);
  const decide14 = async (command: string) => (await decideShell(guard, new SessionState(repo14), repo14, command)).effect;

  for (const command of [
    // A (Neon 1): GNU sed treats the delimiter literally inside a bracket expression.
    "sed 's/[/]/p;s#$(echo X > rce.txt)#x#p;s/ew /tmp/p' a.txt",
    "sed 's/[/]/p;s/w ../outside/p' a.txt",
    "sed '/[/,/s/p;s/]/w out/p' a.txt",
    "sed '\\#[#],\\#s#p;s/]/w out/p' a.txt",
    "sed 's/[^/]*$//' f",
    // B (Neon 2, Opus 1): mikefarah yq v4 treats an existing first operand as an input file.
    "yq -o json secrets.json",
    "yq e .env",
    "yq -I 2 .env",
    "yq .env",
    "yq ~/.kube/config",
    "yq -P ~/.ssh/id_rsa",
    "yq -i AGENTS.md x.yaml",
    `yq -i ${outside14} x.yaml`,
    'yq -i "$f" x.yaml',
    "yq -i AGENT* x.yaml",
    // C (Neon 3): PATTERN_FIRST credentialRead checks every operand when pattern/program comes from an option.
    "grep --regexp=SECRET .env",
    "grep -efoo .env",
    "grep -iefoo .env",
    "grep -fpat.txt .env",
    "grep -f.env src/a.ts",
    "rg -efoo .env",
    "rg --file=pat.txt .env",
    "awk -e'1' .env",
    "awk --source='1' .env",
    "jq -ff.jq .env",
    "jq --from-file=f.jq .env",
    "jq --args .env",
    // D (Opus 2, Neon 4): yq load/load_* functions read files from the expression.
    'yq -n \'load_str(".env")\'',
    'yq \'.a = load_str(".env")\' x.yaml',
    'yq \'.a = load(".env")\' x.yaml',
    'yq \'.a = load_props(".env")\' x.yaml',
    'yq \'.a = load_base64(".env")\' x.yaml',
    'yq \'.a = load_xml(".env")\' x.yaml',
  ]) assert.equal(await decide14(command), "ask", command);

  for (const command of [
    "sed -i 's/[0-9]\\+/N/g' f",
    "sed 's/[[:space:]]*$//' f",
    "sed -n '/^[a-z]/p' f",
    "sed 's/[]a]/x/' f",
    "yq -i '.a=1' a.yaml",
    "yq -i '.' a.yaml",
    "yq '.a' a.yaml",
    "grep -e foo src/a.ts",
    "grep -r foo src",
    "grep foo .env.example",
    "awk '{print $1}' f",
    "jq . a.json",
  ]) assert.equal(await decide14(command), "allow", command);
});

test("round 15 (Neon)", async () => {
  const repo15 = path.join(base, "repo15");
  fs.mkdirSync(repo15, { recursive: true });
  for (const f of ["a.yaml", "b.yaml", ".env", "build.ninja", "justfile", "pytest.ini"]) {
    fs.writeFileSync(path.join(repo15, f), "hello\n");
  }
  fs.symlinkSync("/dev/stdin", path.join(repo15, "stdin-link"));
  execFileSync("git", ["init", "-q", "-b", "main", repo15]);
  const decide15 = async (command: string) => (await decideShell(guard, new SessionState(repo15), repo15, command)).effect;

  for (const command of [
    // #3: yq eval(...) bypasses the load/load_*() expression check.
    'yq -n \'eval("lo" + "ad_str(\\.env)")\'',
    'yq -n \'eval("lo" + "ad_str(\\\".env\\\")")\'',
    "yq 'eval(.e)' a.yaml",
    "yq e 'eval(.e)' a.yaml",
    "yq 'eval ( .e )' a.yaml",
    // Neon's pushback: every `-v` of a test expression is checked, not only the first.
    'a=1; test -v a -a -v "$x"',
    '[ -v a -a -v "$x" ]',
    "test -v a -o -v 'b[1]'",
    // #4: ninja -f, just -f/--justfile, pytest -c/--config-file (and python3 -m pytest) reading from a device.
    'printf "rule r\\n  command = id\\nbuild a: r\\n" | ninja -f /dev/stdin',
    "ninja -f -",
    "ninja -f/dev/stdin",
    "ninja -vf /dev/stdin",
    "ninja -C /dev -f stdin",
    "ninja -f /proc/self/fd/0",
    'ninja -f <(printf "x")',
    'ninja -f "$f"',
    "ninja -f stdin-link",
    'printf "default:\\n\\tid\\n" | just -f /dev/stdin',
    "just -f -",
    "just -f/dev/stdin",
    "just -f=/dev/stdin",
    "just -qf /dev/stdin",
    "just --justfile /dev/stdin",
    "just --justfile=/dev/stdin",
    'just -f <(printf "x")',
    'just -f "$f"',
    "just -f stdin-link",
    "cd /dev && just -f stdin",
    'printf "[pytest]\\n" | pytest -c /dev/stdin',
    "pytest -c -",
    "pytest -c/dev/stdin",
    "pytest -c=/dev/stdin",
    "pytest -vc /dev/stdin",
    "pytest --config-file /dev/stdin",
    "pytest --config-file=/dev/stdin",
    "pytest --config=/dev/stdin",
    'pytest -c <(printf "x")',
    'pytest -c "$f"',
    "pytest -c stdin-link",
    'printf "[pytest]\\n" | python3 -m pytest -c /dev/stdin',
    "python3 -m pytest --config-file=/dev/stdin",
    "python -m pytest -c /dev/stdin",
    'python3 -m pytest -c "$f"',
  ]) assert.equal(await decide15(command), "ask", command);

  for (const command of [
    "yq eval '.a' a.yaml",
    "yq eval-all '.a' a.yaml b.yaml",
    "yq '.eval' a.yaml",
    "test -v a -a -v b",
    "ninja",
    "ninja -f build.ninja",
    "ninja -f /dev/null",
    "just",
    "just -f justfile test",
    "just --justfile=justfile test",
    "pytest",
    "pytest -c pytest.ini",
    "pytest -c /dev/null",
    "pytest -kcheck",
    "pytest -rc",
    "python3 -m pytest",
    "python3 -m pytest -c pytest.ini",
  ]) assert.equal(await decide15(command), "allow", command);
});

test("round 16 (Opus, Neon)", async () => {
  const repo16 = path.join(base, "repo16");
  fs.mkdirSync(path.join(repo16, "src"), { recursive: true });
  fs.mkdirSync(path.join(repo16, "tests"), { recursive: true });
  fs.mkdirSync(path.join(repo16, "build"), { recursive: true });
  fs.writeFileSync(path.join(repo16, "package.json"), JSON.stringify({ scripts: { build: "echo ok" } }) + "\n");
  for (const f of ["src/main.rs", "a.gz", "pytest.ini", "tox.ini", "build.ninja", "justfile"]) {
    fs.writeFileSync(path.join(repo16, f), "hello\n");
  }
  fs.symlinkSync("/dev/stdin", path.join(repo16, "stdin-link"));
  execFileSync("git", ["init", "-q", "-b", "main", repo16]);
  const decide16 = async (command: string) => (await decideShell(guard, new SessionState(repo16), repo16, command)).effect;

  for (const command of [
    // #1 (Neon): option hidden in a variable for test/[, printf, wait.
    'op=-v; test "$op" \'a[$(id)]\'',
    'op=-v; [ "$op" \'a[$(id)]\' ]',
    'op=-R; test "$op" \'a[$(id)]\'',
    'op=-v; printf "$op" \'a[$(id)]\' 1',
    'op=-v; printf "$op" PATH /tmp',
    'op=-vPATH; printf "$op" /tmp',
    'op=-v; v=GIT_SSH_COMMAND; printf "$op" "$v" "sh -c id"',
    'op=-p; wait "$op" PATH',
    'op=-pPATH; wait "$op"',
    // #2 (Neon): python -m MOD expansionProblem lookup + venv KEYED entry.
    'python3 -m pytest "$opt"',
    'python -m pytest "$opt"',
    'python3 -m mypy "$opt" .',
    'python3 -m venv "$opt" venv',
    'opt=--upgrade-deps; python3 -m venv "$opt" venv',
    // #3 (Neon): KEYED entries for cloc, tree, rustfmt, gunzip/compressor siblings.
    'opt=--out=AGENTS.md; cloc "$opt" src',
    'opt=-oAGENTS.md; tree "$opt" src',
    'opt=+/tmp/x; rustfmt "$opt" src/main.rs',
    'tc=/tmp/x; rustfmt "+$tc" src/main.rs',
    'opt=-S; gunzip "$opt" a.gz',
    // #4 (Neon, Opus): pytest abbreviated checked long opts, -o addopts/python_*, unknown flags, @FILE.
    "pytest --basetem=/outside",
    "python3 -m pytest --basetem=/outside",
    "pytest --trac",
    "pytest -o 'addopts=--basetemp=\"/outside\"'",
    'pytest -o "python_functions = interact"',
    'pytest --override-ini "addopts = --pdb"',
    "pytest -o python_files=test_*.py",
    "pytest -dc /dev/stdin",
    "ninja -z -f /dev/stdin",
    "just -z -f /dev/stdin",
    "pytest @<(echo --trace) <<'EOF'\nimport os\nEOF",
    "echo --basetemp=.claude | pytest @/dev/stdin",
    "python3 -m pytest @/dev/stdin",
    // #5 (Neon): bun run codeFromDevice + tox -c/--conf device check.
    "bun run /dev/fd/0",
    "bun run //dev/stdin",
    "bun run /dev/./stdin",
    "bun run stdin-link",
    "tox -c /dev/stdin",
    "tox --conf=/dev/stdin",
    "tox --conf /dev/stdin",
    "tox -c -",
    "tox -c stdin-link",
    'tox -c "$f"',
    // #6 (Neon): compileall stops filtering option values after `--`.
    "python3 -m compileall -- -d /outside",
    "python3 -m compileall -d -d /outside",
    "python3 -m compileall -- .git",
  ]) assert.equal(await decide16(command), "ask", command);

  for (const command of [
    '[ "$x" = y ]',
    '[ "$x" = "$y" ]',
    '[ -n "$x" ]',
    'test -f "$f"',
    "printf '%s\\n' \"$x\"",
    'printf "$fmt" a b',
    'wait "$pid"',
    "tree",
    "tree src",
    "cloc src",
    "gunzip a.gz",
    "rustfmt src/main.rs",
    "pytest",
    "pytest -x",
    "pytest -k foo tests/",
    "pytest --cov=src",
    "pytest --maxfail=1",
    "pytest --no-header -v tests/",
    "python3 -m pytest",
    "python3 -m pytest -k foo",
    "python3 -m mypy .",
    "python3 -m venv venv",
    "python3 -m compileall src",
    "python3 -m compileall -d /outside src",
    "bun run build",
    "tox",
    "tox -c tox.ini",
  ]) assert.equal(await decide16(command), "allow", command);
});

test("round 17 (Opus, Sol): an unquoted expansion that splits into an option and its operand", async () => {
  const repo17 = path.join(base, "repo17");
  fs.mkdirSync(repo17, { recursive: true });
  for (const f of ["f", "a.ts"]) fs.writeFileSync(path.join(repo17, f), "hello\n");
  execFileSync("git", ["init", "-q", "-b", "main", repo17]);
  const decide17 = async (command: string) => (await decideShell(guard, new SessionState(repo17), repo17, command)).effect;

  for (const command of [
    // A known value that splits (Opus 1, Sol 1 and 2).
    "v='-v a[$(id)]'; test $v",
    "v='-R a[$(id)]'; test $v",
    "v='-v a[$(id)]'; [ $v ]",
    "a=foo; op='-v a[$(touch${IFS}marker)]'; test $op",
    "opts='-v PATH'; printf $opts /tmp; ls",
    'op=" -o -v"; test x$op \'a[$(id)]\'',
    // A value the check cannot know: a command substitution, or an expansion beside a subscript (Opus 1, 2).
    "test $(echo '-v a[$(id)]')",
    "printf $(echo '-v a[$(id)] x')",
    "test x$(echo \" -o -v\") 'a[$(id)]'",
    "[ x$(printf \" -o -v\") \"a[\\$(id)]\" ]",
    "test \"$a\" = b$op 'a[$(id)]'",
  ]) assert.notEqual(await decide17(command), "allow", command);

  for (const command of [
    '[ "$x" = y ]',
    "[ -z $x ] && echo empty",
    "x=foo; [ $x = foo ] && echo same",
    '[ -n "$(git status --porcelain)" ] && echo dirty',
    "printf '%s\\n' $x",
    'printf "$fmt" a b',
    "for f in *.ts; do [ -f $f ] && echo $f; done",
    'if [ "$(uname)" = Linux ]; then echo l; fi',
    'msg="hello world"; printf "%s\\n" "$msg"',
    'x="a b"; [ "$x" = "a b" ]',
  ]) assert.equal(await decide17(command), "allow", command);
});

test("round 18 (Opus, Sol): positional parameters, for lists and unread values that split into an option", async () => {
  const repo18 = path.join(base, "repo18");
  fs.mkdirSync(repo18, { recursive: true });
  fs.writeFileSync(path.join(repo18, "f"), "-v a[$(date)]");
  fs.writeFileSync(path.join(repo18, "a.ts"), "hello\n");
  execFileSync("git", ["init", "-q", "-b", "main", repo18]);
  const decide18 = async (command: string) => (await decideShell(guard, new SessionState(repo18), repo18, command)).effect;

  for (const command of [
    // Opus: the positional parameters and a for list.
    "set -- -v 'a[$(date>P)]'; test \"$@\"",
    "set -- -v 'a[$(date>P)]'; test $@",
    "set -- -v 'a[$(date>P)]'; [ \"$@\" ]",
    "set -- -v 'a[$(date>P)]'; test $*",
    "set -- -v 'a[$(date>P)]'; test \"${@:1}\"",
    "for v in '-v a[$(date>P)]'; do test $v; done",
    "set -- -v 'a[$(date>P)]' x; printf \"$@\"",
    "set -- -p 'a[$(date>P)]'; wait \"$@\"",
    "set -- -v PATH .; printf \"$@\"; git status",
    // Sol: a value no check reads, wait's -p from a substitution, and a known split value.
    "v=$(echo '-v a[$(touch marker)]'); test $v",
    "v=$(cat f); test $v",
    "read v < f; test $v",
    "wait $(echo '-p a[$(touch marker)]')",
    "opts='-p PATH'; wait $opts",
  ]) assert.notEqual(await decide18(command), "allow", command);

  for (const command of [
    '[ "$x" = y ]',
    "x=foo; [ $x = foo ] && echo same",
    "for f in *.ts; do [ -f $f ] && echo $f; done",
    "for f in a b c; do test -n $f; done",
    "sleep 1 & wait $!",
    'x=$(git rev-parse HEAD); [ -n "$x" ]',
    'read -r line < f; [ "$line" = x ]',
    "printf '%s\\n' \"$@\"",
    'for f in "$@"; do echo "$f"; done',
    "[ -z $x ] && echo empty",
  ]) assert.equal(await decide18(command), "allow", command);
});

test("round 19 (Opus, Sol): printf -v names, numbered parameters and computed expansions that split", async () => {
  const repo19 = path.join(base, "repo19");
  fs.mkdirSync(repo19, { recursive: true });
  fs.writeFileSync(path.join(repo19, "a.ts"), "hello\n");
  execFileSync("git", ["init", "-q", "-b", "main", repo19]);
  const decide19 = async (command: string) => (await decideShell(guard, new SessionState(repo19), repo19, command)).effect;

  for (const command of [
    "printf -v v '%s %s%s' -v x '[a]'; printf -v a '%s%s%s' y '[$(date)' ']'; test $v",
    "a='y[$(date)]'; printf -v v '%s %s%s' -v x '[a]'; test $v",
    "printf -v v '%s %s%s' -v x '[a]'; [ $v ]",
    "printf -v v '-%s %s' v 'a[$(date)]'; test $v",
    "set -- '-v a[$(date)]'; test $1",
    "set -- '-v a[$(date)]'; test ${1}",
    "v='x-p PATH'; wait ${v#x}",
    "v='x-p PATH'; wait ${v:1}",
  ]) assert.notEqual(await decide19(command), "allow", command);

  for (const command of [
    '[ "$1" = x ] && echo one',
    '[ -n "$1" ]',
    "x=abc; [ ${#x} -gt 2 ] && echo long",
    'v=3; printf -v out "%03d" "$v"; [ "$out" = 003 ]',
    '[ -z "${x:-}" ] && echo unset',
    '[ "${v#x}" = y ]',
  ]) assert.equal(await decide19(command), "allow", command);
});

test("round 20 (Opus, Sol): only names known to be safe pass unquoted into test, printf's first word and wait", async () => {
  const repo20 = path.join(base, "repo20");
  fs.mkdirSync(repo20, { recursive: true });
  fs.writeFileSync(path.join(repo20, "f"), "-v a[$(date)]");
  fs.writeFileSync(path.join(repo20, "a.ts"), "hello\n");
  execFileSync("git", ["init", "-q", "-b", "main", repo20]);
  const decide20 = async (command: string) => (await decideShell(guard, new SessionState(repo20), repo20, command)).effect;

  for (const command of [
    // Sol: concatenated values with blanks.
    "true && op=-v; arg=' a[foo]'; test $op$arg",
    "true && op=-v; arg=' a[foo]'; [ $op$arg ]",
    "v='-v a[foo]'; empty=; test ${v}${empty}",
    "true && op=-p; arg=' PATH'; wait $op$arg",
    // Opus: a name bash sets by itself.
    "read < f; test $REPLY",
    "while read; do test $REPLY; done < f",
    "select x in a b; do test $REPLY; done < f",
    "read < f; test x -a $REPLY",
    "read -r < f; wait $REPLY",
  ]) assert.notEqual(await decide20(command), "allow", command);

  for (const command of [
    "x=foo; [ $x = foo ] && echo same",
    "[ -z $x ] && echo empty",
    "for f in *.ts; do [ -f $f ] && echo $f; done",
    "for f in a b c; do test -n $f; done",
    "sleep 1 & wait $!",
    "[ $? -eq 0 ] && echo ok",
    '[ "$REPLY" = y ]',
    'read -r ans < f; [ "$ans" = y ]',
    "n=3; [ $n -gt 2 ] && echo big",
    "printf '%s\\n' $x",
  ]) assert.equal(await decide20(command), "allow", command);
});

test("round 21 (Opus, Sol): glob-fed loop names whose files hold blanks, and names bash sets by itself", async () => {
  const hostile = path.join(base, "repo21h");
  fs.mkdirSync(hostile, { recursive: true });
  fs.writeFileSync(path.join(hostile, "f"), "-v a[$(date)]\n");
  for (const f of ["x -o -v a[$(date)] -o y.ts", " a[$(date)]", "b.ts"]) fs.writeFileSync(path.join(hostile, f), "");
  execFileSync("git", ["init", "-q", "-b", "main", hostile]);
  const clean = path.join(base, "repo21c");
  fs.mkdirSync(path.join(clean, "d"), { recursive: true });
  for (const f of ["a.ts", "b.ts"]) fs.writeFileSync(path.join(clean, f), "");
  execFileSync("git", ["init", "-q", "-b", "main", clean]);
  const decideIn = async (repo: string, command: string) => (await decideShell(guard, new SessionState(repo), repo, command)).effect;

  for (const command of [
    "for f in *.ts; do [ -f $f ] && echo $f; done",
    "for f in *; do [ -e $f ]; done",
    "for f in */; do [ -d $f ] && ls $f; done",
    "for f in *; do wait $f; done",
    "for arg in *; do test -v$arg; done",
    "REPLY=x; read -r < f; test $REPLY",
    "REPLY=x; read -r < f; [ $REPLY ]",
  ]) assert.notEqual(await decideIn(hostile, command), "allow", command);

  for (const command of [
    "for f in *.ts; do [ -f $f ] && echo $f; done",
    "for f in */; do [ -d $f ] && ls $f; done",
    "REPLY=x; [ $REPLY = x ]",
    "for f in a b; do test -n $f; done",
  ]) assert.equal(await decideIn(clean, command), "allow", command);
});

test("round 22 (Opus, Sol): read behind a keyword, and a glob match's directories holding blanks", async () => {
  const hostile = path.join(base, "repo22h");
  const n = "x -o -v a[$(date)] -o y";
  fs.mkdirSync(path.join(hostile, n), { recursive: true });
  fs.mkdirSync(path.join(hostile, "src a"), { recursive: true });
  fs.writeFileSync(path.join(hostile, n, "z.ts"), "");
  fs.writeFileSync(path.join(hostile, "src a", "b.ts"), "");
  fs.writeFileSync(path.join(hostile, "f"), `${n}\n`);
  execFileSync("git", ["init", "-q", "-b", "main", hostile]);
  const clean = path.join(base, "repo22c");
  fs.mkdirSync(path.join(clean, "src", "a"), { recursive: true });
  fs.writeFileSync(path.join(clean, "src", "a", "b.ts"), "");
  fs.writeFileSync(path.join(clean, "a.ts"), "");
  fs.writeFileSync(path.join(clean, "f"), "x\n");
  execFileSync("git", ["init", "-q", "-b", "main", clean]);
  const decideIn = async (repo: string, command: string) => (await decideShell(guard, new SessionState(repo), repo, command)).effect;

  for (const command of [
    "while read -r line; do [ -n $line ]; done < f",
    "while read v; do test -n $v; done < f",
    "if read v < f; then [ -n $v ]; fi",
    "REPLY=x; if read -r < f; then :; fi; test -n $REPLY",
    "REPLY=x; ! read -r < f; test -n $REPLY",
    "REPLY=x; while read; do :; done < f; test -n $REPLY",
    "for f in */*.ts; do [ -f $f ]; done",
    "for f in src*/*.ts; do [ -f $f ]; done",
  ]) assert.notEqual(await decideIn(hostile, command), "allow", command);

  for (const command of [
    "for f in */*/*.ts; do [ -f $f ] && echo $f; done",
    "for f in *.ts; do [ -f $f ]; done",
    'while read -r line; do echo "$line"; done < f',
    'while read -r line; do [ -n "$line" ] && echo "$line"; done < f',
  ]) assert.equal(await decideIn(clean, command), "allow", command);
});
