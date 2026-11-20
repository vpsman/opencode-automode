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
  ]) assert.equal(await decide(command), "ask", command);
  for (const command of [
    "x=out; echo hi > $x.txt",
    "x=build; mkdir -p $x/a",
    "x=f.gz; gunzip $x",
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
    "x=z; gunzip $x/*.gz",
    "x=sub; gunzip $x/a*.gz",
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
