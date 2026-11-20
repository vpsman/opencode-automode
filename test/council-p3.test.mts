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
