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
  for (const f of ["f", "AGENTS", ".gi", "sub/AGENTS.md.gz", "sub/a.txt.gz"]) fs.writeFileSync(path.join(repo, f), "x\n");
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
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
