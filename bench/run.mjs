// Runs command suites through decideShell() — the same code path as the plugin — against a live
// Kev server, and records every row. The model never decides during a run (askAbove is forced
// above 1), so each classified row keeps its raw score and bench/score.mjs can sweep thresholds.
//
// Rows: {id, command, label: 1 risky | 0 safe | null unlabelled, cwd?}. In command and cwd,
// {home} is $HOME and {project} a scratch git repository.
// Each row is decided as the plugin would: one fixed session project (the scratch repository),
// the row's directory as the command's working directory, and the production reply timeout.
// Usage: node bench/run.mjs --tag kev-0.8b --suites-dir <dir> [--suites a,b] [--endpoint url] [--timeout ms]
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { parseArgs } from "node:util";

const here = import.meta.dirname;
const root = path.dirname(here);
const { values: args } = parseArgs({
  options: {
    tag: { type: "string" },
    "suites-dir": { type: "string", multiple: true },
    suites: { type: "string" },
    endpoint: { type: "string" },
    timeout: { type: "string" },
    limit: { type: "string" },
  },
});
if (!args.tag || !args["suites-dir"]) throw new Error("--tag and --suites-dir are required");

const { decideShell, SessionState, DEFAULT_ASK } = await import(path.join(root, "decide.ts"));
const { compileRules } = await import(path.join(root, "rules.ts"));
const { DEFAULT_CLASSIFIER } = await import(path.join(root, "kev.ts"));

const project = path.join(os.tmpdir(), `automode-bench-project-${process.getuid?.() ?? 0}`);
if (!fs.existsSync(path.join(project, ".git"))) {
  fs.mkdirSync(path.join(project, "src"), { recursive: true });
  fs.writeFileSync(path.join(project, "src", "main.py"), "print('hi')\n");
  execFileSync("git", ["init", "-q", project]);
}
const fill = (s) => s.replaceAll("{home}", os.homedir()).replaceAll("{project}", project).replaceAll("{guard}", root);

const guard = {
  rules: compileRules({ ask: DEFAULT_ASK }),
  guarded: [root],
  configDirs: [path.join(os.homedir(), ".config", "opencode")],
  allowedPaths: [],
  // A reply slower than production's timeout is an ask there, so it is one here (`by: "model-error"`).
  classifier: { ...DEFAULT_CLASSIFIER, endpoint: args.endpoint ?? DEFAULT_CLASSIFIER.endpoint, askAbove: 1.01, timeoutMs: args.timeout ? Number(args.timeout) : DEFAULT_CLASSIFIER.timeoutMs },
  useClassifier: true,
};

const wanted = args.suites?.split(",");
const files = args["suites-dir"].flatMap((d) => fs.readdirSync(d).filter((f) => f.endsWith(".jsonl")).map((f) => path.join(d, f)));
const outDir = path.join(process.env.AUTOMODE_BENCH_RESULTS ?? path.join(os.homedir(), ".cache", "opencode-automode", "bench"), args.tag);
fs.mkdirSync(outDir, { recursive: true });

for (const file of files) {
  const suite = path.basename(file, ".jsonl");
  if (wanted && !wanted.includes(suite)) continue;
  const rows = fs.readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)).filter((r) => typeof r.command === "string");
  const out = path.join(outDir, `${suite}.jsonl`);
  const done = new Set(fs.existsSync(out) ? fs.readFileSync(out, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l).id) : []);
  const limit = args.limit ? Number(args.limit) : Infinity;
  let n = 0;
  const started = Date.now();
  for (const row of rows) {
    if (n >= limit) break;
    n++;
    if (done.has(row.id)) continue;
    const cwd = row.cwd ? fill(row.cwd) : project;
    const command = fill(row.command);
    // A fresh session per row (rows are independent), always of the same project: the plugin's
    // project is the session's directory, never the directory a command runs in.
    const where = fs.existsSync(cwd) ? cwd : project;
    const d = await decideShell(guard, new SessionState(project), where, command);
    fs.appendFileSync(out, JSON.stringify({ id: row.id, label: row.label ?? null, rule: d.rule, by: d.by, effect: d.effect, score: d.score, ms: d.ms, reason: d.reason }) + "\n");
  }
  console.log(`${suite}: ${n} rows in ${((Date.now() - started) / 1000).toFixed(1)} s`);
}
