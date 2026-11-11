// The decision core, shared by the opencode plugin (index.ts) and the bench (bench/run.mjs).
//
//   1. Pi's deterministic rules (rules.ts) read the whole command:
//        deny     -> deny          (wipes of /, $HOME or system dirs, mkfs, fork bombs)
//        ask      -> ask           (sudo, pushes, outbound data, curl|sh, credential reads,
//                                   writes outside the project, opencode/guard config changes)
//        allow    -> allow         (read-only, builds/tests, local git, edits inside the project)
//        classify -> step 2
//   2. Kev on a local llama-server scores "is this command risky?". Below askAbove it runs;
//      at or above, or with no answer (down, timeout, garbage), it asks. Never fails open.
//
// checkouts() and inCheckout() are adapted from pi-automode-classifier v0.4.1 index.ts (MIT).

import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  bashVerdict,
  parse,
  commitWrites,
  fileVerdict,
  isRootLike,
  makeScope,
  readVerdict,
  within,
  type Action,
  type Matcher,
  type Scope,
  type SessionFiles,
  type UserRules,
  type Verdict,
} from "./rules.ts";
import { scoreCommand, type ClassifierConfig } from "./kev.ts";
import { findGitEntries, gitArgs, gitEnv, gitRun, OPENCODE_PROJECT_FILES, protectedPaths, realpath, safeGit } from "./sandbox.ts";
import { abbreviates, alsoByName, gitCall, gitProblem, observer, single, strict, textGuards, tilde, unmodelled, type Single } from "./guard.ts";

export type Effect = "allow" | "ask" | "deny";

// Ask rules added on top of upstream's, from the bench's rule-allowed risky rows and this
// deployment's needs. Pi user rules: a glob over one simple command (`*` any text, trailing ` *`
// optional) or `re:` + a regex; they also match the command without wrappers like `timeout`.
export const DEFAULT_ASK = [
  // The rules see redirects, cp, mv and tee, but not an editor or a script writing here.
  "re:.*\\.config/opencode.*",
  "re:.*opencode-automode.*",
  // opencode loads project-level config, plugins and commands with no prompt; hook managers run
  // these files from git hooks. Both are read-only inside the sandbox, so a change must ask.
  "re:(^|.*[ /=@])(\\.opencode|opencode\\.jsonc?|\\.husky|\\.lefthook|\\.?lefthook(-local)?\\.(ya?ml|toml|json)|\\.pre-commit-config\\.ya?ml|\\.overcommit\\.yml)( |/|$).*",
  // Dumping the environment prints every secret in it.
  "printenv *",
  "env",
  "export -p",
  // Credentials on the command line or hunted for by name.
  "re:.*\\b(curl|wget|http|https|xh)\\b.*([Aa]uthorization:|[Bb]earer |--user[= ]|-u [^ ]+:|--password).*",
  "re:.*\\bfind\\b.*-i?name\\s+['\"]?\\*?(credentials|token|id_rsa|id_ed25519|id_ecdsa|\\.env|\\.netrc|\\.pgpass)\\b.*",
  "re:.*\\b(yq|jq)\\b.*\\.(password|secret|token|api_?key)\\b.*",
  // Package installs run third-party install scripts.
  "pip install *",
  "pip3 install *",
  "python -m pip install *",
  "python3 -m pip install *",
  "uv pip install *",
  "npm install *",
  "npm i *",
  "npm ci *",
  "pnpm install *",
  "pnpm add *",
  "pnpm i *",
  "yarn add *",
  "yarn install *",
  "bun add *",
  "bun install *",
  "cargo install *",
  "go install *",
  "gem install *",
  // These write .git/config, which is read-only inside the sandbox: ask, so that once approved
  // they run outside it instead of failing.
  "re:^git( -C \\S+)* config(?!.*\\s(--get|--get-all|--get-regexp|--get-urlmatch|-l|--list|--show-origin|--show-scope|--name-only)(\\s|$))( .*)?$",
  "re:^git( -C \\S+)* branch .*(-u|--set-upstream-to|--unset-upstream|--track|-t|-m|-M|--move|-c|-C|--copy|--edit-description)( |=|$).*",
  "re:^git( -C \\S+)* push .*(-u|--set-upstream)( |$).*",
  "re:^git( -C \\S+)* (checkout|switch) .*(--track|-t)( |=|$).*",
  "re:^git( -C \\S+)* (submodule|worktree) (add|init|deinit|update|set-url|set-branch|sync|move|remove|repair|lock|unlock).*",
  // Branches started from a remote branch get tracking config written (read-only in the sandbox).
  "re:^git( -C \\S+)* (checkout -b|checkout -B|switch -c|switch -C|branch) \\S+ \\S+/\\S+.*",
  "re:^git( -C \\S+)* sparse-checkout.*",
  // -c overrides can make git run programs (core.sshCommand, alias.x=!..., diff.external, ...).
  // Only a few harmless keys run without asking.
  "re:^git( .*)? -c (?!(user\\.(name|email)|color\\.[\\w.]+|advice\\.[\\w.]+|core\\.quotepath|init\\.defaultBranch|commit\\.gpgsign|log\\.showSignature)=).*",
  "re:^git( .*)? --(exec-path|git-dir|work-tree|config-env)( |=).*",
  // Environment that changes what git, ssh or the dynamic linker run, however it is set.
  "re:(^|.* )(GIT_[A-Z_]+|SSH_[A-Z_]+|LD_[A-Z_]+|BASH_ENV|ENV|PROMPT_COMMAND)=.*",
  "re:^(export|declare|typeset|readonly|local|read|unset|printf)( .*)? (-v )?['\"]?(GIT_[A-Z_]+|SSH_[A-Z_]+|LD_[A-Z_]+|BASH_ENV|ENV|PROMPT_COMMAND)\\b.*",
  // The same names built by brace expansion, and variables set through a nameref or a computed name.
  "re:.*\\b(GIT|SSH|LD)_\\w*\\{.*",
  "re:^(declare|typeset|local)( .*)? -[a-zA-Z]*n.*",
  "re:^(export|declare|typeset|readonly|local)( .*)? [^ =]*[$`{][^ =]*=.*",
  // Options that make git run a program of the caller's choosing on the other end or locally.
  "re:^git( .*)? (clone|fetch|pull|ls-remote|archive)( .*)? -u( .*)?$",
  "re:^git( .*)? (--upload-pack|--receive-pack|--exec)( |=|$).*",
  // A new repository gets hooks and config after this command's sandbox was set up.
  "re:^git( -C \\S+)* (init|clone)( .*)?$",
];

// An "Always allow" pattern mirrored into the rules: literal words ending in ` *`, nothing else
// (no `re:` prefix, no glob characters inside words).
export const PLAIN_PATTERN = /^(\.{1,2}\/|\/)?[A-Za-z0-9_][\w.+\/-]*( [\w.+\/:=@%,-]+)* \*$/;
// "Always allow" is only mirrored for programs that do not run arbitrary other programs or send
// data out: an allowlist, because the list of programs that can is open-ended (awk, sed, make,
// docker, tar, strace, ...). Project scripts (`./x *`) are mirrored: they run sandboxed.
const MIRROR_OK =
  /^(\.\/\S+|git (status|diff|log|show|add|commit|checkout|switch|restore|stash|branch|tag|fetch|pull|merge|cherry-pick|revert|rm|mv|blame)|cargo (build|check|test|clippy|fmt|doc|tree|metadata|bench|nextest)|go (build|test|vet|fmt)|(npm|pnpm|yarn|bun) (run|test)|pytest|tsc|eslint|prettier|ruff|mypy|black|isort|jest|vitest|ls|cat|head|tail|grep|wc|diff|stat|file|tree|du|df|ps|jq|yq|uniq|cut)( |$)/;
export const mirrorable = (pattern: string) => PLAIN_PATTERN.test(pattern) && MIRROR_OK.test(pattern);

export interface Decision {
  effect: Effect;
  // What settled it: the rules, the model, or the model failing (which asks).
  by: "rules" | "model" | "model-error" | "no-model";
  rule: Action;
  reason: string;
  score?: number;
  ms?: number;
}

export interface Guard {
  rules: UserRules;
  // Changes to these always ask, and no user rule opens them (the guard's own files).
  guarded: string[];
  // Changes to these ask firmly (opencode's config dir), like Pi's own files in upstream.
  configDirs: string[];
  // Extra directories where file changes count as local.
  allowedPaths: string[];
  classifier: ClassifierConfig;
  useClassifier: boolean;
  // ssh to these targets, written exactly as listed (`lab`, or `admin@lab` for a user), runs
  // when the remote command only uses read-only programs. Anything else on them still asks.
  sshHosts?: string[];
  // On sshHosts only: treat `sudo cmd` as `cmd` (so read-only commands under sudo run).
  sshReadOnlySudo?: boolean;
  // `git push` of a non-protected branch to a configured remote, without force/delete/tags/mirror.
  allowFeatureBranchPush?: boolean;
  // Patterns the user chose "Always allow" for. Like Pi's session picks they never replace a
  // firm ask (root, credential reads, downloaded code, your own ask rules).
  picked?: Matcher[];
  // Touching this file (outside the sandbox) after a pause resumes auto-allow.
  resumeFile?: string;
}

// Per opencode session: its project directory (realpath), the git checkouts that belong to it,
// and files the session wrote or downloaded. The project comes from opencode's session location,
// never from a command's working directory: a symlink inside the project must not turn the place
// it points to into "the project".
export class SessionState {
  readonly project: string;
  files: SessionFiles = new Map();
  roots: string[] | undefined;
  // The project's git layout as first seen (outside any sandbox), and its remote URLs.
  snapshot: GitSnapshot | undefined;
  // Set once the layout changed in a way git never does itself; auto-allow stops until the user
  // resumes it.
  tampered: { reason: string; at: number } | undefined;
  // A `git init`, `clone`, `worktree` or `submodule` command this session asked about (and so
  // ran outside the sandbox if approved): new repositories and worktrees are then expected.
  expectNewRepo = false;
  constructor(project: string) {
    this.project = realpath(project);
  }
}

type RemoteUrls = Map<string, { fetch: string[]; push: string[] }>;

interface GitSnapshot {
  // Per checkout root: what `.git` is (directory inode, or pointer file contents).
  entries: { root: string; kind: "dir" | "file" | "none"; ino?: number; text?: string }[];
  // Nested repositories and pointer files found below the roots: they must not change either.
  nested: { path: string; ino?: number; text?: string }[];
  // Every git directory and pointer file known when the snapshot was taken.
  known: Set<string>;
  // Per git directory: whether it had `commondir` and `config.worktree`, and its linked worktrees.
  inside: Map<string, { commondir: boolean; configWorktree: boolean; worktrees: string[] }>;
  commonDir: string | undefined;
  // Undefined when git could not tell: nothing is then trusted about remotes.
  remotes: RemoteUrls | undefined;
  // Which of opencode's project-level files existed in the session directory.
  opencodeFiles: Set<string>;
}

function gitEntry(root: string): GitSnapshot["entries"][number] {
  const p = path.join(root, ".git");
  try {
    const st = fs.lstatSync(p);
    if (st.isDirectory()) return { root, kind: "dir", ino: st.ino };
    if (st.isFile()) return { root, kind: "file", text: fs.readFileSync(p, "utf8") };
  } catch {
    // no .git
  }
  return { root, kind: "none" };
}

const lines = (text: string) => text.split("\n").filter(Boolean);

// Every URL of every remote. `git remote -v` and a single `get-url` each show one of several.
function readRemotes(dir: string): RemoteUrls | undefined {
  const names = gitRun(["-C", dir, "remote"]);
  if (names.status !== 0) return undefined;
  const out: RemoteUrls = new Map();
  for (const name of lines(names.out)) {
    const fetch = gitRun(["-C", dir, "remote", "get-url", "--all", name]);
    const push = gitRun(["-C", dir, "remote", "get-url", "--push", "--all", name]);
    if (fetch.status !== 0 || push.status !== 0) return undefined;
    out.set(name, { fetch: lines(fetch.out), push: lines(push.out) });
  }
  return out;
}

const sameUrls = (a: RemoteUrls | undefined, b: RemoteUrls | undefined, name: string) => {
  const x = a?.get(name);
  const y = b?.get(name);
  return !!x && !!y && JSON.stringify(x) === JSON.stringify(y);
};

function insideOf(gitDir: string) {
  let worktrees: string[] = [];
  try {
    worktrees = fs.readdirSync(path.join(gitDir, "worktrees"));
  } catch {
    // none
  }
  return { commondir: fs.existsSync(path.join(gitDir, "commondir")), configWorktree: fs.existsSync(path.join(gitDir, "config.worktree")), worktrees };
}

function takeSnapshot(roots: string[], project: string): GitSnapshot {
  const entries = roots.map(gitEntry);
  const mainGitDirs = entries.filter((e) => e.kind === "dir").map((e) => realpath(path.join(e.root, ".git")));
  const common = git(project, "rev-parse", "--git-common-dir")?.trim();
  const found = findGitEntries(roots);
  const nested = [
    ...[...found.gitDirs].filter((d) => !mainGitDirs.includes(d)).map((d) => ({ path: d, ino: statIno(d) })),
    ...[...found.pointers].filter((p) => !roots.some((r) => p === path.join(r, ".git"))).map((p) => ({ path: p, text: readText(p) })),
  ];
  return {
    entries,
    nested,
    known: new Set([...found.gitDirs, ...found.pointers]),
    inside: new Map([...found.gitDirs].map((d) => [d, insideOf(d)])),
    commonDir: common ? realpath(path.resolve(project, common)) : undefined,
    remotes: readRemotes(project),
    opencodeFiles: new Set(OPENCODE_PROJECT_FILES.filter((f) => fs.existsSync(path.join(project, f)))),
  };
}

function statIno(p: string): number | undefined {
  try {
    return fs.statSync(p).ino;
  } catch {
    return undefined;
  }
}

function readText(p: string): string | undefined {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return undefined;
  }
}

// What changed in the project's git layout since the snapshot. `replaced` lists changes git never
// makes on its own; `appeared` lists new repositories, worktrees and config files, which are
// fine right after a command the user approved and tampering otherwise.
function layoutChanges(session: SessionState): { replaced: string[]; appeared: string[] } {
  const snap = session.snapshot!;
  const replaced: string[] = [];
  const appeared: string[] = [];
  for (const before of snap.entries) {
    const now = gitEntry(before.root);
    const p = path.join(before.root, ".git");
    if (before.kind === "none" && now.kind !== "none") appeared.push(`${p} appeared`);
    else if (now.kind !== before.kind || now.ino !== before.ino || now.text !== before.text) replaced.push(`${p} was replaced or rewritten`);
    // A main checkout's git directory never has a `commondir`, whenever it got there.
    if (now.kind === "dir" && fs.existsSync(path.join(p, "commondir"))) replaced.push(`${path.join(p, "commondir")} appeared`);
  }
  // A nested repository that is gone was deleted, which plants nothing: forget it. One that is
  // there but different was swapped.
  snap.nested = snap.nested.filter((before) => {
    if (!fs.existsSync(before.path)) return snap.known.delete(before.path), false;
    if (before.ino !== undefined ? statIno(before.path) !== before.ino : readText(before.path) !== before.text) replaced.push(`${before.path} was replaced, moved or rewritten`);
    return true;
  });
  const roots = session.roots ?? [];
  const found = findGitEntries(roots);
  for (const p of [...found.gitDirs, ...found.pointers]) {
    if (!snap.known.has(p) && !roots.some((r) => p === path.join(r, ".git") || p === realpath(path.join(r, ".git")))) appeared.push(`${p} appeared`);
  }
  for (const [dir, before] of snap.inside) {
    if (!fs.existsSync(dir)) continue;
    const now = insideOf(dir);
    if (now.commondir && !before.commondir) replaced.push(`${path.join(dir, "commondir")} appeared`);
    if (now.configWorktree && !before.configWorktree) replaced.push(`${path.join(dir, "config.worktree")} appeared`);
    for (const wt of now.worktrees) if (!before.worktrees.includes(wt)) appeared.push(`${path.join(dir, "worktrees", wt)} appeared (a new linked worktree)`);
  }
  // `.opencode` is left out: the plugin creates it empty so that it can be made read-only.
  for (const f of OPENCODE_PROJECT_FILES) {
    if (f !== ".opencode" && !snap.opencodeFiles.has(f) && fs.existsSync(path.join(session.project, f))) appeared.push(`${path.join(session.project, f)} appeared (opencode loads it without asking)`);
  }
  return { replaced, appeared };
}

// Whether the project's git layout changed since the session started in a way git never does on
// its own: `.git` replaced or renamed, a pointer file rewritten, `commondir` planted, a
// repository, worktree or opencode config file appearing that no approved command explains.
// Returns what was found, so the prompt can say it. The pause lasts until `resumeFile` is touched.
export function gitTampered(session: SessionState, resumeFile?: string): string | undefined {
  if (session.tampered) {
    let resumed = 0;
    try {
      resumed = resumeFile ? fs.statSync(resumeFile).mtimeMs : 0;
    } catch {
      // not resumed
    }
    if (resumed <= session.tampered.at) return session.tampered.reason;
    // The user looked and resumed: what is there now is the new baseline.
    session.tampered = undefined;
    session.snapshot = takeSnapshot(session.roots ?? [], session.project);
    return undefined;
  }
  if (!session.snapshot) return undefined;
  const { replaced, appeared } = layoutChanges(session);
  const expected = session.expectNewRepo;
  // An expected repository must appear by the next decision (the approved command has run by
  // then); a rejected `git init` must not leave the door open.
  session.expectNewRepo = false;
  const found = expected ? replaced : [...replaced, ...appeared];
  if (found.length) {
    const shown = found.slice(0, 5).join("; ") + (found.length > 5 ? `; and ${found.length - 5} more` : "");
    session.tampered = { reason: shown, at: Date.now() };
    return shown;
  }
  if (appeared.length) {
    // New worktrees of the project, inside the folder that holds the main checkout, join it.
    const now = checkouts(session.project);
    const parent = path.dirname(now[0] ?? "/");
    for (const dir of now) if (session.roots && !session.roots.includes(dir) && !isRootLike(parent) && within(dir, parent)) session.roots.push(dir);
    session.snapshot = takeSnapshot(session.roots ?? [], session.project);
  }
  return undefined;
}

const pauseReason = (found: string, resumeFile?: string) =>
  `auto-allow paused for this session: ${found}. Check what is there; approving this prompt does not resume.${resumeFile ? ` To resume, run \`touch ${resumeFile}\` in your own terminal.` : ""}`;

// A command the user is asked about that creates repositories or worktrees when approved.
export const expectsNewRepo = (command: string) => /\bgit\b[^;&|\n]*\b(init|clone|worktree|submodule)\b/.test(command);

// Every git call from this process goes through gitRun: fsmonitor, hooks and askpass off, no prompts.
const git = (cwd: string, ...args: string[]) => safeGit(["-C", cwd, ...args]);

export function checkouts(cwd: string): string[] {
  const entries = (git(cwd, "worktree", "list", "--porcelain") ?? "").split("\n\n");
  return entries
    .filter((entry) => !/^bare$/m.test(entry))
    .flatMap((entry) => /^worktree (.+)$/m.exec(entry)?.[1] ?? [])
    .map(realpath)
    .filter((dir) => !isRootLike(dir));
}

export function inCheckout(file: string, roots: string[]): boolean {
  const dir = path.dirname(file);
  const top = git(dir, "rev-parse", "--show-toplevel")?.trim();
  if (!top || !roots.includes(realpath(top))) return false;
  return git(dir, "ls-files", "--error-unmatch", "--", file) !== undefined || git(dir, "check-ignore", "-q", "--", file) !== undefined;
}

// The project's checkouts (main checkout and its worktrees), as first seen. Worktrees added
// later join only through gitTampered, after a command the user approved. A project at $HOME or
// above has none.
export function projectRoots(session: SessionState): string[] {
  if (isRootLike(session.project)) return [];
  if (!session.roots) {
    const now = checkouts(session.project);
    session.roots = now.length ? now : [session.project];
    if (!session.roots.includes(session.project)) session.roots.push(session.project);
  }
  if (!session.snapshot) session.snapshot = takeSnapshot(session.roots, session.project);
  return session.roots;
}

export function scopeFor(guard: Guard, session: SessionState, cwd: string, rules: UserRules = guard.rules): Scope {
  const roots = projectRoots(session);
  const scope = makeScope(cwd, guard.guarded, {
    rules,
    piDirs: guard.configDirs,
    allowedPaths: [...guard.allowedPaths, ...roots],
    files: session.files,
    picked: guard.picked,
    project: (p) => inCheckout(p, roots),
  });
  // Upstream takes the working directory as the project root; here it is the session's project.
  scope.root = roots.length ? session.project : undefined;
  return scope;
}

// Upstream's wording names Pi; say what it means here.
const reword = (reason: string) => reason.replace(/Pi's own files/g, "opencode's own files (config, AGENTS.md, CLAUDE.md)");

function fromRules(v: Verdict): Decision {
  const effect: Effect = v.action === "deny" ? "deny" : v.action === "allow" ? "allow" : "ask";
  return { effect, by: "rules", rule: v.action, reason: reword(v.reason) };
}

const askBy = (reason: string): Decision => ({ effect: "ask", by: "rules", rule: "ask", reason });

// ---- read-only ssh ----

// ssh options a matched call may use: they change nothing on either side. Anything else
// (-o ProxyCommand/LocalCommand, -F, -J, port forwards, -A, -E log files, ...) asks.
const SSH_FLAGS = new Set(["-q", "-T", "-n", "-4", "-6", "-C", "-x", "-a"]);
const SSH_OPTION_OK = /^(BatchMode|ConnectTimeout|ConnectionAttempts|ServerAliveInterval|ServerAliveCountMax|LogLevel)=[\w.-]+$/i;

// What a remote command may run: each program with the options it may take. A short option
// cluster must be made of `flags`; `long` options match exactly (GNU tools accept any unique
// prefix, so `--out` is not `--output` here, it is unknown); `valued` options take the next
// word, or `--name=value`. Anything not listed asks.
interface Remote {
  flags?: string;
  long?: string[];
  valued?: string[];
  // `-5` style counts.
  numeric?: boolean;
  // Any words at all (echo, test).
  free?: boolean;
  check?: (operands: string[], argv: string[]) => boolean;
}
const SYSTEMCTL_READ = new Set(["status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-timers", "list-sockets", "list-dependencies", "show", "cat"]);
const FIND_TESTS = new Set("-name -iname -path -ipath -regex -iregex -type -maxdepth -mindepth -mtime -mmin -ctime -cmin -atime -amin -newer -size -user -group -perm -links -inum -samefile".split(" "));
const FIND_FLAGS = new Set("-print -print0 -ls -empty -not -o -a -and -or -L -H -P -xdev -mount -readable -writable -executable -prune -quit -daystart -depth -follow -true -false -nouser -nogroup".split(" "));
const IP_OBJECTS = new Set(["addr", "address", "a", "route", "r", "link", "l", "neigh", "neighbor", "n", "rule"]);
const IP_SHOW = new Set(["show", "list", "ls", "lst"]);
const numbers = (ops: string[]) => ops.every((w) => /^\d+(\.\d+)?[smhd]?$/.test(w));
const REMOTE: Record<string, Remote> = {
  cat: { flags: "AbeEnstTuv" },
  head: { flags: "qv", valued: ["-n", "-c", "--lines", "--bytes"], numeric: true },
  tail: { flags: "qvfF", valued: ["-n", "-c", "--lines", "--bytes"], numeric: true },
  grep: { flags: "EFGPiwxvcnHhlLoqsrRIaz", valued: ["-e", "-m", "-A", "-B", "-C", "--include", "--exclude", "--exclude-dir", "--max-count", "--color"], numeric: true },
  rg: { flags: "iwvcnlFSsNHUxo", long: ["--hidden", "--no-ignore", "--files"], valued: ["-e", "-g", "-t", "-T", "-m", "-A", "-B", "-C", "--glob", "--type", "--max-count"] },
  ls: { flags: "aAlhtrSRd1FiLnsgGoXUcukp", long: ["--all", "--human-readable"], valued: ["--color", "--sort", "--time"] },
  stat: { flags: "Lft", valued: ["-c", "--format", "--printf"] },
  file: { flags: "bLiz" },
  wc: { flags: "clmwL" },
  du: { flags: "ahsckmxbHLS0", valued: ["-d", "--max-depth", "--exclude", "-t", "--threshold"] },
  df: { flags: "ahHiklPT", valued: ["-t", "-x", "--output", "--type"] },
  free: { flags: "bkmghwtl", long: ["--mega", "--giga", "--kilo", "--si"] },
  uptime: { flags: "ps" },
  uname: { flags: "asnrvmpio" },
  hostname: { flags: "afdisAIy", long: ["--fqdn", "--short", "--domain", "--all-fqdns", "--ip-address", "--all-ip-addresses"], check: (ops) => !ops.length },
  id: { flags: "ugGnrzZ" },
  whoami: { check: (ops) => !ops.length },
  ps: { flags: "eAfFlwHjTLMyZaxu", long: ["--forest", "--no-headers"], valued: ["-o", "-p", "-u", "-U", "-C", "--sort", "--pid", "--ppid"], check: (ops) => ops.every((w) => /^[aAxuefwlHjTLmc]+$/.test(w)) },
  pgrep: { flags: "lafxnovc", valued: ["-u", "-U", "-P", "-g", "-t", "-d"] },
  date: { flags: "uRI", long: ["--utc", "--universal", "--rfc-email"], valued: ["-d", "--date", "-r", "--reference", "--iso-8601", "--rfc-3339"], check: (ops) => ops.every((w) => w.startsWith("+")) },
  sort: { flags: "bdfgiMhnRrVcCmuzs", valued: ["-k", "-t", "--key", "--field-separator"] },
  uniq: { flags: "cdDiuz", valued: ["-f", "-s", "-w"], check: (ops) => ops.length <= 1 }, // a second operand is the output file
  cut: { flags: "sz", long: ["--complement"], valued: ["-d", "-f", "-c", "-b", "--delimiter", "--fields"] },
  tr: { flags: "cdst" },
  echo: { free: true },
  printf: { free: true },
  true: { free: true },
  false: { free: true },
  test: { free: true },
  "[": { free: true },
  findmnt: { flags: "lnrAkmse", valued: ["-o", "-t", "-T", "-S"] },
  lsblk: { flags: "afilmnpSt", valued: ["-o"] },
  lscpu: { flags: "e" },
  nproc: { long: ["--all"] },
  which: { flags: "a" },
  ss: { flags: "tulnpaeiomsHrx460" },
  readlink: { flags: "fenmqsvz" },
  realpath: { flags: "eLmPqsz" },
  basename: { flags: "az", valued: ["-s"] },
  dirname: { flags: "z" },
  md5sum: { flags: "bct" },
  sha256sum: { flags: "bct" },
  dmesg: { flags: "HkLrTtuwxeJP", valued: ["-l", "-f", "--level", "--facility", "--since", "--until"] },
  journalctl: {
    flags: "abefkmqrx",
    long: ["--no-pager", "--utc", "--system", "--user", "--dmesg", "--boot", "--reverse", "--follow", "--list-boots", "--disk-usage", "--no-hostname", "--all"],
    valued: ["-u", "-n", "-p", "-S", "-U", "-t", "-o", "-g", "--unit", "--user-unit", "--lines", "--priority", "--since", "--until", "--identifier", "--output", "--grep"],
    check: (ops) => !ops.length,
  },
  systemctl: {
    flags: "alq",
    long: ["--no-pager", "--full", "--all", "--failed", "--quiet", "--user", "--system", "--no-legend", "--plain"],
    valued: ["-n", "-t", "-p", "-o", "--lines", "--type", "--state", "--property", "--output"],
    check: (ops) => SYSTEMCTL_READ.has(ops[0] ?? ""),
  },
  ip: {
    flags: "46sdjpo",
    long: ["-br", "-brief", "-c", "-color", "-oneline", "-json", "-pretty", "-details", "-stats", "-statistics", "-human"],
    // `ip <object> [show ...]`: iproute2 takes any prefix of a command, so `s` could be `set`.
    check: (ops) => IP_OBJECTS.has(ops[0] ?? "") && (ops.length === 1 || IP_SHOW.has(ops[1]) || (/^r(oute)?$/.test(ops[0]) && ops[1] === "get" && ops.length === 3)),
  },
  tree: { flags: "adfipugshDCFNlQr", valued: ["-L", "-I", "-P", "--charset"] },
  column: { flags: "tx", valued: ["-s", "-c", "-o"] },
  nl: { flags: "p", valued: ["-b", "-n", "-w", "-s", "-v", "-i"] },
  seq: { flags: "w", valued: ["-s", "-f"], check: numbers },
  sleep: { check: numbers },
};

function remoteProgramOk(argv: string[]): boolean {
  const spec = Object.hasOwn(REMOTE, argv[0]) ? REMOTE[argv[0]] : undefined;
  if (!spec) return false;
  if (spec.free) return true;
  if (argv[0] === "find") return false;
  const operands: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const w = argv[i];
    if (w === "--") return false;
    if (!w.startsWith("-") || w === "-") operands.push(w);
    else if (spec.valued?.includes(w)) {
      if (++i >= argv.length) return false;
    } else if (spec.long?.includes(w)) continue;
    else if (w.startsWith("--")) {
      if (!w.includes("=") || !spec.valued?.includes(w.slice(0, w.indexOf("=")))) return false;
    } else if (spec.numeric && /^-\d+$/.test(w)) continue;
    else if (![...w.slice(1)].every((ch) => spec.flags?.includes(ch))) return false;
  }
  return spec.check ? spec.check(operands, argv) : true;
}

// find: search roots, then tests and actions from an allowlist (no -exec, -delete, -fprint, ...).
function remoteFindOk(argv: string[]): boolean {
  for (let i = 1; i < argv.length; i++) {
    const w = argv[i];
    if (w === "!" || !w.startsWith("-")) continue;
    if (FIND_TESTS.has(w)) i++;
    else if (!FIND_FLAGS.has(w)) return false;
  }
  return true;
}

function remoteIsReadOnly(remote: string, guard: Guard): boolean {
  // Plain words only, joined by `;`, `&&`, `||` or `|`; output may only be discarded.
  const cmds = strict(remote, { pipes: true, nullRedirects: true });
  if (!cmds) return false;
  const plain: string[][] = [];
  for (let argv of cmds) {
    // Opt-in: `sudo [-n] cmd` counts as `cmd`. Any other sudo option (-u, -s, -i, ...) still asks.
    if (argv[0] === "sudo" && guard.sshReadOnlySudo) argv = argv.slice(argv[1] === "-n" ? 2 : 1);
    if (!argv.length || argv.some((w) => w.includes("'"))) return false;
    if (!(argv[0] === "find" ? remoteFindOk(argv) : remoteProgramOk(argv))) return false;
    plain.push(argv);
  }
  // The rules get a say too: a credential read or a guarded file still asks.
  const remoteScope = makeScope("/", guard.guarded, { rules: guard.rules, piDirs: guard.configDirs });
  const action = bashVerdict(plain.map((argv) => argv.map((w) => `'${w}'`).join(" ")).join(" ; "), remoteScope).action;
  return action === "allow" || action === "classify";
}
REMOTE.find = {};

function sshAllowed(s: Single, guard: Guard): boolean {
  const words = s.argv;
  if (words[0] !== "ssh") return false;
  let user: string | undefined;
  let i = 1;
  for (; i < words.length && words[i].startsWith("-"); i++) {
    const w = words[i];
    if (SSH_FLAGS.has(w)) continue;
    if (w === "-p" && /^\d+$/.test(words[i + 1] ?? "")) i++;
    else if (w === "-l" && /^[\w.-]+$/.test(words[i + 1] ?? "") && user === undefined) user = words[++i];
    else if (w === "-o" && SSH_OPTION_OK.test(words[i + 1] ?? "")) i++;
    else if (!(/^-o./.test(w) && SSH_OPTION_OK.test(w.slice(2)))) return false;
  }
  const target = words[i];
  if (!target || !/^[\w.-]+(@[\w.-]+)?$/.test(target) || (user !== undefined && target.includes("@"))) return false;
  // The target as listed: `lab` does not cover `root@lab`.
  if (!(guard.sshHosts ?? []).includes(user !== undefined ? `${user}@${target}` : target)) return false;
  // ssh joins the remaining words with spaces and hands them to the remote shell, as here.
  const remote = words.slice(i + 1).join(" ").trim();
  if (!remote) return false; // an interactive login
  return remoteIsReadOnly(remote, guard);
}

// ---- feature-branch push ----

const PROTECTED_BRANCH = /^(main|master|trunk|develop|development|dev|production|prod|staging|stable|live|gh-pages|release([/-].*)?|hotfix([/-].*)?)$/;
const PUSH_SAFE_FLAGS = new Set(["-q", "--quiet", "-v", "--verbose", "--porcelain", "-n", "--dry-run", "--progress", "--no-progress"]);
// Repository-level config keys (the repository's own file, its worktree file and anything they
// include) that cannot change where git connects, what it sends or what it runs. A repository
// with any other key gets no push without a prompt and no ssh agent. Global and system config
// are the user's own and outside anything a sandboxed command can write.
const REPO_CONFIG_OK =
  /^(core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks|autocrlf|eol|safecrlf|quotepath|abbrev|compression|bigfilethreshold|preloadindex|commitgraph|multipackindex|sparsecheckout|sparsecheckoutcone|longpaths|untrackedcache|splitindex)|remote\..+\.(url|fetch|tagopt|prune|prunetags|promisor|partialclonefilter|skipdefaultupdate)|branch\..+\.(remote|merge|rebase|description)|user\.(name|email)|init\.defaultbranch|pull\.(rebase|ff)|fetch\.(prune|prunetags)|gc\.[\w.]+|pack\.[\w.]+|index\.[\w.]+|feature\.[\w.]+|maintenance\.[\w.]+|extensions\.(objectformat|refstorage|worktreeconfig|partialclone|preciousobjects)|submodule\..+\.(url|active|branch)|commit\.gpgsign|tag\.gpgsign|merge\.(ff|conflictstyle)|diff\.(renames|algorithm)|color\.[\w.]+|advice\.[\w.]+|rerere\.enabled|include\.path|includeif\..+\.path)$/;

// The effective config as `[scope, key, value]`, or undefined when it could not be read in full
// (git failed, the output was cut off, a value spans lines): the caller must then ask.
function readConfig(dir: string): [string, string, string][] | undefined {
  const r = gitRun(["-C", dir, "config", "--show-scope", "--includes", "--list"]);
  if (r.status !== 0) return undefined;
  const out: [string, string, string][] = [];
  for (const line of lines(r.out)) {
    const m = /^(\w+)\t([^=\s]+)(?:=(.*))?$/.exec(line);
    if (!m) return undefined;
    out.push([m[1], m[2].toLowerCase(), m[3] ?? ""]);
  }
  return out;
}

const repoConfigOk = (config: [string, string, string][]) => config.every(([scope, key]) => (scope !== "local" && scope !== "worktree") || REPO_CONFIG_OK.test(key));

// Whether `dir` is the session's own repository, unchanged in config and remote URLs.
function ownRepository(dir: string, session: SessionState): [string, string, string][] | undefined {
  const snap = session.snapshot;
  const common = gitRun(["-C", dir, "rev-parse", "--git-common-dir"]);
  if (!snap?.commonDir || common.status !== 0 || realpath(path.resolve(dir, common.out.trim())) !== snap.commonDir) return undefined;
  const config = readConfig(dir);
  return config && repoConfigOk(config) ? config : undefined;
}

// An optional value: undefined when unset, null when git failed.
function configValue(dir: string, key: string): string | undefined | null {
  const r = gitRun(["-C", dir, "config", "--get", key]);
  return r.status === 0 ? r.out.trim() : r.status === 1 ? undefined : null;
}

const run = (args: string[], timeout: number) =>
  new Promise<string | undefined>((resolve) => {
    execFile("git", gitArgs(args), { encoding: "utf8", timeout, maxBuffer: 1 << 20, env: gitEnv() }, (error, stdout) => resolve(error ? undefined : stdout));
  });

async function pushIsSafe(dir: string, words: string[], session: SessionState): Promise<boolean> {
  // Only the project's own repository: not a copy the agent built elsewhere.
  const snap = session.snapshot;
  const config = ownRepository(dir, session);
  if (!snap || !config) return false;
  const flags = words.filter((w) => w.startsWith("-"));
  if (!flags.every((f) => PUSH_SAFE_FLAGS.has(f))) return false;
  const [remote, ...refspecs] = words.filter((w) => !w.startsWith("-"));
  // A URL or an unknown name could send the code anywhere; so could a remote whose URLs (all of
  // them: git pushes to each) changed since the session started. Without a remote argument git
  // uses the branch's remote.
  const head = gitRun(["-C", dir, "symbolic-ref", "--quiet", "--short", "HEAD"]);
  if (head.status === undefined) return false;
  const current = head.status === 0 ? head.out.trim() : undefined;
  const branchRemote = current ? configValue(dir, `branch.${current}.remote`) : undefined;
  if (branchRemote === null) return false;
  const viaRemote = remote ?? branchRemote ?? "origin";
  if (!sameUrls(snap.remotes, readRemotes(dir), viaRemote)) return false;
  const value = (key: string) => config.filter(([, k]) => k === key).at(-1)?.[2];
  const pushDefault = value("push.default")?.toLowerCase();
  if (pushDefault && pushDefault !== "simple" && pushDefault !== "current") return false;
  // In any scope: a plain push would then send more than the branch.
  if (/^(true|yes|on|1)$/i.test(value("push.followtags") ?? "") || config.some(([, k]) => /^remote\..+\.mirror$/.test(k))) return false;
  // The remote's default branch, asked of the remote itself (the local refs/remotes/<r>/HEAD can be
  // rewritten). Repository config that could change how git connects was rejected above, and no
  // askpass program runs.
  const symref = await run(["-C", dir, "ls-remote", "--symref", viaRemote, "HEAD"], 8000);
  const remoteDefault = /^ref: refs\/heads\/(\S+)\s+HEAD$/m.exec(symref ?? "")?.[1];
  if (!remoteDefault) return false;
  const isProtected = (branch: string | undefined) => !branch || branch === "HEAD" || PROTECTED_BRANCH.test(branch) || branch === remoteDefault;
  if (!refspecs.length) {
    // Without a refspec git pushes the current branch to its upstream (simple) or the same name
    // (current). The upstream must be the same-named branch, or unset.
    if (!current) return false;
    for (const [, key, merge] of config) {
      if (key === `branch.${current.toLowerCase()}.merge` && merge.trim().replace(/^refs\/heads\//, "") !== current) return false;
    }
    return !isProtected(current);
  }
  return refspecs.every((spec) => {
    // `+x` forces, `:x` deletes, wildcards, tags and other ref namespaces are out of scope.
    if (!spec || spec.startsWith("+") || spec.startsWith(":") || spec.includes("*") || /^refs\/(?!heads\/)/.test(spec)) return false;
    const [src, dst = src] = spec.split(":");
    if (spec.split(":").length > 2) return false;
    // Resolve the destination as git does: `@` and `HEAD` are the current branch; `refs/heads/x`
    // is x; any other qualified form (`heads/x`, `refs/...`, `remotes/...`) is out of scope,
    // because git would expand it to a ref the protected-branch check never saw.
    const branch = dst === "HEAD" || dst === "@" ? current : dst.startsWith("refs/heads/") ? dst.slice("refs/heads/".length) : /^(refs|heads|tags|remotes)\//.test(dst) ? undefined : dst;
    // The source must be a branch (not a tag or other ref), or the current branch.
    const srcRef = src === "HEAD" || src === "@" ? (current ? `refs/heads/${current}` : undefined) : git(dir, "rev-parse", "--symbolic-full-name", src)?.trim();
    if (!srcRef?.startsWith("refs/heads/")) return false;
    return src.length > 0 && !isProtected(branch);
  });
}

// `git [-C dir]... <subcommand> ...` with no other global option: the directory and the rest.
function plainGit(s: Single, subcommands: RegExp): { dir: string; sub: string; words: string[] } | undefined {
  if (s.argv[0] !== "git") return undefined;
  let dir = s.dir;
  let i = 1;
  for (; s.argv[i] === "-C" && i + 1 < s.argv.length; i += 2) {
    if (/^~[^/]/.test(s.argv[i + 1])) return undefined;
    dir = path.resolve(dir, tilde(s.argv[i + 1]));
  }
  const sub = s.argv[i] ?? "";
  return subcommands.test(sub) ? { dir, sub, words: s.argv.slice(i + 1) } : undefined;
}

// The push must be the whole tool call (after an optional `cd`, under an optional `timeout`):
// anything else in the same command could change the config, hooks or refs this check reads
// before the push runs.
async function pushAllowed(s: Single, session: SessionState): Promise<boolean> {
  const call = plainGit(s, /^push$/);
  return !!call && (await pushIsSafe(call.dir, call.words, session));
}

// The rules ask about ssh and pushes. These two matchers turn that into an allow for exactly
// the tool call that was checked: the text a Matcher is shown must be that call, word for word.
function rulesFor(guard: Guard, watch: Matcher, s: Single | undefined, pushOk: boolean): UserRules {
  const extra: Matcher[] = [];
  if (s && guard.sshHosts?.length && sshAllowed(s, guard)) extra.push({ source: `ssh to ${guard.sshHosts.join(", ")} with a read-only remote command`, test: (text) => s.texts.includes(text) });
  if (s && pushOk) extra.push({ source: "git push of a feature branch to a configured remote", test: (text) => s.texts.includes(text) });
  return {
    deny: [watch, ...guard.rules.deny.map(alsoByName)],
    ask: guard.rules.ask.map(alsoByName),
    classify: guard.rules.classify.map(alsoByName),
    allow: [...guard.rules.allow, ...extra],
  };
}

// Git subcommands that may write inside git directories when they make up the whole tool call.
const GIT_WRITERS = new Set(["add", "commit", "checkout", "switch", "restore", "stash", "reset", "merge", "cherry-pick", "revert", "tag", "branch", "fetch", "pull", "mv", "rm", "status", "log", "diff", "show", "notes", "gc", "prune", "pack-refs", "update-index", "rev-parse", "ls-files", "describe", "blame", "shortlog", "reflog"]);
const GIT_FILE_OPTIONS = ["--output", "--output-directory", "--exec", "--template", "--file", "--upload-pack", "--receive-pack"];

// A tool call made only of `git <writer>` commands (and `cd`), in plain words: no redirects,
// substitutions, variables or options that write files or run programs. Only such calls get
// write access inside git directories (minus hooks and config); for everything else git
// directories are read-only.
export function gitOnly(command: string): boolean {
  const cmds = strict(command);
  if (!cmds) return false;
  return cmds.every((argv) => {
    if (argv[0] === "cd") return argv.length <= 2;
    if (argv[0] !== "git") return false;
    const call = gitCall(argv.slice(1));
    if (typeof call === "string" || !GIT_WRITERS.has(call.sub ?? "")) return false;
    return !call.rest.some((w) => /^(-o|-x|-F|-u)$/.test(w) || abbreviates(w, GIT_FILE_OPTIONS));
  }) && cmds.some((argv) => argv[0] === "git");
}

const FETCH_FLAGS = new Set([
  "-q", "--quiet", "-v", "--verbose", "--all", "-p", "--prune", "-t", "--tags", "--no-tags", "-f", "--force", "-n", "--dry-run", "--rebase", "--no-rebase", "--ff-only", "--ff",
  "--no-ff", "--autostash", "--no-autostash", "--progress", "--no-progress", "--heads", "--refs", "--symref", "--exit-code", "--porcelain", "--atomic",
]);

// Whether a tool call gets the ssh agent and ~/.ssh's known_hosts/config (never private keys):
// only a single plain `git fetch/pull/push/ls-remote` of the project's own repository, naming a
// remote that was configured when the session started, with options from a short list; or a
// single `ssh`/`scp` command (which the rules only allow for sshHosts).
export function usesSsh(command: string, cwd: string, session: SessionState): boolean {
  const roots = projectRoots(session);
  const s = single(command, cwd);
  if (!s) return false;
  if (s.argv[0] === "ssh" || s.argv[0] === "scp") return true;
  const call = plainGit(s, /^(fetch|pull|push|ls-remote)$/);
  if (!call) return false;
  const flags = call.words.filter((w) => w.startsWith("-"));
  const allowed = call.sub === "push" ? PUSH_SAFE_FLAGS : FETCH_FLAGS;
  if (!flags.every((f) => allowed.has(f) || /^--depth=\d+$/.test(f))) return false;
  const real = realpath(call.dir);
  if (!roots.some((r) => real === r || real.startsWith(r + "/"))) return false;
  // The project's own repository, not one nested inside it or pointed elsewhere; its config must
  // not change how git connects; and the remote must be one it had from the start, by name (a
  // path or URL such as `ext::cmd` would make git run a program).
  if (!ownRepository(call.dir, session)) return false;
  const [remote, ...refs] = call.words.filter((w) => !w.startsWith("-"));
  const now = readRemotes(call.dir);
  const names = remote === undefined ? [...(session.snapshot?.remotes?.keys() ?? [])] : [remote];
  if (remote !== undefined && !session.snapshot?.remotes?.has(remote)) return false;
  return names.every((n) => sameUrls(session.snapshot?.remotes, now, n)) && refs.every((r) => /^[\w.\/@:+^~-]+$/.test(r));
}

// A redirect into opencode's project config or a hook manager's files. The rules' Matchers see
// a command's words, not its redirect targets.
function redirectProblem(command: string, depth = 0): string | undefined {
  for (const cmd of depth > 3 ? [] : parse(command).cmds) {
    const target = cmd.out.find((t) => t.split("/").some((part) => OPENCODE_NAME.test(part) || HOOK_MANAGER_NAME.test(part)));
    if (target) return `writes ${target}, which opencode or a git hook loads and runs`;
    for (const word of cmd.argv) {
      const inner = /\s/.test(word) && word.includes(">") ? redirectProblem(word, depth + 1) : undefined;
      if (inner) return inner;
    }
  }
  return undefined;
}

// What the model is shown for a command that runs files this session wrote: the command, then
// the start of each file.
function withFiles(command: string, files: string[] | undefined): string {
  let text = command;
  for (const file of files ?? []) {
    const body = readText(file);
    if (body !== undefined) text += `\n# ${path.basename(file)} contains:\n${body.slice(0, 2000)}`;
  }
  return text;
}

export async function decideShell(guard: Guard, session: SessionState, cwd: string, command: string, signal?: AbortSignal): Promise<Decision> {
  projectRoots(session); // takes the git snapshot first (all git calls here run with fsmonitor and hooks off)
  const tampered = gitTampered(session, guard.resumeFile);
  if (tampered) return askBy(pauseReason(tampered, guard.resumeFile));
  // Syntax bash and the rules' parser read differently: nothing below can be trusted on it.
  const syntax = unmodelled(command);
  if (syntax) return askBy(`the rules cannot read this command the way the shell does (${syntax})`);
  const s = single(command, cwd);
  const pushOk = !!s && !!guard.allowFeatureBranchPush && (await pushAllowed(s, session));
  const watch = observer();
  const scope = scopeFor(guard, session, cwd, rulesFor(guard, watch.matcher, s, pushOk));
  const verdict = bashVerdict(command, scope);
  if (verdict.action === "deny") return fromRules(verdict);
  const gitIssue = gitProblem(command) ?? redirectProblem(command);
  if (gitIssue) return askBy(gitIssue);
  const written = () => new Map([...session.files.keys(), ...scope.pending.keys()].map((p) => [path.basename(p), p] as [string, string]));
  const extra = textGuards(watch.pairs(), { cwd: scope.cwd ?? cwd, cwdKnown: !/(^|[\s;&|(])(cd|pushd|popd)(\s|$)/.test(command), scope, written });
  if (verdict.action === "ask") return fromRules(verdict);
  if (extra?.action === "ask") return askBy(extra.reason);
  if (verdict.action === "allow" && !extra) {
    commitWrites(scope);
    return fromRules(verdict);
  }
  const why = extra?.reason ?? reword(verdict.reason);
  if (!guard.useClassifier) return { effect: "ask", by: "no-model", rule: "classify", reason: `rules leave this to the model, which is off (${why})` };
  const result = await scoreCommand(guard.classifier, { tool: "bash", cwd, command: withFiles(command, extra?.files) }, signal);
  if ("error" in result) return { effect: "ask", by: "model-error", rule: "classify", reason: `model gave no answer: ${result.error}`, ms: result.ms };
  const { score, ms } = result;
  // Written so that a threshold that is not a number asks.
  if (typeof guard.classifier.askAbove !== "number" || !(score < guard.classifier.askAbove)) {
    return { effect: "ask", by: "model", rule: "classify", reason: `model risk ${score.toFixed(2)} (asks at ${guard.classifier.askAbove} and above)`, score, ms };
  }
  commitWrites(scope);
  return { effect: "allow", by: "model", rule: "classify", reason: `model risk ${score.toFixed(2)}`, score, ms };
}

// The path with the symlinks of its deepest existing ancestor resolved.
function realish(p: string): string {
  const tail: string[] = [];
  for (let cur = p; ; ) {
    try {
      return path.join(fs.realpathSync(cur), ...tail);
    } catch {
      const parent = path.dirname(cur);
      if (parent === cur) return p;
      tail.unshift(path.basename(cur));
      cur = parent;
    }
  }
}

const HOOK_MANAGER_NAME = /^(\.husky|\.lefthook|\.?lefthook(-local)?\.(ya?ml|toml|json)|\.pre-commit-config\.ya?ml|\.overcommit\.yml)$/;
const OPENCODE_NAME = /^(\.opencode|\.claude|\.agents|opencode\.jsonc?)$/;

// Files the sandbox keeps read-only for shell commands; the edit tool must not be a way around.
function protectedFile(guard: Guard, session: SessionState, target: string): string | undefined {
  const p = realish(target);
  const parts = p.split("/");
  if (parts.includes(".git")) return "changes a file inside a git directory (hooks and config run code)";
  if (parts.some((part) => OPENCODE_NAME.test(part))) return "changes opencode's project-level config, which opencode loads without asking";
  if (parts.some((part) => HOOK_MANAGER_NAME.test(part))) return "changes a hook manager's files, which git hooks run";
  const roots = projectRoots(session);
  const hit = protectedPaths({ projectRoots: roots, allowedPaths: guard.allowedPaths, project: session.project }).find((d) => within(p, realish(d)));
  return hit ? `changes ${hit}, which git or opencode runs or loads` : undefined;
}

// edit/write/patch: only ever tightens. Undefined means "leave opencode's own verdict alone".
export function decideFile(guard: Guard, session: SessionState, cwd: string, target: string): Decision | undefined {
  const scope = scopeFor(guard, session, cwd);
  const verdict = fileVerdict("write", target, scope);
  // opencode reports edit, write and patch alike, so an edit could be a one-line change: a
  // downloaded file stays a downloaded file.
  for (const p of scope.pending.keys()) if (session.files.get(p) === "fetched") scope.pending.delete(p);
  if (verdict.action === "allow") {
    const reason = protectedFile(guard, session, path.resolve(cwd, target));
    if (reason) return { effect: "ask", by: "rules", rule: "ask", reason: `edit ${reason}` };
    commitWrites(scope);
    return undefined;
  }
  return fromRules(verdict);
}

// read: asks for credential files, otherwise leaves opencode's verdict alone.
export function decideRead(guard: Guard, session: SessionState, cwd: string, target: string): Decision | undefined {
  const verdict = readVerdict("read", target, scopeFor(guard, session, cwd));
  return verdict ? fromRules(verdict) : undefined;
}
