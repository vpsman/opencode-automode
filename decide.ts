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

import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, randomUUID } from "node:crypto";
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
  type Simple,
  type Verdict,
} from "./rules.ts";
import { scoreCommand, type ClassifierConfig } from "./kev.ts";
import { findGitEntries, gitArgs, Scan, gitEnv, gitRun, inGitDir, madeByPlan, pushHooksMissing, HOOK_MANAGER_FILES, OPENCODE_CONFIG_NAMES, OPENCODE_PROJECT_FILES, opencodeDirs, protectedPaths, realpath, safeGit, workTreeSubmodules } from "./sandbox.ts";
import { canonical, type Printed } from "./canon.ts";
import { PathWalkError, fetchDestination, procRelative, runsItsWords } from "./guard.ts";
import { abbreviates, allCommands, arithmeticAssignments, braceWords, expandWord, gitMessageWords, EDITOR_ASSIGNMENT, editorCommand, programs, withoutGlobals, alsoByName, argvGuards, dangerousName, envAssignmentsOk, expansionProblem, gitCall, gitProblem, inputReads, landing, literalTargets, located, physical, placedReads, present, cdTo, type Place, type Places, observer, protectedNameIn, runtimeReads, single, stricter, strict, strictCommands, textGuards, tilde, tildeMismatch, unmodelled, writesOf, writtenBy, type Single, type StrictCommand, getopt, GIT_OPTIONS, lastOf, type Getopt, unreadableGlob } from "./guard.ts";

export type Effect = "allow" | "ask" | "deny";

const literal = (names: string[]) => names.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");

// Ask rules added on top of upstream's, from the bench's rule-allowed risky rows and this
// deployment's needs. Pi user rules: a glob over one simple command (`*` any text, trailing ` *`
// optional) or `re:` + a regex; they also match the command without wrappers like `timeout`.
const GIT_C_KEYS = "user\\.(name|email)|color\\.[\\w.]+|advice\\.[\\w.]+|core\\.quotepath|init\\.defaultBranch|commit\\.gpgsign|log\\.showSignature";
export const DEFAULT_ASK = [
  // The rules see redirects, cp, mv and tee, but not an editor or a script writing here.
  "re:.*\\.config/opencode.*",
  "re:.*opencode-automode.*",
  // opencode loads project-level config, plugins and commands with no prompt; hook managers run
  // these files from git hooks. Both are read-only inside the sandbox, so a change must ask.
  `re:(^|.*[ /=@])(${literal([...OPENCODE_CONFIG_NAMES, ...HOOK_MANAGER_FILES])})( |/|$).*`,
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
  // The commands that write .git/config (read-only inside the sandbox), make a repository or
  // write the sparse-checkout file ask, so that once approved they run outside it instead of
  // failing: `git config` writes, `branch -u`/`-m`/`-c`/`--track`, `push -u`, `checkout`/`switch`
  // `--track` or from a remote start point, `submodule`/`worktree` actions that write, `init`,
  // `clone` and `sparse-checkout`. They are read in the guard by the position of each word, as
  // git reads them (configWrite and gitConfigTouch in guard.ts, round 4 finding 7): the patterns
  // that stood here, anchored at `^git( -C \S+)*`, missed a `-C` value with a blank, a global
  // option before the subcommand and an option before the action.
  // -c overrides can make git run programs (core.sshCommand, alias.x=!..., diff.external, ...).
  // Only a few harmless keys run without asking. Git's own `-c` comes before the subcommand: after
  // it, `-c` is the subcommand's (`switch -c <branch>`, `grep -c`, `diff -c`), round 3 also-list.
  // (`clone -c`/`--config` asks in the guard with every clone; gitCall asks on any global `-c`
  // key outside the same list.)
  `re:^git(?: -C \\S+| -c (?:${GIT_C_KEYS})=\\S*| -(?!c(?: |$))\\S+)* -c (?!(${GIT_C_KEYS})=).*`,
  "re:^git( .*)? --(exec-path|git-dir|work-tree|config-env)( |=).*",
  // Environment that changes what git, ssh or the dynamic linker run, however it is set.
  // `GIT_PAGER=cat` changes nothing that runs (round 3, finding 28, signed off).
  // An editor that does nothing (GIT_EDITOR=true and the like, finding 13) is judged by the guard,
  // which allows it only before the git commands that would open one.
  "re:(^|.* )(GIT_(?!PAGER=cat( |$)|(EDITOR|SEQUENCE_EDITOR)=(true|:)( |$)|MERGE_AUTOEDIT=no( |$))[A-Z_]+|SSH_[A-Z_]+|LD_[A-Z_]+|BASH_ENV|ENV|PROMPT_COMMAND)=.*",
  "re:^(export|declare|typeset|readonly|local|read|unset|printf)( .*)? (-v )?['\"]?(GIT_[A-Z_]+|SSH_[A-Z_]+|LD_[A-Z_]+|BASH_ENV|ENV|PROMPT_COMMAND)\\b.*",
  // The same names built by brace expansion, and variables set through a nameref or a computed name.
  "re:.*\\b(GIT|SSH|LD)_\\w*\\{.*",
  "re:^(declare|typeset|local)( .*)? -[a-zA-Z]*n.*",
  "re:^(export|declare|typeset|readonly|local)( .*)? [^ =]*[$`{][^ =]*=.*",
  // Options that make git run a program of the caller's choosing on the other end or locally.
  "re:^git( .*)? (clone|fetch|pull|ls-remote|archive)( .*)? -u( .*)?$",
  "re:^git( .*)? (--upload-pack|--receive-pack|--exec)( |=|$).*",
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
  // The command as canon.ts printed it back (round 4, finding 16): the text the scanner, the
  // rules and the guards judged. An allow is an allow of this text, and this text is what must
  // run; the plugin hands it to the sandbox wrapper. Unset when the printer asked.
  printed?: string;
  // The printed text relies on bash (braces expanded, `[[ ]]`, `<<<`, ...): under dash it asks.
  bashOnly?: boolean;
  // On an ask: records what the call writes, as an allow does (its named writes, the marks of the
  // writes the checks cannot list, and the git work-tree changes it will make), for when the user
  // approves it (round 4, finding 4, second pass). The plugin calls it from its approval hook.
  approve?: () => void;
  // The git work-tree changes this call makes (decision D1): the plugin sets `done` on each once
  // no process of the call is left, and the next decision marks the files git changed.
  worktree?: WorkTreeChange[];
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
// The moment the session began (round 4, finding 4; B7-1): one moment for every session of this
// process, taken when this module is loaded. A file about to run whose change time is at or after
// it goes to the model. Per SessionState, and taken at the session's first call, it let a second
// session (a subagent, a reload of the session list) read the first one's writes as old.
// `at`: the moment on the clock of the temp directory's file system (0: no reading, which grants
// no trust: every file then counts as changed); `dev`: that file system.
export interface Moment {
  at: bigint;
  dev: bigint | undefined;
}
// What a file system's clock says now, read off a file made there (never Date.now(): two clocks
// are not compared): a file without a name (O_TMPFILE: nothing appears in the directory, and no
// other process can put a file in its place), or, where the file system has none, a file made
// exclusively in a new directory, with its descriptor kept. `tick`: wait until the clock has
// moved on (it can tick more slowly than this runs), so that a file made just before reads as
// older.
const O_TMPFILE = 0o20000000 | fs.constants.O_DIRECTORY;
function clockOn(dir: string, tick = false): { at: bigint; dev: bigint } | undefined {
  let made: string | undefined;
  let fd: number | undefined;
  try {
    try {
      fd = fs.openSync(dir, O_TMPFILE | fs.constants.O_RDWR, 0o600);
    } catch {
      made = fs.mkdtempSync(path.join(dir, ".automode-clock-"));
      fd = fs.openSync(path.join(made, "clock"), "wx", 0o600);
    }
    const first = fs.fstatSync(fd, { bigint: true });
    if (!tick) return { at: first.ctimeNs, dev: first.dev };
    // (For as long as two seconds, not for a number of rounds: ten thousand of them end within
    // one tick on tmpfs now and then, B7-1, and the reading was then none at all.)
    for (const until = process.hrtime.bigint() + 2_000_000_000n; process.hrtime.bigint() < until; ) {
      fs.futimesSync(fd, 0, 0);
      const now = fs.fstatSync(fd, { bigint: true }).ctimeNs;
      if (now > first.ctimeNs) return { at: now, dev: first.dev };
    }
    return undefined;
  } catch {
    return undefined;
  } finally {
    if (fd !== undefined) fs.closeSync(fd);
    if (made) fs.rmSync(made, { recursive: true, force: true });
  }
}
export function takeMoment(): Moment {
  const now = clockOn(os.tmpdir(), true);
  return { at: now?.at ?? 0n, dev: now?.dev };
}
const MOMENT = takeMoment();
// A file system's clock against the temp directory's (B7-1: the two differ on a network file
// system, a shared folder of a virtual machine, a file system that keeps whole seconds). Read
// once per file system, the first time a file on it is judged: the temp clock, that clock, the
// temp clock again. `delta` is what that clock is ahead by, at the least (0 where the readings
// cannot tell the two apart); `grain`: it keeps whole seconds (a reading that ends in nine
// zeros), and a moment on it is then cut down to the second, as its files' times are.
const offsets = new Map<bigint, { delta: bigint; grain: bigint } | null>();
function offsetOf(dev: bigint, dirs: string[]): { delta: bigint; grain: bigint } | null {
  const known = offsets.get(dev);
  if (known !== undefined) return known;
  let found: { delta: bigint; grain: bigint } | null = null;
  for (const dir of dirs) {
    try {
      if (fs.statSync(dir, { bigint: true }).dev !== dev) continue;
    } catch {
      continue;
    }
    const before = clockOn(os.tmpdir());
    const there = clockOn(dir);
    const after = clockOn(os.tmpdir());
    if (!before || !there || !after || there.dev !== dev) continue;
    const grain = there.at % 1_000_000_000n === 0n ? 1_000_000_000n : 1n;
    const low = there.at - after.at;
    const high = there.at - before.at + (grain > 1n ? grain : 0n);
    found = { delta: low <= 0n && high >= 0n ? 0n : low, grain };
    break;
  }
  offsets.set(dev, found);
  return found;
}
// The moment on the clock of the file system `dev` (the one a judged file lives on). `dirs`:
// directories that may lie on it (the file's own, the project's, the home directory), for the
// reading. Where the plugin can make a file in none of them the temp directory's clock stands
// (the kernel keeps one clock for its local file systems; a file system this user cannot write
// to is not one the session's commands wrote to either).
export function momentOn(moment: Moment, dev: bigint, dirs: string[]): bigint {
  if (moment.at === 0n || dev === moment.dev) return moment.at;
  const offset = offsetOf(dev, dirs);
  if (!offset) return moment.at;
  const at = moment.at + offset.delta;
  return at - (at % offset.grain);
}

export class SessionState {
  // The one moment (see Moment). The tests make their files after this module is loaded, and
  // take a moment per state instead (`SessionState.moment = takeMoment`); nothing else sets it.
  static moment: () => Moment = () => MOMENT;
  readonly moment = SessionState.moment();
  // Compare only filesystem timestamps. Failure to take a baseline grants no trust.
  readonly began = this.moment.at;
  readonly project: string;
  files: SessionFiles = new Map();
  // Files a command of this session wrote, appended to or edited in place. The rules' own list
  // (`files`) leaves an appended file's origin alone and does not follow `sed -i`.
  touched = new Set<string>();
  roots: string[] | undefined;
  // The project's git layout as first seen (outside any sandbox), and its remote URLs.
  snapshot: GitSnapshot | undefined;
  // Set once the layout changed in a way git never does itself; auto-allow stops until the user
  // resumes it.
  // `named`: what the reason shows (a path; for operation state the path and what was said of
  // it). A resume takes those into the baseline; whatever else changed meanwhile is named first
  // (round 4, finding 21, sixth pass). `held`: what each named path held when it was shown
  // (`fingerprint`): at the resume only a path that still holds that is taken in, and one that
  // holds something else is named again (seventh pass).
  tampered: { reason: string; at: number; named?: string[]; held?: Record<string, string> } | undefined;
  // Operation state the checks found that no pause has shown yet, by what a pause names it
  // (Change.key): it stays here until a pause that showed it is resumed (seventh pass).
  pendingState = new Map<string, Change>();
  // Repositories and worktrees the user approved: a `git init`, `clone`, `worktree add` or
  // `submodule` command this session asked about, once it was approved and while it runs. Only
  // what appears inside the directories that command named is expected.
  expecting: Expected[] = [];
  // Git-only calls since the last check of the git directories' operation state.
  gitCalls: GitCall[] = [];
  // Directories where an allowed call wrote files the checks cannot list (an archive extracted,
  // a patch applied, a git checkout, a glob they could not expand; round 4, finding 4). A file
  // run by its path below one goes to the model for the rest of the session.
  unlisted: string[] = [];
  // Git calls that write the work tree (decision D1), each with the commit and the status before
  // it: once the call is over, the files git changed are marked (added to `touched`); until then,
  // its repository counts as marked.
  worktree: WorkTreeChange[] = [];
  constructor(project: string) {
    this.project = realpath(project);
  }
}

export interface Expected {
  dirs: string[];
  at: number;
  // Set when the approved command has finished: the next check is the last this covers.
  done?: boolean;
  // Another call that could write in these directories may have been running when the user
  // approved: what appears there may be its, so nothing is expected (round 3, finding 36).
  tainted?: boolean;
}

type RemoteUrls = Map<string, { fetch: string[]; push: string[] }>;

interface GitSnapshot {
  // Per git directory: the descriptor that holds its identity (see takeSnapshot).
  held: Map<string, number>;
  // Per checkout root: what `.git` is (directory inode, or pointer file contents).
  entries: { root: string; kind: "dir" | "file" | "link" | "none"; ino?: string; text?: string }[];
  // Nested repositories and pointer files found below the roots: they must not change either.
  nested: { path: string; ino?: string; text?: string }[];
  // Every git directory and pointer file known when the snapshot was taken.
  known: Set<string>;
  // Per git directory: the work trees that lead to it (the directory around a `.git`, and the
  // ones whose `.git` file names it).
  tops: Map<string, Set<string>>;
  // Per git directory: whether it had `commondir` and `config.worktree` (undefined: it could not
  // be looked into), what its `commondir` held, its linked worktrees, and the place a push into
  // it would run hooks from when that is not there (`$GIT_DIR/<relative core.hooksPath>`, by
  // its first missing part).
  inside: Map<string, { commondir: boolean | undefined; commondirText?: string; configWorktree: boolean | undefined; worktrees: string[]; pushHooks?: string }>;
  commonDir: string | undefined;
  // Undefined when git could not tell: nothing is then trusted about remotes.
  remotes: RemoteUrls | undefined;
  // Which of opencode's project-level files existed, in the session directory and the writable
  // directories above it (full paths).
  opencodeFiles: Set<string>;
  // What was inside each `.opencode` there (the plugin makes the session's own, empty), and which
  // hook managers' files were at the top of each checkout: an archive or a patch can drop one in
  // under a name no command line shows (round 3, finding 24).
  opencodeInside: Set<string>;
  hookFiles: Set<string>;
  // The operation state in each git directory and linked worktree's git directory (gitState).
  state: Map<string, Map<string, string>>;
}

function gitEntry(root: string, held?: Map<string, number>): GitSnapshot["entries"][number] {
  const p = path.join(root, ".git");
  try {
    const st = fs.lstatSync(p);
    if (st.isDirectory()) return { root, kind: "dir", ino: statIno(p, held) };
    if (st.isFile()) return { root, kind: "file", text: fs.readFileSync(p, "utf8") };
    // A link named `.git` is a repository too, wherever it points.
    if (st.isSymbolicLink()) return { root, kind: "link", text: fs.readlinkSync(p) };
  } catch (e) {
    if (held && !["ENOENT", "ENOTDIR"].includes((e as NodeJS.ErrnoException).code ?? "")) throw e;
    // no .git
  }
  return { root, kind: "none" };
}

const lines = (text: string) => text.split("\n").filter(Boolean);

// Every URL of every remote. `git remote -v` and a single `get-url` each show one of several.
// `gitDir`: `dir` is a git directory (a submodule's), not a directory git is run in.
function readRemotes(dir: string, gitDir = false): RemoteUrls | undefined {
  const at = gitDir ? inGitDir(dir) : ["-C", dir];
  const names = gitRun([...at, "remote"]);
  if (names.status !== 0) return undefined;
  const out: RemoteUrls = new Map();
  for (const name of lines(names.out)) {
    const fetch = gitRun([...at, "remote", "get-url", "--all", name]);
    const push = gitRun([...at, "remote", "get-url", "--push", "--all", name]);
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

// What the layout check records of a git directory. One this process cannot look into (a nested
// `.git` of another user, closed to this one) has `commondir` and `config.worktree` unknown:
// neither this process nor a sandboxed command can put anything there, the plan asks about a
// sandboxed call that would work there, and it must not stop every decision and every edit
// (round 4, finding 21). What it holds becomes the baseline when it can first be seen.
function insideOf(gitDir: string): GitSnapshot["inside"] extends Map<string, infer V> ? V : never {
  let worktrees: string[] = [];
  try {
    worktrees = fs.readdirSync(path.join(gitDir, "worktrees"));
  } catch {
    // none
  }
  try {
    const files = controlFiles(gitDir);
    return { ...files, ...(files.commondir ? { commondirText: readText(path.join(gitDir, "commondir")) } : {}), worktrees };
  } catch (e) {
    if (!["EACCES", "EPERM"].includes((e as NodeJS.ErrnoException).code ?? "")) throw e;
    return { commondir: undefined, configWorktree: undefined, worktrees };
  }
}

// Whether a control file is there: lstat, so a link that leads nowhere counts. Any error but
// "not there" is thrown, for the caller to say what not knowing means.
function controlExists(file: string): boolean {
  try {
    fs.lstatSync(file);
    return true;
  } catch (e) {
    if (["ENOENT", "ENOTDIR"].includes((e as NodeJS.ErrnoException).code ?? "")) return false;
    throw e;
  }
}
// The two files a git-only call must not plant in a git directory (round 4, finding 21).
function controlFiles(dir: string) {
  return { commondir: controlExists(path.join(dir, "commondir")), configWorktree: controlExists(path.join(dir, "config.worktree")) };
}

// The per-call check of a git-only call (round 4, finding 21, as decided): in each git directory
// the call could write, a `commondir` or `config.worktree` that is there now and was not when
// the call's shell was allowed to start is renamed to a name git never reads, and the session
// pauses, naming both. It runs when the call completes (opencode awaits that hook before the
// result goes back, also for a command moved to the background) and again when the call is
// retired. `only`: the one call to check; without it, every call the session still holds.
// A `config.worktree` that an approved command of any session named (an untainted approval of
// that very file, whose command is still running) is left, and joins the baselines. A lookup or a rename that fails is named in
// the pause.
export function quarantineGitFiles(session: SessionState, sessions: Iterable<SessionState> = [session], only?: GitCall): string | undefined {
  const found: Change[] = [];
  const expectations = [...sessions].flatMap((s) => s.expecting);
  for (const call of only ? [only] : session.gitCalls) {
    for (const [dir, before] of call.before) {
      for (const [name, existed] of [["commondir", before.commondir], ["config.worktree", before.configWorktree]] as const) {
        const source = path.join(dir, name);
        if (existed) continue;
        try {
          if (!controlExists(source)) continue;
        } catch (e) {
          found.push({ path: source, text: `${source} could not be checked: ${(e as Error).message}` });
          continue;
        }
        // An approval whose command has finished explains nothing that appears from then on
        // (it may stand unpruned for as long as its own session is paused).
        const expected = expectations.some((e) => !e.tainted && !e.done && Date.now() - e.at < EXPECT_MS && e.dirs.includes(source));
        if (expected && name === "config.worktree") {
          before.configWorktree = true;
          // The session's own layout check must not report it either.
          const baseline = session.snapshot?.inside.get(dir);
          if (baseline) baseline.configWorktree = true;
          continue;
        }
        const aside = path.join(dir, `automode-quarantine-${name}-${randomUUID()}`);
        try {
          fs.renameSync(source, aside);
          found.push({ path: source, text: `${source} appeared and was moved to ${aside}` });
        } catch (e) {
          found.push({ path: source, text: `${source} appeared but could not be moved to ${aside}: ${(e as Error).message}` });
        }
      }
    }
    // Where a push into the repository would run its hooks from (`$GIT_DIR/<relative
    // core.hooksPath>`): it was not there when the call started, and nothing git does makes it
    // (round 4, finding 21, sixth pass).
    for (const source of call.watch ?? []) {
      try {
        if (!controlExists(source)) continue;
      } catch (e) {
        found.push({ path: source, text: `${source} could not be checked: ${(e as Error).message}` });
        continue;
      }
      const aside = path.join(path.dirname(source), `automode-quarantine-hooks-${randomUUID()}`);
      try {
        fs.renameSync(source, aside);
        found.push({ path: source, text: `${source} appeared (a push into the repository would run hooks from it) and was moved to ${aside}` });
      } catch (e) {
        found.push({ path: source, text: `${source} appeared (a push into the repository would run hooks from it) but could not be moved to ${aside}: ${(e as Error).message}` });
      }
    }
  }
  if (!found.length) return undefined;
  // Named is what was shown, with what it held then (a path that was moved away holds nothing):
  // a plant beyond the five, or one put back where a named one was, is named by the layout
  // check at the resume (seventh pass). What an earlier reason of this pause showed stays named.
  return pause(session, found, session.tampered);
}

// `held`: a descriptor on each git directory, opened with O_PATH, for as long as the snapshot is
// kept. An inode number alone can be given again to a directory made after the first was
// removed (round 4, finding N1); while the descriptor is open it cannot, so device and inode
// number together name the directory that was there at the start.
// `accepted`: whether a `commondir` in a main checkout's git directory is one the user has seen
// (they resumed with it there, holding `text`). git never makes one in such a directory, so any
// other counts as not having been there: the layout check then names it, at the session's start
// as well, and a resume takes it in like every other file (round 4, finding 21).
// `previous`: what the snapshot this one replaces knew of each git directory. A directory that
// cannot be looked into now keeps what was known of it, so that making it unreadable for the
// time of a retake does not turn what is planted there into its baseline (sixth pass).
function takeSnapshot(roots: string[], project: string, scan?: Scan, accepted: (gitDir: string, text: string | undefined) => boolean = () => false, previous?: GitSnapshot["inside"]): GitSnapshot {
  const held = new Map<string, number>();
  try {
    const entries = roots.map((r) => gitEntry(r, held));
    const mainGitDirs = entries.filter((e) => e.kind === "dir").map((e) => realpath(path.join(e.root, ".git")));
    const common = git(project, "rev-parse", "--git-common-dir")?.trim();
    const found = findGitEntries(roots, scan);
    const atRoot = (p: string) => roots.some((r) => p === path.join(r, ".git"));
    // The main checkouts' own, whether or not the walk got to them.
    const gitDirs = [...new Set([...found.gitDirs, ...mainGitDirs])];
    const inside = new Map(gitDirs.map((d) => [d, insideOf(d)]));
    for (const [dir, here] of inside) {
      const was = previous?.get(dir);
      if (!was) continue;
      if (here.commondir === undefined && was.commondir !== undefined) {
        here.commondir = was.commondir;
        here.commondirText = was.commondirText;
      }
      here.configWorktree ??= was.configWorktree;
    }
    for (const dir of mainGitDirs) {
      const here = inside.get(dir)!;
      if (here.commondir && !accepted(dir, here.commondirText)) here.commondir = false;
    }
    for (const [dir, missing] of pushHooksMissing(gitDirs, found.tops)) inside.get(dir)!.pushHooks = missing;
    const nested = [
      ...[...found.gitDirs].filter((d) => !mainGitDirs.includes(d)).map((d) => ({ path: d, ino: statIno(d, held) })),
      ...[...found.pointers].filter((p) => !atRoot(p)).map((p) => ({ path: p, text: readText(p) })),
      ...[...found.links].filter((p) => !atRoot(p)).map((p) => ({ path: p, text: readLink(p) })),
    ];
    const snapshot: GitSnapshot = {
      held,
      entries,
      nested,
      known: new Set([...found.gitDirs, ...found.pointers, ...found.links]),
      tops: found.tops,
      inside,
      commonDir: common ? realpath(path.resolve(project, common)) : undefined,
      remotes: readRemotes(project),
      opencodeFiles: new Set(opencodeFiles(project, roots).filter(lexists)),
      opencodeInside: new Set(opencodeInside(project, roots)),
      hookFiles: new Set(hookFiles(roots, found)),
      state: new Map(gitDirs.flatMap((d) => [...gitState(d)])),
    };
    snapshotCleanup.register(snapshot, held);
    return snapshot;
  } catch (e) {
    // A snapshot that could not be finished holds nothing open.
    for (const fd of held.values()) fs.closeSync(fd);
    throw e;
  }
}

// A snapshot nobody holds any more (its session was dropped without closeGitSnapshot) gives its
// descriptors back when it is collected.
const snapshotCleanup = new FinalizationRegistry<Map<string, number>>((held) => {
  for (const fd of held.values()) fs.closeSync(fd);
  held.clear();
});

// The state git keeps at the top of a git directory while a rebase, merge, cherry-pick, revert,
// am or bisect is under way (git 2.47: builtin/rebase.c, merge.c, sequencer.c, am.c, bisect.c,
// merge-ort.c), and which subcommands of a git-only call leave each of them. A stopped
// operation is finished later by the user's own git, outside the sandbox: `git rebase
// --continue` runs the `exec` lines of the todo list it finds (round 3, finding 33). `pull`
// merges or rebases; `stash pop`/`apply` and `checkout -m` leave only `AUTO_MERGE` (probed).
const GIT_STATE = /^(rebase-merge|rebase-apply|sequencer|MERGE_HEAD|MERGE_MSG|MERGE_MODE|MERGE_AUTOSTASH|SQUASH_MSG|AUTO_MERGE|REBASE_HEAD|CHERRY_PICK_HEAD|REVERT_HEAD|BISECT_\w+)$/;
const GIT_STATE_BY: Record<string, RegExp> = {
  rebase: /^(rebase-merge|rebase-apply|REBASE_HEAD|MERGE_MSG|AUTO_MERGE)$/,
  pull: /^(rebase-merge|rebase-apply|REBASE_HEAD|MERGE_HEAD|MERGE_MSG|MERGE_MODE|MERGE_AUTOSTASH|SQUASH_MSG|AUTO_MERGE)$/,
  merge: /^(MERGE_HEAD|MERGE_MSG|MERGE_MODE|MERGE_AUTOSTASH|SQUASH_MSG|AUTO_MERGE)$/,
  "cherry-pick": /^(CHERRY_PICK_HEAD|sequencer|MERGE_MSG|AUTO_MERGE)$/,
  revert: /^(REVERT_HEAD|sequencer|MERGE_MSG|AUTO_MERGE)$/,
  am: /^(rebase-apply|AUTO_MERGE)$/,
  bisect: /^BISECT_\w+$/,
  stash: /^AUTO_MERGE$/,
  checkout: /^AUTO_MERGE$/,
  switch: /^AUTO_MERGE$/,
};
// The todo lists a continued operation acts on, and the subcommands that may change them.
const GIT_TODO: Record<string, string[]> = { "rebase-merge/git-rebase-todo": ["rebase", "pull"], "sequencer/todo": ["cherry-pick", "revert"] };
// The commands of a rebase todo list that run a program: `exec`/`x`. A git-only call cannot add
// one (`rebase -x`, `-i` and `--exec` are not git-only), whatever its subcommands.
const execLines = (todo: string | undefined) => (todo ?? "").split("\n").map((l) => l.trim()).filter((l) => /^(exec|x)\s/.test(l));

// The operation state in a git directory and in each linked worktree's git directory below it:
// per directory, each state name present ("" for a file, "dir" for a directory) and the text
// of each todo list.
function gitState(gitDir: string): Map<string, Map<string, string>> {
  const out = new Map<string, Map<string, string>>();
  const read = (dir: string) => {
    let list: fs.Dirent[];
    try {
      list = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    const here = new Map<string, string>();
    for (const e of list) if (GIT_STATE.test(e.name)) here.set(e.name, e.isDirectory() ? "dir" : "");
    for (const todo of Object.keys(GIT_TODO)) {
      const text = readText(path.join(dir, todo));
      if (text !== undefined) here.set(todo, text);
    }
    out.set(dir, here);
  };
  read(gitDir);
  let worktrees: string[] = [];
  try {
    worktrees = fs.readdirSync(path.join(gitDir, "worktrees"));
  } catch {
    // none
  }
  for (const wt of worktrees) read(path.join(gitDir, "worktrees", wt));
  return out;
}

// Operation state that appeared or a todo list that changed since the last check, which none of
// the git-only calls that ran meanwhile explains. With no such call, nothing sandboxed could write
// a git directory (it is read-only to every other call): what changed is the user's own, or an
// approved command's. Either way, what is there now is the baseline for the next check.
function stateChanges(session: SessionState): Change[] {
  const snap = session.snapshot!;
  const calls = session.gitCalls;
  session.gitCalls = calls.filter((c) => !c.done);
  const by = (name: string) => calls.some((c) => (GIT_TODO[name] ? GIT_TODO[name].some((sub) => c.subs.has(sub)) : [...c.subs].some((sub) => GIT_STATE_BY[sub]?.test(name))));
  const out: Change[] = [];
  const now = new Map([...snap.inside.keys()].flatMap((d) => [...gitState(d)]));
  for (const [dir, here] of now) {
    const before = snap.state.get(dir) ?? new Map<string, string>();
    if (!calls.length) continue;
    for (const [name, value] of here) {
      const was = before.get(name);
      const p = path.join(dir, name);
      if (was === undefined && !by(name)) out.push({ path: p, key: `${p}\0appeared`, text: `${p} appeared (git state that the git commands which ran do not leave)` });
      else if (was !== undefined && was !== value && GIT_TODO[name] && !by(name)) out.push({ path: p, key: `${p}\0changed`, text: `${p} changed (a todo list that the git commands which ran do not change)` });
      if (name === "rebase-merge/git-rebase-todo") {
        const known = new Set(execLines(was));
        const added = execLines(value).filter((l) => !known.has(l));
        if (added.length) out.push({ path: p, key: `${p}\0exec`, text: `${p} gained an exec line (${JSON.stringify(added[0].slice(0, 80))}), which \`git rebase --continue\` would run` });
      }
    }
  }
  // What is there now is what the next check compares with; what was found is kept until a
  // pause has shown it and the user has resumed (seventh pass: with more than five things, or
  // found while the session was paused already, it joined the baseline unnamed).
  snap.state = now;
  for (const c of out) session.pendingState.set(c.key ?? c.path, c);
  return out;
}
// The operation state that no resumed pause has shown yet, as far as it is still there.
function unnamedState(session: SessionState): Change[] {
  for (const [key, c] of session.pendingState) if (!lexists(c.path)) session.pendingState.delete(key);
  return [...session.pendingState.values()];
}

// The operation-state check alone, for when a git-only call is over: it reads only the git
// directories already known, so it walks nothing. Pauses the session as gitTampered does.
export function gitStateTampered(session: SessionState): string | undefined {
  if (!session.snapshot) {
    session.gitCalls = session.gitCalls.filter((c) => !c.done);
    return session.tampered?.reason;
  }
  // Paused already: compared all the same, while the record of the call that is over still
  // says what it could have left. What is found is named when the user resumes (seventh pass).
  stateChanges(session);
  if (session.tampered) return session.tampered.reason;
  const found = unnamedState(session);
  return found.length ? pause(session, found) : undefined;
}
// What a prompt shows of a list: the first five.
const SHOWN = 5;
const shown = (found: string[]) => found.slice(0, SHOWN).join("; ") + (found.length > SHOWN ? `; and ${found.length - SHOWN} more` : "");
// One thing the checks found, with the path it is about. `key`: what a pause names it by, where
// several things can be said of one path (operation state); the path otherwise.
interface Change {
  path: string;
  text: string;
  key?: string;
}
// What a path holds, as far as a resume must find it unchanged to take it in: a file's contents,
// a link's target, and for a directory which directory it is and everything in it that git reads
// or runs (eighth pass: by identity and four control files alone, a `hooks/pre-push` or a
// `git-rebase-todo` with an `exec` line added between the prompt and the touch joined the
// baseline unseen). That is its tree of names, each entry with its kind, mode, size, inode and
// change time (a link with its target), and the contents of every file up to `fileBytes` outside
// an object store (the hooks, `config`, `HEAD`, todo lists, `info/`, refs; an object's name is
// its contents' hash, and its size and change time are compared all the same). "missing": not
// there.
//
// The bound: `entries` entries of the tree, read top down (a directory's entries by name, the
// directories below in the order they were met) with every `objects` directory last, so that
// what git runs or takes its settings from comes first; and `bytes` of file contents in all.
// A directory with more entries is compared by its first `entries` only (`over`): the pause says
// so in its prompt (pause), and the session resumes like any other once what was compared is as
// it was shown. What lies past the bound is then taken in uncompared, as the prompt said.
export const fingerprintLimits = { entries: 20_000, fileBytes: 64 * 1024, bytes: 16 << 20 };
function fingerprint(p: string): { held: string; over?: number } {
  try {
    const st = fs.lstatSync(p, { bigint: true });
    if (st.isSymbolicLink()) return { held: `link:${fs.readlinkSync(p)}` };
    if (st.isFile()) {
      try {
        return { held: `file:${createHash("sha256").update(fs.readFileSync(p)).digest("hex")}` };
      } catch {
        // Closed to this process: known by which file it is and when it last changed.
        return { held: `file:unreadable:${st.dev}:${st.ino}:${st.size}:${st.mtimeNs}:${st.ctimeNs}` };
      }
    }
    if (!st.isDirectory()) return { held: `other:${st.dev}:${st.ino}` };
    const tree = treeHeld(p);
    return { held: `dir:${st.dev}:${st.ino}:${tree.digest}${tree.over ? `:first-${tree.over}` : ""}`, ...(tree.over ? { over: tree.over } : {}) };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "";
    return { held: ["ENOENT", "ENOTDIR"].includes(code) ? "missing" : `unknown:${code}` };
  }
}
// The tree below a directory, as one digest (see fingerprint). `over`: the bound, where the tree
// has more entries than that.
function treeHeld(root: string): { digest: string; over?: number } {
  const limit = fingerprintLimits.entries;
  const hash = createHash("sha256");
  const next: string[] = [""];
  const stores: string[] = [];
  let entries = 0;
  let bytes = 0;
  let over = false;
  const errno = (e: unknown) => (e as NodeJS.ErrnoException).code ?? "";
  while ((next.length || stores.length) && !over) {
    const rel = next.length ? next.shift()! : stores.shift()!;
    let names: string[];
    try {
      names = fs.readdirSync(path.join(root, rel)).sort();
    } catch (e) {
      // Closed to this process, or gone since it was listed: said, and compared as that.
      hash.update(`${rel}\0unlisted:${errno(e)}\0`);
      continue;
    }
    for (const name of names) {
      if (entries >= limit) {
        over = true;
        break;
      }
      entries++;
      const at = rel ? `${rel}/${name}` : name;
      const full = path.join(root, at);
      let line: string;
      try {
        const st = fs.lstatSync(full, { bigint: true });
        if (st.isSymbolicLink()) line = `link:${fs.readlinkSync(full)}`;
        else if (st.isDirectory()) {
          line = `dir:${st.mode}`;
          (name === "objects" ? stores : next).push(at);
        } else if (st.isFile()) {
          line = `file:${st.mode}:${st.size}:${st.ino}:${st.ctimeNs}`;
          const size = Number(st.size);
          if (size <= fingerprintLimits.fileBytes && bytes + size <= fingerprintLimits.bytes && !/(^|\/)objects\//.test(at)) {
            bytes += size;
            try {
              line += `:${createHash("sha256").update(fs.readFileSync(full)).digest("hex")}`;
            } catch (e) {
              line += `:unread:${errno(e)}`;
            }
          }
        } else line = `other:${st.mode}:${st.ino}`;
      } catch (e) {
        line = `unknown:${errno(e)}`;
      }
      hash.update(`${at}\0${line}\0`);
    }
  }
  return { digest: hash.digest("hex"), ...(over ? { over: limit } : {}) };
}
// Pauses the session for what was found. The pause names what its reason shows, each with what
// its path holds now (`also`: the pause this one follows; what that named and still holds
// stays named). A named directory too large to compare whole is said to be, with how much of it
// is compared at the resume (fingerprint).
function pause(session: SessionState, found: Change[], also?: SessionState["tampered"]): string {
  const first = found.slice(0, SHOWN);
  const prints = first.map((c) => fingerprint(c.path));
  const partly = [...new Set(first.flatMap((c, n) => (prints[n].over ? [`${c.path} holds more than ${prints[n].over} entries: only the first ${prints[n].over} of them (its hooks, config and refs before its object store) are compared with what is there when you resume`] : [])))];
  const reason = shown(found.map((c) => c.text)) + (partly.length ? `. ${partly.join("; ")}` : "");
  const named = [...new Set([...(also?.named ?? []), ...first.map((c) => c.key ?? c.path)])];
  const held = { ...(also?.held ?? {}), ...Object.fromEntries(first.map((c, n) => [c.key ?? c.path, prints[n].held])) };
  session.tampered = { reason, at: Date.now(), named, held };
  return reason;
}
// What a pause named that still holds what it held when it was shown (a key is a path, or a path
// and what was said of it).
function stillNamed(paused: NonNullable<SessionState["tampered"]>): Set<string> {
  return new Set((paused.named ?? []).filter((key) => paused.held === undefined || paused.held[key] === fingerprint(key.split("\0")[0]).held));
}

// Everything inside the `.opencode` directories opencode loads from, at any depth (bounded).
function opencodeInside(project: string, roots: string[]): string[] {
  const out: string[] = [];
  const visit = (dir: string, depth: number) => {
    let list: fs.Dirent[];
    try {
      list = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of list) {
      if (out.length > 5000) return;
      const p = path.join(dir, e.name);
      out.push(p);
      if (e.isDirectory() && depth < 8) visit(p, depth + 1);
    }
  };
  for (const dir of opencodeDirs(project, roots.map(realpath))) visit(path.join(dir, ".opencode"), 0);
  return out;
}
// The hook managers' files at the top of each checkout: the project's roots and every repository
// found below them.
function hookFiles(roots: string[], found: ReturnType<typeof findGitEntries>): string[] {
  const tops = new Set([...roots.map(realpath), ...[...found.tops.values()].flatMap((t) => [...t])]);
  return [...tops].flatMap((top) => HOOK_MANAGER_FILES.map((name) => path.join(top, name))).filter(lexists);
}

const lexists = (p: string) => {
  try {
    fs.lstatSync(p);
    return true;
  } catch {
    return false;
  }
};
// Every place opencode would load a project-level file from: the session directory and each
// writable directory above it (a session can start in a subdirectory of the checkout).
const opencodeFiles = (project: string, roots: string[]) => opencodeDirs(project, roots.map(realpath)).flatMap((dir) => OPENCODE_PROJECT_FILES.map((f) => path.join(dir, f)));

function readLink(p: string): string | undefined {
  try {
    return fs.readlinkSync(p);
  } catch {
    return undefined;
  }
}

// Linux's O_PATH (0x200000 on x86-64, arm64 and riscv): it needs no read permission on the
// directory, and fstat works on it. Node does not name it everywhere.
const O_PATH = 0x200000;

// What tells one directory from another: device and inode number. With `held`, of a descriptor
// that is opened here and kept (see takeSnapshot); without, of the path as it is now, a link
// not followed. "missing": not there. Undefined: it cannot be told.
function statIno(p: string, held?: Map<string, number>): string | undefined {
  try {
    if (held && !held.has(p)) held.set(p, fs.openSync(p, O_PATH | fs.constants.O_DIRECTORY | fs.constants.O_NOFOLLOW));
    const st = held ? fs.fstatSync(held.get(p)!, { bigint: true }) : fs.lstatSync(p, { bigint: true });
    return `${st.dev}:${st.ino}`;
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return "missing";
    if (held) throw new Error(`cannot hold git directory identity: ${p}`);
    return undefined;
  }
}

// Closes the descriptors a session's snapshot holds: when the snapshot is replaced, and when
// the plugin is disposed of.
export function closeGitSnapshot(session: SessionState): void {
  for (const fd of session.snapshot?.held.values() ?? []) fs.closeSync(fd);
  session.snapshot?.held.clear();
}

function readText(p: string): string | undefined {
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    return undefined;
  }
}

// What changed in the project's git layout since the snapshot. `replaced` lists changes git never
// makes on its own; `appeared` lists new repositories, worktrees and config files with where
// they are: fine inside a directory an approved command named, tampering anywhere else.
interface Appeared {
  path: string;
  text: string;
  // opencode's own files are never explained by a git command.
  opencode?: boolean;
  // Explained only by an approval that names this very path, not by one of a directory above
  // it: a `config.worktree` (`git worktree add` and `git submodule` name the whole common
  // directory, and neither writes that file into a directory that was already there).
  exact?: boolean;
}
function layoutChanges(session: SessionState, scan?: Scan): { replaced: Change[]; appeared: Appeared[] } {
  const snap = session.snapshot!;
  const replaced: Change[] = [];
  const appeared: Appeared[] = [];
  for (const before of snap.entries) {
    const now = gitEntry(before.root);
    const p = path.join(before.root, ".git");
    if (before.kind === "none" && now.kind !== "none") appeared.push({ path: p, text: `${p} appeared${now.kind === "link" ? " (a symbolic link)" : ""}` });
    else if (now.kind !== before.kind || now.ino !== before.ino || now.text !== before.text) replaced.push({ path: p, text: `${p} was replaced or rewritten` });
  }
  // A nested repository that is gone was deleted, which plants nothing: forget it. One that is
  // there but different was swapped.
  snap.nested = snap.nested.filter((before) => {
    if (before.ino === "missing" && !lexists(before.path)) return true;
    // The target of a pointer file that was not there and is now: an appearance, which an
    // approved command can explain.
    if (before.ino === "missing") {
      appeared.push({ path: before.path, text: `${before.path} appeared` });
      return true;
    }
    if (!lexists(before.path)) return snap.known.delete(before.path), false;
    const same = before.ino !== undefined ? statIno(before.path) === before.ino : (readText(before.path) ?? readLink(before.path)) === before.text;
    if (!same) replaced.push({ path: before.path, text: `${before.path} was replaced, moved or rewritten` });
    return true;
  });
  const roots = session.roots ?? [];
  const found = findGitEntries(roots, scan);
  for (const p of [...found.gitDirs, ...found.pointers, ...found.links]) {
    if (!snap.known.has(p) && !roots.some((r) => p === path.join(r, ".git") || p === realpath(path.join(r, ".git")))) appeared.push({ path: p, text: `${p} appeared${found.links.has(p) ? " (a symbolic link named .git)" : ""}` });
  }
  const mains = new Set(snap.entries.filter((e) => e.kind === "dir").map((e) => realpath(path.join(e.root, ".git"))));
  for (const [dir, before] of snap.inside) {
    if (!fs.existsSync(dir)) continue;
    const now = insideOf(dir);
    const file = path.join(dir, "commondir");
    // In a main checkout's git directory too: its baseline is "none" until the user has seen
    // one and resumed (takeSnapshot), also where the directory could not be looked into when
    // the snapshot was taken (git never makes one there, so it is no baseline when first seen).
    if (now.commondir && before.commondir === undefined && mains.has(dir)) before.commondir = false;
    if (now.commondir && before.commondir === false) replaced.push({ path: file, text: `${file} appeared` });
    // One that was there is known by what it holds (sixth pass): pointed elsewhere, it is named.
    else if (now.commondir && before.commondir === true && now.commondirText !== before.commondirText) replaced.push({ path: file, text: `${file} was rewritten` });
    // And one that went is new when it comes back.
    if (now.commondir === false && before.commondir === true) {
      before.commondir = false;
      before.commondirText = undefined;
    }
    // Only an approved command that names this very file explains it (round 4, finding 21).
    if (now.configWorktree && before.configWorktree === false) appeared.push({ path: path.join(dir, "config.worktree"), text: `${path.join(dir, "config.worktree")} appeared`, exact: true });
    // A directory seen into for the first time: what it holds is its baseline.
    if (before.commondir === undefined && now.commondir !== undefined) {
      before.commondir = now.commondir;
      before.commondirText = now.commondirText;
    }
    before.configWorktree ??= now.configWorktree;
    // Where a push into the repository would run hooks from, which was not there (sixth pass).
    if (before.pushHooks && lexists(before.pushHooks)) replaced.push({ path: before.pushHooks, text: `${before.pushHooks} appeared (a push into the repository would run hooks from it)` });
    for (const wt of now.worktrees) if (!before.worktrees.includes(wt)) appeared.push({ path: path.join(dir, "worktrees", wt), text: `${path.join(dir, "worktrees", wt)} appeared (a new linked worktree)` });
  }
  // `.opencode` in the session directory is left out: the plugin creates it empty so that it
  // can be made read-only.
  for (const p of opencodeFiles(session.project, roots)) {
    if (p !== path.join(session.project, ".opencode") && !snap.opencodeFiles.has(p) && lexists(p)) appeared.push({ path: p, text: `${p} appeared (opencode loads it without asking)`, opencode: true });
  }
  for (const p of opencodeInside(session.project, roots)) {
    if (!snap.opencodeInside.has(p)) appeared.push({ path: p, text: `${p} appeared (opencode loads it without asking)`, opencode: true });
  }
  // A hook manager's file at the top of a checkout: a git hook hands control to it. One inside a
  // directory an approved clone or submodule named is that repository's own.
  // (Not the directory a plan made to protect a relative core.hooksPath, `.husky` around
  // `.husky/_`: the plugin's own, empty, and read-only to every call from then on.)
  for (const p of hookFiles(roots, found)) {
    if (!snap.hookFiles.has(p) && !madeByPlan(p)) appeared.push({ path: p, text: `${p} appeared (a git hook hands control to it)` });
  }
  // A path is listed once, with the last thing said of it (a linked worktree's admin directory
  // is found as a git directory and as a new worktree): a pause shows five things (seventh pass).
  const once = new Map<string, Appeared>();
  for (const a of appeared) once.set(a.path, { ...once.get(a.path), ...a });
  return { replaced, appeared: [...once.values()] };
}

// Whether the project's git layout changed since the session started in a way git never does on
// its own: `.git` replaced or renamed, a pointer file rewritten, `commondir` planted, a
// repository, worktree or opencode config file appearing that no approved command explains, or
// operation state that the git-only calls which ran do not leave (stateChanges).
// Returns what was found, so the prompt can say it. The pause lasts until `resumeFile` is touched.
// `scan`: the walks of the decision this check is part of (round 3, finding 40).
export function gitTampered(session: SessionState, resumeFile?: string, scan?: Scan): string | undefined {
  const paused = session.tampered;
  let resumed = 0;
  if (paused) {
    try {
      resumed = resumeFile ? fs.statSync(resumeFile).mtimeMs : 0;
    } catch {
      // not resumed
    }
    if (resumed <= paused.at) return paused.reason;
    // A session that was paused before it had seen the project (another session's finding
    // paused every session, index.ts pauseAll; or its snapshot could not be taken) has nothing
    // of its own to compare with. It starts as a new session does, here: its baseline is what
    // is there, except what git never makes (a `commondir` in a main checkout), which the
    // comparison below names unless the pause named it as it is (seventh pass).
    if (!session.snapshot) projectRoots(session, scan);
    if (!session.snapshot) {
      // A project at the home directory or above: nothing is watched there.
      session.tampered = undefined;
      return undefined;
    }
  }
  if (!session.snapshot) return undefined;
  const { replaced, appeared } = layoutChanges(session, scan);
  stateChanges(session);
  const states = unnamedState(session);
  // What an approved command named is expected while that command runs, and at the first check
  // after it has finished. An approval lasts ten minutes at most.
  const expecting = session.expecting.filter((e) => Date.now() - e.at < EXPECT_MS);
  session.expecting = expecting.filter((e) => !e.done);
  const expected = (a: Appeared) => !a.opencode && expecting.some((e) => !e.tainted && (a.exact ? e.dirs.includes(a.path) : e.dirs.some((dir) => within(a.path, dir))));
  const found: Change[] = [...replaced, ...states, ...appeared.filter((a) => !expected(a))];
  const seen = session.snapshot.inside;
  if (paused) {
    // The user looked and resumed. What the pause named joins the baseline; whatever else
    // changed since is something nobody was shown, and is named before it is taken in (round 4,
    // finding 21, sixth pass). That is a new pause, resumed like the first.
    // Named is a path with what it held: one that holds something else by now was not shown as
    // it is, and is named again (seventh pass).
    const named = stillNamed(paused);
    const fresh = found.filter((c) => !named.has(c.key ?? c.path));
    if (fresh.length) {
      const reason = pause(session, fresh, { ...paused, named: [...named] });
      // Not resumed by the touch that brought it up, whatever the clocks' resolution.
      session.tampered!.at = Math.max(session.tampered!.at, Math.ceil(resumed));
      return reason;
    }
    const next = takeSnapshot(session.roots ?? [], session.project, scan, (dir) => named.has(path.join(dir, "commondir")) || seen.get(dir)?.commondir === true, seen);
    closeGitSnapshot(session);
    session.snapshot = next;
    session.tampered = undefined;
    session.pendingState.clear();
    return undefined;
  }
  if (found.length) return pause(session, found);
  if (appeared.length) {
    // A new worktree of the project joins it when the approved command named its directory and
    // it lies inside the folder that holds the main checkout.
    const now = checkouts(session.project);
    const parent = path.dirname(now[0] ?? "/");
    for (const dir of now) {
      if (session.roots && !session.roots.includes(dir) && !isRootLike(parent) && within(dir, parent) && expecting.some((e) => !e.tainted && e.dirs.some((d) => within(dir, d)))) session.roots.push(dir);
    }
    // An accepted `commondir` stays accepted for as long as it holds what it held.
    const next = takeSnapshot(session.roots ?? [], session.project, scan, (dir, text) => seen.get(dir)?.commondir === true && seen.get(dir)?.commondirText === text, seen);
    closeGitSnapshot(session);
    session.snapshot = next;
  }
  return undefined;
}
export const EXPECT_MS = 600_000;

const pauseReason = (found: string, resumeFile?: string) =>
  `auto-allow paused for this session: ${found}. Check what is there; approving this prompt does not resume.${resumeFile ? ` To resume, run \`touch ${resumeFile}\` in your own terminal.` : ""}`;

// The options of the git commands that create a repository, from git's documentation (2.47):
// those that take a value (the next word, or attached: `--depth=1`, `-bmain`), those that take
// none, and those whose value can only be attached (`--recurse-submodules=x`). An option outside
// these, or a shortened long option, means the place cannot be told: nothing is expected, and
// what appears pauses the session.
interface OptionTable {
  values: string[];
  flags: string[];
  attached?: string[];
}
const CREATE_OPTIONS: Record<string, OptionTable> = {
  clone: {
    values: ["-o", "--origin", "-b", "--branch", "--reference", "--reference-if-able", "--depth", "--shallow-since", "--shallow-exclude", "-j", "--jobs", "-c", "--config", "--template", "--filter", "--server-option", "--bundle-uri", "--ref-format", "--revision"],
    flags: ["-l", "--local", "--no-local", "--no-hardlinks", "-s", "--shared", "--dissociate", "-q", "--quiet", "-v", "--verbose", "--progress", "--no-progress", "-n", "--no-checkout", "--bare", "--mirror", "--sparse", "--reject-shallow", "--no-reject-shallow", "--single-branch", "--no-single-branch", "--tags", "--no-tags", "--shallow-submodules", "--no-shallow-submodules", "--remote-submodules", "--no-remote-submodules", "--also-filter-submodules", "--recurse-submodules", "--recursive"],
    attached: ["--recurse-submodules", "--recursive"],
  },
  init: {
    values: ["--template", "--object-format", "--ref-format", "-b", "--initial-branch"],
    flags: ["-q", "--quiet", "--bare", "--shared"],
    attached: ["--shared"],
  },
  "worktree add": {
    values: ["--reason", "-b", "-B"],
    flags: ["-f", "--force", "--detach", "--checkout", "--no-checkout", "--lock", "--orphan", "--track", "--no-track", "--guess-remote", "--no-guess-remote", "-q", "--quiet"],
  },
  "submodule add": {
    values: ["-b", "--branch", "--name", "--reference", "--ref-format", "--depth"],
    flags: ["-f", "--force", "-q", "--quiet"],
  },
};
// The operands of `words` under `table`, and the options seen (by their full name); undefined
// for an option that is not in it.
function gitOperands(words: string[], table: OptionTable): { operands: string[]; seen: Set<string> } | undefined {
  const operands: string[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (w === "--") {
      operands.push(...words.slice(i + 1));
      break;
    }
    if (!w.startsWith("-") || w === "-") {
      operands.push(w);
      continue;
    }
    if (w.startsWith("--")) {
      const eq = w.indexOf("=");
      const name = eq < 0 ? w : w.slice(0, eq);
      if (table.values.includes(name)) {
        if (eq < 0) i++;
      } else if (!table.flags.includes(name) || (eq >= 0 && !table.attached?.includes(name))) return undefined;
      seen.add(name);
      continue;
    }
    // A cluster of short options: a value option takes the rest of the word, or the next word.
    for (let k = 1; k < w.length; k++) {
      const name = `-${w[k]}`;
      seen.add(name);
      if (table.values.includes(name)) {
        if (k === w.length - 1) i++;
        break;
      }
      if (!table.flags.includes(name)) return undefined;
    }
  }
  return { operands, seen };
}

// The directory git names after a repository URL or path (dir.c, git_url_basename): the last
// component after the scheme and any `user@`, without trailing slashes or blanks, a trailing
// `/.git`, a `:port` on a bare host, and the `.git` (`.bundle` for a bundle) suffix; `.git` added
// for a bare clone; control characters and runs of blanks made one space. Undefined where git
// would give up.
export function urlBasename(repo: string, isBundle: boolean, isBare: boolean): string | undefined {
  const sep = (c: string | undefined) => c === "/";
  const space = (c: string | undefined) => c !== undefined && " \t\n\v\f\r".includes(c);
  let start = repo.indexOf("://");
  start = start < 0 ? 0 : start + 3;
  let end = repo.length;
  for (let p = start; p < end && !sep(repo[p]); p++) if (repo[p] === "@") start = p + 1;
  while (start < end && (sep(repo[end - 1]) || space(repo[end - 1]))) end--;
  if (end - start > 5 && sep(repo[end - 5]) && repo.slice(end - 4, end) === ".git") {
    end -= 5;
    while (start < end && sep(repo[end - 1])) end--;
  }
  if (end - start < 0) return undefined;
  const part = repo.slice(start, end);
  if (!part.includes("/") && part.includes(":")) {
    let p = end;
    while (start < p && /[0-9]/.test(repo[p - 1])) p--;
    if (start < p && repo[p - 1] === ":") end = p - 1;
  }
  let p = end;
  while (start < p && !sep(repo[p - 1]) && repo[p - 1] !== ":") p--;
  let name = repo.slice(p, end);
  const suffix = isBundle ? ".bundle" : ".git";
  if (name.endsWith(suffix)) name = name.slice(0, -suffix.length);
  if (!name || name === "/") return undefined;
  if (isBare) name += ".git";
  let out = "";
  let prevSpace = true;
  for (let ch of name) {
    if (ch < "\x20") ch = " ";
    if (space(ch)) {
      if (prevSpace) continue;
      prevSpace = true;
    } else prevSpace = false;
    out += ch;
  }
  if (out && prevSpace) out = out.slice(0, -1);
  return out || undefined;
}

// Whether git reads `repo`, from `base`, as a bundle file (builtin/clone.c, get_repo_path).
function isBundleFile(base: string, repo: string): boolean {
  if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(repo)) return false;
  const p = path.resolve(base, tilde(repo));
  for (const suffix of ["/.git", "", ".git/.git", ".git"]) {
    try {
      if (fs.statSync(p + suffix).isDirectory()) return false;
    } catch {
      // not there
    }
  }
  return [".bundle", ""].some((suffix) => {
    try {
      return fs.statSync(p + suffix).isFile();
    } catch {
      return false;
    }
  });
}

// Where a command the user is asked about would create repositories or worktrees: the
// directories its `git init`, `clone`, `worktree add` and `submodule` calls name, read from
// plain words only, with the values of their options skipped and the default directory of a
// clone or submodule named as git names it (round 3, finding 15). Undefined when it creates none,
// or is not written in plain words, or uses an option the tables above do not know, or one that
// puts the repository elsewhere (`--separate-git-dir`): what then appears pauses the session,
// and the user resumes it.
export function expectedRepos(command: string, cwd: string): string[] | undefined {
  // Round 4, finding 10: read on lines, as the git-only check reads (a command that ends in a
  // newline recorded nothing, and the approved clone paused the session). Globs and assignments
  // are not taken: a glob could name the directory, and nothing here needs an editor set.
  const cmds = strictCommands(command, { nullRedirects: true, newlines: true, bang: true });
  // A `~` bash expands differently from `tilde()` would name the wrong place.
  if (!cmds || cmds.some((c) => c.quotedTilde)) return undefined;
  const dirs: string[] = [];
  // Where each command runs, as bash goes there (guard.ts, `located`), and git's `-C` words
  // from there, each a chdir (seventh pass). One that may be in several directories names them
  // all. A git command whose directory cannot be told there names nothing, with one exception:
  // a directory that is not there yet, which an earlier command of the call is to make
  // (`mkdir x`, `cd x`, `git init`). No link can lie in what does not exist, so the place is the
  // one the words spell, each `cd` and `-C` joined to the one before as bash joins them (`made`).
  // A `cd` that is not one plain word naming a directory spells no place: `cd -` leads where the
  // shell was last, and `-` is not a name (eighth pass: an approved `cd sub && cd - && git init`
  // expected `sub/-`, and what was planted there during the approval was explained by it);
  // `~user` and an option likewise. From there on nothing is spelled until a `cd` to a full path.
  const where = located(command, cwd);
  const placed = placedCommands(where, cmds.map((c) => c.argv));
  let spelled: string | undefined = cwd;
  for (const [n, { argv }] of cmds.entries()) {
    if (argv[0] === "cd") {
      const word = argv.length === 1 ? "~" : argv.length === 2 ? argv[1] : undefined;
      spelled = word === undefined || /^(-|~[^/])/.test(word) || word === "" || (spelled === undefined && !path.isAbsolute(tilde(word))) ? undefined : path.resolve(spelled ?? "/", tilde(word));
    }
    if (argv[0] !== "git") continue;
    const call = gitCall(argv.slice(1));
    if (typeof call === "string") continue;
    const cmd = placed[n];
    const places = cmd && where.places.get(cmd);
    const bases = new Set<string>();
    for (const place of places ?? []) {
      let at: Place | undefined = place;
      for (const d of call.dirs) at = at && chdirTo(at, d);
      if (at) bases.add(at.real);
      else bases.clear();
      if (!at) break;
    }
    const made = spelled === undefined ? undefined : call.dirs.reduce((at, d) => path.resolve(at, tilde(d)), spelled);
    if (!bases.size && made !== undefined && !lexists(made)) bases.add(made);
    for (const base of bases) {
      // The repository's own git directory gets `worktrees/<name>` and `modules/<name>`.
      const common = () => {
        const out = safeGit(["-C", base, "rev-parse", "--git-common-dir"])?.trim();
        return out ? [realish(path.resolve(base, out))] : [];
      };
      const named = (p: string) => realish(path.resolve(base, tilde(p)));
      if (call.sub === "sparse-checkout" || (call.sub === "config" && call.rest.includes("--worktree"))) {
        const gd = safeGit(["-C", base, "rev-parse", "--absolute-git-dir"])?.trim();
        // By its real path, as the checks that look for the file name it.
        if (gd) dirs.push(path.join(realish(gd), "config.worktree"));
        continue;
      }
      // `git submodule` and `git worktree` take `--quiet` before their own subcommand.
      let rest = call.rest;
      let sub = call.sub ?? "";
      if (sub === "submodule" || sub === "worktree") {
        const at = rest.findIndex((w) => !/^(-q|--quiet)$/.test(w));
        if (at < 0) continue;
        if (rest[at].startsWith("-")) return undefined;
        sub = `${sub} ${rest[at]}`;
        rest = rest.slice(at + 1);
      }
      const table = CREATE_OPTIONS[sub];
      if (table) {
        const read = gitOperands(rest, table);
        if (!read || read.seen.has("--separate-git-dir")) return undefined;
        const [first, second] = read.operands;
        const bare = read.seen.has("--bare") || read.seen.has("--mirror");
        if (sub === "init") dirs.push(named(first ?? "."));
        else if (sub === "clone" && first !== undefined) {
          const guessed = second ?? urlBasename(first, isBundleFile(base, first), bare);
          if (guessed === undefined) return undefined;
          dirs.push(named(guessed));
        } else if (sub === "worktree add" && first !== undefined) dirs.push(named(first), ...common());
        else if (sub === "submodule add" && first !== undefined) {
          const guessed = second ?? urlBasename(first, false, false);
          if (guessed === undefined) return undefined;
          dirs.push(named(guessed), ...common());
        }
      } else if (sub === "submodule update" || sub === "submodule init") {
        // The places are the ones .gitmodules declares, and that file belongs to the repository the
        // command names: only places inside its top level count. A top level that is not the named
        // directory or above it was set elsewhere (core.worktree): nothing counts.
        const shown = safeGit(["-C", base, "rev-parse", "--show-toplevel"])?.trim();
        const top = shown ? realpath(shown) : undefined;
        if (!top || !within(realish(base), top)) continue;
        const listed = safeGit(["config", "--file", path.join(top, ".gitmodules"), "--get-regexp", "^submodule\\..*\\.path$"]);
        for (const line of lines(listed ?? "")) {
          const place = beneath(top, line.slice(line.indexOf(" ") + 1).trim());
          if (place) dirs.push(place);
        }
        if (listed) dirs.push(...common());
      }
    }
  }
  return dirs.length ? [...new Set(dirs)] : undefined;
}

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
export function projectRoots(session: SessionState, scan?: Scan): string[] {
  if (isRootLike(session.project)) return [];
  if (!session.roots) {
    const now = checkouts(session.project);
    session.roots = now.length ? now : [session.project];
    if (!session.roots.includes(session.project)) session.roots.push(session.project);
  }
  if (!session.snapshot) session.snapshot = takeSnapshot(session.roots, session.project, scan);
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
//
// Every value was reviewed for what a hostile one does (round 3, finding 12). Where any value
// only selects, counts, matches or formats what the program prints anyway, it is free: head/tail
// -n -c, grep -e -m -A -B -C --color, rg -g -t -T (with --files only), ls --color --sort --time,
// stat -c --format --printf (metadata, never contents), du -d -t --exclude, df -t -x --type and
// --output (a column list, not a file), pgrep -u -U -P -g -t -d, date -d (a date to show) and -r
// (a file's time, never its contents) and --iso-8601/--rfc-3339, sort -k -t, uniq -f -s -w, cut,
// findmnt -o -t -T -S, lsblk -o, basename -s, dmesg's levels and times, journalctl and systemctl
// unit, lines, priority, time, identifier, grep, type, state and property selectors, tree -L -I
// -P --charset, column -s -c -o (-o is the output separator, not a file), nl, seq -s -f. Options
// that name another file to read or write or another host are not listed and ask: sort -o
// --compress-program -T, tree -o, journalctl --file -D -M --directory, systemctl -H -M,
// find -fprint -fprintf -fls -exec, rg --pre, date -f -s. Held to a list: journalctl/systemctl
// -o/--output (format names), and ps's formats and sort keys (field names, see psOk).
interface Remote {
  flags?: string;
  long?: string[];
  valued?: string[];
  // Values an option is held to.
  values?: Record<string, RegExp>;
  // `-5` style counts.
  numeric?: boolean;
  // Any words at all (true, false).
  free?: boolean;
  check?: (operands: string[], argv: string[]) => boolean;
}
const SYSTEMCTL_READ = new Set(["status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-timers", "list-sockets", "list-dependencies", "show", "cat"]);
const FIND_TESTS = new Set("-name -iname -path -ipath -regex -iregex -type -maxdepth -mindepth -mtime -mmin -ctime -cmin -atime -amin -newer -size -user -group -perm -links -inum -samefile".split(" "));
const FIND_FLAGS = new Set("-print -print0 -ls -empty -not -o -a -and -or -L -H -P -xdev -mount -readable -writable -executable -prune -quit -daystart -depth -follow -true -false -nouser -nogroup".split(" "));
const IP_OBJECTS = new Set(["addr", "address", "a", "route", "r", "link", "l", "neigh", "neighbor", "n", "rule"]);
const IP_SHOW = new Set(["show", "list", "ls", "lst"]);
const numbers = (ops: string[]) => ops.every((w) => /^\d+(\.\d+)?[smhd]?$/.test(w));
const plainWords = (argv: string[]) => argv.slice(1).every((w) => !/[$`[]/.test(w));
const TEST_OPERATORS = new Set("-e -f -d -s -r -w -x -L -h -p -S -b -c -n -z -eq -ne -gt -ge -lt -le -nt -ot -ef -a -o".split(" "));
const JOURNAL_FORMAT = /^(short|short-full|short-iso|short-iso-precise|short-precise|short-monotonic|short-delta|short-unix|with-unit|verbose|export|json|json-pretty|json-sse|json-seq|cat)$/;

// ps output columns and sort keys that print no process's environment (procps has `environ`, and
// BSD `e` appends it): pids, owners, terminals, names and command lines (what `ps aux` shows
// anyway), times, sizes, scheduling and state.
const PS_FIELDS = new Set(
  ("pid ppid pgid pgrp sid sess tid lwp spid tgid nlwp thcount user euser ruser suser fuser uid euid ruid suid fuid uname group egroup rgroup sgroup fgroup " +
    "gid egid rgid sgid fgid tty tt tname tpgid comm ucmd ucomm fname cmd args command exe %cpu pcpu c cp %mem pmem rss rssize rsz vsz vsize sz size drs trs " +
    "stat state s start start_time lstart bsdstart stime etime etimes time cputime cputimes bsdtime ni nice pri priority rtprio policy cls class sched psr " +
    "wchan nwchan f flag flags maj_flt min_flt cgroup cgname unit uunit slice label oom oomadj pending blocked caught ignored sig sigcatch sigignore sigmask lsession machine numa").split(" "),
);
// A format: fields separated by commas or blanks, each `name` or `name=header`. procps 4 ends a
// header at the next comma (`pid=X,environ` is two columns) where older ones took the rest of the
// word: a header is held to plain characters, so both read the same fields.
function psFormatOk(value: string): boolean {
  const items = value.split(/[\s,]+/).filter(Boolean);
  return items.length > 0 && items.every((item) => /^[\w%]+(=[\w%-]*)?$/.test(item) && PS_FIELDS.has(item.replace(/=.*/, "")));
}
const psSortOk = (value: string) => value.split(",").every((k) => PS_FIELDS.has(k.replace(/^[+-]/, "")));
// ps in both syntaxes. Dash options: flags from a list; -o, -O and --format take a format (in the
// same word after -o, or the next); --sort takes sort keys; -p -u -U -C --pid --ppid select.
// BSD words (no dash) are flags from a list, `o` taking a format; `e` (environment) is not one.
function psOk(argv: string[]): boolean {
  const FLAGS = "eAfFlwHjTLMyZaxu";
  const SELECT = new Set(["-p", "-u", "-U", "-C", "--pid", "--ppid"]);
  for (let i = 1; i < argv.length; i++) {
    const w = argv[i];
    const next = () => (++i < argv.length ? argv[i] : undefined);
    if (w === "--forest" || w === "--no-headers") continue;
    if (SELECT.has(w)) {
      if (next() === undefined) return false;
    } else if (w === "--format" || w === "--sort") {
      const v = next();
      if (v === undefined || !(w === "--sort" ? psSortOk(v) : psFormatOk(v))) return false;
    } else if (w.startsWith("--format=")) {
      if (!psFormatOk(w.slice(9))) return false;
    } else if (w.startsWith("--sort=")) {
      if (!psSortOk(w.slice(7))) return false;
    } else if (w.startsWith("-") && w.length > 1 && !w.startsWith("--")) {
      // A cluster: flags, then possibly `o`/`O` with the format after it or in the next word.
      const at = w.search(/[oO]/);
      const flags = at < 0 ? w.slice(1) : w.slice(1, at);
      if (![...flags].every((ch) => FLAGS.includes(ch))) return false;
      if (at >= 0) {
        const v = w.length > at + 1 ? w.slice(at + 1) : next();
        if (v === undefined || !psFormatOk(v)) return false;
      }
    } else if (/^[aAxufwlHjTLmc]*o?$/.test(w) && w !== "") {
      if (w.endsWith("o")) {
        const v = next();
        if (v === undefined || !psFormatOk(v)) return false;
      }
    } else return false;
  }
  return true;
}

// Programs that print what they read: raw reads of devices and of /proc show what no file name
// says (a disk, memory, every process's environment), so they ask, apart from /dev/null and the
// /proc files listed. A path climbing with `..` asks too (/proc/net/.. is /proc/self).
const CONTENT_READERS = new Set(["cat", "head", "tail", "grep", "sort", "uniq", "cut", "nl", "column"]);
const PROC_OK = /^\/proc\/((cpuinfo|meminfo|loadavg|uptime|version|mounts|partitions|diskstats|stat|swaps|vmstat|filesystems|modules|cmdline|devices|interrupts|softirqs|zoneinfo|buddyinfo)|pressure\/(cpu|memory|io)|(\d+|self)\/(status|stat|statm|limits|cmdline|comm|cgroup|mounts|mountinfo|oom_score|io))$/;
function rawRead(word: string): boolean {
  const parts = word.split("/");
  if (parts.includes("..")) return parts.includes("proc") || parts.includes("dev") || word.startsWith("/");
  if (!word.startsWith("/")) return false;
  const p = "/" + parts.filter(Boolean).join("/");
  if (p === "/dev/null") return false;
  if (p === "/proc" || p === "/dev" || p.startsWith("/proc/") || p.startsWith("/dev/")) return !PROC_OK.test(p);
  return false;
}
const REMOTE: Record<string, Remote> = {
  cat: { flags: "AbeEnstTuv" },
  head: { flags: "qv", valued: ["-n", "-c", "--lines", "--bytes"], numeric: true },
  tail: { flags: "qvfF", valued: ["-n", "-c", "--lines", "--bytes"], numeric: true },
  // No -r/-R: a recursive read prints every file below a directory, credentials included, and
  // the rules only see the directory's name. rg is recursive by itself, so it may only list
  // file names (--files).
  grep: { flags: "EFGPiwxvcnHhlLoqsIaz", valued: ["-e", "-m", "-A", "-B", "-C", "--max-count", "--color"], numeric: true },
  rg: { flags: "iwvcnlFSsNHUxo", long: ["--files"], valued: ["-g", "-t", "-T", "--glob", "--type"], check: (_ops, argv) => argv.includes("--files") },
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
  // Read by psOk.
  ps: {},
  pgrep: { flags: "lafxnovc", valued: ["-u", "-U", "-P", "-g", "-t", "-d"] },
  date: { flags: "uRI", long: ["--utc", "--universal", "--rfc-email"], valued: ["-d", "--date", "-r", "--reference", "--iso-8601", "--rfc-3339"], check: (ops) => ops.every((w) => w.startsWith("+")) },
  sort: { flags: "bdfgiMhnRrVcCmuzs", valued: ["-k", "-t", "--key", "--field-separator"] },
  uniq: { flags: "cdDiuz", valued: ["-f", "-s", "-w"], check: (ops) => ops.length <= 1 }, // a second operand is the output file
  cut: { flags: "sz", long: ["--complement"], valued: ["-d", "-f", "-c", "-b", "--delimiter", "--fields"] },
  tr: { flags: "cdst" },
  // bash evaluates the name after `printf -v` and `test -v` as arithmetic, subscripts included:
  // no -v, and no word that could hold a substitution or a subscript.
  echo: { flags: "neE", check: (_ops, argv) => plainWords(argv) },
  printf: { check: (_ops, argv) => plainWords(argv) && !argv.slice(1).some((w) => w.startsWith("-")) },
  true: { free: true },
  false: { free: true },
  test: { check: (_ops, argv) => plainWords(argv) && argv.slice(1).every((w) => !w.startsWith("-") || TEST_OPERATORS.has(w)) },
  "[": { check: (_ops, argv) => plainWords(argv.slice(0, -1)) && argv.at(-1) === "]" && argv.slice(1).every((w) => !w.startsWith("-") || TEST_OPERATORS.has(w)) },
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
    values: { "-o": JOURNAL_FORMAT, "--output": JOURNAL_FORMAT },
    check: (ops) => !ops.length,
  },
  systemctl: {
    flags: "alq",
    long: ["--no-pager", "--full", "--all", "--failed", "--quiet", "--user", "--system", "--no-legend", "--plain"],
    valued: ["-n", "-t", "-p", "-o", "--lines", "--type", "--state", "--property", "--output"],
    values: { "-o": JOURNAL_FORMAT, "--output": JOURNAL_FORMAT },
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
  if (argv[0] === "ps") return psOk(argv);
  const operands: string[] = [];
  for (let i = 1; i < argv.length; i++) {
    const w = argv[i];
    if (w === "--") return false;
    if (!w.startsWith("-") || w === "-") operands.push(w);
    else if (spec.valued?.includes(w)) {
      if (++i >= argv.length) return false;
      if (spec.values?.[w] && !spec.values[w].test(argv[i])) return false;
    } else if (spec.long?.includes(w)) continue;
    else if (w.startsWith("--")) {
      const name = w.slice(0, w.indexOf("="));
      if (!w.includes("=") || !spec.valued?.includes(name)) return false;
      if (spec.values?.[name] && !spec.values[name].test(w.slice(name.length + 1))) return false;
    } else if (spec.numeric && /^-\d+$/.test(w)) continue;
    else if (argv[0] === "test" || argv[0] === "[") continue; // operators, checked by the program's own check
    else if (![...w.slice(1)].every((ch) => spec.flags?.includes(ch))) return false;
  }
  if (CONTENT_READERS.has(argv[0]) && operands.some(rawRead)) return false;
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
//
// Round 3, finding 30: keys that tools write into ordinary repositories and git itself ignores,
// so they cannot change where git connects or what it runs: VS Code's, gh's and T3 Code's
// merge-base notes on a branch (`branch.<b>.vscode-merge-base`, `gh-merge-base`, `t3-merge-base`
// and their `-ref`), gh's `remote.<r>.gh-resolved`, `git init --shared`'s permissions, and the
// git-lfs keys that pick no endpoint: `lfs.repositoryformatversion`, and the `locksverify` and
// `access` (auth mode) git-lfs notes per endpoint. Not `lfs.url` and the like: git-lfs runs as a
// smudge filter during a pull when your own config sets one up, and would connect there, over ssh
// with the agent. `core.hooksPath` (husky) is refused: a hook can run the project's scripts.
//
// Seventh pass (C4 F8): `submodule.recurse`, `fetch.recurseSubmodules`, `push.default` and
// `push.recurseSubmodules` are everyday settings, and what each does is judged where it matters,
// by its value in any scope: a fetch or pull that may go into cloned submodules gets no agent
// whatever the config says (usesSsh, mayRecurse and clonedSubmodules), a push that goes into them
// gets none either (pushRecurses), the push check refuses one (pushIsSafe), and which ref
// `push.default` sends is read from git's own dry run there.
const REPO_CONFIG_OK =
  /^(core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks|autocrlf|eol|safecrlf|quotepath|abbrev|compression|bigfilethreshold|preloadindex|commitgraph|multipackindex|sparsecheckout|sparsecheckoutcone|longpaths|untrackedcache|splitindex|sharedrepository)|remote\..+\.(url|fetch|tagopt|prune|prunetags|promisor|partialclonefilter|skipdefaultupdate|gh-resolved)|branch\..+\.(remote|merge|rebase|description|vscode-merge-base|vscode-merge-base-ref|gh-merge-base|t3-merge-base|t3-merge-base-ref)|lfs\.repositoryformatversion|lfs\..+\.(locksverify|access)|user\.(name|email)|init\.defaultbranch|pull\.(rebase|ff)|fetch\.(prune|prunetags)|gc\.(aggressivedepth|aggressivewindow|auto|autodetach|autopacklimit|bigpackthreshold|cruftpacks|logexpiry|maxcruftsize|packrefs|pruneexpire|reflogexpire|reflogexpireunreachable|rerereresolved|rerereunresolved|worktreepruneexpire|writecommitgraph|.+\.reflogexpire|.+\.reflogexpireunreachable)|pack\.[\w.]+|index\.[\w.]+|feature\.[\w.]+|maintenance\.[\w.]+|extensions\.(objectformat|refstorage|worktreeconfig|partialclone|preciousobjects)|submodule\..+\.(url|active|branch)|commit\.gpgsign|tag\.gpgsign|merge\.(ff|conflictstyle)|diff\.(renames|algorithm)|color\.[\w.]+|advice\.[\w.]+|rerere\.enabled|include\.path|includeif\..+\.path|submodule\.recurse|fetch\.recursesubmodules|push\.(default|recursesubmodules))$/;

// The effective config as `[scope, key, value]`, or undefined when it could not be read in full
// (git failed, the output was cut off): the caller must then ask. Read with -z, so a value that
// spans lines is one value.
function readConfig(dir: string): [string, string, string][] | undefined {
  const r = gitRun(["-C", dir, "config", "--show-scope", "--includes", "--list", "-z"]);
  if (r.status !== 0) return undefined;
  const fields = r.out.split("\0");
  if (fields.pop() !== "" || fields.length % 2) return undefined;
  const out: [string, string, string][] = [];
  for (let i = 0; i < fields.length; i += 2) {
    const entry = fields[i + 1];
    const nl = entry.indexOf("\n");
    // A key with no value at all (`[push] followTags`) is true for git.
    out.push([fields[i], (nl < 0 ? entry : entry.slice(0, nl)).toLowerCase(), nl < 0 ? "true" : entry.slice(nl + 1)]);
  }
  return out;
}

// A boolean as git reads it, in any scope: undefined when unset, null when git could not say.
function configBool(dir: string, key: string): boolean | undefined | null {
  const r = gitRun(["-C", dir, "config", "--type=bool", "--get", key]);
  return r.status === 0 ? r.out.trim() === "true" : r.status === 1 ? undefined : null;
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

// The plugin's own network git (the dry-run push and ls-remote) runs in a session of its own, so
// it has no controlling terminal and neither git nor ssh can prompt on opencode's; stdin is
// /dev/null. On a timeout or too much output the whole process group goes, ssh included.
const run = (args: string[], timeout: number, env: NodeJS.ProcessEnv) =>
  new Promise<string | undefined>((resolve) => {
    let out = "";
    let failed = false;
    const child = spawn("git", gitArgs(args), { detached: true, stdio: ["ignore", "pipe", "ignore"], env });
    const stop = () => {
      failed = true;
      try {
        process.kill(-child.pid!, "SIGKILL");
      } catch {
        // already gone
      }
    };
    const timer = setTimeout(stop, timeout);
    child.stdout!.setEncoding("utf8");
    child.stdout!.on("data", (chunk: string) => {
      out += chunk;
      if (out.length > 1 << 20) stop();
    });
    child.on("error", () => {
      failed = true;
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve(failed || code !== 0 ? undefined : out);
    });
  });

// The environment for that git: ssh in batch mode, unless your own git config names an ssh
// command (it is then yours to configure; it still has no terminal). Repository config with
// core.sshCommand never gets this far (REPO_CONFIG_OK). Undefined when git could not say.
function networkEnv(dir: string): NodeJS.ProcessEnv | undefined {
  const own = configValue(dir, "core.sshCommand");
  if (own === null) return undefined;
  return own === undefined ? { ...gitEnv(), GIT_SSH_COMMAND: "ssh -o BatchMode=yes" } : gitEnv();
}

// A URL git reaches over the network, in a form that names neither a local path nor a program:
// https://, ssh:// and scp-like `[user@]host:path`, read as git reads the word (connect.c,
// url_is_local_not_ssh: a colon before any slash names a host, so `host:/srv/x.git` is ssh, and
// a host is whatever ssh takes for one, an alias with an underscore too; round 4, finding 25,
// seventh pass). A path (absolute, relative, `./x`, `~/x`: a slash before any colon, or no
// colon), file://, a transport helper (`x::...`, ext::, fd::), any other `scheme://` (git runs
// `git-remote-<scheme>`) and anything else are not: for those git runs code from that
// repository (receive-pack, core.alternateRefsCommand) or a program, here, with this process's
// environment. A user or host that begins with `-` is none (ssh would read an option). Applied
// to URLs after git's own rewriting (insteadOf, pushInsteadOf).
const NETWORK_URL = /^(?:(?:https|ssh):\/\/(?:[\w.-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*(?::\d+)?\/|(?:[A-Za-z0-9_.][\w.-]*@)?[A-Za-z0-9][\w.-]*:(?!:|\/\/))/;
const networkUrl = (url: string) => NETWORK_URL.test(url) && !/[\s\0]/.test(url);

// The project's own checkout, at its top: the directory is a mount of its own in every sandbox,
// so no other command can swap it for something else between this check and the command.
const atRoot = (dir: string, session: SessionState) => projectRoots(session).includes(realpath(dir));

// Hooks git would run for the command, with the ssh agent in reach. A hook is the user's own, but
// it often runs the project's scripts, which a sandboxed command can edit.
const HOOKS_RUN: Record<string, string[] | "any"> = { fetch: ["reference-transaction", "pre-auto-gc"], "ls-remote": [], push: ["pre-push", "reference-transaction"], pull: "any" };
function hookWouldRun(dir: string, sub: string, config: [string, string, string][]): boolean {
  const configured = config.filter(([scope, key]) => scope !== "command" && key === "core.hookspath").at(-1)?.[2];
  // git expands `~user/` with that user's home and `%(prefix)/` with its own: not placed here.
  if (configured && ((configured.startsWith("~") && configured !== "~" && !configured.startsWith("~/")) || configured.startsWith("%("))) return true;
  const base = configured ? safeGit(["-C", dir, "rev-parse", "--show-toplevel"])?.trim() : safeGit(["-C", dir, "rev-parse", "--git-common-dir"])?.trim();
  if (!base) return true; // cannot tell
  const hooks = configured ? path.resolve(base, tilde(configured)) : path.resolve(dir, base, "hooks");
  const wanted = HOOKS_RUN[sub] ?? "any";
  let names: string[];
  try {
    names = fs.readdirSync(hooks);
  } catch (e) {
    return !["ENOENT", "ENOTDIR"].includes((e as NodeJS.ErrnoException).code ?? "");
  }
  return names.some((name) => {
    if (name.endsWith(".sample") || (wanted !== "any" && !wanted.includes(name))) return false;
    try {
      fs.accessSync(path.join(hooks, name), fs.constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
}

// The remote a command with no remote operand uses, by git's own order of precedence (remote.c,
// pushremote_for_branch and remote_for_branch): for a push `branch.<b>.pushRemote`, then
// `remote.pushDefault`; then `branch.<b>.remote`; then the only remote when there is exactly
// one; then `origin`. Where git gives its own answer it is asked (`git ls-remote --get-url` with
// no word prints the URL of the remote it picks for the fetch side), and a name whose URL is not
// that answer is not trusted. Null when it cannot be told: the caller asks.
//
// The branch is read by its full name: `--short` prints `heads/main` where a tag is called
// `main` too, and `branch.heads/main.*` is no key of anyone's (seventh pass). A HEAD that points
// outside `refs/heads/` is on no branch, to git as well (remote.c, branch_get).
function defaultRemote(dir: string, sub: string): string | null {
  const head = gitRun(["-C", dir, "symbolic-ref", "--quiet", "HEAD"]);
  if (head.status === undefined) return null;
  const full = head.status === 0 ? head.out.replace(/\n$/, "") : undefined;
  const current = full?.startsWith("refs/heads/") ? full.slice("refs/heads/".length) : undefined;
  if (sub === "push") {
    for (const key of [...(current ? [`branch.${current}.pushRemote`] : []), "remote.pushDefault"]) {
      const value = configValue(dir, key);
      if (value === null) return null;
      if (value) return value;
    }
  }
  const own = current ? configValue(dir, `branch.${current}.remote`) : undefined;
  if (own === null) return null;
  const listed = gitRun(["-C", dir, "remote"]);
  if (listed.status !== 0) return null;
  const names = lines(listed.out);
  const name = own || (names.length === 1 ? names[0] : "origin");
  const picked = gitRun(["-C", dir, "ls-remote", "--get-url"]);
  // git picks a remote that is not configured (`origin` where there is none): it says so itself.
  if (picked.status === 128 && !names.includes(name)) return name;
  const mine = gitRun(["-C", dir, "ls-remote", "--get-url", "--", name]);
  return picked.status === 0 && mine.status === 0 && picked.out === mine.out ? name : null;
}

// What `git push <words>` would do, asked of git itself (`--dry-run --porcelain`): which URL it
// connects to and which ref goes where. Git applies its own precedence (branch.*.pushRemote,
// remote.pushDefault, remote.*.push, push.default, followTags); reading the config here and
// guessing would miss one of them. Hooks, askpass and prompts are off for the plugin's git.
async function dryRunPush(dir: string, words: string[], env: NodeJS.ProcessEnv): Promise<{ urls: string[]; refs: { flag: string; from: string; to: string }[] } | undefined> {
  const out = await run(["-C", dir, "push", "--dry-run", "--porcelain", ...words.filter((w) => w !== "--porcelain" && w !== "-n" && w !== "--dry-run")], 8000, env);
  if (out === undefined) return undefined;
  const urls: string[] = [];
  const refs: { flag: string; from: string; to: string }[] = [];
  for (const line of lines(out)) {
    const to = /^To (.+)$/.exec(line);
    const ref = /^(.)\t([^\t:]*):([^\t]*)\t/.exec(line);
    if (to) urls.push(to[1]);
    else if (ref) refs.push({ flag: ref[1], from: ref[2], to: ref[3] });
    else if (line !== "Done") return undefined;
  }
  return { urls, refs };
}

// A URL as `git push --porcelain` prints it: git drops the user (and password) of a URL it shows
// (transport.c, transport_anonymize_url), so `git@host:o/r.git` is printed `host:o/r.git` and
// `ssh://git@host/p` `ssh://host/p` (round 3, finding 16). From the first `@`, unless the URL is a
// local path, an scp-like one with no `:` after the `@`, a scheme that is not letters, digits and
// `+.-`, or an `@` after the first `/` past the scheme.
export function anonymizeUrl(url: string): string {
  const at = url.indexOf("@");
  const colon = url.indexOf(":");
  const slash = url.indexOf("/");
  const local = colon < 0 || (slash >= 0 && slash < colon);
  if (local || at < 0) return url;
  const anon = url.slice(at + 1);
  const scheme = url.indexOf("://");
  if (scheme < 0) return anon.includes(":") ? anon : url;
  if (!/^[A-Za-z0-9+.-]*$/.test(url.slice(0, scheme))) return url;
  const first = url.indexOf("/", scheme + 3);
  if (first >= 0 && first < at) return url;
  return url.slice(0, scheme + 3) + anon;
}

async function pushIsSafe(dir: string, words: string[], session: SessionState): Promise<boolean> {
  // Only the project's own repository, at the top of a checkout: not a copy the agent built
  // elsewhere, and not a directory another command could swap.
  const snap = session.snapshot;
  const config = ownRepository(dir, session);
  if (!snap?.remotes || !config || !atRoot(dir, session)) return false;
  const flags = words.filter((w) => w.startsWith("-"));
  if (!flags.every((f) => PUSH_SAFE_FLAGS.has(f))) return false;
  const [remote, ...refspecs] = words.filter((w) => !w.startsWith("-"));
  // A URL or an unknown name could send the code anywhere.
  if (remote !== undefined && !snap.remotes.has(remote)) return false;
  // In any scope: a plain push would then send more than the branch.
  if (configBool(dir, "push.followTags") !== undefined || config.some(([, k]) => /^remote\..+\.mirror$/.test(k))) return false;
  // A push that recurses into submodules (push.recurseSubmodules, submodule.recurse) runs a push
  // in each, to remotes from the submodules' own config, which nothing here has vetted.
  const recurse = configValue(dir, "push.recurseSubmodules");
  if (recurse === null || (recurse !== undefined && !/^(no|false|off|0)$/i.test(recurse)) || [true, null].includes(configBool(dir, "submodule.recurse") ?? false)) return false;
  if (hookWouldRun(dir, "push", config)) return false;
  // `+x` forces, `:x` deletes, wildcards, tags and other ref namespaces are out of scope.
  if (refspecs.some((spec) => !spec || spec.startsWith("+") || spec.startsWith(":") || spec.includes("*") || spec.split(":").length > 2 || /^refs\/(?!heads\/)/.test(spec))) return false;
  // Before any git talks to a remote: the dry run starts receive-pack in a local repository (and
  // its core.alternateRefsCommand), or a transport helper, outside the sandbox and before the
  // decision. So every push URL of every remote, as git rewrites it, must be a network URL; git's
  // own choice of remote cannot then reach anything else.
  const before = readRemotes(dir);
  if (!before?.size || ![...before.values()].every((r) => r.push.length > 0 && r.push.every(networkUrl))) return false;
  const env = networkEnv(dir);
  if (!env) return false;
  const would = await dryRunPush(dir, words, env);
  if (!would || !would.urls.length || !would.refs.length) return false;
  // Every URL git would connect to belongs to a remote the session started with, unchanged
  // since (all of its URLs: git pushes to each).
  const now = readRemotes(dir);
  // Compared as git prints them: without a user (anonymizeUrl). Each configured URL that prints
  // as the reported one is checked below.
  const pushUrls = (url: string) => [...snap.remotes!.keys()].filter((name) => sameUrls(snap.remotes, now, name)).flatMap((name) => snap.remotes!.get(name)!.push.filter((configured) => anonymizeUrl(configured) === url));
  if (!would.urls.every((url) => pushUrls(url).length > 0)) return false;
  // The default branch of each repository the push goes to, asked of that URL itself (the local
  // refs/remotes/<r>/HEAD can be rewritten, and a pushurl can name another repository than the
  // fetch URL). The URL must reach ls-remote unchanged: an insteadOf for it would make ls-remote
  // ask a different repository. Repository config that could change how git connects was
  // rejected above, and no askpass program runs.
  const defaults = new Set<string>();
  for (const url of new Set(would.urls.flatMap(pushUrls))) {
    const asked = gitRun(["-C", dir, "ls-remote", "--get-url", url]);
    if (asked.status !== 0 || asked.out.trim() !== url || !networkUrl(url)) return false;
    const symref = await run(["-C", dir, "ls-remote", "--symref", url, "HEAD"], 8000, env);
    const remoteDefault = /^ref: refs\/heads\/(\S+)\s+HEAD$/m.exec(symref ?? "")?.[1];
    if (!remoteDefault) return false;
    defaults.add(remoteDefault);
  }
  // What goes where: a branch, to a branch that is not protected, without force or delete.
  return would.refs.every(({ flag, from, to }) => {
    if (!" *=".includes(flag) || !(from === "HEAD" || from.startsWith("refs/heads/")) || !to.startsWith("refs/heads/")) return false;
    const branch = to.slice("refs/heads/".length);
    return !PROTECTED_BRANCH.test(branch) && !defaults.has(branch);
  });
}

// Whether a tool call is a push the feature-branch check would look at: one plain `git push`.
export function pushCandidate(command: string, cwd: string): boolean {
  const s = single(command, cwd);
  return !!s && !!plainGit(s, /^push$/);
}

// `git [-C dir]... <subcommand> ...` with no other global option: the directory and the rest.
function plainGit(s: Single, subcommands: RegExp): { dir: string; sub: string; words: string[] } | undefined {
  if (s.argv[0] !== "git") return undefined;
  let dir = s.dir;
  let i = 1;
  for (; s.argv[i] === "-C" && i + 1 < s.argv.length; i += 2) {
    // The directory git changes to must be the one that is checked.
    const to = /^~[^/]/.test(s.argv[i + 1]) ? undefined : landing(dir, tilde(s.argv[i + 1]));
    if (!to) return undefined;
    dir = to;
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
function rulesFor(guard: Guard, watch: Matcher | undefined, s: Single | undefined, pushOk: boolean, more: Matcher[] = []): UserRules {
  const extra: Matcher[] = [...more];
  if (s && guard.sshHosts?.length && sshAllowed(s, guard)) extra.push({ source: `ssh to ${guard.sshHosts.join(", ")} with a read-only remote command`, test: (text) => s.texts.includes(text) });
  if (s && pushOk) extra.push({ source: "git push of a feature branch to a configured remote", test: (text) => s.texts.includes(text) });
  return {
    deny: [...(watch ? [watch] : []), ...guard.rules.deny.map(alsoByName)],
    ask: guard.rules.ask.map(alsoByName),
    classify: guard.rules.classify.map(alsoByName),
    allow: [...guard.rules.allow, ...extra],
  };
}

// Git subcommands that may write inside git directories when they make up the whole tool call.
// Those GIT_WRITE marks "asks" never are (round 3, finding 27: remote, bisect, apply and
// symbolic-ref joined).
const GIT_WRITERS = new Set(["add", "commit", "checkout", "switch", "restore", "stash", "reset", "merge", "cherry-pick", "revert", "rebase", "tag", "branch", "fetch", "pull", "push", "mv", "rm", "status", "log", "diff", "show", "notes", "gc", "prune", "pack-refs", "update-index", "rev-parse", "ls-files", "describe", "blame", "shortlog", "reflog", "remote", "bisect", "apply", "symbolic-ref"]);
const GIT_FILE_OPTIONS = ["--output", "--output-directory", "--exec", "--template", "--upload-pack", "--receive-pack", "--interactive", "--patch"];
// Short options that name a program or open an editor, by subcommand. Elsewhere `-u`, `-F` and
// `-o` are harmless (`add -u`, `stash -u`, `commit -F msg`, `commit -o`).
const GIT_SHORT_REFUSED: Record<string, RegExp> = { fetch: /^-[a-zA-Z]*u/, pull: /^-[a-zA-Z]*u/, rebase: /^-[a-zA-Z]*[xi]/, add: /^-[a-zA-Z]*[ipe]/, commit: /^-[a-zA-Z]*[pe]/, checkout: /^-[a-zA-Z]*p/, restore: /^-[a-zA-Z]*p/, reset: /^-[a-zA-Z]*p/, stash: /^-[a-zA-Z]*p/ };
// A tool call made only of `git <writer>` commands (and `cd`), in plain words: no substitutions,
// variables or options that write files or run programs; output may go to /dev/null or be
// merged (`2>&1`). Only such calls get write access inside git directories (minus hooks and
// config); for everything else git directories are read-only.
//
// Round 3, finding 13 (signed off): commands may be on lines of their own; a glob may stand in a
// path operand of `git add`, `rm`, `mv` and `restore` (globPathOk); `!` may stand in double
// quotes; the commit message most agents write, `-m "$(cat <<'EOF' ... EOF⏎)"`, is one word
// whatever its body holds (see strictCommands); and an editor that does nothing may be set for a
// command that would open one (editorCommand).
// Options of `git add`, `rm`, `mv` and `restore` that take no value: a glob may follow one.
const GLOB_AFTER: Record<string, RegExp> = {
  add: /^(-[AfuNvnq]+|--(all|force|update|intent-to-add|verbose|dry-run|ignore-errors|ignore-missing|renormalize|no-all|sparse|ignore-removal|no-ignore-removal))$/,
  rm: /^(-[rfqn]+|--(cached|quiet|dry-run|ignore-unmatch|sparse|force))$/,
  mv: /^(-[fknv]+|--(force|dry-run|verbose))$/,
  restore: /^(-[SWqm]+|--(staged|worktree|quiet|ours|theirs|merge|ignore-unmerged|overlay|no-overlay|progress|no-progress))$/,
};
// A glob bash expands in a git call: only a path operand of add, rm, mv or restore (not the value
// of an option, which the word before it would be), and only one that starts with a plain path
// segment (`src/`, `./`, `../`), so that no file it matches can become an option or pathspec
// magic (`:(...)`, `:!`).
function globPathOk(sub: string, rest: string[], at: number): boolean {
  const after = GLOB_AFTER[sub];
  if (!after || at < 0 || rest.slice(0, at).some((w) => /^--pathspec-from-file/.test(w))) return false;
  const previous = rest[at - 1];
  const option = previous !== undefined && previous.startsWith("-") && previous !== "--" && !rest.slice(0, at - 1).includes("--");
  if (option && !after.test(previous)) return false;
  if (/^(\.{1,2}\/|[A-Za-z0-9_][A-Za-z0-9_.+@,=-]*\/)/.test(rest[at])) return true;
  // Round 4, finding 9 (signed off): a glob at the top level after `--` (`git add -- *.ts`).
  // After `--` no match can become an option. Narrow: every word before the `--` is a flag from
  // the table above (so the `--` is no option's value), the word has no `/`, and it starts with
  // a letter, a digit, `_` or a glob character: none of those matches a leading dot (`.git`),
  // and the word cannot start as pathspec magic (`:`) or with a `-`.
  const end = rest.indexOf("--");
  return end >= 0 && end < at && rest.slice(0, end).every((w) => after.test(w)) && /^[A-Za-z0-9_*?[][^/]*$/.test(rest[at]);
}

// Round 4, finding 9 (signed off): what may follow the last git command of a git-only call.
// `|| true`, and one pipe into `head` or `tail` given nothing or only a count (`-5`, `-n 5`):
// neither reads a file, writes one or runs anything. Any other pipe, a pipe that is not the last
// thing in the call and a `||` before anything else give no git-only reading.
const COUNT_ONLY = (args: string[]) => args.length === 0 || (args.length === 1 && /^-[0-9]{1,9}$/.test(args[0])) || (args.length === 2 && args[0] === "-n" && /^[0-9]{1,9}$/.test(args[1]));
function gitOnlyTail(cmd: StrictCommand): boolean {
  if (cmd.assigns || cmd.globbed || cmd.quotedTilde) return false;
  if (cmd.before === "||") return cmd.argv.length === 1 && cmd.argv[0] === "true";
  if (cmd.before === "|") return (cmd.argv[0] === "head" || cmd.argv[0] === "tail") && COUNT_ONLY(cmd.argv.slice(1));
  return false;
}

// The commands of a git-only call. `command` is the printed text (canon.ts), the one that runs:
// a heredoc commit message is already the literal it stands for there, read as bash reads it
// (round 4, findings 1 and 16; round 3 matched the heredoc with a pattern of its own and swapped
// its body for a fixed one, which is where finding 1's second input got in).
// `quoted`: per command, whether it holds a `~` that bash leaves as it is (see strictCommands).
//
// Eighth pass: a `cd` may also have one of the words of the shape whose places count as known
// (guard.ts, knownShape and cdWord; the maintainer's decision on where a command runs): `$HOME`,
// `$PWD` (or `${…}`), `$(pwd)` or `$(git rev-parse --show-toplevel)`, quoted or not, with or
// without a literal `/…` after it. Nothing else of the call may hold a `$`. Where such a `cd`
// leads is `located`'s to say, and where it does not say the git commands after it have no
// place (gitEnds). `shaped`: per command, whether it is such a `cd` (its word is then a
// stand-in, and names nothing).
export function gitOnlyRead(command: string): { cmds: string[][]; quoted: boolean[]; shaped: boolean[] } | undefined {
  // A stand-in must come out as the one word of a `cd`: the text it replaced was then read as
  // that word by the strict reader, from its first character to its last. One that comes out as
  // a part of some other word stood inside a quoted word (a commit message that spells such a
  // `cd`): that text is put back as it was, and the call is read again.
  const left = new Set<number>();
  let all: StrictCommand[] | undefined;
  let shaped: boolean[] = [];
  for (let round = 0; ; round++) {
    const plain = shapedCds(command, left);
    if (!plain || round > 8) return undefined;
    all = strictCommands(plain.text, { nullRedirects: true, newlines: true, globs: true, bang: true, assignments: EDITOR_ASSIGNMENT, pipes: true });
    if (!all) return undefined;
    shaped = all.map((c) => c.argv[0] === "cd" && c.argv.length === 2 && plain.words.has(c.argv[1]) && !c.assigns && !c.globbed);
    const placed = new Set(all.filter((_c, n) => shaped[n]).map((c) => c.argv[1]));
    const astray = [...plain.words].filter(([word]) => !placed.has(word));
    if (!astray.length) {
      // And nothing else of the call holds one (each stands in the text once).
      const holds = (word: string) => plain.mark !== "" && word.includes(plain.mark);
      if (all.some((c, n) => (c.assigns ?? []).some(holds) || c.argv.some((w, k) => holds(w) && !(shaped[n] && k === 1)))) return undefined;
      break;
    }
    for (const [, at] of astray) left.add(at);
  }
  // `pipes` lets `|` and `||` through the tokenizer; only the last command may follow one, as
  // `|| true` or `| head`/`| tail` with a count, and only straight after a git command.
  const tail = all.length > 1 && (all[all.length - 1].before === "|" || all[all.length - 1].before === "||") ? all[all.length - 1] : undefined;
  const cmds = tail ? all.slice(0, -1) : all;
  if (cmds.some((c) => c.before === "|" || c.before === "||")) return undefined;
  if (tail && (!gitOnlyTail(tail) || cmds[cmds.length - 1].argv[0] === "cd")) return undefined;
  const ok = cmds.every(({ argv: full, assigns, globbed }) => {
    if (full[0] === "cd") return full.length <= 2 && !assigns && !globbed;
    const shift = full[0] === "timeout" && /^\d+(\.\d+)?[smhd]?$/.test(full[1] ?? "") ? 2 : 0;
    if (assigns && shift) return false;
    const argv = full.slice(shift);
    if (argv[0] !== "git") return false;
    const call = gitCall(argv.slice(1));
    if (typeof call === "string" || !GIT_WRITERS.has(call.sub ?? "") || gitWrite(call.sub ?? "", call.rest) === "asks") return false;
    if (assigns && !editorCommand(argv)) return false;
    // Where the rest begins in argv.
    const from = argv.length - call.rest.length;
    if (globbed?.some((g) => !globPathOk(call.sub ?? "", call.rest, g - shift - from))) return false;
    const refused = GIT_SHORT_REFUSED[call.sub ?? ""];
    // The text of a message is no option, whatever it spells (gitMessageWords).
    const messages = new Set(gitMessageWords(argv.slice(1)).map((m) => m.at - (argv.length - 1 - call.rest.length)));
    return !call.rest.some((w, k) => !messages.has(k) && ((refused?.test(w) && !w.startsWith("--")) || abbreviates(w, GIT_FILE_OPTIONS)));
  });
  if (!ok || !cmds.some(({ argv }) => argv.includes("git"))) return undefined;
  return { cmds: cmds.map((c) => c.argv), quoted: cmds.map((c) => !!c.quotedTilde), shaped: shaped.slice(0, cmds.length) };
}
export const gitOnly = (command: string): boolean => gitOnlyRead(command) !== undefined;

// The text with each `cd <word of the shape>` (see gitOnlyRead) given a plain stand-in for its
// word, which the strict reader takes; `words`: the stand-ins, `mark`: what each of them holds
// and nothing else of the text does. The word must be the whole operand of a `cd` that begins a
// command (the start of the text, or after `&&`, `;` or a newline) and ends it. A match inside a
// quoted word is undone by the caller, which finds the stand-in inside another word.
// Undefined where no stand-in can be told from the text's own words.
const SHAPED_NAME = String.raw`(?:\$HOME|\$\{HOME\}|\$PWD|\$\{PWD\}|\$\(pwd\)|\$\(git rev-parse --show-toplevel\))`;
const SHAPED_REST = String.raw`(?:/[A-Za-z0-9_@%+=:,./-]*)?`;
const SHAPED_CD = new RegExp(String.raw`(^|&&|;|\n)([ \t]*)cd[ \t]+(?:"${SHAPED_NAME}${SHAPED_REST}"${SHAPED_REST}|${SHAPED_NAME}${SHAPED_REST})(?=[ \t]*(?:&&|;|\n|$))`, "g");
// `left`: the matches (counted from 0) that are left as they are. `words`: each stand-in with
// the number of the match it replaced.
function shapedCds(command: string, left: Set<number> = new Set()): { text: string; words: Map<string, number>; mark: string } | undefined {
  if (!command.includes("$")) return { text: command, words: new Map(), mark: "" };
  let mark = "automode-shaped-cd";
  for (let n = 0; command.includes(mark); n++) {
    if (n > 20) return undefined;
    mark = `automode-shaped-cd-${randomUUID()}`;
  }
  const words = new Map<string, number>();
  let match = -1;
  const text = command.replace(SHAPED_CD, (found: string, before: string, blank: string) => {
    match++;
    if (left.has(match)) return found;
    const word = `/${mark}/${match}`;
    words.set(word, match);
    return `${before}${blank}cd ${word}`;
  });
  return { text, words, mark };
}

// The directory each git command of a git-only call ends in, after the `cd`s before it and its
// own `-C`s: the repositories the call works in, which is where it gets a writable `.git`
// (round 4, finding 21, decision 1). The shell's directory and the ones a `cd` only passes
// through are not among them unless git runs there. The command is read as gitOnlyRead reads
// it. A directory that cannot be told throws, with the reason, where the command writes its git
// directory: the call then asks. That is a directory that is not there, `cd -` (it leads where
// the shell was last), `~user`, a `~` in a command that holds a quoted one (bash and git leave
// that as it is; which word it is cannot be told from here), and several directories that are
// not in one repository (gitPlace). A command that only reads there is left out (gitEnds).
export const gitDirectories = (command: string, cwd: string): string[] => [...new Set(gitEnds(command, cwd).map((end) => end.dir))];
// Those of them where a command ends that writes its git directory (GIT_WRITE): a repository
// outside the writable roots can be read by `git status` or `git log`, and a commit there would
// only fail (round 4, finding 21, sixth pass).
export const gitWriteDirectories = (command: string, cwd: string): string[] => [...new Set(gitEnds(command, cwd).filter((end) => writesGit(end.sub ?? "", end.rest)).map((end) => end.dir))];

// The directory a git command ends in, from the places bash may be in when it starts
// (guard.ts, `located`: each `cd` followed as bash goes there, by the text of `$PWD`) and its own
// `-C` words, each a chdir (the kernel's walk from where the one before led). Where the place is
// not known, or a `-C` word leads nowhere, it throws with the reason. Where the command may be
// in several directories by then, they must lie in one repository (or all in none): otherwise
// which repository git works in cannot be told, and that throws too (round 4, finding 21,
// seventh pass; C4 F1 and F2).
function gitPlace(places: Places, dirs: string[]): string {
  if (!places?.length) throw new Error("cannot tell which directory git runs in by then (a cd that leads nowhere, or to a place known only when it runs), so which repository git would work in");
  const reals = new Set<string>();
  for (const place of places) {
    let at: Place | undefined = place;
    for (const dir of dirs) at = at && chdirTo(at, dir);
    if (!at) throw new Error(`cannot tell which directory git -C ${dirs.join(" -C ")} leads to, so which repository git would work in`);
    reals.add(at.real);
  }
  const [first, ...others] = [...reals];
  if (!others.length) return first;
  // "": in no repository. Undefined: git could not say.
  const repository = (dir: string) => {
    const r = gitRun(["-C", dir, "rev-parse", "--absolute-git-dir"]);
    return r.status === 0 ? r.out.trim() : r.status === 128 ? "" : undefined;
  };
  const own = repository(first);
  if (own === undefined || others.some((dir) => repository(dir) !== own)) throw new Error(`cannot tell which repository git would work in: it may run in ${first} or in ${others.join(" or in ")}`);
  return first;
}

// Where `git -C <word>` leads from a place: a chdir(2), the kernel's walk from the real directory
// (the word as bash hands it over; a leading `~` or `~/` is the home directory, as unquoted). An
// empty word is no move at all (git: "the current working directory is left unchanged").
// Undefined where it leads to no directory that is there now, and for `~user`.
// Not guard.ts's `cdTo`, which gives up on a relative word whenever this process has a `CDPATH`:
// bash's `cd` looks a word up there, git's chdir never does (eighth pass: with `CDPATH` exported
// where opencode was started, `git -C src add a.txt` asked and an approved `git -C src init`
// paused the session).
function chdirTo(from: Place, word: string): Place | undefined {
  if (word === "") return from;
  if (/^~[^/]/.test(word)) return undefined;
  const target = tilde(word);
  try {
    const real = fs.realpathSync.native(path.isAbsolute(target) ? target : `${from.real}/${target}`);
    return fs.statSync(real).isDirectory() ? { logical: real, real } : undefined;
  } catch {
    return undefined;
  }
}

// The commands of `argvs` (in their order) among the commands `located` lists for the call: the
// same words, each further on than the one before. Undefined for one that is not found.
// A `cd` is the next `cd` listed, whatever its word (the two readings spell a substitution in it
// differently, and the commands of the substitution are listed before it).
function placedCommands(where: ReturnType<typeof located>, argvs: string[][]): (Simple | undefined)[] {
  let next = 0;
  // Without the assignments before the command's name (`GIT_EDITOR=true git rebase --continue`):
  // one reading keeps them among the words, the other does not.
  const words = (argv: string[]) => {
    let at = 0;
    while (at < argv.length - 1 && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[at])) at++;
    return argv.slice(at).join("\0");
  };
  return argvs.map((argv) => {
    const text = words(argv);
    for (let n = next; n < where.cmds.length; n++) {
      if (argv[0] === "cd" ? where.cmds[n].argv[0] !== "cd" : words(where.cmds[n].argv) !== text) continue;
      next = n + 1;
      return where.cmds[n];
    }
    return undefined;
  });
}
// Those of them where a command ends that works on every worktree of its repository: `git gc`
// expires the reflog of each worktree's `HEAD` under a lock in that worktree's admin directory
// (seventh pass: from a linked worktree the plan grants those directories to such a call only).
export const gitMaintainDirectories = (command: string, cwd: string): string[] => [...new Set(gitEnds(command, cwd).filter((end) => end.sub === "gc").map((end) => end.dir))];

// Each git command of a git-only call, with the directory it ends in.
// Eighth pass: a directory is what a grant is made for, and only a command that writes its git
// directory needs one (GIT_WRITE). A command that only reads, in a place that cannot be told or
// in one of several repositories, is left out here: it gets no writable git directory, works on
// a read-only one, and goes where the rest of its call goes (`git status; cd lib; git status`
// stays a rule allow; `cd lib && cd - && git status` is outside the shape of guard.ts and is the
// model's). One that writes there throws as before, and the call asks.
function gitEnds(command: string, cwd: string): { dir: string; sub: string | undefined; rest: string[] }[] {
  const read = gitOnlyRead(command);
  if (!read) return [];
  const where = located(command, cwd);
  const placed = placedCommands(where, read.cmds);
  const ends: { dir: string; sub: string | undefined; rest: string[] }[] = [];
  // bash and git leave a quoted `~` as it is; which word it is cannot be told from here.
  const plain = (word: string, quoted: boolean, what: string) => {
    if (/^~[^/]/.test(word)) throw new Error(`cannot tell which directory ${what} ${word} names`);
    if (word.startsWith("~") && quoted) throw new Error(`cannot tell which directory ${what} ${word} names: the command holds a quoted ~, which is not your home directory to bash or git`);
  };
  // A `cd` whose word cannot be told leaves every command after it without a place.
  let lost: Error | undefined;
  read.cmds.forEach((full, at) => {
    if (full[0] === "cd") {
      try {
        if (!read.shaped[at]) plain(full[1] ?? "", read.quoted[at], "cd");
      } catch (e) {
        lost ??= e as Error;
      }
      return;
    }
    const argv = full[0] === "timeout" ? full.slice(2) : full;
    const call = gitCall(argv.slice(1));
    if (typeof call === "string") throw new Error(call);
    try {
      if (lost) throw lost;
      for (const dir of call.dirs) plain(dir, read.quoted[at], "git -C");
      const cmd = placed[at];
      if (!cmd) throw new Error("cannot tell where the git commands of this call run: its text is read two ways");
      ends.push({ dir: gitPlace(where.places.get(cmd), call.dirs), sub: call.sub, rest: call.rest });
    } catch (e) {
      if (writesGit(call.sub ?? "", call.rest)) throw e;
    }
  });
  return ends;
}

// A URL git reads as a path on this machine (connect.c, url_is_local_not_ssh, and `file://`):
// the path, or undefined for one that names a host or a transport helper.
function localUrl(url: string): string | undefined {
  if (url.startsWith("file://")) return url.slice("file://".length);
  const colon = url.indexOf(":");
  const slash = url.indexOf("/");
  return colon < 0 || (slash >= 0 && slash < colon) ? url : undefined;
}

// `git ls-remote`'s options (git 2.47.3: `git ls-remote --git-completion-helper-all` and `-h`),
// read as the tables in guard.ts are. `--upload-pack` has no short form here (`-u` is fetch's).
const LS_REMOTE_OPTIONS: Getopt = {
  flags: "qtbh",
  values: "o",
  long: { quiet: "flag", tags: "flag", branches: "flag", heads: "flag", refs: "flag", "get-url": "flag", "exit-code": "flag", symref: "flag", "upload-pack": "value", exec: "value", sort: "value", "server-option": "value" },
  negatable: () => true,
};

// `url.<base>.pushInsteadOf` applied to a URL as git applies it to one that has no push URL of
// its own (remote.c: the longest prefix wins): the rewritten URL, or undefined when none
// matches. Throws when the config cannot be read.
function pushRewritten(dir: string, url: string): string | undefined {
  const listed = gitRun(["-C", dir, "config", "--null", "--get-regexp", "^url\\..*\\.pushinsteadof$"]);
  if (listed.status === 1) return undefined;
  if (listed.status !== 0) throw new Error(`cannot read url.*.pushInsteadOf for git in ${dir}, so where a push to ${url} goes`);
  let best: { base: string; prefix: string } | undefined;
  for (const entry of listed.out.split("\0").filter(Boolean)) {
    const nl = entry.indexOf("\n");
    if (nl < 0) continue;
    const prefix = entry.slice(nl + 1);
    const base = entry.slice("url.".length, nl - ".pushinsteadof".length);
    if (prefix && url.startsWith(prefix) && (!best || prefix.length > best.prefix.length)) best = { base, prefix };
  }
  return best ? best.base + url.slice(best.prefix.length) : undefined;
}

// The URLs a git call that contacts a remote will use (round 4, finding 12): read in the
// repository the call runs in, from the words of the call as git's own option parser takes
// them (GIT_OPTIONS in guard.ts). A remote's name gives every URL of it, a word that is no
// remote's name is a URL or a path itself, and with no such word it is the remote git picks
// (defaultRemote), or every remote for `--all` and the like. Each URL is as git rewrites it:
// `insteadOf` for both directions and `pushInsteadOf` for a push (a remote's by `git remote
// get-url`, a word's by `git ls-remote --get-url`, which also reads the legacy files under
// `remotes/` and `branches/`). Where several remotes may be meant (a group) it is all of them.
// `dir` in no repository: a URL on the command line is judged all the same, with your own
// config. Throws, with the reason, when it cannot be told: the call then asks.
function remoteUrls(dir: string, sub: string, rest: string[]): string[] {
  const inRepo = gitRun(["-C", dir, "rev-parse", "--git-dir"]);
  const side = sub === "push" ? "push" : "fetch";
  const unknown = (what: string) => new Error(`cannot tell which remote git ${sub} contacts: ${what}`);
  if (inRepo.status !== 0 && inRepo.status !== 128) throw unknown(`git did not say which repository ${dir} is in`);
  const remotes = inRepo.status === 0 ? readRemotes(dir) : (new Map() as RemoteUrls);
  if (!remotes) throw new Error(`cannot read the remotes of the repository in ${dir}, so where git ${sub} connects`);
  const every = () => [...remotes.values()].flatMap((r) => r[side]);
  // One remote by its name, or a word that is a URL or a path itself.
  const one = (word: string): string[] => {
    const remote = remotes.get(word);
    if (remote) return remote[side];
    if (!word) throw unknown("an empty word stands where the remote is named");
    const asked = gitRun(["-C", dir, "ls-remote", "--get-url", "--", word]);
    const fetched = asked.out.replace(/\n$/, "");
    if (asked.status !== 0 || !fetched) throw unknown(`git could not say where ${word} leads`);
    return [side === "push" ? (pushRewritten(dir, word) ?? fetched) : fetched];
  };
  const named = (word: string): string[] => {
    if (!word) throw unknown("an empty word stands where the remote is named");
    // A group of remotes, for the commands that fetch: any `remotes.<word>` key (the word may
    // hold a dot: `remotes.team.all`), which git looks for before a remote of that name
    // (builtin/fetch.c, add_remote_or_group). A group of one remote or none leaves a fetch of
    // one word with the word itself, so that is judged as well.
    // git compares the word with the key as its config parser hands it over (remote.c,
    // get_remote_group: `strcmp`): the section and the last part in lower case, a subsection as
    // written. A lookup by key would fold the word as well, and find the group `remotes.team`
    // for the remote `Team` (seventh pass): every `remotes.*` key is listed and compared here.
    if (side === "fetch" && sub !== "ls-remote" && inRepo.status === 0) {
      const listed = gitRun(["-C", dir, "config", "--null", "--get-regexp", "^remotes\\."]);
      // 1: no such key.
      if (listed.status !== 0 && listed.status !== 1) throw unknown(`git could not say whether ${word} is a group of remotes`);
      const values = listed.out.split("\0").filter((entry) => (entry.includes("\n") ? entry.slice(0, entry.indexOf("\n")) : entry) === `remotes.${word}`).map((entry) => (entry.includes("\n") ? entry.slice(entry.indexOf("\n") + 1) : ""));
      if (values.length) {
        const members = [...new Set(values.flatMap((value) => value.split(/\s+/)).filter(Boolean))];
        return [...members.flatMap(one), ...(members.length <= 1 ? one(word) : [])];
      }
    }
    return one(word);
  };
  const picked = (): string[] => {
    // In no repository git has no remote to pick, and says so itself.
    if (inRepo.status !== 0) return [];
    const name = defaultRemote(dir, sub);
    if (name === null) throw unknown(`git could not say which one it would pick in ${dir}`);
    return named(name);
  };
  if (sub === "remote") {
    const [op, ...names] = rest.filter((w) => !w.startsWith("-"));
    // `set-head <name> <branch>`: the first word is the remote.
    const remotesNamed = op === "set-head" ? names.slice(0, 1) : names;
    // `git remote update` alone takes the group `remotes.default`, or every remote.
    return remotesNamed.length ? remotesNamed.flatMap(named) : op === "update" ? every() : [];
  }
  const table = sub === "ls-remote" ? LS_REMOTE_OPTIONS : GIT_OPTIONS[sub];
  if (!table) throw unknown("its options are not read here");
  const got = getopt(rest, table);
  if (got.unknown) throw unknown(`${got.unknown} is not an option of git ${sub} that is known here, so which word names the remote cannot be told`);
  const words = got.operands.map((o) => o.word);
  if (sub === "push") {
    // `--repo` stands in for the argument, which takes precedence.
    const repo = lastOf(got, "repo");
    return words.length ? named(words[0]) : repo !== undefined ? named(repo) : picked();
  }
  if (sub === "ls-remote") return words.length ? named(words[0]) : picked();
  // fetch and pull.
  if (lastOf(got, "all") !== undefined) return every();
  if (!words.length) {
    // `fetch.all` makes a fetch with no remote named go to every one (git 2.44).
    const all = inRepo.status === 0 ? configBool(dir, "fetch.all") : false;
    return all === true || all === null ? every() : picked();
  }
  return sub === "fetch" && lastOf(got, "multiple", "m") !== undefined ? words.flatMap(named) : named(words[0]);
}

// Where the pushes of a git-only call go, when that is a repository on this machine: the paths,
// for the plan to grant (a push also works in the repository it pushes to; round 4, finding 21,
// decision 1). The URLs are the ones remoteUrls reads: the remote git takes from the command
// line in every spelling of its options, or the one it picks, every push URL of it, each as git
// rewrites it (a URL that `pushInsteadOf` turns into a path is that path). Git resolves a
// relative path from the top of the work tree. Throws, with the reason, when the remote or its
// URLs cannot be told (an option git does not have among them): the call then asks.
export function pushDestinations(command: string, cwd: string): string[] {
  const out: string[] = [];
  for (const { dir, sub, rest } of gitEnds(command, cwd)) {
    if (sub !== "push") continue;
    // In no repository: git says so itself.
    if (gitRun(["-C", dir, "rev-parse", "--git-dir"]).status === 128) continue;
    const urls = remoteUrls(dir, "push", rest);
    const top = gitRun(["-C", dir, "rev-parse", "--show-toplevel"]);
    const base = top.status === 0 ? top.out.trim() : dir;
    for (const url of urls) {
      const local = localUrl(url);
      if (local === undefined) continue;
      if (/^~[^/]/.test(local)) throw new Error(`cannot tell which directory the push destination ${local} names`);
      out.push(path.resolve(base, tilde(local)));
    }
  }
  return [...new Set(out)];
}
// An allowed git-only call that may still be running. `subs`: the subcommands it is made of,
// which the operation state it leaves is checked against (round 3, finding 33). `before`: per
// git directory it may write, whether `commondir` and `config.worktree` were there when its
// shell was allowed to start (quarantineGitFiles; round 4, finding 21). `done` once no process
// of it is left; the next check is the last that counts it.
export interface GitCall {
  before: Map<string, ReturnType<typeof controlFiles>>;
  // Paths that were not there when the call started and must not be when it is over (the
  // plan's `gitWatch`).
  watch?: string[];
  subs: Set<string>;
  at: number;
  done?: boolean;
}
// Notes a git-only call that is about to run with a writable `.git`; undefined for any other call.
// `dirs`: the git directories it may write (the plan's `gitDirs`). A lookup there that fails is
// thrown: without the record nothing could be compared when the call is over.
// `watch`: the plan's `gitWatch`.
export function noteGitCall(session: SessionState, command: string, dirs = [...(session.snapshot?.inside.keys() ?? [])], watch: string[] = []): GitCall | undefined {
  const read = gitOnlyRead(command);
  if (!read) return undefined;
  const subs = new Set<string>();
  for (const full of read.cmds) {
    const argv = full[0] === "timeout" ? full.slice(2) : full;
    if (argv[0] !== "git") continue;
    const call = gitCall(argv.slice(1));
    if (typeof call !== "string" && call.sub) subs.add(call.sub);
  }
  const entry: GitCall = { subs, before: new Map(dirs.map((dir) => [dir, controlFiles(dir)])), watch: watch.filter((p) => !controlExists(p)), at: Date.now() };
  session.gitCalls.push(entry);
  return entry;
}

// The options a fetch, pull or ls-remote may carry and still get the ssh agent. The first line
// keeps git out of submodules, in the spellings git takes (`git fetch -h`, `git pull -h`).
const FETCH_FLAGS = new Set([
  "--no-recurse-submodules", "--recurse-submodules=no", "--recurse-submodules=false", "--recurse-submodules=off", "--recurse-submodules=0",
  "-q", "--quiet", "-v", "--verbose", "--all", "-p", "--prune", "-t", "--tags", "--no-tags", "-f", "--force", "-n", "--dry-run", "--rebase", "--no-rebase", "--ff-only", "--ff",
  "--no-ff", "--autostash", "--no-autostash", "--progress", "--no-progress", "--heads", "--refs", "--symref", "--exit-code", "--porcelain", "--atomic",
]);

// Whether `git fetch` or `git pull` with these words may go into cloned submodules (it does so
// on demand, by config and by `.gitmodules`, which a sandboxed command can write): unless it
// says not to, in one of the spellings git takes, and as its last word on the matter.
const mayRecurse = (words: string[]) => {
  const said = words.filter((w) => /^--(no-)?recurse-submodules/.test(w)).at(-1);
  return said === undefined || !/^--(no-recurse-submodules|recurse-submodules=(no|false|off|0))$/.test(said);
};

// The git directories of the submodules cloned for the repository `dir` is in, wherever git
// keeps them (round 4, finding 25, decision 3): under `modules/` of the common directory and of
// a linked worktree's own git directory, at any depth and whether or not `.gitmodules` names
// them (read from disk); and in a submodule's own work tree (`lib/.git` a directory, a gitlink
// in the index), among the repositories the session's snapshot knows. Empty when `dir` is in
// no repository. Undefined when it cannot be told: a lookup that fails, or a symbolic link
// below `modules/`, or more rounds of modules within submodules than `submoduleRounds` (giving
// up is "cannot tell", not what was found so far; seventh pass).
// `inModules`: the ones found under a `modules/` directory, which git ties to their work trees by
// a `core.worktree` in their config. `outside`: the ones a work tree leads to by itself (`lib/.git`
// a directory, or a `.git` file that points anywhere else), whose config holds no such key.
export const submoduleRounds = { max: 20 };
function clonedSubmodules(dir: string, session: SessionState): string[] | undefined {
  const found = submoduleDirs(dir, session);
  return found && [...new Set([...found.inModules, ...found.outside])];
}
function submoduleDirs(dir: string, session: SessionState): { inModules: string[]; outside: string[] } | undefined {
  const common = gitRun(["-C", dir, "rev-parse", "--path-format=absolute", "--git-common-dir"]);
  const gitDir = gitRun(["-C", dir, "rev-parse", "--absolute-git-dir"]);
  if (common.status === 128 && gitDir.status === 128) return { inModules: [], outside: [] };
  if (common.status !== 0 || gitDir.status !== 0) return undefined;
  const found: string[] = [];
  let unsure = false;
  const walk = (at: string) => {
    let list: fs.Dirent[];
    try {
      list = fs.readdirSync(at, { withFileTypes: true });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") unsure = true;
      return;
    }
    // A leftover directory without a `HEAD` is no repository; one with it may hold submodules
    // of its own.
    if (list.some((e) => e.name === "HEAD")) {
      found.push(at);
      return walk(path.join(at, "modules"));
    }
    for (const e of list) {
      if (e.isSymbolicLink()) unsure = true;
      else if (e.isDirectory()) walk(path.join(at, e.name));
    }
  };
  for (const base of new Set([common.out.trim(), gitDir.out.trim()])) walk(path.join(base, "modules"));
  if (unsure) return undefined;
  // The work trees whose index names submodules: this repository's, and those of the submodules
  // found so far (a bare repository has none). A submodule kept outside `modules/` (in its own
  // work tree, or wherever its `.git` file points) may hold modules of its own
  // (`lib/.git/modules/inner`), and those work trees of their own: round and round until
  // nothing new is found.
  const top = gitRun(["-C", dir, "rev-parse", "--show-toplevel"]);
  const outside = new Set<string>();
  const walked = new Set<string>();
  let settled = false;
  for (let round = 0; round < submoduleRounds.max && !settled; round++) {
    const tops = top.status === 0 ? [realpath(top.out.trim())] : [];
    for (const module of found) {
      const worktree = gitRun([...inGitDir(module), "config", "--get", "core.worktree"]);
      if (worktree.status === 0) tops.push(realpath(path.resolve(module, worktree.out.trim())));
    }
    const inTree = workTreeSubmodules(tops, session.snapshot?.inside.keys() ?? [], session.snapshot?.tops);
    if (inTree.problem) return undefined;
    const fresh = inTree.dirs.filter((module) => !walked.has(module));
    settled = !fresh.length;
    for (const module of fresh) {
      walked.add(module);
      if (!found.includes(module)) outside.add(module);
      walk(path.join(module, "modules"));
    }
    if (unsure) return undefined;
  }
  // The rounds ran out with something still turning up.
  if (!settled) return undefined;
  return { inModules: [...new Set(found)], outside: [...outside].filter((module) => !found.includes(module)) };
}

// Whether a `git push` here goes into submodules by its config: `push.recurseSubmodules` (any
// value but no) and `submodule.recurse` (true) both set the one variable git reads, so the last
// of them in the order git reads its config counts (builtin/push.c, git_push_config). In each
// submodule git then runs a push, or a check, with that submodule's own config.
function pushRecurses(config: [string, string, string][]): boolean {
  const last = config.filter(([, key]) => key === "push.recursesubmodules" || key === "submodule.recurse").at(-1);
  return !!last && !/^(no|false|off|0|)$/i.test(last[2].trim());
}

// Whether a tool call gets the ssh agent and ~/.ssh's known_hosts/config (never private keys):
// only a single plain `git fetch/pull/push/ls-remote` at the top of the project's own checkout,
// to a remote that was configured when the session started, with options from a short list and
// no hook that would run; or a single `ssh`/`scp` command (which the rules only allow for
// sshHosts). A fetch or pull that may go into cloned submodules gets none: their config and
// hooks are held to neither list (decision 3; `--no-recurse-submodules` is the way through).
// `recursing`: leave that last test out, to tell whether it alone is why (sandboxBreaks).
export function usesSsh(command: string, cwd: string, session: SessionState, recursing = true): boolean {
  projectRoots(session);
  const s = single(command, cwd);
  if (!s) return false;
  if (s.argv[0] === "ssh" || s.argv[0] === "scp") return true;
  const call = plainGit(s, /^(fetch|pull|push|ls-remote)$/);
  if (!call) return false;
  if (recursing && (call.sub === "fetch" || call.sub === "pull") && mayRecurse(call.words) && clonedSubmodules(call.dir, session)?.length !== 0) return false;
  // A push that goes into cloned submodules gets none either: their config is held to no list.
  // (The options that say so on the command line are not among PUSH_SAFE_FLAGS.)
  const settings = call.sub === "push" ? readConfig(call.dir) : [];
  if (call.sub === "push" && (!settings || pushRecurses(settings)) && clonedSubmodules(call.dir, session)?.length !== 0) return false;
  const flags = call.words.filter((w) => w.startsWith("-"));
  const allowed = call.sub === "push" ? PUSH_SAFE_FLAGS : FETCH_FLAGS;
  if (!flags.every((f) => allowed.has(f) || /^--depth=\d+$/.test(f))) return false;
  // The top of a checkout of the project: not a directory below it, which another command
  // running at the same time could replace with a link to a repository of its own.
  if (!atRoot(call.dir, session)) return false;
  // The project's own repository, not one pointed elsewhere; its config must not change how
  // git connects; and the remote must be one it had from the start, by name (a path or URL
  // such as `ext::cmd` would make git run a program).
  const config = ownRepository(call.dir, session);
  const known = session.snapshot?.remotes;
  if (!config || !known?.size || hookWouldRun(call.dir, call.sub, config)) return false;
  const [remote, ...refs] = call.words.filter((w) => !w.startsWith("-"));
  // With no remote named, git picks one: every remote for --all, else the branch's or `origin`.
  const picked = remote ?? (flags.includes("--all") ? undefined : defaultRemote(call.dir, call.sub));
  if (picked === null) return false;
  const names = picked === undefined ? [...known.keys()] : [picked];
  const now = readRemotes(call.dir);
  if (picked === undefined && now?.size !== known.size) return false;
  if (!names.every((n) => known.has(n) && sameUrls(known, now, n)) || !refs.every((r) => /^[\w.\/@:+^~-]+$/.test(r))) return false;
  // And only for a call every URL of which is a network URL (finding 25, sixth pass): a path on
  // this machine is a repository whose own hooks git runs, a transport helper is a program.
  try {
    const urls = remoteUrls(call.dir, call.sub, call.words);
    return urls.length > 0 && urls.every(networkUrl);
  } catch {
    return false;
  }
}

const SSH_URL = /^(ssh:\/\/|git\+ssh:\/\/|ssh\+git:\/\/|[\w.-]+@[\w.-]+:|[\w.-]+:(?!\/\/))/;
// Whether the call contacts a remote: the network commands, and `git remote` that fetches or asks
// the remote (`update`, `prune`, `show`, `set-head -a`).
function contactsRemote(sub: string, rest: string[]): boolean {
  if (["fetch", "pull", "push", "ls-remote"].includes(sub)) return true;
  if (sub !== "remote") return false;
  const op = rest.find((w) => !w.startsWith("-"));
  return op === "update" || op === "prune" || op === "show" || (op === "set-head" && rest.some((w) => /^(-a|--auto)$/.test(w)));
}

// Every git command (`git --list-cmds=main,others`, 2.47) that writes inside the git directory
// (round 3, finding 27), and whether a git-only call may run it with a writable `.git`
// ("git-only": its options can neither run a program nor write outside `.git` and the work tree,
// and it does what an agent does every day) or it asks ("asks": it is rare, writes objects or
// config by hand, or can run a program). Commands not listed only read, or write nowhere near
// `.git` (clean, format-patch, archive, merge-file, mailsplit, unpack-file), or are asked about
// by the rules or DEFAULT_ASK whatever the sandbox (config, init, clone, sparse-checkout,
// filter-branch, submodule add/update/init, worktree add/move/remove). `undefined`: reads only.
type GitWrite = "git-only" | "asks";
const GIT_WRITE: Record<string, GitWrite | ((words: string[], rest: string[]) => GitWrite | undefined)> = {
  add: "git-only", commit: "git-only", checkout: "git-only", switch: "git-only", reset: "git-only", merge: "git-only", "cherry-pick": "git-only", revert: "git-only",
  rebase: "git-only", fetch: "git-only", pull: "git-only", push: "git-only", mv: "git-only", rm: "git-only", gc: "git-only", prune: "git-only", "pack-refs": "git-only", "update-index": "git-only",
  // `restore` without --staged writes only the work tree, but is listed as before.
  restore: "git-only",
  stash: (words) => (["list", "show"].includes(words[0] ?? "") ? undefined : "git-only"),
  branch: (words, rest) => (words.length > 0 && !rest.some((w) => /^(-l|--list|-a|--all|-r|--remotes|--contains|--merged|--no-merged|--show-current|--points-at)$/.test(w)) ? "git-only" : undefined),
  tag: (words, rest) => (words.length > 0 && !rest.some((w) => /^(-l|--list|-n\d*|--contains|--no-contains|--merged|--no-merged|--points-at|-v|--verify)$/.test(w)) ? "git-only" : undefined),
  notes: (words) => (["list", "show", undefined].includes(words[0]) ? undefined : "git-only"),
  // `remote update` and `prune` fetch or drop remote-tracking refs, `set-head` writes one; the
  // rest change config (`set-branches`; add, set-url, rename and remove ask by the rules).
  remote: (words) => (["update", "prune", "set-head"].includes(words[0] ?? "") ? "git-only" : ["set-branches", "add", "set-url", "rename", "rm", "remove"].includes(words[0] ?? "") ? "asks" : undefined),
  // A bisect writes its refs and state; `run` runs a command, `visualize`/`view` a viewer, and
  // `replay` follows a file of steps.
  bisect: (words) => (["log", "help"].includes(words[0] ?? "") ? undefined : ["start", "bad", "good", "new", "old", "skip", "reset", "terms", "next"].includes(words[0] ?? "") ? "git-only" : "asks"),
  // The index with --index, --cached or --3way; `--unsafe-paths` writes outside the work tree and
  // `--build-fake-ancestor` writes an index file of the caller's choosing.
  apply: (_words, rest) => (rest.some((w) => /^--(unsafe-paths|build-fake-ancestor)/.test(w)) ? "asks" : rest.some((w) => /^(--index|--cached|-3|--3way|--intent-to-add|-N)$/.test(w)) ? "git-only" : undefined),
  "symbolic-ref": (words, rest) => (words.length >= 2 || rest.some((w) => /^(-d|--delete)$/.test(w)) ? "git-only" : undefined),
  am: "asks", stage: "asks", "update-ref": "asks", "commit-tree": "asks", "commit-graph": "asks", "multi-pack-index": "asks", "fast-import": "asks", "fetch-pack": "asks", "send-pack": "asks",
  "index-pack": "asks", "pack-objects": "asks", "prune-packed": "asks", repack: "asks", "read-tree": "asks", "write-tree": "asks", mktag: "asks", mktree: "asks", replace: "asks", replay: "asks",
  rerere: "asks", "merge-index": "asks", "merge-octopus": "asks", "merge-one-file": "asks", "merge-ours": "asks", "merge-recursive": "asks", "merge-recursive-ours": "asks",
  "merge-recursive-theirs": "asks", "merge-resolve": "asks", "merge-subtree": "asks", "merge-tree": "asks", mergetool: "asks", quiltimport: "asks", maintenance: "asks", "unpack-objects": "asks",
  "update-server-info": "asks", "checkout-index": "asks", subtree: "asks", refs: (words) => (words[0] === "verify" ? undefined : "asks"),
  "hash-object": (_words, rest) => (rest.some((w) => /^-[a-zA-Z]*w$/.test(w)) ? "asks" : undefined),
  bundle: (words) => (words[0] === "unbundle" ? "asks" : undefined),
  fsck: (_words, rest) => (rest.some((w) => /^--lost-found$/.test(w)) ? "asks" : undefined),
  submodule: (words) => (["absorbgitdirs", "set-branch", "set-url", "add", "update", "init", "deinit", "sync"].includes(words[0] ?? "") ? "asks" : undefined),
  worktree: (words) => (["list"].includes(words[0] ?? "") ? undefined : "asks"),
  reflog: (words) => (["expire", "delete", "write", "drop"].includes(words[0] ?? "") ? "asks" : undefined),
};
// Whether the subcommand writes inside the git directory, and how (see GIT_WRITE).
function gitWrite(sub: string, rest: string[]): GitWrite | undefined {
  const entry = Object.hasOwn(GIT_WRITE, sub) ? GIT_WRITE[sub] : undefined;
  return typeof entry === "function" ? entry(rest.filter((w) => !w.startsWith("-")), rest) : entry;
}
const writesGit = (sub: string, rest: string[]) => gitWrite(sub, rest) !== undefined;

// "Allowed" must mean the command can work. These are allowed by the rules and then fail in
// the sandbox, with an error the agent cannot do anything about: git writing its own directory
// from a call that is not made only of plain git commands, git signing with a key the sandbox
// hides, git logging in over ssh without the agent or over https through a credential helper.
// Each asks instead, so that an approved run happens outside the sandbox.
// Round 4, finding 12 (signed off): programs that work only with something the sandbox hides
// from every command, each with what that is: `gh` (its login in ~/.config/gh, and the GH_*
// variables), `docker` (the daemon's socket) and the clients of the system and session bus.
// While the sandbox is on they ask, so that an approved run happens outside it; showing them
// their credentials or sockets would give every allowed command the same reach. Asking for the
// version or the help needs none of it.
const NEEDS_OUTSIDE: Record<string, string> = {
  gh: "needs your GitHub login, which the sandbox hides from every command",
  docker: "needs the Docker daemon's socket, which the sandbox hides from every command",
};
for (const client of ["systemctl", "loginctl", "busctl", "hostnamectl", "timedatectl", "localectl", "resolvectl", "machinectl", "dbus-send", "gdbus"]) {
  NEEDS_OUTSIDE[client] = "talks to the system or session bus, which the sandbox hides from every command";
}
function needsOutside(cmds: Simple[]): string | undefined {
  for (const { argv } of cmds) {
    for (const at of programs(argv)) {
      const name = path.basename(argv[at]);
      if (!Object.hasOwn(NEEDS_OUTSIDE, name)) continue;
      const args = argv.slice(at + 1);
      if (args.length === 1 && /^(--version|--help|-h)$/.test(args[0])) continue;
      return `${name} ${NEEDS_OUTSIDE[name]}; an approved run happens outside the sandbox`;
    }
  }
  return undefined;
}

// `git reset`'s options (git 2.47.3: `git reset --git-completion-helper-all` and `-h`), read as
// the tables in guard.ts are.
const RESET_OPTIONS: Getopt = {
  flags: "qpN",
  long: { quiet: "flag", refresh: "flag", mixed: "flag", soft: "flag", hard: "flag", merge: "flag", keep: "flag", "recurse-submodules": "optional", patch: "flag", "intent-to-add": "flag", "pathspec-from-file": "value", "pathspec-file-nul": "flag" },
  negatable: (name) => !["mixed", "soft", "hard", "merge", "keep"].includes(name),
};
const moveOptions = (sub: string): Getopt => (sub === "reset" ? RESET_OPTIONS : GIT_OPTIONS[sub]);

// What a `pull`, `switch`, `checkout` or `reset` says about going into submodules: the last of
// its `--[no-]recurse-submodules` spellings as git reads them. Undefined when it says nothing
// (the config then decides), null when its options cannot be read.
function saysRecurse(sub: string, rest: string[]): boolean | undefined | null {
  const got = getopt(rest, moveOptions(sub));
  if (got.unknown) return null;
  const last = got.opts.filter((o) => o.name === "--recurse-submodules" || o.name === "--no-recurse-submodules").at(-1);
  if (!last) return undefined;
  return last.name === "--recurse-submodules" && !/^(no|false|off|0)$/i.test(last.value ?? "");
}

// Whether a `git merge`, `cherry-pick`, `revert` or `am` aborts: `--abort`, in any spelling git's
// option parser takes for it (a prefix down to `--ab`), and not as the text of a message.
function abortsWithMerge(sub: string, rest: string[]): boolean {
  if (!["merge", "cherry-pick", "revert", "am"].includes(sub)) return false;
  const messages = new Set(gitMessageWords([sub, ...rest]).filter((m) => !m.attached).map((m) => m.at - 1));
  return rest.some((w, k) => !messages.has(k) && /^--ab(o(r(t)?)?)?$/.test(w));
}

// The commit a `git switch` or `git checkout` moves to. Undefined: it stays on the commit it is
// on (a new branch with no start point, `--detach` alone). Null: it cannot be told from the
// words, or the call does more than move from one commit to another (it discards changes, takes
// paths, merges, makes an orphan branch).
//
// A `git reset` moves the work tree only with `--keep`, `--merge` or `--hard`, the last of them
// on the line counting: for `--keep` the commit it names, or the one it is on. `--hard` discards
// changes and `--merge` rewrites every submodule's entry (null). `--soft`, `--mixed` and a reset of paths leave the work tree, and every submodule in
// it, as they are (undefined).
function moveTarget(sub: string, rest: string[]): string | undefined | null {
  const got = getopt(rest, moveOptions(sub));
  if (sub === "reset") {
    if (got.unknown) return null;
    const mode = got.opts.filter((o) => ["--mixed", "--soft", "--hard", "--merge", "--keep"].includes(o.name)).at(-1)?.name;
    if (mode !== "--keep" && mode !== "--merge" && mode !== "--hard") return undefined;
    const commits = got.operands.map((o) => o.word);
    // `--merge` goes into the submodules even where it names the commit it is on (seventh pass;
    // run under the wrapper, xcheck/reviewers/c6-sonnet/x-p5.test.mts): like `--hard`, it cannot
    // be shown to move none.
    if (mode === "--hard" || mode === "--merge" || rest.includes("--") || commits.length > 1) return null;
    return commits[0];
  }
  if (got.unknown || rest.includes("--")) return null;
  const has = (...names: string[]) => got.opts.some((o) => names.includes(o.name));
  if (has("-f", "--force", "--discard-changes", "-m", "--merge", "--orphan", "--conflict", "-p", "--patch", "--ours", "--theirs", "-2", "-3", "--pathspec-from-file", "--overlay", "--no-overlay")) return null;
  const words = got.operands.map((o) => o.word);
  if (words.length > 1) return null;
  if (!words.length) return sub === "checkout" || has("-c", "-C", "--create", "--force-create", "-d", "--detach") ? undefined : null;
  return words[0] === "-" ? "@{-1}" : words[0];
}

// A git call that goes into submodules and cannot work in the sandbox (round 4, finding 21;
// each built and run under the wrapper with git 2.47.3, xcheck/c5/p3-submodules.mts):
//   - `git pull` that updates submodules (`--recurse-submodules`, or `submodule.recurse`; not
//     `fetch.recurseSubmodules`, which is the fetch's alone) runs `git submodule update`, which
//     sets `core.worktree` in the config of each submodule kept under `.git/modules`, whatever
//     the pull brought. A git directory's config is read-only in every sandbox. A submodule kept
//     in its own work tree is updated without that, and works.
//   - `git switch` and `git checkout` that go into submodules (`--recurse-submodules`, or
//     `submodule.recurse`) and move one to another commit rewrite its `.git` pointer file, or
//     first move a git directory kept in the work tree under `.git/modules`; the sandbox keeps
//     both in place. Where no submodule's recorded commit differs between HEAD and the target,
//     git touches none, and the call works.
//   - `git reset --keep <commit>` and `--merge <commit>` update the work tree the same way, and
//     fail the same way (sixth pass; run by a reviewer, xcheck/reviewers/c5/p3-moves.mts).
// Only in a repository with a cloned submodule (clonedSubmodules); what cannot be told asks.
//   - `git merge --abort`, `git cherry-pick --abort`, `git revert --abort` and `git am --abort`
//     each reset with `--merge` inside git, and under `submodule.recurse` fail as that does
//     (eighth pass; each run under the wrapper on both sides, xcheck/c8/probes/p2-wrapper.log:
//     exit 128 with the submodule under `.git/modules` and in its own work tree, exit 0 without
//     recursion). `git rebase --abort` and `git merge --quit` do not, and run.
//   - A pull that updates a submodule kept outside `modules/` works only where git can write that
//     git directory, and where its config sets no `core.worktree`: git rewrites that key in the
//     config of every submodule that has one, whatever it holds (builtin/submodule--helper.c,
//     ensure_core_worktree; run: "could not set 'core.worktree'"). `writable`: the directories
//     the sandbox leaves writable besides the project's own and the temp directories.
function submoduleBreak(c: { sub: string; rest: string[]; dir: string }, session: SessionState, writable: string[] = []): string | undefined {
  const aborting = abortsWithMerge(c.sub, c.rest);
  if (!aborting && c.sub !== "pull" && c.sub !== "switch" && c.sub !== "checkout" && c.sub !== "reset") return undefined;
  const said = aborting ? undefined : saysRecurse(c.sub, c.rest);
  const configured = said === undefined ? configBool(c.dir, "submodule.recurse") : undefined;
  if (said === false || (said === undefined && (configured === false || configured === undefined))) return undefined;
  const dirs = submoduleDirs(c.dir, session);
  const modules = dirs && [...dirs.inModules, ...dirs.outside];
  if (modules && !modules.length) return undefined;
  const how = said ? "--recurse-submodules" : said === null ? "its options could not be read, so it may" : configured ? "submodule.recurse is set" : "submodule.recurse could not be read, so it may";
  const outside = "an approved run happens outside the sandbox";
  if (aborting) return `git ${c.sub} --abort resets with --merge, which goes into the cloned submodules here (${how}) and rewrites their .git files or moves their git directories, both of which the sandbox keeps in place; ${outside}`;
  if (c.sub === "pull") {
    const without = "Add --no-recurse-submodules to pull without updating them";
    // The ones under `modules/`: git ties each to its work tree by a `core.worktree` in its config.
    if (!dirs || dirs.inModules.length) return `git pull would update the cloned submodules (${how}), which rewrites the config in their git directories under .git/modules, and the sandbox keeps git's config read-only. ${without}; ${outside}`;
    // A submodule kept in its own work tree (`lib/.git` a directory), or wherever its `.git` file
    // points outside `modules/`, is updated without that (seventh pass), where its git directory
    // can be written and its config holds no such key (eighth pass).
    const roots = [...projectRoots(session), ...writable, "/tmp", "/var/tmp", os.tmpdir()].map(realpath);
    for (const module of dirs.outside) {
      if (!roots.some((root) => within(realpath(module), root))) return `git pull would update the cloned submodule whose git directory is ${module} (${how}), and that lies outside the project, the allowed paths and the temp directories, where the sandbox keeps everything read-only: the pull would fail halfway. ${without}; ${outside}`;
      // 1: no such key. Anything else that is not a value is no knowledge.
      const worktree = gitRun([...inGitDir(module), "config", "--get", "core.worktree"]);
      if (worktree.status !== 1) return `git pull would update the cloned submodule whose git directory is ${module} (${how}), and its config ${worktree.status === 0 ? "sets core.worktree" : "could not be read for core.worktree"}: git rewrites that key on every update, and the sandbox keeps git's config read-only. ${without}; ${outside}`;
    }
    return undefined;
  }
  const target = moveTarget(c.sub, c.rest);
  if (target === undefined) return undefined;
  if (target !== null) {
    // The submodule entries (mode 160000) that differ between the commit git is on and the target.
    const diff = gitRun(["-C", c.dir, "diff-tree", "-r", "--raw", "-z", "--no-renames", "HEAD", target, "--"]);
    if (diff.status === 0 && !/(^|\0):(160000 \d+|\d+ 160000) /.test(diff.out)) return undefined;
  }
  return `git ${c.sub} goes into the cloned submodules here (${how}) and ${target === null ? "it cannot be told that it moves none of them" : `would move one to another commit (or ${target} could not be compared with HEAD)`}; moving a submodule rewrites its .git file or moves its git directory, both of which the sandbox keeps in place. Add --no-recurse-submodules to leave the submodules as they are; ${outside}`;
}

// `writable`: the directories the sandbox leaves writable besides the project's own and the temp
// directories (the allowed paths and `sandboxWritable`), for the checks that ask whether git
// could write a git directory.
export function sandboxBreaks(command: string, cwd: string, session: SessionState, writable: string[] = []): string | undefined {
  // Each git call with the repository it names (round 4, finding 12): the directory its command
  // runs in (a plain `cd` followed) and then its `-C` words. Where that cannot be told the
  // project stands in, as before.
  // `conf`: the `-c key=value` words of the call itself (second pass: `git -c commit.gpgsign=true
  // commit`), which git reads after the repository's config.
  const calls: { sub: string; rest: string[]; dir: string; conf: string[] }[] = [];
  const read = gitOnlyRead(command);
  const where = located(command, realish(cwd));
  const outside = needsOutside(where.cmds);
  if (outside) return outside;
  for (const cmd of where.cmds) {
    cmd.argv.forEach((word, at) => {
      if (path.basename(word) !== "git") return;
      const call = gitCall(cmd.argv.slice(at + 1));
      if (typeof call === "string" || !call.sub) return;
      // Where bash is by then, and git's own `-C` words from there, each a chdir (gitPlace).
      let dir = session.project;
      if (!call.dirs.some((d) => /[$`*?[\]]/.test(d) || /^~[^/]/.test(d))) {
        try {
          dir = gitPlace(where.places.get(cmd), call.dirs);
        } catch {
          // Cannot be told: the project stands in. Where the command's own directory is known
          // and it is a `-C` word that leads nowhere, the directory is the one the words spell:
          // the checks below cannot read a repository there, and so ask (`git -C nowhere commit`).
          const from = where.cwd.get(cmd);
          if (from !== undefined) dir = call.dirs.reduce((to, d) => path.resolve(to, tilde(d)), from);
        }
      }
      const conf: string[] = [];
      const globals = cmd.argv.slice(at + 1, cmd.argv.length - call.rest.length - 1);
      for (let i = 0; i < globals.length; i++) {
        if (globals[i] === "-C") i++;
        else if (globals[i] === "-c" && i + 1 < globals.length) conf.push(globals[++i]);
      }
      calls.push({ sub: call.sub, rest: call.rest, dir, conf });
    });
  }
  if (!calls.length) return undefined;
  const writer = calls.find((c) => writesGit(c.sub, c.rest));
  if (writer && !read) return `git ${writer.sub} writes inside .git, which is read-only unless the tool call is made only of plain git commands`;
  // Signing and verifying need keys or keyrings the sandbox hides (round 3, finding 27): a set
  // config key (true, or one git could not read) asks. Read in the repository each call names,
  // by git itself with the call's own `-c` words, so that the command line counts as git counts
  // it: after the files, the last one winning, in any spelling of the key or of the value.
  const value = (c: { dir: string; conf: string[] }, key: string, type: string[]) => {
    const r = gitRun(["-C", c.dir, ...c.conf.flatMap((kv) => ["-c", kv]), "config", ...type, "--get", key]);
    return r.status === 0 ? r.out.trim() : r.status === 1 ? undefined : null;
  };
  const on = (c: { dir: string; conf: string[] }, key: string) => {
    const v = value(c, key, ["--type=bool"]);
    return v !== "false" && v !== undefined;
  };
  const signed = "git signs here, and the sandbox hides the keys and the agents that hold them";
  const commits = calls.filter((c) => ["commit", "merge", "rebase", "cherry-pick", "revert", "am", "pull"].includes(c.sub));
  if (commits.some((c) => on(c, "commit.gpgsign") || on(c, "rebase.gpgsign"))) return "git signs commits here, and the sandbox hides the keys and the agents that hold them";
  if (commits.some((c) => c.rest.some((w) => /^(-[a-zA-Z]*S|--gpg-sign)/.test(w)))) return signed;
  if (commits.some((c) => (c.sub === "merge" || c.sub === "pull") && (c.rest.includes("--verify-signatures") || on(c, "merge.verifysignatures")))) return "git checks signatures here, and the sandbox hides the keyrings it needs";
  const tags = calls.filter((c) => c.sub === "tag" && writesGit(c.sub, c.rest) && !c.rest.some((w) => /^(-d|--delete)$/.test(w)));
  if (tags.some((c) => c.rest.some((w) => /^(-[a-zA-Z]*[su]|--sign|--local-user)/.test(w)))) return signed;
  if (tags.some((c) => on(c, "tag.gpgsign"))) return signed;
  if (tags.some((c) => c.rest.some((w) => /^(-[a-zA-Z]*[amF]|--annotate|--message|--file)/.test(w)) && on(c, "tag.forcesignannotated"))) return signed;
  // push.gpgSign is a boolean or `if-asked`; unset or false signs nothing.
  const pushSign = (c: { dir: string; conf: string[] }) => {
    const v = value(c, "push.gpgsign", []);
    return v === null || (v !== undefined && !/^(false|no|off|0)$/i.test(v));
  };
  if (calls.some((c) => c.sub === "push" && (c.rest.some((w) => /^--signed(=(?!false|no|off|0$).*)?$/.test(w)) || pushSign(c)))) return signed;
  // A pull, switch or checkout that goes into submodules and cannot work there (finding 21).
  for (const c of calls) {
    const recursion = submoduleBreak(c, session, writable);
    if (recursion) return recursion;
  }
  const contacting = calls.filter((c) => contactsRemote(c.sub, c.rest));
  if (!contacting.length) return undefined;
  // Each call that contacts a remote is judged by the URLs it will use, read in the repository
  // it names (round 4, finding 12): a URL on the command line, the named remote's, or those of
  // the remote git picks. `at`: where git looks the credential helper up for the URL.
  const urls: { url: string; at: string[] }[] = [];
  for (const c of contacting) {
    try {
      for (const url of remoteUrls(c.dir, c.sub, c.rest)) urls.push({ url, at: ["-C", c.dir] });
    } catch (e) {
      return (e as Error).message;
    }
  }
  // A fetch or pull that may go into cloned submodules uses their remotes as well (the call is
  // git-only by now, so the directories its git commands end in can be read).
  let cloned = false;
  // What could not be read of them: it asks, once the agent's own reason has had its say.
  let unread: string | undefined;
  if (read && calls.some((c) => (c.sub === "fetch" || c.sub === "pull") && mayRecurse(c.rest))) {
    const outOf = "add --no-recurse-submodules to fetch or pull without them";
    let ends: string[];
    try {
      ends = gitDirectories(command, cwd);
    } catch (e) {
      return (e as Error).message;
    }
    for (const at of ends) {
      const modules = clonedSubmodules(at, session);
      if (!modules) unread ??= `cannot tell which cloned submodules a fetch or pull in ${at} would go into, and so what it would need; ${outOf}`;
      for (const module of modules ?? []) {
        const remotes = readRemotes(module, true);
        if (!remotes) unread ??= `cannot read the remotes of the cloned submodule in ${module}, which a fetch or pull may go into; ${outOf}`;
        for (const url of [...(remotes?.values() ?? [])].flatMap((r) => [...r.fetch, ...r.push])) urls.push({ url, at: inGitDir(module) });
      }
      if (!modules || modules.length) cloned = true;
    }
  }
  if (urls.some(({ url }) => SSH_URL.test(url)) && !usesSsh(command, cwd, session)) {
    // The submodules are the reason only when the call would have had the agent without them.
    if (cloned && usesSsh(command, cwd, session, false)) return "the repository has cloned submodules whose config and hooks are not checked, so a fetch or pull that may go into them does not get your ssh agent. Add --no-recurse-submodules to fetch or pull without them";
    return "git would need your ssh agent, which only a single plain git fetch, pull, push or ls-remote at the top of the project gets (and only when no hook would run)";
  }
  if (unread) return unread;
  // Each URL as git looks the helper up for it: `credential.<url>.helper` (what `gh auth setup-git`
  // writes) as well as `credential.helper` (round 3, finding 17). Exit 1 is "none"; anything else
  // that is not a value asks.
  const helper = ({ url, at }: { url: string; at: string[] }) => gitRun([...at, "config", "--get-urlmatch", "credential.helper", url]).status !== 1;
  if (urls.some((u) => /^https?:\/\//.test(u.url) && helper(u))) return "git would log in through a credential helper, and the sandbox hides what credential helpers use";
  return undefined;
}

// Programs whose operands are written to: every one of them, or only the last.
const WRITER_OPERANDS: Record<string, "all" | "last"> = {
  cp: "last", ln: "last", install: "last", rsync: "last",
  mv: "all", tee: "all", truncate: "all", touch: "all", mkdir: "all", rmdir: "all", chmod: "all", chown: "all", chgrp: "all", setfacl: "all", shred: "all", unlink: "all", patch: "all", rm: "all", sed: "all",
};

// The writers that keep the name of a file that is already there (round 4, N3): they remove it,
// change its mode or owner, or edit it in place. Every other write makes the file it names.
const NAME_KEEPERS = new Set(["rm", "rmdir", "unlink", "shred", "chmod", "chown", "chgrp", "setfacl", "sed", "patch", "perl", "ruby", "yq", "jq"]);

// A write the rules' Matchers do not see as one: into a path with a `.git` component (a new
// repository, or a link named `.git`), opencode's project files or a hook manager's files. The
// targets are redirects and the operands of the programs that write.
// B7-7: and the place the write lands in, where the command runs (`dirsOf`: each directory it may
// run in; `roots`: the project's): `cd .git/hooks && echo x > pre-commit` names no `.git` in its
// word. The landed path is walked as the kernel walks it (a link to `.git` counts), and read from
// the project's top down where it lies in the project (a project kept under a directory of such
// a name is not written "into" it by every write).
function writeProblem(cmds: Simple[], cwdOf: (cmd: Simple) => string | undefined, dirsOf?: (cmd: Simple) => string[] | undefined, roots?: string[]): string | undefined {
  // Also every place the guard's own list of writes names (`cp -t`, `sort -o`, git's `--output`).
  const extra = writesOf(cmds).writes;
  for (const cmd of cmds) {
    const targets = [...cmd.out, ...extra.filter((w) => w.cmd === cmd).map((w) => w.word)];
    // Round 4, N3: the targets that make a file (see NAME_KEEPERS), with the operands after `--`.
    const made = [...cmd.out, ...extra.filter((w) => w.cmd === cmd && !NAME_KEEPERS.has(w.by ?? "")).map((w) => w.word)];
    cmd.argv.forEach((word, at) => {
      const how = Object.hasOwn(WRITER_OPERANDS, path.basename(word)) ? WRITER_OPERANDS[path.basename(word)] : undefined;
      const args = cmd.argv.slice(at + 1);
      const files = args.filter((a) => !a.startsWith("-"));
      if (path.basename(word) === "sed" && !args.some((a) => /^(-[a-zA-Z]*i|--in-place)/.test(a))) return;
      if (path.basename(word) === "dd") targets.push(...args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3)));
      else if (how) targets.push(...(how === "last" ? files.slice(-1) : files));
      if (path.basename(word) === "dd") made.push(...args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3)));
      else if (how && !NAME_KEEPERS.has(path.basename(word))) {
        const end = args.indexOf("--");
        const operands = end < 0 ? files : [...files.filter((f) => args.indexOf(f) < end), ...args.slice(end + 1)];
        made.push(...(how === "last" || path.basename(word) === "mv" ? operands.slice(-1) : operands));
      }
    });
    // A file whose name begins with `-` is an option to the program a later glob hands it to
    // (round 4, N3: `touch ./--to-command=rec`, then `tar xf a.tar --to*` or `tar xf a.tar *` in
    // this call, where the glob is judged before the file is there). `-` alone is no option.
    for (const target of made) {
      const leaf = (braceWords(target) ?? [target]).map((t) => t.replace(/\/+$/, "").split("/").at(-1) ?? "").find((t) => t.startsWith("-") && t !== "-");
      if (leaf !== undefined) return `makes a file named like an option (${leaf}): a later glob hands it to a program as one`;
    }
    // A name spelled with braces or a glob is the name it can expand to (round 3, finding 24).
    for (const target of targets) {
      // Braces that cannot be expanded in full name files nobody can list (round 4, finding 2).
      if (braceWords(target) === undefined) return `writes ${target}: a brace expansion too large or too unusual to list the files it names`;
      const name = protectedNameIn(target, PROTECTED_NAMES, cwdOf(cmd));
      if (name === ".git") return `writes ${target}: a path inside or named .git, where git finds hooks and config`;
      if (name) return `writes ${target}, which opencode or a git hook loads and runs`;
      const t = tilde(target);
      if (/[$`*?[\]{}]/.test(target) || /^~[^/]/.test(t) || /^&/.test(target) || roots === undefined) continue;
      for (const dir of path.isAbsolute(t) ? ["/"] : (dirsOf?.(cmd) ?? [])) {
        const full = path.isAbsolute(t) ? t : `${dir}/${t}`;
        if (/^\/dev\//.test(full) || procRelative(full)) continue;
        const landed = physical(full);
        const root = roots.find((r) => within(landed, r));
        const below = root === undefined ? landed : path.relative(root, landed);
        const at = protectedNameIn(below, PROTECTED_NAMES);
        if (at === ".git") return `writes ${target}, which is ${landed} where it runs: a path inside or named .git, where git finds hooks and config`;
        if (at) return `writes ${target}, which is ${landed} where it runs: a file opencode or a git hook loads and runs`;
      }
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

// Round 4, finding 27 (signed off): two everyday commands the rules leave to the model only
// because they do not know them. Each is allowed as exactly the words it is, and only where the
// rules' own verdict on those words is that one "do not know" (a credential file, a guarded
// path or a user's ask rule among them keeps its verdict):
//
//   - `read`, with nothing or `-r` before its names, into plain lower-case names that are not on
//     the dangerous list, are not a proxy setting and are not in the plugin's environment (a
//     variable that is exported already reaches the programs that follow). What it reads is the
//     call's to say: no command of the call may take its input from a file named at run time
//     or from a credential file (the rules do not look at the input of `done`, `fi` or `}`).
//   - `node -v`, those two words.
//
// A Matcher is shown a command's words joined by blanks; the texts allowed are those of the
// commands that qualify where they stand, and a text that also belongs to a command that does
// not qualify allows neither (as for the package managers above).
const RULES_KEYWORDS = new Set(["if", "then", "elif", "else", "do", "while", "until", "!", "{", "}"]);
// rules.ts's WRAPPERS (it does not export them): the programs `unwrap` drops with their options.
const RULES_WRAPPERS = new Set(["env", "nice", "ionice", "timeout", "time", "command", "builtin", "nohup", "setsid", "stdbuf", "exec", "chrt", "taskset"]);
const READ_NAME = /^[a-z][a-z0-9_]*$/;
const readNameOk = (name: string) => READ_NAME.test(name) && !dangerousName(name) && !/_proxy$/.test(name) && name !== "auto_resume" && !Object.hasOwn(process.env, name);
function everydayForm(argv: string[]): string | undefined {
  if (argv[0] === "read") {
    const names = argv.slice(argv[1] === "-r" ? 2 : 1);
    return names.every(readNameOk) ? "unknown command read" : undefined;
  }
  if (argv.length === 2 && argv[0] === "node" && argv[1] === "-v") return "runs code with node";
  return undefined;
}
// Round 4, finding 28, as the maintainer decided it after two cross-checks (third pass): `npx`
// is never allowed by rule. It goes to the model where the tool is installed in the project,
// and asks otherwise. So the reading of npm below draws one line only, between the model and
// an ask, and whatever it cannot be sure of asks: the model is shown the command, not the files
// npm reads to start it.
//
// The words (npxWords): `npx`, then `--no-install` or `--no` or nothing, then X, a plain
// program name (no `@version`, no scope, no path). Any other option (`-p`, `-c`, `-y`, `--`)
// may name a package or let npx download one, and asks. In front of `npx` may stand what
// changes nothing about what it runs: shell keywords, assignments (the guard asks about the
// ones that are not harmless), the wrappers the rules look through. Behind anything else
// (`xargs`, `find -exec`, a wrapper's option that takes a word) the guard asks as it did before
// the round. The other spellings (`npm exec`, `npm x`, `pnpm dlx`, `yarn dlx`, `pnpx`, `bunx`)
// are not read: the guard asks about each. Fourth pass: only the bare word `npx` is read. A
// path to a file named npx, absolute or relative, runs that file, whatever it is: the guard
// asks about it as before the round. And the word runs something else where the call defines a
// function or an alias of that name, or the environment holds a function for bash to import
// (`BASH_FUNC_npx%%`): those ask (everydayRules).
//
// The place (npxReading), for each directory the command may run in (the strictest of them;
// with none known, the model), as npm 11.19.1 does it (`config` is @npmcli/config/lib/index.js,
// `libexec` is libnpmexec/lib/index.js):
//   - It is a directory inside the project; npm's prefix (the nearest directory, up to `/`, with
//     a package.json or a node_modules: config 696-763) is inside it, and so is every
//     package.json above the prefix that has `workspaces` or cannot be read (npm may take that
//     one for its prefix: config 728-755). Anything else asks.
//   - A package.json in one of those places that gives X as a `bin` (libexec 94-96, 149-163: npm
//     installs that package into its cache and runs its file, with or without `--no-install`),
//     that has `directories.bin`, or that cannot be read, asks.
//   - An .npmrc there may hold only settings known to leave alone what runs and where npm looks
//     (NPMRC_HARMLESS); the user's own file and `npm_config_*` in the environment are read for
//     the settings that move npm (NPM_MOVES: the shell that starts X, NODE_OPTIONS for it, other
//     packages, other places). A line or key the reader is not sure to read as npm's ini does
//     asks.
//   - npm starts X as `sh -c X` with every node_modules/.bin from the directory up to `/` in
//     front of PATH: an executable `sh` or `node` in one of them runs in place of the real one,
//     and asks. Fourth pass: one that is no executable file is passed over by the PATH search,
//     as it is here; and a `node` that is the bin of an installed package named `node` which
//     the package.json beside that node_modules lists as a dependency is the project's own
//     interpreter (npmShadow).
//   - node_modules/.bin/X, looked for from the prefix up to the top of the project: there, it is
//     an executable file inside the project once its links are followed (else: ask), and the
//     call goes to the model. Not there: npx would download a package of that name, so ask;
//     and with `--no-install` or `--no` (fourth pass; it went to the model) nothing is fetched,
//     but npm runs a program of that name from a directory above the project, from its global
//     bin directory (on many machines the one every system program is in) or from a package
//     it downloaded before. That is not a tool installed in the project: ask.
// Then (everydayRules): what the rules ask about the words `pnpm exec X ...` asks here too.
//
// The reading looks at the disk before the call runs, and another part of the call may take the
// tool away before npx does. Fifth pass, the maintainer's rule in place of the fourth pass's
// reading of every other command (npxNamed: readers, removers, words expanded against the tree,
// `.bin`, `.npmrc`, `package.json`, which missed forms and asked about everyday calls): an npx
// the reading sends to the model asks when the letters `node_modules` stand anywhere in the call
// outside that npx's own arguments, the words behind the tool's name, which are the tool's
// business (npxSpelled). Nothing else about the other commands is read. So a spelling without
// the letters (`rm -rf node_mod*`), a command that removes or swaps the tool without naming it
// (`git clean -fdx`, a script, `git checkout other`) and a change of what npm reads (`echo x >>
// .npmrc`, `npm pkg set`) stay with the model on purpose: it is shown the whole call.
const NPX_FRONT = /^(?:[A-Za-z_][A-Za-z0-9_]*=.*|-[np]|\d+(\.\d+)?[smhd]?)$/s;
function npxWords(argv: string[]): { at: number; program?: number; noInstall: boolean; ask?: string } | undefined {
  const at = programs(argv).find((p) => argv[p] === "npx");
  if (at === undefined) return undefined;
  const front = argv.slice(0, at);
  if (!front.every((w) => RULES_KEYWORDS.has(w) || RULES_WRAPPERS.has(w) || NPX_FRONT.test(w))) return undefined;
  const setting = front.find((w) => /^npm_config_[^=]*=/i.test(w));
  if (setting) return { at, noInstall: false, ask: `sets ${setting.split("=")[0]}, a setting of npm's, for npx` };
  const noInstall = argv[at + 1] === "--no-install" || argv[at + 1] === "--no";
  const program = at + (noInstall ? 2 : 1);
  const word = argv[program];
  if (word === undefined) return { at, noInstall, ask: "npx with no program to run: it reads what to run from its input" };
  if (!/^[a-z][a-z0-9._-]*$/.test(word)) return { at, noInstall, ask: `npx ${word.slice(0, 60)}: only --no-install or --no and then a plain program name are read; any other word may name a package for npx to download and run` };
  return { at, program, noInstall };
}
// Settings that change what `npx X` runs or where npm looks for it (see above).
const NPM_MOVES = new Set(["script-shell", "shell", "node-options", "package", "call", "workspace", "workspaces", "include-workspace-root", "global", "location", "globalconfig"]);
// Settings of a project's .npmrc that leave both alone: the registry and its login, how installs
// save and resolve, what npm prints, and the settings pnpm keeps in the same file.
const NPMRC_HARMLESS = new Set([
  "registry", "strict-ssl", "cafile", "ca", "cert", "key", "proxy", "https-proxy", "noproxy", "no-proxy", "maxsockets", "fetch-retries", "fetch-retry-factor",
  "fetch-retry-mintimeout", "fetch-retry-maxtimeout", "fetch-timeout", "always-auth", "email", "otp", "access", "provenance", "tag", "before",
  "save", "save-exact", "save-prefix", "save-dev", "save-optional", "save-peer", "save-prod", "save-bundle", "engine-strict", "legacy-peer-deps", "strict-peer-deps",
  "fund", "audit", "audit-level", "package-lock", "package-lock-only", "lockfile-version", "prefer-offline", "prefer-online", "offline", "prefer-dedupe",
  "install-strategy", "install-links", "omit", "include", "optional", "ignore-scripts", "foreground-scripts", "if-present", "bin-links", "dry-run",
  "progress", "loglevel", "color", "unicode", "timing", "heading", "update-notifier", "depth", "searchlimit",
  "tag-version-prefix", "sign-git-tag", "sign-git-commit", "commit-hooks", "git-tag-version", "message", "allow-same-version",
  "init-author-name", "init-author-email", "init-author-url", "init-license", "init-version",
  "auto-install-peers", "shamefully-hoist", "strict-peer-dependencies", "node-linker", "hoist", "hoist-pattern", "public-hoist-pattern", "link-workspace-packages",
  "prefer-workspace-packages", "save-workspace-protocol", "shared-workspace-lockfile", "resolution-mode", "dedupe-peer-dependents", "enable-pre-post-scripts",
  "side-effects-cache", "symlink", "lockfile", "prefer-frozen-lockfile", "frozen-lockfile", "recursive-install", "package-manager-strict",
  "manage-package-manager-versions", "resolve-peers-from-workspace-root", "ignore-workspace-root-check", "verify-store-integrity", "child-concurrency", "network-concurrency",
]);
// A scoped registry and the login of a registry (`@acme:registry`, `//host/path/:_authToken`).
const NPMRC_HARMLESS_KEY = /^(?:@[A-Za-z0-9._-]+:registry|\/\/[^\s=]*:(?:_authToken|_auth|_password|username|email|certfile|keyfile))$/;
// The keys of an npmrc file: lines as npm's ini reader splits them (ini/lib/ini.js: at any run
// of carriage returns and newlines), each a comment, a section or `key`, `key = value`,
// `key[] = value`. The reader decodes more than that (quotes, escapes, a comment inside a key),
// so a key that is not plain is not read here: it is a problem. undefined when there is no such
// file; a string when it, or a line of it, cannot be read.
function npmrcKeys(file: string): string[] | string | undefined {
  if (!lexists(file)) return undefined;
  const text = readText(file);
  if (text === undefined) return `${file} cannot be read`;
  const keys: string[] = [];
  for (const raw of text.split(/[\r\n]+/)) {
    const line = raw.trim();
    if (!line || line.startsWith(";") || line.startsWith("#")) continue;
    if (line.startsWith("[")) return `${file} holds a section (${line.slice(0, 40)})`;
    const key = line.split("=")[0].trim();
    if (!/^[A-Za-z0-9_@\/:.-]+(\[\])?$/.test(key)) return `${file} holds a line the check cannot read as npm does (${line.slice(0, 40)})`;
    keys.push(key.replace(/\[\]$/, ""));
  }
  return keys;
}
// What a project's .npmrc holds that is not known to be harmless.
function npmrcProblem(file: string): string | undefined {
  const keys = npmrcKeys(file);
  if (keys === undefined || typeof keys === "string") return keys;
  const odd = keys.find((k) => !NPMRC_HARMLESS.has(k) && !NPMRC_HARMLESS_KEY.test(k));
  return odd === undefined ? undefined : `${file} sets ${odd.slice(0, 60)}, which is not among the npm settings known to leave alone what npx runs and where it looks`;
}
// The same for the user's own file and environment: the settings that move npm. (npm reads a
// relative `userconfig` in the directory it runs in.)
function npmUserconfig(dir: string): string {
  let userconfig = path.join(os.homedir(), ".npmrc");
  // npm takes an empty one for unset.
  for (const [name, value] of Object.entries(process.env)) if (/^npm_config_userconfig$/i.test(name) && value) userconfig = path.resolve(dir, value);
  return userconfig;
}
function npmOwnProblem(dir: string): string | undefined {
  const moves = (key: string) => NPM_MOVES.has(key.replace(/(?!^)_/g, "-").toLowerCase());
  for (const [name, value] of Object.entries(process.env)) {
    if (!/^npm_config_/i.test(name) || !value) continue;
    if (moves(name.slice("npm_config_".length))) return `the environment sets ${name}, which changes what npx runs or where it looks`;
  }
  const userconfig = npmUserconfig(dir);
  const keys = npmrcKeys(userconfig);
  if (keys === undefined || typeof keys === "string") return keys;
  const moved = keys.find(moves);
  return moved === undefined ? undefined : `${userconfig} sets ${moved.slice(0, 60)}, which changes what npx runs or where it looks`;
}
const isFileAt = (p: string) => {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
};
const isDirAt = (p: string) => {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
};
// The package.json of `dir` as an object; null when it is there and cannot be read or parsed,
// undefined when there is none.
function packageJson(dir: string): Record<string, unknown> | null | undefined {
  const file = path.join(dir, "package.json");
  if (!isFileAt(file)) return lexists(file) ? null : undefined;
  try {
    const pkg: unknown = JSON.parse((readText(file) ?? "{").replace(/^﻿/, ""));
    return pkg !== null && typeof pkg === "object" && !Array.isArray(pkg) ? (pkg as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}
// Whether the package.json of `dir` gives npm a bin called `name` (see above): the reason.
function packageBinProblem(dir: string, name: string): string | undefined {
  const pkg = packageJson(dir);
  const file = path.join(dir, "package.json");
  if (pkg === undefined) return undefined;
  if (pkg === null) return `${file} cannot be read, and npm looks there for a bin named ${name} before it looks in node_modules/.bin`;
  const own = `so npm installs that package into its cache and runs the package's own file, not node_modules/.bin/${name}`;
  const base = (key: string) => path.posix.basename(key.replace(/[\\:]/g, "/"));
  const bin = pkg.bin;
  if (bin === undefined || bin === null || bin === false || bin === "") {
    const dirs = pkg.directories;
    return dirs !== null && typeof dirs === "object" && (dirs as Record<string, unknown>).bin ? `${file} has directories.bin, whose files npm takes for the package's bins before it looks in node_modules/.bin` : undefined;
  }
  if (typeof bin === "string") return typeof pkg.name === "string" && base(pkg.name) !== name ? undefined : `${file} has a bin named ${name} (the package's own name), ${own}`;
  if (typeof bin !== "object") return `${file} has a bin the check cannot read, and npm looks there before it looks in node_modules/.bin`;
  const keys = Array.isArray(bin) ? bin.map(String) : Object.keys(bin);
  return keys.some((k) => base(k) === name) ? `${file} has a bin named ${name}, ${own}` : undefined;
}
// Whether `file`, a `sh` or `node` in the node_modules/.bin of `dir`, is what npm's shell (or
// the program's `#!/usr/bin/env node`) would start in place of the real one (see above).
function npmShadow(dir: string, file: string): boolean {
  let real: string;
  try {
    real = fs.realpathSync(file);
    if (!fs.statSync(real).isFile()) return false;
    fs.accessSync(real, fs.constants.X_OK);
  } catch {
    // A link that leads nowhere, or a file that cannot be run: the PATH search passes over it.
    return false;
  }
  if (path.basename(file) !== "node") return true;
  // The project's own interpreter: the npm package `node`, installed here and listed here.
  const home = path.join(realish(dir), "node_modules", "node");
  const installed = packageJson(home);
  const listed = packageJson(dir);
  const lists = (key: string) => {
    const deps = listed?.[key];
    return deps !== null && typeof deps === "object" && !Array.isArray(deps) && Object.hasOwn(deps, "node");
  };
  return !(within(real, home) && real !== home && installed?.name === "node" && ["dependencies", "devDependencies", "optionalDependencies"].some(lists));
}
// How npm would run `npx [--no-install] X` from `dir` (see above): an ask, or the model, each
// with its reason.
type NpxReading = { ask: string } | { model: string };
function npxReading(dir: string, name: string, noInstall: boolean, roots: string[]): NpxReading {
  const start = realish(dir);
  const tops = roots.map(realish);
  const inside = (p: string) => tops.some((r) => within(p, r));
  if (!inside(start)) return { ask: `npx outside the project (in ${start}): npm looks for ${name} there and in the directories above it` };
  const chain: string[] = [];
  for (let at = start; ; at = path.dirname(at)) {
    chain.push(at);
    if (at === path.dirname(at)) break;
  }
  const first = chain.findIndex((d) => isFileAt(path.join(d, "package.json")) || isDirAt(path.join(d, "node_modules")));
  const prefix = chain[Math.max(first, 0)];
  if (!inside(prefix)) return { ask: `npx outside the project: npm starts from ${prefix}, the nearest directory with a package.json or a node_modules` };
  const places = [prefix];
  for (const d of chain.slice(Math.max(first, 0) + 1)) {
    const pkg = packageJson(d);
    if (pkg === undefined || (pkg !== null && !pkg.workspaces)) continue;
    if (!inside(d)) return { ask: `npx outside the project: ${path.join(d, "package.json")} ${pkg ? "has workspaces" : "cannot be read"}, so npm may start from ${d}` };
    places.push(d);
  }
  for (const d of places) {
    const problem = packageBinProblem(d, name) ?? npmrcProblem(path.join(d, ".npmrc"));
    if (problem) return { ask: `npx ${name}: ${problem}` };
  }
  const own = npmOwnProblem(start);
  if (own) return { ask: `npx ${name}: ${own}` };
  for (const d of chain) {
    const shadow = ["sh", "node"].map((b) => path.join(d, "node_modules", ".bin", b)).find((f) => lexists(f) && npmShadow(d, f));
    if (shadow) return { ask: `npx ${name}: npm puts ${shadow} in front of the PATH it starts ${name} with, where it runs in place of the real ${path.basename(shadow)}` };
  }
  for (const d of chain.slice(Math.max(first, 0))) {
    if (!inside(d)) break;
    const file = path.join(d, "node_modules", ".bin", name);
    if (!lexists(file)) continue;
    let ok = false;
    try {
      const real = fs.realpathSync(file);
      ok = fs.statSync(real).isFile() && inside(real);
      fs.accessSync(real, fs.constants.X_OK);
    } catch {
      // A link that leads nowhere, or a file that cannot be run.
      ok = false;
    }
    if (!ok) return { ask: `npx ${name}: ${file} is no program of the project (a link that leads out of it, no regular file, or not executable)` };
    return { model: `npx ${name}: the project has node_modules/.bin/${name}, so npx downloads nothing and runs that file through npm; no rule allows an npx, so it is left to the model` };
  }
  if (!noInstall) return { ask: `npx ${name}: the project has no node_modules/.bin/${name}, so npx would download a package of that name and run it` };
  return { ask: `npx --no-install ${name}: the project has no node_modules/.bin/${name}: npx would run a program of that name from outside the project (a directory above it, npm's global bin directory, or a package it downloaded before)` };
}
// Where the call spells `node_modules` outside the own arguments of its npx (the command `n` of
// `cmds`, whose tool's name is the word `program`): the command and the word, or undefined. The
// words decide, as the parser hands them over, quotes and backslashes gone and braces expanded:
// every word of every other command at any depth (the code of a nested shell and a substitution
// are commands of their own, and a word that holds shell text or any other text is a word), the
// words in front of the tool's name in the npx's own command, and every redirect target, the
// npx's own too. That leaves out exactly the npx's own arguments.
// The one thing in a call that is no word of a command is a here-document's body, and that is
// read as text (the two checks of this pass: the first build cut `npx X ...` out of the text
// with a pattern, which lost `rm -rf npx tsc node_modules` in a body and took an operator inside
// a quoted argument for the end of the npx). Which lines of the text are a body is not read: in
// a call that holds a `<<` the letters anywhere in its text ask, the npx's own arguments too.
// The letters count as written and with the quotes and backslashes of a string taken out (`trap
// 'rm -rf node_mod""ules' DEBUG`: the string is shell text that only bash reads).
const NPX_LETTERS = "node_modules";
const npxLetters = (s: string): boolean => s.includes(NPX_LETTERS) || s.replace(/['"\\]/g, "").includes(NPX_LETTERS);
function npxSpelled(text: string, cmds: Simple[], n: number, program: number): string | undefined {
  for (const [m, other] of cmds.entries()) {
    const words = [...(m === n ? other.argv.slice(0, program) : other.argv), ...other.out, ...(other.in ?? [])];
    const word = words.find(npxLetters);
    if (word !== undefined) return `${m === n ? "npx" : other.argv[programs(other.argv)[0] ?? 0]}: ${word.slice(0, 60)}`;
  }
  if (!text.includes("<<")) return undefined;
  const line = text.split("\n").find(npxLetters);
  return line === undefined ? undefined : `the call's text: ${line.trim().slice(0, 60)}`;
}
interface Everyday {
  allow: Matcher[];
  // By the command's place among the call's commands (as `located` lists them): see
  // GuardContext.npx (guard.ts).
  npx: Map<number, { at: number; program?: number; ask?: string; model?: string }>;
}
function everydayRules(guard: Guard, session: SessionState, text: string, cwd: string, literalInputs: Set<string> = new Set()): Everyday {
  const allow = new Set<string>();
  // The texts of every command that does not qualify. The rules test a command's words also
  // without the keywords, assignments and wrappers in front of them (rules.ts, `unwrap`), so
  // such a command shows them more than one text: `timeout 5 'node -v'` (a program whose name
  // is `node -v`) shows `node -v` (second pass). Every text that begins behind a run of words
  // `unwrap` could drop counts, and every program position the guard knows; a run too long to
  // list allows nothing in the call.
  const other = new Set<string>();
  let unlistable = false;
  const shown = (argv: string[]) => {
    const from = new Set([0, ...programs(argv)]);
    let k = 0;
    while (k < argv.length && (RULES_KEYWORDS.has(argv[k]) || RULES_WRAPPERS.has(path.basename(argv[k])) || /^(?:[A-Za-z_][A-Za-z0-9_]*=|-)/.test(argv[k]) || /^\d+(\.\d+)?[smhd]?$/.test(argv[k]))) from.add(++k);
    if (from.size > 64) unlistable = true;
    else for (const at of from) other.add(argv.slice(at).join(" "));
  };
  const npx: Everyday["npx"] = new Map();
  // Fourth pass: what the word `npx` runs when the call, or the environment, makes it a
  // function or an alias (in any command of the call, a nested shell's code among them).
  // Fifth pass: the pattern is held against the text also without its quotes and backslashes
  // (the printer writes a string that holds `npx() {` as `npx\(\)' {'`, and a trap's code is such a
  // string), and a word that hands a shell the exported function (`env 'BASH_FUNC_npx%%=() {...}'
  // bash -c ...`, which the guard reads as no assignment) is one more spelling.
  const npxDefined = [text, text.replace(/['"\\]/g, "")].some((t) => /(^|[^\w.\/-])function\s+npx(?![\w.-])|(^|[^\w.\/$-])npx\s*\(\s*\)|(^|[^\w.\/-])alias\s[^;&|\n]*(?<![\w.\/-])npx=|(^|[^\w])BASH_FUNC_npx%%=/.test(t))
    ? "the call defines a function or an alias named npx: the word npx then runs that, not npm's npx"
    : Object.hasOwn(process.env, "BASH_FUNC_npx%%")
      ? "the environment holds a function named npx (BASH_FUNC_npx%%): the word npx may run that, not npm's npx"
      : undefined;
  const plain = rulesFor(guard, undefined, undefined, false);
  const placed = located(text, realish(cwd));
  const scopeAt = (cmd: Simple) => {
    const at = placed.cwd.get(cmd);
    return at === undefined ? undefined : scopeFor(guard, session, at, plain);
  };
  const quoted = (words: string[]) => words.map((w) => `'${w.replace(/'/g, "'\\''")}'`).join(" ");
  const inputsOk = placed.cmds.every((cmd) => {
    const scope = scopeAt(cmd);
    // A `$` in the parser's word may have been quoted text: the word passes when it is a `<` target
    // the printer lists that names a literal file (`< 'price$USD.txt'`, B3c), which inputReads judges.
    return (cmd.in ?? []).every((w) => !!scope && (!/[$`]/.test(w) || literalInputs.has(w)) && !readVerdict("read", w, scope));
  });
  for (const [n, cmd] of placed.cmds.entries()) {
    let p = 0;
    while (p < cmd.argv.length && RULES_KEYWORDS.has(cmd.argv[p])) p++;
    const own = cmd.argv.slice(p);
    const texts = [cmd.argv.join(" "), own.join(" ")];
    const expected = everydayForm(own);
    const scope = scopeAt(cmd);
    // The verdict is asked of the words alone, so whatever the rules would say about a redirect
    // on the input side is checked here (`inputsOk`), for both forms.
    const v = expected !== undefined && scope && inputsOk && !cmd.heredoc ? bashVerdict(quoted(own), scope) : undefined;
    const allowed = v?.action === "classify" && v.reason === expected;
    if (allowed) for (const t of texts) allow.add(t);
    else shown(cmd.argv);
    // An npx (finding 28, third pass: see npxWords): never among the allows above.
    const words = npxWords(cmd.argv);
    if (!words) continue;
    let ask = npxDefined ?? words.ask;
    let model: string | undefined;
    if (words.program !== undefined) {
      const name = cmd.argv[words.program];
      // Every directory the command may run in; the tool call's own where they are not known,
      // for what the words alone decide.
      const dirs = placed.places.get(cmd) && [...new Set(placed.places.get(cmd)!.map((place) => place.real))];
      for (const dir of dirs ?? [realish(cwd)]) {
        const same = bashVerdict(quoted(["pnpm", "exec", ...cmd.argv.slice(words.program)]), scopeFor(guard, session, dir, plain));
        if (same.action === "ask" || same.action === "deny") ask ??= `npx ${name}, judged as pnpm exec ${name}: ${same.reason}`;
      }
      if (!dirs) model = `npx ${name}, where the check cannot tell which directory it runs in`;
      for (const dir of dirs ?? []) {
        const reading = npxReading(dir, name, words.noInstall, projectRoots(session));
        if ("ask" in reading) ask ??= reading.ask;
        else model ??= reading.model;
      }
      // The reading looked at the disk as it is before the call runs (see above, fifth pass).
      const spelled = ask ? undefined : npxSpelled(text, placed.cmds, n, words.program);
      if (spelled) ask = `npx ${name} in a call that names node_modules outside the arguments of this npx (${spelled}): the tool was looked for before the call runs, so any other mention of node_modules asks`;
    }
    npx.set(n, { at: words.at, ...(ask ? { ask } : { program: words.program, model }) });
  }
  // A text that a command that does not qualify also shows the rules allows neither.
  return { allow: [{ source: "read into plain names or node -v", test: (t) => !unlistable && allow.has(t) && !other.has(t) }], npx };
}

// `scan`: the walks of this call, which the caller hands to plan() as well (round 3, finding 40).
//
// Round 4, finding 16: the command is first printed back in the canonical spelling (canon.ts).
// Everything below judges that text, and the decision carries it (`printed`): it is the text that
// runs when the decision is an allow. A command that cannot be printed asks.
// ---- what a git call changed in the work tree (round 4, decision D1) ----

// A git call that writes the work tree (`pull`, `merge`, `checkout <branch>`, `rebase`, `stash
// pop`, `reset`, `restore`, `cherry-pick`, `revert`, `am`, `mv`, `bisect`): the repository it
// runs in, the commit and the status there before it ran (taken when the call is decided, which is
// before it runs). `done` is set by the plugin once no process of the call is left (index.ts,
// where the call is over); the next decision then compares the commit and the status with what
// is there now, and marks the files that changed. Until then, and where the lookup fails, the
// repository is marked whole: giving up is a verdict.
export interface WorkTreeChange {
  top: string;
  head: string;
  // Per path relative to `top`: the status line's two letters and what lstat shows of the file.
  status: Map<string, string>;
  at: number;
  done?: boolean;
}
// B7-3: whether the configuration git reads in `dir` names no program of the project for a
// filter (`filter.<name>.clean`, `.smudge`, `.process`) and, with `diff`, none for a diff either
// (`diff.external`, `diff.<driver>.command`, `diff.<driver>.textconv`). git hands each value to
// a shell in the top of the work tree. A value names a program outside the project (git-lfs's
// own `git-lfs clean -- %f`, in the user's global configuration) when all of this holds:
//   - it is plain words (no quote, variable, substitution, redirect, `;`, `&` or `|`);
//   - its first word is an absolute path, or a name found on PATH before any entry of PATH that
//     is relative, to a file outside the project (`inside`) and outside the temp directory;
//   - that program is not one that runs what its words name (a shell, an interpreter, a wrapper,
//     a build tool, a package manager: guard.ts, runsItsWords);
//   - every other word is an option, a placeholder (`%f`), or a word without `/` or `.` that
//     names nothing in the top of the work tree (a subcommand: `clean`, `filter-process`).
// Any other value may run a file the session can write: a filter that names a project file.
const PLAIN_COMMAND = /^[A-Za-z0-9_@%+=:,.\/ -]+$/;
function outsideProgram(value: string, top: string, inside: (p: string) => boolean): boolean {
  if (!PLAIN_COMMAND.test(value)) return false;
  const [program, ...rest] = value.trim().split(/ +/);
  if (!program || runsItsWords(path.basename(program))) return false;
  let file: string | undefined;
  if (program.includes("/")) file = path.isAbsolute(program) ? program : undefined;
  else
    for (const dir of (process.env.PATH ?? "").split(":")) {
      if (!path.isAbsolute(dir)) return false;
      const candidate = path.join(dir, program);
      try {
        fs.accessSync(candidate, fs.constants.X_OK);
        if (!fs.statSync(candidate).isFile()) continue;
      } catch {
        continue;
      }
      file = candidate;
      break;
    }
  if (!file) return false;
  let real: string;
  try {
    real = fs.realpathSync(file);
    if (!fs.statSync(real).isFile()) return false;
  } catch {
    return false;
  }
  const temp = realish(os.tmpdir());
  if ([file, real].some((f) => inside(f) || within(f, temp))) return false;
  return rest.every((w) => w.startsWith("-") || /^%[A-Za-z]$/.test(w) || (!/[\/.]/.test(w) && !lexists(path.join(top, w))));
}
function gitProgramsOutside(dir: string, diff: boolean, inside: (p: string) => boolean): boolean {
  const keys = diff ? "^(filter\\..*\\.(clean|smudge|process)|diff\\.external|diff\\..*\\.(command|textconv))$" : "^filter\\..*\\.(clean|smudge|process)$";
  const r = gitRun(["-C", dir, "config", "--null", "--get-regexp", keys]);
  if (r.status === 1) return true;
  if (r.status !== 0) return false;
  const top = safeGit(["-C", dir, "rev-parse", "--show-toplevel"])?.trim() || dir;
  return r.out.split("\0").filter(Boolean).every((entry) => {
    const at = entry.indexOf("\n");
    return at >= 0 && outsideProgram(entry.slice(at + 1), top, inside);
  });
}

// Decisions that require git's interpretation, in each command's actual directory.
function placedGitIssue(cmds: Simple[], cwdOf: (c: Simple) => string | undefined): string | undefined {
  for (const cmd of cmds) for (const at of programs(cmd.argv)) {
    if (path.basename(cmd.argv[at]) !== "git") continue;
    const call = gitCall(cmd.argv.slice(at + 1));
    if (typeof call === "string") continue;
    let dir = cwdOf(cmd);
    for (const d of call.dirs) dir = dir === undefined || /[$`]/.test(d) ? undefined : path.isAbsolute(d) ? d : `${dir}/${d}`;
    const sub = call.sub ?? "";
    if (!["branch", "switch", "checkout", "fetch", "pull"].includes(sub)) continue;
    const got = getopt(call.rest, GIT_OPTIONS[sub]);
    const words = got.operands.map((o) => o.word);
    let configFailed = false;
    const config = (key: string, boolean = false) => {
      if (dir === undefined) { configFailed = true; return undefined; }
      const r = gitRun(["-C", dir, "config", ...(boolean ? ["--type=bool"] : []), "--get", key]);
      if (r.status !== 0 && r.status !== 1) configFailed = true;
      return r.status === 0 ? r.out.trim() : undefined;
    };
    if (sub === "fetch" || sub === "pull") {
      if (!words.slice(1).some((w) => /:./.test(w))) continue;
      const explicit = got.opts.filter((o) => ["--prune", "--no-prune", "-p"].includes(o.name)).at(-1);
      const configured = explicit ? undefined : config(`remote.${words[0] ?? "origin"}.prune`, true) ?? config("fetch.prune", true);
      if (configFailed) return `git ${sub}: cannot read pruning configuration`;
      const pruning = explicit ? explicit.name !== "--no-prune" : configured === "true";
      // (B7-8: the destination as git reads it: `remotes/origin/x` is under refs/remotes.)
      if (pruning && words.slice(1).some((w) => /:./.test(w) && !fetchDestination(w.slice(w.indexOf(":") + 1)).startsWith("refs/remotes/"))) return "git fetch prunes a destination outside refs/remotes";
      continue;
    }
    // git itself, where the command runs: undefined where it fails.
    const ask = (...args: string[]) => (dir === undefined ? undefined : safeGit(["-C", dir, ...args]));
    const resolves = (rev: string) => ask("rev-parse", "--verify", "--quiet", "--end-of-options", rev) !== undefined;
    if (sub === "branch") {
      // B7-8: `git branch -d <b>` takes the section `branch.<b>` out of git's config with it.
      if (got.opts.some((o) => /^(-d|--delete)$/.test(o.name)) && !got.opts.some((o) => /^(-r|--remotes)$/.test(o.name))) {
        const keys = dir === undefined ? undefined : gitRun(["-C", dir, "config", "--name-only", "--get-regexp", "^branch\\."]);
        if (!keys || (keys.status !== 0 && keys.status !== 1)) return "git branch -d: cannot read git's config for the branch's section";
        const held = words.find((b) => /[$`]/.test(b) || lines(keys.out).some((k) => k.startsWith(`branch.${b}.`)));
        if (held !== undefined) return `git branch -d ${held} removes the section branch.${held} from git's config, which is read-only in the sandbox`;
        continue;
      }
    }
    if (got.opts.some((o) => o.name === "--no-track")) continue;
    const creating = sub === "branch" ? words.length > 0 && !got.opts.some((o) => /^(-[dDlamMcC]|--(delete|list|all|move|copy|contains|merged|points-at))$/.test(o.name)) : got.opts.some((o) => sub === "switch" ? ["-c", "-C", "--create", "--force-create"].includes(o.name) : ["-b", "-B"].includes(o.name));
    const mode = () => (config("branch.autoSetupMerge") ?? "true").toLowerCase();
    if (!creating) {
      // B7-8: `git checkout <name>` and `git switch <name>` with no local branch of that name,
      // where exactly one remote has one (or several, and `checkout.defaultRemote` picks): git
      // makes the branch with its upstream, and writes git's config. Not with `--no-guess`,
      // `checkout.guess=false`, `--detach`, or where `branch.autoSetupMerge` is `false` or
      // `inherit` (git 2.47: the branch is made without an upstream); not where the name is
      // another revision (a tag, `origin/x`, a commit), which git checks out detached.
      if (sub === "branch" || words.length !== 1 || got.opts.some((o) => /^(-d|--detach|--orphan|-p|--patch)$/.test(o.name))) continue;
      const name = words[0];
      if (name === "-" || /[$`]/.test(name) || (dir !== undefined && (resolves(`refs/heads/${name}`) || resolves(`${name}^{commit}`)))) continue;
      const guess = got.opts.filter((o) => o.name === "--guess" || o.name === "--no-guess").at(-1)?.name;
      if (guess === "--no-guess" || (guess === undefined && config("checkout.guess", true) === "false")) continue;
      const remotes = ask("for-each-ref", "--format=%(refname)", "refs/remotes");
      const fetches = dir === undefined ? undefined : gitRun(["-C", dir, "config", "--get-regexp", "^remote\\..*\\.fetch$"]);
      if (remotes === undefined || !fetches || (fetches.status !== 0 && fetches.status !== 1) || configFailed) return `git ${sub} ${name}: cannot tell whether a remote has a branch of that name, from which git would make one with its upstream in git's config`;
      // The remote-tracking refs a remote's fetch refspec gives the branch `name`.
      const have = new Set(lines(remotes));
      const tracking = lines(fetches.out).map((l) => l.slice(l.indexOf(" ") + 1).replace(/^\+/, "")).map((spec) => mapRef(spec, `refs/heads/${name}`, false)).filter((dst): dst is string => dst !== undefined && have.has(dst));
      if (!tracking.length) continue;
      if (new Set(tracking).size > 1 && config("checkout.defaultRemote") === undefined) continue;
      const m = mode();
      if (configFailed) return `git ${sub}: cannot read branch tracking configuration`;
      if (["false", "no", "off", "0", "inherit"].includes(m)) continue;
      return `git ${sub} ${name} makes the branch from ${tracking[0]} with its upstream, and writes that to git's config, which is read-only in the sandbox`;
    }
    // B7-8: the start point as git reads it for tracking (branch.c, create_branch and
    // setup_tracking): the full name of the ref the word names (`rev-parse --symbolic-full-name`
    // reads it as git's dwim_ref does: `origin` is refs/remotes/origin/HEAD's target, `@{u}` the
    // upstream, `-` the branch before), and nothing for a word that names a commit and no ref
    // (`HEAD~0`, `v1^{}`, a commit id, `FETCH_HEAD`, `HEAD@{1}`, a detached HEAD). git sets an
    // upstream only from a local branch (`always`, `inherit`) or from a ref that is the
    // destination of a remote's fetch refspec; from anything else it writes no config.
    const given = sub === "branch" ? words[1] : words[0];
    const start = given === "-" ? "@{-1}" : given ?? "HEAD";
    if (dir !== undefined && !resolves(`${start}^{commit}`)) {
      // An unborn HEAD: `git checkout -b x` in a repository without a commit renames the branch to
      // be; `git branch x` fails. Neither writes config.
      if (given === undefined && ask("symbolic-ref", "-q", "HEAD") !== undefined) continue;
      return `git ${sub}: cannot resolve branch start point ${start}`;
    }
    const answer = ask("rev-parse", "--verify", "--symbolic-full-name", "--end-of-options", start);
    if (answer === undefined) return `git ${sub}: cannot resolve branch start point ${start}`;
    const ref = answer.trim();
    const local = ref.startsWith("refs/heads/");
    if (!local && !ref.startsWith("refs/")) continue;
    const fetches = gitRun(["-C", dir!, "config", "--get-regexp", "^remote\\..*\\.fetch$"]);
    if (fetches.status !== 0 && fetches.status !== 1) return `git ${sub}: cannot read branch tracking configuration`;
    // The branch on the remote that `ref` is the fetch destination of, when it is one.
    const source = local ? undefined : lines(fetches.out).map((l) => l.slice(l.indexOf(" ") + 1).replace(/^\+/, "")).map((spec) => mapRef(spec, ref, true)).find((src) => src !== undefined);
    const remote = source !== undefined;
    const m = mode();
    const newName = sub === "branch" ? words[0] : got.opts.find((o) => ["-b", "-B", "-c", "-C", "--create", "--force-create"].includes(o.name))?.value;
    const tracking = m === "simple" ? remote && source === `refs/heads/${newName}`
      : m === "inherit" ? local && config(`branch.${ref.slice("refs/heads/".length)}.remote`) !== undefined
      : m === "always" ? local || remote
      : remote && !["false", "no", "off", "0"].includes(m);
    if (configFailed) return `git ${sub}: cannot read branch tracking configuration`;
    if (tracking) return `git ${sub} starts from ${ref}, which may write tracking to git's config`;
  }
  return undefined;
}
// A ref through a fetch refspec `src:dst` (one `*` on each side at most): the destination of
// `ref` as a source, or with `back` the source of `ref` as a destination; undefined where the
// refspec does not cover it.
function mapRef(spec: string, ref: string, back: boolean): string | undefined {
  const colon = spec.indexOf(":");
  if (colon < 0) return undefined;
  const [from, to] = back ? [spec.slice(colon + 1), spec.slice(0, colon)] : [spec.slice(0, colon), spec.slice(colon + 1)];
  const star = from.indexOf("*");
  if (star < 0) return from === ref ? to : undefined;
  const head = from.slice(0, star);
  const tail = from.slice(star + 1);
  if (ref.length < head.length + tail.length || !ref.startsWith(head) || !ref.endsWith(tail)) return undefined;
  return to.replace("*", ref.slice(head.length, ref.length - tail.length));
}

// Paths differing from HEAD, including untracked and ignored files, with metadata so a file
// changed again under the same status is still noticed.
// B7-4: ignored files as git matches them (`--ignored=matching`): a directory an ignore pattern
// names is one entry (`node_modules/`), not every file below it (60,000 files gave 4 MB, and
// past the buffer the status failed and the whole tree was marked). A file about to run is
// judged by its own change time (the first line), ignored or not, so D1 needs no list of every
// ignored file: it keeps the entries that match, whose appearing, going or changing marks them (a
// directory: its place, for the runner check). What it reads is bounded: more entries than
// `statusLimit.entries` and the check gives up, which marks the work tree whole.
export const statusLimit = { entries: 20_000 };
function worktreeStatus(top: string): Map<string, string> | undefined {
  // Status can hash a same-size changed file through a clean/process filter. This snapshot
  // runs before the sandbox: give up rather than execute a configured project program (one
  // outside the work tree, git-lfs's, is the user's own and runs for every status of theirs).
  if (!gitProgramsOutside(top, false, (p) => within(realish(p), realish(top)))) return undefined;
  const r = gitRun(["-C", top, "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=none"], 10_000);
  if (r.status !== 0) return undefined;
  const out = new Map<string, string>();
  const fields = r.out.split("\0");
  if (fields.length > statusLimit.entries) return undefined;
  for (let i = 0; i < fields.length; i++) {
    const f = fields[i];
    if (f.length < 4) continue;
    const code = f.slice(0, 2);
    const names = [f.slice(3)];
    // A rename or a copy names its origin in the next field.
    if (/[RC]/.test(code)) names.push(fields[++i] ?? "");
    for (const name of names) {
      let st = "gone";
      try {
        const l = fs.lstatSync(path.join(top, name));
        st = `${l.size}:${l.mtimeMs}:${l.ino}`;
      } catch {
        // deleted
      }
      out.set(name, `${code} ${st}`);
    }
  }
  return out;
}
// The work-tree change a git call will make where it runs, or undefined where the check cannot
// tell (the directory unknown, not a repository, HEAD unborn, git failing).
function worktreeBefore(dir: string | undefined): WorkTreeChange | undefined {
  if (dir === undefined) return undefined;
  const top = safeGit(["-C", dir, "rev-parse", "--show-toplevel"])?.trim();
  if (!top) return undefined;
  const head = safeGit(["-C", top, "rev-parse", "--verify", "-q", "HEAD"])?.trim();
  if (!head) return undefined;
  const status = worktreeStatus(top);
  return status && { top: realish(top), head, status, at: Date.now() };
}
// The files a finished git call changed: the paths between the commit before and HEAD now, and
// those whose status or file changed. Directories (a submodule's) come back with `dir`. Undefined
// when git cannot tell.
function worktreeChanged(e: WorkTreeChange): { files: string[]; dirs: string[] } | undefined {
  const head = safeGit(["-C", e.top, "rev-parse", "--verify", "-q", "HEAD"])?.trim();
  if (!head) return undefined;
  const files = new Set<string>();
  const dirs = new Set<string>();
  if (head !== e.head) {
    const raw = gitRun(["-C", e.top, "diff", "--raw", "-z", "--no-renames", "--no-abbrev", e.head, head], 10_000);
    if (raw.status !== 0) return undefined;
    const fields = raw.out.split("\0");
    for (let i = 0; i + 1 < fields.length; i += 2) {
      const meta = fields[i];
      const name = fields[i + 1];
      if (!meta.startsWith(":")) return undefined;
      // A submodule (mode 160000) is a directory git does not list the files of.
      (/\b160000\b/.test(meta) ? dirs : files).add(path.join(e.top, name));
    }
  }
  const now = worktreeStatus(e.top);
  if (!now) return undefined;
  for (const name of new Set([...e.status.keys(), ...now.keys()])) {
    if (e.status.get(name) === now.get(name)) continue;
    const p = path.join(e.top, name);
    let isDir = false;
    try {
      isDir = fs.lstatSync(p).isDirectory();
    } catch {
      // gone
    }
    (isDir ? dirs : files).add(p);
  }
  return { files: [...files], dirs: [...dirs] };
}
// At each decision: the git calls that are over get their changed files marked. (The
// repositories of those that may still run count as marked: see decidePrinted.)
function settleWorktree(session: SessionState): void {
  session.worktree = session.worktree.filter((e) => {
    if (!e.done) return true;
    const changed = worktreeChanged(e);
    if (!changed) {
      if (!session.unlisted.includes(e.top)) session.unlisted.push(e.top);
      return false;
    }
    for (const f of changed.files) session.touched.add(realish(f));
    for (const d of changed.dirs) if (!session.unlisted.includes(realish(d))) session.unlisted.push(realish(d));
    return false;
  });
}

// The rules' deny for a command as it was issued, if they have one (see decideShell). A text
// the rules cannot read at all is not denied by this: the printer and the checks behind it
// decide it.
function deniedAsIssued(guard: Guard, session: SessionState, cwd: string, command: string): Decision | undefined {
  try {
    const verdict = bashVerdict(command, scopeFor(guard, session, cwd, rulesFor(guard, undefined, undefined, false)));
    return verdict.action === "deny" ? fromRules(verdict) : undefined;
  } catch {
    return undefined;
  }
}

export async function decideShell(guard: Guard, session: SessionState, cwd: string, command: string, signal?: AbortSignal, scan: Scan = new Scan(guard.allowedPaths)): Promise<Decision> {
  try {
  projectRoots(session, scan); // takes the git snapshot first (all git calls here run with fsmonitor and hooks off)
  const tampered = gitTampered(session, guard.resumeFile, scan);
  if (tampered) return withApproval(session, askBy(pauseReason(tampered, guard.resumeFile)));
  // The git calls that are over get the files they changed marked (decision D1).
  settleWorktree(session);
  // What the rules deny on the text as it was issued stays denied, whatever the printer makes
  // of it (found by the documents' check): the rules know a fork bomb by its spelling
  // (`:(){ :|:& };:`), which the printed text (`: ( ) { : | : & } ; :`) no longer has, so the
  // canonical run had turned that deny into a rule allow; and a text the printer cannot print
  // would ask, where the rules had denied it. Only a deny is taken from this reading: what the
  // rules ask about or allow is decided on the printed text.
  const issued = deniedAsIssued(guard, session, cwd, command);
  if (issued) return withApproval(session, issued);
  const printed = canonical(command);
  if ("ask" in printed) return withApproval(session, askBy(`the command cannot be printed back in the plain spelling the rules and the shell read alike (${printed.ask})`));
  const decision = await decidePrinted(guard, session, cwd, printed, signal, scan);
  return { ...withApproval(session, decision), printed: printed.text, ...(printed.bashOnly ? { bashOnly: true } : {}) };
  } catch (e) {
    if (e instanceof PathWalkError) return withApproval(session, askBy(e.message));
    throw e;
  }
}
// An ask whose writes the checks did not get to read (it asked before they ran: syntax the rules
// cannot read, a cd they do not follow): once approved, it may have written anywhere in the
// project, which is marked whole (round 4, finding 4, second pass).
function withApproval(session: SessionState, d: Decision): Decision {
  if (d.effect !== "ask" || d.approve) return d;
  return {
    ...d,
    approve: () => {
      for (const r of projectRoots(session).map(realish)) if (!session.unlisted.includes(r)) session.unlisted.push(r);
    },
  };
}

// `printed.text` is what runs: the scanner and the checks that grant trust read it. The rules
// and the guards read `printed.judged` (see canon.ts for the few places where the two differ).
async function decidePrinted(guard: Guard, session: SessionState, cwd: string, printed: Printed, signal: AbortSignal | undefined, scan: Scan): Promise<Decision> {
  const run = printed.text;
  const text = printed.judged;
  // What the layout check could not see (a walk that stopped, a directory that cannot be listed)
  // it cannot vouch for: nothing is allowed without a prompt, sandbox or not (round 3, finding 11).
  const unseen = findGitEntries(projectRoots(session, scan), scan).problems[0];
  // Syntax bash and the rules' parser read differently: nothing below can be trusted on it. The
  // printed text holds few such spellings; what it keeps (arithmetic, `[[ ]]`, the options of a
  // nested shell, builtins that change how later text is read) is judged here.
  // The names arithmetic assigns, judged with the guards below (arithmeticAssignments).
  const arithmeticSets = new Set<string>();
  const syntax = unmodelled(run, 0, undefined, arithmeticSets);
  if (syntax) return askBy(`the rules cannot read this command the way the shell does (${syntax})`);
  const s = single(run, cwd);
  const pushOk = !!s && !!guard.allowFeatureBranchPush && (await pushAllowed(s, session));
  const watch = observer();
  // A package manager's global options before its subcommand (`pnpm --filter web test`, finding
  // 29): the rules read an option's value as the subcommand and leave the call to the model. Each
  // such command whose global options are all known gets the rules' verdict on the same words
  // without them, where it runs: an allow there allows exactly that command's text, an ask or a
  // deny there asks. The guard still checks the options themselves (a directory in the project,
  // nothing that picks a program).
  const managerAllow = new Set<string>();
  const managerAsk: Matcher[] = [];
  const managerOther = new Set<string>();
  {
    const plain = rulesFor(guard, undefined, undefined, false);
    const placed = located(text, realish(cwd));
    for (const cmd of placed.cmds) {
      const at = placed.cwd.get(cmd);
      for (const p of programs(cmd.argv)) {
        const name = path.basename(cmd.argv[p]);
        const rest = withoutGlobals(name, cmd.argv.slice(p + 1));
        if (!rest) continue;
        const own = cmd.argv.slice(p).join(" ");
        const words = [cmd.argv[p], ...rest].map((w) => `'${w.replace(/'/g, "'\\''")}'`).join(" ");
        const v = at === undefined ? undefined : bashVerdict(words, scopeFor(guard, session, at, plain));
        if (v?.action === "allow") managerAllow.add(own);
        // The same text elsewhere in the call, where it does not get an allow, allows neither.
        else managerOther.add(own);
        if (v?.action === "ask" || v?.action === "deny") managerAsk.push({ source: `${name} without its global options: ${v.reason}`, test: (t) => t === own || t === cmd.argv.join(" ") });
      }
    }
  }
  const everyday = everydayRules(guard, session, text, cwd, literalTargets(printed.inputs));
  const rules = rulesFor(guard, watch.matcher, s, pushOk, [{ source: "a package manager command with known global options", test: (t) => managerAllow.has(t) && !managerOther.has(t) }, ...everyday.allow]);
  rules.ask.push(...managerAsk);
  // The same rules without the observer, for each command judged again where it runs (B3c).
  const rulesAt: UserRules = { ...rules, deny: rules.deny.filter((m) => m !== watch.matcher) };
  const scope = scopeFor(guard, session, cwd, rules);
  const verdict = bashVerdict(text, scope);
  if (verdict.action === "deny") return fromRules(verdict);
  const cwdKnown = !/(^|[\s;&|(])(cd|pushd|popd)(\s|$)/.test(text);
  const here = scope.cwd ?? cwd;
  // Every command the rules look at, each with the directory it runs in (plain `cd` followed).
  const where = located(text, here);
  const cmds = where.cmds;
  if (where.hiddenCd) return askBy(where.hiddenCd);
  const dirs = [...new Set([here, ...where.cwd.values()].filter((d): d is string => !!d))];
  // Whether a word names something on disk where the command could run (a `git checkout` path),
  // the path walked as the kernel walks it (round 4, finding 19, second pass: a link before the
  // `..` after it). `at`: the index of the command (as gitProblem counts them), where it is
  // known; a directory the check cannot place (a `cd` in a subshell, `pushd`) could hold the file.
  const exists = (word: string, at?: number) => {
    if (/[$`]/.test(word)) return false;
    const t = tilde(word);
    if (path.isAbsolute(t)) return present(t);
    if (at === undefined) return dirs.some((d) => present(`${d}/${t}`));
    const cwd = at < 0 ? undefined : where.cwd.get(where.cmds[at]);
    return cwd === undefined || present(`${cwd}/${t}`);
  };
  // (The asks below wait until what the call writes is known: an approved call records it.)
  const gitIssue = gitProblem(text, 0, exists) ?? placedGitIssue(cmds, (c) => where.cwd.get(c)) ?? writeProblem(cmds, (c) => where.cwd.get(c), (c) => where.places.get(c)?.map((p) => p.real), projectRoots(session).map(realish));
  const known = () => new Set([...session.files.keys(), ...scope.pending.keys(), ...session.touched]);
  // The file a word names where `cmd` runs. Where that directory is unknown a relative word
  // cannot be placed: it then stands for any file of that name this session wrote.
  const resolve = (word: string, cmd?: Simple): string | undefined => {
    if (/[$`]/.test(word)) return undefined;
    const p = tilde(word);
    const dir = cmd ? where.cwd.get(cmd) : cwdKnown ? here : undefined;
    // `~user`, `~+` and `~-` are other directories: such a word cannot be placed either.
    // Walked as the kernel walks it (round 4, finding 19, second pass).
    if (!/^~[^/]/.test(p) && (path.isAbsolute(p) || dir !== undefined)) return physical(path.isAbsolute(p) ? p : `${dir ?? here}/${p}`);
    return [...known()].find((f) => path.basename(f) === path.basename(p));
  };
  const roots = projectRoots(session);
  const inProject = (p: string) => roots.some((r) => within(realish(p), r));
  // Files written where the rules do not look (`sort -o`, `cp -t`, git's `--output`): held to the
  // rules' own test for a write (round 3, finding 25).
  // B7-11: an `mv` whose every source is a file there now (not a directory, not missing) that no
  // other command of the call names, as a path or a part of one, brings in no directory: it is
  // the write of its destination and nothing else.
  const filesOnly = (sources: string[], cmd: Simple): boolean => {
    const at = where.cwd.get(cmd);
    const paths: string[] = [];
    for (const source of sources) {
      const t = tilde(source);
      if (/[$`*?[\]{}]/.test(source) || /^~[^/]/.test(t) || (!path.isAbsolute(t) && at === undefined)) return false;
      const p = path.isAbsolute(t) ? t : `${at}/${t}`;
      try {
        if (fs.lstatSync(p).isDirectory()) return false;
      } catch {
        return false;
      }
      paths.push(physical(p));
    }
    for (const other of cmds) {
      if (other === cmd) continue;
      const dir = where.cwd.get(other);
      for (const w of [...other.argv.slice(1), ...other.out]) {
        if (w.startsWith("-")) continue;
        const t = tilde(w);
        if (/[$`*?[\]{}]/.test(w) || /^~[^/]/.test(t) || (!path.isAbsolute(t) && dir === undefined)) return false;
        const q = physical(path.isAbsolute(t) ? t : `${dir}/${t}`);
        if (paths.some((p) => within(p, q))) return false;
      }
    }
    return true;
  };
  const found = writesOf(cmds, filesOnly);
  let writeIssue: string | undefined;
  for (const w of found.writes.filter((x) => !x.checked)) {
    if (writeIssue) break;
    const p = resolve(w.word, w.cmd);
    if (p && /^\/dev\/(null|zero|stdout|stderr|fd\/\d+)$/.test(p)) continue;
    if (!p || (!path.isAbsolute(tilde(w.word)) && where.cwd.get(w.cmd) === undefined)) writeIssue = `writes ${w.word}, a place the check cannot tell`;
    else {
      const v = fileVerdict("edit", p, scope);
      if (v.action !== "allow") writeIssue = v.reason.replace(/^edit /, `${path.basename(w.cmd.argv[0] ?? "")} writes `);
    }
  }
  const cwdOf = (c: Simple) => where.cwd.get(c);
  // Directories where this call writes files the check cannot list (round 4, finding 4, signed
  // off): the session keeps them once the call is allowed, and a file run by its path below one
  // goes to the model from then on. A writer that names no directory covers the one it runs in;
  // one that cannot be placed covers the whole project.
  const marks: string[] = [];
  // (B7-2: by the command that makes each mark, for `others`.)
  const marksBy = new Map<Simple, string[]>();
  const note = (cmd: Simple, dirs: string[]) => {
    marks.push(...dirs);
    marksBy.set(cmd, [...(marksBy.get(cmd) ?? []), ...dirs]);
  };
  const project = (cmd: Simple) => note(cmd, roots.map(realish));
  const mark = (dir: string | undefined, cmd: Simple) => {
    const at = cwdOf(cmd);
    if (dir === undefined || (!path.isAbsolute(tilde(dir)) && at === undefined)) project(cmd);
    else note(cmd, [physical(path.isAbsolute(tilde(dir)) ? tilde(dir) : `${at}/${dir}`)]);
  };
  // A git command that writes the work tree (decision D1): what git changed is marked once it is
  // over, from the commit and the status taken now; where they cannot be taken, its directories
  // are marked as before (for git: the whole project).
  const worktree: WorkTreeChange[] = [];
  for (const u of found.unlisted) {
    if (u.git) {
      const at = cwdOf(u.cmd);
      let dir: string | undefined = at;
      for (const d of u.git) dir = /[$`*?[\]]/.test(d) || /^~[^/]/.test(d) ? undefined : path.isAbsolute(tilde(d)) ? tilde(d) : dir === undefined ? undefined : `${dir}/${d}`;
      const before = worktreeBefore(dir);
      if (before) {
        if (!worktree.some((w) => w.top === before.top)) worktree.push(before);
        marksBy.set(u.cmd, [...(marksBy.get(u.cmd) ?? []), before.top]);
        continue;
      }
    }
    for (const d of u.dirs.length ? u.dirs : ["."]) mark(d, u.cmd);
  }
  // A glob as a write target is every file it matches (`sed -i ... scripts/*.sh`); one the guard
  // cannot expand covers the directory it starts from.
  const expand = (word: string, cmd: Simple): string[] | undefined => {
    const at = cwdOf(cmd);
    if (!path.isAbsolute(tilde(word)) && at === undefined) return undefined;
    return expandWord(word, at ?? "/")?.map(realish);
  };
  const globBase = (word: string) => word.split("/").findIndex((part) => /[*?[]/.test(part));
  // (A glob that starts at `/` starts from `/`: round 4, finding 4, second pass.)
  const writes = writtenBy(cmds, resolve, expand, (word, cmd) => mark(word.split("/").slice(0, Math.max(globBase(word), 0)).join("/") || (word.startsWith("/") ? "/" : "."), cmd));
  const written = () => new Set([...known(), ...writes]);
  // A write the check cannot place (after `mkdir x && cd x`, through a variable) is a file it
  // cannot name either: what runs by its path afterwards may be that file.
  const unplacedAll = found.writes.filter((w) => /[$`]/.test(w.word) || (!path.isAbsolute(tilde(w.word)) && cwdOf(w.cmd) === undefined));
  const unplaced = unplacedAll[0];
  for (const w of unplacedAll) project(w.cmd);
  const unknownWrite = found.unknown ?? (unplaced ? `writes ${unplaced.word} where the check cannot place it` : undefined);
  // The repositories of git calls that may still be writing their work tree count as marked.
  const unlisted = [...new Set([...session.unlisted, ...marks, ...session.worktree.map((w) => w.top), ...worktree.map((w) => w.top)])];
  // B7-2: what a program of the call is judged against after a write: the session's writes and
  // those of every other command of the call, wherever it stands in the text (`npm test & echo x
  // > t.test.js`, `f() { npm test; }; echo x > t.test.js; f`, a loop: a later command runs
  // first or beside), less what the command itself writes (`curl -O`, `git pull` in a fresh
  // session, a redirect of its own output).
  const othersOf = new Map<Simple, { written: Set<string>; unlisted: string[] }>();
  const others = (cmd: Simple) => {
    let known = othersOf.get(cmd);
    if (!known) {
      // (A `tee` further down the command's own pipeline writes the command's own output, as a
      // redirect of it does: `npm test 2>&1 | tee test.log`.)
      const pipe = where.pipes.get(cmd);
      const fed = (c: Simple) => pipe !== undefined && where.pipes.get(c) === pipe && cmds.indexOf(c) > cmds.indexOf(cmd) && c.argv[0] === "tee" && !c.out.length;
      const rest = cmds.filter((c) => c !== cmd && !fed(c));
      const theirs = writtenBy(rest, resolve, expand, () => {});
      known = { written: new Set([...session.files.keys(), ...session.touched, ...theirs]), unlisted: [...new Set([...session.unlisted, ...session.worktree.map((w) => w.top), ...rest.flatMap((c) => marksBy.get(c) ?? [])])] };
      othersOf.set(cmd, known);
    }
    return known;
  };
  const gitFiltersAbsent = (cmd: Simple, args: string[], diff = false) => {
    const call = gitCall(args);
    let dir = cwdOf(cmd);
    if (typeof call === "string") return false;
    for (const d of call.dirs) dir = dir === undefined || /[$`]/.test(d) ? undefined : path.isAbsolute(d) ? d : `${dir}/${d}`;
    if (dir === undefined) return false;
    // Status/add can run clean filters; checkout/reset/restore can run smudge/process filters;
    // a diff can run an external diff, a driver's command or its textconv. A fixed command in
    // read-only config may still name a script the project can change (gitProgramsOutside).
    return gitProgramsOutside(dir, diff, inProject);
  };
  const dirsOf = (c: Simple) => {
    const places = where.places.get(c);
    return places && [...new Set(places.map((p) => p.real))];
  };
  // B7-1: the moment on the clock of the file system the judged file lives on.
  const began = (file: string, dev: bigint) => momentOn(session.moment, dev, [path.dirname(file), ...roots, os.homedir()]);
  const context = { gitFiltersAbsent, others, began, cwd: here, cwdKnown, scope, written, resolve, inProject, cwdOf, dirsOf, pattern: (c: Simple) => where.patterns.has(c), envOk: envAssignmentsOk(cmds, cwdOf, inProject), unknownWrite, unlisted, npx: (c: Simple) => everyday.npx.get(cmds.indexOf(c)) };
  const fromText = textGuards(watch.pairs(), context);
  // Each command judged by the rules where it runs, as bash goes there (B3c: `( cd .aws; cat zzz )`),
  // its words as the parser has them: plain ones bare (so that the allows above, which compare
  // texts, read them as before), others quoted.
  const shellWord = (w: string) => (/^[A-Za-z0-9_@%+=:,.\/-]+$/.test(w) ? w : `'${w.replace(/'/g, "'\\''")}'`);
  const judgeAt = (dir: string, words: string[]) => bashVerdict(words.map(shellWord).join(" "), scopeFor(guard, session, dir, rulesAt));
  const fromPlaces = stricter(placedReads(where, scope, judgeAt), inputReads(printed.inputs, text, where, here, scope, printed.judgedInputs));
  const fromWords = stricter(stricter(stricter(argvGuards(cmds, context), expansionProblem(text)), stricter(runtimeReads(text, where, scope), fromPlaces)), arithmeticAssignments(arithmeticSets));
  const combined = !fromText ? fromWords : !fromWords ? fromText : fromText.action === "ask" ? fromText : fromWords.action === "ask" ? fromWords : (fromWords.files ? fromWords : fromText);
  // The rules read a quoted `~` as the home directory, bash does not: their verdict is about other
  // paths than the ones bash uses.
  const oddTilde = tildeMismatch(text);
  const extra = combined ?? (oddTilde ? { action: "classify" as const, reason: oddTilde } : undefined);
  let committed = false;
  const commit = () => {
    if (committed) return;
    committed = true;
    commitWrites(scope);
    for (const p of writes) session.touched.add(p);
    for (const d of marks) if (!session.unlisted.includes(d)) session.unlisted.push(d);
    session.worktree.push(...worktree);
  };
  // An ask carries the record of what the call writes, for when the user approves it.
  // B7-2: a call that was the model's to judge (code the checks do not read: `python3 -c`, a
  // script, a place they cannot tell) may have written, moved or renamed anything in the project
  // once the user approves it: the project is marked whole then, as for an ask the checks never
  // got to read (withApproval). An ask the rules make of a command they read (`git push`) records
  // what it writes, as before; so does a call the model allows.
  const unread = () => {
    for (const r of roots.map(realish)) if (!session.unlisted.includes(r)) session.unlisted.push(r);
  };
  const asked = (d: Decision): Decision => (d.effect === "ask" ? { ...d, approve: d.rule === "classify" ? () => (commit(), unread()) : commit, ...(worktree.length ? { worktree } : {}) } : d);
  const allowed = (d: Decision): Decision => (commit(), worktree.length ? { ...d, worktree } : d);
  if (gitIssue) return asked(askBy(gitIssue));
  if (writeIssue) return asked(askBy(writeIssue));
  if (verdict.action === "ask") return asked(fromRules(verdict));
  if (extra?.action === "ask") return asked(askBy(extra.reason));
  if (unseen) return asked(askBy(`the project's git layout cannot be checked whole: ${unseen}`));
  if (verdict.action === "allow" && !extra) return allowed(fromRules(verdict));
  const why = extra?.reason ?? reword(verdict.reason);
  if (!guard.useClassifier) return asked({ effect: "ask", by: "no-model", rule: "classify", reason: `rules leave this to the model, which is off (${why})` });
  // The model is shown the text that would run.
  const result = await scoreCommand(guard.classifier, { tool: "bash", cwd, command: withFiles(run, extra?.files) }, signal);
  if ("error" in result) return asked({ effect: "ask", by: "model-error", rule: "classify", reason: `model gave no answer: ${result.error}`, ms: result.ms });
  const { score, ms } = result;
  // Written so that a threshold that is not a number asks.
  if (typeof guard.classifier.askAbove !== "number" || !(score < guard.classifier.askAbove)) {
    return asked({ effect: "ask", by: "model", rule: "classify", reason: `model risk ${score.toFixed(2)} (asks at ${guard.classifier.askAbove} and above)`, score, ms });
  }
  return allowed({ effect: "allow", by: "model", rule: "classify", reason: `model risk ${score.toFixed(2)}`, score, ms });
}

// The path with the symlinks of its deepest existing ancestor resolved.
export function realish(p: string): string {
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

// Where `rel` leads from the directory `top` as the kernel walks it (a symbolic link is followed
// before the `..` after it applies), when that is strictly inside `top`; undefined otherwise: an
// absolute path, a place outside or at `top` itself, a `..` after a component that does not exist
// (the kernel stops there), or a link that leads nowhere.
function beneath(top: string, rel: string): string | undefined {
  if (path.isAbsolute(rel)) return undefined;
  let cur = top;
  let missing = false;
  for (const part of rel.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (missing) return undefined;
      cur = path.dirname(cur);
      continue;
    }
    const next = path.join(cur, part);
    if (missing) cur = next;
    else {
      try {
        cur = fs.realpathSync(next);
      } catch {
        if (lexists(next)) return undefined;
        cur = next;
        missing = true;
      }
    }
  }
  return within(cur, top, true) ? cur : undefined;
}

const HOOK_MANAGER_NAME = new RegExp(`^(${literal(HOOK_MANAGER_FILES)})$`);
const OPENCODE_NAME = new RegExp(`^(${literal(OPENCODE_PROJECT_FILES)})$`);
// Every name a write asks about, wherever it appears in a path: `.git`, opencode's project files and
// the hook managers' files.
const PROTECTED_NAMES = [".git", ...OPENCODE_PROJECT_FILES, ...HOOK_MANAGER_FILES];

// Files the sandbox keeps read-only for shell commands; the edit tool must not be a way around.
function protectedFile(guard: Guard, session: SessionState, target: string, scan: Scan): string | undefined {
  const p = realish(target);
  const parts = p.split("/");
  if (parts.includes(".git")) return "changes a file inside a git directory (hooks and config run code)";
  if (parts.some((part) => OPENCODE_NAME.test(part))) return "changes opencode's project-level config, which opencode loads without asking";
  if (parts.some((part) => HOOK_MANAGER_NAME.test(part))) return "changes a hook manager's files, which git hooks run";
  const roots = projectRoots(session, scan);
  const { paths, problems } = protectedPaths({ projectRoots: roots, allowedPaths: guard.allowedPaths, project: session.project }, scan);
  const hit = paths.find((d) => within(p, realish(d)));
  if (hit) return `changes ${hit}, which git or opencode runs or loads`;
  // What could not be protected makes every edit ask, as it makes every shell command ask: the
  // file may be a hook the walk never reached (round 3, finding 11).
  return problems.length ? `cannot be checked: ${problems[0]}` : undefined;
}

// edit/write/patch: only ever tightens. Undefined means "leave opencode's own verdict alone".
export function decideFile(guard: Guard, session: SessionState, cwd: string, target: string): Decision | undefined {
  // One walk of each root for this edit (round 3, finding 40).
  const scan = new Scan(guard.allowedPaths);
  projectRoots(session, scan);
  const scope = scopeFor(guard, session, cwd);
  const verdict = fileVerdict("write", target, scope);
  // opencode reports edit, write and patch alike, so an edit could be a one-line change: a
  // downloaded file stays a downloaded file.
  for (const p of scope.pending.keys()) if (session.files.get(p) === "fetched") scope.pending.delete(p);
  if (verdict.action === "allow") {
    const reason = protectedFile(guard, session, path.resolve(cwd, target), scan);
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
