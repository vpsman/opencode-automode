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
  type Simple,
  type Verdict,
} from "./rules.ts";
import { scoreCommand, type ClassifierConfig } from "./kev.ts";
import { findGitEntries, gitArgs, gitEnv, gitRun, HOOK_MANAGER_FILES, OPENCODE_CONFIG_NAMES, OPENCODE_PROJECT_FILES, opencodeDirs, protectedPaths, realpath, safeGit } from "./sandbox.ts";
import { abbreviates, allCommands, alsoByName, argvGuards, gitCall, gitProblem, landing, observer, single, strict, strictCommands, textGuards, tilde, unmodelled, writtenBy, type Single } from "./guard.ts";

export type Effect = "allow" | "ask" | "deny";

const literal = (names: string[]) => names.map((n) => n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("|");

// Ask rules added on top of upstream's, from the bench's rule-allowed risky rows and this
// deployment's needs. Pi user rules: a glob over one simple command (`*` any text, trailing ` *`
// optional) or `re:` + a regex; they also match the command without wrappers like `timeout`.
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
  // Files a command of this session wrote, appended to or edited in place. The rules' own list
  // (`files`) leaves an appended file's origin alone and does not follow `sed -i`.
  touched = new Set<string>();
  roots: string[] | undefined;
  // The project's git layout as first seen (outside any sandbox), and its remote URLs.
  snapshot: GitSnapshot | undefined;
  // Set once the layout changed in a way git never does itself; auto-allow stops until the user
  // resumes it.
  tampered: { reason: string; at: number } | undefined;
  // Repositories and worktrees the user approved: a `git init`, `clone`, `worktree add` or
  // `submodule` command this session asked about, once it was approved and while it runs. Only
  // what appears inside the directories that command named is expected.
  expecting: Expected[] = [];
  constructor(project: string) {
    this.project = realpath(project);
  }
}

export interface Expected {
  dirs: string[];
  at: number;
  // Set when the approved command has finished: the next check is the last this covers.
  done?: boolean;
}

type RemoteUrls = Map<string, { fetch: string[]; push: string[] }>;

interface GitSnapshot {
  // Per checkout root: what `.git` is (directory inode, or pointer file contents).
  entries: { root: string; kind: "dir" | "file" | "link" | "none"; ino?: number; text?: string }[];
  // Nested repositories and pointer files found below the roots: they must not change either.
  nested: { path: string; ino?: number; text?: string }[];
  // Every git directory and pointer file known when the snapshot was taken.
  known: Set<string>;
  // Per git directory: whether it had `commondir` and `config.worktree`, and its linked worktrees.
  inside: Map<string, { commondir: boolean; configWorktree: boolean; worktrees: string[] }>;
  commonDir: string | undefined;
  // Undefined when git could not tell: nothing is then trusted about remotes.
  remotes: RemoteUrls | undefined;
  // Which of opencode's project-level files existed, in the session directory and the writable
  // directories above it (full paths).
  opencodeFiles: Set<string>;
}

function gitEntry(root: string): GitSnapshot["entries"][number] {
  const p = path.join(root, ".git");
  try {
    const st = fs.lstatSync(p);
    if (st.isDirectory()) return { root, kind: "dir", ino: st.ino };
    if (st.isFile()) return { root, kind: "file", text: fs.readFileSync(p, "utf8") };
    // A link named `.git` is a repository too, wherever it points.
    if (st.isSymbolicLink()) return { root, kind: "link", text: fs.readlinkSync(p) };
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
  const atRoot = (p: string) => roots.some((r) => p === path.join(r, ".git"));
  const nested = [
    ...[...found.gitDirs].filter((d) => !mainGitDirs.includes(d)).map((d) => ({ path: d, ino: statIno(d) })),
    ...[...found.pointers].filter((p) => !atRoot(p)).map((p) => ({ path: p, text: readText(p) })),
    ...[...found.links].filter((p) => !atRoot(p)).map((p) => ({ path: p, text: readLink(p) })),
  ];
  return {
    entries,
    nested,
    known: new Set([...found.gitDirs, ...found.pointers, ...found.links]),
    inside: new Map([...found.gitDirs].map((d) => [d, insideOf(d)])),
    commonDir: common ? realpath(path.resolve(project, common)) : undefined,
    remotes: readRemotes(project),
    opencodeFiles: new Set(opencodeFiles(project, roots).filter(lexists)),
  };
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
// makes on its own; `appeared` lists new repositories, worktrees and config files with where
// they are: fine inside a directory an approved command named, tampering anywhere else.
interface Appeared {
  path: string;
  text: string;
  // opencode's own files are never explained by a git command.
  opencode?: boolean;
}
function layoutChanges(session: SessionState): { replaced: string[]; appeared: Appeared[] } {
  const snap = session.snapshot!;
  const replaced: string[] = [];
  const appeared: Appeared[] = [];
  for (const before of snap.entries) {
    const now = gitEntry(before.root);
    const p = path.join(before.root, ".git");
    if (before.kind === "none" && now.kind !== "none") appeared.push({ path: p, text: `${p} appeared${now.kind === "link" ? " (a symbolic link)" : ""}` });
    else if (now.kind !== before.kind || now.ino !== before.ino || now.text !== before.text) replaced.push(`${p} was replaced or rewritten`);
    // A main checkout's git directory never has a `commondir`, whenever it got there.
    if (now.kind === "dir" && fs.existsSync(path.join(p, "commondir"))) replaced.push(`${path.join(p, "commondir")} appeared`);
  }
  // A nested repository that is gone was deleted, which plants nothing: forget it. One that is
  // there but different was swapped.
  snap.nested = snap.nested.filter((before) => {
    if (!lexists(before.path)) return snap.known.delete(before.path), false;
    const same = before.ino !== undefined ? statIno(before.path) === before.ino : (readText(before.path) ?? readLink(before.path)) === before.text;
    if (!same) replaced.push(`${before.path} was replaced, moved or rewritten`);
    return true;
  });
  const roots = session.roots ?? [];
  const found = findGitEntries(roots);
  for (const p of [...found.gitDirs, ...found.pointers, ...found.links]) {
    if (!snap.known.has(p) && !roots.some((r) => p === path.join(r, ".git") || p === realpath(path.join(r, ".git")))) appeared.push({ path: p, text: `${p} appeared${found.links.has(p) ? " (a symbolic link named .git)" : ""}` });
  }
  for (const [dir, before] of snap.inside) {
    if (!fs.existsSync(dir)) continue;
    const now = insideOf(dir);
    if (now.commondir && !before.commondir) replaced.push(`${path.join(dir, "commondir")} appeared`);
    if (now.configWorktree && !before.configWorktree) replaced.push(`${path.join(dir, "config.worktree")} appeared`);
    for (const wt of now.worktrees) if (!before.worktrees.includes(wt)) appeared.push({ path: path.join(dir, "worktrees", wt), text: `${path.join(dir, "worktrees", wt)} appeared (a new linked worktree)` });
  }
  // `.opencode` in the session directory is left out: the plugin creates it empty so that it
  // can be made read-only.
  for (const p of opencodeFiles(session.project, roots)) {
    if (p !== path.join(session.project, ".opencode") && !snap.opencodeFiles.has(p) && lexists(p)) appeared.push({ path: p, text: `${p} appeared (opencode loads it without asking)`, opencode: true });
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
  // What an approved command named is expected while that command runs, and at the first check
  // after it has finished. An approval lasts ten minutes at most.
  const expecting = session.expecting.filter((e) => Date.now() - e.at < EXPECT_MS);
  session.expecting = expecting.filter((e) => !e.done);
  const expected = (a: Appeared) => !a.opencode && expecting.some((e) => e.dirs.some((dir) => within(a.path, dir)));
  const found = [...replaced, ...appeared.filter((a) => !expected(a)).map((a) => a.text)];
  if (found.length) {
    const shown = found.slice(0, 5).join("; ") + (found.length > 5 ? `; and ${found.length - 5} more` : "");
    session.tampered = { reason: shown, at: Date.now() };
    return shown;
  }
  if (appeared.length) {
    // A new worktree of the project joins it when the approved command named its directory and
    // it lies inside the folder that holds the main checkout.
    const now = checkouts(session.project);
    const parent = path.dirname(now[0] ?? "/");
    for (const dir of now) {
      if (session.roots && !session.roots.includes(dir) && !isRootLike(parent) && within(dir, parent) && expecting.some((e) => e.dirs.some((d) => within(dir, d)))) session.roots.push(dir);
    }
    session.snapshot = takeSnapshot(session.roots ?? [], session.project);
  }
  return undefined;
}
const EXPECT_MS = 600_000;

const pauseReason = (found: string, resumeFile?: string) =>
  `auto-allow paused for this session: ${found}. Check what is there; approving this prompt does not resume.${resumeFile ? ` To resume, run \`touch ${resumeFile}\` in your own terminal.` : ""}`;

// Where a command the user is asked about would create repositories or worktrees: the
// directories its `git init`, `clone`, `worktree add` and `submodule` calls name, read from
// plain words only. Undefined when it creates none, or is not written in plain words (what then
// appears pauses the session, and the user resumes it).
export function expectedRepos(command: string, cwd: string): string[] | undefined {
  const cmds = strictCommands(command, { nullRedirects: true });
  if (!cmds) return undefined;
  const dirs: string[] = [];
  let dir = cwd;
  for (const { argv } of cmds) {
    if (argv[0] === "cd" && argv.length === 2) dir = path.resolve(dir, tilde(argv[1]));
    if (argv[0] !== "git") continue;
    const call = gitCall(argv.slice(1));
    if (typeof call === "string") continue;
    const base = call.dirs.reduce((at, d) => path.resolve(at, tilde(d)), dir);
    const words = call.rest.filter((w) => !w.startsWith("-"));
    // The repository's own git directory gets `worktrees/<name>` and `modules/<name>`.
    const common = () => {
      const out = safeGit(["-C", base, "rev-parse", "--git-common-dir"])?.trim();
      return out ? [realish(path.resolve(base, out))] : [];
    };
    const named = (p: string) => realish(path.resolve(base, tilde(p)));
    if (call.sub === "init") dirs.push(named(words[0] ?? "."));
    else if (call.sub === "clone" && words.length) dirs.push(named(words[1] ?? path.basename(words[0].replace(/\/+$/, "")).replace(/\.git$/, "")));
    else if (call.sub === "worktree" && words[0] === "add" && words[1]) dirs.push(named(words[1]), ...common());
    else if (call.sub === "submodule" && words[0] === "add" && words[1]) dirs.push(named(words[2] ?? path.basename(words[1].replace(/\/+$/, "")).replace(/\.git$/, "")), ...common());
    else if (call.sub === "submodule" && (words[0] === "update" || words[0] === "init")) {
      // The places are the ones .gitmodules declares.
      const top = safeGit(["-C", base, "rev-parse", "--show-toplevel"])?.trim();
      const listed = top ? safeGit(["config", "--file", path.join(top, ".gitmodules"), "--get-regexp", "^submodule\\..*\\.path$"]) : undefined;
      for (const line of lines(listed ?? "")) dirs.push(realish(path.resolve(top!, line.slice(line.indexOf(" ") + 1).trim())));
      if (listed) dirs.push(...common());
    }
  }
  return dirs.length ? dirs : undefined;
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
  // Without a dash, `e` shows every process's environment.
  ps: { flags: "eAfFlwHjTLMyZaxu", long: ["--forest", "--no-headers"], valued: ["-o", "-p", "-u", "-U", "-C", "--sort", "--pid", "--ppid"], check: (ops) => ops.every((w) => /^[aAxufwlHjTLmc]+$/.test(w)) },
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
    else if (argv[0] === "test" || argv[0] === "[") continue; // operators, checked by the program's own check
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

const run = (args: string[], timeout: number) =>
  new Promise<string | undefined>((resolve) => {
    execFile("git", gitArgs(args), { encoding: "utf8", timeout, maxBuffer: 1 << 20, env: gitEnv() }, (error, stdout) => resolve(error ? undefined : stdout));
  });

// The project's own checkout, at its top: the directory is a mount of its own in every sandbox,
// so no other command can swap it for something else between this check and the command.
const atRoot = (dir: string, session: SessionState) => projectRoots(session).includes(realpath(dir));

// Hooks git would run for the command, with the ssh agent in reach. A hook is the user's own, but
// it often runs the project's scripts, which a sandboxed command can edit.
const HOOKS_RUN: Record<string, string[] | "any"> = { fetch: ["reference-transaction"], "ls-remote": [], push: ["pre-push", "reference-transaction"], pull: "any" };
function hookWouldRun(dir: string, sub: string, config: [string, string, string][]): boolean {
  const configured = config.filter(([scope, key]) => scope !== "command" && key === "core.hookspath").at(-1)?.[2];
  const base = configured ? safeGit(["-C", dir, "rev-parse", "--show-toplevel"])?.trim() : safeGit(["-C", dir, "rev-parse", "--git-common-dir"])?.trim();
  if (!base) return true; // cannot tell
  const hooks = configured ? path.resolve(base, tilde(configured)) : path.resolve(dir, base, "hooks");
  const wanted = HOOKS_RUN[sub] ?? "any";
  let names: string[];
  try {
    names = fs.readdirSync(hooks);
  } catch {
    return false; // no hooks directory
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

// The remote a command with no remote operand uses, by git's own order of precedence.
function defaultRemote(dir: string, sub: string): string | null {
  const head = gitRun(["-C", dir, "symbolic-ref", "--quiet", "--short", "HEAD"]);
  if (head.status === undefined) return null;
  const current = head.status === 0 ? head.out.trim() : undefined;
  const keys = [...(sub === "push" ? [...(current ? [`branch.${current}.pushRemote`] : []), "remote.pushDefault"] : []), ...(current ? [`branch.${current}.remote`] : [])];
  for (const key of keys) {
    const value = configValue(dir, key);
    if (value === null) return null;
    if (value) return value;
  }
  return "origin";
}

// What `git push <words>` would do, asked of git itself (`--dry-run --porcelain`): which URL it
// connects to and which ref goes where. Git applies its own precedence (branch.*.pushRemote,
// remote.pushDefault, remote.*.push, push.default, followTags); reading the config here and
// guessing would miss one of them. Hooks, askpass and prompts are off for the plugin's git.
async function dryRunPush(dir: string, words: string[]): Promise<{ urls: string[]; refs: { flag: string; from: string; to: string }[] } | undefined> {
  const out = await run(["-C", dir, "push", "--dry-run", "--porcelain", ...words.filter((w) => w !== "--porcelain" && w !== "-n" && w !== "--dry-run")], 8000);
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
  if (hookWouldRun(dir, "push", config)) return false;
  // `+x` forces, `:x` deletes, wildcards, tags and other ref namespaces are out of scope.
  if (refspecs.some((spec) => !spec || spec.startsWith("+") || spec.startsWith(":") || spec.includes("*") || spec.split(":").length > 2 || /^refs\/(?!heads\/)/.test(spec))) return false;
  const would = await dryRunPush(dir, words);
  if (!would || !would.urls.length || !would.refs.length) return false;
  // Every URL git would connect to belongs to a remote the session started with, unchanged
  // since (all of its URLs: git pushes to each).
  const now = readRemotes(dir);
  const names = [...snap.remotes.keys()].filter((name) => sameUrls(snap.remotes, now, name) && would.urls.some((url) => snap.remotes!.get(name)!.push.includes(url)));
  if (!names.length || !would.urls.every((url) => names.some((name) => snap.remotes!.get(name)!.push.includes(url)))) return false;
  // The remote's default branch, asked of the remote itself (the local refs/remotes/<r>/HEAD can be
  // rewritten). Repository config that could change how git connects was rejected above, and no
  // askpass program runs.
  const defaults = new Set<string>();
  for (const name of names) {
    const symref = await run(["-C", dir, "ls-remote", "--symref", name, "HEAD"], 8000);
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
const GIT_WRITERS = new Set(["add", "commit", "checkout", "switch", "restore", "stash", "reset", "merge", "cherry-pick", "revert", "rebase", "tag", "branch", "fetch", "pull", "push", "mv", "rm", "status", "log", "diff", "show", "notes", "gc", "prune", "pack-refs", "update-index", "rev-parse", "ls-files", "describe", "blame", "shortlog", "reflog"]);
const GIT_FILE_OPTIONS = ["--output", "--output-directory", "--exec", "--template", "--upload-pack", "--receive-pack", "--interactive", "--patch"];
// Short options that name a program or open an editor, by subcommand. Elsewhere `-u`, `-F` and
// `-o` are harmless (`add -u`, `stash -u`, `commit -F msg`, `commit -o`).
const GIT_SHORT_REFUSED: Record<string, RegExp> = { fetch: /^-[a-zA-Z]*u/, pull: /^-[a-zA-Z]*u/, rebase: /^-[a-zA-Z]*[xi]/, add: /^-[a-zA-Z]*[ipe]/, commit: /^-[a-zA-Z]*[pe]/, checkout: /^-[a-zA-Z]*p/, restore: /^-[a-zA-Z]*p/, reset: /^-[a-zA-Z]*p/, stash: /^-[a-zA-Z]*p/ };
// The commit message most agents write: `-m "$(cat <<'EOF' ... EOF)"`. The delimiter is quoted,
// so the body is text and nothing in it is expanded; it reads as one plain word.
const HEREDOC_MESSAGE = /"\$\(cat <<'([A-Za-z_][A-Za-z0-9_]*)'\n(?:(?!\1\n)[^\n]*\n)*\1\n[ \t]*\)"/g;

// A tool call made only of `git <writer>` commands (and `cd`), in plain words: no substitutions,
// variables or options that write files or run programs; output may go to /dev/null or be
// merged (`2>&1`). Only such calls get write access inside git directories (minus hooks and
// config); for everything else git directories are read-only.
export function gitOnly(command: string): boolean {
  const cmds = strict(command.replace(HEREDOC_MESSAGE, "MESSAGE"), { nullRedirects: true });
  if (!cmds) return false;
  return cmds.every((full) => {
    if (full[0] === "cd") return full.length <= 2;
    const argv = full[0] === "timeout" && /^\d+(\.\d+)?[smhd]?$/.test(full[1] ?? "") ? full.slice(2) : full;
    if (argv[0] !== "git") return false;
    const call = gitCall(argv.slice(1));
    if (typeof call === "string" || !GIT_WRITERS.has(call.sub ?? "")) return false;
    const refused = GIT_SHORT_REFUSED[call.sub ?? ""];
    return !call.rest.some((w) => (refused?.test(w) && !w.startsWith("--")) || abbreviates(w, GIT_FILE_OPTIONS));
  }) && cmds.some((argv) => argv.includes("git"));
}

const FETCH_FLAGS = new Set([
  "-q", "--quiet", "-v", "--verbose", "--all", "-p", "--prune", "-t", "--tags", "--no-tags", "-f", "--force", "-n", "--dry-run", "--rebase", "--no-rebase", "--ff-only", "--ff",
  "--no-ff", "--autostash", "--no-autostash", "--progress", "--no-progress", "--heads", "--refs", "--symref", "--exit-code", "--porcelain", "--atomic",
]);

// Whether a tool call gets the ssh agent and ~/.ssh's known_hosts/config (never private keys):
// only a single plain `git fetch/pull/push/ls-remote` at the top of the project's own checkout,
// to a remote that was configured when the session started, with options from a short list and
// no hook that would run; or a single `ssh`/`scp` command (which the rules only allow for
// sshHosts).
export function usesSsh(command: string, cwd: string, session: SessionState): boolean {
  projectRoots(session);
  const s = single(command, cwd);
  if (!s) return false;
  if (s.argv[0] === "ssh" || s.argv[0] === "scp") return true;
  const call = plainGit(s, /^(fetch|pull|push|ls-remote)$/);
  if (!call) return false;
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
  return names.every((n) => known.has(n) && sameUrls(known, now, n)) && refs.every((r) => /^[\w.\/@:+^~-]+$/.test(r));
}

const SSH_URL = /^(ssh:\/\/|git\+ssh:\/\/|ssh\+git:\/\/|[\w.-]+@[\w.-]+:|[\w.-]+:(?!\/\/))/;
const NETWORK = new Set(["fetch", "pull", "push", "ls-remote"]);
// Whether the subcommand writes inside the git directory. `branch`, `tag`, `stash` and `notes`
// only list when they are given no name.
const WRITES_GIT = new Set(["add", "commit", "checkout", "switch", "restore", "stash", "reset", "merge", "cherry-pick", "revert", "rebase", "am", "tag", "branch", "fetch", "pull", "push", "mv", "rm", "notes", "gc", "prune", "pack-refs", "update-index"]);
function writesGit(sub: string, rest: string[]): boolean {
  if (!WRITES_GIT.has(sub)) return false;
  const words = rest.filter((w) => !w.startsWith("-"));
  if (sub === "stash") return !["list", "show"].includes(words[0] ?? "");
  if (sub === "branch" || sub === "tag") return words.length > 0 && !rest.some((w) => /^(-l|--list|-a|--all|-r|--remotes|--contains|--merged|--no-merged|--show-current|--points-at)$/.test(w));
  if (sub === "notes") return !["list", "show", undefined].includes(words[0]);
  return true;
}

// "Allowed" must mean the command can work. These are allowed by the rules and then fail in
// the sandbox, with an error the agent cannot do anything about: git writing its own directory
// from a call that is not made only of plain git commands, git signing with a key the sandbox
// hides, git logging in over ssh without the agent or over https through a credential helper.
// Each asks instead, so that an approved run happens outside the sandbox.
export function sandboxBreaks(command: string, cwd: string, session: SessionState): string | undefined {
  const calls: { sub: string; rest: string[] }[] = [];
  for (const { argv } of allCommands(command)) {
    argv.forEach((word, at) => {
      if (path.basename(word) !== "git") return;
      const call = gitCall(argv.slice(at + 1));
      if (typeof call !== "string" && call.sub) calls.push({ sub: call.sub, rest: call.rest });
    });
  }
  if (!calls.length) return undefined;
  const writer = calls.find((c) => writesGit(c.sub, c.rest));
  if (writer && !gitOnly(command)) return `git ${writer.sub} writes inside .git, which is read-only unless the tool call is made only of plain git commands`;
  const dir = session.project;
  if (calls.some((c) => ["commit", "merge", "rebase", "cherry-pick", "revert", "am", "pull"].includes(c.sub)) && configBool(dir, "commit.gpgsign") !== false && configBool(dir, "commit.gpgsign") !== undefined) return "git signs commits here, and the sandbox hides the keys and the agents that hold them";
  if (calls.some((c) => (c.sub === "commit" && c.rest.some((w) => /^(-[a-zA-Z]*S|--gpg-sign)/.test(w))) || (c.sub === "tag" && c.rest.some((w) => /^(-[a-zA-Z]*[su]|--sign|--local-user)/.test(w))))) return "git signs here, and the sandbox hides the keys and the agents that hold them";
  if (!calls.some((c) => NETWORK.has(c.sub))) return undefined;
  const urls = [...(session.snapshot?.remotes?.values() ?? [])].flatMap((r) => [...r.fetch, ...r.push]);
  if (urls.some((url) => SSH_URL.test(url)) && !usesSsh(command, cwd, session)) return "git would need your ssh agent, which only a single plain git fetch, pull, push or ls-remote at the top of the project gets (and only when no hook would run)";
  const helper = configValue(dir, "credential.helper");
  if (urls.some((url) => /^https?:\/\//.test(url)) && helper !== undefined) return "git would log in through a credential helper, and the sandbox hides what credential helpers use";
  return undefined;
}

// Programs whose operands are written to: every one of them, or only the last.
const WRITER_OPERANDS: Record<string, "all" | "last"> = {
  cp: "last", ln: "last", install: "last", rsync: "last",
  mv: "all", tee: "all", truncate: "all", touch: "all", mkdir: "all", rmdir: "all", chmod: "all", chown: "all", chgrp: "all", setfacl: "all", shred: "all", unlink: "all", patch: "all", rm: "all", sed: "all",
};

// A write the rules' Matchers do not see as one: into a path with a `.git` component (a new
// repository, or a link named `.git`), opencode's project files or a hook manager's files. The
// targets are redirects and the operands of the programs that write.
function writeProblem(cmds: Simple[]): string | undefined {
  for (const cmd of cmds) {
    const targets = [...cmd.out];
    cmd.argv.forEach((word, at) => {
      const how = Object.hasOwn(WRITER_OPERANDS, path.basename(word)) ? WRITER_OPERANDS[path.basename(word)] : undefined;
      const args = cmd.argv.slice(at + 1);
      const files = args.filter((a) => !a.startsWith("-"));
      if (path.basename(word) === "sed" && !args.some((a) => /^(-[a-zA-Z]*i|--in-place)/.test(a))) return;
      if (path.basename(word) === "dd") targets.push(...args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3)));
      else if (how) targets.push(...(how === "last" ? files.slice(-1) : files));
    });
    for (const target of targets) {
      const parts = target.split("/");
      if (parts.includes(".git")) return `writes ${target}: a path inside or named .git, where git finds hooks and config`;
      if (parts.some((part) => OPENCODE_NAME.test(part) || HOOK_MANAGER_NAME.test(part))) return `writes ${target}, which opencode or a git hook loads and runs`;
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
  const cmds = allCommands(command);
  const gitIssue = gitProblem(command) ?? writeProblem(cmds);
  if (gitIssue) return askBy(gitIssue);
  const cwdKnown = !/(^|[\s;&|(])(cd|pushd|popd)(\s|$)/.test(command);
  const here = scope.cwd ?? cwd;
  const known = () => new Set([...session.files.keys(), ...scope.pending.keys(), ...session.touched]);
  // The file a word names. After a `cd` a relative word cannot be placed: it then stands for any
  // file of that name this session wrote.
  const resolve = (word: string): string | undefined => {
    if (/[$`]/.test(word)) return undefined;
    const p = tilde(word);
    if (path.isAbsolute(p) || cwdKnown) return realish(path.resolve(here, p));
    return [...known()].find((f) => path.basename(f) === path.basename(p));
  };
  const writes = writtenBy(cmds, resolve);
  const written = () => new Set([...known(), ...writes]);
  const context = { cwd: here, cwdKnown, scope, written, resolve };
  const fromText = textGuards(watch.pairs(), context);
  const fromWords = argvGuards(cmds, context);
  const extra = !fromText ? fromWords : !fromWords ? fromText : fromText.action === "ask" ? fromText : fromWords.action === "ask" ? fromWords : (fromWords.files ? fromWords : fromText);
  const commit = () => {
    commitWrites(scope);
    for (const p of writes) session.touched.add(p);
  };
  if (verdict.action === "ask") return fromRules(verdict);
  if (extra?.action === "ask") return askBy(extra.reason);
  if (verdict.action === "allow" && !extra) {
    commit();
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
  commit();
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

const HOOK_MANAGER_NAME = new RegExp(`^(${literal(HOOK_MANAGER_FILES)})$`);
const OPENCODE_NAME = new RegExp(`^(${literal(OPENCODE_PROJECT_FILES)})$`);

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
