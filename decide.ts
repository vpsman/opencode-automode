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
import { findGitEntries, gitArgs, Scan, gitEnv, gitRun, HOOK_MANAGER_FILES, OPENCODE_CONFIG_NAMES, OPENCODE_PROJECT_FILES, opencodeDirs, protectedPaths, realpath, safeGit } from "./sandbox.ts";
import { abbreviates, allCommands, EDITOR_ASSIGNMENT, editorCommand, programs, withoutGlobals, alsoByName, argvGuards, envAssignmentsOk, expansionProblem, gitCall, gitProblem, landing, located, observer, protectedNameIn, runtimeReads, single, stricter, strict, strictCommands, textGuards, tilde, tildeMismatch, unmodelled, writesOf, writtenBy, type Single } from "./guard.ts";

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
  // Only a few harmless keys run without asking. Git's own `-c` comes before the subcommand: after
  // it, `-c` is the subcommand's (`switch -c <branch>`, `grep -c`, `diff -c`), round 3 also-list.
  // (`clone -c`/`--config` asks by the init/clone rule below; gitCall asks on any global `-c` key
  // outside the same list.)
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
  // Git-only calls since the last check of the git directories' operation state.
  gitCalls: GitCall[] = [];
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
  // What was inside each `.opencode` there (the plugin makes the session's own, empty), and which
  // hook managers' files were at the top of each checkout: an archive or a patch can drop one in
  // under a name no command line shows (round 3, finding 24).
  opencodeInside: Set<string>;
  hookFiles: Set<string>;
  // The operation state in each git directory and linked worktree's git directory (gitState).
  state: Map<string, Map<string, string>>;
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

function takeSnapshot(roots: string[], project: string, scan?: Scan): GitSnapshot {
  const entries = roots.map(gitEntry);
  const mainGitDirs = entries.filter((e) => e.kind === "dir").map((e) => realpath(path.join(e.root, ".git")));
  const common = git(project, "rev-parse", "--git-common-dir")?.trim();
  const found = findGitEntries(roots, scan);
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
    opencodeInside: new Set(opencodeInside(project, roots)),
    hookFiles: new Set(hookFiles(roots, found)),
    state: new Map([...found.gitDirs].flatMap((d) => [...gitState(d)])),
  };
}

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
function stateChanges(session: SessionState): string[] {
  const snap = session.snapshot!;
  const calls = session.gitCalls.filter((c) => Date.now() - c.at < EXPECT_MS);
  session.gitCalls = calls.filter((c) => !c.done);
  const by = (name: string) => calls.some((c) => (GIT_TODO[name] ? GIT_TODO[name].some((sub) => c.subs.has(sub)) : [...c.subs].some((sub) => GIT_STATE_BY[sub]?.test(name))));
  const out: string[] = [];
  const now = new Map([...snap.inside.keys()].flatMap((d) => [...gitState(d)]));
  for (const [dir, here] of now) {
    const before = snap.state.get(dir) ?? new Map<string, string>();
    if (!calls.length) continue;
    for (const [name, value] of here) {
      const was = before.get(name);
      const p = path.join(dir, name);
      if (was === undefined && !by(name)) out.push(`${p} appeared (git state that the git commands which ran do not leave)`);
      else if (was !== undefined && was !== value && GIT_TODO[name] && !by(name)) out.push(`${p} changed (a todo list that the git commands which ran do not change)`);
      if (name === "rebase-merge/git-rebase-todo") {
        const known = new Set(execLines(was));
        const added = execLines(value).filter((l) => !known.has(l));
        if (added.length) out.push(`${p} gained an exec line (${JSON.stringify(added[0].slice(0, 80))}), which \`git rebase --continue\` would run`);
      }
    }
  }
  snap.state = now;
  return out;
}

// The operation-state check alone, for when a git-only call is over: it reads only the git
// directories already known, so it walks nothing. Pauses the session as gitTampered does.
export function gitStateTampered(session: SessionState): string | undefined {
  if (session.tampered) return session.tampered.reason;
  if (!session.snapshot) return undefined;
  const found = stateChanges(session);
  if (found.length) session.tampered = { reason: shown(found), at: Date.now() };
  return session.tampered?.reason;
}
const shown = (found: string[]) => found.slice(0, 5).join("; ") + (found.length > 5 ? `; and ${found.length - 5} more` : "");

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
function layoutChanges(session: SessionState, scan?: Scan): { replaced: string[]; appeared: Appeared[] } {
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
  const found = findGitEntries(roots, scan);
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
  for (const p of opencodeInside(session.project, roots)) {
    if (!snap.opencodeInside.has(p)) appeared.push({ path: p, text: `${p} appeared (opencode loads it without asking)`, opencode: true });
  }
  // A hook manager's file at the top of a checkout: a git hook hands control to it. One inside a
  // directory an approved clone or submodule named is that repository's own.
  for (const p of hookFiles(roots, found)) {
    if (!snap.hookFiles.has(p)) appeared.push({ path: p, text: `${p} appeared (a git hook hands control to it)` });
  }
  return { replaced, appeared };
}

// Whether the project's git layout changed since the session started in a way git never does on
// its own: `.git` replaced or renamed, a pointer file rewritten, `commondir` planted, a
// repository, worktree or opencode config file appearing that no approved command explains, or
// operation state that the git-only calls which ran do not leave (stateChanges).
// Returns what was found, so the prompt can say it. The pause lasts until `resumeFile` is touched.
// `scan`: the walks of the decision this check is part of (round 3, finding 40).
export function gitTampered(session: SessionState, resumeFile?: string, scan?: Scan): string | undefined {
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
    session.snapshot = takeSnapshot(session.roots ?? [], session.project, scan);
    return undefined;
  }
  if (!session.snapshot) return undefined;
  const { replaced, appeared } = layoutChanges(session, scan);
  const states = stateChanges(session);
  // What an approved command named is expected while that command runs, and at the first check
  // after it has finished. An approval lasts ten minutes at most.
  const expecting = session.expecting.filter((e) => Date.now() - e.at < EXPECT_MS);
  session.expecting = expecting.filter((e) => !e.done);
  const expected = (a: Appeared) => !a.opencode && expecting.some((e) => !e.tainted && e.dirs.some((dir) => within(a.path, dir)));
  const found = [...replaced, ...states, ...appeared.filter((a) => !expected(a)).map((a) => a.text)];
  if (found.length) {
    session.tampered = { reason: shown(found), at: Date.now() };
    return session.tampered.reason;
  }
  if (appeared.length) {
    // A new worktree of the project joins it when the approved command named its directory and
    // it lies inside the folder that holds the main checkout.
    const now = checkouts(session.project);
    const parent = path.dirname(now[0] ?? "/");
    for (const dir of now) {
      if (session.roots && !session.roots.includes(dir) && !isRootLike(parent) && within(dir, parent) && expecting.some((e) => !e.tainted && e.dirs.some((d) => within(dir, d)))) session.roots.push(dir);
    }
    session.snapshot = takeSnapshot(session.roots ?? [], session.project, scan);
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
  const cmds = strictCommands(command, { nullRedirects: true });
  // A `~` bash expands differently from `tilde()` would name the wrong place.
  if (!cmds || cmds.some((c) => c.quotedTilde)) return undefined;
  const dirs: string[] = [];
  let dir = cwd;
  for (const { argv } of cmds) {
    if (argv[0] === "cd" && argv.length === 2) dir = path.resolve(dir, tilde(argv[1]));
    if (argv[0] !== "git") continue;
    const call = gitCall(argv.slice(1));
    if (typeof call === "string") continue;
    const base = call.dirs.reduce((at, d) => path.resolve(at, tilde(d)), dir);
    // The repository's own git directory gets `worktrees/<name>` and `modules/<name>`.
    const common = () => {
      const out = safeGit(["-C", base, "rev-parse", "--git-common-dir"])?.trim();
      return out ? [realish(path.resolve(base, out))] : [];
    };
    const named = (p: string) => realish(path.resolve(base, tilde(p)));
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
const REPO_CONFIG_OK =
  /^(core\.(repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks|autocrlf|eol|safecrlf|quotepath|abbrev|compression|bigfilethreshold|preloadindex|commitgraph|multipackindex|sparsecheckout|sparsecheckoutcone|longpaths|untrackedcache|splitindex|sharedrepository)|remote\..+\.(url|fetch|tagopt|prune|prunetags|promisor|partialclonefilter|skipdefaultupdate|gh-resolved)|branch\..+\.(remote|merge|rebase|description|vscode-merge-base|vscode-merge-base-ref|gh-merge-base|t3-merge-base|t3-merge-base-ref)|lfs\.repositoryformatversion|lfs\..+\.(locksverify|access)|user\.(name|email)|init\.defaultbranch|pull\.(rebase|ff)|fetch\.(prune|prunetags)|gc\.[\w.]+|pack\.[\w.]+|index\.[\w.]+|feature\.[\w.]+|maintenance\.[\w.]+|extensions\.(objectformat|refstorage|worktreeconfig|partialclone|preciousobjects)|submodule\..+\.(url|active|branch)|commit\.gpgsign|tag\.gpgsign|merge\.(ff|conflictstyle)|diff\.(renames|algorithm)|color\.[\w.]+|advice\.[\w.]+|rerere\.enabled|include\.path|includeif\..+\.path)$/;

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
// https://, ssh:// and scp-like `[user@]host:path`. A path (absolute, relative, `./x`, `~/x`),
// file://, a transport helper (`x::...`, ext::, fd::) and anything else are not: for those git
// runs code from that repository (receive-pack, core.alternateRefsCommand) or a program, here,
// with this process's environment. Applied to URLs after git's own rewriting (insteadOf,
// pushInsteadOf).
const NETWORK_URL = /^(?:(?:https|ssh):\/\/(?:[\w.-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*(?::\d+)?\/|(?:[\w.-]+@)?[A-Za-z0-9][A-Za-z0-9.-]*:(?![:/]))/;
const networkUrl = (url: string) => NETWORK_URL.test(url) && !/[\s\0]/.test(url);

// The project's own checkout, at its top: the directory is a mount of its own in every sandbox,
// so no other command can swap it for something else between this check and the command.
const atRoot = (dir: string, session: SessionState) => projectRoots(session).includes(realpath(dir));

// Hooks git would run for the command, with the ssh agent in reach. A hook is the user's own, but
// it often runs the project's scripts, which a sandboxed command can edit.
const HOOKS_RUN: Record<string, string[] | "any"> = { fetch: ["reference-transaction"], "ls-remote": [], push: ["pre-push", "reference-transaction"], pull: "any" };
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
// Git-only calls made only of subcommands that read: they get a writable `.git` (an index refresh,
// a commit-graph), but cannot move HEAD or a branch.
const GIT_READERS = new Set(["status", "log", "diff", "show", "ls-files", "describe", "blame", "shortlog", "rev-parse"]);
// Whether a git-only call can change what a running push sends: it moves HEAD or a ref.
export function movesRefs(command: string): boolean {
  const read = gitOnlyRead(command);
  return !!read && read.cmds.some((full) => {
    const argv = full[0] === "timeout" ? full.slice(2) : full;
    if (argv[0] !== "git") return false;
    const call = gitCall(argv.slice(1));
    return typeof call === "string" || !GIT_READERS.has(call.sub ?? "");
  });
}

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
  return /^(\.{1,2}\/|[A-Za-z0-9_][A-Za-z0-9_.+@,=-]*\/)/.test(rest[at]);
}

// The commands of a git-only call, and the text the checks read for it: each heredoc message with
// its body replaced by a fixed one. The body is text bash does not read (the tokenizer matched the
// form where bash opens it), while the rules' parser matches parentheses without regard to quotes
// or heredocs and could be led to read the commands after it differently (round 3, finding 13).
export function gitOnlyRead(command: string): { cmds: string[][]; text: string } | undefined {
  const spans: [number, number][] = [];
  const cmds = strictCommands(command, { nullRedirects: true, newlines: true, globs: true, bang: true, messages: true, spans, assignments: EDITOR_ASSIGNMENT });
  if (!cmds) return undefined;
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
    return !call.rest.some((w) => (refused?.test(w) && !w.startsWith("--")) || abbreviates(w, GIT_FILE_OPTIONS));
  });
  if (!ok || !cmds.some(({ argv }) => argv.includes("git"))) return undefined;
  let text = command;
  for (const [start, end] of spans.reverse()) text = text.slice(0, start) + "\"$(cat <<'EOF'\nmessage\nEOF\n)\"" + text.slice(end);
  return { cmds: cmds.map((c) => c.argv), text };
}
export const gitOnly = (command: string): boolean => gitOnlyRead(command) !== undefined;
// An allowed git-only call that may still be running, by the subcommands it is made of: what
// the operation state it leaves is checked against (round 3, finding 33). `done` once no process
// of it is left; the next check is the last that counts it.
export interface GitCall {
  subs: Set<string>;
  at: number;
  done?: boolean;
}
// Notes a git-only call that is about to run with a writable `.git`; undefined for any other call.
export function noteGitCall(session: SessionState, command: string): GitCall | undefined {
  const read = gitOnlyRead(command);
  if (!read) return undefined;
  const subs = new Set<string>();
  for (const full of read.cmds) {
    const argv = full[0] === "timeout" ? full.slice(2) : full;
    if (argv[0] !== "git") continue;
    const call = gitCall(argv.slice(1));
    if (typeof call !== "string" && call.sub) subs.add(call.sub);
  }
  const entry: GitCall = { subs, at: Date.now() };
  session.gitCalls.push(entry);
  return entry;
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
export function sandboxBreaks(command: string, cwd: string, session: SessionState): string | undefined {
  const calls: { sub: string; rest: string[] }[] = [];
  const read = gitOnlyRead(command);
  for (const { argv } of allCommands(read?.text ?? command)) {
    argv.forEach((word, at) => {
      if (path.basename(word) !== "git") return;
      const call = gitCall(argv.slice(at + 1));
      if (typeof call !== "string" && call.sub) calls.push({ sub: call.sub, rest: call.rest });
    });
  }
  if (!calls.length) return undefined;
  const writer = calls.find((c) => writesGit(c.sub, c.rest));
  if (writer && !read) return `git ${writer.sub} writes inside .git, which is read-only unless the tool call is made only of plain git commands`;
  const dir = session.project;
  // Signing and verifying need keys or keyrings the sandbox hides (round 3, finding 27): a set
  // config key (true, or one git could not read) asks.
  const on = (key: string) => {
    const v = configBool(dir, key);
    return v !== false && v !== undefined;
  };
  const signed = "git signs here, and the sandbox hides the keys and the agents that hold them";
  const commits = calls.filter((c) => ["commit", "merge", "rebase", "cherry-pick", "revert", "am", "pull"].includes(c.sub));
  if (commits.length && (on("commit.gpgsign") || on("rebase.gpgsign"))) return "git signs commits here, and the sandbox hides the keys and the agents that hold them";
  if (commits.some((c) => c.rest.some((w) => /^(-[a-zA-Z]*S|--gpg-sign)/.test(w)))) return signed;
  if (commits.some((c) => (c.sub === "merge" || c.sub === "pull") && (c.rest.includes("--verify-signatures") || on("merge.verifysignatures")))) return "git checks signatures here, and the sandbox hides the keyrings it needs";
  const tags = calls.filter((c) => c.sub === "tag" && writesGit(c.sub, c.rest) && !c.rest.some((w) => /^(-d|--delete)$/.test(w)));
  if (tags.some((c) => c.rest.some((w) => /^(-[a-zA-Z]*[su]|--sign|--local-user)/.test(w)))) return signed;
  if (tags.length && on("tag.gpgsign")) return signed;
  if (tags.some((c) => c.rest.some((w) => /^(-[a-zA-Z]*[amF]|--annotate|--message|--file)/.test(w))) && on("tag.forcesignannotated")) return signed;
  // push.gpgSign is a boolean or `if-asked`; unset or false signs nothing.
  const pushSign = () => {
    const v = configValue(dir, "push.gpgsign");
    return v === null || (v !== undefined && !/^(false|no|off|0)$/i.test(v));
  };
  if (calls.some((c) => c.sub === "push" && (c.rest.some((w) => /^--signed(=(?!false|no|off|0$).*)?$/.test(w)) || pushSign()))) return signed;
  if (!calls.some((c) => contactsRemote(c.sub, c.rest))) return undefined;
  const urls = [...(session.snapshot?.remotes?.values() ?? [])].flatMap((r) => [...r.fetch, ...r.push]);
  if (urls.some((url) => SSH_URL.test(url)) && !usesSsh(command, cwd, session)) return "git would need your ssh agent, which only a single plain git fetch, pull, push or ls-remote at the top of the project gets (and only when no hook would run)";
  // Each URL as git looks the helper up for it: `credential.<url>.helper` (what `gh auth setup-git`
  // writes) as well as `credential.helper` (round 3, finding 17). Exit 1 is "none"; anything else
  // that is not a value asks.
  const helper = (url: string) => gitRun(["-C", dir, "config", "--get-urlmatch", "credential.helper", url]).status !== 1;
  if (urls.some((url) => /^https?:\/\//.test(url) && helper(url))) return "git would log in through a credential helper, and the sandbox hides what credential helpers use";
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
function writeProblem(cmds: Simple[], cwdOf: (cmd: Simple) => string | undefined): string | undefined {
  // Also every place the guard's own list of writes names (`cp -t`, `sort -o`, git's `--output`).
  const extra = writesOf(cmds).writes;
  for (const cmd of cmds) {
    const targets = [...cmd.out, ...extra.filter((w) => w.cmd === cmd).map((w) => w.word)];
    cmd.argv.forEach((word, at) => {
      const how = Object.hasOwn(WRITER_OPERANDS, path.basename(word)) ? WRITER_OPERANDS[path.basename(word)] : undefined;
      const args = cmd.argv.slice(at + 1);
      const files = args.filter((a) => !a.startsWith("-"));
      if (path.basename(word) === "sed" && !args.some((a) => /^(-[a-zA-Z]*i|--in-place)/.test(a))) return;
      if (path.basename(word) === "dd") targets.push(...args.filter((a) => a.startsWith("of=")).map((a) => a.slice(3)));
      else if (how) targets.push(...(how === "last" ? files.slice(-1) : files));
    });
    // A name spelled with braces or a glob is the name it can expand to (round 3, finding 24).
    for (const target of targets) {
      const name = protectedNameIn(target, PROTECTED_NAMES, cwdOf(cmd));
      if (name === ".git") return `writes ${target}: a path inside or named .git, where git finds hooks and config`;
      if (name) return `writes ${target}, which opencode or a git hook loads and runs`;
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

// `scan`: the walks of this call, which the caller hands to plan() as well (round 3, finding 40).
export async function decideShell(guard: Guard, session: SessionState, cwd: string, command: string, signal?: AbortSignal, scan: Scan = new Scan()): Promise<Decision> {
  projectRoots(session, scan); // takes the git snapshot first (all git calls here run with fsmonitor and hooks off)
  const tampered = gitTampered(session, guard.resumeFile, scan);
  if (tampered) return askBy(pauseReason(tampered, guard.resumeFile));
  // A git-only call's heredoc messages are read with a fixed body (gitOnlyRead).
  const text = gitOnlyRead(command)?.text ?? command;
  // What the layout check could not see (a walk that stopped, a directory that cannot be listed)
  // it cannot vouch for: nothing is allowed without a prompt, sandbox or not (round 3, finding 11).
  const unseen = findGitEntries(projectRoots(session, scan), scan).problems[0];
  // Syntax bash and the rules' parser read differently: nothing below can be trusted on it.
  const syntax = unmodelled(text);
  if (syntax) return askBy(`the rules cannot read this command the way the shell does (${syntax})`);
  const s = single(text, cwd);
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
  const rules = rulesFor(guard, watch.matcher, s, pushOk, [{ source: "a package manager command with known global options", test: (t) => managerAllow.has(t) && !managerOther.has(t) }]);
  rules.ask.push(...managerAsk);
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
  // Whether a word names something on disk where the command could run (a `git checkout` path).
  const exists = (word: string) => !/[$`]/.test(word) && (path.isAbsolute(tilde(word)) ? [tilde(word)] : dirs.map((d) => path.resolve(d, word))).some(lexists);
  const gitIssue = gitProblem(text, 0, exists) ?? writeProblem(cmds, (c) => where.cwd.get(c));
  if (gitIssue) return askBy(gitIssue);
  const known = () => new Set([...session.files.keys(), ...scope.pending.keys(), ...session.touched]);
  // The file a word names where `cmd` runs. Where that directory is unknown a relative word
  // cannot be placed: it then stands for any file of that name this session wrote.
  const resolve = (word: string, cmd?: Simple): string | undefined => {
    if (/[$`]/.test(word)) return undefined;
    const p = tilde(word);
    const dir = cmd ? where.cwd.get(cmd) : cwdKnown ? here : undefined;
    // `~user`, `~+` and `~-` are other directories: such a word cannot be placed either.
    if (!/^~[^/]/.test(p) && (path.isAbsolute(p) || dir !== undefined)) return realish(path.resolve(dir ?? here, p));
    return [...known()].find((f) => path.basename(f) === path.basename(p));
  };
  const roots = projectRoots(session);
  const inProject = (p: string) => roots.some((r) => within(realish(p), r));
  // Files written where the rules do not look (`sort -o`, `cp -t`, git's `--output`): held to the
  // rules' own test for a write (round 3, finding 25).
  const found = writesOf(cmds);
  for (const w of found.writes.filter((x) => !x.checked)) {
    const p = resolve(w.word, w.cmd);
    if (p && /^\/dev\/(null|zero|stdout|stderr|fd\/\d+)$/.test(p)) continue;
    if (!p || (!path.isAbsolute(tilde(w.word)) && where.cwd.get(w.cmd) === undefined)) return askBy(`writes ${w.word}, a place the check cannot tell`);
    const v = fileVerdict("edit", p, scope);
    if (v.action !== "allow") return askBy(v.reason.replace(/^edit /, `${path.basename(w.cmd.argv[0] ?? "")} writes `));
  }
  const writes = writtenBy(cmds, resolve);
  const written = () => new Set([...known(), ...writes]);
  const cwdOf = (c: Simple) => where.cwd.get(c);
  // A write the check cannot place (after `mkdir x && cd x`, through a variable) is a file it
  // cannot name either: what runs by its path afterwards may be that file.
  const unplaced = found.writes.find((w) => /[$`]/.test(w.word) || (!path.isAbsolute(tilde(w.word)) && cwdOf(w.cmd) === undefined));
  const unknownWrite = found.unknown ?? (unplaced ? `writes ${unplaced.word} where the check cannot place it` : undefined);
  const context = { cwd: here, cwdKnown, scope, written, resolve, inProject, cwdOf, envOk: envAssignmentsOk(cmds, cwdOf, inProject), unknownWrite };
  const fromText = textGuards(watch.pairs(), context);
  const fromWords = stricter(stricter(argvGuards(cmds, context), expansionProblem(text)), runtimeReads(text, where, scope));
  const combined = !fromText ? fromWords : !fromWords ? fromText : fromText.action === "ask" ? fromText : fromWords.action === "ask" ? fromWords : (fromWords.files ? fromWords : fromText);
  // The rules read a quoted `~` as the home directory, bash does not: their verdict is about other
  // paths than the ones bash uses.
  const oddTilde = tildeMismatch(text);
  const extra = combined ?? (oddTilde ? { action: "classify" as const, reason: oddTilde } : undefined);
  const commit = () => {
    commitWrites(scope);
    for (const p of writes) session.touched.add(p);
  };
  if (verdict.action === "ask") return fromRules(verdict);
  if (extra?.action === "ask") return askBy(extra.reason);
  if (unseen) return askBy(`the project's git layout cannot be checked whole: ${unseen}`);
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
  const scan = new Scan();
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
