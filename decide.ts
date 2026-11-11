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

import { execFileSync } from "node:child_process";
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
import { findGitEntries, realpath, safeGit } from "./sandbox.ts";

export type Effect = "allow" | "ask" | "deny";

// Ask rules added on top of upstream's, from the bench's rule-allowed risky rows and this
// deployment's needs. Pi user rules: a glob over one simple command (`*` any text, trailing ` *`
// optional) or `re:` + a regex; they also match the command without wrappers like `timeout`.
export const DEFAULT_ASK = [
  // The rules see redirects, cp, mv and tee, but not an editor or a script writing here.
  "re:.*\\.config/opencode.*",
  "re:.*opencode-automode.*",
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
  // ssh to these hosts runs when the remote command is one the rules would allow locally with no
  // project directory (read-only, in effect). Anything else on them still asks.
  sshHosts?: string[];
  // On sshHosts only: treat `sudo cmd` as `cmd` (so read-only commands under sudo run).
  sshReadOnlySudo?: boolean;
  // `git push` of a non-protected branch to a configured remote, without force/delete/tags/mirror.
  allowFeatureBranchPush?: boolean;
  // Patterns the user chose "Always allow" for. Like Pi's session picks they never replace a
  // firm ask (root, credential reads, downloaded code, your own ask rules).
  picked?: Matcher[];
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
  // Set once the layout changed in a way git never does itself; auto-allow stops for the session.
  tampered: string | undefined;
  // A `git init` or `git clone` this session asked about (and so ran outside the sandbox if
  // approved): a repository appearing at a project root is then expected.
  expectNewRepo = false;
  constructor(project: string) {
    this.project = realpath(project);
  }
}

interface GitSnapshot {
  // Per checkout root: what `.git` is (directory inode, or pointer file contents).
  entries: { root: string; kind: "dir" | "file" | "none"; ino?: number; text?: string }[];
  // Nested repositories and pointer files found below the roots: they must not change either.
  nested: { path: string; ino?: number; text?: string }[];
  // Real git directories of main checkouts: these must never gain a `commondir` file.
  mainGitDirs: string[];
  commonDir: string | undefined;
  remotes: Map<string, string>;
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

function takeSnapshot(roots: string[], project: string): GitSnapshot {
  const entries = roots.map(gitEntry);
  const mainGitDirs = entries.filter((e) => e.kind === "dir").map((e) => realpath(path.join(e.root, ".git")));
  const common = git(project, "rev-parse", "--git-common-dir")?.trim();
  const remotes = new Map<string, string>();
  for (const line of (git(project, "remote", "-v") ?? "").split("\n")) {
    const m = /^(\S+)\s+(\S+)\s+\(push\)$/.exec(line);
    if (m) remotes.set(m[1], m[2]);
  }
  const found = findGitEntries(roots);
  const nested = [
    ...[...found.gitDirs].filter((d) => !mainGitDirs.includes(d)).map((d) => ({ path: d, ino: statIno(d) })),
    ...[...found.pointers].filter((p) => !roots.some((r) => p === path.join(r, ".git"))).map((p) => ({ path: p, text: readText(p) })),
  ];
  return { entries, nested, mainGitDirs, commonDir: common ? realpath(path.resolve(project, common)) : undefined, remotes };
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

// Whether the project's git layout changed since the session started in a way git never does on
// its own: `.git` replaced or renamed, a pointer file rewritten, `commondir` planted.
export function gitTampered(session: SessionState): string | undefined {
  if (session.tampered) return session.tampered;
  const snap = session.snapshot;
  if (!snap) return undefined;
  for (const before of snap.entries) {
    const now = gitEntry(before.root);
    // A repository appearing where there was none (an approved `git init` or clone) is new, not
    // tampering: take a fresh snapshot.
    if (before.kind === "none" && now.kind !== "none") {
      // Expected only after an approved `git init`/`clone`; a sandboxed command could otherwise
      // have written its own `.git` (with hooks) there. Only this entry is renewed: nested
      // repositories keep their original record.
      if (!session.expectNewRepo) return (session.tampered = `${path.join(before.root, ".git")} appeared without an approved git init or clone`);
      session.expectNewRepo = false;
      Object.assign(before, now);
      if (now.kind === "dir") snap.mainGitDirs.push(realpath(path.join(before.root, ".git")));
      const common = git(session.project, "rev-parse", "--git-common-dir")?.trim();
      snap.commonDir = common ? realpath(path.resolve(session.project, common)) : undefined;
      continue;
    }
    if (now.kind !== before.kind || now.ino !== before.ino || now.text !== before.text) return (session.tampered = `${path.join(before.root, ".git")} was replaced or rewritten`);
  }
  for (const before of snap.nested) {
    if (before.ino !== undefined ? statIno(before.path) !== before.ino : readText(before.path) !== before.text) {
      return (session.tampered = `${before.path} was replaced, moved or rewritten`);
    }
  }
  for (const dir of snap.mainGitDirs) {
    if (fs.existsSync(path.join(dir, "commondir"))) return (session.tampered = `${path.join(dir, "commondir")} appeared`);
  }
  // An expected repository must appear by the next decision (the approved command has run by
  // then); a rejected `git init` must not leave the door open.
  session.expectNewRepo = false;
  return undefined;
}

// Every git call from this process goes through safeGit: fsmonitor and hooks off, no prompts.
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

// The project's checkouts (main checkout and its worktrees), as first seen, plus worktrees added
// later inside the folder that holds the main checkout. A project at $HOME or above has none.
export function projectRoots(session: SessionState): string[] {
  if (isRootLike(session.project)) return [];
  const now = checkouts(session.project);
  if (!session.roots) session.roots = now.length ? now : [session.project];
  const parent = path.dirname(now[0] ?? "/");
  for (const dir of now) if (!session.roots.includes(dir) && !isRootLike(parent) && within(dir, parent)) session.roots.push(dir);
  if (!session.roots.includes(session.project)) session.roots.push(session.project);
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

// ---- extra allow matchers (Pi user-rule Matchers with code instead of a pattern) ----
// A matcher sees one simple command as its words joined by spaces, quotes already removed,
// either as written or without wrappers like `timeout 15`.

// ssh options a matched call may use: they change nothing on either side. Anything else
// (-o ProxyCommand/LocalCommand, -F, -J, port forwards, -A, -E log files, ...) asks.
const SSH_FLAGS = new Set(["-q", "-T", "-n", "-4", "-6", "-C", "-x", "-a"]);
const SSH_VALUED_OK = new Set(["-p", "-l"]);
const SSH_OPTION_OK = /^(BatchMode|ConnectTimeout|ConnectionAttempts|ServerAliveInterval|ServerAliveCountMax|LogLevel)=[\w.-]+$/i;

// Programs a remote command may use: they read and report, and change nothing.
const REMOTE_READ_ONLY = new Set([
  "cat", "head", "tail", "grep", "egrep", "fgrep", "rg", "ls", "stat", "file", "wc", "du", "df", "free", "uptime", "uname",
  "hostname", "id", "whoami", "ps", "pgrep", "date", "sort", "uniq", "cut", "tr", "echo", "printf", "true", "false", "test",
  "[", "findmnt", "lsblk", "lscpu", "nproc", "which", "ss", "readlink", "realpath", "basename", "dirname", "md5sum",
  "sha256sum", "dmesg", "journalctl", "systemctl", "ip", "find", "tree", "column", "nl", "seq", "sleep",
]);
const SYSTEMCTL_READ = new Set(["status", "is-active", "is-enabled", "is-failed", "list-units", "list-unit-files", "list-timers", "show", "cat"]);

function remoteIsReadOnly(remoteCommand: string, guard: Guard): boolean {
  let remote = remoteCommand;
  // Substitutions and process substitution run more than the listed programs; output may only be
  // discarded, never written to a file.
  if (/\$\(|`|<\(|>\(/.test(remote)) return false;
  if (/>/.test(remote.replace(/\d?>>?\s*\/dev\/null|\d>&\d/g, ""))) return false;
  // Opt-in: `sudo [-n] cmd` counts as `cmd`. Any other sudo option (-u, -s, -i, ...) still asks.
  if (guard.sshReadOnlySudo) remote = remote.replace(/(^|[;&|(]\s*|&&\s*|\|\|\s*)sudo(\s+-n)?\s+(?!-)/g, "$1");
  const remoteScope = makeScope("/", guard.guarded, { rules: guard.rules, piDirs: guard.configDirs });
  if (bashVerdict(remote, remoteScope).action !== "allow") return false;
  return parse(remote).cmds.every(({ argv }) => {
    const words = argv;
    const program = path.basename(words[0] ?? "");
    if (!REMOTE_READ_ONLY.has(program)) return false;
    if (program === "systemctl") return SYSTEMCTL_READ.has(words.find((w, i) => i > 0 && !w.startsWith("-")) ?? "");
    if (program === "journalctl") return !words.some((w) => /^--(vacuum|rotate|flush|sync|relinquish|setup-keys|update-catalog)/.test(w));
    if (program === "ip" && words.some((w) => /^-(b|batch|force)$|^-ba/.test(w))) return false;
    if (program === "ip") return words.slice(1).every((w) => /^(-\w+|addr|address|a|route|r|link|l|neigh|show|list|ls|dev|[\w.:/-]+)$/.test(w)) && !words.some((w) => /^(add|del|delete|change|replace|set|flush|append)$/.test(w));
    const args = words.slice(1);
    const operands = args.filter((w) => !w.startsWith("-"));
    const has = (re: RegExp) => args.some((w) => re.test(w));
    switch (program) {
      case "uniq": return operands.length <= 1; // a second operand is the output file
      case "sort": return !has(/^(-o|--output|--compress-program)/) && !has(/^-[a-zA-Z]*o/);
      case "tree": return !has(/^(-o|--output)/);
      case "rg": return !has(/^--pre/);
      case "file": return !has(/^(-C|--compile)$/);
      case "date": return !has(/^(-s|--set)/) && operands.every((w) => w.startsWith("+"));
      case "hostname": return args.length === 0 || args.every((w) => /^-[afdisAIy]+$|^--(fqdn|short|domain|all-fqdns|ip-address|all-ip-addresses)$/.test(w));
      case "dmesg": return !has(/^(-c|-C|-n|-D|-E|--clear|--read-clear|--console-(off|on|level))$/) && !has(/^-[a-zA-Z]*[cCnDE]/);
      case "ss": return !has(/^(-K|--kill)$/) && !has(/^-[a-zA-Z]*K/);
      case "find": return !has(/^-(exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/);
      case "tail": case "head": case "cat": case "grep": case "egrep": case "fgrep": return true;
      default: return true;
    }
  });
}

function sshMatcher(guard: Guard): Matcher {
  const hosts = new Set(guard.sshHosts ?? []);
  return {
    source: `ssh to ${[...hosts].join(", ")} with a read-only remote command`,
    test(text) {
      const words = text.split(" ");
      if (path.basename(words[0] ?? "") !== "ssh") return false;
      let i = 1;
      while (i < words.length && words[i].startsWith("-")) {
        const w = words[i];
        if (SSH_FLAGS.has(w)) i += 1;
        else if (SSH_VALUED_OK.has(w) && /^[\w.-]+$/.test(words[i + 1] ?? "")) i += 2;
        else if (w === "-o" && SSH_OPTION_OK.test(words[i + 1] ?? "")) i += 2;
        else if (/^-o/.test(w) && SSH_OPTION_OK.test(w.slice(2))) i += 1;
        else return false;
      }
      const target = words[i];
      if (!target || target === "--") return false;
      const host = target.includes("@") ? target.slice(target.lastIndexOf("@") + 1) : target;
      if (!hosts.has(host)) return false;
      // ssh joins the remaining words with spaces and hands them to the remote shell, as here.
      const remote = words.slice(i + 1).join(" ").trim();
      if (!remote) return false; // an interactive login
      return remoteIsReadOnly(remote, guard);
    },
  };
}

const PROTECTED_BRANCH = /^(main|master|trunk|develop|development|dev|production|prod|staging|stable|live|gh-pages|release([/-].*)?|hotfix([/-].*)?)$/;
const PUSH_SAFE_FLAGS = new Set(["-q", "--quiet", "-v", "--verbose", "--porcelain", "-n", "--dry-run", "--progress", "--no-progress"]);
// Effective config (all scopes, includes followed) that changes where a push goes, how git
// connects, or what it runs. Any of these makes a push ask.
const PUSH_RISKY_CONFIG =
  /^(remote\.[^\n]*\.(push|pushurl|receivepack|uploadpack|proxy|vcs)|url\.[^\n]*\.(insteadof|pushinsteadof)|branch\.[^\n]*\.pushremote|remote\.pushdefault|core\.(sshcommand|hookspath|gitproxy|fsmonitor)|credential\.[^\n]*helper|http\.[^\n]*\.?proxy|protocol\.[^\n]*\.allow)\s/;

// Repository-level config (and files it includes) that changes where git pushes or fetches, how
// it connects, or what it runs. Global and system config are the user's own.
function repoLevelRisky(dir: string): boolean {
  const scoped = (git(dir, "config", "--show-scope", "--get-regexp", ".") ?? "").split("\n").filter(Boolean);
  return scoped.filter((line) => /^(local|worktree)\s/.test(line)).some((line) => PUSH_RISKY_CONFIG.test(line.replace(/^\S+\s+/, "").toLowerCase() + " "));
}

function pushIsSafe(dir: string, words: string[], session: SessionState): boolean {
  // Only the project's own repository: not a copy the agent built elsewhere.
  const snap = session.snapshot;
  const common = git(dir, "rev-parse", "--git-common-dir")?.trim();
  if (!snap?.commonDir || !common || realpath(path.resolve(dir, common)) !== snap.commonDir) return false;
  const flags = words.filter((w) => w.startsWith("-"));
  if (!flags.every((f) => PUSH_SAFE_FLAGS.has(f))) return false;
  const [remote, ...refspecs] = words.filter((w) => !w.startsWith("-"));
  // A URL or an unknown name could send the code anywhere; so could a remote whose URL changed
  // since the session started. Without a remote argument git uses the branch's remote.
  const currentBranch = git(dir, "symbolic-ref", "--quiet", "--short", "HEAD")?.trim();
  const branchRemote = currentBranch ? git(dir, "config", "--get", `branch.${currentBranch}.remote`)?.trim() : undefined;
  const viaRemote = remote ?? branchRemote ?? "origin";
  const recorded = snap.remotes.get(viaRemote);
  const pushUrl = git(dir, "remote", "get-url", "--push", viaRemote)?.trim();
  if (!recorded || pushUrl !== recorded) return false;
  // Only repository-level config (and files it includes) is checked: global and system config are
  // the user's own and outside anything a sandboxed command can write.
  const scoped = (git(dir, "config", "--show-scope", "--get-regexp", ".") ?? "").split("\n").filter(Boolean);
  const config = scoped.map((line) => line.replace(/^\S+\s+/, "")).join("\n");
  // "command" scope is only this process's own safety overrides (user -c options ask).
  const repoLevel = scoped.filter((line) => /^(local|worktree)\s/.test(line)).map((line) => line.replace(/^\S+\s+/, ""));
  if (repoLevel.some((line) => PUSH_RISKY_CONFIG.test(line.toLowerCase() + " "))) return false;
  const pushDefault = /^push\.default (.+)$/im.exec(config)?.[1]?.trim().toLowerCase();
  if (pushDefault && pushDefault !== "simple" && pushDefault !== "current") return false;
  const current = git(dir, "symbolic-ref", "--quiet", "--short", "HEAD")?.trim();
  // The remote's default branch, asked of the remote itself (the local refs/remotes/<r>/HEAD can be
  // rewritten). Repository config that could change how git connects was rejected above.
  const symref = safeGit(["-C", dir, "ls-remote", "--symref", viaRemote, "HEAD"], 8000);
  const remoteDefault = /^ref: refs\/heads\/(\S+)\s+HEAD$/m.exec(symref ?? "")?.[1];
  if (!remoteDefault) return false;
  const isProtected = (branch: string | undefined) => !branch || branch === "HEAD" || PROTECTED_BRANCH.test(branch) || branch === remoteDefault;
  if (!refspecs.length) {
    // Without a refspec git pushes the current branch to its upstream (simple) or the same name
    // (current). The upstream must be the same-named branch, or unset.
    if (!current) return false;
    const merge = /^branch\.(.+)\.merge (.+)$/gim;
    for (let m = merge.exec(config); m; m = merge.exec(config)) {
      if (m[1] === current.toLowerCase() || m[1] === current) {
        if (m[2].trim().replace(/^refs\/heads\//, "") !== current) return false;
      }
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

function pushMatcher(cwd: string, command: string, session: SessionState): Matcher {
  // The push must be the whole tool call (after an optional `cd`): anything else in the same
  // command could change the config, hooks or refs this check reads before the push runs.
  const cmds = parse(command).cmds;
  const alone = cmds.filter((c) => c.argv[0] !== "cd").length === 1 && cmds.every((c) => c.argv[0] === "cd" ? c.argv.length === 2 : true);
  let dir = cwd;
  for (const c of cmds) if (c.argv[0] === "cd") dir = path.resolve(dir, c.argv[1].replace(/^~(?=\/|$)/, os.homedir()));
  return {
    source: "git push of a feature branch to a configured remote",
    test(text) {
      if (!alone) return false;
      const words = text.split(" ").filter(Boolean);
      if (path.basename(words[0] ?? "") !== "git") return false;
      let here = dir;
      let i = 1;
      while (i < words.length && words[i].startsWith("-")) {
        if (words[i] === "-C" && words[i + 1]) {
          here = path.resolve(here, words[i + 1].replace(/^~(?=\/|$)/, os.homedir()));
          i += 2;
        } else return false; // -c, --git-dir, --exec-path and friends change what git does
      }
      if (words[i] !== "push") return false;
      return pushIsSafe(here, words.slice(i + 1), session);
    },
  };
}

function rulesFor(guard: Guard, cwd: string, command: string, session: SessionState): UserRules {
  const extra: Matcher[] = [];
  if (guard.sshHosts?.length) extra.push(sshMatcher(guard));
  if (guard.allowFeatureBranchPush) extra.push(pushMatcher(cwd, command, session));
  return extra.length ? { ...guard.rules, allow: [...guard.rules.allow, ...extra] } : guard.rules;
}

// Git subcommands that may write inside git directories when they make up the whole tool call.
const GIT_WRITERS = new Set(["add", "commit", "checkout", "switch", "restore", "stash", "reset", "merge", "cherry-pick", "revert", "tag", "branch", "fetch", "pull", "mv", "rm", "status", "log", "diff", "show", "notes", "gc", "prune", "pack-refs", "update-index", "rev-parse", "ls-files", "describe", "blame", "shortlog", "reflog"]);

// A tool call made only of `git <writer>` commands (and `cd`), with no redirects, substitutions or
// options that write files. Only such calls get write access inside git directories (minus hooks
// and config); for everything else git directories are read-only.
export function gitOnly(command: string): boolean {
  const parsed = parse(command);
  if (parsed.opaque || /[`]|\$\(|<\(|>\(/.test(command)) return false;
  return parsed.cmds.every(({ argv, out, in: input }) => {
    if (out.length || input?.length) return false;
    if (argv[0] === "cd") return argv.length <= 2;
    if (argv[0] !== "git") return false;
    let i = 1;
    while (i < argv.length && argv[i].startsWith("-")) i += argv[i] === "-C" ? 2 : argv[i] === "-c" ? 2 : 1;
    if (!GIT_WRITERS.has(argv[i] ?? "")) return false;
    return !argv.slice(i + 1).some((w) => /^(--output|-o$|--output-directory|--exec|-x$|--template|--file$|-F$)/.test(w));
  }) && parsed.cmds.some(({ argv }) => argv[0] === "git");
}

// Whether a tool call gets the ssh agent and ~/.ssh's known_hosts/config (never private keys):
// only a single `git fetch/pull/push/ls-remote` of the project's own repository, without options
// that pick a program, or a single `ssh`/`scp` command (which the rules only allow for sshHosts).
export function usesSsh(command: string, cwd: string, session: SessionState): boolean {
  const roots = projectRoots(session);
  const parsed = parse(command);
  if (parsed.opaque || /[`]|\$\(|<\(|>\(/.test(command)) return false;
  let dir = cwd;
  const rest = parsed.cmds.filter(({ argv }) => {
    if (argv[0] !== "cd") return true;
    dir = path.resolve(dir, (argv[1] ?? os.homedir()).replace(/^~(?=\/|$)/, os.homedir()));
    return false;
  });
  if (rest.length !== 1 || rest[0].out.length || rest[0].in?.length) return false;
  const argv = rest[0].argv;
  const program = argv[0] ?? "";
  if (program === "ssh" || program === "scp") return true;
  if (program !== "git" || !/^(fetch|pull|push|ls-remote)$/.test(argv[1] ?? "")) return false;
  if (argv.some((w) => /^(-u|--upload-pack|--receive-pack|--exec|-c|--config-env)(=|$)/.test(w))) return false;
  const real = realpath(dir);
  if (!roots.some((r) => real === r || real.startsWith(r + "/"))) return false;
  // The project's own repository, not one nested inside it or pointed elsewhere, and its own
  // config must not change how git connects.
  const common = git(dir, "rev-parse", "--git-common-dir")?.trim();
  if (!session.snapshot?.commonDir || !common || realpath(path.resolve(dir, common)) !== session.snapshot.commonDir) return false;
  return !repoLevelRisky(dir);
}

export async function decideShell(guard: Guard, session: SessionState, cwd: string, command: string, signal?: AbortSignal): Promise<Decision> {
  projectRoots(session); // takes the git snapshot first (all git calls here run with fsmonitor and hooks off)
  const tampered = gitTampered(session);
  if (tampered) return { effect: "ask", by: "rules", rule: "ask", reason: `auto-allow paused for this session: ${tampered}` };
  const scope = scopeFor(guard, session, cwd, rulesFor(guard, cwd, command, session));
  const verdict = bashVerdict(command, scope);
  if (verdict.action !== "classify") {
    if (verdict.action === "allow") commitWrites(scope);
    return fromRules(verdict);
  }
  if (!guard.useClassifier) return { effect: "ask", by: "no-model", rule: "classify", reason: `rules leave this to the model, which is off (${reword(verdict.reason)})` };
  const result = await scoreCommand(guard.classifier, { tool: "bash", cwd, command }, signal);
  if ("error" in result) return { effect: "ask", by: "model-error", rule: "classify", reason: `model gave no answer: ${result.error}`, ms: result.ms };
  const { score, ms } = result;
  if (score >= guard.classifier.askAbove) {
    return { effect: "ask", by: "model", rule: "classify", reason: `model risk ${score.toFixed(2)} (asks at ${guard.classifier.askAbove} and above)`, score, ms };
  }
  commitWrites(scope);
  return { effect: "allow", by: "model", rule: "classify", reason: `model risk ${score.toFixed(2)}`, score, ms };
}

// edit/write: only ever tightens. Undefined means "leave opencode's own verdict alone".
export function decideFile(guard: Guard, session: SessionState, cwd: string, target: string): Decision | undefined {
  const scope = scopeFor(guard, session, cwd);
  const verdict = fileVerdict("write", target, scope);
  if (verdict.action === "allow") {
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
