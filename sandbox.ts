// The sandbox plan for one auto-allowed command, handed to sandbox/lockwrite:
//   rw      directories (or device files) the command may write beneath. Everything else is
//           mounted read-only, and Landlock confines writes to these as well.
//   ro      paths inside them that are bind-mounted read-only: whole git directories for
//           ordinary commands; for pure git commands only their hooks and config; `.git`
//           pointer files; core.hooksPath directories; files git config includes; hook-manager
//           files; the project's opencode config
//   reopen  directories inside a read-only path that stay writable: the git directory of a
//           submodule a pure git command works in, inside a superproject's `.git` that is
//           read-only whole; each git directory the call is granted there, and the directories
//           kept in place inside one (outermost first)
//   pin     directories bound onto themselves, so they cannot be renamed or replaced: git
//           directories, and every directory between a writable root and a protected path
//   hide    local sockets of other services and credential files/directories, covered up
//   tmpfs   private writable tmpfs mounts (/dev/shm)
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { makeScope, readVerdict } from "./rules.ts";

const HOME = os.homedir();

// No build cache is writable by default. Each of them holds code that a later, unsandboxed build
// runs: unpacked crate sources and git checkouts (build.rs), the pnpm store (hard-linked into
// other projects), Maven and Gradle jars, Go's build cache, wheels. `sandboxWritable` opts in.
export const DEFAULT_CACHE_DIRS: string[] = [];

const XDG_CONFIG = process.env.XDG_CONFIG_HOME || path.join(HOME, ".config");
const XDG_DATA = process.env.XDG_DATA_HOME || path.join(HOME, ".local", "share");
const XDG_STATE = process.env.XDG_STATE_HOME || path.join(HOME, ".local", "state");
const XDG_CACHE = process.env.XDG_CACHE_HOME || path.join(HOME, ".cache");

// Credentials hidden from sandboxed commands (reads are not otherwise restricted). This list
// holds what the rules' own notion of a credential file (rules.ts, asked through readVerdict)
// does not cover; plan() adds every file and directory under $HOME and the project that the
// rules would ask about, so the two cannot drift apart.
export const DEFAULT_SECRET_PATHS = [
  path.join(XDG_CONFIG, "opencode"),
  path.join(XDG_DATA, "opencode"),
  path.join(XDG_STATE, "opencode"),
  path.join(XDG_CONFIG, "gh"),
  path.join(XDG_CONFIG, "glab-cli"),
  path.join(XDG_CONFIG, "github-copilot"),
  path.join(XDG_CONFIG, "gcloud"),
  path.join(XDG_CONFIG, "op"),
  path.join(XDG_CONFIG, "rclone"),
  path.join(XDG_CONFIG, "hub"),
  path.join(XDG_CONFIG, "git", "credentials"),
  path.join(XDG_DATA, "keyrings"),
  path.join(XDG_CACHE, "git", "credential"),
  `/tmp/krb5cc_${process.getuid?.() ?? 0}`,
  ...[
    ".ssh",
    ".gnupg",
    ".password-store",
    ".aws",
    ".azure",
    ".oci",
    ".kube",
    ".docker/config.json",
    ".netrc",
    ".git-credentials",
    ".git-credential-cache",
    ".npmrc",
    ".pypirc",
    ".claude/.credentials.json",
    ".codex/auth.json",
    ".secrets",
    ".cargo/credentials.toml",
    ".cargo/credentials",
    ".vault-token",
    ".pgpass",
    ".my.cnf",
    ".terraform.d/credentials.tfrc.json",
    ".m2/settings.xml",
    ".m2/settings-security.xml",
    ".gradle/gradle.properties",
    ".bash_history",
    ".zsh_history",
    ".sh_history",
    ".python_history",
    ".node_repl_history",
    ".psql_history",
    ".mysql_history",
    ".sqlite_history",
    ".rediscli_history",
    ".lesshst",
    ".Xauthority",
    // Registry logins and browser profiles (cookies, saved passwords).
    ".gem/credentials",
    ".composer/auth.json",
    ".mozilla",
    ".librewolf",
    ".zen",
    "snap/firefox",
    "snap/chromium",
  ].map((p) => path.join(HOME, p)),
  ...["composer/auth.json", "containers/auth.json", "google-chrome", "google-chrome-beta", "chromium", "BraveSoftware", "microsoft-edge", "vivaldi", "opera"].map((p) => path.join(XDG_CONFIG, p)),
  ...["fish/fish_history", "atuin"].map((p) => path.join(XDG_DATA, p)),
];

// In ~/.ssh, what a command that uses ssh may still see: never private keys.
const SSH_VISIBLE = /^(known_hosts(\.old)?|config|authorized_keys|.*\.pub)$/;

// Device files a command may write to. Terminals are not among them, and no device accepts an
// ioctl inside the sandbox. /dev/shm gets a private tmpfs instead of the shared one.
const DEV_WRITABLE = ["/dev/null", "/dev/zero", "/dev/full"];

// Files of hook managers: git hooks hand control to them, so a command that could edit them
// could plant a hook. Only these known names; see "Known gaps" in the README.
export const HOOK_MANAGER_FILES = [
  ".husky",
  ".lefthook",
  ".pre-commit-config.yaml",
  ".pre-commit-config.yml",
  ".overcommit.yml",
  ...["lefthook", ".lefthook", "lefthook-local", ".lefthook-local"].flatMap((n) => ["yml", "yaml", "toml", "json"].map((e) => `${n}.${e}`)),
];
// What opencode loads from the session directory and every directory above it, with no prompt:
// config (MCP commands, plugins), plugin and command directories, instructions and skills.
// This is the one list: the sandbox makes these read-only, a new one pauses the session, and a
// shell command or an edit that writes one asks (decide.ts derives its patterns from it).
// `CLAUDE.md` is here because the rules and the README treat it like `AGENTS.md`.
export const OPENCODE_PROJECT_FILES = ["opencode.json", "opencode.jsonc", ".opencode", ".claude", ".agents", "AGENTS.md", "CLAUDE.md"];
// The ones a command asks about by naming them at all, reads included: config and plugins.
export const OPENCODE_CONFIG_NAMES = ["opencode.json", "opencode.jsonc", ".opencode"];

export interface Plan {
  // What the plan hides whole (credential directories, `~/.ssh` or its private entries).
  hidden: ReadonlySet<string>;
  // The git directories this call may write: where `commondir` and `config.worktree` are
  // compared between the call's start and its end (decide.ts, quarantineGitFiles). A git
  // directory around one of them is read-only whole, so nothing can appear in it.
  gitDirs: string[];
  // Paths that are not there and must not appear while the call runs: where a push into a
  // repository would run its hooks from (`$GIT_DIR/<core.hooksPath>`).
  gitWatch: string[];
  rw: string[];
  ro: string[];
  // Directories inside a read-only path that the call may write (lockwrite, AUTOMODE_REOPEN).
  reopen: string[];
  pin: string[];
  hide: string[];
  tmpfs: string[];
  // Set when a protection cannot be put in place: the command must ask.
  problem?: string;
}

export interface PlanOptions {
  projectRoots: string[];
  allowedPaths: string[];
  cacheDirs: string[];
  // A pure git command (see gitOnly in decide.ts): it may write inside the git directories of
  // the repositories it works in (minus hooks and config), and in no other.
  gitWritable: boolean;
  // The directories its git commands end in (gitDirectories in decide.ts); the session
  // directory when not given.
  gitCwds?: string[];
  // Those of them where a command ends that writes its git directory (gitWriteDirectories in
  // decide.ts); every one of them when not given.
  gitWriteCwds?: string[];
  // Those of them where a command ends that works on every worktree of the repository (`git
  // gc` expires each worktree's reflog under a lock on its `HEAD`; gitMaintainDirectories in
  // decide.ts): from a linked worktree, such a call needs the other worktrees' admin directories.
  gitMaintainCwds?: string[];
  // Where its pushes go, when that is a path on this machine (pushDestinations in decide.ts).
  gitPushTo?: string[];
  // The command may use ssh: keep the ssh agent and ~/.ssh reachable.
  exposeSsh: boolean;
  keepSockets: string[];
  showPaths: string[];
  hidePaths: string[];
  // The session directory: opencode loads project config from it and its parents.
  project?: string;
}

export function realpath(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

const within = (p: string, dir: string) => p === dir || p.startsWith(dir.endsWith("/") ? dir : dir + "/");
// Lists reach lockwrite newline-separated.
const usable = (p: string) => !!p && !p.includes("\n");
const lexists = (p: string) => {
  try {
    fs.lstatSync(p);
    return true;
  } catch {
    return false;
  }
};
const isSymlink = (p: string) => {
  try {
    return fs.lstatSync(p).isSymbolicLink();
  } catch {
    return false;
  }
};

export interface GitResult {
  // The exit status; undefined when git could not be run, timed out or its output was cut off.
  status: number | undefined;
  out: string;
}

const GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false", "-c", "core.askPass=", "-c", "core.pager=cat"];
export const gitEnv = (): NodeJS.ProcessEnv => {
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0", GIT_ASKPASS: "", SSH_ASKPASS: "", SSH_ASKPASS_REQUIRE: "never", GIT_PAGER: "cat" };
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_EDITOR"]) delete env[name];
  return env;
};
export const gitArgs = (args: string[]) => [...GIT_SAFE, ...args];
// git's leading words for a lookup in a git directory the walk found (its config, its remotes).
// `--git-dir` alone makes git change into the directory `core.worktree` names, and a module
// whose submodule was removed (`git rm lib` keeps `.git/modules/lib`) names one that is gone:
// every such lookup then fails (round 4, finding 21, sixth pass). Naming the work tree on the
// command line keeps git where it is; none of these lookups reads a work tree.
export const inGitDir = (gitDir: string) => ["--git-dir", gitDir, "--work-tree", gitDir];

// git, with nothing from the repository able to run code in this process. A caller that grants
// trust on the answer must look at `status`: no answer is not the same as an empty one.
export function gitRun(args: string[], timeout = 3000): GitResult {
  const r = spawnSync("git", gitArgs(args), { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout, maxBuffer: 16 << 20, env: gitEnv() });
  if (r.error || r.status === null) return { status: undefined, out: "" };
  return { status: r.status, out: r.stdout ?? "" };
}

// For callers that only look things up: undefined on any failure.
export function safeGit(args: string[], timeout = 3000): string | undefined {
  const r = gitRun(args, timeout);
  return r.status === 0 ? r.out : undefined;
}

// ---- discovery ----

// One walk of each writable root finds everything the plan must know about: git directories
// and `.git` pointer files, credential files, sockets. It has no depth limit and skips nothing
// (a repository under node_modules is a repository). What it cannot finish is a problem, and a
// plan with a problem makes the command ask: a scan that stops early protects nothing beyond
// the point where it stopped.
export const limits = {
  // Directory entries looked at per root, and the time one root may take.
  entries: 400_000,
  ms: 1500,
  // Credential files hidden per plan (each is a mount).
  secrets: 5000,
};

export interface Found {
  gitDirs: Set<string>; // real git directories (main, bare, linked worktree, common, submodule)
  pointers: Set<string>; // `.git` files of worktrees and submodules
  links: Set<string>; // `.git` entries that are symbolic links: they cannot be made read-only
  tops: Map<string, Set<string>>; // git dir -> every worktree top level that leads to it
  secrets: Set<string>; // what the rules call a credential file or directory
  sockets: Set<string>; // sockets this user can connect to
  // Directories this process could reach into but cannot list, below a root that is not the
  // caller's own (in its own roots each is a problem instead): the plan covers them up.
  unlistable: Set<string>;
  // Credential directories the walk went on into: what lies there is hidden whole by the plan,
  // and is still seen by the layout check.
  veiled: Set<string>;
  // Standalone git directories whose `core.bare` git could not read, each with what to say: a
  // problem in the caller's own roots, and "its own top" (as an unset one is) elsewhere.
  doubts: Map<string, string>;
  problems: string[];
}

const emptyFound = (): Found => ({ gitDirs: new Set(), pointers: new Set(), links: new Set(), tops: new Map(), secrets: new Set(), sockets: new Set(), unlistable: new Set(), veiled: new Set(), doubts: new Map(), problems: [] });

const isDir = (p: string) => {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
};
const reachable = (p: string) => {
  try {
    fs.accessSync(p, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
};
// Whether this process could put something in a directory or reach what is in it, judged by
// access(2) for this process and not by who owns it: it can enter it (X) or write it (W), or it
// owns it and so can change its mode. Round 3, finding 26.
const enterable = (dir: string) => {
  for (const mode of [fs.constants.X_OK, fs.constants.W_OK]) {
    try {
      fs.accessSync(dir, mode);
      return true;
    } catch {
      // not this way
    }
  }
  try {
    return fs.lstatSync(dir).uid === process.getuid?.();
  } catch {
    return false;
  }
};

// The rules' credential test resolves the path on disk, which is too slow to run on every entry
// of a large tree. This cheap test picks the entries worth asking it about. It is broader than
// the rules on purpose (any dotfile, anything with "key", "secret" or "credential" in its name,
// anything inside a dot-directory); test/sandbox.test.mts checks that it lets through every
// kind of name the rules know.
const MAYBE_SECRET = /^(\.|id_)|key|secret|credential|service|\.(pem|p12|pfx|jks|kdbx)$/i;
const SECRET_PARENT = /^(\..*|gh|gcloud|op|keyrings|Keychains)$/;
export const maybeSecret = (name: string, parent: string) => MAYBE_SECRET.test(name) || SECRET_PARENT.test(parent);

// Walks per root, for tests (round 3, finding 40).
export const walkCount = new Map<string, number>();

// The walk of one root. `secrets`: credential files are looked for too.
function scanRoot(root: string, skip: Set<string>, secrets: boolean): Found {
  walkCount.set(root, (walkCount.get(root) ?? 0) + 1);
  const found = emptyFound();
  const started = Date.now();
  let entries = 0;
  let stopped = false;
  // Git directories found outside any other: bare repositories, and the git directories of
  // work trees elsewhere.
  const standalone = new Set<string>();
  // A git directory, and a top level that leads to it when it has one here. A top is where git
  // runs that repository's hooks from: the work tree whose `.git` names the directory, or the
  // directory itself for a bare repository. A git directory that belongs to a work tree (a
  // `.git` directory, and what lies inside one: a submodule's under `modules`, a linked
  // worktree's admin directory under `worktrees`; one kept elsewhere by `--separate-git-dir`)
  // is no top of its own, so nothing is created inside it for a relative core.hooksPath
  // (round 4, finding 21). Where a push into it runs its hooks from is protected by gitPaths.
  const addGitDir = (gitDir: string, top?: string) => {
    found.gitDirs.add(gitDir);
    if (!found.tops.has(gitDir)) found.tops.set(gitDir, new Set());
    if (top !== undefined) found.tops.get(gitDir)!.add(top);
  };
  // Git's data stores contain hashes or ref-derived names, not user credential paths.
  const dataStores = new Set(["objects", "rr-cache"]);
  // `veiled`: below a credential directory, where no further credential is recorded.
  // `storeContainer`: `lfs` or `annex` at the top of a git directory, whose own `objects` is a
  // data store. `inGit`: a `.git` directory or a directory inside a git directory.
  const visit = (dir: string, veiled: boolean, storeContainer = false, inGit = false) => {
    if (stopped) return;
    let list: fs.Dirent[];
    try {
      list = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return; // gone since it was listed
      // A directory that cannot be listed but can be entered or written (or whose mode this user
      // could change) can hold what stays out of sight: a planted repository, a socket. One that
      // is closed to this process both ways holds nothing it can reach.
      if (code !== "EACCES") found.problems.push(`${dir} cannot be listed (${code}), so what is in it cannot be protected`);
      else if (enterable(dir)) found.unlistable.add(dir);
      return;
    }
    entries += list.length;
    if (entries > limits.entries || Date.now() - started > limits.ms) {
      stopped = true;
      found.problems.push(`the scan of ${root} stopped after ${entries} entries (limit ${limits.entries} entries, ${limits.ms} ms); what lies beyond is not protected`);
      return;
    }
    const names = new Set(list.map((e) => e.name));
    const here = realpath(dir);
    // The same three names inside a git directory are a submodule's git directory, whose top is
    // the work tree its pointer file is in. Outside one they are a bare repository, which is its
    // own top, or the git directory of a work tree elsewhere, which is not: `core.bare` tells
    // them apart, once the walk is over (`standalone`). None of it depends on which of a
    // directory and its pointer file the walk reaches first.
    const gitDirHere = names.has("HEAD") && names.has("objects") && names.has("refs") && !names.has(".git");
    if (gitDirHere) {
      addGitDir(here);
      if (!inGit) standalone.add(here);
    }
    // A linked worktree's admin directory, known by its place: its pointer file may lie outside
    // the walk, and the refs below it are still not credentials.
    const admin = path.basename(path.dirname(dir)) === "worktrees" && found.gitDirs.has(realpath(path.dirname(path.dirname(dir))));
    if (admin) addGitDir(here);
    const gitRoot = found.gitDirs.has(here);
    const below = inGit || gitRoot;
    for (const e of list) {
      const p = path.join(dir, e.name);
      if (gitRoot && dataStores.has(e.name) && e.isDirectory()) continue;
      if (storeContainer && e.name === "objects" && e.isDirectory()) continue;
      // git-annex keeps the credentials of special remotes in `annex/creds/`: hidden by name.
      if (secrets && storeContainer && e.name === "creds" && path.basename(dir) === "annex" && e.isDirectory()) {
        found.secrets.add(p);
        found.veiled.add(p);
        visit(p, true, false, true);
        continue;
      }
      if (gitRoot && ["refs", "logs", "lfs", "annex"].includes(e.name) && e.isDirectory()) {
        visit(p, true, ["lfs", "annex"].includes(e.name), true);
        continue;
      }
      if (e.name === ".git") {
        if (e.isSymbolicLink()) {
          found.links.add(p);
          const target = realpath(p);
          if (target !== p && isDir(target)) addGitDir(target, here);
        } else if (e.isDirectory()) {
          addGitDir(realpath(p), here);
          // A root of its own (an allowed path) is walked as itself, once.
          if (!skip.has(p)) visit(p, veiled, false, true);
        } else if (e.isFile()) {
          found.pointers.add(p);
          let text = "";
          try {
            text = fs.readFileSync(p, "utf8");
          } catch {
            found.problems.push(`${p} cannot be read`);
          }
          const m = /^gitdir:\s*(.+)$/m.exec(text);
          if (m) {
            const gitdir = realpath(path.resolve(dir, m[1].trim()));
            addGitDir(gitdir, here);
            try {
              found.gitDirs.add(realpath(path.resolve(gitdir, fs.readFileSync(path.join(gitdir, "commondir"), "utf8").trim())));
            } catch {
              // not a linked worktree
            }
          }
        }
        continue;
      }
      if (secrets && !veiled && maybeSecret(e.name, path.basename(dir)) && isSecretPath(p)) {
        found.secrets.add(p);
        // A link named like a credential file: what it points to holds the secret.
        if (e.isSymbolicLink()) found.secrets.add(realpath(p));
        // A credential directory is hidden whole; the walk goes on so that the layout check,
        // which shares it, still sees a repository planted there.
        else if (e.isDirectory() && !skip.has(p)) {
          found.veiled.add(p);
          visit(p, true, false, below);
        }
        continue;
      }
      if (e.isSocket()) {
        if (reachable(p)) found.sockets.add(p);
      } else if (e.isDirectory() && !skip.has(p)) visit(p, veiled, false, below);
    }
  };
  // A root that is a git directory's own or lies inside one (an allowed path that names `.git`,
  // or a directory below it) starts with the context the walk around it would have brought
  // (round 4, finding 30, sixth pass): without it `.git` would be a bare repository and its
  // own top again.
  const context = gitContext(root);
  visit(root, context.veiled, false, context.inGit);
  for (const dir of standalone) {
    // "false" is the git directory of a work tree. True or unset is a top of its own, as every
    // such directory was before. No answer is no knowledge (seventh pass): it counts as a top
    // of its own too, so that nothing is left unprotected, and is a problem where the caller
    // must be able to tell (`doubts`).
    const bare = gitRun([...inGitDir(dir), "config", "--local", "--includes", "--type=bool", "--get", "core.bare"]);
    if (bare.status !== 0 && bare.status !== 1) found.doubts.set(dir, `git could not read core.bare in ${dir}, so whether it is a bare repository or the git directory of a work tree cannot be told`);
    if (!(bare.status === 0 && bare.out.trim() === "false")) found.tops.get(dir)!.add(dir);
  }
  return found;
}

// Whether a directory is a git directory's own or lies inside one, judged by the directories
// above it: one named `.git`, or one that holds `HEAD`, `objects` and `refs`. `veiled`: it lies
// in the part of it where names are refs and not credential files.
function gitContext(root: string): { inGit: boolean; veiled: boolean } {
  const parts = root.split("/").filter(Boolean);
  let at = "/";
  for (let i = 0; i < parts.length; i++) {
    at = path.join(at, parts[i]);
    const last = i === parts.length - 1;
    const gitDir = parts[i] === ".git" ? isDir(at) : !last && ["HEAD", "objects", "refs"].every((name) => lexists(path.join(at, name)));
    if (gitDir) return { inGit: true, veiled: !last && ["refs", "logs", "lfs", "annex"].includes(parts[i + 1]) };
  }
  return { inGit: false, veiled: false };
}

// The walks of one decision (round 3, finding 40). A shell call's git snapshot, layout check,
// decision and sandbox plan, or an edit's check, each need the same roots walked; one Scan made
// for that call walks each root once and hands every caller the same result. It is never kept
// for another call: a stale walk would miss a repository the previous command made.
//
// `also`: the roots of this decision's plan besides the project's own, known before the first
// walk: the allowed paths and the temp directories. One of them that lies inside a root a
// caller asks about is walked as itself and left out of the walk around it, whoever asks first
// (round 4, finding 30): the layout check, which asks about the project alone, and the plan,
// which asks about them all, then split the project the same way and share every walk.
export class Scan {
  private walks = new Map<string, { found: Found; secrets: boolean }>();
  readonly also: string[];
  constructor(allowedPaths: string[] = []) {
    this.also = [...new Set([...allowedPaths, "/tmp", "/var/tmp", os.tmpdir()].map(realpath))];
  }
  walk(root: string, skip: Set<string>, secrets: boolean): Found {
    // Only the skipped directories inside the root change what its walk sees.
    const key = [root, ...[...skip].filter((d) => d !== root && d.startsWith(root.endsWith("/") ? root : root + "/")).sort()].join("\u0000");
    const done = this.walks.get(key);
    // A walk that looked for credential files answers one that did not.
    if (done && (done.secrets || !secrets)) return done.found;
    const found = scanRoot(root, skip, secrets);
    this.walks.set(key, { found, secrets });
    return found;
  }
}

export interface DiscoverOptions {
  // Directories that are not entered (the runtime directory under /run, which is covered whole).
  skip?: string[];
  // Roots in which credential files are looked for.
  secretsIn?: string[];
  // The caller's own roots (the project and the allowed paths; all of them unless given): there,
  // a directory that cannot be listed is a problem. Elsewhere it is listed in `unlistable`.
  own?: string[];
  scan?: Scan;
}

// Everything below the given directories. A root inside another one is walked once, as itself;
// so is a root of the decision's plan (Scan) that lies inside one of them, and what its walk
// finds counts as found below the directory around it.
export function discover(dirs: string[], o: DiscoverOptions = {}): Found {
  const found = emptyFound();
  const given = [...new Set(dirs.map(realpath))];
  const secretsIn = new Set((o.secretsIn ?? []).map(realpath));
  const ownDirs = new Set((o.own ?? dirs).map(realpath));
  const scan = o.scan ?? new Scan();
  const skipped = o.skip ?? [];
  const inside = scan.also.filter((dir) => !given.includes(dir) && given.some((r) => within(dir, r)) && !skipped.some((s) => within(dir, s)));
  const roots = [...given, ...inside];
  // The given directories a root answers for: itself, or the ones around it.
  const around = (root: string) => (given.includes(root) ? [root] : given.filter((r) => within(root, r)));
  for (const root of roots) {
    const part = scan.walk(root, new Set([...roots.filter((r) => r !== root), ...skipped]), around(root).some((r) => secretsIn.has(r)));
    for (const key of ["gitDirs", "pointers", "links", "secrets", "sockets", "veiled"] as const) for (const p of part[key]) found[key].add(p);
    for (const [gitDir, tops] of part.tops) found.tops.set(gitDir, new Set([...(found.tops.get(gitDir) ?? []), ...tops]));
    found.problems.push(...part.problems);
    for (const [dir, text] of part.doubts) {
      found.doubts.set(dir, text);
      if (around(root).some((r) => ownDirs.has(r))) found.problems.push(text);
    }
    for (const dir of part.unlistable) {
      if (around(root).some((r) => ownDirs.has(r))) found.problems.push(`${dir} cannot be listed (EACCES) but can be entered or written, so what is in it cannot be protected`);
      else found.unlistable.add(dir);
    }
  }
  return found;
}

// Git directories and pointer files below the project's checkouts. Within one decision (a
// `scan`), the walk also looks for credential files, so that the plan can use the same walk.
export const findGitEntries = (dirs: string[], scan?: Scan): Found => discover(dirs, { secretsIn: scan ? dirs : [], scan });

// What a credential directory hides whole is left out of the plan: nothing below it can be
// reached from the sandbox.
const veiledPath = (hidden: Set<string>, p: string) => {
  if (!hidden.size) return false;
  for (let dir = path.dirname(p); dir !== path.dirname(dir); dir = path.dirname(dir)) if (hidden.has(dir)) return true;
  return hidden.has(p);
};
function unveiled(found: Found, hidden: Set<string>): Found {
  if (!hidden.size) return found;
  const keep = (p: string) => !veiledPath(hidden, p);
  const tops = new Map<string, Set<string>>();
  for (const [gitDir, set] of found.tops) if (keep(gitDir)) tops.set(gitDir, new Set([...set].filter(keep)));
  return {
    ...found,
    gitDirs: new Set([...found.gitDirs].filter(keep)),
    pointers: new Set([...found.pointers].filter(keep)),
    links: new Set([...found.links].filter(keep)),
    tops,
    sockets: new Set([...found.sockets].filter(keep)),
  };
}

// The git directories of the populated submodules that git keeps outside `modules/` of the
// repository they belong to: in the submodule's own work tree (`lib/.git` a directory), or
// wherever its `.git` file points (`git clone --separate-git-dir`, then `git submodule add`).
// Among `gitDirs`, each one whose work tree (the directory around a `.git`, and every top in
// `topsOf`) is a gitlink in the index of the work tree around it, starting from the work trees
// `tops` and going on into the submodules found (to any depth git recurses). The index is asked
// about each candidate by name, so a large one costs nothing. A lookup that fails is a problem.
export function workTreeSubmodules(tops: string[], gitDirs: Iterable<string>, topsOf?: ReadonlyMap<string, ReadonlySet<string>>): { dirs: string[]; problem?: string } {
  const around = new Set(tops);
  const dirs = new Set<string>();
  const candidates: { gitDir: string; top: string }[] = [];
  for (const gitDir of gitDirs) {
    const own = new Set<string>(path.basename(gitDir) === ".git" ? [path.dirname(gitDir)] : []);
    for (const top of topsOf?.get(gitDir) ?? []) if (top !== gitDir) own.add(top);
    for (const top of own) candidates.push({ gitDir, top });
  }
  candidates.sort((a, b) => a.top.length - b.top.length);
  for (const { gitDir, top } of candidates) {
    // The nearest work tree around it whose index is read.
    const parent = [...around].filter((t) => t !== top && within(top, t)).sort((a, b) => b.length - a.length)[0];
    if (around.has(top) || parent === undefined) continue;
    const entry = gitRun(["--literal-pathspecs", "-C", parent, "ls-files", "--stage", "-z", "--", path.relative(parent, top)]);
    if (entry.status !== 0) return { dirs: [...dirs], problem: `git could not say whether ${top} is a submodule of ${parent}` };
    if (!entry.out.startsWith("160000 ")) continue;
    dirs.add(gitDir);
    around.add(top);
  }
  return { dirs: [...dirs] };
}

const expandGitPath = (value: string, base: string) => path.resolve(base, value.replace(/^~(?=\/|$)/, HOME));

// A config value as git itself reads it in the repository whose git directory is `gitDir`
// (round 4, findings 21 and 25, seventh pass): from every file git reads there, your own and
// the system's included, with each `includeIf` judged for that repository (a global `includeIf
// "gitdir:<repo>/"` counts in that repository and in no other), the last value winning; byte for
// byte (`-z`: a value that ends in a space names another directory), and telling an empty value
// from none. The overrides gitRun adds on its command line do not answer (scope `command`).
// `receiving`: as the git that receives a push reads it. receive-pack changes into the git
// directory and calls it `.`, and git matches a `gitdir:` condition against that spelling too
// (config.c, include_by_gitdir: `<dir>/.` matches `gitdir:<dir>/`, which the directory's full
// path does not; run with git 2.47.3): the two readings can differ, so each use asks for its own.
// `gitDir` undefined: your own config alone, as git reads it outside any repository.
// Undefined: not set. Null: git could not say (`problems` gets why).
function configured(gitDir: string | undefined, key: string, problems: string[], receiving = false): string | undefined | null {
  const at = gitDir === undefined ? [] : receiving ? ["-C", gitDir, "--git-dir", ".", "--work-tree", "."] : inGitDir(gitDir);
  const r = gitRun([...at, "config", "--includes", "--show-scope", "--null", "--get-all", key]);
  const fields = r.out.split("\0");
  if ((r.status !== 0 && r.status !== 1) || fields.pop() !== "" || fields.length % 2) {
    problems.push(`git could not read ${key}${gitDir === undefined ? " in your own config" : ` in ${gitDir}`}`);
    return null;
  }
  let value: string | undefined;
  for (let i = 0; i < fields.length; i += 2) if (fields[i] !== "command") value = fields[i + 1];
  return value;
}

// The core.hooksPath git uses in a repository (`receiving`: when it receives a push); undefined
// when none is set or it could not be read (`problems` then says so).
function hooksPathOf(gitDir: string, problems: string[], receiving = false): string | undefined {
  // Leftover pointer targets and fixture directories cannot run hooks. Keep their
  // filesystem protections, but do not mistake a missing HEAD for a config failure.
  try {
    fs.lstatSync(path.join(gitDir, "HEAD"));
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return undefined;
  }
  return configured(gitDir, "core.hooksPath", problems, receiving) ?? undefined;
}

// Where git looks for hooks under a core.hooksPath, from `base` (the directory git is in when it
// runs them): an empty value is the root (git joins `<value>/<hook>`), `~/` is your home.
// Undefined for a value git expands in a way that is not followed here (`~user/`, `%(prefix)/`).
function hooksDir(value: string, base: string): string | undefined {
  if (value === "") return "/";
  if (/^(~[^/]|%\()/.test(value)) return undefined;
  return expandGitPath(value, base);
}

// Files a config file pulls in through include.path and includeIf.*.path, whether or not the
// condition holds right now, as deep as git follows them (it gives up at ten). A listing git
// cannot give is a problem: it is not the same as "includes nothing".
const GIT_INCLUDE_DEPTH = 10;
function includedFiles(configFile: string, problems: string[], seen = new Set<string>(), depth = 0): string[] {
  if (depth > GIT_INCLUDE_DEPTH || !fs.existsSync(configFile) || seen.has(realpath(configFile))) return [];
  seen.add(realpath(configFile));
  const out: string[] = [];
  const listed = gitRun(["config", "--file", configFile, "--get-regexp", "^include(if\\..*)?\\.path$"]);
  // 1: no such key.
  if (listed.status !== 0 && listed.status !== 1) {
    problems.push(`git could not say what ${configFile} includes, so those files cannot be protected`);
    return [];
  }
  for (const line of listed.out.split("\n").filter(Boolean)) {
    const value = line.slice(line.indexOf(" ") + 1).trim();
    if (!value) continue;
    const file = expandGitPath(value, path.dirname(configFile));
    out.push(file, ...includedFiles(file, problems, seen, depth + 1));
  }
  return out;
}

// The directories a plan made (ensureDir), each by the device, inode number and time of birth it
// was made with (an inode number alone is given again to the next directory made):
// what the plan itself creates must not look like a plant to the layout check (round 4, finding
// 21, seventh pass; C4 F5: `.husky/_` made for a relative core.hooksPath in a bare repository, or
// in a work tree that has no `.husky`, paused the session at the next decision). Only the very
// directory counts: one that was removed and made again is somebody else's.
const made = new Map<string, string>();
export function madeByPlan(p: string): boolean {
  const id = made.get(p);
  if (id === undefined) return false;
  try {
    const st = fs.lstatSync(p, { bigint: true });
    return st.isDirectory() && `${st.dev}:${st.ino}:${st.birthtimeNs}` === id;
  } catch {
    return false;
  }
}

// Creates a missing directory one component at a time, only below an existing real directory
// inside `roots`, and never through a symlink. False when it cannot be done safely.
function ensureDir(target: string, roots: string[]): boolean {
  const missing: string[] = [];
  let existing = target;
  while (!lexists(existing)) {
    missing.unshift(path.basename(existing));
    const parent = path.dirname(existing);
    if (parent === existing) return false;
    existing = parent;
  }
  let cur: string;
  try {
    cur = fs.realpathSync(existing);
    if (!fs.statSync(cur).isDirectory() || !roots.some((r) => within(cur, r))) return false;
    for (const name of missing) {
      cur = path.join(cur, name);
      fs.mkdirSync(cur);
      const st = fs.lstatSync(cur, { bigint: true });
      if (st.isSymbolicLink()) return false;
      made.set(cur, `${st.dev}:${st.ino}:${st.birthtimeNs}`);
    }
    return fs.realpathSync(cur) === cur;
  } catch {
    return false;
  }
}

// The path with every symbolic link on the way to it resolved, for as far as it exists. A link
// inside a writable directory is returned as `link`: a sandboxed command can replace it, so
// nothing behind it can be protected (a mount holds a directory in place, not a link).
function settle(p: string, rwDirs: string[]): { real: string; link?: string } {
  let cur = path.resolve(p);
  for (let hops = 0; hops < 40; hops++) {
    let link: string | undefined;
    let at = "/";
    for (const part of cur.split("/").filter(Boolean)) {
      at = path.join(at, part);
      if (isSymlink(at)) {
        link = at;
        break;
      }
      if (!lexists(at)) break;
    }
    if (!link) return { real: cur };
    if (rwDirs.some((d) => within(link, d))) return { real: cur, link };
    try {
      cur = path.resolve(path.dirname(link), fs.readlinkSync(link), path.relative(link, cur));
    } catch {
      return { real: cur, link };
    }
  }
  return { real: cur, link: cur };
}

interface Protected {
  ro: string[];
  pin: string[];
  problems: string[];
  // Git directories the call may write that lie inside one that is read-only whole (gitPaths).
  reopen?: string[];
  // The git directories that are read-only whole for the call (gitPaths).
  whole?: string[];
  // Paths that are not there and must not appear while the call runs (Plan.gitWatch).
  watch?: string[];
}

// The hooks git runs in a repository that is pushed into (githooks(5)).
const RECEIVE_HOOKS = ["pre-receive", "update", "post-receive", "post-update", "reference-transaction", "push-to-checkout", "proc-receive"];
// The hooks git runs in a repository that is pushed into (githooks(5)), and the ones the
// commands receive-pack runs there run (seventh pass; run for real, xcheck/reviewers/c6-opus/
// p8-hooks.sh): `pre-auto-gc` (`gc --auto`, on by `receive.autogc`), `post-index-change` (the
// checkout of `receive.denyCurrentBranch=updateInstead`).
const RECEIVE_SIDE_HOOKS = [...RECEIVE_HOOKS, "pre-auto-gc", "post-index-change"];
// Programs a repository's config names that git runs in it during a push into it.
const RECEIVE_PROGRAMS = ["core.fsmonitor", "core.alternateRefsCommand"];
const absoluteHooks = (value: string) => value === "" || /^(\/|~(\/|$))/.test(value);
const unfollowedHooks = (value: string, gitDir: string) => `core.hooksPath is ${JSON.stringify(value)} in ${gitDir}: git expands that in a way that cannot be followed here, so the directory its hooks run from cannot be protected`;
// The part of `target` that is not there yet: the first missing directory on the way to it.
function firstMissing(target: string): string {
  let cur = target;
  while (path.dirname(cur) !== cur && !lexists(path.dirname(cur))) cur = path.dirname(cur);
  return cur;
}

// `own`: the project and the allowed paths. What cannot be protected there is a problem, and the
// command asks. The temp directories are shared with every other program on the machine: what
// exists in a repository there is made read-only, and what cannot be is left (anything can
// build a new repository in /tmp anyway; see "Known gaps").
function gitPaths(found: Found, searchDirs: string[], rwDirs: string[], gitWritable: boolean | Set<string>, own: string[]): Protected {
  // Build caches are not searched: they are only writable when the user opts in.
  const insideRw = (p: string) => rwDirs.some((d) => within(p, d));
  const ro: string[] = [...found.pointers];
  const pin: string[] = [];
  const reopen: string[] = [];
  const watch: string[] = [];
  // The git directories that are read-only whole for this call (linksOut).
  const whole: string[] = [];
  const all: string[] = [];
  const problems = { push: (text: string, at: string) => void (own.some((d) => within(at, d)) && all.push(text)) };
  for (const link of found.links) problems.push(`${link} is a symbolic link, which cannot be made read-only: a command could point it at a repository of its own making`, link);
  // A path that must stay as it is. `create`: it must exist too, and is made when that is safe.
  const protect = (p: string, what: string, create = false) => {
    const { real, link } = settle(p, rwDirs);
    if (link) return void problems.push(`${what} ${p} leads through the symbolic link ${link}, which a command could replace`, link);
    if (!insideRw(real) && !insideRw(realpath(path.dirname(real)))) return; // not writable: nothing to plant
    if (!lexists(real)) {
      if (!create) return void problems.push(`${what} ${p} does not exist inside a writable directory, so it cannot be protected`, real);
      if (!own.some((d) => within(real, d))) return; // nothing is created in a shared temp directory
      if (!ensureDir(real, rwDirs)) return void problems.push(`${what} ${p} does not exist and could not be created safely`, real);
    }
    ro.push(real);
  };
  const listing = (configFile: string) => {
    const failed: string[] = [];
    const files = includedFiles(configFile, failed);
    for (const text of failed) problems.push(text, configFile);
    return files;
  };
  // Your own core.hooksPath as git reads it outside any repository: an absolute one is made
  // where it is missing (below). Each repository's own reading, your config included, follows.
  const globalHooks = configured(undefined, "core.hooksPath", all) ?? undefined;
  const selected = (gitDir: string) => (gitWritable === true || (gitWritable instanceof Set && gitWritable.has(gitDir))) && lexists(path.join(gitDir, "HEAD"));
  for (const gitDir of found.gitDirs) {
    const tops = found.tops.get(gitDir) ?? new Set([path.dirname(gitDir)]);
    const hooks = path.join(gitDir, "hooks");
    // A linked worktree's admin directory has no hooks of its own (git takes them from the
    // directory its `commondir` names): one that is there is protected, none is made.
    const ownHooks = !lexists(path.join(gitDir, "commondir"));
    if (insideRw(gitDir) && lexists(gitDir) && (ownHooks || lexists(hooks))) protect(hooks, "the hooks directory", ownHooks);
    // Keep the specific unreadable include path ahead of a failed effective-config lookup.
    for (const file of [...listing(path.join(gitDir, "config")), ...listing(path.join(gitDir, "config.worktree"))]) protect(file, "git config includes");
    // A relative core.hooksPath is resolved by git in whichever worktree it runs: every one of
    // them is protected, so a pointer file planted elsewhere cannot draw the protection away.
    // The value is the one git uses in this repository (`configured`).
    const failed: string[] = [];
    const hooksPath = hooksPathOf(gitDir, failed);
    if (hooksPath !== undefined) {
      for (const top of tops) {
        const dir = hooksDir(hooksPath, top);
        if (dir !== undefined) protect(dir, "core.hooksPath", true);
      }
      // A value git expands in a way that is not followed here names a directory nobody looked
      // at: it may lie in the project, where every call can write (eighth pass; a user's own
      // `~<name>/` leads into their home directory). Giving up is a verdict: the call asks.
      if (hooksDir(hooksPath, gitDir) === undefined) problems.push(unfollowedHooks(hooksPath, gitDir), gitDir);
    }
    const inside = gitWritable instanceof Set ? [...gitWritable].filter((w) => w !== gitDir && within(w, gitDir) && selected(w)) : [];
    // The hooks of a push into the repository run in its git directory (git changes into the
    // directory a `.git` file names), and a relative core.hooksPath is resolved from there:
    // `.git/.husky/_/pre-receive` in a husky project (round 4, finding 21, sixth pass). Where
    // that place exists it is protected like any hooks directory. Where it does not, nothing is
    // made (the hook manager's files would then appear in `.git`): a git-only call has it
    // watched, and the layout check names it when it appears, for any call. A value that climbs
    // out (`../receive`) leads into the work tree, where every call can write (seventh pass).
    const receiving = lexists(gitDir) ? hooksPathOf(gitDir, failed, true) : undefined;
    const pushHooks = receiving !== undefined && !absoluteHooks(receiving) ? hooksDir(receiving, gitDir) : undefined;
    // (The receiving git may read another value than the one above: `configured`.)
    if (receiving !== undefined && receiving !== hooksPath && hooksDir(receiving, gitDir) === undefined) problems.push(unfollowedHooks(receiving, gitDir), gitDir);
    for (const text of new Set(failed)) problems.push(text, gitDir);
    if (pushHooks !== undefined && pushHooks !== gitDir) {
      if (lexists(pushHooks)) protect(pushHooks, "core.hooksPath for a push into the repository");
      else if (insideRw(firstMissing(pushHooks)) && !within(firstMissing(pushHooks), gitDir)) watch.push(firstMissing(pushHooks));
      else if (within(pushHooks, gitDir) && insideRw(gitDir) && selected(gitDir)) watch.push(firstMissing(pushHooks));
    }
    if (selected(gitDir)) {
      pin.push(gitDir);
      ro.push(hooks, path.join(gitDir, "config"), path.join(gitDir, "config.worktree"), path.join(gitDir, "commondir"), path.join(gitDir, "gitdir"));
      try {
        for (const wt of fs.readdirSync(path.join(gitDir, "worktrees"))) ro.push(path.join(gitDir, "worktrees", wt, "config.worktree"), path.join(gitDir, "worktrees", wt, "commondir"), path.join(gitDir, "worktrees", wt, "gitdir"));
      } catch {
        // no linked worktrees
      }
    } else if (!inside.length) {
      ro.push(gitDir);
      whole.push(gitDir);
    } else if (lexists(path.join(gitDir, "HEAD"))) {
      // A git directory that holds one the call may write (a superproject's `.git` around
      // `modules/<name>`): read-only whole, like any other, and the ones inside it that are the
      // call's are made writable again within it (lockwrite, AUTOMODE_REOPEN; round 4, finding
      // 21, seventh pass). Nothing can then be made at its top or on the way: no `packed-refs`,
      // `shallow`, `index` or `info/` that the superproject's git would trust, no new module.
      // Each of them, the ones inside another too (eighth pass): a git directory the call may
      // write is a mount of its own (a pin), which keeps the read-only flag it got with the
      // directory around it when only that one is made writable again (`git -C inner add` from
      // the outer module failed on `index.lock`).
      ro.push(gitDir);
      whole.push(gitDir);
      reopen.push(...inside);
    } else if (own.some((d) => within(gitDir, d))) {
      // No repository, only named as one (a `.git` file that points at a directory around the
      // call's repository): it is not granted, and cannot be read-only around it either.
      all.push(`${gitDir} is named as a git directory and holds the repository this call works in (${inside[0]}), so it cannot be kept read-only around it`);
    } else {
      ro.push(gitDir);
      whole.push(gitDir);
    }
  }
  if (globalHooks && absoluteHooks(globalHooks)) protect(expandGitPath(globalHooks, HOME), "your global core.hooksPath", true);
  // Your own config: a listing git cannot give counts wherever the file is.
  const globalProblems: string[] = [];
  for (const file of includedFiles(path.join(XDG_CONFIG, "git", "config"), globalProblems).concat(includedFiles(path.join(HOME, ".gitconfig"), globalProblems))) protect(file, "your git config includes");
  // Hook managers, at the top of every checkout.
  const tops = [...found.tops.values()].flatMap((set) => [...set]);
  for (const top of new Set([...tops, ...searchDirs.filter((d) => !["/tmp", "/var/tmp", realpath(os.tmpdir())].includes(d))])) {
    for (const name of HOOK_MANAGER_FILES) {
      const p = path.join(top, name);
      if (lexists(p)) protect(p, "the hook manager file");
    }
  }
  return { ro: [...new Set(ro)].filter(lexists), pin: [...new Set(pin)], problems: [...all, ...globalProblems], reopen: [...new Set(reopen)], watch: [...new Set(watch)], whole: [...new Set(whole)] };
}

// The symbolic links git follows inside a git directory: every one at its top, the ones on the
// way to its modules (below `modules/`, down to each module's own directory: that one holds a
// `HEAD` and is a git directory of its own, looked at as itself) and the entries of `worktrees/`.
// `only`: of the top, these names alone. `full`: there was more below `modules/` than is listed.
const LINK_ENTRIES = 20_000;
function gitLinks(dir: string, only?: string[]): { links: string[]; full: boolean } {
  const links: string[] = [];
  let left = LINK_ENTRIES;
  const entries = (at: string) => {
    try {
      return fs.readdirSync(at, { withFileTypes: true });
    } catch {
      return [];
    }
  };
  const modules = (at: string, depth: number) => {
    for (const e of entries(at)) {
      if (left-- <= 0) return;
      const p = path.join(at, e.name);
      if (e.isSymbolicLink()) links.push(p);
      else if (e.isDirectory() && depth < 8 && !lexists(path.join(p, "HEAD"))) modules(p, depth + 1);
    }
  };
  for (const e of entries(dir)) {
    if (only && !only.includes(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isSymbolicLink()) links.push(p);
    else if (e.isDirectory() && e.name === "modules") modules(p, 0);
    else if (e.isDirectory() && e.name === "worktrees") for (const w of entries(p)) if (w.isSymbolicLink()) links.push(path.join(p, w.name));
  }
  return { links, full: left < 0 };
}

// A git directory that is read-only whole is a mount over the directory, and a symbolic link in
// it is not held by that: what git reads through the link lies wherever the link leads. Where
// that is a place the call may write (inside a writable directory, and in no read-only path
// there, or in a directory made writable again), the call could write what git takes for a part
// of the git directory: the superproject's refs through `.git/refs`, a module of any name
// through `.git/modules/<name>` (round 4, finding 21, eighth pass; run by a reviewer,
// xcheck/reviewers/c7-sonnet/y-p2d.test.mts: `main` forged from a call in a submodule). Each
// such link is a problem, and the call asks. A link that leads outside the writable directories,
// or into a path that is read-only for the call, changes nothing: the link itself cannot be
// replaced (its directory is read-only), and neither can what it leads to.
// `dirs`: the directories to look in, each whole or for the names `only` (a linked worktree's
// common directory, of which `modules/` and `worktrees/` alone are closed). `own`: the caller's
// own directories; a link from a repository in a shared temp directory to another place there
// is left, as everything else in such a repository that cannot be protected is (gitPaths).
function linksOut(dirs: { dir: string; only?: string[] }[], ro: string[], reopen: string[], rwDirs: string[], own: string[]): string[] {
  const out: string[] = [];
  // The innermost read-only path or reopened directory around a place decides.
  const mayWrite = (p: string) => {
    if (!rwDirs.some((d) => within(p, d))) return false;
    let best = -1;
    let open = true;
    for (const dir of ro) if (within(p, dir) && dir.length > best) [best, open] = [dir.length, false];
    for (const dir of reopen) if (within(p, dir) && dir.length >= best) [best, open] = [dir.length, true];
    return open;
  };
  for (const { dir, only } of dirs) {
    const { links, full } = gitLinks(dir, only);
    if (full && own.some((d) => within(dir, d))) out.push(`${dir} holds more than ${LINK_ENTRIES} entries below modules/, too many to look for symbolic links among them`);
    for (const link of links) {
      let target: string;
      try {
        target = fs.realpathSync(link);
      } catch {
        // It leads to nothing that is there: the place a command could make.
        target = settle(link, []).real;
      }
      if (own.some((d) => within(dir, d) || within(target, d)) && mayWrite(target)) out.push(`${link} is a symbolic link in a git directory that is read-only for this call, and it leads to ${target}, which the call may write: what git reads through it cannot be protected`);
    }
  }
  return out;
}

// Where a push into each git directory would run its hooks from when core.hooksPath is relative
// and that place is not there: `$GIT_DIR/<path>`, by its first missing part (the layout check
// in decide.ts records these, and names one that appears). Inside the git directory or, for a
// value that climbs out of it, in the work tree around it. Not for a repository that is its own
// top (a bare one, `tops`): there the plan makes the directory itself, to protect it.
export function pushHooksMissing(gitDirs: Iterable<string>, tops?: ReadonlyMap<string, ReadonlySet<string>>): Map<string, string> {
  const out = new Map<string, string>();
  const unused: string[] = [];
  for (const gitDir of gitDirs) {
    if (tops?.get(gitDir)?.has(gitDir)) continue;
    const hooksPath = hooksPathOf(gitDir, unused, true);
    if (hooksPath === undefined || absoluteHooks(hooksPath)) continue;
    const pushHooks = hooksDir(hooksPath, gitDir);
    if (pushHooks !== undefined && pushHooks !== gitDir && !lexists(pushHooks)) out.set(gitDir, firstMissing(pushHooks));
  }
  return out;
}

// What a push into the repository would run there: a receive-side hook (RECEIVE_SIDE_HOOKS), in
// the hooks directory of its common directory or under the core.hooksPath git uses in it (a
// relative one from the git directory), or a program its config names (RECEIVE_PROGRAMS). What
// cannot be looked up counts as one.
function receiveHook(gitDir: string, common: string): string | undefined {
  const failed: string[] = [];
  const hooksPath = configured(gitDir, "core.hooksPath", failed, true);
  const programs = RECEIVE_PROGRAMS.map((key) => [key, configured(gitDir, key, failed, true)] as const);
  if (failed.length) return `hooks that could not be looked up (${failed[0]})`;
  for (const [key, value] of programs) {
    // `core.fsmonitor` as a boolean switches git's own monitor on or off: no program of anyone's.
    if (value == null || (key === "core.fsmonitor" && /^(true|false|yes|no|on|off|1|0|)$/i.test(value))) continue;
    return `${key} set to a program (${JSON.stringify(value)})`;
  }
  const dir = hooksPath == null ? path.join(common, "hooks") : hooksDir(hooksPath, gitDir);
  if (dir === undefined) return `a core.hooksPath that cannot be followed here (${hooksPath})`;
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch (e) {
    return ["ENOENT", "ENOTDIR"].includes((e as NodeJS.ErrnoException).code ?? "") ? undefined : `a hooks directory that cannot be listed (${dir})`;
  }
  for (const name of RECEIVE_SIDE_HOOKS) {
    if (!names.includes(name)) continue;
    try {
      fs.accessSync(path.join(dir, name), fs.constants.X_OK);
      return `a ${name} hook (${path.join(dir, name)})`;
    } catch {
      // not executable: git does not run it
    }
  }
  return undefined;
}

// Linux limits each environment string, including its name and trailing NUL, to 128 KiB
// (MAX_ARG_STRLEN, 32 pages of 4 KiB; a string of exactly that size is taken): the wrapper is
// handed its lists, the command and the names it may keep as one string each. On a kernel with
// larger pages the limit is higher, and this one only errs towards asking.
export function envStringProblem(name: string, value: string): string | undefined {
  return Buffer.byteLength(`${name}=${value}\0`) > 128 * 1024 ? `${name} exceeds the kernel environment string limit` : undefined;
}

// The directories opencode loads project-level files from: the session directory and every
// writable directory above it.
export function opencodeDirs(project: string | undefined, rwDirs: string[]): string[] {
  const out: string[] = [];
  if (!project) return out;
  for (let dir = realpath(project); rwDirs.some((d) => within(dir, d)); dir = path.dirname(dir)) {
    out.push(dir);
    if (path.dirname(dir) === dir) break;
  }
  return out;
}

// opencode's project-level config, from the session directory up through every writable parent.
// `.opencode` holds plugins opencode loads and runs: it is created (empty, which git does not
// show) so that it can be made read-only instead of appearing later.
function opencodePaths(project: string | undefined, rwDirs: string[]): Protected {
  const ro: string[] = [];
  const problems: string[] = [];
  const dirs = opencodeDirs(project, rwDirs);
  for (const dir of dirs) {
    for (const name of OPENCODE_PROJECT_FILES) {
      const p = path.join(dir, name);
      if (isSymlink(p)) problems.push(`${p} is a symbolic link and cannot be protected`);
      else if (lexists(p)) ro.push(p);
      else if (name === ".opencode" && dir === dirs[0] && ensureDir(p, rwDirs)) ro.push(p);
    }
  }
  return { ro, pin: [], problems };
}

const secretScope = makeScope("/", []);
// The rules' own test for a credential file or directory.
export const isSecretPath = (p: string) => readVerdict("read", p, secretScope) !== undefined;

function list(dir: string): fs.Dirent[] {
  try {
    return fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

// Under $HOME: its own entries, those of each dot-directory, and two levels of the XDG config
// and data directories. ($HOME is not writable for a sandboxed command; the project is, and is
// walked whole.)
function homeSecrets(): string[] {
  const out: string[] = [];
  const visit = (dir: string, depth: number) => {
    for (const e of list(dir)) {
      const p = path.join(dir, e.name);
      if (isSecretPath(p)) out.push(p);
      else if (depth > 0 && e.isDirectory() && (e.name.startsWith(".") || dir !== HOME)) visit(p, depth - 1);
    }
  };
  visit(HOME, 1);
  visit(XDG_CONFIG, 1);
  visit(XDG_DATA, 1);
  // sssd and others add a random suffix to the Kerberos ticket cache.
  const uid = process.getuid?.() ?? 0;
  for (const e of list("/tmp")) if (e.name.startsWith(`krb5cc_${uid}`)) out.push(path.join("/tmp", e.name));
  return out;
}

// Sockets of other services. The runtime directory is covered whole (or entry by entry around a
// socket that must stay); the usual system socket directories are covered where they exist; and
// every socket under /run and the temp directories that this user can connect to is covered.
function sockets(keep: Set<string>, found: Found, problems: string[], scan?: Scan): string[] {
  const uid = process.getuid?.() ?? 0;
  const runtime = realpath(process.env.XDG_RUNTIME_DIR || `/run/user/${uid}`);
  const out = new Set<string>();
  const kept = (p: string) => [...keep].some((k) => within(k, p));
  const cover = (dir: string) => {
    if (!kept(dir)) return void out.add(dir);
    for (const e of list(dir)) {
      const p = path.join(dir, e.name);
      if (keep.has(p) || keep.has(realpath(p))) continue;
      if (e.isSymbolicLink()) out.add(realpath(p));
      else if (e.isDirectory()) cover(p);
      else out.add(p);
    }
  };
  if (fs.existsSync(runtime)) cover(runtime);
  for (const p of [
    "/run/dbus", "/run/docker.sock", "/run/containerd", "/run/podman", "/run/libvirt", "/run/lxd.socket", "/run/screen", "/run/snapd.socket", "/run/snapd-snap.socket",
    "/var/lib/lxd/unix.socket", "/var/snap/lxd/common/lxd/unix.socket", "/var/lib/incus/unix.socket", "/tmp/.X11-unix", "/tmp/.ICE-unix",
  ]) {
    if (fs.existsSync(p)) out.add(realpath(p));
  }
  // Nothing under /run is the caller's own: a directory there that can be entered and not listed
  // is covered whole, as is one in a temp directory (round 3, finding 26).
  const underRun = discover(["/run"], { skip: [runtime, ...out], own: [], scan });
  problems.push(...underRun.problems);
  for (const p of [...found.unlistable, ...underRun.unlistable]) if (!kept(p)) out.add(p);
  for (const p of [...found.sockets, ...underRun.sockets]) if (![...out].some((covered) => within(p, covered))) out.add(p);
  return [...out].filter((p) => !keep.has(p) && !keep.has(realpath(p)));
}

// What stays read-only for every command, to make the edit tool ask; and what could not be
// protected, which makes every edit ask as it makes a shell command ask (round 3, finding 11).
export function protectedPaths(o: Pick<PlanOptions, "projectRoots" | "allowedPaths" | "project">, scan?: Scan): { paths: string[]; problems: string[] } {
  const searchDirs = [...new Set([...o.projectRoots, ...o.allowedPaths].map(realpath))];
  const found = discover(searchDirs, { scan });
  const git = gitPaths(found, searchDirs, searchDirs, false, searchDirs);
  const opencode = opencodePaths(o.project, searchDirs);
  const links = linksOut((git.whole ?? []).map((dir) => ({ dir })), git.ro, [], searchDirs, searchDirs);
  return { paths: [...git.ro, ...opencode.ro], problems: [...found.problems, ...git.problems, ...links, ...opencode.problems] };
}

// `scan`: the walks of this call's decision, used again here (round 3, finding 40).
export function plan(o: PlanOptions, scan?: Scan): Plan {
  const own = [...new Set([...o.projectRoots, ...o.allowedPaths].map(realpath))];
  const searchDirs = [...new Set([...own, ...["/tmp", "/var/tmp", os.tmpdir()].map(realpath)])];
  const rwDirs = [...new Set([...searchDirs, ...o.cacheDirs.map(realpath)])];
  // Credential files are looked for in the project and the allowed paths; the temp directories
  // are shared with everything else on the machine.
  const agent = process.env.SSH_AUTH_SOCK;
  const keep = new Set([...o.keepSockets, ...(o.exposeSsh && agent ? [agent] : [])].filter(Boolean).flatMap((p) => [p, realpath(p)]));
  const show = new Set(o.showPaths.map(realpath));
  const discovered = discover(searchDirs, { secretsIn: own, own, scan });
  const sshDir = path.join(HOME, ".ssh");
  const sshHidden = o.exposeSsh ? list(sshDir).map((e) => e.name).filter((n) => !SSH_VISIBLE.test(n)).map((n) => path.join(sshDir, n)) : [sshDir];
  const hidden = new Set([...discovered.veiled, ...sshHidden].filter((p) => !(o.exposeSsh && p === sshDir) && lexists(p) && !show.has(realpath(p)) && !keep.has(p) && !keep.has(realpath(p))));
  const found = unveiled(discovered, hidden);
  // The git directories this call may write (round 4, finding 21, decision 1): those of the
  // repositories it works in, and no other.
  const writable = new Set<string>();
  const lookupProblems: string[] = [];
  const inRw = (p: string) => rwDirs.some((root) => within(p, root));
  // The repository git finds from `at`: its git directory, its common directory, and every git
  // directory the walk found under its git directory (`modules/…`; for a main checkout, whose
  // git directory is the common one, `worktrees/…` too). Never one around it: a call that works
  // in a submodule kept under `.git/modules/<name>` gets the module, and the superproject's git
  // directory around it is read-only whole (gitPaths). A call in a linked worktree gets its own
  // admin directory and the common directory, which holds the objects and refs it writes; not
  // the modules of the main checkout (a worktree's own are under its admin directory) nor the
  // other worktrees' admin directories, which stay read-only whole (round 4, finding 21,
  // seventh pass).
  // "missing": `at` is in no repository. "outside": it lies outside every writable root, where
  // nothing can be written whatever the plan says. "unknown": git could not say, or the walk
  // did not find it.
  const repository = (at: string): { dir: string; base: string; dirs: string[] } | "missing" | "outside" | "unknown" => {
    const gitDir = gitRun(["-C", at, "rev-parse", "--absolute-git-dir"]);
    const common = gitRun(["-C", at, "rev-parse", "--path-format=absolute", "--git-common-dir"]);
    if (gitDir.status === 128 && common.status === 128) return "missing";
    if (gitDir.status !== 0 || common.status !== 0) return "unknown";
    const dir = realpath(gitDir.out.trim());
    const base = realpath(common.out.trim());
    if (!inRw(dir) && !inRw(base)) return "outside";
    if (!found.gitDirs.has(dir) || !found.gitDirs.has(base)) return "unknown";
    return { dir, base, dirs: [...found.gitDirs].filter((candidate) => candidate === dir || candidate === base || within(candidate, dir)) };
  };
  // The git directories whose work trees the call works in: every one it is granted, except the
  // common directory of a call in a linked worktree (its work tree is the main checkout's, and
  // the submodules there are not this call's).
  const worked = new Set<string>();
  // Calls in a linked worktree: its admin directory, with the common directory it belongs to.
  // `maintains`: a command of it there works on every worktree (PlanOptions.gitMaintainCwds).
  const inLinked: { dir: string; base: string; maintains: boolean }[] = [];
  const grant = (repo: { dir: string; base: string; dirs: string[] }, maintains = false) => {
    for (const dir of repo.dirs) {
      writable.add(dir);
      if (dir !== repo.base || repo.dir === repo.base) worked.add(dir);
    }
    if (repo.dir === repo.base) return;
    inLinked.push({ ...repo, maintains });
    // The other worktrees' admin directories, as a call in the main checkout has them.
    if (maintains) for (const candidate of found.gitDirs) if (within(candidate, path.join(repo.base, "worktrees"))) writable.add(candidate);
  };
  if (o.gitWritable) {
    // Where its git commands run. A command that ends in no repository gets no grant and no
    // problem (git says so itself). One in a repository outside the writable roots can read it
    // and nothing more: a command that writes its git directory would only fail there, so it
    // asks (round 4, finding 21, sixth pass).
    const cwds = o.gitCwds ?? [o.project ?? o.projectRoots[0]];
    const writers = o.gitWriteCwds ?? cwds;
    for (const cwd of cwds) {
      const repo = repository(cwd);
      if (repo === "unknown") lookupProblems.push(`cannot locate a discovered repository for git in ${cwd}`);
      else if (repo === "outside") {
        if (writers.includes(cwd)) lookupProblems.push(`git in ${cwd} would write a git directory that lies outside the project, the allowed paths and the temp directories, where the sandbox keeps everything read-only, so the command would fail; an approved run happens outside the sandbox`);
      } else if (typeof repo !== "string") grant(repo, (o.gitMaintainCwds ?? []).includes(cwd));
    }
    // Where a push goes, when that is a repository on this machine: a push works in it too. It
    // must be one the walk found (git also tries the path with `.git` added). The destination's
    // own receive-side hooks would run inside this call's sandbox, with the pushing
    // repository's git directory writable: one that has such a hook asks (finding 25).
    for (const to of o.gitPushTo ?? []) {
      const repo = [to, `${to}.git`].map(repository).find((r) => r !== "missing") ?? "missing";
      if (typeof repo === "string") {
        lookupProblems.push(`the push goes to ${to} on this machine, which is not a repository in the project, the allowed paths or a temp directory (${repo === "missing" ? "no repository is there" : repo === "outside" ? "it lies outside them" : "it could not be located"}), so the sandbox would keep it read-only and the push would fail`);
        continue;
      }
      grant(repo);
      const hook = receiveHook(repo.dir, repo.base);
      if (hook) lookupProblems.push(`the push goes to ${to} on this machine, which has ${hook}: it would run inside this call's sandbox, with the git directory the push comes from writable; an approved run happens outside the sandbox`);
    }
    // A populated submodule is part of the repository it belongs to, whether git keeps it
    // under `modules/` (granted above), in the submodule's own work tree, or wherever its
    // `.git` file points.
    const tops = [...worked].flatMap((dir) => [...(found.tops.get(dir) ?? [])]);
    const submodules = workTreeSubmodules(tops, found.gitDirs, found.tops);
    if (submodules.problem) lookupProblems.push(submodules.problem);
    for (const dir of submodules.dirs) {
      // A pointer file can name any directory. One that encloses a git directory the call works
      // in is no submodule's: granting it would grant every repository inside it.
      const around = [...writable].find((own) => own !== dir && within(own, dir));
      if (around) lookupProblems.push(`${dir} is named as a submodule's git directory and encloses the repository this call works in (${around}), so it is not granted`);
      else for (const candidate of found.gitDirs) if (within(candidate, dir)) writable.add(candidate);
    }
  }
  const git = gitPaths(found, searchDirs, rwDirs, writable, own);
  // A call in a linked worktree writes the common directory's objects and refs, and nothing
  // under its `modules/` or `worktrees/` but its own admin directory: both are read-only whole,
  // with that one directory writable again inside (so no new module or worktree can be made
  // there either). Not when a command of the same call works in the main checkout; and
  // `worktrees/` stays as a main checkout's call has it for a call that works on every worktree
  // (`git gc`: run under the wrapper, it fails on the other worktrees' `HEAD.lock` otherwise).
  // Every git directory the call is granted below a closed one is made writable again, the
  // submodules kept under the worktree's admin directory with it (eighth pass).
  const closed: string[] = [];
  const opened: string[] = [];
  // Where links are looked for: of each such common directory, the names that are closed.
  const shutIn = new Map<string, string[]>();
  for (const { base } of inLinked) {
    if (worked.has(base)) continue;
    for (const name of inLinked.some((l) => l.base === base && l.maintains) ? ["modules"] : ["modules", "worktrees"]) {
      const shut = path.join(base, name);
      shutIn.set(base, [...new Set([...(shutIn.get(base) ?? []), name])]);
      if (!isDir(shut) || isSymlink(shut) || !inRw(shut)) continue;
      closed.push(shut);
      for (const granted of writable) if (within(granted, shut) && lexists(path.join(granted, "HEAD"))) opened.push(granted);
    }
  }
  const opencode = opencodePaths(o.project, rwDirs);
  const ro = [...new Set([...git.ro, ...opencode.ro, ...closed])];
  const problems = [...found.problems, ...lookupProblems, ...git.problems, ...opencode.problems];
  // ssh-using commands see known_hosts, config and public keys; private keys stay hidden.
  // Credential files in the project and the allowed paths, at any depth.
  const inProject = [...found.secrets];
  if (inProject.length > limits.secrets) problems.push(`${inProject.length} credential files in the project, more than the ${limits.secrets} that can be hidden`);
  const secretList = [...DEFAULT_SECRET_PATHS.filter((p) => p !== sshDir), ...[...homeSecrets(), ...inProject.slice(0, limits.secrets)].filter((p) => !within(p, sshDir)), ...sshHidden, ...o.hidePaths];
  const secrets = secretList.flatMap((p) => [p, realpath(p)]).filter((p) => !show.has(realpath(p)));
  // The ssh agent, wherever it lives (outside the scanned directories too), unless this call may use it.
  const agentPaths = agent && !o.exposeSsh ? [agent, realpath(agent)] : [];
  const hide = [...new Set(["/dev/mqueue", ...sockets(keep, found, problems, scan), ...secrets, ...agentPaths])].filter((p) => lexists(p) && !keep.has(p) && !keep.has(realpath(p)));
  // A directory that holds a protected path could be renamed and rebuilt without it: every
  // directory between a writable root and such a path is pinned.
  const pin = new Set<string>();
  for (const p of [...ro, ...git.pin, ...hide]) {
    const roots = rwDirs.filter((d) => within(p, d) && p !== d);
    for (const root of roots) for (let dir = path.dirname(p); dir !== root && within(dir, root); dir = path.dirname(dir)) pin.add(dir);
  }
  const pins = [...[...pin].sort((a, b) => a.length - b.length), ...git.pin.filter((p) => !pin.has(p))];
  // A pin holds a directory in place. A link on the way cannot be pinned.
  const linked = pins.find((p) => isSymlink(p));
  if (linked) problems.push(`${linked} is a symbolic link on the way to a protected path, and cannot be kept in place`);
  // A directory made writable again is a mount of its own, and so is every directory kept in
  // place inside it (a pin: a module of its own, the way to a module's or a worktree's protected
  // files), which keeps the read-only flag it got with the directory around them: each is made
  // writable again as well, outermost first, unless it lies in a path that is read-only inside
  // that directory (a git directory there that is not the call's).
  const reopened = new Set<string>();
  for (const dir of new Set([...(git.reopen ?? []), ...opened])) {
    if (!inRw(dir)) continue;
    reopened.add(dir);
    for (const kept of pins) if (kept !== dir && within(kept, dir) && isDir(kept) && !isSymlink(kept) && !ro.some((p) => within(kept, p) && within(p, dir))) reopened.add(kept);
  }
  const reopen = [...reopened].sort((a, b) => a.length - b.length);
  // A link in a git directory that is read-only for the call, into a place it may write (linksOut).
  problems.push(...linksOut([...(git.whole ?? []).map((dir) => ({ dir })), ...[...shutIn].map(([dir, only]) => ({ dir, only }))], ro, reopen, rwDirs, own));
  const unexpressible = [...rwDirs, ...ro, ...reopen, ...pins, ...hide].filter((p) => !usable(p));
  if (unexpressible.length) problems.push(`cannot protect a path containing a newline (${JSON.stringify(unexpressible[0])})`);
  for (const [name, paths] of [["RW", rwDirs], ["RO", ro], ["REOPEN", reopen], ["PIN", pins], ["HIDE", hide], ["TMPFS", ["/dev/shm"]]] as const) {
    const tooLong = envStringProblem(`AUTOMODE_${name}`, paths.join("\n"));
    if (tooLong) problems.push(tooLong);
  }
  return {
    hidden,
    gitDirs: [...writable].filter((dir) => inRw(dir) && lexists(path.join(dir, "HEAD"))),
    gitWatch: git.watch ?? [],
    rw: [...rwDirs.filter(usable), ...DEV_WRITABLE, "/dev/shm"],
    ro: ro.filter(usable),
    reopen: reopen.filter(usable),
    pin: pins.filter(usable),
    hide: hide.filter(usable),
    tmpfs: ["/dev/shm"],
    ...(problems.length ? { problem: problems[0] } : {}),
  };
}

// The variables a sandboxed command may see. A name that looks like a credential never passes;
// a name on the well-known list always does; any other passes only with a value that plainly
// is not a secret (short, a number, or a list of paths). `keepEnv` overrides all of it.
const ENV_SECRET_NAME = /KEY|TOKEN|SECRET|PASS|PWD|CRED|AUTH|SESSION|COOKIE|PRIVATE|JWT|DSN|WEBHOOK|SIGNATURE|SALT|LICEN[SC]E|(^|_)SK$|^(AWS|AZURE|GCP|GOOGLE|OPENAI|ANTHROPIC|GITHUB|GH|GITLAB|NPM|PYPI|CARGO_REGISTRY|DOCKER|HF|HUGGING_?FACE|OPENCODE_SERVER|DBUS|XAUTHORITY|DISPLAY|WAYLAND)(_|$)/i;
const ENV_KNOWN =
  /^(PATH|HOME|USER|LOGNAME|SHELL|PWD|OLDPWD|SHLVL|TERM|COLORTERM|LANG|LANGUAGE|LC_[A-Z_]+|TZ|TMPDIR|TEMP|TMP|EDITOR|VISUAL|PAGER|LESS|HOSTNAME|MAIL|XDG_[A-Z_]+|CI|NO_COLOR|FORCE_COLOR|CLICOLOR|NODE_ENV|DEBUG|JAVA_HOME|GOPATH|GOROOT|GOBIN|GOCACHE|GOMODCACHE|CARGO_HOME|RUSTUP_HOME|RUSTUP_TOOLCHAIN|NVM_DIR|NVM_BIN|PNPM_HOME|BUN_INSTALL|VOLTA_HOME|PYENV_ROOT|VIRTUAL_ENV|CONDA_PREFIX|CONDA_DEFAULT_ENV|MANPATH|INFOPATH|LD_LIBRARY_PATH|PKG_CONFIG_PATH|CC|CXX|CFLAGS|CXXFLAGS|LDFLAGS|MAKEFLAGS|AGENT|AI_AGENT|OPENCODE|OPENCODE_SESSION_ID|OPENCODE_TERMINAL)$/;
// bash's own variables that change how it reads a command or what a word of it runs: a file it
// sources before the command (`BASH_ENV`; `ENV` for a shell started as `sh -i`), its options
// (`SHELLOPTS`, `BASHOPTS`, `POSIXLY_CORRECT`, `BASH_COMPAT`), what a glob matches and in which
// order (`GLOBIGNORE`, `GLOBSORT`), where `cd` goes (`CDPATH`), which files a PATH search passes
// over (`EXECIGNORE`), where `enable -f` loads from, how words are split (`IFS`), text it
// expands or runs when it prompts or traces (`PROMPT_COMMAND`, `PS0` to `PS4`), where the trace
// goes (`BASH_XTRACEFD`), and functions it imports (`BASH_FUNC_<name>%%`). The rules read a
// command as a bash with default settings reads it, and guard.ts asks about a command that sets
// one of these (ENV_DANGEROUS; test/c-sixth.test.mts holds the two lists together): a shell the
// plugin sees is not handed an inherited one either, however short and plain its value (round 4,
// finding 29). `sandboxKeepEnv` names the ones that are yours to keep.
const SHELL_OWN = /^(BASH_ENV|ENV|SHELLOPTS|BASHOPTS|POSIXLY_CORRECT|BASH_COMPAT|GLOBIGNORE|GLOBSORT|CDPATH|EXECIGNORE|BASH_LOADABLES_PATH|IFS|PROMPT_COMMAND|PS[0-4]|BASH_XTRACEFD|BASH_ALIASES|BASH_CMDS|histchars|BASH_FUNC_.*)$/;
export const shellOwn = (name: string) => SHELL_OWN.test(name);
// git's own variables that make a git command work in another repository, on another index or
// object store, or with another configuration than the one in the directory it runs in (round 4,
// finding 21, seventh pass). The plugin's own git lookups go to the repository in the command's
// directory (gitEnv drops `GIT_DIR` and its kin), so what they find says nothing about a shell
// that inherits one of these. The first group does that whatever its value. The second names a
// config file, a limit or a switch that the plugin's own git reads too, from its own
// environment: a value that differs from the one this process has makes the shell's git read
// something else, and so does one this process has and the shell does not (eighth pass:
// opencode hands a shell the environment of its session, which need not be this process's; with
// `GIT_CONFIG_GLOBAL` set here alone the checks judged one file and the shell's git read your
// default one). `GIT_NO_REPLACE_OBJECTS` changes which commit a ref names.
const GIT_ELSEWHERE = /^GIT_(DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|NAMESPACE|CONFIG|CONFIG_COUNT|CONFIG_KEY_\d+|CONFIG_VALUE_\d+|CONFIG_PARAMETERS|EXEC_PATH|SHALLOW_FILE|GRAFT_FILE|REPLACE_REF_BASE|ATTR_SOURCE|IMPLICIT_WORK_TREE)$/;
const GIT_ELSEWHERE_IF_OTHER = /^GIT_(CONFIG_GLOBAL|CONFIG_SYSTEM|CONFIG_NOSYSTEM|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|NO_REPLACE_OBJECTS)$/;
// The first such variable in the environment a shell is about to be given (`own`: this
// process's), or undefined. One of the second group may be the shell's or this process's alone.
export function gitElsewhere(env: Record<string, string | undefined>, own: Record<string, string | undefined> = process.env): string | undefined {
  return [...new Set([...Object.keys(env), ...Object.keys(own)])].sort().find((name) => (GIT_ELSEWHERE.test(name) ? env[name] !== undefined : GIT_ELSEWHERE_IF_OTHER.test(name) && env[name] !== own[name]));
}
const plainValue = (v: string) => v.length <= 12 || /^[\d.]+$/.test(v) || (!v.includes("@") && v.split(":").every((part) => /^(\/|~\/|\.\.?\/)[^\s]*$/.test(part) || part === ""));

export function envKept(env: Record<string, string | undefined>, keepEnv: string[]): { keep: string[]; dropped: string[] } {
  const keep: string[] = [];
  const dropped: string[] = [];
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined || name.startsWith("AUTOMODE_")) continue;
    // Proxy settings are needed to reach the network at all; one that carries a password is not kept.
    const proxy = /^(no_proxy|((https?|all|ftp)_proxy))$/i.test(name) && !value.includes("@");
    // The shell's own variables (SHELL_OWN): a sandboxed shell gets its defaults.
    const prompt = shellOwn(name);
    const ok = keepEnv.includes(name) || name === "SSH_AUTH_SOCK" || proxy || (prompt || (name !== "PWD" && name !== "OLDPWD" && ENV_SECRET_NAME.test(name)) ? false : ENV_KNOWN.test(name) || plainValue(value));
    (ok ? keep : dropped).push(name);
  }
  // opencode adds these after the plugin's hook has run.
  keep.push("AGENT", "AI_AGENT", "OPENCODE", "OPENCODE_SESSION_ID");
  return { keep: [...new Set(keep)], dropped };
}
