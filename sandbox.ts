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

// The kernel's answer (realpath(3)): Node's own fs.realpathSync takes `..` away by the text before
// it follows the link in front of it (tenth pass).
export function realpath(p: string): string {
  try {
    return fs.realpathSync.native(p);
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

// Council project review 1, round 4: the plugin's own git (its lookups, and the dry-run push
// and ls-remote with their ssh) finds git and what git runs by PATH: an entry a call can write (in
// the project or a writable path, a temp directory, a relative one) could hold a planted `git` or
// `ssh` that would run in this process, outside the sandbox. Those entries are left out of its
// PATH. `setPluginWritable` tells the places (index.ts); the working directory counts until then.
let pluginWritable: ((p: string) => boolean) | undefined;
export function setPluginWritable(writable: (p: string) => boolean): void {
  pluginWritable = writable;
}
// (Round 7: the loader's lists too: LD_LIBRARY_PATH, LD_PRELOAD and LD_AUDIT keep only their
// absolute entries outside the places a call can write; with none left, the variable goes.)
function pluginLoader(env: NodeJS.ProcessEnv): void {
  for (const name of ["LD_LIBRARY_PATH", "LD_PRELOAD", "LD_AUDIT"]) {
    const value = env[name];
    if (value === undefined) continue;
    const kept = cleanList(value.split(name === "LD_LIBRARY_PATH" ? ":" : /[:\s]/));
    if (kept.length) env[name] = kept.join(":");
    else delete env[name];
  }
}
function cleanList(entries: string[]): string[] {
  const temps = [...new Set(["/tmp", "/var/tmp", "/dev/shm", os.tmpdir()].flatMap((d) => [d, realpath(d)]))];
  const cwd = process.cwd();
  const writable = pluginWritable ?? ((p: string) => cwd !== "/" && !within(HOME, cwd) && within(p, cwd));
  return entries.filter((e) => path.isAbsolute(e) && ![e, realpath(e)].some((p) => writable(p) || temps.some((t) => within(p, t))));
}
export function pluginPath(list = process.env.PATH ?? ""): string {
  const temps = [...new Set(["/tmp", "/var/tmp", "/dev/shm", os.tmpdir()].flatMap((d) => [d, realpath(d)]))];
  const cwd = process.cwd();
  const writable = pluginWritable ?? ((p: string) => cwd !== "/" && !within(HOME, cwd) && within(p, cwd));
  const kept = list
    .split(":")
    .filter((e) => path.isAbsolute(e) && ![e, realpath(e)].some((p) => writable(p) || temps.some((t) => within(p, t))))
    .join(":");
  // (Round 6: an empty PATH is searched as the working directory: with no entry left, git is not
  // found at all, and the lookups that need it ask.)
  return kept || "/nonexistent/automode-no-path";
}
const GIT_SAFE = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false", "-c", "core.askPass=", "-c", "core.pager=cat"];
export const gitEnv = (): NodeJS.ProcessEnv => {
  // GIT_NO_LAZY_FETCH: a partial clone's missing object is not fetched from its promisor remote,
  // whose `uploadpack` a repository's config names (council project review 1).
  const env: NodeJS.ProcessEnv = { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0", GIT_ASKPASS: "", SSH_ASKPASS: "", SSH_ASKPASS_REQUIRE: "never", GIT_PAGER: "cat", GIT_NO_LAZY_FETCH: "1", PATH: pluginPath() };
  for (const name of ["GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG", "GIT_CONFIG_COUNT", "GIT_SSH", "GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_EDITOR"]) delete env[name];
  pluginLoader(env);
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
// trust on the answer must look at `status`: no answer is not the same as an empty one. These
// are lookups: no transport may start (council project review 1: a lazy fetch ran a planted
// `remote.<name>.uploadpack`), which `ls-remote --get-url` does not need. An empty
// GIT_ALLOW_PROTOCOL allows none, and unlike `-c protocol.allow=never` it is not in the
// configuration the checks list.
export function gitRun(args: string[], timeout = 3000): GitResult {
  const r = spawnSync("git", gitArgs(args), { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout, maxBuffer: 16 << 20, env: { ...gitEnv(), GIT_ALLOW_PROTOCOL: "" } });
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
    // (Council project review 1: `HEAD` and `commondir` are a git directory too, its objects and
    // refs in the directory `commondir` names, as git reads it.)
    const gitDirHere = names.has("HEAD") && ((names.has("objects") && names.has("refs")) || names.has("commondir")) && !names.has(".git");
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
            // Followed as git follows it, link by link (tenth pass: by path.resolve,
            // `<outside>/lnk/../admin` was taken for `<outside>/admin` before `lnk` was followed).
            const named = (text: string, base: string) => located(text.startsWith("/") ? text : `${base}/${text}`);
            const gitdir = named(m[1].trim(), dir);
            addGitDir(gitdir, here);
            try {
              found.gitDirs.add(named(fs.readFileSync(path.join(gitdir, "commondir"), "utf8").trim(), gitdir));
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

// A path in git's config as git takes it: from `base` when it is relative, `~/` your home.
// Joined, not resolved: git hands the string to the kernel, which takes a `..` in it after the
// link in front of it (tenth pass: `<outside>/lnk/../h` is `lnk`'s parent's `h`, not
// `<outside>/h`). `settle` walks it as the kernel does; `located` says where it ends.
const expandGitPath = (value: string, base: string) => {
  const v = value.replace(/^~(?=\/|$)/, HOME);
  return v.startsWith("/") ? v : `${base}/${v}`;
};

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
function includedFiles(configFile: string, problems: string[]): string[] {
  return includeTree(configFile, problems).map((i) => i.file);
}
// The same, each with whether git reads it only under a condition: an `includeIf`, or a file
// that one of those includes (twelfth pass). Keys and values as git hands them over (`--null`:
// a condition may hold a space, `gitdir:~/my work/`), each path as git expands it (`--type=path`:
// `~/`, `~<user>/` from the password file, `%(prefix)/`; a relative one is left as it is, and is
// the including file's). Thirteenth pass: `~<you>/` was read as `<HOME>/~<you>/`, and the file it
// names went unread and unprotected (Opus's C12 F1, run under the wrapper). A user git does not
// know stops git (status 128): it could not say.
function includeTree(configFile: string, problems: string[], seen = new Set<string>(), depth = 0, conditional = false): { file: string; conditional: boolean }[] {
  // (The closing reading, step 7 F3: a file reached plainly and again under a condition is walked
  // under the condition too, so a core.hooksPath below it is read as conditional.)
  const key = `${realpath(configFile)}\0${conditional}`;
  if (depth > GIT_INCLUDE_DEPTH || !fs.existsSync(configFile) || seen.has(key)) return [];
  seen.add(key);
  const out: { file: string; conditional: boolean }[] = [];
  const listed = gitRun(["config", "--file", configFile, "--null", "--type=path", "--get-regexp", "^include(if\\..*)?\\.path$"]);
  // 1: no such key.
  if (listed.status !== 0 && listed.status !== 1) {
    problems.push(`git could not say what ${configFile} includes, so those files cannot be protected`);
    return [];
  }
  for (const entry of listed.out.split("\0").filter(Boolean)) {
    const at = entry.indexOf("\n");
    const value = at < 0 ? "" : entry.slice(at + 1);
    if (!value) continue;
    // (Joined, not resolved: expandGitPath.)
    const file = value.startsWith("/") ? value : `${path.dirname(configFile)}/${value}`;
    const under = conditional || /^includeif\./i.test(entry);
    out.push({ file, conditional: under }, ...includeTree(file, problems, seen, depth + 1, under));
  }
  return out;
}
// The user's configuration git reads, as its own environment names it (the closing reading, step 7
// F1): the file GIT_CONFIG_GLOBAL names where it is set (git then reads neither of the two others),
// `$XDG_CONFIG_HOME/git/config` and `~/.gitconfig` otherwise.
export function globalGitConfigs(): string[] {
  const named = process.env.GIT_CONFIG_GLOBAL;
  if (named !== undefined) return named === "" || named === "/dev/null" ? [] : [named];
  return [path.join(XDG_CONFIG, "git", "config"), path.join(HOME, ".gitconfig")];
}
// The system configuration git reads, as its own environment names it (the shell's git gets the
// same: gitElsewhere): `GIT_CONFIG_SYSTEM` where set, `/etc/gitconfig` otherwise, none under
// `GIT_CONFIG_NOSYSTEM` (a boolean to git; only a plain "yes" spelling of it is taken here, so
// that what is not read is never one git reads).
export function systemGitConfig(): string | undefined {
  if (/^\s*(1|true|yes|on)\s*$/i.test(process.env.GIT_CONFIG_NOSYSTEM ?? "")) return undefined;
  return process.env.GIT_CONFIG_SYSTEM ?? "/etc/gitconfig";
}

// A core.hooksPath that a file read only under a condition sets (twelfth pass, the maintainer's
// decision "ask whenever a conditional include sets core.hooksPath"; C11's reading F2, run under
// the wrapper: `includeIf "onbranch:feature"` naming `.hooks-feature`, on `main` nothing named
// it, a call wrote `.hooks-feature/pre-commit`, `git switch -c feature` was allowed, and your
// next commit ran it). Which directory git runs hooks from then depends on the branch, the
// directory or the remote it is in, so it cannot be protected: each such file is a problem.
// Read from that file alone (what it includes is a file of its own here).
function conditionalHooks(included: { file: string; conditional: boolean }[], say: (text: string, at: string) => void) {
  for (const { file } of included.filter((i) => i.conditional && lexists(i.file))) {
    const r = gitRun(["config", "--file", file, "--null", "--get-all", "core.hooksPath"]);
    if (r.status === 1) continue;
    say(r.status === 0 ? `${file} sets core.hooksPath and git reads it only under a condition (includeIf): where git runs hooks from then cannot be told here, so it cannot be protected` : `git could not read core.hooksPath in ${file}, which git reads under a condition (includeIf)`, file);
  }
}

// What git reads its hooks and its settings from for a git directory, besides the directory's
// own `hooks/` and `config`: the directories a configured core.hooksPath names (as the git that
// runs in its work tree reads the key and as the git that receives a push does; a relative one
// from the git directory and, where that is a `.git`, from the directory around it), and the
// files its config includes. For the comparison of a directory a pause named (decide.ts,
// treeHeld). `problems`: what git could not say.
export function gitReadsElsewhere(gitDir: string): { hooks: string[]; includes: string[]; problems: string[] } {
  const problems: string[] = [];
  const hooks = new Set<string>();
  const bases = [gitDir, ...(path.basename(gitDir) === ".git" ? [path.dirname(gitDir)] : [])];
  for (const receiving of [false, true]) {
    const value = hooksPathOf(gitDir, problems, receiving);
    if (value === undefined) continue;
    for (const base of bases) {
      const dir = hooksDir(value, base);
      if (dir === undefined) problems.push(unfollowedHooks(value, gitDir));
      else hooks.add(located(dir));
    }
  }
  const includes = [...includedFiles(path.join(gitDir, "config"), problems), ...includedFiles(path.join(gitDir, "config.worktree"), problems)].map(located);
  return { hooks: [...hooks], includes: [...new Set(includes)], problems: [...new Set(problems)] };
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
// `replaceable`: the caller's own test of that. A chain that does not end, or a link that cannot
// be read, comes back as a `link` too.
// Walked as the kernel walks it, one name at a time from a place that holds no link: a link's
// text is put in front of what is left of the path, and `..` steps up from the place reached so
// far (tenth pass: built with `path.resolve` over the link's text, `<outside>/lnk/../d` was
// taken for `<outside>/d` before `lnk` was followed, where the kernel goes to `d` beside where
// `lnk` leads; run by a reviewer, xcheck/reviewers/c9-opus/p1-dotdot.test.mts). Where the whole
// path is there, the kernel's own answer (realpath(3)) must be the same, or it counts as a link
// that cannot be followed. Where a part is not there, the rest is taken as its text says; a `..`
// after a missing name a call could make into a link is a link that cannot be followed.
function settle(p: string, rwDirs: string[], replaceable = (link: string) => rwDirs.some((d) => within(link, d))): { real: string; link?: string } {
  let at = "/";
  let rest = (p.startsWith("/") ? p : `${process.cwd()}/${p}`).split("/").filter(Boolean);
  let hops = 0;
  while (rest.length) {
    const part = rest.shift()!;
    if (part === ".") continue;
    if (part === "..") {
      at = path.dirname(at);
      continue;
    }
    const next = path.join(at, part);
    let st: fs.Stats;
    try {
      st = fs.lstatSync(next);
    } catch {
      const real = path.join(next, ...rest);
      return rest.includes("..") && replaceable(next) ? { real, link: next } : { real };
    }
    if (!st.isSymbolicLink()) {
      at = next;
      continue;
    }
    if (replaceable(next) || ++hops > 40) return { real: path.join(next, ...rest), link: next };
    let text: string;
    try {
      text = fs.readlinkSync(next);
    } catch {
      return { real: path.join(next, ...rest), link: next };
    }
    if (text.startsWith("/")) at = "/";
    rest = [...text.split("/").filter(Boolean), ...rest];
  }
  try {
    if (fs.realpathSync.native(p) !== at) return { real: at, link: at };
  } catch {
    // gone meanwhile: what was walked stands
  }
  return { real: at };
}
// Where a path git names leads, every link on the way followed as the kernel follows it.
// (decide.ts too, for `core.hooksPath` and `core.worktree`: eleventh pass.)
export function located(p: string): string {
  return settle(p, [], () => false).real;
}

interface Protected {
  ro: string[];
  // The directories whose links linkedInto follows (council round 3), walked together by the
  // caller: a chain from one protected directory through another is held there.
  linkTops?: string[];
  pin: string[];
  problems: string[];
  // Git directories the call may write that lie inside one that is read-only whole (gitPaths).
  reopen?: string[];
  // The git directories that are read-only whole for the call (gitPaths).
  whole?: string[];
  // Paths that are not there and must not appear while the call runs (Plan.gitWatch).
  watch?: string[];
  // The links directly in a hooks directory that gitPaths judged (hookLinks): linksOut leaves them.
  judged?: string[];
}

// The script a hook that is a symbolic link runs, where the link has the one shape whose end can
// be held (tenth pass, the maintainer's decision "protect the script"): it lies directly in a
// hooks directory, and its text names a regular file inside `own` (the project and the allowed
// paths) that has no other name, reached through no symbolic link at all: the hooks directory is
// where it lies, and none of the names of the link's text is a link (so none of the directories
// above the file is: each is the hooks directory's, or one of those names). The kernel's own
// answer (realpath(3) of the link) must then be the path its text names. That file is made
// read-only like the hook (gitPaths); a call could otherwise rewrite what the hook runs, at the
// next commit of whoever commits, outside the sandbox. Undefined for any other shape: the link then asks.
// (Council: a `..` may step out of a directory a call could replace with a link, which then
// decides where the rest of the path goes: `../../tools/sub/../pc`. Only one that stays where it
// is passes: the hooks directory or a directory above it, which the plan pins as the way to a
// protected path, or a directory above the script, pinned once the script is made read-only.)
function hookScript(link: string, own: string[]): string | undefined {
  try {
    // (`link` lies in a hooks directory protect gave: where it lies, with no link on the way.)
    const dir = path.dirname(link);
    const text = fs.readlinkSync(link);
    let at = text.startsWith("/") ? "/" : dir;
    const left: string[] = [];
    for (const part of text.split("/").filter(Boolean)) {
      if (part === ".") continue;
      if (part === "..") {
        left.push(at);
        at = path.dirname(at);
        continue;
      }
      at = path.join(at, part);
      if (fs.lstatSync(at).isSymbolicLink()) return undefined;
    }
    const st = fs.lstatSync(at);
    if (!st.isFile() || st.nlink > 1 || fs.realpathSync.native(link) !== at) return undefined;
    if (left.some((d) => !within(dir, d) && !within(at, d))) return undefined;
    return own.some((d) => within(at, d)) ? at : undefined;
  } catch {
    return undefined;
  }
}

// Where a path leads as the kernel walks it (each link followed before a `..` after it), with
// every symbolic link met on the way; `missing` when a step does not exist (the rest joined on),
// with `gap` the first step that does not: a `..` after it is taken by text here, where the kernel
// would follow whatever a command puts there first (council round 6).
// Undefined for a walk that cannot be done (a link that cannot be read, more than 40 links, a
// file with more of the path after it).
function walkLinks(abs: string): { at: string; links: string[]; missing: boolean; gap?: string; left: string[] } | undefined {
  const links: string[] = [];
  // (The directories a `..` steps out of: one a command can replace with a link decides where the
  // `..` goes. Council round 8.)
  const left: string[] = [];
  const rest = abs.split("/").filter((s) => s !== "" && s !== ".");
  let cur = "/";
  for (let hops = 0; rest.length; ) {
    const part = rest.shift()!;
    if (part === "..") {
      left.push(cur);
      cur = path.dirname(cur);
      continue;
    }
    const next = path.join(cur, part);
    let st: fs.Stats;
    try {
      st = fs.lstatSync(next);
    } catch {
      return { at: path.join(next, ...rest), links, missing: true, gap: next, left };
    }
    if (!st.isSymbolicLink()) {
      // (A file with more of the path after it: the kernel refuses the path, and a command that
      // replaces the file decides where it goes. Council round 7.)
      if (rest.length && !st.isDirectory()) return undefined;
      cur = next;
      continue;
    }
    if (++hops > 40) return undefined;
    links.push(next);
    let text: string;
    try {
      text = fs.readlinkSync(next);
    } catch {
      return undefined;
    }
    rest.unshift(...text.split("/").filter((s) => s !== "" && s !== "."));
    if (text.startsWith("/")) cur = "/";
  }
  return { at: cur, links, missing: false, left };
}

// The symbolic links below `dir` at any depth (links are not followed), and with `hardLinks` the
// regular files there that have another name; undefined past `limit` directories. Only links and
// directories are looked at closer (and files, for `hardLinks`): a large `node_modules` is cheap.
// `unlisted`: directories that could not be listed (council round 6: what they hold is unseen).
function linksBelow(dir: string, hardLinks: boolean, limit = 100_000): { links: string[]; hard: string[]; unlisted: string[] } | undefined {
  const links: string[] = [];
  const hard: string[] = [];
  const unlisted: string[] = [];
  const queue = [dir];
  for (let seen = 0; queue.length; ) {
    if (++seen > limit) return undefined;
    const at = queue.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(at, { withFileTypes: true });
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") unlisted.push(at);
      continue;
    }
    for (const e of entries) {
      const p = path.join(at, e.name);
      if (e.isSymbolicLink()) links.push(p);
      else if (e.isDirectory()) queue.push(p);
      else if (hardLinks && e.isFile()) {
        try {
          if (fs.lstatSync(p).nlink > 1) hard.push(p);
        } catch {
          // gone
        }
      }
    }
  }
  return { links, hard, unlisted };
}

// Council round 3: the links inside a directory that is read-only because opencode or a git hook
// runs what it holds (`.opencode/`, `.claude/`, `.agents/`, `.husky/`, `.lefthook/`: `tops`, the
// project's own). A link there cannot be changed, but where it leads can:
// `.opencode/plugin/x.ts -> ../../tools/x.ts` left `tools/x.ts` writable to every call, and
// opencode loaded it at its next start. Round 7, after four rounds of holes in a walk that
// followed links from directory to directory: one level, and what cannot be vouched for asks.
// - A file inside one of `tops` with another name (a hard link) asks, whether a link leads to it
//   or not (round 8), under `node_modules` too (round 10): bun and pnpm install from their
//   stores by hard links, and the project's own `node_modules` usually shares them. The message
//   says how to reinstall them as copies.
// - A link to a place inside one of `tops` is held there already.
// - A link to a file: one with another name (a hard link) asks, wherever it lies; one inside a
//   writable directory (the temp directories always count: the rules let the edit tool write
//   there) is made read-only.
// - A link to a directory: one that is or holds a directory a command can write (`../..`, the
//   project's top, /var) asks. Any other is listed once, not followed further: a symbolic link
//   in it, a file with another name, a directory that cannot be listed or too many asks. One
//   inside a writable directory is then made read-only.
// - A link whose walk leads through another link a command could replace, through a file with
//   more of the path after it, out of a directory with a `..` that a command could replace with
//   a link (round 8), or to a place not there yet whose first missing step a command could make,
//   asks; so does a link the check cannot follow.
// Every call asks while one of these stands, naming it. More asks in setups that link shared
// folders with links of their own, for a rule small enough to check by reading it.
const LINKED_DIRS = 64;
function linkedInto(tops: string[], rwDirs: string[]): { ro: string[]; problems: string[] } {
  const ro: string[] = [];
  const problems: string[] = [];
  if (!tops.length) return { ro, problems };
  const writable = [...rwDirs, ...["/tmp", "/var/tmp", os.tmpdir()].map(realpath)];
  const insideRw = (p: string) => writable.some((d) => within(p, d));
  const held = tops.map(realpath);
  const isHeld = (p: string) => held.some((h) => within(p, h));
  const listed = new Set<string>();
  // Why a hard-linked file asks. (Council round 10, the user's decision: no exception for
  // `node_modules`. bun and pnpm install a package by hard links from their stores, and the
  // project's own `node_modules` usually holds the same files, so a call could rewrite what
  // opencode loads through them. Reinstalled as copies, the files have one name each.)
  // (Where to install again: the directory that holds the outermost `node_modules` below the
  // protected directory, for pnpm's `.pnpm/<pkg>/node_modules/<pkg>` and nested installs alike.)
  const installDir = (f: string): string | undefined => {
    const h = held.find((d) => within(f, d));
    if (h === undefined) return undefined;
    const rel = path.relative(h, f).split("/");
    const at = rel.indexOf("node_modules");
    return at < 0 ? undefined : path.join(h, ...rel.slice(0, at));
  };
  // (`where`: what to say of the file's place, right after its name.)
  const hardWhy = (f: string, where = ""): string => {
    const dir = installDir(f);
    return dir !== undefined
      ? `${f}${where} has more than one name (hard links), as bun and pnpm install a package from their store, which the project's own node_modules usually shares: a call can rewrite it through another name. In ${dir}, remove node_modules and install again as copies (\`bun install --backend=copyfile\`, or pnpm with \`--package-import-method=copy\`)`
      : `${f}${where} has more than one name (hard links): it can be rewritten through another one`;
  };
  for (const top of held) {
    const below = linksBelow(top, true);
    if (!below) {
      problems.push(`${top} holds too many directories to look for symbolic links among them`);
      continue;
    }
    for (const d of below.unlisted) problems.push(`${d} cannot be listed, in ${top}, which opencode or a git hook runs from: a link in it could lead anywhere`);
    // (Round 8: a file there with another name can be rewritten through that name.)
    for (const f of below.hard) problems.push(hardWhy(f, `, in ${top}, which opencode or a git hook runs from,`));
    for (const link of below.links) {
      const w = walkLinks(link);
      if (!w) {
        problems.push(`${link} is a symbolic link the check cannot follow, in a directory opencode or a git hook runs from`);
        continue;
      }
      const swappable = w.links.find((l) => insideRw(l) && !isHeld(l));
      if (swappable) {
        problems.push(`${link} leads through the symbolic link ${swappable}, which a command could replace: what opencode or a git hook runs through it cannot be protected`);
        continue;
      }
      // (Round 8: a directory a `..` steps out of that a command could replace with a link, so
      // that the `..` goes elsewhere. Not one that is read-only, a writable root itself, or a
      // parent of a protected directory: those are pinned. A parent of the target is pinned too
      // when the target is made read-only, below.)
      const loose = w.left.filter((d) => insideRw(d) && !isHeld(d) && !writable.includes(d) && !held.some((h) => within(h, d)));
      const swapped = `${link} steps out of ${loose[0]} with a \`..\`, a directory a command could replace with a link to send the rest of the path elsewhere`;
      if (w.missing) {
        if (loose.length) problems.push(swapped);
        else if (insideRw(w.gap!) && !isHeld(w.gap!)) problems.push(`${link} leads to ${w.at}, which is not there, and ${w.gap} lies in a directory a command can write: a command could put what opencode or a git hook runs there`);
        continue;
      }
      const st = fs.lstatSync(w.at);
      if (isHeld(w.at)) {
        if (loose.length) problems.push(swapped);
        else if (st.isFile() && st.nlink > 1) problems.push(`${link} leads to a file opencode or a git hook runs: ${hardWhy(w.at)}`);
        continue;
      }
      if (st.isDirectory()) {
        if (writable.some((d) => within(d, w.at))) {
          problems.push(`${link} leads to ${w.at}, which is or holds a directory a command can write: what opencode or a git hook loads through it cannot be held read-only`);
          continue;
        }
        if (!listed.has(w.at)) {
          listed.add(w.at);
          if (listed.size > LINKED_DIRS) {
            problems.push(`the directories opencode or a git hook runs from link to more than ${LINKED_DIRS} directories, too many to look at`);
            continue;
          }
          const inner = linksBelow(w.at, true);
          const why = !inner
            ? "holds too many directories to look at"
            : inner.unlisted.length
              ? `holds ${inner.unlisted[0]}, which cannot be listed`
              : inner.links.length
                ? `holds the symbolic link ${inner.links[0]}, which is not followed this far`
                : inner.hard.length
                  ? `holds ${inner.hard[0]}, which has another name (a hard link)`
                  : undefined;
          if (why) {
            problems.push(`${link} leads to the directory ${w.at}, which ${why}: what opencode or a git hook loads through it cannot be protected`);
            continue;
          }
        }
      } else if (st.nlink > 1) {
        // (A file with another name asks wherever it lies: the other name may be in the project.)
        problems.push(`${link} leads to ${w.at}, which has ${st.nlink} hard links: it can be rewritten through another name`);
        continue;
      }
      const kept = insideRw(w.at);
      if (loose.some((d) => !(kept && within(w.at, d)))) problems.push(swapped);
      else if (kept) ro.push(w.at);
    }
  }
  return { ro, problems };
}

// The regular files below `dir` (or `dir` itself, a file), at any depth, to `limit` entries:
// undefined past it.
function filesBelow(dir: string, limit = 10_000): string[] | undefined {
  const out: string[] = [];
  let seen = 0;
  const visit = (at: string): boolean => {
    let st: fs.Stats;
    try {
      st = fs.lstatSync(at);
    } catch {
      return true;
    }
    if (++seen > limit) return false;
    if (st.isFile()) out.push(at);
    if (!st.isDirectory()) return true;
    let names: string[];
    try {
      names = fs.readdirSync(at);
    } catch {
      return true;
    }
    return names.every((name) => visit(path.join(at, name)));
  };
  return visit(dir) ? out : undefined;
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
  // The shared directories: every writable one that is not the project's or an allowed path's
  // (the temp directories and `sandboxWritable`). Every program on the machine writes them.
  const shared = rwDirs.filter((d) => !own.some((o) => within(d, o)));
  const sharedPlace = (p: string) => !own.some((o) => within(p, o)) && shared.some((d) => within(p, d));
  // What the checks of the hooks, config and info/ git reads for a git directory (`place`) find:
  // said wherever the file lies, unless the git directory lies in a shared directory, where it
  // is said only for a file in the project or an allowed path, as before (eleventh pass: keyed
  // to where the file lies, a hook of a bare repository beside the project, outside every
  // writable directory, hard-linked to the project's script, was found and dropped, and so was
  // an included file outside the project; run by a reviewer, xcheck/reviewers/c10-opus/
  // r1-outside.test.mts).
  const sayFor = (place: string) => (text: string, at: string) => (sharedPlace(place) ? problems.push(text, at) : void all.push(text));
  for (const link of found.links) problems.push(`${link} is a symbolic link, which cannot be made read-only: a command could point it at a repository of its own making`, link);
  // A path that must stay as it is. `create`: it must exist too, and is made when that is safe.
  // What was made read-only, by where it lies. `missing`: where one that does not exist is said
  // (an included config file: for the config that includes it, a shared temp directory too).
  const protect = (p: string, what: string, create = false, missing: (text: string, at: string) => void = problems.push): string | undefined => {
    const { real, link } = settle(p, rwDirs);
    if (link) return void problems.push(`${what} ${p} leads through the symbolic link ${link}, which a command could replace`, link);
    if (!insideRw(real) && !insideRw(realpath(path.dirname(real)))) return; // not writable: nothing to plant
    if (!lexists(real)) {
      if (!create) return void missing(`${what} ${p} does not exist inside a writable directory, so it cannot be protected`, real);
      if (!own.some((d) => within(real, d))) return; // nothing is created in a shared temp directory
      if (!ensureDir(real, rwDirs)) return void problems.push(`${what} ${p} does not exist and could not be created safely`, real);
    }
    ro.push(real);
    return real;
  };
  // The links directly in a hooks directory git runs from (`dir`, where it lies): one that
  // leads to a script of the project (hookScript) has the script made read-only, pinned like a
  // hook; any other asks, whatever it leads to, for every call (tenth pass: judged by where it
  // ends, it was judged by its text). Each is `judged`: linksOut does not say it again. Every
  // such directory, wherever it lies, whether or not the plan could make it read-only (eleventh
  // pass: one outside every writable directory, your global core.hooksPath in your home, was
  // never looked at, and a link there to the project's script let a call rewrite what every
  // commit runs; run by a reviewer, xcheck/reviewers/c10-opus/r1-outside.test.mts).
  const judged = new Set<string>();
  // (Not the root directory, where git looks for hooks under an empty core.hooksPath: only root
  // can put a file or a link there, and the links it holds, `/bin` and the like, are the
  // system's and no hooks.)
  const notRoot = (dir: string) => dir !== "/";
  const hookLinks = (dir: string, say: (text: string, at: string) => void) => {
    let list: fs.Dirent[];
    try {
      list = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of list) {
      if (!e.isSymbolicLink()) continue;
      const link = path.join(dir, e.name);
      judged.add(link);
      const script = hookScript(link, own);
      if (script) ro.push(script);
      else say(`${link} is a symbolic link among the hooks in ${dir}, and not one that leads straight to a script of the project with no other link on the way and no other name: what git runs through it cannot be protected`, link);
    }
  };
  // A file git reads or runs from a git directory that is read-only for the call, with another
  // name (a hard link): what the read-only mount holds can be rewritten through that name, which
  // may lie where the call writes (tenth pass, the maintainer's decision "ask on hard links"; a
  // hook hard-linked to `scripts/pre-commit` was rewritten by any call, run by a reviewer,
  // xcheck/reviewers/c9-sonnet/x9-hardlink.test.mts). A call cannot make one across the mount
  // (EXDEV); only one that is there already matters. git's own files with more than one name
  // (objects and packs a `clone --local` shares, an index) are not read or run as code or settings.
  // Nor is a hook whose name ends in `.sample`, directly in a hooks directory (`hooks`): git never
  // runs one (eleventh pass, the maintainer's decision "skip .sample"; a `cp -al` copy of a
  // repository made every call in either ask for them; run by a reviewer, xcheck/reviewers/
  // c10-sonnet/out10/cpal.log). Its `config` and `info/exclude` with two names still ask.
  const hardLinked = (paths: string[], what: string, say: (text: string, at: string) => void, hooks: string[]) => {
    for (const p of paths) {
      const files = filesBelow(p);
      if (!files) {
        say(`${p} holds too many entries to look for hard links among them`, p);
        continue;
      }
      for (const file of files) {
        if (file.endsWith(".sample") && hooks.includes(path.dirname(file))) continue;
        try {
          const links = fs.lstatSync(file).nlink;
          if (links > 1) say(`${file} (${what}) has ${links} hard links: what git reads or runs from it can be rewritten through another name, which may lie where the call can write`, file);
        } catch {
          // gone
        }
      }
    }
  };
  // (Twelfth pass: what git could not list, and a conditional include that sets core.hooksPath,
  // are said for the git directory, `say`, as everything else of it is; keyed to the config
  // file they were dropped for a git directory outside every writable directory, C11's reading F3.)
  const listing = (configFile: string, say: (text: string, at: string) => void) => {
    const failed: string[] = [];
    const tree = includeTree(configFile, failed);
    for (const text of failed) say(text, configFile);
    conditionalHooks(tree, say);
    return tree.map((i) => i.file);
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
    // What is found among them is said unless this git directory lies in a shared directory.
    const say = sayFor(gitDir);
    // The hooks directories of this repository, where they lie: the ones that are protected
    // (`held`), and every one git runs from (`located`), wherever it lies, whether or not it
    // could be made read-only here (it is not writable). Their links and hard links are looked
    // at below.
    const runFrom = new Set<string>();
    const held = (real: string | undefined) => {
      if (real !== undefined) runFrom.add(real);
    };
    if (insideRw(gitDir) && lexists(gitDir) && (ownHooks || lexists(hooks))) held(protect(hooks, "the hooks directory", ownHooks));
    if (ownHooks && lexists(gitDir)) runFrom.add(located(hooks));
    // Keep the specific unreadable include path ahead of a failed effective-config lookup.
    const includes = [...listing(path.join(gitDir, "config"), say), ...listing(path.join(gitDir, "config.worktree"), say)];
    // (One that is not there yet is said as the rest of the git directory is, in a shared temp
    // directory too: a call could make it there, and git would read it, conditional or not
    // (thirteenth pass; Sonnet's C12 F-2, run: a call wrote the hook, the next made the include
    // that names it, and your commit ran it).)
    for (const file of includes) protect(file, "git config includes", false, say);
    // A relative core.hooksPath is resolved by git in whichever worktree it runs: every one of
    // them is protected, so a pointer file planted elsewhere cannot draw the protection away.
    // The value is the one git uses in this repository (`configured`).
    const failed: string[] = [];
    const hooksPath = hooksPathOf(gitDir, failed);
    if (hooksPath !== undefined) {
      for (const top of tops) {
        const dir = hooksDir(hooksPath, top);
        if (dir === undefined) continue;
        held(protect(dir, "core.hooksPath", true));
        runFrom.add(located(dir));
      }
      // A value git expands in a way that is not followed here names a directory nobody looked
      // at: it may lie in the project, where every call can write (eighth pass; a user's own
      // `~<name>/` leads into their home directory). Giving up is a verdict: the call asks.
      if (hooksDir(hooksPath, gitDir) === undefined) say(unfollowedHooks(hooksPath, gitDir), gitDir);
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
    const pushDir = receiving !== undefined && !absoluteHooks(receiving) ? hooksDir(receiving, gitDir) : undefined;
    const pushHooks = pushDir === undefined ? undefined : located(pushDir);
    // (The receiving git may read another value than the one above: `configured`.)
    if (receiving !== undefined && receiving !== hooksPath && hooksDir(receiving, gitDir) === undefined) say(unfollowedHooks(receiving, gitDir), gitDir);
    for (const text of new Set(failed)) say(text, gitDir);
    if (pushHooks !== undefined && pushHooks !== gitDir) {
      if (lexists(pushHooks)) {
        held(protect(pushDir!, "core.hooksPath for a push into the repository"));
        runFrom.add(pushHooks);
      }
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
      // The outermost of them here: a git directory the call may write inside another is a
      // mount of its own (a pin), which keeps the read-only flag it got with the directory
      // around it, and `plan` makes every such pin writable again with the directory it lies in
      // (eighth pass: `git -C inner add` from the outer module failed on `index.lock`), unless
      // it lies in a path that is read-only there. Naming the inner ones here as well opened one
      // that lies under the outer one's `hooks/` (ninth pass).
      ro.push(gitDir);
      whole.push(gitDir);
      reopen.push(...inside.filter((w) => !inside.some((o) => o !== w && within(w, o))));
    } else if (own.some((d) => within(gitDir, d))) {
      // No repository, only named as one (a `.git` file that points at a directory around the
      // call's repository): it is not granted, and cannot be read-only around it either.
      all.push(`${gitDir} is named as a git directory and holds the repository this call works in (${inside[0]}), so it cannot be kept read-only around it`);
    } else {
      ro.push(gitDir);
      whole.push(gitDir);
    }
    const looked = [...runFrom].filter(notRoot);
    for (const dir of looked) hookLinks(dir, say);
    // What git reads or runs from a git directory that is read-only for the call: no file of it
    // may have another name. (A call that may write the directory is a git-only call, and git
    // writes a work tree's files anew, never in place through another name.)
    if (!selected(gitDir)) hardLinked([...looked, path.join(gitDir, "config"), path.join(gitDir, "config.worktree"), ...includes.map(located), path.join(gitDir, "info")], `read or run by git for ${gitDir}`, say, looked);
  }
  if (globalHooks && absoluteHooks(globalHooks)) {
    const real = protect(expandGitPath(globalHooks, HOME), "your global core.hooksPath", true);
    // Where git runs every repository's hooks from, wherever it lies (eleventh pass): its links
    // and hard links are said whatever place it is, a shared directory too, since git runs it
    // for every repository.
    const runFrom = [...new Set([...(real === undefined ? [] : [real]), located(hooksDir(globalHooks, HOME) ?? expandGitPath(globalHooks, HOME))])].filter(notRoot);
    const say = (text: string) => void all.push(text);
    for (const dir of runFrom) hookLinks(dir, say);
    hardLinked(runFrom, "your global core.hooksPath", say, runFrom);
  }
  // Your own config, and the system's (thirteenth pass: Opus's C12 F3 and Sonnet's F-3, run: an
  // `includeIf "onbranch:…"` there set a hooks path in the project unseen): what they include is
  // protected, and a listing git cannot give, a conditional hooks path or an include that is not
  // there yet counts wherever the file is.
  const globalProblems: string[] = [];
  const sayGlobal = (text: string) => void globalProblems.push(text);
  const system = systemGitConfig();
  const systemIncludes = system === undefined ? [] : includeTree(system, globalProblems);
  const globals = globalGitConfigs();
  const globalIncludes = globals.flatMap((file) => includeTree(file, globalProblems));
  // (The closing reading, step 7 F1: the file itself too, where a call could write it, as git
  // reads it for every command run outside the sandbox.)
  for (const file of globals) if (lexists(file)) protect(file, "your git config", false, sayGlobal);
  for (const { file } of globalIncludes) protect(file, "your git config includes", false, sayGlobal);
  for (const { file } of systemIncludes) protect(file, "the system git config includes", false, sayGlobal);
  conditionalHooks([...globalIncludes, ...systemIncludes], sayGlobal);
  // Hook managers, at the top of every checkout.
  const tops = [...found.tops.values()].flatMap((set) => [...set]);
  // (Council round 3: where the links in the hook managers' directories lead, below.)
  const managerDirs: string[] = [];
  for (const top of new Set([...tops, ...searchDirs.filter((d) => !["/tmp", "/var/tmp", realpath(os.tmpdir())].includes(d))])) {
    for (const name of HOOK_MANAGER_FILES) {
      const p = path.join(top, name);
      if (!lexists(p)) continue;
      const real = protect(p, "the hook manager file");
      if (real !== undefined && isDir(real)) managerDirs.push(real);
    }
  }
  return { linkTops: managerDirs, ro: [...new Set(ro)].filter(lexists), pin: [...new Set(pin)], problems: [...all, ...globalProblems], reopen: [...new Set(reopen)], watch: [...new Set(watch)], whole: [...new Set(whole)], judged: [...judged] };
}

// The symbolic links inside a git directory, at any depth (ninth pass: the eighth looked at the
// top, below `modules/` and at the entries of `worktrees/`, and `.git/refs/heads` as a link into
// the project let a call in a submodule write the superproject's `main`; run by both reviewers,
// xcheck/reviewers/c8-sonnet/x8-p1d.test.mts). Every directory below `dir` is listed, down to
// each git directory of its own that the walk found (`stops`: a module's, a linked worktree's
// admin directory; each is looked at as itself, where it is read-only for the call).
// `only`: of the top, these names alone.
//
// The bound (`linkLimits`). `entries`: the directories, the links, and the files outside an
// object store that are listed. `objects`: the files below a directory named `objects` (git's
// own store, and those of lfs and annex), which are listed and passed over: a loose object or a
// pack is a file, and only a link or a directory among them matters here, so a store of any
// ordinary size costs nothing of the first bound. `depth`: how many directories down.
// `over`: what was not looked at, where a bound was passed or a directory could not be listed.
// That is a problem for the caller, not silence.
export const linkLimits = { entries: 100_000, objects: 1_000_000, depth: 40 };
function gitLinks(dir: string, stops: ReadonlySet<string>, only?: string[]): { links: string[]; over?: string } {
  const links: string[] = [];
  let entries = 0;
  let objects = 0;
  let over: string | undefined;
  const visit = (at: string, depth: number, store: boolean) => {
    let list: fs.Dirent[];
    try {
      list = fs.readdirSync(at, { withFileTypes: true });
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      // Gone since it was listed, or no directory at all (the top of a git directory that is not there).
      if (code !== "ENOENT" && code !== "ENOTDIR") over ??= `${at} cannot be listed (${code}), so the symbolic links in it cannot be looked for`;
      return;
    }
    for (const e of list) {
      if (over) return;
      if (at === dir && only && !only.includes(e.name)) continue;
      const p = path.join(at, e.name);
      const kept = e.isSymbolicLink() || e.isDirectory();
      if (!kept && store) {
        if (++objects > linkLimits.objects) over = `${dir} holds more than ${linkLimits.objects} objects, too many to look for symbolic links among them`;
        continue;
      }
      if (++entries > linkLimits.entries) return void (over = `${dir} holds more than ${linkLimits.entries} entries, too many to look for symbolic links among them`);
      if (e.isSymbolicLink()) links.push(p);
      else if (e.isDirectory() && !stops.has(p)) {
        if (depth >= linkLimits.depth) over = `${p} lies more than ${linkLimits.depth} directories deep in ${dir}, deeper than symbolic links are looked for`;
        else visit(p, depth + 1, store || e.name === "objects");
      }
    }
  };
  visit(dir, 0, false);
  return { links, ...(over ? { over } : {}) };
}

// A git directory that is read-only whole is a mount over the directory, and a symbolic link in
// it is not held by that: what git reads through the link lies wherever the link leads, and the
// place it leads to is not part of the mount: the superproject's refs through `.git/refs` or
// `.git/refs/heads`, a hook through `.git/hooks/pre-commit`, a module of any name through
// `.git/modules/<name>` (round 4, finding 21, eighth and ninth pass). The rule (tenth pass, the
// maintainer's decision "any link asks"): every symbolic link at any depth of such a directory
// is a problem, whatever it leads to, and the call asks. Nothing is judged by where a link goes:
// judged so, link by link, by the text of each, `<outside>/lnk/../d` was taken for a place
// outside where the kernel goes into the project (run by a reviewer, xcheck/reviewers/c9-opus/
// p1-dotdot.test.mts), and before that a chain was taken for its end (c8-opus). What it costs:
// a repository whose objects, refs or logs are a link to a store elsewhere asks for every call
// that has it read-only (every call that is not git-only in it, and a call in its submodules).
// The one exception is a hook that is a link to a script of the project (`judged`: gitPaths
// makes the script read-only, and says every other link among the hooks itself).
// A link in a git directory the call may write (a git-only call in its own repository) is the
// call's own, as the rest of that directory is, and not looked at here. Where only some names of
// a directory are closed (`only`: a linked worktree's common directory, of which `modules/` and
// `worktrees/` are), a link below them asks the same.
// `dirs`: the directories to look in, each whole or for the names `only`. `stops`: the git
// directories the walk found. `own`: the caller's own directories (the project and the allowed
// paths). `shared`: the temp directories, which every program on the machine writes: a git
// directory there is left, as everything else in such a repository that cannot be protected is
// (gitPaths); whatever a call could do through a link of it, it can do there anyway. One outside
// every writable directory (the main checkout of a linked worktree that is the project) is
// read-only for every call, and its links ask like any other; so does passing the bound there
// (eleventh pass: said only for the caller's own directories, a link past it in a bare
// repository beside the project went unseen and unsaid; run by a reviewer,
// xcheck/reviewers/c10-opus/r1-outside.test.mts).
function linksOut(dirs: { dir: string; only?: string[] }[], stops: ReadonlySet<string>, own: string[], shared: string[], judged: ReadonlySet<string>): string[] {
  const out: string[] = [];
  const owned = (p: string) => own.some((d) => within(p, d));
  for (const { dir, only } of dirs) {
    if (!owned(dir) && shared.some((d) => within(dir, d))) continue;
    const { links, over } = gitLinks(dir, stops, only);
    if (over) out.push(over);
    for (const link of links) if (!judged.has(link)) out.push(`${link} is a symbolic link in a git directory that is read-only for this call: what git reads or runs through it lies wherever the link leads, which the sandbox does not hold, so it cannot be protected`);
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
    const dir = hooksDir(hooksPath, gitDir);
    const pushHooks = dir === undefined ? undefined : located(dir);
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
  const named = hooksPath == null ? path.join(common, "hooks") : hooksDir(hooksPath, gitDir);
  const dir = named === undefined ? undefined : located(named);
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
  const held: string[] = [];
  for (const dir of dirs) {
    for (const name of OPENCODE_PROJECT_FILES) {
      const p = path.join(dir, name);
      if (isSymlink(p)) problems.push(`${p} is a symbolic link and cannot be protected`);
      else if (lexists(p)) ro.push(p);
      else if (name === ".opencode" && dir === dirs[0] && ensureDir(p, rwDirs)) ro.push(p);
      else continue;
      if (!isSymlink(p) && isDir(p)) held.push(p);
    }
  }
  // (Council round 3: where the links in `.opencode/`, `.claude/` and `.agents/` lead: the
  // caller walks them with the hook managers' directories, linkedInto.)
  return { ro, pin: [], problems, linkTops: held };
}

// Code caches in the temp directories (council project review 1): Node's compile cache, which
// tsc and tsserver turn on themselves, tsx's, jiti's, v8-compile-cache's (yarn 1, older eslint)
// and Jest's. A later node outside the sandbox
// runs what they hold, checked against its source by little more than its length. Each gets a
// private, empty tmpfs for the call, and one that is missing is made first, so that a call
// cannot make it.
const UID = process.getuid?.() ?? 0;
export const TEMP_CODE_CACHES = ["node-compile-cache", `tsx-${UID}`, "jiti", `v8-compile-cache-${UID}`, `jest_${UID.toString(36)}`];
function codeCaches(rwDirs: string[]): { tmpfs: string[]; problems: string[] } {
  const tmpfs: string[] = [];
  const problems: string[] = [];
  const cover = (p: string, roots: string[]) => {
    if (isSymlink(p) || (lexists(p) && !isDir(p))) problems.push(`${p}, where node keeps code it runs later, is not a directory and cannot be covered`);
    else if (!lexists(p) && !ensureDir(p, roots)) problems.push(`${p}, where node keeps code it runs later, does not exist and could not be made`);
    else tmpfs.push(p);
  };
  for (const temp of new Set(["/tmp", "/var/tmp", os.tmpdir()].map(realpath))) {
    if (!isDir(temp)) continue;
    for (const name of TEMP_CODE_CACHES) cover(path.join(temp, name), [temp]);
  }
  // (Round 2: NODE_COMPILE_CACHE in opencode's environment moves Node's cache: where it lies in a
  // writable directory, it is covered the same way. A relative one lies where node runs.)
  const moved = process.env.NODE_COMPILE_CACHE;
  if (moved && !path.isAbsolute(moved)) problems.push(`NODE_COMPILE_CACHE (${moved}) is relative: where node keeps code it runs later cannot be covered`);
  else if (moved) {
    const at = path.join(realpath(path.dirname(path.resolve(moved))), path.basename(path.resolve(moved)));
    // (Round 3: one that is a writable root itself, `/tmp` say, cannot be covered whole: it asks.)
    if (rwDirs.includes(at)) problems.push(`NODE_COMPILE_CACHE (${moved}) is a directory every call can write, where node keeps code it runs later: it cannot be covered`);
    else if (rwDirs.some((d) => within(at, d))) cover(at, rwDirs);
  }
  return { tmpfs: [...new Set(tmpfs)], problems };
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
  // (Round 8: opencode's directories in the writable parents a call has, temp ones included, as
  // the plan has them.)
  const opencode = opencodePaths(o.project, [...new Set([...searchDirs, ...["/tmp", "/var/tmp", os.tmpdir()].map(realpath)])]);
  // An edit asks where a call would (ninth pass).
  const links = linksOut((git.whole ?? []).map((dir) => ({ dir })), found.gitDirs, searchDirs, ["/tmp", "/var/tmp", os.tmpdir()].map(realpath), new Set(git.judged));
  const linked = linkedInto([...(git.linkTops ?? []), ...(opencode.linkTops ?? [])], searchDirs);
  return { paths: [...git.ro, ...opencode.ro, ...linked.ro], problems: [...found.problems, ...git.problems, ...links, ...opencode.problems, ...linked.problems] };
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
  // (Of the hook managers' directories, only the project's own: a checkout in a temp directory is
  // not this project's matter, and its links could otherwise make every call here ask. opencode's
  // directories are the session's and its writable parents', temp ones included: round 8.)
  const followed = linkedInto([...(git.linkTops ?? []).filter((t) => own.some((o) => within(t, o))), ...(opencode.linkTops ?? [])], rwDirs);
  const ro = [...new Set([...git.ro, ...opencode.ro, ...followed.ro, ...closed])];
  const caches = codeCaches(rwDirs);
  const tmpfs = ["/dev/shm", ...caches.tmpfs];
  const problems = [...found.problems, ...lookupProblems, ...git.problems, ...opencode.problems, ...followed.problems, ...caches.problems];
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
  for (const p of [...ro, ...git.pin, ...hide, ...caches.tmpfs]) {
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
  // A link in a git directory that is read-only for the call, on the way to a place it may write
  // (linksOut). The shared directories it leaves are the writable ones that are not the
  // project's nor an allowed path's: the temp directories and `sandboxWritable` (the cache
  // directories). An allowed path counts as the project: a git directory there is walked.
  problems.push(...linksOut([...(git.whole ?? []).map((dir) => ({ dir })), ...[...shutIn].map(([dir, only]) => ({ dir, only }))], found.gitDirs, own, rwDirs.filter((d) => !own.some((o) => within(d, o))), new Set(git.judged)));
  const unexpressible = [...rwDirs, ...ro, ...reopen, ...pins, ...hide, ...tmpfs].filter((p) => !usable(p));
  if (unexpressible.length) problems.push(`cannot protect a path containing a newline (${JSON.stringify(unexpressible[0])})`);
  for (const [name, paths] of [["RW", rwDirs], ["RO", ro], ["REOPEN", reopen], ["PIN", pins], ["HIDE", hide], ["TMPFS", tmpfs]] as const) {
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
    tmpfs: tmpfs.filter(usable),
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
// default one). `GIT_NO_REPLACE_OBJECTS` changes which commit a ref names. `HOME` and
// `XDG_CONFIG_HOME` are where git finds its global configuration when `GIT_CONFIG_GLOBAL` is not
// set (council round 1: a session `HOME` in the project, with a `.gitconfig` the session wrote
// there, ran its `core.fsmonitor` from an allowed `git status`).
const GIT_ELSEWHERE = /^GIT_(DIR|WORK_TREE|INDEX_FILE|COMMON_DIR|OBJECT_DIRECTORY|ALTERNATE_OBJECT_DIRECTORIES|NAMESPACE|CONFIG|CONFIG_COUNT|CONFIG_KEY_\d+|CONFIG_VALUE_\d+|CONFIG_PARAMETERS|EXEC_PATH|SHALLOW_FILE|GRAFT_FILE|REPLACE_REF_BASE|ATTR_SOURCE|IMPLICIT_WORK_TREE)$/;
const GIT_ELSEWHERE_IF_OTHER = /^(GIT_(CONFIG_GLOBAL|CONFIG_SYSTEM|CONFIG_NOSYSTEM|CEILING_DIRECTORIES|DISCOVERY_ACROSS_FILESYSTEM|NO_REPLACE_OBJECTS)|HOME)$/;
// (`XDG_CONFIG_HOME` unset is `$HOME/.config`: the directory each git would use is compared.)
const xdgConfig = (env: Record<string, string | undefined>) => env.XDG_CONFIG_HOME || (env.HOME === undefined ? undefined : path.join(env.HOME, ".config"));
// The first such variable in the environment a shell is about to be given (`own`: this
// process's), or undefined. One of the second group may be the shell's or this process's alone.
export function gitElsewhere(env: Record<string, string | undefined>, own: Record<string, string | undefined> = process.env): string | undefined {
  const name = [...new Set([...Object.keys(env), ...Object.keys(own)])].sort().find((name) => (GIT_ELSEWHERE.test(name) ? env[name] !== undefined : GIT_ELSEWHERE_IF_OTHER.test(name) && env[name] !== own[name]));
  return name ?? (xdgConfig(env) !== xdgConfig(own) ? "XDG_CONFIG_HOME" : undefined);
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
