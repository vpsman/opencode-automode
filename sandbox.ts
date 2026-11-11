// The sandbox plan for one auto-allowed command, handed to sandbox/lockwrite:
//   rw      directories (or device files) the command may write beneath. Everything else is
//           mounted read-only, and Landlock confines writes to these as well.
//   ro      paths inside them that are bind-mounted read-only: whole git directories for
//           ordinary commands; for pure git commands only their hooks and config; `.git`
//           pointer files; core.hooksPath directories; files git config includes; hook-manager
//           files; the project's opencode config
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
  rw: string[];
  ro: string[];
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
  // A pure git command (see gitOnly in decide.ts) may write inside git directories.
  gitWritable: boolean;
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
  problems: string[];
}

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

// The rules' credential test resolves the path on disk, which is too slow to run on every entry
// of a large tree. This cheap test picks the entries worth asking it about. It is broader than
// the rules on purpose (any dotfile, anything with "key", "secret" or "credential" in its name,
// anything inside a dot-directory); test/sandbox.test.mts checks that it lets through every
// kind of name the rules know.
const MAYBE_SECRET = /^(\.|id_)|key|secret|credential|service|\.(pem|p12|pfx|jks|kdbx)$/i;
const SECRET_PARENT = /^(\..*|gh|gcloud|op|keyrings|Keychains)$/;
export const maybeSecret = (name: string, parent: string) => MAYBE_SECRET.test(name) || SECRET_PARENT.test(parent);

function scanRoot(root: string, skip: Set<string>, found: Found, secrets: boolean, writable: boolean) {
  const uid = process.getuid?.() ?? -1;
  const started = Date.now();
  let entries = 0;
  let stopped = false;
  const addGitDir = (gitDir: string, top: string) => {
    found.gitDirs.add(gitDir);
    if (!found.tops.has(gitDir)) found.tops.set(gitDir, new Set());
    found.tops.get(gitDir)!.add(top);
  };
  // `inGit`: below a `.git/modules`, where only the git directories of submodules matter.
  const visit = (dir: string, inGit: boolean) => {
    if (stopped) return;
    let list: fs.Dirent[];
    try {
      list = fs.readdirSync(dir, { withFileTypes: true });
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code === "ENOENT" || code === "ENOTDIR") return; // gone since it was listed
      // A directory this user owns and cannot list can still be written into: whatever is
      // planted there stays out of sight. Someone else's is closed to this user both ways.
      // Where nothing can be written (/run), only a directory that can be entered matters: a
      // socket in it could be reached without being seen.
      let own = true;
      try {
        own = fs.lstatSync(dir).uid === uid;
        if (!writable) fs.accessSync(dir, fs.constants.X_OK);
      } catch {
        own &&= writable;
      }
      if (own || code !== "EACCES") found.problems.push(`${dir} cannot be listed (${code}), so what is in it cannot be protected`);
      return;
    }
    entries += list.length;
    if (entries > limits.entries || Date.now() - started > limits.ms) {
      stopped = true;
      found.problems.push(`the scan of ${root} stopped after ${entries} entries (limit ${limits.entries} entries, ${limits.ms} ms); what lies beyond is not protected`);
      return;
    }
    const names = new Set(list.map((e) => e.name));
    const gitDirHere = names.has("HEAD") && names.has("objects") && names.has("refs") && !names.has(".git");
    if (gitDirHere) addGitDir(realpath(dir), realpath(dir)); // a bare repository, or a submodule's git directory
    for (const e of list) {
      const p = path.join(dir, e.name);
      if (inGit) {
        if (e.isDirectory() && (!gitDirHere || e.name === "modules")) visit(p, true);
        continue;
      }
      if (e.name === ".git") {
        if (e.isSymbolicLink()) {
          found.links.add(p);
          const target = realpath(p);
          if (target !== p && isDir(target)) addGitDir(target, realpath(dir));
        } else if (e.isDirectory()) {
          addGitDir(realpath(p), realpath(dir));
          visit(path.join(p, "modules"), true);
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
            addGitDir(gitdir, realpath(dir));
            try {
              found.gitDirs.add(realpath(path.resolve(gitdir, fs.readFileSync(path.join(gitdir, "commondir"), "utf8").trim())));
            } catch {
              // not a linked worktree
            }
          }
        }
        continue;
      }
      if (secrets && maybeSecret(e.name, path.basename(dir)) && isSecretPath(p)) {
        found.secrets.add(p);
        // A link named like a credential file: what it points to holds the secret.
        if (e.isSymbolicLink()) found.secrets.add(realpath(p));
        continue;
      }
      if (e.isSocket()) {
        if (reachable(p)) found.sockets.add(p);
      } else if (e.isDirectory() && !skip.has(p)) visit(p, false);
    }
  };
  visit(root, false);
}

// Everything below the given directories. `skip` holds directories that are not entered (the
// runtime directory under /run, which is covered whole).
export function discover(dirs: string[], skip: string[] = [], secretsIn: string[] = [], writable = true): Found {
  const found: Found = { gitDirs: new Set(), pointers: new Set(), links: new Set(), tops: new Map(), secrets: new Set(), sockets: new Set(), problems: [] };
  const roots = [...new Set(dirs.map(realpath))];
  // A root inside another one is walked once, as itself.
  for (const root of roots) scanRoot(root, new Set([...roots.filter((r) => r !== root), ...skip]), found, secretsIn.includes(root), writable);
  return found;
}

// Git directories and pointer files below the given directories.
export const findGitEntries = (dirs: string[]): Found => discover(dirs);

const expandGitPath = (value: string, base: string) => path.resolve(base, value.replace(/^~(?=\/|$)/, HOME));

// A repository's own core.hooksPath (repository scopes only, following includes: the overrides
// gitRun adds must not answer).
function hooksPathOf(gitDir: string): string | undefined {
  for (const scope of ["--worktree", "--local"]) {
    const v = safeGit(["--git-dir", gitDir, "config", scope, "--includes", "--get", "core.hooksPath"])?.trim();
    if (v) return v;
  }
  return undefined;
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
      if (fs.lstatSync(cur).isSymbolicLink()) return false;
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
}

// `own`: the project and the allowed paths. What cannot be protected there is a problem, and the
// command asks. The temp directories are shared with every other program on the machine: what
// exists in a repository there is made read-only, and what cannot be is left (anything can
// build a new repository in /tmp anyway; see "Known gaps").
function gitPaths(found: Found, searchDirs: string[], rwDirs: string[], gitWritable: boolean, own: string[]): Protected {
  // Build caches are not searched: they are only writable when the user opts in.
  const insideRw = (p: string) => rwDirs.some((d) => within(p, d));
  const ro: string[] = [...found.pointers];
  const pin: string[] = [];
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
  const globalHooks = safeGit(["config", "--global", "--includes", "--get", "core.hooksPath"])?.trim();
  for (const gitDir of found.gitDirs) {
    const tops = found.tops.get(gitDir) ?? new Set([path.dirname(gitDir)]);
    const hooks = path.join(gitDir, "hooks");
    if (insideRw(gitDir)) protect(hooks, "the hooks directory", true);
    // A relative core.hooksPath is resolved by git in whichever worktree it runs: every one of
    // them is protected, so a pointer file planted elsewhere cannot draw the protection away.
    const hooksPath = hooksPathOf(gitDir) ?? (globalHooks && !/^(\/|~(\/|$))/.test(globalHooks) ? globalHooks : undefined);
    if (hooksPath) for (const top of tops) protect(expandGitPath(hooksPath, top), "core.hooksPath", true);
    // Files the repository config includes are config too.
    for (const file of [...listing(path.join(gitDir, "config")), ...listing(path.join(gitDir, "config.worktree"))]) protect(file, "git config includes");
    if (gitWritable) {
      pin.push(gitDir);
      ro.push(hooks, path.join(gitDir, "config"), path.join(gitDir, "config.worktree"), path.join(gitDir, "commondir"), path.join(gitDir, "gitdir"));
      try {
        for (const wt of fs.readdirSync(path.join(gitDir, "worktrees"))) ro.push(path.join(gitDir, "worktrees", wt, "config.worktree"), path.join(gitDir, "worktrees", wt, "commondir"), path.join(gitDir, "worktrees", wt, "gitdir"));
      } catch {
        // no linked worktrees
      }
    } else {
      ro.push(gitDir);
    }
  }
  if (globalHooks && /^(\/|~(\/|$))/.test(globalHooks)) protect(expandGitPath(globalHooks, HOME), "your global core.hooksPath", true);
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
  return { ro: [...new Set(ro)].filter(lexists), pin: [...new Set(pin)], problems: [...all, ...globalProblems] };
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
function sockets(keep: Set<string>, found: Found, problems: string[]): string[] {
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
  const underRun = discover(["/run"], [runtime, ...out], [], false);
  problems.push(...underRun.problems);
  for (const p of [...found.sockets, ...underRun.sockets]) if (![...out].some((covered) => within(p, covered))) out.add(p);
  return [...out].filter((p) => !keep.has(p) && !keep.has(realpath(p)));
}

// What stays read-only for every command: used for the plan, and to make the edit tool ask.
export function protectedPaths(o: Pick<PlanOptions, "projectRoots" | "allowedPaths" | "project">): string[] {
  const searchDirs = [...new Set([...o.projectRoots, ...o.allowedPaths].map(realpath))];
  return [...gitPaths(discover(searchDirs), searchDirs, searchDirs, false, searchDirs).ro, ...opencodePaths(o.project, searchDirs).ro];
}

export function plan(o: PlanOptions): Plan {
  const own = [...new Set([...o.projectRoots, ...o.allowedPaths].map(realpath))];
  const searchDirs = [...new Set([...own, ...["/tmp", "/var/tmp", os.tmpdir()].map(realpath)])];
  const rwDirs = [...new Set([...searchDirs, ...o.cacheDirs.map(realpath)])];
  // Credential files are looked for in the project and the allowed paths; the temp directories
  // are shared with everything else on the machine.
  const found = discover(searchDirs, [], own);
  const git = gitPaths(found, searchDirs, rwDirs, o.gitWritable, own);
  const opencode = opencodePaths(o.project, rwDirs);
  const ro = [...new Set([...git.ro, ...opencode.ro])];
  const problems = [...found.problems, ...git.problems, ...opencode.problems];
  const agent = process.env.SSH_AUTH_SOCK;
  const keep = new Set([...o.keepSockets, ...(o.exposeSsh && agent ? [agent] : [])].filter(Boolean).flatMap((p) => [p, realpath(p)]));
  const show = new Set(o.showPaths.map(realpath));
  const sshDir = path.join(HOME, ".ssh");
  // ssh-using commands see known_hosts, config and public keys; private keys stay hidden.
  const sshHidden = o.exposeSsh ? list(sshDir).map((e) => e.name).filter((n) => !SSH_VISIBLE.test(n)).map((n) => path.join(sshDir, n)) : [sshDir];
  // Credential files in the project and the allowed paths, at any depth.
  const inProject = [...found.secrets];
  if (inProject.length > limits.secrets) problems.push(`${inProject.length} credential files in the project, more than the ${limits.secrets} that can be hidden`);
  const secretList = [...DEFAULT_SECRET_PATHS.filter((p) => p !== sshDir), ...[...homeSecrets(), ...inProject.slice(0, limits.secrets)].filter((p) => !within(p, sshDir)), ...sshHidden, ...o.hidePaths];
  const secrets = secretList.flatMap((p) => [p, realpath(p)]).filter((p) => !show.has(realpath(p)));
  // The ssh agent, wherever it lives (outside the scanned directories too), unless this call may use it.
  const agentPaths = agent && !o.exposeSsh ? [agent, realpath(agent)] : [];
  const hide = [...new Set([...sockets(keep, found, problems), ...secrets, ...agentPaths])].filter((p) => lexists(p) && !keep.has(p) && !keep.has(realpath(p)));
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
  const unexpressible = [...rwDirs, ...ro, ...pins, ...hide].filter((p) => !usable(p));
  if (unexpressible.length) problems.push(`cannot protect a path containing a newline (${JSON.stringify(unexpressible[0])})`);
  return {
    rw: [...rwDirs.filter(usable), ...DEV_WRITABLE, "/dev/shm"],
    ro: ro.filter(usable),
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
const plainValue = (v: string) => v.length <= 12 || /^[\d.]+$/.test(v) || (!v.includes("@") && v.split(":").every((part) => /^(\/|~\/|\.\.?\/)[^\s]*$/.test(part) || part === ""));

export function envKept(env: Record<string, string | undefined>, keepEnv: string[]): { keep: string[]; dropped: string[] } {
  const keep: string[] = [];
  const dropped: string[] = [];
  for (const [name, value] of Object.entries(env)) {
    if (value === undefined || name.startsWith("AUTOMODE_")) continue;
    // Proxy settings are needed to reach the network at all; one that carries a password is not kept.
    const proxy = /^(no_proxy|((https?|all|ftp)_proxy))$/i.test(name) && !value.includes("@");
    const ok = keepEnv.includes(name) || name === "SSH_AUTH_SOCK" || proxy || (name !== "PWD" && name !== "OLDPWD" && ENV_SECRET_NAME.test(name) ? false : ENV_KNOWN.test(name) || plainValue(value));
    (ok ? keep : dropped).push(name);
  }
  // opencode adds these after the plugin's hook has run.
  keep.push("AGENT", "AI_AGENT", "OPENCODE", "OPENCODE_SESSION_ID");
  return { keep: [...new Set(keep)], dropped };
}
