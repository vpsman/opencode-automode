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
  ].map((p) => path.join(HOME, p)),
];

// In ~/.ssh, what a command that uses ssh may still see: never private keys.
const SSH_VISIBLE = /^(known_hosts(\.old)?|config|authorized_keys|.*\.pub)$/;

// Device files a command may write to. Terminals are not among them, and no device accepts an
// ioctl inside the sandbox. /dev/shm gets a private tmpfs instead of the shared one.
const DEV_WRITABLE = ["/dev/null", "/dev/zero", "/dev/full"];

// Files of hook managers: git hooks hand control to them, so a command that could edit them
// could plant a hook. Only these known names; see "Known gaps" in the README.
const HOOK_MANAGER_FILES = [
  ".husky",
  ".lefthook",
  ".pre-commit-config.yaml",
  ".pre-commit-config.yml",
  ".overcommit.yml",
  ...["lefthook", ".lefthook", "lefthook-local", ".lefthook-local"].flatMap((n) => ["yml", "yaml", "toml", "json"].map((e) => `${n}.${e}`)),
];
// What opencode loads from the session directory and every directory above it, with no prompt:
// config (MCP commands, plugins), plugin and command directories, instructions and skills.
export const OPENCODE_PROJECT_FILES = ["opencode.json", "opencode.jsonc", ".opencode", ".claude", ".agents", "AGENTS.md"];

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

const isBareRepo = (dir: string) => ["HEAD", "objects", "refs"].every((f) => fs.existsSync(path.join(dir, f))) && !fs.existsSync(path.join(dir, ".git"));

export interface Found {
  gitDirs: Set<string>; // real git directories (main, bare, linked worktree, common)
  pointers: Set<string>; // `.git` files of worktrees and submodules
  worktreeOf: Map<string, string>; // git dir -> its worktree top level (for core.hooksPath)
}

function findGit(dir: string, depth: number, found: Found) {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  if (isBareRepo(dir)) {
    found.gitDirs.add(realpath(dir));
    found.worktreeOf.set(realpath(dir), realpath(dir));
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.name === ".git") {
      if (e.isDirectory()) {
        found.gitDirs.add(realpath(p));
        found.worktreeOf.set(realpath(p), realpath(dir));
      } else if (e.isFile()) {
        found.pointers.add(p);
        const m = /^gitdir:\s*(.+)$/m.exec(fs.readFileSync(p, "utf8"));
        if (m) {
          const gitdir = realpath(path.resolve(dir, m[1].trim()));
          found.gitDirs.add(gitdir);
          found.worktreeOf.set(gitdir, realpath(dir));
          try {
            found.gitDirs.add(realpath(path.resolve(gitdir, fs.readFileSync(path.join(gitdir, "commondir"), "utf8").trim())));
          } catch {
            // not a linked worktree
          }
        }
      }
    } else if (depth > 0 && e.isDirectory() && e.name !== "node_modules") {
      findGit(p, depth - 1, found);
    }
  }
}

// Git directories and pointer files up to `depth` levels below the given directories.
export function findGitEntries(dirs: string[], depth = 4): Found {
  const found: Found = { gitDirs: new Set(), pointers: new Set(), worktreeOf: new Map() };
  for (const dir of dirs) findGit(dir, depth, found);
  return found;
}

const expandGitPath = (value: string, base: string) => path.resolve(base, value.replace(/^~(?=\/|$)/, HOME));

// A repository's own core.hooksPath (repository scopes only, following includes: the overrides
// gitRun adds must not answer).
function hooksPathOf(gitDir: string, top: string): string | undefined {
  for (const scope of ["--worktree", "--local"]) {
    const v = safeGit(["--git-dir", gitDir, "config", scope, "--includes", "--get", "core.hooksPath"])?.trim();
    if (v) return expandGitPath(v, top);
  }
  return undefined;
}

// Files a config file pulls in through include.path and includeIf.*.path, whether or not the
// condition holds right now, followed two levels deep.
function includedFiles(configFile: string, depth = 2): string[] {
  if (depth < 0 || !fs.existsSync(configFile)) return [];
  const out: string[] = [];
  const listed = safeGit(["config", "--file", configFile, "--get-regexp", "^include(if\\..*)?\\.path$"]) ?? "";
  for (const line of listed.split("\n").filter(Boolean)) {
    const value = line.slice(line.indexOf(" ") + 1).trim();
    if (!value) continue;
    const file = expandGitPath(value, path.dirname(configFile));
    out.push(file, ...includedFiles(file, depth - 1));
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

interface Protected {
  ro: string[];
  pin: string[];
  problems: string[];
}

function gitPaths(searchDirs: string[], rwDirs: string[], gitWritable: boolean): Protected {
  // Build caches are not searched: they are only writable when the user opts in.
  const found = findGitEntries(searchDirs);
  const insideRw = (p: string) => rwDirs.some((d) => within(p, d));
  const ro: string[] = [...found.pointers];
  const pin: string[] = [];
  const problems: string[] = [];
  // A path that must exist to be protected: created when it is missing and that is safe.
  const mustExist = (p: string, what: string) => {
    if (!insideRw(realpath(path.dirname(p))) && !insideRw(p)) return; // not writable: nothing to plant
    if (isSymlink(p)) return void problems.push(`${what} ${p} is a symlink and cannot be protected`);
    if (!lexists(p) && !ensureDir(p, rwDirs)) return void problems.push(`${what} ${p} does not exist and could not be created safely`);
    ro.push(p);
  };
  const globalHooks = safeGit(["config", "--global", "--includes", "--get", "core.hooksPath"])?.trim();
  for (const gitDir of found.gitDirs) {
    const top = found.worktreeOf.get(gitDir) ?? path.dirname(gitDir);
    const hooks = path.join(gitDir, "hooks");
    if (insideRw(gitDir)) mustExist(hooks, "the hooks directory");
    const hooksPath = hooksPathOf(gitDir, top);
    if (hooksPath) mustExist(hooksPath, "core.hooksPath");
    // A relative global core.hooksPath is resolved by git inside each worktree.
    if (globalHooks && !/^(\/|~(\/|$))/.test(globalHooks) && !hooksPath) mustExist(path.resolve(top, globalHooks), "the global core.hooksPath");
    // Files the repository config includes are config too.
    for (const file of [...includedFiles(path.join(gitDir, "config")), ...includedFiles(path.join(gitDir, "config.worktree"))]) {
      if (!insideRw(file) && !insideRw(realpath(path.dirname(file)))) continue;
      if (!lexists(file) || isSymlink(file)) problems.push(`git config includes ${file}, which is missing or a symlink inside a writable directory`);
      else ro.push(file);
    }
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
  if (globalHooks && /^(\/|~(\/|$))/.test(globalHooks)) ro.push(expandGitPath(globalHooks, HOME));
  for (const file of includedFiles(path.join(XDG_CONFIG, "git", "config")).concat(includedFiles(path.join(HOME, ".gitconfig")))) {
    if (insideRw(file) && lexists(file) && !isSymlink(file)) ro.push(file);
    else if (insideRw(file) || insideRw(realpath(path.dirname(file)))) problems.push(`your git config includes ${file}, which is missing or a symlink inside a writable directory`);
  }
  // Hook managers, at the top of every checkout.
  for (const top of new Set([...found.worktreeOf.values(), ...searchDirs.filter((d) => !["/tmp", "/var/tmp", realpath(os.tmpdir())].includes(d))])) {
    for (const name of HOOK_MANAGER_FILES) {
      const p = path.join(top, name);
      if (isSymlink(p)) problems.push(`${p} is a symlink and cannot be protected`);
      else if (lexists(p)) ro.push(p);
    }
  }
  return { ro: [...new Set(ro)].filter(lexists), pin: [...new Set(pin)], problems };
}

// opencode's project-level config, from the session directory up through every writable parent.
// `.opencode` holds plugins opencode loads and runs: it is created (empty, which git does not
// show) so that it can be made read-only instead of appearing later.
function opencodePaths(project: string | undefined, rwDirs: string[]): Protected {
  const ro: string[] = [];
  const problems: string[] = [];
  if (!project) return { ro, pin: [], problems };
  const start = realpath(project);
  for (let dir = start; rwDirs.some((d) => within(dir, d)); dir = path.dirname(dir)) {
    for (const name of OPENCODE_PROJECT_FILES) {
      const p = path.join(dir, name);
      if (isSymlink(p)) problems.push(`${p} is a symlink and cannot be protected`);
      else if (lexists(p)) ro.push(p);
      else if (name === ".opencode" && dir === start && ensureDir(p, rwDirs)) ro.push(p);
    }
    if (path.dirname(dir) === dir) break;
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
// and data directories.
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
  return out;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "target", "dist", "build", ".venv", "venv", "__pycache__", ".next", ".cache"]);
// In the project: credential files (.env, *.pem, ...) up to three levels down.
function projectSecrets(dirs: string[]): string[] {
  const out: string[] = [];
  const visit = (dir: string, depth: number) => {
    for (const e of list(dir)) {
      if (out.length >= 500) return;
      const p = path.join(dir, e.name);
      if (e.isSymbolicLink()) continue;
      if (isSecretPath(p)) out.push(p);
      else if (depth > 0 && e.isDirectory() && !SKIP_DIRS.has(e.name)) visit(p, depth - 1);
    }
  };
  for (const dir of dirs) visit(dir, 3);
  return out;
}

const reachable = (p: string) => {
  try {
    fs.accessSync(p, fs.constants.W_OK);
    return true;
  } catch {
    return false;
  }
};

// Sockets of other services. The runtime directory is covered whole (or entry by entry around a
// socket that must stay); the usual system socket directories are covered where they exist; and
// /run and the temp directories are searched for any socket this user can connect to.
function sockets(keep: Set<string>): string[] {
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
  const scan = (dir: string, depth: number) => {
    for (const e of list(dir)) {
      const p = path.join(dir, e.name);
      if (out.has(p) || within(p, runtime)) continue;
      if (e.isSocket()) {
        if (reachable(p)) out.add(p);
      } else if (e.isDirectory() && depth > 0) scan(p, depth - 1);
    }
  };
  scan("/run", 2);
  for (const tmp of new Set(["/tmp", "/var/tmp", realpath(os.tmpdir())])) scan(tmp, 3);
  return [...out].filter((p) => !keep.has(p) && !keep.has(realpath(p)));
}

// What stays read-only for every command: used for the plan, and to make the edit tool ask.
export function protectedPaths(o: Pick<PlanOptions, "projectRoots" | "allowedPaths" | "project">): string[] {
  const searchDirs = [...new Set([...o.projectRoots, ...o.allowedPaths].map(realpath))];
  return [...gitPaths(searchDirs, searchDirs, false).ro, ...opencodePaths(o.project, searchDirs).ro];
}

export function plan(o: PlanOptions): Plan {
  const searchDirs = [...new Set([...o.projectRoots, ...o.allowedPaths, "/tmp", "/var/tmp", os.tmpdir()].map(realpath))];
  const rwDirs = [...new Set([...searchDirs, ...o.cacheDirs.map(realpath)])];
  const git = gitPaths(searchDirs, rwDirs, o.gitWritable);
  const opencode = opencodePaths(o.project, rwDirs);
  const ro = [...new Set([...git.ro, ...opencode.ro])];
  const agent = process.env.SSH_AUTH_SOCK;
  const keep = new Set([...o.keepSockets, ...(o.exposeSsh && agent ? [agent] : [])].filter(Boolean).flatMap((p) => [p, realpath(p)]));
  const show = new Set(o.showPaths.map(realpath));
  const sshDir = path.join(HOME, ".ssh");
  // ssh-using commands see known_hosts, config and public keys; private keys stay hidden.
  const sshHidden = o.exposeSsh ? list(sshDir).map((e) => e.name).filter((n) => !SSH_VISIBLE.test(n)).map((n) => path.join(sshDir, n)) : [sshDir];
  const found = [...homeSecrets(), ...projectSecrets([...o.projectRoots, ...o.allowedPaths].map(realpath))].filter((p) => !within(p, sshDir));
  const secretList = [...DEFAULT_SECRET_PATHS.filter((p) => p !== sshDir), ...found, ...sshHidden, ...o.hidePaths];
  const secrets = secretList.flatMap((p) => [p, realpath(p)]).filter((p) => !show.has(realpath(p)));
  // The ssh agent, wherever it lives (outside the scanned directories too), unless this call may use it.
  const agentPaths = agent && !o.exposeSsh ? [agent, realpath(agent)] : [];
  const hide = [...new Set([...sockets(keep), ...secrets, ...agentPaths])].filter((p) => lexists(p) && !keep.has(p) && !keep.has(realpath(p)));
  // A directory that holds a protected path could be renamed and rebuilt without it: every
  // directory between a writable root and such a path is pinned.
  const pin = new Set<string>();
  for (const p of [...ro, ...git.pin, ...hide]) {
    const roots = rwDirs.filter((d) => within(p, d) && p !== d);
    for (const root of roots) for (let dir = path.dirname(p); dir !== root && within(dir, root); dir = path.dirname(dir)) pin.add(dir);
  }
  const pins = [...[...pin].sort((a, b) => a.length - b.length), ...git.pin.filter((p) => !pin.has(p))];
  const problems = [...git.problems, ...opencode.problems];
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
