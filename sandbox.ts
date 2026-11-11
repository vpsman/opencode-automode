// The sandbox plan for one auto-allowed command, handed to sandbox/lockwrite:
//   rw      directories (or device files) the command may write beneath (Landlock)
//   ro      paths bind-mounted read-only: whole git directories for ordinary commands; for
//           pure git commands only their hooks and config; `.git` pointer files; per-repo
//           core.hooksPath directories
//   pin     git directories bound onto themselves, so they cannot be renamed or replaced
//   hide    local sockets of other services and credential files/directories, covered up
//   tmpfs   private writable tmpfs mounts (/dev/shm)
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const HOME = os.homedir();

// Build caches that builds legitimately write to. Only content stores: directories whose
// contents are later executed directly (~/.cargo/bin, ~/.rustup toolchains, npx and uv tool
// environments, pre-commit hook environments) are deliberately not here.
export const DEFAULT_CACHE_DIRS = [
  ".cargo/registry",
  ".cargo/git",
  ".npm/_cacache",
  ".cache/go-build",
  ".cache/pip/http",
  ".cache/pip/http-v2",
  ".bun/install/cache",
  ".local/share/pnpm/store",
  ".gradle/caches",
  ".m2/repository",
].map((p) => path.join(HOME, p));

const XDG_CONFIG = process.env.XDG_CONFIG_HOME || path.join(HOME, ".config");
const XDG_DATA = process.env.XDG_DATA_HOME || path.join(HOME, ".local", "share");
const XDG_STATE = process.env.XDG_STATE_HOME || path.join(HOME, ".local", "state");

// Credentials hidden from sandboxed commands (reads are not otherwise restricted). opencode's
// config, data and state directories hold provider keys and the local server's password.
export const DEFAULT_SECRET_PATHS = [
  path.join(XDG_CONFIG, "opencode"),
  path.join(XDG_DATA, "opencode"),
  path.join(XDG_STATE, "opencode"),
  path.join(XDG_CONFIG, "gh"),
  path.join(XDG_CONFIG, "gcloud"),
  path.join(XDG_CONFIG, "rclone"),
  path.join(XDG_CONFIG, "hub"),
  ...[
  ".ssh",
  ".gnupg",
  ".password-store",
  ".aws",
  ".azure",
  ".kube",
  ".docker/config.json",
  ".netrc",
  ".git-credentials",
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
  ].map((p) => path.join(HOME, p)),
];

// In ~/.ssh, what a command that uses ssh may still see: never private keys.
const SSH_VISIBLE = /^(known_hosts(\.old)?|config|authorized_keys|.*\.pub)$/;

// Device files a command may write to. /dev/shm gets a private tmpfs instead of the shared one.
const DEV_WRITABLE = ["/dev/null", "/dev/zero", "/dev/full", "/dev/tty", "/dev/ptmx", "/dev/pts"];

export interface Plan {
  rw: string[];
  ro: string[];
  pin: string[];
  hide: string[];
  tmpfs: string[];
  // Set when a protection cannot be expressed (a path containing ':'): the command must ask.
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
}

export function realpath(p: string): string {
  try {
    return fs.realpathSync(p);
  } catch {
    return p;
  }
}

const within = (p: string, dir: string) => p === dir || p.startsWith(dir.endsWith("/") ? dir : dir + "/");
const usable = (p: string) => !!p && !p.includes(":");

// git, with nothing from the repository able to run code in this process.
export function safeGit(args: string[], timeout = 3000): string | undefined {
  try {
    return execFileSync("git", ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false", ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout,
      env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GIT_OPTIONAL_LOCKS: "0" },
    });
  } catch {
    return undefined;
  }
}

const isBareRepo = (dir: string) => ["HEAD", "objects", "refs"].every((f) => fs.existsSync(path.join(dir, f))) && !fs.existsSync(path.join(dir, ".git"));

interface Found {
  gitDirs: Set<string>; // real git directories (main, bare, linked worktree, common)
  pointers: Set<string>; // `.git` files of worktrees and submodules
  worktreeOf: Map<string, string>; // git dir -> its worktree top level (for core.hooksPath)
  // Directories between a writable root and a nested repository: bound onto themselves so a
  // parent cannot be renamed and replaced with a different repository.
  ancestors: Set<string>;
}

function addAncestors(from: string, root: string, found: Found) {
  for (let dir = from; dir !== root && dir.startsWith(root + "/"); dir = path.dirname(dir)) found.ancestors.add(dir);
}

function findGit(dir: string, depth: number, found: Found, root = dir) {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  if (isBareRepo(dir)) {
    found.gitDirs.add(realpath(dir));
    found.worktreeOf.set(realpath(dir), realpath(dir));
    addAncestors(path.dirname(dir), root, found);
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.name === ".git") {
      if (e.isDirectory()) {
        found.gitDirs.add(realpath(p));
        found.worktreeOf.set(realpath(p), realpath(dir));
        addAncestors(dir, root, found);
      } else if (e.isFile()) {
        found.pointers.add(p);
        addAncestors(dir, root, found);
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
      findGit(p, depth - 1, found, root);
    }
  }
}

function hooksPathOf(gitDir: string, top: string): string | undefined {
  // Repository scopes only (following includes): safeGit's own -c overrides must not answer.
  const v = (safeGit(["--git-dir", gitDir, "config", "--worktree", "--includes", "--get", "core.hooksPath"]) ?? safeGit(["--git-dir", gitDir, "config", "--local", "--includes", "--get", "core.hooksPath"]))?.trim();
  if (!v) return undefined;
  return path.resolve(top, v.replace(/^~(?=\/|$)/, HOME));
}

// Git directories, pointer files and nested-repo ancestors below the given directories.
export function findGitEntries(dirs: string[], depth = 4): Found {
  const found: Found = { gitDirs: new Set(), pointers: new Set(), worktreeOf: new Map(), ancestors: new Set() };
  for (const dir of dirs) findGit(dir, dir === "/tmp" || dir === "/var/tmp" ? 2 : depth, found);
  return found;
}

function gitPaths(searchDirs: string[], projectRoots: string[], gitWritable: boolean): { ro: string[]; pin: string[]; all: string[] } {
  // Build caches are not searched: cargo keeps bare repositories there that it must update.
  const found = findGitEntries(searchDirs);
  const insideRw = (p: string) => projectRoots.some((d) => within(p, d));
  const ro: string[] = [...found.pointers];
  const pin: string[] = [];
  for (const gitDir of found.gitDirs) {
    const hooks = path.join(gitDir, "hooks");
    if (insideRw(gitDir) && !fs.existsSync(hooks)) {
      try {
        fs.mkdirSync(hooks); // so it can be bound read-only rather than created by the command
      } catch {
        // then the command cannot create it either
      }
    }
    const hooksPath = hooksPathOf(gitDir, found.worktreeOf.get(gitDir) ?? path.dirname(gitDir));
    if (hooksPath && insideRw(hooksPath) && !fs.existsSync(hooksPath)) {
      try {
        fs.mkdirSync(hooksPath, { recursive: true });
      } catch {
        // as above
      }
    }
    if (hooksPath) ro.push(hooksPath);
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
  const globalHooks = safeGit(["config", "--global", "--includes", "--get", "core.hooksPath"])?.trim();
  if (globalHooks) ro.push(path.resolve(HOME, globalHooks.replace(/^~(?=\/|$)/, HOME)));
  pin.unshift(...[...found.ancestors].sort((a, b) => a.length - b.length));
  const roList = [...new Set(ro)].filter((p) => fs.existsSync(p));
  const pinList = [...new Set(pin)];
  return { ro: roList, pin: pinList, all: [...roList, ...pinList] };
}

function ownedByMe(p: string): boolean {
  try {
    return fs.lstatSync(p).uid === process.getuid?.();
  } catch {
    return false;
  }
}

function sockets(keep: Set<string>): string[] {
  const uid = process.getuid?.() ?? 0;
  const runtime = process.env.XDG_RUNTIME_DIR || `/run/user/${uid}`;
  const out = new Set<string>([path.join(runtime, "systemd"), path.join(runtime, "bus"), "/run/docker.sock", "/var/run/docker.sock"]);
  const scan = (dir: string, depth: number) => {
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      // Only this user's sockets: another user's cannot be reached anyway unless they allow it,
      // and must not be able to make every plan fail (a ':' in a name cannot be expressed).
      if (e.isSocket()) {
        if (ownedByMe(p)) out.add(p);
      } else if (e.isDirectory() && depth > 0) scan(p, depth - 1);
    }
  };
  scan(runtime, 3);
  for (const tmp of new Set(["/tmp", os.tmpdir()])) scan(tmp, 2);
  return [...out].filter((p) => !keep.has(realpath(p)));
}

export function plan(o: PlanOptions): Plan {
  const searchDirs = [...new Set([...o.projectRoots, ...o.allowedPaths, "/tmp", "/var/tmp", os.tmpdir()].map(realpath))];
  const rwDirs = [...new Set([...searchDirs, ...o.cacheDirs.map(realpath)])].filter(usable);
  const { ro, pin } = gitPaths(searchDirs.filter(usable), o.projectRoots.map(realpath), o.gitWritable);
  const keep = new Set([...o.keepSockets, ...(o.exposeSsh ? [process.env.SSH_AUTH_SOCK ?? ""] : [])].filter(Boolean).map(realpath));
  const show = new Set(o.showPaths.map(realpath));
  const sshDir = path.join(HOME, ".ssh");
  // ssh-using commands see known_hosts, config and public keys; private keys stay hidden.
  const sshHidden = o.exposeSsh ? listDir(sshDir).filter((n) => !SSH_VISIBLE.test(n)).map((n) => path.join(sshDir, n)) : [sshDir];
  const secretList = [...DEFAULT_SECRET_PATHS.filter((p) => p !== sshDir), ...sshHidden, ...o.hidePaths];
  const secrets = secretList.flatMap((p) => [p, realpath(p)]).filter((p) => !show.has(realpath(p)));
  // The ssh agent, wherever it lives (outside the scanned directories too), unless this call may use it.
  const agent = process.env.SSH_AUTH_SOCK;
  const agentPaths = agent && !o.exposeSsh ? [agent, realpath(agent)] : [];
  const hide = [...new Set([...sockets(keep), ...secrets, ...agentPaths])].filter((p) => fs.existsSync(p) && !keep.has(realpath(p)));
  const unexpressible = [...ro, ...pin, ...hide].filter((p) => !usable(p));
  return {
    rw: [...rwDirs, ...DEV_WRITABLE, "/dev/shm"],
    ro: ro.filter(usable),
    pin: pin.filter(usable),
    hide: hide.filter(usable),
    tmpfs: ["/dev/shm"],
    ...(unexpressible.length ? { problem: `cannot protect a path containing ':' (${unexpressible[0]})` } : {}),
  };
}

function listDir(dir: string): string[] {
  try {
    return fs.readdirSync(dir);
  } catch {
    return [];
  }
}
