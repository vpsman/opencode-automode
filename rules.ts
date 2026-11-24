// Derived from rules.ts of pi-automode-classifier v0.4.1 (commit e61ea96),
// https://github.com/deepu105/pi-automode-classifier — MIT, see LICENSE.pi-automode-classifier.
// Maintained here since: its bugs are fixed in this file, each with a case in
// test/rules.test.mts, and upstream releases are reviewed by hand against e61ea96 rather than
// copied over it.

// Deterministic rules for pi-automode-classifier. They run before the model and settle
// most tool calls:
//   deny     - blocked outright (wipes of /, $HOME or a system directory, disk formatting)
//   ask      - needs a confirm prompt (root, remote or outward-facing actions, deletes and
//              writes outside the working directory, reads of credential files, edits to this
//              guard's own files and to Pi's own files)
//   allow    - read-only commands, builds and tests, file changes inside the working directory,
//              running a file of the project or one the agent wrote in this session
//   classify - everything else goes to the decider
// With the chat decider, asks go to it as well, except the firm and locked ones (forDecider).
//
// A compound command gets the most severe verdict of its parts. Command substitutions and
// `sh -c` strings are parsed as commands too. Syntax the parser does not model (unbalanced
// quotes) is never allowed by rule.
//
// User rules (UserRules) replace the built-in verdict of a simple command. Two things they
// cannot replace: a built-in deny, and the ask for changes to the guard's own files.
//
// The rules also follow which files a session wrote or downloaded (Scope.files), so a script
// the agent wrote runs without the model and a downloaded one asks. Only writes the rules can
// see are followed: redirects, cp, mv, tee, curl and wget, not what a program writes itself.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export type Action = "allow" | "classify" | "ask" | "deny";
export interface Verdict {
  action: Action;
  reason: string;
  // An ask only because a tool is spelled in a way its reader is not trusted with
  // (`unreadSpelling`): another check's ask, with a reason of its own, is shown instead.
  spelling?: true;
  // A user allow rule cannot replace this verdict.
  locked?: boolean;
  // An ask that stays an ask with the chat decider: your own ask rules and the critical asks.
  // Every other ask goes to the decider instead.
  firm?: boolean;
  // Root, credential reads and running downloaded code: a firm ask that is also blocked without
  // a UI, whatever `withoutUi.onAsk` says. A user rule for the command still replaces it.
  critical?: boolean;
  // Set when the call asks because it changes something outside the working directory: the
  // folder a "for this session" permission would cover.
  dir?: string;
  // Set when one command decides the verdict: an allow pattern for it that the confirm prompt
  // can offer, for the session and, unless fromAsk, in the config file too.
  pattern?: string;
  // The pattern came from an ask, so it is offered for the session only, never saved.
  fromAsk?: boolean;
  // An ask the rules sent to the chat model. It skips the classifiers listed before the chat
  // model: only the chat model sees whether the user asked for it.
  ruleAsk?: boolean;
  // Set on a classify verdict that runs files the session wrote: their paths, so the decider can
  // be given what runs.
  files?: string[];
}

const HOME = os.homedir();
const RANK: Record<Action, number> = { allow: 0, classify: 1, ask: 2, deny: 3 };
function worst(...verdicts: Verdict[]): Verdict {
  const hold = (v: Verdict) => (v.locked ? 3 : v.critical ? 2 : v.firm ? 1 : 0);
  const w = verdicts.reduce((a, b) => (RANK[b.action] > RANK[a.action] || (RANK[b.action] === RANK[a.action] && hold(b) > hold(a)) ? b : a));
  // Files that run go to the decider whichever part of the command runs them.
  const files = verdicts.flatMap((v) => v.files ?? []);
  return files.length && w.action === "classify" ? { ...w, files: [...new Set(files)] } : w;
}
const ALLOW: Verdict = { action: "allow", reason: "" };
const classify = (reason: string): Verdict => ({ action: "classify", reason });
const ask = (reason: string): Verdict => ({ action: "ask", reason });
const deny = (reason: string): Verdict => ({ action: "deny", reason });
const guardAsk = (reason: string): Verdict => ({ action: "ask", reason, locked: true });
const criticalAsk = (reason: string): Verdict => ({ action: "ask", reason, firm: true, critical: true });
// With the chat decider, Claude Code's split: the rules allow what is plainly routine and block
// what is plainly destructive, and the decider judges the rest instead of you being asked.
const forDecider = (v: Verdict, scope: Scope): Verdict => (scope.chatDecider && v.action === "ask" && !v.locked && !v.firm ? { ...v, action: "classify", ruleAsk: true } : v);

// ---- paths ----

// realpath that also works for a path that does not exist: resolves the deepest existing
// ancestor and keeps the rest. A link whose target is not there (yet) is followed, as the kernel
// follows it when a write creates the file: `notes.md -> ~/.bash_profile` is judged as
// ~/.bash_profile, not as a new file in the project (council round 1). Past 40 links the kernel
// refuses the write, and the path is kept as it was.
export function realish(p: string): string {
  const tail: string[] = [];
  let cur = p;
  for (let hops = 0; ; ) {
    try {
      return path.join(fs.realpathSync.native(cur), ...tail);
    } catch {
      // (The link's own directory exists, and is resolved first. The target is joined on as
      // text, not normalised: realpath then takes each `..` after the link before it, as the
      // kernel does (`pivot/../x` with `pivot -> ../deep`: council round 2).)
      // (Not in /dev or /proc: `/dev/stdout` leads to a descriptor, which is no path.)
      let target: string | undefined;
      try {
        if (!/^\/(dev|proc)(\/|$)/.test(cur) && fs.lstatSync(cur).isSymbolicLink()) {
          const text = fs.readlinkSync(cur);
          target = path.isAbsolute(text) ? text : `${fs.realpathSync.native(path.dirname(cur))}/${text}`;
        }
      } catch {}
      if (target !== undefined && ++hops <= 40) {
        cur = target;
        continue;
      }
      const parent = path.dirname(cur);
      if (parent === cur) return p;
      tail.unshift(path.basename(cur));
      cur = parent;
    }
  }
}

export function within(p: string, dir: string, strict = false): boolean {
  const rel = path.relative(dir, p);
  if (rel === "") return !strict;
  return rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel);
}

// (/dev/shm is shared memory: a temp directory, as the README and guard.ts count it.)
const TMP_DIRS = [...new Set(["/tmp", "/var/tmp", "/dev/shm", os.tmpdir()].map(realish))];
// (/dev/full takes no write: every write to it fails, which is what a test of a write error wants.)
const DEV_SINKS = /^\/dev\/(null|zero|full|stdout|stderr|tty|fd\/\d+)$/;
// (opencode-automode: a sink is told by the path as written, absolute and without `..`, not by
// resolving it in this process, whose own descriptors are not the command's: `/dev/stderr` led to
// a terminal here and to a pipe there. A word that resolves to /dev/null through links is a sink
// too; any other device it reaches is not.)
const devSink = (word: string, p: string | undefined) => (word.startsWith("/") && !/(^|\/)\.\.(\/|$)/.test(word) && DEV_SINKS.test(path.normalize(word))) || p === "/dev/null";

// Where the content of a file written in this session came from: the agent itself (write tool,
// heredoc, echo, printf), a download, or a command whose output the rules cannot know.
export type Origin = "authored" | "fetched" | "other";
export type SessionFiles = Map<string, Origin>;

export interface Scope {
  // Working directory, or undefined once a `cd` made it unknown.
  cwd: string | undefined;
  // Project root: file changes inside it are allowed. Undefined when Pi runs from $HOME or above.
  root: string | undefined;
  // This guard's own files and Pi's settings. Changes to them always ask.
  guarded: string[];
  // Pi's agent directory. See isPiFile.
  piDirs: string[];
  // Extra directories where file changes are allowed, like the project root.
  allowed: string[];
  rules?: UserRules;
  // Patterns allowed for the session in a prompt. Unlike your own rules they never replace a
  // firm ask: root, a credential read or downloaded code still asks.
  picked?: Matcher[];
  // Files written by earlier calls of the session.
  files: SessionFiles;
  // Files the call being checked would write. commitWrites() adds them to `files` once the
  // call is allowed to run.
  pending: SessionFiles;
  // True for a file of the project checkout: tracked or ignored by the session's git repository.
  project?: (p: string) => boolean;
  // With the chat decider, running a file the session wrote or edited goes to it instead of being
  // allowed. Otherwise writing code to a file and running it would skip the decider.
  chatDecider?: boolean;
  // Shell variables the command set to known literal text before this point.
  vars?: Map<string, string>;
  // Single-assignment constant variables resolved during bashVerdict (depth 0), for decide.ts.
  resolvedVars?: Map<string, string>;
  // Variables of a `for` loop over literal words, so they only ever hold one of those words.
  loopVars?: Set<string>;
  // The words, globs included, that the variable of a `for` loop takes in turn.
  loopValues?: Map<string, string[]>;
  // Symbolic links the command being checked creates, to the path each leads to.
  links?: Map<string, string>;
  // True for a path the caller protects by name (decide.ts: `.git`, opencode's project files, a
  // hook manager's files). Held against a write's path as the rules resolve it, `$x` included
  // (project review 3, round 3, Mythos: `x=opencode; echo '{}' > $x.json`).
  protectedName?: (p: string) => boolean;
  // True for a variable the command does not set anywhere: it holds what the environment the
  // command starts with gives it (the environment of opencode, which runs it), or nothing.
  unassigned?: (name: string) => boolean;
  // The variables the call assigns where the text the rules are given no longer shows it: by
  // arithmetic, which the caller's printer takes out (decide.ts; project review 3, round 5). And
  // those it may not assign for the same reason: behind arithmetic that can end the line (round 6).
  reassigned?: Set<string>;
}

const expandHome = (p: string) => (p === "~" || p.startsWith("~/") ? HOME + p.slice(1) : p);
const withTargets = (paths: string[]) => [...new Set(paths.map(expandHome).flatMap((p) => [p, realish(p)]))];

export interface ScopeOptions {
  allowedPaths?: string[];
  piDirs?: string[];
  rules?: UserRules;
  picked?: Matcher[];
  files?: SessionFiles;
  project?: (p: string) => boolean;
  chatDecider?: boolean;
}

export function makeScope(cwd: string, guarded: string[], options: ScopeOptions = {}): Scope {
  const real = realish(cwd);
  return {
    cwd: real,
    root: within(HOME, real) ? undefined : real,
    guarded: withTargets(guarded),
    piDirs: withTargets(options.piDirs ?? []),
    allowed: withTargets(options.allowedPaths ?? []),
    rules: options.rules,
    picked: options.picked,
    files: options.files ?? new Map(),
    pending: new Map(),
    project: options.project,
    chatDecider: options.chatDecider,
  };
}

// Call after a checked tool call was allowed to run.
export function commitWrites(scope: Scope) {
  for (const [p, origin] of scope.pending) scope.files.set(p, origin);
}

// ---- user rules ----

export interface Matcher {
  source: string;
  test(text: string): boolean;
  // Also tested on the command with its program by name (`npm install` for `/usr/bin/npm
  // install`), for deny, ask and classify. Set on compiled patterns; a matcher without it is
  // tested on exactly the raw text, then the unwrapped one.
  byName?: boolean;
}
export type UserRules = Record<Action, Matcher[]>;

// A pattern is a glob over one whole simple command, where `*` matches any text and a
// trailing ` *` also matches no arguments. With a `re:` prefix it is a regular expression.
export function compilePattern(pattern: string): Matcher {
  let re: RegExp;
  if (pattern.startsWith("re:")) re = new RegExp(pattern.slice(3), "s");
  else {
    const words = pattern.trim().split(/\s+/).join(" ");
    const open = words.endsWith(" *");
    const body = (open ? words.slice(0, -2) : words).split("*").map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*");
    re = new RegExp(`^${body}${open ? "( .*)?" : ""}$`, "s");
  }
  return { source: pattern, test: (text) => re.test(text), byName: true };
}

export function compileRules(rules: Partial<Record<Action, string[]>>): UserRules {
  const compile = (action: Action) => (rules[action] ?? []).map(compilePattern);
  return { deny: compile("deny"), ask: compile("ask"), classify: compile("classify"), allow: compile("allow") };
}

// deny, ask and classify rules also match the command without its wrappers (`timeout 60`,
// `FOO=1`). An allow rule must match the command as written, or without the shell keywords
// and wrappers that do not change what runs (`then`, `timeout 60`, `nice`). It does not match
// behind `env` or a VAR=value assignment, which can change what runs.
function userVerdict(argv: string[], rules: UserRules): Verdict | undefined {
  const raw = argv.join(" ");
  const inner = unwrap(argv);
  const bare = inner.join(" ");
  // A program named by its path is also matched by its name: an ask rule for `npm install *`
  // covers `/usr/bin/npm install`. (Not for allow rules, which match as written.)
  const named = [...new Set([inner.length ? [path.basename(inner[0]), ...inner.slice(1)].join(" ") : "", argv.length ? [path.basename(argv[0]), ...argv.slice(1)].join(" ") : ""])].filter((t) => t !== "" && t !== raw && t !== bare);
  for (const action of ["deny", "ask", "classify"] as const) {
    const hit = rules[action].find((m) => m.test(raw) || m.test(bare) || (!!m.byName && named.some((t) => m.test(t))));
    if (hit) return { action, reason: `your ${action} rule "${hit.source}"`, ...(action === "ask" && { firm: true }) };
  }
  return allowedBy(argv, rules.allow) ? ALLOW : undefined;
}

function allowedBy(argv: string[], allow: Matcher[]): boolean {
  const raw = argv.join(" ");
  const plain = unwrap(argv, SAME_PROGRAM_WRAPPERS).join(" ");
  return allow.some((m) => m.test(raw) || (plain !== "" && m.test(plain)));
}

// Absolute path for a shell word, or undefined when it cannot be known (variable, ~user,
// relative path after an unknown cd).
const expandVars = (word: string, scope: Scope) => word.replace(/\$\{(\w+)\}|\$(\w+)/g, (m, a, b) => ((a ?? b) === "PWD" ? scope.cwd : scope.vars?.get(a ?? b)) ?? m);
function resolveWord(word: string, scope: Scope): string | undefined {
  word = expandVars(word, scope);
  if (/[$`]/.test(word)) return undefined;
  if (word === "~" || word.startsWith("~/")) word = HOME + word.slice(1);
  else if (word === "~+" || word.startsWith("~+/")) {
    if (!scope.cwd) return undefined;
    word = scope.cwd + word.slice(2);
  } else if (word.startsWith("~")) return undefined;
  if (!path.isAbsolute(word)) {
    if (!scope.cwd) return undefined;
    word = path.resolve(scope.cwd, word);
  }
  const own = ownProcessPath(word, scope);
  if (own !== false) return own;
  return realish(path.normalize(word));
}

// Paths that lead through the process that opens them: /proc/self is the shell running the
// command, not this one, and /dev/stdout and /dev/fd/N are that shell's descriptors. They are read
// by their text: /proc/self/cwd is the command's working directory, /proc/self/root is /, a
// descriptor is a sink (kept as /dev/fd/N or /dev/stdout), and the rest of /proc/self is no
// known path. False for any other path.
function ownProcessPath(word: string, scope: Scope): string | undefined | false {
  const m = /^\/(proc\/(self|thread-self)|dev)(\/.*)?$/.exec(word);
  if (!m) return false;
  const rest = m[3] ?? "";
  if (m[1] === "dev") {
    const sink = /^\/(stdin|stdout|stderr|fd\/\d+)$/.exec(rest);
    if (sink) return `/dev${rest}`;
    return /^\/(stdin|stdout|stderr|fd)(\/|$)/.test(rest) ? undefined : false;
  }
  // A `..` after a link is taken from the link's target, which is not known here.
  if (/(^|\/)\.\.(\/|$)/.test(rest)) return undefined;
  const cwd = /^\/cwd(\/.*)?$/.exec(rest);
  if (cwd) return scope.cwd ? realish(path.join(scope.cwd, cwd[1] ?? "")) : undefined;
  const root = /^\/root(\/.*)?$/.exec(rest);
  if (root) return realish(path.normalize(root[1] || "/"));
  const fd = /^\/fd\/(\d+)$/.exec(rest);
  return fd ? `/dev/fd/${fd[1]}` : undefined;
}

// A path through a link this same command creates before it reads the path (`ln -s ~/.config/gh
// g; cat g/hosts.yml`): the link is not there yet when the command is checked. (Writes through
// such a link are held by the checks around the rules, which also know which programs act on
// the link itself, as mv does.)
function followLinks(p: string, scope: Scope): string {
  for (let hops = 0; scope.links && hops < 40; hops++) {
    const hit = [...scope.links].find(([link]) => within(p, link));
    if (!hit) break;
    const [link, target] = hit;
    const next = realish(path.join(target, path.relative(link, p)));
    if (next === p) break;
    p = next;
  }
  return p;
}

const isGuarded = (p: string | undefined, scope: Scope) => !!p && scope.guarded.some((g) => within(p, g));
// Pi's own configuration, instructions and code: its agent directory, any `.pi` directory (a
// project's Pi config, or a dotfiles copy of the agent directory) and the context files Pi reads
// in every directory. A change to them changes what later sessions do, so it asks you, also with
// the chat decider. Your own allow rules can replace that ask.
const CONTEXT_FILES = new Set(["AGENTS.md", "AGENTS.override.md", "AGENTS.MD", "CLAUDE.md", "CLAUDE.MD"]);
const isPiFile = (p: string | undefined, scope: Scope) => !!p && (p.split("/").includes(".pi") || CONTEXT_FILES.has(path.basename(p)) || scope.piDirs.some((d) => within(p, d)) || !!scope.protectedName?.(p));
const piAsk = (reason: string): Verdict => ({ action: "ask", reason, firm: true });
const inTmp = (p: string) => TMP_DIRS.some((d) => within(p, d, true));
// Provably inside the project or a temp directory.
const isLocal = (p: string | undefined, scope: Scope) =>
  !!p && ((!!scope.root && within(p, scope.root)) || inTmp(p) || scope.allowed.some((d) => within(p, d)));
// /, a top-level directory, $HOME or a parent of it.
export const isRootLike = (p: string) => p === "/" || path.dirname(p) === "/" || within(HOME, p);
const BARE_GLOB = /^(\*|\.\*|\.\[!\.\]\*|\{.*\})$/;

// The folder a session permission for `p` would cover: the git checkout or worktree it is in,
// else its parent directory. Undefined for /, $HOME and system directories, which are never
// opened as a whole.
function folderFor(p: string | undefined): string | undefined {
  if (!p) return undefined;
  const parent = path.dirname(p);
  for (let d = parent; !isRootLike(d); d = path.dirname(d)) {
    if (fs.existsSync(path.join(d, ".git"))) return d;
  }
  return isRootLike(parent) ? undefined : parent;
}
// An ask for a change outside the working directory, with the folder it could be allowed for.
// The `dir` key is there even when no folder can be offered: such an ask is about a path, so it
// never gets a command pattern.
const outside = (reason: string, p: string | undefined): Verdict => ({ action: "ask", reason, dir: folderFor(p) });

// ---- files of the session ----

const originOf = (p: string, scope: Scope) => scope.pending.get(p) ?? scope.files.get(p);
// Records that the call writes `p`. A download stays one until the agent rewrites the whole file.
function note(p: string | undefined, origin: Origin, scope: Scope) {
  if (p && !(origin === "other" && originOf(p, scope) === "fetched")) scope.pending.set(p, origin);
}
const isFetched = (word: string, scope: Scope) => {
  const p = resolveWord(word, scope);
  return !!p && originOf(p, scope) === "fetched";
};

// A script with one of these in its name or arguments stays with the model, even when it is
// a file of the project.
const OUTWARD_WORDS = /deploy|publish|release|upload|prod/i;

// Verdict for running the file `word` with `args`, or undefined when the rules cannot tell.
// A file the agent wrote in this session and a file of the project checkout are allowed: they
// run the same code as the project's build and tests. A download asks.
function runFile(word: string, args: string[], scope: Scope): Verdict | undefined {
  const p = resolveWord(word, scope);
  if (!p) return undefined;
  const origin = originOf(p, scope);
  if (origin === "fetched") return criticalAsk(`runs a file downloaded in this session: ${word}`);
  if (isGuarded(p, scope) || !isLocal(p, scope) || OUTWARD_WORDS.test([path.basename(word), ...args].join(" "))) return undefined;
  // A file the session wrote goes to the decider, whichever decider that is: otherwise writing code
  // to a file and running it would skip every check. A file written by this same command is in the
  // command itself.
  if (origin === "authored") return { ...classify(`runs ${word}, which this session wrote`), files: scope.pending.has(p) ? [] : [p] };
  return origin === undefined && scope.project?.(p) ? ALLOW : undefined;
}

// ---- credentials ----

// Places that hold credentials, in any home directory, and file names that do so anywhere.
// Reading one puts it into the agent's transcript, so it asks even for a read-only command.
const SECRET_PLACES = [
  /\/\.(ssh|aws|gnupg|kube|azure|oci|password-store)(\/|$)/,
  /\/\.config\/(gcloud|op|gh\/hosts\.yml)(\/|$)/,
  /\/\.docker\/config\.json$/,
  /\/\.cargo\/credentials(\.toml)?$/,
  /\/\.terraform\.d\/credentials\.tfrc\.json$/,
  /\/\.local\/share\/keyrings(\/|$)/,
  /\/Library\/Keychains(\/|$)/,
  /^\/etc\/(g?shadow-?|ssl\/private(\/.*)?|ssh\/ssh_host_\w+_key)$/,
  /^\/proc\/[^/]+\/environ$/,
];
const SECRET_NAMES =
  /^(id_(rsa|dsa|ecdsa|ed25519)(_[\w.-]+)?|.+\.(pem|key|p12|pfx|jks|keystore|kdbx)|\.env(\.[\w.-]+)?|credentials\.(json|ya?ml|toml|ini|csv|xml)|secrets?\.(json|ya?ml|toml|ini|env|txt)|.*service[-_]?(account|principal).*\.json|\.(netrc|npmrc|pypirc|git-credentials|vault-token|pgpass|htpasswd)|\.(bash|zsh)_history|.*\.keychain(-db)?)$/i;

const XDG_CONFIG_DIR = process.env.XDG_CONFIG_HOME || path.join(HOME, ".config");
const XDG_DATA_DIR = process.env.XDG_DATA_HOME || path.join(HOME, ".local", "share");
const XDG_STATE_DIR = process.env.XDG_STATE_HOME || path.join(HOME, ".local", "state");
const XDG_CACHE_DIR = process.env.XDG_CACHE_HOME || path.join(HOME, ".cache");

// Credentials sandbox.ts hides from sandboxed commands (DEFAULT_SECRET_PATHS), beside the names and
// places below; plan() adds every file and directory under $HOME and the project that the rules
// would ask about. (Project review 6: a read of one asks too, for the Read tool and for a shell
// command with the sandbox off: `~/.local/share/opencode/auth.json`, `~/.claude/.credentials.json`.)
export const SECRET_PATHS = [
  path.join(XDG_CONFIG_DIR, "opencode"),
  path.join(XDG_DATA_DIR, "opencode"),
  path.join(XDG_STATE_DIR, "opencode"),
  path.join(XDG_CONFIG_DIR, "gh"),
  path.join(XDG_CONFIG_DIR, "glab-cli"),
  path.join(XDG_CONFIG_DIR, "github-copilot"),
  path.join(XDG_CONFIG_DIR, "gcloud"),
  path.join(XDG_CONFIG_DIR, "op"),
  path.join(XDG_CONFIG_DIR, "rclone"),
  path.join(XDG_CONFIG_DIR, "hub"),
  path.join(XDG_CONFIG_DIR, "git", "credentials"),
  path.join(XDG_DATA_DIR, "keyrings"),
  path.join(XDG_CACHE_DIR, "git", "credential"),
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
  ...["composer/auth.json", "containers/auth.json", "google-chrome", "google-chrome-beta", "chromium", "BraveSoftware", "microsoft-edge", "vivaldi", "opera"].map((p) => path.join(XDG_CONFIG_DIR, p)),
  ...["fish/fish_history", "atuin"].map((p) => path.join(XDG_DATA_DIR, p)),
];

function isSecretPath(p: string): boolean {
  const name = path.basename(p);
  // Public keys, host lists, client settings, env templates and certificates hold nothing secret.
  if (/\.pub$|^known_hosts|^authorized_keys$|^\.env\.(example|sample|template|dist|defaults?)$/i.test(name)) return false;
  if (/\/\.(ssh|aws)\/config$/.test(p)) return false;
  if (/cert|chain|public|(^|[._-])ca([._-]|$)/i.test(name) && !/priv|key/i.test(name.replace(/\.key$/i, ""))) return false;
  if (SECRET_PLACES.some((place) => place.test(p)) || SECRET_NAMES.test(name)) return true;
  // By prefix, on the resolved text: the sandbox's walk asks this of every dotfile it meets, and
  // `within` (path.relative) against each of these paths made a walk of a large tree miss its
  // time limit.
  const at = path.resolve(p);
  return SECRET_PATHS.some((d) => at === d || at.startsWith(d + "/"));
}

// The home directory of a user by name, as bash's `~name` finds it (round 11, Opus).
function homeOf(name: string): string | undefined {
  try {
    const line = fs.readFileSync("/etc/passwd", "utf8").split("\n").find((l) => l.split(":")[0] === name);
    return line?.split(":")[5] || undefined;
  } catch {
    return undefined;
  }
}

// (Cross-check, Sol: a relative word with a blank is a path where it names one that is there,
// `cat ".ssh/key with space"`; a message is no file.)
function blankPathThere(word: string, scope: Scope): boolean {
  const p = resolveWord(word.replace(/^[^=/]*=/, "").replace(/^@/, ""), scope);
  return !!p && fs.existsSync(p);
}

// The credential file a shell word names, if any. Handles `--file=path`, curl's `@file` and
// git's `rev:path`. In a command, words with spaces and URLs are text, not paths.
function secretIn(word: string, scope: Scope, isPath = false, operand = false): string | undefined {
  // (Project review 6, round 2, Sol: a word with a blank that begins as a path is one, `~/.config/
  // chromium/"Local State"`.)
  if (!isPath && ((/\s/.test(word) && !/^(\/|~)/.test(word) && !blankPathThere(word, scope)) || /^[a-z][a-z0-9+.-]*:\/\//i.test(word))) return undefined;
  // An operand (after `--`) is a path whatever it starts with (round 40, Opus: `cat -- -/../.env`).
  const text = operand ? word : word.replace(/^[^=/]*=/, "").replace(/^@/, "");
  // (Project review 6, Opus: a value of the form `key=@file` names the file after `=@`,
  // `gh api --field=q=@.env`.)
  for (const candidate of new Set([text, text.slice(text.lastIndexOf(":") + 1), ...(text.includes("=@") ? [text.slice(text.lastIndexOf("=@") + 2)] : [])])) {
    // (Round 41, Mythos: a word that starts with `-` and holds a slash, `-/../.env`, is a path
    // through a directory named like an option, as an option's value or an awk operand reads it.)
    if (!candidate || (candidate.startsWith("-") && !operand && !/^-[^=]*\//.test(candidate))) continue;
    const p = resolveWord(candidate, scope);
    // (Project review 6, round 10, Opus: `~name/rest` is a home directory's `rest`, as bash expands
    // it, `cat ~agent/.local/share/opencode/auth.json`.)
    const named = /^~([^/+-][^/]*)\/(.+)$/.exec(candidate);
    if (named && [HOME, homeOf(named[1])].some((h) => h !== undefined && isSecretPath(path.join(h, named[2])))) return candidate;
    if (isSecretPath(expandHome(candidate)) || (p && (isSecretPath(p) || isSecretPath(followLinks(p, scope))))) return candidate;
  }
  return undefined;
}

// Commands that name a path without showing what is in it.
const NAMES_ONLY = new Set(
  `ls stat test [ file du find readlink realpath basename dirname which echo printf rm rmdir unlink mkdir
   touch chmod chown chgrp setfacl tee truncate shred`.split(/\s+/),
);
// The first operand of these is a pattern, filter or script, not a file.
const PATTERN_FIRST = new Set(["grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "jq", "yq"]);

// Whether an option word before `--` can supply the pattern or program (project review 3, round 14,
// Neon): when it can, the first operand is a file rather than the pattern.
function patternFromOption(name: string, args: string[]): boolean {
  const dashes = args.indexOf("--");
  const head = dashes < 0 ? args : args.slice(0, dashes);
  const longOpt = (a: string, full: string, min = full.length) => {
    if (!a.startsWith("--")) return false;
    const opt = a.split("=")[0];
    return opt.length >= min && full.startsWith(opt);
  };
  if (name === "grep" || name === "egrep" || name === "fgrep" || name === "rg") {
    return head.some((a) => /^-[^-]*[ef]/.test(a) || longOpt(a, "--regexp", 5) || longOpt(a, "--file", 6));
  }
  if (name === "awk" || name === "gawk") {
    return head.some((a) => /^-[^-]*[efE]/.test(a) || longOpt(a, "--source", 4) || longOpt(a, "--file", 5) || longOpt(a, "--exec", 4));
  }
  if (name === "jq") {
    return head.some((a) => /^-[^-]*f/.test(a) || longOpt(a, "--from-file", 4) || a === "--args" || a === "--jsonargs");
  }
  return false;
}

// The credential file a simple command would read, if any.
function credentialRead(name: string, args: string[], cmd: Simple, scope: Scope): string | undefined {
  if (NAMES_ONLY.has(name)) return undefined;
  // (Round 51, Sol and Astra: a call that only prints its help or version reads no file. Round 54,
  // Sol: rsync opens its filter and list files before it prints its version, so those are read
  // there; its help exits first.)
  // (Round 55, Astra: exactly the files rsync opens before the query exits.)
  if (name === "rsync" && rsyncReading(args).prints) {
    for (const v of rsyncReading(args).opensBeforeExit) {
      const secret = secretIn(v, scope, false, true);
      if (secret) return secret;
    }
    return undefined;
  }
  if (printsOnly(name, args)) return undefined;
  // (Round 51, Sol: sort's files are its operands and its option values, read by position.)
  if (name === "sort") {
    // (Round 57, Sol: the assignments before the program, or behind `env`, the last one winning;
    // an operand of that shape is a file.)
    // (Round 58, Opus: `env -i` and `env -u _POSIX2_VERSION` clear it for sort.)
    // (Round 59 and 60: `env -vi`, `env -ui`. Round 61, Opus: env's options read as env reads
    // them, a separate `-v` or `-0` before `-i` included: flags, and `-a`/`-u`/`-C`/`-S` with a
    // value attached or in the next word.)
    let posix: string | undefined;
    let inEnv = false;
    for (let k = 0; k < cmd.argv.length; k++) {
      const w = cmd.argv[k];
      if (/^_POSIX2_VERSION=/.test(w)) posix = w;
      else if (w === "env") inEnv = true;
      else if (inEnv && (w === "-" || (w.length > 3 && "--ignore-environment".startsWith(w)))) posix = "_POSIX2_VERSION=0";
      else if (inEnv && /^--(unset|chdir|split-string|argv0)$/.test(w)) {
        if (w === "--unset" && cmd.argv[k + 1] === "_POSIX2_VERSION") posix = "_POSIX2_VERSION=0";
        k++;
      } else if (inEnv && w === "--unset=_POSIX2_VERSION") posix = "_POSIX2_VERSION=0";
      else if (inEnv && /^--./.test(w)) continue;
      else if (inEnv && /^-[^-]/.test(w)) {
        for (let j = 1; j < w.length; j++) {
          if (w[j] === "i") posix = "_POSIX2_VERSION=0";
          if ("auCS".includes(w[j])) {
            const value = j < w.length - 1 ? w.slice(j + 1) : cmd.argv[++k];
            if (w[j] === "u" && value === "_POSIX2_VERSION") posix = "_POSIX2_VERSION=0";
            break;
          }
        }
      } else if (!/^[A-Za-z_]\w*=/.test(w)) break;
    }
    for (const w of sortReading(args, posix !== undefined ? posix2Strict(Number(posix.slice(16))) : undefined).reads) {
      const secret = secretIn(w, scope, false, true);
      if (secret) return secret;
    }
    return undefined;
  }
  // git log and its kin name paths to filter commits by, and show their content only with a patch.
  if (name === "git") {
    // (Round 35, Sol: the subcommand past git's own options, `-C dir` and `-c key=value`.)
    let g = 0;
    while (g < args.length && args[g].startsWith("-")) g += /^(-C|-c|--git-dir|--work-tree|--namespace|--attr-source|--config-env)$/.test(args[g]) ? 2 : 1;
    const sub = args[g];
    // (Round 34, Mythos and Opus: every option that makes git log print a patch: -U<n>, --unified,
    // the merge diffs (-c, --cc, --dd, -m, --remerge-diff, --diff-merges= other than off/none),
    // --binary, word diffs and function context; long ones by any prefix git accepts.)
    // (`--full-diff` only widens a patch another option asks for; `--check` prints the lines it
    // flags, round 35.)
    const patchLong = ["patch", "unified", "cc", "dd", "remerge-diff", "binary", "word-diff", "color-words", "function-context", "check", "patch-with-stat", "patch-with-raw"];
    const shows = (a: string) =>
      /^(-[a-zA-Z0-9]*[pumcW][a-zA-Z0-9]*|-U\d*|-L.*)$/.test(a) ||
      (/^--diff-merges(=|$)/.test(a) && !/^--diff-merges=(off|none)$/.test(a)) ||
      patchLong.some((name) => longIs(a, name));
    if (["log", "shortlog", "rev-list", "whatchanged"].includes(sub ?? "") && !args.some(shows)) return undefined;
  }
  // An in-place edit shows nothing unless `--debug` prints every input line.
  let words = args;
  if (name === "sed") {
    const r = sedReading(args);
    if (r.inPlace && !r.debug && !r.unknownLong) {
      for (const f of r.scriptFiles) {
        const secret = secretIn(f, scope, false, true) ?? globSecret(f, scope);
        if (secret) return secret;
      }
      return undefined;
    }
    words = [...r.files, ...r.scriptFiles];
  } else if (name === "yq") {
    const yq = yqReading(args);
    words = yq.plain ? (yq.nullInput ? yq.files : yq.operands) : args;
  } else if (PATTERN_FIRST.has(name)) words = patternFromOption(name, args) ? operands(args) : operands(args).slice(1);
  else if (COPIERS.has(name)) {
    // With `-t DIR` (`--target-directory`) the destination is named first and every operand is a
    // source (round 34, Mythos).
    // (Round 35: in a cluster, `-vt DIR`, and by any prefix of the long name, `--target DIR`.)
    const separate = (a: string) => (/^-[a-zA-Z]*t$/.test(a) && !a.startsWith("--")) || (a.length >= 3 && !a.includes("=") && "--target-directory".startsWith(a));
    const attached = (a: string) => (/^-[a-zA-Z]*t./.test(a) && !a.startsWith("--")) || (/^--t[\w-]*=/.test(a) && "--target-directory".startsWith(a.split("=")[0]));
    const t = args.findIndex(separate);
    const target = t >= 0 || args.some(attached);
    // (Round 36, Mythos: a `-t` can be another option's value, `-St` is suffix t; with any `-t` in
    // sight every operand is read, the directory too.)
    words = target ? operands(args) : operands(args).slice(0, -1);
  }
  // A compiler names the files it reads inside other words too: `-include.env`, `-imacros`,
  // `-Wp,-include,.env`, `-Wl,@.env` (round 36, Mythos); its diagnostics print their lines.
  if (/^(gcc|g\+\+|cc|c\+\+|clang|clang\+\+)(-\d+(\.\d+)*)?$/.test(name)) {
    words = [
      ...words,
      ...args.flatMap((a) => [
        ...(/^-(include|imacros)./.test(a) && !a.startsWith("--") ? [a.replace(/^-(include|imacros)/, "")] : []),
        ...(/^-W[lap],/.test(a) ? a.split(",").slice(1).map((w) => w.replace(/^@/, "").replace(/^-(include|imacros)(?=.)/, "")) : []),
      ]),
    ];
  }
  // `--env-file .env` hands the file to a program and shows nothing.
  // (Project review 6, Neon: only a dotenv file, `.env` or `.env.<name>`, and only where no word of
  // the call is a shell or a program that prints its environment or a file: `uv run --env-file
  // .env bash -c 'echo "$SECRET"'` shows it, `--env-file ~/.ssh/id_rsa` names another credential.)
  const dotenv = (v: string | undefined) => v !== undefined && /(^|\/)\.env(\.[\w.-]+)?$/.test(v);
  // (Round 1 cross-check, Opus: any program may print what it is given, `jq -n '$ENV'`, `awk
  // 'BEGIN{print ENVIRON["S"]}'`, `make -p`: only a test run keeps the exemption.)
  const shows = !args.some((a) => /^(pytest|vitest|jest|mocha|test)$/.test(path.basename(a))) || args.some((a) => /^(bash|sh|zsh|dash|ksh|fish|echo|printf|printenv|env|cat|jq|awk|gawk|mawk|make|python3?|node|perl|ruby)$/.test(path.basename(a)));
  if (!shows) words = words.filter((w, i) => !(/^--env-file=/.test(w) && dotenv(w.slice(11))) && !(w === "--env-file" && dotenv(words[i + 1])) && !(words[i - 1] === "--env-file" && dotenv(w)));
  // (Round 41, Mythos: a word that starts with `-` and holds a slash is a path to the programs that
  // read it as an operand, `awk 1 -/../.env`.)
  const dashPaths = args.filter((a) => /^-[^=]*\//.test(a) && !words.includes(a));
  for (const word of [...words, ...dashPaths, ...(cmd.in ?? [])]) {
    const secret = secretIn(word, scope) ?? globSecret(word, scope);
    if (secret) return secret;
  }
  // Every word after `--` is a file, one that begins with `-` too.
  const dashes = args.indexOf("--");
  if (dashes >= 0) for (const word of args.slice(dashes + 1)) {
    const secret = secretIn(word, scope, false, true);
    if (secret) return secret;
  }
  return undefined;
}

// A glob reads the files it matches: the credential file among them, if any. Undefined when the
// word has no glob or matches nothing secret.
function globSecret(word: string, scope: Scope): string | undefined {
  const text = word.replace(/^[^=/]*=/, "").replace(/^@/, "");
  if (!/[*?[]/.test(text) || /\s/.test(text)) return undefined;
  const p = resolveWord(path.dirname(text), scope);
  const base = path.basename(text);
  // A glob in a directory part is not followed: any credential place it could reach counts.
  if (/[*?[]/.test(path.dirname(text)) || !p) return SECRET_PLACES.some((place) => place.test(expandHome(text).replace(/[*?]/g, "x"))) ? text : undefined;
  let re: RegExp;
  try {
    re = new RegExp(`^${base.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".").replace(/\[!/g, "[^")}$`, "s");
  } catch {
    // A bracket bash would take literally: any name that differs only there could match.
    re = new RegExp(`^${base.replace(/\[[^\]]*\]?/g, "\0").replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".").replace(/\0/g, ".*")}$`, "s");
  }
  let names: string[] = [];
  try {
    names = fs.readdirSync(p);
  } catch {}
  const hit = names.find((n) => re.test(n) && isSecretPath(path.join(p, n)));
  return hit ? path.join(path.dirname(text), hit) : isSecretPath(path.join(p, base.replace(/[*?]/g, ""))) ? text : undefined;
}

// The names a glob in the last part of a word matches where the command runs, spelled as the
// word spells its directory; undefined where a directory part holds a glob or cannot be read.
function globNames(word: string, scope: Scope): string[] | undefined {
  // (Round 46, Opus: a POSIX class, `[^`, an equivalence or collating class, or a backslash is
  // left to the model, as this reader does not match them as bash does.)
  if (/[*?[]/.test(path.dirname(word)) || /\s/.test(word) || /\[[:=.^]|\\/.test(word)) return undefined;
  const dir = resolveWord(path.dirname(word), scope);
  if (!dir) return undefined;
  const base = path.basename(word);
  let re: RegExp;
  try {
    re = new RegExp(`^${base.replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".").replace(/\[!/g, "[^")}$`, "s");
  } catch {
    return undefined;
  }
  try {
    // bash matches a leading `.` only when the pattern spells one; a name with none matches as
    // the word (nullglob off).
    const hits = fs.readdirSync(dir).filter((n) => re.test(n) && (base.startsWith(".") || !n.startsWith(".")));
    return hits.length ? hits.map((n) => (word.includes("/") ? `${path.dirname(word)}/${n}` : n)) : [word];
  } catch {
    return undefined;
  }
}

// Whether a read-only program reads a file whose name the shell expands: a substitution, or a
// variable the command does not set to a known value.
// Programs that show the content of the files they are given.
const FILE_READERS = new Set(`cat bat head tail less more wc rg grep egrep fgrep sort uniq cut jq yq column diff cmp comm nl tac rev fold paste join
  sha256sum sha1sum md5sum b3sum xxd hexdump od strings nm zcat xzcat bzcat zstdcat`.split(/\s+/));
// Whether a reader reads a file whose name the shell expands to something the rules do not know:
// a substitution, or a variable the command does not set. A variable of a `for` loop over words
// or globs stands for each of them, and each is checked as a file.
function readsExpansion(name: string, args: string[], dyn: (k: number) => boolean, cmd: Simple, scope: Scope): string | undefined {
  if (!FILE_READERS.has(name)) return undefined;
  let words = args.filter((a, k) => !a.startsWith("-") && dyn(k));
  if (PATTERN_FIRST.has(name) && !patternFromOption(name, args) && (name !== "yq" || yqReading(args).nullInput)) words = words.filter((w) => w !== operands(args)[0]);
  for (const w of [...words, ...(cmd.in ?? []).filter((w, k) => cmd.inDyn?.[k] ?? /[$`]/.test(w))]) {
    const text = expandVars(w, scope);
    const loop = /\$\{?([A-Za-z_]\w*)\}?/.exec(text);
    const values = loop && scope.loopValues?.get(loop[1]);
    if (values && text.replace(loop![0], "").search(/[$`]/) < 0) {
      for (const v of values) {
        const each = text.replace(loop![0], v);
        const secret = secretIn(each, scope) ?? globSecret(each, scope);
        if (secret) return `${name} reads a credential file: ${secret}`;
      }
      continue;
    }
    // Variables the command does not set hold what the environment gives them.
    const fromEnv = text.replace(/\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)/g, (m, a, b) => (scope.unassigned?.(a ?? b) ? (process.env[a ?? b] ?? "") : m));
    if (/[$`]/.test(fromEnv)) return `${name} reads a file named by an expansion`;
    const secret = fromEnv && (secretIn(fromEnv, scope) ?? globSecret(fromEnv, scope));
    if (secret) return `${name} reads a credential file: ${secret}`;
  }
  return undefined;
}

// ---- parser ----

export interface Simple {
  argv: string[];
  // Output redirect targets.
  out: string[];
  // Input redirect sources.
  in?: string[];
  // The targets in `out` opened with `>>`.
  append?: string[];
  // Reads a heredoc: for a shell or interpreter the body is code.
  heredoc?: boolean;
  // The heredoc body holds a variable or a command substitution, so it is not literal text.
  expands?: boolean;
  // Runs in a subshell: inside a command substitution, or as part of a pipeline or a background
  // job. A `cd` or an assignment there does not reach the commands that follow.
  subshell?: boolean;
  // Per word of `in`: the same.
  inDyn?: boolean[];
  // Per word of argv: true when the shell expands something in it (a variable, a substitution,
  // arithmetic) before the program sees it, so the text here is not the text that runs.
  dyn?: boolean[];
  // Per word of argv: true when the word holds an unquoted glob character (`*`, `?`, or `[...]`).
  glob?: boolean[];
  // The operator that follows the command: `;`, a newline, `&&`, `||`, `|`, `&`, `(` or `)`.
  next?: string;
  // `&&` or `||` where that joins the command to one that is not listed: an arithmetic command,
  // a redirect with no command (`< f && x=1`), a subshell's `)`.
  after?: "&&" | "||";
  // `&` where it ends the command's list behind a command that is not listed (`x=1 && ((n)) &`):
  // `next` is then the `&&` or the `||` in front of that one.
  ends?: "&";
  // Something bash does for the command can fail in a way that ends the line it stands on: bash
  // then skips what is left of that line and runs the next (see `reach`).
  aborts?: boolean;
  // Its standard input is a pipe from the command before it.
  piped?: boolean;
  // Inside a command substitution (or a heredoc body's): it runs while the command that holds it
  // is expanded, and is listed before it.
  nested?: boolean;
}
export interface Parsed {
  cmds: Simple[];
  // Syntax that is not modelled: never allow by rule.
  opaque: boolean;
  // Parenthesised subshells: `cd` tracking is unreliable.
  grouped: boolean;
  // The variables a `${name=word}` or `${name:=word}` of the command may assign, wherever it
  // stands: a word, a heredoc's body, another expansion; `${name[0]:=word}` too. And those its
  // arithmetic assigns (`$((name=1))`, `((name++))`, a subscript, an offset).
  assigns?: Set<string>;
  // The command has more than one line: a newline outside quotes ends a command somewhere in it
  // (not a line continuation, which joins two lines into one).
  lines?: boolean;
}

// The parser follows bash: quoting (`'...'`, `"..."`, `$'...'`, backslashes, line continuations),
// substitutions (`$(...)`, backticks, `${...}`, arithmetic), heredocs, redirections and brace
// expansion. What it does not model sets `opaque`, so the command is never allowed by rule.
// Each character of a word carries a tag: `u` unquoted, `q` quoted, `e` the product of an expansion
// (`E` inside double quotes). The tags decide what bash does next with the word: brace expansion
// and `~` act on unquoted text only, a quoted word is never a keyword or an assignment, and only
// an unquoted number before `>` is a file descriptor.
type RedirectKind = "" | "out" | "append" | "in" | "dupout" | "dupin";
interface ParseState {
  depth: number;
  result: Parsed;
  // Variable names read by arithmetic, checked against the whole command once it is parsed.
  arith: Set<string>;
  // How many expansions read so far can fail and end their line (Simple.aborts): the count is
  // shared by every depth of the parse, and a command is marked when it moved while it was read.
  aborts: { n: number };
}

// Commands whose effect on later commands the rules follow; a function by one of these names is not modelled.
const SHADOWS_STATE = new Set(["cd", "pushd", "popd", "command", "builtin", "exec", "eval", "source", ".", "set", "shopt", "unset", "export", "declare", "typeset", "local", "readonly", "read", "printf", "test", "[", "trap", "alias", "unalias", "hash", "enable", "type", "env", "ln", "mapfile", "readarray", "getopts", "wait"]);
// Where an empty quote stood in a word, until brace expansion is done (see `add` in parseList).
const EMPTY_QUOTE = "\uE000";
const unmark = (w: string, m: string): [string, string] => {
  if (!w.includes(EMPTY_QUOTE)) return [w, m];
  let text = "";
  let tags = "";
  for (let k = 0; k < w.length; k++) if (w[k] !== EMPTY_QUOTE) (text += w[k]), (tags += m[k]);
  return [text, tags];
};
const RESERVED = new Set(["if", "then", "elif", "else", "fi", "do", "done", "while", "until", "for", "in", "case", "esac", "select", "function", "time", "coproc", "!", "{", "}", "[[", "]]"]);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*(\[[^\]]*\])?\+?=/s;
// The variables bash makes read-only (bash 5.2): a plain assignment to one fails, and ends the line.
const READONLY = /^(BASHOPTS|BASH_VERSINFO|EUID|PPID|SHELLOPTS|UID)(\[[^\]]*\])?\+?=/;
// Reserved words that can lead a simple command (Project review 3, round 8, Neon: `! UID=1`,
// `{ UID=1; }`, `if true; then UID=1; fi`, `while UID=1; do :; done`, `time -p UID=1`).
const LEAD_ASSIGN = new Set(["if", "then", "elif", "else", "do", "while", "until", "!", "{"]);
function afterLeads(argv: string[]): string[] {
  let k = 0;
  while (k < argv.length) {
    const w = argv[k];
    if (w === "time") {
      k++;
      while (k < argv.length && (argv[k] === "-p" || argv[k] === "--")) {
        if (argv[k++] === "--") break;
      }
    } else if (LEAD_ASSIGN.has(w)) k++;
    else break;
  }
  return argv.slice(k);
}
// A word bash may expand into several words (glob, brace expansion, unquoted expansion).
const MAY_EXPAND = /[*?[\]{}$`]/;

export function parse(command: string, depth = 0): Parsed {
  const result: Parsed = { cmds: [], opaque: depth > 4, grouped: false };
  if (result.opaque) return result;
  const state: ParseState = { depth, result, arith: new Set(), aborts: { n: 0 } };
  parseList(command, 0, false, false, state);
  if (state.arith.size && !arithmeticSafe(command, state.arith)) result.opaque = true;
  return result;
}

// Parses commands from `start`. With `closer`, the list is the body of `$(` or `<(` and ends at
// its `)`; returns the index of that `)`, or s.length when it is missing (the caller treats that
// as unmodelled). `sub`: the commands run in a subshell.
function parseList(s: string, start: number, closer: boolean, sub: boolean, st: ParseState): number {
  const result = st.result;
  const opaque = () => void (result.opaque = true);
  const inner: ParseState = { ...st, depth: st.depth + 1 };
  if (st.depth > 4) {
    opaque();
    return s.length;
  }
  let cur: Simple = { argv: [], out: [], dyn: [], glob: [] };
  let word = "";
  let mask = "";
  let hasWord = false;
  let redirect: RedirectKind = "";
  let parens = 0;
  // Open case statements: reading a pattern (up to its `)`) or the commands of a branch.
  const cases: ("pattern" | "body")[] = [];
  const heredocs: { delimiter: string; quoted: boolean; strip: boolean; owner: Simple }[] = [];
  // An `&&` or `||` that followed nothing listed, for the command after it (Simple.after).
  let unlisted: "&&" | "||" | undefined;
  // The last command this list pushed, and the count of ParseState.aborts when it did.
  let last: Simple | undefined;
  let mark = st.aborts.n;

  // An empty quote (`''`, `""`) leaves EMPTY_QUOTE, tagged `Q`, where it stood: brace expansion
  // keeps a word it makes empty only when that word holds a quote (`''{,x}`, not `{,'x'}`). The
  // marks are taken out before the words are stored.
  const add = (text: string, tags: string) => {
    word += text === "" ? EMPTY_QUOTE : text;
    mask += text === "" ? "Q" : tags;
    hasWord = true;
  };
  // Before the program: only keywords so far.
  const commandPosition = () => cur.argv.every((w) => RESERVED.has(w) || ASSIGNMENT.test(w));
  const place = (kind: RedirectKind, w: string, m: string) => {
    if (kind === "" && commandPosition() && /[^u]/.test(m)) {
      // A quoted word is never a keyword, and a quoted name or `=` is no assignment: bash runs
      // `"x=/a"` and `\{` as programs.
      const plain = unmark(w, m);
      const eq = plain[0].indexOf("=");
      if (RESERVED.has(plain[0]) || (ASSIGNMENT.test(plain[0]) && /[^u]/.test(plain[1].slice(0, eq + 1)))) opaque();
    }
    const words = expandBraces(w, m);
    if (!words) {
      opaque();
      words2push([[w, m]], kind);
      return;
    }
    // A brace pattern in a word that also holds an expansion: the order of the two is not modelled.
    if (words.length > 1 && /[eE]/.test(m)) opaque();
    // bash drops a word the braces make empty, unless something in it was quoted (`{,x}` is `x`).
    words2push((words.length > 1 ? words.filter(([text, tags]) => unmark(text, tags)[0] !== "" || /[qQ]/.test(tags)) : words).map(([text, tags]) => unmark(text, tags)), kind);
  };
  const words2push = (words: [string, string][], kind: RedirectKind) => {
    for (const [w, m] of words) {
      // $HOME as an expansion (not quoted text) is the home directory.
      let text = "";
      for (let k = 0; k < w.length; ) {
        const home = /^(\$\{HOME\}|\$HOME(?![A-Za-z0-9_]))/.exec(w.slice(k));
        if (home && /[eE]/.test(m[k])) {
          text += HOME;
          k += home[0].length;
        } else text += w[k++];
      }
      if (kind === "out" || kind === "append") cur.out.push(text);
      else if (kind === "in") {
        (cur.in ??= []).push(text);
        (cur.inDyn ??= []).push(/[eE]/.test(m));
      }
      else {
        cur.argv.push(text);
        cur.dyn!.push(/[eE]/.test(m));
        let unquotedGlob = false;
        for (let k = 0; k < w.length; k++) {
          if (m[k] !== "u") continue;
          if (w[k] === "*" || w[k] === "?" || (w[k] === "[" && w.indexOf("]", k + 1) >= 0)) {
            unquotedGlob = true;
            break;
          }
        }
        cur.glob!.push(unquotedGlob);
      }
      if (kind === "append") (cur.append ??= []).push(text);
    }
  };
  const pushWord = () => {
    if (!hasWord) return;
    const w = word;
    const m = mask;
    const kind = redirect;
    word = "";
    mask = "";
    hasWord = false;
    redirect = "";
    // `esac` where a pattern or a command would start ends the innermost case.
    if (kind === "" && cases.length && cur.argv.length === 0 && w === "esac" && m === "uuuu") cases.pop();
    if (kind === "dupout" || kind === "dupin") {
      // `>&2`, `<&0`, `>&-` copy or close a descriptor. Any other word is a file: `>& file` sends
      // both outputs there, and in `>&2#x` the word is `2#x`.
      if (/^(\d+-?|-)$/.test(w) && /^u+$/.test(m)) return;
      return place(kind === "dupout" ? "out" : "in", w, m);
    }
    place(kind, w, m);
    // `case WORD in`: patterns follow.
    if (kind === "" && w === "in" && m === "uu" && cur.argv.length === 3 && cur.argv[0] === "case" && !cases.includes("pattern")) cases.push("pattern");
  };
  const pushCmd = (op?: string) => {
    pushWord();
    if (redirect) {
      opaque();
      redirect = "";
    }
    if (cur.argv.length || cur.out.length) {
      cur.next = op;
      if (unlisted) cur.after = unlisted;
      unlisted = undefined;
      if (sub) cur.subshell = cur.nested = true;
      // (Project review 3, round 6, Mythos: an expansion read since the last command, its own or
      // one of a command that is not listed, `(( $((1/0)) ))`; or words that only assign, one of
      // them to a variable bash keeps read-only, `UID=1`, including after leading keywords.)
      const own = afterLeads(cur.argv);
      if (st.aborts.n !== mark || (own.length > 0 && own.every((w) => ASSIGNMENT.test(w)) && own.some((w) => READONLY.test(w)))) cur.aborts = true;
      mark = st.aborts.n;
      last = cur;
      result.cmds.push(cur);
    } else if (op === "&&" || op === "||") unlisted = op;
    cur = { argv: [], out: [], dyn: [], glob: [] };
  };

  // `$` at s[i]: an expansion or a plain dollar sign. Returns the index of its last character.
  const dollar = (i: number, dq: boolean): number => {
    const n = s[i + 1];
    const tag = dq ? "E" : "e";
    if (n === "(" && s[i + 2] === "(") {
      st.aborts.n++;
      const end = readArith(s, i + 3, "))", inner);
      if (end < 0) return (opaque(), s.length);
      add("$()", tag.repeat(3));
      return end + 1;
    }
    if (n === "(") {
      const end = parseList(s, i + 2, true, true, inner);
      if (end >= s.length) return (opaque(), s.length);
      add("$()", tag.repeat(3));
      return end;
    }
    if (n === "[") {
      st.aborts.n++;
      const end = readArith(s, i + 2, "]", inner);
      if (end < 0) return (opaque(), s.length);
      add("$()", tag.repeat(3));
      return end;
    }
    if (n === "{") {
      const end = readParam(s, i + 2, inner);
      if (end < 0) return (opaque(), s.length);
      const text = s.slice(i, end + 1);
      add(text, tag.repeat(text.length));
      return end;
    }
    if (n === "'" && !dq) {
      // ANSI-C quoting: a backslash escapes the next character, `\'` included.
      let j = i + 2;
      while (j < s.length && s[j] !== "'") j += s[j] === "\\" ? 2 : 1;
      if (j >= s.length) return (opaque(), s.length);
      const raw = s.slice(i + 2, j);
      const text = ansiC(raw);
      // Text spelled through numeric escapes (`\x63\x75\x72\x6c`) is hidden from a reader of the
      // command: it counts as expanded, so it is never what decides an allow.
      add(text, (/\\([0-7xuUc])/.test(raw) ? tag : "q").repeat(text.length));
      return j;
    }
    // $"..." is a translated string, quoted as "..." is: the main loop reads it next.
    if (n === '"' && !dq) return i;
    const name = /^([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?$!-])/.exec(s.slice(i + 1));
    if (name) {
      add("$" + name[1], tag.repeat(name[1].length + 1));
      return i + name[1].length;
    }
    // A line continuation after `$` would join it to what follows: `$\⏎(`.
    if (n === "\\" && s[i + 2] === "\n") opaque();
    add("$", dq ? "q" : "u");
    return i;
  };
  const backtick = (i: number, dq: boolean): number => {
    const end = readBacktick(s, i, dq, inner);
    if (end < 0) return (opaque(), s.length);
    add("$()", (dq ? "E" : "e").repeat(3));
    return end;
  };

  let i = start;
  for (; i < s.length; i++) {
    const c = s[i];
    const next = s[i + 1];
    if (c === "\\") {
      if (next === "\n") {
        // A line continuation is removed before tokens form, so next to an operator it joins two
        // into one (`&\⏎&`, `<\⏎<`): not modelled.
        const before = s[i - 1] ?? "";
        const after = s[i + 2] ?? "";
        if ((before === "$" && /[^\s]/.test(after)) || (/[<>&|;(]/.test(before) && /[<>&|;(]/.test(after))) opaque();
      } else if (next !== undefined) add(next, "q");
      i++;
    } else if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) return (opaque(), s.length);
      add(s.slice(i + 1, end), "q".repeat(end - i - 1));
      i = end;
    } else if (c === '"') {
      hasWord = true;
      const before = word.length;
      let j = i + 1;
      for (; j < s.length && s[j] !== '"'; j++) {
        const d = s[j];
        if (d === "\\") {
          const e = s[j + 1];
          if (e === "\n") {
            if (s[j - 1] === "$") opaque();
            j++;
          } else if (e !== undefined && '$`"\\'.includes(e)) {
            add(e, "q");
            j++;
          } else add(d, "q");
        } else if (d === "$") j = dollar(j, true);
        else if (d === "`") j = backtick(j, true);
        else add(d, "q");
      }
      if (j >= s.length) return (opaque(), s.length);
      if (word.length === before) add("", "");
      i = j;
    } else if (c === "$") {
      i = dollar(i, false);
    } else if (c === "`") {
      i = backtick(i, false);
    } else if ((c === "<" || c === ">") && next === "(") {
      // Process substitution: the word is a path to a pipe (tagged `p`: no name the shell computes).
      const end = parseList(s, i + 2, true, true, inner);
      if (end >= s.length) return (opaque(), s.length);
      add("$()", "ppp");
      i = end;
    } else if (c === "<" || c === ">" || (c === "&" && next === ">")) {
      // A number right before the operator, unquoted, is a file descriptor; so is `{name}`.
      if (c !== "&" && hasWord && /^u+$/.test(mask) && (/^\d+$/.test(word) || /^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(word))) {
        word = "";
        mask = "";
        hasWord = false;
      }
      pushWord();
      if (redirect) opaque();
      if (c === "<" && next === "<" && s[i + 2] !== "<") {
        // A heredoc: the delimiter is the whole next word, quotes removed. Any quoting makes the
        // body literal; `<<-` strips leading tabs.
        let k = i + 2;
        const strip = s[k] === "-";
        if (strip) k++;
        while (s[k] === " " || s[k] === "\t") k++;
        let delimiter = "";
        let quoted = false;
        for (; k < s.length && !/[\s;&|()<>]/.test(s[k]); k++) {
          const d = s[k];
          if (d === "\\") {
            if (s[k + 1] === "\n") opaque();
            quoted = true;
            delimiter += s[++k] ?? "";
          } else if (d === "'" || d === '"') {
            const e = s.indexOf(d, k + 1);
            if (e < 0) return (opaque(), s.length);
            quoted = true;
            delimiter += s.slice(k + 1, e);
            k = e;
          } else if (d === "$" && (s[k + 1] === "'" || s[k + 1] === '"' || s[k + 1] === "(" || s[k + 1] === "{")) {
            opaque();
            delimiter += d;
          } else if (d === "`") {
            opaque();
            delimiter += d;
          } else delimiter += d;
        }
        if (!delimiter) opaque();
        heredocs.push({ delimiter, quoted, strip, owner: cur });
        cur.heredoc = true;
        i = k - 1;
        continue;
      }
      let k = i;
      let kind: RedirectKind;
      if (c === "&") {
        k++;
        kind = s[k + 1] === ">" ? (k++, "append") : "out";
      } else if (c === "<") {
        if (next === "<") {
          // A here-string: the word is data.
          k += 2;
          kind = "in";
        } else if (next === "&") {
          k++;
          kind = "dupin";
        } else if (next === ">") {
          // `<>` opens the file for reading and writing.
          k++;
          kind = "out";
        } else kind = "in";
      } else if (next === ">") {
        k++;
        kind = "append";
      } else if (next === "|") {
        k++;
        kind = "out";
      } else if (next === "&") {
        k++;
        kind = "dupout";
      } else kind = "out";
      redirect = kind;
      i = k;
    } else if (c === " " || c === "\t") {
      pushWord();
    } else if (c === "\n") {
      result.lines = true;
      pushCmd("\n");
      if (heredocs.length) i = readBodies(i);
    } else if (c === ";") {
      pushCmd(";");
      // `;;`, `;&` and `;;&` end a case branch: a pattern comes next.
      if (next === ";" || next === "&") {
        if (cases.length) cases[cases.length - 1] = "pattern";
        else opaque();
      }
      if (next === ";") i++;
      if (s[i + 1] === "&") i++;
    } else if (c === "&" && next === "&") {
      pushCmd("&&");
      i++;
    } else if (c === "|" && next === "|") {
      pushCmd("||");
      i++;
    } else if (c === "&" || c === "|") {
      // `|`, `|&` and a single `&` fork: both sides of a pipe, and the background job.
      cur.subshell = true;
      if (c === "|" && next === "&") i++;
      // (Project review 3, round 6, Mythos: the job is the whole list, `x=foo && true &`. Where
      // the `&` stands behind a command that is not listed, `x=foo && ((1)) &`, the last one
      // listed, which an `&&`, an `||` or a `|` joins to it, is told.)
      pushWord();
      if (c === "&" && !cur.argv.length && !cur.out.length && last && ["&&", "||", "|"].includes(last.next ?? "")) last.ends = "&";
      pushCmd(c);
      if (c === "|") cur.subshell = cur.piped = true;
    } else if (c === "(" && cases.at(-1) === "pattern" && !hasWord && cur.argv.length === 0) {
      // A pattern may open with `(`.
    } else if (c === ")" && cases.at(-1) === "pattern") {
      // The end of a pattern; the branch's commands follow. (Its words stay listed as a command of
      // their own, after the header's, as the checks around the rules read them.)
      pushCmd(")");
      cases[cases.length - 1] = "body";
    } else if (c === "(") {
      if (!hasWord && !redirect && commandPosition() && cur.argv.every((w) => RESERVED.has(w)) && next === "(") {
        // An arithmetic command, `(( ... ))`.
        const end = readArith(s, i + 2, "))", inner);
        if (end < 0) return (opaque(), s.length);
        i = end + 1;
        continue;
      }
      // A function definition, `name()` or `name ()`: its body is read as commands where it stands.
      // A function named like a command whose effect the rules follow (`cd`, `export`, `set`...)
      // would stand in for it unseen, so that is not modelled.
      const keyword = cur.argv[0] === "function" ? 1 : 0;
      const fname = hasWord ? (/^u+$/.test(mask) && cur.argv.length === keyword ? word : "") : !redirect && cur.argv.length === 1 + keyword && !RESERVED.has(cur.argv[keyword]) && !cur.dyn![keyword] ? cur.argv[keyword] : "";
      const close = /^[ \t]*\)/.exec(s.slice(i + 1));
      if (fname && close && /^[A-Za-z_][\w.-]*$/.test(fname)) {
        // A function in place of cd: where later commands run is not known (grouped, below).
        if (SHADOWS_STATE.has(fname) && !["cd", "pushd", "popd"].includes(fname)) opaque();
        // The name stays listed as a command of its own, as the checks around the rules expect.
        result.grouped = true;
        pushCmd("(");
        i += close[0].length;
        continue;
      }
      // A subshell group may start a command (after keywords). Extglob (`@(...)`) is not modelled;
      // anything else here is a syntax error, or an array assignment, read as a group as before.
      if (hasWord && /[@!+*?]$/.test(word) && mask.endsWith("u")) opaque();
      result.grouped = true;
      parens++;
      pushCmd("(");
    } else if (c === ")") {
      if (parens > 0) {
        parens--;
        pushCmd(")");
      } else if (closer) {
        pushCmd(")");
        if (heredocs.length) opaque();
        return i;
      } else {
        opaque();
        pushCmd(")");
      }
    } else if (c === "#" && !hasWord) {
      // A word that starts with `#` starts a comment, to the end of the line.
      const end = s.indexOf("\n", i);
      i = end < 0 ? s.length : end - 1;
    } else {
      add(c, "u");
    }
  }
  pushCmd(undefined);
  if (parens > 0 || heredocs.length || cases.length) opaque();
  return s.length;

  // The bodies of the heredocs opened on the line that ends at `nl`. Returns the index just before
  // the newline that ends the last delimiter line, so the main loop goes on from there.
  function readBodies(nl: number): number {
    let pos = nl + 1;
    while (heredocs.length) {
      const doc = heredocs.shift()!;
      let body = "";
      let found = false;
      while (pos < s.length) {
        let eol = s.indexOf("\n", pos);
        if (eol < 0) eol = s.length;
        let line = s.slice(pos, eol);
        // In an unquoted body a backslash-newline joins the next line on before the delimiter is
        // looked for: `EO\⏎F` ends the body.
        while (!doc.quoted && /(^|[^\\])(\\\\)*\\$/.test(line) && eol < s.length) {
          let e2 = s.indexOf("\n", eol + 1);
          if (e2 < 0) e2 = s.length;
          line = line.slice(0, -1) + s.slice(eol + 1, e2);
          eol = e2;
        }
        // The delimiter line is the delimiter exactly; `<<-` strips leading tabs only.
        if ((doc.strip ? line.replace(/^\t+/, "") : line) === doc.delimiter) {
          found = true;
          pos = eol;
          break;
        }
        body += line + "\n";
        pos = eol + 1;
      }
      // An unterminated heredoc: bash takes the rest as its body, with a warning.
      if (!found) {
        opaque();
        pos = s.length;
      }
      if (!doc.quoted) {
        if (/[$`]/.test(body)) doc.owner.expands = true;
        const before = st.aborts.n;
        scanExpansions(body, inner);
        // (Project review 3, round 6, Mythos: bash expands the body when the heredoc's command
        // runs, before the commands written after that one on its line: `: <<E; x=foo`. A heredoc
        // on no command is not listed, so it has nothing to mark: not modelled.)
        if (st.aborts.n !== before) {
          if (!result.cmds.includes(doc.owner)) opaque();
          doc.owner.aborts = true;
          if (mark === before) mark = st.aborts.n;
        }
      }
    }
    return pos - 1;
  }
}

// An expansion that starts at s[j] with `$(`, `$((`, `${` or `$[`: parses what runs in it and
// returns the index of its last character, or -1 when it does not end.
function readDollar(s: string, j: number, st: ParseState): number {
  const n = s[j + 1];
  let end = -1;
  // (Project review 3, round 6, Mythos: an arithmetic expansion that fails ends the line it is
  // on, wherever it stands: a word, a heredoc's body, another expansion, an arithmetic command.)
  if (n === "(" && s[j + 2] === "(") {
    st.aborts.n++;
    end = readArith(s, j + 3, "))", st);
    if (end >= 0) end++;
  } else if (n === "(") end = parseList(s, j + 2, true, true, st);
  else if (n === "{") end = readParam(s, j + 2, st);
  else if (n === "[") {
    st.aborts.n++;
    end = readArith(s, j + 2, "]", st);
  }
  return end >= s.length ? -1 : end;
}

// The substitutions in text the shell expands as it would inside double quotes, but where `"` is
// plain text: an unquoted heredoc body.
function scanExpansions(text: string, st: ParseState) {
  for (let j = 0; j < text.length; j++) {
    const c = text[j];
    if (c === "\\") j++;
    else if (c === "`") {
      const end = readBacktick(text, j, false, st);
      if (end < 0) return void (st.result.opaque = true);
      j = end;
    } else if (c === "$" && "({[".includes(text[j + 1] ?? " ")) {
      const end = readDollar(text, j, st);
      if (end < 0) return void (st.result.opaque = true);
      j = end;
    }
  }
}

// A backtick substitution starting at s[i]: returns the index of the closing backtick, or -1. In
// the body a backslash escapes `$`, a backtick and itself (and `"` inside double quotes).
function readBacktick(s: string, i: number, dq: boolean, st: ParseState): number {
  let body = "";
  let j = i + 1;
  for (; j < s.length && s[j] !== "`"; j++) {
    if (s[j] === "\\") {
      const e = s[j + 1];
      if (e === "\n") j++;
      else if (e !== undefined && ("$`\\".includes(e) || (dq && e === '"'))) {
        body += e;
        j++;
      } else body += "\\";
    } else body += s[j];
  }
  if (j >= s.length) return -1;
  parseList(body, 0, false, true, st);
  return j;
}

// `${...}` from just after the brace: returns the index of the closing `}`, or -1. Substitutions
// inside are parsed; the forms that only pick or edit text are modelled, the rest is opaque.
function readParam(s: string, start: number, st: ParseState): number {
  let j = start;
  for (; j < s.length && s[j] !== "}"; j++) {
    const c = s[j];
    if (c === "\\") {
      if (s[j + 1] === "\n") st.result.opaque = true;
      j++;
    } else if (c === "'" || c === '"') {
      // Quotes inside `${...}` follow rules of their own (in double quotes `'` may or may not
      // quote, by operator): not modelled.
      st.result.opaque = true;
    } else if (c === "`") {
      const end = readBacktick(s, j, false, st);
      if (end < 0) return -1;
      j = end;
    } else if (c === "$" && "({[".includes(s[j + 1] ?? " ")) {
      const end = readDollar(s, j, st);
      if (end < 0) return -1;
      j = end;
    }
  }
  if (j >= s.length) return -1;
  const m = /^(#?)([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?$!-])(\[([^\]]*)\])?(.*)$/s.exec(s.slice(start, j));
  const rest = m?.[5] ?? "";
  // ${x}, ${#x}, ${x[i]}, ${x:-word}, ${x:=word}, ${x#pat}, ${x/a/b}, ${x^^}, ${x:i:n}. A subscript
  // or an offset is arithmetic, read as such. Not modelled: ${!x} (indirection), `:=` on a
  // variable bash reads or the environment holds, and ${x@P} and the other transformations, which
  // can run what the value holds.
  if (m?.[4] !== undefined && m[4] !== "@" && m[4] !== "*") checkArith(m[4], st);
  const offsets = /^:(?![-=?+])(.*)$/s.exec(rest);
  if (m && !m[1] && offsets) for (const part of offsets[1].split(":")) checkArith(part, st);
  const assigns = /^:?=/.test(rest) && !!m && /^[A-Za-z_]/.test(m[2]);
  if (assigns) (st.result.assigns ??= new Set()).add(m![2]);
  // (Project review 3, round 6, Mythos: the expansions that can fail and end their line, beside
  // arithmetic itself. A subscript or an offset that is not a plain number is evaluated, and what
  // it evaluates can be an error; a length below zero is one (`${y:0:-5}` of a short value, of
  // `$@` or of an array always), so a length passes only as digits. `${FUNCNAME:=x}` ends the
  // line without a word: bash refuses the assignment to a variable it keeps for itself.)
  // (Project review 3, round 8, Neon: a leading 0 followed by more digits is octal in bash, where
  // 8 or 9 fails and aborts the line (`${y:0:08}`, `${y:08}`, `${y: -08}`); empty `${y:}` and >2
  // parts abort too.)
  // (Project review 3, round 9: a value past 2^63-1 wraps negative in bash and aborts the line,
  // `${y:0:9223372036854775808}`; cap plain numbers at 18 digits, in step with canon.ts and guard.ts.)
  const parts = m && !m[1] && offsets ? offsets[1].split(":") : [];
  const plainDec = (p: string, signed: boolean) => (signed ? /^\s*(?:-?(?:0|[1-9]\d{0,17}))?\s*$/ : /^\s*(?:0|[1-9]\d{0,17})?\s*$/).test(p);
  if (
    (m?.[4] !== undefined && !/^(?:0|[1-9]\d{0,17}|[@*])$/.test(m[4])) ||
    (m && !m[1] && offsets && (offsets[1] === "" || parts.length > 2 || parts.some((part, k) => !plainDec(part, k === 0)))) ||
    (assigns && (BASH_SETS.test(m![2]) || READONLY.test(`${m![2]}=`)))
  ) st.aborts.n++;
  const plain =
    !!m &&
    (rest === "" ||
      (!m[1] && (!!offsets || /^:?[-?+]/.test(rest) || /^(##?|%%?|\/[/#%]?|\^\^?|,,?)/.test(rest) || (assigns && !BASH_READS.test(m[2]) && !Object.hasOwn(process.env, m[2])))));
  if (!plain) st.result.opaque = true;
  return j;
}

// An arithmetic expression from `start` to its closing `))` (or `]` for `$[`): returns the index of
// the first closing character, or -1. Substitutions inside are parsed. The expression may hold
// numbers, operators and variable names; the names are checked against the command as a whole.
function readArith(s: string, start: number, close: "))" | "]", st: ParseState): number {
  let depth = 0;
  let text = "";
  for (let j = start; j < s.length; j++) {
    const c = s[j];
    if (depth === 0 && ((close === "))" && c === ")") || (close === "]" && c === "]"))) {
      if (close === "))" && s[j + 1] !== ")") return -1;
      checkArith(text, st);
      return j;
    }
    if (c === "(") depth++;
    else if (c === ")") depth--;
    if (c === "\\" && s[j + 1] === "\n") {
      j++;
      continue;
    }
    if (c === "$" && "({[".includes(s[j + 1] ?? " ")) {
      const end = readDollar(s, j, st);
      if (end < 0) return -1;
      // ${name} reads the variable as the bare name does; anything else stands for a number.
      const name = /^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$/.exec(s.slice(j, end + 1));
      text += name ? ` ${name[1]} ` : s[j + 1] === "{" ? " $? " : " 0 ";
      j = end;
      continue;
    }
    text += c;
  }
  return -1;
}

function checkArith(text: string, st: ParseState) {
  const t = text
    .replace(/\b\d+#\$([A-Za-z_][A-Za-z0-9_]*)/g, " $1 ")
    .replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, " $1 ")
    .replace(/\$[#?$!]/g, " 0 ")
    .replace(/\b\d+#[A-Za-z0-9@_]+/g, " 0 ");
  // (Project review 3, round 5, Mythos: a name arithmetic assigns, by `=`, a compound assignment,
  // `++` or `--` on either side, is assigned again, and the words keep none of the arithmetic's
  // text: after `x=foo; : $((x=5))`, `$x` is `5`. Kept with the names a `${x:=word}` assigns.)
  for (const m of t.matchAll(/([A-Za-z_]\w*)\s*(?:=(?!=)|(?:[-+*/%&^|]|<<|>>)=|\+\+|--)|(?:\+\+|--)\s*([A-Za-z_]\w*)/g)) (st.result.assigns ??= new Set()).add(m[1] ?? m[2]);
  // Positional parameters, quotes, subscripts and anything else: not modelled.
  if (/[^\w\s+\-*/%<>=!&|^~?:,();]/.test(t)) {
    st.result.opaque = true;
    return;
  }
  for (const token of t.match(/[A-Za-z0-9_]+/g) ?? []) if (/^[A-Za-z_]/.test(token)) st.arith.add(token);
}

// Arithmetic evaluates a variable's value as an expression again, subscripts included, so a value
// such as `a[$(cmd)]` runs cmd. A name may be read in arithmetic only when the command gives it
// no value but a plain number or expression: no `read`-style builtin, no quoted or substituted value.
function arithmeticSafe(command: string, names: Set<string>): boolean {
  if (/(^|[\s;&|(`])(read|mapfile|readarray|getopts|declare|typeset|local|readonly|export|let|eval|source|select|\.|printf[ \t]+-v)(?=[\s;&|)]|$)/.test(command)) return false;
  for (const name of names) {
    for (const m of command.matchAll(new RegExp(`(^|[^\\w$])${name}(\\[[^\\]]*\\])?\\+?=(?!=)`, "g"))) {
      const value = /^[^\s;&|)]*/.exec(command.slice(m.index + m[0].length))![0];
      if (!/^[\w+\-*/%.,]*$/.test(value) && !/^\$\(\([^$`'"[\]]*$/.test(value)) return false;
    }
    for (const m of command.matchAll(new RegExp(`(^|[\\s;&|(])for[ \\t]+${name}\\b([^;\\n]*)`, "g"))) {
      const words = /^[ \t]+in[ \t]+(.*?)[ \t]*$/.exec(m[2]);
      if (!words || !/^[\w\s+\-.]*$/.test(words[1])) return false;
    }
  }
  return true;
}

// Bash's brace expansion over the unquoted braces of a word: `a{b,c}` is `ab ac`, `{1..3}` is
// `1 2 3`. Quoted braces, `${`, and braces without a comma or a sequence stay as they are.
// Undefined when the expansion would be too large to follow.
function expandBraces(word: string, mask: string, budget = { n: 0 }): [string, string][] | undefined {
  // As bash does it (round 37): the first `{` that opens an expansion splits the word into a
  // preamble, the alternatives (or a sequence) and a postamble. Each alternative and the postamble
  // are expanded on their own, never the joined text again. `{}` opens nothing; a `{` opens an
  // expansion when a comma stands in it at any depth, or it holds a sequence.
  const isSeq = (body: string) => /^([-+]?\d+|[A-Za-z])\.\.([-+]?\d+|[A-Za-z])(\.\.[-+]?\d+)?$/.test(body);
  for (let open = 0; open < word.length; open++) {
    if (word[open] !== "{" || mask[open] !== "u") continue;
    if (word[open + 1] === "}" && mask[open + 1] === "u") {
      // bash passes over `{}` only at the start of a word; elsewhere, with a comma in the word,
      // what it makes is not modelled (round 38).
      if (open > 0 && /,/.test(word.slice(open))) return undefined;
      open++;
      continue;
    }
    let depth = 0;
    let nested = false;
    const commas: number[] = [];
    let close = -1;
    for (let k = open + 1; k < word.length; k++) {
      if (mask[k] !== "u") continue;
      if (word[k] === "{") depth++;
      else if (word[k] === "}") {
        if (depth > 0) {
          depth--;
          continue;
        }
        // Before a comma, a `}` that does not end a sequence is text: `{a}b,c}` is `a}b c`.
        if (commas.length || nested || isSeq(word.slice(open + 1, k)) || !word.slice(k + 1).includes(",")) {
          close = k;
          break;
        }
      } else if (word[k] === ",") {
        if (depth === 0) commas.push(k);
        else nested = true;
      }
    }
    if (close < 0) continue;
    const body = word.slice(open + 1, close);
    let alternatives: [string, string][] = [];
    let expandEach = true;
    if (commas.length) {
      let from = open + 1;
      for (const k of [...commas, close]) {
        alternatives.push([word.slice(from, k), mask.slice(from, k)]);
        from = k + 1;
      }
    } else if (isSeq(body) && !/[^u]/.test(mask.slice(open, close + 1))) {
      const seq = /^([-+]?\d+|[A-Za-z])\.\.([-+]?\d+|[A-Za-z])(\.\.([-+]?\d+))?$/.exec(body)!;
      // A `+` sign, and a letter range across the characters between Z and a: not modelled.
      if (body.includes("+")) return undefined;
      const numeric = /\d/.test(seq[1]) && /\d/.test(seq[2]);
      if (!numeric && (/\d/.test(seq[1]) || /\d/.test(seq[2]))) continue;
      const a = numeric ? Number(seq[1]) : seq[1].charCodeAt(0);
      const b = numeric ? Number(seq[2]) : seq[2].charCodeAt(0);
      if (!numeric && Math.min(a, b) <= 90 && Math.max(a, b) >= 97) return undefined;
      const step = Math.abs(Number(seq[4] ?? 1)) || 1;
      // Past 2^53 adding the step changes nothing, and the loop would not end.
      if (![a, b, step].every(Number.isSafeInteger) || Math.abs(b - a) / step > 1000) return undefined;
      const width = numeric && [seq[1], seq[2]].some((x) => /^-?0\d/.test(x)) ? Math.max(seq[1].length, seq[2].length) : 0;
      for (let v = a; a <= b ? v <= b : v >= b; v += a <= b ? step : -step) {
        // The sign comes before the zeros, `-02 -01 000 001`.
        const text = numeric ? (v < 0 ? "-" : "") + String(Math.abs(v)).padStart(v < 0 ? width - 1 : width, "0") : String.fromCharCode(v);
        alternatives.push([text, "u".repeat(text.length)]);
      }
      expandEach = false;
    } else if (nested) {
      // A group with a comma only further in: bash's reading of it (`{..{,}}` is `.. ..`, but
      // `{{a,b}}` is `{a} {b}`) is not modelled (round 38).
      return undefined;
    } else continue;
    const pre: [string, string] = [word.slice(0, open), mask.slice(0, open)];
    const post = expandBraces(word.slice(close + 1), mask.slice(close + 1), budget);
    if (!post) return undefined;
    const out: [string, string][] = [];
    for (const alt of alternatives) {
      const inner = expandEach ? expandBraces(alt[0], alt[1], budget) : [alt];
      if (!inner) return undefined;
      for (const [w, m] of inner) {
        for (const [pw, pm] of post) {
          if (++budget.n > 1000) return undefined;
          out.push([pre[0] + w + pw, pre[1] + m + pm]);
        }
      }
    }
    return out;
  }
  return [[word, mask]];
}

// The text of `$'...'`: bash's backslash escapes. A NUL ends the string, as it does for bash.
function ansiC(raw: string): string {
  const simple: Record<string, string> = { a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", n: "\n", r: "\r", t: "\t", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?" };
  let out = "";
  for (let k = 0; k < raw.length; k++) {
    if (raw[k] !== "\\" || k + 1 >= raw.length) {
      out += raw[k];
      continue;
    }
    const e = raw[++k];
    let m: RegExpExecArray | null;
    if (simple[e] !== undefined) out += simple[e];
    else if ((m = /^[0-7]{1,3}/.exec(raw.slice(k)))) {
      out += String.fromCharCode(parseInt(m[0], 8) & 0xff);
      k += m[0].length - 1;
    } else if (e === "x" && (m = /^[0-9a-fA-F]{1,2}/.exec(raw.slice(k + 1)))) {
      out += String.fromCharCode(parseInt(m[0], 16));
      k += m[0].length;
    } else if ((e === "u" || e === "U") && (m = new RegExp(`^[0-9a-fA-F]{1,${e === "u" ? 4 : 8}}`).exec(raw.slice(k + 1)))) {
      out += String.fromCodePoint(Math.min(parseInt(m[0], 16), 0x10ffff));
      k += m[0].length;
    } else if (e === "c" && k + 1 < raw.length) {
      out += String.fromCharCode(raw.charCodeAt(++k) & 0x1f);
    } else out += "\\" + e;
  }
  const nul = out.indexOf("\0");
  return nul < 0 ? out : out.slice(0, nul);
}

// ---- command tables ----

export const READ_ONLY = new Set(
  `ls cat bat head tail less more wc rg grep egrep fgrep fd tree stat file du df pwd echo printf
   which whereis type whoami id groups date cal uname hostname uptime printenv ps pgrep free nproc
   lscpu lsblk lsusb lspci lsmod findmnt readlink realpath basename dirname sort uniq cut tr jq yq
   column diff cmp comm nl tac rev fold paste join seq true false test [ sleep export unset wait
   sha256sum sha1sum md5sum b3sum xxd hexdump od strings nm ldd man tldr tokei cloc fastfetch
   journalctl dmesg ss dig nslookup ping getent locale zcat xzcat bzcat zstdcat
   set shopt local declare typeset readonly break continue return exit shift :`.split(/\s+/),
);

// Build, test, lint and format tools that work on the project.
export const DEV_TOOLS = new Set(
  `make just ninja cmake ctest meson pytest tox nox ruff mypy pyright black isort flake8 eslint
   prettier tsc vitest jest mocha rustfmt rustc gcc g++ cc c++ clang clang++ shellcheck shfmt
   stylua luacheck biome golangci-lint hadolint yamllint markdownlint ccache`.split(/\s+/),
);

// Per-tool subcommands. Anything not listed goes to the model.
const SUBCOMMANDS: Record<string, { allow: string; ask?: Record<string, string> }> = {
  git: {
    allow: `status diff log show rev-parse rev-list ls-files ls-tree ls-remote blame describe shortlog
      grep cat-file merge-base name-rev show-ref symbolic-ref count-objects check-ignore
      add commit switch fetch pull merge rebase cherry-pick revert mv init clone apply am bisect
      submodule worktree sparse-checkout notes range-diff format-patch whatchanged version help`,
    ask: {
      push: "git push is visible to others",
      "filter-branch": "rewrites git history",
      "filter-repo": "rewrites git history",
    },
  },
  gh: { allow: `search status version help`, ask: {} },
  cargo: {
    allow: `build check test clippy fmt run bench doc tree metadata nextest clean add remove update
      fetch vendor expand audit deny outdated machete info search pkgid locate-project version help`,
    ask: { publish: "cargo publish is visible to others", yank: "cargo yank is visible to others", login: "stores a registry token" },
  },
  go: { allow: `build test vet run fmt mod generate list get env version doc tool`, ask: {} },
  uv: { allow: `sync lock add remove pip venv tree export version help`, ask: { publish: "uv publish is visible to others" } },
  pip: { allow: `install list show freeze check download wheel uninstall help`, ask: {} },
  pip3: { allow: `install list show freeze check download wheel uninstall help`, ask: {} },
  docker: {
    allow: `build ps images logs inspect version info history top stats diff port`,
    ask: { push: "docker push is visible to others", login: "stores registry credentials" },
  },
  systemctl: {
    allow: `status show cat list-units list-unit-files list-timers list-sockets list-dependencies
      is-active is-enabled is-failed get-default help show-environment list-jobs`,
    ask: {},
  },
  loginctl: { allow: `list-sessions list-users list-seats show-session show-user session-status user-status`, ask: {} },
  niri: { allow: `validate`, ask: {} },
};
for (const pm of ["npm", "pnpm", "yarn", "bun"]) {
  SUBCOMMANDS[pm] = {
    allow: `test t run run-script ci install i ls list outdated audit why explain build start lint add
      remove rm uninstall update up dedupe prune view info pack link rebuild version help`,
    ask: { publish: `${pm} publish is visible to others`, login: "stores a registry token", adduser: "stores a registry token", unpublish: "visible to others", deprecate: "visible to others" },
  };
}

const GH_READ = new Set(["view", "list", "diff", "checks", "status", "watch", "download"]);
// docker <group> <action>: the actions of each group that only read.
const DOCKER_GROUPS: Record<string, string> = {
  image: "ls list inspect history",
  container: "ls list inspect logs top stats port diff",
  network: "ls list inspect",
  volume: "ls list inspect",
  context: "ls list inspect show",
  system: "df info",
};
// Tools where every subcommand not in `allow` changes the system: ask instead of classify.
const ASK_BY_DEFAULT: Record<string, string> = {
  systemctl: "changes a system service",
  loginctl: "changes a login session",
};

// Commands that always need a prompt.
const ALWAYS_ASK: Record<string, string> = {
  sudo: "runs as root", doas: "runs as root", su: "switches user", pkexec: "runs as root",
  ssh: "runs on a remote host", scp: "copies to or from a remote host", sftp: "connects to a remote host",
  ftp: "connects to a remote host", telnet: "opens a raw network connection", nc: "opens a raw network connection",
  ncat: "opens a raw network connection", netcat: "opens a raw network connection", socat: "opens a raw network connection",
  shutdown: "powers off the machine", reboot: "reboots the machine", poweroff: "powers off the machine", halt: "halts the machine",
  stow: "changes symlinks in $HOME", mount: "changes mounts", umount: "changes mounts", swapon: "changes swap", swapoff: "changes swap",
  modprobe: "loads a kernel module", rmmod: "unloads a kernel module", insmod: "loads a kernel module",
  kill: "kills a process", pkill: "kills processes", killall: "kills processes",
  iptables: "changes the firewall", nft: "changes the firewall", ufw: "changes the firewall", "firewall-cmd": "changes the firewall",
  useradd: "changes user accounts", usermod: "changes user accounts", userdel: "changes user accounts", passwd: "changes a password", visudo: "changes sudo rules",
  apt: "changes system packages", "apt-get": "changes system packages", dnf: "changes system packages", yum: "changes system packages",
  zypper: "changes system packages", snap: "changes system packages", flatpak: "changes system packages", brew: "changes system packages",
  twine: "uploads a package", fdisk: "edits disk partitions", parted: "edits disk partitions", sgdisk: "edits disk partitions",
};

// Commands whose operands are written to. "last" means only the final operand is a destination.
const WRITERS: Record<string, "all" | "last"> = {
  cp: "last", ln: "last", install: "last", rsync: "last",
  mv: "all", tee: "all", truncate: "all", touch: "all", mkdir: "all", rmdir: "all", chmod: "all",
  chown: "all", chgrp: "all", setfacl: "all", shred: "all", unlink: "all", patch: "all",
};
// The first operand of these is a mode, owner or script, not a path.
const FIRST_OPERAND_NOT_PATH = new Set(["chmod", "chown", "chgrp", "sed"]);
// Writers whose destination gets the content of their source, and the other writers that
// change a file's content.
const COPIERS = new Set(["cp", "mv", "ln", "install", "rsync"]);
const CONTENT_WRITERS = new Set(["tee", "truncate", "shred", "patch"]);

// Variables that load other code into the program they are set for: the reason given when one is
// set (NODE_OPTIONS that only tunes the runtime is allowed, see NODE_TUNING).
const LOADS_CODE = /^(LD_PRELOAD|LD_AUDIT|DYLD_INSERT_LIBRARIES|BASH_ENV|ENV|NODE_OPTIONS|PERL5OPT|RUBYOPT)=(.*)$/s;
const WRAPPERS = new Set(["env", "nice", "ionice", "timeout", "time", "command", "builtin", "nohup", "setsid", "stdbuf", "exec", "chrt", "taskset"]);
// Wrappers that run the same program with the same environment and PATH lookup.
const SAME_PROGRAM_WRAPPERS = new Set(["timeout", "time", "nice", "ionice", "nohup", "setsid", "stdbuf"]);
const KEYWORDS = new Set(["if", "then", "elif", "else", "do", "while", "until", "!", "{", "}"]);
const NOOP_KEYWORDS = new Set(["fi", "done", "esac", "for", "in"]);
const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh"]);
const INTERPRETERS = new Set(["python", "python3", "node", "perl", "ruby", "php", "lua", "deno", "bun"]);
const PY_MODULES = new Set(["pytest", "unittest", "venv", "pip", "build", "ruff", "mypy", "black", "isort", "compileall", "json.tool"]);
// tool -> subcommand that runs the rest of the line as a command.
const RUNNERS: Record<string, string> = { uv: "run", poetry: "run", pipenv: "run", pdm: "run", hatch: "run", pnpm: "exec", bundle: "exec" };

// Directories whose programs are the tools their names say.
const SYSTEM_BIN = new Set(["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]);

// The options a tool takes before its subcommand. Another option there leaves the subcommand to
// the decider: its value could be read as the subcommand (`systemctl -p status restart nginx`).
// `dirs`: options that move the tool to another directory, which must be local.
const LEAD_OPTIONS: Record<string, OptionTable & { dirs?: string[] }> = {
  npm: { flags: "sqdgyv", long: ["silent", "quiet", "verbose", "workspaces", "include-workspace-root", "if-present", "no-color", "offline", "prefer-offline", "no-audit", "no-fund", "global", "yes"], valued: "w", longValued: ["prefix", "workspace", "loglevel"], dirs: ["--prefix"] },
  pnpm: { flags: "srwv", long: ["silent", "recursive", "workspace-root", "if-present", "no-color", "offline", "prefer-offline", "parallel", "stream", "aggregate-output", "frozen-lockfile"], valued: "CF", longValued: ["dir", "filter", "loglevel", "reporter", "workspace-concurrency"], dirs: ["-C", "--dir"] },
  yarn: { flags: "sv", long: ["silent", "verbose", "offline", "frozen-lockfile", "immutable"], longValued: ["cwd"], dirs: ["--cwd"] },
  bun: { flags: "sv", long: ["silent"], longValued: ["cwd"], dirs: ["--cwd"] },
  cargo: { flags: "qv", long: ["quiet", "verbose", "frozen", "locked", "offline"], valued: "Z", longValued: ["color"] },
  uv: { flags: "qv", long: ["quiet", "verbose", "offline", "no-cache", "native-tls", "no-progress"], longValued: ["directory", "project", "color"], dirs: ["--directory", "--project"] },
  pip: { flags: "qv", long: ["quiet", "verbose", "disable-pip-version-check", "no-cache-dir", "isolated", "no-input", "no-color"] },
  pip3: { flags: "qv", long: ["quiet", "verbose", "disable-pip-version-check", "no-cache-dir", "isolated", "no-input", "no-color"] },
  docker: { flags: "D", long: ["debug"], valued: "l", longValued: ["log-level"] },
  systemctl: { flags: "qlar", long: ["user", "system", "no-pager", "quiet", "no-legend", "full", "all", "failed", "recursive", "no-ask-password", "plain"], valued: "tpPno", longValued: ["type", "property", "lines", "output", "state"] },
  loginctl: { flags: "al", long: ["no-pager", "no-legend", "all", "full", "no-ask-password", "value"], valued: "pPno", longValued: ["property", "lines", "output"] },
};
// The options of a runner's run subcommand, before the command it runs.
const RUNNER_OPTIONS: Record<string, OptionTable> = {
  uv: { flags: "qvsm", long: ["no-sync", "frozen", "locked", "isolated", "no-project", "all-extras", "no-dev", "dev", "quiet", "verbose", "offline", "active", "no-cache", "no-env-file", "all-packages", "exact", "module", "script"], valued: "p", longValued: ["with", "with-editable", "with-requirements", "python", "project", "directory", "group", "only-group", "extra", "env-file", "package"] },
  pnpm: { flags: "r", long: ["recursive", "parallel"] },
};

// The operands: words that are no option, and every word after `--` (round 39, Opus: `rm -rf --
// -/../.git` names a path).
const operands = (args: string[]) => {
  const dashes = args.indexOf("--");
  return [...(dashes < 0 ? args : args.slice(0, dashes)).filter((a) => !a.startsWith("-")), ...(dashes < 0 ? [] : args.slice(dashes + 1))];
};
// Drops a wrapper's leading options; `takesValue` matches the ones followed by a value.
function afterFlags(args: string[], takesValue: RegExp): string[] {
  let i = 0;
  while (i < args.length && args[i].startsWith("-")) i += takesValue.test(args[i]) ? 2 : 1;
  return args.slice(i);
}
const hasFlag = (args: string[], short: string, long?: string) =>
  args.some((a) => (long && a === long) || (/^-[a-zA-Z]+$/.test(a) && a.includes(short)));

// ---- options ----

// Reads leading options against a table: flags, options that take a value (the next word, after
// `=`, or attached to a short letter), and clusters of short flags. Returns the index of the first
// operand, or -1 when an option is not in the table.
interface OptionTable {
  // Short letters that are flags, and those that take a value.
  flags?: string;
  valued?: string;
  // Long options (without the dashes) that are flags, and those that take a value.
  long?: string[];
  longValued?: string[];
}
function leadingOptions(args: string[], table: OptionTable, from = 0): number {
  let i = from;
  while (i < args.length && args[i].startsWith("-") && args[i] !== "-") {
    const a = args[i];
    if (a === "--") return i + 1;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = a.slice(2, eq < 0 ? undefined : eq);
      if (table.longValued?.includes(name)) i += eq < 0 ? 2 : 1;
      else if (eq < 0 && table.long?.includes(name)) i++;
      else return -1;
      continue;
    }
    let k = 1;
    for (; k < a.length; k++) {
      if (table.valued?.includes(a[k])) break;
      if (!table.flags?.includes(a[k])) return -1;
    }
    // A valued letter takes the rest of the word, or the next word.
    i += k < a.length && k === a.length - 1 ? 2 : 1;
  }
  return i;
}

// A long option as git and argp read it: the full name, or an unambiguous prefix of it (any prefix
// here, which errs toward asking), with or without `=value`.
const longIs = (arg: string, name: string) => {
  const head = arg.split("=")[0];
  return head.length > 2 && head.startsWith("--") && `--${name}`.startsWith(head);
};
// A short letter in a cluster such as `-fd`, read up to the first letter that takes a value.
const shortIn = (arg: string, letter: string, valued = "") => {
  if (!/^-[A-Za-z0-9]/.test(arg) || arg.startsWith("--")) return false;
  for (let k = 1; k < arg.length; k++) {
    if (arg[k] === letter) return true;
    if (valued.includes(arg[k])) return false;
  }
  return false;
};


// ---- wrappers and variables ----

// The options of each wrapper, so that an option's value is never read as the program
// (`env -u X cmd`, `timeout -s KILL 5 cmd`). Options that change more than the environment, the
// priority or the time limit (`env -S`, which splits a string into a command; `env -C`; `time -o`,
// which writes a file) are not listed, and leave the command unmodelled. `operands`: what comes
// between the options and the program (timeout's duration, chrt's priority, taskset's mask).
const WRAPPER_OPTIONS: Record<string, OptionTable & { operand?: RegExp }> = {
  env: { flags: "i0v", valued: "u", long: ["ignore-environment", "null", "debug"], longValued: ["unset"] },
  nice: { valued: "n", longValued: ["adjustment"] },
  ionice: { flags: "t", valued: "cn", long: ["ignore"], longValued: ["class", "classdata"] },
  timeout: { flags: "v", valued: "sk", long: ["preserve-status", "foreground", "verbose"], longValued: ["signal", "kill-after"], operand: /^\d+(\.\d+)?[smhd]?$/ },
  time: { flags: "pvq", valued: "f", long: ["portability", "verbose", "quiet"], longValued: ["format"] },
  command: { flags: "p" },
  builtin: {},
  nohup: {},
  setsid: { flags: "cfw", long: ["ctty", "fork", "wait"] },
  stdbuf: { valued: "ioe", longValued: ["input", "output", "error"] },
  exec: { flags: "cl", valued: "a" },
  chrt: { flags: "abdfiorRv", valued: "TPD", long: ["all-tasks", "batch", "deadline", "fifo", "idle", "other", "rr", "reset-on-fork", "verbose"], longValued: ["sched-runtime", "sched-period", "sched-deadline"], operand: /^\d+$/ },
  taskset: { flags: "ac", long: ["all-tasks", "cpu-list"], operand: /^[\da-fA-Fx,:-]+$/ },
};
// What unwrap returns for a wrapper it cannot read: the command is left to the decider.
const UNMODELLED = "\0unmodelled";

// Variables that change how a program formats, logs or labels its work, not what code runs or
// where files go: a command may set, export or pass them on. Any other variable set in the
// environment of a program goes to the decider: PATH, HOME, XDG_*, GIT_*, LD_*, BASH_ENV,
// TAR_OPTIONS, MAKEFLAGS, NODE_OPTIONS with a loader and the like change what runs.
const PLAIN_VARS = /^(_|CI|NODE_ENV|RUST_BACKTRACE|RUST_LOG|RUST_LOG_STYLE|CARGO_TERM_COLOR|CARGO_TERM_VERBOSE|CARGO_TERM_PROGRESS_WHEN|CARGO_INCREMENTAL|DEBUG|VERBOSE|FORCE_COLOR|NO_COLOR|CLICOLOR|CLICOLOR_FORCE|COLUMNS|LINES|TERM|COLORTERM|LANG|LANGUAGE|LC_[A-Z]+|TZ|PYTHONUNBUFFERED|PYTHONDONTWRITEBYTECODE|PYTHONIOENCODING|PYTHONHASHSEED|PYTHONUTF8|PYTHONFAULTHANDLER|PYTHONWARNINGS|GOOS|GOARCH|CGO_ENABLED|GO111MODULE|PORT|HOST|LOG_LEVEL|IFS|GIT_TERMINAL_PROMPT|GIT_AUTHOR_(NAME|EMAIL|DATE)|GIT_COMMITTER_(NAME|EMAIL|DATE)|TIMEFORMAT|SOURCE_DATE_EPOCH|HUSKY|NPM_CONFIG_LOGLEVEL|NPM_CONFIG_FUND|NPM_CONFIG_AUDIT|NPM_CONFIG_UPDATE_NOTIFIER)$/;
// Variables that name a program: allowed only when they name one that does nothing with its input.
const PROGRAM_VARS = /^(EDITOR|VISUAL|GIT_EDITOR|GIT_SEQUENCE_EDITOR|PAGER|GIT_PAGER|SYSTEMD_PAGER|BAT_PAGER|MANPAGER)$/;
const QUIET_PROGRAMS = new Set(["cat", "true", ":", "less", "more", "tee"]);
// NODE_OPTIONS that tune the runtime, without loading anything.
const NODE_TUNING = /^(--max-old-space-size=\d+|--max-semi-space-size=\d+|--stack-size=\d+|--enable-source-maps|--no-warnings|--no-deprecation|--trace-warnings|--trace-deprecation|--trace-uncaught|--unhandled-rejections=[\w-]+|--experimental-vm-modules|--experimental-strip-types|--no-experimental-strip-types|--dns-result-order=[\w-]+|--max-http-header-size=\d+|--disable-warning=[\w-]+|--use-openssl-ca|--use-bundled-ca)$/;
const COMPILERS = /^(cc|c\+\+|gcc|g\+\+|clang|clang\+\+|tcc)(-\d+(\.\d+)*)?$/;
// Variables bash reads itself: where commands are found, how globs and words expand, what runs
// before each command or at startup.
const BASH_READS = /^(PATH|CDPATH|GLOBIGNORE|EXECIGNORE|GLOBSORT|BASHOPTS|SHELLOPTS|POSIXLY_CORRECT|PS4|PWD|OLDPWD|HOME|ENV|BASH_\w+|FUNCNEST|PROMPT_COMMAND|INPUTRC|HISTFILE|TMPDIR|LD_\w+)$/;

// Why setting the variable `name` (to `value`, when known) is left to the decider, if it is.
// `how`: "env" puts it in a program's environment (a prefix, `env`, `export`); "set" sets a shell
// variable, which reaches a program only if it is already exported, as the upper-case names that
// programs read usually are.
function variableProblem(name: string, value: string | undefined, how: "env" | "set", scope: Scope): string | undefined {
  if (name.includes("[")) return `sets ${name}, whose subscript is evaluated as arithmetic`;
  if (PLAIN_VARS.test(name)) return undefined;
  // A variable set on its own stays in the shell, unless it is already in the environment (then
  // the programs after it see the new value) or bash itself reads it.
  if (how === "set" && !BASH_READS.test(name) && !Object.hasOwn(process.env, name)) return undefined;
  // A value that extends the variable's own (`PATH=src:$PATH`) adds only what it spells out.
  const self = new RegExp(`(^|[:\\s])\\$\\{?${name}\\}?(?=$|[:\\s])`, "g");
  if (value !== undefined && self.test(value)) value = value.replace(self, "$1").replace(/^[:\s]+|[:\s]+$/g, "");
  if (value !== undefined && !/[$`]/.test(value)) {
    if (PROGRAM_VARS.test(name) && QUIET_PROGRAMS.has(value)) return undefined;
    if (name === "NODE_OPTIONS" && value.split(/\s+/).filter(Boolean).every((o) => NODE_TUNING.test(o))) return undefined;
    if ((name === "CC" || name === "CXX") && COMPILERS.test(value)) return undefined;
    if (name === "PYTHONPATH" && value.split(":").every((d) => d !== "" && isLocal(resolveWord(d, scope), scope))) return undefined;
  }
  const loads = LOADS_CODE.exec(`${name}=${value ?? ""}`);
  return loads ? `sets ${name}, which loads other code into the program` : `sets ${name}, which can change what a program runs or where it writes`;
}

// The variables a simple command sets, with how: assignments before it and those `env` passes, the
// operands of export/declare/local/readonly/typeset, and the names that read, printf -v, mapfile,
// getopts, unset, for and select set.
function variablesSet(cmd: Simple, argv: string[]): [string, string | undefined, "env" | "set"][] | string {
  const out: [string, string | undefined, "env" | "set"][] = [];
  const pair = (w: string): [string, string] => {
    const eq = w.indexOf("=");
    return [w.slice(0, eq).replace(/\+$/, ""), w.slice(eq + 1)];
  };
  const dropped = cmd.argv.slice(0, cmd.argv.length - argv.length);
  const assignments = dropped.filter((w) => ASSIGNMENT.test(w));
  // Assignments alone set shell variables; before a program (or through env) they are its environment.
  const alone = argv.length === 0;
  for (const w of assignments) out.push([...pair(w), alone ? "set" : "env"]);
  // A loop header: `for NAME in ...`, `select NAME in ...`.
  const head = cmd.argv.findIndex((w) => !RESERVED.has(w) || w === "for" || w === "select");
  if (cmd.argv[head] === "for" || cmd.argv[head] === "select") {
    const name = cmd.argv[head + 1];
    if (name && name !== "((") out.push([name, undefined, "set"]);
  }
  const [program, ...args] = argv;
  if (!program) return out;
  const name = path.basename(program);
  if (["export", "declare", "typeset", "local", "readonly"].includes(name)) {
    const flags = args.filter((a) => /^[-+]/.test(a)).join("");
    // -i evaluates every later assignment as arithmetic; -n makes a name stand for another variable.
    if (/^-.*[in]/.test(flags) || /-[a-zA-Z]*[in]/.test(flags)) return `${name} -i or -n changes how later assignments are read`;
    const how = name === "export" || /-[a-zA-Z]*x/.test(flags) ? "env" : "set";
    for (const a of args.filter((x) => !/^[-+]/.test(x))) {
      if (ASSIGNMENT.test(a)) out.push([...pair(a), how]);
      else if (how === "env" && /^[A-Za-z_]\w*$/.test(a)) out.push([a, undefined, "env"]);
      else if (a.includes("[")) out.push([a, undefined, "set"]);
    }
  } else if (name === "unset") {
    // `unset -f` removes functions.
    if (!args.some((a) => /^-[a-z]*f/.test(a))) for (const a of args.filter((x) => !x.startsWith("-"))) out.push([a, undefined, "set"]);
  } else if (name === "read") {
    const k = leadingOptions(args, { flags: "ers", valued: "adinNptu" });
    if (k < 0) return "read with options the rules do not model";
    const array = args.slice(0, k).find((a, j) => a === "-a" || (args[j - 1] !== "-a" && /^-[a-z]*a$/.test(a)));
    for (const a of args.slice(k)) out.push([a, undefined, "set"]);
    if (array) out.push([args[args.indexOf(array) + 1] ?? "", undefined, "set"]);
  } else if (name === "printf") {
    const v = args.findIndex((a) => a === "-v");
    if (v >= 0) out.push([args[v + 1] ?? "", undefined, "set"]);
    else if (args.some((a) => /^-v./.test(a))) out.push([args.find((a) => /^-v./.test(a))!.slice(2), undefined, "set"]);
  } else if (name === "mapfile" || name === "readarray") {
    if (args.some((a) => /^-[a-zA-Z]*C/.test(a))) return `${name} -C runs a callback`;
    const k = leadingOptions(args, { flags: "t", valued: "dnOsucC" });
    if (k < 0) return `${name} with options the rules do not model`;
    out.push([args[k] ?? "MAPFILE", undefined, "set"]);
  } else if (name === "getopts") {
    out.push([operands(args)[1] ?? "", undefined, "set"]);
  } else if (name === "wait") {
    // (Project review 3, round 5, Mythos: `-p` among other letters, or with its name on it.)
    if (args.some((a) => /^-[a-zA-Z]*p./.test(a) || /^-[a-zA-Z]+p$/.test(a))) return "wait -p in a spelling the rules do not model";
    const p = args.indexOf("-p");
    if (p >= 0) out.push([args[p + 1] ?? "", undefined, "set"]);
  }
  return out;
}

// `set` options that change what later words mean: allexport (-a) puts every later assignment in
// the environment, keyword (-k) takes assignments anywhere on a line as environment.
function setProblem(args: string[]): string | undefined {
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (a === "--" || a === "-") break;
    if (/^[-+]o$/.test(a) && /^(allexport|keyword)$/.test(args[k + 1] ?? "")) return `set -o ${args[k + 1]} changes how later assignments are read`;
    if (/^[-+][a-zA-Z]+$/.test(a) && /[ak]/.test(a.slice(1))) return "set -a or -k changes how later assignments are read";
    if (!/^[-+]/.test(a)) break;
  }
  return undefined;
}

// ---- programs that take code or run programs through their options ----

// POSIX bracket-expression balance in a sed regex part (project review 3, round 14, Neon):
// GNU sed treats the regex delimiter literally inside `[...]`, so a parsed regex part whose
// bracket expression is still open means the reader closed the regex earlier than GNU sed does.
export function sedBracketsClosed(re: string): boolean {
  for (let i = 0; i < re.length; i++) {
    if (re[i] === "\\") {
      i++;
      continue;
    }
    if (re[i] !== "[") continue;
    i++;
    if (i < re.length && re[i] === "^") i++;
    if (i < re.length && re[i] === "]") i++;
    let closed = false;
    for (; i < re.length; i++) {
      if (re[i] === "]") {
        closed = true;
        break;
      }
      if (re[i] === "[" && (re[i + 1] === ":" || re[i + 1] === "." || re[i + 1] === "=")) {
        const close = re.indexOf(`${re[i + 1]}]`, i + 2);
        if (close < 0) return false;
        i = close + 1;
      }
    }
    if (!closed) return false;
  }
  return true;
}

// A sed script that only prints, deletes and substitutes text. Not: `e` (and the `e` flag of `s`),
// which runs a command; `w`, `W` (and the `w` flag), which write a file; `r`, `R`, which read one
// into the output. Anything the reader below does not follow is left to the decider.
function sedScriptSafe(script: string): boolean {
  let i = 0;
  const s = script;
  const skipBlank = () => {
    while (i < s.length && /[ \t]/.test(s[i])) i++;
  };
  // A regex delimited by `d`, from just after the opening delimiter; returns false if unterminated.
  const delimited = (d: string, regex = false): boolean => {
    const start = i;
    for (; i < s.length; i++) {
      if (s[i] === "\\") i++;
      else if (s[i] === d) {
        const body = s.slice(start, i);
        i++;
        return !regex || sedBracketsClosed(body);
      } else if (s[i] === "\n") return false;
    }
    return false;
  };
  const address = (): boolean => {
    if (/\d/.test(s[i] ?? "")) {
      while (/[\d~]/.test(s[i] ?? "")) i++;
    } else if (s[i] === "$") i++;
    else if (s[i] === "/") {
      i++;
      if (!delimited("/", true)) return false;
      while (/[IM]/.test(s[i] ?? "")) i++;
    } else if (s[i] === "\\") {
      const d = s[i + 1];
      if (!d || d === "\n" || d === "\\") return false;
      i += 2;
      if (!delimited(d, true)) return false;
      while (/[IM]/.test(s[i] ?? "")) i++;
    }
    return true;
  };
  while (i < s.length) {
    while (i < s.length && /[\s;]/.test(s[i])) i++;
    if (i >= s.length) break;
    if (s[i] === "#") {
      while (i < s.length && s[i] !== "\n") i++;
      continue;
    }
    if (!address()) return false;
    skipBlank();
    if (s[i] === ",") {
      i++;
      skipBlank();
      if (s[i] === "+" || s[i] === "~") i++;
      if (!address()) return false;
      skipBlank();
    }
    if (s[i] === "!") {
      i++;
      skipBlank();
    }
    const c = s[i++];
    if (c === undefined) return false;
    if (c === "{" || c === "}") continue;
    if ("pPdDnNgGhHxlzF=".includes(c)) {
      // `l` and the quit commands may take a number.
    } else if ("qQL".includes(c)) {
      skipBlank();
      while (/\d/.test(s[i] ?? "")) i++;
    } else if (c === ":" || "btTv".includes(c)) {
      while (i < s.length && !/[;\n]/.test(s[i])) {
        if (c !== ":" && s[i] === "}") break;
        i++;
      }
    } else if ("aic".includes(c)) {
      // Text to the end of the line; a backslash at the end continues it.
      for (; i < s.length && s[i] !== "\n"; i++) if (s[i] === "\\") i++;
    } else if (c === "s" || c === "y") {
      const d = s[i++];
      if (!d || d === "\\" || d === "\n") return false;
      if (!delimited(d, c === "s") || !delimited(d)) return false;
      if (c === "s") {
        while (i < s.length && /[gpiImMe\dw]/.test(s[i])) {
          if (s[i] === "e" || s[i] === "w") return false;
          i++;
        }
      }
    } else return false;
    skipBlank();
    if (i < s.length && !/[;\n}#]/.test(s[i])) return false;
  }
  return true;
}

// GNU sed permutes options before `--` (project review 3, round 9: `sed 's/a/b/' ../outside.txt -i`
// edits in place; abbreviated long options like `--in` / `--in-pl` are also accepted by getopt_long).
export interface SedReading {
  inPlace: boolean;
  sandbox: boolean;
  debug: boolean;
  scripts: string[];
  scriptFiles: string[];
  files: string[];
  suffixes: string[];
  loadsFile: boolean;
  unknownShort?: string;
  unknownLong?: string;
}
export function sedReading(args: string[]): SedReading {
  const scripts: string[] = [];
  const scriptFiles: string[] = [];
  const pos: string[] = [];
  const suffixes: string[] = [];
  let inPlace = false;
  let sandbox = false;
  let debug = false;
  let loadsFile = false;
  let unknownShort: string | undefined;
  let unknownLong: string | undefined;
  let ended = false;
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (ended || a === "-" || !a.startsWith("-")) {
      pos.push(a);
      continue;
    }
    if (a === "--") {
      ended = true;
      continue;
    }
    if (a.startsWith("--")) {
      if (a === "--sandbox") sandbox = true;
      else if (a === "--debug") debug = true;
      else if (a === "--expression") scripts.push(args[++k] ?? "");
      else if (a.startsWith("--expression=")) scripts.push(a.slice(13));
      else if (a === "--in-place") inPlace = true;
      else if (a.startsWith("--in-place=")) {
        inPlace = true;
        if (a.length > 11) suffixes.push(a.slice(11));
      } else if (a === "--file" || a.startsWith("--file=")) {
        loadsFile = true;
        scriptFiles.push(a === "--file" ? (args[++k] ?? "") : a.slice(7));
      } else if (a === "--line-length") k++;
      else if (/^--(quiet|silent|regexp-extended|separate|unbuffered|null-data|posix|follow-symlinks|binary)$/.test(a) || /^--line-length=\d+$/.test(a)) continue;
      else unknownLong ??= a;
      continue;
    }
    for (let j = 1; j < a.length; j++) {
      const ch = a[j];
      if ("nErsuzb".includes(ch)) continue;
      if (ch === "i") {
        inPlace = true;
        if (j + 1 < a.length) suffixes.push(a.slice(j + 1));
        break;
      }
      if (ch === "e" || ch === "l" || ch === "f") {
        const value = j + 1 < a.length ? a.slice(j + 1) : args[++k];
        if (ch === "e") scripts.push(value ?? "");
        else if (ch === "f") {
          loadsFile = true;
          scriptFiles.push(value ?? "");
        }
        break;
      }
      unknownShort ??= `-${ch}`;
      break;
    }
  }
  const hasScriptOpt = scripts.length > 0 || loadsFile;
  const files = hasScriptOpt ? pos : pos.slice(1);
  if (!hasScriptOpt) scripts.push(pos[0] ?? "");
  return { inPlace, sandbox, debug, scripts, scriptFiles, files, suffixes, loadsFile, unknownShort, unknownLong };
}

function sed(args: string[], scope: Scope): Verdict {
  const r = sedReading(args);
  if (r.unknownLong) return { ...ask(`sed ${r.unknownLong.split("=")[0]}: an option the rules do not read`), spelling: true };
  if (r.loadsFile) return classify("sed runs a script from a file");
  if (r.unknownShort) return classify(`sed ${r.unknownShort}: an option the rules do not model`);
  if (!r.sandbox && !r.scripts.every(sedScriptSafe)) return classify("sed script that runs commands or reads or writes other files");
  // After a `--` every word is a file (round 40, Opus).
  return r.inPlace ? writeTargets("sed", ["script", "--", ...r.files], scope) : ALLOW;
}

// An awk program that only reads its input and prints. Not: system(), getline (from a command or
// a file), a pipe (`|` that is not `||`), print or printf redirected to a file, and gawk's `@`
// (indirect calls, @include, @load).
const awkSafe = (program: string) => !/\bsystem\b|\bgetline\b|@|\|&|\bprintf?\b[^;{}\n]*[>|]|[>|]\s*"/.test(program.replace(/\|\|/g, " "));

function awk(args: string[]): Verdict {
  const programs: string[] = [];
  let k = 0;
  for (; k < args.length && args[k].startsWith("-") && args[k] !== "-"; k++) {
    const a = args[k];
    if (a === "--") {
      k++;
      break;
    }
    if (a === "-F" || a === "-v") k++;
    else if (/^-[Fv]./.test(a) || /^--(field-separator|assign)=/.test(a)) continue;
    else if (a === "-e" || a === "--source") programs.push(args[++k] ?? "");
    else if (/^--source=/.test(a)) programs.push(a.slice(9));
    else if (/^-e./.test(a)) programs.push(a.slice(2));
    // -f, -i and -l load a program, a library or an extension; -o, -d and -p write files.
    else return classify(`awk ${a}: an option that loads code or writes files`);
  }
  if (!programs.length) programs.push(args[k] ?? "");
  return programs.every(awkSafe) ? ALLOW : classify("awk that runs commands or reads or writes other files");
}

// make reads its makefile and runs the recipes in it; what can change that from the command line:
// --eval, a makefile from standard input or a descriptor, and variables set to text that is not a
// plain word (`make CC='id;'`) or that make itself reads (SHELL, MAKEFLAGS).
function make(args: string[], scope: Scope): Verdict {
  for (let k = 0; k < args.length; k++) {
    const a = args[k];
    if (longIs(a, "eval") || shortIn(a, "E", "fCIjlWo")) return classify("make --eval runs text as a makefile");
    // (Project review 5, round 1, cross-check, Opus: in a cluster, the first letter that takes a
    // value takes the rest of the word or the next one, `make -kC /etc all`, `make -kf -`.)
    const at = /^-[^-]/.test(a) ? [...a.slice(1)].findIndex((l) => "fCIjlWo".includes(l)) + 1 : 0;
    const short = at > 0 ? [a[at], a.slice(at + 1) || args[k + 1]] : [];
    // (Round 2, Mythos: make takes a long name by any prefix, `--dir=/etc`, `--direc /etc`.)
    const long = (...names: string[]) => (names.some((n) => longIs(a, n)) ? (a.includes("=") ? a.slice(a.indexOf("=") + 1) : args[k + 1]) : undefined);
    const file = long("file", "makefile") ?? (short[0] === "f" ? short[1] : undefined);
    if (file !== undefined && (file === "-" || (/^\/dev\/|^\/proc\//.test(file) && file !== "/dev/null") || /[$`]/.test(file))) return classify("make reads its makefile from a stream");
    const dir = long("directory") ?? (short[0] === "C" ? short[1] : undefined);
    if (dir !== undefined && !isLocal(resolveWord(dir, scope), scope)) return classify("make in a directory outside the working directory");
    const m = /^([A-Za-z_.][\w.]*)\+?[:?!]?=(.*)$/s.exec(a);
    if (m && (/^(SHELL|\.SHELLFLAGS|MAKEFLAGS|MFLAGS|MAKE|MAKEFILES|MAKEFILE_LIST|\.RECIPEPREFIX)$/.test(m[1]) || !/^[\w.+,:=%@\/-]*$/.test(m[2]))) {
      return classify(`make ${m[1]}=: a value the recipes may run`);
    }
  }
  return ALLOW;
}

// tar options that run a program: a checkpoint action, a compressor, --to-command, the volume
// scripts, a remote shell; and an archive named host:file, which tar opens through rsh.
function tarProblem(args: string[]): string | undefined {
  const t = tarReading(args);
  const running = ["checkpoint-action", "use-compress-program", "to-command", "info-script", "new-volume-script", "rsh-command", "rmt-command"];
  const run = running.find((name) => t.has(name));
  if (run) return `tar --${run} runs a program`;
  // Short clusters, and the old style where the first word is a cluster without its dash, read by
  // position: a dash cluster's letters end at one that takes a value (round 42, the reader's).
  if (t.letter("I") || t.letter("F")) return "tar -I or -F runs a program";
  if (t.archives.some((f) => /^[^/]*:/.test(f)) && !t.has("force-local")) return "tar on a remote archive runs a remote shell";
  return undefined;
}

// Modules that are built in, or that `python3 -m unittest` has imported before it looks a name up
// (CPython 3.13); a project package of the same name does not take their place.
const UNITTEST_LOADED = new Set(
  `abc argparse array ast atexit binascii builtins bz2 cmath codecs collections contextlib copy copyreg dataclasses difflib dis encodings enum
   errno faulthandler fcntl fnmatch functools gc genericpath gettext grp heapq importlib inspect io itertools keyword linecache locale lzma
   marshal math opcode operator os posix posixpath pprint pwd pyexpat re reprlib runpy select shutil signal site sitecustomize stat sys syslog
   textwrap time token tokenize traceback types unicodedata unittest warnings weakref zipimport zlib`.split(/\s+/),
);

// The names `python3 -m unittest` is given (it imports and calls each): files or modules of the
// project, read from where the command runs, or `discover` with its options.
// What a tool that deletes files as a side effect (rsync --delete or --remove-source-files, tar
// --remove-files) may delete: outside the project and in a .git directory, as rm -r would; the
// project's own files are left to the decider as before (the maintainer's d-fixes D5 decisions).
function deletion(target: string, scope: Scope): Verdict {
  const v = rm(["-r", "--", target], scope);
  if (v.action === "ask" && /deletes the whole project/.test(v.reason)) {
    const p = resolveWord(target, scope);
    return p && /(^|\/)\.git(\/|$)/.test(p) ? v : ALLOW;
  }
  return v;
}

// `python3 -m venv DIR...` and `uv venv [DIR]`: each directory is written; with `--clear` it is
// emptied first, as `rm -r` would.
function venvTargets(args: string[], valued: string[], scope: Scope): Verdict {
  const dashes = args.indexOf("--");
  const dirs = [...(dashes < 0 ? args : args.slice(0, dashes)).filter((a, k) => !a.startsWith("-") && !valued.includes(args[k - 1] ?? "")), ...(dashes < 0 ? [] : args.slice(dashes + 1))];
  const clear = (dashes < 0 ? args : args.slice(0, dashes)).some((a) => (longIs(a, "clear") && a.length > 3) || a === "-c");
  let verdict = ALLOW;
  for (const d of dirs) {
    const p = resolveWord(d, scope);
    if (p && /(^|\/)\.git(\/|$)/.test(p)) verdict = worst(verdict, ask(`a virtual environment in a .git directory: ${d}`));
    verdict = worst(verdict, clear ? rm(["-r", "--", d], scope) : writeTargets("mkdir", ["--", d], scope));
  }
  return verdict;
}

function unittestNamesOwn(args: string[], scope: Scope): boolean {
  if (args[0] === "discover") return true;
  // Every word after `--` is a name (round 36, Mythos).
  const dash = args.indexOf("--");
  const head = dash < 0 ? args : args.slice(0, dash);
  const names = [...head.filter((a, k) => !a.startsWith("-") && !/^(-k|--durations)$/.test(head[k - 1] ?? "")), ...(dash < 0 ? [] : args.slice(dash + 1))];
  if (!names.length) return true;
  if (!scope.cwd) return false;
  const cwd = scope.cwd;
  return names.every((name) => {
    let n = name;
    if (/[$`]/.test(n)) return false;
    // A path to a test file: unittest turns it into the dotted name it imports (`code/interact.py`
    // is `code.interact`, which a directory without __init__.py leaves to the standard module), so
    // it is held to the same walk (round 36, Opus and Mythos).
    if (n.includes("/") || n.endsWith(".py")) {
      const p = resolveWord(n, scope);
      if (!p || !isLocal(p, scope) || inTmp(p) || !/\.py$/.test(p) || !within(p, cwd, true)) return false;
      n = path.relative(cwd, p).slice(0, -3).split(path.sep).join(".");
    }
    // A dotted name: packages (directories with __init__.py) down to a module file, then at most a
    // class and a method that the module's own text defines. (Round 35, all four: unittest walks
    // any attribute after the module, `test_a.unittest.case.sys.breakpointhook`, and calls what it
    // reaches; a directory without __init__.py does not shadow a standard module.)
    const parts = n.split(".");
    if (!parts.every((p) => /^[A-Za-z_]\w*$/.test(p))) return false;
    // A built-in module, or one python -m unittest has loaded by then, is never the project's
    // (round 37, Mythos: `builtins.breakpoint` with a `builtins/` package).
    if (UNITTEST_LOADED.has(parts[0]) || parts[0].startsWith("_")) return false;
    let dir = cwd;
    for (let i = 0; i < parts.length; i++) {
      const file = path.join(dir, `${parts[i]}.py`);
      if (fs.existsSync(path.join(dir, parts[i], "__init__.py")) && i < parts.length - 1 && !fs.existsSync(file)) {
        dir = path.join(dir, parts[i]);
        continue;
      }
      if (!fs.existsSync(file)) return fs.existsSync(path.join(dir, parts[i], "__init__.py")) && i === parts.length - 1 && within(dir, cwd);
      const rest = parts.slice(i + 1);
      if (rest.length > 2) return false;
      if (!rest.length) return isLocal(file, scope) && !inTmp(file);
      // A regular file of a modest size only: a FIFO named like a module would hold the decision.
      let text = "";
      try {
        const st = fs.statSync(file);
        if (!st.isFile() || st.size > 4_000_000) return false;
        text = fs.readFileSync(file, "utf8");
      } catch {
        return false;
      }
      if (rest[0] && !new RegExp(`^class ${rest[0]}\\b`, "m").test(text)) return false;
      if (rest[1] && !new RegExp(`^[ \\t]+(async[ \\t]+)?def ${rest[1]}\\b`, "m").test(text)) return false;
      return isLocal(file, scope) && !inTmp(file);
    }
    return false;
  });
}

// ---- nested shells ----

// Options of bash and sh that can come before -c without changing how the code is read.
const SHELL_FLAGS = "euxvfhlETCPBHnp";
const SHELL_SET_O = /^(errexit|nounset|pipefail|xtrace|verbose|noglob|noclobber|errtrace|functrace|noexec|hashall)$/;

// `bash -c CODE`: CODE is parsed as a command line, for bash, sh and dash only (zsh and ksh read
// it differently), when no option before it changes how it is read, and when the outer shell
// does not expand anything in it. `bash SCRIPT`: the script runs.
function shell(name: string, args: string[], dyn: (k: number) => boolean, cmd: Simple, scope: Scope, depth: number): Verdict {
  let k = 0;
  let code = false;
  for (; k < args.length && /^[-+]/.test(args[k]) && args[k] !== "-" && args[k] !== "--"; k++) {
    const a = args[k];
    if (/^--(norc|noprofile|login|posix|noediting)$/.test(a)) continue;
    if (/^[-+]o$/.test(a)) {
      if (!SHELL_SET_O.test(args[++k] ?? "")) return classify(`${name} ${a} ${args[k] ?? ""}: an option that changes how the code is read`.trim());
      continue;
    }
    for (const ch of a.slice(1)) {
      if (ch === "c") code = true;
      else if (ch === "o") {
        if (!SHELL_SET_O.test(args[++k] ?? "")) return classify(`${name} -o ${args[k] ?? ""}: an option that changes how the code is read`.trim());
      } else if (!SHELL_FLAGS.includes(ch)) return classify(`${name} -${ch}: an option the rules do not model`);
    }
  }
  if (args[k] === "--" || args[k] === "-") k++;
  // -n reads the code without running it.
  if (args.slice(0, k).some((a) => /^-[a-zA-Z]*n/.test(a))) return ALLOW;
  if (!code) {
    const [script, ...rest] = args.slice(k);
    return (script && !cmd.heredoc && runFile(script, rest, scope)) || classify(`runs a script with ${name}`);
  }
  if (name === "zsh" || name === "ksh") return classify(`${name} -c: code that ${name} reads differently from bash`);
  if (dyn(k)) return classify(`${name} -c of code the outer shell expands first`);
  const text = args[k] ?? "";
  // dash reads these as bash does not: `&>` is a background job, `$'` a dollar sign.
  if ((name === "sh" || name === "dash") && /\$['"]|&>|<<<|\|&|\[\[|\(\(|[<>]\(/.test(text)) return classify(`${name} -c with syntax that sh reads differently from bash`);
  if (depth > 3) return classify(`${name} -c nested too deeply`);
  return evaluateParsed(parse(text), scope, depth + 1);
}

// rsync's command line read by position, as its option parser reads it (round 41, all four):
// options anywhere until `--`, a value after each option that takes one (attached, after `=`, or
// the next word, and in a short cluster the rest of the word after a letter that takes one).
// (Round 42, Mythos and Opus: rsync takes no abbreviated long option, `--dry` is an error, so a
// name is matched whole; `--munge-links` is a flag; the list is rsync 3.5's `--help` with the
// aliases it keeps, `--log-format`, `--cc`, `--zc`, `--zl`, `--zt`, `--time-limit`.)
const RSYNC_LONG_VALUED = new Set(`out-format log-format log-file log-file-format rsh exclude include filter files-from exclude-from include-from
  password-file partial-dir temp-dir backup-dir suffix compare-dest copy-dest link-dest chmod chown usermap groupmap timeout contimeout
  bwlimit max-size min-size block-size port sockopts outbuf remote-option iconv checksum-choice cc compress-choice zc compress-level zl
  compress-threads zt skip-compress info debug modify-window max-delete max-alloc stop-after time-limit stop-at write-batch read-batch
  only-write-batch protocol address rsync-path config dparam checksum-seed early-input copy-as confine-root stderr`.split(/\s+/));
// (Round 55, Astra: rsync opens `--include-from`/`--exclude-from` files and the files of `merge`
// and `.` filter rules as it reads each option, before a later `--help` or any `--version`
// prints; `dir-merge`, `:` and `--files-from` open nothing then: tried, rsync 3.5.0.)
// (Round 56, Opus: a short `.` rule takes its modifiers without a comma, `.-`, `.e`, and `merge,`
// takes `/` among them; any modifiers are matched, which only over-asks on ones rsync refuses.)
const RSYNC_EAGER_RULE = /^(?:merge(?:,[^ _]*)?|\.[^ _]*)[ _](.+)$/;
export function rsyncReading(args: string[]) {
  const longs: [string, string | undefined][] = [];
  const letters: string[] = [];
  const shorts: [string, string | undefined][] = [];
  const operands: string[] = [];
  // The files opened while the options are read, in order, with each help word's place.
  const order: { opens?: string; help?: true }[] = [];
  const eager = (name: string, value: string | undefined) => {
    if (value === undefined) return;
    if (name === "include-from" || name === "exclude-from") order.push({ opens: value });
    const rule = name === "filter" ? RSYNC_EAGER_RULE.exec(value) : null;
    if (rule) order.push({ opens: rule[1] });
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      operands.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const head = eq < 0 ? a : a.slice(0, eq);
      const value = eq >= 0 ? a.slice(eq + 1) : RSYNC_LONG_VALUED.has(head.slice(2)) ? args[++i] : undefined;
      longs.push([head, value]);
      eager(head.slice(2), value);
      if (head === "--help" || ((head === "--info" || head === "--debug") && (value ?? "").split(",").some((t) => /^help\d*$/i.test(t)))) order.push({ help: true });
    } else if (a.startsWith("-") && a.length > 1) {
      for (let k = 1; k < a.length; k++) {
        letters.push(a[k]);
        if ("eTfBM@".includes(a[k])) {
          // (Round 43, Opus and Mythos: popt drops a `=` before an attached value, `-T=dir`.)
          const value = k < a.length - 1 ? a.slice(k + 1).replace(/^=/, "") : args[++i];
          shorts.push([a[k], value]);
          if (a[k] === "f") eager("filter", value);
          break;
        }
      }
    } else operands.push(a);
  }
  // What only takes away (a dry run, a listing) is matched whole; what adds a danger by any prefix.
  const has = (name: string) => longs.some(([h]) => h === `--${name}`);
  const prefixed = (name: string) => longs.some(([h]) => h.length >= 4 && `--${name}`.startsWith(h));
  const dryRun = letters.includes("n") || has("dry-run");
  const listOnly = has("list-only");
  // (Round 42, Mythos: `--read-batch` replays a recorded update into its one operand.)
  const batch = prefixed("read-batch");
  // (Round 43, Mythos: `--server` writes what standard input sends into its operand, which is no
  // source; Sol: a dry run of a batch writes nothing.)
  const server = prefixed("server") || prefixed("sender");
  // (Round 46, Sol: `--version`, `-V` and `--help` print and copy nothing.)
  // (Round 47, Sol: `--version` still opens its `--log-file`; `--help` opens nothing.)
  // (Round 48, Astra: `--info=help` and `--debug=help` print their lists and exit too. Round 49:
  // a `help` among the words of the list, in any case, `--info=name,HELP`, `--debug=help0`; and
  // rsync reads its options in order, so a `--log-file` before the help word is opened and the
  // help written into it (Opus): help writes nothing only where it comes first.)
  const isHelp = ([h, v]: [string, string | undefined]) => h === "--help" || ((h === "--info" || h === "--debug") && (v ?? "").split(",").some((t) => /^help\d*$/i.test(t)));
  const firstHelp = longs.findIndex(isHelp);
  const firstLog = longs.findIndex(([h, v]) => h === "--log-file" && v !== "");
  const help = firstHelp >= 0 && (firstLog < 0 || firstHelp < firstLog);
  const prints = has("version") || firstHelp >= 0 || letters.includes("V");
  // The files opened before a help or version query exits: those before the first help word, or
  // all of them for a version query.
  const helpAt = order.findIndex((e) => e.help);
  const opensBeforeExit = (helpAt >= 0 ? order.slice(0, helpAt) : order).flatMap((e) => (e.opens !== undefined ? [e.opens] : []));
  // (Project review 3, round 8, Neon: one operand that bash may expand into several words,
  // `rsync sub/*`, `rsync ../*`, has an unknown operand count and may copy.)
  return { longs, letters, shorts, operands, dryRun, listOnly, batch, server, prints, help, opensBeforeExit, daemon: prefixed("daemon"), copiesNothing: prints || (!server && (dryRun || listOnly || (!batch && operands.length < 2 && !operands.some((o) => MAY_EXPAND.test(o))))), values: (name: string) => {
      // (Round 48, Sol: the last `--log-file` is the one rsync opens, and an empty one none.)
      // A help word stops the reading where it stands: a log named after it is never opened.
      const all = (firstHelp >= 0 ? longs.slice(0, firstHelp) : longs).filter(([h]) => h === `--${name}`).map(([, v]) => v ?? "");
      return name === "log-file" ? all.slice(-1).filter((v) => v !== "") : all;
    } };
}

// tar's command line read by position (round 41): the old style (a first word of letters without
// a dash, whose letters that take a value take the next words in turn), short clusters, long
// options with their values, and `--` ending the options only where an option stands.
// (Round 42, all four: GNU tar takes a long option by a prefix only where the prefix names one
// option, and a whole name wins, `--list` over `--listed-incremental`; `--backup`, `--occurrence`,
// `--checkpoint` and the like take a value only after `=`. The names are tar 1.35's `--help`,
// with the hidden `--program-name` (a value) and `--HANG` (round 43, Mythos).)
const TAR_LONG_VALUED = `add-file after-date blocking-factor checkpoint-action directory exclude exclude-from exclude-ignore exclude-ignore-recursive
  exclude-tag exclude-tag-all exclude-tag-under file files-from format group group-map hole-detection index-file info-script label level
  listed-incremental mode mtime new-volume-script newer newer-mtime no-quote-chars owner owner-map pax-option quote-chars quoting-style
  record-size rmt-command rsh-command sort sparse-version starting-file strip-components suffix tape-length to-command transform
  use-compress-program volno-file warning xattrs-exclude xattrs-include xform program-name`.split(/\s+/);
const TAR_LONG_FLAGS = `absolute-names acls anchored append atime-preserve auto-compress backup block-number bzip2 catenate check-device check-links
  checkpoint clamp-mtime compare compress concatenate confirmation create delay-directory-restore delete dereference diff exclude-backups
  exclude-caches exclude-caches-all exclude-caches-under exclude-vcs exclude-vcs-ignores extract force-local full-time get gunzip gzip
  hard-dereference help ignore-case ignore-command-error ignore-failed-read ignore-zeros incremental interactive keep-directory-symlink
  keep-newer-files keep-old-files list lzip lzma lzop multi-volume no-acls no-anchored no-auto-compress no-check-device
  no-delay-directory-restore no-ignore-case no-ignore-command-error no-null no-overwrite-dir no-recursion no-same-owner no-same-permissions
  no-seek no-selinux no-unquote no-verbatim-files-from no-wildcards no-wildcards-match-slash no-xattrs null numeric-owner occurrence
  old-archive one-file-system one-top-level overwrite overwrite-dir portability posix preserve-order preserve-permissions read-full-records
  recursion recursive-unlink remove-files restrict same-order same-owner same-permissions seek selinux show-defaults show-omitted-dirs
  show-snapshot-field-ranges show-stored-names show-transformed-names skip-old-files sparse test-label to-stdout totals touch uncompress
  ungzip unlink-first unquote update usage utc verbatim-files-from verbose verify version wildcards wildcards-match-slash xattrs xz zstd HANG`.split(/\s+/);
const TAR_LONGS = [...TAR_LONG_VALUED, ...TAR_LONG_FLAGS];
// The option a long word names, as getopt_long reads it: a whole name, else the one name it is a
// prefix of. Undefined where it names none or several (tar stops with an error).
export const tarLong = (head: string) => {
  const name = head.slice(2);
  if (TAR_LONGS.includes(name)) return name;
  const all = TAR_LONGS.filter((n) => n.startsWith(name));
  return name && all.length === 1 ? all[0] : undefined;
};
const TAR_SHORT_VALUED = "bCfFgHIKLNTVX";
export function tarReading(args: string[]) {
  const clusters: string[] = [];
  const longs: [string, string | undefined][] = [];
  const archives: string[] = [];
  const dirs: string[] = [];
  const members: string[] = [];
  const shortValues: (string | undefined)[] = [];
  const takeShort = (letter: string, value: string | undefined) => {
    if (letter !== "f") shortValues.push(value);
    if (letter === "f" && value !== undefined) archives.push(value);
    if (letter === "C" && value !== undefined) dirs.push(value);
  };
  let i = 0;
  // (Round 43, Mythos: tar takes any first word without a dash as the old style, and a `-` in it
  // ends the options as `--` would: `tar cIf- ./x.sh b.tar f`.)
  let ended = false;
  if (args[0] && !args[0].startsWith("-")) {
    const dash = args[0].indexOf("-");
    const letters = dash < 0 ? args[0] : args[0].slice(0, dash);
    clusters.push(letters);
    i = 1;
    for (const letter of letters) if (TAR_SHORT_VALUED.includes(letter)) takeShort(letter, args[i++]);
    ended = dash >= 0;
  }
  if (ended) members.push(...args.slice(i));
  else for (; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      members.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const head = eq < 0 ? a : a.slice(0, eq);
      const full = tarLong(head);
      const value = eq >= 0 ? a.slice(eq + 1) : full && TAR_LONG_VALUED.includes(full) ? args[++i] : undefined;
      // The whole name where it names one; the word as written where it names none or several.
      longs.push([full ? `--${full}` : head, value]);
      if (full === "file" && value !== undefined) archives.push(value);
      if (full === "directory" && value !== undefined) dirs.push(value);
    } else if (a.startsWith("-") && a.length > 1) {
      // The letters only: in `-tfFILM` the rest of the word after `f` is the archive's name.
      let k = 1;
      while (k < a.length && !TAR_SHORT_VALUED.includes(a[k])) k++;
      clusters.push(a.slice(1, k + 1));
      if (k < a.length) takeShort(a[k], k < a.length - 1 ? a.slice(k + 1) : args[++i]);
    } else members.push(a);
  }
  const has = (name: string) => longs.some(([h]) => h === `--${name}`);
  const values = (name: string) => longs.filter(([h]) => h === `--${name}`).map(([, v]) => v ?? "");
  const letter = (l: string) => clusters.some((c) => c.includes(l));
  // The words an option other than `-f`/`--file` took as its value (round 44, Sol and Astra).
  const optionValues = [...longs.filter(([h]) => h !== "--file").map(([, v]) => v), ...shortValues].filter((v): v is string => v !== undefined);
  return { clusters, longs, archives, dirs, members, has, values, letter, optionValues };
}

// Whether ps prints environments (round 42, all four), read as procps-ng 4 reads its words: a
// word with one dash is a cluster of UNIX letters, one without a dash of BSD letters, and in both a
// letter that takes a value takes the rest of the word or the next word; a long option takes the
// next word where it takes a value. BSD `e` prints them, so does the field `environ` in a format
// (`-o`, `-O`, `o`, `O`, `--format`; a sort key prints nothing), the fields split at commas and
// blanks, and what follows a `=` in one value its heading.
// (Round 43, Mythos: where the UNIX reading fails, a letter that is no UNIX option, `-ex`, or a
// letter that takes a value with none left, `-e -t`, procps reads the dash words again as BSD
// ones, and a UNIX `e` then prints environments. Opus: `-N` is a flag; `--format:` takes a value.)
// (Round 52, Opus: procps-ng 4's `-D`/`--date-format` takes a value too.)
const PS_UNIX_VALUED = "CDGgoOpqstuU";
const PS_UNIX_FLAGS = "AacdefFHjLlMmNPTVwyZ";
const PS_BSD_VALUED = "oOkpqtU";
const PS_LONG_VALUED = /^--(format|sort|cols|columns|width|rows|lines|pid|ppid|tty|user|User|group|Group|sid|quick-pid|date-format)$/;
// The user and group names this machine knows (round 45: an attached name the UNIX reading takes).
let knownNames: Set<string> | undefined;
const namesHere = () => {
  if (!knownNames) {
    knownNames = new Set();
    for (const file of ["/etc/passwd", "/etc/group"]) {
      try {
        for (const line of fs.readFileSync(file, "utf8").split("\n")) if (line && !line.startsWith("#")) knownNames.add(line.split(":")[0]);
      } catch {}
    }
  }
  return knownNames;
};
// Whether the UNIX reading takes a value attached to its letter (round 45, Sol and Astra): a list
// of numbers (`-p1`, `-p+1`, `-u0`, `-p'1 2'`) for a letter that takes ids, a command name for
// `-C`, and, where ps runs here, names this machine knows for `-u`/`-U`/`-g`/`-G`.
// (Round 46, Sol and Astra: a list mixing ids and names, `-u0,root`; a terminal `-t-`, `-t'?'`
// or one this machine has.)
function psValueTaken(letter: string, value: string, here: boolean): boolean {
  if ("oOCD".includes(letter)) return true;
  const items = value.split(/[,\s]+/);
  if (!items.length || items.some((n) => n === "")) return false;
  if ("pqs".includes(letter)) return items.every((n) => /^\+?\d+$/.test(n));
  if ("uUgG".includes(letter)) return items.every((n) => /^\+?\d+$/.test(n) || (here && namesHere().has(n)));
  // (Round 47, Astra: an absolute path to a terminal, `-t/dev/tty`.)
  if (letter === "t") return items.every((n) => n === "-" || n === "?" || (here && /^[\w/]+$/.test(n) && (n.startsWith("/dev/") ? fs.existsSync(n) : ["", "tty", "pts/"].some((p) => fs.existsSync(`/dev/${p}${n}`)))));
  return false;
}
// The format fields procps-ng 4.0.4 knows made of letters only (`ps L`), and `environ`.
const PS_LETTER_FIELDS = new Set(`environ ${`args atime blocked bsdstart bsdtime c caught cgname cgroup cgroupns class cls cmd comm command context cp cpuid
  cputime cputimes cuc cuu drs dsiz egid egroup eip esp etime etimes euid euser exe f fgid fgroup flag flags fname fsgid
  fsgroup fsuid fsuser fuid fuser gid group ignored intpri ipcns label lastcpu lim longtname lsession lstart luid lwp
  lxc machine majflt minflt mntns netns ni nice nlwp numa oom oomadj opri ouid pagein pcpu pending pgid pgrp pid pidns
  pmem policy ppid pri priority psr pss rbytes rchars rgid rgroup rops rss rssize rsz rtprio ruid ruser s sched seat
  sess session sgid sgroup sid sig sigcatch sigignore sigmask size slice spid stackp start stat state stime suid supgid
  supgrp suser svgid svgroup svuid svuser sz tgid thcount tid time timens times tname tpgid trs trss tsig tsiz tt tty
  ucmd ucomm uid uname unit user userns uss util utsns uunit vsize vsz wbytes wcbytes wchan wchars wname wops zone`}`.split(/\s+/));
export function psEnvironments(args: string[], here = true): boolean {
  const formats: string[] = [];
  let unixE = false;
  let again = false;
  // The UNIX letters read as flags, not values (round 48, Sol and Astra: in `-C -H` the `-H` is a
  // command's name).
  let unixFlags = "";
  let forest = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith("--")) {
      const cut = a.search(/[=:]/);
      const head = cut < 0 ? a : a.slice(0, cut);
      const value = cut >= 0 ? a.slice(cut + 1) : PS_LONG_VALUED.test(head) ? args[++i] : undefined;
      if (head === "--format" && value !== undefined) formats.push(value);
      if (head === "--forest") forest = true;
      continue;
    }
    const unix = a.startsWith("-");
    const valued = unix ? PS_UNIX_VALUED : PS_BSD_VALUED;
    // Read again as BSD, a dash word's letters up to an `o` (which takes the rest) are flags.
    if (unix && a.slice(1).split(/[oO]/)[0].includes("e")) unixE = true;
    for (let k = unix ? 1 : 0; k < a.length; k++) {
      if (!unix && a[k] === "e") return true;
      // (Round 53, Opus: procps takes the rest of the word as `-D`'s date format and still reads
      // its letters as options, `ps -Doenviron`: they are read on.)
      if (unix && a[k] === "D" && k < a.length - 1) continue;
      if (valued.includes(a[k])) {
        const value = k < a.length - 1 ? a.slice(k + 1) : args[++i];
        // (Round 48, Opus: a UNIX `-O` given BSD sort keys, `-O p`, `-O +pt`, is refused by the
        // format reader and read again as BSD: procps-ng 4.0.4.)
        // (Round 49, Astra: only BSD's sort-key letters; a format macro, `THREAD`, `DefSysV`, is
        // read as one.)
        if (unix && a[k] === "O" && value !== undefined && /^([+-]?[gjkmnoprtuvyCGJKMNPRSTU])+$/.test(value) && (/[+-]/.test(value) || !PS_LETTER_FIELDS.has(value))) again = true;
        // A value the UNIX reading may refuse (`-uaxe` names the user `axe`) sends it to BSD; a
        // value it takes does not (round 44 and 45, Sol and Astra). A separate word that starts
        // with `-` is refused, and the BSD reading takes it (round 45, Opus: `ps -e -u -x`).
        // (`-C` takes any word as a command's name, `-C -x` too, round 46, Astra.)
        // (Round 47, Sol and Astra: `-t -` names no terminal, as `-t-` does.)
        if (unix && (value === undefined || (k < a.length - 1 ? !psValueTaken(a[k], value, here) : value.startsWith("-") && !"oOCD".includes(a[k]) && !(a[k] === "t" && value === "-")))) again = true;
        if ("oO".includes(a[k]) && value !== undefined) formats.push(value);
        break;
      }
      if (unix && !PS_UNIX_FLAGS.includes(a[k])) again = true;
      if (unix) unixFlags += a[k];
    }
  }
  // (Round 47, Opus: procps reads the words again as BSD ones when the UNIX reading fails after
  // parsing too: a thread display beside a forest, `-eTH`, `-eT --forest`; `-L` beside `-m`;
  // `-T` beside `-m` or `-L`.)
  const threads = ["T", "L", "m"].filter((l) => unixFlags.includes(l));
  if ((threads.length && (forest || unixFlags.includes("H"))) || threads.length > 1) again = true;
  if (unixE && again) return true;
  // (Round 44, Opus: read again as BSD, `-u` in `ps -xu -e` takes no value, so `-e` is BSD `e`.)
  if (again) {
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (!a.startsWith("-") || a.startsWith("--")) continue;
      for (let k = 1; k < a.length; k++) {
        if (a[k] === "e") return true;
        if (PS_BSD_VALUED.includes(a[k])) {
          if (k === a.length - 1) i++;
          break;
        }
      }
    }
  }
  return formats.some((f) => {
    for (const field of f.split(/[\s,]+/)) {
      if (field.split(/[=:]/)[0].replace(/^[+-]/, "") === "environ") return true;
      if (field.includes("=")) return false;
    }
    return false;
  });
}

// gzip, xz, zstd and bzip2 read by position (round 42, Mythos and Sol): a letter that takes a value
// ends its cluster (`-Sc` names the suffix `c`), with the rest of the word or the next word, and
// zstd's `-T4`-like letters with the rest of the word only. A listing, a test or output to
// standard output writes nothing in place; `-o` names the file written.
// (Round 43, Opus, Mythos, Sol, Astra: gzip and xz take a long option by any prefix that names one
// (getopt_long: `--su` is `--suffix`, `--tes` is `--test`), bzip2 and zstd only whole; zstd's `-o`
// takes the next word wherever it stands in a cluster (`-of FILE`), or what follows `=`; zstd
// `--rm` removes its input after an `-o` too; the table is looked up by its own keys.)
type CompressorTable = { family: string; valued: string; attached: string; longs: string[]; longValued: string[]; prefixes: boolean; stdout?: true; decompress?: true };
const XZ_LONGS = `compress decompress uncompress test list keep force stdout to-stdout single-stream no-sparse no-sync suffix files files0 format check
  ignore-check extreme fast best threads block-size block-list flush-timeout memlimit-compress memlimit-decompress memlimit-mt-decompress memlimit
  no-adjust filters filters1 filters2 filters3 filters4 filters5 filters6 filters7 filters8 filters9 filters-help lzma1 lzma2 x86 arm arm64
  armthumb powerpc ia64 sparc riscv delta quiet verbose no-warn robot info-memory help long-help version`.split(/\s+/);
const COMPRESSORS: Record<string, CompressorTable> = {
  gzip: { family: "gzip", valued: "Sb", attached: "", prefixes: true, longValued: ["suffix", "bits"], longs: "ascii to-stdout stdout decompress uncompress force help keep list license no-name name quiet silent synchronous recursive suffix test verbose version fast best lzw bits rsyncable".split(" ") },
  xz: { family: "xz", valued: "SFCTM", attached: "", prefixes: true, longValued: ["suffix", "format", "check", "threads", "block-size", "block-list", "flush-timeout", "memlimit-compress", "memlimit-decompress", "memlimit-mt-decompress", "memlimit", "filters", ...[1, 2, 3, 4, 5, 6, 7, 8, 9].map((n) => `filters${n}`)], longs: XZ_LONGS },
  zstd: { family: "zstd", valued: "", attached: "TBMbei", prefixes: false, longValued: ["trace", "filelist", "output-dir-flat", "output-dir-mirror", "patch-from"], longs: [] },
  bzip2: { family: "bzip2", valued: "", attached: "", prefixes: false, longValued: [], longs: [] },
};
for (const [alias, base, extra] of [["gunzip", "gzip", "d"], ["zcat", "gzip", "dc"], ["unxz", "xz", "d"], ["xzcat", "xz", "dc"], ["lzma", "xz", ""], ["unlzma", "xz", "d"], ["lzcat", "xz", "dc"], ["unzstd", "zstd", "d"], ["zstdcat", "zstd", "dc"], ["zstdmt", "zstd", ""], ["bunzip2", "bzip2", "d"], ["bzcat", "bzip2", "dc"]] as const) {
  COMPRESSORS[alias] = { ...COMPRESSORS[base], ...(extra.includes("d") ? { decompress: true } : {}), ...(extra.includes("c") ? { stdout: true } : {}) };
}
export function compressorReading(name: string, args: string[]) {
  const table = Object.hasOwn(COMPRESSORS, name) ? COMPRESSORS[name] : undefined;
  if (!table) return undefined;
  // The option a long word names: whole, or (getopt_long) the one name it is a prefix of.
  const resolve = (head: string) => {
    const word = head.slice(2);
    if (!table.prefixes || table.longs.includes(word)) return word;
    const all = table.longs.filter((n) => n.startsWith(word));
    return word && all.length === 1 ? all[0] : head;
  };
  const letters: string[] = [];
  const longs: string[] = [];
  const operands: string[] = [];
  const outputs: string[] = [];
  const suffixes: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      operands.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = resolve(eq < 0 ? a : a.slice(0, eq));
      longs.push(name);
      const value = eq >= 0 ? a.slice(eq + 1) : table.longValued.includes(name) ? args[++i] : undefined;
      if (name === "suffix" && value !== undefined) suffixes.push(value);
    } else if (a.startsWith("-") && a.length > 1) {
      for (let k = 1; k < a.length; k++) {
        letters.push(a[k]);
        // (zstd's `-o` and `-D` each take the next word, the cluster going on: `-Do DICT OUT`.)
        if (table.family === "zstd" && (a[k] === "o" || a[k] === "D")) {
          if (a[k + 1] === "=") {
            if (a[k] === "o") outputs.push(a.slice(k + 2));
            break;
          }
          if (i + 1 < args.length) (a[k] === "o" ? outputs : []).push(args[++i]);
          continue;
        }
        // (Round 53, Astra: zstd reads the number after `-T` and goes on, `-T1V` is `-T1 -V`.)
        if (table.attached.includes(a[k])) {
          if (table.family !== "zstd") break;
          while (k + 1 < a.length && /[0-9]/.test(a[k + 1])) k++;
          if (k + 1 < a.length && /[KM]/.test(a[k + 1])) k++;
          if (k + 1 < a.length && a[k + 1] === "i") k++;
          if (k + 1 < a.length && a[k + 1] === "B") k++;
          continue;
        }
        if (table.valued.includes(a[k])) {
          const value = k === a.length - 1 ? args[++i] : a.slice(k + 1);
          if (a[k] === "S" && value !== undefined) suffixes.push(value);
          break;
        }
      }
    } else operands.push(a);
  }
  const long = (...names: string[]) => longs.some((h) => names.includes(h));
  const stdout = !!table.stdout || letters.includes("c") || long("stdout", "to-stdout");
  const test = letters.includes("t") || long("test");
  // (Round 46, Sol: a version, help or licence query prints and writes nothing.)
  // (Round 47, Astra and Sol: xz's `--info-memory` and `--filters-help` print too.)
  const prints = letters.some((l) => "VhH".includes(l) || (l === "L" && table.family !== "xz")) || long("version", "help", "long-help", "license", "info-memory", "filters-help");
  const list = letters.includes("l") || long("list") || prints;
  // A decompression by any prefix getopt would take: the side that adds a write.
  const decompress = !!table.decompress || letters.includes("d") || longs.some((h) => h.length > 0 && ("decompress".startsWith(h.replace(/^--/, "")) || "uncompress".startsWith(h.replace(/^--/, ""))));
  const removes = long("rm");
  // (Round 44, Sol: a listing or a test writes no `-o` file either.)
  const reads = test || list;
  // (Round 45, Opus: what a decompression names its output: the input less its suffix, `-S`'s
  // first; gzip's `-N` takes the name the archive holds, and `-r` the files a directory holds.
  // Round 46, Opus: zstd also takes gzip, xz, lzma and lz4 files and strips their suffixes.)
  // (Round 47, Opus: gzip compares a suffix ignoring case, `.git.GZ`; zstd's `.t*` suffixes end
  // in `.tar`.)
  const DEFAULT_SUFFIXES: Record<string, string[]> = { gzip: [".gz", "-gz", ".z", "-z", "_z", ".tgz", ".taz"], xz: [".xz", ".lzma", ".lz", ".txz", ".tlz"], zstd: [".zst", ".tzst", ".zstd", ".gz", ".tgz", ".xz", ".txz", ".lzma", ".lz4", ".tlz4"], bzip2: [".bz2", ".bz", ".tbz2", ".tbz"] };
  const fold = table.family === "gzip";
  const unnamed = letters.includes("N") && table.family === "gzip" ? "-N" : letters.includes("r") || long("recursive") ? "-r" : long("name") && table.family === "gzip" ? "--name" : undefined;
  const outputName = (input: string) => {
    for (const s of [...suffixes, ...(DEFAULT_SUFFIXES[table.family] ?? [])]) {
      const ends = fold ? input.toLowerCase().endsWith(s.toLowerCase()) : input.endsWith(s);
      if (s && input.length > s.length && ends) return input.slice(0, -s.length) + (/^\.t[a-z0-9]+$/i.test(s) && !suffixes.includes(s) ? ".tar" : "");
    }
    return undefined;
  };
  return { operands, outputs: reads ? [] : outputs, decompress, reads, prints, inPlace: !(stdout || reads) && (!outputs.length || removes), family: table.family, unnamed, outputName };
}

// A copy that copies nothing (round 45, Sol and Opus): an rsync dry run, listing or single
// operand, and a `--help`/`--version` (by a prefix getopt takes) among the option words before
// `--` of cp, mv, ln or install.
// (Round 46, Opus and Astra: read by position, an option's value is no `--help`, `cp -S --help`,
// and no `--` either, `cp -S -- --version`.)
const COPY_VALUED: Record<string, { short: string; long: string[] }> = {
  cp: { short: "St", long: ["suffix", "target-directory", "no-preserve", "sparse"] },
  mv: { short: "St", long: ["suffix", "target-directory"] },
  ln: { short: "St", long: ["suffix", "target-directory"] },
  install: { short: "Stgmo", long: ["suffix", "target-directory", "group", "mode", "owner", "strip-program"] },
};
export function copiesNothing(name: string, args: string[]): boolean {
  if (name === "rsync") return rsyncReading(args).copiesNothing;
  const table = Object.hasOwn(COPY_VALUED, name) ? COPY_VALUED[name] : undefined;
  if (!table) return false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") return false;
    if (a.startsWith("--")) {
      const word = a.slice(2).split("=")[0];
      if (word && "help".startsWith(word)) return true;
      if (word.length >= 4 && "version".startsWith(word)) return true;
      if (!a.includes("=") && word && table.long.some((n) => n.startsWith(word))) i++;
    } else if (a.startsWith("-") && a.length > 1) {
      for (let k = 1; k < a.length; k++) {
        if (table.short.includes(a[k])) {
          if (k === a.length - 1) i++;
          break;
        }
      }
    }
  }
  return false;
}

// Whether sort runs a compressor (round 48, Opus, Sol, Astra): its words read by position, as
// getopt_long reads them, with the options that take a value (GNU sort 9.7); `--` ends the
// options only where an option could stand (`sort --random-source -- --compress-program=sh`).
const SORT_LONGS = `ignore-leading-blanks dictionary-order ignore-case general-numeric-sort ignore-nonprinting month-sort human-numeric-sort
  numeric-sort random-sort random-source reverse sort version-sort batch-size check compress-program debug files0-from key merge output stable
  buffer-size field-separator temporary-directory parallel unique zero-terminated help version`.split(/\s+/);
const SORT_LONG_VALUED = ["random-source", "sort", "batch-size", "compress-program", "files0-from", "key", "output", "buffer-size", "field-separator", "temporary-directory", "parallel"];
// (Round 49, Opus, Sol, Astra: the same reading gives the files `-o`/`--output` name, for the
// guard's write record: `sort --random-source -- -o .git/config f` writes `.git/config`.)
// (Round 50, Opus: `-y` takes a value too, an attached one, GNU sort's `-bcCdfghik:mMno:rRsS:t:T:uVy::z`; Sol,
// Astra: `--help`/`--version` as options print and write nothing.)
// (Round 51, Sol: the files it reads, operands and `--files0-from`/`--random-source` values; a long
// option sort does not know or cannot tell apart, `--ver`, stops it before it does anything.)
// (Round 56, Sol: with `_POSIX2_VERSION` 200112 or later, sort takes no `+POS` key: the word is a
// file.)
// (Round 59, Opus: only for 200112 <= v < 200809; GNU sort takes `+POS` keys again from 200809.)
export const posix2Strict = (v: number) => v >= 200112 && v < 200809;
export function sortReading(args: string[], posix2 = posix2Strict(Number(process.env._POSIX2_VERSION ?? 0))): { compressor: boolean; outputs: string[]; prints: boolean; reads: string[]; lists: string[] } {
  let compressor = false;
  let prints = false;
  const outputs: string[] = [];
  const reads: string[] = [];
  const lists: string[] = [];
  let source: string | undefined;
  let random = false;
  let traditional = false;
  const keys: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      reads.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const word = (eq < 0 ? a : a.slice(0, eq)).slice(2);
      const all = SORT_LONGS.filter((n) => n.startsWith(word));
      const name = SORT_LONGS.includes(word) ? word : all.length === 1 ? all[0] : undefined;
      const value = name && SORT_LONG_VALUED.includes(name) ? (eq >= 0 ? a.slice(eq + 1) : args[++i]) : undefined;
      if (!name) prints = true;
      if (name === "compress-program") compressor = true;
      if (name === "output" && value !== undefined) outputs.push(value);
      // (Round 52, Sol and Astra: only the last `--files0-from` is read, and `--random-source` only
      // in a random sort.)
      if (name === "files0-from" && value !== undefined) lists.splice(0, lists.length, value);
      if (name === "random-source" && value !== undefined) source = value;
      if (name === "random-sort" || (name === "sort" && value !== undefined && "random".startsWith(value) && value !== "")) random = true;
      if (name === "key" && value !== undefined) keys.push(value);
      if (name === "help" || name === "version") prints = true;
    // (Round 57, Astra: under _POSIX2_VERSION 200112 or later, GNU sort still takes `+POS` for a key
    // where a `-POS` follows it. Round 58, Opus: and once it has, every later `+POS` is a key too.
    // POSIXLY_CORRECT is not read: the sandbox gives commands none, Astra and Sol.)
    } else if (/^\+\d+(\.\d+)?[bdfgiMhnRrV]*$/.test(a) && (!posix2 || traditional || /^-\d/.test(args[i + 1] ?? ""))) {
      traditional = true;
      // (Round 54, Sol and Astra: the old key syntax, `+POS1 [-POS2]`, with its modifiers at
      // either end, `sort -R +0n -1`.)
      let key = a.slice(1);
      // (Round 55, Sol: only with modifiers sort takes; `+0xR` is a file.)
      if (/^-\d+(\.\d+)?[bdfgiMhnRrV]*$/.test(args[i + 1] ?? "")) key += `,${args[++i].slice(1)}`;
      keys.push(key);
    } else if (a.startsWith("-") && a.length > 1) {
      for (let k = 1; k < a.length; k++) {
        // (`-y` takes only a value in its own word, `-yk`; alone it takes nothing: `sort -y --
        // -output` sorts the file `-output`, tried.)
        if (a[k] === "y") break;
        if (a[k] === "R") random = true;
        if ("koStT".includes(a[k])) {
          const value = k === a.length - 1 ? args[++i] : a.slice(k + 1);
          if (a[k] === "o" && value !== undefined) outputs.push(value);
          if (a[k] === "k" && value !== undefined) keys.push(value);
          break;
        }
      }
    } else reads.push(a);
  }
  // (Round 53, Opus, Sol, Astra: a key with `R` among its modifiers sorts at random; a key with
  // any modifier of its own takes none of the global ordering options, so a global `-R` is a
  // random sort only where some key has none, or there are no keys.)
  const modifiers = (key: string) => key.replace(/[0-9.,]/g, "");
  const randomized = keys.some((key) => modifiers(key).includes("R")) || (random && (keys.length === 0 || keys.some((key) => modifiers(key) === "")));
  reads.push(...lists, ...(randomized && source !== undefined ? [source] : []));
  return prints ? { compressor: false, outputs: [], prints, reads: [], lists: [] } : { compressor, outputs, prints, reads, lists };
}
export const sortRunsCompressor = (args: string[]) => sortReading(args).compressor;

// Whether a call only prints its help or version and exits (round 50, Sol and Astra), read by the
// tool's own reader so an option's value is no such word: sort, tar, ps, cp/mv/ln/install, the
// compressors, and rsync with its help before any log (a version query still writes its log, and
// is read by rsync's own checks).
export function printsOnly(name: string, args: string[]): boolean {
  if (name === "sort") return sortReading(args).prints;
  if (name === "tar" || name === "gtar") {
    const t = tarReading(args);
    // (Round 51, Astra and Sol: `--show-defaults` and `--show-snapshot-field-ranges` print too.)
    return ["help", "usage", "version", "show-defaults", "show-snapshot-field-ranges"].some((n) => t.has(n)) || t.clusters.some((c) => c.includes("?"));
  }
  if (name === "ps") {
    // (Round 51, Sol and Astra: read as psEnvironments reads the words: `-N` is a flag, `-opcpu`
    // holds its value; `--help:all` as `--help=all`.)
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (/^--(help|version|info)([=:]|$)/.test(a)) return true;
      if (a.startsWith("--")) {
        if (PS_LONG_VALUED.test(a)) i++;
        continue;
      }
      const unix = a.startsWith("-");
      if (a === "-V" || a === "V") return true;
      const valued = unix ? PS_UNIX_VALUED : PS_BSD_VALUED;
      for (let k = unix ? 1 : 0; k < a.length; k++) {
        if (unix && a[k] === "D" && k < a.length - 1) continue;
        if (valued.includes(a[k])) {
          if (k === a.length - 1) i++;
          break;
        }
      }
    }
    return false;
  }
  const z = compressorReading(name, args);
  if (z) return z.prints;
  if (["cp", "mv", "ln", "install"].includes(name)) return copiesNothing(name, args);
  // (Round 59, Astra and Sol: find's `-help`, `-version` and `-D help`; Opus: with no output file
  // opened before it.)
  if (name === "find") {
    const f = findActions(args);
    return f.prints && f.at.length === 0;
  }
  // (Round 53, Sol: a version query reads nothing; it writes its log, which rsync's own checks read.)
  if (name === "rsync") {
    const r = rsyncReading(args);
    // (Round 54 and 55: a query that opens a filter file first does read it.)
    return r.prints && !r.opensBeforeExit.length && (r.help || !r.values("log-file").length);
  }
  // (The compressors' queries are read by compressorReading, as writing nothing.)
  return false;
}

// A directory there now; false for anything else, a link loop included (round 40, Sol: ELOOP).
const isDirectory = (p: string) => {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
};

// ---- the spellings the readers are trusted with ----

// The option readers above (find, tar, rsync, sort, ps and the compressors) were written to read
// every spelling GNU takes, and every round of review found one more they read differently. They
// are now trusted only with the plain spellings listed here: whole option names, short flags in a
// cluster, the common valued options in their usual form. Any other word (an abbreviated long
// option, a rare option, an old-style key, a query word mixed with other options) asks, so a
// reader's slip on a rare spelling can no longer allow a call. Asking on a call these lists leave
// out is by design, not a defect. Each list grows only with a test of what the tool does.
const FIND_VALUED = new Set(
  `-name -iname -path -ipath -wholename -iwholename -regex -iregex -regextype -type -xtype -user -group -perm -size -mtime -mmin -atime -amin
   -ctime -cmin -newer -samefile -inum -links -maxdepth -mindepth -printf`.split(/\s+/),
);
const FIND_BARE = new Set(`-print -print0 -ls -delete -prune -quit -empty -true -false -depth -xdev -mount -daystart -readable -writable -executable
   -nouser -nogroup -not -a -and -o -or ( ) !`.split(/\s+/));
function findPlain(args: string[]): boolean {
  let k = args[0] === "--" ? 1 : 0;
  // Start points: plain names, never `-`, `)` or `,`, which find reads in ways of their own.
  while (k < args.length && !/^-./.test(args[k]) && args[k] !== "(" && args[k] !== "!") {
    if (["-", ")", ","].includes(args[k])) return false;
    k++;
  }
  for (; k < args.length; k++) {
    const w = args[k];
    if (w === "-exec" || w === "-execdir") {
      // The command runs to `;`, or to `+` straight after `{}`; find judges it as a command.
      const end = args.findIndex((a, i) => i > k && (a === ";" || (a === "+" && args[i - 1] === "{}")));
      if (end < 0 || end === k + 1) return false;
      k = end;
    } else if (FIND_VALUED.has(w) || /^-newer[aBcm][aBcmt]$/.test(w)) {
      if (++k >= args.length) return false;
    } else if (!FIND_BARE.has(w)) return false;
  }
  return true;
}
// One word of short options, `-czf` or tar's old `czf`: flags from `flags`, then at most one valued
// letter, last, or (a letter of `attached`) with its value as the rest of the word, `-k2,2n`.
// Returns whether the next word is that letter's value, or undefined if not plain.
function cluster(word: string, flags: string, valued: string, from: number, attached = ""): boolean | undefined {
  if (word.length <= from) return undefined;
  for (let k = from; k < word.length; k++) {
    if (valued.includes(word[k])) return k === word.length - 1 ? true : attached.includes(word[k]) ? false : undefined;
    if (!flags.includes(word[k])) return undefined;
  }
  return false;
}
// The long options a tool takes in plain form: `flags` whole, `valued` as `--name=value` or
// `--name value`.
type Plain = { short: string; shortValued: string; attached?: string; flags: string[]; valued: string[]; oldStyle?: boolean; operand?: (w: string) => boolean };
function optionsPlain(args: string[], t: Plain): boolean {
  for (let k = 0; k < args.length; k++) {
    const w = args[k];
    if (w === "--") return args.slice(k + 1).every((a) => !t.operand || t.operand(a));
    if (w.startsWith("--")) {
      const eq = w.indexOf("=");
      const head = w.slice(2, eq < 0 ? undefined : eq);
      if (eq < 0 && t.flags.includes(head)) continue;
      if (!t.valued.includes(head)) return false;
      if (eq < 0 && ++k >= args.length) return false;
      continue;
    }
    if (w.startsWith("-") && w !== "-") {
      const next = cluster(w, t.short, t.shortValued, 1, t.attached);
      if (next === undefined) return false;
      if (next && ++k >= args.length) return false;
      continue;
    }
    // tar reads a first word without a dash as its options.
    if (k === 0 && t.oldStyle) {
      const next = cluster(w, t.short, t.shortValued, 0);
      if (next === undefined) return false;
      if (next && ++k >= args.length) return false;
      continue;
    }
    if (t.operand && !t.operand(w)) return false;
  }
  return true;
}
const TAR_PLAIN: Plain = {
  short: "ctxvzjJapkO",
  shortValued: "fC",
  flags: "create extract list verbose gzip bzip2 xz to-stdout keep-old-files no-same-owner no-same-permissions exclude-vcs wildcards no-wildcards".split(" "),
  valued: ["file", "directory", "exclude", "strip-components"],
  oldStyle: true,
};
const RSYNC_PLAIN: Plain = {
  short: "avrlptgoDzhcuinqPHxEm",
  shortValued: "",
  flags: "archive verbose recursive links perms times group owner devices specials compress human-readable checksum update itemize-changes dry-run quiet progress partial stats hard-links one-file-system delete".split(" "),
  valued: ["exclude", "include", "info"],
};
// sort: no old `+POS` key, in any place (which GNU sort reads by _POSIX2_VERSION).
const SORT_PLAIN: Plain = {
  short: "bdfgiMhnRrVcCmsuz",
  shortValued: "ktoS",
  attached: "ktS",
  flags: "reverse numeric-sort unique ignore-case human-readable version-sort general-numeric-sort stable check merge zero-terminated ignore-leading-blanks dictionary-order month-sort random-sort".split(" "),
  valued: ["key", "field-separator", "output", "buffer-size", "parallel"],
  operand: (w) => !w.startsWith("+"),
};
const COMPRESSOR_PLAIN: Plain = {
  short: "dckvfqtl123456789",
  shortValued: "",
  flags: "decompress uncompress stdout to-stdout keep force verbose quiet test list fast best".split(" "),
  valued: [],
};
// ps: the BSD and UNIX letters that select processes and choose a standard format, and `-o` with
// fields that are not the environment. Every word without a dash is BSD options.
const PS_FIELDS = new Set(
  `pid ppid pgid sid uid user ruser euser group comm args cmd command %cpu %mem pcpu pmem etime etimes time cputime stat state rss vsz sz tty
   tname tt start lstart stime start_time nlwp ni nice pri psr wchan lwp tid f c class cls rtprio`.split(/\s+/),
);
// A format list: each comma-separated piece a field from the list, with a header after `=` that
// holds no comma (so the list is the same whether ps reads a header to the end of the word or to
// the next comma).
const psFormat = (v: string) => v.split(",").every((piece) => /^([a-z%_]+)(=[^,]*)?$/.test(piece) && PS_FIELDS.has(piece.split("=")[0]));
// A sort list: fields from the list, each with an optional `+` or `-`.
const psSort = (v: string) => v.split(",").every((piece) => PS_FIELDS.has(piece.replace(/^[+-]/, "")));
function psPlain(args: string[]): boolean {
  for (let k = 0; k < args.length; k++) {
    const w = args[k];
    if (w === "--forest" || w === "--no-headers") continue;
    if (w.startsWith("--sort=")) {
      if (!psSort(w.slice(7))) return false;
      continue;
    }
    if (w === "--sort") {
      if (!psSort(args[++k] ?? "")) return false;
      continue;
    }
    const bsd = !w.startsWith("-");
    const next = bsd ? cluster(w, "auxwfjlrh", "o", 0) : cluster(w, "eAafFlwHj", "puCo", 1);
    if (next === undefined) return false;
    if (!next) continue;
    const v = args[++k];
    if (v === undefined) return false;
    const letter = w.at(-1);
    if (letter === "p" && !/^\d+(,\d+)*$/.test(v)) return false;
    if ((letter === "u" || letter === "C") && !/^[\w.-]+(,[\w.-]+)*$/.test(v)) return false;
    if (letter === "o" && !psFormat(v)) return false;
  }
  return true;
}
// Undefined when the call is spelled plainly; otherwise why it asks.
// cloc counts lines, but some options write files (`--out`, `--report-file`, `--strip-comments`,
// `--sql`, `--write-lang-def`) or run a program (`--vcs=<command>`): only its listing options are
// read (project review 3, round 2, Mythos: `cloc --out=package.json .` was allowed unrecorded).
const CLOC_PLAIN: Plain = {
  short: "",
  shortValued: "",
  flags: "by-file by-file-by-lang json yaml csv md xml quiet hide-rate fullpath follow-links skip-uniqueness no-autogen".split(" "),
  valued: "exclude-dir exclude-ext exclude-lang include-lang include-ext match-f not-match-f match-d not-match-d timeout processes".split(" "),
};
// zip: only short flag clusters of `r q j X D 0-9` and `ARCHIVE FILE...` operands; every other
// option (`-m`, `-lf`, `-O`/`--out`, `-T`, `-x`/`-i`, `-@`, `-b`, `-u`/`-f`/`-d`/`-U`, `-y`, `-e`,
// any long option, `-` alone) asks (project review 3, round 13, Opus, Neon).
function zipPlain(args: string[]): boolean {
  let ops = 0;
  for (const w of args) {
    if (w.startsWith("-")) {
      if (!/^-[rqjXD0-9]+$/.test(w)) return false;
    } else ops++;
  }
  return ops >= 2;
}
// yq: expression then file operands (after an optional `eval`/`e`/`eval-all`/`ea` subcommand),
// with only the common formatting/in-place options; `-f`/`--from-file`, `-s`/`--split-exp*` and
// every other option ask (project review 3, round 13, Neon).
const YQ_SUBS = new Set(["eval", "e", "eval-all", "ea"]);
const YQ_PLAIN: Plain = {
  short: "iPernNMC",
  shortValued: "opI",
  attached: "opI",
  flags: ["inplace", "prettyPrint", "exit-status", "unwrapScalar", "null-input", "no-doc"],
  valued: ["output-format", "input-format", "indent"],
};
export interface YqReading {
  plain: boolean;
  inPlace: boolean;
  nullInput: boolean;
  operands: string[];
  files: string[];
  op0Index?: number;
}
export function yqReading(args: string[]): YqReading {
  let plain = true;
  let inPlace = false;
  let nullInput = false;
  let seenSub = false;
  const ops: string[] = [];
  let op0Index: number | undefined;
  for (let k = 0; k < args.length; k++) {
    const w = args[k];
    if (w === "--") {
      for (let j = k + 1; j < args.length; j++) {
        if (ops.length === 0) op0Index = j;
        ops.push(args[j]);
      }
      break;
    }
    if (w.startsWith("--")) {
      const eq = w.indexOf("=");
      const head = w.slice(2, eq < 0 ? undefined : eq);
      if (eq < 0 && YQ_PLAIN.flags.includes(head)) {
        if (head === "inplace") inPlace = true;
        if (head === "null-input") nullInput = true;
        continue;
      }
      if (!YQ_PLAIN.valued.includes(head)) {
        plain = false;
        continue;
      }
      if (eq < 0 && ++k >= args.length) plain = false;
      continue;
    }
    if (w.startsWith("-") && w !== "-") {
      const next = cluster(w, YQ_PLAIN.short, YQ_PLAIN.shortValued, 1, YQ_PLAIN.attached);
      if (next === undefined) {
        plain = false;
        continue;
      }
      for (let j = 1; j < w.length; j++) {
        if (YQ_PLAIN.shortValued.includes(w[j])) break;
        if (w[j] === "i") inPlace = true;
        if (w[j] === "n") nullInput = true;
      }
      if (next && ++k >= args.length) plain = false;
      continue;
    }
    if (!seenSub && ops.length === 0 && YQ_SUBS.has(w)) {
      seenSub = true;
      continue;
    }
    if (ops.length === 0) op0Index = k;
    ops.push(w);
  }
  // yq's `load`, `load_str`, `load_props`, `load_base64`, `load_xml` read files from the expression
  // (project review 3, round 14, Opus, Neon), and `eval(...)` evaluates a built expression (round 15, Neon).
  if ((nullInput ? ops : ops.slice(0, 1)).some((o) => /\b(?:load(?:_\w+)?|eval)\s*\(/.test(o))) plain = false;
  const files = inPlace ? (ops.length === 1 ? ops : ops.slice(1)) : ops.slice(1);
  return { plain, inPlace, nullInput, operands: ops, files, ...(op0Index !== undefined ? { op0Index } : {}) };
}
export function unreadSpelling(name: string, args: string[]): string | undefined {
  if (args.length === 1 && /^--(help|version)$/.test(args[0])) return undefined;
  const plain =
    name === "find" ? findPlain(args)
    : name === "tar" || name === "gtar" ? optionsPlain(args, TAR_PLAIN)
    : name === "rsync" ? optionsPlain(args, RSYNC_PLAIN)
    : name === "sort" ? optionsPlain(args, SORT_PLAIN)
    : name === "ps" ? psPlain(args)
    : Object.hasOwn(COMPRESSORS, name) ? optionsPlain(args, COMPRESSOR_PLAIN)
    : name === "cloc" ? optionsPlain(args, CLOC_PLAIN)
    : name === "zip" ? zipPlain(args)
    : name === "yq" ? yqReading(args).plain
    : true;
  return plain ? undefined : `${name} with an option or spelling the rules do not read`;
}

// ---- rules for one simple command ----

// Options of cp, mv, ln and install (GNU coreutils), so valued options (`-S`, `-t`, `-m`, `-o`,
// `-g`, `--sparse`, ...) consume their values and unknown options make the destination unknown
// (project review 3, round 9).
interface CopySpec {
  flags: string;
  values: string;
  long: Record<string, "flag" | "value" | "optional">;
}
const copyLongs = (kind: "flag" | "value" | "optional", names: string) => names.split(" ").map((n) => [n, kind] as const);
const COPY_SPEC: Record<string, CopySpec> = {
  cp: {
    flags: "abdfiHlLnPpRrsTuvxZ",
    values: "St",
    long: Object.fromEntries([
      ...copyLongs("flag", "archive attributes-only copy-contents debug force interactive link dereference no-clobber no-dereference parents recursive remove-destination strip-trailing-slashes symbolic-link no-target-directory verbose keep-directory-symlink one-file-system help version"),
      ...copyLongs("value", "no-preserve sparse suffix target-directory"),
      ...copyLongs("optional", "backup preserve reflink update context"),
    ]),
  },
  mv: {
    flags: "bfinTuvZ",
    values: "St",
    long: Object.fromEntries([
      ...copyLongs("flag", "debug exchange force interactive no-clobber no-copy strip-trailing-slashes no-target-directory verbose context help version"),
      ...copyLongs("value", "suffix target-directory"),
      ...copyLongs("optional", "backup update"),
    ]),
  },
  ln: {
    flags: "bdFfiLnPrsTv",
    values: "St",
    long: Object.fromEntries([
      ...copyLongs("flag", "directory force interactive logical no-dereference physical relative symbolic no-target-directory verbose help version"),
      ...copyLongs("value", "suffix target-directory"),
      ...copyLongs("optional", "backup"),
    ]),
  },
  install: {
    flags: "bcCdDpsTvZ",
    values: "gmoSt",
    long: Object.fromEntries([
      ...copyLongs("flag", "compare directory debug preserve-timestamps strip no-target-directory verbose preserve-context help version"),
      ...copyLongs("value", "group mode owner strip-program suffix target-directory"),
      ...copyLongs("optional", "backup context"),
    ]),
  },
};
export interface CopyReading {
  targets: string[];
  target?: string;
  operands: string[];
  recursive: boolean;
  hard: boolean;
  symbolic: boolean;
  keepsLinks: boolean;
  installDir: boolean;
  exchange: boolean;
  unknown?: string;
}
export function copyReading(cmd: string, args: string[]): CopyReading {
  const spec = COPY_SPEC[cmd];
  const targets: string[] = [];
  const ops: string[] = [];
  let recursive = false;
  let link = false;
  let symbolic = false;
  let noDeref = false;
  let deref = false;
  let preserveLinks = false;
  let installDir = false;
  let exchange = false;
  let unknown: string | undefined;
  let ended = false;
  const names = Object.keys(spec.long);
  for (let i = 0; i < args.length; i++) {
    const w = args[i];
    if (ended || w === "-" || !w.startsWith("-")) {
      ops.push(w);
      continue;
    }
    if (w === "--") {
      ended = true;
      continue;
    }
    if (w.startsWith("--")) {
      const eq = w.indexOf("=");
      const given = (eq < 0 ? w : w.slice(0, eq)).slice(2);
      const attached = eq < 0 ? undefined : w.slice(eq + 1);
      const exact = names.filter((n) => n === given);
      const prefixed = names.filter((n) => n.startsWith(given));
      const full = exact.length === 1 ? exact[0] : prefixed.length === 1 ? prefixed[0] : undefined;
      if (!full) {
        unknown ??= w;
        continue;
      }
      const kind = spec.long[full];
      if (kind === "value") {
        const val = attached ?? args[++i] ?? "";
        if (full === "target-directory") targets.push(val);
      } else if (kind === "flag") {
        if (attached !== undefined) unknown ??= w;
        if (full === "recursive") recursive = true;
        else if (full === "archive") {
          recursive = true;
          noDeref = true;
          deref = false;
        } else if (full === "no-dereference") {
          noDeref = true;
          deref = false;
        } else if (full === "dereference") {
          deref = true;
          noDeref = false;
        } else if (full === "link") link = true;
        else if (full === "symbolic" || full === "symbolic-link") symbolic = true;
        else if (full === "directory") installDir = true;
        else if (full === "exchange") exchange = true;
      } else if (kind === "optional") {
        if (full === "preserve" && attached !== undefined && attached.split(",").some((v) => v === "links" || v === "all")) preserveLinks = true;
      }
      continue;
    }
    for (let j = 1; j < w.length; j++) {
      const c = w[j];
      const rest = w.slice(j + 1);
      if (spec.values.includes(c)) {
        const val = rest || (args[++i] ?? "");
        if (c === "t") targets.push(val);
        break;
      }
      if (spec.flags.includes(c)) {
        if (c === "r" || c === "R") recursive = true;
        else if (c === "a") {
          recursive = true;
          noDeref = true;
          deref = false;
        } else if (c === "P" || c === "d") {
          noDeref = true;
          deref = false;
          if (c === "d") installDir = true;
        } else if (c === "L") {
          deref = true;
          noDeref = false;
        } else if (c === "l") link = true;
        else if (c === "s") symbolic = true;
      } else {
        unknown ??= `-${c}`;
        break;
      }
    }
  }
  return {
    targets,
    target: targets.at(-1),
    operands: ops,
    recursive,
    hard: (cmd === "ln" && !symbolic) || (cmd === "cp" && link),
    symbolic,
    keepsLinks: cmd === "cp" && (noDeref || preserveLinks || (recursive && !deref)),
    installDir: cmd === "install" && installDir,
    exchange: cmd === "mv" && exchange,
    ...(unknown ? { unknown } : {}),
  };
}

// Operands of the `[IN [OUT]]` writers (`uniq`, `xxd`, `python3 -m json.tool`). Only exact known
// option spellings pass; any other option — including an abbreviated `--ind`, `--skip-f` or xxd's
// single-dash prefix `-co` — makes the output file unknown (project review 3, round 9).
export function twoOpOperands(tool: "uniq" | "xxd" | "json.tool", list: string[]): { operands: string[]; unknown?: string } {
  const out: string[] = [];
  for (let k = 0; k < list.length; k++) {
    const a = list[k];
    // (Project review 3, round 10, Neon: xxd stops option parsing at the first operand, so any
    // later `-` word other than `-` is the output file; uniq accepts obsolete `+N` before `--`.)
    if (tool === "xxd" && out.length > 0 && a.startsWith("-") && a !== "-") return { operands: out, unknown: a };
    if (a === "--") {
      out.push(...list.slice(k + 1));
      break;
    }
    if (tool === "uniq" && a.startsWith("+")) return { operands: out, unknown: a };
    if (a === "-" || !a.startsWith("-")) {
      out.push(a);
      continue;
    }
    if (tool === "uniq") {
      if (a.startsWith("--")) {
        if (/^--(skip-fields|skip-chars|check-chars)$/.test(a)) k++;
        else if (/^--(skip-fields|skip-chars|check-chars)=/.test(a)) continue;
        else if (/^--(count|repeated|ignore-case|unique|zero-terminated|help|version)$/.test(a)) continue;
        else if (/^--(all-repeated|group)(=|$)/.test(a)) continue;
        else return { operands: out, unknown: a };
        continue;
      }
      if (/^-\d+$/.test(a)) continue;
      for (let j = 1; j < a.length; j++) {
        const ch = a[j];
        if ("cdDiuz".includes(ch)) continue;
        if ("fsw".includes(ch)) {
          if (j === a.length - 1) k++;
          break;
        }
        return { operands: out, unknown: a };
      }
    } else if (tool === "json.tool") {
      if (a === "--indent") k++;
      else if (a.startsWith("--indent=")) continue;
      else if (/^(-h|--(help|sort-keys|no-ensure-ascii|json-lines|tab|no-indent|compact))$/.test(a)) continue;
      else return { operands: out, unknown: a };
    } else {
      // xxd parses single- and double-dash long names by prefix (`-co 8` is `-cols 8`).
      if (/^--?(c|cols|g|groupsize|l|len|n|name|o|s|seek|R)$/.test(a)) k++;
      else if (/^--?(a|autoskip|b|bits|C|capitalize|d|e|E|EBCDIC|h|help|i|include|p|ps|postscript|plain|r|revert|u|uppercase|v|version)$/.test(a)) continue;
      else if (/^-[cglo](?:0[xX][\da-fA-F]+|\d+)$/.test(a) || /^-s[+-]?(?:0[xX][\da-fA-F]+|\d+)$/.test(a) || /^-R(always|auto|never)$/.test(a)) continue;
      else return { operands: out, unknown: a };
    }
  }
  return { operands: out };
}

// (Project review 3, round 10, Neon: GNU chmod takes modes starting with `-`, including `-u`,
// `-g`, `-o`, and any-length octal `-00644`. Only chmod's own short options `c f v R` are
// options; a `-` word matching the octal or symbolic mode set is the mode; any other `-` word
// is unknown and asks.)
export interface ChmodReading {
  files: string[];
  recursive: boolean;
  modeAsOption: boolean;
  reference: boolean;
  unknown?: string;
}
export function chmodReading(args: string[]): ChmodReading {
  const ops: string[] = [];
  let recursive = false;
  let modeAsOption = false;
  let reference = false;
  let unknown: string | undefined;
  let ended = false;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (ended || a === "-" || !a.startsWith("-")) {
      ops.push(a);
      continue;
    }
    if (a === "--") {
      ended = true;
      continue;
    }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const head = eq < 0 ? a : a.slice(0, eq);
      if (head === "--reference") {
        reference = true;
        if (eq < 0) i++;
        continue;
      }
      if (eq < 0 && /^--(changes|silent|quiet|verbose|dereference|no-dereference|no-preserve-root|preserve-root|recursive|help|version)$/.test(head)) {
        if (head === "--recursive") recursive = true;
        continue;
      }
      if (eq < 0 && head.length >= 5 && "--recursive".startsWith(head)) recursive = true;
      if (head.length >= 4 && "--reference".startsWith(head)) {
        reference = true;
        if (eq < 0) i++;
      }
      unknown ??= a;
      continue;
    }
    if (/^-[cfvR]+$/.test(a)) {
      if (a.includes("R")) recursive = true;
      continue;
    }
    if (/^-[0-7]+$/.test(a) || /^-[rwxXstugoa+=,-]+$/.test(a)) {
      modeAsOption = true;
      continue;
    }
    unknown ??= a;
  }
  const files = reference || modeAsOption ? ops : ops.slice(1);
  return { files, recursive, modeAsOption, reference, ...(unknown ? { unknown } : {}) };
}

function writeTargets(cmd: string, args: string[], scope: Scope, literalInput = false): Verdict {
  const copy = Object.hasOwn(COPY_SPEC, cmd) ? copyReading(cmd, args) : undefined;
  if (copy?.unknown) return ask(`${cmd} ${copy.unknown}: an option the rules do not read, so its destination is not known`);
  const badTarget = copy?.targets.find((t) => MAY_EXPAND.test(t));
  if (badTarget !== undefined) return ask(`${cmd} -t with an expanding target directory (${badTarget}): bash may expand it into both target directory and sources`);
  const chmod = cmd === "chmod" ? chmodReading(args) : undefined;
  if (chmod?.unknown) return ask(`chmod ${chmod.unknown}: an option the rules do not read`);
  // (Round 39, Mythos: with `--reference=FILE` chmod/chown/chgrp take no mode or owner operand.)
  // (Round 40: a mode can look like an option, `chmod -w f`, and `--reference` is matched by any
  // prefix; its value, as a separate word, is the file read, not a target.)
  const head = args.indexOf("--") < 0 ? args : args.slice(0, args.indexOf("--"));
  const reference = head.findIndex((a) => longIs(a, "reference") && a.split("=")[0].length >= 4);
  const words = reference >= 0 && !head[reference].includes("=") ? args.filter((_, k) => k !== reference + 1) : args;
  const paths = copy ? copy.operands : chmod ? chmod.files : (FIRST_OPERAND_NOT_PATH.has(cmd) && reference < 0 ? operands(words).slice(1) : operands(words));
  const hasTarget = copy?.target !== undefined;
  const installDir = !!copy?.installDir;
  const sources = hasTarget ? paths : paths.slice(0, -1);
  const destWord = hasTarget ? copy!.target! : paths.length > 1 ? paths.at(-1)! : undefined;
  const dest = destWord !== undefined ? resolveWord(destWord, scope) : undefined;
  const intoDir = !installDir && (hasTarget || (COPIERS.has(cmd) && paths.length > 1 && (sources.length > 1 || paths.at(-1)!.endsWith("/") || (!!dest && isDirectory(dest)))));
  // With `-t`/`--target-directory`, guard.ts + decide.ts check the literal destination directory
  // (including `/proc/self/cwd/..` and >4096-char option words); rules.ts still checks `mv` sources
  // and rejects expanding `-t` values above. With `install -d`/`--directory`, every operand is a
  // directory to create.
  const targets = installDir ? paths : hasTarget ? (WRITERS[cmd] === "all" ? paths : []) : WRITERS[cmd] === "last" ? paths.slice(-1) : paths;
  // (Project review 6, Sol, Opus, Neon: patch writes under the directory of `-d`, which an attached
  // or `=` spelling hides from the operands, `-d.claude`, `--directory=.git/hooks`. Every value an
  // option word of patch may carry is held as a place it writes: after an `=`, and after the value
  // letter of a short cluster, `-Nd.claude`. One built at run time is judged elsewhere.)
  const places: string[] = [];
  if (cmd === "patch") {
    for (let a of head) {
      if (!a.startsWith("-") || a === "-" || a === "--") continue;
      // (Round 5, Sol: a variable the call sets to a literal is read as it, `d=.claude; patch
      // -d"$d"`; any other value built at run time is a place the check cannot tell.)
      if (/[$`]/.test(a)) a = expandVars(a, scope);
      if (/[$`]/.test(a)) {
        // (A count built at run time, `-p"$n"`, names no place.)
        if (!/^-[lcenuNREZTbtfsv]*[pF][^a-zA-Z]/.test(a) && !/^--(strip|fuzz)=/.test(a)) return classify(`patch ${a}: an option whose value bash builds at run time, which may name where patch writes`);
        continue;
      }
      if (a.startsWith("--")) {
        if (a.includes("=") && !/^--in/.test(a)) places.push(a.slice(a.indexOf("=") + 1));
      } else {
        // (Only values that may name a place: a count, `-p1`, names none.)
        // (patch's own letters: a flag goes on to the next letter, a value letter takes the rest.)
        // (`-i`, the patch read, names no place written: round 5, Opus.)
        for (let k = 1; k < a.length && "lcenuNREZTbtfsv".includes(a[k]); k++) if ("pForDVBYzgdx".includes(a[k + 1] ?? "")) places.push(a.slice(k + 2));
        if ("pForDVBYzgdx".includes(a[1])) places.push(a.slice(2));
      }
    }
  }
  // (Round 3, Sol: or a name that is there, a link into a protected place, `-dconfiglink`,
  // `-d2026`.)
  // (Round 11, Opus: a patch place as the kernel walks it, `-dext/..`.)
  for (const v of places) {
    const w = walked(v, scope);
    if (w && protectedPlace(w, scope)) return piAsk(`${cmd} changes opencode's own files (config, AGENTS.md, CLAUDE.md, a hook manager's, .git): ${v}`);
    if (w && !isLocal(w, scope)) return outside(`${cmd} writes outside the working directory: ${v}`, w);
  }
  for (const t of [...targets, ...places.filter((v) => /[/~]/.test(v) || v.startsWith(".") || (!!resolveWord(v, scope) && fs.existsSync(resolveWord(v, scope)!)))]) {
    // Copied into a directory, the files land inside it: `cp a.rs /tmp` writes /tmp/a.rs.
    const written = intoDir && t === destWord && dest && sources.length ? sources.map((s) => path.join(dest, path.basename(s))) : [resolveWord(t, scope)];
    for (const p of written) {
      if (devSink(t, p)) continue;
      if (isGuarded(p, scope)) return guardAsk(`${cmd} changes the auto-mode guard's own files`);
      if (isPiFile(p, scope)) return piAsk(`${cmd} changes Pi's own files: ${t}`);
      if (!isLocal(p, scope)) return outside(`${cmd} writes outside the working directory: ${t}`, p);
    }
  }
  // A symbolic link this command makes is followed by the paths it uses after it.
  if (cmd === "ln" && (hasTarget ? paths.length >= 1 : paths.length > 1) && copy?.symbolic) {
    for (const source of sources) {
      const link = dest && intoDir ? path.join(dest, path.basename(source)) : dest;
      const at = link ? path.dirname(link) : undefined;
      const text = expandHome(expandVars(source, scope));
      const target = at && !/[$`]/.test(text) ? realish(path.resolve(at, text)) : undefined;
      if (link && target) (scope.links ??= new Map()).set(link, target);
    }
  }
  if (COPIERS.has(cmd) && !installDir && (hasTarget ? paths.length >= 1 : paths.length > 1)) {
    for (const source of sources) {
      const from = resolveWord(source, scope);
      const kept = from && originOf(from, scope);
      note(dest && intoDir ? path.join(dest, path.basename(source)) : dest, kept === "authored" || kept === "fetched" ? kept : "other", scope);
      if (cmd === "mv") note(from, "other", scope);
    }
  } else if (COPIERS.has(cmd) && !hasTarget && paths.length === 1 && MAY_EXPAND.test(paths[0])) {
    // (Project review 3, round 8, Neon & round 9: one operand bash may expand into several words
    // may supply both source and destination, unless `-t`/`--target-directory` or `install -d`.)
    if (!copy?.installDir) return ask(`${cmd} with one expanding operand (${paths[0]}): bash may expand it into both source and destination`);
  } else if (CONTENT_WRITERS.has(cmd)) {
    const literal = cmd === "tee" && literalInput;
    // Appending literal text to a file of the project makes it one the session wrote; any other
    // origin stays as it was.
    for (const t of targets) {
      const p = resolveWord(t, scope);
      if (literal && hasFlag(args, "a", "--append")) {
        if (p && originOf(p, scope) === undefined) note(p, "authored", scope);
      } else note(p, literal ? "authored" : "other", scope);
    }
  } else if (cmd === "sed") {
    // An in-place edit leaves content the rules did not write.
    for (const t of targets) note(resolveWord(t, scope), "other", scope);
  }
  return ALLOW;
}

function rm(args: string[], scope: Scope): Verdict {
  const head = args.indexOf("--") < 0 ? args : args.slice(0, args.indexOf("--"));
  const recursive = hasFlag(head, "r", "--recursive") || hasFlag(head, "R") || head.some((a) => longIs(a, "recursive"));
  // (Project review 5, round 4, Mythos: an option word bash builds at run time can hold the `-r`,
  // `x=-rf; rm $x *`, `rm "-${x:-r}f" *`: read as maybe recursive, which asks.)
  const maybe = recursive || head.some((a) => /[$`]/.test(a) && /^(-|\$|`)/.test(a));
  let verdict = ALLOW;
  for (const t of operands(args)) {
    const p = resolveWord(t, scope);
    // (Project review 6, Neon, Opus: any name made only of glob characters, bracket expressions
    // and dots matches about every entry, as `*` does: `?*`, `**`, `[!.]*`, `[a-z]*`, `*[!x]`, `./?*`.)
    const base = path.basename(t);
    // (Cross-check 2, Sol, Opus: a class inside the brackets, `[[:alpha:]]*`, is part of them.)
    const unbracketed = base.replace(/\[(\^|!)?\]?(\[[:=.][^\]]*[:=.]\]|[^\]])*\]/g, "?");
    const bare = BARE_GLOB.test(base) || (/^[*?.]+$/.test(unbracketed) && /[*?]/.test(unbracketed));
    if (maybe && p && (isRootLike(p) || (bare && isRootLike(path.dirname(p))))) {
      if (!recursive) return ask(`rm of ${t} with an option bash builds at run time, which may wipe a home or system directory`);
      return deny(`rm -r of ${t} would wipe a home or system directory`);
    }
    if (isGuarded(p, scope)) verdict = worst(verdict, guardAsk("rm deletes the auto-mode guard's own files"));
    else if (isPiFile(p, scope)) verdict = worst(verdict, piAsk(`rm deletes Pi's own files: ${t}`));
    else if (!isLocal(p, scope)) verdict = worst(verdict, outside(`rm deletes outside the working directory: ${t}`, p));
    else if (maybe && scope.root && (p === scope.root || (bare && path.dirname(p!) === scope.root) || /(^|\/)\.git(\/|$)/.test(p!))) {
      verdict = worst(verdict, ask(`rm -r of ${t} deletes the whole project or its git data`));
    }
  }
  return verdict;
}

// git's own options before the subcommand. `-C`, `--git-dir` and `--work-tree` name a repository,
// which must be local; `-c` sets configuration, which only the keys below may do here (core.pager,
// alias.*, core.sshCommand and many more run programs). Any other option, `--exec-path=`,
// `--config-env` and `--super-prefix` among them, leaves the subcommand to the decider.
const GIT_FLAGS = /^(-p|--paginate|-P|--no-pager|--no-replace-objects|--bare|--literal-pathspecs|--glob-pathspecs|--noglob-pathspecs|--icase-pathspecs|--no-optional-locks|--no-lazy-fetch|--no-advice)$/;
// Configuration that changes how git shows or records things, never what it runs.
const GIT_PLAIN_CONFIG = /^(user\.(name|email)|author\.(name|email)|committer\.(name|email)|color\.[\w.-]+|core\.(quotepath|autocrlf|safecrlf|filemode|ignorecase|abbrev|eol)|advice\.\w+|init\.defaultbranch|commit\.(gpgsign|verbose|status)|tag\.gpgsign|log\.[\w.-]+|format\.pretty|diff\.(noprefix|renames|algorithm|colormoved|context|indentheuristic|mnemonicprefix|relative|statgraphwidth|submodule|wserrorhighlight)|merge\.(conflictstyle|ff|log|stat|renames)|pull\.(rebase|ff)|rebase\.(autosquash|autostash|stat|updaterefs)|push\.(autosetupremote|default|followtags)|fetch\.(prune|prunetags|parallel)|status\.[\w.-]+|column\.[\w.-]+|i18n\.[\w.-]+|gc\.auto|branch\.autosetup\w*|help\.autocorrect|rerere\.enabled|blame\.[\w.-]+|grep\.(linenumber|patterntype|extendedregexp|column|fullname)|feature\.\w+|index\.\w+|pack\.\w+|checkout\.defaultremote)$/i;

function git(args: string[], scope: Scope): Verdict {
  // Global options, read as git reads them; the directory git works in follows `-C`.
  let dir: Scope = scope;
  let i = 0;
  for (; i < args.length && args[i].startsWith("-"); i++) {
    const a = args[i];
    if (GIT_FLAGS.test(a)) continue;
    if (a === "--version" || a === "--help" || a === "-h" || a === "-v" || /^--(html|man|info)-path$/.test(a) || /^--list-cmds=/.test(a)) return ALLOW;
    if (a === "-C" || /^--(git-dir|work-tree)(=|$)/.test(a)) {
      const value = a.includes("=") ? a.slice(a.indexOf("=") + 1) : args[++i];
      const p = resolveWord(value ?? "", dir);
      if (!isLocal(p, scope)) return classify("git on a repository outside the working directory");
      if (a === "-C") dir = { ...dir, cwd: p };
      continue;
    }
    if (a === "-c") {
      const key = (args[++i] ?? "").split("=")[0];
      if (!GIT_PLAIN_CONFIG.test(key)) return classify(`git -c ${key} sets configuration that can run programs`);
      continue;
    }
    if (/^--namespace(=|$)/.test(a)) {
      if (!a.includes("=")) i++;
      continue;
    }
    if (/^--attr-source(=|$)/.test(a)) {
      if (!a.includes("=")) i++;
      continue;
    }
    return classify(`git ${a.split("=")[0]} is an option the rules do not model`);
  }
  const sub = args[i];
  const rest = args.slice(i + 1);
  if (!sub) return ALLOW;
  // Options of the subcommand, up to `--`.
  const end = rest.indexOf("--");
  const opts = end < 0 ? rest : rest.slice(0, end);
  // A long option (or an unambiguous prefix of it, as git accepts) or a letter in a short cluster
  // read up to the first letter that takes a value.
  const opt = (long: string | undefined, letter?: string, valued = "") =>
    opts.some((a) => (long !== undefined && longIs(a, long)) || (letter !== undefined && shortIn(a, letter, valued)));
  const words = operands(opts);
  if (rest.some((a) => /^[\w+.-]+::/.test(a))) return classify(`git ${sub} through a remote helper, which runs a program`);
  // Options that run a program: upload-pack and receive-pack for the transports, --exec for
  // archive and rebase, --template hooks.
  if (opt("upload-pack") || opt("receive-pack") || opt("template") || (sub === "clone" && opt(undefined, "u", "obcj")) || (["archive", "ls-remote"].includes(sub) && opt("exec"))) {
    return classify(`git ${sub} with an option that runs a program`);
  }
  if (opt("config", sub === "clone" ? "c" : undefined, "obuj")) {
    const values = opts.flatMap((a, k) => (longIs(a, "config") || a === "-c" ? [a.includes("=") ? a.slice(a.indexOf("=") + 1) : (opts[k + 1] ?? "")] : /^-c./.test(a) ? [a.slice(2)] : []));
    if (!values.every((v) => GIT_PLAIN_CONFIG.test(v.split("=")[0]))) return classify(`git ${sub} sets configuration that can run programs`);
  }
  // Files git writes besides the work tree.
  const outputs: string[] = [];
  // (Project review 5, round 8, Opus: every word, past a `--` too, which can be an option's value:
  // `git format-patch --to -- -o .git/hooks -1`.)
  const valueOf = (long: string, letter?: string) =>
    rest.flatMap((a, k) => (longIs(a, long) ? [a.includes("=") ? a.slice(a.indexOf("=") + 1) : (rest[k + 1] ?? "")] : letter && a === `-${letter}` ? [rest[k + 1] ?? ""] : letter && a.startsWith(`-${letter}`) && a.length > 2 && !a.startsWith("--") ? [a.slice(2)] : []));
  if (["diff", "log", "show", "whatchanged", "range-diff", "format-patch", "diff-tree", "diff-files", "diff-index", "cherry"].includes(sub)) outputs.push(...valueOf("output"));
  if (sub === "format-patch") outputs.push(...valueOf("output-directory", "o"));
  if (sub === "archive") outputs.push(...valueOf("output", "o"));
  if (sub === "bundle" && words[0] === "create" && words[1]) outputs.push(words[1]);
  if (sub === "clone" && words.length > 1) outputs.push(words.at(-1)!);
  if (sub === "init" && words[0]) outputs.push(words[0]);
  if (sub === "worktree" && words[0] === "add" && words[1]) outputs.push(words[1]);
  for (const o of outputs) {
    const p = resolveWord(o, dir);
    if (isGuarded(p, scope)) return guardAsk(`git ${sub} writes the auto-mode guard's own files`);
    if (isPiFile(p, scope)) return piAsk(`git ${sub} writes Pi's own files: ${o}`);
    if (!isLocal(p, scope)) return outside(`git ${sub} writes outside the working directory: ${o}`, p);
  }
  const force = opt("force", "f");
  if (sub === "reset" && opt("hard")) return ask("git reset --hard discards local changes");
  if (sub === "clean" && force) return ask("git clean -f deletes untracked files");
  if (sub === "checkout") {
    if (end >= 0 || words.includes(".") || force || opt(undefined, "B", "bB") || opt("patch", "p", "bB")) return ask("git checkout discards local changes");
    // An operand that names a path checks out that path over local changes.
    const named = opts.filter((a, k) => !a.startsWith("-") && !/^(-b|-B|--orphan)$/.test(opts[k - 1] ?? ""));
    if (named.length && !dir.cwd) return classify("git checkout in a directory the rules cannot place");
    if (named.some((w) => fs.existsSync(path.resolve(dir.cwd!, w)))) return ask("git checkout of a path discards local changes");
    return ALLOW;
  }
  if (sub === "switch") return force || opt("discard-changes") || opt("force-create", "C", "cC") ? ask("git switch discards local changes or resets a branch") : ALLOW;
  // Only --staged alone keeps the working tree; --worktree with it still discards changes.
  if (sub === "restore" && (!opt("staged", "S", "s") || opt("worktree", "W", "s"))) return ask("git restore discards local changes");
  // Without --force git refuses to remove a worktree or submodule that has local changes.
  if (sub === "worktree" && words[0] === "remove" && force) return ask("git worktree remove --force deletes the worktree with its uncommitted changes");
  if (sub === "submodule" && words[0] === "deinit" && force) return ask("git submodule deinit --force deletes submodule working trees with their local changes");
  if (sub === "submodule" && words[0] === "foreach") return classify("git submodule foreach runs a command");
  if (sub === "branch") {
    const deletes = opt("delete", "d", "ut");
    return opt(undefined, "D", "ut") || opt(undefined, "M", "ut") || opt(undefined, "C", "ut") || force || (deletes && force) ? ask("git branch -D, -M, -C or -f deletes or replaces a branch") : ALLOW;
  }
  if (sub === "stash") return words.includes("drop") || words.includes("clear") ? ask("git stash drop deletes stashed changes") : ALLOW;
  if (sub === "tag") return opt("delete", "d", "mFu") ? ask("git tag -d deletes a tag") : opt("force", "f", "mFu") ? ask("git tag -f replaces a tag, which keeps no reflog") : ALLOW;
  if (sub === "rebase" && (opt("interactive", "i", "xsX") || opt("exec", "x", "sX") || opt("edit-todo"))) return classify("git rebase that runs commands or an editor");
  // (Round 38, Mythos: `git bisect view <words>` runs `git <words>`, or the program when it is tig
  // or git-something; with options only it is git log.)
  const viewAt = rest.findIndex((a) => a === "view" || a === "visualize");
  if (sub === "bisect" && (words[0] === "run" || (["view", "visualize"].includes(words[0] ?? "") && rest[viewAt + 1] !== undefined && !rest[viewAt + 1].startsWith("-")))) return classify(`git bisect ${words[0]} runs a command`);
  if (sub === "grep" && (opt("open-files-in-pager", "O", "eABCfm"))) return classify("git grep -O runs a pager program");
  if (sub === "reset" || sub === "clean" || sub === "restore") return ALLOW;
  // (Project review 6, round 2, Opus: `git credential fill` prints a stored password, as `gh auth
  // token` prints a token: a firm ask.)
  if (sub === "credential" || sub?.startsWith("credential-")) return criticalAsk("git credential prints or changes stored passwords");
  if (sub === "config") return gitConfig(opts, rest, dir, scope);
  if (sub === "remote") return words.some((w) => ["add", "set-url", "remove", "rm", "rename"].includes(w)) ? ask("changes where git pushes and fetches") : ALLOW;
  if (sub === "reflog") return words.includes("expire") || words.includes("delete") ? ask("deletes git recovery data") : ALLOW;
  if (sub === "gc") return opt("prune") || opt("aggressive") ? ask("deletes git recovery data") : ALLOW;
  return subcommand("git", [sub, ...rest]);
}

// git config: reads are allowed; a write to the global or system file asks, and a write to the
// repository's own may only set the keys that do not run programs.
function gitConfig(opts: string[], rest: string[], dir: Scope, scope: Scope): Verdict {
  const opt = (long: string, letter?: string) => opts.some((a) => longIs(a, long) || (letter !== undefined && shortIn(a, letter, "f")));
  // Options that take a value, so their value is not an operand.
  const valued = /^(--file|-f|--blob|--type|--default|--comment|--value)$/;
  const words = opts.filter((a, k) => !a.startsWith("-") && !valued.test(opts[k - 1] ?? ""));
  const [action] = words;
  const newRead = action === "get" || action === "list";
  const newWrite = ["set", "unset", "rename-section", "remove-section", "edit"].includes(action ?? "");
  const reads = newRead || opt("get") || opt("get-all") || opt("get-regexp") || opt("get-urlmatch") || opt("get-color") || opt("get-colorbool") || opt("list", "l");
  const writes = newWrite || opt("unset") || opt("unset-all") || opt("add") || opt("replace-all") || opt("rename-section") || opt("remove-section") || opt("edit", "e") || (!reads && (words.length >= 2 || (words.length === 1 && MAY_EXPAND.test(words[0]))));
  if (!writes) return ALLOW;
  if (opt("global") || opt("system")) return ask("changes git config outside the repository");
  const file = opts.flatMap((a, k) => (longIs(a, "file") ? [a.includes("=") ? a.slice(a.indexOf("=") + 1) : (opts[k + 1] ?? "")] : a === "-f" ? [opts[k + 1] ?? ""] : []));
  for (const f of file) {
    const p = resolveWord(f, dir);
    if (!isLocal(p, scope)) return outside(`git config writes outside the working directory: ${f}`, p);
  }
  if (opt("edit", "e") || action === "edit") return classify("git config --edit runs an editor");
  if (opt("rename-section") || opt("remove-section") || action === "rename-section" || action === "remove-section") return classify("git config changes a whole section");
  const key = newWrite ? words[1] : words[0];
  return key && GIT_PLAIN_CONFIG.test(key) ? ALLOW : classify(`git config ${key ?? ""} sets configuration that can run programs`.trim());
}


function gh(args: string[]): Verdict {
  // An option before the group could take the group's place as its value.
  if (args[0]?.startsWith("-")) return classify("gh with an option before its command");
  const [group, action] = operands(args);
  if (!group) return ALLOW;
  // (Project review 5, round 5, Mythos: and one between the group and the action could take the
  // word read as the action for its value: `gh pr --body list comment 123` comments, `gh issue
  // -c list close 5` closes. A call that would be allowed by its action goes to the decider.)
  const early = args[1]?.startsWith("-") ? classify(`gh ${group} with an option before its action`) : undefined;
  if (group === "api") {
    // (Project review 5, round 2, Opus: every method the call names, in each form gh reads, the
    // last one deciding (`--method=DELETE`, `-X=DELETE`, `-X GET ... -X DELETE`), and a field
    // attached to its letter (`-ftitle=x`); any other cluster that holds one of these letters,
    // `-iX DELETE`, `-if title=x`, is not read and asks. A method word right after an option
    // that is not one of gh api's flags may be that option's value, `-f title=x -t -XGET`: it
    // does not make a call with fields a GET.)
    const methods: string[] = [];
    let fields = false;
    let sure = true;
    for (const [k, a] of args.entries()) {
      const method = a === "-X" || a === "--method" ? (args[k + 1] ?? "") : a.startsWith("--method=") ? a.slice(9) : /^-X./.test(a) ? a.slice(2).replace(/^=/, "") : undefined;
      if (method !== undefined) {
        methods.push(method);
        const before = args[k - 1];
        if (before.startsWith("-") && !before.includes("=") && !/^(-i|--include|--paginate|--slurp|--silent|--verbose)$/.test(before)) sure = false;
      } else if (/^(-[fF].*|--(field|raw-field|input)(=.*)?)$/s.test(a)) fields = true;
      else if (/^-[^-]/.test(a) && /[XfF]/.test(a)) return ask(`gh api ${a}: an option cluster the check does not read, which may set the method or a field`);
    }
    if (methods.some((m) => m.toUpperCase() !== "GET") || (fields && (!methods.length || !sure))) return ask("gh api call that changes remote data");
    // (Project review 6, Opus, Sol, Neon: a GET sends a file too, `--input f` as its body and a
    // typed field's `@file` as a query value, `--field=q=@.env`, a spelling the credential check
    // does not read. Any `--input`, and any `-F`/`--field` word that holds `=@`, go to the decider.)
    if (args.some((a, k) => /^--input(=|$)/.test(a) || (/=@/.test(a) && (/^(-F|--field(=|$))/.test(a) || /^(-F|--field)$/.test(args[k - 1] ?? ""))))) return classify("gh api that sends a file's contents");
    return ALLOW;
  }
  // (Round 2 cross-check, Opus: `gh config get oauth_token` prints the token on older gh.)
  if (group === "config" && args.some((w) => /token/i.test(w))) return criticalAsk("gh config of a token prints or changes it");
  if (group === "auth") {
    // (Project review 6, Opus: `gh auth token` prints the token, a firm ask like `status -t`.)
    if (args.slice(args.indexOf("auth") + 1).some((w) => w === "token" || w === "git-credential")) return criticalAsk("gh auth token and gh auth git-credential print the GitHub token");
    if (action !== "status") return classify("gh auth");
    // (Project review 5, round 4, Opus: `-t` / `--show-token` prints the token. Only the options
    // known to print no secret pass.)
    // (Cross-check, Sol and Opus: gh hands options written before `status` to it as well,
    // `gh auth -t=true status`: every word after `auth` but `status` itself.)
    const rest = args.slice(args.indexOf("auth") + 1);
    rest.splice(rest.indexOf("status"), 1);
    for (let k = 0; k < rest.length; k++) {
      const a = rest[k];
      if (a === "-h" || a === "--hostname") k++;
      else if (!a.startsWith("-") || /^--hostname=/.test(a) || a === "-a" || a === "--active") continue;
      else return criticalAsk(`gh auth status ${a}: an option that may print the token`);
    }
    return early ?? ALLOW;
  }
  if (["pr", "issue", "release", "repo", "run", "workflow", "gist", "label", "project", "secret", "variable", "cache"].includes(group)) {
    if (action && GH_READ.has(action)) return early ?? ALLOW;
    if (group === "repo" && action === "clone") return early ?? ALLOW;
    return ask(`gh ${group} ${action ?? ""} is visible to others`.replace(/\s+/g, " "));
  }
  return subcommand("gh", args);
}

// LlamaStash's CLI. Reads run; stopping a model can cut off other sessions that use it.
const LLAMASTASH_READ = new Set(["list", "status", "logs", "requests", "completions", "knobs", "show", "last-params", "help"]);
function llamastash(args: string[]): Verdict {
  const [sub, second, third] = operands(args);
  if (!sub || LLAMASTASH_READ.has(sub)) return ALLOW;
  if (sub === "api-key") return criticalAsk("llamastash api-key prints the proxy's API key");
  if (sub === "stop" || (sub === "daemon" && (second === "stop" || second === "restart"))) return ask("llamastash stops models that other sessions may be using");
  if (sub === "integrations") return piAsk("llamastash integrations changes other tools' configs, Pi's among them");
  if ((sub === "daemon" && second === "status") || (sub === "config" && second === "bindings") || (sub === "favorites" && second === "list")) return ALLOW;
  if (sub === "presets" && (third === "list" || third === "show")) return ALLOW;
  if (sub === "doctor" && !args.includes("--fix")) return ALLOW;
  return { ...classify(`llamastash ${sub}`), pattern: `llamastash ${sub} *` };
}

function subcommand(tool: string, args: string[], scope?: Scope): Verdict {
  const table = SUBCOMMANDS[tool];
  const lead = LEAD_OPTIONS[tool];
  let sub = operands(args)[0];
  // (Round 38, Mythos: systemctl and loginctl read their options anywhere; -H, -M and --root
  // reach another host, machine or tree.)
  if ((tool === "systemctl" || tool === "loginctl") && args.some((a) => /^-[a-zA-Z]*[HM]/.test(a) && !a.startsWith("--") || ["host", "machine", "root"].some((o) => longIs(a, o) && a.split("=")[0].length > 3))) return ask(`${tool} on another host, machine or root`);
  if (lead && args[0]?.startsWith("-")) {
    const k = leadingOptions(args, lead);
    const unknown = (why: string) => (ASK_BY_DEFAULT[tool] ? ask(`${tool} ${why}`) : classify(`${tool} ${why}`));
    if (k < 0) return unknown("with an option before its subcommand that the rules do not model");
    // (Project review 5, round 1, Opus: a value option at the end, `npm -w`, counts past the words.)
    for (let j = 0; j < Math.min(k, args.length); j++) {
      const a = args[j];
      const flag = a.split("=")[0];
      if (!lead.dirs?.includes(flag)) continue;
      const value = a.includes("=") ? a.slice(a.indexOf("=") + 1) : args[j + 1];
      if (!scope || !isLocal(resolveWord(value ?? "", scope), scope)) return unknown(`in a directory outside the working directory: ${value}`);
    }
    sub = args[k];
  } else if (!lead && args[0]?.startsWith("-") && tool !== "git") {
    return classify(`${tool} with an option before its subcommand`);
  }
  if (!sub) return ALLOW;
  if (table.ask?.[sub]) return ask(table.ask[sub]);
  if (table.allow.split(/\s+/).includes(sub)) return ALLOW;
  return ASK_BY_DEFAULT[tool] ? ask(`${tool} ${sub} ${ASK_BY_DEFAULT[tool]}`) : { ...classify(`${tool} ${sub}`), pattern: `${tool} ${sub} *` };
}

function network(cmd: string, args: string[], scope: Scope): Verdict {
  if (cmd === "curl") {
    if (args.some((a) => /^(-d|--data|--data-\w+|--json|-F|--form|--form-string|-T|--upload-file)(=|$)/.test(a) || /^-[a-zA-Z]*[dFT]/.test(a))) {
      return ask("curl sends data to a remote host");
    }
    const m = args.findIndex((a) => a === "-X" || a === "--request");
    const method = m >= 0 ? args[m + 1] : args.find((a) => /^-X\w+$/.test(a))?.slice(2);
    if (method && !/^(GET|HEAD|OPTIONS)$/i.test(method)) return ask(`curl -X ${method} changes remote data`);
    // Headers, query parts and variables read from a file are sent with the request.
    if (args.some((a, k) => (/^(-H|--header|--url-query|--variable)$/.test(args[k - 1] ?? "") && /(^|=)@/.test(a)) || /^-H@/.test(a))) return ask("curl sends a file's contents to a remote host");
    // -K reads more options from a file, which can send data as the command line can.
    if (args.some((a) => a === "-K" || a === "--config" || /^-[a-zA-Z]*K/.test(a))) return classify("curl reads its options from a file");
  } else if (args.some((a) => /^--(post|body|method)/.test(a))) {
    return ask("wget sends data to a remote host");
  } else if (args.some((a) => /^(-e|--execute|--config)(=|$)/.test(a) || /^-[a-zA-Z]*e/.test(a))) {
    return classify("wget runs wgetrc commands or reads its options from a file");
  }
  const curl = cmd === "curl";
  // A URL or header built from a variable or a substitution can carry local data out. The name
  // of the file it saves to stays local.
  const outFlags = curl ? ["-o", "--output"] : ["-O", "--output-document", "-o", "--output-file"];
  const literal = (a: string) => a.replace(/\$\{(\w+)\}|\$(\w+)/g, (m, x, y) => (scope.loopVars?.has(x ?? y) ? "" : m));
  if (args.some((a, i) => /[$`]/.test(literal(a)) && !outFlags.includes(args[i - 1]))) return ask(`${cmd} request built from local data`);
  const opts = optionValues(args, curl ? "AbcCdDeEFHKmoPQrtTuUwxXyYz" : "aABDeiIlOoPQRtTUwX", [...DOWNLOAD_FILES[cmd].other, ...DOWNLOAD_FILES[cmd].saved, DOWNLOAD_FILES[cmd].dir].flat());
  const values = (flags: string[]) => opts.filter(([flag]) => flags.includes(flag)).map(([, value]) => value ?? "");
  const writes = (file: string) => {
    const p = resolveWord(file, scope);
    if (file === "-" || devSink(file, p)) return { p: undefined };
    if (isPiFile(p, scope)) return { p, outside: piAsk(`${cmd} writes Pi's own files: ${file}`) };
    return isLocal(p, scope) ? { p } : { p, outside: outside(`${cmd} writes outside the working directory: ${file}`, p) };
  };
  for (const file of values(DOWNLOAD_FILES[cmd].other)) {
    const w = writes(file);
    if (w.outside) return w.outside;
  }
  const saved = values(DOWNLOAD_FILES[cmd].saved);
  for (const file of saved) {
    const w = writes(file);
    if (w.outside) return w.outside;
    if (w.p) note(w.p, "fetched", scope);
  }
  // wget, and curl -O, save under the URL's file name, in the current directory or the one
  // named by --output-dir (curl) or -P (wget).
  const remoteName = curl ? opts.some(([flag]) => ["-O", "--remote-name", "--remote-name-all"].includes(flag)) : !saved.length;
  if (!remoteName) return ALLOW;
  const named = values(DOWNLOAD_FILES[cmd].dir).at(-1);
  const dir = named === undefined ? scope.cwd : resolveWord(named, scope);
  if (isPiFile(dir, scope)) return piAsk(`${cmd} writes into Pi's own files: ${named ?? dir}`);
  if (!isLocal(dir, scope)) return outside(`${cmd} writes outside the working directory${named ? `: ${named}` : ""}`, dir);
  for (const url of args.filter((a) => /^https?:\/\//.test(a))) {
    const file = path.basename(url.split(/[?#]/)[0]);
    if (file && dir) note(path.join(dir, file), "fetched", scope);
  }
  return ALLOW;
}

// The options of curl and wget that name a file they write: the download itself (`saved`), other
// files such as a cookie jar or a log (`other`), and the directory a remote name is saved in.
const DOWNLOAD_FILES: Record<string, { saved: string[]; other: string[]; dir: string[] }> = {
  curl: { saved: ["-o", "--output"], other: ["-c", "--cookie-jar", "-D", "--dump-header", "--trace", "--trace-ascii", "--stderr"], dir: ["--output-dir"] },
  wget: { saved: ["-O", "--output-document"], other: ["-o", "--output-file", "-a", "--append-output"], dir: ["-P", "--directory-prefix"] },
};

// Options with their values. `valued` holds the short options that take one, so a cluster like
// `-fsSLo file`, `-ofile` or `-qO-` reads right; `long` the long options whose value may be the
// next word.
function optionValues(args: string[], valued: string, long: string[]): [string, string | undefined][] {
  const out: [string, string | undefined][] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      out.push(eq > 0 ? [a.slice(0, eq), a.slice(eq + 1)] : [a, long.includes(a) ? args[++i] : undefined]);
    } else if (a.length > 1 && a.startsWith("-")) {
      for (let j = 1; j < a.length; j++) {
        if (!valued.includes(a[j])) {
          out.push([`-${a[j]}`, undefined]);
          continue;
        }
        out.push([`-${a[j]}`, j + 1 < a.length ? a.slice(j + 1) : args[++i]]);
        break;
      }
    }
  }
  return out;
}

// find's words read as find reads them (round 56, Astra): its options and paths, then
// predicates, some of which take one or two values (`-name -exec` names a pattern), and actions,
// whose command runs to its `;` or `{} +`. `at` holds the place of each action word.
const FIND_ONE = new Set(
  `-name -iname -path -ipath -wholename -iwholename -regex -iregex -regextype -type -xtype -user -group -perm -size -mtime -mmin -atime -amin -ctime
   -cmin -newer -anewer -cnewer -samefile -inum -links -maxdepth -mindepth -fprint -fprint0 -fls -printf -lname -ilname -uid -gid -used -context
   -files0-from -fstype`.split(/\s+/),
);
// (Round 58, Opus: as find's `looks_like_expression` tells, a word is an expression only if it is a
// `-` followed by more, or exactly `(`, `!`, `)` or `,`: a lone `-` or `!x` is a start point.)
export const findExpression = (w: string) => /^-./.test(w) || /^[(!),]$/.test(w);
// (Round 59, Astra: where a start point may stand, `)` and `,` are files: find takes them for an
// expression only after one has begun.)
export const findStartExpression = (w: string) => /^-./.test(w) || w === "(" || w === "!";
// The files find writes no file to: a device it opens by name, the path normalised without `..`
// (round 61, Sol and Astra: `/dev/./null`, `/dev//stdout`). Not `/dev/fd/N`, which find reopens:
// the file behind the descriptor is written (round 61, Opus).
const findSink = (p: string) => !p.split("/").includes("..") && /^\/dev\/(null|zero|full|stdout|stderr|tty)$/.test(path.posix.normalize(p));
export function findActions(args: string[]): { at: number[]; names: string[]; files0: boolean; prints: boolean } {
  const at: number[] = [];
  let files0 = false;
  let prints = false;
  let k = 0;
  while (k < args.length && /^-[HLP]$|^-D$|^-O\d*$/.test(args[k])) {
    // (Round 59, Astra and Sol: `help` anywhere in -D's comma list.)
    if (args[k] === "-D" && (args[k + 1] ?? "").split(",").includes("help")) prints = true;
    k += args[k] === "-D" ? 2 : 1;
  }
  // `-D help` prints before find reads its expression (round 59, Opus: it opens no output).
  if (prints) return { at: [], names: [], files0: false, prints };
  if (args[k] === "--") k++;
  while (k < args.length && !findStartExpression(args[k])) k++;
  for (; k < args.length; k++) {
    const w = args[k];
    // (Round 58, Sol: `-help` and `-version` print and run no action; Astra and Sol:
    // `-files0-from` as find reads it, not a `-name` pattern. Round 59, Opus: find opens each
    // output file as it reads it, so those named before the help word are written; the reading
    // stops there.)
    if (/^--?(help|version)$/.test(w)) {
      prints = true;
      break;
    }
    if (w === "-files0-from") files0 = true;
    // (Round 60, Sol: an output action to a device sink, `-fprint0 /dev/stdout`, writes no file.)
    if (/^-(delete|exec|execdir|ok|okdir)$/.test(w) || (/^-(fprint|fprint0|fprintf|fls)$/.test(w) && !findSink(args[k + 1] ?? ""))) at.push(k);
    if (/^-(exec|execdir|ok|okdir)$/.test(w)) {
      while (k + 1 < args.length && !(args[k + 1] === ";" || (args[k + 1] === "+" && args[k] === "{}"))) k++;
      k++;
    } else if (w === "-fprintf" || /^-newer[aBcmt][aBcmt]$/.test(w)) k += w === "-fprintf" ? 2 : 1;
    else if (FIND_ONE.has(w)) k++;
  }
  // A query keeps the output actions read before it; it runs and deletes nothing.
  const kept = prints ? at.filter((i) => /^-(fprint|fprint0|fprintf|fls)$/.test(args[i])) : at;
  return { at: kept, names: kept.map((i) => args[i]), files0: prints ? false : files0, prints };
}

function find(args: string[], scope: Scope): Verdict {
  // (Round 57, Opus: the start points come after find's own leading options, `-H -L -P -D x -O<n>`,
  // and `--`: `find -L ~ -delete` starts at `~`.)
  let lead = 0;
  while (lead < args.length && /^-[HLP]$|^-D$|^-O\d*$/.test(args[lead])) lead += args[lead] === "-D" ? 2 : 1;
  if (args[lead] === "--") lead++;
  const rest = args.slice(lead);
  const firstOption = rest.findIndex(findStartExpression);
  const roots = firstOption < 0 ? rest : rest.slice(0, firstOption);
  const actions = findActions(args);
  if (!actions.at.length) return ALLOW;
  // Start points read from a file are places the rules cannot tell.
  if (actions.files0) return ask("find deletes or runs commands at start points read from a file");
  for (const r of roots.length ? roots : ["."]) {
    const p = resolveWord(r, scope);
    if (isPiFile(p, scope)) return piAsk(`find deletes or runs commands in Pi's own files: ${r}`);
    if (!isLocal(p, scope)) return outside(`find deletes or runs commands outside the working directory: ${r}`, p);
    // (Round 57, Opus: a start point in a .git directory, where git finds hooks and config.)
    if (/(^|\/)\.git(\/|$)/.test(p ?? r)) return ask(`find deletes or runs commands in a .git directory: ${r}`);
  }
  // (Round 60, Opus: every action find runs, not only the first, each ending where find ends it:
  // at `;`, or at `+` straight after `{}`; `find . -exec true \; -exec rm -rf ~ \;`.)
  const execs = actions.at.filter((i) => /^-(exec|execdir|ok|okdir)$/.test(args[i]));
  if (!execs.length) return classify("find -delete or a -fprint write");
  let verdict = classify("find -exec");
  for (const exec of execs) {
    const end = args.findIndex((a, i) => i > exec && (a === ";" || (a === "+" && args[i - 1] === "{}")));
    // {} stands for a path under the search roots, which were checked above.
    // (Round 61, Opus: the `{}` before `+` is the command's last word, a path, `rm -rf {} +`.)
    const inner = args.slice(exec + 1, end < 0 ? undefined : end).map((a) => (a === "{}" ? "." : a));
    verdict = worst(verdict, simple({ argv: inner, out: [], dyn: inner.map((a) => /[$`]/.test(a)) }, scope, 1));
  }
  return verdict;
}

// Drops leading keywords, VAR=value assignments and wrappers such as `timeout 60` or `env`.
// Empty when nothing is left to run. With `only`, drops just the keywords and those wrappers
// (by exact name) and stops at an assignment.
// Keywords count only before any assignment (`x= done` runs a program called `done`), and
// assignments only before the program and as operands of `env` (`nice x=/a` runs `x=/a`). A loop
// header gives the command after its `do`, if it is on the same line. A wrapper option the rules
// do not know gives UNMODELLED.
function unwrap(words: string[], only?: Set<string>): string[] {
  const argv = [...words];
  const assignment = (word: string) => !only && ASSIGNMENT.test(word);
  let assigned = false;
  let wrapped = false;
  for (;;) {
    while (argv.length && ((!assigned && !wrapped && KEYWORDS.has(argv[0])) || (!wrapped && assignment(argv[0])))) assigned = assignment(argv.shift()!) || assigned;
    if (!argv.length) return [];
    if (!assigned && (argv[0] === "for" || argv[0] === "select")) {
      const body = argv.indexOf("do");
      return body < 0 ? [] : unwrap(argv.slice(body + 1), only);
    }
    // `done`, `fi`, `esac` and `in` close or continue a compound command; words after them are a
    // syntax error to bash.
    if (!assigned && NOOP_KEYWORDS.has(argv[0])) return argv.length === 1 || argv[0] === "in" ? [] : [UNMODELLED];
    const wrapper = only ? argv[0] : path.basename(argv[0]);
    if (!(only ?? WRAPPERS).has(wrapper)) return argv;
    argv.shift();
    wrapped = true;
    // `command -v name` looks a command up and runs nothing.
    if (wrapper === "command" && /^-[vV]$/.test(argv[0] ?? "")) return [];
    const table = WRAPPER_OPTIONS[wrapper] ?? {};
    // nice's old spelling of the adjustment, `nice -10`.
    while (wrapper === "nice" && /^--?\d+$/.test(argv[0] ?? "")) argv.shift();
    // env's `-` is -i.
    if (wrapper === "env" && argv[0] === "-") argv.shift();
    const k = leadingOptions(argv, table);
    if (k < 0) return [UNMODELLED];
    argv.splice(0, k);
    if (table.operand) {
      if (!table.operand.test(argv[0] ?? "")) return [UNMODELLED];
      argv.shift();
    }
    if (wrapper === "env") while (argv.length && assignment(argv[0])) argv.shift();
  }
}

// Where the output of a simple command comes from. Literal text is the agent's own: echo and
// printf without a variable or substitution, and cat of a heredoc.
function outputOrigin(cmd: Simple, scope: Scope): Origin {
  const [program = "", ...args] = unwrap(cmd.argv);
  const name = path.basename(program);
  if (name === "curl" || name === "wget") return "fetched";
  const literal = !cmd.expands && !args.some((a) => /[$`]/.test(a));
  if (literal && (name === "echo" || name === "printf" || (name === "cat" && cmd.heredoc && !operands(args).length))) return "authored";
  return args.some((a) => isFetched(a, scope)) ? "fetched" : "other";
}

function redirects(cmd: Simple, scope: Scope): Verdict {
  let verdict = ALLOW;
  const origin = cmd.out.length ? outputOrigin(cmd, scope) : "other";
  for (const target of cmd.out) {
    const p = resolveWord(target, scope);
    if (devSink(target, p)) continue;
    if (p && /^\/dev\//.test(p) && !inTmp(p)) return deny(`writes to the device ${target}`);
    if (isGuarded(p, scope)) verdict = worst(verdict, guardAsk("redirect overwrites the auto-mode guard's own files"));
    else if (isPiFile(p, scope)) verdict = worst(verdict, piAsk(`redirect writes Pi's own files: ${target}`));
    else if (!isLocal(p, scope)) verdict = worst(verdict, outside(`redirect writes outside the working directory: ${target}`, p));
    // Appending literal text to a file of the project makes it one the session wrote; any other
    // origin stays as it was.
    if (!(origin === "authored" && cmd.append?.includes(target))) note(p, origin, scope);
    else if (p && originOf(p, scope) === undefined) note(p, "authored", scope);
  }
  return verdict;
}

// Redirect targets are always checked by the built-in rules (allowedPaths is the way to open
// a directory). For the command itself a user rule replaces the built-in verdict.
function simple(cmd: Simple, scope: Scope, depth = 0): Verdict {
  const out = redirects(cmd, scope);
  if (out.action === "deny") return out;
  let builtin = command(cmd, scope, depth);
  // The pattern a confirm prompt offers, so the next call like it does not ask. An ask gets one
  // that is offered for the session only; a call the rules leave to a decider gets one that can
  // also be saved, because there the command itself is what decided, and the model only scored it.
  if (!builtin.locked && !builtin.firm && !builtin.pattern && !("dir" in builtin)) {
    const pattern = askPattern(unwrap(cmd.argv));
    if (pattern) builtin = { ...builtin, pattern, ...(builtin.action === "ask" ? { fromAsk: true } : {}) };
  }
  if (builtin.action === "deny" || builtin.locked) return worst(out, builtin);
  const mine = scope.rules && userVerdict(cmd.argv, scope.rules);
  if (mine) return worst(out, mine);
  if (scope.picked && !builtin.firm && allowedBy(cmd.argv, scope.picked)) return worst(out, ALLOW);
  return worst(out, builtin);
}

// Only the plain spellings are left to the option readers (`unreadSpelling`); any other asks. The
// readers still run, so a stronger verdict (a deny, a guarded file) or an ask of their own, with
// its reason and the folder it offers, is kept.
function command(cmd: Simple, scope: Scope, depth: number): Verdict {
  const verdict = commandRead(cmd, scope, depth);
  const argv = unwrap(cmd.argv);
  const unread = argv.length && argv[0] !== UNMODELLED ? unreadSpelling(path.basename(argv[0]), argv.slice(1)) : undefined;
  return unread ? worst(verdict, { ...ask(unread), spelling: true }) : verdict;
}

function commandRead(cmd: Simple, scope: Scope, depth: number): Verdict {
  let verdict = ALLOW;
  const argv = unwrap(cmd.argv);
  if (argv[0] === UNMODELLED) return classify("shell syntax or a wrapper option the rules do not model");
  // Variables set for the program or in the shell: those that can change what runs go to the decider.
  const set = variablesSet(cmd, argv);
  if (typeof set === "string") verdict = classify(set);
  else {
    const problem = set.map(([n, v, how]) => variableProblem(n, v, how, scope)).find(Boolean);
    if (problem) verdict = classify(problem);
  }
  if (!argv.length) return verdict;

  const name = path.basename(argv[0]);
  const args = argv.slice(1);
  // The words of `argv` that the shell expands before the program sees them.
  const offset = cmd.argv.length - argv.length;
  const dyn = (k: number) => cmd.dyn?.[offset + 1 + k] ?? /[$`]/.test(args[k] ?? "");
  // The same command with fewer words at the front, keeping what is known of each word.
  const tail = (inner: string[], extra: boolean[] = []): Simple => ({ argv: [...inner, ...extra.map(() => "$()")], out: [], dyn: [...inner.map((_, k) => cmd.dyn?.[cmd.argv.length - inner.length + k] ?? /[$`]/.test(inner[k])), ...extra] });

  if (["case", "function", "select", "source", ".", "trap", "alias"].includes(name)) return worst(verdict, classify(`shell ${name}`));
  if (/^mkfs(\.|$)/.test(name) || name === "wipefs") return deny(`${name} formats a disk`);

  // The guard's own files: only read-only commands may name them.
  if (!READ_ONLY.has(name) && args.some((a) => isGuarded(resolveWord(a.replace(/^[^=]*=/, ""), scope), scope))) {
    verdict = worst(verdict, guardAsk(`${name} touches the auto-mode guard's own files`));
  }
  const secret = credentialRead(name, args, cmd, scope);
  if (secret) verdict = worst(verdict, criticalAsk(`${name} reads a credential file: ${secret}`));
  // A reader whose file is named by an expansion could be reading anything, a credential included.
  else {
    const unknown = readsExpansion(name, args, dyn, cmd, scope);
    if (unknown) verdict = worst(verdict, unknown.includes("credential") ? criticalAsk(unknown) : classify(unknown));
  }
  // Pi's package commands change its settings and what code every session loads.
  if (name === "pi" && ["install", "remove", "uninstall", "update", "config"].includes(args[0])) verdict = worst(verdict, piAsk(`pi ${args[0]} changes Pi's own setup`));
  // A program named by its path is the tool its name says only in a system directory or in the
  // project (`.venv/bin/pip`, `node_modules/.bin/tsc`): /tmp/file is not file(1), /opt/x/ls not
  // ls, and a file this session wrote or downloaded is what it holds. Elsewhere it must be a file
  // the rules let run, and then the rules for its name apply as well.
  if (argv[0].includes("/")) {
    const word = expandVars(argv[0], scope);
    const p = resolveWord(argv[0], scope);
    const absolute = path.isAbsolute(word) ? path.normalize(word) : p;
    const known = !!p && originOf(p, scope) === undefined && ((!!absolute && SYSTEM_BIN.has(path.dirname(absolute))) || (isLocal(p, scope) && !inTmp(p)));
    if (!known) {
      const own = runFile(argv[0], args, scope) ?? classify(`runs ${argv[0]}`);
      if (own.action !== "allow") return worst(verdict, own);
    }
  }

  if (name === "sudo" || name === "doas") {
    const inner = afterFlags(args, /^-[ugCDhpRrTU]$/);
    return worst(verdict, criticalAsk(`${name} runs as root`), inner.length ? simple(tail(inner), scope, depth + 1) : ALLOW);
  }
  if (ALWAYS_ASK[name]) return worst(verdict, (name === "su" || name === "pkexec" ? criticalAsk : ask)(`${name} ${ALWAYS_ASK[name]}`));
  // (Round 3, Opus: git's credential helpers run as programs print stored passwords too.)
  if (/^git-credential/.test(name)) return worst(verdict, criticalAsk(`${name} prints or changes stored passwords`));
  // (opencode-automode: a lone `-h` or `-V` is an option of many programs, hashall to a shell,
  // verbose to vim, after which they read standard input; only the programs these rules know (read
  // only, dev tools, tools with subcommands, runners, interpreters) take it as help or a version
  // here. `--help` and `--version` stay.)
  if (args.length === 1 && (/^--(version|help)$/.test(args[0]) || (/^-[Vh]$/.test(args[0]) && (READ_ONLY.has(name) || DEV_TOOLS.has(name) || !!SUBCOMMANDS[name] || !!RUNNERS[name] || INTERPRETERS.has(name))))) return verdict;

  // (Round 37, Mythos: declare and its kin read an assignment word again, `a=(...)` as a compound
  // assignment that expands what it holds, `declare -a 'a=($(cmd))'`. The parenthesised text is
  // read as commands; a value the outer shell expands is not modelled.)
  if (["declare", "typeset", "local", "readonly", "export"].includes(name)) {
    for (let k = 0; k < args.length; k++) {
      const m = /^[A-Za-z_]\w*(\[[^\]]*\])?\+?=(.*)$/s.exec(args[k]);
      if (!m) continue;
      if (dyn(k)) {
        verdict = worst(verdict, classify(`${name} of a value the shell expands, which ${name} reads again`));
        continue;
      }
      if (m[2].startsWith("(")) verdict = worst(verdict, classify(`${name} of a compound assignment`), evaluateParsed(parse(m[2].replace(/^\(|\)$/g, "")), scope, depth + 1));
    }
  }
  if (SHELLS.has(name)) return worst(verdict, shell(name, args, dyn, cmd, scope, depth));
  // eval runs its words joined, after the shell has expanded them: a variable in them is code
  // the rules cannot see.
  if (name === "eval") return worst(verdict, args.some((_, k) => dyn(k)) ? classify("eval of expanded text") : evaluateParsed(parse(args.join(" ")), scope, depth + 1));
  if (name === "set") {
    const problem = setProblem(args);
    if (problem) return worst(verdict, classify(problem));
  }
  if (name === "shopt" && args.includes("extglob") && args.some((a) => /^-[a-z]*s/.test(a))) return worst(verdict, classify("shopt -s extglob changes how later lines are read"));
  // test -v evaluates a subscript as arithmetic.
  if ((name === "test" || name === "[") && args.some((a, k) => args[k - 1] === "-v" && a.includes("["))) return worst(verdict, classify("test -v of a subscript, evaluated as arithmetic"));
  // `uv run pytest` and similar: the rest of the line is the command.
  if (RUNNERS[name]) {
    const lead = leadingOptions(args, LEAD_OPTIONS[name] ?? {});
    if (lead >= 0 && args[lead] === RUNNERS[name]) {
      const from = lead + 1;
      const k = leadingOptions(args, RUNNER_OPTIONS[name] ?? {}, from);
      if (k < 0) return worst(verdict, classify(`${name} ${RUNNERS[name]} with an option the rules do not model`));
      // (Project review 6, Opus: the runner's own words, before the command it runs, name places
      // too, `uv run --project .. pytest`, `uv run -p ../venv/bin/python pytest`.)
      if (PROJECT_TOOLS.has(name)) {
        // (Cross-check 2, Opus: one built at run time, `uv run --python="$(cat x)" pytest`, goes
        // to the decider: no other check reads the runner's own words.)
        const built = args.slice(0, k).find((a) => /[$`]/.test(expandVars(a, scope)));
        if (built !== undefined) verdict = worst(verdict, classify(`${name} ${RUNNERS[name]} ${built}: a word built at run time, which may name the program or the project it runs`));
        const own = projectToolPlaces(name, args.slice(0, k), scope, dyn);
        if (own) verdict = worst(verdict, own);
        if (verdict.action === "ask") return verdict;
      }
      const inner = args.slice(k);
      return worst(verdict, inner.length ? simple(tail(inner), scope, depth + 1) : ALLOW);
    }
  }
  // (Round 50, Sol and Astra: a call that only prints its help or version does nothing else.)
  if (printsOnly(name, args)) return verdict;
  // (Round 35, Mythos: a colon before the first slash makes an operand remote for rsync, with an
  // empty host too (`:x`), and `-e` then runs locally.)
  // rsync, read by position (rsyncReading, round 41): a remote operand asks, so does --daemon;
  // the files it writes besides its destination (log, batch, backup, temp, partial places) are
  // held to the write test, a dry run's too; a dry run, a listing or one operand copies and deletes
  // nothing; --remove-source-files deletes its sources and --delete what the destination holds
  // beyond the source (held to rm's test outside the project and for .git, rounds 39 and 40).
  if (name === "rsync") {
    const r = rsyncReading(args);
    // (Round 52, Astra: a version query reaches no host.)
    if (!r.prints && r.operands.some((a) => /^[^/]*:/.test(a))) return worst(verdict, ask("rsync copies to or from a remote host"));
    if (r.daemon && !r.prints) return worst(verdict, ask("rsync --daemon starts a server"));
    if (r.server && !r.prints) return worst(verdict, classify("rsync --server writes what its standard input sends"));
    // (Round 44, Opus: what `-M`/`--remote-option` hands the receiving side, which for a local
    // copy is this machine, is read as rsync's own words: `-M--log-file=../x`.)
    const remote = rsyncReading([...r.shorts.filter(([l]) => l === "M").map(([, v]) => v ?? ""), ...r.values("remote-option")]);
    // (Round 45, Sol: a dry run writes its log and batch, but no backup, partial or temp files.)
    const places = (x: ReturnType<typeof rsyncReading>) => (r.help ? [] : r.prints ? x.values("log-file") : [...["log-file", "write-batch", "only-write-batch", ...(r.dryRun || r.listOnly ? [] : ["backup-dir", "partial-dir", "temp-dir"])].flatMap((n) => x.values(n)), ...(r.dryRun || r.listOnly ? [] : x.shorts.filter(([l]) => l === "T").map(([, v]) => v ?? ""))]);
    // (Round 49, Sol: a version or help query starts no receiver, so its `-M` words open nothing.)
    const outputs = [...places(r), ...(r.prints ? [] : places(remote))];
    if (outputs.some((f) => /(^|\/)\.git(\/|$)/.test(resolveWord(f, scope) ?? f))) return worst(verdict, ask("rsync writes a file in a .git directory"));
    if (outputs.length) {
      const w = writeTargets("tee", ["--", ...outputs], scope);
      if (w.action !== "allow") return worst(verdict, { ...w, reason: w.reason.replace(/^tee/, "rsync") });
    }
    if (r.copiesNothing) return verdict;
    // (Round 42, Mythos: `--read-batch` replays a recorded update, deletions included, into its
    // one operand: held to the write test there, then left to the model.)
    if (r.batch) {
      const w = writeTargets("tee", ["--", ...r.operands.slice(-1)], scope);
      return worst(verdict, w.action !== "allow" ? { ...w, reason: w.reason.replace(/^tee/, "rsync --read-batch") } : classify("rsync --read-batch replays a recorded update"));
    }
    const removes = r.longs.some(([h]) => /^--remove-(source|sent)-files$/.test(h) || (h.length >= 9 && "--remove-source-files".startsWith(h)));
    const deletes = r.longs.some(([h]) => /^--del/.test(h));
    let gone = ALLOW;
    if (removes) for (const src of r.operands.length === 1 ? r.operands : r.operands.slice(0, -1)) gone = worst(gone, deletion(src, scope));
    if (deletes) gone = worst(gone, deletion(r.operands.at(-1)!, scope));
    if (gone.action !== "allow") return worst(verdict, gone);
  }
  // (Project review 6, Opus, Sol, Neon: two programs of the read-only list write a file an option
  // names: `ss -D FILE` / `--diag` dumps raw socket data there, `fastfetch --gen-config[-force]
  // [FILE]` writes a config, its own by default, whose commands later runs execute. Any such
  // option asks, in any spelling: a cluster holding D, a long one by any prefix.)
  if (name === "ss" && args.some((a) => (/^-[^-]*D/.test(a)) || (a.startsWith("--") && a.split("=")[0].length >= 3 && "--diag".startsWith(a.split("=")[0])))) return worst(verdict, ask("ss -D writes raw socket data to a file"));
  if (name === "fastfetch" && args.some((a) => /^--gen/.test(a))) return worst(verdict, ask("fastfetch --gen-config writes a config file, which later runs read"));
  // Files written by an option (round 39, Mythos): held to the write test.
  // Long options by any prefix the tool takes (round 40, Mythos: `--cursor-fil=`).
  const optionWrites: Record<string, { short: RegExp; long: string[] }> = { journalctl: { short: /^$/, long: ["cursor-file"] }, zip: { short: /^-(O|b)$/, long: ["out", "temp-path"] }, docker: { short: /^$/, long: ["iidfile", "metadata-file"] } };
  if (Object.hasOwn(optionWrites, name)) {
    const table = optionWrites[name];
    const named = args.flatMap((a, k) => {
      const eq = a.indexOf("=");
      const head = eq > 0 ? a.slice(0, eq) : a;
      const isLong = head.startsWith("--") && head.length >= 4 && table.long.some((o) => longIs(head, o));
      if (eq > 0 && isLong) return [a.slice(eq + 1)];
      if (isLong || table.short.test(a)) return [args[k + 1] ?? ""];
      const attached = name === "zip" ? /^-(O|b)(.+)$/.exec(a) : null;
      return attached ? [attached[2]] : [];
    });
    if (named.some((f) => /(^|\/)\.git(\/|$)/.test(resolveWord(f, scope) ?? f))) return worst(verdict, ask(`${name} writes a file in a .git directory`));
    if (named.length) {
      const w = writeTargets("tee", ["--", ...named], scope);
      if (w.action !== "allow") return worst(verdict, { ...w, reason: w.reason.replace(/^tee/, name) });
    }
  }
  // (Round 40, Mythos: ps prints other processes' environments with BSD `e` or `environ`.)
  // (Round 42, all four: read by position, psEnvironments.)
  if (name === "ps" && psEnvironments(args)) return worst(verdict, ask("ps that prints other processes' environments"));
  // (setfacl --restore takes its paths from a file.)
  if (name === "setfacl" && args.some((a) => longIs(a, "restore") && a.split("=")[0].length >= 4)) return worst(verdict, classify("setfacl --restore changes the files a list names"));
  if (name === "nm" && args.some((a) => longIs(a, "plugin") && a.split("=")[0].length >= 4)) return worst(verdict, classify("nm --plugin loads a shared object"));
  if (name === "xargs") {
    const k = leadingOptions(args, { flags: "0oprtx", valued: "adEILnPs", long: ["null", "interactive", "no-run-if-empty", "verbose", "exit", "open-tty", "show-limits"], longValued: ["arg-file", "delimiter", "eof", "replace", "max-lines", "max-args", "max-procs", "max-chars", "process-slot-var"] });
    if (k < 0 || args.slice(0, k).some((a) => /^-[eil]/.test(a))) return worst(verdict, classify("xargs with options the rules do not model"));
    const inner = args.slice(k);
    return worst(verdict, classify("xargs"), inner.length ? simple(tail(inner, [true]), scope, depth + 1) : ALLOW);
  }
  // (Project review 6, Neon, Opus: `meson wrap install`, `meson subprojects download` fetch a
  // dependency's sources; `meson subprojects foreach` runs a command.)
  if (name === "meson" && ["wrap", "subprojects"].includes(operands(args)[0] ?? "")) verdict = worst(verdict, classify(`meson ${operands(args)[0]} fetches or changes a dependency's sources, or runs a command in each`));
  // (Round 8, Opus: a tool run as a module, `python -m pytest`, `python3 -m ruff`, is read as
  // the tool.)
  if (/^python3?(\.\d+)?$/.test(name) && args[0] === "-m" && /^(pytest|unittest|ruff|mypy|black|isort|build)$/.test(args[1] ?? "")) {
    const places = projectToolPlaces(`${name} -m ${args[1]}`, args.slice(2), scope, (k) => dyn(k + 2));
    if (places) verdict = worst(verdict, places);
  }
  if (PROJECT_TOOLS.has(name)) {
    const places = projectToolPlaces(name, args, scope, dyn);
    if (places) verdict = worst(verdict, places);
  }
  if (name === "cd" || name === "pushd" || name === "popd") return verdict;

  if (name === "rm") return worst(verdict, rm(args, scope));
  if (name === "dd") {
    const of = args.find((a) => a.startsWith("of="))?.slice(3);
    if (of === undefined) return worst(verdict, classify("dd"));
    const p = resolveWord(of, scope);
    if (p && /^\/dev\//.test(p) && !DEV_SINKS.test(p) && !inTmp(p)) return deny(`dd writes to the device ${of}`);
    if (isPiFile(p, scope)) return worst(verdict, piAsk(`dd writes Pi's own files: ${of}`));
    return worst(verdict, isLocal(p, scope) || (!!p && DEV_SINKS.test(p)) ? classify("dd") : outside(`dd writes outside the working directory: ${of}`, p));
  }
  if (name === "chmod" || name === "chown" || name === "chgrp") {
    const ch = name === "chmod" ? chmodReading(args) : undefined;
    const head = args.indexOf("--") < 0 ? args : args.slice(0, args.indexOf("--"));
    const recursive = ch ? ch.recursive : hasFlag(head, "R", "--recursive") || head.some((a) => longIs(a, "recursive") && a.split("=")[0].length >= 5);
    if (recursive) {
      for (const t of ch ? ch.files : operands(args).slice(1)) {
        const p = resolveWord(t, scope);
        if (p && isRootLike(p)) return deny(`${name} -R on ${t} would change a home or system directory`);
      }
    }
  }
  if (name === "sed") return worst(verdict, sed(args, scope));
  if (name === "awk" || name === "gawk") return worst(verdict, awk(args));
  if (name === "make") {
    const problem = make(args, scope);
    if (problem.action !== "allow") return worst(verdict, problem);
  }
  if (name === "sort") {
    // (Round 47, Sol: a word after `--` is a file, `sort -c -- --compress-program`. Round 48: read
    // by position, sortRunsCompressor.)
    if (sortRunsCompressor(args)) return worst(verdict, classify("sort --compress-program runs a program"));
  }
  if (name === "rg" && args.some((a) => /^--(pre|hostname-bin)(=|$)/.test(a))) return worst(verdict, classify(`rg ${args.find((a) => /^--(pre|hostname-bin)/.test(a))!.split("=")[0]} runs a program`));
  if ((name === "fd" || name === "fdfind") && args.some((a) => /^(-x|-X|--exec|--exec-batch)(=|$)/.test(a) || /^-[a-zA-Z]*[xX]$/.test(a))) return worst(verdict, classify("fd -x runs a command"));
  // man-db: a pager, a config file (which names the formatters), a browser or a preprocessor
  // is a program man runs; any option but these few is left to the decider.
  if (name === "man" && args.some((a) => /^-[a-zA-Z]*[PCH]/.test(a) || ["pager", "config-file", "html", "browser", "preprocessor"].some((o) => longIs(a, o)))) return worst(verdict, classify("man with an option that can name a program"));
  if (name === "file") {
    const head = args.indexOf("--") < 0 ? args : args.slice(0, args.indexOf("--"));
    const list = head.flatMap((a, k) => {
      const isLong = longIs(a, "files-from") && a.split("=")[0].length >= 7;
      if (a === "-f" || (isLong && !a.includes("="))) return [head[k + 1] ?? ""];
      if (isLong && a.includes("=")) return [a.slice(a.indexOf("=") + 1)];
      return /^-f./.test(a) ? [a.slice(2)] : [];
    });
    const secret = list.map((f) => secretIn(f, scope)).find(Boolean);
    if (secret) return worst(verdict, criticalAsk(`file -f prints the lines of a credential file: ${secret}`));
    if (list.some((f) => /[$`]/.test(f))) return worst(verdict, classify("file -f of a list named by an expansion"));
  }
  if ((name === "zip" && args.some((a) => a === "-TT" || longIs(a, "unzip-command"))) ) return worst(verdict, classify("zip -TT runs a program"));
  // (Round 35, Mythos: install -s runs the strip program on what it copied.)
  // (Round 36: `--strip-` is already a prefix getopt takes.)
  if (name === "install" && !copiesNothing(name, args) && args.some((a) => a.split("=")[0].startsWith("--strip-") && longIs(a, "strip-program"))) return worst(verdict, classify("install --strip-program runs a program on the file it writes"));
  // (Round 45, Sol: a copy that copies nothing writes nothing, `cp --version f dst/`.)
  if (WRITERS[name] && copiesNothing(name, args)) return verdict;
  if (WRITERS[name]) return worst(verdict, writeTargets(name, args, scope, !!cmd.heredoc && !cmd.expands));
  if (name === "tar" || name === "zip" || name === "unzip" || name === "gzip" || name === "gunzip" || name === "xz" || name === "zstd") {
    // (Round 39, Mythos: --remove-files deletes the members after archiving them: held to rm's test,
    // and unread under a -C/--directory.)
    // (Round 39, Mythos: --remove-files deletes the members after archiving them: held to rm's
    // test, and unread under a -C/--directory or from a list. Read by position, round 41.)
    const t = name === "tar" ? tarReading(args) : undefined;
    if (t && t.has("remove-files")) {
      if (t.dirs.length || t.has("files-from") || t.clusters.some((c) => c.includes("T"))) return worst(verdict, classify("tar --remove-files under another directory or from a list"));
      let gone = ALLOW;
      for (const m of [...t.members, ...t.values("add-file")]) gone = worst(gone, deletion(m, scope));
      if (gone.action !== "allow") return worst(verdict, gone);
    }
    // --add-file names a member like an operand (round 41, Mythos: held to the same outside test).
    if (t) for (const f of t.values("add-file")) if (!isLocal(resolveWord(f, scope), scope)) return worst(verdict, classify(`tar with a path outside the working directory`));
    const problem = name === "tar" ? tarProblem(args) : undefined;
    if (problem) return worst(verdict, classify(problem));
    // Archives read and write paths given as operands and after -f / -C / -d.
    // A compressor replaces its input with the compressed file beside it: one in a .git directory
    // is a write there (round 40, Opus: `gzip -- -/../.git/config`).
    // (Not a listing, a test, or output to standard output, round 41, Sol.)
    // (Round 42, Mythos: read by position, compressorReading; `-o` names a file it writes.)
    const z = compressorReading(name, args);
    if (z && [...(z.inPlace ? z.operands : []), ...z.outputs].some((a) => /(^|\/)\.git(\/|$)/.test(resolveWord(a, scope) ?? a))) return worst(verdict, ask(`${name} writes in a .git directory`));
    // (Round 44, Opus: a decompression in place names its output by the input less its suffix:
    // `gzip -d sub/.git.gz` writes `sub/.git`. Round 45, Opus, Sol, Astra: that name exactly, with
    // `-S` read, and a glob read as the names it matches here; `-N` and `-r` write names the
    // command does not show.)
    if (z && z.decompress && z.inPlace) {
      if (z.unnamed) return worst(verdict, classify(`${name} -d ${z.unnamed} writes names the command does not show`));
      for (const a of z.operands) {
        const names = /[*?[]/.test(a) ? globNames(a, scope) : [a];
        if (names === undefined) return worst(verdict, classify(`${name} -d of a glob the rules cannot list`));
        if (names.some((n) => path.basename(z.outputName(n) ?? "") === ".git")) return worst(verdict, ask(`${name} -d writes a file named .git`));
      }
    }
    // (Project review 3, round 3, Mythos: what a compressor writes in place, read with the call's
    // own variables, `x=AGENTS.md.gz; gunzip $x`; a name with no known suffix is written as given.
    // Only a word with an expansion: a plain one is read where the whole command is checked
    // (guard.ts, secondNames), and a plain glob there too, each name less its suffix, so that
    // `gunzip *.gz` beside an AGENTS.md does not ask. A glob after the variable is the names it
    // matches here, `x=sub; gunzip $x/*.gz`; a name the rules cannot resolve asks.)
    if (z && z.inPlace && !z.reads) {
      for (const a of z.operands) {
        if (!/[$`]/.test(a)) continue;
        const word = expandVars(a, scope);
        if (/[$`]/.test(word)) return worst(verdict, ask(`${name} writes beside a file whose name is built at run time: ${a}`));
        const names = /[*?[]/.test(word) ? globNames(word, scope) : [word];
        if (names === undefined) return worst(verdict, ask(`${name} of a glob the rules cannot list: ${a}`));
        for (const n of names) {
          if (isPiFile(resolveWord(z.decompress ? (z.outputName(n) ?? n) : n, scope), scope)) return worst(verdict, piAsk(`${name} writes Pi's own files: ${a}`));
        }
      }
    }
    // (Project review 3, round 4, Mythos: the directory an extraction writes in, `tar -C` and
    // `unzip -d`, where the word holds an expansion: read with the call's own variables and held
    // to the protected names, `x=git; unzip -o a.zip -d sub/.$x`. A plain word or a glob is read
    // where the whole command is checked (guard.ts, writesOf). unzip's options are not read
    // here, so every operand of it is held to the test, and an option word that holds an
    // expansion, `-d$x`, is not followed, nor is a word the call's variables make an option,
    // `x=-d; unzip -o a.zip $x sub/.git`.)
    if (name === "unzip" && args.some((a) => /[$`]/.test(a) && (a.startsWith("-") || expandVars(a, scope).startsWith("-")))) return worst(verdict, classify("unzip with an option built at run time"));
    const extracts = !!t && (t.has("extract") || t.has("get") || t.letter("x")) && !(t.has("to-stdout") || t.letter("O"));
    for (const a of name === "unzip" ? operands(args) : extracts ? t!.dirs : []) {
      const p = /[$`]/.test(a) ? resolveWord(a, scope) : undefined;
      if (p && /(^|\/)\.git(\/|$)/.test(p)) return worst(verdict, ask(`${name} writes in a .git directory`));
      if (isPiFile(p, scope)) return worst(verdict, piAsk(`${name} writes Pi's own files: ${a}`));
    }
    for (const a of operands(args)) {
      if (!isLocal(resolveWord(a, scope), scope)) return worst(verdict, classify(`${name} with a path outside the working directory`));
    }
    return verdict;
  }
  if (name === "curl" || name === "wget") return worst(verdict, network(name, args, scope));
  if (name === "find") return worst(verdict, find(args, scope));
  if (name === "git") return worst(verdict, git(args, scope));
  if (name === "gh") return worst(verdict, gh(args));
  if (name === "llamastash") return worst(verdict, llamastash(args));
  if (name === "crontab") return worst(verdict, args.length === 1 && args[0] === "-l" ? ALLOW : ask("crontab changes scheduled jobs"));
  if (name === "sysctl") return worst(verdict, args.some((a) => a === "-w" || a.includes("=")) ? ask("sysctl changes kernel settings") : ALLOW);
  if (name === "pacman" || name === "paru" || name === "yay") {
    return worst(verdict, /^-(Q|Ss|Si|Sl|Sg|F|T|V|h)/.test(args[0] ?? "-h") ? ALLOW : ask(`${name} changes system packages`));
  }
  if (name === "npm" && operands(args)[0] === "config" && ["set", "delete", "edit"].includes(operands(args)[1])) {
    return worst(verdict, ask("npm config changes settings outside the project"));
  }
  // (Round 38: build options that publish or reach out.)
  if (name === "docker" && operands(args)[0] === "build" && args.some((a) => /^--(push|output|ssh|secret)(=|$)/.test(a) || /^-o/.test(a))) return worst(verdict, classify("docker build that publishes, exports or uses credentials"));
  if (name === "docker") {
    const [group, action] = operands(args);
    if (group === "compose" || group === "buildx") return worst(verdict, classify(`docker ${group}`));
    // (Project review 6, Neon: docker's own options before the group are read as for one word,
    // `docker --host=ssh://prod container ls` reaches another daemon.)
    if (group && args[0]?.startsWith("-") && leadingOptions(args, LEAD_OPTIONS.docker) < 0) return worst(verdict, classify("docker with an option before its command that the rules do not model"));
    if (group && Object.hasOwn(DOCKER_GROUPS, group)) {
      return worst(verdict, DOCKER_GROUPS[group].split(" ").includes(action) ? ALLOW : classify(`docker ${group} ${action ?? ""}`.trim()));
    }
  }
  if (name === "uv" && operands(args)[0] === "venv") {
    const v = venvTargets(args.slice(args.indexOf("venv") + 1), ["--python", "-p", "--prompt", "--index-url", "--extra-index-url"], scope);
    if (v.action !== "allow") return worst(verdict, v);
  }
  if (SUBCOMMANDS[name]) return worst(verdict, subcommand(name, args, scope));
  // (Round 35: whatever feeds its standard input, a group, a subshell, `exec <`, and in addopts.)
  // (Round 37, Mythos: `-o python_functions=interact` makes pytest call a function the call names.)
  // (Round 39: pytest empties --basetemp before it uses it: held to rm's test.)
  if (name === "pytest" || (/^python3?$/.test(name) && args[0] === "-m" && args[1] === "pytest")) {
    // (Also inside `-o addopts=...`, round 40, Mythos.)
    const base = args.flatMap((a, k) => [...(a === "--basetemp" ? [args[k + 1] ?? ""] : []), ...[...a.matchAll(/(?:^|[\s=])--basetemp[=\s]+([^\s'"]+)/g)].map((m) => m[1])]);
    for (const b of base) {
      const gone = rm(["-r", "--", b], scope);
      if (gone.action !== "allow") return worst(verdict, gone);
    }
  }
  if (/^python3?$/.test(name) && args[0] === "-m" && args[1] === "compileall") {
    // (Round 40, Astra: -d, -s, -p, -x, -i, -r, -j, -o and -e take a value, which names no
    // output; Mythos: a .git target asks. Project review 3, round 16, Neon: stop filtering
    // option values after `--`.)
    const rest = args.slice(2);
    const dirs: string[] = [];
    for (let k = 0; k < rest.length; k++) {
      const a = rest[k];
      if (a === "--") {
        dirs.push(...rest.slice(k + 1));
        break;
      }
      if (/^-[dspxirjoe]$/.test(a)) {
        k++;
        continue;
      }
      if (!a.startsWith("-")) dirs.push(a);
    }
    for (const d of dirs) {
      const p = resolveWord(d, scope);
      if (p && /(^|\/)\.git(\/|$)/.test(p)) return worst(verdict, ask(`compileall writes in a .git directory: ${d}`));
      const out = writeTargets("mkdir", ["--", d], scope);
      if (out.action !== "allow") return worst(verdict, out);
    }
  }
  if ((name === "pytest" || (/^python3?$/.test(name) && args[0] === "-m" && args[1] === "pytest")) && args.some((a) => /python_(functions|classes|files)=/.test(a))) return worst(verdict, classify("pytest collecting functions the call names"));
  if ((name === "pytest" || (/^python3?$/.test(name) && args[0] === "-m" && args[1] === "pytest")) && args.some((a) => /(^|[\s=])--(pdb|trace)/.test(a))) return worst(verdict, classify("pytest's debugger, which reads commands from standard input"));
  if (/^python3?$/.test(name) && args[0] === "-m" && args[1] === "mypy" && args.some((a) => (longIs(a, "install-types") || longIs(a, "python-executable")) && a.split("=")[0].length > 4)) return worst(verdict, classify("mypy that installs packages or runs another interpreter"));
  // (Project review 3, round 8, Neon & round 9: `uniq`, `xxd` and `python3 -m json.tool` take
  // `[IN [OUT]]`, so one operand that bash may expand into several words can overwrite the second
  // match, and any option spelling the reader does not know — such as an abbreviated `--ind` or
  // `--skip-f` or xxd `-co` — makes the output file unknown.)
  if (name === "uniq" || name === "xxd") {
    const ops = twoOpOperands(name, args);
    if (ops.unknown) return worst(verdict, ask(`${name} ${ops.unknown}: an option the rules do not read, so its output file is not known`));
    if (ops.operands.length === 1 && MAY_EXPAND.test(ops.operands[0])) return worst(verdict, ask(`${name} with one expanding operand (${ops.operands[0]}): bash may expand it into both input and output`));
  }
  if (name === "yq") {
    const yq = yqReading(args);
    if (yq.inPlace) {
      let targets = yq.files;
      // mikefarah yq v4 treats an existing non-directory first operand as an input file (expression
      // `.`), whatever follows (project review 3, round 14, Neon, Opus).
      if (yq.operands.length > 1 && yq.op0Index !== undefined) {
        const op0 = yq.operands[0];
        const op0Dyn = dyn(yq.op0Index);
        const op0Glob = !!cmd.glob?.[offset + 1 + yq.op0Index];
        const op0Tilde = op0.startsWith("~") && !resolveWord(op0, scope);
        if (op0Dyn || op0Glob || op0Tilde || !scope.cwd) {
          return worst(verdict, ask(`yq -i with a first operand (${op0}) that may name an existing file`));
        }
        const fileExists = (p: string | undefined): boolean | undefined => {
          if (!p) return false;
          if (scope.pending.has(p) || scope.links?.has(p)) return true;
          try {
            return !fs.statSync(p).isDirectory();
          } catch (e) {
            const code = (e as NodeJS.ErrnoException)?.code;
            return code === "ENOENT" || code === "ENOTDIR" ? false : undefined;
          }
        };
        const resolved = resolveWord(op0, scope);
        const literal = path.isAbsolute(op0) ? realish(path.normalize(op0)) : realish(path.resolve(scope.cwd, op0));
        const rEx = fileExists(resolved);
        const lEx = resolved === literal ? rEx : fileExists(literal);
        if (rEx === undefined || lEx === undefined) return worst(verdict, ask(`yq -i with a first operand (${op0}) that the rules cannot inspect`));
        if (rEx || lEx) targets = [op0, ...targets];
      }
      if (targets.some((f) => /(^|\/)\.git(\/|$)/.test(resolveWord(f, scope) ?? f))) return worst(verdict, ask("yq writes a file in a .git directory"));
      if (targets.length) {
        const w = writeTargets("tee", ["--", ...targets], scope);
        if (w.action !== "allow") return worst(verdict, { ...w, reason: w.reason.replace(/^tee/, "yq") });
      }
    }
  }
  if (READ_ONLY.has(name) || DEV_TOOLS.has(name)) return verdict;
  // (Council project review 2, round 34, Mythos: unittest imports and calls any name it is given,
  // `python3 -m unittest code.interact` then runs standard input as Python; its names must be the
  // project's own files or modules. pytest's debugger, below, reads commands from standard input.)
  // (Round 37, Mythos: `python3 -m pip` is pip, with pip's subcommand table; round 38: a lone
  // version or help query is one.)
  if (/^python3?$/.test(name) && args[0] === "-m" && args[1] === "pip") return args.length === 3 && /^(-V|--version|-h|--help)$/.test(args[2]) ? verdict : worst(verdict, subcommand("pip", args.slice(2), scope));
  // (Round 38, Mythos: venv writes its directory, and --clear empties it first.)
  // (`--upgrade-deps` runs pip install in the new environment.)
  if (/^python3?$/.test(name) && args[0] === "-m" && args[1] === "venv") return worst(verdict, args.some((a) => longIs(a, "upgrade-deps") && a.length > 4) ? classify("venv --upgrade-deps installs packages") : ALLOW, venvTargets(args.slice(2), ["--prompt"], scope));
  if (/^python3?$/.test(name) && args[0] === "-m" && args[1] === "json.tool") {
    const ops = twoOpOperands("json.tool", args.slice(2));
    if (ops.unknown) return worst(verdict, ask(`${name} -m json.tool ${ops.unknown}: an option the rules do not read, so its output file is not known`));
    if (ops.operands.length === 1 && MAY_EXPAND.test(ops.operands[0])) return worst(verdict, ask(`${name} -m json.tool with one expanding operand (${ops.operands[0]}): bash may expand it into both input and output`));
  }
  if (/^python3?$/.test(name) && args[0] === "-m" && PY_MODULES.has(args[1]) && !cmd.heredoc && (args[1] !== "unittest" || unittestNamesOwn(args.slice(2), scope))) return verdict;
  // `node --test`: the test runner over the project's test files, as `npm test` runs it.
  // (Round 9, Opus: only in the project, whose test files it finds by itself: `cd .. && node --test`.)
  if (name === "node" && args[0] === "--test" && !cmd.heredoc && scope.cwd !== undefined && isLocal(scope.cwd, scope)) {
    const k = leadingOptions(args, { long: ["test", "test-only", "test-force-exit", "experimental-test-coverage", "experimental-strip-types", "no-warnings", "enable-source-maps"], longValued: ["test-name-pattern", "test-skip-pattern", "test-concurrency", "test-timeout", "disable-warning"] });
    const reporters = args.filter((a) => /^--test-reporter(=|$)/.test(a));
    const files = k < 0 ? [] : args.slice(k);
    if (k >= 0 && reporters.length === 0 && files.every((f) => !/[$`]/.test(f) && runFile(f, [], scope)?.action === "allow")) return verdict;
  }
  if (INTERPRETERS.has(name)) {
    // `python3 scripts/x.py`: the script is the first argument. Inline code (-c, -e, a heredoc) stays with the model.
    const script = !cmd.heredoc && args[0] && !args[0].startsWith("-") ? runFile(args[0], args.slice(1), scope) : undefined;
    return worst(verdict, script ?? classify(`runs code with ${name}`));
  }
  // A program named by its path, such as ./scripts/build.sh or target/debug/app.
  if (argv[0].includes("/")) {
    const program = runFile(argv[0], args, scope);
    if (program) return worst(verdict, program);
  }
  return worst(verdict, { ...classify(`unknown command ${name}`), pattern: allowPattern(argv) });
}

// The allow pattern a confirm prompt offers for a command the rules do not know: the command
// and its subcommand or first flag, such as `terraform plan *`. None for a program named by
// path, whose name says nothing about what it is.
// For an ask: the subcommand, plus the word that says what changes for `gh pr edit *`,
// `git config --global *` and `git remote add *`. None when the first word is a flag or an
// operand, for root, for `gh api`, and for programs whose arguments are what they send: the
// pattern would cover the next call's flags and files too, such as `curl -sS -d @.env`.
const NO_ASK_PATTERN = new Set(["sudo", "doas", "curl", "wget", "scp", "rsync", "sftp", "ftp", "nc", "ncat", "netcat", "socat", "ssh", "telnet", "http", "https", "xh", "rclone"]);
// A word that names a file: it has a slash, or starts with `~` or `.`. Quotes, spaces and shell
// characters are left out, so a pattern is something the matcher can read back literally.
const FILE_WORD = /^[\w.~+-]*(?:\/[\w.~+-]*)+$/;
const invokedByPath = (word: string) => FILE_WORD.test(word) || /^[~.]$/.test(word);

// The pattern a confirm prompt offers for a command that asks: `git config remote *` for a
// subcommand, `bash ./wait.sh *` for a script, `./build.sh *` for a program of its own. Nothing
// for programs whose arguments are what they send, and nothing for inline code.
function askPattern(argv: string[]): string | undefined {
  const [program, sub = "", next = ""] = argv;
  // Checked on the last path component, so `/usr/bin/curl` is held to the same rule as `curl`.
  if (!program || NO_ASK_PATTERN.has(path.basename(program))) return undefined;
  if (invokedByPath(program)) return FILE_WORD.test(program) ? `${program} *` : undefined;
  if (!/^[\w.+-]+$/.test(program)) return undefined;
  if (sub && FILE_WORD.test(sub)) return `${program} ${sub} *`;
  if (!/^[a-z][\w-]*$/.test(sub)) return undefined;
  if (program === "gh" && sub === "api") return undefined;
  const third = program === "gh" ? /^[a-z][\w-]*$/.test(next) : program === "git" && ["config", "remote"].includes(sub) && /^(--)?[a-z][\w-]*$/.test(next);
  return `${program} ${sub}${third ? ` ${next}` : ""} *`;
}

function allowPattern(argv: string[]): string | undefined {
  if (!/^[\w.+-]+$/.test(argv[0])) return undefined;
  const first = argv[1] !== undefined && /^(-{1,2})?[A-Za-z][\w-]*$/.test(argv[1]) ? ` ${argv[1]}` : "";
  return `${argv[0]}${first} *`;
}

// ---- whole tool calls ----

const FORK_BOMB = /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:/;
// A download piped into a shell, or into an interpreter that reads its program from stdin.
// `curl ... | python3 -c "..."` is not one: the download is the program's input.
const PIPE_TO_SHELL = /\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(env\s+)?(ba|z|da|k)?sh\b|\b(curl|wget)\b[^|;&\n]*\|\s*(python3?|node|perl|ruby)\s*(-\s*)?($|[|;&\n)])/;

// The variables bash sets or computes by itself (bash 5.2, "Bash Variables"): what one expands to
// is not the text a command assigned to it.
const BASH_SETS = /^(_|BASH\w*|COMP_\w+|COMPREPLY|COPROC|DIRSTACK|EPOCH\w+|E?UID|FUNCNAME|GROUPS|HISTCMD|LINENO|LINES|COLUMNS|MAPFILE|OLDPWD|OPT(ARG|IND|ERR)|PIPESTATUS|PPID|PWD|RANDOM|READLINE_\w+|REPLY|SECONDS|SHELLOPTS|SHLVL|SRANDOM)$/;
// The builtins that set a variable they are given the name of.
const SETS_NAMES = /(^|[^\w.-])(printf|read|wait|mapfile|readarray|getopts|compgen|unset|let|declare|typeset|local|export|readonly)(?![\w.-])/;
// The reserved words a compound command opens and closes with, and those another may follow.
const OPENS = new Set(["{", "if", "while", "until", "for", "select"]);
const CLOSES = new Set(["}", "fi", "done"]);
const LEADS = new Set(["{", "if", "while", "until", "then", "else", "elif", "do", "!", "time", "}", "fi", "done"]);
// The compound commands open once a command's leading reserved words are read, from the count
// before it. A `case`, a `function` or a `coproc`, whose ends the count does not read, leaves it
// open for the rest of the call, and so does a `[[` whose `]]` is not in the same command.
function opened(inside: number, argv: string[]): number {
  for (let i = 0; i < argv.length; i++) {
    const w = argv[i];
    if (w === "time") {
      while (i + 1 < argv.length && (argv[i + 1] === "-p" || argv[i + 1] === "--")) {
        if (argv[++i] === "--") break;
      }
      continue;
    }
    if (OPENS.has(w)) inside++;
    else if (CLOSES.has(w)) inside--;
    else if (["case", "function", "coproc"].includes(w) || (w === "[[" && argv.at(-1) !== "]]")) inside = Infinity;
    if (!LEADS.has(w)) break;
  }
  return inside;
}
// The builtins that make a variable read-only, or give it an attribute that changes what an
// assignment to it does, named as a word of the call or in text it runs (`eval 'readonly y'`).
const FIXES_NAMES = /(^|[\s;&|(){}'"`])(readonly|declare|typeset)(?=$|[\s;&|(){}'"`])/;

// (Project review 3, round 6, Mythos.) Two things the place of a command in the text does not
// say, for the commands outside substitutions:
//
// `background`: the list the command stands in ends with `&`. Bash runs the whole list as a job
// in a shell of its own, so an assignment or a `cd` at its head reaches nothing after it:
// `x=foo && true & wait; echo hi > AGENTS.md$x` writes `AGENTS.md`. The list is read back from
// its end: the first operator after the command, outside every compound command, that is not an
// `&&`, an `||` or a `|`. A list that runs on into commands where the count of compound commands
// is lost (`opened`) is taken for a job; those commands themselves are read as before.
//
// `skipped`: an earlier command of the same line (the command itself, for its own assignments)
// can fail in a way that ends the line: an arithmetic expansion (`$((1/0))`, `$((08))`), a
// substring's length, a subscript or an offset bash evaluates, an assignment to a read-only
// variable (Simple.aborts). In a shell that reads its commands from a string, bash then drops
// what is left of the line and runs the next one: `: $((1/0)); x=foo⏎echo hi > AGENTS.md$x`
// writes `AGENTS.md`, and after `: $((1/0)); cd sub⏎` the shell is where it was. A line ends at a
// newline that follows a command outside every compound command; in a call with parentheses,
// whose ends the commands do not show, nowhere. A call of one line has no next line to run: there
// nothing is skipped that anything after it could miss, and no command is marked. (bash 5.2.37:
// an arithmetic command's own error, `((1/0))`, a builtin's (`readonly y; export y=1`) and one in
// a subshell do not end the line; `${y?}` and `set -u` end the shell.)
function reach(parsed: Parsed): { background: Set<Simple>; skipped: Set<Simple> } {
  const top = parsed.cmds.filter((c) => !c.nested);
  const levels: number[] = [];
  let inside = 0;
  for (const c of top) levels.push((inside = opened(inside, c.argv)));
  const background = new Set<Simple>();
  let end: string | undefined;
  for (let k = top.length - 1; k >= 0; k--) {
    const op = top[k].ends ?? top[k].next ?? "";
    if (levels[k] === Infinity) end = "&";
    else if (levels[k] === 0 && !["&&", "||", "|"].includes(op)) end = op;
    if (end === "&" && levels[k] !== Infinity) background.add(top[k]);
  }
  const skipped = new Set<Simple>();
  let aborted = false;
  for (const [k, c] of parsed.lines ? top.entries() : []) {
    if (c.aborts) aborted = true;
    if (aborted) skipped.add(c);
    if (c.next === "\n" && levels[k] === 0 && !parsed.grouped) aborted = false;
  }
  return { background, skipped };
}
// The commands of a call that bash may skip though it runs the line they stand on (`reach`), for
// the checks that read the text that runs: the text the rules are given holds no arithmetic.
export function skippable(command: string): Simple[] {
  return [...reach(parse(command)).skipped];
}

// `NAME=value` words of a command that only sets variables (or exports them).
function assignments(argv: string[]): [string, string][] | undefined {
  const words = argv[0] === "export" ? argv.slice(1) : argv;
  const pairs = words.map((w) => /^([A-Za-z_]\w*)=(.*)$/s.exec(w));
  return words.length && pairs.every(Boolean) ? pairs.map((m) => [m![1], m![2]]) : undefined;
}

function evaluateParsed(parsed: Parsed, scope: Scope, depth: number): Verdict {
  let verdict: Verdict = parsed.opaque ? classify("shell syntax the rules do not model") : ALLOW;
  // Relative paths are only trusted while the working directory is known.
  const local: Scope = { ...scope, vars: new Map(), loopVars: new Set(), loopValues: new Map(), links: new Map(scope.links ?? []) };
  const hasCd = parsed.cmds.some((c) => ["cd", "pushd", "popd"].includes(c.argv[0]));
  if (hasCd && parsed.grouped) local.cwd = undefined;
  // A variable is followed only when the command names it once, in the assignment, and at the
  // top level: a branch, a loop, `read` or a second assignment could give it another value. A
  // nested shell does not see unexported variables, so it starts with none.
  const words = parsed.cmds.flatMap((c) => [...c.argv, ...c.out, ...(c.in ?? [])]).join(" ");
  // (Project review 3, round 4, Mythos: an expansion that assigns is a second assignment, which
  // the count of bare names does not see: after `x=; : "${x:=.md}"`, `AGENTS$x` is `AGENTS.md`.
  // Read where the parser reads every expansion, a heredoc's body and `${x[0]:=.md}` included,
  // and by the text of the words, which is what an `eval` runs.)
  // (Round 5, Mythos: arithmetic that assigns is another, kept by the parser with these. And a
  // builtin takes the name it sets on its option's letter, where the count of bare names passes
  // it by: `x=foo; printf -vx ''` and `wait -px` leave `$x` empty. In a command that names such a
  // builtin, a word of options that ends in the name names it.)
  const setters = parsed.cmds.map((c) => c.argv.join(" ")).filter((text) => SETS_NAMES.test(text)).join(" ");
  // (Project review 3, round 24, Sol: an option word held in an expansion, `op=-vv; printf "$op"
  // %s .git`, can name any variable, so none keeps its known value.)
  const dynamicSetter = parsed.cmds.some((c) => {
    const at = c.argv.findIndex((w) => w === "printf" || w === "wait");
    if (at < 0) return false;
    const rest = c.argv.slice(at + 1);
    // (Round 25, Opus: only a word that begins with an expansion can become an option; `$!`,
    // `$$`, `$?`, `$#` are numbers.)
    // (Round 26, Opus, Sol: or a word that begins with `-` and holds an expansion, `printf "-$op"`.)
    // (Round 31, Opus: `$!` is empty until a background job starts, so it counts as a number only
    // as the whole word: `printf "$!"-vf ...` is `printf -vf ...`.)
    const dynamic = (w: string) => { const v = /^\$(?:!|\{!\})$/.test(w) ? "" : w.replace(/\$[$?#]/g, ""); return /^[$`]/.test(v) || (v.startsWith("-") && /[$`]/.test(v)); };
    if (c.argv[at] !== "printf") return rest.some(dynamic);
    // (Round 27, Opus, Sol: every word in printf's option area, `printf -v line "$op"` too.)
    for (let i = 0; i < rest.length; i++) {
      const a = rest[i];
      if (a === "--") return false;
      if (dynamic(a)) return true;
      if (a === "-v") i++;
      else if (!/^-v./.test(a)) return false;
    }
    return false;
  });
  const attached = (name: string) => dynamicSetter || new RegExp(`(^|[^\\w$])-[A-Za-z]*${name}(?!\\w)`).test(setters);
  const defaulted = (name: string) => !!parsed.assigns?.has(name) || !!scope.reassigned?.has(name) || new RegExp(`\\$\\{${name}(\\[[^\\]]*\\])?:?=`).test(words) || attached(name);
  const namedOnce = (name: string) => !defaulted(name) && (words.match(new RegExp(`(^|[^$\\w{])${name}(?!\\w)`, "g")) ?? []).length === 1;
  // (Project review 5, round 6, Mythos: a name bash sets by itself is never the environment's,
  // whatever the call shows of it: `read -r < names.txt; column -t "$REPLY"`, `[[ .env =~ .* ]];
  // column "$BASH_REMATCH"`, `column "$_"` after any command.)
  local.unassigned = (name: string) => !BASH_SETS.test(name) && !defaulted(name) && !new RegExp(`(^|[^$\\w{])${name}(?!\\w)`).test(words);
  const track = depth === 0 && !parsed.grouped;
  // The patterns of the parts that decide. A prompt offers one only when it covers them all.
  const patterns = new Set<string | undefined>(parsed.opaque ? [undefined] : []);
  // After a `cd` that can fail (to a directory that is not there yet), the commands joined to it by
  // `&&` run in that directory, and those after a `;`, `||` or `&` in either one.
  // A `{ ...; }` group in that chain is part of it, whatever separates the commands inside.
  let failableCd = false;
  let braces = 0;
  let previous: Simple | undefined;
  // (Project review 3, round 5, Mythos: an assignment is followed as one that ran only where
  // every run of the call reaches it: `false && x=foo; echo hi > .git$x/hooks/pre-commit` writes
  // in `.git`, and so does the second command of a branch, a loop or a group, `if false; then :;
  // x=foo; fi`. `listed`: an `&&` or an `||` stands before the command in its list. `inside`:
  // the compound commands open around it, counted by the reserved words that lead each command;
  // a `case`, a `function` or a `coproc`, whose ends the count does not read, leaves it open
  // for the rest of the call.)
  let listed = false;
  let inside = 0;
  // (Round 6, Mythos: nor where its list is a background job, or a failure earlier on its line
  // may have ended the line (`reach`); and not at all in a call of several lines that names a
  // builtin which makes a variable read-only, where any assignment may be the one that fails.)
  const { background, skipped } = reach(parsed);
  const fixed = !!parsed.lines && FIXES_NAMES.test(words);
  for (const cmd of parsed.cmds) {
    if (!cmd.nested && failableCd && previous && ((!["&&", "|"].includes(previous.next ?? "") && braces === 0) || braces < 0)) {
      local.cwd = undefined;
      failableCd = false;
    }
    if (!cmd.nested) {
      if (previous?.next === "&&" || previous?.next === "||" || cmd.after) listed = true;
      else if (previous?.next !== "|") listed = false;
      inside = opened(inside, cmd.argv);
      previous = cmd;
      for (const w of cmd.argv) {
        if (w === "{") braces++;
        else if (!RESERVED.has(w)) break;
      }
      if (cmd.argv[0] === "}") braces--;
    }
    const [kw, name, inKw, ...values] = cmd.argv;
    if (track && kw === "for" && inKw === "in" && values.every((w) => /^[\w./@:+-]+$/.test(w)) && namedOnce(name)) local.loopVars!.add(name);
    if (track && kw === "for" && inKw === "in" && values.every((w, k) => /^[\w./@:+*?[\]-]+$/.test(w) && !cmd.dyn?.[3 + k]) && namedOnce(name)) (local.loopValues ??= new Map()).set(name, values);
    const part = simple(cmd, local, depth);
    if (part.action === "classify" || part.action === "ask") patterns.add(part.pattern);
    verdict = worst(verdict, part);
    if (verdict.action === "deny") return verdict;
    const apart = cmd.subshell || background.has(cmd) || skipped.has(cmd);
    if (apart) {
      if (["cd", "pushd", "popd"].includes(cmd.argv[0])) local.cwd = undefined;
    } else if (cmd.argv[0] === "cd" && local.cwd) {
      // `cd -` goes to $OLDPWD, which is not known.
      // `cd -L`, `cd -P` and `cd --` before one word go there too (round 38).
      const cdArgs = cmd.argv.slice(1);
      while (cdArgs.length > 1 && /^(-L|-P|--)$/.test(cdArgs[0])) cdArgs.shift();
      const to = cdArgs.length === 1 && cdArgs[0] !== "-" ? resolveWord(cdArgs[0], local) : cdArgs.length === 0 ? HOME : undefined;
      const there = !!to && !!fs.statSync(to, { throwIfNoEntry: false })?.isDirectory();
      local.cwd = there || (to && cmd.next === "&&") ? to : undefined;
      failableCd = !there && local.cwd !== undefined;
      braces = 0;
    } else if (cmd.argv[0] === "pushd" || cmd.argv[0] === "popd") local.cwd = undefined;
    for (const [name, value] of (track && !listed && inside === 0 && !apart && !fixed && assignments(cmd.argv)) || []) {
      // The text is kept and resolved where it is used, after any later `cd`, as the shell does.
      // Only one word of plain text is followed: no expansion, blank or glob. `~` at its start is
      // expanded in an assignment.
      const text = expandVars(value, local);
      const i = cmd.argv.findIndex((w) => w.startsWith(`${name}=`));
      // (Project review 3, round 3, Mythos: not a name bash gives a value of its own, whatever the
      // command assigns: `FUNCNAME=x; mkdir sub/.git$FUNCNAME` makes `sub/.git`, `REPLY` is what a
      // `read` took, `$DIRSTACK` is where the command runs.)
      if (namedOnce(name) && !BASH_SETS.test(name) && /^[\w./~@%+,:=-]*$/.test(text) && !cmd.dyn?.[i]) local.vars!.set(name, text.startsWith("~/") || text === "~" ? HOME + text.slice(1) : text);
    }
  }
  if (depth === 0) scope.resolvedVars = local.vars;
  return verdict.pattern && patterns.size > 1 ? { ...verdict, pattern: undefined } : verdict;
}

// Project review 6 (Sol, Opus, Neon): the build, test, lint and format tools and the package
// managers work on the places their words name, read or written, through options no table
// lists in full: a formatter rewrites the files it is given (`prettier --write AGENTS.md`,
// `shfmt -w .git/hooks/pre-commit`), a build writes where `-o` says (`go build -o
// .git/hooks/x`), a config or a module is loaded from where an option points (`jest --config
// /dev/stdin`, `mocha --require ../x.js`, `npm test --prefix ..`, `cargo run --manifest-path
// ../Cargo.toml`), and the project they run is the directory they start in (`cd .. && make`).
// Bluntly, for every word, an option's value after `=` and a short option's attached path
// included: a protected name (the plugin's, opencode's, a `.git` component) asks, and a path
// outside the project, the temp directories and the allowed places goes to the decider, as does
// a run in such a directory. Words built at run time are judged elsewhere (runtimeReads).
// (Rounds 10 and 11, Sol, Opus: where the kernel's walk of a word leads, a link followed before
// a `..` after it, `-Cext/..`, `-MFdeep/../x`, and for a file not made yet, through the parents
// that are there, `-MFext/deps.d`. A word that starts with `/` is walked from the root.)
function walked(raw: string, scope: Scope): string | undefined {
  const text = expandHome(raw);
  if (!text.startsWith("/") && scope.cwd === undefined) return undefined;
  let at = text.startsWith("/") ? "/" : realish(scope.cwd!);
  for (const c of text.split("/")) {
    if (!c || c === ".") continue;
    if (c === "..") {
      at = path.dirname(at);
      continue;
    }
    at = path.join(at, c);
    try {
      at = fs.realpathSync(at);
    } catch {
      // Not there (yet): the rest is joined as written.
    }
  }
  return at;
}
const protectedPlace = (p: string, scope: Scope) => isGuarded(p, scope) || isPiFile(p, scope) || /(^|\/)\.git(\/|$)/.test(p);
const PROJECT_TOOLS = new Set([...DEV_TOOLS, ..."go cargo npm npx pnpm pnpx yarn bun bunx uv uvx deno poetry pipenv pdm hatch".split(" ")]);
const plainSpelling = (w: string) => !/['"\\]/.test(w) && !/(^|[=:,])~(?!\/)/.test(w);
function projectToolPlaces(name: string, args: string[], scope: Scope, dyn: (k: number) => boolean): Verdict | undefined {
  if (!scope.root) return undefined;
  if (scope.cwd !== undefined && !isLocal(scope.cwd, scope)) return classify(`${name} runs in ${scope.cwd}, outside the project, where it reads that directory's code and config`);
  const pathy = (w: string) => /^(\/|~|\.)/.test(w) || w.includes("/");
  const words = new Set<string>();
  const tails = new Set<string>();
  let verdict: Verdict | undefined;
  for (let [k, a] of args.entries()) {
    // (A process substitution, `-c <(echo ...)`, `-c<(...)`, reads as `$()` here, in a word with no
    // expansion bash computes a name from: a file made when the command runs.)
    if (a.includes("$()") && !dyn(k)) verdict ??= classify(`${name} reads a file made when the command runs (a process substitution)`);
    // (A variable the call plainly sets to a literal is read as that literal, `m=../x.js; mocha
    // --require "$m"`; any other word built at run time is judged in runtimeReads.)
    // (Round 7, Opus: only a word bash builds at run time; a `$` that is text, a regex anchor in
    // `jest --config '{"testRegex":"x$"}'`, is read as written.)
    const plain = /[$`]/.test(a) ? expandVars(a, scope) : a;
    if (/[$`]/.test(plain) && dyn(k)) continue;
    a = plain;
    // (After review 6, a gate in front of the reading below, meant to be temporary: a word in a
    // spelling that is not plain goes to the decider whatever the reading would make of it.
    // Not plain: a quote left inside a value, a backslash, a `~user`: the structured values and
    // escapes rounds 6 to 11 of review 6 kept finding in new forms (`-Dc_args=['-I../x']`,
    // `--config '{"rootDir":".."}'`, `\u002e`, `~agent/x`). Blanks, `|`, parentheses, brackets
    // and a `$` that is text pass (`-ldflags="-s -w"`, `-k "not slow"`, `test_x[flat]`,
    // `-rpath,'$ORIGIN'`, `-run "Test$"`). Delete this gate once the reading covers them.)
    if (!plainSpelling(a)) verdict ??= classify(`${name} ${a.slice(0, 60)}: a spelling the check does not read in full`);
    // (Before round 8: a backstop on the word's text, whatever the reading below makes of its
    // structure: a `.git`, `.claude` or `.opencode` component or a context file's name anywhere
    // asks.)
    if (/(^|[^\w.])\.(git|claude|opencode)([^\w.-]|$)/.test(a) || /(^|[^\w.-])(AGENTS|CLAUDE)\.(md|MD)|AGENTS\.override\.md/.test(a)) return ask(`${name} ${a.slice(0, 60)}: names a protected file or directory, which it may read as config or write`);
    // (Round 7, Sol: a structured value with an escape the tool decodes, `{"rootDir":"\u002e\u002e"}`,
    // is one the check does not read: it goes to the decider.)
    if (/\\/.test(a) && /[{[]/.test(a)) verdict ??= classify(`${name} ${a.slice(0, 60)}: a structured value with escapes the check does not decode`);
    // (Round 5, Opus, Sol: one reading of every value, however deep: after the first `=` and after
    // the last (`--emit=llvm-ir=AGENTS.md`), each blank- or comma-separated part (`pytest -o
    // "pythonpath=src ../x"`, `mocha --require=a.js,../x.js`, `gcc -Wl,-o,.git/hooks/x`), and for
    // a part that is a short option, the rest after each of its leading letters (`-o.git/x`,
    // `-Wp,-MFAGENTS.md`, `-Dc_args=-I../inc`, `go build -ldflags=-L../lib`). The rest after the
    // first letter is held to every check; after a later one, where which letter takes the rest
    // is not known, to the protected names and links, and to the outside check where it starts
    // with `.` or `~`, or with `/` after at most two letters (`-vC/etc`; `-obuild/app` is a name).)
    // (Round 6, Opus: and with the quotes and brackets a tool parses off a structured value,
    // meson's `['-I../inc']`, jest's `{"rootDir":"/x"}`, pytest's `src '/x'`, split on `:` too.)
    const read = (v: string, depth: number, full: boolean, self: boolean): void => {
      v = v.replace(/^[\[\]{}'"]+|[\[\]{}'"]+$/g, "");
      if (!v || depth > 6) return;
      if (self) (full ? words : tails).add(v);
      if (/[\s,:;]/.test(v)) for (const part of v.split(/[\s,:;]+/)) read(part, depth + 1, full, true);
      if (v.includes("=")) {
        read(v.slice(v.indexOf("=") + 1), depth + 1, full, true);
        read(v.slice(v.lastIndexOf("=") + 1), depth + 1, full, true);
      }
      if (/^-[^-]/.test(v) && !/[\s,=]/.test(v.slice(0, 2))) {
        // (A cluster of more letters than the reading follows is not read: it goes to the decider.)
        if (/^-[A-Za-z]{24}/.test(v)) verdict ??= classify(`${name} ${v.slice(0, 40)}...: an option cluster too long for the check to read`);
        read(v.slice(2), depth + 1, full, true);
        for (let k = 3; k < Math.min(v.length, 24) && /^[A-Za-z]+$/.test(v.slice(1, k)); k++) {
          const rest = v.slice(k);
          read(rest, depth + 1, full && (/^[.~]/.test(rest) || (k <= 3 && rest[0] === "/")), true);
        }
      }
    };
    // (An option word itself is no place; its values are.)
    read(a, 0, true, !a.startsWith("-"));
  }
  for (const t of tails) {
    const p = resolveWord(t, scope);
    if (!p && /^~[^/]/.test(t)) verdict ??= classify(`${name} names ${t}, a place the check cannot tell`);
    if (p && (isGuarded(p, scope) || isPiFile(p, scope) || /(^|\/)\.git(\/|$)/.test(p))) return ask(`${name} names ${t}, a protected file or directory it may read as config or write`);
    // (Cross-check, Sol: a tail that is a link out of the project, `ninja -vCext`.)
    const w = t.startsWith("/") ? undefined : walked(t, scope);
    if (w && protectedPlace(w, scope)) return ask(`${name} names ${t}, which leads to ${w}, a protected file or directory it may read as config or write`);
    if (w && !isLocal(w, scope)) verdict ??= classify(`${name} names ${t}, outside the project through a link: a place it may load code or config from, or write`);
  }
  for (const word of words) {
    const value = word.replace(/^@/, "");
    if (!value || /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) continue;
    // (Round 8, Sol: a `$` or backtick that is text, `'../setup$.js'`, is part of the name;
    // one the check still cannot place goes to the decider.)
    const p = resolveWord(value, scope) ?? (scope.cwd !== undefined && /[$`]/.test(value) ? path.resolve(scope.cwd, expandHome(value)) : undefined);
    if (!p) {
      // (Round 9, Opus: or a `~user` path bash expands, `~agent/other`.)
      if (pathy(value) && /[$`]|^~/.test(value)) verdict ??= classify(`${name} names ${value}, a place the check cannot tell`);
      continue;
    }
    if (isGuarded(p, scope) || isPiFile(p, scope) || /(^|\/)\.git(\/|$)/.test(p)) return ask(`${name} names ${value}, a protected file or directory it may read as config or write`);
    // (Round 2, Opus: a plain name that is a link out of the project, `go test -C ext ./...`.)
    const w = walked(value, scope);
    if (w && protectedPlace(w, scope)) return ask(`${name} names ${value}, which leads to ${w}, a protected file or directory it may read as config or write`);
    if (((pathy(value) && !isLocal(p, scope)) || !isLocal(realish(p), scope) || (!!w && !isLocal(w, scope))) && p !== "/dev/null") verdict ??= classify(`${name} names ${value}, outside the project: a place it may load code or config from, or write`);
  }
  return verdict;
}

// The fork bomb in any spelling: a function that pipes itself into itself in the background.
const FORK_BOMB_SHAPE = /([\w:.-]+)\(\)\{\1\|\1&;?\};?\1/;

export function bashVerdict(command: string, scope: Scope): Verdict {
  if (FORK_BOMB.test(command) || FORK_BOMB_SHAPE.test(command.replace(/\s+/g, ""))) return deny("fork bomb");
  const verdict = evaluateParsed(parse(command), scope, 0);
  if (verdict.action === "deny") return verdict;
  return forDecider(PIPE_TO_SHELL.test(command) ? worst(verdict, criticalAsk("downloads code and runs it")) : verdict, scope);
}

// write and edit tools.
export function fileVerdict(tool: string, target: string, scope: Scope): Verdict {
  const p = resolveWord(target.startsWith("@") ? target.slice(1) : target, scope);
  if (isGuarded(p, scope)) return guardAsk(`${tool} changes the auto-mode guard's own files`);
  if (isPiFile(p, scope)) return piAsk(`${tool} changes Pi's own files: ${target}`);
  // The write tool replaces the whole file with the agent's text; an edit keeps the file's origin,
  // and makes a file of no known origin one the session wrote, so a project script the agent
  // changed goes to the decider when run.
  if (tool === "write" || (p && originOf(p, scope) === undefined)) note(p, "authored", scope);
  return isLocal(p, scope) ? ALLOW : forDecider(outside(`${tool} outside the working directory: ${target}`, p), scope);
}

// read and grep tools: an ask for a credential file, undefined for every other path.
export function readVerdict(tool: string, target: string, scope: Scope): Verdict | undefined {
  const secret = secretIn(target.startsWith("@") ? target.slice(1) : target, scope, true);
  return secret ? criticalAsk(`${tool} of a credential file: ${target}`) : undefined;
}

// Tables looked up by a word of the command hold no inherited names (council project review 2,
// round 43, Astra: `./constructor -V` found Object's `constructor` in a table): their prototypes,
// and those of the plain objects they hold, are taken away once the module is loaded.
export function bare(...tables: object[]): void {
  const seen = new Set<object>();
  const strip = (o: unknown) => {
    if (o === null || typeof o !== "object" || seen.has(o) || Object.getPrototypeOf(o) !== Object.prototype) return;
    seen.add(o);
    Object.setPrototypeOf(o, null);
    for (const v of Object.values(o)) strip(v);
  };
  for (const t of tables) strip(t);
}
bare(SUBCOMMANDS, DOCKER_GROUPS, ASK_BY_DEFAULT, ALWAYS_ASK, WRITERS, RUNNERS, LEAD_OPTIONS, RUNNER_OPTIONS, WRAPPER_OPTIONS, COMPRESSORS, DOWNLOAD_FILES, COPY_SPEC);
