// opencode-automode: auto mode for opencode 2.x permission prompts, fully local.
//
// Flow for a shell tool call:
//   tool.execute.before   print the command in one plain spelling (canon.ts), decide on the
//                         printed text (Pi's rules, then Kev for what they leave open) and
//                         remember the decision by tool call. What cannot be printed asks.
//   shell.create.before   if the decision is allow, swap the shell for sandbox/bin/<shell>, a
//                         link to sandbox/lockwrite. It runs the real shell inside a sandbox:
//                         writes only to the project, the allowed paths, temp dirs, a few
//                         devices and `sandboxWritable` (no build cache by default); git
//                         directories read-only; local sockets of other services and
//                         credential files hidden. The shell is handed the printed text, the
//                         text that was judged, in place of the command opencode passed
//                         (AUTOMODE_COMMAND; with the sandbox off the plugin sets
//                         event.command). opencode's own rules and prompts see the command
//                         as issued, and the decision log holds both. Commands that ask are
//                         not sandboxed: what you approve runs as issued. Under a shell that
//                         is not bash (dash included) nothing is allowed without a prompt.
//   permission.evaluate   apply the decision. An allow whose shell was not swapped asks instead,
//                         so a missing or broken sandbox never widens what runs.
// opencode 2.2.7 fires the three in that order for one call (core/src/tool.ts, shell.ts,
// tool/plugin/shell.ts), and hands create.before the child's whole environment. It runs the
// tool calls of one message at the same time, each in a fiber of its own (SessionStep.attempt),
// so the hooks of two calls interleave; and create.before carries no call id, so a shell cannot
// be told from the shell of an identical command. A shell is therefore sandboxed only when
// every identical call in flight is an allow.
//   tool.execute.after    the call is over: it leaves the queue, and what it was approved to
//                         create is no longer expected.
//   permission.asked / permission.replied (events)   which prompt belongs to which call, and
//                         the user's answer: an approval is what makes a new repository expected.
// edit and read only ever tighten (guard and opencode config files, credential files).
// opencode `deny` rules never reach the hook, so they always win. Any error asks.
//
// "Always allow" in opencode's prompt is mirrored into the plugin's allow rules (persisted),
// for plain word patterns only.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Plugin } from "@opencode/plugin";
import { compileRules, compilePattern, within } from "./rules.ts";
import { closeGitSnapshot, decideFile, decideRead, decideShell, EXPECT_MS, expectedRepos, gitDirectories, gitOnly, gitWriteDirectories, gitMaintainDirectories, gitStateTampered, gitTampered, mirrorable, noteGitCall, projectRoots, pushCandidate, pushDestinations, quarantineGitFiles, realish, sandboxBreaks, SessionState, usesSsh, type Decision, type Expected, type GitCall, type Guard } from "./decide.ts";
import { envKept, envStringProblem, gitElsewhere, plan, realpath, Scan, shellOwn, type Plan } from "./sandbox.ts";
import { loadConfig, type Config } from "./config.ts";
import { shellAlsoKeeps } from "./guard.ts";
import { canonical } from "./canon.ts";

// A command that holds the word `git` as a program's name (broad on purpose: `.git` and
// `git.txt` are not it).
const HOLDS_GIT = /(^|[^\w.-])git($|[^\w.-])/;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const HOME = os.homedir();
// An empty XDG variable counts as unset, as in sandbox.ts and the XDG specification.
const CONFIG_DIR = path.join(process.env.XDG_CONFIG_HOME || path.join(HOME, ".config"), "opencode");
const CONFIG_FILE = path.join(CONFIG_DIR, "automode.json");
const STATE_DIR = path.join(process.env.XDG_STATE_HOME || path.join(HOME, ".local", "state"), "opencode-automode");
const ALWAYS_FILE = path.join(STATE_DIR, "always.json");
const LOG_FILE = path.join(STATE_DIR, "decisions.jsonl");
// Touched by the user to resume auto-allow after a pause (see gitTampered).
const RESUME_FILE = path.join(STATE_DIR, "resume");
// An empty file bound over hidden files inside the sandbox.
const COVER_FILE = path.join(STATE_DIR, "empty");
const LOCKWRITE = path.join(HERE, "sandbox", "lockwrite");
const WRAPPER_DIR = path.join(HERE, "sandbox", "bin");
// Shells the wrapper stands in for (sandbox/bin/<name>). opencode passes `-c <command>`.
const WRAPPABLE = new Set(["bash", "sh"]);
// What a shell really is decides whether it is wrapped (round 3, finding 37): the checks model
// bash's syntax. `bash` and `sh` are wrapped when they really are bash, after every symbolic
// link (/etc/alternatives included). zsh, busybox, mksh, ksh, yash and anything else read syntax
// the checks never saw, so an allow under them asks ("its shell could not be sandboxed").
//
// dash was wrapped too, on the strength of its syntax being a subset of bash's (round 3). It is
// not what the checks read: three rounds of round 4 each found text dash takes another way than
// bash (`.?` matches `..` there, `a+=x cmd` runs a command called `a+=x`, `~:` is not expanded,
// a descriptor of two digits is an argument), and the printed text is bash's reading. Finding 15
// offered "a difference asks, or ends the wrapping of that shell"; the maintainer took the
// second. Under dash nothing is allowed without a prompt, and the prompt says so.
const REALLY: Record<string, string[]> = { bash: ["bash"], sh: ["bash"] };
const wrappable = (shell: string) => (REALLY[path.basename(shell)] ?? []).includes(path.basename(realpath(shell)));

// The state directory holds every command the agent ran: private to the user, and hidden from
// sandboxed commands (see the plan's hidePaths).
function stateDir() {
  fs.mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  fs.chmodSync(STATE_DIR, 0o700);
}

function privateWrite(file: string, text: string, append = false) {
  stateDir();
  if (append) fs.appendFileSync(file, text, { mode: 0o600 });
  else fs.writeFileSync(file, text, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

// "Always allow" patterns, per project: { "<project realpath>": ["git status *", ...] }.
function loadAlwaysFile(): Record<string, string[]> {
  try {
    const data = JSON.parse(fs.readFileSync(ALWAYS_FILE, "utf8"));
    return typeof data === "object" && data !== null && !Array.isArray(data) ? data : {};
  } catch {
    return {};
  }
}

function loadAlways(project: string): string[] {
  const list = loadAlwaysFile()[project];
  return Array.isArray(list) ? list.filter((x): x is string => typeof x === "string" && mirrorable(x)) : [];
}

function saveAlways(project: string, list: string[]) {
  const data = loadAlwaysFile();
  data[project] = list;
  privateWrite(ALWAYS_FILE, JSON.stringify(data, null, 2) + "\n");
}

function log(config: Config, entry: Record<string, unknown>) {
  if (!config.log) return;
  try {
    privateWrite(LOG_FILE, JSON.stringify({ time: new Date().toISOString(), ...entry }) + "\n", true);
  } catch {
    // Logging must never change a decision.
  }
}

function resolveShell(shell: string): string | undefined {
  if (path.isAbsolute(shell)) return shell;
  for (const dir of (process.env.PATH ?? "/usr/bin:/bin").split(":")) {
    const p = path.join(dir, shell);
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {
      // keep looking
    }
  }
  return undefined;
}

function selftest(): string | undefined {
  try {
    execFileSync(LOCKWRITE, ["--selftest"], { stdio: ["ignore", "pipe", "pipe"], timeout: 5000, env: { PATH: process.env.PATH ?? "/usr/bin:/bin" } });
    for (const shell of WRAPPABLE) fs.accessSync(path.join(WRAPPER_DIR, shell), fs.constants.X_OK);
    return undefined;
  } catch (e) {
    const err = e as { stderr?: Buffer; message: string };
    return err.stderr?.toString().trim() || err.message;
  }
}

// opencode resolves a tool's workdir against the session directory, expanding a leading `~`.
const resolveWorkdir = (base: string, dir: string) => path.resolve(base, dir === "~" ? HOME : dir.startsWith("~/") ? path.join(HOME, dir.slice(2)) : dir);
const clip = (text: string, max = 4000) => (text.length > max ? `${text.slice(0, max)} ... (${text.length} chars)` : text);
const callKey = (messageID: string, id: string) => `${messageID}\u0000${id}`;
// lockwrite takes its lists newline-separated; plan() reports a path with a newline as a problem.
const joined = (paths: string[]) => paths.join("\n");
// A call waits this long for its shell. opencode creates the shell right after the tool hook
// returns, so anything older belongs to a call that never got one.
const WRAP_WINDOW_MS = 15_000;
// Calls that run at the same time (round 3, findings 18 and 36). A call may still run from its
// decision until its tool call is over and no process of it is left: a call run in the
// background, or moved there, ends its tool call while its process runs. Every shell the plugin
// sees gets `AUTOMODE_CALL=<token>` in its environment, and the processes that carry it show
// whether the call still runs: lockwrite's outer process lives as long as the sandboxed command,
// and an unsandboxed command's processes inherit it. A call that started and has no process left
// a minute later is over even if its tool call never ended; one that never started, an hour
// after its decision.
const STARTED_GRACE_MS = 60_000;
const NEVER_STARTED_MS = 3_600_000;

// The AUTOMODE_CALL tokens of every process whose environment this user can read; undefined when
// /proc cannot be listed (then every call counts as running).
function runningTokens(): Set<string> | undefined {
  let pids: string[];
  try {
    pids = fs.readdirSync("/proc").filter((name) => /^\d+$/.test(name));
  } catch {
    return undefined;
  }
  const tokens = new Set<string>();
  for (const pid of pids) {
    let environ: string;
    try {
      environ = fs.readFileSync(`/proc/${pid}/environ`, "latin1");
    } catch {
      continue; // gone, or another user's
    }
    for (const entry of environ.split("\0")) if (entry.startsWith("AUTOMODE_CALL=")) tokens.add(entry.slice("AUTOMODE_CALL=".length));
  }
  return tokens;
}

interface Call {
  command: string;
  cwd: string;
  sessionID: string;
  decision: Decision;
  sandbox?: Plan;
  exposeSsh?: boolean;
  // A shell for this command and directory was sandboxed while the call was waiting for one.
  wrapped?: boolean;
  // A shell for this command and directory was left as it is while the call was waiting for
  // one, and it may have been this call's: an allow asks instead.
  unsure?: boolean;
  // With the sandbox off: the shell for this command was handed the printed text in place of the
  // command (round 4, finding 16). An allow whose shell was not asks instead.
  rewritten?: boolean;
  // The shell that came for this command is dash and the printed text relies on bash.
  dash?: boolean;
  // The sandbox could not be handed the command or its environment in one string each.
  tooLong?: string;
  // Its shell inherits this variable of git's own, which points git at another repository or
  // configuration than the one judged (gitElsewhere in sandbox.ts).
  gitEnv?: string;
  // That variable is this process's own and the shell does not have it (or has another value
  // of it): the checks' git reads configuration the shell's git does not.
  gitEnvLacks?: boolean;
  // permission.evaluate was applied, or the tool call is over: it waits for no shell.
  settled?: boolean;
  // Where the command would create repositories, when it asks; and the approval of that.
  expects?: string[];
  expecting?: Expected;
  at: number;
  // The AUTOMODE_CALL tokens of the shells that may be this call's.
  tokens: string[];
  // A plain `git push` the feature-branch check looks at: from the start of its decision, other
  // calls that could change what it sends ask.
  push?: boolean;
  // Allowed with a writable .git: even a reader can run an external diff or textconv.
  mover?: boolean;
  // Allowed with a writable `.git` (a git-only call): when it is over, the operation state it
  // left is checked against its subcommands (round 3, finding 33).
  gitCall?: GitCall;
  decided?: boolean;
  // When its process could start: an allow when its permission was applied, an ask when the user
  // approved it. An allow that asks after all (its shell was not sandboxed) counts as an ask.
  started?: number;
  downgraded?: boolean;
  rejected?: boolean;
  // tool.execute.after.
  ended?: number;
}

export default Plugin.define({
  id: "opencode-automode",
  async setup(ctx) {
    const loaded = loadConfig(CONFIG_FILE, ctx.options);
    const config: Config = loaded.config;
    // Which of bash's own variables a shell of this instance is handed (the shell hook below
    // takes the others out): the guard reads CDPATH for a relative `cd` only where the shell has it.
    shellAlsoKeeps(config.enabled ? config.sandboxKeepEnv : undefined);
    // With settings that cannot be used as written, nothing is auto-allowed.
    const configProblem = loaded.problem ? `automode settings are invalid, so nothing is auto-allowed: ${loaded.problem}` : undefined;
    if (configProblem) console.error(`[opencode-automode] ${configProblem}`);
    try {
      stateDir();
      if (!fs.existsSync(COVER_FILE)) fs.writeFileSync(COVER_FILE, "", { mode: 0o400 });
      for (const file of [LOG_FILE, ALWAYS_FILE]) if (fs.existsSync(file)) fs.chmodSync(file, 0o600);
    } catch {
      // Without the cover file hidden files read as /dev/null.
    }
    const cover = () => {
      try {
        const st = fs.statSync(COVER_FILE);
        return st.isFile() && st.size === 0 ? COVER_FILE : undefined;
      } catch {
        return undefined;
      }
    };
    const project = ctx.location.directory;
    const projectKey = realpath(project);
    let always = loadAlways(projectKey);
    const sandboxProblem = config.sandbox ? selftest() : undefined;
    const sandboxReady = config.sandbox && !sandboxProblem;
    if (sandboxProblem) console.error(`[opencode-automode] sandbox unavailable, nothing will be auto-allowed: ${sandboxProblem}`);

    const makeGuard = (): Guard => ({
      rules: compileRules(config.rules),
      picked: always.map(compilePattern),
      guarded: [HERE, CONFIG_FILE, STATE_DIR],
      configDirs: [CONFIG_DIR],
      allowedPaths: config.allowedPaths,
      classifier: config.classifier,
      useClassifier: config.useClassifier,
      sshHosts: config.sshHosts,
      sshReadOnlySudo: config.sshReadOnlySudo,
      allowFeatureBranchPush: config.allowFeatureBranchPush,
      resumeFile: RESUME_FILE,
    });
    // A decision that would run without a prompt becomes a prompt while the settings are invalid.
    const held = (decision: Decision): Decision => (configProblem && decision.effect === "allow" ? { ...decision, effect: "ask", reason: configProblem } : decision);
    const paused = new Set<SessionState>();
    const decide = async (s: SessionState, cwd: string, command: string, scan?: Scan): Promise<Decision> => {
      const decision = held(await decideShell(guard, s, cwd, command, undefined, scan));
      if (s.tampered && !paused.has(s)) {
        paused.add(s);
        console.error(`[opencode-automode] auto-allow paused: ${s.tampered.reason}. To resume after checking: touch ${RESUME_FILE}`);
      } else if (!s.tampered) paused.delete(s);
      return decision;
    };
    let guard = makeGuard();

    const sessions = new Map<string, SessionState>();
    const session = (id: string) => {
      let s = sessions.get(id);
      if (!s) sessions.set(id, (s = new SessionState(project)));
      return s;
    };

    // Decisions by tool call, and allowed calls waiting for their shell to be created.
    const calls = new Map<string, Call>();
    const unseen = new Map<string, { at: number; decision: Decision }>();
    const toWrap = new Map<string, Call[]>();
    const wrapKey = (command: string, cwd: string) => `${path.resolve(cwd)}\u0000${command}`;
    // The calls for one command and directory that still wait for their shell.
    const waiting = (key: string) => (toWrap.get(key) ?? []).filter((c) => !c.settled && Date.now() - c.at < WRAP_WINDOW_MS);
    const bound = <K, V>(map: Map<K, V>, max: number) => {
      while (map.size > max) map.delete(map.keys().next().value!);
    };

    // Calls that may still run, in every session of this plugin (sessions in one directory share
    // it, so this is per checkout). See STARTED_GRACE_MS.
    const live = new Set<Call>();
    const nonce = `${process.pid}.${Date.now().toString(36)}`;
    let shells = 0;
    // A plant the per-call check renamed pauses every session, each naming what that pause names
    // (a resume takes in what was named, and nothing else unseen).
    const pauseAll = (reason: string, from: SessionState) => {
      for (const other of sessions.values()) other.tampered = { reason, at: Date.now(), named: from.tampered?.named, held: from.tampered?.held };
    };
    // A call that is over: an approved command's window closes, and what it made joins the
    // baseline now rather than at its session's next decision, so that no other session waits.
    const finish = (c: Call) => {
      live.delete(c);
      // No process of the call is left: the next decision marks the files its git commands
      // changed in the work tree, and no longer the whole repository (round 4, finding 4).
      for (const change of c.decision.worktree ?? []) change.done = true;
      if (c.gitCall) {
        c.gitCall.done = true;
        // The per-call check once more (its completion hook came while a background process of
        // it still ran, or never came): a plant is renamed, and every session pauses.
        const planted = quarantineGitFiles(session(c.sessionID), sessions.values(), c.gitCall);
        if (planted) pauseAll(planted, session(c.sessionID));
        try {
          gitStateTampered(session(c.sessionID));
        } catch {
          // the next decision checks again
        }
      }
      if (!c.expecting) return;
      c.expecting.done = true;
      try {
        gitTampered(session(c.sessionID), RESUME_FILE);
      } catch {
        // the next decision checks again
      }
    };
    const sweep = () => {
      let procs: Set<string> | undefined | null = null;
      const running = (c: Call) => {
        if (procs === null) procs = runningTokens();
        return !procs || c.tokens.some((t) => procs!.has(t));
      };
      for (const c of [...live]) {
        const alive = c.rejected
          ? false
          : c.ended !== undefined
            ? running(c)
            : c.started === undefined
              ? Date.now() - c.at < NEVER_STARTED_MS || running(c)
              : Date.now() - c.started < STARTED_GRACE_MS || running(c);
        if (!alive) finish(c);
      }
    };
    // New-repository windows that are open: an approved command may be creating one.
    const windows = () => [...sessions.values()].flatMap((x) => x.expecting).filter((e) => Date.now() - e.at < EXPECT_MS);
    // Whether a call could write in one of these directories: its sandbox's writable roots, or
    // anywhere when it runs unsandboxed.
    const reaches = (c: Call, dirs: string[]) => !c.sandbox || dirs.some((d) => c.sandbox!.rw.some((r) => within(d, r) || within(r, d)));
    const asks = (c: Call) => c.decision.effect === "ask" || !!c.downgraded;
    const pushNote = (call: Call) => {
      const push = [...live].find((c) => c !== call && c.push && (!c.decided || (c.decision.effect === "allow" && !c.downgraded)));
      return push ? ` (a checked push is still running: ${clip(push.command, 80)}; approved, this runs outside the sandbox, and if it moves HEAD or a branch before the push finishes, the push sends that instead)` : "";
    };
    // Why an allowed call must ask because of what may run beside it.
    const besides = (call: Call, background: boolean): string | undefined => {
      const others = [...live].filter((c) => c !== call);
      if (call.push) {
        if (background) return "a push run in the background could send another branch than the one checked, if HEAD moves before it runs";
        const mover = others.find((c) => c.decided && (c.mover || asks(c)));
        if (mover) return `another call may still be running ${asks(mover) ? "that you were asked about" : "with a writable .git"} (${clip(mover.command, 80)}): it could move HEAD or a branch, so the push could send another branch than the one checked`;
      }
      if (call.mover) {
        const push = others.find((c) => c.push && (!c.decided || c.decision.effect === "allow"));
        if (push) return `a checked push may still be running (${clip(push.command, 80)}), and this call gets a writable .git, with which it could move HEAD or a branch under it`;
      }
      const open = windows().find((e) => reaches(call, e.dirs));
      if (open) return `an approved command may still be creating a repository in ${open.dirs[0]}, and this call could write there`;
      return undefined;
    };

    const toolHook = await ctx.tool.hook("execute.before", async (event) => {
      if (!config.enabled) return;
      if (event.tool !== "shell" && event.tool !== "bash") return;
      const input = event.input as { command?: unknown; workdir?: unknown; background?: unknown } | undefined;
      if (typeof input?.command !== "string") return;
      const command = input.command;
      // opencode resolves workdir against the session directory without following symlinks.
      const cwd = typeof input.workdir === "string" && input.workdir ? resolveWorkdir(project, input.workdir) : project;
      const started = Date.now();
      const s = session(event.sessionID);
      const call: Call = { command, cwd, sessionID: event.sessionID, decision: { effect: "ask", by: "rules", rule: "ask", reason: "deciding" }, at: started, tokens: [] };
      sweep();
      // A push holds its mark from here, through the dry run, until it is over. The mark is
      // read from the text that would run (the printed one), as the decision is: `git pu\⏎sh`
      // and `git push # note` are pushes too (found by the round 4 cross-check).
      try {
        const early = canonical(command);
        if (config.allowFeatureBranchPush && pushCandidate("ask" in early ? command : early.text, cwd)) call.push = true;
      } catch {
        call.push = true;
      }
      live.add(call);
      // The walks of this call: the decision and the plan share them (round 3, finding 40).
      // It is told the allowed paths, so that every caller splits the roots alike (finding 30).
      const scan = new Scan(config.allowedPaths);
      let decision: Decision;
      try {
        decision = await decide(s, cwd, command, scan);
      } catch (e) {
        decision = { effect: "ask", by: "rules", rule: "ask", reason: `automode failed, asking instead: ${(e as Error).message}` };
      }
      call.decision = decision;
      call.at = Date.now();
      // An allow is an allow of the printed text (round 4, finding 16): that text is what runs,
      // so it is what the sandbox checks read. Without it nothing is allowed.
      if (decision.effect === "allow" && decision.printed === undefined) call.decision = decision = { ...decision, effect: "ask", reason: "would be allowed, but the command was not printed back, so what would run is not what was judged" };
      const run = decision.printed ?? command;
      // Allowed must mean it can work: what the sandbox would only make fail asks instead.
      // (A command too long for the one environment string the wrapper is handed it in is
      // caught where the shell is made, with the names of the variables it keeps.)
      const broken = decision.effect === "allow" && sandboxReady ? sandboxBreaks(run, cwd, s, [...config.allowedPaths, ...config.sandboxWritable]) : undefined;
      if (broken) call.decision = { ...decision, effect: "ask", reason: `would be allowed, but it cannot work in the sandbox: ${broken}` };
      else if (decision.effect === "allow" && sandboxReady) {
        try {
          const roots = projectRoots(s);
          call.exposeSsh = usesSsh(run, cwd, s);
          const gitWritable = gitOnly(run);
          call.mover = gitWritable;
          const p = plan(
            {
              projectRoots: roots,
              allowedPaths: config.allowedPaths,
              cacheDirs: config.sandboxWritable,
              gitWritable,
              // The repositories a git-only call works in: where its git commands end, and where
              // a push goes when that is on this machine.
              gitCwds: gitWritable ? gitDirectories(run, cwd) : [],
              // Those where a command writes its git directory: outside the writable roots it
              // would only fail, so it asks.
              gitWriteCwds: gitWritable ? gitWriteDirectories(run, cwd) : [],
              // Those where a command works on every worktree of the repository (`git gc`).
              gitMaintainCwds: gitWritable ? gitMaintainDirectories(run, cwd) : [],
              gitPushTo: gitWritable ? pushDestinations(run, cwd) : [],
              exposeSsh: call.exposeSsh,
              keepSockets: config.sandboxKeepSockets,
              showPaths: config.sandboxShowPaths,
              hidePaths: [...config.sandboxHidePaths, STATE_DIR],
              project,
            },
            scan,
          );
          if (p.problem) throw new Error(p.problem);
          call.sandbox = p;
        } catch (e) {
          call.decision = { ...decision, effect: "ask", reason: `would be allowed, but the sandbox could not be prepared: ${(e as Error).message}` };
        }
      }
      // Unsandboxed (the sandbox switched off), an allowed git call can move anything.
      if (call.decision.effect === "allow" && !config.sandbox) call.mover = HOLDS_GIT.test(run);
      if (call.decision.effect === "allow") {
        const reason = besides(call, input.background === true);
        if (reason) call.decision = { ...call.decision, effect: "ask", reason: `would be allowed, but ${reason}` };
      }
      if (call.decision.effect !== "allow") call.mover = false;
      // An approved prompt runs unsandboxed: it could move HEAD under a checked push. Say so.
      if (call.decision.effect === "ask") call.decision = { ...call.decision, reason: call.decision.reason + pushNote(call) };
      call.decided = true;
      if (call.decision.effect === "deny") live.delete(call);
      // Every call is queued, asks too, until its permission is evaluated or it is over.
      const key = wrapKey(command, cwd);
      call.at = Date.now();
      toWrap.set(key, [...waiting(key), call]);
      bound(toWrap, 200);
      // If the user approves it, what it creates is expected, where it said it would create it.
      if (call.decision.effect === "ask" && !s.tampered) call.expects = expectedRepos(command, cwd);
      calls.set(callKey(event.messageID, event.id), call);
      // A call that may still run stays in the table whatever its size: its completion hook must
      // find it, for the check of what it left in the git directories it could write (round 4,
      // finding 21). The oldest calls that are over go first.
      for (const [key, old] of calls) {
        if (calls.size <= 500) break;
        if (!live.has(old)) calls.delete(key);
      }
      // The log holds the command as issued, and the text that runs in its place when the two differ.
      const { printed, ...logged } = call.decision;
      log(config, { sessionID: event.sessionID, tool: event.tool, command: clip(command), cwd, ...logged, ...(call.decision.effect === "allow" && printed !== undefined && printed !== command ? { runs: clip(printed) } : {}), totalMs: Date.now() - started });
    });

    // The user approved the prompt for this call: from now until the call is over, a repository
    // may appear where the command named one.
    // An allowed call that may still run and could write there makes the window expect nothing:
    // what appears may be that call's (finding 36). Calls decided later ask while it is open.
    const approved = (call: Call | undefined) => {
      if (!call) return;
      call.started ??= Date.now();
      // What the approved command writes is the session's writing, as an allowed command's is
      // (round 4, finding 4): the decision recorded it for this moment. It runs once.
      call.decision.approve?.();
      if (!call.expects || call.expecting) return;
      sweep();
      const expecting: Expected = { dirs: call.expects, at: Date.now() };
      if ([...live].some((c) => c !== call && c.decided && c.decision.effect === "allow" && !c.downgraded && reaches(c, expecting.dirs))) expecting.tainted = true;
      call.expecting = expecting;
      session(call.sessionID).expecting.push(expecting);
      // The approval was learned only when the call completed, and no process of it is left
      // (the sweep above retired it before it had an approval to close): its window closes
      // here, or every later call would ask until the approval ran out (round 4, finding 21).
      if (call.ended !== undefined && !live.has(call)) finish(call);
    };

    const afterHook = await ctx.tool.hook("execute.after", (event) => {
      const call = calls.get(callKey(event.messageID, event.id));
      if (!call) return;
      call.settled = true;
      call.ended = Date.now();
      // A command the plugin asked about only runs to the end when the user approved it. This
      // also covers an approval whose event has not arrived yet.
      if (event.status === "completed" && call.decision.effect === "ask") approved(call);
      // The per-call check, before the result goes back (opencode awaits this hook), also for a
      // call whose background process lives on: a plant is renamed, and every session pauses.
      if (call.gitCall) {
        const planted = quarantineGitFiles(session(call.sessionID), sessions.values(), call.gitCall);
        if (planted) pauseAll(planted, session(call.sessionID));
      }
      // Over once no process of it is left: the window of an approved command closes then.
      sweep();
    });

    const shellHook = await ctx.shell.hook("create.before", (event) => {
      // No shell the plugin sees inherits bash's own variables that change how a command is read
      // (BASH_ENV, SHELLOPTS, CDPATH and the like; shellOwn in sandbox.ts): the rules judged the
      // command as a bash with default settings reads it, whether it then runs in the sandbox,
      // with the sandbox off, or after a prompt (round 4, finding 29, sixth pass). opencode
      // builds the child's environment from the event after this hook. `sandboxKeepEnv` names
      // the ones that are yours to keep.
      if (config.enabled) for (const name of Object.keys(event.env)) if (shellOwn(name) && !config.sandboxKeepEnv.includes(name)) delete event.env[name];
      // create.before gets the raw workdir; opencode resolves it against the session directory.
      const key = wrapKey(event.command, resolveWorkdir(project, event.cwd));
      // Calls whose shell never came (the tool failed first, or opencode denied it) drop out,
      // so they cannot take the place of a later identical command.
      const queue = waiting(key);
      if (!queue.length) return void toWrap.delete(key);
      toWrap.set(key, queue);
      // Marks the processes of this shell, whichever of the waiting calls it belongs to.
      const token = `${nonce}.${++shells}`;
      for (const c of queue) c.tokens.push(token);
      const shell = resolveShell(event.shell);
      const kind = shell ? path.basename(shell) : "";
      // Which of the waiting calls this shell belongs to cannot be known. It is sandboxed only
      // when that makes no difference: every one of them is an allow of the same session, of the
      // same printed text (identical commands print alike).
      const call = queue.at(-1)!;
      const run = call.decision.printed;
      const allAllowed = queue.every((c) => c.decision.effect === "allow" && !c.unsure && c.decision.printed === run) && run !== undefined && new Set(queue.map((c) => c.sessionID)).size === 1;
      const modelled = !!shell && WRAPPABLE.has(kind) && wrappable(shell);
      // The printed text is bash's reading of the command, and dash's can differ: under dash no
      // allow stands (it is not `modelled`), and the prompt names the reason.
      if (shell && path.basename(realpath(shell)) === "dash") for (const c of queue) c.dash = true;
      // A shell that inherits one of git's own variables that point it at another repository or
      // another configuration (`GIT_DIR`, `GIT_CONFIG_COUNT`, ...; gitElsewhere in sandbox.ts):
      // a git command in it was judged for the repository in its directory, and would work
      // somewhere else. The variable is the user's own setting, so it stays; the shell is left
      // as it is and a call that holds a git command asks, saying which variable (round 4,
      // finding 21, seventh pass). `sandboxKeepEnv` naming it changes nothing here: the checks
      // cannot judge git as that variable makes it work.
      // The other way round too (eighth pass): a variable that names the configuration git
      // reads, set for this process and not for the shell (opencode hands a shell its session's
      // environment), makes the checks' git read one file and the shell's git another.
      const elsewhere = config.enabled ? gitElsewhere(event.env) : undefined;
      if (elsewhere && queue.some((c) => HOLDS_GIT.test(c.decision.printed ?? c.command))) {
        for (const c of queue) {
          c.unsure = true;
          c.gitEnv = elsewhere;
          c.gitEnvLacks = event.env[elsewhere] === undefined;
        }
        event.env.AUTOMODE_CALL = token;
        return;
      }
      if (!config.sandbox && allAllowed && modelled) {
        // No wrapper to hand the text to: the shell is given the printed text as its command.
        // opencode builds the shell's arguments from the event after this hook.
        event.command = run!;
        event.env.AUTOMODE_CALL = token;
        for (const c of queue) c.rewritten = true;
        return;
      }
      if (!allAllowed || !modelled || !queue.every((c) => c.sandbox)) {
        // Left as it is. It may be the shell of any of them, so none may run on an allow.
        for (const c of queue) c.unsure = true;
        event.env.AUTOMODE_CALL = token;
        return;
      }
      // The plan made last is the freshest.
      const sandbox = call.sandbox!;
      if (!call.exposeSsh && !config.sandboxKeepSockets.length) delete event.env.SSH_AUTH_SOCK;
      // Only variables that plainly hold no credential pass. They are removed here, and lockwrite
      // drops everything not on the list as well, whatever environment it was started with.
      const { keep, dropped } = envKept(event.env, config.sandboxKeepEnv);
      // The wrapper is handed the command and the names it may keep as one environment string
      // each. One that the kernel would refuse fails the exec (E2BIG): the shell is left as it
      // is, and the call asks, saying why (round 4, finding 24, sixth pass).
      const tooLong = envStringProblem("AUTOMODE_COMMAND", run!) ?? envStringProblem("AUTOMODE_ENV_KEEP", joined(keep));
      if (tooLong) {
        for (const c of queue) {
          c.unsure = true;
          c.tooLong = tooLong;
        }
        event.env.AUTOMODE_CALL = token;
        return;
      }
      for (const name of dropped) delete event.env[name];
      if (dropped.length) log(config, { command: clip(call.command, 200), envDropped: dropped });
      event.env.AUTOMODE_ENV_KEEP = joined(keep);
      // lockwrite drops every AUTOMODE_* variable from the command's environment; its own process
      // keeps this one for as long as the command runs.
      event.env.AUTOMODE_CALL = token;
      event.env.AUTOMODE_SHELL = shell!;
      // What was judged is what runs: lockwrite runs this text in place of its `-c` argument.
      event.env.AUTOMODE_COMMAND = run!;
      event.env.AUTOMODE_RW = joined(sandbox.rw);
      event.env.AUTOMODE_RO = joined(sandbox.ro);
      event.env.AUTOMODE_REOPEN = joined(sandbox.reopen);
      event.env.AUTOMODE_HIDE = joined(sandbox.hide);
      event.env.AUTOMODE_PIN = joined(sandbox.pin);
      event.env.AUTOMODE_TMPFS = joined(sandbox.tmpfs);
      const coverFile = cover();
      if (coverFile) event.env.AUTOMODE_COVER = coverFile;
      event.shell = path.join(WRAPPER_DIR, kind);
      for (const c of queue) c.wrapped = true;
    });

    const apply = (event: { effect: string; message?: string }, decision: Decision) => {
      event.effect = decision.effect;
      if (decision.effect !== "allow") event.message = `automode: ${decision.reason}`;
    };

    const permissionHook = await ctx.permission.hook("evaluate", async (event) => {
      if (!config.enabled) return;
      const base = { sessionID: event.sessionID, action: event.action, before: event.effect };
      try {
        if (event.action === "shell") {
          const call = event.source ? calls.get(callKey(event.source.messageID, event.source.id)) : undefined;
          if (!call) {
            // A schedule's `if`/`until` check. This request is its approval, and the check later
            // runs outside any sandbox (opencode spawns it directly, with its whole environment).
            // Whoever created the schedule, it is judged like any command and can at most ask.
            if (event.metadata?.unattended === true) {
              const run = typeof event.metadata.run === "string" ? event.metadata.run : event.resources.join("\n");
              const decision = await decide(session(event.sessionID), project, run);
              if (decision.effect === "allow") {
                decision.effect = "ask";
                decision.reason = `a scheduled check runs unsandboxed (${decision.reason || "rules allow it"})`;
              }
              apply(event, decision);
              log(config, { ...base, command: clip(run), schedule: true, ...decision });
              return;
            }
            // A scheduled check's later runs re-ask on every slot; reuse a recent answer.
            const cacheKey = `${event.sessionID}\u0000${event.resources.join("\n")}`;
            const cached = unseen.get(cacheKey);
            if (cached && Date.now() - cached.at < 300_000) {
              apply(event, cached.decision);
              return;
            }
            // Not a tool call this plugin saw start. Judge the statements
            // opencode split out; nothing here can be sandboxed, so an allow becomes an ask.
            // (Whether or not the sandbox is on: a schedule's later checks come this way, and
            // a schedule is never auto-allowed.)
            const decision = await decide(session(event.sessionID), project, event.resources.join("\n"));
            if (decision.effect === "allow") {
              decision.effect = "ask";
              decision.reason = `would be allowed (${decision.reason || "rules"}), but this is not a tool call the plugin saw start, so it cannot be sandboxed`;
            }
            apply(event, decision);
            unseen.set(cacheKey, { at: Date.now(), decision });
            bound(unseen, 200);
            log(config, { ...base, command: clip(event.resources.join("\n")), unseen: true, ...decision });
            return;
          }
          const decision = { ...call.decision };
          const changed = session(call.sessionID).tampered;
          if (decision.effect === "allow" && changed) {
            decision.effect = "ask";
            decision.reason = `auto-allow paused for this session: ${changed.reason}. Check what is there; approving this prompt does not resume. To resume, run \`touch ${RESUME_FILE}\` in your own terminal.`;
          }
          call.settled = true;
          // An allow stands only when its shell runs the text that was judged: inside the
          // wrapper, or, with the sandbox off, as the command the shell was handed.
          // `unsure` counts with the sandbox off as well: a shell that came later for the same
          // command and was left as written may be this call's (round 4 cross-check).
          if (decision.effect === "allow" && (call.unsure || (config.sandbox ? !call.wrapped : !call.rewritten))) {
            decision.effect = "ask";
            const would = `would be allowed (${decision.reason || "rules"})`;
            decision.reason = call.dash
              ? `${would}, but the shell here is dash: the checks read a command as bash reads it, and dash reads some commands another way, so nothing runs without a prompt under dash. Set opencode's shell to bash to have commands allowed`
              : call.gitEnv && call.gitEnvLacks
                ? `${would}, but its shell does not inherit ${call.gitEnv}, which opencode's own environment sets: the checks read git's configuration as that variable says, and git in this shell would read another. Start opencode and its sessions with the same value (or with none), or approve this to run it as it is`
              : call.gitEnv
                ? `${would}, but its shell inherits ${call.gitEnv}, which makes git work in another repository or with another configuration than the one that was judged (the checks read the repository in the command's directory). Unset it where opencode is started, or approve this to run it as it is; naming it in sandboxKeepEnv keeps it for sandboxed shells and does not change this`
              : call.tooLong
                ? `${would}, but the sandbox cannot be handed it: ${call.tooLong} (128 KiB for the command as it runs, and for the names of the environment variables it keeps)`
              : !config.sandbox
                ? `${would}, but its shell could not be handed the text that was judged (a shell other than bash, or an identical command issued at the same time that was not allowed)`
                : !sandboxReady
                  ? `${would}, but the sandbox is unavailable: ${sandboxProblem}`
                  : call.wrapped
                    ? `${would}, but an identical command issued at the same time was not, and their shells cannot be told apart. If you approve this one it may still run sandboxed`
                    : `${would}, but its shell could not be sandboxed`;
            // The reason, so that the log says why an allowed command was asked about after all.
            log(config, { ...base, command: clip(call.command), sandboxMiss: true, reason: decision.reason });
          }
          // The record of what is in the git directories the call may write, before it starts.
          // Without it nothing could be compared when the call is over: it asks instead.
          if (decision.effect === "allow" && call.sandbox && !call.gitCall) {
            try {
              call.gitCall = noteGitCall(session(call.sessionID), call.decision.printed ?? call.command, call.sandbox.gitDirs, call.sandbox.gitWatch);
            } catch (e) {
              decision.effect = "ask";
              decision.reason = `would be allowed (${decision.reason || "rules"}), but a git directory it could write cannot be looked into, so what it leaves there could not be checked: ${(e as Error).message}`;
            }
          }
          if (decision.effect === "allow") call.started ??= Date.now();
          else if (call.decision.effect === "allow") {
            call.downgraded = true;
            decision.reason += pushNote(call);
          }
          apply(event, decision);
          return;
        }
        if (event.action === "edit") {
          // An edit could build a repository where an approved command may be creating one.
          sweep();
          const open = windows();
          for (const resource of event.resources) {
            const target = realish(path.isAbsolute(resource) ? resource : path.resolve(project, resource));
            const dir = open.flatMap((e) => e.dirs).find((d) => within(target, d));
            if (dir) {
              const decision: Decision = { effect: "ask", by: "rules", rule: "ask", reason: `edit inside ${dir}, where an approved command may still be creating a repository` };
              apply(event, decision);
              log(config, { ...base, target, ...decision });
              return;
            }
          }
        }
        if (event.action === "edit" || event.action === "read") {
          for (const resource of event.resources) {
            const target = path.isAbsolute(resource) ? resource : path.resolve(project, resource);
            const decision =
              event.action === "edit" ? decideFile(guard, session(event.sessionID), project, target) : decideRead(guard, session(event.sessionID), project, target);
            // Tighten only: a file verdict never turns opencode's ask into an allow.
            if (decision && decision.effect !== "allow") {
              apply(event, decision);
              log(config, { ...base, target, ...decision });
              return;
            }
          }
        }
      } catch (e) {
        const reason = `automode failed, asking instead: ${(e as Error).message}`;
        if (event.effect === "allow") {
          event.effect = "ask";
          event.message = reason;
        }
        log(config, { ...base, error: (e as Error).message });
      }
    });

    // Mirror "Always allow" replies for shell requests into the plugin's allow rules.
    const stop = new AbortController();
    const pending = new Map<string, string[]>();
    // Prompts for shell tool calls: request id -> the call.
    const prompts = new Map<string, string>();
    void (async () => {
      try {
        for await (const raw of ctx.event.subscribe({ types: ["permission.asked", "permission.replied"], signal: stop.signal })) {
          const event = raw as { type: string; data?: Record<string, unknown> };
          const data = event.data ?? {};
          if (event.type === "permission.asked" && data.action === "shell" && typeof data.id === "string") {
            const save = Array.isArray(data.save) ? (data.save as unknown[]).filter((x): x is string => typeof x === "string") : [];
            if (save.length) pending.set(data.id, save);
            bound(pending, 200);
            const source = data.source as { type?: unknown; messageID?: unknown; id?: unknown } | undefined;
            if (source?.type === "tool" && typeof source.messageID === "string" && typeof source.id === "string") prompts.set(data.id, callKey(source.messageID, source.id));
            bound(prompts, 200);
          } else if (event.type === "permission.replied" && typeof data.requestID === "string") {
            const asked = prompts.get(data.requestID);
            prompts.delete(data.requestID);
            if (asked && (data.reply === "once" || data.reply === "always")) approved(calls.get(asked));
            else if (asked && data.reply === "reject") {
              const rejected = calls.get(asked);
              if (rejected) rejected.rejected = true;
            }
            const save = pending.get(data.requestID);
            pending.delete(data.requestID);
            if (data.reply === "always" && save) {
              // Kept per project, used like a prompt's session pick (never over a firm ask), and
              // only for plain patterns that do not wrap another program.
              const plain = save.filter(mirrorable);
              if (plain.length) {
                always = [...new Set([...loadAlways(projectKey), ...plain])];
                saveAlways(projectKey, always);
                guard = makeGuard();
              }
              log(config, { action: "shell", always: plain, ignored: save.filter((p) => !plain.includes(p)) });
            }
          }
        }
      } catch (e) {
        if (!stop.signal.aborted) console.error(`[opencode-automode] event stream ended: ${(e as Error).message}`);
      }
    })();

    return async () => {
      stop.abort();
      for (const s of sessions.values()) closeGitSnapshot(s);
      sessions.clear();
      calls.clear();
      live.clear();
      toWrap.clear();
      await permissionHook.dispose();
      await shellHook.dispose();
      await afterHook.dispose();
      await toolHook.dispose();
    };
  },
});
