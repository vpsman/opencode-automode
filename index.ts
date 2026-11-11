// opencode-automode: auto mode for opencode 2.x permission prompts, fully local.
//
// Flow for a shell tool call:
//   tool.execute.before   decide on the full command (Pi's rules, then Kev for what they leave
//                         open) and remember the decision by tool call.
//   shell.create.before   if the decision is allow, swap the shell for sandbox/bin/<shell>, a
//                         link to sandbox/lockwrite. It runs the real shell with the same
//                         arguments inside a sandbox: writes only to the project, temp dirs,
//                         /dev and build caches; git hooks and config read-only; local sockets
//                         of other services hidden. The command text is never changed, so
//                         opencode's own rules and prompts see the real command. Commands that
//                         ask are not sandboxed: what you approve runs as you saw it.
//   permission.evaluate   apply the decision. An allow whose shell was not swapped asks instead,
//                         so a missing or broken sandbox never widens what runs.
// opencode 2.2.7 fires the three in that order for one call (core/src/tool.ts, shell.ts,
// tool/plugin/shell.ts), and hands create.before the child's whole environment.
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
import { compileRules, compilePattern } from "./rules.ts";
import { decideFile, decideRead, decideShell, expectsNewRepo, gitOnly, mirrorable, projectRoots, SessionState, usesSsh, type Decision, type Guard } from "./decide.ts";
import { envKept, plan, realpath, type Plan } from "./sandbox.ts";
import { loadConfig, type Config } from "./config.ts";

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
// Shells the wrapper stands in for. opencode passes `-c <command>` (zsh: `+o nomatch -c`).
const WRAPPABLE = new Set(["bash", "zsh", "sh"]);

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

interface Call {
  command: string;
  cwd: string;
  decision: Decision;
  sandbox?: Plan;
  exposeSsh?: boolean;
  wrapped?: boolean;
  at: number;
}

export default Plugin.define({
  id: "opencode-automode",
  async setup(ctx) {
    const loaded = loadConfig(CONFIG_FILE, ctx.options);
    const config: Config = loaded.config;
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
    const decide = async (s: SessionState, cwd: string, command: string): Promise<Decision> => {
      const decision = held(await decideShell(guard, s, cwd, command));
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
    const bound = <K, V>(map: Map<K, V>, max: number) => {
      while (map.size > max) map.delete(map.keys().next().value!);
    };

    const toolHook = await ctx.tool.hook("execute.before", async (event) => {
      if (!config.enabled) return;
      if (event.tool !== "shell" && event.tool !== "bash") return;
      const input = event.input as { command?: unknown; workdir?: unknown } | undefined;
      if (typeof input?.command !== "string") return;
      const command = input.command;
      // opencode resolves workdir against the session directory without following symlinks.
      const cwd = typeof input.workdir === "string" && input.workdir ? resolveWorkdir(project, input.workdir) : project;
      const started = Date.now();
      const s = session(event.sessionID);
      let decision: Decision;
      try {
        decision = await decide(s, cwd, command);
      } catch (e) {
        decision = { effect: "ask", by: "rules", rule: "ask", reason: `automode failed, asking instead: ${(e as Error).message}` };
      }
      const call: Call = { command, cwd, decision, at: Date.now() };
      if (decision.effect === "allow" && sandboxReady) {
        try {
          const roots = projectRoots(s);
          call.exposeSsh = usesSsh(command, cwd, s);
          const p = plan({
            projectRoots: roots,
            allowedPaths: config.allowedPaths,
            cacheDirs: config.sandboxWritable,
            gitWritable: gitOnly(command),
            exposeSsh: call.exposeSsh,
            keepSockets: config.sandboxKeepSockets,
            showPaths: config.sandboxShowPaths,
            hidePaths: [...config.sandboxHidePaths, STATE_DIR],
            project,
          });
          if (p.problem) throw new Error(p.problem);
          call.sandbox = p;
        } catch (e) {
          call.decision = { ...decision, effect: "ask", reason: `would be allowed, but the sandbox could not be prepared: ${(e as Error).message}` };
        }
      }
      // Every call is queued, asks too: a shell is only sandboxed when every call still waiting
      // for a shell with the same command and directory is an allow, so a sandbox can never end
      // up on the wrong call.
      const key = wrapKey(command, cwd);
      call.at = Date.now();
      toWrap.set(key, [...(toWrap.get(key) ?? []).filter((c) => call.at - c.at < WRAP_WINDOW_MS), call]);
      bound(toWrap, 200);
      if (call.decision.effect === "ask" && !s.tampered && expectsNewRepo(command)) s.expectNewRepo = true;
      calls.set(callKey(event.messageID, event.id), call);
      bound(calls, 500);
      log(config, { sessionID: event.sessionID, tool: event.tool, command: clip(command), cwd, ...call.decision, totalMs: Date.now() - started });
    });

    const shellHook = await ctx.shell.hook("create.before", (event) => {
      // create.before gets the raw workdir; opencode resolves it against the session directory.
      const key = wrapKey(event.command, resolveWorkdir(project, event.cwd));
      // Calls whose shell never came (the tool failed first, or opencode denied it) are dropped,
      // so they cannot take the place of a later identical command.
      const queue = (toWrap.get(key) ?? []).filter((c) => Date.now() - c.at < WRAP_WINDOW_MS);
      if (!queue.length) return void toWrap.delete(key);
      const allAllowed = queue.every((c) => c.decision.effect === "allow" && c.sandbox);
      const call = queue.shift()!;
      if (queue.length) toWrap.set(key, queue);
      else toWrap.delete(key);
      if (!allAllowed || !call.sandbox) return; // left as is: an allow among them will ask
      const shell = resolveShell(event.shell);
      const kind = shell ? path.basename(shell) : "";
      if (!shell || !WRAPPABLE.has(kind)) return; // left as is: evaluate will ask
      if (!call.exposeSsh && !config.sandboxKeepSockets.length) delete event.env.SSH_AUTH_SOCK;
      // Only variables that plainly hold no credential pass. They are removed here, and lockwrite
      // drops everything not on the list as well, whatever environment it was started with.
      const { keep, dropped } = envKept(event.env, config.sandboxKeepEnv);
      for (const name of dropped) delete event.env[name];
      if (dropped.length) log(config, { command: clip(call.command, 200), envDropped: dropped });
      event.env.AUTOMODE_ENV_KEEP = joined(keep);
      event.env.AUTOMODE_SHELL = shell;
      event.env.AUTOMODE_RW = joined(call.sandbox.rw);
      event.env.AUTOMODE_RO = joined(call.sandbox.ro);
      event.env.AUTOMODE_HIDE = joined(call.sandbox.hide);
      event.env.AUTOMODE_PIN = joined(call.sandbox.pin);
      event.env.AUTOMODE_TMPFS = joined(call.sandbox.tmpfs);
      const coverFile = cover();
      if (coverFile) event.env.AUTOMODE_COVER = coverFile;
      event.shell = path.join(WRAPPER_DIR, kind);
      call.wrapped = true;
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
            const decision = await decide(session(event.sessionID), project, event.resources.join("\n"));
            if (decision.effect === "allow" && config.sandbox) {
              decision.effect = "ask";
              decision.reason = `would be allowed (${decision.reason || "rules"}), but this call cannot be sandboxed`;
            }
            apply(event, decision);
            unseen.set(cacheKey, { at: Date.now(), decision });
            bound(unseen, 200);
            log(config, { ...base, command: clip(event.resources.join("\n")), unseen: true, ...decision });
            return;
          }
          const decision = { ...call.decision };
          if (decision.effect === "allow" && config.sandbox && !call.wrapped) {
            decision.effect = "ask";
            decision.reason = sandboxReady
              ? `would be allowed (${decision.reason || "rules"}), but its shell could not be sandboxed`
              : `would be allowed (${decision.reason || "rules"}), but the sandbox is unavailable: ${sandboxProblem}`;
            log(config, { ...base, command: clip(call.command), sandboxMiss: true });
          }
          apply(event, decision);
          return;
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
    void (async () => {
      try {
        for await (const raw of ctx.event.subscribe({ types: ["permission.asked", "permission.replied"], signal: stop.signal })) {
          const event = raw as { type: string; data?: Record<string, unknown> };
          const data = event.data ?? {};
          if (event.type === "permission.asked" && data.action === "shell" && typeof data.id === "string") {
            const save = Array.isArray(data.save) ? (data.save as unknown[]).filter((x): x is string => typeof x === "string") : [];
            if (save.length) pending.set(data.id, save);
            bound(pending, 200);
          } else if (event.type === "permission.replied" && typeof data.requestID === "string") {
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
      sessions.clear();
      calls.clear();
      toWrap.clear();
      await permissionHook.dispose();
      await shellHook.dispose();
      await toolHook.dispose();
    };
  },
});
