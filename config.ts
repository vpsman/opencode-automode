// Settings: ~/.config/opencode/automode.json merged with the plugin's options in opencode's
// config. Everything is checked. A file that cannot be read, a wrong type or an unknown key is a
// problem, and with a problem the plugin auto-allows nothing: silently falling back to defaults
// would drop `enabled: false` and the user's own ask and deny rules.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { compilePattern, isRootLike, type Action } from "./rules.ts";
import { DEFAULT_CLASSIFIER, type ClassifierConfig } from "./kev.ts";
import { DEFAULT_ASK } from "./decide.ts";
import { DEFAULT_CACHE_DIRS } from "./sandbox.ts";

export interface Config {
  enabled: boolean;
  useClassifier: boolean;
  classifier: ClassifierConfig;
  rules: Partial<Record<Action, string[]>>;
  allowedPaths: string[];
  sshHosts: string[];
  sshReadOnlySudo: boolean;
  allowFeatureBranchPush: boolean;
  sandbox: boolean;
  sandboxWritable: string[];
  sandboxKeepSockets: string[];
  sandboxShowPaths: string[];
  sandboxHidePaths: string[];
  sandboxKeepEnv: string[];
  log: boolean;
}

const HOME = os.homedir();
const expandHome = (p: string) => (p === "~" ? HOME : p.startsWith("~/") ? path.join(HOME, p.slice(2)) : p);

const BOOLEANS = ["enabled", "useClassifier", "sshReadOnlySudo", "allowFeatureBranchPush", "sandbox", "log"] as const;
const LISTS = ["allowedPaths", "sshHosts", "sandboxWritable", "sandboxKeepSockets", "sandboxShowPaths", "sandboxHidePaths", "sandboxKeepEnv"] as const;
// Directories these open for writing: never /, a top-level directory, $HOME or one above it.
const WRITABLE_LISTS = ["allowedPaths", "sandboxWritable"];
const ACTIONS: Action[] = ["allow", "ask", "deny", "classify"];
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const isStrings = (v: unknown): v is string[] => Array.isArray(v) && v.every((x) => typeof x === "string" && x.length > 0);

export const defaults = (): Config => ({
  enabled: true,
  useClassifier: true,
  classifier: { ...DEFAULT_CLASSIFIER },
  rules: { ask: [...DEFAULT_ASK] },
  allowedPaths: [],
  sshHosts: [],
  sshReadOnlySudo: false,
  allowFeatureBranchPush: false,
  sandbox: true,
  sandboxWritable: [...DEFAULT_CACHE_DIRS],
  sandboxKeepSockets: [],
  sandboxShowPaths: [],
  sandboxHidePaths: [],
  sandboxKeepEnv: [],
  log: true,
});

// The settings in `raw` applied over `config`; every problem found is added to `problems`.
// `optional`: no value at all is fine (opencode passes null when the plugin has no options). A
// settings file that holds `null` is not a settings file.
function apply(config: Config, raw: unknown, where: string, problems: string[], optional = false) {
  if (optional && (raw === undefined || raw === null)) return;
  if (!isObject(raw)) return void problems.push(`${where} must be an object`);
  const bad = (key: string, want: string) => void problems.push(`${where}: "${key}" must be ${want}`);
  for (const [key, value] of Object.entries(raw)) {
    if ((BOOLEANS as readonly string[]).includes(key)) {
      if (typeof value === "boolean") config[key as (typeof BOOLEANS)[number]] = value;
      else bad(key, "true or false");
    } else if ((LISTS as readonly string[]).includes(key)) {
      if (!isStrings(value)) bad(key, "a list of strings");
      else if (key === "sshHosts" && !value.every((h) => /^[\w.-]+(@[\w.-]+)?$/.test(h))) bad(key, "a list of host names, each optionally with a user (user@host)");
      else if (key === "sandboxKeepEnv" && !value.every((n) => /^[A-Za-z_]\w*$/.test(n))) bad(key, "a list of variable names");
      else if (key === "sshHosts" || key === "sandboxKeepEnv") config[key] = value;
      else {
        // A relative path would mean something else in every project and every working directory.
        const paths = value.map(expandHome);
        const relative = paths.find((p) => !path.isAbsolute(p));
        const wide = WRITABLE_LISTS.includes(key) ? paths.find((p) => isRootLike(path.resolve(p))) : undefined;
        if (relative !== undefined) bad(key, `a list of absolute paths (or ~/...); ${JSON.stringify(relative)} is relative`);
        else if (wide !== undefined) bad(key, `a list of directories below your home or elsewhere; ${JSON.stringify(wide)} is /, a top-level directory, or your home or above`);
        else config[key as Exclude<(typeof LISTS)[number], "sshHosts" | "sandboxKeepEnv">] = paths;
      }
    } else if (key === "rules") {
      if (!isObject(value) || !Object.entries(value).every(([action, list]) => ACTIONS.includes(action as Action) && isStrings(list))) {
        bad(key, "an object with allow, ask, deny and classify lists of patterns");
        continue;
      }
      for (const [action, list] of Object.entries(value) as [Action, string[]][]) {
        for (const pattern of list) {
          try {
            compilePattern(pattern);
          } catch (e) {
            problems.push(`${where}: rules.${action} pattern ${JSON.stringify(pattern)} is not valid: ${(e as Error).message}`);
          }
        }
        // Added to what is there already: the plugin options do not replace the file's rules.
        config.rules[action] = [...new Set([...(config.rules[action] ?? (action === "ask" ? DEFAULT_ASK : [])), ...list])];
      }
    } else if (key === "classifier") {
      if (!isObject(value)) {
        bad(key, "an object");
        continue;
      }
      for (const [name, v] of Object.entries(value)) {
        if (name === "askAbove") {
          if (typeof v === "number" && v > 0 && v <= 1) config.classifier.askAbove = v;
          else bad("classifier.askAbove", "a number above 0 and at most 1");
        } else if (name === "timeoutMs") {
          if (typeof v === "number" && v >= 100 && v <= 120_000) config.classifier.timeoutMs = v;
          else bad("classifier.timeoutMs", "a number of milliseconds between 100 and 120000");
        } else if (name === "endpoint") {
          if (typeof v === "string" && /^(unix:\/|https?:\/\/)\S+$/.test(v)) config.classifier.endpoint = v;
          else bad("classifier.endpoint", "unix:/path/to/socket or an http(s) URL");
        } else if (name === "model" || name === "question" || name === "risky" || name === "safe") {
          if (typeof v === "string" && v) config.classifier[name] = v;
          else bad(`classifier.${name}`, "a string");
        } else problems.push(`${where}: unknown setting "classifier.${name}"`);
      }
    } else problems.push(`${where}: unknown setting "${key}"`);
  }
}

export interface Loaded {
  config: Config;
  // Set when the settings could not be used as written. Nothing is auto-allowed then.
  problem?: string;
}

export function loadConfig(configFile: string, options: unknown): Loaded {
  const config = defaults();
  const problems: string[] = [];
  let text: string | undefined;
  try {
    text = fs.readFileSync(configFile, "utf8");
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") problems.push(`${configFile} cannot be read: ${(e as Error).message}`);
  }
  if (text !== undefined) {
    try {
      apply(config, JSON.parse(text), configFile, problems);
    } catch (e) {
      problems.push(`${configFile} is not valid JSON: ${(e as Error).message}`);
    }
  }
  apply(config, options, "plugin options", problems, true);
  return problems.length ? { config: defaults(), problem: problems.join("; ") } : { config };
}
