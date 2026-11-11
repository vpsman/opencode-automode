// Checks that run around the vendored rules (rules.ts), which is kept byte-identical to upstream.
// The rules grant an allow by ruling out the spellings they know; bash, git and the GNU tools
// accept more. Everything here works the other way round: it accepts the exact forms it
// understands and sends the rest to a prompt (or, where a prompt would be too much, to the model).
//
//   unmodelled()   shell syntax the rules' parser reads differently from bash: ask
//   strict()       a tokenizer for the few places that grant extra trust (the ssh agent, a
//                  writable .git, feature-branch push, read-only ssh): plain words only
//   gitProblem()   git global options outside a short allowlist: ask
//   textGuards()   per simple command, as the rules see it (also inside `sh -c`, `sudo`,
//                  `xargs`): environment dumps and overrides, package installs, credential files
//                  named by a glob, files this session wrote
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { parse, readVerdict, type Matcher, type Scope } from "./rules.ts";

const HOME = os.homedir();

export interface GuardVerdict {
  action: "ask" | "classify";
  reason: string;
  // Files this session wrote that the command runs: shown to the model.
  files?: string[];
}

const stricter = (a: GuardVerdict | undefined, b: GuardVerdict | undefined) => (!a ? b : !b ? a : a.action === "ask" ? a : b.action === "ask" ? b : a);

// ---- shell syntax ----

// rules.ts's matchParen: counts parentheses, skipping a backslashed character.
function closeNaive(s: string, open: number): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === "\\") i++;
    else if (s[i] === "(") depth++;
    else if (s[i] === ")" && --depth === 0) return i;
  }
  return -1;
}

// The same, but a parenthesis inside quotes does not count, as in bash.
function closeQuoted(s: string, open: number): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    if (c === "\\") i++;
    else if (c === "'") {
      i = s.indexOf("'", i + 1);
      if (i < 0) return -1;
    } else if (c === '"') {
      for (i++; i < s.length && s[i] !== '"'; i++) if (s[i] === "\\") i++;
      if (i >= s.length) return -1;
    } else if (c === "(") depth++;
    else if (c === ")" && --depth === 0) return i;
  }
  return -1;
}

const WORD_END = /[ \t\n;|&)<>]/;
const HEREDOC = /^<<(-?)[ \t]*(?:'([\w.-]+)'|"([\w.-]+)"|([\w.-]+))(?=[ \t\n;|&)<>]|$)/;

// Shell syntax that bash and the rules' parser read differently, or undefined. The parser never
// sees `$'...'`, takes a `#` after a redirect for a comment, stops a heredoc delimiter at the
// first quote and accepts an indented terminator; in each case bash runs commands the rules
// did not check.
export function unmodelled(s: string, depth = 0): string | undefined {
  if (depth > 6) return "deeply nested substitutions";
  const heredocs: { delimiter: string; dash: boolean; quoted: boolean }[] = [];
  let braces = 0;
  const substitution = (open: number): number | string => {
    const end = closeNaive(s, open);
    if (end < 0 || end !== closeQuoted(s, open)) return "a substitution with quoted or unbalanced parentheses";
    return unmodelled(s.slice(open + 1, end), depth + 1) ?? end;
  };
  const backticks = (open: number): number | string => {
    const end = s.indexOf("`", open + 1);
    if (end < 0) return "an unterminated backtick";
    const body = s.slice(open + 1, end);
    if (body.includes("\\")) return "a backslash inside backticks";
    return unmodelled(body, depth + 1) ?? end;
  };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const next = s[i + 1];
    if (c === "\\") i++;
    else if (c === "'") {
      i = s.indexOf("'", i + 1);
      if (i < 0) return "an unterminated quote";
    } else if (c === '"') {
      for (i++; i < s.length && s[i] !== '"'; i++) {
        if (s[i] === "\\") i++;
        else if (s[i] === "`" || (s[i] === "$" && s[i + 1] === "(")) {
          const end = s[i] === "`" ? backticks(i) : substitution(i + 1);
          if (typeof end === "string") return end;
          i = end;
        }
      }
      if (i >= s.length) return "an unterminated quote";
    } else if (c === "$" && (next === "'" || next === '"')) return `${c}${next}...${next} quoting`;
    else if (c === "$" && next === "{") {
      if (/^\$\{[^}]*@[A-Za-z]\}/.test(s.slice(i))) return "a ${name@X} transformation";
      braces++;
      i++;
    } else if (c === "$" && next === "#") i++;
    else if (c === "`") {
      const end = backticks(i);
      if (typeof end === "string") return end;
      i = end;
    } else if ((c === "$" || c === "<" || c === ">") && next === "(") {
      const end = substitution(i + 1);
      if (typeof end === "string") return end;
      i = end;
    } else if (c === "<" && next === "<") {
      if (s[i + 2] === "<") i += 2; // a here-string
      else {
        const m = HEREDOC.exec(s.slice(i));
        if (!m) return "a heredoc delimiter that is not one plain or fully quoted word";
        heredocs.push({ delimiter: m[2] ?? m[3] ?? m[4], dash: m[1] === "-", quoted: m[4] === undefined });
        i += m[0].length - 1;
      }
    } else if (c === ">") {
      let j = i + 1;
      if (s[j] === ">" || s[j] === "|") j++;
      if (s[j] === "&") {
        // `>&2`: the parser skips the digits and starts a new word; bash reads `>&2x` as one word.
        for (j++; /[\d-]/.test(s[j] ?? ""); j++);
        if (j < s.length && !WORD_END.test(s[j])) return "text straight after a descriptor redirect";
      }
      i = j - 1;
    } else if (c === "#") {
      if (i === 0 || /[ \t\n]/.test(s[i - 1])) {
        const end = s.indexOf("\n", i);
        i = end < 0 ? s.length : end - 1;
      } else if (!braces) return "a # that is not at the start of a word";
    } else if (c === "}" && braces) braces--;
    else if (c === "\n" && heredocs.length) {
      let pos = i + 1;
      for (const doc of heredocs.splice(0)) {
        let found = -1;
        for (let line = pos; line <= s.length; ) {
          const eol = s.indexOf("\n", line);
          const text = s.slice(line, eol < 0 ? s.length : eol);
          if (text.trim() === doc.delimiter) {
            // bash wants the line to be exactly the delimiter (`<<-` strips leading tabs only).
            if ((doc.dash ? text.replace(/^\t+/, "") : text) !== doc.delimiter) return "a heredoc terminator with whitespace around it";
            found = line;
            pos = eol < 0 ? s.length : eol + 1;
            break;
          }
          if (eol < 0) break;
          line = eol + 1;
        }
        if (found < 0) return "a heredoc with no terminator";
        if (!doc.quoted) {
          const body = s.slice(i + 1, found);
          if (/`|\$\(/.test(body) && (/["'\\]/.test(body) || unmodelled(body.replace(/#/g, " "), depth + 1))) return "a heredoc body with substitutions the rules do not model";
        }
      }
      i = pos - 2;
      if (pos >= s.length) break;
    }
  }
  if (heredocs.length) return "a heredoc with no body";
  return parse(s).opaque ? "shell syntax the rules do not model" : undefined;
}

// ---- strict tokenizer ----

const BARE = /[A-Za-z0-9_@%+=:,.\/^~-]/;
const NULL_REDIRECT = /^(?:(?:[12]?>>?|&>) ?\/dev\/null|2>&1)(?=[ \t;|&]|$)/;

// The simple commands of a command line made only of plain words: letters, digits and
// `_@%+=:,./^~-`, single-quoted text, and double-quoted text without `$`, backtick, backslash or
// `!`. Commands are joined by `&&` or `;` (with `pipes`: also `|` and `||`). With
// `nullRedirects`, `>/dev/null`, `2>/dev/null` and `2>&1` are dropped. Anything else (variables,
// substitutions, globs, braces, other redirects, comments, newlines, assignments) gives
// undefined: the caller grants nothing.
export function strict(command: string, opts: { pipes?: boolean; nullRedirects?: boolean } = {}): string[][] | undefined {
  const cmds: string[][] = [];
  let argv: string[] = [];
  let word: string | undefined;
  const endWord = () => {
    if (word !== undefined) argv.push(word);
    word = undefined;
  };
  const endCmd = () => {
    endWord();
    if (!argv.length || argv[0].includes("=")) return false;
    cmds.push(argv);
    argv = [];
    return true;
  };
  const s = command;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === " " || c === "\t") endWord();
    else if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) return undefined;
      word = (word ?? "") + s.slice(i + 1, end);
      i = end;
    } else if (c === '"') {
      const end = s.indexOf('"', i + 1);
      if (end < 0 || /[$`\\!]/.test(s.slice(i + 1, end))) return undefined;
      word = (word ?? "") + s.slice(i + 1, end);
      i = end;
    } else if (c === ";" || c === "&" || c === "|") {
      const two = s[i + 1] === c;
      if (c === "&" && !two) {
        const m = opts.nullRedirects && word === undefined ? NULL_REDIRECT.exec(s.slice(i)) : null;
        if (!m) return undefined;
        i += m[0].length - 1;
        continue;
      }
      if (c === ";" && two) return undefined;
      if (c === "|" && !opts.pipes) return undefined;
      if (!endCmd()) return undefined;
      if (two) i++;
    } else if ((c === ">" || ((c === "1" || c === "2") && s[i + 1] === ">")) && opts.nullRedirects && word === undefined) {
      const m = NULL_REDIRECT.exec(s.slice(i));
      if (!m) return undefined;
      i += m[0].length - 1;
    } else if (BARE.test(c)) word = (word ?? "") + c;
    else return undefined;
  }
  endWord();
  // A trailing `;` is fine; a trailing `&&` or `|` is not.
  if (argv.length ? !endCmd() : !/;\s*$/.test(s) || !cmds.length) return undefined;
  return cmds;
}

export const tilde = (p: string) => (p === "~" || p.startsWith("~/") ? HOME + p.slice(1) : p);

// A tool call that is one plain command, optionally after `cd <dir>` and under `timeout <n>`.
export interface Single {
  dir: string;
  // The command without `timeout <n>`.
  argv: string[];
  // The texts a rules Matcher may be shown for it: as written, and without the wrapper.
  texts: string[];
}
export function single(command: string, cwd: string): Single | undefined {
  const cmds = strict(command);
  if (!cmds) return undefined;
  let dir = cwd;
  const rest: string[][] = [];
  for (const argv of cmds) {
    if (argv[0] !== "cd") rest.push(argv);
    else if (argv.length !== 2 || rest.length || argv[1].startsWith("-") || /^~[^/]/.test(argv[1])) return undefined;
    else dir = path.resolve(dir, tilde(argv[1]));
  }
  if (rest.length !== 1) return undefined;
  const full = rest[0];
  const argv = full[0] === "timeout" && /^\d+(\.\d+)?[smhd]?$/.test(full[1] ?? "") ? full.slice(2) : full;
  if (!argv.length) return undefined;
  return { dir, argv, texts: [...new Set([full.join(" "), argv.join(" ")])] };
}

// ---- git ----

// `-c` keys that change nothing git runs or connects to.
const GIT_C_OK = /^(user\.(name|email)|color\.[\w.]+|advice\.[\w.]+|core\.quotepath|init\.defaultBranch|commit\.gpgsign|log\.showSignature)=/;
const GIT_GLOBAL_FLAGS = new Set(["--no-pager", "-P", "--no-optional-locks", "--literal-pathspecs", "--no-replace-objects", "--version", "--help", "-h", "-v"]);
// Long options that make git run a program or write a file of the caller's choosing. Git
// accepts any unique prefix of a long option, so a prefix of three or more characters counts.
const GIT_PROGRAM_OPTIONS = ["--upload-pack", "--receive-pack", "--exec"];
export const abbreviates = (word: string, options: string[]) => {
  const name = word.split("=")[0];
  return name.length >= 3 && name.startsWith("--") && options.some((o) => o.startsWith(name));
};

export interface GitCall {
  // Values of -C, in order.
  dirs: string[];
  sub: string | undefined;
  rest: string[];
}

// Reads `git <global options> <subcommand> ...` from the word after `git`. A string is the
// reason it must ask: a global option that is not on the allowlist. (The rules skip one word
// per unknown option, so `git --namespace status push --force` reads as `git status` there.)
export function gitCall(words: string[]): GitCall | string {
  const dirs: string[] = [];
  let i = 0;
  for (; i < words.length && words[i].startsWith("-"); i++) {
    const w = words[i];
    if (w === "-C" && i + 1 < words.length) dirs.push(words[++i]);
    else if (w === "-c" && GIT_C_OK.test(words[i + 1] ?? "")) i++;
    else if (!GIT_GLOBAL_FLAGS.has(w)) return `git ${w === "-c" ? `-c ${words[i + 1] ?? ""}` : w} changes what git runs or reads`;
  }
  return { dirs, sub: words[i], rest: words.slice(i + 1) };
}

// Every `git` word in the command (after `sudo`, `xargs`, `env`, in a substitution, inside a
// quoted `sh -c` string) is read as a git call with the real words bash would pass.
export function gitProblem(command: string, depth = 0): string | undefined {
  if (depth > 3) return undefined;
  for (const { argv } of parse(command).cmds) {
    for (let i = 0; i < argv.length; i++) {
      if (path.basename(argv[i]) === "git") {
        const call = gitCall(argv.slice(i + 1));
        if (typeof call === "string") return call;
        const program = call.rest.find((w) => abbreviates(w, GIT_PROGRAM_OPTIONS));
        if (program) return `git ${call.sub} ${program} picks a program for git to run`;
      } else if (/\s/.test(argv[i]) && /\bgit\b/.test(argv[i])) {
        const inner = gitProblem(argv[i], depth + 1);
        if (inner) return inner;
      }
    }
  }
  return undefined;
}

// A user rule also sees a command with its program named by path (`/usr/bin/npm install`) as
// the bare name, and a git command without the allowed global options (`git --no-pager init x`
// as `git init x`).
export function alsoByName(m: Matcher): Matcher {
  return {
    source: m.source,
    test(text) {
      if (m.test(text)) return true;
      const words = text.split(" ");
      const name = path.basename(words[0]);
      if (name !== words[0] && m.test([name, ...words.slice(1)].join(" "))) return true;
      if (name !== "git") return false;
      const call = gitCall(words.slice(1));
      if (typeof call === "string") return false; // asks through gitProblem
      const plain = ["git", ...call.dirs.flatMap((d) => ["-C", d]), ...(call.sub ? [call.sub] : []), ...call.rest].join(" ");
      return plain !== text && m.test(plain);
    },
  };
}

// ---- per simple command ----

// Variables that change which program runs, what it loads or where its config comes from.
const ENV_DANGEROUS =
  /^(PATH|HOME|IFS|CDPATH|SHELL|ENV|BASH_ENV|BASH_FUNC.*|PROMPT_COMMAND|PS[0-4]|EDITOR|VISUAL|PAGER|BROWSER|TMPDIR|GIT_.*|SSH_.*|LD_.*|DYLD_.*|XDG_.*|PYTHON(PATH|STARTUP|HOME|USERBASE)|NODE_(OPTIONS|PATH)|PERL5(LIB|OPT)|RUBY(OPT|LIB)|GEM_(HOME|PATH)|GO(FLAGS|PATH|ROOT|BIN|PROXY|NOSUMDB|INSECURE|PRIVATE)|RUSTC.*|RUSTUP_.*|CARGO_(HOME|BUILD_.*|TARGET_.*_(RUNNER|LINKER)|REGISTR.*)|CC|CXX|LD|AR|MAKEFLAGS|npm_config_.*|NPM_CONFIG_.*|PIP_.*|UV_.*|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|MAVEN_OPTS|GRADLE_.*|OPENCODE.*|AUTOMODE_.*)$/;
// Variables that only change output or verbosity.
const ENV_HARMLESS =
  /^(NODE_ENV|CI|DEBUG|VERBOSE|FORCE_COLOR|NO_COLOR|CLICOLOR(_FORCE)?|TERM|COLORTERM|COLUMNS|LINES|LANG|LANGUAGE|LC_[A-Z]+|TZ|RUST_BACKTRACE|RUST_LOG|CARGO_TERM_[A-Z_]+|CARGO_INCREMENTAL|PYTHONUNBUFFERED|PYTHONDONTWRITEBYTECODE|PYTHONHASHSEED|PYTEST_ADDOPTS|LOG_LEVEL|PORT|HOST|TEST_[A-Z0-9_]+|GOMAXPROCS|JOBS|NINJA_STATUS)$/;
const ASSIGN = /^([A-Za-z_]\w*)\+?=/;
const DECLARERS = new Set(["export", "declare", "typeset", "readonly", "local"]);

const INSTALLERS: Record<string, Set<string>> = {
  pip: new Set(["install", "download", "wheel"]),
  uv: new Set(["add", "sync", "tool"]),
  cargo: new Set(["install", "binstall"]),
  go: new Set(["install", "get"]),
  gem: new Set(["install", "update"]),
};
INSTALLERS.pip3 = INSTALLERS.pip;
for (const pm of ["npm", "pnpm", "yarn", "bun"]) {
  INSTALLERS[pm] = new Set(["install", "i", "ci", "add", "update", "up", "upgrade", "dedupe", "rebuild", "link", "exec", "x", "dlx", "create", "init", "import", "install-test", "it", "install-ci-test", "cit"]);
}

// Commands that name a path without showing what is in it (as in the rules).
const NAMES_ONLY = new Set("ls stat test [ file du find readlink realpath basename dirname which echo printf rm rmdir unlink mkdir touch chmod chown chgrp setfacl tee truncate shred cd pushd".split(" "));
// Programs that show or copy what is in the files they are given.
const READERS = new Set(
  `cat bat head tail less more grep egrep fgrep rg ag ack sed awk gawk cut sort uniq tr diff cmp comm nl tac rev fold paste join
   strings xxd hexdump od base64 base32 jq yq zcat xzcat bzcat zstdcat cp mv ln rsync install tar zip gzip xz zstd dd openssl curl wget`.split(/\s+/),
);
const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh", "source", "."]);
const INTERPRETERS = new Set(["python", "python3", "node", "perl", "ruby", "php", "lua", "deno", "bun"]);

function globRegex(segment: string): RegExp {
  let re = "";
  for (let i = 0; i < segment.length; i++) {
    const c = segment[i];
    if (c === "*") re += "[^/]*";
    else if (c === "?") re += "[^/]";
    else if (c === "[") {
      const end = segment.indexOf("]", i + 2);
      if (end < 0) re += "\\[";
      else {
        const body = segment.slice(i + 1, end).replace(/\\/g, "\\\\").replace(/^[!^]/, "^");
        re += `[${body}]`;
        i = end;
      }
    } else re += c.replace(/[.+^${}()|\\\]]/g, "\\$&");
  }
  return new RegExp(`^${re}$`, "s");
}

// The files a word names once bash has expanded its braces and globs, or undefined when that
// cannot be known here (a variable, a substitution, a `{a..z}` range).
export function expandWord(word: string, cwd: string): string[] | undefined {
  if (/[$`]/.test(word)) return undefined;
  let alternatives = [word];
  for (let round = 0; round < 4; round++) {
    const out: string[] = [];
    for (const w of alternatives) {
      const m = /\{([^{}]*)\}/.exec(w);
      if (!m) out.push(w);
      else if (m[1].includes("..")) return undefined;
      else if (!m[1].includes(",")) out.push(w.replace(m[0], `\u0001${m[1]}\u0002`));
      else for (const part of m[1].split(",")) out.push(w.slice(0, m.index) + part + w.slice(m.index + m[0].length));
    }
    alternatives = out;
  }
  const results: string[] = [];
  for (const raw of alternatives) {
    const alt = raw.replace(/\u0001/g, "{").replace(/\u0002/g, "}");
    const absolute = path.resolve(cwd, tilde(alt));
    if (!/[*?[]/.test(alt)) {
      results.push(absolute);
      continue;
    }
    let dirs = ["/"];
    for (const segment of absolute.split("/").filter(Boolean)) {
      if (!/[*?[]/.test(segment)) {
        dirs = dirs.map((d) => path.join(d, segment));
        continue;
      }
      const re = globRegex(segment);
      const next: string[] = [];
      for (const d of dirs) {
        let names: string[];
        try {
          names = fs.readdirSync(d);
        } catch {
          continue;
        }
        // A leading dot is only matched by a pattern that starts with one.
        for (const n of names) if (re.test(n) && (segment.startsWith(".") || !n.startsWith("."))) next.push(path.join(d, n));
        if (next.length > 5000) return undefined;
      }
      dirs = next;
    }
    results.push(...dirs);
  }
  return results;
}

export interface TextContext {
  cwd: string;
  // False when the command changes directory, so a relative word cannot be placed.
  cwdKnown: boolean;
  scope: Scope;
  // Base names of files this session (or this command) wrote.
  written: () => Map<string, string>;
}

// One simple command as the rules show it to a Matcher: `raw` as written, `bare` without
// wrappers and assignments (empty when nothing is left to run).
export function textGuard(raw: string, bare: string, ctx: TextContext): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  const add = (action: "ask" | "classify", reason: string, files?: string[]) => void (verdict = stricter(verdict, { action, reason, ...(files ? { files } : {}) }));
  const rawWords = raw.split(" ").filter(Boolean);
  const words = bare.split(" ").filter(Boolean);
  const name = path.basename(words[0] ?? "");
  const args = words.slice(1);
  const operands = args.filter((a) => !a.startsWith("-"));

  // Printing the environment prints every secret in it.
  if (name === "printenv") add("ask", "printenv prints the environment");
  if (path.basename(rawWords[0] ?? "") === "env" && rawWords.slice(1).every((w) => w.startsWith("-") || ASSIGN.test(w))) add("ask", "env prints the environment");
  if ((DECLARERS.has(name) && !operands.length) || (name === "set" && !args.length)) add("ask", `${name} without a name prints every variable`);

  // Variables set for a command, or exported for the ones after it.
  const prefix = rawWords.slice(0, Math.max(0, rawWords.length - words.length));
  const declared = DECLARERS.has(name) ? args : [];
  // Only `export` and `declare -x` hand a new variable to the programs that follow.
  const exports = name === "export" || (DECLARERS.has(name) && args.some((a) => /^-[a-zA-Z]*x/.test(a)));
  for (const w of [...prefix, ...declared]) {
    const variable = ASSIGN.exec(w)?.[1] ?? (declared.includes(w) && /^[A-Za-z_]\w*$/.test(w) ? w : undefined);
    if (!variable) continue;
    if (ENV_DANGEROUS.test(variable)) add("ask", `sets ${variable}, which changes what programs run or load`);
    else if (!ENV_HARMLESS.test(variable) && ASSIGN.test(w) && (prefix.includes(w) || exports)) add("classify", `sets ${variable} for the programs it runs`);
  }
  if (!words.length) {
    // A command that only assigns: PATH and friends are exported already.
    for (const w of rawWords) {
      const variable = ASSIGN.exec(w)?.[1];
      if (variable && ENV_DANGEROUS.test(variable)) add("ask", `sets ${variable}, which changes what programs run or load`);
    }
    return verdict;
  }

  // Package installs run third-party install scripts.
  const pip = /^python3?$/.test(name) && args[0] === "-m" && args[1] === "pip";
  const manager = pip ? "pip" : name;
  const managerArgs = pip ? args.slice(2) : args;
  if (INSTALLERS[manager]) {
    const sub = managerArgs.find((a) => !a.startsWith("-"));
    if (managerArgs[0]?.startsWith("-") && sub && !/^(-v|-V|--version|-h|--help)$/.test(managerArgs[0])) add("ask", `${manager} with options before its subcommand`);
    else if (sub && INSTALLERS[manager].has(sub)) add("ask", `${manager} ${sub} installs packages, which runs their install scripts`);
    else if (manager === "uv" && sub === "pip" && managerArgs.some((a) => /^(install|sync)$/.test(a))) add("ask", "uv pip install installs packages, which runs their install scripts");
    else if (manager === "yarn" && !sub) add("ask", "yarn without a subcommand installs packages");
    else if (manager === "go" && sub === "run" && managerArgs.some((a) => a.includes("@"))) add("ask", "go run of a remote package downloads and runs it");
  }
  if (name === "npx" || name === "bunx" || name === "pnpx" || name === "uvx" || name === "pipx") add("ask", `${name} downloads and runs a package`);

  // Credential files named by a glob or by braces: the rules see the word before bash expands it.
  if (!NAMES_ONLY.has(name)) {
    for (const word of args) {
      if (word.startsWith("-") && !word.includes("=")) continue;
      const text = word.replace(/^-[^=]*=/, "").replace(/^@/, "");
      const dynamic = /[$`]/.test(text);
      if (!dynamic && !/[*?[{]/.test(text)) continue;
      const relative = !/^(\/|~\/|~$)/.test(text);
      const files = dynamic || (relative && !ctx.cwdKnown) ? undefined : expandWord(text, ctx.cwd);
      if (!files) {
        if (READERS.has(name)) add("classify", `${name} reads a file named at run time: ${word}`);
      }
      else {
        const secret = files.find((f) => readVerdict("read", f, ctx.scope));
        if (secret) add("ask", `${name} reads a credential file: ${word} matches ${secret}`);
      }
    }
  }

  // A file this session wrote is the agent's own code: the model sees it before it runs.
  const written = ctx.written();
  if (written.size && (SHELLS.has(name) || INTERPRETERS.has(name) || words[0].includes("/"))) {
    const files = words.map((w) => written.get(path.basename(w))).filter((f): f is string => !!f);
    if (files.length) add("classify", `runs ${[...new Set(files)].map((f) => path.basename(f)).join(", ")}, which this session wrote`, [...new Set(files)]);
  }
  return verdict;
}

// Collects every simple command the rules look at, without deciding anything: the rules call
// each `deny` Matcher with the command as written and without its wrappers.
export function observer(): { matcher: Matcher; pairs: () => [string, string][] } {
  const seen: string[] = [];
  return {
    matcher: {
      source: "(observer)",
      test(text) {
        seen.push(text);
        return false;
      },
    },
    // The rules test raw then bare for each command; a deny rule before this one cannot have
    // matched, or the verdict is a deny anyway.
    pairs: () => Array.from({ length: Math.floor(seen.length / 2) }, (_, i) => [seen[2 * i], seen[2 * i + 1]] as [string, string]),
  };
}

export function textGuards(pairs: [string, string][], ctx: TextContext): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  for (const [raw, bare] of pairs) verdict = stricter(verdict, textGuard(raw, bare, ctx));
  return verdict;
}
