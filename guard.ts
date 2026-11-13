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
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { bashVerdict, fileVerdict, parse, readVerdict, within, type Matcher, type Scope, type Simple } from "./rules.ts";
import { gitArgs, gitEnv } from "./sandbox.ts";

const HOME = os.homedir();

export interface GuardVerdict {
  action: "ask" | "classify";
  reason: string;
  // Files this session wrote that the command runs: shown to the model.
  files?: string[];
}

export const stricter = (a: GuardVerdict | undefined, b: GuardVerdict | undefined) => (!a ? b : !b ? a : a.action === "ask" ? a : b.action === "ask" ? b : a);

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

// Where bash ends the substitution that opens at `open`: a parenthesis inside quotes, a comment
// or a heredoc body does not count. -1 when it cannot be followed.
function closeBash(s: string, open: number): number {
  let depth = 0;
  let wordStart = true;
  const heredocs: { delimiter: string; dash: boolean }[] = [];
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    const startsWord: boolean = wordStart;
    wordStart = false;
    if (c === "\\") {
      // A backslash-newline is no character at all: what follows starts a word if this did.
      if (s[i + 1] === "\n") wordStart = startsWord;
      i++;
    } else if (c === "'") {
      i = s.indexOf("'", i + 1);
      if (i < 0) return -1;
    } else if (c === '"') {
      for (i++; i < s.length && s[i] !== '"'; i++) {
        if (s[i] === "\\") i++;
        else if (s[i] === "$" && s[i + 1] === "(") {
          i = closeBash(s, i + 1);
          if (i < 0) return -1;
        }
      }
      if (i >= s.length) return -1;
    } else if (c === "`") {
      i = s.indexOf("`", i + 1);
      if (i < 0) return -1;
    } else if (c === "#" && startsWord) {
      const end = s.indexOf("\n", i);
      if (end < 0) return -1;
      i = end - 1;
    } else if (c === "<" && s[i + 1] === "<" && s[i + 2] !== "<") {
      const m = /^<<(-?)[ \t]*(['"]?)([\w.-]+)\2/.exec(s.slice(i));
      if (!m) return -1;
      heredocs.push({ delimiter: m[3], dash: m[1] === "-" });
      i += m[0].length - 1;
    } else if (c === "\n") {
      wordStart = true;
      for (const doc of heredocs.splice(0)) {
        for (;;) {
          const eol = s.indexOf("\n", i + 1);
          if (eol < 0) return -1;
          const line = s.slice(i + 1, eol);
          i = eol;
          const text = doc.dash ? line.replace(/^\t+/, "") : line;
          if (text === doc.delimiter) break;
          // Inside a substitution bash ends a heredoc at any line that starts with the delimiter
          // and has a `)` later on it, and reads the rest of that line as code (round 4, finding
          // 1; bash 5.2 and 5.3). Such a line cannot be followed, whatever a version does with it.
          if (text.startsWith(doc.delimiter)) return -1;
        }
      }
    } else if (c === "(") {
      depth++;
      wordStart = true;
    } else if (c === ")") {
      if (--depth === 0) return i;
      wordStart = true;
    } else if (" \t;|&<>".includes(c)) wordStart = true;
  }
  return -1;
}

const WORD_END = /[ \t\n;|&)<>]/;
// What may start the next line after `&&\`, `||\` or `|\` and a newline (blanks aside): a
// character that begins a plain word for bash and for the parser alike and joins no operator.
const PLAIN_WORD_START = /^[A-Za-z0-9_.\/~-]$/;
const HEREDOC = /^<<(-?)[ \t]*(?:'([\w.-]+)'|"([\w.-]+)"|([\w.-]+))(?=[ \t\n;|&)<>]|$)/;
// The rules parse the string these are given as a command of its own.
const NESTED_SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh"]);
const CODE_FLAG = /^-[a-zA-Z]*c[a-zA-Z]*$/;
// Of those, the ones whose syntax this scanner follows. Any other shell reads its code its own
// way (zsh runs `{ a } always { b }`, glob qualifiers, `=cmd`), so code handed to one asks.
const BASH_LIKE = new Set(["bash", "sh", "dash"]);
const OTHER_SHELL = /^(?:r?zsh|r?ksh|ksh\d+|mksh|pdksh|oksh|loksh|lksh|ash|fish|csh|tcsh|yash|elvish|nu|xonsh|pwsh|powershell)(?:[-.\d].*)?$/;
// What may stand between a nested bash and its code: these short options and `-o` names change
// nothing about how the code is read. `-O`/`+O` (shopt), `-i` (rc files, aliases, history
// expansion), `-H`, `-o history`, `-o posix`, `-s` and the rest ask.
const SHELL_FLAG_LETTERS = /^[ceuxvlfnC]$/;
const SHELL_LONG_FLAGS = new Set(["--norc", "--noprofile", "--login"]);
const RUNS_ITS_WORDS = new Set(["nice", "ionice", "timeout", "command", "builtin", "nohup", "setsid", "stdbuf", "exec", "chrt", "taskset"]);
const PLAIN_SET_O = new Set(["errexit", "nounset", "pipefail", "xtrace", "verbose", "noglob", "noclobber", "errtrace", "functrace"]);
// Characters neither bash nor the parser may be trusted to read alike: control characters other
// than tab and newline (the parser's heredoc terminator regex has the `m` flag, so its `^` and
// `$` also match at a carriage return, U+2028 and U+2029; the guard's own markers are U+0001
// to U+0006).
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u2028\u2029]/;
// Builtins that can set a variable whose name the scanner does not see spelled out (through a
// brace, a glob, a quote inside the name, a nameref): with one of them in the command, no
// variable counts as holding an integer.
export const SETS_BY_NAME = /(?<![\w-])(?:declare|typeset|local|export|readonly|read|mapfile|readarray|getopts|coproc|eval|source|printf|wait|let|command|builtin|enable|alias|trap|unset)(?![\w-])/;
// Words after which the command's own name is still to come.
const BEFORE_COMMAND = new Set(["if", "then", "elif", "else", "do", "while", "until", "!", "time", "{", "}"]);
const RESERVED_WORDS = new Set(["if", "then", "elif", "else", "fi", "do", "done", "while", "until", "for", "case", "esac", "select", "function", "coproc", "in", "time", "!", "{", "}", "[[", "]]"]);
const BLOCK_OPENERS = new Set(["if", "while", "until", "for", "case", "select", "{", "function", "coproc"]);
const BLOCK_CLOSERS = new Set(["fi", "done", "esac", "}"]);
const ARITHMETIC_TESTS = new Set(["-eq", "-ne", "-lt", "-le", "-gt", "-ge"]);
const NOT_AN_INTEGER = "a variable in an arithmetic context that this command does not set to a plain integer (bash evaluates its value as code)";

// What the scanner knows about variables, for one shell: the names set to a plain integer so
// far, every place a name is mentioned in a way that cannot give it another value, and the
// names an arithmetic context relied on. Positions are offsets into `root`.
interface Variables {
  root: string;
  ints: Set<string>;
  accounted: Set<number>;
  uses: Set<string>;
  // A command whose name is not a plain word: it could be any builtin.
  opaqueCommand: boolean;
  // Every name arithmetic assigns, in this shell and the shells it starts (see `arithmetic`).
  assigned: Set<string>;
}
// Names bash never sets by itself: `_`, REPLY, OPTARG, BASH_REMATCH and the like are upper case
// or `_`.
const settable = (name: string) => /^[a-z][A-Za-z0-9_]*$/.test(name) && name !== "histchars";

// After the scan: every mention of a name that arithmetic relied on must be one the scanner
// accounted for (a plain integer assignment, a `$name`, another arithmetic context). Anything
// else (`read n`, `for n in`, `n+=x`, `declare -n r=n`, text in a string) could give it a value
// that is code. Quotes and backslashes are dropped first, so `r''ead a''b` is seen as `read ab`.
function mentionProblem(v: Variables): string | undefined {
  if (!v.uses.size) return undefined;
  let plain = "";
  const at: number[] = [];
  for (let i = 0; i < v.root.length; i++) {
    if ("'\"\\".includes(v.root[i])) continue;
    plain += v.root[i];
    at.push(i);
  }
  if (v.opaqueCommand || SETS_BY_NAME.test(plain) || /(?:^|[\s;&|(){}])\.[ \t]/.test(plain)) return "arithmetic on a variable in a command that could set it out of the scanner's sight (a builtin that sets variables by name, or a command name that is not a plain word)";
  for (const name of v.uses) {
    const mention = new RegExp(`(?<![A-Za-z0-9_])${name}(?![A-Za-z0-9_])`, "g");
    for (const m of v.root.matchAll(mention)) if (!v.accounted.has(m.index)) return `${name} is used in arithmetic and named elsewhere in the command, where it could be given text (bash evaluates a variable's value as code)`;
    for (const m of plain.matchAll(mention)) if (!v.accounted.has(at[m.index])) return `${name} is used in arithmetic and named elsewhere in the command, where it could be given text (bash evaluates a variable's value as code)`;
  }
  return undefined;
}
// Text the rules read as data and bash runs once it reaches an arithmetic context: a subscript
// that holds a substitution, quoted or escaped (`'a[$(id)]'`).
const PAYLOAD = /\[[^\]\n]*(?:\$\(|`)/;
const ESCAPED_PAYLOAD = /\[[^\]\n]*\\\$\\?\(/;
const PAYLOAD_REASON = "quoted text bash would run as a command in an arithmetic context (a subscript holding a substitution)";
// Inside a word, quoted braces and commas are kept apart from the ones bash expands.
const QUOTED: Record<string, string> = { "{": "\u0001", "}": "\u0002", ",": "\u0003" };
const OPAQUE = "\u0004";
const quotedText = (text: string) => text.replace(/[{},]/g, (c) => QUOTED[c]);

// The words bash makes of a word's braces, in bash's order and by bash's own steps (braces.c):
//
//   - The first `{` that opens a group is looked for from the left. `${` opens a parameter
//     expansion, not a group, and what stands inside it is passed over. `{}` where the word
//     begins is two plain characters (`find -exec`); anywhere else its `{` can open a group
//     (`x{},a}y` is `x}y` and `xay`).
//   - A group ends at the first `}` at its own level that comes after a comma or a `..` at that
//     level. A `}` before one is a plain character (`{a}b,c}` is `a}b` and `c`), and a `{` with
//     no such `}` opens nothing: the search goes on after it.
//   - A group with a comma is cut at its top-level commas and each piece is expanded on its
//     own. One without is a range (`{1..5}`, `{a..e}`, `{01..10..2}`).
//   - The text after the group is expanded on its own too, and every word of the group is set
//     before every word of that text. Nothing is read again once joined: `{{a},b},c}` is
//     `{a},c}` and `b,c}`, although the first of those holds a comma between braces. (The first
//     version here expanded the joined text again and printed `a}`, `c`, `b,c}`; found by the
//     round 4 cross-check.)
//
// Undefined when the words cannot be listed in full: more than BRACE_LIMIT of them, or a `..`
// form that is no plain range of numbers or letters, or whose numbers this reader cannot hold
// (bash has readings of its own for those: it leaves some as written and drops the braces of
// others). A caller that gets undefined must ask (round 4, finding 2: the old reading stopped
// after six rounds, or at a range, and handed back words that still held a group).
const BRACE_LIMIT = 2000;
// A word longer than this that holds a `{` is not expanded: the search below looks again from
// every `{` that opens nothing and goes one level down for every group, so its work and its
// depth grow with the length (a word of 16,000 groups overflowed the stack).
const BRACE_WORD_MAX = 4096;
export function braceWords(word: string): string[] | undefined {
  if (!word.includes("{")) return [word];
  if (word.length > BRACE_WORD_MAX) return undefined;
  // The first `{` at or after `from` that can open a group, as bash's reader finds it.
  const opening = (text: string, from: number): number => {
    let level = 0;
    for (let i = from; i < text.length; i++) {
      const c = text[i];
      if (c === "$" && text[i + 1] === "{") {
        level++;
        i++;
      } else if (c === "{" && level === 0) {
        if (i === 0 && text[1] === "}") continue;
        return i;
      } else if (c === "{") level++;
      else if (c === "}" && level > 0) level--;
    }
    return -1;
  };
  // Where the group that opens at `open` ends, with its top-level commas; undefined when it
  // does not end.
  const closing = (text: string, open: number): { close: number; commas: number[] } | undefined => {
    let level = 0;
    let marks = 0;
    const commas: number[] = [];
    for (let j = open + 1; j < text.length; j++) {
      const c = text[j];
      if (c === "$" && text[j + 1] === "{") {
        level++;
        j++;
      } else if (c === "}" && level === 0 && marks > 0) return { close: j, commas };
      else if (c === "{") level++;
      else if (c === "}" && level > 0) level--;
      else if (c === "," && level === 0) {
        marks++;
        commas.push(j);
      } else if (c === "." && text[j + 1] === "." && text[j + 2] !== "}" && level === 0) marks++;
    }
    return undefined;
  };
  const range = (inner: string): string[] | undefined => {
    const num = /^(-?\d+)\.\.(-?\d+)(?:\.\.(-?\d+))?$/.exec(inner);
    const alpha = /^([A-Za-z])\.\.([A-Za-z])(?:\.\.(-?\d+))?$/.exec(inner);
    // Letters of one case only: between `Z` and `a` lie characters bash has rules of its own for.
    if (!num && !(alpha && /[a-z]/.test(alpha[1]) === /[a-z]/.test(alpha[2]))) return undefined;
    const from = num ? Number(num[1]) : alpha![1].charCodeAt(0);
    const to = num ? Number(num[2]) : alpha![2].charCodeAt(0);
    const step = Math.abs(Number((num ?? alpha)![3] ?? 1)) || 1;
    // A step too long for bash's own integer is no range to it: the word stays as written
    // (`{a..c..99999999999999999999}`). Where that line lies is bash's business; a number this
    // reader cannot hold exactly is not listed.
    if (!Number.isSafeInteger(from) || !Number.isSafeInteger(to) || !Number.isSafeInteger(step) || Math.abs(to - from) / step > BRACE_LIMIT) return undefined;
    // bash pads with zeros to the longer of the two when either starts with one.
    const padded = (n: string) => /^-?0\d/.test(n);
    const width = num && (padded(num[1]) || padded(num[2])) ? Math.max(num[1].length, num[2].length) : 0;
    const out: string[] = [];
    for (let v = from; from <= to ? v <= to : v >= to; v += from <= to ? step : -step) {
      out.push(num ? (v < 0 ? "-" + String(-v).padStart(Math.max(0, width - 1), "0") : String(v).padStart(width, "0")) : String.fromCharCode(v));
    }
    return out;
  };
  // Every call makes at least one word of what it is given, no more than BRACE_LIMIT are ever
  // held, and the word is no longer than BRACE_WORD_MAX: that bounds the work and the depth.
  const expand = (text: string): string[] | undefined => {
    for (let open = opening(text, 0); open >= 0; open = opening(text, open + 1)) {
      const group = closing(text, open);
      if (!group) continue;
      const inner = text.slice(open + 1, group.close);
      let made: string[] = [];
      if (group.commas.length) {
        const cuts = [open, ...group.commas, group.close];
        for (let n = 0; n + 1 < cuts.length; n++) {
          const piece = expand(text.slice(cuts[n] + 1, cuts[n + 1]));
          if (!piece) return undefined;
          made.push(...piece);
          if (made.length > BRACE_LIMIT) return undefined;
        }
      } else {
        // A `..` at the group's level, and a comma (if any) only inside a nested group.
        const listed = inner.includes(",") ? undefined : range(inner);
        if (!listed) return undefined;
        made = listed;
      }
      const after = expand(text.slice(group.close + 1));
      if (!after || made.length * after.length > BRACE_LIMIT) return undefined;
      const before = text.slice(0, open);
      return made.flatMap((m) => after.map((a) => before + m + a));
    }
    return [text];
  };
  return expand(word);
}

// A brace expansion that makes words the rules never saw as such: an option (`curl {-d,@f}`,
// `tar -{-to-command=x}`), an absolute path or a remote (`{/etc,x}`, `{host:dir,}`), a way up
// (`a/{../..,b}`). `--exclude={a,b}` and `src/{a,b}.ts` are what braces are for. A word whose
// braces cannot be expanded in full asks: nothing can be said about the words it makes.
function braceProblem(text: string): string | undefined {
  const first = text.indexOf("{");
  const prefix = text.slice(0, first);
  const words = braceWords(text);
  const asked = "a brace expansion that makes an option, an absolute path or a remote";
  if (!words) return "a brace expansion too large or too unusual to list the words it makes";
  if (/^--?[\w-]+=/.test(prefix)) return undefined; // a value: every word keeps the option in front
  if (words.length === 1 && words[0] === text) return undefined;
  for (const w of words) {
    if (w.startsWith("-")) return asked;
    if (!prefix && (/^[\/~@]/.test(w) || /^[\w.@-]+:/.test(w))) return asked;
    if (w.split("/").includes("..") && !text.replace(/\{[^{}]*\}/g, "").split("/").includes("..")) return asked;
  }
  return undefined;
}

// The strings a command hands to a nested shell, as the rules find them (rules.ts parses the
// word after `sh -c` and the words after `eval`): looked for after any word, so wrappers such as
// `sudo`, `timeout 5`, `xargs` and `find -exec` are covered without listing them.
export function nestedBodies(cmds: Simple[]): string[] {
  const out: string[] = [];
  for (const { argv } of cmds) {
    for (let i = 0; i < argv.length; i++) {
      const name = path.basename(argv[i]);
      if (name === "eval") {
        if (i + 1 < argv.length) out.push(argv.slice(i + 1).join(" "));
        break;
      }
      if (!NESTED_SHELLS.has(name)) continue;
      for (let j = i + 1; j + 1 < argv.length; j++) if (CODE_FLAG.test(argv[j])) out.push(argv[j + 1]);
    }
  }
  return out;
}

// Options and shells that change how the code after them is read, per simple command as the
// parser lists it. `shopt` and `bash -O` can turn on extglob, where `@(a| #)` is one word;
// `set -H` with `-o history` turns on history expansion, which pastes earlier text into later
// lines; `set -k` makes `ls NAME=value` an assignment. A shell that is not bash, sh or dash
// reads the code it is handed in its own way.
function shellProblem(cmds: Simple[]): string | undefined {
  for (const { argv } of cmds) {
    const at = new Set(programs(argv));
    // Round 4, finding 11: the tests below that look at every word are for a wrapper the
    // traversal does not know (`watch zsh -c ls`, `flock x bash -- -c`). Behind a program that
    // only prints or searches for its words, a word that is no program position is data
    // (`rg fish -c src`, `echo zsh -c ls`, `echo bash -- -x`).
    const data = wordsAreData(argv);
    for (let i = 0; i < argv.length; i++) {
      if (data >= 0 && i > data && !at.has(i)) continue;
      const name = path.basename(argv[i]);
      const rest = argv.slice(i + 1);
      if (OTHER_SHELL.test(name) && rest.some((w) => CODE_FLAG.test(w))) return `a command for ${name}, which does not read it the way bash does`;
      // The rules drop `NAME=value` after any wrapper; only `env` takes it as an assignment.
      if (at.has(i) && RUNS_ITS_WORDS.has(name)) {
        const program = rest.find((w) => !/^(-.*|\d+(\.\d+)?[smhd]?)$/.test(w));
        if (program !== undefined && /^[A-Za-z_]\w*=/.test(program)) return `${name} ${program}: a program named like an assignment, which the rules drop`;
      }
      if (at.has(i) && name === "shopt") return "shopt, which changes how bash reads the rest of the command";
      // Builtins that change what a later word runs (round 4, finding 14): an alias is expanded
      // by dash, and by bash in posix mode (the `sh` the plugin wraps), in a shell that is not
      // interactive; `enable -n` and `enable -f` swap a builtin for a program or a loaded object;
      // `hash -p` names the file a later command word runs.
      if (at.has(i) && name === "alias") return "alias, which changes what a later word of the command runs";
      if (at.has(i) && name === "enable") return "enable, which turns a builtin off or loads one from a file, so a later word runs something else";
      if (at.has(i) && name === "hash" && rest.some((w) => /^-[a-zA-Z]*p/.test(w))) return "hash -p, which names the file a later word of the command runs";
      if (at.has(i) && name === "set") {
        const found = optionsProblem(rest, false);
        if (found) return `set ${found}, which changes how bash reads the rest of the command`;
      }
      if (BASH_LIKE.has(name)) {
        const found = optionsProblem(rest, true);
        if (found === "-O") return `${name} -O, which changes how the shell reads its code`;
        // The rules take the word after the first `-c` as the code; bash takes the first word
        // that is not an option, and runs it as a script when no `-c` came before it.
        const code = rest.findIndex((w) => /^-[a-zA-Z]*c$/.test(w));
        const operand = rest.findIndex((w, j) => !/^[-+]/.test(w) && !/^[-+][a-zA-Z]*o$/.test(rest[j - 1] ?? ""));
        const computed = code < 0 ? undefined : rest.slice(0, code).find((w) => /[$`]/.test(w));
        // After `--` or a lone `-` the shell reads no more options: the next word is the script,
        // whatever it is spelled, and the words after it are the script's. `bash -- -c ls` runs a
        // file named `-c` and the rules, which look for a `-c` anywhere, judge `ls` (found by the
        // round 4 variant check; it was so before round 4). So a word shaped like an option
        // straight after the end of the options asks.
        const end = rest.findIndex((w, j) => (w === "--" || w === "-") && rest.slice(0, j).every((v, k) => /^[-+]/.test(v) || /^[-+][a-zA-Z]*o$/.test(rest[k - 1] ?? "")));
        if (end >= 0 && /^[-+]/.test(rest[end + 1] ?? "")) return `${name} ${rest[end]} ${rest[end + 1]}: after ${rest[end]} the shell takes the next word for a script, whatever it is spelled`;
        if (code >= 0 && (found ?? computed)) return `${name} ${found ?? computed} before its code, which changes how the shell reads it`;
        // Round 4, finding 3: the rules allow a shell whose first argument is `-n` without
        // reading its code or its script, and any option the guard does not know to be harmless
        // can undo that (`+n`, `+o noexec`, `-i`: an interactive shell ignores `-n`), as it can
        // move the word the rules take for the script (`--rcfile x script`). So such an option
        // asks with or without a `-c`, wherever the shell is the program that runs.
        if (at.has(i) && found) return `${name} ${found}, which changes how the shell reads or runs what it is given`;
        // The rules find the code only after a cluster that ends in `c` (`-c`, `-ec`). bash and
        // dash take it after any cluster that holds a `c` (`-ce`, `-cx`): there the rules read
        // the code as the name of a script and never judge it (found by the round 4 cross-check).
        const cluster = rest.find((w, j) => (operand < 0 || j < operand) && /^-[a-zA-Z]*c[a-zA-Z]+$/.test(w));
        if (cluster !== undefined) return `${name} ${cluster}: a -c inside a cluster of options, where the rules do not find the code`;
        // Round 4, finding 13: bash takes the first word after `-c` that is no option as the
        // code (`bash -c -- '<cmd>'`, `bash -c -x '<cmd>'`); the rules take the word after `-c`.
        const after = code < 0 ? undefined : rest[code + 1];
        if (after !== undefined && /^[-+]/.test(after)) return `${name} ${rest[code]} ${after}: an option between -c and the code, where the rules take the option for the code`;
        if (at.has(i) && code >= 0 && operand >= 0 && operand < code) return `${name} given a script and a -c: bash runs the script`;
      }
    }
  }
  return undefined;
}

// Programs whose operands are only text to print or to search for: none of them runs a word it
// is given. (`find`, `git`, `tar`, `rsync`, `ag` and `ack` can; `rg --pre` and `--hostname-bin`
// name a program in one word and hand it no code.)
const PRINTS_OR_SEARCHES = new Set(["echo", "printf", "grep", "egrep", "fgrep", "rg"]);
// The index of the program a simple command runs when that program only prints or searches for
// the words after it, or -1: the traversal reads the command without a problem, the program is
// named bare or at a system path (a `./echo` is anyone's program), and the rules judge the same
// word.
function wordsAreData(argv: string[]): number {
  if (traversalProblem(argv)) return -1;
  const main = chainOf(argv).at(-1);
  if (main === undefined) return -1;
  const word = argv[main];
  if (!PRINTS_OR_SEARCHES.has(path.basename(word)) || !/^(?:\/usr\/bin\/|\/bin\/)?[a-z]+$/.test(word)) return -1;
  return main;
}

// The first option among the leading words of `set` or of a shell that is not known to leave
// the reading of code alone; "-O" for a shopt option wherever it stands in a cluster.
function optionsProblem(words: string[], shell: boolean): string | undefined {
  let odd: string | undefined;
  // `set $x` sets whatever options the variable holds; after `--` the words are only arguments.
  const end = words.indexOf("--");
  if (!shell) odd = (end < 0 ? words : words.slice(0, end)).find((w) => /[$`]/.test(w));
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (!/^[-+]/.test(w) || w === "--" || w === "-") break;
    if (/[$`*?[{]/.test(w)) return w;
    // A shell's `+` option turns an option off again: `bash -n +n -c '<cmd>'` runs `<cmd>`,
    // where the rules stop reading at the `-n` (round 4, finding 3).
    if (shell && w.startsWith("+")) return w;
    if (w.startsWith("--")) {
      if (!shell || !SHELL_LONG_FLAGS.has(w)) odd ??= w;
      continue;
    }
    for (const letter of w.slice(1)) {
      if (letter === "O" && shell) return "-O";
      if (letter === "o") {
        const option = words[++i];
        // `set -o` alone prints the options.
        if (option !== undefined && !PLAIN_SET_O.has(option)) odd ??= `${w[0]}o ${option}`;
      } else if (shell ? !SHELL_FLAG_LETTERS.test(letter) : "Hk".includes(letter)) odd ??= w;
    }
  }
  return odd;
}

// Shell syntax that bash and the rules' parser read differently, or undefined. The parser knows
// words, quotes, `$(...)`, backticks, redirects, heredocs and comments; it has no `$'...'`, no
// `${...}`, no arithmetic, no brace expansion, no `[[ ]]` and no extglob, and it reads their
// insides as ordinary command text. So a `#` there starts a comment for the parser only, a `<<`
// a heredoc, a quote a string, and bash runs what the parser skipped.
//
// The scanner admits; it does not exclude. It follows both readings character by character,
// keeps the parser's "at the start of a word" state exactly, and passes a character only where
// it can name what it means to bash and to the parser alike:
//
//   - A control character other than tab and newline asks anywhere, as do U+2028 and U+2029.
//   - A backslash-newline passes only straight after a blank, between words (`cmd \` then
//     `--flag` on the next line, `a && \` then `b`), and straight after a complete `&&`, `||` or
//     `|` when, past the newline and any blanks, the next character starts a plain word: a
//     letter, a digit or one of `_./~-` (`a &&\` then `b`, `ls |\` then `  grep x`). There both
//     read a new command that starts with that word. Bash removes the pair before it forms any
//     token, the parser merely skips two characters, so everywhere else it asks: after `$`, `<`,
//     `>`, `(`, `;`, a single `&` or `|&`; before an operator character, a quote, `#`, `(`, `{`,
//     `$`, a backslash, a newline or the end; inside a word, double quotes, backticks, `${...}`,
//     arithmetic, a heredoc delimiter and an unquoted heredoc body (where it also joins the line
//     that ends the heredoc).
//   - `${...}` and arithmetic pass in plain forms only. In arithmetic, a subscript, a substring
//     offset and an arithmetic test of `[[ ]]`, bash evaluates a variable's value as code, so a
//     name passes only when this command sets it to a plain integer before the use (`i=0`,
//     `i=$((i+1))`, the counter of `for ((i=0; ...))`), at the top level of the shell that uses
//     it, and names it nowhere else in a way that could give it text (see mentionProblem).
//     `>&` and `<&` are not arithmetic and ask there, as does a command substitution.
//   - A `(` straight after `@`, `!`, `+`, `*` or `?` in a word asks (with extglob on, bash
//     reads it to the matching `)` as one word), and so does any parenthesis, `;`, single `|`
//     or `&`, or newline inside `[[ ]]`, where extglob is always on and a regex may hold
//     parentheses. `shopt`, `bash -O`, `set -H` and their like ask as well (shellProblem).
//   - A word that holds both an expansion and a brace expansion asks: bash expands the braces
//     first, so `$e{-delete,}` is an option once the empty `$e` is gone.
//   - A comment that runs to the end of a `$(...)` body asks: for bash it hides the `)`.
//   - Where a command begins, a quoted or escaped word that reads as `NAME=value` or as a
//     reserved word asks (bash runs it as a program; the rules drop it), and so does a
//     `NAME=value` after a wrapper other than `env` (`nice x=/a` runs the file `x=/a`).
//   - A number or `{name}` straight before `<`, a number before `&>`, a backslash at the very
//     end and a space that is not ASCII outside quotes ask: bash and the parser make different
//     words of them.
//
// It also runs on every string the rules parse as a command of its own (`sh -c '...'`, `eval
// ...`), asks when such a string is not literal, and asks when the nested shell is not bash, sh
// or dash.
// `assigned` collects every name arithmetic assigns (arithmeticAssignments judges them).
export function unmodelled(s: string, depth = 0, within?: { variables: Variables; offset: number; kind: "paren" | "tick" }, assigned = new Set<string>()): string | undefined {
  if (depth > 6) return "deeply nested substitutions";
  if (CONTROL.test(s)) return "a control character (a carriage return, an escape or the like) or a Unicode line separator";
  if (ESCAPED_PAYLOAD.test(s)) return PAYLOAD_REASON;
  // A substitution shares its shell's variables; a nested shell and the command itself start anew.
  const variables = within?.variables ?? { root: s, ints: new Set<string>(), accounted: new Set<number>(), uses: new Set<string>(), opaqueCommand: false, assigned };
  const found = scan(s, depth, variables, within?.offset ?? 0, within?.kind);
  if (found) return found;
  if (!within) {
    const mention = mentionProblem(variables);
    if (mention) return mention;
  }
  const parsed = parse(s);
  if (parsed.opaque) return "shell syntax the rules do not model";
  const shell = shellProblem(parsed.cmds);
  if (shell) return shell;
  for (const body of nestedBodies(parsed.cmds)) {
    const inner = unmodelled(body, depth + 1, undefined, variables.assigned);
    if (inner) return `${inner}, in a command a nested shell runs`;
  }
  return undefined;
}

function scan(s: string, depth: number, variables: Variables, offset: number, kind: "paren" | "tick" | undefined): string | undefined {
  const heredocs: { delimiter: string; dash: boolean; quoted: boolean }[] = [];
  // The parser's state: true while it has no word in progress (its `hasWord` is false).
  let atStart = true;
  // The word in progress: where it began, its text without quotes, whether the outer shell
  // expands something in it, and whether it holds a backslash that bash keeps and the parser drops.
  let begin = 0;
  let text = "";
  let expands = false;
  let kept = false;
  let braces = false;
  // Per simple command: 1 once a shell is named, 2 once the words that follow are its code.
  let nested = 0;
  // The last blank the main loop read, and the last character of the last `&&`, `||` or `|`
  // (not `|&`): a backslash-newline passes only straight after one of them.
  let blankAt = -2;
  let joinAt = -2;
  // Inside `[[ ... ]]`, with its words so far.
  let cond = false;
  let condWords: { raw: string; at: number }[] = [];
  // Where an assignment is: inside how many `( )`, and how many compound commands (`if`, a
  // loop, `{ }`). Only one that every run of the command reaches sets a variable for certain.
  let parens = 0;
  let blocks = 0;
  // Per simple command: its words as written, what joined it to the one before, the names its
  // words set to a plain integer, whether it is made of such words only, and whether its own
  // name has been read.
  let words: string[] = [];
  let joinedBy = "";
  let pending: string[] = [];
  let onlyIntegers = true;
  let named = false;
  // Per simple command: an assignment or a redirection came before its name. bash reserves no
  // word after one (`x= {` and `>f {` run a program called `{`); the parser still drops its
  // keywords there. `target`: the next word is the target of a redirection, not a command word.
  let prefixed = false;
  let target = false;
  // `name=$((...))` in progress: the word began with `name=` and its value is the arithmetic
  // that ends at `end`.
  let arithmeticValue: { name: string; begin: number; end: number } | undefined;

  const account = (i: number) => void variables.accounted.add(offset + i);
  // A name whose value an arithmetic context evaluates, at `i`: it must hold an integer.
  const integer = (name: string, i: number): string | undefined => {
    account(i);
    if (!variables.ints.has(name)) return `${NOT_AN_INTEGER}: ${name}`;
    variables.uses.add(name);
    return undefined;
  };
  // A subscript or a substring offset from `from`: a number, or a name that holds an integer.
  const index = (expr: string, from: number): string | undefined => {
    const m = /^(-?\d+)$|^(\$?)([A-Za-z_]\w*)$|^\$\{([A-Za-z_]\w*)\}$/.exec(expr);
    if (!m) return "an array subscript or offset that is not a number or a plain variable, which bash evaluates as arithmetic";
    if (m[1] !== undefined) return undefined;
    return m[3] !== undefined ? integer(m[3], from + m[2].length) : integer(m[4], from + 2);
  };
  // This command runs whenever the tool call does, in the shell whose variables these are.
  const always = (before: string) => !kind && parens === 0 && (before === "" || before === ";" || before === "\n" || before === "&");

  const start = (i: number) => {
    if (!atStart) return;
    atStart = false;
    begin = i;
    text = "";
    expands = kept = braces = false;
  };
  const endWord = (end: number): string | undefined => {
    if (atStart) return undefined;
    atStart = true;
    const raw = s.slice(begin, end);
    const plain = text.replace(/[\u0001-\u0003]/g, "?");
    if (nested === 2) {
      if (expands) return "a command for a nested shell built from a variable or a substitution";
      if (kept) return "a command for a nested shell with a backslash in double quotes";
    } else if (plain === "eval") nested = 2;
    else if (NESTED_SHELLS.has(path.basename(plain)) || OTHER_SHELL.test(path.basename(plain))) nested = 1;
    else if (nested === 1 && CODE_FLAG.test(plain)) nested = 2;

    // `[[ ... ]]`: bash reads it with rules of its own, and its words name no command.
    const inside = cond;
    if (raw === "[[") {
      cond = true;
      condWords = [];
    } else if (cond && raw === "]]") {
      cond = false;
      if (condWords.some((w) => w.raw === "-v" || w.raw === "-R")) return "[[ -v ]], which evaluates a subscript as arithmetic";
      if (condWords.some((w) => ARITHMETIC_TESTS.has(w.raw))) {
        // Both sides of -eq and the like are evaluated as arithmetic.
        for (const w of condWords) {
          if (ARITHMETIC_TESTS.has(w.raw) || w.raw === "!" || /^-?\d+$/.test(w.raw) || /^"?\$[#?]"?$/.test(w.raw)) continue;
          const m = /^(?:()([A-Za-z_]\w*)|("?\$)([A-Za-z_]\w*)"?|("?\$\{)([A-Za-z_]\w*)\}"?)$/.exec(w.raw);
          if (!m) return "an arithmetic test in [[ ]] on something other than a number or a variable that holds one";
          const found = integer(m[2] ?? m[4] ?? m[6], w.at + (m[1] ?? m[3] ?? m[5]).length);
          if (found) return found;
        }
      }
    } else if (cond) condWords.push({ raw, at: begin });

    // A redirection's target is no command word: it neither names the command nor is reserved.
    const isTarget = target;
    target = false;
    // A reserved word bash runs as a program or passes on, where the parser reads syntax: after an
    // assignment or a redirection, where bash reserves nothing (round 3, the scanner leftover).
    if (!isTarget && !named && !inside && prefixed && RESERVED_WORDS.has(raw)) return "a reserved word after an assignment or a redirection, which bash runs as a program and the rules read as syntax";
    // Which compound command this word is in, and whether it is the command's own name.
    const first = words.length === 0;
    if (BLOCK_OPENERS.has(raw)) blocks++;
    else if (first && BLOCK_CLOSERS.has(raw)) blocks = Math.max(0, blocks - 1);
    const assignment = /^[A-Za-z_]\w*(?:\[.*\])?\+?=/s.test(raw);
    // Where a command begins, bash takes `NAME=` and its reserved words only as written:
    // `"x=/a"` runs the file `x=/a` and `\\{` a program called `{`, while the rules read the
    // text without its quotes, as an assignment and a keyword.
    if (!named && !inside && raw !== plain && (RESERVED_WORDS.has(text.replace(/\u0001/g, "{").replace(/\u0002/g, "}")) || (/^[A-Za-z_]\w*=/.test(plain) && !/^[A-Za-z_]\w*=/.test(raw)))) return "a quoted word that the rules read as an assignment or a keyword and bash runs as a command";
    if (!named && !inside && assignment && !isTarget) prefixed = true;
    if (!named && !inside && !assignment && !isTarget && !BEFORE_COMMAND.has(raw)) {
      named = true;
      if (!/^(?:[A-Za-z0-9_.\/+:@%~-]+|\[|\[\[)$/.test(raw)) variables.opaqueCommand = true;
    }
    words.push(raw);

    // What the word sets: `name=5` and `name=$((...))` give an integer; a subscript is arithmetic.
    const literal = /^([A-Za-z_]\w*)=-?\d+$/.exec(raw);
    const computed = arithmeticValue && arithmeticValue.begin === begin && arithmeticValue.end === end - 1 ? arithmeticValue.name : undefined;
    arithmeticValue = undefined;
    const name = literal?.[1] ?? computed;
    if (name !== undefined) {
      account(begin);
      if (settable(name)) pending.push(name);
    } else onlyIntegers = false;
    const subscript = /^(?:[A-Za-z_]\w*)?\[(.*)\]\+?=/s.exec(raw);
    if (subscript) {
      const found = index(subscript[1], begin + raw.indexOf("[") + 1);
      if (found) return found;
    }

    if (!braces) return undefined;
    // Bash expands braces before variables, so the words it makes are not the ones seen here.
    const made = braceWords(text);
    if (expands && (!made || made.length !== 1 || made[0] !== text)) return "a word with both an expansion and a brace expansion, which bash expands braces-first";
    return braceProblem(text);
  };
  // `joins` is what ends the command: `;`, a newline, `&&`, `||`, `|`, `&`, a parenthesis.
  const endCommand = (end: number, joins: string): string | undefined => {
    const found = endWord(end);
    nested = 0;
    if (words.length) {
      if (onlyIntegers && blocks === 0 && always(joinedBy) && (joins === ";" || joins === "\n" || joins === "" || joins === "&&" || joins === "||")) for (const name of pending) variables.ints.add(name);
    }
    joinedBy = joins;
    words = [];
    pending = [];
    onlyIntegers = true;
    named = false;
    prefixed = target = false;
    return found;
  };

  const substitution = (open: number): number | string => {
    const end = closeNaive(s, open);
    if (end < 0 || end !== closeBash(s, open)) return "a substitution with parentheses in quotes, a comment or a heredoc, or unbalanced ones";
    return unmodelled(s.slice(open + 1, end), depth + 1, { variables, offset: offset + open + 1, kind: "paren" }) ?? end;
  };
  const backticks = (open: number): number | string => {
    const end = s.indexOf("`", open + 1);
    if (end < 0) return "an unterminated backtick";
    const body = s.slice(open + 1, end);
    if (body.includes("\\")) return "a backslash inside backticks";
    return unmodelled(body, depth + 1, { variables, offset: offset + open + 1, kind: "tick" }) ?? end;
  };
  // `$(`, `${`, `$((`, `$[` and what cannot follow a `$` here, from the `$` at `i`. Returns the
  // index of the last character, or -1 when the `$` is an ordinary one.
  const dollar = (i: number, quoted: boolean): number | string => {
    const next = s[i + 1];
    if (next === "{") return brace(i, quoted);
    if (next === "(") return s[i + 2] === "(" ? arithmetic(i + 3, false, false) : substitution(i + 1);
    if (next === "[") return "the old $[...] arithmetic";
    return -1;
  };

  // Arithmetic from just after `((`: the index of the closing `))`. The parser reads the inside
  // as commands, so a `#` hides the rest of the line from it, `<<` opens a heredoc and `>&2`
  // swallows the digits. Bash evaluates the value of every variable named here as arithmetic
  // again, so a name must hold an integer; `name = ...` gives it one (kept only with `sets`,
  // when the arithmetic is a command every run reaches, such as the head of a `for ((`).
  // Every name the arithmetic assigns (`=`, a compound assignment, `++` or `--` on either side)
  // is an assignment to that variable (round 4, B3b: `(( PATH=1 )); ls` looks `ls` up in a
  // directory called 1, and the printer erases arithmetic from the text the guards read): a name
  // that changes what programs run or load asks here, as `PATH=1` does, and every one is kept
  // in `variables.assigned` for arithmeticAssignments (a name the environment exports).
  const ASSIGNS_AFTER = /^[ \t]*(?:=(?!=)|(?:[-+*\/%&^|]|<<|>>)=|\+\+|--)/;
  const ASSIGNS_BEFORE = /(?:\+\+|--)[ \t]*$/;
  const arithmetic = (from: number, semicolons: boolean, sets: boolean): number | string => {
    let open = 0;
    let targets: string[] = [];
    const settle = () => {
      if (sets) for (const name of targets) variables.ints.add(name);
      targets = [];
    };
    for (let i = from; i < s.length; i++) {
      const c = s[i];
      const next = s[i + 1] ?? "";
      if (c === ")") {
        if (open > 0) open--;
        else if (next !== ")") return "arithmetic with unbalanced parentheses";
        else {
          settle();
          return i + 1;
        }
      } else if (c === "(") open++;
      else if (/\d/.test(c)) i += /^\d[\w#@]*/.exec(s.slice(i, i + 256))![0].length - 1; // 10, 0x1f, 16#ff
      else if (/[A-Za-z_]/.test(c)) {
        const name = /^[A-Za-z_]\w*/.exec(s.slice(i, i + 256))![0];
        if (name.length === 256) return "a very long name inside arithmetic";
        if (ASSIGNS_AFTER.test(s.slice(i + name.length, i + name.length + 64)) || ASSIGNS_BEFORE.test(s.slice(Math.max(from, i - 64), i))) {
          variables.assigned.add(name);
          if (ENV_DANGEROUS.test(name)) return `arithmetic that ${dangerous(name)}`;
        }
        const assigned = /^[ \t]*=(?!=)/.test(s.slice(i + name.length, i + name.length + 64));
        if (assigned) {
          account(i);
          if (settable(name)) targets.push(name);
        } else {
          const found = integer(name, i);
          if (found) return found;
        }
        i += name.length - 1;
      } else if (c === "$") {
        const braced = /^\$\{(#?)([A-Za-z_]\w*)(\[[@*]\])?\}/.exec(s.slice(i, i + 256));
        const bare = /^\$([A-Za-z_]\w*)/.exec(s.slice(i, i + 256));
        if (next === "(" && s[i + 2] === "(") {
          const end = arithmetic(i + 3, false, false);
          if (typeof end === "string") return end;
          i = end;
        } else if (next === "(") return "a command substitution inside arithmetic, whose output bash evaluates as code";
        else if ("#?$!".includes(next) && next) i++; // a number
        else if (s.startsWith("${#}", i)) i += 3;
        else if (braced?.[1]) {
          account(i + 3);
          i += braced[0].length - 1; // a length
        } else if (braced && !braced[3]) {
          const found = integer(braced[2], i + 2);
          if (found) return found;
          i += braced[0].length - 1;
        } else if (bare) {
          const found = integer(bare[1], i + 1);
          if (found) return found;
          i += bare[0].length - 1;
        } else return "an expansion inside arithmetic that is not a plain variable holding an integer";
      } else if (c === "<" && next === "<") return "<< inside arithmetic, which the rules read as a heredoc";
      else if (((c === "<" || c === ">") && next === "&") || (c === "&" && next === ">")) return "a redirect inside arithmetic";
      else if (c === "," || (c === ";" && semicolons)) settle();
      else if (!/[ \t<>&|.+\-*\/%=!~?:^\[\]]/.test(c)) return "arithmetic with a #, quotes, backticks, backslashes or line breaks";
    }
    return "unterminated arithmetic";
  };

  // `${...}` from its `$`: the index of the closing brace. Only plain forms pass: a name or a
  // special parameter, a subscript that is a number, `@` or `*`, one operator, and a word with
  // no quotes. Inside double quotes the parser reads the rest of the word as text, as bash does;
  // outside them it reads it as command text.
  const brace = (open: number, quoted: boolean): number | string => {
    let i = open + 2;
    if (s[i] === "!") return "an indirect ${!name} expansion";
    let length = false;
    if (s[i] === "#") {
      if (s[i + 1] === "}") return i + 1;
      length = true;
      i++;
    }
    const name = /^(?:[A-Za-z_]\w*|\d+|[@*?$-])/.exec(s.slice(i, i + 256))?.[0];
    if (!name) return "a ${...} form the guard does not model";
    // Reading a variable gives it no value; `${name=word}` does, and is not accounted for.
    const nameAt = i;
    account(nameAt);
    i += name.length;
    if (s[i] === "[") {
      const close = s.indexOf("]", i);
      const inside = close < 0 ? "" : s.slice(i + 1, close);
      const found = close < 0 ? "an unterminated array subscript" : inside === "@" || inside === "*" ? undefined : index(inside, i + 1);
      if (found) return found;
      i = close + 1;
    }
    if (s[i] === "}") return i;
    if (length) return "a ${...} form the guard does not model";
    const c = s[i];
    if (c === "@") return "a ${name@X} transformation";
    if (c === ":" && !"-=+?".includes(s[i + 1] ?? "")) {
      const close = s.indexOf("}", i);
      if (close < 0) return "an unterminated ${";
      // `${x:offset}` and `${x:offset:length}`, each a number or a variable that holds one.
      let from = i + 1;
      for (const part of s.slice(from, close).split(":")) {
        const lead = /^ ?/.exec(part)![0].length;
        const found = index(part.slice(lead), from + lead);
        if (found) return found;
        from += part.length + 1;
      }
      return close;
    }
    if (c === ":") i++;
    const op = s[i];
    if ("-=+?".includes(op) && s[i] !== undefined) {
      if (op === "=" && ENV_DANGEROUS.test(name)) return `sets ${name}, which changes what programs run or load`;
      if (op === "=") variables.accounted.delete(offset + nameAt);
      i++;
    } else if (c === ":") return "a ${...} form the guard does not model";
    else if (op === "#" || op === "%" || op === "^" || op === ",") i += s[i + 1] === op ? 2 : 1;
    else if (op === "/") i += "/#%".includes(s[i + 1] ?? "") ? 2 : 1;
    else return "a ${...} form the guard does not model";
    let wordStart = false;
    for (; i < s.length; i++) {
      const ch = s[i];
      if (ch === "}") return i;
      if (ch === "\\") {
        if (s[i + 1] === "\n") return "a backslash-newline inside ${...}";
        i++;
        wordStart = false;
      } else if (ch === "'" || ch === '"') return "quotes inside ${...}";
      else if (ch === "`") {
        const end = backticks(i);
        if (typeof end === "string") return end;
        i = end;
        wordStart = false;
      } else if (ch === "$") {
        const end = dollar(i, quoted);
        if (typeof end === "string") return end;
        if (end < 0 && /['"]/.test(s[i + 1] ?? "")) return "quotes inside ${...}";
        if (end >= 0) i = end;
        wordStart = false;
      } else if (quoted) continue;
      else if (ch === "#") {
        if (wordStart) return "a # inside ${...}, which the rules read as a comment";
      } else if (ch === " " || ch === "\t") wordStart = true;
      else if ("\n;&|()<>".includes(ch)) return "a shell operator or line break inside ${...}";
      else wordStart = false;
    }
    return "an unterminated ${";
  };

  const dquote = (open: number): number | string => {
    for (let i = open + 1; i < s.length; i++) {
      const c = s[i];
      if (c === '"') return i;
      if (c === "\\") {
        const next = s[i + 1];
        // bash removes a backslash-newline; the parser keeps the newline (`"-\`, newline, `d"` is `-d`).
        if (next === "\n") return "a backslash-newline inside double quotes";
        // bash drops the backslash before these only; the parser drops it before anything.
        if (next !== undefined && !'$`"\\'.includes(next)) kept = true;
        text += quotedText(next ?? "");
        i++;
      } else if (c === "`") {
        const end = backticks(i);
        if (typeof end === "string") return end;
        i = end;
        expands = true;
        text += OPAQUE;
      } else if (c === "$") {
        const end = dollar(i, true);
        if (typeof end === "string") return end;
        if (end >= 0) {
          i = end;
          text += OPAQUE;
        } else text += c;
        if (end >= 0 || /[\w@*?!$#-]/.test(s[i + 1] ?? "")) expands = true;
        if (end < 0 && /[A-Za-z_]/.test(s[i + 1] ?? "")) account(i + 1);
      } else text += quotedText(c);
    }
    return "an unterminated quote";
  };

  // The substitutions bash runs in a heredoc body whose delimiter is not quoted.
  const heredocBody = (from: number, to: number): string | undefined => {
    for (let i = from; i < to; i++) {
      const c = s[i];
      let end: number | string = -1;
      // bash joins the lines first, so `EO\`, newline, `F` ends a heredoc and `$\`, newline, `(` opens a substitution.
      if (c === "\\" && s[i + 1] === "\n") return "a backslash-newline";
      if (c === "\\") i++;
      else if (c === "`") end = backticks(i);
      else if (c === "$") end = dollar(i, true);
      if (typeof end === "string") return end;
      if (end >= to) return "a heredoc body with a substitution that does not end in it";
      if (end >= 0) i = end;
    }
    return undefined;
  };

  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const next = s[i + 1];
    let found: string | undefined;
    // `]]` ends the test even with an operator straight after it.
    if (cond && !atStart && ";\n&|()".includes(c) && s.slice(begin, i) === "]]") {
      found = endWord(i);
      if (found) return found;
    }
    if (c === "\\") {
      if (next === undefined) return "a backslash at the end, which bash keeps and the rules drop";
      if (next === "\n") {
        // Bash removes the two characters before it reads a token; the parser skips them. The
        // two agree where no token can span them: between words, straight after a blank, and
        // between a complete `&&`, `||` or `|` and a plain word, which starts a command for both.
        let after = i + 2;
        while (s[after] === " " || s[after] === "\t") after++;
        if (blankAt !== i - 1 && !(joinAt === i - 1 && PLAIN_WORD_START.test(s[after] ?? ""))) return "a backslash-newline that is not straight after a blank between words, or after &&, || or | before a plain word";
      } else {
        start(i);
        text += quotedText(next);
      }
      i++;
    } else if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) return "an unterminated quote";
      const body = s.slice(i + 1, end);
      if (PAYLOAD.test(body)) return PAYLOAD_REASON;
      start(i);
      text += quotedText(body);
      i = end;
    } else if (c === '"') {
      start(i);
      const end = dquote(i);
      if (typeof end === "string") return end;
      i = end;
    } else if (c === "$" && (next === "'" || next === '"')) return `${c}${next}...${next} quoting`;
    else if (c === "$") {
      start(i);
      // `name=$((...))`: the value is an integer whatever the arithmetic holds.
      const valueOf = next === "(" && s[i + 2] === "(" && s.slice(begin, i) === text ? /^([A-Za-z_]\w*)=$/.exec(text)?.[1] : undefined;
      const end = dollar(i, false);
      if (typeof end === "string") return end;
      if (end >= 0) {
        if (valueOf !== undefined) arithmeticValue = { name: valueOf, begin, end };
        i = end;
        text += OPAQUE;
        expands = true;
      } else if (next === "#") {
        text += "$#";
        i++;
      } else {
        text += c;
        if (/[\w@*?!$-]/.test(next ?? "")) expands = true;
        if (/[A-Za-z_]/.test(next ?? "")) account(i + 1);
      }
    } else if (c === "`") {
      start(i);
      const end = backticks(i);
      if (typeof end === "string") return end;
      i = end;
      text += OPAQUE;
      expands = true;
    } else if ((c === "<" || c === ">") && next === "(") {
      start(i);
      const end = substitution(i + 1);
      if (typeof end === "string") return end;
      i = end;
      text += OPAQUE;
      expands = true;
    } else if (c === "<") {
      // Bash takes a number or `{name}` straight before a redirect as its descriptor; before
      // `<` the parser keeps it as an argument.
      if (!atStart && s.slice(begin, i) === text && /^(?:\d+|\{[A-Za-z_]\w*\})$/.test(text)) return "a descriptor straight before <, which the rules read as an argument";
      found = endWord(i);
      if (!named && !cond) prefixed = true;
      target = true;
      if (next === "<" && s[i + 2] === "<") i += 2; // a here-string
      else if (next === "<") {
        target = false;
        const m = HEREDOC.exec(s.slice(i));
        if (!m) return "a heredoc delimiter that is not one plain or fully quoted word";
        heredocs.push({ delimiter: m[2] ?? m[3] ?? m[4], dash: m[1] === "-", quoted: m[4] === undefined });
        i += m[0].length - 1;
      } else if (next === "&") {
        let j = i + 2;
        while (/[\d-]/.test(s[j] ?? "")) j++;
        if (j === i + 2 || (j < s.length && !WORD_END.test(s[j]))) return "a redirect from a descriptor that is not a plain number";
        i = j - 1;
        target = false;
      }
    } else if (c === ">" || (c === "&" && next === ">")) {
      // The parser drops a number straight before `>` as a descriptor; bash does so only when
      // the number is not quoted.
      if (!atStart && /^\d+$/.test(text)) {
        if (s.slice(begin, i) !== text) return "a quoted number straight before a redirect";
        // `2&>f`: bash passes the 2 as an argument.
        if (c === "&") return "a number straight before &>";
        atStart = true;
      }
      if (!atStart && s.slice(begin, i) === text && /^\{[A-Za-z_]\w*\}$/.test(text)) return "a {name} descriptor straight before a redirect, which the rules read as an argument";
      found = endWord(i);
      if (!named && !cond) prefixed = true;
      target = true;
      let j = i + (c === "&" ? 2 : 1);
      if (s[j] === ">" || s[j] === "|") j++;
      if (s[j] === "!") return "a redirect followed by !, which zsh reads as part of the operator";
      if (s[j] === "&") {
        // `>&2`: the parser skips the digits and starts a new word. bash reads `>&2x` as one
        // word and `>& file` as a redirect of both streams to the file.
        let k = j + 1;
        while (/[\d-]/.test(s[k] ?? "")) k++;
        if (k === j + 1 || (k < s.length && !WORD_END.test(s[k]))) return "a redirect to a descriptor that is not a plain number";
        j = k;
        target = false;
      }
      i = j - 1;
    } else if (c === " " || c === "\t") {
      found = endWord(i);
      blankAt = i;
    } else if (cond && (c === ";" || c === "\n" || c === "(" || c === ")" || ((c === "&" || c === "|") && next !== c))) {
      // Bash reads `[[ ]]` with extglob on and a regex after `=~` to its matching parenthesis;
      // the parser reads commands. Only words, `&&` and `||` are the same to both.
      return "a parenthesis, a ;, a single | or &, or a line break inside [[ ]]";
    } else if (c === ";") found = endCommand(i, ";");
    else if (c === "&" || c === "|") {
      const two = next === c || (c === "|" && next === "&");
      found = endCommand(i, two ? c + next : c);
      if (two) i++;
      if (next === c || (c === "|" && next !== "&")) joinAt = i;
    } else if (c === "(" && !atStart && "@!+*?".includes(s[i - 1])) {
      return "a ( straight after @, !, +, * or ? in a word, which bash reads as one pattern when extglob is on";
    } else if (c === "(" && next === "(") {
      // `(( ... ))` as a command of its own, or the head of `for ((`: what it assigns stays.
      const head = atStart ? words : [...words, s.slice(begin, i)];
      const sets = always(joinedBy) && (head.length === 0 ? blocks === 0 : head.length === 1 && head[0] === "for" && blocks === (atStart ? 1 : 0));
      found = endCommand(i, "((");
      if (found) return found;
      const end = arithmetic(i + 2, true, sets);
      if (typeof end === "string") return end;
      i = end;
    } else if (c === "(") {
      found = endCommand(i, "(");
      parens++;
    } else if (c === ")") {
      found = endCommand(i, ")");
      parens = Math.max(0, parens - 1);
    } else if (c === "#" && atStart) {
      const end = s.indexOf("\n", i);
      // For bash a comment hides the `)` that would end a `$(...)`.
      if (end < 0 && kind === "paren") return "a comment that runs to the end of a substitution";
      i = end < 0 ? s.length : end - 1;
    } else if (c === "\n") {
      found = endCommand(i, "\n");
      if (!found && heredocs.length) {
        let pos = i + 1;
        for (const doc of heredocs.splice(0)) {
          let at = -1;
          for (let line = pos; line <= s.length; ) {
            const eol = s.indexOf("\n", line);
            const lineText = s.slice(line, eol < 0 ? s.length : eol);
            // Inside a substitution bash ends the heredoc at a line that only starts with the
            // delimiter (`EOF)`, `EOF )`) and reads the rest of the line as code (round 4, finding 1).
            const unindented = doc.dash ? lineText.replace(/^\t+/, "") : lineText;
            if (kind && unindented !== doc.delimiter && unindented.startsWith(doc.delimiter)) return "inside a substitution, a heredoc line that starts with the delimiter and goes on, where bash ends the heredoc and runs the rest of the line";
            if (lineText.trim() === doc.delimiter) {
              // bash wants the line to be exactly the delimiter (`<<-` strips leading tabs only).
              if ((doc.dash ? lineText.replace(/^\t+/, "") : lineText) !== doc.delimiter) return "a heredoc terminator with whitespace around it";
              at = line;
              break;
            }
            if (eol < 0) break;
            line = eol + 1;
          }
          if (at < 0) return "a heredoc with no terminator";
          if (!doc.quoted) {
            const issue = heredocBody(pos, at);
            if (issue) return `${issue}, in a heredoc body`;
          }
          const eol = s.indexOf("\n", at);
          pos = eol < 0 ? s.length : eol + 1;
        }
        i = pos - 2;
        if (pos >= s.length) break;
      }
    } else {
      // Everything else is a character of a word to bash and to the parser: letters, digits,
      // `_%+,-./:=@^~`, the glob and brace characters, `!`, a `#` inside a word. A space that
      // is not ASCII is a word character to bash and a space to the parser's regexes.
      if (c > "\x7f" && /\s/.test(c)) return "a space that is not ASCII outside quotes";
      start(i);
      if (c === "{") braces = true;
      text += c;
    }
    if (found) return found;
  }
  if (heredocs.length) return "a heredoc with no body";
  const last = endCommand(s.length, "");
  return last ?? (cond ? "a [[ with no ]]" : undefined);
}

// ---- strict tokenizer ----

const BARE = /[A-Za-z0-9_@%+=:,.\/^~-]/;
// What may follow: a blank, an operator, the end, or a newline (round 4, finding 9; a caller
// that does not read lines gives up at the newline itself).
const NULL_REDIRECT = /^(?:(?:[12]?>>?|&>) ?\/dev\/null|2>&1)(?=[ \t\n;|&]|$)/;

export interface StrictCommand {
  argv: string[];
  // What joined it to the command before it: `&&`, `;`, `|` or `||`.
  before?: string;
  // One of its words has a `~` that bash expands differently from `tilde()`: a leading `~` with
  // a quote before the first unquoted `/` (bash leaves it as it is), `~user`, `~+` or `~-` (another
  // directory), or a `~` after `=` or `:` (bash expands it in a word shaped like an assignment).
  // A caller that would place such a word grants nothing.
  quotedTilde?: boolean;
  // With `assignments`: the assignment words before its name.
  assigns?: string[];
  // With `globs`: the indexes in argv of the words that hold an unquoted `*`, `?`, `[` or `]`.
  globbed?: number[];
}

// Whether bash computes the `~` of a word differently from `tilde()`. `quoted[i]` tells whether
// character i of the word came from inside quotes, and `opens` lists the positions where a quote
// opened (an empty `''` adds no character). Bash expands a leading `~` only when no quote is in it
// or in the text up to the first unquoted `/` (bash 5.2: `~'/x'`, `~"/x"`, `''~/x`, `~""/x` and
// `~'/'x` all stay `~/x`), and `tilde()` only knows the plain `~`.
function tildeDiffers(text: string, quoted: boolean[], opens: number[]): boolean {
  if (text.startsWith("~")) {
    let end = 0;
    while (end < text.length && !(text[end] === "/" && !quoted[end])) end++;
    if (text.slice(0, end) !== "~" || opens.some((at) => at <= end)) return true;
  }
  for (let i = 1; i < text.length; i++) if (text[i] === "~" && (text[i - 1] === "=" || text[i - 1] === ":") && !quoted[i]) return true;
  return false;
}

// The simple commands of a command line made only of plain words: letters, digits and
// `_@%+=:,./^~-`, single-quoted text, and double-quoted text without `$`, backtick, backslash or
// `!`. Commands are joined by `&&` or `;` (with `pipes`: also `|` and `||`). With
// `nullRedirects`, `>/dev/null`, `2>/dev/null` and `2>&1` are dropped. Anything else (variables,
// substitutions, globs, braces, other redirects, comments, newlines, assignments) gives
// undefined: the caller grants nothing.
//
// Widenings for the git-only check (round 3, finding 13, signed off), each an option:
// - `newlines`: a newline outside quotes separates commands as `;` does; blank lines and a newline
//   after `&&`, `||` or `|` (where bash reads on) are nothing.
// - `globs`: `*`, `?`, `[` and `]` outside quotes pass; the command lists the indexes of the words
//   that hold one (`globbed`), for the caller to place.
// - `bang`: `!` passes inside double quotes (a shell that is not interactive does no history
//   expansion; the scanner asks on `set -H` and `set -o history`).
// - `assignments`: words before the command's name that match it (unquoted) are assignments the
//   caller vets (`assigns`); any other assignment gives undefined as before.
//
// Round 4 (finding 16): the text read here is the canonical one (canon.ts), so `\(`, `\)` and
// `\'` outside quotes are read as the one literal character each stands for, and the `messages`
// widening of round 3 is gone: canon.ts has already folded `"$(cat <<'EOF' ... EOF)"` into the
// literal it stands for, reading the heredoc as bash does (finding 1).
export interface StrictOptions {
  pipes?: boolean;
  nullRedirects?: boolean;
  newlines?: boolean;
  globs?: boolean;
  bang?: boolean;
  assignments?: RegExp;
}
export function strictCommands(command: string, opts: StrictOptions = {}): StrictCommand[] | undefined {
  const cmds: StrictCommand[] = [];
  let argv: string[] = [];
  let assigns: string[] = [];
  let globbed: number[] = [];
  let word: string | undefined;
  // Per character of the word: whether it was quoted.
  let quoted: boolean[] = [];
  let opens: number[] = [];
  let glob = false;
  let before: string | undefined;
  let quotedTilde = false;
  const endWord = () => {
    if (word !== undefined) {
      if (!argv.length && opts.assignments?.test(word) && quoted.every((q) => !q) && !glob) assigns.push(word);
      else {
        if (glob) globbed.push(argv.length);
        argv.push(word);
        if (tildeDiffers(word, quoted, opens)) quotedTilde = true;
      }
    }
    word = undefined;
    quoted = [];
    opens = [];
    glob = false;
  };
  const endCmd = (separator?: string) => {
    endWord();
    if (!argv.length || argv[0].includes("=")) return false;
    cmds.push({ argv, ...(before ? { before } : {}), ...(quotedTilde ? { quotedTilde } : {}), ...(assigns.length ? { assigns } : {}), ...(globbed.length ? { globbed } : {}) });
    argv = [];
    assigns = [];
    globbed = [];
    before = separator;
    quotedTilde = false;
    return true;
  };
  const s = command;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === " " || c === "\t") endWord();
    else if (c === "\n" && opts.newlines) {
      endWord();
      if ((argv.length || assigns.length) && !endCmd(";")) return undefined;
    } else if (c === "\\" && (s[i + 1] === "(" || s[i + 1] === ")" || s[i + 1] === "'")) {
      // The canonical spelling of a literal parenthesis or single quote: one quoted character.
      opens.push((word ?? "").length);
      word = (word ?? "") + s[i + 1];
      quoted.push(true);
      i++;
    } else if (c === "'" || c === '"') {
      const end = s.indexOf(c, i + 1);
      if (end < 0 || (c === '"' && (opts.bang ? /[$`\\]/ : /[$`\\!]/).test(s.slice(i + 1, end)))) return undefined;
      opens.push((word ?? "").length);
      word = (word ?? "") + s.slice(i + 1, end);
      for (let k = i + 1; k < end; k++) quoted.push(true);
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
      if (!endCmd(two ? c + c : c)) return undefined;
      if (two) i++;
    } else if ((c === ">" || ((c === "1" || c === "2") && s[i + 1] === ">")) && opts.nullRedirects && word === undefined) {
      const m = NULL_REDIRECT.exec(s.slice(i));
      if (!m) return undefined;
      i += m[0].length - 1;
    } else if (BARE.test(c) || (opts.globs && "*?[]".includes(c))) {
      if (!BARE.test(c)) glob = true;
      word = (word ?? "") + c;
      quoted.push(false);
    } else return undefined;
  }
  endWord();
  // A trailing `;` (or newline) is fine; a trailing `&&` or `|` is not.
  if (argv.length || assigns.length ? !endCmd() : before !== ";" || !cmds.length) return undefined;
  return cmds;
}

export const strict = (command: string, opts: StrictOptions = {}): string[][] | undefined => strictCommands(command, opts)?.map((c) => c.argv);

export const tilde = (p: string) => (p === "~" || p.startsWith("~/") ? HOME + p.slice(1) : p);

// A `~` the rules' parser and bash read differently, in a command as written: the parser takes
// `~'/x'`, `"~"/x`, `''~/x` and `\~/x` for the home directory once it has removed the quotes, and
// bash leaves each as it is. A rough scan over the whole text (nested commands included): a `~` at
// the start of a word after quotes or a backslash, or followed by one before a `/` or the end of
// the word. Quoted text that merely holds a `~` (`grep '~' f`) matches too, which costs a model
// call and nothing more.
export function tildeMismatch(command: string): string | undefined {
  const m = /(?:^|[\s;&|()<>`{}])(?:''|""|\\)*(?:['"]|\\)~|(?:^|[\s;&|()<>`{}])~[^\s/;&|()<>`]*['"\\]/.exec(command);
  return m ? `a ~ that bash leaves as it is and the rules read as your home directory: ${m[0].trim()}` : undefined;
}

// Where `cd <arg>` or `git -C <arg>` ends up from `from`: an existing directory that bash's
// logical `cd` (which drops `..` from the text), a physical one and the kernel all reach.
// Undefined when they could differ (a `..` that crosses a symbolic link) or nothing is there.
export function landing(from: string, arg: string): string | undefined {
  try {
    const real = fs.realpathSync.native(from);
    const physical = fs.realpathSync.native(path.isAbsolute(arg) ? arg : `${real}/${arg}`);
    if (!fs.statSync(physical).isDirectory()) return undefined;
    for (const base of [from, real]) if (fs.realpathSync.native(path.resolve(base, arg)) !== physical) return undefined;
    return physical;
  } catch {
    return undefined;
  }
}

// A tool call that is one plain command, optionally after `cd <dir> &&` and under `timeout <n>`.
export interface Single {
  // Where the command runs: the tool call's directory as given, or the real path `cd` leads to.
  dir: string;
  // The command without `timeout <n>`.
  argv: string[];
  // The texts a rules Matcher may be shown for it: as written, and without the wrapper.
  texts: string[];
}
const TIMEOUT = /^\d+(\.\d+)?[smhd]?$/;
// The check runs on `dir`, so bash must end up there or run nothing: `cd` is joined by `&&`
// (after `cd x;` a failed `cd` still runs the command, somewhere else), and names a directory
// that exists. A word whose `~` bash expands differently from `tilde()` (a quote before the first
// unquoted `/`, `~user`, `~+`, `~-`, a `~` after `=` or `:`) grants nothing.
export function single(command: string, cwd: string): Single | undefined {
  const cmds = strictCommands(command);
  if (!cmds || cmds.some((c) => c.quotedTilde)) return undefined;
  let dir = cwd;
  // Each `cd` as bash goes there, by the logical path (B3c: `cd sub/link && cd ..` is in `sub`).
  let place: Place | undefined;
  const rest: string[][] = [];
  for (const [n, { argv }] of cmds.entries()) {
    if (argv[0] !== "cd") {
      rest.push(argv);
      continue;
    }
    if (argv.length !== 2 || rest.length || argv[1].startsWith("-") || /^~[^/]/.test(argv[1]) || cmds[n + 1]?.before !== "&&") return undefined;
    const to = cdTo((place ??= startPlace(cwd)), argv[1]);
    if (!to) return undefined;
    place = to;
    dir = to.real;
  }
  if (rest.length !== 1) return undefined;
  const full = rest[0];
  const argv = full[0] === "timeout" && TIMEOUT.test(full[1] ?? "") ? full.slice(2) : full;
  if (!argv.length) return undefined;
  return { dir, argv, texts: [...new Set([full.join(" "), argv.join(" ")])] };
}

// ---- git ----

// `-c` keys that change nothing git runs or connects to.
const GIT_C_OK = /^(user\.(name|email)|color\.[\w.]+|advice\.[\w.]+|core\.quotepath|init\.defaultBranch|commit\.gpgsign|log\.showSignature)=/;
const GIT_GLOBAL_FLAGS = new Set(["--no-pager", "-P", "--no-optional-locks", "--literal-pathspecs", "--no-replace-objects", "--version", "--help", "-h", "-v"]);
// Long options that make git run a program or write a file of the caller's choosing. Git
// accepts any unique prefix of a long option, so a prefix of three or more characters counts.
const GIT_PROGRAM_OPTIONS = ["--upload-pack", "--receive-pack", "--exec", "--open-files-in-pager", "--extcmd"];
export const abbreviates = (word: string, options: string[]) => {
  const name = word.split("=")[0];
  return name.length >= 3 && name.startsWith("--") && options.some((o) => o.startsWith(name));
};
// Long options the rules and DEFAULT_ASK look for by their full spelling, per subcommand. Git
// takes `--har` for `--hard`; the rules do not, so a shortened one asks.
const GIT_KEYED_OPTIONS: Record<string, string[]> = {
  reset: ["--hard"],
  clean: ["--force"],
  checkout: ["--force", "--track"],
  switch: ["--track", "--force", "--discard-changes"],
  restore: ["--staged", "--worktree"],
  worktree: ["--force"],
  submodule: ["--force"],
  branch: ["--delete", "--force", "--set-upstream-to", "--unset-upstream", "--track", "--move", "--copy", "--edit-description"],
  tag: ["--delete"],
  push: ["--set-upstream"],
  config: ["--global", "--system"],
  gc: ["--prune", "--aggressive"],
  rebase: ["--interactive"],
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

// The words of a git call that are the text of a message: the word after `-m` or `--message`
// (and the word `--message=<text>`) of `commit`, `tag` and `merge`. Indexes into `args`, the
// words after `git`; `attached` for the `--message=<text>` form. A message is data to git,
// whatever it holds, so the checks that read options and names by their spelling leave these
// words alone (round 4: a git option is told by its position).
//
// This grants trust (the word is not judged), so it reads an allowlist, twice over.
//
// The subcommand: only one for which git has a single option table, so that `-m` means the
// message wherever it stands. `stash` and `notes` have a table per action, and for some of them
// `-m` is another option or none: `git stash list -m --output=f` hands both words to `git log`,
// which writes f (found by the round 4 cross-check of the second version; the maintainer then
// decided on these three). Their messages are read as the ordinary words they are.
// `cherry-pick -m` and `revert -m` take a number and are not here either.
//
// The words before it: every option must be a flag of that subcommand known to take no value;
// any other option stops the reading, because an option that takes a value takes `-m` as that
// value and makes the next word a real option (`git commit --trailer -m --file=.env`,
// `git tag --cleanup -m -d v1`; found by the cross-check of the first version, which took every
// `-m`). Words that are no options (a tag's name, a path) take nothing and are passed over. A
// short cluster counts for `commit` alone, and only of flags that take no value (`-am`, `-qm`).
// Nothing counts after `--`. The caller hands over a word bash computes or expands (`$opt`,
// `*`) as an option this table does not know.
const GIT_MESSAGE_FLAGS: Record<string, { short: string; long: string[] }> = {
  commit: { short: "asvqn", long: ["--all", "--quiet", "--verbose", "--signoff", "--no-signoff", "--no-verify", "--amend", "--allow-empty", "--allow-empty-message", "--no-edit", "--no-gpg-sign", "--include", "--only"] },
  tag: { short: "", long: ["--annotate", "--no-sign"] },
  merge: { short: "", long: ["--no-ff", "--ff", "--ff-only", "--squash", "--no-squash", "--commit", "--no-commit", "--no-edit", "--quiet", "--no-verify", "--stat", "--no-stat"] },
};
const GIT_MESSAGE_SHORT: Record<string, string> = { tag: "a", merge: "q" };
export function gitMessageWords(args: string[]): { at: number; attached: boolean }[] {
  const call = gitCall(args);
  const flags = typeof call === "string" ? undefined : GIT_MESSAGE_FLAGS[call.sub ?? ""];
  if (typeof call === "string" || !flags || !Object.hasOwn(GIT_MESSAGE_FLAGS, call.sub ?? "")) return [];
  const from = args.length - call.rest.length;
  const single = GIT_MESSAGE_SHORT[call.sub ?? ""] ?? flags.short;
  const out: { at: number; attached: boolean }[] = [];
  for (let i = 0; i < call.rest.length; i++) {
    const w = call.rest[i];
    if (!w.startsWith("-") || w === "-") continue;
    if (w === "--message" || w === "-m" || (flags.short && new RegExp(`^-[${flags.short}]+m$`).test(w))) {
      if (i + 1 >= call.rest.length) break;
      out.push({ at: from + ++i, attached: false });
    } else if (w.startsWith("--message=")) out.push({ at: from + i, attached: true });
    else if (flags.long.includes(w) || (single && new RegExp(`^-[${single}]+$`).test(w))) continue;
    // `--`, or an option this table does not know to take no value.
    else break;
  }
  return out;
}

// What writes git's config, makes a repository, or writes the sparse-checkout file (round 4,
// finding 7, second pass): the DEFAULT_ASK patterns anchored at `^git( -C \S+)*` moved here, read
// by the position of each word from gitCall and git's own option tables, so that a `-C` holding a
// blank, a global option before the subcommand, an option before the action and a short option in
// a cluster are read as git reads them. .git/config is read-only in the sandbox, and a new
// repository gets hooks and config after this command's sandbox was set up: each asks, so that an
// approved run happens outside it. A word git refuses leaves the call unread, and asks.
function gitConfigTouch(sub: string, rest: string[]): string | undefined {
  const writes = (what: string) => `git ${sub} ${what} writes git's config, which is read-only in the sandbox`;
  if (sub === "init" || sub === "clone") return `git ${sub} makes a repository, whose hooks and config come after this command's sandbox was set up`;
  if (sub === "sparse-checkout") return "git sparse-checkout writes the sparse-checkout file and git's config";
  if (sub === "submodule" || sub === "worktree") {
    // Their own options stand before the action: `--quiet`, and submodule's `--cached`.
    let k = 0;
    while (k < rest.length && (rest[k] === "-q" || rest[k] === "--quiet" || (sub === "submodule" && rest[k] === "--cached"))) k++;
    const action = rest[k];
    if (action !== undefined && action.startsWith("-")) return `git ${sub} ${action}: an option before the action that the check does not read`;
    // Only these read; every other action writes config, a submodule or a worktree.
    if (sub === "submodule" ? action === undefined || action === "status" || action === "summary" : action === "list") return undefined;
    return writes(action ?? "");
  }
  if (sub === "remote") {
    const action = rest.find((w) => !w.startsWith("-"));
    if (["add", "remove", "rm", "rename", "set-url", "set-branches"].includes(action ?? "")) return writes(action!);
  }
  if (sub === "fetch" || sub === "pull") return lastOf(getopt(rest, GIT_OPTIONS[sub]), "set-upstream") !== undefined ? writes("--set-upstream") : undefined;
  if (sub !== "branch" && sub !== "checkout" && sub !== "switch" && sub !== "push") return undefined;
  const got = getopt(rest, GIT_OPTIONS[sub]);
  if (got.unknown) return `git ${sub} ${got.unknown}: not an option of git ${sub}, or a prefix of two of them, so the check cannot read the words after it`;
  const on = (name: string, short?: string) => lastOf(got, name, short) !== undefined;
  const given = (...names: string[]) => got.opts.find((o) => names.includes(o.name))?.name;
  if (sub === "push") return on("set-upstream", "u") ? writes("--set-upstream") : undefined;
  if (on("track", "t")) return writes("--track");
  // Actual start-point resolution is performed where the command runs in decide.ts.
  if (sub === "branch") {
    const option = given("-u", "--set-upstream-to", "--unset-upstream", "--set-upstream", "-m", "-M", "--move", "-c", "-C", "--copy", "--edit-description");
    if (option) return writes(option);
    return undefined;
  }
  return undefined;
}

// What one git call does that the rules allow by the subcommand's name alone.
// `runs`: whether this git is a program that runs (see gitProblem); gitConfigTouch asks only then.
function gitCallProblem(call: GitCall, exists?: (word: string) => boolean, more = false, runs = true): string | undefined {
  const { sub = "", rest } = call;
  if (sub === "config") {
    const write = configWrite(rest, more);
    if (write) return write;
  }
  const touch = runs ? gitConfigTouch(sub, rest) : undefined;
  if (touch) return touch;
  const program = rest.find((w) => abbreviates(w, GIT_PROGRAM_OPTIONS));
  if (program) return `git ${sub} ${program} picks a program for git to run`;
  const operand = rest.find((w) => !w.startsWith("-"));
  if (sub === "grep" && rest.some((w) => /^-[a-zA-Z]*O/.test(w))) return "git grep -O opens the matches in a program of the caller's choosing";
  if (sub === "submodule" && operand === "foreach") return "git submodule foreach runs a command in every submodule";
  if (sub === "bisect" && operand === "run") return "git bisect run runs a command at every step";
  if (sub === "apply") {
    // Read as git reads it (round 4, finding 20, second pass): a word git refuses, or one the
    // check cannot read as git's, leaves the rest unread.
    const got = getopt(rest, GIT_OPTIONS.apply);
    if (got.unknown) return `git apply ${got.unknown}: not an option of git apply, or a prefix of two of them, so the check cannot read the words after it`;
    // A patch may write anywhere once this is given (round 4, finding 20).
    if (lastOf(got, "unsafe-paths") !== undefined) return "git apply --unsafe-paths lets the patch write outside the work tree";
  }
  if ((sub === "rebase" || sub === "difftool") && rest.some((w) => /^-[a-zA-Z]*[xi]/.test(w))) return `git ${sub} with -x or -i runs a command or an editor`;
  const keyed = GIT_KEYED_OPTIONS[sub] ?? [];
  const short = rest.find((w) => abbreviates(w, keyed) && !keyed.includes(w.split("=")[0]));
  if (short) return `git ${sub} ${short} is a shortened option, which git accepts and the rules do not read`;
  return gitDestroys(sub, rest, exists && placedUnder(call.dirs, exists));
}

// `exists` for a word git reads where its `-C` options lead (round 4, finding 19): `git -C sub
// checkout notes.md` names sub/notes.md. Each `-C` applies after the one before it, and an absolute
// one starts over. A `-C` whose place is known only at run time could be anywhere: the word then
// counts as a file that exists.
function placedUnder(dirs: string[], exists: (word: string) => boolean): (word: string) => boolean {
  if (!dirs.length) return exists;
  const base = gitBase(dirs);
  if (base === undefined) return () => true;
  return (word) => exists(path.isAbsolute(tilde(word)) ? word : `${base}/${word}`);
}

// Where git's `-C` options lead from the directory git starts in (round 4, findings 19 and 20,
// second pass): each after the one before it, an absolute one starting over. A path to put a
// relative word under, kept as written (not normalised: a `..` after a link is the kernel's to
// walk); "" for no `-C`; undefined when one is known only at run time.
export function gitBase(dirs: string[]): string | undefined {
  let base = "";
  for (const d of dirs) {
    if (/[$`*?[\]]/.test(d) || /^~[^/]/.test(d)) return undefined;
    const t = tilde(d);
    base = path.isAbsolute(t) || !base ? t : `${base}/${t}`;
  }
  return base;
}

// git 2.47.3's options, for the subcommands whose options the guard reads (round 4, second pass):
// every name `git <sub> --git-completion-helper-all` lists (the hidden ones too: `--binary` makes
// `--b` a prefix of two), with the values `git <sub> -h` shows. git's parse-options takes any
// unique prefix of a name or of its `--no-` form, a value after `=` or as the next word, short
// letters in clusters, and options after the operands until `--`.
const gitNegatable = (fixed: string[]) => (n: string) => !n.startsWith("no-") && !fixed.includes(n);
export const GIT_OPTIONS: Record<string, Getopt> = {
  apply: {
    flags: "N3zRvq",
    values: "pC",
    long: Object.fromEntries([
      ...["exclude", "include", "build-fake-ancestor", "whitespace", "directory"].map((n) => [n, "value"]),
      ...["no-add", "add", "stat", "allow-binary-replacement", "binary", "numstat", "summary", "check", "index", "intent-to-add", "cached", "unsafe-paths", "apply", "3way", "ours", "theirs", "union", "ignore-space-change", "ignore-whitespace", "reverse", "unidiff-zero", "reject", "allow-overlap", "verbose", "quiet", "inaccurate-eof", "recount", "allow-empty"].map((n) => [n, "flag"]),
    ]),
    negatable: gitNegatable(["exclude", "include", "add", "ours", "theirs", "union"]),
  },
  // Round 4, finding 18, second pass. The values `=` marks in the completion list are required (the
  // next word when not attached); `-h` shows the optional ones (`--jobs[=<n>]` in pull, attached
  // only). A flag's `--no-` form (`--no-recurse-submodules`) needs no entry of its own: every
  // name not in `fixed` takes it.
  fetch: gitTable("vqafmtnpPku46", "jo", "", {
    flag: "verbose quiet all set-upstream append atomic force multiple tags prefetch prune prune-tags dry-run porcelain write-fetch-head keep update-head-ok progress unshallow refetch update-shallow ipv4 ipv6 negotiate-only auto-maintenance auto-gc show-forced-updates write-commit-graph stdin",
    value: "upload-pack jobs depth shallow-since shallow-exclude deepen submodule-prefix recurse-submodules-default refmap server-option negotiation-tip filter",
    optional: "recurse-submodules",
    fixed: "unshallow refetch refmap ipv4 ipv6",
  }),
  pull: gitTable("vqnaftpk46", "sXo", "rSj", {
    flag: "verbose quiet progress stat summary squash commit edit ff ff-only verify verify-signatures autostash allow-unrelated-histories all append force tags prune dry-run keep unshallow update-shallow ipv4 ipv6 show-forced-updates set-upstream",
    value: "cleanup strategy strategy-option upload-pack depth shallow-since shallow-exclude deepen refmap server-option negotiation-tip",
    optional: "recurse-submodules rebase log signoff gpg-sign jobs",
    fixed: "ff-only unshallow refmap",
  }),
  // Round 4, finding 7, second pass: the subcommands that write git's config by an option or a
  // start point (see gitConfigTouch). `--contains`, `--merged` and their kin take the next word
  // (git's last-argument default); `-t`/`--track` take an attached value only.
  branch: gitTable("vqrdDmMcClfai", "u", "t", {
    flag: "verbose quiet set-upstream unset-upstream remotes all delete move omit-empty copy list show-current create-reflog edit-description force ignore-case recurse-submodules",
    value: "set-upstream-to sort points-at format contains no-contains merged no-merged with without",
    optional: "track color abbrev column",
    fixed: "remotes all contains merged with without",
  }),
  checkout: gitTable("qmdf23pl", "bB", "t", {
    flag: "guess overlay quiet progress merge detach force overwrite-ignore ignore-other-worktrees ours theirs patch ignore-skip-worktree-bits pathspec-file-nul",
    value: "conflict orphan pathspec-from-file",
    optional: "track recurse-submodules",
    fixed: "ours theirs",
  }),
  switch: gitTable("qmdf", "cC", "t", {
    flag: "guess discard-changes quiet progress merge detach force overwrite-ignore ignore-other-worktrees",
    value: "create force-create conflict orphan",
    optional: "track recurse-submodules",
  }),
  push: gitTable("vqdnfu46", "o", "", {
    flag: "verbose quiet all branches mirror delete tags dry-run porcelain force force-if-includes thin set-upstream progress prune follow-tags atomic ipv4 ipv6 verify",
    value: "repo recurse-submodules receive-pack exec push-option",
    optional: "force-with-lease signed",
    fixed: "ipv4 ipv6",
  }),
};
// A git option table from its short letters (flags, required values, optional attached values)
// and its long names by kind; `fixed`: the names that take no `--no-`.
function gitTable(flags: string, values: string, optional: string, long: { flag?: string; value?: string; optional?: string; fixed?: string }): Getopt {
  const words = (s?: string) => (s ? s.split(" ") : []);
  return {
    flags,
    values,
    optional,
    long: Object.fromEntries((["flag", "value", "optional"] as const).flatMap((kind) => words(long[kind]).map((n) => [n, kind]))),
    negatable: gitNegatable(words(long.fixed)),
  };
}
// The option's value as the last of its spellings left it: the value (or "" for a flag) when the
// last one is `--name` (or the short letter), undefined when it is `--no-name` or none.
export function lastOf(got: Got, name: string, short?: string): string | undefined {
  const last = got.opts.filter((o) => o.name === `--${name}` || o.name === `--no-${name}` || (short && o.name === `-${short}`)).at(-1);
  return !last || last.name.startsWith("--no-") ? undefined : (last.value ?? "");
}
// Whether `git apply` applies the patch: `--check`, `--stat`, `--numstat` and `--summary` turn
// applying off unless `--apply` is given, each as the last of its spellings leaves it.
export function gitApplies(rest: string[]): boolean {
  const got = getopt(rest, GIT_OPTIONS.apply);
  if (got.unknown) return true;
  return lastOf(got, "apply") !== undefined || !["check", "stat", "numstat", "summary"].some((n) => lastOf(got, n) !== undefined);
}

// Whether `git config` writes (round 4, finding 7), read from the positions of its words, as git
// reads them: the reason when it writes or cannot be read as a read, undefined for a read. git
// 2.46's subcommands `get` and `list` read and the others write. In the older form git takes
// options only up to the first operand (`git config alias.x --get` sets alias.x to `--get`): a
// read is one reading action (`--get`, `--list`, ...) with no writing one, or no action and one
// operand (`git config user.name`). An option git does not have, or two actions, is not a read,
// nor is one operand when more words may follow (`xargs git config core.fsmonitor`). The value
// a write sets is never read for options, so text inside it changes nothing here.
const CONFIG_READS = ["--get", "--get-all", "--get-regexp", "--get-urlmatch", "--list", "--get-color", "--get-colorbool"];
const CONFIG_WRITES = ["--replace-all", "--add", "--unset", "--unset-all", "--rename-section", "--remove-section", "--edit", "--comment", "--no-comment"];
const CONFIG_VALUED = ["--file", "--blob", "--type", "--default", "--comment"];
const CONFIG_FLAGS = ["--global", "--system", "--local", "--worktree", "--null", "--name-only", "--show-origin", "--show-scope", "--show-names", "--bool", "--int", "--bool-or-int", "--bool-or-str", "--path", "--expiry-date", "--includes", "--fixed-value", "--no-type"];
const CONFIG_NEGATED = ["global", "system", "local", "worktree", "file", "blob", "null", "name-only", "show-origin", "show-scope", "show-names", "default", "fixed-value", "includes"].map((n) => `--no-${n}`);
const CONFIG_LONG = [...CONFIG_READS, ...CONFIG_WRITES, ...CONFIG_VALUED, ...CONFIG_FLAGS, ...CONFIG_NEGATED];
function configWrite(rest: string[], more: boolean): string | undefined {
  const write = (why: string) => `git config ${why}: it writes git's config, or the check cannot read it as a read (core.fsmonitor, core.sshCommand or an alias set this way runs a program at the next git command)`;
  const first = rest[0];
  if (first === "get" || first === "list") return undefined;
  if (first !== undefined && ["set", "unset", "rename-section", "remove-section", "edit"].includes(first)) return write(first);
  const actions: string[] = [];
  let i = 0;
  for (; i < rest.length; i++) {
    const w = rest[i];
    if (w === "--") {
      i++;
      break;
    }
    if (!w.startsWith("-") || w === "-") break;
    if (w.startsWith("--")) {
      const name = w.split("=")[0];
      const matches = CONFIG_LONG.filter((o) => o.startsWith(name));
      const full = CONFIG_LONG.includes(name) ? name : matches.length === 1 ? matches[0] : undefined;
      if (!full) return write(`${w}, an option git config does not have`);
      if (CONFIG_READS.includes(full) || CONFIG_WRITES.includes(full)) actions.push(full);
      if (CONFIG_VALUED.includes(full) && !w.includes("=")) i++;
      continue;
    }
    for (let j = 1; j < w.length; j++) {
      const c = w[j];
      if (c === "l") actions.push("--list");
      else if (c === "e") actions.push("--edit");
      else if (c === "f" || c === "t") {
        if (j + 1 === w.length) i++;
        break;
      } else if (c !== "z") return write(`${w}, an option git config does not have`);
    }
  }
  const operands = rest.length - i;
  if (actions.length > 1) return write(actions.join(" "));
  if (actions.length === 1) return CONFIG_READS.includes(actions[0]) ? undefined : write(actions[0]);
  // One operand bash may expand into several (`git config c*` can be a name and a value; round 4,
  // finding 7, second pass) is not one operand. Read from the word without its quotes: a quoted
  // `*`, `?`, `[`, `{` or `$` is no part of a valid name either, so nothing readable is lost.
  const expanded = operands === 1 && /[*?[\]{}$`]/.test(rest[i]);
  if (operands === 1 && !more && !expanded) return undefined;
  return write(expanded ? `${rest[i]}, a word bash may expand into a name and a value` : operands === 1 ? "under a program that adds words" : "with a name and a value");
}

// Destructive git in every spelling git accepts (round 3, finding 22). The rules key on plain
// words (`-D`, `-d` with `-f`, `checkout -f`, `checkout -- path`, `checkout .`); git also reads
// short options in clusters (`-qf`, `-df`), unique prefixes of long ones, and a `checkout` operand
// that names a path instead of a branch. Whatever the rules ask in the plain spelling, and the
// forms that do the same (`switch -f`/`--discard-changes`/`-C`, `checkout -B`, `branch -f`/`-M`/
// `-C`, `gc --prune=<date>`), ask here.
const GIT_VALUE_OPTIONS: Record<string, RegExp> = {
  checkout: /^(-[a-zA-Z]*[bB]|--orphan|--conflict|--pathspec-from-file)$/,
  switch: /^(-[a-zA-Z]*[cC]|--create|--force-create|--orphan|--conflict)$/,
  branch: /^(-[a-zA-Z]*u|--set-upstream-to|--contains|--no-contains|--merged|--no-merged|--points-at|--sort|--format|--color|--column)$/,
};
function gitDestroys(sub: string, rest: string[], exists?: (word: string) => boolean): string | undefined {
  const end = rest.indexOf("--");
  const own = end < 0 ? rest : rest.slice(0, end);
  const letters = own.filter((w) => /^-[a-zA-Z]+$/.test(w)).join("");
  const long = (...names: string[]) => own.some((w) => w.startsWith("--") && (names.includes(w.split("=")[0]) || abbreviates(w, names)));
  const has = (names: string[], short: string) => long(...names) || [...short].some((c) => letters.includes(c));
  const operands: string[] = [];
  const takesValue = GIT_VALUE_OPTIONS[sub];
  for (let i = 0; i < own.length; i++) {
    if (takesValue?.test(own[i]) && !own[i].includes("=")) i++;
    else if (!own[i].startsWith("-") || own[i] === "-") operands.push(own[i]);
  }
  const discards = `git ${sub} discards local changes or deletes what is not merged`;
  if (sub === "checkout") {
    if (has(["--force"], "f") || has(["--patch"], "Bp") || long("--ours", "--theirs", "--pathspec-from-file", "--pathspec-file-nul", "--no-overlay")) return discards;
    const creating = has(["--orphan"], "b");
    // `checkout <tree> <path>...`, or one operand that is a path: the files are overwritten.
    // (B7-8: `git checkout topic --` names a branch and no path: nothing follows the `--`.)
    const pathsAfter = end >= 0 && rest.length > end + 1;
    if (pathsAfter || (end >= 0 && operands.length !== 1) || operands.length > (creating ? 1 : 1)) return `git checkout ${operands.slice(1).join(" ") || "-- ..."} names paths, whose local changes it overwrites`;
    const only = operands[0];
    if (!creating && end < 0 && only !== undefined && only !== "-" && (only === "." || /^\.{1,2}(\/|$)/.test(only) || only.startsWith(":") || /[*?[]/.test(only) || exists?.(only))) return `git checkout ${only} names a path, whose local changes it overwrites`;
  }
  if (sub === "switch" && has(["--force", "--discard-changes", "--force-create"], "fC")) return discards;
  if (sub === "branch") {
    const del = has(["--delete"], "d");
    const force = has(["--force"], "f");
    if (has([], "DMC") || (del && force) || (force && operands.length > 0) || (force && has(["--move", "--copy"], "mc"))) return discards;
  }
  if (sub === "tag" && has(["--delete"], "d")) return discards;
  if (sub === "gc" && own.some((w) => /^--prune=/.test(w))) return "git gc --prune=<date> deletes objects nothing refers to, which git otherwise keeps for a while";
  if (sub === "fetch" || sub === "pull") return fetchMoves(sub, rest);
  return undefined;
}

// A fetch that moves a local ref backwards or deletes one (round 4, finding 18): `git fetch .
// +keep:rel` is `git branch -f rel keep`. A refspec with `+`, `-f`/`--force`, a `--refmap` with a
// value, `--update-head-ok`, and `--prune` with a refspec that names a destination (git then
// deletes the refs there that the source does not have) ask. A refspec without `+` and without
// force only moves branches forward. Remote-tracking destinations may move backwards; other
// namespaces and wildcard destinations ask. Second pass: words are read by git's own tables
// (GIT_OPTIONS: prefixes, clusters, values, `--no-` forms, the last spelling deciding), a word git
// refuses leaves the rest unread, refspecs read from standard input (`--stdin`) are refspecs no
// check has read, and `--prune-tags` deletes local tags the remote lacks: with `--prune`, or with
// `fetch.prune` in a config the check does not read, so it asks alone.
// B7-8: the ref a refspec's destination names, as git reads one without `refs/` (remote.c,
// get_fetch_map: `heads/x`, `tags/x` and `remotes/x` are under `refs/`, any other name is a
// branch): `main:tags/v9` writes refs/tags/v9. Empty for no destination.
export const fetchDestination = (dst: string): string => (dst === "" || dst.startsWith("refs/") ? dst : /^(heads|tags|remotes)\//.test(dst) ? `refs/${dst}` : `refs/heads/${dst}`);
function fetchMoves(sub: string, rest: string[]): string | undefined {
  const moves = (what: string) => `git ${sub} ${what} can move a local branch or tag backwards or delete one, as branch -f and branch -D do`;
  const got = getopt(rest, GIT_OPTIONS[sub]);
  if (got.unknown) return `git ${sub} ${got.unknown}: not an option of git ${sub}, or a prefix of two of them, so the check cannot read the words after it`;
  const on = (name: string, short?: string) => lastOf(got, name, short) !== undefined;
  const refmap = got.opts.find((o) => o.name === "--refmap" && o.value);
  if (refmap) return moves(`--refmap ${refmap.value}`);
  if (on("stdin")) return `git ${sub} --stdin reads refspecs from standard input, which no check has read: one may move a local branch or tag backwards or delete one`;
  const operands = got.operands.map((o) => o.word);
  const forced = operands.find((w) => w.startsWith("+"));
  if (forced) return moves(`${forced}`);
  if (on("force", "f")) return moves(on("tags", "t") ? "--force --tags" : "--force");
  if (on("update-head-ok", "u")) return moves("--update-head-ok");
  if (on("prune-tags", "P")) return moves("--prune-tags");
  // B7-8: a partial fetch writes `remote.<name>.promisor`, `remote.<name>.partialclonefilter` and
  // `extensions.partialClone` into git's config.
  if (lastOf(got, "filter") !== undefined) return `git ${sub} --filter writes git's config, which is read-only in the sandbox`;
  // A destination: `src:dst` with a dst, or `tag <name>`.
  const destination = operands.slice(1).find((w, k, all) => /:./.test(w) || (w === "tag" && all[k + 1] !== undefined));
  for (const word of operands.slice(1)) {
    if (!word.includes(":")) continue;
    const dst = fetchDestination(word.slice(word.indexOf(":") + 1));
    if (dst && !/^(?:refs\/heads\/[^:*?\[\]\\]+|refs\/remotes\/[^/:*?\[\]\\]+\/[^:*?\[\]\\]+)$/.test(dst)) return moves(word);
    if (on("prune", "p") && dst && !dst.startsWith("refs/remotes/")) return moves(`--prune ${word}`);
  }
  if (on("prune", "p") && destination === "tag") return moves("--prune tag");
  return undefined;
}

// The files git writes because an option names them (round 3, finding 25): `--output` of the
// diff and log family, `format-patch -o`/`--output-directory`, `archive -o`/`--output`, `bundle
// create <file>`, and `apply --build-fake-ancestor=<file>` (round 4, finding 20: the only other
// option of a subcommand the rules allow that names a file git writes). Pairs of the word and
// whether it is a directory. `args` are the words after `git`.
export function gitWrites(args: string[]): [string, boolean][] {
  const call = gitCall(args);
  if (typeof call === "string") return [];
  const sub = call.sub ?? "";
  const out: [string, boolean][] = [];
  const rest = call.rest;
  for (let i = 0; i < rest.length; i++) {
    const w = rest[i];
    if (w === "--") break;
    if (w.startsWith("--") && abbreviates(w, ["--output", "--output-directory"])) {
      const dir = !"--output".startsWith(w.split("=")[0]) || w.split("=")[0].length > "--output".length;
      out.push([w.includes("=") ? w.slice(w.indexOf("=") + 1) : (rest[++i] ?? ""), dir && sub === "format-patch"]);
    } else if ((sub === "format-patch" || sub === "archive") && /^-[a-zA-Z]*o/.test(w) && !w.startsWith("--")) {
      const at = w.indexOf("o");
      out.push([at + 1 < w.length ? w.slice(at + 1) : (rest[++i] ?? ""), sub === "format-patch"]);
    }
  }
  // Written with --check and --stat too (round 4, finding 20), by every spelling git takes
  // (second pass: `--build-f=`, the value as the next word, after the operands).
  if (sub === "apply") {
    const fake = lastOf(getopt(rest, GIT_OPTIONS.apply), "build-fake-ancestor");
    if (fake !== undefined) out.push([fake, false]);
  }
  if (sub === "bundle") {
    const words = rest.filter((w) => !w.startsWith("-"));
    if (words[0] === "create" && words[1]) out.push([words[1], false]);
  }
  // git resolves a relative name in the directory `-C` took it to: the whole chain, a later
  // absolute `-C` starting over (second pass). One known only at run time leaves the place
  // unknown: the name keeps the `-C` words, which the caller cannot place.
  const base = gitBase(call.dirs);
  if (!call.dirs.length) return out;
  return out.map(([w, dir]): [string, boolean] => [/^[\/~]/.test(w) || /[$`]/.test(w) ? w : base === undefined ? `${call.dirs.join("/")}/${w}` : `${base}/${w}`, dir]);
}

// Every `git` word in the command (after `sudo`, `xargs`, `env`, in a substitution, inside a
// quoted `sh -c` string) is read as a git call with the real words bash would pass. `exists`
// tells whether a word names a file or directory where the command runs (a `checkout` operand).
// `exists(word, at)`: whether a word names something on disk where the command runs; `at` is the
// index of the command among the commands of the text at depth 0 (round 4, finding 19, second
// pass: each git call looks where its own command runs), -1 where that is not known (a nested
// shell's code that changes directory).
//
// `runs` (round 4, finding 7, third pass: E1): whether the text is code that runs: the command
// itself, or a word of it that is no argument of a program that reads its arguments only as text
// (a nested shell's code, eval's, watch's). gitConfigTouch asks so that an approved run of a git
// command happens outside the sandbox, which only means something where git runs. A git word
// counts as running unless it, or a word that holds it, is an argument of such a program
// (textArgument, whatever the command does with its output): `grep -rn "git clone" README.md |
// head` reads a pattern; `bash -c 'git init x'`, `env git clone URL`, `eval git init x` and
// `watch git init x` run git. The other checks of gitCallProblem read as widely as before.
export function gitProblem(command: string, depth = 0, exists?: (word: string, at?: number) => boolean, at?: number, outer = true, runs = true): string | undefined {
  if (depth > 3) return undefined;
  const cmds = parse(command).cmds;
  // Where no output of the command can be run (no pipe, substitution, background job or redirect
  // to a file anywhere in it, nor in the command whose nested shell this is: `bash -c 'echo ...'
  // | bash`), the arguments of a program that only reads its arguments as text are text (see
  // textArgument).
  const contained = outer && cmds.every((c) => !c.subshell && c.out.every((o) => /^(\/dev\/null|&\d*-?)$/.test(o)));
  for (const [n, cmd] of cmds.entries()) {
    const { argv } = cmd;
    const here = depth === 0 ? n : at;
    const look = exists && ((w: string) => exists(w, here));
    for (let i = 0; i < argv.length; i++) {
      const text = textArgument(argv, i);
      if (contained && text) continue;
      if (path.basename(argv[i]) === "git") {
        const call = gitCall(argv.slice(i + 1));
        if (typeof call === "string") return call;
        // Words may be added after the ones written.
        const more = argv.slice(0, i).some((w) => /^(xargs|parallel)$/.test(path.basename(w)));
        const found = gitCallProblem(call, look, more, runs && !text);
        if (found) return found;
      } else if (/\s/.test(argv[i]) && /\bgit\b/.test(argv[i])) {
        const inner = gitProblem(argv[i], depth + 1, exists, /(^|[\s;&|(])(cd|pushd|popd)(\s|$|;)/.test(argv[i]) ? -1 : here, contained, runs && !text);
        if (inner) return inner;
      }
    }
  }
  return undefined;
}

// Whether argv[i] is an argument of a program that reads its arguments only as text (round 4,
// finding 7, second pass): a pattern, a message, a string to print. `echo "git config a b"`,
// `grep -rn 'git fetch -f' .` and `git log -S 'git config x'` name a git command and run none, and
// their words are not read as one. An allowlist: echo, printf, the grep family, and git's own
// arguments (where git runs one of its words, gitCallProblem asks: `-c`, `--exec`, `rebase -x`,
// `submodule foreach`, `bisect run`); awk and sed only when their programs neither run commands
// nor write (awkScript, sedProblem). Every other program's argument holding a git command may be
// code that runs (a nested shell, `watch`, `ssh`, `su -c`, `flock -c`, `script -c`) and is read.
const TEXT_ARGUMENTS = new Set(["echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "git"]);
function textArgument(argv: string[], i: number): boolean {
  const runs = programs(argv);
  if (runs.includes(i)) return false;
  const owner = runs.filter((p) => p < i).at(-1);
  if (owner === undefined) return false;
  const name = path.basename(argv[owner]);
  const args = argv.slice(owner + 1);
  if (TEXT_ARGUMENTS.has(name)) return true;
  if (AWKS.has(name)) return args.every((a) => !awkScript(a));
  if (name === "sed") return !sedProblem(args);
  return false;
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

// Variables that change which program runs, what it loads or where its config comes from, or
// how a shell reads its code (BASHOPTS=extglob, SHELLOPTS=history:histexpand, POSIXLY_CORRECT).
// Round 3 (finding 10) adds the per-program option and config variables that run a program or
// load a config that can: TAR_OPTIONS (--to-command), MAKEFILES and GNUMAKEFLAGS (makefiles,
// --eval), RIPGREP_CONFIG_PATH (--pre), GREP_OPTIONS, LESSOPEN/LESSCLOSE (input filters), man's
// MANOPT (-C, -P), MANPAGER, MANROFFOPT (-U: unsafe groff), MAN_DISABLE_SECCOMP, MANPATH,
// GROFF_* (GROFF_BIN_PATH picks the programs), FZF_DEFAULT_COMMAND/_OPTS (--preview),
// RSYNC_RSH/RSYNC_CONNECT_PROG, CURL_HOME and WGETRC (a config file sets any option), DOCKER_HOST,
// DOCKER_CONFIG and DOCKER_CONTEXT (another daemon, credential helpers), KUBECONFIG and AWS_*
// (exec credential plugins, credential_process, AWS_PAGER), GOOGLE_APPLICATION_CREDENTIALS and
// CLOUDSDK_* (executable-sourced credentials), PWD and OLDPWD (the rules read `$PWD` as the
// working directory; `cd -` goes to OLDPWD), RUSTFLAGS and its kin (`-C linker=`), JAVA_HOME,
// GOTOOLCHAIN and GOENV (another toolchain, downloaded or from a config file), PYTHONWARNINGS and
// PYTHONBREAKPOINT (import a module), VIRTUAL_ENV (which interpreter uv runs), LUA_* (LUA_INIT
// runs code), PERLLIB and PERL5DB, GCONV_PATH (glibc loads modules from it), SUDO_EDITOR,
// SUDO_ASKPASS, SYSTEMD_PAGER/_EDITOR, BAT_* (pager, config), GH_* (pager, browser, editor, config),
// BUNDLE_* (another Gemfile), POETRY_*, PIPENV_*, PDM_*, HATCH_*, YARN_* (yarnPath runs JS) and
// COREPACK_* (downloads a package manager). DOCKER_BUILDKIT and the like stay with the model.
// Third pass (n6): GLOBIGNORE (once set, `*` matches dot files: `GLOBIGNORE=x; cat *` reads
// .env), GLOBSORT (bash 5.3: the order of a glob's words, so which one is `cp`'s destination),
// EXECIGNORE (which files a PATH search passes over, so which program a word runs) and
// BASH_LOADABLES_PATH (where `enable -f` finds a builtin to load) are bash's own variables that
// change what a word runs or a pattern matches, held as IFS and CDPATH are.
const ENV_DANGEROUS =
  /^(PATH|HOME|IFS|CDPATH|GLOBIGNORE|GLOBSORT|EXECIGNORE|BASH_LOADABLES_PATH|SHELL|ENV|BASH_ENV|BASH_FUNC.*|BASHOPTS|SHELLOPTS|POSIXLY_CORRECT|BASH_COMPAT|BASH_ALIASES|BASH_CMDS|histchars|PROMPT_COMMAND|PS[0-4]|EDITOR|VISUAL|PAGER|BROWSER|TMPDIR|GIT_.*|SSH_.*|LD_.*|DYLD_.*|XDG_.*|PYTHON(PATH|STARTUP|HOME|USERBASE|WARNINGS|BREAKPOINT)|NODE_(OPTIONS|PATH)|PERL5(LIB|OPT|DB)|PERLLIB|RUBY(OPT|LIB)|GEM_(HOME|PATH)|GO(FLAGS|PATH|ROOT|BIN|PROXY|NOSUMDB|INSECURE|PRIVATE|TOOLCHAIN|ENV)|RUSTC.*|RUSTUP_.*|RUSTFLAGS|RUSTDOCFLAGS|CARGO_(HOME|BUILD_.*|TARGET_.*_(RUNNER|LINKER|RUSTFLAGS)|REGISTR.*|ENCODED_RUSTFLAGS)|CC|CXX|LD|AR|MAKEFLAGS|GNUMAKEFLAGS|MAKEFILES|npm_config_.*|NPM_CONFIG_.*|PIP_.*|UV_.*|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JAVA_HOME|MAVEN_OPTS|GRADLE_.*|OPENCODE.*|AUTOMODE_.*|TAR_OPTIONS|RIPGREP_CONFIG_PATH|GREP_OPTIONS|LESSOPEN|LESSCLOSE|MANOPT|MANPAGER|MANROFFOPT|MAN_DISABLE_SECCOMP|MANPATH|GROFF_.*|FZF_DEFAULT_(COMMAND|OPTS)|RSYNC_(RSH|CONNECT_PROG)|CURL_HOME|WGETRC|DOCKER_(HOST|CONFIG|CONTEXT|CERT_PATH)|KUBECONFIG|AWS_.*|GOOGLE_APPLICATION_CREDENTIALS|CLOUDSDK_.*|PWD|OLDPWD|VIRTUAL_ENV|LUA_.*|GCONV_PATH|SUDO_(EDITOR|ASKPASS)|SYSTEMD_(PAGER|EDITOR)|BAT_.*|GH_.*|BUNDLE_.*|POETRY_.*|PIPENV_.*|PDM_.*|HATCH_.*|YARN_.*|COREPACK_.*)$/;
// Values of a dangerous variable that change nothing that runs (round 3, finding 28, signed
// off): NODE_OPTIONS made only of options that load no code, `PAGER=cat`, `GIT_PAGER=cat`, a
// bare compiler name for CC and CXX, and a PYTHONPATH whose every entry lies in the project.
// The same list holds for `NAME=value` arguments of make.
const NODE_OPTIONS_OK = [
  /^--max-old-space-size=\d+$/, /^--max-semi-space-size=\d+$/, /^--stack-size=\d+$/, /^--max-http-header-size=\d+$/, /^--enable-source-maps$/, /^--no-warnings$/,
  /^--no-deprecation$/, /^--trace-warnings$/, /^--trace-deprecation$/, /^--trace-uncaught$/, /^--throw-deprecation$/, /^--expose-gc$/, /^--experimental-vm-modules$/,
  /^--no-experimental-fetch$/, /^--openssl-legacy-provider$/, /^--unhandled-rejections=(strict|warn|none|throw|warn-with-error-code)$/, /^--dns-result-order=(ipv4first|ipv6first|verbatim)$/,
  /^--disable-warning=[\w-]+$/,
];
const COMPILER = /^(gcc|g\+\+|cc|c\+\+|clang|clang\+\+)(-\d+(\.\d+)*)?$/;
// An editor that does nothing, set for a git command that would otherwise open one (round 3,
// finding 13, signed off): `GIT_EDITOR` or `GIT_SEQUENCE_EDITOR` set to `true` or `:`, and
// `GIT_MERGE_AUTOEDIT=no`. Only before `git commit`, `git merge` and `git rebase`, `cherry-pick`,
// `revert`, `merge` or `am` with `--continue` (editorCommand); any other value or command asks.
export const EDITOR_ASSIGNMENT = /^(GIT_EDITOR=(true|:)|GIT_SEQUENCE_EDITOR=(true|:)|GIT_MERGE_AUTOEDIT=no)$/;
const EDITOR_VARIABLES = /^(GIT_EDITOR|GIT_SEQUENCE_EDITOR|GIT_MERGE_AUTOEDIT)$/;
export function editorCommand(argv: string[]): boolean {
  if (argv[0] !== "git") return false;
  const call = gitCall(argv.slice(1));
  if (typeof call === "string") return false;
  if (call.sub === "commit" || call.sub === "merge") return true;
  return ["rebase", "cherry-pick", "revert", "merge", "am"].includes(call.sub ?? "") && call.rest.length === 1 && call.rest[0] === "--continue";
}
// `inProject` gets an absolute path; `cwd` is undefined when the command's directory is unknown.
export function envValueOk(name: string, value: string, cwd: string | undefined, inProject: ((p: string) => boolean) | undefined): boolean {
  // Exactly as written: these are not lists.
  if (name === "GIT_EDITOR" || name === "GIT_SEQUENCE_EDITOR") return value === "true" || value === ":";
  if (name === "GIT_MERGE_AUTOEDIT") return value === "no";
  // The variable's value from your environment (`PYTHONPATH=src:$PYTHONPATH`): an assignment of it
  // anywhere in the call is judged on its own.
  const inherited = new RegExp(`(^|[:\\s])\\$(${name}|\\{${name}\\})(?=$|[:\\s])`, "g");
  value = value.replace(inherited, "$1").replace(/^[:\s]+|[:\s]+$/g, "").replace(/::+/g, ":");
  if (/[$`\\'"]/.test(value)) return false;
  if (name === "NODE_OPTIONS") {
    const options = value.trim().split(/[ \t]+/);
    return options.every((o) => NODE_OPTIONS_OK.some((re) => re.test(o)));
  }
  if (name === "PAGER" || name === "GIT_PAGER") return value === "cat";

  if (name === "CC" || name === "CXX") return COMPILER.test(value);
  if (name === "PYTHONPATH") {
    if (!inProject || /[*?[{~\s]/.test(value)) return false;
    return value.split(":").every((entry) => {
      if (!path.isAbsolute(entry) && cwd === undefined) return false;
      return inProject(path.resolve(cwd ?? "/", entry || "."));
    });
  }
  return false;
}
// Variables that only change output or verbosity.
const ENV_HARMLESS =
  /^(NODE_ENV|CI|DEBUG|VERBOSE|FORCE_COLOR|NO_COLOR|CLICOLOR(_FORCE)?|TERM|COLORTERM|COLUMNS|LINES|LANG|LANGUAGE|LC_[A-Z]+|TZ|RUST_BACKTRACE|RUST_LOG|CARGO_TERM_[A-Z_]+|CARGO_INCREMENTAL|PYTHONUNBUFFERED|PYTHONDONTWRITEBYTECODE|PYTHONHASHSEED|PYTEST_ADDOPTS|LOG_LEVEL|PORT|HOST|TEST_[A-Z0-9_]+|GOMAXPROCS|JOBS|NINJA_STATUS)$/;
const ASSIGN = /^([A-Za-z_]\w*)\+?=/;
const DECLARERS = new Set(["export", "declare", "typeset", "readonly", "local"]);
const dangerous = (variable: string) => `sets ${variable}, which changes what programs run or load`;
// Whether a variable of this name changes what programs run or load (for the callers outside).
export const dangerousName = (name: string) => ENV_DANGEROUS.test(name);

const INSTALLERS: Record<string, Set<string>> = {
  pip: new Set(["install", "download", "wheel"]),
  uv: new Set(["add", "sync", "tool"]),
  cargo: new Set(["install", "binstall", "add"]),
  go: new Set(["install", "get"]),
  gem: new Set(["install", "update"]),
};
INSTALLERS.pip3 = INSTALLERS.pip;
for (const pm of ["npm", "pnpm", "yarn", "bun"]) {
  INSTALLERS[pm] = new Set(["install", "i", "ci", "add", "update", "up", "upgrade", "dedupe", "rebuild", "link", "exec", "x", "dlx", "create", "init", "import", "install-test", "it", "install-ci-test", "cit"]);
}
// `pnpm exec` runs a program already in the project (node_modules/.bin or PATH) and downloads
// nothing; the rules unwrap it as a runner and judge the program, as the traversal does here.
INSTALLERS.pnpm.delete("exec");

// Commands that name a path without showing what is in it (as in the rules).
const NAMES_ONLY = new Set("ls stat test [ file du find readlink realpath basename dirname which echo printf rm rmdir unlink mkdir touch chmod chown chgrp setfacl tee truncate shred cd pushd".split(" "));
// Programs that show or copy what is in the files they are given.
const READERS = new Set(
  `cat bat head tail less more grep egrep fgrep rg ag ack sed awk gawk cut sort uniq tr diff cmp comm nl tac rev fold paste join
   strings xxd hexdump od base64 base32 jq yq zcat xzcat bzcat zstdcat cp mv ln rsync install tar zip gzip xz zstd dd openssl curl wget`.split(/\s+/),
);
const SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh", "source", "."]);
const INTERPRETERS = new Set(["python", "python3", "node", "perl", "ruby", "php", "lua", "deno", "bun", "tsx", "ts-node"]);
// Builds and test runners that run the file they are handed.
const FILE_RUNNERS = new Set(["pytest", "vitest", "jest", "mocha", "go", "just"]);
const AWKS = new Set(["awk", "gawk", "mawk", "nawk"]);
const MAKES = new Set(["make", "gmake"]);

// One code point, as a regular expression that matches exactly it.
const codePoint = (c: string) => `\\u{${c.codePointAt(0)!.toString(16)}}`;
// bash's character classes as glibc's UTF-8 locales draw them: exact for ASCII, and for other
// characters by the Unicode properties glibc's tables are made from.
const GLOB_CLASSES: Record<string, string> = {
  digit: "[0-9]",
  xdigit: "[0-9A-Fa-f]",
  upper: "\\p{CWL}",
  lower: "[\\p{CWU}\\u{df}]",
  alpha: "(?![0-9])[\\p{Alphabetic}\\p{Nd}]",
  alnum: "[\\p{Alphabetic}\\p{Nd}]",
  word: "[\\p{Alphabetic}\\p{Nd}_]",
  space: "(?![\\u{a0}\\u{2007}\\u{202f}])[\\t-\\r\\p{Zs}\\p{Zl}\\p{Zp}]",
  blank: "(?![\\u{a0}\\u{2007}\\u{202f}])[\\t\\p{Zs}]",
  cntrl: "[\\p{Cc}\\p{Zl}\\p{Zp}]",
  print: "[^\\p{Cc}\\p{Cn}\\p{Cs}\\p{Zl}\\p{Zp}]",
  graph: "(?![\\p{Zs}])[^\\p{Cc}\\p{Cn}\\p{Cs}\\p{Zl}\\p{Zp}]",
  punct: "(?![\\p{Zs}\\p{Alphabetic}\\p{Nd}])[^\\p{Cc}\\p{Cn}\\p{Cs}\\p{Zl}\\p{Zp}]",
};
// What a glob segment matches, as bash 5.2's own matcher decides it (round 4, finding 6, second
// pass): a port of GMATCH and BRACKMATCH (bash's lib/glob/sm_loop.c) for code points, held to
// bash by test/glob.test.mts and by a fuzzer. The first pass compiled the bracket to a regular
// expression of its own reading, and read some brackets as unclosed that bash closes (`[^[=ab=]`,
// `[?-[:punct:]`); a port has bash's reading by construction, quirks included:
//   - `!` or `^` after the `[` negates; the first member is a member even when it is `]`;
//   - `[=c=]` (one character) is an equivalence class, `[:name:]` a class, `[.c.]` the character
//     c and `[.name.]` one of bash's named symbols; a `[=` or `[.` of any other shape is plain
//     text, and so its `]` can close the bracket; a `[:` with no `:]` after it is dropped;
//   - a range runs by code point (bash 5's `globasciiranges`, which `shopt` cannot switch off
//     here: the scanner asks about `shopt`); a range end is one character or a `[.c.]`, so
//     `[?-[:punct:]` is the range `?` to `[` followed by the characters `:punct:`;
//   - a bracket nothing closes matches a `[` and nothing else, and matching goes on after it;
//   - once a member has matched, bash skips to the end of the bracket by another reading than
//     the one it uses to look for a match, and the port does the same.
// A backslash is a plain character here: the guard is given a word without its quotes, where an
// unquoted backslash is gone, and canon.ts asks about a quoted or escaped character inside a
// bracket (bash reads it as a plain member, which the word without its quotes cannot show).
//
// What bash reads by the locale, or by tables of its own, the port does not decide: an
// equivalence class against another character, a named collating symbol, a class name it does
// not know, a range with a collating symbol at one end (compared by the locale's collation) and a
// range that runs backwards. There the port takes both outcomes, so its match is the widest bash
// could make, and says the answer is not sure when the two outcomes differ: expandWord() then
// cannot tell, and protectedNameIn() holds the pattern to the wider match.
export interface GlobAnswer {
  match: boolean;
  sure: boolean;
}
const GLOB_CLASS_TESTS: Record<string, RegExp> = Object.fromEntries(Object.entries(GLOB_CLASSES).map(([name, re]) => [name, new RegExp(`^${re}$`, "su")]));
// Undefined where bash's matcher reads no collating symbol (a `[.` with no `.]` after it, or a name
// bash does not know), "named" for one of bash's named symbols, else the character.
function collatingSymbol(P: string[], p: number): { value: string | "named" | undefined; next: number } {
  let k = p + 1;
  while (k < P.length && !(P[k] === "." && P[k + 1] === "]")) k++;
  if (k >= P.length) return { value: undefined, next: k };
  const name = P.slice(p + 1, k);
  return { value: name.length === 1 ? name[0] : BASH_COLLATING_NAMES.has(name.join("")) ? "named" : undefined, next: k + 2 };
}
// bash's table of POSIX collating symbol names (lib/glob/collsyms.h).
const BASH_COLLATING_NAMES = new Set(
  ("NUL SOH STX ETX EOT ENQ ACK alert BEL backspace tab newline vertical-tab carriage-return BS HT LF VT FF CR SO SI DLE DC1 DC2 DC3 DC4 NAK SYN ETB CAN EM SUB ESC IS4 FS IS3 GS IS2 RS IS1 US " +
    "form-feed space exclamation-mark quotation-mark number-sign dollar-sign percent-sign ampersand apostrophe left-parenthesis right-parenthesis asterisk plus-sign comma hyphen hyphen-minus period full-stop slash solidus " +
    "zero one two three four five six seven eight nine colon semicolon less-than-sign equals-sign greater-than-sign question-mark commercial-at left-square-bracket backslash reverse-solidus right-square-bracket " +
    "circumflex circumflex-accent underscore low-line grave-accent left-brace left-curly-bracket vertical-line right-brace right-curly-bracket tilde DEL").split(" "),
);
export function globMatcher(segment: string): (name: string) => GlobAnswer {
  const P = [...segment];
  return (name: string) => {
    const S = [...name];
    let sure = true;
    // The places in P where matching goes on once the bracket whose `[` stands just before
    // P[savep] has been tried on the character t (none: no match).
    const bracket = (savep: number, t: string): number[] => {
      const test = t.codePointAt(0)!;
      const unclosed = () => (t === "[" ? [savep] : []);
      let p = savep;
      const not = P[p] === "!" || P[p] === "^";
      if (not) p++;
      // bash's `matched:`: the skip to the end of the bracket. `q` is where its `p` stands.
      // Where no probe has pinned bash's reading down: the bracket may end after any `]` from `p`
      // on, or nowhere, with a match (`matched`) or either way, and the answer is not sure.
      const anyEnd = (p: number, matched: boolean): number[] => {
        sure = false;
        return [...unclosed(), ...(matched && not ? [] : P.flatMap((x, k) => (k >= p && x === "]" ? [k + 1] : [])))];
      };
      // There a `[.` is passed over up to its `.]`, and with none it runs to the end; a `[=` or
      // `[:` is passed over up to its `=]` or `:]` when no other `]` comes first, and is plain
      // text otherwise (probed in bash 5.2: xcheck/glob/skip.mts). One with a `[` before its
      // closer bash reads in levels no probe has pinned down.
      const matched = (q: number): number[] => {
        let p = q;
        let c: string | undefined = P[--p];
        for (;;) {
          if (c === undefined) return unclosed();
          c = P[p++];
          if (c === "[" && (P[p] === "=" || P[p] === ":" || P[p] === ".")) {
            const type = P[p];
            let close = p + 1;
            while (close < P.length && !(P[close] === type && P[close + 1] === "]") && (type === "." || P[close] !== "]") && P[close] !== "[") close++;
            if (P[close] === "[") return anyEnd(p, true);
            if (close >= P.length && type === ".") return unclosed();
            if (close < P.length && P[close] === type) {
              p = close + 2;
              c = "]";
            }
          } else if (c === "]") return not ? [] : [p];
        }
      };
      // A member read by the locale: both outcomes.
      const both = (q: number, otherwise: () => number[]): number[] => {
        const yes = matched(q);
        const no = otherwise();
        if (yes.length !== no.length || yes.some((v, i) => v !== no[i])) sure = false;
        return [...new Set([...yes, ...no])];
      };
      // The loop of BRACKMATCH from a member `c` with `p` after it.
      const scan = (p: number, c: string | undefined): number[] => {
        for (;;) {
          // After a member that does not match: the next one, or the end.
          const next = (p: number, c: string | undefined) => (): number[] => (c === "]" ? (not ? [p] : []) : scan(p, c));
          let start: number | "named" | undefined = c?.codePointAt(0);
          let forcecoll = false;
          if (c === "[" && P[p] === "=" && P[p + 1] !== undefined && P[p + 2] === "=" && P[p + 3] === "]") {
            const pc = P[p + 1];
            p += 4;
            const after = p;
            const otherwise = () => (P[after] === undefined ? unclosed() : scan(after + 1, P[after]));
            if (pc === t) return matched(after + 1);
            return both(after + 1, otherwise);
          }
          if (c === "[" && P[p] === ":") {
            let close = p + 1;
            while (close < P.length && !(P[close] === ":" && P[close + 1] === "]")) close++;
            // A class name with a bracket in it: see anyEnd.
            if (close < P.length && P.slice(p + 1, close).some((x) => x === "[" || x === "]")) return anyEnd(p, false);
            let pc: boolean | undefined = false;
            if (close < P.length) {
              const re = GLOB_CLASS_TESTS[P.slice(p + 1, close).join("")];
              pc = re ? re.test(t) : undefined;
              p = close + 2;
            }
            const after = p;
            const otherwise = (): number[] => (P[after] === undefined ? unclosed() : P[after] === "]" ? (not ? [after + 1] : []) : scan(after + 1, P[after]));
            if (pc === true) return matched(after + 1);
            if (pc === undefined) return both(after + 1, otherwise);
            return otherwise();
          }
          if (c === "[" && P[p] === ".") {
            const sym = collatingSymbol(P, p);
            p = sym.next;
            start = sym.value === undefined ? test + 1 : sym.value === "named" ? "named" : sym.value.codePointAt(0)!;
            forcecoll = true;
          }
          if (c === undefined) return unclosed();
          c = P[p++];
          if (c === undefined) return unclosed();
          if (c === "-" && P[p] !== "]") {
            const raw = P[p++];
            if (raw === undefined) return [];
            let end: number | "named" = raw.codePointAt(0)!;
            if (raw === "[" && P[p] === ".") {
              const sym = collatingSymbol(P, p);
              p = sym.next;
              end = sym.value === undefined ? test - 1 : sym.value === "named" ? "named" : sym.value.codePointAt(0)!;
              forcecoll = true;
            }
            c = P[p++];
            // By the locale's collation, or backwards: not read.
            if (forcecoll || start === "named" || end === "named" || start! > end) {
              return both(p, next(p, c));
            }
            if (test >= start! && test <= end) return matched(p);
            if (c === "]") return not ? [p] : [];
            continue;
          }
          if (start === "named") return both(p, next(p, c));
          if (test === start) return matched(p);
          if (c === "]") return not ? [p] : [];
        }
      };
      return scan(p + 1, P[p]);
    };
    const memo = new Map<number, boolean>();
    const gmatch = (p: number, s: number): boolean => {
      const key = p * (S.length + 1) + s;
      const known = memo.get(key);
      if (known !== undefined) return known;
      let result: boolean;
      const c = P[p];
      if (c === undefined) result = s === S.length;
      else if (c === "*") {
        result = false;
        for (let k = s; k <= S.length && !result; k++) result = gmatch(p + 1, k);
      } else if (s >= S.length) result = false;
      else if (c === "?") result = gmatch(p + 1, s + 1);
      else if (c === "[") result = bracket(p + 1, S[s]).some((e) => gmatch(e, s + 1));
      else result = S[s] === c && gmatch(p + 1, s + 1);
      memo.set(key, result);
      return result;
    };
    const match = gmatch(0, 0);
    return { match, sure };
  };
}

// The first of `names` that a path segment of `target` can be once bash has expanded it (round
// 3, finding 24): each brace alternative (a `{a..z}` range is read as a glob). A glob segment
// written to reach a protected name (it matches one and no ordinary name: `.g[i]t`, `.gi?`,
// `AGENTS.m?`, `lefthook.y*`) is held to the pattern, which may match a name that does not exist
// yet. A generic one (`*`, `*.md`, `.*`) is held to what it matches on disk where the command runs
// (`cwd`; unknown, it is held to the pattern too). As bash does, `*`, `?` and `[...]` match a
// leading dot only when the pattern starts with one.
const ORDINARY_NAMES = ["x", ".x", "x.md", "x.json", "x.jsonc", "x.yml", "x.yaml", "x.toml", "x.txt", "README.md", "x.sh"];
export function protectedNameIn(target: string, names: string[], cwd?: string): string | undefined {
  const alternatives = braceWords(target) ?? [target.replace(/\{[^{}]*\}/g, "*")];
  for (const alt of alternatives) {
    const segments = alt.split("/");
    for (const [k, segment] of segments.entries()) {
      if (names.includes(segment)) return segment;
      if (!/[*?[]/.test(segment)) continue;
      const glob = globMatcher(segment);
      // The widest match bash could make (see globMatcher), and whether it is sure.
      const matches = (n: string) => {
        const a = glob(n);
        return a.match && (segment.startsWith(".") || !n.startsWith(".")) ? a : undefined;
      };
      const hit = names.find((n) => matches(n));
      if (!hit) continue;
      if (!matches(hit)!.sure || !ORDINARY_NAMES.some((n) => matches(n)) || cwd === undefined || /[$`]/.test(alt)) return hit;
      const found = expandWord(segments.slice(0, k + 1).join("/") || "/", cwd);
      const existing = found === undefined ? hit : found.map((p) => path.basename(p)).find((n) => names.includes(n));
      if (existing) return existing;
    }
  }
  return undefined;
}

// Whether a segment of the word holds a form the matcher reads by the locale (see globMatcher),
// wherever a bracket could stand, whatever the names on disk: an equivalence class, a named
// collating symbol, a class name bash does not know, a range with a collating symbol at one end,
// or a range that runs backwards. Read from the text, so wider than what globMatcher finds unsure
// against the names a directory holds.
function localeForms(segment: string): boolean {
  const P = [...segment];
  const open = P.indexOf("[");
  if (open < 0) return false;
  for (let i = open; i < P.length; i++) {
    if (P[i] === "[" && P[i + 1] === "=" && P[i + 2] !== undefined && P[i + 3] === "=" && P[i + 4] === "]") return true;
    if (P[i] === "[" && P[i + 1] === "." && collatingSymbol(P, i + 1).value === "named") return true;
    if (P[i] === "[" && P[i + 1] === ":") {
      let close = i + 2;
      while (close < P.length && !(P[close] === ":" && P[close + 1] === "]")) close++;
      if (close < P.length && !GLOB_CLASS_TESTS[P.slice(i + 2, close).join("")]) return true;
    }
    if (P[i] === "-" && i > open && P[i + 1] !== undefined && P[i + 1] !== "]") {
      if ((P[i - 1] === "]" && P[i - 2] === ".") || (P[i + 1] === "[" && P[i + 2] === ".")) return true;
      if (P[i - 1].codePointAt(0)! > P[i + 1].codePointAt(0)!) return true;
    }
  }
  return false;
}
export const unreadableGlob = (word: string): boolean => (braceWords(word) ?? [word]).some((alt) => alt.split("/").some((segment) => /[*?[]/.test(segment) && localeForms(segment)));

// The files a word names once bash has expanded its braces and globs, or undefined when that
// cannot be known here (a variable, a substitution, a `{a..z}` range).
export function expandWord(word: string, cwd: string): string[] | undefined {
  return expandNames(word, cwd)?.map(physical);
}
// The same as bash lists them, each path as it is spelled (no link followed: B7-9, a name that
// leads through /proc/self must still show it).
export function expandNames(word: string, cwd: string): string[] | undefined {
  if (/[$`]/.test(word)) return undefined;
  const alternatives = braceWords(word);
  if (!alternatives) return undefined;
  const results: string[] = [];
  for (const alt of alternatives) {
    const t = tilde(alt);
    const absolute = path.isAbsolute(t) ? t : `${cwd}/${t}`;
    // bash globs a word with a `*` or a `?`, or a `[` with a `]` somewhere after it; any other
    // word stays as it is written, nullglob or not.
    if (!/[*?]|\[.*\]/s.test(alt)) {
      results.push(absolute);
      continue;
    }
    let dirs = ["/"];
    for (const segment of absolute.split("/").filter(Boolean)) {
      if (!/[*?[]/.test(segment)) {
        dirs = dirs.map((d) => `${d}/${segment}`);
        continue;
      }
      const glob = globMatcher(segment);
      const next: string[] = [];
      for (const d of dirs) {
        let names: string[];
        try {
          names = fs.readdirSync(d);
        } catch {
          continue;
        }
        for (const n of names) {
          // A leading dot is only matched by a pattern that starts with one.
          if (!segment.startsWith(".") && n.startsWith(".")) continue;
          const a = glob(n);
          // A name bash may or may not match, by the locale or by bash's own tables: unknown.
          if (a.match && !a.sure) return undefined;
          if (a.match) next.push(`${d}/${n}`);
        }
        if (next.length > 5000) return undefined;
      }
      dirs = next;
    }
    results.push(...dirs);
  }
  return results;
}

export interface TextContext {
  // The moment the session began, on the clock of the file system a judged file lives on (B7-1:
  // `file` and its device, as stat gives it); a number where there is one clock.
  began?: bigint | ((file: string, dev: bigint) => bigint);
  // B7-2: what the session and the call's other commands wrote (not `cmd` itself: `curl -O` in a
  // fresh session is not a program run after a write). Not by the order of the text: a command
  // written later runs earlier in a loop, from a function, or beside (`a & b`, `a | b`).
  others?: (cmd: Simple) => { written: Set<string>; unlisted: string[] };
  // B7-3: whether the configuration of the repository a git command works in names no program of
  // the project for a filter (clean, smudge, process) and, with `diff`, none for a diff either
  // (diff.external, diff.<driver>.command, diff.<driver>.textconv).
  gitFiltersAbsent?: (cmd: Simple, args: string[], diff?: boolean) => boolean;
  cwd: string;
  // False when the command changes directory, so a relative word cannot be placed.
  cwdKnown: boolean;
  scope: Scope;
  // Files this session (or this command) wrote, appended to or edited, by full path.
  written: () => Set<string>;
  // Whether an absolute path lies inside the project (PYTHONPATH, finding 28).
  inProject?: (p: string) => boolean;
  // Whether every `NAME=value` word of the call (the real words) gives NAME a value from the
  // signed-off list (finding 28).
  envOk?: (name: string) => boolean;
}

// The judge for envOk: every assignment word of NAME in the commands, where each runs.
export function envAssignmentsOk(cmds: Simple[], cwdOf: (cmd: Simple) => string | undefined, inProject: (p: string) => boolean): (name: string) => boolean {
  const values = new Map<string, [string | undefined, string | undefined][]>();
  for (const cmd of cmds) {
    for (const w of cmd.argv) {
      const m = /^([A-Za-z_]\w*)(\+?)=/.exec(w);
      if (m) values.set(m[1], [...(values.get(m[1]) ?? []), [m[2] ? undefined : w.slice(m[0].length), cwdOf(cmd)]]);
    }
  }
  return (name) => {
    const set = values.get(name);
    return !!set && set.every(([v, cwd]) => v !== undefined && envValueOk(name, v, cwd, inProject));
  };
}

// The variable names a word stands for once bash has expanded its braces; undefined when a glob,
// a variable or a substitution leaves the name unknown (`unset PAT?`, `read "$n"`).
function namesOf(word: string): string[] | undefined {
  if (/[$`*?[\]]/.test(word)) return undefined;
  return braceWords(word);
}
const anyDangerous = (word: string) => namesOf(word)?.some((n) => ENV_DANGEROUS.test(n)) ?? true;
// A variable the plugin's own environment exports (round 4, n6, third pass): the shell inherits it
// exported, so any assignment to it (`https_proxy=...` on a line of its own, `declare`, `read`,
// `printf -v`, a loop) reaches the programs that follow, as `export NAME=value` does, and is
// judged as that is. A name the check cannot read could be one. Not `_`, which bash sets itself
// before every command (and `for ((...))` is judged as a loop over `_`).
const inherited = (word: string) => !ENV_HARMLESS.test(word) && (namesOf(word)?.some((n) => n !== "_" && process.env[n] !== undefined) ?? true);

// The names arithmetic assigns (`(( NAME=1 ))`, `$(( NAME += 2 ))`, `NAME++`; collected by
// unmodelled on the text that runs, since the printer erases arithmetic from the judged text),
// held as a plain assignment to the name is (round 4, B3b): a name that changes what programs
// run or load asks (the scanner already asked), one the environment exports goes to the model.
export function arithmeticAssignments(names: Set<string>): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  for (const name of names) {
    if (ENV_DANGEROUS.test(name)) verdict = stricter(verdict, { action: "ask", reason: `arithmetic that ${dangerous(name)}` });
    else if (inherited(name)) verdict = stricter(verdict, { action: "classify", reason: `arithmetic sets ${name}, which the environment exports, for the programs that follow` });
  }
  return verdict;
}

// One simple command as the rules show it to a Matcher: `raw` as written, `bare` without
// wrappers and assignments (empty when nothing is left to run).
export function textGuard(raw: string, bare: string, ctx: TextContext): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  const add = (action: "ask" | "classify", reason: string) => void (verdict = stricter(verdict, { action, reason }));
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
    const assigned = ASSIGN.exec(w);
    const variable = assigned?.[1] ?? (declared.includes(w) && /^[A-Za-z_]\w*$/.test(w) ? w : undefined);
    if (!variable) continue;
    // A value from the signed-off list changes nothing that runs (finding 28).
    const value = assigned ? w.slice(assigned[0].length) : undefined;
    if (ENV_DANGEROUS.test(variable)) {
      // The rules' text is split on blanks here, so the value is judged on the real words.
      // An editor that does nothing only for the git commands that open one.
      if (value === undefined || w.includes("+=") || !ctx.envOk?.(variable) || (EDITOR_VARIABLES.test(variable) && !editorCommand(words))) add("ask", dangerous(variable));
    }
    // A variable set on a line of its own stays in the shell: only one set for a command, or
    // exported, reaches the programs it runs.
    else if (!ENV_HARMLESS.test(variable) && ASSIGN.test(w) && (exports || (prefix.includes(w) && words.length > 0))) add("classify", `sets ${variable} for the programs it runs`);
    else if (inherited(variable)) add("classify", `sets ${variable}, which the environment exports, for the programs that follow`);
  }
  // A loop variable is set without `NAME=`: `for NAME in`, and also `for NAME;` and `for NAME do`
  // (the positional parameters), the same for `select`. `coproc NAME` sets NAME to its pipe's
  // file descriptors (`$PATH` becomes `63`).
  const forAt = rawWords.findIndex((w) => w === "for" || w === "select" || w === "coproc");
  const loopName = forAt >= 0 ? rawWords[forAt + 1] : undefined;
  if (loopName !== undefined && (namesOf(loopName) ?? [loopName]).some((n) => ENV_DANGEROUS.test(n) || /[$`*?[]/.test(n))) add("ask", dangerous(loopName));
  else if (loopName !== undefined && inherited(loopName)) add("classify", `sets ${loopName}, which the environment exports, for the programs that follow`);
  return verdict;
}

// A word bash globs into a name that begins with `-` (round 4, N3): the program reads the name as
// an option, and the option checks, which read the word as written, never see it (`tar xf a.tar
// --to*` beside a file named `--to-command=rec`). The whole word is expanded, wherever a `-` or an
// `=` stands in it, against the tree as it stands where the command runs. Only a result that
// begins with `-` counts: `src/--ch*` and `./-*` name files. Returns the name; "unplaced" where
// the place is not known; undefined when no result begins with `-`. Where the word cannot be read
// (a form the matcher reads by the locale, an expansion in it, a `..` after the glob) the answer
// is taken from the text before its first glob or expansion: only a name that begins with that
// text can come of it, so a directory that holds no such name beginning with `-` passes. A word
// that begins with an expansion is left to the checks that hold it today. `shown` is the word
// with markExpansions' marks where `marked`; otherwise every `$` and backtick counts as one.
function optionGlob(shown: string, marked: boolean, cwd: string | undefined): { name: string; sure: boolean } | "unplaced" | undefined {
  const word = unmark(shown);
  if (!/[*?]|\[.*\]/s.test(word)) return undefined;
  const expansion = marked ? MARKS : /[$`]/;
  const alternatives = expansion.test(shown) ? undefined : braceWords(word);
  for (const alt of alternatives ?? [shown]) {
    if (/^[/~]/.test(alt)) continue;
    const first = alt.split("/")[0];
    const firstGlob = /[*?[{]/.test(first);
    if (alternatives && !/[*?]|\[.*\]/s.test(alt)) continue;
    if (!firstGlob && !first.startsWith("-")) continue;
    if (cwd === undefined) return "unplaced";
    const found = !alternatives || unreadableGlob(alt) || alt.split("/").includes("..") ? undefined : expandWord(alt, cwd);
    // (A pattern that ends in `/` matches directories only.)
    const files = alt.endsWith("/") ? found?.filter((f) => fs.statSync(f, { throwIfNoEntry: false })?.isDirectory() ?? true) : found;
    if (files) {
      const name = !files.length ? undefined : !firstGlob ? first : files.map((f) => path.relative(cwd, f).split("/")[0]).find((n) => n.startsWith("-"));
      if (name) return { name, sure: true };
      continue;
    }
    const at = alt.search(marked ? /[*?[{\u000e\u000f]/ : /[*?[{$`]/);
    if (at === 0 && expansion.test(alt[0])) continue;
    const lead = alt.slice(0, at < 0 ? alt.length : at);
    let name: string | undefined;
    try {
      if (lead.includes("/")) name = lead.startsWith("-") && fs.existsSync(path.join(cwd, lead.split("/")[0])) ? lead.split("/")[0] : undefined;
      else name = fs.readdirSync(cwd).find((n) => n.startsWith("-") && n.startsWith(lead));
    } catch {
      return "unplaced";
    }
    if (name) return { name, sure: false };
  }
  return undefined;
}

// Files a command is handed that bash names when it runs (round 3, finding 14): a glob or braces,
// a variable or a substitution. Decided on the real words with the marks markExpansions() puts
// where bash expands something, not on the rules' flattened text, where `'{print $1}'` looks like
// `"$f"`. A `$` bash leaves as it is (single quotes, a backslash, `foo$`) names nothing; a script
// that holds one is read as a possible glob with `?` in its place, so it is still held to the
// files it could match. A word bash expands is unknown to a reader, unless it is the variable of
// an enclosing `for NAME in <words>` loop whose words name files here (loopValues): each of those
// files is then tested as if it had been written out. Where the commands cannot be lined up with
// the marked reading (or inside a nested shell's code, which an outer expansion can rewrite)
// every `$` and backtick counts as an expansion, as before.
export function runtimeReads(command: string, where: Located, scope: Scope): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  const add = (action: "ask" | "classify", reason: string) => void (verdict = stricter(verdict, { action, reason }));
  const pairs = markedCommands(command);
  const top = parse(command).cmds.length;
  const aligned = !!pairs && pairs.length === where.cmds.length && pairs.every(([real], n) => real.argv.join("\0") === where.cmds[n].argv.join("\0"));
  // Round 4, finding 27 (signed off): the marks hold inside a nested shell's code too
  // (`bash -c 'grep "foo$" f'`: that `$` expands nothing), when no command of the call that
  // hands code to a nested shell has an expansion in any of its words: the code is then the
  // text the nested shell reads, and no outer expansion can rewrite it.
  const literalCode = !!pairs && pairs.every(([real, mark]) => !nestedBodies([real]).length || !mark.argv.some((w) => MARKS.test(w)));
  const marked = (n: number) => (aligned && (n < top || literalCode) ? pairs![n][1].argv : undefined);
  const loops = aligned ? loopValues(command, pairs!.slice(0, top), (n) => where.cwd.get(where.cmds[n])) : new Map<number, LoopVars>();
  where.cmds.forEach((cmd, n) => {
    const words = marked(n);
    const cwd = where.cwd.get(cmd);
    const { at, chain } = traverse(cmd.argv);
    for (const p of at) {
      const name = path.basename(cmd.argv[p]);
      const end = chain.find((q) => q > p) ?? cmd.argv.length;
      for (let k = p + 1; k < end; k++) {
        const word = cmd.argv[k];
        // Round 4, N3: a glob in any word, one that begins with `-` too, can become an option.
        // (Not the patterns of a `case`, which name no files.)
        const becomes = name === "case" ? undefined : optionGlob(words?.[k] ?? word, !!words, cwd);
        if (becomes === "unplaced") add("classify", `${word} is a glob that can match a name that begins with -, in a place the check cannot tell`);
        else if (becomes) add("ask", `${word} ${becomes.sure ? "matches" : "can match"} ${becomes.name}, which ${name} would read as an option`);
        if (word.startsWith("-") && !word.includes("=")) continue;
        const strip = (w: string) => w.replace(/^-[^=]*=/, "").replace(/^@/, "");
        const text = strip(word);
        const mark = words ? strip(words[k]) : undefined;
        const dynamic = mark === undefined ? /[$`]/.test(text) : MARKS.test(mark);
        if (dynamic) {
          if (!READERS.has(name)) continue;
          const looped = mark !== undefined ? loopUse(mark, loops.get(n), cwd) : undefined;
          if (!looped) {
            // A loop over a glob the matcher cannot read asks, as a reader given that glob does
            // (round 4, finding 6, second pass).
            const unreadable = mark !== undefined ? loopVariable(mark, loops.get(n))?.unreadable : undefined;
            add(unreadable ? "ask" : "classify", unreadable ? `${name} reads ${word}, a file of ${unreadable}, a glob the check cannot read` : `${name} reads a file named at run time: ${word}`);
            continue;
          }
          if (text === word) {
            const option = looped.find((v) => v.text.startsWith("-"));
            if (option) add("ask", `${word} can be ${option.text}, which ${name} would read as an option`);
          }
          const secret = NAMES_ONLY.has(name) ? undefined : looped.find((v) => readVerdict("read", v.file, scope));
          if (secret) add("ask", `${name} reads a credential file: ${word} can be ${secret.file}`);
          continue;
        }
        // A `$` or backtick bash leaves as it is: any character, as far as matching files goes.
        const pattern = text.replace(/[$`]/g, "?");
        if (!/[*?[{]/.test(pattern)) continue;
        // `~+` is bash's name for the directory the command runs in (hereWord): the glob behind it
        // is expanded there (the variant check of the place shape, F2: read as a directory called
        // `~+` it matched nothing, and `cat ~+/.en*` was a rule allow). `~-` and a directory-stack
        // entry are places the check does not know: a pattern it cannot expand.
        const here = pattern.startsWith("~") ? hereWord(pattern) : undefined;
        const placed = here && !here.elsewhere && cwd !== undefined ? `${cwd}${here.rest}` : pattern;
        const relative = !/^(\/|~\/|~$)/.test(placed);
        // A glob with a form bash reads by the locale counts as one the matcher cannot read, even
        // where no file here reaches that form (the first pass's reading, kept: see unreadableGlob).
        const files = here?.elsewhere || (relative && cwd === undefined) || unreadableGlob(placed) ? undefined : expandWord(placed, cwd ?? "/");
        if (!files) {
          // A pattern the matcher cannot read is a verdict (round 4, finding 6).
          if (READERS.has(name)) add(!/[$`]/.test(text) && unreadableGlob(text) ? "ask" : "classify", `${name} reads a file named at run time: ${word}`);
          continue;
        }
        // A file called `-rf` or `--to-command=x` becomes an option once the glob is expanded.
        const option = !text.includes("/") && text === word ? files.find((f) => path.basename(f).startsWith("-")) : undefined;
        if (option) add("ask", `${word} matches ${path.basename(option)}, which ${name} would read as an option`);
        const secret = NAMES_ONLY.has(name) ? undefined : files.find((f) => readVerdict("read", f, scope));
        if (secret) add("ask", `${name} reads a credential file: ${word} matches ${secret}`);
      }
    }
  });
  return verdict;
}

// ---- every input redirect (round 4, group B, third pass, second go) ----
//
// bash opens the file of every `<` it runs and hands it to the command as its input (probed with
// bash 5.2.37 and decoy files): on a simple command, on a compound command (`{ cat; } < F`,
// `while ...; done < F`, `( cat ) < F`) and on `[[ ]]`, whose substitutions read it; `exec < F`
// makes F the input of every command after it; `$(< F)` is bash's way to read F. The rules see
// such a file only for a simple command they read to the end, and only for the programs they know
// read it (`cat < F` asks, `tee o < F` did not). The pass before scanned the text for the input
// of a compound command, and disagreed with bash twice on its first check; canon.ts reads the
// command as bash does at every depth, so it lists every target it prints (Printed.inputs): at
// the top level, in substitutions and process substitutions, in heredoc bodies and in the code of
// nested shells. Each is held here to what the rules say of a file read, `cat '<path>'`, in every
// directory the call's commands may be in (`located`): a relative name where one of those is
// unknown is in a place the check cannot tell. A name known only at run time is held as
// runtimeReads holds `cat "$f"`: the model's, unless it is the variable of a loop over names the
// check knows, whose every value is then judged. A here-string and a heredoc hand the command
// text, not a file (what their substitutions run is a command of its own, and what those
// redirect is listed too).

// The literal path a printed word names, or why it has none. An unquoted `<`, `>` or parenthesis
// in a printed word is a process substitution (the printer quotes a literal one). The quotes are
// read before an expansion is looked for (B3c: `'price$USD.txt'` is a name, `"$f"` is not).
// `pwd`: the word begins with `$PWD`, the directory the command runs in (`path` is the rest).
// `lead`: the text before the first expansion.
type Named = { path: string; pwd: boolean } | { why: "runtime" | "unplaced"; lead: string };
function canonicalPath(word: string): Named {
  const pwd = /^(?:"\$PWD"|"\$\{PWD\}"|\$PWD|\$\{PWD\})(?=\/|$)/.exec(word);
  const rest = pwd ? word.slice(pwd[0].length) : word.replace(/^(?:"\$HOME"|"\$\{HOME\}"|\$HOME|\$\{HOME\})(?=\/|$)/, () => HOME.replace(/[\\'"$`]/g, "\\$&"));
  let p = "";
  for (let j = 0; j < rest.length; j++) {
    const ch = rest[j];
    if (ch === "'") {
      const end = rest.indexOf("'", j + 1);
      if (end < 0) return { why: "unplaced", lead: p };
      p += rest.slice(j + 1, end);
      j = end;
    } else if (ch === "\\") p += rest[++j] ?? "";
    else if (ch === '"') {
      let k = j + 1;
      let text = "";
      for (; k < rest.length && rest[k] !== '"'; k++) {
        if (rest[k] === "$" || rest[k] === "`") return { why: "runtime", lead: p + text };
        if (rest[k] === "\\" && /[$`"\\]/.test(rest[k + 1] ?? "")) k++;
        text += rest[k];
      }
      if (k >= rest.length) return { why: "unplaced", lead: p };
      p += text;
      j = k;
    } else if (ch === "$" || ch === "`" || "<>()".includes(ch)) return { why: "runtime", lead: p };
    else if ("*?[".includes(ch) || (ch === "~" && j > 0)) return { why: "unplaced", lead: p };
    else if (ch === "~") {
      if (pwd || !/^~(\/|$)/.test(rest)) return { why: "unplaced", lead: p };
      p += HOME;
    } else p += ch;
  }
  return { path: p, pwd: !!pwd };
}

// The names of the printed input targets that name a literal file, as the parser has them (no
// quotes): `'price$USD.txt'` is `price$USD.txt`.
export function literalTargets(inputs: string[]): Set<string> {
  const out = new Set<string>();
  for (const word of inputs) {
    const named = canonicalPath(word);
    if (!("why" in named) && !named.pwd) out.add(named.path);
  }
  return out;
}

// A target bash opens a network connection for, by its text (B3c): `/dev/tcp/<host>/<port>` and
// `/dev/udp/...`, as an input as much as an output. bash 5.2.37 also reads `/dev/fd/<n>`,
// `/dev/stdin`, `/dev/stdout` and `/dev/stderr` itself, as a copy of that descriptor: no file is
// opened (what opened the descriptor, a `3< F` before it, is a target of its own here).
const NETWORK_TARGET = /^\/dev\/(tcp|udp)\//;
const DESCRIPTOR_TARGET = /^\/dev\/(fd\/\d+|stdin|stdout|stderr)$/;

// `inputs`: the printed targets (Printed.inputs), and the same in their judged spelling
// (Printed.judgedInputs: a variable that plainly holds a literal is that literal); `command`: the
// judged text, `where` its commands placed from `start`.
export function inputReads(inputs: string[], command: string, where: Located, start: string | undefined, scope: Scope, judgedInputs: string[] = inputs): GuardVerdict | undefined {
  if (!inputs.length) return undefined;
  let verdict: GuardVerdict | undefined;
  const add = (action: "ask" | "classify", reason: string) => void (verdict = stricter(verdict, { action, reason: `a redirect hands a command ${reason}` }));
  // Every place a command of the call may run in (B3c: as bash goes there, see Place).
  const sets: Places[] = [start === undefined ? undefined : [startPlace(start)], ...where.places.values()];
  const unknown = sets.some((p) => p === undefined);
  const places = sets.flatMap((p) => p ?? []);
  const dirs = [...new Set(places.map((p) => p.real))];
  // The kernel opens the file by walking its path (a link before a `..` is followed first).
  const judge = (file: string, word: string) => {
    for (const f of new Set([file, physical(file)])) {
      const v = bashVerdict(`cat '${f.replace(/'/g, "'\\''")}'`, scope);
      if (v.action === "ask" || v.action === "deny") add("ask", `${word}: ${v.reason}`);
      else if (v.action === "classify") add("classify", `${word}: ${v.reason}`);
    }
  };
  const runtime = new Map<string, number>();
  for (const [i, run] of inputs.entries()) {
    const word = judgedInputs[i] ?? run;
    const named = canonicalPath(word);
    const texts = "why" in named ? [named.lead] : named.pwd ? [...new Set(places.map((p) => `${p.logical}${named.path}`))] : [named.path];
    if (texts.some((t) => NETWORK_TARGET.test(t))) {
      add("ask", `${word}, which bash opens as a network connection`);
      continue;
    }
    if ("why" in named) {
      if (named.why === "runtime") runtime.set(run, (runtime.get(run) ?? 0) + 1);
      else add("classify", `a file the check cannot place: ${word}`);
      continue;
    }
    if (named.pwd) {
      if (unknown) add("classify", `${word}, in a directory the check cannot place`);
      else for (const dir of dirs) judge(`${dir}${named.path}`, word);
    } else if (DESCRIPTOR_TARGET.test(named.path)) continue;
    else if (hereWord(named.path)) {
      // B5: `/proc/self/cwd/…` is the path under the directory the command runs in (the plugin
      // would read its own); another process's directory is a place the check cannot tell.
      const here = hereWord(named.path)!;
      if (here.elsewhere || unknown) add("classify", `${word}, in a directory the check cannot place`);
      else for (const p of places) for (const text of hereTexts(here, p)) judge(text, word);
    } else if (path.isAbsolute(named.path)) judge(named.path, word);
    else if (unknown) add("classify", `${word}, in a directory the check cannot place`);
    else for (const dir of dirs) judge(`${dir}/${named.path}`, word);
  }
  if (!runtime.size) return verdict;
  const looped = loopInputs(command, where);
  for (const [word, count] of runtime) {
    const values = looped(word, count);
    if (!values) add("classify", `a file named at run time: ${word}`);
    // B3d: each text the target stands for (the value with its suffix) is held to the test for a
    // network target, as a direct one is: as a file the rules read `/dev/tcp/...` as any path.
    else
      for (const v of values) {
        if (NETWORK_TARGET.test(v.text) || NETWORK_TARGET.test(v.file)) add("ask", `${word} (${v.text}), which bash opens as a network connection`);
        else judge(v.file, `${word} (${v.text})`);
      }
  }
  return verdict;
}

// The files a run-time input name stands for, when it is the variable of a `for NAME in <words>`
// loop over names the check knows (loopValues, loopUse: as runtimeReads reads `cat "$f"`), at the
// top level of the call. `count`: how many targets the printer listed with that spelling; the
// rules' parser must list as many input words that read the same, every one inside such a loop
// (a here-string the parser lists among them, or one it does not see, leaves the name unknown).
function loopInputs(command: string, where: Located): (word: string, count: number) => LoopValue[] | undefined {
  const pairs = markedCommands(command);
  const top = parse(command).cmds.length;
  if (!pairs || pairs.length !== where.cmds.length || !pairs.every(([real], n) => real.argv.join("\0") === where.cmds[n].argv.join("\0"))) return () => undefined;
  const loops = loopValues(command, pairs.slice(0, top), (n) => where.cwd.get(where.cmds[n]));
  return (word, count) => {
    const parsed = parse(word).cmds;
    if (parsed.length !== 1 || parsed[0].argv.length !== 1) return undefined;
    const want = parsed[0].argv[0];
    const values: LoopValue[] = [];
    let seen = 0;
    let ok = true;
    pairs.forEach(([real, mark], n) => {
      (real.in ?? []).forEach((w, j) => {
        if (w !== want) return;
        seen++;
        const m = n < top ? mark.in?.[j] : undefined;
        const v = m === undefined ? undefined : loopUse(m, loops.get(n), where.cwd.get(where.cmds[n]));
        if (v) values.push(...v);
        else ok = false;
      });
    });
    return ok && seen === count ? values : undefined;
  };
}

// One value a loop variable takes: the file, the text bash puts in the variable, and whether the
// text is the loop's own glob (left as it is when it matches nothing).
interface LoopValue {
  file: string;
  text: string;
  glob?: boolean;
}
// The variables of the loops a command sits in, each with its values and the directory the loop
// started in (relative values name files there).
// `unreadable`: the loop's word that is a glob the matcher cannot read (no values then).
type LoopVars = Map<string, { values: LoopValue[]; cwd: string | undefined; unreadable?: string }>;

// The variables of `for NAME in <words>` loops, for each command inside a loop's body (by index in
// `cmds`, the call's top-level commands as [real, marked] pairs). Only a loop whose words name
// files here: plain words, globs and braces, no expansion, the directory known for relative ones.
// Only a NAME the call mentions nowhere but in that one loop header and as `$NAME` or `${NAME}`
// (so nothing else sets it, and no other loop uses it). Loops end at `done`, as the rules' parser
// lists it; any imbalance gives nothing.
function loopValues(command: string, cmds: [Simple, Simple][], cwdOf: (n: number) => string | undefined): Map<number, LoopVars> {
  const out = new Map<number, LoopVars>();
  const open: (LoopVars | undefined)[] = [];
  for (const [n, [real, mark]] of cmds.entries()) {
    const argv = real.argv;
    if (argv[0] === "done") {
      if (!open.length) return new Map();
      open.pop();
      continue;
    }
    const vars: LoopVars = new Map();
    for (const frame of open) for (const [k, v] of frame ?? []) vars.set(k, v);
    if (vars.size) out.set(n, vars);
    let k = 0;
    while (k < argv.length && ["do", "then", "else", "elif", "if", "!", "{", "}", "time"].includes(argv[k])) k++;
    if (!["for", "while", "until", "select"].includes(argv[k] ?? "")) continue;
    const name = argv[k + 1] ?? "";
    const list = mark.argv.slice(k + 3);
    const cwd = cwdOf(n);
    const values: LoopValue[] = [];
    let known = argv[k] === "for" && argv[k + 2] === "in" && /^[A-Za-z_]\w*$/.test(name) && list.length > 0 && !list.some((w) => MARKS.test(w)) && onlyLoopVariable(command, name);
    let unreadable: string | undefined;
    for (const word of known ? list : []) {
      const glob = /[*?[{]/.test(word);
      if (glob && unreadableGlob(word)) {
        unreadable = word;
        break;
      }
      const relative = !/^(\/|~\/|~$)/.test(word);
      if (relative && cwd === undefined) {
        known = false;
        break;
      }
      values.push({ file: path.resolve(cwd ?? "/", tilde(word)), text: word, glob });
      if (!glob) continue;
      const files = expandWord(word, cwd ?? "/");
      if (!files) {
        known = false;
        break;
      }
      for (const file of files) values.push({ file, text: relative ? path.relative(cwd!, file) : file });
    }
    open.push(unreadable ? new Map([[name, { values: [], cwd, unreadable }]]) : known ? new Map([[name, { values, cwd }]]) : undefined);
  }
  return out;
}

// Whether `name` appears in the command only once as a bare word, as `for name`, and otherwise
// only as `$name` or `${name}`. Text-based and so stricter than needed: `-f` or a file `f` counts
// as a mention.
function onlyLoopVariable(command: string, name: string): boolean {
  let bare = 0;
  for (const m of command.matchAll(new RegExp(`(?<![\\w])${name}(?![\\w])`, "g"))) {
    const at = m.index!;
    if (command[at - 1] === "$") continue;
    if (command.slice(at - 2, at) === "${" && command[at + name.length] === "}") continue;
    if (!/(^|[\s;&|(])for[ \t]+$/.test(command.slice(0, at))) return false;
    bare++;
  }
  return bare === 1;
}

// The values a marked word stands for when it is a loop variable (`"$f"`, `$f`, `"${f}"`), alone
// or with plain text after a `/` (B3c: `"$dir/notes.txt"`, `"$dir"/notes.txt`), used in the
// directory its loop started in. Unquoted, bash splits and globs the value again: a value with a
// blank or a backslash, or a file name with a glob character, does not come through as it is.
// (The loop's own glob, left as it is when it matched nothing, matches nothing again.)
const LOOP_WORD = /^([\u000e\u000f])\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})(\/[A-Za-z0-9_@%+=:,.\/-]*)?$/;
// The loop variable a marked word is (`"$f"`, `$f`, `"${f}"`, with any such suffix), with its loop.
function loopVariable(mark: string, vars: LoopVars | undefined) {
  const m = LOOP_WORD.exec(mark.replace(/^([\u000e\u000f]\$(?:\w+|\{\w+\}))\u000f?(?=\/)/, "$1"));
  return m ? vars?.get(m[2] ?? m[3]) : undefined;
}
function loopUse(mark: string, vars: LoopVars | undefined, cwd: string | undefined): LoopValue[] | undefined {
  const m = LOOP_WORD.exec(mark.replace(/^([\u000e\u000f]\$(?:\w+|\{\w+\}))\u000f?(?=\/)/, "$1"));
  const loop = loopVariable(mark, vars);
  if (!m || !loop || loop.cwd !== cwd || loop.unreadable) return undefined;
  if (m[1] === MARK_UNQUOTED && loop.values.some((v) => /[\s\\]/.test(v.text) || (!v.glob && /[*?[]/.test(v.text)))) return undefined;
  const suffix = m[4];
  return suffix === undefined ? loop.values : loop.values.map((v) => ({ file: `${v.file}${suffix}`, text: `${v.text}${suffix}`, glob: v.glob }));
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

// ---- per command, with its real words ----

// Every simple command of a tool call with the words bash passes: the rules' own parse, and
// the same for each string a nested shell is handed.
export function allCommands(command: string, depth = 0): Simple[] {
  if (depth > 4) return [];
  const cmds = parse(command).cmds;
  return [...cmds, ...nestedBodies(cmds).flatMap((body) => allCommands(body, depth + 1))];
}

// ---- the programs a simple command runs ----
//
// One traversal for every argv guard (round 3, findings 8 and 9): the guards look wherever the
// rules look, and wherever bash and the wrapped programs really go. Three readings are joined:
//
//   - the words that could be a program after a chain of wrapper-like words (a wide net: any
//     word after `-exec`, after options, numbers, `NAME=value`, signal names),
//   - the program each wrapper and runner really runs, read with that wrapper's own options
//     (`env -u NAME`, `timeout -s SIG 5`, `nice -n 5`, `uv run --with x`, `xargs -I {}`, every
//     `find -exec`), where an option the guard does not know leaves the reading unknown,
//   - the program the rules judge (their `unwrap`, `sudo`, runner and `xargs` readings).
//
// When the rules judge another program than the one that runs (`env -u ls curl ...` is `ls` to
// them), or a wrapper or runner has an option the guard cannot read, the command asks.
const WRAPPER_NAMES = new Set(["env", "nice", "ionice", "timeout", "time", "command", "builtin", "nohup", "setsid", "stdbuf", "exec", "chrt", "taskset", "sudo", "doas", "xargs", "if", "then", "elif", "else", "do", "while", "until", "!", "{"]);
// What may stand between a wrapper and the program it runs: options, numbers and durations,
// `NAME=value`, signal and variable names, xargs' `{}`.
const WRAPPER_WORD = /^(-.*|\d+(\.\d+)?[smhd]?|[A-Z_][A-Z0-9_]*(=.*)?|\{\})$/;

// The rules' own reading (rules.ts `unwrap`, `command`): kept in step with the vendored file.
const RULES_KEYWORDS = new Set(["if", "then", "elif", "else", "do", "while", "until", "!", "{", "}"]);
const RULES_NOOP = new Set(["fi", "done", "esac", "for", "in"]);
const RULES_WRAPPERS = new Set(["env", "nice", "ionice", "timeout", "time", "command", "builtin", "nohup", "setsid", "stdbuf", "exec", "chrt", "taskset"]);
export const RUNNERS: Record<string, string> = { uv: "run", poetry: "run", pipenv: "run", pdm: "run", hatch: "run", pnpm: "exec", bundle: "exec" };
const RULES_RUNNER_VALUES = /^(--with|--python|-p|--project|--group|--extra|--env-file|--directory)$/;
const rulesAssign = (w: string) => /^[A-Za-z_][A-Za-z0-9_]*=/.test(w);
const afterFlagsAt = (argv: string[], i: number, takesValue: RegExp) => {
  while (i < argv.length && argv[i].startsWith("-")) i += takesValue.test(argv[i]) ? 2 : 1;
  return i;
};
// The index of the program the rules finally judge in a simple command, or -1 for none.
function rulesProgram(argv: string[]): number {
  let i = 0;
  for (let guard = 0; guard < 64; guard++) {
    while (i < argv.length && (RULES_KEYWORDS.has(argv[i]) || rulesAssign(argv[i]))) i++;
    if (i >= argv.length || RULES_NOOP.has(argv[i])) return -1;
    const name = path.basename(argv[i]);
    if (RULES_WRAPPERS.has(name)) {
      i++;
      if (name === "command" && /^-[vV]$/.test(argv[i] ?? "")) return -1;
      while (i < argv.length && (/^(-.*|\d+(\.\d+)?[smhd]?)$/.test(argv[i]) || rulesAssign(argv[i]))) i++;
      continue;
    }
    if (name === "sudo" || name === "doas") {
      i = afterFlagsAt(argv, i + 1, /^-[ugCDhpRrTU]$/);
      if (i >= argv.length) return -1;
      continue;
    }
    const sub = RUNNERS[name];
    if (sub && argv.slice(i + 1).find((a) => !a.startsWith("-")) === sub) {
      i = afterFlagsAt(argv, argv.indexOf(sub, i + 1) + 1, RULES_RUNNER_VALUES);
      if (i >= argv.length) return -1;
      continue;
    }
    if (name === "xargs") {
      i = afterFlagsAt(argv, i + 1, /^-[InPLsdE]$/);
      if (i >= argv.length) return -1;
      continue;
    }
    return i;
  }
  return -1;
}

// How a wrapper or runner takes its own options, as getopt does: short letters that are flags,
// letters that take a value (the rest of the word or the next word), letters whose value can only
// be attached, long flags and long options with a value (`--x=v` or `--x v`, any unique prefix).
interface OptionSpec {
  short?: string;
  shortValue?: string;
  shortAttached?: string;
  long?: string[];
  longValue?: string[];
  // `-5`, `--10`: numbers are options (nice).
  numbers?: boolean;
  // Options that make the reading impossible or run nothing: a reason to ask, or "none".
  stop?: Record<string, string>;
}
type OptionsRead = { next: number; seen: string[] } | { problem: string };
function readOptions(name: string, spec: OptionSpec, argv: string[], i: number): OptionsRead {
  const seen: string[] = [];
  const longs = [...(spec.long ?? []), ...(spec.longValue ?? [])];
  while (i < argv.length) {
    const w = argv[i];
    if (w === "--") return { next: i + 1, seen };
    if (!w.startsWith("-") || w === "-") return { next: i, seen };
    if (spec.numbers && /^--?\d+$/.test(w)) {
      i++;
      continue;
    }
    if (w.startsWith("--")) {
      const given = w.split("=")[0];
      const matches = longs.filter((l) => l === given || l.startsWith(given));
      const full = matches.includes(given) ? given : matches.length === 1 ? matches[0] : undefined;
      if (!full) return { problem: `${name} ${w}: an option the guard does not know, so it cannot tell which program runs` };
      seen.push(full);
      if (spec.stop?.[full]) return { problem: spec.stop[full] };
      i += spec.longValue?.includes(full) && !w.includes("=") ? 2 : 1;
      continue;
    }
    let j = 1;
    for (; j < w.length; j++) {
      const c = w[j];
      seen.push(`-${c}`);
      if (spec.stop?.[`-${c}`]) return { problem: spec.stop[`-${c}`] };
      if (spec.shortAttached?.includes(c)) {
        j = w.length;
        break;
      }
      if (spec.shortValue?.includes(c)) {
        if (j + 1 === w.length) i++;
        j = w.length;
        break;
      }
      if (!spec.short?.includes(c)) return { problem: `${name} -${c}: an option the guard does not know, so it cannot tell which program runs` };
    }
    i++;
  }
  return { next: i, seen };
}

const NONE = "runs no program";
const WRAPPER_SPECS: Record<string, OptionSpec> = {
  env: {
    short: "i0v",
    shortValue: "uCSa",
    long: ["--ignore-environment", "--null", "--debug", "--list-signal-handling", "--block-signal", "--default-signal", "--ignore-signal"],
    longValue: ["--unset", "--chdir", "--split-string", "--argv0"],
    stop: {
      "-C": "env -C runs the program in another directory, which the rules do not follow",
      "--chdir": "env --chdir runs the program in another directory, which the rules do not follow",
      "-S": "env -S splits a string into a command, which the guards cannot read",
      "--split-string": "env --split-string splits a string into a command, which the guards cannot read",
    },
  },
  nice: { shortValue: "n", longValue: ["--adjustment"], numbers: true },
  ionice: { short: "t", shortValue: "cnpPu", long: ["--ignore"], longValue: ["--class", "--classdata", "--pid", "--pgid", "--uid"], stop: { "-p": NONE, "-P": NONE, "-u": NONE, "--pid": NONE, "--pgid": NONE, "--uid": NONE } },
  timeout: { short: "v", shortValue: "sk", long: ["--preserve-status", "--foreground", "--verbose"], longValue: ["--signal", "--kill-after"] },
  time: { short: "pvaq", shortValue: "of", long: ["--portability", "--verbose", "--append", "--quiet"], longValue: ["--output", "--format"] },
  command: { short: "p", stop: { "-v": NONE, "-V": NONE } },
  builtin: {},
  nohup: {},
  setsid: { short: "cfw", long: ["--ctty", "--fork", "--wait"] },
  stdbuf: { shortValue: "ioe", longValue: ["--input", "--output", "--error"] },
  exec: { short: "cl", shortValue: "a" },
  chrt: {
    short: "abdfiorRv",
    shortValue: "TPD",
    long: ["--all-tasks", "--batch", "--deadline", "--fifo", "--idle", "--other", "--rr", "--reset-on-fork", "--verbose"],
    longValue: ["--sched-runtime", "--sched-period", "--sched-deadline"],
    stop: { "-p": NONE, "--pid": NONE, "-m": NONE, "--max": NONE },
  },
  taskset: { short: "ac", long: ["--all-tasks", "--cpu-list"], stop: { "-p": NONE, "--pid": NONE } },
  xargs: {
    short: "0prtxo",
    shortValue: "IaLnPsdE",
    shortAttached: "ile",
    long: ["--null", "--interactive", "--no-run-if-empty", "--verbose", "--exit", "--open-tty", "--show-limits", "--replace", "--max-lines", "--eof"],
    longValue: ["--arg-file", "--delimiter", "--max-args", "--max-procs", "--max-chars", "--process-slot-var"],
  },
};
// Words a wrapper takes after its options and before the program.
const WRAPPER_OPERANDS: Record<string, number> = { timeout: 1, chrt: 1, taskset: 1 };
// The options a runner takes before its subcommand (flags only: a value there is read as the
// subcommand by the rules) and between the subcommand and the program. A value option the rules
// do not know (they skip it as a flag and take its value for the program) may only be attached.
const RUNNER_SPECS: Record<string, { before: OptionSpec; after: OptionSpec }> = {
  uv: {
    before: { short: "qvn", long: ["--quiet", "--verbose", "--offline", "--no-cache", "--native-tls", "--no-progress", "--no-config", "--preview", "--no-python-downloads"] },
    after: {
      short: "qvnsmU",
      shortValue: "p",
      long: [
        "--frozen", "--locked", "--no-sync", "--isolated", "--active", "--no-active", "--no-project", "--all-extras", "--no-dev", "--dev", "--only-dev", "--no-default-groups", "--all-groups",
        "--no-editable", "--exact", "--no-env-file", "--all-packages", "--script", "--gui-script", "--module", "--quiet", "--verbose", "--offline", "--no-cache", "--refresh", "--reinstall",
        "--upgrade", "--compile-bytecode", "--no-build-isolation", "--no-progress", "--native-tls", "--no-config",
      ],
      longValue: ["--with", "--python", "--project", "--group", "--extra", "--env-file", "--directory"],
      stop: { "--directory": "uv run --directory runs the program in another directory, which the rules do not follow" },
    },
  },
  poetry: {
    before: { short: "qvn", long: ["--quiet", "--verbose", "--no-interaction", "--no-ansi", "--ansi", "--no-plugins", "--no-cache"] },
    after: { short: "qvn", long: ["--quiet", "--verbose", "--no-interaction", "--no-ansi", "--ansi", "--no-plugins", "--no-cache"], longValue: ["--project", "--directory"], stop: { "--directory": "poetry run --directory runs the program in another directory, which the rules do not follow" } },
  },
  pipenv: { before: { short: "qv", long: ["--quiet", "--verbose"] }, after: {} },
  pdm: { before: { short: "qv", long: ["--quiet", "--verbose"] }, after: { short: "lsrgqv", shortValue: "p", long: ["--list", "--site-packages", "--json", "--recreate", "--global", "--quiet", "--verbose"], longValue: ["--project"] } },
  hatch: { before: { short: "qv", long: ["--quiet", "--verbose"] }, after: {} },
  pnpm: { before: { short: "r", long: ["--recursive"] }, after: { short: "r", long: ["--recursive", "--parallel", "--no-bail", "--report-summary", "--reverse", "--workspace-root", "--silent"] } },
  bundle: { before: {}, after: { long: ["--keep-file-descriptors"] } },
};
// Only attached (`--opt=value`) is safe for a value option the rules do not skip with its value.
const attachedOnly = (spec: OptionSpec, argv: string[], from: number, to: number) => {
  for (let k = from; k < to; k++) {
    const w = argv[k];
    if (!w.startsWith("--") || w.includes("=")) continue;
    if (spec.longValue?.some((l) => l.startsWith(w) && !RULES_RUNNER_VALUES.test(l))) return w;
  }
  return undefined;
};

// Words that start a simple command as the rules read it: keywords skipped, and the ones that run
// nothing (the rest of `for x in a b` is data). `case`, `select`, `[[` and the like are programs
// to the rules (unknown, so they go to the model) and are left as such.
const BASH_KEYWORDS = RULES_KEYWORDS;
const RUNS_NOTHING = RULES_NOOP;

// The programs bash and the wrapped programs really run, from argv[start] on: every wrapper,
// runner and program position (pushed to `out`). Returns a reason when the reading is unknown,
// and the index of the main program (the first that is neither a wrapper nor a runner).
function faithful(argv: string[], start: number, out: number[]): { main: number; problem?: string } {
  let i = start;
  let assignments = true;
  let keywords = true;
  for (let guard = 0; guard < 64; guard++) {
    while (i < argv.length && ((keywords && BASH_KEYWORDS.has(argv[i])) || (assignments && rulesAssign(argv[i])))) i++;
    if (i >= argv.length || (keywords && RUNS_NOTHING.has(argv[i]))) return { main: -1 };
    const name = path.basename(argv[i]);
    out.push(i);
    const wrapper = WRAPPER_SPECS[name];
    if (wrapper || name === "sudo" || name === "doas") {
      const spec: OptionSpec = wrapper ?? { short: "AbEeHiKklnPSsVvL", shortValue: "uUgCDhpRrtT", long: [], longValue: [] };
      // sudo asks whatever it runs; its options are read leniently, only to find the program.
      const read = name === "sudo" || name === "doas" ? { next: afterFlagsAt(argv, i + 1, /^-[ugCDhpRrTU]$/), seen: [] } : readOptions(name, spec, argv, i + 1);
      if ("problem" in read) return read.problem === NONE ? { main: -1 } : { main: -1, problem: read.problem };
      i = read.next + (WRAPPER_OPERANDS[name] ?? 0);
      if (name === "env") while (i < argv.length && argv[i] === "-") i++;
      assignments = name === "env";
      keywords = false;
      continue;
    }
    const sub = RUNNERS[name];
    const runner = sub ? RUNNER_SPECS[name] : undefined;
    if (sub && runner) {
      const before = readOptions(name, runner.before, argv, i + 1);
      if ("problem" in before) {
        // Not reached as a runner by the rules either when the first operand is not the subcommand.
        if (argv.slice(i + 1).find((a) => !a.startsWith("-")) !== sub) return { main: i };
        return { main: -1, problem: before.problem };
      }
      if (argv[before.next] !== sub) return { main: i };
      const after = readOptions(`${name} ${sub}`, runner.after, argv, before.next + 1);
      if ("problem" in after) return { main: -1, problem: after.problem };
      const detached = attachedOnly(runner.after, argv, before.next + 1, after.next);
      if (detached) return { main: -1, problem: `${name} ${sub} ${detached} takes a value the rules would read as the program` };
      i = after.next;
      assignments = false;
      keywords = false;
      continue;
    }
    if (name === "find") {
      let problem: string | undefined;
      for (let j = i + 1; j < argv.length; j++) if (/^-(exec|execdir|ok|okdir)$/.test(argv[j])) problem ??= faithful(argv, j + 1, out).problem;
      return { main: i, problem };
    }
    return { main: i };
  }
  return { main: -1, problem: "too many wrappers" };
}

interface Traversal {
  at: number[];
  // The programs bash really runs, wrapper by wrapper (see faithful).
  chain: number[];
  problem?: string;
}
const traversals = new WeakMap<string[], Traversal>();
function traverse(argv: string[]): Traversal {
  const known = traversals.get(argv);
  if (known) return known;
  const at = new Set<number>();
  // Whether every word before this one is a wrapper's name, one of its words or an assignment
  // (kept as the loop goes: asking it of the whole prefix at each word made a command of 40,000
  // words take seconds).
  let wrappersOnly = true;
  for (let i = 0; i < argv.length; i++) {
    if (i === 0 || /^-(exec|execdir|ok|okdir)$/.test(argv[i - 1])) at.add(i);
    else if (wrappersOnly && !WRAPPER_WORD.test(argv[i])) at.add(i);
    wrappersOnly &&= WRAPPER_NAMES.has(path.basename(argv[i])) || WRAPPER_WORD.test(argv[i]) || ASSIGN.test(argv[i]);
  }
  const chain: number[] = [];
  const real = faithful(argv, 0, chain);
  for (const i of chain) at.add(i);
  const judged = rulesProgram(argv);
  if (judged >= 0) at.add(judged);
  let problem = real.problem;
  if (!problem && real.main !== judged) problem = `the rules judge ${judged < 0 ? "no program" : argv[judged]} where ${argv[real.main] ?? "nothing"} runs (an option of a wrapper they read differently)`;
  const out = { at: [...at].sort((a, b) => a - b), chain, ...(problem ? { problem } : {}) };
  traversals.set(argv, out);
  return out;
}
// The words of a command that could be the program it runs: see above.
export const programs = (argv: string[]): number[] => traverse(argv).at;
// The programs bash really runs in a command, wrapper by wrapper; the last is the main program
// unless the command runs none or is a `find` with `-exec`.
const chainOf = (argv: string[]): number[] => traverse(argv).chain;
// Why the programs a command runs cannot be read, or undefined.
export const traversalProblem = (argv: string[]): string | undefined => traverse(argv).problem;

const longOption = (args: string[], options: string[]) => args.find((a) => abbreviates(a, options));
const valued = (args: string[], short: string, long: string): string[] => {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (a === long || (new RegExp(`^-[a-zA-Z]*${short}$`).test(a) && !a.startsWith("--"))) out.push(args[++i] ?? "");
    else if (a.startsWith(`${long}=`)) out.push(a.slice(long.length + 1));
    else if (!a.startsWith("--") && new RegExp(`^-[a-zA-Z]*${short}.`).test(a)) out.push(a.slice(a.indexOf(short) + 1));
  }
  return out;
};

// A tool's options as its own parser reads them (round 4, second pass: one reading per tool, in
// place of a regular expression per option). GNU getopt_long, as the GNU tools and git's
// parse-options use it: short letters in clusters (`-sXPOST`), a short letter's value attached or
// the next word, a long option by any unique prefix of the tool's own list and its value after
// `=` or as the next word, optional values only attached, options anywhere among the operands
// until `--` (unless `permute` is false: then the first operand ends them), and `--no-<name>`
// where the tool takes it. The table is the tool's whole list, read from its own help: an option
// outside it, or a prefix of two of its options, is `unknown` (the tool refuses it, or the table
// is wrong; the caller decides which).
export interface Getopt {
  // Short letters: flags, letters with a required value, letters with an optional attached value.
  flags?: string;
  values?: string;
  optional?: string;
  // Long names without the dashes: "flag", "value" (required) or "optional" (attached with `=`).
  long?: Record<string, "flag" | "value" | "optional">;
  // Long names that also take `--no-<name>` (git's parse-options: every flag unless marked).
  negatable?: (name: string) => boolean;
  permute?: boolean;
  // Exact long names only (curl: no abbreviations).
  exact?: boolean;
  // A word after a short letter with an optional value that the tool takes when it is a number
  // (make's `-j 4`).
  numberNext?: string;
}
export interface GotOption {
  // `-x` for a short letter, `--name` (full) for a long one, `--no-name` for a negated one.
  name: string;
  value?: string;
  // The index in args of the word the option stands in.
  at: number;
}
export interface Got {
  opts: GotOption[];
  operands: { word: string; at: number }[];
  // The first word read as an option that is not one of the table's, or a prefix of several.
  unknown?: string;
}
export function getopt(args: string[], spec: Getopt): Got {
  const opts: GotOption[] = [];
  const operands: { word: string; at: number }[] = [];
  let unknown: string | undefined;
  const longs = spec.long ?? {};
  const names = Object.keys(longs);
  let ended = false;
  for (let i = 0; i < args.length; i++) {
    const w = args[i];
    if (ended || w === "-" || !w.startsWith("-")) {
      operands.push({ word: w, at: i });
      if (spec.permute === false) ended = true;
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
      // Every spelling the tool takes in full: its names, and `no-<name>` for a negatable one. A
      // prefix of exactly one of them is that one (git's parse-options and getopt_long alike).
      const spellings = [...names.map((n) => ({ s: n, n, neg: false })), ...names.filter((n) => spec.negatable?.(n)).map((n) => ({ s: `no-${n}`, n, neg: true }))];
      const exact = spellings.filter((x) => x.s === given);
      const prefixed = spec.exact ? [] : spellings.filter((x) => x.s.startsWith(given));
      const hit = exact.length === 1 ? exact[0] : prefixed.length === 1 ? prefixed[0] : undefined;
      if (!hit) {
        unknown ??= w;
        continue;
      }
      const full = hit.n;
      const negated = hit.neg;
      const kind = negated ? "flag" : longs[full];
      const name = negated ? `--no-${full}` : `--${full}`;
      if (kind === "value") opts.push({ name, value: attached ?? args[++i] ?? "", at: i - (attached === undefined ? 1 : 0) });
      else if (kind === "optional") opts.push({ name, value: attached, at: i });
      else {
        if (attached !== undefined) unknown ??= w;
        opts.push({ name, at: i });
      }
      continue;
    }
    for (let j = 1; j < w.length; j++) {
      const c = w[j];
      const rest = w.slice(j + 1);
      if (spec.values?.includes(c)) {
        if (rest) opts.push({ name: `-${c}`, value: rest, at: i });
        else {
          opts.push({ name: `-${c}`, value: args[i + 1] ?? "", at: i });
          i++;
        }
        break;
      }
      if (spec.optional?.includes(c)) {
        if (rest) opts.push({ name: `-${c}`, value: rest, at: i });
        else if (spec.numberNext?.includes(c) && /^\d+(\.\d+)?$/.test(args[i + 1] ?? "")) opts.push({ name: `-${c}`, value: args[++i], at: i - 1 });
        else opts.push({ name: `-${c}`, at: i });
        break;
      }
      if (spec.flags?.includes(c)) opts.push({ name: `-${c}`, at: i });
      else {
        unknown ??= `-${c}`;
        break;
      }
    }
  }
  return { opts, operands, ...(unknown ? { unknown } : {}) };
}

// Global options a package manager takes before its subcommand (round 3, finding 29): the ones
// that change only output, which workspaces run, or the directory, each known to take a value or
// not. A directory option (`--prefix`, `--cwd`, `-C`, `--dir`) must name a place in the project.
// Any other option before the subcommand asks, as before; options that pick a program
// (managerProblem) ask wherever they stand.
interface GlobalOptions {
  values: string[];
  flags: string[];
  dirs: string[];
  // A rustup toolchain (`cargo +nightly build`): a name, not a path.
  word?: RegExp;
}
const PM_GLOBALS: Record<string, GlobalOptions> = {
  npm: {
    values: ["--prefix", "-w", "--workspace", "--loglevel"],
    flags: ["--silent", "-s", "--quiet", "-q", "--verbose", "-d", "-dd", "-ws", "--workspaces", "--include-workspace-root", "--if-present", "--no-color", "--no-progress", "--no-audit", "--no-fund", "--no-update-notifier"],
    dirs: ["--prefix"],
  },
  pnpm: {
    values: ["--filter", "-F", "-C", "--dir", "--reporter", "--loglevel", "--workspace-concurrency"],
    flags: ["-r", "--recursive", "-w", "--workspace-root", "--silent", "-s", "--parallel", "--stream", "--no-bail", "--bail", "--if-present", "--aggregate-output", "--color", "--no-color", "--sequential"],
    dirs: ["-C", "--dir"],
  },
  yarn: { values: ["--cwd"], flags: ["--silent", "-s", "--verbose", "--no-progress", "--offline", "--non-interactive"], dirs: ["--cwd"] },
  cargo: { values: ["--color", "-C"], flags: ["-q", "--quiet", "-v", "-vv", "--verbose", "--locked", "--offline", "--frozen"], dirs: ["-C"], word: /^\+[A-Za-z0-9][A-Za-z0-9._-]*$/ },
  go: { values: ["-C"], flags: [], dirs: ["-C"] },
};
// The index of the subcommand after the known global options, or a reason to ask. `seen` is
// handed each option read, with its value (runnerPlaces).
function afterGlobals(manager: string, args: string[], placeOk?: (dir: string) => boolean, seen?: (name: string, value?: string) => void): number | string {
  const spec = PM_GLOBALS[manager];
  let i = 0;
  for (; i < args.length; i++) {
    const w = args[i];
    if (spec?.word?.test(w)) continue;
    if (!w.startsWith("-")) break;
    const eq = w.startsWith("--") ? w.indexOf("=") : -1;
    const name = eq < 0 ? w : w.slice(0, eq);
    if (spec?.flags.includes(name) && eq < 0) {
      seen?.(name);
      continue;
    }
    if (!spec?.values.includes(name)) return `${manager} with options before its subcommand`;
    const value = eq < 0 ? args[++i] : w.slice(eq + 1);
    if (value === undefined) return `${manager} ${name} without a value`;
    seen?.(name, value);
    if (spec.dirs.includes(name) && !placeOk?.(value)) return `${manager} ${name} ${value}: a directory outside the project, or one the check cannot place`;
  }
  return i;
}

// The words of a package manager call after its global options, when it has at least one and
// all are known (the directory check is the guard's, in installProblem); undefined otherwise. A
// subcommand that runs a program by name (`pnpm exec`, `dlx`, `x`, `create`) gives undefined too:
// the traversal looks for that program only right after the manager.
export function withoutGlobals(manager: string, args: string[]): string[] | undefined {
  if (!Object.hasOwn(PM_GLOBALS, manager)) return undefined;
  const at = afterGlobals(manager, args, () => true);
  if (typeof at === "string" || at === 0 || ["exec", "dlx", "x", "create"].includes(args[at] ?? "")) return undefined;
  return args.slice(at);
}

function installProblem(manager: string, managerArgs: string[], placeOk?: (dir: string) => boolean): string | undefined {
  if (/^(-v|-V|--version|-h|--help)$/.test(managerArgs[0] ?? "")) return undefined;
  const at = afterGlobals(manager, managerArgs, placeOk);
  // Options with no subcommand at all (`npm --version`) install nothing.
  if (typeof at === "string") return managerArgs.some((a) => !a.startsWith("-")) ? at : undefined;
  const sub = managerArgs[at];
  // The traversal finds the program a runner subcommand runs only right after the manager.
  if (at > 0 && sub !== undefined && RUNNERS[manager] === sub) return `${manager} with options before its subcommand`;
  if (sub && INSTALLERS[manager].has(sub)) return `${manager} ${sub} installs packages, which runs their install scripts`;
  if (manager === "uv" && sub === "pip" && managerArgs.some((a) => /^(install|sync)$/.test(a))) return "uv pip install installs packages, which runs their install scripts";
  if (manager === "uv" && sub === "run" && managerArgs.some((a) => /^--with(-requirements|-editable)?(=|$)/.test(a))) return "uv run --with installs packages, which runs their install scripts";
  if (manager !== "pip" && manager !== "pip3" && manager !== "uv" && manager !== "cargo" && manager !== "go" && manager !== "gem" && sub === "audit" && managerArgs.includes("fix")) return `${manager} audit fix installs packages, which runs their install scripts`;
  if (manager === "yarn" && !sub) return "yarn without a subcommand installs packages";
  if (manager === "go" && sub === "run" && managerArgs.some((a) => a.includes("@"))) return "go run of a remote package downloads and runs it";
  return undefined;
}

// A sed script the rules can allow by name: substitutions without the `e` and `w` flags, and
// the commands that print, delete and quit, each after an optional address. Anything else (the
// `e`, `r`, `w` commands, blocks, labels, text for `a`/`i`/`c`) is for the model to read.
const SED_ADDRESS = String.raw`(?:\d+|\$|\/(?:\\.|[^\/\\\n])*\/I?)`;
const SED_PLAIN = new RegExp(String.raw`^\s*(?:${SED_ADDRESS}(?:\s*,\s*(?:${SED_ADDRESS}|[+~]\d+))?)?\s*!?\s*(?:[pdqQ=DPnNgGhHxl]|\}|s([^\s\\\w])(?:\\.|(?!\1)[^\\\n])*\1(?:\\.|(?!\1)[^\\\n])*\1[gpiIm0-9]*|y([^\s\\\w])(?:\\.|(?!\2)[^\\\n])*\2(?:\\.|(?!\2)[^\\\n])*\2)\s*$`);
export const plainSed = (script: string) => script.split(/[;\n]/).every((part) => !part.trim() || SED_PLAIN.test(part));

function sedProblem(args: string[]): GuardVerdict | undefined {
  const scripts: string[] = [];
  let inPlace = false;
  const rest: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      rest.push(...args.slice(i + 1));
      break;
    }
    if (a === "-e" || a === "--expression") scripts.push(args[++i] ?? "");
    else if (a.startsWith("--expression=")) scripts.push(a.slice(13));
    else if (a === "-f" || a === "--file" || a.startsWith("--file=")) return { action: "classify", reason: "sed runs a script from a file" };
    else if (/^--(in-place|quiet|silent|regexp-extended|separate|null-data|posix|unbuffered|debug|sandbox|line-length)(=|$)/.test(a)) inPlace ||= a.startsWith("--in-place");
    else if (a.startsWith("--")) return { action: "classify", reason: `sed ${a}` };
    else if (/^-[nErsuzi]*i/.test(a) && !a.endsWith("e") && !a.includes("f")) inPlace = true; // -i, -i.bak, -ni
    else if (/^-[nErsuz]*e$/.test(a)) scripts.push(args[++i] ?? "");
    else if (/^-[nErsuz]+$/.test(a)) continue;
    else if (a === "-l") i++;
    else if (a.startsWith("-") && a !== "-") return { action: "classify", reason: `sed ${a}` };
    else rest.push(a);
  }
  if (!scripts.length && rest.length) scripts.push(rest.shift()!);
  const odd = scripts.find((script) => !plainSed(script));
  return odd === undefined ? undefined : { action: "classify", reason: "a sed script with more than substitutions, prints and deletes (sed can run commands and write files)" };
}

// Every source an awk program comes from (round 3, finding 9): each `-e`/`--source`, and the
// program operand when there is none. `-f`, `-i`, `-l`, `-E` and mawk's `-W` load a program, a
// library or an extension from a file, and the options that write a file (`-d`, `-D`, `-o`,
// `-p` and their long names) go to the model too, as does any option the guard does not know.
const AWK_LONG_FLAGS = [
  "--characters-as-bytes", "--traditional", "--copyright", "--gen-pot", "--help", "--lint", "--bignum", "--use-lc-numeric", "--non-decimal-data", "--optimize", "--posix",
  "--re-interval", "--no-optimize", "--sandbox", "--lint-old", "--version", "--csv",
];
const AWK_LONG_VALUES = ["--field-separator", "--assign", "--source"];
const AWK_LONG_LOADS = ["--file", "--include", "--load", "--exec", "--dump-variables", "--debug", "--profile", "--pretty-print"];
function awkProblem(args: string[]): GuardVerdict | undefined {
  const model = (reason: string): GuardVerdict => ({ action: "classify", reason });
  const scripts: string[] = [];
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === "--") {
      i++;
      break;
    }
    if (!a.startsWith("-") || a === "-") break;
    if (a.startsWith("--")) {
      const given = a.split("=")[0];
      const all = [...AWK_LONG_FLAGS, ...AWK_LONG_VALUES, ...AWK_LONG_LOADS];
      const matches = all.filter((o) => o.startsWith(given));
      const full = all.includes(given) ? given : matches.length === 1 ? matches[0] : undefined;
      if (!full || AWK_LONG_LOADS.includes(full)) return model(`awk ${a} loads a program, a library or an extension, or writes a file`);
      if (AWK_LONG_VALUES.includes(full)) {
        const value = a.includes("=") ? a.slice(a.indexOf("=") + 1) : args[++i];
        if (full === "--source") scripts.push(value ?? "");
      }
      continue;
    }
    for (let j = 1; j < a.length; j++) {
      const c = a[j];
      const rest = a.slice(j + 1);
      if (c === "F" || c === "v" || c === "e") {
        const value = rest || args[++i];
        if (c === "e") scripts.push(value ?? "");
        break;
      }
      if (c === "L") break; // --lint, with an optional attached value
      if ("bcCgMnNOPrsStVh".includes(c)) continue;
      return model(`awk -${c} loads a program, a library or an extension, writes a file, or is an option the guard does not know`);
    }
  }
  if (!scripts.length && i < args.length) scripts.push(args[i]);
  // The sources make one program, in the order given.
  return scripts.length ? awkScript(scripts.join("\n")) : undefined;
}
// `@` is gawk's indirect call (`@f()` with `f = "system"`) and its `@load`/`@include`.
//
// Round 4, finding 27 (signed off): awk writes a file or feeds a command only from `print` and
// `printf` (`print > "f"`, `print | "cmd"`), and reads through a pipe only with `getline`. So a
// `>` or a `|` with no `print` anywhere before it in the program is a comparison or an `||`
// (`$3 > max`, `NR==1 || /foo/`, `{ if ($1 > max) max = $1 } END { print max }`). The test is on
// the text from the first `print` on, strings and comments included, so a `print` in a string
// only asks more. `system`, `getline` and `@` go to the model wherever they stand.
// Second pass: from the first `print` on, a `>` or a `|` is output whatever follows it: awk
// takes any expression for the target (`print > 1` writes a file called 1, `print > 1 ".sh"`
// one called 1.sh), so what stands behind the sign says nothing.
const AWK_OUTPUT = /[|>]/;
const awkScript = (script: string): GuardVerdict | undefined => {
  const print = script.indexOf("print");
  return /system|getline|@/.test(script) || (print >= 0 && AWK_OUTPUT.test(script.slice(print))) ? { action: "classify", reason: "an awk program that runs commands, reads through a pipe or writes files" } : undefined;
};

// make reads a makefile, and so runs its recipes, from what `-f` names (finding 9): standard
// input, a descriptor or a process substitution is text no check has seen. The values of
// `-f`/`--file`/`--makefile` in every spelling, clusters (`-sf-`) and abbreviations included.
// GNU make 4.4.1's options (`make --help`, and the names in the binary: `--temp-stdin`, which reads
// its file as a makefile, and the jobserver's own). `-j` and `-l` take an optional value: attached,
// or the next word when that is a number.
const MAKE_OPTIONS: Getopt = {
  flags: "bmBdehiknpqrRsStvwL",
  values: "CEfIoW",
  optional: "jlO",
  numberNext: "jl",
  long: {
    "always-make": "flag", directory: "value", debug: "optional", "environment-overrides": "flag", eval: "value", file: "value", makefile: "value", help: "flag",
    "ignore-errors": "flag", "include-dir": "value", jobs: "optional", "jobserver-style": "value", "keep-going": "flag", "load-average": "optional", "max-load": "optional",
    "check-symlink-times": "flag", "just-print": "flag", "dry-run": "flag", recon: "flag", "old-file": "value", "assume-old": "value", "output-sync": "optional",
    "print-data-base": "flag", question: "flag", "no-builtin-rules": "flag", "no-builtin-variables": "flag", shuffle: "optional", silent: "flag", quiet: "flag",
    "no-silent": "flag", "no-keep-going": "flag", stop: "flag", touch: "flag", trace: "flag", version: "flag", "print-directory": "flag", "no-print-directory": "flag",
    "what-if": "value", "new-file": "value", "assume-new": "value", "warn-undefined-variables": "flag", "temp-stdin": "value", "jobserver-auth": "value", "jobserver-fds": "value", "sync-mutex": "value",
  },
};
export const makefiles = (args: string[]): string[] => makeFiles(args).files;
// The makefiles `-f` names and the directories `-C` names, in order (make changes into each
// `-C` directory, one after the other, before it reads any makefile), read as make reads its
// options (`-sC dir`, `--dir=x`, `-lf x.mk` is `-l` with the value `f`). `problem`: a `-j` whose
// value is not a number, which make refuses (the check does not read the rest of the word).
export function makeFiles(args: string[]): { files: string[]; dirs: string[]; problem?: string } {
  const got = getopt(args, MAKE_OPTIONS);
  const files = got.opts.filter((o) => ["-f", "--file", "--makefile", "--temp-stdin"].includes(o.name)).map((o) => o.value ?? "");
  const dirs = got.opts.filter((o) => o.name === "-C" || o.name === "--directory").map((o) => o.value ?? "");
  const jobs = got.opts.find((o) => (o.name === "-j" || o.name === "--jobs") && o.value !== undefined && !/^\d+$/.test(o.value) && !/[$`]/.test(o.value));
  return { files, dirs, ...(jobs ? { problem: `make ${jobs.name}${jobs.value}: make reads the rest of the word as the number of jobs` } : {}) };
}

// The files a program reads as code, where it reads them (round 4, finding 5, second pass): each
// as the word that names it and the directory it is read from (undefined: not known), for make's
// makefiles (`-f`, or the default ones, `GNUmakefile`, `makefile` and `Makefile`, where its `-C`
// options lead), awk's and sed's `-f`, a shell's script and the file `source` reads. `implicit`:
// a default makefile, named by no word.
export interface CodeFile {
  word: string;
  dir: string | undefined;
  implicit?: boolean;
}
const expands = (w: string) => /[$`*?[\]]/.test(w) || /^~[^/]/.test(w);
export function codeFiles(name: string, args: string[], cwd: string | undefined): CodeFile[] {
  if (MAKES.has(name)) {
    const { files, dirs } = makeFiles(args);
    let base = cwd;
    for (const d of dirs) base = expands(d) ? undefined : path.isAbsolute(tilde(d)) ? tilde(d) : base === undefined ? undefined : `${base}/${d}`;
    if (files.length) return files.map((word) => ({ word, dir: base }));
    return ["GNUmakefile", "makefile", "Makefile"].map((word) => ({ word, dir: base, implicit: true }));
  }
  if (name === "sed" || AWKS.has(name)) return valued(args, "f", "--file").map((word) => ({ word, dir: cwd }));
  if (SHELLS.has(name)) {
    const script = shellScript(name, args);
    return script === undefined ? [] : [{ word: script, dir: cwd }];
  }
  return [];
}

// Whether a file a program reads as code (make's `-f`, awk's and sed's `-f`, a shell's script,
// `source`) may be standard input, a descriptor or a device rather than a file on the disk
// (round 4, finding 5): the reason, or undefined for a plain file or one that does not exist.
// The path is walked as the kernel walks it, from `dir` for a relative word, each symbolic link
// followed before the `..` after it. A step into /dev or /proc asks (apart from /dev/null), and
// so does a file there that is not a regular one (a fifo, a socket), `-`, a word whose name
// is known only once the shell expands it, a relative word where the directory is not known,
// and a walk that does not end. So `/dev/./stdin`, `/dev/fd//0`, `//dev/stdin`,
// `/proc/self/fd/../fd/0`, `/proc/self/root/dev/stdin` and a link in the project to /dev/stdin
// all ask, however they are spelled.
// A path walked as the kernel walks it (round 4, second pass: the one walk for findings 5, 19 and
// 4): from `/`, each symbolic link followed before the `..` after it, at most 40 links. `at` is
// where the walk stands (a physical path), `rest` what is left of the path: nothing when the walk
// went through, the steps from the first that does not exist (`missing`), or those after a place
// where `stop` stopped it. With `followLast` false the last step, when it is a link, is the link.
// `problem`: a step that cannot be read, or links that do not end.
export interface Walked {
  at: string;
  rest: string[];
  missing?: boolean;
  problem?: string;
}
export function kernelWalk(abs: string, stop?: (at: string) => boolean, followLast = true): Walked {
  const rest = abs.split("/").filter((s) => s !== "" && s !== ".");
  let cur = "/";
  for (let hops = 0; rest.length; ) {
    if (stop?.(cur)) break;
    const part = rest.shift()!;
    if (part === "..") {
      cur = path.dirname(cur);
      continue;
    }
    const next = path.join(cur, part);
    let st: fs.Stats;
    try {
      st = fs.lstatSync(next);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      return { at: cur, rest: [part, ...rest], ...(code === "ENOENT" || code === "ENOTDIR" ? { missing: true } : { problem: "a path the check cannot walk" }) };
    }
    if (st.isSymbolicLink() && (followLast || rest.length)) {
      if (++hops > 40) return { at: cur, rest: [part, ...rest], problem: "a path the check cannot walk" };
      // (B5: a link the plugin may not read, `/proc/1/cwd`, is a path it cannot walk; it threw.)
      let target: string;
      try {
        target = fs.readlinkSync(next);
      } catch {
        return { at: cur, rest: [part, ...rest], problem: "a path the check cannot walk" };
      }
      rest.unshift(...target.split("/").filter((s) => s !== "" && s !== "."));
      if (path.isAbsolute(target)) cur = "/";
      continue;
    }
    cur = next;
  }
  return { at: cur, rest };
}
// The physical path a path names, walked as the kernel walks it; the part that does not exist yet
// is joined on as written.
export function physical(abs: string): string {
  const w = kernelWalk(abs);
  if (w.problem) throw new PathWalkError(`${abs}: ${w.problem}`);
  return path.resolve(w.at, ...w.rest);
}
export class PathWalkError extends Error {}
// Whether something is at the path (the last step itself when it is a link), as the kernel walks
// it; a path the check cannot walk counts as there.
export function present(abs: string): boolean {
  const w = kernelWalk(abs, undefined, false);
  return !!w.problem || !w.rest.length;
}
// B7-9: a path relative to the process that walks it. The plugin resolves a path in its own
// process and the command in its own: `/proc/self` is each one's own entry, `/proc/self/cwd` each
// one's own directory, and `/proc/<pid>/cwd` a directory the plugin may be unable to read. One
// rule: the walk of the path (the plugin's own, each link followed, so a link in the tree to
// `/proc/self/cwd` counts, and `/proc/self/root/proc/self/cwd`) enters `/proc/self`,
// `/proc/thread-self` or `/proc/<digits>` at any step. Not a descriptor (`/dev/stdin`,
// `/dev/fd/3`, `/proc/self/fd/3`, which are links to there): each process has its own, and the
// checks read those as descriptors.
const PROC_ENTRY = /^\/proc\/(self|thread-self|\d+)(\/|$)/;
export function procRelative(abs: string): boolean {
  let entered = false;
  const walked = kernelWalk(abs, (at) => (entered ||= PROC_ENTRY.test(at)));
  if (!entered) return PROC_ENTRY.test(walked.at);
  return !(walked.rest.length === 2 && walked.rest[0] === "fd" && /^\d+$/.test(walked.rest[1]) && /^\/proc\/\d+$/.test(walked.at));
}
export function codeFromDevice(word: string, dir: string | undefined): string | undefined {
  if (word === "-" || word === "") return "standard input";
  if (/[$`*?[\]]/.test(word) || /^~[^/]/.test(word)) return `${word}, a name the shell expands`;
  const p = tilde(word);
  if (!path.isAbsolute(p) && dir === undefined) return `${word}, in a directory the check cannot place`;
  const device = (at: string) => at === "/dev" || at === "/proc" || at.startsWith("/dev/") || at.startsWith("/proc/");
  const walked = kernelWalk(path.isAbsolute(p) ? p : `${dir}/${p}`, device);
  const { at: cur, rest } = walked;
  if (walked.problem) return `${word}, ${walked.problem}`;
  // The rest does not exist: the program fails to open it.
  if (walked.missing) return device(path.resolve(cur, ...rest)) ? `${word}, a device or a descriptor` : undefined;
  if (device(cur)) return cur === "/dev" && rest.length === 1 && rest[0] === "null" ? undefined : `${word}, a device or a descriptor`;
  try {
    const st = fs.statSync(cur);
    return st.isFile() ? undefined : `${word}, which is not a regular file`;
  } catch {
    return undefined;
  }
}
// The script a shell runs from a file, or `source` reads: undefined when it runs `-c` code or
// reads its standard input (`-s`).
function shellScript(name: string, args: string[]): string | undefined {
  if (name === "source" || name === ".") return args[0] === "--" ? args[1] : args[0];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--" || a === "-") return args[i + 1];
    if (a.startsWith("--")) {
      if (a === "--rcfile" || a === "--init-file") i++;
      continue;
    }
    if (/^[-+]/.test(a) && a.length > 1) {
      if (a.startsWith("-") && /[cs]/.test(a)) return undefined;
      if (/[oO]$/.test(a)) i++;
      continue;
    }
    return a;
  }
  return undefined;
}
// Make variables that pick the shell or how make reads its makefiles, besides the environment's.
const MAKE_DANGEROUS = /^(SHELL|\.SHELLFLAGS|MAKEFLAGS|GNUMAKEFLAGS|MAKEFILES|MAKE|MAKESHELL|MAKEOVERRIDES|\.RECIPEPREFIX|\.DEFAULT_GOAL|\.INCLUDE_DIRS|\.LOADED)$/;
function makeProblem(args: string[], cwd: string | undefined, inProject: ((p: string) => boolean) | undefined): GuardVerdict | undefined {
  const ask = (reason: string): GuardVerdict => ({ action: "ask", reason });
  if (getopt(args, MAKE_OPTIONS).opts.some((o) => o.name === "-E" || o.name === "--eval")) return ask("make --eval runs makefile text from the command line");
  const { problem } = makeFiles(args);
  // (The makefiles themselves are checked in argvGuard, with the other files read as code.)
  if (problem) return ask(problem);
  // `NAME=value` arguments follow the environment's decision (finding 28): a variable that picks
  // what runs asks unless its value is on the signed-off list; any other variable may name a
  // program a recipe runs (`$(RM)`, `$(INSTALL)`), so a value that is not a plain word goes to
  // the model.
  let verdict: GuardVerdict | undefined;
  for (const a of args) {
    const m = /^([A-Za-z_.][\w.-]*?)(\+|\?|::?|!)?=(.*)$/s.exec(a);
    if (!m) continue;
    const [, name, op, value] = m;
    if (op === "!") return ask(`make ${name}!= runs a shell command to set the variable`);
    if (/\$[({]/.test(value)) return ask(`make ${name}=: the value calls a make function or names a variable, which make expands`);
    if (ENV_DANGEROUS.test(name) || MAKE_DANGEROUS.test(name)) {
      if (op || !envValueOk(name, value, cwd, inProject)) return ask(`make ${name}= picks a program make runs or how it reads makefiles`);
    } else if (!/^[\w.,:+@%-]*$/.test(value) || SHELLS.has(value) || INTERPRETERS.has(value) || /^(python[\d.]*|env|xargs|eval|exec|sudo|doas|npx|bunx|uvx|pipx)$/.test(value)) verdict ??= { action: "classify", reason: `make ${name}=${value}: a value make may run in a recipe` };
  }
  return verdict;
}

// Options of package managers that pick the program they run scripts with, or a config that
// does: npm's `--script-shell`, `--node-options`, `--userconfig`, `--globalconfig`, pnpm's
// `--config.<key>`; cargo's `--config` (`build.rustc-wrapper=...`); go's `-toolexec`, `-exec`
// and `-vettool`. Words after `--` (and go's `-args`) go to the program, not the manager.
const PM_PROGRAM_OPTIONS = ["--script-shell", "--node-options", "--userconfig", "--globalconfig", "--init-module"];
function managerProblem(name: string, args: string[]): string | undefined {
  const end = args.findIndex((a) => a === "--" || (name === "go" && /^--?args$/.test(a)));
  const own = end < 0 ? args : args.slice(0, end);
  if (["npm", "pnpm", "yarn", "bun"].includes(name)) {
    const option = own.find((a) => abbreviates(a, PM_PROGRAM_OPTIONS) || /^--(script|node|init)_/.test(a) || /^--config\./.test(a));
    if (option) return `${name} ${option.split("=")[0]} picks the program scripts run with, or a config that does`;
  }
  if (name === "cargo") {
    const option = own.find((a) => abbreviates(a, ["--config"]) || /^-[a-zA-Z]*Z/.test(a));
    if (option) return `cargo ${option.split("=")[0]} sets cargo config, which can name a program to run (build.rustc-wrapper)`;
  }
  if (name === "go") {
    const option = own.find((a) => /^--?(toolexec|exec|vettool)(=|$)/.test(a));
    if (option) return `go ${option.split("=")[0]} runs a program of the caller's choosing`;
  }
  return undefined;
}

// Options that make a program run another one, by the option's name: asked about wherever the
// program is named. Other allowed programs are judged by their own name alone (see Known gaps).
function programProblem(name: string, args: string[], cwd?: string, inProject?: (p: string) => boolean): GuardVerdict | undefined {
  const ask = (reason: string): GuardVerdict => ({ action: "ask", reason });
  if (name === "tar" || name === "gtar" || name === "bsdtar") {
    const option = longOption(args, ["--checkpoint-action", "--use-compress-program", "--to-command", "--info-script", "--new-volume-script", "--rsh-command", "--rmt-command"]);
    if (option) return ask(`tar ${option.split("=")[0]} runs a program`);
    // Bundled short options, with or without the dash (`tar cIf`): -I and -F name a program.
    const bundles = args.filter((a, i) => (/^-[a-zA-Z]+/.test(a) && !a.startsWith("--")) || (i === 0 && /^[a-zA-Z]+$/.test(a)));
    if (bundles.some((a) => /[IF]/.test(a))) return ask("tar -I or -F runs a program");
    if (args.some((a) => !a.startsWith("-") && /^[\w.@-]+:/.test(a)) && !args.includes("--force-local")) return ask("tar with an archive on a remote host runs a remote shell");
  }
  if (name === "sort" && longOption(args, ["--compress-program"])) return ask("sort --compress-program runs a program");
  if (MAKES.has(name)) return makeProblem(args, cwd, inProject);
  if ((name === "fd" || name === "fdfind") && (longOption(args, ["--exec", "--exec-batch"]) || args.some((a) => /^-[a-zA-Z]*[xX]/.test(a) && !a.startsWith("--")))) return ask("fd -x runs a command for every match");
  if (name === "rg" && longOption(args, ["--pre", "--pre-glob", "--hostname-bin"])) return ask("rg --pre runs a program on every file");
  // man-db: -C names a config file whose DEFINE lines pick the programs man runs (finding 35);
  // -P and -H a pager and a browser. -T, -p and -X pick from a fixed set, and a page given with
  // -l or -M is formatted by groff in safe mode (probed on man-db 2.13.1: `.sy` does not run).
  if (name === "man" && (longOption(args, ["--pager", "--html", "--prompt", "--troff-device", "--config-file"]) || args.some((a) => /^-[a-zA-Z0-9]*[PHC]/.test(a) && !a.startsWith("--")))) return ask("man -C, -P or -H names a program for man to run, or a config file that does");
  if (name === "sed") return sedProblem(args);
  if (AWKS.has(name)) return awkProblem(args);
  const manager = managerProblem(name, args);
  if (manager) return ask(manager);
  return undefined;
}

// Shell builtins that evaluate their words as arithmetic, or print what they run. A variable's
// value is evaluated again there, so text the rules read as data (`'a[$(id)]'`) runs.
// What curl and wget may be given without a prompt (round 4, finding 17, signed off): an
// allowlist of options that fetch with GET or HEAD, say how, and save the answer where the rules
// check it. Any other option asks: it may send local data (`-H @file`, `--url-query @file`,
// `--variable`/`--expand-*`, a cookie file, a client certificate, `wget -e post_file=`), read a
// config that can (`-K`, `--config`, `-e`), reach a local socket (`--unix-socket`), take a file
// name from the server (`-J`, `--content-disposition`, `wget -r`) or write a file (`-w
// '%output{f}'`). curl takes neither abbreviations nor `--opt=value`; wget takes both, and an
// abbreviation asks. The rules still check the method, the data options, the files written and
// a request built from local data.
const CURL_FLAGS = new Set([
  "-s", "--silent", "-S", "--show-error", "-f", "--fail", "--fail-with-body", "--fail-early", "-L", "--location", "-I", "--head", "-i", "--include", "--show-headers",
  "-v", "--verbose", "-k", "--insecure", "-O", "--remote-name", "--remote-name-all", "-#", "--progress-bar", "--no-progress-meter", "-N", "--no-buffer", "-R", "--remote-time",
  "-Z", "--parallel", "--parallel-immediate", "-g", "--globoff", "-q", "--disable", "-V", "--version", "-h", "--help", "-M", "--manual", "--compressed", "--create-dirs",
  "-0", "--http1.0", "--http1.1", "--http2", "--http2-prior-knowledge", "--http3", "--http3-only", "-4", "--ipv4", "-6", "--ipv6", "--retry-all-errors", "--retry-connrefused",
  "--path-as-is", "--raw", "--tr-encoding", "--ssl-reqd", "--tlsv1.2", "--tlsv1.3", "--no-keepalive", "--tcp-nodelay",
]);
const CURL_VALUES = new Set([
  "-o", "--output", "--output-dir", "-D", "--dump-header", "-H", "--header", "-A", "--user-agent", "-e", "--referer", "-m", "--max-time", "--connect-timeout",
  "--retry", "--retry-delay", "--retry-max-time", "--max-redirs", "-r", "--range", "-C", "--continue-at", "-X", "--request", "-w", "--write-out", "-z", "--time-cond",
  "-Y", "--speed-limit", "-y", "--speed-time", "--limit-rate", "--keepalive-time", "--parallel-max", "--url", "--noproxy", "--max-filesize",
  // B7-11: a CA bundle is a file curl reads and shows nothing of. Its word is judged as a file
  // curl reads, as every word of a curl call is (the rules, runtimeReads).
  "--cacert",
]);
const WGET_FLAGS = new Set([
  "-q", "--quiet", "-v", "--verbose", "-nv", "--no-verbose", "-c", "--continue", "-N", "--timestamping", "-S", "--server-response", "--spider", "-nc", "--no-clobber",
  "--no-check-certificate", "--show-progress", "-nd", "--no-directories", "-np", "--no-parent",
  "--retry-connrefused", "--https-only", "-4", "--inet4-only", "-6", "--inet6-only", "--no-cache", "--no-dns-cache", "-d", "--debug",
  "-V", "--version", "-h", "--help", "--random-wait", "--ignore-length",
]);
const WGET_VALUES = new Set([
  "-O", "--output-document", "-o", "--output-file", "-a", "--append-output", "-T", "--timeout", "--dns-timeout", "--connect-timeout",
  "--read-timeout", "-t", "--tries", "-w", "--wait", "--waitretry", "-U", "--user-agent", "--header", "--progress", "--limit-rate", "--max-redirect", "--compression",
  "-Q", "--quota",
  // B7-11: the directory wget saves under, joined to every name it chooses and held to the write
  // check there (fetcherWrites).
  "-P", "--directory-prefix",
]);
// The words of a curl or wget call as the tool reads them, over the allowlist above (round 4,
// finding 17, second pass: one reading per tool, for the option check and for the files written):
// each option with its value, the operands (the URLs), and the first option outside the list,
// where the reading stops. curl: short letters in clusters (`-sXPOST`), a value attached or the
// next word, long names in full only, `--no-<flag>`; wget: the same, `--name=value`, and its
// two-letter options (`-nv`) as words of their own.
interface FetcherWords {
  opts: { option: string; value?: string }[];
  operands: string[];
  outside?: string;
}
function fetcherWords(name: string, args: string[]): FetcherWords {
  const curl = name === "curl";
  const flags = curl ? CURL_FLAGS : WGET_FLAGS;
  const values = curl ? CURL_VALUES : WGET_VALUES;
  const out: FetcherWords = { opts: [], operands: [] };
  const stop = (option: string) => ((out.outside = option), out);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (!a.startsWith("-") || a === "-") {
      out.operands.push(a);
      continue;
    }
    if (a.startsWith("--")) {
      const at = curl ? -1 : a.indexOf("=");
      const option = at < 0 ? a : a.slice(0, at);
      if (flags.has(option) && at < 0) {
        out.opts.push({ option });
        continue;
      }
      if (curl && option.startsWith("--no-") && flags.has(`--${option.slice(5)}`)) {
        out.opts.push({ option });
        continue;
      }
      if (!values.has(option)) return stop(option);
      const value = at < 0 ? args[++i] : a.slice(at + 1);
      if (value === undefined) return stop(option);
      out.opts.push({ option, value });
      continue;
    }
    // wget's two-letter short options (`-nv`, `-nc`) are words of their own.
    if (!curl && flags.has(a)) {
      out.opts.push({ option: a });
      continue;
    }
    for (let j = 1; j < a.length; j++) {
      const option = `-${a[j]}`;
      if (flags.has(option)) {
        out.opts.push({ option });
        continue;
      }
      if (!values.has(option)) return stop(option);
      const value = j + 1 < a.length ? a.slice(j + 1) : args[++i];
      if (value === undefined) return stop(option);
      out.opts.push({ option, value });
      break;
    }
  }
  return out;
}
function fetcherOptionProblem(name: string, args: string[]): string | undefined {
  const words = fetcherWords(name, args);
  if (words.outside) return `${name} ${words.outside} is not on the list of options that only fetch: it may send local data, read a config that does, or write a file`;
  for (const { word } of fetcherWrites(name, args).named) if (/(^|\/)(\.env(?:\..*)?|AGENTS\.md|CLAUDE\.md|\.git|\.opencode)(\/|$)/i.test(word)) return `${name} writes a protected file: ${word}`;
  if (name === "curl") {
    const globoff = words.opts.filter((o) => ["-g", "--globoff", "--no-globoff"].includes(o.option)).at(-1)?.option;
    const urls = [...words.operands, ...words.opts.filter((o) => o.option === "--url").map((o) => o.value ?? "")];
    // (B7-11: curl leaves `[]` and a bracketed IPv6 address as they are, `http://[::1]:8080/`.)
    const literal = (u: string) => u.replace(/\[([^\]]*)\]/g, (m, inner: string) => (inner === "" || net.isIPv6(inner.replace(/%25/, "%")) ? "" : m));
    if (globoff !== "-g" && globoff !== "--globoff" && urls.some((u) => /[{[]/.test(literal(u)))) return "curl expands a URL whose effect the check cannot compute";
  }
  // B7-6: wget globs an ftp URL against the server's listing (`*`, `?`, `[`) and writes every
  // name the server lists: names no check has read.
  if (name === "wget" && words.operands.some((u) => /^\s*ftps?:/i.test(u) && /[*?[]/.test(u))) return "wget expands an ftp URL against the server's listing and writes the names the server gives";
  for (const { option, value = "" } of words.opts) {
    // A value that reads a file or writes one: `-H @file`, `-w @file`, `-w '%output{f}'`.
    if ((option === "-H" || option === "--header") && value.startsWith("@")) return `${name} ${option} ${value} sends the lines of a file as headers`;
    if ((option === "-w" || option === "--write-out") && (value.startsWith("@") || /%output\{/.test(value))) return `${name} ${option} ${value} reads or writes a file`;
    if (name !== "curl") continue;
    // Second pass: `--url @file` reads the URLs from a file (`@-`: standard input), and the method
    // is read from every spelling curl takes (`-sX POST`, `-sXDELETE`): anything but GET and HEAD
    // may change something on the other end.
    if (option === "--url" && value.startsWith("@")) return `curl --url ${value} reads the URLs from a file or from standard input, which no check has read`;
    if ((option === "-X" || option === "--request") && value !== "GET" && value !== "HEAD") return `curl ${option} ${value} sends a request that may change something on the server`;
  }
  return undefined;
}

// The files a curl or wget call writes (round 4, finding 17, second pass), each where the tool
// writes it (probed with curl 8.14.1 and wget 1.25.0): `named`, the words of the files it names,
// with whether the rules see that word as the place (`checked`); `chosen`, the directories where
// it writes a file whose name the URL or the server chooses ("" for the directory it runs in),
// with why. curl: `-o` under the last `--output-dir` (a `#1` in it is a name curl makes from the
// URL), `-O` and `--remote-name-all` in the output directory, `-D` as written. wget: `-O` as
// written, `-o` and `-a` (its log), and, without `-O` or `--spider`, a name of its own under the
// current directory; directory-prefix and directory-building options are excluded.
function fetcherWrites(name: string, args: string[]): { named: { word: string; checked: boolean }[]; chosen: { dir: string; why: string }[] } {
  const named: { word: string; checked: boolean }[] = [];
  const chosen: { dir: string; why: string }[] = [];
  const { opts, operands } = fetcherWords(name, args);
  const all = (...options: string[]) => opts.filter((o) => options.includes(o.option)).map((o) => o.value ?? "");
  const under = (dir: string | undefined, word: string) => (dir === undefined ? word : `${dir}/${word}`);
  // The names a tool may give the file of a URL: the last part of its path, in the percent
  // spelling and decoded (wget decodes, curl's -O does not). B7-6, as curl 8.14 reads it
  // (tool_operhlp.c, get_url_file_name): the path without query and fragment and with its dot
  // segments taken out (`/.env/.`, `/.env/x/../`, `%2e` for a dot), a `\` a separator as `/`
  // is, and where the path ends in a separator the part before it (`/.env/` is `.env`). Read
  // wider than curl does: whatever number of separators end the path.
  const urlNames = () => [...operands, ...all("--url")].map((url) => {
    const whole = url.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "").split(/[?#]/)[0];
    const at = whole.search(/[\/\\]/);
    const spellings = [at < 0 ? "" : whole.slice(at)];
    try { spellings.push(decodeURIComponent(spellings[0])); } catch { /* the percent spelling alone */ }
    return spellings.flatMap((p) => {
      const parts: string[] = [];
      for (const part of p.split(/[\/\\]/)) {
        if (part === "" || part === "." || /^%2e$/i.test(part)) continue;
        if (part === ".." || /^(\.|%2e){2}$/i.test(part)) parts.pop();
        else parts.push(part);
      }
      // (And as wget 1.25 names it: the last part as written, where a backslash is part of the
      // name, and with the query, `a?b=c`.)
      const plain = p.split("/").filter(Boolean).at(-1) ?? "";
      const query = /\?[^#]*/.exec(url)?.[0] ?? "";
      // A path that names nothing is saved under the tool's own name for that.
      // (curl 8.14: `curl_response`; wget: `index.html` for every path that ends in a `/`.)
      const unnamed = name === "curl" ? (parts.length ? [] : ["curl_response"]) : !parts.length || /\/$/.test(p) ? ["index.html", ...(query ? [`index.html${query}`] : [])] : [];
      return [parts.at(-1) ?? "", plain, ...(plain && query ? [`${plain}${query}`] : []), ...unnamed];
    });
  }).flat();
  if (name === "curl") {
    const dir = all("--output-dir").at(-1);
    for (const o of all("-o", "--output")) {
      if (o === "-") continue;
      const word = under(dir, o);
      if (/#\d/.test(o)) chosen.push({ dir: path.dirname(word), why: `curl -o ${o} writes names it makes from the URL` });
      else named.push({ word, checked: dir === undefined });
    }
    if (opts.some((o) => ["-O", "--remote-name", "--remote-name-all"].includes(o.option))) {
      chosen.push({ dir: dir ?? "", why: "curl -O writes a file named by the URL" });
      for (const n of new Set(urlNames())) if (n) named.push({ word: under(dir, n), checked: false });
    }
    for (const d of all("-D", "--dump-header")) if (d !== "-") named.push({ word: d, checked: false });
  } else {
    const document = all("-O", "--output-document");
    // (B7-11: `-P DIR` is where wget puts a name it chooses; `-O` is taken as written.)
    const prefix = all("-P", "--directory-prefix").at(-1);
    for (const d of document) if (d !== "-") named.push({ word: d, checked: true });
    for (const log of all("-o", "--output-file", "-a", "--append-output")) named.push({ word: log, checked: false });
    if (!document.length && !opts.some((o) => o.option === "--spider")) {
      chosen.push({ dir: prefix ?? "", why: "wget writes a file named by the URL or the server" });
      for (const n of new Set(urlNames())) if (n) named.push({ word: under(prefix, n), checked: false });
    }
  }
  return { named, chosen };
}

// A file:// URL given to curl is a file read (round 4, decision D2): held to the checks the rules
// give a file named to `cat`. curl takes `file:/p`, `file:///p`, `file://localhost/p` and
// `file://127.0.0.1/p`, in any case, drops `?query` and `#fragment`, decodes `%XX` and expands its own globs (`{a,b}`, `[a-z]`) unless `-g`; a URL it would
// expand, one built at run time, or one that names no absolute path asks.
function fileUrlProblem(args: string[], scope: Scope): GuardVerdict | undefined {
  const { opts, operands } = fetcherWords("curl", args);
  const lastGlob = opts.filter((o) => ["-g", "--globoff", "--no-globoff"].includes(o.option)).at(-1)?.option;
  const globoff = lastGlob === "-g" || lastGlob === "--globoff";
  const urls = [...operands, ...opts.filter((o) => o.option === "--url").map((o) => o.value ?? "")];
  let verdict: GuardVerdict | undefined;
  for (const url of urls) {
    const m = /^file:(?:\/\/([^/]*))?([^?#]*)/is.exec(url);
    if (!m) continue;
    const ask = (why: string) => (verdict = stricter(verdict, { action: "ask", reason: `curl ${url} reads a local file: ${why}` }));
    // curl reads the file for the host "", "localhost" and "127.0.0.1" (probed with 8.14.1) and
    // refuses others; the path is checked whatever the host. A query or a fragment is no part of it.
    if (/[$`]/.test(url)) {
      ask("a name built at run time");
      continue;
    }
    if (!globoff && /[{}[\]]/.test(m[2])) {
      ask("curl expands the name itself");
      continue;
    }
    let p: string;
    try {
      p = decodeURIComponent(m[2]);
    } catch {
      ask("a name the check cannot decode");
      continue;
    }
    if (!p.startsWith("/") || p.includes("\0")) {
      ask("a name the check cannot place");
      continue;
    }
    const v = bashVerdict(`cat '${p.replace(/'/g, "'\\''")}'`, scope);
    if (v.action === "ask" || v.action === "deny") ask(v.reason);
    else if (v.action === "classify") verdict = stricter(verdict, { action: "classify", reason: `curl ${url} reads a local file: ${v.reason}` });
  }
  return verdict;
}

// Programs that look a name up or reach a host: a host or query built at run time can carry local
// data out through DNS or the packet (round 4, finding 17: it goes to the model). curl and wget
// ask on the same in the rules; a git remote named at run time is held here too.
const LOOKUPS = new Set(["dig", "nslookup", "host", "ping", "ping6", "getent", "drill", "kdig", "delv", "whois", "traceroute", "tracepath", "mtr"]);
// Third pass (finding 17, X3): a lookup that reads the names it looks up from a file sends the
// file's lines to a name server, as a name built at run time does: dig's batch file (`-f FILE`,
// in a cluster of its flags or with the name attached, `-f -` for its input), drill's packet
// file (`-f`), mtr's host list (`-F`, `--filename`), and nslookup in its interactive mode (no
// name to look up, or `-` for it), which reads its commands from its input: a redirect, a
// heredoc, a pipe, or whatever input the shell hands it. A letter of dig's options the reading
// does not know counts as `-f` when an `f` follows it (fail closed).
const DIG_FLAGS = "46dhimnruv";
const DIG_VALUES = "bckpqtxy";
function lookupFileProblem(name: string, args: string[]): string | undefined {
  const reads = (file: string) => `${name} reads the names it looks up from ${file}, and sends them to a name server`;
  if (name === "dig") {
    for (let i = 0; i < args.length; i++) {
      const w = args[i];
      if (!w.startsWith("-") || w === "-") continue;
      for (let j = 1; j < w.length; j++) {
        const c = w[j];
        if (DIG_FLAGS.includes(c)) continue;
        if (c === "f" || (!DIG_VALUES.includes(c) && w.slice(j).includes("f"))) return reads(w.slice(j + 1) || args[i + 1] || "its input");
        if (DIG_VALUES.includes(c) && j + 1 === w.length) i++;
        break;
      }
    }
  }
  if (name === "drill" && args.some((a) => /^-[a-zA-Z]*f/.test(a))) return reads("a file");
  if (name === "mtr" && args.some((a) => /^-[a-zA-Z]*F/.test(a) || /^--f/.test(a))) return reads("a file");
  if (name === "nslookup") {
    // The options are `-name` or `-name=value`; the first other word is the name, `-` included.
    const operand = args.find((a) => a === "-" || !a.startsWith("-"));
    if (operand === undefined || operand === "-") return reads("its input");
  }
  return undefined;
}

// Second pass: a git call that talks to a remote goes to the model when any of its words is built
// at run time, wherever it stands (the remote, a refspec, which the protocol sends as a ref
// prefix, a `--server-option`, a `--shallow-exclude`): no option table has to place the remote
// (the first pass took the word after an abbreviated or clustered option, or after `remote show`,
// for an option's value). `archive` talks to a remote only with `--remote`.
const GIT_NETWORK = new Set(["fetch", "pull", "ls-remote", "push", "clone", "archive", "remote"]);
function builtHost(name: string, args: string[]): string | undefined {
  if (LOOKUPS.has(name)) {
    const built = args.find((a) => /[$`]/.test(a));
    return built === undefined ? undefined : `${name} ${built}: a host or a query built at run time can carry local data out through DNS`;
  }
  if (name !== "git") return undefined;
  const call = gitCall(args);
  if (typeof call === "string" || !GIT_NETWORK.has(call.sub ?? "")) return undefined;
  if (call.sub === "archive" && !call.rest.some((w) => w.startsWith("--r"))) return undefined;
  const built = call.rest.find((w) => /[$`]/.test(w));
  return built === undefined ? undefined : `git ${call.sub} ${built}: a word built at run time in a call that talks to a remote can carry local data out (in the host name, a ref name or a server option)`;
}

function sinkProblem(name: string, args: string[]): string | undefined {
  const subscript = (a: string) => /\w\[/.test(a);
  if (name === "let") return "let evaluates its words as arithmetic";
  if (DECLARERS.has(name) && args.some((a) => /^[-+][a-zA-Z]*i/.test(a))) return `${name} -i evaluates the value as arithmetic`;
  if (["unset", "read", "mapfile", "readarray", "wait", "getopts", ...DECLARERS].includes(name) && args.some(subscript)) return `${name} with an array subscript, which bash evaluates as arithmetic`;
  if (name === "printf" && valued(args, "v", "--never").some((v) => subscript(v) || /[$`]/.test(v))) return "printf -v with a subscript or a computed name";
  if (name === "test" || name === "[") {
    const at = args.findIndex((a, i) => (a === "-v" || a === "-R") && i + 1 < args.length);
    if (at >= 0 && (subscript(args[at + 1]) || /[$`]/.test(args[at + 1]))) return `${name} -v with a subscript or a variable, which bash evaluates as arithmetic`;
  }
  if (name === "read" && args.some((a) => /[$`]/.test(a) && !a.startsWith("-"))) return "read into a name taken from a variable";
  return undefined;
}

// Variables set without `NAME=`: the last words of `read` and `mapfile`, the word after
// `printf -v`, the second word of `getopts`, the operands of `unset`. (`for NAME`, `select`,
// `coproc NAME` and `declare NAME` are in textGuard.)
function assignedBy(name: string, args: string[]): string[] {
  if (name === "printf") return valued(args, "v", "--never");
  if (name === "getopts") return args.slice(1, 2);
  if (name === "wait") return valued(args, "p", "--never");
  if (name === "read" || name === "mapfile" || name === "readarray") {
    const names: string[] = [];
    const takesValue = name === "read" ? /^-[a-zA-Z]*[adinNptu]$/ : /^-[a-zA-Z]*[dnOsuCc]$/;
    for (let i = 0; i < args.length; i++) {
      if (takesValue.test(args[i])) {
        if (args[i].endsWith("a")) names.push(args[i + 1] ?? "");
        i++;
      } else if (!args[i].startsWith("-")) names.push(args[i]);
    }
    return names;
  }
  // `unset PATH` leaves bash to search the working directory, where a file the session wrote
  // runs as `ls` (finding 10). `unset -f` removes functions, not variables.
  if (name === "unset") {
    const end = args.indexOf("--");
    const options = end < 0 ? args.filter((a) => /^-/.test(a)) : args.slice(0, end);
    if (options.some((o) => /^-[a-zA-Z]*f/.test(o)) && !options.some((o) => /^-[a-zA-Z]*[vn]/.test(o))) return [];
    return (end < 0 ? args.filter((a) => !a.startsWith("-")) : args.slice(end + 1));
  }
  return [];
}

export interface ArgvContext extends TextContext {
  // Resolves a word to the file it names, where the given command runs; undefined when that
  // cannot be known.
  resolve: (word: string, cmd?: Simple) => string | undefined;
  // The directory a command runs in, when it is known.
  cwdOf?: (cmd: Simple) => string | undefined;
  // B7: every real directory a command may run in (several after `true || cd x`), or undefined
  // where they are not known.
  dirsOf?: (cmd: Simple) => string[] | undefined;
  // B7-3: the command is a pattern of a `case` (the parser lists `*)` as a command of one word).
  pattern?: (cmd: Simple) => boolean;
  // Set when the call writes files the guard cannot name or place (an archive, a patch, a git
  // checkout, a recursive copy): the reason.
  unknownWrite?: string;
  // Directories where this session, this call included, wrote files the guard cannot list (round
  // 4, finding 4): a file run by its path below one may be one of them.
  unlisted?: string[];
  // What this call puts in place by a link, a move or a copy that keeps links (argvGuards fills
  // it), and the first such write it cannot place.
  placed?: string[];
  placedUnknown?: string;
  // Round 4, finding 28 (third pass: `npx` is never a rule allow): for a command whose program
  // is `npx` (decide.ts, everydayRules), where `npx` stands in its words and how the call ends:
  // `ask` with the reason, or the model with the reason `model`. `program`: where the program
  // npx is to run stands, when its words name one.
  npx?: (cmd: Simple) => { at: number; program?: number; ask?: string; model?: string } | undefined;
}

// ---- what a command writes ----

// One file or directory a command writes into: the word that names it, the command, whether the
// rules already check that place (redirects and the operands of their writers), and for a
// directory the files copied into it.
export interface Write {
  word: string;
  cmd: Simple;
  checked: boolean;
  dir?: boolean;
  // A copy into a directory: the source words, each landing at dir/basename.
  sources?: string[];
  // The program that writes (`>` for a redirect).
  by?: string;
}
// Whether a write can leave something other than a regular file with the content the call gives
// it: a link (`ln`, `cp -P`, `cp -a`, `cp -r`, `mv`, `rsync`, a patch), a moved file. A redirect,
// `tee`, `sed -i` and the like write content into a regular file, or through a link that is
// already there (which a walk at decision time sees).
const CONTENT_WRITERS = new Set([">", "tee", "truncate", "sed", "perl", "ruby", "dd", "sort", "tree", "less", "uniq", "xxd", "yq", "jq", "curl", "wget", "install"]);
const linksOrMoves = (w: Write) => !CONTENT_WRITERS.has(w.by ?? "") && !(w.by === "cp" && w.cmd.argv.slice(1).every((a) => !a.startsWith("-") || /^-[finuvb]+$|^--(force|interactive|no-clobber|update|verbose)$/.test(a)));
// The writers' own option tables (round 4, finding 4, second pass: a writer is placed by its own
// reading of its words, abbreviations and clusters included, not by a regular expression per
// option). GNU coreutils 9.7 `cp`, `mv`, `ln`, `install --help`, GNU patch 2.8 `patch --help`,
// GNU tar 1.35 `tar --help` (getopt_long and argp: unique prefixes, `--name=value`, optional
// values attached only, options among the operands). rsync is not installed here: its table is
// read from the rsync 3 manual, exact names only (popt), and an option outside it leaves the
// place unread. An option outside a table, or a prefix of two, leaves the place unread too: the
// caller then marks the whole project.
const longs = (kind: "flag" | "value" | "optional", names: string) => names.split(" ").map((n) => [n, kind] as const);
const COPY_OPTIONS: Record<string, Getopt> = {
  cp: {
    flags: "abdfiHlLnPpRrsTuvxZ",
    values: "St",
    long: Object.fromEntries([
      ...longs("flag", "archive attributes-only copy-contents debug force interactive link dereference no-clobber no-dereference parents recursive remove-destination strip-trailing-slashes symbolic-link no-target-directory verbose keep-directory-symlink one-file-system help version"),
      ...longs("value", "no-preserve sparse suffix target-directory"),
      ...longs("optional", "backup preserve reflink update context"),
    ]),
  },
  mv: {
    flags: "bfinTuvZ",
    values: "St",
    long: Object.fromEntries([...longs("flag", "debug exchange force interactive no-clobber no-copy strip-trailing-slashes no-target-directory verbose context help version"), ...longs("value", "suffix target-directory"), ...longs("optional", "backup update")]),
  },
  ln: {
    flags: "bdFfiLnPrsTv",
    values: "St",
    long: Object.fromEntries([...longs("flag", "directory force interactive logical no-dereference physical relative symbolic no-target-directory verbose help version"), ...longs("value", "suffix target-directory"), ...longs("optional", "backup")]),
  },
  install: {
    flags: "bcCdDpsTvZ",
    values: "gmoSt",
    long: Object.fromEntries([...longs("flag", "compare directory debug preserve-timestamps strip no-target-directory verbose preserve-context help version"), ...longs("value", "group mode owner strip-program suffix target-directory"), ...longs("optional", "backup context")]),
  },
  rsync: {
    flags: "avrlptgoDzhPnucqHAXSxRLkKEWbimOJIC0468",
    values: "efBTM",
    exact: true,
    long: Object.fromEntries([
      ...longs("flag", "archive verbose recursive links perms times group owner devices specials compress human-readable progress partial dry-run update checksum quiet hard-links acls xattrs sparse one-file-system relative copy-links copy-dirlinks keep-dirlinks executability whole-file no-whole-file backup itemize-changes prune-empty-dirs omit-dir-times omit-link-times ignore-times cvs-exclude fuzzy delete delete-before delete-during delete-delay delete-after delete-excluded force stats existing ignore-existing remove-source-files inplace append append-verify no-motd numeric-ids safe-links munge-links size-only mkpath from0 protect-args secluded-args list-only 8-bit-output no-implied-dirs no-perms no-times no-owner no-group no-relative no-recursive no-links ignore-errors ignore-missing-args delete-missing-args copy-unsafe-links atimes crtimes open-noatime fake-super super no-super checksum-seed blocking-io no-blocking-io msgs2stderr no-msgs2stderr help version"),
      ...longs("value", "exclude include exclude-from include-from filter files-from rsh rsync-path chmod chown max-size min-size bwlimit timeout contimeout block-size compress-level compress-choice checksum-choice port suffix usermap groupmap info debug out-format modify-window iconv max-delete max-alloc skip-compress address sockopts outbuf password-file stop-after stop-at log-file log-file-format backup-dir temp-dir partial-dir compare-dest copy-dest link-dest write-batch only-write-batch read-batch protocol remote-option"),
      ["checksum-seed", "value"],
    ]),
  },
};
// The options that put what a writer writes somewhere its words do not show.
const PLACED_ELSEWHERE = new Set(["--backup-dir", "--temp-dir", "-T", "--partial-dir", "--log-file", "--write-batch", "--only-write-batch", "--compare-dest", "--copy-dest", "--link-dest", "--files-from"]);
// What a copy, move or link reads from its words: the target directory (`-t`), the operands, and
// whether it copies directories, makes hard links, or cannot be read.
function copyWords(name: string, args: string[]): { target?: string; operands: string[]; recursive: boolean; hard: boolean; unknown?: string } {
  const got = getopt(args, COPY_OPTIONS[name]);
  const has = (...names: string[]) => got.opts.some((o) => names.includes(o.name));
  const elsewhere = name === "rsync" ? got.opts.find((o) => PLACED_ELSEWHERE.has(o.name))?.name : undefined;
  return {
    target: got.opts.filter((o) => o.name === "-t" || o.name === "--target-directory").at(-1)?.value,
    operands: got.operands.map((o) => o.word),
    recursive: name === "rsync" || has("-r", "-R", "-a", "--recursive", "--archive"),
    hard: (name === "ln" && !has("-s", "--symbolic")) || (name === "cp" && has("-l", "--link")),
    ...(got.unknown || elsewhere ? { unknown: got.unknown ?? elsewhere } : {}),
  };
}
const PATCH_OPTIONS: Getopt = {
  flags: "lcenuNREZTbtfsv",
  values: "pFiorDVBYzgdx",
  long: Object.fromEntries([
    ...longs("flag", "ignore-whitespace context ed normal unified forward reverse remove-empty-files set-utc set-time backup backup-if-mismatch no-backup-if-mismatch batch force quiet silent verbose dry-run posix binary follow-symlinks help version"),
    ...longs("value", "strip fuzz input output reject-file ifdef quoting-style version-control prefix basename-prefix suffix get directory reject-format read-only debug"),
    ...longs("optional", "merge"),
  ]),
};
const TAR_OPTIONS: Getopt = {
  flags: "AcdrtuxGnSkUWOmpsMBiajJzZhPlRvwo",
  values: "gCTXfFLbHVIKN",
  long: Object.fromEntries([
    ...longs("flag", "catenate concatenate create delete diff compare append test-label list update extract get check-device incremental ignore-failed-read no-check-device no-seek seek sparse exclude-backups exclude-caches exclude-caches-all exclude-caches-under exclude-vcs exclude-vcs-ignores no-null no-recursion no-unquote no-verbatim-files-from null verbatim-files-from recursion unquote anchored ignore-case no-anchored no-ignore-case no-wildcards no-wildcards-match-slash wildcards wildcards-match-slash keep-directory-symlink keep-newer-files keep-old-files no-overwrite-dir overwrite overwrite-dir recursive-unlink remove-files skip-old-files unlink-first verify ignore-command-error no-ignore-command-error to-stdout clamp-mtime delay-directory-restore touch no-delay-directory-restore no-same-owner no-same-permissions numeric-owner preserve-permissions same-permissions same-owner preserve-order same-order acls no-acls no-selinux no-xattrs selinux xattrs force-local multi-volume read-full-records ignore-zeros old-archive portability posix auto-compress bzip2 xz lzip lzma lzop no-auto-compress zstd gzip gunzip ungzip compress uncompress hard-dereference dereference one-file-system absolute-names full-time check-links block-number show-defaults show-omitted-dirs show-snapshot-field-ranges show-transformed-names utc verbose interactive confirmation restrict usage version help"),
    ...longs("value", "listed-incremental hole-detection level sparse-version add-file directory exclude exclude-ignore exclude-ignore-recursive exclude-tag exclude-tag-all exclude-tag-under files-from exclude-from to-command group group-map mode mtime owner owner-map sort xattrs-exclude xattrs-include file info-script new-volume-script tape-length rmt-command rsh-command volno-file blocking-factor record-size format label use-compress-program starting-file newer-mtime newer after-date suffix strip-components transform xform checkpoint-action index-file no-quote-chars quote-chars quoting-style warning pax-option"),
    ...longs("optional", "occurrence one-top-level atime-preserve backup checkpoint totals"),
  ]),
};
// The options with which tar writes where its `-C` does not show: absolute member names, another
// top directory, renamed members, member names (and `-C` lines) read from a file, links to
// directories followed.
const TAR_ELSEWHERE = new Set(["-P", "--absolute-names", "--one-top-level", "--transform", "--xform", "-T", "--files-from", "--keep-directory-symlink"]);
// tar's words with an old-style bundle (`tar xfC a.tar sub`) turned into options, as tar does:
// each letter of the first word is an option, and the letters that take a value take the words
// after it in order.
function tarWords(args: string[]): string[] {
  const first = args[0];
  if (first === undefined || first.startsWith("-") || !/^[a-zA-Z]+$/.test(first)) return args;
  const out: string[] = [];
  let k = 1;
  for (const letter of first) {
    out.push(`-${letter}`);
    if (TAR_OPTIONS.values!.includes(letter)) out.push(args[k++] ?? "");
  }
  return [...out, ...args.slice(k)];
}
// Writers whose output names are not on the command line (finding 23).
// `filesOnly`: for an `mv`, whether every source is a file that is there now and that nothing
// else in the call touches (B7-11: then the move brings in no directory of files).
function unnamedWrite(name: string, args: string[], filesOnly?: (sources: string[]) => boolean): string | undefined {
  // A name the URL or the server chooses (round 4, finding 17, second pass).
  if (name === "curl" || name === "wget") return fetcherWrites(name, args).chosen[0]?.why;
  if (name === "tar" || name === "gtar" || name === "bsdtar") {
    const first = args[0] ?? "";
    if (longOption(args, ["--extract", "--get"]) || args.some((a) => /^-[a-zA-Z]*x/.test(a) && !a.startsWith("--")) || /^[a-zA-Z]*x/.test(first)) return `${name} -x writes the files the archive names`;
  }
  if ((name === "unzip" && !args.some((a) => /^-[a-zA-Z]*[lptvZ]/.test(a))) || name === "7z" || name === "cpio" || name === "rar" || name === "unrar") return `${name} writes the files the archive names`;
  if (/^(gunzip|unxz|unzstd|bunzip2|uncompress)$/.test(name) || (/^(gzip|xz|zstd|bzip2)$/.test(name) && args.some((a) => /^(-[a-zA-Z]*d|--decompress|--uncompress)$/.test(a)))) return `${name} -d writes files next to its input`;
  if (name === "patch") {
    const got = getopt(args, PATCH_OPTIONS);
    if (got.unknown || !got.opts.some((o) => ["--dry-run", "-o", "--output"].includes(o.name))) return "patch writes the files the diff names";
  }
  if (name === "rsync") return "rsync writes the files it copies";
  // Read by the tool's own options (round 4, finding 4, second pass: `--recur`, `--arc`).
  if (["cp", "mv", "install"].includes(name)) {
    const words = copyWords(name, args);
    if (words.unknown) return `${name} ${words.unknown}: an option the check cannot read, so it cannot list what is written`;
    // A moved directory brings its files with it, change times and all (B4): `mv` is such a
    // write unless every source is known to be a file.
    const sources = words.target !== undefined ? words.operands : words.operands.slice(0, -1);
    if (words.recursive || (name === "mv" && !(sources.length > 0 && filesOnly?.(sources)))) return `${name} writes the files of directories it copies or moves`;
  }
  if (name === "git") {
    const call = gitCall(args);
    if (typeof call === "string") return undefined;
    const sub = call.sub ?? "";
    const words = call.rest.filter((w) => !w.startsWith("-"));
    // `--stat --apply`, `--stat --app`, `--check --no-check` apply the patch (round 4, finding 4,
    // second pass: read by git's own reading of the options).
    if (sub === "apply" && !gitApplies(call.rest)) return undefined;
    if (sub === "stash" && ["list", "show", "create", "store"].includes(words[0] ?? "")) return undefined;
    if (sub === "stash" && !words.length) return undefined; // saves and cleans: writes only what was there
    if (sub === "branch" || sub === "tag") return undefined;
    // A new branch at HEAD changes no file (round 4, finding 4: the mark it would leave lasts).
    const end = call.rest.indexOf("--");
    const own = end < 0 ? call.rest : call.rest.slice(0, end);
    const creates = sub === "checkout" ? /^-[a-zA-Z]*[bB]$/ : /^-[a-zA-Z]*[cC]$/;
    if ((sub === "checkout" || sub === "switch") && end < 0 && own.some((w) => creates.test(w) || (sub === "switch" && /^--(create|force-create)$/.test(w))) && words.length <= 1 && own.every((w) => !w.startsWith("-") || creates.test(w) || /^-(q|-quiet)$/.test(w) || /^--(create|force-create)$/.test(w))) return undefined;
    if (["apply", "am", "checkout", "switch", "restore", "reset", "stash", "merge", "pull", "rebase", "cherry-pick", "revert", "mv", "checkout-index", "read-tree", "worktree", "submodule", "sparse-checkout"].includes(sub)) return `git ${sub} writes files of the work tree`;
    // A bisect checks out the commits it steps through (round 4, finding 4, second pass).
    if (sub === "bisect" && ["start", "reset", "good", "bad", "new", "old", "skip", "next"].includes(words[0] ?? "")) return "git bisect checks out other commits";
  }
  return undefined;
}

// Where a writer of unnamed files writes (round 4, finding 4, signed off): the directories its
// `-C` or `-d` names in plain words, none for the directory it runs in, or [undefined] when that
// cannot be placed (a value bash expands, several `-C` that tar reads one after the other, an
// abbreviation, tar's `-P`). git writes anywhere in the work tree, whatever directory it runs in.
const plainWord = (w: string) => !/[$`*?[\]{}]/.test(w) && !/^~[^/]/.test(w);
function unnamedWriteDirs(name: string, args: string[]): (string | undefined)[] {
  const place = (dirs: string[]) => (dirs.every(plainWord) ? dirs : [undefined]);
  if (name === "tar" || name === "gtar" || name === "bsdtar") {
    // Read as tar reads its words (round 4, finding 4, second pass): members named before a `-C`
    // go to the directory the `-C` leaves; several `-C` lead one from the other.
    const words = tarWords(args);
    const got = getopt(words, TAR_OPTIONS);
    if (got.unknown || got.opts.some((o) => TAR_ELSEWHERE.has(o.name))) return [undefined];
    const dirs = got.opts.filter((o) => o.name === "-C" || o.name === "--directory");
    if (dirs.length > 1) return [undefined];
    if (!dirs.length) return [];
    const before = got.operands.some((o) => o.at < dirs[0].at);
    return place([...(before ? ["."] : []), dirs[0].value ?? ""]);
  }
  if (name === "unzip") return place(valued(args, "d", "--never"));
  if (name === "patch") {
    const got = getopt(args, PATCH_OPTIONS);
    // Backups under a prefix (`-B`, `-Y`) land where the prefix leads.
    if (got.unknown || got.opts.some((o) => ["-B", "--prefix", "-Y", "--basename-prefix"].includes(o.name))) return [undefined];
    const dirs = got.opts.filter((o) => o.name === "-d" || o.name === "--directory").map((o) => o.value ?? "");
    return dirs.length > 1 ? [undefined] : place(dirs);
  }
  // cpio keeps the member names an archive holds, `..` included: anywhere it can write.
  if (name === "cpio") return [undefined];
  if (name === "7z") return args.some((a) => /^-o/.test(a)) ? place(args.filter((a) => /^-o/.test(a)).map((a) => a.slice(2))) : [];
  if (name === "git") return [undefined];
  if (name === "curl" || name === "wget") return place(fetcherWrites(name, args).chosen.map((c) => c.dir || "."));
  if (/^(gunzip|unxz|unzstd|bunzip2|uncompress|gzip|xz|zstd|bzip2)$/.test(name)) return place(args.filter((a) => !a.startsWith("-")).map((f) => path.dirname(f)));
  if (["cp", "mv", "install", "rsync"].includes(name)) {
    const words = copyWords(name, args);
    if (words.unknown) return [undefined];
    const dest = words.target ?? words.operands.at(-1);
    return dest === undefined ? [] : place([dest]);
  }
  return [];
}

// The files and directories each command writes, as far as its words tell; the first command
// that writes files it does not name; and every such command, with the directories it covers
// (`dirs` empty: where it runs).
export interface Unlisted {
  cmd: Simple;
  reason: string;
  dirs: (string | undefined)[];
  // A git command whose work-tree writes git itself can tell afterwards (round 4, decision D1): the
  // `-C` words it runs under. The caller compares the commit and the status before and after, and
  // marks what changed rather than the directories.
  git?: string[];
}
// The git subcommands of D1: they write the files of the work tree that the commit before and
// after, and the status, show. `apply` and the commands that make another work tree or rewrite
// the index by hand keep the directory mark.
export const WORKTREE_GIT = new Set(["am", "checkout", "switch", "restore", "reset", "stash", "merge", "pull", "rebase", "cherry-pick", "revert", "mv", "bisect"]);
export function writesOf(cmds: Simple[], filesOnly?: (sources: string[], cmd: Simple) => boolean): { writes: Write[]; unknown?: string; unlisted: Unlisted[] } {
  const writes: Write[] = [];
  const unlisted: Unlisted[] = [];
  let unknown: string | undefined;
  for (const cmd of cmds) {
    for (const word of cmd.out) writes.push({ word, cmd, checked: true, by: ">" });
    for (const at of programs(cmd.argv)) {
      const name = path.basename(cmd.argv[at]);
      const args = cmd.argv.slice(at + 1);
      const files = args.filter((a) => !a.startsWith("-"));
      const add = (word: string | undefined, checked: boolean, extra: Partial<Write> = {}) => void (word !== undefined && writes.push({ word, cmd, checked, by: name, ...extra }));
      const blind = unnamedWrite(name, args, filesOnly && ((sources) => filesOnly(sources, cmd)));
      const call = name === "git" ? gitCall(args) : undefined;
      if (blind) unlisted.push({ cmd, reason: blind, dirs: unnamedWriteDirs(name, args), ...(call && typeof call !== "string" && WORKTREE_GIT.has(call.sub ?? "") ? { git: call.dirs } : {}) });
      unknown ??= blind;
      if (name === "tee" || name === "truncate") files.forEach((f) => add(f, true));
      else if (name === "sed" && args.some((a) => /^(-[a-zA-Z]*i|--in-place)/.test(a))) files.slice(args.some((a) => /^(-[a-zA-Z]*e$|--expression)/.test(a)) ? 0 : 1).forEach((f) => add(f, true));
      else if ((name === "perl" || name === "ruby") && args.some((a) => /^-[a-zA-Z]*i/.test(a))) files.slice(args.some((a) => /^-[a-zA-Z]*e$/.test(a)) ? 1 : 0).forEach((f) => add(f, false));
      else if (["cp", "mv", "ln", "install", "rsync"].includes(name)) {
        // `-t DIR` / `--target-directory=DIR`: every operand is a source (the rules read the last
        // one as the destination and never look at DIR).
        // Read by the tool's own options (round 4, finding 4, second pass: `--target-dir=`,
        // `-rt..`, the value of `-S`); one it cannot read lists what the plain reading finds.
        const words = copyWords(name, args);
        const t = words.unknown ? valued(args, "t", "--target-directory").at(-1) : words.target;
        const operands = words.unknown ? files.filter((f) => f !== t && !(name === "install" && valued(args, "m", "--mode").includes(f))) : words.operands;
        if (t !== undefined) add(t, false, { dir: true, sources: operands });
        else if (operands.length > 1) add(operands.at(-1), true, { sources: operands.slice(0, -1) });
        else if (name === "ln" && operands.length === 1) add(path.basename(operands[0]), false, { sources: operands });
        // A hard link makes the source the same file as the link: a write through either name
        // writes both, so the source is the session's too.
        if (words.hard) for (const src of t !== undefined || operands.length === 1 ? operands : operands.slice(0, -1)) add(src, false);
      } else if (name === "dd") args.filter((a) => a.startsWith("of=")).forEach((a) => add(a.slice(3), true));
      else if (name === "patch") {
        files.forEach((f) => add(f, true));
        for (const o of getopt(args, PATCH_OPTIONS).opts) if (["-o", "--output", "-r", "--reject-file"].includes(o.name)) add(o.value, false);
      }
      else if (["gcc", "cc", "clang", "g++", "c++", "clang++"].includes(name)) valued(args, "o", "--output").forEach((f) => add(f, false));
      else if (name === "sort") {
        const got = getopt(args, { flags: "bdfghiMnrRsuVz", values: "otkS", long: Object.fromEntries([...longs("value", "output key field-separator buffer-size parallel temporary-directory files0-from compress-program"), ...longs("flag", "reverse unique numeric-sort general-numeric-sort human-numeric-sort month-sort version-sort random-sort stable ignore-case dictionary-order ignore-leading-blanks ignore-nonprinting zero-terminated")]) });
        for (const o of got.opts) if (["-o", "--output"].includes(o.name)) add(o.value, false);
      }
      else if (name === "tree") valued(args, "o", "--never").forEach((f) => add(f, false));
      else if (name === "less") [...valued(args, "o", "--log-file"), ...valued(args, "O", "--LOG-FILE")].forEach((f) => add(f, false));
      else if (name === "uniq" || name === "xxd") add(files.length > 1 ? files[1] : undefined, false);
      else if ((name === "yq" || name === "jq") && args.some((a) => /^(-[a-zA-Z]*i|--inplace)$/.test(a))) files.slice(1).forEach((f) => add(f, false));
      // B7-7: a directory or a file an option names for the program to write in: tar's `-C` and
      // unzip's `-d` when they extract, find's `-fprint0` (the rules ask on `-fprint`, `-fprintf`
      // and `-fls`), rsync's log, batch, backup, temp and partial places. Each is held to the write
      // check for that place (`tar -xf a.tar -C .git/hooks`).
      // (A place known only when the command runs is the unnamed write's: the project is marked.)
      // Held to the check of protected places alone (decide.ts, writeProblem), which reads every
      // write listed here where it lands: what the rules say of the program's place outside the
      // project stands (`tar -xf a.tar -C /tmp` is the model's, as before).
      const place = (word: string | undefined, dir: boolean) => void (word !== undefined && plainWord(word) && add(word, true, dir ? { dir: true } : {}));
      if (blind && (name === "tar" || name === "gtar" || name === "bsdtar")) for (const o of getopt(tarWords(args), TAR_OPTIONS).opts) if (o.name === "-C" || o.name === "--directory") place(o.value, true);
      if (blind && name === "unzip") valued(args, "d", "--never").forEach((d) => place(d, true));
      if (name === "find") args.forEach((a, k) => void (/^-(fprint0?|fprintf|fls)$/.test(a) && place(args[k + 1], false)));
      if (name === "rsync") for (const o of getopt(args, COPY_OPTIONS.rsync).opts) {
        if (["--log-file", "--write-batch", "--only-write-batch"].includes(o.name)) place(o.value, false);
        if (["--backup-dir", "--temp-dir", "-T", "--partial-dir"].includes(o.name)) place(o.value, true);
      }
      if (name === "curl" || name === "wget") {
        // Round 4, finding 17, second pass: every file each writes, where it writes it, and the
        // directory of a name it chooses (checked as a write there: `--output-dir .git/hooks -O`).
        const { named, chosen } = fetcherWrites(name, args);
        for (const n of named) add(n.word, n.checked);
        for (const c of chosen) add(c.dir || ".", false, { dir: true });
      }
      else if (name === "git") for (const [word, dir] of gitWrites(args)) add(word, false, { dir });
    }
  }
  return { writes, ...(unknown ? { unknown } : {}), unlisted };
}

// The files this command would write, append to or edit in place, as the rules cannot always
// tell (they leave an appended file's origin alone, and do not follow `sed -i`).
//
// A glob bash expands is every file it matches where the command runs (round 4, finding 4:
// `sed -i ... scripts/*.sh` writes scripts/build.sh). `expand` gives those files, or undefined
// when it cannot tell; such a word is handed to `unlisted` with its command.
export function writtenBy(
  cmds: Simple[],
  resolve: (word: string, cmd?: Simple) => string | undefined,
  expand?: (word: string, cmd: Simple) => string[] | undefined,
  unlisted?: (word: string, cmd: Simple) => void,
): string[] {
  const out: (string | undefined)[] = [];
  const glob = (w: string) => !!expand && !/[$`]/.test(w) && /[*?]|\[.*\]/s.test(w);
  // The files a word names: its matches when it is a glob.
  const named = (word: string, cmd: Simple): (string | undefined)[] => {
    if (!glob(word)) return [resolve(word, cmd)];
    const files = expand!(word, cmd);
    if (files === undefined) unlisted?.(word, cmd);
    return files ?? [resolve(word, cmd)];
  };
  for (const w of writesOf(cmds).writes) {
    const targets = named(w.word, w.cmd);
    if (!w.dir) out.push(...targets);
    const p = resolve(w.word, w.cmd);
    if (p && w.sources) for (const s of w.sources) out.push(...(glob(s) ? (expand!(s, w.cmd) ?? (unlisted?.(s, w.cmd), [s])) : [s]).map((f) => path.join(p, path.basename(f))));
  }
  return out.filter((p): p is string => !!p);
}

// ---- where each command runs (round 4, group B, third pass, first part, third go: B3c) ----
//
// bash keeps the directory it is in as text, $PWD. A `cd` joins a relative word to that text and
// takes `.` and `..` off the text (a `..` takes the name before it off, once that name is a
// directory or a link to one), then goes to the directory the text names; where the text names
// nothing (or a `..` follows a name that is no directory) it goes where the kernel's walk of the
// joined word leads, and $PWD is then that real path. `cd -P` walks as the kernel does. A file is
// opened by the kernel, from the real directory. A subshell (`( )`, a substitution, a process
// substitution, each part of a pipeline, a background job) starts where the shell around it is,
// and what a `cd` does inside it ends with it; a group `{ }` is no subshell. `a || cd x` may or
// may not move; a `cd` in a branch, a loop or a function's body moves the shell only sometimes.
// Probed with bash 5.2.37 (xcheck/b3c/bash/).
//
// B3d: a place held as known must be the place bash is in, for certain. It rests on the tree as
// it stands before the call, and on nothing in the call having run before that could change it:
// a name is judged as the file system stands now (a link an earlier command of the call makes is
// not seen: a limit of judging a call before it runs). So a `cd` succeeds for certain only where
// it has no redirect (a redirect that fails keeps it from running) and no assignment in front,
// its directory can be entered now (search permission), and every command that ran before it in
// the call is one that cannot remove, rename or re-permission a directory (STILL); nothing that
// runs beside it (a pipeline's other part, a background job, a process substitution) or before it
// out of the text's order (a heredoc's substitution) may be anything else either. Otherwise it may
// also fail, and leave the shell where it was: after `cd x ;` the shell is in one of two places.
//
// B5, the maintainer's decision: a directory counts as known only in a stated shape of call
// (knownShape); any other call that runs a `cd`, `pushd` or `popd` goes to the model whole, and
// what is outside the shape is not analysed. The walk below computes places as if every move ran
// as written; knownShape says whether that reading holds.

// A directory bash is in: its $PWD text and the real directory that text names.
export interface Place {
  logical: string;
  real: string;
  // Another text $PWD may hold for the same directory: the starting one is the PWD bash inherits
  // when that names the directory it starts in, and the real path otherwise. A relative `cd` is
  // followed only where both texts lead to the same directory.
  alt?: string;
}
// Where a command runs: each place it may be in (several after `true || cd x`, or one for each
// value of a loop over directories), or undefined where the check cannot tell.
export type Places = Place[] | undefined;

const realDir = (p: string): string | undefined => {
  try {
    const real = fs.realpathSync.native(p);
    return fs.statSync(real).isDirectory() ? real : undefined;
  } catch {
    return undefined;
  }
};
const isDirectory = (p: string): boolean => {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
};
// A `cd` there succeeds now: search permission on the directory, by both its texts (B3d).
const enterable = (p: Place): boolean => {
  try {
    for (const dir of new Set([p.logical, p.real])) fs.accessSync(dir, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
};

// Commands that cannot remove, rename or re-permission a directory, nor put anything at a name
// (B3d): `cd`, `pushd` and `popd` change only the shell's own directory; `pwd`, `echo`, `printf`,
// `true`, `false` and `:` are builtins that write only to their output; `ls`, `cat`, `test` and
// `[` only read. (A redirect on one of them can make a file, not take a directory away or put
// a link in its place; what a substitution in their words runs is a command of its own.)
const STILL = new Set(["cd", "pushd", "popd", "pwd", "echo", "printf", "true", "false", ":", "ls", "cat", "test", "["]);
// Whether a simple command, as the parser lists it, is one of those, or a keyword (`fi`, `}`,
// `then`), a loop or `case` header, or assignments alone (not to PATH, which makes `ls` another
// program).
function still(argv: string[]): boolean {
  let k = 0;
  while (k < argv.length && (KEEPS_COMMAND.has(argv[k]) || ["}", "fi", "done", "esac"].includes(argv[k]))) k++;
  for (; k < argv.length && ASSIGN.test(argv[k]); k++) if (ASSIGN.exec(argv[k])![1] === "PATH") return false;
  // (B5: the lookup a `cd "$(git rev-parse --show-toplevel)"` runs changes nothing either.)
  if (argv.slice(k).join(" ") === "git rev-parse --show-toplevel") return true;
  return k === argv.length || ["for", "select", "case"].includes(argv[k]) || STILL.has(argv[k]);
}
// Whether a text has a part that runs beside another (a `|` or `|&`, a background `&`, a process
// substitution), or a heredoc, whose substitutions run before the commands written before them.
// By the text: a `|` in quotes counts too, which only costs a place.
const CONCURRENT = /(^|[^|])\|(?!\|)|(^|[^&<>])&(?![&>])|[<>]\(/;
const HEREDOC_TEXT = /(^|[^<])<<(?!<)/;

// B7-10: the CDPATH of the shell a command runs in. The plugin's shell hook takes bash's own
// variables out of every shell it sees unless the user's `sandboxKeepEnv` names them, so the
// shell has the plugin's CDPATH only where that list names it. guard.ts does not read the
// configuration: the plugin says so when it starts, `shellAlsoKeeps(config.enabled ?
// config.sandboxKeepEnv : undefined)` (undefined: every variable is kept). Until it has, the
// shell is taken to inherit the plugin's own CDPATH, as before (fail closed: a relative `cd` is
// then not followed).
// One guard serves every plugin instance of the process, so what any of them hands its shells
// counts for all: the plugin adds its list (`shellAlsoKeeps`), and nothing takes a name away
// again but `shellKeeps`, which sets the whole answer outright (the tests' way back).
let keptByShell: Set<string> | undefined;
export function shellKeeps(names: Iterable<string> | undefined): void {
  keptByShell = names === undefined ? undefined : new Set(names);
  keepsEverything = false;
}
let keepsEverything = false;
export function shellAlsoKeeps(names: Iterable<string> | undefined): void {
  if (names === undefined) keepsEverything = true;
  else keptByShell = new Set([...(keptByShell ?? []), ...names]);
}
const shellCdpath = (): string | undefined => (keepsEverything || keptByShell === undefined || keptByShell.has("CDPATH") ? process.env.CDPATH || undefined : undefined);

// The place a tool call starts in.
export function startPlace(dir: string): Place {
  const real = realDir(dir) ?? dir;
  const inherited = process.env.PWD;
  const alt = inherited && path.isAbsolute(inherited) && inherited !== real && realDir(inherited) === real ? inherited : undefined;
  return alt ? { logical: real, real, alt } : { logical: real, real };
}

// Where `cd <word>` leads from `from`, as bash goes there (the word as bash has it once expanded;
// a leading `~` or `~/` is the home directory, as unquoted). Undefined where it leads to nothing
// that exists now, or where the check cannot tell: `~user`, `~+`, `~-`, a word bash may look up
// in a CDPATH it inherits. `physical`: `cd -P`.
// (For the other writer, decide.ts `gitEnds`: a `cd <word>` is `cdTo(place, word)`, starting from
// `startPlace(cwd)` and keeping the Place it returns for the next `cd`; the directory git works in
// is its `.real`. `git -C <dir>` is a chdir, the kernel's walk: `cdTo(place, dir, true)`.)
export function cdTo(from: Place, word: string, physical = false): Place | undefined {
  if (word === "" || /^~[^/]/.test(word)) return undefined;
  const target = tilde(word);
  // B7-10: bash looks a relative word up in CDPATH, for `cd` and `cd -P` alike; a plain chdir
  // (`git -C`, which is what `physical` stands for here) never does. Only where the shell the
  // command runs in has a CDPATH (shellCdpath): the walker asks that for a `cd -P` (cdWord).
  if (!physical && shellCdpath() && !/^(\/|\.\.?(\/|$))/.test(target)) return undefined;
  const one = (base: string): Place | undefined => {
    const joined = path.isAbsolute(target) ? target : `${base}/${target}`;
    // B7-9: a target reached through /proc/self is the walker's own directory, not the shell's.
    if (procRelative(joined)) return undefined;
    const kernel = (): Place | undefined => {
      const real = realDir(joined);
      return real === undefined ? undefined : { logical: real, real };
    };
    if (physical) return kernel();
    const parts: string[] = [];
    for (const part of joined.split("/")) {
      if (part === "" || part === ".") continue;
      if (part !== "..") parts.push(part);
      else if (!isDirectory(`/${parts.join("/")}`)) return kernel();
      else parts.pop();
    }
    const logical = `/${parts.join("/")}`;
    if (procRelative(logical)) return undefined;
    const real = realDir(logical);
    return real === undefined ? kernel() : { logical, real };
  };
  const to = one(physical ? from.real : from.logical);
  if (!to || physical || path.isAbsolute(target) || from.alt === undefined) return to;
  const other = one(from.alt);
  if (!other || other.real !== to.real) return undefined;
  return other.logical === to.logical ? to : { ...to, alt: other.logical };
}

const union = (a: Places, b: Places): Places => {
  if (a === undefined || b === undefined) return undefined;
  const seen = new Set<string>();
  return [...a, ...b].filter((p) => {
    const key = `${p.logical}\0${p.real}\0${p.alt ?? ""}`;
    return !seen.has(key) && !!seen.add(key);
  });
};

// One simple command as the rules' parser lists it, with where it runs; for a `cd` or `pushd`,
// its word and where it leads from there.
interface PlacedCommand {
  argv: string[];
  words: string[];
  places: Places;
  cd?: { word: string; to: Places };
  // The name of the function this command's words define (`name ( )`).
  def?: string;
  // It stands at the top level of the text (no frame, no substitution around it).
  top?: boolean;
  // B5: it stands in a loop, a branch or a function's body, at any depth.
  guarded?: boolean;
  // B7-3: its words are a pattern of a `case` (or the `case` header with its first pattern).
  pattern?: boolean;
  // B7-2: the pipeline it is a part of (a number of its own for each pipeline of each list).
  pipe?: number;
}
// B5: a `cd`, `pushd`, `popd` or `set -P` the walk met, with what knownShape asks of it: its words
// from the program on (`own`) and their text as written (`raw`); the words in front (keywords,
// assignments); whether it has a redirect; whether it stands in a loop, a branch or a
// function's body; where it leads (undefined where the walk cannot follow its word), and whether
// that is a directory the `mkdir` before it makes.
interface MoveSeen {
  own: string[];
  raw: string[];
  lead: string[];
  redir: boolean;
  guarded: boolean;
  to: Places;
  made: boolean;
}
interface WalkContext {
  command: string;
  out: PlacedCommand[];
  // Where the body of the function of that name runs: where it is called (B3d: where its one call
  // stands, or where the call starts when nothing in the call changes directory).
  fnPlaces: (name: string | undefined) => Places;
  bail: boolean;
  // B3d: something before this text may have changed the tree (in a nested shell's code: what the
  // call around it runs); the text has parts that run beside each other or out of its order
  // (CONCURRENT, HEREDOC_TEXT); every command of the text is STILL.
  dirty: boolean;
  concurrent: boolean;
  heredoc: boolean;
  allStill: boolean;
  // How many times the text defines each function (`name ( )`).
  defs: Map<string, number>;
  // B5: the text being walked stands in a loop, a branch or a function's body of the text around
  // it; the call sets IFS somewhere (an unquoted expansion may then split anywhere); every move met.
  inside: boolean;
  ifs: boolean;
  seen: MoveSeen[];
}
// A part of the text that holds a list of commands: the whole text, a subshell, a group, the
// body of a branch, a loop or a `case`, or a function's body.
interface Frame {
  kind: "top" | "(" | "{" | "if" | "loop" | "case";
  fn: boolean;
  // Where the shell is when the frame begins (before a function's body: where it is defined).
  entry: Places;
  // Where the next command runs.
  here: Places;
  // The list being read: where it began, where its pipeline began, where the shell is when what
  // was read so far succeeded or failed, the operator before the pipeline being read.
  listStart: Places;
  pipeStart: Places;
  ok: Places;
  fail: Places;
  op: "" | "&&" | "||";
  // The pipeline being read: it has a `|`; it runs nowhere (after `cd x || ...`, where the cd
  // goes to a directory that exists); where the shell is after its last part succeeded or failed;
  // its simple commands; its last simple command's words.
  piped: boolean;
  dead: boolean;
  elemOk: Places;
  elemFail: Places;
  simple: number;
  compound: boolean;
  last?: string[];
  // The previous pipeline of the list, when it was one simple command; B5: the one before it, when
  // `&&` joined the two.
  prev?: string[];
  prev2?: string[];
  // B5: every operator of the list so far is `&&` (madeHere's `rm` then ran, and succeeded).
  andOnly: boolean;
  // `case`: a pattern is being read.
  pattern?: boolean;
  // B7-2: the number of the pipeline being read.
  pipe: number;
  // The group `{ }` that just ended in this frame's list, with where the shell was before it.
  group?: { entry: Places };
}
const KEEPS_COMMAND = new Set(["if", "then", "elif", "else", "do", "while", "until", "!", "time", "{"]);
// B7-2: pipelines are numbered across every text walked, so that no two share a number.
let pipelines = 0;

// Where `mkdir [-p] <word> && cd <word>` leads, the directory not being there yet: the text joined
// as `cd` joins it, under the real directory of the part that exists. Only where nothing before
// the `mkdir` in the call could have changed the tree (B3d: `settled`, every command before it
// STILL; that an earlier command does not name the missing part says nothing of the parts that
// exist, nor of an archive that holds the name), so that what exists now is what `mkdir -p` finds.
// B5: also `rm -rf W && mkdir [-p] W && cd W`, by this rule: in a chain joined by `&&`, where W is
// one plain name and every other command before the `mkdir` cannot change the tree, `cd W` enters
// the new directory W of the place the chain stands in (the `rm` succeeded, so nothing is at W
// when the `mkdir` makes it, whatever was there before).
function madeHere(from: Place, word: string, raw: string, mkdir: string[] | undefined, rm: string[] | undefined, settled: (skip: string[][]) => boolean): Place | undefined {
  if (!mkdir || mkdir[0] !== "mkdir" || literalWord(raw) !== word || /[$`*?[\]~\\]/.test(word) || word.split("/").includes("..")) return undefined;
  const operands: string[] = [];
  let options = true;
  for (const w of mkdir.slice(1)) {
    if (options && w === "--") options = false;
    else if (options && /^-[pv]+$|^--(parents|verbose)$/.test(w)) continue;
    else if (options && w.startsWith("-")) return undefined;
    else operands.push(w);
  }
  if (!operands.includes(word)) return undefined;
  if (rm && /^[^/]+$/.test(word) && word !== "." && from.alt === undefined && rm.length >= 3 && rm[0] === "rm" && rm[rm.length - 1] === word && rm.slice(1, -1).every((w) => /^-(rf|fr|Rf|fR)$/.test(w) || ["-r", "-R", "-f"].includes(w)) && rm.slice(1, -1).some((w) => /[rR]/.test(w)) && settled([mkdir, rm])) {
    return { logical: path.join(from.logical, word), real: path.join(from.real, word) };
  }
  const logical = path.normalize(path.isAbsolute(word) ? word : `${from.logical}/${word}`);
  let existing = logical;
  const made: string[] = [];
  while (!fs.existsSync(existing)) {
    made.unshift(path.basename(existing));
    existing = path.dirname(existing);
  }
  const base = realDir(existing);
  if (!made.length || base === undefined || (from.alt !== undefined && !path.isAbsolute(word)) || !settled([mkdir])) return undefined;
  return { logical, real: path.join(base, ...made) };
}

// B5: the value of a word bash takes as it is written (quotes read, nothing expanded): unquoted
// text with no expansion, glob, brace, tilde or backslash, '…', and "…" with no `$`, backtick or
// backslash in it; undefined for any other word.
function literalWord(raw: string): string | undefined {
  let value = "";
  for (let j = 0; j < raw.length; j++) {
    const ch = raw[j];
    if (ch === "'" || ch === '"') {
      const end = raw.indexOf(ch, j + 1);
      if (end < 0) return undefined;
      const inner = raw.slice(j + 1, end);
      if (ch === '"' && /[$`\\]/.test(inner)) return undefined;
      value += inner;
      j = end;
    } else if (/[$`\\*?[\]{}~]/.test(ch)) return undefined;
    else value += ch;
  }
  return value;
}

// B5: the directory `git rev-parse --show-toplevel` names, run where the shell is (as bash runs
// it: in the real directory, with $PWD the text the shell holds, each text it may hold) with the
// environment the plugin's other git lookups use; undefined where git gives no answer, or two.
function toplevel(p: Place): string | undefined {
  const answers = new Set<string>();
  for (const pwd of new Set([p.logical, p.alt ?? p.logical])) {
    const r = spawnSync("git", gitArgs(["rev-parse", "--show-toplevel"]), { cwd: p.real, env: { ...gitEnv(), PWD: pwd }, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"], timeout: 3000 });
    if (r.error || r.status !== 0) return undefined;
    answers.add((r.stdout ?? "").replace(/\n+$/, ""));
  }
  const [top] = answers;
  return answers.size === 1 && path.isAbsolute(top) && !top.includes("\n") ? top : undefined;
}

// B5: where `cd <raw>` leads from `from`, for the words the plugin resolves itself, exactly these:
// a literal path (literalWord; not one that begins with `-` or `~`); `~` or `~/…`; `$HOME`, `$PWD`
// (`${…}` is the same thing), `$(pwd)` and `$(git rev-parse --show-toplevel)`, each quoted or not,
// with or without a literal `/…` after it. Unquoted, the value must be one bash's splitting and
// globbing leave as it is (no blank or glob character, and IFS set nowhere in the call). The git
// toplevel is taken only where nothing before the cd could have changed the tree (`settled`).
// Undefined for any other word, and where the word leads to nothing that exists now.
const RESOLVED = /^(")?(\$HOME|\$\{HOME\}|\$PWD|\$\{PWD\}|\$\(pwd\)|\$\(git rev-parse --show-toplevel\))/;
function cdWord(raw: string, from: Place, physical: boolean, settled: () => boolean, ifs: boolean): Place | undefined {
  const literal = literalWord(raw);
  // (B7-10: `cd -P x` looks x up in CDPATH as `cd x` does; cdTo's `physical` is a plain chdir.)
  if (literal !== undefined && physical && shellCdpath() && !/^(\/|\.\.?(\/|$))/.test(literal)) return undefined;
  if (literal !== undefined) return literal === "" || /^[-~]/.test(literal) ? undefined : cdTo(from, literal, physical);
  const home = process.env.HOME;
  if (raw === "~" || raw.startsWith("~/")) {
    const rest = raw === "~" ? "" : literalWord(raw.slice(1));
    return rest === undefined || !home || !path.isAbsolute(home) ? undefined : cdTo(from, `${home}${rest}`, physical);
  }
  const m = RESOLVED.exec(raw);
  if (!m) return undefined;
  let after = raw.slice(m[0].length);
  if (m[1]) {
    // `"$PWD/src"`: the quote goes on to a literal text and closes.
    const close = /^([^"$`\\]*)"/.exec(after);
    if (!close) return undefined;
    after = (close[1] ? `"${close[1]}"` : "") + after.slice(close[0].length);
  }
  const rest = literalWord(after);
  if (rest === undefined || (rest !== "" && !rest.startsWith("/"))) return undefined;
  const name = m[2].replace(/[${}()]/g, "");
  const values = name === "HOME" ? [home] : name === "PWD" || name === "pwd" ? [from.logical, from.alt ?? from.logical] : [settled() ? toplevel(from) : undefined];
  if (values.some((v) => v === undefined || !path.isAbsolute(v))) return undefined;
  if (!m[1] && (ifs || values.some((v) => /[\s*?[]/.test(v!)))) return undefined;
  // `$PWD/…` and `$(pwd)/…` are `./…` from where the shell is (both texts it may hold).
  return cdTo(from, name === "PWD" || name === "pwd" ? `.${rest}` : `${values[0]}${rest}`, physical);
}

// rules.ts `matchParen`, which the walk below reads the text with, as the parser does.
function parenEnd(s: string, open: number): number {
  let depth = 0;
  for (let i = open; i < s.length; i++) {
    if (s[i] === "\\") i++;
    else if (s[i] === "(") depth++;
    else if (s[i] === ")" && --depth === 0) return i;
  }
  return -1;
}

// The places of each command of `command` (as the rules' parser lists them, in that order), read
// the way the parser reads the text (this mirrors rules.ts `parse`, and the caller checks that
// both list the same commands).
function walk(command: string, starts: Places, depth: number, ctx: WalkContext): void {
  if (depth > 4) return;
  const s = command;
  const frames: Frame[] = [];
  const open = (kind: Frame["kind"], fn: boolean): Frame => {
    const outer = frames.length ? frames[frames.length - 1].here : starts;
    const here = fn ? ctx.fnPlaces(fnName) : outer;
    const f: Frame = { kind, fn, entry: outer, here, listStart: here, pipeStart: here, ok: here, fail: here, op: "", andOnly: true, piped: false, dead: false, elemOk: here, elemFail: here, simple: 0, compound: false, pipe: ++pipelines };
    frames.push(f);
    return f;
  };
  const top = () => frames[frames.length - 1];
  // B5: a command here stands in a loop, a branch or a function's body (of this text or of the
  // text around it).
  const guarded = () => ctx.inside || frames.some((f) => f.fn || f.kind === "loop" || f.kind === "if" || f.kind === "case");
  open("top", false);
  let fnPending = false;
  // The name a `name ( )` defines (undefined for `function name`); `defining`: the command being
  // recorded is that header (B3d: `cd ( )` defines a function, it moves nothing).
  let fnName: string | undefined;
  let defining: string | undefined;
  // `name ( )`: the parenthesis to skip, and the name's command.
  let fnClose = false;
  // `redir`: the command has a redirect (B3d: one that fails keeps the command from running).
  // B5: `raw`, each word of `argv` as written.
  let cur: { argv: string[]; raw: string[]; out: string[]; in: string[]; redir: boolean } = { argv: [], raw: [], out: [], in: [], redir: false };
  let word = "";
  let hasWord = false;
  let quoted = false;
  let redirect: "" | "out" | "in" = "";
  // B5: where the word being read begins in the text.
  let i = 0;
  let rawStart = 0;
  const heredocs: { delimiter: string; quoted: boolean; places: Places; guarded: boolean }[] = [];

  // (B5: a cd in a branch, a loop or a function's body is outside the shape, so what the shell is
  // after one of those is where it was before it.)
  const close = (kind: Frame["kind"]) => {
    const f = top();
    if (frames.length < 2 || f.kind !== kind) return void (ctx.bail = true);
    frames.pop();
    const after = kind === "{" && !f.fn ? f.here : f.entry;
    const outer = top();
    outer.here = after;
    outer.elemOk = outer.elemFail = after;
    outer.compound = true;
    // A redirect on the group that fails keeps it from running (B3d): see pushCmd.
    outer.group = kind === "{" && !f.fn ? { entry: f.entry } : undefined;
  };
  // A word bash reads where a command begins (a keyword only there, and only unquoted).
  const keyword = (w: string) => {
    const f = top();
    if (f.kind === "case" && f.pattern) {
      if (w === "esac" && cur.argv.length === 0) close("case");
      return;
    }
    if (f.kind === "case" && w === "in" && cur.argv[0] === "case") return void (f.pattern = true);
    const position = cur.argv.every((x) => KEEPS_COMMAND.has(x)) || (fnPending && cur.argv[0] === "function");
    if (!position) {
      if (cur.argv.length === 1 && cur.argv[0] === "function") {
        fnPending = true;
        fnName = undefined;
      }
      return;
    }
    const opens: Record<string, Frame["kind"]> = { "{": "{", if: "if", while: "loop", until: "loop", for: "loop", select: "loop", case: "case" };
    const closes: Record<string, Frame["kind"]> = { "}": "{", fi: "if", done: "loop", esac: "case" };
    if (opens[w]) {
      const g = open(opens[w], fnPending);
      fnPending = false;
      if (w === "case") g.pattern = false;
    } else if (closes[w] && cur.argv.length === 0) close(closes[w]);
    else if (fnPending && w !== "function") ctx.bail = true;
  };
  const pushWord = () => {
    if (hasWord) {
      const expanded = word.replace(/\$\{HOME\}|\$HOME\b/g, HOME);
      if (redirect === "out") cur.out.push(expanded);
      else if (redirect === "") {
        if (!quoted) keyword(word);
        cur.argv.push(expanded);
        cur.raw.push(s.slice(rawStart, i));
      } else cur.in.push(expanded);
      redirect = "";
    }
    word = "";
    hasWord = false;
    quoted = false;
  };
  // B3d: whether nothing that ran before the command just recorded (ctx.out's last; `skip`: ones
  // to leave out, the `mkdir` before a `cd` and the `rm` before it) could have changed the tree. A
  // command in a frame or a substitution may run beside what follows it in the text (`(cd x; ...)
  // | mv x y`): there, in a text with such parts, every command of the text must be STILL; at the
  // top level the shell runs a `cd` before anything after it. A heredoc's substitutions run before
  // the commands written before them. (B5: no cd stands in a loop, whose later commands run before
  // it on the next round: knownShape.)
  const settled = (skip: string[][] = []): boolean => {
    if (ctx.dirty || ((ctx.heredoc || (ctx.concurrent && (frames.length > 1 || depth > 0))) && !ctx.allStill)) return false;
    // (A function's definition counts as a command that is not STILL: `cd() { :; }` makes `cd`
    // another command.)
    return ctx.out.slice(0, -1).every((c) => skip.includes(c.argv) || (c.def === undefined && still(c.argv)));
  };
  // Where a `cd` or `pushd` leaves the shell, when it succeeds and when it fails, read as written
  // (whether it is in the shape is knownShape's to say). `sure`: nothing keeps it from running (no
  // redirect).
  const moved = (own: string[], raw: string[], f: Frame, at: Places, sure: boolean): { ok: Places; fail: Places; cd?: { word: string; to: Places }; made: boolean } => {
    if (own[0] === "popd" || own[0] === "set") return { ok: undefined, fail: undefined, made: false };
    let k = 1;
    let physical = false;
    for (; k < own.length && /^-./.test(own[k]); k++) {
      if (own[k] === "--") {
        k++;
        break;
      }
      for (const ch of own[k].slice(1)) if (ch === "L" || ch === "P") physical = ch === "P";
    }
    const word = k < own.length ? own[k] : "~";
    let to: Places;
    let made = false;
    if (at !== undefined && k < own.length) {
      const all = at.map((p) => {
        const m = f.op === "&&" && at.length === 1 ? madeHere(p, word, raw[k], f.prev, f.prev2, settled) : undefined;
        if (m) made = true;
        return m ?? cdWord(raw[k], p, physical, settled, ctx.ifs);
      });
      to = all.every((p): p is Place => !!p) ? all : undefined;
    }
    const cd = { word, to };
    if (to === undefined) return { ok: undefined, fail: at, cd, made };
    // B3d: certain to succeed, or it may leave the shell where it was.
    return { ok: to, fail: sure && to.every(enterable) && settled() ? [] : at, cd, made };
  };
  const pushCmd = () => {
    pushWord();
    redirect = "";
    if (cur.argv.length || cur.out.length) {
      const f = top();
      const argv = cur.argv;
      const record: PlacedCommand = { argv, words: [...argv, ...cur.out, ...cur.in], places: f.here, top: frames.length === 1 && depth === 0, guarded: guarded(), pipe: f.pipe, ...(f.kind === "case" && f.pattern ? { pattern: true } : {}) };
      ctx.out.push(record);
      f.simple++;
      f.last = argv;
      let k = 0;
      while (k < argv.length && KEEPS_COMMAND.has(argv[k])) k++;
      // A `cd` behind a keyword (`{ cd x`, `then cd x`) or an assignment (`X=1 cd x`) is outside
      // the shape (B5); the walk reads it as moving the shell (the rules do not follow one behind a
      // keyword, and the call asks: Located.hiddenCd).
      let a = k;
      while (a < argv.length && ASSIGN.test(argv[a])) a++;
      const own = argv.slice(a);
      if (defining !== undefined) {
        record.def = defining;
        ctx.defs.set(defining, (ctx.defs.get(defining) ?? 0) + 1);
      }
      const moves = defining === undefined && (["cd", "pushd", "popd"].includes(own[0]) || (own[0] === "set" && own.slice(1).some((w) => /^-[A-Za-z]*P/.test(w) || w === "physical")));
      if (moves) {
        const m = moved(own, cur.raw.slice(a), f, f.here, !cur.redir);
        if (m.cd) record.cd = m.cd;
        ctx.seen.push({ own, raw: cur.raw.slice(a), lead: argv.slice(0, a), redir: cur.redir, guarded: record.guarded!, to: m.cd?.to, made: m.made });
        f.elemOk = m.ok;
        f.elemFail = m.fail;
        f.here = m.ok;
      } else f.elemOk = f.elemFail = f.here;
      // A redirect on a group that fails keeps the group from running (B3d: `{ cd x; } < absent`):
      // the shell is then where it was before the group, and the group has failed.
      if (argv.length === 1 && argv[0] === "}" && cur.redir && f.group) f.elemFail = union(f.elemFail, f.group.entry);
      f.group = undefined;
    }
    cur = { argv: [], raw: [], out: [], in: [], redir: false };
    defining = undefined;
  };
  // The end of a pipeline, by the operator that ends it ("" at the end of the text, a `)` or a
  // `}`): the list goes on, or ends.
  const endPipeline = (op: "&&" | "||" | ";" | "&" | "") => {
    const f = top();
    const pOk = f.dead ? [] : f.piped ? f.pipeStart : f.elemOk;
    const pFail = f.dead ? [] : f.piped ? f.pipeStart : f.elemFail;
    const ok = f.op === "||" ? union(pOk, f.ok) : pOk;
    const fail = f.op === "&&" ? union(pFail, f.fail) : pFail;
    f.prev2 = f.op === "&&" && f.andOnly ? f.prev : undefined;
    f.prev = f.simple === 1 && !f.compound && !f.piped ? f.last : undefined;
    if (op === "&&" || op === "||") {
      f.op = op;
      if (op === "||") f.andOnly = false;
      f.ok = ok;
      f.fail = fail;
      const next = op === "&&" ? ok : fail;
      f.dead = next !== undefined && next.length === 0;
      f.here = f.dead ? f.pipeStart : next;
    } else {
      let end = op === "&" ? f.listStart : union(ok, fail);
      if (end !== undefined && end.length === 0) end = f.pipeStart;
      f.op = "";
      f.dead = false;
      f.here = f.listStart = f.ok = f.fail = end;
      f.prev = f.prev2 = undefined;
      f.andOnly = true;
    }
    f.pipeStart = f.elemOk = f.elemFail = f.here;
    f.piped = false;
    f.simple = 0;
    f.compound = false;
    f.pipe = ++pipelines;
  };
  // A substitution's commands (B5: where the substitution stands in a loop, a branch or a
  // function's body, so do they).
  const absorb = (inner: string, at: Places, within = guarded()) => {
    const saved = frames.length;
    const outer = ctx.inside;
    ctx.inside = within;
    walk(inner, at, depth + 1, ctx);
    ctx.inside = outer;
    if (frames.length !== saved) ctx.bail = true;
  };
  const heredocBody = (body: string, places: Places, within: boolean) => {
    for (let j = 0; j < body.length; j++) {
      if (body[j] === "\\") j++;
      else if (body[j] === "$" && body[j + 1] === "(") {
        const end = parenEnd(body, j + 1);
        if (end < 0) return;
        absorb(body.slice(j + 2, end), places, within);
        j = end;
      } else if (body[j] === "`") {
        const end = body.indexOf("`", j + 1);
        if (end < 0) return;
        absorb(body.slice(j + 1, end), places, within);
        j = end;
      }
    }
  };

  for (; i < s.length; i++) {
    if (!hasWord) rawStart = i;
    const c = s[i];
    const next = s[i + 1];
    if (c === "\\") {
      if (next !== "\n") {
        word += next ?? "";
        hasWord = true;
        quoted = true;
      }
      i++;
    } else if (c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) return void (ctx.bail = true);
      word += s.slice(i + 1, end);
      hasWord = true;
      quoted = true;
      i = end;
    } else if (c === '"') {
      hasWord = true;
      quoted = true;
      let j = i + 1;
      for (; j < s.length && s[j] !== '"'; j++) {
        if (s[j] === "\\" && j + 1 < s.length) word += s[++j];
        else if (s[j] === "$" && s[j + 1] === "(") {
          const end = parenEnd(s, j + 1);
          if (end < 0) return void (ctx.bail = true);
          absorb(s.slice(j + 2, end), top().here);
          word += "$()";
          j = end;
        } else if (s[j] === "`") {
          const end = s.indexOf("`", j + 1);
          if (end < 0) return void (ctx.bail = true);
          absorb(s.slice(j + 1, end), top().here);
          word += "$()";
          j = end;
        } else word += s[j];
      }
      if (j >= s.length) return void (ctx.bail = true);
      i = j;
    } else if (c === "`") {
      const end = s.indexOf("`", i + 1);
      if (end < 0) return void (ctx.bail = true);
      absorb(s.slice(i + 1, end), top().here);
      word += "$()";
      hasWord = true;
      i = end;
    } else if ((c === "$" || c === "<" || c === ">") && next === "(") {
      const end = parenEnd(s, i + 1);
      if (end < 0) return void (ctx.bail = true);
      absorb(s.slice(i + 2, end), top().here);
      word += "$()";
      hasWord = true;
      i = end;
    } else if (c === "<") {
      pushWord();
      cur.redir = true;
      const heredoc = next === "<" && s[i + 2] !== "<" ? /^<<-?\s*(['"]?)([\w.-]+)\1/.exec(s.slice(i)) : null;
      if (heredoc) {
        heredocs.push({ delimiter: heredoc[2], quoted: heredoc[1] !== "", places: top().here, guarded: guarded() });
        i += heredoc[0].length - 1;
      } else {
        if (next === "<") i += s[i + 2] === "<" ? 2 : 1;
        redirect = "in";
      }
    } else if (c === ">" || (c === "&" && next === ">")) {
      if (hasWord && /^\d+$/.test(word)) {
        word = "";
        hasWord = false;
        quoted = false;
      }
      pushWord();
      cur.redir = true;
      if (c === "&") i++;
      const append = s[i + 1] === ">";
      if (append || s[i + 1] === "|") i++;
      if (s[i + 1] === "&") {
        i++;
        while (/[\d-]/.test(s[i + 1] ?? "")) i++;
      } else redirect = "out";
    } else if (c === " " || c === "\t") {
      pushWord();
    } else if (c === "\n" || c === ";") {
      pushCmd();
      const f = top();
      if (c === ";" && f.kind === "case" && (next === ";" || next === "&")) f.pattern = true;
      endPipeline(";");
      while (c === "\n" && heredocs.length) {
        const doc = heredocs.shift()!;
        const end = new RegExp(`^\\s*${doc.delimiter.replace(/[.\-]/g, "\\$&")}\\s*$`, "m").exec(s.slice(i + 1));
        if (!doc.quoted) heredocBody(end ? s.slice(i + 1, i + 1 + end.index) : s.slice(i + 1), doc.places, doc.guarded);
        i = end ? i + end.index + end[0].length : s.length;
      }
    } else if (c === "&" || c === "|") {
      const pair = next === c;
      const caseEnd = c === "&" && s[i - 1] === ";" && top().kind === "case";
      if (pair || (c === "|" && next === "&")) i++;
      pushCmd();
      const f = top();
      if (caseEnd || (c === "|" && f.kind === "case" && f.pattern)) continue;
      if (pair) endPipeline(c === "&" ? "&&" : "||");
      else if (c === "&") endPipeline("&");
      else {
        f.piped = true;
        f.here = f.elemOk = f.elemFail = f.pipeStart;
      }
    } else if (c === "(" || c === ")") {
      const f = top();
      if (c === "(" && !hasWord && cur.argv.length === 0 && f.kind === "case" && f.pattern) {
        pushCmd();
        continue;
      }
      const words = cur.argv.length + (hasWord ? 1 : 0);
      // (B3d: also after a keyword, `{ g() { ...; }; }`, `then g() ...`.)
      let lead = 0;
      while (lead < cur.argv.length && ["{", "then", "do", "else"].includes(cur.argv[lead])) lead++;
      const header = c === "(" && /^\s*\)/.test(s.slice(i + 1)) && !quoted && (cur.argv[lead] === "function" ? words - lead === 2 : words - lead === 1);
      const defined = header ? (hasWord ? word : cur.argv[cur.argv.length - 1]) : undefined;
      defining = defined;
      pushCmd();
      if (defined !== undefined) {
        fnPending = true;
        fnClose = true;
        fnName = defined;
      } else if (c === ")" && fnClose) fnClose = false;
      else if (c === ")" && f.kind === "case" && f.pattern) f.pattern = false;
      else if (c === "(") {
        open("(", fnPending);
        fnPending = false;
      } else {
        endPipeline("");
        close("(");
      }
    } else if (c === "#" && !hasWord) {
      const end = s.indexOf("\n", i);
      i = end < 0 ? s.length : end - 1;
    } else {
      word += c;
      hasWord = true;
    }
  }
  pushCmd();
  endPipeline("");
  if (frames.length !== 1 || fnPending) ctx.bail = true;
}

// Every simple command of a tool call with the words bash passes (as allCommands), each with the
// places it runs in (see Place): the tool call's directory, followed as bash follows each `cd`,
// in the subshells, groups and nested shells it stands in. B5: only for a call in the shape
// (knownShape); in any other call that runs a `cd`, `pushd` or `popd` every place is undefined,
// and so is where each of its cds leads (`unfollowed` says why). Where a call in the shape has a
// text the walk and the rules' parser list differently, the place is undefined too. `cwd`: the
// one real directory of a command, where it has one. `cds`: each `cd` and `pushd` with its word
// and where it leads. A `cd` the rules do not follow (behind a keyword, `builtin`, `command`,
// inside `eval`) is reported: the rules place relative paths in the wrong directory after it.
export interface Located {
  cmds: Simple[];
  cwd: Map<Simple, string | undefined>;
  places: Map<Simple, Places>;
  // (B5: outside the shape, `at` keeps where the walk had the cd start, for the glob check of
  // placedReads alone: a guess, which can only add an ask.)
  cds: Map<Simple, { word: string; to: Places; at?: Places }>;
  // Something in the call changes directory.
  moves: boolean;
  hiddenCd?: string;
  // B5: the call is outside the shape: the reason, the same for every such call.
  unfollowed?: string;
  // B7-3: the commands that are patterns of a `case`, which run nothing.
  patterns: Set<Simple>;
  // B7-2: the pipeline each command is a part of, where the walk and the parser agree.
  pipes: Map<Simple, number>;
}
const CD_WORDS = new Set(["cd", "pushd", "popd"]);
const MOVES = /(^|[^\w.-])(cd|pushd|popd)([^\w.-]|$)|(^|[\s;&|(){}])set\s[^;&|\n]*(-[A-Za-z]*P|physical)/;
export const UNFOLLOWED = "a cd the checks do not follow: where its commands run cannot be told";
export function located(command: string, start: string | undefined): Located {
  const out: Located = { cmds: [], cwd: new Map(), places: new Map(), cds: new Map(), moves: MOVES.test(command), patterns: new Set(), pipes: new Map() };
  const starts: Places = start === undefined ? undefined : [startPlace(start)];
  const seen: MoveSeen[] = [];
  const texts: string[] = [];
  placeAll(command, starts, 0, out, false, false, /\bIFS\b/.test(command), seen, texts);
  if (out.moves && !knownShape(texts, seen, [...out.places.values()])) {
    out.unfollowed = UNFOLLOWED;
    for (const cmd of out.cmds) {
      out.places.set(cmd, undefined);
      out.cwd.set(cmd, undefined);
    }
    for (const [cmd, cd] of out.cds) out.cds.set(cmd, { word: cd.word, to: undefined, at: cd.at });
  }
  return out;
}

// B5 (the maintainer's decision): the one shape of call whose places count as known, as a list of
// what is allowed; anything it does not name is not known. `texts`: the call's text and the code
// of each nested shell in it; `seen`: every `cd`, `pushd`, `popd` and `set -P` the walk met, at
// any depth; `placed`: the places of every command of the call.
const MOVE_FUNCTION = /(^|[^\w.-])(cd|pushd|popd|pwd|git)\s*\(\s*\)|(^|[\s;&|(){}])function\s+(cd|pushd|popd|pwd|git)(?![\w.-])/;
const PROC = /^\/proc(\/|$)/;
function knownShape(texts: string[], seen: MoveSeen[], placed: Places[]): boolean {
  // 1. No function named cd, pushd or popd (nor pwd or git, which give two of the words below) is
  //    defined, in any spelling (`cd() …`, `function cd …`, in a group or a body; quotes and
  //    backslashes read away). `builtin`, `command`, `eval`, an alias and `enable` ask elsewhere.
  if (texts.some((t) => MOVE_FUNCTION.test(t.replace(/['"\\]/g, "")))) return false;
  for (const c of seen) {
    // 2. Bash's own `cd`, with nothing in front: not pushd, popd or `set -P`, no keyword (`!`,
    //    `time`, `then`), no assignment. (The `{` of a group may stand there: a group is no subshell,
    //    and the walk follows it; the rules do not, and such a call asks: Located.hiddenCd.)
    if (c.own[0] !== "cd" || !c.lead.every((w) => w === "{")) return false;
    // 3. No redirect of any spelling.
    if (c.redir) return false;
    // 4. Outside every loop, branch and function body, at any depth.
    if (c.guarded) return false;
    // 5. `cd [-L|-P|--] <one word>`.
    if (!(c.own.length === 2 && !c.own[1].startsWith("-")) && !(c.own.length === 3 && ["-L", "-P", "--"].includes(c.own[1]))) return false;
    // 6. Its word one the plugin resolves itself (cdWord), or the directory the `mkdir` directly
    //    before it makes (madeHere), from every place it may start in ...
    if (c.to === undefined) return false;
    // 7. ... to a directory there now that can be entered (a made one is not there yet) ...
    if (!c.made && !c.to.every(enterable)) return false;
    // 8. ... and not under /proc (the plugin would read its own directory there). (B7-9: one
    //    reached through /proc/self by a link on the way has no place at all: cdTo.)
    if (c.to.some((p) => PROC.test(p.logical) || PROC.test(p.real) || PROC.test(p.alt ?? ""))) return false;
  }
  // 9. And every command of the call has its places (a function's body called in two places, a
  //    text the walk and the parser read differently: not known).
  return placed.every((p) => p !== undefined);
}

// The word a command runs, behind keywords (`then f`, `time f`).
const ownWord = (argv: string[]): string | undefined => argv.find((w) => !KEEPS_COMMAND.has(w));
// `dirty`: what ran before this text (the call around a nested shell's code) may have changed the
// tree. B5: `inside`: the text is the code of a nested shell run from a loop, a branch or a
// function's body; `ifs`: the call sets IFS; `seen`, `texts`: what knownShape reads.
function placeAll(command: string, starts: Places, depth: number, out: Located, dirty: boolean, inside: boolean, ifs: boolean, seen: MoveSeen[], texts: string[]): void {
  if (depth > 4) return;
  texts.push(command);
  const parsed = parse(command);
  const run = (fnPlaces: (name: string | undefined) => Places): WalkContext => {
    const ctx: WalkContext = { command, out: [], fnPlaces, bail: false, dirty, concurrent: CONCURRENT.test(command), heredoc: HEREDOC_TEXT.test(command), allStill: parsed.cmds.every((c) => still(c.argv)) && !/\bfunction\b|\(\s*\)/.test(command), defs: new Map(), inside, ifs, seen: [] };
    walk(command, starts, 0, ctx);
    return ctx;
  };
  // A function's body runs where it is called: where the call starts when nothing in the call
  // changes directory. B3d: otherwise, where its one call stands at the top level, for a function
  // the text defines once (`name ( )`) and names nowhere else (no `trap`, `eval` or second call
  // that may run it), called after it is defined, in a text where no command's program is named
  // at run time (`$(printf ...)` may name it too); elsewhere the body's place is unknown.
  let ctx = run(() => (out.moves ? undefined : starts));
  if (out.moves && ctx.defs.size && !ctx.out.some((r) => /[$`]/.test(ownWord(r.argv) ?? ""))) {
    const placed = new Map<string, Places>();
    for (const [name, count] of ctx.defs) {
      const def = ctx.out.findIndex((r) => r.def === name);
      const calls = ctx.out.flatMap((r, n) => (r.def === undefined && ownWord(r.argv) === name ? [n] : []));
      const named = [...command.matchAll(new RegExp(`(?<![\\w.-])${name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}(?![\\w.-])`, "g"))].length;
      const call = ctx.out[calls[0]];
      if (count === 1 && named === 2 && calls.length === 1 && calls[0] > def && call.top && call.places) placed.set(name, call.places);
    }
    if (placed.size) ctx = run((name) => (name === undefined ? undefined : placed.get(name)));
  }
  seen.push(...ctx.seen);
  const aligned = !ctx.bail && ctx.out.length === parsed.cmds.length && ctx.out.every((w, n) => w.argv.join("\0") === parsed.cmds[n].argv.join("\0"));
  for (const [n, cmd] of parsed.cmds.entries()) {
    out.cmds.push(cmd);
    const places = aligned ? ctx.out[n].places : undefined;
    out.places.set(cmd, places);
    if (aligned && ctx.out[n].pattern) out.patterns.add(cmd);
    if (aligned && ctx.out[n].pipe !== undefined) out.pipes.set(cmd, ctx.out[n].pipe!);
    const reals = places && [...new Set(places.map((p) => p.real))];
    out.cwd.set(cmd, reals?.length === 1 ? reals[0] : undefined);
    const cd = aligned ? ctx.out[n].cd : undefined;
    if (cd) out.cds.set(cmd, { ...cd, at: places });
    else if (CD_WORDS.has(cmd.argv[0])) out.cds.set(cmd, { word: cmd.argv.find((w, k) => k > 0 && !w.startsWith("-")) ?? "~", to: undefined });
    for (const i of programs(cmd.argv)) {
      const name = path.basename(cmd.argv[i]);
      if (i > 0 && CD_WORDS.has(name)) out.hiddenCd ??= `${cmd.argv.slice(0, i + 2).join(" ")}: a cd the rules do not follow, so they judge relative paths in the wrong directory`;
      if (name === "eval" && cmd.argv.slice(i + 1).some((w) => /(^|[\s;&|({])(cd|pushd|popd)(\s|$|;)/.test(w) || CD_WORDS.has(w))) out.hiddenCd ??= "a cd inside eval, which the rules do not follow";
    }
  }
  // A nested shell starts where the command that runs it is; its $PWD is the one it inherits, or
  // the real path where it inherits none.
  const inherited = (places: Places): Places => places?.every((p) => p.alt === undefined || p.logical === p.real) ? places.map((p) => (p.logical === p.real ? p : { logical: p.logical, real: p.real, alt: p.real })) : undefined;
  // B3d: a nested shell's code runs after what the call ran before it, and beside what runs beside
  // it: it starts settled only where every other command of the text is STILL, and the command
  // that runs it is a shell (`bash -c`; not `find -exec sh -c`, `xargs sh -c`, which run it again).
  const SHELL_RUNNERS = ["bash", "sh", "dash", "zsh", "ksh"];
  for (const [n, cmd] of parsed.cmds.entries()) {
    const bodies = nestedBodies([cmd]);
    if (!bodies.length) continue;
    const before = dirty || !SHELL_RUNNERS.includes(path.basename(cmd.argv[0] ?? "")) || parsed.cmds.some((c, m) => m !== n && !still(c.argv));
    const within = inside || !aligned || !!ctx.out[n].guarded;
    for (const body of bodies) placeAll(body, inherited(out.places.get(cmd)), depth + 1, out, before, within, ifs, seen, texts);
  }
}

// ---- what a command reads where it runs (B3c) ----
//
// The rules judge each command's words in the directory they follow it to: through a plain `cd`
// at the top level of a call without parentheses, and nowhere else (in a call with a subshell or
// a group and a `cd`, a relative name is judged by its text alone). So the rules let through a
// `cd` into a credential directory and the reads after it where they lose track (`( cd .aws; cat
// zzz )`, `true || cd src; cat link-to-aws/zzz`). Here every command is judged again by the rules
// in each place it runs (where something in the call changes directory): an ask there asks.
// Each `cd` and `pushd` leads to a directory that is judged as a read of it, as the rules judge a
// `cd` (`cd .aws` asks: "cd reads a credential file"), and where the place it starts from is
// unknown, its word is judged as a path from the root (it may lead into any directory of that
// name). B5: a call outside the shape (Located.unfollowed) is the model's, whole: no reading of
// its commands' operands. A word that names the directory a command runs in by another name
// (hereWord) is judged as the path under each place the command runs in, in every call.
export function placedReads(where: Located, scope: Scope, judgeAt: (dir: string, words: string[]) => { action: string; reason: string }): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  const add = (action: "ask" | "classify", reason: string) => void (verdict = stricter(verdict, { action, reason }));
  if (where.moves) {
    for (const [cmd, { word, to, at: guess }] of where.cds) {
      const name = cmd.argv.find((w) => CD_WORDS.has(w)) ?? "cd";
      if (to) {
        for (const p of to) for (const dir of new Set([p.logical, p.real, ...(p.alt ? [p.alt] : [])])) if (readVerdict("read", dir, scope)) add("ask", `${name} reads a credential file: ${word} (${dir})`);
      } else if (!/[$`]/.test(word) && word !== "-" && !/^~[^/]/.test(word)) {
        const target = tilde(word);
        const p = path.isAbsolute(target) ? target : `/${target}`;
        if (readVerdict("read", p, scope)) add("ask", `${name} reads a credential file: ${word}, wherever it starts`);
        // A glob: each directory it matches where the cd runs (`cd .aw?`).
        if (/[*?[]/.test(word)) {
          for (const at of where.places.get(cmd) ?? guess ?? []) {
            const secret = expandWord(word, at.real)?.find((f) => readVerdict("read", f, scope));
            if (secret) add("ask", `${name} reads a credential file: ${word} matches ${secret}`);
          }
        }
      }
    }
  }
  if (where.unfollowed) add("classify", where.unfollowed);
  for (const cmd of where.cmds) {
    const places = where.places.get(cmd);
    let k = 0;
    while (k < cmd.argv.length && RULES_KEYWORDS.has(cmd.argv[k])) k++;
    const own = cmd.argv.slice(k);
    // B5: the words that name the directory the command runs in (or another process's) by
    // another name: its operands, an option's value after `=`, its redirects' targets.
    const named: { word: string; here: HereWord; write: boolean }[] = [];
    const look = (w: string, write: boolean) => {
      const value = /^-[^=]*=/.test(w) ? w.slice(w.indexOf("=") + 1) : w;
      const here = hereWord(value);
      if (here) named.push({ word: value, here, write });
    };
    own.forEach((w) => look(w, false));
    (cmd.in ?? []).forEach((w) => look(w, false));
    cmd.out.forEach((w) => look(w, true));
    for (const n of named) if (n.here.elsewhere) add("classify", `${n.word} names a directory the check cannot tell`);
    // B7-9: any other word that is a path through /proc/self, a process's entry there or a link
    // to one, in each place the command may run in: relative to the process that walks it.
    // (Not a pattern of a `case`: it names no file.)
    for (const w of where.patterns.has(cmd) ? [] : [...own, ...(cmd.in ?? []), ...cmd.out]) {
      const values = !w.startsWith("-") ? [w] : [...(w.includes("=") ? [w.slice(w.indexOf("=") + 1)] : []), ...(/^-[A-Za-z]./.test(w) ? [w.slice(2)] : [])];
      for (const value of values) if (throughProc(value, places)) add("classify", `${value.slice(0, 80)} is a path through /proc that is relative to the process that walks it: the check reads its own`);
    }
    if (!own.length && !named.length) continue;
    if (!places) {
      if (named.length) add("classify", `${named[0].word} names the directory a command runs in, which the check cannot tell`);
      continue;
    }
    if (!where.moves && !named.length) continue;
    const distinct = new Map(places.map((p) => [`${p.real}\0${p.logical}\0${p.alt ?? ""}`, p]));
    for (const p of distinct.values()) {
      const v = own.length ? judgeAt(p.real, own.map((w) => rewrite(w, p))) : undefined;
      if (v && (v.action === "ask" || v.action === "deny")) add("ask", `${v.reason} (where it runs: ${p.real})`);
      // Each such word as the file it names there, read or written, as the kernel walks it.
      for (const n of named) {
        if (n.here.elsewhere) continue;
        for (const text of hereTexts(n.here, p)) {
          for (const file of new Set([text, physical(text)])) {
            const f = n.write ? fileVerdict("edit", file, scope) : judgeAt(p.real, ["cat", file]);
            if (f.action === "ask" || f.action === "deny") add("ask", `${n.word}, which is ${file} where it runs: ${f.reason}`);
            else if (f.action === "classify") add("classify", `${n.word}, which is ${file} where it runs: ${f.reason}`);
          }
        }
      }
    }
  }
  return verdict;
}

// B7-9: whether a word of a command, as a path in any of the places the command may run in, is
// relative to the process that walks it (procRelative), in any expansion of its braces and
// globs. The two direct spellings of the directory itself (hereWord: `~+`, `/proc/self/cwd`) are
// read as the path under each place first, and only what follows them is walked.
function throughProc(word: string, places: Places): boolean {
  if (word === "" || /[$`\n]/.test(word) || /^~[^/+]/.test(word)) return false;
  const here = hereWord(word);
  if (here?.elsewhere) return false;
  const t = tilde(word);
  const texts = here ? (places ?? []).flatMap((p) => hereTexts(here, p)) : path.isAbsolute(t) ? [t] : (places ?? []).map((p) => `${p.real}/${t}`);
  for (const text of new Set(texts)) {
    const glob = /[*?]|\[.*\]/s.test(text);
    // What the glob's fixed front leads to, then every name it matches.
    const front = glob ? text.split("/").slice(0, text.split("/").findIndex((part) => /[*?[]/.test(part))).join("/") || "/" : text;
    if (!/[{]/.test(front) && procRelative(front)) return true;
    if (!glob && !text.includes("{")) continue;
    for (const name of expandNames(text, "/") ?? []) if (procRelative(name)) return true;
  }
  return false;
}

// B5: a word that names the directory the command runs in by another name: `~+` (bash's $PWD),
// `/proc/self/cwd` and `/proc/thread-self/cwd` (the shell's own directory, which the plugin would
// read as its own), each alone or before `/…`; or a place the checks do not know (`elsewhere`):
// `~-` (bash's $OLDPWD), a directory-stack entry (`~1`, `~+1`, `~-1`), the directory or root of
// another process or task (`/proc/<n>/cwd`, `/proc/$$/root`, `/proc/self/task/<n>/cwd`), and any
// path under /proc that walks a `..`. Read after `//` and `/./` are taken out of the spelling.
// (`/proc/self/root` is the root the plugin has too.)
interface HereWord {
  elsewhere: boolean;
  tilde: boolean;
  rest: string;
}
function hereWord(word: string): HereWord | undefined {
  if (/^~[+-]?\d+(\/|$)/.test(word) || /^~-(\/|$)/.test(word)) return { elsewhere: true, tilde: true, rest: "" };
  const plus = /^~\+(?=\/|$)/.exec(word);
  if (plus) return { elsewhere: false, tilde: true, rest: word.slice(plus[0].length) };
  if (!word.startsWith("/")) return undefined;
  let w = word.replace(/\/+/g, "/");
  for (let before = ""; before !== w; ) {
    before = w;
    w = w.replace(/\/\.(?=\/|$)/g, "").replace(/^\/\.\.(?=\/|$)/, "");
  }
  if (!w.startsWith("/")) w = `/${w}`;
  if (!PROC.test(w)) return undefined;
  // (A `..` after the directory is the kernel's walk from it: the path under the place.)
  const here = /^\/proc\/(self|thread-self)\/cwd(?=\/|$)/.exec(w);
  if (here) return { elsewhere: false, tilde: false, rest: w.slice(here[0].length) };
  if (/^\/proc\/(self|thread-self)\/root(\/|$)/.test(w)) return undefined;
  if (/^\/proc\/[^/]+\/(task\/[^/]+\/)?(cwd|root)(\/|$)/.test(w) || w.split("/").includes("..")) return { elsewhere: true, tilde: false, rest: "" };
  return undefined;
}
// The paths such a word is at a place: `~+` by each text $PWD may hold, `/proc/self/cwd` by the
// real directory (the kernel's link).
const hereTexts = (h: HereWord, p: Place): string[] => (h.tilde ? [...new Set([p.logical, p.alt ?? p.logical])] : [p.real]).map((dir) => `${dir}${h.rest}`);
// A command's word with such a name put in its place (the logical text for `~+`).
function rewrite(w: string, p: Place): string {
  const eq = /^-[^=]*=/.exec(w);
  const value = eq ? w.slice(eq[0].length) : w;
  const h = hereWord(value);
  return h && !h.elsewhere ? `${eq ? eq[0] : ""}${hereTexts(h, p)[0]}` : w;
}

// ---- variables exported after the fact ----

// `export NAME`, `declare -x NAME` and `typeset -x NAME` of a name the call sets elsewhere (before
// or after: an exported variable passes on its later values too) hand that value to every
// program that follows, as `NAME=value cmd` does (finding 10). Judged like that assignment.
export function exportProblem(cmds: Simple[], cwd: string | undefined, inProject: ((p: string) => boolean) | undefined): GuardVerdict | undefined {
  const values = new Map<string, (string | undefined)[]>();
  const exported = new Set<string>();
  const note = (name: string, value: string | undefined) => values.set(name, [...(values.get(name) ?? []), value]);
  for (const { argv } of cmds) {
    let i = 0;
    for (; i < argv.length && ASSIGN.test(argv[i]); i++) {
      const m = ASSIGN.exec(argv[i])!;
      note(m[1], argv[i].includes("+=") ? undefined : argv[i].slice(m[0].length));
    }
    const name = path.basename(argv[i] ?? "");
    const args = argv.slice(i + 1);
    if (DECLARERS.has(name)) {
      const exports = name === "export" || args.some((a) => /^-[a-zA-Z]*x/.test(a));
      const unexport = args.some((a) => /^-[a-zA-Z]*n/.test(a)) && name === "export";
      for (const a of args.filter((w) => !w.startsWith("-"))) {
        const m = ASSIGN.exec(a);
        if (m) note(m[1], a.includes("+=") ? undefined : a.slice(m[0].length));
        if (exports && !unexport) exported.add(m?.[1] ?? a);
      }
    }
    for (const n of assignedBy(name, args)) note(n, undefined);
    if (name === "for" || name === "select") note(argv[i + 1] ?? "", undefined);
  }
  let verdict: GuardVerdict | undefined;
  for (const name of exported) {
    const set = values.get(name);
    if (!set) continue;
    if (ENV_DANGEROUS.test(name)) {
      if (set.some((v) => v === undefined || !envValueOk(name, v, cwd, inProject))) return { action: "ask", reason: dangerous(name) };
    } else if (!ENV_HARMLESS.test(name)) verdict ??= { action: "classify", reason: `sets ${name} for the programs it runs` };
  }
  return verdict;
}

// One simple command with its real words: package installs, options that run programs, the
// arithmetic sinks, variables set without an assignment, and files this session wrote.
export function argvGuard(cmd: Simple, ctx: ArgvContext): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  const add = (v: GuardVerdict | undefined) => void (verdict = stricter(verdict, v));
  const ask = (reason: string | undefined) => add(reason ? { action: "ask", reason } : undefined);
  const written = ctx.written();
  const ran = new Set<string>();
  const timeChanged = new Set<string>();
  const blind = new Set<string>();
  const blindWhy = new Map<string, string>();
  const unlisted = ctx.unlisted ?? [];
  // `checkTime`: "file" for an operand that may be no file at all (`pytest -k name`, `go test
  // ./...`): its change time is read only where it names a regular file now (B7-2).
  const runs = (word: string | undefined, checkTime: boolean | "file" = true) => {
    if (word === undefined) return;
    // `$PWD` and `$HOME` are places the guard knows, as the rules do (round 4, finding 4).
    const cwd = ctx.cwdOf?.(cmd);
    const placed = word.replace(/\$\{PWD\}|\$PWD(?!\w)/g, (m) => cwd ?? m).replace(/\$\{HOME\}|\$HOME(?!\w)/g, HOME);
    // A run word bash expands is every file it matches (round 4, finding 4, second pass:
    // `./scripts/build.s[h]`, `./scripts/*`); one the matcher cannot read, or in a directory the
    // check cannot place, is a word nobody can place.
    if (!/[$`]/.test(placed) && /[*?]|\[.*\]/s.test(placed)) {
      const t = tilde(placed);
      const files = (path.isAbsolute(t) || cwd !== undefined) && !unreadableGlob(placed) ? expandWord(placed, cwd ?? "/") : undefined;
      if (files === undefined) {
        if (written.size > 0 || unlisted.length > 0 || ctx.unknownWrite) blindWhy.set(word, `runs ${word}, a glob the check cannot expand, after this session wrote files`);
        return;
      }
      // (B7: with no match bash runs the word as it is written, `./r[1]`: a file the call makes.)
      if (!files.length) runPath(ctx.resolve(placed, cmd), word, placed, checkTime);
      for (const f of files) runPath(physical(f), word, word, checkTime);
      return;
    }
    runPath(ctx.resolve(placed, cmd), word, placed, checkTime);
  };
  // The same file under another name (round 4, finding 4, second pass: a hard link made before or
  // after the write, or a move): the device and inode numbers of the files this session wrote.
  let ids: Set<string> | undefined;
  const id = (p: string) => {
    try {
      const st = fs.statSync(p);
      return `${st.dev}:${st.ino}`;
    } catch {
      return undefined;
    }
  };
  const sameFile = (p: string) => {
    ids ??= new Set([...written].map(id).filter((x): x is string => x !== undefined));
    const own = ids.size ? id(p) : undefined;
    return own !== undefined && ids.has(own);
  };
  const began = ctx.began;
  const beganFor = (file: string, dev: bigint) => (typeof began === "function" ? began(file, dev) : began!);
  const runPath = (p: string | undefined, word: string, placed = word, checkTime: boolean | "file" = true) => {
    if (checkTime === "file" && began !== undefined) {
      try {
        const st = p ? fs.statSync(p, { bigint: true }) : undefined;
        if (st?.isFile() && st.ctimeNs >= beganFor(p!, st.dev)) return void timeChanged.add(p!);
      } catch {
        // no file there: an operand that names none
      }
    } else if (checkTime && began !== undefined) {
      try {
        const st = p ? fs.statSync(p, { bigint: true }) : undefined;
        if (!st || st.ctimeNs >= beganFor(p!, st.dev)) {
          if (p) timeChanged.add(p);
          else blindWhy.set(word, `runs ${word}, whose path or change time cannot be read`);
          return;
        }
      } catch {
        blindWhy.set(word, `runs ${word}, whose change time cannot be read`);
        return;
      }
    }
    if (p && (written.has(p) || sameFile(p))) ran.add(p);
    // After a write the guard cannot name or place, any file run by its path may be one it wrote.
    else if (ctx.unknownWrite) blind.add(word);
    else if (p ? unlisted.some((d) => within(p, d)) : unlisted.length > 0) blindWhy.set(word, `runs ${word}, in a place where this session wrote files the guard cannot list`);
    // The rules follow variables the guard does not: once the session has written a file, a run
    // word the guard cannot place may be it.
    else if (!p && /[$`]/.test(placed) && written.size > 0) blindWhy.set(word, `runs ${word}, which the guard cannot place, after this session wrote files`);
  };
  ask(traversalProblem(cmd.argv));
  // `for NAME do cmd` on one line: the rules read `do cmd` as words of the loop header and never
  // see `cmd`.
  if ((cmd.argv[0] === "for" || cmd.argv[0] === "select") && cmd.argv[2] === "do") ask(`${cmd.argv[0]} ${cmd.argv[1]} do on one line, where the rules read the loop's commands as words of its header`);
  // The program an `npx` names is a program position too: what is asked about a program is
  // asked about it under npx.
  const npx = ctx.npx?.(cmd);
  for (const at of npx?.program !== undefined ? [...programs(cmd.argv), npx.program] : programs(cmd.argv)) {
    const word = cmd.argv[at];
    if (ASSIGN.test(word)) continue;
    const name = path.basename(word);
    const args = cmd.argv.slice(at + 1);
    const files = args.filter((a) => !a.startsWith("-"));

    // B7-5: an option that reads a file of names, patterns or code is a read of that file, in
    // every place the command may run (listOptions).
    for (const f of listOptions(name, args)) {
      const why = listProblem(name, f, ctx.dirsOf ? ctx.dirsOf(cmd) : ctx.cwdOf?.(cmd) === undefined ? undefined : [ctx.cwdOf(cmd)!], ctx.scope);
      if (why) add(why);
    }

    // Package installs run third-party install scripts.
    const pip = /^python3?$/.test(name) && args[0] === "-m" && args[1] === "pip";
    const manager = pip ? "pip" : name;
    // A directory a global option names (`npm --prefix web`): one in the project (finding 29).
    const placeOk = (dir: string) => {
      const p = ctx.resolve(dir, cmd);
      return !!p && !!ctx.inProject?.(p);
    };
    if (Object.hasOwn(INSTALLERS, manager)) ask(installProblem(manager, pip ? args.slice(2) : args, placeOk));
    if (npx?.at === at) {
      // Third pass (the maintainer's decision): an npx that is not asked about goes to the
      // model, with the one reason the reading gives whatever the session wrote. The model is
      // shown the files the session wrote last: npm and the program read the project's files.
      // (Fourth pass: the last three that are files. A write to /dev/null, to a descriptor or
      // to a file that is gone since takes no place among them.)
      if (npx.ask) ask(npx.ask);
      else add({ action: "classify", reason: npx.model ?? "npx", files: [...written].filter(isFile).slice(-3) });
    } else if (name === "npx" || name === "bunx" || name === "pnpx" || name === "uvx" || name === "pipx") {
      // Fourth pass: by the word's name, wherever a program could stand and whatever path leads
      // to it (a path to a file named npx is not read as npx: decide.ts, npxWords). Not where
      // the word is only looked up: `command -v npx` and `command -V npx` print where the shell
      // would find it and run nothing. (`type`, `which` and `hash` take it as an operand, which
      // is no program position.)
      const chain = chainOf(cmd.argv);
      const last = chain[chain.length - 1];
      const shown = !traversalProblem(cmd.argv) && last !== undefined && last < at && cmd.argv[last] === "command" && /^-[vV]$/.test(cmd.argv[last + 1] ?? "");
      if (!shown) ask(`${name} downloads and runs a package`);
    }

    add(programProblem(name, args, ctx.cwdOf?.(cmd), ctx.inProject));
    if (MAKES.has(name) && getopt(args, MAKE_OPTIONS).unknown) add({ action: "classify", reason: `${name} has an option the check cannot read` });
    ask(sinkProblem(name, args));
    if (name === "curl" || name === "wget") ask(fetcherOptionProblem(name, args));
    if (name === "curl") add(fileUrlProblem(args, ctx.scope));
    const built = builtHost(name, args);
    if (built) add({ action: "classify", reason: built });
    const batch = lookupFileProblem(name, args);
    if (batch) add({ action: "classify", reason: batch });
    for (const variable of assignedBy(name, args)) {
      if (anyDangerous(variable)) ask(dangerous(variable));
      else if (inherited(variable)) add({ action: "classify", reason: `sets ${variable}, which the environment exports, for the programs that follow` });
    }
    // `set -a` exports every variable set after it (finding 10).
    if (name === "set") {
      const end = args.indexOf("--");
      if ((end < 0 ? args : args.slice(0, end)).some((a) => /^-[a-zA-Z]*a/.test(a))) ask("set -a exports every variable set after it to the programs that follow");
    }

    // A file this session wrote is the agent's own code: the model sees it before it runs.
    if (word.includes("/")) runs(word);
    // (B7-2: a test runner's or a builder's file operand is code it runs, `pytest x_test.py`,
    // `go run x.go`: judged by its change time too, where it names a file.)
    if (SHELLS.has(name) || INTERPRETERS.has(name) || FILE_RUNNERS.has(name) || /^python3?(\.\d+)?$/.test(name)) for (const f of files) runs(f, FILE_RUNNERS.has(name) ? "file" : false);
    if (INTERPRETERS.has(name) || /^python3?(\.\d+)?$/.test(name)) {
      // -m/-c/-e execute a module or inline code, not their next operand as a script path.
      if (!args.some((a) => /^(-m|-c|-e|--eval|--print)$/.test(a))) {
        let i = 0;
        while (i < args.length && args[i].startsWith("-")) {
          if (["-X", "-W", "--require", "-r", "--import", "--loader"].includes(args[i])) i++;
          i++;
        }
        // B7-11: bun's first word is a subcommand (`bun test`, `bun run build`, `bun build
        // src/index.ts`), not a script: the words after it are judged where they name a file.
        if (name === "bun" && BUN_SUBCOMMANDS.has(args[i] ?? "")) for (const f of args.slice(i + 1).filter((a) => !a.startsWith("-"))) runs(f, "file");
        else if (args[i]) runs(args[i]);
      }
    }
    // The files the program reads as code, each where it reads it (round 4, finding 5, second
    // pass): make's makefiles where its `-C` options lead (the default ones too), awk's and sed's
    // `-f`, a shell's script, `source`. Each is walked as the kernel walks it for standard input
    // or a device; a step of its path that this call links, moves or copies into place cannot be
    // walked before it exists, and asks; a file this session wrote goes to the model (runs).
    // A name known only at run time, or in a directory the check cannot place, goes to the model
    // (as a script named by a variable did before), or asks for make's `-f` (finding 5); a default
    // makefile in such a directory matters only when make's input is redirected.
    for (const code of codeFiles(name, args, ctx.cwdOf?.(cmd))) {
      const { word: f, dir, implicit } = code;
      const what = implicit ? `its default makefile ${f}` : f;
      if (expands(f) || (!path.isAbsolute(tilde(f)) && dir === undefined)) {
        if (implicit) {
          if (cmd.heredoc || cmd.in?.length || cmd.subshell) add({ action: "classify", reason: `${name} reads ${what} in a directory the check cannot place, with its input redirected` });
        } else if (MAKES.has(name)) ask(`make -f ${f} reads a makefile in a directory the check cannot place, which may be standard input or a device`);
        else add({ action: "classify", reason: `${name} reads code from ${f}, which is known only when the command runs` });
        continue;
      }
      const full = path.isAbsolute(tilde(f)) ? tilde(f) : `${dir}/${f}`;
      const device = codeFromDevice(f, dir);
      if (device) ask(`${name} reads code from standard input, a pipe or a device (${device}), which no check has read`);
      const parts = full.split("/");
      for (let k = 2; k <= parts.length; k++) {
        const step = parts.slice(0, k).join("/");
        const p = ctx.resolve(step, cmd);
        if (p && ctx.placed?.includes(p)) ask(`${name} reads ${what} through ${step}, which this call links, moves or copies into place: the check cannot walk it before it exists`);
      }
      if (ctx.placedUnknown) ask(`${name} reads ${what} after this call ${ctx.placedUnknown}: the check cannot walk the path before it exists`);
      if (implicit && !present(full)) continue;
      runs(full);
    }
  }
  // What the file itself shows comes first: it names the file, and the model is shown it.
  if (ran.size) add({ action: "classify", reason: `runs ${[...ran].map((f) => path.basename(f)).join(", ")}, which this session wrote`, files: [...ran] });
  if (blind.size) add({ action: "classify", reason: `runs ${[...blind].join(", ")} after this command wrote files the guard cannot list (${ctx.unknownWrite})` });
  for (const reason of blindWhy.values()) add({ action: "classify", reason });
  if (timeChanged.size) add({ action: "classify", reason: `runs ${[...timeChanged].map((p) => path.basename(p)).join(", ")}, changed since this session began`, files: [...timeChanged].filter(isFile) });
  // After a session write every program goes to the model unless it is on the safe list (round 4,
  // decision D3 turned round; B7-2). The trigger and the places are the runner check's: a file the
  // session wrote where the program runs, where it lives when a path names it, in what its words
  // name, or above. A program run by a path inside the project, a shell with a script and an
  // interpreter with a file are programs like any other here: an untouched script may source or
  // import what the session wrote. Under `npx X` and `npx --no-install X` the program is X.
  // The writes are the session's and those of the call's other commands, wherever they stand in
  // the text (ctx.others).
  if (!ctx.pattern?.(cmd)) for (const at of npx?.program !== undefined ? [...programs(cmd.argv), npx.program] : programs(cmd.argv)) {
    const word = cmd.argv[at];
    const name = path.basename(word);
    const args = cmd.argv.slice(at + 1);
    if (ASSIGN.test(word)) continue;
    if (safeAfterWrite(name, args, cmd, ctx)) continue;
    const places = runnerPlaces(name, args, ctx.cwdOf?.(cmd), (w) => ctx.resolve(w, cmd)) ?? [];
    if (word.includes("/")) {
      // Where it lives: for a glob, where each file it matches does (`./scripts/b*.sh`).
      const at = ctx.cwdOf?.(cmd);
      const glob = !/[$`{}]/.test(word) && /[*?]|\[.*\]/s.test(word);
      const found = glob ? ((path.isAbsolute(tilde(word)) || at !== undefined) && !unreadableGlob(word) ? expandWord(word, at ?? "/") : undefined) : undefined;
      if (glob) places.push(...(found?.length ? found.map((f) => path.dirname(f)) : [undefined]));
      else {
        const p = /[$`{}]/.test(word) || /^~[^/]/.test(word) ? undefined : ctx.resolve(word, cmd);
        places.push(p === undefined ? undefined : path.dirname(p));
      }
    }
    const other = ctx.others?.(cmd);
    add(runnerTouched(name, places, other?.written ?? written, other?.unlisted ?? unlisted, ctx));
  }
  return verdict;
}

// ---- the safe list (round 4, decision D3 turned round; B7-3) ----
//
// The programs that run and load nothing the project holds, whatever the session wrote: every
// other program goes to the model after a session write in its places. Each group with its
// reason. A name is on the list only in the forms the other guards already let through: an
// option of one of them that runs a program asks or goes to the model on its own
// (programProblem, sedProblem, awkProblem, fetcherOptionProblem, the rules).
const listed = (s: string) => s.split(/\s+/).filter(Boolean);
const SAFE_AFTER_WRITE = new Set([
  // Not programs at all: bash's reserved words where the parser lists one as a command's first
  // word (`for ... done`, `if ... fi`, `while`, `case ... esac`, a group, `[[`). What stands in
  // their bodies is a command of its own, with every guard. (Not `function` and `coproc`: the
  // parser lists the command after them among their own words, so it is read nowhere else.)
  ...listed("if then elif else fi for select in while until do done case esac { } ! [[ ]]"),
  // Builtins that steer the shell or its variables and run no file: bash implements them itself.
  ...listed("cd pushd popd pwd true false : read set unset export local declare typeset readonly wait exit return break continue shift type echo printf test ["),
  // Wrappers: the program they run is a program position of its own (programs()), judged there.
  ...listed("env timeout nice time nohup command exec"),
  // They print or compare bytes, names and metadata of what they are given, and load no code:
  // coreutils and their kin.
  ...listed("ls cat head tail wc sort uniq cut tr diff cmp comm stat file nl tac rev fold paste join column tee less more"),
  ...listed("basename dirname realpath readlink which du df tree md5sum sha1sum sha256sum sha512sum cksum od xxd hexdump strings base64"),
  ...listed("grep egrep fgrep"),
  // They make, copy, move, remove or re-permission files: what they write is recorded as a write.
  ...listed("mkdir touch cp mv rm rmdir ln chmod"),
  // They report on the machine or look a name up, and read nothing of the project.
  ...listed("sleep date uname whoami hostname id nproc uptime ps free ss ping dig nslookup host"),
  // Archives and compression: data in, data out. tar's options that run a program ask.
  ...listed("tar gzip gunzip zcat xz bzip2 zstd unzip patch"),
  // They fetch: what they read is on the network, what they write is recorded as a write, and
  // their only allowed options are the ones on fetcherWords' lists.
  ...listed("curl wget"),
]);
// git's subcommands that read objects, refs or the index, or write refs: no filter, driver or
// alias runs for them, and their hooks and config are read-only in the sandbox. (`push` among
// them, as `fetch` is: it sends objects, and whether it may run at all is the push check's.)
const SAFE_GIT = new Set(listed("branch tag fetch push rev-parse ls-tree rev-list remote mv rm gc ls-remote merge-base show-ref symbolic-ref for-each-ref count-objects reflog"));
// ... that touch the work tree or the index, and so may run a clean, smudge or process filter:
// safe where the configuration names no program of the project for one (gitFiltersAbsent).
// (`git stash` is one of them: see below.)
const FILTER_GIT = new Set(listed("status add commit reset restore checkout switch"));
// ... that show a diff, and so may also run diff.external, a diff driver's command or its
// textconv: safe where the configuration names no program of the project for those either.
const DIFF_GIT = new Set(listed("diff log show blame describe shortlog whatchanged"));
// The options with which `git ls-files` and `git cat-file` read only the index and the objects.
// With any other (`ls-files -m` compares the work tree through the clean filter, `cat-file
// --textconv` and `--filters` run a textconv or a smudge filter: B7-2) they are held to the
// configuration check.
const LS_FILES_PLAIN = /^(-[cosz]+|--(cached|others|stage|exclude-standard|full-name|error-unmatch|deduplicate|abbrev(=\d+)?|exclude=.*|directory|no-empty-directory))$/;
const CAT_FILE_PLAIN = /^-[tsep]$|^--(batch|batch-check|batch-command|batch-all-objects|buffer|unordered|follow-symlinks|allow-unknown-type)(=.*)?$/;
// bun's subcommands (bun 1.x `bun --help`): the word after `bun` is one of these, or a file.
const BUN_SUBCOMMANDS = new Set(listed("run test x repl exec install add remove update audit outdated link unlink publish patch pm info build init create upgrade why"));
function safeAfterWrite(name: string, args: string[], cmd: Simple, ctx: ArgvContext): boolean {
  // A shell is safe for the code it is handed (`bash -c`, whose commands are judged one by one);
  // with a script it is that script (`bash x.sh`, `source x`, `. x`), a program like any other.
  if (SHELLS.has(name)) return name !== "source" && name !== "." && shellScript(name, args) === undefined;
  if (SAFE_AFTER_WRITE.has(name)) return true;
  if (name === "rg") return !args.some((w) => w === "--pre" || w.startsWith("--pre="));
  // sed and awk with a program in their words that only edits or prints (sedProblem, awkProblem:
  // no `-f`, no `e` or `w` command, no `system()`, no `@include`), with or without `-i`.
  if (name === "sed") return sedProblem(args) === undefined;
  if (AWKS.has(name)) return awkProblem(args) === undefined;
  // jq with its filter in its words: not one read from a file, nor one that loads a module.
  if (name === "jq") return !args.some((w) => /^(-[a-zA-Z]*[fL]|--from-file|--library-path)/.test(w) || /\b(import|include)\b/.test(w));
  // zip's `-T`/`-TT` runs a command on the archive.
  if (name === "zip") return !args.some((w) => /^-[a-zA-Z0-9]*T/.test(w) || /^--(test|unzip-command)/.test(w));
  if (name === "find") return !args.some((w) => /^-(exec|execdir|ok|okdir)$/.test(w));
  if (name !== "git") return false;
  const call = gitCall(args);
  if (typeof call === "string") return false;
  const sub = call.sub ?? "";
  const filters = (diff: boolean) => ctx.gitFiltersAbsent?.(cmd, args, diff) ?? false;
  if (SAFE_GIT.has(sub)) return true;
  if (FILTER_GIT.has(sub)) return filters(false);
  if (DIFF_GIT.has(sub)) return filters(true);
  // `git stash` in every form saves and restores files of the work tree (a smudge filter may
  // run); `list` and `show` print a log or a diff.
  if (sub === "stash") return filters(["list", "show"].includes(call.rest[0] ?? ""));
  if (sub === "ls-files") return call.rest.every((w) => !w.startsWith("-") || w === "--" || LS_FILES_PLAIN.test(w)) || filters(false);
  if (sub === "cat-file") return call.rest.every((w) => !w.startsWith("-") || CAT_FILE_PLAIN.test(w)) || filters(true);
  if (sub === "bisect" && ["start", "reset", "good", "bad", "new", "old", "skip", "terms", "log"].includes(call.rest[0] ?? "")) return filters(false);
  // `git clean -n` lists what a clean would remove, and removes nothing.
  if (sub === "clean") return call.rest.some((w) => /^(-[a-zA-Z]*n[a-zA-Z]*|--dry-run)$/.test(w));
  if (sub === "config") return !configWrite(call.rest, false);
  if (sub === "worktree") return call.rest[0] === "list";
  return false;
}
// Whether a program is one that runs what its words name (a shell, an interpreter, a wrapper, a
// build tool or a package manager), for decide.ts: a filter the configuration gives to one of
// these may run a file of the project.
export const runsItsWords = (name: string): boolean => SHELLS.has(name) || INTERPRETERS.has(name) || /^python3?(\.\d+)?$/.test(name) || WRAPPER_NAMES.has(name) || MAKES.has(name) || AWKS.has(name) || FILE_RUNNERS.has(name) || RUNNER_SUBS.has(name) || Object.hasOwn(INSTALLERS, name) || ["sed", "xargs", "find", "git", "npx", "bunx", "pnpx", "uvx", "pipx"].includes(name);

// ---- options that read a file of names, patterns or code (B4-6; B7-5) ----
//
// `file -f F` prints F's first line in an error message, `file -m F` a line of F as a bad magic
// entry, `jq -f F` every line of F in its compile error, `find -files0-from F` F's text as a
// name it cannot find; grep's, rg's, du's and tar's lists of patterns answer whether a line of F
// matches. Each such F is a file the program reads: judged as `cat F`. Per program: the short
// letters (in a cluster, the value attached or the next word), the long names (GNU: any prefix
// that is no other option's name, the value after `=` or as the next word), find's
// single-dash name. `split`: the value is a list (`file -m a:b`).
interface ListSpec {
  short?: string;
  long?: string[];
  // Other options of the program that a prefix of a long name spells in full (`--exclude`).
  not?: string[];
  exact?: boolean;
  single?: string[];
  split?: string;
}
const LIST_OPTIONS: Record<string, ListSpec> = {
  file: { short: "fm", long: ["--files-from", "--magic-file"], split: ":" },
  grep: { short: "f", long: ["--file", "--exclude-from"], not: ["--exclude"] },
  egrep: { short: "f", long: ["--file", "--exclude-from"], not: ["--exclude"] },
  fgrep: { short: "f", long: ["--file", "--exclude-from"], not: ["--exclude"] },
  rg: { short: "f", long: ["--file", "--ignore-file"], exact: true },
  jq: { short: "f", long: ["--from-file"], exact: true },
  wc: { long: ["--files0-from"] },
  sort: { long: ["--files0-from"] },
  du: { short: "X", long: ["--files0-from", "--exclude-from"], not: ["--exclude"] },
  tar: { short: "TX", long: ["--files-from", "--exclude-from"], not: ["--exclude"] },
  gtar: { short: "TX", long: ["--files-from", "--exclude-from"], not: ["--exclude"] },
  bsdtar: { short: "TX", long: ["--files-from", "--exclude-from"], not: ["--exclude"] },
  find: { single: ["-files0-from"] },
};
function listOptions(name: string, args: string[]): string[] {
  const spec = LIST_OPTIONS[name];
  if (!spec) return [];
  const out: string[] = [];
  const words = name === "find" ? args : name.endsWith("tar") ? tarWords(args) : args;
  for (let i = 0; i < words.length; i++) {
    const a = words[i];
    if (a === "--" && name !== "find") break;
    if (spec.single?.includes(a)) out.push(words[++i] ?? "");
    else if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const given = eq < 0 ? a : a.slice(0, eq);
      const hit = spec.long?.some((l) => l === given || (!spec.exact && given.length > 2 && l.startsWith(given) && !spec.not?.includes(given)));
      if (hit) out.push(eq < 0 ? (words[++i] ?? "") : a.slice(eq + 1));
    } else if (spec.short && a.startsWith("-") && a.length > 1) {
      const at = [...a].findIndex((ch, k) => k > 0 && spec.short!.includes(ch));
      if (at > 0 && /^-[a-zA-Z0-9]*$/.test(a.slice(0, at))) out.push(at + 1 < a.length ? a.slice(at + 1) : (words[++i] ?? ""));
    }
  }
  return spec.split ? out.flatMap((v) => v.split(spec.split!)) : out;
}
// The verdict on one such file, as a read in every directory the command may run in (`dirs`;
// undefined: not known). As bash hands the word over: a glob or braces are every file they match
// (`file -f .e*`), and a word the check cannot expand asks. Where the directory is not known
// (B7-9: a call outside the shape places nothing), a name that is a credential's wherever it
// lies asks and any other goes to the model with the rest of the call. A path relative to the
// process that walks it (procRelative) goes to the model.
function listProblem(name: string, word: string, dirs: string[] | undefined, scope: Scope): GuardVerdict | undefined {
  if (word === "-" || word === "") return undefined;
  const reads = (file: string): GuardVerdict | undefined => {
    const v = bashVerdict(`cat '${file.replace(/'/g, "'\\''")}'`, scope);
    return v.action === "ask" || v.action === "deny" ? { action: "ask", reason: `${name} reads ${word} as a list: ${v.reason}` } : v.action === "classify" ? { action: "classify", reason: `${name} reads ${word} as a list: ${v.reason}` } : undefined;
  };
  if (/[$`]/.test(word) || /^~[^/]/.test(word)) return { action: "ask", reason: `${name} reads a list the check cannot place: ${word}` };
  const t = tilde(word);
  if (!path.isAbsolute(t) && dirs === undefined) {
    // By its name alone, as a path from the root (placedReads does the same for a `cd`).
    const lone = braceWords(t)?.some((alt) => readVerdict("read", `/${alt}`, scope));
    return lone === false ? { action: "classify", reason: `${name} reads the list ${word} in a directory the check cannot tell` } : { action: "ask", reason: `${name} reads a list the check cannot place: ${word}` };
  }
  let verdict: GuardVerdict | undefined;
  for (const dir of path.isAbsolute(t) ? ["/"] : dirs!) {
    if (unreadableGlob(word)) return { action: "ask", reason: `${name} reads a list named by a glob the check cannot read: ${word}` };
    const names = expandNames(word, dir);
    if (!names) return { action: "ask", reason: `${name} reads a list the check cannot place: ${word}` };
    for (const file of names.length ? names : [path.isAbsolute(t) ? t : `${dir}/${t}`]) {
      if (procRelative(file)) verdict = stricter(verdict, { action: "classify", reason: `${name} reads the list ${word}, a path through /proc that is relative to the process that walks it` });
      else for (const f of new Set([file, physical(file)])) verdict = stricter(verdict, reads(f));
    }
  }
  return verdict;
}

// Place readers remain useful after inversion: they find additional directories, but never
// decide whether a program deserves trust. Only safeAfterWrite grants that exemption.
// Options of a package manager that pick which workspace packages run (npm `-w`, pnpm
// `--filter`): a value that names a directory is a place, any other (a package name, a selector)
// leaves the place unknown. The flags that run every workspace package leave it unknown too.
const RUNNER_SELECTORS: Record<string, { values: string[]; all: string[] }> = {
  npm: { values: ["-w", "--workspace"], all: ["-ws", "--workspaces"] },
  pnpm: { values: ["--filter", "-F"], all: ["-r", "--recursive", "-w", "--workspace-root"] },
};
// The subcommand of a runner that has one, read past its global options as the tool reads them
// (round 4, D3, third pass: `npm --prefix web test`, `cargo +nightly test`, `go -C . test` hid
// the subcommand behind an option's value): the package managers' tables (PM_GLOBALS, as the
// install check reads them), the flags uv, poetry, pipenv, pdm, hatch, pnpm and bundle take before
// their runner subcommand (RUNNER_SPECS). `places`: the words global options name as the place
// the tool works in or the packages it runs (undefined: a place the check cannot tell).
// `unread`: an option the reading does not know, so the subcommand is not known either.
function runnerSub(name: string, args: string[]): { sub?: string; places: (string | undefined)[]; dirs: string[]; unread: boolean } {
  const places: (string | undefined)[] = [];
  const dirs: string[] = [];
  const selector = RUNNER_SELECTORS[name];
  if (Object.hasOwn(PM_GLOBALS, name)) {
    const at = afterGlobals(name, args, () => true, (option, value) => {
      if (value !== undefined && PM_GLOBALS[name].dirs.includes(option)) dirs.push(value);
      else if (value !== undefined && selector?.values.includes(option)) places.push(value);
      else if (selector?.all.includes(option)) places.push(undefined);
    });
    return typeof at === "string" ? { places, dirs, unread: true } : { sub: args[at], places, dirs, unread: false };
  }
  const before = RUNNER_SPECS[name]?.before;
  const read = before ? readOptions(name, before, args, 0) : { next: args[0]?.startsWith("-") ? -1 : 0 };
  if ("problem" in read || read.next < 0) return { places, dirs, unread: true };
  return { sub: args[read.next], places, dirs, unread: false };
}
const RUNNER_SUBS = new Set(["cargo", "go", "npm", "pnpm", "yarn", "bun", "uv", "poetry", "pipenv", "pdm", "hatch", "bundle", "docker"]);
// The options that name the directory a runner works in, or a file it reads its instructions
// from (whose directory counts): every spelling the rules let through, by tool.
const RUNNER_PLACE_OPTIONS = /^(-C|-d|-f|-S|-B|-P|-c|--directory|--dir|--cwd|--prefix|--manifest-path|--working-directory|--justfile|--file|--makefile|--build|--test-dir|--rootdir|--config|--config-file|--project|--root|--confcutdir)$/;
// Where a runner works: the directories (undefined: one the check cannot place), or undefined
// for a program that is no runner. Its own directory, every directory an option above names (a
// file's directory for a file), and every operand that names something on disk (a test file, a
// package directory, a build directory).
// A spelling the reading cannot place counts as a runner when any of its words could be the
// runner subcommand, with a place the check cannot tell (fail closed).
export function runnerPlaces(name: string, args: string[], cwd: string | undefined, resolve: (word: string) => string | undefined): (string | undefined)[] | undefined {
  const words = args.filter((a) => a !== "--");
  const read = RUNNER_SUBS.has(name) ? runnerSub(name, args) : undefined;
  // Trust is granted by safeAfterWrite, never by completing a list of dev tools.
  // make reads its words as codeFiles does: the `-C` chain, in every spelling.
  if (MAKES.has(name)) {
    const files = codeFiles(name, args, cwd);
    const places = files.flatMap((c) => c.dir === undefined ? [undefined] : [physical(c.dir), path.dirname(physical(path.isAbsolute(c.word) ? c.word : `${c.dir}/${c.word}`))]);
    const base = files[0]?.dir;
    for (const o of getopt(args, MAKE_OPTIONS).opts) if (["-I", "--include-dir"].includes(o.name)) {
      const word = o.value ?? "";
      const target = tilde(word);
      places.push(expands(word) || (!path.isAbsolute(target) && base === undefined) ? undefined : physical(path.isAbsolute(target) ? target : `${base}/${target}`));
    }
    return [...new Set(places)];
  }
  const places: (string | undefined)[] = [cwd];
  const place = (word: string, file: boolean) => {
    if (/[$`*?[\]{}]/.test(word) || /^~[^/]/.test(word)) return void places.push(undefined);
    const p = resolve(word);
    if (p === undefined) return void places.push(undefined);
    places.push(file ? path.dirname(p) : p);
  };
  // What the global options name (third pass): a directory option's value, a workspace selector
  // that names a directory; a selector that names none, and an unread spelling, leave it unknown.
  if (read?.unread) places.push(undefined);
  for (const dir of read?.dirs ?? []) place(dir, false);
  for (const selected of read?.places ?? []) {
    const p = selected === undefined || /[$`*?[\]{}]/.test(selected) ? undefined : resolve(selected);
    places.push(p !== undefined && fs.existsSync(p) && !isFile(p) ? p : undefined);
  }
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    const eq = w.indexOf("=");
    const option = w.startsWith("--") && eq > 0 ? w.slice(0, eq) : /^-[A-Za-z]$/.test(w.slice(0, 2)) && w.length > 2 && !w.startsWith("--") ? w.slice(0, 2) : w;
    if (RUNNER_PLACE_OPTIONS.test(option)) {
      const value = w.startsWith("--") && eq > 0 ? w.slice(eq + 1) : option !== w ? w.slice(2) : words[++i];
      if (value === undefined) continue;
      const p = resolve(value);
      place(value, !!p && isFile(p));
      continue;
    }
    if (w.startsWith("-")) continue;
    // An operand that names something on disk is part of what runs (`pytest tests/test_x.py`).
    const p = /[$`]/.test(w) ? undefined : resolve(w);
    if (p !== undefined && fs.existsSync(p)) places.push(isFile(p) ? path.dirname(p) : p);
  }
  return places;
}
const isFile = (p: string) => {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
};
// Whether this session wrote a file where a runner works (in one of its places or below it, or a
// file in a directory of the project above it: `npm`, `cargo`, `pytest` and `just` look upward),
// or a mark of an unlisted write covers a place or lies below it. The reason names the file;
// the files go to the model.
function runnerTouched(name: string, places: (string | undefined)[], written: Set<string>, unlisted: string[], ctx: ArgvContext): GuardVerdict | undefined {
  if (!written.size && !unlisted.length) return undefined;
  if (places.some((p) => p === undefined)) return { action: "classify", reason: `runs ${name} in a place the check cannot tell, after this session wrote files` };
  const dirs = places as string[];
  const above = (w: string) => {
    const d = path.dirname(w);
    return !!ctx.inProject?.(d) && dirs.some((p) => within(p, d));
  };
  const hits = [...written].filter((w) => dirs.some((p) => within(w, p)) || above(w));
  if (hits.length) {
    const at = ctx.cwdKnown ? ctx.cwd : dirs[0];
    const shown = hits.slice(0, 3).map((w) => path.relative(at, w) || path.basename(w));
    return { action: "classify", reason: `runs ${name} after this session wrote ${shown.join(", ")}${hits.length > 3 ? ` and ${hits.length - 3} more` : ""}`, files: hits.slice(0, 3).filter(isFile) };
  }
  const mark = unlisted.find((m) => dirs.some((p) => within(m, p) || within(p, m)));
  if (mark) return { action: "classify", reason: `runs ${name} where this session wrote files the check cannot list (${mark})` };
  return undefined;
}

// `set -x` prints each command through PS4, which bash expands (a `$(...)` in it runs). Round 4,
// finding 29: with the PS4 bash starts with (`+ `) that prints and runs nothing, so the usual
// first line of a script (`set -euxo pipefail`) is no sink. It is one when the call names PS4
// in any word of any command (an assignment by any builtin, `${PS4:=...}`, a nameref, a nested
// shell's code) or BASH_XTRACEFD, and when the plugin's own environment holds a PS4, which the
// shell would inherit. (Every assignment of PS4 the guards can read asks on its own:
// ENV_DANGEROUS. Arithmetic is not among the words here, and can only give PS4 a number.)
const TRACES = (a: string) => /^-[a-zA-Z]*x/.test(a) || a === "xtrace";
function traceProblem(cmds: Simple[]): string | undefined {
  const traces = cmds.some(({ argv }) => programs(argv).some((at) => path.basename(argv[at]) === "set" && argv.slice(at + 1).some(TRACES)));
  if (!traces) return undefined;
  if (process.env.PS4 !== undefined) return "set -x prints each command through PS4, which bash expands, and the environment sets a PS4";
  if (cmds.some(({ argv }) => argv.some((w) => w.includes("PS4")))) return "set -x prints each command through PS4, which bash expands, and this command names PS4";
  // Where the trace goes is the caller's to say only when it is asked about.
  if (cmds.some(({ argv }) => argv.some((w) => w.includes("BASH_XTRACEFD")))) return "set -x with BASH_XTRACEFD, which sends the trace to a file";
  return undefined;
}

export function argvGuards(cmds: Simple[], ctx: ArgvContext): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  // What this call links, moves or copies into place (round 4, finding 5, second pass).
  const placed: string[] = [];
  let placedUnknown: string | undefined;
  for (const w of writesOf(cmds).writes) {
    if (!linksOrMoves(w)) continue;
    const p = ctx.resolve(w.word, w.cmd);
    if (!p) {
      placedUnknown ??= `${w.by} ${w.word}, which the check cannot place,`;
      continue;
    }
    if (!w.dir) placed.push(p);
    for (const s of w.sources ?? []) placed.push(path.join(p, path.basename(s)));
  }
  ctx = { ...ctx, placed, ...(placedUnknown ? { placedUnknown: `writes ${placedUnknown}` } : {}) };
  for (const cmd of cmds) verdict = stricter(verdict, argvGuard(cmd, ctx));
  const trace = traceProblem(cmds);
  if (trace) verdict = stricter(verdict, { action: "ask", reason: trace });
  return stricter(verdict, exportProblem(cmds, ctx.cwdKnown ? ctx.cwd : undefined, ctx.inProject));
}

// ---- an option that arrives through an expansion (round 3, 5b) ----
//
// The rules read a word that holds `$x` or a substitution as data, and an option table cannot
// vet a word it cannot read: `x=-delete; find build $x`, `git clean ${e}-fd`. For a program whose
// options a guard or the rules key on, a word that can become an option once bash expands it goes
// to the model, as a reader's file named at run time does: a word with an unquoted expansion
// anywhere (word splitting can make new words of it), or one that starts with a quoted one. Not
// risky: a quoted expansion later in a word (`"*.$ext"`), the value of an option that takes the
// next word as its value (`-m "$msg"`), a visible option with the expansion in its value
// (`-j$(nproc)`, `--since="$d"`) unless that option's value is itself checked, and words after
// `--` for programs that end their options there.
const MARK_UNQUOTED = "\u000e";
const MARK_QUOTED = "\u000f";
const MARKS = /[\u000e\u000f]/;
const unmark = (w: string) => w.replace(/[\u000e\u000f]/g, "");

// The command with a mark before each expansion bash performs: MARK_UNQUOTED where it is not
// quoted, MARK_QUOTED inside double quotes. Single-quoted text, escaped characters, comments and
// quoted heredoc bodies are copied as they are, and `$HOME` is left alone (the parser puts the
// home directory in its place). Only marks are inserted, so the rules' parser reads the same
// structure; the caller checks that it did.
export function markExpansions(s: string, depth = 0): string {
  if (depth > 6) return s;
  let out = "";
  let dq = false;
  let wordStart = true;
  const heredocs: { delimiter: string; quoted: boolean }[] = [];
  const sub = (open: number, end: number, mark: string) => mark + s.slice(open, open + 2) + markExpansions(s.slice(open + 2, end), depth + 1) + ")";
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const next = s[i + 1];
    if (c === "\\") {
      out += c + (next ?? "");
      i++;
      wordStart = false;
      continue;
    }
    if (!dq && c === "'") {
      const end = s.indexOf("'", i + 1);
      if (end < 0) return out + s.slice(i);
      out += s.slice(i, end + 1);
      i = end;
      wordStart = false;
      continue;
    }
    if (c === '"') {
      dq = !dq;
      out += c;
      wordStart = false;
      continue;
    }
    if ((c === "$" || (!dq && (c === "<" || c === ">"))) && next === "(") {
      const end = closeNaive(s, i + 1);
      if (end < 0) return out + s.slice(i);
      // A count of processors (`make -j$(nproc)`) is a number: nothing to split or to read as an
      // option.
      const count = /^\s*(nproc( --all)?|getconf _NPROCESSORS_ONLN)\s*$/.test(s.slice(i + 2, end));
      out += sub(i, end, c === "$" && !count ? (dq ? MARK_QUOTED : MARK_UNQUOTED) : "");
      i = end;
      wordStart = false;
      continue;
    }
    if (c === "`") {
      const end = s.indexOf("`", i + 1);
      if (end < 0) return out + s.slice(i);
      out += (dq ? MARK_QUOTED : MARK_UNQUOTED) + "`" + markExpansions(s.slice(i + 1, end), depth + 1) + "`";
      i = end;
      wordStart = false;
      continue;
    }
    if (c === "$" && /[A-Za-z_{@*#?$!0-9-]/.test(next ?? "")) {
      out += (/^\$(\{HOME\}|HOME\b)/.test(s.slice(i)) ? "" : dq ? MARK_QUOTED : MARK_UNQUOTED) + c;
      wordStart = false;
      continue;
    }
    if (!dq && c === "#" && wordStart) {
      const end = s.indexOf("\n", i);
      out += end < 0 ? s.slice(i) : s.slice(i, end);
      i = end < 0 ? s.length : end - 1;
      continue;
    }
    if (!dq && c === "<" && next === "<" && s[i + 2] !== "<") {
      const m = /^<<-?\s*(['"]?)([\w.-]+)\1/.exec(s.slice(i));
      if (m) {
        heredocs.push({ delimiter: m[2], quoted: m[1] !== "" });
        out += m[0];
        i += m[0].length - 1;
        wordStart = false;
        continue;
      }
    }
    out += c;
    if (!dq) wordStart = " \t\n;|&()<>".includes(c);
    if (!dq && c === "\n") {
      while (heredocs.length) {
        const doc = heredocs.shift()!;
        const rest = s.slice(i + 1);
        const end = new RegExp(`^\\s*${doc.delimiter.replace(/[.\-]/g, "\\$&")}\\s*$`, "m").exec(rest);
        const body = end ? rest.slice(0, end.index) : rest;
        out += doc.quoted ? body : markBody(body, depth);
        out += end ? end[0] : "";
        i = end ? i + end.index + end[0].length : s.length;
      }
    }
  }
  return out;
}
// An unquoted heredoc body: the parser reads only its substitutions, as commands.
function markBody(body: string, depth: number): string {
  let out = "";
  for (let j = 0; j < body.length; j++) {
    if (body[j] === "\\") {
      out += body.slice(j, j + 2);
      j++;
    } else if (body[j] === "$" && body[j + 1] === "(") {
      const end = closeNaive(body, j + 1);
      if (end < 0) return out + body.slice(j);
      out += "$(" + markExpansions(body.slice(j + 2, end), depth + 1) + ")";
      j = end;
    } else if (body[j] === "`") {
      const end = body.indexOf("`", j + 1);
      if (end < 0) return out + body.slice(j);
      out += "`" + markExpansions(body.slice(j + 1, end), depth + 1) + "`";
      j = end;
    } else out += body[j];
  }
  return out;
}

interface Keyed {
  // Options whose value is the next word.
  values?: string[];
  // Options (long, or go's single-dash long) and short letters whose value a check reads: an
  // expansion in it is risky even where it is visible.
  checked?: string[];
  letters?: string;
  // Whether `--` ends the program's options.
  dashDash?: boolean;
  // awk: after the program text, words are files and assignments, not options.
  operandEnds?: boolean;
}
const FIND_VALUES = [
  ..."-name -iname -path -ipath -wholename -iwholename -regex -iregex -lname -ilname -type -xtype -maxdepth -mindepth -mtime -mmin -ctime -cmin -atime -amin -used -newer -anewer -cnewer -size -user -group -uid -gid -perm -links -inum -samefile -fstype -context -printf -regextype".split(" "),
  ...[..."aBcm"].flatMap((x) => [..."aBcmt"].map((y) => `-newer${x}${y}`)),
];
const PM: Keyed = { values: ["-w", "--workspace", "--filter", "-F", "-p", "--package", "--bin", "--test", "--example", "--bench", "--features", "--target", "-j", "--jobs", "--profile", "-run", "-bench", "-count", "-timeout", "-tags", "-skip", "-parallel", "-cpu", "-benchtime"], checked: ["--prefix", "--cwd", "--manifest-path", "--config", "--target-dir", ...PM_PROGRAM_OPTIONS, "-toolexec", "-exec", "-vettool", "-o", "-C", "-modfile", "-overlay", "-pkgdir", "--toolexec", "--exec", "--vettool"], letters: "CZ" };
const KEYED: Record<string, Keyed> = {
  find: { values: FIND_VALUES, checked: ["-fprint", "-fprintf", "-fls"], dashDash: false },
  make: { values: ["-j", "-l", "-o", "-W", "--jobs", "--load-average", "--old-file", "--what-if", "--assume-old", "--assume-new", "--new-file"], checked: ["--file", "--makefile", "--include-dir", "--directory", "--eval"], letters: "fCIE", dashDash: false },
  tar: { checked: ["--file", "--directory", "--files-from", "--exclude-from", "--to-command", "--use-compress-program", "--checkpoint-action", "--info-script", "--new-volume-script", "--rsh-command", "--rmt-command"], letters: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" },
  sort: { values: ["-k", "-t", "-S", "--key", "--field-separator", "--buffer-size", "--parallel"], checked: ["--output", "--compress-program", "--files0-from", "--temporary-directory"], letters: "oT" },
  rg: { values: ["-e", "-g", "-t", "-T", "-m", "-A", "-B", "-C", "-M", "-j", "-d", "--regexp", "--glob", "--iglob", "--type", "--type-not", "--max-count", "--after-context", "--before-context", "--context", "--max-columns", "--threads", "--max-depth"], checked: ["--pre", "--pre-glob", "--ignore-file", "--file", "--hostname-bin"], letters: "f" },
  fd: { values: ["-e", "-t", "-E", "-d", "-S", "--extension", "--type", "--exclude", "--max-depth", "--min-depth", "--size", "--changed-within", "--changed-before"], checked: ["--exec", "--exec-batch", "--base-directory", "--search-path", "--ignore-file"], letters: "xX" },
  man: { values: ["-S", "-s", "-L", "-m", "-e", "-E", "-R", "-p"], checked: ["--config-file", "--pager", "--html", "--prompt", "--manpath", "--local-file"], letters: "CPHMl" },
  sed: { values: ["-l", "--line-length"], checked: ["--file", "--expression"], letters: "fe" },
  awk: { values: ["-v", "-F", "--assign", "--field-separator"], checked: ["--file", "--include", "--load", "--exec", "--source"], letters: "fileEW", operandEnds: true },
  xargs: { values: ["-I", "-n", "-L", "-P", "-s", "-d", "-E", "--max-args", "--max-procs", "--max-chars", "--delimiter", "--eof"], checked: ["--arg-file"], letters: "a" },
  env: { checked: ["--unset", "--chdir", "--split-string", "--argv0"], letters: "uCSa" },
  npm: PM,
  cargo: PM,
  go: PM,
  gh: { values: ["-R", "--repo", "-q", "--jq", "-t", "--template"], checked: ["-X", "--method", "-f", "-F", "--field", "--raw-field", "--input", "-H", "--header"], letters: "XfFH" },
  sysctl: {},
  llamastash: {},
  docker: {},
  systemctl: {},
};
for (const [alias, name] of [["gmake", "make"], ["gtar", "tar"], ["bsdtar", "tar"], ["fdfind", "fd"], ["gawk", "awk"], ["mawk", "awk"], ["nawk", "awk"], ["pnpm", "npm"], ["yarn", "npm"], ["bun", "npm"], ["pip", "npm"], ["pip3", "npm"], ["gem", "npm"], ["uv", "npm"], ["poetry", "npm"], ["pipenv", "npm"], ["pdm", "npm"], ["hatch", "npm"], ["bundle", "npm"]]) KEYED[alias] = KEYED[name];
const GIT_VALUES: Record<string, string[]> = {
  commit: ["-m", "-F", "-C", "-c", "-t", "--message", "--file", "--author", "--date", "--template", "--reuse-message", "--reedit-message", "--fixup", "--squash", "--trailer", "--cleanup"],
  tag: ["-m", "-F", "--message", "--file"],
  merge: ["-m", "-F", "-s", "-X", "--message", "--file", "--strategy", "--strategy-option"],
  stash: ["-m", "--message"],
  notes: ["-m", "-F", "--message", "--file"],
  checkout: ["-b", "-B", "--orphan"],
  switch: ["-c", "-C", "--create", "--force-create", "--orphan"],
};
const GIT_CHECKED = ["--output", "--output-directory", "--upload-pack", "--receive-pack", "--exec", "--template", "--open-files-in-pager", "--extcmd"];

// The first word of `args` (marked) that can become an option of the program at run time.
function riskyWord(spec: Keyed, args: string[]): string | undefined {
  let ended = false;
  let operand = false;
  for (let i = 0; i < args.length; i++) {
    const w = args[i];
    const plain = unmark(w);
    if (!ended && spec.dashDash !== false && plain === "--") {
      ended = true;
      continue;
    }
    if (ended || (spec.operandEnds && operand)) continue;
    const at = w.search(MARKS);
    if (at < 0) {
      // A plain option that takes the next word: that word is its value, unless splitting can
      // make more words of it or the value is itself checked.
      const takes = spec.values?.includes(plain) || spec.checked?.includes(plain);
      if (takes && i + 1 < args.length) {
        const value = args[i + 1];
        if (value.includes(MARK_UNQUOTED) || (spec.checked?.includes(plain) && MARKS.test(value))) return unmark(value);
        i++;
        continue;
      }
      if (!plain.startsWith("-")) operand = true;
      continue;
    }
    if (at === 0) return plain;
    // Word splitting can make a new word, an option among them, of any unquoted expansion, also
    // one in the value of a visible option (`--format=$f` with f='%H --output=x').
    if (w.includes(MARK_UNQUOTED)) return plain;
    if (plain.startsWith("-")) {
      // The expansion is in the value of a visible option: fine, unless the option's name is cut
      // by it or its value is checked.
      const eq = w.indexOf("=");
      if (w.startsWith("--") || (eq > 0 && eq < at)) {
        const name = unmark(w.slice(0, eq < 0 ? at : eq));
        if (eq < 0 || eq > at || spec.checked?.some((c) => c === name || (c.startsWith("--") && name.length >= 3 && c.startsWith(name)))) return plain;
        continue;
      }
      const letters = w.slice(1, at);
      if (!letters || [...letters].some((l) => spec.letters?.includes(l))) return plain;
      continue;
    }
    if (w.includes(MARK_UNQUOTED)) return plain;
    operand = true;
  }
  return undefined;
}

// The commands of a call (as allCommands) side by side with the same commands read from the
// marked text; undefined when the two readings do not line up.
function markedCommands(command: string, depth = 0): [Simple, Simple][] | undefined {
  if (depth > 4) return [];
  const real = parse(command).cmds;
  const seen = parse(markExpansions(command)).cmds;
  const same = real.length === seen.length && real.every((c, i) => c.argv.length === seen[i].argv.length && c.argv.every((w, j) => w === unmark(seen[i].argv[j])));
  if (!same) return undefined;
  const out = real.map((c, i): [Simple, Simple] => [c, seen[i]]);
  for (const body of nestedBodies(real)) {
    const inner = markedCommands(body, depth + 1);
    if (!inner) return undefined;
    out.push(...inner);
  }
  return out;
}

export function expansionProblem(command: string): GuardVerdict | undefined {
  if (!/[$`]/.test(command)) return undefined;
  const pairs = markedCommands(command);
  if (!pairs) return { action: "classify", reason: "words with expansions the guard could not line up with the rules' reading" };
  const real = pairs.map(([r]) => r);
  const seen = pairs.map(([, m]) => m);
  for (const [n, cmd] of seen.entries()) {
    const argv = real[n].argv;
    const { at, chain } = traverse(argv);
    for (const p of at) {
      const name = path.basename(argv[p]);
      const end = chain.find((q) => q > p) ?? argv.length;
      const args = cmd.argv.slice(p + 1, end);
      let found: string | undefined;
      if (name === "git") {
        let i = 0;
        for (; i < args.length && unmark(args[i]).startsWith("-"); i++) {
          if (/^-[Cc]$/.test(unmark(args[i]))) {
            if ((args[i + 1] ?? "").includes(MARK_UNQUOTED)) found ??= unmark(args[i + 1]);
            i++;
          } else if (MARKS.test(args[i])) found ??= unmark(args[i]);
        }
        const sub = args[i] ?? "";
        if (MARKS.test(sub)) found ??= unmark(sub);
        found ??= riskyWord({ values: GIT_VALUES[unmark(sub)] ?? [], checked: GIT_CHECKED, letters: ["format-patch", "archive"].includes(unmark(sub)) ? "o" : "" }, args.slice(i + 1));
      } else if (Object.hasOwn(KEYED, name)) found = riskyWord(KEYED[name], args);
      if (found !== undefined) return { action: "classify", reason: `${name} ${found}: a word that can become an option once bash expands it, and ${name}'s options are checked by name` };
    }
  }
  return undefined;
}
