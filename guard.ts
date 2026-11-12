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
import { parse, readVerdict, type Matcher, type Scope, type Simple } from "./rules.ts";

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
          if ((doc.dash ? line.replace(/^\t+/, "") : line) === doc.delimiter) break;
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
const SETS_BY_NAME = /(?<![\w-])(?:declare|typeset|local|export|readonly|read|mapfile|readarray|getopts|coproc|eval|source|printf|wait|let|command|builtin|enable|alias|trap|unset)(?![\w-])/;
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

// The words `{a,b}` stands for, or undefined for a range (`{1..5}`) or too many of them. A
// brace with no comma is left as it is, as bash leaves it.
export function braceWords(word: string): string[] | undefined {
  let alternatives = [word];
  for (let round = 0; round < 6; round++) {
    const out: string[] = [];
    let changed = false;
    for (const w of alternatives) {
      const m = /\{([^{}]*)\}/.exec(w);
      if (!m) out.push(w);
      else if (m[1].includes("..") && !m[1].includes(",")) return undefined;
      else if (!m[1].includes(",")) out.push(w.replace(m[0], `\u0005${m[1]}\u0006`));
      else {
        changed = true;
        for (const part of m[1].split(",")) out.push(w.slice(0, m.index) + part + w.slice(m.index + m[0].length));
      }
      if (out.length > 2000) return undefined;
    }
    alternatives = out;
    if (!changed && !alternatives.some((w) => /\{[^{}]*\}/.test(w))) break;
  }
  return alternatives.map((w) => w.replace(/\u0005/g, "{").replace(/\u0006/g, "}"));
}

// A brace expansion that makes words the rules never saw as such: an option (`curl {-d,@f}`,
// `tar -{-to-command=x}`), an absolute path or a remote (`{/etc,x}`, `{host:dir,}`), a way up
// (`a/{../..,b}`). `--exclude={a,b}` and `src/{a,b}.ts` are what braces are for.
function braceProblem(text: string): string | undefined {
  const first = text.indexOf("{");
  const prefix = text.slice(0, first);
  const words = braceWords(text);
  const asked = "a brace expansion that makes an option, an absolute path or a remote";
  if (/^--?[\w-]+=/.test(prefix)) return undefined; // a value: every word keeps the option in front
  if (!words) return prefix.startsWith("-") || /\{-/.test(text) ? asked : undefined; // a range
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
    for (let i = 0; i < argv.length; i++) {
      const name = path.basename(argv[i]);
      const rest = argv.slice(i + 1);
      if (OTHER_SHELL.test(name) && rest.some((w) => CODE_FLAG.test(w))) return `a command for ${name}, which does not read it the way bash does`;
      // The rules drop `NAME=value` after any wrapper; only `env` takes it as an assignment.
      if (at.has(i) && RUNS_ITS_WORDS.has(name)) {
        const program = rest.find((w) => !/^(-.*|\d+(\.\d+)?[smhd]?)$/.test(w));
        if (program !== undefined && /^[A-Za-z_]\w*=/.test(program)) return `${name} ${program}: a program named like an assignment, which the rules drop`;
      }
      if (at.has(i) && name === "shopt") return "shopt, which changes how bash reads the rest of the command";
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
        if (code >= 0 && (found ?? computed)) return `${name} ${found ?? computed} before its code, which changes how the shell reads it`;
        if (at.has(i) && code >= 0 && operand >= 0 && operand < code) return `${name} given a script and a -c: bash runs the script`;
      }
    }
  }
  return undefined;
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
export function unmodelled(s: string, depth = 0, within?: { variables: Variables; offset: number; kind: "paren" | "tick" }): string | undefined {
  if (depth > 6) return "deeply nested substitutions";
  if (CONTROL.test(s)) return "a control character (a carriage return, an escape or the like) or a Unicode line separator";
  if (ESCAPED_PAYLOAD.test(s)) return PAYLOAD_REASON;
  // A substitution shares its shell's variables; a nested shell and the command itself start anew.
  const variables = within?.variables ?? { root: s, ints: new Set<string>(), accounted: new Set<number>(), uses: new Set<string>(), opaqueCommand: false };
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
    const inner = unmodelled(body, depth + 1);
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
const NULL_REDIRECT = /^(?:(?:[12]?>>?|&>) ?\/dev\/null|2>&1)(?=[ \t;|&]|$)/;

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
// - `messages`: a commit message written `"$(cat <<'EOF' ... EOF⏎)"` (also `<<"EOF"`, and `<<EOF`
//   when the body has no `$`, backtick or backslash, so bash expands nothing in it) is one quoted
//   word whose text is the body. It is matched only where the tokenizer, reading as bash does,
//   is outside quotes, so bash too reads it as a double quote that opens a command substitution
//   running `cat` with that heredoc. Its place in the text is pushed to `spans`.
// - `assignments`: words before the command's name that match it (unquoted) are assignments the
//   caller vets (`assigns`); any other assignment gives undefined as before.
export interface StrictOptions {
  pipes?: boolean;
  nullRedirects?: boolean;
  newlines?: boolean;
  globs?: boolean;
  bang?: boolean;
  messages?: boolean;
  spans?: [number, number][];
  assignments?: RegExp;
}
const MESSAGE = /"\$\(cat <<(['"]?)([A-Za-z_]\w*)\1\n((?:(?!\2\n)[^\n]*\n)*)\2\n[ \t]*\)"/y;
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
  const message = (at: number) => {
    MESSAGE.lastIndex = at;
    return MESSAGE.exec(s);
  };
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === " " || c === "\t") endWord();
    else if (c === "\n" && opts.newlines) {
      endWord();
      if ((argv.length || assigns.length) && !endCmd(";")) return undefined;
    } else if (c === '"' && opts.messages && message(i)) {
      const m = message(i)!;
      // `<<EOF`: bash expands `$`, backticks and backslashes in the body.
      if (m[1] === "" && /[$`\\]/.test(m[3])) return undefined;
      // The body is the value of an option (`-m`): a placeholder keeps it from being read as one.
      opens.push((word ?? "").length);
      word = (word ?? "") + "MESSAGE";
      for (let k = 0; k < "MESSAGE".length; k++) quoted.push(true);
      opts.spans?.push([i, i + m[0].length]);
      i += m[0].length - 1;
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
  const rest: string[][] = [];
  for (const [n, { argv }] of cmds.entries()) {
    if (argv[0] !== "cd") {
      rest.push(argv);
      continue;
    }
    if (argv.length !== 2 || rest.length || argv[1].startsWith("-") || /^~[^/]/.test(argv[1]) || cmds[n + 1]?.before !== "&&") return undefined;
    const to = landing(dir, tilde(argv[1]));
    if (!to) return undefined;
    dir = to;
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

// What one git call does that the rules allow by the subcommand's name alone.
function gitCallProblem(call: GitCall, exists?: (word: string) => boolean): string | undefined {
  const { sub = "", rest } = call;
  const program = rest.find((w) => abbreviates(w, GIT_PROGRAM_OPTIONS));
  if (program) return `git ${sub} ${program} picks a program for git to run`;
  const operand = rest.find((w) => !w.startsWith("-"));
  if (sub === "grep" && rest.some((w) => /^-[a-zA-Z]*O/.test(w))) return "git grep -O opens the matches in a program of the caller's choosing";
  if (sub === "submodule" && operand === "foreach") return "git submodule foreach runs a command in every submodule";
  if (sub === "bisect" && operand === "run") return "git bisect run runs a command at every step";
  if ((sub === "rebase" || sub === "difftool") && rest.some((w) => /^-[a-zA-Z]*[xi]/.test(w))) return `git ${sub} with -x or -i runs a command or an editor`;
  const keyed = GIT_KEYED_OPTIONS[sub] ?? [];
  const short = rest.find((w) => abbreviates(w, keyed) && !keyed.includes(w.split("=")[0]));
  if (short) return `git ${sub} ${short} is a shortened option, which git accepts and the rules do not read`;
  return gitDestroys(sub, rest, exists);
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
    if (end >= 0 || operands.length > (creating ? 1 : 1)) return `git checkout ${operands.slice(1).join(" ") || "-- ..."} names paths, whose local changes it overwrites`;
    const only = operands[0];
    if (!creating && only !== undefined && only !== "-" && (only === "." || /^\.{1,2}(\/|$)/.test(only) || only.startsWith(":") || /[*?[]/.test(only) || exists?.(only))) return `git checkout ${only} names a path, whose local changes it overwrites`;
  }
  if (sub === "switch" && has(["--force", "--discard-changes", "--force-create"], "fC")) return discards;
  if (sub === "branch") {
    const del = has(["--delete"], "d");
    const force = has(["--force"], "f");
    if (has([], "DMC") || (del && force) || (force && operands.length > 0) || (force && has(["--move", "--copy"], "mc"))) return discards;
  }
  if (sub === "tag" && has(["--delete"], "d")) return discards;
  if (sub === "gc" && own.some((w) => /^--prune=/.test(w))) return "git gc --prune=<date> deletes objects nothing refers to, which git otherwise keeps for a while";
  return undefined;
}

// The files git writes because an option names them (round 3, finding 25): `--output` of the
// diff and log family, `format-patch -o`/`--output-directory`, `archive -o`/`--output`, `bundle
// create <file>`. Pairs of the word and whether it is a directory. `args` are the words after
// `git`.
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
  if (sub === "bundle") {
    const words = rest.filter((w) => !w.startsWith("-"));
    if (words[0] === "create" && words[1]) out.push([words[1], false]);
  }
  // git resolves a relative name in the directory `-C` took it to.
  return call.dirs.length ? out.map(([w, dir]): [string, boolean] => [/^[\/~]/.test(w) || /[$`]/.test(w) ? w : path.join(...call.dirs, w), dir]) : out;
}

// Every `git` word in the command (after `sudo`, `xargs`, `env`, in a substitution, inside a
// quoted `sh -c` string) is read as a git call with the real words bash would pass. `exists`
// tells whether a word names a file or directory where the command runs (a `checkout` operand).
export function gitProblem(command: string, depth = 0, exists?: (word: string) => boolean): string | undefined {
  if (depth > 3) return undefined;
  for (const { argv } of parse(command).cmds) {
    for (let i = 0; i < argv.length; i++) {
      if (path.basename(argv[i]) === "git") {
        const call = gitCall(argv.slice(i + 1));
        if (typeof call === "string") return call;
        const found = gitCallProblem(call, exists);
        if (found) return found;
      } else if (/\s/.test(argv[i]) && /\bgit\b/.test(argv[i])) {
        const inner = gitProblem(argv[i], depth + 1, exists);
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
const ENV_DANGEROUS =
  /^(PATH|HOME|IFS|CDPATH|SHELL|ENV|BASH_ENV|BASH_FUNC.*|BASHOPTS|SHELLOPTS|POSIXLY_CORRECT|BASH_COMPAT|BASH_ALIASES|BASH_CMDS|histchars|PROMPT_COMMAND|PS[0-4]|EDITOR|VISUAL|PAGER|BROWSER|TMPDIR|GIT_.*|SSH_.*|LD_.*|DYLD_.*|XDG_.*|PYTHON(PATH|STARTUP|HOME|USERBASE|WARNINGS|BREAKPOINT)|NODE_(OPTIONS|PATH)|PERL5(LIB|OPT|DB)|PERLLIB|RUBY(OPT|LIB)|GEM_(HOME|PATH)|GO(FLAGS|PATH|ROOT|BIN|PROXY|NOSUMDB|INSECURE|PRIVATE|TOOLCHAIN|ENV)|RUSTC.*|RUSTUP_.*|RUSTFLAGS|RUSTDOCFLAGS|CARGO_(HOME|BUILD_.*|TARGET_.*_(RUNNER|LINKER|RUSTFLAGS)|REGISTR.*|ENCODED_RUSTFLAGS)|CC|CXX|LD|AR|MAKEFLAGS|GNUMAKEFLAGS|MAKEFILES|npm_config_.*|NPM_CONFIG_.*|PIP_.*|UV_.*|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|JAVA_HOME|MAVEN_OPTS|GRADLE_.*|OPENCODE.*|AUTOMODE_.*|TAR_OPTIONS|RIPGREP_CONFIG_PATH|GREP_OPTIONS|LESSOPEN|LESSCLOSE|MANOPT|MANPAGER|MANROFFOPT|MAN_DISABLE_SECCOMP|MANPATH|GROFF_.*|FZF_DEFAULT_(COMMAND|OPTS)|RSYNC_(RSH|CONNECT_PROG)|CURL_HOME|WGETRC|DOCKER_(HOST|CONFIG|CONTEXT|CERT_PATH)|KUBECONFIG|AWS_.*|GOOGLE_APPLICATION_CREDENTIALS|CLOUDSDK_.*|PWD|OLDPWD|VIRTUAL_ENV|LUA_.*|GCONV_PATH|SUDO_(EDITOR|ASKPASS)|SYSTEMD_(PAGER|EDITOR)|BAT_.*|GH_.*|BUNDLE_.*|POETRY_.*|PIPENV_.*|PDM_.*|HATCH_.*|YARN_.*|COREPACK_.*)$/;
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
  const matches = (re: RegExp, segment: string, n: string) => re.test(n) && (segment.startsWith(".") || !n.startsWith("."));
  for (const alt of alternatives) {
    const segments = alt.split("/");
    for (const [k, segment] of segments.entries()) {
      if (names.includes(segment)) return segment;
      if (!/[*?[]/.test(segment)) continue;
      const re = globRegex(segment);
      const hit = names.find((n) => matches(re, segment, n));
      if (!hit) continue;
      if (!ORDINARY_NAMES.some((n) => matches(re, segment, n)) || cwd === undefined || /[$`]/.test(alt)) return hit;
      const found = expandWord(segments.slice(0, k + 1).join("/") || "/", cwd);
      const existing = found === undefined ? hit : found.map((p) => path.basename(p)).find((n) => names.includes(n));
      if (existing) return existing;
    }
  }
  return undefined;
}

// The files a word names once bash has expanded its braces and globs, or undefined when that
// cannot be known here (a variable, a substitution, a `{a..z}` range).
export function expandWord(word: string, cwd: string): string[] | undefined {
  if (/[$`]/.test(word)) return undefined;
  const alternatives = braceWords(word);
  if (!alternatives) return undefined;
  const results: string[] = [];
  for (const alt of alternatives) {
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
      // A bracket JavaScript cannot compile (`[&-#]`, a range out of order): unknown.
      let re: RegExp;
      try {
        re = globRegex(segment);
      } catch {
        return undefined;
      }
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
  }
  // A loop variable is set without `NAME=`: `for NAME in`, and also `for NAME;` and `for NAME do`
  // (the positional parameters), the same for `select`. `coproc NAME` sets NAME to its pipe's
  // file descriptors (`$PATH` becomes `63`).
  const forAt = rawWords.findIndex((w) => w === "for" || w === "select" || w === "coproc");
  const loopName = forAt >= 0 ? rawWords[forAt + 1] : undefined;
  if (loopName !== undefined && (namesOf(loopName) ?? [loopName]).some((n) => ENV_DANGEROUS.test(n) || /[$`*?[]/.test(n))) add("ask", dangerous(loopName));
  return verdict;
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
  const marked = (n: number) => (aligned && n < top ? pairs![n][1].argv : undefined);
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
        if (word.startsWith("-") && !word.includes("=")) continue;
        const strip = (w: string) => w.replace(/^-[^=]*=/, "").replace(/^@/, "");
        const text = strip(word);
        const mark = words ? strip(words[k]) : undefined;
        const dynamic = mark === undefined ? /[$`]/.test(text) : MARKS.test(mark);
        if (dynamic) {
          if (!READERS.has(name)) continue;
          const looped = mark !== undefined ? loopUse(mark, loops.get(n), cwd) : undefined;
          if (!looped) {
            add("classify", `${name} reads a file named at run time: ${word}`);
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
        const relative = !/^(\/|~\/|~$)/.test(pattern);
        const files = relative && cwd === undefined ? undefined : expandWord(pattern, cwd ?? "/");
        if (!files) {
          if (READERS.has(name)) add("classify", `${name} reads a file named at run time: ${word}`);
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

// One value a loop variable takes: the file, the text bash puts in the variable, and whether the
// text is the loop's own glob (left as it is when it matches nothing).
interface LoopValue {
  file: string;
  text: string;
  glob?: boolean;
}
// The variables of the loops a command sits in, each with its values and the directory the loop
// started in (relative values name files there).
type LoopVars = Map<string, { values: LoopValue[]; cwd: string | undefined }>;

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
    for (const word of known ? list : []) {
      const relative = !/^(\/|~\/|~$)/.test(word);
      if (relative && cwd === undefined) {
        known = false;
        break;
      }
      const glob = /[*?[{]/.test(word);
      values.push({ file: path.resolve(cwd ?? "/", tilde(word)), text: word, glob });
      if (!glob) continue;
      const files = expandWord(word, cwd ?? "/");
      if (!files) {
        known = false;
        break;
      }
      for (const file of files) values.push({ file, text: relative ? path.relative(cwd!, file) : file });
    }
    open.push(known ? new Map([[name, { values, cwd }]]) : undefined);
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

// The values a marked word stands for when it is exactly a loop variable (`"$f"`, `$f`, `"${f}"`)
// used in the directory its loop started in. Unquoted, bash splits and globs the value again: a
// value with a blank or a backslash, or a file name with a glob character, does not come through
// as it is. (The loop's own glob, left as it is when it matched nothing, matches nothing again.)
function loopUse(mark: string, vars: LoopVars | undefined, cwd: string | undefined): LoopValue[] | undefined {
  const m = /^([\u000e\u000f])\$(?:([A-Za-z_]\w*)|\{([A-Za-z_]\w*)\})$/.exec(mark);
  const loop = m ? vars?.get(m[2] ?? m[3]) : undefined;
  if (!m || !loop || loop.cwd !== cwd) return undefined;
  if (m[1] === MARK_UNQUOTED && loop.values.some((v) => /[\s\\]/.test(v.text) || (!v.glob && /[*?[]/.test(v.text)))) return undefined;
  return loop.values;
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
  for (let i = 0; i < argv.length; i++) {
    if (i === 0 || /^-(exec|execdir|ok|okdir)$/.test(argv[i - 1])) at.add(i);
    else if (argv.slice(0, i).every((w) => WRAPPER_NAMES.has(path.basename(w)) || WRAPPER_WORD.test(w) || ASSIGN.test(w)) && !WRAPPER_WORD.test(argv[i])) at.add(i);
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
// The index of the subcommand after the known global options, or a reason to ask.
function afterGlobals(manager: string, args: string[], placeOk?: (dir: string) => boolean): number | string {
  const spec = PM_GLOBALS[manager];
  let i = 0;
  for (; i < args.length; i++) {
    const w = args[i];
    if (spec?.word?.test(w)) continue;
    if (!w.startsWith("-")) break;
    const eq = w.startsWith("--") ? w.indexOf("=") : -1;
    const name = eq < 0 ? w : w.slice(0, eq);
    if (spec?.flags.includes(name) && eq < 0) continue;
    if (!spec?.values.includes(name)) return `${manager} with options before its subcommand`;
    const value = eq < 0 ? args[++i] : w.slice(eq + 1);
    if (value === undefined) return `${manager} ${name} without a value`;
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
  return scripts.map(awkScript).find(Boolean);
}
// `@` is gawk's indirect call (`@f()` with `f = "system"`) and its `@load`/`@include`.
const awkScript = (script: string): GuardVerdict | undefined =>
  /system|getline|\||@|>>?\s*[^=\s\d]/.test(script) ? { action: "classify", reason: "an awk program that runs commands, reads through a pipe or writes files" } : undefined;

// make reads a makefile, and so runs its recipes, from what `-f` names (finding 9): standard
// input, a descriptor or a process substitution is text no check has seen. The values of
// `-f`/`--file`/`--makefile` in every spelling, clusters (`-sf-`) and abbreviations included.
const MAKE_LONG_FILE = ["--file", "--makefile"];
export function makefiles(args: string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "--") break;
    if (a.startsWith("--")) {
      if (abbreviates(a, MAKE_LONG_FILE)) out.push(a.includes("=") ? a.slice(a.indexOf("=") + 1) : (args[++i] ?? ""));
      continue;
    }
    if (!a.startsWith("-") || a === "-") continue;
    for (let j = 1; j < a.length; j++) {
      const c = a[j];
      if ("CIoWElj".includes(c)) {
        // -j and -l take an optional number; the others a value, attached or the next word.
        if ((c === "j" || c === "l") && !/^\d/.test(a.slice(j + 1)) && !/^\d+$/.test(args[i + 1] ?? "")) break;
        if (j + 1 === a.length) i++;
        break;
      }
      if (c === "f") {
        out.push(j + 1 < a.length ? a.slice(j + 1) : (args[++i] ?? ""));
        break;
      }
    }
  }
  return out;
}
const STDIN_LIKE = /^(-|\/dev\/(stdin|tty|fd\/\d+)|\/proc\/(self|thread-self|\d+)\/fd\/\d+)$/;
// Make variables that pick the shell or how make reads its makefiles, besides the environment's.
const MAKE_DANGEROUS = /^(SHELL|\.SHELLFLAGS|MAKEFLAGS|GNUMAKEFLAGS|MAKEFILES|MAKE|MAKESHELL|MAKEOVERRIDES|\.RECIPEPREFIX|\.DEFAULT_GOAL|\.INCLUDE_DIRS|\.LOADED)$/;
function makeProblem(args: string[], cwd: string | undefined, inProject: ((p: string) => boolean) | undefined): GuardVerdict | undefined {
  const ask = (reason: string): GuardVerdict => ({ action: "ask", reason });
  if (longOption(args, ["--eval"]) || args.some((a) => /^-[a-zA-Z]*E/.test(a) && !a.startsWith("--"))) return ask("make --eval runs makefile text from the command line");
  const piped = makefiles(args).find((f) => STDIN_LIKE.test(f) || /[$`]/.test(f));
  if (piped !== undefined) return ask(`make -f ${piped} reads a makefile from standard input or a pipe, which no check has read`);
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
function sinkProblem(name: string, args: string[]): string | undefined {
  const subscript = (a: string) => /\w\[/.test(a);
  if (name === "let") return "let evaluates its words as arithmetic";
  if (DECLARERS.has(name) && args.some((a) => /^[-+][a-zA-Z]*i/.test(a))) return `${name} -i evaluates the value as arithmetic`;
  if (name === "set" && args.some((a) => /^-[a-zA-Z]*x/.test(a) || a === "xtrace")) return "set -x prints each command through PS4, which bash expands";
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
  // Set when the call writes files the guard cannot name or place (an archive, a patch, a git
  // checkout, a recursive copy): the reason.
  unknownWrite?: string;
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
}
const RECURSIVE = /^(-[a-zA-Z]*[rRa][a-zA-Z]*|--recursive|--archive)$/;
// Writers whose output names are not on the command line (finding 23).
function unnamedWrite(name: string, args: string[]): string | undefined {
  if (name === "tar" || name === "gtar" || name === "bsdtar") {
    const first = args[0] ?? "";
    if (longOption(args, ["--extract", "--get"]) || args.some((a) => /^-[a-zA-Z]*x/.test(a) && !a.startsWith("--")) || /^[a-zA-Z]*x/.test(first)) return `${name} -x writes the files the archive names`;
  }
  if ((name === "unzip" && !args.some((a) => /^-[a-zA-Z]*[lptvZ]/.test(a))) || name === "7z" || name === "cpio" || name === "rar" || name === "unrar") return `${name} writes the files the archive names`;
  if (/^(gunzip|unxz|unzstd|bunzip2|uncompress)$/.test(name) || (/^(gzip|xz|zstd|bzip2)$/.test(name) && args.some((a) => /^(-[a-zA-Z]*d|--decompress|--uncompress)$/.test(a)))) return `${name} -d writes files next to its input`;
  if (name === "patch" && !args.some((a) => /^(--dry-run|-o|--output)/.test(a))) return "patch writes the files the diff names";
  if (name === "rsync") return "rsync writes the files it copies";
  if (["cp", "mv", "install"].includes(name) && args.some((a) => RECURSIVE.test(a))) return `${name} -r writes the files of the directories it copies`;
  if (name === "git") {
    const call = gitCall(args);
    if (typeof call === "string") return undefined;
    const sub = call.sub ?? "";
    const words = call.rest.filter((w) => !w.startsWith("-"));
    if (sub === "apply" && call.rest.some((w) => /^--(check|stat|numstat|summary)$/.test(w)) && !call.rest.includes("--apply")) return undefined;
    if (sub === "stash" && ["list", "show", "create", "store"].includes(words[0] ?? "")) return undefined;
    if (sub === "stash" && !words.length) return undefined; // saves and cleans: writes only what was there
    if (sub === "branch" || sub === "tag") return undefined;
    if (["apply", "am", "checkout", "switch", "restore", "reset", "stash", "merge", "pull", "rebase", "cherry-pick", "revert", "mv", "checkout-index", "read-tree", "worktree", "submodule", "sparse-checkout"].includes(sub)) return `git ${sub} writes files of the work tree`;
  }
  return undefined;
}

// The files and directories each command writes, as far as its words tell, and the first command
// that writes files it does not name.
export function writesOf(cmds: Simple[]): { writes: Write[]; unknown?: string } {
  const writes: Write[] = [];
  let unknown: string | undefined;
  for (const cmd of cmds) {
    for (const word of cmd.out) writes.push({ word, cmd, checked: true });
    for (const at of programs(cmd.argv)) {
      const name = path.basename(cmd.argv[at]);
      const args = cmd.argv.slice(at + 1);
      const files = args.filter((a) => !a.startsWith("-"));
      const add = (word: string | undefined, checked: boolean, extra: Partial<Write> = {}) => void (word !== undefined && writes.push({ word, cmd, checked, ...extra }));
      unknown ??= unnamedWrite(name, args);
      if (name === "tee" || name === "truncate") files.forEach((f) => add(f, true));
      else if (name === "sed" && args.some((a) => /^(-[a-zA-Z]*i|--in-place)/.test(a))) files.slice(args.some((a) => /^(-[a-zA-Z]*e$|--expression)/.test(a)) ? 0 : 1).forEach((f) => add(f, true));
      else if ((name === "perl" || name === "ruby") && args.some((a) => /^-[a-zA-Z]*i/.test(a))) files.slice(args.some((a) => /^-[a-zA-Z]*e$/.test(a)) ? 1 : 0).forEach((f) => add(f, false));
      else if (["cp", "mv", "ln", "install", "rsync"].includes(name)) {
        // `-t DIR` / `--target-directory=DIR`: every operand is a source (the rules read the last
        // one as the destination and never look at DIR).
        const t = valued(args, "t", "--target-directory");
        const operands = files.filter((f) => !t.includes(f) && !(name === "install" && valued(args, "m", "--mode").includes(f)));
        if (t.length) add(t.at(-1), false, { dir: true, sources: operands });
        else if (operands.length > 1) add(operands.at(-1), true, { sources: operands.slice(0, -1) });
      } else if (name === "dd") args.filter((a) => a.startsWith("of=")).forEach((a) => add(a.slice(3), true));
      else if (name === "patch") files.forEach((f) => add(f, true));
      else if (name === "sort") valued(args, "o", "--output").forEach((f) => add(f, false));
      else if (name === "tree") valued(args, "o", "--never").forEach((f) => add(f, false));
      else if (name === "less") [...valued(args, "o", "--log-file"), ...valued(args, "O", "--LOG-FILE")].forEach((f) => add(f, false));
      else if (name === "uniq" || name === "xxd") add(files.length > 1 ? files[1] : undefined, false);
      else if ((name === "yq" || name === "jq") && args.some((a) => /^(-[a-zA-Z]*i|--inplace)$/.test(a))) files.slice(1).forEach((f) => add(f, false));
      else if (name === "curl") [...valued(args, "o", "--output")].forEach((f) => add(f, true));
      else if (name === "wget") [...valued(args, "O", "--output-document")].forEach((f) => add(f, true));
      else if (name === "git") for (const [word, dir] of gitWrites(args)) add(word, false, { dir });
    }
  }
  return { writes, ...(unknown ? { unknown } : {}) };
}

// The files this command would write, append to or edit in place, as the rules cannot always
// tell (they leave an appended file's origin alone, and do not follow `sed -i`).
export function writtenBy(cmds: Simple[], resolve: (word: string, cmd?: Simple) => string | undefined): string[] {
  const out: (string | undefined)[] = [];
  for (const w of writesOf(cmds).writes) {
    const p = resolve(w.word, w.cmd);
    if (!w.dir) out.push(p);
    if (p && w.sources) out.push(...w.sources.map((s) => path.join(p, path.basename(s))));
  }
  return out.filter((p): p is string => !!p);
}

// ---- where each command runs ----

// Every simple command of a tool call with the words bash passes (as allCommands), each with the
// directory it runs in: the tool call's, followed through plain `cd <existing dir>` commands.
// After a `cd` the directory is unknown when it names nothing that exists yet, holds a variable or
// `-`, sits in a subshell or a group, or is `pushd`/`popd`. A `cd` the rules do not follow (behind
// a keyword, `builtin`, `command`, inside `eval`) is reported: the rules place relative paths in
// the wrong directory after it.
export interface Located {
  cmds: Simple[];
  cwd: Map<Simple, string | undefined>;
  hiddenCd?: string;
}
const CD_WORDS = new Set(["cd", "pushd", "popd"]);
export function located(command: string, start: string | undefined, depth = 0, into?: Located): Located {
  const out: Located = into ?? { cmds: [], cwd: new Map() };
  if (depth > 4) return out;
  const parsed = parse(command);
  let cwd = start;
  for (const cmd of parsed.cmds) {
    out.cmds.push(cmd);
    out.cwd.set(cmd, cwd);
    for (const i of programs(cmd.argv)) {
      const name = path.basename(cmd.argv[i]);
      if (i > 0 && CD_WORDS.has(name)) out.hiddenCd ??= `${cmd.argv.slice(0, i + 2).join(" ")}: a cd the rules do not follow, so they judge relative paths in the wrong directory`;
      if (name === "eval" && cmd.argv.slice(i + 1).some((w) => /(^|[\s;&|({])(cd|pushd|popd)(\s|$|;)/.test(w) || CD_WORDS.has(w))) out.hiddenCd ??= "a cd inside eval, which the rules do not follow";
    }
    if (!CD_WORDS.has(cmd.argv[0])) continue;
    if (cmd.argv[0] !== "cd" || cmd.subshell || parsed.grouped || cmd.argv.length > 2) {
      cwd = undefined;
      continue;
    }
    const arg = cmd.argv[1] ?? "~";
    if (/[$`*?[]/.test(arg) || arg === "-" || /^~[^/]/.test(arg)) {
      cwd = undefined;
      continue;
    }
    const target = tilde(arg);
    const base = path.isAbsolute(target) ? "/" : cwd;
    cwd = base === undefined ? undefined : landing(base, target);
  }
  for (const cmd of parsed.cmds) for (const body of nestedBodies([cmd])) located(body, out.cwd.get(cmd), depth + 1, out);
  return out;
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
  const blind = new Set<string>();
  const runs = (word: string | undefined) => {
    if (word === undefined) return;
    const p = ctx.resolve(word, cmd);
    if (p && written.has(p)) ran.add(p);
    // After a write the guard cannot name or place, any file run by its path may be one it wrote.
    else if (ctx.unknownWrite) blind.add(word);
  };
  ask(traversalProblem(cmd.argv));
  // `for NAME do cmd` on one line: the rules read `do cmd` as words of the loop header and never
  // see `cmd`.
  if ((cmd.argv[0] === "for" || cmd.argv[0] === "select") && cmd.argv[2] === "do") ask(`${cmd.argv[0]} ${cmd.argv[1]} do on one line, where the rules read the loop's commands as words of its header`);
  for (const at of programs(cmd.argv)) {
    const word = cmd.argv[at];
    const name = path.basename(word);
    const args = cmd.argv.slice(at + 1);
    const files = args.filter((a) => !a.startsWith("-"));

    // Package installs run third-party install scripts.
    const pip = /^python3?$/.test(name) && args[0] === "-m" && args[1] === "pip";
    const manager = pip ? "pip" : name;
    // A directory a global option names (`npm --prefix web`): one in the project (finding 29).
    const placeOk = (dir: string) => {
      const p = ctx.resolve(dir, cmd);
      return !!p && !!ctx.inProject?.(p);
    };
    if (Object.hasOwn(INSTALLERS, manager)) ask(installProblem(manager, pip ? args.slice(2) : args, placeOk));
    if (name === "npx" || name === "bunx" || name === "pnpx" || name === "uvx" || name === "pipx") ask(`${name} downloads and runs a package`);

    add(programProblem(name, args, ctx.cwdOf?.(cmd), ctx.inProject));
    ask(sinkProblem(name, args));
    for (const variable of assignedBy(name, args)) if (anyDangerous(variable)) ask(dangerous(variable));
    // `set -a` exports every variable set after it (finding 10).
    if (name === "set") {
      const end = args.indexOf("--");
      if ((end < 0 ? args : args.slice(0, end)).some((a) => /^-[a-zA-Z]*a/.test(a))) ask("set -a exports every variable set after it to the programs that follow");
    }

    // A file this session wrote is the agent's own code: the model sees it before it runs.
    if (word.includes("/")) runs(word);
    if (SHELLS.has(name) || INTERPRETERS.has(name) || FILE_RUNNERS.has(name) || /^python3?(\.\d+)?$/.test(name)) for (const f of files) runs(f);
    if (name === "sed" || AWKS.has(name)) for (const f of valued(args, "f", "--file")) runs(f);
    if (MAKES.has(name)) for (const f of makefiles(args)) runs(f);
  }
  if (ran.size) add({ action: "classify", reason: `runs ${[...ran].map((f) => path.basename(f)).join(", ")}, which this session wrote`, files: [...ran] });
  if (blind.size) add({ action: "classify", reason: `runs ${[...blind].join(", ")} after this command wrote files the guard cannot list (${ctx.unknownWrite})` });
  return verdict;
}

export function argvGuards(cmds: Simple[], ctx: ArgvContext): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  for (const cmd of cmds) verdict = stricter(verdict, argvGuard(cmd, ctx));
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
