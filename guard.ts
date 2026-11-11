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

// Where bash ends the substitution that opens at `open`: a parenthesis inside quotes, a comment
// or a heredoc body does not count. -1 when it cannot be followed.
function closeBash(s: string, open: number): number {
  let depth = 0;
  let wordStart = true;
  const heredocs: { delimiter: string; dash: boolean }[] = [];
  for (let i = open; i < s.length; i++) {
    const c = s[i];
    const startsWord = wordStart;
    wordStart = false;
    if (c === "\\") i++;
    else if (c === "'") {
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
const HEREDOC = /^<<(-?)[ \t]*(?:'([\w.-]+)'|"([\w.-]+)"|([\w.-]+))(?=[ \t\n;|&)<>]|$)/;
// The rules parse the string these are given as a command of its own.
const NESTED_SHELLS = new Set(["bash", "sh", "zsh", "dash", "ksh"]);
const CODE_FLAG = /^-[a-zA-Z]*c[a-zA-Z]*$/;
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

// Shell syntax that bash and the rules' parser read differently, or undefined. The parser knows
// words, quotes, `$(...)`, backticks, redirects, heredocs and comments; it has no `$'...'`, no
// `${...}`, no arithmetic and no brace expansion, and it reads their insides as ordinary command
// text. So a `#` there starts a comment for the parser only, a `<<` a heredoc, a quote a string,
// and bash runs what the parser skipped. This scanner follows both readings: it keeps the
// parser's "at the start of a word" state exactly, accepts plain forms inside `${...}` and
// arithmetic, and asks about the rest. It also runs on every string the rules parse as a
// command of its own (`sh -c '...'`, `eval ...`), and asks when such a string is not literal.
export function unmodelled(s: string, depth = 0): string | undefined {
  if (depth > 6) return "deeply nested substitutions";
  if (ESCAPED_PAYLOAD.test(s)) return PAYLOAD_REASON;
  const found = scan(s, depth);
  if (found) return found;
  const parsed = parse(s);
  if (parsed.opaque) return "shell syntax the rules do not model";
  for (const body of nestedBodies(parsed.cmds)) {
    const inner = unmodelled(body, depth + 1);
    if (inner) return `${inner}, in a command a nested shell runs`;
  }
  return undefined;
}

function scan(s: string, depth: number): string | undefined {
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

  const start = (i: number) => {
    if (!atStart) return;
    atStart = false;
    begin = i;
    text = "";
    expands = kept = braces = false;
  };
  const endWord = (): string | undefined => {
    if (atStart) return undefined;
    atStart = true;
    const plain = text.replace(/[\u0001-\u0003]/g, "?");
    if (nested === 2) {
      if (expands) return "a command for a nested shell built from a variable or a substitution";
      if (kept) return "a command for a nested shell with a backslash in double quotes";
    } else if (plain === "eval") nested = 2;
    else if (NESTED_SHELLS.has(path.basename(plain))) nested = 1;
    else if (nested === 1 && CODE_FLAG.test(plain)) nested = 2;
    return braces ? braceProblem(text) : undefined;
  };
  const endCommand = (): string | undefined => {
    const found = endWord();
    nested = 0;
    return found;
  };

  const substitution = (open: number): number | string => {
    const end = closeNaive(s, open);
    if (end < 0 || end !== closeBash(s, open)) return "a substitution with parentheses in quotes, a comment or a heredoc, or unbalanced ones";
    return unmodelled(s.slice(open + 1, end), depth + 1) ?? end;
  };
  const backticks = (open: number): number | string => {
    const end = s.indexOf("`", open + 1);
    if (end < 0) return "an unterminated backtick";
    const body = s.slice(open + 1, end);
    if (body.includes("\\")) return "a backslash inside backticks";
    return unmodelled(body, depth + 1) ?? end;
  };
  // `$(`, `${`, `$((`, `$[` and what cannot follow a `$` here, from the `$` at `i`. Returns the
  // index of the last character, or -1 when the `$` is an ordinary one.
  const dollar = (i: number, quoted: boolean): number | string => {
    const next = s[i + 1];
    if (next === "{") return brace(i, quoted);
    if (next === "(") return s[i + 2] === "(" ? arithmetic(i + 3, false) : substitution(i + 1);
    if (next === "[") return "the old $[...] arithmetic";
    return -1;
  };

  // Arithmetic from just after `((`: the index of the closing `))`. The parser reads the inside
  // as commands, so a `#` at the start of one of its words hides the rest of the line from it.
  const arithmetic = (from: number, semicolons: boolean): number | string => {
    let wordStart = true;
    let parens = 0;
    for (let i = from; i < s.length; i++) {
      const c = s[i];
      if (c === ")") {
        if (parens === 0) return s[i + 1] === ")" ? i + 1 : "arithmetic with unbalanced parentheses";
        parens--;
        wordStart = true;
      } else if (c === "(") {
        parens++;
        wordStart = true;
      } else if (c === "#") {
        if (wordStart) return "a # inside arithmetic, which the rules read as a comment";
      } else if (c === "<" && s[i + 1] === "<") return "<< inside arithmetic, which the rules read as a heredoc";
      else if (c === "$") {
        const end = dollar(i, false);
        if (typeof end === "string") return end;
        if (end < 0 && /['"]/.test(s[i + 1] ?? "")) return "quotes inside arithmetic";
        if (end >= 0) i = end;
        wordStart = false;
      } else if (c === "`") {
        const end = backticks(i);
        if (typeof end === "string") return end;
        i = end;
        wordStart = false;
      } else if (c === " " || c === "\t" || c === "<" || c === ">" || c === "&" || c === "|" || (c === ";" && semicolons)) wordStart = true;
      else if (/[\w.+\-*\/%=!~?:,^\[\]]/.test(c)) wordStart = false;
      else return "arithmetic with quotes, backslashes or line breaks";
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
    i += name.length;
    if (s[i] === "[") {
      const close = s.indexOf("]", i);
      if (close < 0 || !/^(?:[@*]|-?\d+)$/.test(s.slice(i + 1, close))) return "an array subscript that is not a number, which bash evaluates as arithmetic";
      i = close + 1;
    }
    if (s[i] === "}") return i;
    if (length) return "a ${...} form the guard does not model";
    const c = s[i];
    if (c === "@") return "a ${name@X} transformation";
    if (c === ":" && !"-=+?".includes(s[i + 1] ?? "")) {
      const close = s.indexOf("}", i);
      if (close < 0 || !/^ ?-?\d+(?::-?\d+)?$/.test(s.slice(i + 1, close))) return "a substring offset that is not a number, which bash evaluates as arithmetic";
      return close;
    }
    if (c === ":") i++;
    const op = s[i];
    if ("-=+?".includes(op) && s[i] !== undefined) {
      if (op === "=" && ENV_DANGEROUS.test(name)) return `sets ${name}, which changes what programs run or load`;
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
        // bash drops the backslash before these only; the parser drops it before anything.
        if (next !== undefined && !'$`"\\\n'.includes(next)) kept = true;
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
      } else text += quotedText(c);
    }
    return "an unterminated quote";
  };

  // The substitutions bash runs in a heredoc body whose delimiter is not quoted.
  const heredocBody = (from: number, to: number): string | undefined => {
    for (let i = from; i < to; i++) {
      const c = s[i];
      let end: number | string = -1;
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
    if (c === "\\") {
      // A backslash and a line break join two lines: the word, if any, goes on.
      if (next !== "\n") {
        start(i);
        text += quotedText(next ?? "");
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
      const end = dollar(i, false);
      if (typeof end === "string") return end;
      if (end >= 0) {
        i = end;
        text += OPAQUE;
        expands = true;
      } else if (next === "#") {
        text += "$#";
        i++;
      } else {
        text += c;
        if (/[\w@*?!$-]/.test(next ?? "")) expands = true;
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
      found = endWord();
      if (next === "<" && s[i + 2] === "<") i += 2; // a here-string
      else if (next === "<") {
        const m = HEREDOC.exec(s.slice(i));
        if (!m) return "a heredoc delimiter that is not one plain or fully quoted word";
        heredocs.push({ delimiter: m[2] ?? m[3] ?? m[4], dash: m[1] === "-", quoted: m[4] === undefined });
        i += m[0].length - 1;
      } else if (next === "&") {
        let j = i + 2;
        while (/[\d-]/.test(s[j] ?? "")) j++;
        if (j === i + 2 || (j < s.length && !WORD_END.test(s[j]))) return "a redirect from a descriptor that is not a plain number";
        i = j - 1;
      }
    } else if (c === ">" || (c === "&" && next === ">")) {
      // The parser drops a number straight before `>` as a descriptor; bash does so only when
      // the number is not quoted.
      if (!atStart && /^\d+$/.test(text)) {
        if (s.slice(begin, i) !== text) return "a quoted number straight before a redirect";
        atStart = true;
      }
      found = endWord();
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
      }
      i = j - 1;
    } else if (c === " " || c === "\t") found = endWord();
    else if (c === ";") found = endCommand();
    else if (c === "&" || c === "|") {
      found = endCommand();
      if (next === c || (c === "|" && next === "&")) i++;
    } else if (c === "(" && next === "(") {
      found = endCommand();
      const end = arithmetic(i + 2, true);
      if (typeof end === "string") return end;
      i = end;
    } else if (c === "(" || c === ")") found = endCommand();
    else if (c === "#" && atStart) {
      const end = s.indexOf("\n", i);
      i = end < 0 ? s.length : end - 1;
    } else if (c === "\n") {
      found = endCommand();
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
      start(i);
      if (c === "{") braces = true;
      text += c;
    }
    if (found) return found;
  }
  if (heredocs.length) return "a heredoc with no body";
  return endCommand();
}

// ---- strict tokenizer ----

const BARE = /[A-Za-z0-9_@%+=:,.\/^~-]/;
const NULL_REDIRECT = /^(?:(?:[12]?>>?|&>) ?\/dev\/null|2>&1)(?=[ \t;|&]|$)/;

export interface StrictCommand {
  argv: string[];
  // What joined it to the command before it: `&&`, `;`, `|` or `||`.
  before?: string;
  // One of its words starts with a quoted `~`, which bash does not expand.
  quotedTilde?: boolean;
}

// The simple commands of a command line made only of plain words: letters, digits and
// `_@%+=:,./^~-`, single-quoted text, and double-quoted text without `$`, backtick, backslash or
// `!`. Commands are joined by `&&` or `;` (with `pipes`: also `|` and `||`). With
// `nullRedirects`, `>/dev/null`, `2>/dev/null` and `2>&1` are dropped. Anything else (variables,
// substitutions, globs, braces, other redirects, comments, newlines, assignments) gives
// undefined: the caller grants nothing.
export function strictCommands(command: string, opts: { pipes?: boolean; nullRedirects?: boolean } = {}): StrictCommand[] | undefined {
  const cmds: StrictCommand[] = [];
  let argv: string[] = [];
  let word: string | undefined;
  let before: string | undefined;
  let quotedTilde = false;
  const endWord = () => {
    if (word !== undefined) argv.push(word);
    word = undefined;
  };
  const endCmd = (separator?: string) => {
    endWord();
    if (!argv.length || argv[0].includes("=")) return false;
    cmds.push({ argv, ...(before ? { before } : {}), ...(quotedTilde ? { quotedTilde } : {}) });
    argv = [];
    before = separator;
    quotedTilde = false;
    return true;
  };
  const s = command;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === " " || c === "\t") endWord();
    else if (c === "'" || c === '"') {
      const end = s.indexOf(c, i + 1);
      if (end < 0 || (c === '"' && /[$`\\!]/.test(s.slice(i + 1, end)))) return undefined;
      if (word === undefined && s[i + 1] === "~") quotedTilde = true;
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
      if (!endCmd(two ? c + c : c)) return undefined;
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

export const strict = (command: string, opts: { pipes?: boolean; nullRedirects?: boolean } = {}): string[][] | undefined => strictCommands(command, opts)?.map((c) => c.argv);

export const tilde = (p: string) => (p === "~" || p.startsWith("~/") ? HOME + p.slice(1) : p);

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
// that exists. A quoted `~` is not the home directory, so a word that starts with one grants
// nothing.
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
function gitCallProblem(call: GitCall): string | undefined {
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
  return undefined;
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
        const found = gitCallProblem(call);
        if (found) return found;
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
  // Files this session (or this command) wrote, appended to or edited, by full path.
  written: () => Set<string>;
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
    const variable = ASSIGN.exec(w)?.[1] ?? (declared.includes(w) && /^[A-Za-z_]\w*$/.test(w) ? w : undefined);
    if (!variable) continue;
    if (ENV_DANGEROUS.test(variable)) add("ask", dangerous(variable));
    // A variable set on a line of its own stays in the shell: only one set for a command, or
    // exported, reaches the programs it runs.
    else if (!ENV_HARMLESS.test(variable) && ASSIGN.test(w) && (exports || (prefix.includes(w) && words.length > 0))) add("classify", `sets ${variable} for the programs it runs`);
  }
  // A loop variable is set without `NAME=`.
  const forAt = rawWords.findIndex((w) => w === "for" || w === "select");
  if (forAt >= 0 && rawWords[forAt + 2] === "in" && ENV_DANGEROUS.test(rawWords[forAt + 1])) add("ask", dangerous(rawWords[forAt + 1]));
  if (!words.length) return verdict;

  // Credential files named by a glob or by braces: the rules see the word before bash expands it.
  for (const word of args) {
    if (word.startsWith("-") && !word.includes("=")) continue;
    const text = word.replace(/^-[^=]*=/, "").replace(/^@/, "");
    const dynamic = /[$`]/.test(text);
    if (!dynamic && !/[*?[{]/.test(text)) continue;
    const relative = !/^(\/|~\/|~$)/.test(text);
    const files = dynamic || (relative && !ctx.cwdKnown) ? undefined : expandWord(text, ctx.cwd);
    if (!files) {
      if (READERS.has(name)) add("classify", `${name} reads a file named at run time: ${word}`);
      continue;
    }
    // A file called `-rf` or `--to-command=x` becomes an option once the glob is expanded.
    const option = !text.includes("/") && text === word ? files.find((f) => path.basename(f).startsWith("-")) : undefined;
    if (option) add("ask", `${word} matches ${path.basename(option)}, which ${name} would read as an option`);
    const secret = NAMES_ONLY.has(name) ? undefined : files.find((f) => readVerdict("read", f, ctx.scope));
    if (secret) add("ask", `${name} reads a credential file: ${word} matches ${secret}`);
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

// ---- per command, with its real words ----

// Every simple command of a tool call with the words bash passes: the rules' own parse, and
// the same for each string a nested shell is handed.
export function allCommands(command: string, depth = 0): Simple[] {
  if (depth > 4) return [];
  const cmds = parse(command).cmds;
  return [...cmds, ...nestedBodies(cmds).flatMap((body) => allCommands(body, depth + 1))];
}

const WRAPPER_NAMES = new Set(["env", "nice", "ionice", "timeout", "time", "command", "builtin", "nohup", "setsid", "stdbuf", "exec", "chrt", "taskset", "sudo", "doas", "xargs", "if", "then", "elif", "else", "do", "while", "until", "!", "{"]);
// What may stand between a wrapper and the program it runs: options, numbers and durations,
// `NAME=value`, signal and variable names, xargs' `{}`.
const WRAPPER_WORD = /^(-.*|\d+(\.\d+)?[smhd]?|[A-Z_][A-Z0-9_]*(=.*)?|\{\})$/;
// The words of a command that could be the program it runs. The rules drop `timeout 60` and
// `env` and stop at the first word they do not know (`env -u X npm install` reads as `X ...`).
function programs(argv: string[]): number[] {
  const out: number[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (i === 0 || /^-(exec|execdir|ok|okdir)$/.test(argv[i - 1])) out.push(i);
    else if (argv.slice(0, i).every((w) => WRAPPER_NAMES.has(path.basename(w)) || WRAPPER_WORD.test(w) || ASSIGN.test(w)) && !WRAPPER_WORD.test(argv[i])) out.push(i);
  }
  return out;
}

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

function installProblem(manager: string, managerArgs: string[]): string | undefined {
  const sub = managerArgs.find((a) => !a.startsWith("-"));
  if (managerArgs[0]?.startsWith("-") && sub && !/^(-v|-V|--version|-h|--help)$/.test(managerArgs[0])) return `${manager} with options before its subcommand`;
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

function awkProblem(args: string[]): GuardVerdict | undefined {
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-F" || a === "-v" || a === "--field-separator" || a === "--assign") i++;
    else if (/^(-F.|-v.|--field-separator=|--assign=)/.test(a)) continue;
    else if (a === "-e" || a === "--source") return awkScript(args[i + 1] ?? "");
    else if (a.startsWith("--source=")) return awkScript(a.slice(9));
    else if (a.startsWith("-") && a !== "-") return { action: "classify", reason: `awk ${a} loads a program or an extension` };
    else return awkScript(a);
  }
  return undefined;
}
const awkScript = (script: string): GuardVerdict | undefined =>
  /system|getline|\||@\s*(load|include)|>>?\s*[^=\s\d]/.test(script) ? { action: "classify", reason: "an awk program that runs commands, reads through a pipe or writes files" } : undefined;

// Options that make a program run another one, by the option's name: asked about wherever the
// program is named. Other allowed programs are judged by their own name alone (see Known gaps).
function programProblem(name: string, args: string[]): GuardVerdict | undefined {
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
  if (MAKES.has(name)) {
    if (longOption(args, ["--eval"]) || args.some((a) => /^-[a-zA-Z]*E/.test(a) && !a.startsWith("--"))) return ask("make --eval runs makefile text from the command line");
    const variable = args.find((a) => /^(SHELL|\.SHELLFLAGS|MAKEFLAGS|MAKEFILES)=/.test(a));
    if (variable) return ask(`make ${variable.split("=")[0]}= picks the program make runs recipes with`);
  }
  if ((name === "fd" || name === "fdfind") && (longOption(args, ["--exec", "--exec-batch"]) || args.some((a) => /^-[a-zA-Z]*[xX]/.test(a) && !a.startsWith("--")))) return ask("fd -x runs a command for every match");
  if (name === "rg" && longOption(args, ["--pre", "--pre-glob", "--hostname-bin"])) return ask("rg --pre runs a program on every file");
  if (name === "man" && (longOption(args, ["--pager", "--html", "--prompt", "--troff-device"]) || args.some((a) => /^-[a-zA-Z]*[PH]/.test(a) && !a.startsWith("--")))) return ask("man -P or -H runs a program of the caller's choosing");
  if (name === "sed") return sedProblem(args);
  if (AWKS.has(name)) return awkProblem(args);
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
// `printf -v`, the second word of `getopts`. (`for NAME in` and `declare NAME` are in textGuard.)
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
  return [];
}

export interface ArgvContext extends TextContext {
  // Resolves a word to the file it names, or undefined when that cannot be known.
  resolve: (word: string) => string | undefined;
}

// The files this command would write, append to or edit in place, as the rules cannot always
// tell (they leave an appended file's origin alone, and do not follow `sed -i`).
export function writtenBy(cmds: Simple[], resolve: (word: string) => string | undefined): string[] {
  const out: (string | undefined)[] = [];
  for (const cmd of cmds) {
    out.push(...cmd.out.map(resolve));
    for (const at of programs(cmd.argv)) {
      const name = path.basename(cmd.argv[at]);
      const args = cmd.argv.slice(at + 1);
      const files = args.filter((a) => !a.startsWith("-"));
      if (name === "tee") out.push(...files.map(resolve));
      else if (name === "sed" && args.some((a) => /^(-[a-zA-Z]*i|--in-place)/.test(a))) out.push(...files.slice(args.some((a) => /^(-[a-zA-Z]*e$|--expression)/.test(a)) ? 0 : 1).map(resolve));
      else if (["cp", "mv", "ln", "install", "rsync"].includes(name) && files.length > 1) {
        const dest = resolve(files.at(-1)!);
        out.push(dest, ...(dest ? files.slice(0, -1).map((f) => path.join(dest, path.basename(f))) : []));
      } else if (name === "dd") out.push(...args.filter((a) => a.startsWith("of=")).map((a) => resolve(a.slice(3))));
      else if (name === "patch" || name === "truncate") out.push(...files.map(resolve));
    }
  }
  return out.filter((p): p is string => !!p);
}

// One simple command with its real words: package installs, options that run programs, the
// arithmetic sinks, variables set without an assignment, and files this session wrote.
export function argvGuard(cmd: Simple, ctx: ArgvContext): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  const add = (v: GuardVerdict | undefined) => void (verdict = stricter(verdict, v));
  const ask = (reason: string | undefined) => add(reason ? { action: "ask", reason } : undefined);
  const written = ctx.written();
  const ran = new Set<string>();
  const runs = (word: string | undefined) => {
    const p = word === undefined ? undefined : ctx.resolve(word);
    if (p && written.has(p)) ran.add(p);
  };
  for (const at of programs(cmd.argv)) {
    const word = cmd.argv[at];
    const name = path.basename(word);
    const args = cmd.argv.slice(at + 1);
    const files = args.filter((a) => !a.startsWith("-"));

    // Package installs run third-party install scripts.
    const pip = /^python3?$/.test(name) && args[0] === "-m" && args[1] === "pip";
    const manager = pip ? "pip" : name;
    if (Object.hasOwn(INSTALLERS, manager)) ask(installProblem(manager, pip ? args.slice(2) : args));
    if (name === "npx" || name === "bunx" || name === "pnpx" || name === "uvx" || name === "pipx") ask(`${name} downloads and runs a package`);

    add(programProblem(name, args));
    ask(sinkProblem(name, args));
    for (const variable of assignedBy(name, args)) if (ENV_DANGEROUS.test(variable)) ask(dangerous(variable));

    // A file this session wrote is the agent's own code: the model sees it before it runs.
    if (word.includes("/")) runs(word);
    if (SHELLS.has(name) || INTERPRETERS.has(name) || FILE_RUNNERS.has(name) || /^python3?(\.\d+)?$/.test(name)) for (const f of files) runs(f);
    if (name === "sed" || AWKS.has(name) || MAKES.has(name)) for (const f of [...valued(args, "f", "--file"), ...(MAKES.has(name) ? valued(args, "f", "--makefile") : [])]) runs(f);
  }
  if (ran.size) add({ action: "classify", reason: `runs ${[...ran].map((f) => path.basename(f)).join(", ")}, which this session wrote`, files: [...ran] });
  return verdict;
}

export function argvGuards(cmds: Simple[], ctx: ArgvContext): GuardVerdict | undefined {
  let verdict: GuardVerdict | undefined;
  for (const cmd of cmds) verdict = stricter(verdict, argvGuard(cmd, ctx));
  return verdict;
}
