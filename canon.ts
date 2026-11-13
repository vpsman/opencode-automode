// The canonical run (round 4, finding 16). Four rounds each found a family of inputs that bash
// runs differently from how the checks read them, because several hand-written readers (the
// scanner, the strict tokenizer, the vendored parser) each had to agree with bash on every
// spelling bash accepts. This module removes the spellings instead.
//
// canonical() reads a command as bash's lexer does and prints it back in a spelling small enough
// that bash and the vendored parser (rules.ts `parse`) cannot read it differently:
//
//   - A word is a run of pieces. Literal text is written bare when every character of it is
//     plain (`[A-Za-z0-9_@%+=:,./-]`), and in single quotes otherwise; a single quote is `\'`
//     and a parenthesis `\(` or `\)`, outside quotes, so that the parser's parenthesis counting
//     (which knows no quotes) skips it. What bash expands unquoted stays unquoted: globs, `~`.
//   - An expansion has one form: `$name` or `${name}`; `${...}` with a plain operand; `$(...)`
//     with canonical text inside (backticks become `$(...)`); `$((...))` as written. Each is in
//     double quotes exactly when the source had it in double quotes.
//   - Braces are expanded here, by the guard's own expander (held to bash by test/glob.test.mts),
//     into the separate words bash would make of them.
//   - Comments and backslash-newlines are gone. Operators stand between blanks.
//   - A heredoc gets a fresh delimiter that occurs nowhere in the command, and
//     `"$(cat <<'X' ... X)"` (the commit message agents write) is folded into the literal it
//     stands for. Inside `${...}` a heredoc asks.
//   - A command that defines a function is printed as plain words: nothing is folded, no
//     message is replaced and no nested code is printed (see `print`).
//   - The code handed to a nested bash, sh or dash, and to `eval`, is printed the same way.
//
// The printed text is what the scanner, the rules and the guards judge, and it is what runs (the
// wrapper takes it from the environment, see index.ts). So a mistake in this reader changes
// what the command does, in plain sight, and is caught by the round-trip test; it cannot make
// bash run a command the checks did not see. Whatever cannot be printed asks.
//
// `judged` is the text the rules and guards read. It is `text`, except where the vendored parser
// has no reading at all and the construct holds no command of its own: a validated `$((...))` is
// `0`, an arithmetic command is `:`, `[[ ... ]]` is `test ...` with its operators as words, a
// descriptor copy on the input side (`<&3`) is left out, and the text of a message of
// `git commit`, `git tag` or `git merge` is the word `message` (a literal word that bash hands
// on as it is; see `messages`). And a double-quoted `$name` in an argument word is the literal
// the call plainly assigns to `name` at its start, where nothing else in the call can set it
// (see `constantsOf`: the rules then judge `name=foo; grep "$name" src` as `grep foo src`). The
// scanner reads `text`: what a substitution, a subscript or an arithmetic operand inside
// `[[ ]]` or `$(( ))` would run is asked about there.
//
// This is a lexer and a printer, not a grammar. Keywords, `case` patterns and function
// definitions pass through as words and operators; the scanner still runs on the result.
import path from "node:path";
import { braceWords, gitMessageWords, programs, SETS_BY_NAME } from "./guard.ts";

export interface Printed {
  // What runs.
  text: string;
  // What the rules and the guards read.
  judged: string;
  // The text relies on bash: braces were expanded here, or it holds `[[ ]]`, `(( ))`, `<<<`,
  // `&>`, a process substitution or a bash-only keyword. dash reads the source another way, so a
  // call that would run under dash asks.
  bashOnly: boolean;
  // The target of every input redirect printed (`<`, with any descriptor number), as it is
  // printed in `text`, at every depth: the top level, substitutions, process substitutions,
  // heredoc bodies and the code of nested shells and `eval` (round 4, group B, third pass, second
  // go: one reader for every file a `<` hands a command). Not a descriptor copy (`<&3`), a
  // here-string, a heredoc, or a target that is a process substitution as a whole (its code is
  // printed, and what that code redirects is listed).
  inputs: string[];
  // Each of `inputs` in its judged spelling (B3c, round 4, group B, third pass, first part, third
  // go): a variable that plainly holds a literal (see constantsOf) is that literal here, quoted or
  // not, where the target is made of plain text and such variables only. bash does not split a
  // redirect's target into words (a target that would be more than one is an error), and such a
  // value holds no blank and no glob character. Otherwise the same as in `inputs`. The judged
  // text itself keeps the variable in a redirect's target, as constantsOf says.
  judgedInputs: string[];
}
export type Canonical = Printed | { ask: string };

type Part =
  | { kind: "lit"; text: string; quoted: boolean }
  | { kind: "var"; name: string; quoted: boolean }
  | { kind: "param"; head: string; op: string; operand: Part[]; quoted: boolean; bash: boolean }
  | { kind: "arith"; text: string; quoted: boolean }
  | { kind: "sub"; tokens: Token[]; quoted: boolean }
  | { kind: "proc"; dir: "<" | ">"; tokens: Token[] }
  // The code of a nested shell or of `eval`, already printed.
  | { kind: "code"; text: string; judged: string }
  // The literal text of a git message (`git commit -m <text>`): the rules read a fixed word.
  | { kind: "message"; parts: Part[]; attached: boolean }
  // The regular expression after `=~` in `[[ ]]`, kept exactly as written: there a quote makes
  // a character literal and its absence makes it an operator (`$`, `.`, `+`).
  | { kind: "raw"; text: string };
interface Word {
  type: "word";
  parts: Part[];
  // The regular expression after `=~`, read as a word: its quoting is kept as written.
  regex?: boolean;
}
interface Op {
  type: "op";
  op: string;
}
interface Redir {
  type: "redir";
  fd: string;
  op: string;
  target?: Word;
  // `>&2`, `<&-`: a descriptor, no word.
  dup?: string;
}
interface Heredoc {
  type: "heredoc";
  fd: string;
  quoted: boolean;
  body: string;
  // Unquoted: what bash expands in the body.
  parts?: Part[];
  // A line of the body ended in a backslash and was joined with the next before the delimiter
  // was looked for, as bash does. dash looks for the delimiter line by line.
  joined?: boolean;
}
// `(( ... ))` where a command begins, or the head of `for ((`.
interface ArithCommand {
  type: "arith";
  text: string;
  loop: boolean;
}
// `[[ ... ]]`: its words, and `&&` and `||` between them.
interface Cond {
  type: "cond";
  items: (Word | Op)[];
}
type Token = Word | Op | Redir | Heredoc | ArithCommand | Cond;

class Ask extends Error {}
const ask = (reason: string): never => {
  throw new Ask(reason);
};

const CONTROL = new RegExp("[\\u0000-\\u0008\\u000b-\\u001f\\u007f-\\u009f" + String.fromCharCode(0x2028, 0x2029) + "]");
const NAME = /^[A-Za-z_][A-Za-z0-9_]*/;
const SPECIAL = /^(?:[@*#?$!-]|\d+)/;
const PLAIN = /^[A-Za-z0-9_@%+=:,.\/-]$/;
// Unquoted characters bash gives a meaning the printer keeps by leaving them bare.
const ACTIVE = "*?[]!^~";
// What may stand in the operand of `${name<op>operand}` as it is, besides nested expansions.
const OPERAND = /^[A-Za-z0-9_@%+=:,.\/*?\[\]~^!#-]$/;
// The literal text of an operand, whole: those characters, blanks (inside double quotes), a
// `$` that expands nothing, and a backslash with the character after it.
const OPERAND_TEXT = /^(?:[A-Za-z0-9_@%+=:,.\/*?\[\]~^!#$ \t-]|\\[^\n])*$/;
const ARITHMETIC = /^[A-Za-z0-9_ \t+\-*\/%<>=!&|^~?:,.$(){}\[\]#@]*$/;
const ASSIGNMENT = /^[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=/;
const KEEPS_COMMAND_START = new Set(["if", "then", "elif", "else", "do", "while", "until", "!", "{", "time"]);
const RESERVED = new Set(["if", "then", "elif", "else", "fi", "do", "done", "while", "until", "for", "case", "esac", "select", "function", "coproc", "in", "time", "!", "{", "}", "[[", "]]"]);
const BASH_KEYWORDS = new Set(["function", "select", "coproc"]);
const NESTED_SHELLS = new Set(["bash", "sh", "dash"]);
// The words that name git and the shells themselves: the bare name, which the shell finds on
// PATH (a command cannot change PATH without asking), and the places a system keeps them. A
// file reached by any other path (`./git`, `sub/bash`) is a program of the project's, whatever
// it is called: its words are not a git message or shell code (round 4: a script at `./git` was
// handed a message the rules never read).
const SYSTEM_DIRS = ["/usr/bin/", "/bin/", "/usr/local/bin/"];
const GIT_WORDS = new Set(["git", ...SYSTEM_DIRS.map((d) => `${d}git`)]);
const SHELL_WORDS = new Map([...NESTED_SHELLS].flatMap((name) => [name, ...SYSTEM_DIRS.map((d) => d + name)].map((word) => [word, name] as const)));
// Commands whose next two words bash reads before it expands braces: a loop's variable and its
// `in`, a function's name.
const NAMES_NEXT = new Set(["for", "select", "function", "coproc"]);
// Builtins whose arguments are assignments.
const DECLARES = ["export", "declare", "typeset", "local", "readonly"];
// Wrappers that run the words after them unchanged.
const PASSES_WORDS = new Set(["command", "exec", "nohup", "nice", "time", "timeout", "env"]);
const MAX_DEPTH = 6;
// `${a:-${b:-...}}` inside one another: more than anyone writes, far fewer than the stack holds.
const MAX_OPERANDS = 32;
// Bytes. Linux takes no single argument or environment string above 131072.
const MAX_TEXT = 100_000;

const literal = (w: Word): string | undefined => (w.parts.every((p) => p.kind === "lit") ? w.parts.map((p) => (p as { text: string }).text).join("") : undefined);
// The word as written without quotes, when it is one unquoted literal: a keyword, an operator.
const bare = (w: Word | undefined): string | undefined => (w && w.parts.length === 1 && w.parts[0].kind === "lit" && !w.parts[0].quoted ? w.parts[0].text : undefined);
const leading = (w: Word): string => (w.parts[0]?.kind === "lit" && !w.parts[0].quoted ? w.parts[0].text : "");
// A literal word that bash hands on as that one word: nothing in it is unquoted text bash turns
// into other words (a glob, which becomes file names, or a tilde). Where a word is trusted for
// what it says (a git message, the code of a nested shell), only such a word counts: `-m *` is as
// many arguments as there are files, and a file may be named `--amend`.
const fixed = (w: Word): string | undefined => (w.parts.some((p) => p.kind === "lit" && !p.quoted && /[*?[~]/.test(p.text)) ? undefined : literal(w));

// What the readers of one command share: the text (see `Lexer.src`), how many heredocs have been
// opened so far, and whether `"$(cat <<'X' ...)"` is folded into the text it stands for.
interface Source {
  s: string;
  shared: { docs: number; fold: boolean };
}

// Where a command's own words begin: after the reserved words that leave bash at the start of a
// command, and after the `-p` and `--` it reads as part of `time` (`time [-p] [--] command`;
// each only as that bare word, straight after `time`). One reading for everything that asks
// where a command begins: what its name word is (braces), whether it defines a function, and
// the reader's own state (see `Lexer.endWord`). Three rounds of guessing this from the word
// before each found one more way to be wrong (`time -p name() ...`, a word after a redirect).
function headOf(words: Word[]): number {
  let k = 0;
  while (k < words.length && KEEPS_COMMAND_START.has(bare(words[k]) ?? "")) {
    const time = bare(words[k]) === "time";
    k++;
    if (time && bare(words[k]) === "-p") k++;
    if (time && bare(words[k]) === "--") k++;
  }
  return k;
}

// The names a command defines as functions: `name () ...` and `function name ...`, wherever they
// stand (a loop body, a substitution). The tokens are cut into commands as `Printer.list` cuts
// them (at every operator and at `[[ ]]` and `(( ))`), and a command's name word is found as
// `Printer.command` finds it. `function` is the keyword only as a command's name word. An
// empty pair of parentheses after a command's words is a definition when one word stands before
// it, and nothing bash accepts otherwise: it counts as one whatever stands before it. A name
// must be written plainly to be one (bash and dash refuse a quoted or computed name).
function defined(tokens: Token[], into: Set<string>) {
  const inParts = (parts: Part[]) => {
    for (const p of parts) {
      if (p.kind === "sub" || p.kind === "proc") defined(p.tokens, into);
      else if (p.kind === "param") inParts(p.operand);
    }
  };
  // bash and dash refuse a name with quotes, a backslash or an expansion in it and define
  // nothing; printed without them it would be a definition (`'cat'() { ...; }` runs the real
  // cat, `cat ( ) { ...; }` does not).
  const named = (w: Word | undefined) => {
    if (w && bare(w) === undefined) ask("a function name written with quotes, a backslash or an expansion");
    into.add((w && bare(w)) ?? "");
  };
  let words: Word[] = [];
  const end = (op?: string, next?: Token) => {
    if (op === "(" && next?.type === "op" && next.op === ")" && words.length) named(words[words.length - 1]);
    const k = headOf(words);
    if (bare(words[k]) === "function") named(words[k + 1]);
    words = [];
  };
  tokens.forEach((t, n) => {
    if (t.type === "word") {
      words.push(t);
      inParts(t.parts);
    } else if (t.type === "redir") t.target && inParts(t.target.parts);
    else if (t.type === "heredoc") t.parts && inParts(t.parts);
    else if (t.type === "cond") {
      end();
      for (const item of t.items) if (item.type === "word") inParts(item.parts);
    } else if (t.type === "arith") end();
    else end(t.op, tokens[n + 1]);
  });
  end();
}

// bash reads the text inside backticks only when it comes to run the substitution: a syntax
// error there stops that substitution and nothing else, while the same text printed inside
// `$( )` is read with the command around it and stops all of it (found by the generator:
// `` `(})` `` and `` `ls | #` `` ran the commands around them as written, and nothing as
// printed). So backticks may hold only what cannot fail to parse: simple commands joined by
// `|`, `&&`, `||`, `;`, `&` and line breaks, with a command wherever bash wants one. Anything
// else in backticks asks; inside `$( )` bash and this reader see it at the same moment. The
// same holds for every substitution inside the backticks (`` `echo $( (}) )` ``): bash reads
// those, too, only when the backticks run.
function plainCommands(tokens: Token[]): boolean {
  const plainParts = (parts: Part[]): boolean => parts.every((p) => (p.kind === "sub" || p.kind === "proc" ? plainCommands(p.tokens) : p.kind === "param" ? plainParts(p.operand) : true));
  // Words and redirections of the command being read; whether an operator still wants one.
  let words = 0;
  let wanted = false;
  for (const t of tokens) {
    if (t.type === "word") {
      if (words === 0 && RESERVED.has(bare(t) ?? "")) return false;
      if (!plainParts(t.parts)) return false;
      words++;
    } else if (t.type === "redir") {
      if (t.target && !plainParts(t.target.parts)) return false;
      words++;
    } else if (t.type !== "op") return false;
    else if (t.op === "\n") {
      if (words > 0) wanted = false;
      words = 0;
    } else if (t.op === "|" || t.op === "&&" || t.op === "||") {
      if (words === 0) return false;
      words = 0;
      wanted = true;
    } else if (t.op === ";" || t.op === "&") {
      if (words === 0) return false;
      words = 0;
      wanted = false;
    } else return false;
  }
  return !(wanted && words === 0);
}

// ---- the reader ----

class Lexer {
  // The text, shared with the readers of the substitutions in it. bash's reader drops a
  // backslash-newline before it forms any token, outside single quotes, comments and the body of
  // a heredoc with a quoted delimiter; this reader drops each one from the text at the moment it
  // would read it as part of a token (`join`), so that `$\⏎(`, `(\⏎(`, `&\⏎&` and `na\⏎me` are the
  // tokens bash makes of them.
  private src: Source;
  private i: number;
  private depth: number;
  // Inside `$(...)`, backticks or a process substitution: bash ends a heredoc there at any line
  // that starts with the delimiter and has a `)` later on it (round 4, finding 1).
  private inner: boolean;
  private tokens: Token[] = [];
  private parts: Part[] | undefined;
  private pending: { doc: Heredoc; delimiter: string; dash: boolean }[] = [];
  private commandStart = true;
  // 1 after the keyword `time`, 2 after its `-p`.
  private timed = 0;
  // An option of `time` was read in this command: bash called `sh` takes `time` for a program
  // when a word that starts with `-` follows it, and reads the words after it as that
  // program's arguments.
  private timeOption = false;
  // The last operator was `|` (line breaks after it do not change that).
  private piped = false;
  // An assignment or a redirect has been read in this command: bash takes no reserved word
  // after one (`a=1 [[ -n x || cmd ]]` runs a program called `[[`, and then `cmd`). The scanner
  // asks about such a command as well; this is the reader's own reading of it.
  private prefixed = false;
  private cond: Cond | undefined;
  // The word being read is the regular expression after `=~` (see `regex`).
  private regexWord = false;
  private parens = 0;
  // Inside the operand of `${name<op>...}`.
  private operand = 0;

  constructor(src: string | Source, depth: number, inner: boolean, at = 0, shared?: Source["shared"]) {
    if (depth > MAX_DEPTH) ask("deeply nested substitutions");
    this.src = typeof src === "string" ? { s: src, shared: shared ?? { docs: 0, fold: true } } : src;
    this.i = at;
    this.depth = depth;
    this.inner = inner;
  }

  private get s(): string {
    return this.src.s;
  }

  // Drops the backslash-newlines that stand at `at`.
  private join(at = this.i) {
    let s = this.src.s;
    if (s[at] !== "\\" || s[at + 1] !== "\n") return;
    while (s[at] === "\\" && s[at + 1] === "\n") s = s.slice(0, at) + s.slice(at + 2);
    this.src.s = s;
  }

  // The character `k` places on, where every character up to it belongs to one token (an
  // operator, `$(`, a name): the backslash-newlines between them are dropped.
  private ahead(k: number): string | undefined {
    for (let n = 1; n <= k; n++) this.join(this.i + n);
    return this.s[this.i + k];
  }

  // The run of characters from `from` that match, with the backslash-newlines among them dropped.
  private run(from: number, first: RegExp, rest: RegExp = first): string {
    let j = from;
    for (;;) {
      this.join(j);
      const ch = this.s[j];
      if (ch === undefined || !(j === from ? first : rest).test(ch)) break;
      j++;
    }
    return this.s.slice(from, j);
  }

  private lit(text: string, quoted: boolean) {
    this.parts ??= [];
    const last = this.parts.at(-1);
    if (last && last.kind === "lit" && last.quoted === quoted) last.text += text;
    else this.parts.push({ kind: "lit", text, quoted });
  }

  private wanting(): Redir | undefined {
    const last = this.tokens.at(-1);
    return last && last.type === "redir" && last.target === undefined && last.dup === undefined ? last : undefined;
  }

  // Whether a `<(` or `>(` starts at the reader's place: inside a word bash reads a process
  // substitution as more of that word, so `<<EOF<(x)` has the delimiter `EOF<(x)` (and no line
  // `EOF` ends its body), and `2>&1<(x)` names a file. Found by the generator with another seed.
  private joinsProcess(): boolean {
    const c = this.s[this.i];
    return (c === "<" || c === ">") && this.s.slice(this.i + 1).replace(/^(?:\\\n)+/, "")[0] === "(";
  }

  private endWord() {
    const parts = this.parts;
    this.parts = undefined;
    if (!parts) return;
    const word: Word = { type: "word", parts };
    const redir = this.wanting();
    if (redir) {
      redir.target = word;
      return;
    }
    const text = bare(word);
    const piped = this.piped;
    this.piped = false;
    if (this.regexWord) {
      word.regex = true;
      this.regexWord = false;
    }
    // Straight after `|` bash does not take `time` for its keyword (parse.y,
    // `time_command_acceptable`): it runs a program called time, and the words after it are
    // that program's arguments, so a `[[` there is a word and the `||` in it an operator:
    // `cat f | time [[ -s f || cmd ]]` ran `cmd` under an allow (found by the fourth round's
    // second reading review). After two line breaks bash takes it for the keyword again and
    // refuses the text. Nobody writes `x | time y`: it asks.
    if (!this.cond && this.commandStart && piped && text === "time") ask("time straight after a |: bash runs a program called time there, not its keyword, and reads the words after it as that program's arguments");
    if (this.cond) {
      if (text === "]]") {
        this.tokens.push(this.cond);
        this.cond = undefined;
        this.commandStart = false;
      } else this.cond.items.push(word);
      return;
    }
    // `time -p [[ a || b ]]`: a conditional to bash, and to bash called `sh` a program `time`
    // given the word `[[`, then `||`, then a command (the fifth-pass review ran it).
    if (this.commandStart && !this.prefixed && text === "[[" && this.timeOption) ask("[[ after the -p or -- of time: bash reads a conditional there, and bash called sh the arguments of a program and whatever operators follow");
    if (this.commandStart && !this.prefixed && text === "[[") {
      this.cond = { type: "cond", items: [] };
      return;
    }
    // bash knows where a `case` pattern's `)` ends; this reader counts parentheses.
    if (this.commandStart && this.inner && text === "case") ask("a case statement inside a substitution");
    this.tokens.push(word);
    // `time [-p] [--]`: the two options are part of the keyword (see `headOf`).
    // After a redirect bash takes `-p` or `--` for the program, not for an option of `time`
    // (`time >o -p cmd` runs a program called -p), where the rules would judge `cmd`.
    // The same after an assignment (`time a=1 -p cmd`, `time >o a=1 -p cmd`): an assignment
    // word leaves the state as it is, so that the word after it is still held to this.
    if (this.commandStart && this.prefixed && this.timed > 0 && (text === "-p" || text === "--")) ask("-p or -- after time and a redirect or an assignment, which bash runs as a program");
    const option = this.commandStart && ((this.timed === 1 && text === "-p") || (this.timed > 0 && text === "--"));
    const assigning = this.commandStart && ASSIGNMENT.test(leading(word));
    if (!assigning || this.timed === 0) this.timed = this.commandStart && !this.prefixed && text === "time" ? 1 : option && text === "-p" ? 2 : 0;
    if (option) this.timeOption = true;
    if (assigning) this.prefixed = true;
    this.commandStart = this.commandStart && (option || (text !== undefined && KEEPS_COMMAND_START.has(text)) || ASSIGNMENT.test(leading(word)));
  }

  private noTarget() {
    if (!this.parts && this.wanting()) ask("a redirect with no target");
  }

  private op(op: string) {
    this.endWord();
    this.noTarget();
    if (this.cond) {
      if (op !== "&&" && op !== "||") ask("a parenthesis, a ;, a single | or &, or a line break inside [[ ]]");
      this.cond.items.push({ type: "op", op });
      return;
    }
    this.tokens.push({ type: "op", op });
    this.commandStart = true;
    this.timed = 0;
    this.timeOption = false;
    this.prefixed = false;
    this.piped = op === "|" || op === "|&";
  }

  // The tokens up to the end of the text, or (close) up to the `)` that ends the substitution
  // this reader was started in; `i` is then at that `)`.
  list(close: boolean): Token[] {
    for (;;) {
      this.join();
      if (this.i >= this.s.length) break;
      const c = this.s[this.i];
      // The word after `=~` in `[[ ]]` is a regular expression.
      if (this.cond && !this.parts && !this.regexWord && c !== " " && c !== "\t" && c !== "\n") {
        const before = this.cond.items.at(-1);
        if (before?.type === "word" && bare(before) === "=~" && this.regex()) continue;
      }
      if (c === "\\") {
        // A backslash quotes the character after it (a newline was dropped above).
        const quoted = this.s[this.i + 1];
        if (quoted === undefined) ask("a backslash at the end");
        this.lit(quoted!, true);
        this.i += 2;
      } else if (c === "'") {
        const end = this.s.indexOf("'", this.i + 1);
        if (end < 0) ask("an unterminated quote");
        this.lit(this.s.slice(this.i + 1, end), true);
        this.i = end + 1;
      } else if (c === '"') this.doubleQuoted();
      else if (c === "$") this.dollar(false);
      else if (c === "`") this.backticks(false);
      else if ((c === "<" || c === ">") && this.ahead(1) === "(") {
        const inner = new Lexer(this.src, this.depth + 1, true, this.i + 2);
        const tokens = inner.list(true);
        this.i = inner.i + 1;
        (this.parts ??= []).push({ kind: "proc", dir: c, tokens });
      } else if (c === "<" || c === ">" || (c === "&" && this.ahead(1) === ">")) this.redirect();
      else if (c === " " || c === "\t") {
        this.endWord();
        this.i++;
      } else if (c === "\n") {
        this.endWord();
        this.noTarget();
        if (this.cond) ask("a parenthesis, a ;, a single | or &, or a line break inside [[ ]]");
        if (this.pending.length) this.heredocBodies();
        this.tokens.push({ type: "op", op: "\n" });
        this.commandStart = true;
        this.timed = 0;
        this.timeOption = false;
        this.prefixed = false;
        this.i++;
      } else if (c === ";" || c === "&" || c === "|") {
        const two = c + (this.ahead(1) ?? "");
        if (two === "|&") ask("|&");
        if (two === ";&" || (two === ";;" && this.ahead(2) === "&")) ask("a case fall-through");
        const op = two === ";;" || two === "&&" || two === "||" ? two : c;
        this.op(op);
        this.i += op.length;
      } else if (c === "(") {
        const last = this.parts?.at(-1);
        if (last?.kind === "lit" && !last.quoted && /[@!+*?]$/.test(last.text)) ask("a ( straight after @, !, +, * or ? in a word, which bash reads as one pattern when extglob is on");
        if (this.parts && this.parts.length === 1 && last?.kind === "lit" && !last.quoted && /^[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=$/.test(last.text)) ask("an array assignment");
        if (this.ahead(1) === "(") {
          const before = this.tokens.at(-1);
          const loop = !this.parts && before?.type === "word" && bare(before) === "for";
          if (this.parts || this.cond || !(this.commandStart || loop)) ask("(( where no command begins");
          this.arithmeticCommand(loop);
        } else {
          this.op("(");
          this.parens++;
          this.i++;
        }
      } else if (c === ")") {
        if (close && this.parens === 0) {
          this.endWord();
          this.noTarget();
          if (this.cond) ask("a [[ with no ]]");
          if (this.pending.length) ask("a heredoc with no body");
          return this.tokens;
        }
        this.op(")");
        this.parens = Math.max(0, this.parens - 1);
        this.i++;
      } else if (c === "#" && !this.parts) {
        // A comment runs to the end of its line; a backslash at its end continues nothing.
        const end = this.s.indexOf("\n", this.i);
        if (end < 0 && close) ask("a comment that runs to the end of a substitution");
        this.i = end < 0 ? this.s.length : end;
      } else {
        if (c > "\x7f" && /\s/.test(c)) ask("a space that is not ASCII outside quotes");
        this.lit(c, false);
        this.i++;
      }
    }
    if (close) ask("an unterminated substitution");
    this.endWord();
    this.noTarget();
    if (this.cond) ask("a [[ with no ]]");
    if (this.pending.length) ask("a heredoc with no body");
    return this.tokens;
  }

  // The regular expression after `=~`. In it a quote makes a character literal and its absence
  // makes it an operator, so the printer may neither add quotes nor drop them. A word made only
  // of characters that mean the same to bash's lexer and to the rules' parser (with `\x` for a
  // literal character and a `$` at its very end) is kept exactly as written; returns false for
  // any other, which is then read like every word and printed with its quoting kept
  // (`regexWord`), and asks where that cannot be done.
  private regex(): boolean {
    const s = this.s;
    let j = this.i;
    while (j < s.length && !" \t\n".includes(s[j])) j++;
    const raw = s.slice(this.i, j);
    if (raw === "]]" || !/^(?:[A-Za-z0-9_^.*+?\[\]{},:=\/@%-]|\\[^\s])+\$?$/.test(raw)) {
      this.regexWord = true;
      return false;
    }
    this.parts = [{ kind: "raw", text: raw }];
    this.i = j;
    return true;
  }

  private doubleQuoted() {
    this.parts ??= [];
    const before = this.parts.length;
    const tail = this.parts.at(-1);
    const length = tail?.kind === "lit" ? tail.text.length : -1;
    this.i++;
    for (;;) {
      this.join();
      if (this.i >= this.s.length) ask("an unterminated quote");
      const d = this.s[this.i];
      if (d === '"') {
        // The quotes count even when nothing stands between them (`~""/x` is not expanded, and
        // `$x""` is a word when `$x` is empty).
        const last = this.parts.at(-1);
        if (this.parts.length === before && (last?.kind === "lit" ? last.text.length : -1) === length) this.lit("", true);
        break;
      }
      if (d === "\\") {
        const e = this.s[this.i + 1];
        if (e !== undefined && '$`"\\'.includes(e)) {
          this.lit(e, true);
          this.i += 2;
        } else {
          // bash keeps a backslash before any other character.
          this.lit("\\", true);
          this.i++;
        }
      } else if (d === "`") this.backticks(true);
      else if (d === "$") this.dollar(true);
      else {
        this.lit(d, true);
        this.i++;
      }
    }
    this.i++;
  }

  private backticks(quoted: boolean) {
    const end = this.s.indexOf("`", this.i + 1);
    if (end < 0) ask("an unterminated backtick");
    const body = this.s.slice(this.i + 1, end);
    if (body.includes("\\")) ask("a backslash inside backticks");
    const tokens = new Lexer(body, this.depth + 1, true, 0, this.src.shared).list(false);
    if (!plainCommands(tokens)) ask("backticks around more than plain commands (a parenthesis, a keyword, an operator with no command beside it): bash reads what they hold only when it runs it, and the same text in $( ) is read with the whole command");
    (this.parts ??= []).push({ kind: "sub", tokens, quoted });
    this.i = end + 1;
  }

  // From a `$`: an expansion, or the character itself where bash expands nothing.
  private dollar(quoted: boolean) {
    const next = this.ahead(1);
    if (next === "(" && this.ahead(2) === "(") {
      const end = this.arithmeticEnd(this.i + 3);
      (this.parts ??= []).push({ kind: "arith", text: this.s.slice(this.i, end + 2), quoted });
      this.i = end + 2;
    } else if (next === "(") {
      const docs = this.src.shared.docs;
      const inner = new Lexer(this.src, this.depth + 1, true, this.i + 2);
      const tokens = inner.list(true);
      this.i = inner.i + 1;
      // The operand of `${...}` is printed as it stands, and the rules' parser reads it with no
      // notion of a heredoc: a body there could close the braces or the quotes for one reader
      // and not the other (found by the round 4 cross-check: a folded body was printed raw).
      if (this.operand && this.src.shared.docs !== docs) ask("a heredoc inside ${...}");
      const folded = quoted && this.src.shared.fold ? fold(tokens) : undefined;
      if (folded !== undefined) this.lit(folded, true);
      else (this.parts ??= []).push({ kind: "sub", tokens, quoted });
    } else if (next === "{") this.param(quoted);
    else if (next === "'" || next === '"') {
      if (quoted) {
        // Inside double quotes `$"` and `$'` are a dollar and the quote character.
        this.lit("$", true);
        this.i++;
      } else ask("$'...' or $\"...\" quoting");
    } else if (next === "[") ask("the old $[...] arithmetic");
    else {
      const name = this.run(this.i + 1, /[A-Za-z_]/, /[A-Za-z0-9_]/) || (next !== undefined && /[@*#?$!0-9-]/.test(next) ? next : "");
      if (name === "") {
        // A `$` that expands nothing is printed in quotes, which in a regular expression would
        // turn the end-of-line anchor into a literal dollar.
        if (this.regexWord && !quoted) ask("a $ inside a regular expression after =~");
        this.lit("$", true);
        this.i++;
      } else {
        if (name.length > 256) ask("a very long variable name");
        (this.parts ??= []).push({ kind: "var", name, quoted });
        this.i += 1 + name.length;
      }
    }
  }

  // The index of the `))` that ends arithmetic which starts at `from`. A backslash, and so a
  // backslash-newline, is not arithmetic and asks.
  private arithmeticEnd(from: number, loop = false): number {
    const s = this.s;
    let open = 0;
    for (let j = from; j < s.length; j++) {
      if (s[j] === "(") open++;
      else if (s[j] === ")") {
        if (open > 0) open--;
        else if (s[j + 1] === ")") {
          const inside = s.slice(from, j);
          if (!ARITHMETIC.test(loop ? inside.replace(/;/g, "") : inside)) ask("arithmetic with quotes, a backslash, a line break or backticks in it");
          // The rules read a fixed word in place of arithmetic, so it may hold no command.
          if (/\$\((?!\()/.test(inside)) ask("a command substitution inside arithmetic");
          return j;
        } else ask("$(( that does not end in )): a substitution that starts with a subshell");
      }
    }
    return ask("unterminated arithmetic");
  }

  private arithmeticCommand(loop: boolean) {
    const end = this.arithmeticEnd(this.i + 2, loop);
    this.tokens.push({ type: "arith", text: this.s.slice(this.i + 2, end), loop });
    this.i = end + 2;
    this.commandStart = false;
    this.piped = false;
  }

  // `${...}` in the plain forms: a name or a special parameter, an optional subscript, and one
  // operator with an operand that holds no quotes and no backslash (so no backslash-newline).
  private param(quoted: boolean) {
    const s = this.s;
    let j = this.i + 2;
    let head = "";
    let bash = false;
    if (s[j] === "!") ask("an indirect ${!name} expansion");
    if (s[j] === "#" && s[j + 1] !== "}" && !/[-:=+?]/.test(s[j + 1] ?? "")) {
      head = "#";
      j++;
    }
    const name = NAME.exec(s.slice(j, j + 257))?.[0] ?? SPECIAL.exec(s.slice(j, j + 12))?.[0];
    if (name === undefined) ask("a ${...} form that is not printed");
    head += name;
    j += name!.length;
    if (s[j] === "[") {
      const closeAt = s.indexOf("]", j);
      const inside = closeAt < 0 ? "" : s.slice(j + 1, closeAt);
      if (closeAt < 0 || !/^(?:[@*]|-?\d+|\$?[A-Za-z_]\w*|\$\{[A-Za-z_]\w*\})$/.test(inside)) ask("an array subscript that is not a number, a plain variable, @ or *");
      head += s.slice(j, closeAt + 1);
      j = closeAt + 1;
      bash = true;
    }
    const done = (op: string, operand: Part[], end: number) => {
      (this.parts ??= []).push({ kind: "param", head, op, operand, quoted, bash });
      this.i = end + 1;
    };
    if (s[j] === "}") return done("", [], j);
    if (head.startsWith("#")) ask("a ${#...} form that is not printed");
    const m = /^(?::?[-=+?]|##?|%%?|\^\^?|,,?|\/[\/#%]?|:)/.exec(s.slice(j, j + 2));
    if (!m) ask(s[j] === "@" ? "a ${name@X} transformation" : "a ${...} form that is not printed");
    const op = m![0];
    j += op.length;
    if (op === ":") {
      // `${x:offset}` and `${x:offset:length}`.
      const closeAt = s.indexOf("}", j);
      const inside = closeAt < 0 ? "" : s.slice(j, closeAt);
      if (closeAt < 0 || !/^ ?-?[\w$]+(?:: ?-?[\w$]+)?$/.test(inside)) ask("a substring expansion whose offset is not a number or a plain variable");
      bash = true;
      return done(op, [{ kind: "lit", text: inside, quoted: true }], closeAt);
    }
    if (/^[\^,\/]/.test(op)) bash = true;
    // The operand: characters that mean the same to both readers, and nested expansions.
    const outer = this.parts;
    this.parts = [];
    this.i = j;
    if (++this.operand > MAX_OPERANDS) ask("deeply nested ${...}");
    for (;;) {
      if (this.i >= this.s.length) ask("an unterminated ${");
      const ch = this.s[this.i];
      if (ch === "}") break;
      if (ch === "$") this.dollar(quoted);
      else if (ch === "`") {
        // Backticks are read as the substitution they are, and printed as `$(...)`.
        const docs = this.src.shared.docs;
        this.backticks(quoted);
        if (this.src.shared.docs !== docs) ask("a heredoc inside ${...}");
      } else if (OPERAND.test(ch) || (quoted && (ch === " " || ch === "\t"))) {
        this.lit(ch, true);
        this.i++;
      } else if (ch === "\\" && this.s[this.i + 1] !== undefined && this.s[this.i + 1] !== "\n") {
        // A backslash and the character after it are kept as that pair (`${v//\//-}`): to bash
        // the second is then no `}` that closes, no `$` that expands and no quote, and it is
        // printed as it stands, so the scanner judges the very text.
        this.lit(ch + this.s[this.i + 1], true);
        this.i += 2;
      } else ask(ch === "'" || ch === '"' || ch === "\\" ? "quotes or a backslash-newline inside ${...}" : "a blank or a shell operator inside ${...}");
    }
    this.operand--;
    const operand = this.parts;
    this.parts = outer;
    done(op, operand, this.i);
  }

  private redirect() {
    // A descriptor straight before the operator: an unquoted number that is the whole word.
    let fd = "";
    const word = this.parts ? bare({ type: "word", parts: this.parts }) : undefined;
    if (word !== undefined && /^\d+$/.test(word)) {
      if (this.s[this.i] === "&") ask("a number straight before &>");
      // bash takes a number for a descriptor only when it fits an int; a longer one is a word
      // of the command (`git checkout 2147483648>/dev/null`), and the rules' parser drops it.
      if (word.length > 9) ask("a number too long for a descriptor straight before a redirect, which bash reads as an argument");
      fd = word;
      this.parts = undefined;
    } else if (this.parts && /^\{[A-Za-z_]\w*\}$/.test(literal({ type: "word", parts: this.parts }) ?? "")) ask("a {name} descriptor straight before a redirect");
    else if (this.parts && /^\d+$/.test(literal({ type: "word", parts: this.parts }) ?? "")) ask("a quoted number straight before a redirect");
    this.endWord();
    this.noTarget();
    if (this.cond) ask("a < or > inside [[ ]]");
    // The operator's characters are one token: the backslash-newlines among them are dropped.
    this.ahead(1);
    if (/^(<<|<&|<>|>>|>&|>\||&>)/.test(this.s.slice(this.i, this.i + 2))) this.ahead(2);
    const op = /^(<<<|<<-?|<&|<>|<|>>|>&|>\||>|&>>|&>)/.exec(this.s.slice(this.i, this.i + 3))![1];
    this.i += op.length;
    if (op === "<<" || op === "<<-") {
      this.run(this.i, /[ \t]/);
      this.i += this.run(this.i, /[ \t]/).length;
      this.join();
      const open = this.s[this.i];
      let delimiter: string;
      let quoted = false;
      if (open === "'" || open === '"') {
        const end = this.s.indexOf(open, this.i + 1);
        delimiter = end < 0 ? "" : this.s.slice(this.i + 1, end);
        quoted = true;
        this.i = end + 1;
      } else {
        delimiter = this.run(this.i, /[\w.-]/);
        this.i += delimiter.length;
      }
      this.join();
      const after = this.s[this.i];
      if (!/^[\w.-]+$/.test(delimiter) || !(after === undefined || " \t\n;|&)<>".includes(after)) || this.joinsProcess()) ask("a heredoc delimiter that is not one plain or fully quoted word");
      const doc: Heredoc = { type: "heredoc", fd, quoted, body: "" };
      this.src.shared.docs++;
      this.tokens.push(doc);
      this.prefixed = true;
      this.pending.push({ doc, delimiter, dash: op === "<<-" });
    } else if (op === ">&" || op === "<&") {
      const dup = this.run(this.i, /[\d-]/);
      this.i += dup.length;
      this.join();
      const after = this.s[this.i];
      if (!/^(\d+|-)$/.test(dup) || !(after === undefined || " \t\n;|&)<>".includes(after)) || this.joinsProcess()) ask("a redirect to a descriptor that is not a plain number");
      this.tokens.push({ type: "redir", fd, op, dup });
      this.prefixed = true;
    } else {
      if (op === "<>") ask("the <> redirect");
      this.join();
      if (this.s[this.i] === "!") ask("a redirect followed by !");
      // The target is the next word (endWord hands it over).
      this.tokens.push({ type: "redir", fd, op });
      this.prefixed = true;
    }
  }

  // From the newline that ends the line the heredocs were opened on: their bodies. With a quoted
  // delimiter the lines are taken as they are; without one bash joins a line that ends in a
  // backslash with the next before it looks for the delimiter (`EO\`, newline, `F` ends it).
  private heredocBodies() {
    for (const { doc, delimiter, dash } of this.pending.splice(0)) {
      let body = "";
      for (;;) {
        const s = this.s;
        if (this.i + 1 > s.length) ask("a heredoc with no terminator");
        let eol = s.indexOf("\n", this.i + 1);
        let raw = s.slice(this.i + 1, eol < 0 ? s.length : eol);
        while (!doc.quoted && eol >= 0 && /(?:^|[^\\])(?:\\\\)*\\$/.test(raw)) {
          const next = s.indexOf("\n", eol + 1);
          raw = raw.slice(0, -1) + s.slice(eol + 1, next < 0 ? s.length : next);
          eol = next;
          doc.joined = true;
        }
        const line = dash ? raw.replace(/^\t+/, "") : raw;
        if (line !== delimiter) {
          if (this.inner && line.startsWith(delimiter)) ask("inside a substitution, a heredoc line that starts with the delimiter and goes on, where bash ends the heredoc and runs the rest of the line");
          if (raw.trim() === delimiter) ask("a heredoc terminator with whitespace around it");
          if (eol < 0) ask("a heredoc with no terminator");
        }
        this.i = eol < 0 ? s.length - 1 : eol;
        if (line === delimiter) break;
        body += line + "\n";
      }
      if (doc.quoted) doc.body = body;
      else doc.parts = new Lexer(body, this.depth + 1, true, 0, this.src.shared).heredocParts();
    }
  }

  // What bash expands in a heredoc body whose delimiter is not quoted (its lines already joined).
  private heredocParts(): Part[] {
    this.parts = [];
    while (this.i < this.s.length) {
      const c = this.s[this.i];
      if (c === "\\" && "$`\\".includes(this.s[this.i + 1] ?? "\0")) {
        this.lit(this.s[this.i + 1], true);
        this.i += 2;
      } else if (c === "\\") {
        // Any other backslash is a character of the body.
        this.lit(c, true);
        this.i++;
      } else if (c === "`") this.backticks(true);
      else if (c === "$") this.dollar(true);
      else {
        this.lit(c, true);
        this.i++;
      }
    }
    return this.parts;
  }
}

// `"$(cat <<'X'⏎...⏎X⏎)"`, also `<<"X"`, and `<<X` when bash expands nothing in the body: the
// literal it stands for, which is the body without its trailing newlines.
function fold(tokens: Token[]): string | undefined {
  const [first, doc, ...rest] = tokens.filter((t) => !(t.type === "op" && t.op === "\n"));
  if (rest.length || first?.type !== "word" || bare(first) !== "cat" || doc?.type !== "heredoc" || doc.fd !== "") return undefined;
  if (doc.quoted) return doc.body.replace(/\n+$/, "");
  if (!doc.parts!.every((p) => p.kind === "lit")) return undefined;
  return doc.parts!.map((p) => (p as { text: string }).text).join("").replace(/\n+$/, "");
}

// ---- the printer ----

// Literal text: bare when every character between parentheses and single quotes is plain, one
// single-quoted string otherwise; parentheses and single quotes backslashed outside quotes.
// `always`: in single quotes even when plain. A word that also holds a character bash acts on
// needs that: `~'/x'` is not `~/x` (bash expands the second), and `[a'-'z]` is not `[a-z]`.
function quote(text: string, always = false): string {
  // Empty quotes are a word of their own, and beside other text they still count: `''~/x` and
  // `~""/x` are not expanded, and `$x""` is a word when `$x` is empty.
  if (text === "") return "''";
  let out = "";
  let run = "";
  const flush = () => {
    if (run) out += !always && [...run].every((ch) => PLAIN.test(ch)) ? run : `'${run}'`;
    run = "";
  };
  for (const ch of text) {
    if (ch === "(" || ch === ")" || ch === "'") {
      flush();
      out += `\\${ch}`;
    } else run += ch;
  }
  flush();
  return out;
}

// Whether the rules' parser, counting parentheses through a substitution's text (rules.ts
// `matchParen`: a backslash skips a character, quotes and heredocs mean nothing to it), comes out
// of this text where it went in: every `)` closes a `(` of the text, and none is left open.
function balanced(text: string): boolean {
  let depth = 0;
  for (let i = 0; i < text.length; i++) {
    if (text[i] === "\\") i++;
    else if (text[i] === "(") depth++;
    else if (text[i] === ")" && --depth < 0) return false;
  }
  return depth === 0;
}

// A substitution around its printed body. A body that begins with a subshell is set off by a
// blank: `$(` straight before `(` would be `$((`, arithmetic (found by the round 4 cross-check:
// `$( (ls) )` was printed as `$(( ls ))`).
const enclose = (open: string, inner: string) => `${open}${inner.startsWith("(") ? " " : ""}${inner}${inner.endsWith(")") ? " " : ""})`;

// Both texts at once: what runs and what is judged.
interface Two {
  run: string;
  judged: string;
}
const same = (text: string): Two => ({ run: text, judged: text });
const join = (list: Two[], separator: string): Two => ({ run: list.map((t) => t.run).join(separator), judged: list.map((t) => t.judged).join(separator) });

// Characters that stand for a quoted character while the guard's brace expander runs.
const PRIVATE = 0xe000;
// How much text the braces of the command being printed have made so far (see `braces`).
// `canonical` is not re-entered, so one counter serves it and the nested commands it prints.
let braceText = 0;

// ---- variables that plainly hold a literal (round 4, finding 27, signed off) ----
//
// `name=foo; grep -rn "$name" src`, `a=one; b=uno; sed -i "s/$a/$b/" g`: the rules and the
// guards read a word with an expansion as a value nobody has seen (a file named at run time, a
// word that may turn into `--pre=cmd`, a sed script that may hold `e` or `w`), and rightly so.
// Here the call itself shows the value. So in the judged text, and only there, a quoted `$name`
// in an argument word is the literal the call gave it, and the rules judge the command as if it
// had been written out. What runs is not touched.
//
// Narrow on purpose. A variable counts only when all of this holds:
//   - it is assigned in the commands the call begins with: each one word `name=value` and
//     nothing else, followed by `;`, a newline or `&&`. Those run first and cannot fail, so
//     everything after them sees the value;
//   - the name is plain lower case (no variable bash sets, reads or keeps read-only is), the
//     value is letters, digits and `_ . , / -`, and begins with none of the last four;
//   - the call names the variable nowhere else, in any spelling, but as `$name` or `${name}`
//     (tested on the printed text: a second assignment, `read name`, `for name`, `unset name`,
//     `${name:=x}`, the same letters as a file's name all count as naming it);
//   - nothing in the call can set a variable whose name is not spelled out: none of the
//     builtins in SETS_BY_NAME, no arithmetic, no indirect expansion, no `.` file, and no
//     function is defined (a function runs when it is called, not where it is written).
//     Second pass: the `.` file is told from the commands the printer itself prints, not from
//     a pattern over the text (which missed `time -p . f`, `a=1 . f` and a `.` behind a case
//     pattern): any command whose name word is `.` or `source`, wherever it stands, and any
//     whose name is not written out (an expansion, or a glob, which a file called `source` or
//     `eval` in the directory turns into that builtin) is one that may set a variable unseen
//     (`Printer.unspelled`). And no literal is read at all when the plugin's environment holds
//     a function for bash to import (`BASH_FUNC_name%%`): `ls` may then be a function that
//     sets the variable (`x=src/; ls; cat "$x"etc/shadow`).
// Only a `$name` inside double quotes is read so, and only in a word after the command's name:
// not the name word itself (bash runs an expansion's value as a command, never as a keyword or
// an assignment), not an assignment, a redirect's target, a `case` word or pattern, `[[ ]]`, a
// heredoc, or the code handed to a nested shell (which does not see the variable).
const CONSTANT = /^([a-z][a-z0-9_]*)=([A-Za-z0-9_][A-Za-z0-9_.,\/-]*)$/;
const UNSPELLED_SETTER = /\(\(|\$\[|\$\{!/;
const importsFunctions = () => Object.keys(process.env).some((name) => name.startsWith("BASH_FUNC_"));
// `unspelled`: the printer saw a command that reads a file as shell code, or one whose name is
// not written out.
function constantsOf(tokens: Token[], text: string, unspelled: boolean): Map<string, string> {
  const found = new Map<string, string>();
  let n = 0;
  for (;;) {
    while (tokens[n]?.type === "op" && (tokens[n] as Op).op === "\n") n++;
    const w = tokens[n];
    const op = tokens[n + 1];
    if (w?.type !== "word" || op?.type !== "op" || ![";", "\n", "&&"].includes(op.op)) break;
    const whole = fixed(w);
    const m = whole === undefined ? null : CONSTANT.exec(whole);
    if (!m || !leading(w).startsWith(`${m[1]}=`)) break;
    found.set(m[1], m[2]);
    n += 2;
  }
  if (!found.size) return found;
  if (unspelled || importsFunctions()) return new Map();
  if (SETS_BY_NAME.test(text) || UNSPELLED_SETTER.test(text)) return new Map();
  for (const name of [...found.keys()]) {
    let assigned = 0;
    let ok = name !== "histchars" && name !== "auto_resume";
    for (const m of text.matchAll(new RegExp(`(?<![A-Za-z0-9_])${name}(?![A-Za-z0-9_])`, "g"))) {
      const at = m.index!;
      const after = text.slice(at + name.length, at + name.length + 2);
      if (text[at - 1] === "$" || (text.slice(at - 2, at) === "${" && after[0] === "}")) continue;
      if (after[0] === "=") assigned++;
      else ok = false;
    }
    if (!ok || assigned !== 1) found.delete(name);
  }
  return found;
}

class Printer {
  bashOnly = false;
  // Pass 6j: a command of the text moves the shell (`cd`, `pushd`, `popd`), and a descriptor
  // copy `<&N` that is left out of the judged text stands on the closer of a group, a loop, a
  // branch, a `case`, a subshell or a function's body (a command that is that closer, or has no
  // word of its own).
  moves = false;
  dupOnCompound = false;
  // See Printed.inputs and Printed.judgedInputs.
  inputs: string[] = [];
  judgedInputs: string[] = [];
  // Variables that plainly hold a literal, by name (see constantsOf): read as that literal in
  // the judged text.
  constants: Map<string, string> | undefined;
  // A command of the text reads a file as shell code (`.`, `source`), or its name is not written
  // out: it may set a variable whose name the text does not spell (see constantsOf).
  unspelled = false;
  private source: string;
  private depth: number;
  private count = 0;
  // The bodies of the heredocs opened on the line being printed, to follow its newline.
  private docs: (Two & { parens: boolean })[] = [];
  private caseOpen = 0;
  // The command defines a function (see `print`): no word is taken for what its name usually
  // means, so no message gets a placeholder and no nested code is printed as code.
  private plain: boolean;

  constructor(source: string, depth: number, plain: boolean) {
    this.source = source;
    this.depth = depth;
    this.plain = plain;
  }

  // `$name`, or `${name}` where the text that follows would read as more of the name. A special
  // parameter is one character and is printed as written (`$!`, `$?`, `$1`): the scanner takes
  // `${!` for an indirect expansion, and the commands agents write hold `wait $!`.
  private variable(name: string, follows: Part | undefined): string {
    const next = follows?.kind === "lit" ? follows.text : "";
    if (!/^[A-Za-z_]/.test(name)) return /^\d$/.test(name) && /^\d/.test(next) ? `\${${name}}` : `$${name}`;
    return /^[A-Za-z0-9_]/.test(next) ? `\${${name}}` : `$${name}`;
  }

  // `${name<op>operand}` and `$((...))`, without the quotes around them. dash has no `${x^^}`,
  // `${x/a/b}`, `${a[0]}` or `${x:1}`, and its arithmetic has no `**`, `++`, `--`, comma, base
  // (`16#ff`: a `#` after a digit; `$#` is the number of arguments everywhere) or subscript.
  private param(p: Extract<Part, { kind: "param" }>): Two {
    if (p.bash) this.bashOnly = true;
    const operand = this.operand(p.operand);
    // An operand that becomes the word's text (`${u:-.*}`, also `-`, `=`, `+` and their colon
    // forms) is expanded as a file pattern when the expansion is not quoted. The operand of
    // `%`, `#` or `/` is a pattern for the value, not for file names.
    if (!p.quoted && /^:?[-=+]$/.test(p.op)) this.dots(p.operand.map((o) => (o.kind === "lit" ? o.text : "\u0001")).join(""));
    return { run: `\${${p.head}${p.op}${operand.run}}`, judged: `\${${p.head}${p.op}${operand.judged}}` };
  }
  private arith(p: Extract<Part, { kind: "arith" }>): Two {
    if (/\*\*|\+\+|--|,|\d#|\[/.test(p.text)) this.bashOnly = true;
    return { run: p.text, judged: "0" };
  }
  private sub(p: Extract<Part, { kind: "sub" }>): Two {
    // `$(< file)` is bash's way to read a file; dash runs an empty command and gives nothing.
    if (p.tokens.some((t) => t.type === "redir") && !p.tokens.some((t) => t.type === "word" || t.type === "cond" || t.type === "arith")) this.bashOnly = true;
    const inner = this.nested(p.tokens);
    return { run: enclose("$(", inner.run), judged: enclose("$(", inner.judged) };
  }

  private delimiter(body: string): string {
    for (;;) {
      const d = `AUTOMODE_EOF_${++this.count}`;
      if (!body.includes(d) && !this.source.includes(d)) return d;
    }
  }

  // The words bash makes of a word's braces. `fixed`: a place where bash expands none (an
  // assignment, a redirect's target, inside [[ ]], the word or a pattern of a case statement), so
  // one that would expand elsewhere asks.
  private braces(w: Word, fixed: boolean): Word[] {
    if (!w.parts.some((p) => p.kind === "lit" && !p.quoted && p.text.includes("{"))) return [w];
    // Each quoted character and each expansion becomes one private character, so the expander
    // sees only the braces, commas and dots bash would act on.
    const table: Part[] = [];
    let encoded = "";
    // The expander is handed private-use characters in place of what was quoted: one written
    // in the word itself would be taken for one of those.
    if (w.parts.some((p) => p.kind === "lit" && /[\ue000-\uf8ff]/.test(p.text))) ask("a private-use character in a word with braces");
    for (const p of w.parts) {
      if (p.kind === "lit" && !p.quoted) encoded += p.text;
      // Empty quotes too: `''{,}` is two empty words, where `{,}` is none.
      else if (p.kind === "lit" && p.text === "") encoded += String.fromCharCode(PRIVATE + table.push({ kind: "lit", text: "", quoted: true }) - 1);
      else if (p.kind === "lit") for (const ch of p.text) encoded += String.fromCharCode(PRIVATE + table.push({ kind: "lit", text: ch, quoted: true }) - 1);
      else encoded += String.fromCharCode(PRIVATE + table.push(p) - 1);
      if (table.length > 6000) ask("a word too long to expand its braces");
    }
    const words = braceWords(encoded);
    if (!words) ask("a brace expansion too large or too unusual to list the words it makes");
    if (words!.length === 1 && words![0] === encoded) return [w];
    if (fixed) ask("braces where bash expands none, or reads the word before it expands them (an assignment, a redirect, [[ ]], the word or a pattern of a case statement, the word that names the command, the name of a function or of a loop's variable)");
    if (w.parts.some((p) => p.kind !== "lit")) ask("a word with both an expansion and a brace expansion, which bash expands braces-first");
    // A `$` that expands nothing as written can become an expansion once the braces are gone:
    // `{$,a}x` is `$x ax` to bash, which then expands `$x` (found by the variant check). The
    // reader keeps such a `$` as quoted text, so a `$` written in quotes asks here as well.
    if (w.parts.some((p) => p.kind === "lit" && p.text.includes("$"))) ask("a $ in a word with braces: bash expands the braces first and then reads the $ with what follows it");
    // One budget for everything the braces of a command make, counted before any of it is built
    // (a word of 4,000 characters times `{1..2000}` is 8 MB; two dozen of them ran the process
    // out of memory).
    braceText += words!.reduce((n, text) => n + text.length + 1, 0);
    if (braceText > MAX_TEXT) ask("a brace expansion that makes more text than a command may hold");
    this.bashOnly = true;
    const out: Word[] = [];
    for (const text of words!) {
      const word: Word = { type: "word", parts: [] };
      const push = (part: Part) => {
        const last = word.parts.at(-1);
        if (part.kind === "lit" && last?.kind === "lit" && last.quoted === part.quoted) last.text += part.text;
        else word.parts.push(part.kind === "lit" ? { ...part } : part);
      };
      [...text].forEach((ch, at) => {
        const code = ch.charCodeAt(0);
        if (code >= PRIVATE && code < PRIVATE + table.length) push(table[code - PRIVATE]);
        // A made word is a plain argument to bash (see `command`): it expands a `~` that begins
        // the word and no other, where in a word written out it would also expand one after
        // `=` or `:` (`echo {x,y}=~/z` prints the tilde). So any other `~` is printed quoted.
        else push({ kind: "lit", text: ch, quoted: ch === "~" && at > 0 });
      });
      // bash drops a word that comes out empty, unless something in it was quoted.
      if (word.parts.length) out.push(word);
    }
    return out;
  }

  // dash, and bash before 5.2, match `.` and `..` with a pattern that begins with a dot and can
  // be one or two dots long (`.?`, `.*`, `.[.]`): `chmod -R 700 .?` then reaches the directory
  // above. bash 5.2 never matches them. `shape`: the text with each expansion as U+0001 and what
  // was quoted (and is not a dot or a slash) as U+0002. Each path segment is held to this from
  // its leading dot and from each expansion in it (the value may be empty, a dot, or end in
  // `/.`: `ls $e.*`, `ls $d*`, `ls x$e*`): what follows, up to the next slash, is a pattern, and
  // without its stars and expansions nothing, a dot or a `?` is left, or it holds a bracket at
  // all. Brackets are not read: two rounds of reading them each missed a form
  // (`.[[:punct:]]` matches `..`), so `.[!.]*` and `.[a-z]*rc` are marked too.
  private dots(shape: string) {
    const reach = (tail: string) => /[*?[]/.test(tail) && (tail.includes("[") || /^(?:|\.|\?)$/.test(tail.replace(/[*\u0001]/g, "")));
    // A value may hold a slash, begin with one or end in one, be empty, or be or end in a dot:
    // so a segment of the pattern bash builds can begin at the written segment's start or
    // straight after any expansion, and end at the written segment's end or straight before
    // any expansion (`.?${e}repo` with e=/ is `.?` and `repo`). Each such piece is held to the
    // rule: from its own leading dot, or, after an expansion, also from a dot the value ends
    // in.
    const dotted = (segment: string) => {
      const at = [...segment.matchAll(/\u0001/g)].map((m) => m.index);
      // The pieces are the pairs of expansions: a segment with more expansions than this is
      // not read piece by piece (ten thousand of them took a quarter of a minute), and counts
      // as such a pattern when it holds a glob character at all.
      if (at.length > 32) return /[*?[]/.test(segment);
      for (const from of [0, ...at.map((i) => i + 1)]) {
        for (const to of [segment.length, ...at.filter((i) => i >= from)]) {
          const piece = segment.slice(from, to);
          if (piece.startsWith(".") && reach(piece.slice(1))) return true;
          if (from > 0 && reach(piece)) return true;
        }
      }
      return false;
    };
    if (shape.split("/").some(dotted)) this.bashOnly = true;
  }

  // `quoted`: what was quoted stays in quotes (the regular expression after `=~`).
  // `assigns`: the word stands where bash takes `NAME=value` for an assignment: before a
  // command's name ("word"), or as an argument of a builtin that declares variables
  // ("argument": the builtin reads the assignment when it runs, quotes or not).
  // `literal`: the word stands after a command's name, where a variable that plainly holds a
  // literal is judged as that literal (see constantsOf).
  private parts(parts: Part[], quoted = false, assigns: false | "word" | "argument" = false, literal = false): Two {
    // A quoted or escaped character inside a bracket of a glob is a plain member to bash
    // (`.g['!'i]t`, `.g[i\]]t` and `.g[\^i]t` are `.git`), and the word without its quotes, which
    // is all the guard and the rules read, cannot show it: the same text unquoted (`.g[!i]t`) is
    // a negated bracket (round 4, finding 6, second pass). So such a word asks: an unquoted `[`,
    // then quoted text, then a `]`, quoted or not.
    //
    // The bracket ends where bash ends it (third pass, E2: `echo [1]"a]"` asked): at the first
    // unquoted `]` that is not its first member (right after `[`, or after an unquoted `!` or `^`
    // there) and not the end of a `[:class:]`, `[=x=]` or `[.x.]` inside it; quoted text after
    // that is no member of it, and a later unquoted `[` opens another. A `[:`, `[=` or `[.` is read
    // to its unquoted `:]`, `=]` or `.]`, or to the end of the word when it has none (bash would
    // then take the `[` as a member and might close sooner: the bracket is held open, which asks
    // more, never less).
    //
    // An expansion where the first member would stand may be empty (B3b, third pass, second go:
    // `echo [$x]\a]` with x empty is `[]\a]`, a bracket of `]` and a quoted `a`), or hold `!` or
    // `^`: the character after it may then be the first member, and a `!` or `^` there the
    // negation. Holding the bracket open is not always the stricter reading (`[$x][:a'b']` asks
    // only where the bracket closes after `$x`), so every reading is followed: a set of states,
    // one per way the expansions so far may have gone, and the word asks when any of them does.
    //
    // That is all this check reads of an expansion, and it is not all bash makes of one: a value
    // elsewhere in the word can close a bracket or open one (`[a$x[:a'-'z]` with x=`]` is
    // `[a][:a'-'z]`, two brackets, the second with a quoted `-`), and a quoted expansion is a
    // quoted member (`p[a"$x"]` with x=`]` matches `p]`) (B3c, third go: both are printed with
    // no ask). The check is here because the guards match a word against the files it names as a
    // literal pattern, which they read without its quotes; and they never do so for a word with
    // an expansion in it: such a word is a name known at run time to them (runtimeReads), which
    // goes to the model when a program reads it, however its brackets read.
    if (!quoted) {
      const chars = parts.flatMap((p) => (p.kind === "lit" ? [...p.text].map((ch) => ({ ch, q: p.quoted })) : [{ ch: "", q: false }]));
      const unquoted = (k: number, set: string) => !!chars[k] && !chars[k].q && chars[k].ch !== "" && set.includes(chars[k].ch);
      const member = "a quoted or escaped character inside a bracket of a glob, which bash reads as a plain member";
      // `first`: where the first member stands; `negated`: a `!` or `^` was read where it stood;
      // `sub`: the end of a `[:...:]` being read; `skip`: characters before it are read already.
      interface Bracket {
        open: boolean;
        inside: boolean;
        first: number;
        negated: boolean;
        sub?: string;
        skip: number;
      }
      let states: Bracket[] = [{ open: false, inside: false, first: -1, negated: false, skip: 0 }];
      for (let k = 0; k < chars.length; k++) {
        const { ch, q } = chars[k];
        const next: Bracket[] = [];
        for (const s of states) {
          if (k < s.skip) next.push(s);
          else if (ch === "") {
            next.push(s);
            if (s.open && !s.sub && k === s.first) next.push({ ...s, first: k + 1 });
          } else if (!s.open) next.push(!q && ch === "[" ? { open: true, inside: false, first: k + 1, negated: false, skip: 0 } : s);
          else if (q) {
            if (ch === "]") ask(member);
            next.push({ ...s, inside: true });
          } else if (s.sub) next.push(ch === s.sub && unquoted(k + 1, "]") ? { ...s, sub: undefined, skip: k + 2 } : s);
          else if (k === s.first && !s.negated && (ch === "!" || ch === "^")) next.push({ ...s, first: k + 1, negated: true });
          else if (ch === "[" && unquoted(k + 1, ":=.")) next.push({ ...s, sub: chars[k + 1].ch, skip: k + 2 });
          else if (ch === "]" && k !== s.first) {
            if (s.inside) ask(member);
            next.push({ ...s, open: false });
          } else next.push(s);
        }
        // Positions already passed no longer tell states apart.
        const seen = new Set<string>();
        states = next.filter((s) => {
          const key = `${s.open}|${s.inside}|${s.first > k ? s.first : -1}|${s.negated}|${s.sub ?? ""}|${s.skip > k ? s.skip : 0}`;
          return !seen.has(key) && !!seen.add(key);
        });
      }
    }
    const out: Two = { run: "", judged: "" };
    const add = (t: Two | string) => {
      out.run += typeof t === "string" ? t : t.run;
      out.judged += typeof t === "string" ? t : t.judged;
    };
    // Where quotes change what bash makes of the word, what was quoted stays in quotes even when
    // it is plain text: beside an unquoted character bash acts on (a glob, a tilde: `~'/x'`,
    // `[a'-'z]`); where the bare text would read as `NAME=value` and the name was quoted (to
    // `declare` and its like `"a"=$x` is no assignment, so `$x` is split); and where the bare
    // text would be a reserved word (`"do"`, `'}'`).
    const whole = parts.map((p) => (p.kind === "lit" ? p.text : "\u0000")).join("");
    const lead = parts[0]?.kind === "lit" && !parts[0].quoted ? parts[0].text : "";
    const always =
      quoted ||
      parts.some((p) => p.kind === "lit" && !p.quoted && [...p.text].some((ch) => ACTIVE.includes(ch))) ||
      (ASSIGNMENT.test(whole) && !ASSIGNMENT.test(lead)) ||
      RESERVED.has(whole);
    // The dot rule (see `dots`): for the word as bash expands it, and for a value the word
    // assigns, which a later unquoted `$name` expands as a pattern whether or not the value was
    // quoted here (`p=".?"; chmod -R 700 $p`). An operand that can become the word's text
    // (`${x:-*}`) is read both ways, as a value nobody knows and as its own text: `.${x:-*}` is
    // `.*` when x is unset. The rule does not follow a value: a pattern that reaches a variable
    // some other way (`read`, a loop, the environment), or a glob in a value that meets its dot
    // only where the variable is used (`p='*'; ls .$p`), is not marked.
    // Every reading is taken: each such operand, at any depth, as a value nobody knows or as
    // its own text, in every combination (`.${x:-${y:-*}}` is `.*` with both unset; in
    // `.${x:-*${y+c}}` the inner one may give nothing; in `.${x:-${y:-*}${z+c}}` one inner
    // operand gives the star and the other nothing). Three rounds of picking readings each
    // missed a combination, so none is picked. A word with more readings than `READINGS` is
    // not read: it is marked when it holds a glob character at all.
    // `raw`: quoted text and quoted operands count as written (an assigned value).
    const READINGS = 64;
    const valued = (q: Part): q is Extract<Part, { kind: "param" }> => q.kind === "param" && /^:?[-=+]$/.test(q.op);
    const readings = (list: Part[], raw: boolean, top: boolean): string[] | undefined => {
      let out = [""];
      for (const q of list) {
        let texts: string[];
        if (q.kind === "lit") {
          // In an operand a backslashed dot or slash is that character.
          texts = [top ? (q.quoted && !raw ? q.text.replace(/[^./]/g, "\u0002") : q.text) : q.text.replace(/\\(.)/g, (_m, c: string) => (c === "." || c === "/" ? c : "\u0002"))];
        } else if (valued(q) && (!top || raw || !q.quoted)) {
          const inner = readings(q.operand, raw, false);
          if (!inner) return undefined;
          texts = ["\u0001", ...inner];
        } else texts = ["\u0001"];
        // The cap is held before the texts are built: a long word times thousands of readings
        // took minutes to put in a set.
        if (out.length * texts.length > READINGS) return undefined;
        out = [...new Set(out.flatMap((head) => texts.map((t) => head + t)))];
      }
      return out;
    };
    const written = (list: Part[]): string => list.map((q) => (q.kind === "lit" ? q.text : q.kind === "param" ? written(q.operand) : "")).join("");
    const shapes = (raw: boolean): string[] => {
      const all = readings(parts, raw, true);
      if (all) return all;
      if (/[*?[]/.test(written(parts))) this.bashOnly = true;
      return [];
    };
    for (const shape of shapes(false)) if (/[*?[]/.test(shape)) this.dots(shape);
    // An assigned value: a later unquoted `$name` splits it at blanks before it expands each
    // field as a pattern (`p="-d .?"; ls $p`). An argument of a declaring builtin is an
    // assignment whether or not it is written with quotes (`readonly "p=.*"`).
    const assignment = assigns === "word" ? ASSIGNMENT.test(lead) : assigns === "argument" ? ASSIGNMENT.test(whole.replaceAll("\u0000", "x")) : false;
    if (assignment) for (const shape of shapes(true)) for (const field of shape.replace(/^[^=]*=/, "").split(/[ \t\n]+/)) this.dots(field);
    // A word that begins with `~`: the prefix runs to the first slash. A quote in it stops bash
    // from expanding it, and the printer quotes whatever is neither plain nor a character bash
    // acts on (`~root:#` would be printed `~root:'#'`, `~root:$x,#` as `~root:$x,'#'`), so such a
    // character anywhere before the first slash asks. bash also ends the prefix at a `:` and
    // expands, and reads `~0` as a directory of its stack; dash does neither.
    if (lead.startsWith("~")) {
      let prefix = "";
      let pure = true;
      for (const p of parts) {
        if (p.kind !== "lit" || p.quoted) {
          pure = false;
          continue;
        }
        const cut = p.text.indexOf("/");
        const piece = cut < 0 ? p.text : p.text.slice(0, cut);
        if ([...piece].some((ch) => !PLAIN.test(ch) && !ACTIVE.includes(ch))) ask("a ~ word with a character the printer would have to quote, which would stop bash from expanding the ~");
        prefix += piece;
        if (cut >= 0) break;
      }
      if (!pure || !/^~(?:[A-Za-z_][A-Za-z0-9._-]*)?$/.test(prefix)) this.bashOnly = true;
    }
    // Empty quotes inside a word that is literal text all through, and not empty without them,
    // change nothing (`g''it` is `git`), unless the word is one of the kinds above.
    const droppable = !always && parts.every((p) => p.kind === "lit") && parts.some((p) => p.kind === "lit" && p.text !== "");
    parts.forEach((p, n) => {
      if (p.kind === "lit") {
        if (p.quoted && p.text === "" && droppable) return;
        if (p.quoted) add(quote(p.text, always));
        else if (parts.length === 1 && (p.text === "{" || p.text === "}")) add(p.text);
        else {
          // Unquoted text: what bash acts on stays bare, the rest is literal.
          let text = "";
          const flush = () => {
            if (text) add(quote(text));
            text = "";
          };
          for (const ch of p.text) {
            if (PLAIN.test(ch) || ACTIVE.includes(ch)) {
              flush();
              add(ch);
            } else text += ch;
          }
          flush();
          // dash reads these another way than bash: `[^a]` (no negation), `~+` and `~-`, and a
          // `~` after `=` or `:` in a word that is no assignment.
          if (/\[\^/.test(p.text) || (n === 0 && /^~[+-]/.test(p.text)) || /[=:]~/.test(p.text)) this.bashOnly = true;
        }
      } else if (p.kind === "var") {
        // Text that would read as more of the name, quoted or not (quoted plain text is printed bare).
        const text = this.variable(p.name, parts[n + 1]);
        const constant = literal && p.quoted ? this.constants?.get(p.name) : undefined;
        if (constant !== undefined) add({ run: `"${text}"`, judged: quote(constant, always) });
        else add(p.quoted ? `"${text}"` : text);
      } else if (p.kind === "param" || p.kind === "arith" || p.kind === "sub") {
        const inner = p.kind === "param" ? this.param(p) : p.kind === "arith" ? this.arith(p) : this.sub(p);
        // `"${name}"` with nothing after the name is `"$name"`.
        const constant = literal && p.quoted && p.kind === "param" && p.op === "" && !p.operand.length ? this.constants?.get(p.head) : undefined;
        if (constant !== undefined) add({ run: `"${inner.run}"`, judged: quote(constant, always) });
        else add(p.quoted ? { run: `"${inner.run}"`, judged: p.kind === "arith" ? "0" : `"${inner.judged}"` } : inner);
      } else if (p.kind === "proc") {
        this.bashOnly = true;
        const inner = this.nested(p.tokens);
        add({ run: enclose(`${p.dir}(`, inner.run), judged: enclose(`${p.dir}(`, inner.judged) });
      } else if (p.kind === "message") add({ run: this.parts(p.parts).run, judged: p.attached ? "--message=message" : "message" });
      else if (p.kind === "raw") add(p.text);
      else add({ run: quote(p.text), judged: quote(p.judged) });
    });
    return out.run === "" ? same("''") : out;
  }

  // Inside `${name<op>...}`: no quotes are added; the expansion's own quoting holds.
  private operand(parts: Part[]): Two {
    return join(
      parts.map((p, n): Two => {
        // Printed as it stands, so only what the reader took one character at a time.
        if (p.kind === "lit") return OPERAND_TEXT.test(p.text) ? same(p.text) : ask("text inside ${...} that is not printed as it stands");
        if (p.kind === "var") return same(/^[A-Za-z_]/.test(p.name) ? `\${${p.name}}` : this.variable(p.name, parts[n + 1]));
        if (p.kind === "param") return this.param(p);
        if (p.kind === "arith") return this.arith(p);
        if (p.kind === "sub") return this.sub(p);
        return ask("an expansion inside ${...} that is not printed");
      }),
      "",
    );
  }

  private nested(tokens: Token[]): Two {
    const outer = { docs: this.docs, caseOpen: this.caseOpen };
    this.docs = [];
    this.caseOpen = 0;
    const out = this.list(tokens, true);
    this.docs = outer.docs;
    this.caseOpen = outer.caseOpen;
    return out;
  }

  // One simple command: its words, redirections and heredocs, in the order written. `by`: the
  // operator that ended it.
  private command(items: (Word | Redir | Heredoc)[], by?: string): Two {
    const words = items.filter((t): t is Word => t.type === "word");
    // Where the command's own words begin: after keywords, then after assignments.
    let k = headOf(words);
    const keywords = new Set(words.slice(0, k));
    const assigns = new Set<Word>();
    while (k < words.length && ASSIGNMENT.test(leading(words[k]))) assigns.add(words[k++]);
    // `NAME+=value` and `NAME[n]=value` are assignments to bash; dash runs a command of that name.
    for (const w of assigns) if (/^[A-Za-z_]\w*(?:\[|\+=)/.test(leading(w))) this.bashOnly = true;
    const name = words[k];
    let caseHead = false;
    if (name) {
      // Where a command begins bash takes `NAME=` and its reserved words only as written, and
      // the rules read the text without its quotes.
      const text = name.parts.map((p) => (p.kind === "lit" ? p.text : "\u0000")).join("");
      const quoted = name.parts.some((p) => p.kind === "lit" && p.quoted);
      // bash takes the arguments of `export` and its like for assignments only when the name
      // is written plainly: `"export" p=$x` splits and globs `$x`, and printed without its
      // quotes it would not.
      // The same behind `command` (bash as sh looks through it for the declaring builtin, and
      // only through one written plainly: `"command" export p=$x` splits too). Nothing looks
      // through `builtin`.
      let behind = k;
      let spelled = false;
      while (literal(words[behind]) === "command" && behind + 1 < words.length) {
        if (bare(words[behind]) === undefined) spelled = true;
        behind++;
      }
      const declaring = behind > k && DECLARES.includes(literal(words[behind]) ?? "") && (spelled || bare(words[behind]) === undefined);
      if ((quoted && DECLARES.includes(text)) || declaring) ask("a quoted export, declare, typeset, local or readonly: bash then splits and globs its arguments, and would not once printed");
      if (quoted && (RESERVED.has(text) || ASSIGNMENT.test(text))) ask("a quoted word that the rules read as an assignment or a keyword and bash runs as a command");
      const first = bare(name);
      if (first === "case") {
        this.caseOpen++;
        caseHead = true;
      }
      if (first === "esac") this.caseOpen = Math.max(0, this.caseOpen - 1);
      if (first !== undefined && BASH_KEYWORDS.has(first)) this.bashOnly = true;
      // `coproc [NAME] command`: the command begins after one word or two, and this reader does
      // not follow it there (a function it defines went unseen). Nobody's everyday command.
      if (first === "coproc") ask("a coprocess (coproc)");
    }
    // `time` is a keyword of bash; dash runs a program of that name.
    const timed = [...keywords].some((w) => bare(w) === "time");
    if (timed) this.bashOnly = true;
    // bash takes `-p` and `--` for parts of `time` only as bare words; a quoted one is the
    // command's name, and printed without its quotes it would be the option.
    if (timed && name && bare(name) === undefined && ["-p", "--"].includes(literal(name) ?? "")) ask("a quoted -p or -- after time, which bash runs as a command and would read as an option of time once printed");
    // In a case statement bash expands no braces in the word after `case` or in a pattern, and
    // does in the commands of an arm. A pattern stands straight before `)` or `|` (bash takes no
    // newline between them), so inside a case every run of words that one of those ends is held
    // to be one: a pipeline or a subshell in an arm is too, which only asks more than it need.
    const pattern = this.caseOpen > 0 && (caseHead || by === ")" || by === "|");
    if (name) {
      // (See constantsOf.) A name with an expansion or a glob in it could be any builtin; a case
      // pattern is no name, but a `.` is taken for one even there.
      const text = literal(name);
      const computed = text === undefined || (text !== "[" && name.parts.some((p) => p.kind === "lit" && !p.quoted && /[*?[]/.test(p.text)));
      if (text === "." || text === "source" || (computed && !pattern)) this.unspelled = true;
    }
    // Where an assignment may stand, bash reads a word that starts `name[` up to the matching
    // `]` as one word, blanks and operators included: `a[ 0 ]=1 cmd` is an assignment (to no
    // valid name, which bash reports) and then runs `cmd`, where this reader and the rules see a
    // command called `a[` with `cmd` among its arguments; `a[ 0 | x ]=1 cmd` holds no pipe. The
    // rules do not know `a[0]=1` as an assignment either. A case pattern is exempt (`v[0-9]*)`),
    // but only a run of one bare word whose bracket closes inside it, ended by `)` or `|`: in an
    // arm `x) a[0|x]=1 cmd` is cut at the `|` like a pattern, and its first piece `a[0` is not
    // closed.
    const closed = (w: Word) => /^[A-Za-z_]\w*\[[^\[\]]+\]/.test(bare(w) ?? "");
    const patternWord = pattern && words.length === 1 && closed(words[0]);
    if (!patternWord) for (const w of [...assigns, ...(name ? [name] : [])]) if (/^[A-Za-z_]\w*\[/.test(leading(w))) ask("a word that starts like an array element (name[) where an assignment may stand: bash reads it up to the matching ], blanks and operators included");
    // The command's words once bash has expanded their braces, in order; `owner[n]` is the
    // written word that made word n.
    const flat: (Word | undefined)[] = [];
    const owner: Word[] = [];
    // Braces are expanded only in the words after the command's name. bash settles what the
    // name word is (a reserved word, an assignment, a function's name, a command) before it
    // expands braces, and a made word is then a plain word whatever it spells: `{time,} ls` runs
    // a command called time, `{,} a=1 ls` one called a=1, `{a,}() { ...; }` defines a function
    // called `{a,}`. Three rounds found one such reading after another, so a brace in the name
    // word asks, and so does one in the two words after `for`, `select`, `function` or `coproc`.
    // In the words after that a made word is an argument, and the only reading that differs
    // from a written one is the `~` (see `braces`).
    const head = name !== undefined && NAMES_NEXT.has(bare(name) ?? "") ? new Set(words.slice(k + 1, k + 3)) : new Set<Word>();
    // bash as sh decides from the words as written whether `command ... export` declares: a
    // brace in a word of that chain is no `command` and no `export` to it, and printed with
    // its braces expanded it would be (`command {export,} p=$x`).
    const chain = new Set<Word>();
    if (name !== undefined && literal(name) === "command") {
      let at = k + 1;
      while (words[at] !== undefined && literal(words[at]) === "command") at++;
      for (const w of words.slice(k + 1, at + 1)) chain.add(w);
    }
    for (const w of words) {
      for (const made of this.braces(w, keywords.has(w) || assigns.has(w) || pattern || w === name || head.has(w) || chain.has(w))) {
        flat.push(made);
        owner.push(w);
      }
    }
    this.code(flat);
    this.messages(flat);
    const out: Two[] = [];
    // `export p=.?` and its like assign as an assignment before a command does, also behind
    // `command` or `builtin`.
    // Behind `command` or `builtin` and their options the builtin is the next word
    // (`command -p export p=.?`); a later word of that name is an argument
    // (`command echo export "p=.*"`).
    // Quotes make no difference here: the builtin reads its arguments when it runs.
    const plain = (w: Word | undefined) => (w === undefined ? undefined : literal(w));
    let runs = k;
    while (["command", "builtin"].includes(plain(words[runs]) ?? "")) {
      runs++;
      while (plain(words[runs])?.startsWith("-")) runs++;
    }
    const declares = name !== undefined && DECLARES.includes(plain(words[runs]) ?? "");
    // A descriptor copy `<&N` is left out of the judged text (the rules read the digit as a
    // command there), and one that fails keeps its command from running. On a program that is
    // harmless: one that does not run changes nothing after it. After a command that moves the
    // shell every later command is judged by where it went (`cd src <&9; cat x` was judged in
    // `src`, and bash never left): there it asks (round 4, the variant check of group B's fourth
    // go; before the round the rules sent such a call to the model as "unknown command 9").
    const copied = items.some((item) => item.type === "redir" && item.op === "<&" && item.dup !== undefined);
    const mover = ["cd", "pushd", "popd"].includes(plain(words[runs]) ?? "");
    if (mover && copied) ask("a descriptor copy (<&N) on cd, pushd or popd: when it fails the command does not run, and the commands after it are where the shell was");
    // Pass 6j: the same on a compound command (`{ true; cd src; } <&9; cat x`: the group does not
    // run when the copy fails). Which compound command a closer ends is not followed here: a
    // copy on any closer (`}`, `done`, `fi`, `esac`, or a command with no word of its own, as
    // after a `)`), in a call that moves the shell anywhere (in a nested shell's code, eval's or
    // a substitution too), asks (print, below).
    // A copy on any other command stays as it is. For a program that is right by itself. A
    // builtin or a function that would change what later commands are judged by is held by
    // other checks, which this one rests on: `eval` with a cd in its code and `.`/`source` ask
    // (guard.ts, the hidden cd; `unspelled` here), a function's body that moves is outside the
    // shape the guard follows (knownShape, condition 4), as are `pushd`, `popd` and `set -P`
    // (condition 2), and `shopt` asks by itself.
    if (mover) this.moves = true;
    if (copied && (words[runs] === undefined || ["}", "done", "fi", "esac"].includes(plain(words[runs]) ?? ""))) this.dupOnCompound = true;
    const made = new Map<Word, (Word | undefined)[]>();
    flat.forEach((w, n) => void (made.get(owner[n]) ?? made.set(owner[n], []).get(owner[n])!).push(w));
    for (const item of items) {
      if (item.type === "word") for (const w of made.get(item) ?? []) w && out.push(this.parts(w.parts, false, assigns.has(item) ? "word" : declares ? "argument" : false, !pattern && !head.has(item) && words.indexOf(item) > k));
      else if (item.type === "redir") out.push(this.redirect(item));
      else out.push(this.heredoc(item));
    }
    return { run: out.map((t) => t.run).filter(Boolean).join(" "), judged: out.map((t) => t.judged).filter(Boolean).join(" ") };
  }

  // The text of a message of `git commit`, `git tag` or `git merge` (`-m <text>`, also from a
  // folded heredoc) is data to git, whatever it holds: it names no command, no file and no
  // option. The rules and the guards key on spellings (`opencode.json`, `--exec`, `sudo`), so
  // they read one fixed word in its place; what runs keeps the text. Only a literal word that
  // bash hands on as it is: a message bash computes is read as it is, with the commands in it,
  // and so is one a glob or a tilde makes. Not in a command that defines a function.
  private messages(words: (Word | undefined)[]) {
    if (words.some((w) => !w) || this.plain) return;
    // A word bash expands (a glob, a tilde) is no message, and before the flag it counts as a
    // word bash computes: `git commit * -m x` with a file named `--trailer`.
    const values = words.map((w) => fixed(w!));
    const argv = values.map((v) => v ?? "$()");
    for (const at of programs(argv)) {
      if (values[at] === undefined || !GIT_WORDS.has(argv[at])) continue;
      // Only where git is handed the words as they are written: first in the command, or behind
      // shell keywords, assignments and the wrappers that pass their words on. `xargs -I{}`,
      // `parallel` and `find -exec` add or replace words (`echo --cleanup | xargs -I{} git tag {}
      // -m -d v1` deletes the tag: the word after `-m` is the value of what `{}` became).
      const passes = (w: string, n: number) => KEEPS_COMMAND_START.has(w) || ASSIGNMENT.test(w) || PASSES_WORDS.has(w) || (/^\d+(?:\.\d+)?[smhd]?$/.test(w) && argv[n - 1] === "timeout");
      if (!argv.slice(0, at).every((w, n) => values[n] !== undefined && passes(w, n))) return;
      // A word bash computes or expands could become any option, one that takes `-m` as its
      // value among them: it is handed over as an option the reading does not know, which stops
      // it there.
      for (const { at: k, attached } of gitMessageWords(values.slice(at + 1).map((v) => v ?? "--\u0000"))) {
        const n = at + 1 + k;
        if (values[n] === undefined) continue;
        words[n] = { type: "word", parts: [{ kind: "message", parts: words[n]!.parts, attached }] };
      }
      return;
    }
  }

  // The code a nested bash, sh or dash is handed after `-c`, and the words `eval` is handed, at
  // the places where a program runs: printed as a command of its own, in place of the word (for
  // `eval`, in place of all its words: the first becomes the code and the rest are dropped). The
  // word must be literal: code built from a variable or a substitution cannot be read.
  private code(words: (Word | undefined)[]) {
    // A word with a glob or a tilde is not literal code: bash makes other words of it first.
    const values = words.map((w) => fixed(w!));
    const argv = values.map((v) => v ?? "$()");
    for (const at of programs(argv)) {
      if (values[at] === undefined) continue;
      const name = argv[at] === "eval" ? "eval" : SHELL_WORDS.get(argv[at]);
      if (name === undefined) {
        // A program called like a shell at a path the checks do not know: the rules go by the
        // name and would judge the word after `-c` as code, and it cannot be printed as code
        // for a program that may be anything.
        if (NESTED_SHELLS.has(path.basename(argv[at])) && values.some((v, n) => n > at && v !== undefined && /^-[a-zA-Z]*c[a-zA-Z]*$/.test(v))) ask(`${argv[at]} with -c: a program named like a shell at a path the checks do not know`);
        continue;
      }
      // Where the command defines a function, `bash`, `sh` or `eval` may be one, and the word
      // after it data: it cannot be printed as code, and left as written it would be code
      // nothing printed. Such a command is rare enough to ask about.
      if (this.plain) ask(`${name} in a command that defines a function: its words cannot be told from the function's arguments`);
      if (name === "eval") {
        const rest = values.slice(at + 1);
        if (!rest.length) continue;
        if (rest.some((v) => v === undefined)) ask("code for eval built from a variable, a substitution or a glob");
        const inner = print(rest.join(" "), this.depth + 1, "in the code eval runs");
        // What eval defines stays defined for the rest of the command, which was read as a
        // command that defines nothing.
        if (inner.defines) ask("code for eval that defines a function, which changes what a later word of the command runs");
        if (/^[-+]/.test(inner.text)) ask("code for eval that starts with - or + once printed, which eval reads as an option");
        if (inner.bashOnly) this.bashOnly = true;
        this.inputs.push(...inner.inputs);
        this.judgedInputs.push(...inner.judgedInputs);
        if (inner.moves) this.moves = true;
        if (inner.dupOnCompound) this.dupOnCompound = true;
        words[at + 1] = { type: "word", parts: [{ kind: "code", text: inner.text, judged: inner.judged }] };
        for (let n = at + 2; n < words.length; n++) words[n] = undefined;
        return;
      }
      const flag = values.findIndex((v, n) => n > at && v !== undefined && /^-[a-zA-Z]*c$/.test(v));
      if (flag < 0 || flag + 1 >= words.length) continue;
      // Only where `-c` is the shell's own option: every word before it is one too (or the name
      // of a `-o`/`-O` option). After a script's name `-c` is an argument of the script.
      const between = values.slice(at + 1, flag);
      if (!between.every((v, n) => v !== undefined && (/^[-+]/.test(v) || /^[-+][a-zA-Z]*[oO]$/.test(between[n - 1] ?? "")))) continue;
      const code = values[flag + 1];
      if (code === undefined) ask("code for a nested shell built from a variable, a substitution or a glob");
      // The scanner asks about an option between -c and the code; such a word is left as it is.
      if (/^[-+]/.test(code!)) continue;
      const inner = print(code!, this.depth + 1, "in a command a nested shell runs");
      // `bash -c ' -x' 'cmd'` runs a command called `-x`; printed without its blank, `-x` would
      // be an option and `cmd` the code.
      if (/^[-+]/.test(inner.text)) ask("code for a nested shell that starts with - or + once printed, which the shell reads as an option");
      // `sh` may be dash, which does not read braces, `[[ ]]` and the like as bash does.
      if (inner.bashOnly && name !== "bash") ask(`code for ${name} that only bash reads this way (braces, [[ ]], <<<, &>, a pattern that could match . or ..), where ${name} may be another shell`);
      this.inputs.push(...inner.inputs);
        this.judgedInputs.push(...inner.judgedInputs);
      if (inner.moves) this.moves = true;
      if (inner.dupOnCompound) this.dupOnCompound = true;
      words[flag + 1] = { type: "word", parts: [{ kind: "code", text: inner.text, judged: inner.judged }] };
      return;
    }
  }

  // An input target in its judged spelling (Printed.judgedInputs), where it differs from the one
  // that runs: plain text and variables that plainly hold a literal (constantsOf), each such
  // variable as its literal. Undefined for any other target (an expansion of another kind, a
  // variable that holds no literal, unquoted text bash acts on, such as a leading `~`).
  private judgedTarget(parts: Part[]): string | undefined {
    if (!this.constants?.size) return undefined;
    let out = "";
    let read = false;
    for (const p of parts) {
      const name = p.kind === "var" ? p.name : p.kind === "param" && p.op === "" && !p.operand.length ? p.head : undefined;
      const value = name === undefined ? undefined : this.constants.get(name);
      if (value !== undefined) {
        out += quote(value);
        read = true;
      } else if (p.kind === "lit" && (p.quoted || [...p.text].every((ch) => PLAIN.test(ch)))) out += quote(p.text);
      else return undefined;
    }
    return read ? out : undefined;
  }

  private redirect(r: Redir): Two {
    if (r.op === "<<<" || r.op === "&>" || r.op === "&>>") this.bashOnly = true;
    // dash takes one digit for a descriptor: `git tag 12>/dev/null` makes a tag named 12 there.
    if (r.fd.length > 1 || (r.dup !== undefined && r.dup.length > 1)) this.bashOnly = true;
    if (r.dup !== undefined) return { run: `${r.fd}${r.op}${r.dup}`, judged: r.op === "<&" ? "" : `${r.fd}${r.op}${r.dup}` };
    // bash expands a glob there only when it matches one file, and dash and bash's posix mode not
    // at all.
    if (r.target!.parts.some((p) => p.kind === "lit" && !p.quoted && /[*?[]/.test(p.text))) ask("a glob in the target of a redirect");
    const target = this.braces(r.target!, true)[0];
    const printed = this.parts(target.parts);
    if (r.op === "<" && !(target.parts.length === 1 && target.parts[0].kind === "proc")) {
      this.inputs.push(printed.run);
      this.judgedInputs.push(this.judgedTarget(target.parts) ?? printed.run);
    }
    return { run: `${r.fd}${r.op} ${printed.run}`, judged: `${r.fd}${r.op} ${printed.judged}` };
  }

  private heredoc(doc: Heredoc): Two {
    const body: Two = doc.quoted
      ? same(doc.body)
      : join(
          doc.parts!.map((p, n): Two => {
            if (p.kind === "lit") return same(p.text.replace(/[\\$`]/g, "\\$&"));
            if (p.kind === "var") return same(/^[A-Za-z_]/.test(p.name) ? `\${${p.name}}` : this.variable(p.name, doc.parts![n + 1]));
            if (p.kind === "param") return this.param(p);
            if (p.kind === "arith") return this.arith(p);
            if (p.kind === "sub") return this.sub(p);
            return ask("an expansion in a heredoc body that is not printed");
          }),
          "",
        );
    const d = this.delimiter(body.run + body.judged);
    // Parentheses in the body that do not balance as the rules' parser counts them: inside a
    // substitution it would find another end for it than bash does. (A body such as
    // `fix (api): $x` balances; the first version asked about every parenthesis.)
    const parens = !balanced(body.run) || !balanced(body.judged);
    if (doc.joined) this.bashOnly = true;
    this.docs.push({ run: `${body.run}${d}\n`, judged: `${body.judged}${d}\n`, parens });
    if (doc.fd.length > 1) this.bashOnly = true;
    const open = `${doc.fd}<<${doc.quoted ? `'${d}'` : d}`;
    return same(open);
  }

  private cond(c: Cond): Two {
    this.bashOnly = true;
    const out: Two[] = [same("[[")];
    for (const item of c.items) {
      if (item.type === "op") out.push({ run: item.op, judged: `'${item.op}'` });
      else if (item.regex) {
        // Printed with its quoting kept; an unquoted character the printer would have to quote
        // (a brace, a `#`) would become a literal one.
        if (item.parts.some((p) => p.kind === "lit" && !p.quoted && [...p.text].some((ch) => !PLAIN.test(ch) && !ACTIVE.includes(ch)))) ask("a regular expression after =~ with a character the printer would have to quote");
        out.push(this.parts(item.parts, true));
      } else out.push(this.parts(this.braces(item, true)[0].parts));
    }
    out.push(same("]]"));
    const all = join(out, " ");
    // The rules read `test` and the same words. What an operand can run (a substitution, a
    // subscript in `-v 'a[$(cmd)]'`, an arithmetic operand of `-eq`) is the scanner's to ask
    // about, on the text that runs.
    return { run: all.run, judged: all.judged.replace(/^\[\[/, "test").replace(/ \]\]$/, "") };
  }

  // A token list. `inner`: the body of a substitution, where the parser counts parentheses
  // without regard to quotes or heredocs, so none may stand unbalanced or in a heredoc body.
  list(tokens: Token[], inner = false): Two {
    const out: Two = { run: "", judged: "" };
    // The last character of each text so far: asking a long string for it at every token made
    // printing quadratic in the number of lines.
    const last = { run: "", judged: "" };
    const put = (key: "run" | "judged", text: string) => {
      if (text === "") return;
      out[key] += text;
      last[key] = text[text.length - 1];
    };
    const add = (t: Two) => {
      for (const key of ["run", "judged"] as const) if (t[key] !== "") put(key, (last[key] !== "" && last[key] !== "\n" ? " " : "") + t[key]);
    };
    const newline = () => {
      const docs = this.docs.splice(0);
      // The parser's parenthesis count reads a heredoc body too.
      if (inner && docs.some((d) => d.parens)) ask("an unbalanced parenthesis in a heredoc body inside a substitution");
      for (const key of ["run", "judged"] as const) {
        if (docs.length) put(key, "\n" + docs.map((d) => d[key]).join(""));
        else if (last[key] !== "" && last[key] !== "\n") put(key, "\n");
      }
    };
    let items: (Word | Redir | Heredoc)[] = [];
    let level = 0;
    const flush = (by?: string) => {
      if (items.length) add(this.command(items, by));
      items = [];
    };
    for (const t of tokens) {
      if (t.type === "word" || t.type === "redir" || t.type === "heredoc") items.push(t);
      else if (t.type === "cond") {
        flush();
        add(this.cond(t));
      } else if (t.type === "arith") {
        flush();
        this.bashOnly = true;
        // `for (( ... ))` is a loop the rules need not read; an arithmetic command runs nothing.
        add(t.loop ? { run: `((${t.text}))`, judged: "_ in 0" } : { run: `((${t.text}))`, judged: ":" });
      } else {
        flush(t.op);
        if (t.op === "\n") newline();
        else {
          if (t.op === "(") level++;
          if (t.op === ")" && --level < 0) {
            if (inner) ask("a parenthesis that closes nothing inside a substitution");
            level = 0;
          }
          add(same(t.op));
        }
      }
    }
    flush();
    if (inner && level !== 0) ask("an unbalanced parenthesis inside a substitution");
    if (this.docs.length) newline();
    return out;
  }
}

// One rule for a command that defines a function, whatever the function is called (decided by
// the maintainer after two rounds of matching names: first `cat` and `git`, then `./git` and a
// function named `bash` got through). A name then runs the function, with the words after it as
// its arguments, so nothing in such a command is taken for what its name usually means: no
// `"$(cat <<'X' ...)"` is folded into the text it holds, no git message gets a placeholder, and
// no word is printed as the code of a nested shell or of `eval`. The text is printed as plain
// words and the rules judge those. (A nested shell's code is printed on its own: what it
// defines is its own matter, and what the command around it defines is not printed into it,
// since under this rule that command prints no nested code at all.)
// `defines`: whether this command defines a function.
function print(command: string, depth: number, where?: string): Printed & { defines: boolean; moves: boolean; dupOnCompound: boolean } {
  if (depth > MAX_DEPTH) ask("deeply nested shells");
  try {
    let tokens = new Lexer(command, depth, false).list(false);
    const names = new Set<string>();
    defined(tokens, names);
    const defines = names.size > 0;
    // Read again without folding.
    if (defines) tokens = new Lexer(command, depth, false, 0, { docs: 0, fold: false }).list(false);
    const braces = braceText;
    const printer = new Printer(command, depth, defines);
    const out = printer.list(tokens);
    const { moves, dupOnCompound } = printer;
    if (depth === 0 && moves && dupOnCompound) {
      ask("a descriptor copy (<&N) on a compound command or on a redirect with no command, in a call with a cd, pushd or popd anywhere: when the copy fails the commands inside do not run, and the commands after it are where the shell was");
    }
    // The whole call, not the code of a nested shell (which starts without these variables).
    const constants = depth === 0 && !defines ? constantsOf(tokens, out.run, printer.unspelled) : new Map<string, string>();
    if (constants.size) {
      // Printed again with the literals in the judged text; what runs must come out the same.
      braceText = braces;
      const again = new Printer(command, depth, defines);
      again.constants = constants;
      const judged = again.list(new Lexer(command, depth, false).list(false));
      if (judged.run === out.run) return { text: out.run, judged: judged.judged, bashOnly: again.bashOnly, inputs: again.inputs, judgedInputs: again.judgedInputs, defines, moves, dupOnCompound };
    }
    return { text: out.run, judged: out.judged, bashOnly: printer.bashOnly, inputs: printer.inputs, judgedInputs: printer.judgedInputs, defines, moves, dupOnCompound };
  } catch (e) {
    if (e instanceof Ask && where) throw new Ask(`${e.message}, ${where}`);
    throw e;
  }
}

export function canonical(command: string): Canonical {
  try {
    if (CONTROL.test(command)) return { ask: "a control character (a carriage return, an escape or the like) or a Unicode line separator" };
    // The shell is started as `<shell> -c <text>`, and bash and dash go on reading options
    // after `-c`: a text that starts with `-` or `+` is taken for options, not for a command.
    braceText = 0;
    if (/^[-+]/.test(command)) return { ask: "a command line that starts with - or +, which the shell reads as its own options" };
    // The text is handed to the shell as one argument or one variable, and the kernel takes no
    // single string above 128 KiB: a command near that size could not run as printed.
    if (Buffer.byteLength(command) > MAX_TEXT) return { ask: "a command too long to hand to the shell in one piece" };
    const { text, judged, bashOnly, inputs, judgedInputs } = print(command, 0);
    if (/^[-+]/.test(text)) return { ask: "a command line that starts with - or + once blanks, comments and line continuations are gone, which the shell would read as its own options" };
    if (Buffer.byteLength(text) > MAX_TEXT) return { ask: "a command too long to hand to the shell in one piece once printed" };
    return { text, judged, bashOnly, inputs, judgedInputs };
  } catch (e) {
    if (e instanceof Ask) return { ask: e.message };
    // A mistake in this reader must not become an error the caller has to think of: whatever
    // could not be printed asks (the second cross-check found a word that overflowed the stack).
    return { ask: `the command could not be read (${e instanceof Error ? e.name : "an error"} in the reader)` };
  }
}
