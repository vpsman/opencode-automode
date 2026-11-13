// The glob table (round 4, finding 6): the guard's own glob matcher is held to bash's. Each
// pattern is expanded by real bash in a directory that holds every name of the table, and by
// expandWord() over the same directory. The two lists must be the same; expandWord() may also say
// it cannot tell (undefined), which its callers turn into a prompt, but it may not give another
// list. A pattern bash expands to a protected name is one protectedNameIn() must report, with the
// directory known and unknown: that is the test `printf x > .g[[:lower:]]t/config` passed.
//
// bash runs with nullglob, so a pattern that matches nothing gives nothing (as expandWord()
// does), and in the C.UTF-8 locale where it is installed: there `?` matches one character of a
// name that is not ASCII, as it does for the guard (in the plain C locale bash matches bytes, and
// the name outside ASCII is left out of the table). bash 5 reads a range as a range of code
// points in every locale (`globasciiranges`).
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { braceWords, expandWord, protectedNameIn } from "../guard.ts";
import { canonical } from "../canon.ts";
import { parse } from "../rules.ts";

const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "automode-globtable-")));
const UTF8 = /^C\.(UTF-8|utf8)$/im.exec(spawnSync("locale", ["-a"], { encoding: "utf8" }).stdout ?? "")?.[0];
const NAMES = [".git", ".gIt", ".g1t", ".g-t", ".g]t", ".g[t", ".gt", ".x", "a", "b", "c", "d", "i", "I", "A", "Z", "1", "9", "-", "]", "[", "!", "^", ":", "=", "a]", "ab", "a1", "a-", "abc", ...(UTF8 ? ["é"] : []), "x y", "AGENTS.md", "opencode.json", "_", "x", "[a", "[:", "[l", ".g_t",
  // Second pass (round 4, finding 6): names the bracket quirks below reach.
  ".env", ".gxt", ".g=t", ".g!t", ".g^t", "=]", "[=", "[.", ":]", "@", "?", "t", "[]", "a=", "[a-", "a-]", "x]", "]]"];
const PATTERNS = [
  // Plain globs.
  "*", "?", "??", ".*", ".g?t", ".g*t", "a*", "*b*", "a?", "*.md", "*.j*",
  // Brackets: sets, ranges, negation, the characters that are special inside one.
  "[abc]", "[a-c]", "[!a-c]", "[^a-c]", "[a-cA-Z]", "[0-9]", "[!0-9]", "a[b1]", "a[!b]", "[]]", "[]a]", "[!]]", "[!]a]", "[[]", "[a[]", "[-a]", "[a-]", "[!-]", "[a^]", "[^^]", "[!!]", "[a!]", "[:=]",
  ".g[i]t", ".g[!i]t", ".g[a-z]t", ".g[A-Z]t", ".g[0-9]t", ".g[]]t", ".g[[]t", ".g[-]t", ".g[i-]t", ".[g]it", "[.]git", "[.]*",
  // POSIX classes, equivalence classes and collating symbols (finding 6).
  "[[:lower:]]", "[[:upper:]]", "[[:digit:]]", "[[:alpha:]]", "[[:alnum:]]", "[[:punct:]]", "[[:space:]]", "[[:xdigit:]]", "[![:lower:]]", "[^[:digit:]]", "[[:lower:][:digit:]]", "[a[:digit:]]", "[[:digit:]a]", "[[:lower:]-]",
  "a[[:digit:]]", "a[[:lower:]]", "a[[:punct:]]", "*[[:digit:]]*", "x[[:space:]]y", "[[:blank:]]", "[[:nope:]]", "[[:lower:]", "[[:lower:]]]",
  ".g[[:lower:]]t", ".g[[:upper:]]t", ".g[[:alpha:]]t", ".g[[:alnum:]]t", ".g[[:digit:]]t", ".g[[:punct:]]t", ".g[![:digit:]]t", ".g[[:lower:][:upper:]]t",
  "[[=i=]]", "[[=a=]]", ".g[[=i=]]t", ".g[[=I=]]t", "[[.i.]]", "[[.-.]]", ".g[[.i.]]t", ".g[[.hyphen.]]t", ".g[[=i=][.x.]]t", "opencode.jso[[:lower:]]", "AGENTS.m[[:lower:]]", "AGENTS[[:punct:]]md",
  // Unclosed brackets are literal characters.
  "[", "a[", ".g[t", "[a", "[!", "[]", "[!]",
  // From probing bash 5.2 for finding 6: the classes the table did not have, ranges that run
  // backwards or have a class or a collating symbol at one end, a `-` first or last, an unclosed
  // bracket whose next `[` opens one, and forms bash reads by the locale or by its own tables.
  "[[:word:]]", "[[:graph:]]", "[[:print:]]", "[[:cntrl:]]", "[c-a]", "[!c-a]", "[!-]", "[]-a]", "[a-]]", "[a-[:digit:]]", "[[:digit:]-a]", "[[:lower:]-z]",
  "[[.-.]-a]", "[a-[.b.]]", "[[.a.]-b]", "[[=a=]-b]", "[a-[=b=]]", "[[:lower:][.-.]]", "[[.].]]", "[[.[.]]", "[[=]=]]", "[[=ab=]]", "[[.ab.]]", "[[.nope.]]",
  "[[.a.]", "[[=a=]", "[[:nope:]", "[[:alpha:]", "[[]:lower:]", "[[.left-square-bracket.]]", "[[.underscore.]]", ".g[[:word:]]t", ".g[[.underscore.]]t", ".g[[.h.]-[.j.]]t", ".g[!-[:digit:]]t",
  // Second pass (round 4, finding 6): where bash closes a bracket the first pass read as unclosed.
  // A `[=` or `[.` that is not a one-character equivalence class is no class: its `[` is a member
  // and its `]` closes the bracket; a range that ends at `[` ends there, and `:class:]` after it is
  // plain characters. Each probed in bash 5.2.
  ".g[^[=ab=]t", ".g[![=ab=]t", ".e[![=ab=]v", ".en[![=ab=]", "AGENT[?-[:punct:].md", "AGENT[mn?-[:punct:].md", "opencode.jso[?-[:punct:]", ".[^][=ab=]it",
  "[[=ab=]", "[a[=b=]", "[[:abc]", "[a[:]", "[[:]]", "[[=]", "[a[.b]", "[[.a.]", "[?-[:punct:]", "[a-", "[a-]]", "[[=a=]]]", "[[:lower:]]]", "[[:digit:]]]", "[]-a]",
  "[[.].]a]", "[[.[.]]", "[x[.].]]", "[]]]", "[!]]]", "[[=a=]", "[[:lower:]", "[a[=b=]]", "[a[:x]", "[[:x]:]]", "[x-[.].]]", "[[.a.]-[.c.]]",
  // Braces with globs.
  ".g{i,[[:lower:]]}t", "{a,[[:digit:]]}", ".{git,x}", "a{b,[[:digit:]],]}",
];

// The patterns expandWord() cannot tell (round 4, finding 6), whose callers ask: the bracket holds
// what bash reads by the locale or by tables of its own (an equivalence class, a named collating
// symbol, a class name bash does not know), a range with one of those, or a class, at one end, or
// a range that runs backwards (which bash reads by the locale's collation without globasciiranges).
// Every other pattern must be read, and read as bash reads it.
//
// Second pass: the matcher is now a port of bash's own (see globMatcher in guard.ts), and it can
// tell where it could not before: `[[:digit:]-a]` and `[[:lower:]-z]` (a `-` after a class is a
// member), `[[=ab=]]` (no equivalence class: a bracket of `[=ab=`) and `[[.ab.]]`, `[[.nope.]]` (a
// name bash's own table does not hold matches nothing, in every locale) left the set. A range with
// a collating symbol at one end is compared by the locale's collation, not by code point, and
// joined it, as did patterns holding an equivalence class (`[[=a=]]]`, `[a[=b=]]`) and a class
// name with a `]` in it (`[[:x]:]]`).
const CANNOT_TELL = new Set([
  "[[:nope:]]", "[[=i=]]", "[[=a=]]", ".g[[=i=]]t", ".g[[=I=]]t", ".g[[.hyphen.]]t", ".g[[=i=][.x.]]t", "[a-[:digit:]]",
  "[[=a=]-b]", "[a-[=b=]]", "[[=]=]]", "[[.left-square-bracket.]]", "[[.underscore.]]", ".g[[.underscore.]]t", "[c-a]", "[!c-a]",
  "[[.-.]-a]", "[a-[.b.]]", "[[.a.]-b]", ".g[[.h.]-[.j.]]t", "[[=a=]]]", "[x-[.].]]", "[[.a.]-[.c.]]", "[a[=b=]]", "[[:x]:]]",
]);

before(() => {
  for (const name of NAMES) {
    if (name === ".git" || name === ".gIt") fs.mkdirSync(path.join(dir, name));
    else fs.writeFileSync(path.join(dir, name), "");
  }
  fs.writeFileSync(path.join(dir, ".git", "config"), "");
});
after(() => fs.rmSync(dir, { recursive: true, force: true }));

// What bash makes of each pattern, one list per pattern.
function bashExpands(patterns: string[]): string[][] {
  const script = `shopt -s nullglob; while IFS= read -r -d '' pattern; do eval "printf '%s\\\\0' $pattern"; printf '\\1\\0'; done`;
  const r = spawnSync("/bin/bash", ["-c", script], { cwd: dir, input: patterns.map((p) => p + "\0").join(""), encoding: "utf8", env: { PATH: "/usr/bin:/bin", LC_ALL: UTF8 ?? "C" } });
  assert.equal(r.status, 0, r.stderr);
  const lists = r.stdout.split("\x01\0").slice(0, -1);
  assert.equal(lists.length, patterns.length, `bash answered for ${lists.length} of ${patterns.length} patterns: ${r.stderr}`);
  return lists.map((list) => list.split("\0").filter(Boolean).sort());
}

// The brace table (round 4, finding 2): braceWords() against bash's own brace expansion. As
// with globs, braceWords() may say it cannot tell (undefined), and its callers then ask; it may
// not give another list than bash's. bash drops a word that expands to nothing, so empty words are
// left out on both sides.
const BRACES = [
  "{a,b}", "a{b,c}d", "{a,b}{1,2}", "{a,b}{1,2}{x,y}", "{,}", "{,}{,}", "x{,}", "{a,}", "{,a}", "{a,b,}", "{,,}", "a{,}{,}b",
  "{a}", "{}", "x{}y{a}", "{a", "a}", "}{", "{a,b", "a,b}", "{a}{b,c}", "{a,b}{c}", "{{a,b}}", "{{a,b},c}", "{a,{b,c}}", "{a,{b,{c,d}}}", "{{{{{{{-delete,},},},},},},}", "{x{a,b}}", "{x,{a}}",
  "{,}{,}{,}{,}{,}{,}{-delete,}", "{,}{,}{,}{,}{,}{,}{,}{a,}", "{a,b}{c,d}{e,f}{g,h}{i,j}{k,l}{m,n}",
  "{1..5}", "{5..1}", "{-2..2}", "{2..-2}", "{1..10..3}", "{10..1..3}", "{1..10..-3}", "{01..03}", "{1..010}", "{-01..1}", "{08..11}", "{0..0}", "{1..1}", "{1..3}{a,b}", "{a,b}{1..3}", "x{1..3}y", "{1..3..0}",
  "{a..e}", "{e..a}", "{a..e..2}", "{A..C}", "{a..a}", "{f..f}", "{https://h/,-T}{f..f}", "{a,-d}{1..2}",
  "{a..3}", "{1..a}", "{1..}", "{..1}", "{1...3}", "{1.5..3}", "{a..bb}", "{1..2..x}", "{a,b}..{c,d}", "a..b", "{a.b}", "{a.,b}",
  // From the round 4 cross-check: a `}` before the group's first comma is a plain character.
  "{a}b,c}", "{a}{1..2},}", "x{a}b,c}", "{a}{,}", "{}a,b}", "{a}}b,c}", "{a}{b}c,d}", "{a,b}c,d}", "{a}1..2}", "a}{b,c}", "{a{b,c}..x}", "{a{b}c,d}", "{{a}b,c}", "{,{a}b}",
  "--exclude={a,b}", "src/{a,b}.ts", "-{-to-command=x,f}", "{/etc,x}", "a/{../..,b}", "${x}{a,b}", "$x{a,b}", "a${x}", "{a,b}$x",
  // From the second round 4 cross-check: `{}` is two plain characters only where the word
  // begins, and bash expands the text after a group on its own: what a group's words and that
  // text make together is not read again as a group.
  "x{},a}y", ".{},}", "{{a},b},c}", "{a,{b}}c,d}", "{{bb},a},.}", "{a{b},c}d,e}", "{},a}", "{{x},-d,@f},host}", "{{opencode.json},x},y}", "a{},b}", "{a,b}{},c}", "{},{a,b}", "{a,b}{}", "{a,}{}{b,c}", "{{},a}", "{a,{}}", "x{}{a,b}", "{a,b}x{}", "{a{},b}",
  "{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}{a,b}", "{1..3}{}", "{}{1..3}", "{a,b}}", "{{a,b}", "{a,b}{", "}{a,b}", "{a,b},c}", "{a,b}{c}d,e}",
  // A word too long to expand here gives no list (the test below holds the time it takes).
  // A step that does not fit a number: bash leaves that group as written.
  "{a..c..99999999999999999999}", "{a..c..99999999999999999999}{x,y}", "{a,b}{1..2..99999999999999999999}",
];
describe("the brace table: the guard's brace expansion against bash's", () => {
  test("braceWords gives bash's words, or says it cannot tell", () => {
    // Quoted `$`: the table asks what bash does with the braces, not with the variable.
    const script = `while IFS= read -r -d '' pattern; do eval "printf '%s\\\\0' $pattern"; printf '\\1\\0'; done`;
    const escaped = BRACES.map((p) => p.replace(/\$/g, "\\$"));
    const r = spawnSync("/bin/bash", ["-c", script], { cwd: dir, input: escaped.map((p) => p + "\0").join(""), encoding: "utf8", env: { PATH: "/usr/bin:/bin", LC_ALL: "C" } });
    assert.equal(r.status, 0, r.stderr);
    const want = r.stdout.split("\x01\0").slice(0, -1).map((list) => list.split("\0").filter(Boolean));
    assert.equal(want.length, BRACES.length, `bash answered for ${want.length} of ${BRACES.length} words: ${r.stderr}`);
    const bad: string[] = [];
    let unknown = 0;
    for (const [n, word] of BRACES.entries()) {
      const got = braceWords(word)?.filter(Boolean);
      if (got === undefined) unknown++;
      else if (JSON.stringify(got) !== JSON.stringify(want[n])) bad.push(`${word}: bash ${JSON.stringify(want[n])}, the guard ${JSON.stringify(got)}`);
    }
    assert.deepEqual(bad, [], `${bad.length} of ${BRACES.length} words differ:\n${bad.join("\n")}`);
    // The table must not pass by answering "cannot tell" throughout.
    assert.ok(unknown <= 19, `braceWords could not tell for ${unknown} of ${BRACES.length} words`);
  });
  test("braceWords gives up on a word too long for it, at once", () => {
    const started = Date.now();
    for (const word of ["{1..1}".repeat(16_000), "{".repeat(40_000), `a${"{x,y}".repeat(900)}`, `${"{".repeat(3_000)}a,b${"}".repeat(3_000)}`]) assert.equal(braceWords(word), undefined, `${word.slice(0, 20)}... (${word.length} characters)`);
    assert.deepEqual(braceWords(`${"x".repeat(50_000)}`), ["x".repeat(50_000)], "a long word with no brace is itself");
    assert.ok(Date.now() - started < 1_000, `took ${Date.now() - started} ms`);
  });
  // `${name}` opens no group and what stands inside it is passed over. The table above writes
  // `\$`, which makes the `{` after it an ordinary brace; here the expansions are real, of
  // variables with known values, and the guard's words are compared with those values put in.
  test("braceWords beside a parameter expansion: bash's words", () => {
    const words = ["${x}{a,b}", "a${x}", "${y}{},a}", "{x,${y}}z,w}", "${y}{a,b}${x}", "{${x},b}", "{a,${x}}", "x${y}{}", "${x}{}", "{}${x}{a,b}", "${x},{a,b}", "{a,b}${y}{c,d}", "${x}{1..2}", "{${x}..3}"];
    const script = `while IFS= read -r -d '' word; do eval "printf '%s\\\\0' $word"; printf '\\1\\0'; done`;
    const r = spawnSync("/bin/bash", ["-c", script], { cwd: dir, input: words.map((w) => w + "\0").join(""), encoding: "utf8", env: { PATH: "/usr/bin:/bin", LC_ALL: "C", x: "P", y: "Q" } });
    assert.equal(r.status, 0, r.stderr);
    const want = r.stdout.split("\x01\0").slice(0, -1).map((list) => list.split("\0").filter(Boolean));
    assert.equal(want.length, words.length, r.stderr);
    const bad: string[] = [];
    for (const [n, word] of words.entries()) {
      const got = braceWords(word)?.map((w) => w.replaceAll("${x}", "P").replaceAll("${y}", "Q")).filter(Boolean);
      if (got !== undefined && JSON.stringify(got) !== JSON.stringify(want[n])) bad.push(`${word}: bash ${JSON.stringify(want[n])}, the guard ${JSON.stringify(got)}`);
    }
    assert.deepEqual(bad, [], bad.join("\n"));
  });
});

describe("the glob table: the guard's matcher against bash's", () => {
  test("the table reaches the protected name through a class, an equivalence class and a collating symbol", () => {
    const got = bashExpands([".g[[:lower:]]t", ".g[[=i=]]t", ".g[[.i.]]t"]);
    // (`.gxt` is in the table since the second pass.)
    assert.deepEqual(got, [[".git", ".gxt"], [".git"], [".git"]], "bash here does not expand the three POSIX forms as the finding says");
  });
  test("expandWord gives bash's list, or says it cannot tell exactly where the table says so", () => {
    const want = bashExpands(PATTERNS);
    const bad: string[] = [];
    for (const [n, pattern] of PATTERNS.entries()) {
      const got = expandWord(pattern, dir)?.map((p) => path.relative(dir, p)).sort();
      if (CANNOT_TELL.has(pattern)) {
        if (got !== undefined) bad.push(`${pattern}: the table says the guard cannot tell, the guard ${JSON.stringify(got)}`);
      } else if (got === undefined) bad.push(`${pattern}: bash ${JSON.stringify(want[n])}, the guard cannot tell`);
      else if (JSON.stringify(got) !== JSON.stringify(want[n])) bad.push(`${pattern}: bash ${JSON.stringify(want[n])}, the guard ${JSON.stringify(got)}`);
    }
    for (const pattern of CANNOT_TELL) if (!PATTERNS.includes(pattern)) bad.push(`${pattern}: in CANNOT_TELL but not in the table`);
    assert.deepEqual(bad, [], `${bad.length} of ${PATTERNS.length} patterns differ:\n${bad.join("\n")}`);
  });
  test("a pattern bash expands to a protected name is reported, with the directory known and unknown", () => {
    const protectedNames = [".git", "AGENTS.md", "opencode.json"];
    const want = bashExpands(PATTERNS);
    const bad: string[] = [];
    for (const [n, pattern] of PATTERNS.entries()) {
      const hits = want[n].filter((name) => protectedNames.includes(name));
      if (!hits.length) continue;
      for (const cwd of [dir, undefined]) {
        const found = protectedNameIn(`${pattern}/config`, protectedNames, cwd);
        if (!found) bad.push(`${pattern}/config (directory ${cwd ? "known" : "unknown"}): bash reaches ${hits.join(", ")}, the guard reports nothing`);
      }
    }
    assert.deepEqual(bad, [], `${bad.length} write targets reach a protected name unseen:\n${bad.join("\n")}`);
  });
  // Second pass: a pattern the matcher cannot read is held to the wider match, where bash may or
  // may not reach the protected name (by the locale: `[[=x=]]`, `[[.hyphen.]]`, a range with a
  // collating symbol at one end; or a range that runs backwards).
  test("a pattern the matcher cannot read is held to the wider match", () => {
    const bad: string[] = [];
    for (const pattern of [".g[[.hyphen.]]t", ".g[c-a]t", ".g[!c-a]t", ".g[[=x=]]t", ".g[[:nope:]]t", ".g[[.underscore.]]t", ".g[[.h.]-[.j.]]t", ".g[[.a.]-[.c.]]t", ".g[x-[.j.]]t", ".g[[=a=][:digit:]]t"]) {
      for (const cwd of [dir, undefined]) if (protectedNameIn(`${pattern}/config`, [".git"], cwd) !== ".git") bad.push(`${pattern}/config (directory ${cwd ? "known" : "unknown"})`);
      if (expandWord(pattern, dir) !== undefined) bad.push(`${pattern}: expandWord reads it, ${JSON.stringify(expandWord(pattern, dir))}`);
    }
    assert.deepEqual(bad, [], bad.join("\n"));
  });
  // The table gives expandWord() the pattern as bash's source text. Production gives it the word
  // the rules' parser made of the printed text, quotes removed. The two are the same only for a
  // pattern with no quoted character in it; a quoted character inside a bracket is a plain member
  // to bash (`.g['!'i]t` is `.git`), which the word without its quotes cannot show, and the
  // printer asks about it.
  test("the table's patterns reach the guard as written, and a quoted character in a bracket asks", () => {
    const bad: string[] = [];
    for (const pattern of PATTERNS) {
      const printed = canonical(`ls ${pattern}`);
      if ("ask" in printed) continue; // braces the printer will not expand, a lone `[` and the like
      const words = parse(printed.judged).cmds.flatMap((c) => c.argv.slice(1));
      if (!words.every((w) => !/[\\'"]/.test(w))) bad.push(`${pattern}: the guard reads ${JSON.stringify(words)}`);
    }
    for (const word of [".g['!'i]t", ".g[i\\]]t", ".g[\\^i]t", '.g["!"i]t', ".g[\\!i]t", ".g['i]']t", ".en['!'v]", "[a'-'z]", "[\\[:lower:]]", "x['^']", "[!'a']"]) {
      const printed = canonical(`cat ${word}`);
      if (!("ask" in printed)) bad.push(`${word}: printed ${JSON.stringify(printed.text)}, no ask`);
      const nested = canonical(`bash -c ${JSON.stringify(`cat ${word}`).replace(/\$/g, "\\$")}`);
      if (!("ask" in nested)) bad.push(`bash -c "cat ${word}": printed ${JSON.stringify(nested.text)}, no ask`);
    }
    // Quoted text before a bracket opens or after it closes is no member of it.
    for (const word of ["'a b'[xy]", "[xy]'a b'", "\"$d\"/[ab]*", "[ab]*'.md'", "x'['y]", "'[a]'"]) {
      const printed = canonical(`cat ${word}`);
      if ("ask" in printed) bad.push(`${word}: asks (${printed.ask})`);
    }
    assert.deepEqual(bad, [], bad.join("\n"));
  });
  // Round 4, group B, third pass (E2): the bracket ends where bash ends it, at the first unquoted
  // `]` that is not its first member (after `[`, `[!` or `[^`) and not the end of a `[:class:]`,
  // `[=x=]` or `[.x.]` inside it. Quoted text after that is no member of it; a quoted character
  // inside a later bracket is.
  test("r4 B3 6 (E2): quoted text after a bracket closes does not ask, a quoted member of a later bracket does", () => {
    const bad: string[] = [];
    for (const word of ["[1]\"a]\"", "[ab]'x]'", "[!]]'a]'", "[]]'a]'", "[^]]'a]'", "[[:alpha:]]'x]'", "[[=a=]]'x]'", "[[.a.]]'x]'", "[a]'b]'[c]", ".g[i]t'x]'", "[a-z]*'.md]'"]) {
      for (const command of [`echo ${word}`, `cat ${word}`]) {
        const printed = canonical(command);
        if ("ask" in printed) bad.push(`${command}: asks (${printed.ask})`);
      }
    }
    for (const word of ["[]'a']", "[!]'a']", "[^]'a']", "[[:alpha:]'x']", "[1]x['a']", "[1]\"a]\"['b']", "[a]'b]'[c'd']", "[[:alpha:]\\]]", "[[=a=]'b']"]) {
      const printed = canonical(`cat ${word}`);
      if (!("ask" in printed)) bad.push(`${word}: printed ${JSON.stringify(printed.text)}, no ask`);
    }
    assert.deepEqual(bad, [], bad.join("\n"));
  });
});
