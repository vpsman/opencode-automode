// Round 4, B11 (the closing review's F6): reads judged by where they lead. Around the vendored
// rules: an existing operand of a reading command is also judged by its physical path (the
// kernel's walk, where a link is followed before the `..` after it), and `ln -s <credential
// location> x` counts as a read of that location. Run: node test/run.mjs test/b11-links.test.mts.
//
// The decoy credentials live in a directory outside the project (`E`, laid out as a home), and,
// for the rows spelled with `~`, in the throwaway home test/run.mjs supplies.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, describe, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideShell, SessionState, takeMoment, type Guard } from "../decide.ts";
SessionState.moment = takeMoment;
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

assert.ok(process.env.GIT_CONFIG_GLOBAL?.startsWith(os.homedir()), "run through test/run.mjs, which supplies a throwaway $HOME");
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), "b11-")));
const repo = path.join(base, "repo");
// A home-shaped place outside the project, with decoy credentials.
const E = path.join(base, "elsewhere");
const git = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const write = (file: string, text: string) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
};
const guard: Guard = {
  rules: compileRules({ ask: DEFAULT_ASK }),
  guarded: [path.resolve(import.meta.dirname, "..")],
  configDirs: [path.join(os.homedir(), ".config", "opencode")],
  allowedPaths: [],
  classifier: DEFAULT_CLASSIFIER,
  useClassifier: false,
  sshHosts: [],
  allowFeatureBranchPush: false,
};
const DECOYS = ["Library/Keychains/login.keychain-db", ".config/gh/hosts.yml", ".config/gcloud/credentials.db", ".docker/config.json", ".cargo/credentials", ".local/share/keyrings/login.keyring", ".terraform.d/credentials.tfrc.json", ".aws/credentials", ".netrc"];
before(() => {
  for (const d of DECOYS) write(path.join(E, d), "DECOY\n");
  write(path.join(E, ".config/plain/settings.json"), "{}\n");
  write(path.join(E, "plain/notes.txt"), "notes\n");
  write(path.join(E, ".local/share/other/x"), "x\n");
  write(path.join(E, ".cargo/registry/x"), "x\n");
  fs.mkdirSync(path.join(E, "empty/.config"), { recursive: true });
  write(path.join(repo, "f"), "x\n");
  write(path.join(repo, "src/main.c"), "int main(void) { return 0; }\n");
  write(path.join(repo, "sub/notes.txt"), "notes\n");
  write(path.join(repo, "node_modules/.pnpm/left-pad@1.3.0/node_modules/left-pad/index.js"), "module.exports = 1;\n");
  write(path.join(repo, ".gitignore"), "node_modules/\n");
  git(base, "init", "-q", "-b", "main", repo);
  git(repo, "add", "-A");
  git(repo, "commit", "-qm", "one");
  // Links made before the session: to a place outside with no credential in it (whose `..` leads
  // to one), to a credential file, to pnpm's store, to a system directory.
  fs.symlinkSync(path.join(E, ".config/plain"), path.join(repo, "pl"));
  fs.symlinkSync(path.join(E, ".local/share/other"), path.join(repo, "sh0"));
  fs.symlinkSync(path.join(E, ".cargo/registry"), path.join(repo, "cg"));
  fs.symlinkSync(path.join(E, ".config/gh/hosts.yml"), path.join(repo, "g2"));
  fs.symlinkSync(".pnpm/left-pad@1.3.0/node_modules/left-pad", path.join(repo, "node_modules/left-pad"));
  fs.symlinkSync("/usr/share", path.join(repo, "share"));
  fs.symlinkSync("src/main.c", path.join(repo, "m.c"));
  fs.symlinkSync("sub", path.join(repo, "sl"));
  fs.symlinkSync("sub", path.join(repo, "hl"));
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

type Want = "allow" | "ask" | "classify";
async function outcome(command: string, session = new SessionState(repo)): Promise<{ kind: Want | "deny"; reason: string }> {
  const d = await decideShell(guard, session, repo, command);
  return { kind: d.by === "no-model" ? "classify" : d.effect === "allow" ? "allow" : d.effect === "ask" ? "ask" : "deny", reason: `${command} -> ${d.effect} by ${d.by}: ${d.reason}` };
}
const rows = (label: string, want: Want, commands: string[], also?: (reason: string, c: string) => void) => {
  for (const c of commands) test(`B11 ${label}: ${want}: ${JSON.stringify(c)}`, async () => {
    const got = await outcome(c);
    assert.equal(got.kind, want, got.reason);
    also?.(got.reason, c);
  });
};
// The reason names both spellings: the words as written and the place they lead to.
const namesBoth = (word: string, place: () => string) => (reason: string) => {
  assert.ok(reason.includes(word), `${reason} names ${word}`);
  assert.ok(reason.includes(place()), `${reason} names ${place()}`);
};

describe("B11-1: a read's operand judged by its physical path", () => {
  const hosts = () => path.join(E, ".config/gh/hosts.yml");
  // `pl` leads to E/.config/plain: `pl/..` is E/.config to the kernel, the project to the text.
  rows("1", "ask", [
    "cat pl/../gh/hosts.yml",
    "cat ./pl/../gh/hosts.yml",
    "cat pl/..//gh/hosts.yml",
    "cat -- pl/../gh/hosts.yml",
    "cat f pl/../gh/hosts.yml",
    "cat 'pl/../gh/hosts.yml'",
    "head -1 pl/../gh/hosts.yml",
    "tail -n 2 pl/../gh/hosts.yml",
    "less pl/../gh/hosts.yml",
    "cp pl/../gh/hosts.yml out",
    "cp -L pl/../gh/hosts.yml out",
    "grep tok pl/../gh/hosts.yml",
    "base64 pl/../gh/hosts.yml",
    "xxd pl/../gh/hosts.yml",
    "od -c pl/../gh/hosts.yml",
    "strings pl/../gh/hosts.yml",
    "sed -n 1p pl/../gh/hosts.yml",
    "awk 1 pl/../gh/hosts.yml",
    "diff pl/../gh/hosts.yml f",
    "wc -l pl/../gh/hosts.yml",
    "tar cf o.tar pl/../gh/hosts.yml",
    "cd src && cat ../pl/../gh/hosts.yml",
    "cd sub; head ../pl/../gh/hosts.yml",
    "true && cat pl/../gh/hosts.yml | wc -l",
    "cat pl/../gh/hosts.yml > out",
    "cd sl && cat ../pl/../gh/hosts.yml",
    // After a `name=` and an `@`, as the rules read a path in a word.
    "dd if=pl/../gh/hosts.yml of=out",
    "gcc @pl/../gh/hosts.yml -o x",
  ], namesBoth("pl/..", hosts));
  rows("1", "ask", ["cat pl/../gcloud/credentials.db", "cat sh0/../keyrings/login.keyring", "cat cg/../credentials"], (r) => assert.match(r, /which leads to/));
  // A `<` input was judged by its physical path before (inputReads), `--file=` by grep's own list
  // reader, and a place whose name is in the text by the rules: they hold.
  rows("1 (held)", "ask", ["cat < pl/../gh/hosts.yml", "wc -l < pl/../gh/hosts.yml", "grep --file=pl/../gh/hosts.yml f", "cat pl/../../.docker/config.json", "cat pl/../../.cargo/credentials", "cat pl/../../.local/share/keyrings/login.keyring"]);
  // Names only, or a place with no credential: as before.
  rows("1 (as before)", "allow", ["cat pl/../plain/settings.json", "cat pl/settings.json", "ls pl/../gh", "stat pl/../gh/hosts.yml", "readlink pl/../gh/hosts.yml", "ls -la pl/..", "cat src/../f", "head m.c", "wc -l pl/../../plain/notes.txt", "cat sh0/../keyrings/missing"]);
});

describe("B11-2: a link to a credential location counts as a read of it", () => {
  const gh = () => path.join(E, ".config/gh");
  rows("2", "ask", [
    `ln -s ${E}/.config/gh g1`,
    `ln -s ${E}/.config g3`,
    `ln -sf ${E}/.config/gh g1`,
    `ln -sfn ${E}/.config/gh g1`,
    `ln -sT ${E}/.config/gh g1`,
    `ln --symbolic ${E}/.config/gh g1`,
    `ln -s ${E}/.config/gh sub/`,
    `ln -s ${E}/.config/gh sub/g1`,
    `ln -sr ${E}/.config/gh g1`,
    `ln -s ${E}/.docker dk`,
    `ln -s ${E}/.cargo c`,
    `ln -s ${E}/.local/share s`,
    `ln -s ${E}/.local s`,
    `ln -s ${E}/.terraform.d t`,
    `cp -rs ${E}/.config/gh g1`,
    `cp -rs ${E}/.config g3`,
    // Through an earlier link, and relative to the link's own directory.
    "ln -s pl/../gh g7",
    "ln -s ../pl/../gh sub/g8",
    "ln -s pl/../gh/hosts.yml g6",
    "ln -s ../pl/../gh/hosts.yml sub/g10",
    // In the same call as the read through it (the link does not exist when the call is judged).
    `ln -s ${E}/.config/gh g1; cat g1/hosts.yml`,
    `ln -s ${E}/.config g3 && cat g3/gh/hosts.yml`,
    `ln -sf ${E}/.config/gh g1 && grep -r tok g1`,
  ], (r) => assert.match(r, /credential/));
  // Asked before, for another reason (the rules read the link's directory as what ln writes, or
  // the target's own text names the credential): they hold.
  rows("2 (held)", "ask", [`ln -s -t sub ${E}/.config/gh`, `ln -s --target-directory=sub ${E}/.config/gh`, `ln -s ${E}/.config/gh`, `cp -s ${E}/.config/gh/hosts.yml h`, "ln pl/../gh/hosts.yml hard", `ln -s ${E}/.config/gh/hosts.yml g9`, `ln -s ${E}/.aws a1`]);
  rows("2 (names both)", "ask", [`ln -s ${E}/.config/gh g1`], namesBoth(`${E}/.config/gh`, () => path.join(gh(), "hosts.yml")));
  // The places named from the root: a link to `/` or `/etc` hides `/etc/shadow` from the text.
  rows("2 (root)", "ask", fs.existsSync("/etc/shadow") ? ["ln -s /etc e", "ln -s / r", "ln -s /etc/../ r"] : []);
  rows("2 (root)", "ask", ["ln -s /proc p", "ln -s /proc/self ps", ...(fs.readdirSync("/etc/ssh").some((n) => /^ssh_host_\w+_key$/.test(n)) ? ["ln -s /etc/ssh s"] : []), ...(fs.existsSync("/etc/ssl/private") ? ["ln -s /etc/ssl s"] : [])], (r) => assert.match(r, /credential location/));
  rows("2 (Library)", "ask", [`ln -s ${E}/Library l`], (r) => assert.match(r, /credential location/));
  // A link to a home: the credential's own names and places stay in the path through it.
  rows("2 (as before)", "allow", [
    "ln -s src/main.c m2.c",
    "ln -s ../f sub/f2",
    "ln -s src s2",
    "ln -s /usr/share/doc d",
    `ln -s ${E}/.config/plain p2`,
    `ln -s ${E}/plain p3`,
    `ln -s ${E} h`,
    `ln -s ${E}/nothing-here x`,
    `ln -s ${E}/empty/.config c`,
    "ln -s src/main.c m2.c && cat m2.c",
    "ln -s /usr/share/doc d && ls d",
    `ln -s ${E} h && ls h`,
    `ln -s ${E}/.config/plain p2 && cat p2/settings.json`,
    "ln -s /proc/cpuinfo c",
    // A copy, not a link (a recursive copy of the directory reads it by its own path as before).
    `cp -r ${E}/.config/gh c`,
    `cp -R ${E}/.config c`,
  ]);
  // A link to a home, then a read of its credentials through it: the text names them.
  rows("2 (names in the text)", "ask", [`ln -s ${E} h && cat h/.config/gh/hosts.yml`, `ln -s ${E} h && cat h/.netrc`, `ln -s ${E} h && cat h/.aws/credentials`]);
  test("B11-2: ask: `ln -s ~/.config/gh g1` with the place in the home", async () => {
    const home = os.homedir();
    const made = !fs.existsSync(path.join(home, ".config/gh"));
    write(path.join(home, ".config/gh/hosts.yml"), "DECOY\n");
    try {
      for (const c of ["ln -s ~/.config/gh g1", "ln -s ~/.config g3", "ln -s $HOME/.config/gh g1", 'ln -s "$HOME/.config" g3', "ln -s ~/.config/gh g1; cat g1/hosts.yml"]) {
        const got = await outcome(c);
        assert.equal(got.kind, "ask", got.reason);
      }
    } finally {
      if (made) fs.rmSync(path.join(home, ".config/gh"), { recursive: true, force: true });
    }
  });
});

describe("B11-2/3: a link the same call makes, walked as made", () => {
  rows("2+3", "ask", [
    `ln -s ${E}/.config/plain pl4; cat pl4/../gh/hosts.yml`,
    `ln -s ${E}/.config/plain pl4 && head -1 pl4/../gcloud/credentials.db`,
    `ln -sfn ${E}/.config/plain hl && cat hl/../gh/hosts.yml`,
    `mkdir -p d2 && ln -s ${E}/.config/plain d2/pl && cat d2/pl/../gh/hosts.yml`,
    `ln -s ${E}/.config/plain sub/ && cat sub/plain/../gh/hosts.yml`,
    `ln -s ${E}/.local/share/other o && cp o/../keyrings/login.keyring x`,
  ], (r) => assert.match(r, /which leads to/));
  // (The rules ask about `-t` for another reason: they read its directory as what ln writes.)
  rows("2+3 (held)", "ask", [`ln -s -t sub ${E}/.config/plain && cat sub/plain/../gh/hosts.yml`]);
  rows("2+3", "ask", [`ln -s ${E}/.config/plain pl5 && ln -s pl5/../gh g11`], (r) => assert.match(r, /credential location/));
  rows("2+3 (as before)", "allow", [`ln -s ${E}/.config/plain p6 && cat p6/settings.json`, "ln -s src s7 && cat s7/../f", `ln -s ${E}/.config/plain p6 && cat p6/../plain/settings.json`]);
});

describe("B11-3: a link made earlier", () => {
  test("B11-3: a link an earlier call made, then a read through it and `..`", async () => {
    const s = new SessionState(repo);
    const link = path.join(repo, "pl3");
    const made = await outcome(`ln -s ${E}/.config/plain pl3`, s);
    assert.equal(made.kind, "allow", made.reason);
    fs.symlinkSync(path.join(E, ".config/plain"), link);
    try {
      for (const c of ["cat pl3/../gh/hosts.yml", "head pl3/../gcloud/credentials.db", "cp pl3/../gh/hosts.yml x", "grep -h tok pl3/../gh/hosts.yml"]) {
        const got = await outcome(c, s);
        assert.equal(got.kind, "ask", got.reason);
        assert.match(got.reason, /which leads to/);
      }
      for (const c of ["cat pl3/settings.json", "ls pl3/..", "cat pl3/../plain/settings.json"]) {
        const got = await outcome(c, s);
        assert.equal(got.kind, "allow", got.reason);
      }
    } finally {
      fs.rmSync(link, { force: true });
    }
  });
  // Made before the session (the fixture's g2 -> E/.config/gh/hosts.yml): the rules resolve it.
  rows("3 (held)", "ask", ["cat g2", "cp -L g2 /tmp/x", "head g2", "grep tok g2", "cat < g2", "ln -s g2 g4", "ln g2 hard"]);
});

describe("B11-4: what stays", () => {
  rows("4", "allow", [
    "cat node_modules/left-pad/index.js",
    "head node_modules/left-pad/../left-pad/index.js",
    "ls share/doc",
    "ls share/..",
    "cat m.c",
    "grep main m.c src/main.c",
    "cp m.c out.c",
    "wc -l share/../../etc/hostname",
  ]);
});

// The F6 writer's finding: a `..` after a link takes a write outside the project too. The rules
// normalise a written path before they resolve its links, as for a read: `pl/../x` is the project's
// `x` to them and E/.config/x to the kernel. With `sandbox: false` such a write lands without a
// prompt. Each written word and redirect target is judged again as the kernel walks it, a link the
// same call makes included.
describe("B11-5: a write judged by where it leads", () => {
  rows("5", "ask", [
    "echo x > pl/../x",
    "echo x >> pl/../x",
    "echo x > ./pl/../x",
    "echo x > pl/../plain/settings.json",
    "printf x 1> pl/../x",
    "cat f > pl/../x",
    "cp f pl/../x",
    "cp f pl/../plain/settings.json",
    "touch pl/../x",
    "mv f pl/../moved",
    "sed -i s/a/b/ pl/../plain/settings.json",
    "tee pl/../x < f",
    "rm pl/../plain/settings.json",
    "dd if=f of=pl/../x",
    "cd sub && echo x > ../pl/../x",
    "cd sub && cp ../f ../pl/../x",
    "true && echo x > pl/../x",
    `ln -s ${E}/.config/plain p8; echo x > p8/../x`,
    `ln -s ${E}/.config/plain p8 && cp f p8/../x`,
    // A link the call makes, written through without a `..`: the rules see a name in the project.
    `ln -s ${E}/.config/plain p8 && echo x > p8/y`,
    `ln -s ${E}/.config/plain p8 && cp f p8/`,
    `ln -s ${E}/.config/plain/settings.json s10 && echo x > s10`,
    `ln -sf ${E}/.config/plain/settings.json f && cat sub/notes.txt > f`,
  ], (r) => assert.match(r, /leads to/));
  rows("5 (as before)", "allow", [
    "echo x > src/../out",
    "echo x > sl/../out",
    "cp f sl/../out2",
    "touch sub/new",
    "echo x > /dev/null",
    "cat pl/../x",
    "ls pl/..",
    "echo x > out && cat pl/settings.json",
    "ln -s src s9 && echo x > s9/../out",
  ]);
});

// The Sonnet check of F6 and its write part (closing): S1 a relative target through a directory the
// call makes; S2 a `<` input through a link the call makes; S3 `~+` in ln's target; S4 a link cp
// copies as a link or mv moves; S5 a written path through `$PWD`; S6 an answer of the model's for
// the walked path; C1 `ln -s ../..` judged as a loop up to `/`; mv of a made link.
describe("B11-6: the Sonnet check's finds", () => {
  rows("6 S1", "ask", [
    "mkdir d9; ln -s ../../elsewhere/.config/gh d9/g; cat d9/g/hosts.yml",
    "mkdir d9; ln -s ../../elsewhere/.config d9/c; cat d9/c/gh/hosts.yml",
    "mkdir -p d9/e; ln -s ../../../elsewhere/.config/gh d9/e/g; cat d9/e/g/hosts.yml",
    "mkdir d9; ln -s ../../elsewhere/.config/plain d9/p; cat d9/p/../gh/hosts.yml",
  ]);
  rows("6 S2", "ask", [`ln -s ${E}/.config/plain p9; cat <p9/../gh/hosts.yml`, `ln -s ${E}/.config/plain p9; wc -l < p9/../gh/hosts.yml`]);
  rows("6 S3", "ask", ["ln -s ~+/../elsewhere/.config/gh g9; cat g9/hosts.yml", "ln -s ~+/../elsewhere/.config/plain p9; cat p9/../gh/hosts.yml", "ln -s ~+/../elsewhere/plain o9; echo x > o9/x"]);
  rows("6 S4", "ask", [
    `ln -s ${E}/.config/plain pa; cp -P pa pb; cat pb/../gh/hosts.yml`,
    `ln -s ${E}/.config/plain pa; cp -a pa pb; cat pb/../gh/hosts.yml`,
    `ln -s ${E}/.config/plain pa; cp -d pa pb; cat pb/../gh/hosts.yml`,
    `ln -s ${E}/.config/plain pa; cp --no-dereference pa pb; cat pb/../gh/hosts.yml`,
    `ln -s ${E}/.config/plain pa; mv pa sub/; cat sub/pa/../gh/hosts.yml`,
    "cp -P pl pb && cat pb/../gh/hosts.yml",
    "cp -P pl pb && echo x > pb/x",
    "mv pl pm && cat pm/../gh/hosts.yml",
    "ln -s ../elsewhere/plain o8; cp -P o8 o9; echo x > o9/x",
  ]);
  rows("6 S5", "ask", ['echo x > "$PWD/pl/../x"', "echo x > ${PWD}/pl/../x", 'touch "$PWD/pl/../x"', 'tee "$PWD/pl/../x" < f']);
  // (rules.ts follows a variable the call sets to plain text, so `$d` is `$PWD` here: an ask, as
  // for the spelling above. It used to leave these to the model.)
  rows("6 S5 (an expansion before a ..)", "ask", ["d=$PWD; echo x > $d/pl/../x", "d=$PWD; touch $d/pl/../x", "d=$PWD; tee $d/pl/../x < f"]);
  // (`tar --directory=<outside> -xf` is a rule allow without any link too: the sandbox stops the
  // write, and with it off decision 16 asks for every extraction.)
  rows("6 S6", "classify", ["tar cf z.tar f; tar xf z.tar -C pl/..", "tar cf z.tar f; tar -xf z.tar -C pl/../plain"]);
  rows("6 C1 (as before)", "allow", ["ln -s ../.. up", "ln -s ../.. sub/x", "cd sub && ln -s ../.. up", `ln -s ${E}/.config/plain pa && mv pa pb`, "ln -s src s8 && cp -P s8 s9 && cat s9/main.c"]);
});
