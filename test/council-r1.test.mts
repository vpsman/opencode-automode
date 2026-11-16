// Council round 1: an edit or a write through a link whose target is not there yet is judged where
// the link leads; a write through a link the call makes into .git asks; a saved "Always allow" for `git stash` or `git restore` is not mirrored into the rules.
// Run: node test/run.mjs test/council-r1.test.mts.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_ASK, decideFile, decideShell, mirrorable, SessionState, takeMoment, type Guard } from "../decide.ts";
import { plan, protectedPaths } from "../sandbox.ts";
import { canonical } from "../canon.ts";
SessionState.moment = takeMoment;
import { compileRules } from "../rules.ts";
import { DEFAULT_CLASSIFIER } from "../kev.ts";

assert.ok(process.env.GIT_CONFIG_GLOBAL?.startsWith(os.homedir()), "run through test/run.mjs, which supplies a throwaway $HOME");
const base = fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), "council-r1-")));
const repo = path.join(base, "repo");
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

before(() => {
  fs.mkdirSync(repo, { recursive: true });
  fs.writeFileSync(path.join(repo, "f"), "x\n");
  execFileSync("git", ["init", "-q", "-b", "main", repo]);
  execFileSync("git", ["-C", repo, "add", "-A"]);
  execFileSync("git", ["-C", repo, "commit", "-qm", "init"]);
  // Links whose targets are not there: outside the project, and into .git.
  fs.symlinkSync(path.join(os.homedir(), ".bash_profile_missing"), path.join(repo, "notes.md"));
  fs.symlinkSync(".git/hooks/pre-commit", path.join(repo, "hook.txt"));
  fs.symlinkSync("chain1", path.join(repo, "chain0"));
  fs.symlinkSync(path.join(os.homedir(), "deep", "x"), path.join(repo, "chain1"));
  // (Round 2: a `..` after a link in the target is taken after the link, as the kernel takes it.)
  fs.mkdirSync(path.join(base, "deep"));
  fs.symlinkSync("../deep", path.join(repo, "pivot"));
  fs.symlinkSync("pivot/../.bash_profile", path.join(repo, "pivoted.md"));
});
after(() => fs.rmSync(base, { recursive: true, force: true }));

const effect = async (command: string) => (await decideShell(guard, new SessionState(repo), repo, command)).effect;

test("an edit through a link whose target is not there is judged where it leads", () => {
  for (const name of ["notes.md", "hook.txt", "chain0", "pivoted.md"]) {
    const d = decideFile(guard, new SessionState(repo), repo, path.join(repo, name));
    assert.equal(d?.effect, "ask", `${name}: ${JSON.stringify(d)}`);
  }
  // A plain new file in the project is as before.
  assert.equal(decideFile(guard, new SessionState(repo), repo, path.join(repo, "new.md"))?.effect ?? "allow", "allow");
});

test("a shell write through a link whose target is not there is judged where it leads", async () => {
  assert.notEqual(await effect("printf x >> notes.md"), "allow");
  assert.notEqual(await effect("echo x > hook.txt"), "allow");
  assert.equal(await effect("echo x > plain.txt"), "allow");
});

test("a write through a link the same call makes into .git asks", async () => {
  assert.notEqual(await effect("ln -s .git/hooks/post-checkout h2 && echo x > h2"), "allow");
  assert.notEqual(await effect("ln -s .git/hooks/post-checkout h3 && tee h3 < f"), "allow");
  assert.equal(await effect("ln -s f h4 && echo x > h4"), "allow");
});

test("git tag -f with a name asks; a plain tag and a listing do not", async () => {
  for (const c of ["git tag -f v1 HEAD", "git tag --force v1", "git tag -af v1 -m x"]) assert.notEqual(await effect(c), "allow", c);
  for (const c of ["git tag v2", "git tag -l"]) assert.equal(await effect(c), "allow", c);
});

test("a heredoc cat is folded only where the cat PATH finds is not one a call can write", async () => {
  const commit = `git commit --allow-empty -m "$(cat <<'EOF'\nmessage\nEOF\n)"`;
  assert.equal(await effect(commit), "allow");
  const bin = path.join(repo, "bin");
  fs.mkdirSync(bin, { recursive: true });
  fs.writeFileSync(path.join(bin, "cat"), "#!/bin/sh\necho WRAPPED\n", { mode: 0o755 });
  const before = process.env.PATH;
  process.env.PATH = `${bin}:${before}`;
  try {
    const d = await decideShell(guard, new SessionState(repo), repo, commit);
    assert.equal(d.effect, "ask");
    assert.match(d.reason, /cat it would run/);
  } finally {
    process.env.PATH = before;
    fs.rmSync(bin, { recursive: true, force: true });
  }
});

test("Always allow for git stash or git restore is not mirrored", () => {
  for (const p of ["git stash *", "git stash drop *", "git restore *"]) assert.equal(mirrorable(p), false, p);
  for (const p of ["git status *", "git commit *", "git checkout *"]) assert.equal(mirrorable(p), true, p);
});

// Round 2 and 3: the links inside the directories opencode or a git hook runs from. Each case in a
// repository of its own: what cannot be protected makes every call there ask.
let n = 0;
function project(setup: (r: string) => void): string {
  const r = path.join(base, `p${n++}`);
  fs.mkdirSync(r);
  execFileSync("git", ["init", "-q", "-b", "main", r]);
  for (const d of [".opencode/plugin", ".husky", ".claude", ".agents", "tools", "scripts", "other"]) fs.mkdirSync(path.join(r, d), { recursive: true });
  setup(r);
  return r;
}
const paths = (r: string) => protectedPaths({ projectRoots: [r], allowedPaths: [], project: r });
const planned = (r: string) => plan({ project: r, projectRoots: [r], allowedPaths: [], cacheDirs: [], gitWritable: false, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [] });
const edit = (r: string, file: string) => decideFile(guard, new SessionState(r), r, path.join(r, file))?.effect ?? "allow";

test("a link in .opencode/ or .husky/ to a project file makes that file read-only", () => {
  const r = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "x.ts"), "export {};\n");
    fs.writeFileSync(path.join(r, "scripts", "pc"), "#!/bin/sh\n", { mode: 0o755 });
    fs.symlinkSync("../../tools/x.ts", path.join(r, ".opencode", "plugin", "x.ts"));
    fs.symlinkSync("../scripts/pc", path.join(r, ".husky", "pre-commit"));
  });
  const p = paths(r);
  assert.deepEqual(p.problems, []);
  for (const f of ["tools/x.ts", "scripts/pc"]) {
    assert.ok(p.paths.includes(path.join(r, f)), f);
    assert.equal(edit(r, f), "ask", f);
  }
  const q = planned(r);
  assert.equal(q.problem, undefined, q.problem);
  for (const f of ["tools/x.ts", "scripts/pc"]) assert.ok(q.ro.includes(path.join(r, f)), f);
  // The link itself, and a file nothing links to, as before.
  assert.equal(edit(r, ".opencode/plugin/x.ts"), "ask");
  assert.equal(edit(r, "tools/other.ts"), "allow");
});

test("a link in .claude/ to a directory of the project makes it read-only; one holding a link asks", () => {
  const r = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "z.md"), "z\n");
    fs.symlinkSync("../tools", path.join(r, ".claude", "commands"));
  });
  const p = paths(r);
  assert.deepEqual(p.problems, []);
  assert.ok(p.paths.includes(path.join(r, "tools")));
  assert.equal(edit(r, "tools/z.md"), "ask");
  // (Round 7: links are followed one level; a link inside a linked directory asks.)
  const q = project((r) => {
    fs.writeFileSync(path.join(r, "other", "z.md"), "z\n");
    fs.symlinkSync("../other/z.md", path.join(r, "tools", "z.md"));
    fs.symlinkSync("../tools", path.join(r, ".claude", "commands"));
  });
  assert.ok(paths(q).problems.some((x) => /not followed this far/.test(x)));
  assert.equal(edit(q, "other/z.md"), "ask");
});

test("a link in .claude/ to a place no call can write is left as it is", () => {
  const shared = fs.mkdtempSync(path.join(base, "shared-"));
  const r = project((r) => fs.symlinkSync(shared, path.join(r, ".claude", "skills")));
  assert.deepEqual(paths(r).problems, []);
  assert.equal(edit(r, "tools/a.ts"), "allow");
});

test("a link in .opencode/ or .husky/ that cannot be protected makes every call ask", () => {
  const cases: [string, (r: string) => void][] = [
    ["a target not there yet", (r) => fs.symlinkSync("../../tools/x.ts", path.join(r, ".opencode", "plugin", "x.ts"))],
    ["a hook's script not there yet", (r) => fs.symlinkSync("../scripts/pc", path.join(r, ".husky", "pre-commit"))],
    ["through a link a command could replace", (r) => {
      fs.writeFileSync(path.join(r, "tools", "y.ts"), "export {};\n");
      fs.symlinkSync("tools", path.join(r, "lnk"));
      fs.symlinkSync("../../lnk/y.ts", path.join(r, ".opencode", "plugin", "y.ts"));
    }],
    ["a file with another name", (r) => {
      fs.writeFileSync(path.join(r, "tools", "h.ts"), "export {};\n");
      fs.linkSync(path.join(r, "tools", "h.ts"), path.join(r, "other", "h.ts"));
      fs.symlinkSync("../../tools/h.ts", path.join(r, ".opencode", "plugin", "h.ts"));
    }],
  ];
  for (const [what, setup] of cases) {
    const r = project(setup);
    assert.ok(paths(r).problems.length > 0, what);
    assert.ok(planned(r).problem, what);
    assert.equal(edit(r, "new.md"), "ask", what);
  }
});

// Round 4: the findings on the link walk.
test("round 4: a file with another name in a linked directory asks", () => {
  const r = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "x.sh"), "#!/bin/sh\n");
    fs.linkSync(path.join(r, "tools", "x.sh"), path.join(r, "other", "alias.sh"));
    fs.symlinkSync("../tools", path.join(r, ".claude", "commands"));
  });
  assert.ok(paths(r).problems.some((x) => /hard link/.test(x)));
  assert.equal(edit(r, "other/alias.sh"), "ask");
});

test("round 4: a link to a temp directory is protected for the edit tool too", () => {
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "council-r4-")));
  try {
    const target = path.join(tmp, "external.sh");
    fs.writeFileSync(target, "#!/bin/sh\n");
    const r = project((r) => fs.symlinkSync(target, path.join(r, ".claude", "x.sh")));
    assert.ok(paths(r).paths.includes(target));
    assert.equal(decideFile(guard, new SessionState(r), r, target)?.effect, "ask");
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

test("round 4: a chain through another protected directory is held there", () => {
  const r = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "x.sh"), "#!/bin/sh\n");
    fs.symlinkSync("../tools/x.sh", path.join(r, ".agents", "x.sh"));
    fs.symlinkSync("../.agents/x.sh", path.join(r, ".claude", "x.sh"));
  });
  const p = paths(r);
  assert.deepEqual(p.problems, []);
  assert.ok(p.paths.includes(path.join(r, "tools", "x.sh")));
});

test("round 4: a large node_modules in .opencode/ and links inside it are no problem", () => {
  const r = project((r) => {
    const big = path.join(r, ".opencode", "node_modules", "big");
    fs.mkdirSync(big, { recursive: true });
    for (let i = 0; i < 10_050; i++) fs.writeFileSync(path.join(big, `f${i}`), "");
    fs.mkdirSync(path.join(r, ".opencode", "node_modules", ".bin"));
    fs.symlinkSync("../big/f1", path.join(r, ".opencode", "node_modules", ".bin", "f1"));
    // A link to a file not there, inside the read-only directory itself: nothing can make it.
    fs.symlinkSync("missing.js", path.join(r, ".opencode", "x.js"));
  });
  assert.deepEqual(paths(r).problems, []);
  assert.equal(edit(r, "new.md"), "allow");
});

test("round 4: a directory no call can write is walked for links back into the project", () => {
  const shared = fs.mkdtempSync(path.join(base, "shared-"));
  const r = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "x.ts"), "export {};\n");
    fs.symlinkSync(path.join(r, "tools", "x.ts"), path.join(shared, "x.ts"));
    fs.symlinkSync(shared, path.join(r, ".opencode", "plugin", "shared"));
  });
  // (Round 7: not followed this far; it asks.)
  assert.ok(paths(r).problems.some((x) => /not followed this far/.test(x)));
  assert.equal(edit(r, "tools/x.ts"), "ask");
});

test("round 4: a command that defines a function is not counted as folding a heredoc cat", () => {
  const p = canonical(`f() { :; }; git commit -m "$(cat <<'EOF'\nm\nEOF\n)"`);
  assert.ok(!("ask" in p) && !p.folded, JSON.stringify(p));
  const q = canonical(`git commit -m "$(cat <<'EOF'\nm\nEOF\n)"`);
  assert.ok(!("ask" in q) && q.folded);
});

// Round 5.
test("round 5: a link to a directory that holds the project does not count the project as read-only", () => {
  const r = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "x.ts"), "export {};\n");
    fs.symlinkSync("../../tools/x.ts", path.join(r, ".opencode", "plugin", "x.ts"));
    fs.symlinkSync("../..", path.join(r, ".opencode", "up"));
  });
  assert.ok(paths(r).paths.includes(path.join(r, "tools", "x.ts")));
  assert.ok(planned(r).ro.includes(path.join(r, "tools", "x.ts")));
  assert.equal(edit(r, "tools/x.ts"), "ask");
});

test("round 5: a link to a file outside the writable directories with another name asks", () => {
  const outside = fs.mkdtempSync(path.join(base, "outside-"));
  const r = project((r) => {
    fs.writeFileSync(path.join(outside, "x.ts"), "export {};\n");
    fs.linkSync(path.join(outside, "x.ts"), path.join(r, "alias.ts"));
    fs.symlinkSync(path.join(outside, "x.ts"), path.join(r, ".claude", "x.ts"));
  });
  assert.ok(paths(r).problems.some((x) => /hard link/.test(x)));
  assert.equal(edit(r, "alias.ts"), "ask");
});

test("round 5: a chain from .claude/ through .husky/ is held there", () => {
  const r = project((r) => {
    fs.writeFileSync(path.join(r, "scripts", "x"), "#!/bin/sh\n");
    fs.symlinkSync("../scripts/x", path.join(r, ".husky", "x"));
    fs.symlinkSync("../.husky/x", path.join(r, ".claude", "x"));
  });
  const p = paths(r);
  assert.deepEqual(p.problems, []);
  assert.ok(p.paths.includes(path.join(r, "scripts", "x")));
});

// Round 6.
test("round 6: a linked directory that cannot be listed asks", () => {
  const ext = fs.mkdtempSync(path.join(base, "ext-"));
  const r = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "x.ts"), "export {};\n");
    fs.symlinkSync(path.join(r, "tools", "x.ts"), path.join(ext, "x.ts"));
    fs.symlinkSync(ext, path.join(r, ".claude", "commands"));
  });
  fs.chmodSync(ext, 0o111);
  try {
    assert.ok(paths(r).problems.some((x) => /cannot be listed/.test(x)));
    assert.equal(edit(r, "tools/x.ts"), "ask");
  } finally {
    fs.chmodSync(ext, 0o755);
  }
});

test("round 6: the order of the links does not decide", () => {
  for (const first of ["a", "zz"]) {
    const r = project((r) => {
      fs.writeFileSync(path.join(r, "scripts", "x"), "#!/bin/sh\n");
      fs.symlinkSync("../scripts/x", path.join(r, "tools", "x"));
      fs.symlinkSync("../tools/x", path.join(r, ".claude", first));
      fs.symlinkSync("../tools", path.join(r, ".claude", "z"));
    });
    // (Round 7: the same in either order: a link inside a linked directory asks.)
    assert.ok(paths(r).problems.length > 0, first);
  }
});

test("round 6: a .. after a step not there yet is judged at that step", () => {
  const r = project((r) => fs.symlinkSync("../../tools/n/../../../outside/x.ts", path.join(r, ".opencode", "plugin", "x.ts")));
  assert.ok(paths(r).problems.some((x) => /is not there/.test(x)));
  // Inside a read-only directory nothing can be put: no problem.
  const q = project((r) => fs.symlinkSync("n/../y.ts", path.join(r, ".opencode", "x.ts")));
  assert.deepEqual(paths(q).problems, []);
});

test("round 6: a link to a directory that holds or is a writable one asks", () => {
  for (const to of ["../..", ".."]) {
    const r = project((r) => fs.symlinkSync(to, path.join(r, ".claude", "commands")));
    assert.ok(paths(r).problems.some((x) => /is or holds a directory a command can write/.test(x)), to);
  }
});

test("round 6: a checkout in a temp directory with a broken hook link is not this project's matter", () => {
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "council-r6-")));
  try {
    execFileSync("git", ["init", "-q", "-b", "main", tmp]);
    fs.mkdirSync(path.join(tmp, ".husky"));
    fs.symlinkSync("../scripts/missing", path.join(tmp, ".husky", "pre-commit"));
    const r = project(() => {});
    const q = planned(r);
    assert.equal(q.problem, undefined, q.problem);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Round 7.
test("round 7: a file with more of the path after it asks", () => {
  const r = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "blocker"), "");
    fs.mkdirSync(path.join(r, "tools", "safe"));
    fs.writeFileSync(path.join(r, "tools", "safe", "x"), "");
    fs.symlinkSync("../tools/blocker/../safe/x", path.join(r, ".claude", "x"));
  });
  assert.ok(paths(r).problems.some((x) => /cannot follow/.test(x)));
});

test("round 7: a checkout in a temp directory does not change what the project's own links are judged by", () => {
  const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "council-r7-")));
  try {
    const r = project((r) => {
      fs.symlinkSync("../gen/missing.ts", path.join(r, "tools", "y.ts"));
      fs.symlinkSync("../tools", path.join(r, ".claude", "commands"));
    });
    execFileSync("git", ["init", "-q", "-b", "main", tmp]);
    fs.mkdirSync(path.join(tmp, ".husky"));
    fs.symlinkSync(path.join(r, "tools"), path.join(tmp, ".husky", "h"));
    for (let i = 0; i < 70; i++) {
      fs.mkdirSync(path.join(tmp, `d${i}`));
      fs.symlinkSync(path.join(tmp, `d${i}`), path.join(tmp, ".husky", `l${i}`));
    }
    assert.ok(planned(r).problem);
    assert.ok(paths(r).problems.length > 0);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

// Round 8.
test("round 8: a file in a protected directory with another name asks, under node_modules too", () => {
  const cases: [string, (r: string) => void][] = [
    ["a hard link in .opencode/", (r) => {
      fs.writeFileSync(path.join(r, "tools", "x.ts"), "export {};\n");
      fs.linkSync(path.join(r, "tools", "x.ts"), path.join(r, ".opencode", "plugin", "x.ts"));
    }],
    ["a hard link in .husky/", (r) => {
      fs.writeFileSync(path.join(r, "scripts", "pc"), "#!/bin/sh\n");
      fs.linkSync(path.join(r, "scripts", "pc"), path.join(r, ".husky", "pre-commit"));
    }],
    ["a link to a hard-linked file in .opencode/", (r) => {
      fs.mkdirSync(path.join(r, ".opencode", "shared"));
      fs.writeFileSync(path.join(r, "tools", "alias.ts"), "export {};\n");
      fs.linkSync(path.join(r, "tools", "alias.ts"), path.join(r, ".opencode", "shared", "x.ts"));
      fs.symlinkSync("../shared/x.ts", path.join(r, ".opencode", "plugin", "x.ts"));
    }],
  ];
  for (const [what, setup] of cases) {
    const r = project(setup);
    assert.ok(paths(r).problems.some((x) => /hard link/.test(x)), what);
    assert.ok(planned(r).problem, what);
  }
  // (Round 10: under node_modules too, saying how to reinstall as copies.)
  const r = project((r) => {
    const pkgDir = path.join(r, ".opencode", "node_modules", "pkg");
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(r, "other", "store.js"), "\n");
    fs.linkSync(path.join(r, "other", "store.js"), path.join(pkgDir, "index.js"));
  });
  assert.ok(paths(r).problems.some((x) => /--backend=copyfile/.test(x) && x.includes(`In ${path.join(r, ".opencode")}, remove node_modules`)));
  assert.match(planned(r).problem ?? "", /copyfile/);
  // pnpm's layout: the directory to install in is the one above the outermost node_modules.
  const pn = project((r) => {
    const deep = path.join(r, ".opencode", "node_modules", ".pnpm", "pkg@1", "node_modules", "pkg");
    fs.mkdirSync(deep, { recursive: true });
    fs.writeFileSync(path.join(r, "other", "s.js"), "\n");
    fs.linkSync(path.join(r, "other", "s.js"), path.join(deep, "index.js"));
    fs.linkSync(path.join(r, "other", "s.js"), path.join(r, "other", "t.js"));
  });
  const msg = paths(pn).problems.find((x) => /copyfile/.test(x)) ?? "";
  assert.ok(msg.includes(`In ${path.join(pn, ".opencode")}, remove node_modules`), msg);
  assert.match(msg, /more than one name/);
  // Installed as copies: nothing to ask.
  const q = project((r) => {
    const pkgDir = path.join(r, ".opencode", "node_modules", "pkg");
    fs.mkdirSync(pkgDir, { recursive: true });
    fs.writeFileSync(path.join(pkgDir, "index.js"), "\n");
  });
  assert.deepEqual(paths(q).problems, []);
});

test("round 8: .opencode/ in a writable parent in a temp directory is followed", () => {
  const parent = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "council-r8-")));
  try {
    const r = path.join(parent, "repo");
    fs.mkdirSync(path.join(r, "tools"), { recursive: true });
    execFileSync("git", ["init", "-q", "-b", "main", r]);
    fs.writeFileSync(path.join(r, "tools", "x.ts"), "export {};\n");
    fs.mkdirSync(path.join(parent, ".opencode", "plugin"), { recursive: true });
    fs.symlinkSync(path.join(r, "tools", "x.ts"), path.join(parent, ".opencode", "plugin", "x.ts"));
    assert.ok(planned(r).ro.includes(path.join(r, "tools", "x.ts")));
    assert.ok(paths(r).paths.includes(path.join(r, "tools", "x.ts")));
    assert.equal(edit(r, "tools/x.ts"), "ask");
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("round 8: a .. out of a directory a command could replace asks", () => {
  const r = project((r) => {
    fs.mkdirSync(path.join(r, "tools", "sub"));
    fs.writeFileSync(path.join(r, "tools", "x.ts"), "export {};\n");
    fs.symlinkSync("../../tools/sub/../x.ts", path.join(r, ".opencode", "plugin", "x.ts"));
  });
  assert.ok(paths(r).problems.some((x) => /steps out of/.test(x)));
  // The usual `../../tools/x.ts` steps out of protected directories only.
  const q = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "x.ts"), "export {};\n");
    fs.symlinkSync("../../tools/x.ts", path.join(r, ".opencode", "plugin", "x.ts"));
  });
  assert.deepEqual(paths(q).problems, []);
});

// After the council: hookScript's `..`, and a package store a call can write.
test("a hook link whose .. steps out of a directory a call could replace asks; the usual one does not", () => {
  const r = project((r) => {
    fs.mkdirSync(path.join(r, "tools", "sub"));
    fs.writeFileSync(path.join(r, "tools", "pc"), "#!/bin/sh\n", { mode: 0o755 });
    fs.mkdirSync(path.join(r, ".git", "hooks"), { recursive: true });
    fs.symlinkSync("../../tools/sub/../pc", path.join(r, ".git", "hooks", "pre-commit"));
  });
  assert.ok(planned(r).problem);
  const q = project((r) => {
    fs.writeFileSync(path.join(r, "tools", "pc"), "#!/bin/sh\n", { mode: 0o755 });
    fs.mkdirSync(path.join(r, ".git", "hooks"), { recursive: true });
    fs.symlinkSync("../../tools/pc", path.join(r, ".git", "hooks", "pre-commit"));
  });
  const p = planned(q);
  assert.equal(p.problem, undefined, p.problem);
  assert.ok(p.ro.includes(path.join(q, "tools", "pc")));
});
