// Round 4, group C, tenth pass: the maintainer's decisions after the two checks of the ninth.
// Any symbolic link in a git directory that is read-only for the call asks, whatever it leads to;
// the one exception, a hook linked to a script of the project, has that script made read-only;
// a hard link among the hooks, the config or info/ asks; every git directory below a named one
// is compared first; `logs` is written with `refs`; `--gpg-sign` in any spelling git takes.
// (The edit of a linked hook's script is held at the hooks too, test/plugin.test.mts.) Each test
// builds a repository of its own under the throwaway home.
// Needs `npm run build:sandbox`. Run alone: node test/run.mjs test/c-tenth.test.mts.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import * as d from "../decide.ts";
import { envKept, gitReadsElsewhere, plan, protectedPaths, realpath, type Plan } from "../sandbox.ts";

const ROOT = path.resolve(import.meta.dirname, "..");
const WRAPPER = path.join(ROOT, "sandbox", "bin", "bash");
const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.homedir(), `c-tenth-${name}-`)));
const gitIn = (dir: string, ...args: string[]) => execFileSync("git", ["-C", dir, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
const commit = (dir: string, message = "one") => gitIn(dir, "commit", "-q", "--allow-empty", "-m", message);
const write = (file: string, text: string | Buffer, mode?: number) => {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, text);
  if (mode !== undefined) fs.chmodSync(file, mode);
};
const mkdir = (dir: string) => {
  fs.mkdirSync(dir, { recursive: true });
  return dir;
};

// An empty repository on `main` with a session that has seen nothing yet, removed afterwards
// with everything beside it that carries its name; `g` runs git in it.
async function fixture(fn: (r: string, g: (...args: string[]) => string, session: d.SessionState) => void | Promise<void>) {
  const r = scratch("repo");
  const g = (...args: string[]) => gitIn(r, ...args);
  const session = new d.SessionState(r);
  try {
    g("init", "-q", "-b", "main");
    await fn(r, g, session);
  } finally {
    d.closeGitSnapshot(session);
    fs.rmSync(r, { recursive: true, force: true });
    for (const beside of fs.readdirSync(path.dirname(r))) if (beside.startsWith(`${path.basename(r)}-`)) fs.rmSync(path.join(path.dirname(r), beside), { recursive: true, force: true });
  }
}
const opts = (r: string) => ({ project: r, projectRoots: [r], allowedPaths: [] as string[], cacheDirs: [], gitWritable: true, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [] });
const planEnv = (p: Plan): Record<string, string> => ({
  AUTOMODE_RW: p.rw.join("\n"),
  AUTOMODE_RO: p.ro.join("\n"),
  AUTOMODE_HIDE: p.hide.join("\n"),
  AUTOMODE_PIN: p.pin.join("\n"),
  AUTOMODE_TMPFS: p.tmpfs.join("\n"),
  AUTOMODE_REOPEN: p.reopen.join("\n"),
});
// One command under the real wrapper with a plan, as index.ts starts it.
function sandboxed(p: Plan, command: string, cwd: string) {
  assert.ok(fs.existsSync(WRAPPER), "run `npm run build:sandbox` first");
  const env: Record<string, string | undefined> = { ...process.env };
  delete env.NODE_TEST_CONTEXT;
  const { keep, dropped } = envKept(env, []);
  for (const name of dropped) delete env[name];
  Object.assign(env, { AUTOMODE_ENV_KEEP: keep.join("\n"), AUTOMODE_SHELL: "/bin/bash", AUTOMODE_COMMAND: command, ...planEnv(p) });
  return spawnSync(WRAPPER, ["-c", command], { cwd, env, stdio: ["ignore", "pipe", "pipe"], encoding: "utf8", timeout: 120_000 });
}
// The plan index.ts makes for an allowed git-only call.
const planFor = (r: string, command: string, cwd = r) =>
  plan({ ...opts(r), gitCwds: d.gitDirectories(command, cwd), gitWriteCwds: d.gitWriteDirectories(command, cwd), gitMaintainCwds: d.gitMaintainDirectories(command, cwd), gitPushTo: d.pushDestinations(command, cwd) });
// The plan of a call that is not git-only: every git directory is read-only whole.
const plainPlan = (r: string) => plan({ ...opts(r), gitWritable: false });
// What makes an edit ask there, and what an edit asks about.
const editProblems = (r: string) => protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).problems;
const editPaths = (r: string) => protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).paths;
function resuming() {
  const file = path.join(scratch("resume"), "resume");
  let last = 0;
  return {
    file,
    touch() {
      last = Math.max(last, Date.now()) + 10;
      fs.writeFileSync(file, "");
      fs.utimesSync(file, new Date(last), new Date(last));
    },
    remove: () => fs.rmSync(path.dirname(file), { recursive: true, force: true }),
  };
}
const FILE = ["-c", "protocol.file.allow=always"];
const LINK = /symbolic link/;
const HARD = /hard links?/;

// A project with the submodules `lib` and `other`, added for real (git keeps their git
// directories under `.git/modules/`), and a linked worktree `wt` inside the project.
async function withLib(fn: (r: string, session: d.SessionState, g: (...args: string[]) => string) => void | Promise<void>) {
  await fixture(async (r, g, session) => {
    const upstream = `${r}-lib-upstream`;
    execFileSync("git", ["init", "-q", "-b", "main", upstream]);
    write(path.join(upstream, "tracked"), "one\n");
    gitIn(upstream, "add", "tracked");
    gitIn(upstream, "commit", "-qm", "lib one");
    commit(r);
    g(...FILE, "submodule", "add", "-q", upstream, "lib");
    g(...FILE, "submodule", "add", "-q", upstream, "other");
    g("commit", "-qm", "two submodules");
    await fn(r, session, g);
  });
}

// ---- 1. any link asks ----

test("r4 21: any symbolic link at any depth of a git directory that is read-only for the call asks, wherever it leads: refs, logs, objects, hooks, info, lfs, a module's and a worktree's admin directory", () =>
  withLib((r, session, g) => {
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    g("worktree", "add", "-q", "-b", "wt", path.join(r, "wt"));
    const wtAdmin = path.join(dotGit, "worktrees", "wt");
    assert.ok(fs.existsSync(path.join(wtAdmin, "HEAD")), "the fixture: a linked worktree");
    gitIn(r, "config", "core.logAllRefUpdates", "true");
    commit(r, "with a reflog");
    mkdir(path.join(dotGit, "lfs", "objects"));
    d.projectRoots(session);
    assert.equal(planFor(r, "git status", lib).problem, undefined, "the fixture: without a link the call is planned");
    assert.equal(plainPlan(r).problem, undefined, "the fixture: a plain call too");
    assert.deepEqual(editProblems(r), [], "the fixture: and an edit");
    const outside = mkdir(`${r}-outside`);
    const inTmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "c-tenth-links-")));
    let n = 0;
    // What the link holds: each a directory, so that no link here has the one shape that does not ask (a hook's script).
    const KINDS: [string, (link: string) => string][] = [
      ["into the project", () => mkdir(path.join(r, "store", `k${n}`))],
      ["outside everything", () => mkdir(path.join(outside, `k${n}`))],
      ["into the temp directory", () => mkdir(path.join(inTmp, `k${n}`))],
      ["relative", (link) => path.relative(path.dirname(link), mkdir(path.join(r, "store", `k${n}`)))],
      ["a chain outside", () => {
        const hop = path.join(outside, `hop${n}`);
        fs.symlinkSync(mkdir(path.join(outside, `end${n}`)), hop);
        return hop;
      }],
      ["broken", () => path.join(outside, `nothing${n}`)],
    ];
    const PLACES: [string, string][] = [
      ["refs", path.join(dotGit, "refs")],
      ["logs", path.join(dotGit, "logs")],
      ["objects", path.join(dotGit, "objects")],
      ["hooks", path.join(dotGit, "hooks")],
      ["info", path.join(dotGit, "info")],
      ["lfs", path.join(dotGit, "lfs")],
      ["the module other", path.join(dotGit, "modules", "other")],
      ["the worktree's admin directory", wtAdmin],
    ];
    try {
      for (const [where, dir] of PLACES) {
        for (let depth = 1; depth <= 6; depth++) {
          for (const [kind, target] of KINDS) {
            n++;
            const between = Array.from({ length: depth - 1 }, (_, k) => `d${n}-${k}`);
            const link = path.join(dir, ...between, `lnk${n}`);
            mkdir(path.dirname(link));
            fs.symlinkSync(target(link), link);
            try {
              for (const [who, problem] of [
                ["a call in the submodule", planFor(r, "git status", lib).problem],
                ["a call that is not git-only", plainPlan(r).problem],
                ["an edit", editProblems(r).find((text) => text.includes(link))],
              ] as const) {
                assert.match(problem ?? "", LINK, `${where}, depth ${depth}, ${kind}, ${who}`);
                assert.ok((problem ?? "").includes(link), `${where}, depth ${depth}, ${kind}, ${who}: ${problem}`);
              }
            } finally {
              fs.rmSync(between.length ? path.join(dir, between[0]) : link, { recursive: true });
            }
          }
        }
      }
    } finally {
      fs.rmSync(inTmp, { recursive: true, force: true });
    }
    // A call in the repository that owns the git directory may write it: a link among its refs
    // is its own, as before.
    const heads = path.join(dotGit, "modules", "lib", "refs", "heads", "lnk");
    fs.symlinkSync(mkdir(path.join(outside, "own")), heads);
    assert.equal(planFor(r, "git status", lib).problem, undefined, "the module's own call");
    assert.ok((planFor(r, "git status", path.join(r, "other")).problem ?? "").includes(heads), "the module beside it has it read-only");
    fs.rmSync(heads);
    assert.equal(plainPlan(r).problem, undefined, "the fixture: put back");
  }));

test("r4 21: a git directory outside every writable directory is read-only for the call too: a link in it asks, wherever it leads; one in a repository of the shared temp directory is left", () =>
  fixture((r, g) => {
    // The project is a linked worktree of `r`, whose git directory lies outside it.
    commit(r);
    const wt = `${r}-wt`;
    g("worktree", "add", "-q", "-b", "wt", wt);
    const ownPlan = (command: string) =>
      plan({ ...opts(wt), gitCwds: d.gitDirectories(command, wt), gitWriteCwds: d.gitWriteDirectories(command, wt), gitMaintainCwds: d.gitMaintainDirectories(command, wt), gitPushTo: d.pushDestinations(command, wt) });
    const plain = () => plan({ ...opts(wt), gitWritable: false });
    assert.equal(plain().problem, undefined, "the fixture");
    const outside = mkdir(`${r}-elsewhere`);
    for (const [kind, target] of [["into the project", mkdir(path.join(wt, "store"))], ["outside everything", outside]] as const) {
      const link = path.join(r, ".git", "refs", "heads", "lnk");
      fs.symlinkSync(target, link);
      try {
        assert.ok((plain().problem ?? "").includes(link), `${kind}: ${plain().problem}`);
        assert.ok(protectedPaths({ projectRoots: [wt], allowedPaths: [], project: wt }).problems.some((t) => t.includes(link)), `${kind}: an edit`);
      } finally {
        fs.rmSync(link);
      }
    }
    // Outside every writable directory no call can write it, a git-only call in the worktree neither.
    fs.symlinkSync(outside, path.join(r, ".git", "refs", "heads", "lnk"));
    assert.ok((ownPlan("git status").problem ?? "").includes("lnk"), ownPlan("git status").problem);
    fs.rmSync(path.join(r, ".git", "refs", "heads", "lnk"));
    assert.equal(ownPlan("git status").problem, undefined, "the fixture: put back");
    // A repository in the temp directory: everything a call could do to it, it can do anyway.
    const inTmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "c-tenth-shared-")));
    try {
      execFileSync("git", ["init", "-q", inTmp]);
      fs.symlinkSync(mkdir(path.join(r, "work")), path.join(inTmp, ".git", "refs", "lnk"));
      assert.equal(plainPlan(r).problem, undefined, plainPlan(r).problem);
    } finally {
      fs.rmSync(inTmp, { recursive: true, force: true });
    }
  }));

test("r4 21: a link whose text has `..` after another link is judged by nothing: the reviewer's spelling asks, and the superproject's refs are not written through it", () =>
  withLib((r, session, g) => {
    const lib = path.join(r, "lib");
    const outside = mkdir(`${r}-outside`);
    const main = g("rev-parse", "main").trim();
    d.projectRoots(session);
    const heads = path.join(r, ".git", "refs", "heads");
    fs.mkdirSync(path.join(r, "work", "sub"), { recursive: true });
    fs.renameSync(heads, path.join(r, "work", "d"));
    fs.symlinkSync(path.join(r, "work", "sub"), path.join(outside, "lnk"));
    fs.symlinkSync(`${outside}/lnk/../d`, heads);
    assert.equal(fs.realpathSync.native(heads), path.join(r, "work", "d"), "the fixture: the kernel ends in the project");
    assert.equal(g("rev-parse", "main").trim(), main, "the fixture: git reads main through it");
    for (const [who, problem] of [
      ["a call in the submodule", planFor(r, "git status", lib).problem],
      ["a call that is not git-only", plainPlan(r).problem],
      ["an edit", editProblems(r).find((text) => text.includes(heads))],
    ] as const) {
      assert.match(problem ?? "", LINK, who);
      assert.ok((problem ?? "").includes(heads), `${who}: ${problem}`);
    }
    // The same spelling for a hook (a file link).
    fs.rmSync(heads);
    fs.renameSync(path.join(r, "work", "d"), heads);
    write(path.join(r, "work", "pc"), "#!/bin/sh\nexit 0\n", 0o755);
    const hook = path.join(r, ".git", "hooks", "pre-commit");
    fs.symlinkSync(`${outside}/lnk/../pc`, hook);
    assert.ok((planFor(r, "git status", lib).problem ?? "").includes(hook));
    assert.ok((plainPlan(r).problem ?? "").includes(hook));
    assert.ok(editProblems(r).some((text) => text.includes(hook)));
  }));

test("r4 21: a path protect follows takes `..` where the kernel takes it: a hooks path and an include spelled through a link outside are protected where git reads them", () =>
  fixture((r, g, session) => {
    commit(r);
    d.projectRoots(session);
    const outside = mkdir(`${r}-outside`);
    // `<outside>/lnk` -> `<project>/work/sub`: `<outside>/lnk/../h` is `<project>/work/h` to the kernel, and `<outside>/h` to the text.
    fs.mkdirSync(path.join(r, "work", "sub"), { recursive: true });
    fs.symlinkSync(path.join(r, "work", "sub"), path.join(outside, "lnk"));
    write(path.join(r, "work", "h", "pre-commit"), "#!/bin/sh\nexit 0\n", 0o755);
    write(path.join(r, "work", "inc.cfg"), "[user]\n\tname = x\n");
    g("config", "core.hooksPath", `${outside}/lnk/../h`);
    g("config", "include.path", `${outside}/lnk/../inc.cfg`);
    assert.equal(g("rev-parse", "--git-path", "hooks/pre-commit").trim(), `${outside}/lnk/../h/pre-commit`, "the fixture: git names it so");
    const p = planFor(r, "git status");
    assert.equal(p.problem, undefined, p.problem);
    for (const where of [path.join(r, "work", "h"), path.join(r, "work", "inc.cfg")]) {
      assert.ok(p.ro.includes(where), `${where} is not protected: ${p.ro.join(", ")}`);
      assert.ok(editPaths(r).includes(where), `${where}: an edit is not asked about`);
    }
    // Run for real: neither the hook nor the include can be rewritten from the sandbox.
    for (const file of [path.join(r, "work", "h", "pre-commit"), path.join(r, "work", "inc.cfg")]) {
      const ran = sandboxed(p, `echo planted >> ${file}`, r);
      assert.notEqual(ran.status, 0, `${file} was written`);
      assert.doesNotMatch(fs.readFileSync(file, "utf8"), /planted/);
    }
    // The path a caller is handed for a path is the kernel's answer (realpath(3)).
    assert.equal(realpath(`${outside}/lnk/../inc.cfg`), path.join(r, "work", "inc.cfg"));
    // The comparison of a named directory reads them where git does.
    const reads = gitReadsElsewhere(path.join(r, ".git"));
    assert.ok(reads.hooks.includes(path.join(r, "work", "h")), reads.hooks.join(", "));
    assert.ok(reads.includes.includes(path.join(r, "work", "inc.cfg")), reads.includes.join(", "));
    // A `..` after a name that is not there: a call could make that name a link, and the kernel
    // would then take the `..` from where it leads.
    g("config", "--unset", "include.path");
    g("config", "core.hooksPath", "nothere/../h2");
    assert.match(planFor(r, "git status").problem ?? "", /nothere/);
    assert.match(plainPlan(r).problem ?? "", /nothere/);
  }));

test("r4 21: a .git file's gitdir spelled with `..` after a link is found where git finds it, and protected there", () =>
  fixture((r, g) => {
    commit(r);
    const outside = mkdir(`${r}-outside`);
    fs.mkdirSync(path.join(r, "work", "sub"), { recursive: true });
    fs.symlinkSync(path.join(r, "work", "sub"), path.join(outside, "lnk"));
    // A linked worktree's admin directory away from `worktrees/` (HEAD and commondir: found by
    // nothing but the pointer), named `<outside>/lnk/../admin`: git takes it, link by link, to
    // `<project>/work/admin`; by the text it is `<outside>/admin`, which is not there.
    const admin = path.join(r, "work", "admin");
    write(path.join(admin, "HEAD"), `${g("rev-parse", "HEAD").trim()}\n`);
    write(path.join(admin, "commondir"), `${path.join(r, ".git")}\n`);
    write(path.join(admin, "gitdir"), `${path.join(r, "inner", ".git")}\n`);
    write(path.join(r, "inner", ".git"), `gitdir: ${outside}/lnk/../admin\n`);
    assert.equal(gitIn(path.join(r, "inner"), "rev-parse", "--absolute-git-dir").trim(), admin, "the fixture: git finds it there");
    const p = plainPlan(r);
    assert.equal(p.problem, undefined, p.problem);
    assert.ok(p.ro.includes(admin), `${admin} is not read-only: ${p.ro.join(", ")}`);
    assert.notEqual(sandboxed(p, `echo planted > ${admin}/config.worktree`, r).status, 0);
    assert.ok(!fs.existsSync(path.join(admin, "config.worktree")), "the admin directory was written");
  }));

test("r4 21: a hooks path for a push that climbs out of the git directory is watched where git takes it, now that paths git names are joined as written", () =>
  fixture((r, g) => {
    commit(r);
    // As receive-pack reads it, from the git directory: `<r>/.git/../receive` is `<r>/receive`.
    g("config", "core.hooksPath", "../receive");
    const p = plainPlan(r);
    assert.ok(p.gitWatch.includes(path.join(r, "receive")), `not watched: ${p.gitWatch.join(", ")}`);
  }));

// ---- 2. a hook linked to a script of the project: the script is protected ----

// A repository whose `pre-commit` hook is a link (`text`, made by `hook`) to `scripts/pre-commit`.
const SCRIPT = "#!/bin/sh\nexit 0\n";

test("r4 21: a hook linked to a script of the project, relative or absolute: every call is planned, the script is read-only in the sandbox, and an edit of it asks", () =>
  fixture((r, g, session) => {
    write(path.join(r, "a.txt"), "a\n");
    write(path.join(r, "scripts", "pre-commit"), SCRIPT, 0o755);
    g("add", "-A");
    g("commit", "-qm", "one");
    d.projectRoots(session);
    const hook = path.join(r, ".git", "hooks", "pre-commit");
    const script = path.join(r, "scripts", "pre-commit");
    for (const text of ["../../scripts/pre-commit", script]) {
      fs.symlinkSync(text, hook);
      try {
        for (const [who, p] of [["a call that is not git-only", plainPlan(r)], ["a git-only call", planFor(r, "git status")], ["a commit", planFor(r, "git commit -m x")]] as const) {
          assert.equal(p.problem, undefined, `${text}, ${who}: ${p.problem}`);
          assert.ok(p.ro.includes(script), `${text}, ${who}: the script is not read-only`);
        }
        assert.deepEqual(editProblems(r), [], text);
        assert.ok(editPaths(r).includes(script), `${text}: an edit of the script is not asked about`);
        // Run for real: the script cannot be rewritten, replaced or moved away; the rest works.
        const p = plainPlan(r);
        for (const command of [`echo planted >> ${script}`, `rm -f ${script}`, `mv scripts scripts.old`, `mv ${script} ${r}/elsewhere`]) {
          const ran = sandboxed(p, command, r);
          assert.notEqual(ran.status, 0, `${text}: ${command} worked`);
          assert.equal(fs.readFileSync(script, "utf8"), SCRIPT, `${text}: ${command}`);
        }
        const ran = sandboxed(p, "ls scripts && cat scripts/pre-commit && echo b >> a.txt && git status --short", r);
        assert.equal(ran.status, 0, ran.stderr);
        // A commit runs it, through the link.
        const committed = sandboxed(planFor(r, "git commit -am two"), "git commit -qam two", r);
        assert.equal(committed.status, 0, committed.stderr);
      } finally {
        fs.rmSync(hook);
      }
    }
    // The same for a configured hooks path in the work tree.
    write(path.join(r, ".githooks", "keep"), "");
    g("config", "core.hooksPath", ".githooks");
    fs.symlinkSync("../scripts/pre-commit", path.join(r, ".githooks", "pre-commit"));
    const p = plainPlan(r);
    assert.equal(p.problem, undefined, p.problem);
    assert.ok(p.ro.includes(script));
    assert.notEqual(sandboxed(p, `echo planted >> ${script}`, r).status, 0);
    assert.equal(fs.readFileSync(script, "utf8"), SCRIPT);
  }));

test("r4 21: a hook link of any other shape asks: a link on the way, a script outside the project or in the temp directory, a directory, `..` after a link, a script with another name", () =>
  fixture((r, g, session) => {
    write(path.join(r, "tools", "pre-commit"), SCRIPT, 0o755);
    commit(r);
    d.projectRoots(session);
    const outside = mkdir(`${r}-outside`);
    write(path.join(outside, "pre-commit"), SCRIPT, 0o755);
    const inTmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "c-tenth-hook-")));
    write(path.join(inTmp, "pre-commit"), SCRIPT, 0o755);
    const hook = path.join(r, ".git", "hooks", "pre-commit");
    // `scripts` a link to `tools`: the call could point it elsewhere.
    fs.symlinkSync("tools", path.join(r, "scripts"));
    fs.symlinkSync(path.join(r, "work"), path.join(outside, "lnk"));
    mkdir(path.join(r, "work"));
    write(path.join(r, "hard"), SCRIPT, 0o755);
    fs.linkSync(path.join(r, "hard"), path.join(r, "tools", "hard-too"));
    const SHAPES: [string, string][] = [
      ["a link on the way, relative", "../../scripts/pre-commit"],
      ["a link on the way, absolute", path.join(r, "scripts", "pre-commit")],
      ["a link to a link", path.join(r, "tools", "again")],
      ["outside the project", path.join(outside, "pre-commit")],
      ["in the temp directory", path.join(inTmp, "pre-commit")],
      ["a directory", "../../tools"],
      ["`..` after a link", `${outside}/lnk/../tools/pre-commit`],
      ["`..` after a link in the project", "../../scripts/../tools/pre-commit"],
      ["a script with another name too", "../../tools/hard-too"],
      ["broken", "../../tools/nothing"],
    ];
    fs.symlinkSync("pre-commit", path.join(r, "tools", "again"));
    try {
      for (const [shape, text] of SHAPES) {
        fs.symlinkSync(text, hook);
        try {
          for (const [who, problem] of [
            ["a call that is not git-only", plainPlan(r).problem],
            ["a git-only call", planFor(r, "git status").problem],
            ["an edit", editProblems(r).find((t) => t.includes(hook))],
          ] as const) {
            assert.match(problem ?? "", LINK, `${shape}, ${who}`);
            assert.ok((problem ?? "").includes(hook), `${shape}, ${who}: ${problem}`);
          }
        } finally {
          fs.rmSync(hook);
        }
      }
      // A link below the hooks directory is no hook: in a git directory read-only for the call it asks.
      fs.symlinkSync(path.join(r, "tools", "pre-commit"), path.join(mkdir(path.join(r, ".git", "hooks", "lib")), "pre-commit"));
      assert.match(plainPlan(r).problem ?? "", LINK);
      fs.rmSync(path.join(r, ".git", "hooks", "lib"), { recursive: true });
      // And in a configured hooks path, a link of another shape asks too.
      mkdir(path.join(r, ".githooks"));
      g("config", "core.hooksPath", ".githooks");
      fs.symlinkSync(path.join(outside, "pre-commit"), path.join(r, ".githooks", "pre-commit"));
      assert.ok((plainPlan(r).problem ?? "").includes(path.join(r, ".githooks", "pre-commit")));
      assert.ok((planFor(r, "git status").problem ?? "").includes(path.join(r, ".githooks", "pre-commit")));
    } finally {
      fs.rmSync(inTmp, { recursive: true, force: true });
    }
  }));

// ---- 3. hard links ----

test("r4 21: a hook, a config, an included file or a file under info/ with another name asks; git's own objects, packs and index with more than one name do not", () =>
  withLib((r, session, g) => {
    const dotGit = path.join(r, ".git");
    const lib = path.join(r, "lib");
    d.projectRoots(session);
    write(path.join(r, "scripts", "pre-commit"), SCRIPT, 0o755);
    write(path.join(r, "inc.cfg"), "[user]\n\tname = x\n");
    g("config", "include.path", "../inc.cfg");
    assert.equal(plainPlan(r).problem, undefined, "the fixture");
    const CASES: [string, string, string][] = [
      ["a hook", path.join(r, "scripts", "pre-commit"), path.join(dotGit, "hooks", "pre-commit")],
      ["a hook of a module", path.join(r, "scripts", "pre-commit"), path.join(dotGit, "modules", "other", "hooks", "pre-commit")],
      ["info/exclude", path.join(r, "exclude-too"), path.join(dotGit, "info", "exclude")],
      ["info/attributes", path.join(r, "attributes-too"), path.join(dotGit, "info", "attributes")],
      ["config", path.join(r, "config-too"), path.join(dotGit, "config")],
      ["config.worktree", path.join(r, "config-worktree-too"), path.join(dotGit, "config.worktree")],
    ];
    for (const [what, name, inGit] of CASES) {
      const had = fs.existsSync(inGit);
      if (had) fs.linkSync(inGit, name);
      else {
        if (!fs.existsSync(name)) write(name, "x\n");
        fs.linkSync(name, inGit);
      }
      try {
        assert.ok(fs.statSync(inGit).nlink > 1, `the fixture: ${what}`);
        for (const [who, problem] of [
          ["a call in the submodule", planFor(r, "git status", lib).problem],
          ["a call that is not git-only", plainPlan(r).problem],
          ["an edit", editProblems(r).find((text) => text.includes(inGit))],
        ] as const) {
          assert.match(problem ?? "", HARD, `${what}, ${who}`);
          assert.ok((problem ?? "").includes(inGit), `${what}, ${who}: ${problem}`);
        }
      } finally {
        fs.rmSync(had ? name : inGit);
      }
    }
    // An included file with another name.
    fs.linkSync(path.join(r, "inc.cfg"), path.join(r, "inc-too.cfg"));
    assert.ok((plainPlan(r).problem ?? "").includes(path.join(r, "inc.cfg")));
    fs.rmSync(path.join(r, "inc-too.cfg"));
    assert.equal(plainPlan(r).problem, undefined, "the fixture: put back");
    // A git-only call in the repository that owns the git directory: the directory is its own,
    // and plain git commands write a work tree's files anew, never through another name.
    fs.linkSync(path.join(r, "scripts", "pre-commit"), path.join(dotGit, "hooks", "pre-commit"));
    assert.equal(planFor(r, "git status").problem, undefined, planFor(r, "git status").problem);
    fs.rmSync(path.join(dotGit, "hooks", "pre-commit"));
    // Past the bound of the walk for hard links, the call asks: what lies past it was not seen.
    for (let k = 0; k <= 10_000; k++) fs.writeFileSync(path.join(dotGit, "info", `f${k}`), "");
    assert.match(plainPlan(r).problem ?? "", /too many entries to look for hard links/);
    for (let k = 0; k <= 10_000; k++) fs.rmSync(path.join(dotGit, "info", `f${k}`));
    // Run for real: the problem is real. Through the other name the hook is rewritten.
    fs.linkSync(path.join(r, "scripts", "pre-commit"), path.join(dotGit, "hooks", "pre-commit"));
    const loose = { ...plainPlan(r), problem: undefined };
    assert.equal(sandboxed(loose, `echo planted >> ${r}/scripts/pre-commit`, r).status, 0);
    assert.match(fs.readFileSync(path.join(dotGit, "hooks", "pre-commit"), "utf8"), /planted/);
    fs.rmSync(path.join(dotGit, "hooks", "pre-commit"));
    // git's own files: a local clone shares the objects by hard link, and an index with another name is no hook.
    const clone = path.join(r, "clone");
    execFileSync("git", ["clone", "-q", "--local", r, clone]);
    const pack = fs.readdirSync(path.join(clone, ".git", "objects", "pack")).find((name) => name.endsWith(".pack"));
    const loose2 = fs.readdirSync(path.join(clone, ".git", "objects")).find((name) => /^[0-9a-f]{2}$/.test(name));
    const shared = pack ? path.join(clone, ".git", "objects", "pack", pack) : path.join(clone, ".git", "objects", loose2!, fs.readdirSync(path.join(clone, ".git", "objects", loose2!))[0]);
    assert.ok(fs.statSync(shared).nlink > 1, "the fixture: the clone shares its objects");
    fs.linkSync(path.join(dotGit, "index"), path.join(r, "index-too"));
    assert.equal(plainPlan(r).problem, undefined, plainPlan(r).problem);
    assert.equal(planFor(r, "git status", lib).problem, undefined);
    assert.deepEqual(editProblems(r), []);
  }));

// ---- 4. every git directory below a named one is compared first ----

const junk = (dir: string, count: number) => {
  for (let n = 0; n < count; n++) write(path.join(dir, `a${String(n).padStart(6, "0")}`), "");
};

test("r4 21: the git directories below a named one are compared first: files that fill the named one do not push a module's hooks or config, or a worktree's config.worktree or HEAD, past the bound", () =>
  fixture((r, g, session) => {
    const resume = resuming();
    const before = { ...d.fingerprintLimits };
    const upstream = `${r}-up`;
    try {
      execFileSync("git", ["init", "-q", "-b", "main", upstream]);
      commit(upstream);
      commit(r);
      g(...FILE, "submodule", "add", "-q", upstream, "lib");
      g("commit", "-qm", "two");
      g("config", "extensions.worktreeConfig", "true");
      commit(r, "three");
      g("worktree", "add", "-q", "-b", "wt", `${r}-w`);
      const adm = fs.readdirSync(path.join(r, ".git", "worktrees"))[0];
      fs.renameSync(path.join(r, ".git", "worktrees", adm), path.join(r, ".git", "worktrees", "w"));
      write(path.join(`${r}-w`, ".git"), `gitdir: ${path.join(r, ".git", "worktrees", "w")}\n`);
      write(path.join(r, ".git", "worktrees", "w", "config.worktree"), "[core]\n\tsparseCheckout = false\n");
      const previous = g("rev-parse", "HEAD~1").trim();
      const current = g("rev-parse", "HEAD").trim();
      // Each a change from what is there, every time it is made (`i`: the case).
      const CHANGES: [string, (dotGit: string, i: number) => void][] = [
        ["a hook added to module lib", (dotGit, i) => write(path.join(dotGit, "modules", "lib", "hooks", "pre-commit"), `#!/bin/sh\ntouch /tmp/never-${i}\n`, 0o755)],
        ["core.fsmonitor in lib's config", (dotGit, i) => fs.appendFileSync(path.join(dotGit, "modules", "lib", "config"), `[core]\n\tfsmonitor = touch /tmp/never-${i}\n`)],
        ["core.hooksPath in w's config.worktree", (dotGit, i) => fs.appendFileSync(path.join(dotGit, "worktrees", "w", "config.worktree"), `[core]\n\thooksPath = /tmp/never-${i}\n`)],
        ["w's HEAD moved", (dotGit) => {
          const head = path.join(dotGit, "worktrees", "w", "HEAD");
          write(head, `${fs.readFileSync(head, "utf8").trim() === previous ? current : previous}\n`);
        }],
        ["lib's info/attributes", (dotGit, i) => write(path.join(dotGit, "modules", "lib", "info", "attributes"), `* filter=evil-${i}\n`)],
      ];
      d.projectRoots(session);
      d.fingerprintLimits.entries = 120;
      assert.equal(d.gitTampered(session, resume.file), undefined, "the fixture: a clean start");
      const dotGit = path.join(r, ".git");
      let i = 0;
      for (const place of ["modules", "worktrees", ".", "lfs/tmp", "rr-cache", "modules/aaa"]) {
        for (const [what, change] of CHANGES) {
          i++;
          // `.git` rebuilt as a new directory that keeps its old `modules/` and `worktrees/`: only `.git` is named.
          fs.cpSync(dotGit, `${dotGit}.copy`, { recursive: true, verbatimSymlinks: true });
          for (const name of ["modules", "worktrees"]) {
            fs.rmSync(path.join(`${dotGit}.copy`, name), { recursive: true });
            fs.renameSync(path.join(dotGit, name), path.join(`${dotGit}.copy`, name));
          }
          fs.rmSync(`${r}-old-git`, { recursive: true, force: true });
          fs.renameSync(dotGit, `${r}-old-git`);
          fs.renameSync(`${dotGit}.copy`, dotGit);
          junk(path.join(dotGit, place), 300);
          const first = d.gitTampered(session, resume.file) ?? "";
          assert.ok(first.includes(`${dotGit} was replaced`), `${place}, ${what}: ${first}`);
          assert.doesNotMatch(first, /modules\/lib (appeared|was replaced)|worktrees\/w (appeared|was replaced)/, `${place}, ${what}: the fixture names only .git`);
          change(dotGit, i);
          resume.touch();
          assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${dotGit} was replaced`), `junk in .git/${place}: ${what} joined the baseline unseen`);
          // Taken in once what was shown is as it was; the files go again. (Files in worktrees/
          // are each a new linked worktree as well, named five at a time.)
          const touches = place === "worktrees" ? 100 : 4;
          for (let k = 0; k < touches && d.gitTampered(session, resume.file); k++) resume.touch();
          assert.equal(d.gitTampered(session, resume.file), undefined, `${place}, ${what}: settled`);
          for (let k = 0; k < 300; k++) fs.rmSync(path.join(dotGit, place, `a${String(k).padStart(6, "0")}`));
          for (let k = 0; k < touches && d.gitTampered(session, resume.file); k++) resume.touch();
        }
      }
    } finally {
      Object.assign(d.fingerprintLimits, before);
      resume.remove();
    }
  }));

test("r4 21: the build check's three orders: a planted git directory with files before its module's config or hooks prompts again, with the bound lowered", () =>
  fixture((r, _g, session) => {
    const resume = resuming();
    const before = { ...d.fingerprintLimits };
    try {
      commit(r);
      d.projectRoots(session);
      d.fingerprintLimits.entries = 120;
      let n = 0;
      for (const place of ["modules/aaa", ".", "lfs"]) {
        for (const [what, change] of [
          ["a config line in modules/zzz", (nested: string) => fs.appendFileSync(path.join(nested, "modules", "zzz", "config"), "[core]\n\tfsmonitor = touch /tmp/never\n")],
          ["a hook in modules/zzz", (nested: string) => write(path.join(nested, "modules", "zzz", "hooks", "pre-commit"), "#!/bin/sh\ntouch /tmp/never\n", 0o755)],
          // A module named `deep/zzz`, and a module of a module.
          ["a config line in modules/deep/zzz", (nested: string) => fs.appendFileSync(path.join(nested, "modules", "deep", "zzz", "config"), "[core]\n\tfsmonitor = touch /tmp/never\n")],
          ["a hook in modules/zzz/modules/inner", (nested: string) => write(path.join(nested, "modules", "zzz", "modules", "inner", "hooks", "pre-commit"), "#!/bin/sh\ntouch /tmp/never\n", 0o755)],
          // (A module's refs are the second part's: files in lfs/ come after them.)
          ...(place === "lfs" ? ([["a ref in modules/zzz", (nested: string) => write(path.join(nested, "modules", "zzz", "refs", "heads", "planted"), `${"1".repeat(40)}\n`)]] as const) : []),
        ] as const) {
          const top = path.join(r, `zze${n++}`);
          execFileSync("git", ["init", "-q", "-b", "main", top]);
          const nested = path.join(top, ".git");
          for (const at of [["zzz"], ["deep", "zzz"], ["zzz", "modules", "inner"]]) execFileSync("git", ["init", "-q", "--bare", path.join(nested, "modules", ...at)]);
          junk(path.join(nested, place), 300);
          const first = d.gitTampered(session, resume.file) ?? "";
          assert.ok(first.includes(`${nested} appeared`), `${place}, ${what}: ${first}`);
          change(nested);
          resume.touch();
          assert.ok((d.gitTampered(session, resume.file) ?? "").includes(`${nested} appeared`), `files in ${place}: ${what} joined the baseline unseen`);
          resume.touch();
          assert.equal(d.gitTampered(session, resume.file), undefined, `${place}, ${what}`);
          fs.rmSync(top, { recursive: true });
          for (let k = 0; k < 4 && d.gitTampered(session, resume.file); k++) resume.touch();
        }
      }
      // The git directories below have the part's allowance: past it, the prompt says so and stays.
      d.fingerprintLimits.first = 120;
      const top = path.join(r, "many");
      execFileSync("git", ["init", "-q", "-b", "main", top]);
      for (let k = 0; k < 150; k++) mkdir(path.join(top, ".git", "modules", `m${String(k).padStart(3, "0")}`, "refs"));
      const first = d.gitTampered(session, resume.file) ?? "";
      assert.match(first, /cannot be compared whole where it matters: the git directories below it/, first);
      resume.touch();
      assert.match(d.gitTampered(session, resume.file) ?? "", /cannot be compared whole/);
    } finally {
      Object.assign(d.fingerprintLimits, before);
      resume.remove();
    }
  }));

// ---- 5. logs linked outside ----

test("r4 21: a repository whose logs is a link to a store outside every writable directory: a git command that writes a ref asks (it appends to the reflog), and one that does not runs", () =>
  fixture((r, g, session) => {
    write(path.join(r, "a.txt"), "a\n");
    g("add", "a.txt");
    g("commit", "-qm", "one");
    g("branch", "topic");
    const origin = `${r}-origin.git`;
    execFileSync("git", ["clone", "-q", "--bare", r, origin]);
    g("remote", "add", "origin", origin);
    g("fetch", "-q", "origin");
    g("branch", "-q", "--set-upstream-to=origin/main", "main");
    fs.appendFileSync(path.join(r, "a.txt"), "b\n");
    g("stash", "-q");
    d.projectRoots(session);
    const WRITERS = ["git commit -am x", "git commit --allow-empty -m x", "git commit --amend --no-edit", "git checkout topic", "git switch topic", "git switch main", "git branch topic2", "git fetch", "git pull", "git reset HEAD", "git stash pop", "git remote update"];
    const READERS = ["git status", "git log --oneline -3", "git add a.txt", "git diff", "git stash list", "git branch", "git checkout -- a.txt", "git checkout HEAD -- a.txt"];
    for (const text of [...WRITERS, ...READERS]) assert.equal(d.sandboxBreaks(text, r, session), undefined, `the fixture, ${text}`);
    const logs = path.join(r, ".git", "logs");
    fs.renameSync(logs, `${r}-store-logs`);
    fs.symlinkSync(`${r}-store-logs`, logs);
    try {
      for (const text of WRITERS) {
        const broken = d.sandboxBreaks(text, r, session) ?? "";
        assert.match(broken, /that store lies outside what the sandbox lets the call write/, text);
        assert.ok(broken.includes(logs), broken);
      }
      for (const text of READERS) assert.equal(d.sandboxBreaks(text, r, session), undefined, text);
      // What it is asked about for: run for real, the switch fails on the reflog.
      const ran = sandboxed(planFor(r, "git switch topic"), "git switch topic", r);
      assert.notEqual(ran.status, 0);
      assert.match(ran.stderr, /logs\/HEAD|Read-only file system/);
    } finally {
      fs.rmSync(logs);
      fs.renameSync(`${r}-store-logs`, logs);
    }
  }));

// ---- 6. --gpg-sign in any spelling git takes ----

test("r4 27: --gpg-sign abbreviated after --no-gpg-sign signs, and asks; --no-gpg-sign behind `--` is a pathspec; --no-gpg-sign abbreviated is read", () =>
  fixture((r, g, session) => {
    commit(r);
    d.projectRoots(session);
    g("config", "commit.gpgsign", "true");
    const SIGNS = /git signs/;
    for (const text of [
      "git commit --no-gpg-sign --gpg -m x",
      "git commit --no-gpg-sign --gpg- -m x",
      "git commit --no-gpg-sign --gpg-s -m x",
      "git commit --no-gpg-sign --gpg-si -m x",
      "git commit --no-gpg-sign --gpg-sig=ABCD -m x",
      "git commit --no-gpg-sign --gpg=ABCD -m x",
      "git commit -- a.txt --no-gpg-sign",
      "git commit -- --no-gpg-sign",
      "GIT_EDITOR=true git commit -- a.txt --no-gpg-sign",
    ]) assert.match(d.sandboxBreaks(text, r, session) ?? "", SIGNS, text);
    for (const text of ["git commit --no-gpg -m x", "git commit --no-gpg-s -m x", "git commit --no-gpg-sig -m x", "git commit --no-gpg-sign -m x"]) assert.doesNotMatch(d.sandboxBreaks(text, r, session) ?? "", SIGNS, text);
    // Without the config, an abbreviation alone signs.
    g("config", "commit.gpgsign", "false");
    assert.match(d.sandboxBreaks("git commit --gpg -m x", r, session) ?? "", SIGNS);
    assert.match(d.sandboxBreaks("git commit --gpg-si=ABCD -m x", r, session) ?? "", SIGNS);
    assert.doesNotMatch(d.sandboxBreaks("git commit --no-gpg -m x", r, session) ?? "", SIGNS);
  }));

// ---- After review 6: config read by its text before git is asked ----

test("a core.hooksPath git reads is still found when the config is read by its text first: any case, a linked worktree's common directory, an include, your own config", () =>
  fixture((r, g) => {
    commit(r);
    const hooksOf = (gitDir: string) => gitReadsElsewhere(gitDir).hooks;
    // Nothing set: nothing found.
    assert.deepEqual(hooksOf(path.join(r, ".git")), []);
    // Written by hand, in a case git takes.
    fs.appendFileSync(path.join(r, ".git", "config"), "[CORE]\n\tHOOKSPATH = hk1\n");
    assert.ok(hooksOf(path.join(r, ".git")).includes(path.join(r, "hk1")), hooksOf(path.join(r, ".git")).join(", "));
    // A linked worktree's admin directory reads the common directory's config.
    g("worktree", "add", "-q", `${r}-wt`);
    const admin = path.join(r, ".git", "worktrees", path.basename(`${r}-wt`));
    assert.ok(hooksOf(admin).some((h) => h.endsWith("/hk1")), hooksOf(admin).join(", "));
    g("worktree", "remove", "--force", `${r}-wt`);
    // Set only in a file the config includes.
    g("config", "--unset", "core.hooksPath");
    write(path.join(r, "inc.cfg"), "[core]\n\thooksPath = hk2\n");
    fs.appendFileSync(path.join(r, ".git", "config"), "[Include]\n\tpath = ../inc.cfg\n");
    assert.ok(hooksOf(path.join(r, ".git")).includes(path.join(r, "hk2")), hooksOf(path.join(r, ".git")).join(", "));
    // Set in your own config.
    g("config", "--unset", "include.path");
    assert.deepEqual(hooksOf(path.join(r, ".git")), []);
    const own = process.env.GIT_CONFIG_GLOBAL!;
    const before = fs.existsSync(own) ? fs.readFileSync(own) : undefined;
    try {
      fs.appendFileSync(own, "[core]\n\thooksPath = hk3\n");
      assert.ok(hooksOf(path.join(r, ".git")).includes(path.join(r, "hk3")), hooksOf(path.join(r, ".git")).join(", "));
    } finally {
      if (before === undefined) fs.rmSync(own, { force: true });
      else fs.writeFileSync(own, before);
    }
  }));
