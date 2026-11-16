// Round 4, the closing reading (step 7): two holes in which configuration files the plan reads.
// F1: the global configuration is the one GIT_CONFIG_GLOBAL names where it is set (git then reads
// neither ~/.gitconfig nor the XDG file); the plan read only those two. F3: a file included twice,
// first plainly and then under an includeIf, was walked once, as plain, so a core.hooksPath set
// below it under the condition went unseen.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import assert from "node:assert/strict";
import { plan, protectedPaths } from "../sandbox.ts";

const scratch = (name: string) => fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `c-closing-${name}-`)));
const opts = (r: string) => ({ project: r, projectRoots: [r], allowedPaths: [] as string[], cacheDirs: [], gitWritable: false, exposeSsh: false, keepSockets: [], showPaths: [], hidePaths: [] });
const repo = (base: string) => {
  const r = path.join(base, "repo");
  fs.mkdirSync(r);
  execFileSync("git", ["init", "-q", "-b", "main", r]);
  execFileSync("git", ["-C", r, "commit", "-q", "--allow-empty", "-m", "one"]);
  return r;
};

test("r4 closing F1: the global configuration GIT_CONFIG_GLOBAL names is the one read", () => {
  const base = scratch("gcg");
  const r = repo(base);
  const other = path.join(base, "other-gitconfig");
  const feature = path.join(base, "feature.cfg");
  const inc = path.join(r, "inc.cfg");
  fs.writeFileSync(other, "[user]\n\tname = t\n\temail = t@example.invalid\n");
  fs.writeFileSync(feature, "[core]\n\thooksPath = .hooks-feature\n");
  fs.writeFileSync(inc, "[user]\n\tname = x\n");
  const before = process.env.GIT_CONFIG_GLOBAL;
  process.env.GIT_CONFIG_GLOBAL = other;
  try {
    assert.equal(plan(opts(r)).problem, undefined, "a plain global configuration elsewhere: nothing to say");
    // What it includes is protected (the include in the project is read-only).
    fs.appendFileSync(other, `[include]\n\tpath = ${inc}\n`);
    const p = plan(opts(r));
    assert.equal(p.problem, undefined, p.problem);
    assert.ok(p.ro.includes(inc), "the file it includes is read-only");
    // A conditional core.hooksPath in it asks, for a call and for an edit.
    fs.appendFileSync(other, `[includeIf "onbranch:feature"]\n\tpath = ${feature}\n`);
    assert.match(plan(opts(r)).problem ?? "", /core\.hooksPath/);
    assert.ok(protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).problems.some((x) => /core\.hooksPath/.test(x)));
    // The global file itself, where a call could write it, is protected too.
    const inProject = path.join(r, "my-gitconfig");
    fs.copyFileSync(other, inProject);
    process.env.GIT_CONFIG_GLOBAL = inProject;
    const q = plan(opts(r));
    assert.ok(q.ro.includes(inProject) || /my-gitconfig/.test(q.problem ?? ""), "a global configuration in the project is held or named");
  } finally {
    if (before === undefined) delete process.env.GIT_CONFIG_GLOBAL;
    else process.env.GIT_CONFIG_GLOBAL = before;
    fs.rmSync(base, { recursive: true, force: true });
  }
});

test("r4 closing F3: a file included plainly and then under a condition is read under the condition too", () => {
  const base = scratch("twice");
  const r = repo(base);
  try {
    fs.writeFileSync(path.join(r, ".git", "a.cfg"), "[include]\n\tpath = b.cfg\n");
    fs.writeFileSync(path.join(r, ".git", "b.cfg"), "[core]\n\thooksPath = .hooks-a\n");
    fs.appendFileSync(path.join(r, ".git", "config"), `[include]\n\tpath = a.cfg\n[core]\n\thooksPath = .githooks\n[includeIf "onbranch:feature"]\n\tpath = a.cfg\n`);
    assert.match(plan(opts(r)).problem ?? "", /core\.hooksPath/, "the conditional reading of b.cfg asks");
    assert.ok(protectedPaths({ projectRoots: [r], allowedPaths: [], project: r }).problems.some((x) => /core\.hooksPath/.test(x)));
  } finally {
    fs.rmSync(base, { recursive: true, force: true });
  }
});
