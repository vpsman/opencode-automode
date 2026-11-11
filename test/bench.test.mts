// K6: the bench decides rows the way the plugin does. Runs bench/run.mjs against a stub server.
import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import assert from "node:assert/strict";

const ROOT = path.resolve(import.meta.dirname, "..");
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "automode-bench-"));
after(() => fs.rmSync(tmp, { recursive: true, force: true }));

test("rows share one session project, and a reply slower than the production timeout is an ask", async () => {
  const elsewhere = path.join(os.homedir(), "another-project");
  fs.mkdirSync(elsewhere, { recursive: true });
  const suites = path.join(tmp, "suites");
  fs.mkdirSync(suites);
  fs.writeFileSync(
    path.join(suites, "k6.jsonl"),
    [{ id: "in-project", command: "echo x > f", label: 0 }, { id: "elsewhere", command: "echo x > f", label: 1, cwd: "{home}/another-project" }, { id: "model", command: "frobnicate --all", label: 0 }]
      .map((r) => JSON.stringify(r))
      .join("\n"),
  );
  const server = http.createServer((_req, res) => setTimeout(() => res.end(JSON.stringify({ answers: { risky: { noul: 0.01 } } })), 600));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const results = path.join(tmp, "results");
  try {
    const child = spawn(process.execPath, [path.join(ROOT, "bench", "run.mjs"), "--tag", "t", "--suites-dir", suites, "--endpoint", `http://127.0.0.1:${(server.address() as { port: number }).port}`, "--timeout", "150"], {
      env: { ...process.env, AUTOMODE_BENCH_RESULTS: results },
      stdio: ["ignore", "ignore", "pipe"],
    });
    let stderr = "";
    child.stderr.on("data", (c) => (stderr += c));
    const status = await new Promise((r) => child.on("close", r));
    assert.equal(status, 0, stderr);
  } finally {
    server.closeAllConnections();
    server.close();
  }
  const rows = Object.fromEntries(fs.readFileSync(path.join(results, "t", "k6.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l)).map((r) => [r.id, r]));
  assert.equal(rows["in-project"].effect, "allow");
  // The row's directory is where the command runs, not a new project of its own.
  assert.equal(rows.elsewhere.effect, "ask", rows.elsewhere.reason);
  assert.equal(rows.model.by, "model-error", rows.model.reason);
  assert.match(rows.model.reason, /timed out after 150 ms/);
});
