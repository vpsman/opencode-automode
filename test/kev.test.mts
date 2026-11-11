// The model client against local stub servers: no model is needed.
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { describe, test } from "node:test";
import assert from "node:assert/strict";
import { DEFAULT_CLASSIFIER, scoreCommand } from "../kev.ts";

const state = { tool: "bash", cwd: "/work", command: "frobnicate" };
type Handler = (req: http.IncomingMessage, res: http.ServerResponse, body: string) => void;

async function withServer<T>(where: string | number, handler: Handler, fn: (endpoint: string) => Promise<T>): Promise<T> {
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => handler(req, res, body));
  });
  if (typeof where === "string") fs.mkdirSync(path.dirname(where), { recursive: true });
  await new Promise<void>((r) => (typeof where === "string" ? server.listen(where, r) : server.listen(where, "127.0.0.1", r)));
  const endpoint = typeof where === "string" ? `unix:${where}` : `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    return await fn(endpoint);
  } finally {
    server.closeAllConnections();
    server.close();
  }
}
const json = (value: unknown): Handler => (_req, res) => res.end(JSON.stringify(value));
const score = (endpoint: string, extra = {}) => scoreCommand({ ...DEFAULT_CLASSIFIER, endpoint, timeoutMs: 1000, ...extra }, state);

describe("scoreCommand", () => {
  test("sends the question and reads the score (TCP)", async () => {
    let sent: any;
    const r = await withServer(0, (req, res, body) => {
      sent = { url: req.url, method: req.method, body: JSON.parse(body) };
      res.end(JSON.stringify({ answers: { risky: { noul: 0.07 } } }));
    }, score);
    assert.deepEqual("score" in r && r.score, 0.07);
    assert.equal(sent.url, "/v1/systemone");
    assert.equal(sent.method, "POST");
    assert.deepEqual(sent.body.state, state);
    assert.equal(sent.body.questions.risky.type, "noul");
  });

  test("H4: the default endpoint is a unix socket in the runtime directory, and it works", async () => {
    assert.match(DEFAULT_CLASSIFIER.endpoint, /^unix:\//);
    const socket = DEFAULT_CLASSIFIER.endpoint.slice(5);
    assert.ok(socket.startsWith(process.env.XDG_RUNTIME_DIR!), socket);
    const r = await withServer(socket, json({ answers: { risky: { noul: 0.5 } } }), () => scoreCommand({ ...DEFAULT_CLASSIFIER, timeoutMs: 1000 }, state));
    assert.deepEqual("score" in r && r.score, 0.5);
  });

  for (const bad of [-1, -0.0001, 1.0001, 7, "0.1", null, true, Number.NaN]) {
    test(`H1: a score of ${JSON.stringify(bad)} is an error, never an allow`, async () => {
      const r = await withServer(0, (_req, res) => res.end(`{"answers":{"risky":{"noul":${typeof bad === "number" && Number.isNaN(bad) ? "NaN" : JSON.stringify(bad)}}}}`), score);
      assert.ok("error" in r, JSON.stringify(r));
    });
  }
  for (const ok of [0, 1, 0.2]) {
    test(`a score of ${ok} is an answer`, async () => assert.deepEqual(await withServer(0, json({ answers: { risky: { noul: ok } } }), async (e) => (await score(e) as any).score), ok));
  }

  test("an HTTP error is an error", async () => {
    const r = await withServer(0, (_req, res) => ((res.statusCode = 503), res.end("loading model")), score);
    assert.match((r as { error: string }).error, /HTTP 503: loading model/);
  });
  test("an answer that is not JSON, or has no score, is an error", async () => {
    assert.ok("error" in (await withServer(0, (_req, res) => res.end("<html>"), score)));
    assert.ok("error" in (await withServer(0, json({ answers: {} }), score)));
    assert.ok("error" in (await withServer(0, json(null), score)));
  });
  test("a slow server times out, over TCP and over a unix socket", async () => {
    const slow: Handler = () => {};
    assert.match(((await withServer(0, slow, (e) => score(e, { timeoutMs: 150 }))) as { error: string }).error, /timed out after 150 ms/);
    const socket = path.join(process.env.XDG_RUNTIME_DIR!, "slow", "kev.sock");
    assert.match(((await withServer(socket, slow, (e) => score(e, { timeoutMs: 150 }))) as { error: string }).error, /timed out after 150 ms/);
  });
  test("a server that is down is an error", async () => {
    assert.ok("error" in (await score("http://127.0.0.1:9")));
    assert.ok("error" in (await score(`unix:${path.join(process.env.XDG_RUNTIME_DIR!, "nobody-listens.sock")}`)));
  });
  test("a caller's abort is an error", async () => {
    const r = await withServer(0, () => {}, (endpoint) => scoreCommand({ ...DEFAULT_CLASSIFIER, endpoint, timeoutMs: 5000 }, state, AbortSignal.timeout(100)));
    assert.ok("error" in r);
  });
  test("a timeout that is not a number is an error", async () => {
    assert.ok("error" in (await score("http://127.0.0.1:9", { timeoutMs: "soon" })));
  });
});
