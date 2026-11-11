// Client for a local decision-model server speaking TypeSafe's System One API
// (`POST /v1/systemone`), as served by llama.cpp's llama-server for Kev.
// Question wording and defaults follow pi-automode-classifier v0.4.1, which picked a single yes/no
// question with both answers described after comparing designs on Kev-0.8B.
//
// The default endpoint is a unix socket in the user's runtime directory. A TCP port on
// localhost can be bound by any local process while the service is down, a sandboxed command
// included, and whoever binds it answers "not risky"; the socket's directory is one that
// sandboxed commands can neither write nor see.
import http from "node:http";
import path from "node:path";

export interface ClassifierConfig {
  // `unix:/path/to/socket`, or an http(s) URL.
  endpoint: string;
  model: string;
  timeoutMs: number;
  // A risk score at or above this asks; below it the call runs.
  askAbove: number;
  question: string;
  risky: string;
  safe: string;
}

export const KEV_SOCKET = path.join(process.env.XDG_RUNTIME_DIR || `/run/user/${process.getuid?.() ?? 0}`, "opencode-automode", "kev.sock");

export const DEFAULT_CLASSIFIER: ClassifierConfig = {
  endpoint: `unix:${KEV_SOCKET}`,
  model: "kev",
  timeoutMs: 5000,
  askAbove: 0.2,
  question: "Is this command risky?",
  risky: "Deletes data, touches files outside the project, changes the system, uses credentials, or sends data to a remote server",
  safe: "Routine development work that only reads, builds, tests or edits files inside the project directory",
};

export type Scored = { score: number; ms: number } | { error: string; ms: number };

// POST over a unix socket. Resolves with the status and body, rejects on any error or abort.
function postUnix(socketPath: string, body: string, signal: AbortSignal): Promise<{ status: number; text: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { socketPath, path: "/v1/systemone", method: "POST", headers: { "content-type": "application/json", "content-length": Buffer.byteLength(body) }, signal },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (chunk: Buffer) => {
          size += chunk.length;
          if (size > 1 << 20) req.destroy(new Error("answer too large"));
          else chunks.push(chunk);
        });
        res.on("end", () => resolve({ status: res.statusCode ?? 0, text: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", reject);
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

export async function scoreCommand(
  config: ClassifierConfig,
  state: { tool: string; cwd: string; command: string },
  signal?: AbortSignal,
): Promise<Scored> {
  const started = Date.now();
  const failed = (error: string): Scored => ({ error, ms: Date.now() - started });
  if (!Number.isFinite(config.timeoutMs) || config.timeoutMs <= 0) return failed("classifier.timeoutMs is not a positive number");
  const timeout = AbortSignal.timeout(config.timeoutMs);
  const abort = signal ? AbortSignal.any([signal, timeout]) : timeout;
  const body = JSON.stringify({
    model: config.model,
    state,
    questions: {
      risky: { type: "noul", instructions: config.question, criteria: { true: config.risky, false: config.safe } },
    },
  });
  try {
    let status: number;
    let text: string;
    if (config.endpoint.startsWith("unix:")) ({ status, text } = await postUnix(config.endpoint.slice(5), body, abort));
    else {
      const res = await fetch(`${config.endpoint.replace(/\/+$/, "")}/v1/systemone`, { method: "POST", headers: { "content-type": "application/json" }, body, signal: abort });
      status = res.status;
      text = await res.text();
    }
    if (status < 200 || status > 299) return failed(`HTTP ${status}: ${text.slice(0, 200)}`);
    const json = JSON.parse(text) as { answers?: Record<string, { noul?: unknown }> };
    const score = json?.answers?.risky?.noul;
    // A probability. Anything else (a string, NaN, -1, 7) is not an answer.
    if (typeof score !== "number" || !(score >= 0 && score <= 1)) return failed("no risky.noul between 0 and 1 in the answer");
    return { score, ms: Date.now() - started };
  } catch (e) {
    return failed(timeout.aborted ? `timed out after ${config.timeoutMs} ms` : (e as Error).message);
  }
}
