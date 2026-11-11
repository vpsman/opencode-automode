// Client for a local decision-model server speaking TypeSafe's System One API
// (`POST /v1/systemone`), as served by llama.cpp's llama-server for Kev.
// Question wording and defaults follow pi-automode-classifier v0.4.1, which picked a single yes/no
// question with both answers described after comparing designs on Kev-0.8B.

export interface ClassifierConfig {
  endpoint: string;
  model: string;
  timeoutMs: number;
  // A risk score at or above this asks; below it the call runs.
  askAbove: number;
  question: string;
  risky: string;
  safe: string;
}

export const DEFAULT_CLASSIFIER: ClassifierConfig = {
  endpoint: "http://127.0.0.1:11438",
  model: "kev",
  timeoutMs: 5000,
  askAbove: 0.2,
  question: "Is this command risky?",
  risky: "Deletes data, touches files outside the project, changes the system, uses credentials, or sends data to a remote server",
  safe: "Routine development work that only reads, builds, tests or edits files inside the project directory",
};

export type Scored = { score: number; ms: number } | { error: string; ms: number };

export async function scoreCommand(
  config: ClassifierConfig,
  state: { tool: string; cwd: string; command: string },
  signal?: AbortSignal,
): Promise<Scored> {
  const started = Date.now();
  const timeout = AbortSignal.timeout(config.timeoutMs);
  const body = {
    model: config.model,
    state,
    questions: {
      risky: { type: "noul", instructions: config.question, criteria: { true: config.risky, false: config.safe } },
    },
  };
  try {
    const res = await fetch(`${config.endpoint.replace(/\/+$/, "")}/v1/systemone`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
      signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    });
    if (!res.ok) return { error: `HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`, ms: Date.now() - started };
    const json = (await res.json()) as { answers?: Record<string, { noul?: number }> };
    const score = json.answers?.risky?.noul;
    if (typeof score !== "number" || !Number.isFinite(score)) return { error: "no risky.noul in the answer", ms: Date.now() - started };
    return { score, ms: Date.now() - started };
  } catch (e) {
    return { error: (e as Error).name === "TimeoutError" ? `timed out after ${config.timeoutMs} ms` : (e as Error).message, ms: Date.now() - started };
  }
}
