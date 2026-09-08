/**
 * THE LOOP, SEPARATED FROM THE PROCESS IT RUNS IN.
 *
 * Newline-delimited JSON-RPC: one message per line in, one response per line
 * out. It lived inline in `index.ts` under a top-level `main()` call and was
 * therefore unreachable by any test — the only way to exercise it was to start
 * the published binary and speak to it over a pipe, which nothing did.
 *
 * Taking the streams as arguments is the whole change. `index.ts` passes
 * `process.stdin` / `process.stdout`; a test passes anything with the same two
 * methods, and the loop it exercises is the one that ships.
 */
import { createInterface } from "node:readline";
import { ErrorCode } from "./protocol.js";

/**
 * How many messages may be in flight at once.
 *
 * ── WHY NOT ONE, WHICH IS WHAT IT USED TO BE ────────────────────────────────
 * The loop awaited each handler before reading the next line, so while a
 * `pre_flight_check` ran NOTHING else was dispatched — not `tools/list`, not
 * another call, and not `ping`, which hosts use as a liveness probe. That call
 * is bounded at 60 seconds by its own lookup budget, so a healthy server could
 * look dead for a minute and be disconnected. `notifications/cancelled` was
 * worse than ignored: it could not even be READ until the thing it cancels had
 * finished.
 *
 * ── WHY NOT UNBOUNDED, WHICH IS THE OBVIOUS FIX ─────────────────────────────
 * Each `pre_flight_check` may make up to 1,000 registry lookups eight at a
 * time. Dispatching every line as it arrives lets a client put a hundred scans
 * in flight and open eight hundred sockets from the USER's address — the exact
 * burst the per-call budget exists to prevent, moved up one level.
 *
 * Four is enough that a liveness ping never queues behind the one scan an
 * editor actually runs, and small enough that the fan-out stays in the
 * hundreds. Beyond it the reader stops pulling lines, which is backpressure
 * rather than a queue that grows without limit.
 */
export const MAX_IN_FLIGHT = 4;

/** Just enough of a writable stream for this loop, so a test can supply one. */
export interface LineSink {
  write(chunk: string): unknown;
}

export interface Server {
  handleMessage(msg: unknown): Promise<object | null>;
}

/** The spec's response to a line that is not JSON: no id to echo, so null. */
export function parseErrorResponse(): object {
  return {
    jsonrpc: "2.0",
    id: null,
    error: { code: ErrorCode.ParseError, message: "Parse error" },
  };
}

/**
 * Read until the input ends.
 *
 * Resolves when stdin closes — which is how an editor tells the server to shut
 * down, and the only way this function returns.
 */
export async function serveStdio(opts: {
  server: Server;
  input: NodeJS.ReadableStream;
  output: LineSink;
  /** Overridable so a test can drive the queue without sending real work. */
  maxInFlight?: number;
}): Promise<void> {
  const rl = createInterface({ input: opts.input, crlfDelay: Infinity });
  const limit = opts.maxInFlight ?? MAX_IN_FLIGHT;

  const inFlight = new Set<Promise<void>>();

  /** Answer one message. Never rejects; the reader must not depend on it. */
  const dispatch = async (msg: unknown): Promise<void> => {
    // NOTHING THROWN HERE MAY LEAVE. `handleMessage` turns tool failures into
    // JSON-RPC errors, but a defect inside it would otherwise become an
    // unhandled rejection and take the process down mid-session — the editor
    // sees the integration vanish, not an error it can report.
    let response: object | null;
    try {
      response = await opts.server.handleMessage(msg);
    } catch (err) {
      response = {
        jsonrpc: "2.0",
        id: (msg as { id?: unknown })?.id ?? null,
        error: {
          code: ErrorCode.InternalError,
          message: `Internal error: ${String(err)}`,
        },
      };
    }
    // ONE `write` PER RESPONSE, and that is what keeps the framing intact under
    // concurrency: a reader splitting on newlines can never see two half
    // responses, because no response is ever written in two calls.
    if (response !== null) opts.output.write(JSON.stringify(response) + "\n");
  };

  for await (const line of rl) {
    const trimmed = line.trim();
    // A blank line is not a message. Answering it with a parse error would
    // make a trailing newline look like a client bug.
    if (!trimmed) continue;

    let msg: unknown;
    try {
      msg = JSON.parse(trimmed);
    } catch {
      opts.output.write(JSON.stringify(parseErrorResponse()) + "\n");
      continue;
    }

    // Not awaited: the reader goes straight back for the next line. See
    // MAX_IN_FLIGHT for what bounds it.
    const task = dispatch(msg).finally(() => inFlight.delete(task));
    inFlight.add(task);

    if (inFlight.size >= limit) await Promise.race(inFlight);
  }

  // stdin closed. Finish what was accepted before answering the shutdown —
  // a client that sent a request and then closed the pipe is entitled to the
  // answer it is still waiting for.
  await Promise.all(inFlight);
}
