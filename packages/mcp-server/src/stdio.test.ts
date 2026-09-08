/**
 * THE LOOP AN EDITOR TALKS TO FOR THE WHOLE SESSION.
 *
 * Every message a coding agent sends this package goes through here, and until
 * the loop took its streams as arguments nothing could run it: it sat under a
 * top-level `main()` in the entry module, so importing it blocked on real
 * stdin. The published binary's message loop was, in the literal sense,
 * unreachable by any test.
 *
 * The property worth pinning is not "it answers" — it is that NOTHING ends the
 * loop except the input ending. A server process that exits mid-session shows
 * up in an editor as the integration disappearing, with no error the user can
 * act on.
 */
import { describe, it, expect, vi } from "vitest";
import { Readable } from "node:stream";
import { serveStdio, parseErrorResponse, MAX_IN_FLIGHT } from "./stdio.js";
import { ErrorCode } from "./protocol.js";

/** Collects what the loop writes, one parsed message per line. */
function sink() {
  const lines: string[] = [];
  return {
    write(chunk: string) {
      lines.push(chunk);
      return true;
    },
    lines,
    messages: () =>
      lines
        .join("")
        .split("\n")
        .filter(Boolean)
        .map(l => JSON.parse(l)),
  };
}

function input(...lines: string[]) {
  return Readable.from([lines.join("\n")]);
}

const echoServer = {
  handleMessage: async (msg: unknown) => ({
    jsonrpc: "2.0",
    id: (msg as { id?: unknown })?.id ?? null,
    result: {},
  }),
};

describe("one line in, one line out", () => {
  it("answers each message on its own line", async () => {
    const out = sink();

    await serveStdio({
      server: echoServer,
      input: input(
        JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
        JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })
      ),
      output: out,
    });

    expect(out.messages().map(m => m.id)).toEqual([1, 2]);
    for (const line of out.lines) expect(line.endsWith("\n")).toBe(true);
  });

  it("returns when the input ends, which is how an editor shuts it down", async () => {
    const out = sink();

    await expect(
      serveStdio({ server: echoServer, input: input(""), output: out })
    ).resolves.toBeUndefined();
  });

  it("writes nothing at all for a notification", async () => {
    // handleMessage returns null for `notifications/*`, and a JSON-RPC
    // notification must not be answered. A response here is a protocol
    // violation the client may or may not tolerate.
    const out = sink();

    await serveStdio({
      server: { handleMessage: async () => null },
      input: input(
        JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" })
      ),
      output: out,
    });

    expect(out.lines).toEqual([]);
  });
});

describe("a line that is not a message", () => {
  it("skips a blank line rather than calling it a parse error", async () => {
    // A trailing newline is not a client bug, and answering it with an error
    // would make every well-behaved client look broken.
    const handleMessage = vi.fn(async () => null);
    const out = sink();

    await serveStdio({
      server: { handleMessage },
      input: input("", "   ", "\t"),
      output: out,
    });

    expect(handleMessage).not.toHaveBeenCalled();
    expect(out.lines).toEqual([]);
  });

  it("answers unparseable JSON with the spec's ParseError and a null id", async () => {
    const out = sink();

    await serveStdio({
      server: echoServer,
      input: input("{not json"),
      output: out,
    });

    const [msg] = out.messages();
    expect(msg.id).toBeNull();
    expect(msg.error.code).toBe(ErrorCode.ParseError);
  });

  it("keeps serving after one, because a client recovers from its own mistake", async () => {
    const out = sink();

    await serveStdio({
      server: echoServer,
      input: input(
        "{not json",
        JSON.stringify({ jsonrpc: "2.0", id: 9, method: "ping" })
      ),
      output: out,
    });

    const msgs = out.messages();
    expect(msgs).toHaveLength(2);
    expect(msgs[1].id).toBe(9);
  });

  it("parseErrorResponse is the shape the spec names", () => {
    expect(parseErrorResponse()).toEqual({
      jsonrpc: "2.0",
      id: null,
      error: { code: ErrorCode.ParseError, message: "Parse error" },
    });
  });
});

describe("nothing ends the loop except the input ending", () => {
  it("a throwing handler becomes an InternalError, not a dead server", async () => {
    // `handleMessage` is written to catch, so reaching this means a defect
    // inside it. Letting that escape ends the `for await` and the process —
    // the editor sees the integration vanish, with nothing to report.
    const out = sink();

    await serveStdio({
      server: {
        handleMessage: async () => {
          throw new Error("unexpected");
        },
      },
      input: input(JSON.stringify({ jsonrpc: "2.0", id: 4, method: "ping" })),
      output: out,
    });

    const [msg] = out.messages();
    expect(msg.id).toBe(4);
    expect(msg.error.code).toBe(ErrorCode.InternalError);
    expect(msg.error.message).toContain("unexpected");
  });

  it("keeps serving the next message after a handler throws", async () => {
    const handleMessage = vi
      .fn()
      .mockRejectedValueOnce(new Error("boom"))
      .mockResolvedValueOnce({ jsonrpc: "2.0", id: 2, result: {} });
    const out = sink();

    await serveStdio({
      server: { handleMessage },
      input: input(
        JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" }),
        JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })
      ),
      output: out,
    });

    expect(handleMessage).toHaveBeenCalledTimes(2);
    expect(out.messages()).toHaveLength(2);
  });

  it("echoes the id of the message that failed, so the client can match it", async () => {
    const out = sink();

    await serveStdio({
      server: {
        handleMessage: async () => {
          throw new Error("x");
        },
      },
      input: input(
        JSON.stringify({ jsonrpc: "2.0", id: "abc", method: "ping" })
      ),
      output: out,
    });

    expect(out.messages()[0].id).toBe("abc");
  });

  it("uses a null id when the failing message had none", async () => {
    const out = sink();

    await serveStdio({
      server: {
        handleMessage: async () => {
          throw new Error("x");
        },
      },
      input: input(JSON.stringify({ jsonrpc: "2.0", method: "ping" })),
      output: out,
    });

    expect(out.messages()[0].id).toBeNull();
  });
});

/**
 * A SLOW CALL MUST NOT SILENCE THE SERVER.
 *
 * The loop used to await each handler before reading the next line, so while a
 * `pre_flight_check` ran NOTHING else was dispatched — not `tools/list`, not
 * another call, and not `ping`, which hosts use as a liveness probe. That call
 * is bounded at sixty seconds by its own lookup budget, so a healthy server
 * could look dead for a minute and be disconnected, and the answer would then
 * arrive on a channel nobody was reading. `notifications/cancelled` was worse
 * than ignored: it could not be READ until the thing it cancels had finished.
 *
 * Responses may now arrive out of order, which JSON-RPC allows — replies are
 * correlated by id, not by position. What must NOT change is the framing: one
 * write per response, so a reader splitting on newlines never sees two halves.
 */
describe("a slow message does not block the ones behind it", () => {
  /** Resolves when `release()` is called; nothing else can finish it. */
  function gate() {
    let release!: () => void;
    const opened = new Promise<void>(r => (release = r));
    return { opened, release };
  }

  it("answers a fast message while a slow one is still running", async () => {
    const slow = gate();
    const out = sink();
    const handleMessage = vi.fn(async (msg: unknown) => {
      const id = (msg as { id: number }).id;
      if (id === 1) await slow.opened;
      return { jsonrpc: "2.0", id, result: {} };
    });

    const served = serveStdio({
      server: { handleMessage },
      input: input(
        JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call" }),
        JSON.stringify({ jsonrpc: "2.0", id: 2, method: "ping" })
      ),
      output: out,
    });

    // The ping is answered with the slow call still in flight. Under the old
    // loop this would hang until the slow one was released.
    await vi.waitFor(() => expect(out.messages().map(m => m.id)).toEqual([2]));

    slow.release();
    await served;

    expect(
      out
        .messages()
        .map(m => m.id)
        .sort()
    ).toEqual([1, 2]);
  });

  it("still answers every id, whatever the order", async () => {
    const out = sink();
    const handleMessage = vi.fn(async (msg: unknown) => {
      const id = (msg as { id: number }).id;
      await new Promise(r => setTimeout(r, id === 1 ? 20 : 1));
      return { jsonrpc: "2.0", id, result: {} };
    });

    await serveStdio({
      server: { handleMessage },
      input: input(
        ...[1, 2, 3].map(id =>
          JSON.stringify({ jsonrpc: "2.0", id, method: "ping" })
        )
      ),
      output: out,
    });

    expect(
      out
        .messages()
        .map(m => m.id)
        .sort()
    ).toEqual([1, 2, 3]);
  });

  it("writes each response in ONE call, so lines are never interleaved", async () => {
    // The invariant concurrency could break and must not: a reader splitting
    // on newlines has to see whole documents.
    const out = sink();

    await serveStdio({
      server: {
        handleMessage: async (msg: unknown) => ({
          jsonrpc: "2.0",
          id: (msg as { id: number }).id,
          result: { padding: "x".repeat(500) },
        }),
      },
      input: input(
        ...[1, 2, 3].map(id =>
          JSON.stringify({ jsonrpc: "2.0", id, method: "ping" })
        )
      ),
      output: out,
    });

    expect(out.lines).toHaveLength(3);
    for (const line of out.lines) {
      expect(line.endsWith("\n")).toBe(true);
      expect(line.slice(0, -1)).not.toContain("\n");
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });

  it("finishes what it accepted before returning on a closed pipe", async () => {
    // A client that sends a request and then closes stdin is still waiting for
    // the answer. Returning early would drop it.
    const out = sink();

    await serveStdio({
      server: {
        handleMessage: async (msg: unknown) => {
          await new Promise(r => setTimeout(r, 15));
          return { jsonrpc: "2.0", id: (msg as { id: number }).id, result: {} };
        },
      },
      input: input(JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" })),
      output: out,
    });

    expect(out.messages()).toHaveLength(1);
  });
});

describe("the in-flight bound", () => {
  it("stops reading once the cap is reached, rather than queueing without limit", async () => {
    // Each pre_flight_check may make up to a thousand registry lookups eight at
    // a time. Dispatching every line as it arrives would let a client open
    // hundreds of sockets from the USER's address — the burst the per-call
    // budget exists to prevent, moved up one level.
    const out = sink();
    let concurrent = 0;
    let peak = 0;
    const gates: Array<() => void> = [];

    const served = serveStdio({
      server: {
        handleMessage: async (msg: unknown) => {
          concurrent += 1;
          peak = Math.max(peak, concurrent);
          await new Promise<void>(r => gates.push(r));
          concurrent -= 1;
          return { jsonrpc: "2.0", id: (msg as { id: number }).id, result: {} };
        },
      },
      input: input(
        ...Array.from({ length: 10 }, (_, i) =>
          JSON.stringify({ jsonrpc: "2.0", id: i, method: "ping" })
        )
      ),
      output: out,
      maxInFlight: 3,
    });

    await vi.waitFor(() => expect(gates).toHaveLength(3));
    expect(peak).toBe(3);

    // Drain: each release lets exactly one more line be read.
    while (gates.length) gates.shift()!();
    const drain = setInterval(() => gates.length && gates.shift()!(), 1);
    await served;
    clearInterval(drain);

    expect(peak).toBeLessThanOrEqual(3);
    expect(out.messages()).toHaveLength(10);
  });

  it("defaults to a bound rather than to unbounded", () => {
    expect(MAX_IN_FLIGHT).toBeGreaterThan(1);
    expect(MAX_IN_FLIGHT).toBeLessThanOrEqual(8);
  });
});
