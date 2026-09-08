/**
 * Minimal MCP server core — JSON-RPC 2.0 over a single dispatch function, with
 * exactly the Model Context Protocol surface a stdio tool server needs:
 * `initialize`, `tools/list`, `tools/call`, `ping`, and the client
 * `notifications/*` (acknowledged with no reply).
 *
 * Why this exists instead of `@modelcontextprotocol/sdk`: the SDK pulls in a
 * whole HTTP transport stack (hono, ajv, …) that a stdio-only server never
 * touches, and that dependency tree is what makes `npm audit` flag this package
 * for a Windows path-traversal advisory in code we do not run. Hand-rolling the
 * tiny slice we use lets `@graneth/mcp-server` ship with ZERO runtime
 * dependencies — auditable in full, which is the whole point of a supply-chain
 * security tool.
 *
 * The constants and the version-negotiation rule are copied verbatim from the
 * SDK (@modelcontextprotocol/sdk 1.29.0, `types.js` / `server/index.js`) so a
 * real client (Claude Code, Cursor, Codex) negotiates identically:
 *   protocolVersion = SUPPORTED.includes(requested) ? requested : LATEST
 * This file is transport-agnostic and fully unit-tested; the stdio loop that
 * feeds it lives in index.ts.
 */

/** From SDK types.js — keep the first entry as the latest. */
export const LATEST_PROTOCOL_VERSION = "2025-11-25";
export const SUPPORTED_PROTOCOL_VERSIONS = [
  LATEST_PROTOCOL_VERSION,
  "2025-06-18",
  "2025-03-26",
  "2024-11-05",
  "2024-10-07",
];

/** Standard JSON-RPC 2.0 error codes (SDK types.js `ErrorCode`). */
export const ErrorCode = {
  ParseError: -32700,
  InvalidRequest: -32600,
  MethodNotFound: -32601,
  InvalidParams: -32602,
  InternalError: -32603,
} as const;

/** Thrown by a tool's `parse` when the arguments are invalid — mapped to -32602. */
export class InvalidParams extends Error {}

export interface ToolContent {
  type: "text";
  text: string;
}
export interface ToolResult {
  content: ToolContent[];
  isError?: boolean;
}

export interface Tool<T> {
  name: string;
  description: string;
  /** JSON Schema served verbatim in tools/list. */
  inputSchema: Record<string, unknown>;
  /** Validate raw `arguments`; return the typed value or throw InvalidParams. */
  parse(args: unknown): T;
  handler(input: T): Promise<ToolResult>;
}

interface JsonRpcId {
  id?: string | number | null;
}
type JsonRpcRequest = JsonRpcId & {
  jsonrpc?: string;
  method?: unknown;
  params?: any;
};

interface ServerOptions {
  name: string;
  version: string;
  tools: Tool<any>[];
}

function ok(id: string | number | null, result: unknown) {
  return { jsonrpc: "2.0" as const, id, result };
}
function fail(id: string | number | null, code: number, message: string) {
  return { jsonrpc: "2.0" as const, id, error: { code, message } };
}

export function createServer(opts: ServerOptions) {
  const byName = new Map(opts.tools.map(t => [t.name, t]));

  async function callTool(id: string | number | null, params: any) {
    const name = params?.name;
    const tool = typeof name === "string" ? byName.get(name) : undefined;
    if (!tool) {
      return fail(id, ErrorCode.InvalidParams, `Unknown tool: ${String(name)}`);
    }
    let input: unknown;
    try {
      input = tool.parse(params?.arguments);
    } catch (err) {
      const message =
        err instanceof InvalidParams
          ? err.message
          : `Invalid arguments: ${String(err)}`;
      return fail(id, ErrorCode.InvalidParams, message);
    }
    try {
      const result = await tool.handler(input);
      return ok(id, result);
    } catch (err) {
      // The tool contract already turns expected failures into an isError
      // ToolResult; reaching here means an unexpected throw. Never leak it as an
      // unhandled rejection — surface it as a JSON-RPC InternalError.
      return fail(
        id,
        ErrorCode.InternalError,
        `Tool "${tool.name}" failed: ${String(err)}`
      );
    }
  }

  /**
   * Handle one parsed JSON-RPC message. Returns the response object, or `null`
   * when the message is a notification that takes no reply.
   */
  async function handleMessage(msg: unknown): Promise<object | null> {
    // ── A BATCH IS AN ARRAY, AND AN ARRAY HAS NO `method` ─────────────────────
    //
    // Without this, the whole batch fell into the "Missing or invalid `method`"
    // branch below and produced ONE error with `id: null` — uncorrelatable to
    // anything the client sent, while every id inside it went unanswered and
    // the client blocked on each until its own timeout. `2025-03-26` is in
    // SUPPORTED_PROTOCOL_VERSIONS above and the initialize handler echoes it
    // back, so this server told clients it speaks the revision that introduced
    // batching. A host that batches its start-up calls saw the server fail to
    // come up rather than degrade.
    //
    // An all-notification batch returns null and, per JSON-RPC 2.0, is answered
    // with nothing at all — which the caller's `response !== null` guard
    // already does.
    if (Array.isArray(msg)) {
      if (msg.length === 0)
        return fail(null, ErrorCode.InvalidRequest, "Empty batch");
      const replies = (await Promise.all(msg.map(handleMessage))).filter(
        r => r !== null
      );
      return replies.length ? (replies as unknown as object) : null;
    }

    const req = (msg ?? {}) as JsonRpcRequest;
    const id = req.id ?? null;
    const method = req.method;

    if (typeof method !== "string") {
      return fail(id, ErrorCode.InvalidRequest, "Missing or invalid `method`");
    }

    // Client notifications (initialized, cancelled, progress, …) are one-way.
    if (method.startsWith("notifications/")) return null;

    switch (method) {
      case "initialize": {
        const requested = req.params?.protocolVersion;
        const protocolVersion = SUPPORTED_PROTOCOL_VERSIONS.includes(requested)
          ? requested
          : LATEST_PROTOCOL_VERSION;
        return ok(id, {
          protocolVersion,
          capabilities: { tools: {} },
          serverInfo: { name: opts.name, version: opts.version },
        });
      }
      case "ping":
        return ok(id, {});
      case "tools/list":
        return ok(id, {
          tools: opts.tools.map(t => ({
            name: t.name,
            description: t.description,
            inputSchema: t.inputSchema,
          })),
        });
      case "tools/call":
        return callTool(id, req.params);
      default:
        return fail(
          id,
          ErrorCode.MethodNotFound,
          `Method not found: ${method}`
        );
    }
  }

  return { handleMessage };
}
