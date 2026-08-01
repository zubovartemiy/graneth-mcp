import { describe, it, expect } from "vitest";
import {
  createServer,
  InvalidParams,
  SUPPORTED_PROTOCOL_VERSIONS,
  LATEST_PROTOCOL_VERSION,
  type Tool,
} from "./protocol.js";

// A trivial echo tool to exercise dispatch without touching the real detector.
const echoTool: Tool<{ msg: string }> = {
  name: "echo",
  description: "echoes",
  inputSchema: {
    type: "object",
    properties: { msg: { type: "string" } },
    required: ["msg"],
    additionalProperties: false,
  },
  parse(args: unknown) {
    if (!args || typeof args !== "object" || typeof (args as any).msg !== "string") {
      throw new InvalidParams("msg (string) is required");
    }
    return { msg: (args as any).msg };
  },
  async handler(input) {
    return { content: [{ type: "text", text: `echo: ${input.msg}` }] };
  },
};

const throwingTool: Tool<Record<string, never>> = {
  name: "boom",
  description: "throws",
  inputSchema: { type: "object", properties: {}, additionalProperties: false },
  parse() {
    return {};
  },
  async handler() {
    throw new Error("kaboom");
  },
};

function server() {
  return createServer({ name: "graneth", version: "9.9.9", tools: [echoTool, throwingTool] });
}

describe("MCP protocol core", () => {
  it("initialize echoes a supported protocol version back", async () => {
    const s = server();
    const r: any = await s.handleMessage({
      jsonrpc: "2.0",
      id: 1,
      method: "initialize",
      params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "c", version: "1" } },
    });
    expect(r.jsonrpc).toBe("2.0");
    expect(r.id).toBe(1);
    expect(r.result.protocolVersion).toBe("2025-06-18");
    expect(r.result.serverInfo).toEqual({ name: "graneth", version: "9.9.9" });
    expect(r.result.capabilities.tools).toBeDefined();
  });

  it("initialize falls back to the latest version for an unknown one", async () => {
    const s = server();
    const r: any = await s.handleMessage({
      jsonrpc: "2.0",
      id: 2,
      method: "initialize",
      params: { protocolVersion: "1999-01-01", capabilities: {} },
    });
    expect(r.result.protocolVersion).toBe(LATEST_PROTOCOL_VERSION);
    expect(SUPPORTED_PROTOCOL_VERSIONS).toContain(LATEST_PROTOCOL_VERSION);
  });

  it("notifications/initialized produces no response (null)", async () => {
    const s = server();
    const r = await s.handleMessage({ jsonrpc: "2.0", method: "notifications/initialized" });
    expect(r).toBeNull();
  });

  it("ping returns an empty result", async () => {
    const s = server();
    const r: any = await s.handleMessage({ jsonrpc: "2.0", id: 3, method: "ping" });
    expect(r.result).toEqual({});
  });

  it("tools/list returns every tool with its JSON-Schema inputSchema", async () => {
    const s = server();
    const r: any = await s.handleMessage({ jsonrpc: "2.0", id: 4, method: "tools/list" });
    const names = r.result.tools.map((t: any) => t.name);
    expect(names).toEqual(["echo", "boom"]);
    const echo = r.result.tools.find((t: any) => t.name === "echo");
    expect(echo.description).toBe("echoes");
    expect(echo.inputSchema.type).toBe("object");
    expect(echo.inputSchema.required).toEqual(["msg"]);
  });

  it("tools/call dispatches to the matching handler", async () => {
    const s = server();
    const r: any = await s.handleMessage({
      jsonrpc: "2.0",
      id: 5,
      method: "tools/call",
      params: { name: "echo", arguments: { msg: "hi" } },
    });
    expect(r.result.content[0].text).toBe("echo: hi");
    expect(r.error).toBeUndefined();
  });

  it("tools/call with invalid arguments → InvalidParams (-32602)", async () => {
    const s = server();
    const r: any = await s.handleMessage({
      jsonrpc: "2.0",
      id: 6,
      method: "tools/call",
      params: { name: "echo", arguments: { msg: 123 } },
    });
    expect(r.error.code).toBe(-32602);
    expect(r.result).toBeUndefined();
  });

  it("tools/call for an unknown tool → error, not a crash", async () => {
    const s = server();
    const r: any = await s.handleMessage({
      jsonrpc: "2.0",
      id: 7,
      method: "tools/call",
      params: { name: "nope", arguments: {} },
    });
    expect(r.error.code).toBe(-32602);
    expect(String(r.error.message)).toMatch(/unknown tool/i);
  });

  it("a handler that throws → InternalError (-32603), never an unhandled rejection", async () => {
    const s = server();
    const r: any = await s.handleMessage({
      jsonrpc: "2.0",
      id: 8,
      method: "tools/call",
      params: { name: "boom", arguments: {} },
    });
    expect(r.error.code).toBe(-32603);
  });

  it("unknown method → MethodNotFound (-32601)", async () => {
    const s = server();
    const r: any = await s.handleMessage({ jsonrpc: "2.0", id: 9, method: "resources/list" });
    expect(r.error.code).toBe(-32601);
  });

  it("a request with a string id preserves that id in the response", async () => {
    const s = server();
    const r: any = await s.handleMessage({ jsonrpc: "2.0", id: "abc", method: "ping" });
    expect(r.id).toBe("abc");
  });
});
