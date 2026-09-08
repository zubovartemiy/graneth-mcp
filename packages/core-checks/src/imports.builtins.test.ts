/**
 * The Node-builtin list in imports.ts is INLINED on purpose (the shared core is
 * bundled for the browser too, and a static `import … from "node:module"`
 * resolves to Vite's throwing browser stub — it blanked the whole landing).
 *
 * That trade buys runtime portability at the cost of possible drift, so this
 * test pins the list against Node's own `builtinModules`: when a future Node
 * adds a builtin, CI fails here instead of the scanner silently reporting a
 * false CRITICAL ("`node:newthing` does not exist in npm") on real code.
 */
import { describe, it, expect } from "vitest";
import { builtinModules } from "node:module";
import { isNodeBuiltin, isResolvableNpmName } from "./imports.js";

describe("Node builtin recognition (drift guard)", () => {
  it("recognises every builtin Node itself reports", () => {
    // Node lists a few deprecated/internal aliases that are not import targets
    // in practice; everything else must be covered by the inlined set.
    const ignored = new Set([
      "_http_agent",
      "_http_client",
      "_http_common",
      "_http_incoming",
      "_http_outgoing",
      "_http_server",
      "_stream_duplex",
      "_stream_passthrough",
      "_stream_readable",
      "_stream_transform",
      "_stream_wrap",
      "_stream_writable",
      "_tls_common",
      "_tls_wrap",
      "freelist",
      "node:sea",
      "node:sqlite",
      "node:test",
      "node:test/reporters",
      "wasi",
    ]);
    const missing = builtinModules
      .filter(m => !ignored.has(m) && !m.startsWith("internal/"))
      .filter(m => !isNodeBuiltin(m));
    expect(
      missing,
      `inlined NODE_BUILTINS is missing: ${missing.join(", ")}`
    ).toEqual([]);
  });

  it("treats the node: protocol form as a builtin regardless of the list", () => {
    expect(isNodeBuiltin("node:fs")).toBe(true);
    expect(isNodeBuiltin("node:some-future-builtin")).toBe(true);
  });

  it("never lets a builtin reach the registry, and still resolves real packages", () => {
    for (const b of ["fs", "fs/promises", "node:crypto", "path"]) {
      expect(
        isResolvableNpmName(b),
        `${b} must not be treated as an npm name`
      ).toBe(false);
    }
    for (const pkg of ["express", "@scope/pkg", "left-pad"]) {
      expect(isResolvableNpmName(pkg), `${pkg} must stay resolvable`).toBe(
        true
      );
    }
  });
});
