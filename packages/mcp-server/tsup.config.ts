import { defineConfig } from "tsup";

export default defineConfig({
  entry: ["src/index.ts"],
  format: ["esm"],
  target: "node18",
  platform: "node",
  outDir: "dist",
  clean: true,
  // The entry's `#!/usr/bin/env node` shebang is preserved by tsup so dist is
  // directly executable as the `graneth-mcp-server` bin.
  //
  // Bundle @graneth/core-checks source into the single output file so the
  // published package is self-contained. As of v0.7.0 there are NO runtime
  // dependencies at all: the MCP/JSON-RPC layer is hand-rolled (protocol.ts)
  // and validation is inline, so nothing needs to stay external — core-checks
  // is imported by relative source path and is always bundled. Node built-ins
  // (node:readline) are external by default on the node18 target.
});
