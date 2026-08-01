/**
 * Coverage for registry.ts — the portable, cache-free npm/PyPI existence
 * check used by the standalone MCP server. Pins the documented fail-OPEN
 * contract: a registry outage must never block a commit on a false
 * "does not exist" — it returns exists:true with the `unreachable` marker
 * the caller surfaces (deliberately different from the server-side
 * fail-closed scanner contract).
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import { ECOSYSTEMS, packageExists } from "./registry.js";

const DAY_MS = 24 * 60 * 60 * 1000;

function mockFetchOnce(status: number, body?: unknown) {
  const res = {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  };
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue(res));
}

afterEach(() => vi.unstubAllGlobals());

describe("packageExists — npm", () => {
  it("404 → does not exist", async () => {
    mockFetchOnce(404);
    expect(await packageExists("no-such-pkg-xyz", "npm")).toEqual({
      exists: false, isNewPackage: false, publishedAt: null,
    });
  });

  it("200 with a recent first publish → exists and isNewPackage", async () => {
    const created = new Date(Date.now() - 3 * DAY_MS).toISOString();
    mockFetchOnce(200, { versions: { "1.0.0": {} }, time: { created } });
    const r = await packageExists("fresh-pkg", "npm");
    expect(r.exists).toBe(true);
    expect(r.isNewPackage).toBe(true);
    expect(r.publishedAt).toEqual(new Date(created));
  });

  it("200 with an old first publish → exists, not new", async () => {
    mockFetchOnce(200, { versions: { "1.0.0": {} }, time: { created: "2018-01-01T00:00:00.000Z" } });
    const r = await packageExists("old-pkg", "npm");
    expect(r).toMatchObject({ exists: true, isNewPackage: false });
  });

  it("200 without time metadata → exists, not new, null publishedAt", async () => {
    mockFetchOnce(200, {});
    // toMatchObject: the npm result also carries advisory trust signals
    // (hasInstallScripts/hasProvenance/isDeprecated/hasRepository) parsed from
    // the same packument — assert the core existence fields here.
    expect(await packageExists("weird-pkg", "npm")).toMatchObject({
      exists: true, isNewPackage: false, publishedAt: null,
    });
  });

  it("extracts npm trust signals from the packument (no extra fetch)", async () => {
    mockFetchOnce(200, {
      "dist-tags": { latest: "2.0.0" },
      versions: { "2.0.0": { scripts: { postinstall: "node x.js" }, deprecated: "use y", dist: { attestations: { url: "…" } } } },
      time: { created: "2020-01-01T00:00:00.000Z" },
      repository: { url: "git+https://github.com/a/b.git" },
    });
    const r = await packageExists("signal-pkg", "npm");
    expect(r).toMatchObject({ exists: true, hasInstallScripts: true, isDeprecated: true, hasProvenance: true, hasRepository: true });
  });
});

describe("packageExists — pypi", () => {
  it("404 → does not exist", async () => {
    mockFetchOnce(404);
    expect(await packageExists("no-such-dist", "pypi")).toEqual({
      exists: false, isNewPackage: false, publishedAt: null,
    });
  });

  it("200 → earliest release upload_time drives isNewPackage", async () => {
    mockFetchOnce(200, {
      releases: {
        "1.0.0": [{ upload_time: "2019-05-01T00:00:00" }],
        "2.0.0": [{ upload_time: "2024-01-01T00:00:00" }],
      },
    });
    const r = await packageExists("old-dist", "pypi");
    expect(r.exists).toBe(true);
    expect(r.isNewPackage).toBe(false);
    expect(r.publishedAt).toEqual(new Date("2019-05-01T00:00:00"));
  });

  it("200 with no releases → exists, null publishedAt", async () => {
    mockFetchOnce(200, { releases: {} });
    expect(await packageExists("empty-dist", "pypi")).toEqual({
      exists: true, isNewPackage: false, publishedAt: null,
    });
  });
});

describe("packageExists — a hostile package name cannot reshape the registry request", () => {
  // Defence in depth. Packagist + the Go proxy are the two registries whose names
  // legitimately contain `/`, so the name can't be blanket-encoded — it used to be
  // interpolated RAW. The host is a hardcoded literal (the name only ever lands in
  // the PATH, so it can never redirect to another host), but a name carrying `@`,
  // `?`, `#` or a space could still reshape the request to the fixed registry.
  it("Packagist: odd characters in the name are percent-encoded, the vendor/name slash is kept", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(String(url)).toContain("/packages/evil%40host/x%3Fa%3Db%23f.json");
      expect(String(url).startsWith("https://packagist.org/")).toBe(true);
      return { ok: false, status: 404 } as any;
    });
    vi.stubGlobal("fetch", fetchMock);
    expect((await packageExists("evil@host/x?a=b#f", "composer")).exists).toBe(false);
  });

  it("Packagist: a real vendor/name is passed through untouched", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(String(url)).toContain("/packages/monolog/monolog.json");
      return { ok: true, status: 200, json: async () => ({ package: { time: "2011-01-01T00:00:00+00:00" } }) } as any;
    });
    vi.stubGlobal("fetch", fetchMock);
    expect((await packageExists("monolog/monolog", "composer")).exists).toBe(true);
  });

  it("Go proxy: odd characters are encoded while the !-escaping and path slashes survive", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(String(url)).toContain("/github.com/!azure/x%20y/@latest");
      expect(String(url).startsWith("https://proxy.golang.org/")).toBe(true);
      return { ok: false, status: 404 } as any;
    });
    vi.stubGlobal("fetch", fetchMock);
    expect((await packageExists("github.com/Azure/x y", "go")).exists).toBe(false);
  });
});

describe("packageExists — scoped npm names", () => {
  it("requests @scope%2Fname with a raw @ (a %40-encoded path is rejected by npm)", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(String(url)).toContain("/@fastify%2Fcors");
      expect(String(url)).not.toContain("%40");
      return { ok: true, status: 200, json: async () => ({ versions: { "1.0.0": {} }, time: { created: "2020-01-01T00:00:00.000Z" } }) } as any;
    });
    vi.stubGlobal("fetch", fetchMock);
    const r = await packageExists("@fastify/cors", "npm");
    expect(r.exists).toBe(true);
    expect(r.unreachable).toBeUndefined();
  });
});

describe("packageExists — fail-open contract on registry outage", () => {
  it("non-2xx/non-404 → exists:true with the unreachable marker (never a false 'does not exist')", async () => {
    mockFetchOnce(503);
    expect(await packageExists("any-pkg", "npm")).toEqual({
      exists: true, isNewPackage: false, publishedAt: null, unreachable: true,
    });
  });

  it("network error → same unreachable result", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("ECONNRESET")));
    expect(await packageExists("any-dist", "pypi")).toEqual({
      exists: true, isNewPackage: false, publishedAt: null, unreachable: true,
    });
  });
});

describe("packageExists — crates.io", () => {
  it("404 → does not exist", async () => {
    mockFetchOnce(404);
    expect((await packageExists("no-such-crate-xyz", "crates")).exists).toBe(false);
  });

  it("200 → exists; crate.created_at drives isNewPackage; sends a User-Agent (crates.io 403s without one)", async () => {
    const created = new Date(Date.now() - 5 * DAY_MS).toISOString();
    const fetchMock = vi.fn(async (_url: string, init: any) => {
      expect(init?.headers?.["User-Agent"]).toBeTruthy();
      return { ok: true, status: 200, json: async () => ({ crate: { created_at: created } }) } as any;
    });
    vi.stubGlobal("fetch", fetchMock);
    const r = await packageExists("fresh-crate", "crates");
    expect(r.exists).toBe(true);
    expect(r.isNewPackage).toBe(true);
    expect(r.publishedAt).toEqual(new Date(created));
  });

  it("outage → fail-open unreachable", async () => {
    mockFetchOnce(500);
    expect(await packageExists("any-crate", "crates")).toMatchObject({ exists: true, unreachable: true });
  });
});

describe("packageExists — RubyGems", () => {
  it("404 → does not exist", async () => {
    mockFetchOnce(404);
    expect((await packageExists("no-such-gem-xyz", "gems")).exists).toBe(false);
  });

  it("200 → the OLDEST version's created_at drives isNewPackage (latest release date must not read as 'new')", async () => {
    mockFetchOnce(200, [
      { number: "8.1.3", created_at: new Date(Date.now() - 2 * DAY_MS).toISOString() },
      { number: "1.0.0", created_at: "2010-08-29T00:00:00.000Z" },
    ]);
    const r = await packageExists("rails", "gems");
    expect(r.exists).toBe(true);
    expect(r.isNewPackage).toBe(false); // first published 2010, recent update ≠ new package
    expect(r.publishedAt).toEqual(new Date("2010-08-29T00:00:00.000Z"));
  });

  it("outage → fail-open unreachable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("timeout")));
    expect(await packageExists("any-gem", "gems")).toMatchObject({ exists: true, unreachable: true });
  });
});

describe("packageExists — Packagist (composer)", () => {
  it("404 → does not exist", async () => {
    mockFetchOnce(404);
    expect((await packageExists("no-vendor/no-pkg", "composer")).exists).toBe(false);
  });

  it("200 → package.time (first publish) drives isNewPackage", async () => {
    mockFetchOnce(200, { package: { time: "2011-09-27T00:35:19+00:00" } });
    const r = await packageExists("monolog/monolog", "composer");
    expect(r.exists).toBe(true);
    expect(r.isNewPackage).toBe(false);
    expect(r.publishedAt).toEqual(new Date("2011-09-27T00:35:19+00:00"));
  });
});

describe("packageExists — Go module proxy", () => {
  it("404 → does not exist", async () => {
    mockFetchOnce(404);
    expect((await packageExists("github.com/nope/nope", "go")).exists).toBe(false);
  });

  it("410 → does not exist (proxy uses 410 Gone for known-missing modules)", async () => {
    mockFetchOnce(410);
    expect((await packageExists("github.com/gone/gone", "go")).exists).toBe(false);
  });

  it("uppercase letters are !-escaped in the proxy URL (github.com/Azure → github.com/!azure)", async () => {
    const fetchMock = vi.fn(async (url: string) => {
      expect(String(url)).toContain("/github.com/!azure/azure-sdk-for-go/@latest");
      return { ok: true, status: 200, json: async () => ({ Version: "v68.0.0", Time: "2023-01-01T00:00:00Z" }) } as any;
    });
    vi.stubGlobal("fetch", fetchMock);
    const r = await packageExists("github.com/Azure/azure-sdk-for-go", "go");
    expect(r.exists).toBe(true);
  });
});

describe("ECOSYSTEMS — the runtime set, so nothing downstream has to write a number", () => {
  it("names every registry the detector has a client for", () => {
    // Sorted, so the assertion is about membership rather than declaration
    // order — the band that consumes this reads order from its own model.
    expect([...ECOSYSTEMS].sort()).toEqual(["composer", "crates", "gems", "go", "npm", "pypi"]);
  });

  it("is derived from the client table, not written beside it", async () => {
    // The property that makes it safe to count: every member answers. A hand
    // list could name a registry with no client, and the caller would render a
    // set member the detector cannot actually query.
    for (const eco of ECOSYSTEMS) {
      mockFetchOnce(404);
      await expect(packageExists("definitely-not-a-real-package-xyz", eco)).resolves.toBeDefined();
    }
  });
});
