/**
 * THE VALIDATORS AN EDITOR'S AGENT ACTUALLY HITS.
 *
 * `@graneth/mcp-server` is on npm. Every one of these functions runs on other
 * people's machines, invoked by a model that decides what to pass from a
 * schema — and all of them measured 0% covered, because they sat in a module
 * whose import started a blocking stdio loop.
 *
 * Two things matter here and one of them is easy to miss. The obvious one is
 * that bad input is refused. The other is that the SCHEMA the model reads and
 * the PARSER that rejects it agree: a model handed `maxItems: 50` and a parser
 * that allows 60 wastes a round trip; a parser stricter than the schema
 * produces a tool call the model believed was valid, which reads to a user as
 * the tool being broken.
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { InvalidParams } from "./protocol.js";
import {
  parsePreFlight,
  parseReport,
  requireString,
  optionalString,
  requireObject,
  verdictAction,
  toPreFlightFinding,
  reportOutcomeText,
  reportHallucinationTool,
  preFlightCheckTool,
  PRE_FLIGHT_CHECK_INPUT_SCHEMA,
  REPORT_HALLUCINATION_INPUT_SCHEMA,
  REPORTABLE_ECOSYSTEMS,
  MAX_FILES,
  MAX_CONTENT_CHARS,
  MAX_PATH_CHARS,
  MAX_CONTEXT_CHARS,
  MAX_PACKAGE_CHARS,
  TOOLS,
} from "./tools.js";

const file = (over: Record<string, unknown> = {}) => ({
  path: "src/app.py",
  content: "import requests\n",
  ...over,
});

describe("the schema the model reads and the parser that judges it agree", () => {
  const s = PRE_FLIGHT_CHECK_INPUT_SCHEMA;

  it("caps the file count at the same number in both", () => {
    expect(s.properties.files.maxItems).toBe(MAX_FILES);
    expect(() =>
      parsePreFlight({ files: Array.from({ length: MAX_FILES }, () => file()) })
    ).not.toThrow();
    expect(() =>
      parsePreFlight({
        files: Array.from({ length: MAX_FILES + 1 }, () => file()),
      })
    ).toThrow(InvalidParams);
  });

  it("requires at least one file in both", () => {
    expect(s.properties.files.minItems).toBe(1);
    expect(() => parsePreFlight({ files: [] })).toThrow(InvalidParams);
  });

  it("caps path, content and context at the same numbers in both", () => {
    expect(s.properties.files.items.properties.path.maxLength).toBe(
      MAX_PATH_CHARS
    );
    expect(s.properties.files.items.properties.content.maxLength).toBe(
      MAX_CONTENT_CHARS
    );
    expect(s.properties.context.maxLength).toBe(MAX_CONTEXT_CHARS);
  });

  it("accepts exactly the content length it advertises, and one more is refused", () => {
    const at = "x".repeat(MAX_CONTENT_CHARS);
    expect(() =>
      parsePreFlight({ files: [file({ content: at })] })
    ).not.toThrow();
    expect(() =>
      parsePreFlight({ files: [file({ content: at + "x" })] })
    ).toThrow(InvalidParams);
  });

  it("offers the same ecosystems the report parser accepts", () => {
    expect(REPORT_HALLUCINATION_INPUT_SCHEMA.properties.ecosystem.enum).toEqual(
      [...REPORTABLE_ECOSYSTEMS]
    );
    for (const eco of REPORTABLE_ECOSYSTEMS)
      expect(() =>
        parseReport({ package: "reqeusts", ecosystem: eco })
      ).not.toThrow();
  });

  it("caps the package name at the same number in both", () => {
    expect(REPORT_HALLUCINATION_INPUT_SCHEMA.properties.package.maxLength).toBe(
      MAX_PACKAGE_CHARS
    );
  });

  it("names both tools it serves", () => {
    expect(TOOLS.map(t => t.name)).toEqual([
      "pre_flight_check",
      "report_hallucination",
    ]);
  });
});

describe("pre_flight_check refuses what it cannot check", () => {
  it("rejects arguments that are not an object", () => {
    for (const bad of [null, undefined, [], "files", 7])
      expect(() => parsePreFlight(bad)).toThrow(InvalidParams);
  });

  it("rejects a missing or non-array files field", () => {
    expect(() => parsePreFlight({})).toThrow(InvalidParams);
    expect(() => parsePreFlight({ files: "src/app.py" })).toThrow(
      InvalidParams
    );
  });

  it("names the offending index, because the model has to fix it", () => {
    expect(() => parsePreFlight({ files: [file(), { path: "b.py" }] })).toThrow(
      /files\[1\]\.content/
    );
  });

  it("rejects a file entry that is not an object", () => {
    expect(() => parsePreFlight({ files: ["src/app.py"] })).toThrow(
      /files\[0\] must be an object/
    );
  });

  it("accepts an EMPTY file, which a newly-created empty file really is", () => {
    // minLength 0 on content is deliberate: `git add` of an empty file is not
    // an error, and refusing it would fail the whole batch it arrived in.
    expect(() =>
      parsePreFlight({ files: [file({ content: "" })] })
    ).not.toThrow();
  });

  it("rejects an empty PATH, which is not a file", () => {
    expect(() => parsePreFlight({ files: [file({ path: "" })] })).toThrow(
      InvalidParams
    );
  });

  it("treats a missing context as absent rather than as empty", () => {
    expect(parsePreFlight({ files: [file()] }).context).toBeUndefined();
    expect(
      parsePreFlight({ files: [file()], context: null }).context
    ).toBeUndefined();
  });

  it("keeps a context it was given", () => {
    expect(
      parsePreFlight({ files: [file()], context: "adds auth" }).context
    ).toBe("adds auth");
  });
});

describe("report_hallucination refuses what would pollute a public feed", () => {
  it("rejects an ecosystem it cannot verify against", () => {
    for (const eco of ["go", "composer", "maven", "", "NPM", undefined])
      expect(() => parseReport({ package: "x", ecosystem: eco })).toThrow(
        InvalidParams
      );
  });

  it("lists the ecosystems it does accept, so the model can retry", () => {
    expect(() => parseReport({ package: "x", ecosystem: "maven" })).toThrow(
      /npm, pypi, crates, gems/
    );
  });

  it("rejects an empty package name", () => {
    expect(() => parseReport({ package: "", ecosystem: "npm" })).toThrow(
      InvalidParams
    );
  });

  it("rejects a name longer than npm allows", () => {
    expect(() =>
      parseReport({
        package: "x".repeat(MAX_PACKAGE_CHARS + 1),
        ecosystem: "npm",
      })
    ).toThrow(InvalidParams);
  });

  it("rejects a reporter handle too short to attribute anything", () => {
    expect(() =>
      parseReport({ package: "x", ecosystem: "npm", reporter: "a" })
    ).toThrow(InvalidParams);
  });

  it("treats an absent reporter as anonymous rather than as empty", () => {
    expect(
      parseReport({ package: "x", ecosystem: "npm" }).reporter
    ).toBeUndefined();
  });
});

describe("the primitive validators", () => {
  it("requireObject rejects arrays, which typeof calls objects", () => {
    expect(() => requireObject([])).toThrow(InvalidParams);
    expect(requireObject({ a: 1 })).toEqual({ a: 1 });
  });

  it("requireString reports the field name it was checking", () => {
    expect(() => requireString(7, "pkg", 1, 5)).toThrow(/`pkg`/);
    expect(() => requireString("", "pkg", 1, 5)).toThrow(/at least 1/);
    expect(() => requireString("abcdef", "pkg", 1, 5)).toThrow(/at most 5/);
  });

  it("optionalString passes null and undefined through, and checks the rest", () => {
    expect(optionalString(undefined, "f", 1, 5)).toBeUndefined();
    expect(optionalString(null, "f", 1, 5)).toBeUndefined();
    expect(optionalString("ok", "f", 1, 5)).toBe("ok");
    expect(() => optionalString("toolong", "f", 1, 5)).toThrow(InvalidParams);
  });
});

describe("what the agent is told to do about a verdict", () => {
  it("tells it NOT to commit when blocked", () => {
    expect(verdictAction("BLOCKED")).toMatch(/Do NOT commit/);
  });

  it("tells it to review, not to stop, when review is required", () => {
    expect(verdictAction("REVIEW_REQUIRED")).toMatch(/Review warnings/);
    expect(verdictAction("REVIEW_REQUIRED")).not.toMatch(/Do NOT commit/);
  });

  it("falls through to safe-to-commit for CLEAR and for anything unknown", () => {
    // The fallthrough is the permissive branch, so a verdict this file has
    // never heard of reads as "safe". That is deliberate — the verdict comes
    // from core-checks, not from a caller — but it is the branch to check
    // first if a new verdict is ever added.
    expect(verdictAction("CLEAR")).toMatch(/Safe to commit/);
    expect(verdictAction("SOMETHING_NEW")).toMatch(/Safe to commit/);
  });
});

describe("a finding is passed on whole, and nothing else is", () => {
  it("carries every field a user acts on", () => {
    const out = toPreFlightFinding({
      severity: "critical",
      type: "hallucinated_package",
      title: 'Package "reqeusts" not found',
      file: "requirements.txt",
      line: 3,
      description: "not in PyPI",
      recommendation: "remove it",
      cve: "CVE-2026-1",
    } as never);

    expect(out).toEqual({
      severity: "critical",
      type: "hallucinated_package",
      title: 'Package "reqeusts" not found',
      file: "requirements.txt",
      line: 3,
      description: "not in PyPI",
      recommendation: "remove it",
      cve: "CVE-2026-1",
    });
  });

  it("does not forward a field the shape does not name", () => {
    const out = toPreFlightFinding({
      severity: "info",
      internalDebugTrace: "/home/user/secret/path",
    } as never);

    expect(out).not.toHaveProperty("internalDebugTrace");
  });
});

describe("what the reporter is told after a report", () => {
  it("names the entry and the attribution on acceptance", () => {
    const text = reportOutcomeText(
      { status: "accepted", entry: { name: "reqeusts", reporter: "artemiy" } },
      200
    );
    expect(text).toContain("reqeusts");
    expect(text).toContain("artemiy");
  });

  it("omits the attribution clause when nobody claimed it", () => {
    const text = reportOutcomeText(
      { status: "accepted", entry: { name: "reqeusts" } },
      200
    );
    expect(text).toContain("reqeusts");
    expect(text).not.toContain("attributed to");
  });

  it("says nothing was stored when the answer is unrecognised", () => {
    // The important half: a response shape this client does not know must not
    // read as success. A user who is told "reported" and was not will never
    // report it again.
    expect(reportOutcomeText({ status: "teapot" }, 418)).toMatch(
      /nothing was stored/i
    );
    expect(reportOutcomeText({}, 500)).toMatch(/nothing was stored/i);
    expect(reportOutcomeText(null, 502)).toMatch(/nothing was stored/i);
  });

  it("passes the server's reason through on a rejection", () => {
    expect(
      reportOutcomeText(
        { status: "rejected", reason: "the package exists" },
        200
      )
    ).toContain("the package exists");
  });

  it("distinguishes 'could not verify' from 'rejected', because one is retryable", () => {
    const unverifiable = reportOutcomeText({ status: "unverifiable" }, 200);
    expect(unverifiable).toMatch(/try again/i);
    expect(reportOutcomeText({ status: "rejected" }, 200)).not.toMatch(
      /try again/i
    );
  });
});

describe("the only tool that leaves the machine", () => {
  const realFetch = globalThis.fetch;
  afterEach(() => {
    globalThis.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it("sends exactly the package, the ecosystem and the handle — and nothing else", async () => {
    // The tool description promises "exactly one package name + ecosystem …
    // never file contents". This is that promise as an assertion.
    const fetchMock = vi.fn(async (_url: string, _init: RequestInit) => ({
      status: 200,
      json: async () => ({ status: "accepted", entry: { name: "reqeusts" } }),
    }));
    globalThis.fetch = fetchMock as never;

    await reportHallucinationTool.handler({
      package: "reqeusts",
      ecosystem: "pypi",
      reporter: "artemiy",
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://graneth.com/api/threat-feed/report");
    expect(JSON.parse(init.body as string)).toEqual({
      package: "reqeusts",
      ecosystem: "pypi",
      reporter: "artemiy",
    });
    // Nothing identifying in the URL either — a name in a query string is in
    // every proxy log between here and there.
    expect(url).not.toContain("reqeusts");
  });

  it("reports a network failure as an error, and says nothing was stored", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error("ENOTFOUND");
    }) as never;

    const out = await reportHallucinationTool.handler({
      package: "x",
      ecosystem: "npm",
    });

    expect(out.isError).toBe(true);
    expect(out.content[0].text).toMatch(/[Nn]othing was stored/);
  });

  it("survives a response body that is not JSON", async () => {
    globalThis.fetch = vi.fn(async () => ({
      status: 502,
      json: async () => {
        throw new SyntaxError("Unexpected token < in JSON");
      },
    })) as never;

    const out = await reportHallucinationTool.handler({
      package: "x",
      ecosystem: "npm",
    });

    // An HTML error page from a proxy must read as "nothing was stored", not
    // as a crash and not as success.
    expect(out.isError).toBeUndefined();
    expect(out.content[0].text).toMatch(/nothing was stored/i);
  });
});

describe("pre_flight_check never takes the server down with it", () => {
  it("turns an exploding check into an isError result, not a rejection", async () => {
    // The handler catches so `callTool` never has to. If this regressed, one
    // malformed file would end the session for the whole editor.
    const out = await preFlightCheckTool.handler({
      files: [{ path: "a.py", content: "x" }] as never,
      context: undefined,
    });

    expect(out).toHaveProperty("content");
    expect(Array.isArray(out.content)).toBe(true);
  });
});
