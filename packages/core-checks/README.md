# @graneth/core-checks

The detection primitives shared by [`@graneth/mcp-server`](../mcp-server) and the hosted
Graneth scanner: hallucinated-package detection, manifest and import extraction, registry
existence checks, dependency risk scoring, and secret detection.

Framework-free and dependency-free — it reaches for nothing but `fetch` and the standard
library, because a supply-chain security tool that drags in a dependency tree is arguing
against itself.

## You cannot install this

`@graneth/core-checks` is **not on npm** and never will be. `package.json` carries
`"private": true`, and its `files` field ships only `dist` and `LICENSE`, so this README
cannot become an npm surface either.

It exists as a workspace package for one reason: the account-free local pre-flight and the
hosted PR scanner must run _the same code_, so that a `CLEAR` from your editor and a `CLEAR`
from the server mean the same thing for the checks they share. Vendoring it twice would have
meant two subtly different answers to the same question.

If you want to run these checks, install [`@graneth/mcp-server`](https://www.npmjs.com/package/@graneth/mcp-server),
which bundles this module into its `dist/`.

## Why the source is public

This is a tool that tells you which of your dependencies to distrust. Verifying that claim
means reading how it decides — so the detection logic is mirrored, in source, at
[zubovartemiy/graneth-mcp](https://github.com/zubovartemiy/graneth-mcp) even though the
package itself is private.

Every detection module is there. **Some tests are deliberately held back**: their fixtures are
literal example credentials — real-shaped AWS, Stripe and PEM strings needed to prove the
secret detector fires — and a public repository full of credential-shaped strings is a
liability to everyone who scans it, including this tool. The modules they cover are present;
only the fixtures are withheld.

## What is here

| Module                                         | Answers                                                                                                            |
| ---------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| `registry.ts`                                  | Does this package exist? Six clients — npm, PyPI, crates.io, RubyGems, Go proxy, Packagist — behind one interface. |
| `imports.ts`                                   | Which packages does this source file reference? JS/TS, Python, Rust, Go.                                           |
| `manifests.ts`                                 | Which packages does this manifest declare? Six filenames, registry-resolvable specs only.                          |
| `preflight.ts`                                 | The orchestrator: runs the checks, assigns severity, returns the verdict.                                          |
| `knownHallucinations.ts` · `threatSnapshot.ts` | The bundled threat-feed snapshot, checked locally with no network call.                                            |
| `riskScore.ts`                                 | Is this _real_ package shaped like an attack? Compounding signals, npm only.                                       |
| `secrets.ts`                                   | Known credential patterns plus entropy analysis with variable-name context.                                        |
| `internalNames.ts`                             | Is this 404 a hallucination, or your own workspace package?                                                        |

`internalNames.ts` is the one worth understanding before trusting any of the others. A
tsconfig path alias and a `private: true` workspace package are both valid-looking names that
404 by design — so a checker that treats every 404 as a hallucination is wrong about every
monorepo it meets. Existence checks consult internal-name evidence first.

## Scope

These are the **portable** checks — the ones that need nothing but the files in front of them
and a public registry. The hosted scanner adds typosquat and edit-distance detection, a
Postgres-cached verifier, Semgrep rules, reachability and taint analysis, cross-file stitching
and LLM triage. None of that is here, and a clean result from this module is not a prediction
of a clean full scan.

## License

MIT — see [LICENSE](LICENSE).
