/**
 * Six-ecosystem expansion — import extraction (Rust, Go) and manifest
 * dependency extraction (Cargo.toml, go.mod, Gemfile, composer.json).
 *
 * Ruby and PHP get NO import-based extraction on purpose: `require "json"`
 * (Ruby stdlib vs gem name) and PHP `use App\Thing` (namespace, not package)
 * cannot be mapped to registry names reliably — flagging them would produce
 * false ghost criticals. Their manifests are the high-signal source.
 */
import { describe, it, expect } from "vitest";
import { extractImportedPackages, primaryEcosystem } from "./imports.js";
import { extractManifestPackages, manifestKind } from "./manifests.js";

// ─── primaryEcosystem routing ────────────────────────────────────────────────

describe("primaryEcosystem — new extensions", () => {
  it("routes .rs to crates and .go to go", () => {
    expect(primaryEcosystem("src/main.rs")).toBe("crates");
    expect(primaryEcosystem("cmd/server/main.go")).toBe("go");
  });

  it("does NOT route .rb / .php (manifest-only ecosystems)", () => {
    expect(primaryEcosystem("app/models/user.rb")).toBeNull();
    expect(primaryEcosystem("src/Controller.php")).toBeNull();
  });
});

// ─── Rust imports ────────────────────────────────────────────────────────────

describe("extractImportedPackages — Rust", () => {
  it("extracts crate roots from use and extern crate", () => {
    const refs = extractImportedPackages([{
      path: "src/lib.rs",
      content: [
        "use serde_json::Value;",
        "use tokio::net::TcpListener;",
        "extern crate rand;",
      ].join("\n"),
    }]);
    const names = refs.map((r) => r.pkg);
    expect(names).toContain("serde_json");
    expect(names).toContain("tokio");
    expect(names).toContain("rand");
    expect(refs.every((r) => r.ecosystem === "crates")).toBe(true);
  });

  it("skips built-ins and local paths (std/core/alloc/self/super/crate)", () => {
    const refs = extractImportedPackages([{
      path: "src/main.rs",
      content: [
        "use std::collections::HashMap;",
        "use core::fmt;",
        "use alloc::vec::Vec;",
        "use crate::config::Settings;",
        "use self::helpers::run;",
        "use super::shared;",
      ].join("\n"),
    }]);
    expect(refs).toHaveLength(0);
  });
});

// ─── Go imports ──────────────────────────────────────────────────────────────

describe("extractImportedPackages — Go", () => {
  it("extracts module roots from single imports and import blocks", () => {
    const refs = extractImportedPackages([{
      path: "main.go",
      content: [
        'import "github.com/pkg/errors"',
        "import (",
        '\t"fmt"',
        '\t"github.com/aws/aws-sdk-go-v2/service/s3"',
        '\t"golang.org/x/mod/semver"',
        ")",
      ].join("\n"),
    }]);
    const names = refs.map((r) => r.pkg);
    expect(names).toContain("github.com/pkg/errors");
    // subpackage import collapses to the 3-segment module root
    expect(names).toContain("github.com/aws/aws-sdk-go-v2");
    expect(names).toContain("golang.org/x/mod");
    expect(names).not.toContain("fmt"); // stdlib: no dot in first segment
  });

  it("skips stdlib and unknown vanity hosts (conservative — no root-guessing FPs)", () => {
    const refs = extractImportedPackages([{
      path: "main.go",
      content: [
        'import "net/http"',
        'import "custom-vanity.dev/team/pkg/sub"',
      ].join("\n"),
    }]);
    expect(refs).toHaveLength(0);
  });
});

// ─── Cargo.toml ──────────────────────────────────────────────────────────────

describe("extractManifestPackages — Cargo.toml", () => {
  it("recognizes the manifest kind", () => {
    expect(manifestKind("Cargo.toml")).toBe("cargo");
    expect(manifestKind("crates/foo/Cargo.toml")).toBe("cargo");
  });

  it("extracts deps from all dependency sections, skipping path/git deps", () => {
    const { refs, errors } = extractManifestPackages([{
      path: "Cargo.toml",
      content: [
        "[package]",
        'name = "my-app"',
        'version = "0.1.0"',
        'rust-version = "1.70"',
        "",
        "[dependencies]",
        'serde = "1.0"',
        'tokio = { version = "1", features = ["full"] }',
        'local-helper = { path = "../helper" }',
        'internal-git = { git = "https://github.com/org/x" }',
        "",
        "[dev-dependencies]",
        'insta = "1.34"',
        "",
        "[build-dependencies]",
        'cc = "1.0"',
      ].join("\n"),
    }]);
    expect(errors).toHaveLength(0);
    const names = refs.map((r) => r.pkg);
    expect(names).toEqual(expect.arrayContaining(["serde", "tokio", "insta", "cc"]));
    expect(names).not.toContain("local-helper");
    expect(names).not.toContain("internal-git");
    // [package] keys must never be treated as dependencies
    expect(names).not.toContain("my-app");
    expect(refs.every((r) => r.ecosystem === "crates")).toBe(true);
  });

  it("handles [dependencies.NAME] subtables and package= renames", () => {
    const { refs } = extractManifestPackages([{
      path: "Cargo.toml",
      content: [
        "[dependencies.serde_derive]",
        'version = "1.0"',
        "",
        "[dependencies.local_thing]",
        'path = "../thing"',
        "",
        "[dependencies]",
        'my_alias = { package = "real-crate-name", version = "2" }',
      ].join("\n"),
    }]);
    const names = refs.map((r) => r.pkg);
    expect(names).toContain("serde_derive");
    expect(names).not.toContain("local_thing"); // path dep
    expect(names).toContain("real-crate-name"); // rename: registry name is `package=`
    expect(names).not.toContain("my_alias");
  });
});

// ─── go.mod ──────────────────────────────────────────────────────────────────

describe("extractManifestPackages — go.mod", () => {
  it("recognizes the manifest kind", () => {
    expect(manifestKind("go.mod")).toBe("gomod");
    expect(manifestKind("services/api/go.mod")).toBe("gomod");
  });

  it("extracts require lines (block and single), skips locally-replaced modules", () => {
    const { refs, errors } = extractManifestPackages([{
      path: "go.mod",
      content: [
        "module github.com/acme/api",
        "",
        "go 1.22",
        "",
        "require github.com/pkg/errors v0.9.1",
        "",
        "require (",
        "\tgithub.com/gorilla/mux v1.8.1",
        "\tgolang.org/x/mod v0.17.0 // indirect",
        "\tgithub.com/acme/private-lib v0.0.0",
        ")",
        "",
        "replace github.com/acme/private-lib => ../private-lib",
      ].join("\n"),
    }]);
    expect(errors).toHaveLength(0);
    const names = refs.map((r) => r.pkg);
    expect(names).toEqual(expect.arrayContaining([
      "github.com/pkg/errors", "github.com/gorilla/mux", "golang.org/x/mod",
    ]));
    // replaced by a LOCAL path → never hits the proxy → must not be flagged
    expect(names).not.toContain("github.com/acme/private-lib");
    expect(refs.every((r) => r.ecosystem === "go")).toBe(true);
  });
});

// ─── Gemfile ─────────────────────────────────────────────────────────────────

describe("extractManifestPackages — Gemfile", () => {
  it("recognizes the manifest kind", () => {
    expect(manifestKind("Gemfile")).toBe("gemfile");
    expect(manifestKind("api/Gemfile")).toBe("gemfile");
  });

  it("extracts gem declarations, skipping path/git/github-sourced gems", () => {
    const { refs } = extractManifestPackages([{
      path: "Gemfile",
      content: [
        'source "https://rubygems.org"',
        "",
        'gem "rails", "~> 7.1"',
        "gem 'puma'",
        'gem "internal-lib", path: "../internal"',
        'gem "forked-thing", git: "https://github.com/org/x"',
        'gem "gh-thing", github: "org/y"',
        "# gem \"commented-out\"",
      ].join("\n"),
    }]);
    const names = refs.map((r) => r.pkg);
    expect(names).toEqual(expect.arrayContaining(["rails", "puma"]));
    expect(names).not.toContain("internal-lib");
    expect(names).not.toContain("forked-thing");
    expect(names).not.toContain("gh-thing");
    expect(names).not.toContain("commented-out");
    expect(refs.every((r) => r.ecosystem === "gems")).toBe(true);
  });
});

// ─── composer.json ───────────────────────────────────────────────────────────

describe("extractManifestPackages — composer.json", () => {
  it("recognizes the manifest kind (and does not shadow package.json)", () => {
    expect(manifestKind("composer.json")).toBe("composer");
    expect(manifestKind("package.json")).toBe("package.json");
  });

  it("extracts require + require-dev, skipping platform packages", () => {
    const { refs, errors } = extractManifestPackages([{
      path: "composer.json",
      content: JSON.stringify({
        name: "acme/app",
        require: {
          php: ">=8.1",
          "ext-json": "*",
          "lib-openssl": "*",
          "monolog/monolog": "^3.0",
          "guzzlehttp/guzzle": "^7.8",
        },
        "require-dev": { "phpunit/phpunit": "^10" },
      }, null, 2),
    }]);
    expect(errors).toHaveLength(0);
    const names = refs.map((r) => r.pkg);
    expect(names).toEqual(expect.arrayContaining([
      "monolog/monolog", "guzzlehttp/guzzle", "phpunit/phpunit",
    ]));
    expect(names).not.toContain("php");
    expect(names).not.toContain("ext-json");
    expect(names).not.toContain("lib-openssl");
    expect(refs.every((r) => r.ecosystem === "composer")).toBe(true);
  });

  it("an unparsable composer.json is a reported error, never silent-clean", () => {
    const { refs, errors } = extractManifestPackages([{
      path: "composer.json",
      content: "{ not json",
    }]);
    expect(refs).toHaveLength(0);
    expect(errors).toHaveLength(1);
    expect(errors[0].file).toBe("composer.json");
  });
});
