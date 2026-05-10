/**
 * Regression tests for the URL trust boundary on `NotebookLibrary`.
 *
 * Pins three behaviours added to fix Codex's "Critical: Stored Trusted-
 * State Notebook URL Poisoning" finding:
 *
 *   1. addNotebook(url=…) MUST run validateNotebookUrl() before persist.
 *      A read-scope tool call planting `https://attacker.example/...`
 *      would later let SessionManager navigate the authenticated browser
 *      to that origin and BrowserSession would write NotebookLM
 *      sessionStorage there.
 *
 *   2. updateNotebook({url:"…"}) MUST run the same validator.
 *
 *   3. loadLibrary() MUST defensively re-validate every persisted URL on
 *      read and drop bad entries — covers the case where the library was
 *      written before the validator existed (or by a downgrade attack
 *      that bypassed runtime checks).
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";

const { TMP_ROOT } = vi.hoisted(() => {
  const _fs = require("node:fs") as typeof import("node:fs");
  const _os = require("node:os") as typeof import("node:os");
  const _path = require("node:path") as typeof import("node:path");
  return {
    TMP_ROOT: _fs.mkdtempSync(_path.join(_os.tmpdir(), "nlmcp-library-url-test-")),
  };
});

vi.mock("../src/config.js", async () => {
  const actual = await vi.importActual<typeof import("../src/config.js")>("../src/config.js");
  return {
    ...actual,
    CONFIG: {
      ...actual.CONFIG,
      dataDir: TMP_ROOT,
      configDir: TMP_ROOT,
      notebookUrl: "",
      notebookDescription:
        "General knowledge base - configure NOTEBOOK_DESCRIPTION to help Claude understand what's in this notebook",
    },
  };
});

import { NotebookLibrary } from "../src/library/notebook-library.js";
import { SecurityError } from "../src/utils/security.js";

const VALID_URL = "https://notebooklm.google.com/notebook/abc";
const POISONED_URL = "https://attacker.example/notebook/abc";

beforeEach(() => {
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
  fs.mkdirSync(TMP_ROOT, { recursive: true });
  vi.clearAllMocks();
});

afterEach(() => {
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
  fs.mkdirSync(TMP_ROOT, { recursive: true });
});

describe("addNotebook URL validation", () => {
  it("accepts a NotebookLM URL", () => {
    const lib = new NotebookLibrary();
    const nb = lib.addNotebook({
      url: VALID_URL,
      name: "OK",
      description: "ok",
      topics: [],
    });
    expect(nb.url).toBe(VALID_URL);
  });

  it("rejects a non-NotebookLM URL", () => {
    const lib = new NotebookLibrary();
    expect(() =>
      lib.addNotebook({
        url: POISONED_URL,
        name: "Bad",
        description: "evil",
        topics: [],
      }),
    ).toThrow(/Domain not allowed/);
  });

  it("rejects javascript: URLs as a notebook entry", () => {
    const lib = new NotebookLibrary();
    expect(() =>
      lib.addNotebook({
        url: "javascript:alert(1)",
        name: "XSS",
        description: "evil",
        topics: [],
      }),
    ).toThrow(SecurityError);
  });

  it("rejects empty URL", () => {
    const lib = new NotebookLibrary();
    expect(() =>
      lib.addNotebook({
        url: "",
        name: "Blank",
        description: "blank",
        topics: [],
      }),
    ).toThrow();
  });
});

describe("updateNotebook URL validation", () => {
  it("rejects an attempt to swap a valid entry's URL for a poisoned one", () => {
    const lib = new NotebookLibrary();
    const nb = lib.addNotebook({
      url: VALID_URL,
      name: "OK",
      description: "ok",
      topics: [],
    });

    expect(() => lib.updateNotebook({ id: nb.id, url: POISONED_URL })).toThrow(
      /Domain not allowed/,
    );

    // The on-disk record is unchanged after the rejected update.
    const lib2 = new NotebookLibrary();
    const reloaded = lib2.getNotebook(nb.id);
    expect(reloaded?.url).toBe(VALID_URL);
  });

  it("permits updates that change non-URL fields", () => {
    const lib = new NotebookLibrary();
    const nb = lib.addNotebook({
      url: VALID_URL,
      name: "OK",
      description: "ok",
      topics: [],
    });
    const updated = lib.updateNotebook({ id: nb.id, name: "Renamed" });
    expect(updated.name).toBe("Renamed");
    expect(updated.url).toBe(VALID_URL);
  });
});

describe("loadLibrary defensive revalidation", () => {
  it("strips entries with poisoned URLs from a pre-existing library.json", () => {
    // Simulate a library written by an older (vulnerable) version that
    // had no URL validation at write time.
    const libraryPath = path.join(TMP_ROOT, "library.json");
    const poisoned = {
      notebooks: [
        {
          id: "good",
          url: VALID_URL,
          name: "Good",
          description: "ok",
          topics: [],
          content_types: [],
          use_cases: [],
          added_at: new Date().toISOString(),
          last_used: new Date().toISOString(),
          use_count: 0,
          tags: [],
        },
        {
          id: "bad",
          url: POISONED_URL,
          name: "Bad",
          description: "evil",
          topics: [],
          content_types: [],
          use_cases: [],
          added_at: new Date().toISOString(),
          last_used: new Date().toISOString(),
          use_count: 0,
          tags: [],
        },
      ],
      active_notebook_id: "bad",
      last_modified: new Date().toISOString(),
      version: "1.0.0",
    };
    fs.writeFileSync(libraryPath, JSON.stringify(poisoned));

    const lib = new NotebookLibrary();
    const ids = lib.listNotebooks().map((n) => n.id);
    expect(ids).toContain("good");
    expect(ids).not.toContain("bad");
    // Active pointer was the bad one — must be cleared on load.
    expect(lib.getActiveNotebook()?.id ?? null).not.toBe("bad");
  });

  it("re-persists the cleaned library so the bad entry doesn't reappear", () => {
    const libraryPath = path.join(TMP_ROOT, "library.json");
    const poisoned = {
      notebooks: [
        {
          id: "bad",
          url: POISONED_URL,
          name: "Bad",
          description: "evil",
          topics: [],
          content_types: [],
          use_cases: [],
          added_at: new Date().toISOString(),
          last_used: new Date().toISOString(),
          use_count: 0,
          tags: [],
        },
      ],
      active_notebook_id: "bad",
      last_modified: new Date().toISOString(),
      version: "1.0.0",
    };
    fs.writeFileSync(libraryPath, JSON.stringify(poisoned));

    new NotebookLibrary();
    const persisted = JSON.parse(fs.readFileSync(libraryPath, "utf8"));
    expect(persisted.notebooks).toHaveLength(0);
    expect(persisted.active_notebook_id).toBeNull();
  });
});
