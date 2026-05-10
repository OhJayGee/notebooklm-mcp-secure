/**
 * Regression test for tool-scope classification.
 *
 * Pre-fix (Codex H finding "The Read-Only Token Is Not Read-Only"),
 * mutating tools — add_notebook, update_notebook, remove_notebook,
 * select_notebook, create_notebook, batch_create_notebooks,
 * sync_library, add_source, remove_source, generate_audio_overview,
 * generate_video_overview, generate_data_table, set_quota_tier,
 * close_session, reset_session — were classified read-scope. A
 * read-only token (or auth-disabled deployment) could mutate library
 * state, trigger remote NotebookLM mutations, and tweak quota.
 *
 * Post-fix, every one of those tools sits in TOOLS_REQUIRING_AUTH and
 * forces admin-scope auth even when global auth is disabled.
 *
 * This test reads the source file directly because the two Sets are
 * module-private and the index.ts module is heavy to import for a
 * unit test (it pulls in all transports and registers handlers). A
 * source-text check is brittle but correct: if someone edits the Sets,
 * this test sees the change immediately.
 */

import { describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const indexSrc = fs.readFileSync(path.join(here, "..", "src", "index.ts"), "utf8");

function setMembers(setName: string): Set<string> {
  const re = new RegExp(`const\\s+${setName}\\s*=\\s*new\\s+Set<[^>]*>\\(\\[(.*?)\\]\\)`, "s");
  const match = re.exec(indexSrc);
  if (!match) {
    throw new Error(`Could not find ${setName} in src/index.ts`);
  }
  // Strip line comments first so a `//` block that immediately precedes
  // a tool name on the next line doesn't swallow it when we extract
  // string literals. Block comments aren't used inside these arrays so
  // we don't have to handle `/* … */`.
  const noComments = match[1].replace(/\/\/[^\n]*/g, "");
  // Pull every "literal" out of the array body — far more robust than
  // splitting on commas, which mishandles comments and nested commas.
  const members = Array.from(noComments.matchAll(/"([^"]+)"/g)).map((m) => m[1]);
  return new Set(members);
}

describe("Tool scope classification (CODEX_REVIEW.md Read-Only Token finding)", () => {
  const requiringAuth = setMembers("TOOLS_REQUIRING_AUTH");
  const exemptFromAuth = setMembers("TOOLS_EXEMPT_FROM_AUTH");

  // Tools that mutate persistent local state, mutate remote NotebookLM
  // state, write to the filesystem, perform outbound HTTP, or affect
  // rate-limit decisions for every tool. None of these may sit in the
  // "read scope is enough" bucket.
  const MUTATING_TOOLS = [
    "add_notebook",
    "update_notebook",
    "remove_notebook",
    "select_notebook",
    "create_notebook",
    "batch_create_notebooks",
    "sync_library",
    "add_source",
    "remove_source",
    "generate_audio_overview",
    "generate_video_overview",
    "generate_data_table",
    "set_quota_tier",
    "close_session",
    "reset_session",
    "add_folder",
    "cleanup_data",
    "export_library",
    "setup_auth",
    "re_auth",
    "configure_webhook",
    "remove_webhook",
    "test_webhook",
    "delete_document",
    "upload_document",
    "download_audio",
  ];

  it.each(MUTATING_TOOLS)("'%s' is in TOOLS_REQUIRING_AUTH", (tool) => {
    expect(requiringAuth.has(tool)).toBe(true);
  });

  it.each(MUTATING_TOOLS)("'%s' is NOT in TOOLS_EXEMPT_FROM_AUTH", (tool) => {
    expect(exemptFromAuth.has(tool)).toBe(false);
  });

  it("the two sets are disjoint", () => {
    const overlap = [...requiringAuth].filter((t) => exemptFromAuth.has(t));
    expect(overlap).toEqual([]);
  });

  it("read-scope set still includes the obvious read-only tools", () => {
    const expectedReadOnly = [
      "ask_question",
      "list_notebooks",
      "get_notebook",
      "search_notebooks",
      "get_library_stats",
      "get_quota",
      "get_project_info",
      "list_sessions",
      "get_health",
      "list_sources",
      "get_audio_status",
      "get_video_status",
      "get_data_table",
      "list_webhooks",
      "deep_research",
      "gemini_query",
      "get_research_status",
      "query_document",
      "list_documents",
      "query_chunked_document",
      "get_query_history",
      "get_notebook_chat_history",
    ];
    for (const tool of expectedReadOnly) {
      expect(exemptFromAuth.has(tool)).toBe(true);
    }
  });
});
