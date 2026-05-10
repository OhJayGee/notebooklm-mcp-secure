/**
 * Notebook Management Handlers
 *
 * Standalone handler functions for notebook CRUD and library operations.
 */

import type { HandlerContext } from "./types.js";
import type {
  AddNotebookInput,
  LibraryStats,
  NotebookEntry,
  UpdateNotebookInput,
} from "../../library/types.js";
import type { ToolResult } from "../../types.js";
import { log } from "../../utils/logger.js";
import { audit } from "../../utils/audit-logger.js";
import { getSanitizedErrorMessage, getErrorAuditArgs } from "./error-utils.js";

/**
 * Extract just the host from a notebook URL for audit records.
 * Same rationale as webhook-dispatcher.ts:safeHost — never log the
 * full URL (path components on Slack/Discord-style URLs leak secret
 * tokens, and even on safe URLs the host alone is enough to identify
 * the target without disclosing query strings or paths the audit
 * reader doesn't need).
 */
function safeNotebookHost(rawUrl: string | undefined): string {
  if (!rawUrl) return "[no-url]";
  try {
    return new URL(rawUrl).host;
  } catch {
    return "[invalid-url]";
  }
}

async function withNotebookHandler<T>(
  toolName: string,
  fn: () => Promise<ToolResult<T>> | ToolResult<T>
): Promise<ToolResult<T>> {
  try {
    return await fn();
  } catch (error) {
    const errorMessage = getSanitizedErrorMessage(error);
    log.error(`❌ [TOOL] ${toolName} failed: ${errorMessage}`);
    return {
      success: false,
      data: null,
      error: errorMessage,
    };
  }
}

/**
 * Handle add_notebook tool
 *
 * Library mutations are audit-logged because the library is a
 * privilege boundary: URLs persisted here are later trusted by the
 * session manager for browser navigation. The audit trail makes
 * library writes visible in the same hash-chained log that records
 * every other admin-scope tool invocation. Only the host is recorded
 * — never the full URL — to match the webhook-dispatcher.recordWebhookChange
 * pattern.
 */
export async function handleAddNotebook(
  ctx: HandlerContext,
  args: AddNotebookInput
): Promise<ToolResult<{ notebook: NotebookEntry }>> {
  const startTime = Date.now();
  log.info(`🔧 [TOOL] add_notebook called`);
  log.info(`  Name: ${args.name}`);

  return withNotebookHandler("add_notebook", async () => {
    try {
      const notebook = ctx.library.addNotebook(args);
      await audit.tool("add_notebook", {
        name: args.name,
        url_host: safeNotebookHost(notebook.url),
        topics_count: notebook.topics?.length ?? 0,
        notebook_id: notebook.id,
      }, true, Date.now() - startTime);
      log.success(`✅ [TOOL] add_notebook completed: ${notebook.id}`);
      return { success: true, data: { notebook } };
    } catch (err) {
      const msg = getSanitizedErrorMessage(err);
      await audit.tool("add_notebook", getErrorAuditArgs("add_notebook", msg), false, Date.now() - startTime, msg);
      throw err;
    }
  });
}

/**
 * Handle list_notebooks tool
 */
export async function handleListNotebooks(
  ctx: HandlerContext
): Promise<ToolResult<{ notebooks: NotebookEntry[] }>> {
  log.info(`🔧 [TOOL] list_notebooks called`);

  return withNotebookHandler("list_notebooks", () => {
    const notebooks = ctx.library.listNotebooks();
    log.success(`✅ [TOOL] list_notebooks completed (${notebooks.length} notebooks)`);
    return {
      success: true,
      data: { notebooks },
    };
  });
}

/**
 * Handle get_notebook tool
 */
export async function handleGetNotebook(
  ctx: HandlerContext,
  args: { id: string }
): Promise<ToolResult<{ notebook: NotebookEntry }>> {
  log.info(`🔧 [TOOL] get_notebook called`);
  log.info(`  ID: ${args.id}`);

  return withNotebookHandler("get_notebook", () => {
    const notebook = ctx.library.getNotebook(args.id);
    if (!notebook) {
      log.warning(`⚠️  [TOOL] Notebook not found: ${args.id}`);
      return {
        success: false,
        data: null,
        error: `Notebook not found: ${args.id}`,
      };
    }

    log.success(`✅ [TOOL] get_notebook completed: ${notebook.name}`);
    return {
      success: true,
      data: { notebook },
    };
  });
}

/**
 * Handle select_notebook tool
 */
export async function handleSelectNotebook(
  ctx: HandlerContext,
  args: { id: string }
): Promise<ToolResult<{ notebook: NotebookEntry }>> {
  const startTime = Date.now();
  log.info(`🔧 [TOOL] select_notebook called`);
  log.info(`  ID: ${args.id}`);

  return withNotebookHandler("select_notebook", async () => {
    try {
      const notebook = ctx.library.selectNotebook(args.id);
      await audit.tool("select_notebook", {
        notebook_id: notebook.id,
        url_host: safeNotebookHost(notebook.url),
      }, true, Date.now() - startTime);
      log.success(`✅ [TOOL] select_notebook completed: ${notebook.name}`);
      return { success: true, data: { notebook } };
    } catch (err) {
      const msg = getSanitizedErrorMessage(err);
      await audit.tool("select_notebook", getErrorAuditArgs("select_notebook", msg), false, Date.now() - startTime, msg);
      throw err;
    }
  });
}

/**
 * Handle update_notebook tool
 */
export async function handleUpdateNotebook(
  ctx: HandlerContext,
  args: UpdateNotebookInput
): Promise<ToolResult<{ notebook: NotebookEntry }>> {
  const startTime = Date.now();
  log.info(`🔧 [TOOL] update_notebook called`);
  log.info(`  ID: ${args.id}`);

  return withNotebookHandler("update_notebook", async () => {
    try {
      // Capture pre-mutation state so the audit record can document
      // what changed. Only the host is recorded for URL changes —
      // never the full URL — to match the recordWebhookChange pattern.
      const before = ctx.library.getNotebook(args.id);
      const oldHost = safeNotebookHost(before?.url);
      const notebook = ctx.library.updateNotebook(args);
      const newHost = safeNotebookHost(notebook.url);
      await audit.tool("update_notebook", {
        notebook_id: notebook.id,
        url_host_before: oldHost,
        url_host_after: newHost,
        url_changed: oldHost !== newHost,
        fields_changed: Object.keys(args).filter((k) => k !== "id"),
      }, true, Date.now() - startTime);
      log.success(`✅ [TOOL] update_notebook completed: ${notebook.name}`);
      return { success: true, data: { notebook } };
    } catch (err) {
      const msg = getSanitizedErrorMessage(err);
      await audit.tool("update_notebook", getErrorAuditArgs("update_notebook", msg), false, Date.now() - startTime, msg);
      throw err;
    }
  });
}

/**
 * Handle remove_notebook tool
 */
export async function handleRemoveNotebook(
  ctx: HandlerContext,
  args: { id: string }
): Promise<ToolResult<{ removed: boolean; closed_sessions: number }>> {
  const startTime = Date.now();
  log.info(`🔧 [TOOL] remove_notebook called`);
  log.info(`  ID: ${args.id}`);

  return withNotebookHandler("remove_notebook", async () => {
    const notebook = ctx.library.getNotebook(args.id);
    if (!notebook) {
      log.warning(`⚠️  [TOOL] Notebook not found: ${args.id}`);
      // Still audit the failed lookup so probes for non-existent IDs
      // are visible in the trail.
      await audit.tool("remove_notebook", {
        notebook_id: args.id,
        result: "not_found",
      }, false, Date.now() - startTime, "Notebook not found");
      return {
        success: false,
        data: null,
        error: `Notebook not found: ${args.id}`,
      };
    }

    try {
      const removed = ctx.library.removeNotebook(args.id);
      if (removed) {
        const closedSessions = await ctx.sessionManager.closeSessionsForNotebook(
          notebook.url
        );
        await audit.tool("remove_notebook", {
          notebook_id: args.id,
          url_host: safeNotebookHost(notebook.url),
          closed_sessions: closedSessions,
        }, true, Date.now() - startTime);
        log.success(`✅ [TOOL] remove_notebook completed`);
        return {
          success: true,
          data: { removed: true, closed_sessions: closedSessions },
        };
      } else {
        log.warning(`⚠️  [TOOL] Notebook not found: ${args.id}`);
        return {
          success: false,
          data: null,
          error: `Notebook not found: ${args.id}`,
        };
      }
    } catch (err) {
      const msg = getSanitizedErrorMessage(err);
      await audit.tool("remove_notebook", getErrorAuditArgs("remove_notebook", msg), false, Date.now() - startTime, msg);
      throw err;
    }
  });
}

/**
 * Handle search_notebooks tool
 */
export async function handleSearchNotebooks(
  ctx: HandlerContext,
  args: { query: string }
): Promise<ToolResult<{ notebooks: NotebookEntry[] }>> {
  log.info(`🔧 [TOOL] search_notebooks called`);
  log.info(`  Query: "${args.query}"`);

  return withNotebookHandler("search_notebooks", () => {
    const notebooks = ctx.library.searchNotebooks(args.query);
    log.success(`✅ [TOOL] search_notebooks completed (${notebooks.length} results)`);
    return {
      success: true,
      data: { notebooks },
    };
  });
}

/**
 * Handle get_library_stats tool
 */
export async function handleGetLibraryStats(
  ctx: HandlerContext
): Promise<ToolResult<LibraryStats>> {
  log.info(`🔧 [TOOL] get_library_stats called`);

  return withNotebookHandler("get_library_stats", () => {
    const stats = ctx.library.getStats();
    log.success(`✅ [TOOL] get_library_stats completed`);
    return {
      success: true,
      data: stats,
    };
  });
}
