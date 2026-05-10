/**
 * Regression tests for two webhook-dispatcher security fixes:
 *
 * 1. updateWebhook() must NOT persist the secret to disk. addWebhook
 *    has always stored the secret in an in-memory SecureCredential
 *    and writes `secret: undefined` to webhooks.json. Pre-fix,
 *    updateWebhook() wrote `input.secret` straight into the persisted
 *    record, creating an inconsistency that contradicted the explicit
 *    "secret never persisted to disk" comment on addWebhook.
 *
 * 2. sendWithRetry() must re-validate the URL at delivery time, not
 *    only at config time. A domain that resolved to a public IP when
 *    the webhook was added can later resolve to 169.254.169.254
 *    (cloud metadata) or RFC 1918 space — classic DNS-rebinding.
 *
 * Cross-references:
 *   - CLAUDE_REVIEW.md O-2: updateWebhook persists secret
 *   - CODEX_REVIEW.md "Webhook SSRF Protection Is Only Time-of-Configuration"
 */

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import fs from "node:fs";
import path from "node:path";

const { TMP_ROOT } = vi.hoisted(() => {
  const _fs = require("node:fs") as typeof import("node:fs");
  const _os = require("node:os") as typeof import("node:os");
  const _path = require("node:path") as typeof import("node:path");
  return {
    TMP_ROOT: _fs.mkdtempSync(_path.join(_os.tmpdir(), "nlmcp-webhook-sec-test-")),
  };
});

vi.mock("../src/config.js", async () => {
  const actual = await vi.importActual<typeof import("../src/config.js")>("../src/config.js");
  return {
    ...actual,
    CONFIG: { ...actual.CONFIG, dataDir: TMP_ROOT, configDir: TMP_ROOT },
  };
});

vi.mock("../src/utils/audit-logger.js", () => ({
  audit: {
    auth: vi.fn().mockResolvedValue(undefined),
    security: vi.fn().mockResolvedValue(undefined),
    session: vi.fn().mockResolvedValue(undefined),
    system: vi.fn().mockResolvedValue(undefined),
    tool: vi.fn().mockResolvedValue(undefined),
    compliance: vi.fn().mockResolvedValue(undefined),
    dataAccess: vi.fn().mockResolvedValue(undefined),
    configChange: vi.fn().mockResolvedValue(undefined),
    retention: vi.fn().mockResolvedValue(undefined),
  },
  getAuditLogger: vi.fn(() => ({
    onEvent: vi.fn(() => () => undefined),
    getStats: vi.fn(() => ({ totalEvents: 0 })),
  })),
}));

vi.mock("../src/compliance/change-log.js", () => ({
  getChangeLog: vi.fn(() => ({
    recordChange: vi.fn().mockResolvedValue(undefined),
  })),
}));

import { WebhookDispatcher } from "../src/webhooks/webhook-dispatcher.js";

beforeEach(() => {
  // Disable DNS resolution for the lexical-only checks; individual
  // tests re-enable it explicitly when needed.
  process.env.NLMCP_WEBHOOK_RESOLVE_DNS = "false";
  delete process.env.NLMCP_WEBHOOK_URL;
  delete process.env.NLMCP_SLACK_WEBHOOK_URL;
  delete process.env.NLMCP_DISCORD_WEBHOOK_URL;
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
  fs.mkdirSync(TMP_ROOT, { recursive: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("updateWebhook secret persistence (CLAUDE_REVIEW.md O-2)", () => {
  it("writes undefined to disk even when caller supplies a new secret", async () => {
    const dispatcher = new WebhookDispatcher();

    const w = await dispatcher.addWebhook({
      name: "test",
      url: "https://example.com/hook",
      events: ["*"],
      secret: "initial-secret-aaaa",
    });

    // Initial add already writes undefined — sanity check.
    let onDisk = JSON.parse(
      fs.readFileSync(path.join(TMP_ROOT, "webhooks.json"), "utf8"),
    );
    expect(onDisk.webhooks[0].secret).toBeUndefined();

    // Update with a new secret. Pre-fix, this would write the new
    // plaintext secret straight into webhooks.json.
    await dispatcher.updateWebhook({
      id: w.id,
      secret: "rotated-secret-bbbb",
    });

    onDisk = JSON.parse(
      fs.readFileSync(path.join(TMP_ROOT, "webhooks.json"), "utf8"),
    );
    expect(onDisk.webhooks[0].secret).toBeUndefined();
  });

  it("writes undefined when caller clears the secret", async () => {
    const dispatcher = new WebhookDispatcher();
    const w = await dispatcher.addWebhook({
      name: "test",
      url: "https://example.com/hook",
      events: ["*"],
      secret: "original",
    });

    await dispatcher.updateWebhook({ id: w.id, secret: "" });

    const onDisk = JSON.parse(
      fs.readFileSync(path.join(TMP_ROOT, "webhooks.json"), "utf8"),
    );
    expect(onDisk.webhooks[0].secret).toBeUndefined();
  });

  it("leaves the persisted record alone when secret is not in the update", async () => {
    const dispatcher = new WebhookDispatcher();
    const w = await dispatcher.addWebhook({
      name: "test",
      url: "https://example.com/hook",
      events: ["*"],
      secret: "still-here",
    });

    await dispatcher.updateWebhook({ id: w.id, name: "renamed" });

    const onDisk = JSON.parse(
      fs.readFileSync(path.join(TMP_ROOT, "webhooks.json"), "utf8"),
    );
    expect(onDisk.webhooks[0].name).toBe("renamed");
    expect(onDisk.webhooks[0].secret).toBeUndefined();
  });
});

describe("send-time URL revalidation (DNS rebinding defense)", () => {
  it("refuses delivery when the configured URL is no longer valid", async () => {
    // To exercise this, we add a webhook with DNS resolution off, then
    // turn DNS resolution on and use a hostname that resolves to a
    // private IP. Pre-fix, validation would not run again at send time
    // and the request would proceed.
    const dispatcher = new WebhookDispatcher();
    const w = await dispatcher.addWebhook({
      name: "test",
      url: "https://example.com/hook",
      events: ["*"],
    });

    // Mutate the persisted URL directly to simulate a DNS-rebinding
    // window where the host validates lexically but resolves to a
    // private range. We use a hostname known to resolve to an RFC 1918
    // address: `localhost.localdomain` passes the lexical "is this an
    // IP?" check (it isn't) and is recognised as a private host by
    // isPrivateHost().
    const internal = (dispatcher as unknown as {
      store: { webhooks: Array<{ id: string; url: string; enabled: boolean }> };
    }).store;
    const found = internal.webhooks.find((x) => x.id === w.id)!;
    found.url = "https://localhost.localdomain/hook";

    const fetchSpy = vi.fn();
    (globalThis as { fetch?: unknown }).fetch = fetchSpy;

    const result = await dispatcher.testWebhook(w.id);

    expect(result.success).toBe(false);
    // The HTTP fetch must NOT have been attempted, because the
    // send-time validator rejected the URL first.
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("does not pre-emptively reject a still-valid URL", async () => {
    // Sanity: a still-valid URL passes the send-time check and at
    // least reaches the fetch layer (which we stub out).
    const dispatcher = new WebhookDispatcher();
    const w = await dispatcher.addWebhook({
      name: "test",
      url: "https://example.com/hook",
      events: ["*"],
    });

    const fetchSpy = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      text: () => Promise.resolve("ok"),
    });
    (globalThis as { fetch?: unknown }).fetch = fetchSpy;

    const result = await dispatcher.testWebhook(w.id);

    expect(result.success).toBe(true);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });
});
