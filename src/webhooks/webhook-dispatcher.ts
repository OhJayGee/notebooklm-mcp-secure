/**
 * Webhook Dispatcher
 *
 * Delivers events to configured webhook endpoints with retry logic.
 */

import crypto from "crypto";
import fs from "fs";
import path from "path";
import net from "node:net";
import dns from "node:dns/promises";
import { log } from "../utils/logger.js";
import { writeFileSecure, PERMISSION_MODES } from "../utils/file-permissions.js";
import { CONFIG } from "../config.js";
import { eventEmitter } from "../events/event-emitter.js";
import type { SystemEvent, EventType } from "../events/event-types.js";
import { scanAndRedactSecrets } from "../utils/secrets-scanner.js";
import { SecureCredential } from "../utils/secure-memory.js";
import { getMetricsRegistry } from "../observability/metrics.js";
import type {
  WebhookConfig,
  WebhookConfigPublic,
  WebhookDelivery,
  WebhookStats,
  AddWebhookInput,
  UpdateWebhookInput,
} from "./types.js";

// Headers that must never be forwarded from user-configured webhook.headers
// — they are either hop-by-hop (Host), auth-overriding (Authorization),
// or would confuse the transport (Content-Length, Transfer-Encoding).
const BLOCKED_OUTBOUND_HEADERS = new Set([
  "host",
  "authorization",
  "content-length",
  "transfer-encoding",
  "connection",
]);

interface WebhooksStore {
  webhooks: WebhookConfig[];
  deliveries: WebhookDelivery[];
  version: string;
}

interface CircuitBreakerState {
  consecutiveFailures: number;
  openUntil?: number;
  halfOpenProbeInFlight: boolean;
}

type WebhookUrlValidation =
  | { ok: true; url: URL }
  | { ok: false; error: string };

/**
 * Classify an IPv4 address as private/loopback/link-local/metadata.
 * See RFC 1918, RFC 3927, RFC 6598, RFC 5735.
 */
function isPrivateIPv4(addr: string): boolean {
  const parts = addr.split(".").map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return false;
  const [a, b] = parts;
  if (a === 0) return true;                                  // 0.0.0.0/8
  if (a === 10) return true;                                 // 10.0.0.0/8
  if (a === 100 && b >= 64 && b <= 127) return true;         // 100.64.0.0/10 CGNAT
  if (a === 127) return true;                                // 127.0.0.0/8 loopback
  if (a === 169 && b === 254) return true;                   // 169.254.0.0/16 link-local + AWS/GCP metadata
  if (a === 172 && b >= 16 && b <= 31) return true;          // 172.16.0.0/12
  if (a === 192 && b === 168) return true;                   // 192.168.0.0/16
  if (a >= 224) return true;                                 // multicast + reserved
  return false;
}

function isPrivateIPv6(addr: string): boolean {
  const lower = addr.toLowerCase();
  if (lower === "::1" || lower === "::") return true;         // loopback, unspecified
  if (lower.startsWith("fe80:") || lower.startsWith("fe80::")) return true; // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;        // unique local fc00::/7
  if (lower.startsWith("ff")) return true;                    // multicast

  // IPv4-mapped IPv6. Node's URL parser normalizes dotted-quad form to
  // compressed hex (::ffff:169.254.169.254 -> ::ffff:a9fe:a9fe), so we
  // accept both and recover the IPv4 for range-checking.
  if (lower.startsWith("::ffff:")) {
    const rest = lower.slice(7);
    if (net.isIPv4(rest)) return isPrivateIPv4(rest);
    const parts = rest.split(":");
    if (parts.length === 2 && /^[0-9a-f]{1,4}$/.test(parts[0]) && /^[0-9a-f]{1,4}$/.test(parts[1])) {
      const hi = parseInt(parts[0], 16);
      const lo = parseInt(parts[1], 16);
      const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
      return isPrivateIPv4(ipv4);
    }
  }
  return false;
}

function isPrivateHost(hostname: string): boolean {
  let h = hostname.toLowerCase();
  // WHATWG URL returns IPv6 hostnames wrapped in brackets (e.g. "[::1]").
  // Strip them so net.isIPv6 / IPv6 range checks work.
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);

  if (h === "localhost" || h === "localhost.localdomain") return true;
  if (h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal")) return true;
  if (net.isIPv4(h) && isPrivateIPv4(h)) return true;
  if (net.isIPv6(h) && isPrivateIPv6(h)) return true;
  return false;
}

/**
 * Validate a webhook URL before we ever send it an outbound request.
 *
 * Checks (in order):
 *   1. Parseable URL
 *   2. Scheme: require https:; allow http: only when NLMCP_WEBHOOK_ALLOW_HTTP=true
 *   3. Lexical hostname in private/loopback/link-local/metadata space
 *   4. DNS resolution — all resolved addresses must be public (closes
 *      DNS-rebinding attacks); skipped when NLMCP_WEBHOOK_RESOLVE_DNS=false
 *
 * Exported for use by tool handlers that want to pre-validate before
 * calling dispatcher.addWebhook().
 */
export async function validateWebhookUrl(rawUrl: string): Promise<WebhookUrlValidation> {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch (err) {
    log.debug(`webhook-dispatcher: parsing webhook URL in validateWebhookUrl: ${err instanceof Error ? err.message : String(err)}`);
    return { ok: false, error: "invalid URL" };
  }

  const allowHttp = process.env.NLMCP_WEBHOOK_ALLOW_HTTP === "true";
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && allowHttp)) {
    return {
      ok: false,
      error: `scheme '${parsed.protocol}' not allowed (need https:; set NLMCP_WEBHOOK_ALLOW_HTTP=true to permit http:)`,
    };
  }

  const host = parsed.hostname;
  if (!host) return { ok: false, error: "URL missing hostname" };
  if (isPrivateHost(host)) {
    return {
      ok: false,
      error: `hostname '${host}' is in a private/loopback/link-local range (SSRF block)`,
    };
  }

  if (process.env.NLMCP_WEBHOOK_RESOLVE_DNS !== "false" && !net.isIP(host)) {
    try {
      const addresses = await Promise.race([
        dns.lookup(host, { all: true }),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error("DNS lookup timed out after 2s")), 2000),
        ),
      ]);
      for (const { address, family } of addresses) {
        if (family === 4 && isPrivateIPv4(address)) {
          return {
            ok: false,
            error: `hostname '${host}' resolves to private IPv4 ${address} (SSRF block)`,
          };
        }
        if (family === 6 && isPrivateIPv6(address)) {
          return {
            ok: false,
            error: `hostname '${host}' resolves to private IPv6 ${address} (SSRF block)`,
          };
        }
      }
    } catch (err) {
      return {
        ok: false,
        error: `DNS resolution failed for '${host}': ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }

  return { ok: true, url: parsed };
}

const WEBHOOK_SECRET_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

export class WebhookDispatcher {
  private storePath: string;
  private deliveryLogPath: string;
  private store: WebhooksStore;
  private unsubscribe: (() => void) | null = null;
  private deliveryHistory: WebhookDelivery[] = [];
  private maxDeliveryHistory = 100;
  private readonly circuitBreakerThreshold = 5;
  private readonly circuitBreakerResetMs = 60_000;
  private circuitBreakers = new Map<string, CircuitBreakerState>();
  private deliverySequence = 0;
  // In-memory SecureCredential store for webhook secrets (I321)
  private webhookSecrets = new Map<string, SecureCredential>();
  // Serialises saveStore() writes so concurrent addWebhook/removeWebhook don't interleave (I277)
  private saveQueue: Promise<void> = Promise.resolve();
  /**
   * Resolves once env-driven webhook initialisation has completed (DNS
   * lookups for NLMCP_WEBHOOK_URL etc. are async). Held so dispatch /
   * listWebhooks / addWebhook can `await` it and avoid a race where an
   * event fires before the env-configured webhooks are actually in the
   * in-memory store.
   */
  private initFromEnvPromise: Promise<void>;

  constructor() {
    this.storePath = path.join(CONFIG.dataDir, "webhooks.json");
    this.deliveryLogPath = path.join(CONFIG.dataDir, "webhook-deliveries.jsonl");
    this.store = this.loadStore();
    this.loadDeliveryHistory();
    this.subscribeToEvents();

    // Env-driven webhook init is async (URL validation calls dns.lookup).
    // Hold the promise so callers can `await` it before observing
    // listWebhooks() / dispatching events — pre-fix this was a fire-
    // and-forget that could race with the very first event.
    this.initFromEnvPromise = this.initializeFromEnv().catch((err) => {
      log.warning(`WebhookDispatcher env init failed: ${err instanceof Error ? err.message : String(err)}`);
    });

    log.info("🔔 WebhookDispatcher initialized");
    log.info(`  Webhooks: ${this.store.webhooks.filter((w) => w.enabled).length} active`);
  }

  /**
   * Public hook so external callers can wait for env-driven init to
   * settle before observing the in-memory store. Mostly useful in
   * tests and during server bootstrap; production dispatch / listing
   * paths await this internally.
   */
  async whenInitialized(): Promise<void> {
    await this.initFromEnvPromise;
  }

  /**
   * Load webhooks from disk.
   *
   * Legacy `secret` field migration: pre-fix releases of this file
   * sometimes wrote the webhook secret directly into webhooks.json
   * (the inconsistency between addWebhook and updateWebhook in
   * v2026.3.3). On load we move any persisted `secret` value into
   * the in-memory `webhookSecrets` SecureCredential map and scrub
   * the field from the persisted record. The cleaned store is
   * re-persisted so subsequent loads see no plaintext secrets.
   *
   * The migration is idempotent: an already-clean record (secret ===
   * undefined) flows through untouched.
   */
  private loadStore(): WebhooksStore {
    try {
      if (fs.existsSync(this.storePath)) {
        const data = fs.readFileSync(this.storePath, "utf-8");
        const parsed: WebhooksStore = JSON.parse(data);

        let migrationOccurred = false;
        for (const w of parsed.webhooks ?? []) {
          // Cast to escape the TS-typed-as-undefined assumption — we are
          // explicitly checking the runtime value migrated from older
          // releases.
          const legacySecret = (w as { secret?: string }).secret;
          if (typeof legacySecret === "string" && legacySecret.length > 0) {
            this.webhookSecrets.set(
              w.id,
              new SecureCredential(legacySecret, WEBHOOK_SECRET_TTL_MS),
            );
            (w as { secret?: string }).secret = undefined;
            migrationOccurred = true;
          }
        }

        if (migrationOccurred) {
          log.warning(
            "🔐 Migrated legacy webhook.secret values from disk into in-memory SecureCredential map; scrubbed file.",
          );
          // Best-effort: re-persist the cleaned store. If this fails,
          // the in-memory state is still correct; next save will
          // converge.
          try {
            const cleaned = JSON.stringify(parsed, null, 2);
            writeFileSecure(this.storePath, cleaned, PERMISSION_MODES.OWNER_READ_WRITE);
          } catch (err) {
            log.warning(`webhook secret migration: failed to re-persist scrubbed store: ${err instanceof Error ? err.message : String(err)}`);
          }
        }

        return parsed;
      }
    } catch (error) {
      log.warning(`Failed to load webhooks: ${error}`);
    }

    return {
      webhooks: [],
      deliveries: [],
      version: "1.0.0",
    };
  }

  /**
   * Save webhooks to disk
   */
  private saveStore(): void {
    // Chain onto the existing save to serialise concurrent mutation (I277)
    this.saveQueue = this.saveQueue.then(() => {
      try {
        const data = JSON.stringify(this.store, null, 2);
        writeFileSecure(this.storePath, data, PERMISSION_MODES.OWNER_READ_WRITE);
      } catch (error) {
        log.error(`Failed to save webhooks: ${error}`);
      }
    });
  }

  /**
   * Initialize webhooks from environment variables. Each URL is validated
   * via validateWebhookUrl before being stored — invalid env values log a
   * warning and are skipped (server must still start).
   */
  private async initializeFromEnv(): Promise<void> {
    const tryAdd = async (envVar: string, input: AddWebhookInput): Promise<void> => {
      if (this.store.webhooks.some((w) => w.url === input.url)) return;
      try {
        await this.addWebhook(input);
        log.info(`  Added webhook from env (${envVar}): host=${new URL(input.url).host}`);
      } catch (err) {
        log.warning(
          `  ⚠️ Skipping ${envVar} — ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    };

    const webhookUrl = process.env.NLMCP_WEBHOOK_URL;
    if (webhookUrl) {
      const events = process.env.NLMCP_WEBHOOK_EVENTS
        ? (process.env.NLMCP_WEBHOOK_EVENTS.split(",") as EventType[])
        : (["*"] as ["*"]);
      await tryAdd("NLMCP_WEBHOOK_URL", {
        name: "Default Webhook",
        url: webhookUrl,
        events,
        secret: process.env.NLMCP_WEBHOOK_SECRET,
      });
    }

    const slackUrl = process.env.NLMCP_SLACK_WEBHOOK_URL;
    if (slackUrl) {
      await tryAdd("NLMCP_SLACK_WEBHOOK_URL", {
        name: "Slack Notifications",
        url: slackUrl,
        events: ["*"],
        format: "slack",
      });
    }

    const discordUrl = process.env.NLMCP_DISCORD_WEBHOOK_URL;
    if (discordUrl) {
      await tryAdd("NLMCP_DISCORD_WEBHOOK_URL", {
        name: "Discord Notifications",
        url: discordUrl,
        events: ["*"],
        format: "discord",
      });
    }
  }

  /**
   * Subscribe to all events
   */
  private subscribeToEvents(): void {
    this.unsubscribe = eventEmitter.on("*", async (event) => {
      await this.dispatch(event);
    });
  }

  /**
   * Dispatch an event to all matching webhooks in parallel.
   *
   * Using Promise.allSettled so one slow/failing webhook does not block
   * or cancel delivery to others (I275).
   *
   * Awaits env-driven init first so an event fired during the very
   * first tick of the server (before NLMCP_WEBHOOK_URL has finished
   * its DNS resolution) does not silently miss its env-configured
   * delivery target.
   */
  async dispatch(event: SystemEvent): Promise<void> {
    await this.initFromEnvPromise;
    const targets = this.store.webhooks.filter(
      (w) => w.enabled && this.shouldSend(w, event.type),
    );
    if (targets.length === 0) return;

    await Promise.allSettled(targets.map((w) => this.sendWithRetry(w, event)));
  }

  /**
   * Check if webhook should receive this event type
   */
  private shouldSend(webhook: WebhookConfig, eventType: EventType): boolean {
    if (webhook.events.includes("*")) return true;
    return webhook.events.includes(eventType);
  }

  private getCircuitBreakerState(webhookId: string): CircuitBreakerState {
    const existing = this.circuitBreakers.get(webhookId);
    if (existing) return existing;

    const state: CircuitBreakerState = {
      consecutiveFailures: 0,
      halfOpenProbeInFlight: false,
    };
    this.circuitBreakers.set(webhookId, state);
    return state;
  }

  private shouldSkipForOpenCircuit(webhook: WebhookConfig): boolean {
    const state = this.getCircuitBreakerState(webhook.id);
    if (!state.openUntil) return false;

    const now = Date.now();
    if (state.openUntil > now) {
      log.warning(
        `webhook_dispatcher circuit_open ${JSON.stringify({
          webhookId: webhook.id,
          webhookName: webhook.name,
          urlHost: this.safeHost(webhook.url),
          openUntil: new Date(state.openUntil).toISOString(),
        })}`
      );
      return true;
    }

    if (state.halfOpenProbeInFlight) {
      log.warning(
        `webhook_dispatcher circuit_half_open_busy ${JSON.stringify({
          webhookId: webhook.id,
          webhookName: webhook.name,
          urlHost: this.safeHost(webhook.url),
        })}`
      );
      return true;
    }

    state.halfOpenProbeInFlight = true;
    log.warning(
      `webhook_dispatcher circuit_half_open_probe ${JSON.stringify({
        webhookId: webhook.id,
        webhookName: webhook.name,
        urlHost: this.safeHost(webhook.url),
      })}`
    );
    return false;
  }

  private onDeliverySuccess(webhook: WebhookConfig): void {
    const state = this.getCircuitBreakerState(webhook.id);
    state.consecutiveFailures = 0;
    state.openUntil = undefined;
    state.halfOpenProbeInFlight = false;
  }

  private onDeliveryFailure(webhook: WebhookConfig): void {
    const state = this.getCircuitBreakerState(webhook.id);
    state.consecutiveFailures += 1;
    state.halfOpenProbeInFlight = false;

    if (state.consecutiveFailures >= this.circuitBreakerThreshold) {
      state.openUntil = Date.now() + this.circuitBreakerResetMs;
      log.warning(
        `webhook_dispatcher circuit_opened ${JSON.stringify({
          webhookId: webhook.id,
          webhookName: webhook.name,
          urlHost: this.safeHost(webhook.url),
          consecutiveFailures: state.consecutiveFailures,
          openUntil: new Date(state.openUntil).toISOString(),
        })}`
      );
    }
  }

  private logAttempt(
    webhook: WebhookConfig,
    event: SystemEvent,
    attempt: number,
    maxAttempts: number,
    delivery: WebhookDelivery
  ): void {
    log.warning(
      `webhook_dispatcher delivery_attempt ${JSON.stringify({
        webhookId: webhook.id,
        webhookName: webhook.name,
        eventType: event.type,
        attempt,
        maxAttempts,
        success: delivery.success,
        statusCode: delivery.statusCode,
        error: delivery.error,
        errorKind: delivery.errorKind,
        durationMs: delivery.durationMs,
      })}`
    );
  }

  /**
   * Send event with retry logic.
   *
   * Retries capped at 3 attempts with max 30 s total window (I276).
   * Payload is secrets-scanned before dispatch (I273).
   * Outbound headers filtered to remove dangerous overrides (I282).
   * HMAC signature includes unix timestamp to prevent replay (I271).
   */
  private async sendWithRetry(
    webhook: WebhookConfig,
    event: SystemEvent
  ): Promise<boolean> {
    if (this.shouldSkipForOpenCircuit(webhook)) {
      return false;
    }

    // Re-validate the URL at delivery time, not just at configuration
    // time. A domain that resolved to a public IP when the webhook was
    // added can later resolve to 169.254.169.254, loopback, or RFC 1918
    // space — classic DNS-rebinding. `validateWebhookUrl` re-runs the
    // DNS lookup and re-checks every resolved address against the
    // private-range list. The result is then thrown away (we still let
    // `fetch` perform its own DNS resolution); this is a TOCTOU window
    // we accept in exchange for not pinning IPs at the application
    // layer. Mitigations: short request timeout, redirect:"error", and
    // a refusal to send any future delivery if validation now fails.
    const sendTimeValidation = await validateWebhookUrl(webhook.url);
    if (!sendTimeValidation.ok) {
      log.warning(
        `webhook_dispatcher send_time_validation_failed ${JSON.stringify({
          webhookId: webhook.id,
          webhookName: webhook.name,
          urlHost: this.safeHost(webhook.url),
          error: sendTimeValidation.error,
        })}`,
      );
      this.onDeliveryFailure(webhook);
      return false;
    }

    // Cap retries: max 3 attempts, max 10 s per-request timeout (I276)
    const maxAttempts = Math.min(webhook.retryCount ?? 3, 3);
    const baseDelay = Math.min(webhook.retryDelayMs ?? 1000, 2000);
    const timeout = Math.min(webhook.timeoutMs ?? 5000, 10_000);

    const deliveryId = crypto.randomUUID();
    const startTime = Date.now();

    // Scan payload for secrets once before any attempt (I273)
    const rawPayload = this.formatPayload(event, webhook.format);
    let payload: string;
    try {
      const { clean } = await scanAndRedactSecrets(rawPayload);
      payload = clean;
    } catch (err) {
      log.debug(`webhook-dispatcher: scanning and redacting secrets from payload: ${err instanceof Error ? err.message : String(err)}`);
      payload = rawPayload;
    }

    // Filter user-configured headers to block dangerous overrides (I282)
    const safeCustomHeaders = Object.fromEntries(
      Object.entries(webhook.headers ?? {}).filter(
        ([k]) => !BLOCKED_OUTBOUND_HEADERS.has(k.toLowerCase()),
      ),
    );

    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        // Include unix timestamp in HMAC to prevent indefinite replay (I271)
        const timestamp = Math.floor(Date.now() / 1000);
        const secret = this.webhookSecrets.get(webhook.id)?.getValue() ?? webhook.secret;
        const signature = secret
          ? this.sign(payload, secret, timestamp)
          : undefined;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeout);

        let response: Response;
        try {
          response = await fetch(webhook.url, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "User-Agent": `notebooklm-mcp/${process.env.npm_package_version ?? "2026.2.11"}`,
              ...(signature && {
                "X-Webhook-Signature": signature,
                "X-Webhook-Timestamp": String(timestamp),
              }),
              ...safeCustomHeaders,
            },
            body: payload,
            signal: controller.signal,
            // Refuse redirects — a pre-validated host redirecting to cloud
            // metadata (169.254.169.254) would otherwise bypass validateWebhookUrl.
            redirect: "error",
          });
        } finally {
          clearTimeout(timeoutId);
        }

        const delivery: WebhookDelivery = {
          id: `${deliveryId}-${attempt}`,
          sequence: this.nextDeliverySequence(),
          webhookId: webhook.id,
          eventType: event.type,
          timestamp: new Date().toISOString(),
          success: response.ok,
          statusCode: response.status,
          attempts: attempt,
          durationMs: Date.now() - startTime,
        };

        this.recordDelivery(delivery);
        this.logAttempt(webhook, event, attempt, maxAttempts, delivery);

        if (response.ok) {
          this.onDeliverySuccess(webhook);
          log.dim(`  ✅ Webhook delivered: ${webhook.name} (${event.type})`);
          return true;
        }

        log.warning(
          `  ⚠️ Webhook failed (attempt ${attempt}/${maxAttempts}): ${webhook.name} - ${response.status}`
        );
      } catch (error) {
        const errorMessage = error instanceof Error ? error.message : String(error);

        // Walk the cause chain: Node's fetch wraps DNS/connect errors as
        // TypeError("fetch failed", { cause: Error("getaddrinfo ENOTFOUND ...") })
        const causeMessages: string[] = [];
        let cur: unknown = error;
        while (cur instanceof Error) {
          causeMessages.push(cur.message);
          cur = (cur as { cause?: unknown }).cause;
        }
        const combinedMessage = causeMessages.join(" ");

        const isAbort = error instanceof DOMException && error.name === "AbortError";
        const isDns = /ENOTFOUND|EAI_AGAIN|ECONNREFUSED/.test(combinedMessage);
        const errorKind: WebhookDelivery["errorKind"] = isAbort
          ? "timeout"
          : isDns
            ? "dns_or_connect"
            : "network";

        const delivery: WebhookDelivery = {
          id: `${deliveryId}-${attempt}`,
          sequence: this.nextDeliverySequence(),
          webhookId: webhook.id,
          eventType: event.type,
          timestamp: new Date().toISOString(),
          success: false,
          error: errorMessage,
          errorKind,
          attempts: attempt,
          durationMs: Date.now() - startTime,
        };
        this.recordDelivery(delivery);
        this.logAttempt(webhook, event, attempt, maxAttempts, delivery);

        if (isDns) {
          this.onDeliveryFailure(webhook);
          log.error(`  ❌ Webhook failed permanently: ${webhook.name} - ${errorKind}: ${errorMessage}`);
          return false;
        }

        if (attempt === maxAttempts) {
          this.onDeliveryFailure(webhook);
          log.error(`  ❌ Webhook failed permanently: ${webhook.name} - ${errorKind}: ${errorMessage}`);
          return false;
        }

        log.warning(
          `  ⚠️ Webhook error (attempt ${attempt}/${maxAttempts}): ${webhook.name} - ${errorKind}: ${errorMessage}`
        );
      }

      // Exponential backoff
      if (attempt < maxAttempts) {
        const delay = baseDelay * Math.pow(2, attempt - 1);
        await new Promise((r) => setTimeout(r, delay));
      }
    }

    this.onDeliveryFailure(webhook);
    return false;
  }

  /**
   * Format event payload for different platforms
   */
  private formatPayload(
    event: SystemEvent,
    format: WebhookConfig["format"]
  ): string {
    switch (format) {
      case "slack":
        return JSON.stringify(this.formatSlack(event));
      case "discord":
        return JSON.stringify(this.formatDiscord(event));
      case "teams":
        return JSON.stringify(this.formatTeams(event));
      default:
        return JSON.stringify(event);
    }
  }

  /**
   * Format for Slack
   */
  private formatSlack(event: SystemEvent): object {
    const emoji = this.getEmoji(event.type);
    return {
      text: `${emoji} NotebookLM: ${this.getTitle(event)}`,
      blocks: [
        {
          type: "section",
          text: {
            type: "mrkdwn",
            text: `*${emoji} ${this.getTitle(event)}*\n${this.getDescription(event)}`,
          },
        },
        {
          type: "context",
          elements: [
            {
              type: "mrkdwn",
              text: `Event: \`${event.type}\` | Time: ${event.timestamp}`,
            },
          ],
        },
      ],
    };
  }

  /**
   * Format for Discord
   */
  private formatDiscord(event: SystemEvent): object {
    const color = this.getColor(event.type);
    return {
      embeds: [
        {
          title: `${this.getEmoji(event.type)} ${this.getTitle(event)}`,
          description: this.getDescription(event),
          color,
          timestamp: event.timestamp,
          footer: {
            text: `NotebookLM MCP | ${event.type}`,
          },
        },
      ],
    };
  }

  /**
   * Format for Microsoft Teams
   */
  private formatTeams(event: SystemEvent): object {
    return {
      "@type": "MessageCard",
      "@context": "http://schema.org/extensions",
      themeColor: this.getColor(event.type).toString(16),
      summary: this.getTitle(event),
      sections: [
        {
          activityTitle: `${this.getEmoji(event.type)} ${this.getTitle(event)}`,
          activitySubtitle: event.timestamp,
          text: this.getDescription(event),
          facts: Object.entries(event.payload || {}).map(([key, value]) => ({
            name: key,
            value: String(value),
          })),
        },
      ],
    };
  }

  /**
   * Get emoji for event type
   */
  private getEmoji(type: EventType): string {
    const emojis: Record<EventType, string> = {
      question_answered: "💬",
      notebook_created: "📓",
      notebook_deleted: "🗑️",
      source_added: "➕",
      source_removed: "➖",
      session_created: "🌐",
      session_expired: "⏰",
      auth_required: "🔐",
      rate_limit_hit: "🚫",
      security_incident: "🛡️",
      quota_warning: "⚠️",
      audio_generated: "🎙️",
      batch_complete: "📦",
    };
    return emojis[type] || "📢";
  }

  /**
   * Get color for event type (Discord embed color)
   */
  private getColor(type: EventType): number {
    const colors: Record<EventType, number> = {
      question_answered: 0x00ff00, // Green
      notebook_created: 0x3498db, // Blue
      notebook_deleted: 0xff6b6b, // Red
      source_added: 0x00d4aa, // Teal
      source_removed: 0xffa500, // Orange
      session_created: 0x9b59b6, // Purple
      session_expired: 0x95a5a6, // Gray
      auth_required: 0xf39c12, // Yellow
      rate_limit_hit: 0xe74c3c, // Red
      security_incident: 0xe74c3c, // Red
      quota_warning: 0xf39c12, // Yellow
      audio_generated: 0x1abc9c, // Green
      batch_complete: 0x3498db, // Blue
    };
    return colors[type] || 0x7289da;
  }

  /**
   * Get title for event
   */
  private getTitle(event: SystemEvent): string {
    const titles: Record<EventType, string> = {
      question_answered: "Question Answered",
      notebook_created: "Notebook Created",
      notebook_deleted: "Notebook Deleted",
      source_added: "Source Added",
      source_removed: "Source Removed",
      session_created: "Session Started",
      session_expired: "Session Expired",
      auth_required: "Authentication Required",
      rate_limit_hit: "Rate Limit Reached",
      security_incident: "Security Alert",
      quota_warning: "Quota Warning",
      audio_generated: "Audio Overview Ready",
      batch_complete: "Batch Operation Complete",
    };
    return titles[event.type] || event.type;
  }

  /**
   * Get description for event
   */
  private getDescription(event: SystemEvent): string {
    const payload = event.payload as Record<string, unknown>;

    switch (event.type) {
      case "question_answered":
        return `Query answered in ${payload.duration_ms}ms (${payload.answer_length} chars)`;
      case "notebook_created":
        return `Created "${payload.name}" with ${payload.source_count} sources`;
      case "notebook_deleted":
        return `Deleted notebook "${payload.name}"`;
      case "source_added":
        return `Added ${payload.source_type} source to notebook`;
      case "rate_limit_hit":
        return `${payload.limit_type} limit reached: ${payload.current_count}/${payload.limit}`;
      case "security_incident":
        return `[${payload.severity}] ${payload.description}`;
      case "quota_warning":
        return `${payload.resource}: ${payload.percent}% used (${payload.used}/${payload.limit})`;
      case "batch_complete":
        return `${payload.operation}: ${payload.succeeded}/${payload.total} succeeded`;
      default:
        return JSON.stringify(payload);
    }
  }

  /**
   * Sign payload with HMAC-SHA256, including a unix timestamp in the signed
   * data so receivers can reject replayed requests (I271).
   * Signed message: "<timestamp>\n<payload>"
   */
  private sign(payload: string, secret: string, timestamp: number): string {
    const hmac = crypto.createHmac("sha256", secret);
    hmac.update(`${timestamp}\n${payload}`);
    return `sha256=${hmac.digest("hex")}`;
  }

  /**
   * Load recent delivery history from disk on startup (I279)
   */
  private loadDeliveryHistory(): void {
    try {
      if (!fs.existsSync(this.deliveryLogPath)) return;
      const lines = fs.readFileSync(this.deliveryLogPath, "utf-8").trim().split("\n");
      // Load last maxDeliveryHistory lines to seed in-memory buffer
      const recent = lines.slice(-this.maxDeliveryHistory);
      for (const line of recent) {
        try {
          if (line.trim()) {
            const delivery = JSON.parse(line) as WebhookDelivery;
            this.deliveryHistory.push(delivery);
            if (typeof delivery.sequence === "number" && delivery.sequence > this.deliverySequence) {
              this.deliverySequence = delivery.sequence;
            }
          }
        } catch {
          // skip malformed lines
        }
      }
    } catch (err) {
      log.debug(`webhook-dispatcher: failed to load delivery history: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * Record delivery for history — persists to disk for cross-restart auditability (I279)
   */
  private recordDelivery(delivery: WebhookDelivery): void {
    getMetricsRegistry().increment("webhook_deliveries_total", {
      event_type: delivery.eventType,
      success: delivery.success,
    });
    this.deliveryHistory.push(delivery);
    if (this.deliveryHistory.length > this.maxDeliveryHistory) {
      this.deliveryHistory.shift();
    }
    // Append to delivery log for durable audit trail
    try {
      fs.appendFileSync(this.deliveryLogPath, JSON.stringify(delivery) + "\n", { mode: 0o600 });
    } catch (err) {
      log.debug(`webhook-dispatcher: failed to persist delivery record: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  private nextDeliverySequence(): number {
    this.deliverySequence += 1;
    return this.deliverySequence;
  }

  // === Public API ===

  /**
   * Add a new webhook. Validates the URL before persisting; throws on
   * scheme/host/DNS-resolution failure so callers see a clear reason.
   * Records a ChangeLog entry for SOC2 change-management audit trail.
   */
  async addWebhook(input: AddWebhookInput): Promise<WebhookConfig> {
    const validation = await validateWebhookUrl(input.url);
    if (!validation.ok) {
      throw new Error(`webhook URL rejected: ${validation.error}`);
    }

    const webhook: WebhookConfig = {
      id: crypto.randomUUID(),
      name: input.name,
      url: input.url,
      enabled: true,
      events: input.events || ["*"],
      format: input.format || "generic",
      secret: undefined, // secret never persisted to disk
      headers: input.headers,
      retryCount: 3,
      retryDelayMs: 1000,
      timeoutMs: 5000,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    // Store secret in SecureCredential, not in the persisted webhook object (I321)
    if (input.secret) {
      this.webhookSecrets.set(webhook.id, new SecureCredential(input.secret, WEBHOOK_SECRET_TTL_MS));
    }

    this.store.webhooks.push(webhook);
    this.saveStore();

    log.success(`✅ Webhook added: ${webhook.name}`);
    await this.recordWebhookChange("add", webhook.id, null, validation.url.host);
    return webhook;
  }

  /**
   * Update a webhook. Re-validates the URL if it is being changed.
   * Records a ChangeLog entry for SOC2 change-management audit trail.
   *
   * Secret handling matches `addWebhook`: the new secret is held only in
   * the in-memory `webhookSecrets` SecureCredential map and written as
   * `undefined` to the persisted store. The previous implementation
   * silently disagreed with the comment in addWebhook — `updateWebhook`
   * was writing the plaintext secret straight into webhooks.json.
   */
  async updateWebhook(input: UpdateWebhookInput): Promise<WebhookConfig | null> {
    const index = this.store.webhooks.findIndex((w) => w.id === input.id);
    if (index === -1) return null;

    if (input.url !== undefined) {
      const validation = await validateWebhookUrl(input.url);
      if (!validation.ok) {
        throw new Error(`webhook URL rejected: ${validation.error}`);
      }
    }

    const webhook = this.store.webhooks[index];
    const oldHost = this.safeHost(webhook.url);
    const updated: WebhookConfig = {
      ...webhook,
      ...(input.name && { name: input.name }),
      ...(input.url && { url: input.url }),
      ...(input.enabled !== undefined && { enabled: input.enabled }),
      ...(input.events && { events: input.events }),
      ...(input.format && { format: input.format }),
      ...(input.headers && { headers: input.headers }),
      // Force secret to undefined in the persisted record. Real value
      // (if any) is stored in the in-memory SecureCredential map below.
      secret: undefined,
      updatedAt: new Date().toISOString(),
    };

    this.store.webhooks[index] = updated;
    this.saveStore();

    // Update SecureCredential store. `null` from caller means "clear",
    // a string means "rotate to this value", `undefined` means "leave as-is".
    if (input.secret !== undefined) {
      const existing = this.webhookSecrets.get(updated.id);
      if (existing) existing.wipe();
      if (input.secret) {
        this.webhookSecrets.set(
          updated.id,
          new SecureCredential(input.secret, WEBHOOK_SECRET_TTL_MS),
        );
      } else {
        this.webhookSecrets.delete(updated.id);
      }
    }

    log.success(`✅ Webhook updated: ${updated.name}`);
    await this.recordWebhookChange("update", updated.id, oldHost, this.safeHost(updated.url));
    return updated;
  }

  /**
   * Remove a webhook.
   * Records a ChangeLog entry for SOC2 change-management audit trail.
   */
  async removeWebhook(id: string): Promise<boolean> {
    const index = this.store.webhooks.findIndex((w) => w.id === id);
    if (index === -1) return false;

    const webhook = this.store.webhooks[index];
    this.store.webhooks.splice(index, 1);
    this.webhookSecrets.delete(id); // cleanup SecureCredential (I321)
    this.circuitBreakers.delete(id);
    this.saveStore();

    log.success(`✅ Webhook removed: ${webhook.name}`);
    await this.recordWebhookChange("remove", webhook.id, this.safeHost(webhook.url), null);
    return true;
  }

  /**
   * Helper: extract just the host from a URL for audit records. Never
   * log the full URL (may contain secret tokens as path components, as
   * Slack/Discord do).
   */
  private safeHost(rawUrl: string): string {
    try {
      return new URL(rawUrl).host;
    } catch (err) {
      log.debug(`webhook-dispatcher: parsing URL in safeHost: ${err instanceof Error ? err.message : String(err)}`);
      return "[invalid-url]";
    }
  }

  /**
   * Helper: write a ChangeLog entry for webhook CRUD. Errors are
   * swallowed with a warning — the webhook change itself has already
   * succeeded and compliance logging must not break the caller.
   */
  private async recordWebhookChange(
    action: "add" | "update" | "remove",
    id: string,
    oldHost: string | null,
    newHost: string | null,
  ): Promise<void> {
    try {
      const { getChangeLog } = await import("../compliance/change-log.js");
      await getChangeLog().recordChange("webhooks", `webhook.${id}`, oldHost, newHost, {
        changedBy: "user",
        method: "api",
        impact: action === "remove" ? "medium" : "low",
        affectedCompliance: ["SOC2"],
      });
    } catch (err) {
      log.warning(
        `ChangeLog recordChange failed (webhooks.${action}): ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  /**
   * List all webhooks (full records, including URL).
   *
   * Internal-only — this returns full URLs that may embed secret
   * tokens (Slack incoming-webhook URLs, Discord webhooks, etc.) and
   * historically may include legacy persisted `secret` fields. MCP
   * tool handlers must use `listWebhooksPublic()` instead.
   */
  listWebhooks(): WebhookConfig[] {
    return this.store.webhooks;
  }

  /**
   * List webhooks as redacted public DTOs.
   *
   * The MCP `list_webhooks` tool is read-scope, which means a caller
   * with only a read-only token can invoke it. Handing back full
   * `WebhookConfig` records would leak credential-bearing URLs
   * (Slack, Discord, Teams all embed tokens in the URL path). This
   * method returns just the metadata needed to identify each
   * webhook: id, name, host, format, events, enabled flag, retry
   * settings, timestamps, and a `hasSecret` boolean to disclose
   * whether an HMAC secret is configured without revealing it.
   */
  listWebhooksPublic(): WebhookConfigPublic[] {
    return this.store.webhooks.map((w) => {
      let host: string;
      try {
        host = new URL(w.url).host;
      } catch {
        host = "[invalid-url]";
      }
      return {
        id: w.id,
        name: w.name,
        enabled: w.enabled,
        events: w.events,
        format: w.format,
        host,
        hasSecret: this.webhookSecrets.has(w.id),
        retryCount: w.retryCount,
        retryDelayMs: w.retryDelayMs,
        timeoutMs: w.timeoutMs,
        createdAt: w.createdAt,
        updatedAt: w.updatedAt,
      };
    });
  }

  /**
   * Get a specific webhook
   */
  getWebhook(id: string): WebhookConfig | null {
    return this.store.webhooks.find((w) => w.id === id) || null;
  }

  /**
   * Test a webhook
   */
  async testWebhook(id: string): Promise<{ success: boolean; error?: string }> {
    const webhook = this.getWebhook(id);
    if (!webhook) {
      return { success: false, error: "Webhook not found" };
    }

    const testEvent: SystemEvent = {
      type: "question_answered",
      timestamp: new Date().toISOString(),
      source: "notebooklm-mcp",
      version: process.env.npm_package_version ?? "2026.2.11",
      payload: {
        question_length: 50,
        answer_length: 200,
        session_id: "test-session",
        duration_ms: 1234,
      },
    };

    const success = await this.sendWithRetry(webhook, testEvent);
    return { success };
  }

  /**
   * Get webhook statistics
   */
  getStats(): WebhookStats {
    const deliveries = this.deliveryHistory;
    const successes = deliveries.filter((d) => d.success);
    const failures = deliveries.filter((d) => !d.success);

    return {
      totalDeliveries: deliveries.length,
      successCount: successes.length,
      failureCount: failures.length,
      lastDelivery: deliveries[deliveries.length - 1]?.timestamp,
      lastSuccess: successes[successes.length - 1]?.timestamp,
      lastFailure: failures[failures.length - 1]?.timestamp,
    };
  }

  /**
   * Cleanup
   */
  destroy(): void {
    if (this.unsubscribe) {
      this.unsubscribe();
      this.unsubscribe = null;
    }
  }
}

// Singleton instance
let dispatcher: WebhookDispatcher | null = null;

export function getWebhookDispatcher(): WebhookDispatcher {
  if (!dispatcher) {
    dispatcher = new WebhookDispatcher();
  }
  return dispatcher;
}
