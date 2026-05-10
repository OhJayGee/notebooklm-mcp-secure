/**
 * Webhook Configuration Types
 */

import type { EventType } from "../events/event-types.js";

export interface WebhookConfig {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  events: (EventType | "*")[]; // Which events to send
  format: "generic" | "slack" | "discord" | "teams";
  secret?: string; // For HMAC signature
  headers?: Record<string, string>; // Custom headers
  retryCount?: number; // Default: 3
  retryDelayMs?: number; // Default: 1000 (exponential backoff)
  timeoutMs?: number; // Default: 5000
  createdAt: string;
  updatedAt: string;
}

export interface WebhookDelivery {
  id: string;
  /** Monotonic sequence number for ordering/replay across restarts */
  sequence: number;
  webhookId: string;
  eventType: EventType;
  timestamp: string;
  success: boolean;
  statusCode?: number;
  error?: string;
  /** Classifies network-level failures: timeout = AbortController fired; dns_or_connect = permanent unreachable; network = other */
  errorKind?: "timeout" | "dns_or_connect" | "network";
  attempts: number;
  durationMs: number;
}

export interface WebhookStats {
  totalDeliveries: number;
  successCount: number;
  failureCount: number;
  lastDelivery?: string;
  lastSuccess?: string;
  lastFailure?: string;
}

export interface AddWebhookInput {
  name: string;
  url: string;
  events?: (EventType | "*")[];
  format?: "generic" | "slack" | "discord" | "teams";
  secret?: string;
  headers?: Record<string, string>;
}

export interface UpdateWebhookInput {
  id: string;
  name?: string;
  url?: string;
  enabled?: boolean;
  events?: (EventType | "*")[];
  format?: "generic" | "slack" | "discord" | "teams";
  secret?: string;
  headers?: Record<string, string>;
}

/**
 * Redacted public DTO returned by listWebhooks-style read endpoints.
 *
 * Some webhook URL formats (Slack, Discord, Microsoft Teams) embed
 * credential tokens directly in the URL path — handing the full URL
 * back to a read-scope MCP caller is equivalent to handing them the
 * webhook secret. The `host` field is the only URL component a
 * read-scope caller needs to identify the webhook target. The
 * `hasSecret` boolean discloses whether an HMAC signing secret is
 * configured without revealing its value.
 */
export interface WebhookConfigPublic {
  id: string;
  name: string;
  enabled: boolean;
  events: (EventType | "*")[];
  format: "generic" | "slack" | "discord" | "teams";
  /** URL host only — never the full URL. */
  host: string;
  hasSecret: boolean;
  retryCount?: number;
  retryDelayMs?: number;
  timeoutMs?: number;
  createdAt: string;
  updatedAt: string;
}
