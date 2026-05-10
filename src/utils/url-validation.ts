/**
 * Shared outbound-URL validation helpers.
 *
 * Hoisted from src/webhooks/webhook-dispatcher.ts so the same SSRF
 * defences can be applied uniformly to every code path that issues
 * outbound HTTP from the server: webhook delivery, alert-manager
 * notifications, SIEM export, and (browser-context) audio download
 * navigation.
 *
 * Two checks live here:
 *
 *   - `isPrivateHost(hostname)` — synchronous lexical check that
 *     covers loopback, link-local (incl. AWS/GCP metadata 169.254/16),
 *     RFC 1918, RFC 6598 CGNAT, multicast, IPv4-mapped IPv6, and the
 *     `localhost` / `*.local` / `*.internal` family.
 *
 *   - `validateOutboundUrl(url, options)` — async URL gate. Parses,
 *     enforces scheme allowlist, applies the private-host check
 *     lexically, and (when `resolveDns: true`) resolves the host
 *     and re-checks every resulting IP. The DNS-resolution branch
 *     closes the DNS-rebinding window between config-time validation
 *     and delivery — callers that need the strongest guarantee
 *     (`webhook-dispatcher.ts:sendWithRetry`) re-run it before each
 *     delivery.
 *
 * Both helpers preserve the `webhook-dispatcher.ts` pre-existing
 * behaviour exactly — they are factored, not rewritten.
 */

import net from "node:net";
import dns from "node:dns/promises";

export type UrlValidationResult =
  | { ok: true; url: URL }
  | { ok: false; error: string };

/**
 * RFC 1918 + 6598 + 5735 + AWS/GCP metadata classification of an
 * IPv4 dotted-quad address.
 */
export function isPrivateIPv4(addr: string): boolean {
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

export function isPrivateIPv6(addr: string): boolean {
  const lower = addr.toLowerCase();
  if (lower === "::1" || lower === "::") return true;         // loopback, unspecified
  if (lower.startsWith("fe80:") || lower.startsWith("fe80::")) return true; // link-local
  if (lower.startsWith("fc") || lower.startsWith("fd")) return true;        // unique local fc00::/7
  if (lower.startsWith("ff")) return true;                    // multicast

  // IPv4-mapped IPv6. Node's URL parser normalises dotted-quad form
  // to compressed hex (::ffff:169.254.169.254 -> ::ffff:a9fe:a9fe), so
  // we accept both and recover the IPv4 for range-checking.
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

/**
 * Lexical private-host check. Strips IPv6 brackets, then matches
 * loopback / link-local / RFC 1918 / metadata IP ranges, plus the
 * `localhost` / `*.local` / `*.internal` family.
 */
export function isPrivateHost(hostname: string): boolean {
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

export interface ValidateOutboundUrlOptions {
  /** Allow `http:` URLs in addition to `https:`. Default: false. */
  allowHttp?: boolean;
  /** Resolve DNS and check every returned IP. Default: false. */
  resolveDns?: boolean;
  /** DNS lookup timeout in ms. Default: 2000. */
  dnsTimeoutMs?: number;
}

/**
 * Validate an outbound URL against the SSRF defence pipeline:
 *   1. URL parses
 *   2. Scheme on allowlist (https, plus http when allowHttp=true)
 *   3. Lexical hostname not in private/loopback/link-local space
 *   4. (Optional) DNS resolution; every resulting IP must be public
 *
 * Returns a discriminated `UrlValidationResult`. Callers must check
 * the `ok` flag before using `result.url`.
 */
export async function validateOutboundUrl(
  rawUrl: string,
  options: ValidateOutboundUrlOptions = {},
): Promise<UrlValidationResult> {
  const { allowHttp = false, resolveDns = false, dnsTimeoutMs = 2000 } = options;

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, error: "invalid URL" };
  }

  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && allowHttp)) {
    return {
      ok: false,
      error: `scheme '${parsed.protocol}' not allowed (need https:${allowHttp ? " or http:" : ""})`,
    };
  }

  const host = parsed.hostname;
  if (!host) return { ok: false, error: "URL missing hostname" };
  if (isPrivateHost(host)) {
    return { ok: false, error: `hostname '${host}' is in a private/loopback/link-local range` };
  }

  if (resolveDns && !net.isIP(host)) {
    try {
      const addresses = await Promise.race([
        dns.lookup(host, { all: true }),
        new Promise<never>((_, reject) =>
          setTimeout(() => reject(new Error(`DNS lookup timed out after ${dnsTimeoutMs}ms`)), dnsTimeoutMs),
        ),
      ]);
      for (const { address, family } of addresses) {
        if (family === 4 && isPrivateIPv4(address)) {
          return { ok: false, error: `hostname '${host}' resolves to private IPv4 ${address}` };
        }
        if (family === 6 && isPrivateIPv6(address)) {
          return { ok: false, error: `hostname '${host}' resolves to private IPv6 ${address}` };
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

/**
 * Synchronous outbound-URL gate. Same as `validateOutboundUrl` minus
 * the DNS resolution branch. Used by code paths that cannot await
 * (browser-context navigation, sync log/alert paths). Combine with
 * `validateOutboundUrl({ resolveDns: true })` for stronger guarantees
 * where async is acceptable.
 */
export function validateOutboundUrlSync(
  rawUrl: string,
  options: Omit<ValidateOutboundUrlOptions, "resolveDns" | "dnsTimeoutMs"> = {},
): UrlValidationResult {
  const { allowHttp = false } = options;

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, error: "invalid URL" };
  }

  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && allowHttp)) {
    return {
      ok: false,
      error: `scheme '${parsed.protocol}' not allowed (need https:${allowHttp ? " or http:" : ""})`,
    };
  }

  const host = parsed.hostname;
  if (!host) return { ok: false, error: "URL missing hostname" };
  if (isPrivateHost(host)) {
    return { ok: false, error: `hostname '${host}' is in a private/loopback/link-local range` };
  }

  return { ok: true, url: parsed };
}

/**
 * Allowlist for hostnames that NotebookLM-rendered media (audio
 * overviews, video overviews) is expected to download from. Google
 * uses `*.googleusercontent.com` for object storage, `*.google.com`
 * for routed download endpoints, and occasionally `*.googleapis.com`
 * for content APIs. We accept any subdomain of those three families.
 *
 * Hard-coded here (not derived from a wider list) so a future
 * `validateNotebookUrl` allowlist expansion does not silently widen
 * the media-download allowlist.
 */
const NOTEBOOKLM_MEDIA_HOST_SUFFIXES: readonly string[] = [
  ".google.com",
  ".googleusercontent.com",
  ".googleapis.com",
];

/**
 * Validate a URL that the server is about to navigate to from inside
 * an authenticated browser context to download user-visible media
 * (audio overview MP3, video MP4, etc.).
 *
 * The threat model: the URL is scraped from the NotebookLM page DOM
 * via `page.evaluate(...)`. A prompt-injection chain through a source
 * document the user added to the notebook can plant arbitrary
 * `<a download href="...">` or `<audio src="...">` elements. Without
 * this gate, `page.goto(scrapedUrl)` would navigate the authenticated
 * session to whatever the attacker chose — including `file:///etc/passwd`
 * (local file disclosure into the response body) or `https://169.254.169.254/`
 * (cloud metadata SSRF in cloud-hosted deployments).
 *
 * This gate enforces:
 *   1. HTTPS (rejects `file:`, `javascript:`, `data:`, `http:`).
 *   2. Hostname not in the private-IP / loopback / metadata range.
 *   3. Hostname suffix matches one of NOTEBOOKLM_MEDIA_HOST_SUFFIXES
 *      (Google's expected media-download domains).
 *
 * Returns the parsed URL on success; throws Error on rejection so
 * callers can use a single try/catch.
 */
export function validateNotebookLMMediaUrl(rawUrl: string): URL {
  const sync = validateOutboundUrlSync(rawUrl);
  if (!sync.ok) throw new Error(`media URL rejected: ${sync.error}`);

  const host = sync.url.hostname.toLowerCase();
  const allowed = NOTEBOOKLM_MEDIA_HOST_SUFFIXES.some((suffix) =>
    host === suffix.replace(/^\./, "") || host.endsWith(suffix),
  );
  if (!allowed) {
    throw new Error(
      `media URL host '${host}' is not on the NotebookLM media-download allowlist`,
    );
  }
  return sync.url;
}
