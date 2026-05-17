# Security Hardening Documentation

Fork lineage: [PleasePrompto/notebooklm-mcp](https://github.com/PleasePrompto/notebooklm-mcp) → [Pantheon-Security/notebooklm-mcp-secure](https://github.com/Pantheon-Security/notebooklm-mcp-secure) → this fork. Maintained by [OhJayGee](https://github.com/OhJayGee).

**Version**: 2026.3.3
**Security mechanisms**: see the table below — each row is a concrete mechanism backed by a test, not a marketing line item
**Platforms**: Linux, macOS, Windows

> **v2026.3.3 — Adversarial Review Fixes.** Two independent adversarial reviews of the codebase converged on the same critical findings (notebook-library URL poisoning, sessionStorage-into-attacker-origin, single-file upload bypass, read-only token can mutate state) plus a high-severity arbitrary file write in `get_notebook_chat_history`. All findings are patched in v2026.3.3 with regression tests pinning each one (104 new tests across 8 files; suite is now 747 passing). The package's `securityHardening` and `complianceControls` blocks have been rewritten in honest scope at the same time — each entry now describes its actual mechanism rather than a boolean. See [CHANGELOG.md](./CHANGELOG.md) for the full list.

> **v2026.3.1 — Security Audit Complete.** In April 2026 we ran a parallel deep-audit of this codebase using four specialised AI code reviewers, each independently focused on a different attack surface. They produced a 334-item master issue list. All 334 issues are resolved across v2026.3.0 and v2026.3.1. See [CHANGELOG.md](./CHANGELOG.md) for the full list.

## Threat Model — What This Fork Defends Against, And What It Doesn't

The security claims below are scoped against a specific threat model. Reading
them outside that model will mislead you.

**This fork actively defends against:**

- A prompt-injection chain through a malicious notebook source, web page, or
  uploaded document trying to coerce the host LLM into emitting tool calls
  that exfiltrate local files, overwrite system files, or navigate the
  authenticated browser to attacker origins.
- An MCP client (Claude Code, Codex CLI) that has accumulated bad context
  and is now emitting unintended tool calls.
- An attacker with read-scope authentication (or in an `NLMCP_AUTH_DISABLED`
  deployment) trying to mutate library state, trigger remote NotebookLM
  mutations, or upload local credentials to Google.
- Supply-chain compromise of a transitive dependency at install time
  (signature verification, `--ignore-scripts`, lockfile-drift detection,
  exact-version pins).
- Offline theft of individual encrypted credential / state files (local
  at-rest encryption with ChaCha20-Poly1305 + ML-KEM-768).

**This fork does NOT defend against:**

- An attacker with admin-scope authentication. Admin scope can read any file
  the process can read and write any path within the export base. Treat the
  admin token as equivalent to your shell.
- An attacker who has compromised the Google account whose session is in
  use. The MCP server has the same notebook access the user does.
- An attacker who can read or modify files in the data directory while the
  server is running. The "encryption at rest" is local — the unwrap key
  lives on the same disk. Filesystem isolation (perms, FDE) is the
  defence-in-depth layer here.
- Shoulder-surfing or screen-recording during interactive setup
  (`setup_auth` opens a visible browser by default).
- Browser-level exploits in Chrome / Chromium (we use the user's installed
  browser).
- A compromised Google bidding for the NotebookLM domain (the URL allowlist
  trusts that `notebooklm.google.com` is operated by Google).

**This fork is NOT a compliance certification.** GDPR / SOC2 / CSSF are
organisational properties: they require policies, training, vendor management,
incident response procedures, and a third-party audit. The compliance code
in this repo provides necessary primitives — consent management, DSAR
handling, retention engine, hash-chained audit logs, SIEM exporter — but
those primitives are not sufficient for certification on their own.

## Security Features Overview

| Feature | Status | Description |
|---------|--------|-------------|
| Input Validation | ✅ | URL whitelisting, Zod schemas, injection prevention |
| Rate Limiting | ✅ | Per-session request throttling |
| Log Sanitization | ✅ | Credential masking, PII redaction |
| Audit Logging | ✅ | Hash-chained tamper-evident logs, verified on read |
| Session Timeout | ✅ | Hard lifetime + inactivity limits |
| MCP Authentication | ✅ | Token-based auth with persistent salt + lockout |
| Response Validation | ✅ | Prompt injection detection, suspicious URL blocking |
| **Post-Quantum Encryption** | ✅ | ML-KEM-768 + ChaCha20-Poly1305 (local at-rest) |
| **Secrets Scanning** | ✅ | Detect 30+ credential patterns (AWS, GitHub, Slack…) |
| **Memory Scrubbing** | ✅ | Zero sensitive data after use, FinalizationRegistry cleanup |
| **MEDUSA Integration** | ✅ | Automated security scanning in CI |
| **Cross-Platform Permissions** | ✅ | Secure file permissions on all OSes |
| **Secure-by-Default Auth** | ✅ | Auth enabled without configuration; stdio MCP clients use `NLMCP_STDIO_TRANSPORT_AUTH=true` for the trusted-pipe model (see MCP Authentication section); explicit opt-out via `NLMCP_AUTH_DISABLED=true` |
| **Exponential Backoff Lockout** | ✅ | Failed auth lockouts escalate 5min → 15min → 45min → 4hr; `lockoutCount` persists |
| **Credential Isolation** | ✅ | `LOGIN_PASSWORD` and `GEMINI_API_KEY` wrapped in `SecureCredential` with 30-min TTL; env vars scrubbed from `process.env` |
| **Webhook SSRF Protection** | ✅ | Delivery targets validated against SSRF blocklist; HMAC signing on all deliveries |
| **Per-Page Mutex** | ✅ | Browser page operations serialised per-page to prevent race conditions |

---

## Cross-Platform Support

Full native support for Linux, macOS, and Windows with proper secure file permissions on each platform.

### Platform-Specific Security

| Platform | File Permissions | Implementation |
|----------|-----------------|----------------|
| **Linux** | Unix chmod | `0o600` (files), `0o700` (directories) |
| **macOS** | Unix chmod | `0o600` (files), `0o700` (directories) |
| **Windows** | ACLs via icacls | Current user only (Full Control) |

### Data Directories

| Platform | Path |
|----------|------|
| Linux | `~/.local/share/notebooklm-mcp/` |
| macOS | `~/Library/Application Support/notebooklm-mcp/` |
| Windows | `%LOCALAPPDATA%\notebooklm-mcp\` |

### Protected Files

All sensitive files are automatically protected with owner-only permissions:
- Encryption keys (`pq-keys.enc`)
- Authentication tokens (`auth-token.hash`)
- Audit logs (`audit/*.jsonl`)
- Browser session state (`browser_state/`)
- Notebook library (`library.json`)
- Settings (`settings.json`)

---

## Post-Quantum Encryption (Local At-Rest)

### Scope

Secrets written to disk (cookies, session state, auth tokens, PQ key pair) are encrypted with hybrid post-quantum primitives:
- **ML-KEM-768 (Kyber)** - NIST-standardized post-quantum key encapsulation
- **ChaCha20-Poly1305** - Modern stream cipher (NOT AES-GCM)

### What this does and does not protect against

This is **local at-rest** encryption. Both keys live on the same machine: the PQ secret key is wrapped with a classical key derived from a machine-bound secret, not held by a remote recipient.

- ✅ Protects against **offline theft** of individual encrypted files (backup leak, misplaced disk)
- ✅ Defence-in-depth on top of the underlying filesystem permissions
- ❌ Does **NOT** protect against Harvest-Now-Decrypt-Later attacks — that threat model requires a remote PQ recipient holding the unwrap key, which this implementation does not have
- ❌ Does **NOT** protect against an attacker who compromises the host — they can read the machine-derived key and unwrap the PQ secret key in the same step

### Why ChaCha20-Poly1305 over AES-GCM?

| Property | ChaCha20-Poly1305 | AES-GCM |
|----------|-------------------|---------|
| Timing attacks | Immune (constant-time) | Vulnerable without AES-NI |
| Software speed | Fast everywhere | Slow without hardware |
| Complexity | Simple | Complex (GCM mode) |
| Adoption | Google, Cloudflare TLS | Legacy systems |

This provides **double protection**: even if one algorithm is broken, the other remains secure.

### What's Encrypted

- Browser session state (cookies, localStorage)
- Session storage data
- Post-quantum key pairs (double-encrypted)

### Encrypted File Format

Files are saved with `.pqenc` extension:
```json
{
  "version": 3,
  "algorithm": "chacha20-poly1305",
  "pqAlgorithm": "ML-KEM-768",
  "encapsulatedKey": "<base64>",
  "nonce": "<base64>",
  "salt": "<base64>",
  "ciphertext": "<base64 with Poly1305 tag appended>"
}
```

### Configuration

```bash
# Enable/disable post-quantum encryption (default: enabled)
NLMCP_USE_POST_QUANTUM=true

# Provide your own classical key (optional)
NLMCP_ENCRYPTION_KEY=<base64-32-bytes>

# Disable encryption entirely (NOT recommended)
NLMCP_ENCRYPTION_ENABLED=false
```

### Automatic Migration

When you upgrade, existing unencrypted files are automatically:
1. Loaded
2. Re-encrypted with ML-KEM-768 + ChaCha20-Poly1305
3. Old unencrypted files are deleted

---

## Secrets Scanning

Real-time detection of credentials in logs and responses using patterns from TruffleHog and GitLeaks.

### Detected Secret Types

| Category | Types |
|----------|-------|
| Cloud | AWS Access Keys, GCP API Keys, Azure Tokens |
| AI Services | OpenAI, Anthropic, Google AI API keys |
| Source Control | GitHub PATs, GitLab tokens |
| Communication | Slack tokens/webhooks |
| Payment | Stripe API keys |
| Auth | JWTs, Bearer tokens, Basic Auth |
| Databases | PostgreSQL, MongoDB, MySQL connection strings |
| Keys | RSA, EC, SSH, PGP private keys |

### Configuration

```bash
NLMCP_SECRETS_SCANNING=true       # Enable scanning (default: true)
NLMCP_SECRETS_BLOCK=false         # Block on detection (default: false, just warn)
NLMCP_SECRETS_REDACT=true         # Auto-redact secrets (default: true)
NLMCP_SECRETS_MIN_SEVERITY=low    # Minimum severity: critical, high, medium, low
NLMCP_SECRETS_IGNORE=pattern1,pattern2  # Ignore specific patterns
```

### Example Detection

```
🔐 Secrets detected: 1 critical, 0 high
   - AWS Access Key ID at line 42
```

---

## Memory Scrubbing

Sensitive data is securely wiped from memory after use to prevent:
- Memory dump attacks
- Cold boot attacks
- Credential persistence in RAM

### Features

| Feature | Description |
|---------|-------------|
| `zeroBuffer()` | Securely zero-fill Buffer objects |
| `SecureString` | String wrapper with `.wipe()` method |
| `SecureCredential` | Auto-expiring credential with timer |
| `SecureObject` | Object with dispose-and-wipe capability |
| `secureCompare()` | Timing-safe string comparison |

### Auto-cleanup

Using `FinalizationRegistry`, secure buffers are automatically wiped when garbage collected.

### Usage

```typescript
import { SecureCredential, withSecureCredential } from './utils/secure-memory.js';

// Auto-wipe after 5 minutes
const cred = new SecureCredential(apiKey, 300000);

// Or use helper that auto-wipes after function completes
await withSecureCredential(apiKey, async (cred) => {
  await makeRequest(cred.getValue());
});
// Credential is now wiped
```

---

## MEDUSA Integration

Automated security scanning using [MEDUSA](https://github.com/Pantheon-Security/medusa) - Multi-Language Security Scanner with 46+ analyzers.

### Quick Scan

```bash
npm run security-scan
# or
medusa scan . --fail-on high
```

### Configuration

See `.medusa.yml` in project root.

### CI/CD Integration

```yaml
# GitHub Actions
- name: Security Scan
  run: npm run security-scan
```

---

## Audit Logging

All events are logged with cryptographic integrity:

```
~/.local/share/notebooklm-mcp/audit/
├── audit-2025-11-28.jsonl
└── ...
```

### Log Format (JSONL with hash chain)

```json
{"timestamp":"2025-11-28T10:30:00Z","type":"tool","event":"ask_question","success":true,"duration_ms":3420,"hash":"a1b2c3..."}
```

Each entry's hash includes the previous entry, making tampering detectable.

### Configuration

```bash
NLMCP_AUDIT_ENABLED=true       # Default: true
NLMCP_AUDIT_DIR=/path/to/audit # Default: ~/.local/share/notebooklm-mcp/audit
```

---

## Session Timeout

Sessions are protected by dual timeout enforcement:

| Timeout | Default | Purpose |
|---------|---------|---------|
| Max Lifetime | 8 hours | Hard limit regardless of activity |
| Inactivity | 30 minutes | Closes idle sessions |

### Configuration

```bash
NLMCP_SESSION_MAX_LIFETIME=28800   # 8 hours in seconds
NLMCP_SESSION_INACTIVITY=1800      # 30 minutes in seconds
```

---

## MCP Authentication

Require authentication for all MCP requests. The trust model depends
on transport.

### Trust model

**Stdio transport.** The pipe between parent and child IS the trust
boundary. Only the spawning parent can write to that file descriptor.
Once the parent has proved knowledge of the token at startup, every
subsequent message on that pipe is by definition from the same trusted
parent — per-call re-validation adds no security against any attacker
the design defends against (prompt-injection coercion of an already-
trusted parent is in scope; an attacker who has compromised the parent
process is out of scope). `NLMCP_STDIO_TRANSPORT_AUTH=true` enables
this model.

**HTTP/SSE transport.** Anyone on the network could connect, so per-
call auth stays mandatory. Token must be presented in
`request.params._meta.authToken` on every tool call. Default mode.

### Modes

| Mode | Env vars | When to use |
|---|---|---|
| **default (per-call)** | `NLMCP_AUTH_TOKEN` | HTTP/SSE, or custom stdio clients that inject `_meta.authToken` per call. Will NOT work with Claude Code / Codex CLI / Claude Desktop. |
| **stdio transport-auth (recommended for stdio)** | `NLMCP_AUTH_TOKEN` + `NLMCP_STDIO_TRANSPORT_AUTH=true` | Stdio MCP clients. Parent proves token at startup, server scrubs env, per-call auth short-circuits. Admin scope. |
| **stdio transport-auth (read-only)** | Above + `NLMCP_STDIO_TRANSPORT_AUTH_SCOPE=read` | Trust pinned to read scope; admin-scope tools (`setup_auth`, mutations) rejected with `insufficient_scope`. |
| **legacy escape hatch** | `NLMCP_AUTH_TOKEN` + `NLMCP_AUTH_KEEP_ENV=true` | Same operational effect as transport-auth but leaves token in `process.env` for the process lifetime. Retained for backwards compatibility; prefer transport-auth. |

### Setup

On first run with auth enabled, a token is auto-generated:
```
╔══════════════════════════════════════════════════════════════════════╗
║  MCP AUTHENTICATION TOKEN                                           ║
╠══════════════════════════════════════════════════════════════════════╣
║  Token: <your-token>                                                 ║
╠══════════════════════════════════════════════════════════════════════╣
║  Add to your stdio MCP client config:                               ║
║    NLMCP_AUTH_TOKEN=<token>                                          ║
║    NLMCP_STDIO_TRANSPORT_AUTH=true                                   ║
╚══════════════════════════════════════════════════════════════════════╝
```

### Claude Code Configuration

```bash
claude mcp add notebooklm \
  --env NLMCP_AUTH_TOKEN=<your-token> \
  --env NLMCP_STDIO_TRANSPORT_AUTH=true \
  -- npx notebooklm-mcp-secure
```

For a read-only deployment, add `--env NLMCP_STDIO_TRANSPORT_AUTH_SCOPE=read`.

### Rate Limiting for Failed Auth

- 5 failed attempts = 5 minute lockout
- Prevents brute force attacks
- Bypassed entirely in transport-auth mode (the pipe is the trust
  boundary; lockouts cannot apply to a connection that doesn't need
  per-call token validation)

---

## Response Validation

All responses from NotebookLM are scanned for:

### Prompt Injection Detection
- `ignore previous instructions`
- `you are now in [mode]`
- `system:` injections
- Chat template delimiters (`[INST]`, `<|im_start|>`)

### Suspicious URL Detection
- URL shorteners (bit.ly, tinyurl)
- Paste services (pastebin)
- File/JavaScript protocols
- Raw IP addresses
- Webhook URLs

### Encoded Payload Detection
- Long Base64 strings
- Hex encoded data
- Heavy URL encoding
- Unicode escape sequences

### Configuration

```bash
NLMCP_RESPONSE_VALIDATION=true
NLMCP_BLOCK_PROMPT_INJECTION=true
NLMCP_BLOCK_SUSPICIOUS_URLS=true
NLMCP_BLOCK_ENCODED_PAYLOADS=false  # Just warn by default
```

---

## Input Validation

All user inputs are validated:

| Input | Validation |
|-------|-----------|
| `notebook_url` | HTTPS only, domain whitelist (notebooklm.google.com variants) |
| `notebook_id` | Alphanumeric + dashes only, max 128 chars |
| `session_id` | Alphanumeric + dashes only, max 64 chars |
| `question` | Non-empty, max 32,000 chars |

### URL Whitelisting

Allowed domains:
- `notebooklm.google.com`
- Regional variants (`.co.uk`, `.de`, `.fr`, etc.)

Blocked:
- `javascript:` URLs
- `data:` URLs
- `file:` URLs
- Non-HTTPS URLs
- Path traversal attempts

---

## Log Sanitization

Sensitive data is masked in all log output:
- Email: `j***n@example.com`
- Passwords: `[REDACTED]`
- API keys: `[REDACTED]`
- Tokens: `[REDACTED]`

---

## Rate Limiting

Built-in rate limiting prevents abuse:
- 100 requests per minute per session
- Configurable via `RateLimiter` class

---

## Remaining Considerations

### Browser Automation Risks

This MCP uses browser automation (Patchright) which:
- May violate Google's Terms of Service
- Could be detected and blocked

**Recommendations:**
- Use a dedicated Google account (not your primary)
- Run in an isolated environment (VM or container)

### Not Encrypted (Chrome Profile)

The Chrome profile directory itself is not fully encrypted:
- `~/.local/share/notebooklm-mcp/chrome_profile/`

The sensitive state files (cookies, session) ARE encrypted with hybrid post-quantum primitives for at-rest protection. See [Post-Quantum Encryption (Local At-Rest)](#post-quantum-encryption-local-at-rest) above for the exact threat model this covers.

---

## Quick Start

```bash
# Install
npm install notebooklm-mcp-secure

# Or with Claude Code
claude mcp add notebooklm npx notebooklm-mcp-secure@latest

# With all security features (recommended for stdio MCP clients)
claude mcp add notebooklm \
  --env NLMCP_AUTH_TOKEN=$(openssl rand -base64 32) \
  --env NLMCP_STDIO_TRANSPORT_AUTH=true \
  --env NLMCP_USE_POST_QUANTUM=true \
  -- npx notebooklm-mcp-secure@latest
```

---

## Security Module API

```typescript
// Input validation & rate limiting
import {
  validateNotebookUrl,
  validateSessionId,
  validateQuestion,
  sanitizeForLogging,
  maskEmail,
  RateLimiter,
  SecurityError,
} from './utils/security.js';

// Post-quantum encryption (ML-KEM-768 + ChaCha20-Poly1305)
import {
  getSecureStorage,
  SecureStorage,
  encryptPQ,
  decryptPQ,
  generatePQKeyPair,
} from './utils/crypto.js';

// Response validation & prompt injection detection
import { getResponseValidator, validateResponse } from './utils/response-validator.js';

// Tamper-evident audit logging
import { getAuditLogger, audit } from './utils/audit-logger.js';

// MCP token authentication
import { getMCPAuthenticator, authenticateMCPRequest } from './auth/mcp-auth.js';

// Secrets scanning
import {
  SecretsScanner,
  scanForSecrets,
  scanAndRedactSecrets,
} from './utils/secrets-scanner.js';

// Memory security
import {
  SecureString,
  SecureCredential,
  zeroBuffer,
  withSecureCredential,
  secureCompare,
} from './utils/secure-memory.js';

// === USAGE EXAMPLES ===

// Post-quantum encrypted storage
const storage = getSecureStorage();
await storage.save('/path/to/file', sensitiveData);
const data = await storage.load('/path/to/file');

// Direct post-quantum encryption
const keyPair = generatePQKeyPair();
const encrypted = encryptPQ('secret data', keyPair.publicKey);
const decrypted = decryptPQ(encrypted, keyPair.secretKey);

// Secrets scanning
const secrets = scanForSecrets(responseText);
if (secrets.length > 0) {
  console.log('Found secrets:', secrets.map(s => s.type));
}

// Auto-redact secrets
const { clean, secrets: found } = await scanAndRedactSecrets(responseText);

// Memory-safe credential handling
await withSecureCredential(apiKey, async (cred) => {
  await makeRequest(cred.getValue());
}); // Auto-wiped after use

// Timing-safe comparison (prevents timing attacks)
if (secureCompare(userToken, storedToken)) {
  // Authenticated
}

// Response validation
const result = await validateResponse(notebookLMResponse);
if (!result.safe) {
  console.log('Blocked:', result.blocked);
}

// Audit logging
await audit.tool('ask_question', true, 3420, { question_length: 150 });
await audit.security('prompt_injection_detected', 'critical', { pattern: '...' });
```

---

## Reporting Vulnerabilities

If you discover a security vulnerability:
- Email: olv@grolle.de
- Do NOT open a public GitHub issue for security vulnerabilities

---

## Credits

- Original implementation: [Gérôme Dexheimer](https://github.com/PleasePrompto)
- First security-hardening fork: [Pantheon Security](https://github.com/Pantheon-Security/notebooklm-mcp-secure)
- This fork (adversarial-review fixes + claim trim): [OhJayGee](https://github.com/OhJayGee)
- Post-quantum crypto: [@noble/post-quantum](https://www.npmjs.com/package/@noble/post-quantum)

## License

MIT License — preserved through every link in the fork chain.
