/**
 * Regression test for SecureStorage.save() fail-closed behaviour.
 *
 * Pre-fix, when encryption was disabled OR no key was available, save()
 * silently fell back to writing plaintext via writeFileSecure(). This is
 * a poor failure mode for files that hold session cookies, sessionStorage,
 * and auth state — a misconfigured key results in cleartext credentials
 * on disk.
 *
 * Post-fix, save() throws unless the operator explicitly opts in via
 * NLMCP_ALLOW_PLAINTEXT_CREDENTIAL_STORAGE=true.
 *
 * Cross-reference: CODEX_REVIEW.md "Encryption Fails Open to Plaintext".
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const { TMP_ROOT } = vi.hoisted(() => {
  const _fs = require("node:fs") as typeof import("node:fs");
  const _os = require("node:os") as typeof import("node:os");
  const _path = require("node:path") as typeof import("node:path");
  return {
    TMP_ROOT: _fs.mkdtempSync(_path.join(_os.tmpdir(), "nlmcp-crypto-fail-closed-")),
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
    security: vi.fn().mockResolvedValue(undefined),
    auth: vi.fn().mockResolvedValue(undefined),
    session: vi.fn().mockResolvedValue(undefined),
    system: vi.fn().mockResolvedValue(undefined),
    tool: vi.fn().mockResolvedValue(undefined),
  },
}));

import { SecureStorage } from "../src/utils/crypto.js";

beforeEach(() => {
  delete process.env.NLMCP_ALLOW_PLAINTEXT_CREDENTIAL_STORAGE;
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
  fs.mkdirSync(TMP_ROOT, { recursive: true });
});

afterEach(() => {
  delete process.env.NLMCP_ALLOW_PLAINTEXT_CREDENTIAL_STORAGE;
});

describe("SecureStorage.save() fail-closed behaviour", () => {
  it("throws when encryption is disabled and plaintext is not opted in", async () => {
    const storage = new SecureStorage({
      enabled: false,
      useMachineKey: false,
      usePostQuantum: false,
    });

    const target = path.join(TMP_ROOT, "credentials.json");
    await expect(storage.save(target, { token: "secret-data" })).rejects.toThrow(
      /refusing to write plaintext/,
    );

    expect(fs.existsSync(target)).toBe(false);
  });

  it("permits plaintext when NLMCP_ALLOW_PLAINTEXT_CREDENTIAL_STORAGE=true", async () => {
    process.env.NLMCP_ALLOW_PLAINTEXT_CREDENTIAL_STORAGE = "true";

    const storage = new SecureStorage({
      enabled: false,
      useMachineKey: false,
      usePostQuantum: false,
    });

    const target = path.join(TMP_ROOT, "opted-in.json");
    await storage.save(target, { token: "secret-data" });

    expect(fs.existsSync(target)).toBe(true);
    const written = fs.readFileSync(target, "utf8");
    expect(written).toContain("secret-data");
  });

  it("does not throw when encryption is enabled and a key is available", async () => {
    // With useMachineKey=true the storage layer derives a key from
    // host identifiers; encryption proceeds normally.
    const storage = new SecureStorage({
      enabled: true,
      useMachineKey: true,
      usePostQuantum: false,
    });

    const target = path.join(TMP_ROOT, "encrypted.json");
    await storage.save(target, { token: "secret-data" });

    // The encrypted variant ends in .enc (or .pqenc when PQ is on).
    const wroteEncrypted = fs.existsSync(target + ".enc") || fs.existsSync(target + ".pqenc");
    expect(wroteEncrypted).toBe(true);

    // Plaintext path must NOT have been used.
    expect(fs.existsSync(target)).toBe(false);
  });

  it("audit-logs a security event when refusing to write plaintext", async () => {
    const storage = new SecureStorage({
      enabled: false,
      useMachineKey: false,
      usePostQuantum: false,
    });

    const auditModule = await import("../src/utils/audit-logger.js");
    const target = path.join(TMP_ROOT, "refused.json");
    await expect(storage.save(target, "x")).rejects.toThrow();

    expect(auditModule.audit.security).toHaveBeenCalledWith(
      "plaintext_save_refused",
      "error",
      expect.objectContaining({ reason: expect.any(String) }),
    );
  });
});
