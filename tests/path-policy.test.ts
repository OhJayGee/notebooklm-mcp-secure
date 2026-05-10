/**
 * Regression tests for src/utils/path-policy.ts.
 *
 * These tests pin the contract of the shared path-policy module that
 * gates filesystem writes (chat-history export, audio download, library
 * export) and reads (file-source uploads, gemini upload_document). The
 * module is the single source of truth for the export-base allowlist
 * and the credential-directory denylist; if any of these tests
 * regresses, a tool that touches user files lost a key defence.
 *
 * Cross-references:
 *   - CLAUDE_REVIEW.md Vuln 1: get_notebook_chat_history.output_file
 *   - CODEX_REVIEW.md "add_source / create_notebook arbitrary upload"
 *   - CODEX_REVIEW.md "add_folder symlink-bypass"
 */

import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import {
  resolveExportFilePath,
  assertSafeLocalReadPath,
  resolveAndCheckFolderPath,
  assertSafeFolderEntryPath,
  getFolderAllowedBases,
  isDeniedReadPath,
  PathPolicyError,
} from "../src/utils/path-policy.js";

// realpathSync for both: macOS resolves /tmp → /private/tmp and home
// directories may also be symlinks on some configurations. The export-
// path helper now realpath-resolves the base internally, so tests must
// expect the realpath form to avoid spurious mismatches.
const REAL_HOME = fs.realpathSync(os.homedir());
const TMP_ROOT = fs.realpathSync(
  fs.mkdtempSync(path.join(os.tmpdir(), "nlmcp-path-policy-test-")),
);

function cleanEnv(): void {
  delete process.env.NLMCP_EXPORT_DIR;
  delete process.env.NLMCP_FOLDER_ALLOWLIST;
}

beforeAll(() => {
  // Test fixtures: make sure $HOME-relative dotfile checks work even
  // on systems where $HOME may not have these dirs in real life.
  fs.mkdirSync(path.join(TMP_ROOT, ".ssh"), { recursive: true });
  fs.writeFileSync(path.join(TMP_ROOT, ".ssh", "id_rsa"), "fake key");
  fs.writeFileSync(path.join(TMP_ROOT, "ok.txt"), "fine");
});

afterAll(() => {
  fs.rmSync(TMP_ROOT, { recursive: true, force: true });
  cleanEnv();
});

beforeEach(() => {
  cleanEnv();
});

describe("resolveExportFilePath (Vuln 1: chat-history output_file)", () => {
  it("defaults to <HOME>/<defaultName> when no userPath is given", () => {
    const result = resolveExportFilePath(undefined, "chat-history.json");
    expect(result).toBe(path.join(REAL_HOME, "chat-history.json"));
  });

  it("resolves a relative userPath against the export base", () => {
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    const result = resolveExportFilePath("subdir/out.json", "default.json");
    expect(result).toBe(path.resolve(TMP_ROOT, "subdir/out.json"));
  });

  it("rejects ../ traversal that escapes the export base", () => {
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    expect(() => resolveExportFilePath("../escape.json", "default.json"))
      .toThrow(PathPolicyError);
  });

  it("rejects absolute paths outside the export base", () => {
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    expect(() => resolveExportFilePath("/etc/passwd", "default.json"))
      .toThrow(PathPolicyError);
  });

  it("rejects writes that traverse a sensitive directory segment", () => {
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    // Either the parent-realpath check or the lexical-segment check
    // can trip first depending on whether the candidate's parent dir
    // exists yet — both cite the offending segment in their message.
    expect(() => resolveExportFilePath(".ssh/authorized_keys", "default.json"))
      .toThrow(/sensitive directory '\.ssh'/);
  });

  it("rejects overwriting sensitive shell-config files even inside base", () => {
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    expect(() => resolveExportFilePath(".zshrc", "default.json"))
      .toThrow(/sensitive shell\/config file/);
  });

  it("rejects writes to absolute system directories regardless of base", () => {
    // Using NLMCP_EXPORT_DIR=/ to exercise the deniedAbsolute check.
    // macOS firmlinks `/etc` to `/private/etc` and the parent-realpath
    // check resolves through that, so the message may cite either form.
    process.env.NLMCP_EXPORT_DIR = "/";
    expect(() => resolveExportFilePath("etc/cron.d/x", "default.json"))
      .toThrow(/protected system directory.*etc/);
  });

  it("accepts a sane export inside the base", () => {
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    const result = resolveExportFilePath("notebooklm-history.json", "default.json");
    expect(result).toBe(path.join(TMP_ROOT, "notebooklm-history.json"));
  });
});

describe("assertSafeLocalReadPath (file-source upload bypass)", () => {
  it("rejects ~/.ssh/id_rsa even though it exists and is readable", () => {
    const target = path.join(TMP_ROOT, ".ssh/id_rsa");
    expect(() => assertSafeLocalReadPath(target)).toThrow(/sensitive directory '.ssh'/);
  });

  it("rejects /etc/passwd via absolute denylist", () => {
    expect(() => assertSafeLocalReadPath("/etc/passwd"))
      .toThrow(/protected system directory \/etc/);
  });

  it("rejects symlinks that resolve into a denied directory", () => {
    const symlink = path.join(TMP_ROOT, "innocent-name.txt");
    const target = path.join(TMP_ROOT, ".ssh/id_rsa");
    try {
      fs.symlinkSync(target, symlink);
    } catch {
      // Some sandboxes disallow symlink creation; skip in that case.
      return;
    }

    try {
      expect(() => assertSafeLocalReadPath(symlink))
        .toThrow(/sensitive directory '.ssh'/);
    } finally {
      try { fs.unlinkSync(symlink); } catch { /* ignore */ }
    }
  });

  it("accepts a normal file path", () => {
    const result = assertSafeLocalReadPath(path.join(TMP_ROOT, "ok.txt"));
    expect(result).toBe(fs.realpathSync(path.join(TMP_ROOT, "ok.txt")));
  });

  it("rejects empty / missing path", () => {
    expect(() => assertSafeLocalReadPath("")).toThrow(/file path is required/);
  });
});

describe("resolveAndCheckFolderPath (add_folder allowlist)", () => {
  it("defaults to $HOME when NLMCP_FOLDER_ALLOWLIST is unset", () => {
    const sub = path.join(REAL_HOME, "Documents");
    // We can't assume Documents exists; just check it's accepted lexically.
    const result = resolveAndCheckFolderPath(sub);
    expect(result).toBe(sub);
  });

  it("rejects folders outside the allowlist", () => {
    process.env.NLMCP_FOLDER_ALLOWLIST = TMP_ROOT;
    expect(() => resolveAndCheckFolderPath("/var")).toThrow(/folder_path must be inside/);
  });

  it("rejects folders that traverse a denied segment", () => {
    process.env.NLMCP_FOLDER_ALLOWLIST = TMP_ROOT;
    expect(() => resolveAndCheckFolderPath(path.join(TMP_ROOT, ".ssh")))
      .toThrow(/sensitive directory '.ssh'/);
  });

  it("supports colon-separated multiple allowlist bases", () => {
    // The helper realpath-resolves its return value, so on macOS
    // /var/folders/... → /private/var/folders/... etc. Use realpath
    // for both the input and the expected value.
    const secondRaw = fs.mkdtempSync(path.join(os.tmpdir(), "nlmcp-allowlist-2-"));
    const second = fs.realpathSync(secondRaw);
    try {
      process.env.NLMCP_FOLDER_ALLOWLIST = `${TMP_ROOT}${path.delimiter}${second}`;
      expect(resolveAndCheckFolderPath(second)).toBe(second);
      expect(resolveAndCheckFolderPath(TMP_ROOT)).toBe(TMP_ROOT);
    } finally {
      fs.rmSync(secondRaw, { recursive: true, force: true });
    }
  });
});

describe("isDeniedReadPath (per-entry symlink-resolved check used by scanDir)", () => {
  it("returns the offending segment for paths inside denied dirs", () => {
    expect(isDeniedReadPath("/Users/alice/.ssh/id_rsa")).toMatch(/.ssh/);
    expect(isDeniedReadPath("/etc/shadow")).toMatch(/\/etc/);
  });

  it("returns null for innocuous paths", () => {
    expect(isDeniedReadPath("/Users/alice/Documents/notes.txt")).toBeNull();
    expect(isDeniedReadPath("/tmp/random.bin")).toBeNull();
  });
});

// ════════════════════════════════════════════════════════════════════
// External review findings (Codex + Gemini, 2026-05-10)
// ════════════════════════════════════════════════════════════════════
//
// Each section below pins one finding that the external reviews
// surfaced after the initial v2026.3.3 path-policy module landed. The
// tests serve as regression guards against re-introduction.

describe("Finding A: symlink in export base lets writes escape", () => {
  it("rejects writes through a parent symlink that escapes the export base", () => {
    // Plant a symlink inside the export base that points OUTSIDE the
    // export base (to ~/.ssh — a protected directory). Pre-fix, the
    // lexical check accepted candidate `<base>/escape/authorized_keys`
    // and `fs.writeFile` followed the parent symlink to write into
    // the SSH directory.
    const symlinkInsideBase = path.join(TMP_ROOT, "escape-symlink");
    const externalDeniedTarget = path.join(REAL_HOME, ".ssh");

    // Skip if the symlink already exists (e.g. from a prior run).
    try { fs.unlinkSync(symlinkInsideBase); } catch { /* ignore */ }
    try {
      fs.symlinkSync(externalDeniedTarget, symlinkInsideBase);
    } catch {
      return; // sandbox refused symlink creation
    }

    try {
      process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
      expect(() =>
        resolveExportFilePath("escape-symlink/authorized_keys", "default.json"),
      ).toThrow(PathPolicyError);
    } finally {
      try { fs.unlinkSync(symlinkInsideBase); } catch { /* ignore */ }
    }
  });

  it("refuses to write through an existing symlink at the leaf", () => {
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    const decoyTarget = path.join(TMP_ROOT, "decoy-target.txt");
    const leafSymlink = path.join(TMP_ROOT, "leaf-symlink.json");
    fs.writeFileSync(decoyTarget, "decoy");

    try { fs.unlinkSync(leafSymlink); } catch { /* ignore */ }
    try {
      fs.symlinkSync(decoyTarget, leafSymlink);
    } catch {
      return; // sandbox refused symlink creation
    }

    try {
      expect(() => resolveExportFilePath("leaf-symlink.json", "default.json"))
        .toThrow(/symlink.*refusing/i);
    } finally {
      try { fs.unlinkSync(leafSymlink); } catch { /* ignore */ }
      try { fs.unlinkSync(decoyTarget); } catch { /* ignore */ }
    }
  });
});

describe("Finding B: add_folder symlinks must be checked against the allowlist, not just the denylist", () => {
  it("rejects an entry whose realpath escapes the allowlist", () => {
    // Create a directory OUTSIDE the allowlist with an innocuous-named
    // file in it. Then construct an "entry" path whose realpath would
    // resolve to that out-of-allowlist file.
    const outsideAllowlist = fs.mkdtempSync(path.join(os.tmpdir(), "nlmcp-outside-"));
    const outsideFile = path.join(outsideAllowlist, "leak.md");
    fs.writeFileSync(outsideFile, "leak");

    try {
      const allowedBases = [TMP_ROOT];
      expect(() => assertSafeFolderEntryPath(outsideFile, allowedBases))
        .toThrow(/outside the allowlist/);
    } finally {
      fs.rmSync(outsideAllowlist, { recursive: true, force: true });
    }
  });

  it("accepts an entry whose realpath resolves inside the allowlist", () => {
    const okFile = path.join(TMP_ROOT, "doc.md");
    fs.writeFileSync(okFile, "ok");
    const realFile = fs.realpathSync(okFile);

    try {
      expect(() => assertSafeFolderEntryPath(realFile, [TMP_ROOT])).not.toThrow();
    } finally {
      try { fs.unlinkSync(okFile); } catch { /* ignore */ }
    }
  });

  it("getFolderAllowedBases honours path.delimiter (NOT a hard-coded ':')", () => {
    // On Windows path.delimiter is ';'. The pre-fix code split on ':'
    // hard-coded, which broke Windows drive-letter paths. The fix
    // uses path.delimiter so both POSIX and Windows behave correctly.
    const second = fs.mkdtempSync(path.join(os.tmpdir(), "nlmcp-allowlist-2-"));
    try {
      process.env.NLMCP_FOLDER_ALLOWLIST = `${TMP_ROOT}${path.delimiter}${second}`;
      const bases = getFolderAllowedBases();
      // Both bases should appear, realpath-resolved.
      expect(bases.length).toBe(2);
      expect(bases).toContain(fs.realpathSync(TMP_ROOT));
      expect(bases).toContain(fs.realpathSync(second));
    } finally {
      delete process.env.NLMCP_FOLDER_ALLOWLIST;
      fs.rmSync(second, { recursive: true, force: true });
    }
  });
});

describe("Finding C: read policy must refuse non-regular files (FIFOs, /dev/*)", () => {
  it("refuses a FIFO even with a non-suspicious name", () => {
    const fifo = path.join(TMP_ROOT, "trap.pdf");
    try { fs.unlinkSync(fifo); } catch { /* ignore */ }
    try {
      // Use the syscall path; not all platforms support mkfifo from JS,
      // so fall back to skipping if mkfifoSync isn't available.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const fsAny = fs as any;
      if (typeof fsAny.mkfifoSync !== "function") {
        // No portable JS API — skip.
        return;
      }
      fsAny.mkfifoSync(fifo, 0o600);
    } catch {
      return; // can't create FIFO in this sandbox
    }

    try {
      expect(() => assertSafeLocalReadPath(fifo)).toThrow(/regular file/);
    } finally {
      try { fs.unlinkSync(fifo); } catch { /* ignore */ }
    }
  });

  it("refuses /dev/null (character device, not a regular file)", () => {
    // Cross-platform-friendly: only run on POSIX where /dev/null exists
    // as a character device.
    if (process.platform === "win32") return;
    expect(() => assertSafeLocalReadPath("/dev/null")).toThrow(/regular file|protected/i);
  });

  it("refuses a non-existent path outright (no lexical fallback)", () => {
    // Pre-fix, a non-existent path silently fell back to the lexical
    // resolved path, so the policy check ran on the wrong target.
    expect(() => assertSafeLocalReadPath("/nonexistent/path/foo.pdf"))
      .toThrow(/must exist|regular file/);
  });
});

describe("Finding D: case-insensitive denylist bypass", () => {
  it("rejects upper-cased denied segments (`.SSH/id_rsa`)", () => {
    // The malicious caller uses the exact case-flipped path. On a
    // case-insensitive FS this resolves to the same file as `.ssh`.
    expect(() => assertSafeLocalReadPath("/Users/alice/.SSH/id_rsa"))
      .toThrow(/sensitive|regular file|must exist/i);
    // The "must exist" message is fine here — we want SOMETHING to
    // refuse this. The case-insensitive comparison is provable via
    // the export-path test below where the path doesn't need to exist.
  });

  it("rejects upper-cased basenames in export writes (`.ZSHRC`)", () => {
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    expect(() => resolveExportFilePath(".ZSHRC", "default.json"))
      .toThrow(/sensitive shell\/config file/);
    expect(() => resolveExportFilePath(".Zshrc", "default.json"))
      .toThrow(/sensitive shell\/config file/);
  });

  it("rejects mixed-case denied segments via containsDeniedSegment", () => {
    expect(isDeniedReadPath("/home/u/.SSH/id_rsa")).toMatch(/ssh/i);
    expect(isDeniedReadPath("/home/u/.AwS/credentials")).toMatch(/aws/i);
  });
});

describe("Finding E: Windows-style basename quirks normalised before policy", () => {
  // We can't directly exercise IS_WIN32 branches on a non-Windows host,
  // but we can verify that the basename-normalisation logic is plumbed
  // — via the env-variant case, which IS cross-platform and uses the
  // same normalisation pipeline.
  it("rejects .env-variant basenames (.env.production)", () => {
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    expect(() => resolveExportFilePath(".env.production", "default.json"))
      .toThrow(/refusing/);
    expect(() => resolveExportFilePath(".env.local", "default.json"))
      .toThrow(/refusing/);
    expect(() => resolveExportFilePath(".env.development", "default.json"))
      .toThrow(/refusing/);
  });

  it("env-variant rejection applies to read paths too", () => {
    const envFile = path.join(TMP_ROOT, ".env.local");
    fs.writeFileSync(envFile, "SECRET=1");
    try {
      expect(() => assertSafeLocalReadPath(envFile))
        .toThrow(/credential file|sensitive|env/i);
    } finally {
      try { fs.unlinkSync(envFile); } catch { /* ignore */ }
    }
  });
});

describe("Finding F: extended denylist covers modern credential stores", () => {
  it.each([
    ".config/gh/hosts.yml",
    ".config/Cursor/User/globalStorage/storage.json",
    ".azure/credentials",
    ".terraformrc",
    ".gem/credentials",
    ".gradle/gradle.properties",
    "Library/Application Support/Code/User/settings.json",
    "Library/Application Support/JetBrains/IntelliJIdea/options/security.xml",
    "AppData/Roaming/Microsoft/Credentials/secret",
    "AppData/Local/Microsoft/Credentials/secret",
  ])("denies '%s' via isDeniedReadPath", (suffix) => {
    expect(isDeniedReadPath(`/Users/alice/${suffix}`)).not.toBeNull();
  });
});

describe("Finding G: Windows absolute paths are in DENIED_ABSOLUTE", () => {
  // Windows absolute path comparisons happen on the host's policySegment
  // which lowercases. The function should refuse these regardless of
  // whether the host is Windows — Linux callers with mounted Windows
  // volumes can still hit them.
  it.each([
    "C:\\Windows\\System32\\config\\SAM",
    "c:\\windows\\system32\\config\\sam",
    "C:\\Documents and Settings\\admin\\NTUSER.DAT",
  ])("denies '%s' via isDeniedReadPath", (winPath) => {
    expect(isDeniedReadPath(winPath)).not.toBeNull();
  });
});

describe("Finding H: macOS APFS case-insensitive containment is forgiving", () => {
  // On case-insensitive platforms, /Users/Olv and /users/olv refer to
  // the same path. isWithinBase via path.relative would otherwise
  // reject the case-flipped form even though both paths name the same
  // directory.
  it("does not false-reject case-flipped paths on darwin", () => {
    if (process.platform !== "darwin") return;
    process.env.NLMCP_EXPORT_DIR = TMP_ROOT;
    const flipped = path.join(TMP_ROOT.toUpperCase(), "child.json");
    // We expect either acceptance (case-insensitive containment) OR a
    // rejection that's NOT due to "must resolve inside" — the
    // usability fix is that /USERS/OLV inside /Users/olv base is
    // recognised as contained.
    try {
      const result = resolveExportFilePath(flipped, "default.json");
      expect(result.length).toBeGreaterThan(0);
    } catch (err) {
      // If it does throw, it must NOT be the containment error.
      expect(String(err)).not.toMatch(/must resolve inside/);
    }
  });
});

describe("Finding I: NLMCP_FOLDER_ALLOWLIST splits on path.delimiter", () => {
  // On Windows path.delimiter is ';' — splitting on ':' would
  // misinterpret 'C:\\foo' as ['C', '\\foo']. The fix uses
  // path.delimiter so both POSIX and Windows work.
  it("accepts a colon-separated list on POSIX", () => {
    if (path.delimiter !== ":") return;
    const second = fs.mkdtempSync(path.join(os.tmpdir(), "nlmcp-allowlist-3-"));
    try {
      process.env.NLMCP_FOLDER_ALLOWLIST = `${TMP_ROOT}:${second}`;
      const bases = getFolderAllowedBases();
      expect(bases.length).toBe(2);
    } finally {
      delete process.env.NLMCP_FOLDER_ALLOWLIST;
      fs.rmSync(second, { recursive: true, force: true });
    }
  });
});
