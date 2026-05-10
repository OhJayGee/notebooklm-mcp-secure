# Path Policy Security Audit Findings

This document summarizes the findings from a security review of `src/utils/path-policy.ts`, focusing on path traversal, bypasses, and cross-OS robustness.

---

## 1. Case-insensitive denylist bypass on macOS and Windows

**Summary** — Path validation uses literal string equality for sensitive segments and basenames, allowing attackers to bypass the denylist on case-insensitive filesystems (macOS and Windows) by varying the casing.

**Location** — `src/utils/path-policy.ts`: `containsDeniedSegment` (line 86) and `resolveExportFilePath` basename check (line 151).

**Reproduction** — An agent tool call with `file_path: ".SSH/id_rsa"` (via `upload_document`) or `output_file: ".ZSHRC"` (via `get_notebook_chat_history`) will bypass the denylist on macOS and Windows, as `.SSH` does not strictly equal `.ssh`.

**Severity** — **High** (Confidence: 10/10)

**Suggested change** — Normalize segments and basenames to lowercase before comparison. Additionally, normalize Unicode to NFC to prevent normalization-form bypasses.

```typescript
function containsDeniedSegment(resolved: string): string | null {
  const normalized = resolved.normalize("NFC").toLowerCase();
  const segments = normalized.split(path.sep);
  for (const denied of DENIED_SEGMENTS) {
    const parts = denied.toLowerCase().split("/");
    for (let i = 0; i <= segments.length - parts.length; i++) {
      if (parts.every((p, j) => segments[i + j] === p)) {
        return denied;
      }
    }
  }
  return null;
}
```

---

## 2. Windows absolute path bypass and missing system denylist

**Summary** — `isInDeniedAbsolute` uses hardcoded Unix-style paths starting with `/`, which fail to match any absolute path on Windows (e.g., `C:\...`), and the module lacks a denylist for sensitive Windows system directories.

**Location** — `src/utils/path-policy.ts`: `DENIED_ABSOLUTE` (line 59) and `isInDeniedAbsolute` (line 98).

**Reproduction** — `assertSafeLocalReadPath("C:\\Windows\\System32\\config\\SAM")` is accepted because it does not match any prefix in the Unix-centric `DENIED_ABSOLUTE` list.

**Severity** — **High** (Confidence: 10/10)

**Suggested change** — Use `path.resolve` on all denylist entries at startup to ensure they match the host OS format, and add Windows-specific sensitive paths.

```typescript
const DENIED_ABSOLUTE: readonly string[] = [
  "/etc", "/root", "/proc", "/sys", "/private/etc",
  "C:\\Windows\\System32\\config",
  "C:\\Windows\\System32\\drivers\\etc\\hosts",
  "C:\\Documents and Settings",
].map(p => path.resolve(p)); // Pre-resolve to match platform semantics (C:\ vs /)
```

---

## 3. Windows basename quirks bypass (Trailing dots, Alt-Streams, Reserved names)

**Summary** — The basename check for forbidden write paths is bypassed by NTFS-specific quirks such as trailing dots/spaces, Alternative Data Streams (e.g., `:secret`), or reserved device names (e.g., `CON`).

**Location** — `src/utils/path-policy.ts`: `resolveExportFilePath` (lines 150–154).

**Reproduction** — `resolveExportFilePath(".zshrc.", "default.json")` or `resolveExportFilePath(".zshrc:hidden", "default.json")` on Windows will bypass the `.zshrc` block but successfully write to the sensitive file or its stream.

**Severity** — **Medium** (Confidence: 10/10)

**Suggested change** — Strip NTFS-specific suffixes and check against a list of Windows reserved names before the basename comparison.

```typescript
  const rawBasename = path.basename(candidate);
  // Strip Windows Alt-Streams (:stream) and trailing dots/spaces
  const normalizedBasename = rawBasename.split(":")[0].replace(/[.\s]+$/, "").toLowerCase();
  
  const isReserved = ["CON", "PRN", "AUX", "NUL", "COM1", "LPT1"].includes(normalizedBasename.toUpperCase());
  if (isReserved || DENIED_WRITE_BASENAMES.some(d => d.toLowerCase() === normalizedBasename)) {
    throw new PathPolicyError(`output_path uses a protected or reserved name '${rawBasename}'`);
  }
```

---

## 4. Incomplete denylist for modern dev tools and `.env` variants

**Summary** — The `DENIED_SEGMENTS` list is missing several critical credential locations for modern tools (GitHub CLI, Stripe, Azure) and IDEs (Cursor, VS Code Insiders), and only blocks `.env` exactly, missing common variants.

**Location** — `src/utils/path-policy.ts`: `DENIED_SEGMENTS` (line 36).

**Reproduction** — `assertSafeLocalReadPath("~/.config/Cursor/User/globalStorage/storage.json")` or `assertSafeLocalReadPath(".env.production")` are currently accepted.

**Severity** — **Medium** (Confidence: 10/10)

**Suggested change** — Expand `DENIED_SEGMENTS` with the following entries and ensure `.env` matches are performed as prefixes where appropriate:

```typescript
  ".config/gh", ".config/stripe", ".config/Cursor", ".config/Code - Insiders",
  "Library/Application Support/Cursor", "Library/Application Support/Code",
  "AppData/Roaming/Cursor", "AppData/Roaming/Code", ".azure",
  ".gem/credentials", ".terraformrc", "application_default_credentials.json"
```

---

## 5. Usability: `isWithinBase` false-rejections on macOS

**Summary** — `path.relative` on macOS is case-sensitive, which causes `isWithinBase` to incorrectly reject valid paths that reside within the base directory but have mismatched casing in the user environment or input.

**Location** — `src/utils/path-policy.ts`: `isWithinBase` (line 109).

**Reproduction** — If `os.homedir()` returns `/Users/olv` but the user provides `/users/olv/file.txt`, `path.relative` returns `../../users/olv/file.txt` on macOS, triggering a "must resolve inside" error.

**Severity** — **Low** (Confidence: 8/10)

**Suggested change** — When `os.platform() === 'darwin'`, perform the `isWithinBase` check using lowercased paths to match APFS behavior.
