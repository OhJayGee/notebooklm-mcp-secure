/**
 * Shared filesystem-path policy helpers.
 *
 * Centralises three primitives so all tool handlers apply consistent
 * containment / denylist rules:
 *
 *   1. resolveExportFilePath  — outbound writes (chat history export,
 *      library export, audio download). Confines to NLMCP_EXPORT_DIR
 *      (or the user's home directory by default), realpath-resolves the
 *      parent so a symlink inside the base cannot escape, and refuses
 *      to write through an existing symlink leaf.
 *
 *   2. assertSafeLocalReadPath — inbound reads (single-file source
 *      upload, gemini Files API upload). Allows any path the user
 *      could plausibly intend to share with NotebookLM/Gemini, but
 *      refuses sensitive credential/config locations and refuses
 *      anything that isn't a regular file (FIFOs, /dev/* devices,
 *      sockets, character devices).
 *
 *   3. resolveAndCheckFolderPath / assertSafeFolderEntryPath — multi-
 *      file scan path used by add_folder. Allowlist + denylist; same
 *      denylist as the read helper above, kept in one place so other
 *      upload paths (add_source, create_notebook) cannot bypass it.
 *      Per-entry allowlist enforcement guards against symlinks that
 *      escape the allowed roots even when they point at non-denied
 *      targets.
 *
 * All three share one denylist so a future addition (e.g. ~/.config/op
 * for 1Password) updates every callsite at once.
 */

import path from "path";
import os from "os";
import fs from "fs";

/**
 * Sensitive path segments that should never be read by file-source uploads
 * or written by tool-controlled exports. Matched against any consecutive
 * sequence of path segments in the resolved path, after NFC + casefold
 * normalisation.
 *
 * Format: forward-slash separated; multi-segment denylist entries are
 * split and matched element-by-element so "Library/Application Support"
 * works on macOS the same way ".config/gcloud" works on Linux.
 *
 * Segments are lowercased here at the source so the comparison loop in
 * `containsDeniedSegment` only has to lowercase the haystack.
 */
const DENIED_SEGMENTS_RAW: readonly string[] = [
  // SSH / GPG / cloud
  ".ssh",
  ".aws",
  ".azure",
  ".gnupg",
  ".gpg",
  ".docker",
  ".kube",
  ".config/gcloud",
  ".config/op",
  // Git / GitHub / GitLab
  ".config/git",
  ".config/gh",
  ".config/hub",
  ".github_token",
  ".gitlab-runner",
  // Stripe / Terraform / language tooling
  ".config/stripe",
  ".terraformrc",
  ".cargo/credentials",
  ".cargo/credentials.toml",
  ".gem/credentials",
  ".gradle/gradle.properties",
  // Standard credential / dotfile leaks
  ".netrc",
  ".npmrc",
  ".pypirc",
  ".env",
  ".envrc",
  // ADC token (gcloud's "application default credentials")
  "application_default_credentials.json",
  // MCP registry tokens
  ".mcpregistry_github_token",
  ".mcpregistry_registry_token",
  // Browser stores (macOS)
  "Library/Application Support/Google/Chrome",
  "Library/Application Support/Firefox",
  // IDE / editor secret stores (macOS)
  "Library/Application Support/Code",
  "Library/Application Support/Code - Insiders",
  "Library/Application Support/Cursor",
  "Library/Application Support/JetBrains",
  // Same on Linux
  ".config/Code",
  ".config/Code - Insiders",
  ".config/Code/User",
  ".config/Cursor",
  ".config/JetBrains",
  // Same on Windows
  "AppData/Roaming/Code",
  "AppData/Roaming/Code - Insiders",
  "AppData/Roaming/Code/User",
  "AppData/Roaming/Cursor",
  "AppData/Roaming/JetBrains",
  // Windows credential stores
  "AppData/Roaming/Microsoft/Credentials",
  "AppData/Local/Microsoft/Credentials",
];
const DENIED_SEGMENTS: readonly string[] = DENIED_SEGMENTS_RAW.map((s) =>
  s.toLowerCase(),
);

/**
 * Absolute directories that must never be read or written even with an
 * explicit caller-supplied path. Stored lowercased; comparison is
 * lowercase-on-lowercase. Each entry is matched as a path-segment
 * prefix, so `/etc/passwd` matches `/etc` but `/etcetera` does not.
 *
 * Both Unix and Windows entries live here because non-matching entries
 * on a given platform harmlessly fail to match and the alternative —
 * branching on platform — is a foot-gun if anyone forgets a branch.
 */
const DENIED_ABSOLUTE_RAW: readonly string[] = [
  // Unix
  "/etc",
  "/root",
  "/proc",
  "/sys",
  "/var/log",
  "/var/lib/sudo",
  "/dev",
  "/run",
  "/var/run",
  "/private/etc",
  "/private/var/log",
  // Windows
  "C:\\Windows\\System32\\config",
  "C:\\Windows\\System32\\drivers\\etc",
  "C:\\Windows\\repair",
  "C:\\Windows\\security",
  "C:\\Documents and Settings",
];
const DENIED_ABSOLUTE: readonly string[] = DENIED_ABSOLUTE_RAW.map((s) =>
  s.toLowerCase(),
);

/**
 * Dotfile basenames that are commonly overwritten as a privilege-pivot
 * primitive (`fs.writeFile($HOME/.bashrc, payload)` style attacks).
 * Only applied to write paths, not read paths — reading these is also
 * blocked by DENIED_SEGMENTS but writing them is the sharper risk.
 *
 * Stored lowercased; comparison is lowercase-on-lowercase.
 */
const DENIED_WRITE_BASENAMES: readonly string[] = [
  ".bashrc",
  ".bash_profile",
  ".bash_logout",
  ".zshrc",
  ".zshenv",
  ".zprofile",
  ".zlogin",
  ".profile",
  ".inputrc",
  ".tmux.conf",
  ".vimrc",
  ".gitconfig",
  ".gitattributes",
  ".gitignore_global",
  ".npmrc",
  ".pypirc",
  ".netrc",
  ".env",
  ".envrc",
];

/**
 * Windows reserved device names. NTFS treats `CON`, `PRN`, `AUX`,
 * `NUL`, and the numbered COMx / LPTx series specially regardless of
 * extension; trying to write `CON.txt` does not write a file. These
 * are dangerous because they can be used to confuse callers about
 * whether the write succeeded, or to consume input/output devices.
 */
const WINDOWS_RESERVED_BASENAMES: ReadonlySet<string> = new Set([
  "con", "prn", "aux", "nul",
  "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
  "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
]);

const IS_WIN32 = process.platform === "win32";
const IS_DARWIN = process.platform === "darwin";

/**
 * macOS APFS and Windows NTFS are case-insensitive by default; Linux
 * ext4 is case-sensitive. We use this to decide whether to lowercase
 * paths before comparing them against the denylist / containment base.
 *
 * Note: the policy comparison ALWAYS lowercases the denylist itself so
 * a malicious `.SSH/id_rsa` is caught on every platform. The platform
 * branch only affects `isWithinBase`, where a literal case mismatch on
 * Linux ext4 should be a real "not contained" decision (someone really
 * has two different directories) but on macOS / Windows is a
 * usability false-rejection.
 */
function isCaseInsensitivePlatform(): boolean {
  return IS_DARWIN || IS_WIN32;
}

/**
 * Normalise a path segment for policy comparison: NFC Unicode form
 * (handles `é` vs `é` style attacks), lowercased (so
 * `.SSH` ≡ `.ssh` everywhere), and on Windows the trailing dots /
 * spaces that NTFS strips at the filesystem layer are stripped here
 * too — `.zshrc.` and `.zshrc ` would otherwise both reach `.zshrc`
 * as the actual write target while bypassing the literal denylist
 * check.
 */
function policySegment(s: string): string {
  let out = s.normalize("NFC").toLowerCase();
  if (IS_WIN32) {
    // NTFS quirk: trailing dots and spaces are stripped at write.
    out = out.replace(/[. ]+$/u, "");
  }
  return out;
}

/**
 * Normalise a basename for policy comparison. Same as policySegment
 * plus: on Windows, anything after a `:` is an Alternate Data Stream
 * specifier; the underlying file is the part before the colon. So
 * `.zshrc:hidden` writes to `.zshrc`'s default stream from the policy
 * point of view.
 */
function policyBasename(s: string): string {
  let out = s;
  if (IS_WIN32 && out.includes(":")) {
    out = out.split(":")[0];
  }
  return policySegment(out);
}

/**
 * `.env`, `.env.local`, `.env.production`, `.env.development`, etc.
 * are all credential files in modern app conventions. Match anything
 * that starts with `.env` followed by either nothing or a dot.
 */
function isEnvVariantBasename(name: string): boolean {
  const normalized = policyBasename(name);
  return /^\.env(\..+)?$/.test(normalized);
}

function splitForPolicy(p: string): string[] {
  // Split on BOTH separators so a Windows-style path passed on macOS
  // still gets its segments compared correctly.
  return p.split(/[\\/]/).map((s) => policySegment(s));
}

function containsDeniedSegment(resolved: string): string | null {
  const segments = splitForPolicy(resolved);
  for (const denied of DENIED_SEGMENTS) {
    const parts = denied.split("/");
    for (let i = 0; i <= segments.length - parts.length; i++) {
      if (parts.every((p, j) => segments[i + j] === p)) {
        return denied;
      }
    }
  }
  return null;
}

function isInDeniedAbsolute(resolved: string): string | null {
  const norm = policySegment(resolved);
  for (const denied of DENIED_ABSOLUTE) {
    // Match either an exact directory or a path strictly inside it.
    // Both `/` and `\` are valid separators on Windows; also accept
    // either as a child-path divider for cross-platform robustness.
    if (norm === denied) return denied;
    if (norm.startsWith(denied + "/")) return denied;
    if (norm.startsWith(denied + "\\")) return denied;
  }
  return null;
}

/**
 * Containment check. On case-insensitive platforms we lowercase both
 * sides so `/Users/olv/...` and `/users/olv/...` both validate against
 * a `/Users/olv` base. On case-sensitive platforms (Linux ext4) we
 * preserve case because two different cased paths really are two
 * different directories.
 */
function isWithinBase(resolved: string, base: string): boolean {
  const a = isCaseInsensitivePlatform() ? resolved.toLowerCase() : resolved;
  const b = isCaseInsensitivePlatform() ? base.toLowerCase() : base;
  const rel = path.relative(b, a);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function getExportBase(): string {
  const envDir = process.env.NLMCP_EXPORT_DIR?.trim();
  return path.resolve(envDir && envDir.length > 0 ? envDir : os.homedir());
}

export class PathPolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PathPolicyError";
  }
}

/**
 * Resolve and validate an export (write) path. Caller may pass undefined
 * to default to `<base>/<defaultName>`.
 *
 * Hardening over the lexical-only check:
 *   - The export base is realpath-resolved before containment, so a
 *     symlinked `NLMCP_EXPORT_DIR` is interpreted by its target.
 *   - The candidate's parent directory is realpath-resolved and re-
 *     checked for containment + denylist. This blocks the case where
 *     a symlink inside the base points at e.g. `~/.ssh` and an
 *     innocent-looking relative path writes through it.
 *   - If the candidate file already exists as a symlink, the call
 *     refuses. We never write through a symlink at the leaf — the
 *     attacker plants the symlink, we write through it to the target.
 *   - Windows reserved device basenames (CON, PRN, NUL, …) are refused.
 *   - Alternate Data Stream specifiers (`:stream`) and trailing
 *     dot/space NTFS quirks are normalised before the basename check.
 *
 * Throws PathPolicyError on rejection. Returns the absolute resolved
 * path on success.
 */
export function resolveExportFilePath(
  userPath: string | undefined,
  defaultName: string,
): string {
  const baseLexical = getExportBase();
  let realBase: string;
  try {
    realBase = fs.realpathSync(baseLexical);
  } catch {
    // If the base doesn't exist yet, fall back to the lexical path.
    // Caller is responsible for creating the base before writing —
    // the writer code paths all do this already.
    realBase = baseLexical;
  }

  const candidate = userPath && userPath.trim().length > 0
    ? path.resolve(realBase, userPath)
    : path.resolve(realBase, defaultName);

  if (!isWithinBase(candidate, realBase)) {
    throw new PathPolicyError(
      `output_path must resolve inside ${realBase} (got '${candidate}'). ` +
      `Set NLMCP_EXPORT_DIR to allow another base directory.`,
    );
  }

  // Realpath-check the parent directory so a symlinked subdir cannot
  // tunnel writes outside the base. Walk the chain progressively in
  // case the parent itself does not exist yet.
  let realParent: string | null = null;
  for (
    let probe = path.dirname(candidate);
    probe && probe !== path.dirname(probe);
    probe = path.dirname(probe)
  ) {
    try {
      realParent = fs.realpathSync(probe);
      break;
    } catch {
      continue;
    }
  }
  if (realParent && !isWithinBase(realParent, realBase)) {
    throw new PathPolicyError(
      `output_path parent resolves outside the export base (real parent: ${realParent}); refusing to write.`,
    );
  }
  if (realParent && isInDeniedAbsolute(realParent)) {
    throw new PathPolicyError(
      `output_path parent resolves into a protected system directory (${realParent}); refusing to write.`,
    );
  }
  const parentDeniedSegment = realParent ? containsDeniedSegment(realParent) : null;
  if (parentDeniedSegment) {
    throw new PathPolicyError(
      `output_path parent traverses sensitive directory '${parentDeniedSegment}'; refusing to write.`,
    );
  }

  // If the candidate already exists, refuse to write through a symlink.
  try {
    const lst = fs.lstatSync(candidate);
    if (lst.isSymbolicLink()) {
      throw new PathPolicyError(
        `output_path '${candidate}' is a symlink; refusing to write through it.`,
      );
    }
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code !== "ENOENT" && !(err instanceof PathPolicyError)) {
      throw err;
    }
    if (err instanceof PathPolicyError) throw err;
    // ENOENT = doesn't exist yet, which is fine.
  }

  // Lexical denylist checks (unchanged in spirit, normalised for
  // case-insensitive filesystems and Windows quirks).
  const deniedAbs = isInDeniedAbsolute(candidate);
  if (deniedAbs) {
    throw new PathPolicyError(
      `output_path is inside protected system directory ${deniedAbs}; refusing to write.`,
    );
  }

  const deniedSeg = containsDeniedSegment(candidate);
  if (deniedSeg) {
    throw new PathPolicyError(
      `output_path traverses sensitive directory '${deniedSeg}'; refusing to write.`,
    );
  }

  const rawBasename = path.basename(candidate);
  const normalizedBasename = policyBasename(rawBasename);

  if (IS_WIN32 && WINDOWS_RESERVED_BASENAMES.has(normalizedBasename.replace(/\..*$/, ""))) {
    throw new PathPolicyError(
      `output_path uses a Windows reserved device name '${rawBasename}'; refusing to write.`,
    );
  }

  if (
    DENIED_WRITE_BASENAMES.includes(normalizedBasename) ||
    isEnvVariantBasename(rawBasename)
  ) {
    throw new PathPolicyError(
      `output_path overwrites a sensitive shell/config file '${rawBasename}'; refusing to write.`,
    );
  }

  return candidate;
}

/**
 * Validate a single-file path that the caller wants the server to read
 * and forward to a third party (NotebookLM source upload, Gemini Files
 * API upload). Returns the absolute resolved path; throws on rejection.
 *
 * Hardening:
 *   - The path must exist and resolve (via realpath) to a regular file.
 *     FIFOs, character devices, block devices, and sockets are all
 *     refused — they are not "documents" in any meaningful sense and
 *     reading from `/dev/zero` or `/dev/random` causes denial-of-
 *     service or entropy consumption.
 *   - Symlink resolution applies before the denylist check, so a
 *     symlink pointing at e.g. ~/.ssh/id_rsa cannot bypass the segment
 *     check by hiding inside an otherwise-innocent path.
 */
export function assertSafeLocalReadPath(userPath: string): string {
  if (!userPath || userPath.trim().length === 0) {
    throw new PathPolicyError("file path is required");
  }

  const resolved = path.resolve(userPath);

  // Refuse non-existent paths outright. Falling back to the lexical
  // path is unsafe because it lets the caller bypass realpath-based
  // denylist checks for a path that the underlying upload layer
  // would have read by following the symlink anyway.
  let realPath: string;
  try {
    realPath = fs.realpathSync(resolved);
  } catch {
    throw new PathPolicyError(
      `file path must exist and resolve to a regular file (got '${userPath}')`,
    );
  }

  // Must be a regular file. lstat would let symlinks through; we want
  // stat (follow) here because we already realpath-resolved.
  let st: fs.Stats;
  try {
    st = fs.statSync(realPath);
  } catch (err) {
    throw new PathPolicyError(
      `file path could not be stat'd: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
  if (!st.isFile()) {
    throw new PathPolicyError(
      `file path must be a regular file (got '${realPath}', mode 0o${st.mode.toString(8)})`,
    );
  }

  for (const candidate of new Set([resolved, realPath])) {
    const deniedAbs = isInDeniedAbsolute(candidate);
    if (deniedAbs) {
      throw new PathPolicyError(
        `file path is inside protected system directory ${deniedAbs}; refusing to read.`,
      );
    }
    const deniedSeg = containsDeniedSegment(candidate);
    if (deniedSeg) {
      throw new PathPolicyError(
        `file path traverses sensitive directory '${deniedSeg}'; refusing to read.`,
      );
    }
    const baseSeg = path.basename(candidate);
    if (isEnvVariantBasename(baseSeg)) {
      throw new PathPolicyError(
        `file path is an .env-style credential file '${baseSeg}'; refusing to read.`,
      );
    }
  }

  return realPath;
}

/**
 * Resolve a folder path and check it against the allowlist + denylist.
 * The user-supplied folder is realpath-resolved up front so a symlink
 * at the root cannot escape the allowlist.
 *
 * Used by `add_folder` for the initial entry point. Per-entry checks
 * during recursive scan use `assertSafeFolderEntryPath` below.
 */
export function resolveAndCheckFolderPath(userPath: string): string {
  if (!userPath || userPath.trim().length === 0) {
    throw new PathPolicyError("folder_path is required");
  }

  const resolved = path.resolve(userPath);
  let realResolved: string;
  try {
    realResolved = fs.realpathSync(resolved);
  } catch {
    // If the folder doesn't exist, the lexical check still gates entry —
    // the caller's later `fs.stat` will surface the ENOENT.
    realResolved = resolved;
  }

  const allowedBases = getFolderAllowedBases();
  if (!allowedBases.some((base) => isWithinBase(realResolved, base))) {
    throw new PathPolicyError(
      `folder_path must be inside one of: ${allowedBases.join(", ")}. ` +
      `Set NLMCP_FOLDER_ALLOWLIST to extend the list.`,
    );
  }

  const deniedAbs = isInDeniedAbsolute(realResolved);
  if (deniedAbs) {
    throw new PathPolicyError(
      `folder_path is inside protected system directory ${deniedAbs}; refusing to read.`,
    );
  }
  const deniedSeg = containsDeniedSegment(realResolved);
  if (deniedSeg) {
    throw new PathPolicyError(
      `folder_path traverses sensitive directory '${deniedSeg}'; refusing to read.`,
    );
  }

  return realResolved;
}

/**
 * Per-entry policy enforcement for `add_folder`'s recursive scan.
 *
 * The recursive scan resolves each entry via `fs.realpath` and then
 * calls this function with the resolved path AND the allowlist bases
 * it was given for the top-level scan. Both checks must pass: the
 * realpath must (a) resolve inside one of the allowed roots, AND (b)
 * not cross a denied segment.
 *
 * Without (a), a symlink inside an allowed folder pointing at
 * /tmp/outside/leak.md would be uploaded — the denylist alone does
 * not forbid /tmp/outside.
 */
export function assertSafeFolderEntryPath(
  realTarget: string,
  allowedBases: readonly string[],
): void {
  if (!allowedBases.some((base) => isWithinBase(realTarget, base))) {
    throw new PathPolicyError(
      `folder entry resolves outside the allowlist (target: ${realTarget})`,
    );
  }
  const deniedAbs = isInDeniedAbsolute(realTarget);
  if (deniedAbs) {
    throw new PathPolicyError(
      `folder entry resolves into protected system directory ${deniedAbs}`,
    );
  }
  const deniedSeg = containsDeniedSegment(realTarget);
  if (deniedSeg) {
    throw new PathPolicyError(
      `folder entry resolves into sensitive directory '${deniedSeg}'`,
    );
  }
  if (isEnvVariantBasename(path.basename(realTarget))) {
    throw new PathPolicyError(
      `folder entry resolves to an .env-style credential file: ${path.basename(realTarget)}`,
    );
  }
}

/**
 * Return the list of realpath-resolved allowed folder bases for
 * `add_folder`. Splits NLMCP_FOLDER_ALLOWLIST on `path.delimiter`
 * (`:` on POSIX, `;` on Windows) — using a hard-coded `:` as before
 * was broken on Windows where drive-letter paths contain colons.
 */
export function getFolderAllowedBases(): string[] {
  const envList = process.env.NLMCP_FOLDER_ALLOWLIST?.trim();
  const raw = envList && envList.length > 0
    ? envList.split(path.delimiter).map((p) => p.trim()).filter((p) => p.length > 0)
    : [os.homedir()];
  return raw.map((p) => {
    const abs = path.resolve(p);
    try {
      return fs.realpathSync(abs);
    } catch {
      return abs;
    }
  });
}

/**
 * Re-export of denylist for tests and for the recursive folder scan,
 * which needs to apply per-entry denial after `realpath` resolution.
 */
export const PATH_POLICY_DENIED_SEGMENTS = DENIED_SEGMENTS_RAW;
export const PATH_POLICY_DENIED_ABSOLUTE = DENIED_ABSOLUTE_RAW;

/**
 * Lightweight per-entry check used by `scanDir` after symlink-resolving
 * each entry, so a malicious symlink inside an allowed folder cannot
 * exfiltrate ~/.ssh keys. Kept for back-compat — new callers should
 * prefer `assertSafeFolderEntryPath`, which also enforces the
 * allowlist.
 */
export function isDeniedReadPath(resolved: string): string | null {
  return isInDeniedAbsolute(resolved) ?? containsDeniedSegment(resolved);
}
