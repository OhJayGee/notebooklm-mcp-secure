# Codex Findings: `src/utils/path-policy.ts`

## 1. Export writes can follow symlinks outside the export base

**Summary:** `resolveExportFilePath` validates the lexical path only, so an output path inside the export base can write through an existing symlinked file or symlinked parent to a denied or out-of-base target.

**Location:** `src/utils/path-policy.ts:164`, `src/utils/path-policy.ts:170`; surfaced by `src/tools/handlers/gemini.ts:904` and `src/notebook-creation/audio-manager.ts:392`.

**Reproduction:** Set `NLMCP_EXPORT_DIR=/tmp/export`, create a symlink with `ln -s ~/.ssh /tmp/export/s`, then call `get_notebook_chat_history` with `output_file: "s/authorized_keys"` or `download_audio` with `output_path: "s/authorized_keys"`. The helper accepts `/tmp/export/s/authorized_keys`; `writeFile` follows the parent symlink.

**Severity / confidence:** High severity, confidence 9.

**Suggested change:** Resolve and validate the real export base and real existing parent before returning, and reject existing symlink leafs:

```ts
const realBase = fs.realpathSync(base);
const parent = path.dirname(candidate);
const realParent = fs.realpathSync(parent);

if (!isWithinBase(realParent, realBase) || isDeniedReadPath(realParent)) {
  throw new PathPolicyError("output_path parent resolves outside the allowed export base or into a denied path.");
}

try {
  if (fs.lstatSync(candidate).isSymbolicLink()) {
    throw new PathPolicyError("output_path resolves to a symlink; refusing to write.");
  }
} catch (err) {
  if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
}
```

Also open/write with `O_NOFOLLOW` where possible, or use a small `writeExportFile` helper so callers cannot accidentally reintroduce symlink-following writes.

## 2. `add_folder` symlinks are checked against denylist but not allowlist

**Summary:** `add_folder` re-checks symlink targets against the denylist but not against the folder allowlist, so a symlink inside an allowed folder can upload files outside the allowed roots.

**Location:** `src/utils/path-policy.ts:249`, `src/utils/path-policy.ts:296`, `src/tools/handlers/notebook-creation.ts:555`.

**Reproduction:** Set `NLMCP_FOLDER_ALLOWLIST=$HOME`, create a symlink with `ln -s /tmp/outside ~/allowed-link`, put `leak.md` under `/tmp/outside`, then call `add_folder` with `folder_path: "~/allowed-link"` or put `leak.md` behind a symlink inside an allowed directory. `scanDir` uploads `/tmp/outside/leak.md` unless it happens to hit a denied segment.

**Severity / confidence:** Medium severity, confidence 10.

**Suggested change:** Realpath allowlist bases and enforce them per entry:

```ts
export function getFolderAllowedBases(): string[] {
  const envList = process.env.NLMCP_FOLDER_ALLOWLIST?.trim();
  const raw = envList ? envList.split(path.delimiter) : [os.homedir()];
  return raw.map((p) => fs.realpathSync(path.resolve(p.trim())));
}

export function assertSafeFolderEntryPath(realTarget: string, allowedBases = getFolderAllowedBases()): void {
  if (!allowedBases.some((base) => isWithinBase(realTarget, base))) {
    throw new PathPolicyError("folder entry resolves outside the folder allowlist.");
  }
  const denied = isDeniedReadPath(realTarget);
  if (denied) throw new PathPolicyError(`folder entry resolves to denied path '${denied}'.`);
}
```

Then call `assertSafeFolderEntryPath(realTarget, allowedBases)` inside `scanDir` before `stat`.

## 3. Read policy accepts non-regular files

**Summary:** `assertSafeLocalReadPath` accepts non-regular files and falls back to lexical paths on `realpath` failure, allowing device and FIFO reads and predictable hangs.

**Location:** `src/utils/path-policy.ts:217`, `src/utils/path-policy.ts:241`; surfaced by `src/gemini/gemini-client.ts:493`.

**Reproduction:** Create a FIFO with `mkfifo /tmp/trap.pdf`, then call `upload_document` with `file_path: "/tmp/trap.pdf"`. The policy accepts it, then the Gemini upload path can block reading the FIFO. `/dev/zero` is likewise accepted because `/dev` is not denied and no regular-file check runs.

**Severity / confidence:** Medium severity, confidence 9.

**Suggested change:** For read helpers, require an existing regular file after symlink resolution; do not fall back for missing paths:

```ts
let realPath: string;
try {
  realPath = fs.realpathSync(resolved);
} catch {
  throw new PathPolicyError("file path must exist and resolve to a regular file");
}

const stat = fs.statSync(realPath);
if (!stat.isFile()) {
  throw new PathPolicyError("file path must be a regular file");
}
```

Add `/dev`, `/run`, and `/var/run` to absolute denied paths as defense in depth.

## 4. Denylist comparisons miss case and Windows normalization variants

**Summary:** Denylist segment and basename comparisons are case-sensitive and do not account for Windows trailing dot/space normalization, so denied paths can be addressed through alternate spellings on case-insensitive filesystems.

**Location:** `src/utils/path-policy.ts:107`, `src/utils/path-policy.ts:191`.

**Reproduction:** On default macOS or Windows filesystems, `output_file: ".SSH/authorized_keys"` or `output_file: ".ZSHRC"` can refer to `.ssh/authorized_keys` or `.zshrc` while bypassing literal `.ssh` and `.zshrc` comparisons. On Windows, `.ssh./authorized_keys` and `.ssh /authorized_keys` are also risky spellings.

**Severity / confidence:** High severity, confidence 8.

**Suggested change:** Normalize path segments before policy comparison:

```ts
function policySegment(s: string): string {
  let out = s.normalize("NFC");
  if (process.platform === "win32") out = out.replace(/[ .]+$/u, "");
  return out.toLowerCase();
}
```

Apply this in `containsDeniedSegment` and for `DENIED_WRITE_BASENAMES`; on Windows also reject `:` in path segments to avoid alternate data streams.

## 5. Denylist misses common credential stores

**Summary:** The hard-coded denylist misses several common credential stores, so file uploads can still exfiltrate high-value local tokens through ordinary-looking paths.

**Location:** `src/utils/path-policy.ts:39`, `src/utils/path-policy.ts:68`.

**Reproduction:** `upload_document` or `add_source` with `~/.config/gh/hosts.yml`, `~/.github_token`, `~/.gem/credentials`, `~/.gradle/gradle.properties`, `~/Library/Application Support/Code/User/settings.json`, or `~/Library/Application Support/Cursor/User/globalStorage/...` is accepted unless another segment happens to match.

**Severity / confidence:** Medium severity, confidence 9.

**Suggested change:** Extend `DENIED_SEGMENTS` concretely with at least:

```ts
".azure",
".config/gh",
".config/hub",
".github_token",
".gem/credentials",
".gradle/gradle.properties",
"Library/Application Support/Code/User",
"Library/Application Support/Code - Insiders/User",
"Library/Application Support/Cursor/User",
"Library/Application Support/JetBrains",
".config/Code - Insiders/User",
".config/Cursor/User",
".config/JetBrains",
"AppData/Roaming/Code/User",
"AppData/Roaming/Code - Insiders/User",
"AppData/Roaming/Cursor/User",
"AppData/Roaming/JetBrains",
"AppData/Roaming/Microsoft/Credentials",
"AppData/Local/Microsoft/Credentials",
```

Also replace the folder allowlist separator `":"` with `path.delimiter`; current parsing is not viable for Windows drive-letter paths.
