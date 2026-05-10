# Security Review Artifacts

Verbatim reports from the adversarial reviews that produced the
v2026.3.3 release. Kept in the repo as provenance: they document what
was reviewed, what was found, and (cross-referenced with the
`CHANGELOG.md` entry for v2026.3.3) which findings were addressed and
how.

## Round 1 — Whole-codebase adversarial review

Two independent reviewers were asked to do an adversarial read of the
whole codebase, with no prior context on what controls were intended,
and to surface any concrete vulnerability with a clear exploit path.

| File | Reviewer | Scope |
|------|----------|-------|
| [`CLAUDE_REVIEW.md`](./CLAUDE_REVIEW.md) | Claude (Opus 4.7) | Whole repo: index/auth/library/sessions/tools/webhooks/crypto/secrets |
| [`CODEX_REVIEW.md`](./CODEX_REVIEW.md) | Codex (GPT-5) | Whole repo: same scope |

Both rounds converged on the same critical findings — that's the
strongest signal you'll get from independent review. See the
"Vulnerabilities Patched" subsection of the v2026.3.3 CHANGELOG
entry for the per-finding fix list.

## Round 2 — Targeted review of the new path-policy module

After Round 1's fixes landed, the new shared `src/utils/path-policy.ts`
module became a single point of trust for filesystem path containment.
A targeted second-pass review was run against just that module, using
a deliberately defensive-toned prompt (the offensive-security framing
of the original had triggered Codex's safety classifier).

| File | Reviewer | Scope |
|------|----------|-------|
| [`CODEX_FINDINGS.md`](./CODEX_FINDINGS.md) | Codex (GPT-5) | `src/utils/path-policy.ts` and its callers |
| [`GEMINI_FINDINGS.md`](./GEMINI_FINDINGS.md) | Gemini (3 Pro) | Same |

Nine distinct findings (after deduplication across both reviewers),
all confidence ≥ 7, all addressed in the same v2026.3.3 release. See
the "External Review Findings Addressed" subsection of the v2026.3.3
CHANGELOG entry.

## How to interpret these files

- **Findings flagged confidence < 7 may not be present.** The review
  prompt asked reviewers to filter their own output to confidence ≥ 7
  to keep signal-to-noise high. Both reviewers complied; nothing
  below the bar was reported.
- **A "false positive" in the report does not necessarily mean the
  reviewer was wrong.** Some findings turn out to be already-mitigated
  in surrounding code, in which case the regression test stage proved
  the existing protection. Each finding's resolution is documented in
  CHANGELOG.
- **These reports are point-in-time.** They reflect the state of the
  codebase at the moment of review. A finding here is "resolved" only
  if the corresponding fix exists in HEAD AND a regression test pins
  it.

## Future reviews

If you run another review round, drop the verbatim report into this
directory under a name that follows the existing pattern
(`<REVIEWER>_<ROUND>.md`), then add the appropriate "Round N" section
to this README. The CHANGELOG entry for the release that addresses
the round should reference these files explicitly.

[`REVIEW_PROMPT_TEMPLATE.md`](./REVIEW_PROMPT_TEMPLATE.md) holds the
two prompt templates used to date — one for module-scoped reviews
and one for whole-repo reviews. Both have been deliberately drafted
to avoid offensive-security keywords that trigger safety classifiers.
Use them as the starting point for any future review round.
