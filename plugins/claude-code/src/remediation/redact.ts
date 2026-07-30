/**
 * Redacts leaked keys from the local transcript/temp artifacts the
 * remediation "Redact" options route through. Given the where-found references the
 * secret findings carry plus the raw value to strike, it rewrites each in-scope
 * artifact in place so the leaked key is no longer readable, and reports how many
 * keys it actually redacted.
 *
 * BINDING SCOPE LIMIT: redaction is limited to the artifact roots the scope names —
 * the platform default is the Claude Code transcript directory, and a caller that
 * scans a bounded temp directory supplies that directory explicitly. A target
 * whose real path falls outside every root is an ordinary project file and is left
 * byte-identical; the flow never performs in-place redaction of arbitrary project
 * files. The limit is structural: an out-of-scope path is never opened for writing,
 * and containment is checked against real paths so a symlink inside a root cannot
 * redirect a write to a file outside it.
 *
 * RAW SAFETY: `rawValue` is raw-bearing and lives in-process only — it is recovered
 * from the still-on-disk artifact, struck here, and dropped. It is never persisted
 * or rendered; the persisted projection stays the raw-free MaskedSecretFinding.
 * This module returns only a count, never a raw value.
 *
 * IO is node:fs only — no store access, no network, no detection engine. Reads and
 * writes are best-effort per file: an unreadable or vanished artifact is skipped so
 * one bad file cannot abort the sweep of the rest.
 */
import { readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute, relative, resolve } from 'node:path';

import type { MaskedFindingLocation } from '@akasecurity/schema';

import { transcriptsDir } from '../history/transcripts.ts';

// The masked/redacted form a struck key is replaced with, matching the
// `[REDACTED:CATEGORY]` convention the detections redactor uses. Secret keys are
// the only thing this module strikes, so the category is fixed.
const REDACTED_PLACEHOLDER = '[REDACTED:SECRET]';

// Matches `$`-pattern sequences that String.replace-family APIs expand ($&,
// $', $`, $$, $1…, $<name>). Production replacements are vault pointers, which
// never contain `$`, so refusing these costs nothing.
const REPLACE_PATTERN_SEQUENCE = /\$[$&`'<0-9]/;

// The string a struck occurrence of `rawValue` is rewritten to: the caller's
// pre-resolved replacement when one is supplied (an async caller resolves vault
// pointers ahead of this synchronous sweep), else the one-way placeholder. A
// replacement that CONTAINS the raw value (including the raw value itself)
// falls back to the placeholder — honouring it would leave the secret readable
// while reporting it redacted. So does a replacement carrying `$`-pattern
// sequences: this module splices literally, but replace-family APIs expand
// those sequences to re-insert the matched secret, so such a candidate is
// never propagated anywhere.
function replacementFor(
  rawValue: string,
  replacements: ReadonlyMap<string, string> | undefined,
): string {
  const candidate = replacements?.get(rawValue);
  if (
    candidate === undefined ||
    candidate.includes(rawValue) ||
    REPLACE_PATTERN_SEQUENCE.test(candidate)
  ) {
    return REDACTED_PLACEHOLDER;
  }
  return candidate;
}

// One leaked key to strike: the finding's where-found reference (the raw-free
// MaskedSecretFinding location — the artifact path, plus an optional span) and the
// raw value to remove. The scope limit is enforced on `where.filePath`.
export interface RedactionTarget {
  where: MaskedFindingLocation;
  rawValue: string;
}

// The transcript/temp artifact roots whose contained files may be redacted in
// place. A file outside every root is an ordinary project file, left untouched.
export interface RedactionScope {
  artifactRoots: readonly string[];
}

// The platform default scope: prior Claude Code transcripts under
// `~/.claude/projects`. `transcriptsDir()` is the one place that knows the
// transcript layout, so it is reused rather than re-derived here. The whole OS temp
// tree is deliberately NOT a default root — a caller scanning a bounded temp
// directory passes that directory explicitly, so redaction is never granted over
// arbitrary files that merely happen to live under the OS temp dir. `home`
// mirrors `transcriptsDir`'s own override — supplied only by tests/harnesses that
// need a throwaway transcripts root; no production call site passes it.
export function platformRedactionScope(home?: string): RedactionScope {
  return { artifactRoots: [transcriptsDir(home)] };
}

// The real (symlink-resolved) path, or null when the path does not exist or cannot
// be resolved. Resolving symlinks is what makes the containment check safe against
// a symlink inside an allowed root that points at an external file. Exported so the
// production surfaced-secret adapter (surfaced-redact.ts) can apply the same
// symlink-safe containment check when validating a candidate root, rather than
// re-implementing it.
export function realPathOrNull(path: string): string | null {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
}

// True when `realTarget` (already a resolved real path) sits strictly inside `root`
// (a nested descendant, never the root itself and never an escaping `..` sibling).
// The root is resolved too, so both sides are compared as real paths.
function isWithinRoot(realTarget: string, root: string): boolean {
  const realRoot = realPathOrNull(root);
  if (realRoot === null) return false;
  const rel = relative(realRoot, realTarget);
  return rel !== '' && !rel.startsWith('..') && !isAbsolute(rel);
}

// The real path of `filePath` when it is an in-scope artifact, else null. Returns
// the resolved real path so the caller reads and writes exactly the canonical
// in-scope file — never a path that a symlink could redirect out of scope.
// Exported so the production surfaced-secret adapter can decide which findings'
// artifacts are even worth reading for raw-value recovery, without re-implementing
// this containment check.
export function resolveRedactableArtifact(filePath: string, scope: RedactionScope): string | null {
  const realTarget = realPathOrNull(resolve(filePath));
  if (realTarget === null) return null;
  return scope.artifactRoots.some((root) => isWithinRoot(realTarget, root)) ? realTarget : null;
}

// The detailed outcome of a redaction sweep: the real count (same figure
// `redactLeakedKeys` returns) plus exactly which input targets were struck —
// so a caller that needs to know which specific findings remain unredacted
// (rather than only how many) can compare its input targets against `struck`.
export interface RedactionDetail {
  readonly redactedKeys: number;
  // How many of `redactedKeys` were rewritten to a caller-supplied replacement
  // (a recoverable vault pointer) rather than the one-way placeholder — so a
  // caller's copy can say exactly which strikes are recoverable and which are
  // irreversible. Always ≤ `redactedKeys`; 0 when no replacements were supplied.
  readonly pointeredKeys: number;
  readonly struck: readonly RedactionTarget[];
}

/**
 * Redact every in-scope leaked-key occurrence in place and report the real count of
 * keys actually redacted (a key counts only when its raw value was present, struck,
 * and the rewrite persisted) plus exactly which of the input targets were struck.
 * Targets outside the scope roots are skipped and their files never written.
 * Targets against the same file are folded into a single read/rewrite. Each file is
 * handled best-effort: a read or write failure on one artifact is skipped so the
 * rest of the batch is still redacted.
 *
 * `replacements` maps a raw value to the pre-resolved string it is rewritten to
 * — a recoverable vault pointer, resolved by the async caller because this sweep
 * must stay synchronous. A value with no entry — or with an entry that contains
 * the raw value or `$`-pattern sequences — is struck with the one-way
 * placeholder, so with no map the behavior is byte-identical to the plain strike.
 */
export function redactLeakedKeysDetailed(
  targets: readonly RedactionTarget[],
  scope: RedactionScope = platformRedactionScope(),
  replacements?: ReadonlyMap<string, string>,
): RedactionDetail {
  // Group the in-scope targets (keeping each target's identity, not just its raw
  // value) by the real path of the file they strike, so a file with several leaked
  // keys is read and rewritten once.
  const byFile = new Map<string, RedactionTarget[]>();
  for (const target of targets) {
    if (target.rawValue === '') continue;
    const artifactPath = resolveRedactableArtifact(target.where.filePath, scope);
    if (artifactPath === null) continue;
    const existing = byFile.get(artifactPath);
    if (existing === undefined) byFile.set(artifactPath, [target]);
    else existing.push(target);
  }

  let redactedKeys = 0;
  let pointeredKeys = 0;
  const struck: RedactionTarget[] = [];
  for (const [filePath, fileTargets] of byFile) {
    let content: string;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue; // unreadable or vanished artifact — skip, don't abort the batch
    }
    const struckHere: RedactionTarget[] = [];
    let pointeredHere = 0;
    // rawValue → the replacement actually applied to this file, so a sibling
    // target sharing the value counts the same way (pointered vs one-way) even
    // when the first strike fell back to the placeholder.
    const applied = new Map<string, string>();
    for (const target of fileTargets) {
      // A sibling target sharing this raw value already struck every occurrence
      // in this file, so `content.includes` is now false even though this
      // target's value IS redacted — count it struck rather than misreport it as
      // still exposed (two findings on one repeated value both resolve together).
      const prior = applied.get(target.rawValue);
      if (prior !== undefined) {
        struckHere.push(target);
        if (prior !== REDACTED_PLACEHOLDER) pointeredHere += 1;
        continue;
      }
      if (!content.includes(target.rawValue)) continue;
      let replacement = replacementFor(target.rawValue, replacements);
      // Literal splice, never `replaceAll` with a string pattern — split/join
      // carries no `$`-pattern semantics, so the replacement can never be
      // expanded against the match it strikes.
      let next = content.split(target.rawValue).join(replacement);
      if (next.includes(target.rawValue)) {
        // Bytes around a spliced replacement recombined into the raw value
        // again (an overlap/boundary artifact) — strike one-way instead.
        replacement = REDACTED_PLACEHOLDER;
        next = content.split(target.rawValue).join(replacement);
        // Still readable even after the placeholder pass: leave this value's
        // occurrences as they were and do not count it redacted.
        if (next.includes(target.rawValue)) continue;
      }
      content = next;
      applied.set(target.rawValue, replacement);
      struckHere.push(target);
      if (replacement !== REDACTED_PLACEHOLDER) pointeredHere += 1;
    }
    if (struckHere.length === 0) continue;
    // Write atomically: a full write to a sibling temp file, then rename over the
    // original (rename is atomic on the same filesystem). A crash mid-write leaves
    // the original transcript intact rather than truncated.
    const tmpPath = `${filePath}.aka-redact.tmp`;
    try {
      writeFileSync(tmpPath, content);
      renameSync(tmpPath, filePath);
    } catch {
      try {
        // `recursive: true` also clears a `tmpPath` that turned out to be a
        // directory (e.g. a stray leftover), not just a partially written file —
        // a bare `force: true` throws EISDIR on a directory and the entry survives.
        rmSync(tmpPath, { force: true, recursive: true });
      } catch {
        // temp file may not exist — nothing to clean up
      }
      continue; // write failed — don't count keys that were not persisted
    }
    // Count only after the rewrite is on disk, so the returned counts reflect keys
    // actually redacted rather than merely matched.
    redactedKeys += struckHere.length;
    pointeredKeys += pointeredHere;
    struck.push(...struckHere);
  }

  return { redactedKeys, pointeredKeys, struck };
}

/**
 * Redact every in-scope leaked-key occurrence in place and return the real count of
 * keys actually redacted. A thin wrapper over `redactLeakedKeysDetailed` for callers
 * that only need the count.
 */
export function redactLeakedKeys(
  targets: readonly RedactionTarget[],
  scope: RedactionScope = platformRedactionScope(),
): number {
  return redactLeakedKeysDetailed(targets, scope).redactedKeys;
}
