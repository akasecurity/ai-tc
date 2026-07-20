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
 */
export function redactLeakedKeysDetailed(
  targets: readonly RedactionTarget[],
  scope: RedactionScope = platformRedactionScope(),
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
  const struck: RedactionTarget[] = [];
  for (const [filePath, fileTargets] of byFile) {
    let content: string;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue; // unreadable or vanished artifact — skip, don't abort the batch
    }
    const struckHere: RedactionTarget[] = [];
    const struckValues = new Set<string>();
    for (const target of fileTargets) {
      // A sibling target sharing this raw value already struck every occurrence
      // in this file, so `content.includes` is now false even though this
      // target's value IS redacted — count it struck rather than misreport it as
      // still exposed (two findings on one repeated value both resolve together).
      if (struckValues.has(target.rawValue)) {
        struckHere.push(target);
        continue;
      }
      if (!content.includes(target.rawValue)) continue;
      content = content.replaceAll(target.rawValue, REDACTED_PLACEHOLDER);
      struckValues.add(target.rawValue);
      struckHere.push(target);
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
    // Count only after the rewrite is on disk, so the returned count reflects keys
    // actually redacted rather than merely matched.
    redactedKeys += struckHere.length;
    struck.push(...struckHere);
  }

  return { redactedKeys, struck };
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
