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
import { readFileSync, realpathSync, writeFileSync } from 'node:fs';
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
// arbitrary files that merely happen to live under the OS temp dir.
export function platformRedactionScope(): RedactionScope {
  return { artifactRoots: [transcriptsDir()] };
}

// The real (symlink-resolved) path, or null when the path does not exist or cannot
// be resolved. Resolving symlinks is what makes the containment check safe against
// a symlink inside an allowed root that points at an external file.
function realPathOrNull(path: string): string | null {
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
function resolveRedactableArtifact(filePath: string, scope: RedactionScope): string | null {
  const realTarget = realPathOrNull(resolve(filePath));
  if (realTarget === null) return null;
  return scope.artifactRoots.some((root) => isWithinRoot(realTarget, root)) ? realTarget : null;
}

/**
 * Redact every in-scope leaked-key occurrence in place and return the real count of
 * keys actually redacted (a key counts only when its raw value was present, struck,
 * and the rewrite persisted). Targets outside the scope roots are skipped and their
 * files never written. Targets against the same file are folded into a single
 * read/rewrite. Each file is handled best-effort: a read or write failure on one
 * artifact is skipped so the rest of the batch is still redacted.
 */
export function redactLeakedKeys(
  targets: readonly RedactionTarget[],
  scope: RedactionScope = platformRedactionScope(),
): number {
  // Group the in-scope targets by the real path of the file they strike, so a file
  // with several leaked keys is read and rewritten once.
  const byFile = new Map<string, string[]>();
  for (const target of targets) {
    if (target.rawValue === '') continue;
    const artifactPath = resolveRedactableArtifact(target.where.filePath, scope);
    if (artifactPath === null) continue;
    const values = byFile.get(artifactPath);
    if (values === undefined) byFile.set(artifactPath, [target.rawValue]);
    else values.push(target.rawValue);
  }

  let redactedKeys = 0;
  for (const [filePath, rawValues] of byFile) {
    let content: string;
    try {
      content = readFileSync(filePath, 'utf8');
    } catch {
      continue; // unreadable or vanished artifact — skip, don't abort the batch
    }
    let struckHere = 0;
    for (const rawValue of rawValues) {
      if (!content.includes(rawValue)) continue;
      content = content.replaceAll(rawValue, REDACTED_PLACEHOLDER);
      struckHere += 1;
    }
    if (struckHere === 0) continue;
    try {
      writeFileSync(filePath, content);
    } catch {
      continue; // write failed — don't count keys that were not persisted
    }
    // Count only after the rewrite is on disk, so the returned count reflects keys
    // actually redacted rather than merely matched.
    redactedKeys += struckHere;
  }

  return redactedKeys;
}
