/**
 * At-rest scrub of a live session's transcript file. Claude Code appends every
 * prompt to `~/.claude/projects/*.jsonl` even when a hook blocked it, so a raw
 * secret the tail scan just found is also sitting in plaintext on disk. This
 * module rewrites those secret spans IN PLACE to vault pointers (via the
 * injected vault-glue tokenizer), line by line, so the file stays valid
 * newline-delimited JSON and untouched lines stay byte-identical.
 *
 * SCOPE LIMIT: the target must resolve (symlink-safe, real-path containment)
 * inside the redaction scope's artifact roots. An out-of-scope path is never
 * opened for writing — the same structural containment the remediation
 * redactor enforces, reused from `remediation/redact.ts` rather than
 * re-implemented.
 *
 * FAULT POSTURE: any error returns null and leaves the file as it was — the
 * reconcile pass continues. The injected tokenizer is itself fail-secure: a
 * span it cannot vault degrades to the one-way `[REDACTED:CATEGORY]`
 * placeholder, so a fault destroys residue rather than leaking it. The one
 * tokenizer outcome treated as a fault HERE is the unclassifiable blanket
 * (a changed line with no pointers and no degraded spans — the tokenizer could
 * not tell secret from clean): rewriting whole transcript lines to a blanket
 * placeholder would destroy the user's transcript, so the scrub aborts with
 * the file untouched instead.
 */
import { readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';

import { type platformRedactionScope, resolveRedactableArtifact } from '../remediation/redact.ts';

// Files larger than this are skipped whole (return null): this scrub does a
// whole-file read — acceptable because it runs in the detached reconcile
// worker, off the hot hook path — but a pathological transcript must not
// balloon the worker, so the read is capped.
const DEFAULT_MAX_SCRUB_BYTES = 32 * 1024 * 1024;

export interface TailScrubDeps {
  // The vault-glue text tokenizer: self-scans, shields existing pointers so a
  // re-run never re-tokenizes them, and replaces each secret span with a
  // pointer (or a one-way placeholder on degrade).
  tokenizeText(
    text: string,
    opts?: { findings?: unknown[] },
  ): Promise<{ text: string; pointers: string[]; degraded: { category: string }[] }>;
  // The artifact roots whose contained files may be rewritten in place.
  scope: ReturnType<typeof platformRedactionScope>;
  // Whole-file read cap in bytes; a larger file is skipped (null). Defaults to
  // 32 MiB when unset.
  maxBytes?: number;
}

/**
 * Scrub one transcript file: replace every detected secret span with a vault
 * pointer, in place, preserving line structure and the trailing newline
 * exactly as found. Returns the count of rewritten lines, `{ rewritten: 0 }`
 * without writing when nothing matched, and null when the path is out of
 * scope, oversized, unreadable, or anything failed (the file is then left
 * byte-identical).
 */
export async function scrubTranscriptTail(
  filePath: string,
  deps: TailScrubDeps,
): Promise<{ rewritten: number } | null> {
  try {
    // Containment first: out of scope → never opened for writing.
    const realPath = resolveRedactableArtifact(filePath, deps.scope);
    if (realPath === null) return null;
    // Snapshot the stat up front: the size gates the whole-file read, the mode
    // is re-applied to the rewrite, and size+mtime detect concurrent appends
    // just before the rename below.
    const statBefore = statSync(realPath);
    if (statBefore.size > (deps.maxBytes ?? DEFAULT_MAX_SCRUB_BYTES)) return null;

    const content = readFileSync(realPath, 'utf8');
    // Line-by-line so the rewrite can only ever change bytes WITHIN a line —
    // the newline structure (including a trailing newline, which survives the
    // split/join round-trip as a final empty element) is preserved exactly.
    const lines = content.split('\n');
    let rewritten = 0;
    for (const [i, line] of lines.entries()) {
      if (line === '') continue;
      const result = await deps.tokenizeText(line);
      if (result.text === line) continue;
      // A changed line that minted no pointer and degraded no span is the
      // tokenizer's unclassifiable blanket — abort rather than destroy lines.
      if (result.pointers.length === 0 && result.degraded.length === 0) return null;
      lines[i] = result.text;
      rewritten += 1;
    }
    if (rewritten === 0) return { rewritten: 0 };

    // Atomic rewrite: full write to a sibling temp file, then rename over the
    // original — a crash mid-write leaves the transcript intact.
    const tmpPath = `${realPath}.aka-scrub.tmp`;
    try {
      // Preserve the transcript's permission bits: without an explicit mode
      // the temp file is created at the umask default, and the rename would
      // widen a 0600 transcript to world-readable.
      writeFileSync(tmpPath, lines.join('\n'), { mode: statBefore.mode & 0o777 });
      // The transcript is LIVE — Claude Code may have appended lines while the
      // scrub tokenized its in-memory snapshot. Renaming the snapshot over a
      // file that changed underneath would silently destroy those lines, so
      // ANY difference since the first stat aborts the rewrite: a lost scrub
      // is retried by the next reconcile pass, but lost transcript lines do
      // not come back.
      const statNow = statSync(realPath);
      if (statNow.size !== statBefore.size || statNow.mtimeMs !== statBefore.mtimeMs) {
        rmSync(tmpPath, { force: true, recursive: true });
        return null;
      }
      renameSync(tmpPath, realPath);
    } catch {
      try {
        // `recursive: true` also clears a tmpPath that turned out to be a
        // directory, not just a partially written file.
        rmSync(tmpPath, { force: true, recursive: true });
      } catch {
        // temp file may not exist — nothing to clean up
      }
      return null;
    }
    return { rewritten };
  } catch {
    return null;
  }
}
