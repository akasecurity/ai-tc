import { readFileSync } from 'node:fs';

// ─── FROZEN. NEVER EDIT. ─────────────────────────────────────────────────────
//
// `readHistorySyncState` as it stood at 3c5f21f6, before the state file could
// carry a counts scope marker: its constants (`src/history-sync-state.ts`
// :35-41, :62), its checks and the result it builds (:99-124) and its two
// guards (:126-132), verbatim but for the types, which are the plain shape that
// build returned.
//
// It is not a model of a reader. It is the reader every release up to that
// commit runs, and those releases keep running beside newer ones on one
// machine, because the CLI and each plugin are installed separately and each
// bundles its own copy. Whatever this copy makes of a file, they make of it too.
// That it still matches is checked, not assumed: the state test's "agrees with
// the live reader" cases hand this copy and the live reader the same unmarked
// files, a refusal of each kind included, and require the same answer.
//
// What is NOT copied: where the file lives. The caller passes the path, so the
// one question this copy answers is what an older build makes of the bytes a
// newer writer leaves.

const SPEC_VERSION = 1;
const PHASES: ReadonlySet<string> = new Set(['filling', 'complete']);
const OUTCOMES: ReadonlySet<string> = new Set(['ok', 'unreachable', 'refused', 'interrupted']);

/** The file at `path`, read exactly as the shipped reader read it. */
export function frozenReadHistorySyncState(path: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const r = parsed as Record<string, unknown>;
    if (r.specVersion !== SPEC_VERSION) return null;
    if (typeof r.phase !== 'string' || !PHASES.has(r.phase)) return null;
    if (typeof r.lastOutcome !== 'string' || !OUTCOMES.has(r.lastOutcome)) return null;
    if (!isCount(r.lastPassAtMs)) return null;
    if (!isCount(r.sentTotal) || !isCount(r.pendingTotal) || !isCount(r.skippedTotal)) return null;
    if (!isNullableCount(r.startedAtMs) || !isNullableCount(r.completedAtMs)) return null;
    return {
      specVersion: SPEC_VERSION,
      phase: r.phase,
      lastOutcome: r.lastOutcome,
      lastPassAtMs: r.lastPassAtMs,
      sentTotal: r.sentTotal,
      pendingTotal: r.pendingTotal,
      skippedTotal: r.skippedTotal,
      startedAtMs: r.startedAtMs,
      completedAtMs: r.completedAtMs,
    };
  } catch {
    return null;
  }
}

function isCount(v: unknown): v is number {
  return typeof v === 'number' && Number.isFinite(v) && v >= 0;
}

function isNullableCount(v: unknown): v is number | null {
  return v === null || isCount(v);
}
