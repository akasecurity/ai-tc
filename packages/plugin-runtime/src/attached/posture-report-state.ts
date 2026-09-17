import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  ATTACHED_POSTURE_REPORT_FILENAME,
  ensureDataDirSync,
  writeOwnerOnlyFileSync,
} from '@akasecurity/persistence';

import type { PostureReportOutcome } from './posture-reporter.ts';

/**
 * Where the last posture send's OUTCOME is recorded, for `status` to render.
 *
 * ITS OWN FILE, for the reason the sync outcome and the history drain each
 * have one: `attached-state.json` is rewritten wholesale by every breaker
 * transition and cleared by the next successful forward of anything — so a
 * posture send refused an hour ago would be erased by a tool call that landed
 * a minute ago, and status would read healthy on a machine whose plane has
 * graded it silent. NOT `posture-state.json` under settings/ either: that file
 * is the device identity plus the throttle stamp, and `markAttempted` rewrites
 * it WHOLESALE before every send — the same erase-on-rewrite hazard, one
 * directory over.
 */
// Defined in @akasecurity/persistence, which sits below both detach surfaces
// (`aka detach` and the dashboard's settings action) and owns the list they
// both clear. Re-exported under this package's own name so its consumers are
// unaffected by where the string lives.
export const POSTURE_REPORT_STATE_FILENAME = ATTACHED_POSTURE_REPORT_FILENAME;

/** The persisted form. Deliberately tiny, and deliberately free of any error text. */
export interface PostureReportState {
  outcome: PostureReportOutcome;
  atMs: number;
}

/**
 * The renderable set, validated on read.
 *
 * Built from a Record KEYED BY THE OUTCOME TYPE rather than spelled as a list:
 * a reason added to `ForwardFailureReason` that this file does not know fails
 * typecheck here, where a list would compile and let the reporter WRITE an
 * outcome the reader then refuses — status saying "no report recorded yet"
 * about a send that was recorded. The other direction stays downgrade-safe: a
 * state written by a NEWER build than the one reading it fails the check and
 * reads as nothing recorded, silence rather than a wrong verdict.
 */
const OUTCOME_KEYS: Record<PostureReportOutcome, true> = {
  ok: true,
  unauthorized: true,
  forbidden: true,
  unreachable: true,
  'breaker-open': true,
  'invalid-request': true,
  'route-absent': true,
  rejected: true,
};
const OUTCOMES: ReadonlySet<string> = new Set(Object.keys(OUTCOME_KEYS));

export function postureReportStatePath(dataDir: string): string {
  return join(dataDir, POSTURE_REPORT_STATE_FILENAME);
}

/**
 * Record what the last send did. Best-effort: a send whose outcome cannot be
 * written is still a send that happened, and the caller is on a fail-open path.
 *
 * Only the coarse enum and a timestamp are persisted. The raw error never
 * reaches this module at all — the forward policy classified it and dropped it
 * — so there is nothing here that could carry a URL, a header echo or a body
 * fragment into a rendered status line.
 */
export function writePostureReportState(dataDir: string, state: PostureReportState): void {
  try {
    ensureDataDirSync(dataDir);
    writeOwnerOnlyFileSync(postureReportStatePath(dataDir), `${JSON.stringify(state)}\n`);
  } catch {
    // Best-effort — never let telemetry bookkeeping fail the report.
  }
}

/** The last recorded send, or `null` when there is none or it is unreadable. */
export function readPostureReportState(dataDir: string): PostureReportState | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(postureReportStatePath(dataDir), 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const record = parsed as { outcome?: unknown; atMs?: unknown };
    // Validate the enum rather than trusting the file: this value is rendered,
    // so an arbitrary string from a hand-edited file must not reach the output.
    if (typeof record.outcome !== 'string' || !OUTCOMES.has(record.outcome)) return null;
    if (typeof record.atMs !== 'number' || !Number.isFinite(record.atMs)) return null;
    return { outcome: record.outcome as PostureReportOutcome, atMs: record.atMs };
  } catch {
    return null;
  }
}
