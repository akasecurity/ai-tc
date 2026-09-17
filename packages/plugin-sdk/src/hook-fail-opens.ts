import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { ensureDataDirSync, writeOwnerOnlyFileSync } from '@akasecurity/persistence';

/**
 * Where a hook's fail-open exits are counted, for `aka status` to render.
 *
 * Failing open is the ABSENCE of output: a hook that throws writes nothing,
 * exits 0, and the host reads that as "no opinion". That is the right contract
 * for the session and the wrong one for the person asking whether the plugin
 * is working — a hook throwing on every call leaves no trace anywhere, and
 * every other file beside this one describes a control plane that is simply
 * not being written to. This tally is the trace.
 *
 * In the DATA dir beside the forward tallies, and deliberately NOT in the
 * attachment's derived-file list: a hook that fails open on a standalone
 * machine is the same fault, and a detach must not zero a count that is not
 * about the attachment.
 */
export const HOOK_FAIL_OPENS_FILENAME = 'hook-fail-opens.json';

/**
 * A COUNT and a clock, and nothing else — no hook name, no error text. The
 * catch this is written from has the error in hand, and an error's message can
 * carry a path, a payload fragment or a header echo; the way to be certain none
 * of that reaches a rendered status line is never to write it down.
 */
export interface HookFailOpens {
  /** Fail-open exits recorded on this machine. */
  failOpens: number;
  /** When the most recent one happened, epoch millis on the local clock. */
  lastAtMs: number;
}

export function hookFailOpensPath(dataDir: string): string {
  return join(dataDir, HOOK_FAIL_OPENS_FILENAME);
}

/**
 * Count one fail-open exit.
 *
 * READ-MODIFY-WRITE with no lock, and that is a known imprecision rather than
 * an oversight: two hooks can fail open at once and lose an increment, exactly
 * as the forward drop tally can. The renderer says "at least" for that reason.
 * A lock would be the wrong trade on a path whose whole contract is that
 * nothing can delay or fail the exit.
 *
 * NEVER THROWS. It is called from inside a fail-open catch, where a throw would
 * escape as an uncaught exception and turn a silent allow into a non-zero exit
 * — the one outcome that catch exists to prevent.
 */
export function recordHookFailOpen(dataDir: string, nowMs: number): void {
  try {
    ensureDataDirSync(dataDir);
    const previous = readHookFailOpens(dataDir);
    const next: HookFailOpens = {
      failOpens: (previous?.failOpens ?? 0) + 1,
      lastAtMs: nowMs,
    };
    writeOwnerOnlyFileSync(hookFailOpensPath(dataDir), `${JSON.stringify(next)}\n`);
  } catch {
    // Best-effort bookkeeping; a fail-open that cannot be counted is still a fail-open.
  }
}

/**
 * The tally, or `null` when there is none or it cannot be read.
 *
 * Validated rather than trusted: these values are rendered, and a hand-edited
 * or truncated file must read as "nothing recorded" rather than put an
 * arbitrary value into the status block. A corrupt tally restarts from one on
 * the next exit rather than refusing to count.
 */
export function readHookFailOpens(dataDir: string): HookFailOpens | null {
  try {
    const parsed: unknown = JSON.parse(readFileSync(hookFailOpensPath(dataDir), 'utf8'));
    if (typeof parsed !== 'object' || parsed === null) return null;
    const record = parsed as { failOpens?: unknown; lastAtMs?: unknown };
    if (typeof record.failOpens !== 'number' || !Number.isFinite(record.failOpens)) return null;
    if (record.failOpens <= 0) return null;
    if (typeof record.lastAtMs !== 'number' || !Number.isFinite(record.lastAtMs)) return null;
    return { failOpens: record.failOpens, lastAtMs: record.lastAtMs };
  } catch {
    return null;
  }
}
