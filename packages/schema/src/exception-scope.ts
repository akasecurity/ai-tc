// Scope resolution for exception grants (`aka exception approve|add` and the
// web-ui's exception forms). Pure (no I/O): maps the mutually-exclusive
// once | for-<duration> | permanent choice onto the two nullable columns that
// actually drive evaluation (expiresAt/maxUses). Lives in the schema package —
// next to the exception contract it computes — so the CLI and the OSS web-ui
// share one implementation.
import type { DetectionException } from './zod/exception.ts';

export const MINUTE_MS = 60_000;
export const HOUR_MS = 60 * MINUTE_MS;

// Temporary grants are capped at 24 hours: a longer bypass should be a
// deliberate permanent grant (revocable any time), not a forgotten timer.
export const MAX_TEMPORARY_MS = 24 * HOUR_MS;

// A one-time grant that is never used should not dangle forever — it expires
// on its own after 30 minutes even if nothing consumes it.
export const ONCE_BACKSTOP_MS = 30 * MINUTE_MS;

// `30m` / `1h` / `24h` — minutes or hours only, no compound forms.
const DURATION_RE = /^(\d+)([mh])$/;

/**
 * Parse a `30m`/`1h`/`24h`-style duration into milliseconds. Throws with a
 * user-facing message on anything malformed, zero, or over the 24h cap.
 */
export function parseDuration(input: string): number {
  const match = DURATION_RE.exec(input.trim());
  const count = match ? Number(match[1]) : 0;
  if (!match || count <= 0) {
    throw new Error(`invalid duration '${input}' — use <n>m or <n>h (e.g. 30m, 1h, 24h)`);
  }
  const ms = count * (match[2] === 'h' ? HOUR_MS : MINUTE_MS);
  if (ms > MAX_TEMPORARY_MS) {
    throw new Error(
      `duration '${input}' exceeds the 24h maximum for --for — use --permanent (revocable any time) for an open-ended grant`,
    );
  }
  return ms;
}

// The scope subset of the exception contract computed at create time.
export type ResolvedScope = Pick<DetectionException, 'scope' | 'expiresAt' | 'maxUses'>;

export interface ScopeFlagValues {
  once?: boolean | undefined;
  for?: string | undefined;
  permanent?: boolean | undefined;
}

/**
 * Resolve the scope flags to the stored scope columns. Returns null when NO
 * scope flag was given (the caller prompts on a terminal, or fails with the
 * scope help — scope is an explicit choice, never defaulted). Throws when more
 * than one flag is set or the --for duration is invalid/over the cap.
 */
export function resolveScopeFlags(flags: ScopeFlagValues, now = Date.now()): ResolvedScope | null {
  const picked = [flags.once === true, flags.for !== undefined, flags.permanent === true].filter(
    Boolean,
  ).length;
  if (picked > 1) {
    throw new Error('pick exactly ONE scope: --once | --for <duration> | --permanent');
  }
  if (picked === 0) return null;
  if (flags.once === true) {
    return {
      scope: 'once',
      expiresAt: new Date(now + ONCE_BACKSTOP_MS).toISOString(),
      maxUses: 1,
    };
  }
  if (flags.for !== undefined) {
    return {
      scope: 'temporary',
      expiresAt: new Date(now + parseDuration(flags.for)).toISOString(),
      maxUses: null,
    };
  }
  return { scope: 'permanent', expiresAt: null, maxUses: null };
}

/**
 * Parse an interactive scope answer: 'once', 'permanent', or a duration like
 * '30m'/'1h'/'24h' (→ temporary). Throws the duration parser's message on
 * anything else.
 */
export function scopeFromAnswer(answer: string, now = Date.now()): ResolvedScope {
  const trimmed = answer.trim().toLowerCase();
  if (trimmed === 'once') {
    return { scope: 'once', expiresAt: new Date(now + ONCE_BACKSTOP_MS).toISOString(), maxUses: 1 };
  }
  if (trimmed === 'permanent') {
    return { scope: 'permanent', expiresAt: null, maxUses: null };
  }
  return {
    scope: 'temporary',
    expiresAt: new Date(now + parseDuration(trimmed)).toISOString(),
    maxUses: null,
  };
}
