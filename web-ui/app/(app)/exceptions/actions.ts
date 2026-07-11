'use server';

import { userInfo } from 'node:os';

import { maskMatch, scan } from '@akasecurity/detections';
import type { CreateExceptionInput } from '@akasecurity/persistence';
import {
  BLOCKED_DETECTIONS_RETENTION_MS,
  dataDir,
  DuplicateActiveExceptionError,
  fingerprintValue,
  loadOrCreateFingerprintKey,
  rotateFingerprintKey,
} from '@akasecurity/persistence';
import type { ResolvedScope } from '@akasecurity/schema';
import { scopeFromAnswer } from '@akasecurity/schema';
import { revalidatePath } from 'next/cache';

import { db } from '../../lib/db';

// Exception management server actions — the web twins of the `aka exception`
// verbs, writing the same local store through the same persistence repository.
// Every mutation is loopback-only (the server binds 127.0.0.1; Next enforces
// Origin/Host on server actions). Raw values are handled ONLY inside
// `addException`: fingerprinted + masked immediately, never persisted, never
// logged, and never echoed back in an error.

export interface ActionResult {
  ok: boolean;
  error?: string;
}

// The grant creator's identity — the OS account running the local server,
// mirroring the CLI's resolveCreatedBy.
function resolveCreatedBy(): string {
  try {
    return userInfo().username;
  } catch {
    return 'unknown';
  }
}

function resolveScope(answer: string): ResolvedScope | { error: string } {
  try {
    return scopeFromAnswer(answer);
  } catch (err) {
    return { error: err instanceof Error ? err.message : 'invalid scope' };
  }
}

function createGrant(input: CreateExceptionInput): Promise<ActionResult> {
  return db()
    .exceptions.create(input)
    .then(() => {
      revalidatePath('/exceptions');
      return { ok: true };
    })
    .catch((err: unknown) => {
      if (err instanceof DuplicateActiveExceptionError) {
        return {
          ok: false,
          error: 'An active exception for this value already exists — revoke it first.',
        };
      }
      return { ok: false, error: 'Could not create the exception.' };
    });
}

/**
 * Grant an exception from a blocked-ledger entry (`aka exception approve`).
 * The value never travels — the ledger row already carries its keyed
 * fingerprint + masked preview. Permanent scope requires the masked value
 * retyped; re-checked here, not just in the dialog.
 */
export async function approveBlocked(input: {
  reference: string;
  scope: string;
  reason: string;
  confirmation?: string;
}): Promise<ActionResult> {
  const reason = input.reason.trim();
  if (reason === '') return { ok: false, error: 'A reason is required — it is the audit trail.' };
  const scope = resolveScope(input.scope);
  if ('error' in scope) return { ok: false, error: scope.error };

  // Looked up against the full retention window, not just the UI's currently
  // selected lookback — approving a row the user can see must not depend on
  // which filter chip happens to be active.
  const entry = (await db().exceptions.recentBlocked(BLOCKED_DETECTIONS_RETENTION_MS)).find(
    (b) => b.reference === input.reference,
  );
  if (!entry) {
    return {
      ok: false,
      error: 'That blocked detection has expired from the ledger — trigger it again.',
    };
  }
  if (scope.scope === 'permanent' && input.confirmation !== entry.maskedValue) {
    return {
      ok: false,
      error: 'Permanent grants require retyping the masked value exactly as shown.',
    };
  }

  return createGrant({
    ruleId: entry.ruleId,
    category: entry.category,
    valueFingerprint: entry.valueFingerprint,
    keyVersion: entry.keyVersion,
    maskedValue: entry.maskedValue,
    ...scope,
    justification: reason,
    conditions: null,
    createdBy: resolveCreatedBy(),
    createdVia: 'web-approve',
  });
}

/**
 * Pre-authorize a value that has never been blocked (`aka exception add`).
 * The raw value exists only inside this function: verified against the rule's
 * DB-snapshot definition, reduced to fingerprint + masked preview, and
 * discarded. Errors never echo the value.
 */
export async function addException(input: {
  ruleId: string;
  value: string;
  scope: string;
  reason: string;
  confirmation?: string;
}): Promise<ActionResult> {
  const reason = input.reason.trim();
  if (reason === '') return { ok: false, error: 'A reason is required — it is the audit trail.' };
  const scope = resolveScope(input.scope);
  if ('error' in scope) return { ok: false, error: scope.error };
  if (input.value === '') return { ok: false, error: 'No value supplied — nothing to except.' };
  if (scope.scope === 'permanent' && input.confirmation !== input.value) {
    return { ok: false, error: 'Permanent grants require retyping the value exactly.' };
  }

  // The installed snapshot is the scan authority — the same enabled
  // rules the runtime evaluates, read from the DB, passed explicitly (never the
  // engine's process-global registry, which must stay untouched in this
  // long-lived server).
  const { rules } = db().installedPacks.installedRuleset();
  const rule = rules.find((r) => r.id === input.ruleId);
  if (!rule) return { ok: false, error: `Unknown or disabled rule '${input.ruleId}'.` };

  // The grant must bind to something the engine would actually detect under
  // this rule, or it would never apply at enforcement time (mirrors the CLI).
  const matches = scan(input.value, rules).filter((m) => m.ruleId === input.ruleId);
  if (matches.length === 0) {
    return {
      ok: false,
      error: `The value does not match rule ${input.ruleId} — a grant for it would never apply.`,
    };
  }
  const spans = [...new Set(matches.map((m) => m.rawMatch))];
  const span = spans[0];
  if (spans.length > 1 || span === undefined) {
    return {
      ok: false,
      error: `The input contains ${String(spans.length)} distinct values matching ${input.ruleId} — supply exactly one.`,
    };
  }

  let grant: { valueFingerprint: string; keyVersion: number; maskedValue: string };
  try {
    const key = loadOrCreateFingerprintKey(dataDir());
    grant = {
      valueFingerprint: fingerprintValue(key, span),
      keyVersion: key.version,
      maskedValue: maskMatch(span),
    };
  } catch {
    // Corrupt key file — fail secure with the CLI's recovery guidance.
    return {
      ok: false,
      error:
        'The exception key file is corrupt. Delete ~/.aka/data/exception.key to mint a new key (this invalidates existing grants).',
    };
  }

  return createGrant({
    ruleId: rule.id,
    category: rule.category,
    ...grant,
    ...scope,
    justification: reason,
    conditions: null,
    createdBy: resolveCreatedBy(),
    createdVia: 'web-add',
  });
}

/** Revoke an active grant (`aka exception revoke`) — terminal, audit-retained. */
export async function revokeException(id: string, reason: string): Promise<ActionResult> {
  const revoked = await db()
    .exceptions.revoke(id, resolveCreatedBy(), reason.trim() === '' ? undefined : reason.trim())
    .catch(() => false);
  if (!revoked) return { ok: false, error: 'No active exception with that id.' };
  revalidatePath('/exceptions');
  revalidatePath(`/exceptions/${id}`);
  return { ok: true };
}

/**
 * Rotate the fingerprint key (`aka exception rotate-key`) — INVALIDATION of
 * every existing grant. The typed confirmation is re-checked here; the dialog
 * gate alone is not the control.
 */
// eslint-disable-next-line @typescript-eslint/require-await -- 'use server' exports must be async
export async function rotateKey(confirmation: string): Promise<ActionResult> {
  if (confirmation !== 'rotate') {
    return { ok: false, error: 'Type "rotate" to confirm.' };
  }
  try {
    rotateFingerprintKey(dataDir());
  } catch {
    return {
      ok: false,
      error:
        'The exception key file is corrupt and cannot be rotated. Delete ~/.aka/data/exception.key to mint a new key.',
    };
  }
  revalidatePath('/exceptions');
  return { ok: true };
}
