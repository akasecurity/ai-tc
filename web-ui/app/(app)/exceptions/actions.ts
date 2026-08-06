'use server';

import { userInfo } from 'node:os';

import { maskMatch, scan } from '@akasecurity/detections';
import type { CreateExceptionInput, FingerprintKey } from '@akasecurity/persistence';
import {
  BLOCKED_DETECTIONS_RETENTION_MS,
  createKeyProvider,
  dataDir,
  DuplicateActiveExceptionError,
  fingerprintValue,
  isCurrentKeyVersion,
  keysDir,
  loadOrCreateFingerprintKey,
  readFingerprintKey,
  readWorkspaceSettings,
  rotateFingerprintKey,
  SecretVault,
} from '@akasecurity/persistence';
import type {
  ActionInputFailure,
  AddExceptionInput,
  ApproveBlockedInput,
  BlockedDetection,
  GrantRevealInput,
  PointerDescriptor,
  PointerIdentity,
  ResolvedScope,
  Rule,
} from '@akasecurity/schema';
import {
  AddExceptionInput as AddExceptionInputSchema,
  ApproveBlockedInput as ApproveBlockedInputSchema,
  DetectionCategory,
  GrantRevealInput as GrantRevealInputSchema,
  isVaultConsentValid,
  parseActionInput,
  PointerToken,
  RevokeExceptionInput as RevokeExceptionInputSchema,
  RotateKeyInput as RotateKeyInputSchema,
  scopeFromAnswer,
} from '@akasecurity/schema';
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

// Recovery guidance for a key file that exists but cannot be PARSED. Every path
// that resolves the key routes through keyAccessError below, so this
// instruction — the only one safe to answer with "delete it" — cannot drift
// between them.
const CORRUPT_KEY_ERROR =
  'The exception key file is corrupt. Delete ~/.aka/data/exception.key to mint a new key (this invalidates existing grants).';

// A key file that is present and well-formed but cannot be read or written —
// wrong owner, lost permissions, a failing disk. Deliberately NOT the corrupt
// message: telling someone to delete a perfectly good key over a permissions
// error destroys every grant on the machine, because the replacement carries
// fresh material that no stored fingerprint was written under.
const KEY_IO_ERROR =
  'Could not access the exception key file — check the permissions on ~/.aka/data. Do not delete exception.key to work around this; that invalidates every existing grant.';

// The local store is the only data source; a read that fails has to surface as a
// message rather than an exception, or a Server Action rejects and the dialog
// shows a framework error page instead of a way forward.
const STORE_ERROR = 'Could not read the local store (~/.aka/data/aka.db).';

// The same requirement, reached through the other door. A Server Action's
// arguments arrive as untrusted JSON over an HTTP POST, so the parameter types
// below are a compile-time claim about a runtime that never checked one: a
// caller is free to post a number, a null, or an object carrying a hostile
// `toString`. Such a value reaching a `.trim()`, a `.slice()`, a template
// literal or a SQL bind parameter throws — and a thrown Server Action rejects,
// producing exactly the framework error page STORE_ERROR exists to avoid.
//
// So every action below parses its whole input before touching a field,
// including the case where the input is not an object at all. The refusal names
// the FIELD and never its value: a payload that arrives as the wrong type is
// still a live credential, and a rejection is not a place to echo one. The name
// comes from the schema's own key, so nothing derived from the payload reaches
// the message.
//
// It branches on `wrongType` rather than always naming the type, because the
// parse is generic over any schema: every field is `z.string()` today, so every
// failure really is a type failure — but a `.min()` or `.uuid()` added to one of
// them would reject a value that IS text, and "did not arrive as text" would
// then be a false diagnosis pointing at the wrong fix.
function malformedInput(failure: ActionInputFailure): string {
  if (failure.field === null) {
    return 'The request did not arrive in the expected shape — reload the page and try again.';
  }
  return failure.wrongType
    ? `The '${failure.field}' field did not arrive as text — reload the page and try again.`
    : `The '${failure.field}' field was not in the expected form — reload the page and try again.`;
}

// Minting a key reads the store to find a version no stored row already claims,
// and refuses rather than guess when it cannot — so a key resolution can fail
// for a reason that is nothing to do with the key file.
const KEY_FLOOR_ERROR = `${STORE_ERROR} The fingerprint key cannot be minted until it is readable, because a key that reused a stored version would produce grants that never match.`;

// Three failures, three ways forward, and only the parse failure may be
// answered with "delete the file":
//   - the floor read gave up      → a store problem, tagged 'floor-unreadable'
//   - a filesystem error          → carries an errno `code`
//   - the strict key-file parse   → a plain Error with no `code`
function keyAccessError(err: unknown): string {
  const code: unknown = (err as { code?: unknown } | null)?.code;
  if (code === 'floor-unreadable') return KEY_FLOOR_ERROR;
  return typeof code === 'string' ? KEY_IO_ERROR : CORRUPT_KEY_ERROR;
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
 * retyped; re-checked here, not just in the dialog. A row fingerprinted under
 * a key version that is no longer current is refused: the grant could never
 * match.
 */
export async function approveBlocked(raw: ApproveBlockedInput): Promise<ActionResult> {
  const parsed = parseActionInput(ApproveBlockedInputSchema, raw);
  if (!parsed.ok) return { ok: false, error: malformedInput(parsed) };
  const input = parsed.data;

  const reason = input.reason.trim();
  if (reason === '') return { ok: false, error: 'A reason is required — it is the audit trail.' };
  const scope = resolveScope(input.scope);
  if ('error' in scope) return { ok: false, error: scope.error };

  // Looked up against the full retention window, not just the UI's currently
  // selected lookback — approving a row the user can see must not depend on
  // which filter chip happens to be active.
  let entry: BlockedDetection | undefined;
  try {
    entry = (await db().exceptions.recentBlocked(BLOCKED_DETECTIONS_RETENTION_MS)).find(
      (b) => b.reference === input.reference,
    );
  } catch {
    return { ok: false, error: STORE_ERROR };
  }
  if (!entry) {
    return {
      ok: false,
      error: 'That blocked detection has expired from the ledger — trigger it again.',
    };
  }

  // The ledger row carries the fingerprint computed when the hook blocked the
  // value, under whichever key version was live then. Enforcement fingerprints
  // under the CURRENT key and the bundle query is scoped to it, so a grant
  // minted from a rotated-away (or deleted) key could never match. Reject
  // rather than write a grant that is inert the moment it is created — the
  // ledger outlives a rotation, so this is one click away.
  //
  // Checked BEFORE the confirmation gate on purpose: an unusable row is
  // unusable whatever the user types, and asking someone to retype a masked
  // value only to then refuse the grant is worse than refusing it up front.
  let key: FingerprintKey | null;
  try {
    key = readFingerprintKey(dataDir());
  } catch (err) {
    return { ok: false, error: keyAccessError(err) };
  }
  if (!isCurrentKeyVersion(key, entry.keyVersion)) {
    return {
      ok: false,
      error:
        key === null
          ? 'The exception key file is missing, so the fingerprint recorded for this detection can no longer be matched. Trigger the detection again.'
          : `That detection was blocked under fingerprint key v${String(entry.keyVersion)}; the key is now v${String(key.version)}, so a grant from it could never match. Trigger the detection again.`,
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
 * discarded. Errors never echo `value`.
 *
 * Read that as scoped to `value`, because the other fields are not alike.
 * `ruleId` IS echoed, by the unknown-rule refusal below — safe for the id it is
 * meant to carry, and the reason the parse above matters: before it, an object
 * with a hostile `toString` posted as `ruleId` reached that template literal
 * and came back carrying whatever it yielded. It discloses nothing the caller
 * did not already send, but "errors never echo" was the claim, and the field
 * the claim was written about was not the field it travelled through.
 */
export async function addException(raw: AddExceptionInput): Promise<ActionResult> {
  const parsed = parseActionInput(AddExceptionInputSchema, raw);
  if (!parsed.ok) return { ok: false, error: malformedInput(parsed) };
  const input = parsed.data;

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
  // Typed with the schema's own Rule rather than left to an evolving `let`:
  // this is a contract boundary, and the annotation is what makes a change to
  // installedRuleset()'s shape fail here rather than downstream.
  let rules: Rule[];
  try {
    ({ rules } = db().installedPacks.installedRuleset());
  } catch {
    return { ok: false, error: STORE_ERROR };
  }
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

  // Only the key RESOLUTION is guarded: keyAccessError classifies key-file and
  // store failures, and a plain Error from anything else — a masking bug in
  // maskMatch, say — has no `code` and would come back as "your key is corrupt,
  // delete it". Deriving the fingerprint and preview outside the try keeps that
  // guidance attached to the failure it actually describes.
  let key: FingerprintKey;
  try {
    key = loadOrCreateFingerprintKey(dataDir());
  } catch (err) {
    // Unusable key file — fail secure with recovery guidance matched to the
    // reason (a corrupt file may be deleted; a permissions failure must not).
    return { ok: false, error: keyAccessError(err) };
  }
  const grant = {
    valueFingerprint: fingerprintValue(key, span),
    keyVersion: key.version,
    maskedValue: maskMatch(span),
  };

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

export type RevealGrantResult = { ok: true; grantIdPrefix: string } | { ok: false; error: string };

// The category segment of a shape-valid pointer. The PointerToken pattern pins
// the segment to the DetectionCategory members, so this only returns null for
// a string that never passed PointerToken.safeParse.
function categoryFromToken(token: string): DetectionCategory | null {
  const segment = token.slice('[[aka:'.length).split(':')[0] ?? '';
  const parsed = DetectionCategory.safeParse(segment);
  return parsed.success ? parsed.data : null;
}

/**
 * Mint a reveal-to-model grant from a resolved vault pointer (the dashboard
 * twin of `aka exception approve --reveal-to-model`). No raw value is touched:
 * the pointer resolves to the vault row's raw-free identity (rule + keyed
 * fingerprint + key version), which is exactly what the grant matches on. The
 * fingerprint never reaches the browser — only an id prefix comes back. Scope
 * timestamps and expiry are stamped server-side from the validated choice.
 *
 * `confirmation` is required when scope is permanent: the masked value retyped,
 * so a never-expiring reveal takes the same deliberate confirmation every other
 * permanent grant does.
 */
export async function grantRevealFromPointer(raw: GrantRevealInput): Promise<RevealGrantResult> {
  const shape = parseActionInput(GrantRevealInputSchema, raw);
  if (!shape.ok) return { ok: false, error: malformedInput(shape) };
  const input = shape.data;

  const justification = input.justification.trim();
  if (justification === '') {
    return { ok: false, error: 'A justification is required — it is the audit trail.' };
  }
  const scope = resolveScope(input.scope);
  if ('error' in scope) return { ok: false, error: scope.error };

  // Reject anything that is not pointer-shaped before it reaches the vault.
  const parsed = PointerToken.safeParse(input.pointer.trim());
  if (!parsed.success) {
    return { ok: false, error: 'Not a vault pointer — paste the full [[aka:...]] token.' };
  }

  let identity: PointerIdentity | null;
  let descriptor: PointerDescriptor | null;
  try {
    const vault = new SecretVault({
      repo: db().secretVault,
      keys: createKeyProvider(readWorkspaceSettings().vaultKeyCustody, keysDir()),
      // Read live so a consent revocation applies to the very next call.
      isConsented: () => isVaultConsentValid(readWorkspaceSettings().vaultConsent),
    });
    identity = await vault.resolvePointerIdentity(parsed.data);
    descriptor = identity === null ? null : await vault.describePointer(parsed.data);
  } catch {
    // Corrupt key file or unreadable store — same outward shape as an
    // unresolvable pointer; the error never carries store internals.
    identity = null;
    descriptor = null;
  }
  if (identity === null) {
    return {
      ok: false,
      error:
        'The pointer could not be resolved — it is not one this machine issued, or its entry was purged.',
    };
  }

  // The descriptor is presentation data; if it is unavailable the grant still
  // binds correctly through the identity, with a category recovered from the
  // token itself and a fully-opaque preview.
  const category = descriptor?.category ?? categoryFromToken(parsed.data);
  if (category === null) {
    return { ok: false, error: 'Not a vault pointer — paste the full [[aka:...]] token.' };
  }

  // A permanent reveal is the strongest grant in the product — a never-expiring
  // authorization for raw to reach the model. It takes the same value-specific
  // typed confirmation as every other permanent grant, re-checked here
  // server-side; without a descriptor there is nothing meaningful to retype, so
  // permanent is refused rather than waved through against an opaque preview.
  if (scope.scope === 'permanent') {
    if (descriptor === null) {
      return {
        ok: false,
        error:
          'A permanent reveal needs the value preview to confirm against — use a time-limited scope.',
      };
    }
    if (input.confirmation !== descriptor.maskedMatch) {
      return {
        ok: false,
        error: `A permanent reveal must be confirmed by retyping the masked value (${descriptor.maskedMatch}).`,
      };
    }
  }

  try {
    const created = await db().exceptions.create({
      ruleId: identity.ruleId,
      category,
      valueFingerprint: identity.valueFingerprint,
      keyVersion: identity.fingerprintKeyVersion,
      maskedValue: descriptor?.maskedMatch ?? '···',
      capability: 'reveal_to_model',
      ...scope,
      justification,
      conditions: null,
      createdBy: 'dashboard',
      createdVia: 'web-approve',
    });
    revalidatePath('/exceptions');
    return { ok: true, grantIdPrefix: created.id.slice(0, 8) };
  } catch (err) {
    if (err instanceof DuplicateActiveExceptionError) {
      return {
        ok: false,
        error: 'An active exception for this value already exists — revoke it first.',
      };
    }
    return { ok: false, error: 'Could not create the reveal grant.' };
  }
}

/**
 * Revoke an active grant (`aka exception revoke`) — terminal, audit-retained.
 * A blank reason is normalised away rather than stored: the column already
 * encodes "none given" as NULL, and an empty string would be a second encoding
 * of the same absence that reads as a recorded reason to anything asking
 * `revoke_reason IS NOT NULL`.
 */
export async function revokeException(id: string, reason: string): Promise<ActionResult> {
  // Positional arguments, parsed as one object so the shape of the call is
  // checked too. A non-string `id` would otherwise reach the repository as a
  // SQL bind parameter, whose refusal is indistinguishable here from a store
  // that cannot be read — and answering a malformed id with "your store is
  // unreadable" sends someone to repair a database that is fine.
  const parsed = parseActionInput(RevokeExceptionInputSchema, { id, reason });
  if (!parsed.ok) return { ok: false, error: malformedInput(parsed) };
  const input = parsed.data;

  const note = input.reason.trim();

  // Opening the handle and running the UPDATE are both synchronous, and the
  // repository wraps the result in an already-resolved promise — so a failing
  // store throws out of this call rather than rejecting a promise a `.catch`
  // could see, and an uncaught throw reaches the client as a framework error
  // page instead of the guidance every other action here returns. Kept separate
  // from the refusal below because the two need different answers: a store that
  // cannot be read is not evidence that the grant is gone, and saying so would
  // leave someone believing a still-active bypass had been taken away.
  let revoked: boolean;
  try {
    revoked = await db().exceptions.revoke(
      input.id,
      resolveCreatedBy(),
      note === '' ? undefined : note,
    );
  } catch {
    return { ok: false, error: STORE_ERROR };
  }
  if (!revoked) return { ok: false, error: 'No active exception with that id.' };
  revalidatePath('/exceptions');
  revalidatePath(`/exceptions/${input.id}`);
  return { ok: true };
}

/**
 * Rotate the fingerprint key (`aka exception rotate-key`) — INVALIDATION of
 * every existing grant. The typed confirmation is re-checked here; the dialog
 * gate alone is not the control.
 */
export async function rotateKey(confirmation: string): Promise<ActionResult> {
  // The `!==` below already REFUSES every non-string, so this parse changes no
  // accept/reject decision — only the message, from "type rotate to confirm"
  // (which a caller who posted a number cannot act on) to one naming the field.
  // Its real job is to make "every mutating action on this surface validates its
  // whole input" a property of the file rather than of four of its five
  // functions, and to stop the guarantee resting on one comparison operator that
  // a later "be more forgiving" edit could turn into `==`.
  const parsed = parseActionInput(RotateKeyInputSchema, { confirmation });
  if (!parsed.ok) return { ok: false, error: malformedInput(parsed) };

  if (parsed.data.confirmation !== 'rotate') {
    return { ok: false, error: 'Type "rotate" to confirm.' };
  }
  let next: FingerprintKey;
  try {
    next = rotateFingerprintKey(dataDir());
  } catch (err) {
    // Rotation keeps its own PREFIX — what is being refused is the rotation,
    // not a grant — but not its own classification. Rotation writes as well as
    // reads, so this catch sees permission and I/O failures too, and answering
    // one of those with "delete the key" destroys every grant on the machine to
    // fix a chmod. That is the harm KEY_IO_ERROR exists to stop, and the CLI's
    // runRotateKey already routes through the same split.
    return { ok: false, error: `Could not rotate the fingerprint key. ${keyAccessError(err)}` };
  }
  // Grants invalidate by design; vault entries must NOT. Re-key their
  // fingerprints under the new epoch so dedup keeps finding stored values —
  // otherwise a re-detected value fingerprints under the new key, misses its
  // row, and mints a second pointer for the same secret. Best-effort: a fault
  // here leaves skipped rows resolving under their old epoch and must not fail
  // the rotation that already happened.
  try {
    const vault = new SecretVault({
      repo: db().secretVault,
      keys: createKeyProvider(readWorkspaceSettings().vaultKeyCustody, keysDir()),
      isConsented: () => isVaultConsentValid(readWorkspaceSettings().vaultConsent),
    });
    await vault.refreshFingerprints(next);
  } catch {
    // The rotation itself succeeded; a skipped refresh only degrades dedup.
  }
  revalidatePath('/exceptions');
  return { ok: true };
}
