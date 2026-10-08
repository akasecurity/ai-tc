// Edits to the enrolled scope a SCOPED attachment forwards, made on the RAW
// stored record.
//
// RAW, never rebuilt from parseAttachmentScope. That parse drops what it cannot
// read — an entry a newer build wrote with a kind this build does not know, a
// key on the envelope it does not declare — and writing its output back would
// delete them for good. It would change retention too: a scoped attachment
// holds every owed body while any stored entry fails validation
// (syncLaneRetentionOf), and a rebuilt record would quietly stop doing so. So
// these append to, or filter, the stored `entries` list and copy every other key
// as found.
//
// A record that names the deployment but that this build cannot read (a binding
// field a newer build's bounds allow, say) is not replaced either: enrolling into
// it throws UnreadableAttachmentScopeError, so the caller writes nothing.
//
// Pure: no I/O. Run them inside applyOnboarding's updater, which hands over the
// file the merge is about to land on, so two writers cannot lose each other's
// edit.
import type { AttachmentScope, PluginWhoami } from '@akasecurity/schema';
import { AttachmentScopeEntry, isAttachmentScopeValid } from '@akasecurity/schema';

/**
 * Thrown by addAttachmentScopeEntries for a scope record that names the
 * endpoint but that this build cannot read, so that nothing is written over it.
 * The message is fixed text and repeats nothing from the record.
 */
export class UnreadableAttachmentScopeError extends Error {
  constructor() {
    super('refusing to enroll into a scope record this build cannot read');
    this.name = 'UnreadableAttachmentScopeError';
  }
}

/** Whether a raw record names `endpoint` as its deployment, whatever else it holds. */
function namesEndpoint(raw: unknown, endpoint: string): boolean {
  return typeof raw === 'object' && raw !== null && 'endpoint' in raw && raw.endpoint === endpoint;
}

/** The stored `entries` list of a raw record, or none. */
function storedEntries(raw: unknown): readonly unknown[] {
  if (typeof raw !== 'object' || raw === null || !('entries' in raw)) return [];
  const entries: unknown = raw.entries;
  return Array.isArray(entries) ? (entries as readonly unknown[]) : [];
}

/** A stored entry's `identity` as written, when it carries a string one. */
function storedIdentity(entry: unknown): string | undefined {
  if (typeof entry !== 'object' || entry === null || !('identity' in entry)) return undefined;
  return typeof entry.identity === 'string' ? entry.identity : undefined;
}

/** The record's own keys as found, with its `entries` replaced. */
function withEntries(raw: unknown, entries: readonly unknown[]): Record<string, unknown> {
  return { ...(raw as Record<string, unknown>), entries: [...entries] };
}

/**
 * A fresh, BOUND scope record for `endpoint`: nothing enrolled yet, and the
 * organization and account `who` names recorded beside it, so
 * isAttachmentScopeBoundTo can tell whether the record belongs to a given
 * organization and account.
 *
 * Only the two binding fields of `who` are copied, so a full whoami answer may
 * be passed without its role, key kind or server time reaching settings.json.
 */
export function freshAttachmentScope(
  endpoint: string,
  who: Pick<PluginWhoami, 'tenantName' | 'userEmail'>,
): AttachmentScope {
  return { endpoint, tenantName: who.tenantName, userEmail: who.userEmail, entries: [] };
}

/**
 * Enroll `entries` in the scope record for `endpoint`, editing the raw record.
 *
 * On a record that counts for `endpoint` (isAttachmentScopeValid), each entry
 * whose identity is not already enrolled is APPENDED, and everything else the
 * record carries is copied as found: its binding, any key a newer build put on
 * the envelope, and every stored entry, one this build cannot read included.
 * "Already enrolled" means a stored entry that reads as one carries the same
 * identity, byte for byte. A stored entry this build cannot read does not
 * count: it enrolls nothing here, so treating it as present would make this call
 * a silent no-op for an identity it was asked to add. An identity repeated
 * within `entries` is appended once, the first time.
 *
 * With no record for `endpoint` — none at all, as an older settings writer
 * leaves it, a value that is not a record, a record that names no endpoint, or
 * one for another deployment — the result is a NEW record holding just these
 * entries, and UNBOUND: it names no organization or account, so
 * isAttachmentScopeBoundTo answers false for it. It forwards what it lists, as
 * any record that counts for its endpoint does: the binding takes no part in the
 * forwarding verdict. Another deployment's record is not carried along; it
 * counted for nothing here.
 *
 * A record that names `endpoint` but does not count for it — a binding field
 * outside this build's bounds (a newer build may allow more), entries that are
 * not a list — is neither replaced nor repaired. Its entries may be another
 * build's, read and forwarded there, and a new record in its place would delete
 * them for good. Dropping the binding instead would make this build forward
 * every entry the record holds, which nobody asked for here, and the binding
 * cannot be worked out again without asking the deployment. So this THROWS
 * UnreadableAttachmentScopeError, and nothing should be written.
 *
 * `added` lists the identities appended, in order. When it is empty, `next` is
 * `raw` itself, so a caller can skip a write that would change nothing. That
 * includes a call with nothing to add on a record this build cannot read, which
 * is not refused.
 *
 * THROWS for an entry the schema would drop on read (an empty or unprintable
 * identity, a label over 80 characters, a bad timestamp) rather than store an
 * enrollment that could never take effect; the message repeats nothing of the
 * entry. Each appended entry is the schema's parse of the one given, so a stray
 * key on it is not stored. Never mutates `raw`.
 */
export function addAttachmentScopeEntries(
  raw: unknown,
  endpoint: string,
  entries: readonly AttachmentScopeEntry[],
): { next: unknown; added: readonly string[] } {
  const counts = isAttachmentScopeValid(raw, endpoint);
  const stored = counts ? storedEntries(raw) : [];
  const enrolled = new Set<string>();
  for (const candidate of stored) {
    const entry = AttachmentScopeEntry.safeParse(candidate);
    if (entry.success) enrolled.add(entry.data.identity);
  }
  const appended: AttachmentScopeEntry[] = [];
  for (const candidate of entries) {
    const entry = AttachmentScopeEntry.safeParse(candidate);
    if (!entry.success) {
      throw new Error('refusing to enroll an entry this build would not read back');
    }
    if (enrolled.has(entry.data.identity)) continue;
    enrolled.add(entry.data.identity);
    appended.push(entry.data);
  }
  const added = appended.map((entry) => entry.identity);
  if (appended.length === 0) return { next: raw, added };
  if (!counts && namesEndpoint(raw, endpoint)) throw new UnreadableAttachmentScopeError();
  if (!counts) return { next: { endpoint, entries: appended }, added };
  return { next: withEntries(raw, [...stored, ...appended]), added };
}

/**
 * Unenroll `identities` from the scope record for `endpoint`, editing the raw
 * record.
 *
 * Every stored entry whose `identity` is one of them, byte for byte, is removed,
 * one this build cannot otherwise read included: removing an entry means "stop
 * forwarding this", and an entry a newer build would read must not be left
 * behind to keep forwarding it there. Everything else the record carries is
 * copied as found.
 *
 * With no record that counts for `endpoint`, nothing is removed: another
 * deployment's record is not this function's to edit. `removed` lists each
 * identity that matched at least one stored entry, once, in the order asked.
 * When it is empty, `next` is `raw` itself. Never mutates `raw`.
 */
export function removeAttachmentScopeEntries(
  raw: unknown,
  endpoint: string,
  identities: readonly string[],
): { next: unknown; removed: readonly string[] } {
  if (!isAttachmentScopeValid(raw, endpoint)) return { next: raw, removed: [] };
  const asked = new Set(identities);
  const matched = new Set<string>();
  const kept = storedEntries(raw).filter((entry) => {
    const identity = storedIdentity(entry);
    if (identity === undefined || !asked.has(identity)) return true;
    matched.add(identity);
    return false;
  });
  const removed = [...asked].filter((identity) => matched.has(identity));
  return removed.length === 0 ? { next: raw, removed } : { next: withEntries(raw, kept), removed };
}
