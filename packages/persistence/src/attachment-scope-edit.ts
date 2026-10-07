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
// Pure: no I/O. Run them inside applyOnboarding's updater, which hands over the
// file the merge is about to land on, so two writers cannot lose each other's
// edit.
import type { AttachmentScope, PluginWhoami } from '@akasecurity/schema';
import { AttachmentScopeEntry, isAttachmentScopeValid } from '@akasecurity/schema';

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
 * organization and account the deployment verified recorded beside it, so a
 * later re-attach can tell whether the record is this account's to keep
 * (isAttachmentScopeBoundTo).
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
 * count: it enrolls nothing here, so treating it as present would turn the
 * user's enroll into a silent no-op. An identity repeated within `entries` is
 * appended once, the first time.
 *
 * With no record that counts for `endpoint` — none at all, as an older settings
 * writer leaves it, a damaged one, or one for another deployment — the result is
 * a NEW record holding just these entries, and UNBOUND: it names no
 * organization or account. It forwards what it lists, since those entries were
 * enrolled under the credential now in force, but the next re-attach cannot
 * confirm whose it is and does not keep it. Another deployment's record is not
 * carried along; it counted for nothing here.
 *
 * `added` lists the identities appended, in order. When it is empty, `next` is
 * `raw` itself, so a caller can skip a write that would change nothing.
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
  if (!counts) return { next: { endpoint, entries: appended }, added };
  return { next: withEntries(raw, [...stored, ...appended]), added };
}

/**
 * Unenroll `identities` from the scope record for `endpoint`, editing the raw
 * record.
 *
 * Every stored entry whose `identity` is one of them, byte for byte, is removed,
 * one this build cannot otherwise read included: unenrolling means "stop
 * forwarding this", and an entry a newer build would read must not be left
 * behind to keep forwarding it there. Everything else the record carries is
 * copied as found.
 *
 * With no record that counts for `endpoint`, nothing is removed: another
 * deployment's record is not this command's to edit. `removed` lists each
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
