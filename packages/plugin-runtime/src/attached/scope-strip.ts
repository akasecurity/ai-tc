/**
 * The local scope key, kept off the wire.
 *
 * A structural producer stamps `attributes.scope_key` on what it records: the
 * canonical repository key (`host/owner/repo`) of the directory the row was
 * recorded in. It exists for a scoped attachment, which is meant to compare it
 * against the repositories it covers before a row leaves the machine; that
 * comparison is not part of this change. It is a fact for THIS machine and for
 * nothing on the far side of the wire.
 *
 * Nothing in the request shapes keeps it local. The attributes member of an
 * audit-event request is an open record (`AttributeBag`; the llm/tool bags carry
 * a catch-all), so the outbound parse passes an unknown key straight through
 * and the receiving side stores whatever arrived. Stripping it is therefore the
 * forward paths' job, at the two choke points every structural body passes:
 * `reKeyForForward` on the live path, and the history drain's
 * `rebuildAuditEvent`. A capture needs no strip: its key travels beside the
 * event on the capture record, never on the event itself.
 *
 * Stripped in EVERY attachment mode, not only a scoped one. Producers stamp
 * regardless of mode, so a machine attachment that skipped this would start
 * sending a member it never sent before.
 */

/**
 * `event` without `attributes.scope_key`.
 *
 * NON-MUTATING. The caller's object is still what the local store holds and
 * what gets stamped delivered, so this returns a copy whenever it changes
 * anything. When there is nothing to strip it returns the input itself,
 * untouched, which is what keeps an unstamped row byte-identical. That covers
 * an empty bag a producer wrote (`attributes: {}`) too.
 *
 * When the key was the bag's ONLY member, the bag goes too rather than leaving
 * `attributes: {}` behind. A producer that stamps a bare row (an
 * attribute-less session stub) must forward exactly what it forwarded before
 * it stamped.
 *
 * Any value under the name is dropped, string or not. It is the member that is
 * local, not a well-formed value of it.
 */
export function withoutScopeKey<T extends { attributes?: Record<string, unknown> | undefined }>(
  event: T,
): T {
  const attributes = event.attributes;
  if (attributes == null || !Object.hasOwn(attributes, 'scope_key')) return event;
  const rest: Record<string, unknown> = { ...attributes };
  delete rest.scope_key;
  if (Object.keys(rest).length > 0) return { ...event, attributes: rest };
  const bare = { ...event };
  delete bare.attributes;
  return bare;
}
