// The credential values a session has been given, held in this process's memory
// only. In the hook server they outlive one call, so a repeated handle is not
// resolved again and a later PostToolUse or transcript pass can recognise a
// value that was injected; in a one-shot hook process they last for that call.
// Nothing here writes to disk, logs or settings.
import type { CredentialRefusalReason, CredentialSlug } from '@akasecurity/schema';

/** Sessions remembered at once; the least recently used is dropped past this. */
export const MAX_REMEMBERED_SESSIONS = 32;

export interface SessionCredentials {
  readonly values: Map<CredentialSlug, string>;
  transcriptPath: string | undefined;
}

export interface ResolvedForCall {
  /** Values for the slugs that resolved, from memory or from the deployment. */
  readonly values: ReadonlyMap<CredentialSlug, string>;
  /** Slugs the deployment refused, with its reason. */
  readonly refused: readonly { slug: CredentialSlug; reason: CredentialRefusalReason }[];
  /** Slugs nothing answered for: not attached, a timeout or a fault. */
  readonly unanswered: readonly CredentialSlug[];
}

export type CredentialResolver = (
  slugs: readonly CredentialSlug[],
  sessionId: string | undefined,
) => Promise<
  | {
      resolved: { slug: CredentialSlug; value: string }[];
      refused: { slug: CredentialSlug; reason: CredentialRefusalReason }[];
    }
  | undefined
>;

const sessions = new Map<string, SessionCredentials>();

function sessionEntry(sessionId: string): SessionCredentials {
  let entry = sessions.get(sessionId);
  if (entry === undefined) {
    entry = { values: new Map(), transcriptPath: undefined };
  } else {
    sessions.delete(sessionId);
  }
  sessions.set(sessionId, entry);
  while (sessions.size > MAX_REMEMBERED_SESSIONS) {
    const oldest = sessions.keys().next().value;
    if (oldest === undefined) break;
    sessions.delete(oldest);
  }
  return entry;
}

/**
 * The values for `slugs` in this session: remembered ones first, the rest asked
 * of `resolve`. Values are remembered only under a session id; refusals are
 * never remembered, so a grant made mid-session takes effect on the next call.
 */
export async function resolveForSession(
  sessionId: string | undefined,
  slugs: readonly CredentialSlug[],
  resolve: CredentialResolver,
): Promise<ResolvedForCall> {
  const known = sessionId === undefined || sessionId === '' ? undefined : sessionEntry(sessionId);
  const values = new Map<CredentialSlug, string>();
  const missing: CredentialSlug[] = [];
  for (const slug of slugs) {
    const remembered = known?.values.get(slug);
    if (remembered === undefined) missing.push(slug);
    else values.set(slug, remembered);
  }
  if (missing.length === 0) return { values, refused: [], unanswered: [] };

  const answer = await resolve(missing, sessionId);
  if (answer === undefined) return { values, refused: [], unanswered: missing };
  const asked = new Set(missing);
  for (const { slug, value } of answer.resolved) {
    if (!asked.has(slug)) continue;
    values.set(slug, value);
    known?.values.set(slug, value);
  }
  const refused = answer.refused.filter(({ slug }) => asked.has(slug) && !values.has(slug));
  const answered = new Set([...values.keys(), ...refused.map(({ slug }) => slug)]);
  return { values, refused, unanswered: missing.filter((slug) => !answered.has(slug)) };
}

/** The values injected in `sessionId` so far (slug → value); empty when none. */
export function injectedValues(sessionId: string | undefined): ReadonlyMap<CredentialSlug, string> {
  if (sessionId === undefined) return new Map();
  return sessions.get(sessionId)?.values ?? new Map();
}

/** Remembers where the session's transcript is, for the transcript pass. */
export function noteTranscript(sessionId: string | undefined, transcriptPath: string | undefined) {
  if (sessionId === undefined || transcriptPath === undefined) return;
  const entry = sessions.get(sessionId);
  if (entry !== undefined) entry.transcriptPath = transcriptPath;
}

/** Every session holding at least one value, with its transcript when known. */
export function sessionsWithValues(): { sessionId: string; credentials: SessionCredentials }[] {
  return [...sessions.entries()]
    .filter(([, credentials]) => credentials.values.size > 0)
    .map(([sessionId, credentials]) => ({ sessionId, credentials }));
}

/** Drops every remembered value. */
export function forgetSessionCredentials(): void {
  sessions.clear();
}
