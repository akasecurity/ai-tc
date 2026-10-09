import { z } from 'zod';

import { SOURCE_TOOL, WebSourceTool } from './harness-map.ts';

// The account a web chat is signed in to, as a scope key: `<provider>:<workspace-id>`.
//
// It is what `aka enroll --account` stores in a scoped attachment's entries, what
// the browser extension's host stamps on what it records from that account, and
// what the detected-account record lists. One grammar for all three, so a key the
// host stamps is always one a user can enroll, and the reverse.
//
// Pure, with no I/O, and never throws.

// The providers a web account key can name, by member. A provider joins only
// once its workspace id has a verified source: claude.ai's completion route names
// the active organization in its own path. ChatGPT has none yet.
export const WEB_ACCOUNT_PROVIDER = {
  Claude: 'claude',
} as const;
export type WebAccountProvider = (typeof WEB_ACCOUNT_PROVIDER)[keyof typeof WEB_ACCOUNT_PROVIDER];

/**
 * The provider whose accounts each web chat site signs in to, or `undefined` for
 * a site whose account cannot be read yet. Annotated over the whole web vocabulary,
 * so a site added there is a compile error here until someone decides.
 */
export const WEB_ACCOUNT_PROVIDER_OF: Record<WebSourceTool, WebAccountProvider | undefined> = {
  [SOURCE_TOOL.ClaudeAi]: WEB_ACCOUNT_PROVIDER.Claude,
  [SOURCE_TOOL.ChatGpt]: undefined,
};

// A claude.ai organization id: a UUID, lower-cased in the key so the same
// organization has one key however a URL spelled it.
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

const WORKSPACE_ID: Record<WebAccountProvider, RegExp> = {
  [WEB_ACCOUNT_PROVIDER.Claude]: UUID,
};

function isProvider(value: string): value is WebAccountProvider {
  return Object.values(WEB_ACCOUNT_PROVIDER).includes(value as WebAccountProvider);
}

/**
 * The account key for a workspace id a site's own request named, or `undefined`
 * when the site has no account provider or the id is not one of its ids.
 *
 * The id is lower-cased first: a UUID's hex digits are case-insensitive, and two
 * spellings of one organization must not become two keys.
 */
export function webAccountKey(tool: WebSourceTool, workspaceId: unknown): string | undefined {
  try {
    const provider = WEB_ACCOUNT_PROVIDER_OF[tool];
    if (provider === undefined || typeof workspaceId !== 'string') return undefined;
    const id = workspaceId.toLowerCase();
    return WORKSPACE_ID[provider].test(id) ? `${provider}:${id}` : undefined;
  } catch {
    return undefined;
  }
}

/**
 * A key split into its provider and workspace id, or `undefined` when it is not
 * exactly a web account key: a known provider, one colon, and an id in that
 * provider's grammar, already lower-cased.
 */
export function parseWebAccountKey(
  key: unknown,
): { provider: WebAccountProvider; workspaceId: string } | undefined {
  try {
    if (typeof key !== 'string') return undefined;
    const at = key.indexOf(':');
    if (at === -1) return undefined;
    const provider = key.slice(0, at);
    const workspaceId = key.slice(at + 1);
    if (!isProvider(provider)) return undefined;
    return WORKSPACE_ID[provider].test(workspaceId) ? { provider, workspaceId } : undefined;
  } catch {
    return undefined;
  }
}

/** Whether `key` is exactly a web account key (see parseWebAccountKey). */
export function isWebAccountKey(key: unknown): boolean {
  return parseWebAccountKey(key) !== undefined;
}

/**
 * The account key a user typed, normalized to the stored form, or `undefined`
 * when it names no web account. Surrounding whitespace is dropped and the id is
 * lower-cased, so a key copied with different case enrolls the same account.
 */
export function normalizeWebAccountKey(input: unknown): string | undefined {
  if (typeof input !== 'string') return undefined;
  const typed = input.trim();
  const at = typed.indexOf(':');
  if (at === -1) return undefined;
  const key = `${typed.slice(0, at)}:${typed.slice(at + 1).toLowerCase()}`;
  return isWebAccountKey(key) ? key : undefined;
}

// The most accounts the detected-account record keeps. The oldest by last sight
// is dropped first, so the record cannot grow without bound.
export const DETECTED_WEB_ACCOUNTS_MAX = 32;

export const DETECTED_WEB_ACCOUNTS_SPEC_VERSION = 1;

/**
 * One web chat account this machine's browser extension saw a site's own request
 * name: the key, the site, and when it was first and last seen.
 *
 * Content-free by construction: no account name, email, plan, conversation or
 * text. It is account data all the same, so it is written only under the
 * `webChatCapture.account` grant (isWebChatAccountGrantValid).
 */
export const DetectedWebAccount = z.object({
  identity: z.string().refine(isWebAccountKey),
  tool: WebSourceTool,
  firstSeenAt: z.iso.datetime(),
  lastSeenAt: z.iso.datetime(),
});
export type DetectedWebAccount = z.infer<typeof DetectedWebAccount>;

/** The stored record: every account seen, newest sight first. */
export const DetectedWebAccounts = z.object({
  specVersion: z.literal(DETECTED_WEB_ACCOUNTS_SPEC_VERSION),
  accounts: z.array(DetectedWebAccount),
});
export type DetectedWebAccounts = z.infer<typeof DetectedWebAccounts>;

// The envelope with its entries left unread, so one bad entry costs that entry
// alone.
const DetectedWebAccountsEnvelope = DetectedWebAccounts.extend({ accounts: z.array(z.unknown()) });

/**
 * The accounts a stored record holds, newest sight first, or `[]` for anything
 * that is not a record of this version. Each entry is validated on its own and an
 * invalid one is dropped; a repeated identity keeps its newest sight. Never throws.
 */
export function parseDetectedWebAccounts(raw: unknown): DetectedWebAccount[] {
  try {
    const envelope = DetectedWebAccountsEnvelope.safeParse(raw);
    if (!envelope.success) return [];
    const byIdentity = new Map<string, DetectedWebAccount>();
    for (const candidate of envelope.data.accounts) {
      const entry = DetectedWebAccount.safeParse(candidate);
      if (!entry.success) continue;
      const seen = byIdentity.get(entry.data.identity);
      if (seen === undefined || seen.lastSeenAt < entry.data.lastSeenAt) {
        byIdentity.set(entry.data.identity, entry.data);
      }
    }
    return [...byIdentity.values()].sort((a, b) =>
      a.lastSeenAt < b.lastSeenAt ? 1 : a.lastSeenAt > b.lastSeenAt ? -1 : 0,
    );
  } catch {
    return [];
  }
}

/**
 * The record with `identity` seen on `tool` at `at`: its first sight kept, its
 * last sight moved, newest first, and cut to DETECTED_WEB_ACCOUNTS_MAX. Returns
 * the record unchanged when `identity` is not an account key or `at` is not a
 * time. Pure.
 */
export function withDetectedWebAccount(
  accounts: readonly DetectedWebAccount[],
  identity: string,
  tool: WebSourceTool,
  at: string,
): DetectedWebAccount[] {
  const seen = accounts.find((account) => account.identity === identity);
  const entry = DetectedWebAccount.safeParse({
    identity,
    tool,
    firstSeenAt: seen?.firstSeenAt ?? at,
    lastSeenAt: at,
  });
  if (!entry.success) return [...accounts];
  return [entry.data, ...accounts.filter((account) => account.identity !== identity)].slice(
    0,
    DETECTED_WEB_ACCOUNTS_MAX,
  );
}

/** The stored form of a record. */
export function detectedWebAccountsDocument(
  accounts: readonly DetectedWebAccount[],
): DetectedWebAccounts {
  return { specVersion: DETECTED_WEB_ACCOUNTS_SPEC_VERSION, accounts: [...accounts] };
}
