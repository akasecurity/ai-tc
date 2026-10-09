import { describe, expect, it } from 'vitest';

import { SOURCE_TOOL } from '../../src/zod/harness-map.ts';
import type { DetectedWebAccount } from '../../src/zod/web-account.ts';
import {
  DETECTED_WEB_ACCOUNTS_MAX,
  DETECTED_WEB_ACCOUNTS_SPEC_VERSION,
  detectedWebAccountsDocument,
  isWebAccountKey,
  normalizeWebAccountKey,
  parseDetectedWebAccounts,
  parseWebAccountKey,
  WEB_ACCOUNT_PROVIDER,
  webAccountKey,
  withDetectedWebAccount,
} from '../../src/zod/web-account.ts';

const ORG = '0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b';
const OTHER = 'a1b2c3d4-e5f6-4789-9abc-def012345678';
const KEY = `claude:${ORG}`;
const AT = '2026-10-09T10:00:00.000Z';
const LATER = '2026-10-09T11:00:00.000Z';

describe('webAccountKey', () => {
  it('names a claude.ai organization as claude:<uuid>', () => {
    expect(webAccountKey(SOURCE_TOOL.ClaudeAi, ORG)).toBe(KEY);
  });

  it('lower-cases the id, so one organization has one key', () => {
    expect(webAccountKey(SOURCE_TOOL.ClaudeAi, ORG.toUpperCase())).toBe(KEY);
  });

  // ChatGPT has no verified source for its workspace id, so no key is made for
  // it whatever is handed in.
  it('makes no key for a site with no account provider', () => {
    expect(webAccountKey(SOURCE_TOOL.ChatGpt, ORG)).toBeUndefined();
  });

  it.each([
    ['', 'empty'],
    ['not-a-uuid', 'not a uuid'],
    [`${ORG}/x`, 'a trailing segment'],
    [` ${ORG}`, 'surrounding space'],
    [`${ORG}\n`, 'a trailing newline'],
  ])('makes no key from %j (%s)', (id) => {
    expect(webAccountKey(SOURCE_TOOL.ClaudeAi, id)).toBeUndefined();
  });

  it('makes no key from a value that is not a string', () => {
    expect(webAccountKey(SOURCE_TOOL.ClaudeAi, 42)).toBeUndefined();
    expect(webAccountKey(SOURCE_TOOL.ClaudeAi, undefined)).toBeUndefined();
  });
});

describe('parseWebAccountKey', () => {
  it('splits a key into provider and id', () => {
    expect(parseWebAccountKey(KEY)).toEqual({
      provider: WEB_ACCOUNT_PROVIDER.Claude,
      workspaceId: ORG,
    });
  });

  it.each([
    [`Claude:${ORG}`, 'a provider in another case'],
    [`claude:${ORG.toUpperCase()}`, 'an id not lower-cased'],
    [`chatgpt:${ORG}`, 'a provider with no accounts yet'],
    [`claude:${ORG}:x`, 'a second colon'],
    [ORG, 'no provider'],
    ['github.com/acme/payments-api', 'a repository key'],
    ['', 'empty'],
  ])('refuses %j (%s)', (key) => {
    expect(parseWebAccountKey(key)).toBeUndefined();
    expect(isWebAccountKey(key)).toBe(false);
  });

  it('round-trips every key webAccountKey makes', () => {
    const key = webAccountKey(SOURCE_TOOL.ClaudeAi, OTHER.toUpperCase());
    expect(isWebAccountKey(key)).toBe(true);
  });
});

describe('normalizeWebAccountKey', () => {
  it('trims and lower-cases the id of a typed key', () => {
    expect(normalizeWebAccountKey(`  claude:${ORG.toUpperCase()}  `)).toBe(KEY);
  });

  // The provider is forgiven the same way, so a key copied from somewhere that
  // capitalises it still enrolls the account the extension stamps.
  it('trims and lower-cases the provider too, on either side of the colon', () => {
    expect(normalizeWebAccountKey(`CLAUDE:${ORG}`)).toBe(KEY);
    expect(normalizeWebAccountKey(`  Claude:${ORG}  `)).toBe(KEY);
    expect(normalizeWebAccountKey(`claude : ${ORG}`)).toBe(KEY);
  });

  it('refuses anything that names no account', () => {
    expect(normalizeWebAccountKey('github.com/acme/payments-api')).toBeUndefined();
    expect(normalizeWebAccountKey(`chatgpt:${ORG}`)).toBeUndefined();
    expect(normalizeWebAccountKey(`claude:${ORG}:extra`)).toBeUndefined();
    expect(normalizeWebAccountKey(ORG)).toBeUndefined();
    expect(normalizeWebAccountKey(undefined)).toBeUndefined();
  });

  // Only case and surrounding space are forgiven. A provider spelled with a
  // Cyrillic "а" lower-cases to itself and still names no provider.
  it('forgives no lookalike', () => {
    expect(normalizeWebAccountKey(`cl\u0430ude:${ORG}`)).toBeUndefined();
    expect(normalizeWebAccountKey(`claude:${ORG.slice(0, -1)}`)).toBeUndefined();
  });
});

describe('the detected-account record', () => {
  const seen = (identity: string, lastSeenAt: string): DetectedWebAccount => ({
    identity,
    tool: SOURCE_TOOL.ClaudeAi,
    firstSeenAt: AT,
    lastSeenAt,
  });

  it('reads a record back newest first', () => {
    const doc = detectedWebAccountsDocument([seen(KEY, AT), seen(`claude:${OTHER}`, LATER)]);
    expect(parseDetectedWebAccounts(doc).map((a) => a.identity)).toEqual([`claude:${OTHER}`, KEY]);
  });

  it('drops an invalid entry and keeps the rest', () => {
    const raw = {
      specVersion: DETECTED_WEB_ACCOUNTS_SPEC_VERSION,
      accounts: [seen(KEY, AT), { ...seen('not-a-key', AT) }, { identity: KEY }],
    };
    expect(parseDetectedWebAccounts(raw)).toEqual([seen(KEY, AT)]);
  });

  it('reads anything that is not a record of this version as empty', () => {
    expect(parseDetectedWebAccounts(undefined)).toEqual([]);
    expect(parseDetectedWebAccounts({ specVersion: 2, accounts: [seen(KEY, AT)] })).toEqual([]);
    expect(parseDetectedWebAccounts({ specVersion: 1 })).toEqual([]);
  });

  it('keeps the newest sight of an identity listed twice', () => {
    const raw = { specVersion: 1, accounts: [seen(KEY, AT), seen(KEY, LATER)] };
    expect(parseDetectedWebAccounts(raw)).toEqual([seen(KEY, LATER)]);
  });

  it('moves the last sight and keeps the first', () => {
    const next = withDetectedWebAccount([seen(KEY, AT)], KEY, SOURCE_TOOL.ClaudeAi, LATER);
    expect(next).toEqual([{ ...seen(KEY, LATER), firstSeenAt: AT }]);
  });

  it('adds a new account at the front', () => {
    const next = withDetectedWebAccount(
      [seen(KEY, AT)],
      `claude:${OTHER}`,
      SOURCE_TOOL.ClaudeAi,
      LATER,
    );
    expect(next.map((a) => a.identity)).toEqual([`claude:${OTHER}`, KEY]);
    expect(next[0]?.firstSeenAt).toBe(LATER);
  });

  it('refuses an identity that is not an account key', () => {
    const before = [seen(KEY, AT)];
    expect(withDetectedWebAccount(before, 'not-a-key', SOURCE_TOOL.ClaudeAi, LATER)).toEqual(
      before,
    );
  });

  it('keeps at most DETECTED_WEB_ACCOUNTS_MAX accounts, dropping the oldest', () => {
    let accounts: DetectedWebAccount[] = [];
    for (let i = 0; i <= DETECTED_WEB_ACCOUNTS_MAX; i += 1) {
      const id = `${i.toString(16).padStart(8, '0')}-0000-4000-8000-000000000000`;
      const at = new Date(Date.parse(AT) + i * 1000).toISOString();
      accounts = withDetectedWebAccount(accounts, `claude:${id}`, SOURCE_TOOL.ClaudeAi, at);
    }
    expect(accounts).toHaveLength(DETECTED_WEB_ACCOUNTS_MAX);
    expect(accounts.at(-1)?.identity).toBe('claude:00000001-0000-4000-8000-000000000000');
  });
});
