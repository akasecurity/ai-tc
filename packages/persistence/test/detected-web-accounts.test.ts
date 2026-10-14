import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { SOURCE_TOOL } from '@akasecurity/schema';
import { describe, expect, it } from 'vitest';

import {
  clearDetectedWebAccounts,
  DETECTED_WEB_ACCOUNT_RESIGHT_MS,
  DETECTED_WEB_ACCOUNTS_FILENAME,
  readDetectedWebAccounts,
  recordDetectedWebAccount,
} from '../src/detected-web-accounts.ts';
import { useTempStore } from './helpers/temp-store.ts';

// The detected-account record: what `aka enroll --list-detected` reads. The
// account grant is the caller's check; these cases drive the file itself.

const store = useTempStore('aka-detected-web-accounts-');

const KEY = 'claude:0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b';
const OTHER = 'claude:a1b2c3d4-e5f6-4789-9abc-def012345678';
const AT = new Date('2026-10-09T10:00:00.000Z');

const fileOf = (): string => join(store.dataDir, DETECTED_WEB_ACCOUNTS_FILENAME);

describe('the detected-account record', () => {
  it('reads as empty when nothing was recorded', () => {
    expect(readDetectedWebAccounts(store.dataDir)).toEqual([]);
  });

  it('records a sighting and reads it back', () => {
    expect(recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, AT)).toBe(true);
    expect(readDetectedWebAccounts(store.dataDir)).toEqual([
      {
        identity: KEY,
        tool: SOURCE_TOOL.ClaudeAi,
        firstSeenAt: AT.toISOString(),
        lastSeenAt: AT.toISOString(),
      },
    ]);
  });

  it('writes the file owner-only', (ctx) => {
    if (process.platform === 'win32') ctx.skip('POSIX modes do not apply on Windows');
    recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, AT);
    expect(statSync(fileOf()).mode & 0o777).toBe(0o600);
  });

  // A busy chat would otherwise rewrite the file on every turn.
  it('does not rewrite for a sighting inside the resight window', () => {
    recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, AT);
    const before = readFileSync(fileOf(), 'utf8');
    const soon = new Date(AT.getTime() + DETECTED_WEB_ACCOUNT_RESIGHT_MS - 1);
    expect(recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, soon)).toBe(true);
    expect(readFileSync(fileOf(), 'utf8')).toBe(before);
  });

  it('moves the last sight once the window has passed, and keeps the first', () => {
    recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, AT);
    const later = new Date(AT.getTime() + DETECTED_WEB_ACCOUNT_RESIGHT_MS);
    recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, later);
    expect(readDetectedWebAccounts(store.dataDir)).toEqual([
      {
        identity: KEY,
        tool: SOURCE_TOOL.ClaudeAi,
        firstSeenAt: AT.toISOString(),
        lastSeenAt: later.toISOString(),
      },
    ]);
  });

  it('adds a second account in front of the first', () => {
    recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, AT);
    recordDetectedWebAccount(
      store.dataDir,
      OTHER,
      SOURCE_TOOL.ClaudeAi,
      new Date(AT.getTime() + 1),
    );
    expect(readDetectedWebAccounts(store.dataDir).map((a) => a.identity)).toEqual([OTHER, KEY]);
  });

  it('refuses an identity that is not an account key, and writes nothing', () => {
    expect(
      recordDetectedWebAccount(store.dataDir, 'github.com/acme/api', SOURCE_TOOL.ClaudeAi, AT),
    ).toBe(false);
    expect(readDetectedWebAccounts(store.dataDir)).toEqual([]);
  });

  it('reads a damaged file as empty, and a later sighting replaces it', () => {
    writeFileSync(fileOf(), '{ not json');
    expect(readDetectedWebAccounts(store.dataDir)).toEqual([]);
    expect(recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, AT)).toBe(true);
    expect(readDetectedWebAccounts(store.dataDir).map((a) => a.identity)).toEqual([KEY]);
  });

  it('is deleted whole when cleared', () => {
    recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, AT);
    expect(clearDetectedWebAccounts(store.dataDir)).toBe(true);
    expect(readDetectedWebAccounts(store.dataDir)).toEqual([]);
    // Clearing what is not there is still a clean answer.
    expect(clearDetectedWebAccounts(store.dataDir)).toBe(true);
  });

  it('reports a write it could not make', () => {
    // A directory where the file should be: the publish's rename cannot replace it.
    recordDetectedWebAccount(store.dataDir, KEY, SOURCE_TOOL.ClaudeAi, AT);
    clearDetectedWebAccounts(store.dataDir);
    mkdirSync(fileOf());
    expect(recordDetectedWebAccount(store.dataDir, OTHER, SOURCE_TOOL.ClaudeAi, AT)).toBe(false);
  });
});
