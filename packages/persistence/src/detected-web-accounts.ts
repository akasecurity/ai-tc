import { readFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';

import type { DetectedWebAccount, WebSourceTool } from '@akasecurity/schema';
import {
  detectedWebAccountsDocument,
  parseDetectedWebAccounts,
  withDetectedWebAccount,
} from '@akasecurity/schema';

import { withFileLock } from './file-lock.ts';
import { ensureDataDirSync, writeOwnerOnlyFileSync } from './paths.ts';

// The web chat accounts this machine's browser extension saw a site's own
// requests name, kept for `aka enroll --list-detected`.
//
// A file of its own rather than store rows: it is account data, not a capture,
// it is written only under the account grant (isWebChatAccountGrantValid), and
// revoking that grant deletes it whole. The native host is its only writer and
// takes the lock below for every write, so two host processes cannot lose each
// other's sightings. Owner-only, like every file under the data dir.
export const DETECTED_WEB_ACCOUNTS_FILENAME = 'detected-web-accounts.json';

// How stale an account's last sight may be before another sighting rewrites the
// file. Without it every assistant turn would rewrite it; with it, a busy chat
// costs one write an hour, and `--list-detected` is never more than an hour out.
export const DETECTED_WEB_ACCOUNT_RESIGHT_MS = 60 * 60 * 1000;

function fileOf(dataDir: string): string {
  return join(dataDir, DETECTED_WEB_ACCOUNTS_FILENAME);
}

/**
 * The accounts recorded under `dataDir`, newest sight first, or `[]` when there
 * is no record or it cannot be read or parsed. Never throws.
 */
export function readDetectedWebAccounts(dataDir: string): DetectedWebAccount[] {
  try {
    return parseDetectedWebAccounts(JSON.parse(readFileSync(fileOf(dataDir), 'utf8')));
  } catch {
    return [];
  }
}

/**
 * Record that `identity` was seen on `tool` at `at`. Writes only when the account
 * is new or its last sight is older than DETECTED_WEB_ACCOUNT_RESIGHT_MS, and
 * never writes an identity that is not an account key.
 *
 * The CALLER checks the account grant; this only writes. Returns whether the
 * record now holds the sighting (true when nothing needed writing), false when
 * the write failed. Never throws.
 */
export function recordDetectedWebAccount(
  dataDir: string,
  identity: string,
  tool: WebSourceTool,
  at: Date = new Date(),
): boolean {
  try {
    const when = at.toISOString();
    ensureDataDirSync(dataDir);
    const file = fileOf(dataDir);
    return withFileLock(file, () => {
      const current = readDetectedWebAccounts(dataDir);
      const seen = current.find((account) => account.identity === identity);
      if (
        seen !== undefined &&
        at.getTime() - Date.parse(seen.lastSeenAt) < DETECTED_WEB_ACCOUNT_RESIGHT_MS
      ) {
        return true;
      }
      const next = withDetectedWebAccount(current, identity, tool, when);
      if (!next.some((account) => account.identity === identity)) return false;
      writeOwnerOnlyFileSync(
        file,
        `${JSON.stringify(detectedWebAccountsDocument(next), null, 2)}\n`,
      );
      return true;
    });
  } catch {
    return false;
  }
}

/**
 * Delete the record, as revoking the account grant does. Returns whether there
 * is no record afterwards. Never throws.
 */
export function clearDetectedWebAccounts(dataDir: string): boolean {
  try {
    const file = fileOf(dataDir);
    ensureDataDirSync(dataDir);
    withFileLock(file, () => {
      rmSync(file, { force: true });
    });
    return true;
  } catch {
    return false;
  }
}
