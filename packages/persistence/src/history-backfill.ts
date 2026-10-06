import { existsSync } from 'node:fs';
import { join } from 'node:path';

import type { WorkspaceSettings } from '@akasecurity/schema';
import { attachmentModeOf, resolveScope, scopeFilterOf } from '@akasecurity/schema';

import type { CredentialFileRead } from './control-plane-credential.ts';
import { openLocalDatabase } from './database.ts';
import { DB_FILENAME } from './paths.ts';

/**
 * Mark every capture already on disk as owed, as of `beforeMs`.
 *
 * The consent-time backfill for the existing-history grant's capture half.
 * Three surfaces record a fresh `historySyncConsent` — `aka attach`,
 * `aka sync-history --on`, and the dashboard's settings action — and each
 * calls this once, right after that write succeeds, with its own "now" as
 * `beforeMs`. What gets marked owed is exactly what is on disk at that
 * instant, never a boundary a later pass could widen; see
 * `SqliteHistorySyncRepository.markCaptureBacklogOwed` for why a marker
 * rather than a time window is what the drain reads at all.
 *
 * SCOPED on a scoped attachment: `scopeKeys` is the caller's `scopeFilterOf(...)`
 * answer. `undefined` marks every capture as before, a list marks only captures
 * stamped with one of its keys, and an empty list marks nothing.
 *
 * BEST-EFFORT and deliberately silent, for the reason
 * `clearAttachmentDerivedState` gives for its own callers: the grant has
 * already been recorded by the time anything reaches this, and a store that
 * cannot be opened or written must not turn a successful consent into a
 * reported failure. A miss here is not permanent — the next grant (a
 * re-attach, or running this command again) calls this again with a newer
 * bound and covers whatever this pass missed, on top of whatever it already
 * marked.
 *
 * NO STORE IS NOT A STORE THAT FAILED TO OPEN — the same distinction
 * `readLocalHistoryPreview` draws on the same `aka attach` prompt path, and
 * for the same reason: a machine that has never run `aka init` has no
 * capture backlog to mark by definition, so opening `openLocalDatabase` here
 * would create the file and run every migration in the ledger — synchronously,
 * inside this catch, after the attach has already been reported successful —
 * to mark zero rows. Skip before that call ever runs, exactly as the preview
 * does with `existsSync`.
 */
export function seedCaptureBacklogOwed(
  dataDir: string,
  beforeMs: number,
  scopeKeys?: readonly string[],
): void {
  if (!existsSync(join(dataDir, DB_FILENAME))) return;
  try {
    const db = openLocalDatabase(dataDir);
    try {
      db.historySync.markCaptureBacklogOwed(beforeMs, scopeKeys);
    } finally {
      db.close();
    }
  } catch {
    // See above: a ledger write that fails here does not undo the grant that
    // was just recorded, and the next one retries it.
  }
}

/**
 * The key list the consent-time capture seed marks under: the same scope the
 * drain reads with, so the seed and the read agree about what this machine
 * forwards. Hand it to `seedCaptureBacklogOwed` as `scopeKeys`.
 *
 * `read` is the credential file's read result and `settings` the settings the
 * caller holds; the caller does the reading, so this does no I/O. Pass
 * `undefined` for `read` when there is no connection to read a credential for.
 *
 * `undefined` (every capture, as before) on a machine attachment, and whenever
 * the credential cannot be read or there is no connection: the mode lives on the
 * credential, so without it there is nothing to scope by. That is safe rather
 * than merely permissive, because marking is not sending: the drain cannot run
 * without a usable credential, and once it can, its capture read applies the
 * scope in SQL whatever this marked. On a scoped attachment it is the keys
 * enrolled for the connection's endpoint, possibly none, and an empty list marks
 * nothing.
 */
export function captureBackfillScope(
  read: CredentialFileRead | undefined,
  settings: WorkspaceSettings,
): readonly string[] | undefined {
  const connection = settings.controlPlane;
  if (connection === undefined || !read?.usable) return undefined;
  return scopeFilterOf(
    resolveScope({
      mode: attachmentModeOf(read.credential),
      scope: settings.attachmentScope,
      endpoint: connection.endpoint,
    }),
  );
}
