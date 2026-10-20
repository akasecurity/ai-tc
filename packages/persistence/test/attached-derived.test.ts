import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  ATTACHED_CONFIG_INVENTORY_FILENAME,
  ATTACHED_CONFIG_INVENTORY_STATE_FILENAME,
  ATTACHED_DERIVED_FILENAMES,
  ATTACHED_FORWARD_DROPS_FILENAME,
  ATTACHED_FORWARD_STATE_FILENAME,
  ATTACHED_HISTORY_SYNC_STATE_FILENAME,
  ATTACHED_IDENTITY_FILENAME,
  ATTACHED_LABEL_SYNC_FILENAME,
  ATTACHED_POSTURE_REPORT_FILENAME,
  ATTACHED_SYNC_STATE_FILENAME,
  clearAttachmentDerivedState,
  POLICY_CACHE_FILENAME,
} from '../src/attached-derived.ts';
import { SESSION_ACCOUNTS_DIRNAME } from '../src/session-accounts.ts';
import { useTempStore } from './helpers/temp-store.ts';

describe('ATTACHED_DERIVED_FILENAMES', () => {
  // Both detach surfaces clear exactly this list, and the dashboard's detach
  // test iterates it for its seed and its assertion alike — so that test proves
  // the clear, never the membership. This pins the membership, EXACTLY: an
  // entry dropped would leave a file describing a deployment the machine has
  // left, and an entry added would clear something detach must leave alone.
  it('names exactly the ten files an attachment leaves behind', () => {
    expect(ATTACHED_DERIVED_FILENAMES).toHaveLength(10);
    expect(new Set(ATTACHED_DERIVED_FILENAMES)).toEqual(
      new Set([
        POLICY_CACHE_FILENAME,
        ATTACHED_SYNC_STATE_FILENAME,
        ATTACHED_FORWARD_STATE_FILENAME,
        ATTACHED_FORWARD_DROPS_FILENAME,
        ATTACHED_POSTURE_REPORT_FILENAME,
        ATTACHED_HISTORY_SYNC_STATE_FILENAME,
        ATTACHED_LABEL_SYNC_FILENAME,
        ATTACHED_IDENTITY_FILENAME,
        ATTACHED_CONFIG_INVENTORY_FILENAME,
        ATTACHED_CONFIG_INVENTORY_STATE_FILENAME,
      ]),
    );
  });
});

describe('clearAttachmentDerivedState', () => {
  const store = useTempStore('aka-attached-derived-');

  it('removes every file on the list', () => {
    for (const name of ATTACHED_DERIVED_FILENAMES) writeFileSync(join(store.dataDir, name), '{}');
    clearAttachmentDerivedState(store.dataDir);
    for (const name of ATTACHED_DERIVED_FILENAMES) {
      expect(existsSync(join(store.dataDir, name)), `${name} outlived the clear`).toBe(false);
    }
  });

  // A directory, which the per-file removal above cannot take.
  it('detach removes session-accounts', () => {
    const dir = join(store.dataDir, SESSION_ACCOUNTS_DIRNAME);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 's-1.log'), '{}\n');
    writeFileSync(join(dir, 's-1.scan.json'), '{}');
    clearAttachmentDerivedState(store.dataDir);
    expect(existsSync(dir)).toBe(false);
  });
});
