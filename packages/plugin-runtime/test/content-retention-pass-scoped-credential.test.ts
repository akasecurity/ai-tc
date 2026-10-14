import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  applyOnboarding,
  dataDir,
  dbPath,
  openLocalDatabase,
  readWorkspaceSettings,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runContentRetentionPass, syncLaneRetentionFor } from '../src/content-retention-pass.ts';

// Body retention on a machine whose credential file really is a scoped (v2)
// one, read by the real reader — no stand-in anywhere in this file. The pass
// suite beside it relabels a v1 read as scoped to decide the verdict; this one
// is what fails if the reader stops accepting a scoped credential. Refused, the
// sync lane resolves to no scope and holds every unsent body, so nothing is
// expired and the personal and unstamped bodies below would never be freed.

const DAY = 86_400_000;
const ENDPOINT = 'https://plane.example.test';
const AT = '2026-08-01T00:00:00.000Z';
const WORK = 'github.com/acme/work';
const PERSONAL = 'github.com/someone/personal';
// Built from parts so nothing in this file reads as a real credential.
const API_KEY = ['test', 'only', 'credential'].join('-');

let base: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-retention-scoped-cred-'));
});

afterEach(() => {
  removeTree(base);
});

/** Attached to one endpoint, with a scoped credential on disk and body expiry on. */
function attachScoped(): void {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
      attachmentScope: {
        endpoint: ENDPOINT,
        entries: [{ kind: 'repo', identity: WORK, enrolledAt: AT }],
      },
      bodyRetention: { enabled: true, retainDays: 30 },
    },
    base,
    null,
  );
  writeControlPlaneCredential(settingsDir(base), {
    specVersion: 2,
    mode: 'scoped',
    endpoint: ENDPOINT,
    apiKey: API_KEY,
    mintedAt: AT,
  });
}

// Three unsent sync-lane bodies past the horizon, written straight to the
// store so each carries exactly the key the case needs: one enrolled, one
// personal, one stamped with nothing.
function seedLane(): void {
  openLocalDatabase(dataDir(base)).close();
  const raw = new DatabaseSync(dbPath(base));
  try {
    const old = Date.now() - 60 * DAY;
    const insert = raw.prepare(
      `INSERT INTO audit_events (id, event_type, started_at, content, content_hash, attributes)
       VALUES (?, 'prompt', ?, ?, ?, ?)`,
    );
    insert.run(
      'enrolled',
      old,
      'w'.repeat(100),
      'hash-enrolled',
      JSON.stringify({ scope_key: WORK }),
    );
    insert.run(
      'personal',
      old,
      'p'.repeat(100),
      'hash-personal',
      JSON.stringify({ scope_key: PERSONAL }),
    );
    insert.run('unstamped', old, 'u'.repeat(100), 'hash-unstamped', JSON.stringify({}));
  } finally {
    raw.close();
  }
}

function bodyOf(id: string): string | null {
  const raw = new DatabaseSync(dbPath(base));
  try {
    return (
      raw.prepare('SELECT content FROM audit_events WHERE id = ?').get(id) as {
        content: string | null;
      }
    ).content;
  } finally {
    raw.close();
  }
}

describe('runContentRetentionPass — a scoped credential read from disk', () => {
  it('holds only the enrolled repository, as a scoped attachment owes it', () => {
    attachScoped();

    expect(syncLaneRetentionFor(readWorkspaceSettings(base), base)).toEqual({
      kind: 'hold-keys',
      keys: [WORK],
    });
  });

  it('expires the personal and the unstamped bodies and holds the enrolled one', () => {
    attachScoped();
    seedLane();

    expect(runContentRetentionPass({ base })).toEqual({
      ran: true,
      rowsExpired: 2,
      bytesFreed: 200,
      done: true,
    });
    expect(bodyOf('enrolled')).toBe('w'.repeat(100));
    expect(bodyOf('personal')).toBeNull();
    expect(bodyOf('unstamped')).toBeNull();
  });
});
