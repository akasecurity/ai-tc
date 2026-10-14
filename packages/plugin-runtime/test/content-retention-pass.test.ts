/**
 * The detached child's program.
 *
 * It re-reads the setting rather than trusting the parent that spawned it, and
 * it never throws — it runs with stdio ignored and nobody watching, so a
 * rejection would be an unhandled rejection that reaches no one.
 */
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type * as Persistence from '@akasecurity/persistence';
import {
  applyOnboarding,
  controlPlaneCredentialPath,
  dataDir,
  dbPath,
  openLocalDatabase,
  settingsDir,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../test/helpers/remove-tree.ts';
import { runContentRetentionPass } from '../src/content-retention-pass.ts';

// The credential reader's answer, re-labelled on request. Which credential
// versions the reader accepts is not this suite's concern, so a scoped
// attachment here is the real version-1 credential a case wrote, handed to the
// pass as a scoped one; `throws` stands in for a read that fails outright.
// Every other case gets the real reader.
const reader = vi.hoisted((): { mode: 'real' | 'scoped' | 'throws' } => ({ mode: 'real' }));
vi.mock('@akasecurity/persistence', async (importOriginal) => {
  const actual = await importOriginal<typeof Persistence>();
  return {
    ...actual,
    readControlPlaneCredentialFile: (
      ...args: Parameters<typeof actual.readControlPlaneCredentialFile>
    ) => {
      if (reader.mode === 'throws') throw new Error('credential read failed');
      const read = actual.readControlPlaneCredentialFile(...args);
      if (reader.mode !== 'scoped' || !read.usable) return read;
      return { usable: true, credential: { ...read.credential, specVersion: 2, mode: 'scoped' } };
    },
  };
});

const DAY = 86_400_000;
let base: string;

function seedBody(ageDays: number, bytes = 500): void {
  const db = openLocalDatabase(dataDir(base));
  db.recordCapture(
    {
      id: `evt-${String(ageDays)}-${String(bytes)}`,
      sourceTool: 'claude-code',
      kind: 'code_change',
      occurredAt: new Date(Date.now() - ageDays * DAY).toISOString(),
      contentHash: `hash-${String(ageDays)}-${String(bytes)}`,
      content: 'x'.repeat(bytes),
      metadata: { sessionId: `sess-${String(ageDays)}`, filePath: 'src/a.ts' },
    },
    [],
  );
}

describe('runContentRetentionPass', () => {
  beforeEach(() => {
    base = mkdtempSync(join(tmpdir(), 'aka-retention-pass-'));
  });
  afterEach(() => {
    removeTree(base);
  });

  it('makes no pass while the setting is off', () => {
    seedBody(60);
    expect(runContentRetentionPass({ base })).toEqual({ ran: false, reason: 'disabled' });
  });

  it('expires past the configured horizon once switched on', () => {
    seedBody(60);
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);

    const report = runContentRetentionPass({ base });
    expect(report).toEqual({ ran: true, rowsExpired: 1, bytesFreed: 500, done: true });
  });

  it('spares a body inside the horizon', () => {
    seedBody(1);
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);

    const report = runContentRetentionPass({ base });
    expect(report).toEqual({ ran: true, rowsExpired: 0, bytesFreed: 0, done: true });
  });

  it('re-reads the setting rather than trusting whoever spawned it', () => {
    seedBody(60);
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);
    // Switched back off between the spawn and the pass — which is a real window,
    // and the thing being decided is whether to destroy data.
    applyOnboarding({ bodyRetention: { enabled: false, retainDays: 30 } }, base, null);

    expect(runContentRetentionPass({ base })).toEqual({ ran: false, reason: 'disabled' });
  });

  it('reads a corrupt settings file as an unonboarded machine, so the pass is DISABLED', () => {
    // Not the `unreadable` branch, and worth pinning as its own fact because it
    // reads like one: `readUserSettings` already fails open to
    // `defaultWorkspaceSettings()` on a corrupt file, so expiry comes back off
    // and the pass declines before it ever opens a store. An enabled setting
    // written beforehand is overwritten by the corruption and does nothing.
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);
    writeFileSync(join(settingsDir(base), 'settings.json'), '{ not json');

    expect(runContentRetentionPass({ base })).toEqual({ ran: false, reason: 'disabled' });
  });

  it('reports rather than throws when the STORE cannot be opened', () => {
    // The `catch` is this function's whole safety property — it runs detached
    // with stdio ignored and nobody watching, so a throw reaches no one at all —
    // and it is the one branch nothing else reaches. Settings stay valid and
    // enabled; the store is what is broken, which is also the likelier failure
    // for an hourly background pass.
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);
    mkdirSync(join(dataDir(base), 'aka.db'), { recursive: true });

    // The exact reason, not merely `ran: false` — `disabled` is what a setup
    // that does not do what it reads as doing would report here.
    expect(runContentRetentionPass({ base })).toEqual({ ran: false, reason: 'unreadable' });
  });

  // The scope keys a sync-lane body can carry, and the attachment instant, shared
  // by the standalone control and the attachment cases.
  const AT = '2026-08-01T00:00:00.000Z';
  const WORK = 'github.com/acme/work';
  const PERSONAL = 'github.com/someone/personal';

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

  it('expires every unsent body on a standalone machine', () => {
    // The control for the attachment cases below: without it they pass on a
    // seed the sweep would never have touched.
    applyOnboarding({ bodyRetention: { enabled: true, retainDays: 30 } }, base, null);
    seedLane();

    expect(runContentRetentionPass({ base })).toEqual({
      ran: true,
      rowsExpired: 3,
      bytesFreed: 300,
      done: true,
    });
    expect(bodyOf('enrolled')).toBeNull();
    expect(bodyOf('personal')).toBeNull();
    expect(bodyOf('unstamped')).toBeNull();
  });

  describe('on an attachment, by the credential mode', () => {
    const ENDPOINT = 'https://plane.example.test';
    const OTHER_ENDPOINT = 'https://elsewhere.example.test';
    // Built from parts so nothing in this file reads as a real credential.
    const API_KEY = ['test', 'only', 'credential'].join('-');

    afterEach(() => {
      reader.mode = 'real';
    });

    // `other-endpoint` is a well-formed credential minted for a different
    // deployment than the one the settings name.
    function attach(credential: 'v1' | 'other-endpoint' | 'malformed'): void {
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
      if (credential === 'v1' || credential === 'other-endpoint') {
        writeControlPlaneCredential(settingsDir(base), {
          specVersion: 1,
          endpoint: credential === 'v1' ? ENDPOINT : OTHER_ENDPOINT,
          apiKey: API_KEY,
          mintedAt: AT,
        });
      } else {
        writeFileSync(controlPlaneCredentialPath(settingsDir(base)), '{ not json');
      }
    }

    it('expires an out-of-scope and an unstamped body, and holds the enrolled one', () => {
      reader.mode = 'scoped';
      attach('v1');
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

    it('holds every unsent body on a machine attachment', () => {
      attach('v1');
      seedLane();

      expect(runContentRetentionPass({ base })).toEqual({
        ran: true,
        rowsExpired: 0,
        bytesFreed: 0,
        done: true,
      });
      expect(bodyOf('personal')).toBe('p'.repeat(100));
    });

    it('holds every unsent body when the credential cannot be parsed', () => {
      attach('malformed');
      seedLane();

      expect(runContentRetentionPass({ base })).toEqual({
        ran: true,
        rowsExpired: 0,
        bytesFreed: 0,
        done: true,
      });
      expect(bodyOf('personal')).toBe('p'.repeat(100));
    });

    it('holds every unsent body when the credential was minted for another deployment', () => {
      // The scoped relabel only applies to a credential the reader accepts, so
      // this case reaches a scoped answer exactly when the read is made without
      // the settings' endpoint to check the credential against.
      reader.mode = 'scoped';
      attach('other-endpoint');
      seedLane();

      expect(runContentRetentionPass({ base })).toEqual({
        ran: true,
        rowsExpired: 0,
        bytesFreed: 0,
        done: true,
      });
      expect(bodyOf('enrolled')).toBe('w'.repeat(100));
      expect(bodyOf('personal')).toBe('p'.repeat(100));
    });

    it('holds every unsent body, and still runs, when reading the credential throws', () => {
      // `ran: true` is the point: the lane decision is total on its own, so the
      // pass still runs, and every body is held.
      reader.mode = 'throws';
      attach('v1');
      seedLane();

      expect(runContentRetentionPass({ base })).toEqual({
        ran: true,
        rowsExpired: 0,
        bytesFreed: 0,
        done: true,
      });
      expect(bodyOf('enrolled')).toBe('w'.repeat(100));
    });
  });
});
