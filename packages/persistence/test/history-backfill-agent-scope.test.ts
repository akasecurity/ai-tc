import { randomUUID } from 'node:crypto';
import { join } from 'node:path';

import type { WorkspaceSettings } from '@akasecurity/schema';
import { agentKey, defaultWorkspaceSettings } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  captureBackfillScope,
  dataDir,
  readAttachedIdentity,
  recordValidatedWorkAccount,
  seedCaptureBacklogOwed,
  writeAttachedIdentity,
} from '../src/index.ts';
import { useTempStore } from './helpers/temp-store.ts';

// The consent seed marks the backlog of the stored entries alone. A coding-agent
// key is marked owed only by the live path, when a row is stamped, so a work
// account this device learned never widens what a grant re-sends.
//
// The seed's scope is worked out from the credential and the settings alone, so
// a version of it that also read the identity record could find one only in the
// default data directory. HOME therefore points at a directory inside the temp
// store, the identity record sits in that default data directory, and the store
// the seed marks is the temp store's own.

const TEST_KEY = 'not-a-real-key';
const ENDPOINT = 'https://plane.example.test';
const AT = '2026-08-24T10:00:00.000Z';
const WORK_REPO = 'github.com/acme/payments-api';
const CREDENTIAL = {
  specVersion: 2,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: TEST_KEY,
  mintedAt: AT,
} as const;

const store = useTempStore('aka-backfill-learned-');

let home: string;

beforeEach(() => {
  home = join(store.home, 'os-home');
  vi.stubEnv('HOME', home);
  vi.stubEnv('USERPROFILE', home);
  // Nothing below may touch the real home: stop before the first write if the
  // stub did not take.
  expect(dataDir()).toBe(join(home, '.aka', 'data'));
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('captureBackfillScope — a learned work account', () => {
  it('ignores a learned account', () => {
    const account = `claude:${randomUUID()}`;
    writeAttachedIdentity(dataDir(), {
      endpoint: ENDPOINT,
      apiKey: TEST_KEY,
      tenantName: 'Acme',
      userEmail: ['member', 'example.test'].join('@'),
    });
    recordValidatedWorkAccount(dataDir(), {
      endpoint: ENDPOINT,
      credential: CREDENTIAL,
      key: account,
    });
    const record = readAttachedIdentity(dataDir());
    if (!record?.workAccounts.some((entry) => entry.identity === account)) {
      throw new Error('the account was not learned');
    }
    const settings: WorkspaceSettings = {
      ...defaultWorkspaceSettings(),
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
      attachmentScope: {
        endpoint: ENDPOINT,
        entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: AT }],
      },
    };
    const agentScoped = agentKey(record.scopeTag, account);
    if (agentScoped === undefined) throw new Error('no agent key was built');
    const before = new Date(Date.parse(AT) - 3_600_000).toISOString();
    const db = store.open();
    try {
      db.auditEvents.ensureSessionRoot('backlog', before);
      for (const [id, scopeKey] of [
        ['work', WORK_REPO],
        ['agent', agentScoped],
      ] as const) {
        db.auditEvents.insertAuditEvent({
          id,
          eventType: 'prompt',
          rootSessionId: 'backlog',
          parentId: 'backlog',
          startedAt: before,
          content: `text of ${id}`,
          contentHash: 'e'.repeat(64),
          attributes: { source_tool: 'claude-code', scope_key: scopeKey },
        });
      }
    } finally {
      db.close();
    }

    seedCaptureBacklogOwed(store.dataDir, Date.parse(AT), () =>
      captureBackfillScope({ usable: true, credential: CREDENTIAL }, settings),
    );

    const owed = store
      .openRaw()
      .prepare('SELECT id, outbox_owed AS owed FROM audit_events ORDER BY id')
      .all()
      .map((row) => ({ ...row }));
    // The control: the enrolled repository's backlog is marked; the agent key's is not.
    expect(owed).toEqual([
      { id: 'agent', owed: null },
      { id: 'backlog', owed: null },
      { id: 'work', owed: 1 },
    ]);
  });
});
