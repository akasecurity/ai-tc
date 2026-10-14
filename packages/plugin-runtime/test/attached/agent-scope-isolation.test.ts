import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  applyOnboarding,
  captureBackfillScope,
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  openLocalDatabase,
  readAttachedIdentity,
  readWorkspaceSettings,
  recordValidatedWorkAccount,
  seedCaptureBacklogOwed,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { IngestEvent, RecordAuditEventRequest } from '@akasecurity/schema';
import { agentKey, HISTORY_SYNC_PAYLOAD_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import type { HistorySyncResult } from '../../src/attached/history-sync.ts';
import { runHistorySync } from '../../src/attached/history-sync.ts';
import { syncLaneRetentionFor } from '../../src/content-retention-pass.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// What a learned work account must never reach, on a real store beside a real
// scoped credential and identity record: the claude.ai chat rows keyed by the
// same organization's web account key, and the rows stamped for the same
// account under another attached user. Every case also sends this attachment's
// own agent-keyed session, so a case cannot pass because nothing was sent.

const ENDPOINT = 'https://aka.acme.test';
const AT = '2026-08-24T10:00:00.000Z';
const ATTACHED_MS = Date.parse(AT);
// The backlog, recorded before the attachment: what the structural lane offers.
const BACKLOG = new Date(ATTACHED_MS - 86_400_000).toISOString();
const T0 = Date.parse('2026-08-25T00:00:00.000Z');
const TEST_KEY = 'not-a-real-key';
const WORK_REPO = 'github.com/acme/payments-api';
const ACCOUNT = `claude:${randomUUID()}`;
// A tag no record on this device carries: another attached user's.
const OTHER_TAG = 'ffffffffffffffff';
const CREDENTIAL = {
  specVersion: 2,
  mode: 'scoped',
  endpoint: ENDPOINT,
  apiKey: TEST_KEY,
  mintedAt: AT,
} as const;

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-agent-scope-isolation-'));
  // Schema by file copy rather than a migration per test.
  migratedStore.seed(dataDirOf(home));
});

afterEach(() => {
  removeTree(home);
});

/**
 * Attached as a personal device with a history grant and the work repository
 * enrolled, with ACCOUNT learned under this credential. Returns ACCOUNT's agent
 * key for this attachment.
 */
function attachAndLearn(): string {
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint: ENDPOINT, attachedAt: AT },
      historySyncConsent: {
        acknowledgedAt: AT,
        payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
        endpoint: ENDPOINT,
      },
      attachmentScope: {
        endpoint: ENDPOINT,
        entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: AT }],
      },
    },
    home,
    null,
  );
  writeControlPlaneCredential(settingsDirOf(home), CREDENTIAL);
  writeAttachedIdentity(dataDirOf(home), {
    endpoint: ENDPOINT,
    apiKey: TEST_KEY,
    tenantName: 'Acme',
    userEmail: ['member', 'example.test'].join('@'),
  });
  recordValidatedWorkAccount(dataDirOf(home), {
    endpoint: ENDPOINT,
    credential: CREDENTIAL,
    key: ACCOUNT,
  });
  const record = readAttachedIdentity(dataDirOf(home));
  if (!record?.workAccounts.some((entry) => entry.identity === ACCOUNT)) {
    throw new Error('the account was not learned');
  }
  expect(record.scopeTag).not.toBe(OTHER_TAG);
  return agentKeyOf(record.scopeTag, ACCOUNT);
}

/** The agent key the schema's builder makes for `account` under `scopeTag`, failing the case if none. */
function agentKeyOf(scopeTag: string, account: string): string {
  const key = agentKey(scopeTag, account);
  if (key === undefined) throw new Error(`no agent key for ${account}`);
  return key;
}

/**
 * One backlog session, every row stamped `scopeKey`: a root, an `llm_call`
 * leaf, a reply capture marked owed, and a prompt capture that is not.
 */
function seedSession(id: string, scopeKey: string, sourceTool: string): void {
  const attributes = { scope_key: scopeKey, source_tool: sourceTool };
  const db = openLocalDatabase(dataDirOf(home));
  try {
    db.auditEvents.insertAuditEvent({
      id,
      eventType: 'session',
      startedAt: BACKLOG,
      attributes: { ...attributes, harness: sourceTool },
    });
    db.auditEvents.insertAuditEvent({
      id: `${id}-llm`,
      eventType: 'llm_call',
      rootSessionId: id,
      parentId: id,
      startedAt: BACKLOG,
      attributes,
    });
    for (const [suffix, eventType] of [
      ['reply', 'response'],
      ['prompt', 'prompt'],
    ] as const) {
      db.auditEvents.insertAuditEvent({
        id: `${id}-${suffix}`,
        eventType,
        rootSessionId: id,
        parentId: id,
        startedAt: BACKLOG,
        content: `text of ${id}-${suffix}`,
        contentHash: 'd'.repeat(64),
        attributes,
      });
    }
    db.historySync.markCaptureOwed(`${id}-reply`);
  } finally {
    db.close();
  }
}

function owed(id: string): number | null {
  const raw = new DatabaseSync(dbPathOf(home));
  try {
    const row = raw.prepare('SELECT outbox_owed FROM audit_events WHERE id = ?').get(id) as
      { outbox_owed: number | null } | undefined;
    if (row === undefined) throw new Error(`no row ${id}`);
    return row.outbox_owed;
  } finally {
    raw.close();
  }
}

/** One drain pass, every sender recording: the structural ids and the capture texts it sent. */
async function drain(): Promise<{
  result: HistorySyncResult;
  structural: string[];
  captures: unknown[];
}> {
  const structural: RecordAuditEventRequest[] = [];
  const captures: IngestEvent[] = [];
  let clock = T0;
  const result = await runHistorySync({
    base: home,
    settingsDir: settingsDirOf(home),
    dataDir: dataDirOf(home),
    now: () => clock,
    sleep: () => {
      clock += 1;
      return Promise.resolve();
    },
    random: () => 0,
    sendBatch: (events) => {
      structural.push(...events);
      return Promise.resolve({ settled: events.length });
    },
    sendOne: (event) => {
      structural.push(event);
      return Promise.resolve();
    },
    sendCaptures: (events) => {
      captures.push(...events);
      return Promise.resolve({ settled: events.length });
    },
  });
  if (!result.attempted)
    throw new Error(`expected a pass to run, but it was skipped: ${result.reason}`);
  return {
    result,
    structural: structural.map((event) => event.id).sort(),
    captures: captures.map((event) => event.content).sort(),
  };
}

describe('a learned work account and the claude.ai chats of the same organization', () => {
  it('a learned org never forwards, seeds, holds or counts a claude.ai chat', async () => {
    const ownKey = attachAndLearn();
    seedSession('own', ownKey, 'claude-code');
    seedSession('chat', ACCOUNT, 'claude-ai');

    const { result, structural, captures } = await drain();
    // Forwarded: this attachment's own agent-keyed session, and nothing of the chat.
    expect(structural).toEqual(['own', 'own-llm']);
    expect(captures).toEqual(['text of own-reply']);
    expect(owed('chat-reply')).toBe(1);
    // Counted: the chat's root and leaf are not in this scope's totals.
    expect(result.counts.sent).toBe(2);
    expect(result.counts.pending).toBe(0);

    // Seeded: the consent seed marks no chat capture owed.
    seedCaptureBacklogOwed(dataDirOf(home), ATTACHED_MS, () =>
      captureBackfillScope({ usable: true, credential: CREDENTIAL }, readWorkspaceSettings(home)),
    );
    expect(owed('chat-prompt')).toBeNull();

    // Held: the sync lane holds the agent key's bodies, not the web account's.
    expect(syncLaneRetentionFor(readWorkspaceSettings(home), home)).toEqual({
      kind: 'hold-keys',
      keys: [WORK_REPO, ownKey].sort(),
    });
  });
});

describe('rows stamped for the same account under another attached user', () => {
  it('rows stamped under another attached user stay local', async () => {
    const ownKey = attachAndLearn();
    seedSession('own', ownKey, 'claude-code');
    seedSession('other', agentKeyOf(OTHER_TAG, ACCOUNT), 'claude-code');

    const { structural, captures } = await drain();

    expect(structural).toEqual(['own', 'own-llm']);
    expect(captures).toEqual(['text of own-reply']);
    expect(owed('other-reply')).toBe(1);
  });
});
