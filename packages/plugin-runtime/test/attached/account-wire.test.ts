import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  dataDir as dataDirOf,
  dbPath as dbPathOf,
  openLocalDatabase,
  readAttachedIdentity,
  readForwardHealth,
  readWorkspaceSettings,
  recordValidatedWorkAccount,
  settingsDir as settingsDirOf,
  writeAttachedIdentity,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { buildModelRefusalEvent } from '@akasecurity/plugin-sdk';
import type { InventoryContext } from '@akasecurity/schema';
import {
  AccountCheckReason,
  agentKey,
  HISTORY_SYNC_PAYLOAD_VERSION,
  SOURCE_TOOL,
} from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { useLoopbackServer } from '../../../remote/test/helpers/loopback.ts';
import { stampScopeKey } from '../../src/account-scope.ts';
import { resolveGatewayForConfig } from '../../src/attached/factory.ts';
import { runHistorySync } from '../../src/attached/history-sync.ts';
import { migratedStore } from '../helpers/store-templates.ts';

// No account material reaches the wire. Every producer a coding-agent session
// has writes a row stamped with a work account's agent key through the real
// gateway, and then the current drain sends the backlog stamped the same way,
// both through the real network client to a loopback server that records each
// request whole: method, path, headers and body. None of them may carry the
// account's id, an account or agent key, the attached user's address, a digest,
// the scope tag, a plan, or a reason code.
//
// The server answers by the body's shape, never by the path: a batch of events
// gets an acknowledgement of all of them, anything else an empty object. The
// forward breaker's own file proves every request was accepted, so the case
// cannot pass because the requests failed before they were made.

const server = useLoopbackServer();

const AT = '2026-10-01T09:00:00.000Z';
const BACKLOG = new Date(Date.parse(AT) - 86_400_000).toISOString();
const TEST_KEY = 'not-a-real-key';
const ADDRESS = ['member', 'example.test'].join('@');
const WORK_REPO = 'github.com/acme/payments-api';
const PERSONAL_REPO = 'github.com/someone/side-project';
const ORG = randomUUID();
const ACCOUNT = `claude:${ORG}`;
const PLANS = ['claude_team', 'claude_enterprise'];

const CONTEXT: InventoryContext = {
  harness: { objectType: 'harness', identityKey: SOURCE_TOOL.ClaudeCode, attributes: {} },
  project: {
    url: 'https://github.com/someone/side-project.git',
    name: 'side-project',
    attributes: {},
  },
};

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'aka-account-wire-'));
  migratedStore.seed(dataDirOf(home));
  server.received.length = 0;
  server.reply((request, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(acknowledge(request.body)));
  });
});

afterEach(() => {
  removeTree(home);
});

function acknowledge(body: string): unknown {
  try {
    const parsed: unknown = JSON.parse(body);
    const events = Array.isArray(parsed) ? parsed : (parsed as { events?: unknown }).events;
    if (Array.isArray(events)) return { accepted: events.length, duplicates: 0 };
  } catch {
    // An empty or non-JSON body: answered like any other request.
  }
  return {};
}

/**
 * Attached as a personal device to the loopback server, with a history grant,
 * the work repository enrolled, and ACCOUNT learned. Returns the record.
 */
function attach() {
  const endpoint = server.origin;
  applyOnboarding(
    {
      runMode: 'attached',
      controlPlane: { endpoint, attachedAt: AT },
      historySyncConsent: {
        acknowledgedAt: AT,
        payloadVersion: HISTORY_SYNC_PAYLOAD_VERSION,
        endpoint,
      },
      attachmentScope: {
        endpoint,
        entries: [{ kind: 'repo', identity: WORK_REPO, enrolledAt: AT }],
      },
    },
    home,
    null,
  );
  const credential = {
    specVersion: 2,
    mode: 'scoped',
    endpoint,
    apiKey: TEST_KEY,
    mintedAt: AT,
  } as const;
  writeControlPlaneCredential(settingsDirOf(home), credential);
  writeAttachedIdentity(dataDirOf(home), {
    endpoint,
    apiKey: TEST_KEY,
    tenantName: 'Acme',
    userEmail: ADDRESS,
  });
  recordValidatedWorkAccount(dataDirOf(home), { endpoint, credential, key: ACCOUNT });
  const record = readAttachedIdentity(dataDirOf(home));
  if (record?.workAccounts.some((entry) => entry.identity === ACCOUNT) !== true) {
    throw new Error('the account was not learned');
  }
  return record;
}

function config(): PluginConfig {
  return {
    settings: readWorkspaceSettings(home),
    dataDir: dataDirOf(home),
    dbPath: dbPathOf(home),
    settingsDir: settingsDirOf(home),
    onboarded: true,
    provider: { provider: 'anthropic' },
  };
}

/** Every live producer of a coding-agent session in a personal folder, signed in to ACCOUNT. */
async function produceLive(expectedKey: string): Promise<void> {
  const gateway = resolveGatewayForConfig(config());
  try {
    const key = stampScopeKey(gateway, PERSONAL_REPO, ACCOUNT);
    // Every producer below is agent-keyed, or this suite would prove nothing.
    expect(key).toBe(expectedKey);
    const at = new Date().toISOString();
    await gateway.ensureInventory(CONTEXT, { scopeKey: key });
    await gateway.recordAuditEvent({
      id: 'live',
      eventType: 'session',
      startedAt: at,
      attributes: { harness: 'claude-code', cwd: '/work/side-project', scope_key: key },
    });
    await gateway.recordCapture({
      event: {
        id: randomUUID(),
        sourceTool: 'claude-code',
        kind: 'prompt',
        occurredAt: at,
        contentHash: 'f'.repeat(64),
        content: 'text of live-prompt',
        metadata: { sessionId: 'live', repo: 'side-project' },
      },
      findings: [],
      ...(key === undefined ? {} : { scopeKey: key }),
    });
    await gateway.recordLlmCalls([
      {
        sessionId: 'live',
        messageId: 'live-msg',
        parentId: 'live',
        rootSessionId: 'live',
        startedAt: at,
        attributes: { model: 'example-model', input_tokens: 1, output_tokens: 1, scope_key: key },
      },
    ]);
    await gateway.recordToolCalls([
      {
        sessionId: 'live',
        toolUseId: 'live-tool',
        parentId: 'live',
        rootSessionId: 'live',
        startedAt: at,
        attributes: { tool_name: 'Bash', tool_use_id: 'live-tool', target: 'ls', scope_key: key },
        inspections: [],
      },
    ]);
    await gateway.recordAuditEvent(
      buildModelRefusalEvent({
        id: randomUUID(),
        sessionId: 'live',
        model: 'example-frontier-model',
        seam: 'turn',
        sourceTool: 'claude-code',
        occurredAt: at,
        scopeKey: key,
      }),
    );
  } finally {
    await gateway.close();
  }
}

/** A backlog session from before the attach, stamped with the agent key, for the drain. */
function seedBacklog(scopeKey: string): void {
  const attributes = { scope_key: scopeKey, source_tool: 'claude-code' };
  const db = openLocalDatabase(dataDirOf(home));
  try {
    db.auditEvents.insertAuditEvent({
      id: 'backlog',
      eventType: 'session',
      startedAt: BACKLOG,
      attributes: { ...attributes, harness: 'claude-code' },
    });
    db.auditEvents.insertAuditEvent({
      id: 'backlog-llm',
      eventType: 'llm_call',
      rootSessionId: 'backlog',
      parentId: 'backlog',
      startedAt: BACKLOG,
      attributes,
    });
    db.auditEvents.insertAuditEvent({
      id: 'backlog-reply',
      eventType: 'response',
      rootSessionId: 'backlog',
      parentId: 'backlog',
      startedAt: BACKLOG,
      content: 'text of backlog-reply',
      contentHash: 'a'.repeat(64),
      attributes,
    });
    db.historySync.markCaptureOwed('backlog-reply');
  } finally {
    db.close();
  }
}

/** Every string value in a parsed body, keys excluded: the wire schema's own names are fixed. */
function stringValues(value: unknown): string[] {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value)) return value.flatMap(stringValues);
  if (typeof value === 'object' && value !== null) {
    return Object.values(value).flatMap(stringValues);
  }
  return [];
}

/** Every string value of every JSON body the server received. */
function receivedValues(): string[] {
  return server.received.flatMap((request) => {
    try {
      return stringValues(JSON.parse(request.body));
    } catch {
      return [];
    }
  });
}

/**
 * Nothing of the account in any part of any request: its id, an account or
 * agent key, the attached user's address, the record's digests and tag, a plan;
 * and no reason code as a value in any body.
 */
function expectNoAccountMaterial(record: ReturnType<typeof attach>): void {
  const everything = server.received
    .map((request) =>
      [request.method, request.url, JSON.stringify(request.headers), request.body].join('\n'),
    )
    .join('\n');
  for (const forbidden of [
    ORG,
    'claude:',
    'chatgpt:',
    'agent:',
    ADDRESS,
    record.attachedUserDigest,
    record.credentialDigest,
    record.scopeTag,
    ...PLANS,
  ]) {
    expect(everything).not.toContain(forbidden);
  }
  const reasons = new Set<string>(AccountCheckReason.options);
  expect(receivedValues().filter((value) => reasons.has(value))).toEqual([]);
}

describe('the wire carries no account material', () => {
  it('no account material reaches the wire from any producer or the current drain', async () => {
    const record = attach();
    const agentScoped = agentKey(record.scopeTag, ACCOUNT);
    if (agentScoped === undefined) throw new Error('no agent key was built');
    seedBacklog(agentScoped);

    await produceLive(agentScoped);
    let clock = Date.parse('2026-10-02T00:00:00.000Z');
    const drained = await runHistorySync({
      base: home,
      settingsDir: settingsDirOf(home),
      dataDir: dataDirOf(home),
      now: () => clock,
      sleep: () => {
        clock += 1;
        return Promise.resolve();
      },
      random: () => 0,
    });
    expect(drained.attempted).toBe(true);

    // Every request was accepted: the breaker writes its file only on a failure.
    expect(readForwardHealth(dataDirOf(home), Date.now())).toBeNull();

    // Each producer reached the wire, and so did both of the drain's lanes.
    const values = new Set(receivedValues());
    for (const reached of [
      'side-project',
      'live',
      'text of live-prompt',
      'llm_call',
      'tool_call',
      'model_refusal',
      'backlog',
      'text of backlog-reply',
    ]) {
      expect(values.has(reached)).toBe(true);
    }

    expectNoAccountMaterial(record);
  });
});
