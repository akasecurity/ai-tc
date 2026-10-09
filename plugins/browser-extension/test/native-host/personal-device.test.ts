// On a machine attached as a personal device the native host keeps nothing
// from a web chat: a prompt is still checked and enforced, but recorded
// nowhere, and an exchange or capture status is dropped on arrival. Every case
// here runs the same request on a machine-wide attachment as its control, so
// an absence below is the gate's doing rather than a request that would have
// written nothing anyway.
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  DB_FILENAME,
  openLocalDatabase,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { setDefaultGatewayFactory, standaloneGatewayFactory } from '@akasecurity/plugin-runtime';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import type {
  AttachedCredentialAny,
  ControlPlaneConnection,
  WebCaptureStatus,
  WebExchange,
} from '@akasecurity/schema';
import { WEB_CHAT_CAPTURE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { handleRequest, readCaptureStatus } from '../../src/native-host/host.ts';
import type { WebSourceTool } from '../../src/native-host/protocol.ts';

const ENDPOINT = 'https://cp.example';
const MINTED_AT = '2026-10-01T00:00:00.000Z';
const CONNECTION: ControlPlaneConnection = { endpoint: ENDPOINT, attachedAt: MINTED_AT };
// A plain word standing in for the key: nothing here sends it anywhere.
const KEY = 'placeholder';
const CREDENTIALS: Record<'machine' | 'scoped', AttachedCredentialAny> = {
  machine: { specVersion: 1, endpoint: ENDPOINT, apiKey: KEY, mintedAt: MINTED_AT },
  scoped: { specVersion: 2, mode: 'scoped', endpoint: ENDPOINT, apiKey: KEY, mintedAt: MINTED_AT },
};

// Benign, high-entropy text that no rule matches, so where it lands says what
// was recorded and nothing else.
const MARKER = 'qzv7Lw3kXr9Tn2Pm';

// The rule whose own example drives the enforcement half, taken from the
// bundled pack so no secret-shaped literal is written here.
const RULE_ID = 'secrets/twilio-key';
const SECRET_PACK = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
const SECRET_EXAMPLE = SECRET_PACK?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];

let dir: string;
let restoreGateway: () => void;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-native-host-personal-'));
  // A migrated store from the start, so a count of zero below reads a real,
  // empty table rather than one no request ever created.
  openLocalDatabase(dir).close();
  // The local gateway whatever the settings say, so an attached configuration
  // opens no client. The gate under test reads the credential, not the gateway.
  restoreGateway = setDefaultGatewayFactory(standaloneGatewayFactory);
});

afterEach(() => {
  restoreGateway();
  removeTree(dir);
});

function attachAs(mode: 'machine' | 'scoped'): void {
  writeControlPlaneCredential(dir, CREDENTIALS[mode]);
}

function config(
  tool: WebSourceTool | undefined,
  runMode: 'attached' | 'standalone' = 'attached',
): PluginConfig {
  return {
    settings: {
      specVersion: 3,
      runMode,
      controlPlane: CONNECTION,
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      bodyRetention: { enabled: false, retainDays: 30 },
      webChatCapture: {
        responses: 'always',
        account: false,
        consent: {
          acknowledgedAt: '2026-01-01T00:00:00.000Z',
          version: WEB_CHAT_CAPTURE_CONSENT_VERSION,
        },
      },
    },
    dataDir: dir,
    dbPath: join(dir, 'aka.db'),
    settingsDir: dir,
    onboarded: true,
    provider: tool === 'chatgpt' ? { provider: 'openai' } : { provider: 'anthropic' },
  };
}

function rowCount(where: string): number {
  const db = new DatabaseSync(join(dir, DB_FILENAME));
  try {
    const row = db.prepare(`SELECT count(*) AS n FROM audit_events WHERE ${where}`).get() as {
      n: number;
    };
    return row.n;
  } finally {
    db.close();
  }
}

// Every byte under the data dir, walked rather than listed, so a copy that
// landed anywhere is seen.
function storeBytes(): string {
  const walk = (from: string): string[] =>
    readdirSync(from, { withFileTypes: true }).flatMap((entry) =>
      entry.isDirectory()
        ? walk(join(from, entry.name))
        : entry.isFile()
          ? [join(from, entry.name)]
          : [],
    );
  return Buffer.concat(walk(dir).map((path) => readFileSync(path))).toString('latin1');
}

function blockTheSecretPack(): void {
  if (SECRET_PACK === undefined) throw new Error(`bundled rule ${RULE_ID} is missing`);
  const db = openLocalDatabase(dir);
  try {
    db.installedPacks.recordInventory(bundledDetections());
    db.installedPacks.setPolicy(SECRET_PACK.namespace, SECRET_PACK.packId, 'block');
  } finally {
    db.close();
  }
}

const CAPTURE_KINDS = "event_type IN ('prompt','response','code_change','tool_use')";

function exchange(): WebExchange {
  return {
    messageId: 'msg_personal',
    startedAt: '2026-01-01T00:00:00.000Z',
    usageSource: 'none',
    toolCalls: [{ toolUseId: 'tu_personal', toolName: 'web_search', target: MARKER }],
    truncated: false,
    responseText: `the reply mentions ${MARKER}`,
  };
}

const STATUS: WebCaptureStatus = {
  patched: true,
  live: true,
  blind: false,
  sendsSeenDom: 1,
  exchangesSeenNet: 1,
  parseFailures: 0,
  unparsedBodies: 0,
  shapeMisses: [],
  conversationEndpoints: 1,
  closed: false,
  enforcement: 'watching',
};

describe('a prompt on a personal device', () => {
  it('is checked and enforced, and recorded nowhere', async () => {
    if (SECRET_EXAMPLE === undefined) throw new Error(`bundled rule ${RULE_ID} has no example`);
    blockTheSecretPack();
    attachAs('scoped');
    const response = await handleRequest(
      {
        type: 'capture',
        requestId: 'pd-capture',
        sessionId: 'browser-pd-capture',
        tool: 'chatgpt',
        kind: 'prompt',
        text: `${MARKER} deploy with ${SECRET_EXAMPLE} now`,
      },
      config,
    );
    if (response.type !== 'capture') throw new Error('expected a capture response');
    expect(response.action).toBe('block');
    expect(response.text).toBeNull();
    expect(response.ruleIds).toContain(RULE_ID);
    expect(rowCount(CAPTURE_KINDS)).toBe(0);
    expect(storeBytes()).not.toContain(MARKER);
  });

  it('is recorded on a machine-wide attachment, with the same decision', async () => {
    if (SECRET_EXAMPLE === undefined) throw new Error(`bundled rule ${RULE_ID} has no example`);
    blockTheSecretPack();
    attachAs('machine');
    const response = await handleRequest(
      {
        type: 'capture',
        requestId: 'md-capture',
        sessionId: 'browser-md-capture',
        tool: 'chatgpt',
        kind: 'prompt',
        text: `${MARKER} deploy with ${SECRET_EXAMPLE} now`,
      },
      config,
    );
    if (response.type !== 'capture') throw new Error('expected a capture response');
    expect(response.action).toBe('block');
    expect(rowCount(CAPTURE_KINDS)).toBe(1);
    expect(storeBytes()).toContain(MARKER);
  });
});

describe('an exchange on a personal device', () => {
  it('is dropped on arrival: nothing is written, and the reply is not scanned', async () => {
    attachAs('scoped');
    const response = await handleRequest(
      {
        type: 'exchange',
        requestId: 'pd-exchange',
        sessionId: 'browser-pd-exchange',
        tool: 'chatgpt',
        exchange: exchange(),
      },
      config,
    );
    expect(response).toEqual({
      type: 'exchange',
      requestId: 'pd-exchange',
      ok: true,
      accepted: false,
      skipped: 'out-of-scope',
      llmCalls: 0,
      toolCalls: 0,
      ruleIds: [],
    });
    expect(rowCount("root_session_id = 'browser-pd-exchange' OR id = 'browser-pd-exchange'")).toBe(
      0,
    );
    expect(storeBytes()).not.toContain(MARKER);
  });

  it('is recorded on a machine-wide attachment', async () => {
    attachAs('machine');
    const response = await handleRequest(
      {
        type: 'exchange',
        requestId: 'md-exchange',
        sessionId: 'browser-md-exchange',
        tool: 'chatgpt',
        exchange: exchange(),
      },
      config,
    );
    if (response.type !== 'exchange') throw new Error('expected an exchange response');
    expect(response.accepted).toBe(true);
    expect(response.llmCalls).toBe(1);
    expect(rowCount("event_type = 'response' AND root_session_id = 'browser-md-exchange'")).toBe(1);
    expect(storeBytes()).toContain(MARKER);
  });

  it('is read per request, so attaching as a personal device applies to the next one', async () => {
    attachAs('machine');
    const first = await handleRequest(
      {
        type: 'exchange',
        requestId: 'switch-1',
        sessionId: 'browser-switch',
        tool: 'chatgpt',
        exchange: exchange(),
      },
      config,
    );
    attachAs('scoped');
    const second = await handleRequest(
      {
        type: 'exchange',
        requestId: 'switch-2',
        sessionId: 'browser-switch',
        tool: 'chatgpt',
        exchange: { ...exchange(), messageId: 'msg_personal_2' },
      },
      config,
    );
    expect(first).toMatchObject({ accepted: true });
    expect(second).toMatchObject({ accepted: false, skipped: 'out-of-scope' });
    expect(rowCount("event_type = 'llm_call' AND root_session_id = 'browser-switch'")).toBe(1);
  });
});

describe('a capture status on a personal device', () => {
  it('is neither stored nor kept in memory', async () => {
    attachAs('scoped');
    const response = await handleRequest(
      {
        type: 'capture_status',
        requestId: 'pd-status',
        sessionId: 'browser-pd-status',
        tool: 'chatgpt',
        status: STATUS,
      },
      config,
    );
    expect(response).toEqual({
      type: 'capture_status',
      requestId: 'pd-status',
      ok: true,
      accepted: false,
      skipped: 'out-of-scope',
    });
    expect(readCaptureStatus('browser-pd-status')).toBeUndefined();
    expect(rowCount("event_type = 'capture_status'")).toBe(0);
  });

  it('is stored and kept on a machine-wide attachment', async () => {
    attachAs('machine');
    const response = await handleRequest(
      {
        type: 'capture_status',
        requestId: 'md-status',
        sessionId: 'browser-md-status',
        tool: 'chatgpt',
        status: STATUS,
      },
      config,
    );
    expect(response).toMatchObject({ accepted: true });
    expect(readCaptureStatus('browser-md-status')).toBeDefined();
    expect(rowCount("event_type = 'capture_status'")).toBe(1);
  });
});

describe('capture_state on a personal device', () => {
  it('says the machine is one', async () => {
    attachAs('scoped');
    const response = await handleRequest({ type: 'capture_state', requestId: 'pd-state' }, config);
    expect(response).toMatchObject({ type: 'capture_state', personalDevice: true });
  });

  it('says a machine-wide attachment is not one', async () => {
    attachAs('machine');
    const response = await handleRequest({ type: 'capture_state', requestId: 'md-state' }, config);
    expect(response).toMatchObject({ type: 'capture_state', personalDevice: false });
  });

  it('says a machine with no credential is not one', async () => {
    const response = await handleRequest({ type: 'capture_state', requestId: 'no-state' }, config);
    expect(response).toMatchObject({ type: 'capture_state', personalDevice: false });
  });
});

describe('a half attachment that still holds a scoped credential', () => {
  // The settings no longer say attached, so the gateway forwards nothing, and
  // no detached sync child is started by the session start below.
  const halfAttached = (tool: WebSourceTool | undefined): PluginConfig =>
    config(tool, 'standalone');

  it('counts as a personal device, which records less', async () => {
    attachAs('scoped');
    const response = await handleRequest(
      {
        type: 'exchange',
        requestId: 'half-exchange',
        sessionId: 'browser-half',
        tool: 'claude-ai',
        exchange: exchange(),
      },
      halfAttached,
    );
    expect(response).toMatchObject({ accepted: false, skipped: 'out-of-scope' });
  });

  it('still opens the session root, which carries no chat content', async () => {
    attachAs('scoped');
    const response = await handleRequest(
      {
        type: 'session_start',
        requestId: 'half-start',
        sessionId: 'browser-half-start',
        tool: 'claude-ai',
        hostname: 'claude.ai',
      },
      halfAttached,
    );
    expect(response).toEqual({ type: 'session_start', requestId: 'half-start', ok: true });
    expect(rowCount("event_type = 'session' AND id = 'browser-half-start'")).toBe(1);
  });
});
