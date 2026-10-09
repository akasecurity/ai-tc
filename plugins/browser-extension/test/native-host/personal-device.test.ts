// On a machine that withholds web chats (a personal device, or one whose
// credential cannot be read) the native host keeps nothing from a chat: a
// prompt is still checked and enforced but recorded nowhere, an exchange is
// dropped on arrival, a capture status stays in this process's memory only,
// and a session start opens no root. Every case runs the same request on a
// machine that records as its control, so an absence below is the gate's doing
// rather than a request that would have written nothing anyway.
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import {
  controlPlaneCredentialPath,
  DATA_FILE_MODE,
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
  it('is kept in memory for the popup, and never stored', async () => {
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
    // The popup's source for an enforcement fault on this machine.
    expect(readCaptureStatus('browser-pd-status')?.status).toEqual(STATUS);
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

describe('capture_state says why chats are withheld', () => {
  it('on a personal device', async () => {
    attachAs('scoped');
    const response = await handleRequest({ type: 'capture_state', requestId: 'pd-state' }, config);
    expect(response).toMatchObject({ type: 'capture_state', withheld: 'personal-device' });
  });

  it('on a credential it cannot read', async () => {
    writeFileSync(controlPlaneCredentialPath(dir), '{ not json', { mode: DATA_FILE_MODE });
    const response = await handleRequest({ type: 'capture_state', requestId: 'ur-state' }, config);
    expect(response).toMatchObject({ type: 'capture_state', withheld: 'unreadable-attachment' });
  });

  it('and not at all on a machine-wide attachment', async () => {
    attachAs('machine');
    const response = await handleRequest({ type: 'capture_state', requestId: 'md-state' }, config);
    expect(response).toMatchObject({ type: 'capture_state' });
    expect(response).not.toHaveProperty('withheld');
  });

  it('and not at all on a machine with no credential', async () => {
    const response = await handleRequest({ type: 'capture_state', requestId: 'no-state' }, config);
    expect(response).not.toHaveProperty('withheld');
  });
});

describe('a machine that cannot tell what it was attached as', () => {
  it('records no exchange when its credential cannot be read', async () => {
    writeFileSync(controlPlaneCredentialPath(dir), '{ not json', { mode: DATA_FILE_MODE });
    const response = await handleRequest(
      {
        type: 'exchange',
        requestId: 'ur-exchange',
        sessionId: 'browser-ur-exchange',
        tool: 'chatgpt',
        exchange: exchange(),
      },
      config,
    );
    expect(response).toMatchObject({ accepted: false, skipped: 'out-of-scope' });
    expect(storeBytes()).not.toContain(MARKER);
  });

  it('records no exchange beside a stored scope, whatever the credential says', async () => {
    // What a scoped attach over a machine-wide one leaves between its two
    // writes: the scope it wrote, beside the machine credential it replaces.
    attachAs('machine');
    const scoped = (tool: WebSourceTool | undefined): PluginConfig => {
      const base = config(tool);
      return {
        ...base,
        settings: { ...base.settings, attachmentScope: { endpoint: ENDPOINT, entries: [] } },
      };
    };
    const response = await handleRequest(
      {
        type: 'exchange',
        requestId: 'scope-exchange',
        sessionId: 'browser-scope-exchange',
        tool: 'chatgpt',
        exchange: exchange(),
      },
      scoped,
    );
    expect(response).toMatchObject({ accepted: false, skipped: 'out-of-scope' });
  });
});

describe('a session start on a machine that withholds web chats', () => {
  // The settings do not say attached, so the gateway forwards nothing and no
  // detached sync child is started; the scoped credential beside them is what
  // withholds. A half attachment like this one counts as a personal device.
  const halfAttached = (tool: WebSourceTool | undefined): PluginConfig =>
    config(tool, 'standalone');

  it('opens no session root', async () => {
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
    expect(rowCount("event_type IN ('session', 'config_scan')")).toBe(0);
  });

  it('opens one on a machine with no credential', async () => {
    // The control: the same request, recorded.
    const response = await handleRequest(
      {
        type: 'session_start',
        requestId: 'plain-start',
        sessionId: 'browser-plain-start',
        tool: 'claude-ai',
        hostname: 'claude.ai',
      },
      halfAttached,
    );
    expect(response).toEqual({ type: 'session_start', requestId: 'plain-start', ok: true });
    expect(rowCount("event_type = 'session' AND id = 'browser-plain-start'")).toBe(1);
  });

  it('drops an exchange too', async () => {
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
});
