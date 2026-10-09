// On a machine that withholds web chats (a personal device, or one whose
// credential cannot be read) the native host keeps nothing from a chat: a
// prompt is still checked and enforced but recorded nowhere, an exchange is
// dropped on arrival, a capture status stays in this process's memory only,
// and a session start opens no root. Every case runs the same request on a
// machine that records as its control, so an absence below is the gate's doing
// rather than a request that would have written nothing anyway.
import type * as ChildProcess from 'node:child_process';
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
import { bundledDetections, maskMatch } from '@akasecurity/plugin-sdk';
import type {
  AttachedCredentialAny,
  ControlPlaneConnection,
  WebCaptureStatus,
  WebExchange,
} from '@akasecurity/schema';
import { SOURCE_TOOL, WEB_CHAT_CAPTURE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { handleRequest, readCaptureStatus } from '../../src/native-host/host.ts';
import type { WebSourceTool } from '../../src/native-host/protocol.ts';

// The detached children a session start asks for on an attached machine (the
// policy refresh among them), recorded instead of run, so a fully attached
// session start can be driven here without starting a process that would try
// to reach the control plane.
const spawned = vi.hoisted(() => ({ scripts: [] as string[] }));
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof ChildProcess>();
  return {
    ...actual,
    spawn: (_command: string, args: readonly string[]) => {
      spawned.scripts.push(String(args[0]));
      return { on: () => undefined, unref: () => undefined };
    },
  };
});

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
const RULE_EXAMPLE = SECRET_PACK?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];

// The value a prompt carries. Blocking needs the pack inventory in the store,
// and that inventory holds each rule's own examples, so the example itself is
// at rest by design and a byte scan for it would always find it. Reversing the
// body after the two-letter prefix gives a value the same rule matches and no
// file holds.
function liveValue(): string {
  if (RULE_EXAMPLE === undefined) throw new Error(`bundled rule ${RULE_ID} has no example`);
  const value = RULE_EXAMPLE.slice(0, 2) + RULE_EXAMPLE.slice(2).split('').reverse().join('');
  if (value === RULE_EXAMPLE) throw new Error(`bundled rule ${RULE_ID} has a palindromic example`);
  return value;
}

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
    provider: tool === SOURCE_TOOL.ChatGpt ? { provider: 'openai' } : { provider: 'anthropic' },
  };
}

// The same machine with web-chat capture never granted.
function withoutConsent(tool: WebSourceTool | undefined): PluginConfig {
  const base = config(tool);
  return {
    ...base,
    settings: { ...base.settings, webChatCapture: { responses: 'always', account: false } },
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

interface LedgerRow {
  reference: string;
  rule_id: string;
  masked_value: string;
}

// The blocked-detections ledger `aka exception` approves from. It records the
// rule, a keyed fingerprint and a masked preview of a value an enforcing
// policy stopped; it is the one thing a personal device still writes.
function ledgerRows(): LedgerRow[] {
  const db = new DatabaseSync(join(dir, DB_FILENAME));
  try {
    return db
      .prepare('SELECT reference, rule_id, masked_value FROM blocked_detections')
      .all() as unknown as LedgerRow[];
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
    const value = liveValue();
    blockTheSecretPack();
    attachAs('scoped');
    const response = await handleRequest(
      {
        type: 'capture',
        requestId: 'pd-capture',
        sessionId: 'browser-pd-capture',
        tool: SOURCE_TOOL.ChatGpt,
        kind: 'prompt',
        text: `${MARKER} deploy with ${value} now`,
      },
      config,
    );
    if (response.type !== 'capture') throw new Error('expected a capture response');
    expect(response.action).toBe('block');
    expect(response.text).toBeNull();
    expect(response.ruleIds).toContain(RULE_ID);
    expect(rowCount(CAPTURE_KINDS)).toBe(0);
    expect(storeBytes()).not.toContain(MARKER);

    // The one thing a block still leaves: a masked ledger entry, handed back
    // to the page as the reference `aka exception` approves from. The mask is
    // the product's own, never a hand-written one, and it must differ from the
    // value or the absence checks below prove nothing.
    const masked = maskMatch(value);
    expect(masked).not.toBe(value);
    expect(response.blockedReferences).toHaveLength(1);
    expect(response.blockedReferences?.[0]).toMatchObject({
      ruleId: RULE_ID,
      maskedValue: masked,
    });
    const ledger = ledgerRows();
    expect(ledger).toHaveLength(1);
    expect(ledger[0]).toMatchObject({
      reference: response.blockedReferences?.[0]?.reference,
      rule_id: RULE_ID,
      masked_value: masked,
    });
    // Nothing else holds the value: not the ledger, not any file under the
    // data dir. The machine-wide control below stores the benign marker, so
    // this absence is a gate's doing and not a store that keeps nothing.
    expect(ledger[0]?.masked_value).not.toBe(value);
    expect(storeBytes()).not.toContain(value);
  });

  it('is recorded on a machine-wide attachment, with the same decision', async () => {
    const value = liveValue();
    blockTheSecretPack();
    attachAs('machine');
    const response = await handleRequest(
      {
        type: 'capture',
        requestId: 'md-capture',
        sessionId: 'browser-md-capture',
        tool: SOURCE_TOOL.ChatGpt,
        kind: 'prompt',
        text: `${MARKER} deploy with ${value} now`,
      },
      config,
    );
    if (response.type !== 'capture') throw new Error('expected a capture response');
    expect(response.action).toBe('block');
    expect(rowCount(CAPTURE_KINDS)).toBe(1);
    expect(storeBytes()).toContain(MARKER);

    // The ledger entry is the same on both attachments: a personal device
    // loses the recorded event, not the approve flow.
    const masked = maskMatch(value);
    expect(response.blockedReferences).toHaveLength(1);
    expect(response.blockedReferences?.[0]).toMatchObject({
      ruleId: RULE_ID,
      maskedValue: masked,
    });
    const ledger = ledgerRows();
    expect(ledger).toHaveLength(1);
    expect(ledger[0]).toMatchObject({
      reference: response.blockedReferences?.[0]?.reference,
      rule_id: RULE_ID,
      masked_value: masked,
    });
    expect(storeBytes()).not.toContain(value);
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
        tool: SOURCE_TOOL.ChatGpt,
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
        tool: SOURCE_TOOL.ChatGpt,
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
        tool: SOURCE_TOOL.ChatGpt,
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
        tool: SOURCE_TOOL.ChatGpt,
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
        tool: SOURCE_TOOL.ChatGpt,
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

  // Consent governs recording, and nothing is recorded here, so an enforcement
  // fault reaches the popup whether or not capture was ever granted.
  it('is kept in memory without capture consent, so the popup can name a site that is not checked', async () => {
    attachAs('scoped');
    const response = await handleRequest(
      {
        type: 'capture_status',
        requestId: 'pd-no-consent-status',
        sessionId: 'browser-pd-no-consent',
        tool: SOURCE_TOOL.ClaudeAi,
        status: { ...STATUS, enforcement: 'unattached' },
      },
      withoutConsent,
    );
    expect(response).toMatchObject({ accepted: false, skipped: 'out-of-scope' });
    expect(readCaptureStatus('browser-pd-no-consent')?.status.enforcement).toBe('unattached');
    expect(rowCount("event_type = 'capture_status'")).toBe(0);

    const state = await handleRequest(
      { type: 'capture_state', requestId: 'pd-no-consent-state' },
      withoutConsent,
    );
    if (state.type !== 'capture_state') throw new Error('expected a capture_state response');
    expect(state.withheld).toBe('personal-device');
    expect(state.sites.find((site) => site.tool === SOURCE_TOOL.ClaudeAi)?.enforcement).toBe(
      'unattached',
    );
  });

  // The control: with no withholding, a missing consent still refuses the
  // report before it is kept anywhere.
  it('is refused before it is kept on a machine-wide attachment without consent', async () => {
    attachAs('machine');
    const response = await handleRequest(
      {
        type: 'capture_status',
        requestId: 'md-no-consent-status',
        sessionId: 'browser-md-no-consent',
        tool: SOURCE_TOOL.ClaudeAi,
        status: STATUS,
      },
      withoutConsent,
    );
    expect(response).toMatchObject({ accepted: false, skipped: 'no-consent' });
    expect(readCaptureStatus('browser-md-no-consent')).toBeUndefined();
  });

  it('is stored and kept on a machine-wide attachment', async () => {
    attachAs('machine');
    const response = await handleRequest(
      {
        type: 'capture_status',
        requestId: 'md-status',
        sessionId: 'browser-md-status',
        tool: SOURCE_TOOL.ChatGpt,
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
        tool: SOURCE_TOOL.ChatGpt,
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
        tool: SOURCE_TOOL.ChatGpt,
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
        tool: SOURCE_TOOL.ClaudeAi,
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
        tool: SOURCE_TOOL.ClaudeAi,
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
        tool: SOURCE_TOOL.ClaudeAi,
        exchange: exchange(),
      },
      halfAttached,
    );
    expect(response).toMatchObject({ accepted: false, skipped: 'out-of-scope' });
  });
});

describe('a fully attached personal device', () => {
  it('starts a session with no root, and still asks for the policy refresh', async () => {
    attachAs('scoped');
    spawned.scripts.length = 0;
    const response = await handleRequest(
      {
        type: 'session_start',
        requestId: 'attached-start',
        sessionId: 'browser-attached-start',
        tool: SOURCE_TOOL.ClaudeAi,
        hostname: 'claude.ai',
      },
      config,
    );
    expect(response).toEqual({ type: 'session_start', requestId: 'attached-start', ok: true });
    expect(rowCount("event_type IN ('session', 'config_scan')")).toBe(0);
    // The positive control: the attached half of the session start ran, so the
    // missing root is the gate's doing and not a pass that gave up early.
    expect(spawned.scripts.some((script) => script.endsWith('sync.js'))).toBe(true);
  });

  it('reports every site unreported, while keeping what it heard about enforcement', async () => {
    attachAs('scoped');
    await handleRequest(
      {
        type: 'capture_status',
        requestId: 'attached-status',
        sessionId: 'browser-attached-status',
        tool: SOURCE_TOOL.ChatGpt,
        status: { ...STATUS, enforcement: 'unattached' },
      },
      config,
    );
    const response = await handleRequest(
      { type: 'capture_state', requestId: 'attached-state' },
      config,
    );
    if (response.type !== 'capture_state') throw new Error('expected a capture_state response');
    expect(response.sites.map((site) => site.state)).toEqual(['unreported', 'unreported']);
    expect(response.sites.find((site) => site.tool === SOURCE_TOOL.ChatGpt)?.enforcement).toBe(
      'unattached',
    );

    // The control: the same memory, read on a machine-wide attachment, reports
    // the network state the tab saw.
    attachAs('machine');
    const recorded = await handleRequest(
      { type: 'capture_state', requestId: 'machine-state' },
      config,
    );
    if (recorded.type !== 'capture_state') throw new Error('expected a capture_state response');
    expect(recorded.sites.find((site) => site.tool === SOURCE_TOOL.ChatGpt)?.state).not.toBe(
      'unreported',
    );
  });
});
