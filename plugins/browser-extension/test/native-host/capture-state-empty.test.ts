import { randomUUID } from 'node:crypto';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { openLocalDatabase } from '@akasecurity/persistence';
import type { PluginConfig } from '@akasecurity/plugin-sdk';
import type { WebChatCapture, WebChatResponseCapture } from '@akasecurity/schema';
import { toCaptureStatusAttributes, WEB_CHAT_CAPTURE_CONSENT_VERSION } from '@akasecurity/schema';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../test/helpers/remove-tree.ts';
import { handleRequest } from '../../src/native-host/host.ts';
import type { WebSourceTool } from '../../src/native-host/protocol.ts';

// A SEPARATE file, deliberately: host.ts's in-memory `captureStatuses` map is
// module-global for the life of the process (by design — one host process
// serves one browser), so within ONE test file it accumulates every
// `capture_status` report every earlier `it()` recorded. A file boundary is
// what vitest reloads the module fresh for, which is the only way to observe
// a host that has heard about NOTHING yet.
let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-capture-state-empty-'));
});

afterEach(() => {
  removeTree(dir);
});

function config(tool: WebSourceTool | undefined, webChat?: WebChatCapture): PluginConfig {
  return {
    settings: {
      specVersion: 3,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
      redactFallback: 'warn',
      ...(webChat !== undefined ? { webChatCapture: webChat } : {}),
    },
    dataDir: dir,
    dbPath: join(dir, 'aka.db'),
    settingsDir: dir,
    onboarded: true,
    provider: tool === 'chatgpt' ? { provider: 'openai' } : { provider: 'anthropic' },
  };
}

function webChatSettings(
  responses: WebChatResponseCapture = 'with-findings',
  version: number = WEB_CHAT_CAPTURE_CONSENT_VERSION,
): WebChatCapture {
  return {
    responses,
    account: false,
    consent: { acknowledgedAt: '2026-01-01T00:00:00.000Z', version },
  };
}

describe('capture_state on a host that has heard nothing yet', () => {
  it('answers every known site, in schema order, both unreported', async () => {
    const response = await handleRequest(
      { type: 'capture_state', requestId: 'state-empty-1' },
      (tool) => config(tool, webChatSettings()),
    );
    expect(response).toEqual({
      type: 'capture_state',
      requestId: 'state-empty-1',
      ok: true,
      consented: true,
      sites: [
        { tool: 'chatgpt', state: 'unreported' },
        { tool: 'claude-ai', state: 'unreported' },
      ],
    });
  });

  it('reads a status a previous host process stored', async () => {
    // The restart shape, and the only one that reaches the store read: in
    // host.test.ts every capture_state case runs after that file's own
    // capture_status did, so the module-global map answers identically there
    // and the store branch can be deleted with that whole suite green. Here
    // the map is empty, so a stored row is the only thing that can answer.
    const db = openLocalDatabase(dir);
    try {
      db.auditEvents.insertAuditEvent({
        id: randomUUID(),
        eventType: 'capture_status',
        startedAt: '2026-01-01T00:00:00.000Z',
        attributes: toCaptureStatusAttributes(
          {
            patched: true,
            live: true,
            blind: false,
            sendsSeenDom: 1,
            exchangesSeenNet: 1,
            parseFailures: 0,
            unparsedBodies: 0,
            shapeMisses: [],
            conversationEndpoints: 1,
          },
          'claude-ai',
        ),
      });
    } finally {
      db.close();
    }

    const response = await handleRequest(
      { type: 'capture_state', requestId: 'state-empty-2' },
      (tool) => config(tool, webChatSettings()),
    );
    const sites = (response as { sites: { tool: string; state: string }[] }).sites;
    expect(sites.find((s) => s.tool === 'claude-ai')?.state).toBe('active');
    expect(sites.find((s) => s.tool === 'chatgpt')?.state).toBe('unreported');
  });
});
