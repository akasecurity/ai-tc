import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { handleRequest } from '../../src/native-host/host.ts';
import type { WebSourceTool } from '../../src/native-host/protocol.ts';

// The canonical AWS example key id, composed at runtime so the repo's own
// secret scanning doesn't flag this file (see handle-capture.test.ts).
const AWS_EXAMPLE_KEY = ['AKIA', 'IOSFODNN7EXAMPLE'].join('');

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-native-host-'));
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function config(tool: WebSourceTool | undefined): PluginConfig {
  return {
    settings: {
      specVersion: 3,
      runMode: 'standalone',
      policy: 'redact',
      historicalAccess: 'session-only',
      dataSharesInPlace: true,
      vaultKeyCustody: 'file',
      vaultInlineReveal: 'masked',
    },
    dataDir: dir,
    dbPath: join(dir, 'aka.db'),
    settingsDir: dir,
    onboarded: true,
    provider: tool === 'chatgpt' ? { provider: 'openai' } : { provider: 'anthropic' },
  };
}

function open(): DatabaseSync {
  return new DatabaseSync(join(dir, 'aka.db'));
}

describe('handleRequest (native-messaging host)', () => {
  it('answers ping with the resolved store path', async () => {
    const response = await handleRequest({ type: 'ping', requestId: 'r1' }, config);
    expect(response).toEqual({
      type: 'ping',
      requestId: 'r1',
      ok: true,
      dbPath: join(dir, 'aka.db'),
      onboarded: true,
    });
  });

  it('opens a session root for session_start, stamping the tab hostname as harness_interface', async () => {
    const response = await handleRequest(
      {
        type: 'session_start',
        requestId: 'r2',
        sessionId: 'browser-s1',
        tool: 'claude-ai',
        hostname: 'claude.ai',
      },
      config,
    );
    expect(response).toEqual({ type: 'session_start', requestId: 'r2', ok: true });

    const db = open();
    const session = db
      .prepare("SELECT * FROM audit_events WHERE event_type = 'session' AND id = 'browser-s1'")
      .get() as Record<string, unknown>;
    const attrs = JSON.parse(session.attributes as string) as Record<string, unknown>;
    db.close();

    expect(attrs.harness).toBe('claudeai');
    expect(attrs.harness_interface).toBe('claude.ai');
    expect(attrs.provider).toBe('anthropic');
  });

  it('records a capture and returns its action + rule ids', async () => {
    const text = `here is ${AWS_EXAMPLE_KEY} value`;
    const response = await handleRequest(
      {
        type: 'capture',
        requestId: 'r3',
        sessionId: 'browser-s2',
        tool: 'chatgpt',
        kind: 'prompt',
        text,
      },
      config,
    );
    expect(response.type).toBe('capture');
    if (response.type !== 'capture') throw new Error('unreachable');
    // The bundled secrets pack is unassigned by default, so it monitors (log) —
    // masking at rest is independent of enforcement, same as handleCapture's own test.
    expect(response.action).toBe('log');
    expect(response.ruleIds).toContain('secrets/aws-access-key');
    // No composer rewrite needed for a log outcome, so the (possibly large)
    // prompt text is NOT echoed back over the 1 MB-capped host→Chrome pipe.
    expect(response.text).toBeUndefined();

    const db = open();
    const row = db.prepare('SELECT source_tool, content, metadata FROM events').get() as {
      source_tool: string;
      content: string;
      metadata: string;
    };
    db.close();

    expect(row.source_tool).toBe('chatgpt');
    expect(row.content).not.toContain(AWS_EXAMPLE_KEY);
    expect(JSON.parse(row.metadata) as Record<string, unknown>).toMatchObject({
      sessionId: 'browser-s2',
    });
  });

  it('answers health with the store-wide findings tally after a capture lands a finding', async () => {
    await handleRequest(
      {
        type: 'capture',
        requestId: 'h1',
        sessionId: 'browser-s4',
        tool: 'chatgpt',
        kind: 'prompt',
        text: `key: ${AWS_EXAMPLE_KEY}`,
      },
      config,
    );

    const response = await handleRequest({ type: 'health', requestId: 'h2' }, config);
    expect(response.type).toBe('health');
    if (response.type !== 'health') throw new Error('unreachable');
    expect(response.findings).toBeGreaterThanOrEqual(1);
    expect(response.bySeverity.critical).toBeGreaterThanOrEqual(1);
  });

  it('is fail-open: an unusable data dir degrades capture to log + original text, never throws', async () => {
    // Point dataDir at a regular file so opening the store throws while resolving —
    // same setup as handleCapture's own fail-open test.
    const filePath = join(dir, 'blocker');
    writeFileSync(filePath, 'x');
    const broken = (tool: WebSourceTool | undefined): PluginConfig => ({
      ...config(tool),
      dataDir: filePath,
      dbPath: join(filePath, 'aka.db'),
    });

    const response = await handleRequest(
      {
        type: 'capture',
        requestId: 'r4',
        sessionId: 'browser-s3',
        tool: 'claude-ai',
        kind: 'prompt',
        text: 'SECRET_MARKER',
      },
      broken,
    );
    expect(response).toEqual({
      type: 'capture',
      requestId: 'r4',
      ok: true,
      action: 'log',
      ruleIds: [],
    });
  });
});
