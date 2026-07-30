import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { ConfigForTool } from '../../src/native-host/host.ts';
import { runHost } from '../../src/native-host/host.ts';
import type { WebSourceTool } from '../../src/native-host/protocol.ts';
import { isHostRequest } from '../../src/native-host/protocol.ts';
import { readMessages, writeMessage } from '../../src/native-host/wire.ts';

describe('isHostRequest', () => {
  it('accepts every request shape the protocol defines', () => {
    expect(isHostRequest({ type: 'ping', requestId: 'r1' })).toBe(true);
    expect(isHostRequest({ type: 'health', requestId: 'r2' })).toBe(true);
    expect(
      isHostRequest({
        type: 'session_start',
        requestId: 'r3',
        sessionId: 's1',
        tool: 'chatgpt',
        hostname: 'chatgpt.com',
      }),
    ).toBe(true);
    expect(
      isHostRequest({
        type: 'capture',
        requestId: 'r4',
        sessionId: 's1',
        tool: 'claude-ai',
        kind: 'prompt',
        text: 'hello',
      }),
    ).toBe(true);
  });

  it('rejects a request without a string requestId', () => {
    expect(isHostRequest({ type: 'ping' })).toBe(false);
    expect(isHostRequest({ type: 'ping', requestId: 7 })).toBe(false);
  });

  it('rejects an unknown request type', () => {
    expect(isHostRequest({ type: 'shutdown', requestId: 'r1' })).toBe(false);
  });

  it('rejects malformed payloads', () => {
    expect(isHostRequest(null)).toBe(false);
    expect(isHostRequest('ping')).toBe(false);
    expect(
      isHostRequest({
        type: 'session_start',
        requestId: 'r1',
        sessionId: 's1',
        tool: 'gemini', // not a WebSourceTool this contract accepts
        hostname: 'gemini.google.com',
      }),
    ).toBe(false);
    expect(
      isHostRequest({
        type: 'session_start',
        requestId: 'r1',
        sessionId: 's1',
        tool: 'chatgpt',
        // hostname missing
      }),
    ).toBe(false);
    expect(
      isHostRequest({
        type: 'capture',
        requestId: 'r1',
        sessionId: 's1',
        tool: 'chatgpt',
        kind: 'prompt',
        // text missing
      }),
    ).toBe(false);
  });
});

let dir: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'aka-native-protocol-'));
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

// Frame the given messages onto a stdin stream, run the dispatch loop to
// completion, and return every framed response it wrote — the same
// length-prefixed wire format Chrome speaks on both directions.
async function drive(frames: unknown[], configForTool: ConfigForTool): Promise<unknown[]> {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  const done = runHost(stdin, stdout, configForTool);
  for (const frame of frames) {
    await writeMessage(stdin, frame);
  }
  stdin.end();
  await done;
  stdout.end();

  const responses: unknown[] = [];
  for await (const message of readMessages(stdout)) {
    responses.push(message);
  }
  return responses;
}

describe('runHost (stdio dispatch loop)', () => {
  it('answers an unknown-but-well-formed request type with an error carrying its requestId, then keeps serving', async () => {
    const responses = await drive(
      [
        { type: 'time_travel', requestId: 'u1' },
        { type: 'unframed_junk' }, // no requestId — nothing to correlate, silently skipped
        { type: 'ping', requestId: 'u2' },
      ],
      config,
    );

    expect(responses).toEqual([
      { type: 'error', requestId: 'u1', ok: false, message: 'unrecognized request' },
      { type: 'ping', requestId: 'u2', ok: true, dbPath: join(dir, 'aka.db'), onboarded: true },
    ]);
  });

  it('a request whose handler throws yields an error response and the loop survives to the next frame', async () => {
    let calls = 0;
    const flaky: ConfigForTool = (tool) => {
      calls += 1;
      if (calls === 1) throw new Error('config exploded');
      return config(tool);
    };

    const responses = await drive(
      [
        { type: 'ping', requestId: 'e1' },
        { type: 'ping', requestId: 'e2' },
      ],
      flaky,
    );

    expect(responses).toEqual([
      { type: 'error', requestId: 'e1', ok: false, message: 'config exploded' },
      { type: 'ping', requestId: 'e2', ok: true, dbPath: join(dir, 'aka.db'), onboarded: true },
    ]);
  });
});
