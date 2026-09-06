import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';

import type { PluginConfig } from '@akasecurity/plugin-sdk';
import { bundledDetections } from '@akasecurity/plugin-sdk';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import type { ConfigForTool } from '../../src/native-host/host.ts';
import { runHost } from '../../src/native-host/host.ts';
import type { WebSourceTool } from '../../src/native-host/protocol.ts';
import { isHostRequest } from '../../src/native-host/protocol.ts';
import { readMessages, writeMessage } from '../../src/native-host/wire.ts';
import { expectNoEchoOf } from '../helpers/no-echo.ts';

// The bundled rule's own example, so no secret-shaped literal is written by
// hand — same pattern as host.test.ts's secretFixture().
const RULE_ID = 'secrets/twilio-key';
function secretFixture(): string {
  const pack = bundledDetections().find((p) => p.rules.some((r) => r.id === RULE_ID));
  const example = pack?.rules.find((r) => r.id === RULE_ID)?.examples?.[0];
  if (example === undefined) {
    throw new Error(`bundled rule ${RULE_ID} is missing from the pack registry or has no example`);
  }
  return example;
}
const SECRET_EXAMPLE = secretFixture();

const VALID_EXCHANGE = {
  messageId: 'm1',
  startedAt: '2026-01-01T00:00:00.000Z',
  usageSource: 'site',
  toolCalls: [],
  truncated: false,
};

const VALID_STATUS = {
  patched: true,
  live: false,
  blind: false,
  sendsSeenDom: 0,
  exchangesSeenNet: 0,
  parseFailures: 0,
  unparsedBodies: 0,
  shapeMisses: [],
};

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

  it('accepts a well-formed exchange and capture_status', () => {
    // `exchange` and `capture_status` are on the wire so the isolated-world
    // bridge can relay them, and this host now has a handler for both.
    expect(
      isHostRequest({
        type: 'exchange',
        requestId: 'r5',
        sessionId: 's1',
        tool: 'claude-ai',
        exchange: VALID_EXCHANGE,
      }),
    ).toBe(true);
    expect(
      isHostRequest({
        type: 'capture_status',
        requestId: 'r6',
        sessionId: 's1',
        tool: 'claude-ai',
        status: VALID_STATUS,
      }),
    ).toBe(true);
  });

  it('refuses an exchange whose payload fails WebExchange', () => {
    const request = (exchange: unknown) => ({
      type: 'exchange',
      requestId: 'r5',
      sessionId: 's1',
      tool: 'claude-ai',
      exchange,
    });
    expect(isHostRequest(request({ ...VALID_EXCHANGE, usageSource: 'sometimes' }))).toBe(false);
    expect(isHostRequest(request({ ...VALID_EXCHANGE, messageId: '' }))).toBe(false);
    expect(isHostRequest(request({ ...VALID_EXCHANGE, startedAt: 'yesterday' }))).toBe(false);
    expect(
      isHostRequest(request({ ...VALID_EXCHANGE, toolCalls: [{ toolUseId: '', toolName: 'x' }] })),
    ).toBe(false);
    expect(
      isHostRequest({ type: 'exchange', requestId: 'r5', sessionId: 's1', tool: 'claude-ai' }),
    ).toBe(false);
  });

  it('refuses a capture_status whose payload fails WebCaptureStatus', () => {
    const request = (status: unknown) => ({
      type: 'capture_status',
      requestId: 'r6',
      sessionId: 's1',
      tool: 'claude-ai',
      status,
    });
    expect(isHostRequest(request({ ...VALID_STATUS, sendsSeenDom: -1 }))).toBe(false);
    expect(isHostRequest(request({ ...VALID_STATUS, patched: 'yes' }))).toBe(false);
    expect(
      isHostRequest({
        type: 'capture_status',
        requestId: 'r6',
        sessionId: 's1',
        tool: 'claude-ai',
      }),
    ).toBe(false);
  });

  it('refuses an exchange or capture_status whose tool is not a web source tool, or whose sessionId is missing', () => {
    expect(
      isHostRequest({
        type: 'exchange',
        requestId: 'r5',
        sessionId: 's1',
        tool: 'gemini',
        exchange: VALID_EXCHANGE,
      }),
    ).toBe(false);
    expect(
      isHostRequest({
        type: 'exchange',
        requestId: 'r5',
        tool: 'claude-ai',
        exchange: VALID_EXCHANGE,
      }),
    ).toBe(false);
    expect(
      isHostRequest({
        type: 'capture_status',
        requestId: 'r6',
        sessionId: 's1',
        tool: 'gemini',
        status: VALID_STATUS,
      }),
    ).toBe(false);
    expect(
      isHostRequest({
        type: 'capture_status',
        requestId: 'r6',
        tool: 'claude-ai',
        status: VALID_STATUS,
      }),
    ).toBe(false);
  });

  it('rejects a request without a string requestId', () => {
    expect(isHostRequest({ type: 'ping' })).toBe(false);
    expect(isHostRequest({ type: 'ping', requestId: 7 })).toBe(false);
  });

  it('rejects an unknown request type', () => {
    expect(isHostRequest({ type: 'shutdown', requestId: 'r1' })).toBe(false);
  });

  it('accepts capture_state — it carries no fields beyond requestId', () => {
    expect(isHostRequest({ type: 'capture_state', requestId: 'r7' })).toBe(true);
  });

  it('refuses a capture_state frame with no requestId', () => {
    expect(isHostRequest({ type: 'capture_state' })).toBe(false);
  });

  it('accepts a capture_status frame from a build with no conversationEndpoints', () => {
    // VALID_STATUS carries no conversationEndpoints field at all — the shape
    // an older extension build sends. It defaults to 0 on the schema side, so
    // it must not be rejected here.
    expect(
      isHostRequest({
        type: 'capture_status',
        requestId: 'r8',
        sessionId: 's1',
        tool: 'chatgpt',
        status: VALID_STATUS,
      }),
    ).toBe(true);
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
      redactFallback: 'warn',
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

  it('answers a malformed exchange frame carrying a secret with a fixed message, echoing nothing of it', async () => {
    const responses = await drive(
      [
        {
          type: 'exchange',
          requestId: 'x1',
          sessionId: 's1',
          tool: 'claude-ai',
          exchange: { ...VALID_EXCHANGE, usageSource: 'sometimes', responseText: SECRET_EXAMPLE },
        },
      ],
      config,
    );

    expect(responses).toHaveLength(1);
    const [reply] = responses as [{ message: string }];
    // Positive control first: the message is really the fixed string, so the
    // echo check below is not passing on empty bytes.
    expect(reply.message).toBe('unrecognized request');
    expectNoEchoOf(JSON.stringify(reply), SECRET_EXAMPLE);
  });
});
