import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  applyOnboarding,
  ATTACHED_CAPTURE_SETTINGS_FILENAME,
  ATTACHED_FORWARD_STATE_FILENAME,
  dataDir as dataDirOf,
  settingsDir as settingsDirOf,
  writeControlPlaneCredential,
} from '@akasecurity/persistence';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { useLoopbackServer } from '../../../remote/test/helpers/loopback.ts';
import { checkSessionHold, SESSION_HOLD_TIMEOUT_MS } from '../../src/attached/session-hold.ts';

const server = useLoopbackServer();
let base: string;
let dataDir: string;

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'aka-session-hold-'));
  dataDir = dataDirOf(base);
  mkdirSync(dataDir, { recursive: true });
});
afterEach(() => {
  rmSync(base, { recursive: true, force: true });
});

function holdCheckOn(on = true): void {
  writeFileSync(
    join(dataDir, ATTACHED_CAPTURE_SETTINGS_FILENAME),
    JSON.stringify({ v: 1, sessionHold: on }),
  );
}

function attachTo(
  handler: (url: string, respond: (status: number, body: unknown) => void) => void,
): string[] {
  const seen: string[] = [];
  server.reply((req, res) => {
    seen.push(`${req.method ?? ''} ${req.url ?? ''} ${String(req.headers['x-api-key'])}`);
    handler(req.url ?? '', (status, body) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    });
  });
  const endpoint = server.origin;
  applyOnboarding(
    { runMode: 'attached', controlPlane: { endpoint, attachedAt: '2026-10-28T10:00:00.000Z' } },
    base,
  );
  writeControlPlaneCredential(settingsDirOf(base), {
    specVersion: 1,
    endpoint,
    apiKey: 'not-a-real-key-hold',
  });
  return seen;
}

describe('checkSessionHold', () => {
  it('asks the deployment about this session and returns its hold', async () => {
    holdCheckOn();
    const seen = attachTo((_url, respond) => {
      respond(200, { held: true, reason: 'Paused by your organization.' });
    });
    await expect(checkSessionHold({ dataDir, sessionId: 's/1' })).resolves.toEqual({
      held: true,
      reason: 'Paused by your organization.',
    });
    expect(seen).toEqual(['GET /v1/plugin/sessions/s%2F1/hold not-a-real-key-hold']);
  });

  it('asks nothing when the settings do not turn the check on', async () => {
    const seen = attachTo((_url, respond) => {
      respond(200, { held: true });
    });
    await expect(checkSessionHold({ dataDir, sessionId: 's1' })).resolves.toEqual({ held: false });
    holdCheckOn(false);
    await expect(checkSessionHold({ dataDir, sessionId: 's1' })).resolves.toEqual({ held: false });
    expect(seen).toEqual([]);
  });

  it('asks nothing without a session id', async () => {
    holdCheckOn();
    const seen = attachTo((_url, respond) => {
      respond(200, { held: true });
    });
    await expect(checkSessionHold({ dataDir, sessionId: undefined })).resolves.toEqual({
      held: false,
    });
    expect(seen).toEqual([]);
  });

  it('is not held when the machine is not attached', async () => {
    holdCheckOn();
    await expect(checkSessionHold({ dataDir, sessionId: 's1' })).resolves.toEqual({ held: false });
  });

  it('fails open on a deployment that does not answer within the bound', async () => {
    holdCheckOn();
    attachTo(() => {
      // Never answers.
    });
    const started = performance.now();
    await expect(checkSessionHold({ dataDir, sessionId: 's1' })).resolves.toEqual({ held: false });
    expect(performance.now() - started).toBeLessThan(SESSION_HOLD_TIMEOUT_MS + 700);
  });

  it('fails open on an error status, an older deployment and an unreadable answer', async () => {
    holdCheckOn();
    for (const [status, body] of [
      [500, { error: { code: 'internal' } }],
      [404, { error: { code: 'not_found' } }],
      [403, { error: { code: 'forbidden' } }],
      [200, { held: 'yes' }],
    ] as const) {
      attachTo((_url, respond) => {
        respond(status, body);
      });
      await expect(checkSessionHold({ dataDir, sessionId: 's1' }), String(status)).resolves.toEqual(
        { held: false },
      );
    }
  });

  it('asks nothing while the forward breaker is open', async () => {
    holdCheckOn();
    const seen = attachTo((_url, respond) => {
      respond(200, { held: true });
    });
    const now = Date.now();
    writeFileSync(
      join(dataDir, ATTACHED_FORWARD_STATE_FILENAME),
      JSON.stringify({
        consecutiveFailures: 3,
        openedAtMs: now - 1000,
        lastFailure: 'unreachable',
      }),
    );
    await expect(checkSessionHold({ dataDir, sessionId: 's1', now: () => now })).resolves.toEqual({
      held: false,
    });
    expect(seen).toEqual([]);
  });

  it('fails open when the transport throws', async () => {
    holdCheckOn();
    await expect(
      checkSessionHold({
        dataDir,
        sessionId: 's1',
        fetchHold: () => Promise.reject(new Error('boom')),
      }),
    ).resolves.toEqual({ held: false });
  });
});
