// The hook server over a real unix socket in a temp directory.
import { chmodSync, existsSync, mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../../test/helpers/remove-tree.ts';
import type { HookHandler, HookServerOptions } from '../../../src/hooks/hook-server/server.ts';
import { startHookServer } from '../../../src/hooks/hook-server/server.ts';
import { MAX_REQUEST_BYTES } from '../../../src/hooks/hook-server/wire.ts';
import { sendFrame } from '../../helpers/unix-socket.ts';

// Unix-domain sockets and owner-only directory modes are the platforms' own.
const describeUnix = process.platform === 'win32' ? describe.skip : describe;

function request(hook: string, payload: string, head: readonly string[] = []): string {
  return `AKA-HOOK 1 ${hook}\n${head.map((line) => `${line}\n`).join('')}P ${String(Buffer.byteLength(payload))}\n${payload}`;
}

describeUnix('the hook server', () => {
  const roots: string[] = [];
  const stops: (() => Promise<void>)[] = [];
  afterEach(async () => {
    for (const stop of stops.splice(0)) await stop();
    for (const root of roots.splice(0)) removeTree(root);
  });

  async function start(
    handlers: Record<string, HookHandler>,
    over: Partial<HookServerOptions> = {},
  ): Promise<{
    socketPath: string;
    exits: string[];
    logs: string[];
    failOpens: number[];
    dir: string;
  }> {
    const root = mkdtempSync(join(tmpdir(), 'aka-hs-'));
    roots.push(root);
    const dir = join(root, 'run');
    const socketPath = join(dir, 's.sock');
    const exits: string[] = [];
    const logs: string[] = [];
    const failOpens: number[] = [];
    const running = await startHookServer({
      socketPath,
      handlers: new Map(Object.entries(handlers)),
      idleMs: 60_000,
      maxAgeMs: 60_000,
      handlerTimeoutMs: 5_000,
      maxQueued: 4,
      readTimeoutMs: 2_000,
      isStale: () => false,
      dirMode: 0o700,
      onExit: (reason) => {
        exits.push(reason);
      },
      log: (line) => {
        logs.push(line);
      },
      onFailOpen: () => {
        failOpens.push(1);
      },
      ...over,
    });
    stops.push(() => running.stop('test'));
    return { socketPath, exits, logs, failOpens, dir };
  }

  it('answers a request with the handler output behind an OK line', async () => {
    const seen: unknown[] = [];
    const { socketPath } = await start({
      'pre-tool-use': (req) => {
        seen.push(req);
        return Promise.resolve('{"decision":"deny"}');
      },
    });
    const reply = await sendFrame(
      socketPath,
      request('pre-tool-use', '{"a":1}', ['C /w', 'E CLAUDE_CONFIG_DIR /c']),
    );
    expect(reply).toBe('OK\n{"decision":"deny"}');
    expect(seen).toEqual([
      {
        hook: 'pre-tool-use',
        cwd: '/w',
        env: { CLAUDE_CONFIG_DIR: '/c' },
        payload: '{"a":1}',
      },
    ]);
  });

  it('answers a client that closes its sending side and then waits', async () => {
    const { socketPath } = await start({
      'pre-tool-use': async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
        return 'late';
      },
    });
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'), true)).toBe('OK\nlate');
  });

  it('answers FALLBACK to a client that closes before the request is whole', async () => {
    const { socketPath } = await start({ 'pre-tool-use': () => Promise.resolve('x') });
    const half = request('pre-tool-use', '{"a":1}').slice(0, -3);
    expect(await sendFrame(socketPath, half, true)).toBe('FALLBACK\n');
  });

  it('answers OK with nothing when the hook has no opinion', async () => {
    const { socketPath } = await start({ 'pre-tool-use': () => Promise.resolve('') });
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'))).toBe('OK\n');
  });

  it('answers FALLBACK when the handler declines the request', async () => {
    const { socketPath } = await start({ 'pre-tool-use': () => Promise.resolve(null) });
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'))).toBe('FALLBACK\n');
  });

  it('answers FALLBACK for a hook it does not serve and for a malformed frame', async () => {
    const { socketPath } = await start({ 'pre-tool-use': () => Promise.resolve('x') });
    expect(await sendFrame(socketPath, request('stop', '{}'))).toBe('FALLBACK\n');
    expect(await sendFrame(socketPath, 'GET / HTTP/1.1\nHost: x\n\n')).toBe('FALLBACK\n');
  });

  it('answers FALLBACK for a request over the size limit, without running the hook', async () => {
    let ran = false;
    const { socketPath } = await start({
      'pre-tool-use': () => {
        ran = true;
        return Promise.resolve('x');
      },
    });
    const header = `AKA-HOOK 1 pre-tool-use\nP ${String(MAX_REQUEST_BYTES + 1)}\n`;
    expect(await sendFrame(socketPath, header)).toBe('FALLBACK\n');
    expect(ran).toBe(false);
  });

  it('runs requests one at a time, in arrival order', async () => {
    const order: string[] = [];
    let active = 0;
    let overlapped = false;
    const { socketPath } = await start({
      'pre-tool-use': async (req) => {
        active += 1;
        if (active > 1) overlapped = true;
        order.push(`start ${req.payload}`);
        await new Promise((resolve) => setTimeout(resolve, 20));
        order.push(`end ${req.payload}`);
        active -= 1;
        return req.payload;
      },
    });
    const replies = await Promise.all(
      ['1', '2', '3'].map((n) => sendFrame(socketPath, request('pre-tool-use', n))),
    );
    expect(replies).toEqual(['OK\n1', 'OK\n2', 'OK\n3']);
    expect(overlapped).toBe(false);
  });

  it('does not run a queued request that waited past the client give-up time', async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let calls = 0;
    const { socketPath } = await start(
      {
        'pre-tool-use': async () => {
          calls += 1;
          await gate;
          return 'done';
        },
      },
      { clientGiveUpMs: 100 },
    );
    const first = sendFrame(socketPath, request('pre-tool-use', '{}'));
    await new Promise((resolve) => setTimeout(resolve, 20));
    const second = sendFrame(socketPath, request('pre-tool-use', '{}'));
    await new Promise((resolve) => setTimeout(resolve, 200));
    release();
    expect(await first).toBe('OK\ndone');
    expect(await second).toBe('FALLBACK\n');
    expect(calls).toBe(1);
  });

  it('answers FALLBACK when the queue is full', async () => {
    let release: () => void = () => undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { socketPath } = await start(
      {
        'pre-tool-use': async () => {
          await gate;
          return 'done';
        },
      },
      { maxQueued: 1 },
    );
    const first = sendFrame(socketPath, request('pre-tool-use', '{}'));
    // The second finds the first still running and the queue at its limit.
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'))).toBe('FALLBACK\n');
    release();
    expect(await first).toBe('OK\ndone');
  });

  it('turns a handler that throws into an empty answer and keeps serving', async () => {
    let calls = 0;
    const { socketPath, logs } = await start({
      'pre-tool-use': () => {
        calls += 1;
        return calls === 1 ? Promise.reject(new Error('boom')) : Promise.resolve('fine');
      },
    });
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'))).toBe('OK\n');
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'))).toBe('OK\nfine');
    expect(logs.join('\n')).toContain('boom');
  });

  it('answers empty and exits when a handler outlives its deadline', async () => {
    const { socketPath, exits, failOpens } = await start(
      { 'pre-tool-use': () => new Promise<string>(() => undefined) },
      { handlerTimeoutMs: 50 },
    );
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'))).toBe('OK\n');
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(exits).toEqual(['handler-timeout']);
    expect(failOpens).toHaveLength(1);
    expect(existsSync(socketPath)).toBe(false);
  });

  it('exits when it has been idle', async () => {
    const { socketPath, exits } = await start(
      { 'pre-tool-use': () => Promise.resolve('') },
      { idleMs: 60 },
    );
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(exits).toEqual(['idle']);
    expect(existsSync(socketPath)).toBe(false);
  });

  it('declines a request and exits once the code it runs has been replaced', async () => {
    let stale = false;
    const { socketPath, exits } = await start(
      { 'pre-tool-use': () => Promise.resolve('x') },
      { isStale: () => stale },
    );
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'))).toBe('OK\nx');
    stale = true;
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'))).toBe('FALLBACK\n');
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(exits).toEqual(['replaced']);
  });

  it('refuses to start where another live server owns the socket', async () => {
    const first = await start({ 'pre-tool-use': () => Promise.resolve('') });
    await expect(
      startHookServer({
        socketPath: first.socketPath,
        handlers: new Map(),
        idleMs: 1000,
        maxAgeMs: 1000,
        handlerTimeoutMs: 1000,
        maxQueued: 1,
        readTimeoutMs: 1000,
        isStale: () => false,
        dirMode: 0o700,
        onExit: () => undefined,
        log: () => undefined,
        onFailOpen: () => undefined,
      }),
    ).rejects.toThrow('already running');
  });

  it('replaces the socket file a dead server left behind', async () => {
    const root = mkdtempSync(join(tmpdir(), 'aka-hs-'));
    roots.push(root);
    const dir = join(root, 'run');
    mkdirSync(dir, { mode: 0o700 });
    const socketPath = join(dir, 's.sock');
    writeFileSync(socketPath, 'left behind');
    const running = await startHookServer({
      socketPath,
      handlers: new Map([['pre-tool-use', () => Promise.resolve('up')]]),
      idleMs: 60_000,
      maxAgeMs: 60_000,
      handlerTimeoutMs: 1000,
      maxQueued: 1,
      readTimeoutMs: 1000,
      isStale: () => false,
      dirMode: 0o700,
      onExit: () => undefined,
      log: () => undefined,
      onFailOpen: () => undefined,
    });
    stops.push(() => running.stop('test'));
    expect(await sendFrame(socketPath, request('pre-tool-use', '{}'))).toBe('OK\nup');
  });

  it('refuses a directory other users could enter', async () => {
    const root = mkdtempSync(join(tmpdir(), 'aka-hs-'));
    roots.push(root);
    const dir = join(root, 'run');
    mkdirSync(dir);
    chmodSync(dir, 0o755);
    await expect(
      startHookServer({
        socketPath: join(dir, 's.sock'),
        handlers: new Map(),
        idleMs: 1000,
        maxAgeMs: 1000,
        handlerTimeoutMs: 1000,
        maxQueued: 1,
        readTimeoutMs: 1000,
        isStale: () => false,
        dirMode: 0o700,
        onExit: () => undefined,
        log: () => undefined,
        onFailOpen: () => undefined,
      }),
    ).rejects.toThrow('accessible to other users');
  });

  it('creates the socket readable by its owner only', async () => {
    const { socketPath } = await start({ 'pre-tool-use': () => Promise.resolve('') });
    const { statSync } = await import('node:fs');
    expect(statSync(socketPath).mode & 0o077).toBe(0);
  });
});
