// The shell client hooks.json runs, driven under real shells against a real
// server. A stand-in `node` records how it was called, so a fallback is visible
// as a recorded call rather than inferred from the output.
import { spawn, spawnSync } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';

import { removeTree } from '../../../../../test/helpers/remove-tree.ts';
import { hookClientScript } from '../../../src/hooks/hook-server/client-script.ts';
import type { HookHandler } from '../../../src/hooks/hook-server/server.ts';
import { startHookServer } from '../../../src/hooks/hook-server/server.ts';
import type { HookRequest } from '../../../src/hooks/hook-server/wire.ts';

const VERSION = '9.9.9';

// The client talks to the server through perl; a platform without it runs the
// node hook, which the fallback cases cover without needing it.
const PERL_USABLE =
  process.platform !== 'win32' &&
  spawnSync('sh', ['-c', 'command -v perl >/dev/null 2>&1 && perl -e "use Socket"']).status === 0;
const describeServer = PERL_USABLE ? describe : describe.skip;
const describeUnix = process.platform === 'win32' ? describe.skip : describe;

const SHELLS = ['/bin/sh', '/bin/dash', '/bin/bash'].filter((shell) => existsSync(shell));

let root: string;
let scripts: string;
let bin: string;
let nodeLog: string;

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'aka-hc-'));
  scripts = join(root, 'scripts');
  bin = join(root, 'bin');
  nodeLog = join(root, 'node.log');
  mkdirSync(scripts);
  mkdirSync(bin);
  writeFileSync(join(scripts, 'hook-client.sh'), hookClientScript(VERSION), { mode: 0o755 });
  // A node that logs its arguments and the locale it was given, and echoes stdin.
  const fakeNode = join(bin, 'node');
  writeFileSync(
    fakeNode,
    [
      '#!/bin/sh',
      `printf '%s|LC_ALL=%s\\n' "$*" "\${LC_ALL-unset}" >> "${nodeLog}"`,
      'case $* in *hook-server.js*) exit 0 ;; esac',
      'printf "NODE:"; cat',
      '',
    ].join('\n'),
    { mode: 0o755 },
  );
  chmodSync(fakeNode, 0o755);
});
afterAll(() => {
  removeTree(root);
});

interface Outcome {
  stdout: string;
  code: number | null;
}

function runClient(options: {
  shell: string;
  home: string;
  payload: string;
  env?: Record<string, string | undefined>;
  path?: string;
  cwd?: string;
}): Promise<Outcome> {
  return new Promise((resolve, reject) => {
    const env: Record<string, string> = {
      PATH: options.path ?? `${bin}:/usr/bin:/bin`,
      HOME: options.home,
    };
    for (const [key, value] of Object.entries(options.env ?? {})) {
      if (value !== undefined) env[key] = value;
    }
    const child = spawn(options.shell, [join(scripts, 'hook-client.sh'), 'pre-tool-use'], {
      env,
      cwd: options.cwd ?? tmpdir(),
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    let stdout = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk: string) => {
      stdout += chunk;
    });
    child.on('error', reject);
    child.on('close', (code) => {
      resolve({ stdout, code });
    });
    child.stdin.end(options.payload);
  });
}

const readNodeLog = (): string => (existsSync(nodeLog) ? readFileSync(nodeLog, 'utf8') : '');
const resetNodeLog = (): void => {
  writeFileSync(nodeLog, '');
};

describeUnix.each(SHELLS)('the hook client under %s without a server', (shell) => {
  const homes: string[] = [];
  afterEach(() => {
    for (const home of homes.splice(0)) removeTree(home);
  });
  const newHome = (): string => {
    const home = mkdtempSync(join(tmpdir(), 'aka-hc-home-'));
    homes.push(home);
    return home;
  };

  it('runs the node hook with the payload byte for byte, and starts a server for the next call', async () => {
    resetNodeLog();
    const home = newHome();
    const payload = '{"command":"echo héllo\\n日本語"}\n\n';
    const out = await runClient({ shell, home, payload });
    expect(out).toEqual({ stdout: `NODE:${payload}`, code: 0 });
    await new Promise((resolve) => setTimeout(resolve, 200));
    const log = readNodeLog();
    expect(log).toContain(`${join(scripts, 'pre-tool-use.js')}|`);
    expect(log).toContain('hook-server.js --daemonize');
    expect(existsSync(join(home, '.aka', 'run', `hook-${VERSION}.starting`))).toBe(true);
  });

  it('starts only one server for a burst of calls', async () => {
    resetNodeLog();
    const home = newHome();
    await Promise.all([1, 2, 3].map(() => runClient({ shell, home, payload: '{}' })));
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(
      readNodeLog()
        .split('\n')
        .filter((l) => l.includes('--daemonize')),
    ).toHaveLength(1);
  });

  it('removes a start lock a server never released, without starting one on that call', async () => {
    resetNodeLog();
    const home = newHome();
    const lock = join(home, '.aka', 'run', `hook-${VERSION}.starting`);
    mkdirSync(lock, { recursive: true });
    const old = new Date(Date.now() - 5 * 60_000);
    utimesSync(lock, old, old);
    await runClient({ shell, home, payload: '{}' });
    expect(existsSync(lock)).toBe(false);
    expect(readNodeLog()).not.toContain('--daemonize');
  });

  it('puts the caller locale back before node starts', async () => {
    resetNodeLog();
    const home = newHome();
    await runClient({ shell, home, payload: '{}', env: { LC_ALL: 'en_US.UTF-8' } });
    await runClient({ shell, home, payload: '{}' });
    const calls = readNodeLog()
      .split('\n')
      .filter((l) => l.includes('pre-tool-use.js'));
    expect(calls[0]).toContain('LC_ALL=en_US.UTF-8');
    expect(calls[1]).toContain('LC_ALL=unset');
  });

  it('runs the node hook when AKA_HOOK_SERVER=0, and starts nothing', async () => {
    resetNodeLog();
    const home = newHome();
    const out = await runClient({ shell, home, payload: '{"a":1}', env: { AKA_HOOK_SERVER: '0' } });
    expect(out.stdout).toBe('NODE:{"a":1}');
    expect(readNodeLog()).not.toContain('--daemonize');
    expect(existsSync(join(home, '.aka'))).toBe(false);
  });

  it('runs the node hook when perl is not installed, and starts nothing', async () => {
    resetNodeLog();
    const home = newHome();
    // A PATH with the few tools the script uses and no perl.
    const lean = mkdtempSync(join(tmpdir(), 'aka-hc-lean-'));
    homes.push(lean);
    for (const tool of ['cat', 'mkdir', 'rmdir', 'find']) {
      const found = spawnSync('sh', ['-c', `command -v ${tool}`], {
        encoding: 'utf8',
      }).stdout.trim();
      if (found) symlinkSync(found, join(lean, tool));
    }
    symlinkSync(join(bin, 'node'), join(lean, 'node'));
    const out = await runClient({ shell, home, payload: '{"a":1}', path: lean });
    expect(out.stdout).toBe('NODE:{"a":1}');
    expect(readNodeLog()).not.toContain('--daemonize');
  });

  it('runs the node hook when HOME is unset', async () => {
    resetNodeLog();
    const out = await new Promise<Outcome>((resolve) => {
      const child = spawn(shell, [join(scripts, 'hook-client.sh'), 'pre-tool-use'], {
        env: { PATH: `${bin}:/usr/bin:/bin` },
        stdio: ['pipe', 'pipe', 'ignore'],
      });
      let stdout = '';
      child.stdout.setEncoding('utf8');
      child.stdout.on('data', (c: string) => {
        stdout += c;
      });
      child.on('close', (code) => {
        resolve({ stdout, code });
      });
      child.stdin.end('{}');
    });
    expect(out).toEqual({ stdout: 'NODE:{}', code: 0 });
  });
});

describeServer.each(SHELLS)('the hook client under %s with a server', (shell) => {
  const stops: (() => Promise<void>)[] = [];
  const homes: string[] = [];
  afterEach(async () => {
    for (const stop of stops.splice(0)) await stop();
    for (const home of homes.splice(0)) removeTree(home);
  });

  async function serve(handler: HookHandler): Promise<string> {
    const home = mkdtempSync(join(tmpdir(), 'aka-hc-srv-'));
    homes.push(home);
    const dir = join(home, '.aka', 'run');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const running = await startHookServer({
      socketPath: join(dir, `hook-${VERSION}.sock`),
      handlers: new Map([['pre-tool-use', handler]]),
      idleMs: 60_000,
      maxAgeMs: 60_000,
      handlerTimeoutMs: 5_000,
      maxQueued: 4,
      readTimeoutMs: 2_000,
      isStale: () => false,
      dirMode: 0o700,
      onExit: () => undefined,
      log: () => undefined,
      onFailOpen: () => undefined,
    });
    stops.push(() => running.stop('test'));
    return home;
  }

  it('prints the server answer and never starts node', async () => {
    resetNodeLog();
    const home = await serve(() =>
      Promise.resolve('{"hookSpecificOutput":{"permissionDecision":"deny"}}'),
    );
    const out = await runClient({ shell, home, payload: '{"tool_name":"Bash"}' });
    expect(out).toEqual({
      stdout: '{"hookSpecificOutput":{"permissionDecision":"deny"}}',
      code: 0,
    });
    expect(readNodeLog()).toBe('');
  });

  it('prints nothing for an OK answer with nothing in it', async () => {
    resetNodeLog();
    const home = await serve(() => Promise.resolve(''));
    expect(await runClient({ shell, home, payload: '{}' })).toEqual({ stdout: '', code: 0 });
    expect(readNodeLog()).toBe('');
  });

  it('hands the server the payload exactly, multi-byte text and newlines included', async () => {
    const seen: HookRequest[] = [];
    const home = await serve((request) => {
      seen.push(request);
      return Promise.resolve('');
    });
    const payload = '{"command":"echo héllo \\\\ \\"q\\" 日本語"}\n  second line\n';
    await runClient({ shell, home, payload });
    expect(seen[0]?.payload).toBe(payload);
  });

  it('forwards the working directory and the named variables, and a marker for credentials', async () => {
    const seen: HookRequest[] = [];
    const home = await serve((request) => {
      seen.push(request);
      return Promise.resolve('');
    });
    const cwd = mkdtempSync(join(tmpdir(), 'aka-hc-cwd-'));
    homes.push(cwd);
    await runClient({
      shell,
      home,
      payload: '{}',
      cwd,
      env: {
        CLAUDE_CODE_BRIDGE_SESSION_ID: 'session_abc',
        CLAUDE_CONFIG_DIR: '/home/a/.claude work',
        ANTHROPIC_API_KEY: 'sk-ant-do-not-send',
        CLAUDE_CODE_OAUTH_TOKEN: '',
        UNRELATED: 'x',
      },
    });
    const request = seen[0];
    expect(request?.cwd).toBeDefined();
    expect(request?.env).toEqual({
      CLAUDE_CODE_BRIDGE_SESSION_ID: 'session_abc',
      CLAUDE_CONFIG_DIR: '/home/a/.claude work',
      ANTHROPIC_API_KEY: '1',
    });
    expect(JSON.stringify(request)).not.toContain('sk-ant-do-not-send');
  });

  it('runs the node hook when the server declines the request', async () => {
    resetNodeLog();
    const home = await serve(() => Promise.resolve('unused'));
    // Larger than the server takes: it answers FALLBACK and the client runs node.
    const payload = JSON.stringify({ command: 'x'.repeat(300 * 1024) });
    const out = await runClient({ shell, home, payload });
    expect(out.stdout).toBe(`NODE:${payload}`);
    expect(readNodeLog()).not.toContain('--daemonize');
  });

  it('runs the node hook and tries to start a server when the socket is dead', async () => {
    resetNodeLog();
    const home = mkdtempSync(join(tmpdir(), 'aka-hc-dead-'));
    homes.push(home);
    const dir = join(home, '.aka', 'run');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    // A socket file nothing listens on: a server that is killed outright leaves its file behind.
    const socketFile = join(dir, `hook-${VERSION}.sock`);
    const dying = spawn(
      process.execPath,
      [
        '-e',
        `require('node:net').createServer().listen(${JSON.stringify(socketFile)},()=>console.log('up'))`,
      ],
      { stdio: ['ignore', 'pipe', 'ignore'] },
    );
    await new Promise<void>((resolve) => {
      dying.stdout.once('data', () => {
        resolve();
      });
    });
    dying.kill('SIGKILL');
    await new Promise((resolve) => dying.once('close', resolve));
    expect(existsSync(socketFile)).toBe(true);
    const out = await runClient({ shell, home, payload: '{"a":1}' });
    expect(out.stdout).toBe('NODE:{"a":1}');
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(readNodeLog()).toContain('--daemonize');
  });
});

describe('the generated script', () => {
  it('refuses a plugin version that could change the script', () => {
    expect(() => hookClientScript('1.0.0"; rm -rf ~; "')).toThrow('unusable plugin version');
    expect(() => hookClientScript('')).toThrow('unusable plugin version');
  });

  it('names the socket for the version it was built for', () => {
    expect(hookClientScript('1.2.3')).toContain('hook-1.2.3.sock');
    expect(hookClientScript('1.2.3')).toContain('hook-1.2.3.starting');
  });
});
